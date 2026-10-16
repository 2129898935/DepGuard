"""Proof-oriented regressions for bounded DepGuard evidence execution."""

import json

import pytest

from agent.batch_runtime import SplitBatch, replay_stage, run_stage
from agent.evidence_contract import (
    content_hash, evidence_id, normalize_components, validate_coverage,
)


def _components(count=5):
    return normalize_components([
        {"name": f"Pkg_{index}", "version": "1.0.0", "ecosystem": "PyPI"}
        for index in range(count)
    ])


def test_component_id_distinguishes_unresolved_constraint_and_merges_occurrences():
    result = normalize_components([
        {"name": "My_Pkg", "version": "1.0.0", "source_file": "a.txt"},
        {"name": "my-pkg", "version": "1.0.0", "source_file": "b.txt"},
        {"name": "my.pkg", "version": ">=1.0", "source_file": "c.txt"},
    ])
    assert len(result) == 2
    assert result[0]["component_id"] == "pkg:pypi/my-pkg@1.0.0"
    assert len(result[0]["source_occurrences"]) == 2
    assert result[1]["component_id"].startswith("req:pypi/my-pkg#")


def test_equal_counts_cannot_hide_missing_and_duplicate_ids():
    ids = {item["component_id"] for item in _components(3)}
    rows = [{"component_id": cid, "status": "complete"} for cid in sorted(ids)]
    rows[1]["component_id"] = rows[0]["component_id"]
    errors = validate_coverage(ids, rows, "S2")
    assert any("未覆盖" in error for error in errors)
    assert any("重复" in error for error in errors)


@pytest.mark.asyncio
async def test_split_lineage_leaf_only_replay_and_tamper_gate(tmp_path):
    components = _components(5)

    async def worker(batch, circuit):
        if len(batch) > 2:
            raise SplitBatch("context_overflow")
        return {"outcomes": [{"component_id": item["component_id"], "status": "no_finding"}
                             for item in batch],
                "records": [], "datasource_snapshot_id": "fixture"}

    result = await run_stage(tmp_path, "S2", components, worker, max_items=5)
    assert result["ok"] is True
    assert len(result["outcomes"]) == 5
    manifest = json.loads((tmp_path / "batch_plan_s2.json").read_text(encoding="utf-8"))
    assert manifest["batches"][0]["status"] == "split"
    assert all("/" in row["batch_id"] for row in manifest["batches"][1:])
    assert replay_stage(tmp_path, "S2", components)["ok"] is True
    leaf = next(row for row in manifest["batches"] if row["status"] == "succeeded")
    output = tmp_path / leaf["output_file"]
    payload = json.loads(output.read_text(encoding="utf-8"))
    payload["outcomes"][0]["component_id"] = components[-1]["component_id"]
    output.write_text(json.dumps(payload), encoding="utf-8")
    errors = replay_stage(tmp_path, "S2", components)["errors"]
    assert any("哈希不匹配" in error for error in errors)


@pytest.mark.asyncio
async def test_incomplete_batch_lists_exact_uncovered_component(tmp_path):
    components = _components(2)

    async def worker(batch, circuit):
        if batch[0]["name"] == "pkg-1":
            raise ValueError("source schema contradiction")
        return {"outcomes": [{"component_id": batch[0]["component_id"],
                              "status": "no_finding"}],
                "records": [], "datasource_snapshot_id": "fixture"}

    result = await run_stage(tmp_path, "S2", components, worker, max_items=1)
    assert result["ok"] is False
    assert result["uncovered"] == [{
        "component_id": components[1]["component_id"], "status": "source_failed",
        "reason_code": "batch_incomplete", "batch_id": "s2-0002",
        "detail": "source schema contradiction",
    }]


@pytest.mark.asyncio
async def test_s234_batch_path_closes_all_components_without_model_json(tmp_path, monkeypatch):
    from api.context import set_session_context, reset_session_context
    import agent.parallel_analysis as parallel

    components = _components(4)
    monkeypatch.setenv("DEPGUARD_LLM_REVIEW", "0")
    (tmp_path / "s1_components.json").write_text(json.dumps({"components": components}), encoding="utf-8")

    def fake_osv(names, ecosystem, versions, max_details):
        assert len(names) <= 16
        return json.dumps({"packages": [
            {"name": name, "version": version, "vulnerabilities": [],
             "omitted_ids": [], "total_vulnerabilities": 0}
            for name, version in zip(names, versions)]})

    def fake_metadata(name, version, system):
        return json.dumps({"ok": True, "name": name, "version": version,
                           "licenses": ["MIT"]})

    monkeypatch.setattr(parallel.query_osv_vulns, "func", fake_osv)
    monkeypatch.setattr(parallel.query_package_info, "func", fake_metadata)
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)
    token = set_session_context(str(tmp_path))
    try:
        result = await parallel.run_parallel_analysis("@s1_components.json")
    finally:
        reset_session_context(token)
    assert result["status"] == "completed"
    assert set(result["stages"]) == {"S2", "S3", "S4"}
    for stage in ("S2", "S3", "S4"):
        evidence = json.loads((tmp_path / f"{stage.lower()}_evidence.json").read_text(encoding="utf-8"))
        assert len(evidence["coverage"]["outcomes"]) == 4
        assert replay_stage(tmp_path, stage, components)["ok"] is True
    assert json.loads((tmp_path / "s4_evidence.json").read_text(encoding="utf-8"))["status"] == "degraded_no_source_evidence"


@pytest.mark.asyncio
async def test_s5_plan_references_exact_evidence_and_remains_pending_compatibility(tmp_path, monkeypatch):
    from agent import upgrade_batches as upgrade

    components = normalize_components([
        {"name": "vulnerable", "version": "1.0.0", "ecosystem": "PyPI"},
        {"name": "clean", "version": "1.0.0", "ecosystem": "PyPI"},
    ])
    cid = components[0]["component_id"]
    s1 = {"components": components}
    s2 = {"vulnerabilities": [{
        "component_id": cid, "canonical_id": "GHSA-test",
        "affected_component": "vulnerable", "affected_ecosystem": "PyPI",
        "affected_version": "1.0.0",
        "evidence_id": evidence_id("S2", cid, "OSV", "GHSA-test"),
        "evidence_status": "confirmed", "fixed_versions": ["1.0.1"],
        "affected_ranges": [{"package": {"name": "vulnerable", "ecosystem": "PyPI"},
                             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}]}],
    }]}
    s3 = {"components": []}
    s4 = {"package_results": []}
    for name, value in (("s1_components.json", s1), ("s2_evidence.json", s2),
                        ("s3_evidence.json", s3), ("s4_evidence.json", s4)):
        (tmp_path / name).write_text(json.dumps(value), encoding="utf-8")

    monkeypatch.setattr(upgrade.query_dependencies, "func", lambda *args: json.dumps(
        {"ok": True, "name": args[0], "direct_dependencies": []}))
    monkeypatch.setattr(upgrade.query_osv_vulns, "func", lambda *args: json.dumps(
        {"packages": [{"name": "vulnerable", "version": "1.0.1",
                       "total_vulnerabilities": 0, "vulnerabilities": [], "omitted_ids": []}]}))
    monkeypatch.setattr(upgrade.query_package_info, "func", lambda *args: json.dumps(
        {"ok": True, "name": args[0], "version": args[1]}))
    summary = await upgrade.build_plan(tmp_path)
    assert summary["ok"] and summary["plan_count"] == 1
    plan = json.loads((tmp_path / "s5_plan.txt").read_text(encoding="utf-8"))
    assert upgrade.validate_plan(plan, s1, s2, s3, s4) == []
    proposed = next(row for row in plan["dispositions"] if row["name"] == "vulnerable")
    assert proposed["plan_status"] == "pending_compatibility"
    proposed["evidence_refs"] = ["s2:nonexistent"]
    assert any("缺失或错位" in error for error in upgrade.validate_plan(plan, s1, s2, s3, s4))


@pytest.mark.asyncio
async def test_specialist_review_uses_one_schema_feedback_then_succeeds(tmp_path, monkeypatch):
    import agent.parallel_analysis as parallel

    class Reviewer:
        calls = 0

        async def ainvoke(self, state):
            self.calls += 1
            content = "broken JSON" if self.calls == 1 else '{"observations":["需要人工确认"]}'
            message = type("Message", (), {"content": content,
                                           "usage_metadata": {"total_tokens": 10}})()
            return {"messages": [message]}

    reviewer = Reviewer()

    async def agents():
        return {"S4": reviewer}

    monkeypatch.setattr(parallel, "_get_review_agents", agents)
    monkeypatch.delenv("DEPGUARD_LLM_REVIEW", raising=False)
    result = await parallel._review_branch("S4", {"status": "degraded_no_source_evidence",
                                                   "scan_summary": {"packages_scanned": 0}}, tmp_path)
    assert result["status"] == "completed"
    assert result["feedback_used"] is True
    assert result["model_tokens"] == 20
    assert reviewer.calls == 2


def test_s6_rejects_unverified_success_claim(tmp_path):
    from types import SimpleNamespace
    from api.context import set_session_context, reset_session_context
    from agent.planner import PlanTracker, default_scan_plan
    from agent.scan_guard import ScanExecution

    (tmp_path / "batch_plan_s2.json").write_text("{}", encoding="utf-8")
    tracker = PlanTracker(default_scan_plan())
    runner = ScanExecution(tracker)
    token = set_session_context(str(tmp_path))
    try:
        runner.record_call({"id": "s6", "name": "task",
                            "args": {"subagent_type": "报告与审查助手"}})
        runner.record_result(SimpleNamespace(tool_call_id="s6", status="success",
                                             content='{"ok":true,"report_file":"dependency_risk_report.md","sbom_file":"sbom.cdx.json"}'))
    finally:
        reset_session_context(token)
    assert tracker._by_id["S6"].status == "failed"
