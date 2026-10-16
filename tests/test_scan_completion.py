"""Regression tests: a scan cannot finish on an unsupported final answer."""
import json
from types import SimpleNamespace

import pytest

import agent.main_agent as main
from agent.planner import PlanTracker, default_scan_plan
from agent.scan_guard import ScanExecution, requires_full_scan, scan_completion_errors, prepare_requirements_evidence, build_deliverables_from_evidence
from agent.report_builder import deduplicate_vulnerabilities, render_report
from tools.sbom_tool import build_sbom


def _ai(content="", tool_calls=None):
    return SimpleNamespace(content=content, tool_calls=tool_calls or [], usage_metadata={}, id=None)


def _call(call_id, name, **kwargs):
    return {"id": call_id, "name": name, "args": kwargs}


def _tool(call_id, content, status="success"):
    return SimpleNamespace(tool_call_id=call_id, content=content, status=status)


def test_manifest_requires_scan_and_missing_artifacts_fail(tmp_path):
    assert requires_full_scan("分析上传文件", ["requirements2.txt"])
    assert not requires_full_scan("你好", [])
    tracker = PlanTracker(default_scan_plan())
    errors = scan_completion_errors(tracker, tmp_path, ["requirements2.txt"])
    assert any("S1" in error for error in errors)
    assert any("报告不存在" in error for error in errors)
    assert any("SBOM 不存在" in error for error in errors)


def test_stage_completes_only_after_successful_tool_response():
    tracker = PlanTracker(default_scan_plan())
    run = ScanExecution(tracker)
    run.record_call(_call("one", "task", subagent_type="依赖解析助手"))
    assert tracker.done_count() == 0
    run.record_result(_tool("one", "parse failed", "error"))
    assert tracker._by_id["S1"].status == "failed"
    run.record_call(_call("two", "task", subagent_type="依赖解析助手"))
    run.record_result(_tool("two", '{"components": [{"name": "requests"}]}'))
    assert tracker._by_id["S1"].status == "done"
    run.record_call(_call("three", "parallel_dependency_analysis", component_evidence="[]"))
    assert tracker.done_count() == 1
    result = {"stages": {stage: {"status": "completed"} for stage in ("S2", "S3", "S4")}}
    run.record_result(_tool("three", json.dumps(result)))
    assert tracker.done_count() == 4


class FakeGraph:
    def __init__(self, complete_on_retry=False):
        self.calls = 0
        self.complete_on_retry = complete_on_retry

    async def astream(self, state, config):
        self.calls += 1
        if self.calls == 1 or not self.complete_on_retry:
            yield {"model": {"messages": [_ai("扫描已完成")]}}
            return
        sequence = [
            ("a", "task", {"subagent_type": "依赖解析助手"}, '{"components": [{"name": "requests", "version": "2.32.3"}]}'),
            ("b", "parallel_dependency_analysis", {"component_evidence": "[]"}, json.dumps({"stages": {s: {"status": "completed"} for s in ("S2", "S3", "S4")}})),
            ("c", "task", {"subagent_type": "升级规划助手"}, '{"upgrade": []}'),
            ("d", "task", {"subagent_type": "报告与审查助手"}, '{"reviewed": true}'),
        ]
        for call_id, name, args, result in sequence:
            yield {"model": {"messages": [_ai(tool_calls=[_call(call_id, name, **args)])]}}
            yield {"tools": {"messages": [_tool(call_id, result)]}}
        from api.context import get_session_context
        from pathlib import Path
        directory = Path(get_session_context())
        sbom = build_sbom([{"name": "requests", "version": "2.32.3"}])
        (directory / "sbom.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
        (directory / "dependency_risk_report.md").write_text(
            render_report({"components": [{"name": "requests", "version": "2.32.3"}],
                           "source_files": ["requirements2.txt"]},
                          {"vulnerabilities": []}, {"components": []}, {}, "{}", sbom),
            encoding="utf-8")
        yield {"model": {"messages": [_ai("已生成并校验报告。")]}}


@pytest.mark.asyncio
@pytest.mark.parametrize("complete_on_retry,expected_status", [(False, "failed"), (True, "done")])
async def test_scan_recovers_or_fails_without_false_done(tmp_path, monkeypatch, complete_on_retry, expected_status):
    monkeypatch.setenv("DEPGUARD_MANIFEST_FAST_PATH", "0")
    monkeypatch.setattr(main, "project_root_path", tmp_path)
    thread_id = "scan-test"
    uploaded = tmp_path / "updated" / f"session_{thread_id}"
    uploaded.mkdir(parents=True)
    (uploaded / "requirements2.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    fake = FakeGraph(complete_on_retry)

    async def get_fake_agent():
        return fake

    statuses, results, events = [], [], []
    monkeypatch.setattr(main, "get_agent", get_fake_agent)
    monkeypatch.setattr(main, "update_session_status", lambda *args: statuses.append(args))
    monkeypatch.setattr("db.session_store.update_session_metrics", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.monitor, "_emit", lambda *args: events.append(args))
    monkeypatch.setattr(main.monitor, "report_session_dir", lambda *args: None)
    monkeypatch.setattr(main.monitor, "report_assistant", lambda *args: None)
    monkeypatch.setattr(main.monitor, "report_task_result", lambda result: results.append(result))

    await main.run_deep_agent("分析上传的 requirements2.txt，生成漏洞清单和报告", thread_id)
    assert fake.calls == 2
    assert statuses[-1][1] == expected_status, statuses
    assert len(results) == (1 if complete_on_retry else 0)
    if complete_on_retry:
        assert (tmp_path / "output" / f"session_{thread_id}" / "sbom.cdx.json").is_file()
    else:
        assert "扫描未完成" in statuses[-1][2]
        assert any(event[0] == "scan_recovery" for event in events)


def test_large_requirements_is_preserved_in_s1_artifact(tmp_path):
    from pathlib import Path
    from api.context import set_session_context, reset_session_context
    source = Path(__file__).parents[1] / "requirements2.txt"
    (tmp_path / source.name).write_bytes(source.read_bytes())
    evidence = prepare_requirements_evidence(tmp_path, [source.name])
    assert evidence["total_components"] == 120
    stored = json.loads((tmp_path / "s1_components.json").read_text(encoding="utf-8"))
    assert len(stored["components"]) == 120
    token = set_session_context(str(tmp_path))
    try:
        tracker = PlanTracker(default_scan_plan())
        for step in tracker.plan.steps:
            tracker.mark(step.id, "done")
        sbom = build_sbom(stored["components"])
        (tmp_path / "sbom.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
        (tmp_path / "dependency_risk_report.md").write_text(
            render_report(stored, {"vulnerabilities": []}, {"components": []}, {}, "{}", sbom),
            encoding="utf-8")
        assert scan_completion_errors(tracker, tmp_path, [source.name]) == []
        sbom["components"].pop()
        (tmp_path / "sbom.cdx.json").write_text(json.dumps(sbom), encoding="utf-8")
        errors = scan_completion_errors(tracker, tmp_path, [source.name])
        assert any("未覆盖" in error for error in errors)
    finally:
        reset_session_context(token)


def test_s5_evidence_generates_valid_report_and_sbom(tmp_path):
    from api.context import set_session_context, reset_session_context
    (tmp_path / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    prepare_requirements_evidence(tmp_path, ["requirements.txt"])
    (tmp_path / "s2_evidence.json").write_text(json.dumps({
        "source_status": {"osv": "ok"},
        "vulnerabilities": [{
            "canonical_id": "GHSA-test-one", "affected_component": "requests",
            "ratings": [{"source": "GHSA", "cvss_version": "CVSS_V3",
                         "score": 5.3, "severity": "medium"}],
            "fixed_versions": ["2.32.4"], "references": ["https://example.com/advisory"],
            "evidence_status": "confirmed",
        }],
    }), encoding="utf-8")
    (tmp_path / "s3_evidence.json").write_text('{"components": []}', encoding="utf-8")
    (tmp_path / "s4_evidence.json").write_text('{"hits": []}', encoding="utf-8")
    (tmp_path / "s5_plan.txt").write_text("升级到 2.32.4；运行 pytest；失败时回滚。", encoding="utf-8")
    token = set_session_context(str(tmp_path))
    try:
        assert build_deliverables_from_evidence(tmp_path)
        tracker = PlanTracker(default_scan_plan())
        for step in tracker.plan.steps:
            tracker.mark(step.id, "done")
        assert scan_completion_errors(tracker, tmp_path, ["requirements.txt"]) == []
        report = (tmp_path / "dependency_risk_report.md").read_text(encoding="utf-8")
        assert "GHSA-test-one" in report
        assert "2.32.4" in report
        assert "## 执行摘要" in report
        assert "## 许可证与维护性" in report
        assert '"components": []' not in report
        sbom = json.loads((tmp_path / "sbom.cdx.json").read_text(encoding="utf-8"))
        assert len(sbom["components"]) == 1
        assert len(sbom["vulnerabilities"]) == 1
    finally:
        reset_session_context(token)


def test_truncated_s5_result_does_not_complete_stage(tmp_path):
    from api.context import set_session_context, reset_session_context
    tracker = PlanTracker(default_scan_plan())
    run = ScanExecution(tracker)
    token = set_session_context(str(tmp_path))
    try:
        run.record_call(_call("s5", "task", subagent_type="升级规划助手"))
        run.record_result(_tool("s5", '{"upgrade": [{"name": "requests", "version": "2.'))
        assert tracker._by_id["S5"].status == "failed"
        assert not (tmp_path / "s5_plan.txt").exists()
    finally:
        reset_session_context(token)


@pytest.mark.asyncio
async def test_manifest_scan_uses_bounded_main_orchestrator(tmp_path, monkeypatch):
    monkeypatch.delenv("DEPGUARD_MANIFEST_FAST_PATH", raising=False)
    monkeypatch.setattr(main, "project_root_path", tmp_path)
    uploaded = tmp_path / "updated" / "session_fast-path-test"
    uploaded.mkdir(parents=True)
    (uploaded / "requirements.txt").write_text("requests==2.32.3\n", encoding="utf-8")
    calls = []

    async def forbidden_deep_agent():
        raise AssertionError("manifest fast path must not build the open-ended graph")

    async def fake_parallel(_):
        calls.append("parallel")
        return {"parallel_group_id": "fixture", "status": "completed",
                "stages": {stage: {"status": "completed"} for stage in ("S2", "S3", "S4")}}

    async def fake_plan(_):
        calls.append("plan")
        return {"ok": True, "plan_count": 1, "manual_review_count": 0}

    monkeypatch.setattr(main, "get_agent", forbidden_deep_agent)
    monkeypatch.setattr(main, "run_parallel_analysis", fake_parallel)
    monkeypatch.setattr(main, "build_plan", fake_plan)
    monkeypatch.setattr(main.finalize_dependency_scan, "func", lambda: json.dumps(
        {"ok": True, "components": 1, "vulnerabilities": 1}))
    monkeypatch.setattr(main, "scan_completion_errors", lambda *args: [])
    monkeypatch.setattr(main, "update_session_status", lambda *args: calls.append(args[1]))
    monkeypatch.setattr("db.session_store.update_session_metrics", lambda *args, **kwargs: None)
    monkeypatch.setattr(main.monitor, "report_session_dir", lambda *args: None)
    monkeypatch.setattr(main.monitor, "report_assistant", lambda *args: None)
    monkeypatch.setattr(main.monitor, "report_agent_status", lambda *args: None)
    monkeypatch.setattr(main.monitor, "report_task_result", lambda *args: None)
    monkeypatch.setattr(main.monitor, "_emit", lambda *args: None)
    for stage in ("s2", "s3", "s4"):
        folder = tmp_path / "output" / "session_fast-path-test"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{stage}_evidence.json").write_text(
            '{"specialist_review":{"model_tokens":3}}', encoding="utf-8")

    await main.run_deep_agent("请审计上传的依赖", "fast-path-test")
    assert calls == ["running", "parallel", "plan", "done"]


def test_ghsa_and_pysec_aliases_count_as_one():
    merged = deduplicate_vulnerabilities([
        {"canonical_id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-12345", "PYSEC-2026-1"],
         "affected_component": "requests", "affected_ecosystem": "PyPI",
         "fixed_versions": ["2.32.4"], "evidence_status": "confirmed"},
        {"canonical_id": "PYSEC-2026-1", "aliases": ["GHSA-aaaa-bbbb-cccc", "CVE-2026-12345"],
         "affected_component": "requests", "affected_ecosystem": "PyPI",
         "fixed_versions": ["2.32.4"], "evidence_status": "confirmed"},
    ])
    assert len(merged) == 1
    assert merged[0]["canonical_id"] == "GHSA-aaaa-bbbb-cccc"
    assert "PYSEC-2026-1" in merged[0]["aliases"]
