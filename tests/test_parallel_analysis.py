import asyncio
import time

import pytest

import agent.parallel_analysis as parallel


class FakeAgent:
    def __init__(self, stage_id, timeline):
        self.stage_id = stage_id
        self.timeline = timeline

    async def ainvoke(self, state):
        self.timeline.append((self.stage_id, "start", time.perf_counter()))
        await asyncio.sleep(0.12)
        self.timeline.append((self.stage_id, "end", time.perf_counter()))
        payload = {"S2": '{"vulnerabilities":[]}', "S3": '{"components":[]}',
                   "S4": '{"ok":true}'}[self.stage_id]
        return {"messages": [type("Message", (), {"content": payload})()]}


@pytest.mark.asyncio
async def test_s2_s3_s4_really_run_concurrently(monkeypatch):
    timeline = []
    agents = {stage: FakeAgent(stage, timeline) for stage in ("S2", "S3", "S4")}

    async def fake_get_agents():
        return agents

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)

    started = time.perf_counter()
    result = await parallel.run_parallel_analysis("[]")
    elapsed = time.perf_counter() - started

    assert result["status"] == "completed"
    assert set(result["stages"]) == {"S2", "S3", "S4"}
    assert elapsed < 0.28  # 串行至少约 0.36 秒
    starts = [item[2] for item in timeline if item[1] == "start"]
    first_end = min(item[2] for item in timeline if item[1] == "end")
    assert max(starts) < first_end  # 三个分支都在任一分支结束前启动


@pytest.mark.asyncio
async def test_can_retry_only_failed_branch(monkeypatch):
    timeline = []
    agents = {stage: FakeAgent(stage, timeline) for stage in ("S2", "S3", "S4")}

    async def fake_get_agents():
        return agents

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)

    result = await parallel.run_parallel_analysis("[]", stage_ids=["S3"])

    assert set(result["stages"]) == {"S3"}
    assert {item[0] for item in timeline} == {"S3"}


def test_main_agent_registers_parallel_tool():
    from pathlib import Path

    source = (Path(__file__).parents[1] / "agent" / "main_agent.py").read_text(encoding="utf-8")
    assert "tools=[read_file_content, parallel_dependency_analysis]" in source
    assert "S1 → [S2、S3、S4 并行] → S5 → S6" in source


def test_frontend_handles_parallel_events():
    from pathlib import Path

    source = (Path(__file__).parents[1] / "api" / "static" / "index.html").read_text(encoding="utf-8")
    assert "case 'parallel_group'" in source
    assert "case 'agent_status'" in source
    assert "并行运行中" in source


@pytest.mark.asyncio
async def test_parallel_monitor_exposes_three_running_branches(monkeypatch):
    timeline = []
    events = []
    agents = {stage: FakeAgent(stage, timeline) for stage in ("S2", "S3", "S4")}

    async def fake_get_agents():
        return agents

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(
        parallel.monitor,
        "report_agent_status",
        lambda stage, name, status, group, *rest: events.append((stage, status)),
    )
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)

    await parallel.run_parallel_analysis("[]")

    started_indexes = [events.index((stage, "started")) for stage in ("S2", "S3", "S4")]
    completed_indexes = [events.index((stage, "completed")) for stage in ("S2", "S3", "S4")]
    assert max(started_indexes) < min(completed_indexes)


def test_main_agent_limits_repeated_stage_calls():
    from pathlib import Path

    source = (Path(__file__).parents[1] / "agent" / "main_agent.py").read_text(encoding="utf-8")
    assert "subagent_call_counts[subagent_type] > 2" in source
    assert "阶段子 Agent 重复调用超过上限" in source


@pytest.mark.asyncio
async def test_parallel_response_returns_evidence_files_not_long_inline_payload(monkeypatch, tmp_path):
    from api.context import set_session_context, reset_session_context
    agents = {stage: FakeAgent(stage, []) for stage in ("S2", "S3", "S4")}

    async def fake_get_agents():
        return agents

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)
    token = set_session_context(str(tmp_path))
    try:
        result = await parallel.run_parallel_analysis('{"components": []}')
    finally:
        reset_session_context(token)
    assert result["status"] == "completed"
    for stage in ("S2", "S3", "S4"):
        info = result["stages"][stage]
        assert "evidence" not in info
        assert info["evidence_file"] == f"{stage.lower()}_evidence.json"
        assert (tmp_path / info["evidence_file"]).is_file()


@pytest.mark.asyncio
async def test_invalid_s2_json_uses_structured_osv_fallback(monkeypatch, tmp_path):
    from api.context import set_session_context, reset_session_context

    class InvalidAgent:
        async def ainvoke(self, state):
            return {"messages": [type("Message", (), {"content": '{"vulnerabilities": [broken'})()]}

    async def fake_get_agents():
        return {"S2": InvalidAgent()}

    async def fake_fallback(component_evidence):
        return {"stage": "S2", "components": [{"name": "requests"}],
                "vulnerabilities": [], "source_status": {"osv": "ok"}}

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(parallel, "_fallback_vulnerability_evidence", fake_fallback)
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)
    token = set_session_context(str(tmp_path))
    try:
        result = await parallel.run_parallel_analysis('{"components":[{"name":"requests"}]}', stage_ids=["S2"])
    finally:
        reset_session_context(token)
    assert result["status"] == "completed"
    assert "OSV" in result["stages"]["S2"]["degradation"]
    assert (tmp_path / "s2_evidence.json").is_file()


@pytest.mark.asyncio
async def test_s2_fallback_requests_full_details_and_marks_remaining_ids(monkeypatch):
    import json
    calls = []

    def fake_osv(names, ecosystem, versions, max_details):
        calls.append(max_details)
        return json.dumps({"detail_limit_reached": False, "packages": [{
            "name": "requests", "version": "2.32.3", "omitted_ids": ["PYSEC-2026-2"],
            "vulnerabilities": [{
                "id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-12345"],
                "database_specific": {"severity": "HIGH"},
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}],
                "fixed_versions": ["2.32.4"], "references": [],
            }],
        }]})

    monkeypatch.setattr(parallel.query_osv_vulns, "func", fake_osv)
    result = await parallel._fallback_vulnerability_evidence(
        '{"components":[{"name":"requests","version":"2.32.3"}]}')
    assert calls == [1000]
    assert result["source_status"]["id_only_count"] == 1
    assert result["vulnerabilities"][0]["ratings"][0]["severity"] == "high"


@pytest.mark.asyncio
async def test_invalid_s3_json_uses_depsdev_fallback(monkeypatch, tmp_path):
    import json
    from api.context import set_session_context, reset_session_context

    class InvalidAgent:
        async def ainvoke(self, state):
            return {"messages": [type("Message", (), {"content": "bad license response"})()]}

    async def fake_get_agents():
        return {"S3": InvalidAgent()}

    monkeypatch.setattr(parallel, "_get_agents", fake_get_agents)
    monkeypatch.setattr(parallel.query_package_info, "func", lambda name, version, system: json.dumps({
        "ok": True, "licenses": ["Apache-2.0"], "is_deprecated": False
    }))
    monkeypatch.setattr(parallel.monitor, "report_agent_status", lambda *args, **kwargs: None)
    monkeypatch.setattr(parallel.monitor, "report_parallel_group", lambda *args, **kwargs: None)
    token = set_session_context(str(tmp_path))
    try:
        result = await parallel.run_parallel_analysis(
            '{"components":[{"name":"requests","version":"2.32.3"}]}', stage_ids=["S3"]
        )
    finally:
        reset_session_context(token)
    assert result["status"] == "completed"
    assert result["stages"]["S3"]["component_count"] == 1
    evidence = json.loads((tmp_path / "s3_evidence.json").read_text(encoding="utf-8"))
    assert evidence["components"][0]["licenses"] == ["Apache-2.0"]
