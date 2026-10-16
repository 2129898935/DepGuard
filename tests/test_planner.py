"""M4 —— 结构化 Plan/Replan 单元测试。"""
from agent.planner import PlanTracker, default_scan_plan, subagent_to_step_id, tool_to_step_id


def test_default_scan_plan_has_six_steps():
    plan = default_scan_plan()
    assert len(plan.steps) == 6
    assert [step.id for step in plan.steps] == ["S1", "S2", "S3", "S4", "S5", "S6"]


def test_mark_and_progress():
    t = PlanTracker(default_scan_plan())
    assert t.done_count() == 0
    t.mark("S1", "done")
    t.mark("S2", "done")
    assert t.done_count() == 2
    assert t.is_complete() is False


def test_is_complete():
    t = PlanTracker(default_scan_plan())
    for s in t.plan.steps:
        t.mark(s.id, "done")
    assert t.is_complete() is True


def test_replan_after_consecutive_failures():
    t = PlanTracker(default_scan_plan(), replan_after_failures=3)
    t.mark("S1", "failed")
    t.mark("S2", "failed")
    assert t.should_replan() is False  # 只有 2 次失败
    t.mark("S3", "failed")
    assert t.should_replan() is True   # 连续 3 次失败 → Replan


def test_success_resets_failure_count():
    t = PlanTracker(default_scan_plan(), replan_after_failures=3)
    t.mark("S1", "failed")
    t.mark("S2", "done")   # 成功重置失败计数
    t.mark("S3", "failed")
    assert t.should_replan() is False


def test_summary_contains_steps():
    summary = PlanTracker(default_scan_plan()).summary()
    assert "S1" in summary and "S6" in summary


def test_tool_to_step_id():
    assert tool_to_step_id("query_osv_vulns") == "S2"
    assert tool_to_step_id("parse_requirements_tool") == "S1"
    assert tool_to_step_id("query_package_info") == "S3"
    assert tool_to_step_id("generate_markdown") == "S6"
    assert tool_to_step_id("query_advisory") == "S2"   # GHSA 详情也属查漏洞
    assert tool_to_step_id("analyze_dependency_usage") == "S4"
    assert tool_to_step_id("query_releases") == "S5"
    assert tool_to_step_id("internet_search") is None  # 旧 Demo 工具不映射


def test_subagent_to_step_id():
    assert subagent_to_step_id("依赖解析助手") == "S1"
    assert subagent_to_step_id("报告与审查助手") == "S6"
    assert subagent_to_step_id("市场情报助手") is None


def test_dag_exposes_parallel_wave():
    tracker = PlanTracker(default_scan_plan())
    assert [step.id for step in tracker.ready_steps()] == ["S1"]

    tracker.mark("S1", "done")
    ready = tracker.ready_steps()
    assert [step.id for step in ready] == ["S2", "S3", "S4"]
    assert {step.parallel_group for step in ready} == {"analysis"}

    for step_id in ("S2", "S3", "S4"):
        tracker.mark(step_id, "done")
    assert [step.id for step in tracker.ready_steps()] == ["S5"]
