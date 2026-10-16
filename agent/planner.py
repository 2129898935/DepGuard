"""DepGuard 六阶段结构化 Plan / Replan 与进度映射。"""
from pydantic import BaseModel, Field


class PlanStep(BaseModel):
    id: str
    description: str
    depends_on: list[str] = Field(default_factory=list)
    parallel_group: str | None = None
    status: str = "pending"  # pending / running / done / failed


class Plan(BaseModel):
    name: str
    steps: list[PlanStep]


def default_scan_plan() -> Plan:
    """DepGuard 默认六阶段 DAG：S1 → [S2,S3,S4] → S5 → S6。"""
    return Plan(
        name="depguard-analysis",
        steps=[
            PlanStep(id="S1", description="解析并标准化依赖"),
            PlanStep(id="S2", description="聚合并去重漏洞情报", depends_on=["S1"], parallel_group="analysis"),
            PlanStep(id="S3", description="评估许可证与维护性", depends_on=["S1"], parallel_group="analysis"),
            PlanStep(id="S4", description="分析源码引用与影响", depends_on=["S1"], parallel_group="analysis"),
            PlanStep(id="S5", description="制定最小安全升级路径", depends_on=["S2", "S3", "S4"]),
            PlanStep(id="S6", description="生成并审查报告与 SBOM", depends_on=["S5"]),
        ],
    )


def tool_to_step_id(tool_name: str) -> str | None:
    """把确定性工具映射到六阶段步骤。"""
    n = (tool_name or "").lower()
    if any(k in n for k in ("parse", "requirements", "read_file", "osv_scanner")):
        return "S1"
    if any(k in n for k in ("osv", "advisory", "cvss", "vuln", "cve")):
        return "S2"
    if any(k in n for k in ("package_info", "dependencies", "license", "repo_health")):
        return "S3"
    if any(k in n for k in ("impact", "usage", "reachability")):
        return "S4"
    if any(k in n for k in ("release", "upgrade")):
        return "S5"
    if any(k in n for k in ("sbom", "markdown", "pdf", "report")):
        return "S6"
    return None


def subagent_to_step_id(subagent_name: str) -> str | None:
    """把子智能体显示名映射到六阶段步骤。"""
    name = subagent_name or ""
    mapping = {
        "依赖解析助手": "S1",
        "漏洞情报助手": "S2",
        "许可证与维护性助手": "S3",
        "影响分析助手": "S4",
        "升级规划助手": "S5",
        "报告与审查助手": "S6",
    }
    return mapping.get(name)


class PlanTracker:
    """追踪计划进度，判定是否完成 / 是否该 Replan。"""

    def __init__(self, plan: Plan, replan_after_failures: int = 3):
        self.plan = plan
        self.replan_after_failures = replan_after_failures
        self._by_id = {s.id: s for s in plan.steps}
        self._consecutive_failures = 0

    def mark(self, step_id: str, status: str) -> None:
        if status not in {"pending", "running", "done", "failed"}:
            raise ValueError(f"不支持的计划状态: {status}")
        if step_id in self._by_id:
            self._by_id[step_id].status = status
        if status == "failed":
            self._consecutive_failures += 1
        elif status == "done":
            self._consecutive_failures = 0

    def done_count(self) -> int:
        return sum(1 for s in self.plan.steps if s.status == "done")

    def ready_steps(self) -> list[PlanStep]:
        """返回依赖已完成、可以立即调度的步骤；同 parallel_group 可并行启动。"""
        done = {step.id for step in self.plan.steps if step.status == "done"}
        return [
            step for step in self.plan.steps
            if step.status == "pending" and set(step.depends_on).issubset(done)
        ]

    def is_complete(self) -> bool:
        return all(s.status == "done" for s in self.plan.steps)

    def should_replan(self) -> bool:
        return self._consecutive_failures >= self.replan_after_failures

    def summary(self) -> str:
        return "\n".join(f"- {s.id} [{s.status}] {s.description}" for s in self.plan.steps)
