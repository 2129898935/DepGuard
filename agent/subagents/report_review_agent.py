"""阶段 6：报告生成与证据审查子智能体。"""
from agent.prompts import sub_agents_content
from agent.finalize_scan import finalize_dependency_scan

_cfg = sub_agents_content["report_review"]
report_review_agent = {
    "name": _cfg["name"],
    "description": _cfg["description"],
    "system_prompt": _cfg["system_prompt"],
    "tools": [finalize_dependency_scan],
}
