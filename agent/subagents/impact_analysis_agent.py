"""阶段 4：源码影响分析子智能体。"""
from agent.prompts import sub_agents_content
from tools.impact_analysis_tool import analyze_dependency_usage

_cfg = sub_agents_content["impact_analysis"]
impact_analysis_agent = {
    "name": _cfg["name"],
    "description": _cfg["description"],
    "system_prompt": _cfg["system_prompt"],
    "tools": [analyze_dependency_usage],
}
