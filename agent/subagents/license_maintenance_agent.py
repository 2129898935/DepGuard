"""阶段 3：许可证、维护性与内部策略子智能体。"""
from agent.prompts import sub_agents_content
from tools.depsdev_tool import query_dependencies, query_package_info
from tools.github_repo_tool import query_repo_health
from tools.ragflow_tools import create_ask_delete, get_assistant_list

_cfg = sub_agents_content["license_maintenance"]
license_maintenance_agent = {
    "name": _cfg["name"],
    "description": _cfg["description"],
    "system_prompt": _cfg["system_prompt"],
    "tools": [query_package_info, query_dependencies, query_repo_health, get_assistant_list, create_ask_delete],
}
