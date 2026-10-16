"""阶段 1：依赖解析子智能体。"""
from agent.prompts import sub_agents_content
from tools.osv_scanner_tool import scan_repo_with_osv_scanner
from tools.parse_requirements import parse_requirements_tool
from tools.upload_file_read_tool import read_file_content

_cfg = sub_agents_content["dependency_parser"]
dependency_parser_agent = {
    "name": _cfg["name"],
    "description": _cfg["description"],
    "system_prompt": _cfg["system_prompt"],
    "tools": [read_file_content, parse_requirements_tool, scan_repo_with_osv_scanner],
}
