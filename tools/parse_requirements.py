"""解析 requirements.txt 为依赖清单（对齐 M11）。"""
import json

from langchain_core.tools import tool
from packaging.requirements import Requirement


def parse_requirements(content: str) -> list[dict]:
    """解析 requirements.txt 内容，返回 [{"name": 包名, "version": 版本}]。

    忽略空行、注释、以及 -r/--index-url 等非依赖行；解析失败的行直接跳过。
    包名会按 PEP 503 规范小写化（packaging 库的行为）。
    """
    packages = []
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # 去掉行内注释
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            req = Requirement(line)
        except Exception:
            continue
        # 优先取 == 精确版本；没有则回退到完整 specifier（如 >=4.0）
        version = ""
        for spec in req.specifier:
            if spec.operator == "==":
                version = spec.version
                break
        if not version and str(req.specifier):
            version = str(req.specifier)
        packages.append({"name": req.name, "version": version})
    return packages


@tool
def parse_requirements_tool(content: str) -> str:
    """解析 requirements.txt 文本内容，返回依赖清单 JSON（供漏洞情报子智能体使用）。"""
    return json.dumps(parse_requirements(content), ensure_ascii=False)
