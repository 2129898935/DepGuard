"""deps.dev 数据源工具：按精确版本查询许可证、弃用状态与依赖。"""
import json
from urllib.parse import quote

import httpx
from langchain_core.tools import tool

DEPSDEV_BASE = "https://api.deps.dev/v3alpha"


def _segment(value: str) -> str:
    return quote(str(value), safe="")


def _get_json(url: str) -> dict:
    response = httpx.get(url, timeout=10)
    response.raise_for_status()
    return response.json()


@tool
def query_package_info(name: str, version: str = "", system: str = "PYPI") -> str:
    """查询包的具体版本信息；许可证必须来自 GetVersion，不能从 GetPackage 摘要猜测。"""
    system = system.upper()
    try:
        package_url = f"{DEPSDEV_BASE}/systems/{_segment(system)}/packages/{_segment(name)}"
        selected_version = version.strip()
        if not selected_version:
            package = _get_json(package_url)
            versions = package.get("versions", [])
            default = next((item for item in versions if item.get("isDefault")), None)
            if default is None:
                return json.dumps({
                    "ok": False,
                    "source": "deps.dev",
                    "name": name,
                    "error": "包没有可确认的默认版本；请显式传入 version",
                }, ensure_ascii=False)
            selected_version = str(default.get("versionKey", {}).get("version") or "")
        if not selected_version:
            return json.dumps({"ok": False, "source": "deps.dev", "name": name, "error": "版本为空"}, ensure_ascii=False)

        version_url = package_url + f"/versions/{_segment(selected_version)}"
        detail = _get_json(version_url)
        return json.dumps({
            "ok": True,
            "source": "deps.dev",
            "name": detail.get("versionKey", {}).get("name") or name,
            "system": detail.get("versionKey", {}).get("system") or system,
            "version": detail.get("versionKey", {}).get("version") or selected_version,
            "is_default": detail.get("isDefault"),
            "is_deprecated": detail.get("isDeprecated"),
            "deprecated_reason": detail.get("deprecatedReason") or "",
            "published_at": detail.get("publishedAt"),
            "licenses": detail.get("licenses", []),
            "license_details": detail.get("licenseDetails", []),
            "links": detail.get("links", []),
            "advisory_ids": [item.get("id") for item in detail.get("advisoryKeys", []) if item.get("id")],
        }, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({
            "ok": False,
            "source": "deps.dev",
            "name": name,
            "version": version,
            "error": str(exc),
        }, ensure_ascii=False)


@tool
def query_dependencies(name: str, version: str, system: str = "PYPI") -> str:
    """查询某个精确版本的解析后依赖图，并区分直接与间接依赖。"""
    try:
        url = (
            f"{DEPSDEV_BASE}/systems/{_segment(system.upper())}/packages/{_segment(name)}"
            f"/versions/{_segment(version)}:dependencies"
        )
        data = _get_json(url)
        nodes = []
        for node in data.get("nodes", []):
            key = node.get("versionKey", {})
            nodes.append({
                "name": key.get("name"),
                "version": key.get("version"),
                "relation": node.get("relation") or "INDIRECT",
            })
        return json.dumps({
            "ok": not bool(data.get("error")),
            "source": "deps.dev",
            "name": name,
            "version": version,
            "error": data.get("error") or "",
            "dependencies": nodes,
            "direct_dependencies": [node for node in nodes if node["relation"] == "DIRECT"],
            "transitive_dependencies": [node for node in nodes if node["relation"] != "DIRECT"],
        }, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({
            "ok": False,
            "source": "deps.dev",
            "name": name,
            "version": version,
            "error": str(exc),
            "dependencies": [],
        }, ensure_ascii=False)
