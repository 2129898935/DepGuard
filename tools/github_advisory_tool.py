"""GitHub Advisory 数据源工具（对齐 M11）：查询 GHSA 通告详情。

OSV 返回的 aliases 里含 GHSA-ID，可用本工具补充 GitHub Advisory 的详情。
"""
import json
import os

import httpx
from dotenv import find_dotenv, load_dotenv
from langchain_core.tools import tool

load_dotenv(find_dotenv())

ADVISORY_URL = "https://api.github.com/advisories"


def _headers() -> dict:
    """构造请求头，带 GH_TOKEN 时自动加 Authorization 避免限流。"""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@tool
def query_advisory(ghsa_id: str) -> str:
    """查询 GitHub Advisory 上指定 GHSA 的通告详情（严重度/摘要/发布时间）。"""
    try:
        resp = httpx.get(
            f"{ADVISORY_URL}/{ghsa_id}",
            headers=_headers(),
            timeout=10,
        )
        resp.raise_for_status()
        a = resp.json()
        return json.dumps(
            {
                "ghsa_id": a.get("ghsa_id"),
                "severity": a.get("severity"),
                "summary": a.get("summary"),
                "published_at": a.get("published_at"),
                "cvss": a.get("cvss", {}),
                "cvss_severities": a.get("cvss_severities", {}),
                "cve_id": a.get("cve_id"),
                "vulnerabilities": [
                    {
                        "package": item.get("package"),
                        "vulnerable_version_range": item.get("vulnerable_version_range"),
                        "first_patched_version": item.get("first_patched_version"),
                    }
                    for item in a.get("vulnerabilities", [])
                ],
            },
            ensure_ascii=False,
        )
    except Exception as e:
        return f"GitHub Advisory 查询失败：{e}"
