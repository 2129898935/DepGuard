"""GitHub 仓库工具（对齐 M11）：查询仓库维护性信号。"""
import json
import os

import httpx
from dotenv import find_dotenv, load_dotenv
from langchain_core.tools import tool

load_dotenv(find_dotenv())

GITHUB_API = "https://api.github.com"


def _headers() -> dict:
    """构造请求头，带 GH_TOKEN 时自动加 Authorization 避免限流。"""
    headers = {"Accept": "application/vnd.github+json"}
    token = os.getenv("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@tool
def query_repo_health(owner: str, repo: str) -> str:
    """查询 GitHub 仓库的维护性信号（star / open issues / 最后推送时间 / 是否归档）。"""
    try:
        resp = httpx.get(f"{GITHUB_API}/repos/{owner}/{repo}", headers=_headers(), timeout=10)
        resp.raise_for_status()
        d = resp.json()
        return json.dumps(
            {
                "full_name": d.get("full_name"),
                "stars": d.get("stargazers_count"),
                "open_issues": d.get("open_issues_count"),
                "pushed_at": d.get("pushed_at"),
                "archived": d.get("archived"),
            },
            ensure_ascii=False,
        )
    except Exception as e:
        return f"GitHub 仓库查询失败：{e}"


@tool
def query_releases(owner: str, repo: str, limit: int = 10) -> str:
    """查询 GitHub 仓库最近的 Release，供升级规划识别版本说明和 breaking changes。"""
    try:
        safe_limit = max(1, min(limit, 30))
        resp = httpx.get(
            f"{GITHUB_API}/repos/{owner}/{repo}/releases",
            headers=_headers(),
            params={"per_page": safe_limit},
            timeout=10,
        )
        resp.raise_for_status()
        releases = []
        for item in resp.json()[:safe_limit]:
            releases.append(
                {
                    "tag_name": item.get("tag_name"),
                    "name": item.get("name"),
                    "published_at": item.get("published_at"),
                    "prerelease": item.get("prerelease"),
                    "body": (item.get("body") or "")[:1000],
                    "html_url": item.get("html_url"),
                }
            )
        return json.dumps(releases, ensure_ascii=False)
    except Exception as e:
        return f"GitHub Releases 查询失败：{e}"
