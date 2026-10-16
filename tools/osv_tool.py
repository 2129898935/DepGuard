"""OSV.dev 漏洞查询工具（对齐 M11）。

两段式查询（OSV API 本身的设计）：
  1. POST /v1/querybatch —— 按包名+版本批量查出「哪些包有哪些漏洞 ID」（精简，每条只回 id + modified）
  2. GET  /v1/vulns/{id}  —— 逐条补全详情（severity / summary / aliases(CVE) / fixed 版本）

只用 querybatch 会丢 severity / summary / CVE / 修复版本，导致报告只能靠模型猜。
"""
import json
from concurrent.futures import ThreadPoolExecutor

import httpx
from langchain_core.tools import tool

from db.cache import cache_get, cache_set
from utils.retry import retry_with_backoff

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns"


@retry_with_backoff(max_retries=3, base_delay=1.0, max_delay=10.0)
def _query_osv(payload: dict) -> dict:
    """POST /v1/querybatch（带 24h 缓存 + 退避重试）。"""
    cache_key = "osv:" + json.dumps(payload, sort_keys=True)
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    resp = httpx.post(OSV_QUERYBATCH, json=payload, timeout=10)
    resp.raise_for_status()
    data = resp.json()
    cache_set(cache_key, data, 24 * 3600)
    return data


def _get_vuln_detail(vuln_id: str) -> dict:
    """GET /v1/vulns/{id} 拿单条漏洞完整详情（带 24h 缓存）。"""
    cache_key = "osv-vuln:" + vuln_id
    cached = cache_get(cache_key)
    if cached is not None:
        return cached
    resp = httpx.get(f"{OSV_VULN}/{vuln_id}", timeout=10)
    resp.raise_for_status()
    data = resp.json()
    cache_set(cache_key, data, 24 * 3600)
    return data


def _extract_fixed(vuln: dict, package_name: str | None = None,
                   ecosystem: str | None = None) -> list[str]:
    """提取全部 fixed 事件，避免把不同版本线的修复边界压成一个版本。"""
    fixed: list[str] = []
    for affected in vuln.get("affected", []):
        package = affected.get("package") or {}
        if package_name and package.get("name") and package["name"].lower() != package_name.lower():
            continue
        if ecosystem and package.get("ecosystem") and package["ecosystem"].lower() != ecosystem.lower():
            continue
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                value = event.get("fixed")
                if value and value not in fixed:
                    fixed.append(value)
    return fixed


def _detail(vuln: dict) -> dict:
    """保留 OSV 原始证据；不从 CVSS 向量自行推断严重度。"""
    return {
        "id": vuln.get("id"),
        "aliases": vuln.get("aliases", []),
        "summary": vuln.get("summary") or "",
        "severity": vuln.get("severity", []),
        "database_specific": vuln.get("database_specific", {}),
        "fixed_versions": _extract_fixed(vuln),
        "affected": [
            {"package": item.get("package") or {}, "ranges": item.get("ranges") or [],
             "versions": item.get("versions") or []}
            for item in vuln.get("affected", []) if isinstance(item, dict)
        ],
        "modified": vuln.get("modified"),
        "published": vuln.get("published"),
        "references": [
            {"type": item.get("type"), "url": item.get("url")}
            for item in vuln.get("references", [])
            if item.get("url")
        ],
    }


@tool
def query_osv_vulns(
    package_names: list[str],
    ecosystem: str = "PyPI",
    versions: list[str] | None = None,
    max_details: int = 1000,
) -> str:
    """批量查询漏洞并返回结构化 OSV 证据。

    severity 保留 OSV 原始 CVSS 向量，不自行映射 Critical/High；
    最终等级应由 NVD/GHSA 的明确 score/severity 确认。
    """
    queries = []
    for index, name in enumerate(package_names):
        query = {"package": {"name": name, "ecosystem": ecosystem}}
        if versions and index < len(versions) and versions[index]:
            query["version"] = versions[index]
        queries.append(query)

    data = _query_osv({"queries": queries})
    packages: list[dict] = []
    selected_ids: list[str] = []
    detail_count = 0
    detail_limit_reached = False
    results = data.get("results", [])
    for index, name in enumerate(package_names):
        response = results[index] if index < len(results) else {}
        summaries = response.get("vulns", [])
        version = versions[index] if versions and index < len(versions) else ""
        wanted_ids = []
        omitted_ids = []
        for summary in summaries:
            vuln_id = summary.get("id")
            if not vuln_id:
                continue
            if detail_count >= max_details:
                omitted_ids.append(vuln_id)
                detail_limit_reached = True
                continue
            wanted_ids.append(vuln_id)
            selected_ids.append(vuln_id)
            detail_count += 1
        packages.append({
            "name": name,
            "version": version,
            "total_vulnerabilities": len(summaries),
            "wanted_ids": wanted_ids,
            "omitted_ids": omitted_ids,
        })

    # Fetch independent advisory details concurrently. Keep a bounded pool so
    # Large manifests keep a bounded pool instead of serializing detail requests.
    unique_ids = list(dict.fromkeys(selected_ids))
    with ThreadPoolExecutor(max_workers=min(8, len(unique_ids) or 1)) as pool:
        futures = {vuln_id: pool.submit(_get_vuln_detail, vuln_id)
                   for vuln_id in unique_ids}
        detail_by_id = {}
        for vuln_id, future in futures.items():
            try:
                detail_by_id[vuln_id] = _detail(future.result())
            except Exception as exc:
                detail_by_id[vuln_id] = {"id": vuln_id, "detail_error": str(exc)}
    for package in packages:
        selected = []
        for vuln_id in package.pop("wanted_ids"):
            detail = dict(detail_by_id[vuln_id])
            if detail.get("affected"):
                matching = [item for item in detail["affected"] if
                            (not (item.get("package") or {}).get("name") or
                             (item["package"]["name"].lower() == package["name"].lower())) and
                            (not (item.get("package") or {}).get("ecosystem") or
                             item["package"]["ecosystem"].lower() == ecosystem.lower())]
                detail["affected"] = matching
                detail["fixed_versions"] = _extract_fixed(
                    {"affected": matching}, package["name"], ecosystem)
            else:
                detail["fixed_versions"] = []
            selected.append(detail)
        package["vulnerabilities"] = selected
    return json.dumps({
        "source": "OSV",
        "ecosystem": ecosystem,
        "packages": packages,
        "detailed_vulnerabilities": detail_count,
        "detail_limit": max_details,
        "detail_limit_reached": detail_limit_reached,
        "severity_policy": "OSV CVSS vectors are preserved verbatim; do not infer labels from impact metrics.",
    }, ensure_ascii=False)


def query_osv_vuln_ids(
    package_names: list[str],
    ecosystem: str = "PyPI",
    versions: list[str] | None = None,
) -> dict[str, set[str]]:
    """按包返回其所有漏洞的完整 ID 集合（主 ID + 别名），供评测/多源去重使用。

    与 query_osv_vulns 的区别：不做截断、不做摘要，只返回可用于归一化对比的 ID 集合。
    别名归一化是漏洞聚合的关键：GHSA / CVE / PYSEC / GO 可能指向同一个漏洞。
    """
    queries = []
    for i, n in enumerate(package_names):
        q = {"package": {"name": n, "ecosystem": ecosystem}}
        if versions and i < len(versions) and versions[i]:
            q["version"] = versions[i]
        queries.append(q)

    data = _query_osv({"queries": queries})
    result: dict[str, set[str]] = {}
    for i, name in enumerate(package_names):
        res = data.get("results", [])[i] if i < len(data.get("results", [])) else {}
        ids: set[str] = set()
        for v in res.get("vulns", []):
            vid = v.get("id", "")
            if not vid:
                continue
            ids.add(vid)
            try:
                ids.update(_get_vuln_detail(vid).get("aliases", []))
            except Exception:
                pass
        result[name] = ids
    return result
