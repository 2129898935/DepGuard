"""NVD 数据源工具：返回带来源和 CVSS 版本的结构化评分。"""
import json

import httpx
from langchain_core.tools import tool

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@tool
def query_cvss(cve_id: str) -> str:
    """查询 NVD 指定 CVE；不得把 CNA 分数冒充为 NVD 评分。"""
    try:
        response = httpx.get(NVD_URL, params={"cveId": cve_id}, timeout=10)
        response.raise_for_status()
        vulnerabilities = response.json().get("vulnerabilities", [])
        if not vulnerabilities:
            return json.dumps({"ok": False, "source": "NVD", "cve_id": cve_id, "error": "not_found"})
        cve = vulnerabilities[0].get("cve", {})
        scores = []
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for metric in cve.get("metrics", {}).get(key, []):
                cvss = metric.get("cvssData", {})
                scores.append({
                    "metric": key,
                    "source": metric.get("source"),
                    "type": metric.get("type"),
                    "score": cvss.get("baseScore"),
                    "severity": cvss.get("baseSeverity"),
                    "vector": cvss.get("vectorString"),
                })
        descriptions = cve.get("descriptions", [])
        english = next((item.get("value") for item in descriptions if item.get("lang") == "en"), "")
        return json.dumps({
            "ok": True,
            "source": "NVD",
            "cve_id": cve.get("id") or cve_id,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
            "description": english,
            "ratings": scores,
            "rating_policy": "Each rating retains its original source; only source=nvd@nist.gov is an NVD assessment.",
        }, ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "source": "NVD", "cve_id": cve_id, "error": str(exc)}, ensure_ascii=False)
