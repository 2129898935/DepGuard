"""OSV 证据转换不得自行猜测严重度。"""
from tools.osv_tool import _detail, _extract_fixed


def test_osv_detail_preserves_vector_without_inferred_label():
    raw = {
        "id": "GHSA-test",
        "aliases": ["CVE-2023-50447"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [{"ranges": [{"events": [{"fixed": "10.2.0"}, {"fixed": "12.0.0"}]}]}],
    }
    detail = _detail(raw)

    assert detail["severity"] == raw["severity"]
    assert "severity_label" not in detail
    assert detail["fixed_versions"] == ["10.2.0", "12.0.0"]
    assert _extract_fixed(raw) == ["10.2.0", "12.0.0"]


def test_osv_detail_fetch_is_bounded_parallel(monkeypatch):
    import json
    import time
    import tools.osv_tool as osv

    ids = [f"GHSA-test-{i}" for i in range(12)]
    monkeypatch.setattr(osv, "_query_osv", lambda payload: {
        "results": [{"vulns": [{"id": item} for item in ids]}]
    })
    seen = []

    def slow_detail(vuln_id):
        seen.append(vuln_id)
        time.sleep(0.06)
        return {"id": vuln_id, "aliases": [], "affected": []}

    monkeypatch.setattr(osv, "_get_vuln_detail", slow_detail)
    started = time.perf_counter()
    result = json.loads(osv.query_osv_vulns.func(["requests"], max_details=10))
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5  # Ten sequential requests would take at least 0.6 s.
    assert len(seen) == 10
    assert result["detail_limit_reached"] is True
    assert len(result["packages"][0]["vulnerabilities"]) == 10
    assert len(result["packages"][0]["omitted_ids"]) == 2
