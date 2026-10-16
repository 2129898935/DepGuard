from tools.evidence_tool import validate_evidence_bundle_data


def _bundle():
    return {
        "stages": {
            "dependency_parser": {},
            "vulnerability_intelligence": {},
            "license_maintenance": {},
            "impact_analysis": {},
            "upgrade_planning": {},
        },
        "components": [{"name": "requests", "version": "2.31.0"}],
        "vulnerabilities": [{
            "canonical_id": "CVE-2024-35195",
            "aliases": ["GHSA-9wx4-h78v-vm56"],
            "affected_component": "requests",
            "affected_ecosystem": "PyPI",
            "affected_version": "2.31.0",
            "ratings": [{"source": "GHSA", "cvss_version": "3.1", "score": 7.5, "severity": "high"}],
            "fixed_versions": ["2.32.0"],
            "evidence_status": "detailed",
        }],
    }


def test_valid_evidence_bundle():
    result = validate_evidence_bundle_data(_bundle())
    assert result["ok"] is True
    assert result["unique_vulnerability_count"] == 1


def test_rejects_duplicate_canonical_id_and_unsourced_rating():
    bundle = _bundle()
    duplicate = dict(bundle["vulnerabilities"][0])
    duplicate["ratings"] = [{"score": 8.0}]
    bundle["vulnerabilities"].append(duplicate)
    result = validate_evidence_bundle_data(bundle)
    assert result["ok"] is False
    assert any("canonical_id 重复" in error for error in result["errors"])
    assert any("评分缺少 source" in error for error in result["errors"])


def test_id_only_not_treated_as_detailed():
    bundle = _bundle()
    bundle["vulnerabilities"] = [{
        "canonical_id": "GHSA-id-only",
        "affected_component": "requests",
        "affected_ecosystem": "PyPI",
        "affected_version": "2.31.0",
        "evidence_status": "id_only",
    }]
    result = validate_evidence_bundle_data(bundle)
    assert result["ok"] is True
    assert result["detailed_vulnerability_count"] == 0
    assert result["id_only_count"] == 1


def test_confirmed_status_from_s2_is_valid():
    bundle = _bundle()
    bundle["vulnerabilities"][0]["evidence_status"] = "confirmed"
    assert validate_evidence_bundle_data(bundle)["ok"] is True
