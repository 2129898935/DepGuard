"""SBOM 生成与交付门禁测试。"""
import json
import tempfile
from pathlib import Path

from api.context import reset_session_context, set_session_context
from tools.sbom_tool import build_sbom, validate_deliverables, validate_sbom_data, write_sbom


def test_write_sbom_with_vulnerabilities_and_dependencies():
    with tempfile.TemporaryDirectory() as directory:
        token = set_session_context(directory)
        try:
            result = json.loads(write_sbom.func(
                packages=[{"name": "Requests", "version": "2.31.0"}],
                vulnerabilities=[{
                    "id": "CVE-2024-35195",
                    "source": "GHSA",
                    "severity": "high",
                    "score": 7.5,
                    "affects": ["requests"],
                }],
                filename="sbom.cdx.json",
                application_name="requirements1",
            ))
        finally:
            reset_session_context(token)

        assert result == {
            "ok": True,
            "filename": "sbom.cdx.json",
            "components": 1,
            "vulnerabilities": 1,
            "specVersion": "1.6",
        }
        data = json.loads(Path(directory, "sbom.cdx.json").read_text(encoding="utf-8"))
        assert data["metadata"]["component"]["name"] == "requirements1"
        assert data["components"][0]["purl"] == "pkg:pypi/requests@2.31.0"
        assert data["vulnerabilities"][0]["affects"][0]["ref"] == data["components"][0]["bom-ref"]
        assert data["dependencies"][0]["dependsOn"] == [data["components"][0]["bom-ref"]]
        assert validate_sbom_data(data, 1, 1) == []


def test_build_sbom_skips_empty_names_and_supports_npm():
    data = build_sbom([
        {"name": "", "version": "1.0"},
        {"name": "@scope/pkg", "version": "2.0.0", "ecosystem": "npm"},
    ])
    assert len(data["components"]) == 1
    assert data["components"][0]["purl"] == "pkg:npm/@scope/pkg@2.0.0"


def test_validate_deliverables_rejects_count_mismatch():
    with tempfile.TemporaryDirectory() as directory:
        token = set_session_context(directory)
        try:
            write_sbom.func(
                [{"name": "requests", "version": "2.31.0"}],
                vulnerabilities=[],
                filename="sbom.cdx.json",
            )
            Path(directory, "dependency_risk_report.md").write_text(
                "# report\n- 组件数: 1\n- 唯一漏洞数: 2\n",
                encoding="utf-8",
            )
            result = json.loads(validate_deliverables.func())
        finally:
            reset_session_context(token)
        assert result["ok"] is False
        assert "报告唯一漏洞数与 SBOM 不一致" in result["errors"]


def test_validate_sbom_rejects_missing_vulnerability_affects():
    data = build_sbom(
        [{"name": "requests", "version": "2.31.0"}],
        [{"id": "CVE-1", "source": "OSV", "severity": "high"}],
    )
    assert any("缺少 affects" in error for error in validate_sbom_data(data))


def test_validate_deliverables_rejects_machine_dump_as_report():
    with tempfile.TemporaryDirectory() as directory:
        token = set_session_context(directory)
        try:
            write_sbom.func([{"name": "requests", "version": "2.31.0"}],
                            vulnerabilities=[], filename="sbom.cdx.json")
            Path(directory, "dependency_risk_report.md").write_text(
                '# 报告\n- 组件数: 1\n- 唯一漏洞数: 0\n'
                '## 许可证与维护性\n{\n  "stage": "S3",\n  "components": []\n}\n',
                encoding="utf-8")
            result = json.loads(validate_deliverables.func())
            assert result["ok"] is False
            assert any("执行摘要" in error for error in result["errors"])
        finally:
            reset_session_context(token)
