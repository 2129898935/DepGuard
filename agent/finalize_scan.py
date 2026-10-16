"""Single bounded S6 action: restore deterministic deliverables and validate them."""

from __future__ import annotations

import json
from pathlib import Path

from langchain_core.tools import tool

from agent.scan_guard import build_deliverables_from_evidence, evidence_chain_errors
from api.context import get_session_context
from tools.sbom_tool import validate_deliverables


@tool
def finalize_dependency_scan() -> str:
    """只读阶段证据，确定性生成报告和 SBOM，校验证据链与交付物；只返回简短结果。"""
    session = get_session_context()
    if not session:
        return json.dumps({"ok": False, "errors": ["缺少会话工作目录"]}, ensure_ascii=False)
    session_dir = Path(session)
    errors = evidence_chain_errors(session_dir)
    if errors:
        return json.dumps({"ok": False, "errors": errors}, ensure_ascii=False)
    try:
        if not build_deliverables_from_evidence(session_dir):
            return json.dumps({"ok": False, "errors": ["S1-S5 证据未齐全"]}, ensure_ascii=False)
        s1 = json.loads((session_dir / "s1_components.json").read_text(encoding="utf-8"))
        sbom = json.loads((session_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
        result = json.loads(validate_deliverables.func(
            report_filename="dependency_risk_report.md", sbom_filename="sbom.cdx.json",
            expected_components=len(s1.get("components") or []),
            expected_vulnerabilities=len(sbom.get("vulnerabilities") or []),
        ))
        result.update({"report_file": "dependency_risk_report.md", "sbom_file": "sbom.cdx.json"})
        return json.dumps(result, ensure_ascii=False)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=False)
