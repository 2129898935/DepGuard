"""六阶段之间的结构化证据包校验。"""
import json

from langchain_core.tools import tool

_REQUIRED_STAGES = {
    "dependency_parser",
    "vulnerability_intelligence",
    "license_maintenance",
    "impact_analysis",
    "upgrade_planning",
}


def validate_evidence_bundle_data(bundle: dict) -> dict:
    errors: list[str] = []
    warnings: list[str] = []
    stages = bundle.get("stages", {})
    if not isinstance(stages, dict):
        return {"ok": False, "errors": ["stages 必须是对象"], "warnings": []}
    missing = sorted(_REQUIRED_STAGES - set(stages))
    if missing:
        errors.append("缺少阶段证据：" + ", ".join(missing))

    components = bundle.get("components", [])
    vulnerabilities = bundle.get("vulnerabilities", [])
    if not isinstance(components, list) or not components:
        errors.append("components 必须是非空数组")
        components = []
    if not isinstance(vulnerabilities, list):
        errors.append("vulnerabilities 必须是数组")
        vulnerabilities = []

    component_keys = {
        (str(item.get("name", "")).lower(), str(item.get("version", "")))
        for item in components
        if item.get("name")
    }
    canonical_ids: set[str] = set()
    detailed_count = 0
    id_only_count = 0
    for vulnerability in vulnerabilities:
        canonical_id = str(vulnerability.get("canonical_id") or "").strip()
        status = vulnerability.get("evidence_status")
        if not canonical_id:
            errors.append("漏洞缺少 canonical_id")
        elif canonical_id in canonical_ids:
            errors.append(f"canonical_id 重复：{canonical_id}")
        canonical_ids.add(canonical_id)

        if status == "id_only":
            id_only_count += 1
            continue
        detailed_count += 1
        if status not in {"detailed", "confirmed"}:
            errors.append(f"{canonical_id} 缺少有效 evidence_status")
        if not vulnerability.get("affected_ecosystem"):
            errors.append(f"{canonical_id} 缺少 affected_ecosystem")
        affected = (
            str(vulnerability.get("affected_component", "")).lower(),
            str(vulnerability.get("affected_version", "")),
        )
        if affected not in component_keys:
            warnings.append(f"{canonical_id} 的受影响组件不在直接组件清单中，可能是传递依赖或其他生态")
        ratings = vulnerability.get("ratings", [])
        if not ratings:
            errors.append(f"{canonical_id} 的详细证据缺少 ratings")
        for rating in ratings:
            if not rating.get("source"):
                errors.append(f"{canonical_id} 的评分缺少 source")
            if rating.get("score") is not None and not rating.get("cvss_version"):
                errors.append(f"{canonical_id} 的评分有 score 但缺少 cvss_version")
        if "fixed_versions" not in vulnerability:
            errors.append(f"{canonical_id} 缺少 fixed_versions 字段")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "component_count": len(components),
        "unique_vulnerability_count": len(canonical_ids),
        "detailed_vulnerability_count": detailed_count,
        "id_only_count": id_only_count,
    }


@tool
def validate_evidence_bundle(bundle: dict) -> str:
    """校验六阶段 Evidence Bundle；ok=false 时禁止生成最终报告。"""
    return json.dumps(validate_evidence_bundle_data(bundle), ensure_ascii=False)
