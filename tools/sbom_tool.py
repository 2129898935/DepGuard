"""CycloneDX SBOM 生成、写入与校验工具。"""
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from langchain_core.tools import tool

from api.context import get_session_context


def _normalize_name(name: str, ecosystem: str) -> str:
    value = str(name or "").strip()
    if ecosystem.lower() == "pypi":
        return re.sub(r"[-_.]+", "-", value).lower()
    return value


def _purl(package: dict) -> str | None:
    ecosystem = str(package.get("ecosystem") or "PyPI")
    name = _normalize_name(package.get("name"), ecosystem)
    version = str(package.get("version") or "").strip()
    if not name:
        return None
    purl_type = {"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang"}.get(ecosystem.lower())
    if not purl_type:
        return None
    value = f"pkg:{purl_type}/{quote(name, safe='@:/')}"
    return value + (f"@{quote(version, safe='.+-_')}" if version else "")


def _severity(value: str) -> str:
    level = str(value or "unknown").lower()
    return level if level in {"critical", "high", "medium", "low", "info", "none", "unknown"} else "unknown"


def build_sbom(
    packages: list[dict],
    vulnerabilities: list[dict] | None = None,
    dependencies: list[dict] | None = None,
    application_name: str = "scanned-application",
    spec_version: str = "1.6",
) -> dict:
    """构造 CycloneDX JSON；漏洞和依赖关系必须来自上游结构化证据。"""
    if spec_version not in {"1.5", "1.6"}:
        raise ValueError("spec_version 仅支持 1.5 或 1.6")

    components = []
    ref_by_name: dict[str, str] = {}
    for package in packages:
        ecosystem = str(package.get("ecosystem") or "PyPI")
        name = _normalize_name(package.get("name"), ecosystem)
        version = str(package.get("version") or "").strip()
        if not name:
            continue
        ref = str(package.get("bom-ref") or (f"pkg:{ecosystem.lower()}:{name}@{version}" if version else f"pkg:{ecosystem.lower()}:{name}"))
        component = {"type": str(package.get("type") or "library"), "bom-ref": ref, "name": name}
        if version:
            component["version"] = version
        purl = _purl({**package, "name": name, "ecosystem": ecosystem})
        if purl:
            component["purl"] = purl
        components.append(component)
        ref_by_name[name] = ref
        ref_by_name[str(package.get("name") or "").lower()] = ref

    root_ref = f"application:{_normalize_name(application_name, 'PyPI') or 'scanned-application'}"
    dependency_entries = [{"ref": root_ref, "dependsOn": [c["bom-ref"] for c in components]}]
    for item in dependencies or []:
        source = str(item.get("ref") or item.get("name") or "")
        source_ref = ref_by_name.get(source.lower(), source)
        targets = item.get("dependsOn") or item.get("depends_on") or []
        target_refs = [ref_by_name.get(str(target).lower(), str(target)) for target in targets]
        dependency_entries.append({"ref": source_ref, "dependsOn": target_refs})

    vuln_entries = []
    for item in vulnerabilities or []:
        vuln_id = str(item.get("id") or item.get("cve") or "").strip()
        if not vuln_id:
            continue
        source_value = item.get("source") or "OSV"
        source = source_value if isinstance(source_value, dict) else {"name": str(source_value)}
        entry: dict = {"id": vuln_id, "source": source}
        rating = {"severity": _severity(item.get("severity"))}
        if item.get("score") is not None:
            rating["score"] = float(item["score"])
        if item.get("method"):
            raw_method = str(item["method"]).replace(".", "").lower()
            methods = {
                "cvssv2": "CVSSv2",
                "cvssv3": "CVSSv3",
                "cvssv30": "CVSSv3",
                "cvssv31": "CVSSv31",
                "cvssv4": "CVSSv4",
                "cvssv40": "CVSSv4",
                "owasp": "OWASP",
                "ssvc": "SSVC",
                "other": "other",
            }
            rating["method"] = methods.get(raw_method, "other")
        entry["ratings"] = [rating]
        if item.get("description") or item.get("summary"):
            entry["description"] = str(item.get("description") or item.get("summary"))
        affects = item.get("affects") or item.get("packages") or []
        if isinstance(affects, str):
            affects = [affects]
        refs = []
        for affected in affects:
            value = affected.get("ref") or affected.get("name") if isinstance(affected, dict) else affected
            ref = ref_by_name.get(str(value).lower(), str(value))
            if ref:
                refs.append({"ref": ref})
        if refs:
            entry["affects"] = refs
        if item.get("advisories"):
            entry["advisories"] = [{"url": str(url)} for url in item["advisories"]]
        vuln_entries.append(entry)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec_version,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "DepGuard Agent"}]},
            "component": {"type": "application", "bom-ref": root_ref, "name": application_name},
        },
        "components": components,
        "dependencies": dependency_entries,
        "vulnerabilities": vuln_entries,
    }


def validate_sbom_data(data: dict, expected_components: int | None = None, expected_vulnerabilities: int | None = None) -> list[str]:
    """返回机器可判定的 SBOM 错误列表。"""
    errors: list[str] = []
    if data.get("bomFormat") != "CycloneDX":
        errors.append("bomFormat 必须为 CycloneDX")
    if data.get("specVersion") not in {"1.5", "1.6"}:
        errors.append("不支持的 CycloneDX specVersion")
    components = data.get("components")
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(components, list):
        errors.append("components 必须是数组")
        components = []
    if not isinstance(vulnerabilities, list):
        errors.append("vulnerabilities 必须是数组（即使为空也必须存在）")
        vulnerabilities = []
    if not data.get("metadata", {}).get("component"):
        errors.append("缺少 metadata.component")
    if not isinstance(data.get("dependencies"), list):
        errors.append("缺少 dependencies 依赖关系数组")
    if expected_components is not None and len(components) != expected_components:
        errors.append(f"组件数不一致：期望 {expected_components}，实际 {len(components)}")
    if expected_vulnerabilities is not None and len(vulnerabilities) != expected_vulnerabilities:
        errors.append(f"漏洞数不一致：期望 {expected_vulnerabilities}，实际 {len(vulnerabilities)}")
    refs = {item.get("bom-ref") for item in components}
    refs.add(data.get("metadata", {}).get("component", {}).get("bom-ref"))
    if len(refs) != len(components) + 1:
        errors.append("存在重复或缺失的 bom-ref")
    for component in components:
        if not component.get("purl"):
            errors.append(f"组件 {component.get('name')} 缺少 purl")
        elif component["purl"].startswith("pkg:pypi/") and component["purl"] != component["purl"].lower():
            errors.append(f"PyPI purl 未规范化为小写：{component['purl']}")
    for vulnerability in vulnerabilities:
        if not vulnerability.get("id") or not vulnerability.get("source"):
            errors.append("漏洞缺少 id 或 source")
        if not vulnerability.get("affects"):
            errors.append(f"漏洞 {vulnerability.get('id')} 缺少 affects")
        for affected in vulnerability.get("affects", []):
            if affected.get("ref") not in refs:
                errors.append(f"漏洞 {vulnerability.get('id')} 引用了不存在的 bom-ref")
    return errors


@tool
def write_sbom(
    packages: list[dict],
    vulnerabilities: list[dict] | None = None,
    dependencies: list[dict] | None = None,
    filename: str = "sbom.cdx.json",
    application_name: str = "scanned-application",
    spec_version: str = "1.6",
) -> str:
    """生成含组件、漏洞和依赖关系的 CycloneDX SBOM。"""
    session_dir = Path(get_session_context() or ".")
    safe_name = Path(filename).name
    if not safe_name.endswith(".json"):
        safe_name += ".json"
    path = session_dir / safe_name
    data = build_sbom(packages, vulnerabilities, dependencies, application_name, spec_version)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.dumps({
        "ok": True,
        "filename": safe_name,
        "components": len(data["components"]),
        "vulnerabilities": len(data["vulnerabilities"]),
        "specVersion": data["specVersion"],
    }, ensure_ascii=False)


@tool
def validate_deliverables(
    report_filename: str = "dependency_risk_report.md",
    sbom_filename: str = "sbom.cdx.json",
    expected_components: int | None = None,
    expected_vulnerabilities: int | None = None,
) -> str:
    """读回报告与 SBOM 并做交付门禁；只有 ok=true 才能向用户声明完成。"""
    session_dir = Path(get_session_context() or ".")
    report_path = session_dir / Path(report_filename).name
    sbom_path = session_dir / Path(sbom_filename).name
    errors: list[str] = []
    report_text = ""
    if not report_path.is_file() or report_path.stat().st_size == 0:
        errors.append(f"报告不存在或为空：{report_path.name}")
    else:
        report_text = report_path.read_text(encoding="utf-8")
        required_sections = (
            "## 执行摘要", "## 范围、方法与证据来源", "## 重点组件与处置顺序",
            "## 许可证与维护性", "## 源码影响分析", "## 升级、验证与回滚",
            "## 待确认项", "## 漏洞明细",
        )
        for section in required_sections:
            if section not in report_text:
                errors.append(f"报告缺少面向人的必需章节：{section}")
        if len(re.findall(r'(?m)^\s*"(?:stage|source_status|components|package_results)"\s*:', report_text)) > 3:
            errors.append("报告包含大段原始 JSON，未转换为可读摘要")
        if report_text.count("```") % 2:
            errors.append("报告包含未闭合的代码块，内容可能截断")
    if not sbom_path.is_file() or sbom_path.stat().st_size == 0:
        errors.append(f"SBOM 不存在或为空：{sbom_path.name}")
        data = {}
    else:
        try:
            data = json.loads(sbom_path.read_text(encoding="utf-8"))
            errors.extend(validate_sbom_data(data, expected_components, expected_vulnerabilities))
            missing_ids = [str(item.get("id")) for item in data.get("vulnerabilities", [])
                           if item.get("id") and str(item["id"]) not in report_text]
            if missing_ids:
                errors.append(f"报告漏洞明细缺少 {len(missing_ids)} 个 SBOM ID")
            declared_components = re.search(r"(?m)^- 组件数[：:]\s*(\d+)\s*$", report_text)
            declared_vulnerabilities = re.search(r"(?m)^- 唯一漏洞数[：:]\s*(\d+)\s*$", report_text)
            if not declared_components or not declared_vulnerabilities:
                errors.append("报告缺少机器可校验的“组件数/唯一漏洞数”指标")
            else:
                if int(declared_components.group(1)) != len(data.get("components", [])):
                    errors.append("报告组件数与 SBOM 不一致")
                if int(declared_vulnerabilities.group(1)) != len(data.get("vulnerabilities", [])):
                    errors.append("报告唯一漏洞数与 SBOM 不一致")
        except (OSError, json.JSONDecodeError) as exc:
            data = {}
            errors.append(f"SBOM 无法解析：{exc}")
    return json.dumps({
        "ok": not errors,
        "errors": errors,
        "report_bytes": report_path.stat().st_size if report_path.is_file() else 0,
        "components": len(data.get("components", [])),
        "vulnerabilities": len(data.get("vulnerabilities", [])),
    }, ensure_ascii=False)
