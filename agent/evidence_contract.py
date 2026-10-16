"""Versioned, machine-checkable identities and coverage contract for DepGuard.

Hashes establish replay consistency, not the factual truth of an advisory.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Any
from urllib.parse import quote

from packaging.version import InvalidVersion, Version


RULESET_VERSION = "depguard-contract-v1"
TERMINAL_OUTCOMES = frozenset({
    "complete", "no_finding", "unknown", "not_applicable", "source_failed",
    "over_budget", "manual_review",
})
BATCH_STATES = frozenset({"pending", "running", "succeeded", "failed", "split", "incomplete"})
NO_PLAN_REASONS = frozenset({
    "no_fixed_version", "already_satisfied", "compatibility_unverified",
    "manual_review", "out_of_scope", "source_failed", "unresolved_version",
})


def canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", str(name).strip().lower())


def content_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def is_resolved_version(version: str) -> bool:
    value = str(version or "").strip()
    if not value or any(char in value for char in "<>=!~*,; "):
        return False
    try:
        Version(value)
    except InvalidVersion:
        return False
    return True


def component_id(component: dict) -> str:
    ecosystem = str(component.get("ecosystem") or "PyPI").lower()
    name = canonical_name(component.get("name", ""))
    version = str(component.get("version") or "")
    if not name:
        raise ValueError("组件缺少 name")
    if is_resolved_version(version):
        return f"pkg:{ecosystem}/{quote(name, safe='-')}@{quote(version, safe='.-_')}"
    return f"req:{ecosystem}/{quote(name, safe='-')}#{content_hash(version)[:16]}"


def normalize_components(components: list[dict]) -> list[dict]:
    result = []
    seen: dict[str, dict] = {}
    for raw in components:
        item = dict(raw)
        item["name"] = canonical_name(item.get("name", ""))
        item["ecosystem"] = str(item.get("ecosystem") or "PyPI")
        item["component_id"] = component_id(item)
        item["resolution_status"] = (
            "resolved" if is_resolved_version(item.get("version", "")) else "unresolved"
        )
        item["source_occurrences"] = list(item.get("source_occurrences") or [{
            "source_file": item.get("source_file"),
            "requirement": item.get("requirement"),
        }])
        if item["component_id"] in seen:
            seen[item["component_id"]]["source_occurrences"].extend(item["source_occurrences"])
            continue
        seen[item["component_id"]] = item
        result.append(item)
    return result


def evidence_id(stage: str, component: dict | str, source: str, record_key: str) -> str:
    cid = component if isinstance(component, str) else component_id(component)
    return f"{stage.lower()}:{content_hash([cid, source.lower(), record_key.lower()])[:24]}"


def validate_coverage(expected_ids: set[str], outcomes: list[dict], stage: str) -> list[str]:
    """Set equality plus exactly one effective terminal outcome per component."""
    errors = []
    ids = [str(item.get("component_id") or "") for item in outcomes]
    counts = Counter(ids)
    missing = expected_ids - set(ids)
    extra = set(ids) - expected_ids
    duplicates = {cid for cid, count in counts.items() if count != 1}
    if missing:
        errors.append(f"{stage} 未覆盖组件: {', '.join(sorted(missing)[:8])}")
    if extra:
        errors.append(f"{stage} 出现额外组件: {', '.join(sorted(extra)[:8])}")
    if duplicates:
        errors.append(f"{stage} 重复终态: {', '.join(sorted(duplicates)[:8])}")
    for item in outcomes:
        if item.get("status") not in TERMINAL_OUTCOMES:
            errors.append(f"{stage} 非法终态: {item.get('component_id')}={item.get('status')}")
        if item.get("status") not in {"complete", "no_finding"} and not item.get("reason_code"):
            errors.append(f"{stage} 非完成终态缺少原因码: {item.get('component_id')}")
    return errors


def validate_evidence_refs(components: list[dict], vulnerabilities: list[dict]) -> list[str]:
    by_id = {item["component_id"]: item for item in components}
    errors = []
    for item in vulnerabilities:
        cid = item.get("component_id")
        if cid not in by_id:
            errors.append(f"漏洞引用了不存在的组件: {item.get('canonical_id')} -> {cid}")
            continue
        component = by_id[cid]
        if canonical_name(item.get("affected_component", "")) != component["name"]:
            errors.append(f"漏洞组件名称不匹配: {item.get('canonical_id')}")
        if str(item.get("affected_ecosystem", "")).lower() != component["ecosystem"].lower():
            errors.append(f"漏洞生态不匹配: {item.get('canonical_id')}")
        if str(item.get("affected_version", "")) != str(component.get("version", "")):
            errors.append(f"漏洞版本不匹配: {item.get('canonical_id')}")
        if not item.get("canonical_id") or not item.get("evidence_id"):
            errors.append(f"漏洞缺少身份字段: {cid}")
    return errors


def version_after(current: str, candidate: str) -> bool | None:
    try:
        return Version(candidate) > Version(current)
    except InvalidVersion:
        return None
