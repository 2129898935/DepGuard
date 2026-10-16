"""S5 upgrade dispositions derived from immutable stage evidence, in batches."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from langchain_core.tools import tool
from packaging.version import Version

from agent.batch_runtime import run_stage
from agent.report_builder import deduplicate_vulnerabilities
from agent.evidence_contract import (
    NO_PLAN_REASONS, canonical_name, content_hash, evidence_id, normalize_components, version_after,
)
from api.context import get_session_context
from tools.depsdev_tool import query_dependencies, query_package_info
from tools.osv_tool import query_osv_vulns


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _planning_groups(components: list[dict], links: list[dict]) -> list[list[str]]:
    """Group only confirmed direct dependency links, never name heuristics."""
    by_name = {item["name"]: item["component_id"] for item in components}
    parent = {item["component_id"]: item["component_id"] for item in components}

    def root(cid):
        while parent[cid] != cid:
            parent[cid] = parent[parent[cid]]
            cid = parent[cid]
        return cid

    for link in links:
        source = by_name.get(link.get("name"))
        if not source or not link.get("ok"):
            continue
        for dependency in link.get("direct_dependencies", []):
            target = by_name.get(canonical_name(dependency.get("name") or ""))
            if target and target != source:
                parent[root(target)] = root(source)
    groups: dict[str, list[str]] = {}
    for item in components:
        cid = item["component_id"]
        groups.setdefault(root(cid), []).append(cid)
    return list(groups.values())


async def _dependency_links(session_dir: Path, components: list[dict], s2: dict) -> list[dict]:
    path = session_dir / "s5_dependency_links.json"
    source_hash = content_hash([components, s2.get("vulnerabilities") or []])
    if path.is_file():
        cached = _read(path)
        if cached.get("input_hash") == source_hash:
            return cached["links"]
    vulnerable = {item.get("component_id") for item in s2.get("vulnerabilities") or []}
    selected = [item for item in components if item["component_id"] in vulnerable
                and item.get("resolution_status") == "resolved"]
    gate = asyncio.Semaphore(6)

    async def one(item):
        async with gate:
            try:
                return json.loads(await asyncio.to_thread(
                    query_dependencies.func, item["name"], item["version"], "PYPI"))
            except Exception as exc:
                return {"ok": False, "name": item["name"], "error": str(exc),
                        "direct_dependencies": []}

    links = await asyncio.gather(*(one(item) for item in selected))
    path.write_text(json.dumps({"input_hash": source_hash, "links": links},
                               ensure_ascii=False, indent=2), encoding="utf-8")
    return links


def validate_plan(plan: dict, s1: dict, s2: dict, s3: dict, s4: dict) -> list[str]:
    components = normalize_components(s1.get("components") or [])
    by_id = {item["component_id"]: item for item in components}
    evidence = {}
    for item in s2.get("vulnerabilities") or []:
        if item.get("evidence_id"):
            evidence[item["evidence_id"]] = item
    for item in (s3.get("components") or []) + (s4.get("package_results") or []):
        if item.get("evidence_id"):
            evidence[item["evidence_id"]] = item
    records = plan.get("dispositions") or []
    ids = [row.get("component_id") for row in records]
    errors = []
    if not plan.get("dependency_links_hash"):
        errors.append("S5 缺少联动依赖快照哈希")
    if set(ids) != set(by_id) or len(ids) != len(by_id):
        errors.append("S5 规划处置未与 S1 组件集合一一对应")
    for row in records:
        cid = row.get("component_id")
        if cid not in by_id:
            continue
        component = by_id[cid]
        if row.get("current_version") != component.get("version"):
            errors.append(f"S5 当前版本不匹配: {cid}")
        refs = row.get("evidence_refs") or []
        for ref in refs:
            record = evidence.get(ref)
            if not record or record.get("component_id") != cid:
                errors.append(f"S5 引用了缺失或错位的证据: {cid} -> {ref}")
            elif record in s2.get("vulnerabilities", []):
                if (canonical_name(record.get("affected_component", "")) != component["name"]
                    or str(record.get("affected_version", "")) != str(component.get("version", ""))
                    or str(record.get("affected_ecosystem", "")).lower() != component["ecosystem"].lower()):
                    errors.append(f"S5 漏洞证据事实与组件不匹配: {cid} -> {ref}")
        if row.get("needs_disposition") and not refs:
            errors.append(f"S5 待处置组件缺少证据引用: {cid}")
        if row.get("needs_upgrade_plan") and row.get("decision") != "plan":
            errors.append(f"S5 升级规划义务未闭合: {cid}")
        if row.get("decision") == "no_plan" and row.get("needs_disposition"):
            if row.get("reason_code") not in NO_PLAN_REASONS:
                errors.append(f"S5 不规划原因非法: {cid}")
        if row.get("decision") == "plan":
            if not row.get("target_version") or version_after(
                    row["current_version"], row["target_version"]) is not True:
                errors.append(f"S5 目标版本不是有效升级: {cid}")
            if row.get("plan_status") not in {"pending_compatibility", "verified"}:
                errors.append(f"S5 计划状态非法: {cid}")
            candidate_check = row.get("candidate_check") or {}
            if candidate_check.get("source") != "OSV" or candidate_check.get("version") != row.get("target_version") or candidate_check.get("vulnerabilities") != 0:
                errors.append(f"S5 候选版本缺少 OSV 无漏洞验证: {cid}")
            confirmed = [v for v in deduplicate_vulnerabilities(s2.get("vulnerabilities") or [])
                         if v.get("component_id") == cid and v.get("evidence_status") == "confirmed"]
            for vuln in confirmed:
                if not any(version_after(component["version"], str(fix)) is True
                           and version_after(row["target_version"], str(fix)) is False
                           for fix in vuln.get("fixed_versions") or []):
                    errors.append(f"S5 目标版本缺少漏洞修复下限支持: {cid}/{vuln.get('canonical_id')}")
        if row.get("revision_hash") != content_hash({k: v for k, v in row.items() if k != "revision_hash"}):
            errors.append(f"S5 处置记录哈希不匹配: {cid}")
    return errors


async def build_plan(session_dir: Path) -> dict:
    s1, s2, s3, s4 = (_read(session_dir / filename) for filename in
                      ("s1_components.json", "s2_evidence.json", "s3_evidence.json", "s4_evidence.json"))
    components = normalize_components(s1.get("components") or [])
    by_id = {item["component_id"]: item for item in components}
    s2_by_id: dict[str, list[dict]] = {cid: [] for cid in by_id}
    for vuln in deduplicate_vulnerabilities(s2.get("vulnerabilities") or []):
        if vuln.get("component_id") in s2_by_id:
            s2_by_id[vuln["component_id"]].append(vuln)
    s3_by_id = {item.get("component_id"): item for item in s3.get("components") or []}
    s4_by_id = {item.get("component_id"): item for item in s4.get("package_results") or []}
    links = await _dependency_links(session_dir, components, s2)
    groups = _planning_groups(components, links)
    inputs = [{**item, "s2_projection": [
        {k: v.get(k) for k in ("evidence_id", "canonical_id", "evidence_status",
                              "fixed_versions", "affected_ranges", "source_snapshot_id")}
        for v in s2_by_id[item["component_id"]]],
        "s3_evidence_id": (s3_by_id.get(item["component_id"]) or {}).get("evidence_id"),
        "s4_evidence_id": (s4_by_id.get(item["component_id"]) or {}).get("evidence_id")}
              for item in components]

    async def worker(batch: list[dict], circuit) -> dict:
        outcomes, records, raw_checks = [], [], []
        for item in batch:
            cid = item["component_id"]
            vulns = s2_by_id[cid]
            confirmed = [v for v in vulns if v.get("evidence_status") == "confirmed"]
            refs = [v["evidence_id"] for v in vulns if v.get("evidence_id")]
            candidates = []
            for vuln in confirmed:
                fixes = [fix for fix in vuln.get("fixed_versions") or []
                         if version_after(item["version"], str(fix)) is True]
                if fixes:
                    candidates.append(min(fixes, key=Version))
            row = {"component_id": cid, "name": item["name"],
                   "current_version": item["version"], "evidence_refs": refs,
                   "needs_disposition": bool(vulns), "needs_upgrade_plan": False,
                   "decision": "no_plan", "reason_code": "out_of_scope"}
            if vulns and item.get("resolution_status") != "resolved":
                row["reason_code"] = "unresolved_version"
            elif vulns and not confirmed:
                row["reason_code"] = "manual_review"
            elif confirmed and len(candidates) != len(confirmed):
                row["reason_code"] = "no_fixed_version"
            elif candidates:
                target = str(max(candidates, key=Version))
                circuit.check("osv_api")
                try:
                    check = json.loads(await asyncio.to_thread(
                        query_osv_vulns.func, [item["name"]], "PyPI", [target], 0))
                    circuit.record("osv_api", True)
                except Exception:
                    circuit.record("osv_api", False)
                    raise
                raw_checks.append(check)
                packages = check.get("packages") or []
                if len(packages) == 1 and packages[0].get("total_vulnerabilities") == 0:
                    metadata = json.loads(await asyncio.to_thread(
                        query_package_info.func, item["name"], target, "PYPI"))
                    raw_checks.append(metadata)
                    if metadata.get("ok") and str(metadata.get("version")) == target:
                        row.update({"needs_upgrade_plan": True, "decision": "plan",
                                    "reason_code": None, "target_version": target,
                                    "plan_status": "pending_compatibility",
                                    "candidate_check": {"source": "OSV", "version": target,
                                                        "vulnerabilities": 0,
                                                        "snapshot_id": content_hash(check)},
                                    "candidate_verification": "OSV querybatch: no advisories at candidate version; deps.dev version exists",
                                    "validation": ["重新解析锁文件并运行 pip check", "运行项目测试和漏洞复扫"],
                                    "rollback": "保留原锁文件和镜像；失败时恢复并重新部署"})
                    else:
                        row["reason_code"] = "manual_review"
                else:
                    row["reason_code"] = "manual_review"
            row["evidence_id"] = evidence_id("S5", cid, "planner", "disposition")
            row["revision_hash"] = content_hash(row)
            records.append(row)
            outcomes.append({"component_id": cid,
                             "status": "complete" if row["decision"] == "plan" or not vulns else "manual_review",
                             **({"reason_code": row["reason_code"]} if vulns and row["decision"] != "plan" else {})})
        return {"outcomes": outcomes, "records": records,
                "datasource_snapshot_id": content_hash(raw_checks),
                "metadata": {"source": "S2/S3/S4 + OSV/deps.dev candidate checks"}}

    result = await run_stage(session_dir, "S5", inputs, worker,
                             groups=groups, token_budget=3600, max_items=12)
    if not result["ok"]:
        raise ValueError("S5 批次门禁失败: " + "；".join(result["errors"]))
    plan = {"stage": "S5", "ruleset_version": "depguard-contract-v1",
            "source_hashes": {name: content_hash(data) for name, data in
                              (("S1", s1), ("S2", s2), ("S3", s3), ("S4", s4))},
            "dependency_links_file": "s5_dependency_links.json",
            "dependency_links_hash": content_hash(links),
            "batch_plan_file": result["plan_file"],
            "dispositions": result["records"], "uncovered": result["uncovered"],
            "metrics": result["metrics"]}
    errors = validate_plan(plan, s1, s2, s3, s4)
    if errors:
        raise ValueError("S5 规划义务门禁失败: " + "；".join(errors))
    (session_dir / "s5_plan.txt").write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "plan_file": "s5_plan.txt", "component_count": len(components),
            "plan_count": sum(row["decision"] == "plan" for row in plan["dispositions"]),
            "manual_review_count": sum(row["needs_disposition"] and row["decision"] != "plan"
                                       for row in plan["dispositions"]),
            "batch_count": len(result["metrics"]), "errors": []}


@tool
async def build_upgrade_plan() -> str:
    """从 S1-S4 文件确定性分批生成并验证 S5 计划，仅返回文件索引与统计。"""
    session_dir = get_session_context()
    if not session_dir:
        return json.dumps({"ok": False, "errors": ["缺少会话工作目录"]}, ensure_ascii=False)
    try:
        return json.dumps(await build_plan(Path(session_dir)), ensure_ascii=False)
    except Exception as exc:
        return json.dumps({"ok": False, "errors": [str(exc)]}, ensure_ascii=False)
