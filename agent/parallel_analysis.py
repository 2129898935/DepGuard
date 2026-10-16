"""S2/S3/S4 并行分析组。

S1 的标准化组件证据由主 Agent 传入；本模块用三个独立 Agent 图并发执行，
汇合为一个结构化结果后交回主 Agent，再进入 S5/S6。
"""
import asyncio
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any

from langchain.agents import create_agent
from langchain_core.tools import tool

from agent.llm import model
from agent.batch_runtime import run_stage
from agent.evidence_contract import (
    content_hash, evidence_id, is_resolved_version, normalize_components,
    validate_evidence_refs,
)
from agent.subagents.impact_analysis_agent import impact_analysis_agent
from agent.subagents.license_maintenance_agent import license_maintenance_agent
from agent.subagents.vulnerability_intelligence_agent import vulnerability_intelligence_agent
from tools.osv_tool import query_osv_vulns
from tools.depsdev_tool import query_package_info
from tools.impact_analysis_tool import find_dependency_usage, _SOURCE_SUFFIXES, _IGNORED_DIRS
from api.monitor import monitor
from api.context import get_session_context

_BRANCHES = {
    "S2": vulnerability_intelligence_agent,
    "S3": license_maintenance_agent,
    "S4": impact_analysis_agent,
}
_agents: dict[str, Any] | None = None
_agents_lock = asyncio.Lock()
_review_agents: dict[str, Any] | None = None
_review_lock = asyncio.Lock()
BRANCH_TIMEOUT_SECONDS = 600


def _transient_source_error(message: str) -> bool:
    value = str(message or "").lower()
    return any(token in value for token in (
        "429", "500", "502", "503", "504", "timeout", "timed out",
        "connection", "rate limit", "temporarily", "network",
    ))


async def _get_agents() -> dict[str, Any]:
    global _agents
    if _agents is not None:
        return _agents
    async with _agents_lock:
        if _agents is None:
            _agents = {
                stage_id: create_agent(
                    model=model,
                    tools=spec["tools"],
                    system_prompt=spec["system_prompt"],
                    name=f"depguard-{stage_id.lower()}",
                )
                for stage_id, spec in _BRANCHES.items()
            }
    return _agents


async def _get_review_agents() -> dict[str, Any]:
    """Three real, bounded specialist agent graphs; never authoritative for facts."""
    global _review_agents
    if _review_agents is not None:
        return _review_agents
    async with _review_lock:
        if _review_agents is None:
            domains = {"S2": "漏洞情报", "S3": "许可证与维护性", "S4": "源码影响"}
            _review_agents = {stage: create_agent(
                model=model, tools=[], name=f"depguard-{stage.lower()}-review",
                system_prompt=(f"你是 DepGuard 的{domain}专家。只能根据用户给出的程序生成的有界证据投影"
                               "提出最多三条人工核查建议；不得新增漏洞 ID、版本、许可证或可达性事实。"
                               "只返回 JSON：{\"observations\":[\"...\"]}，总长不超过 600 字。"),
            ) for stage, domain in domains.items()}
    return _review_agents


async def _review_branch(stage_id: str, evidence: dict, session_dir: Path) -> dict:
    """LLM review is advisory; factual evidence remains disk-backed and deterministic."""
    if os.getenv("DEPGUARD_LLM_REVIEW", "1") == "0":
        return {"status": "disabled", "observations": [], "model_tokens": 0}
    if stage_id == "S2":
        rows = evidence.get("vulnerabilities") or []
        projection = {"components": len(evidence.get("components") or []),
                      "vulnerabilities": len(rows),
                      "sample": [{"id": r.get("canonical_id"), "name": r.get("affected_component"),
                                  "severity": (r.get("ratings") or [{}])[0].get("severity"),
                                  "fixed_versions": (r.get("fixed_versions") or [])[:2]}
                                 for r in rows[:10]]}
    elif stage_id == "S3":
        rows = evidence.get("components") or []
        projection = {"components": len(rows),
                      "unknown_licenses": sum(not r.get("licenses") for r in rows),
                      "nonstandard": [r.get("name") for r in rows if
                                      "non-standard" in [str(x).lower() for x in r.get("licenses") or []]][:12],
                      "repository_status": "unknown unless separately verified"}
    else:
        projection = {"status": evidence.get("status"),
                      "summary": evidence.get("scan_summary")}
    key = content_hash(projection)
    path = session_dir / f"{stage_id.lower()}_review.json"
    if path.is_file():
        cached = json.loads(path.read_text(encoding="utf-8"))
        if cached.get("input_hash") == key and cached.get("status") == "completed":
            return cached
    try:
        agents = await _get_review_agents()
        total_tokens = 0
        for attempt in range(2):
            instruction = json.dumps(projection, ensure_ascii=False)
            if attempt:
                instruction += ("\n上一次响应不是可解析的指定 JSON。请只输出一个 JSON 对象，"
                                "键 observations 的值必须为字符串数组；不要 Markdown 代码块或前后解释。")
            result = await asyncio.wait_for(agents[stage_id].ainvoke({"messages": [{
                "role": "user", "content": instruction,
            }]}), timeout=30)
            messages = result.get("messages") or []
            content = _message_text(messages[-1]) if messages else ""
            usage = (getattr(messages[-1], "usage_metadata", None) or {}) if messages else {}
            total_tokens += int(usage.get("total_tokens", 0) or 0)
            try:
                parsed = _json_evidence(content)
                observations = parsed.get("observations")
                if not isinstance(observations, list):
                    raise ValueError("专家审查未返回 observations 数组")
            except (ValueError, TypeError):
                if attempt == 0:
                    continue
                raise
            review = {"status": "completed", "input_hash": key,
                      "observations": [str(item)[:160] for item in observations[:3]],
                      "model_tokens": total_tokens, "feedback_used": bool(attempt)}
            path.write_text(json.dumps(review, ensure_ascii=False), encoding="utf-8")
            return review
    except Exception as exc:
        return {"status": "degraded", "input_hash": key,
                "observations": [], "model_tokens": 0,
                "reason": str(exc)[:160]}


def _json_evidence(content: str) -> dict:
    """Extract the JSON object from a branch response."""
    value = content.strip()
    start, end = value.find("{"), value.rfind("}")
    if start < 0 or end < start:
        raise ValueError("分支未返回 JSON 证据")
    result = json.loads(value[start:end + 1])
    if not isinstance(result, dict):
        raise ValueError("分支证据必须是 JSON 对象")
    return result


def _message_text(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            str(block.get("text") if isinstance(block, dict) else block)
            for block in content
        )
    return str(content)


async def _fallback_vulnerability_evidence(component_evidence: str) -> dict:
    """Use the OSV tool's structured output when S2's prose is invalid JSON."""
    parsed = json.loads(component_evidence)
    components = parsed.get("components", []) if isinstance(parsed, dict) else parsed
    if not isinstance(components, list) or not components:
        raise ValueError("S2 降级扫描缺少组件清单")
    names = [str(item["name"]) for item in components]
    versions = [str(item.get("version") or "") for item in components]
    # The tool's default cap of 100 silently left most enterprise scans as ID-only.
    # Keep a safety limit, but size it for the whole manifest rather than a demo.
    raw = await asyncio.to_thread(query_osv_vulns.func, names, "PyPI", versions, 1000)
    osv = json.loads(raw)
    vulnerabilities = []
    seen = set()
    for package in osv.get("packages", []):
        for detail in package.get("vulnerabilities", []):
            vuln_id = detail.get("id")
            if not vuln_id or (package.get("name"), vuln_id) in seen:
                continue
            seen.add((package.get("name"), vuln_id))
            explicit_severity = str((detail.get("database_specific") or {}).get("severity") or "").lower()
            if explicit_severity not in {"critical", "high", "moderate", "medium", "low", "informational"}:
                explicit_severity = "unknown"
            elif explicit_severity == "moderate":
                explicit_severity = "medium"
            elif explicit_severity == "informational":
                explicit_severity = "info"
            ratings = [
                {"source": "OSV", "cvss_version": item.get("type"),
                 "vector": item.get("score"), "score": None, "severity": explicit_severity}
                for item in detail.get("severity", []) if isinstance(item, dict)
            ]
            if not ratings and explicit_severity != "unknown":
                ratings = [{"source": "OSV database_specific", "cvss_version": None,
                            "vector": None, "score": None, "severity": explicit_severity}]
            vulnerabilities.append({
                "canonical_id": vuln_id,
                "aliases": detail.get("aliases", []),
                "affected_component": package.get("name"),
                "affected_ecosystem": "PyPI",
                "affected_version": package.get("version"),
                "ratings": ratings,
                "fixed_versions": detail.get("fixed_versions", []),
                "affected_ranges": detail.get("affected", []),
                "summary": detail.get("summary", ""),
                "references": [r.get("url") for r in detail.get("references", []) if r.get("url")],
                "evidence_status": "id_only" if detail.get("detail_error") else "confirmed",
            })
        for vuln_id in package.get("omitted_ids", []):
            if (package.get("name"), vuln_id) not in seen:
                seen.add((package.get("name"), vuln_id))
                vulnerabilities.append({
                    "canonical_id": vuln_id, "aliases": [],
                    "affected_component": package.get("name"),
                    "affected_ecosystem": "PyPI",
                    "affected_version": package.get("version"),
                    "ratings": [], "fixed_versions": [], "summary": "",
                    "references": [], "evidence_status": "id_only",
                })
    id_only_count = sum(item["evidence_status"] == "id_only" for item in vulnerabilities)
    return {
        "stage": "S2", "source_status": {
            "osv": "ok", "ghsa": "not_queried", "nvd": "not_queried",
            "degradation": "S2 model returned invalid JSON; rebuilt from OSV tool evidence",
            "detail_limit_reached": bool(osv.get("detail_limit_reached")),
            "id_only_count": id_only_count,
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }


async def _s2_batch(components: list[dict], circuit) -> dict:
    resolved = [item for item in components if is_resolved_version(item.get("version", ""))]
    raw = {"packages": []}
    if resolved:
        circuit.check("osv_api")
        try:
            async with circuit.gates["osv_api"]:
                response = await asyncio.to_thread(
                    query_osv_vulns.func, [item["name"] for item in resolved], "PyPI",
                    [item["version"] for item in resolved], 1000,
                )
            raw = json.loads(response)
            circuit.record("osv_api", True)
        except Exception:
            circuit.record("osv_api", False)
            raise
    packages = raw.get("packages", [])
    if len(packages) != len(resolved):
        raise ValueError("OSV 返回包数与查询包数不一致")
    by_id = {item["component_id"]: package for item, package in zip(resolved, packages)}
    outcomes, records = [], []
    for item in components:
        cid = item["component_id"]
        if cid not in by_id:
            outcomes.append({"component_id": cid, "status": "unknown",
                             "reason_code": "unresolved_version"})
            continue
        package = by_id[cid]
        details = package.get("vulnerabilities", [])
        ids = set()
        for detail in details:
            vid = detail.get("id")
            if not vid:
                continue
            ids.add(vid)
            severity = str((detail.get("database_specific") or {}).get("severity") or "").lower()
            severity = {"moderate": "medium", "informational": "info"}.get(severity, severity)
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "unknown"
            ratings = [{"source": "OSV", "cvss_version": row.get("type"),
                        "vector": row.get("score"), "score": None,
                        "severity": severity} for row in detail.get("severity", [])
                       if isinstance(row, dict)]
            if not ratings and severity != "unknown":
                ratings = [{"source": "OSV database_specific", "cvss_version": None,
                            "vector": None, "score": None, "severity": severity}]
            record = {
                "canonical_id": vid, "aliases": detail.get("aliases") or [],
                "component_id": cid, "affected_component": item["name"],
                "affected_ecosystem": item["ecosystem"],
                "affected_version": item["version"], "ratings": ratings,
                "fixed_versions": detail.get("fixed_versions") or [],
                "affected_ranges": detail.get("affected") or [],
                "summary": detail.get("summary") or "",
                "references": [r.get("url") for r in detail.get("references", [])
                               if isinstance(r, dict) and r.get("url")],
                "evidence_status": "id_only" if detail.get("detail_error") else "confirmed",
                "source": "OSV", "source_snapshot_id": content_hash(detail),
            }
            record["evidence_id"] = evidence_id("S2", cid, "OSV", vid)
            record["revision_hash"] = content_hash(record)
            records.append(record)
        for vid in package.get("omitted_ids", []):
            if vid not in ids:
                record = {"canonical_id": vid, "aliases": [], "component_id": cid,
                          "affected_component": item["name"],
                          "affected_ecosystem": item["ecosystem"],
                          "affected_version": item["version"], "ratings": [],
                          "fixed_versions": [], "affected_ranges": [], "summary": "",
                          "references": [], "evidence_status": "id_only", "source": "OSV",
                          "source_snapshot_id": content_hash(package)}
                record["evidence_id"] = evidence_id("S2", cid, "OSV", vid)
                record["revision_hash"] = content_hash(record)
                records.append(record)
        if package.get("omitted_ids") or any(d.get("detail_error") for d in details):
            outcomes.append({"component_id": cid, "status": "unknown",
                             "reason_code": "advisory_detail_unavailable"})
        else:
            outcomes.append({"component_id": cid,
                             "status": "complete" if details else "no_finding"})
    errors = validate_evidence_refs(components, records)
    if errors:
        raise ValueError("；".join(errors))
    return {"outcomes": outcomes, "records": records,
            "datasource_snapshot_id": content_hash(raw),
            "metadata": {"source": "OSV", "detail_limit_reached": raw.get("detail_limit_reached", False)}}


async def _s3_batch(components: list[dict], circuit) -> dict:

    async def one(item):
        if not is_resolved_version(item.get("version", "")):
            return item, {"ok": False, "error": "unresolved_version"}
        circuit.check("deps_dev")
        async with circuit.gates["deps_dev"]:
            raw = await asyncio.to_thread(query_package_info.func, item["name"], item["version"], "PYPI")
        data = json.loads(raw)
        circuit.record("deps_dev", bool(data.get("ok")) or not _transient_source_error(data.get("error")))
        return item, data

    pairs = await asyncio.gather(*(one(item) for item in components))
    outcomes, records = [], []
    for item, data in pairs:
        cid = item["component_id"]
        ok = bool(data.get("ok"))
        record = {"component_id": cid, "name": item["name"],
                  "version": item["version"], "licenses": data.get("licenses") or [],
                  "license_details": data.get("license_details") or [],
                  "license_source": "deps.dev" if ok else "unknown",
                  "is_deprecated": data.get("is_deprecated"),
                  "published_at": data.get("published_at"),
                  "repository_status": "unknown",
                  "source_error": data.get("error") if not ok else None,
                  "source_snapshot_id": content_hash(data)}
        record["evidence_id"] = evidence_id("S3", cid, "deps.dev", "version_metadata")
        record["revision_hash"] = content_hash(record)
        records.append(record)
        status = "complete" if ok and record["licenses"] else "unknown"
        reason = None if status == "complete" else (
            "license_unknown" if ok else data.get("error") or "deps_dev_failed")
        outcomes.append({"component_id": cid, "status": status, **({"reason_code": reason} if reason else {})})
    return {"outcomes": outcomes, "records": records,
            "datasource_snapshot_id": content_hash([data for _, data in pairs]),
            "metadata": {"source": "deps.dev", "repository_status": "unknown"}}


async def _s4_batch(components: list[dict], circuit, session_dir: Path, has_source: bool) -> dict:
    outcomes, records = [], []
    for item in components:
        cid = item["component_id"]
        hits = await asyncio.to_thread(find_dependency_usage, session_dir, item["name"]) if has_source else []
        record = {"component_id": cid, "name": item["name"], "version": item["version"],
                  "static_references": len(hits), "evidence": hits,
                  "impact": "static_reference_found" if hits else "unresolved",
                  "limitation": "静态引用扫描不能证明漏洞可达或不可达"}
        record["evidence_id"] = evidence_id("S4", cid, "source_scan", "imports")
        record["revision_hash"] = content_hash(record)
        records.append(record)
        outcomes.append({"component_id": cid, "status":
                         "complete" if hits else ("no_finding" if has_source else "unknown"),
                         **({"reason_code": "no_source_evidence"} if not has_source else {})})
    return {"outcomes": outcomes, "records": records,
            "datasource_snapshot_id": content_hash(records),
            "metadata": {"source_files_present": has_source}}


def _has_source_files(session_dir: Path) -> bool:
    return any(path.is_file() and path.suffix.lower() in _SOURCE_SUFFIXES and
               not any(part in _IGNORED_DIRS for part in path.parts)
               for path in session_dir.rglob("*"))


async def _invoke_batched_branch(stage_id: str, components: list[dict],
                                 session_dir: Path, group_id: str) -> dict:
    name = _BRANCHES[stage_id]["name"]
    started = time.perf_counter()
    monitor.report_agent_status(stage_id, name, "started", group_id)
    try:
        has_source = _has_source_files(session_dir) if stage_id == "S4" else False
        async def worker(batch, circuit):
            if stage_id == "S2":
                return await _s2_batch(batch, circuit)
            if stage_id == "S3":
                return await _s3_batch(batch, circuit)
            return await _s4_batch(batch, circuit, session_dir, has_source)
        result = await run_stage(session_dir, stage_id, components, worker)
        if not result["ok"]:
            raise ValueError("；".join(result["errors"]))
        if stage_id == "S2":
            evidence = {"stage": stage_id, "components": components,
                        "vulnerabilities": result["records"],
                        "source_status": {"osv": "queried", "ghsa": "not_queried",
                                          "nvd": "not_queried"}}
        elif stage_id == "S3":
            evidence = {"stage": stage_id, "components": result["records"],
                        "source_status": {"deps_dev": "queried", "ragflow_policy": "not_queried"}}
        else:
            evidence = {"stage": stage_id,
                        "status": "completed" if has_source else "degraded_no_source_evidence",
                        "scan_summary": {"packages_scanned": len(components) if has_source else 0,
                                         "components_accounted_for": len(components),
                                         "total_static_references": sum(r["static_references"] for r in result["records"])},
                        "package_results": result["records"]}
        evidence["coverage"] = {"outcomes": result["outcomes"],
                                 "uncovered": result["uncovered"],
                                 "plan_file": result["plan_file"],
                                 "input_set_hash": content_hash(sorted(c["component_id"] for c in components))}
        evidence["metrics"] = result["metrics"]
        evidence["specialist_review"] = await _review_branch(stage_id, evidence, session_dir)
        evidence_file = f"{stage_id.lower()}_evidence.json"
        (session_dir / evidence_file).write_text(
            json.dumps(evidence, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        duration = round((time.perf_counter() - started) * 1000)
        monitor.report_agent_status(stage_id, name, "completed", group_id, duration)
        return {"stage_id": stage_id, "assistant_name": name, "status": "completed",
                "duration_ms": duration, "evidence_file": evidence_file,
                "component_count": len(components),
                "vulnerability_count": len(result["records"]) if stage_id == "S2" else 0,
                "uncovered_count": len(result["uncovered"]), "batch_count": len(result["metrics"])}
    except Exception as exc:
        duration = round((time.perf_counter() - started) * 1000)
        monitor.report_agent_status(stage_id, name, "failed", group_id, duration, str(exc))
        return {"stage_id": stage_id, "assistant_name": name, "status": "failed",
                "duration_ms": duration, "error": str(exc)}


async def _fallback_license_evidence(component_evidence: str) -> dict:
    """Retain per-package metadata and explicit source errors from deps.dev."""
    parsed = json.loads(component_evidence)
    components = parsed.get("components", []) if isinstance(parsed, dict) else parsed
    if not isinstance(components, list) or not components:
        raise ValueError("S3 降级扫描缺少组件清单")
    semaphore = asyncio.Semaphore(8)

    async def one(package: dict) -> dict:
        async with semaphore:
            raw = await asyncio.to_thread(
                query_package_info.func, str(package["name"]),
                str(package.get("version") or ""), "PYPI"
            )
        data = json.loads(raw)
        return {
            "name": package["name"], "version": package.get("version", ""),
            "licenses": data.get("licenses", []),
            "license_details": data.get("license_details", []),
            "license_source": "deps.dev" if data.get("ok") else "unknown",
            "is_deprecated": data.get("is_deprecated"),
            "published_at": data.get("published_at"),
            "repository_status": "unknown",
            "source_error": data.get("error") if not data.get("ok") else None,
        }

    return {
        "stage": "S3", "source_status": {
            "deps_dev": "queried", "ragflow_policy": "not_queried",
            "degradation": "S3 model returned invalid JSON; rebuilt from deps.dev metadata",
        },
        "components": await asyncio.gather(*(one(item) for item in components)),
    }


async def _invoke_branch(
    stage_id: str,
    agent: Any,
    component_evidence: str,
    analysis_context: str,
    group_id: str,
) -> dict:
    spec = _BRANCHES[stage_id]
    name = spec["name"]
    started = time.perf_counter()
    monitor.report_agent_status(stage_id, name, "started", group_id)
    instruction = f"""你正在执行 DepGuard 并行分析组的 {stage_id} 分支。
以下是 S1 依赖解析助手产出的标准化组件证据，必须以此为输入，不得改写版本：
<component_evidence>
{component_evidence}
</component_evidence>

补充上下文：
{analysis_context or "无"}

返回本分支的 Evidence Bundle JSON。你与另外两个分支并行运行，不要等待或假设它们的结果。"""
    try:
        result = await asyncio.wait_for(
            agent.ainvoke({"messages": [{"role": "user", "content": instruction}]}),
            timeout=BRANCH_TIMEOUT_SECONDS,
        )
        messages = result.get("messages", [])
        content = _message_text(messages[-1]) if messages else ""
        try:
            evidence = _json_evidence(content)
            if stage_id == "S2" and not isinstance(evidence.get("vulnerabilities"), list):
                raise ValueError("S2 证据缺少 vulnerabilities 数组")
            if stage_id == "S3" and not isinstance(evidence.get("components"), list):
                raise ValueError("S3 证据缺少 components 数组")
            degradation = None
        except ValueError:
            if stage_id == "S2":
                evidence = await _fallback_vulnerability_evidence(component_evidence)
                degradation = "S2 模型 JSON 无效，改用 OSV 原始结构化证据"
            elif stage_id == "S3":
                evidence = await _fallback_license_evidence(component_evidence)
                degradation = "S3 模型 JSON 无效，改用 deps.dev 原始结构化证据"
            else:
                raise
        session_path = get_session_context()
        evidence_file = f"{stage_id.lower()}_evidence.json"
        if session_path:
            (Path(session_path) / evidence_file).write_text(
                json.dumps(evidence, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
        duration_ms = round((time.perf_counter() - started) * 1000)
        monitor.report_agent_status(stage_id, name, "completed", group_id, duration_ms)
        return {
            "stage_id": stage_id,
            "assistant_name": name,
            "status": "completed",
            "duration_ms": duration_ms,
            "evidence_file": evidence_file if session_path else None,
            "evidence_bytes": len(content.encode("utf-8")),
            "component_count": len(evidence.get("components", [])),
            "vulnerability_count": len(evidence.get("vulnerabilities", [])),
            "degradation": degradation,
        }
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started) * 1000)
        monitor.report_agent_status(stage_id, name, "failed", group_id, duration_ms, str(exc))
        return {
            "stage_id": stage_id,
            "assistant_name": name,
            "status": "failed",
            "duration_ms": duration_ms,
            "error": str(exc),
        }


async def run_parallel_analysis(
    component_evidence: str,
    analysis_context: str = "",
    stage_ids: list[str] | None = None,
) -> dict:
    """并发执行指定分支；默认严格同时启动 S2/S3/S4。"""
    session_dir = Path(get_session_context() or ".")
    evidence_path = session_dir / "s1_components.json"
    if evidence_path.is_file():
        component_evidence = evidence_path.read_text(encoding="utf-8")
    selected = stage_ids or ["S2", "S3", "S4"]
    invalid = [stage for stage in selected if stage not in _BRANCHES]
    if invalid:
        raise ValueError("不支持的并行阶段: " + ", ".join(invalid))
    group_id = str(uuid.uuid4())
    monitor.report_parallel_group(group_id, selected, "started")
    group_started = time.perf_counter()
    parsed = json.loads(component_evidence)
    raw_components = parsed.get("components", []) if isinstance(parsed, dict) else parsed
    if evidence_path.is_file() and raw_components and all(
            isinstance(item, dict) and item.get("component_id") for item in raw_components):
        components = normalize_components(raw_components)
        results = await asyncio.gather(*(
            _invoke_batched_branch(stage, components, session_dir, group_id)
            for stage in selected))
    else:
        # Non-manifest/ad-hoc analysis retains the interactive specialist agents.
        agents = await _get_agents()
        results = await asyncio.gather(*(
            _invoke_branch(stage, agents[stage], component_evidence, analysis_context, group_id)
            for stage in selected))
    duration_ms = round((time.perf_counter() - group_started) * 1000)
    status = "completed" if all(item["status"] == "completed" for item in results) else "partial_failure"
    monitor.report_parallel_group(group_id, selected, status, duration_ms)
    return {
        "parallel_group_id": group_id,
        "status": status,
        "duration_ms": duration_ms,
        "stages": {item["stage_id"]: item for item in results},
    }


@tool
async def parallel_dependency_analysis(
    component_evidence: str,
    analysis_context: str = "",
    stage_ids: list[str] | None = None,
) -> str:
    """在一个并行组中执行 S2 漏洞、S3 许可证维护性、S4 影响分析。

    首次调用不要传 stage_ids，将同时启动 S2/S3/S4；仅在某分支失败重试时传对应阶段。
    """
    result = await run_parallel_analysis(component_evidence, analysis_context, stage_ids)
    return json.dumps(result, ensure_ascii=False)
