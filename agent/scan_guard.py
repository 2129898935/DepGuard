"""Full-scan detection and completion checks for DepGuard sessions."""

import json
import re
from pathlib import Path

from agent.planner import PlanTracker
from tools.parse_requirements import parse_requirements
from tools.sbom_tool import validate_deliverables, build_sbom
from api.context import get_session_context
from agent.report_builder import deduplicate_vulnerabilities, render_report
from agent.evidence_contract import normalize_components, content_hash
from agent.evidence_contract import validate_evidence_refs
from agent.batch_runtime import replay_stage
from agent.upgrade_batches import validate_plan

_MANIFEST_NAMES = {
    "pyproject.toml", "poetry.lock", "pipfile", "pipfile.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
}
_SCAN_TERMS = re.compile(
    r"扫描|审计|漏洞清单|风险报告|依赖风险|生成报告|生成\s*sbom|完整分析|全面分析|full scan|security audit",
    re.I,
)


def is_requirements_file(name: str) -> bool:
    value = name.lower()
    return value.startswith("requirements") and value.endswith(".txt")


def requires_full_scan(query: str, uploaded_files: list[str]) -> bool:
    """A dependency manifest submitted for analysis requires the six-stage workflow."""
    return any(is_requirements_file(name) or name.lower() in _MANIFEST_NAMES
               for name in uploaded_files) or bool(_SCAN_TERMS.search(query or ""))


def scan_completion_errors(tracker: PlanTracker, session_dir: Path,
                           uploaded_files: list[str]) -> list[str]:
    """Check stage results, deliverables, and direct requirements coverage."""
    errors = []
    if not tracker.is_complete():
        errors.append("未完成阶段：" + ", ".join(
            step.id for step in tracker.plan.steps if step.status != "done"
        ))
    result = json.loads(validate_deliverables.func(
        report_filename="dependency_risk_report.md",
        sbom_filename="sbom.cdx.json",
    ))
    errors.extend(result.get("errors", []))
    errors.extend(evidence_chain_errors(session_dir))
    sbom_path = session_dir / "sbom.cdx.json"
    if not sbom_path.is_file():
        return errors
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
        actual = {
            (re.sub(r"[-_.]+", "-", str(c.get("name", "")).lower()),
             str(c.get("version", "")))
            for c in sbom.get("components", [])
        }
        for filename in uploaded_files:
            if not is_requirements_file(filename):
                continue
            path = session_dir / Path(filename).name
            if not path.is_file():
                continue
            expected = parse_requirements(path.read_text(encoding="utf-8"))
            missing = [
                package["name"] for package in expected
                if not any(
                    name == re.sub(r"[-_.]+", "-", package["name"].lower())
                    and (not package["version"] or version == package["version"])
                    for name, version in actual
                )
            ]
            if missing:
                errors.append(
                    f"SBOM 未覆盖 {filename} 中 {len(missing)} 个直接依赖："
                    + ", ".join(missing[:10])
                )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors.append(f"依赖覆盖校验失败：{exc}")
    return errors


def evidence_chain_errors(session_dir: Path) -> list[str]:
    """Verify modern batch artifacts against S1, not just their record counts."""
    s1_path = session_dir / "s1_components.json"
    if not s1_path.is_file() or not (session_dir / "batch_plan_s2.json").is_file():
        return []  # Legacy/ad-hoc sessions do not have a batch contract.
    try:
        s1 = json.loads(s1_path.read_text(encoding="utf-8"))
        components = normalize_components(s1.get("components") or [])
        errors = []
        data = {}
        for stage in ("S2", "S3", "S4"):
            path = session_dir / f"{stage.lower()}_evidence.json"
            if not path.is_file():
                errors.append(f"{stage} 证据文件缺失")
                continue
            data[stage] = json.loads(path.read_text(encoding="utf-8"))
            replay = replay_stage(session_dir, stage, components)
            errors.extend(replay["errors"])
            key = {"S2": "vulnerabilities", "S3": "components", "S4": "package_results"}[stage]
            if content_hash(data[stage].get(key) or []) != content_hash(replay["records"]):
                errors.append(f"{stage} 汇总证据与叶批次产物不一致")
            coverage = data[stage].get("coverage") or {}
            if content_hash(coverage.get("outcomes") or []) != content_hash(replay["outcomes"]):
                errors.append(f"{stage} 汇总覆盖终态与批次不一致")
        if "S2" in data:
            errors.extend(validate_evidence_refs(components, data["S2"].get("vulnerabilities") or []))
        s5_path = session_dir / "s5_plan.txt"
        if all(stage in data for stage in ("S2", "S3", "S4")):
            if not s5_path.is_file():
                errors.append("S5 规划文件缺失")
            else:
                plan = json.loads(s5_path.read_text(encoding="utf-8"))
                for stage, value in (("S1", s1), *data.items()):
                    if plan.get("source_hashes", {}).get(stage) != content_hash(value):
                        errors.append(f"S5 输入证据快照与当前 {stage} 不一致")
                links_path = session_dir / "s5_dependency_links.json"
                if not links_path.is_file() or plan.get("dependency_links_hash") != content_hash(
                        json.loads(links_path.read_text(encoding="utf-8")).get("links") or []):
                    errors.append("S5 联动依赖快照与当前文件不一致")
                errors.extend(validate_plan(plan, s1, data["S2"], data["S3"], data["S4"]))
        return errors
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return [f"证据链校验失败：{exc}"]


def prepare_requirements_evidence(session_dir: Path, uploaded_files: list[str]) -> dict | None:
    """Parse complete uploaded requirements locally and persist lossless S1 evidence."""
    components = []
    sources = []
    for filename in uploaded_files:
        if not is_requirements_file(filename):
            continue
        path = session_dir / Path(filename).name
        if not path.is_file():
            continue
        packages = parse_requirements(path.read_text(encoding="utf-8"))
        components.extend({**package, "ecosystem": "PyPI", "source_file": filename}
                          for package in packages)
        sources.append(filename)
    if not sources:
        return None
    if not components:
        raise ValueError("上传的 requirements 文件没有可解析的依赖声明")
    components = normalize_components(components)
    result = {"stage": "S1", "source_files": sources,
              "total_components": len(components), "components": components,
              "component_set_hash": content_hash(sorted(c["component_id"] for c in components))}
    (session_dir / "s1_components.json").write_text(
        json.dumps(result, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )
    return result


class ScanExecution:
    """Only successful tool responses may complete stages."""

    def __init__(self, tracker: PlanTracker):
        self.tracker = tracker
        self.prevalidated_steps: set[str] = set()
        self.pending: dict[str, tuple[str, str | None]] = {}
        self.order_errors: list[str] = []

    def record_call(self, call: dict) -> None:
        name = call.get("name", "")
        args = call.get("args") or {}
        if name == "task":
            from agent.planner import subagent_to_step_id
            step_id = subagent_to_step_id(args.get("subagent_type", ""))
            if step_id and step_id not in self.prevalidated_steps:
                self._check_order(step_id)
                self.tracker.mark(step_id, "running")
                if call.get("id"):
                    self.pending[call["id"]] = ("task", step_id)
        elif name == "parallel_dependency_analysis":
            for step_id in (args.get("stage_ids") or ["S2", "S3", "S4"]):
                self._check_order(step_id)
                self.tracker.mark(step_id, "running")
            if call.get("id"):
                self.pending[call["id"]] = ("parallel", None)

    def _check_order(self, step_id: str) -> None:
        step = next((s for s in self.tracker.plan.steps if s.id == step_id), None)
        if step:
            missing = [dep for dep in step.depends_on
                       if next(s for s in self.tracker.plan.steps if s.id == dep).status != "done"]
            if missing:
                self.order_errors.append(f"{step_id} 启动时前置阶段未完成：{', '.join(missing)}")

    def record_result(self, message) -> None:
        call_id = getattr(message, "tool_call_id", None)
        pending = self.pending.pop(call_id, None)
        if not pending:
            return
        kind, step_id = pending
        content = getattr(message, "content", "")
        if isinstance(content, list):
            content = "\n".join(str(item) for item in content)
        content = str(content).strip()
        is_error = (getattr(message, "status", "success") == "error" or not content
                    or content.lower().startswith(("error:", "tool execution error", "工具执行失败")))
        if kind == "task" and step_id:
            if step_id == "S5" and not is_error:
                session = Path(get_session_context()) if get_session_context() else None
                modern = bool(session and (session / "batch_plan_s2.json").is_file())
                try:
                    plan = json.loads(content)
                    if not isinstance(plan, dict):
                        plan = {}
                except (ValueError, TypeError):
                    plan = {}
                if modern:
                    # The subagent may wrap a valid file index in prose.  The
                    # persisted, fully validated artifact is authoritative.
                    is_error = (plan.get("ok") is False or not (session / "s5_plan.txt").is_file()
                                or bool(evidence_chain_errors(session)))
                else:
                    is_error = not plan or plan.get("ok") is False
                    if not is_error and session:
                        (session / "s5_plan.txt").write_text(content, encoding="utf-8")
            if step_id == "S6" and not is_error and get_session_context() and (
                    Path(get_session_context()) / "batch_plan_s2.json").is_file():
                try:
                    review = json.loads(content)
                    if isinstance(review, dict) and review.get("ok") is False:
                        is_error = True
                except (ValueError, TypeError):
                    pass
                if not is_error:
                    try:
                        session = Path(get_session_context())
                        gate = json.loads(validate_deliverables.func(
                            expected_components=len(json.loads(
                                (session / "s1_components.json").read_text(encoding="utf-8")
                            ).get("components") or [])))
                        is_error = not gate.get("ok") or bool(evidence_chain_errors(session))
                    except (OSError, ValueError, TypeError, KeyError):
                        is_error = True
            self.tracker.mark(step_id, "failed" if is_error else "done")
        elif kind == "parallel":
            try:
                payload = json.loads(content) if not is_error else {}
                stages = payload.get("stages", {})
            except (ValueError, TypeError, AttributeError):
                stages = {}
            for stage in ("S2", "S3", "S4"):
                if self.tracker._by_id[stage].status == "running":
                    result = stages.get(stage)
                    self.tracker.mark(stage, "done" if result and result.get("status") == "completed" else "failed")


def build_deliverables_from_evidence(session_dir: Path) -> bool:
    """Build a factual report and CycloneDX SBOM from persisted stage evidence.

    Returns False until S1-S5 evidence is available. S6 reviews these files.
    """
    needed = ["s1_components.json", "s2_evidence.json", "s3_evidence.json",
              "s4_evidence.json", "s5_plan.txt"]
    if not all((session_dir / name).is_file() for name in needed):
        return False
    chain_errors = evidence_chain_errors(session_dir)
    if chain_errors:
        raise ValueError("证据链门禁失败：" + "；".join(chain_errors))
    s1, s2, s3, s4 = [json.loads((session_dir / name).read_text(encoding="utf-8"))
                      for name in needed[:4]]
    upgrade_plan = (session_dir / "s5_plan.txt").read_text(encoding="utf-8")
    packages = s1.get("components", [])
    if not isinstance(packages, list) or not packages:
        raise ValueError("S1 缺少组件清单")
    raw_vulnerabilities = s2.get("vulnerabilities", [])
    if not isinstance(raw_vulnerabilities, list):
        raise ValueError("S2 vulnerabilities 不是数组")
    unique = {item["canonical_id"]: item for item in
              deduplicate_vulnerabilities(raw_vulnerabilities)}
    vulnerabilities = []
    for canonical_id, item in unique.items():
        ratings = item.get("ratings") or []
        rating = next((r for r in ratings if isinstance(r, dict) and r.get("score") is not None),
                      ratings[0] if ratings and isinstance(ratings[0], dict) else {})
        affected = item.get("affected_component") or item.get("package")
        if isinstance(affected, dict):
            affected = affected.get("name")
        if not affected:
            raise ValueError(f"漏洞 {canonical_id} 缺少受影响组件")
        references = item.get("references") or []
        advisory_urls = [r.get("url") if isinstance(r, dict) else str(r)
                         for r in references]
        entry = {
            "id": canonical_id,
            "source": rating.get("source") or "OSV",
            "severity": str(rating.get("severity") or "unknown").lower(),
            "description": item.get("summary") or "",
            "affects": [affected],
            "advisories": [u for u in advisory_urls if u],
        }
        if rating.get("score") is not None:
            entry["score"] = rating["score"]
        if rating.get("cvss_version"):
            entry["method"] = rating["cvss_version"]
        vulnerabilities.append(entry)
    sbom = build_sbom(packages, vulnerabilities, application_name="scanned-application")
    (session_dir / "sbom.cdx.json").write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (session_dir / "dependency_risk_report.md").write_text(
        render_report(s1, s2, s3, s4, upgrade_plan, sbom), encoding="utf-8"
    )
    return True
