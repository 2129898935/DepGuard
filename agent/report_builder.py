"""Produce a readable report from persisted evidence without asking an LLM to copy it."""

import json
from collections import Counter, defaultdict


LEVELS = ("critical", "high", "medium", "low", "info", "unknown")


def deduplicate_vulnerabilities(items):
    """Merge GHSA/CVE/PYSEC aliases for the same affected package."""
    records = [item for item in items if isinstance(item, dict)
               and (item.get("canonical_id") or item.get("id"))]
    parents = list(range(len(records)))

    def root(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    seen = {}
    for index, item in enumerate(records):
        package = str(item.get("affected_component") or "").lower()
        ecosystem = str(item.get("affected_ecosystem") or "").lower()
        for alias in [item.get("canonical_id") or item.get("id"), *(item.get("aliases") or [])]:
            if not alias:
                continue
            key = (ecosystem, package, str(alias).lower())
            if key in seen:
                parents[root(index)] = root(seen[key])
            else:
                seen[key] = index

    groups = defaultdict(list)
    for index, item in enumerate(records):
        groups[root(index)].append(item)
    merged = []
    for group in groups.values():
        group.sort(key=lambda item: (
            item.get("evidence_status") != "confirmed",
            not str(item.get("canonical_id") or item.get("id")).startswith("GHSA-"),
            str(item.get("canonical_id") or item.get("id")),
        ))
        chosen = dict(group[0])
        canonical = chosen.get("canonical_id") or chosen.get("id")
        aliases = []
        for item in group:
            aliases.extend([item.get("canonical_id") or item.get("id"), *(item.get("aliases") or [])])
        chosen["canonical_id"] = canonical
        chosen["aliases"] = list(dict.fromkeys(str(alias) for alias in aliases
                                               if alias and str(alias) != canonical))
        for field in ("ratings", "fixed_versions", "references"):
            values = [value for item in group for value in item.get(field) or []]
            chosen[field] = list({json.dumps(value, sort_keys=True, ensure_ascii=False): value
                                  for value in values}.values())
        if not chosen.get("summary"):
            chosen["summary"] = next((item.get("summary") for item in group if item.get("summary")), "")
        if any(item.get("evidence_status") == "confirmed" for item in group):
            chosen["evidence_status"] = "confirmed"
        merged.append(chosen)
    return merged


def cell(value):
    return str(value if value not in (None, "") else "待确认").replace("|", "\\|").replace("\n", " ")


def rating(item):
    ratings = [r for r in item.get("ratings", []) if isinstance(r, dict)]
    rated = next((r for r in ratings if str(r.get("severity", "")).lower() in LEVELS[:-1]),
                 ratings[0] if ratings else {})
    level = str(rated.get("severity") or "unknown").lower()
    if level not in LEVELS:
        level = "unknown"
    detail = " / ".join(cell(rated.get(k)) for k in ("source", "cvss_version", "score"))
    return level, detail


def render_report(s1, s2, s3, s4, s5_text, sbom):
    packages = s1.get("components") or []
    unique = {item["canonical_id"]: item for item in
              deduplicate_vulnerabilities(s2.get("vulnerabilities") or [])}
    grouped = defaultdict(list)
    severity = Counter()
    id_only = 0
    for key, item in unique.items():
        grouped[str(item.get("affected_component") or "待确认")].append((key, item))
        if item.get("evidence_status") == "id_only":
            id_only += 1
        else:
            severity[rating(item)[0]] += 1
    source = ", ".join(s1.get("source_files") or []) or "待确认"
    versions = {str(p.get("name", "")).lower(): str(p.get("version") or "待确认") for p in packages}
    lines = [
        "# 依赖风险审计报告", "",
        f"- 组件数: {len(sbom['components'])}",
        f"- 唯一漏洞数: {len(sbom['vulnerabilities'])}", "",
        "## 执行摘要", "",
        f"本次扫描覆盖 **{len(packages)} 个直接依赖**（{source}），在 **{len(grouped)} 个组件**中记录 **{len(unique)} 条去重漏洞情报**。",
        "情报匹配提交的版本，不等于已确认源码可达或可利用。", "",
        "| 严重度 | 数量 |", "| --- | ---: |",
    ]
    lines.extend(f"| {level.upper()} | {severity[level]} |" for level in LEVELS)
    lines += [f"| 仅有 ID、无法分级 | {id_only} |", ""]
    priority = sorted(name for name, entries in grouped.items()
                      if any(item.get("evidence_status") != "id_only"
                             and rating(item)[0] in ("critical", "high") for _, item in entries))
    lines.append("需优先核查的 HIGH/CRITICAL 组件：" + (", ".join(priority) if priority else
                 "暂无可核实分级；UNKNOWN 不能视为低风险") + "。")
    lines += ["", "## 范围、方法与证据来源", "",
              f"- 直接依赖来自 {source}；完整 {len(packages)} 项清单见 SBOM。",
              "- 漏洞证据：s2_evidence.json；按 canonical ID 去重，别名不重复计数。",
              "- 许可证/维护性：s3_evidence.json；源码影响：s4_evidence.json。",
              "- 传递依赖未完整解析或扫描，不能将本报告视为完整依赖树的安全证明。"]
    for stage, data in (("S2", s2), ("S3", s3)):
        degradation = (data.get("source_status") or {}).get("degradation")
        if degradation:
            lines.append(f"- {stage} 降级：{cell(degradation)}。")
    if s4.get("status") not in (None, "completed"):
        lines.append(f"- S4 降级：{cell(s4['status'])}。")
    lines += ["", "## 重点组件与处置顺序", "",
              "按情报条数排序，**不是风险等级排序**。候选版本仅来自 S2，升级前仍须验证兼容性。", "",
              "| 组件 | 当前版本 | 情报条数 | 候选修复版本 |", "| --- | --- | ---: | --- |"]
    for name, entries in sorted(grouped.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        fixes = list(dict.fromkeys(str(fix) for _, item in entries
                                   for fix in item.get("fixed_versions") or [] if fix))
        candidates = ", ".join(fixes[:3]) + (f" 等 {len(fixes)} 个" if len(fixes) > 3 else "")
        lines.append(f"| {cell(name)} | {cell(versions.get(name.lower()))} | {len(entries)} | {cell(candidates)} |")
    license_rows = s3.get("components") or []
    licenses = Counter(str(value) for item in license_rows for value in item.get("licenses") or [])
    unknown_license = sum(not item.get("licenses") for item in license_rows)
    nonstandard_license = sum(any(str(value).lower() == "non-standard"
                                  for value in item.get("licenses") or []) for item in license_rows)
    unknown_repo = sum(str(item.get("repository_status") or "unknown").lower() == "unknown"
                       for item in license_rows)
    deprecated = [str(item.get("name")) for item in license_rows if item.get("is_deprecated") is True]
    lines += ["", "## 许可证与维护性", "",
              f"S3 返回 {len(license_rows)} 个组件；许可证缺失 {unknown_license} 个、标为 non-standard {nonstandard_license} 个（需人工核验），仓库维护状态未知 {unknown_repo} 个。",
              "已识别许可证（一个组件可能有多个）：" +
              (", ".join(f"{cell(name)} {count}" for name, count in licenses.most_common(8)) if licenses else "待确认") + "。",
              "明确标记废弃：" + (", ".join(deprecated) if deprecated else "无；不代表其余组件已证实活跃") + "。"]
    impact = s4.get("scan_summary") or {}
    lines += ["", "## 源码影响分析", "",
              f"S4 状态：{cell(s4.get('status'))}；已检查 {cell(impact.get('packages_scanned'))} 个组件，静态引用命中 {cell(impact.get('total_static_references'))} 处。"]
    if s4.get("status") == "degraded_no_source_evidence":
        lines.append("工作目录没有可分析的源码，**不能据此断言依赖未使用或漏洞不可达**；需提供源码后重跑。")
    else:
        lines.append("静态扫描不覆盖动态加载、插件和反射；真实可达性仍需验证。")
    try:
        plan = json.loads(s5_text)
        plan_valid = isinstance(plan, dict)
    except (json.JSONDecodeError, TypeError):
        plan = {}
        plan_valid = False
    lines += ["", "## 升级、验证与回滚", "",
              "1. 以重点组件的候选修复版本为起点，核对 PyPI 发行版本、Python 要求和上下游约束；单条漏洞的修复版本不一定覆盖该组件的全部漏洞。",
              "2. 在隔离分支分批升级并重新锁定，运行 python -m pip check、项目测试和漏洞复扫；高耦合依赖须联合回归。",
              "3. 保存原锁定文件与镜像版本；测试或复扫失败时恢复原锁定文件并部署先前镜像。", ""]
    lines.append("S5 的结构化计划见 s5_plan.txt；目标版本仍须对照 S2 和兼容性复核。"
                 if plan_valid else
                 "**S5 计划降级：输出不是完整 JSON，可能已截断；未将其中未经复核的目标版本纳入本报告。**")
    dispositions = plan.get("dispositions") or [] if plan_valid else []
    planned = [row for row in dispositions if row.get("decision") == "plan"]
    review = [row for row in dispositions if row.get("needs_disposition")
              and row.get("decision") != "plan"]
    if dispositions:
        lines += ["", f"已形成 {len(planned)} 个候选升级计划；{len(review)} 个待人工处置。",
                  "候选版本仅通过所记录情报源核查，**兼容性与生产可部署性尚未验证**。", "",
                  "| 组件 | 当前版本 | 候选目标 | 状态 | 依据条数 / 索引 |",
                  "| --- | --- | --- | --- | --- |"]
        for row in planned:
            refs = row.get("evidence_refs") or []
            lines.append(f"| {cell(row.get('name'))} | {cell(row.get('current_version'))} | "
                         f"{cell(row.get('target_version'))} | {cell(row.get('plan_status'))} | "
                         f"{len(refs)} 条；详见 s5_plan.txt |")
        if review:
            lines += ["", "待人工处置组件：" + ", ".join(
                f"{cell(row.get('name'))}（{cell(row.get('reason_code'))}）" for row in review) + "。"]
    for stage, data in (("S2", s2), ("S3", s3), ("S4", s4)):
        coverage = data.get("coverage") or {}
        if coverage.get("uncovered"):
            lines.append(f"{stage} 非完整覆盖 {len(coverage['uncovered'])} 项；明细及原因码见 {stage.lower()}_evidence.json。")
    lines += ["", "## 待确认项", "",
              "- UNKNOWN/仅 ID 漏洞的可信严重度、CVSS 评分来源与修复范围。",
              "- 传递依赖覆盖情况、生产与开发依赖边界。",
              "- 目标版本兼容性、部署环境可达性、许可证与维护性未知项。", "",
              "## 漏洞明细（审计附录）", "",
              "每条只保留一个主证据链接；完整别名、受影响范围及引用见 s2_evidence.json。", "",
              "| 组件 | 当前版本 | Canonical ID / 别名 | 严重度 | 来源 / CVSS 版本 / 分数 | 修复版本 | 主证据 |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for name, entries in sorted(grouped.items()):
        for key, item in sorted(entries):
            level, detail = rating(item)
            if item.get("evidence_status") == "id_only":
                level, detail = "ID_ONLY", "待确认"
            aliases = ", ".join(str(v) for v in (item.get("aliases") or [])[:3])
            identity = cell(key) + (f" ({cell(aliases)})" if aliases else "")
            fixes = ", ".join(str(v) for v in item.get("fixed_versions") or [])
            refs = [r.get("url") if isinstance(r, dict) else r for r in item.get("references") or []]
            link = next((r for r in refs if isinstance(r, str) and r.startswith("https://")), "")
            evidence = f"[公告]({link})" if link else "待确认"
            lines.append(f"| {cell(name)} | {cell(versions.get(name.lower()))} | {identity} | {level.upper()} | {cell(detail)} | {cell(fixes)} | {evidence} |")
    return "\n".join(lines) + "\n"
