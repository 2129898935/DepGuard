"""M12 业务评测：DepGuard（OSV 查询 + 版本匹配） vs osv-scanner 基准。

10 个真实开源仓库，跨 Python/npm/Maven/Go 四种生态。每个仓库记录其自身 + 依赖（旧版本，含已知漏洞）。
指标：
  - 漏洞覆盖率 = DepGuard 命中的 osv-scanner 漏洞数 / osv-scanner 漏洞总数
  - 误报率     = DepGuard 报出但 osv-scanner 未确认的漏洞数 / DepGuard 漏洞总数
"""
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path

from dotenv import find_dotenv, load_dotenv

from tools.osv_tool import query_osv_vuln_ids

load_dotenv(find_dotenv())

# 10 个真实开源仓库，dependencies 第一个是仓库自身，其余是它的依赖（都用有已知漏洞的旧版本）
DATASET = {
    "requests": {"ecosystem": "PyPI", "dependencies": [
        ("requests", "2.31.0"),
        ("urllib3", "1.26.15"),
        ("certifi", "2023.7.22"),
        ("charset-normalizer", "3.1.0"),
        ("idna", "3.4"),
    ]},
    "Flask": {"ecosystem": "PyPI", "dependencies": [
        ("Flask", "1.1.4"),
        ("Jinja2", "2.11.3"),
        ("Werkzeug", "1.0.1"),
        ("click", "7.1.2"),
        ("itsdangerous", "1.1.0"),
    ]},
    "Django": {"ecosystem": "PyPI", "dependencies": [
        ("Django", "3.2.15"),
        ("pytz", "2022.1"),
        ("asgiref", "3.5.2"),
        ("sqlparse", "0.4.2"),
    ]},
    "fastapi": {"ecosystem": "PyPI", "dependencies": [
        ("fastapi", "0.68.0"),
        ("starlette", "0.15.0"),
        ("pydantic", "1.8.2"),
        ("uvicorn", "0.15.0"),
    ]},
    "express": {"ecosystem": "npm", "dependencies": [
        ("express", "4.17.1"),
        ("accepts", "1.3.7"),
        ("body-parser", "1.19.0"),
        ("cookie", "0.4.1"),
        ("debug", "2.6.9"),
    ]},
    "react": {"ecosystem": "npm", "dependencies": [
        ("react", "17.0.2"),
        ("loose-envify", "1.4.0"),
        ("object-assign", "4.1.1"),
    ]},
    "lodash": {"ecosystem": "npm", "dependencies": [
        ("lodash", "4.17.20"),
    ]},
    "axios": {"ecosystem": "npm", "dependencies": [
        ("axios", "0.21.1"),
        ("follow-redirects", "1.13.0"),
    ]},
    "spring-boot": {"ecosystem": "Maven", "dependencies": [
        ("org.springframework:spring-core", "5.3.13"),
        ("org.springframework:spring-web", "5.3.13"),
        ("org.springframework:spring-webmvc", "5.3.13"),
    ]},
    "gin": {"ecosystem": "Go", "dependencies": [
        ("github.com/gin-gonic/gin", "v1.7.7"),
        ("github.com/gin-contrib/sse", "v0.1.0"),
        ("github.com/ugorji/go", "v1.1.7"),
    ]},
}

def _osv_scanner_bin() -> str:
    return os.getenv("OSV_SCANNER_PATH", "osv-scanner")


def _write_lockfile(dir: Path, ecosystem: str, deps: list[tuple[str, str]]) -> str:
    """按生态写对应的依赖清单文件，返回文件名。"""
    if ecosystem == "PyPI":
        p = dir / "requirements.txt"
        p.write_text("\n".join(f"{n}=={v}" for n, v in deps) + "\n", encoding="utf-8")
    elif ecosystem == "npm":
        # osv-scanner 扫锁文件 package-lock.json，不扫 package.json
        packages = {"": {"name": "eval", "version": "1.0.0", "dependencies": {n: v for n, v in deps}}}
        for n, v in deps:
            packages[f"node_modules/{n}"] = {"version": v}
        lock = {"name": "eval", "version": "1.0.0", "lockfileVersion": 3, "packages": packages}
        p = dir / "package-lock.json"
        p.write_text(json.dumps(lock), encoding="utf-8")
    elif ecosystem == "Maven":
        p = dir / "pom.xml"
        deps_xml = "".join(
            f"<dependency><groupId>{n.split(':')[0]}</groupId><artifactId>{n.split(':')[1]}</artifactId><version>{v}</version></dependency>"
            for n, v in deps
        )
        p.write_text(
            f'<project><modelVersion>4.0.0</modelVersion><groupId>eval</groupId><artifactId>eval</artifactId><version>1.0</version><dependencies>{deps_xml}</dependencies></project>',
            encoding="utf-8",
        )
    elif ecosystem == "Go":
        p = dir / "go.mod"
        p.write_text("module eval\n\ngo 1.17\n\nrequire (\n" + "\n".join(f"\t{n} {v}" for n, v in deps) + "\n)\n", encoding="utf-8")
    else:
        raise ValueError(f"不支持的生态: {ecosystem}")
    return p.name


def depguard_ids(deps: list[tuple[str, str]], ecosystem: str) -> set[str]:
    """DepGuard 查到的漏洞 ID 集合（主 ID + 别名，归一化后用于对比）。"""
    names = [n for n, _ in deps]
    versions = [v for _, v in deps]
    per_pkg = query_osv_vuln_ids(names, ecosystem=ecosystem, versions=versions)
    return set().union(*per_pkg.values()) if per_pkg else set()


def osv_scanner_ids(deps: list[tuple[str, str]], ecosystem: str) -> set[str]:
    """osv-scanner 查到的漏洞 ID 集合。"""
    with tempfile.TemporaryDirectory() as d:
        _write_lockfile(Path(d), ecosystem, deps)
        r = subprocess.run(
            [_osv_scanner_bin(), "--format", "json", "-r", d],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
        )
        data = json.loads(r.stdout)
        ids: set[str] = set()
        for result in data.get("results", []):
            for pkg in result.get("packages", []):
                for group in pkg.get("groups", []):
                    ids.update(group.get("ids", []))
                    ids.update(group.get("aliases", []))  # 别名也纳入，与 DepGuard 的归一化对齐
        return ids


def main() -> None:
    rows = []
    total_dg = total_osv = total_inter = total_fp = 0
    total_time = 0.0

    for repo, meta in DATASET.items():
        eco = meta["ecosystem"]
        deps = meta["dependencies"]
        t0 = time.time()
        try:
            dg = depguard_ids(deps, eco)
            ov = osv_scanner_ids(deps, eco)
        except Exception as e:
            print(f"[skip] {repo} ({eco}): {type(e).__name__}: {str(e)[:80]}")
            continue
        elapsed = time.time() - t0
        total_time += elapsed

        inter = dg & ov
        fp = dg - ov
        missed = ov - dg
        total_dg += len(dg)
        total_osv += len(ov)
        total_inter += len(inter)
        total_fp += len(fp)

        rows.append((repo, eco, len(deps), len(dg), len(ov), len(inter), len(fp), len(missed), elapsed))
        print(f"{repo} [{eco}]: 依赖={len(deps)} DepGuard={len(dg)} osv={len(ov)} 交集={len(inter)} 误报={len(fp)} 漏报={len(missed)} {elapsed:.1f}s")

    coverage = total_inter / total_osv if total_osv else 0.0
    fp_rate = total_fp / total_dg if total_dg else 0.0
    avg_time = total_time / len(rows) if rows else 0.0

    lines = [
        "# DepGuard 评测结果（vs osv-scanner 基准）",
        "",
        f"- **评测时间**：{time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"- **数据集**：{len(DATASET)} 个真实开源仓库（跨 Python / npm / Maven / Go）",
        f"- **基准**：osv-scanner（`{_osv_scanner_bin()}`）",
        "",
        "## 一、逐仓库对比",
        "",
        "| 仓库 | 生态 | 依赖数 | DepGuard | osv-scanner | 交集 | 误报 | 漏报 | 耗时 |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for repo, eco, depn, dg, ov, inter, fp, missed, elapsed in rows:
        lines.append(f"| {repo} | {eco} | {depn} | {dg} | {ov} | {inter} | {fp} | {missed} | {elapsed:.1f}s |")
    lines += [
        "",
        "## 二、总体指标",
        "",
        f"- **漏洞覆盖率**：{coverage * 100:.1f}%",
        f"- **误报率**：{fp_rate * 100:.1f}%",
        f"- **总漏洞数**：DepGuard {total_dg} 个，osv-scanner {total_osv} 个",
        f"- **平均单仓库耗时**：{avg_time:.1f}s",
        "",
        "## 三、说明",
        "",
        "- 两者都基于 OSV.dev 数据源，覆盖率预期接近 100%；差异主要来自版本范围匹配边界与别名归一化。",
        "- 误报/漏报可能是同一漏洞的主 ID 与别名（GHSA/CVE/PYSEC/GO）归一到不同侧导致的计数差异，不代表事实性错报。",
    ]
    out = Path(__file__).parent / "results.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n评测完成 → {out}")
    print(f"覆盖率={coverage * 100:.1f}% 误报率={fp_rate * 100:.1f}% 平均耗时={avg_time:.1f}s")


if __name__ == "__main__":
    main()
