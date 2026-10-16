"""轻量源码影响分析：在会话工作目录中查找依赖引用证据。"""
import json
import re
from pathlib import Path

from langchain_core.tools import tool

from api.context import get_session_context
from utils.path_utils import resolve_path

_SOURCE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".rb", ".php"}
_IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".pytest_cache"}


def find_dependency_usage(root: Path, package_name: str, max_files: int = 2000, max_hits: int = 100) -> list[dict]:
    """扫描源码中的依赖引用，返回文件、行号、片段和代码区域。"""
    package_name = package_name.strip()
    if not package_name:
        return []

    variants = {package_name, package_name.replace("-", "_")}
    if "/" in package_name:
        variants.add(package_name.split("/")[-1])
    patterns = [
        re.compile(r"^\s*(?:from|import)\s+" + re.escape(v) + r"(?:\b|\.)", re.IGNORECASE)
        for v in variants
    ]
    patterns += [
        re.compile(
            r"""(?:require\s*\(\s*['"]|from\s*['"]|import\s*\(\s*['"])""" + re.escape(v) + r"""(?:['"]|/)""",
            re.IGNORECASE,
        )
        for v in variants
    ]

    hits: list[dict] = []
    scanned = 0
    for path in root.rglob("*"):
        if scanned >= max_files or len(hits) >= max_hits:
            break
        if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
            continue
        if any(part in _IGNORED_DIRS for part in path.parts):
            continue
        scanned += 1
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            if any(pattern.search(line) for pattern in patterns):
                relative = path.relative_to(root)
                is_test = any(part.lower() in {"test", "tests", "__tests__"} for part in relative.parts)
                hits.append(
                    {
                        "file": relative.as_posix(),
                        "line": line_no,
                        "scope": "test" if is_test else "production",
                        "snippet": line.strip()[:300],
                    }
                )
                if len(hits) >= max_hits:
                    break
    return hits


@tool
def analyze_dependency_usage(package_name: str, path: str = ".") -> str:
    """在工作目录源码中查找指定依赖的 import/require 引用证据。"""
    session_dir = get_session_context()
    if not session_dir:
        return json.dumps({"error": "缺少会话工作目录"}, ensure_ascii=False)

    root = Path(resolve_path(path, session_dir)).resolve()
    session_root = Path(session_dir).resolve()
    if not root.is_relative_to(session_root) or not root.exists() or not root.is_dir():
        return json.dumps({"error": "扫描路径无效或超出工作目录"}, ensure_ascii=False)

    hits = find_dependency_usage(root, package_name)
    return json.dumps(
        {
            "package": package_name,
            "static_references": len(hits),
            "evidence": hits,
            "limitation": "轻量静态扫描不覆盖动态加载、反射、插件注册或运行时生成代码。",
        },
        ensure_ascii=False,
    )
