"""osv-scanner 本地基准工具（对齐 M11/M12）：调用本机 CLI 做交叉验证。

osv-scanner 是 Google 官方的本地依赖扫描器（Go 编写），
用于交叉验证依赖数量、许可证，并作为 M12 评测的「真实值」基准。
安装：go install github.com/google/osv-scanner/cmd/osv-scanner@latest
     或到 https://github.com/google/osv-scanner/releases 下载二进制。
"""
import os
import subprocess
from pathlib import Path

from dotenv import find_dotenv, load_dotenv
from langchain_core.tools import tool

from api.context import get_session_context
from utils.path_utils import resolve_path

load_dotenv(find_dotenv())


def _find_osv_scanner() -> str:
    """定位 osv-scanner 二进制：优先 OSV_SCANNER_PATH 环境变量，其次 PATH。"""
    env_path = os.getenv("OSV_SCANNER_PATH")
    if env_path and Path(env_path).exists():
        return env_path
    return "osv-scanner"  # 交给 subprocess 在 PATH 里找


@tool
def scan_repo_with_osv_scanner(path: str) -> str:
    """调用本地 osv-scanner 扫描指定目录，返回 JSON 结果（用于基准交叉验证）。"""
    try:
        # 相对路径解析到会话目录，与其它文件工具保持一致
        session_dir = get_session_context()
        resolved = resolve_path(path, session_dir) if session_dir else path
        r = subprocess.run(
            [_find_osv_scanner(), "--format", "json", "-r", resolved],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        # osv-scanner 退出码：0=无漏洞，1=发现漏洞（两者 stdout 都是有效 JSON），其它为扫描错误
        if r.returncode in (0, 1):
            return r.stdout[:5000]
        return f"osv-scanner 扫描失败（错误码 {r.returncode}）：{r.stderr[:500]}"
    except FileNotFoundError:
        return "未找到 osv-scanner，请安装后放入 PATH，或设置 OSV_SCANNER_PATH 指向 osv-scanner.exe"
    except Exception as e:
        return f"osv-scanner 执行失败：{e}"
