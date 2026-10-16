import logging
import json
import re
from collections import Counter
from pathlib import Path
from typing import Annotated, Optional

from langchain_core.tools import tool
from api.monitor import monitor
from api.context import get_session_context
from utils.path_utils import resolve_path
from agent.report_builder import deduplicate_vulnerabilities


def _bounded_text(content: str, instruction: str) -> str:
    """Respect head requests and keep large files out of the model context."""
    match = re.search(r"(?:前|头部|开头)\s*(\d{1,4})\s*行", instruction)
    if match or any(word in instruction for word in ("头部", "开头")):
        limit = min(int(match.group(1)) if match else 60, 200)
        lines = content.splitlines()
        return "\n".join(lines[:limit]) + (f"\n[仅返回前 {limit}/{len(lines)} 行]" if len(lines) > limit else "")
    if len(content) > 24000:
        return content[:22000] + f"\n[文件共 {len(content)} 字符，已截断；请指定组件或读取头部，不要反复读取整文件]"
    return content


def _summarize_json(filename: str, content: str, instruction: str) -> str:
    """Provide bounded, deterministic views of large evidence bundles."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return _bounded_text(content, instruction)
    if not isinstance(data, dict):
        return _bounded_text(content, instruction)
    if filename == "s2_evidence.json":
        raw_vulns = data.get("vulnerabilities") or []
        vulns = deduplicate_vulnerabilities(raw_vulns)
        components = data.get("components") or []
        names = {str(item.get("name", "")).lower() for item in components if isinstance(item, dict)}
        selected = sorted(name for name in names
                          if name and re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])",
                                                instruction, re.I))
        counts = Counter(str(item.get("affected_component") or "unknown") for item in vulns)
        summary = {"stage": "S2", "source_status": data.get("source_status"),
                   "components": len(components), "raw_records": len(raw_vulns),
                   "unique_vulnerabilities": len(vulns),
                   "id_only": sum(item.get("evidence_status") == "id_only" for item in vulns),
                   "by_component": dict(counts.most_common(30))}
        if selected:
            matches = [item for item in vulns
                       if str(item.get("affected_component") or "").lower() in selected]
            summary["selected_components"] = selected
            summary["selected_total"] = len(matches)
            summary["selected_vulnerabilities"] = [
                {key: item.get(key) for key in ("canonical_id", "aliases", "affected_component",
                 "affected_version", "ratings", "fixed_versions", "evidence_status")}
                for item in matches[:50]
            ]
            if len(matches) > 50:
                summary["notice"] = "仅返回前 50 条；请缩小到单个组件"
        else:
            summary["notice"] = "大文件不返回全部原文；请在 instruction 中指定组件名。完整证据仍保存在文件中。"
        return _bounded_text(json.dumps(summary, ensure_ascii=False, separators=(",", ":")), instruction)
    if filename == "s3_evidence.json":
        rows = data.get("components") or []
        licenses = Counter(str(value) for row in rows for value in row.get("licenses") or [])
        result = {"stage": "S3", "source_status": data.get("source_status"),
                  "components": len(rows), "licenses": dict(licenses.most_common(20)),
                  "unknown_license": sum(not row.get("licenses") for row in rows),
                  "unknown_repository_status": sum(
                      str(row.get("repository_status") or "unknown").lower() == "unknown"
                      for row in rows)}
        return json.dumps(result, ensure_ascii=False)
    if filename == "sbom.cdx.json":
        result = {key: data.get(key) for key in ("bomFormat", "specVersion", "metadata")}
        result["components"] = len(data.get("components") or [])
        result["vulnerabilities"] = len(data.get("vulnerabilities") or [])
        return _bounded_text(json.dumps(result, ensure_ascii=False), instruction)
    return _bounded_text(content, instruction)

# 尝试导入可选依赖，实现按需加载
try:
    import docx
except ImportError:
    docx = None

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    import pandas as pd
except ImportError:
    pd = None


# def read_file_content(filename: str, instruction: str = "提取全部内容") -> str:
#     """
#     读取指定文件的内容。支持 Markdown(.md)、Word(.docx)、PDF(.pdf) 和 Excel(.xlsx/.xls)。
#     对于 Excel 文件，会自动提供数据统计信息（head 和 describe）。

#     Args:
#         filename: 要读取的文件名或路径（支持 .md, .docx, .pdf, .xlsx, .xls）
#         instruction: 对提取内容的具体指令（例如：'提取摘要', '统计数据'）

@tool
def read_file_content(
        filename: Annotated[str, "要读取的文件名或路径（支持 .md, .docx, .pdf, .xlsx, .xls）"],
        instruction: Annotated[str, "对提取内容的具体指令（例如：'提取摘要', '统计数据'）"] = "提取全部内容"
) -> str:
    """
    读取指定文件的内容。支持 Markdown(.md)、Word(.docx)、PDF(.pdf) 和 Excel(.xlsx/.xls)。
    对于 Excel 文件，会自动提供数据统计信息（head 和 describe）。
    """
    monitor.report_tool("文件内容读取工具", {"filename": filename, "instruction": instruction})

    # ====================== 1. Path 重构路径解析 ======================
    session_dir = get_session_context()
    file_path = Path(resolve_path(filename, session_dir))  # 转为Path对象

    # 检查文件是否存在（替代os.path.exists）
    if not file_path.exists():
        return f"错误：文件 '{filename}' 不存在 (解析路径: {file_path})。"

    # 获取后缀名（替代os.path.splitext，自动转小写）
    ext = file_path.suffix.lower()

    try:
        if ext in ['.md', '.txt']:
            # Path直接读取文本（替代open + os.path）
            return _bounded_text(file_path.read_text(encoding='utf-8'), instruction)

        elif ext == '.docx':
            if docx is None:
                return "错误：未安装 'python-docx' 库，无法读取 Word 文件。"
            doc = docx.Document(str(file_path))  # 转字符串传给docx
            full_text = [para.text for para in doc.paragraphs]
            return '\n'.join(full_text)

        elif ext == '.pdf':
            if pypdf is None:
                return "错误：未安装 'pypdf' 库，无法读取 PDF 文件。"
            reader = pypdf.PdfReader(str(file_path))  # 转字符串传给pypdf
            text = "\n".join([page.extract_text() or "" for page in reader.pages])
            return text

        elif ext in ['.xlsx', '.xls']:
            if pd is None:
                return "错误：未安装 'pandas' 库，无法读取 Excel 文件。"

            try:
                df = pd.read_excel(str(file_path))  # 转字符串传给pandas
            except Exception as e:
                return f"读取 Excel 失败: {str(e)}"

            result = [
                f"文件: {filename}",
                f"行数: {len(df)}, 列数: {len(df.columns)}",
                f"列名: {', '.join(df.columns.astype(str))}",
                "\n[前5行数据预览]:",
                df.head().to_string(index=False),
                "\n[统计描述]:",
                df.describe().to_string()
            ]
            return "\n".join(result)

        elif ext == '.json':
            return _summarize_json(file_path.name, file_path.read_text(encoding='utf-8'), instruction)

        else:
            # 尝试作为纯文本读取
            try:
                return _bounded_text(file_path.read_text(encoding='utf-8'), instruction)
            except UnicodeDecodeError:
                return f"错误：不支持的文件格式 '{ext}'，且无法作为文本读取。"

    except Exception as e:
        return f"读取文件出错: {str(e)}"

# ====================== 测试入口（完全按你要求的格式） ======================
if __name__ == '__main__':
    # 1. 固定 session_dir（仅赋值，不Mock）
    def get_session_context():
        return "./test_session_123"

    # 2. 定义测试文件路径
    md_path = "sub_dir/测试文件.md"
    excel_path = "sub_dir/测试数据.xlsx"

    # 3. 测试调用（先测试MD文件，指令用默认）
    result = read_file_content.invoke({
        "filename": md_path
    })
    print("===== 读取MD文件结果 =====")
    print(result)

    # 可选：测试Excel文件（取消注释即可）
    # result_excel = read_file_content.invoke({
    #     "filename": excel_path,
    #     "instruction": "统计数据"
    # })
    # print("\n===== 读取Excel文件结果 =====")
    # print(result_excel)
