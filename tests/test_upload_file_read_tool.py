import json

from api.context import set_session_context, reset_session_context
from tools.upload_file_read_tool import read_file_content


def test_s2_read_is_bounded_and_component_filter_works(tmp_path):
    evidence = {
        "components": [{"name": "pyjwt"}, {"name": "pillow"}],
        "vulnerabilities": [
            {"canonical_id": f"GHSA-pyjwt-{i}", "affected_component": "pyjwt",
             "references": ["https://example.com/" + "x" * 1000]}
            for i in range(80)
        ] + [{"canonical_id": "GHSA-pillow-one", "affected_component": "pillow"}],
    }
    (tmp_path / "s2_evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
    token = set_session_context(str(tmp_path))
    try:
        overview = read_file_content.func("s2_evidence.json", "提取全部漏洞情报")
        selected = read_file_content.func("s2_evidence.json", "只输出 pillow 的条目")
    finally:
        reset_session_context(token)
    assert len(overview) < 3000
    assert "大文件不返回全部原文" in overview
    assert json.loads(selected)["selected_total"] == 1
    assert "GHSA-pillow-one" in selected
    assert "GHSA-pyjwt-0" not in selected


def test_large_markdown_head_request_is_honored(tmp_path):
    (tmp_path / "report.md").write_text("header\n" + "line\n" * 10000, encoding="utf-8")
    token = set_session_context(str(tmp_path))
    try:
        content = read_file_content.func("report.md", "提取文件开头前 3 行")
    finally:
        reset_session_context(token)
    assert content.startswith("header\nline\nline")
    assert "仅返回前 3/" in content
    assert len(content) < 100
