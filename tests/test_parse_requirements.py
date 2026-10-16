"""M11 —— requirements.txt 解析单元测试。"""
from tools.parse_requirements import parse_requirements


def test_parse_simple_pin():
    result = parse_requirements("requests==2.31.0\n")
    assert result == [{"name": "requests", "version": "2.31.0"}]


def test_parse_mixed_lines():
    content = "# 注释\nflask\n\ndjango>=4.0\n-r other.txt\n--index-url https://x\n"
    result = parse_requirements(content)
    names = [p["name"] for p in result]
    assert names == ["flask", "django"]  # 注释/空行/-r/--index-url 被跳过
    assert result[1]["version"] == ">=4.0"


def test_parse_no_version():
    result = parse_requirements("numpy\n")
    assert result == [{"name": "numpy", "version": ""}]


def test_parse_inline_comment():
    result = parse_requirements("urllib3==1.26.0 # 间接依赖\n")
    assert result == [{"name": "urllib3", "version": "1.26.0"}]
