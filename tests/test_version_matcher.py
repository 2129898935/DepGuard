"""M11 —— 版本范围精确匹配单元测试。"""
from utils.version_matcher import is_affected


def test_fixed_range_exclusive():
    ranges = [{"events": [{"introduced": "0"}, {"fixed": "2.31.2"}]}]
    assert is_affected("2.31.0", ranges) is True
    assert is_affected("0.1", ranges) is True
    assert is_affected("2.31.2", ranges) is False   # fixed 是排他的
    assert is_affected("3.0.0", ranges) is False


def test_last_affected_range_inclusive():
    ranges = [{"events": [{"introduced": "2.31.0"}, {"last_affected": "2.31.1"}]}]
    assert is_affected("2.31.0", ranges) is True
    assert is_affected("2.31.1", ranges) is True    # last_affected 是包含的
    assert is_affected("2.31.2", ranges) is False


def test_no_ranges():
    assert is_affected("1.0.0", []) is False
    assert is_affected("1.0.0", [{"events": []}]) is False


def test_invalid_version_not_crash():
    ranges = [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
    assert is_affected("not-a-version", ranges) is False


def test_multiple_ranges_any_match():
    ranges = [
        {"events": [{"introduced": "0"}, {"fixed": "1.0"}]},
        {"events": [{"introduced": "2.0"}, {"fixed": "3.0"}]},
    ]
    assert is_affected("2.5", ranges) is True   # 命中第二个范围
    assert is_affected("1.5", ranges) is False  # 两个范围都不命中
