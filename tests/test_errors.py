"""M6 —— 错误分类 ToolError 单元测试。"""
import json

from utils.errors import ErrorCategory, ToolError


def test_to_result_structure():
    e = ToolError(
        category=ErrorCategory.FATAL,
        message="数据库查询失败",
        retryable=False,
        suggestion="请检查连接",
    )
    r = e.to_result()
    assert r["ok"] is False
    assert r["error"] == "FATAL"
    assert r["message"] == "数据库查询失败"
    assert r["retryable"] is False
    assert r["suggestion"] == "请检查连接"


def test_str_returns_message():
    e = ToolError(ErrorCategory.INVALID_INPUT, "参数错误")
    assert str(e) == "参数错误"


def test_defaults():
    e = ToolError(ErrorCategory.RETRYABLE, "限流")
    assert e.retryable is False          # 默认不可重试
    assert e.suggestion is None
    assert e.to_result()["suggestion"] == ""


def test_to_result_str_is_json():
    e = ToolError(ErrorCategory.PERMISSION_DENIED, "被拒绝", suggestion="请改用只读查询")
    s = e.to_result_str()
    d = json.loads(s)  # 是合法 JSON
    assert d["ok"] is False
    assert d["error"] == "PERMISSION_DENIED"
    assert d["message"] == "被拒绝"
    assert d["suggestion"] == "请改用只读查询"


def test_categories_distinct():
    cats = {
        ErrorCategory.RETRYABLE,
        ErrorCategory.INVALID_INPUT,
        ErrorCategory.PERMISSION_DENIED,
        ErrorCategory.FATAL,
    }
    assert len(cats) == 4
