"""M6 —— 分级重试单元测试。"""
import pytest

from utils.errors import ErrorCategory, ToolError
from utils.retry import retry_with_backoff


def test_non_retryable_raises_immediately():
    calls = {"n": 0}

    @retry_with_backoff(max_retries=3, base_delay=0)
    def f():
        calls["n"] += 1
        raise ToolError(ErrorCategory.INVALID_INPUT, "参数错误", retryable=False)

    with pytest.raises(ToolError):
        f()
    assert calls["n"] == 1  # 不可重试：只调用一次，直接抛出不重试


def test_retryable_eventually_succeeds():
    calls = {"n": 0}

    @retry_with_backoff(max_retries=2, base_delay=0)
    def f():
        calls["n"] += 1
        if calls["n"] < 3:
            raise ToolError(ErrorCategory.RETRYABLE, "限流", retryable=True)
        return "ok"

    assert f() == "ok"
    assert calls["n"] == 3  # 首次 + 2 次重试


def test_plain_exception_retries():
    calls = {"n": 0}

    @retry_with_backoff(max_retries=1, base_delay=0)
    def f():
        calls["n"] += 1
        if calls["n"] < 2:
            raise ValueError("临时网络抖动")
        return "ok"

    assert f() == "ok"
    assert calls["n"] == 2  # 普通异常默认仍重试
