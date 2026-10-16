"""M5 —— 统一工具执行入口单元测试。"""
import pytest

from tools.runtime import execute_tool
from utils.errors import ToolError


def test_dangerous_tool_rejected():
    with pytest.raises(ToolError) as ei:
        execute_tool("create_pr", lambda: "ok")
    assert ei.value.category == "PERMISSION_DENIED"


def test_read_tool_passes():
    assert execute_tool("internet_search", lambda: "result") == "result"


def test_exception_wrapped_as_fatal():
    def boom():
        raise ValueError("x")

    with pytest.raises(ToolError) as ei:
        execute_tool("internet_search", boom)
    assert ei.value.category == "FATAL"
