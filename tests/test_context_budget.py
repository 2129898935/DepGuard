"""M2 —— Context 预算/截断单元测试。"""
from utils.context_budget import token_count, truncate_messages, truncate_text


def test_token_count_empty():
    assert token_count([]) == 0


def test_token_count_positive():
    assert token_count(["hello world"]) > 0


def test_truncate_messages_under_budget():
    messages = [f"m{i} " * 100 for i in range(100)]  # 100 条长消息
    budget = token_count(messages[:1] + messages[-2:])  # 预算只够 system + 最近 2 条
    result = truncate_messages(messages, budget=budget, keep_last=6)
    assert token_count(result) <= budget
    assert result[0] == messages[0]      # system 保留
    assert result[-1] == messages[-1]    # 最近一条保留
    assert len(result) < len(messages)   # 中间被丢弃


def test_truncate_messages_noop_when_under_budget():
    messages = ["hello", "world"]
    assert truncate_messages(messages, budget=100000) == messages


def test_truncate_text_under_limit():
    assert truncate_text("hello", max_tokens=100) == "hello"


def test_truncate_text_over_limit():
    long_text = "word " * 2000
    result = truncate_text(long_text, max_tokens=50)
    assert len(result) < len(long_text)
    assert "已截断" in result
