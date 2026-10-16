"""Context 预算感知 + 截断（对齐 M2）。

背景：长对话 / 大工具结果会打爆 LLM 上下文窗口——成本变高、延迟变大、注意力稀释。
这里用 tiktoken 估算 token，超预算时保留 system prompt + 最近 N 条，丢弃中间最久远
的部分（对当前决策影响最小）。
"""
import tiktoken

_enc = tiktoken.get_encoding("cl100k_base")  # 近似估算即可


def token_count(messages: list) -> int:
    """估算消息列表的 token 总数（不精确，只要接近阈值时能触发即可）。"""
    total = 0
    for m in messages:
        text = getattr(m, "content", "") or str(m)
        total += len(_enc.encode(str(text)))
    return total


def truncate_messages(messages: list, budget: int, keep_last: int = 6) -> list:
    """保留 system（第一条）+ 最近 keep_last 条，中间超预算的部分丢弃。"""
    if not messages or token_count(messages) <= budget:
        return messages
    head = messages[:1]              # 假设第一条是 system prompt
    tail = messages[-keep_last:]
    result = head + tail
    # 若仍超预算，继续减少 tail（从最旧开始丢）
    while token_count(result) > budget and len(tail) > 1:
        tail = tail[1:]
        result = head + tail
    return result


def truncate_text(text: str, max_tokens: int) -> str:
    """把单段文本截断到 token 预算内（用于超大输入的兜底）。"""
    if not text:
        return text
    ids = _enc.encode(text)
    if len(ids) <= max_tokens:
        return text
    return _enc.decode(ids[:max_tokens]) + "\n...[内容过长已截断]"
