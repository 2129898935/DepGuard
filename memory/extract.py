"""长期记忆提取层（M3）：任务结束后用 LLM 从对话中提炼「值得长期记住」的信息。

规则 + LLM 双保险：
  1. 规则：空输入直接跳过；
  2. LLM：判断是否「跨会话有价值」，输出结构化 JSON（type + content）。
"""
import json
import re

_MEMORY_TYPES = {"USER_PREFERENCE", "IGNORED_CVE", "WHITELIST", "DECISION"}

_EXTRACT_PROMPT = """你是一个记忆提炼器。输入内容只允许是用户原始消息。仅提取用户明确、主动表达且适合跨会话保留的信息。

值得记的信息类型（type 只能是以下之一）：
- USER_PREFERENCE：用户的持久偏好（例如「偏好保守升级」「优先修高危」）
- IGNORED_CVE：用户明确判定为误报、要忽略的 CVE
- WHITELIST：用户认可、纳入白名单的依赖包
- DECISION：用户做出的历史决策（例如「决定升级到某版本」）

不值得记的：Agent 的建议或结论、从扫描报告推断出的偏好、一次性查询、当前会话临时内容。
DECISION/IGNORED_CVE/WHITELIST 必须有用户明确的决定性措辞；不得把系统推荐写成用户决定。

严格输出 JSON 数组，每项格式 {"type": "...", "content": "..."}。
如果没有值得记的，输出 []。不要输出任何其它文字。

用户原始消息：
{conversation}

输出："""


async def extract_memories(conversation: str, llm) -> list[dict]:
    """从对话文本里提炼记忆，返回 [{"type","content"}]。"""
    if not conversation or not conversation.strip():
        return []
    try:
        # 用 replace 而非 format：提示词里含 JSON 示例的 {} 会被 format 误解析成占位符
        resp = await llm.ainvoke(_EXTRACT_PROMPT.replace("{conversation}", conversation[:4000]))
        text = resp.content if hasattr(resp, "content") else str(resp)
    except Exception:
        return []

    return _parse_memories(text)


def _parse_memories(text: str) -> list[dict]:
    """解析 LLM 返回的文本，提取结构化记忆（纯函数，可单测）。"""
    # 去掉可能包裹的 markdown 代码块
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # 兜底：用正则抓第一个 [ ... ] 片段
        m = re.search(r"\[.*\]", text, re.DOTALL)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []

    if not isinstance(data, list):
        return []
    result = []
    for item in data:
        if isinstance(item, dict) and item.get("type") in _MEMORY_TYPES and item.get("content"):
            result.append({"type": item["type"], "content": item["content"].strip()})
    return result
