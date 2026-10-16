#  获取助手列表（查询知识库信息） + 向助手提问
# 直接调 RAGFlow HTTP API（v1.0），不依赖 ragflow_sdk，避免 SDK 与服务器版本不匹配导致的解析错误。
import httpx
from langchain_core.tools import tool

from api.monitor import monitor
from rawflow.rag_config import _load_ragflow_env

_api_key, _base_url = _load_ragflow_env()


def _headers() -> dict:
    return {"Authorization": f"Bearer {_api_key}", "Content-Type": "application/json"}


def _list_chats(name: str | None = None) -> list[dict]:
    """列出聊天助手。v1.0 返回 data 为 dict（{"chats":[...]}），旧版为 list，两者都兼容。"""
    params = {"page": 1, "page_size": 30}
    if name:
        params["name"] = name
    resp = httpx.get(f"{_base_url}/api/v1/chats", headers=_headers(), params=params, timeout=15)
    resp.raise_for_status()
    d = resp.json()
    if d.get("code") != 0:
        raise Exception(d.get("message", "查询失败"))
    data = d.get("data", {})
    if isinstance(data, dict):
        return data.get("chats", [])
    return data


@tool
def get_assistant_list() -> str:
    """
    查询 ragflow 服务器中有哪些助手和助手关联的知识库信息。
    返回：助手名称 + 功能介绍 + 关联的知识库 ID 列表。
    """
    monitor.report_tool(tool_name="ragflow聊天助手列表查询工具：get_assistant_list")
    try:
        chats = _list_chats()
        if not chats:
            return "没有任何可用助手"
        lines = []
        for c in chats:
            name = c.get("name", "")
            desc = c.get("description", "")
            ds = c.get("dataset_ids", [])
            lines.append(f"助手名称:{name};功能介绍：{desc}; 关联的知识库ID:{ds}")
        return "\n".join(lines)
    except Exception as e:
        return f"查询助手信息异常，无可用助手,异常信息:{str(e)}"


@tool
def create_ask_delete(chat_name: str, question: str) -> str:
    """
    向指定的助手提问（v1.0 使用 OpenAI 兼容接口，无会话状态，直接返回答案）。
    chat_name: 助手的名字（先调用 get_assistant_list 获取准确名称）
    question: 要提问的问题
    """
    monitor.report_tool(tool_name="ragflow提问助手工具：create_ask_delete", args={"chat_name": chat_name, "question": question})
    try:
        chats = _list_chats(name=chat_name)
        if not chats:
            return f"未找到助手：{chat_name}，请先调用 get_assistant_list 确认助手名称"
        chat_id = chats[0]["id"]

        resp = httpx.post(
            f"{_base_url}/api/v1/openai/{chat_id}/chat/completions",
            headers=_headers(),
            # v1.0 约定：model 传占位符 "model"，服务器会解析成该助手配置的 llm_id
            json={"model": "model", "messages": [{"role": "user", "content": question}], "stream": False},
            timeout=60,
        )
        resp.raise_for_status()
        d = resp.json()

        # RAGFlow 业务错误（如 llm_id 未配置）返回 {"code": 非0, "message": ...}
        if isinstance(d, dict) and d.get("code") not in (0, None) and d.get("data") is None:
            return f"提问失败：{d.get('message', d)}"

        # OpenAI 兼容成功格式：choices[0].message.content
        try:
            return d["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            pass
        # 兜底：RAGFlow 原生格式 data.answer
        data = d.get("data", {}) if isinstance(d, dict) else {}
        if isinstance(data, dict) and data.get("answer"):
            return data["answer"]
        return str(d)[:2000]
    except Exception as e:
        return f"提问失败，错误原因：{str(e)}"
