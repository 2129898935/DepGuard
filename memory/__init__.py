"""长期记忆模块（M3）：跨会话的用户偏好、决策、白名单、忽略的 CVE。

与 Session（checkpointer 对话历史）、RAG（RAGFlow 外部文档）区分：
- Session：当前会话完整消息，会话结束归档；
- Memory：跨会话的事实/偏好，长期、语义召回、按 user 隔离；
- RAG：外部文档知识，永久、向量检索。
"""
