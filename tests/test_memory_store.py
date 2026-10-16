"""M3 —— 长期记忆存储/召回单元测试。"""
import sqlite3

import memory.store as ms
from memory.retrieve import retrieve_memories


def test_add_and_list_by_user(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "偏好保守升级")
    ms.add_memory("alice", "IGNORED_CVE", "CVE-2020-1234 是误报")
    ms.add_memory("bob", "WHITELIST", "requests")

    alice = ms.list_memories("alice")
    assert len(alice) == 2
    assert {m["type"] for m in alice} == {"USER_PREFERENCE", "IGNORED_CVE"}

    bob = ms.list_memories("bob")
    assert len(bob) == 1
    assert bob[0]["content"] == "requests"


def test_duplicate_not_inserted(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "保守升级")
    ms.add_memory("alice", "USER_PREFERENCE", "保守升级")  # 重复
    assert len(ms.list_memories("alice")) == 1  # 不重复插入，只刷新时间戳


def test_delete(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "DECISION", "升级到 requests 2.32")
    m = ms.list_memories("alice")[0]
    ms.delete_memory(m["id"])
    assert ms.list_memories("alice") == []


def test_filter_by_type(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "保守升级")
    ms.add_memory("alice", "IGNORED_CVE", "CVE-1")
    prefs = ms.list_memories("alice", type_="USER_PREFERENCE")
    assert len(prefs) == 1
    assert prefs[0]["content"] == "保守升级"


def test_retrieve_formats(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "偏好保守升级")
    text = retrieve_memories("alice")
    assert "与当前任务相关的用户长期记忆" in text
    assert "保守升级" in text


def test_retrieve_empty():
    assert retrieve_memories("nobody") == ""
    assert retrieve_memories("") == ""


def test_semantic_retrieval_prefers_relevant_memory(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "USER_PREFERENCE", "依赖升级优先选择保守方案")
    ms.add_memory("alice", "USER_PREFERENCE", "周末喜欢徒步和喝咖啡")

    text = retrieve_memories("alice", query="这次依赖升级采用什么策略？", limit=1)

    assert "保守方案" in text
    assert "徒步" not in text


def test_semantic_retrieval_isolated_by_user(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "DECISION", "requests 固定在 2.31.0")
    ms.add_memory("bob", "DECISION", "requests 升级到 2.32.4")

    results = ms.search_memories("alice", "requests 版本决策")

    assert [item["content"] for item in results] == ["requests 固定在 2.31.0"]


def test_legacy_row_is_not_recalled_until_reconfirmed(monkeypatch, tmp_path):
    db_path = tmp_path / "memories.db"
    monkeypatch.setattr(ms, "_db_path", db_path)
    conn = ms._conn()
    conn.execute(
        "INSERT INTO memories (user_id, type, content, created_at, updated_at) VALUES (?,?,?,?,?)",
        ("alice", "DECISION", "系统曾建议升级 internal-sdk", "2025-01-01", "2025-01-01"),
    )
    conn.commit()
    conn.close()

    assert ms.search_memories("alice", "internal-sdk 升级决策") == []

    conn = sqlite3.connect(db_path)
    source = conn.execute("SELECT source FROM memories").fetchone()[0]
    conn.close()
    assert source == "legacy_unverified"


def test_explicit_memory_is_semantically_recalled(monkeypatch, tmp_path):
    monkeypatch.setattr(ms, "_db_path", tmp_path / "memories.db")
    ms.add_memory("alice", "DECISION", "我决定将 internal-sdk 升级到 3.0")
    results = ms.search_memories("alice", "internal-sdk 升级决策")
    assert results[0]["content"] == "我决定将 internal-sdk 升级到 3.0"
