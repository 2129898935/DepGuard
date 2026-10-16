"""长期记忆存储与语义检索：SQLite 元数据 + 持久化向量。"""
import json
import math
import sqlite3
from datetime import datetime
from pathlib import Path

from memory.embeddings import cosine_similarity, embed_text


class MemoryType:
    USER_PREFERENCE = "USER_PREFERENCE"
    IGNORED_CVE = "IGNORED_CVE"
    WHITELIST = "WHITELIST"
    DECISION = "DECISION"

    ALL = {USER_PREFERENCE, IGNORED_CVE, WHITELIST, DECISION}


_db_path = Path(__file__).parents[1] / "data" / "memories.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    content TEXT NOT NULL,
    embedding TEXT,
    embedding_model TEXT,
    source TEXT NOT NULL DEFAULT 'legacy_unverified',
    created_at TEXT,
    updated_at TEXT
)
"""


def _conn() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path))
    conn.execute(_SCHEMA)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(memories)").fetchall()}
    if "embedding" not in columns:
        conn.execute("ALTER TABLE memories ADD COLUMN embedding TEXT")
    if "embedding_model" not in columns:
        conn.execute("ALTER TABLE memories ADD COLUMN embedding_model TEXT")
    if "source" not in columns:
        conn.execute("ALTER TABLE memories ADD COLUMN source TEXT NOT NULL DEFAULT 'legacy_unverified'")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_memories_user_updated ON memories(user_id, updated_at DESC)"
    )
    conn.commit()
    return conn


def add_memory(user_id: str, type_: str, content: str, source: str = "user_explicit") -> None:
    """写入记忆及其向量；完全相同的记忆刷新时间并更新向量。"""
    content = content.strip()
    if not user_id or not content or type_ not in MemoryType.ALL:
        return
    if source not in {"user_explicit", "legacy_unverified"}:
        source = "legacy_unverified"
    embedding_model, vector = embed_text(content)
    embedding = json.dumps(vector)
    now = datetime.now().isoformat()
    conn = _conn()
    try:
        row = conn.execute(
            "SELECT id FROM memories WHERE user_id=? AND type=? AND content=?",
            (user_id, type_, content),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE memories SET embedding=?, embedding_model=?, source=?, updated_at=? WHERE id=?",
                (embedding, embedding_model, source, now, row[0]),
            )
        else:
            conn.execute(
                "INSERT INTO memories "
                "(user_id, type, content, embedding, embedding_model, source, created_at, updated_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (user_id, type_, content, embedding, embedding_model, source, now, now),
            )
        conn.commit()
    finally:
        conn.close()


def _row_dicts(rows: list[tuple], columns: list[str]) -> list[dict]:
    return [dict(zip(columns, row)) for row in rows]


def list_memories(user_id: str, type_: str | None = None, limit: int = 20, trusted_only: bool = False) -> list[dict]:
    """按更新时间读取记忆；主要用于管理界面和无查询时的兼容降级。"""
    conn = _conn()
    try:
        where = "WHERE user_id=?"
        params: list = [user_id]
        if type_:
            where += " AND type=?"
            params.append(type_)
        if trusted_only:
            where += " AND source='user_explicit'"
        params.append(max(1, limit))
        cursor = conn.execute(
            "SELECT id, user_id, type, content, created_at, updated_at "
            f"FROM memories {where} ORDER BY updated_at DESC LIMIT ?",
            params,
        )
        return _row_dicts(cursor.fetchall(), [item[0] for item in cursor.description])
    finally:
        conn.close()


def search_memories(
    user_id: str,
    query: str,
    limit: int = 10,
    candidate_limit: int = 200,
    min_similarity: float = 0.05,
) -> list[dict]:
    """按向量相似度召回，再用时间衰减做小幅重排。

    旧记录没有向量或向量后端变化时会懒计算并回写，无需离线迁移脚本。
    """
    if not user_id or not query.strip():
        return []
    query_model, query_vector = embed_text(query)
    conn = _conn()
    try:
        cursor = conn.execute(
            "SELECT id, user_id, type, content, embedding, embedding_model, created_at, updated_at "
            "FROM memories WHERE user_id=? AND source='user_explicit' ORDER BY updated_at DESC LIMIT ?",
            (user_id, max(limit, candidate_limit)),
        )
        columns = [item[0] for item in cursor.description]
        memories = _row_dicts(cursor.fetchall(), columns)
        now = datetime.now()
        ranked = []
        for memory in memories:
            vector = None
            if memory["embedding"] and memory["embedding_model"] == query_model:
                try:
                    vector = json.loads(memory["embedding"])
                except (TypeError, json.JSONDecodeError):
                    vector = None
            if vector is None:
                model, vector = embed_text(memory["content"])
                conn.execute(
                    "UPDATE memories SET embedding=?, embedding_model=? WHERE id=?",
                    (json.dumps(vector), model, memory["id"]),
                )
                if model != query_model:
                    continue
            similarity = cosine_similarity(query_vector, vector)
            if similarity < min_similarity:
                continue
            try:
                age_days = max(0.0, (now - datetime.fromisoformat(memory["updated_at"])).total_seconds() / 86400)
            except (TypeError, ValueError):
                age_days = 365.0
            recency = math.exp(-age_days / 180.0)
            memory["similarity"] = similarity
            memory["score"] = similarity * 0.9 + recency * 0.1
            memory.pop("embedding", None)
            memory.pop("embedding_model", None)
            ranked.append(memory)
        conn.commit()
        ranked.sort(key=lambda item: item["score"], reverse=True)
        return ranked[: max(1, limit)]
    finally:
        conn.close()


def delete_memory(memory_id: int) -> None:
    conn = _conn()
    try:
        conn.execute("DELETE FROM memories WHERE id=?", (memory_id,))
        conn.commit()
    finally:
        conn.close()
