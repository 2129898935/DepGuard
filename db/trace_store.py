"""Trace 持久化（M8）：每次工具调用/结果写一条 trace，出问题可按 thread 回溯。"""
import json
import sqlite3
from datetime import datetime
from pathlib import Path

_db_path = Path(__file__).parents[1] / "data" / "traces.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS traces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id TEXT,
    node TEXT,
    tool_name TEXT,
    args TEXT,
    result_summary TEXT,
    token_usage INTEGER DEFAULT 0,
    duration_ms INTEGER,
    status TEXT,
    timestamp TEXT
)
"""


def _conn() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path))
    conn.execute(_SCHEMA)
    return conn


def add_trace(
    thread_id: str | None,
    node: str,
    tool_name: str | None = None,
    args: dict | None = None,
    result_summary: str = "",
    token_usage: int = 0,
    duration_ms: int | None = None,
    status: str = "ok",
) -> None:
    """写一条 trace。args 序列化为 JSON 文本。"""
    args_text = json.dumps(args, ensure_ascii=False)[:2000] if args else ""
    result_text = result_summary[:500]
    conn = _conn()
    try:
        conn.execute(
            "INSERT INTO traces (thread_id, node, tool_name, args, result_summary, token_usage, duration_ms, status, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (thread_id, node, tool_name, args_text, result_text, token_usage, duration_ms, status, datetime.now().isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def list_traces(thread_id: str | None = None, limit: int = 50) -> list[dict]:
    """按 thread 回溯 trace（thread_id 为空则返回最近所有）。"""
    conn = _conn()
    try:
        if thread_id:
            rows = conn.execute(
                "SELECT * FROM traces WHERE thread_id=? ORDER BY id DESC LIMIT ?", (thread_id, limit)
            ).fetchall()
        else:
            rows = conn.execute("SELECT * FROM traces ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        cols = [d[0] for d in conn.execute("SELECT * FROM traces LIMIT 0").description]
        return [dict(zip(cols, r)) for r in rows]
    finally:
        conn.close()
