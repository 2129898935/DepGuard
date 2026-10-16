"""通用 TTL 缓存（SQLite 落盘），用于缓存 OSV/deps.dev 等外部 API 结果。

背景（对齐 M11）：外部数据源有调用成本和限流，同一包反复查浪费且可能被限流。
这里用一个带过期时间的 key-value 缓存，按数据源设不同 TTL（OSV 24h、deps.dev 7d）。
"""
import json
import sqlite3
import time
from pathlib import Path

_db_path = Path(__file__).parents[1] / "data" / "cache.db"


def _conn() -> sqlite3.Connection:
    _db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_db_path))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS kv_cache (key TEXT PRIMARY KEY, value TEXT, expires_at REAL)"
    )
    return conn


def cache_get(key: str):
    """取缓存；不存在或已过期返回 None。"""
    conn = _conn()
    try:
        row = conn.execute("SELECT value, expires_at FROM kv_cache WHERE key=?", (key,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    value, expires_at = row
    if expires_at < time.time():
        return None  # 过期
    return json.loads(value)


def cache_set(key: str, value, ttl_seconds: int) -> None:
    """写缓存，ttl_seconds 为过期秒数。"""
    conn = _conn()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO kv_cache (key, value, expires_at) VALUES (?, ?, ?)",
            (key, json.dumps(value, ensure_ascii=False), time.time() + ttl_seconds),
        )
        conn.commit()
    finally:
        conn.close()
