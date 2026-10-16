"""M11 —— 通用 TTL 缓存单元测试。"""
import db.cache as c


def test_set_get(monkeypatch, tmp_path):
    monkeypatch.setattr(c, "_db_path", tmp_path / "cache.db")
    c.cache_set("k1", {"a": 1}, ttl_seconds=10)
    assert c.cache_get("k1") == {"a": 1}
    assert c.cache_get("missing") is None


def test_expiry(monkeypatch, tmp_path):
    monkeypatch.setattr(c, "_db_path", tmp_path / "cache.db")
    c.cache_set("k1", "v", ttl_seconds=-1)  # 已过期
    assert c.cache_get("k1") is None
