"""M1 —— 会话元数据持久化单元测试。"""
import db.session_store as ss


def test_session_lifecycle(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "_db_path", tmp_path / "sessions.db")

    ss.create_session("t1", "alice")
    s = ss.get_session("t1")
    assert s["status"] == "pending"
    assert s["user_id"] == "alice"

    ss.update_session_status("t1", "running")
    assert ss.get_session("t1")["status"] == "running"

    ss.update_session_status("t1", "failed", "boom")
    s = ss.get_session("t1")
    assert s["status"] == "failed"
    assert s["error"] == "boom"
    assert s["finished_at"] is not None


def test_get_missing_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "_db_path", tmp_path / "sessions.db")
    assert ss.get_session("nope") is None


def test_title_saved_and_listed(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "_db_path", tmp_path / "sessions.db")
    ss.create_session("t1", "alice", title="分析销售趋势")
    ss.create_session("t2", "bob", title="查询依赖漏洞")
    by_id = {s["id"]: s for s in ss.list_sessions()}
    assert by_id["t1"]["title"] == "分析销售趋势"
    assert by_id["t2"]["title"] == "查询依赖漏洞"


def test_update_session_metrics(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "_db_path", tmp_path / "sessions.db")
    ss.create_session("t1", "alice")
    ss.update_session_metrics("t1", token_usage=1234, finding_count=7)
    session = ss.get_session("t1")
    assert session["token_usage"] == 1234
    assert session["finding_count"] == 7


def test_cancelled_session_is_terminal(monkeypatch, tmp_path):
    monkeypatch.setattr(ss, "_db_path", tmp_path / "sessions.db")
    ss.create_session("cancel-me", "alice")
    ss.update_session_status("cancel-me", "running")
    ss.update_session_status("cancel-me", "cancelled", "用户取消")
    session = ss.get_session("cancel-me")
    assert session["status"] == "cancelled"
    assert session["finished_at"] is not None
