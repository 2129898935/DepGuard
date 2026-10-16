"""M8 —— Trace 持久化单元测试。"""
import db.trace_store as ts


def test_add_and_list(monkeypatch, tmp_path):
    monkeypatch.setattr(ts, "_db_path", tmp_path / "traces.db")
    ts.add_trace(thread_id="t1", node="tool", tool_name="query_osv_vulns", args={"names": ["requests"]}, status="start")
    ts.add_trace(thread_id="t1", node="result", result_summary="完成", status="done")

    traces = ts.list_traces(thread_id="t1")
    assert len(traces) == 2
    assert traces[0]["node"] == "result"          # 按 id 倒序，最新在前
    assert traces[1]["tool_name"] == "query_osv_vulns"


def test_filter_by_thread(monkeypatch, tmp_path):
    monkeypatch.setattr(ts, "_db_path", tmp_path / "traces.db")
    ts.add_trace(thread_id="t1", node="tool")
    ts.add_trace(thread_id="t2", node="tool")
    assert len(ts.list_traces(thread_id="t1")) == 1
    assert len(ts.list_traces()) == 2


def test_args_serialized(monkeypatch, tmp_path):
    monkeypatch.setattr(ts, "_db_path", tmp_path / "traces.db")
    ts.add_trace(thread_id="t1", node="tool", args={"a": 1})
    trace = ts.list_traces(thread_id="t1")[0]
    assert '{"a": 1}' in trace["args"]
