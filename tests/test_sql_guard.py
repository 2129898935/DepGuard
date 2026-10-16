"""M5 —— SQL 只读护栏单元测试。"""
import json

import pytest

from tools.db_tools import execute_sql_query
from tools.sql_guard import add_limit, is_read_only_sql


@pytest.mark.parametrize("sql,expected", [
    ("select * from orders", True),
    ("SELECT id, name FROM orders", True),
    ("show tables", True),
    ("describe orders", True),
    ("explain select * from orders", True),
    ("drop table orders", False),
    ("DELETE FROM orders", False),
    ("update orders set x=1", False),
    ("insert into orders values (1)", False),
    ("select * from orders into outfile '/tmp/x'", False),  # SELECT ... INTO 也是写操作
    ("grant select on orders to 'u'", False),
    ("create table t (id int)", False),
])
def test_is_read_only_sql(sql, expected):
    assert is_read_only_sql(sql) is expected


@pytest.mark.parametrize("sql,expected", [
    ("select * from orders", "select * from orders LIMIT 100"),
    ("SELECT * FROM orders", "SELECT * FROM orders LIMIT 100"),
    ("select * from orders limit 10", "select * from orders limit 10"),  # 已有 limit 不再加
    ("show tables", "show tables"),  # 非 select 不加
])
def test_add_limit(sql, expected):
    assert add_limit(sql) == expected


def test_execute_sql_query_rejects_write_and_returns_feedback():
    """写操作被护栏拦截后，返回结构化结果回填给模型（而不是抛异常崩溃）。"""
    result = execute_sql_query.invoke({"query": "DROP TABLE orders"})
    d = json.loads(result)
    assert d["ok"] is False
    assert d["error"] == "PERMISSION_DENIED"
    assert "只读" in d["message"]
    assert d["suggestion"]
