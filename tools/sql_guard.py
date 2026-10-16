"""SQL 只读护栏：无论模型怎么写，都只放行只读查询，并强制加 LIMIT。

背景（对齐 M5）：
    模型生成 SQL 直接执行，可能幻觉出 DROP TABLE / DELETE，或 SELECT * 无 LIMIT
    把大结果集打爆上下文。prompt 是软约束，这里用代码做硬约束兜底。

设计取舍：
    用「正则白名单」而不是完整 SQL 解析器（如 sqlglot）——白名单实现简单、能拦住
    90% 的误操作；生产环境可换成解析器或只读数据库账号。面试时讲清这个取舍即是加分。
"""
import re

# 危险关键词：只要出现即拒绝
_FORBIDDEN = (
    "insert", "update", "delete", "drop", "alter", "truncate",
    "replace", "create", "grant", "revoke", "into",
)
# 只读查询允许的前缀
_ALLOWED_PREFIX = ("select", "show", "describe", "explain")


def is_read_only_sql(sql: str) -> bool:
    """判断一条 SQL 是否为只读查询。"""
    s = sql.strip().rstrip(";").strip().lower()
    if not s.startswith(_ALLOWED_PREFIX):
        return False
    for kw in _FORBIDDEN:
        if re.search(rf"\b{kw}\b", s):
            return False
    return True


def add_limit(sql: str, limit: int = 100) -> str:
    """给 SELECT 查询自动追加 LIMIT，避免大结果集打爆上下文。"""
    s = sql.strip().rstrip(";").strip()
    if s.lower().startswith("select") and "limit" not in s.lower():
        return f"{s} LIMIT {limit}"
    return s
