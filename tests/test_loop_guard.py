"""M7 —— 死循环/进度检测单元测试。"""
from agent.loop_guard import ProgressDetector


def test_same_tool_same_args_stuck():
    d = ProgressDetector(max_repeats=3)
    for _ in range(3):
        d.observe("internet_search", {"query": "房价"}, "结果A")
    assert d.is_stuck() is True  # 同工具同参数连续 3 次 → 卡住


def test_changing_args_not_stuck():
    d = ProgressDetector(max_repeats=3)
    for page in [1, 2, 3]:
        d.observe("get_table_data", {"page": page}, f"第{page}页数据")
    assert d.is_stuck() is False  # 参数在变、结果在变 → 正常推进


def test_same_result_stuck():
    d = ProgressDetector(max_repeats=3)
    d.observe("internet_search", {"query": "a"}, "相同结果")
    d.observe("internet_search", {"query": "b"}, "相同结果")
    d.observe("internet_search", {"query": "c"}, "相同结果")
    assert d.is_stuck() is True  # 换着参数问但结果完全相同 → 打转


def test_below_threshold_not_stuck():
    d = ProgressDetector(max_repeats=3)
    d.observe("internet_search", {"query": "a"}, "结果")
    d.observe("internet_search", {"query": "a"}, "结果")
    assert d.is_stuck() is False  # 只有 2 次，未到阈值


def test_different_tools_without_result_not_false_positive():
    """接线场景：只传 tool_name+args（无结果），不同工具不应误判卡住。"""
    d = ProgressDetector(max_repeats=3)
    d.observe("internet_search", {"query": "a"})
    d.observe("list_sql_tables", {})
    d.observe("get_table_data", {"table_name": "orders"})
    assert d.is_stuck() is False  # 三个不同工具，无结果，不应误报


def test_same_tool_same_args_without_result_stuck():
    d = ProgressDetector(max_repeats=3)
    for _ in range(3):
        d.observe("internet_search", {"query": "房价"})
    assert d.is_stuck() is True  # 同工具同参数，即使无结果也应判卡住
