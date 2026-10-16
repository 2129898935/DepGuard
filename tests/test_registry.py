"""M0 —— TaskRegistry 单元测试。"""
import asyncio

import pytest

from agent.registry import TaskRegistry


@pytest.mark.asyncio
async def test_start_and_auto_remove():
    r = TaskRegistry()
    started = asyncio.Event()

    async def work():
        started.set()
        await asyncio.sleep(0.01)

    r.start("t1", work())
    await started.wait()
    assert r.is_running("t1") is True
    assert r.count() == 1

    await asyncio.sleep(0.02)  # 等任务结束
    assert r.is_running("t1") is False  # 结束后自动移除
    assert r.count() == 0


@pytest.mark.asyncio
async def test_cancel():
    r = TaskRegistry()
    task = r.start("t1", asyncio.sleep(10))
    assert r.is_running("t1") is True

    assert r.cancel("t1") is True
    assert r.cancel("t1") is False  # 已经没了，返回 False
    assert r.is_running("t1") is False
    assert r.count() == 0

    # 消费掉 CancelledError，避免事件循环关闭时残留未取回的任务告警
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_cancel_unknown_returns_false():
    r = TaskRegistry()
    assert r.cancel("nope") is False
    assert r.is_running("nope") is False


@pytest.mark.asyncio
async def test_cancel_all():
    r = TaskRegistry()
    r.start("t1", asyncio.sleep(10))
    r.start("t2", asyncio.sleep(10))
    assert r.count() == 2
    r.cancel_all()
    assert r.count() == 0
