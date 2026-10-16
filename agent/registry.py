"""后台任务注册表：让 asyncio.create_task 产生的任务可查询、可取消。

背景（对齐 M0）：
    server 层用 asyncio.create_task 把 Agent 丢到后台跑，但返回值被丢弃，
    导致任务「发出去就不管」——失败无感知、无法取消、重启即蒸发。
    这里用一个 dict[thread_id -> asyncio.Task] 把任务接住，管理它的生命周期。
"""
import asyncio
from typing import Dict


class TaskRegistry:
    def __init__(self) -> None:
        self._tasks: Dict[str, asyncio.Task] = {}

    def start(self, thread_id: str, coro) -> asyncio.Task:
        """启动一个后台任务并登记，任务结束时自动移除。"""
        task = asyncio.create_task(coro)
        self._tasks[thread_id] = task
        task.add_done_callback(lambda _: self._discard(thread_id, task))
        return task

    def _discard(self, thread_id: str, task: asyncio.Task) -> None:
        """任务结束时移除登记。

        仅当登记的仍是「同一个任务」时才移除，避免误删同一 thread_id 的后续任务。
        """
        if self._tasks.get(thread_id) is task:
            self._tasks.pop(thread_id, None)

    def cancel(self, thread_id: str) -> bool:
        """取消指定会话的任务。返回是否真的取消了。

        pop 原子地取出并移除登记，避免「已取消但未清理」时被重复 cancel。
        """
        task = self._tasks.pop(thread_id, None)
        if task is None:
            return False
        task.cancel()
        return True

    def is_running(self, thread_id: str) -> bool:
        return thread_id in self._tasks

    def count(self) -> int:
        return len(self._tasks)

    def cancel_all(self) -> None:
        """取消所有在途任务（优雅停机用）。"""
        for thread_id in list(self._tasks.keys()):
            self.cancel(thread_id)


# 模块级单例，server 直接 import 这个实例
registry = TaskRegistry()
