"""统一错误分类：让工具失败「可被模型区分」。

背景（对齐 M6）：
    工具里把异常 return 成一个字符串，对模型来说等于「工具成功了」——模型无法区分
    「临时失败」和「永久失败」，可能反复调用一个注定失败的工具（变相死循环）。
    这里定义错误类别 + 结构化结果，让失败与成功可区分、让重试策略可判断。

分类原则（一句话）：
    网络/限流 → 系统自己重试（重试能改变结果）；
    参数错 → 不重试，回填结构化错误让模型改参数（重试不改变结果）；
    越权/致命 → 直接终止。
"""
import json
from dataclasses import dataclass
from typing import Any, Optional


class ErrorCategory:
    RETRYABLE = "RETRYABLE"                  # 网络/限流 → 系统自动重试
    INVALID_INPUT = "INVALID_INPUT"          # 参数错 → 交模型修正
    PERMISSION_DENIED = "PERMISSION_DENIED"  # 越权 → 终止
    FATAL = "FATAL"                          # 服务不可用 → 终止


@dataclass
class ToolError(Exception):
    """工具执行的结构化错误。继承 Exception 以便被上层 ToolNode 捕获并转成错误消息。"""

    category: str
    message: str
    retryable: bool = False
    suggestion: Optional[str] = None
    detail: Optional[dict] = None

    def __post_init__(self) -> None:
        # 设置 Exception 的 args，使 str(e) 输出 message 而不是空串，
        # 这样框架把异常转成 ToolMessage 时模型能看到真实错误信息。
        super().__init__(self.message)

    def to_result(self) -> dict[str, Any]:
        """把错误转成「模型能读懂」的结构化结果（dict）。"""
        return {
            "ok": False,
            "error": self.category,
            "message": self.message,
            "retryable": self.retryable,
            "suggestion": self.suggestion or "",
        }

    def to_result_str(self) -> str:
        """把错误转成 JSON 字符串，直接作为工具返回值回填给模型。

        为什么 return 而不是 raise：
            工具 raise 的异常取决于框架的 handle_tool_errors 配置，deepagents 默认
            对自定义异常是「重新抛出」→ 整个任务崩掉，模型看不到错误；而工具 return
            的值一定会被转成 ToolMessage 回填给模型。用 return 保证模型稳定收到反馈。
        """
        return json.dumps(self.to_result(), ensure_ascii=False)
