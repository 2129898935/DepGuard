from agent.subagents.dependency_parser_agent import dependency_parser_agent
from agent.subagents.vulnerability_intelligence_agent import vulnerability_intelligence_agent
from agent.subagents.license_maintenance_agent import license_maintenance_agent
from agent.subagents.impact_analysis_agent import impact_analysis_agent
from agent.subagents.upgrade_planning_agent import upgrade_planning_agent
from agent.subagents.report_review_agent import report_review_agent
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from tools.upload_file_read_tool import read_file_content
from agent.parallel_analysis import parallel_dependency_analysis, run_parallel_analysis

from deepagents import create_deep_agent

from agent.llm import model
from agent.prompts import main_agent_content

from api.monitor import monitor
import asyncio
import uuid
import shutil
from pathlib import Path
import re
import json
import os

from api.context import set_session_context, reset_session_context, set_thread_context

from agent.loop_guard import ProgressDetector
from agent.planner import PlanTracker, default_scan_plan
from utils.context_budget import truncate_text
from db.session_store import update_session_status
from memory.retrieve import retrieve_memories
from memory.extract import extract_memories
from memory.store import add_memory
from tools.sbom_tool import validate_deliverables
from agent.scan_guard import ScanExecution, requires_full_scan, scan_completion_errors, prepare_requirements_evidence, is_requirements_file, build_deliverables_from_evidence
from agent.upgrade_batches import build_plan
from agent.finalize_scan import finalize_dependency_scan

from langchain_core.messages import AIMessage

# 持久化 checkpoint：使用 SQLite 替代内存存储
# 服务重启后对话历史不丢失，支持多轮对话上下文
checkpoint_db_path = Path(__file__).parents[1] / "data" / "checkpoints.db"
checkpoint_db_path.parent.mkdir(parents=True, exist_ok=True)


# ---- M0: Agent 单例化 ----
# 整个进程只构建一次 LangGraph 图、只开一次 checkpointer 连接。
# 图本身是无状态的，会话状态在 checkpointer 里，靠 config["configurable"]["thread_id"]
# 隔离不同会话，所以「重的图共享一份、轻的状态按会话隔离」，不需要每次请求重建 Agent。
_agent = None
_checkpointer = None
_checkpointer_cm = None  # 保留异步上下文管理器引用，便于进程结束时优雅关闭连接（对齐 M10）
_agent_lock = asyncio.Lock()


async def get_agent():
    """懒加载单例：整个进程只构建一次 Agent 图 + checkpointer 连接。"""
    global _agent, _checkpointer, _checkpointer_cm
    if _agent is not None:
        return _agent

    async with _agent_lock:
        # 双重检查：拿到锁后可能已被并发的首个请求构建过
        if _agent is not None:
            return _agent

        # AsyncSqliteSaver.from_conn_string 是 @asynccontextmanager，调用返回的是「异步
        # 上下文管理器」，而不是 saver 本身。手动 __aenter__ 一次让底层 SQLite 连接常驻到
        # 进程结束，拿到真正的 AsyncSqliteSaver 实例复用。
        _checkpointer_cm = AsyncSqliteSaver.from_conn_string(str(checkpoint_db_path))
        _checkpointer = await _checkpointer_cm.__aenter__()

        _agent = create_deep_agent(
            model=model,
            system_prompt=main_agent_content["system_prompt"],
            tools=[read_file_content, parallel_dependency_analysis],
            checkpointer=_checkpointer,
            subagents=[
                dependency_parser_agent,
                upgrade_planning_agent,
                report_review_agent,
            ],
        )
        print("[Agent] create_deep_agent 已构建（单例，只应出现一次）")
        return _agent


async def close_agent():
    """优雅停机：关闭单例 checkpointer 连接（M10）。"""
    global _agent, _checkpointer, _checkpointer_cm
    if _checkpointer_cm is not None:
        await _checkpointer_cm.__aexit__(None, None, None)
        _checkpointer_cm = None
        _checkpointer = None
        _agent = None


# 执行
"""
  1. 执行主智能体 一定选异步，原因：对应多个客户端
  2. 什么时候触发我们智能体的调用或者执行？？？
  3. 客户端 -》 api/task -> fastapi 接口 -》 异步执行 -》 main_agent的运行 （异步方法）
  4. main_agent执行stream流式处理 -》 调用工具 -》 已经埋好了点  
                                   调用子智能体 -》 结果解析 -》 name = task -> monitor -> 发送子智能体
                                   调用最终结果 -》 结果 -》 monitor -> 发送结果的方法
                                   开启调用以后 -》 当前会话 -》 文件夹地址 -》 推送到前端
"""

project_root_path = Path(__file__).parents[1].resolve()  # 绝对 解析路径标识以及软连接


def _use_manifest_fast_path(query: str, prepared_s1: dict | None) -> bool:
    """Known read-only manifest scans do not need a costly open-ended tool loop."""
    if not prepared_s1 or os.getenv("DEPGUARD_MANIFEST_FAST_PATH", "1") == "0":
        return False
    return not bool(re.search(r"修改|直接升级|自动修复|提交.?PR|创建.?PR|apply\s+fix|modify\s+file", query, re.I))


async def _run_prepared_manifest_scan(session_dir: Path, uploaded_files: list[str],
                                      task_query: str, session_id: str, user_id: str | None,
                                      tracker: PlanTracker) -> None:
    """Main orchestrator dispatches the known DAG with bounded stage artifacts."""
    from db.session_store import update_session_metrics

    update_session_status(session_id, "running")
    parallel = await run_parallel_analysis("@s1_components.json")
    for stage in ("S2", "S3", "S4"):
        tracker.mark(stage, "done" if parallel["stages"].get(stage, {}).get("status") == "completed" else "failed")
    if parallel["status"] != "completed":
        raise RuntimeError("并行证据阶段失败：" + json.dumps(parallel["stages"], ensure_ascii=False)[:1200])

    group_id = parallel["parallel_group_id"]
    monitor.report_assistant("升级规划助手", {"description": "按证据联动关系分批生成 S5 计划"})
    monitor.report_agent_status("S5", "升级规划助手", "started", group_id)
    summary = await build_plan(session_dir)
    if not summary.get("ok"):
        tracker.mark("S5", "failed")
        raise RuntimeError("S5 规划门禁失败：" + json.dumps(summary, ensure_ascii=False))
    tracker.mark("S5", "done")
    monitor.report_agent_status("S5", "升级规划助手", "completed", group_id)

    monitor.report_assistant("报告与审查助手", {"description": "重建并校验风险报告和 SBOM"})
    monitor.report_agent_status("S6", "报告与审查助手", "started", group_id)
    final = json.loads(finalize_dependency_scan.func())
    if not final.get("ok"):
        tracker.mark("S6", "failed")
        raise RuntimeError("S6 交付门禁失败：" + json.dumps(final.get("errors") or [], ensure_ascii=False))
    tracker.mark("S6", "done")
    monitor.report_agent_status("S6", "报告与审查助手", "completed", group_id)

    errors = scan_completion_errors(tracker, session_dir, uploaded_files)
    if errors:
        raise RuntimeError("扫描未完成：" + "；".join(errors))
    token_usage = sum(
        int((json.loads((session_dir / f"{stage}_evidence.json").read_text(encoding="utf-8"))
             .get("specialist_review") or {}).get("model_tokens", 0) or 0)
        for stage in ("s2", "s3", "s4")
    )
    update_session_metrics(session_id, token_usage=token_usage,
                           finding_count=final["vulnerabilities"])
    # Scan requests rarely contain durable preferences. Avoid a separate LLM
    # extraction call unless the user explicitly asks to remember something.
    if user_id and re.search(r"记住|以后.*偏好|remember", task_query, re.I):
        try:
            for memory in await extract_memories(task_query, model):
                await asyncio.to_thread(add_memory, user_id, memory["type"], memory["content"])
        except Exception as exc:
            monitor._emit("warning", f"长期记忆提炼失败：{exc}")
    update_session_status(session_id, "done")
    monitor.report_task_result(
        f"依赖审计完成：{final['components']} 个直接依赖、{final['vulnerabilities']} 条去重漏洞情报；"
        f"{summary['plan_count']} 个候选升级计划、{summary['manual_review_count']} 个待人工处置。"
        "报告：dependency_risk_report.md；SBOM：sbom.cdx.json。候选版本尚需兼容性验证。"
    )
# project_root_path = Path(__file__).parents[1].absolute() # 绝对
# main_agent.invoke()
# main_agent.stream()
# main_agent.astream() [选他]

async def run_deep_agent(task_query, session_id, user_id=None):
    """
    定义流式+异步执行主智能体！！
    执行过程中，返回  会话文件化返回  调用子智能体  调用最终结果 （monitor）
    task_query: 前端提问的问题
    session_id: 每个前端会话对应的标识 （1.存储session_id ContextVars 2.session_id 给他创建对应的output输出地址）
    """
    print(f"当前会话的main_agent开始执行了！ 会话id:{session_id}")
    # 准备工作 【1. session_dir（前端） 2. relative_session_dir (大模型) 3. 上传的文件拼接上传文件专属提示词】
    # project_root_path / output / session_session_id(uuid)
    # 当前会话存储生成文件的专属文件夹
    session_dir = project_root_path / "output" / f"session_{session_id}"
    # 文件夹可能没有，第一次请求要创建
    session_dir.mkdir(parents=True, exist_ok=True)
    # \  \n \t -> /
    session_dir_str = str(session_dir).replace("\\", "/")
    # 获取相对文件夹
    # session_dir : project_root_path / output / session_session_id(uuid)
    # project_root_path : project_root_path
    # relative_session_dir_str: / output / session_session_id(uuid)
    relative_session_dir_str = str(session_dir.relative_to(project_root_path)).replace("\\", "/")

    # 处理上传文件 （updated / session_session_id）
    updated_dir_path = project_root_path / "updated" / f"session_{session_id}"
    updated_info_prompt = ""  # 有上传文件，拼接上传文件专属解析位置的提示词
    uploaded_files: list[str] = []
    if updated_dir_path.exists():
        # 有
        files = [f.name for f in updated_dir_path.iterdir() if f.is_file()]
        uploaded_files = files
        # 将上传文件统一赋值到 output_dir 方便前端统一读取 session_dir
        if files:
            for filename in files:
                # 将原文件 -》 复制 -》 目标文件中  （copy2 保留原文件修改时间和权限等元数据）
                shutil.copy2(updated_dir_path / filename, session_dir / filename)
            # 构建提示词！告诉大模型，有上传文件，你要读取上传文件！！
            updated_info_prompt = (f"\n    [已上传文件] 已加载到工作目录:\n" +
                                   "\n".join([f"    - {f}" for f in files]) +
                                   "\n    请优先使用工具（read_file_content）读取并参考这些文件。")

    # 继续准备 1. 当前会话的对应的session_id session_dir 存储到contextVars [后续工具获取，socket -> 推送消息] 2.调用monitor给前端推送session_dir信息
    session_dir_token = set_session_context(session_dir_str)  # 存储的当前会话对应的文件夹地址
    session_id_token = set_thread_context(session_id)  # 获取当前会话的session_id对应socket

    monitor.report_session_dir(session_dir_str)  # 当前会话对应的文件夹地址推送给起前端！

    # 执行main_agent
    config = {
        "configurable": {
            "thread_id": session_id
        }
    }

    # 构建提示词
    path_instruction = f"""
    【工作环境指令】
    工作目录: {relative_session_dir_str}
    {updated_info_prompt}

    规则：
    1. 自定义文件工具已通过 ContextVar 锚定工作目录；调用 generate_markdown/write_sbom/read_file_content 时只传文件名，path 留空。
    2. 禁止把 '{relative_session_dir_str}' 再作为自定义工具的 path 参数，否则会重复嵌套目录。
    3. 若存在上传文件，必须使用 read_file_content 读取，或委派“依赖解析助手”读取；传递文件名，不要带绝对目录前缀。
    4. 禁止使用 deepagents 内置的 ls/read_file 读取上传文件：它们是虚拟文件系统，看不到宿主机会话目录。
    5. 使用相对路径，禁止使用绝对路径
    6. 扫描 DAG 固定依赖为：S1 → [S2、S3、S4 并行] → S5 → S6。S1 后必须调用 parallel_dependency_analysis，一次同时启动三个分支；汇合成功后才能进入 S5。
    7. parallel_dependency_analysis 返回的是证据文件索引。分支 status=completed 即已落盘；不要因摘要短而重跑。S5 委派升级规划助手调用 build_upgrade_plan；S6 委派报告与审查助手调用 finalize_dependency_scan。两者只返回紧凑 JSON，禁止使用内置 ls/glob/grep。
    """
    if any(is_requirements_file(name) for name in uploaded_files):
        path_instruction += (
            "\n    系统会将 requirements 文件确定性解析为 s1_components.json；"
            "这份文件是完整的 S1 Evidence。不要重复委派 S1 或手写组件清单。"
            "下一步直接调用 parallel_dependency_analysis，component_evidence 传 @s1_components.json；"
            "并行工具会从会话目录读取完整原文。\n"
        )
    # M3: 召回用户长期记忆，注入用户消息（跨会话记忆）
    memory_prompt = await asyncio.to_thread(retrieve_memories, user_id, task_query) if user_id else ""

    # M2: Context 预算——输入过长时截断，防止超大输入打爆上下文
    user_content = truncate_text(
        task_query + ("\n\n" + memory_prompt if memory_prompt else "") + path_instruction,
        max_tokens=8000,
    )

    # The model proposes actions; actual tool responses and deliverables decide completion.
    detector = ProgressDetector()
    plan_tracker = PlanTracker(default_scan_plan())
    scan_execution = ScanExecution(plan_tracker)
    scan_required = requires_full_scan(task_query, uploaded_files)
    seen_usage_messages: set[str] = set()
    subagent_call_counts: dict[str, int] = {}
    token_usage = 0
    deliverables_prepared = False

    try:
        prepared_s1 = prepare_requirements_evidence(session_dir, uploaded_files)
        if prepared_s1:
            plan_tracker.mark("S1", "done")
            scan_execution.prevalidated_steps.add("S1")
            monitor._emit("agent_status", f"S1 确定性解析完成：{prepared_s1['total_components']} 个组件", {
                "stage_id": "S1", "status": "completed",
                "component_count": prepared_s1["total_components"],
            })
        if scan_required and _use_manifest_fast_path(task_query, prepared_s1):
            await _run_prepared_manifest_scan(
                session_dir, uploaded_files, task_query, session_id, user_id, plan_tracker)
            return
        main_agent = await get_agent()
        update_session_status(session_id, "running")
        final_result = ""
        next_message = user_content

        # A premature final answer gets one bounded chance to resume the same checkpoint.
        for attempt in range(2 if scan_required else 1):
            final_result = ""
            async for chunk in main_agent.astream({
                "messages": [{"role": "user", "content": next_message}]
            }, config=config):
                for node_name, state in chunk.items():
                    if not state or not isinstance(state.get("messages"), list):
                        continue
                    messages = state["messages"]
                    for message in messages:
                        if getattr(message, "tool_call_id", None):
                            scan_execution.record_result(message)
                            if (scan_required and not deliverables_prepared
                                    and plan_tracker._by_id["S5"].status == "done"):
                                deliverables_prepared = build_deliverables_from_evidence(session_dir)
                                if deliverables_prepared:
                                    monitor._emit("report_prepared", "已从证据生成报告与 SBOM，等待 S6 审查")
                    if node_name != "model" or not messages:
                        continue
                    last_msg = messages[-1]
                    usage = getattr(last_msg, "usage_metadata", None) or {}
                    message_key = str(getattr(last_msg, "id", "") or id(last_msg))
                    if message_key not in seen_usage_messages:
                        token_usage += int(usage.get("total_tokens", 0) or 0)
                        seen_usage_messages.add(message_key)

                    tool_calls = getattr(last_msg, "tool_calls", None) or []
                    if tool_calls:
                        for tool_call in tool_calls:
                            scan_execution.record_call(tool_call)
                            name = tool_call.get("name", "")
                            args = tool_call.get("args") or {}
                            if name == "task":
                                subagent_type = args.get("subagent_type", "")
                                subagent_call_counts[subagent_type] = subagent_call_counts.get(subagent_type, 0) + 1
                                if subagent_call_counts[subagent_type] > 2:
                                    raise RuntimeError(
                                        f"阶段子 Agent 重复调用超过上限: {subagent_type}；"
                                        "首次执行加一次局部重试后仍未收敛"
                                    )
                                monitor.report_assistant(subagent_type, {"description": args.get("description", "")})
                            detector.observe(name, args)
                            if detector.is_stuck():
                                monitor._emit("error", "检测到任务可能陷入无进展循环（重复调用同一工具）")
                    elif last_msg.content:
                        final_result = str(last_msg.content)

            if not scan_required:
                break
            errors = scan_completion_errors(plan_tracker, session_dir, uploaded_files)
            errors.extend(scan_execution.order_errors)
            if not errors:
                break
            if attempt == 1:
                raise RuntimeError("扫描未完成，不能标记 done：" + "；".join(errors))
            monitor._emit("scan_recovery", "扫描尚未完成，主 Agent 继续执行", {
                "errors": errors,
                "stage_status": plan_tracker.summary(),
            })
            next_message = (
                "上一轮未完成真实依赖扫描。请继续执行，禁止直接给最终回答。"
                "先检查下列未完成项，严格依次完成 S1 → [S2/S3/S4 并行] → S5 → S6。"
                "若已有 s1_components.json，S1 已由系统完成，不要重新委派；否则调用依赖解析助手。"
                "S2/S3/S4 必须调用 parallel_dependency_analysis，传入 @s1_components.json（若存在）；"
                "S5/S6 必须分别调用对应助手；最后实际写入并校验 dependency_risk_report.md 和 sbom.cdx.json。"
                "若无法完成，明确报告失败，不得声称扫描完成。\n"
                "原始请求：" + task_query + "\n"
                "当前进度：\n" + plan_tracker.summary() + "\n"
                "未完成原因：" + "；".join(errors)
            )

        # Even non-scan tasks that created deliverables must pass the file gate.
        if not scan_required and any((session_dir / name).exists() for name in
                                     ("dependency_risk_report.md", "sbom.cdx.json", "sbom.json")):
            gate = json.loads(validate_deliverables.func())
            if not gate.get("ok"):
                raise RuntimeError("交付物校验失败：" + "；".join(gate.get("errors", [])))

        if not final_result:
            raise RuntimeError("主 Agent 没有返回最终结果")
        from db.session_store import update_session_metrics
        if scan_required:
            sbom = json.loads((session_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
            finding_count = len(sbom.get("vulnerabilities", []))
        else:
            finding_count = len(set(re.findall(
                r"\b(?:CVE-\d{4}-\d+|GHSA-[0-9a-z-]+)\b", final_result, re.IGNORECASE,
            )))
        update_session_metrics(session_id, token_usage=token_usage, finding_count=finding_count)
        print(f"[Plan] 六阶段计划进度 ({plan_tracker.done_count()}/{len(plan_tracker.plan.steps)}):\n{plan_tracker.summary()}")
        if user_id:
            try:
                for memory in await extract_memories(task_query, model):
                    await asyncio.to_thread(add_memory, user_id, memory["type"], memory["content"])
            except Exception as exc:
                monitor._emit("warning", f"长期记忆提炼失败：{exc}")
        update_session_status(session_id, "done")
        monitor.report_task_result(final_result)

    except asyncio.CancelledError:
        monitor._emit("cancelled", "任务已取消")
        update_session_status(session_id, "cancelled", "用户或服务取消任务")
        raise
    except Exception as e:
        # 报错推送错误信息给前端
        monitor._emit("error", f"执行主智能发生异常信息：{str(e)}")
        update_session_status(session_id, "failed", str(e))  # M1: 会话状态 → failed
    finally:
        # 释放存储的地址和session_id
        reset_session_context(session_dir_token, session_id_token)
