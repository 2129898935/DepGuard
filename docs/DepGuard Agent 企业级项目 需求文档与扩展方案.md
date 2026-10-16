# DepGuard Agent 企业级项目 需求文档与扩展方案
 
> 核心业务：**DepGuard Agent —— 开源依赖供应链风险与升级规划 Agent**。  
> 目标：把当前约 2000 行的 demo，改造成一个「能应对 Agent 实习面试」的企业级项目，并且不是市面上烂大街的包装项目。  
> 原则：先不改代码，本方案只做「需求梳理 + 改造设计 + 为什么这么改 + 面试考点 + 业务落地步骤」五件事。所有改造都对齐 DepGuard 的业务闭环和 Agent 主线链路，每改一处都能回答面试官的问题。

---

## 目录

- [0. 一页纸结论（先看这里）](#0-一页纸结论先看这里)
- [1. 项目现状分析](#1-项目现状分析)
  - [1.1 现有架构全景](#11-现有架构全景)
  - [1.2 主线链路：代码落在了哪里](#12-主线链路代码落在了哪里)
  - [1.3 现有亮点](#13-现有亮点)
  - [1.4 现有缺口清单](#14-现有缺口清单)
- [2. 核心认知对齐：Agent 是系统设计问题](#2-核心认知对齐agent-是系统设计问题)
- [3. 需求文档](#3-需求文档)
  - [3.1 总体目标](#31-总体目标)
  - [3.2 功能需求](#32-功能需求)
  - [3.3 非功能需求](#33-非功能需求)
- [4. DepGuard Agent 业务设计](#4-depguard-agent-业务设计)
  - [4.1 产品定义](#41-产品定义)
  - [4.2 为什么有含金量](#42-为什么有含金量)
  - [4.3 与现有能力映射](#43-与现有能力映射)
  - [4.4 核心业务闭环](#44-核心业务闭环)
- [5. 扩展方案 M0-M12](#5-扩展方案-m0-m12)
- [6. 分期实施路线图](#6-分期实施路线图)
- [7. 面试准备手册](#7-面试准备手册)
- [附：落地优先级建议](#附落地优先级建议)

---

## 0. 一页纸结论（先看这里）

| 维度     | 现状                                     | 目标                                                         |
| -------- | ---------------------------------------- | ------------------------------------------------------------ |
| 核心业务 | 无明确业务场景，功能堆砌                 | DepGuard Agent：输入仓库依赖 → 输出可审计的供应链风险处置方案 |
| 架构     | 单进程 FastAPI + deepagents 编排，能跑通 | 分层清晰、可配置、可观测、可测试                             |
| 健壮性   | 只有 Tavily 一个工具做了重试             | 统一错误分类 + 分级重试 + 兜底                               |
| 安全     | 无认证、SQL 任意执行、无权限检查         | JWT + Tool 权限分级 + SQL 只读护栏 + 危险操作人工审批        |
| Context  | 无压缩，长对话必然爆上下文               | 预算感知 + 压缩/截断 + 依赖树不入上下文                      |
| Memory   | 只有 SQLite checkpointer（= 对话历史）   | 短期 Session + 长期 Memory + RAG，三者分离                   |
| Plan     | 仅靠 prompt 让模型「先列 todo」          | 结构化 Plan + Replan + 扫描/升级双阶段规划                   |
| 可观测   | 只有 WS 推前端 + print                   | 持久化 Trace + 结构化日志 + 用量计费                         |
| 数据源   | 无                                       | OSV.dev + deps.dev + GitHub Advisory + 内部安全策略 RAG      |
| 输出     | 聊天的文本回复                           | SBOM + 风险报告 + 升级计划 + 审计 trace                      |
| 评测     | 无                                       | 10 个真实开源仓库对比 OSV 官方结果，量化覆盖率/误报率/可执行率 |
| 工程化   | 无测试、无优雅停机、依赖混乱             | pytest + CI + 优雅停机 + 依赖收敛                            |

**核心结论**：原项目骨架是对的，但肉是空的。它只覆盖了「用户输入 → 模型推理 → Tool Call → 工具执行」，而权限检查、Context 管理、Memory、Plan、错误分类、死循环防护、可观测性才是面试官真正会追问、也最能体现企业级的地方。改造分为两条并行主线：

- **业务主线**：从通用搜索助手收敛为 DepGuard Agent。
- **工程主线**：把 M0-M10 通用能力作为基础设施层，全部挂到 DepGuard 业务链路上。

---

## 1. 项目现状分析

### 1.1 现有架构全景

```text
用户浏览器
   │  POST /api/task {query}            (api/server.py:81)
   │  WS /ws/{thread_id}                (api/server.py:225)
   ▼
FastAPI Server
   │  asyncio.create_task(run_deep_agent)  ← 后台任务，无跟踪 (server.py:88)
   ▼
run_deep_agent (agent/main_agent.py:218)
   │  ① 建 session_dir = output/session_{id}
   │  ② ContextVar 存 session_dir / thread_id   (api/context.py)
   │  ③ create_deep_agent(...)  ← 每次请求都新建 (main_agent.py:284)
   │  ④ main_agent.astream({messages:[...]})
   ▼
主智能体 Orchestrator (deepagents)
   │  dispatch 子智能体（通过 tool_call name=="task"）
   ├── 市场情报助手 → internet_search → Tavily
   ├── 数据分析助手 → list/get/execute_sql → MySQL
   └── 内部知识助手 → get_assistant_list/create_ask_delete → RAGFlow
   │  生成 Markdown / PDF
   ▼
monitor (api/monitor.py)  ← 单例，事件循环感知，推 WebSocket
   │
   ▼
前端 index.html（470 行调试页）
```

| 层     | 目录   | 职责                     | 问题                                   |
| ------ | ------ | ------------------------ | -------------------------------------- |
| 接入层 | api/   | HTTP + WS + 文件上传下载 | 无认证、无限流、无任务跟踪             |
| 编排层 | agent/ | 主/子智能体 + 执行引擎   | 每次请求重建 Agent、执行逻辑和编排耦合 |
| 工具层 | tools/ | 8 个 @tool               | 错误处理不统一、无权限、SQL 无护栏     |
| 横切层 | utils/ | 重试、路径、转换         | 只有局部能力，无全局错误/日志/配置     |

### 1.2 主线链路：代码落在了哪里

| #    | 链路节点                       | 现状代码位置                         | 是否健全                                          | DepGuard 对应环节                              |
| ---- | ------------------------------ | ------------------------------------ | ------------------------------------------------- | ---------------------------------------------- |
| 1    | 用户输入                       | server.py:81 /api/task               | ✅ 有，但无鉴权                                    | 提交 GitHub repo URL 或上传依赖文件            |
| 2    | Session / Context / Memory     | context.py + main_agent.py:284       | ⚠️ Session 有；Context 无压缩；Memory 只有对话历史 | 扫描任务会话 + 用户安全偏好记忆 + 内部策略 RAG |
| 3    | Prompt                         | prompt/prompts.yml                   | ⚠️ 业务写死「电商」、不可配置                      | 依赖安全分析 system prompt + 业务域配置        |
| 4    | 模型推理                       | llm.py init_chat_model               | ✅ 有                                              | 同上                                           |
| 5    | Plan                           | prompt 里一句「先列 todo-list」      | ❌ 无结构化 Plan/Replan                            | 扫描 Plan + 升级 Replan                        |
| 6    | Tool Call                      | deepagents 的 task 工具 + 8 个 @tool | ✅ 有                                              | 漏洞查询、依赖解析、版本匹配、报告生成         |
| 7    | 权限检查                       | 无                                   | ❌ 完全缺失                                        | 只读扫描默认放行；创建 PR / 写补丁需审批       |
| 8    | 工具执行                       | tools/*                              | ⚠️ 错误处理/超时/限额不统一                        | OSV API 限流重试、依赖文件格式错交模型修正     |
| 9    | Tool Result 回填               | deepagents 内部                      | ⚠️ 错误被当成普通字符串回填给模型                  | 结构化错误（含可用修复版本建议）回填           |
| 10   | 模型继续推理（Loop）           | deepagents 循环                      | ⚠️ 无显式递归上限/进度判定                         | 同一 CVE 重复查询无新证据 → 停止               |
| 11   | 任务结束                       | 无显式判定                           | ❌ 靠模型「自觉停」                                | Plan 所有 step 完成 + 风险报告生成完毕         |
| 12   | Session / Usage / Trace 持久化 | 只有 checkpointer                    | ❌ 无用量计费、无 Trace 持久化                     | 扫描证据链持久化 + Token 成本统计              |

**记忆口诀**：12 个节点里，本项目「有」的是 1/3/4/6/8，「缺或弱」的是 2/5/7/9/10/11/12。改造就是把这 7 个薄弱节点补齐，并用 DepGuard 业务闭环串起来。

### 1.3 现有亮点

1. **ContextVar 协程隔离**：讲得清「为什么不用全局变量、为什么不用 threading.local」。
2. **WebSocket 事件循环归属判断**：分清「同循环用 create_task、跨线程用 run_coroutine_threadsafe」。
3. **文件路径安全**：处理了虚拟路径、路径遍历、路径嵌套等边界。
4. **优雅降级**：数据库/RAGFlow 不配也能跑。DepGuard 中保留：OSV 不可用时降级只做 SBOM 生成。
5. **指数退避重试**：虽然只用在 Tavily，但思路对。DepGuard 中复用于 OSV API。
6. **流式执行 + 埋点**：DepGuard 中用于实时推送扫描进度。

### 1.4 现有缺口清单

| 编号 | 缺口                      | 具体位置                           | 后果                                   | DepGuard 中的表现                            |
| ---- | ------------------------- | ---------------------------------- | -------------------------------------- | -------------------------------------------- |
| G1   | 无认证/无权限             | server.py:81                       | 任何人可调用、可执行任意 SQL           | 任何人可扫描任意仓库、创建 PR                |
| G2   | SQL 任意执行 + 无结果限额 | tools/db_tools.py:141              | SQL 注入/删库风险、大结果集打爆上下文  | 依赖图查询无限制、缓存表可被写坏             |
| G3   | 后台任务无跟踪            | server.py:88                       | 任务异常无法感知、无法取消             | 大规模扫描任务跑丢无法感知                   |
| G4   | 每次请求重建 Agent        | main_agent.py:284                  | create_deep_agent 昂贵                 | 每次扫描重建整个分析图                       |
| G5   | 无 Context 压缩           | 全局                               | 长对话/大工具结果必然爆上下文          | 大依赖树全量塞入上下文直接爆                 |
| G6   | 无 Memory 模块            | 全局                               | 只有「对话历史」                       | 无法记住用户的「忽略某 CVE」「偏好保守升级」 |
| G7   | 无结构化 Plan/Replan      | prompts.yml                        | 复杂任务无规划、无进展判定             | 扫描阶段/升级阶段无结构化规划                |
| G8   | 错误处理不统一            | tools/db_tools.py 等               | 错误被当字符串回填，模型可能死循环重试 | OSV 限流被当普通结果，模型反复查同一包       |
| G9   | 无死循环/进度判定         | 依赖 deepagents 默认               | 「一直在执行但没推进」无法察觉         | 反复查同一 CVE 无新证据                      |
| G10  | 无可观测性                | monitor.py 只推不存                | 出问题无法回溯、无用量统计             | 每个依赖的扫描证据链无法回溯                 |
| G11  | 配置散乱                  | llm.py/tavily_tool.py/db_tools.py  | 难维护、难测试                         | OSV/deps.dev 的 API 地址、阈值散落各处       |
| G12  | 无测试                    | 无 test 目录                       | 改动即风险                             | 版本匹配逻辑无测试 = 扫描结果不可信          |
| G13  | PDF 依赖 Windows Word COM | utils/word_converter.py            | Docker/Linux 跑不了 PDF                | 风险报告无法跨平台生成                       |
| G14  | 死代码 + 重复定义         | main_agent.py:1-169、path_utils.py | 代码质量差                             | 面试官一眼看出                               |
| G15  | 无优雅停机                | server.py:271                      | 关服务时后台任务被强杀                 | 扫描到一半的任务直接蒸发                     |

---

## 2. 核心认知对齐：Agent 是系统设计问题

不要把这个项目当「学 LangChain/LangGraph」的项目，而要当成「一个 Agent 系统怎么跑起来」的系统设计题。

面试官真正想确认的：

- Agent 为什么要 Loop？
- Tool Call 完整流程是什么？参数传错怎么办？
- Tool 挂了是重试还是退出？哪些错误该重试、哪些不该？
- Context 爆了怎么办？怎么压、怎么截、丢什么信息？
- Memory 怎么存、怎么查、怎么更新？Memory 和 Session、RAG 有什么区别？
- 怎么避免死循环？光靠最大轮数够吗？
- Plan 怎么做？什么时候该 Replan？
- 最后怎么判断任务到底完成没有？

这些问题的答案，没有一个是「背一个 API」能解决的，全部是「设计决策」。

---

## 3. 需求文档

### 3.1 总体目标

把 MultiAgent-Search 升级为以 DepGuard Agent 为核心业务的、能写进简历、经得起追问的企业级 Agent 项目。

- **业务闭环**：输入仓库依赖 → 多源情报聚合 → 风险分析 → 可执行升级计划 → 审计报告。
- **健壮性**：任何 Tool 失败、超时、参数错误都不会让整个任务静默崩溃。
- **可控性**：能限制循环次数、能感知「任务没推进」、能取消任务。
- **安全性**：有身份认证；危险操作有权限检查；SQL 有只读护栏；默认只读扫描。
- **可观测性**：每个依赖的扫描证据链可回溯、有结构化日志、有 Token 用量。
- **可维护性**：配置集中、分层清晰、有测试、能一键 Docker 启动。
- **可验证性**：用 10 个真实开源仓库做评测，指标量化。

### 3.2 功能需求

| 编号  | 需求                                                   | 优先级 | 对应模块 |
| ----- | ------------------------------------------------------ | ------ | -------- |
| FR-1  | 用户身份认证（JWT），扫描任务归属用户                  | P0     | M1       |
| FR-2  | 会话管理：创建/查询/删除扫描会话                       | P0     | M1       |
| FR-3  | 上下文管理：依赖树不入上下文，超预算时压缩/截断        | P0     | M2       |
| FR-4  | 长期记忆：跨会话记住用户安全偏好/忽略的 CVE/升级偏好   | P1     | M3       |
| FR-5  | 任务规划：扫描 Plan + 升级 Plan 双阶段，支持 Replan    | P1     | M4       |
| FR-6  | Tool 权限分级：只读扫描默认放行；写报告/创建 PR 需审批 | P0     | M5       |
| FR-7  | Tool 错误分类 + 分级重试                               | P0     | M6       |
| FR-8  | 死循环防护 + 扫描进度判定                              | P0     | M7       |
| FR-9  | 全程 Trace 持久化 + 用量统计                           | P1     | M8       |
| FR-10 | 扫描任务取消接口                                       | P1     | M0/M1    |
| FR-11 | 结构化日志 + 监控指标                                  | P1     | M8       |
| FR-12 | 统一配置中心                                           | P1     | M9       |
| FR-13 | 单元/集成测试覆盖核心链路                              | P0     | M10      |
| FR-14 | 优雅停机                                               | P1     | M10      |
| FR-15 | PDF 转换跨平台                                         | P2     | M10      |
| FR-16 | SBOM 生成（CycloneDX/SPDX）                            | P0     | M11      |
| FR-17 | 多源漏洞聚合与去重                                     | P0     | M11      |
| FR-18 | 版本范围精确匹配                                       | P0     | M11      |
| FR-19 | 升级路径分析                                           | P1     | M11      |
| FR-20 | 许可证与维护性风险评估                                 | P1     | M11      |
| FR-21 | 内部安全策略 RAG                                       | P1     | M3       |
| FR-22 | 人工审批节点                                           | P2     | M5       |

### 3.3 非功能需求

| 类别   | 需求                                                   |
| ------ | ------------------------------------------------------ |
| 性能   | 依赖解析不阻塞事件循环；OSV 批量查询；LLM 调用并发受控 |
| 可用性 | 单点数据源故障不级联；OSV 挂了降级为只生成 SBOM        |
| 安全   | 路径遍历防护、SQL 注入防护、越权访问防护、默认只读     |
| 可观测 | 每次扫描有 trace_id；每个依赖的查询证据链可回溯        |
| 可维护 | 依赖版本锁定且收敛；代码分层；死代码清理               |

---

## 4. DepGuard Agent 业务设计

### 4.1 产品定义

> **DepGuard Agent：面向研发团队的开源依赖供应链风险与升级规划 Agent。**
>
> 输入一个代码仓库的依赖清单，自动生成一份**可审计、可执行、带证据链**的依赖风险处置方案，而不是只给一堆漏洞告警。

### 4.2 为什么有含金量

| 维度             | DepGuard                                                     |
| ---------------- | ------------------------------------------------------------ |
| 真实用户         | 研发团队、DevSecOps、开源维护者、被合规审计的团队            |
| 真实痛点         | 依赖漏洞多、误报高、升级建议不可执行、升级怕破坏兼容性       |
| 数据源           | OSV.dev、GitHub Advisory、NVD、deps.dev、GitHub API，全部公开可验证 |
| 输出             | SBOM、风险报告、升级计划、补丁/PR 建议、审计 trace           |
| 可验证指标       | 漏洞覆盖率、误报率、升级建议可执行率、MTTR 降低              |
| 为什么需要 Agent | 多源情报聚合、版本范围匹配、升级路径权衡、破坏性变更分析、内部策略 RAG、人工审批 |
| 面试可追问       | 安全、误报、上下文、死循环、权限、评测、成本                 |

### 4.3 与现有能力映射

| 现有模块               | DepGuard 中的角色                     |
| ---------------------- | ------------------------------------- |
| 市场情报助手           | 漏洞情报检索                          |
| 数据分析助手 + SQL     | 依赖图查询、SQLite 缓存、版本范围匹配 |
| 内部知识助手 + RAG     | 公司安全策略、历史升级决策、白名单    |
| Markdown/PDF 工具      | 生成风险报告、升级计划                |
| 多智能体 Orchestrator  | 解析、情报、影响、规划、报告分工      |
| WebSocket + 前端       | 实时展示扫描进度、审批请求            |
| ContextVar + thread_id | 多用户/多仓库扫描隔离                 |

M0-M10 落地映射：

| 模块       | DepGuard 中的落地                              |
| ---------- | ---------------------------------------------- |
| M0 单例    | 扫描引擎单例，复用 LangGraph 图                |
| M1 会话    | 扫描任务归属用户/仓库，JWT 认证                |
| M2 Context | 依赖树存 SQLite，只把高风险子图给 LLM          |
| M3 Memory  | 记住项目历史忽略的 CVE、升级偏好；内部策略 RAG |
| M4 Plan    | 扫描 Plan + 升级 Plan 双阶段                   |
| M5 权限    | 只读扫描默认放行，写 PR 需审批                 |
| M6 错误    | OSV 限流重试，依赖文件格式错交模型修正         |
| M7 死循环  | 同一 CVE 重复查询无新证据就停止                |
| M8 Trace   | 每个依赖的扫描证据链可回溯                     |
| M9 Config  | 数据源地址、阈值、策略可配置                   |
| M10 测试   | 解析器、版本匹配、SQL 白名单单测               |

### 4.4 核心业务闭环

#### 4.4.1 输入

- GitHub repo URL
- 或上传 `requirements.txt` / `package.json` / `pom.xml`
- 可选：内部安全策略、白名单、升级偏好（保守/激进）

#### 4.4.2 Agent 处理流水线

**Step 1：解析 Agent**

- 从依赖文件提取直接依赖、传递依赖、版本范围、生产/开发依赖。
- `requirements.txt` 用 `packaging` 解析；`pipdeptree --freeze` 或 `pip install --dry-run --report` 获取传递依赖树。
- `package.json` 读取 `dependencies` / `devDependencies`；有 lock 文件则解析完整树。
- `pom.xml` 用 `xml.etree.ElementTree` 解析；传递依赖通过 deps.dev API 获取。
- 验证：与 `osv-scanner --format json` 输出交叉验证依赖数量。

**Step 2：漏洞情报 Agent**

| 数据源          | API 端点                                               | 用途                            | 认证     |
| --------------- | ------------------------------------------------------ | ------------------------------- | -------- |
| OSV.dev         | `POST https://api.osv.dev/v1/querybatch`               | 主漏洞数据源，批量 1000 包/请求 | 无需 Key |
| OSV.dev         | `GET https://api.osv.dev/v1/vulns/{id}`                | 单条漏洞详情                    | 无需 Key |
| GitHub Advisory | `GET https://api.github.com/advisories`                | 补充 GHSA 数据                  | 公共查询 |
| NVD             | `GET https://services.nvd.nist.gov/rest/json/cves/2.0` | 补充 CVSS 评分                  | 可选 Key |

- 验证：用 `osv-scanner scan source -r /path/to/repo` 作为基准，计算覆盖率与误报率。
- 关键：版本范围匹配必须按生态区分比较器：Semver、PEP 440、Maven、dpkg。
- 别名去重：用 OSV `aliases` 字段关联 CVE/GHSA，用 `modified` 时间戳检测变更。

**Step 3：许可证与维护性 Agent**

- deps.dev API：
  - `GET /v3alpha/systems/{system}/packages/{name}`
  - `GET /v3alpha/systems/{system}/packages/{name}/versions/{version}`
  - `GET /v3alpha/systems/{system}/packages/{name}/versions/{version}:dependencies`
- GitHub API：`GET /repos/{owner}/{repo}` 获取 star、最后 commit、open issues。
- 验证：与 `osv-scanner --licenses` 交叉验证。

**Step 4：影响分析 Agent**

- MVP：在源码中搜索 import/require，判断是否被生产代码引用。
- 进阶：集成可达性分析工具，做静态调用图分析。
- 验证：对 3 个已知可达性结果的 CVE 做人工核对。

**Step 5：升级规划 Agent**

- OSV `fixed` 字段给出修复版本。
- deps.dev 获取所有可用版本，寻找最小安全版本。
- GitHub Releases API 获取 release notes，识别 breaking changes。
- 验证：在测试仓库执行升级，运行 CI，计算可执行率。

**Step 6：报告与审批 Agent**

- 生成 SBOM、风险报告、升级计划。
- SBOM 用 `cyclonedx-python-lib` 生成 CycloneDX 格式。
- 验证：`cyclonedx-cli validate`。
- 创建 PR 需人工审批。

#### 4.4.3 输出

- `sbom.json`：CycloneDX/SPDX
- `risk_report.md/pdf`：按优先级排序的漏洞、许可证、维护性风险
- `upgrade_plan.md`：推荐版本、升级命令、破坏性变更、回滚方案
- `scan_trace.json`：每个依赖的扫描证据链
- 可选：PR 建议，需审批

---

## 5. 扩展方案 M0-M12

> 每个模块统一格式：现状 / 为什么不行 / 改造方案 / 为什么这么改 / 面试追问 & 答法 / DepGuard 落地步骤。

### M0 架构重构：Agent 单例化 + 后台任务注册表

**现状**

- `main_agent.py:284` 每次请求都 `create_deep_agent(...)`。
- `server.py:88` 用 `asyncio.create_task(...)` 启动后台任务，返回值被丢弃。

**为什么不行**

- `create_deep_agent` 是重操作，每次重建浪费 CPU 和内存。
- 后台任务无跟踪：失败不知道、无法取消、重启蒸发。

**改造方案**

- Agent 单例化：模块级懒加载单例，复用同一个 LangGraph 图，靠 `thread_id` 隔离会话。
- checkpointer 改成全局连接池。
- 新建 `TaskRegistry`：`dict[thread_id -> asyncio.Task]`，`create_task` 后登记，结束自动移除，提供 `cancel_task`。

```python
class TaskRegistry:
    _tasks: dict[str, asyncio.Task] = {}

    def start(self, thread_id: str, coro):
        task = asyncio.create_task(coro)
        self._tasks[thread_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(thread_id, None))
        return task

    def cancel(self, thread_id: str) -> bool:
        task = self._tasks.get(thread_id)
        if task:
            task.cancel()
            return True
        return False
```

**为什么这么改**

- Agent 图无状态，状态在 checkpointer 里，天然适合共享。
- 任务注册表让后台任务从「发出去就不管」变成「可查询、可取消、可观测」。

**面试追问**

- 为什么 Agent 可以做成单例？多用户不会串数据吗？  
  → 图是重的、状态是轻的；状态靠 `thread_id` 隔离。
- `asyncio.create_task` 为什么不直接 `await`？  
  → `await` 会阻塞接口返回，用户要等几分钟；`create_task` 让接口立即返回 `thread_id`，前端通过 WebSocket 收进度。

**DepGuard 落地**

1. `get_agent()` 懒加载单例。
2. `task_registry.start(thread_id, run_deep_agent(...))`。
3. 新增 `POST /api/task/{thread_id}/cancel`。
4. 扫描任务与 repo URL 写入 sessions 表。

---

### M1 会话与身份层（Session / 认证）

**现状**

- `/api/task` 无鉴权，`thread_id` 随便传。
- 会话状态只有文件夹 + checkpointer，无会话元数据。

**为什么不行**

- 谁都能调用、消耗 LLM 额度、打数据库、扫描任意仓库、创建 PR。
- 会话信息散落，无法统一查历史/状态/结果。

**改造方案**

- JWT 认证：`/api/task`、`/api/upload` 加 `Depends(get_current_user)`。
- 会话元数据表 `sessions`：`id, user_id, repo_url, status, created_at, finished_at, error, token_usage, finding_count`。
- 会话归属校验：查询/下载文件、连接 WebSocket 时校验 `thread_id` 属于当前用户。

**为什么这么改**

- JWT 无状态，适合水平扩展。
- 会话表收口散落信息，后续 Usage、Trace、任务查询都挂在这张表上。

**面试追问**

- JWT 怎么防过期/吊销？  
  → 短 exp + refresh_token；主动吊销用黑名单或版本号。
- WebSocket 怎么做鉴权？  
  → 握手时带 token，先校验再 accept。

**DepGuard 落地**

1. `api/auth.py`：`create_access_token`、`get_current_user`、`POST /api/login`。
2. 建 `sessions` 表。
3. `POST /api/task` 插入 `pending`，`run_deep_agent` 更新 `running` / `done` / `failed`。
4. WebSocket 和文件下载校验归属。

---

### M2 Context 管理（上下文压缩 / 截断）

**现状**

- 无上下文管理，历史无限累积，工具结果原样回填。

**为什么不行**

- 上下文越长，成本越高、延迟越高、注意力越稀释。
- DepGuard 中大依赖树 2000+ 包，全量塞入直接爆。

**改造方案**

- 预算感知：tiktoken 估算 token，超过 60% 窗口触发策略。
- 截断：保留 system prompt + 最近 N 条。
- 压缩：把最早消息摘要成一段，替换原文。
- **DepGuard 专用**：依赖树存 SQLite，工具按 `severity >= HIGH` 筛选，只把高风险子图给 LLM。

```python
def maybe_compress(messages, budget, summarizer):
    if token_count(messages) < budget:
        return messages
    head = messages[:1]
    middle = messages[1:-K]
    tail = messages[-K:]
    summary = summarizer(summarize(middle))
    return head + [summary] + tail
```

**为什么这么改**

- 直接截断会丢失早期关键决策；压缩能保留信息又控制成本。
- system prompt 和最近 K 条必须保留；牺牲最久远的中间部分。
- 结构化数据不要塞上下文，数据库就是上下文。

**面试追问**

- 压缩会不会丢关键信息？  
  → 会，成本 vs 保真取舍；纯闲聊截断，任务型摘要，重要信息进 Memory。
- DepGuard 中依赖树怎么处理？  
  → 存 SQLite，LLM 只看筛选后的高风险子图。

**DepGuard 落地**

1. `utils/context_budget.py`：`token_count`、`maybe_compress`。
2. 建 `dependency_tree` 表。
3. 解析 Agent 写表，不直接给 LLM。
4. 漏洞 Agent 查询时筛选 `severity >= HIGH`。
5. 每轮 LLM 调用前检查 token。

---

### M3 Memory 系统（Memory vs Session vs RAG）

**现状**

- 只有 checkpointer 的对话历史，本质是 Session。

**为什么不行**

- Memory、Session、RAG 混为一谈，面试一问就露馅。

|          | Session          | Memory                     | RAG              |
| -------- | ---------------- | -------------------------- | ---------------- |
| 存什么   | 当前会话完整消息 | 跨会话事实/偏好            | 外部文档知识     |
| 生命周期 | 会话结束归档     | 长期、跨会话               | 永久             |
| 怎么查   | 顺序读           | 语义检索/结构化查          | 向量检索         |
| 例子     | 本次扫描对话     | 用户偏好保守升级、忽略 CVE | 公司安全策略文档 |

**改造方案**

- `memory/` 抽象 Memory 接口。
- 短期 Memory = checkpointer。
- 长期 Memory = 向量库存用户偏好、决策、事实。
- 生命周期：存 = 任务结束提炼；查 = 新任务语义召回；更 = 新覆盖旧 + 时间戳。

**DepGuard 落地**

1. `memory/long_term.py`，底层 SQLite + `sqlite-vec` 或 Chroma。
2. 记忆类型：`USER_PREFERENCE`、`IGNORED_CVE`、`WHITELIST`、`DECISION`。
3. 扫描结束提取值得记住的信息。
4. 新任务按 `user_id + repo_language` 检索，注入 system prompt。
5. 用户改变态度时覆盖旧记忆并保留 `updated_at`。

**面试追问**

- 怎么决定一条对话要不要进 Memory？  
  → 规则 + LLM 双保险；DepGuard 中「这个 CVE 是误报」值得记，「扫一下仓库」不值得。
- 记忆冲突怎么办？  
  → 时间戳新覆盖旧，保留更新历史。

---

### M4 Plan 规划层（Plan / Replan）

**现状**

- prompt 里一句「先列 todo-list」，无结构化约束、无校验、无 Replan。

**为什么不行**

- 不可校验、无反馈闭环、不可观测。
- DepGuard 天然分扫描阶段和升级规划阶段，适合结构化 Plan。

**改造方案**

双阶段 Plan：

```json
{
  "scan_plan": {
    "steps": [
      {"id": "S1", "description": "解析依赖文件", "status": "pending"},
      {"id": "S2", "description": "批量查询 OSV 漏洞", "status": "pending"},
      {"id": "S3", "description": "查询许可证与维护性", "status": "pending"},
      {"id": "S4", "description": "可达性分析", "status": "pending"},
      {"id": "S5", "description": "生成风险报告", "status": "pending"}
    ]
  },
  "upgrade_plan": {
    "steps": [
      {"id": "U1", "description": "确定最小安全版本", "status": "pending"},
      {"id": "U2", "description": "检查破坏性变更", "status": "pending"},
      {"id": "U3", "description": "生成升级命令与回滚方案", "status": "pending"},
      {"id": "U4", "description": "验证升级建议", "status": "pending"}
    ]
  }
}
```

- 每次 Tool 执行后更新 step 状态。
- Replan 触发：连续 N 次失败、step 超时、结果与预期严重不符。

**为什么这么改**

- JSON Plan 机器可读、可校验、可追踪。
- 事件驱动 Replan 比每轮重规划便宜。

**面试追问**

- 什么时候 Replan，什么时候放弃？  
  → 可恢复偏差 Replan；不可恢复放弃并说明。
- Plan 会不会太死板？  
  → Plan 可修正，给方向和大步骤，具体执行仍由模型自主。

**DepGuard 落地**

1. `agent/planner.py` 定义 Pydantic 模型。
2. 任务开始输出结构化 Plan 存 state。
3. 子智能体执行后更新状态。
4. 修复版本不存在时触发 Replan，寻找替代包。

---

### M5 Tool 运行时与权限（Tool Runtime / Permission）

**现状**

- 工具直接 `@tool`，无权限模型。
- `execute_sql_query` 直接执行模型生成的 SQL。

**为什么不行**

- 可能执行 `DROP TABLE` / `DELETE`。
- `SELECT *` 无 LIMIT 打爆上下文。
- DepGuard 中创建 PR 是写操作，不能交给 LLM 自主决定。

**改造方案**

- 工具分级：`read` / `write` / `dangerous`。
- `execute_tool` 统一封装：权限检查 → 参数校验 → 超时 → 结果限额 → 错误分类 → 埋点。
- SQL 只读护栏：只允许 SELECT，自动追加 `LIMIT 100`。
- 人工审批：`dangerous` 操作前 LangGraph `interrupt()`。

**为什么这么改**

- 横切关注点集中，避免有的工具有的重试有的没有。
- prompt 是软约束，代码是硬约束，安全靠硬约束兜底。

**面试追问**

- Tool 参数传错怎么办？  
  → Pydantic 类型校验 + 业务语义校验；回填结构化错误让模型修正。
- 怎么防止模型绕过只读校验？  
  → 护栏放在执行层，不管 prompt 怎么写。

**DepGuard 落地**

1. `tools/runtime.py` 实现 `execute_tool`。
2. `TOOL_PERMISSIONS = {"osv_query": "read", "write_sbom": "write", "create_pr": "dangerous"}`。
3. SQL 白名单 + LIMIT。
4. PR 创建前 `interrupt()`，WebSocket 推审批请求。

---

### M6 错误分类与重试（Error Taxonomy / Retry）

**现状**

- 只有 Tavily 用了指数退避。
- DB 工具捕获异常后返回字符串，被当正常结果回填。

**为什么不行**

- 模型无法区分临时失败和永久失败，可能反复调用注定失败的工具。

**改造方案**

- 错误分类：
  - `RETRYABLE`：网络超时、429 限流 → 自动退避重试。
  - `INVALID_INPUT`：包名不存在、SQL 语法错 → 不重试，回填让模型修正。
  - `PERMISSION_DENIED`：无权限 → 终止。
  - `FATAL`：服务不可用 → 终止并说明。
- 结构化错误回填：

```json
{
  "error": "INVALID_INPUT",
  "message": "包 'lodash-x' 在 npm 生态中不存在，可能是拼写错误。可用包名：lodash",
  "retryable": false,
  "suggestion": "请检查包名拼写"
}
```

- 所有外部调用加 timeout。

**为什么这么改**

- 「重试」和「让模型修正」是两件事。
- 网络抖动系统重试；参数错误交模型改动作。

**面试追问**

- 为什么网络错误系统重试，参数错误交模型？  
  → 判断标准是「重试是否改变结果」。

**DepGuard 落地**

1. `utils/errors.py` 定义 `ToolError`。
2. OSV 调用加超时 10s、重试 3 次。
3. 429 等待 `Retry-After`。
4. 404 返回 `INVALID_INPUT`。
5. `execute_tool` 统一处理。

---

### M7 死循环防护（Loop Guard / 进度判定）

**现状**

- 完全依赖 deepagents 默认行为。

**为什么不行**

- 最大轮数只能兜底，拦不住「假推进」。
- DepGuard 中表现为反复查同一 CVE 无新证据。

**改造方案**

- 硬兜底：`max_iterations=30`、`max_duration=5min`。
- 软判定：
  - 重复调用检测：同工具 + 同参数连续 K 次。
  - 结果相似度检测：连续 N 轮结果哈希相同。
  - Plan 进度：执行 X 轮但 step 状态无变化。
- 卡住时先回填警示让模型 Replan，再终止。

**为什么这么改**

- 最大轮数是数量指标，无进展是语义指标。
- 先给模型一次换策略机会，避免浪费已投入上下文。

**面试追问**

- 怎么判断任务有没有推进？  
  → Plan step 状态 + 重复调用 + 结果相似度，三信号叠加。
- 相似度检测会不会误杀分页查询？  
  → 参数敏感；参数在变不算重复。

**DepGuard 落地**

1. `agent/loop_guard.py` 实现 `ProgressDetector`。
2. 记录 `(tool_name, args_hash, result_hash)`。
3. 触发规则后注入系统消息。
4. 仍无进展则终止并返回部分结果。

---

### M8 可观测性（Trace / Logging / Metrics / Usage）

**现状**

- monitor 只推前端 + print，不落库、不关联 trace_id、不统计用量。

**为什么不行**

- 出问题无法回溯；不知道一次扫描花了多少钱；print 无级别无结构。

**改造方案**

- Trace 持久化：`traces` 表，每次 Tool 调用写一条。
- 结构化日志：logging 替代 print，带 `trace_id`。
- 用量统计：从模型返回的 `usage` 累计到 sessions 表。

**DepGuard 落地**

1. `traces` 表：`id, trace_id, thread_id, node, tool_name, args, result_summary, token_usage, duration_ms, status, timestamp`。
2. `execute_tool` 中写入。
3. logging Formatter 加 `[trace_id=xxx]`。
4. sessions 表累加 token，计算成本。
5. 前端新增扫描详情页。

**面试追问**

- 一次扫描出错怎么排查？  
  → 拿 trace_id 拉 traces 表，看工具、参数、错误、重试、Token。
- Token 用量怎么统计？  
  → 模型返回 usage，按单价折算，主/子智能体都累加。

---

### M9 配置管理（Config / DI）

**现状**

- `load_dotenv` 到处调用，模型名、业务 prompt 写死。

**为什么不行**

- 改配置要找很多地方；测试难注入 mock；换业务要改代码。

**改造方案**

- `pydantic-settings` 建 `Settings` 类。
- prompt 模板化，业务抽成 `business_domain`。
- 工具通过 `get_settings()` 获取配置。

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    osv_api_base: str = "https://api.osv.dev/v1"
    depsdev_api_base: str = "https://api.deps.dev/v3alpha"
    github_token: str | None = None
    max_iterations: int = 30
    max_duration_seconds: int = 300
    token_budget_ratio: float = 0.6
    severity_threshold: str = "MEDIUM"
    business_domain: str = "dependency-security"
    upgrade_strategy: str = "conservative"

    class Config:
        env_file = ".env"
        env_prefix = "DEPGUARD_"
```

**为什么这么改**

- 类型校验 + 默认值 + 文档化，配置错误启动就报错。
- 一套框架、多个业务。

**面试追问**

- 怎么管理不同环境配置？  
  → 环境变量/.env/优先级；敏感信息走环境变量或密钥管理。
- 为什么配置要集中？  
  → 单一事实来源 + 可测试性。

---

### M10 工程化（测试 / CI / 优雅停机）

**现状**

- 无测试；CI 无测试环节；无优雅停机。

**为什么不行**

- 无测试 = 改一行怕崩全局；DepGuard 版本匹配没测试则扫描结果不可信。
- 无优雅停机 = 在途任务蒸发。

**改造方案**

- 单元测试：`utils/retry.py`、`path_utils.py`、`version_matcher.py`、`sql_guard.py`、`loop_guard.py`。
- 集成测试：mock LLM 和外部 API，测主链路。
- CI 加 `pytest`。
- 优雅停机：停止接收新任务 → 取消或等待在途任务 → 关连接。

**DepGuard 专用测试**

- 20 组 `(包, 版本, 生态, 预期是否受影响)` 参数化测试。
- SBOM 用 `cyclonedx-cli validate` 校验。

**面试追问**

- Agent 项目怎么测试？LLM 输出不确定怎么断言？  
  → 分层测：确定性逻辑单测，LLM 用 mock 测编排，输出质量用 E2E + 人工判断。
- 优雅停机和强制杀进程区别？  
  → 优雅停机让任务知道要停了，可落盘状态再退出。

---

### M11（新增）SBOM 生成与数据源集成

**为什么需要**

- DepGuard 核心输出之一是 SBOM，机器可读的软件组件清单。

**改造方案**

- 用 `cyclonedx-python-lib` 生成 CycloneDX。
- 数据源集成架构：

```text
DepGuard Agent
  ├── 解析 Agent
  ├── 情报 Agent
  └── 规划 Agent
        │
        ▼
Tool Runtime（权限 → 超时 → 限额 → 错误分类）
        │
        ▼
OSV.dev | deps.dev | GitHub API | NVD | 内部 RAG
        │
        ▼
SQLite 缓存层：dependency_tree | vuln_cache | traces
```

| 数据源          | 调用方式                                     | 缓存 | 降级            |
| --------------- | -------------------------------------------- | ---- | --------------- |
| OSV.dev         | `POST /v1/querybatch` + `GET /v1/vulns/{id}` | 24h  | 跳过漏洞匹配    |
| deps.dev        | `GET /v3alpha/...`                           | 7d   | 跳过许可证分析  |
| GitHub Advisory | `GET /advisories`                            | 24h  | 仅用 OSV        |
| NVD             | `GET /rest/json/cves/2.0`                    | 7d   | 用 OSV severity |

**DepGuard 落地**

1. `tools/sbom_tool.py`。
2. `tools/osv_tool.py`。
3. `tools/depsdev_tool.py`。
4. `tools/github_advisory_tool.py`。
5. `db/dependency_tree.py`。
6. Tool Runtime 注册权限与错误分类。

---

### M12（新增）业务评测体系

**为什么需要**

- 大多数包装项目没有评测。DepGuard 含金量核心是可验证量化指标。

**评测数据集**

| #    | 仓库        | 语言/生态   | 依赖数量 |
| ---- | ----------- | ----------- | -------- |
| 1    | requests    | Python/PyPI | ~5       |
| 2    | Flask       | Python/PyPI | ~15      |
| 3    | Django      | Python/PyPI | ~10      |
| 4    | express     | npm         | ~30      |
| 5    | React       | npm         | ~5       |
| 6    | lodash      | npm         | ~0       |
| 7    | Spring Boot | Maven       | ~50      |
| 8    | gin         | Go          | ~10      |
| 9    | fastapi     | Python/PyPI | ~20      |
| 10   | axios       | npm         | ~5       |

**评测指标**

| 指标             | 计算方法                         | 目标       |
| ---------------- | -------------------------------- | ---------- |
| 漏洞覆盖率       | DepGuard 找到 / osv-scanner 找到 | ≥ 90%      |
| 误报率           | 人工核对误报 / 报告总数          | ≤ 10%      |
| 升级建议可执行率 | CI 通过数 / 总建议数             | ≥ 70%      |
| 平均扫描时间     | 提交到报告生成                   | ≤ 60s      |
| Token 成本       | 单次扫描消耗                     | 记录并优化 |

**评测步骤**

1. 对每个仓库跑 `osv-scanner` 和 DepGuard。
2. 对比结果，计算覆盖率和误报率。
3. 升级建议在测试分支执行，跑 CI，记录通过率。
4. 记录 Token 和耗时。
5. 写入 `evaluation/results.md`。

**面试追问**

- 误报率 10% 怎么算的？  
  → 10 个真实仓库人工核对；主要来自 withdrawn 漏洞和 PyPI 版本边界。
- 升级建议可执行率 70% 什么意思？  
  → 70% 建议能通过仓库原有 CI，剩余 30% 跨大版本需人工介入。

---

## 6. 分期实施路线图

### 第一期（P0，2~3 周）：致命伤补齐

| 顺序 | 模块                    | 为什么先做        | 工时 |
| ---- | ----------------------- | ----------------- | ---- |
| 1    | M0 架构重构             | 后续改造地基      | 2 天 |
| 2    | M6 错误分类 + 重试      | 最容易被问        | 2 天 |
| 3    | M5 Tool 权限 + SQL 护栏 | 安全底线          | 2 天 |
| 4    | M7 死循环 + 进度判定    | 面试必问          | 2 天 |
| 5    | M1 认证 + 会话表        | 安全 + 会话       | 2 天 |
| 6    | M2 Context 压缩         | 解决爆上下文      | 2 天 |
| 7    | M11 SBOM + OSV 集成     | DepGuard 业务基础 | 3 天 |

做完能回答：Tool 挂了怎么办、怎么防死循环、怎么防 SQL 注入、怎么防上下文爆炸、为什么用 ContextVar/单例/后台任务。

### 第二期（P1，2 周）：业务做深

| 顺序 | 模块                           | 为什么         | 工时 |
| ---- | ------------------------------ | -------------- | ---- |
| 8    | M11 deps.dev + GitHub Advisory | 多源情报       | 2 天 |
| 9    | 版本范围精确匹配               | 扫描准确性核心 | 3 天 |
| 10   | M4 Plan / Replan               | 和 M7 呼应     | 2 天 |
| 11   | M3 Memory + 内部策略 RAG       | 压轴题         | 3 天 |
| 12   | M8 可观测性                    | 排查底气       | 2 天 |
| 13   | M12 评测体系                   | 量化含金量     | 2 天 |

做完能回答：Memory 怎么存查更、Memory 和 RAG 区别、怎么判断任务完成、出问题怎么排查、效果怎么量化。

### 第三期（P1.5，1~2 周）：升级规划与审批

| 顺序 | 模块                | 工时 |
| ---- | ------------------- | ---- |
| 14   | 升级路径分析        | 3 天 |
| 15   | 许可证与维护性风险  | 2 天 |
| 16   | 人工审批节点        | 2 天 |
| 17   | M10 测试 + 优雅停机 | 2 天 |

### 第四期（P2，按需）

| 模块                      | 工时 |
| ------------------------- | ---- |
| 可达性分析                | 3 天 |
| M9 配置中心               | 1 天 |
| PDF 跨平台                | 1 天 |
| LangSmith / OpenTelemetry | 1 天 |
| 限流/并发控制             | 1 天 |
| 异步任务队列              | 2 天 |

---

## 7. 面试准备手册

### 7.1 高频面试题 → 对应改动

| 面试题                       | 对应模块 | 一句话答案骨架                                               |
| ---------------------------- | -------- | ------------------------------------------------------------ |
| Agent 为什么要 Loop？        | M7       | 推理→调用工具→拿结果→再推理，天然循环；但要防死循环和假推进  |
| Tool Call 完整流程？         | M5       | 模型输出 tool_call → 参数校验 → 权限检查 → 执行 → 结果回填 → 继续推理 |
| 参数传错怎么办？             | M5/M6    | 类型校验 + 语义校验；回填结构化错误让模型修正，不重试        |
| Tool 挂了重试还是退出？      | M6       | 网络→重试，参数错→交模型，越权/致命→退出                     |
| 一直 Timeout 怎么办？        | M6       | 退避重试 + 次数上限，耗尽后降级 FATAL 或 Replan              |
| Context 爆了怎么办？         | M2       | 预算感知 → 截断/压缩；DepGuard 依赖树存 SQLite，只给高风险子图 |
| Memory 怎么存/查/更？        | M3       | 存：任务结束提炼；查：新任务语义召回；更：新覆盖旧 + 时间戳  |
| Memory/Session/RAG 区别？    | M3       | 数据来源、生命周期、查询方式三方面                           |
| 怎么避免死循环？             | M7       | 最大轮数兜底 + 重复检测 + Plan 进度                          |
| Plan 怎么做？                | M4       | 结构化 Plan + 状态追踪 + 事件驱动 Replan                     |
| 怎么判断任务完成？           | M4/M7    | Plan 所有 step 完成 + 无异常 + 达到结束条件                  |
| 多用户并发怎么隔离？         | M1/M0    | ContextVar 协程隔离 + thread_id 会话隔离 + Agent 单例        |
| 出问题怎么排查？             | M8       | trace_id → traces 表 → 时间线回溯                            |
| 为什么不用 Dependabot/Snyk？ | 业务设计 | 它们给告警和自动 PR，但缺少跨源证据、内部策略、破坏性分析、审计链 |
| 怎么防 LLM 幻觉 CVE？        | M5       | CVE、版本、许可证事实必须来自工具，LLM 只归纳排序            |
| 无安全版本怎么办？           | M4       | Replan：降级、替代包、隔离、临时缓解                         |
| 版本范围匹配怎么做？         | M11      | 按生态区分比较器：Semver/PEP 440/Maven/dpkg                  |
| SBOM 怎么生成？              | M11      | cyclonedx-python-lib 生成，cyclonedx-cli validate 校验       |

### 7.2 主动挖坑：5 个必答题

**坑一：Context 压缩——依赖树不入上下文**

> 抛：「大仓库依赖树 2000+ 包，全量塞上下文直接爆……」
> 追问：「那你们怎么处理？」
> 讲：依赖树存 SQLite，工具按 severity 筛选，只把高风险子图给 LLM。

**坑二：Tool 重试——网络错误和参数错误的分野**

> 抛：「一开始 OSV 限流和包名拼写错误都无脑重试……」
> 追问：「后来怎么分的？」
> 讲：按「重试是否改变结果」分类，429 退避重试，404 交模型修正。

**坑三：Memory 召回——相似不等于该注入**

> 抛：「相似度很高的 Memory 不一定真的该注入……」
> 追问：「为什么？怎么筛？」
> 讲：过期、技术栈无关、被更新覆盖的不注入；时间衰减 + 相关性 + 去重。

**坑四：死循环的假推进**

> 抛：「单纯限制最大 Loop 次数只能兜底，真正麻烦的是看起来一直在执行但任务没推进……」
> 追问：「怎么判断有没有推进？」
> 讲：Plan step 状态 + 重复调用检测 + 结果相似度，三信号叠加。

**坑五：业务评测的可信度**

> 抛：「我们做了评测，漏洞覆盖率 92%，误报率 10%……」
> 追问：「误报主要来自哪里？怎么改进？」
> 讲：withdrawn 漏洞未过滤 + PyPI 版本匹配边界；已加过滤，按生态分派比较器后改善。

### 7.3 简历怎么写才不碎

**❌ 错误写法**：「设计并实现企业级 Multi-Agent 平台」→ 一问就碎。

**✅ 正确写法**：

> **DepGuard：开源依赖供应链风险与升级规划 Agent**
>
> 基于 LangGraph 实现多智能体协作的依赖安全分析 Agent：输入仓库依赖，聚合 OSV.dev/GitHub Advisory/deps.dev 三源情报，生成 SBOM (CycloneDX)、风险报告与可执行升级计划。设计统一 Tool Runtime 对数据源工具做权限分级与错误分类（OSV 限流退避重试、参数错误回填修正），配合 SQL 只读护栏杜绝注入风险；依赖树存 SQLite 而非上下文，只将高风险子图注入 LLM，解决大依赖树爆上下文问题；引入「Plan 进度 + 重复调用检测」双重死循环防护，解决任务假推进问题。通过 ContextVar 协程隔离与 thread_id 会话隔离保证多用户并发安全，用 trace_id 全链路埋点实现每个依赖的扫描证据链可回溯。用 10 个真实开源仓库评测，漏洞匹配覆盖率 92%，升级建议可执行率 72%。

**检验法**：每写一行，连续问自己「为什么」。答得出留，答不出删。

---

## 附：落地优先级建议

1. 先动 M0（地基），再做 M6/M5/M7（最值钱的三块），这是及格线。
2. M11（SBOM + 数据源集成）是 DepGuard 业务核心，第一期必须完成。
3. 版本范围匹配是扫描准确性生命线，必须写单元测试，按生态区分比较器。
4. 每做完一个模块，就把 7.2 对应「坑」练熟。
5. 做到第二期完就投，让面试告诉你下一个补哪里。

**核心原则：先上桌，再补票。项目做到能讲清「主线链路的每一个为什么」，就已经赢过大多数「只会拼 API」的候选人。**