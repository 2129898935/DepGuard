# DepGuard Agent

DepGuard 是面向研发、DevSecOps 和安全团队的开源依赖供应链风险分析 Agent。它接收依赖文件或代码仓库，聚合公开漏洞与包元数据，生成带证据链的 SBOM、风险报告和升级方案。

## 核心流水线

```text
FastAPI + JWT + WebSocket
          │
          ▼
DepGuard 主编排 Agent
  ├─ S1 依赖解析助手
  ├─ S2 漏洞情报助手
  ├─ S3 许可证与维护性助手
  ├─ S4 影响分析助手
  ├─ S5 升级规划助手
  └─ S6 报告与审查助手
          │
          ▼
SBOM / 风险报告 / 升级计划 / Trace
```

六个子 Agent 有明确边界：

| 阶段 | 职责 | 主要工具/数据源 |
|---|---|---|
| S1 依赖解析 | 读取依赖文件并标准化组件 | requirements 解析、osv-scanner |
| S2 漏洞情报 | 漏洞查询、别名去重、修复边界 | OSV、GitHub Advisory、NVD |
| S3 许可证与维护性 | 许可证、依赖关系、仓库活跃度、内部策略 | deps.dev、GitHub、RAGFlow |
| S4 影响分析 | 查找源码中的依赖引用证据 | import/require 静态扫描 |
| S5 升级规划 | 最小安全版本、兼容风险、验证和回滚 | OSV、deps.dev、GitHub Releases |
| S6 报告与审查 | 证据质量门禁与文件输出 | CycloneDX、Markdown、PDF |

## 工程能力

- LangGraph/deepagents 多智能体编排与 SQLite checkpoint
- Agent 图单例复用、后台任务注册和取消
- JWT、SQL 只读护栏、工具权限分级
- Context 预算、长期 Memory、六阶段 Plan、Loop Guard
- SQLite 会话/缓存/Trace 持久化
- WebSocket 实时进度与会话文件管理
- pytest 自动测试和 osv-scanner 对照评测

## 快速开始

要求 Python 3.11+。复制环境变量模板并至少配置兼容 OpenAI 协议的模型：

```powershell
Copy-Item .env.example .env
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe api/server.py
```
```powershell
docker compose up -d
docker compose down
```
浏览器打开 http://localhost:8000。前端会使用本地开发登录接口获取 JWT。

API 调试示例：

```powershell
$login = Invoke-RestMethod -Method Post "http://localhost:8000/api/login?user_id=demo"
$headers = @{ Authorization = "Bearer $($login.token)" }
$body = @{ query = "分析 requests==2.31.0 的漏洞并给出升级建议" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/task -Headers $headers -ContentType application/json -Body $body
```

## 目录

- `agent/main_agent.py`：主图、六 Agent 接线和流式执行
- `agent/subagents/`：六个领域子 Agent
- `prompt/prompts.yml`：DepGuard 主身份和角色边界
- `tools/`：漏洞、包元数据、影响分析、SBOM 和报告工具
- `memory/`：长期记忆提取、存储与召回
- `db/`：会话、缓存与 Trace
- `api/`：FastAPI、JWT、WebSocket 和前端
- `evaluation/`：与 osv-scanner 的一致性评测
- `docs/`：设计与实施文档
- `tests/`：确定性逻辑测试

## 测试

```powershell
.venv\Scripts\python.exe -m pytest tests -q
```

## 当前边界

- 影响分析是轻量静态扫描，不覆盖动态加载、反射和完整调用图。
- Plan 已拆成六阶段，但结构化阶段产出写入共享 state 和自动 Replan 仍需继续增强。
- 创建 PR、自动修改依赖文件等危险操作尚未开放；当前只生成建议。
- PDF 转换目前仍依赖 Windows Word COM。
- 开发登录接口只用于本地演示，生产环境需要真实用户认证和资源归属校验。

