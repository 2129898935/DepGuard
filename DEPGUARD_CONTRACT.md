# DepGuard 证据与批次契约（v1）

本契约适用于 `requirements*.txt` 的六阶段完整扫描。目标是让大清单可分批执行、故障后可恢复，并让“确实覆盖了输入且没有错位”可由程序复核。哈希只证明产物与输入/快照一致，**不证明外部漏洞情报本身正确**。

## 身份与来源

| 对象 | 生成者 | 规则 | 用途 |
| --- | --- | --- | --- |
| 已解析组件 ID | S1 `component_id` | `pkg:<ecosystem>/<PEP503-name>@<version>`，如 `pkg:pypi/requests@2.32.3` | S2～S5 稳定关联键 |
| 未解析需求 ID | S1 `component_id` | `req:<ecosystem>/<PEP503-name>#<约束哈希>` | 保留约束，不冒充可扫描的精确版本 |
| 证据 ID | S2/S3/S4 `evidence_id` | 阶段、组件 ID、来源、来源记录键的规范化哈希 | S5 引用目标 |
| 证据修订 | 每条记录 `revision_hash` | 当前记录内容哈希 | 区分同一逻辑证据的不同修订 |
| 来源快照 | 每批 `source_snapshot_id` | 本次实际 API 响应内容哈希 | 批次幂等和离线重放 |

S1 合并同一组件在多个输入文件中的声明，保留 `source_occurrences`。外部数据源只查询精确已解析版本；范围约束记为 `unknown/unresolved_version`。API 响应按会话落盘，不把“最新在线结果”当作可重放快照。OSV 工具自身的 24 小时缓存仍适用；跨会话不复用旧批次结果。

## 终态与规划义务

每个方向每个组件恰有一个有效终态：`complete`、`no_finding`、`unknown`、`not_applicable`、`source_failed`、`over_budget`、`manual_review`。非完整终态必须有 `reason_code`。`superseded` 只用于将来记录历史批次，**不是有效终态**。“许可证没有查到”是 `unknown`，不是 `not_applicable`。批次本身另有 `pending → running → succeeded | failed | split | incomplete` 状态；父批次 `split` 后只作为谱系节点，合并器只读取成功的叶子。

S5 对每个组件写一条 `disposition`。出现已确认或仅 ID 漏洞即 `needs_disposition=true`；已确认受影响、存在修复下限、候选版本在 OSV 查询无已知漏洞且 deps.dev 确认该版本存在，才令 `needs_upgrade_plan=true`。没有可验证候选时明确给出 `no_fixed_version` / `manual_review` / `unresolved_version` 等原因。候选计划状态为 `pending_compatibility`：OSV 无返回不等于生产安全、Python/上下游兼容或可达性已验证。S5 引用的每个证据 ID 必须存在并属于同一组件、生态和当前版本；S3/S4 证据无需全部被计划消费。

## 批次执行与门禁

`batch_plan_s2.json` 等清单保存稳定的拥有者集合、上下文集合、父子 ID、内容哈希和执行状态。`owned_components` 在有效叶子之间必须精确划分 S1 集合；上下文可重叠，但不产生第二个终态。批次输入按预算装箱，数量仅作兜底；S5 根据 deps.dev 已确认的直接依赖链接将联动组件放进同一规划单元。只有上下文溢出/输出截断会拆分成 `parent/1`、`parent/2`；确定性 schema/引用冲突不靠拆批掩盖。

每批产物保存输入 ID 集合哈希、输出终态 ID 集合哈希、输入内容哈希、来源快照 ID、幂等键、输出内容哈希、耗时与估算 token。门禁同时检查集合相等、唯一终态、哈希、漏洞引用、S5 规划义务和报告/SBOM。未知项会列在阶段 `coverage.uncovered` 中，不伪装成零漏洞；外部依赖按 `osv_api`、`deps_dev` 熔断，单批最多三次尝试。批次产物已经成功且内容未变时，重跑可直接复用。

S2/S3/S4 各自仍有独立的领域 Agent 图，并行审查程序生成的有界投影；审查意见属于建议，不写回漏洞/版本等事实字段。审查模型不可用时只降级该意见，证据批次仍可完成。设置 `DEPGUARD_LLM_REVIEW=0` 可关闭这三次额外模型调用，便于离线验证与成本控制。

上传 requirements 文件且请求只读扫描时，主控使用确定性 DAG 快速路径直接调度 S2/S3/S4、S5、S6；避免开放式主模型对固定流程反复调用造成高 token 成本。开放式任务仍保留 DeepAgent 交互路径；设置 `DEPGUARD_MANIFEST_FAST_PATH=0` 可用于该路径回归。S5/S6 在快速路径是证据驱动的阶段工作器，非额外的 LLM 推理调用；它们的完成必须通过实际文件与门禁验证。

离线重放：`python -m agent.replay output/session_<id>`。它只读本地批次/证据文件，不调用模型或网络；可发现缺失、错位和篡改。完整事实仍需与对应外部来源及抓取时点核对。源码不存在时 S4 对全部组件记 `unknown/no_source_evidence`，不能声称未使用或不可达。传递依赖未被本契约自动纳入 S1 扫描范围。
