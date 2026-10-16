# DepGuard 评测结果（vs osv-scanner 基准）

- **评测时间**：2026-10-11 20:26:54
- **数据集**：10 个真实开源仓库（跨 Python / npm / Maven / Go）
- **基准**：osv-scanner（`D:/OsvScanner/osv-scanner.exe`）

## 一、逐仓库对比

| 仓库 | 生态 | 依赖数 | DepGuard | osv-scanner | 交集 | 误报 | 漏报 | 耗时 |
|---|---|---|---|---|---|---|---|---|
| requests | PyPI | 5 | 48 | 48 | 48 | 0 | 0 | 78.3s |
| Flask | PyPI | 5 | 46 | 46 | 46 | 0 | 0 | 69.7s |
| Django | PyPI | 4 | 114 | 114 | 114 | 0 | 0 | 134.4s |
| fastapi | PyPI | 4 | 36 | 36 | 36 | 0 | 0 | 56.9s |
| express | npm | 5 | 10 | 10 | 10 | 0 | 0 | 2.2s |
| react | npm | 3 | 0 | 0 | 0 | 0 | 0 | 1.6s |
| lodash | npm | 1 | 10 | 10 | 10 | 0 | 0 | 7.0s |
| axios | npm | 2 | 58 | 58 | 58 | 0 | 0 | 57.1s |
| spring-boot | Maven | 3 | 54 | 54 | 54 | 0 | 0 | 66.2s |
| gin | Go | 3 | 5 | 5 | 5 | 0 | 0 | 4.5s |

## 二、总体指标

- **漏洞覆盖率**：100.0%
- **误报率**：0.0%
- **总漏洞数**：DepGuard 381 个，osv-scanner 381 个
- **平均单仓库耗时**：47.8s

## 三、说明

- 两者都基于 OSV.dev 数据源，覆盖率预期接近 100%；差异主要来自版本范围匹配边界与别名归一化。
- 误报/漏报可能是同一漏洞的主 ID 与别名（GHSA/CVE/PYSEC/GO）归一到不同侧导致的计数差异，不代表事实性错报。