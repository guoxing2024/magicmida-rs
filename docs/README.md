# docs/ 权威文档索引

> 2026-08-26 净化后，本目录只保留"活"文档。历史过程产物在
> `archive/operations/{work-orders,reports,audits}/`，早期 GTO 路线史在
> `archive/gto-20260730/` 与 `archive/routes/`。
> 新增权威文档必须登记到这里；工作单/交接类文件禁止进入 `docs/`
>（由 `.gitignore` 拦截）。

## 架构 / 契约 / 政策

| 文档 | 主题 |
|---|---|
| [VNEXT_ARCHITECTURE.md](VNEXT_ARCHITECTURE.md) | vNext 目标边界 |
| [ACCEPTANCE_CONTRACT.md](ACCEPTANCE_CONTRACT.md) | 验收契约（R0B） |
| [VNEXT_EVIDENCE_BUNDLE_V1.md](VNEXT_EVIDENCE_BUNDLE_V1.md) | 证据包契约 |
| [ARTIFACT_POLICY.md](../ARTIFACT_POLICY.md) | 入库边界政策（仓库根） |
| [GTO_SAMPLE_REVISION_POLICY.md](GTO_SAMPLE_REVISION_POLICY.md) | mutable 样本解析策略 |
| [SAMPLE_IDENTITY_LIFECYCLE.md](SAMPLE_IDENTITY_LIFECYCLE.md) | 样本身份生命周期 |
| [GTO_PREFLIGHT_LANE.md](GTO_PREFLIGHT_LANE.md) | GTO 预检通道 |
| [PROJECT_AUDIT_AND_ROADMAP.md](PROJECT_AUDIT_AND_ROADMAP.md) | 综合审计与路线图 |
| [GTO_TERMINAL_CHARACTERIZATION_20260822.md](GTO_TERMINAL_CHARACTERIZATION_20260822.md) | GTO dump 路线终态 |

## API / 行为契约（被代码直接引用）

| 文档 | 引用方 |
|---|---|
| [VNEXT_R1_PE_API.md](VNEXT_R1_PE_API.md) | pe/tests/purity_boundary.rs |
| [VNEXT_R1_ROADMAP.md](VNEXT_R1_ROADMAP.md) | README |
| [VNEXT_R2_RUNTIME_API.md](VNEXT_R2_RUNTIME_API.md) | core/src/addr.rs |
| [VNEXT_R3_OREANS_PATH.md](VNEXT_R3_OREANS_PATH.md) | tools/_r3_gate_run.py |
| [VNEXT_BEHAVIORAL_PATH.md](VNEXT_BEHAVIORAL_PATH.md) | behavior_oracle_contract.rs 等 |
| [MIDA_ADR_1_SURFACE_INVENTORY.md](MIDA_ADR_1_SURFACE_INVENTORY.md) | antidebug/src/profile.rs |
| [MIDA_ADR_2_PROBE_CATALOG.md](MIDA_ADR_2_PROBE_CATALOG.md) | antidebug/src/profile.rs |
| [WO-1702-seh-probe-shim-contract.md](WO-1702-seh-probe-shim-contract.md) | walker_protocol.rs（ABI §3） |
| [GTO_H5_STARTUP_ORDER_ATTRIBUTION_REPORT.md](GTO_H5_STARTUP_ORDER_ATTRIBUTION_REPORT.md) | tools/dd_restore.py |
| [GTO_R6_A1_DD_RESTORE_REPORT.md](GTO_R6_A1_DD_RESTORE_REPORT.md) | tools/dd_restore.py |

## 近期工作保留的引用文档

- [ADR7_B4_BINDING_CORRECTION_REPORT.md](ADR7_B4_BINDING_CORRECTION_REPORT.md)
- [ADR7_B5_TLS_ROOT_CAUSE_ISOLATION_REPORT.md](ADR7_B5_TLS_ROOT_CAUSE_ISOLATION_REPORT.md)
- [IMP09_DISPATCH_WIRING2_REPORT_20260826.md](IMP09_DISPATCH_WIRING2_REPORT_20260826.md)

以上三篇虽属过程报告，但被代码/tools 引用，暂留原位；解除引用后可移入
`archive/operations/reports/`。

## GTO-TR 线研究报告（T0 R0 交付物集）

GTO-TR 线是 TERMINAL 报告预留的「新工具/新思路走新治理」路线；其 R0 交付物
由 `WORK_ORDER_GTO-TR-0_20260826.md` §6 指定落地在 `docs/`：

| 文档 | 主题 |
|---|---|
| [GTO_TR_R0_FINGERPRINT_REPORT.md](GTO_TR_R0_FINGERPRINT_REPORT.md) | T0 引擎指纹收口（F1-F3） |
| [GTO_TR_T0_F2_FINGERPRINT_MATRIX.md](GTO_TR_T0_F2_FINGERPRINT_MATRIX.md) | 公开语料「版本×特征」矩阵（F2 子报告） |
| [GTO_TR_T0_F3_ATTRIBUTION_REFINEMENT.md](GTO_TR_T0_F3_ATTRIBUTION_REFINEMENT.md) | 归因精化（F3 子报告） |
