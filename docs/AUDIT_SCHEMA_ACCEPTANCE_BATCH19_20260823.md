# AUDIT_SCHEMA_ACCEPTANCE — Batch 20 Schema/digest acceptance gate 最终交叉审计（WO-2004）

**工单编号**: WO-2004（Batch 20）
**日期**: 2026-08-23（worker 机时钟；temporal-mismatch 见 AUDIT_EVIDENCE_BATCH19 §6）
**审计性质**: readiness/acceptance 只读审计；未实现 v2 schema、digest 或消费者。
**基线**: 最终 HEAD = 208f1f0（生产代码与 f39d1df 相同：Batch 20 零生产变更）

## 1. 目的

以最终 HEAD 对照真实代码更新 v1/v2 事实表；明确三状态区分；核查占位 digest 与各门禁当前消费结果；检查是否存在把 design-only/worker evidence/fixture 写成 production PASS 的文档。

## 2. 最终 HEAD 事实表（对照真实源码，HEAD=208f1f0）

### 2.1 exports.rs

| 事实 | 行 | 状态 |
|------|----|------|
| MidaAntidebugInitialize（v1 入口） | L182 | 存在（未变） |
| MidaInitParams（v1 结构） | L89 | 存在（未变） |
| MidaAntidebugInitializeV2 / MidaInitParamsV2 | — | **不存在**（rg 零命中；WO-2002 合同冻结 ≠ 实现） |
| runtime_sha256 = adr4-foundation-unbound | L239 | 存在（占位） |
| out_runtime_sha256 输出回显 | L316-320 | 存在（输出通道） |

### 2.2 runtime_loader.rs

| 事实 | 行 | 状态 |
|------|----|------|
| MidaExports 3 字段 | L533-537 | 存在（未变；无 initialize_v2/walker_execute） |
| wanted 3 项 | L1451-1455 | 存在（未变） |
| build_init_params_bytes（v1, 0x30） | L1792 | 存在（未变；无 v2 变体） |
| digest_controller 计算/复核 | — | 不存在 |
| V2 thunk（THUNK_CODE_7ARG / ThunkArgs7） | — | 不存在（WO-2002 合同） |

### 2.3 attestation.rs / provenance.rs

| 事实 | 行 | 状态 |
|------|----|------|
| RuntimeAttestation v1 + deny_unknown_fields | L104-106 | 存在 |
| ATTESTATION_SCHEMA = .../v1 | L17 | 存在 |
| schema_version / walker_attestation / record_digest | — | 不存在 |
| json-c14n serializer | — | 不存在 |
| Provenance v1 | provenance.rs | 存在 |

## 3. 三状态（WO-2004 明确）

| 状态 | 定义 | 当前 | 证据 |
|------|------|------|------|
| readiness accepted | 设计合同/矩阵经联审 | 是 | WO-1503/WO-1505 + 各 cross-audit；WO-2002 合同冻结 不等于 代码存在 |
| schema implemented | 仓库有 Rust 类型/函数/测试 | 否 | rg 零命中（§2.1-2.3） |
| acceptance allowed | acceptance 可消费 v2 证据并判定 | 否 | 无 v2 解析/校验；占位 digest 仍被接受 |

禁止误报规则：WO-2002 的 V2 envelope 合同（§5.3e-g）是本批 design 交付；任何合同已冻结的表述不得写成实现已完成。

## 4. 门禁消费结果核查（最终 HEAD）

| 门禁 | 当前代码消费结果 | 结论 |
|------|------------------|------|
| placeholder adr4-foundation-unbound | acceptance 当前接受该占位值（无拒收逻辑） | 未实现（阻断） |
| V2 required（digest 需求 → V2 必选） | 无 V2 入口，无需求判定 | 未实现（阻断） |
| Walker attestation 消费 | 无 v2 容器 | 未实现（阻断） |
| record digest 校验 | 无 record_digest 字段 | 未实现（阻断） |
| EvidenceInsufficient | 仅 v1 parse/validate 失败路径（runtime_loader.rs:1236-1255、antidebug_controller.rs:593-604）；无 v2 专属码 | 部分（v1） |
| orphan/unconfirmed | 无 walker 代码 | 未实现（阻断） |

## 5. PASS 误报检查

逐文档核查 Batch 17-20 交付物，确认：
- 无文档把 design-only 合同写成 production PASS（WO-1702/1802/1901/2001 均标注 design-only 或待验证）；
- 无文档把 worker evidence 写成 commander PASS（三层分离保持）；
- 无文档把 fixture 写成 Windows 行为证据（各 fixture 头部均有 NOT-a-compiled-implementation / NOT Windows proof 声明）；
- **未发现误报**。

## 6. 结论

readiness 是 / schema implemented 否 / acceptance allowed 否；
全部 v2/digest/acceptance 门禁保持未实现阻断；无 PASS 误报。本审计不派生产实现。
