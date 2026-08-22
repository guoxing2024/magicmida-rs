# AUDIT — Schema Acceptance Gate — 最终 HEAD 审计（Batch 21 / WO-2104）

**审计运行日期**：2026-08-22（总指挥侧；worker 文件时间戳 2026-08-23，temporal-mismatch 继续标记）
**审计基线**：`381507e`（docs(gto): WO-2005 protocol caller audit final-tree correction (P1)）
**前版基线**：`208f1f0`（AUDIT_SCHEMA_ACCEPTANCE_BATCH19_20260823.md 绑定旧树，已废弃声明）
**性质**：只读最终树审计；不实现 v2 schema/digest/consumer；不修改生产代码
**范围**：`381507e` 全树事实核对

## 0. 版本与继承关系

- 本文件是 WO-2104 的最终 HEAD 版本，取代 AUDIT_SCHEMA_ACCEPTANCE_BATCH19_20260823.md 的最终树声明。
- 旧文档基线 `208f1f0` 之后的提交（`dd6cae3`、`381507e`）均为 docs/fixtures 变更，生产代码（crates/）
  零修改。**结论措辞**：源码事实可复用，但旧审计树声明不等于最终树审计；本文件以 `381507e` 为唯一基线。

## 1. 最终 HEAD 事实表（381507e，逐文件核对）

### 1.1 crates/antidebug-runtime/src/exports.rs

| 行号（381507e） | 真实内容 | 状态 |
|----------------|---------|------|
| L89 | pub struct MidaInitParams（v1，0x30） | 未变 |
| L182 | pub unsafe extern "C" fn MidaAntidebugInitialize（6 参 v1 入口） | 未变 |
| L190 | catch_unwind（仅 FFI panic 防火墙，不捕 AV） | 未变 |
| L239 | let runtime_sha256 = "adr4-foundation-unbound"（占位，非真实 digest） | 未变（占位仍在） |
| L316-320 | out_runtime_sha256 回显（copy_nonoverlapping） | 未变 |
| L367 | MidaAntidebugGetAttestation | 未变 |
| L406 | MidaAntidebugShutdown | 未变 |
| L489 | read_cstr（有界 C 字符串读取） | 未变 |

**结论**：无 MidaAntidebugInitializeV2 导出、无 WalkerExecute 导出、无 7 参 thunk；
v2 schema 未实现。

### 1.2 crates/cli/src/unpacker/runtime_loader.rs

| 行号（381507e） | 真实内容 | 状态 |
|----------------|---------|------|
| L181 | authority.verify_file（manifest 身份校验） | 未变 |
| L533-537 | pub struct MidaExports { initialize, get_attestation, shutdown }（3 字段） | 未变 |
| L1029 | load_and_initialize（完整 ADR-6 链） | 未变 |
| L1040 | verify_file(runtime_path)（步骤 0，任何远程写入前） | 未变 |
| L1094 | resolve_mida_exports_remote(target, module_base) | 未变 |
| L1112 | build_init_params_bytes（v1 blob 构造） | 未变 |
| L1452-1456 | wanted: [&[u8]; 3] = [Initialize, GetAttestation, Shutdown] | 未变（无 V2/Walker） |
| L1792 | build_init_params_bytes（v1，0x30 + 绝对指针） | 未变 |

**结论**：loader 无 V2 调用路径、无 digest 下发、无 walker 导出解析。

### 1.3 crates/antidebug-runtime/src/attestation.rs

| 行号（381507e） | 真实内容 | 状态 |
|----------------|---------|------|
| L17 | ATTESTATION_SCHEMA = "mida.antidebug-runtime-attestation/v1" | 未变（无 v2 常量） |
| L105-106 | #[serde(deny_unknown_fields)] pub struct RuntimeAttestation | 未变 |
| L112 | pub runtime_sha256: String | 未变 |
| L139 | foundation() 构造器 | 未变 |
| L182 | from_surfaces() 构造器 | 未变 |

**结论**：无 schema_version 字段、无 walker_attestation 容器、无 record_digest；
json-c14n 与 digest vectors 均未实现。

### 1.4 crates/antidebug-runtime/src/provenance.rs

- v1 deny_unknown_fields 封闭结构，未变；无 v2 变体。

### 1.5 crates/cli/src/unpacker/antidebug_controller.rs

- grep runtime_sha256/DigestUnbound/EvidenceInsufficient/walker_attestation/schema_version：
  **零命中**。controller 不含任何 v2/digest/walker 消费逻辑（与 Batch 19 审计一致）。

## 2. 三状态矩阵（WO-2104 必须保持）

| 状态 | 判定 | 依据（381507e） |
|------|------|----------------|
| schema readiness | **ACCEPTED**（设计合同冻结） | WO-1503 v2 schema、json-c14n、4 digest vectors、WO-1505 V2 入口合同（WO-2102 修订）已冻结 |
| schema implemented | **NOT IMPLEMENTED** | exports.rs/attestation.rs 无 v2 代码；生产零修改 ≠ v2 实现 |
| acceptance allowed | **NOT ALLOWED** | 无实现可验收；LIVE-4 未授权；placeholder digest 仍被接受（阻断） |

## 3. 门禁消费结果复核（381507e）

| 检查项 | 结果 | 证据 |
|--------|------|------|
| placeholder digest 仍被接受 | **是（阻断项）** | exports.rs L239 "adr4-foundation-unbound"；无拒收逻辑 |
| V2 required（digest 需求） | 未实现 | 无 DigestBindingRequired 错误路径 |
| Walker attestation 消费 | 不存在 | attestation.rs 无 walker_attestation 字段 |
| record digest 校验 | 不存在 | 无 json-c14n/record_digest 代码 |
| EvidenceInsufficient | 仅在 v1 既有语义存在 | acceptance 无 v2 分支 |
| orphan/unconfirmed | 设计层（WO-1503 §7） | 无实现 |
| PASS 误报情况 | 未发现 | 本批与 Batch 17-20 交付物均为 design-only/fixture/审计文档，无生产代码改动 |

## 4. 源码事实可复用性声明

由于 `208f1f0` → `381507e` 之间仅 docs/fixtures 提交（`dd6cae3`、`381507e`），生产代码
逐字节未变，上一版审计的源码行号事实**可复用**；但旧文档基线 `208f1f0` 的"最终树"
声明不成立。本文件以 `381507e` 为唯一事实基线，行号均为最终树核对结果。

## 5. 结论

- readiness ✅ / implemented ❌ / acceptance allowed ❌（三状态与 Batch 19 结论一致，基线升级为 381507e）。
- placeholder digest 未实现替换 → implementation gate 阻断项仍开放。
- 本审计不构成 commander PASS；worker evidence 仅证明文档事实，Windows/live 行为 absent。

## 6. 残余风险

1. WO-2102 修订的 V2 合同（self-relative + params_bytes + strict extension）仍是 design-only；
   实现工单必须与 fixture（WO-2102-v2-envelope-fixture.h）逐行对照落地。
2. digest 流（controller 计算 → V2 下发 → attestation 回显 → acceptance 复核）四环节均未实现。
3. temporal-mismatch：worker 时间戳 2026-08-23 相对审计日 2026-08-22 为未来日期，已标记。

---
（WO-2104 交付，绑定 381507e）