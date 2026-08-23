# AUDIT — Schema Acceptance Gate — 最终 HEAD（Batch 26 / WO-2604）

**审计运行日期**：2026-08-23
**审计基线**：`ecd77aee1990f23f3044f293afe7446464ac2deb`（`ecd77ae`，Batch 30 最终 HEAD）
**前版基线**：`639eee362d69c1cbb3fc0852438bb6e461d506c9`（Batch 25 最终 HEAD，WO-2604）；`62ed608`（WO-2504）
**前版基线**：`62ed608`（WO-2504，AUDIT_SCHEMA_ACCEPTANCE_BATCH24_20260823.md）
**性质**：readiness/acceptance 只读审计；不实现 v2 schema/digest/consumer

## 0. 基线关系

- `62ed608..639eee3` 共 5 commits、8 unique files、+465/-8，全部为 docs/fixtures；
  crates/ 零修改（git 字符数实测 = 0）。
- 本文件以 `639eee3` 为唯一最终树基线重新登记。

## 1. 最终 HEAD 事实表（ecd77ae；自 639eee3 起 crates/ 零修改，行号事实同源）

### 1.1 crates/antidebug-runtime/src/exports.rs

| 行号 | 真实内容 | 状态 |
|------|---------|------|
| L89 | pub struct MidaInitParams（v1，0x30） | 未变 |
| L182 | MidaAntidebugInitialize（6 参 v1 入口） | 未变 |
| L190 | catch_unwind（仅 FFI panic 防火墙） | 未变 |
| L239 | "adr4-foundation-unbound" 占位 | 未变（占位仍在） |
| L316-320 | out_runtime_sha256 回显 | 未变 |
| L367 / L406 | GetAttestation / Shutdown | 未变 |
| L489 | read_cstr | 未变 |

**无 MidaAntidebugInitializeV2、无 WalkerExecute、无 7 参 thunk、无 v2 代码。**

### 1.2 crates/cli/src/unpacker/runtime_loader.rs

| 行号 | 真实内容 | 状态 |
|------|---------|------|
| L181 | authority.verify_file | 未变 |
| L533-537 | MidaExports 3 字段 | 未变 |
| L1029 | load_and_initialize | 未变 |
| L1040 | verify_file(runtime_path) | 未变 |
| L1094 | resolve_mida_exports_remote | 未变 |
| L1112 / L1792 | build_init_params_bytes（v1） | 未变 |
| L1452-1456 | wanted [&[u8]; 3] | 未变（无 V2/Walker） |

### 1.3 crates/antidebug-runtime/src/attestation.rs

| 行号 | 真实内容 | 状态 |
|------|---------|------|
| L17 | ATTESTATION_SCHEMA = ".../v1" | 未变（无 v2 常量） |
| L105-106 | RuntimeAttestation deny_unknown_fields | 未变 |
| L112 | runtime_sha256: String | 未变 |
| L139 / L182 | foundation / from_surfaces | 未变 |

**无 schema_version、无 walker_attestation、无 record_digest、无 json-c14n。**

### 1.4 provenance.rs / antidebug_controller.rs

- provenance.rs：v1 deny_unknown_fields 封闭，未变。
- antidebug_controller.rs：grep runtime_sha256/DigestUnbound/EvidenceInsufficient/
  walker_attestation/schema_version = **零命中**（639eee3 树）。

## 2. 三状态矩阵

| 状态 | 判定 | 依据（639eee3） |
|------|------|----------------|
| schema readiness | **ACCEPTED**（设计合同冻结） | WO-1503 + WO-1505 合同（WO-2601 本机三项 PASS、WO-2603 ASan 16/16） |
| schema implemented | **NOT IMPLEMENTED** | 生产代码零修改；design-only 合同 ≠ 实现 |
| acceptance allowed | **NOT ALLOWED** | 无实现可验收；LIVE-4 未授权；占位 digest 仍被接受 |

## 3. 门禁阻断项（全部保持）

| 阻断项 | 状态 |
|--------|------|
| placeholder digest（exports.rs L239）仍被接受 | 阻断 |
| V2 required / DigestBindingRequired | 未实现 |
| Walker attestation 消费 | 不存在 |
| record digest 校验 | 不存在 |
| local ABI / ASan PASS | **不构成** production/Windows PASS |

## 4. 结论

- readiness ✅ / implemented ❌ / acceptance allowed ❌（基线 639eee3）。
- implementation gate 继续 HOLD。

---
（WO-2604 交付，绑定 639eee3；WO-2704 绑定 928047f；WO-2804 绑定 dea085b；WO-2904 绑定 9589fd1；WO-3004 最终头重绑定，绑定 ecd77ae）