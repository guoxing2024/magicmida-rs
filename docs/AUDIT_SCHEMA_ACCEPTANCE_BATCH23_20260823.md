# AUDIT — Schema Acceptance Gate — 最终 HEAD 重跑（Batch 24 / WO-2404）

**审计运行日期**：2026-08-23
**审计基线**：`221ef33c68ac8108aa5072bd233f0cfc06ddc885`（Batch 23 最终 HEAD）
**前版基线**：`ea79518`（WO-2304，AUDIT_SCHEMA_ACCEPTANCE_BATCH22_20260823.md）
**性质**：readiness/acceptance 只读审计；不实现 v2 schema/digest/consumer

## 0. 基线关系

- `ea79518..221ef33` 共 2 commits（0ebfff4、221ef33）、6 unique files、+388/-28，
  **全部为 docs/ 或 docs/fixtures/**；crates/ 逐字节零修改（git diff 字符数实测 = 0）。
- 因此 WO-2304 的源码行号事实**可复用**，但本文件以 `221ef33` 为唯一最终树基线重新登记。

## 1. 最终 HEAD 事实表（221ef33）

### 1.1 crates/antidebug-runtime/src/exports.rs（行号与 ea79518 一致）

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

### 1.4 crates/antidebug-runtime/src/provenance.rs / crates/cli/src/unpacker/antidebug_controller.rs

- provenance.rs：v1 deny_unknown_fields 封闭，未变。
- antidebug_controller.rs：grep runtime_sha256/DigestUnbound/EvidenceInsufficient/
  walker_attestation/schema_version = **零命中**（221ef33 树）。

## 2. 三状态矩阵（保持）

| 状态 | 判定 | 依据（221ef33） |
|------|------|----------------|
| schema readiness | **ACCEPTED**（设计合同冻结） | WO-1503 v2 schema + WO-1505 V2 合同（WO-2401 栈对齐实测、WO-2402 checked-add hostile 16/16） |
| schema implemented | **NOT IMPLEMENTED** | 生产代码零修改；design-only 合同 ≠ 实现 |
| acceptance allowed | **NOT ALLOWED** | 无实现可验收；LIVE-4 未授权；占位 digest 仍被接受 |

## 3. 门禁消费结果复核（221ef33）

| 检查项 | 结果 | 证据 |
|--------|------|------|
| placeholder digest 仍被接受 | **是（阻断项）** | exports.rs L239；无拒收逻辑 |
| V2 required / DigestBindingRequired | 未实现 | 无该错误路径 |
| Walker attestation 消费 | 不存在 | attestation.rs 无容器字段 |
| record digest 校验 | 不存在 | 无 json-c14n 代码 |
| EvidenceInsufficient | 仅 v1 既有语义 | acceptance 无 v2 分支 |
| orphan/unconfirmed | 设计层（WO-1503 §7） | 无实现 |
| PASS 误报 | 未发现 | Batch 22-24 交付物均为 design/fixture/审计 |

## 4. 文档误报检查

- Batch 24 新增（WO-2401 栈对齐、WO-2402 offset-wrap）均为 design-only 合同与离线
  fixture；**本机 ABI 测试 ≠ Windows remote execution**（V10 待 LIVE-4）。
- WO-2401 的 thunk7_abi/rsp_test 是**本机** x64 ABI 验证（VirtualAlloc 本进程），
  不涉及 target 远程、不构成 Windows live PASS。

## 5. 结论

- readiness ✅ / implemented ❌ / acceptance allowed ❌（基线 221ef33）。
- 占位 digest 未替换 → implementation gate 阻断项仍开放。
- 本审计不构成 commander PASS；Windows/live absent。

---
（WO-2404 交付，绑定 221ef33）