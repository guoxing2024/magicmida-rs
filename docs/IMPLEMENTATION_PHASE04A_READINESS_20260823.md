# IMPLEMENTATION PHASE 04-A — Production Wiring Readiness (IMP-06..IMP-10)

**性质**: 设计/静态审计单 — 无 tracked 文件修改，无远程执行，无 LIVE-4。
**基线**: HEAD `c27e8e6bc2744accdba619a3af70762c7be117db`（branch `oreans/impl-phase03`）
**冻结树**: `914e73e46763d469c7c581379da48fb78835b770`（ancestor of HEAD，+6 commits RC-1..RC-6）
**日期**: 2026-08-23
**状态**: 交付为“生产实现前置设计与静态审计”，implementation gate 保持 HOLD。

> 本文件是**设计草案**（design-only）。所有“必须输出”的回答都绑定到真实源码行号；
> 任何“将 / 下一实现单”均为设计意图，不是已实现事实。

---

## 1. 事实基线（与工单一致的核查结果）

| 对象 | 真实状态 | 证据 |
|---|---|---|
| `V2ParamsBlob::parse_offsets()` | 存在，纯本地解析，fail-closed | `crates/cli/src/unpacker/runtime_loader.rs:2565-2752` |
| `V2ParamsBlob::preflight_local()` | 存在，纯本地，**无任何生产调用点** | `runtime_loader.rs:2857-2907`；调用点仅 `#[cfg(test)]`（同文件 3406+） |
| `V2PreflightResult` | 存在，结构化本地结果 | `runtime_loader.rs:2815-2845` |
| `surface_string()` | 存在，纯本地读取 | `runtime_loader.rs:2914-2929` |
| `exports.rs:239` digest | **占位** `adr4-foundation-unbound` | `crates/antidebug-runtime/src/exports.rs:237-239` |
| `MidaAntidebugInitializeV2` | **不存在**于 runtime 导出 | `exports.rs` 导出面仅 3 个（L182/L367/L406）；rg 全仓零命中实现 |
| `WalkerExecute` | **不存在**于 runtime 导出/loader wanted | `crates/cli/src/unpacker/runtime_loader.rs:1451-1455` wanted 仅 3 项；`attestation.rs:830` 仅为文档注释 |
| `MidaExportsV2` / `require_complete()` | 存在但**仅被测试调用** | `runtime_loader.rs:2262-2288`；调用点仅 `imp03_inert_adapter_tests`（2958-2977） |
| `THUNK7_PRODUCTION` | 60B 字节 fixture，parser-only，**未接线** | `runtime_loader.rs:2301-2318`；`Thunk7Fixture::validate_structure` 仅结构校验 |
| Walker 协议（validated 三道门） | 纯离线 API，**仅测试调用** | `walker_protocol.rs:1523-1636`；全仓调用点均在 `tests/` |
| `RoundLedger` / `ProbeSummary` | 数据模型 + 校验，**无生产写入点** | `attestation.rs:684-813`；写入仅测试（`tests/attestation.rs`） |
| `ImplementationFacts` | 门禁结构存在；当前事实全部为 false/占位 | `implementation_gate.rs:43-65, 100-181` |

---

## 2. IMP-06 — Digest Authority / Placeholder 解锁路径

### DIGEST_COMPUTE_POINT（唯一合法生产计算点）

```text
RuntimeAuthorityManifest::verify_file()   crates/cli/src/unpacker/runtime_loader.rs:181-219
  sha256_hex(std::fs::read(canonical_runtime_dll))   L201-210  ← 唯一 runtime 文件字节哈希
  + size_bytes + verify_pe_x64()                      L194-212
```

- loader 侧实际计算 runtime SHA-256 的位置：**`runtime_loader.rs:204`**（`sha256_hex`，helper 定义 L424-430）。
- 该 digest 已经绑定进 `RuntimeFileIdentity.sha256`（L270-275）并经 `verify_runtime_provenance`（L1884-1953）与 manifest/provenance 三方对账。

### DIGEST_ABI_ENTRY（冻结设计，WO-1505 §5.3 / WO-1803 / WO-2102）

```text
MidaAntidebugInitializeV2(const MidaInitParamsV2* params, uint64_t params_bytes,
                          uint8_t* out_runtime_sha256, size_t out_runtime_sha256_len,
                          uint8_t* out_attestation_json, size_t out_attestation_len,
                          size_t* out_attestation_written)
digest 经 params blob 内 self-relative digest_off (0x38) + digest_len (0x40 == 64) 下发
```

- runtime 侧当前**没有任何** entry 接收真实 digest：`MidaAntidebugInitialize` 从不读取 0x30 之后（v1 契约），`MidaAntidebugInitializeV2` **不存在**。
- `out_runtime_sha256` 回显通道：loader 现把 arg1/arg2 指向 `remote_att` 缓冲区但**从不读回**（`runtime_loader.rs:1168-1169`，注释明示 “unused by loader”）。当前不存在回显校验。

### DIGEST_RUNTIME_VERSION_BOUNDARY / 字段边界 / MISMATCH_BEHAVIOR

- 字段边界（冻结设计，WO-1505 §5.3e / 代码已实现于 V2ParamsBlob::build）：digest 恰 64 个 lowercase hex + 第 65 字节 NUL；`digest_len` 字段必须 == 64；`digest_off` 在 `[0x48, len)` 内；blob 尾部不允许未知区（`runtime_loader.rs:2437-2548` 已实现 builder 侧；`parse_offsets` L2565-2752 已实现 parser 侧拒收）。
- MISMATCH_BEHAVIOR（冻结设计）：controller 复核 `attestation.runtime_sha256 == digest_controller`，不一致 → 拒收（EvidenceInsufficient / DigestUnbound）；`adr4-foundation-unbound` 在 digest 需求为真时不得进入可接受证据（WO-1505 §5.3d, §5.4）。**当前代码无此复核逻辑**（`runtime_loader.rs` 全文件无 `runtime_sha256` 比对，见 grep）。
- 生命周期：digest 字符串随 v2 params blob 同一次 `VirtualAllocEx` 分配、同回收（wait-before-free 铁律，`thunk_call_tracked_with_handle` L1003-1016 已实现保留语义）。

### PLACEHOLDER_REPLACEMENT_CONDITION（唯一合法解锁条件）

```text
adr4-foundation-unbound 只能被替换为：
  1) 由 verify_file()（L204）对同一 runtime DLL 文件字节计算出的 sha256 值；且
  2) 经 MidaAntidebugInitializeV2 digest_off/digest_len 通道下发（self-relative，blob 内）；
  3) runtime 用该值构建 attestation.runtime_sha256 并经 out_runtime_sha256 回显；
  4) controller 校验 回显 == attestation.runtime_sha256 == digest_controller，三者一致才可消费。
禁止：随意固定字符串 / 测试 SHA 当生产 authority / 新增独立内存槽绕过 ABI / 自嵌入（自引用循环，WO-1505 §5.1）。
```

### DIGEST_AUTHORITY_MATRIX

| 环节 | 当前状态 | 证据位置 |
|---|---|---|
| 文件字节哈希（唯一权威） | ✅ 已实现（loader/controller 侧） | `runtime_loader.rs:201-210` |
| manifest 编译期锁定 | ✅ 已实现 | `runtime_loader.rs:87-90, 106-145` |
| 与 provenance 三方对账 | ✅ 已实现 | `runtime_loader.rs:1884-1953` |
| runtime 侧真实 digest 接收 | ❌ 未实现（V2 entry 不存在） | `exports.rs` 导出面 |
| out_runtime_sha256 回显读取 | ❌ 未实现（loader 注释 unused） | `runtime_loader.rs:1168-1169` |
| attestation.runtime_sha256 == digest 复核 | ❌ 未实现 | 全仓 grep 无比对 |
| placeholder 拒收（acceptance 层） | ⚠️ 部分：gate 仅查 `digest_value == PLACEHOLDER` | `implementation_gate.rs:109-115`；真实 attestation 消费路径无拒收 |

---

## 3. IMP-07 — V2 Consumer Production Caller 设计

### CALLER_GRAPH（真实，截至 HEAD）

```text
unpack()  crates/cli/src/unpacker/mod.rs:120
  ├─ post-attach 预恢复 loader        mod.rs:549-590  → run_runtime_loader (L561)
  │     └─ AntidebugController        mod.rs:750-796  （loader_result 注入 L767-768）
  └─ CREATE_PROCESS 处理器            mod.rs:1084-1481
        └─ run_runtime_loader         mod.rs:1235     → 结果注入 L1243-1244
              └─ load_and_initialize  runtime_loader.rs:1029-1265
                    ├─ verify_file()                L1040
                    ├─ LoadLibraryW 远程线程        L1087-1089
                    ├─ resolve_mida_exports_remote  L1094（wanted 3 项，L1451-1455）
                    ├─ build_init_params_bytes(v1)  L1112-1119
                    └─ thunk_call(6 参, v1 init)     L1165-1183
```

**V2 专属路径（preflight_local / V2ParamsBlob / MidaExportsV2 / require_complete）当前零生产调用**：全仓 grep 证明所有调用点都在 `#[cfg(test)] mod imp03_inert_adapter_tests`（runtime_loader.rs:2933+）内。硬门结论：

```text
production loader/controller → preflight_local()   ✗ 不存在
preflight_local() → test                            ✓（仅测试）
⇒ has_v2_consumer = false
```

### INPUT_OWNERSHIP / BLOB_BASE_PROVENANCE / PARAMS_BYTES_PROVENANCE

- 设计（WO-1505 §5.3e + WO-2202 §5.3f）：v2 blob 由 controller 单次 `VirtualAllocEx` 分配、WPM 全量写入、再创建远程线程调用 V2 entry；`params == blob_base_va`、`params_bytes == 分配大小`，同源不变式由 controller 调用序列保证；runtime 侧 header 读取属硬信任边界（坏指针 = 进程终止，不返回错误码）。**当前代码无任何 v2 blob 分配/写入/调用路径**（`VirtualAllocEx` 调用点仅 path/params(v1)/att/thunk，见 L1053-1056/1097-1105/1148-1156/922-930）。
- 测试中 `blob_base` 为假想常量 `0x0000_1000_0000`（`runtime_loader.rs:2938`），**不是**生产来源。

### PREFLIGHT_CALL_SITE / RESULT_CONSUMER

- 唯一真实调用点：`runtime_loader.rs:3408, 3439, 3450, ...`（同文件 test mod）。
- `V2PreflightResult` 唯一消费方：`surface_string()`（L2914，本地）与测试断言；**没有** controller/loader 生产消费。
- 设计建议（下一实现单）：唯一生产调用点 = `load_and_initialize` 中 v2 分支（digest 需求为真时），在 `WriteProcessMemory(params)` 之前对本地构造的 blob 字节调用 `preflight_local(remote_params_va)` 作为写入前自检；消费方 = 后续 digest 下发/attestation 构造。**本单不实现，仅钉死边界。**

### FAIL_CLOSED_EXIT / NO_REMOTE_EXECUTION_BOUNDARY

- preflight 失败 → `RuntimeLoadError::ExportResolutionFailed` → `run_runtime_loader` Err → controller `DependencyUnavailable`/`RuntimeLoadFailed` → 无 candidate、target 终止（mod.rs:776-796, 1355-1393）。该 fail-closed 出口链已存在且被 v1 路径使用。
- 语义隔离：`V2PreflightResult` 文档注释明示 “LOCAL PREFLIGHT ≠ runtime/live PASS”（runtime_loader.rs:2806-2813），且 preflight 不读远程内存、不创建远程线程、不调用 runtime entry。local 与 live 无混淆路径——**因为 live V2 路径不存在**。

---

## 4. IMP-08 — V2 Exports / Loader 接线状态

### EXPORT_WANTED_SET（真实 vs 设计）

```text
真实 wanted（3 项）:  runtime_loader.rs:1451-1455
  [MidaAntidebugInitialize, MidaAntidebugGetAttestation, MidaAntidebugShutdown]
设计 wanted（5 项，未实现）:  WO-1505 §5.3c
  + MidaAntidebugInitializeV2 + WalkerExecute
```

### EXPORT_RESOLUTION_ENTRY / VALIDATION

- 真实解析入口：`resolve_mida_exports_remote`（L1275-1508）：远程读 PE 导出目录 → `resolve_exports_from_buffers`（L1525-1603）→ 缺失任一 → `ExportResolutionFailed`（L1495-1502）。缺失/重复/forwarded/out-of-module：forwarded 已被 exp_rva 窗口检查跳过（L1589-1598）；重复名目前**静默取首个**（L1562-1563 `if found[wi].is_some() continue`），设计（WO-1505 §5.3c）要求拒收 AmbiguousExport——**差异待下一实现单**。
- `entry_va == module_base + export_rva`：解析器返回 `module_base + func_rva`（L1599）——成立；但 v1 loader 只在初始化时使用 `exports.initialize`（L1166），`get_attestation`/`shutdown` 字段标 `#[allow(dead_code)]`（L532），`remote_shutdown`/`free_remote_allocations`（L1697/L1721）**无生产调用者**（全仓 grep 仅定义处）。
- exports 解析结果进入初始化路径：**是**（v1，L1094 → L1166）。

### REQUIRE_COMPLETE_CALLER / V2_INITIALIZATION_CALLER / ATTESTATION_CALLER

```text
require_complete()            仅测试（L2958-2977）      ⇒ 生产无 caller
MidaAntidebugInitializeV2     runtime 导出不存在        ⇒ 无初始化 caller
V2 attestation 解析            parse_attestation 仅测试  ⇒ 生产 controller 仍用 v1 from_canonical_json
  （antidebug_controller.rs:593）
```

### UNWIRED_SYMBOL 结论

```text
WANTED_EXPORTS_V2 / MidaExportsV2 / require_complete / Thunk7Fixture / THUNK7_PRODUCTION /
V2ParamsBlob / V2PreflightResult / preflight_local / surface_string / WalkerParamsV2 /
controller_* / RoundLedger / ProbeSummary / WalkerAttestation / RuntimeAttestationV2
全部 = UNWIRED（仅测试/文档引用）
```

**禁止误报**：`MidaExportsV2::require_complete()` 测试存在 ≠ exports 已接线；`THUNK7_PRODUCTION` fixture 存在 ≠ 7 参 thunk 已接线；`walker_protocol.rs` 纯离线 API ≠ Walker 生产 caller。

---

## 5. IMP-09 — Walker Production Caller 前置设计（状态机草案）

> 设计意图，**本单不实现**。禁止：WPM、CreateRemoteThread、执行 thunk、SEH/VEH live、启动 Walker runtime。状态机文档 ≠ production caller。

### 状态机（下一实现单的冻结草案）

```text
UNINITIALIZED
  -> ENTRY_VALIDATED        （controller_validate_entry 通过；WALKER wanted 解析 + allowlist 断言）
  -> SECTION_RECEIVED       （结果 section 从 target 读回，pending 允许）
  -> RESULT_VALIDATED       （controller_read_completed_section：identity/CRC/closed sets）
  -> ROUND_RECORDED         （RoundLedger 写入：round 1 -> next_round_authorized -> round 2）
  -> ATTESTATION_BUILD      （WalkerAttestation + RuntimeAttestationV2 + record_digest）
  -> ATTESTATION_VERIFIED   （nested digest 先于 top-level；binding matrix 全项）
  -> COMPLETED
所有错误路径 -> ABORTED     （abort_state 闭集：thread_hung/wait_fail/walker_abort/budget_exhausted/stop_loss；
                             orphan 记录；auto_retry 恒 false；wait-before-free）
```

### 设计要点（钉死给下一张实现单）

| 项 | 冻结边界 |
|---|---|
| caller 初始化 | 复用 `run_runtime_loader` 的 authority + 5 项 wanted；digest 需求判定（WO-1505 §5.3d 三条件） |
| round 1/2 | `RoundLedger::new(1/2)`；序列校验已实现（attestation.rs:945-957）；`next_round_authorized` 唯一来源 = round 1 退出时 ledger 字段，由 caller 显式写入并二次校验 |
| `auto_retry` | 恒 false；validate 拒收 true（attestation.rs:800-802） |
| 三道硬门 | `controller_validate_entry`（walker_protocol.rs:1523）、`controller_read_section`（1545）、`validate_section`（1421）——全部纯离线，已冻结 |
| orphan | `Orphan` 记录点 = ABORTED 路径；`Unconfirmed` 不得声称已回收（WO-1503 §7） |
| digest/abort 定点 | walker attestation 的 runtime_module_sha256 必须 == 顶层 runtime_sha256（attestation.rs:907-909）；顶层又依赖 IMP-06 真实 digest——**先决条件** |

---

## 6. IMP-10 — ImplementationFacts 最终事实矩阵（绑定源码位置）

| Fact | 当前要求 | 真值 | SOURCE_FILE:LINE_RANGE | PROOF_CLASS |
|---|---|---|---|---|
| `digest_value` | 非占位 | `adr4-foundation-unbound` | `crates/antidebug-runtime/src/exports.rs:237-239`；gate 常量 `crates/acceptance/src/implementation_gate.rs:16` | PRODUCTION_SOURCE（占位，仍阻断） |
| `has_initialize_v2` | exports/entry 实际定义 | **false**（导出不存在） | `exports.rs:181-486`（3 导出）；`runtime_loader.rs:1451-1455`（wanted 3 项） | NOT_PROVEN（负证据：rg 零命中） |
| `has_production_thunk_wired` | 生产 7 参 thunk 接线 | **false**（fixture 仅 parser/test） | `runtime_loader.rs:2301-2382`（THUNK7 + validate_structure）；`runtime_loader.rs:470-503`（仅 6 参 THUNK_CODE） | FIXTURE_ONLY |
| `has_walker_caller` | 生产 Walker caller | **false**（仅测试调用） | `walker_protocol.rs:1523-1636`（API）；调用点全部在 `crates/antidebug-runtime/tests/*` | TEST_ONLY |
| `has_v2_consumer` | 生产 V2 consumer | **false**（preflight 仅测试调用） | `runtime_loader.rs:2857-2907`；调用点 2933+ test mod | TEST_ONLY |
| `walker_dispatched` | 已 dispatch | **false** | 全仓无 walker dispatch 代码 | NOT_PROVEN |
| `live_authorized` | LIVE-4 | **false**（必须 false） | `implementation_gate.rs:56-58`（注释明示） | NOT_PROVEN |
| `windows_runtime_verified` | 真实 Windows 证据 | **false** | 无 WPM/CRT/SEH/VEH 观察证据入仓；仅 `timeout_harness` 测试（`runtime_loader.rs:2021+`） | TEST_ONLY（harness 属测试，不构成 acceptance 证据） |
| `evidence_sufficient` | 分层充分 | **false** | `implementation_gate.rs:63-64, 155-158` | NOT_PROVEN |

gate 结果（用当前事实实跑）：`readiness=ready, implemented=ready, acceptance_allowed=ready, gate=Fail` —— 与 `implementation_gate.rs:188-212` 测试固化一致。**无需、也不得修改任何事实字段**。

---

## 7. 验证记录

```text
git status --short        → 44 个未跟踪文件（全部为工作令/审计文档），零 tracked 修改
git diff --stat           → 空
git diff <HEAD> --stat    → 空
git grep caller / placeholder / preflight_local / MidaAntidebugInitializeV2 / MidaExportsV2
                          → 结果见 §1-§4（V2 相关全部仅测试/文档）
cargo check --workspace --offline  → 通过（exit 0，1 个既有 unused warning: post_attach.rs:400 dump_timing）
```

环境：Rust workspace 可离线 check；`link.exe`/rustup 未参与本单（无构建产物要求）。

---

## 8. 关闭门评估（IMP-06..IMP-10）

| 关闭门 | 状态 |
|---|---|
| 1. digest authority 唯一路径明确 | ✅ `verify_file` L201-210 + manifest/provenance 对账；V2 下发通道为冻结设计 |
| 2. placeholder 替换条件明确 | ✅ §2 PLACEHOLDER_REPLACEMENT_CONDITION（4 条，全未满足） |
| 3. preflight_local 生产调用点 | ✅ 明确：**尚不存在**（硬门 → has_v2_consumer=false） |
| 4. V2 exports/loader caller 图完整 | ✅ §3/§4（v1 图完整；V2 图=设计） |
| 5. Walker caller 状态机 + abort 闭环 | ✅ §5（设计冻结；未实现） |
| 6. ImplementationFacts 逐项绑定 | ✅ §6（全部绑定源码行 + PROOF_CLASS） |
| 7. local / preflight / live 三层无混淆 | ✅ preflight 文档 + gate 注释双保险；live 路径不存在 |
| 8. 无远程执行 | ✅ 本单零远程执行 |
| 9. 无 LIVE-4 | ✅ |
| 10. 无 inert adapter 冒充 production | ✅ 全部 V2/Walker 符号标记 UNWIRED/TEST_ONLY/FIXTURE_ONLY |

**下一张生产实现单建议顺序**（NEXT_IMPLEMENTATION_ORDER）：
1. IMP-06 实现：runtime 新增 `MidaAntidebugInitializeV2` + digest 接收/回显（含 WO-1902 golden/拒收矩阵测试）；
2. IMP-08 实现：loader wanted 5 项 + `MidaExports` 5 字段 + 解析泛化 + 7 参 thunk（THUNK7_PRODUCTION 接线）+ `require_complete` 生产调用 + digest 需求 fallback 门禁；
3. IMP-07 实现：`preflight_local` 唯一生产调用点（v2 分支写入前自检）+ out_runtime_sha256 回显校验；
4. IMP-09 实现：Walker caller（状态机 §5）+ WalkerExecute 导出 + allowlist 断言 + RoundLedger 写入；
5. 全部完成后按真实源码刷新 `ImplementationFacts`（禁止先改事实再实现）。
