# IMP-09 — Authorized Target-side WalkerExecute Dispatch Bridge (Design)

**工单**: WORK_ORDER_IMP-09-DISPATCH-BRIDGE-DESIGN_20260825.md
**性质**: 设计 + 静态审计（无 tracked 生产代码改动、无 live）
**基线**: HEAD `c33401a`（R5-R4 已入库）
**日期**: 2026-08-25
**对账基线**: `docs/IMPLEMENTATION_PHASE04A_READINESS_20260823.md`（Phase04A，基线 HEAD `c27e8e6` 树冻结 `914e73e`）

> 本文件是**设计文档**。所有 Rust 代码块均为接口草案（贴在文档内，**不落 src/**）。
> 实现卡照此设计实施；本单不改任何 `src/` 文件、不改 `runner_preflight.rs`、
> 不改 R5-R2/R5-R3/R5-R4 冻结语义、不接 live。

---

## 0. 摘要（TL;DR）

`execute_walker_production()`（`crates/cli/src/unpacker/antidebug_controller.rs:842-872`）
是 IMP-09 链最后一块生产件的**消费点**：它已经实现完整的 fail-closed 门控逻辑
（liveness 探测 → 桥接存在性 → raw status → 输出存在性 → R5-R3 V2 digest 闭包），
但桥接槽位 `options.walker_dispatch` 在生产路径恒为 `None`（`mod.rs:1227 / 790`），
因此永远停在 `WalkerExecuteOutcome::NotImplemented`（fail-closed 正确，未解锁）。

本设计定义 **AUTHORIZED target-side dispatch bridge** 的完整契约：

1. **调用面**: 目标侧入口 = V2 导出集的 `WalkerExecute(params_va: u64) -> i32`
   （已在 runtime `exports.rs:1366` 存在；loader 已按 5 项 wanted 解析，`runtime_loader.rs:2157-2163, 2247-2253`）。
2. **权威链**: 桥接的每个输入（params_va / section1_va / 双 digest / export RVA / profile）
   全部来自既有 sealed carrier（`LoaderResult` / `VerifiedTargetIdentity` /
   `VerifiedProfileIdentity` / `install_walker_session_verified` 矩阵），零 open-caller 字符串。
3. **写原语边界**: 桥接复刻 loader 的远程调用原语（thunk + CreateRemoteThread），
   按 Windows 版本可用性标注 CreateRemoteThread / NtCreateThreadEx / APC；默认推荐 CreateRemoteThread。
4. **失败语义**: 注入失败 = session 从未建立 → teardown 必须报 `Released`/空账本，
   不得伪造 `PartiallyReleased`；controller 侧已有完整 fail-closed 出口（§5）。
5. **观测性**: dispatch 每步进 walker evidence sidecar 字段（`WalkerEvidenceRecord` /
   `WalkerRawEvent` / `WalkerTeardownReport`）。
6. **LIVE 边界**: 桥接实施（`RemoteWalkerExecuteBridge` 生产实现 + mod.rs 接线）只在
   LIVE-4 授权文件批准后落地；offline 只证明"未解锁"（ImplementationFacts 保持 false）。

---

## 1. 现状锚点核对表（真实源码行号 + Phase04A 对账）

### 1.1 工单 §3.3 要求的锚点（当前 HEAD `c33401a` 实测）

| 锚点 | 位置（HEAD 实测） | 状态 |
|---|---|---|
| `execute_walker_production()` | `antidebug_controller.rs:842-872`（fn 主体 842；gate 逻辑 849-871） | ✅ 存在（R5-R2-4 冻结） |
| `WalkerExecuteOutcome` | `antidebug_controller.rs:415-430` | ✅ 存在 |
| `WalkerDispatchBridge` trait | `walker_session.rs:459-469` | ✅ 存在（typed seam，生产恒 None） |
| `options.walker_dispatch` | `antidebug_controller.rs:482-489`；生产接线 `mod.rs:1221-1227`（CREATE_PROCESS）、`mod.rs:785-790`（post-attach） | ✅ 恒 `None` |
| 远程 exports 解析（5 项 wanted） | `runtime_loader.rs:1905-2254`（`resolve_mida_exports_remote`），wanted 数组 `2157-2163`，`MidaExportsV2` 组装 `2247-2253` | ✅ 存在（IMP-08 已实现） |
| `WANTED_EXPORTS_V2` 常量 | `runtime_loader.rs:3480-3486` | ✅ 存在（5 项，含 `WalkerExecute`） |
| `MidaExportsV2::require_complete` | `runtime_loader.rs:3501-3528`；`require_v2_entry` `3531-3537` | ✅ 存在（digest-required 生产调用点 `1597-1598`） |
| `resolve_walker_export_rva_from_file`（pure-file RVA） | `runtime_loader.rs:2511-2805`；生产消费 `3219-3220` → `LoaderResult::new` | ✅ 存在 |
| `LoaderResult::walker_export_rva` sealed carrier | `antidebug_controller.rs:536-542, 592-602` | ✅ 存在 |
| `run_runtime_loader` 生产调用点 | `mod.rs:1314-1319`（CREATE_PROCESS）、`mod.rs:567`（post-attach 段） | ✅ 存在 |
| `install_walker_session_production` | `walker_session.rs:724-823` | ✅ 存在（R5-R1 冻结） |
| `install_walker_session_verified` | `crates/antidebug-runtime/src/exports.rs:1157-1187` | ✅ 存在（唯一生产 install API） |
| `WalkerDigestAuthority`（sealed） | `walker_control.rs:100-203`（`pub(crate) fn new` 130-167） | ✅ 存在 |
| `WalkerExecute` C ABI 导出 | `crates/antidebug-runtime/src/exports.rs:1366-1378`（`walker_execute_inner` 1380-1540） | ✅ 存在 |
| `MidaAntidebugInitializeV2` C ABI 导出 | `exports.rs:591-612`（`initialize_v2_inner` 614+） | ✅ **存在**（IMP-08 已落地） |
| WALKER_STATUS 常量闭集 | `walker_protocol.rs:135-140`（OK=0, BAD_PARAMS=1, MAP_FAILED=2, VEH_FAILED=3, PROBE_ABORTED=4, INTERNAL_PANIC=5） | ✅ 存在 |
| `probe_process_liveness` | `walker_session.rs:206-219` | ✅ 存在（R5-R2-1） |
| `WalkerTeardownReport` / `TeardownOutcome` | `walker_teardown.rs:377-416 / 90-112` | ✅ 存在（R5-R4） |
| `verify_v2_attestation_digest` | `walker_consumer.rs:328-350` | ✅ 存在（R5-R3） |
| `RuntimeAttestationV2` | `attestation.rs:981-1086`（`compute_digest` 1017-1022，`validate` 1028-1077，`to_canonical_json` 1079-1081） | ✅ 存在 |
| `WalkerEvidenceRecord` | `antidebug_controller.rs:392-412`；写 sidecar `1602-1614` | ✅ 存在 |
| 生产调用点（控制器 gate） | `mod.rs:1420`（CREATE_PROCESS `ad_controller.run()`）、`mod.rs:805`（post-attach） | ✅ 存在 |

### 1.2 与 Phase04A 事实基线对账

**"当时不存在、现在仍不存在"（保持 fail-closed / UNWIRED，本单不改变）**

| 项 | Phase04A 事实（2026-08-23） | HEAD `c33401a`（2026-08-25） | 证据 |
|---|---|---|---|
| 生产 authorized dispatch bridge | 不存在（`has_walker_caller=false`、`walker_dispatched=false`） | **仍不存在** — `options.walker_dispatch` 两生产路径恒 `None` | `mod.rs:1227, 790`；`walker_session.rs:455-458` 注释 |
| `THUNK7_PRODUCTION` 生产接线到 dispatch | 仅 parser/test（FIXTURE_ONLY） | **仍未接线到 dispatch**（仅 V2 init 使用 `thunk_call_v2`，`runtime_loader.rs:1203-1228, 1731-1732`） | grep 无 dispatch 侧引用 |
| 7-arg thunk → WalkerExecute | 不存在 | **仍不存在**（WalkerExecute 是 1-arg `params_va`，不是 7-arg init） | `exports.rs:1366` |
| live Windows 证据 | 无（`windows_runtime_verified=false`） | **仍无**（本单不接 live） | — |
| `live_authorized` | false（必须 false） | **仍 false** | `implementation_gate.rs:56-58` 注释；本单 LIVE_AUTHORIZED=false |

**"当时不存在、现在已存在（可直接复用）"**

| 项 | Phase04A 事实 | HEAD `c33401a` | 证据 |
|---|---|---|---|
| `MidaAntidebugInitializeV2` 导出 | 不存在（`has_initialize_v2=false`，Phase04A §4 L19） | **已存在**（IMP-08 落地，digest 通道 + echo） | `exports.rs:591-612`；`runtime_loader.rs:1597-1598, 1708-1718, 1791-1880` |
| loader 5 项 wanted 解析 | 设计（wanted 3 项实现） | **已实现**（5 项 `resolve_mida_exports_remote` + `require_complete`） | `runtime_loader.rs:2157-2163, 2247-2253, 3501-3528` |
| 纯文件 WalkerExecute RVA 解析 | 不存在 | **已实现**（`resolve_walker_export_rva_from_file`） | `runtime_loader.rs:2511-2805`；`LoaderResult` 密封 `antidebug_controller.rs:592-602` |
| digest echo 生产校验 | 无（注释 "unused by loader"） | **已实现**（`verify_runtime_echo` 生产调用） | `runtime_loader.rs:1863-1880`；`RuntimeDigestAuthority::verify_runtime_echo` 534-541 |
| `preflight_local` 生产调用点 | 不存在（TEST_ONLY） | **已存在**（digest-required 分支写入前自检） | `runtime_loader.rs:1486-1505`（`build_preflight_and_validate`） |
| walker bind/execute 生产 gate | 设计 | **已实现**（R5-R2-4 + R5-R3 digest 闭包） | `antidebug_controller.rs:842-872, 883-905`；`mod.rs:1420-1424` |
| walker evidence sidecar 生产写入 | 不存在 | **已实现** | `mod.rs:1451-1456`（create_process）、`mod.rs:818-823`（post_attach） |
| 结构化 teardown 观测 | 不存在 | **已实现**（R5-R4） | `walker_teardown.rs:377-439`；guard `antidebug_controller.rs:125-184` |

**结论**: 桥接实现卡的前置件（loader 5 项解析、纯文件 RVA、V2 初始化、walk bind/execute gate、
evidence、teardown）在 HEAD 已全部就位。唯一缺口 = 生产桥接实现 + LIVE-4 授权后接线。

---

## 2. 设计六问（逐项成文）

### Q1. 调用面 — 目标侧入口与参数 blob 布局

**目标侧入口**: V2 导出集的 `WalkerExecute`（唯一合法目标侧 walker 入口）：

```c
// runtime 导出面（已存在，exports.rs:1366）
int32_t WalkerExecute(uint64_t params_va);
```

- 单参数：`params_va` = 目标进程内 walker params blob 的 VA（canonical user VA）。
- 返回值：raw i32 walker status（`walker_protocol.rs:135-140` 闭集：
  OK=0 / BAD_PARAMS=1 / MAP_FAILED=2 / VEH_FAILED=3 / PROBE_ABORTED=4 / INTERNAL_PANIC=5）。
  非 0 一律 fail-closed（controller `antidebug_controller.rs:864-867` 已实现）。

**参数 blob 布局**（冻结协议，`WalkerParamsV2`，`walker_protocol.rs:491+`）：

```text
0x00              params_blob_total (u64)          <- blob 总字节数（含候选数组）
0x08              section_bytes   (u64)            <- 结果 section 容量（两轮）
0x10              options_flags   (u16)
0x12              probe_span      (u16)
0x14              reserved        (u32)
0x18              result_nonce    (u64)            <- CSPRNG 会话 nonce
0x20              candidate_count (u32)
0x24              reserved        (u32)
0x28              magic "WALK"    (u32)
0x2C              version         (u16)
0x2E              reserved        (u16)
0x30              header_crc32    (u32)            <- CRC32 over [0x00, 0x38)
0x38              reserved        (u8 x8)
0x40              candidates[0..candidate_count] (u64 xN)   <- 探针目标 VA
```

- **与 R5-R3 params blob 的关系**: 同一个 `WalkerParamsV2` 冻结布局。
  - `WalkerSessionMemory::write_params`（`walker_session.rs:572-625`）用
    `WalkerParamsV2::new` + `to_blob_bytes` 构造并 **先经 `controller_validate_entry`
    本地验证再 WPM**（602-609）。
  - `install_walker_session_production`（`walker_session.rs:724-823`）在**一个事务**里
    allocate(params+section) → write_params → write_section_header → 装 provider →
    `install_walker_session_verified` → READY。session_id 由
    `derive_session_id(nonce, params_va, candidate_count)` 派生（763-767）。
  - 桥接只消费 `mem.params_va()`（`walker_session.rs:675-677`），**不重新构造 blob**。
- **输出通道**: walker 完成时 runtime 在目标进程内把 `RuntimeAttestationV2`（含
  `record_digest`）写入**进程内** `WALKER_OUTPUT`（`exports.rs:1029-1030, 1526-1537`）。
  目标侧无法直接返回结构体；桥接通过 **RPM 读回结果 section**（两轮结果）+ 控制器
  侧 `verify_v2_attestation_digest` 重建/验证。设计上桥接的返回 = `(raw_status, Option<RuntimeAttestationV2>)`，
  与既有 `WalkerDispatchBridge::dispatch` 签名（`walker_session.rs:459-469`）完全一致。

**Q1 结论（接口草案 §A）**: 不改 V2 导出集（5 项已冻结，`runtime_loader.rs:3480-3486`）。
新生产桥接实现 `WalkerDispatchBridge`；入口地址 = `LoadedRuntime.exports.walker_execute`
（远程解析的 target VA，`MidaExportsV2.walker_execute`，`runtime_loader.rs:3496`）。

---

### Q2. 权威链 — target-side 执行的每个输入如何从 sealed carrier 获得

**硬约束（工单 §2.2）**: 禁止 open caller 字符串 / 魔法值；沿用
`install_walker_session_verified` 矩阵。

| 输入 | 权威来源（sealed carrier） | 代码路径 |
|---|---|---|
| `params_va` / `section1_va` | `WalkerSessionMemory`（`VirtualAllocEx` 返回，`walker_session.rs:505-565`）；经 `mem.params_va()` / `mem.section1_va()` 读取 | `bind_walker_from_loader_production` → `install_walker_session_production`（`antidebug_controller.rs:773-827`） |
| target digest | `VerifiedTargetIdentity::sha256()`（密封，无 Deserialize，`runner_preflight.rs:1200-1257`）；经 `target_image_sha256()`（`antidebug_controller.rs:1011-1013`） | bind 矩阵 `antidebug_controller.rs:709-716`（且强制 ≠ runtime digest） |
| runtime digest | `RuntimeDigestAuthority`（唯一来自 `RuntimeAuthorityManifest::verify_file`，`runtime_loader.rs:204` 单点哈希）；`LoaderResult::digest_authority()` | bind 矩阵 `antidebug_controller.rs:706, 743` |
| module_base | `LoaderResult::module_base()`（sealed ctor，`antidebug_controller.rs:588-590`） | bind 矩阵 `antidebug_controller.rs:744, 788-793` |
| WalkerExecute export RVA | `LoaderResult::walker_export_rva()`（纯文件解析 + 密封，`antidebug_controller.rs:592-602, 1041-1043`；来源 `runtime_loader.rs:3219-3220`） | bind 矩阵 `antidebug_controller.rs:724-727, 745` |
| profile_id / profile_digest | `VerifiedProfileIdentity`（同一 source object，`runner_preflight.rs:1271-1349`） | bind 矩阵 `antidebug_controller.rs:717-723, 746-747` |
| target_pid / owner_pid | debugger 注入 `target_pid`（`mod.rs:1186`）+ `std::process::id()`（controller PID，`antidebug_controller.rs:737`） | `install_walker_session_production` 参数 |
| result_nonce | `RtlGenRandom` CSPRNG（`antidebug_controller.rs:961-976`），拒绝 0 | bind `antidebug_controller.rs:823-826` |
| 候选 VA | 从 **verified module_base** 派生（base + k*0x1000, k∈0..3），限定在 verified image envelope 内；每项先 `prove_candidate_mappings`（`walker_session.rs:299-445`） | `antidebug_controller.rs:788-822` |

**权威链图（全部 sealed，无字符串）：**

```text
RuntimeAuthorityManifest::verify_file (runtime_loader.rs:181-219, 哈希 L204)
  → RuntimeFileIdentity (sealed)                      runtime_loader.rs
  → RuntimeDigestAuthority::from_verified_identity    runtime_loader.rs
  → LoaderResult::new (sealed ctor)                   antidebug_controller.rs:549-565
  → AntidebugController::bind_walker_from_loader      antidebug_controller.rs:694-756
  → install_walker_session_production                 walker_session.rs:724-823
  → install_walker_session_verified                   exports.rs:1157-1187
  → WalkerDigestAuthority::new (pub(crate))           walker_control.rs:130-167
  → WalkerSessionBinding (sealed)                     exports.rs:920-957

VerifiedTargetIdentity::from_attested                 runner_preflight.rs:1213-1236  --┐
VerifiedProfileIdentity::from_verified_profile        runner_preflight.rs:1286-1328  --┤→ bind 矩阵
resolve_walker_export_rva_from_file (pure-file)       runtime_loader.rs:2511-2805    --┘
```

**桥接新增的输入面（唯一新增的"外部输入"）**: 远程线程入口地址。它**不是** open
caller 字符串，而是两个 sealed 来源的交集：

- 纯文件侧: `resolve_walker_export_rva_from_file`（`runtime_loader.rs:2511-2805`，
  对 verified runtime 文件字节重算 size+sha256 后解析，拒绝 forwarded/out-of-module/重复名）；
- 目标侧: `resolve_mida_exports_remote`（`runtime_loader.rs:1905-2254`，对**已加载模块**
  的导出目录做同规则解析，返回 target VA = module_base + RVA）。

桥接生产实现必须**两者交叉校验**: `remote_va == module_base + file_rva`（checked add，
`WalkerDigestAuthority::new` 已含 `module_base + walker_export_rva` 溢出检查，
`walker_control.rs:149-153`）。任何一侧缺失/不一致 → 不创建桥（fail-closed）。

**入口地址的携带**: 桥接构造参数来自 `LoaderResult`（密封）：
`(target_handle, target_pid, module_base, walker_export_rva, walker_execute_remote_va)`。
其中 `walker_execute_remote_va` 由 `LoadedRuntime.exports.walker_execute`（`MidaExportsV2`，
`runtime_loader.rs:3496`）提供 —— 该结构由 `resolve_mida_exports_remote` 唯一产生，
且 `require_complete()` 强制 5 项齐全（`runtime_loader.rs:3501-3528`）。

---

### Q3. 写原语边界 — 注入机制对比与默认推荐

桥接的"写"分为两类：
1. **会话建立**（已实现，R5-R1/R5-R2 冻结）：`VirtualAllocEx` + `WriteProcessMemory` +
   `VirtualQueryEx` 映射证明。**本设计不改**。
2. **dispatch 注入**（本设计新增）：把 1-arg thunk 注入目标并等待完成，读取
   `(raw_status, section 两轮结果)`。

注入机制对比（每个标注 Windows 版本可用性与检测面）：

| 机制 | Windows 版本可用性 | 检测面 / 目标侧可见性 | 现有仓库先例 |
|---|---|---|---|
| **CreateRemoteThread + 1-arg thunk**（默认推荐） | Vista+（全系 x64） | 目标侧可经 PEB/ETW/内核回调观察到新线程；受 `CreateRemoteThread` 挂钩影响 | **仓库生产路径已用**（`runtime_loader.rs:923, 1073`；`remote_call_raw_bounded` 909-1043） |
| NtCreateThreadEx（ntdll 直呼） | Vista+；`NtCreateThreadEx` 是 ntdll 导出，全系 | 与 CRT 同源（最终同一 syscall `NtCreateThread`），但可绕过 kernel32 层挂钩；`ntdll` 钩子仍可见 | 仓库无先例（需新增地址解析）；检测面与 CRT 本质相同，收益有限 |
| APC（QueueUserAPC / NtQueueApcThread） | Vista+；需目标线程处于 alertable wait，**不能保证执行窗口** | 异步、无独立线程创建痕迹；但执行时机不可控 → 无法满足"bind/execute 必须在 provably-alive 窗口内完成"的 R5-R2-1 要求 | 仓库无先例；语义不匹配本场景 |
| 手动映射 + 线程劫持（SetThreadContext） | XP+ | 检测面最大；需要暂停/恢复目标线程，与 debug 事件窗口交互复杂 | 仓库无先例；超出本单范围（IMPL 卡不做） |

**默认推荐: CreateRemoteThread + 冻结 1-arg thunk（THUNK_WALKER）**，理由：

1. **仓库已有同族生产原语**：`thunk_call_tracked_with_handle_code`（`runtime_loader.rs:1288-1403`）
   已实现 allocate(RW) → WPM(thunk+args) → VirtualProtectEx(RX) → CreateRemoteThread →
   单调时钟 deadline wait + drain → 超时保留分配/不释放 的完整契约（ADR-5B-R3）。
   桥接复刻该模式，风险面最小。
2. **1-arg ABI 最简**：`WalkerExecute(params_va)` 只需要 `rcx = params_va`。
   可直接 `CreateRemoteThread(entry, params_va)`（入口即 C ABI `extern "C" fn(u64)->i32`，
   x64 调用约定单参在 rcx），**甚至不需要 thunk 参数块** —— 但为与既有
   thunk 内存生命周期管理（超时保留、成功释放）一致，仍建议走统一的
   thunk 分配路径（见接口草案 §B `dispatch_thunk`），便于 evidence 记录。
3. **deadline 语义已冻结**：`remote_call_raw_bounded`（`runtime_loader.rs:909-1043`）
   的单调时钟 + drain 轮询 + 超时不释放 thunk 的契约，是 walker 在 debug 会话中
   执行的硬要求（CreateProcess 事件冻结目标 → 必须 drain）。
4. APC 的执行时机不可控，**违反 R5-R2-1 的 alive-window 证明**（bind/execute 必须在
   `terminate_and_wait()` 之前完成且可观测），故不推荐。

**写原语边界（冻结声明）**:
- 桥接**只写**：thunk 代码页（RX）+ 可选 args 块（同页）+ 结果 section 读回（RPM，只读）；
- **不写**：params blob（已由 R5-R1 会话写入）、不注入 DLL、不修改目标代码/数据段；
- 释放：dispatch 成功后 `VirtualFreeEx(thunk)`；超时/失败**保留**（线程可能仍在执行，
  `runtime_loader.rs:1391-1398` 既有契约），随目标进程退出回收。

---

### Q4. 失败语义 — 注入失败 fail-closed + TeardownOutcome 交互

**注入失败 → session 从未建立 → teardown 必须报 `Released`/空账本，不得伪造 `PartiallyReleased`。**

既有机制已保证这一点（R5-R4 冻结，`walker_teardown.rs`）：

1. `WalkerTeardownReport::no_session()`（`walker_teardown.rs:402-410`）：
   `outcome = Released`、`events = []`、`ledger_empty = true`。语义 = "没有分配需要释放"。
2. RAII guard（`antidebug_controller.rs:125-184`）：`mem_ptr` 为 `None`（从未 install）
   → `no_session()` 报告。这是**每个** run() 出口路径（含 unwind）的兜底（T5）。
3. 账本只登记**已分配**的 VA（`teardown_walker_session_report`，
   `walker_teardown.rs:425-439`）；`VirtualAllocEx` 失败 → `allocate` 回滚双释放
   （`walker_session.rs:537-557`）→ `install_walker_session_production` 返回 None →
   controller `walker_mem = None` → guard 走 no_session。

**时序表（注入失败 vs teardown）**：

| 阶段 | 注入失败点 | walker_mem | teardown 报告 |
|---|---|---|---|
| `VirtualAllocEx(params)` 失败 | allocate 内（`walker_session.rs:537-540`） | None | `Released` + 空账本（no_session） |
| `VirtualAllocEx(section)` 失败 | allocate 内（`550-553`） | None（先回滚 params） | `Released` + 空账本 |
| `write_params` / `write_section_header` 失败 | install 内（`walker_session.rs:768-796`） | None（cleanup 双释放） | `Released` + 空账本 |
| 映射证明失败（`prove_candidate_mappings`） | bind 前（`antidebug_controller.rs:818-822`） | None（从未 allocate） | `Released` + 空账本 |
| liveness 非 Alive | bind 前（`antidebug_controller.rs:783-787`） | None | `Released` + 空账本 |
| `install_walker_session_verified` 失败 | install 内（`walker_session.rs:804-820`） | None | `Released` + 空账本 |
| **dispatch 注入失败（新）** | 桥接 dispatch 返回 Err（§B） | **Some（session 已 READY）** | **`Released` + 2 个成功 free 事件（正常释放 params+section）** |

**关键区分**:
- **会话未建立**（上面 1-6）→ teardown `Released`/空账本（`no_session`），
  因为**没有任何远程分配存在** —— 报 `PartiallyReleased` 是伪造（有失败步骤才允许）。
- **会话已建立、dispatch 失败**（第 7 行）→ session 内存**照常释放**，teardown 是
  正常 `Released`（2 事件）。dispatch 失败不改变 teardown 账本；teardown 失败
  也不改变 dispatch 结果（T1 分离，`walker_teardown.rs:23-29`）。
- 控制器侧的 fail-closed 出口已实现：dispatch 非 OK → `WalkerExecuteOutcome::NonOk` →
  `FailCode::ProbeInconsistent`（`antidebug_controller.rs:1459-1467`）；注入失败 →
  `NotImplemented` → `AntiDebugRuntimeUnavailable`（1450-1458）→ Proceed 阻断，
  证据 sidecar 完整（`failure_evidence` 1520-1592 携带 walker_events + teardown report）。

**新事件（建议，见 §5 观测性）**: 注入失败应记录 `execute_enter` 的 detail =
`"dispatch_failed: <win32>"`，`execute_exit` raw = None；与"桥接不存在"
（detail="NotImplemented"）区分 —— 两者都 fail-closed，但 evidence 可区分
"未授权" vs "授权后注入执行失败"。

---

### Q5. 观测性 — dispatch 每步进 walker evidence sidecar 的哪些字段

现有 sidecar 结构（`WalkerEvidenceRecord`，`antidebug_controller.rs:392-412`；
`WalkerRawEvent` 378-384；`WalkerTeardownReport` `walker_teardown.rs:377-387`）：

| sidecar 字段 | 类型 | dispatch 各步写入 |
|---|---|---|
| `events[].phase` | String | 既有序列 `loader_complete → bind_enter → bind_exit → execute_enter → execute_exit → terminate_enter`（`mod.rs:1444-1450` 注释固化）。**桥接新增建议**：`execute_enter` detail 记录 `bridge=remote thunk entry=<va>`；`execute_exit` 记录 `outcome=... raw=<i32>`（已有逻辑 `antidebug_controller.rs:1403-1423`） |
| `events[].walker_status_raw` | Option\<i32\> | 目标侧返回值原样（R5-R2-4，`antidebug_controller.rs:1409-1415`）；桥接注入失败时 = None + detail 标记 |
| `execute_liveness` | Option\<String\> | EXECUTE 窗口 GetExitCodeProcess 探测（`antidebug_controller.rs:851-858`；`LivenessProbe::as_str` `walker_session.rs:191-198`） |
| `candidate_mapping` | Option\<CandidateMappingProofSet\> | bind 前逐候选证明（`walker_session.rs:261-268, 424-445`）；`all_passed` 为 gate |
| `teardown` | Option\<WalkerTeardownReport\> | R5-R4：outcome + 每个 VirtualFreeEx 事件（seq/addr/size/type/ok/last_error）+ double-free 拒绝 + ledger_empty（`walker_teardown.rs:377-399`） |
| `liveness_probe` | Option\<String\> | BIND 窗口探测（`antidebug_controller.rs:783-784`） |
| `target_pid` / `capture_phase` | 基础 | 记录哪个生产路径（`create_process` / `post_attach`，`mod.rs:1452, 819`） |

**桥接新增观测字段（设计草案，实现卡落地）**:

```rust
/// 桥接 dispatch 的一次执行的观测记录（挂在 WalkerEvidenceRecord 新可选字段）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalkerDispatchObservation {
    pub bridge_kind: String,          // "remote-thunk-create-remote-thread"
    pub entry_va: u64,                // module_base + walker_export_rva（checked）
    pub params_va: u64,               // 会话 params VA（mem.params_va()）
    pub section1_va: u64,             // 会话 section1 VA
    pub thunk_alloc_va: u64,          // VirtualAllocEx(thunk) 结果（0 = 未分配）
    pub thread_created: bool,         // CreateRemoteThread ok
    pub wait_outcome: String,         // "finished" | "timeout" | "abandoned" | "wait_failed" | "not-started"
    pub exit_code_raw: Option<i32>,   // GetExitCodeThread（= walker raw status）
    pub section_read_ok: bool,        // 两轮 section RPM 读回是否成功
    pub round1_done: bool,
    pub round2_done: bool,
    pub win32_last_error: Option<u32>, // 注入失败时的 GetLastError（0 = none）
}
```

写入时机：`execute_enter` 前建 observation，`execute_exit` 后填充并挂到
`WalkerEvidenceRecord`（新增 `Option<WalkerDispatchObservation>` 字段，向后兼容 ——
旧记录该字段为 None）。写入位置沿用 `write_walker_evidence`（`antidebug_controller.rs:1602-1614`，
原子 tmp+rename）。

**不变量**: observation 只是观测，**不是 gate**。gate 仍由 raw status + R5-R3
digest 闭包承担（`antidebug_controller.rs:864-871, 883-905`）。

---

### Q6. LIVE 边界 — 哪些行为只在 live 授权后发生，offline 如何证明未解锁

**live 专属行为（仅 LIVE-4 授权文件批准后发生）**:

| 行为 | 触发点 | offline 表现 |
|---|---|---|
| 生产桥接构造 + `options.walker_dispatch = Some(...)` | `mod.rs:1227 / 790` 改为注入生产桥接（仅授权后） | 恒 `None` → `NotImplemented`（`antidebug_controller.rs:860-863`） |
| CreateRemoteThread 注入目标 | 桥接 `dispatch()` | 不存在 → 无远程线程 |
| 目标侧 `WalkerExecute` 执行 | 桥接入口调用 | 不执行 |
| 两轮结果 section RPM 读回 | 桥接 `dispatch()` | 不读 |

**offline 证明未解锁（可机器复验）**:

1. `ImplementationFacts`（`crates/acceptance/src/implementation_gate.rs`）关键事实保持：
   - `walker_dispatched = false`（全仓无 dispatch 生产调用）；
   - `live_authorized = false`（`implementation_gate.rs:56-58` 注释 + gate 结果固化 `188-212`）；
   - `has_walker_caller = false` / `has_production_thunk_wired = false`（桥接未接线）。
   本单**不改**这些事实（Phase04A §6 结论：gate=Fail 是当前正确状态）。
2. grep 证据：`walker_dispatch:` 生产两处接线均为 `None`（`mod.rs:1227, 790`）。
3. 本单 `LIVE_AUTHORIZED = false`（出口门）。
4. 离线测试矩阵（§5）覆盖：未授权时拒绝（无桥接 → NotImplemented → Proceed 阻断）、
   注入失败、digest mismatch —— 全部在测试进程内完成，不碰 live 目标。
5. **唯一合法解锁条件**（本设计钉死）：owner 授权文件批准 LIVE-4 后，实现卡
   （1）实现 `RemoteWalkerExecuteBridge`；（2）`mod.rs` 两处接线点从 `None`
   改为注入；（3）重跑全部离线矩阵 + live smoke 记录；（4）按真实行为刷新
   `ImplementationFacts`（禁止先改事实再实现）。

---

## 3. Caller Graph（现 NotImplemented 点 → 新桥 → target 入口）

```text
CREATE_PROCESS handler  mod.rs:1183-1492
  └─ AntidebugController::run()            antidebug_controller.rs:1219-1497
       ├─ resolve_dependency()             1167-1197
       ├─ loader_result 注入                797-798 (post_attach) / 1321-1322 (create_process)
       ├─ bind_walker_from_loader_production()  773-827
       │    └─ install_walker_session_production  walker_session.rs:724-823
       │         └─ install_walker_session_verified exports.rs:1157-1187  (READY)
       ├─ record execute_enter              1403-1407
       ├─ execute_walker_production()       842-872        ◄── 现 NotImplemented 点
       │    ├─ probe_process_liveness       851-858
       │    ├─ [桥接槽位] options.walker_dispatch       ◄── 生产恒 None（mod.rs:1227/790）
       │    │     └─ NEW: RemoteWalkerExecuteBridge::dispatch(params_va)
       │    │          ├─ alloc thunk 页 (VirtualAllocEx RW)      [§A]
       │    │          ├─ WPM(THUNK_WALKER + args)               [§A]
       │    │          ├─ VirtualProtectEx RX                     [§A]
       │    │          ├─ CreateRemoteThread(entry, params_va)    [§A]  ──► target: exports.rs:1366 WalkerExecute
       │    │          │     └─ walker_execute_inner 1380-1540（协议驱动，输出进 WALKER_OUTPUT）
       │    │          ├─ bounded wait + drain                     [§A]
       │    │          ├─ GetExitCodeThread → raw status           [§A]
       │    │          └─ RPM 读回两轮 section（round1/round2）      [§A]
       │    └─ raw status 门 + 输出存在性门     864-871
       ├─ verify_walker_output_v2()         883-905   (R5-R3 digest 闭包)
       ├─ record execute_exit               1416-1423
       ├─ ProceedApproved / Failed          1431-1496
       └─ [RAII guard] WalkerTeardownGuard  125-184  → teardown_walker_session_report
post-attach handler  mod.rs:756-843（同构，capture_phase="post_attach"）
```

**入口地址来源**（双 sealed 交叉）:

```text
LoadedRuntime.exports.walker_execute (target VA)   runtime_loader.rs:2247-2253 (MidaExportsV2)
  ↑ resolve_mida_exports_remote                     runtime_loader.rs:1905-2254
LoaderResult.walker_export_rva (pure RVA)           antidebug_controller.rs:592-602
  ↑ resolve_walker_export_rva_from_file             runtime_loader.rs:2511-2805
cross-check: target_va == module_base + file_rva    (checked; WalkerDigestAuthority::new 已有溢出门)
```

---

## 4. 接口草案（文档内，不落 src/）

### §A. 生产桥接实现（实现 `WalkerDispatchBridge`）

```rust
// 文件建议: crates/cli/src/unpacker/walker_dispatch.rs（新文件，实现卡落）
//
// 构造仅接受 sealed 来源：
//   - target_handle / target_pid : debugger 注入（mod.rs 既有 options.target_handle）
//   - entry_va                   : LoadedRuntime.exports.walker_execute（远程解析）
//   - walker_export_rva          : LoaderResult::walker_export_rva（纯文件解析）
//   - module_base                : LoaderResult::module_base
// 构造时交叉校验 entry_va == module_base.checked_add(walker_export_rva)，
// 任一缺失/不一致 → None（fail-closed）。

pub struct RemoteWalkerExecuteBridge {
    target: windows::Win32::Foundation::HANDLE,
    target_pid: u32,
    entry_va: u64,
    /// 会话内存所有者（只借用于读取 params_va / section1_va；不持有所有权）。
    session: std::sync::Arc<WalkerSessionMemory>,
}

impl RemoteWalkerExecuteBridge {
    /// 仅 sealed 输入；交叉校验失败返回 None。
    pub fn new(
        target: HANDLE,
        target_pid: u32,
        module_base: u64,
        walker_export_rva: u64,
        remote_entry_va: u64,
        session: std::sync::Arc<WalkerSessionMemory>,
    ) -> Option<Self> {
        let entry = module_base.checked_add(walker_export_rva)?;
        if entry != remote_entry_va {
            return None; // 双解析不一致 → 拒绝（fail-closed）
        }
        if !mida_antidebug_runtime::walker_protocol::is_canonical_user_va(entry) {
            return None;
        }
        Some(Self { target, target_pid, entry_va: entry, session })
    }
}

impl WalkerDispatchBridge for RemoteWalkerExecuteBridge {
    fn dispatch(
        &self,
        params_va: u64,
    ) -> (
        i32,
        Option<mida_antidebug_runtime::attestation::RuntimeAttestationV2>,
    ) {
        // 1. 只接受本会话的 params_va（binding.params_va 语义，exports.rs:1402-1405）。
        // 2. thunk 注入 + 有界等待（deadline + drain，复刻 remote_call_raw_bounded 契约）。
        // 3. raw status = GetExitCodeThread。
        // 4. status == OK 时 RPM 读回两轮结果 section，
        //    用 controller_read_section / validate_section 重建并构造
        //    RuntimeAttestationV2（record_digest 由 R5-R3 消费门验证）。
        // 5. 任何失败 → (raw, None)；注入失败本身 → 哨兵值（实现卡定：
        //    WALKER_STATUS_ERROR_INTERNAL_PANIC(5) 或新增协议常量），
        //    但 controller 侧必须能区分"注入失败"（detail 标记）与
        //    "目标执行返回 5"。
        todo!() // 实现卡落地；本单只定契约
    }
}
```

> **契约钉死**：桥接**永不伪造成功** —— 只有远程线程真正结束、raw status==0、
> 两轮 section 读回 + 校验通过、输出 attestation 可序列化，才返回
> `(0, Some(att))`。其余全部 `(raw, None)` 或注入失败哨兵 + `None`。

### §B. dispatch thunk（1-arg，冻结字节草案）

```rust
// THUNK_WALKER: 1-arg x64 thunk —— rcx = params_va 已就绪（CreateRemoteThread
// 的 lpParameter 直接进 rcx），thunk 只需 call 入口再 ret。
// 与 THUNK7_PRODUCTION 同族（runtime_loader.rs:3551-3568），但无 7-arg 搬运。
pub const THUNK_WALKER: [u8; 8] = [
    0xFF, 0xD0,             // 0000 call rax        （rax = entry_va，由 args 块装载）
    0x48, 0x83, 0xC4, 0x00, // 0002 add rsp, 0      （占位；实际按帧对齐调整）
    0xC3,                   // 0006 ret
];
// 注: 更简单且与既有 loader 一致的做法是 CreateRemoteThread 直接以
// entry_va 为线程入口、lpParameter = params_va（x64 C ABI 单参即 rcx），
// 无需 thunk 页；但统一走 thunk 路径可复用既有"超时保留/成功释放"内存
// 生命周期 + evidence 记录。实现卡二选一并在文档固化（推荐 thunk 路径）。
```

### §C. 观测记录接入（§Q5 的字段挂到 sidecar）

```rust
// WalkerEvidenceRecord 新增字段（向后兼容，None = 旧记录/无桥接）:
pub struct WalkerEvidenceRecord {
    // ...既有字段...
    pub dispatch: Option<WalkerDispatchObservation>, // 见 §Q5
}
```

### §D. controller 侧接线（IMP-09-DISPATCH-WIRING：wired behind env gate）

**接线现状（2026-08-26 实测）**: 由 `WORK_ORDER_IMP-09-DISPATCH-WIRING_20260826.md` 实施，两处生产构造点（`crates/cli/src/unpacker/mod.rs` CREATE_PROCESS ~L1228 / post-attach ~L791）已从恒 `None` 改为经集中式门控函数接线。

```rust
// mod.rs:1227 / 790 两处，从:
walker_dispatch: None,
// 改为（授权后）:
walker_dispatch: {
    let session = ad_controller.walker_session_arc()?; // 新增访问器：Arc<WalkerSessionMemory>
    let exports = loader_result.exports();              // LoadedRuntime::exports（MidaExportsV2）
    RemoteWalkerExecuteBridge::new(
        dbg.process_handle(),
        pid,
        loader_result.module_base(),
        loader_result.walker_export_rva()?,
        exports.walker_execute?,
        session,
    )
    .map(|b| Box::new(b) as Box<dyn WalkerDispatchBridge>)
},
// 注意: 桥接需要持有 session 的 Arc —— 现有 WalkerSessionMemory 生命周期
// 在 controller 内（walker_mem 字段）；实现卡需将 walker_mem 改为
// Arc<WalkerSessionMemory> 或桥接在 bind 成功后构造并持有 clone。
// 该改动属实现卡范围，本单只钉死契约。
```

**门控语义（IMP-09-DISPATCH-WIRING 实测）**:

- 集中式门控 `walker_dispatch::live_dispatch_gate()`：仅当
  `MIDA_GTO_NO_BYPASS == "1"` **且** `MIDA_GTO_LIVE_DISPATCH == "1"` 才返回
  true；任一缺失/其他值 -> false（fail-closed）。`MIDA_GTO_LIVE_AUTHORIZED`
  已废弃（历史名，从未有读取点），不再使用。
- 接线点写法（两处同款）：
  `walker_dispatch: walker_dispatch::try_build_live_dispatch_bridge_boxed(`
  `dbg.process_handle(), loader_outcome.as_ref().ok(), exports)`；
  gate 关 -> `None`（offline 默认，与基线字节级等价，控制器仍走
  NOT_IMPLEMENTED fail-closed 分支）；
  gate 开 + 双 sealed 载体完整 -> `Some(WalkerDispatchBridgeImpl)`（构造经
  `WalkerDispatchBridgeImpl::new` 双 sealed 交叉校验；dispatch 时
  `remote_va == module_base + file_rva` 不一致 -> BAD_PARAMS，门开也不能
  跳过权威链）；
  gate 开 + 任一载体缺失 -> `None`（fail-closed）。
- **WIRING-2（2026-08-26，commit 645459c 之上）— 缺口 closed**: 由
  `WORK_ORDER_IMP-09-DISPATCH-WIRING-2_20260826.md` 补全载体通道：
  `LoaderResult` 增加密封字段 `walker_exports: Option<MidaExportsV2>`
  + `pub fn walker_exports() -> Option<&MidaExportsV2>` accessor；
  `run_runtime_loader` 尾部在 `load_and_initialize` 成功（`require_complete`
  已通过）后将 `Some(loaded.exports)` 写入该字段随 `LoaderResult` 返回；
  mod.rs post-attach 构造点把 `exports` 参数从 `None` 改为
  `loader_outcome.as_ref().ok().and_then(|l| l.walker_exports())`——
  通道可达、运行期该处可真正构造桥。
  T17（载体一致）+ T18（门开消费通道）验证：
  - T17: 走 pub(crate) sealed ctor 构造带 `walker_exports` 的 `LoaderResult`，
    验证 `walker_execute == module_base + file_rva`（双 sealed 交叉一致），
    且未带通道的 bare `LoaderResult` 仍为 `None`（fail-closed）；
  - T18: gate 开 + 通道载体完整 -> `try_build_live_dispatch_bridge_boxed`
    返回 `Some(bridge)` 且 `cross_check` 通过；通道缺失/loader 缺失 ->
    `None`。
  **CREATE_PROCESS 构造点仍然 `None`**：该构造点在 runtime loader 运行**之前**
  完成，loader_result 此刻尚不可及；按"缺载体保持 None + 报告说明"护栏，
  该处保持 `None`（fail-closed）；如需该处也接入 WIRING-2 通道需引入
  `AntidebugController` 的 deferred/rebuild seam（属新工单，本单不实施）。
  R5-R2/R3/R4 冻结语义、`runner_preflight.rs`、桥与门控语义均未触碰。

---

## 5. 测试计划（实现卡离线测试矩阵）

| # | 用例 | 期望 | 关联冻结语义 |
|---|---|---|---|
| T1 | 无桥接（生产现状） | `execute_exit` outcome=NotImplemented，raw=None，Proceed 阻断，fail_code=AntiDebugRuntimeUnavailable | R5-R2-4（已有测试 `imp09_r5r2_no_bridge_records_not_implemented_raw`，`antidebug_controller.rs:2874-2886`） |
| T2 | 桥接构造: entry_va ≠ module_base+rva | `new()` 返回 None（fail-closed） | 本设计 §A |
| T3 | 桥接构造: 任一 sealed 输入缺失 | None | 本设计 §A |
| T4 | dispatch 注入失败（mock 远程调用层返回 win32 错误） | `(哨兵, None)`；controller 记 detail=`dispatch_failed`；Proceed 阻断；teardown = `Released` + 2 事件（会话内存正常释放） | R5-R4 T1 分离 |
| T5 | dispatch 超时（deadline 到期，线程未完成） | 不释放 thunk；返回失败；evidence 记 wait_outcome=timeout | ADR-5B-R3（loader 既有契约） |
| T6 | raw status = 2（MAP_FAILED） | `NonOk{2}`；Proceed 阻断；fail_code=ProbeInconsistent；raw=2 入 evidence | R5-R2-4（已有 `imp09_r5r2_execute_gate_non_ok_status_blocks_proceed`，2831-2852） |
| T7 | status OK 但 section 读回失败 | OutputMissing；Proceed 阻断 | R5-R2-4（已有 2854-2872） |
| T8 | status OK + section OK 但 V2 digest 不闭包 | R5-R3 digest 门阻断；`output_verify_fail` 事件 | R5-R3（已有 tampered_digest 路径 2727-2729） |
| T9 | 会话未建立时 teardown | `Released` + 空账本（no_session），**绝无 PartiallyReleased** | R5-R4（已有 `r5r4_teardown_walker_allocations_with_none_is_released`，`walker_teardown.rs:776-781`） |
| T10 | 未授权时拒绝（LIVE 边界） | 生产接线仍为 None；`walker_dispatched=false`；ImplementationFacts gate=Fail | Phase04A §6 |
| T11 | 双轮 section 读回 + 校验 | round1/round2 DONE 标志、identity/nonce/session_id 匹配 | `walker_protocol.rs:1542-1615` |
| T12 | 观测记录 roundtrip | `WalkerDispatchObservation` 序列化/反序列化稳定 | §Q5 |

---

## 6. 附带轻量任务结果（工单 §4）

### 6.1 ADR7 Oreans 门复验（17/17）

工具: `tools/verify_adr7_closeout.ps1`（只读，`-EvidenceRoot D:\MidaVault\lab\evidence`）。
**raw 输出（17 项 check，0 warnings，RESULT: PASS）**:

```text
[check] B4 seal entries vs disk (115 entries)
[check] B4 final manifest hash matches seal.final_manifest_sha256
[check] B4 final -> root manifest hash OK
[check] B4 root covers (9)
[check] B5 seal entries vs disk (87 entries)
[check] B5 final manifest hash matches seal.final_manifest_sha256
[check] B5 final -> root manifest hash OK
[check] B5 root covers (10)
[check] B4 report hash OK
[check] B5 report hash OK
[check] B5 formal sign-off hash OK
[check] B5 target semantic summary (6 attempts)
[check] B5 benign control semantic summary (3 attempts)
[check] B5 debugger control semantic summary (3 attempts)
[check] B4 passive target semantic summary (6 attempts)
[check] no protected sample copies (0 stray exe)
[check] helper provenance (B4 + B5, 6 binaries)

checks run:   17
warnings:     0
RESULT: PASS
```

→ **ADR7_REGRESSION = 17/17**（与历史各期报告一致，`docs/GTO_AUDIT_CORRECTION_2026-08-21.md:43` 等）。

### 6.2 GTO preflight resolver dry-run（只读）

工具: `tools/resolve_gto_source_revision.ps1`（包装 `tools/_resolve_gto_source_revision.py`）。
参数: `-ManifestPath lab/cases/v2/gto_launcher.json -VaultRoot D:\MidaVault\vault
-EvidenceDir <temp scratch> -CaseId gto_launcher`（未给 `-SourcePath` / `-ForceAcquire`，
纯 authorized_vault 只读路径：只 rehash vault 对象 + 校验 manifest，不执行样本、不读可变定位器）。
**结果**: exit 0，`revision_match = true`（关键字段）:

```json
{
  "case_id": "gto_launcher",
  "manifest_revision": 2,
  "manifest_sha256": "fc57928adad3e55999f149f5e327070ad2ba95e1e73f884d105150b52c7fd411",
  "resolution_mode": "authorized_vault",
  "observed_sha256": "11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86",
  "observed_size_bytes": 24636416,
  "resolved_vault_path": "D:\\MidaVault\\vault\\sha256\\11\\11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86\\artifact.exe",
  "revision_match": true,
  "vault_object_verified": true,
  "resolution_status": "ResolvedAuthorizedRevision"
}
```

→ **GTO_PREFLIGHT_DRYRUN = MATCH**（无 mismatch，不需 STOP）。scratch evidence 已删除；
vault / manifest / 仓库零写入（resolver 的 `_finalize_record` 只写 EvidenceDir = temp）。

---

## 7. 出口门实测

```ini
DISPATCH_BRIDGE_DESIGN = DELIVERED
AUTHORITY_MATRIX_COMPLETE = true
OFFLINE_LIVE_BOUNDARY_DEFINED = true
ADR7_REGRESSION = 17/17
GTO_PREFLIGHT_DRYRUN = MATCH
NO_PRODUCTION_CODE_CHANGED = true
LIVE_AUTHORIZED = false
```

**核验**:
- `git rev-parse HEAD` = `c33401a3e49a3dd50e9874846cb1bfdcd908fe15`（与工单基线一致）；
- `git status --short` tracked 修改 = **零**（仅本单新增的未跟踪文档 + 既有未跟踪文档/工单）；
- `git diff --stat` = 空；
- 未改 `runner_preflight.rs`；未改 R5-R2/R5-R3/R5-R4 冻结语义；未接 live；
  未执行任何样本（GTO resolver 只读 rehash，ADR7 verifier 只读校验证据封存）。

**Correction 上限 = 1**；证据从简（本文档 + §6 raw 输出）。
