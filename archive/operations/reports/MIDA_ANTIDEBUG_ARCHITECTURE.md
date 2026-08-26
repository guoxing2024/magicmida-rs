# MIDA-ADR 架构文档（MIDA AntiDebug Compatibility Runtime）

> **工作令：** MIDA-ADR-0 —— 建立自研 anti-debug runtime 的第三方依赖边界与 clean-room 规范。
> **状态：** 设计定稿（文档阶段）。本阶段不执行样本、不实现 hook、不复制 ScyllaHide 源码或二进制。
> **基线：** `4fe2cc350378faf8a1408dadb0caf5c30fd20786`（当前 HEAD，P9 工作流封存后基线）。
> **前置条件：** T5-C 已关闭（仓库内无活动引用，grep `T5-C|T5C|T5_C` = 0 命中）。

## 0. 本文件的范围

本文档是 MIDA-ADR（MIDA AntiDebug Compatibility Runtime）的顶层架构说明。它回答：

1. MIDA-ADR 是什么、不是什么；
2. 为什么现有 `ScyllaHide` 集成必须被替换，以及替换的边界；
3. 分层覆盖（L0–L6）如何组织；
4. 施工顺序（MIDA-ADR-0 到 MIDA-ADR-8）如何推进；
5. 与既有 T5 / P9 / GTO 工作流的接口与所有权关系。

配套文档：

| 文档 | 内容 |
|---|---|
| [MIDA_ANTIDEBUG_ARCHITECTURE.md](MIDA_ANTIDEBUG_ARCHITECTURE.md) | 本文件：架构、分层、施工顺序 |
| [MIDA_ANTIDEBUG_CLEAN_ROOM_RULES.md](MIDA_ANTIDEBUG_CLEAN_ROOM_RULES.md) | clean-room 角色分离、provenance 字段、禁止项 |
| [MIDA_ANTIDEBUG_EVIDENCE_CONTRACT.md](MIDA_ANTIDEBUG_EVIDENCE_CONTRACT.md) | 证据 schema、attestation 契约、fail-closed 决策规则 |

## 1. 定位与命名

- **项目名：** MIDA AntiDebug Compatibility Runtime，简称 **MIDA-ADR**。
- **目标：** 对目标样本**实际使用的** anti-debug surface，提供**可验证、最小化、profile-driven** 的兼容行为；任何注入或 hook 不完整都**自动失败（fail closed）**。
- **非目标：** 全局绕过所有保护、内核/hypervisor 隐藏（L6 明确暂不实现）、把 ScyllaHide 行为逐字节复制。

MIDA-ADR 不是“更隐蔽的 ScyllaHide”。它是一个**带 attestation 的兼容层**：每个观察面（observation surface）的虚拟化结果都必须是**多源一致**的，并且 runtime 缺失、身份不符、hook 不完整时**禁止继续 unpack**。

### 1.1 核心组件

```
mida-antidebug-controller（host 侧，crates/antidebug）
        │
        ├─ preflight / dependency identity
        ├─ target launch / process identity
        ├─ injector（未来：自有注入器）
        ├─ runtime attestation 校验
        └─ evidence writer
                │
                ▼
mida-antidebug-runtime-x64.dll   （crates/antidebug-runtime，x64 目标）
mida-antidebug-runtime-x86.dll   （crates/antidebug-runtime，x86 目标）
        │
        ├─ user-mode API compatibility（IsDebuggerPresent / NtQueryInformationProcess / …）
        ├─ PEB/heap/debug state virtualization
        ├─ timing consistency（RDTSC / QueryPerformanceCounter / tick）
        ├─ exception/VEH compatibility
        ├─ parent/process/window compatibility
        └─ hook health telemetry（telemetry channel）
```

- **controller** 是决策者：它选择 profile、校验 artifact、绑定 target identity、写证据。
- **runtime** 是被注入到目标进程内的兼容层：它执行 hook、维护一致性状态、回报 telemetry。
- **evidence writer** 把 attestation 与 probe 结果写成结构化 JSON（schema 见证据契约文档）。

## 2. 现状审计：为什么必须替换 ScyllaHide 集成

### 2.1 当前状态（基线 HEAD）

| 项 | 现状 |
|---|---|
| ScyllaHide 注入代码 | `crates/packers/themida/src/antiantidebug/scyllahide.rs`（`inject_scylla_hide`） |
| 调用点 | `crates/cli/src/unpacker/mod.rs:920-924` |
| **缺陷（fail-open）** | 注入失败仅 `warn!("ScyllaHide injection failed (non-fatal)")`，**继续 unpack**；无 attestation、无 runtime 健康检查 |
| 二进制身份 | `crates/packers/themida/src/binaries.rs` 硬编码 SHA-256（x64 已封存；x86 为全零占位 fail-closed） |
| 行为依赖 | ScyllaHide 的 ntdll hook（`scylla_hide.ini` 驱动）对真实样本是**黑盒**：哪些 surface 被虚拟化、何时生效、是否完整，均不可验证 |
| 配置 | 无 profile；对 x64/x86 使用同一注入路径，hook_delay_ms 经验值 500ms |

### 2.2 具体缺陷清单

1. **缺文件仍继续跑**：injector/DLL 缺失或 hash 不匹配时，`inject_scylla_hide` 返回 Err，但调用点只 warn —— unpack 继续，样本大概率死于 anti-debug（`STATUS_FATAL_APP_EXIT`），且产出**无证据**的失败。
2. **无 runtime attestation**：无法证明 hook 已安装、完整、生效。
3. **无多源一致性保证**：ScyllaHide 是黑盒，无法交叉验证 PEB / NtQueryInformationProcess / timing / exception 观察一致。
4. **无 profile**：对所有样本统一 hook，无法针对样本实际 surface 最小化。
5. **x86 支持悬空**：x86 hash 为占位符，误构建会 fail-closed（这是对的），但没有任何 x86 runtime。
6. **不可审计**：ScyllaHide 注入是外部进程 + 配置文件，日志不可结构化，失败不可分类。

### 2.3 替换路线（不是重写，是替换）

1. 先堵 fail-open 缺陷（MIDA-ADR-3 controller 阶段即可：runtime 缺失 → 直接失败）。
2. 再建 surface inventory（MIDA-ADR-1）。
3. 再建自有行为规范与差分 oracle（MIDA-ADR-2）。
4. 实现自有 x64 runtime（MIDA-ADR-4）、early TLS/loader runtime（MIDA-ADR-5）、x86 runtime（MIDA-ADR-6）。
5. 差分验证（MIDA-ADR-7）通过后移除 ScyllaHide（MIDA-ADR-8）。

## 3. 核心原则

### P1. Profile-driven，不做全局粗暴隐藏

每个样本/packer family 使用明确 profile：

```json
{
  "profile_id": "oreans_x64_v1",
  "architecture": "x86_64",
  "expected_surfaces": [
    "peb_debug_flags",
    "nt_query_information_process",
    "thread_hide_from_debugger",
    "timing_consistency"
  ],
  "required_hooks": 12,
  "fail_if_missing": true
}
```

- 不对所有 API 做大范围 hook；只 hook 目标**实际检查**的 surface。
- `fail_if_missing` 恒为 true（第一阶段）。未来若某 surface 证明可安全降级，才允许显式降级（仍需 attestation 记录）。

### P2. 多源状态一致性

高级 anti-debug 交叉验证多个来源。MIDA-ADR 保证以下观察彼此一致：

- PEB.BeingDebugged / PEB flags
- NtQueryInformationProcess（DebugPort=7 / DebugObjectHandle=30 / DebugFlags=31）
- CheckRemoteDebuggerPresent
- debug object（NtQueryObject / DebugObject）
- thread hide state（NtSetInformationThread ThreadHideFromDebugger=0x11）
- heap flags（HeapFlags / NtGlobalFlag）
- timing（RDTSC / RDTSCP / QueryPerformanceCounter / GetTickCount）
- parent process / session / window 观察
- exception 行为（VEH/SEH 链、breakpoint 语义）

**规则：** 任一来源的虚拟化结果不一致 → runtime 视为退化（degraded），按 fail-closed 处理（见证据契约文档的 `consistency_status`）。

### P3. Runtime attestation

注入后必须生成 `mida_antidebug_runtime_attestation.json`，至少包括：

```json
{
  "schema": "mida.antidebug-runtime-attestation/v1",
  "runtime_sha256": "…",
  "architecture": "x86_64",
  "profile_id": "oreans_x64_v1",
  "profile_digest": "…",
  "target_pid": 1234,
  "module_base": "0x…",
  "initialized": true,
  "hooks_expected": 12,
  "hooks_installed": 12,
  "hook_failures": [],
  "telemetry_channel": "ready"
}
```

**没有 attestation：禁止继续 unpack。**（fail-closed，见证据契约。）

### P4. Hook 健康检查

不能只看 injector 返回码。必须验证：

1. runtime module 已加载（目标进程内，module_base 可解析）；
2. module hash 正确（与 controller 期望一致）；
3. 初始化函数执行（initialized=true）；
4. profile digest 匹配（profile 与 runtime 编译期绑定）；
5. 期望 hook 数量全部安装（hooks_installed == hooks_expected）；
6. 没有 hook failure（hook_failures 为空）；
7. telemetry channel 可用（ready）；
8. cleanup handler 已注册（未来卸载路径可验证）。

### P5. 失败即停

以下任意情况直接终止 unpack（不再输出 `Unpacked successfully`、`TLS pass`、`OEP pass`、`candidate accepted`）：

- `AntiDebugRuntimeUnavailable`
- `AntiDebugRuntimeIdentityMismatch`
- `AntiDebugRuntimeArchitectureMismatch`
- `AntiDebugRuntimeInitializationFailed`
- `AntiDebugRuntimePartialHooks`
- `AntiDebugRuntimeTelemetryLost`

## 4. 分层覆盖（L0–L6）

| 层 | 内容 | 状态 |
|---|---|---|
| **L0** | 依赖与身份：runtime DLL hash、injector hash、profile hash、architecture、toolchain、target identity | 本文档定义，MIDA-ADR-3 实现 |
| **L1** | Debugger host hygiene：process launch mode、debug event flow、thread suspend/resume、context access、breakpoint strategy、exception routing、handle cleanup | 现有 debugger core 已有部分；MIDA-ADR-4 验收 |
| **L2** | User-mode observation virtualization：PEB debug fields、process debug information、thread debug information、heap/debug flags、parent process observation、debugger presence APIs、debug object queries | MIDA-ADR-4（x64 最小覆盖） |
| **L3** | Early-start / TLS / loader：TLS callback 前初始化、loader-lock 安全、early anti-debug checks、initialization ordering、callback/entrypoint timing | MIDA-ADR-5 |
| **L4** | Timing and consistency：RDTSC、RDTSCP、performance counter、tick APIs、sleep/quantum consistency、debugger-induced latency | MIDA-ADR-4 基础版 + MIDA-ADR-7 差分 |
| **L5** | Exception and environment：VEH/SEH chain consistency、debug-print behavior、breakpoint exception semantics、invalid-handle behavior、parent/window/session checks | MIDA-ADR-4/5 覆盖子集，扩展待 inventory |
| **L6** | Kernel/hypervisor：kernel debugger state、DR0-DR7（内核侧）、kernel callback、hypervisor artifact | **暂不实现**。仅当 evidence 证明目标确实检查后才开独立任务 |

**L6 明确不实现。** 不做 driver/hypervisor。那会把工程复杂度和风险直接拉爆；现有样本（origin_macro、lunlun_software 均为 PE32+，即 x64 user-mode surface）不要求 L6。

## 5. 施工顺序（MIDA-ADR-0 .. MIDA-ADR-8）

| 任务 | 内容 | 交付 | 依赖 |
|---|---|---|---|
| **MIDA-ADR-0** | 第三方依赖边界与 clean-room 规范 | 本三份文档 + runtime provenance schema | T5-C 关闭 |
| **MIDA-ADR-1** | 目标样本 anti-debug surface inventory（只读分析 origin_macro、lunlun_software） | sample × surface 矩阵（check site / API / phase / expected observation / ScyllaHide 依赖 / MIDA 优先级） | ADR-0 |
| **MIDA-ADR-2** | 独立行为规范与 differential oracle | AntiDebugObservation / AntiDebugExpectedState / AntiDebugProbeResult 规范 + probe 记录 schema | ADR-1 |
| **MIDA-ADR-3** | 自有 controller 与 attestation（可先无 hook：堵掉 fail-open） | crates/antidebug：artifact discovery、hash/size/arch 校验、profile 选择、target identity 绑定、注入结果、module identity、hook health、telemetry、fail-closed 决策、evidence output | ADR-0/2 |
| **MIDA-ADR-4** | 自有 x64 runtime（最小覆盖：PEB/debug flags、NtQueryInformationProcess、NtSetInformationThread、CheckRemoteDebuggerPresent、heap/debug flags、parent process、basic timing） | crates/antidebug-runtime（x64）+ 每类 hook 的 positive/negative control、pre/post-hook observation、attestation、rollback | ADR-3 |
| **MIDA-ADR-5** | early TLS / loader runtime | TLS callback 前加载、loader-lock 安全、初始化顺序、early check observation、callback↔runtime 通信；验收：runtime ready、TLS callback 不见半初始化、失败不留半套 hook | ADR-4 |
| **MIDA-ADR-6** | x86 runtime | 独立验证 ABI、calling convention、stack cleanup、pointer width、PEB layout、NTAPI 参数、TLS callback pointer、exception frame | ADR-5 |
| **MIDA-ADR-7** | 差分验证 | 每样本三态：无 anti-debug runtime / ScyllaHide reference / MIDA-ADR；比较 target behavior、candidate stability、TLS/OEP/IAT evidence、runtime observation、exception behavior、timing profile、cleanup | ADR-4/5/6 |
| **MIDA-ADR-8** | 移除 ScyllaHide 依赖 | 满足：origin_macro x64 通过、lunlun_software x64 通过、所有 required hooks 有 attestation、失败路径 fail closed、多次 isolated replay 稳定、MIDA evidence 独立可验证 → 移除 ScyllaHide runtime | ADR-7 |

**第一阶段（本工作令）只做 MIDA-ADR-0。** 不执行样本；不实现 hook；不复制 ScyllaHide 源码或二进制。

## 6. 与现有代码/工作流的关系

- **不动现有 T5 producer/consumer**：MIDA-ADR-0..7 阶段不修改 `crates/packers/themida` 的 producer/gate 逻辑，也不修改 `crates/acceptance` 的 envelope/verifier 契约。
- **当前 fail-open 修复**：MIDA-ADR-3 的 controller 落库时，把 `crates/cli/src/unpacker/mod.rs:920-924` 的 `warn!` 升级为硬失败（`AntiDebugRuntimeUnavailable` 等）——这是独立提交，先于 runtime 实现。
- **ScyllaHide 保留为 differential oracle**：在 MIDA-ADR-8 之前，ScyllaHide 仍是 reference 对照（外部 oracle），但不再作为生产路径的必需品；MIDA-ADR-3 之后生产路径要求 MIDA-ADR attestation，ScyllaHide 仅用于差分实验。
- **workspace 结构建议**（独立 crate，验证后再接主 pipeline）：

```
crates/antidebug            ← controller（host 侧）
crates/antidebug-runtime    ← runtime DLL（x64/x86，MSVC/无依赖 C 或 Rust no_std 风格）
crates/antidebug-evidence   ← evidence 类型与 writer（可被 controller/acceptance 复用）
crates/antidebug-fixtures   ← 测试 fixture（符合 ARTIFACT_POLICY.md 的 fixture 例外）
```

> 不建议一开始就把所有代码塞进 `crates/core` / `crates/cli`。独立 crate 先验证，再接入主 pipeline。

## 7. 验收标准（MIDA-ADR-0）

文档必须明确：

1. **第三方 artifact 分类**（oracle / reference / prohibited / permitted-cleanroom）→ 见 CLEAN_ROOM_RULES；
2. **source/binary/license provenance 字段** → 见 CLEAN_ROOM_RULES §3；
3. **clean-room 角色分离**（spec 作者 vs 实现 agent vs oracle 操作者）→ 见 CLEAN_ROOM_RULES §2；
4. **行为规范如何传递给实现 agent** → 见 CLEAN_ROOM_RULES §5；
5. **ScyllaHide differential oracle 边界**（可观察输入/输出，不接触源码）→ 见 CLEAN_ROOM_RULES §4；
6. **MIDA-ADR 自有 evidence schema** → 见 EVIDENCE_CONTRACT；
7. **runtime missing/incomplete 时的 fail-closed 规则** → 见 EVIDENCE_CONTRACT §4；
8. **何时允许移除 ScyllaHide** → 见 CLEAN_ROOM_RULES §6 / ARCHITECTURE §5（ADR-8 条件）。

## 8. 文档治理

- 若项目治理要求，本三份文档可先写入外部 vault（不入 Git）。当前仓库为研究仓库，文档直接入 `docs/` 便于审查；如需移动，移动时保持相对链接（本文件引用同目录两兄弟文档）。
- 所有 schema 版本以 `mida.<name>/vN` 命名（与仓库既有约定一致，如 `mida.unpack-evidence-bundle/v1`、`mida.oreans-two-sample-gate/v8`）。
- 本工作令产物不含任何第三方 DLL/EXE/ini，不修改任何现有 Rust 代码。
