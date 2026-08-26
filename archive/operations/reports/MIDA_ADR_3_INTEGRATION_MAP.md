# MIDA-ADR-3 Integration Map（现有代码接线地图）

> **工作令：** MIDA-ADR-3 —— 设计 MIDA 自有 anti-debug controller/runtime 接线与 fail-closed 生命周期。
> **状态：** 设计定稿（只读审计；**未修改**任何 Rust 代码）。
> **基线：** `6f0d22765547c33857f3decb675427f0f317d538`。

## 1. 目的

标注未来 MIDA-ADR controller/runtime 的接线位置。本文件只画接线与状态，**不改代码**。

## 2. 当前已知 fail-open 点（必须修复）

| 位置 | 现状（基线 HEAD） | 未来改为 |
|---|---|---|
| `crates/cli/src/unpacker/mod.rs` ≈ L920-924（CREATE_PROCESS handler 内） | `inject_scylla_hide(pid, &scylla_config)` 失败 → `warn!("ScyllaHide injection failed (non-fatal)")` → **继续 unpack** | `AntiDebugRuntimeUnavailable` → hard error → 终止 unpack → 写 structured evidence（`mida.antidebug-evidence/v1`, decision=fail-closed）→ 不产生 candidate |

修复位置：`mod.rs` CREATE_PROCESS handler 的"Apply ScyllaHide"块（L909-924），未来替换为 controller 生命周期调用（`lifecycle.step(...)`）。

## 3. 接线点审计（只读）

### 3.1 `crates/cli/src/unpacker/mod.rs`

| 位置 | 现有职责 | 未来 MIDA-ADR 接线 |
|---|---|---|
| L65 | import `inject_scylla_hide`/`ScyllaHideConfig` | 移除（ADR-8）或保留为 oracle-only 路径（差分）；生产路径改为 controller |
| L895-899 | post-attach 模式跳过 PEB/ScyllaHide/API | controller 生命周期同样需要 post-attach 分支（runtime 注入时序不同） |
| L900-903 | `patch_peb_anti_debug`（PEB.BeingDebugged/pShimData） | 保留；attestation 记录 peb_state（AD-PROC-002/003 hard_required 的运行时证据） |
| L907 | `resolve_api_addrs()` | 保留（debugger 自身 API）；与 controller 无关 |
| L909-924 | ScyllaHide 注入（fail-open） | **替换为** controller 生命周期：DependencyVerified → … → Proceed；失败 → hard error |
| L962-968 | CloseHandle BP 安装策略 | 保留；与 runtime 并存（runtime 处理 anti-debug，BP 链处理 dump 时序） |

### 3.2 `crates/cli/src/unpacker/session.rs`

| 位置 | 现有职责 | 未来接线 |
|---|---|---|
| `ProcessSession` | RAII 包装 debugger + `ResolvedApis` | 增加 `antidebug: Option<AntidebugSession>` 字段（controller 生命周期状态 + runtime 句柄），随 session 一起清理 |
| `apis: Option<ResolvedApis>` | kernel32/ntdll 地址 | 保留；controller 的 runtime 通信可复用 |

### 3.3 `crates/cli/src/unpacker/post_attach.rs`

| 位置 | 现有职责 | 未来接线 |
|---|---|---|
| `run_post_attach_path` | 无调试端口快速路径：observe .text、freeze、dump | runtime 在 post-attach 模式下同样需要注入（时序：attach 后、resume 前）；controller 状态机需要有 post-attach 分支 |

### 3.4 `crates/cli/src/unpacker/post_loop.rs`

| 位置 | 现有职责 | 未来接线 |
|---|---|---|
| `run_post_loop_phases` | IAT repair、post-process、dump | 无直接 anti-debug 接线；但 evidence writer 的 candidate hash/size 在此产生（evidence 绑定候选） |

### 3.5 `crates/cli/src/runner_preflight.rs`

| 位置 | 现有职责 | 未来接线 |
|---|---|---|
| `run_offline_preflight` / `require_ready_before_launch` | runner-config envelope v4 校验；launch 前必须 ready | **controller 生命周期插入点**：Dependency/Profile 校验可在 preflight 阶段执行（L0 依赖身份）；`require_ready_before_launch` 与 controller 的 `DependencyVerified→ProfileVerified` 合并 |

### 3.6 `crates/core/src/process.rs`

| 位置 | 现有职责 | 未来接线 |
|---|---|---|
| `create_debug_process` | CREATE_SUSPENDED + DEBUG_ONLY_THIS_PROCESS 创建 | 保留；runtime 注入时机 = CREATE_SUSPENDED 后、首次 resume 前（保证 TLS callback 前 ready） |
| `patch_peb_anti_debug` | PEB.BeingDebugged/pShimData patch | 保留；作为 hard_required surface 的现有实现（AD-PROC-002/003） |

### 3.7 `crates/core/src/windows_debugger.rs`

| 位置 | 现有职责 | 未来接线 |
|---|---|---|
| `WindowsDebugger` | wait/continue/context/memory 操作 | 保留；controller 通过它读 runtime 状态（module_base、回读 hash、heartbeat 检查） |

## 4. 注入时序设计（L3 TLS/early loader）

```text
create_debug_process (CREATE_SUSPENDED)
  │  ── TLS callbacks 尚未执行（进程冻结）
  ▼
CREATE_PROCESS_DEBUG_EVENT
  │  ── 进程仍冻结
  ▼
[MIDA-ADR controller] DependencyVerified → ProfileVerified → TargetIdentityVerified
  ▼
[runtime load] 注入 runtime DLL（目标进程内）
  │  ── 必须在首次 resume 前完成（TLS callback 在 resume 时执行）
  ▼
[runtime init] MidaAntidebugInitialize（loader-lock 安全）
  ▼
[hook health] 9 步检查 + attestation
  ▼
[probes] 受控 probe（hard_required/candidate 面）
  ▼
Proceed → continue_event（首次 resume → TLS callbacks → 壳解包）
```

**关键约束：** runtime 必须在 TLS callback 执行前 ready（L3 面）。当前 pipeline 的注入点（CREATE_PROCESS 后、continue 前）满足此约束；ADR-3A 实现时在 `mod.rs` L1010 `continue_event` 之前完成整个 controller 生命周期（Proceed 后才 resume）。

## 5. 状态机 ↔ 现有代码映射

| 状态 | 对应现有代码位置 |
|---|---|
| Unresolved → DependencyVerified | runner_preflight 阶段（或 mod.rs 注入前） |
| ProfileVerified | runner_preflight / controller |
| TargetIdentityVerified | runner_preflight（case manifest 匹配） |
| LaunchPrepared | process.rs create_debug_process |
| RuntimeLoading → RuntimeInitialized | mod.rs CREATE_PROCESS handler（未来新代码） |
| HookHealthChecking → Attested | mod.rs CREATE_PROCESS handler（未来新代码） |
| ProbeReady → Proceed | mod.rs continue_event 前 |
| fail states | 任意点 → 终止 + evidence + 非 0 退出 |

## 6. 未来移除 ScyllaHide（ADR-8）时接线清理

- `mod.rs` L65 import、L909-924 注入块 → 删除或移入 oracle-only 差分路径；
- `helpers.rs` `scylla_injector_path`/`scylla_hook_path`（L28-33）→ 删除或 oracle-only；
- `crates/packers/themida/src/binaries.rs` hash 常量 → 保留（oracle 校验）或移除。

## 7. 审计声明

- 本文件基于基线 HEAD 只读审计；所有行号为基线时的行号，ADR-3A 实现时以实际代码为准。
- 未修改任何 Rust 文件；未执行样本；未执行 ScyllaHide。