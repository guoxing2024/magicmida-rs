# MIDA-ADR-3 Lifecycle 状态机（fail-closed）

> **工作令：** MIDA-ADR-3 —— 设计 MIDA 自有 anti-debug controller/runtime 接线与 fail-closed 生命周期。
> **状态：** 设计定稿（文档阶段）。未实现代码。
> **基线：** `6f0d22765547c33857f3decb675427f0f317d538`。

## 1. 成功路径状态机

```text
Unresolved
  │
  ▼  Dependency Resolver: artifact 发现 + hash/size/arch/provenance 校验
DependencyVerified
  │
  ▼  Profile Resolver: sample_id/family/arch/profile_id/profile_digest 校验
ProfileVerified
  │
  ▼  Target Launcher: protected input identity + PID + launch mode
TargetIdentityVerified
  │
  ▼  LaunchPrepared: process created (CREATE_SUSPENDED), pre-resume ready
LaunchPrepared
  │
  ▼  Runtime Loader: load runtime DLL into target (pre-TLS-callback)
RuntimeLoading
  │
  ▼  Runtime init entry + bounded init timeout
RuntimeInitialized
  │
  ▼  Hook Health Checker: 9-step check (module/hash/profile/init/hooks/telemetry/heartbeat)
HookHealthChecking
  │
  ▼  Attestation writer: mida.antidebug-runtime-attestation/v1
Attested
  │
  ▼  Controlled probes (profile-defined; only for hard_required/candidate surfaces with probe defs)
ProbeReady
  │
  ▼  decision = proceed
Proceed
```

## 2. 失败状态（terminating；任何失败状态都不能转移到 Proceed）

| fail state | 触发条件 | exit semantics |
|---|---|---|
| `DependencyUnavailable` | runtime/injector artifact 缺失或不可读 | fail-closed；`AntiDebugRuntimeUnavailable`；写 evidence；非 0 退出 |
| `DependencyIdentityMismatch` | hash/size 不匹配 | fail-closed；`AntiDebugRuntimeIdentityMismatch` |
| `ArchitectureMismatch` | runtime arch != target arch | fail-closed；`AntiDebugRuntimeArchitectureMismatch` |
| `ProfileMismatch` | profile/sample/arch/digest 不匹配；unknown required；candidate 误当 hard | fail-closed；`AntiDebugRuntimeIdentityMismatch`（或专用 ProfileMismatch code） |
| `TargetIdentityMismatch` | protected input hash/size != manifest | fail-closed；`AntiDebugRuntimeIdentityMismatch` |
| `RuntimeLoadFailed` | 注入/加载失败；超时 | fail-closed；`AntiDebugRuntimeUnavailable` 或 `AntiDebugRuntimeInitializationFailed` |
| `RuntimeInitializationFailed` | init 返回失败/超时/initialized=false | fail-closed；`AntiDebugRuntimeInitializationFailed` |
| `PartialHooks` | hooks_installed != hooks_expected 或 hook_failures 非空 | fail-closed；`AntiDebugRuntimePartialHooks` |
| `TelemetryLost` | telemetry channel 不可用/丢失/heartbeat 超时 | fail-closed；`AntiDebugRuntimeTelemetryLost` |
| `ProbeInconsistent` | 受控 probe expected != observed（高置信）或 consistency degraded | fail-closed；`ProbeInconsistent` |
| `CleanupFailed` | 目标终止失败/等待超时/卸载状态未知 | fail-closed；`CleanupFailed` |

## 3. 转移规则

### 3.1 成功转移（每步必须产生结构化证据）

| from | to | 证据 |
|---|---|---|
| Unresolved → DependencyVerified | artifact identity 记录（hash/size/arch/provenance） | `mida.antidebug-provenance/v1` |
| DependencyVerified → ProfileVerified | profile 绑定记录 | profile_id + profile_digest |
| ProfileVerified → TargetIdentityVerified | input identity | protected_input sha256/size |
| TargetIdentityVerified → LaunchPrepared | launch 参数 | pid、launch mode、env digest |
| LaunchPrepared → RuntimeLoading | 注入发起 | runtime hash、inject 参数 |
| RuntimeLoading → RuntimeInitialized | init 成功 | initialized=true、module_base |
| RuntimeInitialized → HookHealthChecking | 健康检查启动 | — |
| HookHealthChecking → Attested | 9 步全部通过 | `mida.antidebug-runtime-attestation/v1` |
| Attested → ProbeReady | 受控 probe 通过 | `mida.antidebug-probe-result/v1` 数组 |
| ProbeReady → Proceed | decision=proceed | `mida.antidebug-evidence/v1` bundle |

### 3.2 失败转移（所有失败 → fail-closed，写 evidence，非 0 退出）

```text
任何状态 --(失败)--> [fail state] --(evidence+exit)--> TERMINAL
```

失败时：
1. 若目标已创建：尝试 TerminateProcess + WaitForSingleObject（有界等待）；
2. 若目标无法终止：CleanupFailed 记录；
3. 写 `mida.antidebug-evidence/v1`（decision=fail-closed, fail_code, 已收集字段）；
4. 返回非 0 退出码；
5. **不得**输出 candidate success / TLS pass / OEP pass。

## 4. 状态机属性

- **确定性**：相同输入 → 相同转移（可重放）；
- **无隐式回退**：失败状态是终态，不自动重试（重试由上层显式重新开始完整生命周期）；
- **无旁路**：不存在跳过某状态的 seam；Proceed 只能从 ProbeReady 到达；
- **证据在每个成功转移处累积**：最终 bundle 包含全部中间证据；
- **fail-closed 优先于部分成功**：任何一步失败即终态，即使后续步骤可能"仍可继续"。

## 5. 实现验收（ADR-3A 时）

- 状态机为显式 enum（`Unresolved…Proceed` + 11 个 fail states）；
- `transition()` 是纯函数（state, event) → (state, evidence)；
- 单元测试覆盖：每个成功转移、每个失败转移、失败后不可达 Proceed；
- fail_code 与 ADR-0 EVIDENCE_CONTRACT §4.1 对齐。