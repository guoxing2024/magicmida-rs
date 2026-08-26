# MIDA-ADR 证据契约（Evidence Contract）

> **工作令：** MIDA-ADR-0 —— 建立自研 anti-debug runtime 的第三方依赖边界与 clean-room 规范。
> **状态：** 定稿（文档阶段）。不执行样本、不实现 hook、不复制 ScyllaHide 源码或二进制。
> **基线：** `4fe2cc350378faf8a1408dadb0caf5c30fd20786`。
> 配套：[ARCHITECTURE](MIDA_ANTIDEBUG_ARCHITECTURE.md) · [CLEAN_ROOM_RULES](MIDA_ANTIDEBUG_CLEAN_ROOM_RULES.md)

## 1. 目的

本文件定义 MIDA-ADR 的证据 schema、runtime attestation 契约、hook 健康检查与 fail-closed 决策规则。任何注入或 hook 不完整都必须自动失败，且失败必须有结构化证据可审计。

## 2. Schema 命名与版本

沿用仓库既有约定 `mida.<name>/vN`：

| schema | 用途 |
|---|---|
| `mida.antidebug-profile/v1` | 样本/packer family 的 anti-debug surface profile |
| `mida.antidebug-runtime-attestation/v1` | 注入后 runtime 身份与健康 attestation |
| `mida.antidebug-observation/v1` | 单个 observation（probe 输入/输出/来源/置信度） |
| `mida.antidebug-probe-result/v1` | 单个 probe 的 expected vs observed 对比 |
| `mida.antidebug-expected-state/v1` | sample × surface 的 no-debugger 期望状态（ADR-2 引入；required 标记 + allowed_variance） |
| `mida.antidebug-evidence/v1` | 一次 unpack 尝试的完整证据包（含 attestation 与 probes） |
| `mida.antidebug-provenance/v1` | artifact provenance（见 CLEAN_ROOM_RULES §7） |

所有 schema **fail-closed**：字段缺失、类型错误、未知 schema 版本 → 拒绝（不静默容忍）。**未知字段同样拒绝**：runtime attestation / provenance / telemetry 的所有结构化记录在解析期启用 `deny_unknown_fields`（ADR-4-CORRECTION 落实），不依赖"缺字段才失败"的宽松默认。

`mida.antidebug-evidence/v1` 的 CLI 失败记录使用 `record_kind = "cli-failure"`（ADR-3B-CORRECTION 统一登记）：

| record_kind | 用途 | 必填字段 |
|---|---|---|
| `cli-failure` | CLI 侧 anti-debug 生命周期失败 sidecar（runtime 缺失/身份/初始化/hook/telemetry/probe/cleanup 失败） | `decision=fail-closed`、`fail_code`、`failure_state`、`sequence`、`cleanup_result`、`candidate_created=false` |

该 record_kind 只描述失败，不携带成功声明，不进入 T5/acceptance 成功证据链。

## 3. Profile schema（`mida.antidebug-profile/v1`）

```json
{
  "schema": "mida.antidebug-profile/v1",
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

- `expected_surfaces` 枚举目标实际检查的 surface（来自 MIDA-ADR-1 inventory，不由 ScyllaHide 支持集反推）。
- `required_hooks` = profile 声明需要安装的 hook 总数；runtime attestation 必须满足 `hooks_installed == required_hooks`。
- **required 两级（ADR-3 引入）**：`hard_required_surfaces`（必须安装；缺失 → `AntiDebugRuntimePartialHooks`）与 `required_candidate_surfaces`（接线时验证；满足 call_site_confirmed / runtime_observed / decision_semantics_confirmed 之一后升级 hard_required，升级产生 profile revision + promotion evidence + digest 变化 + 审计记录；失败降 observe-only）。
- `fail_if_missing` 恒 true（第一阶段）。允许显式降级仅当 profile 修订记录证据（含差分对照），且 attestation 记录降级事实。
- 每个 profile 有 `profile_digest`（规范化 JSON 的 SHA-256），runtime 编译期绑定；controller 校验一致。

## 4. Runtime attestation（`mida.antidebug-runtime-attestation/v1`）

注入后必须生成 `mida_antidebug_runtime_attestation.json`：

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
  "telemetry_channel": "ready",
  "cleanup_handler_registered": true
}
```

字段说明（部分在 §5 有更细的校验规则）：

| 字段 | 规则 |
|---|---|
| `runtime_sha256` | 与 controller 期望的 runtime artifact hash 一致 |
| `architecture` | 与目标架构一致（`x86_64` / `x86`） |
| `profile_digest` | 与 controller 选择的 profile digest 一致 |
| `target_pid` | 与本次启动的 target 一致（target identity 绑定）；controller 必须交叉校验（`verify_identity`），防跨进程搬用 attestation |
| `module_base` | 非零；controller 在目标进程内可解析该模块；attestation 声称的 base 必须与 controller 解析值一致 |
| `initialized` | 初始化函数已执行 |
| `hooks_installed == hooks_expected` | 全部安装 |
| `hook_failures` | 空数组 |
| `telemetry_channel` | `ready`（可收发 telemetry） |
| `cleanup_handler_registered` | true（卸载路径可验证） |

**没有 attestation：禁止继续 unpack。** runtime 缺失、身份不符、初始化失败、hook 不完整、telemetry 丢失 → 一律停止。

### 4.1 失败码（fail-closed 错误）

| 错误 | 触发条件 |
|---|---|
| `AntiDebugRuntimeUnavailable` | runtime DLL/injector 缺失或不可读 |
| `AntiDebugRuntimeIdentityMismatch` | runtime SHA-256 与期望不符；attestation target_pid/module_base 与本次运行不符（跨进程搬用） |
| `AntiDebugProfileMismatch` | profile 与 sample/architecture/digest 不匹配、unknown surface 出现在 hard_required、required_candidate 被误当 hard_required（ADR-3A 定案专用码） |
| `AntiDebugRuntimeArchitectureMismatch` | runtime 架构与目标架构不符 |
| `AntiDebugRuntimeInitializationFailed` | 初始化函数未执行 / initialized=false |
| `AntiDebugRuntimePartialHooks` | hooks_installed != hooks_expected 或 hook_failures 非空 |
| `AntiDebugRuntimeTelemetryLost` | telemetry channel 不可用 / 中途丢失 |

**禁止输出：** `Unpacked successfully`、`TLS pass`、`OEP pass`、`candidate accepted` —— 上述任一失败码存在时不得输出。

## 5. Hook 健康检查（controller 侧校验）

不能只看 injector 返回码。controller 必须按序验证：

1. **runtime module 已加载**：目标进程内能解析 module_base，且模块在目标内存中。
1a. **target identity 交叉校验**：attestation.target_pid == 本次启动 PID；attestation.module_base == controller 解析值且非零（ADR-4-CORRECTION）。
2. **module hash 正确**：运行时读回模块字节的 hash 与 `runtime_sha256` 一致（或等价：模块签名/绑定校验通过）。
3. **初始化函数执行**：`initialized == true`。
4. **profile digest 匹配**：`profile_digest` 与 controller 选择的 profile 一致。
5. **期望 hook 数量全部安装**：`hooks_installed == hooks_expected`。
6. **没有 hook failure**：`hook_failures` 为空。
7. **telemetry channel 可用**：`telemetry_channel == "ready"`，且一次 ping 往返成功。
8. **cleanup handler 已注册**：`cleanup_handler_registered == true`。

任一步失败 → 对应失败码（§4.1）→ 终止 unpack，写 evidence。

## 6. Observation / Probe 记录

### 6.1 `mida.antidebug-observation/v1`

```json
{
  "schema": "mida.antidebug-observation/v1",
  "observation_id": "obs-0001",
  "sample_id": "origin_macro",
  "phase": "early_loader",
  "surface": "nt_query_information_process",
  "api": "NtQueryInformationProcess",
  "expected": {"ProcessInformationClass": 7, "return_status": 0, "debug_port": 0},
  "observed": {"ProcessInformationClass": 7, "return_status": 0, "debug_port": 0},
  "source": "mida-runtime-telemetry",
  "confidence": 1.0
}
```

- `phase` ∈ `early_loader` / `tls_callback` / `oep_prelude` / `runtime_loop` / `exception_path` / `self_check` / `timing_path`。
- `source` ∈ `mida-runtime-telemetry` / `debugger-core` / `scyllahide-oracle` / `static-analysis` / `public-doc`。

### 6.2 `mida.antidebug-probe-result/v1`

每个 probe 记录：

| 字段 | 说明 |
|---|---|
| `probe_id` | 唯一 |
| `sample_id` | 目标样本标识 |
| `phase` | 同 §6.1 |
| `input` | 探针输入（API、参数、环境） |
| `expected_result` | 行为规范声明的期望观察 |
| `observed_result` | 实际观察 |
| `source` | 观察来源 |
| `confidence` | 0..1（低置信度禁止作为“通过”依据） |

**一致性规则（P2）：** 多源交叉观察（PEB / NtQueryInformationProcess / CheckRemoteDebuggerPresent / debug object / thread hide / heap flags / timing / parent / exception）必须一致；任一不一致 → `consistency_status: "degraded"` → fail-closed。

## 7. Evidence bundle（`mida.antidebug-evidence/v1`）

一次 unpack 尝试的完整证据包：

```json
{
  "schema": "mida.antidebug-evidence/v1",
  "run_id": "…",
  "tool_revision": "4fe2cc350378faf8a1408dadb0caf5c30fd20786",
  "target": {"sample_id": "origin_macro", "pid": 1234, "architecture": "x86_64"},
  "profile": {"profile_id": "oreans_x64_v1", "profile_digest": "…"},
  "attestation": { …mida.antidebug-runtime-attestation/v1… },
  "observations": [ …mida.antidebug-observation/v1… ],
  "probes": [ …mida.antidebug-probe-result/v1… ],
  "consistency_status": "consistent",
  "decision": "proceed" | "fail-closed",
  "fail_code": null | "AntiDebugRuntimePartialHooks",
  "differential": [
    {
      "mode": "no-runtime" | "scyllahide-reference" | "mida-adr",
      "sha256": "…",
      "observations": [ … ]
    }
  ],
  "provenance": [ …mida.antidebug-provenance/v1… ]
}
```

- `decision` 只能来自 attestation + probes 的确定性规则（§8），不允许人工旁路。
- `differential` 用于 MIDA-ADR-7：同一样本在三种模式下的观察对比，目标是“MIDA 能解释地得到与 reference 同等或更强的 evidence”，不是逐字节一致。

## 8. Fail-closed 决策规则（确定性）

```
decision = fail-closed  当且仅当 任一:
  attestation 缺失
  attestation 任一字段校验失败（schema/身份/架构/digest/init/hooks/telemetry/cleanup）
  probes 存在 expected != observed 且 confidence >= 0.9（高置信失败）
  consistency_status == degraded
否则 decision = proceed（可继续 unpack 管线）
```

- 规则是纯函数：相同输入必得相同 decision（可重放）。
- `fail-closed` 时：不输出任何成功声明（§4.1 禁止项），写出 evidence bundle，退出码为非成功。
- 未来若 profile 声明某 surface 可安全降级，必须：修订 profile（记录证据）+ attestation 记录降级 + 仍保留 `consistency_status` 检查。

## 9. 与既有契约的对接

- **T5 producer/consumer 不变**：MIDA-ADR 证据是**附加**的（sidecar 风格，`mida.antidebug-evidence/v1`），不修改 `mida.behavior-evidence/v0` / envelope v4 / gate v8 的既有 schema。
- **isolated replay**：evidence bundle 必须可离线重放（确定性规则 + 完整输入），供 `mida_acceptance` 或审计工具复算 `decision`。
- **ScyllaHide oracle**：oracle 模式的 `differential` 记录必须有完整三文件 SHA-256 与运行参数（见 CLEAN_ROOM_RULES §4），且永远标记 `source` 为 oracle，不进入 MIDA runtime 实现。

## 10. MIDA-ADR-0 验收对照

| 要求 | 落点 |
|---|---|
| 1. 第三方 artifact 分类 | CLEAN_ROOM_RULES §3 |
| 2. provenance 字段 | CLEAN_ROOM_RULES §7 |
| 3. clean-room 角色分离 | CLEAN_ROOM_RULES §2 |
| 4. 行为规范传递 | CLEAN_ROOM_RULES §5 |
| 5. ScyllaHide differential oracle 边界 | CLEAN_ROOM_RULES §4 · 本文 §9 |
| 6. MIDA-ADR 自有 evidence schema | 本文 §2–§7 |
| 7. runtime missing/incomplete fail-closed | 本文 §4.1 · §8 |
| 8. 何时允许移除 ScyllaHide | CLEAN_ROOM_RULES §6 · ARCHITECTURE §5（ADR-8） |