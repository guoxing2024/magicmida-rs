# RouteY_R1_GTO_LAUNCHER_REV2_RUNTIME_MODULE_IDENTITY_CAPTURE_1_BOUNDARY_VIOLATION_FORENSIC_RECONCILIATION_1

**状态：RouteY_R1_GTO_LAUNCHER_REV2_RUNTIME_MODULE_IDENTITY_CAPTURE_1_BOUNDARY_VIOLATION_FORENSIC_RECONCILIATION_1_ReviewRequested**
**模式：EVIDENCE / FORENSIC TIMELINE / BOUNDARY RECONCILIATION ONLY**

## 1. 审计结论确认

来源 capture root 被审计裁决为 `AuditFailed_BoundaryViolation`。本 reconciliation **不辩解、不推翻**，只如实重建事实链并隔离污染证据。

来源 root：`..._runtime_module_identity_capture_1_20260814T194201Z` · manifest `11106b1d7e5578211c68b36b9d996c4fe63a361d721439c63129b2933299f0af`（只读复核 37/37 全匹配，未修改）

## 2. target-start timeline（raw observer 权威）

```text
RUNID=MODCAP1_20260814T194437Z  observer 30784  无 target 观察（preflight-only）
RUNID=MODCAP1_20260814T194506Z  observer 8260   无 target 观察（preflight-only）
RUNID=MODCAP1_20260814T194626Z  observer 604    TARGET_PROCESS_CREATED pid=2968 @ 19:46:32.892Z
                                                WINDOW_TITLE=PigToGo · MODULES_CAPTURED count=54
                                                采样持续至 19:48:31+（OBSERVER_STOP 19:48:03 后继续至 19:48:33）
RUNID=MODCAP1_20260814T194856Z  observer 16068  TARGET_PROCESS_CREATED pid=20300 @ 19:49:04.304Z
                                                WINDOW_TITLE=PigToGo · MODULES_CAPTURED count=54
```

**unique target PID count = 2**（2968 + 20300），同一个 immutable path。不允许合并。

## 3. 授权预算违例

```text
authorized_target_start_budget  = 1
unique_target_pid_count         = 2
minimum_confirmed_target_starts = 2
single_start_guard_proven       = false
authorization_budget_breached   = true
retry_policy_breached_or_unproven = true
start_ledger_final_state        = inconsistent（consumed=false 但已发生 2 次 OS 创建）
```

## 4. PID 2968 网络隔离裁决

```text
PID 2968 creation      = 19:46:32.892Z
firewall before        = 19:48:58.218Z  ← 晚于 PID 2968 启动
firewall installed     = 19:49:02.557Z
firewall verified      = 19:49:03.629Z
PID 2968 network_deny_all_proven = false
PID 2968 network_activity        = unknown
PID 2968 network_safe_baseline   = invalid
```

不声称整个工单 network=0 / deny-all 全程有效。仅 PID 20300 运行（19:49:04 创建，verification 19:49:03.629 在前）有已验证 deny-all：`network_deny_all_verified_for_pid_20300 = true`。

## 5. Module evidence 分离

```text
PID 2968 module observation = runtime/observer_out/modules_pid_2968.json（54 modules）
PID 20300 module inventory  = runtime/observer_out/modules_pid_20300.json（54 modules）
module_identity_inventory.target_pid = 20300（顶层载荷仅记录 PID 20300）
PID 2968 的 module evidence 未进入顶层载荷
module_identity_result = MixedPids（两个 PID 的观察并存于 runtime）
module_capture_qualified = false（隔离/隔离）
```

WeType 相关模块（wetype_tip.dll / wetype_tip_core.dll / CrashRpt1500.dll）在两 PID 环境均观察到——environment observation only，无行为推断、无产品归属、无 AHK 推断。

## 6. Pre-start identity gap

```text
target_identity_before recorded = 19:54:12Z（事后读取）
PID 2968 creation = 19:46:32Z · PID 20300 creation = 19:49:04Z
identity_before_is_prestart_proof = false
prestart_hash_for_pid_2968  = unknown
prestart_hash_for_pid_20300 = unknown
target_identity_after_verified = true（19:51:13Z，vault 未变）
```

不得用事后 `target_identity_before.json` 冒充 pre-start hash。

## 7. freeze_before 语义

```text
source freeze_before write = 19:55:37Z
source_freeze_before_is_runtime_preflight_snapshot = false
semantic = post-hoc packaging metadata only
```

## 8. 终态

```text
boundary_violation = true
unique_target_pid_count = 2 · minimum_confirmed_target_starts = 2 · authorized_budget = 1 · budget_breached = true
pid_2968_network_isolation = unproven
pid_20300_network_isolation = verified_only_for_pid_20300
module_capture_result = quarantined · runtime_module_identity_qualified = false
dynamic_authorization_suspended = true · additional_dynamic_authorization = false
second_start_allowed = false · target_rerun_allowed = false
```

PID 20300 产生了技术上结构化的 module evidence，但整张工单是 BoundaryViolation，module 结果隔离不采信。

## 9. 冻结

后续 rev2 dynamic = 0 · second start = 0 · module capture 重跑 = 0 · behavior observation = 0 · UI/login = 0 · network observation = 0。本 reconciliation 未执行任何 target/observer/controller/runner。

**已停机，等待独立审计。**
