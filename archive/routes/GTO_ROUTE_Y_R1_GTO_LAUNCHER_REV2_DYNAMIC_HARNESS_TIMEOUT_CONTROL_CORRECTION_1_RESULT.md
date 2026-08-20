# RouteY_R1_GTO_LAUNCHER_REV2_DYNAMIC_HARNESS_TIMEOUT_CONTROL_CORRECTION_1

**状态：RouteY_R1_GTO_LAUNCHER_REV2_DYNAMIC_HARNESS_TIMEOUT_CONTROL_CORRECTION_1_ReviewRequested**
**模式：OFFLINE / SYNTHETIC-HARNESS-ONLY / TIMEOUT-CONTROLLER ENGINEERING / NO REV2 TARGET READ / NO REV2 TARGET EXECUTION / NO LOCATOR READ / EVIDENCE-FIRST**

## 1. Authority

- Git HEAD = `9419ce9c40fd0874b97ac4c4459167d345ac8091`（branch `oreans/two-sample-mainline`，staged=0）
- 前置 Audit PASS = `..._EVIDENCE_PACKAGING_CORRECTION_1_AuditPassed`（manifest `e1ccc683...`）
- 动态 baseline correction authority = `76785e5ab5d51da8b0aa550d1aaa368296b88dca4ecc76f20c321fdf7da1fa2b`
- 治理状态 = `RouteY_R1_GTO_LAUNCHER_REV2_StaticResearchExhausted`

## 2. 历史违例 root-cause（只读评估，不重解释）

| 事实 | 值 |
|---|---|
| target start request | 2026-08-14T15:20:32.130Z |
| hard deadline | 2026-08-14T15:22:32.130Z |
| termination record | 2026-08-14T15:22:55Z |
| recomputed runtime | 142870ms |
| deadline overrun | 22870ms |
| hard_timeout_compliance | false / Violated |
| 旧字段 runtime_duration_ms | 122675 (unsupported) |
| 旧 controller 实现 | 未封装（historical_controller_implementation_available=false） |
| exact_old_code_root_cause | unproven |
| observed enforcement failure | true |
| end_utc 混淆 | proven（target_exit.end_utc = evidence 记录时间 15:24:12.821Z，非 process end） |

新 controller 设计移除的依赖：observer 不在 timeout 关键路径、wall-clock 不用于 enforcement、证据写入不在 timeout 路径、单一 end 字段拆分 4 事件语义。

## 3. 新 timeout-controller 设计要点

- 权威时间源：`System.Diagnostics.Stopwatch`（monotonic）；wall-clock 仅报告
- deadline 锚定在 loop 起始（子进程枚举后），monotonic 比较
- 终止请求在 monotonic deadline 发出（不等待 observer/证据/UI/module sampling）
- 完整 process-tree kill：CIM 枚举后代 → 子先于父 → 残留复查
- start-attempt ledger：OS 调用前原子检查+预留；第二次调用被阻止
- 13 个权威时间字段，4 事件语义分离（termination requested / API returned / disappeared / evidence written）

## 4. Synthetic 测试矩阵（8/8 PASS）

| 场景 | 说明 | terminal | term overrun | exit overrun | 结果 |
|---|---|---|---|---|---|
| S1 | NormalExitBeforeDeadline | NaturalExit | - | -2449ms | PASS |
| S2 | ExactTimeoutKill | TimeoutTerminated | +15ms | +226ms | PASS |
| S3 | ImmediateExit | NaturalExit | - | -2990ms | PASS |
| S4 | NonzeroExit | NaturalExit (exit=7) | - | -2671ms | PASS |
| S5 | ChildTreeKill | TimeoutTerminated | +17ms | +206ms | PASS (3 child PIDs killed, 0 residual) |
| S6 | ObserverNotReadyPreflight | ObserverNotReady | n/a | n/a | PASS (0 OS calls) |
| S7 | AttemptBudgetExceeded | AttemptBudgetExceeded | n/a | n/a | PASS (0 OS calls) |
| S8 | EvidenceWriteDelayIsolation | TimeoutTerminated | +13ms | +206ms | PASS (evidence delayed 2s after termination) |

门限：termination_request_overrun_ms ≤ 250ms（S2=15, S5=17, S8=13）；process_exit_overrun_ms ≤ 2000ms（max 226ms）。全部通过，未扩宽容差。

## 5. 关键证明

- **monotonic_deadline_used** = true；**wall_clock_not_used_for_enforcement** = true
- **observer_not_on_critical_timeout_path** = true（S6 只做预检门，未参与 enforcement）
- **evidence_write_not_on_critical_timeout_path** = true（S8：人工 2s 证据延迟不影响 process-exit 时间，字段未混淆）
- **complete_process_tree_cleanup** = true（S5：3 子进程全部击杀，parent+child residual = 0）
- **second_start_blocked_before_os_invocation** = true（S7：ledger 耗尽 → OS 调用前阻止，0 次 OS creation）
- **timestamp_roles_unambiguous** = true（13 字段，4 事件分离）
- **timeout_algorithm_deadline_independent** = true（1s/3s deadline 下同一算法，无 120s 真实 target 测试）
- synthetic_scenarios_pass = 8 / fail = 0
- 预算：scenarios=8（≤8），process creation attempts=7（≤16），rev2 target=0，candidate=0

## 6. 边界合规

- rev2_target_read = false；rev2_target_start_count = 0；candidate_sample_start_count = 0
- mutable_locator 未读；无 debugger/hook/injection/dump/network
- source/manifest/historical root 未修改；无 commit/push/git add
- 只创建了新 evidence root；helper 不含任何 target/locator 路径引用

## 7. Dynamic authorization

dynamic_authorized = false；second_rev2_dynamic_run_allowed = false。本工单 PASS 不自动授权第二次 rev2 动态；下一步只能是独立的 dynamic authorization review。

**已停机，等待独立审计。**
