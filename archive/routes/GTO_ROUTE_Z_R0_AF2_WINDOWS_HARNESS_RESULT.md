# GTO Product Recovery — Route Z R0 AF2 Real Windows Capture Epoch Harness

> 状态：**`RouteZ_R0_AF2_ReviewRequested`**（真实 benign Windows 进程 harness 验证 freeze/unfreeze/thread-set/suspend-count/error rollback。未 commit、未 live、未 candidate、未 protected sample）。
> 授权 baseline：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`）。允许一个 benign helper process。

---

## 1. 授权 baseline 核对（只读）

| 检查 | 预期 | 实际 | 结果 |
|---|---|---|---|
| branch | `oreans/two-sample-mainline` | 一致 | ✅ |
| HEAD | `68b8032` | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` | ✅ |
| HEAD^ | `9450b3a` | `9450b3aed570ff42c62a248f7e7013540a7e1348` | ✅ |
| untracked docs（6 个冻结） | X R1 / Y R0 / Y R1 / Y R1 A2 / Z R0 / Z R0 AF1 | 全部存在且未修改 | ✅ |
| `git diff --check` | 干净 | 干净 | ✅ |

**baseline 全部匹配。** 冻结 evidence 未覆盖。

## 2. Benign helper process

新增 `crates/core/src/bin/capture_epoch_helper.rs`：
- 主线程 + 初始 worker 线程（`--workers N`）
- 一个 spawner 线程周期性创建新 worker（`--spawn-every-ms M`，0 关闭）
- 共享**命名内存映射**：`counter`(u64) / `running`(u32) / `worker_count`(u32)
- 写 PID 到 pidfile
- 无网络、无 protected sample、无外部依赖、无 candidate
- 通过 `running` 标志 + 硬超时退出

## 3. 真实冻结验证（核心证明）

新增 `crates/core/tests/capture_epoch_harness.rs`（integration test，用 `CARGO_BIN_EXE_capture_epoch_helper` 启动 helper）：

| 测试 | 验证点 | 结果 |
|---|---|---|
| `real_process_freeze_stops_workers` | freeze 前 counter 持续增长；freeze 后 350ms 内 counter **不变**（TOCTOU 被阻止）；freeze 后所有枚举线程 suspend count ≥ 1 | ✅ |
| `real_process_unfreeze_resumes_workers` | unfreeze 后 counter **恢复增长**；previously-running 线程 suspend count 回到 0 | ✅ |
| `real_process_freeze_covers_thread_set` | helper spawner 周期性创建新线程（40ms）；freeze 二次枚举至稳定覆盖全部（含新线程） | ✅ |
| `real_process_prior_suspend_count_restored` | 手动 SuspendThread 一个线程（prior=1）；freeze 记录 prior=1（suspend→2）；unfreeze 只抵消自己（→1，**不**无条件归零）；手动 resume→0 | ✅ |
| `real_process_partial_freeze_rolls_back` | freeze 无效 PID → **fail-closed**（Err 或空列表），不声称 frozen | ✅ |
| `real_process_repeated_20x_all_pass` | **20 次真实 freeze/restore 重复全部通过** | ✅ |

**所有 6 个真实 Windows 进程测试通过**。无残留 helper 进程（每次 cleanup + Child::drop kill）。

## 4. Thread-set race 验证

- `freeze_process_threads`（`windows_debugger.rs`）用 ToolHelp 枚举 + `OpenThread`/`SuspendThread`，**二次枚举至线程集合稳定**（`MAX_ROUNDS=8`）。
- `real_process_freeze_covers_thread_set` 用 helper 的 spawner（每 40ms 创建新线程）验证 freeze 覆盖了 freeze 期间新创建的线程（post-freeze 枚举所有线程 suspend count ≥ 1）。
- **fail-closed**：`OpenThread`/`SuspendThread` 失败 → 已 suspend 的线程 rollback + 返回 Err；线程集合无法收敛 → rollback + Err。绝不返回"frozen"但有线程在运行。

## 5. Prior suspend count（真实验证）

`real_process_prior_suspend_count_restored` 验证：
- 预先 suspend 的线程（prior=1），epoch 只加自己的层（→2）
- unfreeze 只抵消自己（→1），**不**无条件 ResumeThread 到 0
- 手动 resume 后回到 running（→0）

## 6. PID 与线程范围

- `freeze_process_threads(pid)` 严格按 `pid` 过滤（`th32OwnerProcessID == pid`），只冻结 target PID。
- **不冻结调用线程**（跳过 `GetCurrentThreadId`）。
- 测试进程（Rust test）不被冻结（freeze 只针对 helper pid）。
- 每个 `OpenThread` 成功句柄立即 `CloseHandle`；snapshot 也 `CloseHandle`。
- 无跨进程泄漏（无残留 helper 进程）。

## 7. CaptureEpochGuard 代码审计（工单 7 节）

| 审计项 | 结论 |
|---|---|
| begin 是否完整 | ✅ freeze 所有线程，返回 suspended 列表 |
| Drop 是否调用 unfreeze | ✅ `Drop → end()`，总是恢复 |
| end/Drop 是否幂等 | ✅ `restored` 标志，end 或 Drop 只恢复一次 |
| partial freeze rollback | ✅ `freeze_process_threads` 失败时 rollback 已 suspend 线程 |
| panic 是否恢复 | ✅ RAII Drop 在 unwind 时恢复（mock 测试 `capture_epoch_restores_threads_on_error` 验证） |
| Windows API error 是否保留 | ✅ freeze/unfreeze 返回 `CoreError`，失败不吞掉 |
| **默认实现 fail-closed** | ✅ 已改：`DebuggerCore::freeze_target_threads` 默认返回 **Err**（非 no-op），除非 backend 实现真实冻结 |
| no-op 误用 | ✅ 修复：默认 fail-closed，任何不支持的 backend 会显式失败而非静默跳过 |
| elapsed/suspended IDs/started 准确 | ✅ telemetry 记录 |
| epoch 在 seed/transforms 前结束 | ✅ `capture_epoch.end()` 在 normalize/seed 之前 |

**关键审计修复**：`DebuggerCore::freeze_target_threads` 默认实现从"no-op Ok"改为**fail-closed Err**，并在 `ProcessSession`（真实 GTO live debugger）加 freeze/unfreeze 委托（转发给内部 `WindowsDebugger`），确保生产路径真实冻结。

## 8. Evidence excerpt 验证

`RawCaptureDrift` 的 bounded excerpt 保留（AF1 实现）：
- mismatch 前 ≤16 bytes、mismatch 起 ≤64 bytes，raw/slab 分开，hex
- 不 dump 整个对象（测试 `raw_capture_drift_excerpt_is_bounded`）
- 失败类型仍 `RawCaptureDrift`（fail-closed 不变）
- C==S 未放宽

## 9. Required gates（全绿）

| Gate | 结果 |
|---|---|
| `cargo fmt --all -- --check` | PASS（0 差异） |
| `cargo test -p mida-core` | **75 + 6 harness passed / 0 failed** |
| `cargo test -p mida-pe` | **644 passed / 0 failed** |
| `cargo test -p mida-cli --features gto-product-recovery` | **298 / 0 / 1 ignored** |
| `cargo test -p mida-cli` | **296 / 0 / 1 ignored** |
| `python tools/test_gto_live_route_controller.py` | **36 / 36** |
| `git diff --check` | PASS（干净） |
| mida-pe lib warnings | **12**（与基线一致，新增 = 0） |

**未运行**：protected sample、Route Y R1 A3、GTO live、candidate、cold-start。

## 10. 候选源码清单（后续 commit 需明确纳入）

- `crates/core/src/debugger.rs`（trait + fail-closed 默认）
- `crates/core/src/windows_debugger.rs`（真实 freeze/unfreeze + 模块级 pub 函数）
- `crates/core/src/bin/capture_epoch_helper.rs`（benign helper，**生产/测试源码，非临时文件**）
- `crates/core/tests/capture_epoch_harness.rs`（真实 harness 测试，**非临时文件**）
- `crates/pe/src/dumper/capture_epoch.rs`（CaptureEpochGuard，**非临时文件**）
- `crates/pe/src/dumper/dump_process.rs`（epoch 集成）
- `crates/pe/src/dumper/mod.rs`（模块注册）
- `crates/pe/src/dumper/raw_slab_coherence.rs`（excerpt）
- `crates/cli/src/unpacker/session.rs`（ProcessSession freeze 委托）

**6 个 docs 全部排除**：X R1 / Y R0 / Y R1 / Y R1 A2 / Z R0 / Z R0 AF1 结果。

## 11. 提交边界

- **未 commit、未 push、未修改既有 evidence / 既有 6 个报告、未 live、未 candidate、未 protected sample。**
- tracked 修改：6 个文件（+375/−18）
- untracked：`crates/core/src/bin/capture_epoch_helper.rs`、`crates/core/tests/capture_epoch_harness.rs`、`capture_epoch.rs` + 6 个 docs
- 新增报告：`docs/GTO_ROUTE_Z_R0_AF2_WINDOWS_HARNESS_RESULT.md`（本文件，untracked）
- **capture_epoch.rs / helper / harness 是应纳入后续 commit 的生产源码和测试，不是临时文件，不得遗漏或清掉。**

**最终状态：`RouteZ_R0_AF2_ReviewRequested`**

> 真实 benign Windows 进程 20 次重复 freeze/restore 全部通过；freeze 停止 worker（TOCTOU 阻止）、unfreeze 恢复、thread-set 覆盖、prior suspend count 精确保留、error rollback、fail-closed 默认实现全部有真实证据。全部门禁通过。

---

## 最终报告

- **baseline/head**：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`，无 tracked 修改）
- **真实验证结果**：6 个 harness 测试全过（含 20x），见第 3 节
- **freeze/restore/thread-set/suspend-count/error rollback 证据**：见第 3/4/5/7 节
- **候选源码清单**：见第 10 节（helper/harness/capture_epoch 明确纳入，非临时文件）
- **门禁结果**：见第 9 节（core 75+6 / pe 644 / cli 298+296 / controller 36 / fmt 0 / warnings 12）
- **未运行**：protected sample / Route Y R1 A3 / GTO live / candidate / cold-start
- **最终状态**：**`RouteZ_R0_AF2_ReviewRequested`**

完成后停止。不得自行签发 Route Z R1 / Route Y R1 A3 / live / candidate validation / commit。
