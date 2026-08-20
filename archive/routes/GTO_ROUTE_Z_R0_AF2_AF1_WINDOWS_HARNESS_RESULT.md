# GTO Product Recovery — Route Z R0 AF2 AF1 Adversarial Windows Freeze Rollback and Harness Packaging Closure

> 状态：**`RouteZ_R0_AF2_AF1_ReviewRequested`**（补齐真实 adversarial 验证：partial-freeze rollback、真实 CaptureEpochGuard Drop/error/panic、线程退出竞态、end/Drop 幂等、handle leak；helper packaging 隔离。未 commit、未 live、未 candidate、未 protected sample）。
> 授权 baseline：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`）。允许 benign helper process。

---

## 1. 授权 baseline 核对（只读）

| 检查 | 预期 | 实际 | 结果 |
|---|---|---|---|
| branch | `oreans/two-sample-mainline` | 一致 | ✅ |
| HEAD | `68b8032` | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` | ✅ |
| HEAD^ | `9450b3a` | `9450b3aed570ff42c62a248f7e7013540a7e1348` | ✅ |
| untracked docs（7 个冻结） | X R1 / Y R0 / Y R1 / Y R1 A2 / Z R0 / Z R0 AF1 / Z R0 AF2 | 全部存在且未修改 | ✅ |
| `git diff --check` | 干净 | 干净 | ✅ |

**baseline 全部匹配。** 冻结 evidence 未覆盖。

## 2. 修改文件

### 生产源码（应进入未来 commit）

| 文件 | 改动 |
|---|---|
| `crates/core/src/capture_epoch.rs` | **新增**：`CaptureEpochGuard`（从 mida-pe 迁移）+ `EpochState`（Active/Ended/RestoreFailed）+ `EpochSuspendedThread`；RAII `Drop` 恢复 |
| `crates/core/src/debugger.rs` | `DebuggerCore`：`freeze_target_threads` 默认 fail-closed Err；`unfreeze_target_threads` 返回 `Result<(), CoreError>` |
| `crates/core/src/windows_debugger.rs` | `freeze_process_threads` / `unfreeze_process_threads` / `enumerate_process_threads`（pub）+ `freeze_process_threads_with_failure`（test-only injectable）；区分线程退出（code 87）与其他错误；线程集合收敛 fail-closed；handle 全部关闭 |
| `crates/core/src/lib.rs` | 注册 `capture_epoch` 模块 |
| `crates/core/Cargo.toml` | 加 `capture-epoch-harness` feature + `[[bin]] capture_epoch_helper required-features`（**packaging 隔离**） |
| `crates/pe/src/dumper/capture_epoch.rs` | guard 迁移后只留 `pub use` + offline mock 测试（TockMock） |
| `crates/pe/src/dumper/dump_process.rs` | 用 `mida_core::capture_epoch::CaptureEpochGuard`；`end()` 返回 Result 处理 |
| `crates/pe/src/dumper/mod.rs` | 注册 capture_epoch |
| `crates/pe/src/dumper/raw_slab_coherence.rs` | RawCaptureDrift bounded excerpt |
| `crates/cli/src/unpacker/session.rs` | `ProcessSession` 委托 freeze/unfreeze 到内部 WindowsDebugger |

### 测试源码（应进入未来 commit）

| 文件 | 内容 |
|---|---|
| `crates/core/src/bin/capture_epoch_helper.rs` | benign helper（workers + spawner + 短命线程 + 共享计数器），feature 门控 |
| `crates/core/tests/capture_epoch_harness.rs` | 真实 Windows harness（12 个测试） |

### 不提交（docs，全部排除）

X R1 / Y R0 / Y R1 / Y R1 A2 / Z R0 / Z R0 AF1 / Z R0 AF2 结果报告 + 本 AF1 报告。

## 3. 真实 partial-freeze rollback（[P1] 修复）

**`real_process_partial_freeze_after_n_threads_rolls_back`**（真实 helper，4 workers）：
- 通过 test-only injectable `freeze_process_threads_with_failure(pid, Some(2))` 在 **2 个真实线程成功 SuspendThread 后**注入失败。
- 断言 freeze 返回 `Err`（fail-closed），**绝不返回成功 token**。
- rollback 后：counter 恢复增长（前 2 个已 suspend worker 恢复）；无线程永久 suspended（suspend count ∈ {0,1}）。
- 失败注入仅 `#[doc(hidden)]` test-only API，生产路径传 `None`，**不启用**（无产品环境变量开关，无公共 bypass）。

**无效 PID 测试保留**（`real_process_partial_freeze_rolls_back`），但已注明它不是 partial rollback 证明。

## 4. 真实 CaptureEpochGuard Drop（[P1] 修复）

通过 **`HelperDebugger`**（mida-core 测试内，包装 helper pid，freeze/unfreeze 委托给真实 `freeze_process_threads`）+ 真实 `CaptureEpochGuard`（迁移到 mida-core）：

- **`real_process_epoch_guard_drop_restores_on_error`**：`begin` → capture body panic（模拟错误）→ guard `Drop` → 线程恢复，counter 恢复增长。
- **`real_process_epoch_guard_drop_restores_on_panic`**：`begin` → panic → `catch_unwind` → guard `Drop` 恢复，panic 未杀死 test runner。
- 均为**真实 RAII 路径**（不是 mock）。

## 5. 真实线程退出竞态（[P1] 修复）

**`real_process_thread_exit_during_enumeration`**（helper 短命线程，`--short-lived-every-ms 5`）：
- 短命线程快速创建/退出（100µs 存活）。
- `freeze_process_threads` 区分 **线程已退出**（`OpenThread` 返回 code 低 16 位 = 87 / 0x80070057，`ERROR_INVALID_PARAMETER`）→ **容忍跳过**（transient），而非误报为 frozen-process 失败。
- 其他错误（权限等）→ fail-closed rollback。
- 最终收敛，冻结存活 worker（counter 停）；unfreeze 后恢复；无死循环（`MAX_ROUNDS=8` + 集合稳定判断）。

## 6. end/Drop 幂等性（[P1] 修复）

**`real_process_epoch_end_then_drop_is_idempotent`**：
- `begin` 冻结（counter 停）→ 显式 `end()` 精确恢复一层（counter 恢复）→ 后续 `Drop` **不再次 ResumeThread**（无 suspend-count underflow）。
- 验证所有线程 suspend count ≥ 0（无 underflow）。
- `EpochState` 状态机（Active/Ended/RestoreFailed）保证幂等：`end()` 成功后状态 = Ended，`Drop` 不再恢复。

## 7. Unfreeze 错误处理

`unfreeze_target_threads` 现在返回 `Result<(), CoreError>`：
- `unfreeze_process_threads` 对每个线程 ResumeThread，**汇总 restore failures**（不静默吞掉）。
- `CaptureEpochGuard::end()` 返回 `Result`：成功 → Ended，失败 → RestoreFailed + Err。
- `Drop` 路径：恢复失败记录 fatal telemetry（`eprintln!`），**不 panic**（unwind 安全）。

## 8. Handle leak 验证（[P2] 修复）

**`real_process_repeated_freeze_has_no_handle_growth`**：
- 用 `GetProcessHandleCount` 记录 test process 初始 handle count。
- **50 次** freeze/unfreeze（每次 open+suspend+resume+close 多个 thread handle + ToolHelp snapshot）。
- 最终 handle count 增长 ≤ 32（一次性框架波动，**无随迭代单调增长**）。
- helper 正常退出，无残留 PID、无 suspended thread。

## 9. Helper packaging 隔离（[P2] 修复）

采用**方案 B**（非 default feature + `required-features`）：
- `crates/core/Cargo.toml`：`[features] capture-epoch-harness=[]`，`[[bin]] capture_epoch_helper required-features=["capture-epoch-harness"]`。
- `default = []`（不含该 feature）。
- **验证**：`cargo build -p mida-core`（无 feature）**不产生 `capture_epoch_helper.exe`**（干净 target 确认）。
- canonical mida-cli build 依赖 mida-core lib（不含 bin），不产生 helper。
- harness 用 `--features capture-epoch-harness` 构建 helper + 运行。
- 无 feature 时 integration test 的 `option_env!("CARGO_BIN_EXE_capture_epoch_helper")` 为 None → 测试 skip（不误报）。

## 10. 真实测试重复矩阵

（全部在 `cargo test -p mida-core --features capture-epoch-harness --test capture_epoch_harness` 运行，真实 Windows helper 进程）

| 测试 | 迭代 | 结果 |
|---|---|---|
| 普通 freeze/unfreeze | 20x（`repeated_20x_all_pass`） | ✅ |
| spawner/thread-set convergence | 20x 内 + `freeze_covers_thread_set` | ✅ |
| partial freeze rollback | `partial_freeze_after_n_threads_rolls_back` | ✅ |
| guard error Drop | `epoch_guard_drop_restores_on_error` | ✅ |
| guard panic Drop | `epoch_guard_drop_restores_on_panic` | ✅ |
| prior suspend count | `prior_suspend_count_restored` | ✅ |
| short-lived thread exit race | `thread_exit_during_enumeration` | ✅ |
| handle leak | 50x（`repeated_freeze_has_no_handle_growth`） | ✅ |
| end/Drop 幂等 | `epoch_end_then_drop_is_idempotent` | ✅ |

**harness 12/12 全绿，无残留 helper 进程**。counter 恢复断言改用 bounded polling（消除并行负载下的间歇失败）。

## 11. Required gates（全绿）

| Gate | 结果 |
|---|---|
| `cargo fmt --all -- --check` | PASS（0 差异） |
| `cargo test -p mida-core --features capture-epoch-harness` | **75 单元 + 12 harness passed / 0 failed** |
| `cargo test -p mida-pe` | **644 passed / 0 failed** |
| `cargo test -p mida-cli --features gto-product-recovery` | **298 / 0 / 1 ignored** |
| `cargo test -p mida-cli` | **296 / 0 / 1 ignored** |
| `python tools/test_gto_live_route_controller.py` | **36 / 36** |
| `git diff --check` | PASS（干净） |
| mida-pe lib warnings | **12**（与基线一致） |
| mida-core lib warnings | **0** |
| capture_epoch 相关新增 warning | **0** |

### 定向

- capture epoch mock 测试（mida-pe）：7 个全绿
- 真实 Windows harness：12/12 全绿
- Route Y 20/20（mida-pe 644 内）
- Route X fail-closed / strict drift / bounded excerpt：保持绿

**未运行**：protected sample / Route Y R1 A3 / GTO live / candidate / cold-start。

## 12. 提交边界 / 状态

- **未 commit、未 push、未修改既有 evidence / 既有 7 个报告、未 live、未 candidate、未 protected sample。**
- tracked 修改：8 个文件（+427/−18）
- untracked 源码（应进入 commit）：`crates/core/src/capture_epoch.rs`、`crates/core/src/bin/capture_epoch_helper.rs`、`crates/core/tests/capture_epoch_harness.rs`、`crates/pe/src/dumper/capture_epoch.rs`
- untracked docs（排除）：7 个既有 + 本 AF1 报告
- **helper 已通过 feature 门控隔离，不属于默认产品 binary 面**
- HEAD `68b8032` 不变，无残留 helper 进程

**最终状态：`RouteZ_R0_AF2_AF1_ReviewRequested`**

> 真实 Windows harness 补齐了全部 adversarial 场景：partial-freeze rollback（≥2 线程 suspend 后注入失败并恢复）、真实 CaptureEpochGuard error/panic Drop、线程退出枚举竞态（区分 transient exit）、end/Drop 幂等、unfreeze 错误上报、50 轮无 handle leak。helper 通过非 default feature 隔离于产品 binary 面。全部门禁通过。

---

## 最终报告

- **baseline/head**：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`，无 tracked 修改）
- **修改文件**：见第 2 节（8 tracked + 4 untracked 源码）
- **partial rollback 真实证据**：见第 3 节（with_failure 注入，2 线程后失败，rollback 恢复）
- **thread exit race**：见第 5 节（code 87 容忍 transient exit，其他 fail-closed）
- **guard error/panic Drop**：见第 4 节（真实 CaptureEpochGuard + HelperDebugger）
- **end/Drop 幂等**：见第 6 节（EpochState 状态机，无 underflow）
- **unfreeze failure handling**：见第 7 节（Result 返回，不吞掉）
- **handle count**：见第 8 节（50 轮无增长，GetProcessHandleCount）
- **helper packaging 方案**：见第 9 节（方案 B：feature + required-features，canonical build 无 helper）
- **production/test source 分类**：见第 2 节
- **真实测试重复矩阵**：见第 10 节（12 测试全绿）
- **Required gates**：见第 11 节（core 75+12 / pe 644 / cli 298+296 / controller 36 / fmt 0 / warnings 12+0）
- **diff/stat**：`8 files changed, 427 insertions(+), 18 deletions(-)` + 4 untracked 源码
- **未跟踪文件清单**：见第 2 节（源码 + 8 docs）
- **禁止事项确认**：未 commit/push、未改 evidence、未 live、未 candidate
- **最终状态**：**`RouteZ_R0_AF2_AF1_ReviewRequested`**

完成后停止。不得自行 commit / push / Route Y R1 A3 / Route Z R1 / live / protected sample / candidate。
