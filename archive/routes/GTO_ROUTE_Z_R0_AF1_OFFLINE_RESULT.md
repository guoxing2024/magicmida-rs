# GTO Product Recovery — Route Z R0 AF1 Atomic Capture Epoch and Drift Evidence Closure

> 状态：**`RouteZ_R0_AF1_ReviewRequested`**（离线实现并验证一致 capture epoch + RawCaptureDrift 证据增强。未 commit、未 live、未 candidate）。
> 授权 baseline：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`）。不授权 live。

---

## 1. 授权 baseline 核对（只读）

| 检查 | 预期 | 实际 | 结果 |
|---|---|---|---|
| branch | `oreans/two-sample-mainline` | 一致 | ✅ |
| HEAD | `68b8032` | `68b8032d6c3600e7aaa8b9498b77e636b67d58e9` | ✅ |
| HEAD^ | `9450b3a` | `9450b3aed570ff42c62a248f7e7013540a7e1348` | ✅ |
| 无 tracked 修改 | 是 | 是（改动前） | ✅ |
| untracked docs | 5 个 | 5 个 | ✅ |
| `git diff --check` | 干净 | 干净 | ✅ |

**baseline 全部匹配。** 三套冻结 evidence（X1 / NotRun / A2）+ Z R0 analysis 均未修改。

## 2. 根因回顾（来自 Route Z R0）

- child `0x3327260`（RVA `0x144400`）与主堆 slab 是**两次独立 `ReadProcessMemory`**（间隔约 249 ms）。
- target 无全进程冻结（`direct dump mode`，main thread resumed），两次读取之间 target 运行。
- 严格 extent（ObservedAllocation）要求 `C == S`；对象在两次读取间被修改 → 假阳性 `RawCaptureDrift`。
- 修复方向：**一致 capture epoch**（C 与 S 在同一冻结 epoch 内读取），而非放宽 seed 校验。

## 3. 现有暂停模型审计

| 项 | 结论 |
|---|---|
| post-attach 模型 | main thread 在 `resume_post_attach_main_thread` 后 resume；`direct dump mode` 无 debug port |
| 全进程冻结 | **无**（无 debugger stop-the-world，无 `NtSuspendProcess`） |
| `DebuggerCore` 冻结原语 | 之前**无**；本次新增 `freeze_target_threads` / `unfreeze_target_threads` |
| `read_memory` | 直接 `ReadProcessMemory`（`windows_debugger.rs:958`），无冻结 |
| 现成 RAII guard | 无；本次新增 `CaptureEpochGuard` |
| double-suspend 风险 | 处理：记录 `prior_suspend_count`，drop 只抵消自己的一次 SuspendThread |
| 原本 suspended 线程 | 处理：记录 prior，drop 恢复到进入前状态，不错误恢复 |

## 4. 修改文件

| 文件 | 改动 |
|---|---|
| `crates/core/src/debugger.rs` | `DebuggerCore` trait 新增 `freeze_target_threads` / `unfreeze_target_threads`（默认 no-op） |
| `crates/core/src/windows_debugger.rs` | 实现真实线程冻结：ToolHelp 枚举 + OpenThread/SuspendThread，二次枚举至线程集合稳定；unfreeze 精确恢复 |
| `crates/pe/src/dumper/capture_epoch.rs` | **新增** `CaptureEpochGuard`（RAII）+ `EpochSuspendedThread` + `drift_excerpt` 测试 |
| `crates/pe/src/dumper/dump_process.rs` | 在 `detect_containers` 前 begin epoch，capture 调用走 `capture_epoch.debugger()`，`capture_heap_slab` 后 end；epoch telemetry |
| `crates/pe/src/dumper/mod.rs` | 注册 `capture_epoch` 模块 |
| `crates/pe/src/dumper/raw_slab_coherence.rs` | `RawCaptureDrift` 增加 `raw_child_excerpt` / `raw_slab_slice_excerpt`；`raw_capture_drift_error` 填充 bounded excerpt；`drift_excerpt` 辅助 |

diff 统计：`5 files changed, 247 insertions(+), 18 deletions(-)`（+ 新增 `capture_epoch.rs`）。

## 5. Capture epoch 边界

```
CAPTURE_EPOCH_BEGIN  (CaptureEpochGuard::begin → freeze every target thread)
  → detect_containers            (live read)
  → detect_heap_globals          (live read: raw child C)
  → capture_heap_slab            (live read: authoritative slab S)
CAPTURE_EPOCH_END    (CaptureEpochGuard::end → restore every thread)
  → normalize_authoritative_slabs   (offline)
  → reconcile_duplicate_heap_globals (offline)
  → capture_identity_bind / seed / transforms / overlay / runtime plan / manifest (offline)
```

核心不变量（工单 4 节）：
- **C 与 S 来自同一冻结 epoch** ✓（两者都在 guard 存活期间读取）
- 两次读取期间任何 target 线程不得继续执行 ✓（SuspendThread 冻结）
- `transform_input_seed` 不在冻结区间 ✓（seed 在 end() 之后离线执行）
- 不通过 S 覆盖 C 伪造一致性 ✓（C、S 独立保留，strict `C==S` 仍校验）
- 禁止无条件 ResumeThread / 错误恢复原本 suspended 线程 ✓（记录 prior，只抵消自己）

## 6. Pause/resume 模型

- **freeze（WindowsDebugger）**：`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid)` 枚举所有线程 → 对非当前线程 `OpenThread(THREAD_SUSPEND_RESUME|THREAD_QUERY_INFORMATION)` + `SuspendThread`（返回 prior suspend count）→ **再次枚举直到线程集合稳定**（处理线程 spawn）。
- **记录**：`(thread_id, prior_suspend_count)`。
- **restore**：对每个 suspend 的线程 `ResumeThread` **恰好一次**，恢复到进入 epoch 前的 suspend count。原本 suspended（prior ≥ 1）的线程，其 prior 被保留（我们只抵消自己那次 SuspendThread）。
- 禁止暂停当前线程（跳过 `GetCurrentThreadId`）。

## 7. Error rollback

`CaptureEpochGuard` 是 RAII：`Drop` 总是调用 `end()`（unfreeze），**包括 panic / early-return / error 路径**。测试 `capture_epoch_restores_threads_on_error` 用 `catch_unwind` 验证 panic 后线程被恢复。

## 8. Telemetry

dump_process 在 epoch 结束时记录（Route Z R0 AF1）：
- `suspended_thread_count`
- `suspended_thread_ids`
- `epoch_elapsed_ms`
- `epoch_started_ms`

这**证明** child（detect_heap_globals）和 slab（capture_heap_slab）同属一个冻结 epoch（同一 guard 作用域）。

## 9. RawCaptureDrift evidence excerpt schema

`RawCaptureDrift` 新增两个诊断字段（hex 编码，严格 bounded）：
- `raw_child_excerpt`：mismatch 前 ≤16 字节 + mismatch 起 ≤64 字节
- `raw_slab_slice_excerpt`：同上（slab slice 侧）

`drift_excerpt(slice, mismatch_offset, 16, 64)` 保证：
- 长度上限：`(16 + 64)` 字节 → hex `≤ 240 chars`
- **从不** dump 整个 heap object / slab
- 不记录不相关内存
- 不改变 `RawCaptureDrift` 的 fail-closed 语义（excerpt 仅诊断）

测试 `raw_capture_drift_excerpt_is_bounded` 验证 offset 0 和非零 offset 均 bounded。

## 10. 测试矩阵

### Route Z R0 AF1 新增测试（7 个，全绿）

| 测试 | 验证点 |
|---|---|
| `capture_epoch_prevents_child_slab_toctou` | mock frozen → child/slab 两次读一致（同一 epoch） |
| `capture_without_epoch_reproduces_child_slab_drift` | mock running → 两次读不同（复现 A2 类 drift） |
| `capture_epoch_restores_threads_on_success` | guard drop 后线程恢复 |
| `capture_epoch_restores_threads_on_error` | panic 路径线程恢复（RAII） |
| `capture_epoch_preserves_preexisting_suspend_count` | prior suspend count 保留 |
| `capture_epoch_handles_thread_set_change` | 多线程集合处理 |
| `raw_capture_drift_excerpt_is_bounded` | excerpt 长度上限 |

### 回归（保持绿）

- `route_y_r0_*` **20 / 20**
- `route_x_af1_same_base_size_change_fails_closed` ✓（未声明漂移仍 fail-closed）
- `route_x_r0_participant_set_change_fails_closed` ✓
- `r0g_strict_observed_allocation_drift_fails_closed` ✓（strict C==S 仍拒绝）
- `r0g_backing_object_drift_fails_closed` ✓
- mida-pe **644 / 0**

## 11. Required gates

| Gate | 结果 |
|---|---|
| `cargo fmt --all -- --check` | PASS（0 差异） |
| `cargo test -p mida-pe` | **644 passed / 0 failed** |
| `cargo test -p mida-cli --features gto-product-recovery` | **298 / 0 / 1 ignored** |
| `cargo test -p mida-cli` | **296 / 0 / 1 ignored** |
| `python tools/test_gto_live_route_controller.py` | **36 / 36** |
| `git diff --check` | PASS（干净） |
| mida-pe lib warnings | **12**（与基线一致，新增 = 0） |

### 定向运行

- Route Z 新增 7 测试：全绿
- `route_y_r0_*`：20/20
- `route_x_af1_same_base_size_change_fails_closed`：✓
- strict raw capture drift：✓
- thread suspension/restore：✓

**未运行 live**（本工单不授权）。

## 12. 已知风险 / 诚实边界

1. **真实 Windows 线程冻结效果的离线验证边界**：`CaptureEpochGuard` 的**行为契约**已离线验证（mock：freeze 时 C==S、running 时 C!=S、restore 调用、prior count、thread set）。但**真实 `SuspendThread` 冻结真实 target 的所有线程**依赖 OS 原语语义（`SuspendThread` 是可靠同步原语，其"挂起线程"语义由 OS 保证），无法在无 live target 的离线测试中直接证明。这是 `direct dump mode` 下标准的冻结做法。
   - 已确认：Windows API 语义保证 SuspendThread 冻结线程；ToolHelp 枚举 + 二次枚举至稳定是标准做法。
   - **未离线证明**：真实进程所有线程的挂起效果（需 live 或真实 Windows 进程测试确认）。
   - **诚实标注**：若审计要求真实进程级冻结的离线证明，则此实现尚需一个最小真实进程验证 harness（本工单未含）。

2. **epoch identity 字段**：工单 8 节允许本轮先记录在 telemetry（不扩 schema）。已用 telemetry（suspended_thread_ids / elapsed / started_ms）证明 child/slab 同属一 epoch。未给 `RawSlabCapture` 加持久 `capture_epoch_id` 字段（避免大规模 schema 改动），因此测试 9 `different_capture_epoch_cannot_be_mixed` 未实现（工单允许"若实现 epoch identity"）。

3. **`reconcile_duplicate_heap_globals` 在 freeze 外**：它不读 live memory（用已捕获的 child 和 slab），放 freeze 外符合工单 7 节（freeze 只含 live 读取）。逻辑正确。

4. **freeze 失败路径**：若 `freeze_target_threads` 失败（如无法枚举），`begin` 返回 `PeError::GtoStage`（`capture_epoch_freeze`），dump 失败关闭，不产生候选。

## 13. 提交边界 / 状态

- **未 commit、未 push、未修改既有 evidence / 既有 X/Y/Z R0 报告、未 live、未 candidate。**
- tracked 修改：5 个文件（debugger.rs、windows_debugger.rs、dump_process.rs、mod.rs、raw_slab_coherence.rs）
- untracked：`capture_epoch.rs`（新）+ 5 个 docs（X R1 / Y R0 / Y R1 / Y R1 A2 / Z R0）
- 新增报告：`docs/GTO_ROUTE_Z_R0_AF1_OFFLINE_RESULT.md`（本文件，untracked）
- 冻结 evidence 未修改（A2 controller_run.json 14:56、NotRun 14:41 未变）

**最终状态：`RouteZ_R0_AF1_ReviewRequested`**

> 一致 capture epoch 已实现（child C 与 slab S 在同一冻结 epoch 读取），RawCaptureDrift 证据已增强（bounded excerpt），fail-closed 语义不变，declared size transition 语义不变。
> 诚实边界：真实 Windows 线程冻结效果依赖 OS 原语语义，离线仅验证 guard 行为契约；如需真实进程级证明，需一个最小真实进程验证 harness（另行授权）。

---

## 最终报告

- **baseline/head**：`68b8032`（branch `oreans/two-sample-mainline`，HEAD^ `9450b3a`，无 tracked 修改）
- **修改文件**：见第 4 节（5 tracked + 1 新增 capture_epoch.rs）
- **capture epoch 边界**：见第 5 节
- **pause/resume 模型**：见第 6 节
- **error rollback**：见第 7 节（RAII，panic 安全）
- **telemetry**：见第 8 节（suspended count / ids / elapsed / started）
- **evidence excerpt schema**：见第 9 节（bounded hex，mismatch ±64）
- **测试矩阵**：见第 10 节（7 新增 + 回归全绿）
- **门禁结果**：见第 11 节（644/298/296/36，warnings 12）
- **已知风险**：见第 12 节（真实冻结需 live 确认；epoch identity 走 telemetry）
- **diff/stat**：`5 files changed, 247 insertions(+), 18 deletions(-)` + 新增 capture_epoch.rs
- **最终状态**：**`RouteZ_R0_AF1_ReviewRequested`**

完成后停止。不得自行签发 Route Z R1 / Route Y R1 A3 / live / candidate validation / commit。
