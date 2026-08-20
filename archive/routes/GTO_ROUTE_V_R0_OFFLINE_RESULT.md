# GTO Product Recovery — Route V R0 Post-Capture Stage Timing and Deadline Evidence Closure

**日期：** 2026-08-10
**授权：** Route V R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate / 0 cold-start）
**起点提交：** `db129d6`（Route U R0，`RouteU_R0_AuditFix1Accepted`）
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteV_R0_AuditFix1ReviewRequested`**

> 本文档是 **离线结果**。Route V R0 是离线 telemetry 接入与 deadline 证据闭环，非 live
> run，未生成 candidate。V0-A..V0-E 全部完成。
> 2026-08-10：AF1 审计 `RouteV_R0_NotReady`（2 缺口：`cargo fmt --check` 失败、
> `monotonic_elapsed_ms` 字段名实不符——不是全局单调时间），已修复
> （rustfmt 全绿 + pipeline 级 monotonic anchor + 2 项新测试）。

---

## 1. 背景

Route U R1 live run 因 controller 120s 总超时先于 candidate 完成触发而判定
`RouteU_R1_CandidateNotReady`。审计时间线确认 main heap slab（`0x964000`）在
start + ~10s 捕获，随后有约 **110s 静默窗口**（`11:24:14.722Z` → `11:26:04.969Z`，
~110.247s 无日志增长）。捕获后、emit 前的耗时热点未知。

Route V R0 只增加**观察**，不改语义：给 post-capture 每个阶段加 enter/exit/error 计时
（V0-A），在 controller 记录 deadline/输出增长证据（V0-B），把下一硬超时预算设为 600s
（V0-C），并明确 V0 内禁止语义优化（V0-D），附全套离线测试（V0-E）。

## 2. 实现（V0-A .. V0-E）

### V0-A：post-capture 阶段 telemetry（生产代码）

新增 `crates/pe/src/dumper/stage_timing.rs`：
- `StageGuard`：构造记 `enter`，Drop 记 `exit`；`with_item_count` / `with_byte_count` /
  `with_stats` 附加计数；`error()` 显式记 `error` 且 Drop 不再补发假 `exit`。
- `run_stage(stage, stats, closure)`：enter→(exit|error)，错误仅 display/Debug 记录，
  不改语义。
- `StageStats { item_count, byte_count }`。
- stage 名与闭包签名用 `&str`（非 `&'static str`），以承载动态 transform_id。

13 项阶段全部埋点（`grep` 逐项核对）：

| 阶段 | 方式 | 位置 |
|---|---|---|
| capture_heap_slab | `StageGuard` | dump_process.rs:892 |
| normalize_authoritative_slabs | `run_stage` | dump_process.rs:925 |
| reconcile_duplicate_heap_globals | `StageGuard` | dump_process.rs:953 |
| capture_identity_bind | `run_stage` | dump_process.rs:963 |
| capture_coverage_bind | `run_stage` | dump_process.rs:983 |
| raw_children_from_capture | `StageGuard` | dump_process.rs:1000 |
| transform_input_seed | `run_stage` | dump_process.rs:1035 |
| 每个 recorded transform | `run_stage(transform_id)` | raw_slab_coherence.rs |
| raw_slab_overlay | `run_stage` | dump_process.rs:1399 |
| runtime_rebase_plan_build | `run_stage` | dump_process.rs:1691 |
| runtime_rebase_plan_build_validation | build 错误路径（组合计时） | dump_process.rs:1715 |
| manifest_construction | `StageGuard` | dump_process.rs:2198 |
| candidate_emit | `StageGuard` | dump_process.rs:1979 |

`try_apply_recorded_transform<E>` 因泛型 `E` 用 `StageGuard` 直记（`Debug` 记录），
业务结果与 `E` 类型不变。

#### V0-AF1：全局 monotonic timeline（`stage_timing.rs`）

AF1 修正 `monotonic_elapsed_ms` 名实不符：原实现把 `monotonic_elapsed_ms` 直接等于
单 stage 耗时（每阶段从 0 重新计），无法提供跨 stage 全局单调时间线。现引入进程级 anchor：

```
static PIPELINE_START: OnceLock<Instant> = OnceLock::new();
fn pipeline_elapsed_ms() -> i64 {
    PIPELINE_START.get_or_init(Instant::now).elapsed().as_millis() as i64
}
```

- `enter`：`monotonic_elapsed_ms = pipeline_elapsed_ms()`，`stage_elapsed_ms = 0`；
- `exit/error`：`monotonic_elapsed_ms = pipeline_elapsed_ms()`，
  `stage_elapsed_ms = stage_started.elapsed()`。

语义：`monotonic_elapsed_ms` 跨所有 stage 单调不减、可直接比较相对位置；
`stage_elapsed_ms` 仍为单 stage 自身耗时（进入即 0）。纯观察，不改业务。

### V0-B：controller deadline 证据（`tools/gto_live_route_controller.py`）

`run_child` 从 `proc.wait(timeout)` 阻塞改为 **0.25s 轮询**，子进程运行中采样输出增长与
最后 stage。`controller_run.json` 新增：
```
configured_timeout_sec          # 与传入 timeout 一致
last_output_growth_utc          # 最后一次输出增长 UTC
last_output_size                # 累计输出字节（stdout+stderr）
last_observed_stage             # 日志最后 gto_stage_ 的 stage 名（best-effort）
last_observed_stage_event       # enter|exit|error
silence_before_timeout_ms       # 仅超时时非 None，= 距上次增长的静默毫秒
```
- 新增 `_sample_last_stage()`：读 `child.*.bin` 尾部（last 8KiB），正则匹配
  `stage=... event=... gto_stage_...`，**recording-only**，不驱动成败。
- 静默时长用 `elapsed - last_growth_offset`（相对 t0 偏移），修正了初版误混绝对 monotonic
  导致的负值 bug。
- 预检拒绝路径（exit 6）也写入六字段默认值。

### V0-C：下一硬超时预算 600s

- `gto_live_route_controller.py` `--timeout` 默认 `120.0 → 600.0`；
- `run_gto_live_route_controller.ps1` `$Timeout` 默认 `120.0 → 600.0`；
- **未加入** aggressive no-progress kill；`silence_before_timeout_ms` 仅记录，绝不用于
  提前终止。若未来加入，必须 ≥300s。

### V0-D：V0 内禁止语义优化（审计承诺）

本 route 只加观察。git diff 核对：无 slab 内容 / capture 数量 / normalize/digest /
fail-closed / coverage 门禁 / transform / planner / candidate 改动。唯一生产行为变化是
`MIDA_GTO_NO_BYPASS` 相关 controller 证据与轮询 loop（观测性），无业务语义变化。

### V0-E：离线测试

Rust（`stage_timing.rs`，需 `tracing-subscriber` dev-dep，测试专用）：
```
route_v_r0_stage_enter_exit_order      ✓  enter→exit 严格有序
run_stage_success_and_error_order      ✓  enter→exit / enter→error
stage_error_has_no_false_exit          ✓  显式 error 后无假 exit
stage_counts_attached_via_with_stats   ✓  计数随 exit 上报
route_v_af1_monotonic_elapsed_is_global_and_nondecreasing  ✓  monotonic 跨 stage 单调不减
route_v_af1_stage_elapsed_resets_but_pipeline_elapsed_does_not ✓  stage_elapsed 归零、pipeline 不归零
```
`cargo test -p mida-pe`：**599 passed / 0 failed**（原 593 不退化 + 4 新 V0-E + 2 新 V0-AF1）。

Python（`tools/test_gto_live_route_controller.py`，用真实短命/沉睡子进程）：
```
route_v_r0_controller_records_configured_timeout   ✓  configured_timeout_sec=12.5, rc=0
route_v_r0_controller_records_last_output_progress ✓  size=139, stage=capture_heap_slab, event=enter
route_v_r0_timeout_records_silence_duration        ✓  timed_out, silence=750ms, action=terminate_tree
route_v_r0_timeout_preserves_binary_evidence       ✓  stdout.bin 保留, sha 存在
route_v_r0_600s_policy_is_explicit                 ✓  core600, driver600, records_silence, no kill-on-silence
```
原 Route U R0+AF1 14 项不退化。总计 **19 passed / 0 failed**。

## 3. 验收结论

| 门槛 | 结果 |
|---|---|
| `cargo test -p mida-pe` | **599/0** ✓（原 593 不退化 + 4 新 V0-E + 2 新 V0-AF1） |
| `python tools/test_gto_live_route_controller.py` | **19/0** ✓（14 原测 + 5 新） |
| controller_run.json V0-B 六字段 | ✓（含预检拒绝路径默认值） |
| `configured_timeout_sec` 与传入一致 | ✓ |
| `silence_before_timeout_ms` 仅超时非 None 且 ≥0 | ✓ |
| V0-D 无语义优化 | ✓（diff 仅 telemetry + 证据 + 测试 + docs） |

**终态：`RouteV_R0_AuditFix1ReviewRequested`**。等待 Route V R1 授权：single live truth
run，用新 600s 硬超时 + stage 级 telemetry（全局单调时间线）+ controller deadline 证据，
在真实 candidate 上定位 ~110s 静默窗口的确切归属（预期落在某个 post-capture transform /
overlay / rebase / emit）。

### V0-AF1 验收（阻断补齐后）

| 门槛 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | **0** ✓ |
| `cargo test -p mida-pe` | **599/0** ✓（+2 AF1） |
| `cargo test -p mida-cli`（gto） | 基线不变 ✓（独立 `--lib` 测 **294/0/1**，mida-cli 源码未被 AF1 触碰；审计基线 296/0/1 含额外 target 统计） |
| `python tools/test_gto_live_route_controller.py` | **19/0** ✓ |
| `git diff-tree --check` | **0** ✓ |
| `monotonic_elapsed_ms` 跨 stage 非递减 | ✓（新测试断言） |
| `stage_elapsed_ms` 仍为单 stage 耗时 | ✓（每 enter 归零） |
| AF1 commit 仅含 rustfmt + monotonic 修正 + 文档 | ✓ |

## 4. 已知风险 / 说明

- `_sample_last_stage` 依赖 Rust CLI 日志格式（`stage=... event=... gto_stage_...`）不变；
  若格式变化，`last_observed_stage/event` 会回到 None，但不影响其它字段与运行。
- 轮询间隔 0.25s 使 `last_output_growth_utc` 精度 ~250ms，足够区分 ~110s 级热点。
- `silence_before_timeout_ms` 在自然退出时为 None（仅超时场景有意义）。
- `monotonic_elapsed_ms` 的 anchor（`PIPELINE_START`）是进程级 `OnceLock`：同一进程内跨
  stage 单调；若同一进程连续多次 dump，时间线跨 dump 继续累加，不归零（不改变业务）。
  单次 live run 只 dump 一次，anchor 语义成立。
