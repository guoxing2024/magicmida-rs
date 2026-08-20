# GTO Product Recovery — Route V R0 Post-Capture Stage Timing and Deadline Evidence Closure

**日期：** 2026-08-10
**授权：** Route V R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate / 0 cold-start）
**起点提交：** `db129d6`（Route U R0，`RouteU_R0_AuditFix1Accepted`）
**分支：** `oreans/two-sample-mainline`

> 本文档是 **离线 work order**。Route V R0 是离线 telemetry 接入与 deadline 证据闭环，
> 非 live run。它只增加诊断观察（stage enter/exit/error + controller deadline 证据），
> **不改变任何业务语义**（见 V0-D）。

---

## 1. 背景

Route U R1 live run 被判定 `RouteU_R1_CandidateNotReady`（controller timeout，env 契约
已通过）。审计后确认时间线：

- main heap slab（`0x964000`）在 start + ~10s 内被捕获；
- 随后有一段约 **110s 的静默窗口**（`11:24:14.722Z` 捕获 main slab →
  `11:26:04.969Z` controller timeout，约 110.247s 无日志增长）；
- controller 当时 120s 总超时先于 candidate 完成触发。

`all_slabs`/candidate 均未产出，route 未消耗 candidate。Route U 冻结。

**核心开放问题：** 捕获 main slab 之后、candidate emit 之前，`dump_process` 有约 110s
花在哪？必须用 stage 级 telemetry 定位，而不是猜测。Route V R0 的职责是：给每个
post-capture 阶段加上非语义的 enter/exit/error 计时，并在 controller 侧记录 deadline /
输出增长证据，从而在下一个 live run 精确指出耗时热点。

## 2. 工单范围（V0-A .. V0-E）

### V0-A：post-capture 阶段 enter/exit/error telemetry（生产代码）

在 `crates/pe/src/dumper/` 生产代码中，为下列阶段添加 **非语义** 计时遥测：
每个阶段记录 `stage` / `event=enter|exit|error` / `monotonic_elapsed_ms` /
`stage_elapsed_ms` / `item_count` / `byte_count`。**不记录任何敏感内容**，不参与
dump 成败判定。

新增模块 `crates/pe/src/dumper/stage_timing.rs`：
- `StageGuard`（RAII：构造记 `enter`，Drop 记 `exit`；`with_item_count` /
  `with_byte_count` / `with_stats` 附加计数；`error()` 显式记 `error`，且 Drop
  不再补发假的 `exit`）；
- `run_stage(stage, stats, closure)`：闭包式 enter→(exit|error)，错误用 `String` 传递
  （仅 `Debug`/display 记录，不改语义）；
- `StageStats { item_count, byte_count }`。

需埋点的阶段（V0-A 要求 13 项）：
```
capture_heap_slab
normalize_authoritative_slabs
reconcile_duplicate_heap_globals
capture_identity_bind
capture_coverage_bind
raw_children_from_capture
transform_input_seed
<each recorded transform>            # 通过 apply/try_apply_recorded_transform(transform_id)
raw_slab_overlay
runtime_rebase_plan_build
runtime_rebase_plan_validation       # = runtime_rebase_plan_build 的错误路径
manifest_construction
candidate_emit
```

约束：埋点 **不改变** slab 内容、capture 数量、normalize/digest、fail-closed 逻辑、
transform/planner/candidate 输出。

### V0-B：controller deadline 证据（`tools/gto_live_route_controller.py`）

`controller_run.json` 增加：
```
configured_timeout_sec          # 本次配置的硬超时秒数
last_output_growth_utc          # 最后一次观察到 stdout/stderr 增长的 UTC 时间
last_output_size                # 最后一次观察到的累计输出字节数
last_observed_stage             # 日志中最后出现的 gto_stage_<...> 的 stage 名（best-effort）
last_observed_stage_event       # 该 stage 的 event（enter|exit|error）
silence_before_timeout_ms       # 超时触发前距最后一次输出增长的静默时长（仅超时时有值）
```

实现要点：
- 运行 loop 从 `proc.wait(timeout=...)` 阻塞改为**轮询**（0.25s 间隔），从而在子进程运行中
  采样输出文件增长与最后 stage；
- stage 解析为 **recording-only**：从 stdout/stderr 原始 `child.*.bin` 尾部
  （last 8KiB）best-effort 匹配 Rust CLI 的 `stage=... event=...` 行，**不驱动成败**；
- 静默时长 = `elapsed - last_growth_offset`（相对 t0 的偏移，勿混绝对 monotonic）。

### V0-C：下一硬超时预算（600s）由离线策略测试判定

- candidate：将 controller core 与 PS driver 的默认 `--timeout` 从 `120.0` 提升为
  `600.0`（足以容纳 ~110s 静默 + 后续 emit）；
- **不加入** aggressive no-progress kill：`silence_before_timeout_ms` 仅记录，绝不用于
  提前终止（若未来加入 no-progress kill，必须 ≥300s）；
- 用离线策略测试断言：core 默认 600、driver 默认 600、存在总超时 kill guard、且
  静默值不参与 kill 判定。

### V0-D：V0 内禁止语义优化（约束记录）

本 route **只加观察，不改语义**。明确禁止（并记录为审计承诺）：
- 禁止改动 slab 内容 / capture 数量 / normalize/digest；
- 禁止跳过 normalize / overlay / fail-closed / coverage 门禁；
- 禁止改动 transform / planner / candidate 输出；
- 禁止放松任何 fail-closed 或放行条件。

任何"顺手优化耗时"的改动都不属于 V0，且会破坏本 route 的定位能力。

### V0-E：离线测试

Rust（`crates/pe/src/dumper/stage_timing.rs`）：
```
route_v_r0_stage_enter_exit_order      # 成功阶段严格 enter→exit
run_stage_success_and_error_order      # run_stage 成功 enter→exit；错误 enter→error
stage_error_has_no_false_exit          # 显式 error() 后 Drop 不再补发假 exit
stage_counts_attached_via_with_stats   # with_stats 计数随 exit 上报
```
（需 `tracing-subscriber` dev-dependency，测试专用；生产 `mida-pe` 不引入。）

Python（`tools/test_gto_live_route_controller.py`）：
```
route_v_r0_controller_records_configured_timeout
route_v_r0_controller_records_last_output_progress
route_v_r0_timeout_records_silence_duration
route_v_r0_timeout_preserves_binary_evidence
route_v_r0_600s_policy_is_explicit
```
（用真实短命/沉睡子进程，经 controller 轮询 loop，验证 deadline 证据与二进制证据保留。）

## 3. 验收门槛

- `cargo test -p mida-pe`：≥593 通过、0 失败（原 593 不退化 + 4 项新 stage_timing）。
- `python tools/test_gto_live_route_controller.py`：14 原测不退化 + 5 新测，0 失败。
- `controller_run.json` 含 V0-B 六字段；`configured_timeout_sec` 与传入一致；
  `silence_before_timeout_ms` 仅超时时非 None 且 ≥0。
- V0-D 无语义优化（git diff 仅 telemetry + controller 证据 + 测试 + docs）。

## 4. 提交边界

包含：
```
crates/pe/src/dumper/stage_timing.rs        (新增)
crates/pe/src/dumper/mod.rs
crates/pe/src/dumper/dump_process.rs
crates/pe/src/dumper/raw_slab_coherence.rs
crates/pe/Cargo.toml
tools/gto_live_route_controller.py
tools/run_gto_live_route_controller.ps1
tools/test_gto_live_route_controller.py
docs/GTO_ROUTE_V_R0_OFFLINE_WORK_ORDER.md
docs/GTO_ROUTE_V_R0_OFFLINE_RESULT.md
```
排除：`docs/GTO_ROUTE_U_R1_LIVE_RESULT.md`（Route U R1 独立报告）、acceptance、
TrustToken、vault、resolver、protected sample、Route T transform/coherence 逻辑。
