# GTO Product Recovery — Route X R0 Raw-Coherence Participant-Set and Transform Ledger Identity Closure

**日期：** 2026-08-10
**授权：** Route X R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate）
**起点提交：** `4491b5b44bf73f44f458a72b7af8cb0de8e5a628`（Route W R0 AF1）
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteX_R0_AuditFix1Rev1ReviewRequested`**

> 本文档是 **离线结果**。Route X R0 是离线实现 + 测试，未 commit（等待复审），未 live。
> 2026-08-10：AF1 审计 `RouteX_R0_AuditFix1Required`（4 个 P0：seeding 未用 canonical
> predicate；identity 只有 live_ptr；全局 run membership validator 缺失；full-pipeline 测试
> 绕过生产链）。已全部修复（X0-AF1）。
> Rev1 审计 `RouteX_R0_AuditFix1Rev1Required`（唯一新增 warning：`check_identity` 的无效
> `mut`）。已删除该 `mut`；cargo check 警告集与基线 `4491b5b` 逐项一致（13 = 13，无 Route X
> 归因警告）。门禁全部在隔离 target 复跑。

---

## 1. 根因 → 代码映射

Route W R1 的 `raw_slab_overlay` 失败（`TransformRunLedgerInvalid`，run[3464]，空
`child_capture_id`）根因是 **raw-coherence participant-set 不变量被破坏**：

| # | 根因环节 | 代码 |
|---|---|---|
| 1 | image-inline 构造用默认 `CaptureExtentEvidence`，capture_id 空 | `HeapGlobalSnapshot` 构造（测试/生产 fixture） |
| 2 | `validate_raw_coherence_capture_identities` 显式跳过 image-inline | `raw_slab_coherence.rs:validate_raw_coherence_capture_identities` |
| 3 | `raw_children_from_capture` 也跳过 image-inline | `raw_slab_coherence.rs:raw_children_from_capture` |
| 4 | `scrub_uncaptured_heap_pointers` 修改所有 heap globals（含 image-inline） | `heap_global_snapshot.rs:scrub_uncaptured_heap_pointers` |
| 5 | `diff_transform_write_runs` 对全部 before/after 快照 **positional zip** 生成 run，**未应用 participant predicate** | `raw_slab_coherence.rs:diff_transform_write_runs`（修复前） |

修复前 `diff_transform_write_runs` 用 `before.iter().zip(after.iter())` 且无条件
`child_capture_id: a.extent_evidence.capture_id.clone()` —— 一个不属于 raw coherence 的
image-inline 对象因此带着空 ID 进入 raw-overlay ledger，被全局 validator 正确拒绝。

## 2. 实现（X0-A .. X0-F）

### X0-A：唯一 canonical raw-coherence participant predicate

新增 `HeapGlobalSnapshot::is_raw_coherence_participant()`（`heap_global_snapshot.rs`）：
```
非 heap_handle && 非 image_inline && 非 empty && 非 SyntheticDerived
```
并在下列生产路径统一使用（替换原来的 ad-hoc 条件集）：
- `validate_raw_coherence_capture_identities`（identity gate）
- `raw_children_from_capture`（raw-child 构造）
- `build_patched_backing_slab` 的 transformed_globals 收集（overlay participant 集合）
- `compute_heap_slab_span` / `capture_heap_slab`（slab 覆盖）

不再有复制的条件集；image-inline 保持 image-backed、non-raw，永不进入 raw coherence。

### X0-B：raw-ledger recording by participant identity，非 positional zip

重写 `diff_transform_write_runs`，返回 `Result<Vec<TransformWriteRun>, OverlayError>`：
- 只对 `is_raw_coherence_participant()` 的参与者生成 run；
- 按稳定 child identity（`live_ptr`）建立 before/after 索引，**拒绝重复/歧义 identity**
  （duplicate raw participant identity）；
- **拒绝 participant-set 跨变换变化**（before 有而 after 无，或反之 →
  "participant set change"）；
- 变换导致变化时，raw 参与者必须有非空 capture_id（否则
  "empty raw capture id" fail-closed）；
- 保留执行顺序、before/after byte 证据与 digest；
- non-raw 参与者即使被变换修改，也**不进 raw ledger**，但 child-level 证据（transform_ids /
  provenance）保留不销毁。

`apply_recorded_transform` 与 `try_apply_recorded_transform` 现返回 `Result`，把
`OverlayError` 传播给调用方，管线在 overlay/manifest/candidate 前 fail-closed。

### X0-C：image-inline 语义固定

gscript image-inline 是 image-backed、non-raw。**不填假 ID、不重分类为 heap slab child、
不从无关 slab seed、不削弱 validator**。其 scrub write 保留为 child-level transform 证据，
但绝不进入 `TransformRunLedger`（其 consumer 是 raw slab overlay）。

### X0-D：pre-overlay participant + binding closure

`diff_transform_write_runs` 在 byte replay 前验证每个 raw write run 恰好对应一个 raw child
（按 `live_ptr` identity）且属于 canonical participant set。malformed run（空 capture_id /
participant-set change / duplicate identity）→ 精确 `TransformRunLedgerInvalid`，报告
run index / transform id / base / size / capture id / reason，不误报为 byte drift。

### X0-E：controller stage parser closure

`tools/gto_live_route_controller.py::_sample_last_stage` 现在：
- 先剥离 ANSI SGR 转义（`_ANSI_ESC_RE`）；
- 接受 quoted / unquoted field 值（`stage="..."` / `event="..."`）；
- 保持 best-effort recording-only 语义；
- 实测 W R1 原始 `child.stderr.bin` → 解析为 `raw_slab_overlay / error`（修复前为 None）。

### X0-F：定向测试

Rust（`raw_slab_coherence.rs`，8 项 + 10 AF1）：
```
route_x_r0_exact_140149d50_geometry               ✓ image-inline RVA/VA/size=0x1950 复现 W 类，无 raw run
route_x_r0_image_inline_is_non_raw_participant    ✓ identity gate/raw-child/ledger 一致排除 image-inline
route_x_r0_scrub_raw_runs_never_have_empty_capture_id ✓ 真实 scrub 过生产 recorder，raw run 无空 ID
route_x_r0_identity_gate_and_run_ledger_share_participant_set ✓ 同一 predicate
route_x_r0_non_raw_mutation_keeps_child_level_evidence ✓ image-inline 不入 ledger，child 证据保留
route_x_r0_malformed_empty_raw_id_still_fails_closed ✓ 真正 malformed raw 空 ID 拒绝
route_x_r0_participant_set_change_fails_closed    ✓ participant-set 变化拒绝
route_x_r0_full_pipeline_reaches_overlay_past_w_run_3464 ✓（AF1 重写为真实生产链）
```
Python（`test_gto_live_route_controller.py`，+2）：
```
route_x_r0_stage_parser_handles_ansi_quoted_fields ✓ ANSI+quoted 解析
route_x_r0_stage_parser_reports_raw_slab_overlay_error ✓ 终态 raw_slab_overlay/error
```

#### X0-AF1（审计 4 P0 修复）

**P0-1（seeding 用 canonical predicate）**：`seed_transform_inputs_from_authoritative_slab`
与 `validate_probe_coverage` 现在都用 `is_raw_coherence_participant()`（替换 ad-hoc 条件）。
全库 grep 确认 raw-coherence 决策点无残留复制条件。
```
route_x_af1_seeding_uses_canonical_participant_set ✓ 只 seed raw 参与者
route_x_af1_synthetic_derived_is_excluded_from_seeding ✓ SyntheticDerived 不入 seed
```

**P0-2（完整 identity tuple）**：`diff_transform_write_runs` 按 `live_ptr` 初始索引后，对每个
匹配对验证完整 raw identity（capture_id / content.len() / extent_kind / capture_path）不变，
任一变化 → 精确 `TransformRunLedgerInvalid`。
```
route_x_af1_same_base_capture_id_change_fails_closed ✓
route_x_af1_same_base_size_change_fails_closed ✓
route_x_af1_same_base_extent_change_fails_closed ✓
route_x_af1_same_base_capture_path_change_fails_closed ✓
```

**P0-3（全局 run membership gate）**：新增 `validate_run_membership`，在 byte replay 前遍历每个
run：按 `(capture_id, old_base, child_size)` 全 identity 匹配 raw child，必须恰好一个，且 child
属于 canonical participant set；未命中/重复/size 不一致 → 精确 `TransformRunLedgerInvalid`。
在 `build_patched_backing_slab_q0c` 的 `validate_run_ledger_shape` 后调用。
```
route_x_af1_well_formed_extra_run_without_raw_child_fails_closed ✓
route_x_af1_run_wrong_capture_id_fails_membership ✓
route_x_af1_run_wrong_child_size_fails_membership ✓
route_x_af1_run_matches_exactly_one_raw_child_positive ✓
```

**P0-4（full-pipeline 用真实生产链）**：重写测试为
`route_x_af1_w_exact_geometry_real_scrub_recorder_q0c_overlay`，执行真实顺序：
```
validate_raw_coherence_capture_identities → validate_probe_coverage →
raw_children_from_capture → seed_transform_inputs_from_authoritative_slab →
apply_recorded_transform(真实 scrub_uncaptured_heap_pointers) →
build_patched_backing_slab_q0c(真实 bindings + 真实 run ledger) → overlay 完成
```
精确 W 几何（image RVA 0x149d50 / VA 0x140149d50 / size 0x1950 / scrub area），断言：image-inline
被真实 scrub 修改、child-level 证据保留、无 raw run 引用 image-inline、raw child run identity 完整、
全局 membership 通过、Q0-C overlay 完成。**legacy `build_patched_backing_slab` 不再是验收对象。**

## 3. 门禁核验（隔离 target 复跑）

| 门禁 | 实测 |
|---|---|
| `cargo fmt --all -- --check` | **0** ✓ |
| `cargo test -p mida-pe`（`D:\tmp\magicmida-xaf1-pe`） | **617/0** ✓（599 基线 + 8 X + 10 AF1） |
| `cargo test -p mida-cli --features gto-product-recovery`（`D:\tmp\magicmida-xaf1-feature`） | **298/0/1** ✓（不退化） |
| `cargo test -p mida-cli` default（`D:\tmp\magicmida-xaf1-default`） | **296/0/1** ✓（不退化） |
| controller 测试 | **36/0** ✓（34 + 2 X parser） |
| `git diff --check` | **0** ✓ |
| Route X 新增编译警告 | **0** ✓（cargo check 警告集与基线逐项一致：13=13，`check_identity` `mut` 已删） |

## 4. 提交边界 / 状态

**本报告为 `RouteX_R0_AuditFix1Rev1ReviewRequested`，尚未 commit。** 变更文件（都在授权
write set 内）：
```
crates/pe/src/dumper/heap_global_snapshot.rs
crates/pe/src/dumper/raw_slab_coherence.rs
crates/pe/src/dumper/dump_process.rs
tools/gto_live_route_controller.py
tools/test_gto_live_route_controller.py
docs/GTO_ROUTE_X_R0_OFFLINE_WORK_ORDER.md   (untracked)
docs/GTO_ROUTE_X_R0_OFFLINE_RESULT.md       (untracked, 本文档)
```
`snapshot_manifest.rs` 未改动（无需 schema 变更）。`docs/GTO_ROUTE_W_R1_LIVE_RESULT.md`
保持 untracked，**已排除在 X commit 之外**（冻结证据）。

**0 live / 0 spawn / 0 candidate / 0 rerun / 0 cold-start。** 未执行任何 protected sample、
未调用 live controller、未生成/修补 candidate。

## 5. 已知风险 / 说明

- participant-set-change fail-closed 假定生产变换不增删 raw 参与者的 `live_ptr`（只改 content
  原位）；synthetic-namespace 变换新增的 SyntheticDerived 区域是 non-participant，不影响 raw
  set，故不会误报。
- `diff_transform_write_runs` 变 fallible 后，`apply_recorded_transform` 调用方需处理
  `OverlayError`；已通过 `?`（生产）或 `.unwrap()`/`.expect()`（测试）接入。
- X0-E 解析仍为 best-effort：日志格式若再变化，`last_observed_stage/event` 可能回 None，但
  不影响运行成败。
