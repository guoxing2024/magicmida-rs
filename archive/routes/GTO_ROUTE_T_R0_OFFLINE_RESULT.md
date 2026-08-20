# GTO Product Recovery — Route T R0 Authoritative Probe Coverage Closure

**日期：** 2026-08-10
**授权：** Route T R0（OFFLINE ONLY，0 live / 0 spawn / 0 candidate / 0 cold-start）
**起点提交：** `a4bdb939bb44f998d322a89bde00a44e2115eb1c`
**分支：** `oreans/two-sample-mainline`
**终态：** **`RouteT_R0_AuditFix3Rev1ReviewRequested`**

> 本文档是 **offline 结果**。Route T R0 是离线实现，非 live run，未生成 candidate。
> 2026-08-10：AF3 后审计 `RouteT_R0_AuditFix3_Rev1Required`（唯一阻断：reverse-containment
> event 把 dropped input 与 survivor input 身份混在一起），实施 **Audit Fix 3 Rev 1
> 最小修正**（event bijection + survivor origin identity），已全部完成。

---

## 1. 根因（已确认）

Route S R1 live 失败的根因已由现场证据 + 源码分析双重确认：

**分散的 dangling-edge heap 分配把单个主 slab span 撑爆，导致无任何 authoritative slab。**

现场日志（`live_20260810T035848Z_route_s_r1_capture_identity_closure/child.stderr.bin`）：
```
Captured dangling heap edge (pre-scrub) heap=0x850150  size=4096  refs=128
Captured dangling heap edge (pre-scrub) heap=0x8553d0  size=944   refs=776
Captured dangling heap edge (pre-scrub) heap=0x851a80  size=3520  refs=208
Captured dangling heap edge (pre-scrub) heap=0x854cd0  size=1792  refs=168
... 共 12 条，地址从 0x850150 到 0x3852d30
```

`compute_heap_slab_span` 对**所有** heap-global 取 `[min-0x1000, max_end)` 作为单 slab span：
`0x850150 → 0x3852d30` 跨度 ≈ **0x30000000 ≈ 768 MiB**，超过 `MAX_HEAP_SLAB_BYTES`（64 MiB）。
→ `capture_heap_slab` 返回 `None` → `raw_capture` 为空 → **无 authoritative slab**。
→ 每个 dangling-edge ProbeWindow 无覆盖 → R0-F.1 在 runtime plan 拒绝（Route S R1 终态）。

这解释了为何 Route R1（dangling-edge 较少、span 未超 64MiB）能产生 slab，而 Route S R1
（新增分散 dangling edges）把 span 撑爆。

## 2. 解决方案（T0-A ~ T0-E）

### T0-B — 每个 dangling-edge 分配提升为专用 authoritative slab（根因修复）

- `capture_dangling_edges` 现在对每个准入的 dangling-edge，除 ProbeWindow heap-global 外，
  还 push 一个**专用 `HeapSlab`**，覆盖 `[value, value+len)`（内容直接来自 debuggee，即权威）。
- `detect_heap_globals` 返回 `(globals, dedicated_slabs)` 元组。
- `compute_heap_slab_span` 排除 `CapturePath::DanglingEdge` 的 global（它们有专用 slab），
  使主 slab 只覆盖连续的非-dangling 簇，不再被分散 edges 撑爆 64MiB 上限。

### T0-A — `capture_coverage_bind` 覆盖门（提前暴露未覆盖窗口）

- 新增 `validate_probe_coverage(heap_globals, heap_slabs)`：对每个 ProbeWindow/InteriorSubview
  验证被**恰好一个** authoritative slab 包含（主 slab 或专用 dangling-edge slab）。
- 在 `dump_process` 中于 overlay / runtime plan **之前**执行，stage=`capture_coverage_bind`。
- 未覆盖 → 在此处精确失败，而非拖到 `runtime_rebase_plan_validation`。

### T0-C — 精确 `ProbeCoverageMissing` 错误

- `OverlayError::ProbeCoverageMissing`（coverage 门）与 `RebaseError::ProbeCoverageMissing`
  （R0-F.1 保留）均携带：`child_base`、`child_size`、`extent_kind`、
  `candidate_slab_count`、`nearest_authority`、`nearest_authority_gap`。
- 不再用泛化字符串让 operator 猜 coverage 问题。

### T0-D — 基于 range，非 VA 硬编码

- 覆盖判定完全基于 slab range 与 child range 的包含关系，**无 `if base == 0x850150` 特判**。
- `validate_probe_coverage` / `normalize_containment` 对任意地址的 probe 一视同仁。

### 多 slab 支持（T0-B 架构）

- `build_runtime_rebase_plan` / `prepare_runtime_rebase_for_dump` / `declared_slots_from_capture`
  的 `heap_slab: Option<&HeapSlab>` → `heap_slabs: &[HeapSlab]`。
- `normalize_containment` 吸收判定扩展：`Contains` **或 `ExactDuplicate`**（probe 与专用 slab
  完全同 base+size 时 offset=0 吸收为 alias）。

## 3. 新增测试（T0-E + T0-B fixture）

`raw_slab_coherence.rs`（coverage 门）：
1. `route_t_r0_uncovered_probe_fails` — 未覆盖 ProbeWindow → `ProbeCoverageMissing`
2. `route_t_r0_covered_probe_ok` — 覆盖 ProbeWindow → 通过
3. `route_t_r0_exact_850150_geometry_covered` — `0x850150` 精确几何 → 覆盖通过
4. `route_t_r0_multiple_probes_one_slab_all_ok` — 一 slab 多 probe → 全部通过
5. `route_t_r0_probe_crossing_slab_boundary_fails` — 跨 slab 边界 → fail-closed
6. `route_t_r0_no_slabs_probe_fails_with_none_authority` — 无 slab → 精确失败（nearest=None）
7. `route_t_r0_coverage_is_range_based_not_va_hardcoded` — 任意地址均按 range 处理
8. `route_t_r0_interior_subview_uncovered_fails` — InteriorSubview 未覆盖 → 失败

`runtime_rebase.rs`（多 slab plan）：
9. `route_t_r0_850150_dedicated_slab_absorbs_probe_alias` — 精确几何被吸收为 alias（offset 0）
10. `route_t_r0_multiple_probes_one_slab_all_aliases` — 一 slab 多 probe 全部 alias
11. `route_t_r0_uncovered_probe_rebase_error_precise` — 未覆盖 → 精确 `RebaseError::ProbeCoverageMissing`

## 4. 核验结果（Route T R0 Audit Fix 3 Rev 1 后）

| 项 | 结果 |
|---|---|
| `cargo fmt --all -- --check` | 通过（0 diff） |
| `mida-pe` 测试 | **593 passed / 0 failed / 0 ignored**（含 11 TAF1 + 8 TAF2 + 5 TAF3 + 2 Rev1） |
| `mida-cli --features gto-product-recovery` | **296 passed / 0 failed / 1 ignored** |
| `git diff --check` | 通过（exit 0） |
| CLI 二进制构建（MSVC） | 成功 |
| 警告数 | 11（均为既有，无新增） |

## 4e. Route T R0 Audit Fix 3 Rev 1 — Reverse-Containment Event Bijection

审计判定 `RouteT_R0_AuditFix3_Rev1Required`（唯一阻断：reverse-containment event 把
dropped input 与 survivor input 身份混在一起）。最小修正，全部完成：

- **Rev1-1**：`NormalizedSlab` 新增 `origin_input_sequence`（survivor 的真实来源 input）。
- **Rev1-2**：reverse replacement（S 替换 A）修正两个输入的事件身份：
  - A 的原 "kept" event **更新**为 `contained_exact_alias`（input_seq=A.origin、
    input_role=A.role、geometry=A、survivor=ki）——不再混用 S 的身份；
  - 为 S 新增 "kept" event（input_seq=seq、input_role=cand.role、geometry=S、survivor=ki）；
  - survivor = slab=S、role=cand.role（**非** dropped.role）、origin_input_sequence=seq。
- **Rev1-3**：normalization 成功返回前强制 **event bijection**：有效 input 数 == event 数、
  所有 input_sequence 唯一、survivor_sequence 在界内、每个 survivor 有 origin 的 "kept"
  event、每个 event 的 role/base/size/digest 对应**自身 input**（非 survivor）。非法 fail-closed。
- **Rev1-4**：新增 2 测试：
  `route_t_af3_rev1_reverse_containment_event_identity_is_bijective`（events.len==2、
  seq{0,1}、seq0=A/main/alias、seq1=S/dedicated/kept、survivor role=dedicated、
  origin=1）、
  `route_t_af3_rev1_reverse_containment_manifest_provenance_roundtrip`（render→parse→
  重复断言）。

### Rev1 测试矩阵（2/2 通过）

```
route_t_af3_rev1_reverse_containment_event_identity_is_bijective  ✓
route_t_af3_rev1_reverse_containment_manifest_provenance_roundtrip ✓
```

## 4d. Route T R0 Audit Fix 3 — Normalization Provenance Closure and Pairwise Slab Invariant

审计判定 `RouteT_R0_AuditFix2_NotReady`（3 阻断）。已全部修复（TAF3-A..G）：

- **TAF3-A（dedicated-only role 误标 main）**：`normalize_authoritative_slabs` 现接受
  `&[AuthoritativeSlabCandidate { slab, role }]`，role 来自真实捕获来源（main/dedicated），
  不再用 `kept.is_empty()` 推断。dedicated-only 的第一项保持 `dedicated`。
- **TAF3-B（丢弃的 dup/alias 无 event）**：normalization 现输出 `NormalizationEvent` ledger
  （input_sequence/input_role/input_old_base/input_size/input_raw_digest/action/
  survivor_sequence/relationship），manifest 渲染 `normalization_events` 数组。可回答：
  哪个 slab 被丢弃、为什么、归属于哪个 survivor、原始 digest。
- **TAF3-C（reverse-containment 提前 break）**：reverse containment 替换 kept slab 后，
  用专门的 recheck 循环重新检查新的 outer 与**所有** kept slab，捕捉任何 partial overlap 或
  byte conflict（不再 break 后漏检）。
- **TAF3-D（pairwise-disjoint 不变量）**：normalization 结束后对所有 kept slab 做
  pairwise-disjoint 断言，任意残留重叠 fail-closed。
- **TAF3-E/F/G**：新增 5 测试：
  `dedicated_only_role_stays_dedicated`（dedicated-only role 正确）、
  `dedup_and_alias_emit_events`（dedup/alias 的 manifest event roundtrip）、
  `reverse_containment_plus_partial_overlap_fails_closed`、
  `normalized_output_is_pairwise_disjoint`、
  `reverse_containment_rechecks_all_kept`。

### TAF3 测试矩阵（5/5 通过）

```
route_t_af3_dedicated_only_role_stays_dedicated                  ✓
route_t_af3_dedup_and_alias_emit_events                          ✓
route_t_af3_reverse_containment_plus_partial_overlap_fails_closed ✓
route_t_af3_normalized_output_is_pairwise_disjoint               ✓
route_t_af3_reverse_containment_rechecks_all_kept                ✓
```

## 4c. Route T R0 Audit Fix 2 — Authoritative Slab Identity Enforcement and Overlap Normalization

审计判定 `RouteT_R0_AuditFix1_NotReady`（2 P0 + 2 证据缺口）。已全部修复（TAF2-A..F）：

- **TAF2-A（P0：slab_size/slab_digest 未进入生产校验）**：overlay 的 exact-binding 匹配
  现在强制 `binding.slab_size == actual_slab.content.len()` 且
  `binding.slab_digest == sha256(actual_slab.content)`。任一不符 → 精确
  `TransformPreimageBindingIdentityInvalid` fail-closed。新增 3 负向测试：
  `route_t_af2_wrong_slab_size/digest/base_and_digest_fails_closed`。
- **TAF2-B（P0：main/dedicated 重叠未归一化）**：新增 `normalize_authoritative_slabs`，
  在 coverage/raw capture/seed 前确定性归一化 authoritative slab 集合：
  1) exact duplicate → 保留一个；2) dedicated 被 main 完整包含且 bytes 一致 → exact alias，
  只保留一个 backing；3) 完整包含但 bytes 不一致 → `AuthoritativeSlabConflict`
  （contained_byte_conflict）fail-closed；4) 部分重叠 → fail-closed（partial_overlap）。
  归一化集合同时供 coverage/raw capture/seed/overlay/runtime/manifest。
- **TAF2-C**：真实重叠测试：`main_dedicated_exact_duplicate_normalizes` /
  `main_dedicated_contained_same_bytes_normalizes` /
  `main_dedicated_contained_different_bytes_fails_closed`。
- **TAF2-D**：`partial_overlap_fails_closed`。
- **TAF2-E（manifest authoritative_slab_ledger）**：manifest 新增
  `authoritative_slab_ledger`（sequence/role/old_base/size/raw_digest/patched_digest/
  normalization/source）；dump_process 把 `authoritative_slabs`（raw）与 `all_slabs`
  （patched）对齐传参，证明 runtime slab set == overlay slab set == manifest 声明集。
- **TAF2-F（证据缺口修复）**：3 项名实不符测试重写为真实生产顺序/roundtrip/重叠测试：
  `coverage_runs_before_overlay`（镜像 dump_process 阶段序）、
  `manifest_roundtrip_contains_all_authoritative_slabs`（真实 render→parse→校验）、
  `exact_duplicate_does_not_double_allocate`（main+dedicated 重叠场景）。

### TAF2 测试矩阵（8/8 通过）

```
route_t_af2_wrong_slab_size_fails_closed                       ✓
route_t_af2_wrong_slab_digest_fails_closed                     ✓
route_t_af2_wrong_slab_base_and_digest_fails_closed            ✓
route_t_af2_main_dedicated_exact_duplicate_normalizes          ✓
route_t_af2_main_dedicated_contained_same_bytes_normalizes     ✓
route_t_af2_main_dedicated_contained_different_bytes_fails_closed ✓
route_t_af2_partial_overlap_fails_closed                       ✓
route_t_af2_normalized_set_is_shared_by_overlay_and_runtime    ✓
```

## 4b. Route T R0 Audit Fix 1 — Multi-Slab Authoritative Coherence Wiring

审计判定 `RouteT_R0_NotReady`（阻断：dedicated slab 未进入 raw capture→seed→overlay；
主 slab 缺失时 coherence 被跳过；coverage gate 在 overlay 之后；空 slab 跳过 coverage gate）。
已全部修复（TAF1-A..F）：

- **TAF1-A**：`RawSlabCapture { slab }` → `RawSlabCapture { slabs: Vec<HeapSlab> }`。
  生产路径用 `authoritative_slabs`（main + dedicated）构造 raw capture bundle，main 与
  dedicated 都进入同一 authoritative capture。
- **TAF1-B**：新增 `covering_slab_for_child`，从多 slab 集合确定性选择唯一覆盖者
  （0 个 → fail-closed，>1 个 → fail-closed）。binding 记录实际 slab：
  `slab_old_base` / `slab_size` / `slab_digest` / `slab_offset` / `basis`。
- **TAF1-C**：seed（`slab_slice_for_child`）与 overlay（`build_patched_backing_slab_q0c`
  返回 `Vec<HeapSlab>`）对所有 authoritative slabs 生效；dedicated-only 场景不绕过
  seed/overlay。
- **TAF1-D**：生产顺序改为 `capture_identity_bind → capture_coverage_bind → seed →
  transforms → raw_slab_overlay → runtime`。coverage gate 在 overlay 之前。
- **TAF1-E**：coverage gate **无条件**执行（空 slab 也执行；有 probe 无 slab 时在
  `capture_coverage_bind`/`ProbeCoverageMissing` fail-closed，overlay/runtime 不执行）。
- **TAF1-F**：runtime（`build_runtime_rebase_plan` / `prepare_runtime_rebase_for_dump` /
  `declared_slots_from_capture` / manifest）全部使用同一 normalized authoritative slab set
  （patched `Vec<HeapSlab>`）；manifest 渲染新增 `slab_size` / `slab_digest`。

### TAF1 强制测试矩阵（11/11 通过）

```
route_t_af1_multislab_raw_capture_seed_overlay_positive ✓
route_t_af1_dedicated_child_not_outside_main_slab        ✓
route_t_af1_main_plus_dedicated_transform_overlay        ✓
route_t_af1_dedicated_only_transform_overlay             ✓ (关键)
route_t_af1_no_main_slab_does_not_skip_coherence         ✓
route_t_af1_empty_slab_coverage_fails_at_capture_coverage_bind ✓
route_t_af1_coverage_runs_before_overlay                 ✓
route_t_af1_multi_slab_binding_records_actual_slab       ✓
route_t_af1_exact_duplicate_does_not_double_allocate     ✓
route_t_af1_cross_slab_child_fails_closed                ✓
route_t_af1_manifest_roundtrip_contains_all_authoritative_slabs ✓
```

**`route_t_af1_dedicated_only_transform_overlay`**：dangling-edge child（`0x850150`）在
专用 slab 中完成 seed → transform（scrub +0x40）→ overlay，产出 patched 专用 slab，
离线闭环证明 Route S R1 根因已被修复。

## 5. 改动文件

```
crates/pe/src/dumper/dump_process.rs
crates/pe/src/dumper/heap_global_snapshot.rs
crates/pe/src/dumper/raw_slab_coherence.rs
crates/pe/src/dumper/runtime_bootstrap.rs   (仅测试参数适配)
crates/pe/src/dumper/runtime_rebase.rs
crates/pe/src/dumper/snapshot_manifest.rs    (authoritative_slab_ledger 渲染 + slab_size/slab_digest)
docs/GTO_ROUTE_T_R0_OFFLINE_RESULT.md        (本文档, untracked)
```

## 6. 边界（已遵守）

- OFFLINE ONLY：0 live spawn / 0 candidate / 0 cold-start / 0 rerun；
- 未运行 protected sample，未改 acceptance / TrustToken / report schema / 签名 /
  product gate / `lab/cases/v2/gto_launcher.json` / canonical vault artifact /
  resolver 工具 / `gto_live_route_controller.py`；
- 未访问 mutable locator `D:\Tools\RE\dumps\gto\启动器.exe`；
- `MIDA_GTO_NO_BYPASS=1` 语义未改变；无 bypass / semantic repair / forced visibility /
  product-code skip / IAT / TLS / runtime code patch；
- Route S R1 未重跑；Route S R2 未签发；Route T R1 未授权。

## 7. 结论

Route T R0 Audit Fix 3 Rev 1 完成了 reverse-containment provenance 收口：

- **Rev1-1/2**：reverse replacement 时 dropped input 与 survivor input 的 event 身份
  严格分离（各自 role/geometry/digest），survivor 使用正确 role + origin；
- **Rev1-3**：event bijection 不变量强制（每有效 input 恰好一个 event，身份对应自身）；
- **Rev1-4**：2 新测试 + TAF3 旧 5 项不退化；
- **门禁**：mida-pe 593/0（≥593），mida-cli gto 296/0/1，fmt 0，diff-check 0，11 warnings（无新增）。

**下一步：** 请审计负责人复审 Route T R0 Audit Fix 3 Rev 1。若通过将直接签
`RouteT_R0_AuditFix3Accepted` + commit authorized；Route T R1（live truth run）之后单独考虑。
