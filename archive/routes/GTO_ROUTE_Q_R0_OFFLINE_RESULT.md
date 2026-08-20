# GTO Product Recovery — Route Q R0 Offline Result

**日期：** 2026-08-09
**绑定基线：** `d11580695c349648e40674b493c2f939458d9608`
**绑定分支：** `oreans/two-sample-mainline`
**工单：** `docs/GTO_ROUTE_Q_R0_OFFLINE_WORK_ORDER.md`
**判定：** `RouteQ_R0_OfflineRepairReady`（候选）

> ⚠️ 本状态**不代表 live 已修复、不代表可生成 candidate**。仅表示离线模型、测试与证据过门。是否签发 Route Q R1 由审计负责人另行决定。

---

## 1. Commit / diff baseline

- HEAD：`d11580695c349648e40674b493c2f939458d9608`（未变，工作树未提交）
- 修改文件（授权写集内）：
  - `crates/pe/src/dumper/raw_slab_coherence.rs`（+1609 含测试）
  - `crates/pe/src/dumper/heap_global_snapshot.rs`（+458）
  - `crates/pe/src/dumper/snapshot_manifest.rs`（+124）
  - `crates/pe/src/dumper/dump_process.rs`（+41）
- 未触及：resolver、vault、sample manifest、acceptance、live controller、protected-launch、`_resolve_gto_source_revision`、`run_cargo_msvc`。
- 未新增 untracked：`docs/GTO_ROUTE_Q_R0_OFFLINE_WORK_ORDER.md`（工单）、`docs/GTO_ROUTE_Q_R0_OFFLINE_RESULT.md`（本文件）。

## 2. Preimage / overlay 状态机（Q0-C）

| Extent | Transform input P | write-set | 证据 | resolution |
|---|---|---|---|---|
| Strict（`ObservedAllocation`/`BackingObject`/Container） | `P = C`，强制 `C == S` | `{i \| T[i] != C[i]}` | binding `ChildCapture` + `raw_child_digest==raw_slab_slice_digest` | `C!=S` → `RawCaptureDrift` fail-closed |
| `ProbeWindow`/`InteriorSubview` | `P = S`（seed） | `{i \| T[i] != S[i]}` | binding `AuthoritativeSlabSlice` + `transform_input_digest==sha256(S)` | 写 → `TransformReplayedOnAuthoritativePreimage`；非写漂移 → `NonWriteSlabAuthoritative` |
| 无 binding / digest 不匹配 | — | — | — | `TransformPreimageDrift` fail-closed |

生产接线：`dump_process.rs` 在 transform 前调用 `seed_transform_inputs_from_authoritative_slab`，overlay 改用 `build_patched_backing_slab_q0c`，manifest 渲染 `transform_preimage_ledger`。

## 3. 新增结构与测试计数

| 阶段 | 新类型 | 新测试 | 通过 |
|---|---|---|---|
| Q0-A | `TransformPreimageBasis`、`TransformPreimageBinding`、`seed_transform_inputs_from_authoritative_slab` | 3 | ✓ |
| Q0-B | `TransformWriteRun`、`TransformRunLedger`、`diff_transform_write_runs` | 6 | ✓ |
| Q0-C | `build_patched_backing_slab_q0c`、`CaptureDriftResolution::TransformReplayedOnAuthoritativePreimage` | 4 | ✓ |
| Q0-D | `q0d_fixture`/`wide` 测试 helper | 8 | ✓ |
| Q0-E | manifest `transform_preimage_ledger` 渲染 | 1 | ✓ |

**Route Q tests 合计 22**（≥8 ✓）。

## 4. 测试计数核对（工单 §9）

| 门禁 | 要求 | 实测 | 结果 |
|---|---|---|---|
| `cargo fmt --all -- --check` | 0 diff | 0 diff | ✓ |
| R0-G | 27/27 | 27 | ✓ |
| R0-F.1 | 20/20 | **9** | ⚠️ 见 §7 |
| R0-F.2 | 25/25 | 25 | ✓ |
| 新 Route Q tests | ≥8 | 22 | ✓ |
| `cargo test -p mida-pe --lib` | ≥480 / 0 failed | 502 / 0 | ✓ |
| `cargo test -p mida-cli --features gto-product-recovery` | ≥296 / 0 | 296 / 0 / 1 ignored | ✓ |
| `git diff --check` | clean | clean | ✓ |

## 5. 审计性质核对

- 无 hard-coded live address / sample-specific byte bypass（`0x8aa5f8`/`0x8aa628` 仅出现于测试）。
- manifest `transform_preimage_ledger` 可独立证明每个 child 的 preimage basis（`basis` + 三 digest + `seeded_from_slab`）。
- byte/run ledger 能唯一定位 `+0x28` writer = `repair_label_names_after_scrub`；`mark_labels_non_nested` 只写 `+0x23`。
- strict extent 规则未削弱：所有 fail-closed 负向测试通过（含 `r0g_strict_observed_allocation_drift_fails_closed`、`route_q_r0c_strict_extent_write_applies_and_drift_rejected`）。
- 旧 R0-G fail-closed 负向测试继续成立（27/27）。
- repo diff 只在授权写集。
- 无 candidate、无 debuggee PID、无 live evidence claim。

## 6. Exact synthetic reproduction

Route P 精确几何（`InteriorSubview`，child `0x8aa5f8`，size `0x70`，drift `+0x28`，`C.mName=0`、`S.mName=非空`）在 Q0-D Test 6 全链路复现：seed(S) → overlay，S 指针保留，overlay applied。Route P 的 `TransformPreimageDrift` 在 Q0-C 下不再触发（因为 transform 从 S 推导，非过期 C）。

## 7. 已知剩余风险 / 诚实披露

1. **R0-F.1 计数与工单不符**：工单 §9 写 "R0-F.1：20/20"，实测仅 **9** 个 `r0f1_` 前缀测试。基线 `d115806` 也是 9，**未删除/未放宽任何测试**（mida-pe 480→502 的 +22 全部为新增 route_q）。工单的 "20" 应为 R0-F 与 R0-F.1 的合并估算或笔误。如实报告，不虚报 20/20。
2. **生产接线已在 Q0-E 完成**：`dump_process.rs` 已切换 Q0-C overlay + seeding，但**未经 live 验证**。离线测试证明模型正确，但真实 GTO 样本的 raw slab overlay 是否通过，须由 Route Q R1 单次 live truth run 判定。
3. **`repair_label_names_after_scrub` 未改逻辑**：Q0-D 证明其在权威 preimage（P=S）下决策正确。根因（基于过期 C 合成指针）由 Q0-A seeding 机制消除，非 patch 修复。
4. 旧 `build_patched_backing_slab` 保留供 r0g 测试；生产走 `_q0c`。

## 8. 建议

**建议申请 Route Q R1**（独立授权、预算 1 route attempt / 1 protected spawn / 0 rerun）。首要观察点：Route P 精确几何是否仍出现、`transform_preimage_ledger` 是否证明 `P=S`、`repair_label_names_after_scrub` 的 `+0x28` write 是否基于权威 preimage、raw slab overlay 是否完成、candidate 是否自然产生。

## 9. 终态

`RouteQ_R0_OfflineRepairReady`（候选，待审计负责人确认）。**不是** live 已修复，**不**可生成 candidate。
