# Route Y R1 A6 — Q0-C Narrow Mitigation AF3 AF2 — RESULT
## (Source Evidence Frozen Into the Full Raw → Binding → Recorder → Q0-C Identity Chain)

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF3_AF2_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged — no commit)

This is the **AF3 AF2** work order, issued by the AF3 AF1 audit rejection
(`AF3_AF1_Accepted` → `AF3_NeedsAF2`). The audit accepted AF3 AF1's closure of the
exhaust emitter path and capture-family scope, but identified the central residual gap:

> AF3 AF1 已把 source evidence 用于"是否授权"，但还没把它冻结进
> raw → binding → recorder → Q0-C 整条身份链。现在需要堵住
> raw capture 后悄悄改 source evidence 的口子。

AF3 AF2 closes exactly that gap. All seven production work items (P1-1..P1-7) are
implemented, and all **16** mandatory AF3 AF2 tests are present and green. No live, no
protected sample, no controller spawn, no candidate, no cold-start, no promote, no
second protected live, no Supervisor Production Integration, no commit. All
pre-existing AF1 / AF2R1 / AF3 / AF3-AF1 tests are preserved.

---

## 0. The core concern and the fix

Before AF3 AF2, a raw capture was used to decide *whether a child was authorized*, but the
source evidence (`source_root_rva`, `source_slot_offset`, `probe_requested_size`,
`was_interior`, `containing_parent_old_base`, `containing_parent_size`) was **not** part of
the identity that the raw→binding→recorder→Q0-C chain froze. A child could silently change
its source evidence after raw capture and still bind/resolve by the old partial tuple
(capture_id, extent, path).

AF3 AF2 introduces a **single structurally-compared `FullCaptureIdentity`** that every
stage derives from and compares, so *any* source-evidence drift after raw capture fails
closed. Equality is structural field comparison (never string-concatenated formatting).

---

## 1. P1-1 — unified `FullCaptureIdentity`

A single `FullCaptureIdentity` struct (`crates/pe/src/dumper/raw_slab_coherence.rs`) now
carries the complete capture identity:

- `kind`, `capture_id`, `old_base`, `size`, `extent_kind`, `capture_path`,
  `source_root_rva`, `source_slot_offset`, `probe_requested_size`, `was_interior`,
  `containing_parent_old_base`, `containing_parent_size`.

It derives `PartialEq`/`Eq` and is built from the same struct at every boundary:
`from_raw_child(&RawChild)`, `from_heap_global(&HeapGlobalSnapshot)`,
`from_container(&ContainerSnapshot)`. A `#[cfg(test)] from_plain_parts` helper exists only
for test fixtures that carry no source evidence. `source_parent_old_base` is intentionally
**not** a separate field — `containing_parent_old_base` is the single truthful parent
anchor.

## 2. P1-2 — `RawChild.source_root_rva`

`RawChild` gained `source_root_rva: Option<u32>` and it is frozen at raw-capture time (in
`raw_children_from_capture`) and mirrored through the `a6_contained_label_pipeline` so the
raw child and the transformed snapshot carry the **same** complete identity. `FullCaptureIdentity::from_raw_child`
reads it, so the raw→binding→recorder→Q0-C chain never re-derives it from a transformed
snapshot.

## 3. P1-3 — recorder compares the FULL identity

`validate_raw_identity_across_transform` (called by the production recorder
`apply_recorded_transform` → `diff_transform_write_runs`) now compares **every** identity
field: `capture_id`, `extent_kind`, `capture_path`, `source_root_rva`, `source_slot_offset`,
`probe_requested_size`, `was_interior`, `containing_parent_old_base`,
`containing_parent_size`, `old_base`, `kind`. Any drift → `TransformRunLedgerInvalid`.
The only allowed mutation is `content.len` for a **declared** size reinit
(`declared_size_reinit`), and even then `validate_declared_size_reinit` enforces the exact
RVA / old-size tolerance / new-size / zero-fill — provenance can never change.

## 4. P1-4 — Q0-C raw resolution uses the FULL identity

`build_patched_backing_slab_q0c` now resolves a transformed child to a raw child by the
**complete** `FullCaptureIdentity`, not a partial (capture_id, extent, path) tuple. When
multiple raw children share `(base, kind)` the resolution requires exactly one full-identity
match and **fails closed** (`RawChildMissing`) on 0 or >1 matches — it never picks
`max(raw.size)`, never uses slab-bytes, never takes first-match.

## 5. P1-5 — binding carries the FULL identity

`TransformPreimageBinding` now carries `identity: FullCaptureIdentity`, written by
`seed_transform_inputs_from_authoritative_slab` from `from_raw_child(raw)`. At Q0-C the
overlay verifies the closure:

```
binding.identity == raw_child.identity == transformed.identity
```

via `identity_matches_binding` and `identity_matches_raw_child` (size is exempt **only** for
a declared size reinit). Any field difference → fail-closed at the overlay exact-match
(`TransformPreimageBindingIdentityInvalid`).

## 6. P1-6 — ledger / run membership source-identity boundary

`validate_run_membership` still keys runs by `(capture_id, old_base)` but the raw children
must have **unique** `(capture_id, old_base)`; two raw children sharing that key but
differing in source evidence fail closed (`TransformRunLedgerInvalid`), so a run can never
cross-select between two source-evidence identities. The full identity is already closed by
binding/raw/transformed before membership is checked.

## 7. P1-7 — parent identity struct honesty (option A)

The existing `CurrentScrubIdentity` (the live scrub parent identity) is the authoritative
consumer of the containing-parent source evidence. `route_y_r1_a6_q0c_identity_fields_are_consumed`
proves every parent field (capture_id, extent_kind, capture_path, old_base, size) and every
child field is independently consumed by `protection_authorizes_qword` — a single-field flip
denies authorization. No un-compared parent field exists to be silently bound.

---

## 8. The 16 mandatory AF3 AF2 tests

All 16 present, all green:

| # | Test | Proves |
|---|------|--------|
| 1 | `route_y_r1_a6_q0c_source_root_rva_drift_after_raw_capture_fails_closed` | recorder rejects source_root_rva drift (P1-3) |
| 2 | `route_y_r1_a6_q0c_source_slot_offset_drift_after_raw_capture_fails_closed` | recorder rejects source_slot_offset drift (P1-3) |
| 3 | `route_y_r1_a6_q0c_probe_requested_size_drift_after_raw_capture_fails_closed` | recorder rejects probe drift (P1-3) |
| 4 | `route_y_r1_a6_q0c_was_interior_drift_after_raw_capture_fails_closed` | recorder rejects was_interior drift (P1-3) |
| 5 | `route_y_r1_a6_q0c_containing_parent_base_drift_after_raw_capture_fails_closed` | recorder rejects parent-base drift (P1-3) |
| 6 | `route_y_r1_a6_q0c_containing_parent_size_drift_after_raw_capture_fails_closed` | recorder rejects parent-size drift (P1-3) |
| 7 | `route_y_r1_a6_q0c_same_base_id_path_extent_different_source_root_not_resolved` | Q0-C does not pick first on source_root (P1-4) |
| 8 | `route_y_r1_a6_q0c_same_base_id_path_extent_different_source_slot_not_resolved` | Q0-C does not pick first on source_slot (P1-4) |
| 9 | `route_y_r1_a6_q0c_same_base_id_path_extent_different_probe_not_resolved` | Q0-C does not pick first on probe (P1-4) |
| 10 | `route_y_r1_a6_q0c_same_base_id_path_extent_different_parent_not_resolved` | Q0-C does not pick first on parent (P1-4) |
| 11 | `route_y_r1_a6_q0c_binding_source_identity_mismatch_fails_closed` | binding source_root/offset/probe/interior/parent each fail closed (P1-5) |
| 12 | `route_y_r1_a6_q0c_ledger_cannot_cross_source_identity` | a run cannot cross-select two source-evidence identities (P1-6) |
| 13 | `route_y_r1_a6_q0c_label_table_emitter_full_identity_roundtrip` | label-table emitter: raw==binding==transformed==Q0-C identity + overlay success + canonical qword `00 00 00 01 00 00 00 00`, B+0x23==1 |
| 14 | `route_y_r1_a6_q0c_child_link_emitter_full_identity_roundtrip` | child-link emitter: full identity roundtrip + Q0-C overlay success |
| 15 | `route_y_r1_a6_q0c_declared_size_reinit_cannot_change_source_identity` | declared reinit may change size but NEVER source evidence (each field fails closed) |
| 16 | `route_y_r1_a6_q0c_identity_fields_are_consumed` | parent/child identity fields are consumed, not merely carried (P1-7, option A) |

### 8.1 Emitter roundtrip (tests 13/14)

Both emitter tests drive the real `a6_contained_label_pipeline` (production scrub → mark →
recorded ledger → Q0-C overlay) and assert the structural equality
`FullCaptureIdentity::from_raw_child(B) == FullCaptureIdentity::from_heap_global(B) == binding_B.identity`
for B, then that Q0-C **succeeds** with B overlaid.

- **label-table emitter** (`GscriptLabelTableEntry`, in_table): the canonical protected
  family. Final patched qword `00 00 00 01 00 00 00 00`, `B+0x23 == 1`, and the original
  dangling pointer is not preserved.
- **child-link emitter** (`GscriptChildLink`, not table-reachable): B's only transform is
  scrub, which zeroes the shared byte to `0x00` — **agreeing** with A's scrub (legitimate
  containment). Q0-C succeeds; `B+0x23 == 0x00`, dangling pointer cleared.

Both verify the identity roundtrip through the whole chain and that the overlay binds the
exact full identity.

---

## 9. Gates (all green)

| Gate | Command | Result |
|------|---------|--------|
| fmt | `cargo fmt --all -- --check` | clean |
| mida-pe offline | `cargo test -p mida-pe --offline` (via `af3_pe_full.cmd`) | **725 passed / 0 failed** (710 pre-existing + 15 new; #16 pre-existed) |
| mida-cli features | `cargo test -p mida-cli --features gto-product-recovery` (via `af3_cli_gates.cmd`) | **298 passed / 0 failed** |
| mida-cli offline | `cargo test -p mida-cli --offline` (via `af3_cli_gates.cmd`) | **296 passed / 0 failed** |
| python controller | `python tools/test_gto_live_route_controller.py` | **36 passed / 0 failed** |
| whitespace | `git diff --check` | clean (only CRLF note) |

### 9.1 Preserved test matrix

- AF1 / AF2R1 / AF3 / AF3-AF1 suites: all preserved and green (725 total mida-pe).
- Label-table canonical qword (`route_y_r1_a6_q0c_final_patched_qword_is_canonical`),
  child-link/legitimate-containment success, and all fail-closed negative tests unchanged.

---

## 10. Production diff

- `crates/pe/src/dumper/raw_slab_coherence.rs` — `FullCaptureIdentity`, `RawChild.source_root_rva`,
  `TransformedChild`, `TransformPreimageBinding.identity`, extended `validate_raw_identity_across_transform`,
  full-identity raw resolution, `identity_matches_ignore_size/binding/raw_child`, the 15 new tests.
- `crates/pe/src/dumper/heap_global_snapshot.rs` — fixture source-evidence alignment for the
  three strict-identity fixtures previously failing under the full-identity binding check.
- `crates/pe/src/dumper/snapshot_manifest.rs` — two binding literals carry the full identity.
- **No `Cargo.toml` / `Cargo.lock` / source-only changes outside the three files above.**

---

## 11. Constraints honored

- **No commit**; HEAD unchanged at `f386b49`.
- **No Supervisor Production Integration**, **no second protected live**, **no controller /
  protected spawn**, **no candidate / cold-start / promotion**, **no Route Z R1**.
- **No `D:\tmp`**; controller gates run only via native PowerShell `cmd.exe //c`.
- Q0-C, `resolved_writes`, last-writer, binding, run-membership, slab-slice, digest, and strict
  identity are **not weakened**.
- Source-evidence validation was **not removed** to solve this work order.
- No new field was added "only for protection" — `source_root_rva` enters the
  raw/binding/Q0-C identity chain (P1-2/P1-5).
- A6 frozen evidence is untouched; docs remain untracked.
- **Stop here.** No Supervisor Production Integration; no second protected live; no commit.
