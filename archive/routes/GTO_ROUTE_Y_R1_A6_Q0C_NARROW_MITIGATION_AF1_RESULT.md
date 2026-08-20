# Route Y R1 A6 — Q0-C Narrow Mitigation AF1 — RESULT

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF1_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This AF1 work order **tightens the production mitigation** to full identity/parent binding, **removes ProbeWindow** from the protection scope, adds the **7 explicit independent negative tests**, and **proves qword-grant minimality**. NO live, NO protected sample, NO controller, NO spawn, NO candidate, NO cold-start, NO commit.

---

## 1. Production diff

| File | Change | Nature |
|---|---|---|
| `crates/pe/src/dumper/heap_global_snapshot.rs` | +184 / -2 | **Production mitigation (AF1-tightened)** |
| `crates/pe/src/dumper/raw_slab_coherence.rs` | +737 / -0 | **Tests** (11 Q0-C tests + `LabelConfig` helper) |

The 2 deletions are the old `scrub_buffer_external_ptrs(...)` call sites, replaced by the protection-aware signature. No other production logic removed.

## 2. Protected entry — full fields (P1-1)

New struct `LabelFlagProtection` carries every identity field:

```rust
struct LabelFlagProtection {
    child_capture_id: String,              // Label capture_id, must start "gscript_label:"
    child_extent_kind: CaptureExtentKind,  // must be InteriorSubview
    child_capture_path: CapturePath,       // must be GscriptChildLink | GscriptFirstHop
    child_base: u64,                        // Label live_ptr
    child_size: usize,                      // Label content.len()
    flag_addr: u64,                         // = child_base + 0x23
    parent_old_base: u64,                   // containing_parent_old_base
    parent_size: usize,                     // containing_parent_size
}
```

## 3. Parent/child binding judgment (P1-1 / P1-3)

`scrub_buffer_external_ptrs` now skips a qword **only when ALL hold**:
1. the qword contains a protected `flag_addr`;
2. `p.flag_addr >= qword_lo && p.flag_addr < qword_hi`;
3. **`p.parent_old_base == buf_base` AND `p.parent_size == buf_size`** — the buffer being scrubbed is the Label's **exact containing parent** (not merely "any different object", not by physical address alone).

The `buf_base != child.live_ptr` heuristic is **removed**. A same-address object with a different capture identity, extent, path, or parent is **not** authorized.

## 4. ProbeWindow final disposition (P1-2)

**Removed.** The protection accepts **only `InteriorSubview`** (the confirmed A6/fixture lineage). `ProbeWindow` is excluded by design (no fixture or production evidence justifies it). Verified by the `route_y_r1_a6_q0c_probe_window_extent_not_protected` test → `TransformWriteConflict`.

## 5. The 7 explicit independent negative tests (P1-3)

| # | Test | Failure mode isolated | Result |
|---|---|---|---|
| 1 | `route_y_r1_a6_q0c_same_addr_diff_capture_id_fails_closed` | same address/shape, different capture_id | **TransformWriteConflict** |
| 2 | `route_y_r1_a6_q0c_non_gscript_object_not_protected` | non-gscript (ObservedAllocation/MainSlot/"other") same offset | **TransformWriteConflict** |
| 3 | `route_y_r1_a6_q0c_label_wrong_containing_parent_not_protected` | InteriorSubview+gscript_label id, but containing_parent = wrong object | **TransformWriteConflict** |
| 4 | `route_y_r1_a6_q0c_label_wrong_capture_path_not_protected` | gscript_label id, MainSlot path (not a Label path) | **TransformWriteConflict** |
| 5 | `route_y_r1_a6_q0c_label_flag_out_of_bounds_not_protected` | content.len() <= 0x23 → no protected entry | A's scrub clobbers target byte (asserted) |
| 6 | `route_y_r1_a6_q0c_probe_window_extent_not_protected` | ProbeWindow extent (not authorized) | **TransformWriteConflict** |
| 7 | `route_y_r1_a6_q0c_unrelated_overlapping_parent_not_protected` | buffer C overlaps flag address but is NOT the Label's parent | C's qword scrubbed to 0 (asserted) |

Plus `route_y_r1_a6_q0c_two_distinct_identities_conflict_still_fails_closed` (two distinct identities, different values → conflict) and the two positive tests (protected label resolves; legitimate containment agrees). **Each negative test asserts the actual outcome** (TransformWriteConflict or the target byte being scrubbed) — not merely "helper returned false".

## 6. qword minimal-authorization proof (P2)

`route_y_r1_a6_q0c_qword_grant_is_minimal` proves:
- The Label's own flag qword `A[0xa00..0xa08)` (holding B+0x23) is **preserved** by A's scrub (A skips it).
- The qword **before B** (`A[0x9c0..0x9c8)`), the qword **after B** (`A[0xde0..0xde8)`), and an **unrelated dangling qword** (`A[0x500..0x508)`) in the same parent buffer A are **all scrubbed to 0**.

The whole-qword skip is justified by the gscript Label layout: `B[0x20..0x28)` is entirely Label metadata (the flag `+0x23` plus adjacent label state), not a genuine dangling external pointer; scrub zeroes qwords atomically, so skipping the one qword that holds the protected flag is the minimal correct grant. The adjacent-qword scrubbing proves the grant does not leak to surrounding bytes.

## 7. Must-preserve invariants (verified by full suite)

- `resolved_writes` conflict check: **unchanged** (all 7 negative tests still produce TransformWriteConflict).
- last-writer / binding / slab slice+digest validation: unchanged.
- capture_id/extent_kind/capture_path strict: enforced in `gscript_label_flag_protections` (`gscript_label:` prefix, InteriorSubview, Gscript path) + existing identity matrix.
- undeclared size drift fails closed; declared transition `RVA 0x141bf0 / old 0x8000 / new 0x180 / zero-filled / strict identity` — `declared_reinit` + `sanitize_ahk_runtime_global` tests pass.
- Route X/Y existing fail-closed tests: full mida-pe suite passes.

## 8. Offline gates (all pass)

- `cargo fmt --all -- --check` → **clean** (applied `cargo fmt`; re-check passes)
- `cargo test -p mida-pe --offline` → **673 + 7 + 2 + 3 passed** (1 ignored), 0 failed
- `cargo test -p mida-cli --features gto-product-recovery` → **298 + 4 + 1 + 20 + 17 + 3 passed**
- `cargo test -p mida-cli --offline` → **296 + 4 + 1 + 20 + 17 + 3 passed**
- `python tools/test_gto_live_route_controller.py` → **36 passed / 0 failed**
- `git diff --check` → **clean**

## 9. Git boundary

- **tracked modified (2):** `crates/pe/src/dumper/heap_global_snapshot.rs` (+184/-2, production), `crates/pe/src/dumper/raw_slab_coherence.rs` (+737/-0, tests)
- **untracked source:** 0
- **untracked docs:** 27 (unchanged)
- **No git add/commit** (work order forbids auto-commit)
- A6 original evidence frozen/unmodified; A6 report not touched

---

## Honesty statement

- The mitigation now carries **full identity + exact containing-parent binding**: a protected flag byte is skipped only when the scrubbed buffer matches the Label's declared `containing_parent` (old_base AND size), and the Label's `capture_id` carries the `gscript_label:` prefix, `InteriorSubview` extent, and a gscript capture path.
- **ProbeWindow is removed** from the protection scope — only the confirmed `InteriorSubview` lineage is authorized.
- **All 7 AF1 negative tests are independent and assert the actual outcome** (fail-closed), not a helper-return.
- The qword grant is proven minimal (flag qword preserved; before/after/unrelated qwords scrubbed).
- `resolved_writes` / last-writer / binding / slab-digest checks unchanged; declared transition preserved.
- No live, no candidate, no cold-start, no Route Z R1, no commit. Execution stopped.

---

## Post-execution boundary

- Production mitigation: `heap_global_snapshot.rs` (+184/-2). Tests: `raw_slab_coherence.rs` (+737/-0).
- A6 live evidence and A6 report frozen/unmodified; no residual processes.
- Only new report file: `docs/GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_AF1_RESULT.md` (untracked).
