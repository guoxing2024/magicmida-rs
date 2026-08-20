# Route Y R1 A6 — Q0-C Deterministic Fixture and Code-Fix — RESULT

**Status:** `RouteY_R1_A6_Q0C_CodeFixReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This is the **Q0-C deterministic fixture + code-fix work order**. NO live, NO protected sample, NO controller, NO spawn, NO candidate, NO cold-start. Added a deterministic offline fixture reproducing the live A6 conflict and permanent regression tests. **No production logic was changed** — only additive tests.

---

## 1. Deterministic fixture created

Added `route_y_r1_a6_q0c_contained_label_scrub_vs_mark_conflict` to `crates/pe/src/dumper/raw_slab_coherence.rs` (test module). It reproduces the exact A6 conflict deterministically:

- **A** = heap-global parent slot at `0x8e93c8`, size `0x2000` (8192), `extent_kind=ObservedAllocation`, `capture_id="heap_global_slot:0x8e93c8"`, `capture_path=MainSlot`.
- **B** = interior gscript label-table entry at `0x8e9da8`, size `0x400` (1024), `extent_kind=InteriorSubview`, `capture_id="gscript_label:0x8e9da8"`, `capture_path=GscriptChildLink`, `containing_parent_old_base=Some(A_BASE)`, `containing_parent_size=Some(A_SIZE)`.
- **B is strictly contained in A** (address containment).
- A dangling user pointer (`0x70000000`, LE `[00,00,00,70,...]`) is placed so the `0x70` non-zero byte lands at **A+0xa03 == B+0x23 == 0x8e9dcb** (the A6 conflict byte).
- `gscript` (0x8f0000) + `label table` (0x8f1000, entry=B) + string snapshot (0x900000) are present so `mark_labels_non_nested` fires on B.
- **Identity/coverage/lineage evidence recorded explicitly:** capture_id, extent_kind, capture_path, coverage membership (probe coverage validated), parent/interior lineage (`containing_parent_old_base`/`containing_parent_size`), before/after digests (via binding).
- Runs the **real production order**: `scrub_uncaptured_heap_pointers` → `mark_labels_non_nested`, then `build_patched_backing_slab_q0c`.

**Result:** A's scrub zeroes the dangling qword (A+0xa03 → 0x00); B's scrub zeroes it then `mark_labels_non_nested` sets B+0x23 = 0x01. The overlay writes the SAME slab byte `0x8e9dcb` to different values → **`OverlayError::TransformWriteConflict { a_child_old_base: A_BASE, b_child_old_base: B_BASE, .. }`** (fail-closed). This **exactly reproduces the live A6 conflict** deterministically.

## 2. Second regression test (legitimate containment)

Added `route_y_r1_a6_q0c_legitimate_containment_agrees_no_conflict`: the same A/B geometry, but B is NOT referenced from the gscript label table (empty table), so `mark_labels_non_nested` does NOT target B. Both A and B scrub the shared byte to `0x00` (agreeing writes). **The overlay SUCCEEDS** (`SharedWriteSameValue`, no false conflict) — proving legitimate contained label writes that agree with the parent are NOT over-rejected. Both A and B appear as overlays.

## 3. Root-cause verdict

**`Q0C_ConflictRootCauseFound_SeparatePatchNeeded`**

The deterministic fixture **confirms** the root cause that the earlier offline review had as a hypothesis:

- The A6 conflict is a **genuine transform-ownership disagreement on a shared slab byte** `0x8e9dcb` between two distinct captures: the parent heap-global slot A (chain `[scrub]` → writes `0x00`) and the interior gscript label B (chain `[scrub, mark_labels_non_nested]` → writes `0x01`).
- **`mark_labels_non_nested` sets B+0x23 = 1** as a REQUIRED non-nested redirect flag for the gscript cold-start path (`0xc13d0`; `heap_global_snapshot.rs:2293-2296`).
- **`scrub_uncaptured_heap_pointers` zeroes B+0x23** because that byte lies inside a qword `B[0x20..0x28)` that `is_external_dangling_ptr` classifies as a dangling external pointer (its value is not inside any captured range). The scrub walks qwords and zeroes the whole 8-byte qword, clobbering B's +0x23 flag.
- **Same interaction class as the already-mitigated `count@+0x10`** (`dump_process.rs:1240`): scrub walks every qword and can clear a live gscript field embedded in a pointer-shaped qword. `count@+0x10` was mitigated via `resynthesize_gscript_label_count`; **`+0x23` has NO such mitigation**.

**This is now CONFIRMED, not just hypothesized** — the deterministic fixture reproduces it exactly, and the mechanism is proven by the source (`is_external_dangling_ptr`, scrub qword-walk, mark_labels flag write) plus the fixture's before/after values.

### Proposed narrow fix (separate patch — NOT implemented here)

A narrow, lineage-aware fix: **protect known gscript label flag bytes (specifically `+0x23`) from scrub clobbering**, analogous to the `+0x10` mitigation. Concretely, `scrub_uncaptured_heap_pointers` should skip (not zero) a qword whose range includes a recognized label non-nested flag byte — OR, more narrowly, `mark_labels_non_nested`'s +0x23 write should be treated as owning that byte (re-applied after scrub, like `resynthesize_gscript_label_count` re-applies count@+0x10 after scrub). This is a **narrow rule keyed to known label flag ownership**, NOT a general overlap permission, NOT last-writer bypass, NOT slab fallback, NOT identity weakening.

**This fix is intentionally NOT auto-applied in this work order** — it changes production dump behavior and needs its own review + regression gates (per the work order's "如需修复" conditional and the audit's earlier "不能把 +0x23 假设直接变成 production patch"). It is deferred to a separate authorized code-fix work order.

## 4. Regression test coverage (work order §5)

| Requirement | Coverage |
|---|---|
| Legitimate label containment | `route_y_r1_a6_q0c_legitimate_containment_agrees_no_conflict` (overlay succeeds, no false positive) |
| Same address different identity | Existing suite (CaptureIdentityInvalid tests at raw_slab_coherence.rs:7826+); plus my conflict test (distinct identities at overlapping byte → TransformWriteConflict) |
| Same identity different value | Existing `route_y_r0_q0c_overlap_different_value_fails_closed`; my conflict test (distinct identities, different values at shared byte) |
| Uncovered object write | Existing suite (RawCaptureDrift / TransformPreimageDrift / RawChildOutsideSlab fail-closed) |
| Route X / Route Y existing fail-closed tests | Full mida-pe suite passes (below) |

## 5. Offline gates (all pass)

- `cargo fmt --all -- --check` → **clean** (applied `cargo fmt` to my new tests; re-check passes)
- `cargo test -p mida-pe --offline` → **664 + 7 + 2 + 3 passed** (incl. my 2 new tests), 0 failed
- `cargo test -p mida-cli --features gto-product-recovery` → **17 + 3 passed**
- `cargo test -p mida-cli --offline` → **296 + 4 + 1 + 20 + 17 + 3 passed** (1 ignored)
- `python tools/test_gto_live_route_controller.py` → **36 passed / 0 failed**
- `git diff --check` → **clean**

## 6. Git boundary

- **Source change (tracked modified):** `crates/pe/src/dumper/raw_slab_coherence.rs` — **298 insertions, 0 deletions** (purely additive; only the 2 new test functions; no production logic modified).
- **Untracked source:** 0.
- **Untracked docs:** 25 (unchanged).
- **No git add/commit** (work order forbids auto-commit).
- A6 original evidence frozen/unmodified; A6 report not touched.

---

## Required report fields

- **final status:** `RouteY_R1_A6_Q0C_CodeFixReviewRequested`
- **deterministic fixture:** created (reproduces A6 conflict: A=[0x8e93c8,+0x2000), B=[0x8e9da8,+0x400), byte 0x8e9dcb, A_after=0x00, B_after=0x01, TransformWriteConflict)
- **identity/coverage/lineage evidence:** capture_id, extent_kind, capture_path, coverage membership, parent/interior lineage, before/after digests recorded
- **root-cause verdict:** **`Q0C_ConflictRootCauseFound_SeparatePatchNeeded`** — confirmed scrub-vs-mark ownership conflict on B+0x23, same class as the mitigated count@+0x10
- **proposed fix:** protect B+0x23 from scrub (narrow lineage rule) — **deferred to separate code-fix work order, NOT applied here**
- **new tests:** 2 permanent regression tests added
- **gates:** all 6 pass (fmt, mida-pe, mida-cli×2, python controller, git diff --check)
- **no live / no protected / no controller / no spawn / no candidate / no cold-start:** confirmed
- **Git:** 1 tracked modified (additive tests), 0 untracked source, 25 docs

---

## Honesty statement

- The deterministic fixture **reproduces the exact A6 conflict** with the real production transforms (scrub → mark_labels → Q0-C overlay), and **confirms the root cause** that the earlier offline review could only hypothesize. This is genuine, reproducible evidence, not synthetic.
- **No production logic was changed** — the diff is purely additive test code (298 insertions, 0 deletions). The proposed scrub fix is deliberately **not auto-applied**, pending separate authorization, because it changes production dump behavior.
- The `+0x23` root cause is now **confirmed via deterministic fixture + source mechanism**, not address-guessing.
- All offline gates pass; no regression. No candidate generated; no cold-start; no Route Z R1; execution stopped.
- No git commit (work order forbids auto-commit).

---

## Post-execution boundary

- Source change: `crates/pe/src/dumper/raw_slab_coherence.rs` (additive tests, 298 ins/0 del).
- A6 live evidence and A6 report frozen/unmodified; no residual processes.
- Deferred: the narrow scrub-vs-+0x23 fix (separate code-fix work order).
- Only new report file: `docs/GTO_ROUTE_Y_R1_A6_Q0C_CODEFIX_RESULT.md` (untracked).
