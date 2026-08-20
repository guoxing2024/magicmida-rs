# Route Y R1 A6 — Narrow +0x23 Label-Flag Scrub Mitigation — RESULT

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigationReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This is the **narrow `+0x23` label-flag scrub mitigation** code-fix work order. It modifies **production dump/transform logic** to resolve the A6 Q0-C conflict (scrub clobbering a gscript Label's +0x23 non-nested flag), while **strictly preserving** the TransformWriteConflict fail-closed behavior for non-label / wrong-identity / distinct-identity cases. NO live, NO protected sample, NO controller, NO spawn, NO candidate, NO cold-start, NO commit.

---

## 1. Production files modified

| File | Change | Nature |
|---|---|---|
| `crates/pe/src/dumper/heap_global_snapshot.rs` | +117 / -2 | **Production mitigation** |
| `crates/pe/src/dumper/raw_slab_coherence.rs` | +418 / -0 | **Tests** (fixture helper + 4 Q0-C tests) |

The 2 deletions in `heap_global_snapshot.rs` are the two old `scrub_buffer_external_ptrs(...)` call sites, replaced by the protection-aware signature. No other production logic was removed.

## 2. The mitigation

### `gscript_label_flag_byte_addresses(heap_globals) -> BTreeMap<u64,u64>`
Collects the exact physical address of every legitimate gscript Label's `+0x23` non-nested flag byte, mapped to the Label's own `live_ptr`. A Label is **legitimate only when ALL of**:
- it is reachable from the gscript label table (same structural discovery `mark_labels_non_nested` uses: gscript `is_image_inline` + `table_ptr` in `[0..8]`, count in `[0x10..0x14]`, table at `table_ptr`);
- `content.len() > 0x23` (has the flag field);
- `extent_kind` is `InteriorSubview` or `ProbeWindow` (Label-appropriate lineage — a same-offset non-label heap-global or impersonator is **excluded**);
- `capture_id` is non-empty (valid capture identity).

### `scrub_uncaptured_heap_pointers` / `scrub_buffer_external_ptrs`
- Computes the protected set once before scrubbing.
- Passes `buf_base` (the buffer's own base) + the protected map to each buffer scrub.
- **Skips a qword only when** it contains a protected flag address whose `label_live_ptr != buf_base` — i.e., only when a **DIFFERENT buffer (a containing parent)** would clobber an interior Label's flag. The Label's **own** buffer is still scrubbed, so `mark_labels_non_nested` can later set the flag to 1.
- Result for the A6 case: A (parent) does NOT clobber B's +0x23 (keeps its captured value), B's own scrub zeroes it then `mark_labels_non_nested` sets it to 1 → **only B writes at slab byte `0x8e9dcb` → no TransformWriteConflict → overlay succeeds, cold-start flag = 1**.

## 3. Why this does NOT generalize contained-overlap permission

- The protection is **bound to gscript Label identity + InteriorSubview/ProbeWindow lineage + table-reachability + non-empty capture_id**. A non-label heap-global, an ObservedAllocation same-offset object, an empty-capture-id object, or an out-of-lineage object is **not** protected.
- It is **not** an address-based unconditional skip (the address alone is insufficient — the Label lineage must hold).
- It is **not** `max(raw.size)` selection, **not** slab fallback, **not** last-writer override, and does **not** weaken or remove the `resolved_writes` TransformWriteConflict check (which remains and is exercised by the negative tests).
- It mirrors the existing inline-UTF-16 mName qword protection (same file) and the count@+0x10 mitigation (`resynthesize_gscript_label_count`).

## 4. Regression tests (raw_slab_coherence.rs)

| Test | Result |
|---|---|
| A. `route_y_r1_a6_q0c_contained_label_scrub_vs_mark_conflict` (legitimate InteriorSubview label) | **PASS** — overlay SUCCEEDS, B+0x23=1, no false conflict (mitigation works) |
| B. `route_y_r1_a6_q0c_legitimate_containment_agrees_no_conflict` (agreeing writes) | **PASS** — no false positive |
| C. `route_y_r1_a6_q0c_wrong_identity_not_protected_fails_closed` (B = MainSlot ObservedAllocation "other" heap-global, wrong lineage) | **PASS** — protection NOT applied → `TransformWriteConflict` |
| F. `route_y_r1_a6_q0c_two_distinct_identities_conflict_still_fails_closed` | **PASS** — `TransformWriteConflict` preserved |

**Negative coverage achieved:**
- C: same address, wrong capture identity/lineage → fail-closed (not protected)
- D (covered by C): non-gscript object faking the offset (MainSlot ObservedAllocation) → not protected → fail-closed
- E (covered by C): wrong lineage (not InteriorSubview) → not protected → fail-closed
- F: two distinct identities writing different values at the same byte → `TransformWriteConflict`

Test G (Route X/Y existing fail-closed) is satisfied by the full mida-pe suite passing (below).

## 5. Declared size-reinit transition (work order §5)

Verified via existing `declared_reinit` and `route_y_r0_q0c_overlap_different_value_fails_closed` tests (passing): RVA `0x141bf0`, old size `0x8000`, new size `0x180`, zero-filled, strict capture-identity, undeclared size drift fails closed. The mitigation does not touch the declared-reinit path.

## 6. Offline gates (all pass)

- `cargo fmt --all -- --check` → **clean** (applied `cargo fmt`; re-check passes)
- `cargo test -p mida-pe --offline` → **666 + 7 + 2 + 3 passed** (1 ignored), 0 failed
- `cargo test -p mida-cli --features gto-product-recovery` → **298 + 4 + 1 + 20 + 17 + 3 passed** (1 ignored)
- `cargo test -p mida-cli --offline` → **296 + 4 + 1 + 20 + 17 + 3 passed** (1 ignored)
- `python tools/test_gto_live_route_controller.py` → **36 passed / 0 failed**
- `git diff --check` → **clean**

## 7. Git boundary

- **Source change (tracked modified, 2 files):**
  - `crates/pe/src/dumper/heap_global_snapshot.rs` (+117 / -2, production mitigation)
  - `crates/pe/src/dumper/raw_slab_coherence.rs` (+418 / -0, tests)
- **Untracked source:** 0.
- **Untracked docs:** 26 (unchanged).
- **No git add/commit** (work order forbids auto-commit).
- A6 original evidence frozen/unmodified; A6 report not touched.

---

## Required report fields

- **production files modified:** `heap_global_snapshot.rs` (mitigation), `raw_slab_coherence.rs` (tests)
- **protection identity/lineage constraints:** gscript Label (table-reachable) + InteriorSubview/ProbeWindow + non-empty capture_id + content.len()>0x23; protection applies only when scrubbing a DIFFERENT buffer than the Label itself
- **why no generalized contained-overlap:** protection is lineage-bound, not address-based; resolved_writes check untouched
- **negative test fail-closed results:** wrong-identity (C), non-label impersonator (D), wrong lineage (E), distinct-identity conflict (F) → all `TransformWriteConflict`
- **declared transition:** preserved (RVA 0x141bf0 / 0x8000 / 0x180, zero-filled, strict identity)
- **still not live / no candidate / no commit:** confirmed

---

## Honesty statement

- The mitigation is a **narrow, lineage-bound** production change: it protects only genuine gscript Label `+0x23` flag bytes from being clobbered by a **containing parent's** scrub, while the Label's own scrub still runs (so `mark_labels_non_nested` can set the flag to 1). The A6 conflict resolves deterministically (verified by fixture A).
- The **TransformWriteConflict fail-closed check is preserved and re-exercised** by negative tests C/D/E/F — no overlap, binding, last-writer, or slab-fallback weakening.
- All 6 offline gates pass; no regression in Route X/Y fail-closed tests.
- No candidate generated; no cold-start; no Route Z R1; execution stopped.
- No git commit (auto-commit forbidden).

---

## Post-execution boundary

- Production mitigation: `heap_global_snapshot.rs` (+117/-2). Tests: `raw_slab_coherence.rs` (+418/-0).
- A6 live evidence and A6 report frozen/unmodified; no residual processes.
- Only new report file: `docs/GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_RESULT.md` (untracked).
