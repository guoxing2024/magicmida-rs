# Route Y R1 A6 — Q0-C Narrow Mitigation AF2 — RESULT
## (AF2R1 delivery closure: materialized mandatory tests + report)

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF2R1_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This is the **AF2R1 交付闭环** work order. The AF2 production identity implementation was already in the working tree; this work order materialized the **10 mandatory permanent `#[test]` functions** and the **2 unique-resolution tests** that were missing, ran the full gate suite, and delivered this report. The existing AF2 full-identity production implementation is preserved unchanged in semantics (only visibility promotion `pub(crate)` for test access + a pure range-authorization helper extraction in test 8's scope). NO live, NO protected sample, NO controller, NO spawn, NO candidate, NO cold-start, NO Route Z R1, NO commit.

---

## 1. Production diff (live)

| File | Change (from HEAD) | Nature |
|---|---|---|
| `crates/pe/src/dumper/heap_global_snapshot.rs` | +443 / -3 | AF2 production identity rewrite (already in tree) + AF2R1 visibility promotion + pure range helper |
| `crates/pe/src/dumper/raw_slab_coherence.rs` | +1517 / -0 | AF2 fixture/config (already in tree) + **AF2R1 12 materialized `#[test]` functions** |

Total: **+1960 / -3**. (`git diff --check` → clean.)

The 2 deletions in `heap_global_snapshot.rs` are the old AF1 scrub call sites (already replaced by protection-aware signature in AF2). No other production logic removed.

---

## 2. CurrentScrubIdentity — fields (AF2, now `pub(crate)` for direct predicate tests)

```rust
pub(crate) enum ScrubObjectKind { HeapGlobal, Container }
pub(crate) struct CurrentScrubIdentity {
    pub(crate) kind: ScrubObjectKind,
    pub(crate) capture_id: String,
    pub(crate) extent_kind: CaptureExtentKind,
    pub(crate) capture_path: CapturePath,
    pub(crate) old_base: u64,
    pub(crate) size: usize,
}
```

Containers carry no reliable capture identity → `CurrentScrubIdentity::container` yields empty capture_id / default extent / default path, so a container **never** equals a heap-global parent identity and **never** receives Label-flag protection (work order P1-1: "如果某类 buffer 没有可靠 identity…必须继续普通 scrub").

---

## 3. LabelFlagProtection — child + parent full identity (AF2)

```rust
pub(crate) struct CaptureIdentity {
    pub(crate) capture_id: String,
    pub(crate) extent_kind: CaptureExtentKind,
    pub(crate) capture_path: CapturePath,
    pub(crate) old_base: u64,
    pub(crate) size: usize,
}
pub(crate) struct LabelFlagProtection {
    pub(crate) child: CaptureIdentity,
    pub(crate) parent: CaptureIdentity,
    pub(crate) flag_offset: usize,   // always 0x23
    pub(crate) flag_addr: u64,       // = child.old_base + 0x23 (checked_add)
    pub(crate) flag_qword_lo: u64,
    pub(crate) flag_qword_hi: u64,
}
```

**Every field participates in an authorization predicate** (no field stored-for-documentation):

| Field | Consumed in | Gate |
|---|---|---|
| current.kind | `matches_parent` | must be `HeapGlobal` |
| current.capture_id / parent.capture_id | `matches_parent` | must be **equal** (step 1) |
| current.extent_kind / parent.extent_kind | `matches_parent` | must be **equal** |
| current.capture_path / parent.capture_path | `matches_parent` | must be **equal** |
| current.old_base / parent.old_base | `matches_parent` | must be **equal** |
| current.size / parent.size | `matches_parent` + step 8 | must be **equal** |
| child.capture_id | `parse_canonical_gscript_label_capture_id` re-check at consume (step 2) | canonical type + encoded address == child.old_base |
| child.extent_kind | step 3 | must be `InteriorSubview` |
| child.capture_path | step 3 | must be `GscriptChildLink` / `GscriptFirstHop` |
| child.old_base | step 5 | flag_addr must == child.old_base + 0x23 (checked) |
| child.size | step 7 pure range fn | child range strictly inside parent, flag inside child & parent |
| flag_offset | step 4 | must be exactly 0x23 |
| flag_addr / flag_qword | step 5 + step 6 | flag inside this exact qword; qword == protection qword |
| parent.old_base / parent.size | step 7 pure range fn | child ⊆ parent, flag ⊆ parent |

**`protection_authorizes_qword`** (make it `pub(crate)`, called by scrub and directly by AF2R1 mandatory tests) requires **ALL** of:
1. `CurrentScrubIdentity.matches_parent(p.parent)` — full identity equality (kind + capture_id + extent_kind + capture_path + old_base + size);
2. child canonical capture_id re-validation;
3. child extent == InteriorSubview and path ∈ {GscriptChildLink, GscriptFirstHop};
4. flag_offset == 0x23;
5. flag_addr == child.old_base.checked_add(0x23);
6. flag_addr within [qword_lo, qword_hi) and qword == protection's flag qword;
7. pure `label_flag_range_authorized(child, parent, flag)` (checked_add only);
8. current base/size equality restated.

**`label_flag_range_authorized`** (pure, `pub(crate)`) is the narrow pure function covering checked range arithmetic (work order test 8's overflow allowance):

```rust
pub(crate) fn label_flag_range_authorized(
    child_base, child_size, parent_base, parent_size, flag_addr,
) -> bool  // false on any checked_add overflow; uses checked_add, never wrapping
```

AF2R1 test `flag_address_overflow_or_outside_parent_not_protected` proves `child_base + 0x23` at `u64::MAX - 0x10` has `checked_add == None`, and the range helper returns false (no wrapping authorization), plus a fully-contained baseline true case.

---

## 4. Canonical capture_id parsing rules (AF2, `parse_canonical_gscript_label_capture_id`)

Accepts ONLY the production emitter form `gscript_label:{live_ptr:#x}` (e.g. `gscript_label:0x8e9da8`):

- exact prefix `gscript_label:` then `0x` then lowercase hex;
- every remaining char must be `[0-9a-f]` (rejects uppercase, trailing garbage, whitespace, `:foreign`, non-hex);
- the encoded address must equal the child's `old_base`/`live_ptr` AND the string must be exactly the canonical rendering (rejects leading-zero non-canonical forms like `0x00008e9da8`).

**Rejected** (verified by mandatory tests 3 + 4):
`gscript_label:` (prefix only), `gscript_label:wrong`, `gscript_label:0x8e9000` (wrong encoded address), `gscript_label:0x8e9da8:foreign`, `gscript_label:0x8E9DA8` (uppercase), `gscript_label:0x8e9da8garbage`, `gscript_label:0x00008e9da8` (leading zero), `gscript_label:0x8e9da8x`, `gscript_label:0x8e9da8 `, `gscript_label:0x8e9da8\n`, empty string.

---

## 5. Unique resolution (AF2, `unique_heap_global`)

- 0 matches → None (no authorization, existing fail-closed semantics);
- >1 matches → None (refuse; never silently pick the first `.find()`).

Applied to: gscript object (`is_image_inline && content.len() >= 8`), label table (`live_ptr == table_ptr && content.len() >= 8`), label (`live_ptr == entry`), containing parent (`live_ptr == parent_base && content.len() == parent_size`). Parent must additionally have a non-empty capture_id.

---

## 6. The 10 AF2R1 mandatory tests — materialized + results

All 10 are real independent `#[test]` functions in `crates/pe/src/dumper/raw_slab_coherence.rs` (exact names verified by `git grep`, section 11). All pass in the full suite.

| # | Exact test name (`route_y_r1_a6_q0c_` prefix) | What it proves | Result |
|---|---|---|---|
| 1 | `same_parent_base_size_different_capture_id_not_protected` | parent base/size same, capture_id different → predicate denies + actual scrub zeroes the flag qword | **PASS** |
| 2 | `same_parent_identity_except_capture_path_not_protected` | only camera_path differs → predicate denies | **PASS** |
| 3 | `same_child_address_gscript_prefix_but_wrong_encoded_address` | `gscript_label:` prefix but encoded address mismatch → parser rejects + **full pipeline fails closed** `TransformWriteConflict` | **PASS** |
| 4 | `malformed_gscript_label_capture_id_not_protected` | table-driven: 10 malformed forms; parser independently rejects each; full pipeline for each non-empty form → `TransformWriteConflict` | **PASS** |
| 5 | `duplicate_label_same_address_fails_closed` | two labels at one table-entry address → unique resolution refuses (no first-pick) | **PASS** |
| 6 | `duplicate_parent_same_base_size_fails_closed` | two parents same base/size, different identity → refuse | **PASS** |
| 7 | `child_not_fully_contained_not_protected` | child start below parent / child end beyond parent → `label_flag_range_authorized` false (pure) + contained baseline true | **PASS** |
| 8 | `flag_address_overflow_or_outside_parent_not_protected` | `checked_add` overflow near `u64::MAX` → range helper false (no wrapping); flag outside parent → false; contained baseline true | **PASS** |
| 9 | `identity_fields_are_consumed` | **all 10 fields** — child capture_id/extent/path/old_base/size + parent capture_id/extent/path/old_base/size — each flipped independently → predicate denials (baseline match authorizes) | **PASS** |
| 10 | `final_patched_qword_is_canonical` | full real pipeline scrub→mark→recorded ledger→`build_patched_backing_slab_q0c`; overlay **succeeds**; patched `B+0x23 == 0x01`; patched flag qword = `[0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00]` (≠ original dangling `0x70000000` LE bytes `[0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00]`); A does not clobber the shared byte (A preserves `0x70`); ledger records child's zeroing scrub run **and** canonical mark run (replayable) | **PASS** |

**Mandatory test #9 field coverage — the actual 10 flips (not "9"):**

- child.capture_id → `gscript_label:0x99999999` → deny
- child.extent_kind → `ProbeWindow` → deny
- child.capture_path → `MainSlot` → deny
- child.old_base → `B_BASE + 0x10` (flag_addr no longer matches child+0x23) → deny
- child.size → `0x10` (< 0x23, flag out of bounds) → deny
- parent.capture_id → `heap_global_slot:0xDEADBEEF` → deny
- parent.extent_kind → `ProbeWindow` → deny
- parent.capture_path → `GscriptChildLink` → deny
- parent.old_base → `A_BASE + 0x100` → deny
- parent.size → `A_SIZE - 0x100` → deny

Each flip asserts the **actual authorization outcome** (the production predicate `.any()` over protections returns a skip only for the unflipped baseline; every flipped variant is denied), not merely struct-content equality.

---

## 7. Task 2 — additional unique-resolution tests (materialized)

| Test name | Proves | Result |
|---|---|---|
| `route_y_r1_a6_q0c_duplicate_gscript_refuses_protection` | **two image-inline gscript candidates** (distinct bases) → `unique_heap_global` finds >1 → no protection | **PASS** |
| `route_y_r1_a6_q0c_duplicate_label_table_refuses_protection` | **two objects at the label table pointer** → >1 table candidate → no protection | **PASS** |

---

## 8. Final patched qword (mandatory test #10 physical values)

Fixture: A=[0x8e93c8,+0x2000), B=[0x8e9da8,+0x400), slab base 0x800000, DANGLING=0x70000000.

- Original flag qword inside B: `[0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00]` (LE `0x70000000`).
- B's own scrub zeroes the 0x70 byte; `mark_labels_non_nested` sets `B+0x23 = 1`.
- **Patched slab qword at B[0x20..0x28) = `[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]`** (canonical).
- **Patched `B+0x23` byte = `0x01`.**
- The original dangling pointer value is **NOT** preserved.
- Parent A preserved its snapshot byte at the shared address (A=0x70, i.e. A never wrote 0x00 there); overlay succeeds with no parent/child conflicting write.

---

## 9. Offline gate results (all PASS)

- `cargo fmt --all -- --check` → **clean** (fmt applied; re-check passes)
- `cargo test -p mida-pe --offline` → **685 + 7 + 2 + 3 passed** (1 ignored), 0 failed
  (Q0-C suite alone: route_y_r1_a6_q0c_* → **23/23**, includes all 12 AF2R1 tests + all AF1 tests, 0 regression)
- `cargo test -p mida-cli --features gto-product-recovery` → **298 + 4 + 1 + 20 + 17 + 3 passed**
- `cargo test -p mida-cli --offline` → **296 + 4 + 1 + 20 + 17 + 3 passed**
- `python tools/test_gto_live_route_controller.py` → **36 passed / 0 failed**
- `git diff --check` → **clean**

---

## 10. Mandatory git grep evidence (exist in source — exact match)

```
crates/pe/src/dumper/raw_slab_coherence.rs:12019: fn route_y_r1_a6_q0c_same_parent_base_size_different_capture_id_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:12084: fn route_y_r1_a6_q0c_same_parent_identity_except_capture_path_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:12136: fn route_y_r1_a6_q0c_same_child_address_gscript_prefix_but_wrong_encoded_address()
crates/pe/src/dumper/raw_slab_coherence.rs:12186: fn route_y_r1_a6_q0c_malformed_gscript_label_capture_id_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:12261: fn route_y_r1_a6_q0c_duplicate_label_same_address_fails_closed()
crates/pe/src/dumper/raw_slab_coherence.rs:12290: fn route_y_r1_a6_q0c_duplicate_parent_same_base_size_fails_closed()
crates/pe/src/dumper/raw_slab_coherence.rs:12318: fn route_y_r1_a6_q0c_child_not_fully_contained_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:12355: fn route_y_r1_a6_q0c_flag_address_overflow_or_outside_parent_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:12403: fn route_y_r1_a6_q0c_identity_fields_are_consumed()
crates/pe/src/dumper/raw_slab_coherence.rs:12555: fn route_y_r1_a6_q0c_final_patched_qword_is_canonical()
crates/pe/src/dumper/raw_slab_coherence.rs:12623: fn route_y_r1_a6_q0c_duplicate_gscript_refuses_protection()
crates/pe/src/dumper/raw_slab_coherence.rs:12660: fn route_y_r1_a6_q0c_duplicate_label_table_refuses_protection()
```

---

## 11. Live git boundary

- **tracked modified (2):**
  - `crates/pe/src/dumper/heap_global_snapshot.rs` (+443 / -3, production + visibility + pure range helper)
  - `crates/pe/src/dumper/raw_slab_coherence.rs` (+1517 / -0, tests including 12 AF2R1 + AF2 fixture/config)
- **untracked source:** 0
- **untracked docs:** **28 before this report → 29 after** (this file `GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_AF2_RESULT.md` is newly untracked; counted live via `git status --short`)
- **No git add/commit** (work order forbids auto-commit)
- A6 original evidence frozen/unmodified; A6 report not touched.
- No live / protected sample / controller / spawn / candidate / cold-start / promote / Route Z R1.
- Supervisor Production Integration NOT executed; no second protected live authorized.

---

## Honesty statement

- The 10 mandatory AF2R1 tests and the 2 unique-resolution tests are **real, materialized `#[test]` functions** in the working tree, each found by exact `git grep` (section 10) and each passing in the full offline suite (section 9). Nothing claimed is absent from source.
- The AF2 full-identity production implementation was **already** in the tree and is preserved; AF2R1 only promoted visibility to `pub(crate)` (so the mandatory tests can call `protection_authorizes_qword` / `parse_canonical_gscript_label_capture_id` / `gscript_label_flag_protections` / `label_flag_range_authorized` directly, per work order) and extracted the pure range helper. No authorization semantics weakened; `resolved_writes` / last-writer / binding / slab slice+digest / run-membership checks untouched.
- Mandatory test #9 covers the **actual 10 fields** (child 5 + parent 5), not the outdated "9".
- Final patched qword bytes are asserted from the real production pipeline (scrub → mark → recorded ledger → Q0-C overlay), not manufactured.
- `git diff --check` clean; all 6 gates green; Route X/Y fail-closed tests unchanged.
- No candidate generated (the only patched fixture is in-memory inside mandatory test #10); no commit.

---

## Post-execution boundary

- Production file: `crates/pe/src/dumper/heap_global_snapshot.rs` (+443/-3). Tests: `crates/pe/src/dumper/raw_slab_coherence.rs` (+1517/-0).
- A6 evidence + A6 report frozen/unmodified; no residual processes.
- New report file: `docs/GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_AF2_RESULT.md` (untracked).
- Stopped. Awaiting independent audit. No Supervisor Production Integration; no second protected live; no commit.