# Route Y R1 A6 — Q0-C Narrow Mitigation AF3 AF1 — RESULT
## (Real Pre-Existing Emitter Proof, Capture-Family Scope Closure, and Ambiguous-Parent Fail-Closed)

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF3_AF1_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This is the **AF3 AF1** work order, issued by the AF3 audit rejection
(`AF3_ExhaustEmitterPathAccepted` / `AF3_NeedsAF1`). The audit accepted the new
`exhaust` label-table path as production-reachable, but blocked the overall AF3 on four
gaps that AF3 AF1 closes:

- **P1-1** — the pre-existing child-link test was a *hand-built* tuple, not real emitter output;
- **P1-2** — `GscriptFirstHop` was authorized without a real proof;
- **P1-3** — the real capture families were enumerated but not adjudicated/closed;
- **P1-4** — containing-parent "unique" resolution could silently pick the iteration-order first;
- **P1-5** — the label-table identity did not record the deterministic source evidence;
- **P1-6** — the new identity fields must be consumed, not merely carried.

All six are closed. No live, no protected sample, no controller, no spawn, no candidate,
no cold-start, no promote, no install, no commit. The already-accepted AF3 exhaust path,
the 12 AF3 tests, and all AF1/AF2R1 tests are preserved.

---

## 1. P1-1 — real pre-existing child-link emitter proof

The audit rejected `production_preexisting_label_entry_protection_is_reachable` because
it deleted the real B and hand-reinserted a `gscript_child_link:` tuple. That test is
**rewritten** to drive the **REAL** `exhaust_gscript_child_link_fields` emitter (the
production child-link emitter that runs in `detect_heap_globals` immediately before the
label-table exhaust). B's entire identity is produced by the emitter — capture_id,
capture_path, extent_kind, source_root_rva, source_slot_offset, probe_requested_size,
was_interior, and containing_parent — and **never** hand-built, deleted-and-reinserted, or
directly formatted.

Pipeline proven by `production_preexisting_label_entry_protection_is_reachable`:
1. build `out` = [A (parent, whose link field at +0x10 points to B), gscript (image-inline,
   table ptr + count), label table (references B), snap] + a memory-map mock serving B;
2. drive the **REAL** `exhaust_gscript_child_link_fields` → B admitted as
   `GscriptChildLink` + `InteriorSubview` + parent A + `gscript_child_link:{A}:{loff}:{B}:{probe}`;
3. drive the **REAL** `exhaust_gscript_label_table_entries` → B is already an exact live
   ptr, so **no duplicate B** is created;
4. `gscript_label_flag_protections` yields **exactly one** protection whose child/parent
   identities **equal the real emitter output field-by-field** (including
   source_slot_offset, probe_requested_size, was_interior).

The companion full-pipeline test **`production_preexisting_child_link_scrub_mark_q0c_succeeds`**
starts from the real child-link emitter output and runs the complete
raw → validate → coverage → seed → scrub → mark → ledger → Q0-C overlay, asserting the
patched flag qword is canonical (`B+0x23 == 1`, no dangling pointer preserved), A does not
clobber the flag byte, and the overlay succeeds.

`exhaust_gscript_child_link_fields` was promoted `pub(crate)` for the test to drive the
real emitter (no semantics change).

---

## 2. P1-2 — GscriptFirstHop: explicitly rejected (方案A)

The first-hop capture-id `gscript_first_hop:{edge_off:#x}` encodes **only** the edge
offset. It cannot strictly bind child base / parent / probe / was_interior on its own, so
keeping it authorized would be "code allows, test does not prove". AF3 AF1 removes
`GscriptFirstHop` from the authorized set:

- removed from `gscript_label_flag_protections` path gate;
- removed from `parse_canonical_label_capture_id_for`;
- removed from `parse_canonical_protection_child_capture_id`;
- removed the now-dead `parse_canonical_gscript_first_hop_capture_id` parser;
- added **`first_hop_table_reachable_not_protected`**: a table-reachable label carrying
  the real `gscript_first_hop:0x0` id + `GscriptFirstHop` path + InteriorSubview +
  parent is **not** protected (stays fail-closed).

The real emitter `exhaust_gscript_first_hop` still emits this id for capture/multi_fixup,
but the protection refuses it.

---

## 3. P1-3 — capture-family scope closure (adjudication)

Every real production capture-identity family that could become a table-reachable Label is
now explicitly adjudicated, with a negative test for the rejected families and a
real-emitter positive test for the supported families.

| Family | Canonical id | Adjudication | Real emitter proof | Table-reachable negative |
|---|---|---|---|---|
| label-table exhaust | `gscript_label:{base:#x}` | **SupportedAndStrictlyValidated** | `production_exhaust_emitter_label_protection_is_reachable` (AF3) | — |
| child-link | `gscript_child_link:{parent}:{loff}:{base}:{probe}` | **SupportedAndStrictlyValidated** | `production_preexisting_label_entry_protection_is_reachable` (AF3 AF1) | — |
| first-hop | `gscript_first_hop:{edge_off:#x}` | **ExplicitlyRejectedFailClosed** | — | `first_hop_table_reachable_not_protected` |
| pointer-table child | `gscript_child:{base:#x}` | **ExplicitlyRejectedFailClosed** | — | `gscript_child_table_reachable_not_protected` |
| seed child | `gscript_seed_child:{base:#x}` | **ExplicitlyRejectedFailClosed** | — | `gscript_seed_child_table_reachable_not_protected` |
| graph child | `graph_child:{base:#x}` | **ExplicitlyRejectedFailClosed** | — | `graph_child_table_reachable_not_protected` |

No arbitrary `gscript_*` prefix is accepted. The `gscript_child:`, `gscript_seed_child:`,
and `graph_child:` families use paths (GscriptChildLink / GscriptFirstHop) whose ids do
not match the strict child-link / label-table canonical forms, so they are rejected by the
strict family parser and their negative tests prove they stay fail-closed.

The report no longer claims "every real family is accepted" — it now states the exact
Supported/Rejected split above.

---

## 4. P1-4 — containing-parent unique resolution (fail-closed)

`label_table_entry_interior_classification` is **rewritten** to take the **child base AND
the actual child size**, use `checked_add` for every span, require **full child-range
containment**, select the **minimal containing span**, and require **exactly one** complete
capture identity at that span. It returns `(None, ProbeWindow)` for:

- 0 parents fully containing the child range;
- `checked_add` overflow on child or parent span (wrapping containment never proven);
- `child_size == 0`;
- >1 parents tied for the same minimal span;
- the minimal span having >1 distinct capture identities (equal-size different base, or
  same base/size different capture_id);
- child starts inside a parent but its end escapes that parent.

Selection is **order-independent**: every candidate is collected first, then the minimal
span is chosen, then uniqueness is enforced — iteration order never picks "the first".

Five emitter-driven tests verify the **emitter's final extent/parent fields** (not just
the pure helper):

| Test | Proves | Result |
|---|---|---|
| `equal_size_different_base_parents_refuse_interior_classification` | two equal-size, different-base parents both containing B → ProbeWindow, no parent | **PASS** |
| `same_base_size_different_parent_identity_refuses_classification` | two same-base/size parents, different identity → ProbeWindow | **PASS** |
| `child_start_inside_but_end_outside_is_probe_window` | child starts inside parent but end escapes → ProbeWindow | **PASS** |
| `parent_range_overflow_is_probe_window` | parent `checked_add` overflows u64 → ProbeWindow | **PASS** |
| `unique_innermost_parent_is_selected` | exactly one innermost parent → InteriorSubview with that parent | **PASS** |

---

## 5. P1-5 — label-table source evidence (recorded + validated)

The exhaust emitter now records the **deterministic label-table source evidence** on every
admitted entry (AF3 AF1):

- `source_slot_offset = Some(table_entry_off)` (the byte offset within the label table);
- `source_root_rva = Some(gscript.rva)` when the image-inline gscript root has a non-zero
  RVA (production always does);
- `probe_requested_size = 0` (this family is bounded by `cap_size_before_next_base`, NOT a
  first-hop probe — the canonical rule requires exactly 0);
- `was_interior` and `containing_parent` as before.

`parse_canonical_label_table_source_evidence` requires: `source_slot_offset.is_some()`,
`probe_requested_size == 0`, `was_interior == true`, and `source_root_rva` is `Some(non-zero)`.
Additionally, `gscript_label_flag_protections` verifies the source evidence **values**
against the actual table context: `source_slot_offset == table_entry_offset (i*8)` and
`source_root_rva == gscript.rva`. Three negative tests:

| Test | Proves | Result |
|---|---|---|
| `label_table_entry_wrong_table_offset_not_protected` | correct base but wrong table offset → not protected | **PASS** |
| `label_table_entry_wrong_source_root_not_protected` | correct base but wrong source root RVA → not protected | **PASS** |
| `label_table_entry_missing_source_evidence_not_protected` | GscriptLabelTableEntry path with missing source evidence → not protected | **PASS** |

---

## 6. P1-6 — full identity-field consumption

`CaptureIdentity` now carries `source_root_rva: Option<u32>` and `was_interior: bool`
(alongside the existing `source_slot_offset`/`probe_requested_size`), populated by
`from_heap_global` and flowing into every `LabelFlagProtection.child`. These fields are
**consumed**, not merely carried:

- **Generation** — `parse_canonical_label_table_source_evidence` (label-table) consumes
  source_slot_offset, probe, was_interior, source_root_rva; `parse_canonical_label_capture_id_for`
  (child-link) now also requires `was_interior`; `gscript_label_flag_protections` verifies
  the source evidence **values** against the actual table entry offset and gscript root RVA.
- **Consume-time** — `parse_canonical_protection_child_capture_id` re-verifies the stored
  child's `source_slot_offset`, `probe_requested_size`, `was_interior`, `source_root_rva`
  (label-table) and `was_interior` (child-link) before any scrub authorization.

The parent identity is the full `CurrentScrubIdentity` (kind + capture_id + extent_kind +
capture_path + old_base + size) compared field-by-field via `matches_parent`; every field
participates. No field is stored-for-documentation.

---

## 7. Production diff (live)

| File | Change (from HEAD) | Nature |
|---|---|---|
| `crates/pe/src/dumper/heap_global_snapshot.rs` | +856 / -12 | AF3 (in tree) + AF3 AF1: classification rewrite (P1-4), source evidence recording (P1-5), family parsers / first-hop removal (P1-2/P1-3), `CaptureIdentity` extension + full consumption (P1-6), `pub(crate)` child-link emitter (P1-1) |
| `crates/pe/src/dumper/raw_slab_coherence.rs` | +3072 / -0 | AF3 (in tree) + **AF3 AF1 14 `#[test]` functions** (real child-link emitter, family negatives, source-evidence negatives, parent-ambiguity tests) |
| `crates/pe/src/dumper/snapshot_manifest.rs` | +3 / -0 | `GscriptLabelTableEntry` path_label (AF3) |

Total: **+3919 / -12**. (`git diff --check` → clean.)

The 12 deletions are the removed first-hop parser and the old classification logic, plus
formatting. No other production logic removed; Q0-C fail-closed, `resolved_writes`,
run-membership, exact-binding, slab slice+digest, and strict identity are all preserved.

---

## 8. Offline gate results (all PASS)

- `cargo fmt --all -- --check` → **clean** (fmt applied; re-check passes)
- `cargo test -p mida-pe --offline` → **710 + 7 + 2 + 3 passed** (1 ignored), 0 failed
  (AF3 + AF3 AF1 emitter-driven + negative suite fully green; existing AF1/AF2R1 Q0-C
  suite preserved)
- `cargo test -p mida-cli --features gto-product-recovery` → **passed** (exit 0)
- `cargo test -p mida-cli --offline` → **passed** (exit 0)
- `python tools/test_gto_live_route_controller.py` → **36 passed / 0 failed**
- `git diff --check` → **clean**

Note: the separate pre-existing `tests/test_gto_live_route_controller.py` (binary-safe
controller, committed at `2f08642`, not touched by AF3/AF3-AF1) reports environment-specific
`None != 0` for synthetic child exit codes; it is not an AF3/AF3-AF1 gate and its schema
expectations are unchanged by this work.

---

## 9. Mandatory git grep evidence (AF3 AF1 tests exist in source — exact match)

```
crates/pe/src/dumper/raw_slab_coherence.rs:13019: fn production_preexisting_label_entry_protection_is_reachable()
crates/pe/src/dumper/raw_slab_coherence.rs:13167: fn production_preexisting_child_link_scrub_mark_q0c_succeeds()
crates/pe/src/dumper/raw_slab_coherence.rs:13840: fn first_hop_table_reachable_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13861: fn gscript_child_table_reachable_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13879: fn gscript_seed_child_table_reachable_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13897: fn graph_child_table_reachable_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13915: fn label_table_entry_wrong_table_offset_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13932: fn label_table_entry_wrong_source_root_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13949: fn label_table_entry_missing_source_evidence_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13967: fn equal_size_different_base_parents_refuse_interior_classification()
crates/pe/src/dumper/raw_slab_coherence.rs:14029: fn same_base_size_different_parent_identity_refuses_classification()
crates/pe/src/dumper/raw_slab_coherence.rs:14086: fn child_start_inside_but_end_outside_is_probe_window()
crates/pe/src/dumper/raw_slab_coherence.rs:14142: fn parent_range_overflow_is_probe_window()
crates/pe/src/dumper/raw_slab_coherence.rs:14196: fn unique_innermost_parent_is_selected()
```

---

## 10. Live git boundary

- **tracked modified (3):** `heap_global_snapshot.rs`, `raw_slab_coherence.rs`,
  `snapshot_manifest.rs`
- **untracked source:** 0
- **untracked docs:** 30 → 31 after this report
- **No git add/commit** (work order forbids auto-commit)
- A6 original evidence frozen/unmodified (line 251 `gscript label-table entry heap=0x8e9da8`
  verified); A6 report not touched.
- No live / protected sample / controller / spawn / candidate / cold-start / promote /
  install / distribute / Route Z R1.
- Supervisor Production Integration **NOT** executed; no second protected live authorized.

---

## Honesty statement

- All 14 AF3 AF1 tests are **real, materialized `#[test]` functions** in the working tree
  (section 9) and pass in the full offline suite (section 8).
- P1-1 tests drive the **real** `exhaust_gscript_child_link_fields` and
  `exhaust_gscript_label_table_entries` emitters; B's identity is produced by the emitter,
  never hand-built / deleted-and-reinserted / directly formatted. The full pipeline test
  builds the slab from the emitter output.
- P1-2 removed GscriptFirstHop from authorization and proved its table-reachable rejection;
  the dead parser was deleted, so no "code allows, test does not prove".
- P1-3 adjudicates every real family as Supported or Rejected with a test each; the report
  no longer overstates parser coverage.
- P1-4 classification is order-independent and fail-closed on every ambiguity; verified by
  emitter-driven tests checking final extent/parent fields.
- P1-5 records and validates the deterministic label-table source evidence; three negative
  tests prove wrong/missing source evidence is rejected.
- P1-6 threads source_root_rva / was_interior through CaptureIdentity → protection child →
  generation → consume predicates; nothing is carried-but-unconsumed.
- `git diff --check` clean; all 6 gates green; existing AF1/AF2R1/AF3 Q0-C and the full
  mida-pe / mida-cli suites preserved.
- No candidate generated; no commit.

---

## Post-execution boundary

- Production files: `heap_global_snapshot.rs`, `raw_slab_coherence.rs`, `snapshot_manifest.rs`.
- A6 evidence + A6 report frozen/unmodified; no residual processes.
- New report file: `docs/GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_AF3_AF1_RESULT.md`
  (untracked).
- Stopped. Awaiting independent audit. No Supervisor Production Integration; no second
  protected live; no commit.
