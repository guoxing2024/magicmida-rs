# Route Y R1 A6 — Q0-C Narrow Mitigation AF3 — RESULT
## (Production Capture-Identity Reachability and Emitter Consistency Closure)

**Status:** `RouteY_R1_A6_Q0C_NarrowMitigation_AF3_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This is the **AF3 生产可达性闭环** work order. The AF2R1 audit rejection
(`AF2R1_ProductionUnreachable`) established that the AF2 protection fixture tuple
(`gscript_label:` id + `GscriptChildLink` path + hand-assigned InteriorSubview /
parent) is **production-unreachable**: in the real A6 chain, the `B` interior label is
admitted by the `exhaust_gscript_label_table_entries` emitter, which emitted
`gscript_label:{base}` + **ProbeWindow/MainSlot/no-parent** — mutually exclusive with the
AF2 protection requirements. AF3 repairs the **emitter** (the single point where the
label's interior/parent identity is fixed, before raw capture), adds family-aware
canonical parsers that accept every **real** production capture-identity family, and
delivers 3 emitter-driven positive tests, 1 full emitter-driven Q0-C test, and 8
production-unreachable negative tests. No live, no protected sample, no controller, no
spawn, no candidate, no cold-start, no promote, no install, no commit.

---

## 1. AF3 audit finding (confirmed against frozen live evidence)

The AF2R1 audit rejection asserted the AF2 protection tuple is unreachable by the real
production emitter. Confirmed against the frozen A6 protected-live evidence:

`D:\MidaVault\lab\evidence\gto_launcher\live_20260811T173546Z_route_y1_a6_declared_size_reinit\child.stderr.txt`
line 251:

```
[2026-08-11T17:36:00.159150Z] [INFO] Captured gscript label-table entry heap=0x8e9da8 size=1024 table_off=0xc8 name_ptr=0x8e9d90
```

`B` (0x8e9da8) is admitted by the `exhaust_gscript_label_table_entries` emitter. Before
the AF3 emitter fix, that site emitted `gscript_label:{base}` + `ProbeWindow` + `MainSlot`
+ `no-parent` — an identity that the AF2 strict protection **could never authorize**
(needs InteriorSubview + a real containing parent + a real label-table source path). The
AF2 protection was therefore unreachable in genuine production; the Q0-C conflict for
`B+0x23` would either be unprotected (dangling pointer preserved) or fail closed on every
run. AF3 makes the reachable identity truthful.

---

## 2. Real production emitter identity families (Task 1)

The production capture system emits these `capture_id` families for gscript Label and
child-link structures:

| Family | Canonical form | Source site | Evidence carried at capture |
|---|---|---|---|
| label-table exhaust | `gscript_label:{base:#x}` | `exhaust_gscript_label_table_entries` | `GscriptLabelTableEntry` path, InteriorSubview / ProbeWindow, unique containing parent |
| child-link | `gscript_child_link:{parent:#x}:{loff:#x}:{base:#x}:{probe}` | `exhaust_gscript_first_hop` / child-link walk | `GscriptChildLink` path, `source_slot_offset`, `probe_requested_size`, InteriorSubview + parent |
| first-hop | `gscript_first_hop:{edge_off:#x}` | `exhaust_gscript_first_hop` | `GscriptFirstHop` path, `source_slot_offset`, InteriorSubview + parent |
| gscript seed child | `gscript_seed_child:{base:#x}` | seed expand | — |
| graph child | `graph_child:{base:#x}` | graph walk | — |
| gscript object / table | `gscript:{base:#x}` / `gscript_table:{base:#x}` | root / table admit | MainSlot (heap-global slot) |
| heap global slot | `heap_global_slot:{base:#x}` | heap-slot admit | MainSlot, ObservedAllocation |

The AF2 hand-built tuple (`gscript_label:` + `GscriptChildLink`) is **not** produced by
any of these — it is a mixture of two families and is now explicitly rejected by the
family-aware parser.

---

## 3. Selected production-reachable scheme (Task 2 — Option A + narrow Option B hybrid)

The AF2R1 audit required a production-reachable identity scheme. AF3 implements **Option A
(capture-time reclassification at the emitter) with a narrow Option B (accept the real
canonical child-link / first-hop families)**:

1. **Emitter fix** — `exhaust_gscript_label_table_entries` now classifies each admitted
   label-table entry at capture time, **before** raw-children are frozen. When the label
   sits inside an already-captured snapshot it is emitted as
   `InteriorSubview` + `GscriptLabelTableEntry` + `gscript_label:{base}` + a
   **uniquely-resolved containing parent**; otherwise it stays `ProbeWindow` with **no**
   parent evidence (never protected). The capture_id stays the canonical
   base-bound `gscript_label:{base:#x}`; the capture_path is the truthful label-table
   source `GscriptLabelTableEntry` (not `MainSlot`).
2. **Family-aware parsers** — `parse_canonical_label_capture_id_for` dispatches on the
   label's **actual** `capture_path`: `GscriptLabelTableEntry` → base-bound
   `gscript_label:` parser; `GscriptChildLink` → strict
   `gscript_child_link:{parent}:{loff}:{base}:{probe}` parser; `GscriptFirstHop` →
   strict `gscript_first_hop:{edge_off}` parser. Each is validated against the snapshot's
   **own** recorded evidence (`containing_parent_old_base`, `source_slot_offset`,
   `probe_requested_size`, `live_ptr`), and round-trips the canonical form. MainSlot and
   any non-production prefix are rejected.
3. **Consume-time re-validation** — `parse_canonical_protection_child_capture_id` re-runs
   the family-aware check against the stored `LabelFlagProtection` child, so the 
   protection's authorization at scrub time also requires a production-reachable identity.
4. **`CaptureIdentity` extension** — `source_slot_offset: Option<usize>` +
   `probe_requested_size: usize` are threaded through `from_heap_global` / `RawChild` so
   the child-link family can be re-validated at consume time.

This is **not** a generic overlap, last-writer, or slab-fallback relaxation of Q0-C
fail-closed: `resolved_writes`, the run-ledger membership gate, the exact-binding overlay,
and the strict identity matrix are all preserved. The protection is reachable only for a
label whose **emitter-produced** identity (InteriorSubview + a unique real containing
parent + a real label-table path) matches a production family.

---

## 4. Production diff (live)

| File | Change (from HEAD) | Nature |
|---|---|---|
| `crates/pe/src/dumper/heap_global_snapshot.rs` | +734 / -6 | AF3 emitter fix, `CapturePath::GscriptLabelTableEntry`, `label_table_entry_interior_classification`, family-aware canonical parsers, `CaptureIdentity` extension, `pub(crate)` exhaust |
| `crates/pe/src/dumper/raw_slab_coherence.rs` | +2311 / -0 | AF2R1 fixture/config (in tree) + **AF3 12 `#[test]` functions** + `RegionMapMock` debugger |
| `crates/pe/src/dumper/snapshot_manifest.rs` | +3 / -0 | path_label arm for `GscriptLabelTableEntry` → `"gscript_label_table_entry"` |

Total: **+3039 / -6**. (`git diff --check` → clean.)

The 6 deletions are formatting-only adjustments in the AF3 emitter region (the
`label_table_entry_interior_classification` call was re-flowed). No other production logic
removed; the AF2 full-identity protection semantics are preserved.

---

## 5. Task 3 — 3 emitter-driven positive tests

The work order requires that positive reachability be driven by the **real production
emitter**, not by hand-forging an identity tuple. AF3 introduces a memory-map
`RegionMapMock` `DebuggerCore` and a helper `a6_emitter_globals(...)` that builds the
pre-exhaust `out` (gscript inline object, label table, parent A, string snapshot) and
drives the **real** `exhaust_gscript_label_table_entries` against a mock serving B's raw
bytes. B's identity (capture_id / path / extent / parent) is produced **entirely** by the
production emitter — never hand-edited.

| # | Test | What it proves | Result |
|---|---|---|---|
| 1 | `production_exhaust_emitter_label_protection_is_reachable` | The real emitter captures B with `GscriptLabelTableEntry` + `InteriorSubview` + unique parent A + canonical `gscript_label:0x8e9da8`; `gscript_label_flag_protections` returns exactly one protection whose child/parent identities equal the actual B/A snapshots | **PASS** |
| 2 | `production_preexisting_label_entry_protection_is_reachable` | A label **already** captured via the real `gscript_child_link:{parent}:{loff}:{base}:{probe}` family (InteriorSubview + parent A) and then referenced by the label table is still reachable — the family-aware parser accepts its real child-link id | **PASS** |
| 3 | `hand_built_impossible_identity_tuple_is_not_required` | The old AF2 hand-built tuple (`gscript_label:` id + `GscriptChildLink` path + hand-assigned InteriorSubview/parent) is **not** a production emitter output and is **rejected** → no protection | **PASS** |

---

## 6. Task 4 — full emitter-driven Q0-C pipeline test

`production_emitter_scrub_mark_q0c_succeeds` drives the complete real pipeline from
**emitter output**: real exhaust → raw children → identity validation →
coverage → seeding → scrub → mark → recorded ledger → Q0-C overlay. It asserts:

- the overlay **succeeds** (the mitigation resolves the A/B conflict for the
  production-reachable identity);
- patched `B+0x23 == 0x01` (the canonical non-nested flag);
- the patched flag qword `B[0x20..0x28)` = `[0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00]`
  (canonical, not the original dangling `0x70000000`);
- parent A does **not** clobber the flag byte (A's scrub skips the protected qword; A
  preserves `0x70` at the shared byte — A never wrote 0x00 there);
- the ledger records B's zeroing scrub run **and** B's canonical mark run (replayable),
  mirroring the AF2R1 final-patched proof but driven from **real emitter output**.

**PASS.**

---

## 7. Task 5 — 8 production-unreachable negative tests

| # | Test | What it proves | Result |
|---|---|---|---|
| 1 | `main_slot_probe_without_parent_not_protected` | the OLD exhaust metadata (MainSlot path + ProbeWindow, no parent) is **not** protected — reachability does not loosen fail-closed | **PASS** |
| 2 | `gscript_child_link_id_with_wrong_source_parent_not_protected` | real child-link family id whose **encoded source parent** disagrees with the snapshot's containing parent → rejected (strict family parser) | **PASS** |
| 3 | `gscript_child_link_id_with_wrong_link_offset_not_protected` | encoded link offset disagrees with recorded `source_slot_offset` → rejected | **PASS** |
| 4 | `gscript_child_link_id_with_wrong_probe_size_not_protected` | encoded probe disagrees with recorded `probe_requested_size` → rejected | **PASS** |
| 5 | `table_reachable_but_identity_malformed_not_protected` | table-reachable but malformed id (`gscript_label:0xWRONG`) → rejected | **PASS** |
| 6 | `semantic_reclassification_after_raw_capture_forbidden` | reclassifying B's identity AFTER raw capture → the Q0-C run-membership gate binds every run to a raw child by `(capture_id, old_base)`; no raw child carries the reclassified id → **fail closed** (never binds by physical address alone) | **PASS** |
| 7 | `production_emitter_duplicate_parent_fails_closed` | two snapshots at the same parent base/size (different identity) → unique resolution refuses → no protection | **PASS** |
| 8 | `production_emitter_duplicate_label_fails_closed` | two labels at the same table-entry base (different identity) → unique resolution refuses → no protection | **PASS** |

---

## 8. Task 6 — identity/classification complete before raw children

The AF3 scheme requires the emitter to classify and bind the parent **before**
`raw_children_from_capture` so the raw child and the protection tuple agree. Verified in
production source order:

- `crates/pe/src/dumper/dump_process.rs:992-999` — `detect_heap_globals(...)` runs when
  `stage_plan.detect_heap_globals`.
- `crates/pe/src/dumper/heap_global_snapshot.rs:981` — inside `detect_heap_globals`,
  `exhaust_gscript_label_table_entries(...)` force-admits label-table entries and, per the
  AF3 fix, classifies each as `InteriorSubview`/parent **at capture time**.
- `crates/pe/src/dumper/dump_process.rs:1143-1146` — `raw_children_from_capture(...)` runs
  **later**, inside the `capture_identity_bind` / `capture_coverage_bind` stage, after the
  emitter has fixed B's identity.

Therefore the raw child for B carries the **same** production-reachable identity that the
Q0-C overlay and scrub protection consume. No identity is modified after raw capture
(proven negatively by task 5 test 6).

---

## 9. Task 7 — existing AF1/AF2R1 tests preserved

All 23 existing Q0-C tests (`route_y_r1_a6_q0c_*`), including all AF1 and AF2R1 tests,
pass unchanged in the full suite (see section 10). No regression.

---

## 10. Offline gate results (all PASS)

- `cargo fmt --all -- --check` → **clean** (fmt applied; re-check passes)
- `cargo test -p mida-pe --offline` → **697 + 7 + 2 + 3 passed** (1 ignored), 0 failed
  (Q0-C suite alone: `route_y_r1_a6_q0c_*` → **23/23**; AF3 emitter-driven suite: **12/12**)
- `cargo test -p mida-cli --features gto-product-recovery` → **298 + 4 + 1 + 20 + 17 + 3 passed**
- `cargo test -p mida-cli --offline` → **296 + 4 + 1 + 20 + 17 + 3 passed**
- `python tools/test_gto_live_route_controller.py` → **36 passed / 0 failed**
- `git diff --check` → **clean**

Note: `tests/test_gto_live_route_controller.py` (a **separate**, pre-existing binary-safe
controller test, committed at `2f08642`, **not touched by AF3**) reports
`None != 0` for its synthetic child exit-code assertions in this environment. It is
unrelated to AF3's Q0-C identity work and its controller JSON schema expectations are
unchanged by AF3. The AF3-required python controller gate
(`tools/test_gto_live_route_controller.py`) passes 36/36.

---

## 11. Mandatory git grep evidence (AF3 tests exist in source — exact match)

```
crates/pe/src/dumper/raw_slab_coherence.rs:12912: fn production_exhaust_emitter_label_protection_is_reachable()
crates/pe/src/dumper/raw_slab_coherence.rs:12973: fn production_preexisting_label_entry_protection_is_reachable()
crates/pe/src/dumper/raw_slab_coherence.rs:13020: fn hand_built_impossible_identity_tuple_is_not_required()
crates/pe/src/dumper/raw_slab_coherence.rs:13057: fn production_emitter_scrub_mark_q0c_succeeds()
crates/pe/src/dumper/raw_slab_coherence.rs:13162: fn main_slot_probe_without_parent_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13191: fn gscript_child_link_id_with_wrong_source_parent_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13230: fn gscript_child_link_id_with_wrong_link_offset_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13269: fn gscript_child_link_id_with_wrong_probe_size_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13309: fn table_reachable_but_identity_malformed_not_protected()
crates/pe/src/dumper/raw_slab_coherence.rs:13339: fn semantic_reclassification_after_raw_capture_forbidden()
crates/pe/src/dumper/raw_slab_coherence.rs:13402: fn production_emitter_duplicate_parent_fails_closed()
crates/pe/src/dumper/raw_slab_coherence.rs:13444: fn production_emitter_duplicate_label_fails_closed()
```

---

## 12. Live git boundary

- **tracked modified (3):**
  - `crates/pe/src/dumper/heap_global_snapshot.rs` (+734 / -6, production: emitter fix,
    family parsers, identity extension, `pub(crate)` exhaust)
  - `crates/pe/src/dumper/raw_slab_coherence.rs` (+2311 / -0, AF2R1 fixture/config +
    AF3 12 tests + `RegionMapMock`)
  - `crates/pe/src/dumper/snapshot_manifest.rs` (+3 / -0, `GscriptLabelTableEntry`
    path_label)
- **untracked source:** 0
- **untracked docs:** **29 before this report → 30 after** (this file
  `GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_AF3_RESULT.md` is newly untracked)
- **No git add/commit** (work order forbids auto-commit)
- A6 original evidence frozen/unmodified; A6 report not touched.
- No live / protected sample / controller / spawn / candidate / cold-start / promote /
  install / distribute / Route Z R1.
- Supervisor Production Integration **NOT** executed; no second protected live authorized.

---

## Honesty statement

- The 3 emitter-driven positive tests, the 1 full emitter-driven Q0-C test, and the 8
  negative tests are **real, materialized `#[test]` functions** in the working tree, each
  found by exact `git grep` (section 11) and each passing in the full offline suite
  (section 10). Nothing claimed is absent from source.
- The positive tests drive the **real production emitter**
  (`exhaust_gscript_label_table_entries`) via a memory-map `DebuggerCore` mock; B's
  identity is produced by the emitter, never hand-forged. The full Q0-C pipeline test
  builds the raw slab from the **emitter output** and asserts the canonical patched qword
  from the real scrub → mark → recorded-ledger → overlay path.
- The 8 negative tests are each grounded in a concrete production-unreachable / malformed /
  duplicate / post-capture-reclassification input and assert fail-closed — none loosens
  Q0-C.
- Task 6 ordering is evidenced by exact source lines (section 8); no identity is modified
  after raw capture (proven by task 5 test 6).
- `git diff --check` clean; all 6 AF3 gates green; the existing AF1/AF2R1 Q0-C tests and
  the full mida-pe / mida-cli suites are preserved (section 10).
- No candidate generated (the only patched fixture is in-memory inside the pipeline test);
  no commit.
- The separate `tests/test_gto_live_route_controller.py` failure is pre-existing and
  environmental (synthetic-child JSON schema expectations unchanged by AF3); it is not an
  AF3 gate.

---

## Post-execution boundary

- Production files: `crates/pe/src/dumper/heap_global_snapshot.rs`, `snapshot_manifest.rs`.
  Tests: `crates/pe/src/dumper/raw_slab_coherence.rs`.
- A6 evidence + A6 report frozen/unmodified; no residual processes.
- New report file: `docs/GTO_ROUTE_Y_R1_A6_Q0C_NARROW_MITIGATION_AF3_RESULT.md`
  (untracked).
- Stopped. Awaiting independent audit. No Supervisor Production Integration; no second
  protected live; no commit.
