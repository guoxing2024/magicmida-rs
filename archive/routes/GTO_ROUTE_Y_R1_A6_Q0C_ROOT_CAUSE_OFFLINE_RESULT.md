# Route Y R1 A6 — Q0-C Conflict Root-Cause Offline Review — RESULT

**Status:** `RouteY_R1_A6_Q0C_RootCauseReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This is an **offline root-cause review** — NO live, NO protected sample, NO controller, NO spawn, NO candidate, NO cold-start. Read-only on source + frozen A6 evidence.

---

## Verdict

**`Q0C_ConflictEvidenceInsufficient`** (with a **strong, source-mechanism-supported structural hypothesis**)

The Q0-C fail-closed behavior is **confirmed correct** (0 candidates, no slab fallback, no binding relaxation, no last-writer bypass, no conflict ignored). However, per the audit's bar ("必须有结构/identity/coverage 或 deterministic fixture 证据"), the root cause is **not yet a confirmed finding** — it is a high-confidence structural hypothesis that needs a deterministic fixture (a separate code-fix work order) to confirm.

---

## 1. Conflict being reviewed

```
A: [0x8e93c8,+0x2000) @ +0xa03 -> 0x00   chain=[scrub_uncaptured_heap_pointers]
B: [0x8e9da8,+0x400)  @ +0x23 -> 0x01   chain=[scrub_uncaptured_heap_pointers, mark_labels_non_nested]
same physical byte: 0x8e9dcb
slab offset: 0x6fadcb   before=0x04
```

B is strictly contained within A (A=`[0x8e93c8,0x8eb3c8)`, B=`[0x8e9da8,0x8ea1a8)`). Both chains write the same slab byte `0x8e9dcb` to different values → `TransformWriteConflict` fail-closed.

## 2. Deterministic structural lineage (from frozen child.stderr.txt)

| Line | Telemetry | Interpretation |
|---|---|---|
| 155 | `Captured heap-global slot rva=0x14a428 heap=0x8e93c8 size=8192 xref=26` | **A** = heap-global slot at `0x8e93c8`, size `0x2000` (8192), rva `0x14a428` |
| 250 | `Externalized label mName wide string heap=0x8e9d90 size=24 label=0x8e9da8` | B's mName wide string at `0x8e9d90` |
| 251 | `Captured gscript label-table entry heap=0x8e9da8 size=1024 table_off=0xc8 name_ptr=0x8e9d90` | **B** = gscript label-table entry at `0x8e9da8`, size `0x400` (1024), inside A |

**A is a heap-global slot; B is a gscript Label table entry that lies interior to A.** This is deterministic from the frozen telemetry (not address-guessing).

## 3. Source-mechanism hypothesis (strong but not fixture-confirmed)

- **B+0x23 is a critical live flag** — the gscript Label **non-nested redirect flag** (`heap_global_snapshot.rs:2293-2296`): at runtime `0xc13d0`, if `[label+0x23]==0` then `rbx=[label+0x10]` (nested line); `mark_labels_non_nested` forces `+0x23=1` so the non-nested cold-start path is taken. Zeroing it kills the product window path.
- **`scrub_uncaptured_heap_pointers` zeroes entire qwords** that look like external dangling pointers (`heap_global_snapshot.rs:5781,5792`). The qword containing B+0x23 is `B[0x20..0x28)`. A's scrub walks A's full `0x2000` buffer and zeroed that qword.
- **`is_external_dangling_ptr`** (`heap_global_snapshot.rs:5825-5841`) returns `false` (protected) when a value falls inside any captured `ranges`. B is a captured heap_global, so a pointer INTO B would be protected. The fact that **A_after=0x00** means the qword at B+0x20..0x28 held a value judged to be a **dangling external pointer (not into any captured range)** — so scrub zeroed all 8 bytes, including B+0x23.
- **Same interaction class as the documented +0x10** (`dump_process.rs:1240`): "scrub walks every qword and can clear gscript count@+0x10 when the live dword was embedded in a pointer-shaped qword" — previously mitigated via `resynthesize_gscript_label_count`. The +0x23 flag is the same class (a live flag embedded in a pointer-shaped qword) with **no mitigation**.
- **Confirmed behavior from the frozen conflict:** A_after=0x00 (A's scrub wrote 0x00 over the byte), B_after=0x01 (B's `mark_labels_non_nested` wrote 0x01). Both confirmed from the frozen `child.stderr.txt` line 571.

## 4. Why NOT confirmed root cause yet (audit bar)

- The mechanism is **strongly supported** by source (`is_external_dangling_ptr`) + deterministic structural lineage + confirmed after-values (0x00 vs 0x01).
- BUT the exact **qword value** at B+0x20..0x28 and the **ranges membership at scrub time** are NOT in the frozen evidence. The `0x00` after-value is inferred to come from scrub's dangling-pointer classification, not directly evidenced.
- **No deterministic offline fixture** reproduces the conflict (adding one is a source change requiring a separate code-fix work order; this order forbids production source modification).

## 5. Minimal gap to confirm

1. A **deterministic offline fixture** that constructs a parent heap-global slot containing an interior gscript label-table entry whose +0x23 flag qword looks like a dangling external pointer, and asserts that scrub zeroes B+0x23 while `mark_labels_non_nested` sets it to 1 → conflict (separate code-fix work order).
2. OR: surface per-child `capture_id` / `extent_kind` / `capture_path` / binding identity + `raw_child_digest` + `slab_slice_digest` in live telemetry so the exact A/B ownership is confirmed.

## 6. Recommendation

Defer a **confirmed** classification to a separate code-fix work order that:
- adds a deterministic offline regression fixture reproducing the scrub-vs-+0x23 conflict;
- optionally mitigates via a targeted rule (e.g., protect known label flag bytes from scrub, analogous to `resynthesize_gscript_label_count` for +0x10).
Keep Q0-C **fail-closed** in the interim. Do **NOT** relax overlap/binding/last-writer/slab-fallback.

---

## Required report fields

- **final status:** `RouteY_R1_A6_Q0C_RootCauseReviewRequested`
- **Q0-C conflict:** A `[0x8e93c8,+0x2000)@+0xa03→0x00` vs B `[0x8e9da8,+0x400)@+0x23→0x01`, byte `0x8e9dcb`, slab offset `0x6fadcb`, before `0x04`
- **lineage:** A = heap-global slot (rva 0x14a428), B = interior gscript label-table entry (name_ptr 0x8e9d90); deterministic from stderr lines 155/250/251
- **capture_id / extent_kind / capture_path / binding / digests:** EVIDENCE_GAP (not in frozen stderr)
- **verdict:** `Q0C_ConflictEvidenceInsufficient` (fail-closed correct; +0x23 scrub hypothesis strong but not fixture-confirmed)
- **minimal gap:** deterministic fixture + per-child identity telemetry
- **no relaxation applied:** yes (fail-closed preserved, candidate=0)
- **Git:** 0 tracked / 0 source / 23 docs untracked (report makes 24)

---

## Honesty statement

- All analysis is **read-only** on frozen A6 evidence + source; outputs written to `D:\MidaVault\lab\analysis\route_y_r1_a6_postlive_20260811T175608Z\q0c_rootcause_review.json`.
- Identity fields remain **EVIDENCE_GAP**, not inferred from addresses/names.
- The +0x23 scrub hypothesis is presented as a **strong structural hypothesis backed by source mechanism and deterministic lineage**, NOT a confirmed root cause — per the audit's requirement for deterministic fixture evidence.
- No production source change; no candidate; no cold-start; no Route Z R1. A6 original evidence not modified.
- Execution stopped; no second live, no candidate promotion.

---

## Post-execution boundary

- Analysis outputs preserved: `q0c_rootcause_review.json` (and prior `q0c_overlay_conflict_dossier.json`, `transform_lineage_analysis.json`, `live_result_reparsed.json`) in the analysis dir.
- A6 live evidence and A6 report frozen/unmodified.
- Only new repo file: `docs/GTO_ROUTE_Y_R1_A6_Q0C_ROOT_CAUSE_OFFLINE_RESULT.md` (untracked).
