# Route Y R1 A6 — Post-Live Offline Closure — RESULT

**Status:** `RouteY_R1_A6_PostLiveOfflineClosureComplete`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403`
**HEAD^:** `68b8032d6c3600e7aaa8b9498b77e636b67d58e9`

This is a **post-live offline closure** — NOT a live authorization. **No protected sample, no controller invocation, no second spawn, no candidate, no cold-start/promote.** Read-only analysis of the frozen A6 live evidence, plus offline/synthetic supervisor finalization qualification.

---

## 0. A6 live truth (frozen, confirmed)

- **protected live authorization consumed:** true (`controller_run.spawned=true`, `controller_pid=22388`)
- **protected sample spawn:** 1
- **second spawn / rerun:** 0
- **candidate:** 0 (`RouteY_R1_A6_CandidateNotReady`)
- **full upstream chain reached `sanitize_ahk_runtime_global`** (exit)
- **first production failure:** `raw_slab_overlay` (Q0-C overlay)

## 1. Evidence freeze

SHA-256 computed for all required raw files (written to `analysis\evidence_freeze.json`):

| File | SHA-256 |
|---|---|
| child.stderr.bin | `23b3c6f2…` |
| child.stderr.txt | `73b6ea4a…` |
| controller_run.json / controller_attempt_001.json | `3ead89a8…` |
| live_result.json | `00d03825…` |
| driver_journal.jsonl | `767048fc…` |
| driver_self_result.json | `fec4f9d3…` |
| build_attestation_copy.json | `9cf1beb6…` |
| binary_verification.json | `79603a36…` |
| argv_static_verification.json | `f4ad0c4f…` |
| driver frozen copy (live_driver_frozen.ps1.txt) | `d4ae91aa…` |
| live supervisor frozen copy | `806098bb…` |

Original files unmodified. A6 report not overwritten.

## 2. Q0-C conflict dossier (`q0c_overlay_conflict_dossier.json`)

From frozen `child.stderr.txt` (line 571 `gto_stage_error`, 573 `FATAL`):

- **Conflict object A:** base `0x8e93c8`, size `0x2000`, offset `+0xa03` → absolute `0x8e9dcb`; chain `["scrub_uncaptured_heap_pointers"]`
- **Conflict object B:** base `0x8e9da8`, size `0x400`, offset `+0x23` → absolute `0x8e9dcb`; chain `["scrub_uncaptured_heap_pointers", "mark_labels_non_nested"]`
- **Overlay:** slab mismatch offset `0x6fadcb`, before `0x04`, A_after `0x00`, B_after `0x01`
- **Containment:** **B is strictly contained within A** (`B_is_contained_in_A=true`): A=`[0x8e93c8,0x8eb3c8)`, B=`[0x8e9da8,0x8ea1a8)`; both target the **same authoritative slab byte** (`0x8e9dcb`).
- **Identity fields** (capture_id, extent_kind, capture_path, binding_identity, raw_child_digest, slab_slice_digest): **EVIDENCE_GAP** — not present in frozen evidence; marked, not guessed/inferred.

## 3. Offline transform lineage analysis (`transform_lineage_analysis.json`)

**Classification: `Q0C_ConflictEvidenceInsufficient`**

The six questions answered (all offline, no production changes):

1. **A/B relationship:** Most likely parent-allocation + interior-child (A size `0x2000` fully encloses B size `0x400`, consistent with a parent heap block containing an interior gscript label object). NOT definitively provable offline — capture_id/extent_kind/capture_path absent.
2. **Authoritative slab normalization of A/B:** Cannot be determined — normalize/reconcile stages exited but per-object treatment not surfaced in stderr. Evidence gap.
3. **Same physical byte?** **YES** — both chains target slab byte `0x8e9dcb`, with divergent transformed values (A→0x00, B→0x01).
4. **`mark_labels_non_nested` 0x01 basis:** Structural — sets `content[0x23]=1` as a "non-nested" flag for gscript Label objects (`heap_global_snapshot.rs:3141`), conditional only on nested-ptr null/missing, NOT on A's scrub. A real intended transform on B.
5. **Scrub 0x00 as parent overwrite?** **PLAUSIBLE** — `scrub_uncaptured_heap_pointers` zeroes full 8-byte qwords that look like external dangling pointers (`heap_global_snapshot.rs:5792`). B+0x23 lies inside qword `[B+0x20,B+0x28)`; if pointer-shaped+dangling, scrub zeroes it including +0x23. **Same interaction class is already documented** (`dump_process.rs:1240`: "scrub walks every qword and can clear gscript count@+0x10 when the live dword was embedded in a pointer-shaped qword") and was previously mitigated for count@+0x10 via `resynthesize_gscript_label_count`.
6. **Q0-C fail-closed disposition:** Fail-closed behavior **confirmed correct** (0 candidates, no slab fallback, no binding weakening, no last-writer bypass, no conflict ignored). But whether this is an expected parent+interior-child conflict correct to reject vs. an implementation defect (scrub clearing a live flag byte that mark_labels owns) **cannot be concluded offline** — it requires capture identity/coverage lineage not present in the frozen evidence. Whether +0x23 needs a similar mitigation to +0x10 is a **separate code-fix work order**.

**Disposition: `Q0C_ConflictEvidenceInsufficient`** — fail-closed behavior proven; root-cause (expected vs. needs-patch) requires the missing identity/coverage evidence.

## 4. Live result offline reparse (`live_result_reparsed.json`)

The driver-generated `live_result.json` had inconsistencies vs raw stderr (epoch freeze/restore seen=false, last_successful=raw_slab_overlay, first_failing=null). Offline parser re-read the frozen `child.stderr.txt` (strip ANSI, parse stages/epoch/sanitize/error/candidate):

```
capture_epoch_freeze_seen=true
suspended_thread_count=7
suspended_thread_ids=[3000,8060,10564,21600,22040,26132,26976]
capture_epoch_restore_seen=true
transform_input_seed_seen=true
sanitize_ahk_runtime_global_seen=true
last_successful_stage=sanitize_ahk_runtime_global   (correct — NOT raw_slab_overlay)
first_failing_stage=raw_slab_overlay                (correct — not empty)
runtime_rebase_plan_seen=false
bound_transform_manifest_seen=false
candidate_count=0
parsed_sanitize_transition: RVA=0x141bf0, old_size=0x8000 (32768), new_size=0x180 (384)
```

All required fields satisfied; `raw_slab_overlay` error is correctly **not** marked as last-successful; `first_failing_stage` is non-empty. The corrected reparse **does not modify** the original `live_result.json`.

## 5. Synthetic supervisor finalization matrix (`supervisor_matrix/`)

Built a **scratch-only improved supervisor** (`matrix_supervisor.ps1`) with atomic rename (temp → `Move-Item`) and guaranteed finalization, plus a **benign synthetic driver** (`matrix_driver.ps1`) with 5 exit-path variants. **No protected sample, no controller.** Results (`matrix_summary.json`):

| Case | supervisor exit | driver.stdout.log | driver.stderr.log | driver.exit.json | supervisor_final_result.json | driver_self_result | evidence_complete |
|---|---|---|---|---|---|---|---|
| A_success (exit 0) | **0** | ✓ | ✓ | ✓ | ✓ | ✓ | **true** |
| B_candidate_not_ready (exit 1) | **10** | ✓ | ✓ | ✓ | ✓ | ✓ | **true** |
| C_timeout | **10** | ✓ | ✓ | ✓ | ✓ | ✗ (hung, killed) | false (correct) |
| D_unexpected_exit | **10** | ✓ | ✓ | ✓ | ✓ | ✗ (threw) | false (correct) |
| E_child_like_stderr | **10** | ✓ | ✓ | ✓ | ✓ | ✗ (no self-result) | false (correct) |

**Proven:**
- Supervisor **always writes** `driver.stdout.log`, `driver.stderr.log`, `driver.exit.json`, `supervisor_final_result.json` across **all** driver exit paths — **no Ctrl+C / handle-inheritance silent loss** (this is the A6 0xC000013A gap).
- Final JSON contains all required fields: `driver_os_exit_code`, `supervisor_final_exit`, `controller_exit` (via live_result_status/candidate_count), `candidate_count`, `first_failing_stage`, `last_successful_stage`, `evidence_complete`.
- Atomic rename verified (no `.tmp` residue).
- Timeout detected (taskkill) + finalized; missing self-result correctly → `evidence_complete=false` (fail-closed).
- supervisor exit propagation correct: 0 for full success, 10 for driver exit≠0.
- No stdout-sentinel used for exit code (numeric OS exit captured via `ProcessStartInfo`).

## 6. Supervisor gap repair boundary (offline qualification)

The A6 supervisor finalization gap is **confirmed fixable offline** with the improved pattern: ensure redirected handles closed (`$p.Close()` after write), wait for full driver exit, run finalization on all paths (try/finally + guaranteed writes), atomic rename, explicit `evidence_complete` flag. This is a **scratch-only supervisor fix** for the next authorized live work order — **not applied to production source** (forbidden this work order).

## 7. Git boundary

- **At start:** 0 tracked / 0 source / 22 docs untracked (live count).
- **After report:** 0 tracked / 0 source / **23 docs** untracked (only new file `GTO_ROUTE_Y_R1_A6_POSTLIVE_OFFLINE_RESULT.md`).
- No git add/commit; no production source/Cargo/controller/policy change; A6 live evidence and A6 report frozen/unmodified; no residual processes.

## 8. Required report fields

- **protected live authorization consumed:** true; spawn=1; second spawn=0; rerun=0; candidate=0
- **full upstream chain:** reached `sanitize_ahk_runtime_global`; first production failure = `raw_slab_overlay`
- **exact Q0-C conflict:** A `[0x8e93c8,+0x2000)@+0xa03` vs B `[0x8e9da8,+0x400)@+0x23`, slab offset `0x6fadcb`, before `0x04`, A `0x00`, B `0x01`
- **Q0-C current disposition:** `Q0C_ConflictEvidenceInsufficient` (fail-closed confirmed; root-cause needs missing identity/coverage evidence)
- **driver live_result vs raw stderr inconsistency:** identified and corrected via offline reparse
- **supervisor 0xC000013A gap:** confirmed; offline synthetic matrix proves finalization fix
- **offline parser reparse result:** `live_result_reparsed.json` with all required fields correct
- **synthetic supervisor finalization matrix:** 5 cases, all finalization files written, no silent loss
- **no protected rerun / no candidate execution / no cold-start / no promote:** confirmed
- **Git status/docs count:** 0 tracked / 0 source / 22→23 docs

---

## Honesty statement

- All analysis is **read-only** on frozen A6 live evidence; outputs written only to the independent analysis dir `D:\MidaVault\lab\analysis\route_y_r1_a6_postlive_20260811T175608Z`.
- Identity fields (capture_id/extent_kind/capture_path/binding/digests) are marked **EVIDENCE_GAP**, not guessed from addresses or names.
- The Q0-C conflict root-cause is classified **`Q0C_ConflictEvidenceInsufficient`** — the fail-closed behavior is proven correct, but "expected" vs "needs a separate patch" cannot be determined offline without the missing identity/coverage lineage. This does NOT classify it as a Route Y regression or as an expected rejection without that evidence.
- The synthetic matrix used **only benign synthetic drivers** (no protected sample, no controller); its purpose is supervisor-plumbing qualification, not production behavior.
- **No production source changes made.** The supervisor finalization fix is scratch-only, deferred to a separate authorized work order.
- Execution stopped. No second live, no candidate execution, no cold-start/promote, no Route Z R1.

---

## Post-execution boundary

- Analysis outputs preserved in `D:\MidaVault\lab\analysis\route_y_r1_a6_postlive_20260811T175608Z\` (evidence_freeze.json, q0c_overlay_conflict_dossier.json, transform_lineage_analysis.json, live_result_reparsed.json, supervisor_matrix/, frozen script copies).
- A6 live evidence and A6 report frozen/unmodified; no production source change; no git add/commit.
- Only new repo file: `docs/GTO_ROUTE_Y_R1_A6_POSTLIVE_OFFLINE_RESULT.md` (untracked).
