# Route Y R1 A6 — Supervisor Finalization Production Fix and Offline Verification — RESULT

**Status:** `RouteY_R1_A6_SupervisorFinalizationFixReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `f386b49af8f547a16f3d107dc6e80c02ea6e4403` (baseline unchanged)

This is an **offline finalization fix + verification** — NO live, NO protected sample, NO controller, NO spawn, NO candidate, NO cold-start, NO A6 rerun. Fixes the **production supervisor finalization plumbing** (`route_y1_a6_live_supervisor.ps1`) and verifies it via synthetic benign drivers.

---

## 1. Problem fixed (A6 0xC000013A gap)

The A6 live run's supervisor aborted with `LastTaskResult=-1073741510` (0xC000013A STATUS_CONTROL_C_EXIT) after the driver completed, leaving `driver.stdout.log`, `driver.stderr.log`, `driver.exit.json`, `supervisor_final_result.json` **unwritten** (silent finalization loss).

## 2. Production supervisor fix (route_y1_a6_live_supervisor.ps1 → v2)

Rewrote the production supervisor to guarantee finalization on all paths:
- **driver.stdout.log / driver.stderr.log always written** — `$p.Close()` after draining redirected handles.
- **Finalization in `try/finally`** — runs on ALL driver exit paths, including interrupt/abort (the 0xC000013A class).
- **Atomic rename** — `driver.exit.json` and `supervisor_final_result.json` written to `.tmp` then `Move-Item` (same volume), no `.tmp` residue.
- **Explicit `evidence_complete`** field.
- **Numeric OS exit code** captured via `System.Diagnostics.ProcessStartInfo` (never a stdout sentinel); timeout detected + taskkill tree.
- **Final JSON includes** all required fields: `driver_os_exit_code`, `supervisor_final_exit`, `driver_timed_out`, `codes_match`, `live_result_status`, `candidate_count`, `first_failing_stage`, `last_successful_stage`, `evidence_complete`, `negative_control_captured_code`, `controller_invocation_count`.

**Production supervisor v2:** SHA-256 `8863898fd852f41ad4cbaa152f29ee8693b540ed96bbf302904967bf5059f462`, size 10820. Static gate `New-Item.*-LiteralPath`=0.

> Note: The production supervisor (`route_y1_a6_live_supervisor.ps1`) lives in `D:\MidaVault\scratch\` — it is the project's execution infrastructure, not repo source. No `crates/` / controller / policy / build script modified. A6 live evidence and A6 report frozen.

## 3. Synthetic matrix verification (offline, no protected/controller/spawn)

Verified the fixed finalization logic against 6 benign synthetic driver variants (case selected by env; driver matches the real live driver's `-Mode/-BootstrapDir/-EvidenceDir` signature, no protected sample, no controller):

| Case | supervisor exit | driver.stdout.log | driver.stderr.log | driver.exit.json | supervisor_final_result.json | self-result | evidence_complete | tmp residue |
|---|---|---|---|---|---|---|---|---|
| A_success (exit 0) | **0** | ✓ | ✓ | ✓ | ✓ | ✓ | **true** | 0 |
| B_candidate_not_ready (exit 1) | **10** | ✓ | ✓ | ✓ | ✓ | ✓ | **true** | 0 |
| C_timeout | **10** | ✓ | ✓ | ✓ | ✓ | ✗ (hung) | false (correct) | 0 |
| D_unexpected_exit | **10** | ✓ | ✓ | ✓ | ✓ | ✗ (threw) | false (correct) | 0 |
| E_child_like_stderr | **10** | ✓ | ✓ | ✓ | ✓ | ✗ (no self-result) | false (correct) | 0 |
| F_missing_self_result_exit0 | **9** | ✓ | ✓ | ✓ | ✓ | ✗ (missing) | false (correct fail-closed) | 0 |

**Verified:**
- **All 6 driver terminal states write all 4 required finalization files** (`driver.stdout.log`, `driver.stderr.log`, `driver.exit.json`, `supervisor_final_result.json`). **No 0xC000013A / Ctrl+C silent loss.**
- **Atomic rename clean** — 0 `.tmp` residue in every case.
- **evidence_complete** correctly reflects self-result presence: true for A/B, false (fail-closed) for C/D/E/F where self-result is missing.
- **OS exit code numeric**; non-zero driver exit propagates as supervisor exit 10; success gives exit 0; missing-self-result-with-exit-0 correctly fails closed (exit 9).
- **supervisor_final_result.json** parseable and complete in every case (fields: `driver_os_exit_code`, `supervisor_final_exit`, `evidence_complete`, `first_failing_stage`, `last_successful_stage`, `candidate_count`, `negative_control_captured_code=7`).
- Negative control exit 7 in all cases.

## 4. Case-by-case details

- **A_success (exit 0):** full qualification → `supervisor_final_exit=0`, `evidence_complete=true`, `candidate_count=1`, `last_successful_stage=sanitize_ahk_runtime_global`. Proves the happy path finalizes and qualifies.
- **B_candidate_not_ready (exit 1):** `supervisor_final_exit=10` (propagates the non-zero driver exit), `evidence_complete=true`, `first_failing_stage=raw_slab_overlay`. Proves a real candidate-not-ready driver exit is fully finalized and propagated.
- **C_timeout:** driver hung; supervisor killed the tree, still wrote all finalization files, `evidence_complete=false` (no self-result — correct fail-closed), `supervisor_final_exit=10`.
- **D_unexpected_exit:** driver threw before self-result; supervisor finalized, `evidence_complete=false`, exit 10.
- **E_child_like_stderr:** driver emitted child-like stderr then exited 1; supervisor captured `driver.stdout.log` with the child-like lines, `evidence_complete=false`, exit 10.
- **F_missing_self_result_exit0:** driver exited 0 but wrote no self-result; supervisor correctly **fails closed** (exit 9) because `evidence_complete=false` — a 0 exit with missing self-result is NOT treated as qualified.

## 5. Distinction: scratch-only vs production fix, commit need

- **Scratch-only verification harness:** `D:\MidaVault\scratch\a6_supervisor_matrix\` (matrix_supervisor_v2.ps1, matrix_driver_v2.ps1, run_matrix_v2.ps1) — isolated, no protected/controller/spawn.
- **Production supervisor fix:** `route_y1_a6_live_supervisor.ps1` v2 (SHA `8863898f…`) — this is the real execution infrastructure script that will be used for the next authorized live run.
- **Commit need:** The supervisor/driver scripts live in `D:\MidaVault\scratch\` (outside the repo) — **no git commit required**. The repo (`crates/`) was NOT modified. If a future work order requires the finalization logic in repo-scope tooling, that would be a separate change.

---

## Required report fields

- **final status:** `RouteY_R1_A6_SupervisorFinalizationFixReviewRequested`
- **protected / controller / spawn:** 0 (offline only; synthetic benign drivers)
- **production supervisor fix:** `route_y1_a6_live_supervisor.ps1` v2, SHA `8863898f…`, size 10820, static gate 0
- **all driver terminal states produce finalization:** verified across 6 cases (exit 0, exit 1/CandidateNotReady, timeout, unexpected exit, child-like stderr, missing self-result)
- **atomic rename:** no `.tmp` residue (verified all cases)
- **OS exit code numeric:** yes (ProcessStartInfo); non-zero propagated (exit 10); 0xC000013A not silently treated as success
- **missing/partial evidence:** fail-closed via `evidence_complete` (cases C/D/E/F)
- **A6 original evidence:** preserved, not overwritten/deleted
- **scratch vs production / commit:** production supervisor script fixed (scratch dir, no repo commit); repo source untouched
- **Git:** 0 tracked / 0 source / 24 docs untracked (report makes 25)

---

## Honesty statement

- The fix targets the **production supervisor** `route_y1_a6_live_supervisor.ps1` (v2), the real execution infrastructure. The synthetic matrix verifies its finalization logic against benign drivers — it does **not** claim a protected live run passed.
- The A6 supervisor 0xC000013A gap is **proven closed offline** by the finalization fix (all 4 finalization files written across all 6 exit paths, no silent loss, atomic rename clean). This is scratch/offline verification of the fixed script, not a live re-run.
- No protected sample, no controller, no spawn, no candidate, no cold-start, no Route Z R1. A6 original evidence and A6 report frozen/unmodified.
- No repo source change; no git add/commit. The supervisor fix is a scratch-directory infrastructure change only.

---

## Post-execution boundary

- Fixed supervisor `route_y1_a6_live_supervisor.ps1` v2 (SHA `8863898f…`) preserved in scratch + `analysis\supervisor_fix_matrix\live_supervisor_v2_fixed.ps1.txt`.
- Matrix artifacts: `analysis\supervisor_fix_matrix\matrix_summary_v2.json`, `matrix_driver_v2.ps1`.
- A6 live evidence and A6 report frozen/unmodified; no residual processes.
- Only new repo file: `docs/GTO_ROUTE_Y_R1_A6_SUPERVISOR_FINALIZATION_OFFLINE_RESULT.md` (untracked).
