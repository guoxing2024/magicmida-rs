# Route Z R0 AF2 Audit Fix 2 — Fail-Closed Restore, Scope Gating, and Deterministic Windows Race Closure

**Status:** `RouteZ_R0_AF2_AF1_AF2_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `68b8032` (unchanged — no commit made)
**HEAD^:** `9450b3a`

This work order closes the 10 static-audit blockers (3 P1 / 3 P2 from AF1 plus the 4 new P1s re-audited here) with real offline code fixes, a benign Windows helper/harness, and a strict production-scope gate. **No commit / push / live / protected-sample / candidate / cold-start was performed.** All docs remain untracked and excluded from the code commit.

---

## Audit blockers → resolutions

### [P1-1] Partial-freeze rollback swallowed restore failures — FIXED
`crates/core/src/windows_debugger.rs`

- New private `unfreeze_process_threads_impl(&[(u32,u32)], fail_resume_tid)` **continues past every single failure** and returns `CoreError::CaptureEpochRestore { failed_count, failed: Vec<RestoreFailure> }` carrying each failed **thread_id**, the failing **phase** (`"open"`/`"resume"`), and the **Win32 error code**. It never stops at the first error and never swallows a failed restore.
- New `rollback_or_combine(...)` merges the **original freeze failure** with **every rollback failure**:
  - rollback fully OK → plain `CoreError::ProcessCreation(freeze_msg)` (nothing left suspended);
  - rollback partially failed → `CoreError::CaptureFreezeWithRollbackFailure { freeze, rollback_failed_count, rollback_failed: Vec<RestoreFailure> }` (some threads may be left suspended — surfaced, never hidden).
- All four freeze failure sites (snapshot, SuspendThread, OpenThread non-transient, non-convergence) route through `rollback_or_combine` with the full `suspended` list, so a partially-failed rollback still attempts every thread.
- `rollback_suspended` (which discarded the error) is removed.

### [P1-2] Partial-rollback test allowed `count ∈ {0,1}` — FIXED
`crates/core/tests/capture_epoch_harness.rs`

- `real_process_partial_freeze_after_n_threads_rolls_back`: records the **exact pre-freeze suspend count of EVERY target thread** (`BTreeMap<tid, i32>`) *before* the injected failure, then asserts **`post_rollback_suspend_count == pre_freeze_suspend_count` for every thread** (exact equality, not a range). Also asserts every pre-enumerated thread still exists. The shared counter resuming is no longer used as the restore proof.
- `real_process_partial_freeze_rollback_failure_reports_tid` (new): injects a **real, controlled `ResumeThread` failure** for exactly one victim tid during rollback, and proves:
  - (a) every **other** thread is restored to its exact pre-freeze count (rollback continued past the failure);
  - (b) the returned error is `CaptureFreezeWithRollbackFailure` carrying the original freeze message AND the victim's `RestoreFailure{thread_id, phase:"resume", code:0}`;
  - (c) the victim is genuinely left suspended at `pre_count + 1` (the injected layer), then cleaned up by the test.

### [P1-3] "Error-Drop" test was really a panic test — FIXED
- `real_process_epoch_guard_drop_restores_on_error` now runs a real `fn capture_body(...) -> Result<(), CoreError>` that begins a `CaptureEpochGuard`, verifies threads froze, and returns `Err(...)` via ordinary early return (`?`/return) — **no panic**. It asserts every thread returns to its exact pre-epoch suspend count after the guard drops.
- The independent `real_process_epoch_guard_drop_restores_on_panic` (panic + `catch_unwind`) is kept and also upgraded to per-thread exact restore verification.

### [P1-4] Failure injection was not truly test-only — FIXED
`crates/core/src/windows_debugger.rs`, `crates/core/Cargo.toml`

- `freeze_process_threads_with_failure` is now **`#[cfg(feature = "capture-epoch-harness")]`** — real compile gating, not `#[doc(hidden)]`. It does not exist on the default production library surface at all.
- Production `freeze_process_threads(pid)` calls only the private `freeze_process_threads_impl(pid, None, None)` — provably the `None` code path.
- Verified in a **fresh isolated target**: default `cargo build -p mida-core` produces **NO `capture_epoch_helper` binary**; the same target with `--features capture-epoch-harness` does. (Two fresh target dirs tested: `af2_iso2` default=no helper, feature=helper present.)
- The benign helper binary was already gated by `[[bin]] required-features=["capture-epoch-harness"]`.

### [P1-5] Capture epoch unconditionally applied to OreansClassic / no-live-capture path — FIXED
`crates/pe/src/dumper/dump_process.rs`

- New pure predicate `pub fn capture_epoch_needed(plan: ExperimentalStagePlan) -> bool { plan.detect_containers || plan.detect_heap_globals }`.
- `CaptureEpochGuard::begin(debugger)` is now **strictly gated inside `if epoch_needed`**; when no live-capture stage is enabled (OreansClassic), the target is **never frozen**, no backend freeze support is required, and a `ReadOnlyProcessDebugger` (which cannot freeze) is not forced to fail. Route Z's fix no longer expands to unrelated dump profiles/backends.
- The epoch `end()` + `drop()` complete **before** all offline seed/transform/overlay/runtime work.
- `crates/core/src/debugger.rs`: `unfreeze_target_threads` default is now fail-closed — returns an explicit unsupported error instead of `Ok(())`, so a backend that freezes but forgets to unfreeze can never silently leave the target frozen.
- Regression tests (`capture_epoch_gating_tests`, 5 tests) pin the predicate: OreansClassic → false (freeze=0/unfreeze=0); full GTO → true (freeze=1/unfreeze=1); containers-only and heap-globals-only → true; offline-only stages → false.
- `real_process_freeze_only_backend_end_fails_closed` (new harness test): a backend implementing only `freeze_target_threads` (real freeze via helper) returns `Err` from `CaptureEpochGuard::end()` (never silent success), then the test cleans up the leaked suspended threads.

### [P2-1] Thread-exit race not proven to hit the transient branch — FIXED
`crates/core/src/bin/capture_epoch_helper.rs`, `crates/core/src/windows_debugger.rs`, harness

- Feature-gated diagnostic `TRANSIENT_EXIT_TIDS: Mutex<Vec<u32>>` + `clear_transient_exit_diagnostics()` / `transient_exit_tids()` record the **exact TID** of every thread that hit the transient-exit branch (observed in the ToolHelp snapshot, already gone at `OpenThread`, code low-16 == 87).
- Helper `--exit-on-command` now runs an **exit storm**: a coordinator spawns short-lived threads on a ~200µs cycle, each exiting after ~1µs, making the snapshot→OpenThread exit race deterministic in practice.
- `real_process_deterministic_thread_exit_race` runs many freeze iterations and **asserts the transient-exit diagnostic is NON-EMPTY** (proves the branch was actually exercised, with exact TIDs), asserts the diagnostic never contains the main thread, and verifies every surviving thread is precisely restored to its pre-freeze count (threads that exited are not restore failures).
- `SuspendThread`-after-`OpenThread` exit is handled in the freeze impl (fail-closed rollback via `rollback_or_combine`); non-transient errors still fail closed (covered by `real_process_partial_freeze_rolls_back` on a nonexistent PID).

### [P2-2] Handle-leak threshold too loose (+32) — FIXED
- `real_process_repeated_freeze_has_no_handle_growth` now **warm-ups** 5 cycles, then measures **50 serial cycles** and requires **NET ZERO growth** (`final == initial`), with a max-seen bound that must not exceed the final settled count (no monotonic growth). Runs under `--test-threads=1`. Outputs `initial/warmup/max/final` handle counts.

### [P2-3] end/Drop idempotence could not detect double-resume — FIXED
- `real_process_epoch_end_then_drop_is_idempotent` now uses a **real pre-suspended worker thread**: baseline `=1`, epoch active `=2`, after `end()` `=1`, after `Drop` still `=1` (a double-resume would underflow below the pre-suspended baseline). Test cleanup releases only the harness's own pre-suspend layer. No `count >= 0` assertions.

---

## Real Windows harness (14 tests, feature-gated)

| Test | Proof |
|---|---|
| `real_process_deterministic_thread_exit_race` | transient-exit branch hit (exact TIDs from feature-gated diagnostic >0), survivors precisely restored |
| `real_process_epoch_end_then_drop_is_idempotent` | real pre-suspended thread baseline=1→2→1→1, no double-resume |
| `real_process_epoch_guard_drop_restores_on_error` | real `Result::Err` early-return → Drop, exact per-thread restore |
| `real_process_epoch_guard_drop_restores_on_panic` | panic + `catch_unwind` → Drop, exact per-thread restore |
| `real_process_freeze_only_backend_end_fails_closed` | freeze-only backend → `end()` returns Err (default unfreeze fail-closed) |
| `real_process_freeze_stops_workers` / `unfreeze_resumes_workers` / `freeze_covers_thread_set` | live freeze stops counter, unfreeze resumes, thread set covered |
| `real_process_partial_freeze_after_n_threads_rolls_back` | precise per-thread `post == pre` after injected failure |
| `real_process_partial_freeze_rollback_failure_reports_tid` | combined freeze+rollback error, victim TID + phase reported, others restored |
| `real_process_partial_freeze_rolls_back` | nonexistent PID fails closed |
| `real_process_prior_suspend_count_restored` | pre-suspended thread baseline=1, epoch=2, restore=1 |
| `real_process_repeated_20x_all_pass` | 20 live freeze/restore round-trips |
| `real_process_repeated_freeze_has_no_handle_growth` | warm-up + 50 cycles, net-zero handle growth |

Result: **14/14 pass** (ran 3+ times, no flake).

---

## Required gates — all green

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean (no Diff) |
| `cargo test -p mida-core --offline` | **75 / 0** (harness compiles to 0 tests w/o feature) |
| `cargo test -p mida-core --features capture-epoch-harness --test capture_epoch_harness --offline -- --test-threads=1` | **14 / 0** (real Windows) |
| fresh isolated default `cargo build -p mida-core` | succeeds; **no helper binary** |
| default isolated target produces `capture_epoch_helper` | NO (feature build does) |
| `cargo test -p mida-pe --offline` | **649+7+2+3 / 0** (incl. 5 new gating tests) |
| `cargo test -p mida-cli --features gto-product-recovery` | **298+4+1+20+17+3 / 0** |
| `cargo test -p mida-cli --offline` | **296+4+1+20+17+3 / 0** |
| `python tools/test_gto_live_route_controller.py` | **36 / 0** |
| `git diff --check` | clean |

Warnings: mida-core default **0**; mida-core feature (bins+tests) **0**; mida-pe **14** (pre-existing baseline, my changes add 0); full `cargo check --workspace` clean. No residual helper processes.

---

## Honesty statement

- `#[doc(hidden)]` is **not** claimed as test-only — the injection API is `#[cfg(feature = "capture-epoch-harness")]` compile-gated.
- Panic test and error-return test are **separate**; the error test uses a genuine `Result::Err` early return, not a panic.
- Partial-rollback proof uses **exact per-thread suspend-count equality**, never `count ∈ {0,1}` or "counter resumed".
- The deterministic exit-race test proves the transient branch via the feature-gated **TID diagnostic**, not statistical assumption.

---

## Deliverables & boundary

- New report: `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF2_WINDOWS_HARNESS_RESULT.md` (untracked).
- Untracked source: `crates/core/src/bin/` (helper), `crates/core/tests/` (harness), `crates/core/src/capture_epoch.rs`, `crates/pe/src/dumper/capture_epoch.rs`.
- Tracked modifications: 8 files (`session.rs`, `core/Cargo.toml`, `debugger.rs`, `error.rs`, `lib.rs`, `windows_debugger.rs`, `dump_process.rs`, `mod.rs` — plus `raw_slab_coherence.rs` noted in the AF1 diff).
- All 8 prior docs remain untracked and excluded.
- HEAD `68b8032` unchanged; no commit/push/live/protected-sample/candidate.
- Temp build helper and isolated target dirs cleaned up.
