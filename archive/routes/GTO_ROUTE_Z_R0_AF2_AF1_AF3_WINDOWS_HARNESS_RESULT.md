# Route Z R0 AF2 AF1 AF3 — Deterministic Thread-Exit Barriers and Evidence Integrity Closure

**Status:** `RouteZ_R0_AF2_AF1_AF3_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `68b8032` (unchanged — no commit made)
**HEAD^:** `9450b3a`

This work order closes the AF2 static-audit blockers (4 P1 + 4 P2 + warnings evidence) with deterministic thread-exit barriers, fail-closed error evidence, real production call-count gating, and per-warning baseline evidence. **No commit / push / live / protected-sample / candidate / cold-start was performed.** All docs remain untracked.

---

## Blocker → resolution

### [P1-1] "Deterministic" thread-exit was a probabilistic storm — FIXED with a real barrier
`crates/core/src/windows_debugger.rs`, `crates/core/src/bin/capture_epoch_helper.rs`, `crates/core/tests/capture_epoch_harness.rs`

The "exit storm + retry up to 200×" approach was deleted. It is replaced by a **shared-memory command/status barrier** that makes a single freeze call deterministically hit the target window:

- Helper (`--exit-on-command N`) arms N **barrier threads**. Each publishes its exact TID to `barrier_cur_tid`, then **blocks** (polls the shared command slot every 50µs) until the test commands exactly that TID to exit.
- `ExitBarrier` (feature-gated) carries `{ tid, window, force_exit }`. The `force_exit(tid)` callback (harness) writes `barrier_cmd_tid=tid, cmd_set=1` and **blocks until the helper confirms the thread terminated** (`barrier_done=1`).
- The freeze impl's feature-gated hook invokes `force_exit(tid)` at the exact window:
  - `BeforeOpen`: after the ToolHelp snapshot observes the TID, before `OpenThread` → `OpenThread` deterministically returns `ERROR_INVALID_PARAMETER` (87), hitting the `"before_open"` transient branch in a **single** freeze call.
  - `AfterOpenBeforeSuspend`: after `OpenThread` succeeds, before `SuspendThread` → the thread terminates, `SuspendThread` fails, and the impl detects the dead thread (below), hitting `"after_open_before_suspend"`.
- The feature-gated diagnostic records `(tid, phase)`; the tests assert the exact TID + phase was recorded. **No retry loop, no "very likely".**

### [P1-2] OpenThread→SuspendThread exit window not covered — FIXED
`crates/core/src/windows_debugger.rs`

When `SuspendThread` fails (`u32::MAX`) after `OpenThread` succeeded:
1. `GetLastError` is read immediately (before any further call).
2. `GetExitCodeThread` (with a bounded 100ms poll) distinguishes `STILL_ACTIVE` (thread still alive → **fail-closed rollback**) from a real exit code (thread terminated → **transient**, recorded `phase="after_open_before_suspend"`).
3. A genuinely-alive thread never reports a non-STILL_ACTIVE exit code, so the poll does not hide a real failure.
- Two independent deterministic tests (`real_process_deterministic_exit_before_open`, `real_process_deterministic_exit_after_open_before_suspend`) each hit their window in a single shot.

### [P1-3] Win32 error code read timing — FIXED
- `ResumeThread` failure: `GetLastError` is now read into a local (`resume_code`) **immediately after `ResumeThread` and before `CloseHandle`**, so the recorded code belongs to `ResumeThread`.
- `SuspendThread` failure: `GetLastError` is read immediately into `suspend_code` and carried into the freeze error.
- `RestoreFailure`/combined errors carry real `(phase, tid, code)`.
- Unit test `restore_failure_records_phase_and_thread` locks the phase/thread mapping of the restore pipeline.

### [P1-4] `rollback_or_combine` fail-open classification — FIXED (exhaustive)
`crates/core/src/windows_debugger.rs`, `crates/core/src/error.rs`

`rollback_or_combine` now **exhaustively** matches the rollback result:
- `Ok` → rollback succeeded → plain freeze error.
- `Err(CaptureEpochRestore)` → structured per-thread failures merged with the freeze error.
- `Err(other)` → **any** other rollback error is a rollback failure (NEVER success), preserved in the new `CaptureFreezeWithRollbackFailure.rollback_error: Option<String>` alongside the freeze error.
- Unit tests: `generic_rollback_error_is_fail_closed` (non-`CaptureEpochRestore` error → combined error with both freeze + generic text) and `successful_rollback_returns_plain_freeze_error`.

### [P2-1] Production scope gating locked by real call counts — FIXED
`crates/pe/src/dumper/dump_process.rs`

Extracted `with_capture_epoch(debugger, epoch_needed, body)` — **the exact function `dump_process` calls** — which begins/ends the epoch (or not) around the live-capture body. A `CountingDebuggerCell` mock (counts `freeze_target_threads`/`unfreeze_target_threads`) drives the SAME production function in 5 tests:
- (a) OreansClassic / no live capture → **freeze=0, unfreeze=0**.
- (b) GTO capture success → **freeze=1, unfreeze=1**, target unfrozen after return.
- (c) capture body `Err` → **freeze=1, unfreeze=1** (epoch `Drop` restores).
- (d) restore failure → surfaced as `capture_epoch_restore` error (never silent).
- (e) offline work runs only after `unfreeze` completes (target not frozen after `with_capture_epoch` returns).

Assertion messages describe the counts, not the predicate. The pure-predicate tests remain but no longer masquerade as call-count tests.

### [P2-2] Harness handle leak — FIXED
- The `matches!(OpenThread(...), Ok(_))` handle leaks in the exit tests were replaced with `thread_exists(tid)` (RAII: open + `CloseHandle` immediately).
- Both deterministic-exit tests now assert a **before/after process handle-count net-zero** for the harness's own operations (`handles_after_launch == after_ops`).
- The 50-cycle handle test (warm-up 5 + measured 50) already asserts net-zero for the production freeze loop.

### [P2-3] `GetProcessHandleCount` failure handling — FIXED
- `process_handle_count()` now returns `Result<u32, String>` and propagates `GetProcessHandleCount` failure (never silently returns a default `0`). The handle test uses `.unwrap()` on the Result.
- Measured: `warmup=126 initial=126 max=126 final=126` → **net-zero**, no monotonic growth. Runs under `--test-threads=1`.

### [P2-4] Warnings evidence — RESOLVED
mida-pe **lib** build (`cargo build -p mida-pe --offline`, same toolchain/feature/command as the frozen Route Y R0/Route Z baseline): **12 warnings**, identical to the frozen baseline. **My AF3 changes add 0.**

Per-warning list (crate/file/line/text) — all 12 are pre-existing (from committed HEAD / earlier routes; none in my AF2/AF3 diff):
| # | location | text |
|---|---|---|
| 1 | `pe/dumper/dump_process.rs:1392` | `value assigned to materialized is never read` |
| 2 | `pe/dumper/heap_global_snapshot.rs:2625` | `variable does not need to be mutable` |
| 3 | `pe/dumper/raw_slab_coherence.rs:3062` | `variable does not need to be mutable` |
| 4 | `pe/dumper/raw_slab_coherence.rs:4257` | `variable does not need to be mutable` |
| 5 | `pe/dumper/heap_global_snapshot.rs:2444` | `methods id and old_base are never used` |
| 6 | `pe/dumper/heap_global_snapshot.rs:2608` | `function sha256_hex_pub is never used` |
| 7 | `pe/dumper/heap_global_snapshot.rs:2930` | `function align_up_u64 is never used` |
| 8 | `pe/dumper/raw_slab_coherence.rs:76` | fields `source_parent_old_base` … `containing_parent_size` are never read |
| 9 | `pe/dumper/raw_slab_coherence.rs:1849` | variants `TransformPreimageDrift` and `StrictExtentRejected` are never constructed |
| 10 | `pe/dumper/raw_slab_coherence.rs:2693` | `function build_patched_backing_slab is never used` |
| 11 | `pe/dumper/stage_timing.rs:75` | `method with_item_count is never used` |
| 12 | `pe/dumper/x64_asm.rs:269` | `function mov_r64_imm64 is never used` |

**12 → 14 → 13 → 12 story:** the AF2 report's "14" was an overcount. Two of its counted warnings were `variable does not need to be mutable` warnings that my own AF2/AF3 code introduced (`epoch_tel` in the then-inline epoch block, and the `dedicated_slabs` `mut` in the new `with_capture_epoch` binding). These were both removed (the epoch refactor eliminated the inline `epoch_tel`; this AF3 removed the `dedicated_slabs` `mut`). After cleanup, mida-pe is back to the **exact frozen baseline of 12**, with `cargo fix` suggestion count also back to baseline (3 vs the inflated count). `materialized` (dump_process.rs:1392) is committed HEAD code, verified **not** present in the uncommitted diff.

mida-core: **0 warnings** in both default and `capture-epoch-harness` (bins+tests) builds.

---

## Real Windows harness (15 tests, feature-gated, `--test-threads=1`)

| Test | Evidence |
|---|---|
| `real_process_deterministic_exit_before_open` | single freeze, barrier thread TID recorded, phase `"before_open"` proven; harness handle net-zero |
| `real_process_deterministic_exit_after_open_before_suspend` | single freeze, barrier TID (e.g. 25640) recorded, phase `"after_open_before_suspend"` proven; harness handle net-zero |
| `real_process_epoch_end_then_drop_is_idempotent` | real pre-suspended thread baseline=1→2→1→1, no double-resume |
| `real_process_epoch_guard_drop_restores_on_error` | real `Result::Err` early-return → Drop, exact per-thread restore |
| `real_process_epoch_guard_drop_restores_on_panic` | panic + `catch_unwind` → Drop, exact per-thread restore |
| `real_process_freeze_only_backend_end_fails_closed` | freeze-only backend → `end()` Err (default unfreeze fail-closed) |
| `real_process_freeze_stops_workers` / `unfreeze_resumes_workers` / `freeze_covers_thread_set` | live freeze stops counter, unfreeze resumes, thread set covered |
| `real_process_partial_freeze_after_n_threads_rolls_back` | precise per-thread `post == pre` after injected failure |
| `real_process_partial_freeze_rollback_failure_reports_tid` | combined freeze+rollback error, victim TID+phase, others restored |
| `real_process_partial_freeze_rolls_back` | nonexistent PID fails closed |
| `real_process_prior_suspend_count_restored` | pre-suspended thread baseline=1, epoch=2, restore=1 |
| `real_process_repeated_20x_all_pass` | 20 live freeze/restore round-trips |
| `real_process_repeated_freeze_has_no_handle_growth` | warmup=126 initial=126 max=126 final=126, net-zero |

Result: **15/15 pass** across 4+ independent runs, no flake.

**Barrier state transitions (deterministic):**
`barrier thread TID created` → `publishes TID to barrier_cur_tid` → `blocks (waiting)` → `ToolHelp snapshot observes TID` → `freeze hook calls force_exit(TID)` → `helper confirms termination (barrier_done=1)` → `OpenThread` (before_open: fails 87) / `SuspendThread` (after_open: fails, GetExitCodeThread reports terminated) → `diagnostic records (TID, phase)` → surviving threads frozen → `unfreeze` → threads restored precisely.

---

## Required gates — all green

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo test -p mida-core --offline` | **78 / 0** (incl. 3 new P1-3/P1-4 unit tests) |
| `cargo test -p mida-core --features capture-epoch-harness --test capture_epoch_harness --offline -- --test-threads=1` | **15 / 0** |
| fresh isolated `cargo build -p mida-core --offline` | succeeds; **no helper binary** |
| fresh isolated `cargo build -p mida-core --features capture-epoch-harness --offline` | succeeds; **helper binary present** |
| default target `capture_epoch_helper` | absent (P1-4 compile gating) |
| feature target `capture_epoch_helper` | present |
| `cargo test -p mida-pe --offline` | **654+7+2+3 / 0** (654 lib incl. 5 new call-count + 5 predicate tests) |
| `cargo test -p mida-cli --features gto-product-recovery` | **298 / 0** (lib) + 4+1+20+17+3 |
| `cargo test -p mida-cli --offline` | **296 / 0** (lib) + 4+1+20+17+3 |
| `python tools/test_gto_live_route_controller.py` | **36 / 0** |
| `git diff --check` | clean |

Warnings: mida-core 0 (default + feature); mida-pe lib **12** (frozen baseline, my delta 0, per-warning list above). No residual helper processes.

---

## Honesty statement

- The thread-exit tests use a **shared-memory command/status barrier** (single-shot), not a probabilistic storm. The exact TID and phase are proven by the feature-gated diagnostic.
- The test-injected `ResumeThread` failure is explicitly **controlled injection** (`fail_resume_tid`), not a claim of natural Windows API failure.
- The production gating is locked by **real `freeze_target_threads`/`unfreeze_target_threads` call counts** on a mock driving `with_capture_epoch` — the same function `dump_process` calls. Predicate tests are separate and not presented as call-count tests.
- Gate results are listed per command/test binary; aggregated counts are broken down by lib/test binary.
- Win32 error codes are read immediately after the failing call and before `CloseHandle` (P1-3), structurally and unit-locked.

---

## Deliverables & boundary

- New report: `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF3_WINDOWS_HARNESS_RESULT.md` (untracked).
- Untracked source: `crates/core/src/bin/` (helper), `crates/core/tests/` (harness), `crates/core/src/capture_epoch.rs`, `crates/pe/src/dumper/capture_epoch.rs`.
- Tracked modifications: 8 files (`session.rs`, `core/Cargo.toml`, `debugger.rs`, `error.rs`, `lib.rs`, `windows_debugger.rs`, `dump_process.rs`, `mod.rs`, `raw_slab_coherence.rs`). Cumulative diff against HEAD: +1266 / -54 across these 9 files (AF1+AF2+AF3 uncommitted work).
- All 9 prior/current docs untracked and excluded.
- HEAD `68b8032` unchanged; no commit/push/live/protected-sample/candidate.
- Temp build helper and isolated target dirs cleaned up; no residual helper processes.
