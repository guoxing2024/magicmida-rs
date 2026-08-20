# Route Z R0 AF2 AF1 AF5 — Wait-Failure Evidence and Epoch Failure Telemetry Closure

**Status:** `RouteZ_R0_AF2_AF1_AF5_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `68b8032` (unchanged — no commit made)
**HEAD^:** `9450b3a`

This is the AF-series closure work order. It fixes two real evidence bugs (WAIT_FAILED error-code capture order; epoch telemetry lost on error paths) and makes the barrier-protocol/evidence claims match the implementation. **No commit / push / live / protected-sample / candidate / cold-start was performed.** All docs remain untracked.

---

## Blocker → resolution

### [P1-1] Production `WAIT_FAILED` error code read after `CloseHandle` — FIXED
`crates/core/src/windows_debugger.rs`

The `SuspendThread`-failure classification now uses an explicit `match`-style flow with **immediate `GetLastError` capture on `WAIT_FAILED`, before `CloseHandle`**:
- `WAIT_OBJECT_0` → thread object signaled → terminated → transient skip.
- `WAIT_TIMEOUT` → still alive → bounded retry, then fail-closed rollback.
- `WAIT_FAILED` → `GetLastError` read **immediately** into a local (`wait_failed_code`), then `CloseHandle`, then fail-closed rollback. No sleep / continued polling after a `WAIT_FAILED`.
- Unexpected wait value → fail-closed rollback (never treated as terminated).
- The evidence includes the TID, phase, `SuspendThread` error, the wait result, and the wait error.

A **pure, testable classifier** `classify_thread_wait(WAIT_EVENT) -> ThreadWaitClass` was extracted (`Terminated` / `StillAlive` / `QueryFailed` / `Unexpected`) and unit-tested for all four outcomes. The `WAIT_FAILED` immediate-capture order is structurally guaranteed in the code (local read before `CloseHandle`).

### [P1-2] Body/restore error paths lost epoch telemetry — FIXED
`crates/pe/src/dumper/dump_process.rs`, `crates/pe/src/error.rs`

`CaptureEpochTelemetry` was moved into `crate::error` (a neutral home) and the error paths now carry it:
- `(Ok, Ok)` → returns `(value, telemetry)`.
- `(Err(body), Ok)` → `PeError::CaptureEpochBodyFailed { error, telemetry }`.
- `(Ok, Err(restore))` → `PeError::CaptureEpochRestoreFailed { error, telemetry }`.
- `(Err(body), Err(restore))` → `PeError::CaptureEpochCombined { body, restore, telemetry }`.

Every error path now exposes `epoch_begun`, `suspended_count`, `suspended_thread_ids`, `elapsed_ms`, `started_ms`. New tests:
- `body_error_preserves_telemetry` — a 20ms body delay on the error path must still report `elapsed_ms >= 20`, plus count/ids/started.
- `restore_error_preserves_telemetry` — count/ids/started recoverable.
- `combined_error_preserves_both_and_telemetry` — both errors + telemetry.

### [P2-1] `command_acknowledged` claimed without a real ack — FIXED (honest terminology)
The report and test evidence now use **`command_published`** (the harness wrote the command into shared memory), not `command_acknowledged`. The only termination evidence is the OS thread-object signal. State distinction in the report:
- `command_published` (harness armed the command)
- `thread_object_signaled` (`WaitForSingleObject` = `WAIT_OBJECT_0` on a `THREAD_SYNCHRONIZE` handle)
- `transient_phase_recorded` (freeze diagnostic)

No ack field was added (option b of the audit), because the harness does not receive a helper acknowledgement — the OS signal is the only proof.

### [P2-2] Timestamp evidence not actually generated — FIXED (report matches implementation)
The AF5 report claims **ordering** evidence only (command published → OS signaled → phase recorded), not timestamps. It does not list any timestamp evidence the source does not produce. The concrete observed evidence in tests is the exact barrier TID and the recorded phase (e.g. `barrier_tid=10344 phase_hit=true`), plus handle counts.

### [P2-3] `BarrierExitResult::Failure` mislabeled the HRESULT as a Win32 code — FIXED
`crates/core/src/windows_debugger.rs`, harness

`BarrierExitResult::Failure` is now a struct `{ hresult: u32, win32_code: u32 }`:
- `OpenThread` failure: `hresult = e.code().0 as u32` (true HRESULT), `win32_code = hresult & 0xffff` (Win32 low word).
- `WAIT_FAILED`: `hresult = 0`, `win32_code = GetLastError().0` (true Win32 code).

A raw HRESULT is never mislabeled as a Win32 code.

### [P2-2] Handle closure on all wait-failure paths — FIXED
The freeze's `OpenThread` handle is closed on every outcome (`WAIT_OBJECT_0`, `WAIT_TIMEOUT`, `WAIT_FAILED`, unexpected). The barrier's `THREAD_SYNCHRONIZE` handle is closed on success, timeout, `WAIT_FAILED`, and open-failure. The deterministic `before_open`, `after_open`, and `barrier_failure` tests each assert current-process handle **net-zero**.

---

## Real Windows harness (16 tests, feature-gated, `--test-threads=1`)

| Test | Evidence |
|---|---|
| `real_process_deterministic_exit_before_open` | single freeze, OS-proven barrier, phase `"before_open"`; handle net-zero |
| `real_process_deterministic_exit_after_open_before_suspend` | single freeze, barrier TID (e.g. 10344), phase `"after_open_before_suspend"`; handle net-zero |
| `real_process_barrier_failure_fails_closed_no_handle_leak` | barrier `Timeout` → freeze fails closed, no thread suspended, handle net-zero |
| `real_process_epoch_end_then_drop_is_idempotent` | real pre-suspended thread baseline=1→2→1→1 |
| `real_process_epoch_guard_drop_restores_on_error` / `_on_panic` | exact per-thread restore |
| `real_process_freeze_only_backend_end_fails_closed` | freeze-only backend → `end()` Err |
| `real_process_freeze_stops_workers` / `unfreeze_resumes_workers` / `freeze_covers_thread_set` | live freeze/unfreeze round-trip |
| `real_process_partial_freeze_after_n_threads_rolls_back` | precise per-thread `post==pre` |
| `real_process_partial_freeze_rollback_failure_reports_tid` | combined freeze+rollback error, victim TID+phase |
| `real_process_partial_freeze_rolls_back` | nonexistent PID fails closed |
| `real_process_prior_suspend_count_restored` | pre-suspended thread baseline=1, epoch=2, restore=1 |
| `real_process_repeated_20x_all_pass` | 20 live round-trips |
| `real_process_repeated_freeze_has_no_handle_growth` | warmup=125 initial=125 max=125 final=125, net-zero |

Result: **16/16 pass** across 3+ independent runs, no flake.

**Barrier ordering evidence (no timestamps claimed):**
`barrier TID created → published → blocks → ToolHelp snapshot observes → command published → harness WaitForSingleObject = WAIT_OBJECT_0 (thread_object_signaled) → freeze OpenThread/SuspendThread result → diagnostic records (TID, phase) → surviving threads frozen → unfreeze → precise restore`.

---

## Required gates — all green

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo test -p mida-core --offline` | **79 / 0** (incl. new `classify_thread_wait` test) |
| `cargo test -p mida-core --features capture-epoch-harness --test capture_epoch_harness --offline -- --test-threads=1` | **16 / 0** |
| fresh isolated `cargo build -p mida-core --offline` | no `capture_epoch_helper` (P1-4) |
| fresh isolated `cargo build -p mida-core --features capture-epoch-harness --offline` | `capture_epoch_helper` present |
| `cargo test -p mida-pe --offline` | **662+7+2+3 / 0** (662 lib incl. 13 call-count + telemetry tests) |
| `cargo test -p mida-cli --features gto-product-recovery` | **298 / 0** (lib) + others |
| `cargo test -p mida-cli --offline` | **296 / 0** (lib) + others |
| `python tools/test_gto_live_route_controller.py` | **36 / 0** |
| `git diff --check` | clean |

Warnings: mida-core **0** (default + feature); mida-pe lib **12** (frozen Route Y R0/Route Z baseline — my delta 0). No residual helper processes.

---

## Honesty statement

- `WAIT_FAILED`'s `GetLastError` is read **immediately** into a local, **before** `CloseHandle`, and no sleep/poll follows a `WAIT_FAILED`.
- Telemetry (`epoch_begun`/`suspended_count`/`suspended_thread_ids`/`elapsed_ms`/`started_ms`) is preserved on every `with_capture_epoch` error path (body Err, restore Err, both Err) via structured `PeError` variants.
- The barrier protocol claims **`command_published`**, not `command_acknowledged`; only the OS thread-object signal is treated as termination proof.
- No timestamp evidence is claimed that the source does not produce; only ordering is claimed.
- `BarrierExitResult::Failure` distinguishes HRESULT from the Win32 low word (and from a true `WAIT_FAILED` `GetLastError`).
- The `WAIT_FAILED` immediate-capture order is structurally guaranteed in the production code; the pure `classify_thread_wait` classifier is unit-locked.

---

## Deliverables & boundary

- New report: `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF5_WINDOWS_HARNESS_RESULT.md` (untracked).
- **Tracked modified: 10 files** — `session.rs`, `core/Cargo.toml`, `debugger.rs`, `core/error.rs`, `lib.rs`, `windows_debugger.rs`, `dump_process.rs`, `mod.rs`, `raw_slab_coherence.rs`, `pe/src/error.rs`. No new tracked files were added by this work order.
- **Untracked source: 4** — `crates/core/src/bin/`, `crates/core/src/capture_epoch.rs`, `crates/core/tests/`, `crates/pe/src/dumper/capture_epoch.rs`.
- **Untracked docs after this report: 12**, listed:
  1. `docs/GTO_ROUTE_X_R1_LIVE_RESULT.md`
  2. `docs/GTO_ROUTE_Y_R0_OFFLINE_RESULT.md`
  3. `docs/GTO_ROUTE_Y_R1_LIVE_RESULT.md`
  4. `docs/GTO_ROUTE_Y_R1_LIVE_RESULT_A2.md`
  5. `docs/GTO_ROUTE_Z_R0_AF1_OFFLINE_RESULT.md`
  6. `docs/GTO_ROUTE_Z_R0_OFFLINE_RESULT.md`
  7. `docs/GTO_ROUTE_Z_R0_AF2_WINDOWS_HARNESS_RESULT.md`
  8. `docs/GTO_ROUTE_Z_R0_AF2_AF1_WINDOWS_HARNESS_RESULT.md`
  9. `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF2_WINDOWS_HARNESS_RESULT.md`
  10. `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF3_WINDOWS_HARNESS_RESULT.md`
  11. `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF4_WINDOWS_HARNESS_RESULT.md`
  12. `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF5_WINDOWS_HARNESS_RESULT.md`
- Read-only baseline `68b8032`, no commit/live. Temp build helper and isolated targets cleaned; no residual helper processes.
