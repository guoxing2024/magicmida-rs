# Route Z R0 AF2 AF1 AF4 — OS-Termination Proof, Atomic Barrier Protocol, and Epoch Error/Telemetry Closure

**Status:** `RouteZ_R0_AF2_AF1_AF4_ReviewRequested`
**Branch:** `oreans/two-sample-mainline`
**HEAD:** `68b8032` (unchanged — no commit made)
**HEAD^:** `9450b3a`

This work order separates "thread received the exit command" from "Windows confirmed the thread object terminated" and closes the epoch error/telemetry semantics. **No commit / push / live / protected-sample / candidate / cold-start was performed.** All docs remain untracked.

---

## Blocker → resolution

### [P1-1] `barrier_done` written before real termination — FIXED with OS-termination proof
`crates/core/src/bin/capture_epoch_helper.rs`, `crates/core/tests/capture_epoch_harness.rs`, `crates/core/src/windows_debugger.rs`

The helper no longer claims termination. The barrier thread, when commanded, simply `return`s (terminates). **Termination is proven by the harness via `WaitForSingleObject` on a real `THREAD_SYNCHRONIZE` thread handle**:
- `force_exit(tid)` opens a `THREAD_SYNCHRONIZE` handle to the barrier thread, commands exit via shared memory, then blocks until `WaitForSingleObject` returns `WAIT_OBJECT_0` (the OS thread object is signaled = fully terminated). It returns `BarrierExitResult::Terminated` **only** on that OS-level proof.
- `before_open`: `command exit → OS-termination confirmed → OpenThread` (OpenThread then deterministically fails 87).
- `after_open_before_suspend`: `OpenThread success → command exit → same handle signaled confirmed → SuspendThread` (fails; the freeze re-confirms via its own `THREAD_SYNCHRONIZE` handle).
- The `barrier_done` shared field was removed entirely (no false termination claim).
- Evidence distinguishes: `command_acknowledged` (command armed), `thread_object_signaled` (`WaitForSingleObject` = `WAIT_OBJECT_0`), `transient_phase_recorded` (freeze diagnostic). Single shot, no retry.

### [P1-2] `GetExitCodeThread` failure treated as terminated — FIXED (fail-closed)
`crates/core/src/windows_debugger.rs`

The `GetExitCodeThread` approach (with its `STILL_ACTIVE=259` ambiguity and the `!ok => terminated` fail-open) was replaced with a **thread-object signal** check on the freeze's own `THREAD_SYNCHRONIZE` handle:
- `WAIT_OBJECT_0` → thread object signaled → terminated → transient skip.
- `WAIT_TIMEOUT` → still alive → fail-closed rollback.
- `WAIT_FAILED` → evidence failure (never treated as terminated) → fail-closed rollback, `GetLastError` saved.
- `SuspendThread` failure code is read immediately (before any other Win32 call); `OpenThread` now requests `THREAD_SYNCHRONIZE` so the handle is waitable.

### [P1-3] Barrier callback failure only `debug_assert!` — FIXED (structured error, release-identical)
`crates/core/src/windows_debugger.rs`, harness

`BarrierExitResult` is matched explicitly at both windows. Anything other than `Terminated`:
- returns a **structured freeze error** (via `rollback_or_combine`) carrying the barrier TID, window/phase, and the timeout/failure reason;
- **rolls back** already-suspended threads;
- does **not** proceed to `OpenThread`/`SuspendThread`.
- No `debug_assert` — release and debug behave identically.
- New test `real_process_barrier_failure_fails_closed_no_handle_leak`: a barrier returning `Timeout` fails the freeze closed, leaves no thread suspended, and has net-zero handle growth.

### [P1-4] `with_capture_epoch` body + restore both preserved — FIXED
`crates/pe/src/dumper/dump_process.rs`, `crates/pe/src/error.rs`

`with_capture_epoch` no longer uses `?` on the body then relies on `Drop`. It captures **both** the body result and the explicit `end()` result and matches all four combinations:
- (a) body `Ok` + restore `Ok` → `Ok`.
- (b) body `Err` + restore `Ok` → body error.
- (c) body `Ok` + restore `Err` → restore error.
- (d) body `Err` + restore `Err` → new `PeError::CaptureEpochCombined { body, restore }` preserving **both** errors.

Ordinary error returns never depend on `Drop`; `Drop` remains only the last resort for panic/unwind. Call-count tests cover all four, each with `unfreeze exactly once`.

### [P1-5] Epoch elapsed telemetry captured before the body — FIXED
`crates/pe/src/dumper/dump_process.rs`

`elapsed_ms` is now captured **after** the live capture body runs and **before** `unfreeze`, so it reflects the full `detect_containers`/`detect_heap_globals`/`capture_heap_slab` window, not just the begin overhead. `started_ms`/`suspended_count`/`suspended_thread_ids` are captured after begin (they are begin-facts). New test `telemetry_elapsed_covers_body` puts a controllable 20ms delay in the body and asserts `elapsed_ms >= 20`.

### [P2-1] Shared-memory access model inconsistent — FIXED (uniform atomics + alignment)
`crates/core/tests/capture_epoch_harness.rs`, `crates/core/src/bin/capture_epoch_helper.rs`

Both the helper and the harness now access every shared field through **`AtomicU32`/`AtomicU64` with `Ordering::SeqCst`** (the harness previously used plain raw load/store). This gives the command/status protocol an explicit happens-before: test `store` publishes a command → helper `load` observes → barrier thread exits → harness `WaitForSingleObject` observes the OS signal. The harness adds **alignment `debug_assert`s** (`u64` at OFF_COUNTER 8-aligned; all `u32` fields 4-aligned; `MAP_SIZE` covers all fields).

### [P2-2] Handle/evidence closure — FIXED
- The barrier's `THREAD_SYNCHRONIZE` handle is closed on every path (success, `WAIT_TIMEOUT`, `WAIT_FAILED`, and best-effort on the open-failure path).
- The freeze's `OpenThread` handle is closed in every `SuspendThread`/`WaitForSingleObject` outcome branch.
- Both deterministic-exit tests retain their current-process handle **net-zero** assertion; the new barrier-failure test asserts net-zero too.

---

## Real Windows harness (16 tests, feature-gated, `--test-threads=1`)

| Test | Evidence |
|---|---|
| `real_process_deterministic_exit_before_open` | single freeze, OS-termination-proven barrier, phase `"before_open"`; handle net-zero |
| `real_process_deterministic_exit_after_open_before_suspend` | single freeze, barrier TID (e.g. 27052), phase `"after_open_before_suspend"`; handle net-zero |
| `real_process_barrier_failure_fails_closed_no_handle_leak` | barrier returns `Timeout` → freeze fails closed, no thread suspended, handle net-zero |
| `real_process_epoch_end_then_drop_is_idempotent` | real pre-suspended thread baseline=1→2→1→1 |
| `real_process_epoch_guard_drop_restores_on_error` / `_on_panic` | exact per-thread restore on error-return and panic-unwind |
| `real_process_freeze_only_backend_end_fails_closed` | freeze-only backend → `end()` Err |
| `real_process_freeze_stops_workers` / `unfreeze_resumes_workers` / `freeze_covers_thread_set` | live freeze/unfreeze round-trip |
| `real_process_partial_freeze_after_n_threads_rolls_back` | precise per-thread `post==pre` |
| `real_process_partial_freeze_rollback_failure_reports_tid` | combined freeze+rollback error, victim TID+phase |
| `real_process_partial_freeze_rolls_back` | nonexistent PID fails closed |
| `real_process_prior_suspend_count_restored` | pre-suspended thread baseline=1, epoch=2, restore=1 |
| `real_process_repeated_20x_all_pass` | 20 live round-trips |
| `real_process_repeated_freeze_has_no_handle_growth` | warmup=127 initial=127 max=127 final=127, net-zero |

Result: **16/16 pass** across 3+ independent runs, no flake.

**Barrier evidence protocol (P1-1):**
`barrier TID created → publishes to barrier_cur_tid → blocks → ToolHelp snapshot observes TID → force_exit commands exit (command_acknowledged) → harness WaitForSingleObject observes thread-object signaled (thread_object_signaled) → freeze OpenThread/SuspendThread result → diagnostic records (TID, phase) (transient_phase_recorded) → surviving threads frozen → unfreeze → precise restore`.

---

## Required gates — all green

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo test -p mida-core --offline` | **78 / 0** |
| `cargo test -p mida-core --features capture-epoch-harness --test capture_epoch_harness --offline -- --test-threads=1` | **16 / 0** |
| fresh isolated `cargo build -p mida-core --offline` | no `capture_epoch_helper` (P1-4) |
| fresh isolated `cargo build -p mida-core --features capture-epoch-harness --offline` | `capture_epoch_helper` present |
| `cargo test -p mida-pe --offline` | **659+7+2+3 / 0** (659 lib incl. 10 call-count + 5 predicate tests) |
| `cargo test -p mida-cli --features gto-product-recovery` | **298 / 0** (lib) + others |
| `cargo test -p mida-cli --offline` | **296 / 0** (lib) + others |
| `python tools/test_gto_live_route_controller.py` | **36 / 0** |
| `git diff --check` | clean |

Warnings: mida-core **0** (default + feature bins+tests); mida-pe lib **12** (frozen Route Y R0/Route Z baseline — my delta 0). No residual helper processes.

---

## Honesty statement

- Termination is proven by the **OS thread-object signal** (`WaitForSingleObject` = `WAIT_OBJECT_0` on a `THREAD_SYNCHRONIZE` handle), never by a helper's "done" flag or a command acknowledgement.
- `WAIT_FAILED` / evidence-query failure is **fail-closed rollback**, never interpreted as terminated; `WAIT_TIMEOUT` is still-alive fail-closed.
- The barrier callback failure path returns a structured error with TID/window/reason and rolls back — identical in release and debug (no `debug_assert`).
- `with_capture_epoch` preserves both body and restore errors; ordinary error returns never depend on `Drop`.
- Telemetry `elapsed_ms` covers the live body (test with a 20ms controllable delay).
- Shared memory uses a consistent atomic protocol on both ends with alignment assertions.
- Gate results are listed per command/test binary; the `with_capture_epoch` refactor is the exact production function tested by the call-count mock.

---

## Deliverables & boundary

- New report: `docs/GTO_ROUTE_Z_R0_AF2_AF1_AF4_WINDOWS_HARNESS_RESULT.md` (untracked).
- **Tracked modified: 10 files** — `session.rs`, `core/Cargo.toml`, `debugger.rs`, `error.rs`, `lib.rs`, `windows_debugger.rs`, `dump_process.rs`, `mod.rs`, `raw_slab_coherence.rs`, `pe/src/error.rs` (the last added `PeError::CaptureEpochCombined` for P1-4).
- **Untracked source: 4** — `crates/core/src/bin/`, `crates/core/src/capture_epoch.rs`, `crates/core/tests/`, `crates/pe/src/dumper/capture_epoch.rs`.
- **Untracked docs after this report: 11**, listed:
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
- HEAD `68b8032` unchanged; no commit/push/live/protected-sample/candidate.
- Temp build helper and isolated target cleaned; no residual helper processes.
