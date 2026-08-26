# IMP-09-CARRIER-R5-R4 - Teardown Observability Design

Work order: WORK_ORDER_IMP-09-CARRIER-R5-R4-TEARDOWN_20260825.md
Branch: codex/imp09-carrier-r5-r2
Baseline HEAD: 4c8661f04bfdcc0ca14d3499aeb5b0d825a89c10 (R5-R3, audited PASS 242/0)
Status: offline_mock=true / live_authorized=false / protected_sample=NOT_AUTHORIZED
Date: 2026-08-25

---

## 1. Goal

Make the walker session teardown observable: every `VirtualFreeEx` release
step is recorded as a structured event `(sequence, address, size, free_type,
ok, last_error)`, the teardown verdict is reported SEPARATELY from the walker
execute verdict (T1), double-frees are refused by the ledger (T3), the
ABORTED session path goes through the same teardown (T4), and tests prove the
guard ledger is empty after the normal / failure / abort paths (T5).

## 2. Release order + relation to the R5-R2 guard ledger (work order section 4.3)

### Release order (frozen R5-R2 semantics, unchanged)

```
WalkerSessionMemory::allocate(target, n)
  -> params region  (VirtualAllocEx MEM_RESERVE|MEM_COMMIT)
  -> section region (VirtualAllocEx MEM_RESERVE|MEM_COMMIT)
Teardown release order (fixed, never reordered):
  step 1: params  (VirtualFreeEx MEM_RELEASE)
  step 2: section (VirtualFreeEx MEM_RELEASE)
```

The R5-R2 transactional guard (`WalkerTeardownGuard`, constructed at the top
of `AntidebugController::run()`) already owned exactly these two allocations
via `walker_mem: Option<WalkerSessionMemory>` and freed them with
`WalkerSessionMemory::cleanup()` (idempotent `params.take()` / `section.take()`
+ `VirtualFreeEx`).

### Relation diagram (R5-R4: ONE accounting story, no second ledger)

```
R5-R2 accounting (source of truth)          R5-R4 event ledger (derived, exportable)
-----------------------------------          -------------------------------------------
WalkerSessionMemory.params_va  -----------> TeardownLedger.register(params_va)   (step 1)
WalkerSessionMemory.section1_va ----------> TeardownLedger.register(section1_va) (step 2)
                                                    |
                                                    v
                                       TeardownLedger.run_teardown(target, backend)
                                       (per-step VirtualFreeEx + GetLastError capture)
                                                    |
                                                    v
                              WalkerTeardownReport { outcome, events, double_free_events,
                                                     ledger_empty }  --stashed on controller-->
                                                                        walker evidence sidecar
```

- The R5-R2 `WalkerSessionMemory` remains the ONLY owner of the allocation
  state. The teardown ledger DERIVES its registered set from
  `params_va()` / `section1_va()` at teardown time — it never independently
  books allocations (no second accounting set).
- After the ledger releases both regions, the `WalkerSessionMemory` owner is
  dropped; its frozen `Drop::cleanup()` re-attempts `VirtualFreeEx` on the
  already-released regions, which fails harmlessly at the OS level and is
  ignored (exactly the pre-existing idempotent behavior — unchanged).
- `TeardownLedger::is_empty()` == `owned.is_empty()`: empty exactly when no
  allocation remains tracked (T5).

## 3. Structured types (work order section 3)

```rust
// walker_teardown.rs
pub const TEARDOWN_EVIDENCE_SCHEMA: &str = "mida.antidebug-walker-teardown/v1";

pub struct TeardownFreeEvent {
    pub sequence: u32,      // monotonic 1-based, across free + double-free events
    pub address: u64,
    pub size: usize,        // 0 for MEM_RELEASE
    pub free_type: u32,     // raw MEMORY_FREE_TYPE bits (MEM_RELEASE = 0x8000)
    pub ok: bool,           // VirtualFreeEx TRUE?
    pub last_error: u32,    // GetLastError immediately after failure (0 on ok)
}

pub enum TeardownOutcome {
    Released,                                    // all tracked allocations freed
    PartiallyReleased { failed_steps: Vec<TeardownFreeEvent> }, // some freed, failures exported
    Failed { step: u32, error: String },         // first free failed, sequence stopped
}

pub struct WalkerTeardownReport {
    pub schema: String,
    pub outcome: TeardownOutcome,
    pub events: Vec<TeardownFreeEvent>,          // T2 exportable
    pub double_free_events: Vec<TeardownFreeEvent>, // T3
    pub ledger_empty: bool,                      // T5
}

pub trait FreeBackend: fmt::Debug {
    fn free(&self, target: HANDLE, address: u64, size: usize, free_type: u32) -> Result<(), u32>;
}
pub struct Win32FreeBackend; // production: VirtualFreeEx + immediate GetLastError
```

## 4. Fail-closed semantics (work order section 1.3 / T1-T5)

- **No silent retry**: a failed `VirtualFreeEx` is recorded once; the sequence
  ABORTS at the first failure. `PartiallyReleased.failed_steps` exports every
  failed step; `Failed{step,error}` reports a first-step failure with the raw
  win32 error.
- **T1 separation**: the teardown report NEVER changes `run()`'s verdict. The
  RAII guard runs after the walker gates decided Proceed/Failed; a failed free
  only affects the report, never the walker output consumption.
- **T3 double-free refusal**: `register()` refuses a duplicate address and
  records a double-free event; `run_teardown` refuses an address present in
  BOTH `owned` and `released` (ledger inconsistency) before any free and
  records the refusal. Idempotency: a second `run_teardown` on an empty
  `owned` set issues NO free.
- **T4 ABORTED**: the abort path (execute gate fails closed, or any early
  failure) exits `run()` through the same guard — the session allocations are
  freed and the report records the release.
- **T5 no-leak**: tests assert `ledger_empty == true` (owned set empty) after
  the normal (COMPLETED), failure, and abort paths.

## 5. Production wiring

- `WalkerTeardownGuard` (antidebug_controller.rs) now holds a second raw
  pointer to `controller.teardown_report`; on Drop it runs
  `teardown_walker_session_report(&mem, handle)` (real `Win32FreeBackend`),
  drops the session owner, and stashes the report. Every exit path of
  `run()` — success, early return, unwind — records a report (no-session
  report when nothing was installed).
- `AntidebugController::teardown_walker_session()` runs the same structured
  path explicitly and returns the report (idempotent).
- `WalkerEvidenceRecord.teardown: Option<WalkerTeardownReport>` carries the
  report into the walker evidence sidecar written by the two production paths
  (create_process + post_attach) after `terminate_and_wait()`.

## 6. Tests (positive + negative >= 4)

Module `walker_teardown::imp09_r5r4_teardown_tests` (12):
- release order params-then-section; production release frees both + ledger
  zeroed (T5 normal); idempotent second run frees nothing (T3); ABORTED path
  frees all + ledger zeroed (T4/T5); free failure (injectable backend) ->
  PartiallyReleased with exported steps (T2); first-free failure -> Failed
  with step + win32 error; double-free rejected + recorded (T3); ledger
  inconsistency detected (T3); teardown failure does not affect output
  consumption (T1); production wrapper over real `VirtualFreeEx`; None ->
  Released; report JSON round-trip.

Controller `antidebug_controller::tests` (5):
- guard records structured teardown after Proceed (T1/T2/T5 + evidence
  carries report); guard records teardown after abort failure (T4/T5); early
  failure records no-session teardown (T5); teardown failure does not block
  output consumption (T1); explicit teardown idempotent + report exportable
  (T3/T5).

## 7. Frozen semantics (untouched)

round_flags extension layout, R5-R2 lifecycle window order, candidate mapping
proof / envelope / liveness / execute gates, `runner_preflight.rs`,
`VirtualFreeEx`/`GetLastError` semantics, `WalkerSessionMemory::cleanup`/`Drop`
exactly-once + idempotent behavior, `WalkerSessionMemory` allocation layout
(params + section).
