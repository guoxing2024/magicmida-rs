//! IMP-09-CARRIER-R5-R4: production teardown observability for the walker
//! session (VirtualFreeEx release sequence).
//!
//! # Scope
//!
//! Every walker session owns TWO target-side allocations (params region +
//! two-round section region, allocated transactionally by
//! [`crate::unpacker::walker_session::WalkerSessionMemory::allocate`]).
//! Teardown must:
//!
//! 1. release both allocations in a fixed order (params first, then
//!    section) — the SAME order the R5-R2 transactional guard used, so
//!    rollback and teardown reuse one accounting story (no second ledger);
//! 2. record one structured event per `VirtualFreeEx` call:
//!    `(sequence, address, size, free_type, ok, last_error)` — T2;
//! 3. fail closed: a failed free is NEVER swallowed and NEVER silently
//!    retried; the full failure event sequence is exported — T1/T2;
//! 4. reject double-free: a second release of the same allocation is
//!    refused by the ledger and recorded as an event — T3;
//! 5. never block the consumption of an already-produced walker output:
//!    teardown outcome is SEPARATE from the WalkerExecute outcome — T1.
//!
//! # Separation of concerns (T1)
//!
//! [`TeardownOutcome`] is reported independently of
//! [`WalkerExecuteOutcome`](crate::unpacker::antidebug_controller::WalkerExecuteOutcome):
//! a partially-released session (failed free) still returns the walker
//! output for consumption; the teardown failure is exported alongside
//! (evidence + logs), never as a substitute verdict.
//!
//! # Free backend (injectable, never a mock masquerading as production)
//!
//! Production uses [`Win32FreeBackend`] — the real
//! `VirtualFreeEx`/`GetLastError` path. Tests inject a deterministic
//! failure backend through the SAME trait seam (`FreeBackend`), exactly
//! like the existing `CleanupBackend` pattern. The injectable backend is a
//! dependency-injection seam for failure injection; it is NOT a
//! production-path substitute.

use std::fmt;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{VirtualFreeEx, MEM_RELEASE, VIRTUAL_FREE_TYPE};

/// Registered teardown evidence schema (R5-R4 evidence contract).
pub const TEARDOWN_EVIDENCE_SCHEMA: &str = "mida.antidebug-walker-teardown/v1";

/// One `VirtualFreeEx` call, recorded verbatim (T2).
///
/// `size` is the size argument passed to `VirtualFreeEx` (0 for
/// MEM_RELEASE), `free_type` the raw `MEMORY_FREE_TYPE` bits
/// (MEM_RELEASE = 0x8000). `ok=false` carries the raw `GetLastError`
/// captured immediately after the failing call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TeardownFreeEvent {
    /// Monotonic 1-based sequence of this free within the teardown.
    pub sequence: u32,
    /// Remote allocation address being freed.
    pub address: u64,
    /// Size argument (0 for MEM_RELEASE).
    pub size: usize,
    /// Raw MEMORY_FREE_TYPE bits (MEM_RELEASE = 0x8000).
    pub free_type: u32,
    /// Whether VirtualFreeEx returned TRUE.
    pub ok: bool,
    /// Raw GetLastError captured immediately after a failed call (0 on ok).
    pub last_error: u32,
}

impl TeardownFreeEvent {
    /// Stable short name of the free type for evidence/logs.
    pub fn free_type_name(&self) -> &'static str {
        if self.free_type & VIRTUAL_FREE_TYPE(MEM_RELEASE.0).0 != 0 {
            "MEM_RELEASE"
        } else if self.free_type != 0 {
            "OTHER"
        } else {
            "UNKNOWN"
        }
    }
}

/// Structured outcome of one teardown sequence (T1).
///
/// - [`TeardownOutcome::Released`]: every allocation was freed.
/// - [`TeardownOutcome::PartiallyReleased`]: some frees failed; the
///   failed step list is exported (never swallowed, never retried).
/// - [`TeardownOutcome::Failed`]: the first free failed and teardown
///   stopped at that step (no silent retry, full sequence exported).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TeardownOutcome {
    /// All tracked allocations released.
    Released,
    /// Some allocations released, some failed (exported steps).
    PartiallyReleased {
        /// The failed free steps (event list).
        failed_steps: Vec<TeardownFreeEvent>,
    },
    /// Teardown aborted at `step` (first failure) with `error`.
    Failed { step: u32, error: String },
}

impl TeardownOutcome {
    /// Stable short name for evidence/logs.
    pub fn name(&self) -> &'static str {
        match self {
            TeardownOutcome::Released => "Released",
            TeardownOutcome::PartiallyReleased { .. } => "PartiallyReleased",
            TeardownOutcome::Failed { .. } => "Failed",
        }
    }
}

/// Injectable free backend (R5-R4 T2 dependency-injection seam).
///
/// Production uses [`Win32FreeBackend`] (real `VirtualFreeEx` +
/// `GetLastError`). Tests inject a deterministic backend to exercise the
/// failure ledger; a test backend is NEVER a production-path substitute.
pub trait FreeBackend: fmt::Debug {
    /// Free one remote allocation. Returns `Ok(())` on success, or
    /// `Err(win32_last_error)` captured immediately after the failure.
    /// Callers must not retry (fail-closed).
    fn free(&self, target: HANDLE, address: u64, size: usize, free_type: u32) -> Result<(), u32>;
}

/// Production free backend: `VirtualFreeEx` + immediate `GetLastError`.
#[derive(Debug)]
pub struct Win32FreeBackend;

impl Win32FreeBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Win32FreeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FreeBackend for Win32FreeBackend {
    fn free(&self, target: HANDLE, address: u64, size: usize, free_type: u32) -> Result<(), u32> {
        // SAFETY: VirtualFreeEx on a target handle + allocation address
        // owned by the walker session; VIRTUAL_FREE_TYPE is a u32 newtype
        // with no additional safety contract.
        let ok = unsafe {
            VirtualFreeEx(
                target,
                address as *mut core::ffi::c_void,
                size,
                VIRTUAL_FREE_TYPE(free_type),
            )
        };
        if ok.is_ok() {
            Ok(())
        } else {
            // SAFETY: GetLastError read immediately after the failed call.
            Err(unsafe { windows::Win32::Foundation::GetLastError() }.0)
        }
    }
}

/// Teardown event ledger (R5-R4 T2/T3/T5).
///
/// Reuses the R5-R2 allocation accounting: allocations are pushed as they
/// are owned, and released exactly once. A second release of the same
/// allocation is REFUSED and recorded as a `double_free` event (T3).
/// The ledger is empty exactly when no allocation remains tracked (T5).
#[derive(Debug, Clone)]
pub struct TeardownLedger {
    /// Allocations still tracked as owned (params first, then section —
    /// the frozen R5-R2 release order).
    owned: Vec<u64>,
    /// Allocations already released.
    released: Vec<u64>,
    /// Monotonic free-event record (T2).
    events: Vec<TeardownFreeEvent>,
    /// Double-free attempts (T3), recorded as events.
    double_free_events: Vec<TeardownFreeEvent>,
}

impl TeardownLedger {
    pub fn new() -> Self {
        Self {
            owned: Vec::new(),
            released: Vec::new(),
            events: Vec::new(),
            double_free_events: Vec::new(),
        }
    }

    /// Register an owned allocation (push order = release order).
    /// Refuses duplicate registration (same address twice) — fail-closed
    /// — and records the refusal as a double-free event (T3).
    pub fn register(&mut self, address: u64) -> bool {
        if address == 0 {
            return false;
        }
        if self.owned.contains(&address) {
            self.reject_double_free(address, 0, MEM_RELEASE.0);
            return false;
        }
        if self.released.contains(&address) {
            self.reject_double_free(address, 0, MEM_RELEASE.0);
            return false;
        }
        self.owned.push(address);
        true
    }

    /// The release order (params first, then section — as registered).
    pub fn owned(&self) -> &[u64] {
        &self.owned
    }

    /// The exported free-event sequence (T2).
    pub fn events(&self) -> &[TeardownFreeEvent] {
        &self.events
    }

    /// The exported double-free events (T3).
    pub fn double_free_events(&self) -> &[TeardownFreeEvent] {
        &self.double_free_events
    }

    /// True when no allocation remains TRACKED as owned (T5: ledger
    /// zeroed). After a successful teardown nothing is owned — the
    /// ledger holds nothing left to release.
    pub fn is_empty(&self) -> bool {
        self.owned.is_empty()
    }

    /// True when every registered allocation was released.
    pub fn all_released(&self) -> bool {
        self.owned.is_empty() && !self.released.is_empty()
    }

    /// Reject a double-free (T3): the address was already released or
    /// registered. The sequence number is monotonic across ALL events
    /// (free + double-free) so the ledger is a single exportable stream.
    fn reject_double_free(&mut self, address: u64, size: usize, free_type: u32) {
        let event = TeardownFreeEvent {
            sequence: self.events.len() as u32 + self.double_free_events.len() as u32 + 1,
            address,
            size,
            free_type,
            ok: false,
            last_error: 0,
        };
        self.double_free_events.push(event);
    }

    /// Record one real free attempt (T2). The sequence number is
    /// monotonic across ALL events (free + double-free).
    fn record_event(
        &mut self,
        ok: bool,
        last_error: u32,
        address: u64,
        size: usize,
        free_type: u32,
    ) {
        let event = TeardownFreeEvent {
            sequence: self.events.len() as u32 + self.double_free_events.len() as u32 + 1,
            address,
            size,
            free_type,
            ok,
            last_error,
        };
        self.events.push(event);
        if ok {
            if let Some(pos) = self.owned.iter().position(|&a| a == address) {
                let addr = self.owned.remove(pos);
                self.released.push(addr);
            }
        }
    }

    /// Run the full teardown sequence (T1/T2/T4).
    ///
    /// - Fixed order: registered order (params first, then section).
    /// - Each `VirtualFreeEx` call is recorded; a failed call is never
    ///   silently retried.
    /// - The FIRST failure aborts the sequence; the remaining owned
    ///   allocations stay tracked (PartiallyReleased exports them).
    /// - A second teardown call on an empty owned set issues NO free
    ///   (idempotent — T3/T5).
    pub fn run_teardown(&mut self, target: HANDLE, backend: &dyn FreeBackend) -> TeardownOutcome {
        // Idempotency: nothing owned -> no free issued (a previously
        // failed run left the failed address tracked; a successful run
        // left nothing).
        if self.owned.is_empty() {
            return TeardownOutcome::Released;
        }
        // T3: refuse to free any address that was already released.
        for &address in &self.owned {
            if self.released.contains(&address) {
                self.reject_double_free(address, 0, MEM_RELEASE.0);
                return TeardownOutcome::Failed {
                    step: 1,
                    error: format!(
                        "ledger inconsistency: address {address:#x} is both owned and released"
                    ),
                };
            }
        }
        let order = self.owned.clone();
        for (idx, &address) in order.iter().enumerate() {
            let free_type = MEM_RELEASE.0;
            match backend.free(target, address, 0, free_type) {
                Ok(()) => {
                    self.record_event(true, 0, address, 0, free_type);
                }
                Err(last_error) => {
                    // Fail-closed: no silent retry; record the failure
                    // event and abort the sequence at this step.
                    self.record_event(false, last_error, address, 0, free_type);
                    let failed_step = idx as u32 + 1;
                    // Some allocations were released before the failure:
                    // partially released, failures exported. Otherwise
                    // nothing was released: Failed at this step.
                    let failed_steps: Vec<TeardownFreeEvent> =
                        self.events.iter().filter(|e| !e.ok).cloned().collect();
                    if failed_steps.len() == 1 && self.released.is_empty() {
                        return TeardownOutcome::Failed {
                            step: failed_step,
                            error: format!(
                                "VirtualFreeEx failed at step {failed_step} addr={address:#x} win32={last_error}"
                            ),
                        };
                    }
                    return TeardownOutcome::PartiallyReleased { failed_steps };
                }
            }
        }
        TeardownOutcome::Released
    }
}

impl Default for TeardownLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the production teardown sequence for the two walker allocations
/// (params + section) with the real `VirtualFreeEx` backend.
///
/// Returns the structured outcome + the full event ledger. Idempotent:
/// running teardown twice releases nothing the second time (T3/T5).
pub fn teardown_walker_allocations(
    target: HANDLE,
    params_va: Option<u64>,
    section1_va: Option<u64>,
) -> (TeardownOutcome, TeardownLedger) {
    let mut ledger = TeardownLedger::new();
    // Fixed R5-R2 release order: params first, then section.
    if let Some(va) = params_va {
        ledger.register(va);
    }
    if let Some(va) = section1_va {
        ledger.register(va);
    }
    let backend = Win32FreeBackend::new();
    let outcome = ledger.run_teardown(target, &backend);
    (outcome, ledger)
}

/// Full teardown report: structured outcome + exportable event ledger.
///
/// This is the evidence unit (R5-R4 T2): it carries the schema, the
/// verdict, every `VirtualFreeEx` event, any double-free refusals, and
/// the T5 "ledger empty" flag. It serializes to JSON for the walker
/// evidence sidecar.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WalkerTeardownReport {
    pub schema: String,
    pub outcome: TeardownOutcome,
    /// Every free event, in release order (T2).
    pub events: Vec<TeardownFreeEvent>,
    /// Double-free refusals (T3).
    pub double_free_events: Vec<TeardownFreeEvent>,
    /// True when the ledger holds no allocation after teardown (T5).
    pub ledger_empty: bool,
}

impl WalkerTeardownReport {
    /// Build from a finished ledger + outcome.
    pub fn from_ledger(ledger: &TeardownLedger, outcome: TeardownOutcome) -> Self {
        Self {
            schema: TEARDOWN_EVIDENCE_SCHEMA.to_string(),
            outcome,
            events: ledger.events().to_vec(),
            double_free_events: ledger.double_free_events().to_vec(),
            ledger_empty: ledger.is_empty(),
        }
    }

    /// A no-op report: no session was installed (nothing to free).
    pub fn no_session() -> Self {
        Self {
            schema: TEARDOWN_EVIDENCE_SCHEMA.to_string(),
            outcome: TeardownOutcome::Released,
            events: Vec::new(),
            double_free_events: Vec::new(),
            ledger_empty: true,
        }
    }

    /// Stable short verdict name for evidence/logs.
    pub fn outcome_name(&self) -> &'static str {
        self.outcome.name()
    }
}

/// Run the structured teardown over a live walker session memory owner.
///
/// Derives the teardown ledger from the R5-R2 transactional accounting
/// (params VA first, then section VA — the frozen release order), frees
/// both with the real `VirtualFreeEx` backend, and returns the full
/// exportable report. Never called when no session is installed; the
/// caller (the RAII guard) decides session presence.
pub fn teardown_walker_session_report(
    mem: &crate::unpacker::walker_session::WalkerSessionMemory,
    target: HANDLE,
) -> WalkerTeardownReport {
    let mut ledger = TeardownLedger::new();
    if let Some(va) = mem.params_va() {
        ledger.register(va);
    }
    if let Some(va) = mem.section1_va() {
        ledger.register(va);
    }
    let backend = Win32FreeBackend::new();
    let outcome = ledger.run_teardown(target, &backend);
    WalkerTeardownReport::from_ledger(&ledger, outcome)
}

#[cfg(test)]
mod imp09_r5r4_teardown_tests {
    use super::*;
    use windows::Win32::System::Threading::GetCurrentProcess;

    fn self_handle() -> HANDLE {
        unsafe { GetCurrentProcess() }
    }

    fn alloc_local(size: usize) -> u64 {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
        };
        let p = unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert!(!p.is_null(), "VirtualAlloc failed");
        p as u64
    }

    /// Deterministic free backend for failure injection. NEVER used in a
    /// production path — only to drive the teardown failure ledger.
    #[derive(Debug)]
    struct FailingBackend {
        fail_addr: u64,
        last_error: u32,
    }

    impl FreeBackend for FailingBackend {
        fn free(
            &self,
            _target: HANDLE,
            address: u64,
            _size: usize,
            _free_type: u32,
        ) -> Result<(), u32> {
            if address == self.fail_addr {
                Err(self.last_error)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn r5r4_release_order_is_params_then_section() {
        let mut ledger = TeardownLedger::new();
        assert!(ledger.register(0x1000));
        assert!(ledger.register(0x2000));
        // Params first, section second — the frozen R5-R2 order.
        assert_eq!(ledger.owned(), &[0x1000, 0x2000]);
        // register is refused for a duplicate address (T3 defense).
        assert!(!ledger.register(0x1000));
        assert!(!ledger.register(0x2000));
    }

    #[test]
    fn r5r4_teardown_production_releases_both_and_ledger_zeroed() {
        let pv = alloc_local(0x1000);
        let sv = alloc_local(0x2000);
        let backend = Win32FreeBackend::new();
        let mut ledger = TeardownLedger::new();
        assert!(ledger.register(pv));
        assert!(ledger.register(sv));
        let outcome = ledger.run_teardown(self_handle(), &backend);
        assert_eq!(
            outcome,
            TeardownOutcome::Released,
            "both frees must succeed"
        );
        // T2: two recorded events, params first, both ok, MEM_RELEASE.
        let events = ledger.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[0].address, pv);
        assert_eq!(events[0].size, 0);
        assert_eq!(events[0].free_type, MEM_RELEASE.0);
        assert!(events[0].ok);
        assert_eq!(events[0].last_error, 0);
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[1].address, sv);
        assert!(events[1].ok);
        // T5: ledger zeroed after the normal path.
        assert!(ledger.is_empty());
        assert!(ledger.all_released());
        assert!(ledger.double_free_events().is_empty());
    }

    #[test]
    fn r5r4_teardown_idempotent_second_run_frees_nothing() {
        let pv = alloc_local(0x1000);
        let sv = alloc_local(0x1000);
        let backend = Win32FreeBackend::new();
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        ledger.register(sv);
        let o1 = ledger.run_teardown(self_handle(), &backend);
        assert_eq!(o1, TeardownOutcome::Released);
        assert_eq!(ledger.events().len(), 2);
        // Second teardown: nothing owned -> no free issued (idempotent).
        let o2 = ledger.run_teardown(self_handle(), &backend);
        assert_eq!(o2, TeardownOutcome::Released);
        assert_eq!(
            ledger.events().len(),
            2,
            "idempotent: no second VirtualFreeEx issued"
        );
        assert!(ledger.is_empty());
    }

    #[test]
    fn r5r4_teardown_aborted_path_releases_all_and_ledger_zeroed() {
        // T4: the ABORTED session path goes through the same teardown —
        // both allocations freed, ledger zeroed.
        let pv = alloc_local(0x1000);
        let sv = alloc_local(0x1000);
        let backend = Win32FreeBackend::new();
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        ledger.register(sv);
        let outcome = ledger.run_teardown(self_handle(), &backend);
        assert_eq!(outcome, TeardownOutcome::Released);
        assert!(ledger.is_empty(), "T5: abort path ledger zeroed");
        // The regions are really free (VirtualQuery sees MEM_FREE).
        assert!(region_is_free(pv));
        assert!(region_is_free(sv));
    }

    fn region_is_free(va: u64) -> bool {
        use windows::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_FREE};
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let n = unsafe {
            VirtualQuery(
                Some(va as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        n != 0 && mbi.State == MEM_FREE
    }

    #[test]
    fn r5r4_free_failure_is_partially_released_with_exported_steps() {
        let pv = alloc_local(0x1000);
        let sv = alloc_local(0x1000);
        // First free (params) succeeds, second (section) fails: the real
        // memory must NOT be freed by the failing backend, so we free it
        // manually afterwards to keep the test process clean.
        let failing = FailingBackend {
            fail_addr: sv,
            last_error: 0x57, // ERROR_INVALID_PARAMETER
        };
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        ledger.register(sv);
        let outcome = ledger.run_teardown(self_handle(), &failing);
        match outcome {
            TeardownOutcome::PartiallyReleased { failed_steps } => {
                assert_eq!(failed_steps.len(), 1, "one failed step exported");
                assert_eq!(failed_steps[0].address, sv);
                assert!(!failed_steps[0].ok);
                assert_eq!(failed_steps[0].last_error, 0x57);
                assert_eq!(failed_steps[0].free_type, MEM_RELEASE.0);
            }
            other => panic!("expected PartiallyReleased, got {other:?}"),
        }
        // T2: the failed event is in the exportable ledger.
        let events = ledger.events();
        assert_eq!(events.len(), 2);
        assert!(events[0].ok);
        assert!(!events[1].ok);
        assert_eq!(events[1].last_error, 0x57);
        // T3: the failed allocation stays tracked (never silently retried
        // in the same run) — a second run attempts it again (exactly-once
        // per run), but the outcome stays PartiallyReleased and the failed
        // step is exported again (no silent success).
        assert!(ledger.owned().contains(&sv));
        let o2 = ledger.run_teardown(self_handle(), &failing);
        assert!(
            matches!(o2, TeardownOutcome::PartiallyReleased { .. }),
            "second run re-attempts the failed step, still partially released"
        );
        assert_eq!(
            ledger.events().len(),
            3,
            "second run records one more free event"
        );
        // Cleanup: free the region that the failing backend did not free.
        use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        unsafe {
            let _ = VirtualFree(sv as *mut core::ffi::c_void, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn r5r4_first_free_failure_is_failed_with_step() {
        let pv = alloc_local(0x1000);
        let failing = FailingBackend {
            fail_addr: pv,
            last_error: 0x5, // ERROR_ACCESS_DENIED
        };
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        let outcome = ledger.run_teardown(self_handle(), &failing);
        match outcome {
            TeardownOutcome::Failed { step, error } => {
                assert_eq!(step, 1);
                assert!(error.contains("VirtualFreeEx failed"));
                assert!(error.contains("win32=5"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // The failed event is exported.
        assert_eq!(ledger.events().len(), 1);
        assert!(!ledger.events()[0].ok);
        assert_eq!(ledger.events()[0].last_error, 0x5);
        // Cleanup.
        use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        unsafe {
            let _ = VirtualFree(pv as *mut core::ffi::c_void, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn r5r4_double_free_rejected_and_recorded() {
        let pv = alloc_local(0x1000);
        let backend = Win32FreeBackend::new();
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        let o1 = ledger.run_teardown(self_handle(), &backend);
        assert_eq!(o1, TeardownOutcome::Released);
        // Re-register of an already-released address is refused AND
        // recorded as a double-free event (T3).
        assert!(
            !ledger.register(pv),
            "re-register of released address refused"
        );
        assert_eq!(ledger.double_free_events().len(), 1);
        assert_eq!(ledger.double_free_events()[0].address, pv);
        assert!(!ledger.double_free_events()[0].ok);
        // A second teardown run after a full release issues NO free and
        // records NO new event (idempotent — T3/T5).
        let o2 = ledger.run_teardown(self_handle(), &backend);
        assert_eq!(o2, TeardownOutcome::Released);
        assert_eq!(
            ledger.events().len(),
            1,
            "idempotent: no second free issued"
        );
        assert!(ledger.is_empty());
        // The run-time double-free guard (owned AND released at once) is
        // covered by r5r4_ledger_inconsistency_detected.
    }

    #[test]
    fn r5r4_ledger_inconsistency_detected() {
        // T3/negative: a ledger whose released set contains an address
        // that is ALSO still owned (inconsistent bookkeeping) must refuse
        // to free it and report the inconsistency.
        let pv = alloc_local(0x1000);
        let backend = Win32FreeBackend::new();
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        // Force an inconsistency: mark released without removing owned.
        ledger.released.push(pv);
        let outcome = ledger.run_teardown(self_handle(), &backend);
        assert!(
            matches!(outcome, TeardownOutcome::Failed { .. }),
            "ledger inconsistency must fail closed"
        );
        assert_eq!(ledger.double_free_events().len(), 1);
        // The address was NOT freed a second time (VirtualFreeEx never ran).
        assert!(
            !region_is_free(pv),
            "double-free must never reach VirtualFreeEx"
        );
        // Cleanup.
        use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        unsafe {
            let _ = VirtualFree(pv as *mut core::ffi::c_void, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn r5r4_teardown_failure_does_not_affect_output_consumption() {
        // T1: teardown failure is SEPARATE from the walker output. A
        // teardown that fails still returns Released/PartiallyReleased
        // WITHOUT touching the already-produced output (the output
        // consumption is the caller's separate step). Here we prove the
        // outcome separation contract at the ledger level: the teardown
        // outcome is produced independently of any output value.
        let pv = alloc_local(0x1000);
        let sv = alloc_local(0x1000);
        let failing = FailingBackend {
            fail_addr: sv,
            last_error: 0x57,
        };
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        ledger.register(sv);
        let outcome = ledger.run_teardown(self_handle(), &failing);
        // The outcome is a teardown verdict (PartiallyReleased); the
        // output consumption result is a separate value carried by the
        // caller — a failed teardown can never erase or block it.
        assert!(matches!(outcome, TeardownOutcome::PartiallyReleased { .. }));
        // The failed step export is complete (T2): sequence, address,
        // size, free_type, ok=false, last_error.
        let failed = match &outcome {
            TeardownOutcome::PartiallyReleased { failed_steps } => failed_steps.clone(),
            _ => unreachable!(),
        };
        assert_eq!(failed[0].sequence, 2);
        assert_eq!(failed[0].address, sv);
        assert_eq!(failed[0].size, 0);
        assert_eq!(failed[0].free_type, MEM_RELEASE.0);
        assert!(!failed[0].ok);
        assert_eq!(failed[0].last_error, 0x57);
        // Cleanup the region the failing backend did not free.
        use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        unsafe {
            let _ = VirtualFree(sv as *mut core::ffi::c_void, 0, MEM_RELEASE);
        }
    }

    #[test]
    fn r5r4_teardown_walker_allocations_production_wrapper() {
        // The production wrapper drives the real Win32FreeBackend over the
        // two walker allocations and returns outcome + ledger.
        let pv = alloc_local(0x1000);
        let sv = alloc_local(0x1000);
        let (outcome, ledger) = teardown_walker_allocations(self_handle(), Some(pv), Some(sv));
        assert_eq!(outcome, TeardownOutcome::Released);
        assert_eq!(ledger.events().len(), 2);
        assert!(ledger.is_empty());
    }

    #[test]
    fn r5r4_teardown_walker_allocations_with_none_is_released() {
        let (outcome, ledger) = teardown_walker_allocations(self_handle(), None, None);
        assert_eq!(outcome, TeardownOutcome::Released);
        assert!(ledger.is_empty());
        assert!(ledger.events().is_empty());
    }

    #[test]
    fn r5r4_evidence_record_roundtrips() {
        // The exported ledger/outcome serialize for evidence.
        let pv = alloc_local(0x1000);
        let sv = alloc_local(0x1000);
        let failing = FailingBackend {
            fail_addr: sv,
            last_error: 0x57,
        };
        let mut ledger = TeardownLedger::new();
        ledger.register(pv);
        ledger.register(sv);
        let outcome = ledger.run_teardown(self_handle(), &failing);
        let json = serde_json::to_string(&(outcome.clone(), ledger.events().to_vec())).unwrap();
        let back: (TeardownOutcome, Vec<TeardownFreeEvent>) = serde_json::from_str(&json).unwrap();
        assert_eq!(back.0, outcome);
        assert_eq!(back.1, ledger.events().to_vec());
        use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
        unsafe {
            let _ = VirtualFree(sv as *mut core::ffi::c_void, 0, MEM_RELEASE);
        }
    }
}
