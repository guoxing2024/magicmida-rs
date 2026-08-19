//! ADR7-B5 TLS scene capture (debugger-side, zero perturbation).
//!
//! B5 goal: isolate whether the runtime panic path (panic -> panic_count::
//! increase -> LOCAL_PANIC_COUNT TLS slot -> int29 fail-fast) fails because
//! of a TLS-context problem in the target, or because of the panic source
//! itself. This module defines the *data model*, *classification rules*, and
//! the *pure capture pipeline* (primitives injected as closures); the actual
//! reading of the target process happens in windows_debugger.rs (which owns
//! the process handle / read / query primitives) so the classification and
//! capture logic stays pure and unit-testable.
//!
//! Layout facts for the bound runtime (ADR7-B4 offset map, runtime
//! AE42901E..., verified via cdb symbols + dumpbin disassembly):
//! panic_count::increase (entry RVA 0x2eda0) reads its per-thread state from
//! the module TLS slot:
//!
//!     TEB + 0x58                    -> TLS array pointer (ThreadLocalStoragePointer)
//!     TLS array[ tls_index ]        -> module TLS slot pointer (rdx at 0x2edbf)
//!     slot + 0x18                   -> LOCAL_PANIC_COUNT counter (u64)
//!     slot + 0x20                   -> LOCAL_PANIC_COUNT in-panic flag (u8)
//!     _tls_index (RVA 0x575b4)      -> module TLS index (mov eax,[_tls_index]
//!                                      at 0x2edaa, verified via cdb symbol x)
//!
//! The fault site observed in the B4 active matrix (0xc0000005 @ 0x2edcf =
//! the counter increment) indicates the counter write faulted; the
//! classification below distinguishes WHY, using only debugger-side reads.

/// RVA of the module TLS index global (`_tls_index`) in the bound runtime.
pub const TLS_INDEX_RVA: u32 = 0x575b4;
/// TEB offset of the ThreadLocalStoragePointer (TLS array base).
pub const TLS_ARRAY_TEB_OFFSET: u64 = 0x58;
/// Offset of the LOCAL_PANIC_COUNT counter within the module TLS slot.
pub const LOCAL_PANIC_COUNT_COUNTER_OFFSET: u64 = 0x18;
/// Offset of the LOCAL_PANIC_COUNT in-panic flag within the module TLS slot.
pub const LOCAL_PANIC_COUNT_FLAG_OFFSET: u64 = 0x20;

/// Classification of the TLS scene at a captured moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsClassification {
    /// The thread has no TEB or the TLS array/slot pointer is null/absent.
    SlotAbsent,
    /// The slot pointer is non-null but the slot memory cannot be read at all.
    SlotInvalid,
    /// The slot memory reads, but the LOCAL_PANIC_COUNT fields
    /// (counter at +0x18 / flag at +0x20) are not readable -> pointer or
    /// layout corruption.
    CounterPointerCorrupted,
    /// The slot and its LOCAL_PANIC_COUNT fields are readable (and the page
    /// is writable per VirtualQueryEx): the TLS context itself is healthy.
    SlotWritable,
    /// The slot reads and the page is mapped but NOT writable: a write to
    /// the counter would fault even though reads succeed.
    SlotReadOnly,
    /// A capture-level error (open thread / query failed) -> no verdict.
    CaptureFailed,
}

impl TlsClassification {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SlotAbsent => "tls_slot_absent",
            Self::SlotInvalid => "tls_slot_invalid",
            Self::CounterPointerCorrupted => "local_panic_count_pointer_corrupted",
            Self::SlotWritable => "tls_slot_writable",
            Self::SlotReadOnly => "tls_slot_read_only",
            Self::CaptureFailed => "capture_failed",
        }
    }
}

/// One TLS scene snapshot (raw facts; classification derived).
#[derive(Debug, Clone)]
pub struct TlsSnapshot {
    /// Target thread id the snapshot belongs to.
    pub tid: u32,
    /// TEB base address (NtQueryInformationThread ThreadBasicInformation).
    pub teb_address: Option<u64>,
    /// ThreadLocalStoragePointer at TEB+0x58 (TLS array base).
    pub tls_array_base: Option<u64>,
    /// Module TLS index (`_tls_index` read from the runtime image).
    pub tls_index: Option<u32>,
    /// TLS slot pointer: TLS array[ tls_index ].
    pub tls_slot_pointer: Option<u64>,
    /// VirtualQueryEx state of the slot page (MEM_COMMIT etc., as u32).
    pub slot_page_state: Option<u32>,
    /// VirtualQueryEx protect of the slot page (PAGE_* flags, as u32).
    pub slot_page_protect: Option<u32>,
    /// LOCAL_PANIC_COUNT counter value at slot+0x18 (when readable).
    pub local_panic_count_counter: Option<u64>,
    /// LOCAL_PANIC_COUNT in-panic flag at slot+0x20 (when readable).
    pub local_panic_count_flag: Option<u8>,
    /// Derived classification.
    pub classification: TlsClassification,
    /// What triggered this capture: the exception code observed at the
    /// capture point (e.g. "0xc0000005", "0xc0000409") or "control" for a
    /// non-exception capture. F-B5-002: the trigger is recorded as observed,
    /// never inferred.
    pub capture_trigger: String,
    /// Which debug-event phase the capture happened in:
    /// "first_chance" | "second_chance" | "post_exception" | "control".
    /// A second-chance capture is a POST-FAULT snapshot and can never
    /// describe the pre-fault TLS state.
    pub capture_phase: String,
    /// First capture error (never fatal).
    pub capture_error: Option<String>,
}

impl TlsSnapshot {
    /// Classify from the raw facts (pure; unit-testable).
    ///
    /// F-B5-001 (ADR7-B5-TLS-ROOT-CAUSE-ISOLATION-1): ANY capture error makes
    /// the snapshot capture_failed — even when some fields (e.g. TEB) were
    /// read successfully. A snapshot with a capture error must NEVER produce
    /// an affirmative TLS classification (SlotAbsent / SlotInvalid /
    /// CounterPointerCorrupted / SlotWritable / SlotReadOnly are all TLS
    /// scene verdicts and are only valid when the full capture succeeded).
    pub fn classify(&mut self) {
        self.classification = if self.capture_error.is_some() {
            TlsClassification::CaptureFailed
        } else if self.teb_address.is_none()
            || self.tls_array_base == Some(0)
            || self.tls_slot_pointer == Some(0)
        {
            TlsClassification::SlotAbsent
        } else if self.tls_slot_pointer.is_none() {
            // Slot pointer could not be resolved (TLS array/index read failed).
            TlsClassification::SlotAbsent
        } else if self.local_panic_count_counter.is_none() || self.local_panic_count_flag.is_none()
        {
            // Slot reads but the LOCAL_PANIC_COUNT fields do not.
            TlsClassification::CounterPointerCorrupted
        } else {
            match self.slot_page_state {
                Some(s) if s == 0 => TlsClassification::SlotInvalid,
                Some(_) => {
                    let writeable = self
                        .slot_page_protect
                        .map(|p| {
                            // PAGE_READWRITE=0x04, PAGE_WRITECOPY=0x08,
                            // PAGE_EXECUTE_READWRITE=0x40,
                            // PAGE_EXECUTE_WRITECOPY=0x80.
                            p & 0x04 != 0 || p & 0x08 != 0 || p & 0x40 != 0 || p & 0x80 != 0
                        })
                        .unwrap_or(false);
                    if writeable {
                        TlsClassification::SlotWritable
                    } else {
                        TlsClassification::SlotReadOnly
                    }
                }
                None => TlsClassification::SlotWritable,
            }
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_when_null_slot() {
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(0),
            tls_slot_pointer: Some(0),
            slot_page_state: None,
            slot_page_protect: None,
            local_panic_count_counter: None,
            local_panic_count_flag: None,
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: None,
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::SlotAbsent);
    }

    #[test]
    fn writable_when_all_reads_ok() {
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(3),
            tls_slot_pointer: Some(0x3000),
            slot_page_state: Some(0x1000), // MEM_COMMIT
            slot_page_protect: Some(0x04), // PAGE_READWRITE
            local_panic_count_counter: Some(1),
            local_panic_count_flag: Some(0),
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: None,
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::SlotWritable);
    }

    #[test]
    fn readonly_when_protect_not_writeable() {
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(0),
            tls_slot_pointer: Some(0x3000),
            slot_page_state: Some(0x1000),
            slot_page_protect: Some(0x02), // PAGE_READONLY
            local_panic_count_counter: Some(0),
            local_panic_count_flag: Some(0),
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: None,
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::SlotReadOnly);
    }

    #[test]
    fn corrupted_when_counter_unreadable() {
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(0),
            tls_slot_pointer: Some(0x3000),
            slot_page_state: Some(0x1000),
            slot_page_protect: Some(0x04),
            local_panic_count_counter: None,
            local_panic_count_flag: None,
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: None,
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CounterPointerCorrupted);
    }

    #[test]
    fn capture_failed_when_error_and_no_teb() {
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: None,
            tls_array_base: None,
            tls_index: None,
            tls_slot_pointer: None,
            slot_page_state: None,
            slot_page_protect: None,
            local_panic_count_counter: None,
            local_panic_count_flag: None,
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: Some("open thread failed".into()),
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CaptureFailed);
    }

    // F-B5-001 regression tests: ANY capture error (even with most fields
    // read successfully) must classify CaptureFailed — a partial capture must
    // never produce an affirmative TLS scene verdict.

    #[test]
    fn capture_failed_when_teb_ok_but_tls_array_failed() {
        // TEB read OK, but the TLS array read failed => capture error present.
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: None,
            tls_index: None,
            tls_slot_pointer: None,
            slot_page_state: None,
            slot_page_protect: None,
            local_panic_count_counter: None,
            local_panic_count_flag: None,
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: Some("TLS array read failed".into()),
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CaptureFailed);
    }

    #[test]
    fn capture_failed_when_tls_index_read_failed() {
        // TEB + TLS array OK, but _tls_index read failed.
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: None,
            tls_slot_pointer: None,
            slot_page_state: None,
            slot_page_protect: None,
            local_panic_count_counter: None,
            local_panic_count_flag: None,
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: Some("_tls_index read: error".into()),
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CaptureFailed);
    }

    #[test]
    fn capture_failed_when_slot_read_failed() {
        // TEB/TLS array/index OK, but the slot pointer could not be read.
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(2),
            tls_slot_pointer: None,
            slot_page_state: None,
            slot_page_protect: None,
            local_panic_count_counter: None,
            local_panic_count_flag: None,
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: Some("TLS slot pointer read failed".into()),
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CaptureFailed);
    }

    #[test]
    fn capture_failed_when_counter_read_failed_with_teb_ok() {
        // Everything up to the counter read OK, then the counter read failed.
        // (Regression: old logic classified CounterPointerCorrupted here.)
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(2),
            tls_slot_pointer: Some(0x3000),
            slot_page_state: Some(0x1000),
            slot_page_protect: Some(0x04),
            local_panic_count_counter: None,
            local_panic_count_flag: Some(0),
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: Some("LOCAL_PANIC_COUNT counter unreadable".into()),
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CaptureFailed);
    }

    #[test]
    fn capture_failed_when_page_query_failed() {
        // All reads OK, but VirtualQueryEx failed => capture error present.
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(2),
            tls_slot_pointer: Some(0x3000),
            slot_page_state: None,
            slot_page_protect: None,
            local_panic_count_counter: Some(0),
            local_panic_count_flag: Some(0),
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: Some("VirtualQueryEx failed".into()),
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CaptureFailed);
    }

    #[test]
    fn capture_failed_when_flag_read_failed() {
        // Counter OK but flag read failed.
        let mut s = TlsSnapshot {
            tid: 1,
            teb_address: Some(0x1000),
            tls_array_base: Some(0x2000),
            tls_index: Some(2),
            tls_slot_pointer: Some(0x3000),
            slot_page_state: Some(0x1000),
            slot_page_protect: Some(0x04),
            local_panic_count_counter: Some(0),
            local_panic_count_flag: None,
            classification: TlsClassification::CaptureFailed,
            capture_trigger: "test".to_string(),
            capture_phase: "control".to_string(),
            capture_error: Some("LOCAL_PANIC_COUNT flag unreadable".into()),
        };
        s.classify();
        assert_eq!(s.classification, TlsClassification::CaptureFailed);
    }
}
