//! Pure debug-event lifecycle state machine.
//!
//! Tracks the single pending Windows debug event that has been delivered by
//! `WaitForDebugEvent` but not yet resumed with `ContinueDebugEvent`.
//!
//! Extracted so unit tests can exercise the exactly-once continue contract
//! without launching a process or calling the Windows debug API.

use crate::error::{format_continue_debug_event_error, CoreError};

/// Identity of a debug event that is waiting for `ContinueDebugEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingDebugEvent {
    /// Process ID from the raw `DEBUG_EVENT` (`dwProcessId`).
    pub process_id: u32,
    /// Thread ID from the raw `DEBUG_EVENT` (`dwThreadId`).
    pub thread_id: u32,
    /// Raw `DEBUG_EVENT.dwDebugEventCode` value.
    pub debug_event_code: u32,
    /// Monotonic sequence assigned when the event is recorded.
    pub sequence: u64,
}

/// Whether an event should be continued internally before the next wait, or
/// returned to the outer debug loop for explicit handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeDisposition {
    /// Caller will handle the event and must call `continue_event` later.
    Deliver,
    /// Internally ignored (e.g. `OUTPUT_DEBUG_STRING`); lifecycle must
    /// `DBG_CONTINUE` exactly once on the pending identity before waiting again.
    IgnoreAndContinue,
    /// System-level RIP error; lifecycle continues once then surfaces a failure.
    RipError,
}

/// Outcome of validating a continue request against the pending event.
#[derive(Debug)]
pub enum ContinuePlan {
    /// Call `ContinueDebugEvent(pending_pid, pending_tid, status)` then clear.
    Proceed {
        /// PID from the pending event (must be used, not the root pid alone).
        process_id: u32,
        /// TID from the pending event (must match the provided TID).
        thread_id: u32,
    },
    /// Validation failed; no Win32 call should be made.
    Reject(CoreError),
}

/// Pure lifecycle controller: pending identity + sequence counter.
///
/// Does not call Windows APIs. The outer debugger injects continue/wait
/// operations based on the plans this type returns.
#[derive(Debug, Default)]
pub struct DebugEventLifecycle {
    pending: Option<PendingDebugEvent>,
    next_sequence: u64,
    /// Root process id for diagnostic messages (the debuggee created by us).
    root_pid: u32,
}

impl DebugEventLifecycle {
    /// Create a lifecycle bound to the debuggee root PID.
    pub fn new(root_pid: u32) -> Self {
        Self {
            pending: None,
            next_sequence: 1,
            root_pid,
        }
    }

    /// Root process ID used in diagnostics.
    pub fn root_pid(&self) -> u32 {
        self.root_pid
    }

    /// Current pending event, if any.
    pub fn pending(&self) -> Option<&PendingDebugEvent> {
        self.pending.as_ref()
    }

    /// `true` when an event has been waited but not yet continued.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Record a successful `WaitForDebugEvent` delivery.
    ///
    /// Must be called immediately after a successful wait, before decode
    /// or bookkeeping. Fails if a previous event is still pending.
    pub fn record_wait_success(
        &mut self,
        process_id: u32,
        thread_id: u32,
        debug_event_code: u32,
    ) -> Result<&PendingDebugEvent, CoreError> {
        if let Some(p) = self.pending {
            return Err(CoreError::DebugState(format!(
                "WaitForDebugEvent refused: pending event still set \
                 (pending_pid={} pending_tid={} pending_code={} seq={}; \
                 new_pid={process_id} new_tid={thread_id} new_code={debug_event_code})",
                p.process_id, p.thread_id, p.debug_event_code, p.sequence
            )));
        }
        let seq = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.pending = Some(PendingDebugEvent {
            process_id,
            thread_id,
            debug_event_code,
            sequence: seq,
        });
        Ok(self.pending.as_ref().expect("just inserted"))
    }

    /// Pre-check before calling `WaitForDebugEvent`.
    ///
    /// Returns `Err` when a pending event has not been continued yet.
    pub fn ensure_can_wait(&self) -> Result<(), CoreError> {
        if let Some(p) = self.pending {
            return Err(CoreError::DebugState(format!(
                "WaitForDebugEvent refused: pending event not continued \
                 (pending_pid={} pending_tid={} pending_code={} seq={})",
                p.process_id, p.thread_id, p.debug_event_code, p.sequence
            )));
        }
        Ok(())
    }

    /// Validate a `continue_event(provided_tid, ...)` request.
    ///
    /// TID mismatch and missing pending are rejected **before** any Win32 call.
    /// On `Proceed`, the caller must use `process_id`/`thread_id` from the plan
    /// (pending identity), then call [`Self::clear_pending_after_continue_ok`]
    /// only on success. On continue failure, leave pending set.
    pub fn plan_continue(&self, provided_tid: u32) -> ContinuePlan {
        let Some(p) = self.pending else {
            return ContinuePlan::Reject(CoreError::DebugState(format!(
                "continue_event refused: no pending debug event \
                 (provided_tid={provided_tid} root_pid={})",
                self.root_pid
            )));
        };
        if provided_tid != p.thread_id {
            return ContinuePlan::Reject(CoreError::DebugState(format!(
                "continue_event refused: TID mismatch before ContinueDebugEvent \
                 (provided_tid={provided_tid} pending_tid={} pending_pid={} \
                 pending_code={} seq={} root_pid={})",
                p.thread_id, p.process_id, p.debug_event_code, p.sequence, self.root_pid
            )));
        }
        ContinuePlan::Proceed {
            process_id: p.process_id,
            thread_id: p.thread_id,
        }
    }

    /// Clear pending after a successful `ContinueDebugEvent`.
    pub fn clear_pending_after_continue_ok(&mut self) {
        self.pending = None;
    }

    /// Build a diagnostic error for a failed `ContinueDebugEvent`.
    ///
    /// Pending is **retained** for diagnosis (exactly-once failure path).
    pub fn continue_failed_error(&self, hresult: u32, provided_tid: u32) -> CoreError {
        let (ppid, ptid, pcode) = match self.pending {
            Some(p) => (p.process_id, p.thread_id, p.debug_event_code),
            None => (0, 0, 0),
        };
        CoreError::DebugState(format_continue_debug_event_error(
            hresult,
            ppid,
            ptid,
            pcode,
            provided_tid,
            self.root_pid,
            self.pending.is_some(),
        ))
    }

    /// Classify a raw debug-event code for internal ignore/continue policy.
    pub fn disposition_for_event_code(code: u32) -> DecodeDisposition {
        // Windows DEBUG_EVENT codes (numeric, avoid coupling tests to the crate).
        // OUTPUT_DEBUG_STRING_EVENT = 8, RIP_EVENT = 9.
        match code {
            8 => DecodeDisposition::IgnoreAndContinue, // OUTPUT_DEBUG_STRING_EVENT
            9 => DecodeDisposition::RipError,          // RIP_EVENT
            // Known deliverable event codes:
            // EXCEPTION=1 CREATE_THREAD=2 CREATE_PROCESS=3 EXIT_THREAD=4
            // EXIT_PROCESS=5 LOAD_DLL=6 UNLOAD_DLL=7
            1..=7 => DecodeDisposition::Deliver,
            _ => DecodeDisposition::IgnoreAndContinue, // unknown → ignore + continue
        }
    }
}

// ---------------------------------------------------------------------------
// Access-type classification (exc_type) — pure helper for neutral logging
// ---------------------------------------------------------------------------

/// Human-readable access class from `EXCEPTION_ACCESS_VIOLATION`
/// `ExceptionInformation[0]` (`exc_type`).
///
/// - 0 = read
/// - 1 = write
/// - 8 = execute
/// - other = unknown
pub fn classify_av_exc_type(exc_type: u8) -> &'static str {
    match exc_type {
        0 => "read",
        1 => "write",
        8 => "execute",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::win32_from_hresult;

    #[test]
    fn pending_event_recorded_on_wait_success() {
        let mut lc = DebugEventLifecycle::new(1000);
        let p = lc
            .record_wait_success(1000, 2000, 1)
            .expect("record should succeed");
        assert_eq!(p.process_id, 1000);
        assert_eq!(p.thread_id, 2000);
        assert_eq!(p.debug_event_code, 1);
        assert_eq!(p.sequence, 1);
        assert!(lc.has_pending());
    }

    #[test]
    fn matching_tid_uses_pending_pid() {
        let mut lc = DebugEventLifecycle::new(1111);
        // Event from a different PID than root (defensive; Windows usually matches).
        lc.record_wait_success(2222, 3333, 1).unwrap();
        match lc.plan_continue(3333) {
            ContinuePlan::Proceed {
                process_id,
                thread_id,
            } => {
                assert_eq!(process_id, 2222, "must use pending PID, not root");
                assert_eq!(thread_id, 3333);
            }
            ContinuePlan::Reject(e) => panic!("expected Proceed, got {e}"),
        }
    }

    #[test]
    fn tid_mismatch_rejects_before_winapi() {
        let mut lc = DebugEventLifecycle::new(1000);
        lc.record_wait_success(1000, 50, 1).unwrap();
        match lc.plan_continue(99) {
            ContinuePlan::Reject(CoreError::DebugState(msg)) => {
                assert!(msg.contains("TID mismatch"), "msg={msg}");
                assert!(msg.contains("provided_tid=99"));
                assert!(msg.contains("pending_tid=50"));
            }
            other => panic!("expected Reject, got {other:?}"),
        }
        // Pending must still be set (no clear on reject).
        assert!(lc.has_pending());
    }

    #[test]
    fn continue_ok_clears_pending() {
        let mut lc = DebugEventLifecycle::new(1);
        lc.record_wait_success(1, 2, 1).unwrap();
        assert!(matches!(lc.plan_continue(2), ContinuePlan::Proceed { .. }));
        lc.clear_pending_after_continue_ok();
        assert!(!lc.has_pending());
    }

    #[test]
    fn continue_failure_retains_pending() {
        let mut lc = DebugEventLifecycle::new(17532);
        lc.record_wait_success(17532, 12748, 1).unwrap();
        let err = lc.continue_failed_error(0x8007_0057, 12748);
        assert!(lc.has_pending(), "failure must retain pending");
        match err {
            CoreError::DebugState(msg) => {
                assert!(msg.contains("0x80070057") || msg.contains("80070057"));
                assert!(msg.contains("Win32=87"));
                assert!(msg.contains("pending_tid=12748"));
                assert!(msg.contains("pending_still_set=true"));
            }
            other => panic!("expected DebugState, got {other:?}"),
        }
    }

    #[test]
    fn double_continue_rejected() {
        let mut lc = DebugEventLifecycle::new(1);
        lc.record_wait_success(1, 2, 1).unwrap();
        lc.clear_pending_after_continue_ok();
        match lc.plan_continue(2) {
            ContinuePlan::Reject(CoreError::DebugState(msg)) => {
                assert!(msg.contains("no pending"), "msg={msg}");
            }
            other => panic!("expected Reject for double continue, got {other:?}"),
        }
    }

    #[test]
    fn wait_while_pending_rejected() {
        let mut lc = DebugEventLifecycle::new(1);
        lc.record_wait_success(1, 2, 1).unwrap();
        let err = lc.ensure_can_wait().unwrap_err();
        match err {
            CoreError::DebugState(msg) => {
                assert!(msg.contains("pending event not continued"), "msg={msg}");
            }
            other => panic!("expected DebugState, got {other:?}"),
        }
        // Also record_wait_success must fail.
        assert!(lc.record_wait_success(1, 3, 1).is_err());
    }

    #[test]
    fn output_debug_string_is_ignore_and_continue() {
        assert_eq!(
            DebugEventLifecycle::disposition_for_event_code(8),
            DecodeDisposition::IgnoreAndContinue
        );
    }

    #[test]
    fn unknown_event_is_ignore_and_continue() {
        assert_eq!(
            DebugEventLifecycle::disposition_for_event_code(99),
            DecodeDisposition::IgnoreAndContinue
        );
    }

    #[test]
    fn ignored_event_exactly_once_continue_flow() {
        // Simulate: wait → record → plan continue → clear → wait ok again.
        let mut lc = DebugEventLifecycle::new(10);
        lc.record_wait_success(10, 20, 8).unwrap(); // OUTPUT_DEBUG_STRING
        assert_eq!(
            DebugEventLifecycle::disposition_for_event_code(8),
            DecodeDisposition::IgnoreAndContinue
        );
        match lc.plan_continue(20) {
            ContinuePlan::Proceed {
                process_id,
                thread_id,
            } => {
                assert_eq!(process_id, 10);
                assert_eq!(thread_id, 20);
            }
            ContinuePlan::Reject(e) => panic!("{e}"),
        }
        lc.clear_pending_after_continue_ok();
        assert!(lc.ensure_can_wait().is_ok());
        // Second ignored unknown event.
        lc.record_wait_success(10, 21, 99).unwrap();
        assert_eq!(
            DebugEventLifecycle::disposition_for_event_code(99),
            DecodeDisposition::IgnoreAndContinue
        );
        assert!(matches!(lc.plan_continue(21), ContinuePlan::Proceed { .. }));
        lc.clear_pending_after_continue_ok();
        assert!(!lc.has_pending());
    }

    #[test]
    fn hresult_0x80070057_maps_to_win32_87() {
        let hr: u32 = 0x8007_0057;
        assert_eq!(win32_from_hresult(hr), 87);
        // Decimal form of the HRESULT must not be the only representation.
        let msg = format_continue_debug_event_error(hr, 1, 2, 1, 2, 1, true);
        assert!(msg.contains("0x80070057") || msg.contains("80070057"));
        assert!(msg.contains("Win32=87"));
        assert!(!msg.contains("2147942487") || msg.contains("Win32=87"));
        // Pure Win32 low-word extraction for the S3 failure decimal form.
        let decimal: u32 = 2_147_942_487; // 0x80070057 as i32 reinterpreted unsigned
        assert_eq!(win32_from_hresult(decimal), 87);
    }

    #[test]
    fn exc_type_0_is_read_not_write() {
        assert_eq!(classify_av_exc_type(0), "read");
        assert_ne!(classify_av_exc_type(0), "write");
        assert_eq!(classify_av_exc_type(1), "write");
        assert_eq!(classify_av_exc_type(8), "execute");
    }

    #[test]
    fn rip_event_disposition() {
        assert_eq!(
            DebugEventLifecycle::disposition_for_event_code(9),
            DecodeDisposition::RipError
        );
    }
}
