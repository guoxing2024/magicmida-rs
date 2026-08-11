//! Core error types for the debugger engine.
//!
//! All errors produced by the core crate are represented by the [`CoreError`]
//! enum. This avoids stringly-typed error handling and gives callers a clear
//! picture of what can go wrong.

use thiserror::Error;

/// Errors that can occur during debugger operation.
#[derive(Error, Debug)]
pub enum CoreError {
    /// A Windows API call failed. Contains the raw error code from
    /// [`GetLastError`](windows::Win32::Foundation::GetLastError).
    #[error("Windows API error: code {0}")]
    Windows(u32),

    /// The target process could not be created.
    #[error("failed to create process: {0}")]
    ProcessCreation(String),

    /// A memory read from the target process failed.
    #[error("failed to read memory at {address:#x} (requested {requested} bytes)")]
    MemoryRead {
        /// Address in the target's virtual address space.
        address: u64,
        /// Number of bytes requested.
        requested: usize,
    },

    /// A memory write to the target process failed.
    #[error("failed to write memory at {address:#x} (requested {requested} bytes)")]
    MemoryWrite {
        /// Address in the target's virtual address space.
        address: u64,
        /// Number of bytes attempted to write.
        requested: usize,
    },

    /// All four hardware debug registers are already in use.
    #[error("hardware breakpoint limit exceeded (maximum 4)")]
    HwbpLimitExceeded,

    /// The requested hardware breakpoint slot (DR0–DR3) is already occupied.
    #[error("hardware breakpoint slot {0} is already in use")]
    HwbpSlotInUse(usize),

    /// A thread ID was not found in the debugger's thread table.
    #[error("thread {0} not found")]
    ThreadNotFound(u32),

    /// A non-error debug event was handled transparently.
    /// Signals the caller to skip this event and continue the debug loop.
    #[error("transparently handled event (continue debug loop)")]
    Handled,

    /// Debug event wait timed out.
    #[error("debug event wait timed out")]
    Timeout,

    /// Debug-event lifecycle state machine violation (no Win32 call made, or
    /// ContinueDebugEvent failed with full diagnostic context).
    ///
    /// Prefer this over bare [`CoreError::Windows`] when the failure involves
    /// pending-event identity, double-continue, TID mismatch, or
    /// `ContinueDebugEvent` parameter errors such as `ERROR_INVALID_PARAMETER`.
    #[error("{0}")]
    DebugState(String),

    /// A capture-epoch restore (unfreeze / rollback) could not resume one or more
    /// target threads. Carries the exact thread ids, the failing Win32 phase and
    /// each Win32 error code, so a leaked suspended thread is never swallowed.
    ///
    /// This is a hard fail-closed signal: the epoch may be partially restored and
    /// some threads may still be suspended.
    #[error(
        "capture epoch restore failed for {failed_count} thread(s); some may be left suspended: {failed:?}"
    )]
    CaptureEpochRestore {
        /// Number of threads whose restore failed (≥1).
        failed_count: usize,
        /// Per-thread restore-failure details (phase + Win32 code).
        failed: Vec<RestoreFailure>,
    },

    /// A capture-epoch freeze failed AND rolling back the already-suspended
    /// threads also failed (partial rollback itself failed). Combines the original
    /// freeze failure with the rollback failures so the caller learns both that
    /// freezing was aborted and that some threads may still be suspended.
    ///
    /// Exhaustive (fail-closed): this is returned whenever the rollback did NOT
    /// fully succeed — whether it produced structured per-thread failures
    /// (`rollback_failed`) or a generic restore error (`rollback_error`). It is
    /// NEVER treated as a successful rollback.
    #[error(
        "capture epoch freeze aborted: {freeze}; rollback ALSO failed (count={rollback_failed_count} structured + generic={rollback_error:?}), some may be left suspended: {rollback_failed:?}"
    )]
    CaptureFreezeWithRollbackFailure {
        /// The original freeze failure (message).
        freeze: String,
        /// Number of threads whose rollback-resume failed (≥1 when
        /// `rollback_failed` is non-empty).
        rollback_failed_count: usize,
        /// Per-thread rollback failure details (phase + Win32 code).
        rollback_failed: Vec<RestoreFailure>,
        /// A generic (non-per-thread) rollback restore error, when the rollback
        /// returned an error that was not a structured `CaptureEpochRestore`.
        /// `None` when the rollback failed structurally (or the rollback succeeded,
        /// in which case this error is not constructed at all).
        rollback_error: Option<String>,
    },
}

/// Details of one failed thread-restore (unfreeze or rollback-resume) step.
///
/// Every restore failure is surfaced with the target thread id, the exact Win32
/// phase that failed, and the Win32 error code, so a partial restore can never be
/// misreported as complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreFailure {
    /// The target thread id that could not be restored.
    pub thread_id: u32,
    /// The failing phase: `"open"` (`OpenThread`) or `"resume"` (`ResumeThread`).
    pub phase: &'static str,
    /// The Win32 error code from the failed call (`0` when a phase returned the
    /// invalid suspend count `0xFFFFFFFF` rather than a GetLastError code).
    pub win32_code: u32,
}

/// Format a `ContinueDebugEvent` failure with HRESULT, Win32 low-word, and
/// pending-event identity. Used so `ERROR_INVALID_PARAMETER` is never shown
/// only as the decimal HRESULT `2147942487`.
pub fn format_continue_debug_event_error(
    hresult: u32,
    pending_pid: u32,
    pending_tid: u32,
    pending_code: u32,
    provided_tid: u32,
    root_pid: u32,
    pending_still_set: bool,
) -> String {
    let win32 = hresult & 0xFFFF;
    format!(
        "ContinueDebugEvent failed: HRESULT=0x{hresult:08X} Win32={win32} \
         (ERROR_INVALID_PARAMETER=87 when Win32=87); \
         pending_pid={pending_pid} pending_tid={pending_tid} pending_code={pending_code} \
         provided_tid={provided_tid} root_pid={root_pid} pending_still_set={pending_still_set}"
    )
}

/// Extract the Win32 low-word error code from an HRESULT (HRESULT_FROM_WIN32).
#[inline]
pub fn win32_from_hresult(hresult: u32) -> u32 {
    hresult & 0xFFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hresult_0x80070057_parses_win32_87() {
        let hr = 0x8007_0057u32;
        assert_eq!(win32_from_hresult(hr), 87);
        // Same bit pattern as S3's decimal HRESULT display (2147942487).
        assert_eq!(win32_from_hresult(2_147_942_487), 87);
        let msg = format_continue_debug_event_error(hr, 17532, 12748, 1, 12748, 17532, true);
        assert!(msg.contains("HRESULT=0x80070057"));
        assert!(msg.contains("Win32=87"));
        assert!(msg.contains("pending_pid=17532"));
        assert!(msg.contains("pending_tid=12748"));
        assert!(msg.contains("provided_tid=12748"));
        assert!(msg.contains("root_pid=17532"));
        assert!(msg.contains("pending_still_set=true"));
    }
}
