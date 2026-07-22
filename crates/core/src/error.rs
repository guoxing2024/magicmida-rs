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
