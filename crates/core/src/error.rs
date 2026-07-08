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
}
