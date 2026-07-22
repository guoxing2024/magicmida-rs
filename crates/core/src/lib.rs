//! # mida-core
//!
//! Debugger core: process creation, breakpoints, and the debug event loop.
//!
//! This crate provides the foundational types and traits for the Themida
//! unpacker. It contains no packer-specific logic — it is the generic
//! debugging layer that the `packers` crate builds on top of.

pub mod breakpoint;
pub mod cleanup;
pub mod debug_event_lifecycle;
pub mod debugger;
pub mod error;
pub mod process;
pub mod windows_debugger;

// Re-export commonly used types.
pub use breakpoint::{HwBreakpoint, HwbpType, SoftBpAction};
pub use cleanup::{cleanup_action, CleanupAction, CleanupReport, ProcessOwnership, WaitOutcome};
pub use debug_event_lifecycle::{
    classify_av_exc_type, ContinuePlan, DebugEventLifecycle, DecodeDisposition, PendingDebugEvent,
};
pub use debugger::{ContinueStatus, DebugEvent, DebuggerCore};
pub use error::{format_continue_debug_event_error, win32_from_hresult, CoreError};
pub use process::{
    cleanup_stub_exe, close_process_handles, create_debug_process, patch_peb_anti_debug,
    CreateProcessOptions, TargetProcess,
};
pub use windows_debugger::WindowsDebugger;
