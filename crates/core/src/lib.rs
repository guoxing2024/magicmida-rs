//! # mida-core
//!
//! Debugger core: process creation, breakpoints, and the debug event loop.
//!
//! This crate provides the foundational types and traits for the Themida
//! unpacker. It contains no packer-specific logic — it is the generic
//! debugging layer that the `packers` crate builds on top of.

pub mod breakpoint;
pub mod debugger;
pub mod error;
pub mod process;
pub mod windows_debugger;

// Re-export commonly used types.
pub use breakpoint::{HwBreakpoint, HwbpType, SoftBpAction};
pub use debugger::{
    ctx_ip, ctx_sp, set_ctx_ip, set_ctx_sp, ContinueStatus, DebugEvent, DebuggerCore,
};
pub use error::CoreError;
pub use process::{
    cleanup_stub_exe, close_process_handles, create_debug_process, ensure_loader_host,
    patch_peb_anti_debug, sweep_stale_loader_hosts, CreateProcessOptions, TargetProcess,
};
pub use windows_debugger::WindowsDebugger;

/// Log-message severity levels used by the trace loops.
///
/// Corresponds to `TLogMsgType` in the Pascal reference (`Utils.pas`).
///
/// This lives here rather than in `mida-tracer` because every consumer
/// (`packers/themida`, `cli`) needs only this enum — not the `Tracer` engine,
/// which has no production call sites.  Keeping the enum in `core` removes a
/// whole crate dependency edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogMsgType {
    /// General informational message.
    Info,
    /// Positive / success message.
    Good,
    /// Fatal error — execution cannot continue.
    Fatal,
}
