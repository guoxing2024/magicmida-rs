//! # mida-core
//!
//! Debugger core: process creation, breakpoints, and the debug event loop.
//!
//! This crate provides the foundational types and traits for the Themida
//! unpacker. It contains no packer-specific logic — it is the generic
//! debugging layer that the `packers` crate builds on top of.
//!
//! R2 adds pure address newtypes ([`addr`]) so preferred ImageBase and ASLR
//! runtime base are not mixed as raw `u64`.

pub mod addr;
pub mod breakpoint;
pub mod cleanup;
pub mod debug_event_lifecycle;
pub mod debugger;
pub mod error;
pub mod plugin;
pub mod process;
pub mod runtime_engine;
pub mod windows_debugger;

// Re-export commonly used types.
pub use addr::{FileOffset, PreferredBase, RuntimeBase, Rva, Va};
pub use breakpoint::{HwBreakpoint, HwbpType, SoftBpAction};
pub use cleanup::{cleanup_action, CleanupAction, CleanupReport, ProcessOwnership, WaitOutcome};
pub use debug_event_lifecycle::{
    classify_av_exc_type, ContinuePlan, DebugEventLifecycle, DecodeDisposition, PendingDebugEvent,
};
pub use debugger::{ContinueStatus, DebugEvent, DebuggerCore};
pub use error::{format_continue_debug_event_error, win32_from_hresult, CoreError};
pub use plugin::{
    DumpAdvice, HostLoopFacts, IdentifyInput, IdentifyResult, NullPackerPlugin, PackerPlugin,
    PluginAdvice, PluginCtx, UnpackPhase,
};
pub use process::{
    cleanup_stub_exe, close_process_handles, create_debug_process, patch_peb_anti_debug,
    CreateProcessOptions, TargetProcess,
};
pub use runtime_engine::{
    guard_oep_event_script, DebuggerCoreEngine, EngineEvent, ReplayMemory, ReplayRuntimeEngine,
    RuntimeEngine,
};
pub use windows_debugger::WindowsDebugger;
