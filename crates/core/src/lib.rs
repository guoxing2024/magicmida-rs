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
pub mod adr7_b4_observer;
pub mod b4_runtime_offsets;
pub mod b5_tls_capture;
pub mod breakpoint;
pub mod capture_epoch;
pub mod cleanup;
pub mod debug_event_lifecycle;
pub mod debugger;
pub mod error;
pub mod plugin;
pub mod process;
pub mod runner_config;
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
pub use error::{format_continue_debug_event_error, win32_from_hresult, CoreError, RestoreFailure};
pub use plugin::{
    CapturePolicyHint, DumpAdvice, HostLoopFacts, IdentifyInput, IdentifyResult, NullPackerPlugin,
    OepProvenance, OepSource, PackerPlugin, PluginAdvice, PluginCtx, UnpackPhase,
};
pub use process::{
    cleanup_stub_exe, close_process_handles, create_debug_process, patch_peb_anti_debug,
    CreateProcessOptions, TargetProcess,
};
pub use runner_config::{
    canonical_runner_config, runner_config_digest, IsolationConfig, RunnerConfig,
};
pub use runtime_engine::{
    guard_oep_event_script, CapabilityOp, CapabilityRecord, DebuggerCoreEngine, EngineEvent,
    ReplayMemory, ReplayRuntimeEngine, RuntimeEngine, ThreadContextSnapshot,
};
pub use windows_debugger::{DrainDisposition, DrainReceipt, DrainStats, WindowsDebugger};
