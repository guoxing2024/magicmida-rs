//! # mida-tracer
//!
//! Single-step trace engine for following control flow through the packer's
//! obfuscated stubs.
//!
//! Works in concert with `mida-core` (for breakpoints and memory access) and
//! `mida-disasm` (for instruction decoding during trace analysis).
//!
//! ## Architecture note
//!
//! The trace loop defined in [`Tracer::trace`] **temporarily takes over the
//! debug event loop**. It calls [`DebuggerCore::wait_event`] and
//! [`DebuggerCore::continue_event`] directly for the duration of the trace,
//! filtering for `SingleStep` events on the target thread. Events from other
//! threads are transparently forwarded.

pub mod error;
pub mod tracer;

// Re-export the public API.
pub use error::TracerError;
pub use tracer::{TracePredicate, TraceResult, Tracer};

/// Log-message severity levels used by the tracer (and shared across the
/// packer crates).
///
/// Corresponds to `TLogMsgType` in the Pascal reference (`Utils.pas`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogMsgType {
    /// General informational message.
    Info,
    /// Positive / success message.
    Good,
    /// Fatal error — execution cannot continue.
    Fatal,
}
