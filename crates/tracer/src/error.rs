//! Error types for the single-step tracer.
//!
//! All errors are expressed as typed enum variants — no stringly-typed
//! errors. This gives callers a clear, matchable picture of what can go
//! wrong during a trace.

use thiserror::Error;

/// Errors that can occur during trace operations.
#[derive(Error, Debug)]
pub enum TracerError {
    /// The requested thread was not found in the debugger's thread table.
    #[error("thread {0} not found")]
    ThreadNotFound(u32),

    /// Unexpected exception during trace (breakpoint or access violation).
    #[error("unexpected trace break at {address:#x}: {kind}")]
    TraceBreak {
        /// Address where the unexpected exception occurred.
        address: u64,
        /// Categorization of the exception.
        kind: TraceBreakKind,
    },

    /// Target process exited during trace.
    #[error("target process exited during trace (code {exit_code})")]
    ProcessExited {
        /// The exit code of the target process.
        exit_code: u32,
    },

    /// Instruction limit reached during trace.
    #[error("instruction limit ({limit}) reached during trace")]
    LimitReached {
        /// The limit that was hit.
        limit: u64,
    },

    /// An error propagated from the debugger layer with context.
    #[error("debugger error at {context}: {source}")]
    Debugger {
        /// Underlying error source.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
        /// Context for where the error occurred.
        context: &'static str,
    },

    /// Internal invariant violation — a precondition that should be
    /// guaranteed by the calling contract was not met.
    #[error("internal error: {0}")]
    Internal(&'static str),
}

/// Categorization of the unexpected breakpoint that terminated a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceBreakKind {
    /// Hit an int3 breakpoint unexpectedly.
    UnexpectedBreakpoint,
    /// Hit an access violation unexpectedly.
    AccessViolation {
        /// The target address that was accessed.
        target_address: u64,
        /// `true` if the access was a write, `false` for a read.
        is_write: bool,
    },
}

impl std::fmt::Display for TraceBreakKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedBreakpoint => write!(f, "unexpected breakpoint"),
            Self::AccessViolation { target_address, is_write } => {
                let rw = if *is_write { "write" } else { "read" };
                write!(f, "access violation ({rw} at {target_address:#x})")
            }
        }
    }
}