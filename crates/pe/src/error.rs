//! Error types for the `mida-pe` crate.

use std::io;

/// Telemetry recorded by a [`with_capture_epoch`](crate::dumper::dump_process::with_capture_epoch)
/// run. When no epoch was begun (`epoch_begun == false`), the count/ids/elapsed/started
/// reflect "nothing frozen". Carried on error paths too so a failed live capture
/// still records which epoch it ran in (Route Z R0 AF2 AF1 AF5 / P1-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureEpochTelemetry {
    /// Whether the atomic capture epoch was actually begun (and ended).
    pub epoch_begun: bool,
    /// Number of target threads frozen (0 when no epoch).
    pub suspended_count: usize,
    /// Suspended thread ids (0/empty when no epoch).
    pub suspended_thread_ids: Vec<u32>,
    /// Epoch elapsed milliseconds (0 when no epoch).
    pub elapsed_ms: u128,
    /// Epoch start unix ms (0 when no epoch).
    pub started_ms: u64,
}

impl CaptureEpochTelemetry {
    /// Telemetry for a run with NO epoch (nothing frozen).
    pub fn none() -> Self {
        Self {
            epoch_begun: false,
            suspended_count: 0,
            suspended_thread_ids: Vec::new(),
            elapsed_ms: 0,
            started_ms: 0,
        }
    }
}

/// Errors that can occur during PE parsing and manipulation.
#[derive(Debug, thiserror::Error)]
pub enum PeError {
    /// The DOS signature ("MZ") is missing or invalid.
    #[error("Invalid DOS signature")]
    InvalidDosSignature,

    /// The PE signature ("PE\0\0") is missing or invalid.
    #[error("Invalid PE signature")]
    InvalidPeSignature,

    /// The section count in the file header is invalid (too large).
    #[error("Invalid section count: {0}")]
    InvalidSectionCount(u32),

    /// No section contains the given RVA.
    #[error("Section not found at RVA: {0:#x}")]
    SectionNotFound(u32),

    /// The requested file offset is outside any section's raw data range.
    #[error("Offset out of range: {0:#x}")]
    OffsetOutOfRange(u32),

    /// The requested RVA is outside any section's virtual range.
    #[error("RVA out of range: {0:#x}")]
    RvaOutOfRange(u32),

    /// An I/O error occurred while reading or writing.
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// A general PE parse error with a descriptive message.
    #[error("PE parse error: {0}")]
    Parse(String),

    /// A GTO/AHK stage-boundary failure with a stable machine-parseable stage
    /// id. Keeps the specific error text in ``error`` while adding a stable
    /// stage marker so a live-route failure is attributable to the exact
    /// pipeline stage. This is error-context only: it never changes recovery
    /// semantics or dump decisions.
    #[error("GTO_UNPACK_FAILED stage={stage} error={error}")]
    GtoStage {
        /// Stable pipeline stage id (e.g. ``runtime_rebase_plan_validation``).
        stage: String,
        /// Specific stage error text (root cause), preserving the chain.
        error: String,
    },

    /// The atomic capture epoch's live body AND its restore both failed. Preserves
    /// BOTH error texts so the caller learns that the capture aborted AND that
    /// some target threads may still be suspended, plus the epoch telemetry so the
    /// failed capture's epoch is still recorded (Route Z R0 AF2 AF1 AF4/AF5).
    #[error(
        "capture epoch body failed: {body}; AND restore failed: {restore} (epoch telemetry: {telemetry:?})"
    )]
    CaptureEpochCombined {
        /// The live capture body error.
        body: String,
        /// The epoch restore (unfreeze) error.
        restore: String,
        /// Epoch telemetry captured before the failure.
        telemetry: CaptureEpochTelemetry,
    },

    /// The atomic capture epoch's live body failed (restore succeeded). Carries the
    /// epoch telemetry so the failed capture's epoch is still recorded (P1-2).
    #[error("capture epoch body failed: {error} (epoch telemetry: {telemetry:?})")]
    CaptureEpochBodyFailed {
        /// The live capture body error.
        error: String,
        /// Epoch telemetry captured before the failure.
        telemetry: CaptureEpochTelemetry,
    },

    /// The atomic capture epoch's restore (unfreeze) failed. Carries the epoch
    /// telemetry so the failed restore's epoch is still recorded (P1-2).
    #[error("capture epoch restore failed: {error} (epoch telemetry: {telemetry:?})")]
    CaptureEpochRestoreFailed {
        /// The restore (unfreeze) error.
        error: String,
        /// Epoch telemetry captured before the failure.
        telemetry: CaptureEpochTelemetry,
    },

    /// The unknown or unsupported optional header magic.
    #[error("Unknown optional header magic: {0:#x}")]
    UnknownMagic(u16),

    /// The data buffer is too small to contain valid PE headers.
    #[error("Buffer too small: need at least {0} bytes, got {1}")]
    BufferTooSmall(usize, usize),

    /// A size field from PE headers or live process memory exceeds the
    /// allowed allocation cap (malformed / hostile input DoS guard).
    #[error("Size limit exceeded for {what}: requested {size} bytes (max {max})")]
    SizeLimit {
        /// Human-readable description of the allocation site.
        what: String,
        /// Requested size in bytes.
        size: usize,
        /// Configured maximum in bytes.
        max: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gto_stage_display_is_structured() {
        let e = PeError::GtoStage {
            stage: "runtime_rebase_plan_validation".into(),
            error: "RequiredPointerUnresolved: slot 3".into(),
        };
        let s = e.to_string();
        assert!(s.contains("GTO_UNPACK_FAILED"), "got: {s}");
        assert!(
            s.contains("stage=runtime_rebase_plan_validation"),
            "got: {s}"
        );
        assert!(s.contains("error=RequiredPointerUnresolved"), "got: {s}");
    }

    #[test]
    fn gto_stage_keeps_source_error_text() {
        let e = PeError::GtoStage {
            stage: "bootstrap_install".into(),
            error: "HeapBootstrapError::MissingImport(\"VirtualAlloc\")".into(),
        };
        let s = e.to_string();
        assert!(s.contains("stage=bootstrap_install"), "got: {s}");
        assert!(s.contains("VirtualAlloc"), "got: {s}");
    }

    #[test]
    fn gto_stage_is_nonzero_error_source() {
        let e = PeError::GtoStage {
            stage: "final_summary_not_complete".into(),
            error: "RebaseError::RequiredRuntimeCaptureMissing".into(),
        };
        // Implements std::error::Error (thiserror) -> usable in anyhow chains.
        let _: &dyn std::error::Error = &e;
        let s = format!("{:#}", e);
        assert!(s.contains("final_summary_not_complete"), "got: {s}");
    }
}
