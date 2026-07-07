//! Error types for the Themida unpacker.
//!
//! All fallible operations in this crate return `Result<_, ThemidaError>`.

use crate::version::ThemidaVersion;

/// Errors specific to Themida detection and unpacking.
///
/// Implements [`From<mida_pe::PeError>`] so callers can use `?` when
/// calling PE parsing functions.
#[derive(Debug, thiserror::Error)]
pub enum ThemidaError {
    /// The binary does not appear to be protected by Themida.
    #[error("Not a Themida protected binary")]
    NotThemida,

    /// PE parsing failed. Delegates to `mida_pe::PeError`.
    #[error("PE parse error: {0}")]
    Pe(#[from] mida_pe::PeError),

    /// The identified Themida version is not (yet) supported for unpacking.
    #[error("Unsupported Themida version: {0:?}")]
    UnsupportedVersion(ThemidaVersion),

    /// The original entry point could not be detected or is ambiguous.
    #[error("OEP detection failed: {0}")]
    OepDetectionFailed(String),

    /// The Import Address Table was not found.
    #[error("IAT not found")]
    IatNotFound,

    /// ScyllaHide injection failed (binary not found, spawn error, …).
    #[error("ScyllaHide error: {0}")]
    ScyllaHide(String),

    /// A debugger-level error (process attach, memory read, thread control, …).
    #[error("Debugger error: {0}")]
    Debugger(String),

    /// A post-processing step failed (shrink, data sections, dump, anti-dump-fix).
    #[error("Post-process error: {0}")]
    PostProcess(String),

    /// Not enough space at the OEP to install the anti-dump stub.
    #[error("Space too small at OEP — needed {needed} bytes but only {available} available")]
    SpaceTooSmall {
        /// Number of bytes the stub requires.
        needed: usize,
        /// Number of bytes that were successfully written (`<= needed`).
        available: usize,
    },
}
