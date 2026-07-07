//! Error types for the disasm crate.

use thiserror::Error;

/// Errors that can occur during pattern matching or disassembly.
#[derive(Debug, Error)]
pub enum DisasmError {
    /// The pattern string has invalid format (e.g. odd number of hex chars).
    #[error("invalid pattern format: {0}")]
    InvalidPattern(String),

    /// A hex byte in the pattern could not be parsed.
    #[error("invalid hex byte: {0}")]
    InvalidHex(String),

    /// The bitness value is not 16, 32, or 64.
    #[error("invalid bitness: {0} (must be 16, 32, or 64)")]
    InvalidBitness(u32),

    /// An error from the underlying disassembly engine.
    #[error("disassembly error: {0}")]
    Disasm(String),
}
