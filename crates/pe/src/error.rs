//! Error types for the `mida-pe` crate.

use std::io;

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

    /// The unknown or unsupported optional header magic.
    #[error("Unknown optional header magic: {0:#x}")]
    UnknownMagic(u16),

    /// The data buffer is too small to contain valid PE headers.
    #[error("Buffer too small: need at least {0} bytes, got {1}")]
    BufferTooSmall(usize, usize),
}
