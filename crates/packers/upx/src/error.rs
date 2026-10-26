//! Errors of the static unpacker.
//!
//! Every variant names the stage that produced it; a malformed file must
//! surface as an error, never as a panic — `/unpack` runs on untrusted input.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpxUnpackError {
    #[error("no valid PackHeader found")]
    NoPackHeader,

    #[error("compressed stream is truncated in the file")]
    StreamTruncated,

    #[error("{0}")]
    BadImage(&'static str),

    #[error("c_adler mismatch: header {expected:#010x}, stream {actual:#010x}")]
    CAdlerMismatch { expected: u32, actual: u32 },

    #[error("u_adler mismatch: header {expected:#010x}, decoded {actual:#010x}")]
    UAdlerMismatch { expected: u32, actual: u32 },

    #[error("decoded size {actual} != u_len {expected}")]
    DecodeLengthMismatch { expected: u32, actual: usize },

    #[error("unsupported compression method {0:#x}")]
    UnsupportedMethod(u8),

    #[error("unsupported filter id {0:#x}")]
    UnsupportedFilter(u8),

    #[error("nrv2b decode: {0}")]
    Nrv2b(&'static str),

    #[error("nrv2d decode: {0}")]
    Nrv2d(&'static str),

    #[error("nrv2e decode: {0}")]
    Nrv2e(&'static str),

    #[error("bitstream: {0}")]
    Bitstream(&'static str),

    #[error("lzma decode: {0}")]
    Lzma(String),

    #[error("relocs: {0}")]
    Reloc(&'static str),

    #[error("resource tree: {0}")]
    Resource(&'static str),
}
