//! # mida-disasm
//!
//! Instruction disassembly and pattern-matching utilities built on `iced-x86`.
//!
//! Provides high-level abstractions for x86/x64 instruction decoding,
//! control-flow analysis, and the pattern-matching engine used by the
//! unpacker to recognise Themida stubs.

pub mod decoder;
pub mod error;
mod iat_scanner;
pub mod pattern;

// Re-export commonly used types.
pub use decoder::{is_indirect_call, is_indirect_jmp, Disassembler};
pub use error::DisasmError;
pub use iat_scanner::find_all_iat_references;
pub use pattern::{find_dynamic, find_static, BytePattern};
