//! # mida-packers-ahk-gto
//!
//! Second protection-family plugin (VNEXT-R4): AHK/GTO research path.
//!
//! R4-A0: identify + session defaults + event/milestone policy surface.
//! Dump heap/container stages remain gated by CLI
//! [`mida_pe::DumpProfile::AhkGtoExperimental`] — this crate does **not**
//! enable them from identify alone.
//!
//! Boundaries (architecture contract):
//! - Must not import `mida-acceptance` or set product verdicts.
//! - Must not auto-select experimental dump stages by filename/SHA.
//! - Oreans samples must not Match this plugin.

pub mod plugin;

pub use plugin::AhkGtoPlugin;
