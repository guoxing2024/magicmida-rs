//! PE dump and import table reconstruction.
//!
//! Corresponds to `Dumper.pas` `TDumper.Process` and `TDumper.DumpToFile`,
//! plus `TDumperDotnet.DumpToFile` for .NET assemblies.
//!
//! ## Architecture
//!
//! The dumper uses a **two-pass voting algorithm** to reconstruct the
//! import table from the live IAT in the target process:
//!
//! **Pass 1 — Collect candidates:**
//! For each slot in the IAT, read the resolved API address and find every
//! loaded module whose export table contains that address.  Forward exports
//! (where the export entry points to a string like `"NTDLL.RtlAllocateHeap"`)
//! are recursively resolved so the address of the *real* implementation is
//! also considered.
//!
//! **Pass 2 — Vote on best module:**
//! IAT slots are grouped by zero separators (matching the original pre-resolved
//! import table layout).  Within each group, every slot's candidates cast votes
//! for their module, and the module with the most votes wins.  Ties are broken
//! by a `PreferenceScore` (kernel32 > kernelbase, user32 > …, etc.).
//!
//! A new `.import` PE section is then constructed containing
//! `IMAGE_IMPORT_DESCRIPTOR` entries, the hint/name table, and the resolved IAT.

// Submodules
mod helpers;
mod types;
mod serialize;
mod remote_modules;
mod import_rebuild;
mod header_patch;
mod sections;
mod import_section;
mod output_writer;
mod dump_process;
mod original_imports;
#[cfg(test)]
mod tests;

// Re-export public API
pub use self::dump_process::{dump_dotnet, dump_process};
pub use self::helpers::is_dotnet;
pub use self::import_rebuild::rebuild_import_table;
pub use self::original_imports::get_original_imports;
pub use self::remote_modules::take_module_snapshot;
pub use self::types::{DumpOptions, RemoteModule};
