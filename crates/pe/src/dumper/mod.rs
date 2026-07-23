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
mod container_bootstrap;
mod container_snapshot;
mod data_reinit;
mod data_snapshot;
mod dump_process;
mod global_vars;
mod header_patch;
mod heap_bootstrap;
mod heap_global_snapshot;
mod helpers;
mod import_rebuild;
mod import_section;
mod original_imports;
mod output_writer;
mod pure_rebuild_adapter;
mod remote_modules;
mod sections;
mod serialize;
#[cfg(test)]
mod tests;
mod tls_bootstrap;
mod types;
mod wrapper_call_patch;
mod wrapper_materialize;

// Re-export public API
pub use self::dump_process::{dump_dotnet, dump_process};
pub use self::helpers::is_dotnet;
pub use self::import_rebuild::rebuild_import_table;
pub use self::original_imports::get_original_imports;
pub use self::pure_rebuild_adapter::{
    emit_pure_rebuild, emit_pure_rebuild_with_parity, plan_from_host_dump,
    PureRebuildEmitOptions, PureRebuildParitySnapshot,
};
pub use self::remote_modules::take_module_snapshot;
pub use self::types::{
    ContainerRestoreMode, DumpOptions, DumpProfile, DumpProfileCapabilities, EarlySectionSnapshot,
    ExperimentalStagePlan, OepPolicy, RemoteModule,
};
