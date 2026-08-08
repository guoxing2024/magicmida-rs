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
mod capture_policy;
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
mod iat_gap_retarget;
mod import_rebuild;
mod import_section;
mod original_imports;
mod output_writer;
mod pure_rebuild_adapter;
mod raw_slab_coherence;
mod remote_modules;
mod runtime_bootstrap;
mod runtime_rebase;
mod sections;
mod serialize;
mod snapshot_manifest;
#[cfg(test)]
mod tests;
mod tls_bootstrap;
mod types;
mod wrapper_call_patch;
mod wrapper_materialize;
mod x64_asm;

// Re-export public API
pub use self::capture_policy::DumpCapturePolicy;
pub use self::dump_process::{
    dump_dotnet_with_source, dump_process, dump_process_with_report, write_bound_transform_manifest,
};
pub use self::helpers::is_dotnet;
pub use self::import_rebuild::{rebuild_import_table, rebuild_import_table_with_report};
pub use self::original_imports::get_original_imports;
pub use self::pure_rebuild_adapter::{
    emit_pure_rebuild, emit_pure_rebuild_with_parity, plan_from_host_dump, PureRebuildEmitOptions,
    PureRebuildParitySnapshot,
};
pub use self::remote_modules::take_module_snapshot;
pub use self::runtime_bootstrap::{
    build_runtime_bootstrap, decode_plan_metadata, encode_plan_metadata, simulate_runtime_rebase,
    BootFixup, BootMetadata, BootRegion, BootResolver, HeapBootstrapError, InstalledHeapBootstrap,
};
pub use self::runtime_rebase::{
    attribute_external, build_external_resolvers_from_imports, build_runtime_rebase_plan,
    declared_slots_from_capture, finalize_summary_after_install, prepare_runtime_rebase_for_dump,
    summarize_plan, validate_bootstrap_contract, validate_rebased_snapshots,
    validate_runtime_rebase_plan, DeclaredPointerSlot, ExternalAttribution, ExternalResolutionKind,
    ExternalResolverTable, ExternalTarget, PointerCandidate, PointerClassification,
    PreparedRuntimeRebase, RebaseError, RebaseRegion, RebaseStatus, RuntimeRebasePlan,
    RuntimeRebaseSummary, SlotProvenance,
};
pub use self::snapshot_manifest::manifest_path_for_output;
pub use self::types::{
    ContainerRestoreMode, DumpOptions, DumpProcessReport, DumpProfile, DumpProfileCapabilities,
    EarlySectionSnapshot, ExperimentalStagePlan, OepPolicy, RemoteModule,
};
