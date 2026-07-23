//! # mida-pe
//!
//! PE file parsing, section operations, and import table reconstruction.
//!
//! This crate handles reading the PE structure of target executables,
//! reconstructing the import address table, and applying post-unpack
//! fixups.  It provides its own types that wrap the underlying PE
//! structures — no `pelite` types are exposed in the public API.
//!
//! ## Modules
//!
//! - [`header`]   — PE header parsing ([`PeHeader`], DOS/NT/optional headers)
//! - [`section`]  — section table manipulation (create, delete, trim, sanitize)
//! - [`dumper`]   — import table reconstruction and process-dump to file
//! - [`import_table`] — import descriptor / thunk data structures
//! - [`apiset`]   — ApiSet name resolution (Windows 10/11)
//! - [`error`]    — error types
//! - [`utils`]    — alignment helpers and flag checks

pub mod apiset;
pub mod apiset_data;
pub mod byte_map;
pub mod dll_exports;
pub mod dumper;
pub mod error;
pub mod exception_table;
pub mod export_table;
pub mod header;
pub mod import_table;
pub mod original_imports;
pub mod postprocess;
pub mod rebuild;
pub mod relocation;
pub mod section;
pub mod tls;
pub mod utils;

// Re-export the primary types so callers can do `use mida_pe::PeHeader` etc.
pub use apiset::{get_apiset_module_by_api, is_apiset_dll, resolve_apiset, ApiSetMapping};
pub use byte_map::{
    directory_hints, exception_builder_from_map, plan_from_memory_image, rebuild_from_memory_image,
    relocations_from_map, section_bytes_from_map, slice_rva, ByteMapPlanOptions, ImageByteMap,
    MapDirectoryHints,
};
pub use dumper::{
    dump_dotnet, dump_process, emit_pure_rebuild, emit_pure_rebuild_with_parity,
    get_original_imports, is_dotnet, plan_from_host_dump, rebuild_import_table,
    ContainerRestoreMode, DumpOptions, DumpProfile, DumpProfileCapabilities, EarlySectionSnapshot,
    ExperimentalStagePlan, OepPolicy, PureRebuildEmitOptions, PureRebuildParitySnapshot,
};
pub use error::PeError;
pub use exception_table::{
    minimal_x64_unwind_info, ExceptionTableBuilder, RuntimeFunction, RUNTIME_FUNCTION_SIZE,
};
pub use export_table::{ExportFunction, ExportTableBuilder, EXPORT_DIRECTORY_SIZE};
pub use header::{
    ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
    ImageSectionHeader, PeHeader, PeSection,
};
pub use import_table::{ImportModule, ImportTableBuilder, ImportThunk};
pub use original_imports::{read_original_import_table, resolve_imports_via_getprocaddress};
pub use postprocess::{pack_tail_sections, postprocess_image, PostprocessOptions};
pub use rebuild::{
    rebuild_pe_image, rebuild_pe_image_with_meta, PlannedSection, RebuildPlan, RebuildResult,
    DIR_BASERELOC, DIR_EXCEPTION, DIR_EXPORT, DIR_IAT, DIR_IMPORT, DIR_TLS,
};
pub use relocation::RelocationTableBuilder;
pub use tls::{TlsDirectoryBuilder, TLS_DIRECTORY32_SIZE, TLS_DIRECTORY64_SIZE};
pub use utils::{align_up, has_force_integrity, is_dll};
