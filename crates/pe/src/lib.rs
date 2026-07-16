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
pub mod dll_exports;
pub mod dumper;
pub mod error;
pub mod header;
pub mod import_table;
pub mod original_imports;
pub mod postprocess;
pub mod relocation;
pub mod section;
pub mod utils;

// Re-export the primary types so callers can do `use mida_pe::PeHeader` etc.
pub use apiset::{get_apiset_module_by_api, is_apiset_dll, resolve_apiset, ApiSetMapping};
pub use dumper::{
    dump_dotnet, dump_process, get_original_imports, is_dotnet, rebuild_import_table, DumpOptions,
    EarlySectionSnapshot,
};
pub use error::PeError;
pub use header::{
    ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
    ImageSectionHeader, PeHeader, PeSection,
};
pub use import_table::{ImportModule, ImportTableBuilder, ImportThunk};
pub use original_imports::{read_original_import_table, resolve_imports_via_getprocaddress};
pub use postprocess::{pack_tail_sections, postprocess_image, PostprocessOptions};
pub use relocation::RelocationTableBuilder;
pub use utils::{align_up, has_force_integrity, is_dll};
