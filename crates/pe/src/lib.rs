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

pub mod error;
pub mod header;
pub mod section;
pub mod utils;
pub mod import_table;
pub mod apiset;
pub mod apiset_data;
pub mod dumper;
pub mod original_imports;
pub mod relocation;

// Re-export the primary types so callers can do `use mida_pe::PeHeader` etc.
pub use error::PeError;
pub use header::{ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader, ImageSectionHeader, PeHeader, PeSection};
pub use original_imports::{read_original_import_table, resolve_imports_via_getprocaddress};
pub use utils::{align_up, has_force_integrity, is_dll};
pub use import_table::{ImportModule, ImportTableBuilder, ImportThunk};
pub use apiset::{ApiSetMapping, get_apiset_module_by_api, is_apiset_dll, resolve_apiset};
pub use dumper::{DumpOptions, dump_process, dump_dotnet, rebuild_import_table, get_original_imports, is_dotnet};
pub use relocation::RelocationTableBuilder;
