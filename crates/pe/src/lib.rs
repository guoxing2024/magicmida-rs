//! # mida-pe
//!
//! PE file parsing, section operations, and import table reconstruction.
//!
//! This crate handles reading the PE structure of target executables,
//! reconstructing the import address table, and applying post-unpack
//! fixups.  It provides its own types that wrap the underlying PE
//! structures —no `pelite` types are exposed in the public API.
//!
//! ## Modules
//!
//! - [`header`]   —PE header parsing ([`PeHeader`], DOS/NT/optional headers)
//! - [`section`]  —section table manipulation (create, delete, trim, sanitize)
//! - [`dumper`]   —import table reconstruction and process-dump to file
//! - [`import_table`] —import descriptor / thunk data structures
//! - [`apiset`]   —ApiSet name resolution (Windows 10/11)
//! - [`error`]    —error types
//! - [`utils`]    —alignment helpers and flag checks

pub mod apiset;
pub mod apiset_data;
pub mod byte_map;
pub mod dll_exports;
pub mod dumper;
pub mod error;
pub mod exception_final;
pub mod exception_observation;
pub mod exception_table;
pub mod export_table;
pub mod header;
pub mod iat_completeness;
pub mod import_table;
pub mod original_imports;
pub mod postprocess;
pub mod rebuild;
pub mod relocation;
pub mod relocation_observation;
pub mod section;
pub mod tls;
pub mod tls_observation;
pub mod utils;

// Re-export the primary types so callers can do `use mida_pe::PeHeader` etc.
pub use apiset::{get_apiset_module_by_api, is_apiset_dll, resolve_apiset, ApiSetMapping};
pub use byte_map::{
    directory_hints, exception_builder_from_map, plan_from_memory_image, rebuild_from_memory_image,
    relocations_from_map, section_bytes_from_map, slice_rva, ByteMapPlanOptions, ImageByteMap,
    MapDirectoryHints,
};
pub use dumper::sidecar_consumer::{
    build_old_table, cleanup_artifact, load_session_table, parse_session_table,
    serialize_session_table, CleanupStats, SessionTableEntry, SidecarError, HIGH_ASLR_MODULE_MIN,
};
pub use dumper::{
    address_owned_by_loaded_module, dump_dotnet_with_source, dump_process,
    dump_process_with_report, emit_pure_rebuild, emit_pure_rebuild_with_parity,
    evaluate_partial_accept, get_original_imports, is_dotnet, observe_encrypted_regions,
    plan_from_host_dump, rebuild_import_table, rebuild_import_table_with_report,
    shannon_entropy_bits, static_corroboration_candidate, ContainerRestoreMode, DumpCapturePolicy,
    DumpOptions, DumpProcessReport, DumpProfile, DumpProfileCapabilities, DumpTiming,
    EarlySectionSnapshot, EncryptedRegionObservation, ExperimentalStagePlan,
    IatPartialAcceptDecision, IatRejectedSlot, IatStaleSlot, IatStaticCorroboration, OepPolicy,
    PureRebuildEmitOptions, PureRebuildParitySnapshot, SectionContentReference,
    ENCRYPTED_REGION_ENTROPY_THRESHOLD, R2_SAMPLE_BYTES,
};
pub use error::PeError;
pub use exception_final::{
    compare_runtime_final, compare_runtime_final_shrink, ExceptionFinalDecoder,
    ExceptionFinalReport, ExceptionPreservationComparison,
};
pub use exception_observation::{
    observe_exception_runtime, ChainInfoObservation, ChainInfoStatus, ExceptionDirectoryStatus,
    ExceptionObservationReport, RuntimeFunctionObservation, RuntimeFunctionStatus,
    UnwindCodeObservation, UnwindCodeStatus, UnwindInfoObservation, UnwindInfoStatus,
    MAX_EXCEPTION_DIRECTORY_BYTES, UNWIND_INFO_HEADER_SIZE,
};
pub use exception_table::{
    minimal_x64_unwind_info, ExceptionTableBuilder, RuntimeFunction, RUNTIME_FUNCTION_SIZE,
};
pub use export_table::{ExportFunction, ExportTableBuilder, EXPORT_DIRECTORY_SIZE};
pub use header::{
    ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
    ImageSectionHeader, PeHeader, PeSection,
};
pub use iat_completeness::{
    IatRecoveryReport, IatResolutionSource, IatSlotReport, IatSlotStatus, IatUnresolvedReason,
};
pub use import_table::{ImportModule, ImportTableBuilder, ImportThunk};
pub use original_imports::{
    parse_final_import_identities, read_original_import_table, resolve_imports_via_getprocaddress,
    FinalImportIdentity,
};
pub use postprocess::{pack_tail_sections, postprocess_image, PostprocessOptions};
pub use rebuild::{
    rebuild_pe_image, rebuild_pe_image_with_meta, PlannedSection, RebuildPlan, RebuildResult,
    DIR_BASERELOC, DIR_EXCEPTION, DIR_EXPORT, DIR_IAT, DIR_IMPORT, DIR_TLS,
};
pub use relocation::RelocationTableBuilder;
pub use relocation_observation::{
    observe_relocations_runtime, RelocationObservationReport, RelocationTargetObservation,
    RelocationTargetStatus, IMAGE_DIRECTORY_ENTRY_BASERELOC,
};
pub use tls::{TlsDirectoryBuilder, TLS_DIRECTORY32_SIZE, TLS_DIRECTORY64_SIZE};
pub use tls_observation::{
    observe_tls_runtime, TlsCallbackObservation, TlsCallbackStatus, TlsObservationReport,
    IMAGE_DIRECTORY_ENTRY_TLS, MAX_TLS_CALLBACK_SLOTS,
};
pub use utils::{align_up, has_force_integrity, is_dll};
