//! Shared types used across dumper submodules.
//!
//! Extracted from `dumper.rs`.

// -----------------------------------------------------------------------
// DumpOptions
// -----------------------------------------------------------------------

/// Options controlling the dump process.
#[derive(Debug, Clone)]
pub struct DumpOptions {
    /// Preferred load address of the target executable.
    pub image_base: u64,

    /// RVA of the original entry point.
    pub entry_point: u32,

    /// If `true`, reconstruct the import table from the live IAT.
    pub fix_imports: bool,

    /// If `true`, restore `.rdata`/`.data` sections from the target.
    pub create_data_sections: bool,

    /// If `true`, remove sections that are no longer needed (compression
    /// leftovers, Themida-specific sections).
    pub shrink: bool,

    /// Path where the dumped executable will be written.
    pub output_path: std::path::PathBuf,

    /// Optional IAT location override.  When `Some`, the dump uses this
    /// address and size instead of looking up the IAT data directory in
    /// the PE header.  This is needed for protectors (e.g. Themida) that
    /// strip or obfuscate the PE header's IAT directory.
    pub iat_location: Option<(usize, usize)>,

    /// Additional IAT locations (virtual addresses) referenced by code.
    /// These will be filled with the same Hint/Name RVAs as the primary IAT.
    /// Used to fix the "dual IAT" problem where code uses mov+call pattern.
    pub additional_iat_locations: Vec<usize>,

    /// Original (disk) path of the protected executable.  When present,
    /// the dumper reads the on-disk PE header to recover fields that may
    /// have been corrupted in-memory by the protector's VM exit
    /// (FileHeader.Characteristics, Subsystem, etc.).  Falls back to the
    /// in-memory header if the file is missing or unparseable.
    pub executable_path: Option<std::path::PathBuf>,
}

// -----------------------------------------------------------------------
// RemoteModule (for Pass 1)
// -----------------------------------------------------------------------

/// Information about a loaded module in the target process.
/// Corresponds to `TRemoteModule` in `Dumper.pas`.
#[derive(Debug, Clone)]
pub struct RemoteModule {
    /// Base address of the module in the target's virtual address space.
    pub(crate) base: u64,
    /// End of the module (`base + size`).
    pub(crate) end_off: u64,
    /// Module name (lowercase, e.g. `"kernel32.dll"`).
    pub(crate) name: String,
    /// Export table: address → function name (or `"#ordinal"`).
    pub(crate) exports: std::collections::HashMap<u64, String>,
    /// Forward entries: `"module.function"` → export address in this module.
    #[allow(dead_code)]
    pub(crate) forwards: Vec<(String, u64)>,
}

/// A candidate resolution for one IAT slot.
#[derive(Debug, Clone)]
pub(crate) struct ResolutionCandidate {
    /// The address in the target process that identifies the export.
    pub(crate) address: u64,
    /// Index into `all_modules` identifying which module owns this export.
    pub(crate) module_index: usize,
}

/// State for one IAT slot during reconstruction.
#[derive(Debug)]
pub(crate) struct IatSlot {
    /// All valid resolutions for this slot.
    pub(crate) candidates: Vec<ResolutionCandidate>,
    /// Index into `candidates` of the chosen resolution, or `None` if
    /// unresolved.
    pub(crate) chosen: Option<usize>,
    /// `true` if the slot value is zero (group separator).
    pub(crate) is_zero: bool,
}

// -----------------------------------------------------------------------
// is_api_address
// -----------------------------------------------------------------------

/// Check whether an address falls within a known module's export table.
///
/// Corresponds to `TDumper.IsAPIAddress` in `Dumper.pas`.
pub(crate) fn is_api_address(modules: &[RemoteModule], address: u64) -> bool {
    for m in modules {
        if address > m.base && address < m.end_off {
            return m.exports.contains_key(&address);
        }
    }
    false
}
