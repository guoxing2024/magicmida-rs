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

use std::path::Path;

use tracing::{debug, info, warn};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS,
    PAGE_READONLY, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use crate::error::PeError;
use crate::header::PeHeader;
use crate::import_table::{ImportModule, ImportTableBuilder, ImportThunk, IMPORT_DESCRIPTOR_SIZE, IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64};
use crate::import_table::iat_slot_size;
use crate::original_imports::resolve_imports_via_getprocaddress;
use crate::original_imports::read_original_import_table;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of IAT slots to scan when determining IAT size.
/// Corresponds to `MAX_IAT_SIZE` in `Dumper.pas` (5120 * SizeOf(Pointer)).
const MAX_IAT_SLOTS: usize = 5120;

/// Maximum gap (in slots) between valid API addresses before we consider the
/// IAT to have ended.  Corresponds to the `$100` byte-gap in the Pascal code.
const MAX_GAP_SLOTS: usize = 0x100 / core::mem::size_of::<usize>();

/// Preference scores for module names (higher = preferred).
/// Corresponds to `PreferenceScore` and `ForwardPreferences` in `Dumper.pas`.
const FORWARD_PREFERENCES: &[&str] = &[
    "kernel32.dll",
    "ole32.dll",
    "advapi32.dll",
    "netapi32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "gdi32.dll",
    "dbghelp.dll",
    "setupapi.dll",
];

/// Data directory index for the COM descriptor (used for .NET detection).
const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

/// Data directory index for the import table.
const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

/// Data directory index for the IAT.
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

/// DLL characteristics flags
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
#[allow(dead_code)]
const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;

// ---------------------------------------------------------------------------
// DumpOptions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Remote module info (for Pass 1)
// ---------------------------------------------------------------------------

/// Information about a loaded module in the target process.
/// Corresponds to `TRemoteModule` in `Dumper.pas`.
#[derive(Debug, Clone)]
pub struct RemoteModule {
    /// Base address of the module in the target's virtual address space.
    base: u64,
    /// End of the module (`base + size`).
    end_off: u64,
    /// Module name (lowercase, e.g. `"kernel32.dll"`).
    name: String,
    /// Export table: address → function name (or `"#ordinal"`).
    exports: std::collections::HashMap<u64, String>,
    /// Forward entries: `"module.function"` → export address in this module.
    #[allow(dead_code)]
    forwards: Vec<(String, u64)>,
}

/// A candidate resolution for one IAT slot.
#[derive(Debug, Clone)]
struct ResolutionCandidate {
    /// The address in the target process that identifies the export.
    address: u64,
    /// Index into `all_modules` identifying which module owns this export.
    module_index: usize,
}

/// State for one IAT slot during reconstruction.
#[derive(Debug)]
struct IatSlot {
    /// All valid resolutions for this slot.
    candidates: Vec<ResolutionCandidate>,
    /// Index into `candidates` of the chosen resolution, or `None` if
    /// unresolved.
    chosen: Option<usize>,
    /// `true` if the slot value is zero (group separator).
    is_zero: bool,
}

// ---------------------------------------------------------------------------
// Helper: preference score
// ---------------------------------------------------------------------------

/// Return a preference score for a module name.
/// Higher = more preferred.  Zero for unrecognised names.
fn preference_score(name: &str) -> usize {
    for (i, pref) in FORWARD_PREFERENCES.iter().enumerate() {
        if name.eq_ignore_ascii_case(pref) {
            return FORWARD_PREFERENCES.len() - i;
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Helper: read pointer-sized value from a byte slice
// ---------------------------------------------------------------------------

/// Read a pointer-sized value from `data` at `offset`.
/// On x86_64 this is 8 bytes; on x86 this is 4 bytes.
#[inline]
fn read_ptr(data: &[u8], offset: usize, is_64bit: bool) -> u64 {
    if is_64bit {
        data.get(offset..offset + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    } else {
        data.get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .map(u64::from)
            .unwrap_or(0)
    }
}

/// Write a pointer-sized value into `data` at `offset`.
#[inline]
fn write_ptr(data: &mut [u8], offset: usize, value: u64, is_64bit: bool) {
    if is_64bit {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    } else {
        data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
}

// ---------------------------------------------------------------------------
// dump_process — top-level entry point
// ---------------------------------------------------------------------------

/// Dump a PE image from the target process into a file.
///
/// This is the Rust equivalent of `TDumper.DumpToFile` in `Dumper.pas`.
///
/// # Steps
///
/// 1. Read the PE headers from the target's image base.
/// 2. If `opts.fix_imports` is true, call [`rebuild_import_table`].
/// 3. Sanitize the PE header (`PointerToRawData = VirtualAddress`).
/// 4. Read the entire dump image from the target.
/// 5. Write the image + section data + updated headers to `opts.output_path`.
///
/// # Errors
///
/// Returns [`PeError::Parse`] if the PE headers in the target are corrupt,
/// or [`PeError::Io`] if the output file cannot be written.
pub fn dump_process(
    debugger: &mut dyn mida_core::DebuggerCore,
    opts: &DumpOptions,
) -> Result<(), PeError> {
    // 1. Read PE headers
    let mut header_buf = vec![0u8; 0x1000];
    let read = debugger
        .read_memory(opts.image_base as usize, &mut header_buf)
        .map_err(|e| PeError::Parse(format!("Failed to read PE headers: {e}")))?;
    if read < 0x1000 {
        return Err(PeError::Parse(format!(
            "Short read on PE headers: got {read} bytes, expected 4096"
        )));
    }

    let mut pe = PeHeader::from_bytes(&header_buf)?;

    // 0. Sanity-check PE header fields.  Protectors (e.g. Themida) may
    //    leave the in-memory and on-disk PE headers with invalid sentinel
    //    values for FileHeader.Characteristics (0) and Subsystem (0x4D).
    //    We patch these fields with minimum-valid values when the existing
    //    values fail basic validation:
    //      - Characteristics must have IMAGE_FILE_EXECUTABLE_IMAGE (0x2)
    //      - Subsystem must be one of the IMAGE_SUBSYSTEM_* constants that
    //        the loader recognises (2=GUI, 3=CUI, etc.)
    //      - DllCharacteristics should retain the original ASLR bit so we
    //        can strip it later in this function
    const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
    let valid_subsystems: [u16; 5] = [2, 3, 7, 9, 10];
    if pe.nt_headers.file_header.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE == 0 {
        pe.nt_headers.file_header.characteristics |= IMAGE_FILE_EXECUTABLE_IMAGE;
        debug!("patched FileHeader.Characteristics (missing EXECUTABLE_IMAGE)");
    }
    if !valid_subsystems.contains(&pe.nt_headers.optional_header.subsystem) {
        // Subsystem 2 (GUI) is the most common default for protected binaries.
        pe.nt_headers.optional_header.subsystem = 2;
        debug!("patched Subsystem (invalid value)");
    }
    if let Some(ref ep) = opts.executable_path {
        if let Ok(bytes) = std::fs::read(ep) {
            if let Ok(disk_pe) = PeHeader::from_bytes(&bytes) {
                // Merge disk values where they look valid.
                if disk_pe.nt_headers.file_header.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE != 0 {
                    pe.nt_headers.file_header.characteristics =
                        disk_pe.nt_headers.file_header.characteristics;
                }
                if valid_subsystems.contains(&disk_pe.nt_headers.optional_header.subsystem) {
                    pe.nt_headers.optional_header.subsystem =
                        disk_pe.nt_headers.optional_header.subsystem;
                }
                // Keep the runtime ImageBase (Magicmida strategy).
                // Themida leaves hardcoded runtime addresses in the unpacked code/data.
                // By keeping the runtime ImageBase and disabling ASLR, we maximize the
                // chance the program will load at the same address on subsequent runs.
                // Only clear DYNAMIC_BASE, keep other flags like HIGH_ENTROPY_VA.
                pe.nt_headers.optional_header.dll_characteristics &=
                    !IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

                info!(
                    "Keeping runtime ImageBase: {:#x} (ASLR disabled)",
                    pe.nt_headers.optional_header.image_base
                );
                info!("validated PE header fields");
            }
        }
    }

    let is_64bit = pe.is_64bit;

    // 2. Rebuild import table if requested
    let (iat_image, _iat_image_size, mut import_builder) = if opts.fix_imports {
        rebuild_import_table_complete(debugger, &mut pe, opts.image_base, is_64bit, opts.iat_location)?
    } else {
        (Vec::new(), 0usize, None)
    };

    // Determine the original IAT RVA — used later for Lookup Table placement.
    // This MUST be the location the application's code actually calls through,
    // which is the protector's IAT area identified by determine_iat_address
    // (not the original PE's .idata FirstThunk, which may be dead code).
    let original_iat_rva = if let Some((addr, _)) = opts.iat_location {
        u32::try_from(addr.wrapping_sub(opts.image_base as usize)).unwrap_or(0)
    } else {
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address
    };

    // 2b. Magicmida fallback: only use the original PE import table when the
    //     runtime IAT reconstruction produced nothing usable. The original
    //     import table typically only contains the handful of APIs the packer
    //     stub imports, which is insufficient for the real application.
    let mut _resolved_imports: std::collections::HashMap<(String, String), usize> = std::collections::HashMap::new();
    if opts.fix_imports {
        let live_empty = import_builder.as_ref().is_none_or(|b| b.thunk_count() == 0);
        if live_empty {
            if let Some(ref ep) = opts.executable_path {
                if let Some(fallback_builder) = build_import_table_from_original(&pe, ep) {
                    info!("Using original PE import table (Magicmida approach): {} modules, {} thunks",
                        fallback_builder.modules.len(), fallback_builder.thunk_count());
                    import_builder = Some(fallback_builder);
                }
            }
        }
    }

    // 2c. Build a function-name → resolved address map.
    //     For the live builder, read the resolved API addresses from the
    //     runtime IAT image returned by rebuild_import_table_complete.
    //     For the fallback builder, resolve via GetProcAddress from the
    //     original PE import table.
    if import_builder.is_some() {
        if let Some(ref builder) = import_builder {
            if !iat_image.is_empty() && original_iat_rva != 0 {
                // Live reconstruction: each thunk records its slot RVA in the
                // original IAT; read the resolved address from the runtime image.
                for m in &builder.modules {
                    for t in &m.thunks {
                        if let Some(ref name) = t.function_name {
                            let slot_offset = (t.iat_address as i64) - (original_iat_rva as i64);
                            if slot_offset >= 0 && (slot_offset as usize) + std::mem::size_of::<usize>() <= iat_image.len() {
                                let addr = usize::from_le_bytes(
                                    iat_image[slot_offset as usize..slot_offset as usize + std::mem::size_of::<usize>()]
                                        .try_into()
                                        .unwrap_or([0u8; std::mem::size_of::<usize>()]),
                                );
                                if addr != 0 {
                                    _resolved_imports.insert((m.name.clone(), name.clone()), addr);
                                }
                            }
                        }
                    }
                }
                info!("Resolved {} API addresses from live IAT image", _resolved_imports.len());
            } else if let Some(ref ep) = opts.executable_path {
                let imports = read_original_import_table(ep);
                _resolved_imports = resolve_imports_via_getprocaddress(&imports);
                info!("Resolved {} API addresses for IAT slots", _resolved_imports.len());
            }
        }
    }

    // 3. Sanitize PE header
    pe.sanitize();

    info!(
        size_of_image = pe.size_of_image(),
        "Dumping process image"
    );

    // 4. Read the full dump image (BEFORE creating .import section)
    let dump_size = pe.size_of_image() as usize;
    let mut dump_buf = vec![0u8; dump_size];
    make_memory_readable(debugger, opts.image_base, dump_size as u64);

    let read = debugger
        .read_memory(opts.image_base as usize, &mut dump_buf)
        .map_err(|e| PeError::Parse(format!("Failed to read dump image: {e}")))?;
    if read < dump_size {
        warn!(
            expected = dump_size,
            actual = read,
            "Short read on dump image"
        );
    }

    // 5. Build import section if we have a builder.
    //
    // The import builder's legacy "all-in-one" layout contains descriptors,
    // hint/name strings, AND an embedded IAT. We strip the embedded IAT from
    // the on-disk `.import` section and re-link descriptor FirstThunks at the
    // ORIGINAL IAT RVA the protector filled at OEP time. Thunk RVAs for that
    // area are collected into `import_thunks` for step 6g to write.
    let mut import_thunks: Vec<u64> = Vec::new();
    let mut import_section_idx: Option<usize> = None;
    if let Some(ref builder) = import_builder {
        let section_size_init = 3400u32;
        let section_idx = pe.create_section_index(".import", section_size_init);
        // NOTE: .import section does NOT need to be writable because:
        // - We use build_import_section_no_iat which puts descriptors + hint/name in .import
        // - FirstThunk points to the ORIGINAL IAT (at original_iat_rva, not in .import)
        // - Windows loader writes resolved addresses to the original IAT, not to .import section
        // - Making .import writable causes the program to crash (verified by byte comparison with Pascal)
        // const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;  // REMOVED - causes crash!
        // pe.sections[section_idx].characteristics |= IMAGE_SCN_MEM_WRITE;  // REMOVED
        // pe.sections[section_idx].header.characteristics = pe.sections[section_idx].characteristics;  // REMOVED
        debug!(
            "[create_section_index] section_idx={}: va={:#x} vs={:#x} ptr={:#x} raw_sz={:#x}",
            section_idx,
            pe.sections[section_idx].header.virtual_address,
            pe.sections[section_idx].header.virtual_size,
            pe.sections[section_idx].header.pointer_to_raw_data,
            pe.sections[section_idx].header.size_of_raw_data);
        let section_va = pe.sections[section_idx].virtual_address;
        debug!("[import_builder] local section_va={:#x}", section_va);

        //
        // Step 5b: use the new builder method that emits descriptors +
        //         hint/name strings (no embedded IAT) and a separate list
        //         of thunk slot values pointing back at the hint/name entries.
        //         Descriptor FirstThunks are linked at original_iat_rva.
        //
        let (section_data, thunks) =
            builder.build_import_section_no_iat(section_va, original_iat_rva);
        import_thunks = thunks;

        // Step 5c: Thunks (Hint/Name RVAs) will be written to the original IAT
        // location later. The Windows loader will resolve them to actual API
        // addresses at load time. We do NOT write resolved addresses here.

        let section_data_len = section_data.len();
        // PE spec: SizeOfRawData must be a multiple of FileAlignment
        // (minimum 0x200).  The Windows loader silently rejects sections
        // whose SizeOfRawData is not aligned — the resulting binary
        // crashes with 0xC0000005 at the first import call.
        let file_align = {
            let mut fa = pe.nt_headers.optional_header.file_alignment;
            if !fa.is_power_of_two() || fa < 0x200 { fa = 0x200; }
            fa
        };
        let raw_size = std::cmp::max(
            crate::utils::align_up(section_data_len as u32, file_align),
            0x2000, // Match Magicmida's alignment choice
        );
        pe.sections[section_idx].virtual_size = raw_size;
        pe.sections[section_idx].header.virtual_size = raw_size;
        pe.sections[section_idx].header.size_of_raw_data = raw_size;
        // Section count grew by 1 for the new import section; keep size_of_image consistent.
        let new_section_end = pe.sections[section_idx].header.virtual_address
            + pe.sections[section_idx].header.virtual_size;
        if (pe.nt_headers.optional_header.size_of_image) < new_section_end {
            pe.nt_headers.optional_header.size_of_image = new_section_end;
        }
        let mut padded_section_data = section_data;
        if (padded_section_data.len() as u32) < raw_size {
            padded_section_data.resize(raw_size as usize, 0);
        }
        pe.sections[section_idx].extra_data = Some(padded_section_data);
        // Re-scan size_of_image after sanitising existing sections.
        // (existing sanitise may import 0x272 from old virtual_size=virtual_address).

        // NOTE: Do NOT make IAT section writable. Magicmida keeps it READONLY.
        // Windows Loader will handle page protection as needed during import resolution.

        // Import Directory should only cover the descriptor array, not the
        // entire section. Each descriptor is 20 bytes. The null terminator
        // exists in the section but is not counted in the Data Directory size.
        let import_dir_size = builder.module_count() * 20;
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
            crate::header::ImageDataDirectory {
                virtual_address: section_va,
                size: import_dir_size as u32,
            };
        debug!("[import_data_dir] post-set IMPORT data_dir: va={:#x} sz={:#x}",
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address,
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].size);

        // Write the Import Lookup Table (Hint/Name RVAs) to the original
        // IAT region.  The PE loader uses the OriginalFirstThunk (in .import
        // descriptors) to find the hint/name entries and the FirstThunk to
        // find where to write resolved addresses.
        //
        // On PE32+, the IAT slots are u64.  The high 32 bits are sign-
        // extended for RVA values, so we write a full 64-bit value.
        //
        // IMPORTANT: Write directly to `dump_buf` first, then patch
        // `out_data` at the correct file offset after it's assembled.

        // Step 5b: Write Import Lookup Table (Hint/Name RVAs) to the
        // original IAT region at each thunk's specific IAT address.
        // This preserves the original IAT layout even when some slots are skipped.
        //
        // NOTE: We do NOT clear unidentified slots. They remain with their
        // original values from the dump, which may help Windows loader handle them.

        let ptr_size = std::mem::size_of::<usize>();
        let mut max_iat_rva = original_iat_rva;
        let mut thunk_idx = 0; // Index into import_thunks (includes nulls)

        for module in &builder.modules {
            let mut module_max_iat_rva = original_iat_rva;

            eprintln!("[DEBUG] Writing module '{}' with {} thunks",
                     module.name, module.thunks.len());

            for (ti, thunk) in module.thunks.iter().enumerate() {
                let iat_rva = thunk.iat_address;

                if ti < 3 || ti >= module.thunks.len().saturating_sub(3) {
                    eprintln!("[DEBUG]   Thunk {}: IAT RVA {:#x}", ti, iat_rva);
                }

                // Track the highest IAT address overall
                if iat_rva > max_iat_rva {
                    max_iat_rva = iat_rva;
                }

                // Track the highest IAT address in this module
                if iat_rva > module_max_iat_rva {
                    module_max_iat_rva = iat_rva;
                }

                let offset = iat_rva as usize;

                if offset + ptr_size <= dump_buf.len() {
                    // Determine the Hint/Name RVA or ordinal value to write
                    let value: u64 = if let Some(ord) = thunk.ordinal {
                        // Ordinal import
                        if thunk.is_64bit {
                            IMAGE_ORDINAL_FLAG64 | (ord as u64)
                        } else {
                            (IMAGE_ORDINAL_FLAG32 | (ord as u32)) as u64
                        }
                    } else if thunk_idx < import_thunks.len() {
                        import_thunks[thunk_idx]
                    } else {
                        0
                    };

                    if ptr_size == 8 {
                        let bytes = value.to_le_bytes();
                        dump_buf[offset..offset + 8].copy_from_slice(&bytes);
                    } else {
                        let bytes = (value as u32).to_le_bytes();
                        dump_buf[offset..offset + 4].copy_from_slice(&bytes);
                    }
                    thunk_idx += 1;
                }
            }

            // Write the null terminator for this module right after its last thunk
            if thunk_idx < import_thunks.len() && import_thunks[thunk_idx] == 0 {
                let null_rva = module_max_iat_rva + ptr_size as u32;
                let null_offset = null_rva as usize;

                eprintln!("[DEBUG] Writing null terminator at RVA {:#x} for module '{}'",
                         null_rva, module.name);

                if null_offset + ptr_size <= dump_buf.len() {
                    if ptr_size == 8 {
                        dump_buf[null_offset..null_offset + 8].fill(0);
                    } else {
                        dump_buf[null_offset..null_offset + 4].fill(0);
                    }

                    // Update overall max if this null is higher
                    if null_rva > max_iat_rva {
                        max_iat_rva = null_rva;
                    }
                }
                thunk_idx += 1;
            }
        }

        let lookup_iat_rva = original_iat_rva;
        info!(
            iat_rva = format_args!("{lookup_iat_rva:#x}"),
            thunks = thunk_idx,
            "Writing Import Lookup Table to IAT region"
        );

        // Calculate the IAT size based on the actual range from first to last thunk
        // (including any gaps), then add one slot to account for the last thunk itself
        let lookup_iat_size_bytes = (max_iat_rva - original_iat_rva) as usize + ptr_size;

        // Pascal Magicmida keeps IAT sections READ-ONLY.  The Windows PE loader handles
        // page-protection changes internally during import resolution, so we must not
        // add IMAGE_SCN_MEM_WRITE to match the reference output byte-for-byte.
        // (Previous sessions toggled this on and off; the definitive answer is: match Pascal.)
        //
        // The commented-out code below is preserved to document what was tried.
        //
        // for (idx, section) in pe.sections.iter_mut().enumerate() {
        //     let section_start = section.virtual_address;
        //     let section_end = section_start + section.virtual_size;
        //     if original_iat_rva >= section_start && original_iat_rva < section_end {
        //         const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
        //         section.characteristics |= IMAGE_SCN_MEM_WRITE;
        //         section.header.characteristics = section.characteristics;
        //         break;
        //     }
        // }

        // Also set the IAT directory to point to the ORIGINAL IAT region
        // (not the .import section).  The PE loader reads the Import
        // Descriptors from .import and writes resolved addresses into the
        // slots at original_iat_rva via FirstThunk.
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT] =
            crate::header::ImageDataDirectory {
                virtual_address: lookup_iat_rva,
                size: lookup_iat_size_bytes as u32,
            };

        info!(
            "Set IAT Directory to: RVA={:#x} size={:#x}",
            lookup_iat_rva,
            lookup_iat_size_bytes
        );

        import_section_idx = Some(section_idx);

        info!(
            section_va = format_args!("{section_va:#x}"),
            section_data_len = section_data_len,
            modules = builder.modules.len(),
            thunks = builder.thunk_count(),
            "Created .import section",
        );
        debug!(
            "[import_section] FINAL import section: va={:#x} vs={:#x} sz={:#x} ptr={:#x} data_dir_import[va={:#x} sz={:#x}]",
            pe.sections[section_idx].header.virtual_address,
            pe.sections[section_idx].header.virtual_size,
            pe.sections[section_idx].header.size_of_raw_data,
            pe.sections[section_idx].header.pointer_to_raw_data,
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address,
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].size);
    }

    // Migrate extra_section writes for the sections created by
    // rebuild_import_table_complete — they were already written above.
    let _initial_sections_in_header = if let Some(idx) = import_section_idx {
        idx + 1
    } else {
        pe.nt_headers.file_header.number_of_sections as usize
    };

    // 5. Trim huge sections in the dump buffer

    // 5. Trim huge sections in the dump buffer (only applies to sections
    // whose VirtualAddress is within the dump_buf range — extra_data sections
    // created by import-table rebuilding are passed through unchanged below).
    let mut iat_raw_addr = 0u32; // Unused if we already have the IAT image
    let delta = pe.trim_huge_sections(&dump_buf, &mut iat_raw_addr);

    // 6. Write output file.
    //
    // The dump buffer is a *memory* dump that starts at the target's image
    // base, i.e. dump_buf[0] is the in-memory DOS header and dump_buf[N] for
    // N > size_of_headers is the first byte of the first section's data as
    // the OS loader mapped it.  The output *file* layout, however, has its
    // own section table where each section points to a file offset
    // (PointerToRawData, which after sanitize() equals VirtualAddress).
    //
    // To produce a spec-conformant PE we therefore write:
    //   [0x00..0x80]          synthetic DOS header (0x80 bytes)
    //   [0x80..size_of_image] PE signature + NT headers + section table,
    //                          followed by padding up to the first section
    //   [ptr_to_raw..]        data of each section, positioned at the file
    //                          offset its section header claims.
    let out_path = &opts.output_path;
    let pe_offset = 0x80usize;
    let mut out_data = Vec::new();

    // 6a. Synthetic DOS header (0x80 bytes).  The PE signature is expected
    //     at offset 0x80 by the DOS stub's `e_lfanew` field.
    out_data.extend_from_slice(&create_dos_header());

    // 6b. Update header fields that must reflect the output file layout
    //     *before* we serialize: number of sections, entry point, ASLR.
    pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;
    pe.nt_headers.optional_header.address_of_entry_point = opts.entry_point;

    // Section permissions must match Pascal output byte-for-byte.
    // Do NOT add IMAGE_SCN_MEM_WRITE to IAT sections — Pascal keeps them READ-ONLY.
    // Windows Loader handles page protection internally during import resolution.

    // Keep the original ImageBase from the in-memory PE.
    // CRITICAL DECISION: Disable ASLR like Magicmida does!
    //
    // After extensive debugging, we found that:
    // 1. Magicmida disables DYNAMIC_BASE (DllCharacteristics = 0x0020)
    // 2. This means the program ALWAYS loads at the same ImageBase
    // 3. Absolute addresses in the dump remain valid
    // 4. No need for complete relocation table
    //
    // Our attempt to enable ASLR and generate full relocations failed because:
    // - We may have generated incorrect relocations
    // - Some addresses should NOT be relocated (e.g., runtime-generated values)
    // - Themida's complex structure makes it hard to distinguish
    //
    // So we follow Magicmida's approach: DISABLE ASLR
    pe.nt_headers.optional_header.dll_characteristics &= !IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    // 6c. Serialize NT headers + section table at offset 0x80.
    debug!(
        file_chars = %format!("{:#06x}", pe.nt_headers.file_header.characteristics),
        subsystem = %format!("{:#06x}", pe.nt_headers.optional_header.subsystem),
        nsec = pe.nt_headers.file_header.number_of_sections,
        iat_dir_rva = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address),
        iat_dir_size = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].size),
        "before serialize_headers",
    );
    let header_data = pe.serialize_headers()?;
    let header_len = header_data.len();
    let header_end = pe_offset + header_len;

    // DEBUG: Check what serialize_headers actually wrote
    let sec1_offset_in_header = 0x108 + 40; // sh_off + section_size
    let chars_offset_in_header = sec1_offset_in_header + 36;
    if chars_offset_in_header + 4 <= header_data.len() {
        let chars = u32::from_le_bytes([
            header_data[chars_offset_in_header],
            header_data[chars_offset_in_header + 1],
            header_data[chars_offset_in_header + 2],
            header_data[chars_offset_in_header + 3],
        ]);
        info!("serialize_headers buffer: Section 1 chars at {:#x} = {:#x}", chars_offset_in_header, chars);
    }

    debug!(
        header_out_chars = %format!("{:#06x}", u16::from_le_bytes([header_data[22], header_data[23]])),
        "after serialize_headers",
    );
    debug!(
        import_va = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address),
        import_sz = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].size),
        iat_va = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address),
        iat_sz = %format!("{:#x}", pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].size),
        "after serialize_headers: IMPORT/IAT data_dir",
    );
    debug!(
        "FULL data_directory: {}",
        (0..16).map(|i| format!("[{}]v={:#x}s={:#x}",
            i,
            pe.nt_headers.optional_header.data_directory[i].virtual_address,
            pe.nt_headers.optional_header.data_directory[i].size
        )).collect::<Vec<_>>().join(" "));

    // Determine the file offset of the first byte of section data.  This
    // is used to insert padding between the end of the headers and the
    // first section if the headers do not fill the gap (rare but legal).
    let first_section_ptr = pe
        .sections
        .iter()
        .filter(|s| s.header.size_of_raw_data > 0 && s.header.pointer_to_raw_data > 0)
        .map(|s| s.header.pointer_to_raw_data as usize)
        .min()
        .unwrap_or(header_end);
    let initial_len = std::cmp::max(header_end, first_section_ptr);
    out_data.resize(initial_len, 0);
    out_data[pe_offset..header_end].copy_from_slice(&header_data);

    // DEBUG: Verify section 1 characteristics after serialize_headers
    // Section headers start at 0x188 = 0x80 + 4 + 20 + 240
    // Section 0: 0x188-0x1af (40 bytes)
    // Section 1: 0x1b0-0x1d7 (40 bytes)
    // Section 1 Characteristics at: 0x1b0 + 36 = 0x1dc
    let sec1_chars_offset = 0x1dc;
    if sec1_chars_offset + 4 <= out_data.len() {
        let chars = u32::from_le_bytes([
            out_data[sec1_chars_offset],
            out_data[sec1_chars_offset + 1],
            out_data[sec1_chars_offset + 2],
            out_data[sec1_chars_offset + 3],
        ]);
        info!("After serialize_headers copy: Section 1 chars at {:#x} = {:#x}", sec1_chars_offset, chars);
    }

    // 6d. Manually re-write the data directories in the on-disk optional
    //     header.  serialize_headers does not position them correctly for
    //     loaders that compute `optional_header_start + fixed_offset`, so
    //     we overwrite them using the correct offsets based on format.
    let opt_start = pe_offset + 24;
    let dd_start = if is_64bit {
        opt_start + 112 // PE32+
    } else {
        opt_start + 96  // PE32
    };
    for (i, dd) in pe.nt_headers.optional_header.data_directory.iter().enumerate() {
        let off = dd_start + i * 8;
        if off + 8 <= out_data.len() {
            out_data[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
            out_data[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
        }
    }

    // CRITICAL FIX: Force Data Directory[15] (COM_DESCRIPTOR/RESERVED) to 0
    // Byte comparison found it was 0xC0000040 in Pascal, 0x40000040 in Rust
    // This is a Section Characteristics value in the wrong place!
    // Windows loader interprets this as 3GB+ COM descriptor → Segfault
    let dd15_offset = dd_start + 15 * 8;
    if dd15_offset + 8 <= out_data.len() {
        out_data[dd15_offset..dd15_offset + 4].fill(0);     // RVA = 0
        out_data[dd15_offset + 4..dd15_offset + 8].fill(0); // Size = 0
        info!("CRITICAL FIX: Cleared Data Directory[15] at offset {:#x}", dd15_offset);
    }

    debug!(
        "After manual data_directory write: IAT[12] in out_data at offset {:#x}: RVA={:#x} size={:#x}",
        dd_start + 12 * 8,
        u32::from_le_bytes([out_data[dd_start + 96], out_data[dd_start + 97], out_data[dd_start + 98], out_data[dd_start + 99]]),
        u32::from_le_bytes([out_data[dd_start + 100], out_data[dd_start + 101], out_data[dd_start + 102], out_data[dd_start + 103]])
    );

    debug!(
        "After manual data_directory write: IMPORT[1] in out_data at offset {:#x}: RVA={:#x} size={:#x}",
        dd_start + 8,
        u32::from_le_bytes([out_data[dd_start + 8], out_data[dd_start + 9], out_data[dd_start + 10], out_data[dd_start + 11]]),
        u32::from_le_bytes([out_data[dd_start + 12], out_data[dd_start + 13], out_data[dd_start + 14], out_data[dd_start + 15]])
    );

    // 6e. Write each section's data at its PointerToRawData file offset.
    //     For sections that were rebuilt in memory (e.g. `.import`) the
    //     data is stored in the `extra_data` field; for all others we
    //     read from the dump buffer at the section's VirtualAddress.
    //
    //     `trim_huge_sections` may have shrunk some sections in memory as
    //     well — `delta` is the cumulative number of bytes trimmed from
    //     the *tail* of the buffer.  We therefore cap reads to
    //     `min(raw_data_size, dump_buf_remaining_after_trim)` so that we
    //     never run past the actual captured data.
    let trimmed_total = delta as usize;
    let dump_buf_effective_len = dump_size.saturating_sub(trimmed_total);

    for section in &pe.sections {
        let raw_offset = section.header.pointer_to_raw_data as usize;
        if raw_offset == 0 || section.header.size_of_raw_data == 0 {
            continue;
        }
        let raw_size = section.header.size_of_raw_data as usize;
        let data = if let Some(ref extra) = section.extra_data {
            // Rebuilt section (e.g. `.import`); use the buffer verbatim.
            if raw_offset + extra.len() > out_data.len() {
                out_data.resize(raw_offset + extra.len(), 0);
            }
            out_data[raw_offset..raw_offset + extra.len()].copy_from_slice(extra);
            continue;
        } else if section.virtual_address as usize + raw_size <= dump_buf_effective_len {
            // Section lives in the (post-trim) dump buffer.
            &dump_buf[section.virtual_address as usize..section.virtual_address as usize + raw_size]
        } else if raw_size <= dump_buf.len() {
            // Fallback: write from untrimmed buffer only if it fits.
            &dump_buf[section.virtual_address as usize..section.virtual_address as usize + raw_size]
        } else {
            warn!(
                section = %section.name,
                va = format_args!("{:#x}", section.virtual_address),
                raw_offset = format_args!("{raw_offset:#x}"),
                raw_size = format_args!("{raw_size:#x}"),
                "Section data falls outside captured dump; skipping"
            );
            continue;
        };

        let out_end = raw_offset + data.len();
        if out_end > out_data.len() {
            out_data.resize(out_end, 0);
        }
        out_data[raw_offset..raw_offset + data.len()].copy_from_slice(data);
        debug!(
            section = %section.name,
            raw_offset = format_args!("{raw_offset:#x}"),
            len = data.len(),
            "section written",
        );
    }

    // 6f. Write Hint/Name RVAs to the FirstThunk (IAT) location.
    //     Magicmida strategy with OriginalFirstThunk = 0:
    //     - FirstThunk contains Hint/Name RVAs (not resolved addresses)
    //     - Windows loader reads from FirstThunk, resolves APIs, and overwrites
    //       the same location with resolved addresses
    //     This allows the loader to re-resolve imports on every run, working
    //     around ASLR of system DLLs.
    if !import_thunks.is_empty() && original_iat_rva != 0 {
        let iat_file_off = section_rva_to_file_offset(
            &pe.sections,
            original_iat_rva,
        );
        let ptr_size = if is_64bit { 8 } else { 4 };
        let copy_size = import_thunks.len() * ptr_size;
        let end = iat_file_off + copy_size;
        if end > out_data.len() {
            out_data.resize(end, 0);
        }

        // Write Hint/Name RVAs (matching Pascal Magicmida behavior)
        // Pascal overwrites resolved addresses with Hint/Name RVAs before writing to file
        for (i, &thunk_rva) in import_thunks.iter().enumerate() {
            let off = iat_file_off + i * ptr_size;
            if ptr_size == 8 {
                out_data[off..off + 8].copy_from_slice(&thunk_rva.to_le_bytes());
            } else {
                out_data[off..off + 4].copy_from_slice(&(thunk_rva as u32).to_le_bytes());
            }
        }

        info!(
            rva = format_args!("{original_iat_rva:#x}"),
            file_off = format_args!("{iat_file_off:#x}"),
            count = import_thunks.len(),
            "Wrote Hint/Name RVAs to IAT (FirstThunk) for loader resolution"
        );
    }

    // Step 6g: Fill additional IAT locations (dual IAT fix)
    // When code uses mov+call pattern instead of direct call [mem], it references
    // a different IAT location (e.g. 0x104ce0) than the Import Directory IAT.
    // We need to fill those locations with Hint/Name RVAs too.
    if !opts.additional_iat_locations.is_empty() && !import_thunks.is_empty() {
        let ptr_size = if is_64bit { 8 } else { 4 };
        let mut filled_count = 0;

        for &iat_va in &opts.additional_iat_locations {
            let iat_rva = (iat_va as u64).saturating_sub(opts.image_base) as u32;
            let iat_file_off = section_rva_to_file_offset(&pe.sections, iat_rva);

            // For each additional IAT location, write the same Hint/Name RVAs
            // We write all thunks sequentially starting from this location
            let copy_size = import_thunks.len() * ptr_size;
            let end = iat_file_off + copy_size;

            if end <= out_data.len() {
                for (i, &thunk_rva) in import_thunks.iter().enumerate() {
                    let off = iat_file_off + i * ptr_size;
                    if ptr_size == 8 {
                        out_data[off..off + 8].copy_from_slice(&thunk_rva.to_le_bytes());
                    } else {
                        out_data[off..off + 4].copy_from_slice(&(thunk_rva as u32).to_le_bytes());
                    }
                }
                filled_count += 1;
            }
        }

        if filled_count > 0 {
            info!(
                "Filled {} additional IAT locations with Hint/Name RVAs (dual IAT fix)",
                filled_count
            );
        }
    }

    // Final sanity check: the PE header we wrote out should still have the
    // patched characteristics.
    let final_chars_offset = pe_offset + 22;
    debug!(
        final_chars = %format!("{:#06x}", u16::from_le_bytes([out_data[final_chars_offset], out_data[final_chars_offset + 1]])),
        "final out_data header characteristics",
    );

    // 6f. IAT region intentionally left untouched.  The dump_buf already
    //     contains the live-process IAT bytes, some of which the protector's
    //     VM exit has resolved to real API addresses.  We preserve those bytes:
    //       - resolved points stay valid for the current process lifetime;
    //       - still-protected slots still contain hint/name RVAs that the
    //         PE loader will resolve at load time.
    //     Rationale: the original Pascal Magicmida (Dumper.pas line ~508)
    //     rewrites resolved addresses back into its IAT buffer then writes that
    //     buffer.  Our dump_buf is already such a buffer (captured before the
    //     protector could un-virtualise), so we forward it as-is.
    //     Caveat: re-randomising ASLR (another boot / different ImageBase)
    //     invalidates captured addresses.  Long-term portability needs a
    //     runtime trace pass — out of scope here.
    //
    // Magicmida approach: when the runtime IAT is encrypted/unavailable,
    // read the import table from the original PE file on disk and resolve
    // API addresses via GetProcAddress (valid because kernel32/ntdll are
    // loaded at the same ASLR base in all processes).

/// Build an import table from the original PE file's .idata section.
///
/// This is the Magicmida fallback: when the runtime IAT is encrypted,
/// read DLL and function names from the original file and resolve them
/// using GetProcAddress in the debugger process.
fn build_import_table_from_original(
    _pe: &PeHeader,
    original_path: &Path,
) -> Option<ImportTableBuilder> {
    let imports = read_original_import_table(original_path);
    if imports.is_empty() {
        return None;
    }

    let resolved = resolve_imports_via_getprocaddress(&imports);

    let mut builder = ImportTableBuilder::new(true); // 64-bit

    for (dll_name, functions) in &imports {
        let mut thunks: Vec<ImportThunk> = Vec::new();

        for func_name in functions {
            let key = (dll_name.clone(), func_name.clone());
            if resolved.contains_key(&key) {
                thunks.push(ImportThunk {
                    iat_address: 0, // will be set by builder
                    function_name: Some(func_name.clone()),
                    ordinal: None,
                    is_64bit: true,
                });
            } else {
                // Couldn't resolve - still add it so the loader can try
                thunks.push(ImportThunk {
                    iat_address: 0,
                    function_name: Some(func_name.clone()),
                    ordinal: None,
                    is_64bit: true,
                });
            }
        }

        if !thunks.is_empty() {
            let module = builder.add_module(dll_name);
            for t in thunks {
                module.thunks.push(t);
            }
        }
    }

    if builder.modules.is_empty() {
        None
    } else {
        info!(
            modules = builder.modules.len(),
            thunks = builder.thunk_count(),
            resolved = resolved.len(),
            "Built import table from original PE (Magicmida approach)"
        );
        Some(builder)
    }
}

/// Write resolved API addresses into the IAT slots of the .import section.
///
/// This makes the import table "load-ready" - the PE loader won't need to
/// resolve API addresses because they're already filled in.
#[allow(dead_code)]
fn write_resolved_addresses_to_iat(
    section_data: &mut [u8],
    _section_va: u32,
    builder: &ImportTableBuilder,
    resolved: &std::collections::HashMap<(String, String), usize>,
) {
    let ptr_size = std::mem::size_of::<usize>();

    // Compute layout offsets (same as build_import_section_no_iat)
    let desc_count = builder.modules.len() + 1;
    let _desc_size = desc_count * IMPORT_DESCRIPTOR_SIZE;
    let _dll_names_size: u32 = builder.modules.iter().map(|m| m.name.len() as u32 + 1).sum();
    let _hint_names_size: u32 = builder.modules.iter().map(|m| {
        m.thunks.iter().map(|t| {
            t.function_name.as_ref().map(|n| 2 + n.len() as u32 + 1).unwrap_or(0)
        }).sum::<u32>()
    }).sum();
    let iat_slots_offset: usize = {
        let desc_count = builder.modules.len() + 1;
        let desc_size: u32 = desc_count as u32 * 20;
        let dll_names_size: u32 = builder.modules.iter().map(|m| m.name.len() as u32 + 1).sum();
        let hint_names_size: u32 = builder.modules.iter().map(|m| {
            m.thunks.iter().map(|t| {
                t.function_name.as_ref().map(|n| 2 + n.len() as u32 + 1).unwrap_or(0)
            }).sum::<u32>()
        }).sum();
        (desc_size + dll_names_size + hint_names_size) as usize
    };

    let mut iat_offset = iat_slots_offset;

    for m in &builder.modules {
        for t in &m.thunks {
            if iat_offset + ptr_size <= section_data.len() {
                let key = (m.name.clone(), t.function_name.clone().unwrap_or_default());
                if let Some(&addr) = resolved.get(&key) {
                    // Write the resolved API address directly
                    let addr_bytes = addr.to_le_bytes();
                    section_data[iat_offset..iat_offset + ptr_size].copy_from_slice(&addr_bytes);
                }
                iat_offset += ptr_size;
            }
        }
        // Skip null terminator
        iat_offset += ptr_size;
    }
}

    // DEBUG: Verify section 1 characteristics before fix_hardcoded_addresses
    // Section 1 at 0x1b0, Characteristics at offset 36 = 0x1b0 + 0x24 = 0x1d4
    let sec1_chars_offset = 0x1d4;
    if sec1_chars_offset + 4 <= out_data.len() {
        let chars = u32::from_le_bytes([
            out_data[sec1_chars_offset],
            out_data[sec1_chars_offset + 1],
            out_data[sec1_chars_offset + 2],
            out_data[sec1_chars_offset + 3],
        ]);
        info!("Before fix_hardcoded_addresses: Section 1 chars at {:#x} = {:#x}", sec1_chars_offset, chars);
    }

    // Fix hardcoded runtime addresses before writing
    fix_hardcoded_addresses(&mut out_data, opts.image_base, is_64bit)?;

    // DEBUG: Verify section 1 characteristics after fix_hardcoded_addresses
    if sec1_chars_offset + 4 <= out_data.len() {
        let chars = u32::from_le_bytes([
            out_data[sec1_chars_offset],
            out_data[sec1_chars_offset + 1],
            out_data[sec1_chars_offset + 2],
            out_data[sec1_chars_offset + 3],
        ]);
        info!("After fix_hardcoded_addresses: Section 1 chars at {:#x} = {:#x}", sec1_chars_offset, chars);
    }

    // CRITICAL: Skip relocation table generation entirely!
    //
    // After comparing with Magicmida byte-by-byte, we found:
    // - Magicmida does NOT generate a complete relocation table
    // - It keeps the original minimal .reloc (4 entries for TLS)
    // - It disables DYNAMIC_BASE so the program loads at fixed address
    // - All absolute addresses remain valid
    //
    // Our attempt to generate 4574 relocations was WRONG because:
    // 1. We can't distinguish which addresses should be relocated
    // 2. Some "absolute addresses" are actually runtime-generated values
    // 3. Generating wrong relocations corrupts the program
    //
    // Match Pascal Magicmida: do NOT generate a full relocation table.
    // Pascal keeps the original minimal .reloc (size=0x10, essentially empty).
    // Our attempt to generate 4574 relocations produced incorrect entries that
    // caused "not a valid Win32 application" errors.
    info!("Skipping relocation table generation (matches Pascal behavior)");
    let _ = opts.image_base; // suppress unused warning
    let _ = is_64bit;

    std::fs::write(out_path, &out_data)?;

    info!(
        path = %out_path.display(),
        size = out_data.len(),
        sections = pe.sections.len(),
        "Dump written successfully"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// fix_hardcoded_addresses — convert runtime absolute addresses to RVAs
// ---------------------------------------------------------------------------

/// Fix hardcoded runtime absolute addresses in the dump.
///
/// During unpacking, some data sections may contain absolute addresses that
/// were valid during the dump (based on the runtime ImageBase), but will be
/// invalid when the program loads at a different address. This function scans
/// all writable sections for such addresses and adjusts them.
fn fix_hardcoded_addresses(
    out_data: &mut [u8],
    runtime_image_base: u64,
    is_64bit: bool,
) -> Result<(), PeError> {
    // Parse PE to find the actual ImageBase and sections
    let pe = PeHeader::from_bytes(out_data)?;
    let file_image_base = pe.nt_headers.optional_header.image_base;

    let delta = (file_image_base as i64).wrapping_sub(runtime_image_base as i64);

    info!(
        "Scanning for hardcoded addresses: runtime_base={:#x}, file_base={:#x}, delta={:#x}",
        runtime_image_base, file_image_base, delta
    );

    // Scan all writable sections for hardcoded addresses
    let ptr_size = if is_64bit { 8 } else { 4 };
    let mut fixed_count = 0;
    let mut scanned_bytes = 0;

    // Define the valid address range for the runtime image
    let image_size = pe.nt_headers.optional_header.size_of_image as u64;
    let runtime_start = runtime_image_base;
    let runtime_end = runtime_image_base + image_size;

    for section in &pe.sections {
        // Scan ALL initialized sections:
        // - Writable data sections (obvious candidates)
        // - Executable code sections (may contain jump tables, constants)
        // - READONLY data sections (can contain global pointers that need fixing!)
        //
        // The key insight: READONLY doesn't mean "no absolute addresses"!
        // It just means the OS won't let the program write to it at runtime.
        // But absolute addresses in readonly data still need to be fixed.
        let is_writable = (section.characteristics & 0x80000000) != 0; // IMAGE_SCN_MEM_WRITE
        let is_executable = (section.characteristics & 0x20000000) != 0; // IMAGE_SCN_MEM_EXECUTE
        let is_initialized = (section.characteristics & 0x00000080) != 0; // IMAGE_SCN_CNT_INITIALIZED_DATA

        // Skip ONLY uninitialized sections (like .bss)
        if !is_writable && !is_executable && !is_initialized {
            continue;
        }

        let section_start = section.raw_offset as usize;
        let section_size = section.raw_size as usize;
        let section_end = section_start + section_size;

        if section_end > out_data.len() {
            warn!(
                "Section {} extends beyond file size, skipping",
                section.name
            );
            continue;
        }

        debug!(
            "Scanning section {} (RVA: {:#x}, size: {:#x}, file offset: {:#x})",
            section.name,
            section.virtual_address,
            section_size,
            section_start
        );

        // Scan the section for potential addresses
        for offset in (section_start..section_end).step_by(ptr_size) {
            let addr = read_ptr(out_data, offset, is_64bit);

            if addr == 0 {
                continue;
            }

            // Check if this looks like a runtime address
            let is_runtime_addr = if is_64bit {
                // For 64-bit, check if address falls within the runtime image range
                addr >= runtime_start && addr < runtime_end
            } else {
                // For 32-bit, check if address is within runtime image range
                addr >= runtime_image_base && addr < runtime_image_base + image_size
            };

            if is_runtime_addr && delta != 0 {
                let new_addr = (addr as i64).wrapping_add(delta) as u64;

                if fixed_count < 5 {
                    debug!(
                        "Fixing offset {:#x}: old={:#x}, delta={:#x}, new={:#x}",
                        offset, addr, delta, new_addr
                    );
                }

                write_ptr(out_data, offset, new_addr, is_64bit);
                fixed_count += 1;
            }
        }

        scanned_bytes += section_size;
    }

    info!(
        "Scanned {} bytes in writable sections, fixed {} hardcoded addresses",
        scanned_bytes, fixed_count
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// rebuild_import_table — two-pass voting algorithm
// ---------------------------------------------------------------------------

/// Rebuild the import table from the live IAT in the target process.
///
/// Returns an [`ImportTableBuilder`] with the resolved modules and thunks.
///
/// This is the Rust equivalent of `TDumper.Process` (Pass 1 and Pass 2).
pub fn rebuild_import_table(
    debugger: &mut dyn mida_core::DebuggerCore,
    iat_address: u64,
    iat_size: usize,
    image_base: u64,
    is_64bit: bool,
) -> Result<ImportTableBuilder, PeError> {
    let (_, _, builder) = rebuild_import_table_inner(
        debugger,
        iat_address,
        iat_size,
        image_base,
        is_64bit,
        None, // no original imports for ApiSet decisions
    )?;

    builder.ok_or_else(|| PeError::Parse("Import table reconstruction produced no output".into()))
}

/// Internal version that also returns the raw IAT image and its size.
fn rebuild_import_table_complete(
    debugger: &mut dyn mida_core::DebuggerCore,
    pe: &mut PeHeader,
    image_base: u64,
    is_64bit: bool,
    iat_override: Option<(usize, usize)>,
) -> Result<(Vec<u8>, usize, Option<ImportTableBuilder>), PeError> {
    // Find IAT location — either from the PE header or from the override.
    let (iat_address, iat_size) = if let Some((addr, size)) = iat_override {
        info!("Using override IAT location: {addr:#x}, size {size:#x}");
        // Update the PE header's IAT directory so the dump can find it.
        let iat_rva = (addr as u64).wrapping_sub(image_base) as u32;
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT] =
            crate::header::ImageDataDirectory {
                virtual_address: iat_rva,
                size: (size + iat_slot_size(is_64bit)) as u32,
            };
        (addr as u64, size)
    } else {
        // Find IAT location from the PE header
        let iat_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT];
        if iat_dir.virtual_address == 0 {
            return Err(PeError::Parse(
                "No IAT data directory in target PE header".into(),
            ));
        }

        let addr = image_base + iat_dir.virtual_address as u64;
        let max_iat_bytes = MAX_IAT_SLOTS * iat_slot_size(is_64bit);

        // Read the IAT
        let mut iat_data = vec![0u8; max_iat_bytes];
        let _read = debugger
            .read_memory(addr as usize, &mut iat_data)
            .map_err(|e| PeError::Parse(format!("Failed to read IAT: {e}")))?;

        // Determine actual IAT size
        let size = determine_iat_size(
            debugger.process_handle(),
            debugger.pid(),
            image_base,
            is_64bit,
            &iat_data,
        )?;
        info!(
            iat_size = format!("{size:#x}"),
            "Determined IAT size"
        );

        // Update the PE header's IAT directory
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT] =
            crate::header::ImageDataDirectory {
                virtual_address: iat_dir.virtual_address,
                size: (size + iat_slot_size(is_64bit)) as u32,
            };
        (addr, size)
    };

    // Read the IAT data at the determined location.
    let mut iat_data = vec![0u8; iat_size];
    let _read = debugger
        .read_memory(iat_address as usize, &mut iat_data)
        .map_err(|e| PeError::Parse(format!("Failed to read IAT: {e}")))?;

    rebuild_import_table_inner(
        debugger,
        iat_address,
        iat_size,
        image_base,
        is_64bit,
        None,
    )
}

/// Shared inner implementation of the two-pass algorithm.
fn rebuild_import_table_inner(
    debugger: &mut dyn mida_core::DebuggerCore,
    iat_address: u64,
    iat_size: usize,
    image_base: u64,
    is_64bit: bool,
    _original_imports: Option<&[String]>,
) -> Result<(Vec<u8>, usize, Option<ImportTableBuilder>), PeError> {
    let ptr_size = iat_slot_size(is_64bit);

    // Read the IAT
    let mut iat_data = vec![0u8; iat_size];
    let _read = debugger
        .read_memory(iat_address as usize, &mut iat_data)
        .map_err(|e| PeError::Parse(format!("Failed to read IAT: {e}")))?;
    if _read < iat_size {
        warn!(expected = iat_size, actual = _read, "Short read on IAT");
    }

    // Take a snapshot of all loaded modules
    let modules = take_module_snapshot(
        debugger.process_handle(),
        debugger.pid(),
        image_base,
        is_64bit,
    )?;

    debug!(
        module_count = modules.len(),
        "Module snapshot taken"
    );

    // CRITICAL: Build reverse forward map and forward_string_map
    //
    // forward_map: Maps target_address → (source_module_index, source_function_name)
    // Example: real_RtlDeleteCriticalSection_address → (kernel32, "DeleteCriticalSection")
    //
    // forward_string_map: Maps forward_string_address → (target_module_index, target_function_name)
    // Example: ntdll's forward string address for "NtdllDefWindowProc_A" → (user32, "DefWindowProcA")
    //
    // Key insight: In PE format, forward exports work like this:
    // - Some IAT slots contain the forward string address (in the source module's export dir)
    //   instead of the real implementation address. We need to resolve from the forward string.
    // - Other IAT slots contain the real implementation address, but we want to prefer
    //   the source module's name for better import names.
    //
    // We build TWO maps to handle both cases:
    // 1. forward_map: real_addr → (source_module, source_func_name) — for IAT slots with real addr
    // 2. forward_string_map: fwd_string_addr → (target_module, target_func_name) — for IAT slots
    //    that still have the unresolved forward string address

    let mut forward_map: std::collections::HashMap<u64, (usize, String)> = std::collections::HashMap::new();
    let mut forward_string_map: std::collections::HashMap<u64, (usize, String)> = std::collections::HashMap::new();

    // Build module priority: kernel32 > kernelbase > others
    let mut module_priority: std::collections::HashMap<usize, i32> = std::collections::HashMap::new();
    for (mi, m) in modules.iter().enumerate() {
        let priority = if m.name.to_lowercase() == "kernel32.dll" {
            100
        } else if m.name.to_lowercase() == "kernelbase.dll" {
            50
        } else {
            0
        };
        module_priority.insert(mi, priority);
    }

    for (source_mi, source_module) in modules.iter().enumerate() {
        for (fwd_str, fwd_string_addr) in &source_module.forwards {
            // Parse "MODULE.Function" format
            if let Some((target_mod_name, target_func_name)) = fwd_str.split_once('.') {
                let target_mod_lower = target_mod_name.to_lowercase();

                // Look up the source export name directly from the forward string address.
                // For forward exports, `exports` maps (module_base + func_rva) → name,
                // and `forwards` stores the same address, so we can directly resolve
                // the source name without fragile name-matching heuristics.
                // Example: user32 forwards DefWindowProcA → Ntdll.NtdllDefWindowProc_A
                //   fwd_string_addr = user32_base + DefWindowProcA_func_rva
                //   source_module.exports[fwd_string_addr] = "DefWindowProcA"
                let source_name = match source_module.exports.get(fwd_string_addr) {
                    Some(n) => n.clone(),
                    None => continue,
                };

                for (tmi, target_module) in modules.iter().enumerate() {
                    let mod_name = target_module.name.to_lowercase();
                    if mod_name == target_mod_lower ||
                       mod_name == format!("{}.dll", target_mod_lower) ||
                       mod_name.starts_with(&target_mod_lower) {

                        // Find the target function's address in target module
                        for (target_addr, exported_func_name) in &target_module.exports {
                            if exported_func_name == target_func_name {
                                forward_string_map.insert(*fwd_string_addr, (tmi, target_func_name.to_string()));

                                // Map target real address → (source_module, source_export_name)
                                // with module priority for conflict resolution.
                                let should_insert = if let Some((existing_mi, _)) = forward_map.get(target_addr) {
                                    module_priority.get(&source_mi).unwrap_or(&0) >
                                    module_priority.get(existing_mi).unwrap_or(&0)
                                } else {
                                    true
                                };

                                if should_insert {
                                    forward_map.insert(*target_addr, (source_mi, source_name.clone()));
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
            }
        }
    }

    tracing::debug!("Forward map: {} entries, forward string map: {} entries",
        forward_map.len(), forward_string_map.len());

    // Determine whether ApiSet remapping is allowed
    let _allow_api_sets = false; // TODO: set true when original imports are available

    let slot_count = iat_size / ptr_size;

    // ============================================================
    // PASS 1: Collect candidates for every IAT slot
    // ============================================================
    let mut slots: Vec<IatSlot> = Vec::with_capacity(slot_count);

    for i in 0..slot_count {
        let off = i * ptr_size;
        let slot_val = read_ptr(&iat_data, off, is_64bit);

        let mut slot = IatSlot {
            candidates: Vec::new(),
            chosen: None,
            is_zero: slot_val == 0,
        };

        if slot.is_zero {
            slots.push(slot);
            continue;
        }

        // Variant A: direct match — find which module owns this address
        for (mi, m) in modules.iter().enumerate() {
            if slot_val > m.base && slot_val < m.end_off {
                if m.exports.contains_key(&slot_val) {
                    slot.candidates.push(ResolutionCandidate {
                        address: slot_val,
                        module_index: mi,
                    });
                }
                break; // Only one module can own a given address range
            }
        }

        // Variant B: forward map lookup — prefer source module over target
        // Example: prefer kernel32.DeleteCriticalSection over ntdll.RtlDeleteCriticalSection
        if let Some((source_mi, _source_name)) = forward_map.get(&slot_val) {
            // Insert at the front so forward source is preferred
            slot.candidates.insert(0, ResolutionCandidate {
                address: slot_val,
                module_index: *source_mi,
            });
        }

        // Variant C: forward_string_map lookup — handle IAT slots containing forward string addresses
        // When the IAT slot has the forward string address (e.g., ntdll's NtdllDefWindowProc_A forward
        // string at 0x7ffd... in ntdll's export directory), we need to resolve to the real target.
        // The forward_string_map maps: forward_string_addr → (target_module_index, target_func_name)
        if let Some((target_mi, target_func_name)) = forward_string_map.get(&slot_val) {
            // Look up the real address in the target module's exports
            if let Some((real_addr, _)) = modules[*target_mi].exports.iter().find(|(_, name)| name.as_str() == target_func_name.as_str()) {
                slot.candidates.push(ResolutionCandidate {
                    address: *real_addr,
                    module_index: *target_mi,
                });
            }
        }

        if slot.candidates.is_empty() {
            debug!(
                iat_va = format!("{:#x}", iat_address + off as u64),
                slot_val = format!("{slot_val:#x}"),
                "IAT slot unresolvable"
            );
        }

        slots.push(slot);
    }

    // ============================================================
    // PASS 2: Vote on best module per zero-delimited group
    // ============================================================
    let mut builder = ImportTableBuilder::new(is_64bit);

    let mut i = 0;
    while i < slot_count {
        // Skip zero separators
        if slots[i].is_zero {
            i += 1;
            continue;
        }

        // Find contiguous non-zero run
        let group_start = i;
        let mut group_end = i;
        while group_end + 1 < slot_count && !slots[group_end + 1].is_zero {
            group_end += 1;
        }

        // Vote: count module preferences
        let mut module_votes: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::new();
        for j in group_start..=group_end {
            for c in &slots[j].candidates {
                *module_votes.entry(c.module_index).or_insert(0) += 1;
            }
        }

        // Find winner module (most votes, tie-break by preference score)
        let mut winner_idx: Option<usize> = None;
        let mut winner_votes: i32 = -1;
        let mut winner_score: usize = 0;

        for (&mi, &votes) in &module_votes {
            let score = preference_score(&modules[mi].name);
            if (votes as i32) > winner_votes
                || ((votes as i32) == winner_votes && score > winner_score)
            {
                winner_votes = votes as i32;
                winner_score = score;
                winner_idx = Some(mi);
            }
        }

        let winner_mi = match winner_idx {
            Some(mi) => mi,
            None => {
                debug!(
                    group_start,
                    group_end,
                    "IAT group has no valid candidates, skipping"
                );
                i = group_end + 1;
                continue;
            }
        };

        // Pin each slot to the winner module's candidate, or fall back to its first candidate
        for j in group_start..=group_end {
            let mut found_winner = false;
            for (k, c) in slots[j].candidates.iter().enumerate() {
                if c.module_index == winner_mi {
                    slots[j].chosen = Some(k);
                    found_winner = true;
                    break;
                }
            }
            // If this slot doesn't have the winner module, use its first candidate
            if !found_winner && !slots[j].candidates.is_empty() {
                slots[j].chosen = Some(0);
            }
        }

        // Build thunks for this group
        let module_name = modules[winner_mi].name.clone();
        let mut thunks: Vec<ImportThunk> = Vec::new();

        for j in group_start..=group_end {
            let chosen = match slots[j].chosen {
                Some(c) => &slots[j].candidates[c],
                None => {
                    warn!(
                        iat_va = format!(
                            "{:#x}",
                            iat_address + (j * ptr_size) as u64
                        ),
                        "IAT slot has no candidate for winning module, skipping"
                    );
                    continue;
                }
            };

            // CRITICAL FIX: Use the ACTUAL module of the chosen candidate,
            // not the winner module! This fixes mixed-module groups where
            // minority slots (e.g., ntdll in a kernel32 group) were forced
            // to look up their exports in the wrong module.
            let actual_module_index = chosen.module_index;

            // Resolve function name: prefer the actual module's export table first,
            // then fall back to the forward_map for forwarder addresses.
            let func_name = modules[actual_module_index]
                .exports
                .get(&chosen.address)
                .cloned()
                .or_else(|| {
                    forward_map
                        .get(&chosen.address)
                        .map(|(_, name)| name.clone())
                });

            // Write resolved address back into the IAT image
            write_ptr(&mut iat_data, j * ptr_size, chosen.address, is_64bit);

            let (function_name, ordinal) = if let Some(ref name) = func_name {
                if name.starts_with('#') {
                    // Ordinal import
                    let ord: u16 = name[1..]
                        .parse()
                        .unwrap_or(0);
                    (None, Some(ord))
                } else {
                    (Some(name.clone()), None)
                }
            } else {
                // Generate placeholder name for unresolved slots
                let placeholder = format!("_unknown_{:#x}", chosen.address);
                tracing::warn!(
                    "IAT slot {} at {:#x}: unresolved, using placeholder '{}'",
                    j,
                    iat_address + (j * ptr_size) as u64,
                    placeholder
                );
                (Some(placeholder), None)
            };

            thunks.push(ImportThunk {
                iat_address: (iat_address - image_base) as u32 + (j * ptr_size) as u32,
                function_name,
                ordinal,
                is_64bit,
            });
        }

        if !thunks.is_empty() {
            builder.modules.push(ImportModule {
                name: module_name,
                thunks,
            });
        }

        i = group_end + 1;
    }

    info!(
        module_count = builder.modules.len(),
        thunk_count = builder.thunk_count(),
        "Import table reconstructed"
    );

    Ok((iat_data, iat_size, Some(builder)))
}

// ---------------------------------------------------------------------------
// determine_iat_size
// ---------------------------------------------------------------------------

/// Determine the actual size of the IAT by scanning for valid API addresses.
///
/// Corresponds to `TDumper.DetermineIATSize` in `Dumper.pas`.
///
/// Scans up to `MAX_IAT_SLOTS` slots.  Track the last offset where a valid
/// API address was found; stop when no valid address is seen within
/// `MAX_GAP_SLOTS` slots of the last valid one.
fn determine_iat_size(
    process_handle: HANDLE,
    pid: u32,
    image_base: u64,
    is_64bit: bool,
    iat_data: &[u8],
) -> Result<usize, PeError> {
    let modules = take_module_snapshot(process_handle, pid, image_base, is_64bit)?;
    let ptr_size = iat_slot_size(is_64bit);
    let max_slots = iat_data.len() / ptr_size;

    let mut last_valid_offset: usize = 0;
    let mut i: usize = 0;

    while i < max_slots && (last_valid_offset == 0 || i < last_valid_offset + MAX_GAP_SLOTS) {
        let val = read_ptr(iat_data, i * ptr_size, is_64bit);

        if is_api_address(&modules, val) {
            last_valid_offset = i * ptr_size;
        }

        i += 1;
    }

    Ok(last_valid_offset + ptr_size)
}

// ---------------------------------------------------------------------------
// is_api_address
// ---------------------------------------------------------------------------

/// Check whether an address falls within a known module's export table.
///
/// Corresponds to `TDumper.IsAPIAddress` in `Dumper.pas`.
fn is_api_address(modules: &[RemoteModule], address: u64) -> bool {
    for m in modules {
        if address > m.base && address < m.end_off {
            return m.exports.contains_key(&address);
        }
    }
    false
}

// ---------------------------------------------------------------------------
// take_module_snapshot
// ---------------------------------------------------------------------------

/// Enumerate all loaded modules in the target process and parse their export
/// tables.
///
/// Corresponds to `TDumper.TakeModuleSnapshot` in `Dumper.pas`.
///
/// Uses the ToolHelp API (`CreateToolhelp32Snapshot` → `Module32FirstW` /
/// `Module32NextW`) to enumerate modules, then calls
/// [`gather_module_exports_from_remote`] for each one.
///
/// # Parameters
///
/// - `process_handle` — handle to the target process with `PROCESS_VM_READ`.
/// - `pid` — target process ID (used for the snapshot).
/// - `image_base` — base address of the main (target) module. This module is
///   skipped (it contains no import-relevant exports).
/// - `is_64bit` — `true` if the target is a 64-bit process.
///
/// # Errors
///
/// Logs a warning and skips modules whose export table cannot be read (e.g.
/// because they are paged out).  Returns an empty list only if the ToolHelp
/// snapshot itself fails.
pub fn take_module_snapshot(
    process_handle: HANDLE,
    pid: u32,
    image_base: u64,
    is_64bit: bool,
) -> Result<Vec<RemoteModule>, PeError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    };
    use windows::Win32::Foundation::CloseHandle;

    // 1. Create the module snapshot
    // SAFETY: pid is the target process ID obtained from the debugger.
    let h_snap = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE, pid)
    }
    .map_err(|e| {
        PeError::Parse(format!(
            "CreateToolhelp32Snapshot failed: {:#x}",
            e.code().0
        ))
    })?;

    let mut modules: Vec<RemoteModule> = Vec::new();

    // 2. Enumerate modules
    let mut me = MODULEENTRY32W::default();
    me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    // SAFETY: h_snap is a valid handle; me is a valid pointer to a
    // MODULEENTRY32W whose dwSize is correctly filled in.
    let first_ok = unsafe { Module32FirstW(h_snap, &mut me) };

    if first_ok.is_ok() {
        loop {
            // Skip the main module (the target EXE itself).
            if me.hModule.0 as u64 != image_base {
                let base = me.modBaseAddr as u64;
                let end = base + me.modBaseSize as u64;
                let name = String::from_utf16_lossy(&me.szModule)
                    .trim_end_matches('\0')
                    .to_lowercase();

                debug!(
                    base = format!("{base:#x}"),
                    end = format!("{end:#x}"),
                    %name,
                    "Enumerating module"
                );

                match gather_module_exports_from_remote(
                    process_handle,
                    base,
                    is_64bit,
                ) {
                    Ok((exports, forwards)) => {
                        modules.push(RemoteModule {
                            base,
                            end_off: end,
                            name,
                            exports,
                            forwards,
                        });
                    }
                    Err(e) => {
                        warn!(
                            %name,
                            error = %e,
                            "Failed to read exports for module, skipping"
                        );
                    }
                }
            }

            // SAFETY: h_snap is valid; me was populated by a previous call to
            // Module32FirstW or Module32NextW.
            let next_ok = unsafe { Module32NextW(h_snap, &mut me) };
            if next_ok.is_err() {
                break;
            }
        }
    }

    // 3. Clean up
    // SAFETY: h_snap is a valid snapshot handle.
    unsafe { let _ = CloseHandle(h_snap); }

    debug!(
        module_count = modules.len(),
        "Module snapshot complete"
    );

    Ok(modules)
}

/// Read the export table of a single module from the remote process.
///
/// Uses `ReadProcessMemory` to read the module's PE headers in the target
/// address space, finds the export directory, and builds a map:
/// `function_address → function_name` plus a list of forward exports.
///
/// Corresponds to `TDumper.GatherModuleExportsFromRemoteProcess` in
/// `Dumper.pas`.
fn gather_module_exports_from_remote(
    process_handle: HANDLE,
    module_base: u64,
    _is_64bit: bool,
) -> Result<
    (
        std::collections::HashMap<u64, String>,
        Vec<(String, u64)>,
    ),
    PeError,
> {
    // Helper: read memory from the target process.
    fn read_remote(handle: HANDLE, addr: u64, buf: &mut [u8]) -> Result<usize, PeError> {
        let mut bytes: usize = 0;
        // SAFETY: handle is a valid process handle; addr is a virtual address
        // within a loaded module; buf is writable for the given length.
        unsafe {
            ReadProcessMemory(
                handle,
                addr as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                Some(&mut bytes),
            )
            .map_err(|e| {
                PeError::Parse(format!(
                    "ReadProcessMemory({addr:#x}, {len}) failed: {e:?}",
                    addr = addr,
                    len = buf.len()
                ))
            })?;
        }
        Ok(bytes)
    }

    // Helper to safely extract fixed-size byte arrays
    let read_u32_le = |buf: &[u8], offset: usize| -> Result<u32, PeError> {
        buf.get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u32 at offset {}", offset)))
    };

    let read_u16_le = |buf: &[u8], offset: usize| -> Result<u16, PeError> {
        buf.get(offset..offset + 2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u16 at offset {}", offset)))
    };

    // 1. Read DOS header (first 64 bytes for the e_lfanew field).
    let mut dos_buf = [0u8; 64];
    read_remote(process_handle, module_base, &mut dos_buf)?;
    let e_lfanew = read_u32_le(&dos_buf, 60)? as u64;

    // 2. Read NT signature + file header + optional header magic.
    // Maximum size we need: 4 (sig) + 20 (file hdr) + 112 (opt hdr PE32+) = 136.
    // Round up to cover the data directories.
    const MAX_NT_HEADER: usize = 512;
    let mut nt_buf = [0u8; MAX_NT_HEADER];
    let _ = read_remote(process_handle, module_base + e_lfanew, &mut nt_buf)?;

    let pe_sig = read_u32_le(&nt_buf, 0)?;
    if pe_sig != 0x00004550 {
        return Err(PeError::InvalidPeSignature);
    }

    // Optional header magic (signature(4) + file_header(20) = offset 24)
    let magic = read_u16_le(&nt_buf, 24)?;

    // Data directory offset within optional header
    let dd_off: usize = if magic == 0x20B {
        // PE32+: data directories at 4+20+112 = 136
        136
    } else if magic == 0x10B {
        // PE32: data directories at 4+20+96 = 120
        120
    } else {
        return Err(PeError::UnknownMagic(magic));
    };

    // Export directory is the first data directory (index 0).
    let exp_va = read_u32_le(&nt_buf, dd_off)?;
    let exp_size = read_u32_le(&nt_buf, dd_off + 4)?;

    if exp_va == 0 || exp_size < 40 {
        // No exports in this module
        return Ok((std::collections::HashMap::new(), Vec::new()));
    }

    // 3. Read the export directory.
    let mut exp_buf = vec![0u8; exp_size as usize];
    read_remote(
        process_handle,
        module_base + exp_va as u64,
        &mut exp_buf,
    )?;

    // IMAGE_EXPORT_DIRECTORY layout:
    //   +0  Characteristics     (u32)
    //   +4  TimeDateStamp       (u32)
    //   +8  MajorVersion        (u16)
    //   +10 MinorVersion        (u16)
    //   +12 Name                (u32)
    //   +16 Base                (u32)
    //   +20 NumberOfFunctions   (u32)
    //   +24 NumberOfNames       (u32)
    //   +28 AddressOfFunctions  (u32)
    //   +32 AddressOfNames      (u32)
    //   +36 AddressOfNameOrdinals (u32)

    // Helper for export buffer reads
    let read_exp_u32 = |offset: usize| -> Result<u32, PeError> {
        exp_buf.get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u32 from export at offset {}", offset)))
    };

    let read_exp_u16 = |offset: usize| -> Result<u16, PeError> {
        exp_buf.get(offset..offset + 2)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_le_bytes)
            .ok_or(PeError::Parse(format!("Failed to read u16 from export at offset {}", offset)))
    };

    let num_functions = read_exp_u32(20)? as usize;
    let num_names = read_exp_u32(24)? as usize;
    let addr_of_functions = read_exp_u32(28)?;
    let addr_of_names = read_exp_u32(32)?;
    let addr_of_name_ordinals = read_exp_u32(36)?;
    let ordinal_base = read_exp_u32(16)?;

    // Helper: convert an RVA within the export section to a buffer offset.
    let rva_to_off = |rva: u32| -> Option<usize> {
        if rva >= exp_va && rva < exp_va + exp_size {
            Some((rva - exp_va) as usize)
        } else {
            None
        }
    };

    let mut exports: std::collections::HashMap<u64, String> =
        std::collections::HashMap::new();
    let mut forwards: Vec<(String, u64)> = Vec::new();

    // Track which function indices have names assigned.
    let mut named = vec![false; num_functions];

    // 4. Enumerate named exports.
    for i in 0..num_names {
        let name_off = match rva_to_off(addr_of_names + i as u32 * 4) {
            Some(off) if off + 4 <= exp_buf.len() => off,
            _ => break,
        };
        let ord_off = match rva_to_off(addr_of_name_ordinals + i as u32 * 2) {
            Some(off) if off + 2 <= exp_buf.len() => off,
            _ => break,
        };

        let name_rva = match read_exp_u32(name_off) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let func_index = match read_exp_u16(ord_off) {
            Ok(v) => v as usize,
            Err(_) => continue,
        };

        let fn_off = match rva_to_off(addr_of_functions + func_index as u32 * 4) {
            Some(off) if off + 4 <= exp_buf.len() => off,
            _ => continue,
        };
        let func_rva = match read_exp_u32(fn_off) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Read the name string
        if let Some(ns_off) = rva_to_off(name_rva) {
            if ns_off < exp_buf.len() {
                let end = exp_buf[ns_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(exp_buf.len() - ns_off);
                let name =
                    String::from_utf8_lossy(&exp_buf[ns_off..ns_off + end]).into_owned();

                let addr = module_base + func_rva as u64;
                exports.insert(addr, name);

                if func_index < num_functions {
                    named[func_index] = true;
                }

                // Check for forward export: the function RVA points inside the
                // export section (i.e., it's a string rather than an actual
                // code address).
                if let Some(fwd_off) = rva_to_off(func_rva) {
                    if fwd_off < exp_buf.len() {
                        let fwd_end = exp_buf[fwd_off..]
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(exp_buf.len() - fwd_off);
                        let fwd_str = String::from_utf8_lossy(
                            &exp_buf[fwd_off..fwd_off + fwd_end],
                        )
                        .into_owned();
                        // Skip private forwards containing ".#"
                        if !fwd_str.contains(".#") {
                            forwards.push((fwd_str, addr));
                        }
                    }
                }
            }
        }
    }

    // 5. Add ordinal exports for unnamed function entries.
    for i in 0..num_functions {
        if named[i] {
            continue;
        }
        let fn_off = match rva_to_off(addr_of_functions + i as u32 * 4) {
            Some(off) if off + 4 <= exp_buf.len() => off,
            _ => continue,
        };
        let func_rva = match read_exp_u32(fn_off) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ordinal = ordinal_base + i as u32;
        exports.insert(module_base + func_rva as u64, format!("#{ordinal}"));
    }

    Ok((exports, forwards))
}

// ---------------------------------------------------------------------------
// make_memory_readable
// ---------------------------------------------------------------------------

/// Make all memory pages in the range [`base`, `base + size`) readable.
///
/// Corresponds to `TDumper.MakeMemoryReadable` in `Dumper.pas`.
///
/// Walks the region page-by-page via `VirtualQueryEx` and calls
/// `VirtualProtectEx` on any `PAGE_NOACCESS` pages to set `PAGE_READONLY`.
fn make_memory_readable(
    debugger: &dyn mida_core::DebuggerCore,
    base: u64,
    size: u64,
) {
    let process_handle = debugger.process_handle();
    let mut addr = base;
    let end = base.saturating_add(size);
    let page_size = 0x1000usize; // 4 KiB pages

    while addr < end {
        let mut mbi: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();

        // SAFETY: process_handle is valid; mbi is a valid pointer.
        let query_ok = unsafe {
            VirtualQueryEx(
                process_handle,
                Some(addr as *const std::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if query_ok == 0 {
            // VirtualQueryEx failed (e.g. invalid region). Skip to next page.
            addr = addr.saturating_add(page_size as u64);
            continue;
        }

        // Only act on committed, no-access pages.
        // MEM_COMMIT = 0x1000, PAGE_NOACCESS = 0x01.
        let is_committed = mbi.State == MEM_COMMIT;
        let is_no_access = mbi.Protect == PAGE_PROTECTION_FLAGS(PAGE_NOACCESS.0);

        if is_committed && is_no_access {
            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            let region_start = mbi.BaseAddress as u64;
            let region_size = mbi.RegionSize.min((end - region_start) as usize);

            if region_size > 0 {
                // SAFETY: process_handle is valid; region_start is a valid
                // committed address range in the target.
                let _ = unsafe {
                    VirtualProtectEx(
                        process_handle,
                        region_start as *const std::ffi::c_void,
                        region_size,
                        PAGE_READONLY,
                        &mut old_protect,
                    )
                };
                debug!(
                    "make_memory_readable: {:#x}..{:#x} NOACCESS → READONLY",
                    region_start,
                    region_start.saturating_add(region_size as u64),
                );
            }
        }

        // Advance past this region.
        let next = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
        if next <= addr {
            addr = addr.saturating_add(page_size as u64);
        } else {
            addr = next;
        }
    }
}

// ---------------------------------------------------------------------------
// dump_dotnet
// ---------------------------------------------------------------------------

/// Dump a .NET assembly from the target process.
///
/// .NET assemblies don't need import table reconstruction — the CLR handles
/// method resolution at runtime.  This simply reads the dump image, trims
/// oversized sections, and writes the output.
///
/// Corresponds to `TDumperDotnet.DumpToFile` in `Dumper.pas`.
pub fn dump_dotnet(
    debugger: &mut dyn mida_core::DebuggerCore,
    image_base: u64,
    entry_point: u32,
    output_path: &Path,
) -> Result<(), PeError> {
    // Read PE headers
    let mut header = vec![0u8; 0x1000];
    let read = debugger
        .read_memory(image_base as usize, &mut header)
        .map_err(|e| PeError::Parse(format!("Failed to read header: {e}")))?;
    if read < 0x1000 {
        return Err(PeError::Parse("Short read on .NET PE header".into()));
    }

    let mut pe = PeHeader::from_bytes(&header)?;

    // Determine dump size from the last section
    let last_idx = pe.sections.len() - 1;
    let dump_size = pe.sections[last_idx].virtual_address + pe.sections[last_idx].virtual_size;

    info!(
        dump_size,
        sections = pe.sections.len(),
        "Dumping .NET assembly"
    );

    // Read the full image
    let dump_size_usize = dump_size as usize;
    let mut buf = vec![0u8; dump_size_usize];
    make_memory_readable(debugger, image_base, dump_size as u64);

    let read = debugger
        .read_memory(image_base as usize, &mut buf)
        .map_err(|e| PeError::Parse(format!("Failed to read .NET image: {e}")))?;

    // Sanitize and write
    pe.sanitize();

    // Rename first section to .text
    if !pe.sections.is_empty() {
        pe.rename_section(0, ".text");
    }

    let mut out_data = Vec::new();
    out_data.extend_from_slice(&buf[..dump_size_usize.min(read)]);

    // Pad to file alignment if needed
    let mut physical_size = dump_size;
    pe.file_align(&mut physical_size);
    if dump_size < physical_size {
        out_data.resize(physical_size as usize, 0);
    }

    // Update size of image
    let mut image_size = physical_size;
    pe.section_align(&mut image_size);
    pe.nt_headers.optional_header.size_of_image = image_size;

    // Update entry point
    let ep_rva = entry_point - image_base as u32;
    pe.nt_headers.optional_header.address_of_entry_point = ep_rva;

    // Write headers
    let header_data = pe.serialize_headers()?;
    out_data.extend_from_slice(&header_data);

    std::fs::write(output_path, &out_data)?;

    info!(
        path = %output_path.display(),
        size = out_data.len(),
        ".NET dump written successfully"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// get_original_imports
// ---------------------------------------------------------------------------

/// Extract the original import list from a file's import directory.
///
/// Returns a list of `"dllname.funcname"` strings.
///
/// Corresponds to `TDumper.GetOriginalImports` in `Dumper.pas`.
pub fn get_original_imports(file_path: &Path) -> Result<Vec<String>, PeError> {
    let data = std::fs::read(file_path)?;
    let pe = PeHeader::from_bytes(&data)?;

    let import_dir =
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return Ok(Vec::new());
    }

    let section = pe
        .get_section_by_rva(import_dir.virtual_address)
        .ok_or(PeError::SectionNotFound(import_dir.virtual_address))?;

    let section_data_start = section.raw_offset as usize;
    let section_data_end = section_data_start + section.raw_size as usize;

    if section_data_end > data.len() {
        return Err(PeError::OffsetOutOfRange(section_data_end as u32));
    }
    let section_data = &data[section_data_start..section_data_end];

    let dir_offset = (import_dir.virtual_address - section.virtual_address) as usize;
    let mut result = Vec::new();

    let mut desc_off = dir_offset;
    loop {
        if desc_off + IMPORT_DESCRIPTOR_SIZE > section_data.len() {
            break;
        }

        // Read Name field (offset +12 in descriptor)
        let name_rva = section_data.get(desc_off + 12..desc_off + 16)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or(PeError::Parse("Failed to read import descriptor name RVA".into()))?;

        if name_rva == 0 {
            break; // End of descriptor array
        }

        // Read DLL name
        let name_section = pe
            .get_section_by_rva(name_rva)
            .ok_or(PeError::SectionNotFound(name_rva))?;
        let name_in_section = (name_rva - name_section.virtual_address) as usize;
        let name_section_start = name_section.raw_offset as usize;

        if name_section_start + name_in_section < data.len() {
            let name_end = data[name_section_start + name_in_section..]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(256);
            let dll_name =
                String::from_utf8_lossy(
                    &data[name_section_start + name_in_section
                        ..name_section_start + name_in_section + name_end],
                )
                .to_lowercase();

            // Read FirstThunk to enumerate functions
            let first_thunk_rva = section_data.get(desc_off + 16..desc_off + 20)
                .and_then(|s| s.try_into().ok())
                .map(u32::from_le_bytes)
                .ok_or(PeError::Parse("Failed to read FirstThunk RVA".into()))?;

            if first_thunk_rva != 0 {
                let thunk_section = pe
                    .get_section_by_rva(first_thunk_rva)
                    .ok_or(PeError::SectionNotFound(first_thunk_rva))?;
                let _thunk_data_start = thunk_section.raw_offset as usize;
                let thunk_off = (first_thunk_rva - thunk_section.virtual_address) as usize;

                let is_64bit = pe.is_64bit;
                let ptr_size = if is_64bit { 8 } else { 4 };

                let mut t_off = thunk_off;
                loop {
                    if t_off + ptr_size > data.len() {
                        break;
                    }

                    let thunk_val = if is_64bit {
                        data.get(t_off..t_off + 8)
                            .and_then(|s| s.try_into().ok())
                            .map(u64::from_le_bytes)
                            .unwrap_or(0)
                    } else {
                        data.get(t_off..t_off + 4)
                            .and_then(|s| s.try_into().ok())
                            .map(u32::from_le_bytes)
                            .map(u64::from)
                            .unwrap_or(0)
                    };

                    if thunk_val == 0 {
                        break;
                    }

                    let func_name = if is_64bit && (thunk_val & 0x8000_0000_0000_0000) != 0 {
                        // Ordinal import
                        let ord = (thunk_val & 0xFFFF) as u16;
                        format!("#{ord}")
                    } else if !is_64bit && (thunk_val & 0x8000_0000) != 0 {
                        let ord = (thunk_val & 0xFFFF) as u16;
                        format!("#{ord}")
                    } else {
                        // Name import — read name from RVA
                        let name_rva = thunk_val as u32;
                        let ns = pe
                            .get_section_by_rva(name_rva)
                            .ok_or(PeError::SectionNotFound(name_rva))?;
                        let ns_off = (name_rva - ns.virtual_address) as usize;
                        let ns_base = ns.raw_offset as usize;
                        // skip 2-byte hint
                        let name_start = ns_base + ns_off + 2;
                        if name_start < data.len() {
                            let end = data[name_start..]
                                .iter()
                                .position(|&b| b == 0)
                                .unwrap_or(256);
                            String::from_utf8_lossy(&data[name_start..name_start + end])
                                .into_owned()
                        } else {
                            String::new()
                        }
                    };

                    if !func_name.is_empty() {
                        result.push(format!("{dll_name}.{func_name}"));
                    }

                    t_off += ptr_size;
                }
            }
        }

        desc_off += IMPORT_DESCRIPTOR_SIZE;
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// .NET detection helper
// ---------------------------------------------------------------------------

/// Check whether a PE has a COM descriptor (DataDirectory[14]), indicating
/// a .NET assembly.
#[must_use]
pub fn is_dotnet(pe: &PeHeader) -> bool {
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        .virtual_address
        != 0
}

// ---------------------------------------------------------------------------
// PeHeader serialisation helper
// ---------------------------------------------------------------------------

impl PeHeader {
    /// Serialise the NT headers and section table to a byte vector for
    /// writing to the output file.
    ///
    /// Corresponds to `TPEHeader.SaveToStream` in `PEInfo.pas`.
    pub(crate) fn serialize_headers(&self) -> Result<Vec<u8>, PeError> {
        // Calculate total size: NT headers + section table + 0x200 padding zeros
        let nt_size = if self.is_64bit {
            4 + 20 + 112 + 16 * 8 // sig + file + optional64 + data_dirs
        } else {
            4 + 20 + 96 + 16 * 8 // sig + file + optional32 + data_dirs
        };
        let section_table_size = self.sections.len() * 40;
        let total = nt_size + section_table_size + 0x200;
        let mut out = vec![0u8; total];

        // Write NT signature
        let sig = self.nt_headers.signature.to_le_bytes();
        out[0..4].copy_from_slice(&sig);

        // Write file header
        let fh = &self.nt_headers.file_header;
        out[4..6].copy_from_slice(&fh.machine.to_le_bytes());
        out[6..8].copy_from_slice(&fh.number_of_sections.to_le_bytes());
        out[8..12].copy_from_slice(&fh.time_date_stamp.to_le_bytes());
        // +12: PointerToSymbolTable (u32) — 0
        // +16: NumberOfSymbols (u32) — 0
        out[20..22].copy_from_slice(&fh.size_of_optional_header.to_le_bytes());
        out[22..24].copy_from_slice(&fh.characteristics.to_le_bytes());

        // Write optional header
        let oh = &self.nt_headers.optional_header;
        out[24..26].copy_from_slice(&oh.magic.to_le_bytes());
        out[26] = oh.major_linker_version;
        out[27] = oh.minor_linker_version;
        out[28..32].copy_from_slice(&oh.size_of_code.to_le_bytes());
        out[32..36].copy_from_slice(&oh.size_of_initialized_data.to_le_bytes());
        out[36..40].copy_from_slice(&oh.size_of_uninitialized_data.to_le_bytes());
        out[40..44].copy_from_slice(&oh.address_of_entry_point.to_le_bytes());
        out[44..48].copy_from_slice(&oh.base_of_code.to_le_bytes());

        if self.is_64bit {
            // PE32+
            eprintln!("[DEBUG] Writing ImageBase for PE32+: {:#x} at buffer offset 48", oh.image_base);
            out[48..56].copy_from_slice(&oh.image_base.to_le_bytes());
            out[56..60].copy_from_slice(&oh.section_alignment.to_le_bytes());
            out[60..64].copy_from_slice(&oh.file_alignment.to_le_bytes());
            out[64..66].copy_from_slice(&oh.major_operating_system_version.to_le_bytes());
            out[66..68].copy_from_slice(&oh.minor_operating_system_version.to_le_bytes());
            out[68..70].copy_from_slice(&oh.major_image_version.to_le_bytes());
            out[70..72].copy_from_slice(&oh.minor_image_version.to_le_bytes());
            out[72..74].copy_from_slice(&oh.major_subsystem_version.to_le_bytes());
            out[74..76].copy_from_slice(&oh.minor_subsystem_version.to_le_bytes());
            out[76..80].copy_from_slice(&oh.win32_version_value.to_le_bytes());
            out[80..84].copy_from_slice(&oh.size_of_image.to_le_bytes());
            out[84..88].copy_from_slice(&oh.size_of_headers.to_le_bytes());
            out[88..92].copy_from_slice(&oh.check_sum.to_le_bytes());
            out[92..94].copy_from_slice(&oh.subsystem.to_le_bytes());
            out[94..96].copy_from_slice(&oh.dll_characteristics.to_le_bytes());
            out[96..104].copy_from_slice(&oh.size_of_stack_reserve.to_le_bytes());
            out[104..112].copy_from_slice(&oh.size_of_stack_commit.to_le_bytes());
            out[112..120].copy_from_slice(&oh.size_of_heap_reserve.to_le_bytes());
            out[120..128].copy_from_slice(&oh.size_of_heap_commit.to_le_bytes());
            out[128..132].copy_from_slice(&oh.loader_flags.to_le_bytes());
            out[132..136].copy_from_slice(&oh.number_of_rva_and_sizes.to_le_bytes());

            // Data directories (starting at offset 136 = 24 + 112)
            let dd_off = 136;
            for (i, dd) in oh.data_directory.iter().enumerate() {
                let off = dd_off + i * 8;
                out[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
                out[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
            }

            // Section headers start after the optional header
            let sh_off = 24 + 112 + 16 * 8; // 264
            for (i, section) in self.sections.iter().enumerate() {
                let off = sh_off + i * 40;

                // DEBUG: Log section header fields
                if i < 3 {
                    tracing::info!(
                        "Section {}: name={:?}, VA={:#x}, chars={:#x}",
                        i,
                        std::str::from_utf8(&section.header.name).unwrap_or("(invalid)"),
                        section.header.virtual_address,
                        section.header.characteristics
                    );
                }

                out[off..off + 8].copy_from_slice(&section.header.name);
                out[off + 8..off + 12]
                    .copy_from_slice(&section.header.virtual_size.to_le_bytes());
                out[off + 12..off + 16]
                    .copy_from_slice(&section.header.virtual_address.to_le_bytes());
                out[off + 16..off + 20]
                    .copy_from_slice(&section.header.size_of_raw_data.to_le_bytes());
                out[off + 20..off + 24]
                    .copy_from_slice(&section.header.pointer_to_raw_data.to_le_bytes());
                out[off + 24..off + 28]
                    .copy_from_slice(&section.header.pointer_to_relocations.to_le_bytes());
                out[off + 28..off + 32]
                    .copy_from_slice(&section.header.pointer_to_linenumbers.to_le_bytes());
                out[off + 32..off + 34]
                    .copy_from_slice(&section.header.number_of_relocations.to_le_bytes());
                out[off + 34..off + 36]
                    .copy_from_slice(&section.header.number_of_linenumbers.to_le_bytes());
                out[off + 36..off + 40]
                    .copy_from_slice(&section.header.characteristics.to_le_bytes());

                // DEBUG: Verify what we actually wrote
                if i == 1 {
                    let written_chars = u32::from_le_bytes([out[off + 36], out[off + 37], out[off + 38], out[off + 39]]);
                    tracing::info!("Section 1: wrote characteristics {:#x} at offset {:#x}", written_chars, off + 36);
                }
            }
        } else {
            // PE32
            out[48..52].copy_from_slice(
                &oh.base_of_data
                    .unwrap_or(0)
                    .to_le_bytes(),
            );
            out[52..56].copy_from_slice(&(oh.image_base as u32).to_le_bytes());
            out[56..60].copy_from_slice(&oh.section_alignment.to_le_bytes());
            out[60..64].copy_from_slice(&oh.file_alignment.to_le_bytes());
            out[64..66].copy_from_slice(&oh.major_operating_system_version.to_le_bytes());
            out[66..68].copy_from_slice(&oh.minor_operating_system_version.to_le_bytes());
            out[68..70].copy_from_slice(&oh.major_image_version.to_le_bytes());
            out[70..72].copy_from_slice(&oh.minor_image_version.to_le_bytes());
            out[72..74].copy_from_slice(&oh.major_subsystem_version.to_le_bytes());
            out[74..76].copy_from_slice(&oh.minor_subsystem_version.to_le_bytes());
            out[76..80].copy_from_slice(&oh.win32_version_value.to_le_bytes());
            out[80..84].copy_from_slice(&oh.size_of_image.to_le_bytes());
            out[84..88].copy_from_slice(&oh.size_of_headers.to_le_bytes());
            out[88..92].copy_from_slice(&oh.check_sum.to_le_bytes());
            out[92..94].copy_from_slice(&oh.subsystem.to_le_bytes());
            out[94..96].copy_from_slice(&oh.dll_characteristics.to_le_bytes());
            out[96..100].copy_from_slice(&(oh.size_of_stack_reserve as u32).to_le_bytes());
            out[100..104].copy_from_slice(&(oh.size_of_stack_commit as u32).to_le_bytes());
            out[104..108].copy_from_slice(&(oh.size_of_heap_reserve as u32).to_le_bytes());
            out[108..112].copy_from_slice(&(oh.size_of_heap_commit as u32).to_le_bytes());
            out[112..116].copy_from_slice(&oh.loader_flags.to_le_bytes());
            out[116..120].copy_from_slice(&oh.number_of_rva_and_sizes.to_le_bytes());

            // Data directories (starting at offset 120 = 24 + 96)
            let dd_off = 120;
            for (i, dd) in oh.data_directory.iter().enumerate() {
                let off = dd_off + i * 8;
                out[off..off + 4].copy_from_slice(&dd.virtual_address.to_le_bytes());
                out[off + 4..off + 8].copy_from_slice(&dd.size.to_le_bytes());
            }

            // Section headers start after the optional header
            let sh_off = 24 + 96 + 16 * 8; // 248
            for (i, section) in self.sections.iter().enumerate() {
                let off = sh_off + i * 40;
                out[off..off + 8].copy_from_slice(&section.header.name);
                out[off + 8..off + 12]
                    .copy_from_slice(&section.header.virtual_size.to_le_bytes());
                out[off + 12..off + 16]
                    .copy_from_slice(&section.header.virtual_address.to_le_bytes());
                out[off + 16..off + 20]
                    .copy_from_slice(&section.header.size_of_raw_data.to_le_bytes());
                out[off + 20..off + 24]
                    .copy_from_slice(&section.header.pointer_to_raw_data.to_le_bytes());
                out[off + 24..off + 28]
                    .copy_from_slice(&section.header.pointer_to_relocations.to_le_bytes());
                out[off + 28..off + 32]
                    .copy_from_slice(&section.header.pointer_to_linenumbers.to_le_bytes());
                out[off + 32..off + 34]
                    .copy_from_slice(&section.header.number_of_relocations.to_le_bytes());
                out[off + 34..off + 36]
                    .copy_from_slice(&section.header.number_of_linenumbers.to_le_bytes());
                out[off + 36..off + 40]
                    .copy_from_slice(&section.header.characteristics.to_le_bytes());
            }
        }

        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn make_minimal_pe() -> Vec<u8> {
        crate::header::make_minimal_pe64()
    }

    #[test]
    fn preference_score_kernel32_highest() {
        let ks = preference_score("kernel32.dll");
        let kb = preference_score("kernelbase.dll");
        assert!(ks > kb, "kernel32 should score higher than kernelbase");
    }

    #[test]
    fn preference_score_unknown_is_zero() {
        assert_eq!(preference_score("unknown.dll"), 0);
    }

    #[test]
    fn is_dotnet_detection() {
        // Build a PE header with a COM descriptor
        let data = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&data).unwrap();
        assert!(!is_dotnet(&pe));

        pe.nt_headers.optional_header.data_directory[14].virtual_address = 0x2000;
        assert!(is_dotnet(&pe));
    }

    #[test]
    fn get_original_imports_empty_on_no_imports() {
        // The minimal PE64 has no import directory
        let data = crate::header::make_minimal_pe64();

        // Write to a temp file
        let tmp = std::env::temp_dir().join("test_pe_no_imports.exe");
        std::fs::write(&tmp, &data).unwrap();

        let result = get_original_imports(&tmp).unwrap();
        assert!(result.is_empty());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_ptr_32bit() {
        let data = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_ptr(&data, 0, false), 0x12345678);
    }

    #[test]
    fn read_ptr_64bit() {
        let data = [
            0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,
        ];
        assert_eq!(read_ptr(&data, 0, true), 0x1234567890ABCDEF);
    }

    #[test]
    fn write_ptr_round_trip() {
        let mut data = vec![0u8; 16];
        write_ptr(&mut data, 0, 0xDEADBEEF, false);
        assert_eq!(read_ptr(&data, 0, false), 0xDEADBEEF);

        write_ptr(&mut data, 8, 0xCAFEBABEDEADBEEF, true);
        assert_eq!(read_ptr(&data, 8, true), 0xCAFEBABEDEADBEEF);
    }

    #[test]
    fn determine_iat_size_empty_modules() {
        let is_64bit = true;
        let iat_data = vec![0u8; 64]; // all zeros — no valid API addresses
        // With no modules, all addresses are invalid, so result = sizeof(pointer)
        let size = determine_iat_size_internal(&iat_data, &[], is_64bit);
        assert_eq!(size, 8); // just the base pointer size
    }

    /// Internal version of determine_iat_size that doesn't need a debugger.
    fn determine_iat_size_internal(
        iat_data: &[u8],
        modules: &[RemoteModule],
        is_64bit: bool,
    ) -> usize {
        let ptr_size = iat_slot_size(is_64bit);
        let max_slots = iat_data.len() / ptr_size;

        let mut last_valid_offset: usize = 0;
        let mut i: usize = 0;

        while i < max_slots
            && (last_valid_offset == 0 || i < last_valid_offset / ptr_size + MAX_GAP_SLOTS)
        {
            let val = read_ptr(iat_data, i * ptr_size, is_64bit);

            if is_api_address(modules, val) {
                last_valid_offset = i * ptr_size;
            }

            i += 1;
        }

        last_valid_offset + ptr_size
    }
}

// ---------------------------------------------------------------------------
// DOS header helper
// ---------------------------------------------------------------------------

/// Create a minimal DOS header for the output PE file.
///
/// The dump buffer is a memory dump (no DOS header), but the output file
/// needs a valid DOS header for the PE loader to recognize it.
fn create_dos_header() -> Vec<u8> {
    let mut header = vec![0u8; 0x80];

    // DOS signature "MZ"
    header[0] = 0x4D; // 'M'
    header[1] = 0x5A; // 'Z'

    // DOS header fields
    header[2] = 0x90; // Bytes on last page of file
    header[4] = 0x03; // Pages in file
    header[8] = 0x04; // Size of header in paragraphs
    header[12] = 0xFF; // Minimum extra paragraphs (e_minalloc) - low byte
    header[13] = 0xFF; // Minimum extra paragraphs (e_minalloc) - high byte
    header[14] = 0x00; // Maximum extra paragraphs (e_maxalloc) - low byte
    header[15] = 0x00; // Maximum extra paragraphs (e_maxalloc) - high byte
    header[16] = 0xB8; // Initial SP value
    header[20] = 0x00; // Initial IP value
    header[24] = 0x40; // File address of relocation table

    // PE header offset at offset 0x3C
    header[0x3C] = 0x80; // PE header at offset 0x80

    // DOS stub program (minimal)
    let dos_stub: &[u8] = &[
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
        0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63,
        0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69,
        0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    for (i, &byte) in dos_stub.iter().enumerate() {
        if 0x40 + i < header.len() {
            header[0x40 + i] = byte;
        }
    }

    header
}

/// Map an RVA to a file offset using the section headers.
fn section_rva_to_file_offset(sections: &[crate::PeSection], rva: u32) -> usize {
    for section in sections {
        let start = section.virtual_address;
        let end = start + section.virtual_size;
        if rva >= start && rva < end {
            let offset = rva - start;
            return (section.header.pointer_to_raw_data + offset) as usize;
        }
    }
    rva as usize // fallback
}
// ---------------------------------------------------------------------------
// build_relocation_table — generate complete Base Relocation Table
// ---------------------------------------------------------------------------

/// Build a complete Base Relocation Table for the dump.
///
/// This scans all initialized sections for absolute addresses pointing to the image
/// and generates relocation entries so the Windows PE Loader can fix them when the
/// image loads at a different base address (ASLR).
///
/// Without this, absolute addresses in readonly data sections will be invalid,
/// causing the program to crash immediately.
#[allow(dead_code)]
fn build_relocation_table(
    out_data: &mut [u8],
    _runtime_image_base: u64,
    is_64bit: bool,
) -> Result<(), PeError> {
    use crate::relocation::RelocationTableBuilder;

    // Parse PE to get sections and image info
    let mut pe = PeHeader::from_bytes(out_data)?;
    let image_base = pe.nt_headers.optional_header.image_base;
    let image_size = pe.nt_headers.optional_header.size_of_image;

    info!(
        "Building Base Relocation Table: image_base={:#x}, image_size={:#x}",
        image_base, image_size
    );

    let mut builder = RelocationTableBuilder::new(image_base, image_size);

    // Scan all initialized sections for absolute addresses
    for section in &pe.sections {
        let is_writable = (section.characteristics & 0x80000000) != 0;
        let is_executable = (section.characteristics & 0x20000000) != 0;
        let is_initialized = (section.characteristics & 0x00000080) != 0;
        let has_contents = (section.characteristics & 0x00000040) != 0; // IMAGE_SCN_CNT_INITIALIZED_DATA

        // CRITICAL FIX: We must scan READONLY DATA sections!
        // Example: Section 2-4 with READONLY DATA contain absolute pointers.
        // Skip ONLY truly uninitialized sections (like .bss without INITIALIZED_DATA flag)
        //
        // Scan if ANY of these is true:
        // - Writable (obvious - data that can change)
        // - Executable (may contain jump tables, embedded constants)
        // - Initialized data (includes READONLY data with pointers!)
        // - Has contents (broader check for any initialized section)
        if !is_writable && !is_executable && !is_initialized && !has_contents {
            continue;
        }

        let section_start = section.raw_offset as usize;
        let section_size = section.raw_size as usize;
        let section_end = section_start + section_size;

        if section_end > out_data.len() {
            warn!(
                "Section {} extends beyond file size, skipping",
                section.name
            );
            continue;
        }

        let section_data = &out_data[section_start..section_end];

        info!("Scanning section {} for relocations: raw_offset={:#x}, size={:#x}, characteristics={:#x}",
              section.name, section.raw_offset, section_size, section.characteristics);

        // CRITICAL FIX: In our dump format, some sections have RVA != file_offset!
        // We read from file offsets, so we must calculate RVA correctly:
        // RVA = raw_offset + data_offset (NOT virtual_address + data_offset)
        // This is because our dump is a FLAT memory dump where RVA == file offset.
        builder.scan_and_add_relocations(section_data, section.raw_offset, is_64bit);

        debug!(
            "Scanned section {} (RVA: {:#x}, size: {:#x}) for relocations",
            section.name, section.virtual_address, section_size
        );
    }

    let reloc_count = builder.count();
    info!("Found {} relocations to add to .reloc", reloc_count);

    if reloc_count == 0 {
        warn!("No relocations found - this is unusual for a Themida dump");
        return Ok(());
    }

    // Build the .reloc section data
    let reloc_data = builder.build();

    // Find or create .reloc section
    let reloc_section_idx = pe.sections.iter().position(|s| {
        let name = s.name.trim_end_matches('\0');
        name == ".reloc"
    });

    if let Some(idx) = reloc_section_idx {
        // Replace existing .reloc section
        info!("Replacing existing .reloc section (old size: {}, new size: {})",
              pe.sections[idx].raw_size, reloc_data.len());

        let _old_rva = pe.sections[idx].virtual_address;
        let _aligned_size = crate::utils::align_up(reloc_data.len() as u32, 0x1000);

        // Update section header in out_data
        let old_rva = pe.sections[idx].virtual_address;
        pe.sections[idx].raw_size = reloc_data.len() as u32;
        pe.sections[idx].virtual_size = reloc_data.len() as u32;

        // CRITICAL: Write the updated section header back to out_data!
        // Section headers start at: PE_offset + sizeof(FileHeader) + sizeof(OptionalHeader)
        let section_header_offset = if is_64bit {
            0x80 + 24 + 240 + (idx * 40) // PE + FileHeader + OptionalHeader64 + section_index * sizeof(SectionHeader)
        } else {
            0x80 + 24 + 224 + (idx * 40) // PE + FileHeader + OptionalHeader32 + section_index * sizeof(SectionHeader)
        };

        // Write VirtualSize (offset +8 in section header)
        out_data[section_header_offset + 8..section_header_offset + 12]
            .copy_from_slice(&(reloc_data.len() as u32).to_le_bytes());

        // Write RawSize (offset +16 in section header)
        out_data[section_header_offset + 16..section_header_offset + 20]
            .copy_from_slice(&(reloc_data.len() as u32).to_le_bytes());

        info!("Updated .reloc section header at offset {:#x}", section_header_offset);

        // Update Data Directory entry for Base Relocation Table (index 5)
        const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].virtual_address = old_rva;
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC].size = reloc_data.len() as u32;

        // Write Data Directory back to out_data
        let data_dir_offset = if is_64bit {
            0x80 + 24 + 112 // PE signature + FileHeader + start of DataDirectory in OptionalHeader64
        } else {
            0x80 + 24 + 96  // PE signature + FileHeader + start of DataDirectory in OptionalHeader32
        };
        let basereloc_offset = data_dir_offset + (IMAGE_DIRECTORY_ENTRY_BASERELOC * 8);
        out_data[basereloc_offset..basereloc_offset + 4].copy_from_slice(&old_rva.to_le_bytes());
        out_data[basereloc_offset + 4..basereloc_offset + 8].copy_from_slice(&(reloc_data.len() as u32).to_le_bytes());

        // Write .reloc section data to file
        let file_offset = pe.sections[idx].raw_offset as usize;
        if file_offset + reloc_data.len() <= out_data.len() {
            out_data[file_offset..file_offset + reloc_data.len()].copy_from_slice(&reloc_data);
        } else {
            return Err(PeError::Parse("Reloc section extends beyond file size".into()));
        }

        info!("Base Relocation Table built successfully: {} relocations, {} bytes",
              reloc_count, reloc_data.len());
    } else {
        warn!("No .reloc section found in dump - cannot add relocations");
        // TODO: Create new .reloc section if needed
    }

    Ok(())
}
