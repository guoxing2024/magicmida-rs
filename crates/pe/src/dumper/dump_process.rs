//! Main dump orchestration — `dump_process` and `dump_dotnet`.
//!
//! Extracted from `dumper.rs` — corresponds to `TDumper.DumpToFile`
//! and `TDumperDotnet.DumpToFile` in `Dumper.pas`.

use std::path::Path;

use tracing::{debug, info, warn};

use crate::error::PeError;
use crate::header::PeHeader;
use crate::original_imports::{read_original_import_table, resolve_imports_via_getprocaddress};

use super::header_patch::{shrink_sections, validate_and_patch_pe_header};

/// Relocate internal RVAs in an IMAGE_EXPORT_DIRECTORY structure.
///
/// The export directory contains several RVA fields that point to arrays
/// and strings that live *inside* the export directory:
/// - `Name` (offset 0x0C): RVA to the DLL name string.
/// - `AddressOfFunctions` (offset 0x1C): RVA to the function RVA array.
/// - `AddressOfNames` (offset 0x20): RVA to the name RVA array.
/// - `AddressOfNameOrdinals` (offset 0x24): RVA to the ordinal array.
///
/// When the export directory is moved to a new section, the directory
/// fields and the *name RVA array elements* must be adjusted by `delta`.
///
/// **Forwarder vs code RVAs:** entries in the `AddressOfFunctions` array are
/// *either* code RVAs (pointing into `.text`, outside the export directory)
/// *or* forwarder RVAs (pointing to a forwarder string such as
/// `"ntdll.NtCreateFile"` that lives *inside* the export directory).  Only
/// forwarder RVAs — those that fall within
/// `[original_export_rva, original_export_rva + export_size)` — are shifted
/// by `delta`.  Code RVAs are left untouched: the code did not move.
///
/// `AddressOfNameOrdinals` array *elements* are ordinals (not RVAs) and are
/// never adjusted — only the directory field (0x24) is relocated.
///
/// # Fail-closed
///
/// Every count, array offset, and bound is validated.  On overflow, an array
/// running out of the export buffer, or a field RVA outside the export
/// directory range, this returns [`PeError`] rather than writing garbage.
///
/// # Arguments
///
/// - `export_data` — the full export directory blob (directory + arrays +
///   strings) captured from the original export range.  Offsets within it are
///   `rva - original_export_rva`.
/// - `original_export_rva` — the RVA the export directory had *before* the
///   move (used to validate that fields point inside the directory and to
///   classify forwarder vs code RVAs).
/// - `export_size` — the size of the original export directory range.
///   `export_data.len()` may be larger (padding) but must be `>= export_size`.
/// - `delta` — `new_export_rva.wrapping_sub(original_export_rva)`.
fn relocate_export_table_rvas(
    export_data: &mut [u8],
    original_export_rva: u32,
    export_size: u32,
    delta: u32,
) -> Result<(), PeError> {
    const DIRECTORY_SIZE: usize = 40;

    // Reject a too-small *declared* export_size BEFORE reading the directory.
    // This is distinct from the buffer-length check below: a caller could pass
    // a buffer physically >= 40 bytes but declare export_size < 40, in which
    // case reading the IMAGE_EXPORT_DIRECTORY fields would read zero-padded
    // garbage.  Fail closed first.
    if (export_size as usize) < DIRECTORY_SIZE {
        return Err(PeError::Parse(format!(
            "declared export_size ({export_size}) smaller than IMAGE_EXPORT_DIRECTORY ({DIRECTORY_SIZE})"
        )));
    }

    if export_data.len() < DIRECTORY_SIZE {
        return Err(PeError::Parse(format!(
            "export directory too small: {} bytes (need {DIRECTORY_SIZE})",
            export_data.len()
        )));
    }

    // Validate that export_data covers at least export_size.  This is checked
    // even when delta == 0 so the structural validation always runs.
    let export_size_usize = export_size as usize;
    if export_data.len() < export_size_usize {
        return Err(PeError::Parse(format!(
            "export buffer ({}) smaller than declared export_size ({export_size})",
            export_data.len()
        )));
    }

    // delta == 0 still performs full structural validation below; the writes
    // are no-ops (wrapping_add(0)) but every bounds/range check still runs.

    let dir_start = original_export_rva;
    let dir_end = original_export_rva
        .checked_add(export_size)
        .ok_or_else(|| {
            PeError::Parse(format!(
                "export directory end overflow: {original_export_rva:#x} + {export_size:#x}"
            ))
        })?;

    // Helper: read a little-endian u32 at a byte offset.
    let read_u32 = |buf: &[u8], off: usize| -> Result<u32, PeError> {
        buf.get(off..off + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .ok_or_else(|| PeError::Parse(format!("u32 read out of bounds at {off:#x}")))
    };

    // Helper: write a little-endian u32 at a byte offset.
    let write_u32 = |buf: &mut [u8], off: usize, v: u32| -> Result<(), PeError> {
        buf.get_mut(off..off + 4)
            .map(|s| s.copy_from_slice(&v.to_le_bytes()))
            .ok_or_else(|| PeError::Parse(format!("u32 write out of bounds at {off:#x}")))
    };

    // Helper: validate that an RVA points inside the export directory and
    // return its offset within the buffer.
    let offset_of = |rva: u32| -> Result<usize, PeError> {
        if rva == 0 {
            return Err(PeError::Parse(
                "export directory field RVA is 0 (expected inside-directory RVA)".into(),
            ));
        }
        if rva < dir_start || rva >= dir_end {
            return Err(PeError::Parse(format!(
                "export RVA {rva:#x} outside directory [{dir_start:#x},{dir_end:#x})"
            )));
        }
        Ok((rva - dir_start) as usize)
    };

    // Read counts (offset 0x14 / 0x18).
    let num_functions = read_u32(export_data, 0x14)? as usize;
    let num_names = read_u32(export_data, 0x18)? as usize;

    // --- Relocate Name (0x0C) ---
    let name_rva = read_u32(export_data, 0x0C)?;
    if name_rva != 0 {
        // Name must point inside the directory.
        offset_of(name_rva)?;
        write_u32(export_data, 0x0C, name_rva.wrapping_add(delta))?;
    }

    // --- Relocate AddressOfFunctions (0x1C) + its array elements ---
    let addr_funcs = read_u32(export_data, 0x1C)?;
    if addr_funcs != 0 {
        let arr_off = offset_of(addr_funcs)?;
        // Fail-closed: the full array must fit inside the declared export_size
        // (NOT the padded buffer length).  An array that spills into raw
        // padding but past export_size is rejected.
        let arr_end = arr_off
            .checked_add(num_functions.checked_mul(4).ok_or_else(|| {
                PeError::Parse(format!("num_functions*4 overflow: {num_functions}"))
            })?)
            .ok_or_else(|| PeError::Parse(format!("AddressOfFunctions end overflow")))?;
        if arr_end > export_size_usize {
            return Err(PeError::Parse(format!(
                "AddressOfFunctions array [{arr_off:#x},{arr_end:#x}) exceeds export_size {export_size:#x}"
            )));
        }
        // Relocate the directory field.
        write_u32(export_data, 0x1C, addr_funcs.wrapping_add(delta))?;
        // Relocate each function RVA: forwarder (inside dir) → +delta;
        // code RVA (outside dir) → unchanged.  Zero entries are skipped
        // (unexported slot).
        for i in 0..num_functions {
            let off = arr_off + i * 4;
            let func_rva = read_u32(export_data, off)?;
            if func_rva == 0 {
                continue;
            }
            let is_forwarder = func_rva >= dir_start && func_rva < dir_end;
            if is_forwarder {
                write_u32(export_data, off, func_rva.wrapping_add(delta))?;
            }
            // else: code RVA — leave unchanged.
        }
    }

    // --- Relocate AddressOfNames (0x20) + its name RVA array elements ---
    let addr_names = read_u32(export_data, 0x20)?;
    if addr_names != 0 {
        let arr_off = offset_of(addr_names)?;
        let arr_end = arr_off
            .checked_add(
                num_names
                    .checked_mul(4)
                    .ok_or_else(|| PeError::Parse(format!("num_names*4 overflow: {num_names}")))?,
            )
            .ok_or_else(|| PeError::Parse(format!("AddressOfNames end overflow")))?;
        if arr_end > export_size_usize {
            return Err(PeError::Parse(format!(
                "AddressOfNames array [{arr_off:#x},{arr_end:#x}) exceeds export_size {export_size:#x}"
            )));
        }
        // Relocate the directory field.
        write_u32(export_data, 0x20, addr_names.wrapping_add(delta))?;
        // Relocate each name RVA (they point to name strings inside the dir).
        for i in 0..num_names {
            let off = arr_off + i * 4;
            let name_rva = read_u32(export_data, off)?;
            if name_rva == 0 {
                continue;
            }
            // Name strings must live inside the export directory.
            offset_of(name_rva)?;
            write_u32(export_data, off, name_rva.wrapping_add(delta))?;
        }
    }

    // --- Relocate AddressOfNameOrdinals (0x24) directory field only ---
    // Ordinal *array elements* are indices, not RVAs, and are never adjusted.
    let addr_ordinals = read_u32(export_data, 0x24)?;
    if addr_ordinals != 0 {
        let arr_off = offset_of(addr_ordinals)?;
        // The ordinal array has num_names entries of u16.
        let arr_end = arr_off
            .checked_add(
                num_names
                    .checked_mul(2)
                    .ok_or_else(|| PeError::Parse(format!("num_names*2 overflow: {num_names}")))?,
            )
            .ok_or_else(|| PeError::Parse(format!("AddressOfNameOrdinals end overflow")))?;
        if arr_end > export_size_usize {
            return Err(PeError::Parse(format!(
                "AddressOfNameOrdinals array [{arr_off:#x},{arr_end:#x}) exceeds export_size {export_size:#x}"
            )));
        }
        // Relocate the directory field; leave the u16 ordinal elements alone.
        write_u32(export_data, 0x24, addr_ordinals.wrapping_add(delta))?;
    }

    tracing::debug!(
        "Relocated export directory: {} functions, {} names, delta {:#x}",
        num_functions,
        num_names,
        delta
    );
    Ok(())
}

use super::helpers::{make_memory_readable, IMAGE_DIRECTORY_ENTRY_IAT};
use super::import_rebuild::rebuild_import_table_complete;
use super::import_section::{build_import_table_from_original, create_import_section};
use super::output_writer::write_output_file;
use super::sections::{create_pdata_section, create_reloc_section};
use super::types::{DumpOptions, EarlySectionSnapshot};

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

    // 1a. Validate and patch PE header fields
    validate_and_patch_pe_header(&mut pe, opts)?;

    // 1b. Shrink: remove Themida-specific sections if requested.
    let mut saved_exception_rva: Option<(u32, u32)> = None;
    if opts.shrink {
        saved_exception_rva = shrink_sections(&mut pe);
    }

    // 1c. Preserve export table for AutoHotkey and other DLLs
    // If export directory points to a removed section, save it now
    const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    let export_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    let saved_export_data = if export_dir.virtual_address != 0 && export_dir.size > 0 {
        let export_size = export_dir.size as usize;
        if export_size > super::helpers::MAX_EXPORT_DIRECTORY_BYTES {
            warn!(
                "Export directory size {:#x} exceeds cap {:#x}; skipping export preserve",
                export_size,
                super::helpers::MAX_EXPORT_DIRECTORY_BYTES
            );
            None
        } else {
            let export_va = opts.image_base as u64 + export_dir.virtual_address as u64;
            match super::helpers::alloc_capped(
                export_size,
                super::helpers::MAX_EXPORT_DIRECTORY_BYTES,
                "export directory",
            ) {
                Ok(mut export_buf) => {
                    match debugger.read_memory(export_va as usize, &mut export_buf) {
                        Ok(_) => {
                            info!(
                                "Saved export table: RVA={:#x} Size={:#x} for relocation",
                                export_dir.virtual_address, export_dir.size
                            );
                            Some((export_buf, export_dir.size))
                        }
                        Err(e) => {
                            warn!("Failed to read export table: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("Export directory allocation rejected: {e}");
                    None
                }
            }
        }
    } else {
        None
    };

    let is_64bit = pe.is_64bit;

    // 2. Rebuild import table if requested
    let (iat_image, _iat_image_size, mut import_builder) = if opts.fix_imports {
        rebuild_import_table_complete(
            debugger,
            &mut pe,
            opts.image_base,
            is_64bit,
            opts.iat_location,
        )?
    } else {
        (Vec::new(), 0usize, None)
    };

    // Determine the original IAT RVA
    let original_iat_rva = if let Some((addr, _)) = opts.iat_location {
        u32::try_from(addr.wrapping_sub(opts.image_base as usize)).unwrap_or(0)
    } else {
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address
    };

    // 2b. Magicmida fallback
    let mut _resolved_imports: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    if opts.fix_imports {
        let live_empty = import_builder.as_ref().is_none_or(|b| b.thunk_count() == 0);

        // NEW: Also use original imports if IAT rebuild is significantly incomplete
        //
        // CRITICAL FIX: Compare against runtime IAT size, not original PE import count.
        // Themida removes unused imports at runtime, so the original PE may list 660
        // functions while the runtime IAT only has 572 slots. The 82% "coverage" is
        // actually 545/572 = 95% of the runtime IAT, which is sufficient.
        let use_original = if live_empty {
            true
        } else if let Some(ref ep) = opts.executable_path {
            let rebuilt_count = import_builder
                .as_ref()
                .map(|b| b.thunk_count())
                .unwrap_or(0);

            // Determine runtime IAT slot count from PE header
            let runtime_iat_slots = if let Some((iat_va, iat_size)) = opts.iat_location {
                iat_size / 8 // 64-bit = 8 bytes per slot
            } else {
                let iat_dir =
                    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT];
                if iat_dir.size > 0 {
                    (iat_dir.size / 8) as usize
                } else {
                    // Fallback: use original import count (old behavior)
                    let orig_imports = crate::original_imports::read_original_import_table(ep);
                    orig_imports.iter().map(|(_, funcs)| funcs.len()).sum()
                }
            };

            // If we're missing more than 10% of runtime IAT slots, use original
            let threshold = (runtime_iat_slots as f64 * 0.9) as usize;
            if rebuilt_count < threshold {
                warn!(
                    "IAT rebuild incomplete: {}/{} runtime slots ({}% coverage) - using original import table",
                    rebuilt_count, runtime_iat_slots,
                    (rebuilt_count as f64 / runtime_iat_slots as f64 * 100.0) as u32
                );
                true
            } else {
                info!(
                    "IAT rebuild sufficient: {}/{} runtime slots ({}% coverage) - using rebuilt table",
                    rebuilt_count, runtime_iat_slots,
                    (rebuilt_count as f64 / runtime_iat_slots as f64 * 100.0) as u32
                );
                false
            }
        } else {
            false
        };

        if use_original {
            if let Some(ref ep) = opts.executable_path {
                if let Some(fallback_builder) =
                    build_import_table_from_original(&pe, ep, original_iat_rva)
                {
                    info!("Using original PE import table (Magicmida approach): {} modules, {} thunks",
                        fallback_builder.modules.len(), fallback_builder.thunk_count());
                    import_builder = Some(fallback_builder);
                }
            }
        }
    }

    // 2c. Fix module attribution using the original PE's import table.
    //     On Windows 10+, combase.dll forwards some ole32.dll exports,
    //     causing pass2_vote to attribute ole32 functions to combase.dll.
    //     We read the original PE's import table to determine the correct
    //     module for each function, and reassign thunks as needed.
    if opts.fix_imports && import_builder.is_some() {
        if let Some(ref ep) = opts.executable_path {
            let orig_imports = crate::original_imports::read_original_import_table(ep);
            if !orig_imports.is_empty() {
                // Build a map: function_name -> original_dll_name
                let mut func_to_dll: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for (dll, funcs) in &orig_imports {
                    for func in funcs {
                        if !func.starts_with('#') {
                            func_to_dll
                                .entry(func.clone())
                                .or_insert_with(|| dll.clone());
                        }
                    }
                }

                // Check if any original modules are missing from the rebuilt table.
                // Guarded by the outer `import_builder.is_some()` check, but use
                // `if let` so a future refactor of that guard cannot panic here.
                let has_missing;
                let has_misattributed;
                if let Some(builder_ref) = import_builder.as_ref() {
                    let rebuilt_modules: std::collections::HashSet<String> = builder_ref
                        .modules
                        .iter()
                        .map(|m| m.name.to_lowercase())
                        .collect();
                    has_missing = orig_imports.iter().any(|(dll, _)| {
                        !rebuilt_modules.contains(&dll.to_lowercase()) && !dll.is_empty()
                    });

                    // Also check for misattributed functions: a function may
                    // be in the wrong module because Windows 10+ export
                    // forwarding causes pass2_vote to attribute it to the
                    // forwarding DLL instead of the real one (e.g. EnableWindow
                    // attributed to shlwapi.dll instead of user32.dll).
                    has_misattributed = builder_ref.modules.iter().any(|m| {
                        m.thunks.iter().any(|t| {
                            t.function_name.as_ref().is_some_and(|fname| {
                                func_to_dll.get(fname).is_some_and(|correct_dll| {
                                    correct_dll.to_lowercase() != m.name.to_lowercase()
                                })
                            })
                        })
                    });
                } else {
                    has_missing = false;
                    has_misattributed = false;
                }
                if has_missing || has_misattributed {
                    info!("Fixing module attribution using original PE import table");
                    // Guarded by the outer `import_builder.is_some()` check;
                    // `if let` avoids `unwrap()` panic if that guard changes.
                    if let Some(builder) = import_builder.as_mut() {
                        // Collect thunks to move: (module_idx, thunk_idx, correct_dll)
                        let mut moves: Vec<(usize, usize, String)> = Vec::new();
                        for (mi, module) in builder.modules.iter().enumerate() {
                            for (ti, thunk) in module.thunks.iter().enumerate() {
                                if let Some(ref fname) = thunk.function_name {
                                    if let Some(correct_dll) = func_to_dll.get(fname) {
                                        if correct_dll.to_lowercase() != module.name.to_lowercase()
                                        {
                                            moves.push((mi, ti, correct_dll.clone()));
                                        }
                                    }
                                }
                            }
                        }

                        // Group moved thunks by correct DLL
                        let mut new_modules: std::collections::HashMap<
                            String,
                            Vec<crate::import_table::ImportThunk>,
                        > = std::collections::HashMap::new();
                        for (mi, ti, dll) in &moves {
                            let thunk = &builder.modules[*mi].thunks[*ti];
                            new_modules
                                .entry(dll.clone())
                                .or_default()
                                .push(thunk.clone());
                        }

                        // Remove moved thunks from original modules (reverse order)
                        for (mi, ti, _) in moves.iter().rev() {
                            builder.modules[*mi].thunks.remove(*ti);
                        }

                        // Add new modules for moved thunks
                        for (dll, thunks) in new_modules {
                            // Check if module already exists
                            let existing = builder
                                .modules
                                .iter()
                                .position(|m| m.name.to_lowercase() == dll.to_lowercase());
                            match existing {
                                Some(idx) => {
                                    builder.modules[idx].thunks.extend(thunks);
                                }
                                None => {
                                    info!(
                                        "Added missing module '{}' with {} thunks",
                                        dll,
                                        thunks.len()
                                    );
                                    builder.modules.push(crate::import_table::ImportModule {
                                        name: dll,
                                        thunks,
                                    });
                                }
                            }
                        }

                        // Remove empty modules
                        builder.modules.retain(|m| !m.thunks.is_empty());

                        info!(
                            "Module attribution fixed: {} modules, {} thunks",
                            builder.modules.len(),
                            builder.thunk_count()
                        );

                        // CRITICAL FIX: Restore ordinal imports from original PE
                        // IAT rebuild converts all imports to name imports because it resolves
                        // addresses from memory and looks up names in exports.
                        // But some DLLs (WSOCK32.dll, OLEAUT32.dll) use ordinal imports,
                        // and converting them to names can cause "Cannot locate ordinal N" errors.
                        //
                        // Strategy:
                        // 1. Find which DLLs use ordinal imports in original PE
                        // 2. Load those DLLs and read their export tables
                        // 3. Build function_name -> ordinal mapping
                        // 4. Convert rebuilt thunks from name to ordinal

                        // Step 1: Collect ordinal imports from original PE
                        let mut ordinal_imports: std::collections::HashMap<String, Vec<u16>> =
                            std::collections::HashMap::new();

                        for (orig_dll, orig_funcs) in &orig_imports {
                            for orig_func in orig_funcs {
                                if let Some(ordinal_str) = orig_func.strip_prefix('#') {
                                    if let Ok(ordinal) = ordinal_str.parse::<u16>() {
                                        ordinal_imports
                                            .entry(orig_dll.to_lowercase())
                                            .or_insert_with(Vec::new)
                                            .push(ordinal);
                                    }
                                }
                            }
                        }

                        if !ordinal_imports.is_empty() {
                            info!(
                                "Found {} DLLs with ordinal imports in original PE",
                                ordinal_imports.len()
                            );

                            // Step 2 & 3: Load DLLs and build name -> ordinal maps
                            let mut dll_exports: std::collections::HashMap<
                                String,
                                std::collections::HashMap<u16, String>,
                            > = std::collections::HashMap::new();

                            debug!("Starting to load DLL exports for ordinal restoration");

                            for dll_name in ordinal_imports.keys() {
                                debug!("Loading exports for {}", dll_name);
                                if let Some(dll_path) =
                                    crate::dll_exports::find_system_dll(dll_name)
                                {
                                    let exports = crate::dll_exports::read_dll_exports(&dll_path);
                                    debug!("Loaded {} exports from {}", exports.len(), dll_name);
                                    if !exports.is_empty() {
                                        dll_exports.insert(dll_name.clone(), exports);
                                    }
                                } else {
                                    warn!("Could not find system DLL: {}", dll_name);
                                }
                            }

                            debug!("Finished loading DLL exports, starting conversion");

                            // Step 4: Convert thunks from name to ordinal
                            let mut converted_count = 0;

                            for module in &mut builder.modules {
                                let module_name_lower = module.name.to_lowercase();

                                // Check if this DLL uses ordinals in original PE
                                if let Some(ordinals_for_dll) =
                                    ordinal_imports.get(&module_name_lower)
                                {
                                    // Get export map for this DLL
                                    if let Some(exports) = dll_exports.get(&module_name_lower) {
                                        // Build reverse map: function_name -> ordinal
                                        let name_to_ordinal: std::collections::HashMap<
                                            String,
                                            u16,
                                        > = exports
                                            .iter()
                                            .map(|(ord, name)| (name.to_lowercase(), *ord))
                                            .collect();

                                        // Convert thunks
                                        for thunk in &mut module.thunks {
                                            if let Some(ref func_name) = thunk.function_name {
                                                let func_name_lower = func_name.to_lowercase();

                                                // Check if original PE imported this function by ordinal
                                                if let Some(&ordinal) =
                                                    name_to_ordinal.get(&func_name_lower)
                                                {
                                                    if ordinals_for_dll.contains(&ordinal) {
                                                        // Convert to ordinal import
                                                        debug!(
                                                            "Converting {}.{} to ordinal #{}",
                                                            module.name, func_name, ordinal
                                                        );
                                                        thunk.function_name = None;
                                                        thunk.ordinal = Some(ordinal);
                                                        converted_count += 1;
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "Could not load exports for {}, ordinals will not be restored",
                                            module.name
                                        );
                                    }
                                }
                            }

                            if converted_count > 0 {
                                info!(
                                    "Converted {} name imports to ordinal imports (matching original PE)",
                                    converted_count
                                );
                            }
                        }
                    }
                }

                // Do not replace live IAT sequences from the protected file's
                // import descriptors. Themida can retain bootstrap descriptors
                // that are not slot-for-slot equivalent to the decrypted IAT;
                // inserting a missing name shifts every later FirstThunk and
                // breaks fixed code references. Original imports are used only
                // for module attribution above.
            }
        }
    }

    // 2d. Build function-name → resolved address map
    if import_builder.is_some() {
        if let Some(ref builder) = import_builder {
            if !iat_image.is_empty() && original_iat_rva != 0 {
                for m in &builder.modules {
                    for t in &m.thunks {
                        if let Some(ref name) = t.function_name {
                            let slot_offset = (t.iat_address as i64) - (original_iat_rva as i64);
                            if slot_offset >= 0
                                && (slot_offset as usize) + std::mem::size_of::<usize>()
                                    <= iat_image.len()
                            {
                                let addr = usize::from_le_bytes(
                                    iat_image[slot_offset as usize
                                        ..slot_offset as usize + std::mem::size_of::<usize>()]
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
                info!(
                    "Resolved {} API addresses from live IAT image",
                    _resolved_imports.len()
                );
            } else if let Some(ref ep) = opts.executable_path {
                let imports = read_original_import_table(ep);
                _resolved_imports = resolve_imports_via_getprocaddress(&imports);
                info!(
                    "Resolved {} API addresses for IAT slots",
                    _resolved_imports.len()
                );
            }
        }
    }

    // 3. Sanitize PE header
    pe.sanitize();

    info!(size_of_image = pe.size_of_image(), "Dumping process image");

    // 4. Read the full dump image (SizeOfImage is attacker-controlled).
    let dump_size = pe.size_of_image() as usize;
    let mut dump_buf = super::helpers::alloc_capped(
        dump_size,
        super::helpers::MAX_IMAGE_DUMP_BYTES,
        "process image dump",
    )?;
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

    // GTO/AHK experimental stages are gated by DumpProfile (default OreansClassic).
    // Never re-guess profile from filename/SHA/section names — only opts.profile.
    let stage_plan = opts.profile.stage_plan();
    info!(
        profile = ?opts.profile,
        experimental = stage_plan.all_enabled(),
        "Dump profile stage plan"
    );

    // Detect SecurityCookie-encoded heap containers from the LIVE late image
    // BEFORE rewinding `.data` to the early (pre-CRT) baseline. The early
    // overlay intentionally strips process-local CRT state so the dumped PE
    // can re-run CRT from entry; that also erases encoded container triples.
    // OreansClassic: leave containers empty (no GTO/AHK capture).
    let mut containers = if stage_plan.detect_containers {
        super::container_snapshot::detect_containers(&pe, &dump_buf, debugger)
    } else {
        Vec::new()
    };
    // Zero-raw .fill heap slots must be snapshotted from the LIVE late image
    // before pointer scrub zeros process-local addresses.
    // OreansClassic: leave heap_globals empty (no HOT_GSCRIPT_RVAs path).
    let mut heap_globals = if stage_plan.detect_heap_globals {
        super::heap_global_snapshot::detect_heap_globals(&pe, &dump_buf, debugger)
    } else {
        Vec::new()
    };
    // Zero dangling inter-object pointers that fall outside captured ranges so
    // post-CRT restore does not hand ntdll stale heap addresses (RtlpFindEntry).
    let image_end = (opts.image_base as u64).saturating_add(pe.size_of_image() as u64);
    if stage_plan.scrub_uncaptured_heap_pointers {
        super::heap_global_snapshot::scrub_uncaptured_heap_pointers(
            &mut containers,
            &mut heap_globals,
            opts.image_base as u64,
            image_end,
        );
    }
    // Cookie + complement RVAs must be captured before early overlay zeros storage.
    // Prefer authoritative site from offline CRT resolve; never fuzzy-rescan when set.
    // B7.2.1: authority resolve/validation failure is a hard dump error (no structural success).
    let cookie_site = super::heap_bootstrap::resolve_security_cookie_site(
        &pe,
        &dump_buf,
        opts.security_cookie_rva,
        opts.security_cookie_complement_rva,
    )?;
    let had_authority =
        opts.security_cookie_rva.is_some() || opts.security_cookie_complement_rva.is_some();
    let cookie_rva = cookie_site.map(|s| s.cookie_rva);
    if let Some(site) = cookie_site {
        info!(
            cookie_rva = format_args!("{:#x}", site.cookie_rva),
            complement_rva = format_args!("{:#x}", site.complement_rva),
            authoritative = had_authority,
            "SecurityCookie site (pre-overlay)"
        );
    }

    let overlay = apply_early_section_overlays(
        &mut dump_buf,
        &opts.early_section_snapshots,
        opts.iat_location,
        opts.image_base,
    )?;
    if overlay.changed_bytes > 0 {
        info!(
            snapshots = overlay.applied_snapshots,
            changed_bytes = overlay.changed_bytes,
            "Applied early section snapshot overlay"
        );
    }

    // Scrub any remaining process-local absolute pointers and encoded
    // container triples that survived the early overlay (polluted baseline).
    super::data_reinit::reinitialize_zero_filled_data(
        &pe,
        &mut dump_buf,
        opts.executable_path.as_deref(),
    );

    // Early overlay zeros the live cookie. MSVC `__security_init_cookie` only
    // regenerates when storage still holds the default sentinel; plant it so
    // CRT re-entry produces a real cookie before post-CRT container encode.
    // B7.2.1: when authority was supplied, plant failure is a hard error.
    if !super::heap_bootstrap::plant_default_security_cookie(&pe, &mut dump_buf, cookie_site) {
        if had_authority {
            return Err(PeError::Parse(
                "Failed to plant authoritative SecurityCookie site after overlay; \
                 refusing structural success"
                    .into(),
            ));
        }
        warn!("Could not plant default SecurityCookie — CRT may skip cookie init");
    }

    // 4b. Create .pdata and .reloc sections
    if opts.shrink {
        if let Some((exc_rva, exc_size)) = saved_exception_rva {
            create_pdata_section(
                &mut pe,
                &dump_buf,
                exc_rva,
                exc_size,
                opts.executable_path.as_deref(),
            );
        }
        create_reloc_section(&mut pe);
    }

    // 5. VA compaction is DISABLED.  compact_and_shift moves sections
    //     to fill gaps left by removed Themida sections, but .text
    //     contains absolute address references (mov rax, 0x1400ec2000)
    //     that point to the original VAs.  fix_hardcoded_addresses only
    //     patches runtime ImageBase → file ImageBase, not VA shifts.
    //     Keeping original VAs avoids this problem — the gaps are
    //     unused memory and don't affect file size (sanitize sets
    //     ptr=VA so the file only contains actual section data).
    // if opts.shrink {
    //     compact_and_shift(&mut pe, &mut dump_buf);
    //     pe.sanitize();
    // }

    // 5b. Heap / container bootstrap (AhkGtoExperimental only).
    // Dump buffer must be mutable so post-CRT can rewrite the CRT wrapper jmp.
    // OreansClassic: never install heap/container bootstrap.
    let output_entry_point = if stage_plan.install_heap_bootstrap {
        import_builder
            .as_ref()
            .and_then(|builder| {
                super::heap_bootstrap::install_heap_bootstrap(
                    &mut pe,
                    &mut dump_buf,
                    builder,
                    opts.entry_point,
                    &containers,
                    &heap_globals,
                    opts.container_restore,
                    cookie_rva,
                    Some(debugger),
                )
            })
            .unwrap_or(opts.entry_point)
    } else {
        opts.entry_point
    };

    // 5c. Build import section (uses original virtual addresses)
    let mut import_thunks: Vec<u64> = Vec::new();
    if let Some(ref builder) = import_builder {
        info!(
            "Creating import section with {} modules, {} thunks",
            builder.modules.len(),
            builder.thunk_count()
        );
        let (thunks, _section_idx) =
            create_import_section(&mut pe, builder, original_iat_rva, &mut dump_buf, is_64bit);
        info!(
            "Import section created successfully, {} thunk addresses returned",
            thunks.len()
        );
        import_thunks = thunks;
    } else {
        warn!("No import_builder - skipping import section creation");
    }

    // 5c2. Materialize image-local IAT wrappers (AhkGtoExperimental only).
    // OreansClassic: no .wfix/.fill materialization, no image-local slot zeroing.
    let iat_size_bytes = opts.iat_location.map(|(_, size)| size).unwrap_or_else(|| {
        import_thunks
            .len()
            .saturating_mul(if is_64bit { 8 } else { 4 })
    });
    if stage_plan.materialize_image_iat_wrappers {
        let _ = super::wrapper_materialize::materialize_image_iat_wrappers(
            &mut pe,
            &mut dump_buf,
            original_iat_rva,
            iat_size_bytes,
            opts.image_base,
        );
    }
    // Follow E8/E9 (and movabs) from .text/.wfix into zero-raw .fill pages
    // that still hold live decrypted code — without this, wrappers call into
    // empty BSS (e.g. .wfix `call 0x334c98` → C0000005 / C0000409).
    if stage_plan.materialize_fill_code_refs {
        let _ = super::wrapper_materialize::materialize_fill_code_refs(
            &mut pe,
            &mut dump_buf,
            opts.image_base,
        );
    }
    // Redirect call sites that go through image-local wrapper IAT slots to a
    // direct call, then zero those slots so the PE loader does not interpret
    // them as Hint/Name RVAs (LdrpSnapModule AV).
    // Only AhkGtoExperimental may call this; never discard the result.
    if stage_plan.patch_wrapper_iat_call_sites {
        let (slots_zeroed, sites_patched) = super::wrapper_call_patch::patch_wrapper_iat_call_sites(
            &pe,
            &mut dump_buf,
            original_iat_rva,
            iat_size_bytes,
            opts.image_base,
        );
        info!(slots_zeroed, sites_patched, "wrapper_call_patch result");
        if slots_zeroed > 0 && sites_patched == 0 {
            warn!(
                slots_zeroed,
                sites_patched,
                "wrapper_call_patch: slots_zeroed > 0 but sites_patched == 0 \
                 (call sites may still reference zeroed IAT slots)"
            );
        }
    }

    // 5c. Fix import descriptor FirstThunk to match actual IAT slot addresses.
    //     create_import_section assigns sequential FirstThunk addresses, but
    //     write_iat_to_output writes to thunks' original iat_address.  When
    //     thunks are moved between modules, these don't match.  We fix the
    //     descriptors in the .import section's extra_data.
    //
    // NOTE: This override was REMOVED.  build_import_section_no_iat already
    // sets FirstThunk to the correct sequential offset (including null
    // terminators between modules).  Overriding with min(iat_address)
    // pointed FirstThunk at the ORIGINAL IAT layout (which has interleaved
    // module slots without null terminators), causing the PE loader to read
    // past module boundaries.  write_iat_to_output writes thunks
    // sequentially (matching the FirstThunk from build_import_section_no_iat),
    // so the sequential FirstThunk is correct.

    // 5d. Trim huge sections
    let mut iat_raw_addr = 0u32;
    let _delta = pe.trim_huge_sections(&dump_buf, &mut iat_raw_addr);

    // 5e. Rebuild .edata section for AutoHotkey and other DLLs.
    //
    // CRITICAL: This must run BEFORE write_output_file so the section goes
    // through the unified serialize flow (serialize_headers →
    // write_section_data).  The old code appended .edata AFTER serialization,
    // which left the section table / data directories / file layout
    // inconsistent and corrupted the output (the export bytes were written
    // at the new RVA as a raw file offset, but PointerToRawData was 0, so the
    // loader could not find them and the section table was stale).
    //
    // We follow the same pattern as create_pdata_section / create_import_section:
    //   - create_section_index lays out VA + PointerToRawData correctly
    //   - extra_data carries the payload; write_section_data emits it
    //   - DataDirectory[0] (EXPORT) is pointed at the new section
    //   - SizeOfImage is bumped to cover the new section
    if let Some((export_data, export_size)) = saved_export_data {
        create_edata_section(
            &mut pe,
            &export_data,
            export_size,
            export_dir.virtual_address,
        )?;
    }

    // 6. Write output file
    // R1-D/E: optional pure rebuild emit path. Host still owns live capture,
    // overlays, import section construction (as extra_data), and profile
    // stages; pure modules plan + rebuild PE bytes. R1-E preserves host
    // section VAs and carries host data directories for content import/IAT.
    let mut out_data = if opts.pure_rebuild {
        info!("R1-E pure rebuild emit path enabled");
        let pure_opts = super::pure_rebuild_adapter::PureRebuildEmitOptions {
            image_base: opts.image_base,
            entry_point_rva: output_entry_point,
            // Prefer content sections for exception/reloc when host already
            // built shells; typed rebind still helps empty cover sections.
            rebind_exceptions: true,
            rebind_relocations: true,
            prefer_aslr_when_relocs: true,
            preserve_section_vas: true,
            carry_host_data_directories: true,
            max_slice_bytes: super::helpers::MAX_IMAGE_DUMP_BYTES,
        };
        super::pure_rebuild_adapter::emit_pure_rebuild(&pe, &dump_buf, &pure_opts)?
    } else {
        write_output_file(
            &mut pe,
            &dump_buf,
            import_builder.as_ref(),
            &import_thunks,
            original_iat_rva,
            is_64bit,
            opts,
            output_entry_point,
            &containers,
        )?
    };

    // DEBUG: Verify section 1 characteristics
    debug_section_chars(&out_data, "Before fix_hardcoded_addresses");

    // Fix hardcoded runtime addresses
    crate::postprocess::fix_hardcoded_addresses(&mut out_data, Some(opts.image_base), is_64bit)?;

    debug_section_chars(&out_data, "After fix_hardcoded_addresses");

    // ===超越 Pascal: 文件布局重排===
    if opts.shrink {
        crate::postprocess::pack_section_layout(&mut out_data, &pe)?;
    }

    // ===超越 Pascal: 生成重定位表===
    if opts.shrink {
        crate::postprocess::build_relocation_table(&mut out_data, None, is_64bit)?;
    }

    std::fs::write(&opts.output_path, &out_data)?;

    info!(
        path = %opts.output_path.display(),
        size = out_data.len(),
        sections = pe.sections.len(),
        "Dump written successfully"
    );

    Ok(())
}

/// Create a `.edata` section holding a relocated export directory.
///
/// Used by `dump_process` to preserve the export table when the original
/// export directory lived inside a Themida section that was removed by
/// `shrink_sections`.  The export bytes (IMAGE_EXPORT_DIRECTORY + all the
/// arrays/strings it references) are captured up-front and replayed here
/// into a fresh `.edata` section.
///
/// This MUST be called before `write_output_file` so the section flows
/// through the normal serialize path (`serialize_headers` writes the
/// section table, `write_section_data` emits `extra_data` at
/// `pointer_to_raw_data`).  Appending `.edata` after serialization — as the
/// old code did — left the section table stale, set `PointerToRawData = 0`,
/// and wrote the export bytes at the RVA as a raw file offset, corrupting
/// the output.
///
/// Mirrors `create_pdata_section` / `create_import_section`:
///  - `create_section_index` lays out VA + `PointerToRawData` correctly.
///  - `extra_data` carries the payload; `write_section_data` emits it.
///  - `DataDirectory[0]` (EXPORT) is pointed at the new section.
///  - `SizeOfImage` is bumped to cover the new section.
fn create_edata_section(
    pe: &mut PeHeader,
    export_data: &[u8],
    export_size: u32,
    original_export_rva: u32,
) -> Result<(), PeError> {
    const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    const IMAGE_SCN_MEM_READ_ED: u32 = 0x4000_0000;
    const IMAGE_SCN_CNT_INITIALIZED_DATA_ED: u32 = 0x0000_0040;
    const DIRECTORY_SIZE: usize = 40;

    // Fail-closed BEFORE any section mutation: a too-small declared export_size
    // must be rejected without appending a .edata section, so the raw-data
    // padding applied later can never mask a short DataDirectory.Size.
    if (export_size as usize) < DIRECTORY_SIZE {
        return Err(PeError::Parse(format!(
            "declared export_size ({export_size}) smaller than IMAGE_EXPORT_DIRECTORY ({DIRECTORY_SIZE})"
        )));
    }
    if export_data.len() < (export_size as usize) {
        return Err(PeError::Parse(format!(
            "export buffer ({}) smaller than declared export_size ({export_size})",
            export_data.len()
        )));
    }

    let file_align = pe.nt_headers.optional_header.file_alignment;
    let section_align = pe.nt_headers.optional_header.section_alignment;
    let raw_size = crate::utils::align_up(export_size, file_align);

    let edata_idx = pe.create_section_index(".edata", export_size);

    // create_section_index sets VirtualSize = export_size (unaligned); keep
    // the unaligned virtual size so the loader maps exactly export_size
    // bytes, but align SizeOfRawData to FileAlignment.
    pe.sections[edata_idx].virtual_size = export_size;
    pe.sections[edata_idx].header.virtual_size = export_size;
    pe.sections[edata_idx].header.size_of_raw_data = raw_size;
    pe.sections[edata_idx].raw_size = raw_size;
    pe.sections[edata_idx].characteristics =
        IMAGE_SCN_MEM_READ_ED | IMAGE_SCN_CNT_INITIALIZED_DATA_ED;
    pe.sections[edata_idx].header.characteristics = pe.sections[edata_idx].characteristics;

    // Relocate the export directory's internal RVAs to the new section VA.
    // The export buffer contains the IMAGE_EXPORT_DIRECTORY plus the arrays
    // and strings it references; all RVAs must be adjusted by `delta`.
    let new_export_rva = pe.sections[edata_idx].virtual_address;
    let mut padded = export_data.to_vec();
    if (padded.len() as u32) < raw_size {
        padded.resize(raw_size as usize, 0);
    }
    let delta = new_export_rva.wrapping_sub(original_export_rva);
    // Always run full structural validation (even when delta == 0) so a
    // malformed export directory is rejected regardless of whether it moved.
    relocate_export_table_rvas(&mut padded, original_export_rva, export_size, delta)?;
    if delta != 0 {
        debug!("Fixed export table internal RVAs with delta {:#x}", delta);
    }
    pe.sections[edata_idx].extra_data = Some(padded);

    // Update SizeOfImage for the new section.
    let new_end = pe.sections[edata_idx].header.virtual_address
        + crate::utils::align_up(export_size, section_align);
    if pe.nt_headers.optional_header.size_of_image < new_end {
        pe.nt_headers.optional_header.size_of_image = new_end;
    }

    // Point DataDirectory[0] (EXPORT) at the new .edata section.
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT] =
        crate::header::ImageDataDirectory {
            virtual_address: new_export_rva,
            size: export_size,
        };

    info!(
        "Relocated export table: {:#x} → {:#x} (size {:#x}, delta {:#x}, raw {:#x})",
        original_export_rva, new_export_rva, export_size, delta, raw_size
    );
    Ok(())
}

/// Debug helper: verify section 1 characteristics in the output buffer.
fn debug_section_chars(out_data: &[u8], label: &str) {
    let sec1_chars_offset = 0x1d4;
    if sec1_chars_offset + 4 <= out_data.len() {
        let chars = u32::from_le_bytes([
            out_data[sec1_chars_offset],
            out_data[sec1_chars_offset + 1],
            out_data[sec1_chars_offset + 2],
            out_data[sec1_chars_offset + 3],
        ]);
        info!(
            "{}: Section 1 chars at {:#x} = {:#x}",
            label, sec1_chars_offset, chars
        );
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct OverlayStats {
    applied_snapshots: usize,
    changed_bytes: usize,
}

fn apply_early_section_overlays(
    dump_buf: &mut [u8],
    snapshots: &[EarlySectionSnapshot],
    iat_location: Option<(usize, usize)>,
    image_base: u64,
) -> Result<OverlayStats, PeError> {
    let iat_range = iat_location.and_then(|(address, size)| {
        let image_base = usize::try_from(image_base).ok()?;
        let start = address.checked_sub(image_base)?;
        let end = start.checked_add(size)?;
        Some(start..end)
    });
    let mut stats = OverlayStats::default();

    for snapshot in snapshots {
        if snapshot.section_name != ".data" {
            warn!(
                section = %snapshot.section_name,
                rva = format_args!("{:#x}", snapshot.rva),
                "Skipping unsupported early snapshot overlay"
            );
            continue;
        }

        let start = snapshot.rva as usize;
        let end = start.checked_add(snapshot.bytes.len()).ok_or_else(|| {
            PeError::Parse(format!(
                "Early snapshot range overflow for {} at RVA {:#x}",
                snapshot.section_name, snapshot.rva
            ))
        })?;
        if end > dump_buf.len() {
            return Err(PeError::Parse(format!(
                "Early snapshot for {} exceeds dump image: {start:#x}..{end:#x} > {:#x}",
                snapshot.section_name,
                dump_buf.len()
            )));
        }
        if iat_range
            .as_ref()
            .is_some_and(|iat| start < iat.end && iat.start < end)
        {
            return Err(PeError::Parse(format!(
                "Early snapshot for {} overlaps IAT range",
                snapshot.section_name
            )));
        }

        let target = &mut dump_buf[start..end];
        stats.changed_bytes += target
            .iter()
            .zip(&snapshot.bytes)
            .filter(|(late, early)| late != early)
            .count();
        target.copy_from_slice(&snapshot.bytes);
        stats.applied_snapshots += 1;
    }

    Ok(stats)
}

#[cfg(test)]
mod overlay_tests {
    use super::*;

    fn snapshot(name: &str, rva: u32, bytes: &[u8]) -> EarlySectionSnapshot {
        EarlySectionSnapshot {
            section_name: name.into(),
            rva,
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn empty_snapshots_leave_dump_unchanged() {
        let mut dump = vec![0x55; 16];
        let before = dump.clone();
        let stats = apply_early_section_overlays(&mut dump, &[], None, 0x1400_0000).unwrap();
        assert_eq!(dump, before);
        assert_eq!(stats, OverlayStats::default());
    }

    #[test]
    fn overlays_data_and_counts_changes() {
        let mut dump = vec![0u8; 16];
        dump[5] = 7;
        let stats = apply_early_section_overlays(
            &mut dump,
            &[snapshot(".data", 4, &[1, 7, 2])],
            None,
            0x1400_0000,
        )
        .unwrap();
        assert_eq!(&dump[4..7], &[1, 7, 2]);
        assert_eq!(stats.changed_bytes, 2);
        assert_eq!(stats.applied_snapshots, 1);
    }

    #[test]
    fn skips_non_data_snapshots() {
        let mut dump = vec![0u8; 16];
        let stats = apply_early_section_overlays(
            &mut dump,
            &[snapshot(".text", 4, &[1, 2])],
            None,
            0x1400_0000,
        )
        .unwrap();
        assert_eq!(&dump[4..6], &[0, 0]);
        assert_eq!(stats, OverlayStats::default());
    }

    #[test]
    fn rejects_out_of_bounds_snapshot() {
        let mut dump = vec![0u8; 8];
        let err = apply_early_section_overlays(
            &mut dump,
            &[snapshot(".data", 7, &[1, 2])],
            None,
            0x1400_0000,
        )
        .unwrap_err();
        assert!(err.to_string().contains("exceeds dump image"));
    }

    #[test]
    fn rejects_iat_overlap() {
        let base = 0x1400_0000usize;
        let mut dump = vec![0u8; 32];
        let err = apply_early_section_overlays(
            &mut dump,
            &[snapshot(".data", 8, &[1, 2, 3, 4])],
            Some((base + 10, 8)),
            base as u64,
        )
        .unwrap_err();
        assert!(err.to_string().contains("overlaps IAT"));
    }
}

// -----------------------------------------------------------------------
// dump_dotnet
// -----------------------------------------------------------------------

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
    if pe.sections.is_empty() {
        return Err(PeError::Parse(
            "Cannot dump .NET assembly: PE has no sections".into(),
        ));
    }
    let last_idx = pe.sections.len() - 1;
    let dump_size = pe.sections[last_idx].virtual_address + pe.sections[last_idx].virtual_size;

    info!(
        dump_size,
        sections = pe.sections.len(),
        "Dumping .NET assembly"
    );

    // Read the full image (span is derived from untrusted section headers).
    let dump_size_usize = dump_size as usize;
    let mut buf = super::helpers::alloc_capped(
        dump_size_usize,
        super::helpers::MAX_IMAGE_DUMP_BYTES,
        ".NET image dump",
    )?;
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

/// Synthetic export-directory fixtures for `.edata` relocation tests.
#[cfg(test)]
mod edata_relocation_tests {
    use super::*;
    use crate::header::{
        ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
        ImageSectionHeader, PeHeader, PeSection,
    };

    const ORIGINAL_EXPORT_RVA: u32 = 0x10000;

    /// Build a realistic export blob laid out as:
    /// ```text
    /// 0x00  IMAGE_EXPORT_DIRECTORY (40 bytes)
    /// 0x28  AddressOfFunctions[2]   (code RVA + forwarder RVA)
    /// 0x30  AddressOfNames[1]        (name RVA)
    /// 0x34  AddressOfNameOrdinals[1] (ordinal index, u16)
    /// 0x38  Name string        "testmod.dll\0"
    /// 0x48  Func1 name string  "Func1\0"
    /// 0x50  forwarder string   "ntdll.NtCreateFile\0"
    /// ```
    fn build_export_blob() -> Vec<u8> {
        let mut buf = vec![0u8; 0x64]; // 100 bytes
        const OFF_DIR: usize = 0x00;
        const OFF_FUNCS: usize = 0x28;
        const OFF_NAMES: usize = 0x30;
        const OFF_ORDS: usize = 0x34;
        const OFF_NAME_STR: usize = 0x38;
        const OFF_FUNC1_STR: usize = 0x48;
        const OFF_FWD_STR: usize = 0x50;

        let rva_of = |off: usize| ORIGINAL_EXPORT_RVA + off as u32;

        let put = |buf: &mut [u8], off: usize, v: u32| {
            buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
        };
        put(&mut buf, OFF_DIR + 0x0C, rva_of(OFF_NAME_STR));
        put(&mut buf, OFF_DIR + 0x10, 1);
        put(&mut buf, OFF_DIR + 0x14, 2);
        put(&mut buf, OFF_DIR + 0x18, 1);
        put(&mut buf, OFF_DIR + 0x1C, rva_of(OFF_FUNCS));
        put(&mut buf, OFF_DIR + 0x20, rva_of(OFF_NAMES));
        put(&mut buf, OFF_DIR + 0x24, rva_of(OFF_ORDS));

        put(&mut buf, OFF_FUNCS + 0, 0x2000);
        put(&mut buf, OFF_FUNCS + 4, rva_of(OFF_FWD_STR));
        put(&mut buf, OFF_NAMES + 0, rva_of(OFF_FUNC1_STR));
        buf[OFF_ORDS..OFF_ORDS + 2].copy_from_slice(&1u16.to_le_bytes());

        let name_str = b"testmod.dll\0";
        buf[OFF_NAME_STR..OFF_NAME_STR + name_str.len()].copy_from_slice(name_str);
        let func1_str = b"Func1\0";
        buf[OFF_FUNC1_STR..OFF_FUNC1_STR + func1_str.len()].copy_from_slice(func1_str);
        let fwd_str = b"ntdll.NtCreateFile\0";
        buf[OFF_FWD_STR..OFF_FWD_STR + fwd_str.len()].copy_from_slice(fwd_str);

        buf
    }

    fn read_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }

    /// Code RVA stays unchanged; forwarder RVA shifts by delta; name array
    /// elements shift; ordinals stay; directory fields shift.
    #[test]
    fn relocate_distinguishes_code_and_forwarder_rvas() {
        let mut buf = build_export_blob();
        let export_size = buf.len() as u32;
        let delta = 0x20000u32;
        relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, export_size, delta).unwrap();
        assert_eq!(read_u32(&buf, 0x0C), ORIGINAL_EXPORT_RVA + 0x38 + delta);
        assert_eq!(read_u32(&buf, 0x1C), ORIGINAL_EXPORT_RVA + 0x28 + delta);
        assert_eq!(read_u32(&buf, 0x20), ORIGINAL_EXPORT_RVA + 0x30 + delta);
        assert_eq!(read_u32(&buf, 0x24), ORIGINAL_EXPORT_RVA + 0x34 + delta);
        assert_eq!(read_u32(&buf, 0x28), 0x2000);
        assert_eq!(read_u32(&buf, 0x2C), ORIGINAL_EXPORT_RVA + 0x50 + delta);
        assert_eq!(read_u32(&buf, 0x30), ORIGINAL_EXPORT_RVA + 0x48 + delta);
        assert_eq!(u16::from_le_bytes(buf[0x34..0x36].try_into().unwrap()), 1);
        assert_eq!(read_u32(&buf, 0x10), 1);
    }

    #[test]
    fn relocate_zero_delta_is_noop() {
        let mut buf = build_export_blob();
        let before = buf.clone();
        let sz = buf.len() as u32;
        relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, sz, 0).unwrap();
        assert_eq!(buf, before);
    }

    #[test]
    fn relocate_rejects_short_directory() {
        let mut buf = vec![0u8; 16];
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, 16, 0x100).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn relocate_rejects_size_larger_than_buffer() {
        let mut buf = build_export_blob();
        let sz = (buf.len() + 16) as u32;
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, sz, 0x100).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn relocate_rejects_functions_array_out_of_bounds() {
        let mut buf = build_export_blob();
        buf[0x14..0x18].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let sz = buf.len() as u32;
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, sz, 0x100).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn relocate_rejects_field_rva_outside_directory() {
        let mut buf = build_export_blob();
        buf[0x20..0x24].copy_from_slice(&0x3000u32.to_le_bytes());
        let sz = buf.len() as u32;
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, sz, 0x100).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn relocate_rejects_name_rva_outside_directory() {
        let mut buf = build_export_blob();
        buf[0x30..0x34].copy_from_slice(&0x3000u32.to_le_bytes());
        let sz = buf.len() as u32;
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, sz, 0x100).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    fn pe_with_text_section(text_va: u32, text_vsize: u32) -> PeHeader {
        let text_rawsize = text_vsize;
        PeHeader {
            dos_header: ImageDosHeader {
                e_magic: 0x5A4D,
                e_lfanew: 0x80,
            },
            nt_headers: ImageNtHeaders {
                signature: 0x4550,
                file_header: ImageFileHeader {
                    machine: 0x8664,
                    number_of_sections: 1,
                    time_date_stamp: 0,
                    size_of_optional_header: 0xF0,
                    characteristics: 0x22,
                },
                optional_header: ImageOptionalHeader {
                    magic: 0x20B,
                    major_linker_version: 14,
                    minor_linker_version: 0,
                    size_of_code: text_rawsize,
                    size_of_initialized_data: 0,
                    size_of_uninitialized_data: 0,
                    address_of_entry_point: 0x1000,
                    base_of_code: text_va,
                    base_of_data: None,
                    image_base: 0x140000000,
                    section_alignment: 0x1000,
                    file_alignment: 0x200,
                    major_operating_system_version: 6,
                    minor_operating_system_version: 0,
                    major_image_version: 0,
                    minor_image_version: 0,
                    major_subsystem_version: 6,
                    minor_subsystem_version: 0,
                    win32_version_value: 0,
                    size_of_image: text_va + 0x1000,
                    size_of_headers: 0x200,
                    check_sum: 0,
                    subsystem: 3,
                    dll_characteristics: 0,
                    size_of_stack_reserve: 0x100000,
                    size_of_stack_commit: 0x1000,
                    size_of_heap_reserve: 0x100000,
                    size_of_heap_commit: 0x1000,
                    loader_flags: 0,
                    number_of_rva_and_sizes: 16,
                    data_directory: [ImageDataDirectory::default(); 16],
                },
            },
            sections: vec![PeSection {
                header: ImageSectionHeader {
                    name: *b".text\0\0\0",
                    virtual_size: text_vsize,
                    virtual_address: text_va,
                    size_of_raw_data: text_rawsize,
                    pointer_to_raw_data: 0x200,
                    pointer_to_relocations: 0,
                    pointer_to_linenumbers: 0,
                    number_of_relocations: 0,
                    number_of_linenumbers: 0,
                    characteristics: 0x60000020,
                },
                name: ".text".to_string(),
                virtual_address: text_va,
                virtual_size: text_vsize,
                raw_offset: 0x200,
                raw_size: text_rawsize,
                characteristics: 0x60000020,
                extra_data: None,
            }],
            image_base: 0x140000000,
            entry_point: 0x1000,
            is_64bit: true,
            file_alignment: 0x200,
            section_alignment: 0x1000,
        }
    }

    #[test]
    fn synthetic_edata_section_serializes_and_reparses() {
        let export_blob = build_export_blob();
        let export_size = export_blob.len() as u32;
        let mut pe = pe_with_text_section(0x1000, 0x200);

        pe.nt_headers.optional_header.data_directory[0] = ImageDataDirectory {
            virtual_address: ORIGINAL_EXPORT_RVA,
            size: export_size,
        };

        create_edata_section(&mut pe, &export_blob, export_size, ORIGINAL_EXPORT_RVA).unwrap();

        // The full dump pipeline syncs NumberOfSections in output_writer;
        // exercise the same sync here so serialization writes all sections.
        pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;

        let edata = pe
            .sections
            .iter()
            .find(|s| s.name.starts_with(".edata"))
            .expect(".edata section must exist");
        assert!(edata.raw_size >= export_size);
        assert_eq!(edata.virtual_size, export_size);
        assert_eq!(pe.sections.len(), 2, "NumberOfSections must be 2");
        let new_end = edata.virtual_address + ((export_size + 0xFFF) & !0xFFF);
        assert!(pe.nt_headers.optional_header.size_of_image >= new_end);
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[0].virtual_address,
            edata.virtual_address
        );
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[0].size,
            export_size
        );

        let payload = edata
            .extra_data
            .as_ref()
            .expect(".edata must carry extra_data");
        let delta = edata.virtual_address.wrapping_sub(ORIGINAL_EXPORT_RVA);
        assert!(delta != 0, ".edata must be relocated to a new RVA");
        let new_va = edata.virtual_address;
        // Expected relocated RVAs = new section VA + the original blob offset.
        let addr_names = u32::from_le_bytes(payload[0x20..0x24].try_into().unwrap());
        assert_eq!(addr_names, new_va.wrapping_add(0x30));
        let ord_val = u16::from_le_bytes(payload[0x34..0x36].try_into().unwrap());
        assert_eq!(ord_val, 1);
        let code_rva = u32::from_le_bytes(payload[0x28..0x2C].try_into().unwrap());
        assert_eq!(code_rva, 0x2000);
        let fwd_rva = u32::from_le_bytes(payload[0x2C..0x30].try_into().unwrap());
        assert_eq!(fwd_rva, new_va.wrapping_add(0x50));
        let name_rva = u32::from_le_bytes(payload[0x0C..0x10].try_into().unwrap());
        assert_eq!(name_rva, new_va.wrapping_add(0x38));
        let name_off = (name_rva.wrapping_sub(new_va)) as usize;
        assert_eq!(&payload[name_off..name_off + 12], b"testmod.dll\0");

        let headers = pe.serialize_headers().unwrap();
        let mut image = vec![0u8; 0x80];
        image[0..2].copy_from_slice(&0x5A4Du16.to_le_bytes());
        image[60..64].copy_from_slice(&0x80u32.to_le_bytes());
        image.extend_from_slice(&headers);

        let reparsed = PeHeader::from_bytes(&image).expect("re-parse must succeed");
        assert_eq!(reparsed.sections.len(), 2, "NumberOfSections after reparse");
        assert_eq!(reparsed.nt_headers.file_header.number_of_sections, 2);
        let reparsed_edata = reparsed
            .sections
            .iter()
            .find(|s| s.name.starts_with(".edata"))
            .expect(".edata section present after reparse");
        assert_eq!(reparsed_edata.virtual_address, edata.virtual_address);
        assert_eq!(reparsed_edata.virtual_size, edata.virtual_size);
        assert_eq!(reparsed_edata.raw_size, edata.raw_size);
        assert!(reparsed.nt_headers.optional_header.size_of_image >= new_end);
        assert_eq!(
            reparsed.nt_headers.optional_header.data_directory[0].virtual_address,
            edata.virtual_address
        );
        assert_eq!(
            reparsed.nt_headers.optional_header.data_directory[0].size,
            export_size
        );
    }

    /// An array whose end crosses `export_size` but still lies inside the
    /// raw-padded buffer must be rejected — bounds are against `export_size`,
    /// not the padded buffer length.
    #[test]
    fn relocate_rejects_array_crossing_export_size_into_raw_padding() {
        // Start from a valid blob and inflate num_functions so the
        // AddressOfFunctions array end crosses export_size while every
        // directory field RVA stays inside [dir_start, export_size).
        let mut buf = build_export_blob();
        buf.resize(0x200, 0); // clearly larger than export_size (raw padding)
                              // num_functions (offset 0x14) = 7 → array end = 0x28 + 7*4 = 0x44.
        buf[0x14..0x18].copy_from_slice(&7u32.to_le_bytes());
        // export_size = 0x40: includes all directory fields + Name field
        // (0x38) but the functions array end (0x44) > 0x40, while <= 0x200.
        let export_size = 0x40u32;
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, export_size, 0x100)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("AddressOfFunctions") && msg.contains("exceeds export_size"),
            "expected AddressOfFunctions-exceeds-export_size failure, got: {msg}"
        );
    }

    /// delta == 0 must still run full structural validation: a field RVA
    /// outside the directory is rejected even when there is no move.
    #[test]
    fn relocate_zero_delta_still_validates_structure() {
        let mut buf = build_export_blob();
        buf[0x20..0x24].copy_from_slice(&0x3000u32.to_le_bytes()); // AddressOfNames outside dir
        let sz = buf.len() as u32;
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, sz, 0).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    /// End-to-end: build a synthetic PE with `.text` + `.edata`, run it through
    /// the real `write_output_file`, then read the `.edata` payload back from
    /// `PointerToRawData` in the written file and parse the named export, its
    /// ordinal, and the forwarder string.  No real target process is touched.
    #[test]
    fn write_output_file_round_trips_edata_exports() {
        let export_blob = build_export_blob();
        let export_size = export_blob.len() as u32;
        let mut pe = pe_with_text_section(0x1000, 0x200);
        pe.nt_headers.optional_header.data_directory[0] = ImageDataDirectory {
            virtual_address: ORIGINAL_EXPORT_RVA,
            size: export_size,
        };
        create_edata_section(&mut pe, &export_blob, export_size, ORIGINAL_EXPORT_RVA).unwrap();
        pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;

        let edata_va = pe
            .sections
            .iter()
            .find(|s| s.name.starts_with(".edata"))
            .unwrap()
            .virtual_address;
        let image_base = pe.image_base;
        let entry_point = pe.entry_point;
        // write_section_data slices dump_buf by SizeOfImage even when a section
        // has no extra_data (.text); provide a zeroed image-sized buffer.
        let dump_buf = vec![0u8; pe.size_of_image() as usize];

        // Real pipeline call: empty dump_buf / thunks / containers are safe —
        // write_output_file early-returns on the IAT paths and .text falls
        // back to zeros (we only assert .edata here).
        let opts = DumpOptions {
            image_base,
            entry_point,
            fix_imports: false,
            create_data_sections: false,
            shrink: false,
            output_path: std::path::PathBuf::from("NUL"),
            iat_location: None,
            additional_iat_locations: Vec::new(),
            executable_path: None,
            early_section_snapshots: Vec::new(),
            container_restore: crate::ContainerRestoreMode::Off,
            profile: crate::DumpProfile::OreansClassic,
            security_cookie_rva: None,
            security_cookie_complement_rva: None,
            pure_rebuild: false,
        };
        let out_data = write_output_file(
            &mut pe,
            &dump_buf,
            None,
            &[],
            0,
            true,
            &opts,
            entry_point,
            &[],
        )
        .expect("write_output_file must succeed on synthetic PE");

        // Re-parse the written file and locate .edata by its on-disk layout.
        let reparsed = PeHeader::from_bytes(&out_data).expect("re-parse written PE");
        let edata_sec = reparsed
            .sections
            .iter()
            .find(|s| s.name.starts_with(".edata"))
            .expect(".edata section present in written file");
        assert_eq!(edata_sec.virtual_address, edata_va);
        let ptr = edata_sec.header.pointer_to_raw_data as usize;
        assert!(ptr != 0, "PointerToRawData must be non-zero");
        let raw = edata_sec.header.size_of_raw_data as usize;
        assert!(raw >= export_size as usize);
        let blob = &out_data[ptr..ptr + export_size as usize];

        // Parse the IMAGE_EXPORT_DIRECTORY from the on-disk blob.
        let rd = |o: usize| u32::from_le_bytes(blob[o..o + 4].try_into().unwrap());
        let addr_funcs = rd(0x1C);
        let addr_names = rd(0x20);
        let addr_ordinals = rd(0x24);
        // Directory fields were relocated to edata_va + original_offset.
        assert_eq!(addr_funcs, edata_va + 0x28);
        assert_eq!(addr_names, edata_va + 0x30);
        assert_eq!(addr_ordinals, edata_va + 0x34);

        // Name RVA array[0] → "Func1" string.
        let names_off = (addr_names - edata_va) as usize;
        let name_rva = u32::from_le_bytes(blob[names_off..names_off + 4].try_into().unwrap());
        assert_eq!(name_rva, edata_va + 0x48);
        let name_off = (name_rva - edata_va) as usize;
        let name_end = blob[name_off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_off + p)
            .unwrap();
        assert_eq!(&blob[name_off..name_end], b"Func1");

        // Ordinal array[0] → index 1 (points at the forwarder slot).
        let ord_off = (addr_ordinals - edata_va) as usize;
        let ord_idx = u16::from_le_bytes(blob[ord_off..ord_off + 2].try_into().unwrap());
        assert_eq!(ord_idx, 1);

        // Functions array[1] (the ordinal-targeted slot) is a forwarder RVA
        // inside the .edata directory → forwarder string.
        let funcs_off = (addr_funcs - edata_va) as usize;
        let fwd_slot = funcs_off + ord_idx as usize * 4;
        let fwd_rva = u32::from_le_bytes(blob[fwd_slot..fwd_slot + 4].try_into().unwrap());
        assert!(
            fwd_rva >= edata_va && fwd_rva < edata_va + export_size,
            "forwarder RVA must lie inside .edata"
        );
        let fwd_off = (fwd_rva - edata_va) as usize;
        let fwd_end = blob[fwd_off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| fwd_off + p)
            .unwrap();
        assert_eq!(&blob[fwd_off..fwd_end], b"ntdll.NtCreateFile");
    }

    /// Precise regression: a buffer that is physically >= 40 bytes but whose
    /// *declared* `export_size` < 40 must be rejected BEFORE the directory is
    /// read — even when every directory field is zero.  This prevents
    /// zero-padded garbage from being interpreted as a valid directory.
    #[test]
    fn relocate_rejects_small_export_size_even_with_large_buffer_and_zero_fields() {
        // 64-byte zero buffer (>= 40), export_size = 32 (< 40), all fields zero.
        let mut buf = vec![0u8; 64];
        let err = relocate_export_table_rvas(&mut buf, ORIGINAL_EXPORT_RVA, 32, 0x100)
            .expect_err("export_size < 40 must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("declared export_size (32)") && msg.contains("IMAGE_EXPORT_DIRECTORY"),
            "expected declared-export_size-too-small failure, got: {msg}"
        );
        // delta == 0 must also reject (validation runs regardless of delta).
        let mut buf2 = vec![0u8; 64];
        let err2 = relocate_export_table_rvas(&mut buf2, ORIGINAL_EXPORT_RVA, 32, 0)
            .expect_err("export_size < 40 must be rejected at delta=0 too");
        assert!(format!("{err2}").contains("declared export_size (32)"));
    }

    /// Production path: `create_edata_section` must propagate the short-
    /// export_size rejection.  A short DataDirectory.Size must NOT be masked
    /// by the raw-data padding that `create_edata_section` applies.
    #[test]
    fn create_edata_section_rejects_short_export_size_not_masked_by_padding() {
        let mut pe = pe_with_text_section(0x1000, 0x200);
        pe.nt_headers.optional_header.data_directory[0] = ImageDataDirectory {
            virtual_address: ORIGINAL_EXPORT_RVA,
            // Declared size 32 — too small for a directory.
            size: 32,
        };
        // Blob physically >= 40 bytes; padding would otherwise hide the
        // short declared size.
        let blob = vec![0u8; 64];
        let err = create_edata_section(&mut pe, &blob, 32, ORIGINAL_EXPORT_RVA)
            .expect_err("short export_size must be rejected by create_edata_section");
        assert!(
            format!("{err}").contains("declared export_size (32)"),
            "create_edata_section must surface the short-size failure"
        );
        // No .edata section must have been appended on failure.
        assert!(
            pe.sections.iter().all(|s| !s.name.starts_with(".edata")),
            "no .edata section must be created on rejection"
        );
    }
}
