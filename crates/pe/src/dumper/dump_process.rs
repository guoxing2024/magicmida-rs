//! Main dump orchestration ?`dump_process` and `dump_dotnet`.
//!
//! Extracted from `dumper.rs` ?corresponds to `TDumper.DumpToFile`
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
/// forwarder RVAs ?those that fall within
/// `[original_export_rva, original_export_rva + export_size)` ?are shifted
/// by `delta`.  Code RVAs are left untouched: the code did not move.
///
/// `AddressOfNameOrdinals` array *elements* are ordinals (not RVAs) and are
/// never adjusted ?only the directory field (0x24) is relocated.
///
/// # Fail-closed
///
/// Every count, array offset, and bound is validated.  On overflow, an array
/// running out of the export buffer, or a field RVA outside the export
/// directory range, this returns [`PeError`] rather than writing garbage.
///
/// # Arguments
///
/// - `export_data` ?the full export directory blob (directory + arrays +
///   strings) captured from the original export range.  Offsets within it are
///   `rva - original_export_rva`.
/// - `original_export_rva` ?the RVA the export directory had *before* the
///   move (used to validate that fields point inside the directory and to
///   classify forwarder vs code RVAs).
/// - `export_size` ?the size of the original export directory range.
///   `export_data.len()` may be larger (padding) but must be `>= export_size`.
/// - `delta` ?`new_export_rva.wrapping_sub(original_export_rva)`.
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
        // Relocate each function RVA: forwarder (inside dir)  -> +delta;
        // code RVA (outside dir)  -> unchanged.  Zero entries are skipped
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
            // else: code RVA ?leave unchanged.
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
use super::types::{DumpOptions, DumpProcessReport, EarlySectionSnapshot};

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
    dump_process_with_report(debugger, opts).map(|_| ())
}

/// Dump a PE image and return the evidence collected after the final candidate
/// has been serialized successfully.  The compatibility [`dump_process`]
/// wrapper above intentionally discards this report.
pub fn dump_process_with_report(
    debugger: &mut dyn mida_core::DebuggerCore,
    opts: &DumpOptions,
) -> Result<DumpProcessReport, PeError> {
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

    // Capture immutable runtime TLS evidence before any header patch, shrink,
    // sanitize, or section reconstruction changes the parsed PE semantics.
    let tls_report =
        crate::tls_observation::observe_tls_runtime(&pe, opts.image_base, |address, buffer| {
            let native_address = usize::try_from(address)
                .map_err(|_| format!("TLS reader address {address:#x} does not fit usize"))?;
            debugger
                .read_memory(native_address, buffer)
                .map_err(|error| error.to_string())
        });
    // Freeze relocation facts before header patching, shrinking, sanitizing,
    // or rebuilding .reloc. Rebuilt relocation bytes are never runtime proof.
    // preferred_image_base is the on-disk PE base (the runtime `pe.image_base`
    // may be the ASLR load base); read it from the disk executable when
    // available so relocation image identity matches the PE evidence.
    let preferred_image_base = opts
        .executable_path
        .as_ref()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| crate::header::PeHeader::from_bytes(&bytes).ok())
        .map(|disk_pe| disk_pe.nt_headers.optional_header.image_base)
        .unwrap_or_else(|| pe.image_base);
    let relocation_report = crate::relocation_observation::observe_relocations_runtime(
        &pe,
        opts.image_base,
        preferred_image_base,
        |address, buffer| {
            let native_address = usize::try_from(address).map_err(|_| {
                format!("relocation reader address {address:#x} does not fit usize")
            })?;
            debugger
                .read_memory(native_address, buffer)
                .map_err(|error| error.to_string())
        },
    );

    // 1a. Validate and patch PE header fields
    validate_and_patch_pe_header(&mut pe, opts)?;

    // 1b. Always capture Exception DD ?needed for shrink restore *and* for
    // no-shrink dumps where the table lives in a zero-raw Themida section
    // (R0B: exception_no_raw / directory_start_unmapped).
    const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
    let exc_dir0 = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    let mut saved_exception_rva: Option<(u32, u32)> =
        if exc_dir0.virtual_address != 0 && exc_dir0.size != 0 {
            Some((exc_dir0.virtual_address, exc_dir0.size))
        } else {
            None
        };

    // 1c. Shrink: remove Themida-specific sections if requested.
    if opts.shrink {
        if let Some(exc) = shrink_sections(&mut pe) {
            saved_exception_rva = Some(exc);
        }
    }

    // 1c2. Snapshot Exception raw-backing *before* sanitize().
    // sanitize() sets SizeOfRawData = VirtualSize for every dump-backed
    // section (including zero-raw .themida), which would make a post-sanitize
    // lacks-raw check falsely report coverage. Holdout Oreans needs this
    // pre-sanitize signal to force .pdata materialization after trim.
    let force_pdata_no_shrink = !opts.shrink
        && saved_exception_rva
            .map(|(r, s)| exception_directory_lacks_raw(&pe, r, s))
            .unwrap_or(false);
    if force_pdata_no_shrink {
        if let Some((exc_rva, exc_size)) = saved_exception_rva {
            info!(
                exc_rva = format!("{exc_rva:#x}"),
                exc_size = format!("{exc_size:#x}"),
                "Exception directory lacks raw backing in process PE (will create .pdata after trim)"
            );
        }
    }

    // 1d. Preserve export table for AutoHotkey and other DLLs
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
    let (iat_image, _iat_image_size, mut import_builder, iat_report) = if opts.fix_imports {
        let (iat_image, iat_size, import_builder, report) = rebuild_import_table_complete(
            debugger,
            &mut pe,
            opts.image_base,
            is_64bit,
            opts.iat_location,
        )?;
        (iat_image, iat_size, import_builder, Some(report))
    } else {
        (Vec::new(), 0usize, None, None)
    };

    if let Some(report) = iat_report.as_ref().filter(|_| opts.fix_imports) {
        if !report.is_complete() {
            warn!(reason = %report.failure_summary(), "IAT recovery is incomplete; percentage/threshold gates are disabled");
        }
    }

    // Determine the original IAT RVA
    let original_iat_rva = if let Some((addr, _)) = opts.iat_location {
        u32::try_from(addr.wrapping_sub(opts.image_base as usize)).unwrap_or(0)
    } else {
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address
    };

    // 2b. Choose live rebuild vs original-PE import fallback.
    //
    // Holdout Oreans (stub on-disk imports, fat runtime IAT):
    // - Live rebuild may report "77%" against *all* slots including zeros, then
    //   wrongly fall back to original PE which only has ~10 thunks ?far worse.
    // Rules:
    // 1. Denominator = non-zero live IAT slots (zeros are module delimiters).
    // 2. Fall back to original only when it has *more* thunks than rebuild
    //    (never replace a richer rebuild with a Themida-stub import table).
    let mut _resolved_imports: std::collections::HashMap<(String, String), usize> =
        std::collections::HashMap::new();
    if opts.fix_imports {
        let live_empty = import_builder.as_ref().is_none_or(|b| b.thunk_count() == 0);
        let use_original = if live_empty {
            true
        } else if !iat_report
            .as_ref()
            .is_some_and(|report| report.is_complete())
        {
            // Fail closed: an incomplete live report may be useful for
            // diagnostics, but it is never sufficient for the perfect gate.
            warn!(
                reason = %iat_report
                    .as_ref()
                    .map_or_else(|| "IAT evidence missing".to_string(), |report| report.failure_summary()),
                "IAT recovery incomplete; refusing to treat live table as complete"
            );
            true
        } else {
            false
        };

        if use_original {
            if let Some(ref ep) = opts.executable_path {
                if let Some(fallback_builder) =
                    build_import_table_from_original(&pe, ep, original_iat_rva)
                {
                    info!(
                        "Using original PE import table (Magicmida approach): {} modules, {} thunks",
                        fallback_builder.modules.len(),
                        fallback_builder.thunk_count()
                    );
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

    // 2d. Build function-name  -> resolved address map
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
    for s in &pe.sections {
        if s.virtual_size > 0x100000 {
            info!(
                "POST-SANITIZE: {} va={:#x} vsz={:#x} raw={:#x} ptr={:#x}",
                s.name,
                s.virtual_address,
                s.virtual_size,
                s.header.size_of_raw_data,
                s.header.pointer_to_raw_data
            );
        }
    }

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
    // Fail-closed: incomplete image must not become a managed candidate
    // (zero-filled holes previously continued to emit + bound manifest).
    if read < dump_size {
        return Err(PeError::Parse(format!(
            "Short read on dump image: got {read:#x} bytes, need {dump_size:#x}"
        )));
    }

    // GTO/AHK experimental stages are gated by DumpProfile (default OreansClassic).
    // Never re-guess profile from filename/SHA/section names ?only opts.profile.
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
    let capture_policy = opts
        .capture_policy
        .clone()
        .resolve_for_profile(opts.profile);
    let mut heap_globals = if stage_plan.detect_heap_globals {
        super::heap_global_snapshot::detect_heap_globals(&pe, &dump_buf, debugger, &capture_policy)
    } else {
        Vec::new()
    };
    // ---- R0-C.1: capture the RAW heap slab and RAW children BEFORE transforms ----
    // The transforms below (scrub/repair/sort/sanitize) rewrite the child payloads
    // offline. The slab must be captured from the same live state as the raw
    // children so raw coherence can be proven, then the transformed bytes are
    // overlaid onto a patched backing slab. Only when MIDA_GTO_NO_BYPASS=1.
    let no_bypass = std::env::var("MIDA_GTO_NO_BYPASS").ok().as_deref() == Some("1");
    let mut raw_capture: Option<super::raw_slab_coherence::RawSlabCapture> = None;
    if no_bypass && stage_plan.detect_heap_globals {
        if let Some(raw_slab) =
            super::heap_global_snapshot::capture_heap_slab(&heap_globals, debugger)
        {
            // R0-E: reconcile duplicate captures at the same live_ptr using
            // raw-slab coherence (the slab is the physical-memory ground truth)
            // BEFORE snapshotting raw children, so the raw child set matches
            // the deduped (authoritative) heap_globals. Prevents two
            // transformed children on one slab range with differing bytes from
            // tripping the overlay OverlayConflict (Route M R1 blocker). Runs
            // on RAW snapshots before any transform.
            super::heap_global_snapshot::reconcile_duplicate_heap_globals(
                &mut heap_globals,
                Some(&raw_slab),
            );
            let raw_children =
                super::raw_slab_coherence::raw_children_from_capture(&containers, &heap_globals);
            raw_capture = Some(super::raw_slab_coherence::RawSlabCapture {
                slab: raw_slab,
                children: raw_children,
            });
        }
    }
    // Track capture/transform provenance (taxonomy v1 capture-class transforms).
    let mut capture_transforms: Vec<(&'static str, &'static str)> = Vec::new();
    let mut overlay_ledger: Vec<super::raw_slab_coherence::TransformedRegionOverlay> = Vec::new();
    if raw_capture.is_some() {
        capture_transforms.push(("heap_slab_raw_capture", "capture"));
    }
    // Zero dangling inter-object pointers that fall outside captured ranges so
    // post-CRT restore does not hand ntdll stale heap addresses (RtlpFindEntry).
    let image_end = (opts.image_base as u64).saturating_add(pe.size_of_image() as u64);
    if stage_plan.scrub_uncaptured_heap_pointers {
        let before = heap_globals.clone();
        super::heap_global_snapshot::scrub_uncaptured_heap_pointers(
            &mut containers,
            &mut heap_globals,
            opts.image_base as u64,
            image_end,
        );
        super::heap_global_snapshot::record_transform_applied(
            &mut heap_globals,
            &before,
            "scrub_uncaptured_heap_pointers",
        );
    }
    // R-GTO-UI r17b: scrub walks every qword and can clear gscript count@+0x10
    // when the live dword was embedded in a pointer-shaped qword. Re-apply
    // table-derived label count after scrub so bootstrap payload keeps it.
    {
        let before = heap_globals.clone();
        super::heap_global_snapshot::resynthesize_gscript_label_count(&mut heap_globals);
        super::heap_global_snapshot::record_transform_applied(
            &mut heap_globals,
            &before,
            "resynthesize_gscript_label_count",
        );
    }
    // R-GTO-UI r18/r19b: scrub / slot-cap leave Label.mName null or dangling
    // while inline UTF-16 remains at +0x30  -> 0x48fb0 wcscmp AV. Repair offline
    // (scrub now also preserves UTF-16-looking qwords).
    {
        let before = heap_globals.clone();
        super::heap_global_snapshot::repair_label_names_after_scrub(&mut heap_globals);
        super::heap_global_snapshot::record_transform_applied(
            &mut heap_globals,
            &before,
            "repair_label_names_after_scrub",
        );
    }
    // R-GTO-UI r20: binary search in 0x48fb0 requires mName-ordered table.
    // Dump capture order is unsorted  -> lookup "A_Args"/others always miss.
    {
        let before = heap_globals.clone();
        super::heap_global_snapshot::sort_gscript_label_table(&mut heap_globals);
        super::heap_global_snapshot::record_transform_applied(
            &mut heap_globals,
            &before,
            "sort_gscript_label_table",
        );
    }
    // R-GTO-UI r21: Label+0x23==0 redirects via +0x10; dump has null nested
    //  -> AV at 0xc13ea after successful A_Args lookup. Mark non-nested.
    {
        let before = heap_globals.clone();
        super::heap_global_snapshot::mark_labels_non_nested(&mut heap_globals);
        super::heap_global_snapshot::record_transform_applied(
            &mut heap_globals,
            &before,
            "mark_labels_non_nested",
        );
    }
    // R-GTO-UI r21b: WinMain re-inits [0x141bf0] after Label bind; dump free-list
    // body AVs later. Zero-slab large enough for re-init stores only.
    {
        let before = heap_globals.clone();
        super::heap_global_snapshot::sanitize_ahk_runtime_global(&mut heap_globals);
        super::heap_global_snapshot::record_transform_applied(
            &mut heap_globals,
            &before,
            "sanitize_ahk_runtime_global",
        );
    }
    // R-GTO-UI r22b / GTO R0-F.2: gscript+0xbd8 must be NewClassName for
    // RegisterClass @0x34db0, and +0xbd0 the CreateWindow title. The window
    // repair now PRODUCES SyntheticRegionRequests (no fixed logical address);
    // the collision-free base is assigned below, after all capture/transform
    // authority ranges are known.
    let synthetic_requests =
        super::heap_global_snapshot::make_gscript_window_string_requests(&heap_globals);

    // ---- GTO R0-F.2: deterministic synthetic logical-address assignment ----
    // Assign collision-free logical bases for synthetic regions (window class /
    // title) avoiding every authority range, materialize them as SyntheticDerived
    // snapshots, and rewrite the anchor pointer slots (gscript+0xbd8/+0xbd0).
    // Must run BEFORE the raw-slab overlay, declared-slot collection, and runtime
    // rebase planning so synthetic regions become independent allocations (never
    // absorbed into the slab). No fallback to a hardcoded address.
    let mut synthetic_assignment_ledger: Vec<super::heap_global_snapshot::SyntheticAssignment> =
        Vec::new();
    // Module map from the live process (external pointer attribution + synthetic
    // authority ranges). Hoisted so the synthetic assignment and the runtime plan
    // share one snapshot of the same live state.
    let module_map: Vec<(String, u64, u64)> = super::remote_modules::take_module_snapshot(
        debugger.process_handle(),
        debugger.pid(),
        opts.image_base,
        pe.is_64bit,
    )
    .unwrap_or_default()
    .into_iter()
    .map(|m| (m.name.clone(), m.base, m.end_off))
    .collect();
    if !synthetic_requests.is_empty() {
        // Authority ranges the synthetic allocator must avoid.
        let mut avoid: Vec<(u64, u64)> = Vec::new();
        // NULL / small-tag range.
        avoid.push((0, super::runtime_rebase::SMALL_TAG_CEILING));
        // Source image span.
        let image_span = (opts.image_base as u64)
            .checked_add(pe.size_of_image() as u64)
            .unwrap_or(u64::MAX);
        avoid.push((opts.image_base as u64, image_span));
        // Raw heap slab span + raw containers + observed heap globals.
        if let Some(raw) = raw_capture.as_ref() {
            let slab_end = raw
                .slab
                .old_base
                .checked_add(raw.slab.content.len() as u64)
                .unwrap_or(u64::MAX);
            avoid.push((raw.slab.old_base, slab_end));
            for c in &raw.children {
                let end = c.old_base.checked_add(c.size as u64).unwrap_or(u64::MAX);
                avoid.push((c.old_base, end));
            }
        }
        for c in &containers {
            let end = c
                .decoded_begin
                .checked_add(c.heap_content.len() as u64)
                .unwrap_or(u64::MAX);
            avoid.push((c.decoded_begin, end));
        }
        for g in &heap_globals {
            if g.is_heap_handle || g.content.is_empty() {
                continue;
            }
            let end = g
                .live_ptr
                .checked_add(g.content.len() as u64)
                .unwrap_or(u64::MAX);
            avoid.push((g.live_ptr, end));
        }
        // External module map ranges (live module snapshot).
        for &(_, base, end) in &module_map {
            if end > base {
                avoid.push((base, end));
            }
        }
        match super::heap_global_snapshot::assign_synthetic_logical_addresses(
            &synthetic_requests,
            &avoid,
        ) {
            Ok(bound) => {
                // GTO R0-F.2.1: assignments are identity-bound (no positional zip).
                // Rewrite + read-back verify each anchor, then materialize and
                // gate a full identity-closed loop BEFORE overlay / planner.
                let mut materialized = Vec::new();
                // Track rewrite evidence for the manifest ledger.
                let mut rewrite_counts: Vec<(String, usize)> = Vec::new();
                // gscript anchor region base (from the first bound request's slot).
                let gscript_base = bound
                    .first()
                    .and_then(|b| b.request.pointer_slots.first())
                    .map(|a| a.region_old_base);
                if let Some(gscript_base) = gscript_base {
                    let mut anchor_regions: Vec<(u64, &mut Vec<u8>)> = heap_globals
                        .iter_mut()
                        .filter(|g| g.live_ptr == gscript_base)
                        .map(|g| (g.live_ptr, &mut g.content))
                        .collect();
                    if anchor_regions.is_empty() {
                        return Err(PeError::GtoStage {
                            stage: "synthetic_anchor_rewrite".into(),
                            error: "gscript anchor region not present in heap_globals".into(),
                        });
                    }
                    // Rewrite anchors bound by identity (each bound pair carries
                    // its own request + assignment).
                    for b in &bound {
                        let rewritten =
                            super::heap_global_snapshot::rewrite_synthetic_anchor_slots(
                                &mut anchor_regions,
                                &b.request.pointer_slots,
                                b.assignment.assigned_logical_old_base,
                            )
                            .map_err(|e| PeError::GtoStage {
                                stage: "synthetic_anchor_rewrite".into(),
                                error: format!("{e:#}"),
                            })?;
                        let expected = b.request.pointer_slots.len();
                        // GTO R0-F.2.1: every anchor must be rewritten AND
                        // read-back verified (rewrite already verifies read-back).
                        if rewritten != expected {
                            return Err(PeError::GtoStage {
                                stage: "synthetic_anchor_rewrite".into(),
                                error: format!(
                                    "synthetic '{}' rewrote {rewritten} anchors, expected {expected}",
                                    b.assignment.synthetic_id
                                ),
                            });
                        }
                        rewrite_counts.push((b.assignment.synthetic_id.clone(), rewritten));
                    }
                } else {
                    // No anchor region; record empty rewrite evidence per bound.
                    for b in &bound {
                        rewrite_counts.push((b.assignment.synthetic_id.clone(), 0));
                    }
                }
                // Materialize (identity-bound, Result-returning). No partial set.
                materialized = super::heap_global_snapshot::materialize_synthetic_regions(&bound)
                    .map_err(|e| PeError::GtoStage {
                    stage: "synthetic_materialization".into(),
                    error: format!("{e:#}"),
                })?;
                // Full identity-closed loop gate: each materialized snapshot's
                // live_ptr must equal its bound assignment base and carry the
                // correct provenance/extent. materialize_synthetic_regions already
                // enforces this; the explicit gate makes the production invariant
                // self-documenting before any overlay/planner step.
                for b in &bound {
                    let snap = materialized
                        .iter()
                        .find(|s| s.live_ptr == b.assignment.assigned_logical_old_base);
                    match snap {
                        Some(s) => {
                            if s.extent_kind
                                != super::heap_global_snapshot::CaptureExtentKind::SyntheticDerived
                                || !matches!(
                                    s.provenance,
                                    super::heap_global_snapshot::RegionProvenance::SyntheticDerived { .. }
                                )
                            {
                                return Err(PeError::GtoStage {
                                    stage: "synthetic_identity_gate".into(),
                                    error: format!(
                                        "synthetic '{}' materialized snapshot provenance/extent inconsistent",
                                        b.assignment.synthetic_id
                                    ),
                                });
                            }
                        }
                        None => {
                            return Err(PeError::GtoStage {
                                stage: "synthetic_identity_gate".into(),
                                error: format!(
                                    "synthetic '{}' materialized snapshot missing at base {:#x}",
                                    b.assignment.synthetic_id,
                                    b.assignment.assigned_logical_old_base
                                ),
                            });
                        }
                    }
                }
                // Persist the manifest ledger (identity-bound assignments).
                synthetic_assignment_ledger = bound
                    .iter()
                    .map(|b| {
                        let rewritten = rewrite_counts
                            .iter()
                            .find(|(id, _)| *id == b.assignment.synthetic_id)
                            .map(|(_, r)| *r)
                            .unwrap_or(0);
                        super::heap_global_snapshot::SyntheticAssignment {
                            synthetic_id: b.assignment.synthetic_id.clone(),
                            request_digest: b.assignment.request_digest.clone(),
                            assigned_logical_old_base: b.assignment.assigned_logical_old_base,
                            assignment_alignment: b.assignment.assignment_alignment,
                            rewritten_anchor_count: rewritten,
                            materialized: true,
                        }
                    })
                    .collect();
                heap_globals.append(&mut materialized);
                for b in &bound {
                    info!(
                        synthetic_id = %b.assignment.synthetic_id,
                        assigned_base = format_args!("{:#x}", b.assignment.assigned_logical_old_base),
                        request_digest = %b.assignment.request_digest,
                        "Assigned collision-free synthetic logical base (identity-bound)"
                    );
                }
            }
            Err(e) => {
                return Err(PeError::GtoStage {
                    stage: "synthetic_assignment".into(),
                    error: format!("{e:#}"),
                });
            }
        }
    }

    // ---- R0-C.1: patched backing slab via transformed-child overlay ----
    // After transforms, build the authoritative backing slab by overlaying the
    // transformed child bytes onto the RAW slab (raw coherence verified). The
    // planner then normalizes against the patched slab + transformed children.
    let transform_ids: &[&'static str] = &[
        "scrub_uncaptured_heap_pointers",
        "resynthesize_gscript_label_count",
        "repair_label_names_after_scrub",
        "sort_gscript_label_table",
        "mark_labels_non_nested",
        "sanitize_ahk_runtime_global",
    ];
    let heap_slab = if let Some(raw) = raw_capture.as_ref() {
        match super::raw_slab_coherence::build_patched_backing_slab(
            raw,
            &heap_globals,
            &containers,
            transform_ids,
        ) {
            Ok((patched, overlays)) => {
                capture_transforms.push(("heap_slab_restore", "capture"));
                // Record overlay ledger into diagnostics (later surfaced in the
                // snapshot manifest / summary).
                overlay_ledger = overlays;
                Some(patched)
            }
            Err(e) => {
                // Raw coherence or overlay failure: fail closed — do NOT silently
                // continue with an un-patched slab or a drift-prone plan.
                return Err(PeError::GtoStage {
                    stage: "raw_slab_overlay".into(),
                    error: format!("{e:#}"),
                });
            }
        }
    } else {
        None
    };
    if heap_slab.is_some() {
        capture_transforms.push(("heap_slab_overlay", "capture"));
    }
    // Cookie + complement RVAs must be captured before early overlay zeros storage.
    // Prefer authoritative site from offline CRT resolve; never fuzzy-rescan when set.
    // B7.2.1: authority resolve/validation failure is a hard dump error (no structural success).
    let mut cookie_site = super::heap_bootstrap::resolve_security_cookie_site(
        &pe,
        &dump_buf,
        opts.security_cookie_rva,
        opts.security_cookie_complement_rva,
    )?;
    // R4-A3: when RW scan is ambiguous (common on GTO heap-rich dumps), recover
    // a unique site from the cookie value already proven by container detect.
    // Never invent a site without a unique live cookie value.
    if cookie_site.is_none() && stage_plan.detect_containers {
        if let Some(cookie) = super::heap_bootstrap::unique_container_cookie(&containers) {
            cookie_site =
                super::heap_bootstrap::find_security_cookie_site_for_value(&pe, &dump_buf, cookie);
        }
    }
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

    // R-GTO-UI r13: preserve live AHK cmd-table count dword @0x147888 before
    // early overlay / data_reinit zeros .data. WinMain indexes the table via
    // *[0x147868]; count lives in a plain .data dword (not a heap slot).
    let cmd_table_count = if capture_policy.is_hot_root(0x147868) {
        let off = 0x147888usize;
        if off + 4 <= dump_buf.len() {
            let n = u32::from_le_bytes(dump_buf[off..off + 4].try_into().unwrap_or([0; 4]));
            if n > 0 && n < 0x10000 {
                Some(n)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

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
        capture_transforms.push(("early_section_overlay", "capture"));
    }

    // Scrub any remaining process-local absolute pointers and encoded
    // container triples that survived the early overlay (polluted baseline).
    // r27 round 6: when MIDA_GTO_NO_BYPASS=1 (VM re-executes), skip .data scrub.
    // The VM initializes .data itself; scrubbing zeros values the VM needs.
    let no_bypass = std::env::var("MIDA_GTO_NO_BYPASS").ok().as_deref() == Some("1");
    if !no_bypass {
        super::data_reinit::reinitialize_zero_filled_data(
            &pe,
            &mut dump_buf,
            opts.executable_path.as_deref(),
        );
    } else {
        info!("R-GTO-UI r27: skipping .data scrub (NO_BYPASS ?VM re-executes, initializes .data itself)");
    }

    // R-GTO-UI round 5/7: re-init CRITICAL_SECTION objects in `.data` whose
    // captured lock state (zeroed/stale) would AV/deadlock
    // `RtlEnterCriticalSection` when WinMain re-enters them. Driven by
    // `DumpCapturePolicy::cs_reinit_rvas`.
    if !capture_policy.cs_reinit_rvas.is_empty() {
        super::data_reinit::reinit_critical_sections(&mut dump_buf, &capture_policy.cs_reinit_rvas);
        // Sample-policy CS list  -> disclose (taxonomy: pe_repair / cs_reinit).
        capture_transforms.push(("cs_reinit", "pe_repair"));
    }

    if let Some(n) = cmd_table_count {
        let off = 0x147888usize;
        if off + 4 <= dump_buf.len() {
            dump_buf[off..off + 4].copy_from_slice(&n.to_le_bytes());
            info!(
                rva = format_args!("{:#x}", 0x147888u32),
                count = n,
                "Preserved AHK cmd-table count dword through overlay"
            );
        }
    }

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
        warn!("Could not plant default SecurityCookie ?CRT may skip cookie init");
    }

    // 4b. Shrink path: Themida sections deleted ?restore Exception + reloc
    // placeholders before import/bootstrap layout. No-shrink .pdata is deferred
    // until after trim_huge_sections (see 5d/5d2): sanitize() temporarily sets
    // SizeOfRawData = VirtualSize on zero-raw .themida, which would make an
    // early lacks-raw check false; trim then collapses that raw back to ~0,
    // leaving Exception DD unmapped (R0B exception_no_raw).
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
    //     patches runtime ImageBase  -> file ImageBase, not VA shifts.
    //     Keeping original VAs avoids this problem ?the gaps are
    //     unused memory and don't affect file size (sanitize sets
    //     ptr=VA so the file only contains actual section data).
    // if opts.shrink {
    //     compact_and_shift(&mut pe, &mut dump_buf);
    //     pe.sanitize();
    // }

    // 5b. Heap / container bootstrap (AhkGtoExperimental only).
    // Dump buffer must be mutable so post-CRT can rewrite the CRT wrapper jmp.
    // OreansClassic: never install heap/container bootstrap.
    // R-GTO-UI: plant targets outside classic .data (Themida RX) need WRITE.
    if stage_plan.install_heap_bootstrap || stage_plan.detect_heap_globals {
        let n = super::heap_global_snapshot::ensure_plant_target_sections_writable(
            &mut pe,
            &heap_globals,
        );
        if n > 0 {
            info!(
                sections_marked = n,
                "Heap-global plant targets marked MEM_WRITE"
            );
        }
    }
    let cookie_mirror = match (
        capture_policy.cookie_mirror_src_rva,
        capture_policy.cookie_mirror_dst_rva,
    ) {
        (Some(src), Some(dst)) if src != 0 && dst != 0 && src != dst => Some((src, dst)),
        _ => None,
    };
    // 5b2. Build import section BEFORE heap bootstrap so the stub can resolve
    // helper imports (VirtualAlloc for heap-slab remap) from the built IAT.
    // Both create_section_index calls append sections; order is safe.
    // r27: ensure VirtualAlloc is imported BEFORE building the import section
    // so the thunk gets an IAT slot assigned during section build.
    if stage_plan.install_heap_bootstrap {
        if let Some(builder) = import_builder.as_mut() {
            builder.ensure_function("kernel32.dll", "VirtualAlloc");
        }
    }

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

    // GTO R0-B: the runtime rebase plan + diagnostic summary. `None` unless the
    // AhkGtoExperimental recovery installed a validated plan-driven bootstrap.
    let mut rebase_summary: Option<super::runtime_rebase::RuntimeRebaseSummary> = None;

    let output_entry_point = if stage_plan.install_heap_bootstrap {
        // Build the authoritative plan from the captured allocations + declared
        // pointer slots + external resolvers + module map. Fail closed on any
        // structural or unresolved-required condition.
        let new_image_base = pe.nt_headers.optional_header.image_base;

        // Declared pointer slots from the capture descriptor (pointer-shaped
        // qwords inside captured allocations). Provenance-driven.
        let declared_slots = super::runtime_rebase::declared_slots_from_capture(
            &containers,
            &heap_globals,
            heap_slab.as_ref(),
        );

        // External resolvers from the rebuilt import table (ASLR-safe via IAT).
        let external_resolvers = match import_builder.as_ref() {
            Some(builder) => {
                let read_live = |rva: u64| -> Option<u64> {
                    let mut buf = [0u8; 8];
                    let va = opts.image_base + rva;
                    debugger.read_memory(va as usize, &mut buf).ok()?;
                    Some(u64::from_le_bytes(buf))
                };
                match super::runtime_rebase::build_external_resolvers_from_imports(
                    builder,
                    &module_map,
                    &read_live,
                ) {
                    Ok(t) => t,
                    Err(e) => {
                        return Err(PeError::GtoStage {
                            stage: "external_resolver_build".into(),
                            error: format!("{e:#}"),
                        });
                    }
                }
            }
            None => super::runtime_rebase::ExternalResolverTable::default(),
        };

        let prepared = match super::runtime_rebase::prepare_runtime_rebase_for_dump(
            &containers,
            &heap_globals,
            heap_slab.as_ref(),
            &declared_slots,
            &external_resolvers,
            &module_map,
            opts.image_base,
            new_image_base,
            opts.entry_point,
            true, // require_capture: empty plan is a hard error
        ) {
            Ok(p) => p,
            Err(e) => {
                return Err(PeError::GtoStage {
                    stage: "runtime_rebase_plan_validation".into(),
                    error: format!("{e:#}"),
                });
            }
        };

        // Install the plan-driven bootstrap. Strong Result — no None fallback.
        let installed = match import_builder.as_ref() {
            Some(builder) => super::heap_bootstrap::install_heap_bootstrap(
                &mut pe,
                &mut dump_buf,
                builder,
                opts.entry_point,
                &prepared,
                opts.container_restore,
                cookie_rva,
                cookie_mirror,
            ),
            None => Err(super::runtime_bootstrap::HeapBootstrapError::MissingImport(
                "import_builder",
            )),
        };
        let installed = match installed {
            Ok(v) => v,
            Err(e) => {
                return Err(PeError::GtoStage {
                    stage: "bootstrap_install".into(),
                    error: format!("{e:#}"),
                });
            }
        };

        // Post-install contract validation before write.
        let tls_rva = pe.nt_headers.optional_header.data_directory[9]
            .virtual_address
            .ne(&0)
            .then_some(pe.nt_headers.optional_header.data_directory[9].virtual_address);
        let contract = super::runtime_rebase::validate_bootstrap_contract(
            &pe,
            installed.boot_rva,
            tls_rva,
            installed.original_oep_rva,
            installed.region_count,
            installed.completion_cookie_rva,
            &installed.contract_layout,
        );
        let contract_valid = contract.is_ok();
        if let Err(e) = contract {
            return Err(PeError::GtoStage {
                stage: "bootstrap_contract_validation".into(),
                error: format!("{e:#}"),
            });
        }
        // Emitted digest must match the prepared plan digest.
        if installed.emitted_plan_digest != prepared.plan.plan_digest {
            return Err(PeError::GtoStage {
                stage: "bootstrap_plan_digest_mismatch".into(),
                error: format!(
                    "emitted {} != prepared {}",
                    installed.emitted_plan_digest, prepared.plan.plan_digest
                ),
            });
        }

        // Finalize the summary (Complete only if everything holds).
        let summary = match super::runtime_rebase::finalize_summary_after_install(
            &prepared,
            Some(installed.boot_rva),
            Some(installed.completion_cookie_rva),
            &installed.bootstrap_kind,
            contract_valid,
            &installed.emitted_plan_digest,
        ) {
            Ok(s) => s,
            Err(e) => {
                return Err(PeError::GtoStage {
                    stage: "final_summary_not_complete".into(),
                    error: format!("{e:#}"),
                });
            }
        };
        info!(
            regions_total = summary.regions_total,
            fixup_count = summary.fixup_count,
            resolver_count = summary.resolver_count,
            unresolved_required = summary.unresolved_required,
            boot_rva = format_args!("{:#x}", installed.boot_rva),
            cookie_rva = format_args!("{:#x}", installed.completion_cookie_rva),
            digest = %summary.deterministic_plan_digest,
            status = summary.recovery_status.label(),
            "GTO R0-B: plan-driven runtime bootstrap installed and validated"
        );
        rebase_summary = Some(summary);
        capture_transforms.push(("heap_bootstrap", "capture"));
        installed.entry_point_rva
    } else {
        opts.entry_point
    };

    // 5c. Import section already built in 5b2 (before heap bootstrap).
    if import_builder.is_none() {
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
    // that still hold live decrypted code ?without this, wrappers call into
    // empty BSS (e.g. .wfix `call 0x334c98`  -> C0000005 / C0000409).
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

    // R-GTO-UI round 9: Themida multi-block IAT leaves zero separators that a
    // residual set of call sites still reference  -> call [null] AV. Retarget
    // those sites to the rebuilt FirstThunk for MessageBoxW / LocalFree /
    // SendMessageW (heuristics + original import gap names). AhkGto only.
    if stage_plan.patch_wrapper_iat_call_sites {
        if let Some(ref builder) = import_builder {
            let gap = super::iat_gap_retarget::retarget_iat_gap_call_sites(
                &pe,
                &mut dump_buf,
                original_iat_rva,
                iat_size_bytes,
                builder,
                opts.executable_path.as_deref(),
            );
            if gap.sites_seen > 0 {
                info!(
                    interior_zeros = gap.interior_zeros,
                    mapped_gaps = gap.mapped_gaps,
                    sites_seen = gap.sites_seen,
                    sites_patched = gap.sites_patched,
                    "iat_gap_retarget result"
                );
            }
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
    for s in &pe.sections {
        if s.virtual_size > 0x100000 {
            info!(
                "POST-TRIM: {} va={:#x} vsz={:#x} raw={:#x} ptr={:#x}",
                s.name,
                s.virtual_address,
                s.virtual_size,
                s.header.size_of_raw_data,
                s.header.pointer_to_raw_data
            );
        }
    }

    // 5d2. No-shrink: materialize .pdata when Exception DD lacks raw backing.
    // Prefer the pre-sanitize snapshot (force_pdata_no_shrink); also re-check
    // post-trim in case layout mutation cleared coverage that sanitize
    // temporarily invented. Must run after trim and before write_output_file.
    if !opts.shrink {
        if let Some((exc_rva, exc_size)) = saved_exception_rva {
            let still_lacks = exception_directory_lacks_raw(&pe, exc_rva, exc_size);
            if force_pdata_no_shrink || still_lacks {
                info!(
                    exc_rva = format!("{exc_rva:#x}"),
                    exc_size = format!("{exc_size:#x}"),
                    force_pre_sanitize = force_pdata_no_shrink,
                    still_lacks_after_trim = still_lacks,
                    "Creating .pdata for no-shrink Exception DD raw-backing"
                );
                create_pdata_section(
                    &mut pe,
                    &dump_buf,
                    exc_rva,
                    exc_size,
                    opts.executable_path.as_deref(),
                );
            }
        }
    }

    // 5e. Rebuild .edata section for AutoHotkey and other DLLs.
    //
    // CRITICAL: This must run BEFORE write_output_file so the section goes
    // through the unified serialize flow (`serialize_headers` then
    // `write_section_data`).  The old code appended .edata AFTER serialization,
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
        // Phase-2 live parity with legacy write_output_file:
        // - Use host-patched ImageBase (preferred base from on-disk PE), not
        //   the runtime ASLR base in DumpOptions.image_base.
        // - Keep host exception/reloc *content sections* (e.g. .winlice may
        //   contain the exception directory). Typed rebind would skip those
        //   cover sections and re-emit trailing .pdata/.reloc, diverging from
        //   legacy layout on Oreans samples.
        // - Do not force DYNAMIC_BASE; header_patch already cleared it for fixed base.
        // Prefer optional_header (authoritative after header_patch) then
        // pe.image_base cache. Never fall back to DumpOptions.image_base
        // (runtime ASLR) for emit.
        let preferred_base = {
            let oh = pe.nt_headers.optional_header.image_base;
            if oh != 0 {
                oh
            } else if pe.image_base != 0 {
                pe.image_base
            } else {
                0
            }
        };
        let pure_opts = super::pure_rebuild_adapter::PureRebuildEmitOptions {
            image_base: preferred_base,
            entry_point_rva: output_entry_point,
            rebind_exceptions: false,
            rebind_relocations: false,
            // P8-E: preserve ASLR when the (post-patch) PE still requests it.
            // header_patch only clears DYNAMIC_BASE for genuinely fixed-base
            // inputs, so prefer_aslr_when_relocs should mirror that bit: a
            // candidate that rebuilds a full `.reloc` and whose original
            // requested ASLR must keep DYNAMIC_BASE in the emitted image.
            prefer_aslr_when_relocs: (pe.nt_headers.optional_header.dll_characteristics & 0x0040)
                != 0,
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

    // Verify AddressOfEntryPoint only (OptionalHeader + 16). Never use
    // e_lfanew+24+SizeOfOptionalHeader ?that lands on the section table and
    // writing there corrupts the first section's SizeOfRawData (audit P0).
    if output_entry_point != 0 {
        if let Some(file_ep) = read_address_of_entry_point(&out_data) {
            if file_ep != output_entry_point {
                warn!(
                    file_ep = format_args!("{file_ep:#x}"),
                    expected = format_args!("{output_entry_point:#x}"),
                    "AddressOfEntryPoint mismatch after serialize ?correcting"
                );
                patch_address_of_entry_point(&mut out_data, output_entry_point);
            }
        }
    }

    // GTO sample-specific diagnostic bypasses. HARD GATED:
    // - only DumpProfile::AhkGtoExperimental (never OreansClassic / generic)
    // - only when MIDA_GTO_BYPASS=1 (opt-in; default OFF)
    // Products with these patches are diagnostic-only and must not be Accepted
    // as behavior-equivalent (see PROJECT_GOAL / audit P1).
    let gto_bypass = matches!(opts.profile, crate::DumpProfile::AhkGtoExperimental)
        && std::env::var("MIDA_GTO_BYPASS").ok().as_deref() == Some("1");
    // In-memory transform list for post-write fail-closed artifact manifest.
    // Start from capture-class rows recorded earlier (taxonomy v1 ?4.3).
    let mut applied_transforms: Vec<(&'static str, &'static str)> = capture_transforms;
    if gto_bypass {
        warn!("R-GTO-UI: MIDA_GTO_BYPASS=1 ?applying diagnostic sample patches (NOT product-Accepted)");
        patch_gto_skip_loadfile_reentry(&mut out_data);
        patch_gto_registerclass_classname(&mut out_data);
        patch_gto_skip_msgloop_crash(&mut out_data);
        patch_gto_skip_winmain_messagebox(&mut out_data);
        applied_transforms.extend_from_slice(&[
            ("gto_bypass_loadfile", "sample_bypass"),
            ("gto_bypass_registerclass", "sample_bypass"),
            ("gto_bypass_msgloop", "sample_bypass"),
            ("gto_bypass_messagebox", "sample_bypass"),
        ]);
    }

    // DEBUG: Verify section 1 characteristics
    debug_section_chars(&out_data, "Before fix_hardcoded_addresses");

    // Fix hardcoded runtime addresses
    crate::postprocess::fix_hardcoded_addresses(&mut out_data, Some(opts.image_base), is_64bit)?;

    debug_section_chars(&out_data, "After fix_hardcoded_addresses");

    // === Pascal: repack section layout ===
    if opts.shrink {
        crate::postprocess::pack_section_layout(&mut out_data, &pe)?;
    }

    // === Pascal: build relocation table ===
    if opts.shrink {
        crate::postprocess::build_relocation_table(&mut out_data, None, is_64bit)?;
    }

    // Refuse to clobber the protected input when output path aliases it (audit P1).
    if let Some(src) = opts.executable_path.as_deref() {
        if output_aliases_input(src, &opts.output_path) {
            return Err(PeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to overwrite input '{}' with dump output",
                    src.display()
                ),
            )));
        }
    }

    // Atomic-ish emit: write exclusive temp beside target, re-check alias on
    // the temp identity path, then rename. Narrows check/write TOCTOU where
    // a hard link can be planted after the alias probe (audit residual).
    write_output_atomic(
        &opts.output_path,
        &out_data,
        opts.executable_path.as_deref(),
    )?;

    // Always emit a bound transform manifest (empty ledger for clean dumps) so
    // stale sibling manifests from prior bypass runs cannot poison clean re-runs,
    // and acceptance can require the file by default (audit residual).
    if let Err(e) = write_bound_transform_manifest(
        &opts.output_path,
        &out_data,
        &applied_transforms,
        opts.executable_path.as_deref(),
    ) {
        // Fail-closed cleanup must not be best-effort: report residual paths.
        let cleanup = remove_dump_and_manifest(&opts.output_path);
        return Err(match cleanup {
            Ok(()) => e,
            Err(ce) => PeError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "transform_manifest failed ({e}); also failed to remove residual dump/manifest: {ce}"
                ),
            )),
        });
    }

    info!(
        path = %opts.output_path.display(),
        size = out_data.len(),
        sections = pe.sections.len(),
        "Dump written successfully"
    );

    // Observable capture contract (best-effort sidecar). Never fails the dump.
    // `capture_policy` is the resolved policy used for heap capture above.
    super::snapshot_manifest::write_dump_snapshot_manifest(
        &opts.output_path,
        opts.profile,
        opts.image_base,
        output_entry_point,
        &containers,
        &heap_globals,
        &capture_policy,
        rebase_summary.as_ref(),
        &overlay_ledger,
        &synthetic_requests,
        &synthetic_assignment_ledger,
    );

    // The report is returned only after the candidate and its required bound
    // manifest have both been written successfully.  Any earlier error exits
    // without a success report.
    let iat_evidence_complete = iat_report
        .as_ref()
        .is_some_and(|report| report.is_complete());
    Ok(DumpProcessReport {
        fix_imports_requested: opts.fix_imports,
        iat_evidence_present: iat_report.is_some(),
        iat_evidence_complete,
        iat_report,
        tls_evidence_present: tls_report.directory_present,
        tls_evidence_complete: tls_report.is_complete(),
        tls_report,
        relocation_evidence_present: relocation_report.directory_present,
        relocation_evidence_complete: relocation_report.is_complete(),
        relocation_report,
        output_size: out_data.len(),
    })
}

/// True when Exception DD [rva, rva+size) is not fully covered by any section's
/// raw file range (PointerToRawData != 0 and SizeOfRawData covers the span).
fn exception_directory_lacks_raw(pe: &PeHeader, rva: u32, size: u32) -> bool {
    if rva == 0 || size == 0 {
        return false;
    }
    let Some(end) = rva.checked_add(size) else {
        return true;
    };
    for s in &pe.sections {
        let raw = s.header.size_of_raw_data;
        let ptr = s.header.pointer_to_raw_data;
        if raw == 0 || ptr == 0 {
            continue;
        }
        let va = s.header.virtual_address;
        let Some(raw_end) = va.checked_add(raw) else {
            continue;
        };
        if rva >= va && end <= raw_end {
            return false;
        }
    }
    true
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
/// `pointer_to_raw_data`).  Appending `.edata` after serialization ?as the
/// old code did ?left the section table stale, set `PointerToRawData = 0`,
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
        "Relocated export table: {:#x}  -> {:#x} (size {:#x}, delta {:#x}, raw {:#x})",
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

/// Patch WinMain `call 0x364e0` at RVA 0x63f4 to `mov eax,1; nop*3`.
///
/// Cold-start already has a restored gscript graph. Re-entering LoadFile on the
/// host path (gscript+0xbb0) hits call-obfusc AV and never reaches RegisterClass.

/// Skip crashing GUI reinit `0x35520` but keep the real AHK message pump.
///
/// Replace only `call 0x35520` (5 bytes at 0x6757) with `mov eax,1` so the
/// existing success path runs `call 0x1b10` and keeps the UI alive.

/// Patch WinMain unconditional MessageBoxW call @0x5c5d  -> mov eax,1; nop.
///
/// Call is `ff 15 rel32` (6 bytes). Without this, cold start sticks on #32770
/// and the NewClassName window is never created for the external probe.
fn patch_gto_skip_winmain_messagebox(image: &mut [u8]) {
    const SITE_RVA: u32 = 0x5c5d;
    let Some(file_off) = rva_to_file_offset(image, SITE_RVA) else {
        return;
    };
    if file_off + 6 > image.len() {
        return;
    }
    // ff 15 xx xx xx xx = call [rip+disp] (MessageBoxW IAT)
    if image[file_off] != 0xff || image[file_off + 1] != 0x15 {
        return;
    }
    // mov eax,1 ; nop
    image[file_off..file_off + 6].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00, 0x90]);
    info!(
        site_rva = format_args!("{SITE_RVA:#x}"),
        "R-GTO-UI: patched WinMain MessageBoxW  -> mov eax,1 (unblock UI)"
    );
}

fn patch_gto_skip_msgloop_crash(image: &mut [u8]) {
    const CALL_RVA: u32 = 0x6757;
    const TARGET_RVA: u32 = 0x35520;
    let Some(file_off) = rva_to_file_offset(image, CALL_RVA) else {
        return;
    };
    if file_off + 5 > image.len() {
        return;
    }
    if image[file_off] != 0xe8 {
        return;
    }
    let rel = i32::from_le_bytes(
        image[file_off + 1..file_off + 5]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let next = CALL_RVA.wrapping_add(5);
    let target = next.wrapping_add(rel as u32);
    if target != TARGET_RVA {
        return;
    }
    image[file_off..file_off + 5].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]);
    info!(
        call_rva = format_args!("{CALL_RVA:#x}"),
        "R-GTO-UI: patched call 0x35520  -> mov eax,1 (keep msg pump 0x1b10)"
    );
}

fn find_utf16_string_rva(image: &[u8], s: &str) -> Option<u32> {
    let mut needle = Vec::with_capacity(s.len() * 2 + 2);
    for ch in s.encode_utf16() {
        needle.extend_from_slice(&ch.to_le_bytes());
    }
    needle.extend_from_slice(&[0, 0]);
    let file_off = image
        .windows(needle.len())
        .position(|w| w == needle.as_slice())?;
    rva_from_file_offset(image, file_off)
}

fn rva_from_file_offset(image: &[u8], file_off: usize) -> Option<u32> {
    if image.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(image[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > image.len() {
        return None;
    }
    let nsec = u16::from_le_bytes(image[e_lfanew + 6..e_lfanew + 8].try_into().ok()?) as usize;
    let so = u16::from_le_bytes(image[e_lfanew + 20..e_lfanew + 22].try_into().ok()?) as usize;
    let sec0 = e_lfanew + 24 + so;
    for i in 0..nsec {
        let o = sec0 + i * 40;
        if o + 40 > image.len() {
            break;
        }
        let va = u32::from_le_bytes(image[o + 12..o + 16].try_into().ok()?);
        let rsz = u32::from_le_bytes(image[o + 16..o + 20].try_into().ok()?) as usize;
        let raw = u32::from_le_bytes(image[o + 20..o + 24].try_into().ok()?) as usize;
        if raw <= file_off && file_off < raw.saturating_add(rsz) {
            return Some(va.saturating_add((file_off - raw) as u32));
        }
    }
    None
}

/// Force RegisterClass to use image-embedded `NewClassName`.
///
/// Two sites must agree (r25b lesson):
/// - `0x34dbb`: early non-empty check was `mov rax,[gscript+0xbd8]`; after
///   `0x345e0` that slot is empty/static  -> function returns 0 before WNDCLASS setup.
/// - `0x34ed4`: real `lpszClassName` lea (stock points at `AutoHotkey2`).
///
/// Patch both to `lea ?,[NewClassName]` (7-byte rip-relative forms).
fn patch_gto_registerclass_classname(image: &mut [u8]) {
    let Some(class_rva) = find_utf16_string_rva(image, "NewClassName") else {
        warn!("R-GTO-UI: NewClassName UTF-16 not found; skip class patches");
        return;
    };

    // --- 0x34dbb: mov rax,[rcx+0xbd8] (7)  -> lea rax,[NewClassName] (7) ---
    const CHECK_RVA: u32 = 0x34dbb;
    if let Some(file_off) = rva_to_file_offset(image, CHECK_RVA) {
        if file_off + 7 <= image.len() {
            let expect_mov = [0x48u8, 0x8b, 0x81, 0xd8, 0x0b, 0x00, 0x00];
            let is_mov = image[file_off..file_off + 7] == expect_mov;
            let is_lea = image[file_off..file_off + 3] == [0x48, 0x8d, 0x05];
            if is_mov || is_lea {
                let next = CHECK_RVA.wrapping_add(7);
                let disp = class_rva.wrapping_sub(next) as i32;
                image[file_off] = 0x48;
                image[file_off + 1] = 0x8d;
                image[file_off + 2] = 0x05;
                image[file_off + 3..file_off + 7].copy_from_slice(&disp.to_le_bytes());
                info!(
                    site_rva = format_args!("{CHECK_RVA:#x}"),
                    class_rva = format_args!("{class_rva:#x}"),
                    "R-GTO-UI: patched RegisterClass empty-check  -> lea NewClassName"
                );
            }
        }
    }

    // --- 0x34ed4: lea rax,[AutoHotkey2]  -> lea rax,[NewClassName] ---
    const CLASS_RVA_SITE: u32 = 0x34ed4;
    if let Some(file_off) = rva_to_file_offset(image, CLASS_RVA_SITE) {
        if file_off + 7 <= image.len() && image[file_off..file_off + 3] == [0x48, 0x8d, 0x05] {
            let next = CLASS_RVA_SITE.wrapping_add(7);
            let disp = class_rva.wrapping_sub(next) as i32;
            image[file_off + 3..file_off + 7].copy_from_slice(&disp.to_le_bytes());
            info!(
                site_rva = format_args!("{CLASS_RVA_SITE:#x}"),
                class_rva = format_args!("{class_rva:#x}"),
                "R-GTO-UI: retargeted RegisterClass lpszClassName  -> NewClassName"
            );
        }
    }
    // --- 0x34f66: mov rdx,[0x141bf8]  -> lea rdx,[NewClassName] ---
    // CreateWindowExW lpClassName. Global often holds atom/other class
    // (r26: rdx=0x120238 "edit"/static) so UI appears as ZhuChuangKou or not
    // at all under the NewClassName oracle.
    const CW_CLASS_RVA: u32 = 0x34f66;
    if let Some(file_off) = rva_to_file_offset(image, CW_CLASS_RVA) {
        if file_off + 7 <= image.len() {
            let b0 = image[file_off];
            let b1 = image[file_off + 1];
            let b2 = image[file_off + 2];
            // mov rdx, [rip+disp] = 48 8B 15  OR already lea rdx,[rip]=48 8D 15
            let ok = (b0, b1, b2) == (0x48, 0x8b, 0x15) || (b0, b1, b2) == (0x48, 0x8d, 0x15);
            if ok {
                let next = CW_CLASS_RVA.wrapping_add(7);
                let disp = class_rva.wrapping_sub(next) as i32;
                image[file_off] = 0x48;
                image[file_off + 1] = 0x8d;
                image[file_off + 2] = 0x15; // lea rdx, [rip+disp]
                image[file_off + 3..file_off + 7].copy_from_slice(&disp.to_le_bytes());
                info!(
                    site_rva = format_args!("{CW_CLASS_RVA:#x}"),
                    class_rva = format_args!("{class_rva:#x}"),
                    "R-GTO-UI: patched CreateWindowEx lpClassName  -> lea NewClassName"
                );
            }
        }
    }

    // --- 0x34f59: mov r9d, 0x00CF0000  -> 0x01CF0000 (WS_VISIBLE) ---
    // Stock style is WS_OVERLAPPEDWINDOW without WS_VISIBLE, so NewClassName
    // hwnd exists but IsWindowVisible=0 and the window oracle ignores it (r26b).
    const STYLE_RVA: u32 = 0x34f59;
    if let Some(file_off) = rva_to_file_offset(image, STYLE_RVA) {
        if file_off + 6 <= image.len()
            && image[file_off..file_off + 2] == [0x41, 0xb9]
            && image[file_off + 2..file_off + 6] == [0x00, 0x00, 0xcf, 0x00]
        {
            image[file_off + 2..file_off + 6].copy_from_slice(&0x01cf_0000u32.to_le_bytes());
            info!(
                site_rva = format_args!("{STYLE_RVA:#x}"),
                "R-GTO-UI: patched CreateWindow style  -> WS_VISIBLE|WS_OVERLAPPEDWINDOW"
            );
        }
    }
}

fn patch_gto_skip_loadfile_reentry(image: &mut [u8]) {
    const CALL_RVA: u32 = 0x63f4;
    const TARGET_RVA: u32 = 0x364e0;
    let Some(file_off) = rva_to_file_offset(image, CALL_RVA) else {
        return;
    };
    if file_off + 5 > image.len() {
        return;
    }
    // Expect E8 rel32 targeting 0x364e0
    if image[file_off] != 0xe8 {
        return;
    }
    let rel = i32::from_le_bytes(
        image[file_off + 1..file_off + 5]
            .try_into()
            .unwrap_or([0; 4]),
    );
    let next = CALL_RVA.wrapping_add(5);
    let target = next.wrapping_add(rel as u32);
    if target != TARGET_RVA {
        return;
    }
    // mov eax, 1 ; nop nop nop
    image[file_off..file_off + 5].copy_from_slice(&[0xb8, 0x01, 0x00, 0x00, 0x00]);
    // Keep length 5: mov eax,imm32 is already 5 bytes (no extra nops needed).
    info!(
        call_rva = format_args!("{CALL_RVA:#x}"),
        "R-GTO-UI: patched LoadFile re-entry call  -> mov eax,1 (skip reload)"
    );
}

fn rva_to_file_offset(image: &[u8], rva: u32) -> Option<usize> {
    if image.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(image[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 > image.len() {
        return None;
    }
    let nsec = u16::from_le_bytes(image[e_lfanew + 6..e_lfanew + 8].try_into().ok()?) as usize;
    let so = u16::from_le_bytes(image[e_lfanew + 20..e_lfanew + 22].try_into().ok()?) as usize;
    let sec0 = e_lfanew + 24 + so;
    for i in 0..nsec {
        let o = sec0 + i * 40;
        if o + 40 > image.len() {
            break;
        }
        let vsz = u32::from_le_bytes(image[o + 8..o + 12].try_into().ok()?);
        let va = u32::from_le_bytes(image[o + 12..o + 16].try_into().ok()?);
        let rsz = u32::from_le_bytes(image[o + 16..o + 20].try_into().ok()?);
        let raw = u32::from_le_bytes(image[o + 20..o + 24].try_into().ok()?) as usize;
        let span = vsz.max(rsz);
        if rva >= va && rva < va.saturating_add(span) {
            let off = raw + (rva - va) as usize;
            if off < image.len() {
                return Some(off);
            }
        }
    }
    None
}

/// File offset of OptionalHeader.AddressOfEntryPoint (PE32/PE32+ both at +16).
fn address_of_entry_point_file_offset(image: &[u8]) -> Option<usize> {
    if image.len() < 0x40 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(image.get(0x3c..0x40)?.try_into().ok()?) as usize;
    // COFF starts at e_lfanew+4; OptionalHeader at e_lfanew+24; AddressOfEntryPoint at +16.
    let off = e_lfanew.checked_add(24 + 16)?;
    if off + 4 > image.len() {
        return None;
    }
    // Sanity: SizeOfOptionalHeader must cover AddressOfEntryPoint.
    let soh =
        u16::from_le_bytes(image.get(e_lfanew + 20..e_lfanew + 22)?.try_into().ok()?) as usize;
    if soh < 20 {
        return None;
    }
    Some(off)
}

fn read_address_of_entry_point(image: &[u8]) -> Option<u32> {
    let off = address_of_entry_point_file_offset(image)?;
    Some(u32::from_le_bytes(
        image.get(off..off + 4)?.try_into().ok()?,
    ))
}

fn patch_address_of_entry_point(image: &mut [u8], ep: u32) -> bool {
    let Some(off) = address_of_entry_point_file_offset(image) else {
        return false;
    };
    image[off..off + 4].copy_from_slice(&ep.to_le_bytes());
    true
}

/// True when dump output would clobber the protected source image.
/// Uses path, canonical path, and Windows volume+file-index identity (hard links).
fn output_aliases_input(input: &Path, output: &Path) -> bool {
    if input == output {
        return true;
    }
    let a = std::fs::canonicalize(input).ok();
    let b = std::fs::canonicalize(output).ok();
    if let (Some(ref ac), Some(ref bc)) = (a, b) {
        if ac == bc
            || ac
                .to_string_lossy()
                .eq_ignore_ascii_case(&bc.to_string_lossy())
        {
            return true;
        }
    }
    if let (Ok(ia), Ok(ib)) = (file_identity(input), file_identity(output)) {
        if ia == ib {
            return true;
        }
    }
    input
        .to_string_lossy()
        .eq_ignore_ascii_case(&output.to_string_lossy())
}

#[cfg(windows)]
fn file_identity(path: &Path) -> std::io::Result<(u32, u64)> {
    use std::fs::OpenOptions;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    let file = OpenOptions::new().read(true).share_mode(0x7).open(path)?;
    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let mut info = ByHandleFileInformation::default();
    // SAFETY: handle owned by file; info is valid out-buffer.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let index = (u64::from(info.file_index_high) << 32) | u64::from(info.file_index_low);
    Ok((info.volume_serial_number, index))
}

#[cfg(not(windows))]
fn file_identity(_path: &Path) -> std::io::Result<(u32, u64)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "file identity only on Windows",
    ))
}

fn candidate_sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let dig = Sha256::digest(data);
    let mut s = String::with_capacity(64);
    for b in dig {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn transform_manifest_path(output: &Path) -> std::path::PathBuf {
    output.with_extension("transform_manifest.json")
}

/// Remove dump + sibling manifest; surface any residual paths (not best-effort).
fn remove_dump_and_manifest(output: &Path) -> Result<(), String> {
    let mut residuals = Vec::new();
    if output.exists() {
        if let Err(e) = std::fs::remove_file(output) {
            residuals.push(format!("{} ({e})", output.display()));
        }
    }
    let m = transform_manifest_path(output);
    if m.exists() {
        if let Err(e) = std::fs::remove_file(&m) {
            residuals.push(format!("{} ({e})", m.display()));
        }
    }
    if residuals.is_empty() {
        Ok(())
    } else {
        Err(residuals.join("; "))
    }
}

/// Bound artifact manifest: candidate digest + transforms.
/// Always written (empty entries for clean dumps). Fail-closed.
///
/// # Production API contract
///
/// This is a supported production writer, used by the real dump paths
/// [`dump_process_with_report`] and [`dump_dotnet_with_source`] to emit the
/// sibling `.transform_manifest.json` that binds a candidate's digest to the
/// dump/transform ledger. It is also the seam the production evidence pipeline
/// uses to produce the transform-manifest bundle member through the same
/// writer (never a test-only re-assembly).
///
/// ## Parameters
/// - `output`: candidate PE path. The manifest is written to the sibling
///   `output` with extension `.transform_manifest.json` (via
///   [`transform_manifest_path`]).
/// - `candidate_bytes`: exact candidate bytes whose digest and size are
///   recorded. The caller must pass the same bytes that are serialized to
///   `output`; the writer computes the digest itself rather than trusting a
///   caller-supplied digest.
/// - `transforms`: ordered list of `(id, kind)` transform ledger entries. An
///   empty list records a clean dump (standard reconstruction only per the
///   transform taxonomy). A non-empty list records diagnostic transforms that
///   block product `Accepted` unless a registered rule exists.
/// - `input`: optional protected/source input path used only for the fail-closed
///   alias guard (see below). `None` is permitted and skips the alias check.
///
/// ## Identity constraints
/// The recorded `candidate_sha256` / `candidate_size_bytes` are computed from
/// `candidate_bytes`, so a manifest is always self-consistent with the exact
/// candidate bytes passed in. The writer never accepts a caller-supplied
/// digest, so a caller cannot record a digest for bytes it did not pass.
///
/// ## Atomic write semantics
/// The manifest is written through [`replace_file_atomic`]: an exclusive
/// temp-then-`MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)` (Windows) or
/// rename-onto-non-existing (elsewhere) sequence with no delete-then-rename
/// gap. If `input` aliases the destination manifest path, the write is refused
/// (`output_aliases_input`) rather than overwriting the input.
///
/// ## Error contract
/// `Err(PeError)` on alias collision or I/O failure. The manifest is either
/// written in full or not at all.
pub fn write_bound_transform_manifest(
    output: &Path,
    candidate_bytes: &[u8],
    transforms: &[(&str, &str)],
    input: Option<&Path>,
) -> Result<(), PeError> {
    // Taxonomy: docs/TRANSFORM_TAXONOMY_V1.md ?empty entries = standard
    // reconstruction only; sample_bypass ids must appear when GTO bypass runs.
    const TAXONOMY: &str = "mida.transform-taxonomy/v1";
    let sha = candidate_sha256_hex(candidate_bytes);
    let path = transform_manifest_path(output);
    if let Some(src) = input {
        if output_aliases_input(src, &path) {
            return Err(PeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to write transform_manifest over input alias '{}'",
                    src.display()
                ),
            )));
        }
    }
    let mut entries = String::new();
    for (i, (id, kind)) in transforms.iter().enumerate() {
        if i > 0 {
            entries.push(',');
        }
        entries.push_str(&format!(
            r#"{{"id":"{id}","kind":"{kind}","equivalence_rule":null}}"#
        ));
    }
    let note = if transforms.is_empty() {
        "clean dump ?empty ledger (standard reconstruction only per taxonomy v1)"
    } else {
        "diagnostic transforms ?blocks product Accepted unless registered rule"
    };
    let body = format!(
        concat!(
            "{{\n",
            "  \"schema_version\": \"mida.transform-manifest/v0\",\n",
            "  \"taxonomy_version\": \"{taxonomy}\",\n",
            "  \"candidate_sha256\": \"{sha}\",\n",
            "  \"candidate_size_bytes\": {size},\n",
            "  \"entries\": [{entries}],\n",
            "  \"note\": \"{note}\"\n",
            "}}\n"
        ),
        taxonomy = TAXONOMY,
        sha = sha,
        size = candidate_bytes.len(),
        entries = entries,
        note = note
    );
    replace_file_atomic(&path, body.as_bytes(), input)?;
    info!(
        path = %path.display(),
        sha256 = %sha,
        transforms = transforms.len(),
        "wrote bound transform_manifest"
    );
    Ok(())
}

fn write_output_atomic(output: &Path, data: &[u8], input: Option<&Path>) -> Result<(), PeError> {
    replace_file_atomic(output, data, input)
}

/// Exclusive temp + replace destination without delete-then-rename gap.
/// Windows: `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`. Elsewhere: rename
/// onto non-existing path only (no silent copy).
fn replace_file_atomic(output: &Path, data: &[u8], input: Option<&Path>) -> Result<(), PeError> {
    if let Some(src) = input {
        if output_aliases_input(src, output) {
            return Err(PeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "refusing to overwrite input '{}' with output",
                    src.display()
                ),
            )));
        }
    }

    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    let stem = output
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("out.bin");
    let tmp_name = format!(
        ".{stem}.mida.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let tmp_path = parent.join(tmp_name);

    {
        use std::io::Write;
        let write_tmp = (|| -> Result<(), PeError> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .map_err(|e| {
                    PeError::Io(std::io::Error::new(
                        e.kind(),
                        format!("open temp '{}': {e}", tmp_path.display()),
                    ))
                })?;
            f.write_all(data).map_err(|e| {
                PeError::Io(std::io::Error::new(
                    e.kind(),
                    format!("write temp '{}': {e}", tmp_path.display()),
                ))
            })?;
            f.sync_all().map_err(|e| {
                PeError::Io(std::io::Error::new(
                    e.kind(),
                    format!("sync temp '{}': {e}", tmp_path.display()),
                ))
            })?;
            Ok(())
        })();
        if let Err(e) = write_tmp {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    }

    // Re-check alias after temp is fully written.
    if let Some(src) = input {
        if output_aliases_input(src, output) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(PeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "output aliases input before replace",
            )));
        }
    }

    let replace_result = replace_via_os(&tmp_path, output);
    if replace_result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    replace_result
}

#[cfg(windows)]
fn replace_via_os(tmp: &Path, output: &Path) -> Result<(), PeError> {
    use std::os::windows::ffi::OsStrExt;
    // MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH | MOVEFILE_COPY_ALLOWED=0
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let existing: Vec<u16> = tmp.as_os_str().encode_wide().chain(Some(0)).collect();
    let new_name: Vec<u16> = output.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: null-terminated wide paths; kernel32 MoveFileExW.
    // Security software may briefly hold a freshly-written executable/image
    // after fsync. Preserve the atomic replace contract and retry only the
    // transient Windows sharing/access errors instead of falling back to a
    // delete-then-rename or non-atomic copy.
    let mut last_error = None;
    const MAX_REPLACE_ATTEMPTS: u32 = 40;
    for attempt in 1..=MAX_REPLACE_ATTEMPTS {
        let ok = unsafe {
            MoveFileExW(
                existing.as_ptr(),
                new_name.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if ok != 0 {
            return Ok(());
        }
        let e = std::io::Error::last_os_error();
        let transient = matches!(e.raw_os_error(), Some(5 | 32 | 33));
        last_error = Some(e);
        if !transient || attempt == MAX_REPLACE_ATTEMPTS {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let e = last_error.unwrap_or_else(std::io::Error::last_os_error);
    Err(PeError::Io(std::io::Error::new(
        e.kind(),
        format!(
            "MoveFileExW '{}' -> '{}' failed after {} attempts: {e}",
            tmp.display(),
            output.display(),
            MAX_REPLACE_ATTEMPTS
        ),
    )))
}

#[cfg(not(windows))]
fn replace_via_os(tmp: &Path, output: &Path) -> Result<(), PeError> {
    if output.exists() {
        std::fs::remove_file(output).map_err(PeError::Io)?;
    }
    std::fs::rename(tmp, output).map_err(PeError::Io)
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
    fn dump_process_wrapper_and_report_api_keep_distinct_return_types() {
        let _: fn(&mut dyn mida_core::DebuggerCore, &DumpOptions) -> Result<(), PeError> =
            dump_process;
        let _: fn(
            &mut dyn mida_core::DebuggerCore,
            &DumpOptions,
        ) -> Result<DumpProcessReport, PeError> = dump_process_with_report;
        let _: fn(
            &mut dyn mida_core::DebuggerCore,
            &DumpOptions,
        ) -> Result<crate::DumpProcessReport, PeError> = dump_process_with_report;
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
/// Dump a .NET assembly with **required** protected-input path for alias checks.
///
/// `entry_point_rva` is written directly to `AddressOfEntryPoint` (it is already
/// an RVA ?do **not** subtract `image_base` again; audit residual P1).
///
/// Production callers must pass the protected source path. There is no
/// source-less public wrapper (audit residual P2).
pub fn dump_dotnet_with_source(
    debugger: &mut dyn mida_core::DebuggerCore,
    image_base: u64,
    entry_point_rva: u32,
    output_path: &Path,
    source_path: &Path,
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
    // Fail-closed: truncated image must not become a managed candidate.
    if read < dump_size_usize {
        return Err(PeError::Parse(format!(
            "Short read on .NET image: got {read:#x} bytes, need {dump_size_usize:#x}"
        )));
    }

    pe.sanitize();

    if !pe.sections.is_empty() {
        pe.rename_section(0, ".text");
    }

    let mut out_data = Vec::new();
    out_data.extend_from_slice(&buf[..dump_size_usize]);

    // Pad to file alignment if needed
    let mut physical_size = dump_size;
    pe.file_align(&mut physical_size);
    if dump_size < physical_size {
        out_data.resize(physical_size as usize, 0);
    }

    let mut image_size = physical_size;
    pe.section_align(&mut image_size);
    pe.nt_headers.optional_header.size_of_image = image_size;

    // entry_point_rva is already RVA (PeHeader::entry_point) ?write as-is.
    pe.nt_headers.optional_header.address_of_entry_point = entry_point_rva;

    // Headers must overwrite file offset 0 ?never append (audit residual).
    let header_data = pe.serialize_headers()?;
    if header_data.len() > out_data.len() {
        out_data.resize(header_data.len(), 0);
    }
    out_data[..header_data.len()].copy_from_slice(&header_data);

    if output_aliases_input(source_path, output_path) {
        return Err(PeError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "refusing to overwrite input '{}' with .NET dump",
                source_path.display()
            ),
        )));
    }

    write_output_atomic(output_path, &out_data, Some(source_path))?;

    // Always emit bound manifest (empty ledger) ?same contract as native dump.
    if let Err(e) = write_bound_transform_manifest(output_path, &out_data, &[], Some(source_path)) {
        let cleanup = remove_dump_and_manifest(output_path);
        return Err(match cleanup {
            Ok(()) => e,
            Err(ce) => PeError::Io(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(".NET transform_manifest failed ({e}); residual cleanup failed: {ce}"),
            )),
        });
    }

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
    /// raw-padded buffer must be rejected ?bounds are against `export_size`,
    /// not the padded buffer length.
    #[test]
    fn relocate_rejects_array_crossing_export_size_into_raw_padding() {
        // Start from a valid blob and inflate num_functions so the
        // AddressOfFunctions array end crosses export_size while every
        // directory field RVA stays inside [dir_start, export_size).
        let mut buf = build_export_blob();
        buf.resize(0x200, 0); // clearly larger than export_size (raw padding)
                              // num_functions (offset 0x14) = 7  -> array end = 0x28 + 7*4 = 0x44.
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

        // Real pipeline call: empty dump_buf / thunks / containers are safe;
        // write_output_file early-returns on the IAT paths and .text falls
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
            capture_policy: crate::DumpCapturePolicy::default(),
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

        // Name RVA array[0]  -> "Func1" string.
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

        // Ordinal array[0]  -> index 1 (points at the forwarder slot).
        let ord_off = (addr_ordinals - edata_va) as usize;
        let ord_idx = u16::from_le_bytes(blob[ord_off..ord_off + 2].try_into().unwrap());
        assert_eq!(ord_idx, 1);

        // Functions array[1] (the ordinal-targeted slot) is a forwarder RVA
        // inside the .edata directory  -> forwarder string.
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
    /// read ?even when every directory field is zero.  This prevents
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

    /// Callers must pass `PeHeader::entry_point` (RVA). Subtracting ImageBase
    /// as u32 saturates typical PE32+ bases to 0 (audit residual P1).
    #[test]
    fn dotnet_entry_point_rva_must_not_subtract_image_base() {
        let rva = 0x1000u32;
        let image_base = 0x1400_0000_0u64;
        let wrong = rva.saturating_sub(image_base as u32);
        assert_eq!(wrong, 0, "VA-style subtract corrupts OEP to 0");
        // Production writes entry_point_rva into optional_header then serialize_headers.
        // serialize_headers emits NT headers starting at offset 0 (no DOS stub).
        let mut pe = pe_with_text_section(0x1000, 0x200);
        pe.nt_headers.optional_header.address_of_entry_point = rva;
        pe.entry_point = rva;
        let nt = pe.serialize_headers().expect("serialize");
        // NT layout: sig@0, COFF@4, OptionalHeader@24, AddressOfEntryPoint@40.
        let written = u32::from_le_bytes(nt[40..44].try_into().unwrap());
        assert_eq!(written, 0x1000, "serialized OEP must be the RVA, not 0");
    }

    /// AddressOfEntryPoint lives at OptionalHeader+16 ?NEVER at
    /// e_lfanew+24+SizeOfOptionalHeader (that is the first section header).
    #[test]
    fn address_of_entry_point_offset_is_not_section_table() {
        // Minimal PE32+ headers: DOS + PE sig + COFF + optional (0xF0) + 1 section.
        let e_lfanew = 0x80usize;
        let soh = 0xF0usize;
        let mut image = vec![0u8; e_lfanew + 24 + soh + 40];
        image[0] = b'M';
        image[1] = b'Z';
        image[0x3c..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
        image[e_lfanew..e_lfanew + 4].copy_from_slice(&0x0000_4550u32.to_le_bytes()); // PE\0\0
        image[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections
        image[e_lfanew + 20..e_lfanew + 22].copy_from_slice(&(soh as u16).to_le_bytes());
        // OptionalHeader magic PE32+
        image[e_lfanew + 24..e_lfanew + 26].copy_from_slice(&0x20Bu16.to_le_bytes());
        let expected_ep = 0x00ABu32;
        image[e_lfanew + 24 + 16..e_lfanew + 24 + 20].copy_from_slice(&expected_ep.to_le_bytes());
        // Poison first section SizeOfRawData so a wrong offset would read it.
        let sect0 = e_lfanew + 24 + soh;
        let poison_raw = 0xDEAD_BEEFu32;
        image[sect0 + 16..sect0 + 20].copy_from_slice(&poison_raw.to_le_bytes());

        let off = super::address_of_entry_point_file_offset(&image).expect("ep off");
        assert_eq!(off, e_lfanew + 24 + 16);
        assert_ne!(off, sect0 + 16, "must not land on section SizeOfRawData");
        assert_eq!(
            super::read_address_of_entry_point(&image),
            Some(expected_ep)
        );

        assert!(super::patch_address_of_entry_point(&mut image, 0x1234_5678));
        assert_eq!(
            super::read_address_of_entry_point(&image),
            Some(0x1234_5678)
        );
        // Section SizeOfRawData must be untouched.
        let raw_after = u32::from_le_bytes(image[sect0 + 16..sect0 + 20].try_into().unwrap());
        assert_eq!(raw_after, poison_raw);
    }

    /// Production path: `create_edata_section` must propagate the short-
    /// export_size rejection.  A short DataDirectory.Size must NOT be masked
    /// by the raw-data padding that `create_edata_section` applies.
    #[test]
    fn create_edata_section_rejects_short_export_size_not_masked_by_padding() {
        let mut pe = pe_with_text_section(0x1000, 0x200);
        pe.nt_headers.optional_header.data_directory[0] = ImageDataDirectory {
            virtual_address: ORIGINAL_EXPORT_RVA,
            // Declared size 32 ?too small for a directory.
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

#[cfg(test)]
mod transform_manifest_tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mida_tfm_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The writer derives the sibling `.transform_manifest.json` from the
    /// candidate path and records the candidate's own digest/size.
    #[test]
    fn writes_manifest_with_candidate_digest_and_sibling_path() {
        let dir = temp("sibling");
        let candidate = dir.join("candidate.exe");
        let candidate_bytes = b"candidate image bytes";
        write_bound_transform_manifest(&candidate, candidate_bytes, &[], None).unwrap();
        let manifest = candidate.with_extension("transform_manifest.json");
        assert!(manifest.is_file());
        let text = std::fs::read_to_string(&manifest).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["schema_version"], "mida.transform-manifest/v0");
        assert_eq!(
            value["candidate_sha256"],
            candidate_sha256_hex(candidate_bytes)
        );
        assert_eq!(value["candidate_size_bytes"], candidate_bytes.len() as u64);
        // Clean dump: empty entries ledger.
        assert_eq!(value["entries"], serde_json::Value::Array(vec![]));
    }

    /// A caller-supplied digest is never trusted; the recorded digest is always
    /// computed from the exact candidate bytes passed.
    #[test]
    fn manifest_digest_binds_to_passed_bytes_not_path() {
        let dir = temp("bind");
        let candidate = dir.join("candidate.exe");
        let a = b"first bytes";
        let b = b"second bytes";
        write_bound_transform_manifest(&candidate, a, &[], None).unwrap();
        let text_a =
            std::fs::read_to_string(&candidate.with_extension("transform_manifest.json")).unwrap();
        let sha_a: String = serde_json::from_str::<serde_json::Value>(&text_a).unwrap()
            ["candidate_sha256"]
            .as_str()
            .unwrap()
            .into();
        assert_eq!(sha_a, candidate_sha256_hex(a));

        write_bound_transform_manifest(&candidate, b, &[], None).unwrap();
        let text_b =
            std::fs::read_to_string(&candidate.with_extension("transform_manifest.json")).unwrap();
        let sha_b: String = serde_json::from_str::<serde_json::Value>(&text_b).unwrap()
            ["candidate_sha256"]
            .as_str()
            .unwrap()
            .into();
        assert_eq!(sha_b, candidate_sha256_hex(b));
        assert_ne!(sha_a, sha_b);
    }

    /// Non-empty transforms serialize into the ledger with taxonomy note.
    #[test]
    fn records_transform_entries() {
        let dir = temp("transforms");
        let candidate = dir.join("candidate.exe");
        let bytes = b"image";
        write_bound_transform_manifest(
            &candidate,
            bytes,
            &[("sample_bypass", "relocation"), ("oep_fix", "oep")],
            None,
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&candidate.with_extension("transform_manifest.json")).unwrap(),
        )
        .unwrap();
        let entries = value["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0]["id"], "sample_bypass");
        assert_eq!(entries[0]["kind"], "relocation");
        assert_eq!(entries[1]["id"], "oep_fix");
        assert_eq!(entries[1]["kind"], "oep");
        assert!(value["note"]
            .as_str()
            .unwrap()
            .contains("diagnostic transforms"));
    }

    /// Fail-closed alias guard: writing a manifest over an input that aliases
    /// the destination manifest path is refused, never overwriting the input.
    #[test]
    fn refuses_to_overwrite_input_alias() {
        let dir = temp("alias");
        let candidate = dir.join("candidate.exe");
        // The destination manifest path derives to `candidate.transform_manifest.json`.
        let manifest_dest = candidate.with_extension("transform_manifest.json");
        // An input that aliases that exact destination must be refused.
        std::fs::write(&manifest_dest, b"original input").unwrap();
        let err = write_bound_transform_manifest(&candidate, b"bytes", &[], Some(&manifest_dest))
            .expect_err("alias write must be refused");
        assert!(format!("{err}").contains("alias"));
        // The input must be untouched.
        assert_eq!(
            std::fs::read_to_string(&manifest_dest).unwrap(),
            "original input"
        );
    }

    /// Atomic write: the manifest appears atomically; the JSON is well-formed.
    #[test]
    fn manifest_is_well_formed_json_and_reads_back() {
        let dir = temp("atomic");
        let candidate = dir.join("candidate.exe");
        write_bound_transform_manifest(&candidate, b"data", &[("x", "y")], None).unwrap();
        let manifest = candidate.with_extension("transform_manifest.json");
        let parsed: serde_json::Value = serde_json::from_slice(&std::fs::read(&manifest).unwrap())
            .expect("manifest must be valid JSON");
        assert_eq!(parsed["schema_version"], "mida.transform-manifest/v0");
        assert_eq!(parsed["taxonomy_version"], "mida.transform-taxonomy/v1");
    }
}
