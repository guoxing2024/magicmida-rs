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
        let use_original = if live_empty {
            true
        } else if let Some(ref ep) = opts.executable_path {
            // Read original import count for comparison
            let orig_imports = crate::original_imports::read_original_import_table(ep);
            let orig_count: usize = orig_imports.iter().map(|(_, funcs)| funcs.len()).sum();
            let rebuilt_count = import_builder.as_ref().map(|b| b.thunk_count()).unwrap_or(0);

            // If we're missing more than 10% of functions, use original
            let threshold = (orig_count as f64 * 0.9) as usize;
            if rebuilt_count < threshold {
                warn!(
                    "IAT rebuild incomplete: {}/{} functions ({}% coverage) - using original import table",
                    rebuilt_count, orig_count,
                    (rebuilt_count as f64 / orig_count as f64 * 100.0) as u32
                );
                true
            } else {
                false
            }
        } else {
            false
        };

        if use_original {
            if let Some(ref ep) = opts.executable_path {
                if let Some(fallback_builder) = build_import_table_from_original(&pe, ep) {
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
                            let mut dll_exports: std::collections::HashMap<String, std::collections::HashMap<u16, String>> =
                                std::collections::HashMap::new();

                            debug!("Starting to load DLL exports for ordinal restoration");

                            for dll_name in ordinal_imports.keys() {
                                debug!("Loading exports for {}", dll_name);
                                if let Some(dll_path) = crate::dll_exports::find_system_dll(dll_name) {
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
                                if let Some(ordinals_for_dll) = ordinal_imports.get(&module_name_lower) {
                                    // Get export map for this DLL
                                    if let Some(exports) = dll_exports.get(&module_name_lower) {
                                        // Build reverse map: function_name -> ordinal
                                        let name_to_ordinal: std::collections::HashMap<String, u16> =
                                            exports.iter().map(|(ord, name)| (name.to_lowercase(), *ord)).collect();

                                        // Convert thunks
                                        for thunk in &mut module.thunks {
                                            if let Some(ref func_name) = thunk.function_name {
                                                let func_name_lower = func_name.to_lowercase();

                                                // Check if original PE imported this function by ordinal
                                                if let Some(&ordinal) = name_to_ordinal.get(&func_name_lower) {
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

    // 4. Read the full dump image
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

    // A pre-`.text` snapshot can still contain protector-created encoded
    // containers backed by the unpacking process heap. Detect containers that
    // reference heap memory BEFORE resetting them, then reset to prevent crashes.
    let containers = super::container_snapshot::detect_containers(&pe, &dump_buf, debugger);
    super::data_reinit::reinitialize_zero_filled_data(
        &pe,
        &mut dump_buf,
        opts.executable_path.as_deref(),
    );

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

    // 5b. Rebuild process-local CRT heap state before creating the import
    // section. Detection is semantic: the same writable global must feed at
    // least two distinct Heap* IAT calls, and GetProcessHeap must be imported.
    // If containers were detected, install a full container restoration bootstrap.
    let output_entry_point = import_builder
        .as_ref()
        .and_then(|builder| {
            super::heap_bootstrap::install_heap_bootstrap(
                &mut pe,
                &dump_buf,
                builder,
                opts.entry_point,
                &containers,
                Some(debugger),
            )
        })
        .unwrap_or(opts.entry_point);

    // 5c. Build import section (uses original virtual addresses)
    let mut import_thunks: Vec<u64> = Vec::new();
    if let Some(ref builder) = import_builder {
        info!("Creating import section with {} modules, {} thunks",
            builder.modules.len(), builder.thunk_count());
        let (thunks, _section_idx) =
            create_import_section(&mut pe, builder, original_iat_rva, &mut dump_buf, is_64bit);
        info!("Import section created successfully, {} thunk addresses returned", thunks.len());
        import_thunks = thunks;
    } else {
        warn!("No import_builder - skipping import section creation");
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

    // 6. Write output file with container restoration
    let mut out_data = write_output_file(
        &mut pe,
        &dump_buf,
        import_builder.as_ref(),
        &import_thunks,
        original_iat_rva,
        is_64bit,
        opts,
        output_entry_point,
        &containers,
    )?;

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

    // Pack .reloc/.import tightly after .pdata to eliminate the file gap
    // left by sanitize() setting ptr=VA for all sections.
    // Disabled: pack_tail_sections uses the pe object's section table,
    // but out_data's section table may differ after pack_section_layout
    // moves sections with large gaps.  When compact_and_shift is disabled,
    // pack_section_layout already handles file layout compression.
    // if opts.shrink {
    //     crate::postprocess::pack_tail_sections(&mut out_data, &pe)?;
    // }

    std::fs::write(&opts.output_path, &out_data)?;

    info!(
        path = %opts.output_path.display(),
        size = out_data.len(),
        sections = pe.sections.len(),
        "Dump written successfully"
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
