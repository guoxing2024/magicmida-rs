//! Import table reconstruction via the two-pass voting algorithm.
//!
//! Extracted from `dumper.rs` — corresponds to `TDumper.Process`
//! (Pass 1 and Pass 2).

use tracing::{debug, info, warn};

use crate::error::PeError;
use crate::header::PeHeader;
use crate::import_table::{
    ImportModule, ImportTableBuilder, ImportThunk, iat_slot_size,
};

use super::helpers::{
    preference_score, read_ptr, write_ptr, IMAGE_DIRECTORY_ENTRY_IAT, MAX_IAT_SLOTS,
};
use super::remote_modules::{determine_iat_size, take_module_snapshot};
use super::types::{IatSlot, RemoteModule, ResolutionCandidate};

// -----------------------------------------------------------------------
// rebuild_import_table (public API)
// -----------------------------------------------------------------------

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

// -----------------------------------------------------------------------
// rebuild_import_table_complete
// -----------------------------------------------------------------------

/// Internal version that also returns the raw IAT image and its size.
pub(crate) fn rebuild_import_table_complete(
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

// -----------------------------------------------------------------------
// rebuild_import_table_inner (the core two-pass algorithm)
// -----------------------------------------------------------------------

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

    // Build forward maps (see comments in original dumper.rs for details).
    let mut forward_map: std::collections::HashMap<u64, (usize, String)> = std::collections::HashMap::new();
    let mut forward_string_map: std::collections::HashMap<u64, (usize, String)> = std::collections::HashMap::new();

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

    build_forward_maps(
        &modules,
        &mut forward_map,
        &mut forward_string_map,
        &module_priority,
    );

    tracing::debug!("Forward map: {} entries, forward string map: {} entries",
        forward_map.len(), forward_string_map.len());

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

        collect_candidates(&mut slot, slot_val, &modules, &forward_map, &forward_string_map);

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
    let builder = pass2_vote(&mut slots, &modules, &mut iat_data, iat_address, image_base, is_64bit, ptr_size, slot_count, &forward_map);

    Ok((iat_data, iat_size, Some(builder)))
}

// -----------------------------------------------------------------------
// build_forward_maps
// -----------------------------------------------------------------------

fn build_forward_maps(
    modules: &[RemoteModule],
    forward_map: &mut std::collections::HashMap<u64, (usize, String)>,
    forward_string_map: &mut std::collections::HashMap<u64, (usize, String)>,
    module_priority: &std::collections::HashMap<usize, i32>,
) {
    for (source_mi, source_module) in modules.iter().enumerate() {
        for (fwd_str, fwd_string_addr) in &source_module.forwards {
            if let Some((target_mod_name, target_func_name)) = fwd_str.split_once('.') {
                let target_mod_lower = target_mod_name.to_lowercase();

                let source_name = match source_module.exports.get(fwd_string_addr) {
                    Some(n) => n.clone(),
                    None => continue,
                };

                for (tmi, target_module) in modules.iter().enumerate() {
                    let mod_name = target_module.name.to_lowercase();
                    if mod_name == target_mod_lower ||
                       mod_name == format!("{}.dll", target_mod_lower) ||
                       mod_name.starts_with(&target_mod_lower) {

                        for (target_addr, exported_func_name) in &target_module.exports {
                            if exported_func_name == target_func_name {
                                forward_string_map.insert(*fwd_string_addr, (tmi, target_func_name.to_string()));

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
}

// -----------------------------------------------------------------------
// collect_candidates (Pass 1 per-slot logic)
// -----------------------------------------------------------------------

fn collect_candidates(
    slot: &mut IatSlot,
    slot_val: u64,
    modules: &[RemoteModule],
    forward_map: &std::collections::HashMap<u64, (usize, String)>,
    forward_string_map: &std::collections::HashMap<u64, (usize, String)>,
) {
    // Variant A: direct match
    for (mi, m) in modules.iter().enumerate() {
        if slot_val > m.base && slot_val < m.end_off {
            if m.exports.contains_key(&slot_val) {
                slot.candidates.push(ResolutionCandidate {
                    address: slot_val,
                    module_index: mi,
                });
            }
            break;
        }
    }

    // Variant B: forward map lookup
    if let Some((source_mi, _source_name)) = forward_map.get(&slot_val) {
        slot.candidates.insert(0, ResolutionCandidate {
            address: slot_val,
            module_index: *source_mi,
        });
    }

    // Variant C: forward_string_map lookup
    if let Some((target_mi, target_func_name)) = forward_string_map.get(&slot_val) {
        if let Some((real_addr, _)) = modules[*target_mi].exports.iter().find(|(_, name)| name.as_str() == target_func_name.as_str()) {
            slot.candidates.push(ResolutionCandidate {
                address: *real_addr,
                module_index: *target_mi,
            });
        }
    }
}

// -----------------------------------------------------------------------
// pass2_vote (Pass 2 voting + thunk building)
// -----------------------------------------------------------------------

fn pass2_vote(
    slots: &mut [IatSlot],
    modules: &[RemoteModule],
    iat_data: &mut [u8],
    iat_address: u64,
    image_base: u64,
    is_64bit: bool,
    ptr_size: usize,
    slot_count: usize,
    forward_map: &std::collections::HashMap<u64, (usize, String)>,
) -> ImportTableBuilder {
    let mut builder = ImportTableBuilder::new(is_64bit);

    let mut i = 0;
    while i < slot_count {
        if slots[i].is_zero {
            i += 1;
            continue;
        }

        let group_start = i;
        let mut group_end = i;
        while group_end + 1 < slot_count && !slots[group_end + 1].is_zero {
            group_end += 1;
        }

        // Vote
        let mut module_votes: std::collections::HashMap<usize, usize> = std::collections::HashMap::new();
        for j in group_start..=group_end {
            for c in &slots[j].candidates {
                *module_votes.entry(c.module_index).or_insert(0) += 1;
            }
        }

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
                debug!(group_start, group_end, "IAT group has no valid candidates, skipping");
                i = group_end + 1;
                continue;
            }
        };

        // Pin each slot to the winner module's candidate
        for j in group_start..=group_end {
            let mut found_winner = false;
            for (k, c) in slots[j].candidates.iter().enumerate() {
                if c.module_index == winner_mi {
                    slots[j].chosen = Some(k);
                    found_winner = true;
                    break;
                }
            }
            if !found_winner && !slots[j].candidates.is_empty() {
                slots[j].chosen = Some(0);
            }
        }

        // Build thunks
        let module_name = modules[winner_mi].name.clone();
        let mut thunks: Vec<ImportThunk> = Vec::new();

        for j in group_start..=group_end {
            let chosen = match slots[j].chosen {
                Some(c) => &slots[j].candidates[c],
                None => {
                    warn!(
                        iat_va = format!("{:#x}", iat_address + (j * ptr_size) as u64),
                        "IAT slot has no candidate for winning module, skipping"
                    );
                    continue;
                }
            };

            let actual_module_index = chosen.module_index;
            let func_name = modules[actual_module_index]
                .exports
                .get(&chosen.address)
                .cloned()
                .or_else(|| forward_map.get(&chosen.address).map(|(_, name)| name.clone()));

            write_ptr(iat_data, j * ptr_size, chosen.address, is_64bit);

            let (function_name, ordinal) = if let Some(ref name) = func_name {
                if name.starts_with('#') {
                    let ord: u16 = name[1..].parse().unwrap_or(0);
                    (None, Some(ord))
                } else {
                    (Some(name.clone()), None)
                }
            } else {
                let placeholder = format!("_unknown_{:#x}", chosen.address);
                tracing::warn!(
                    "IAT slot {} at {:#x}: unresolved, using placeholder '{}'",
                    j, iat_address + (j * ptr_size) as u64, placeholder
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
            builder.modules.push(ImportModule { name: module_name, thunks });
        }

        i = group_end + 1;
    }

    info!(
        module_count = builder.modules.len(),
        thunk_count = builder.thunk_count(),
        "Import table reconstructed"
    );

    builder
}
