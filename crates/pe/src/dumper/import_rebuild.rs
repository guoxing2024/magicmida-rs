//! Import table reconstruction via the two-pass voting algorithm.
//!
//! Extracted from `dumper.rs` — corresponds to `TDumper.Process`
//! (Pass 1 and Pass 2).

use tracing::{debug, info, warn};

use crate::error::PeError;
use crate::header::PeHeader;
use crate::iat_completeness::{IatRecoveryReport, IatSlotReport, IatSlotStatus, IatUnresolvedReason};
use crate::import_table::{iat_slot_size, ImportModule, ImportTableBuilder, ImportThunk};

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
    let (builder, report) =
        rebuild_import_table_with_report(debugger, iat_address, iat_size, image_base, is_64bit)?;
    if !report.is_complete() {
        return Err(PeError::Parse(format!(
            "IAT recovery incomplete: {}",
            report.failure_summary()
        )));
    }
    Ok(builder)
}

/// Rebuild the IAT and return an auditable per-slot report.
///
/// This API intentionally returns partial output together with the report so
/// callers can preserve evidence.  Callers that need a usable/complete table
/// must gate on [`IatRecoveryReport::is_complete`], or use
/// [`rebuild_import_table`] which does so for them.
pub fn rebuild_import_table_with_report(
    debugger: &mut dyn mida_core::DebuggerCore,
    iat_address: u64,
    iat_size: usize,
    image_base: u64,
    is_64bit: bool,
) -> Result<(ImportTableBuilder, IatRecoveryReport), PeError> {
    let (_, _, builder, report) = rebuild_import_table_inner(
        debugger,
        iat_address,
        iat_size,
        image_base,
        is_64bit,
        None, // no original imports for ApiSet decisions
    )?;

    let builder = builder
        .ok_or_else(|| PeError::Parse("Import table reconstruction produced no output".into()))?;
    Ok((builder, report))
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
) -> Result<
    (
        Vec<u8>,
        usize,
        Option<ImportTableBuilder>,
        IatRecoveryReport,
    ),
    PeError,
> {
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
        info!(iat_size = format!("{size:#x}"), "Determined IAT size");

        // Update the PE header's IAT directory
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT] =
            crate::header::ImageDataDirectory {
                virtual_address: iat_dir.virtual_address,
                size: (size + iat_slot_size(is_64bit)) as u32,
            };
        (addr, size)
    };

    // Read the IAT data at the determined location.
    let mut iat_data =
        super::helpers::alloc_capped(iat_size, super::helpers::MAX_IAT_READ_BYTES, "IAT read")?;
    let _read = debugger
        .read_memory(iat_address as usize, &mut iat_data)
        .map_err(|e| PeError::Parse(format!("Failed to read IAT: {e}")))?;

    rebuild_import_table_inner(debugger, iat_address, iat_size, image_base, is_64bit, None)
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
) -> Result<
    (
        Vec<u8>,
        usize,
        Option<ImportTableBuilder>,
        IatRecoveryReport,
    ),
    PeError,
> {
    let ptr_size = iat_slot_size(is_64bit);

    // Read the IAT
    let mut iat_data =
        super::helpers::alloc_capped(iat_size, super::helpers::MAX_IAT_READ_BYTES, "IAT rebuild")?;
    let bytes_read = debugger
        .read_memory(iat_address as usize, &mut iat_data)
        .map_err(|e| PeError::Parse(format!("Failed to read IAT: {e}")))?;
    if bytes_read < iat_size {
        warn!(
            expected = iat_size,
            actual = bytes_read,
            "Short read on IAT"
        );
    }

    // Take a snapshot of all loaded modules
    let modules = take_module_snapshot(
        debugger.process_handle(),
        debugger.pid(),
        image_base,
        is_64bit,
    )?;

    debug!(module_count = modules.len(), "Module snapshot taken");

    // Build forward maps (see comments in original dumper.rs for details).
    let mut forward_map: std::collections::HashMap<u64, (usize, String)> =
        std::collections::HashMap::new();
    let mut forward_string_map: std::collections::HashMap<u64, (usize, String)> =
        std::collections::HashMap::new();

    let mut module_priority: std::collections::HashMap<usize, i32> =
        std::collections::HashMap::new();
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

    tracing::debug!(
        "Forward map: {} entries, forward string map: {} entries",
        forward_map.len(),
        forward_string_map.len()
    );

    let slot_count = iat_size / ptr_size;

    // ============================================================
    // PASS 1: Collect candidates for every IAT slot
    // ============================================================
    let mut slots: Vec<IatSlot> = Vec::with_capacity(slot_count);

    for i in 0..slot_count {
        let off = i * ptr_size;
        let fully_read = off
            .checked_add(ptr_size)
            .is_some_and(|end| end <= bytes_read);
        let mut slot = IatSlot {
            candidates: Vec::new(),
            observed_value: None,
            rebuilt_value: None,
            chosen: None,
            is_zero: false,
            status: if fully_read {
                IatSlotStatus::Unresolved
            } else {
                IatSlotStatus::ShortRead
            },
            unresolved_reason: if fully_read {
                None
            } else {
                Some(IatUnresolvedReason::ShortRead)
            },
        };

        if !fully_read {
            slots.push(slot);
            continue;
        }

        // Capture the live value once, before PASS2 is allowed to mutate the
        // reconstruction buffer.  Reports must never re-read `iat_data` after
        // `write_ptr`, otherwise observed evidence becomes the chosen value.
        let slot_val = read_ptr(&iat_data, off, is_64bit);
        slot.observed_value = Some(slot_val);
        slot.is_zero = slot_val == 0;
        if slot.is_zero {
            slot.status = IatSlotStatus::ZeroTerminator;
            slots.push(slot);
            continue;
        }

        collect_candidates(
            &mut slot,
            slot_val,
            &modules,
            &forward_map,
            &forward_string_map,
        );

        if slot.candidates.is_empty() {
            let inside_module = modules
                .iter()
                .any(|m| m.end_off > m.base && slot_val >= m.base && slot_val < m.end_off);
            if inside_module {
                slot.status = IatSlotStatus::Stale;
                slot.unresolved_reason = Some(IatUnresolvedReason::AddressNotExported);
            } else {
                slot.status = IatSlotStatus::Unresolved;
                // The value lies outside every loaded module range.  This is a
                // deterministic offline classification; it does not assert any
                // protection cause.
                slot.unresolved_reason = Some(IatUnresolvedReason::ModuleNotFound);
            }
            debug!(
                iat_va = format!("{:#x}", iat_address + off as u64),
                slot_val = format!("{slot_val:#x}"),
                status = ?slot.status,
                reason = ?slot.unresolved_reason,
                "IAT slot unresolvable"
            );
        } else if modules.iter().any(|m| m.end_off <= m.base) {
            slot.status = IatSlotStatus::InvalidModule;
            slot.unresolved_reason = Some(IatUnresolvedReason::InvalidModule);
        } else {
            slot.status = IatSlotStatus::Resolved;
        }

        slots.push(slot);
    }

    // ============================================================
    // PASS 2: Vote on best module per zero-delimited group
    // ============================================================
    let builder = pass2_vote(
        &mut slots,
        &modules,
        &mut iat_data,
        iat_address,
        image_base,
        is_64bit,
        ptr_size,
        slot_count,
        &forward_map,
    );

    let mut report = IatRecoveryReport::new(iat_size, bytes_read, ptr_size);
    for (slot_index, slot) in slots.iter().enumerate() {
        let (module_name, function_name, ordinal) = slot
            .chosen
            .and_then(|chosen| slot.candidates.get(chosen))
            .and_then(|candidate| {
                modules
                    .get(candidate.module_index)
                    .map(|module| (module, candidate))
            })
            .map(|(module, candidate)| {
                let raw_name = module.exports.get(&candidate.address).cloned().or_else(|| {
                    forward_map
                        .get(&candidate.address)
                        .map(|(_, name)| name.clone())
                });
                let (function_name, ordinal) = export_identity(raw_name);
                (Some(module.name.clone()), function_name, ordinal)
            })
            .unwrap_or((None, None, None));
        let slot_address = iat_address + (slot_index * ptr_size) as u64;
        let slot_rva = slot_address
            .checked_sub(image_base)
            .and_then(|rva| u32::try_from(rva).ok());
        let observed_value = slot.observed_value;
        report.slots.push(IatSlotReport {
            slot_index,
            slot_address,
            slot_rva,
            observed_value,
            rebuilt_value: slot.rebuilt_value,
            // Compatibility field deliberately aliases the immutable capture.
            slot_value: observed_value,
            status: slot.status,
            unresolved_reason: slot.unresolved_reason,
            module_name,
            function_name,
            ordinal,
        });
    }

    Ok((iat_data, iat_size, Some(builder), report))
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
                    if mod_name == target_mod_lower
                        || mod_name == format!("{}.dll", target_mod_lower)
                        || mod_name.starts_with(&target_mod_lower)
                    {
                        for (target_addr, exported_func_name) in &target_module.exports {
                            if exported_func_name == target_func_name {
                                forward_string_map
                                    .insert(*fwd_string_addr, (tmi, target_func_name.to_string()));

                                let should_insert =
                                    if let Some((existing_mi, _)) = forward_map.get(target_addr) {
                                        module_priority.get(&source_mi).unwrap_or(&0)
                                            > module_priority.get(existing_mi).unwrap_or(&0)
                                    } else {
                                        true
                                    };

                                if should_insert {
                                    forward_map
                                        .insert(*target_addr, (source_mi, source_name.clone()));
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
        slot.candidates.insert(
            0,
            ResolutionCandidate {
                address: slot_val,
                module_index: *source_mi,
            },
        );
    }

    // Variant C: forward_string_map lookup
    if let Some((target_mi, target_func_name)) = forward_string_map.get(&slot_val) {
        if let Some((real_addr, _)) = modules[*target_mi]
            .exports
            .iter()
            .find(|(_, name)| name.as_str() == target_func_name.as_str())
        {
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

/// Convert the stable export-table spelling into first-class identity fields.
///
/// Export snapshots encode ordinal-only exports as `#N`; the report keeps the
/// ordinal separately so later sidecars do not need to parse a display string.
fn export_identity(raw_name: Option<String>) -> (Option<String>, Option<u16>) {
    match raw_name {
        Some(name) if name.starts_with('#') => name
            .get(1..)
            .and_then(|ordinal| ordinal.parse::<u16>().ok())
            .map_or((None, None), |ordinal| (None, Some(ordinal))),
        Some(name) if !name.is_empty() => (Some(name), None),
        _ => (None, None),
    }
}

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
        let mut module_votes: std::collections::HashMap<usize, usize> =
            std::collections::HashMap::new();
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
                for slot in &mut slots[group_start..=group_end] {
                    if !slot.is_zero {
                        slot.status = IatSlotStatus::Unresolved;
                    }
                }
                debug!(group_start, group_end, "IAT group has no valid candidates");
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
            if !found_winner {
                // A candidate from another module is not a valid substitute for
                // the winning module.  Do not serialize a thunk under the
                // winner's ImportModule with a different module's identity.
                slots[j].chosen = None;
                slots[j].rebuilt_value = None;
                if !slots[j].is_zero {
                    slots[j].status = IatSlotStatus::Unresolved;
                }
            }
        }

        // Build thunks.  Resolve the stable export identity before writing the
        // chosen address into the output buffer; the original observation is
        // already frozen in `IatSlot::observed_value`.
        let module_name = modules[winner_mi].name.clone();
        let mut thunks: Vec<ImportThunk> = Vec::new();

        for j in group_start..=group_end {
            let chosen = match slots[j]
                .chosen
                .and_then(|candidate| slots[j].candidates.get(candidate))
                .cloned()
            {
                Some(chosen) => chosen,
                None => {
                    slots[j].chosen = None;
                    slots[j].rebuilt_value = None;
                    if slots[j].status == IatSlotStatus::Resolved {
                        slots[j].status = IatSlotStatus::Unresolved;
                    }
                    warn!(
                        iat_va = format!("{:#x}", iat_address + (j * ptr_size) as u64),
                        "IAT slot has no candidate for winning module"
                    );
                    continue;
                }
            };

            let Some(module) = modules.get(chosen.module_index) else {
                slots[j].status = IatSlotStatus::InvalidModule;
                continue;
            };
            let raw_name = module.exports.get(&chosen.address).cloned().or_else(|| {
                forward_map
                    .get(&chosen.address)
                    .map(|(_, name)| name.clone())
            });
            let (function_name, ordinal) = export_identity(raw_name);
            if function_name.is_none() && ordinal.is_none() {
                slots[j].status = IatSlotStatus::Stale;
                tracing::warn!(
                    "IAT slot {} at {:#x}: export identity unavailable",
                    j,
                    iat_address + (j * ptr_size) as u64,
                );
                continue;
            }

            write_ptr(iat_data, j * ptr_size, chosen.address, is_64bit);
            slots[j].rebuilt_value = Some(chosen.address);
            slots[j].status = IatSlotStatus::Resolved;
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

    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass2_buffer_mutation_does_not_overwrite_observed_value() {
        let mut iat_data = vec![0u8; 8];
        let observed = 0x1111_2222_3333_4444u64;
        let rebuilt = 0x5555_6666_7777_8888u64;
        write_ptr(&mut iat_data, 0, observed, true);
        let mut slot = IatSlot {
            candidates: Vec::new(),
            observed_value: Some(read_ptr(&iat_data, 0, true)),
            rebuilt_value: None,
            chosen: None,
            is_zero: false,
            status: IatSlotStatus::Unresolved,
            unresolved_reason: Some(IatUnresolvedReason::ModuleNotFound),
        };

        // This is the same mutation performed by PASS2.  The report source is
        // the frozen field, never a second read from the modified buffer.
        write_ptr(&mut iat_data, 0, rebuilt, true);
        slot.rebuilt_value = Some(rebuilt);

        assert_eq!(slot.observed_value, Some(observed));
        assert_eq!(slot.rebuilt_value, Some(rebuilt));
        assert_eq!(read_ptr(&iat_data, 0, true), rebuilt);
        assert_ne!(slot.observed_value, slot.rebuilt_value);
    }

    #[test]
    fn pass2_rejects_cross_module_fallback_for_a_slot() {
        let modules = vec![
            RemoteModule {
                base: 0x1000,
                end_off: 0x2000,
                name: "kernel32.dll".into(),
                exports: std::collections::HashMap::from([(0x1100, "First".into())]),
                forwards: Vec::new(),
            },
            RemoteModule {
                base: 0x2000,
                end_off: 0x3000,
                name: "user32.dll".into(),
                exports: std::collections::HashMap::from([(0x2100, "Second".into())]),
                forwards: Vec::new(),
            },
        ];
        let mut iat_data = vec![0u8; 16];
        write_ptr(&mut iat_data, 0, 0x1100, true);
        write_ptr(&mut iat_data, 8, 0x2100, true);
        let mut slots = vec![
            IatSlot {
                candidates: vec![ResolutionCandidate {
                    address: 0x1100,
                    module_index: 0,
                }],
                observed_value: Some(0x1100),
                rebuilt_value: None,
                chosen: None,
                is_zero: false,
                status: IatSlotStatus::Resolved,
                unresolved_reason: None,
            },
            IatSlot {
                candidates: vec![ResolutionCandidate {
                    address: 0x2100,
                    module_index: 1,
                }],
                observed_value: Some(0x2100),
                rebuilt_value: None,
                chosen: None,
                is_zero: false,
                status: IatSlotStatus::Resolved,
                unresolved_reason: None,
            },
        ];

        let builder = pass2_vote(
            &mut slots,
            &modules,
            &mut iat_data,
            0x5000,
            0x4000,
            true,
            8,
            2,
            &std::collections::HashMap::new(),
        );

        assert_eq!(builder.modules.len(), 1);
        assert_eq!(builder.modules[0].name, "kernel32.dll");
        assert_eq!(builder.modules[0].thunks.len(), 1);
        assert_eq!(slots[0].chosen, Some(0));
        assert_eq!(slots[0].rebuilt_value, Some(0x1100));
        assert_eq!(slots[1].chosen, None);
        assert_eq!(slots[1].rebuilt_value, None);
        assert_eq!(slots[1].status, IatSlotStatus::Unresolved);
        assert_eq!(read_ptr(&iat_data, 8, true), 0x2100);
    }

    #[test]
    fn ordinal_export_identity_is_not_only_a_display_string() {
        assert_eq!(export_identity(Some("#42".into())), (None, Some(42)));
        assert_eq!(
            export_identity(Some("CreateFileW".into())),
            (Some("CreateFileW".into()), None)
        );
        assert_eq!(
            export_identity(Some("#not-an-ordinal".into())),
            (None, None)
        );
    }
}
