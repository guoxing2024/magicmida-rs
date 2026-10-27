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
    classic_imports: bool,
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
        classic_imports,
    )
}

// -----------------------------------------------------------------------
// rebuild_import_table_inner (the core two-pass algorithm)
// -----------------------------------------------------------------------

/// Shared inner implementation of the two-pass algorithm.
/// Post-validation for the two-pass rebuild: move every thunk whose
/// (module, function) pair the named module does not actually export to the
/// module that does export the slot's live address, and drop modules left
/// without thunks.
///
/// The loader's contract is only "the named DLL exports the named function";
/// which DLL the address physically lives in today (forwards!) is not the
/// program's business.  Measured defect: `user32!NtUserRedrawWindow` -
/// `NtUserRedrawWindow` is win32u.dll's export, so the pair failed
/// `0xC0000139` at load.
fn validate_and_regroup(
    builder: &mut ImportTableBuilder,
    iat_data: &[u8],
    iat_base_rva: u32,
    modules: &[RemoteModule],
    is_64bit: bool,
    stub_map: Option<&std::collections::HashMap<u64, (usize, String)>>,
) {
    let ptr_size = if is_64bit { 8 } else { 4 };
    let resolve = |addr: u64| -> Option<(usize, String)> {
        for (mi, m) in modules.iter().enumerate() {
            if let Some(name) = m.exports.get(&addr) {
                return Some((mi, name.clone()));
            }
        }
        None
    };

    // Regrouped output keyed by lowercase module name.
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<ImportThunk>> =
        std::collections::HashMap::new();
    let mut moved = 0usize;
    let mut dropped_thunks = 0usize;

    for module in builder.modules.drain(..) {
        for thunk in module.thunks {
            let off = (thunk.iat_address - iat_base_rva) as usize;
            let live = if off + ptr_size <= iat_data.len() {
                let b = &iat_data[off..off + ptr_size];
                if is_64bit {
                    u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
                } else {
                    u32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as u64
                }
            } else {
                0
            };

            // Prefer the stub-derived original (module, name) when this
            // slot's live address is a stub target.  Measured on the classic
            // ladder's 1.9.1 unpackme (2026-10-27): the rebuilt IAT holds
            // win32u!NtUserRedrawWindow's address where user32's own
            // RedrawWindow stub (`ff 25 [abs]`, IAT slot holding the very
            // same pointer) jumps through — the original import table named
            // user32, and (user32, "RedrawWindow") is loader-valid (the name
            // is in user32's export table, the stub lands on the same
            // function).  Both pairs resolve identically, but only the
            // derived one lets the whole user32/win32u cluster collapse
            // back into one portable user32 descriptor instead of staying
            // same-boot on the dumped live addresses.
            let derived = stub_map
                .and_then(|m| m.get(&live))
                .map(|&(mi, ref n)| (modules[mi].name.clone(), n.clone()));

            // A thunk with NEITHER a name NOR an ordinal serialises as a raw
            // value in the ILT - the loader reads it as a hint/name RVA,
            // finds it unmapped, and kills the process with
            // STATUS_ENTRYPOINT_NOT_FOUND before its first instruction
            // (measured: 2 of the 74 thunks on the classic ladder's 1.9.1
            // unpackme, in combase/ole32).  Resolve the name from the slot's
            // live address, or drop the thunk.
            if thunk.function_name.is_none() && thunk.ordinal.is_none() {
                if let Some((target_module, name)) = &derived {
                    let mut fixed = thunk.clone();
                    fixed.function_name = Some(name.clone());
                    fixed.ordinal = None;
                    moved += 1;
                    let entry = if let Some(g) = groups.get_mut(target_module) {
                        g
                    } else {
                        order.push(target_module.clone());
                        groups.entry(target_module.clone()).or_default()
                    };
                    entry.push(fixed);
                    continue;
                }
                match resolve(live) {
                    Some((mi, name)) => {
                        let target = modules[mi].name.clone();
                        let mut fixed = thunk.clone();
                        fixed.function_name = Some(name);
                        fixed.ordinal = None;
                        moved += 1;
                        let entry = if let Some(g) = groups.get_mut(&target) {
                            g
                        } else {
                            order.push(target.clone());
                            groups.entry(target).or_default()
                        };
                        entry.push(fixed);
                    }
                    None => {
                        dropped_thunks += 1;
                    }
                }
                continue;
            }

            // Named thunks: adopt the derived pair unless it equals the
            // current one (win32u bucket with its own NtUser* name is already
            // fine when no derivation exists; with one, the stub's module is
            // the faithful home).
            if let Some((target_module, name)) = &derived {
                let differs = *target_module != module.name
                    || thunk.function_name.as_deref() != Some(name.as_str());
                if differs {
                    let mut fixed = thunk.clone();
                    fixed.function_name = Some(name.clone());
                    fixed.ordinal = None;
                    moved += 1;
                    let entry = if let Some(g) = groups.get_mut(target_module) {
                        g
                    } else {
                        order.push(target_module.clone());
                        groups.entry(target_module.clone()).or_default()
                    };
                    entry.push(fixed);
                    continue;
                }
            }

            // Does the thunk's current module export the thunk's NAME?  The
            // loader's contract is name-based: it never sees the address the
            // shell's session resolved to, so an address test here would
            // re-home perfectly valid pairs (measured on the x86 v3 gate:
            // a kernel32 thunk resolved via kernelbase got moved to a new
            // kernelbase descriptor and the whole .import layout shifted -
            // the byte golden moved with it).  A name test is also what
            // makes a live-snapshot "valid" verdict match the loader's.
            let current_valid = match thunk.function_name.as_ref() {
                Some(fname) => modules.iter().any(|m| {
                    m.name == module.name
                        && m.exports.values().any(|n| n == fname)
                }),
                None => false,
            };

            if current_valid {
                let entry = if let Some(g) = groups.get_mut(&module.name) {
                    g
                } else {
                    order.push(module.name.clone());
                    groups.entry(module.name.clone()).or_default()
                };
                entry.push(thunk);
                continue;
            }

            // Re-resolve: which module really exports the live address?
            match resolve(live) {
                Some((mi, name)) => {
                    let target = modules[mi].name.clone();
                    let mut fixed = thunk.clone();
                    fixed.function_name = Some(name);
                    fixed.ordinal = None;
                    moved += 1;
                    let entry = if let Some(g) = groups.get_mut(&target) {
                        g
                    } else {
                        order.push(target.clone());
                        groups.entry(target).or_default()
                    };
                    entry.push(fixed);
                }
                None => {
                    // The slot's live address matches no export: keep the
                    // thunk where the vote put it (best effort) - a dropped
                    // thunk would break the code that calls through it.
                    let entry = if let Some(g) = groups.get_mut(&module.name) {
                        g
                    } else {
                        order.push(module.name.clone());
                        groups.entry(module.name.clone()).or_default()
                    };
                    entry.push(thunk);
                    dropped_thunks += 1;
                }
            }
        }
    }

    info!(
        moved,
        kept_unresolvable = dropped_thunks,
        total_modules = order.len(),
        "Import regroup: thunks re-homed to the module that really exports them"
    );

    builder.modules = order
        .into_iter()
        .filter_map(|name| {
            let thunks = groups.remove(&name)?;
            if thunks.is_empty() {
                None // measured: winmm.dll / oledlg.dll came out empty
            } else {
                Some(ImportModule { name, thunks })
            }
        })
        .collect();
}

// -----------------------------------------------------------------------
// build_stub_target_map (classic path)
// -----------------------------------------------------------------------

/// Extract the absolute target of a `ff 25` / `ff 15` (jmp/call [abs32])
/// stub from its first six bytes, if any.
fn stub_jump_target(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 6 || bytes[0] != 0xFF {
        return None;
    }
    match bytes[1] {
        0x25 | 0x15 => Some(u32::from_le_bytes([
            bytes[2], bytes[3], bytes[4], bytes[5],
        ])),
        _ => None,
    }
}

/// Reverse-derive stub targets: every live function address that some
/// loaded module's export stub jumps to, mapped back to that stub's own
/// (module, name).
///
/// Measured shape (2026-10-27): user32.dll's `RedrawWindow` etc. are
/// five-byte thunks `ff 25 xx xx xx xx` whose indirect target is a pointer
/// held in user32's IAT — the very win32u!NtUser* address a classic shell
/// stores in the rebuilt IAT slot.  Reading that pointer from live memory
/// gives the address to join against; the stub's module and export name are
/// the original import pair the loader can resolve.
///
/// Scans every export address of every loaded module; a stub is only
/// recorded when its target lands inside a *different* module's range.
/// Cost: one 6-byte read per export plus one pointer read per thunk — a
/// few thousand reads on a 20k-export snapshot, classic-only.
fn build_stub_target_map(
    debugger: &mut dyn mida_core::DebuggerCore,
    modules: &[RemoteModule],
    _is_64bit: bool,
) -> std::collections::HashMap<u64, (usize, String)> {
    let mut map: std::collections::HashMap<u64, (usize, String)> =
        std::collections::HashMap::new();

    for (mi, m) in modules.iter().enumerate() {
        for (&addr, name) in m.exports.iter() {
            let mut stub = [0u8; 6];
            if debugger.read_memory(addr as usize, &mut stub).map(|n| n < 6).unwrap_or(true) {
                continue;
            }
            let Some(target) = stub_jump_target(&stub) else { continue };
            let target = target as u64;
            let mut ptr = [0u8; 4];
            if debugger
                .read_memory(target as usize, &mut ptr)
                .map(|n| n < 4)
                .unwrap_or(true)
            {
                continue;
            }
            let ptr_val = u32::from_le_bytes(ptr) as u64;
            // The pointer must land in a different module's range for the
            // join against a rebuilt IAT slot to be meaningful.
            let owner = modules
                .iter()
                .position(|m2| m2.base != m.base && m2.base <= ptr_val && ptr_val < m2.end_off);
            if let Some(_owner_idx) = owner {
                map.entry(ptr_val).or_insert((mi, name.clone()));
            }
        }
    }

    map
}

// -----------------------------------------------------------------------
// normalize_module_runs (classic path)
// -----------------------------------------------------------------------

/// Split the regrouped per-name buckets into address-contiguous descriptors.
///
/// The PE loader's contract is a parallel array per descriptor: it walks
/// `FirstThunk` slot by slot until the first zero and resolves **every**
/// entry it passes under that descriptor's DLL name.  Pass 2 buckets thunks
/// by the module each slot actually resolved to — correct per (module, name)
/// pair, but on classic (Themida 1.x) targets the shell rebuilds the whole
/// IAT region as one flat array, so one original array's slots contribute to
/// SEVERAL buckets, interleaved by address.  Measured on the ladder's 1.9.1
/// unpackme (2026-10-27):
///
/// ```text
/// user32  array slots 0..39, but slots 7,8,21 resolved to win32u!NtUser*
/// combase array slots .., with OleInitialize/OleFlushClipboard resolved to
///         ole32 (a genuine ole32 export) interleaved in between
/// ```
///
/// Serialising one descriptor per bucket then breaks the walk twice over:
/// the loader reads win32u's hint entries as user32 entries
/// (`user32!NtUserRedrawWindow` — a pair user32's name table does not have,
/// `STATUS_ENTRYPOINT_NOT_FOUND` before the first instruction), and an
/// unowned gap slot keeps its dumped live API address, which the loader
/// misreads as a hint/name RVA — the same failure.
///
/// One descriptor per maximal address-contiguous run makes every walked
/// array contain exactly its own thunks.  Runs of *different* modules that
/// sit directly adjacent cannot both be expressed (the first run's terminator
/// would clobber the second run's first thunk), so adjacent runs are merged
/// into clusters and each cluster is covered by the first module under which
/// **every** name is valid.  A forwarded name is valid under the forwarding
/// module: its string sits in that module's export name table (the RVA merely
/// points into the export directory), and the loader resolves the forwarder
/// chain to the very address the slot already held — measured:
/// `ole32!CLSIDFromString` → `api-ms-win-core-com-l1-1-0` → combase, all
/// names of the mixed combase/ole32 region are ole32-valid, so that whole
/// region becomes one ole32 descriptor and loads portably.
///
/// A cluster with no such module (the user32/win32u one: user32's name table
/// has no `NtUser*`, win32u's has none of the surrounding user32 names) is
/// left **undescribed**: its slots keep the dumped live addresses, no
/// descriptor walks them, and the loader never touches them.  The OEP code's
/// calls through those slots keep working for as long as the system DLL
/// bases match the dump session (same boot) — recorded as the classic line's
/// portability gap, not claimed as loader-resolved.
pub(crate) fn normalize_module_runs(builder: &mut ImportTableBuilder, snapshot: &[RemoteModule]) {
    let ptr = iat_slot_size(builder.is_64bit) as u32;

    let name_valid_under = |module_name: &str, fname: &str| -> bool {
        snapshot.iter().any(|m| {
            m.name == module_name && m.exports.values().any(|n| n == fname)
        })
    };

    // Flatten and sort by recorded IAT slot.  Addresses are unique across the
    // builder (one thunk per traced slot); a duplicate would mean a pass-2 or
    // regroup defect — keep the first, count the rest.
    let mut all: Vec<(String, ImportThunk)> = Vec::new();
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut duplicates = 0usize;
    for module in &builder.modules {
        for thunk in &module.thunks {
            if seen.insert(thunk.iat_address) {
                all.push((module.name.clone(), thunk.clone()));
            } else {
                duplicates += 1;
            }
        }
    }
    all.sort_by_key(|(_, t)| t.iat_address);

    // Maximal same-module, address-contiguous runs.
    let mut runs: Vec<(String, Vec<ImportThunk>)> = Vec::new();
    for (name, thunk) in all {
        match runs.last_mut() {
            Some((n, list))
                if *n == name
                    && list.last().unwrap().iat_address + ptr == thunk.iat_address =>
            {
                list.push(thunk);
            }
            _ => runs.push((name, vec![thunk])),
        }
    }

    // Clusters: transitively merge runs whose terminator position would land
    // on the next run's first slot.
    let mut clusters: Vec<Vec<(String, Vec<ImportThunk>)>> = Vec::new();
    for run in runs {
        match clusters.last_mut() {
            Some(cluster) => {
                let prev_end = cluster.last().unwrap().1.last().unwrap().iat_address;
                if prev_end + ptr == run.1[0].iat_address {
                    cluster.push(run);
                    continue;
                }
                clusters.push(vec![run]);
            }
            None => clusters.push(vec![run]),
        }
    }

    // Emit: single-run clusters under their own module; multi-run clusters
    // under the first candidate module that exports every name; else undescribed.
    let mut out: Vec<ImportModule> = Vec::new();
    let mut merged_clusters = 0usize;
    let mut uncovered_slots = 0usize;
    let mut uncovered_modules: Vec<String> = Vec::new();
    for mut cluster in clusters {
        if cluster.len() == 1 {
            let (name, thunks) = cluster.pop().unwrap();
            out.push(ImportModule { name, thunks });
            continue;
        }

        let slot_count: usize = cluster.iter().map(|(_, t)| t.len()).sum();
        let mut candidates: Vec<String> = Vec::new();
        for (name, _) in &cluster {
            if !candidates.iter().any(|c| c == name) {
                candidates.push(name.clone());
            }
        }
        let chosen = candidates.iter().find(|cand| {
            let cand: &String = cand;
            cluster.iter().all(|(_, thunks)| {
                thunks.iter().all(|t| match t.function_name.as_ref() {
                    // An ordinal only resolves under its own module.
                    Some(fname) => name_valid_under(cand, fname),
                    None => t.ordinal.is_some() && *cand == candidate_self_module(&cluster, t),
                })
            })
        });
        match chosen {
            Some(module_name) => {
                merged_clusters += 1;
                let mut thunks: Vec<ImportThunk> = Vec::new();
                for (_, list) in &cluster {
                    thunks.extend(list.iter().cloned());
                }
                out.push(ImportModule {
                    name: module_name.clone(),
                    thunks,
                });
            }
            None => {
                uncovered_slots += slot_count;
                for (name, _) in &cluster {
                    if !uncovered_modules.iter().any(|m| m == name) {
                        uncovered_modules.push(name.clone());
                    }
                }
            }
        }
    }

    info!(
        descriptors = out.len(),
        merged_clusters,
        uncovered_slots,
        duplicate_slots = duplicates,
        uncovered_modules = ?uncovered_modules,
        "Classic IAT normalized to address-contiguous descriptors"
    );

    builder.modules = out;
}

/// The (unique) module name of the cluster member holding `thunk`.
fn candidate_self_module(cluster: &[(String, Vec<ImportThunk>)], thunk: &ImportThunk) -> String {
    for (name, list) in cluster {
        if list.iter().any(|t| t.iat_address == thunk.iat_address) {
            return name.clone();
        }
    }
    String::new()
}


fn rebuild_import_table_inner(
    debugger: &mut dyn mida_core::DebuggerCore,
    iat_address: u64,
    iat_size: usize,
    image_base: u64,
    is_64bit: bool,
    _original_imports: Option<&[String]>,
    classic_imports: bool,
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
    let mut builder = pass2_vote(&mut slots, &modules, &mut iat_data, iat_address, image_base, is_64bit, ptr_size, slot_count, &forward_map);

    // ---- post-validation: every (module, function) pair must exist -------
    //
    // Measured on the classic ladder's 1.9.1 unpackme (2026-10-27): pass 2's
    // group vote pairs a slot's resolved NAME with a neighbouring slot's
    // MODULE when Windows forwards the export (user32!RedrawWindow lives in
    // win32u.dll today), producing `user32!NtUserRedrawWindow` - a pair the
    // loader refuses with STATUS_ENTRYPOINT_NOT_FOUND (0xC0000139), and the
    // product dies before its first instruction.  Re-resolve every thunk
    // from its slot's live address and regroup; the loader only requires
    // that the named module actually exports the named function.
    let iat_base_rva = (iat_address - image_base) as u32;
    if classic_imports {
        let stub_map = build_stub_target_map(debugger, &modules, is_64bit);
        if !stub_map.is_empty() {
            info!(stub_targets = stub_map.len(), "Stub target map built");
        }
        validate_and_regroup(&mut builder, &iat_data, iat_base_rva, &modules, is_64bit, Some(&stub_map));
        normalize_module_runs(&mut builder, &modules);
    }

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
    // Variant A: direct match against every module's export map.
    //
    // **No address-range test, and no `break`.**
    //
    // Two independent reasons, both measured on the x86 reference sample.
    //
    // 1. `break` at the first containing module.  A single resolved address can
    //    be exported under several names.  IAT slot rva 0x7208 holds
    //    `0x77ba5610`, which `GetProcAddress` resolves as both
    //    `ntdll!NtdllDefWindowProc_A` and `user32!DefWindowProcA` — the two
    //    names return the identical address.  Stopping early kept only one
    //    spelling and made the slot disagree with its group.
    //
    // 2. The range test itself is wrong for aliased exports.  `user32`'s export
    //    map contains `0x77ba5610` = `user32.base + 0x1115610`, but
    //    `0x1115610` is larger than user32's own image (0x1ED000), so the
    //    address lies *outside* user32's `[base, end_off)` range — inside
    //    ntdll's instead.  An export map is keyed by the address the export
    //    really has, so it is the authority; the range test only ever subtracted
    //    real candidates from it.
    //
    // Together they made the rebuilt table declare `user32!NtdllDefWindowProc_A`
    // — a pair `GetProcAddress` cannot resolve — and the loader died with
    // `0xC0000139 STATUS_ENTRYPOINT_NOT_FOUND`.  The original program imported
    // `user32!DefWindowProcA`.
    //
    // Keeping every module's spelling lets `pass2_vote`'s "prefer the winning
    // module" rule choose the one that matches the slot's own group.
    for (mi, m) in modules.iter().enumerate() {
        if m.exports.contains_key(&slot_val) {
            slot.candidates.push(ResolutionCandidate {
                address: slot_val,
                module_index: mi,
            });
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

        // Choose a candidate for every slot in the group.
        //
        // The original implementation forced the whole group onto the winning
        // module's candidate, falling back to candidate 0 for slots that had no
        // candidate from that module.  That is wrong for a Themida DLL whose IAT
        // interleaves real API pointers with shell trampolines and contains no
        // zero separators at all — observed layout on the reference sample:
        //
        //   0x1421a0  0x7fffe43dd280   user32 API
        //   0x1421a8  0x7fff2d181f8b   shell trampoline
        //   0x1421b0  0x7fff2d042c4f   shell trampoline
        //   0x1421c0  0x7fffe4401ea0   user32 API
        //
        // With no zeros to split on, that whole run forms one group, the vote
        // picks a single module, and the slots belonging to other modules get
        // either a wrong name or are dropped.  Result: `CreateWindowExA`,
        // `GetSystemMetrics` and `LoadIconA` were missing from the rebuilt table
        // and the dumped DLL crashed inside `.import` when `Run()` called them.
        //
        // Prefer the winner module when it has a candidate (keeps the common
        // case identical), otherwise take that slot's own best candidate.
        for j in group_start..=group_end {
            if slots[j].candidates.is_empty() {
                continue;
            }
            let mut chosen_idx = 0usize;
            for (k, c) in slots[j].candidates.iter().enumerate() {
                if c.module_index == winner_mi {
                    chosen_idx = k;
                    break;
                }
            }
            slots[j].chosen = Some(chosen_idx);
        }

        // Build thunks, bucketed by the module each slot actually resolved to.
        //
        // The group no longer implies a single module (see the selection comment
        // above), so a group can contribute thunks to several import descriptors.
        // Bucket by module index and emit one `ImportModule` per bucket.
        let mut by_module: std::collections::BTreeMap<usize, Vec<ImportThunk>> =
            std::collections::BTreeMap::new();

        for j in group_start..=group_end {
            let chosen = match slots[j].chosen {
                Some(c) => &slots[j].candidates[c],
                None => {
                    debug!(
                        iat_va = format!("{:#x}", iat_address + (j * ptr_size) as u64),
                        "IAT slot has no candidate, skipping"
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

            by_module.entry(actual_module_index).or_default().push(ImportThunk {
                iat_address: (iat_address - image_base) as u32 + (j * ptr_size) as u32,
                function_name,
                ordinal,
                is_64bit,
            });
        }

        for (mi, thunks) in by_module {
            builder.modules.push(ImportModule {
                name: modules[mi].name.clone(),
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

// -----------------------------------------------------------------------
// Tests — normalize_module_runs
// -----------------------------------------------------------------------

#[cfg(test)]
mod normalize_tests {
    use super::*;
    use crate::import_table::ImportThunk;

    fn thunk(rva: u32, name: &str) -> ImportThunk {
        ImportThunk {
            iat_address: rva,
            function_name: Some(name.to_string()),
            ordinal: None,
            is_64bit: false,
        }
    }

    fn module_with_thunks(name: &str, thunks: Vec<ImportThunk>) -> ImportModule {
        ImportModule {
            name: name.to_string(),
            thunks,
        }
    }

    fn snapshot_module(name: &str, exports: &[&str]) -> RemoteModule {
        let mut map = std::collections::HashMap::new();
        for (i, n) in exports.iter().enumerate() {
            // Forwarder-style entries carry a bogus address (inside the export
            // directory); the NAME is what normalize_module_runs matches on.
            map.insert(0x7f000000 + 0x1000 * i as u64, n.to_string());
        }
        RemoteModule {
            base: 0x7f000000,
            end_off: 0x7f100000,
            name: name.to_string(),
            exports: map,
            forwards: Vec::new(),
        }
    }

    /// The measured combase/ole32 shape: interleaved buckets whose every name
    /// is valid under ole32 (forwarders) collapse into ONE ole32 descriptor
    /// covering the whole cluster, thunks in position order.
    #[test]
    fn adjacent_cluster_merges_under_the_module_that_exports_every_name() {
        let mut builder = ImportTableBuilder::new(false);
        // Positions: 0x1000..0x100c combase, 0x100c..0x1014 ole32, 0x1014 combase
        builder.modules.push(module_with_thunks("combase.dll", vec![
            thunk(0x1000, "CLSIDFromString"),
            thunk(0x1004, "CLSIDFromProgID"),
            thunk(0x1008, "CoTaskMemFree"),
            thunk(0x1014, "CoRevokeClassObject"),
        ]));
        builder.modules.push(module_with_thunks("ole32.dll", vec![
            thunk(0x100c, "OleInitialize"),
            thunk(0x1010, "OleUninitialize"),
        ]));
        let snapshot = vec![
            snapshot_module("combase.dll", &["CLSIDFromString", "CLSIDFromProgID", "CoTaskMemFree", "CoRevokeClassObject"]),
            // ole32 carries every name via forwarder name entries.
            snapshot_module("ole32.dll", &["CLSIDFromString", "CLSIDFromProgID", "CoTaskMemFree",
                "CoRevokeClassObject", "OleInitialize", "OleUninitialize"]),
        ];

        normalize_module_runs(&mut builder, &snapshot);

        assert_eq!(builder.modules.len(), 1, "one cluster -> one descriptor");
        let m = &builder.modules[0];
        assert_eq!(m.name, "ole32.dll", "first candidate under which every name is valid");
        let rvas: Vec<u32> = m.thunks.iter().map(|t| t.iat_address).collect();
        assert_eq!(rvas, vec![0x1000, 0x1004, 0x1008, 0x100c, 0x1010, 0x1014],
            "thunks stay in slot-position order");
    }

    /// The measured user32/win32u shape: no candidate module exports every
    /// name, so the cluster is left undescribed and the slots keep their
    /// dumped live addresses.
    #[test]
    fn unmergeable_cluster_is_left_undescribed() {
        let mut builder = ImportTableBuilder::new(false);
        builder.modules.push(module_with_thunks("user32.dll", vec![
            thunk(0x2000, "MessageBoxA"),
            thunk(0x2004, "LoadIconA"),
            thunk(0x200c, "GetDC"),
        ]));
        builder.modules.push(module_with_thunks("win32u.dll", vec![
            thunk(0x2008, "NtUserRedrawWindow"),
        ]));
        let snapshot = vec![
            // user32 does NOT export NtUserRedrawWindow; win32u does not
            // export MessageBoxA — exactly the measured name tables.
            snapshot_module("user32.dll", &["MessageBoxA", "LoadIconA", "GetDC"]),
            snapshot_module("win32u.dll", &["NtUserRedrawWindow"]),
        ];

        normalize_module_runs(&mut builder, &snapshot);

        assert!(builder.modules.is_empty(), "no coverable cluster -> no descriptor");
    }

    /// A standalone run with a free slot after it keeps its own module and is
    /// covered by its own descriptor.
    #[test]
    fn standalone_run_keeps_its_own_module() {
        let mut builder = ImportTableBuilder::new(false);
        builder.modules.push(module_with_thunks("winspool.drv", vec![
            thunk(0x3000, "OpenPrinterA"),
            thunk(0x3004, "ClosePrinter"),
        ]));
        builder.modules.push(module_with_thunks("comdlg32.dll", vec![
            thunk(0x300c, "FindTextA"),
        ]));
        let snapshot = vec![
            snapshot_module("winspool.drv", &["OpenPrinterA", "ClosePrinter"]),
            snapshot_module("comdlg32.dll", &["FindTextA"]),
        ];

        normalize_module_runs(&mut builder, &snapshot);

        assert_eq!(builder.modules.len(), 2);
        assert_eq!(builder.modules[0].name, "winspool.drv");
        assert_eq!(builder.modules[1].name, "comdlg32.dll");
        assert_eq!(builder.modules[1].thunks[0].iat_address, 0x300c);
    }

    /// Runs are split on ANY address gap, even inside one bucket: the loader
    /// must not walk a gap slot as this module's entry.
    #[test]
    fn bucket_split_on_interior_gap() {
        let mut builder = ImportTableBuilder::new(false);
        builder.modules.push(module_with_thunks("combase.dll", vec![
            thunk(0x4000, "CoTaskMemFree"),
            // gap at 0x4004 (the measured 0x761b0a0d slot)
            thunk(0x4008, "CoGetClassObject"),
        ]));
        let snapshot = vec![snapshot_module("combase.dll", &["CoTaskMemFree", "CoGetClassObject"])];

        normalize_module_runs(&mut builder, &snapshot);

        assert_eq!(builder.modules.len(), 2, "gap splits the bucket into two runs");
        assert_eq!(builder.modules[0].thunks[0].iat_address, 0x4000);
        assert_eq!(builder.modules[1].thunks[0].iat_address, 0x4008);
    }

    /// An ordinal thunk inside a merged cluster is only accepted under its
    /// own module.
    #[test]
    fn ordinal_thunk_blocks_foreign_merge() {
        let mut builder = ImportTableBuilder::new(false);
        builder.modules.push(module_with_thunks("a.dll", vec![thunk(0x5000, "A1")]));
        let mut ord = thunk(0x5004, "");
        ord.function_name = None;
        ord.ordinal = Some(7);
        builder.modules.push(module_with_thunks("b.dll", vec![ord]));
        let snapshot = vec![
            // a.dll exports A1 but nothing else; b.dll only has the ordinal.
            snapshot_module("a.dll", &["A1"]),
            snapshot_module("b.dll", &[]),
        ];

        normalize_module_runs(&mut builder, &snapshot);

        // The two runs are adjacent, so they form ONE cluster: covering a.dll
        // alone would write its terminator over the ordinal's live slot.  No
        // candidate module expresses both, so the whole cluster stays
        // undescribed and both slots keep their dumped live addresses.
        assert!(builder.modules.is_empty());
    }
}

#[cfg(test)]
mod stub_tests {
    use super::*;
    use crate::import_table::{ImportThunk};

    fn thunk(rva: u32, name: Option<&str>) -> ImportThunk {
        ImportThunk {
            iat_address: rva,
            function_name: name.map(|n| n.to_string()),
            ordinal: None,
            is_64bit: false,
        }
    }

    fn snapshot_module(name: &str, exports: &[(&str, u64)]) -> RemoteModule {
        let mut map = std::collections::HashMap::new();
        for (n, a) in exports {
            map.insert(*a, n.to_string());
        }
        RemoteModule {
            base: 0x7f000000,
            end_off: 0x7f800000,
            name: name.to_string(),
            exports: map,
            forwards: Vec::new(),
        }
    }

    /// The measured user32.dll (SysWOW64, 2026-10-27) stub shape — pinned
    /// byte-for-byte against the real file so a shape change fails the test.
    #[test]
    fn measured_user32_stub_shape_is_recognised() {
        // RedrawWindow @0x3b0e0: ff 25 90 ee 0e 10 -> jmp [0x100eee90]
        assert_eq!(
            stub_jump_target(&[0xff, 0x25, 0x90, 0xee, 0x0e, 0x10]),
            Some(0x100eee90)
        );
        // InvalidateRect @0x3ad10: ff 25 84 ef 0e 10 -> jmp [0x100eef84]
        assert_eq!(
            stub_jump_target(&[0xff, 0x25, 0x84, 0xef, 0x0e, 0x10]),
            Some(0x100eef84)
        );
        // call [abs] variant
        assert_eq!(stub_jump_target(&[0xff, 0x15, 0x11, 0x22, 0x33, 0x44]), Some(0x44332211));
        // Real function bodies are not thunks: GetSysColor (8b ff 55 8b ec),
        // LoadIconA (8b ff 55 8b ec 51), a plain jmp rel32 (e8).
        assert_eq!(stub_jump_target(&[0x8b, 0xff, 0x55, 0x8b, 0xec, 0x8b]), None);
        assert_eq!(stub_jump_target(&[0x8b, 0xff, 0x55, 0x8b, 0xec, 0x51]), None);
        assert_eq!(stub_jump_target(&[0xe8, 0x94, 0x21, 0x00, 0x00, 0xff]), None);
        // short buffers
        assert_eq!(stub_jump_target(&[0xff, 0x25]), None);
        assert_eq!(stub_jump_target(&[]), None);
    }

    /// The measured regroup scenario: a win32u-bucketed NtUser* thunk whose
    /// live address is user32's RedrawWindow stub target gets re-homed to
    /// (user32, RedrawWindow) — the original, portable pair.
    #[test]
    fn stub_derivation_rehomes_ntuser_thunks_to_user32() {
        let live_win32u_addr: u64 = 0x7f12a0; // win32u base 0x7f000000 + 0x12a0
        let mut iat_data = vec![0u8; 8];
        iat_data[0..4].copy_from_slice(&(live_win32u_addr as u32).to_le_bytes());

        let mut builder = ImportTableBuilder::new(false);
        builder.modules.push(ImportModule {
            name: "win32u.dll".into(),
            thunks: vec![thunk(0x60de8, Some("NtUserRedrawWindow"))],
        });
        builder.modules.push(ImportModule {
            name: "user32.dll".into(),
            thunks: vec![thunk(0x60e00, Some("MessageBoxA"))],
        });

        let modules = vec![
            snapshot_module("user32.dll", &[("RedrawWindow", 0x7f00100), ("MessageBoxA", 0x7f00200)]),
            snapshot_module("win32u.dll", &[("NtUserRedrawWindow", live_win32u_addr)]),
        ];
        let mut stub_map = std::collections::HashMap::new();
        stub_map.insert(live_win32u_addr, (0, "RedrawWindow".to_string()));

        validate_and_regroup(
            &mut builder, &iat_data, 0x60de8, &modules, false, Some(&stub_map),
        );

        assert_eq!(builder.modules.len(), 1, "win32u group is empty and dropped");
        assert_eq!(builder.modules[0].name, "user32.dll");
        assert_eq!(builder.modules[0].thunks.len(), 2);
        let renamed = &builder.modules[0].thunks[0];
        assert_eq!(renamed.iat_address, 0x60de8);
        assert_eq!(renamed.function_name.as_deref(), Some("RedrawWindow"));
    }

    /// No derivation for the address: the thunk keeps its own bucket.
    #[test]
    fn without_derivation_thunk_stays_where_it_was() {
        let live_addr: u64 = 0x7f12a0;
        let mut iat_data = vec![0u8; 8];
        iat_data[0..4].copy_from_slice(&(live_addr as u32).to_le_bytes());

        let mut builder = ImportTableBuilder::new(false);
        builder.modules.push(ImportModule {
            name: "win32u.dll".into(),
            thunks: vec![thunk(0x60de8, Some("NtUserRedrawWindow"))],
        });
        let modules = vec![
            snapshot_module("user32.dll", &[("RedrawWindow", 0x7f00100)]),
            snapshot_module("win32u.dll", &[("NtUserRedrawWindow", live_addr)]),
        ];
        let empty: std::collections::HashMap<u64, (usize, String)> =
            std::collections::HashMap::new();

        validate_and_regroup(
            &mut builder, &iat_data, 0x60de8, &modules, false, Some(&empty),
        );

        assert_eq!(builder.modules.len(), 1);
        assert_eq!(builder.modules[0].name, "win32u.dll");
        assert_eq!(builder.modules[0].thunks[0].function_name.as_deref(), Some("NtUserRedrawWindow"));
    }

    /// A nameless thunk gets the derived name instead of a placeholder.
    #[test]
    fn nameless_thunk_gets_derived_name() {
        let live_addr: u64 = 0x7f12a0;
        let mut iat_data = vec![0u8; 8];
        iat_data[0..4].copy_from_slice(&(live_addr as u32).to_le_bytes());

        let mut builder = ImportTableBuilder::new(false);
        builder.modules.push(ImportModule {
            name: "win32u.dll".into(),
            thunks: vec![thunk(0x60de8, None)],
        });
        let modules = vec![
            snapshot_module("user32.dll", &[("RedrawWindow", 0x7f00100)]),
            snapshot_module("win32u.dll", &[]),
        ];
        let mut stub_map = std::collections::HashMap::new();
        stub_map.insert(live_addr, (0, "RedrawWindow".to_string()));

        validate_and_regroup(
            &mut builder, &iat_data, 0x60de8, &modules, false, Some(&stub_map),
        );

        assert_eq!(builder.modules.len(), 1);
        assert_eq!(builder.modules[0].name, "user32.dll");
        assert_eq!(builder.modules[0].thunks[0].function_name.as_deref(), Some("RedrawWindow"));
    }
}
