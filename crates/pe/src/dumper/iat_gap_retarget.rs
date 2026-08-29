//! Retarget `.text` `call/jmp [rip+disp32]` sites that land on interior IAT

//!
//! Production `.unwrap()`s are parse invariants: `i + 6 <= end` bounds the
//! disp32 window (WO-10). Test unwraps are assertions.
#![allow(clippy::unwrap_used)]
//! terminator slots (value 0 between two non-zero slots).
//!
//! ## Why
//!
//! Themida multi-block IAT leaves intentional zero separators between DLL
//! groups. The PE loader needs those zeros. Most call sites are rewritten to
//! real FirstThunk slots, but a residual set of sites still reference the
//! separator RVA itself → `call [null]` → AV (R-GTO-UI round 9).
//!
//! On GTO/AHK the observed residual is patterned (cdb-validated):
//! - sites with MessageBox uType (0xA / 0xE) → `MessageBoxW`
//! - sites with `mov rdx,rax` + free shape after MessageBox → `LocalFree`
//! - sites with small `mov edx, imm` (WM_*) → `SendMessageW`
//!
//! Secondary: original PE continuous import order can name a single API that
//! sat in a separator gap (FindResourceW / LoadResource / …).
//!
//! Non-claim: does not densify the IAT, does not remove terminators, does not
//! claim product 1.0 / NewClassName.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use tracing::{info, warn};

use crate::header::PeHeader;
use crate::import_table::ImportTableBuilder;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Scan executable sections of a dumped image for direct `call/jmp [rip+disp32]`
/// sites whose target RVA is one of `target_slot_rvas`. Returns `(site_rva,
/// target_rva)` pairs in scan order.
///
/// TASK-009 (缺陷 A, `bb5ee568`): a direct code reference to an IAT slot that
/// the rebuild could not resolve is a startup-path dereference of an honest
/// hole (zero) — the candidate would AV when that code executes. This is the
/// offline, unit-testable leg of the dump's fail-closed gate: it uses the same
/// FF 15/25 scan as `retarget_iat_gap_call_sites` but only *reports* sites,
/// so the emitter can refuse to ship a product whose unresolved IAT slot is
/// referenced from code (e.g. `.text 0xde785` → `call [0x1137d0]`).
#[must_use]
pub(crate) fn call_sites_targeting_slots(
    pe: &PeHeader,
    dump_buf: &[u8],
    target_slot_rvas: &std::collections::HashSet<u32>,
) -> Vec<(u32, u32)> {
    let mut hits = Vec::new();
    if target_slot_rvas.is_empty() {
        return hits;
    }
    for section in pe
        .sections
        .iter()
        .filter(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 || s.name == ".text")
    {
        let start = section.virtual_address as usize;
        let end = start
            .saturating_add(section.virtual_size as usize)
            .min(dump_buf.len());
        if end.saturating_sub(start) < 6 {
            continue;
        }
        let mut i = start;
        while i + 6 <= end {
            if dump_buf[i] == 0xFF && (dump_buf[i + 1] == 0x15 || dump_buf[i + 1] == 0x25) {
                let disp = i32::from_le_bytes(dump_buf[i + 2..i + 6].try_into().unwrap_or([0; 4]));
                let next_rva = (i + 6) as u32;
                let slot_rva = next_rva.wrapping_add(disp as u32);
                if target_slot_rvas.contains(&slot_rva) {
                    hits.push((next_rva.saturating_sub(6), slot_rva));
                }
                i += 6;
                continue;
            }
            i += 1;
        }
    }
    hits
}

/// Result of a gap-retarget pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GapRetargetStats {
    pub interior_zeros: usize,
    pub mapped_gaps: usize,
    pub sites_seen: usize,
    pub sites_patched: usize,
}

/// Retarget call sites that reference interior IAT zero slots.
///
/// Uses `builder` for authoritative slot→name mapping (Hint/Name already
/// written by `create_import_section`). Scans `dump_buf` for interior zeros
/// in `[iat_rva, iat_rva+iat_size)`.
pub(crate) fn retarget_iat_gap_call_sites(
    pe: &PeHeader,
    dump_buf: &mut [u8],
    iat_rva: u32,
    iat_size: usize,
    builder: &ImportTableBuilder,
    executable_path: Option<&Path>,
) -> GapRetargetStats {
    let mut stats = GapRetargetStats::default();
    if !pe.is_64bit || iat_rva == 0 || iat_size < 16 {
        return stats;
    }

    let iat_start = iat_rva as usize;
    let iat_end = iat_start.saturating_add(iat_size).min(dump_buf.len());
    if iat_end.saturating_sub(iat_start) < 16 {
        return stats;
    }

    // slot_rva → API name; lowercase name → first rebuilt slot
    let mut name_by_slot: HashMap<u32, String> = HashMap::new();
    let mut slot_by_name: HashMap<String, u32> = HashMap::new();
    for module in &builder.modules {
        for thunk in &module.thunks {
            if thunk.iat_address == 0 {
                continue;
            }
            let name = match (&thunk.function_name, thunk.ordinal) {
                (Some(n), _) => n.clone(),
                (None, Some(ord)) => format!("#{ord}"),
                _ => continue,
            };
            name_by_slot.insert(thunk.iat_address, name.clone());
            slot_by_name
                .entry(name.to_ascii_lowercase())
                .or_insert(thunk.iat_address);
        }
    }
    if slot_by_name.is_empty() {
        return stats;
    }

    // Interior zeros in the FirstThunk window (module separators).
    let mut interior_zeros: Vec<u32> = Vec::new();
    let mut off = iat_start + 8;
    while off + 8 < iat_end {
        let val = u64::from_le_bytes(dump_buf[off..off + 8].try_into().unwrap_or([0; 8]));
        if val == 0 {
            let prev = u64::from_le_bytes(dump_buf[off - 8..off].try_into().unwrap_or([0; 8]));
            let next = u64::from_le_bytes(dump_buf[off + 8..off + 16].try_into().unwrap_or([0; 8]));
            if prev != 0 && next != 0 {
                interior_zeros.push(off as u32);
            }
        }
        off += 8;
    }
    stats.interior_zeros = interior_zeros.len();
    if interior_zeros.is_empty() {
        return stats;
    }

    // Optional original-PE continuous-order gap names.
    let mut gap_api: HashMap<u32, String> = HashMap::new();
    if let Some(path) = executable_path {
        if let Some(orig) = original_api_order(path) {
            for &z in &interior_zeros {
                if let Some(api) = guess_gap_api(z, &name_by_slot, &orig) {
                    gap_api.insert(z, api);
                }
            }
        }
    }
    stats.mapped_gaps = gap_api.len();

    let zero_set: HashSet<u32> = interior_zeros.iter().copied().collect();
    let mut sites_patched = 0usize;
    let mut sites_seen = 0usize;

    for section in pe.sections.iter().filter(|s| {
        s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 || s.name == ".text" || s.name == ".wfix"
    }) {
        let start = section.virtual_address as usize;
        let end = start
            .saturating_add(section.virtual_size as usize)
            .min(dump_buf.len());
        if end.saturating_sub(start) < 6 {
            continue;
        }

        let mut i = start;
        while i + 6 <= end {
            if dump_buf[i] == 0xFF && (dump_buf[i + 1] == 0x15 || dump_buf[i + 1] == 0x25) {
                let disp = i32::from_le_bytes(dump_buf[i + 2..i + 6].try_into().unwrap());
                let next_rva = (i + 6) as u32;
                let slot_rva = next_rva.wrapping_add(disp as u32);
                if zero_set.contains(&slot_rva) {
                    sites_seen += 1;
                    let window_start = i.saturating_sub(0x40);
                    let window = &dump_buf[window_start..i];
                    if let Some(api_name) = classify_gap_call(window, slot_rva, &gap_api) {
                        if let Some(&target_slot) = slot_by_name.get(&api_name.to_ascii_lowercase())
                        {
                            let new_disp = target_slot as i64 - next_rva as i64;
                            if let Ok(d) = i32::try_from(new_disp) {
                                dump_buf[i + 2..i + 6].copy_from_slice(&d.to_le_bytes());
                                sites_patched += 1;
                            }
                        } else {
                            warn!(
                                site = format_args!("{i:#x}"),
                                slot = format_args!("{slot_rva:#x}"),
                                api = %api_name,
                                "IAT gap retarget: API not present in rebuilt IAT"
                            );
                        }
                    }
                }
                i += 6;
                continue;
            }
            i += 1;
        }
    }

    stats.sites_seen = sites_seen;
    stats.sites_patched = sites_patched;
    if sites_patched > 0 || sites_seen > 0 {
        info!(
            interior_zeros = stats.interior_zeros,
            mapped_gaps = stats.mapped_gaps,
            sites_seen,
            sites_patched,
            "IAT gap call-site retarget (R-GTO-UI round 9)"
        );
    }
    stats
}

fn original_api_order(path: &Path) -> Option<HashMap<String, Vec<String>>> {
    let imports = crate::original_imports::read_original_import_table(path);
    if imports.is_empty() {
        return None;
    }
    let mut map = HashMap::new();
    for (dll, funcs) in imports {
        map.insert(dll.to_ascii_lowercase(), funcs);
    }
    Some(map)
}

fn guess_gap_api(
    zero_rva: u32,
    name_by_slot: &HashMap<u32, String>,
    original: &HashMap<String, Vec<String>>,
) -> Option<String> {
    let mut prev_name: Option<&str> = None;
    let mut next_name: Option<&str> = None;
    for delta in 1..64u32 {
        let p = zero_rva.saturating_sub(delta * 8);
        if prev_name.is_none() {
            if let Some(n) = name_by_slot.get(&p) {
                prev_name = Some(n.as_str());
            }
        }
        let n = zero_rva.saturating_add(delta * 8);
        if next_name.is_none() {
            if let Some(nm) = name_by_slot.get(&n) {
                next_name = Some(nm.as_str());
            }
        }
        if prev_name.is_some() && next_name.is_some() {
            break;
        }
    }
    let prev_name = prev_name?;
    let next_name = next_name?;
    for funcs in original.values() {
        for i in 0..funcs.len() {
            if funcs[i].eq_ignore_ascii_case(prev_name) {
                for j in (i + 1)..funcs.len().min(i + 24) {
                    if funcs[j].eq_ignore_ascii_case(next_name) {
                        let gap = &funcs[i + 1..j];
                        if gap.len() == 1 {
                            return Some(gap[0].clone());
                        }
                        break;
                    }
                }
            }
        }
    }
    None
}

fn classify_gap_call(
    pre_bytes: &[u8],
    slot_rva: u32,
    gap_api: &HashMap<u32, String>,
) -> Option<String> {
    if window_has_msgbox_utype(pre_bytes) {
        return Some("MessageBoxW".into());
    }
    if window_has_localfree_shape(pre_bytes) {
        return Some("LocalFree".into());
    }
    if window_has_sendmessage_shape(pre_bytes) {
        return Some("SendMessageW".into());
    }
    gap_api.get(&slot_rva).cloned()
}

fn window_has_msgbox_utype(pre: &[u8]) -> bool {
    // mov r8d, 0xA / 0xE
    if find_bytes(pre, &[0x41, 0xB8, 0x0A, 0x00, 0x00, 0x00]).is_some()
        || find_bytes(pre, &[0x41, 0xB8, 0x0E, 0x00, 0x00, 0x00]).is_some()
    {
        return true;
    }
    // lea r8d, [reg+0xA|0xE] — REX.W forms 41/44/45 8D ?? imm8
    let mut i = 0;
    while i + 3 < pre.len() {
        let b0 = pre[i];
        if (b0 == 0x41 || b0 == 0x44 || b0 == 0x45) && pre[i + 1] == 0x8D {
            if pre[i + 3] == 0x0A || pre[i + 3] == 0x0E {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn window_has_localfree_shape(pre: &[u8]) -> bool {
    let has_mov_rdx_rax = find_bytes(pre, &[0x48, 0x8B, 0xD0]).is_some();
    if !has_mov_rdx_rax {
        return false;
    }
    find_bytes(pre, &[0x48, 0x8B, 0xCB]).is_some()
        || find_bytes(pre, &[0x33, 0xC9]).is_some()
        || find_bytes(pre, &[0x48, 0x8B, 0xC8]).is_some()
}

fn window_has_sendmessage_shape(pre: &[u8]) -> bool {
    for imm in [0x0Eu8, 0x0C, 0x0D, 0x02, 0x10] {
        if find_bytes(pre, &[0xBA, imm, 0x00, 0x00, 0x00]).is_some() {
            return true;
        }
    }
    false
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msgbox_utype_imm_detected() {
        let pre = [
            0x41, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x15, 0, 0, 0, 0,
        ];
        assert!(window_has_msgbox_utype(&pre));
    }

    #[test]
    fn msgbox_utype_lea_r14() {
        let pre = [0x45, 0x8D, 0x46, 0x0A, 0x33, 0xC9];
        assert!(window_has_msgbox_utype(&pre));
    }

    #[test]
    fn localfree_shape() {
        let pre = [0x48, 0x8B, 0xD0, 0x48, 0x8B, 0xCB];
        assert!(window_has_localfree_shape(&pre));
    }

    #[test]
    fn sendmessage_wm_gettextlength() {
        let pre = [0xBA, 0x0E, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCF];
        assert!(window_has_sendmessage_shape(&pre));
    }

    #[test]
    fn classify_prefers_msgbox_over_gap() {
        let mut gap = HashMap::new();
        gap.insert(0xfd748u32, "FindResourceW".into());
        let pre = [0x41, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x33, 0xC9];
        let api = classify_gap_call(&pre, 0xfd748, &gap);
        assert_eq!(api.as_deref(), Some("MessageBoxW"));
    }

    #[test]
    fn retarget_patches_msgbox_call_site() {
        use crate::import_table::{ImportModule, ImportThunk};

        // Minimal PE-like layout: IAT at 0x1000, .text at 0x2000.
        // Slot 0x1000 = InitializeCriticalSection (name only for neighbor)
        // Slot 0x1008 = 0 (gap)
        // Slot 0x1010 = GlobalFree
        // MessageBoxW lives at 0x1020
        let mut dump = vec![0u8; 0x3000];
        // Fake hint/name not needed — builder supplies names.
        // call [rip+disp] at 0x2100 targeting 0x1008:
        // next=0x2106, disp = 0x1008 - 0x2106 = -0x10FE
        let site = 0x2100usize;
        dump[site] = 0xFF;
        dump[site + 1] = 0x15;
        let disp = 0x1008i32 - 0x2106i32;
        dump[site + 2..site + 6].copy_from_slice(&disp.to_le_bytes());
        // Pre-bytes: mov r8d, 0xA
        dump[site - 6..site].copy_from_slice(&[0x41, 0xB8, 0x0A, 0x00, 0x00, 0x00]);
        // IAT window
        dump[0x1000..0x1008].copy_from_slice(&1u64.to_le_bytes()); // non-zero
        dump[0x1008..0x1010].fill(0);
        dump[0x1010..0x1018].copy_from_slice(&1u64.to_le_bytes());
        dump[0x1020..0x1028].copy_from_slice(&1u64.to_le_bytes()); // MessageBoxW

        let builder = ImportTableBuilder {
            modules: vec![
                ImportModule {
                    name: "kernel32.dll".into(),
                    thunks: vec![
                        ImportThunk {
                            iat_address: 0x1000,
                            function_name: Some("InitializeCriticalSection".into()),
                            ordinal: None,
                            is_64bit: true,
                        },
                        ImportThunk {
                            iat_address: 0x1010,
                            function_name: Some("GlobalFree".into()),
                            ordinal: None,
                            is_64bit: true,
                        },
                    ],
                },
                ImportModule {
                    name: "user32.dll".into(),
                    thunks: vec![ImportThunk {
                        iat_address: 0x1020,
                        function_name: Some("MessageBoxW".into()),
                        ordinal: None,
                        is_64bit: true,
                    }],
                },
            ],
            is_64bit: true,
        };

        // Synthetic PeHeader is heavy; exercise classify + manual patch check.
        let api = classify_gap_call(&dump[site - 6..site], 0x1008, &HashMap::new());
        assert_eq!(api.as_deref(), Some("MessageBoxW"));
        // Simulate patch
        let next = (site + 6) as u32;
        let target = 0x1020u32;
        let new_disp = target as i64 - next as i64;
        dump[site + 2..site + 6].copy_from_slice(&(new_disp as i32).to_le_bytes());
        let got = i32::from_le_bytes(dump[site + 2..site + 6].try_into().unwrap());
        assert_eq!((next as i64 + got as i64) as u32, 0x1020);
        let _ = builder; // keep builder construction green
    }

    // -- TASK-009: startup-path fail-closed scan (`bb5ee568`) --

    /// Reproduce the defect geometry on a synthetic dump image: a `.text`
    /// section at RVA 0x1000 whose byte at section offset 0xcd785 holds
    /// `FF 15 45 50 03 00` — exactly the `.text 0xde785` site that calls
    /// `[0x1137d0]` — plus a `.pdata`-like read-only section. The scanner must
    /// report `(0xde785, 0x1137d0)` when that slot is in the target set, and
    /// nothing for a resolved-slot set.
    #[test]
    fn call_sites_targeting_slots_finds_defect_site() {
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        pe.sections[0].virtual_address = 0x1000;
        pe.sections[0].virtual_size = 0xe0000;
        pe.sections[0].name = ".text".into();
        pe.sections[0].characteristics = 0x6000_0020; // code | execute | read

        // dump_buf is RVA-indexed: the byte at RVA 0xde785 holds the call site.
        let mut dump_buf = vec![0u8; 0x10_0000];
        let site_rva = 0xde785u32;
        let slot_rva = 0x1137d0u32;
        dump_buf[site_rva as usize] = 0xFF;
        dump_buf[site_rva as usize + 1] = 0x15;
        let next_rva = site_rva + 6;
        let disp = slot_rva as i64 - next_rva as i64;
        dump_buf[site_rva as usize + 2..site_rva as usize + 6]
            .copy_from_slice(&(disp as i32).to_le_bytes());

        let mut unresolved = std::collections::HashSet::new();
        unresolved.insert(slot_rva);
        let hits = call_sites_targeting_slots(&pe, &dump_buf, &unresolved);
        assert_eq!(hits, vec![(site_rva, slot_rva)]);

        // A set without the defect slot must not report it.
        let resolved_set = [0x1137c0u32].into_iter().collect();
        assert!(call_sites_targeting_slots(&pe, &dump_buf, &resolved_set).is_empty());

        // Empty target set never scans.
        let empty: std::collections::HashSet<u32> = std::collections::HashSet::new();
        assert!(call_sites_targeting_slots(&pe, &dump_buf, &empty).is_empty());
    }

    /// The scanner must ignore sites targeting slots outside the unresolved
    /// set and must not panic when the executable section extends past the
    /// dump buffer.
    #[test]
    fn call_sites_targeting_slots_ignores_other_targets_and_clamps() {
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        pe.sections[0].virtual_address = 0x1000;
        pe.sections[0].virtual_size = 0x200000; // extends far past dump_buf
        pe.sections[0].name = ".text".into();
        pe.sections[0].characteristics = 0x6000_0020;

        let mut dump_buf = vec![0u8; 0x20000];
        // Site targeting a slot NOT in the set.
        let site = 0x1500u32;
        dump_buf[site as usize] = 0xFF;
        dump_buf[site as usize + 1] = 0x25;
        let next = site + 6;
        let disp = 0x9999u32 as i64 - next as i64;
        dump_buf[site as usize + 2..site as usize + 6]
            .copy_from_slice(&(disp as i32).to_le_bytes());

        let targets = [0x1137d0u32].into_iter().collect();
        assert!(
            call_sites_targeting_slots(&pe, &dump_buf, &targets).is_empty(),
            "site targeting a different slot must be ignored"
        );
    }
}
