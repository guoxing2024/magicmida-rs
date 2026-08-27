//! Patch `.text` call sites that reference unresolved (image-local) IAT slots
//!
//! Production `.unwrap()`s are parse invariants: the disp32 window is bounded
//! by the scan loop's `i + 6 <= end` guard (WO-10). Test unwraps are
//! assertions.
#![allow(clippy::unwrap_used)]
//! so they call the wrapper code directly instead of going through the IAT.
//!
//! Why: the PE loader walks FirstThunk ranges and interprets every non-zero
//! slot as a Hint/Name RVA (`LdrpSnapModule`). Leaving an image VA there
//! crashes the loader. Zeroing the slot is correct for the loader, but then
//! `call [slot]` becomes `call null`. Redirect those call sites to the
//! wrapper entry at its original RVA (materialized into `.wfix`).

use tracing::info;

use crate::header::PeHeader;

/// For each IAT slot that still holds an image-local absolute address
/// (Themida wrapper), zero the slot (so the loader treats it as a module
/// terminator / gap) and rewrite `call/jmp [rip+disp]` sites in executable
/// sections to a direct `call/jmp rel32` to the wrapper.
///
/// Returns `(slots_zeroed, sites_patched)`.
pub(crate) fn patch_wrapper_iat_call_sites(
    pe: &PeHeader,
    dump_buf: &mut [u8],
    original_iat_rva: u32,
    iat_size: usize,
    image_base: u64,
) -> (usize, usize) {
    if !pe.is_64bit || original_iat_rva == 0 || iat_size < 8 {
        return (0, 0);
    }

    let image_size = pe.size_of_image() as u64;
    let image_end = image_base.saturating_add(image_size);
    let iat_start = original_iat_rva as usize;
    let iat_end = iat_start.saturating_add(iat_size).min(dump_buf.len());
    if iat_end.saturating_sub(iat_start) < 8 {
        return (0, 0);
    }

    // slot_rva -> wrapper_rva
    let mut wrappers: Vec<(u32, u32)> = Vec::new();
    for off in (iat_start..iat_end).step_by(8) {
        let target = u64::from_le_bytes(dump_buf[off..off + 8].try_into().unwrap_or_default());
        if target < image_base + 0x1000 || target >= image_end {
            continue;
        }
        let slot_rva = off as u32; // dump is VA-indexed by RVA for image sections
                                   // Only consider slots inside the original IAT window.
        if slot_rva < original_iat_rva || (slot_rva as usize) >= iat_end {
            continue;
        }
        let wrapper_rva = (target - image_base) as u32;
        wrappers.push((slot_rva, wrapper_rva));
    }

    if wrappers.is_empty() {
        return (0, 0);
    }

    // Patch executable sections for call/jmp [rip+disp] targeting wrapper slots.
    let mut sites = 0usize;
    for section in pe.sections.iter().filter(|s| {
        s.characteristics & 0x2000_0000 != 0 // IMAGE_SCN_MEM_EXECUTE
            || s.name == ".text"
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
            // FF 15 disp32  => call qword ptr [rip+disp]
            // FF 25 disp32  => jmp  qword ptr [rip+disp]
            if dump_buf[i] == 0xFF && (dump_buf[i + 1] == 0x15 || dump_buf[i + 1] == 0x25) {
                let is_call = dump_buf[i + 1] == 0x15;
                let disp = i32::from_le_bytes(dump_buf[i + 2..i + 6].try_into().unwrap());
                let next = (i + 6) as u32;
                let slot_rva = next.wrapping_add(disp as u32);
                if let Some(&(_, wrapper_rva)) = wrappers.iter().find(|(s, _)| *s == slot_rva) {
                    // E8/E9 rel32 to wrapper. Rel = wrapper - (i+5). Need 6 bytes:
                    // E8 rel32; 90
                    let instr_rva = i as u32;
                    let rel = wrapper_rva as i64 - (instr_rva as i64 + 5);
                    if rel >= i32::MIN as i64 && rel <= i32::MAX as i64 {
                        dump_buf[i] = if is_call { 0xE8 } else { 0xE9 };
                        dump_buf[i + 1..i + 5].copy_from_slice(&(rel as i32).to_le_bytes());
                        dump_buf[i + 5] = 0x90; // nop
                        sites += 1;
                    }
                }
                i += 6;
                continue;
            }
            i += 1;
        }
    }

    // Zero the IAT slots so the PE loader does not try to snap them.
    let mut zeroed = 0usize;
    for (slot_rva, _) in &wrappers {
        let off = *slot_rva as usize;
        if off + 8 <= dump_buf.len() {
            dump_buf[off..off + 8].fill(0);
            zeroed += 1;
        }
    }

    info!(
        slots = zeroed,
        sites, "Redirected image-local IAT wrapper call sites; zeroed slots for loader"
    );
    (zeroed, sites)
}
