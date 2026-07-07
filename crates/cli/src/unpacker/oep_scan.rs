//! Live memory OEP scan — find the real OEP in decrypted `.text`.
//!
//! After IAT tracing completes, the Themida VM has decrypted `.text` in the
//! target process.  This module reads `.text` from live memory and searches
//! for MSVC CRT startup patterns to locate the real entry point.

use tracing::{debug, info, warn};
use mida_core::DebuggerCore;
use mida_pe::PeSection;
use mida_packers_themida::find_real_oep_in_bytes;
use super::session::ProcessSession;

/// Scan decrypted .text in live memory for the MSVC CRT startup address.
///
/// Returns `Some(real_oep)` if a better OEP is found, or `None` if the
/// current OEP should be kept.
pub(super) fn scan_live_memory_for_real_oep(
    dbg: &ProcessSession,
    image_base: usize,
    sections: &[PeSection],
    base_of_data: u64,
    major_linker_version: u8,
) -> Result<Option<usize>, anyhow::Error> {
    let Some(text_sec) = sections.iter().find(|sec| {
        sec.virtual_size > 0x1000 && (sec.characteristics & 0x20000000 != 0)
    }) else {
        return Ok(None);
    };
    let text_base_va = image_base + text_sec.virtual_address as usize;
    let text_len = if text_sec.virtual_address < base_of_data as u32 {
        (base_of_data as u32 - text_sec.virtual_address) as usize
    } else {
        text_sec.virtual_size as usize
    };
    if text_len < 64 {
        return Ok(None);
    }

    let read_size = text_len.min(0x100_000);
    let mut text_buf = vec![0u8; read_size];
    let bytes_read = dbg
        .read_memory(text_base_va, &mut text_buf)
        .map_err(|e| anyhow::anyhow!("read decrypted .text: {e}"))?;
    let effective_len = bytes_read.min(read_size);

    if effective_len < 64 {
        warn!("Short read on decrypted .text: got {bytes_read} bytes");
        return Ok(None);
    }

    // Strategy 1: MSVC CRT startup pattern (E8 .. E9)
    if [6u8, 7, 8, 9, 10, 11, 12, 14].contains(&major_linker_version)
        || major_linker_version == 0
    {
        if let Some(offset) = find_real_oep_in_bytes(&text_buf[..effective_len], 0) {
            let real_oep = text_base_va + offset as usize;
            info!(
                offset = format_args!("{offset:#x}"),
                real_oep = format_args!("{real_oep:#x}"),
                "MSVC CRT startup pattern (E8..E9, target=.text[0]) found in live memory"
            );
            return Ok(Some(real_oep));
        }

        for entry_offset_guess in [0u32, 0x100, 0x200, 0x400, 0x800] {
            if let Some(offset) = find_real_oep_in_bytes(&text_buf[..effective_len], entry_offset_guess) {
                let target_va_in_text = entry_offset_guess as usize;
                let real_oep = text_base_va + offset as usize;
                if offset as usize > target_va_in_text && offset < 0x10000 {
                    info!(
                        offset = format_args!("{offset:#x}"),
                        real_oep = format_args!("{real_oep:#x}"),
                        "MSVC CRT startup pattern (E8..E9, target=.text[0x{entry_offset_guess:x}]) found"
                    );
                    return Ok(Some(real_oep));
                }
            }
        }
    }

    // Strategy 1.5: MSVC x64 CRT startup — `48 83 EC xx` (sub rsp, imm8)
    let scan_end = 0x40000.min(effective_len).saturating_sub(4);
    for i in 0x100..scan_end {
        if text_buf[i] == 0x48
            && text_buf[i + 1] == 0x83
            && text_buf[i + 2] == 0xEC
            && text_buf[i + 3] <= 0x80
        {
            let real_oep = text_base_va + i;
            info!(
                real_oep = format_args!("{real_oep:#x}"),
                "x64 CRT startup (sub rsp, imm8) found in live memory"
            );
            return Ok(Some(real_oep));
        }
    }

    // Strategy 2: Old MSVC (version 2)
    if major_linker_version == 2 {
        let scan_end = 0x20000.min(effective_len).saturating_sub(10);
        for i in 0x100..scan_end {
            if text_buf[i] == 0x83 && text_buf[i + 1] == 0xEC {
                let mut func_start = i;
                for j in (i.saturating_sub(32)..i).rev() {
                    match text_buf[j] {
                        0x50..=0x57 => { func_start = j; break; }
                        0x6A => { func_start = j; break; }
                        0x68 => { func_start = j; break; }
                        0x8B => if text_buf[j + 1] == 0xEC { func_start = j; break; }
                        _ => continue,
                    }
                }
                let mut adjusted_start = func_start;
                for adj in 1..=10u32 {
                    if adj > func_start as u32 { break; }
                    let idx = func_start - adj as usize;
                    match text_buf[idx] {
                        0x50..=0x57 | 0x68 | 0x6A | 0xB9 | 0xB8 => {
                            adjusted_start = func_start - adj as usize;
                            break;
                        }
                        _ => {}
                    }
                }
                let real_oep = text_base_va.wrapping_add(adjusted_start);
                info!(
                    real_oep = format_args!("{real_oep:#x}"),
                    "Old MSVC OEP (sub esp, ..) found in live memory"
                );
                return Ok(Some(real_oep));
            }
        }
        for i in 0x100..scan_end {
            if text_buf[i] == 0x81 && text_buf[i + 1] == 0xEC {
                let mut func_start = i;
                for j in (i.saturating_sub(32)..i).rev() {
                    match text_buf[j] {
                        0x50..=0x57 => { func_start = j; break; }
                        0x6A => { func_start = j; break; }
                        0x68 => { func_start = j; break; }
                        _ => continue,
                    }
                }
                let real_oep = text_base_va + func_start;
                info!(
                    real_oep = format_args!("{real_oep:#x}"),
                    "Old MSVC OEP (sub esp, imm32) found in live memory"
                );
                return Ok(Some(real_oep));
            }
        }
    }

    // Strategy 3: Scan for function prologues past the VM entry point
    let prologue_start = 0x100.min(effective_len);
    let prologue_end = 0x10000.min(effective_len);
    let mut best_prologue: Option<usize> = None;
    for i in prologue_start..prologue_end {
        let is_prologue = match text_buf[i] {
            0x55 | 0x53 | 0x56 | 0x57 => true,
            0x8B => matches!(text_buf.get(i + 1), Some(&0xEC)),
            0x48 => matches!(text_buf.get(i + 1), Some(&0x83 | &0x89 | &0x8B)),
            0x41 => matches!(text_buf.get(i + 1), Some(&(0x54..=0x57))),
            _ => false,
        };
        if is_prologue && best_prologue.is_none() {
            best_prologue = Some(i);
        }
    }
    if let Some(offset) = best_prologue {
        let real_oep = text_base_va + offset;
        info!(
            real_oep = format_args!("{real_oep:#x}"),
            "Function prologue OEP in live memory"
        );
        return Ok(Some(real_oep));
    }

    // Fallback: scan for sub eax, imm32 (0x2D)
    let scan_end = effective_len.saturating_sub(4);
    for i in 256..scan_end {
        if text_buf[i] == 0x2D {
            let real_oep = text_base_va + i;
            info!(
                real_oep = format_args!("{real_oep:#x}"),
                "Fallback OEP (sub eax, imm32) found in live memory"
            );
            return Ok(Some(real_oep));
        }
    }

    debug!("Live memory OEP scan found no better OEP");
    Ok(None)
}
