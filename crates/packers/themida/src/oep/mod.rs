//! Original Entry Point (OEP) detection and restoration for Themida targets.
//!
//! ## Overview
//!
//! Themida redirects the PE entry point to its own protection stub. After
//! unpacking, it transfers control to the OEP, but that transfer is not
//! always clean (virtualised, stolen, displaced, or reached via TLS callbacks).
//!
//! ## Modules
//!
//! - [`restore`] — stolen OEP byte restoration (MSVC6, MSVC9 DLL) and
//!   x64 MSVC OEP synthesis.

mod restore;

// Re-export the restoration functions from the `restore` submodule.
pub use restore::{
    restore_stolen_oep_msvc6, restore_stolen_oep_msvc9_dll, write_msvc_oep_x64,
};

use tracing::{debug, info, warn};

use mida_core::DebuggerCore;

use crate::error::ThemidaError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Major linker versions known to use the MSVC CRT startup pattern
/// (`call __security_init_cookie; jmp __scrt_common_main_seh`).
pub(crate) const KNOWN_MSVC_VERSIONS: [u8; 9] = [2, 6, 7, 8, 9, 10, 11, 12, 14];

// ---------------------------------------------------------------------------
// Virtualized OEP detection
// ---------------------------------------------------------------------------

/// Check if the OEP is virtualized (first instruction jumps into Themida section).
///
/// This is a runtime version that reads from the target process memory,
/// unlike the static version in `version.rs` that works with PE header bytes.
///
/// Returns `true` if the OEP is virtualized (jmp into Themida section).
pub fn is_oep_virtualized(
    debugger: &dyn DebuggerCore,
    oep: usize,
    themida_section_start: usize,
) -> bool {
    let mut code = [0u8; 5];
    if debugger.read_memory(oep, &mut code).unwrap_or(0) < 5 {
        return false;
    }

    if code[0] == 0xE9 {
        let displacement = i32::from_le_bytes([code[1], code[2], code[3], code[4]]) as i64;
        let target = (oep as i64) + 5 + displacement;

        if target >= themida_section_start as i64 {
            info!(
                oep = format_args!("{oep:#x}"),
                target = format_args!("{target:#x}"),
                "OEP is virtualized: jmp into Themida section"
            );
            return true;
        }
    }

    false
}

// ---------------------------------------------------------------------------
// OEP discovery by scanning
// ---------------------------------------------------------------------------

/// Find the real OEP for unknown compilers by scanning the .text section.
pub fn find_real_oep_by_scanning(
    debugger: &dyn DebuggerCore,
    image_base: usize,
    text_section_rva: u32,
    text_section_size: u32,
) -> Result<Option<usize>, ThemidaError> {
    let text_base = image_base + text_section_rva as usize;
    let size = text_section_size as usize;

    let read_size = size.min(0x100_000);
    let mut text_buf = vec![0u8; read_size];
    let bytes_read = debugger
        .read_memory(text_base, &mut text_buf)
        .map_err(|e| ThemidaError::Debugger(format!("read .text section: {e}")))?;

    let effective_len = bytes_read.min(read_size);

    // ---- MSVC-ification pattern: old MSVC uses E8..E9 at OEP ----
    let scan_end = effective_len.saturating_sub(16);
    for i in 0..scan_end {
        // Pattern: 81 EC xx xx xx xx 33 C9 (sub esp, imm32; xor ecx, ecx)
        if text_buf[i] == 0x81
            && text_buf.get(i + 1) == Some(&0xEC)
            && text_buf.get(i + 6) == Some(&0x33)
            && text_buf.get(i + 7) == Some(&0xC9)
        {
            let func_addr = text_base + i;
            if i > 0x100 {
                info!(
                    addr = format_args!("{func_addr:#x}"),
                    rva = format_args!("{:#x}", i),
                    "Found MSVC pattern (sub esp, imm32; xor ecx, ecx) — using as OEP"
                );
                return Ok(Some(func_addr));
            }
        }

        if text_buf[i] == 0x8B
            && text_buf.get(i + 1) == Some(&0xEC)
            && text_buf.get(i + 2) == Some(&0x83)
            && text_buf.get(i + 3) == Some(&0xEC)
        {
            let func_addr = text_base + i;
            if i > 0x100 {
                info!(
                    addr = format_args!("{func_addr:#x}"),
                    rva = format_args!("{:#x}", i),
                    "Found MSVC pattern (mov ebp, esp; sub esp, imm8) — using as OEP"
                );
                return Ok(Some(func_addr));
            }
        }
    }

    // ---- Common function prologue detection ----
    let scan_end = effective_len.saturating_sub(4);
    let mut first_function: Option<usize> = None;

    for i in 0..scan_end {
        let instr = text_buf[i];

        let is_prologue = match instr {
            0x55 => true,
            0x53 => true,
            0x56 => true,
            0x57 => true,
            0x48 => {
                matches!(text_buf.get(i + 1), Some(&0x8B | &0x83 | &0x81))
            }
            0x41 => {
                matches!(text_buf.get(i + 1), Some(&(0x54..=0x57)))
            }
            _ => false,
        };

        if is_prologue {
            let func_addr = text_base + i;
            if first_function.is_none() {
                first_function = Some(func_addr);
                info!(
                    addr = format_args!("{func_addr:#x}"),
                    rva = format_args!("{:#x}", i),
                    "Found first function prologue in .text"
                );
                break;
            }
        }
    }

    Ok(first_function)
}

// ---------------------------------------------------------------------------
// TLS callback result
// ---------------------------------------------------------------------------

/// Result returned by [`handle_tls_callbacks`] when a potential TLS callback
/// is detected at the guarded access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsCallbackResult {
    /// Whether the OEP was found (and TLS processing should stop).
    pub oep_found: bool,
    /// The resolved OEP address, if available.
    pub oep_address: Option<usize>,
    /// Number of TLS callbacks that have been executed so far.
    pub tls_callbacks_executed: u32,
}

// ---------------------------------------------------------------------------
// Public API — OEP discovery
// ---------------------------------------------------------------------------

/// Scan the `.text` section near the reported `oep` for the real entry point.
pub fn try_find_correct_oep(
    debugger: &dyn DebuggerCore,
    oep: usize,
    text_base: usize,
    text_len: usize,
    major_linker_version: u8,
) -> Result<Option<usize>, ThemidaError> {
    if !KNOWN_MSVC_VERSIONS.contains(&major_linker_version) {
        warn!(
            major_linker_version,
            "Don't know what to do about OEP for this compiler — target likely won't run"
        );
        return Ok(None);
    }

    if text_len < 10 {
        warn!("Text section too small for OEP scan ({text_len} bytes)");
        return Ok(None);
    }

    let mut text_buf = vec![0u8; text_len];
    let bytes_read = debugger
        .read_memory(text_base, &mut text_buf)
        .map_err(|e| ThemidaError::Debugger(format!("read text section for OEP scan: {e}")))?;

    if bytes_read < text_len {
        debug!(
            requested = text_len,
            actual = bytes_read,
            "Partial read of text section for OEP scan"
        );
    }

    let oep_rva = oep.wrapping_sub(text_base) as u32;

    match find_real_oep_in_bytes(&text_buf[..bytes_read.min(text_len)], oep_rva) {
        Some(real_oep_rva) => {
            let real_oep = text_base.wrapping_add(real_oep_rva as usize);
            info!("Found likely real OEP at {real_oep:#x} (was {oep:#x})");
            Ok(Some(real_oep))
        }
        None => {
            warn!("Real OEP not found near {oep:#x} — target likely won't run");
            Ok(None)
        }
    }
}

/// Pure helper: scan a `.text` buffer for the MSVC CRT startup pattern
/// `call rel32; jmp rel32` whose `call` target is `oep_rva`.
pub fn find_real_oep_in_bytes(text_buf: &[u8], oep_rva: u32) -> Option<u32> {
    let len = text_buf.len();
    if len < 10 {
        return None;
    }

    let scan_end = len.saturating_sub(10);
    for i in 0..=scan_end {
        if text_buf[i] == 0xE8 && text_buf[i + 5] == 0xE9 {
            let displacement = i32::from_le_bytes([
                text_buf[i + 1],
                text_buf[i + 2],
                text_buf[i + 3],
                text_buf[i + 4],
            ]) as i64;

            let call_target = (i as i64).wrapping_add(5).wrapping_add(displacement) as u32;

            if call_target == oep_rva {
                debug!(
                    real_oep_rva = format_args!("{i:#x}"),
                    oep_rva = format_args!("{oep_rva:#x}"),
                    "MSVC CRT startup pattern matched"
                );
                return Some(i as u32);
            }
        }
    }

    None
}

/// Attempt to find the correct OEP with a search range around the current OEP.
pub fn try_find_correct_oep_by_range(
    debugger: &dyn DebuggerCore,
    oep: usize,
    search_range: usize,
    text_base: usize,
    text_len: usize,
    major_linker_version: u8,
) -> Result<Option<usize>, ThemidaError> {
    if !KNOWN_MSVC_VERSIONS.contains(&major_linker_version) {
        warn!(
            major_linker_version,
            "Don't know what to do about OEP for this compiler — target likely won't run"
        );
        return Ok(None);
    }

    let scan_start = text_base.max(oep.saturating_sub(search_range));
    let scan_end = (text_base + text_len).min(oep.saturating_add(search_range));
    let scan_size = scan_end.saturating_sub(scan_start);

    if scan_size < 10 {
        warn!(oep = format_args!("{oep:#x}"), "OEP search window too small");
        return Ok(None);
    }

    let mut buf = vec![0u8; scan_size];
    let bytes_read = debugger
        .read_memory(scan_start, &mut buf)
        .map_err(|e| ThemidaError::Debugger(format!("read memory for OEP range scan: {e}")))?;

    let effective_len = bytes_read.min(scan_size);

    let end = effective_len.saturating_sub(10);
    for i in 0..end {
        if buf[i] == 0xE8 && buf[i + 5] == 0xE9 {
            let disp = {
                let mut d = [0u8; 4];
                d.copy_from_slice(&buf[i + 1..i + 5]);
                i32::from_le_bytes(d)
            };
            let call_target = (scan_start + i + 5).wrapping_add_signed(disp as isize);
            if call_target == oep {
                let real_oep = scan_start + i;
                info!("Found likely real OEP at {real_oep:#x} (was {oep:#x})");
                return Ok(Some(real_oep));
            }
        }
    }

    Ok(None)
}

// ---------------------------------------------------------------------------
// Public API — TLS callback handling
// ---------------------------------------------------------------------------

/// Handle TLS callback execution during guarded access.
pub fn handle_tls_callbacks(
    #[allow(unused)] debugger: &mut dyn DebuggerCore,
    exception_address: usize,
    execution_type: u32,
    tls_total: u32,
    tls_counter: &mut u32,
) -> Result<TlsCallbackResult, ThemidaError> {
    if tls_total == 0 || *tls_counter >= tls_total {
        return Ok(TlsCallbackResult {
            oep_found: false,
            oep_address: None,
            tls_callbacks_executed: *tls_counter,
        });
    }

    // On x64, execute access (type == 8) inside .text with remaining TLS callbacks.
    #[cfg(target_arch = "x86_64")]
    {
        if execution_type != 8 {
            return Ok(TlsCallbackResult {
                oep_found: false,
                oep_address: None,
                tls_callbacks_executed: *tls_counter,
            });
        }

        *tls_counter += 1;
        info!(
            "TLS callback skipped (x64): {}/{} at {exception_address:#x}",
            *tls_counter, tls_total
        );

        Ok(TlsCallbackResult {
            oep_found: false,
            oep_address: None,
            tls_callbacks_executed: *tls_counter,
        })
    }

    // On x86, check the thread context for TLS-callback signatures.
    #[cfg(target_arch = "x86")]
    {
        let ctx = debugger
            .get_thread_context(thread_id)
            .map_err(|e| ThemidaError::Debugger(format!("get_thread_context for TLS: {e}")))?;

        let sp = ctx.Esp as usize;
        let mut ret_addr_bytes: [u8; 4] = [0; 4];
        let read = debugger
            .read_memory(sp, &mut ret_addr_bytes)
            .map_err(|e| ThemidaError::Debugger(format!("read TLS return addr: {e}")))?;
        if read < 4 {
            trace!("TLS: short read of return address");
            return Ok(TlsCallbackResult {
                oep_found: true,
                oep_address: Some(exception_address),
                tls_callbacks_executed: *tls_counter,
            });
        }
        let ret_addr = u32::from_le_bytes(ret_addr_bytes) as usize;

        let mut args_bytes: [u8; 12] = [0; 12];
        let read = debugger
            .read_memory(sp + 4, &mut args_bytes)
            .map_err(|e| ThemidaError::Debugger(format!("read TLS args: {e}")))?;
        if read < 12 {
            trace!("TLS: short read of callback args");
            return Ok(TlsCallbackResult {
                oep_found: true,
                oep_address: Some(exception_address),
                tls_callbacks_executed: *tls_counter,
            });
        }

        let arg0 = args_bytes.get(0..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        let arg1 = args_bytes.get(4..8)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        let _arg2 = args_bytes.get(8..12)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);

        if (arg0 & 0xFFF) == 0 && arg1 <= 3 {
            *tls_counter += 1;
            info!(
                "TLS callback skipped: {}/{} at {exception_address:#x} (args: {arg0:#x}, {arg1})",
                *tls_counter, tls_total,
            );

            let mut ctx = debugger
                .get_thread_context(thread_id)
                .map_err(|e| ThemidaError::Debugger(format!("get_thread_context for TLS skip: {e}")))?;

            ctx.Eip = ret_addr as u32;
            ctx.Esp = (sp + 4 + 12) as u32;

            debugger
                .set_thread_context(thread_id, &ctx)
                .map_err(|e| ThemidaError::Debugger(format!("set_thread_context for TLS skip: {e}")))?;

            return Ok(TlsCallbackResult {
                oep_found: false,
                oep_address: None,
                tls_callbacks_executed: *tls_counter,
            });
        }

        debug!(
            "TLS: not a TLS callback (ret={ret_addr:#x}, args: {arg0:#x}, {arg1}) — assuming OEP"
        );
        Ok(TlsCallbackResult {
            oep_found: true,
            oep_address: Some(exception_address),
            tls_callbacks_executed: *tls_counter,
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msvc_text_with_pattern(pattern_offset: u32, oep_rva: u32) -> Vec<u8> {
        let len = (pattern_offset as usize) + 20;
        let mut buf = vec![0xCCu8; len];

        let call_disp = (oep_rva as i64) - (pattern_offset as i64) - 5;
        let call_disp: i32 = call_disp as i32;

        buf[pattern_offset as usize] = 0xE8;
        buf[pattern_offset as usize + 1..pattern_offset as usize + 5]
            .copy_from_slice(&call_disp.to_le_bytes());

        buf[pattern_offset as usize + 5] = 0xE9;
        let jmp_disp: i32 = 0x100;
        buf[pattern_offset as usize + 6..pattern_offset as usize + 10]
            .copy_from_slice(&jmp_disp.to_le_bytes());

        buf
    }

    #[test]
    fn test_known_msvc_versions() {
        assert!(KNOWN_MSVC_VERSIONS.contains(&2));
        assert!(KNOWN_MSVC_VERSIONS.contains(&6));
        assert!(KNOWN_MSVC_VERSIONS.contains(&7));
        assert!(KNOWN_MSVC_VERSIONS.contains(&8));
        assert!(KNOWN_MSVC_VERSIONS.contains(&9));
        assert!(KNOWN_MSVC_VERSIONS.contains(&14));
        assert!(!KNOWN_MSVC_VERSIONS.contains(&1));
        assert!(!KNOWN_MSVC_VERSIONS.contains(&5));
        assert!(!KNOWN_MSVC_VERSIONS.contains(&15));
    }

    #[test]
    fn find_real_oep_in_bytes_matches_at_offset_zero() {
        let buf = make_msvc_text_with_pattern(0, 0x1010);
        assert_eq!(find_real_oep_in_bytes(&buf, 0x1010), Some(0));
    }

    #[test]
    fn find_real_oep_in_bytes_matches_mid_buffer() {
        let buf = make_msvc_text_with_pattern(0x1000, 0x2010);
        assert_eq!(find_real_oep_in_bytes(&buf, 0x2010), Some(0x1000));
    }

    #[test]
    fn find_real_oep_in_bytes_no_match_when_oep_rva_differs() {
        let buf = make_msvc_text_with_pattern(0x100, 0x2000);
        assert_eq!(find_real_oep_in_bytes(&buf, 0x3000), None);
    }

    #[test]
    fn find_real_oep_in_bytes_skips_non_matching_e8() {
        let mut buf = vec![0xCCu8; 20];
        buf[0] = 0xE8;
        buf[1..5].copy_from_slice(&0x100_i32.to_le_bytes());
        buf[5] = 0x90;
        assert_eq!(find_real_oep_in_bytes(&buf, 0x105), None);
    }

    #[test]
    fn find_real_oep_in_bytes_small_buffer_returns_none() {
        let buf = vec![0xE8u8, 0x01, 0x02, 0x03, 0x04, 0xE9, 0x05];
        assert_eq!(find_real_oep_in_bytes(&buf, 0), None);
    }

    #[test]
    fn find_real_oep_in_bytes_empty_buffer_returns_none() {
        assert_eq!(find_real_oep_in_bytes(&[], 0), None);
    }

    #[test]
    fn find_real_oep_in_bytes_exact_ten_bytes() {
        let mut buf = vec![0xCCu8; 10];
        buf[0] = 0xE8;
        buf[1..5].copy_from_slice(&(-5_i32).to_le_bytes());
        buf[5] = 0xE9;
        buf[6..10].copy_from_slice(&0_i32.to_le_bytes());
        assert_eq!(find_real_oep_in_bytes(&buf, 0), Some(0));
    }

    #[test]
    fn find_real_oep_in_bytes_returns_first_match() {
        let len = 0x200 + 20;
        let mut buf = vec![0xCCu8; len];

        let call_disp_a: i32 = (0x500_i64 - 0x100 - 5) as i32;
        buf[0x100] = 0xE8;
        buf[0x101..0x105].copy_from_slice(&call_disp_a.to_le_bytes());
        buf[0x105] = 0xE9;
        buf[0x106..0x10A].copy_from_slice(&0x100_i32.to_le_bytes());

        let call_disp_b: i32 = (0x500_i64 - 0x200 - 5) as i32;
        buf[0x200] = 0xE8;
        buf[0x201..0x205].copy_from_slice(&call_disp_b.to_le_bytes());
        buf[0x205] = 0xE9;
        buf[0x206..0x20A].copy_from_slice(&0x200_i32.to_le_bytes());

        assert_eq!(find_real_oep_in_bytes(&buf, 0x500), Some(0x100));
    }

    #[test]
    fn test_tls_callback_result_defaults() {
        let result = TlsCallbackResult {
            oep_found: false,
            oep_address: None,
            tls_callbacks_executed: 0,
        };
        assert!(!result.oep_found);
        assert!(result.oep_address.is_none());
        assert_eq!(result.tls_callbacks_executed, 0);
    }

    #[test]
    fn test_tls_callback_result_oep_found() {
        let result = TlsCallbackResult {
            oep_found: true,
            oep_address: Some(0x401000),
            tls_callbacks_executed: 2,
        };
        assert!(result.oep_found);
        assert_eq!(result.oep_address, Some(0x401000));
        assert_eq!(result.tls_callbacks_executed, 2);
    }
}
