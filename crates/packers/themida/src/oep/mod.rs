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

mod msvc_crt;
mod restore;

// Re-export the restoration functions from the `restore` submodule.
pub use msvc_crt::{
    cookie_complement_from_security_init_xrefs, decode_msvc_oep_wrapper, encode_msvc_oep_wrapper,
    find_cookie_complement_site, ftrace_common_main_hint, ftrace_enter_preserve_common_main,
    is_scrt_common_main_seh_bytes, is_tls_or_dynamic_init_helper_bytes,
    reject_if_tls_helper_as_common_main, require_full_section_read,
    resolve_cookie_site_via_security_init_xrefs, resolve_msvc_crt_targets,
    resolve_msvc_crt_targets_from_process, resolve_msvc_crt_targets_with_sections,
    resolve_security_init_cookie, rva_range_in_section, select_cookie_storage_section,
    validate_scrt_common_main_seh, validate_wrapper_targets,
    window_contains_security_cookie_sentinel, write_msvc_oep_x64_validated, CookieComplementSite,
    ExecRange, MsvcCrtResolveError, MsvcCrtTargets, PeSectionView, DEFAULT_SECURITY_COOKIE,
    MSVC_OEP_WRAPPER_LEN,
};
pub use restore::{restore_stolen_oep_msvc6, restore_stolen_oep_msvc9_dll, write_msvc_oep_x64};

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
    Ok(find_real_oep_by_scanning_with_backtrack(
        debugger,
        image_base,
        text_section_rva,
        text_section_size,
    )?
    .map(|o| o.final_oep))
}

/// Scan result carrying the OEP backtracking decision (XX-11-B / #17).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OepScanOutcome {
    /// Final OEP after any prologue backtracking (what the PE EP will be set to).
    pub final_oep: usize,
    /// The raw scan hit before backtracking.
    pub scan_hit: usize,
    /// Backtracking decision (already_start / backtracked / uncertain).
    pub backtrack: BacktrackDecision,
}

/// Like [`find_real_oep_by_scanning`] but also reports the backtracking
/// decision so the caller can record `scan_hit_rva` / `final_oep_rva` and
/// `oep_backtrack` in the sidecar (XX-11-B / #17).
pub fn find_real_oep_by_scanning_with_backtrack(
    debugger: &dyn DebuggerCore,
    image_base: usize,
    text_section_rva: u32,
    text_section_size: u32,
) -> Result<Option<OepScanOutcome>, ThemidaError> {
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
            // In PE32+ `81 EC` alone decodes as `sub esp, imm32`, which
            // zero-extends RSP.  It is the tail of an x64 `48 81 EC`
            // instruction, never a valid function boundary.  Recover the
            // containing MSVC function prologue instead of entering at the
            // second byte and corrupting the stack.
            let start = if i >= 7
                && text_buf.get(i - 7..i) == Some(&[0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48])
            {
                i - 7
            } else if i >= 2
                && text_buf.get(i - 2) == Some(&0x57)
                && text_buf.get(i - 1) == Some(&0x48)
            {
                i - 2
            } else {
                continue;
            };
            let func_addr = text_base + start;
            if i > 0x100 {
                info!(
                    addr = format_args!("{func_addr:#x}"),
                    rva = format_args!("{:#x}", start),
                    "Found x64 MSVC function containing sub rsp, imm32"
                );
                return Ok(Some(OepScanOutcome {
                    final_oep: func_addr,
                    scan_hit: i,
                    backtrack: BacktrackDecision::Backtracked {
                        scan_hit: i,
                        reason: "MSVC 81 EC pattern recovered to prologue",
                    },
                }));
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
                return Ok(Some(OepScanOutcome {
                    final_oep: func_addr,
                    scan_hit: i,
                    backtrack: BacktrackDecision::AlreadyStart,
                }));
            }
        }
    }

    // ---- Common function prologue detection ----
    let scan_end = effective_len.saturating_sub(4);

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
            // XX-11-B (#17): backtrack from the scan hit to the start of the
                // containing function prologue.  A scan hit may land inside a
                // prologue (e.g. at `48 83 EC 58` inside a `push...; sub rsp`
                // sequence) — writing that as EP skips the pushes/sub and leaves
                // the process with an 8-byte misaligned stack for its whole life
                // (XX-10: wininet cold-start SSE `movdqa` AV).  Backtrack only
                // when the boundary is provable; otherwise keep the hit + WARN.
                let (final_start, backtrack) = backtrack_to_function_start(
                    &text_buf[..effective_len],
                    i,
                );
                let func_addr = text_base + final_start;
                match backtrack {
                    BacktrackDecision::Backtracked { scan_hit, reason } => {
                        warn!(
                            scan_hit = format_args!("{scan_hit:#x}"),
                            final_oep = format_args!("{func_addr:#x}"),
                            reason,
                            "OEP scan hit was inside a function prologue; backtracked to function start"
                        );
                    }
                    BacktrackDecision::AlreadyStart => {
                        info!(
                            addr = format_args!("{func_addr:#x}"),
                            rva = format_args!("{:#x}", final_start),
                            "Found first function prologue in .text (already at function start)"
                        );
                    }
                    BacktrackDecision::Uncertain { scan_hit } => {
                        warn!(
                            scan_hit = format_args!("{scan_hit:#x}"),
                            final_oep = format_args!("{func_addr:#x}"),
                            "OEP scan hit near prologue but boundary unprovable; keeping hit (no guess)"
                        );
                    }
                }
                // Record the raw scan hit (offset before backtracking) for the
                // sidecar `scan_hit_rva` / `oep_backtrack` fields.
                return Ok(Some(OepScanOutcome {
                    final_oep: func_addr,
                    scan_hit: i,
                    backtrack,
                }));
        }
    }

    Ok(None)
}

/// Decision produced by [`backtrack_to_function_start`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacktrackDecision {
    /// Scan hit was already the first non-prologue instruction after a
    /// provable function prologue; no adjustment needed.
    AlreadyStart,
    /// Scan hit was inside a provable prologue; backtracked to the prologue's
    /// first byte (the real function entry point).
    Backtracked { scan_hit: usize, reason: &'static str },
    /// No provable boundary; the scan hit is kept unchanged (conservative,
    /// never guess).  Caller should record `oep_backtrack=uncertain`.
    Uncertain { scan_hit: usize },
}

/// Backtrack from a scan hit offset to the start of the containing function
/// prologue, when provable.
///
/// Recognises the MSVC/x64 pattern:
///   `41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC 58`  (push r15..rbx; sub rsp, imm8)
/// i.e. a run of `push` (0x53/55/56/57, or 0x41-prefixed 0x54..=0x57) followed by
/// `48 83 EC imm8` / `48 81 EC imm32`.  The function entry is the first byte of
/// that run.  Boundary proof: byte before the run is `ret`/`int3`/`nop`/0xCC
/// padding, or the hit is at section offset 0.
///
/// Conservative: if the boundary cannot be proven, return the original hit with
/// [`BacktrackDecision::Uncertain`] — never guess.
pub fn backtrack_to_function_start(
    text_buf: &[u8],
    scan_hit: usize,
) -> (usize, BacktrackDecision) {
    const MAX_BACKTRACK: usize = 32;

    // If the scan hit itself is the start of a `sub rsp, imm` (`48 83 EC` /
    // `48 81 EC`), extend the window to include that sub so it can anchor the
    // push-run detection (XX-11-B: hit landed on 0x101c = `48 83 EC 58`).
    let sub_len_at_hit = if scan_hit + 3 < text_buf.len()
        && text_buf[scan_hit] == 0x48
        && matches!(text_buf[scan_hit + 1], 0x83 | 0x81)
        && text_buf[scan_hit + 2] == 0xEC
    {
        if text_buf[scan_hit + 1] == 0x83 {
            4
        } else {
            7
        }
    } else {
        0
    };
    let window_end = scan_hit.saturating_add(sub_len_at_hit).min(text_buf.len());

    // Walk back at most MAX_BACKTRACK bytes looking for a push-sequence prologue.
    let back_start = scan_hit.saturating_sub(MAX_BACKTRACK);
    let window = &text_buf[back_start..window_end];

    // Find the rightmost `sub rsp, imm` (`48 83 EC xx` or `48 81 EC xx xx xx xx`)
    // in the window, then verify the bytes before it are a pure push run.
    let mut best: Option<(usize, bool)> = None; // (push_run_start_abs, sub_imm32)
    let mut w = 0usize;
    while w + 3 < window.len() {
        // `48 83 EC imm8`
        if window[w] == 0x48
            && window.get(w + 1) == Some(&0x83)
            && window.get(w + 2) == Some(&0xEC)
        {
            let sub_end = w + 4;
            if sub_end <= window.len() {
                // Walk back from the `48` over a pure push run.
                if let Some(push_start_rel) = push_run_start(&window[..w]) {
                    best = Some((back_start + push_start_rel, false));
                }
            }
            w += 1;
        }
        // `48 81 EC imm32`
        else if window[w] == 0x48
            && window.get(w + 1) == Some(&0x81)
            && window.get(w + 2) == Some(&0xEC)
        {
            let sub_end = w + 7;
            if sub_end <= window.len() {
                if let Some(push_start_rel) = push_run_start(&window[..w]) {
                    best = Some((back_start + push_start_rel, true));
                }
            }
            w += 1;
        } else {
            w += 1;
        }
    }

    if let Some((push_start_abs, _is_imm32)) = best {
        // Boundary proof: the byte before the push run must be a terminator.
        let boundary_ok = if push_start_abs == 0 {
            true // section start is a valid function boundary
        } else {
            matches!(
                text_buf.get(push_start_abs - 1),
                Some(&0xC3 | &0xCC | &0x90 | &0x0F) // ret / int3 / nop / nop-prefix
            )
        };
        if boundary_ok {
            return (
                push_start_abs,
                BacktrackDecision::Backtracked {
                    scan_hit,
                    reason: "scan hit inside push/sub prologue",
                },
            );
        }
    }

    // No provable prologue before the hit: is the hit itself the first
    // instruction of a function (byte before it is a terminator)?
    let hit_is_start = if scan_hit == 0 {
        true
    } else {
        matches!(
            text_buf.get(scan_hit - 1),
            Some(&0xC3 | &0xCC | &0x90 | &0x0F)
        )
    };
    if hit_is_start {
        (scan_hit, BacktrackDecision::AlreadyStart)
    } else {
        (scan_hit, BacktrackDecision::Uncertain { scan_hit })
    }
}

/// Given bytes `[0..end)` that end immediately before a `48 83 EC`/`48 81 EC`
/// sub, find the start of a pure run of push instructions that ends exactly at
/// `end`.  Returns the absolute offset of the first push byte if the run is
/// pure and immediately precedes the sub, else `None`.
///
/// Scans forward from the first non-padding byte; the run must be contiguous
/// push encodings (`push rbx/rbp/rsi/rdi`, or `41 54..57` push r12..r15) and
/// its end must coincide with `bytes.len()` (the sub it belongs to).
fn push_run_start(bytes: &[u8]) -> Option<usize> {
    // Skip leading padding (ret/int3/nop) that terminates the previous function.
    let mut i = 0usize;
    while i < bytes.len() && matches!(bytes[i], 0xC3 | 0xCC | 0x90) {
        i += 1;
    }
    let first = i;
    let mut push_count = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == 0x41 && i + 1 < bytes.len() && matches!(bytes[i + 1], 0x54..=0x57) {
            push_count += 1;
            i += 2;
        } else if matches!(b, 0x53 | 0x55 | 0x56 | 0x57) {
            push_count += 1;
            i += 1;
        } else {
            break;
        }
    }
    // The push run must end exactly where the sub begins (contiguous), and be
    // non-empty.  Any non-push byte before the sub terminates the run without
    // a match (conservative: don't guess across a gap).
    if push_count > 0 && i == bytes.len() {
        Some(first)
    } else {
        None
    }
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
        warn!(
            oep = format_args!("{oep:#x}"),
            "OEP search window too small"
        );
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

        let arg0 = args_bytes
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        let arg1 = args_bytes
            .get(4..8)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);
        let _arg2 = args_bytes
            .get(8..12)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0);

        if (arg0 & 0xFFF) == 0 && arg1 <= 3 {
            *tls_counter += 1;
            info!(
                "TLS callback skipped: {}/{} at {exception_address:#x} (args: {arg0:#x}, {arg1})",
                *tls_counter, tls_total,
            );

            let mut ctx = debugger.get_thread_context(thread_id).map_err(|e| {
                ThemidaError::Debugger(format!("get_thread_context for TLS skip: {e}"))
            })?;

            ctx.Eip = ret_addr as u32;
            ctx.Esp = (sp + 4 + 12) as u32;

            debugger.set_thread_context(thread_id, &ctx).map_err(|e| {
                ThemidaError::Debugger(format!("set_thread_context for TLS skip: {e}"))
            })?;

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

    // -------------------------------------------------------------------
    // XX-11-B (#17): OEP prologue backtracking
    // -------------------------------------------------------------------

    /// XX-10 scene vector: `0x1010` prologue (`41 57 ... 48 83 EC 58`),
    /// scan hit at `0x1020` (inside the CRT code after the prologue).
    fn xx10_scene_text() -> Vec<u8> {
        // 0x1000: padding terminator bytes (nop/ret)
        let mut buf = vec![0x90u8; 0x1100];
        // 0x1000: explicit `ret` as the terminator before the function
        buf[0x1000] = 0xC3;
        // 0x1010..0x101e: 8-push + sub rsp,0x58 prologue
        let prologue = [
            0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x57, 0x56, 0x53, 0x48, 0x83,
            0xEC, 0x58,
        ];
        buf[0x1010..0x1020].copy_from_slice(&prologue);
        // 0x1020: CRT body `mov eax,0x30; mov rax,gs:[eax]`
        buf[0x1020..0x1025].copy_from_slice(&[0xB8, 0x30, 0x00, 0x00, 0x00]);
        buf[0x1025..0x1027].copy_from_slice(&[0x65, 0x48]);
        buf[0x1027..0x102b].copy_from_slice(&[0x8B, 0x04, 0x25, 0x30]);
        buf
    }

    #[test]
    fn xx11b_backtrack_from_hit_inside_prologue() {
        // Scan hit at 0x1020 (first byte after the prologue): backtrack to 0x1010.
        let buf = xx10_scene_text();
        let (start, decision) = backtrack_to_function_start(&buf, 0x1020);
        assert_eq!(start, 0x1010);
        assert!(matches!(
            decision,
            BacktrackDecision::Backtracked { scan_hit: 0x1020, .. }
        ));
    }

    #[test]
    fn xx11b_backtrack_when_hit_is_sub_itself() {
        // Scan hit lands on the `48 83 EC 58` (0x101c): still backtrack to 0x1010.
        let buf = xx10_scene_text();
        let (start, decision) = backtrack_to_function_start(&buf, 0x101c);
        assert_eq!(start, 0x1010);
        assert!(matches!(decision, BacktrackDecision::Backtracked { .. }));
    }

    #[test]
    fn xx11b_already_at_function_start() {
        // Hit is already the prologue start (0x1010): no adjustment.
        let buf = xx10_scene_text();
        let (start, decision) = backtrack_to_function_start(&buf, 0x1010);
        assert_eq!(start, 0x1010);
        assert_eq!(decision, BacktrackDecision::AlreadyStart);
    }

    #[test]
    fn xx11b_conservative_when_boundary_unprovable() {
        // Hit at 0x1020 but with NO terminator before the push run (garbage
        // bytes between the run and the section start): must not guess.
        let mut buf = xx10_scene_text();
        // Remove the `ret` terminator at 0x1000, replace with junk that is not
        // a push/sub prologue so the push run's left boundary is unprovable.
        buf[0x1000] = 0xE8; // call — not a terminator, and 0xE8 starts a call
        buf[0x1001] = 0x00;
        buf[0x1002] = 0x00;
        buf[0x1003] = 0x00;
        buf[0x1004] = 0x00;
        let (start, decision) = backtrack_to_function_start(&buf, 0x1020);
        // 0x1000..0x1005 is `E8 00 00 00 00` (call rel32), then 0x1005..
        // are the original nops; the push run 0x1010 has no provable left
        // boundary => Uncertain keeps the original hit.
        assert_eq!(start, 0x1020);
        assert!(matches!(
            decision,
            BacktrackDecision::Uncertain { scan_hit: 0x1020 }
        ));
    }

    #[test]
    fn xx11b_rev1_golden_path_unchanged() {
        // rev1 golden path: hit is a plain `sub rsp,0x28` prologue start (the
        // classic MSVC mainCRTStartup). Backtracking must NOT move it.
        // 0x2000: ret terminator; 0x2001: `sub rsp,0x28` (48 83 EC 28); then code.
        let mut buf = vec![0x90u8; 0x2040];
        buf[0x2000] = 0xC3;
        buf[0x2001..0x2005].copy_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
        buf[0x2005..0x2009].copy_from_slice(&[0xB8, 0x30, 0x00, 0x00]);
        buf[0x2009] = 0x00;
        // Hit at 0x2005 (first non-prologue instruction): no push run before
        // the sub, so no backtrack; hit is at a valid boundary after sub.
        let (start, decision) = backtrack_to_function_start(&buf, 0x2005);
        assert_eq!(start, 0x2005);
        assert!(matches!(
            decision,
            BacktrackDecision::AlreadyStart | BacktrackDecision::Uncertain { .. }
        ));
        // And the prologue start 0x2001 itself must remain reachable as-is.
        let (start2, decision2) = backtrack_to_function_start(&buf, 0x2001);
        assert_eq!(start2, 0x2001);
        assert!(matches!(
            decision2,
            BacktrackDecision::AlreadyStart | BacktrackDecision::Uncertain { .. }
        ));
    }
}
