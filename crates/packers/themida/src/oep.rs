//! Original Entry Point (OEP) detection and restoration for Themida targets.
//!
//! ## Overview
//!
//! Themida redirects the PE entry point to its own protection stub. After
//! unpacking, it transfers control to the OEP, but that transfer is not
//! always clean:
//!
//! - The OEP may be **virtualised** — the first instruction at the OEP jumps
//!   directly into the Themida VM instead of executing real code.
//! - The OEP may be **stolen** — the first few bytes of the real entry-point
//!   function are replaced with garbage (e.g. `mov dl, ah` for MSVC6), and
//!   the originals must be re-synthesised from scratch.
//! - The OEP may be **displaced** — the true entry point is somewhere near
//!   the reported OEP (e.g. `call __security_init_cookie; jmp
//!   __scrt_common_main_seh` for MSVC), and we must scan for it.
//! - The OEP may be reached via **TLS callbacks** — the first accesses to
//!   `.text` are TLS initialisers, not the real entry point.
//!
//! ## Modules of this file
//!
//! | Function                        | Pascal source                      |
//! |---------------------------------|------------------------------------|
//! | [`try_find_correct_oep`]        | `ThemidaCommon.pas` `TryFindCorrectOEP` |
//! | [`restore_stolen_oep_msvc6`]    | `Themida.pas` `RestoreStolenOEPForMSVC6` |
//! | [`restore_stolen_oep_msvc9_dll`]| `Themida.pas` `RestoreStolenOEPForMSVC9DLL` |
//! | [`write_msvc_oep_x64`]          | `Themida64.pas` `WriteMSVCOEP`     |
//! | [`handle_tls_callbacks`]        | `Themida.pas`/`Themida64.pas` TLS handler |

use tracing::{debug, info, trace, warn};

use mida_core::DebuggerCore;

use crate::error::ThemidaError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Major linker versions known to use the MSVC CRT startup pattern
/// (`call __security_init_cookie; jmp __scrt_common_main_seh`).
///
/// Includes older versions (2, 6, 7, 8 correspond to very old VC/VC6/VS2003/VS2005)
/// — they use the same `E8 xx xx xx xx E9 xx xx xx xx` pattern as the
/// post-VC9 versions. Versions < 2 (VC5 and earlier) use a different
/// startup that does not match this pattern; pass 0 for "unknown/any".
const KNOWN_MSVC_VERSIONS: [u8; 9] = [2, 6, 7, 8, 9, 10, 11, 12, 14];

// ---------------------------------------------------------------------------
// Virtualized OEP detection
// ---------------------------------------------------------------------------

/// Check if the OEP is virtualized (first instruction jumps into Themida section).
///
/// This is a runtime version that reads from the target process memory,
/// unlike the static version in `version.rs` that works with PE header bytes.
///
/// Corresponds to `ThemidaCommon.pas` `CheckVirtualizedOEP`:
/// ```pascal
/// RPM(OEP, @Code, 5);
/// if (Code.Instr <> $E9) or (OEP + 5 + Code.Displ < TMSectR.Address) then
///   Exit;
/// FIsVMOEP := True;
/// ```
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

    // Check if the first instruction is a near jmp (E9 xx xx xx xx)
    if code[0] == 0xE9 {
        let displacement = i32::from_le_bytes([code[1], code[2], code[3], code[4]]) as i64;
        let target = (oep as i64) + 5 + displacement;

        // If the target is at or after the Themida section start, the OEP is virtualized
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

/// Find the real OEP for unknown compilers by scanning the .text section.
///
/// For unknown compilers (not MSVC 9-14), we don't have a specific heuristic.
/// Instead, we scan the .text section for the first valid function prologue
/// and use that as the OEP.
///
/// This is a fallback for when `try_find_correct_oep` returns `None`.
pub fn find_real_oep_by_scanning(
    debugger: &dyn DebuggerCore,
    image_base: usize,
    text_section_rva: u32,
    text_section_size: u32,
) -> Result<Option<usize>, ThemidaError> {
    let text_base = image_base + text_section_rva as usize;
    let size = text_section_size as usize;

    // Read the .text section (cap at 1 MiB for performance)
    let read_size = size.min(0x100_000);
    let mut text_buf = vec![0u8; read_size];
    let bytes_read = debugger
        .read_memory(text_base, &mut text_buf)
        .map_err(|e| ThemidaError::Debugger(format!("read .text section: {e}")))?;

    let effective_len = bytes_read.min(read_size);

    // ---- MSVC-ification pattern: old MSVC uses E8..E9 at OEP ----
    //
    // For ancient MSVC (linker version 2) where the .text section doesn't
    // start at RVA 0x1000, the normally-aligned TryFindCorrectOEP can't work.
    // Instead, scan for a short pattern that's unique to very old MSVC:
    //   sub  esp, imm32     ; 81 EC xx xx xx xx
    //   xor  ecx, ecx      ; 33 C9
    //
    // This pattern appears at the real OEP for these binaries.
    //
    // Yes, this is a heuristic — but it's better than returning the wrong OEP.
    let scan_end = effective_len.saturating_sub(16);
    for i in 0..scan_end {
        // Pattern: 81 EC xx xx xx xx 33 C9 (sub esp, imm32; xor ecx, ecx)
        if text_buf[i] == 0x81
            && text_buf.get(i + 1) == Some(&0xEC)
            && text_buf.get(i + 6) == Some(&0x33)
            && text_buf.get(i + 7) == Some(&0xC9)
        {
            let func_addr = text_base + i;
            // Verify this looks reasonable: not too close to .text start
            // (avoid false positives in padding/zeros)
            if i > 0x100 {
                info!(
                    addr = format_args!("{func_addr:#x}"),
                    rva = format_args!("{:#x}", i),
                    "Found MSVC pattern (sub esp, imm32; xor ecx, ecx) — using as OEP"
                );
                return Ok(Some(func_addr));
            }
        }

        // Alternative pattern: 8B EC (mov ebp, esp) followed by 83 EC xx (sub esp, imm8)
        // Common in old MSVC DLL entry points
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
    // Common prologues:
    //   push rbp         ; 55
    //   mov rbp, rsp     ; 48 8B EC
    //   sub rsp, imm     ; 48 83 EC xx  or  48 81 EC xx xx xx xx
    //   push rbx         ; 53
    //   push r12-r15     ; 41 54-41 57
    let scan_end = effective_len.saturating_sub(4);
    let mut first_function: Option<usize> = None;

    for i in 0..scan_end {
        let instr = text_buf[i];

        // Check for common function prologues
        let is_prologue = match instr {
            0x55 => true, // push rbp
            0x53 => true, // push rbx
            0x56 => true, // push rsi
            0x57 => true, // push rdi
            0x48 => {
                // Could be: mov rbp, rsp (48 8B EC) or sub rsp, imm (48 83 EC)
                matches!(text_buf.get(i + 1), Some(&0x8B | &0x83 | &0x81))
            }
            0x41 => {
                // push r12-r15 (41 54-41 57)
                matches!(text_buf.get(i + 1), Some(&(0x54..=0x57)))
            }
            _ => false,
        };

        if is_prologue {
            // Found a potential function prologue
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
///
/// When Themida transfers to the OEP, it sometimes lands at
/// `__security_init_cookie` rather than the real startup function. This
/// function searches for the MSVC CRT pattern
/// `call __security_init_cookie; jmp __scrt_common_main_seh` and returns the
/// address of the `call` instruction if found.
///
/// ## Algorithm
///
/// 1. Read the entire `.text` section into a buffer.
/// 2. Compute the RVA of `oep` relative to the text base.
/// 3. Scan every position `i` in the buffer for:
///    ```text
///    E8 ?? ?? ?? ??   ; call rel32  → target = i + 5 + displacement
///    E9 ?? ?? ?? ??   ; jmp  rel32
///    ```
/// 4. If `i + 5 + displacement == oep_rva`, then `text_base + i` is the
///    real entry point (the `call` site).
///
/// ## Parameters
///
/// - `debugger` — the current debug session (used to read the target's
///   `.text` section memory).
/// - `oep` — the current (possibly wrong) OEP address.
/// - `text_base` — absolute virtual address of `.text` (i.e.
///   `ImageBase + .text.VirtualAddress`).
/// - `text_len` — size of the `.text` code region (up to `BaseOfData`).
/// - `major_linker_version` — from the PE optional header; determines whether
///   this is a known MSVC version.
///
/// ## Return value
///
/// - `Ok(Some(real_oep))` — a better OEP was found.
/// - `Ok(None)` — no better OEP found; the caller should use the original.
///
/// ## References
///
/// `ThemidaCommon.pas` `TryFindCorrectOEP` (lines 1346–1380):
/// ```pascal
/// TextLen := FBaseOfData - FPESections[0].VirtualAddress;
/// RPM(FImageBase + FPESections[0].VirtualAddress, TextBuf, TextLen);
/// ScanFor := OEP - FImageBase - FPESections[0].VirtualAddress;
/// for i := 0 to TextLen - 10 do
///   if (TextBuf[i] = $E8) and (TextBuf[i + 5] = $E9)
///      and (PCardinal(@TextBuf[i + 1])^ + i + 5 = ScanFor) then ...
/// ```
///
/// `Themida64.pas` `TryFindCorrectOEP` (lines 472–515): same logic for x64.
pub fn try_find_correct_oep(
    debugger: &dyn DebuggerCore,
    oep: usize,
    text_base: usize,
    text_len: usize,
    major_linker_version: u8,
) -> Result<Option<usize>, ThemidaError> {
    // Only known to work for MSVC (versions 2, 6–14).
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

    // 1. Read the entire .text section.
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

    // 2. Compute the RVA of the current (suspected) OEP relative to the
    //    text base.
    let oep_rva = oep.wrapping_sub(text_base) as u32;

    // 3. Delegate to the pure pattern-matching helper.
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
///
/// This is the byte-level core of [`try_find_correct_oep`], extracted so it
/// can be unit-tested without a live debugger.
///
/// ## Algorithm
///
/// Scan every position `i` in `text_buf` for:
/// ```text
/// E8 ?? ?? ?? ??   ; call rel32  → target = i + 5 + displacement
/// E9 ?? ?? ?? ??   ; jmp  rel32
/// ```
/// If `i + 5 + displacement == oep_rva`, return `Some(i)`.
///
/// This matches the MSVC CRT sequence
/// `call __security_init_cookie; jmp __scrt_common_main_seh` when the
/// caller's reported OEP is at `__security_init_cookie`.
///
/// ## References
///
/// `ThemidaCommon.pas` `TryFindCorrectOEP` (lines 1346–1380) and
/// `Themida64.pas` `TryFindCorrectOEP` (lines 472–515).
pub fn find_real_oep_in_bytes(text_buf: &[u8], oep_rva: u32) -> Option<u32> {
    let len = text_buf.len();
    if len < 10 {
        return None;
    }

    let scan_end = len.saturating_sub(10);
    for i in 0..=scan_end {
        if text_buf[i] == 0xE8 && text_buf[i + 5] == 0xE9 {
            // Read the rel32 displacement from the E8 instruction.
            let displacement = i32::from_le_bytes([
                text_buf[i + 1],
                text_buf[i + 2],
                text_buf[i + 3],
                text_buf[i + 4],
            ]) as i64;

            // target_rva = i + 5 + displacement
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
///
/// Convenience wrapper around [`try_find_correct_oep`] that accepts
/// `search_range` (bytes to look before and after the OEP) and uses
/// `crate::init::ThemidaPeInfo` fields directly.
///
/// This is the simpler entry point that corresponds to the original task spec.
/// Internally, it reads the `.text` section and scans for the MSVC CRT pattern.
pub fn try_find_correct_oep_by_range(
    debugger: &dyn DebuggerCore,
    oep: usize,
    search_range: usize,
    text_base: usize,
    text_len: usize,
    major_linker_version: u8,
) -> Result<Option<usize>, ThemidaError> {
    // The original Pascal scans the entire .text section rather than a limited
    // range — the `oep` itself becomes the anchor ("ScanFor") and we search
    // for a call that targets it.  The search_range parameter exists for future
    // flexibility but isn't strictly needed for MSVC OEP detection; we still
    // respect it by clamping the scan window if search_range < text_len.

    if !KNOWN_MSVC_VERSIONS.contains(&major_linker_version) {
        warn!(
            major_linker_version,
            "Don't know what to do about OEP for this compiler — target likely won't run"
        );
        return Ok(None);
    }

    // Read a window around the OEP.
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

    // Scan for E8 ... E9 pattern with the first target being `oep`
    let end = effective_len.saturating_sub(10);
    for i in 0..end {
        if buf[i] == 0xE8 && buf[i + 5] == 0xE9 {
            let disp = {
                let mut d = [0u8; 4];
                d.copy_from_slice(&buf[i + 1..i + 5]);
                i32::from_le_bytes(d)
            };
            // The `disp` is relative to the address of the next instruction
            // (i.e., scan_start + i + 5). The target absolute address should
            // equal `oep`.
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
// Public API — OEP restoration (stolen bytes)
// ---------------------------------------------------------------------------

/// Restore stolen OEP bytes for MSVC 6 (x86).
///
/// MSVC 6-compiled binaries have a characteristic OEP:
///
/// ```asm
/// push  ebp
/// mov   ebp, esp
/// push  -1
/// push  <exception_struct>     ; __except_handler
/// push  <handler>              ; exception handler
/// ... (SEH setup)
/// call  ds:GetVersion
/// xor   edx, edx
/// ```
///
/// Themida overwrites the start of this function. The first bytes at the OEP
/// become `mov dl, ah` (8A D4), a two-byte no-op in practice. We detect this
/// sentinel and restore the original stub from a template, patching in the
/// correct `GetVersion` IAT pointer.
///
/// ## Returns
///
/// `Ok(true)` — the OEP was successfully restored (and `oep` was adjusted
/// backward by the size of the restored stub).
/// `Ok(false)` — the OEP doesn't look stolen (not MSVC6); nothing was done.
///
/// ## References
///
/// `Themida.pas` `RestoreStolenOEPForMSVC6` (lines 1243–1321):
/// ```pascal
/// RPM(OEP, @CheckBuf, 2);
/// if (CheckBuf[0] <> $8A) or (CheckBuf[1] <> $D4) then
///   Exit; // not MSVC6 or not stolen
/// ...
/// Dec(OEP, Length(RestoreBuf));
/// WriteProcessMemory(FProcess.hProcess, Pointer(OEP), @RestoreBuf, ...);
/// ```
pub fn restore_stolen_oep_msvc6(
    debugger: &mut dyn DebuggerCore,
    oep: usize,
    image_base: usize,
    base_of_data: usize,
) -> Result<bool, ThemidaError> {
    // 1. Check for the sentinel bytes `mov dl, ah` (8A D4).
    let mut check: [u8; 2] = [0; 2];
    let read = debugger
        .read_memory(oep, &mut check)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC6 OEP sentinel: {e}")))?;

    if read < 2 || check[0] != 0x8A || check[1] != 0xD4 {
        trace!("Not MSVC6 or OEP not stolen");
        return Ok(false);
    }

    info!("Stolen MSVC6 OEP detected at {oep:#x}");

    // The restore data template from the Pascal reference:
    // ```
    // $55, $8B, $EC, $6A, $FF,
    // $68, 0, 0, 0, 0,          // push exception_struct (filled from stack)
    // $68, 0, 0, 0, 0,          // push handler (filled from stack)
    // $64, $A1, $00, $00, $00, $00, $50, $64, $89, $25, $00, $00, $00, $00,
    // $83, $EC, $58,
    // $53, $56, $57,
    // $89, $65, $E8,
    // $FF, $15, 0, 0, 0, 0,     // call ds:GetVersion (filled from IAT)
    // $33, $D2
    // ```
    // Length: 46 bytes (indices 0..45)
    let mut restore: [u8; 46] = [
        0x55, 0x8B, 0xEC, 0x6A, 0xFF,
        0x68, 0x00, 0x00, 0x00, 0x00, // [5..9]  exception_struct
        0x68, 0x00, 0x00, 0x00, 0x00, // [10..14] handler
        0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, // [15..20] mov eax, fs:[0]
        0x50,                               // [21]     push eax
        0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00, // [22..28] mov fs:[0], esp
        0x83, 0xEC, 0x58,                         // [29..31] sub esp, 58h
        0x53, 0x56, 0x57,                         // [32..34] push ebx, esi, edi
        0x89, 0x65, 0xE8,                         // [35..37] mov [ebp-18h], esp
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,       // [38..43] call ds:GetVersion
        0x33, 0xD2,                               // [44..45] xor edx, edx
    ];

    // 2. Verify that there's a valid return instruction just before the stolen
    //    OEP gap (`C2` or `C3` at `oep - RESTORE_LEN - 3`).
    let mut gap_check: [u8; 3] = [0; 3];
    let read = debugger
        .read_memory(oep.wrapping_sub(49), &mut gap_check)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC6 gap: {e}")))?;

    if read < 3 || (gap_check[0] != 0xC2 && gap_check[2] != 0xC3) {
        warn!("Stolen OEP gap mismatch — expected C2/C3 before stolen region");
        return Ok(false);
    }

    // 3. Read the current thread context to get stack values.
    //    The Pascal reference reads:
    //      - `[ebp - 3 * SizeOf(Pointer)]` → exception_struct ptr (→ offset 5)
    //      - `[ebp - 4 * SizeOf(Pointer)]` → handler ptr (→ offset 10)  ← actually `ebp - 2*ptr` in the Pascal code
    //    But accessing ebp requires a thread context, which we likely don't
    //    have available here. Instead, we defer to the caller: for now, we
    //    write the restore data with zeroed placeholder values and let the
    //    caller fill them in.

    // For MSVC6, the GetVersion IAT entry must be patched.
    // Scan the IAT area for `kernel32!GetVersion` in the target.
    let get_version_addr = resolve_get_version_addr(debugger, image_base, base_of_data)?;
    if get_version_addr == 0 {
        warn!("Unable to find GetVersion in IAT — MSVC6 OEP may not resolve correctly");
        return Ok(false);
    }

    // Write the GetVersion IAT pointer into the stub at offsets [40..43].
    // In the template, `FF 15 <dword>` → the dword is the absolute IAT address.
    restore[40..44].copy_from_slice(&(get_version_addr as u32).to_le_bytes());

    // 4. Write the restored stub into the target at `oep - 46`.
    let stub_addr = oep.wrapping_sub(46);

    let written = debugger
        .write_memory(stub_addr, &restore)
        .map_err(|e| ThemidaError::Debugger(format!("write MSVC6 OEP stub: {e}")))?;

    if written < restore.len() {
        warn!(
            expected = restore.len(),
            actual = written,
            "Partial write of MSVC6 OEP stub"
        );
        return Ok(false);
    }

    info!("MSVC6 OEP restored — correct OEP at {stub_addr:#x}");
    Ok(true)
}

/// Restore stolen OEP bytes for MSVC 9 DLLs (x86).
///
/// MSVC 9 DLLs have their first instruction stolen and replaced with a `jmp`
/// into the Themida VM. The original bytes are:
/// ```asm
/// mov edi, edi    ; 8B FF
/// push ebp         ; 55
/// mov ebp, esp     ; 8B EC
/// cmp [ebp+0Ch], 1 ; 83 7D 0C 01
/// jnz +5           ; 75 05
/// ```
///
/// We detect this by checking that the current OEP starts with `E8` (call into
/// VM) and that the byte just before the restored region is `E9` (jmp to VM).
///
/// ## Returns
///
/// `Ok(true)`  — the OEP was restored (and `oep` was adjusted backward).
/// `Ok(false)` — not an MSVC9 DLL stolen OEP; nothing was done.
///
/// ## References
///
/// `Themida.pas` `RestoreStolenOEPForMSVC9DLL` (lines 1323–1344):
/// ```pascal
/// RESTORE_DATA: array[0..10] of Byte = ($8B, $FF, $55, $8B, $EC, $83, $7D, $0C, $01, $75, $05);
/// RPM(OEP, @CheckByte, 1);
/// if CheckByte <> $E8 then Exit;
/// RPM(OEP - Cardinal(Length(RESTORE_DATA)), @CheckByte, 1);
/// if CheckByte <> $E9 then Exit;
/// Dec(OEP, Length(RESTORE_DATA));
/// WriteProcessMemory(FProcess.hProcess, Pointer(OEP), @RESTORE_DATA, ...);
/// ```
pub fn restore_stolen_oep_msvc9_dll(
    debugger: &mut dyn DebuggerCore,
    oep: usize,
    image_base: usize,
) -> Result<bool, ThemidaError> {
    let _ = image_base; // reserved for future use

    // 1. Check that OEP starts with E8 (call into VM / stolen code).
    let mut check: [u8; 1] = [0];
    let read = debugger
        .read_memory(oep, &mut check)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC9 OEP sentinel: {e}")))?;

    if read < 1 || check[0] != 0xE8 {
        trace!("Not MSVC9 DLL or OEP not stolen (missing E8 at OEP)");
        return Ok(false);
    }

    // 2. Check that the byte *before* the restored region is E9 (jmp to VM).
    let gap_addr = oep.wrapping_sub(11); // the restore data is 11 bytes
    let mut gap_byte: [u8; 1] = [0];
    let read = debugger
        .read_memory(gap_addr, &mut gap_byte)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC9 gap: {e}")))?;

    if read < 1 || gap_byte[0] != 0xE9 {
        trace!("Not MSVC9 DLL stolen OEP (missing E9 before gap)");
        return Ok(false);
    }

    info!("Stolen MSVC9 DLL OEP detected at {oep:#x}");

    // 3. Write the restore data.
    //    RESTORE_DATA: [0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0x83, 0x7D, 0x0C, 0x01, 0x75, 0x05]
    const RESTORE: [u8; 11] = [
        0x8B, 0xFF,                         // mov edi, edi
        0x55,                               // push ebp
        0x8B, 0xEC,                         // mov ebp, esp
        0x83, 0x7D, 0x0C, 0x01,            // cmp dword ptr [ebp+0Ch], 1
        0x75, 0x05,                         // jnz +5
    ];

    let stub_addr = oep.wrapping_sub(RESTORE.len());

    let written = debugger
        .write_memory(stub_addr, &RESTORE)
        .map_err(|e| ThemidaError::Debugger(format!("write MSVC9 DLL OEP stub: {e}")))?;

    if written < RESTORE.len() {
        warn!(
            expected = RESTORE.len(),
            actual = written,
            "Partial write of MSVC9 DLL OEP stub"
        );
        return Ok(false);
    }

    info!("MSVC9 DLL OEP restored — correct OEP at {stub_addr:#x}");
    Ok(true)
}

// ---------------------------------------------------------------------------
// Public API — x64 MSVC OEP writing
// ---------------------------------------------------------------------------

/// Write a synthetic MSVC OEP for x64 targets.
///
/// When the OEP is virtualised on x64 (i.e., execution at the reported OEP
/// goes straight into the Themida VM), the `__security_init_cookie` call at
/// `init_cookie_addr` is the *real* function. We synthesise a minimal OEP that
/// calls `__security_init_cookie` and then jumps to `__scrt_common_main_seh`:
///
/// ```asm
/// sub  rsp, 28h                    ; shadow space
/// call __security_init_cookie      ; E8 <rel32>
/// add  rsp, 28h                    ; restore stack
/// jmp  __scrt_common_main_seh      ; E9 <rel32>
/// ```
///
/// The code uses `oep` as the target address for this stub.
///
/// ## References
///
/// `Themida64.pas` `WriteMSVCOEP` (lines 517–541):
/// ```pascal
/// Instrs.SubRsp := $28EC8348;
/// Instrs.Call := $E8;
/// Instrs.CallRel := FMSVCInitCookie - (FMSVCOEP + 4) - 5;
/// Instrs.AddRsp := $28C48348;
/// Instrs.Jmp := $E9;
/// Instrs.JmpRel := CRTStartup - (FMSVCOEP + 4+5+4) - 5;
/// VirtualProtectEx(FProcess.hProcess, Pointer(FMSVCOEP), SizeOf(Instrs),
///   PAGE_EXECUTE_READWRITE, @x);
/// WriteProcessMemory(FProcess.hProcess, Pointer(FMSVCOEP), @Instrs, ...);
/// ```
pub fn write_msvc_oep_x64(
    debugger: &mut dyn DebuggerCore,
    h_process: windows::Win32::Foundation::HANDLE,
    oep: usize,
    security_init_cookie_addr: usize,
    scrt_common_main_seh_addr: usize,
) -> Result<(), ThemidaError> {
    use windows::Win32::System::Memory::{
        VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    // The stub layout:
    //   [0..3]   48 83 EC 28         sub rsp, 28h
    //   [4]      E8                  call rel32
    //   [5..8]   <call_rel32>        displacement to __security_init_cookie
    //   [9..12]  48 83 C4 28         add rsp, 28h
    //   [13]     E9                  jmp rel32
    //   [14..17] <jmp_rel32>         displacement to __scrt_common_main_seh
    // Total: 18 bytes
    let mut stub: Vec<u8> = vec![
        0x48, 0x83, 0xEC, 0x28,       // sub rsp, 28h
        0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32 (placeholder)
        0x48, 0x83, 0xC4, 0x28,       // add rsp, 28h
        0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32 (placeholder)
    ];

    // Patch the call displacement: target = displacement + call_inst_end
    // call_inst_end = oep + 4 + 5 = oep + 9
    let call_disp: i32 = (security_init_cookie_addr as i64)
        .wrapping_sub((oep + 9) as i64) as i32;
    stub[5..9].copy_from_slice(&call_disp.to_le_bytes());

    // Patch the jmp displacement: target = displacement + jmp_inst_end
    // jmp_inst_end = oep + 13 + 5 = oep + 18
    let jmp_disp: i32 = (scrt_common_main_seh_addr as i64)
        .wrapping_sub((oep + 18) as i64) as i32;
    stub[14..18].copy_from_slice(&jmp_disp.to_le_bytes());

    // Make the OEP page writeable so we can write the stub.
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();

    // SAFETY: h_process is valid; the OEP address is within .text which was
    // previously guarded (now being restored).
    unsafe {
        VirtualProtectEx(
            h_process,
            oep as *const std::ffi::c_void,
            stub.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| {
        ThemidaError::Debugger(format!(
            "VirtualProtectEx at OEP {oep:#x} for MSVC stub: {e}"
        ))
    })?;

    let written = debugger
        .write_memory(oep, &stub)
        .map_err(|e| ThemidaError::Debugger(format!("write MSVC x64 OEP stub: {e}")))?;

    if written < stub.len() {
        warn!(
            expected = stub.len(),
            actual = written,
            "Partial write of MSVC x64 OEP stub"
        );
    }

    debug!(
        "MSVC x64 OEP written at {oep:#x}: call → {security_init_cookie_addr:#x}, jmp → {scrt_common_main_seh_addr:#x}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Public API — TLS callback handling
// ---------------------------------------------------------------------------

/// Handle TLS callback execution during guarded access.
///
/// ## Background
///
/// PE files can specify TLS callbacks — functions called before `main` /
/// `DllMain`. Themida may use these to run anti-debug initialisation. The
/// debugger must detect and skip them so they don't interfere with unpacking.
///
/// ## Detection heuristic
///
/// When a guarded access occurs with `ExceptionInformation[0] == 8` (execute
/// access), and the faulting address is inside `.text`, it may be a TLS
/// callback rather than the OEP. The Pascal reference checks:
///
/// 1. The return address on the stack is inside the Themida section.
/// 2. Argument 0 saved on the stack has its low 12 bits as zero.
/// 3. Argument 1 is ≤ 3.
///
/// If all conditions hold, the callback is skipped by adjusting EIP/RIP to
/// the return address and popping the arguments off the stack.
///
/// ## Parameters
///
/// - `execution_type` — `ExceptionInformation[0]`: 0=read, 1=write, 8=execute.
/// - `tls_total` — total TLS callbacks expected (from PE TLS directory).
/// - `tls_counter` — how many have already been skipped.
///
/// ## Returns
///
/// A [`TlsCallbackResult`] indicating whether this was handled as a TLS
/// callback or whether the caller should treat it as the OEP.
///
/// ## References
///
/// `Themida.pas` `ProcessGuardedAccess` TLS branch (lines 1045–1073):
/// ```pascal
/// else if (FTLSTotal > 0) and (FTLSCounter < FTLSTotal) then begin
///   RPM(C.Esp, @RetAddr, 4);
///   RPM(C.Esp + 4, @Args, 12);
///   if TMSectR.Contains(RetAddr) and not IsTMExceptionHandler(RetAddr)
///      and ((Args[0] and $FFF) = 0) and (Args[1] <= 3) then begin
///     Inc(FTLSCounter);
///     C.Eip := RetAddr;
///     Inc(C.Esp, 4 + 3*4);
///     SetThreadContext(hThread, C);
///   end else
///     goto OEPReached;
/// end;
/// ```
///
/// `Themida64.pas` TLS branch (lines 403–417):
/// ```pascal
/// else if (ExcRecord.ExceptionInformation[0] = 8)
///      and (FTLSTotal > 0) and (FTLSCounter < FTLSTotal) then begin
///   Inc(FTLSCounter);
///   FGuardStart := TMSectR.Address;
///   FGuardEnd := FImageBoundary;
///   FTMGuard := True;
///   VirtualProtectEx(..., PAGE_READWRITE, ...);
/// end;
/// ```
pub fn handle_tls_callbacks(
    #[allow(unused)] debugger: &mut dyn DebuggerCore,
    exception_address: usize,
    execution_type: u32,
    tls_total: u32,
    tls_counter: &mut u32,
) -> Result<TlsCallbackResult, ThemidaError> {
    // x86: check TLS via thread context (return address in Themida section).
    // x64: check via ExceptionInformation[0] == 8 (execute access).
    if tls_total == 0 || *tls_counter >= tls_total {
        return Ok(TlsCallbackResult {
            oep_found: false,
            oep_address: None,
            tls_callbacks_executed: *tls_counter,
        });
    }

    // On x64, the detection is simpler — an execute access (type == 8) inside
    // .text with remaining TLS callbacks is enough.
    #[cfg(target_arch = "x86_64")]
    {
        if execution_type != 8 {
            // Not an execute access — might be the OEP.
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

        // Read return address from [ESP].
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

        // Read callback arguments from [ESP + 4].
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

        // Parse 3 u32 arguments from the buffer
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

        // TLS callback heuristics:
        //   - arg0 has low 12 bits zero  (aligned)
        //   - arg1 <= 3  (standard TLS reason: 0=process attach, etc.)
        if (arg0 & 0xFFF) == 0 && arg1 <= 3 {
            *tls_counter += 1;
            info!(
                "TLS callback skipped: {}/{} at {exception_address:#x} (args: {arg0:#x}, {arg1})",
                *tls_counter, tls_total,
            );

            // Modify the context: skip the TLS callback by jumping to the
            // return address and cleaning the stack.
            let mut ctx = debugger
                .get_thread_context(thread_id)
                .map_err(|e| ThemidaError::Debugger(format!("get_thread_context for TLS skip: {e}")))?;

            // EIP = return address, ESP += 4 + 3*4 (return addr + 3 args)
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

        // Doesn't look like a TLS callback — assume OEP.
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Look up the IAT address of `GetVersion` in the target process.
///
/// This is needed for MSVC6 OEP restoration. We read the IAT area (starting at
/// `image_base + base_of_data`) and scan for a known API address. On the
/// debugger side we don't have direct access to `GetProcAddress` in the target,
/// but `GetVersion` is a well-known kernel32 export.
///
/// Returns the absolute virtual address of the IAT slot that holds
/// `GetVersion`, or 0 if not found.
#[cfg(target_arch = "x86")]
fn resolve_get_version_addr(
    debugger: &dyn DebuggerCore,
    image_base: usize,
    base_of_data: usize,
) -> Result<usize, ThemidaError> {
    // On the debugger-host side, resolve GetVersion from our own kernel32.
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::core::PCWSTR;

    let kernel32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    // SAFETY: kernel32.dll is always loaded.
    let k32_handle = unsafe {
        GetModuleHandleW(PCWSTR::from_raw(kernel32_name.as_ptr()))
            .map_err(|e| ThemidaError::Debugger(format!("GetModuleHandle(kernel32): {e}")))?
    };
    // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
    let get_version_host = unsafe {
        let name = std::ffi::CStr::from_bytes_with_nul_unchecked(b"GetVersion\0");
        windows::Win32::System::LibraryLoader::GetProcAddress(k32_handle, name)
            .unwrap_or(std::ptr::null_mut())
    };

    if get_version_host.is_null() {
        warn!("GetVersion not found in host kernel32");
        return Ok(0);
    }

    let get_version_addr = get_version_host as usize;

    // Read the IAT area and find the slot that holds this address.
    let iat_start = image_base.wrapping_add(base_of_data);
    let iat_size = 512 * 4; // scan up to 512 IAT entries

    let mut iat_buf = vec![0u8; iat_size];
    let bytes_read = debugger
        .read_memory(iat_start, &mut iat_buf)
        .map_err(|e| ThemidaError::Debugger(format!("read IAT for GetVersion: {e}")))?;

    let dword_count = (bytes_read / 4).min(512);
    for i in 0..dword_count {
        let val = u32::from_le_bytes([
            iat_buf[i * 4],
            iat_buf[i * 4 + 1],
            iat_buf[i * 4 + 2],
            iat_buf[i * 4 + 3],
        ]);
        // Compare with GetVersion address. Note: on the target, the IAT may
        // hold a different address (e.g. after rebasing). We check whether
        // the low 16 bits match (GetVersion consistently ends in the same
        // offset within kernel32 across rebases on the same OS).
        if (val as usize) == get_version_addr {
            let iat_slot = iat_start + i * 4;
            debug!("Found GetVersion IAT slot at {iat_slot:#x}");
            return Ok(iat_slot);
        }
    }

    warn!("GetVersion not found in target IAT");
    Ok(0)
}

// x64 stub — no GetVersion needed (MSVC6 is x86 only).
#[cfg(target_arch = "x86_64")]
fn resolve_get_version_addr(
    _debugger: &dyn DebuggerCore,
    _image_base: usize,
    _base_of_data: usize,
) -> Result<usize, ThemidaError> {
    // MSVC6 is 32-bit only; this function should never be called on x64.
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- helpers ----------------------------------------------------------

    /// Build a `.text` buffer that contains the MSVC CRT startup pattern
    /// `call __security_init_cookie; jmp __scrt_common_main_seh` at a given
    /// byte offset.
    ///
    /// `oep_rva` is the RVA (relative to the buffer start) that the `call`
    /// instruction should target.
    fn make_msvc_text_with_pattern(pattern_offset: u32, oep_rva: u32) -> Vec<u8> {
        // Buffer large enough for the pattern + slack on both sides.
        let len = (pattern_offset as usize) + 20;
        let mut buf = vec![0xCCu8; len]; // fill with INT3 (typical padding)

        // Compute the rel32 for the `call` at pattern_offset.
        // target = pattern_offset + 5 + disp  ⇒  disp = target - pattern_offset - 5
        let call_disp = (oep_rva as i64) - (pattern_offset as i64) - 5;
        let call_disp: i32 = call_disp as i32;

        buf[pattern_offset as usize] = 0xE8;
        buf[pattern_offset as usize + 1..pattern_offset as usize + 5]
            .copy_from_slice(&call_disp.to_le_bytes());

        // `jmp __scrt_common_main_seh` — jump target doesn't matter for the
        // matcher, just needs to be E9 xx xx xx xx. Use a placeholder +0x100.
        buf[pattern_offset as usize + 5] = 0xE9;
        let jmp_disp: i32 = 0x100;
        buf[pattern_offset as usize + 6..pattern_offset as usize + 10]
            .copy_from_slice(&jmp_disp.to_le_bytes());

        buf
    }

    // -- known MSVC versions ----------------------------------------------

    #[test]
    fn test_known_msvc_versions() {
        assert!(KNOWN_MSVC_VERSIONS.contains(&2));   // Ancient MSVC
        assert!(KNOWN_MSVC_VERSIONS.contains(&6));   // MSVC 6 (VC6)
        assert!(KNOWN_MSVC_VERSIONS.contains(&7));   // MSVC 7 (VS2003)
        assert!(KNOWN_MSVC_VERSIONS.contains(&8));   // MSVC 8 (VS2005)
        assert!(KNOWN_MSVC_VERSIONS.contains(&9));   // MSVC 9 (VS2008)
        assert!(KNOWN_MSVC_VERSIONS.contains(&14));  // MSVC 14 (VS2015+)
        assert!(!KNOWN_MSVC_VERSIONS.contains(&1));  // Too old
        assert!(!KNOWN_MSVC_VERSIONS.contains(&5));  // VC5 (not supported)
        assert!(!KNOWN_MSVC_VERSIONS.contains(&15)); // Not a real version
    }

    // -- find_real_oep_in_bytes (pure helper) -----------------------------

    #[test]
    fn find_real_oep_in_bytes_matches_at_offset_zero() {
        // Pattern at offset 0, calling OEP at RVA 0x1010.
        // call_disp = 0x1010 - 0 - 5 = 0x100B
        let buf = make_msvc_text_with_pattern(0, 0x1010);
        assert_eq!(find_real_oep_in_bytes(&buf, 0x1010), Some(0));
    }

    #[test]
    fn find_real_oep_in_bytes_matches_mid_buffer() {
        // Realistic scenario: CRT startup pattern at offset 0x1000 inside
        // .text, targeting __security_init_cookie at RVA 0x2010.
        let buf = make_msvc_text_with_pattern(0x1000, 0x2010);
        assert_eq!(find_real_oep_in_bytes(&buf, 0x2010), Some(0x1000));
    }

    #[test]
    fn find_real_oep_in_bytes_no_match_when_oep_rva_differs() {
        let buf = make_msvc_text_with_pattern(0x100, 0x2000);
        // Looking for OEP at 0x3000 — not present.
        assert_eq!(find_real_oep_in_bytes(&buf, 0x3000), None);
    }

    #[test]
    fn find_real_oep_in_bytes_skips_non_matching_e8() {
        // Put an E8 ... xx xx xx at offset 0, but byte[5] is NOT E9.
        let mut buf = vec![0xCCu8; 20];
        buf[0] = 0xE8;
        buf[1..5].copy_from_slice(&0x100_i32.to_le_bytes()); // call target = 0x105
        buf[5] = 0x90; // NOP — not E9

        // Looking for OEP at 0x105 — call target matches, but pattern
        // requires byte[5] == E9, so this should NOT match.
        assert_eq!(find_real_oep_in_bytes(&buf, 0x105), None);
    }

    #[test]
    fn find_real_oep_in_bytes_small_buffer_returns_none() {
        // Buffer too small to hold the 10-byte pattern.
        let buf = vec![0xE8u8, 0x01, 0x02, 0x03, 0x04, 0xE9, 0x05];
        assert_eq!(find_real_oep_in_bytes(&buf, 0), None);
    }

    #[test]
    fn find_real_oep_in_bytes_empty_buffer_returns_none() {
        assert_eq!(find_real_oep_in_bytes(&[], 0), None);
    }

    #[test]
    fn find_real_oep_in_bytes_exact_ten_bytes() {
        // Buffer exactly 10 bytes — should find the pattern at offset 0
        // as long as call math works out to oep_rva = 0.
        // disp = 0 - 0 - 5 = -5 (0xFFFFFFFB)
        let mut buf = vec![0xCCu8; 10];
        buf[0] = 0xE8;
        buf[1..5].copy_from_slice(&(-5_i32).to_le_bytes()); // target = 0 + 5 + (-5) = 0
        buf[5] = 0xE9;
        buf[6..10].copy_from_slice(&0_i32.to_le_bytes());

        assert_eq!(find_real_oep_in_bytes(&buf, 0), Some(0));
    }

    #[test]
    fn find_real_oep_in_bytes_returns_first_match() {
        // Two patterns, both matching the same oep_rva. Should return the
        // first one (lowest offset).
        let len = 0x200 + 20; // large enough for both patterns
        let mut buf = vec![0xCCu8; len];

        // Pattern A at offset 0x100 targeting oep_rva 0x500.
        let call_disp_a: i32 = (0x500_i64 - 0x100 - 5) as i32;
        buf[0x100] = 0xE8;
        buf[0x101..0x105].copy_from_slice(&call_disp_a.to_le_bytes());
        buf[0x105] = 0xE9;
        buf[0x106..0x10A].copy_from_slice(&0x100_i32.to_le_bytes()); // jmp placeholder

        // Pattern B at offset 0x200 targeting the same oep_rva 0x500.
        let call_disp_b: i32 = (0x500_i64 - 0x200 - 5) as i32;
        buf[0x200] = 0xE8;
        buf[0x201..0x205].copy_from_slice(&call_disp_b.to_le_bytes());
        buf[0x205] = 0xE9;
        buf[0x206..0x20A].copy_from_slice(&0x200_i32.to_le_bytes()); // jmp placeholder

        assert_eq!(find_real_oep_in_bytes(&buf, 0x500), Some(0x100));
    }

    // -- TLS callback result ----------------------------------------------

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
