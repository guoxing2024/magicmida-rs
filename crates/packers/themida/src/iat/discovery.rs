//! IAT reference discovery: compiler detection, Delphi/Go helpers, and the
//! generic MSVC IAT-reference scanner.
//!
//! All functions in this module are `pub(super)` — they are internal to the
//! [`crate::iat`] module.

use tracing::{debug, info, warn};

use mida_core::DebuggerCore;
use mida_disasm::Disassembler;

use crate::error::ThemidaError;
use super::fix::is_likely_api_address;
use super::{MAX_IAT_SCAN_INSTR, MAX_IAT_SIZE};

// ===========================================================================
// Compiler detection
// ===========================================================================

/// Internal: detect compiler from `.text` content alone.
///
/// Detection signals:
///
/// | Compiler | Signal                                |
/// |----------|---------------------------------------|
/// | Go       | `.text` starts with `FF 20 47 6F`     |
/// |          | (identifiable by "Go build ID")        |
/// | Delphi   | `MajorLinkerVersion` >= 6 **and**       |
/// |          | `.text` bytes at offset 6 (x86) or     |
/// |          | 10 (x64) spell `"Bool"` or `"Byte"`    |
/// | MSVC     | Everything else.                       |
///
/// The Delphi offset differs between architectures: on x86 the "Boolean"
/// type-info string sits at offset 6, while on x64 it sits at offset 10.
/// See `ThemidaCommon.pas` `DetermineIATAddress`:
/// ```pascal
/// (PCardinal(@CodeDump[{$IFDEF CPUX86}6{$ELSE}10{$ENDIF}])^ = $6C6F6F42) or
/// (PCardinal(@CodeDump[6])^ = $65747942)
/// ```
pub(super) fn detect_compiler_from_text(text: &[u8]) -> super::CompilerHint {
    use super::CompilerHint;
    // Go: .text starts with FF 20 47 6F ("  Go" — "Go build ID" header).
    if text.len() >= 4
        && text[0] == 0xFF
        && text[1] == 0x20
        && text[2] == 0x47
        && text[3] == 0x6F
    {
        return CompilerHint::Go;
    }

    // Delphi: offset 6 (x86) or 10 (x64) spells "Bool" ("Boolean"); or
    // offset 6 always spells "Byte" ("ByteType").  These are Delphi
    // type-info strings embedded at the start of .text.
    let delphi_bool_offset = if cfg!(target_arch = "x86_64") { 10 } else { 6 };
    if text.len() >= delphi_bool_offset + 4 {
        let at_bool_off = &text[delphi_bool_offset..delphi_bool_offset + 4];
        if at_bool_off == b"Bool" {
            return CompilerHint::Delphi;
        }
    }
    if text.len() >= 10 {
        let at6 = &text[6..10];
        if at6 == b"Byte" {
            return CompilerHint::Delphi;
        }
    }

    CompilerHint::Msvc
}

// ===========================================================================
// Internal — Delphi / Go helpers
// ===========================================================================

/// Find the offset (from `.text` base) where Delphi's type-metadata prefix
/// ends and real code begins.
///
/// Delphi binaries have type information (a stream of dword pointers) at the
/// start of `.text`.  We skip forward until we've seen three `FF 25` (jmp
/// dword ptr) instructions — the third one is likely our first real API
/// import reference.
///
/// Returns an address (image_base + offset).
pub(super) fn find_delphi_call(text: &[u8], text_base: usize) -> usize {
    let limit = text.len().saturating_sub(6);
    let mut counter: u32 = 0;

    for i in 0..limit {
        // FF 25 = jmp dword ptr [mem] (x86) or FF 25 = jmp qword ptr [rip+...] (x64)
        if text[i] == 0xFF && text[i + 1] == 0x25 {
            counter += 1;
            if counter == 3 {
                // Skip the first two to be safe.
                return text_base + i;
            }
        }
    }

    // Fallback: start from the beginning of .text.
    text_base
}

/// Find the end of the "Go build ID" string embedded in `.text`.
///
/// Go places a `FF 20` marker at the very start of `.text` to indicate the
/// end of the build-id.  We search for `FF 20` and return the offset + 2.
pub(super) fn find_go_build_id_end(text: &[u8]) -> usize {
    if text.len() < 2 {
        return 0;
    }

    // The "Go build ID" string ends with 20 FF (space + 0xFF marker byte).
    for i in 0..text.len().saturating_sub(1) {
        if text[i] == 0xFF && text[i + 1] == 0x20 {
            return i + 2;
        }
    }

    0
}

/// Go-specific IAT reference search.
///
/// Go binaries use a different calling convention: the API address is loaded
/// via `mov rax, [addr]; call rax` (x64) or `mov eax, [addr]; call eax` (x86).
/// We scan for this pattern and return the address of the memory operand
/// (the IAT slot).
pub(super) fn find_go_api_call(
    debugger: &dyn DebuggerCore,
    text: &[u8],
    text_base: usize,
    start_addr: usize,
) -> Result<usize, ThemidaError> {
    let bitness = if std::mem::size_of::<usize>() == 8 {
        64
    } else {
        32
    };
    let disasm = Disassembler::new(bitness, start_addr as u64);

    let offset_in_text = start_addr.saturating_sub(text_base);
    if offset_in_text >= text.len() {
        return Ok(0);
    }

    let slice = &text[offset_in_text..];

    for insn in disasm.decode_all(slice) {
        let ip = insn.ip() as usize;
        let len = insn.len();

        // Look for: mov reg, [mem] followed by call reg
        // On x64: mov rax, [rip + disp] (7 bytes: 48 8B 05 ...)
        //          mov [rsp+...], rax (5 bytes: 48 89 44 24 ...)
        //          call rax (2 bytes: FF D0)
        // The Pascal reference checks opcode == 0x8B and then
        // tests for the specific mov/call sequence.
        if bitness == 64 {
            if insn.mnemonic() == iced_x86::Mnemonic::Mov
                && insn.op0_kind() == iced_x86::OpKind::Register
                && insn.op1_kind() == iced_x86::OpKind::Memory
                && len == 7
            {
                // Check the next instruction(s): we need mov [rsp+...], reg
                // then call reg. This is the Go-specific pattern.
                let after_mov = offset_in_text + (ip - start_addr) + len;
                if after_mov + 7 <= text.len() {
                    // Is the next instruction `mov [rsp+...], reg` (48 89 44 24 xx)?
                    if text[after_mov] == 0x48
                        && text[after_mov + 1] == 0x89
                        && text[after_mov + 2] == 0x44
                        && text[after_mov + 3] == 0x24
                    {
                        // The IAT pointer is the memory displacement from the
                        // first mov. It's RIP-relative on x64.
                        let iat_pointer =
                            ip + 7 + insn.memory_displacement64() as usize;

                        // Verify by reading the pointer and checking it looks
                        // like an API address.
                        let mut ptr_val: usize = 0;
                        // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
                        let buf = unsafe {
                            std::slice::from_raw_parts_mut(
                                &mut ptr_val as *mut usize as *mut u8,
                                std::mem::size_of::<usize>(),
                            )
                        };
                        if debugger.read_memory(iat_pointer, buf).is_ok()
                            && is_likely_api_address(ptr_val) {
                                return Ok(iat_pointer);
                            }
                    }
                }
            }
        } else {
            // x86: mov eax, [addr] (6 bytes: A1 xx xx xx xx or 8B 05 ...)
            // followed by call eax (2 bytes: FF D0)
            if insn.mnemonic() == iced_x86::Mnemonic::Mov
                && insn.op0_kind() == iced_x86::OpKind::Register
                && insn.op1_kind() == iced_x86::OpKind::Memory
                && len == 6
            {
                let after_mov = offset_in_text + (ip - start_addr) + len;
                if after_mov + 5 <= text.len()
                    && (text[after_mov] == 0x89 || text[after_mov] == 0x8B)
                        && (text[after_mov + 1] & 0xF8) == 0x04
                        && (text[after_mov + 2] == 0x24)
                    {
                        let iat_pointer = insn.memory_displacement64() as usize;
                        if iat_pointer > 0x10000 {
                            let mut ptr_val: usize = 0;
                            // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
                            let buf = unsafe {
                                std::slice::from_raw_parts_mut(
                                    &mut ptr_val as *mut usize as *mut u8,
                                    std::mem::size_of::<usize>(),
                                )
                            };
                            if debugger.read_memory(iat_pointer, buf).is_ok()
                                && is_likely_api_address(ptr_val) {
                                    return Ok(iat_pointer);
                                }
                        }
                    }
            }
        }
    }

    // Fall back to MSVC-style scan.
    warn!("Go API call pattern not found — falling back to MSVC strategy");
    find_iat_ref_from_address(debugger, text, text_base, start_addr, text.len(), true, MAX_IAT_SCAN_INSTR)
}

// ===========================================================================
// Internal — IAT reference discovery (MSVC / generic)
// ===========================================================================

/// Scan the entire `.text` section for `call [mem]` / `jmp [mem]` instructions,
/// returning the earliest (lowest RVA) IAT pointer found.
///
/// This helps find the true IAT start when OEP-based scanning finds a ref
/// in the middle of the IAT (common when the OEP uses `mov rax,[mem]; call rax`
/// instead of `call [mem]`).
pub(super) fn find_earliest_iat_ref(
    debugger: &dyn DebuggerCore,
    text: &[u8],
    text_base: usize,
    code_size: usize,
) -> Result<usize, ThemidaError> {
    let mut earliest_ref: usize = 0;

    // Scan for FF 15 (call [rip+disp]) and FF 25 (jmp [rip+disp])
    // This matches Pascal's FindCallOrJmpPtr main logic.
    for i in 0..text.len().saturating_sub(6) {
        if text[i] == 0xFF && (text[i + 1] == 0x15 || text[i + 1] == 0x25) {
            let ip = text_base + i;
            let disp32 = i32::from_le_bytes([
                text[i + 2],
                text[i + 3],
                text[i + 4],
                text[i + 5],
            ]);
            let iat_pointer = (ip as i64 + 6 + disp32 as i64) as usize;

            // Validate: pointer should be outside .text
            if iat_pointer < text_base || iat_pointer >= text_base + code_size {
                // Read the slot to ensure it's a valid API address
                let mut ptr_buf = [0u8; 8];
                if debugger.read_memory(iat_pointer, &mut ptr_buf).is_ok() {
                    let the_pointer = usize::from_le_bytes(ptr_buf);
                    if the_pointer > text_base + code_size {
                        // Valid IAT slot
                        if earliest_ref == 0 || iat_pointer < earliest_ref {
                            earliest_ref = iat_pointer;
                        }
                    }
                }
            }
        }
    }

    Ok(earliest_ref)
}

/// Scan from `start_addr`, disassembling instructions and looking for the
/// first `call [mem]` or `jmp [mem]` whose memory operand points outside
/// the `.text` section (i.e. into the IAT / data area).
///
/// If an internal `call rel32` is encountered (target inside `.text`), the
/// function recursively follows it — this handles MSVC's chain of thunks
/// (e.g. `__scrt_common_main_seh` → `main` → `call [__imp_MessageBoxA]`).
///
/// A `ret` instruction stops the search in the current function (unless
/// `ignore_boundary` is `true`, in which case we keep scanning linearly).
pub(super) fn find_iat_ref_from_address(
    debugger: &dyn DebuggerCore,
    text: &[u8],
    text_base: usize,
    start_addr: usize,
    code_size: usize,
    ignore_boundary: bool,
    max_instructions: usize,
) -> Result<usize, ThemidaError> {
    let bitness = if std::mem::size_of::<usize>() == 8 {
        64
    } else {
        32
    };
    let disasm = Disassembler::new(bitness, start_addr as u64);

    let offset = start_addr.saturating_sub(text_base);
    if offset >= text.len() {
        return Ok(0);
    }
    let slice = &text[offset..];
    let mut num_insn: usize = 0;

    for insn in disasm.decode_all(slice) {
        if num_insn >= max_instructions
            && !(ignore_boundary && start_addr < text_base + code_size)
        {
            debug!(
                "Scanning stopped: num_insn={num_insn}, max_instructions={max_instructions}, \
                 ignore_boundary={ignore_boundary}"
            );
            break;
        }

        let ip = insn.ip() as usize;
        let insn_bytes = &slice[(ip - start_addr)..];

        if num_insn < 20 || num_insn.is_multiple_of(50) {
            debug!(
                "Scanning insn #{num_insn} at {ip:#x}: {:02X?}",
                &insn_bytes[..insn_bytes.len().min(8)]
            );
        }

        // Check for indirect call/jmp through memory: `call [mem]` or
        // `jmp [mem]`.  On x86 these are `FF 15 ...` / `FF 25 ...`.
        // On x64 these are also `FF 15 ...` / `FF 25 ...` (RIP-relative).
        if insn_bytes.len() >= 2
            && insn_bytes[0] == 0xFF
            && (insn_bytes[1] == 0x15 || insn_bytes[1] == 0x25)
        {
            // Compute the target of the memory operand.
            // On x86: the displacement is an absolute 32-bit address.
            // On x64: the displacement is a 32-bit signed RIP-relative
            // offset; the effective address is RIP + 6 + disp32.
            //
            // IMPORTANT: iced-x86's `memory_displacement64()` returns the
            // zero-extended 64-bit value.  We must read the raw 32-bit
            // displacement from the instruction bytes and sign-extend it
            // manually to get the correct RIP-relative address.
            let iat_pointer = if bitness == 64 {
                // Read the 32-bit displacement from bytes [2..6] of the
                // instruction (FF 15/25 [disp32]).
                let raw_disp = u32::from_le_bytes([
                    insn_bytes[2],
                    insn_bytes[3],
                    insn_bytes[4],
                    insn_bytes[5],
                ]);
                let disp32 = raw_disp as i32 as i64;
                let insn_end = ip + 6; // FF 15/25 [disp32] is 6 bytes
                (insn_end as i64 + disp32) as usize
            } else {
                // x86: the displacement is an absolute 32-bit address.
                let raw_disp = u32::from_le_bytes([
                    insn_bytes[2],
                    insn_bytes[3],
                    insn_bytes[4],
                    insn_bytes[5],
                ]);
                raw_disp as usize
            };

            debug!(
                "Found indirect {} at {ip:#x} (insn_len={}): bytes={:02X?} → IAT pointer {iat_pointer:#x}",
                if insn_bytes[1] == 0x15 { "call" } else { "jmp" },
                insn.len(),
                &insn_bytes[..insn_bytes.len().min(6)],
            );

            // Sanity check (matches Pascal `DetermineIATAddress.FindCallOrJmpPtr`):
            //   if not RPM(IATPointer, @ThePointer, SizeOf(Pointer))
            //      or (ThePointer > TextBase + CodeSize) then Exit(IATPointer);
            //
            // We read the pointer stored at `iat_pointer`.  If the read fails
            // OR the pointed-to value is outside the code section (i.e. it
            // looks like an API address, not a pointer into .text), then
            // `iat_pointer` is a real IAT slot.
            let mut the_pointer: usize = 0;
            // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
            let ptr_buf = unsafe {
                std::slice::from_raw_parts_mut(
                    &mut the_pointer as *mut usize as *mut u8,
                    std::mem::size_of::<usize>(),
                )
            };
            let ptr_read = debugger.read_memory(iat_pointer, ptr_buf).is_ok();

            if !ptr_read || the_pointer > text_base + code_size {
                info!(
                    "IAT reference found at {iat_pointer:#x} (indirect {} at {ip:#x})",
                    if insn_bytes[1] == 0x15 { "call" } else { "jmp" },
                );
                return Ok(iat_pointer);
            }

            debug!(
                "Skipping IAT pointer {iat_pointer:#x}: points to {the_pointer:#x} \
                 (inside code section)"
            );
        }

        // Follow internal `call rel32` (E8) — if the target is inside
        // the code section, recursively search there.
        if !ignore_boundary
            && insn_bytes.len() >= 5
            && insn_bytes[0] == 0xE8
        {
            let rel32 = i32::from_le_bytes([
                insn_bytes[1],
                insn_bytes[2],
                insn_bytes[3],
                insn_bytes[4],
            ]);
            let target = (ip as i64 + 5 + rel32 as i64) as usize;

            if target >= text_base && target < text_base + code_size {
                // Recurse into the callee.
                let result = find_iat_ref_from_address(
                    debugger,
                    text,
                    text_base,
                    target,
                    code_size,
                    false,
                    max_instructions,
                )?;
                if result != 0 {
                    return Ok(result);
                }
            } else {
                // Direct API call (target outside .text) — not an IAT
                // reference per se, but for x86 this means the IAT is
                // handled via guard addresses.
                debug!(
                    "Direct call to {target:#x} at {ip:#x} — \
                     stopping (probable direct API call)"
                );
                return Ok(0);
            }
        }

        // Stop at `ret` / `ret imm16` unless we're ignoring method boundaries.
        if !ignore_boundary && !insn_bytes.is_empty()
            && (insn_bytes[0] == 0xC3 || insn_bytes[0] == 0xC2) {
                return Ok(0);
            }

        num_insn += 1;
    }

    Ok(0)
}

// ===========================================================================
// Internal — guard-address fallback
// ===========================================================================

/// Fallback: use the first guarded address to find an IAT reference.
///
/// When Themida writes the OEP and resolved API addresses into `.text`,
/// the code-section guard records these writes.  The first one usually
/// contains a `call rel32` or `jmp rel32` whose target is a resolved API.
/// We read that target and scan for it in the data sections.
pub(super) fn iat_ref_from_guard_addrs(
    debugger: &dyn DebuggerCore,
    guard_addrs: &[usize],
    _text_base: usize,
    _code_size: usize,
    data_section_base: usize,
    data_section_size: usize,
) -> Result<usize, ThemidaError> {
    if guard_addrs.is_empty() {
        return Ok(0);
    }

    // Read 6 bytes from the first guarded address.
    let mut site = [0u8; 6];
    debugger
        .read_memory(guard_addrs[0], &mut site)
        .map_err(|e| ThemidaError::Debugger(format!("guard addr read: {e}")))?;

    info!(
        "Guard addrs count: {}, first guard addr: {:#x}, bytes: {:02X?}",
        guard_addrs.len(),
        guard_addrs[0],
        site
    );

    // Determine the target API address.
    let target: usize = if site[0] == 0xE8 || site[0] == 0xE9 {
        // call/jmp rel32 at byte 0
        let rel32 = i32::from_le_bytes([site[1], site[2], site[3], site[4]]);
        (guard_addrs[0] as i64 + 5 + rel32 as i64) as usize
    } else if site[1] == 0xE8 || site[1] == 0xE9 {
        // call/jmp rel32 at byte 1 (prefixed with something)
        let rel32 = i32::from_le_bytes([site[2], site[3], site[4], site[5]]);
        (guard_addrs[0] as i64 + 6 + rel32 as i64) as usize
    } else {
        warn!(
            "First guard address {:#x} is not a call/jmp — \
             bytes: {:02X?}",
            guard_addrs[0], &site[..]
        );
        return Ok(0);
    };

    info!(
        "First guard addr {:#x} yielded API {target:#x}",
        guard_addrs[0]
    );

    // Scan for this target value in the data section to find an IAT reference.
    scan_data_for_pointer(debugger, target, data_section_base, data_section_size)
}

// ===========================================================================
// Internal — data scanning for pointer values
// ===========================================================================

/// Scan the target's data sections for a specific pointer value.
///
/// This is used as a fallback when we have a resolved API address (e.g. from
/// a guarded call site) and need to find where in the IAT it lives.
///
/// Corresponds to `ThemidaCommon.pas` `DetermineIATAddress.ScanData`.
///
/// The scan is performed in two passes:
/// 1. First scan the data section (typically `.data` / `.rdata`).  The IAT
///    usually lives here.
/// 2. If not found, scan the code section (`.text`) as a last resort —
///    handles extreme section merges in Themida v1.
pub(super) fn scan_data_for_pointer(
    debugger: &dyn DebuggerCore,
    target: usize,
    data_section_base: usize,
    data_section_size: usize,
) -> Result<usize, ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();

    // Pass 1: scan the data section.
    if data_section_size > 0 {
        // Cap the scan size to avoid huge reads — the IAT is usually small.
        let scan_size = data_section_size.min(MAX_IAT_SIZE * 2);
        let mut buf = vec![0u8; scan_size];
        let bytes_read = debugger
            .read_memory(data_section_base, &mut buf)
            .map_err(|e| ThemidaError::Debugger(format!("scan_data read: {e}")))?;

        let slot_count = bytes_read / ptr_size;
        for i in 0..slot_count {
            let offset = i * ptr_size;
            let mut slot_bytes = [0u8; 8];
            let copy_len = ptr_size.min(bytes_read - offset);
            slot_bytes[..copy_len].copy_from_slice(&buf[offset..offset + copy_len]);
            let val = usize::from_le_bytes(slot_bytes);
            if val == target {
                let iat_addr = data_section_base + offset;
                info!("Found IAT reference to {target:#x} at {iat_addr:#x} (data section)");
                return Ok(iat_addr);
            }
        }
    }

    warn!("Data-scan fallback for pointer {target:#x} — not found in data section");
    Ok(0)
}
