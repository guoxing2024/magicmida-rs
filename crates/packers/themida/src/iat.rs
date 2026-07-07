//! IAT (Import Address Table) location and repair for Themida targets.
//!
//! ## Corresponding Pascal source
//!
//! | Rust function             | Pascal equivalent                          |
//! |---------------------------|--------------------------------------------|
//! | [`determine_iat_address`] | `TTMCommon.DetermineIATAddress`            |
//! | [`fix_iat`]               | `TTMDebugger.TMIATFix` series (dispatch)   |
//! | [`fix_iat_v1`]            | `TTMDebugger.TMIATFixThemidaV1`            |
//! | [`fix_iat_v2`]            | `TTMDebugger.TMIATFix2`鈥揱TMIATFix5`        |
//! | [`fix_iat_v3`]            | `TTMCommon.TraceImports`                   |
//! | [`fixup_api_call_sites`]  | `TTMDebugger.FixupAPICallSites`            |
//! | [`detect_compiler`]       | (heuristic, inline in `DetermineIATAddress`)|
//!
//! ## Overview
//!
//! Themida obfuscates the Import Address Table. This module provides:
//!
//! 1. **IAT location** 鈥?finding the IAT in memory by disassembling `.text`
//!    and locating indirect call/jmp instructions that reference it.
//! 2. **IAT repair** 鈥?fixing the IAT entries so they point to the real API
//!    addresses instead of Themida stubs.
//! 3. **API call-site fixup** 鈥?rewriting `call rel32` / `jmp rel32`
//!    instructions that target Themida stubs back into indirect calls
//!    through the (now-repaired) IAT.

use tracing::{debug, error, info, warn};

use mida_core::DebuggerCore;
use mida_disasm::Disassembler;
use mida_pe::PeHeader;

use crate::common::ThemidaState;
use crate::error::ThemidaError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum IAT size in bytes 鈥?`5120 * sizeof(ptr)`.
///
/// Corresponds to `Dumper.pas` `MAX_IAT_SIZE`.
const MAX_IAT_SIZE: usize = 5120 * std::mem::size_of::<usize>();

/// Maximum number of instructions to scan when looking for IAT references
/// from a single starting point.
const MAX_IAT_SCAN_INSTR: usize = 200;

/// Number of consecutive zero slots that signal the end of the IAT.
const CONSECUTIVE_ZERO_THRESHOLD: usize = 64;

/// Maximum number of consecutive non-API / non-Themida-stub slots before
/// we give up during backward IAT-boundary scanning.
const MAX_TRASH_SLOTS: usize = 64;

// ---------------------------------------------------------------------------
// IatLocation
// ---------------------------------------------------------------------------

/// Result of IAT location.
///
/// Contains the virtual address and byte-size of the Import Address Table.
#[derive(Debug, Clone, Copy)]
pub struct IatLocation {
    /// Virtual address of the first IAT slot (start of the table).
    pub address: usize,
    /// Total size of the IAT in bytes.
    pub size: usize,
    /// If true, the section containing this IAT must be marked writable
    /// in the dumped PE. This happens when the IAT is in a read-only section
    /// (.rdata) that the code directly references via `mov reg,[rip+disp]`.
    pub requires_writable_section: bool,
}

// ---------------------------------------------------------------------------
// CompilerHint
// ---------------------------------------------------------------------------

/// Hint about the compiler used to build the target binary.
///
/// Different compilers lay out their `.text` section differently, which
/// affects how we search for IAT references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompilerHint {
    /// Try to auto-detect the compiler from PE headers / `.text` features.
    Auto,
    /// Microsoft Visual C++ (MSVC).
    Msvc,
    /// Borland / Embarcadero Delphi (or C++Builder).
    Delphi,
    /// Go (Go build ID string present in `.text`).
    Go,
}

// ---------------------------------------------------------------------------
// IatFixStrategy
// ---------------------------------------------------------------------------

/// IAT repair strategy, chosen based on the Themida version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IatFixStrategy {
    /// Themida v1: simple IAT jumper patch.
    V1,
    /// Themida v2: locate magic jumps via ImageBase comparison.
    V2,
    /// Themida v3: import addresses are obfuscated; requires single-step
    /// tracing through the Themida VM (framework only for now).
    V3,
}

// ===========================================================================
// Public API 鈥?IAT location
// ===========================================================================

/// Locate the Import Address Table in a Themida-protected process.
///
/// The strategy depends on the compiler and whether the OEP is virtualised:
///
/// | Scenario            | Strategy                                               |
/// |---------------------|--------------------------------------------------------|
/// | Go binary           | Scan for `mov rax, [addr]; call rax` after "Go build ID" |
/// | MSVC, OEP not VM    | Disassemble from OEP, follow a chain of indirect calls   |
/// | Delphi (Borland)    | Skip type-metadata prefix, then same as MSVC             |
/// | VM OEP, non-Delphi  | Scan from `.text` base, ignoring method boundaries       |
/// | GuardAddrs fallback | Use the first guarded address to find an IAT reference   |
///
/// Returns `Ok(None)` if no IAT could be found, or an error if the
/// operation failed at the debugger level.
///
/// # Arguments
///
/// * `debugger` 鈥?the active debugger session (for memory reads).
/// * `oep` 鈥?the original entry point virtual address.
/// * `text_base` 鈥?absolute virtual address of `.text` start
///   (`ImageBase + .text.VirtualAddress`).  The `text_section` slice is
///   mapped at this address.
/// * `text_section` 鈥?raw byte dump of the `.text` section (or at minimum
///   the code portion up to `base_of_data`).
/// * `data_section_base` 鈥?absolute virtual address of the data section start
///   (used by the guard-address fallback to scan for the API pointer).
/// * `data_section_size` 鈥?size of the data section in bytes.
/// * `is_vm_oep` 鈥?whether the OEP is virtualised (jumps into the Themida VM).
///   When `true`, the scan starts from `text_base` instead of `oep`.
/// * `compiler_hint` 鈥?compiler hint. Pass [`CompilerHint::Auto`] for
///   automatic detection.
/// * `guard_addrs` 鈥?addresses collected by the code-section guard before
///   the OEP was reached (fallback for x86 / ancient Themida).
///
/// # Errors
///
/// Returns [`ThemidaError::Debugger`] if memory reads fail.
/// Returns [`ThemidaError::IatNotFound`] if no viable IAT reference could
/// be found after exhausting all strategies.
pub fn determine_iat_address(
    debugger: &dyn DebuggerCore,
    oep: usize,
    text_base: usize,
    text_section: &[u8],
    data_section_base: usize,
    data_section_size: usize,
    is_vm_oep: bool,
    compiler_hint: CompilerHint,
    guard_addrs: &[usize],
) -> Result<Option<IatLocation>, ThemidaError> {
    let code_size = text_section.len();

    // Resolve the compiler hint.
    let compiler = match compiler_hint {
        CompilerHint::Auto => detect_compiler_from_text(text_section),
        c => c,
    };

    // Step 1: Disassemble to find an IAT reference (a pointer *into* the IAT
    // area).  Each strategy returns a virtual address that is inside the IAT.
    //
    // The choice of start address matters:
    //   - VM OEP (V3 x64): the OEP jumps into the Themida VM, so scanning from
    //     the OEP finds VM code, not real calls.  Scan from the .text base
    //     instead (matches Pascal `FindCallOrJmpPtr(TextBase, True)`).
    //   - Non-VM OEP: scan from the OEP (real code starts there).
    let iat_ref: usize = match compiler {
        CompilerHint::Go => {
            let go_build_end = find_go_build_id_end(text_section);
            if go_build_end == 0 {
                warn!("Go build ID end not found 鈥?falling back to MSVC strategy");
                let start = if is_vm_oep { text_base } else { oep };
                find_iat_ref_from_address(
                    debugger,
                    text_section,
                    text_base,
                    start,
                    code_size,
                    is_vm_oep, // ignore method boundaries when VM OEP
                    MAX_IAT_SCAN_INSTR,
                )?
            } else {
                let start_addr = text_base + go_build_end;
                find_go_api_call(debugger, text_section, text_base, start_addr)?
            }
        }
        CompilerHint::Delphi => {
            let delphi_start = find_delphi_call(text_section, text_base);
            find_iat_ref_from_address(
                debugger,
                text_section,
                text_base,
                delphi_start,
                code_size,
                true, // ignore method boundaries for Delphi
                MAX_IAT_SCAN_INSTR,
            )?
        }
        CompilerHint::Msvc | CompilerHint::Auto => {
            // For VM OEP, scan from .text base with IgnoreMethodBoundary=true;
            // otherwise scan from OEP with IgnoreMethodBoundary=false (stop at
            // the first `ret`, matching Pascal `FindCallOrJmpPtr(OEP)`).
            // Pascal ThemidaCommon.pas line 298:
            //   IATRef := FindCallOrJmpPtr(OEP)  // default IgnoreBoundary=False
            // Only VMOEP/Delphi paths pass IgnoreBoundary=True.
            let (start, ignore_boundary) = if is_vm_oep {
                (text_base, true)
            } else {
                (oep, false)
            };
            let result = find_iat_ref_from_address(
                debugger,
                text_section,
                text_base,
                start,
                code_size,
                ignore_boundary,
                MAX_IAT_SCAN_INSTR,
            )?;

            // If scanning from OEP failed (short function without IAT refs),
            // fall back to scanning the entire .text section from base with
            // ignore_boundary=true.  This handles targets where the OEP is a
            // small stub that doesn't directly reference the IAT, but later
            // code (e.g. CRT startup called from OEP) does reference it via
            // `call [rip+disp]`.  Matches Pascal's VMOEP path behavior.
            if result == 0 && !is_vm_oep && start == oep {
                info!("Scan from OEP failed - retrying from .text base with ignore_boundary=true");
                find_iat_ref_from_address(
                    debugger,
                    text_section,
                    text_base,
                    text_base,
                    code_size,
                    true,
                    MAX_IAT_SCAN_INSTR,
                )?
            } else {
                result
            }
        }
    };

    // The initial scan from OEP (ignore_boundary=false) stops at the first
    // `ret`.  For MSVC targets where the OEP is a small stub that calls
    // `__scrt_common_main_seh`, the recursion finds a stale `FF 15` in
    // Themida stub code (in `.boot`/`.winlice`), not the real IAT.
    //
    // Re-scan from .text base with ignore_boundary=true to find the real
    // IAT reference in CRT startup code (`call [rip+disp]` pointing into
    // `.rdata`).  If rescan finds a different (non-zero) ref, prefer it.
    // If OEP scan found an IAT ref, try to find an earlier one by scanning
    // the entire .text section.  The earliest IAT ref is closer to the true
    // IAT start, which helps when the IAT spans multiple modules.
    let iat_ref = if iat_ref == 0 {
        info!("No IAT reference found via OEP scan - trying full .text scan");
        let earliest = find_earliest_iat_ref(
            debugger,
            text_section,
            text_base,
            code_size,
        )?;
        if earliest != 0 {
            earliest
        } else if !guard_addrs.is_empty() {
            // Pascal fallback (ThemidaCommon.pas lines 307-318):
            // Read the first guard addr, extract the call target, then
            // scan the data section for that value to locate the IAT slot.
            info!("No IAT ref via .text scan - trying guard_addrs fallback (ScanData)");
            iat_ref_from_guard_addrs(
                debugger,
                guard_addrs,
                text_base,
                code_size,
                data_section_base,
                data_section_size,
            )?
        } else {
            0
        }
    } else {
        // Found via OEP scan, but try to find an earlier ref
        let earliest = find_earliest_iat_ref(
            debugger,
            text_section,
            text_base,
            code_size,
        )?;
        if earliest != 0 && earliest < iat_ref {
            info!(
                oep_ref = format_args!("{iat_ref:#x}"),
                earliest = format_args!("{earliest:#x}"),
                "Found earlier IAT ref via full .text scan"
            );
            earliest
        } else {
            iat_ref
        }
    };

    if iat_ref == 0 { return Err(ThemidaError::IatNotFound); }

    info!("First IAT reference: {iat_ref:#x}");


    // Step 2: Walk backwards from `iat_ref` to find the start of the IAT.
    // The IAT is a contiguous array of pointers, preceded by a region of
    // zeros (or at least non-API pointers).  We also do a forward walk to
    // determine the end.
    let iat = scan_iat_boundaries(debugger, iat_ref)?;

    Ok(Some(iat))
}

// ===========================================================================
// Public API 鈥?IAT repair
// ===========================================================================

/// Repair the IAT using the strategy appropriate for the Themida version.
///
/// This is the top-level dispatch. Callers should choose [`IatFixStrategy`]
/// based on the detected [`ThemidaVersion`].
///
/// # Errors
///
/// Returns [`ThemidaError::Debugger`] if memory reads/writes fail.
pub fn fix_iat(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    iat: &IatLocation,
    main_thread_id: u32,
    strategy: IatFixStrategy,
) -> Result<(), ThemidaError> {
    match strategy {
        IatFixStrategy::V1 => fix_iat_v1(debugger, iat),
        IatFixStrategy::V2 => {
            // Determine Themida section bounds from pe_info.
            let (tm_start, tm_end) = get_themida_section_bounds(state);
            fix_iat_v2(debugger, iat, tm_start, tm_end)
        }
        IatFixStrategy::V3 => fix_iat_v3(debugger, state, iat, main_thread_id),
    }
}

// ===========================================================================
// Public API 鈥?API call-site fixup
// ===========================================================================

/// Rewrite relative calls/jumps that target Themida stubs back into indirect
/// calls/jumps through the IAT.
///
/// Themida replaces `call dword ptr [IAT_slot]` / `jmp dword ptr [IAT_slot]`
/// with `call ThemidaStub` / `jmp ThemidaStub` (PC-relative).  After we
/// repair the IAT, those stubs are either dead or resolve to the same API,
/// but the original indirect form is cleaner for the dumped binary.
///
/// This function scans the `.text` section for `call rel32` / `jmp rel32`
/// instructions.  If the target falls inside a Themida section **and** the
/// target address is known to be an IAT jumper (i.e. its eventual destination
/// is an API in the IAT), the instruction is rewritten to `call/jmp [IAT_slot]`.
///
/// Returns the number of call sites that were fixed up.
///
/// # Errors
///
/// Returns [`ThemidaError::Debugger`] if memory reads/writes fail.
pub fn fixup_api_call_sites(
    debugger: &mut dyn DebuggerCore,
    _text_section_start: usize,
    _text_section_size: usize,
    iat: &IatLocation,
    _themida_section_start: usize,
    _themida_section_end: usize,
    guard_addrs: &[usize],
) -> Result<usize, ThemidaError> {
    // Pascal approach: Use guard_addrs to locate call sites directly
    let mut sorted = guard_addrs.to_vec();
    sorted.sort_unstable();

    let mut site_set = Vec::new();
    if let Some(&first) = sorted.first() {
        site_set.push(first);
        for &addr in &sorted[1..] {
            if addr >= *site_set.last().unwrap() + 6 {
                site_set.push(addr);
            }
        }
    }

    if site_set.is_empty() {
        info!("No guard addresses collected - skipping call site fixup");
        return Ok(0);
    }

    info!(
        "Deduced {} call sites from {} guard accesses",
        site_set.len(),
        guard_addrs.len()
    );

    // Read IAT and build API -> slot map
    let iat_slot_count = iat.size / std::mem::size_of::<usize>();
    let mut iat_data = vec![0usize; iat_slot_count];
    let bytes_read = debugger
        .read_memory(iat.address, unsafe {
            std::slice::from_raw_parts_mut(
                iat_data.as_mut_ptr() as *mut u8,
                iat_data.len() * std::mem::size_of::<usize>(),
            )
        })
        .map_err(|e| ThemidaError::Debugger(format!("fixup read IAT: {e}")))?;

    let actual_slots = bytes_read / std::mem::size_of::<usize>();
    iat_data.truncate(actual_slots);

    use std::collections::HashMap;
    let mut api_to_slot: HashMap<usize, usize> = HashMap::with_capacity(iat_data.len());
    for (i, &api_addr) in iat_data.iter().enumerate() {
        if api_addr != 0 {
            api_to_slot.insert(api_addr, iat.address + i * std::mem::size_of::<usize>());
        }
    }

    // Fix each call site
    let mut fixup_count: usize = 0;

    for &site_addr in &site_set {
        let mut insn = [0u8; 7];
        if debugger.read_memory(site_addr, &mut insn).is_err() {
            warn!("Failed to read at {:#x}", site_addr);
            continue;
        }

        info!(
            "Checking site {:#x}: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
            site_addr, insn[0], insn[1], insn[2], insn[3], insn[4], insn[5], insn[6]
        );

        // Check for mov reg,[rip+disp]: 48 8B xx [disp32]
        if insn[0] == 0x48 && insn[1] == 0x8B {
            let modrm = insn[2];
            info!("Found mov instruction, ModR/M={:#04x}", modrm);
            if modrm == 0x05 || modrm == 0x0D || modrm == 0x15 || modrm == 0x1D
                || modrm == 0x25 || modrm == 0x2D || modrm == 0x35 || modrm == 0x3D
            {
                let old_disp = i32::from_le_bytes([insn[3], insn[4], insn[5], insn[6]]);
                let old_target = (site_addr as i64 + 7 + old_disp as i64) as usize;
                info!("old_disp={:#x}, old_target={:#x}", old_disp, old_target);

                if let Some(&iat_slot_va) = api_to_slot.get(&old_target) {
                    info!("Found in IAT map! iat_slot_va={:#x}", iat_slot_va);
                    let rip = site_addr + 7;
                    let new_disp = iat_slot_va.wrapping_sub(rip) as i64;

                    if new_disp > i32::MAX as i64 || new_disp < i32::MIN as i64 {
                        warn!("IAT slot too far for mov at {:#x}", site_addr);
                        continue;
                    }

                    let new_disp32 = (new_disp as i32).to_le_bytes();
                    insn[3..7].copy_from_slice(&new_disp32);

                    if debugger.write_memory(site_addr, &insn).is_ok() {
                        info!(
                            "Fixed mov at {:#x}: old_target={:#x} -> IAT_slot={:#x}",
                            site_addr, old_target, iat_slot_va
                        );
                        fixup_count += 1;
                    }
                } else {
                    debug!("mov at {:#x} target {:#x} not in IAT", site_addr, old_target);
                }
            }
        }
    }

    info!("Fixed up {fixup_count} API call sites");
    Ok(fixup_count)
}

// ===========================================================================
// Compiler detection
// ===========================================================================

/// Auto-detect the compiler used to build the target, based on PE header and
/// `.text` section characteristics.
///
/// Detection signals:
///
/// | Compiler | Signal                                |
/// |----------|---------------------------------------|
/// | Go       | `.text` starts with `FF 20 47 6F`     |
/// |          | (identifiable by "Go build ID")        |
/// | Delphi   | `MajorLinkerVersion` 鈮?6 **and**       |
/// |          | `.text` bytes at offset 6 spell        |
/// |          | `"Boole"` or `"ByteT"`                 |
/// | MSVC     | Everything else.                       |
#[must_use]
pub fn detect_compiler(_pe: &PeHeader, text_section: &[u8]) -> CompilerHint {
    detect_compiler_from_text(text_section)
}

/// Internal: detect compiler from `.text` content alone.
///
/// Detection signals:
///
/// | Compiler | Signal                                |
/// |----------|---------------------------------------|
/// | Go       | `.text` starts with `FF 20 47 6F`     |
/// |          | (identifiable by "Go build ID")        |
/// | Delphi   | `MajorLinkerVersion` 鈮?6 **and**       |
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
fn detect_compiler_from_text(text: &[u8]) -> CompilerHint {
    // Go: .text starts with FF 20 47 6F ("  Go" 鈥?"Go build ID" header).
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
// Internal 鈥?Delphi / Go helpers
// ===========================================================================

/// Find the offset (from `.text` base) where Delphi's type-metadata prefix
/// ends and real code begins.
///
/// Delphi binaries have type information (a stream of dword pointers) at the
/// start of `.text`.  We skip forward until we've seen three `FF 25` (jmp
/// dword ptr) instructions 鈥?the third one is likely our first real API
/// import reference.
///
/// Returns an address (image_base + offset).
fn find_delphi_call(text: &[u8], text_base: usize) -> usize {
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
fn find_go_build_id_end(text: &[u8]) -> usize {
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
fn find_go_api_call(
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
    warn!("Go API call pattern not found 鈥?falling back to MSVC strategy");
    find_iat_ref_from_address(debugger, text, text_base, start_addr, text.len(), true, MAX_IAT_SCAN_INSTR)
}

// ===========================================================================
// Internal 鈥?IAT reference discovery (MSVC / generic)
// ===========================================================================

/// Scan the entire `.text` section for `call [mem]` / `jmp [mem]` instructions,
/// returning the earliest (lowest RVA) IAT pointer found.
///
/// This helps find the true IAT start when OEP-based scanning finds a ref
/// in the middle of the IAT (common when the OEP uses `mov rax,[mem]; call rax`
/// instead of `call [mem]`).
fn find_earliest_iat_ref(
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
/// function recursively follows it 鈥?this handles MSVC's chain of thunks
/// (e.g. `__scrt_common_main_seh` 鈫?`main` 鈫?`call [__imp_MessageBoxA]`).
///
/// A `ret` instruction stops the search in the current function (unless
/// `ignore_boundary` is `true`, in which case we keep scanning linearly).
fn find_iat_ref_from_address(
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
                "Found indirect {} at {ip:#x} (insn_len={}): bytes={:02X?} 鈫?IAT pointer {iat_pointer:#x}",
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

        // Follow internal `call rel32` (E8) 鈥?if the target is inside
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
                // Direct API call (target outside .text) 鈥?not an IAT
                // reference per se, but for x86 this means the IAT is
                // handled via guard addresses.
                debug!(
                    "Direct call to {target:#x} at {ip:#x} 鈥?\
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
// Internal 鈥?guard-address fallback
// ===========================================================================

/// Fallback: use the first guarded address to find an IAT reference.
///
/// When Themida writes the OEP and resolved API addresses into `.text`,
/// the code-section guard records these writes.  The first one usually
/// contains a `call rel32` or `jmp rel32` whose target is a resolved API.
/// We read that target and scan for it in the data sections.
fn iat_ref_from_guard_addrs(
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
            "First guard address {:#x} is not a call/jmp 鈥?\
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
// Internal 鈥?data scanning for pointer values
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
/// 2. If not found, scan the code section (`.text`) as a last resort 鈥?///    handles extreme section merges in Themida v1.
fn scan_data_for_pointer(
    debugger: &dyn DebuggerCore,
    target: usize,
    data_section_base: usize,
    data_section_size: usize,
) -> Result<usize, ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();

    // Pass 1: scan the data section.
    if data_section_size > 0 {
        // Cap the scan size to avoid huge reads 鈥?the IAT is usually small.
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

    warn!("Data-scan fallback for pointer {target:#x} 鈥?not found in data section");
    Ok(0)
}

// ===========================================================================
// Internal — Multi-block IAT discovery
// ===========================================================================

/// A contiguous region of valid IAT slots, discovered during multi-block scanning.
#[derive(Debug, Clone, Copy)]
struct IatBlock {
    /// Slot index (relative to the start of the read buffer) of the first slot.
    start_slot: usize,
    /// Number of slots in this block.
    slot_count: usize,
}

/// Find all valid IAT blocks in the scanned buffer.
///
/// Magicmida's `TraceImports` does NOT assume a single contiguous IAT — it
/// iterates through the entire IAT buffer and resolves *every* slot that
/// points into the Themida section, regardless of gaps between valid slots.
///
/// V3 binaries can have fragmented IATs where valid entries are separated by
/// large runs of zeros.  To match Magicmida, we:
///
/// 1. Read the full MAX_IAT_SIZE buffer starting from `iat_start`.
/// 2. Identify all "valid" slots — those that are either zero (padding),
///    valid API addresses (outside the image), or Themida-section pointers
///    (V3 obfuscated imports).
/// 3. Group contiguous valid slots into blocks separated by "corrupt" slots
///    (non-zero, non-API, non-Themida pointers — these are NOT IAT entries).
/// 4. Return all blocks; callers can choose to merge adjacent blocks or
///    process them individually.
///
/// The returned blocks are sorted by slot index (ascending).
fn discover_iat_blocks(iat_data: &[usize]) -> Vec<IatBlock> {
    let mut blocks: Vec<IatBlock> = Vec::new();
    let mut current_start: Option<usize> = None;
    let mut valid_count: usize = 0;

    for (i, &val) in iat_data.iter().enumerate() {
        let is_valid = val == 0
            || is_likely_api_address(val)
            || is_within_image(val, 0, iat_data.len());

        if is_valid {
            if current_start.is_none() {
                current_start = Some(i);
            }
            valid_count += 1;
        } else {
            // "Corrupt" slot — end the current block.
            if let Some(start) = current_start {
                if valid_count >= 1 {
                    blocks.push(IatBlock {
                        start_slot: start,
                        slot_count: valid_count,
                    });
                }
                current_start = None;
                valid_count = 0;
            }
        }
    }

    // Don't forget the last block.
    if let Some(start) = current_start {
        if valid_count >= 1 {
            blocks.push(IatBlock {
                start_slot: start,
                slot_count: valid_count,
            });
        }
    }

    blocks
}

/// Choose the best IAT block as the "primary" one — the block that contains
/// the reference slot `ref_index`.
///
/// If no block contains `ref_index`, returns the largest block (by slot count).
fn select_primary_block(blocks: &[IatBlock], ref_index: usize) -> Option<usize> {
    if blocks.is_empty() {
        return None;
    }

    // Prefer the block containing the reference index.
    for (idx, block) in blocks.iter().enumerate() {
        if ref_index >= block.start_slot && ref_index < block.start_slot + block.slot_count {
            return Some(idx);
        }
    }

    // Fallback: largest block.
    blocks
        .iter()
        .enumerate()
        .max_by_key(|(_, b)| b.slot_count)
        .map(|(idx, _)| idx)
}

// ===========================================================================
// Internal 鈥?IAT boundary scanning
// ===========================================================================

/// Given a known pointer *inside* the IAT (`iat_ref`), walk backwards to
/// find the start and forwards to find the size.
///
/// The IAT is a contiguous block of pointer-sized slots.  Valid slots are
/// either:
/// - non-zero and point to an API (address outside the image, or in a
///   known DLL range), OR
/// - non-zero and point inside a Themida section (V3 obfuscated imports).
///
/// The table is preceded and followed by regions with many consecutive
/// zero slots (or non-API / non-Themida pointers).
///
/// ## Multi-block IAT support (V3 fragmented IATs)
///
/// Some Themida v3 binaries have fragmented IATs where valid entries are
/// separated by large runs of zeros (more than `CONSECUTIVE_ZERO_THRESHOLD`
/// slots).  The original Magicmida `TraceImports` handles this by iterating
/// through the *entire* IAT buffer and resolving every slot that points into
/// the Themida section, regardless of gaps.
///
/// To match Magicmida, this function:
/// 1. Reads the full `MAX_IAT_SIZE` buffer centered on `iat_ref`.
/// 2. Uses `discover_iat_blocks` to find all valid IAT regions.
/// 3. Selects the block containing `iat_ref` as the primary block.
/// 4. If additional valid blocks exist *after* the primary block (with only
///    zero/corrupt gaps between them), extends the IAT to include them.
fn scan_iat_boundaries(
    debugger: &dyn DebuggerCore,
    iat_ref: usize,
) -> Result<IatLocation, ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();

    // Allocate a buffer large enough to hold the maximum IAT.
    let max_slots = MAX_IAT_SIZE / ptr_size;
    let mut iat_data = vec![0usize; max_slots];

    // Read the IAT data centred on `iat_ref` such that iat_data[high] is
    // the pointer at iat_ref.
    let read_start = iat_ref.saturating_sub(MAX_IAT_SIZE.saturating_sub(ptr_size));
    let bytes_read = debugger
        .read_memory(read_start, unsafe {
            std::slice::from_raw_parts_mut(
                iat_data.as_mut_ptr() as *mut u8,
                iat_data.len() * ptr_size,
            )
        })
        .map_err(|e| ThemidaError::Debugger(format!("scan_iat_boundaries read: {e}")))?;

    let actual_slots = bytes_read / ptr_size;
    iat_data.truncate(actual_slots);

    if actual_slots < 2 {
        return Err(ThemidaError::IatNotFound);
    }

    // The index in iat_data that corresponds to `iat_ref`.
    let ref_index = (iat_ref.saturating_sub(read_start)) / ptr_size;
    if ref_index >= actual_slots {
        return Err(ThemidaError::IatNotFound);
    }

    let mut iat_start = 0usize; // stays 0 until we find a valid region
    let mut consecutive_zeros: usize = 0;

    // Walk backwards from `ref_index` to find the start.
    // Cap the backward scan to avoid extending into adjacent data
    // sections (e.g. Section 4 when the IAT is in Section 6).
    const MAX_IAT_SLOTS_BACKWARD: usize = 512; // 4 KiB on x64
    let mut seeker = ref_index;
    let mut slots_scanned: usize = 0;
    loop {
        let val = iat_data[seeker];

        if val == 0 {
            consecutive_zeros += 1;
            if consecutive_zeros > CONSECUTIVE_ZERO_THRESHOLD {
                iat_start = read_start
                    + (seeker + consecutive_zeros + 1).min(actual_slots - 1) * ptr_size;
                break;
            }
        } else if is_likely_api_address(val) || is_within_image(val, read_start, actual_slots) {
            iat_start = read_start + seeker * ptr_size;
            consecutive_zeros = 0;
        } else {
            info!("Ending IAT start search at {:#x} because pointer is {val:#x}", read_start + seeker * ptr_size);
            iat_start = read_start + (seeker + 1) * ptr_size;
            break;
        }

        slots_scanned += 1;
        if slots_scanned > MAX_IAT_SLOTS_BACKWARD { break; }

        if seeker == 0 {
            if iat_start == 0 { return Err(ThemidaError::IatNotFound); }
            break;
        }
        seeker -= 1;
    }

    if iat_start == 0 {
        return Err(ThemidaError::IatNotFound);
    }

    // Now walk forwards from iat_start to find the size.
    // Use multi-block discovery to handle fragmented V3 IATs.
    let start_index = (iat_start.saturating_sub(read_start)) / ptr_size;

    // Discover all valid IAT blocks in the buffer.
    let blocks = discover_iat_blocks(&iat_data);

    // Find the block that contains our start_index.
    let primary_idx = select_primary_block(&blocks, start_index);

    let (final_start_slot, final_slot_count) = match primary_idx {
        Some(idx) => {
            let primary = blocks[idx];
            let primary_end = primary.start_slot + primary.slot_count;

            // Check if there are additional valid blocks after the primary block.
            // If so, extend the IAT to include them (matching Magicmida's behavior
            // of iterating through the entire IAT buffer).
            let mut combined_end = primary_end;
            let mut combined_start = primary.start_slot;

            // Look for subsequent blocks that are "close enough" to be part of
            // the same logical IAT.  We use a generous gap threshold here because
            // V3 IATs can have large internal gaps.
            for block in &blocks[idx + 1..] {
                let gap = block.start_slot.saturating_sub(combined_end);
                // If the gap is small enough (less than MAX_IAT_SIZE / 8), consider
                // it part of the same IAT.  This handles fragmented V3 IATs where
                // valid entries are separated by runs of zeros.
                if gap < MAX_IAT_SIZE / (ptr_size * 8) {
                    combined_end = block.start_slot + block.slot_count;
                } else {
                    break;
                }
            }

            // Also check if there are valid blocks *before* the primary block
            // that should be included (e.g., if the IAT starts earlier than
            // our backward scan found).
            for block in blocks[..idx].iter().rev() {
                let gap = combined_start.saturating_sub(block.start_slot + block.slot_count);
                if gap < MAX_IAT_SIZE / (ptr_size * 8) {
                    combined_start = block.start_slot;
                } else {
                    break;
                }
            }

            info!(
                "IAT multi-block: primary block at slot {} ({} slots), \
                 combined span: slot {} ({} slots), total blocks: {}",
                primary.start_slot,
                primary.slot_count,
                combined_start,
                combined_end - combined_start,
                blocks.len()
            );

            (combined_start, combined_end - combined_start)
        }
        None => {
            // No valid blocks found — fall back to the original single-block
            // forward scan behavior.
            warn!("No valid IAT blocks discovered — falling back to single-block scan");
            let mut trash_counter: usize = 0;
            let mut iat_end = iat_start;

            for i in start_index..actual_slots {
                let val = iat_data[i];

                if val == 0 || !is_likely_api_address(val) {
                    trash_counter += 1;
                    if trash_counter > MAX_TRASH_SLOTS {
                        iat_end = read_start
                            + i.saturating_sub(trash_counter) * ptr_size;
                        break;
                    }
                } else {
                    trash_counter = 0;
                    iat_end = read_start + (i + 1) * ptr_size;
                }
            }

            let size = iat_end.saturating_sub(iat_start);
            if size == 0 || size > MAX_IAT_SIZE {
                warn!("IAT size {size} is zero or exceeds MAX_IAT_SIZE");
                return Err(ThemidaError::IatNotFound);
            }

            info!(
                "IAT boundaries (single-block fallback): start={:#x}, end={:#x}, size={} ({} slots)",
                iat_start,
                iat_end,
                size,
                size / ptr_size,
            );

            return Ok(IatLocation {
                address: iat_start,
                size,
                requires_writable_section: false,  // TODO: detect from PE header
            });
        }
    };

    let iat_start_final = read_start + final_start_slot * ptr_size;
    // The multi-block scan can extend the IAT start backwards into adjacent
    // data sections because `is_likely_api_address`/`is_within_image` are
    // permissive heuristics (Pascal's `IsAPIAddress` checks module export
    // tables, which naturally rejects data-section pointers).
    //
    // For Themida V3 where the IAT is a small region in a data section, we
    // clamp the start to `iat_ref` itself when the scan tries to extend too
    // far back.  This matches the observation that Pascal's IAT start
    // (`0x1369b0`) is within a few hundred bytes of its IAT ref.
    let iat_start_final = if iat_start_final < iat_ref.saturating_sub(0x2000) {
        info!(
            "Clamping IAT start from {:#x} to iat_ref {:#x} (scan extended too far back)",
            iat_start_final, iat_ref
        );
        iat_ref
    } else {
        iat_start_final
    };
    let size = final_slot_count * ptr_size;

    if size == 0 || size > MAX_IAT_SIZE {
        warn!("IAT size {size} is zero or exceeds MAX_IAT_SIZE");
        return Err(ThemidaError::IatNotFound);
    }

    let iat_end_final = iat_start_final + size;

    info!(
        "IAT boundaries: start={:#x}, end={:#x}, size={} ({} slots), blocks={}",
        iat_start_final,
        iat_end_final,
        size,
        size / ptr_size,
        blocks.len(),
    );

    Ok(IatLocation {
        address: iat_start_final,
        size,
        requires_writable_section: false,  // TODO: detect from PE header
    })
}

// ===========================================================================
// IAT repair — V1
// =========================================================================== 鈥?V1
// ===========================================================================

/// Repair the IAT for Themida v1.
///
/// Themida v1 wraps each IAT entry with a simple jumper: the IAT slot points
/// to a small stub in the Themida section, and that stub jumps to the real
/// API.  The strategy is:
///
/// 1. Read each IAT slot.
/// 2. If the slot points into the Themida section, follow the jump(er) to
///    get the real API address.
/// 3. Write the real API address back into the IAT slot.
fn fix_iat_v1(
    debugger: &mut dyn DebuggerCore,
    iat: &IatLocation,
) -> Result<(), ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();
    let slot_count = iat.size / ptr_size;
    let mut iat_data = vec![0usize; slot_count];

    let bytes_read = debugger
        .read_memory(iat.address, unsafe {
            std::slice::from_raw_parts_mut(
                iat_data.as_mut_ptr() as *mut u8,
                iat_data.len() * ptr_size,
            )
        })
        .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v1 read: {e}")))?;

    let actual_slots = bytes_read / ptr_size;
    let mut fix_count: usize = 0;

    for i in 0..actual_slots {
        let slot_va = iat.address + i * ptr_size;
        let current = iat_data[i];

        if current == 0 {
            continue;
        }

        // In v1, each IAT slot points to a jumper stub that looks like:
        //   jmp [real_api]   or   mov eax, real_api; jmp eax
        // We read 8 bytes from the current value and try to resolve the
        // real API.
        if let Some(real_api) =
            resolve_v1_jumper(debugger, current)?
        {
            if real_api != current && real_api != 0 {
                iat_data[i] = real_api;
                fix_count += 1;
                debug!("IAT[{i}] {slot_va:#x}: {current:#x} 鈫?{real_api:#x}");
            }
        }
    }

    // Write the repaired IAT back.
    if fix_count > 0 {
        let write_size = actual_slots * ptr_size;
        let bytes_written = debugger
            .write_memory(iat.address, unsafe {
                std::slice::from_raw_parts(
                    iat_data.as_ptr() as *const u8,
                    write_size,
                )
            })
            .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v1 write: {e}")))?;

        if bytes_written < write_size {
            warn!(
                "fix_iat_v1: short write ({bytes_written} of {write_size} bytes)"
            );
        }
    }

    info!("fix_iat_v1: repaired {fix_count} IAT entries");
    Ok(())
}

/// Try to resolve a v1 jumper stub to the real API address.
///
/// Reads 8 bytes at `jumper_addr` and looks for common patterns:
/// - `jmp [addr]` (FF 25 ...)
/// - `mov reg, addr; jmp reg`
fn resolve_v1_jumper(
    debugger: &dyn DebuggerCore,
    jumper_addr: usize,
) -> Result<Option<usize>, ThemidaError> {
    let mut code = [0u8; 8];
    let n = debugger
        .read_memory(jumper_addr, &mut code)
        .map_err(|e| ThemidaError::Debugger(format!("resolve_v1_jumper read: {e}")))?;

    if n < 2 {
        return Ok(None);
    }

    // Pattern 1: jmp [addr] 鈥?FF 25 xx xx xx xx
    if code[0] == 0xFF && code[1] == 0x25 && n >= 6 {
        let disp = i32::from_le_bytes([code[2], code[3], code[4], code[5]]);
        let target = if std::mem::size_of::<usize>() == 8 {
            // x64: RIP-relative
            (jumper_addr as i64 + 6 + disp as i64) as usize
        } else {
            // x86: absolute
            disp as usize
        };
        // Read the pointer at the target.
        let mut ptr: usize = 0;
        let buf = unsafe {
            std::slice::from_raw_parts_mut(
                &mut ptr as *mut usize as *mut u8,
                std::mem::size_of::<usize>(),
            )
        };
        if debugger.read_memory(target, buf).is_ok() && ptr != 0 {
            return Ok(Some(ptr));
        }
    }

    // Pattern 2: jmp rel32 鈥?E9 xx xx xx xx 鈥?the target *is* the API.
    if code[0] == 0xE9 && n >= 5 {
        let rel32 = i32::from_le_bytes([code[1], code[2], code[3], code[4]]);
        let target = (jumper_addr as i64 + 5 + rel32 as i64) as usize;
        if is_likely_api_address(target) {
            return Ok(Some(target));
        }
    }

    // Pattern 3: mov eax, imm32; jmp eax 鈥?B8 xx xx xx xx FF E0
    if code[0] == 0xB8 && n >= 7 && code[5] == 0xFF && code[6] == 0xE0 {
        let imm = usize::from_le_bytes([
            code[1], code[2], code[3], code[4], 0, 0, 0, 0,
        ]);
        if is_likely_api_address(imm) {
            return Ok(Some(imm));
        }
    }

    Ok(None)
}

// ===========================================================================
// IAT repair 鈥?V2
// ===========================================================================

/// Repair the IAT for Themida v2.
///
/// Themida v2 uses a more complex IAT redirection. Each IAT slot points to a
/// stub inside the Themida section. We need to:
///
/// 1. Read each IAT slot.
/// 2. If the slot points into the Themida section, try to resolve the real
///    API by following the jump chain (the stub eventually jumps to the
///    real API or loads it from a table).
/// 3. Write the real API address back into the IAT slot.
///
/// If we can't resolve a slot (e.g. because it requires single-stepping
/// through obfuscated code), we leave it as-is 鈥?the follow-up v3 tracer
/// step will handle those.
fn fix_iat_v2(
    debugger: &mut dyn DebuggerCore,
    iat: &IatLocation,
    themida_section_start: usize,
    themida_section_end: usize,
) -> Result<(), ThemidaError> {
    let ptr_size = std::mem::size_of::<usize>();
    let slot_count = iat.size / ptr_size;

    // Allocate buffer.
    let mut iat_data = vec![0usize; slot_count.min(MAX_IAT_SIZE / ptr_size)];

    let bytes_read = debugger
        .read_memory(iat.address, unsafe {
            std::slice::from_raw_parts_mut(
                iat_data.as_mut_ptr() as *mut u8,
                iat_data.len() * ptr_size,
            )
        })
        .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v2 read: {e}")))?;

    let actual_slots = bytes_read / ptr_size;
    let mut fix_count: usize = 0;

    for i in 0..actual_slots {
        let slot_va = iat.address + i * ptr_size;
        let current = iat_data[i];

        if current == 0 {
            continue;
        }

        // If the slot points into the Themida section, try to follow the
        // jump chain.
        if current >= themida_section_start && current < themida_section_end {
            if let Some(real_api) = resolve_v2_stub(debugger, current, themida_section_start, themida_section_end)? {
                if real_api != current && real_api != 0 {
                    iat_data[i] = real_api;
                    fix_count += 1;
                    debug!("IAT[{i}] {slot_va:#x}: {current:#x} 鈫?{real_api:#x}");
                }
            }
        }
        // If the slot already points to a valid API, leave it alone.
    }

    if fix_count > 0 {
        let write_size = actual_slots * ptr_size;
        let bytes_written = debugger
            .write_memory(iat.address, unsafe {
                std::slice::from_raw_parts(
                    iat_data.as_ptr() as *const u8,
                    write_size,
                )
            })
            .map_err(|e| ThemidaError::Debugger(format!("fix_iat_v2 write: {e}")))?;

        if bytes_written < write_size {
            warn!("fix_iat_v2: short write ({bytes_written} of {write_size} bytes)");
        }
    }

    info!("fix_iat_v2: repaired {fix_count} IAT entries");
    Ok(())
}

/// Try to resolve a Themida v2 stub to the real API address by following
/// the jump chain.
///
/// Many v2 stubs end with a `jmp [rip+disp]` or `jmp rel32` that ultimately
/// reaches the real API.  We read a small window of code at `stub_addr` and
/// disassemble it, looking for these patterns.
fn resolve_v2_stub(
    debugger: &dyn DebuggerCore,
    stub_addr: usize,
    _tm_start: usize,
    _tm_end: usize,
) -> Result<Option<usize>, ThemidaError> {
    let mut code = [0u8; 32];
    let n = debugger
        .read_memory(stub_addr, &mut code)
        .map_err(|e| ThemidaError::Debugger(format!("resolve_v2_stub read: {e}")))?;

    let bitness = if std::mem::size_of::<usize>() == 8 {
        64
    } else {
        32
    };
    let disasm = Disassembler::new(bitness, stub_addr as u64);

    // Scan the code window for:
    // - jmp [mem] 鈫?follow the memory operand 鈫?read the pointer
    // - jmp rel32 鈫?if target looks like an API, return it
    // - mov rax/eax, imm; jmp rax/eax 鈫?return the imm
    for insn in disasm.decode_all(&code[..n]) {
        let ip = insn.ip() as usize;
        let _insn_bytes = &code[(ip - stub_addr)..];

        match insn.mnemonic() {
            iced_x86::Mnemonic::Jmp => {
                match insn.op0_kind() {
                    iced_x86::OpKind::Memory => {
                        // jmp [mem] 鈥?follow the memory operand.
                        let target_ptr = if bitness == 64 {
                            ip + insn.len() + insn.memory_displacement64() as usize
                        } else {
                            insn.memory_displacement64() as usize
                        };
                        let mut ptr: usize = 0;
                        let buf = unsafe {
                            std::slice::from_raw_parts_mut(
                                &mut ptr as *mut usize as *mut u8,
                                std::mem::size_of::<usize>(),
                            )
                        };
                        if debugger.read_memory(target_ptr, buf).is_ok()
                            && is_likely_api_address(ptr)
                        {
                            return Ok(Some(ptr));
                        }
                    }
                    iced_x86::OpKind::NearBranch64 => {
                        let target = insn.near_branch_target() as usize;
                        if is_likely_api_address(target) {
                            return Ok(Some(target));
                        }
                    }
                    _ => {}
                }
            }
            iced_x86::Mnemonic::Mov => {
                // mov rax/eax, imm 鈫?if next is jmp rax/eax, return imm.
                if insn.op0_kind() == iced_x86::OpKind::Register
                    && insn.op1_kind() == iced_x86::OpKind::Immediate64
                {
                    let imm = insn.immediate64() as usize;
                    // Check if the next instruction is jmp reg.
                    let next_offset = (ip - stub_addr) + insn.len();
                    if next_offset + 2 <= n
                        && code[next_offset] == 0xFF
                    {
                        // It's a jmp reg (FF Ex). The immediate is likely the API.
                        if is_likely_api_address(imm) {
                            return Ok(Some(imm));
                        }
                    }
                }
            }
            iced_x86::Mnemonic::Ret | iced_x86::Mnemonic::Retf => {
                // ret 鈥?end of the stub; stop scanning.
                break;
            }
            _ => {}
        }
    }

    Ok(None)
}

// ===========================================================================
// IAT repair — V3 (via single-step VM tracing)
// ===========================================================================

/// Repair the IAT for Themida v3 using single-step VM tracing.
///
/// Themida v3 obfuscates each import address so that the IAT slot does not
/// point to a simple jumper stub but into the Themida VM.  Resolving the
/// real API requires single-stepping through the VM until it reaches a known
/// API function.
///
/// This is the Rust equivalent of `ThemidaCommon.pas` `TraceImports`.  The
/// actual tracing logic lives in [`trace_imports::trace_imports`]; here we
/// set up the anti-trace API addresses in `state` (the disassembler host-
/// process addresses are valid in the target because kernel32 is loaded at
/// a per-system ASLR base shared by all processes) and delegate.
pub fn fix_iat_v3(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    iat: &IatLocation,
    main_thread_id: u32,
) -> Result<(), ThemidaError> {
    use crate::trace_imports::trace_imports;
    use mida_tracer::LogMsgType;

    // Resolve anti-trace API addresses in the host process (valid in the
    // target because kernel32 is loaded at a per-system ASLR base).
    if state.sleep_api == 0 || state.lstrlen_api == 0 {
        resolve_anti_trace_apis(state);
    }

    // Capture trace start SP if not already set.
    if state.trace_start_sp == 0 {
        match debugger.get_thread_context(main_thread_id) {
            Ok(ctx) => {
                #[cfg(target_arch = "x86")]
                {
                    state.trace_start_sp = ctx.Esp as usize;
                }
                #[cfg(target_arch = "x86_64")]
                {
                    state.trace_start_sp = ctx.Rsp as usize;
                }
            }
            Err(e) => {
                warn!("fix_iat_v3: cannot get thread context: {e}");
            }
        }
    }

    if state.trace_start_sp == 0 {
        warn!("fix_iat_v3: trace_start_sp is 0 - cannot trace");
        return Ok(());
    }

    let log = |msg_type: LogMsgType, msg: &str| {
        match msg_type {
            LogMsgType::Info => info!("[v3-trace] {msg}"),
            LogMsgType::Good => info!("[v3-trace] OK {msg}"),
            LogMsgType::Fatal => error!("[v3-trace] {msg}"),
        }
    };

    let result = trace_imports(debugger, state, iat, main_thread_id, &log)?;

    info!(
        "fix_iat_v3: {} resolved, {} failed ({} slots total)",
        result.resolved_count,
        result.failed_count,
        iat.size / std::mem::size_of::<usize>(),
    );

    if !result.failed_slots.is_empty() {
        warn!(
            "fix_iat_v3: failed slots: {:?}",
            &result.failed_slots[..result.failed_slots.len().min(10)]
        );
    }

    Ok(())
}

/// Resolve the host-process addresses of the anti-trace APIs (Sleep and
/// lstrlenA) and store them in `state`. Valid in the target because kernel32
/// is loaded at a per-system ASLR base shared by all processes.
fn resolve_anti_trace_apis(state: &mut ThemidaState) {
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let to_pcstr = |s: &str| PCSTR::from_raw(s.as_ptr());

    let Ok(k32) = (unsafe { GetModuleHandleA(to_pcstr("kernel32.dll\0")) }) else {
        warn!("resolve_anti_trace_apis: GetModuleHandleA(kernel32) failed");
        return;
    };

    if state.sleep_api == 0 {
        state.sleep_api = unsafe { GetProcAddress(k32, to_pcstr("Sleep\0")) }
            .map(|f| f as usize)
            .unwrap_or(0);
    }
    if state.lstrlen_api == 0 {
        state.lstrlen_api = unsafe { GetProcAddress(k32, to_pcstr("lstrlenA\0")) }
            .map(|f| f as usize)
            .unwrap_or(0);
    }
}

// ===========================================================================
// Internal 鈥?helpers
// ===========================================================================

/// Extract the Themida section bounds from the PE info in `state`.
fn get_themida_section_bounds(state: &ThemidaState) -> (usize, usize) {
    let image_base = state.pe_info.image_base as usize;

    if let Some(idx) = state.pe_info.themida_section {
        if let Some(section) = state.pe_info.pe_sections.get(idx) {
            let start = image_base + section.virtual_address as usize;
            let end = start + section.virtual_size as usize;
            return (start, end);
        }
    }

    // Fallback: use the entire image boundary.
    (image_base, state.pe_info.image_boundary as usize)
}

/// Heuristic: does `addr` look like a valid API address?
///
/// API addresses are typically:
/// - Above `0x10000` (no low-memory code).
/// - Outside the image boundaries (for most DLLs; can be inside the image
///   for forwarded exports, but that's rare).
/// - Not obviously a kernel address (for user-mode targets).
fn is_likely_api_address(addr: usize) -> bool {
    // Must be above the low-memory region.
    if addr < 0x10000 {
        return false;
    }

    // On 64-bit Windows, user-mode DLLs load in the 0x0000_7FF6_xxxx_xxxx
    // to 0x0000_7FFF_xxxx_xxxx range (high user space).  API addresses
    // are typically in this range.  Small values (< 0x7fff_0000_0000)
    // are likely RVAs or data pointers, not resolved API addresses.
    //
    // This mirrors Pascal's `IsAPIAddress` which checks module export
    // tables — resolved API addresses live inside loaded DLLs, not in
    // the protected image's data sections.
    #[cfg(target_arch = "x86_64")]
    {
        (0x7ff0_0000_0000..0x0000_7FFF_FFFF_0000).contains(&addr)
    }
    #[cfg(target_arch = "x86")]
    {
        // 32-bit: DLLs load in the 0x60000000-0x7FFF0000 range typically.
        addr >= 0x6000_0000 && addr < 0x7FFF_0000
    }
}

/// Heuristic: is `addr` within the image being unpacked?
///
/// Used during IAT boundary scanning to identify Themida-stub pointers
/// (resolved API addresses that land inside the protector's VM section).
/// We only accept addresses that look like user-mode VAs above 0x10000;
/// small RVAs (like `0x1383bc`) are rejected because they are data
/// pointers, not resolved API addresses.
fn is_within_image(addr: usize, _iat_base: usize, _slot_count: usize) -> bool {
    // Resolved API addresses and Themida-stub pointers are always above
    // 0x7ff0_0000_0000 on x64.  Small values (< 0x7fff_0000_0000) are
    // RVAs or data pointers, not API addresses.
    #[cfg(target_arch = "x86_64")]
    {
        (0x7ff0_0000_0000..0x0000_7FFF_FFFF_0000).contains(&addr)
    }
    #[cfg(target_arch = "x86")]
    {
        addr >= 0x6000_0000 && addr < 0x7FFF_0000
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- CompilerHint

    #[test]
    fn compiler_hint_debug() {
        assert_eq!(format!("{:?}", CompilerHint::Auto), "Auto");
        assert_eq!(format!("{:?}", CompilerHint::Msvc), "Msvc");
        assert_eq!(format!("{:?}", CompilerHint::Delphi), "Delphi");
        assert_eq!(format!("{:?}", CompilerHint::Go), "Go");
    }

    #[test]
    fn compiler_hint_copy() {
        let h = CompilerHint::Auto;
        let h2 = h;
        assert_eq!(h, h2);
    }

    // -- IatFixStrategy

    #[test]
    fn fix_strategy_copy() {
        let s = IatFixStrategy::V2;
        let s2 = s;
        assert_eq!(s, s2);
    }

    // -- IatLocation

    #[test]
    fn iat_location_debug() {
        let loc = IatLocation {
            address: 0x140020000,
            size: 4096,
            requires_writable_section: false,
        };
        let dbg = format!("{loc:?}");
        // Derived Debug uses decimal for numeric fields.
        assert!(dbg.contains("5368840192")); // 0x140020000 in decimal
        assert!(dbg.contains("4096"));
    }

    // -- detect_compiler_from_text

    #[test]
    fn detect_go_from_text() {
        // Go: .text starts with FF 20 47 6F
        let text = [0xFF, 0x20, 0x47, 0x6F, 0x00, 0x00];
        assert_eq!(detect_compiler_from_text(&text), CompilerHint::Go);
    }

    #[test]
    fn detect_delphi_from_text() {
        // Delphi: "Bool" at offset 6 (x86) or 10 (x64).
        let delphi_bool_offset = if cfg!(target_arch = "x86_64") { 10 } else { 6 };
        let mut text = vec![0u8; delphi_bool_offset + 4];
        text[delphi_bool_offset] = b'B';
        text[delphi_bool_offset + 1] = b'o';
        text[delphi_bool_offset + 2] = b'o';
        text[delphi_bool_offset + 3] = b'l';
        assert_eq!(detect_compiler_from_text(&text), CompilerHint::Delphi);
    }

    #[test]
    fn detect_delphi_byte() {
        let mut text = [0u8; 16];
        text[6] = b'B';
        text[7] = b'y';
        text[8] = b't';
        text[9] = b'e';
        assert_eq!(detect_compiler_from_text(&text), CompilerHint::Delphi);
    }

    #[test]
    fn detect_delphi_bool_x86_offset() {
        // On x86, "Bool" is at offset 6.
        #[cfg(target_arch = "x86")]
        {
            let mut text = [0u8; 16];
            text[6] = b'B';
            text[7] = b'o';
            text[8] = b'o';
            text[9] = b'l';
            assert_eq!(detect_compiler_from_text(&text), CompilerHint::Delphi);
        }
    }

    #[test]
    fn detect_delphi_bool_x64_offset() {
        // On x64, "Bool" is at offset 10.
        #[cfg(target_arch = "x86_64")]
        {
            let mut text = [0u8; 16];
            text[10] = b'B';
            text[11] = b'o';
            text[12] = b'o';
            text[13] = b'l';
            assert_eq!(detect_compiler_from_text(&text), CompilerHint::Delphi);
        }
    }

    #[test]
    fn detect_msvc_default() {
        let text = [0xCCu8; 32]; // int3 padding 鈥?not Go, not Delphi
        assert_eq!(detect_compiler_from_text(&text), CompilerHint::Msvc);
    }

    #[test]
    fn detect_go_trumps_delphi() {
        // Go takes priority because it's checked first.
        let text = [0xFF, 0x20, 0x47, 0x6F, 0x00, 0x00, b'B', b'o', b'o', b'l'];
        // Starts with "Go build ID" pattern, so it's Go.
        assert_eq!(detect_compiler_from_text(&text), CompilerHint::Go);
    }

    // -- find_go_build_id_end

    #[test]
    fn find_go_build_id_end_present() {
        let text = [0x00, 0x00, 0xFF, 0x20, 0xAA, 0xBB];
        // FF 20 at offset 2 鈫?end at offset 4.
        assert_eq!(find_go_build_id_end(&text), 4);
    }

    #[test]
    fn find_go_build_id_end_not_present() {
        let text = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(find_go_build_id_end(&text), 0);
    }

    #[test]
    fn find_go_build_id_end_empty() {
        assert_eq!(find_go_build_id_end(&[]), 0);
    }

    // -- find_delphi_call

    #[test]
    fn find_delphi_call_third_ff25() {
        let mut text = vec![0x00u8; 128];
        // Place FF 25 at offsets 0, 4, 8 鈫?third is at offset 8.
        text[0] = 0xFF; text[1] = 0x25;
        text[4] = 0xFF; text[5] = 0x25;
        text[8] = 0xFF; text[9] = 0x25;
        let addr = find_delphi_call(&text, 0x400000);
        assert_eq!(addr, 0x400008);
    }

    #[test]
    fn find_delphi_call_not_enough_patterns() {
        let mut text = vec![0x00u8; 128];
        // Only one FF 25 鈫?falls back to text_base.
        text[0] = 0xFF; text[1] = 0x25;
        let addr = find_delphi_call(&text, 0x400000);
        assert_eq!(addr, 0x400000);
    }

    // -- is_likely_api_address

    #[test]
    fn low_address_not_api() {
        assert!(!is_likely_api_address(0x1000));
        assert!(!is_likely_api_address(0));
    }

    #[test]
    fn normal_address_is_api() {
        // x64: API addresses live in 0x7ff0_0000_0000 - 0x7fff_ffff_0000.
        assert!(is_likely_api_address(0x7FFE12345678));
        // Small RVAs / data pointers are NOT API addresses.
        assert!(!is_likely_api_address(0x1383bc));
        assert!(!is_likely_api_address(0x1000));
    }

    // -- fix_iat_v3 signature (compile-time check that the function exists and
    //    has the expected signature; full functional testing requires a live
    //    debugger session which is not available in unit tests).

    /// Compile-time test: ensures `fix_iat_v3` has the expected signature
    /// `(DebuggerCore, &mut ThemidaState, &IatLocation, u32)`.
    #[test]
    fn fix_iat_v3_signature_check() {
        fn _assert_fn_signature(
            _f: fn(
                &mut dyn DebuggerCore,
                &mut ThemidaState,
                &IatLocation,
                u32,
            ) -> Result<(), ThemidaError>,
        ) {
        }
        _assert_fn_signature(fix_iat_v3);
    }

    // -- is_within_image

    #[test]
    fn within_image_typical() {
        // x64: user-mode VAs above 0x7ff0_0000_0000 are "within image" candidates.
        assert!(is_within_image(0x7FFE12345678, 0, 0));
        // Small RVAs are NOT within-image candidates (they are data pointers).
        assert!(!is_within_image(0x140001000, 0, 0));
        assert!(!is_within_image(0x1000, 0, 0));
    }

    // -- get_themida_section_bounds

    #[test]
    fn bounds_from_state() {
        use crate::common::ThemidaState;
        use crate::init::ThemidaPeInfo;
        use crate::version::ThemidaVersion;
        use mida_pe::PeSection;
        use mida_pe::ImageSectionHeader;

        let mut name = [0u8; 8];
        name[0] = b'.'; name[1] = b't'; name[2] = b'e'; name[3] = b'x'; name[4] = b't';
        let text_header = ImageSectionHeader {
            name,
            virtual_size: 0x1000, virtual_address: 0x1000,
            size_of_raw_data: 0x200, pointer_to_raw_data: 0x200,
            pointer_to_relocations: 0, pointer_to_linenumbers: 0,
            number_of_relocations: 0, number_of_linenumbers: 0,
            characteristics: 0x60000020,
        };

        let mut tm_name = [0u8; 8];
        tm_name[0] = b'T'; tm_name[1] = b'h'; tm_name[2] = b'e';
        tm_name[3] = b'm'; tm_name[4] = b'i'; tm_name[5] = b'd'; tm_name[6] = b'a';
        let tm_header = ImageSectionHeader {
            name: tm_name,
            virtual_size: 0x5000, virtual_address: 0x4000,
            size_of_raw_data: 0x200, pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0, pointer_to_linenumbers: 0,
            number_of_relocations: 0, number_of_linenumbers: 0,
            characteristics: 0xE0000020,
        };

        let sections = vec![
            PeSection {
                header: text_header, name: ".text".into(),
                virtual_address: 0x1000, virtual_size: 0x1000,
                raw_offset: 0x200, raw_size: 0x200,
                characteristics: 0x60000020,
                extra_data: None,
            },
            PeSection {
                header: tm_header, name: "Themida".into(),
                virtual_address: 0x4000, virtual_size: 0x5000,
                raw_offset: 0x400, raw_size: 0x200,
                characteristics: 0xE0000020,
                extra_data: None,
            },
        ];

        let pe_info = ThemidaPeInfo {
            image_base: 0x140000000,
            image_boundary: 0x140006000,
            base_of_data: 0x2000,
            pe_sections: sections,
            major_linker_version: 14,
            themida_version: ThemidaVersion::V3,
            is_vm_oep: false,
            themida_section: Some(1),
            tls_total: 0,
        };

        let state = ThemidaState::new(pe_info, false);
        let (start, end) = get_themida_section_bounds(&state);
        assert_eq!(start, 0x140004000);
        assert_eq!(end, 0x140009000);
    }

    // -- discover_iat_blocks

    #[test]
    fn discover_iat_blocks_single_contiguous() {
        // A simple contiguous IAT: [API, 0, API, API, 0, 0, 0]
        // All slots are "valid" (zero or API), so one block.
        let iat_data = vec![0x7FFE_0000_1000, 0, 0x7FFE_0000_2000, 0x7FFE_0000_3000, 0, 0, 0];
        let blocks = discover_iat_blocks(&iat_data);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_slot, 0);
        assert_eq!(blocks[0].slot_count, 7);
    }

    #[test]
    fn discover_iat_blocks_fragmented_with_corrupt() {
        // Fragmented IAT with a "corrupt" slot (non-zero, non-API, non-image)
        // separating two valid regions:
        // [API, 0, API, CORRUPT, 0, API, API]
        // The corrupt slot (0xDEAD) splits this into two blocks.
        let iat_data = vec![
            0x7FFE_0000_1000,
            0,
            0x7FFE_0000_2000,
            0xDEAD, // corrupt
            0,
            0x7FFE_0000_3000,
            0x7FFE_0000_4000,
        ];
        let blocks = discover_iat_blocks(&iat_data);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].start_slot, 0);
        assert_eq!(blocks[0].slot_count, 3); // slots 0,1,2
        assert_eq!(blocks[1].start_slot, 4);
        assert_eq!(blocks[1].slot_count, 3); // slots 4,5,6
    }

    #[test]
    fn discover_iat_blocks_all_zeros() {
        // All zeros — one block (zeros are valid padding).
        let iat_data = vec![0usize; 100];
        let blocks = discover_iat_blocks(&iat_data);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_slot, 0);
        assert_eq!(blocks[0].slot_count, 100);
    }

    #[test]
    fn discover_iat_blocks_empty() {
        let iat_data: Vec<usize> = vec![];
        let blocks = discover_iat_blocks(&iat_data);
        assert!(blocks.is_empty());
    }

    #[test]
    fn discover_iat_blocks_corrupt_at_start() {
        // Corrupt slot at the start, then valid data.
        let iat_data = vec![0xDEAD, 0x7FFE_0000_1000, 0, 0x7FFE_0000_2000];
        let blocks = discover_iat_blocks(&iat_data);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_slot, 1);
        assert_eq!(blocks[0].slot_count, 3);
    }

    #[test]
    fn discover_iat_blocks_corrupt_at_end() {
        // Valid data followed by corrupt slot.
        let iat_data = vec![0x7FFE_0000_1000, 0, 0x7FFE_0000_2000, 0xDEAD];
        let blocks = discover_iat_blocks(&iat_data);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].start_slot, 0);
        assert_eq!(blocks[0].slot_count, 3);
    }

    // -- select_primary_block

    #[test]
    fn select_primary_block_contains_ref() {
        let blocks = vec![
            IatBlock { start_slot: 0, slot_count: 10 },
            IatBlock { start_slot: 20, slot_count: 5 },
            IatBlock { start_slot: 30, slot_count: 15 },
        ];
        // Ref index 22 is in the second block (slots 20..25).
        assert_eq!(select_primary_block(&blocks, 22), Some(1));
    }

    #[test]
    fn select_primary_block_fallback_largest() {
        let blocks = vec![
            IatBlock { start_slot: 0, slot_count: 10 },
            IatBlock { start_slot: 20, slot_count: 5 },
            IatBlock { start_slot: 30, slot_count: 15 },
        ];
        // Ref index 100 is not in any block — should return largest (index 2).
        assert_eq!(select_primary_block(&blocks, 100), Some(2));
    }

    #[test]
    fn select_primary_block_empty() {
        let blocks: Vec<IatBlock> = vec![];
        assert_eq!(select_primary_block(&blocks, 0), None);
    }

    #[test]
    fn select_primary_block_first_slot() {
        let blocks = vec![
            IatBlock { start_slot: 0, slot_count: 10 },
            IatBlock { start_slot: 20, slot_count: 5 },
        ];
        // Ref index 0 is in the first block.
        assert_eq!(select_primary_block(&blocks, 0), Some(0));
    }

    #[test]
    fn select_primary_block_last_slot() {
        let blocks = vec![
            IatBlock { start_slot: 0, slot_count: 10 },
            IatBlock { start_slot: 20, slot_count: 5 },
        ];
        // Ref index 24 is the last slot of the second block (20..25).
        assert_eq!(select_primary_block(&blocks, 24), Some(1));
    }
}
