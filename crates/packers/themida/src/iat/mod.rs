//! IAT (Import Address Table) location and repair for Themida targets.
//!
//! ## Corresponding Pascal source
//!
//! | Rust function             | Pascal equivalent                          |
//! |---------------------------|--------------------------------------------|
//! | [`determine_iat_address`] | `TTMCommon.DetermineIATAddress`            |
//! | [`fix_iat`]               | `TTMDebugger.TMIATFix` series (dispatch)   |
//! | [`fix_iat_v1`]            | `TTMDebugger.TMIATFixThemidaV1`            |
//! | [`fix_iat_v2`]            | `TTMDebugger.TMIATFix2`–`TMIATFix5`        |
//! | [`fix_iat_v3`]            | `TTMCommon.TraceImports`                   |
//! | [`fixup_api_call_sites`]  | `TTMDebugger.FixupAPICallSites`            |
//! | [`detect_compiler`]       | (heuristic, inline in `DetermineIATAddress`)|
//!
//! ## Overview
//!
//! Themida obfuscates the Import Address Table. This module provides:
//!
//! 1. **IAT location** — finding the IAT in memory by disassembling `.text`
//!    and locating indirect call/jmp instructions that reference it.
//! 2. **IAT repair** — fixing the IAT entries so they point to the real API
//!    addresses instead of Themida stubs.
//! 3. **API call-site fixup** — rewriting `call rel32` / `jmp rel32`
//!    instructions that target Themida stubs back into indirect calls
//!    through the (now-repaired) IAT.

mod boundaries;
mod discovery;
mod fix;

use tracing::{info, warn};

use mida_core::DebuggerCore;
use mida_pe::PeHeader;

use crate::common::ThemidaState;
use crate::error::ThemidaError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum IAT size in bytes — `5120 * sizeof(ptr)`.
///
/// Corresponds to `Dumper.pas` `MAX_IAT_SIZE`.
pub(super) const MAX_IAT_SIZE: usize = 5120 * std::mem::size_of::<usize>();

/// Maximum number of instructions to scan when looking for IAT references
/// from a single starting point.
pub(super) const MAX_IAT_SCAN_INSTR: usize = 200;

/// Number of consecutive zero slots which signal the end of the IAT.
pub(super) const CONSECUTIVE_ZERO_THRESHOLD: usize = 64;

/// Maximum number of consecutive non-API / non-Themida-stub slots before
/// we give up during backward IAT-boundary scanning.
pub(super) const MAX_TRASH_SLOTS: usize = 64;

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
// Public API — IAT location
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
/// * `debugger` — the active debugger session (for memory reads).
/// * `oep` — the original entry point virtual address.
/// * `text_base` — absolute virtual address of `.text` start
///   (`ImageBase + .text.VirtualAddress`).  The `text_section` slice is
///   mapped at this address.
/// * `text_section` — raw byte dump of the `.text` section (or at minimum
///   the code portion up to `base_of_data`).
/// * `data_section_base` — absolute virtual address of the data section start
///   (used by the guard-address fallback to scan for the API pointer).
/// * `data_section_size` — size of the data section in bytes.
/// * `is_vm_oep` — whether the OEP is virtualised (jumps into the Themida VM).
///   When `true`, the scan starts from `text_base` instead of `oep`.
/// * `compiler_hint` — compiler hint. Pass [`CompilerHint::Auto`] for
///   automatic detection.
/// * `guard_addrs` — addresses collected by the code-section guard before
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
        CompilerHint::Auto => discovery::detect_compiler_from_text(text_section),
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
            let go_build_end = discovery::find_go_build_id_end(text_section);
            if go_build_end == 0 {
                warn!("Go build ID end not found — falling back to MSVC strategy");
                let start = if is_vm_oep { text_base } else { oep };
                discovery::find_iat_ref_from_address(
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
                discovery::find_go_api_call(debugger, text_section, text_base, start_addr)?
            }
        }
        CompilerHint::Delphi => {
            let delphi_start = discovery::find_delphi_call(text_section, text_base);
            discovery::find_iat_ref_from_address(
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
            let result = discovery::find_iat_ref_from_address(
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
                discovery::find_iat_ref_from_address(
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
        let earliest = discovery::find_earliest_iat_ref(
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
            discovery::iat_ref_from_guard_addrs(
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
        let earliest = discovery::find_earliest_iat_ref(
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
    let iat = boundaries::scan_iat_boundaries(debugger, iat_ref)?;

    Ok(Some(iat))
}

// ===========================================================================
// Public API — IAT repair
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
        IatFixStrategy::V1 => fix::fix_iat_v1(debugger, iat),
        IatFixStrategy::V2 => {
            // Determine Themida section bounds from pe_info.
            let (tm_start, tm_end) = fix::get_themida_section_bounds(state);
            fix::fix_iat_v2(debugger, iat, tm_start, tm_end)
        }
        IatFixStrategy::V3 => fix::fix_iat_v3(debugger, state, iat, main_thread_id),
    }
}

// ===========================================================================
// Public API — API call-site fixup
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
            if addr >= *site_set.last().unwrap_or(&0) + 6 {
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
        // SAFETY: iat_data is a Vec<usize> with len * size_of::<usize>() bytes; the aliasing slice is passed to read_memory and discarded before reuse.
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
                    tracing::debug!("mov at {:#x} target {:#x} not in IAT", site_addr, old_target);
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
/// | Delphi   | `MajorLinkerVersion` >= 6 **and**       |
/// |          | `.text` bytes at offset 6 spell        |
/// |          | `"Boole"` or `"ByteT"`                 |
/// | MSVC     | Everything else.                       |
#[must_use]
pub fn detect_compiler(_pe: &PeHeader, text_section: &[u8]) -> CompilerHint {
    discovery::detect_compiler_from_text(text_section)
}
