//! Themida v3 import tracing via single-step execution.
//!
//! ## Overview
//!
//! Themida v3 obfuscates each IAT slot so that it no longer points directly to
//! a real API but instead into the Themida VM.  The VM code deobfuscates the
//! true API address at runtime (via xor + subtraction) and then jumps to it.
//!
//! Because the entire deobfuscation logic is itself virtualised, we cannot
//! extract the API addresses through static analysis.  Instead we single-step
//! through the stub for each IAT slot until the instruction pointer leaves the
//! Themida section — at which point we know we've reached the real API.
//!
//! ## Modules
//!
//! - [`decision`] — pure decision logic (`TraceStepDecision`, `trace_is_at_api`).
//! - [`slot`] — the core single-slot trace loop (`trace_one_slot`).

mod decision;
mod slot;

// Re-export public API items used by external callers (lib.rs re-exports these
// further).
pub use decision::{trace_is_at_api, TraceStepDecision};
// is_real_api_address is only used internally by tests but keep it accessible.
#[cfg(test)]
pub(crate) use decision::is_real_api_address;

use mida_core::debugger::{DebugEvent, DebuggerCore};
use mida_tracer::LogMsgType;

use crate::common::ThemidaState;
use crate::error::ThemidaError;
use crate::iat::IatLocation;

// ---------------------------------------------------------------------------
// Architecture helpers
// ---------------------------------------------------------------------------

/// Pointer size in the target.
#[cfg(target_arch = "x86")]
pub(crate) const PTR_SIZE: usize = 4;
#[cfg(target_arch = "x86_64")]
pub(crate) const PTR_SIZE: usize = 8;

/// Read the instruction pointer from a `CONTEXT`.
#[cfg(target_arch = "x86")]
pub(crate) fn instr_ptr(ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT) -> usize {
    ctx.Eip as usize
}
#[cfg(target_arch = "x86_64")]
pub(crate) fn instr_ptr(ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT) -> usize {
    ctx.Rip as usize
}

/// Read the stack pointer from a `CONTEXT`.
#[cfg(target_arch = "x86")]
pub(crate) fn stack_ptr(ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT) -> usize {
    ctx.Esp as usize
}
#[cfg(target_arch = "x86_64")]
pub(crate) fn stack_ptr(ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT) -> usize {
    ctx.Rsp as usize
}

/// Set the instruction pointer in a `CONTEXT`.
#[cfg(target_arch = "x86")]
pub(crate) fn set_instr_ptr(ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT, val: usize) {
    ctx.Eip = val as u32;
}
#[cfg(target_arch = "x86_64")]
pub(crate) fn set_instr_ptr(ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT, val: usize) {
    ctx.Rip = val as u64;
}

/// Set the stack pointer in a `CONTEXT`.
#[cfg(target_arch = "x86")]
pub(crate) fn set_stack_ptr(ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT, val: usize) {
    ctx.Esp = val as u32;
}
#[cfg(target_arch = "x86_64")]
pub(crate) fn set_stack_ptr(ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT, val: usize) {
    ctx.Rsp = val as u64;
}

/// Set the trap flag (TF, bit 8 of EFlags) in a `CONTEXT`.
pub(crate) fn set_trap_flag(ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT) {
    ctx.EFlags |= 0x100;
}

// ---------------------------------------------------------------------------
// VM signature constants
// ---------------------------------------------------------------------------

/// Themida VM entry signature: first 4 bytes of "lock cmpxchg [rbx+rbp], ecx"
/// or "lock cmpxchg [ebx+ebp], ecx".  Same 4-byte prefix for both x86 and x64.
const THEMIDA_VM_PATTERN: [u8; 4] = [0xF0, 0x0F, 0xB1, 0x0C];

/// Check whether the instruction at `ip` is the Themida VM entry.
pub fn is_at_themida_vm(debugger: &dyn DebuggerCore, ip: usize) -> bool {
    let mut buf = [0u8; 4];
    match debugger.read_memory(ip, &mut buf) {
        Ok(n) if n >= 4 => buf == THEMIDA_VM_PATTERN,
        _ => false,
    }
}

/// Maximum number of consecutive invalid/zero IAT slots before we give up
/// and assume we've reached the end of the table.
const TRASH_THRESHOLD: usize = 64;

/// Default single-step limit per IAT slot.  The Pascal reference uses 500 000.
/// We use a much smaller limit to avoid hanging on difficult slots.
pub const TRACE_LIMIT: u64 = 500_000;

// ---------------------------------------------------------------------------
// TraceImportResult
// ---------------------------------------------------------------------------

/// Result of a v3 IAT trace pass.
#[derive(Debug)]
pub struct TraceImportResult {
    /// Number of IAT slots that were successfully resolved.
    pub resolved_count: usize,
    /// Number of IAT slots that could not be resolved.
    pub failed_count: usize,
    /// Zero-based indices of the slots that failed.
    pub failed_slots: Vec<usize>,
}

// ===========================================================================
// Public API
// ===========================================================================

/// Trace and resolve every obfuscated IAT slot for a Themida v3 target.
///
/// This is the top-level entry point.  It corresponds to
/// `TTMCommon.TraceImports` in `ThemidaCommon.pas`.
///
/// # How it works
///
/// 1. Reads the entire IAT into a local buffer.
/// 2. For each slot whose value falls inside the Themida section, it starts a
///    single-step trace from that address.
/// 3. The trace runs until the predicate signals completion, the instruction
///    limit is hit, or the VM is entered.
/// 4. Resolved API addresses are written back into the IAT buffer.
/// 5. The buffer is flushed to the target process.
///
/// # Arguments
///
/// * `debugger` — active debug session (for memory R/W and thread context).
/// * `state` — mutable unpacker state (`traced_api`, `trace_start_sp`, etc.).
/// * `iat` — location of the Import Address Table in the target.
/// * `main_thread_id` — ID of the main (only) thread in the debuggee.
/// * `log` — log callback (same signature as `mida_tracer::LogMsgType`).
///
/// # Errors
///
/// Returns [`ThemidaError::Debugger`] if memory read/write or context
/// operations fail at the OS level.
pub fn trace_imports(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    iat: &IatLocation,
    main_thread_id: u32,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<TraceImportResult, ThemidaError> {
    let ptr_size = PTR_SIZE;
    let slot_count = iat.size / ptr_size;

    // Read the entire IAT into a local buffer.
    let mut iat_data = vec![0usize; slot_count];
    let bytes_read = debugger
        .read_memory(
            iat.address,
            // SAFETY: iat_data is a Vec<usize>; the aliasing slice covers len * ptr_size bytes and is discarded after read_memory.
            unsafe {
                std::slice::from_raw_parts_mut(
                    iat_data.as_mut_ptr() as *mut u8,
                    iat_data.len() * ptr_size,
                )
            },
        )
        .map_err(|e| ThemidaError::Debugger(format!("trace_imports read IAT: {e}")))?;
    let actual_slots = bytes_read / ptr_size;
    iat_data.truncate(actual_slots);

    // Resolve Themida section bounds using the ACTUAL image base (ASLR-reloaded).
    let actual_image_base = debugger.image_base() as usize;
    let pe_image_base = state.pe_info.image_base as usize;
    let image_delta = actual_image_base.wrapping_sub(pe_image_base);

    let (tm_start, tm_end) = get_themida_section_bounds(state, actual_image_base);
    let image_base = actual_image_base;
    let image_boundary = state.pe_info.image_boundary as usize + image_delta;

    let mut resolved_count: usize = 0;
    let mut failed_count: usize = 0;
    let mut failed_slots: Vec<usize> = Vec::new();
    let mut trash_counter: usize = 0;
    let mut did_set_exit_process: bool = false;

    log(
        LogMsgType::Info,
        &format!(
            "Starting IAT trace: {} slots, IAT at {:#x}, Themida section: {:#x}-{:#x}, image: {:#x}-{:#x}",
            actual_slots, iat.address, tm_start, tm_end, image_base, image_boundary
        ),
    );

    for i in 0..actual_slots {
        let slot_va = iat.address + i * ptr_size;
        let current = iat_data[i];

        if i < 5 {
            let in_themida = current >= tm_start && current < tm_end;
            let in_image = current >= image_base && current < image_boundary;
            log(
                LogMsgType::Info,
                &format!(
                    "IAT slot {i}: value={current:#x}, in_themida={in_themida}, in_image={in_image}"
                ),
            );
        }

        let in_themida = current >= tm_start && current < tm_end;

        if !in_themida || current == 0 {
            trash_counter += 1;
            if trash_counter > TRASH_THRESHOLD {
                log(
                    LogMsgType::Info,
                    &format!("Trash threshold ({TRASH_THRESHOLD}) exceeded at slot {i} — stopping IAT trace"),
                );
                break;
            }
            continue;
        }

        log(
            LogMsgType::Info,
            &format!("Tracing IAT slot {i} ({slot_va:#x}) from {current:#x}"),
        );
        trash_counter = 0;

        if debugger.get_thread_context(main_thread_id).is_err() {
            log(
                LogMsgType::Info,
                &"Debug session ended — skipping remaining IAT slots".to_string(),
            );
            break;
        }

        state.traced_api = 0;
        state.trace_in_vm = false;

        match slot::trace_one_slot(
            debugger,
            state,
            current as u64,
            main_thread_id,
            tm_start,
            tm_end,
            image_base,
            image_boundary,
            log,
        ) {
            Ok(()) => {
                if state.trace_in_vm {
                    if !did_set_exit_process {
                        did_set_exit_process = true;
                        let real_exit_process = resolve_exit_process();
                        iat_data[i] = real_exit_process;
                        resolved_count += 1;
                        log(
                            LogMsgType::Info,
                            &format!("IAT[{i}] {slot_va:#x}: VM entry → ExitProcess ({real_exit_process:#x})"),
                        );
                    } else {
                        failed_count += 1;
                        failed_slots.push(i);
                        log(
                            LogMsgType::Fatal,
                            &format!("IAT[{i}] {slot_va:#x}: trace entered VM — giving up"),
                        );
                    }
                } else if state.traced_api != 0 {
                    let api = state.traced_api;

                    if api < 0x10000 || (api >= image_base && api < image_boundary) {
                        log(
                            LogMsgType::Info,
                            &format!(
                                "IAT[{i}] {slot_va:#x}: discarding result {api:#x} \
                                 (in image range or too low), aborting IAT tracing"
                            ),
                        );
                        break;
                    }

                    iat_data[i] = api;
                    resolved_count += 1;
                    log(
                        LogMsgType::Good,
                        &format!("IAT[{i}] {slot_va:#x}: {current:#x} → {api:#x}"),
                    );
                } else {
                    failed_count += 1;
                    failed_slots.push(i);
                    log(
                        LogMsgType::Fatal,
                        &format!("IAT[{i}] {slot_va:#x}: tracing completed but no API resolved"),
                    );
                }
            }
            Err(e) => {
                failed_count += 1;
                failed_slots.push(i);
                log(
                    LogMsgType::Fatal,
                    &format!("IAT[{i}] {slot_va:#x}: tracer error: {e}"),
                );
            }
        }
    }

    // Write the repaired IAT back to the target.
    if resolved_count > 0 {
        let write_size = actual_slots * ptr_size;
        let bytes_written = debugger
            .write_memory(
                iat.address,
                // SAFETY: iat_data is a Vec<usize>; the aliasing immutable slice covers exactly write_size bytes and is discarded after write_memory.
                unsafe {
                    std::slice::from_raw_parts(iat_data.as_ptr() as *const u8, write_size)
                },
            )
            .map_err(|e| ThemidaError::Debugger(format!("trace_imports write IAT: {e}")))?;

        if bytes_written < write_size {
            log(
                LogMsgType::Info,
                &format!("trace_imports: short write ({bytes_written} of {write_size} bytes)"),
            );
        }
    }

    log(
        LogMsgType::Good,
        &format!(
            "IAT trace complete: {} resolved, {} failed",
            resolved_count, failed_count
        ),
    );

    Ok(TraceImportResult {
        resolved_count,
        failed_count,
        failed_slots,
    })
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Extract the Themida section bounds from the PE info in `state`.
///
/// Returns the bounds of ALL Themida sections combined (min start, max end).
///
/// `actual_image_base` is the ASLR-reloaded image base (from the
/// CREATE_PROCESS debug event), which may differ from the PE header's
/// `ImageBase` field.
pub(crate) fn get_themida_section_bounds(state: &ThemidaState, actual_image_base: usize) -> (usize, usize) {
    let pe_image_base = state.pe_info.image_base as usize;
    let image_delta = actual_image_base.wrapping_sub(pe_image_base);

    let mut min_start = usize::MAX;
    let mut max_end = 0;
    let mut found = false;

    for section in &state.pe_info.pe_sections {
        if crate::version::is_themida_section(section) {
            let start = actual_image_base + section.virtual_address as usize;
            let end = start + section.virtual_size as usize;
            min_start = min_start.min(start);
            max_end = max_end.max(end);
            found = true;
        }
    }

    if found {
        (min_start, max_end)
    } else {
        (actual_image_base, state.pe_info.image_boundary as usize + image_delta)
    }
}

/// Resolve the real `kernel32!ExitProcess` address for the **target** process.
///
/// ExitProcess is a special case: Themida v3 sometimes resolves it to a VM
/// internal function rather than the true Windows API.  When the trace hits
/// the VM, we assume the first such slot is ExitProcess and replace it with
/// the real address.
///
/// **Note:** this uses `GetProcAddress` in the *debugger* process.  Because
/// kernel32.dll is a known DLL loaded at the same base across all processes
/// in a session, the returned address is also valid in the target process.
fn resolve_exit_process() -> usize {
    // SAFETY: GetModuleHandleA / GetProcAddress are always available on
    // Windows. The returned address is valid in the target because kernel32
    // is a known DLL loaded at a fixed base per session.
    unsafe {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        let kernel32 = GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0".as_ptr()))
            .unwrap_or_else(|_| panic!("resolve_exit_process: kernel32.dll must be loaded"));
        let addr = GetProcAddress(kernel32, PCSTR::from_raw(b"ExitProcess\0".as_ptr()))
            .unwrap_or_else(|| panic!("resolve_exit_process: ExitProcess must exist in kernel32"));
        addr as usize
    }
}

/// Extract the thread ID from any [`DebugEvent`] variant.
///
/// Every variant except [`DebugEvent::ExitProcess`] carries a thread ID.
pub(crate) fn thread_id_of(ev: &DebugEvent) -> u32 {
    match ev {
        DebugEvent::Breakpoint { thread_id, .. }
        | DebugEvent::SingleStep { thread_id, .. }
        | DebugEvent::AccessViolation { thread_id, .. }
        | DebugEvent::CreateThread { thread_id, .. }
        | DebugEvent::ExitThread { thread_id, .. }
        | DebugEvent::LoadDll { thread_id, .. }
        | DebugEvent::UnloadDll { thread_id, .. }
        | DebugEvent::CreateProcess { thread_id, .. }
        | DebugEvent::Other { thread_id } => *thread_id,
        DebugEvent::ExitProcess { .. } => 0,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- TraceImportResult

    #[test]
    fn trace_import_result_debug() {
        let r = TraceImportResult {
            resolved_count: 42,
            failed_count: 3,
            failed_slots: vec![5, 10, 15],
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("42"));
        assert!(dbg.contains("3"));
        assert!(dbg.contains("5"));
    }

    // -- VM pattern constants

    #[test]
    fn vm_pattern_has_correct_length() {
        assert_eq!(THEMIDA_VM_PATTERN.len(), 4);
    }

    // -- get_themida_section_bounds

    #[test]
    fn bounds_from_state() {
        use crate::common::ThemidaState;
        use crate::init::ThemidaPeInfo;
        use crate::version::ThemidaVersion;
        use mida_pe::ImageSectionHeader;
        use mida_pe::PeSection;

        let mut name = [0u8; 8];
        name[0] = b'.';
        name[1] = b't';
        name[2] = b'e';
        name[3] = b'x';
        name[4] = b't';
        let text_header = ImageSectionHeader {
            name,
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x200,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x60000020,
        };

        let mut tm_name = [0u8; 8];
        tm_name[0] = b'T';
        tm_name[1] = b'h';
        tm_name[2] = b'e';
        tm_name[3] = b'm';
        tm_name[4] = b'i';
        tm_name[5] = b'd';
        tm_name[6] = b'a';
        let tm_header = ImageSectionHeader {
            name: tm_name,
            virtual_size: 0x5000,
            virtual_address: 0x4000,
            size_of_raw_data: 0x200,
            pointer_to_raw_data: 0x400,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0xE0000020,
        };

        let sections = vec![
            PeSection {
                header: text_header,
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x200,
                raw_size: 0x200,
                characteristics: 0x60000020,
                extra_data: None,
            },
            PeSection {
                header: tm_header,
                name: "Themida".into(),
                virtual_address: 0x4000,
                virtual_size: 0x5000,
                raw_offset: 0x400,
                raw_size: 0x200,
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
        let actual_image_base = 0x140000000;
        let (start, end) = get_themida_section_bounds(&state, actual_image_base);
        assert_eq!(start, 0x140004000);
        assert_eq!(end, 0x140009000);
    }

    #[test]
    fn bounds_fallback_no_themida_section() {
        use crate::common::ThemidaState;
        use crate::init::ThemidaPeInfo;
        use crate::version::ThemidaVersion;

        let pe_info = ThemidaPeInfo {
            image_base: 0x400000,
            image_boundary: 0x500000,
            base_of_data: 0x2000,
            pe_sections: Vec::new(),
            major_linker_version: 14,
            themida_version: ThemidaVersion::V3,
            is_vm_oep: false,
            themida_section: None,
            tls_total: 0,
        };

        let state = ThemidaState::new(pe_info, false);
        let actual_image_base = 0x400000;
        let (start, end) = get_themida_section_bounds(&state, actual_image_base);
        assert_eq!(start, 0x400000);
        assert_eq!(end, 0x500000);
    }
}
