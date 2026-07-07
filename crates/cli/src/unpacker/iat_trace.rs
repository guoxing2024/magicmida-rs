//! In-loop IAT tracing for Themida v3 targets.
//!
//! For v3 targets, IAT values point into the Themida VM.  We single-step
//! through the VM code within the debug loop to resolve real API addresses.
//!
//! - [`IatTraceState`] — tracks per-session IAT tracing state.
//! - [`handle_trace_step`] — handles a `SINGLE_STEP` event during tracing.
//! - [`advance_to_next_slot`] — moves to the next IAT slot.

use anyhow::{anyhow, Context};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

use mida_core::{ContinueStatus, DebuggerCore};
use mida_packers_themida::{trace_is_at_api, TraceStepDecision};

use crate::log::{self, LogType};
use super::session::{ProcessSession, get_thread_context_control, set_thread_context_control};

// ---------------------------------------------------------------------------
// IatTraceState
// ---------------------------------------------------------------------------

/// State for IAT tracing within the debug loop.
///
/// For Themida v3 targets, the IAT values point to VM code.  We need to
/// single-step through the VM code to resolve the real API addresses.
/// This is done within the debug loop so that `ContinueDebugEvent` works
/// correctly.
#[derive(Debug)]
pub(super) struct IatTraceState {
    pub(super) iat_address: usize,
    #[allow(dead_code)]
    iat_size: usize,
    pub(super) current_slot: usize,
    pub(super) total_slots: usize,
    pub(super) slot_values: Vec<usize>,
    themida_start: usize,
    themida_end: usize,
    image_base: usize,
    image_boundary: usize,
    trash_counter: usize,
    did_set_exit_process: bool,
    pub(super) resolved_count: usize,
    pub(super) failed_count: usize,
    pub(super) failed_slots: Vec<usize>,
    pub(super) trace_thread_id: u32,
    trace_start_sp: usize,
    pub(super) trace_phase: TracePhase,
    trace_counter: u64,
    traced_api: usize,
    trace_in_vm: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TracePhase {
    Idle,
    Tracing,
}

impl IatTraceState {
    pub(super) fn new(
        iat_address: usize,
        iat_size: usize,
        slot_values: Vec<usize>,
        themida_start: usize,
        themida_end: usize,
        image_base: usize,
        image_boundary: usize,
        trace_thread_id: u32,
        trace_start_sp: usize,
    ) -> Self {
        let total_slots = slot_values.len();
        Self {
            iat_address,
            iat_size,
            current_slot: 0,
            total_slots,
            slot_values,
            themida_start,
            themida_end,
            image_base,
            image_boundary,
            trash_counter: 0,
            did_set_exit_process: false,
            resolved_count: 0,
            failed_count: 0,
            failed_slots: Vec::new(),
            trace_thread_id,
            trace_start_sp,
            trace_phase: TracePhase::Idle,
            trace_counter: 0,
            traced_api: 0,
            trace_in_vm: false,
        }
    }
}

// ---------------------------------------------------------------------------
// handle_trace_step
// ---------------------------------------------------------------------------

/// Handle a single step event during IAT tracing.
///
/// Optimized version: reduces kernel call overhead and logging frequency
/// to improve tracing performance on large IAT tables.
pub(super) fn handle_trace_step(
    dbg: &mut ProcessSession,
    trace: &mut IatTraceState,
    _address: u64,
    _image_base: usize,
    _image_boundary: usize,
) -> Result<(), anyhow::Error> {
    use mida_packers_themida::trace_imports::{is_at_themida_vm, TRACE_LIMIT};

    trace.trace_counter += 1;

    if trace.trace_counter > TRACE_LIMIT {
        log::log(LogType::Info, &format!("Giving up trace slot {} due to instruction limit ({}/{})", trace.current_slot, trace.trace_counter, TRACE_LIMIT));
        trace.failed_count += 1;
        trace.failed_slots.push(trace.current_slot);
        advance_to_next_slot(dbg, trace)?;
        return Ok(());
    }

    if trace.trace_counter.is_multiple_of(5000) {
        log::log(LogType::Info, &format!("Trace step {} (limit {})", trace.trace_counter, TRACE_LIMIT));
    }

    let ctx = get_thread_context_control(dbg, trace.trace_thread_id)?;
    let ip = ctx.Rip as usize;
    let sp = ctx.Rsp as usize;

    if trace.trace_counter.is_multiple_of(50000) {
        log::log(LogType::Info, &format!("Trace step {}: IP={:#x}, SP={:#x}", trace.trace_counter, ip, sp));
    }

    let is_vm_entry = is_at_themida_vm(dbg as &mut dyn DebuggerCore, ip);
    let (sleep_api, lstrlen_api) = dbg.apis.as_ref().map(|a| (a.sleep, a.lstrlen)).unwrap_or((0, 0));

    let mut ret_addr = 0usize;
    if sp < trace.trace_start_sp {
        let mut ret_bytes = [0u8; 8];
        if dbg.read_memory(sp, &mut ret_bytes).is_ok() {
            ret_addr = u64::from_le_bytes(ret_bytes) as usize;
        }
    }

    match trace_is_at_api(
        ip,
        sp,
        trace.trace_start_sp,
        trace.trace_counter,
        trace.themida_start,
        trace.themida_end,
        trace.image_base,
        trace.image_boundary,
        sleep_api,
        lstrlen_api,
        is_vm_entry,
        ret_addr,
    ) {
        TraceStepDecision::HitVm { ip: vm_ip } => {
            trace.trace_in_vm = true;
            log::log(LogType::Info, &format!("Trace ran into VM at {vm_ip:#x}"));
            handle_trace_result(dbg, trace)?;
            Ok(())
        }
        TraceStepDecision::SkipAntiTraceApi { ip: api_ip, ret_addr: target_ip } => {
            let mut new_ctx = ctx;
            new_ctx.Rip = target_ip as u64;
            new_ctx.Rsp += 8;
            new_ctx.EFlags |= 0x100;
            set_thread_context_control(dbg, trace.trace_thread_id, &new_ctx)?;
            dbg.continue_event(trace.trace_thread_id, ContinueStatus::Continue)?;
            log::log(LogType::Info, &format!("Skipping anti-trace API at {api_ip:#x}"));
            Ok(())
        }
        TraceStepDecision::FoundApi { ip: api_ip } => {
            trace.traced_api = api_ip;
            handle_trace_result(dbg, trace)?;
            Ok(())
        }
        TraceStepDecision::Continue => {
            let mut new_ctx = ctx;
            new_ctx.EFlags |= 0x100;
            set_thread_context_control(dbg, trace.trace_thread_id, &new_ctx)?;
            dbg.continue_event(trace.trace_thread_id, ContinueStatus::Continue)?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// handle_trace_result
// ---------------------------------------------------------------------------

fn handle_trace_result(dbg: &mut ProcessSession, trace: &mut IatTraceState) -> Result<(), anyhow::Error> {
    if trace.trace_in_vm {
        if !trace.did_set_exit_process {
            trace.did_set_exit_process = true;
            // SAFETY: kernel32.dll is always loaded; the byte literal is null-terminated and lives for the call duration.
            let real_exit_process = unsafe {
                use windows::core::PCSTR;
                use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
                let k32 = GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0".as_ptr()))
                    .context("kernel32.dll must be loaded")?;
                let addr = GetProcAddress(k32, PCSTR::from_raw(b"ExitProcess\0".as_ptr()))
                    .context("ExitProcess must exist in kernel32")?;
                addr as usize
            };
            trace.slot_values[trace.current_slot] = real_exit_process;
            trace.resolved_count += 1;
            log::log(LogType::Good, &format!("IAT[{}] VM → ExitProcess", trace.current_slot));
        } else {
            trace.failed_count += 1;
            trace.failed_slots.push(trace.current_slot);
        }
    } else if trace.traced_api != 0 {
        let api = trace.traced_api;
        if api < 0x10000 || (api >= trace.image_base && api < trace.image_boundary) {
            trace.current_slot = trace.total_slots;
            return Ok(());
        }
        trace.slot_values[trace.current_slot] = api;
        trace.resolved_count += 1;
        log::log(LogType::Good, &format!("IAT[{}] → {api:#x}", trace.current_slot));
    } else {
        trace.failed_count += 1;
        trace.failed_slots.push(trace.current_slot);
    }

    advance_to_next_slot(dbg, trace)
}

// ---------------------------------------------------------------------------
// advance_to_next_slot
// ---------------------------------------------------------------------------

/// Advance to the next IAT slot that needs tracing, or write the resolved
/// IAT back to the target if all slots are done.
pub(super) fn advance_to_next_slot(dbg: &mut ProcessSession, trace: &mut IatTraceState) -> Result<(), anyhow::Error> {
    trace.current_slot += 1;
    trace.traced_api = 0;
    trace.trace_in_vm = false;
    trace.trace_counter = 0;

    while trace.current_slot < trace.total_slots {
        let current = trace.slot_values[trace.current_slot];
        let in_themida = current >= trace.themida_start && current < trace.themida_end;
        let is_real_api = current >= 0x10000 && !in_themida
            && !(current >= trace.image_base && current < trace.image_boundary);

        // Skip null terminators - they're normal IAT structure, not trash
        if current == 0 {
            trace.current_slot += 1;
            continue;
        }

        // Skip already-resolved APIs (real API addresses in system DLLs)
        if is_real_api {
            trace.trash_counter = 0;
            trace.current_slot += 1;
            continue;
        }

        // Found a Themida VM entry - trace it
        if in_themida {
            trace.trash_counter = 0;
            break;
        }

        // Skip program-internal addresses (not imports)
        let in_image = current >= trace.image_base && current < trace.image_boundary;
        if in_image {
            trace.trash_counter = 0;
            trace.current_slot += 1;
            continue;
        }

        // Unknown/invalid value - count as trash
        trace.trash_counter += 1;
        if trace.trash_counter > 64 {
            trace.current_slot = trace.total_slots;
            return Ok(());
        }
        trace.current_slot += 1;
    }

    if trace.current_slot >= trace.total_slots {
        log::log(LogType::Good, &format!("IAT trace complete: {} resolved, {} failed", trace.resolved_count, trace.failed_count));
        if trace.resolved_count > 0 {
            let write_size = trace.total_slots * std::mem::size_of::<usize>();
            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            // SAFETY: dbg.process_handle() is a valid process handle; trace.iat_address and write_size are valid IAT bounds; old_protect is a valid out-pointer.
            unsafe {
                VirtualProtectEx(
                    dbg.process_handle(),
                    trace.iat_address as *const std::ffi::c_void,
                    write_size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            }
            .map_err(|e| anyhow!("VirtualProtectEx failed for IAT: {e}"))?;

            // SAFETY: dbg.process_handle() is a valid process handle; trace.iat_address and write_size are valid IAT bounds; old_protect is a valid out-pointer.
            dbg.write_memory(trace.iat_address, unsafe {
                std::slice::from_raw_parts(trace.slot_values.as_ptr() as *const u8, write_size)
            })?;

            let mut _restored = PAGE_PROTECTION_FLAGS::default();
            // SAFETY: dbg.process_handle() is a valid process handle; trace.iat_address and write_size are valid IAT bounds; old_protect is a valid out-pointer.
            unsafe {
                VirtualProtectEx(
                    dbg.process_handle(),
                    trace.iat_address as *const std::ffi::c_void,
                    write_size,
                    old_protect,
                    &mut _restored,
                )
            }
            .ok();
        }
        return Ok(());
    }

    let current = trace.slot_values[trace.current_slot];
    log::log(LogType::Info, &format!("Tracing IAT slot {} from {current:#x}", trace.current_slot));

    let mut ctx = match get_thread_context_control(dbg, trace.trace_thread_id) {
        Ok(ctx) => ctx,
        Err(e) => {
            log::log(LogType::Fatal, &format!("get_thread_context_control failed: {e} - skipping slot"));
            trace.failed_count += 1;
            trace.failed_slots.push(trace.current_slot);
            trace.current_slot += 1;
            return advance_to_next_slot(dbg, trace);
        }
    };
    log::log(LogType::Info, &format!("Got thread context (CONTROL), RIP={:#x}", ctx.Rip));

    ctx.Rip = current as u64;
    ctx.Rsp = trace.trace_start_sp as u64;
    ctx.EFlags |= 0x100;

    log::log(LogType::Info, &format!("Setting thread context: RIP={current:#x}, RSP={:#x}", ctx.Rsp));
    if let Err(e) = set_thread_context_control(dbg, trace.trace_thread_id, &ctx) {
        log::log(LogType::Fatal, &format!("set_thread_context_control failed: {e} - skipping slot"));
        trace.failed_count += 1;
        trace.failed_slots.push(trace.current_slot);
        trace.current_slot += 1;
        return advance_to_next_slot(dbg, trace);
    }
    trace.trace_phase = TracePhase::Tracing;
    log::log(LogType::Info, "Thread context set, continuing...");
    if let Err(e) = dbg.continue_event(trace.trace_thread_id, ContinueStatus::Continue) {
        log::log(LogType::Fatal, &format!("continue_event failed: {e} - aborting tracing"));
        trace.current_slot = trace.total_slots;
        return Ok(());
    }
    log::log(LogType::Info, "Thread continued, waiting for SingleStep");
    Ok(())
}
