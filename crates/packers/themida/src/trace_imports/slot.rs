//! Single-slot trace loop — the core single-step execution that follows one
//! IAT slot through the Themida VM until a real API is reached.
//!
//! Contains: [`trace_one_slot`].

use tracing::debug;

use mida_core::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
use mida_tracer::LogMsgType;

use crate::common::ThemidaState;
use crate::error::ThemidaError;

use super::{
    TRACE_LIMIT, is_at_themida_vm, instr_ptr, set_instr_ptr, set_stack_ptr, set_trap_flag,
    stack_ptr, thread_id_of, PTR_SIZE,
};
use super::decision::{trace_is_at_api, TraceStepDecision};

/// Run the single-step trace for one IAT slot.
///
/// This is the core trace loop, structured identically to
/// `Tracer.pas` `TTracer.Trace`, but with the `TraceIsAtAPI` logic
/// inlined so that both `debugger` and `state` are accessible without
/// borrow-checker conflicts.
///
/// On exit, `state.traced_api` holds the resolved address (if the trace was
/// successful) or `state.trace_in_vm` is set to `true` (if we hit the VM).
///
/// # Returns
///
/// - `Ok(())` — trace completed (check `state.traced_api` and
///   `state.trace_in_vm` for the result).
/// - `Err(...)` — an OS-level debugger error occurred.
pub(crate) fn trace_one_slot(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    start_address: u64,
    thread_id: u32,
    themida_section_start: usize,
    themida_section_end: usize,
    image_base: usize,
    image_boundary: usize,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<(), ThemidaError> {
    let mut counter: u64 = 0;
    let limit: u64 = TRACE_LIMIT;

    // ---- Set up the initial context ----------------------------------------
    let mut ctx = debugger
        .get_thread_context(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("trace_one_slot get_thread_context: {e}")))?;

    state.trace_start_sp = stack_ptr(&ctx);

    set_instr_ptr(&mut ctx, start_address as usize);
    set_trap_flag(&mut ctx);

    debugger
        .set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("trace_one_slot set_thread_context: {e}")))?;

    // Resume from the event that brought us here.
    debugger
        .continue_event(thread_id, ContinueStatus::Continue)
        .map_err(|e| ThemidaError::Debugger(format!("trace_one_slot continue: {e}")))?;

    // ---- Event loop --------------------------------------------------------
    loop {
        let ev = debugger
            .wait_event()
            .map_err(|e| ThemidaError::Debugger(format!("trace_one_slot wait: {e}")))?;

        let event_thread_id = thread_id_of(&ev);

        // ExitProcess is a session-ending event.
        if matches!(&ev, DebugEvent::ExitProcess { .. }) {
            return Err(ThemidaError::Debugger(
                "target process exited during trace".into(),
            ));
        }

        // ---- Events on the traced thread -----------------------------------
        if event_thread_id == thread_id {
            match ev {
                DebugEvent::SingleStep { address, .. } => {
                    counter += 1;

                    // Check instruction limit.
                    if counter > limit {
                        log(
                            LogMsgType::Info,
                            "Giving up trace due to instruction limit",
                        );
                        return Ok(());
                    }

                    // Fetch latest context.
                    ctx = debugger
                        .get_thread_context(thread_id)
                        .map_err(|e| {
                            ThemidaError::Debugger(format!(
                                "trace_one_slot context at {address:#x}: {e}"
                            ))
                        })?;

                    let ip = instr_ptr(&ctx);
                    let sp = stack_ptr(&ctx);

                    // Pre-read return address for the anti-trace skip path.
                    let mut ret_addr: usize = 0;
                    if sp < state.trace_start_sp {
                        let mut ret_buf = [0u8; 8];
                        let bytes_read = debugger.read_memory(sp, &mut ret_buf).unwrap_or(0);
                        if bytes_read >= PTR_SIZE {
                            ret_addr = u64::from_le_bytes(ret_buf) as usize;
                        }
                    }

                    let decision = trace_is_at_api(
                        ip,
                        sp,
                        state.trace_start_sp,
                        counter,
                        themida_section_start,
                        themida_section_end,
                        image_base,
                        image_boundary,
                        state.sleep_api,
                        state.lstrlen_api,
                        is_at_themida_vm(debugger, ip),
                        ret_addr,
                    );

                    match decision {
                        TraceStepDecision::HitVm { ip: vm_ip } => {
                            state.trace_in_vm = true;
                            log(
                                LogMsgType::Info,
                                &format!("Trace ran into Themida VM at {vm_ip:#x} — stopping"),
                            );
                            return Ok(());
                        }
                        TraceStepDecision::SkipAntiTraceApi { ip: _, ret_addr: target_ip }
                            if target_ip != 0 =>
                        {
                            log(
                                LogMsgType::Info,
                                &format!("Skipping anti-trace API at {ip:#x}"),
                            );
                            // Pop the return address from the stack and continue from it.
                            #[cfg(target_arch = "x86")]
                            {
                                set_stack_ptr(&mut ctx, sp + 8);
                            }
                            #[cfg(target_arch = "x86_64")]
                            {
                                set_stack_ptr(&mut ctx, sp + PTR_SIZE);
                            }
                            set_instr_ptr(&mut ctx, target_ip);
                            ctx.EFlags |= 0x100;
                            debugger
                                .set_thread_context(thread_id, &ctx)
                                .map_err(|e| {
                                    ThemidaError::Debugger(format!(
                                        "skip_anti_trace_api set_context: {e}"
                                    ))
                                })?;
                            debugger
                                .continue_event(thread_id, ContinueStatus::Continue)
                                .map_err(|e| {
                                    ThemidaError::Debugger(format!(
                                        "trace_one_slot continue after skip: {e}"
                                    ))
                                })?;
                            continue;
                        }
                        TraceStepDecision::FoundApi { ip: api_ip } => {
                            // Success! IP is the real API.
                            state.traced_api = api_ip;
                            return Ok(());
                        }
                        TraceStepDecision::Continue
                        | TraceStepDecision::SkipAntiTraceApi { .. } => {
                            // Keep tracing.
                        }
                    }

                    // ---- Continue tracing ---------------------------------

                    // Re-set TF so the next instruction also single-steps.
                    ctx.EFlags |= 0x100;
                    debugger
                        .set_thread_context(thread_id, &ctx)
                        .map_err(|e| {
                            ThemidaError::Debugger(format!(
                                "trace_one_slot set_tf: {e}"
                            ))
                        })?;

                    debugger
                        .continue_event(thread_id, ContinueStatus::Continue)
                        .map_err(|e| {
                            ThemidaError::Debugger(format!(
                                "trace_one_slot continue: {e}"
                            ))
                        })?;
                }

                // Unexpected exceptions on the traced thread are fatal.
                DebugEvent::Breakpoint {
                    address,
                    thread_id: _,
                }
                | DebugEvent::AccessViolation {
                    address,
                    thread_id: _,
                    ..
                } => {
                    let desc = match &ev {
                        DebugEvent::Breakpoint { .. } => {
                            format!("unexpected breakpoint at {address:#x}")
                        }
                        DebugEvent::AccessViolation {
                            target_address, ..
                        } => {
                            format!(
                                "access violation at {address:#x} \
                                 (target {target_address:#x})"
                            )
                        }
                        _ => unreachable!(),
                    };
                    log(
                        LogMsgType::Fatal,
                        &format!(
                            "Unexpected exception during tracing: {desc} \
                             in thread {thread_id}"
                        ),
                    );
                    return Err(ThemidaError::Debugger(desc));
                }

                // Non-exception events on our thread — continue.
                _ => {
                    debug!(
                        thread_id,
                        "trace_one_slot continuing non-exception event"
                    );
                    debugger
                        .continue_event(thread_id, ContinueStatus::Continue)
                        .map_err(|e| {
                            ThemidaError::Debugger(format!(
                                "trace_one_slot continue non-exc: {e}"
                            ))
                        })?;
                }
            }
        } else {
            // ---- Events on other threads -----------------------------------

            log(
                LogMsgType::Info,
                &format!("Suspending spurious thread {event_thread_id}"),
            );
            debugger
                .continue_event(event_thread_id, ContinueStatus::Continue)
                .map_err(|e| {
                    ThemidaError::Debugger(format!(
                        "trace_one_slot continue other thread: {e}"
                    ))
                })?;
        }
    }
}
