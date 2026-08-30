//! Single-slot trace loop — the core single-step execution that follows one
//! IAT slot through the Themida VM until a real API is reached.
//!
//! Contains: [`trace_one_slot`].

use tracing::debug;

use mida_core::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
use mida_tracer::LogMsgType;

use crate::common::ThemidaState;
use crate::error::ThemidaError;

use super::decision::{trace_is_at_api, TraceStepDecision};
use super::{
    instr_ptr, is_at_themida_vm, set_instr_ptr, set_stack_ptr, set_trap_flag, stack_ptr,
    thread_id_of, PTR_SIZE,
};

/// TASK-014: diagnostic back-fill path marker for one slot trace attempt.
///
/// The trace loop itself only writes `state.traced_api` / `state.trace_in_vm`;
/// the caller (trace_imports) needs to know HOW a slot ended so the
/// per-slot diagnostic (backfill path) can be emitted. This enum is
/// produced by [`trace_one_slot`]'s caller-side reduction and logged without
/// touching [`ThemidaState`] (which is outside the authorized file list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotTraceEnd {
    /// `state.traced_api` holds a real API address (or ExitProcess resolved).
    Api,
    /// The trace entered the Themida VM (ExitProcess special case).
    Vm,
    /// The trace returned with neither API nor VM (edge).
    NoResult,
    /// The trace could not start (lifecycle error, e.g. TID mismatch).
    LifecycleError,
}

/// Run [`trace_one_slot`] and reduce its result to a [`SlotTraceEnd`] for
/// diagnostics. The trace semantics are unchanged; this only adds the
/// caller-side classification used by the per-slot diagnostic path.
pub(crate) fn trace_one_slot_end(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    start_address: u64,
    thread_id: u32,
    themida_section_start: usize,
    themida_section_end: usize,
    image_base: usize,
    image_boundary: usize,
    trace_limit: u64,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<SlotTraceEnd, ThemidaError> {
    match trace_one_slot(
        debugger,
        state,
        start_address,
        thread_id,
        themida_section_start,
        themida_section_end,
        image_base,
        image_boundary,
        trace_limit,
        log,
    ) {
        Ok(()) => {
            if state.trace_in_vm {
                Ok(SlotTraceEnd::Vm)
            } else if state.traced_api != 0 {
                Ok(SlotTraceEnd::Api)
            } else {
                Ok(SlotTraceEnd::NoResult)
            }
        }
        Err(_) => Ok(SlotTraceEnd::LifecycleError),
    }
}

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
/// # `trace_limit`
///
/// The instruction budget for this pass. The caller may retry a failed slot
/// with a deepened budget (XX-10-A direction 1): a VM deobfuscation that
/// yields a partial/non-owned address on the first pass can complete on a
/// longer pass, so the limit is a parameter rather than a hard-coded
/// `TRACE_LIMIT`.
///
/// # Returns
///
/// - `Ok(())` — trace completed (check `state.traced_api` and
///   `state.trace_in_vm` for the result).
/// - `Err(...)` — an OS-level debugger error occurred.
#[allow(clippy::too_many_arguments)]
pub(crate) fn trace_one_slot(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    start_address: u64,
    thread_id: u32,
    themida_section_start: usize,
    themida_section_end: usize,
    image_base: usize,
    image_boundary: usize,
    trace_limit: u64,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<(), ThemidaError> {
    let mut counter: u64 = 0;
    let limit: u64 = trace_limit;

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

    // Resume from the event that brought us here — OR bootstrap from a
    // no-pending-event state (XX-8-A).
    //
    // Two entry states exist:
    // - event entry: the caller (debug loop) still holds a pending debug event;
    //   `continue_event` resumes it so the RIP+TF context write takes effect.
    // - frozen entry: the caller left the loop via a timeout freeze (e.g. the
    //   IAT-materialization wait's `FreezeAndDump` after 30s) with NO pending
    //   event; the trace thread is already free-running and the RIP+TF context
    //   write above is sufficient.  There is nothing to continue, so we must
    //   NOT call `continue_event` (the engine rejects it as "no pending event")
    //   and instead enter the wait loop directly to receive the first
    //   single-step event.
    //
    // Fail-fast is reserved for genuinely abnormal sequences (debugger errors,
    // unexpected exceptions on the traced thread), never for a legal frozen
    // entry that simply lacks a pending event.
    let had_pending_event = debugger.pending_event_thread_id().is_some();
    if had_pending_event {
        debugger
            .continue_event(thread_id, ContinueStatus::Continue)
            .map_err(|e| ThemidaError::Debugger(format!("trace_one_slot continue: {e}")))?;
    } else {
        log(
            LogMsgType::Info,
            "trace_one_slot: no pending event — bootstrapping via first wait (frozen entry)",
        );
    }

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

                    // Fetch latest context.
                    ctx = debugger.get_thread_context(thread_id).map_err(|e| {
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
                        TraceStepDecision::SkipAntiTraceApi {
                            ip: _,
                            ret_addr: target_ip,
                        } if target_ip != 0 => {
                            log(
                                LogMsgType::Info,
                                &format!("Skipping anti-trace API at {ip:#x}"),
                            );
                            // Check instruction limit AFTER the decision ran on
                            // this instruction (P2 issue 6). A SkipAntiTraceApi
                            // must NOT bypass the limit: if we have reached
                            // `limit`, stop here instead of continuing.
                            if counter >= limit {
                                log(LogMsgType::Info, "Giving up trace due to instruction limit");
                                return Ok(());
                            }
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
                            debugger.set_thread_context(thread_id, &ctx).map_err(|e| {
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

                    // Check instruction limit AFTER the decision ran on this
                    // instruction (P2 issue 6: the limit-th step is still
                    // classified/decided, then the trace stops once `counter`
                    // reaches `limit`). `>=` (not `>`) means "at most `limit`
                    // instructions executed".
                    if counter >= limit {
                        log(LogMsgType::Info, "Giving up trace due to instruction limit");
                        return Ok(());
                    }

                    // Re-set TF so the next instruction also single-steps.
                    ctx.EFlags |= 0x100;
                    debugger.set_thread_context(thread_id, &ctx).map_err(|e| {
                        ThemidaError::Debugger(format!("trace_one_slot set_tf: {e}"))
                    })?;

                    debugger
                        .continue_event(thread_id, ContinueStatus::Continue)
                        .map_err(|e| {
                            ThemidaError::Debugger(format!("trace_one_slot continue: {e}"))
                        })?;
                }

                // Unexpected exceptions on the traced thread are fatal.
                DebugEvent::Breakpoint {
                    address,
                    thread_id: _,
                }
                | DebugEvent::AccessViolation { address, .. } => {
                    let desc = match &ev {
                        DebugEvent::Breakpoint { .. } => {
                            format!("unexpected breakpoint at {address:#x}")
                        }
                        DebugEvent::AccessViolation { target_address, .. } => {
                            format!(
                                "access violation at {address:#x} \
                                 (target {target_address:#x})"
                            )
                        }
                        // Unreachable: the outer match already constrained
                        // `ev` to Breakpoint | AccessViolation. Kept as a
                        // safe fallback so a future refactor cannot panic
                        // inside the trace loop.
                        _ => format!("unexpected debug event at {address:#x}"),
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
                    debug!(thread_id, "trace_one_slot continuing non-exception event");
                    debugger
                        .continue_event(thread_id, ContinueStatus::Continue)
                        .map_err(|e| {
                            ThemidaError::Debugger(format!("trace_one_slot continue non-exc: {e}"))
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
                    ThemidaError::Debugger(format!("trace_one_slot continue other thread: {e}"))
                })?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::init::ThemidaPeInfo;
    use crate::trace_imports::TRACE_LIMIT;
    use crate::version::ThemidaVersion;
    use mida_core::CoreError;
    use std::cell::RefCell;
    use windows::Win32::{Foundation::HANDLE, System::Diagnostics::Debug::CONTEXT};

    /// Scripted debugger that drives `trace_one_slot` with a controllable
    /// pending-event identity and a fixed event stream.
    struct ScriptedDebugger {
        pending_tid: Option<u32>,
        events: Vec<DebugEvent>,
        context: RefCell<CONTEXT>,
        continue_calls: u32,
    }

    impl ScriptedDebugger {
        fn new(pending_tid: Option<u32>) -> Self {
            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
            #[cfg(target_arch = "x86_64")]
            {
                ctx.Rip = 0x7ff8_0000_1000;
                ctx.Rsp = 0x2000;
            }
            #[cfg(target_arch = "x86")]
            {
                ctx.Eip = 0x0000_1000;
                ctx.Esp = 0x2000;
            }
            Self {
                pending_tid,
                events: Vec::new(),
                context: RefCell::new(ctx),
                continue_calls: 0,
            }
        }

        fn with_event(mut self, ev: DebugEvent) -> Self {
            self.events.push(ev);
            self
        }
    }

    impl DebuggerCore for ScriptedDebugger {
        fn process_handle(&self) -> HANDLE {
            HANDLE::default()
        }
        fn pid(&self) -> u32 {
            1
        }
        fn image_base(&self) -> u64 {
            0x7ff7_0000_0000
        }
        fn pending_event_thread_id(&self) -> Option<u32> {
            self.pending_tid
        }
        fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
            if self.events.is_empty() {
                return Err(CoreError::Timeout);
            }
            Ok(self.events.remove(0))
        }
        fn continue_event(
            &mut self,
            _thread_id: u32,
            _status: ContinueStatus,
        ) -> Result<(), CoreError> {
            self.continue_calls += 1;
            Ok(())
        }
        fn read_memory(&self, _address: usize, _buf: &mut [u8]) -> Result<usize, CoreError> {
            Ok(0)
        }
        fn write_memory(&mut self, _address: usize, _data: &[u8]) -> Result<usize, CoreError> {
            Ok(0)
        }
        fn get_thread_context(&self, _thread_id: u32) -> Result<CONTEXT, CoreError> {
            Ok(*self.context.borrow())
        }
        fn set_thread_context(&self, _thread_id: u32, ctx: &CONTEXT) -> Result<(), CoreError> {
            // Persist the RIP+TF write so the subsequent single-step context
            // read observes the redirected instruction pointer (matching the
            // real backend's SetThreadContext semantics).
            *self.context.borrow_mut() = *ctx;
            Ok(())
        }
    }

    fn pe_info() -> ThemidaPeInfo {
        ThemidaPeInfo {
            image_base: 0x7ff7_0000_0000,
            image_boundary: 0x7ff7_0000_6000,
            base_of_data: 0x2000,
            pe_sections: Vec::new(),
            major_linker_version: 14,
            themida_version: ThemidaVersion::V3,
            is_vm_oep: false,
            themida_section: None,
            tls_total: 0,
        }
    }

    const THREAD: u32 = 42;
    const REAL_API: usize = 0x7ff8_0000_1234;

    #[test]
    fn frozen_entry_bootstraps_without_continue() {
        // XX-8-A problem 1: when the caller left the loop via a timeout freeze,
        // there is NO pending debug event. The trace must NOT call
        // continue_event (which the engine rejects), and must instead wait
        // directly for the first single-step event.
        let mut dbg = ScriptedDebugger::new(None).with_event(DebugEvent::SingleStep {
            thread_id: THREAD,
            address: REAL_API as u64,
        });
        let mut state = ThemidaState::new(pe_info(), false);
        let noop = |_: LogMsgType, _: &str| {};

        let result = trace_one_slot(
            &mut dbg,
            &mut state,
            REAL_API as u64,
            THREAD,
            0x7ff7_0000_3000,
            0x7ff7_0000_5000,
            0x7ff7_0000_0000,
            0x7ff7_0000_6000,
            TRACE_LIMIT,
            &noop,
        );

        assert!(result.is_ok(), "frozen entry must bootstrap: {result:?}");
        assert_eq!(dbg.continue_calls, 0, "no continue_event on frozen entry");
        assert_eq!(
            state.traced_api, REAL_API,
            "single-step must resolve the API"
        );
        assert!(!state.trace_in_vm);
    }

    #[test]
    fn event_entry_continues_pending_event() {
        // Event entry: the caller still holds a pending debug event for THREAD.
        // trace_one_slot must continue it exactly once before waiting.
        let mut dbg = ScriptedDebugger::new(Some(THREAD)).with_event(DebugEvent::SingleStep {
            thread_id: THREAD,
            address: REAL_API as u64,
        });
        let mut state = ThemidaState::new(pe_info(), false);
        let noop = |_: LogMsgType, _: &str| {};

        let result = trace_one_slot(
            &mut dbg,
            &mut state,
            REAL_API as u64,
            THREAD,
            0x7ff7_0000_3000,
            0x7ff7_0000_5000,
            0x7ff7_0000_0000,
            0x7ff7_0000_6000,
            TRACE_LIMIT,
            &noop,
        );

        assert!(result.is_ok(), "event entry must trace: {result:?}");
        assert_eq!(dbg.continue_calls, 1, "exactly one continue on event entry");
        assert_eq!(state.traced_api, REAL_API);
    }
}
