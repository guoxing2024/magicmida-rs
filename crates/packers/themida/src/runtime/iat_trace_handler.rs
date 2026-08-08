//! Pure IAT trace handler decisions (P3-C).
//!
//! `IatTraceState`, the single-step decision, the slot-result classification
//! and the slot walk are extracted from `crates/cli/src/unpacker/iat_trace.rs`
//! verbatim in behavior. The host implements [`IatTraceQuery`] (context,
//! memory, `VirtualProtectEx` via a protected-IAT capability, exactly-once
//! continue) and executes the returned actions; no Win32 type appears here.
//!
//! Contract:
//! - resolved / skipped / failed / abort / final-terminator accounting is
//!   preserved (`slots_accounted`, `product_complete`);
//! - a completed walk emits exactly one completion milestone (the host-side
//!   summary log) and performs the IAT writeback at most once;
//! - trash storms, short reads, bad resolves and continue failures stay
//!   fail-closed (`mark_aborted` is never silently cleared).

use mida_core::ThreadContextSnapshot;

use crate::runtime::av_oep_handler::LogLevel;
use crate::trace_imports::{trace_is_at_api, TraceStepDecision, TRACE_LIMIT};

/// State for IAT tracing within the debug loop.
///
/// For Themida v3 targets, the IAT values point to VM code.  We need to
/// single-step through the VM code to resolve the real API addresses.
#[derive(Debug)]
pub struct IatTraceState {
    pub iat_address: usize,
    #[allow(dead_code)]
    pub iat_size: usize,
    pub current_slot: usize,
    pub total_slots: usize,
    pub slot_values: Vec<usize>,
    themida_start: usize,
    themida_end: usize,
    image_base: usize,
    image_boundary: usize,
    trash_counter: usize,
    did_set_exit_process: bool,
    pub resolved_count: usize,
    pub failed_count: usize,
    /// Slots intentionally not traced (null padding / already real API / in-image data).
    pub skip_count: usize,
    pub failed_slots: Vec<usize>,
    /// Early abort (trash storm / bad result) — must not report product-complete.
    pub aborted: bool,
    pub abort_reason: Option<String>,
    pub trace_thread_id: u32,
    trace_start_sp: usize,
    pub trace_phase: TracePhase,
    trace_counter: u64,
    traced_api: usize,
    trace_in_vm: bool,
}

/// Per-slot tracing phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracePhase {
    Idle,
    Tracing,
}

impl IatTraceState {
    /// Build a fresh trace session.
    #[must_use]
    pub fn new(
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
            skip_count: 0,
            failed_slots: Vec::new(),
            aborted: false,
            abort_reason: None,
            trace_thread_id,
            trace_start_sp,
            trace_phase: TracePhase::Idle,
            trace_counter: 0,
            traced_api: 0,
            trace_in_vm: false,
        }
    }

    /// Accounting invariant: every slot is resolved, failed, or validated-skip.
    #[must_use]
    pub fn slots_accounted(&self) -> usize {
        self.resolved_count
            .saturating_add(self.failed_count)
            .saturating_add(self.skip_count)
    }

    /// Product-complete only when the walk finished without abort, every slot
    /// is accounted for, and no slot failed. Walking to `current_slot == total`
    /// alone is **not** success (audit residual P1).
    /// Empty table (`total_slots == 0`) is complete iff !aborted (no work).
    #[must_use]
    pub fn product_complete(&self) -> bool {
        !self.aborted
            && self.current_slot >= self.total_slots
            && self.failed_count == 0
            && self.slots_accounted() == self.total_slots
    }

    fn mark_aborted(&mut self, reason: impl Into<String>) {
        self.aborted = true;
        self.abort_reason = Some(reason.into());
        self.current_slot = self.total_slots;
        self.trace_phase = TracePhase::Idle;
    }

    /// Public fail-closed abort path for host-side execution failures
    /// (e.g. the host could not apply the slot context or resume the thread).
    pub fn abort(&mut self, reason: impl Into<String>) {
        self.mark_aborted(reason);
    }
}

/// What the host must do after one single-step or advance decision.
///
/// The decision never continues by itself: every action maps to exactly one
/// host-side continue (or a stop).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IatTraceAction {
    /// Set the trap flag on the trace thread, then resume exactly once.
    ContinueWithTrap,
    /// Redirect RIP/RSP (trap flag set), then resume exactly once.
    ContinueWithContext { rip: u64, rsp: u64 },
    /// Arm the next slot: apply `context` to the trace thread, then resume
    /// exactly once for single-stepping.
    TraceSlot { context: ThreadContextSnapshot },
    /// Walk finished. `writeback` is true only when the resolved IAT was
    /// written back; `product_complete` follows the accounting invariant.
    /// This is the single completion milestone for the walk.
    Finished {
        writeback: bool,
        product_complete: bool,
        aborted: bool,
    },
}

/// Capability seam the host implements over its debugger/engine.
pub trait IatTraceQuery {
    fn log(&mut self, level: LogLevel, message: &str);

    fn get_rip(&mut self, thread_id: u32) -> Option<u64>;
    fn get_rsp(&mut self, thread_id: u32) -> Option<u64>;

    /// Read target memory (short reads reported by the length).
    fn read_memory(&mut self, address: usize, buf: &mut [u8]) -> Result<usize, String>;
    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, String>;

    fn is_at_themida_vm(&mut self, ip: usize) -> bool;

    /// Resolve the real `ExitProcess` address (host-side Win32 lookup).
    fn resolve_exit_process(&mut self) -> Result<usize, String>;

    /// Toggle executable/writable protection on the IAT range.
    fn protect_iat(&mut self, address: usize, size: usize, executable: bool) -> Result<(), String>;

    /// `(sleep_api, lstrlen_api)` addresses from the host's API table.
    fn apis(&self) -> (usize, usize);
}

/// Handle one `SINGLE_STEP` event during IAT tracing.
pub fn handle_trace_step(
    query: &mut dyn IatTraceQuery,
    trace: &mut IatTraceState,
) -> Result<IatTraceAction, String> {
    trace.trace_counter += 1;

    if trace.trace_counter.is_multiple_of(5000) {
        query.log(
            LogLevel::Info,
            &format!("Trace step {} (limit {})", trace.trace_counter, TRACE_LIMIT),
        );
    }

    let ip = query
        .get_rip(trace.trace_thread_id)
        .ok_or_else(|| "get_thread_context_control failed: no RIP".to_string())?
        as usize;
    let sp = query
        .get_rsp(trace.trace_thread_id)
        .ok_or_else(|| "get_thread_context_control failed: no RSP".to_string())?
        as usize;

    if trace.trace_counter.is_multiple_of(50000) {
        query.log(
            LogLevel::Info,
            &format!("Trace step {}: IP={ip:#x}, SP={sp:#x}", trace.trace_counter),
        );
    }

    let is_vm_entry = query.is_at_themida_vm(ip);
    let (sleep_api, lstrlen_api) = query.apis();

    let mut ret_addr = 0usize;
    if sp < trace.trace_start_sp {
        let mut ret_bytes = [0u8; 8];
        if query.read_memory(sp, &mut ret_bytes).is_ok() {
            ret_addr = u64::from_le_bytes(ret_bytes) as usize;
        }
    }

    // Run the decision FIRST on this instruction (P2 issue 6: the limit-th step
    // is still classified — a FoundApi/HitVm on the limit-th step is honored,
    // not swallowed by the limit). Only a `Continue` that does not stop the
    // slot is subject to the instruction limit.
    let action = match trace_is_at_api(
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
            query.log(LogLevel::Info, &format!("Trace ran into VM at {vm_ip:#x}"));
            return handle_trace_result(query, trace);
        }
        TraceStepDecision::SkipAntiTraceApi {
            ip: api_ip,
            ret_addr: target_ip,
        } => {
            query.log(
                LogLevel::Info,
                &format!("Skipping anti-trace API at {api_ip:#x}"),
            );
            IatTraceAction::ContinueWithContext {
                rip: target_ip as u64,
                rsp: sp.saturating_add(8) as u64,
            }
        }
        TraceStepDecision::FoundApi { ip: api_ip } => {
            trace.traced_api = api_ip;
            return handle_trace_result(query, trace);
        }
        TraceStepDecision::Continue => IatTraceAction::ContinueWithTrap,
    };

    // The decision did not stop the slot. Check the instruction limit: `>=`
    // (not `>`) means "at most TRACE_LIMIT instructions executed" — the slot
    // fails once `trace_counter` reaches TRACE_LIMIT.
    if trace.trace_counter >= TRACE_LIMIT {
        query.log(
            LogLevel::Info,
            &format!(
                "Giving up trace slot {} due to instruction limit ({}/{})",
                trace.current_slot, trace.trace_counter, TRACE_LIMIT
            ),
        );
        trace.failed_count += 1;
        trace.failed_slots.push(trace.current_slot);
        trace.current_slot += 1;
        return advance_to_next_slot(query, trace);
    }

    Ok(action)
}

/// Classify one slot result and advance. Never jumps `current_slot` to total
/// on a bad result (that previously marked "complete" with missing slots).
fn handle_trace_result(
    query: &mut dyn IatTraceQuery,
    trace: &mut IatTraceState,
) -> Result<IatTraceAction, String> {
    if trace.trace_in_vm {
        if !trace.did_set_exit_process {
            trace.did_set_exit_process = true;
            let real_exit_process = query.resolve_exit_process()?;
            trace.slot_values[trace.current_slot] = real_exit_process;
            trace.resolved_count += 1;
            query.log(
                LogLevel::Info,
                &format!("IAT[{}] VM → ExitProcess", trace.current_slot),
            );
        } else {
            trace.failed_count += 1;
            trace.failed_slots.push(trace.current_slot);
        }
    } else if trace.traced_api != 0 {
        let api = trace.traced_api;
        if api < 0x10000 || (api >= trace.image_base && api < trace.image_boundary) {
            // Bad resolve: count failure and continue.
            trace.failed_count += 1;
            trace.failed_slots.push(trace.current_slot);
            query.log(
                LogLevel::Warn,
                &format!(
                    "IAT[{}] discarding result {api:#x} (in image or too low) — slot failed",
                    trace.current_slot
                ),
            );
        } else {
            trace.slot_values[trace.current_slot] = api;
            trace.resolved_count += 1;
            query.log(
                LogLevel::Info,
                &format!("IAT[{}] → {api:#x}", trace.current_slot),
            );
        }
    } else {
        trace.failed_count += 1;
        trace.failed_slots.push(trace.current_slot);
    }

    // The armed slot's outcome is consumed: move past it, then advance.
    trace.current_slot += 1;
    advance_to_next_slot(query, trace)
}

/// Move to the next IAT slot that needs tracing, or write the resolved IAT
/// back to the target if all slots are done.
///
/// Slot-0 fix (P6-0, explicit semantic correction after the P3 migration):
/// the legacy walk pre-incremented `current_slot` before its first
/// examination, so slot 0 — the first real thunk of the IAT — was never
/// classified and non-empty tables could never report `product_complete`.
/// The increment now happens where the *previous* slot's outcome is
/// consumed (`handle_trace_result` / step give-up), so the walk classifies
/// every slot from index 0. This is a deliberate behavior change from the
/// P3 baseline, pinned by dedicated tests.
pub fn advance_to_next_slot(
    query: &mut dyn IatTraceQuery,
    trace: &mut IatTraceState,
) -> Result<IatTraceAction, String> {
    trace.traced_api = 0;
    trace.trace_in_vm = false;
    trace.trace_counter = 0;

    while trace.current_slot < trace.total_slots {
        let current = trace.slot_values[trace.current_slot];
        let in_themida = current >= trace.themida_start && current < trace.themida_end;
        let is_real_api = current >= 0x10000
            && !in_themida
            && !(current >= trace.image_base && current < trace.image_boundary);

        // Skip null terminators — normal IAT structure, not trash.
        if current == 0 {
            trace.skip_count += 1;
            trace.current_slot += 1;
            continue;
        }

        // Skip already-resolved APIs (real API addresses in system DLLs).
        if is_real_api {
            trace.trash_counter = 0;
            trace.skip_count += 1;
            trace.current_slot += 1;
            continue;
        }

        // Found a Themida VM entry — trace it.
        if in_themida {
            trace.trash_counter = 0;
            break;
        }

        // Skip program-internal addresses (not imports).
        let in_image = current >= trace.image_base && current < trace.image_boundary;
        if in_image {
            trace.trash_counter = 0;
            trace.skip_count += 1;
            trace.current_slot += 1;
            continue;
        }

        // Unknown/invalid value — count as trash / failed slot, keep walking.
        trace.trash_counter += 1;
        trace.failed_count += 1;
        trace.failed_slots.push(trace.current_slot);
        if trace.trash_counter > 64 {
            trace.mark_aborted(format!(
                "trash storm after slot {} (>64 consecutive invalid)",
                trace.current_slot
            ));
            query.log(
                LogLevel::Warn,
                &format!(
                    "IAT trace ABORTED: {} — resolved={} failed={} skipped={}",
                    trace.abort_reason.as_deref().unwrap_or("?"),
                    trace.resolved_count,
                    trace.failed_count,
                    trace.skip_count
                ),
            );
            return Ok(IatTraceAction::Finished {
                writeback: false,
                product_complete: false,
                aborted: true,
            });
        }
        trace.current_slot += 1;
    }

    if trace.current_slot >= trace.total_slots {
        let accounted = trace.slots_accounted();
        let product_ok = trace.product_complete();
        query.log(
            if product_ok {
                LogLevel::Info
            } else {
                LogLevel::Warn
            },
            &format!(
                "IAT trace finished: resolved={} failed={} skipped={} accounted={}/{} aborted={} product_complete={}",
                trace.resolved_count,
                trace.failed_count,
                trace.skip_count,
                accounted,
                trace.total_slots,
                trace.aborted,
                product_ok
            ),
        );
        // Only write back when we resolved something and did not abort mid-table.
        let writeback = trace.resolved_count > 0 && !trace.aborted;
        if writeback {
            let write_size = trace.total_slots * std::mem::size_of::<usize>();
            query.protect_iat(trace.iat_address, write_size, true)?;
            query.write_memory(trace.iat_address, unsafe {
                std::slice::from_raw_parts(trace.slot_values.as_ptr() as *const u8, write_size)
            })?;
            let _ = query.protect_iat(trace.iat_address, write_size, false);
        }
        return Ok(IatTraceAction::Finished {
            writeback,
            product_complete: product_ok,
            aborted: trace.aborted,
        });
    }

    let current = trace.slot_values[trace.current_slot];
    query.log(
        LogLevel::Info,
        &format!("Tracing IAT slot {} from {current:#x}", trace.current_slot),
    );

    let mut context = ThreadContextSnapshot::blank();
    match query.get_rip(trace.trace_thread_id) {
        Some(rip) => context.rip = rip,
        None => {
            query.log(
                LogLevel::Warn,
                &format!(
                    "get_thread_context_control failed: no RIP - skipping slot {}",
                    trace.current_slot
                ),
            );
            trace.failed_count += 1;
            trace.failed_slots.push(trace.current_slot);
            trace.current_slot += 1;
            return advance_to_next_slot(query, trace);
        }
    }
    query.log(
        LogLevel::Info,
        &format!("Got thread context (CONTROL), RIP={:#x}", context.rip),
    );

    context.rip = current as u64;
    context.rsp = trace.trace_start_sp as u64;
    context.eflags |= 0x100;

    query.log(
        LogLevel::Info,
        &format!(
            "Setting thread context: RIP={current:#x}, RSP={:#x}",
            context.rsp
        ),
    );
    trace.trace_phase = TracePhase::Tracing;
    query.log(LogLevel::Info, "Thread context set, continuing...");
    Ok(IatTraceAction::TraceSlot { context })
}
