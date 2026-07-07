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
//! ## Reference
//!
//! - `ThemidaCommon.pas` → `TraceImports` (the outer loop)
//! - `Themida.pas` / `Themida64.pas` → `TraceIsAtAPI` (the per-step predicate)
//!
//! ## How it works
//!
//! 1. Iterate over every IAT slot.
//! 2. If the slot value is 0 or already a real API address, skip it.
//! 3. Otherwise, record the current stack pointer and start single-stepping.
//! 4. After every step, run the stop predicate:
//!    - IP left the Themida section → **success** (IP is the real API).
//!    - IP equals `Sleep` or `lstrlenA/W` with RSP < trace_start_sp →
//!      anti-trace fake call; skip it by popping the return address off the
//!      stack and continuing.
//!    - IP hit the Themida VM entry (`lock cmpxchg [rbx+rbp], ecx`) → **give
//!      up** on this slot.
//!    - Instruction limit exceeded → **give up**.
//! 5. Write the resolved API address back into the IAT slot.
//!
//! ## Special cases
//!
//! - **ExitProcess**: sometimes resolves to a Themida VM internal function
//!   instead of the true `kernel32!ExitProcess`.  We detect this and replace
//!   it with the real address.
//! - **Trash counter**: if we hit 64 consecutive zero or invalid IAT slots,
//!   we stop early — the table is over.

use tracing::debug;

use mida_core::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
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
    // The state.pe_info.image_base is the PE header's preferred load address,
    // which may differ from the actual load address due to ASLR.
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

        // Log first few slots for debugging.
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

        // Check if this slot needs tracing.
        // Magicmida's TraceImports only traces slots whose value falls inside
        // the Themida section (TMSectR.Contains).  Slots that are zero, already
        // resolved API addresses, or point to image-internal functions are NOT
        // traced — they simply increment the trash counter.
        let in_themida = current >= tm_start && current < tm_end;

        if !in_themida || current == 0 {
            // Not a Themida-section pointer — treat as trash.
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

        // The slot value is in the Themida section — it needs tracing.
        log(
            LogMsgType::Info,
            &format!("Tracing IAT slot {i} ({slot_va:#x}) from {current:#x}"),
        );
        trash_counter = 0;

        // Check if the process is still being debugged by attempting a
        // simple operation.  If the debug session has ended (e.g. due to
        // incorrect OEP causing the process to crash), skip tracing.
        if debugger.get_thread_context(main_thread_id).is_err() {
            log(
                LogMsgType::Info,
                &"Debug session ended — skipping remaining IAT slots".to_string(),
            );
            break;
        }

        state.traced_api = 0;
        state.trace_in_vm = false;

        // ---- single-step trace loop for this slot ---------------------------
        //
        // We run the trace loop inline (rather than using `Tracer::trace`)
        // because the predicate needs access to both `debugger` and `state`
        // simultaneously, which would conflict with Rust's borrow rules if
        // they were captured in a closure while `Tracer` also borrows
        // `debugger`.
        //
        // This follows the same structure as `Tracer.pas` `TTracer.Trace`
        // but keeps debugger and state accessible.

        match trace_one_slot(
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
                    // The trace hit the Themida VM — this slot cannot be
                    // resolved via single-stepping.
                    if !did_set_exit_process {
                        // The first VM-bound slot is assumed to be
                        // ExitProcess.
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

                    // Sanity check: discard obviously bogus results.
                    if api < 0x10000 || (api >= image_base && api < image_boundary) {
                        log(
                            LogMsgType::Info,
                            &format!(
                                "IAT[{i}] {slot_va:#x}: discarding result {api:#x} \
                                 (in image range or too low), aborting IAT tracing"
                            ),
                        );
                        // Per Pascal: break out entirely on this condition.
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
                // Continue with next slot instead of aborting.
            }
        }
    }

    // Write the repaired IAT back to the target.
    if resolved_count > 0 {
        let write_size = actual_slots * ptr_size;
        let bytes_written = debugger
            .write_memory(
                iat.address,
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
// Single-slot trace loop
// ===========================================================================

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
fn trace_one_slot(
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

    // Update trace_start_sp per slot (Pascal ThemidaCommon.pas lines 385-386:
    // reads the current RSP before each slot trace).  Without this refresh,
    // the baseline SP drifts across slots and the anti-trace Sleep/lstrlen
    // skip logic makes incorrect decisions.
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
                        // Mark as failed (traced_api stays at 0).
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

                    // ---- TraceIsAtAPI decision (shared helper) ----------------
                    //
                    // Corresponds to `Themida.pas` / `Themida64.pas`
                    // `TraceIsAtAPI`.  Using the pure helper function means both
                    // `trace_one_slot` and `unpacker::handle_trace_step` share the
                    // exact same decision logic.

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

                // Unexpected exceptions on the traced thread are fatal
                // (matches the Pascal reference).
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

// ===========================================================================
// Trace-Is-At-API decision helper
// ===========================================================================

/// Decision returned by [`trace_is_at_api`].
///
/// Encapsulates the "what should I do next?" outcome of examining the
/// current instruction pointer and stack pointer during a single-step trace,
/// once per step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStepDecision {
    /// Keep tracing — none of the stop/skip conditions are met.
    Continue,
    /// A real API has been reached at `ip`.  Stop tracing this slot; the
    /// resolved API address is `ip`.
    FoundApi { ip: usize },
    /// The trace walked into the Themida VM entry at `ip`.  Stop tracing this
    /// slot; the resolution failed (`trace_in_vm = true`).
    HitVm { ip: usize },
    /// Anti-trace fake call (Sleep/lstrlen) at `ip`.  Return address popped from
    /// `sp`; trace should continue from that address.
    SkipAntiTraceApi { ip: usize, ret_addr: usize },
}

/// Pure computation: given the current IP/SP and trace context, decide what
/// to do next.
///
/// This is the Rust equivalent of `Themida.pas`/`Themida64.pas` `TraceIsAtAPI`
/// predicate, extracted from `trace_one_step` and `handle_trace_step` so both
/// call sites share the exact same rules.
///
/// # Parameters
///
/// - `ip` — current instruction pointer
/// - `sp` — current stack pointer
/// - `trace_start_sp` — stack pointer at trace start (any later `sp < this`
///   means we're inside a nested call)
/// - `counter` — instruction counter for this slot (used to gate VM detection)
/// - `themida_start` / `themida_end` — Themida section bounds
/// - `image_base` / `image_boundary` — full image bounds
/// - `sleep_api` / `lstrlen_api` — resolved anti-trace API addresses (0 = unknown)
/// - `is_vm_entry` — whether the instruction at `ip` is the VM entry signature
pub fn trace_is_at_api(
    ip: usize,
    sp: usize,
    trace_start_sp: usize,
    counter: u64,
    themida_start: usize,
    themida_end: usize,
    image_base: usize,
    image_boundary: usize,
    sleep_api: usize,
    lstrlen_api: usize,
    is_vm_entry: bool,
    #[allow(unused)] return_addr: usize,
) -> TraceStepDecision {
    // 1. VM entry detection — only in counter range 100..5000 (matches Pascal).
    if counter > 100 && counter < 5000 && is_vm_entry {
        return TraceStepDecision::HitVm { ip };
    }

    // 2. Anti-trace API skipping.  sp < trace_start_sp means we're in a
    //    nested call; if the target is Sleep or lstrlenA/W, pop return addr.
    if sp < trace_start_sp && (ip == sleep_api || ip == lstrlen_api) {
        return TraceStepDecision::SkipAntiTraceApi { ip, ret_addr: return_addr };
    }

    // 3. Section exit check — did we leave the Themida section?
    let in_themida = ip >= themida_start && ip < themida_end;
    if !in_themida {
        // Pascal: Result := not TMSectR.Contains(C.Rip) → True (stop)
        // But if nested call (sp < trace_start_sp), might be fake API → continue
        if sp < trace_start_sp {
            return TraceStepDecision::Continue;
        }

        // Not nested. Check if in-image (internal function) or outside (real API)
        if ip >= image_base && ip < image_boundary {
            // Inside image but outside Themida - internal function, continue
            return TraceStepDecision::Continue;
        }

        // Outside image - real API
        return TraceStepDecision::FoundApi { ip };
    }

    // 4. Still in Themida section — keep tracing.
    TraceStepDecision::Continue
}

// ===========================================================================
// IAT slot validity
// ===========================================================================

/// Check whether an IAT slot value is already a real API address (i.e. does
/// NOT need tracing).
///
/// Returns `true` when the value looks like a resolved API and can be skipped.
///
/// Logic (matches `Dumper.IsAPIAddress` + `TraceImports` range check):
/// - `0` → NOT a real API (needs tracing, but slot is empty).
/// - In the Themida section → NOT a real API (needs tracing).
/// - In the image but NOT in the Themida section → internal function (needs
///   tracing — it's not a real API from a system DLL).
/// - Outside the image → real API (skip).
#[allow(dead_code)]
fn is_real_api_address(
    address: usize,
    image_base: usize,
    image_boundary: usize,
    themida_section_start: usize,
    themida_section_end: usize,
) -> bool {
    if address == 0 {
        return false;
    }

    // In the Themida section → obfuscated, needs tracing.
    if address >= themida_section_start && address < themida_section_end {
        return false;
    }

    // In the image but outside the Themida section → Probably an internal
    // function, still needs tracing.
    if address >= image_base && address < image_boundary {
        return false;
    }

    // Below the minimum valid address → bogus.
    if address < 0x10000 {
        return false;
    }

    // Outside the image, above 0x10000 → likely a real API.
    true
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
fn get_themida_section_bounds(state: &ThemidaState, actual_image_base: usize) -> (usize, usize) {
    let pe_image_base = state.pe_info.image_base as usize;
    let image_delta = actual_image_base.wrapping_sub(pe_image_base);

    let mut min_start = usize::MAX;
    let mut max_end = 0;
    let mut found = false;

    for section in &state.pe_info.pe_sections {
        if crate::version::is_themida_section(section) {
            // Use actual_image_base instead of pe_image_base for correct
            // ASLR-reloaded addresses.
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
        // Fallback: use the entire image boundary.
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
fn thread_id_of(ev: &DebugEvent) -> u32 {
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

    // -- is_real_api_address --

    #[test]
    fn zero_is_not_real_api() {
        assert!(!is_real_api_address(
            0,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn in_themida_section_needs_tracing() {
        // address inside Themida section → not a real API
        assert!(!is_real_api_address(
            0x411000,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn in_image_but_not_themida_needs_tracing() {
        // inside image but outside Themida section → internal function
        assert!(!is_real_api_address(
            0x405000,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn outside_image_is_real_api() {
        // outside the image → real API from a system DLL
        assert!(is_real_api_address(
            0x7FFE12345678,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn low_address_is_not_real_api() {
        assert!(!is_real_api_address(
            0x5000,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    // -- TraceImportResult --

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

    // -- VM pattern constants --

    #[test]
    fn vm_pattern_has_correct_length() {
        assert_eq!(THEMIDA_VM_PATTERN.len(), 4);
    }

    // -- trace_is_at_api (pure helper) --

    #[test]
    fn trace_is_at_api_continue_inside_themida() {
        // IP inside Themida section — should keep tracing
        assert_eq!(
            trace_is_at_api(
                0x410500, // ip: inside Themida section
                0x10000,  // sp
                0x10000,  // trace_start_sp (same as sp → not nested)
                50,       // counter (below VM detection threshold)
                0x410000, // themida_start
                0x420000, // themida_end
                0x400000, // image_base
                0x500000, // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                false,  // is_vm_entry
                0,      // return_addr
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    fn trace_is_at_api_hit_vm_within_counter_range() {
        // Inside counter range 100..5000 and vm_entry=true → HitVm
        assert_eq!(
            trace_is_at_api(
                0x410500, // ip
                0x10000,  // sp
                0x10000,  // trace_start_sp
                200,      // counter in VM detection range
                0x410000, // themida_start (IP still in Themida)
                0x420000, // themida_end
                0x400000, // image_base
                0x500000, // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                true,   // is_vm_entry
                0,      // return_addr
            ),
            TraceStepDecision::HitVm { ip: 0x410500 },
        );
    }

    #[test]
    fn trace_is_at_api_ignore_vm_below_counter_threshold() {
        // counter <= 100 — VM detection not active
        assert_eq!(
            trace_is_at_api(
                0x410500, // ip (still in Themida section)
                0x10000,  // sp
                0x10000,  // trace_start_sp
                50,       // counter below VM threshold
                0x410000, // themida_start
                0x420000, // themida_end
                0x400000, // image_base
                0x500000, // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                true,   // is_vm_entry (would trigger if counter was in range)
                0,      // return_addr
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    fn trace_is_at_api_ignore_vm_above_counter_threshold() {
        // counter >= 5000 — VM detection not active
        assert_eq!(
            trace_is_at_api(
                0x410500, // ip
                0x10000,  // sp
                0x10000,  // trace_start_sp
                5001,     // counter above VM detection range
                0x410000, // themida_start
                0x420000, // themida_end
                0x400000, // image_base
                0x500000, // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                true,   // is_vm_entry (ignored because counter out of range)
                0,      // return_addr
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    fn trace_is_at_api_found_api_outside_image() {
        // IP outside image boundary, sp >= trace_start_sp → real API found
        assert_eq!(
            trace_is_at_api(
                0x7FFE12340000, // ip: kernel32-style address
                0x10000,    // sp
                0x10000,    // trace_start_sp (not nested)
                50,         // counter
                0x410000,   // themida_start
                0x420000,   // themida_end
                0x400000,   // image_base
                0x500000,   // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                false,      // is_vm_entry
                0,          // return_addr
            ),
            TraceStepDecision::FoundApi { ip: 0x7FFE12340000 },
        );
    }

    #[test]
    fn trace_is_at_api_continue_on_internal_function() {
        // IP inside image but outside Themida section, sp >= trace_start_sp →
        // internal function, keep tracing
        assert_eq!(
            trace_is_at_api(
                0x405000, // ip: inside image, outside Themida
                0x10000,  // sp
                0x10000,  // trace_start_sp
                50,       // counter
                0x410000, // themida_start
                0x420000, // themida_end
                0x400000, // image_base
                0x500000, // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                false,  // is_vm_entry
                0,      // return_addr
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    fn trace_is_at_api_skip_anti_trace_sleep() {
        // IP matches Sleep address, sp < trace_start_sp (nested call)
        assert_eq!(
            trace_is_at_api(
                0x7FFE0000, // ip: == sleep_api
                0x0FF00,    // sp: below trace_start_sp (nested)
                0x10000,    // trace_start_sp
                50,         // counter
                0x410000,   // themida_start
                0x420000,   // themida_end
                0x400000,   // image_base
                0x500000,   // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                false,      // is_vm_entry
                0xDEAD0000, // return_addr to pop
            ),
            TraceStepDecision::SkipAntiTraceApi {
                ip: 0x7FFE0000,
                ret_addr: 0xDEAD0000,
            },
        );
    }

    #[test]
    fn trace_is_at_api_skip_anti_trace_lstrlen() {
        // IP matches lstrlen address, sp < trace_start_sp
        assert_eq!(
            trace_is_at_api(
                0x7FFE1000, // ip: == lstrlen_api
                0x0FF00,    // sp: below trace_start_sp (nested)
                0x10000,    // trace_start_sp
                50,         // counter
                0x410000,   // themida_start
                0x420000,   // themida_end
                0x400000,   // image_base
                0x500000,   // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                false,      // is_vm_entry
                0xDEAD0001, // return_addr
            ),
            TraceStepDecision::SkipAntiTraceApi {
                ip: 0x7FFE1000,
                ret_addr: 0xDEAD0001,
            },
        );
    }

    #[test]
    fn trace_is_at_api_no_skip_when_sp_at_start() {
        // Sleep API at IP but sp == trace_start_sp (not in nested call) —
        // should NOT trigger anti-trace skip. IP is outside Themida, sp not
        // nested, so this becomes FoundApi.
        assert_eq!(
            trace_is_at_api(
                0x7FFE0000, // ip: == sleep_api
                0x10000,    // sp: == trace_start_sp (not nested)
                0x10000,    // trace_start_sp
                50,         // counter
                0x410000,   // themida_start
                0x420000,   // themida_end
                0x400000,   // image_base
                0x500000,   // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                false,      // is_vm_entry
                0,          // return_addr
            ),
            TraceStepDecision::FoundApi { ip: 0x7FFE0000 },
        );
    }

    #[test]
    fn trace_is_at_api_continue_when_outside_themida_but_nested() {
        // Outside Themida, sp < trace_start_sp, IP not matching APIs →
        // "might have encountered new fake API" — keep tracing
        assert_eq!(
            trace_is_at_api(
                0x505000, // ip: between themida_end (0x420000) and image_boundary
                0x0FF00,  // sp: below trace_start_sp (nested)
                0x10000,  // trace_start_sp
                50,       // counter
                0x410000, // themida_start
                0x420000, // themida_end
                0x400000, // image_base
                0x500000, // image_boundary
                0x7FFE0000, // sleep_api
                0x7FFE1000, // lstrlen_api
                false,  // is_vm_entry
                0,      // return_addr
            ),
            TraceStepDecision::Continue,
        );
    }

    // -- get_themida_section_bounds --

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
        let actual_image_base = 0x140000000; // Same as pe_image_base in test
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
        let actual_image_base = 0x400000; // Same as pe_image_base in test
        let (start, end) = get_themida_section_bounds(&state, actual_image_base);
        assert_eq!(start, 0x400000);
        assert_eq!(end, 0x500000);
    }
}
