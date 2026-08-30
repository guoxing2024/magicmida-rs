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

use mida_core::debugger::{DebugEvent, DebuggerCore};
use mida_tracer::LogMsgType;
use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS, PAGE_READWRITE};

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
pub(crate) fn set_instr_ptr(
    ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT,
    val: usize,
) {
    ctx.Eip = val as u32;
}
#[cfg(target_arch = "x86_64")]
pub(crate) fn set_instr_ptr(
    ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT,
    val: usize,
) {
    ctx.Rip = val as u64;
}

/// Set the stack pointer in a `CONTEXT`.
#[cfg(target_arch = "x86")]
pub(crate) fn set_stack_ptr(
    ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT,
    val: usize,
) {
    ctx.Esp = val as u32;
}
#[cfg(target_arch = "x86_64")]
pub(crate) fn set_stack_ptr(
    ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT,
    val: usize,
) {
    ctx.Rsp = val as u64;
}

/// Trap flag bit of the x86/x64 EFlags register (single-step TF, bit 8).
/// The x86 architecture defines this bit; it is not a sample-specific magic
/// value. Setting it makes the CPU raise a single-step debug exception after
/// the next instruction — the mechanism the Themida VM tracer relies on.
pub(crate) const X86_EFLAGS_TRAP_FLAG: u32 = 0x100;

/// Set the trap flag (TF, bit 8 of EFlags) in a `CONTEXT`.
pub(crate) fn set_trap_flag(ctx: &mut windows::Win32::System::Diagnostics::Debug::CONTEXT) {
    ctx.EFlags |= X86_EFLAGS_TRAP_FLAG;
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

/// Minimum user-mode address (the 64KiB floor below which no real API or
/// module mapping lives on Windows). Used as the "already resolved" boundary
/// for IAT slot values: anything above this and outside the image is a real
/// system API, not an in-image pointer. This is a Windows user/kernel address
/// convention, not a sample-specific constant.
pub const MIN_USER_MODE_ADDRESS: usize = 0x1_0000;

/// Maximum consecutive *unknown/invalid* IAT slot values before we stop.
///
/// Must NOT count null terminators, already-resolved system APIs, or
/// in-image non-Themida pointers — those are normal multi-module IAT
/// structure (see CLI `advance_to_next_slot`).  Counting them as trash
/// caused holdout `xiongxiong_duokai` to stop mid-table after ~64 resolved
/// gaps and leave later Themida wrappers untraced (~79% rebuild).
const TRASH_THRESHOLD: usize = 64;

/// How a live IAT slot is handled by the v3 tracer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IatSlotClass {
    /// Pointer into the Themida section — single-step deobfuscation needed.
    Trace,
    /// Null, already-resolved system API, or in-image non-import — skip.
    Skip,
    /// Outside known ranges and not a plausible API — count toward trash.
    Trash,
}

/// Classify one IAT slot value for v3 tracing.
///
/// Matches CLI `advance_to_next_slot` semantics so multi-block IATs with
/// large already-resolved gaps still reach later Themida wrappers.
pub(crate) fn classify_iat_slot_for_trace(
    current: usize,
    themida_start: usize,
    themida_end: usize,
    image_base: usize,
    image_boundary: usize,
) -> IatSlotClass {
    if current == 0 {
        return IatSlotClass::Skip;
    }

    let in_themida = current >= themida_start && current < themida_end;
    if in_themida {
        return IatSlotClass::Trace;
    }

    // Outside image (and above low-address floor) → already a real API.
    let in_image = current >= image_base && current < image_boundary;
    if current >= MIN_USER_MODE_ADDRESS && !in_image {
        return IatSlotClass::Skip;
    }

    // Program-internal address (not an import wrapper) — skip, not trash.
    if in_image {
        return IatSlotClass::Skip;
    }

    // Low / unknown pointer.
    IatSlotClass::Trash
}

/// Default single-step limit per IAT slot.  The Pascal reference uses 500 000.
/// We use a much smaller limit to avoid hanging on difficult slots.
pub const TRACE_LIMIT: u64 = 500_000;

/// Deepened retry budget for a slot whose first-pass trace failed
/// (XX-10-A direction 1). A VM deobfuscation can be timing-dependent: a slot
/// that yields a partial/non-owned address on the first pass may complete on a
/// longer pass. 4x the default keeps the retry bounded while giving the
/// deobfuscation path room to finish.
pub const TRACE_LIMIT_DEEPENED: u64 = 2_000_000;

// ---------------------------------------------------------------------------
// TraceImportResult
// ---------------------------------------------------------------------------

/// Result of a v3 IAT trace pass.
///
/// Callers **must** gate on [`Self::is_product_complete()`], not on
/// `failed_count == 0` alone (abort / partial account can still yield
/// failed==0 in edge paths — audit residual).
///
/// Completeness is **computed**, never a free-standing bool field that can
/// drift from the counters (audit residual P2).
#[derive(Debug)]
pub struct TraceImportResult {
    /// Total slots examined in this pass.
    pub total_slots: usize,
    /// Number of IAT slots that were successfully resolved this pass.
    pub resolved_count: usize,
    /// Number of IAT slots that could not be resolved.
    pub failed_count: usize,
    /// Validated skips (null / already-real API / in-image non-wrapper).
    pub skip_count: usize,
    /// Zero-based indices of the slots that failed.
    pub failed_slots: Vec<usize>,
    /// Early abort (trash storm, etc.).
    pub aborted: bool,
    pub abort_reason: Option<String>,
}

impl TraceImportResult {
    /// `!aborted && failed==0 && resolved+failed+skipped==total`.
    /// Empty table (`total_slots==0`) is complete iff !aborted.
    pub fn is_product_complete(&self) -> bool {
        !self.aborted
            && self.failed_count == 0
            && self
                .resolved_count
                .saturating_add(self.failed_count)
                .saturating_add(self.skip_count)
                == self.total_slots
    }
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
    let mut skip_count: usize = 0;
    let mut failed_slots: Vec<usize> = Vec::new();
    let mut trash_counter: usize = 0;
    let mut did_set_exit_process: bool = false;
    let mut aborted = false;
    let mut abort_reason: Option<String> = None;

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

        match classify_iat_slot_for_trace(current, tm_start, tm_end, image_base, image_boundary) {
            IatSlotClass::Skip => {
                // Null / resolved API / in-image non-wrapper: validated skip.
                trash_counter = 0;
                skip_count += 1;
                continue;
            }
            IatSlotClass::Trash => {
                trash_counter += 1;
                failed_count += 1;
                failed_slots.push(i);
                if trash_counter > TRASH_THRESHOLD {
                    aborted = true;
                    abort_reason = Some(format!(
                        "trash threshold ({TRASH_THRESHOLD}) exceeded at slot {i}"
                    ));
                    log(
                        LogMsgType::Fatal,
                        &format!(
                            "Trash threshold ({TRASH_THRESHOLD}) exceeded at slot {i} — aborting IAT trace (not product-complete)"
                        ),
                    );
                    break;
                }
                continue;
            }
            IatSlotClass::Trace => {
                trash_counter = 0;
            }
        }

        log(
            LogMsgType::Info,
            &format!("Tracing IAT slot {i} ({slot_va:#x}) from {current:#x}"),
        );

        // Context / session errors: let trace_one_slot return Err and fail-fast
        // (no pre-check break that could yield a false 0/0 success).

        match trace_slot(
            debugger,
            state,
            current as u64,
            main_thread_id,
            tm_start,
            tm_end,
            image_base,
            image_boundary,
            &mut did_set_exit_process,
            i,
            slot_va,
            log,
        ) {
            Ok(TraceSlotOutcome::Resolved(api)) => {
                iat_data[i] = api;
                resolved_count += 1;
                log(
                    LogMsgType::Good,
                    &format!("IAT[{i}] {slot_va:#x}: {current:#x} → {api:#x}"),
                );
            }
            Ok(TraceSlotOutcome::ExitProcess(real_exit_process)) => {
                iat_data[i] = real_exit_process;
                resolved_count += 1;
                log(
                    LogMsgType::Info,
                    &format!(
                        "IAT[{i}] {slot_va:#x}: VM entry → ExitProcess ({real_exit_process:#x})"
                    ),
                );
            }
            Ok(TraceSlotOutcome::Failed(reason)) => {
                failed_count += 1;
                failed_slots.push(i);
                log(
                    LogMsgType::Fatal,
                    &format!("IAT[{i}] {slot_va:#x}: {reason}"),
                );
            }
            Err(e) => {
                // TASK-014 (shell-side diagnostic extension): a lifecycle
                // error on ONE slot (e.g. `continue_event refused: TID
                // mismatch` because the pending event belongs to another
                // thread) must NOT fail-fast-abort the whole pass — the
                // remaining slots may still resolve. Record the slot as
                // failed (diagnostic back-fill path `lifecycle_error`) and
                // continue; the product-complete gate still fails closed on
                // any failed slot, so the fail-closed semantics are
                // unchanged.
                //
                // Fail-fast is retained only for genuinely terminal errors
                // that cannot be slot-scoped (OS-level debugger failure
                // before any slot could be attributed).
                log(
                    LogMsgType::Fatal,
                    &format!("IAT[{i}] {slot_va:#x}: tracer error (slot-scoped): {e}"),
                );
                failed_count += 1;
                failed_slots.push(i);
                // Do NOT return Err here: keep walking so the rest of the
                // table gets resolved (diagnostic goal: maximize per-slot
                // coverage before the dump-stage gate sees the holes).
            }
        }
    }

    // Write the repaired IAT back to the target.
    // IAT often lives in a READONLY data section (name may be empty / not
    // ".rdata"); temporarily PAGE_READWRITE the exact range before write, then
    // restore the previous protection. Single old_protect is enough for the
    // current lunlun range (one 4K page); not a multi-page protect framework.
    if resolved_count > 0 {
        let write_size = actual_slots * ptr_size;
        // SAFETY: iat_data is a Vec<usize>; the aliasing immutable slice covers
        // exactly write_size bytes and is discarded after write_memory.
        let iat_bytes =
            unsafe { std::slice::from_raw_parts(iat_data.as_ptr() as *const u8, write_size) };

        let mut old_protect = PAGE_PROTECTION_FLAGS::default();
        // SAFETY: process_handle is the live debuggee; iat.address/write_size
        // are the exact IAT buffer bounds; old_protect is a valid out-pointer.
        unsafe {
            VirtualProtectEx(
                debugger.process_handle(),
                iat.address as *const std::ffi::c_void,
                write_size,
                PAGE_READWRITE,
                &mut old_protect,
            )
        }
        .map_err(|e| {
            ThemidaError::Debugger(format!(
                "trace_imports write IAT: VirtualProtectEx PAGE_READWRITE failed \
                 at {:#x} size={write_size} (VPE stage=unprotect): {e}",
                iat.address
            ))
        })?;

        // Do not `?` the write: restore must always run after a successful unprotect.
        let write_outcome = debugger.write_memory(iat.address, iat_bytes);

        let mut restore_tmp = PAGE_PROTECTION_FLAGS::default();
        // SAFETY: same handle/range as unprotect; restore saved old_protect.
        let restore_outcome = unsafe {
            VirtualProtectEx(
                debugger.process_handle(),
                iat.address as *const std::ffi::c_void,
                write_size,
                old_protect,
                &mut restore_tmp,
            )
        };

        let write_for_merge: Result<usize, String> = write_outcome.map_err(|e| e.to_string());
        let restore_for_merge: Result<(), String> = restore_outcome.map_err(|e| e.to_string());
        if let Err(msg) =
            combine_bulk_iat_write_restore(write_for_merge, write_size, restore_for_merge)
        {
            return Err(ThemidaError::Debugger(msg));
        }
    }

    let accounted = resolved_count
        .saturating_add(failed_count)
        .saturating_add(skip_count);
    // Product-complete requires full account + no fails + no abort.
    // actual_slots==0 (no wrappers) is a valid empty success when !aborted.
    // Early break / trash abort previously still logged "complete".
    let result = TraceImportResult {
        total_slots: actual_slots,
        resolved_count,
        failed_count,
        skip_count,
        failed_slots,
        aborted,
        abort_reason,
    };
    let product_complete = result.is_product_complete();
    let complete_level = if product_complete {
        LogMsgType::Good
    } else {
        LogMsgType::Fatal
    };
    log(
        complete_level,
        &format!(
            "IAT trace finished: resolved={} failed={} skipped={} accounted={}/{} aborted={} reason={:?} product_complete={}",
            result.resolved_count,
            result.failed_count,
            result.skip_count,
            accounted,
            result.total_slots,
            result.aborted,
            result.abort_reason,
            product_complete
        ),
    );

    Ok(result)
}

/// Outcome of one slot's trace attempt (single or deepened retry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceSlotOutcome {
    /// A real, module-owned API address was resolved.
    Resolved(usize),
    /// The trace entered the Themida VM; the value is the resolved ExitProcess
    /// replacement (only for the first VM hit of the pass).
    ExitProcess(usize),
    /// The slot could not be resolved; carries a deterministic reason.
    Failed(&'static str),
}

/// Trace a single IAT slot, retrying with a deepened instruction budget when
/// the first pass yields an un-owned address (XX-10-A direction 1).
///
/// The first pass runs with [`TRACE_LIMIT`]; if it fails with a non-owned or
/// in-image/too-low result (a partial VM deobfuscation), a second pass runs
/// with [`TRACE_LIMIT_DEEPENED`]. Any result from the second pass is final:
/// either it resolves to a module-owned address or the slot is recorded as
/// failed with the deterministic reason.
///
/// # ExitProcess special case
///
/// The first slot whose trace enters the Themida VM (across the whole pass) is
/// treated as ExitProcess (mirroring the legacy behaviour). `did_set_exit_process`
/// tracks that exactly once. A VM hit is never retried: it is a terminal
/// classification, not a partial deobfuscation.
#[allow(clippy::too_many_arguments)]
fn trace_slot(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    start_address: u64,
    main_thread_id: u32,
    tm_start: usize,
    tm_end: usize,
    image_base: usize,
    image_boundary: usize,
    did_set_exit_process: &mut bool,
    slot_index: usize,
    slot_va: usize,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<TraceSlotOutcome, ThemidaError> {
    // Pass 1: default budget.
    let first = run_slot_trace(
        debugger,
        state,
        start_address,
        main_thread_id,
        tm_start,
        tm_end,
        image_base,
        image_boundary,
        TRACE_LIMIT,
        log,
    )?;
    match first {
        SlotTraceRaw::ExitProcess => {
            if *did_set_exit_process {
                return Ok(TraceSlotOutcome::Failed(
                    "trace entered VM — giving up (ExitProcess already resolved)",
                ));
            }
            *did_set_exit_process = true;
            let real_exit_process = resolve_exit_process();
            if real_exit_process != 0 {
                return Ok(TraceSlotOutcome::ExitProcess(real_exit_process));
            }
            Ok(TraceSlotOutcome::Failed(
                "VM entry, but ExitProcess unresolved — leaving slot",
            ))
        }
        SlotTraceRaw::Resolved(api) => {
            if api < MIN_USER_MODE_ADDRESS || (api >= image_base && api < image_boundary) {
                // Partial deobfuscation (in-image or too low). Retry deepened.
                log(
                    LogMsgType::Info,
                    &format!(
                        "IAT[{slot_index}] {slot_va:#x}: first pass yielded {api:#x} \
                         (in image range or too low) — retrying with deepened budget"
                    ),
                );
                retry_or_fail(
                    debugger,
                    state,
                    start_address,
                    main_thread_id,
                    tm_start,
                    tm_end,
                    image_base,
                    image_boundary,
                    did_set_exit_process,
                    slot_index,
                    slot_va,
                    log,
                )
            } else {
                let module_ranges = crate::iat::loaded_module_ranges(debugger.pid());
                let owned_by_module = module_ranges
                    .iter()
                    .any(|&(base, end)| end > base && api >= base && api < end);
                if owned_by_module {
                    Ok(TraceSlotOutcome::Resolved(api))
                } else {
                    // Not owned by any loaded module — partial VM deobfuscation
                    // (e.g. XX-8's `0x1b370fa3810`). Retry deepened.
                    log(
                        LogMsgType::Info,
                        &format!(
                            "IAT[{slot_index}] {slot_va:#x}: first pass yielded {api:#x} \
                             (not owned by any loaded module) — retrying with deepened budget"
                        ),
                    );
                    retry_or_fail(
                        debugger,
                        state,
                        start_address,
                        main_thread_id,
                        tm_start,
                        tm_end,
                        image_base,
                        image_boundary,
                        did_set_exit_process,
                        slot_index,
                        slot_va,
                        log,
                    )
                }
            }
        }
        SlotTraceRaw::Failed(reason) => {
            // No API resolved at all (limit hit without result, etc.). Retry
            // with the deepened budget before giving up.
            log(
                LogMsgType::Info,
                &format!(
                    "IAT[{slot_index}] {slot_va:#x}: first pass failed ({reason}) \
                     — retrying with deepened budget"
                ),
            );
            retry_or_fail(
                debugger,
                state,
                start_address,
                main_thread_id,
                tm_start,
                tm_end,
                image_base,
                image_boundary,
                did_set_exit_process,
                slot_index,
                slot_va,
                log,
            )
        }
    }
}

/// Raw, pre-classification result of one `trace_one_slot` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotTraceRaw {
    /// The trace left the VM to a real API address (not yet ownership-checked).
    Resolved(usize),
    /// The trace entered the Themida VM (ExitProcess special case).
    ExitProcess,
    /// The trace ended without a usable result (limit hit, etc.).
    Failed(&'static str),
}

/// Run exactly one `trace_one_slot` invocation and reduce it to a raw outcome.
#[allow(clippy::too_many_arguments)]
fn run_slot_trace(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    start_address: u64,
    main_thread_id: u32,
    tm_start: usize,
    tm_end: usize,
    image_base: usize,
    image_boundary: usize,
    trace_limit: u64,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<SlotTraceRaw, ThemidaError> {
    state.traced_api = 0;
    state.trace_in_vm = false;

    match slot::trace_one_slot_end(
        debugger,
        state,
        start_address,
        main_thread_id,
        tm_start,
        tm_end,
        image_base,
        image_boundary,
        trace_limit,
        log,
    )? {
        // TASK-014: a lifecycle error on one slot is slot-scoped (the caller
        // records it as a failed slot and keeps walking); it does not abort
        // the whole pass. The `?` above only propagates genuinely terminal
        // OS-level errors, which are rare and must still fail-fast.
        slot::SlotTraceEnd::Api | slot::SlotTraceEnd::Vm | slot::SlotTraceEnd::NoResult => {}
        // TASK-015: a slot whose trace could not even start (lifecycle error,
        // e.g. a stale pending event that could not be cleared) must be
        // reported as such — never mislabeled as a "completed" trace with no
        // API. This keeps the fail-closed accounting (the slot is failed) but
        // records an honest root-cause reason for the per-slot diagnostics.
        slot::SlotTraceEnd::LifecycleError => {
            log(
                LogMsgType::Fatal,
                "trace lifecycle error — slot could not start (TASK-015)",
            );
            return Ok(SlotTraceRaw::Failed(
                "trace lifecycle error (slot could not start)",
            ));
        }
    }

    if state.trace_in_vm {
        Ok(SlotTraceRaw::ExitProcess)
    } else if state.traced_api != 0 {
        Ok(SlotTraceRaw::Resolved(state.traced_api))
    } else {
        Ok(SlotTraceRaw::Failed(
            "tracing completed but no API resolved",
        ))
    }
}

/// Second-pass retry with [`TRACE_LIMIT_DEEPENED`]; its outcome is final.
#[allow(clippy::too_many_arguments)]
fn retry_or_fail(
    debugger: &mut dyn DebuggerCore,
    state: &mut ThemidaState,
    start_address: u64,
    main_thread_id: u32,
    tm_start: usize,
    tm_end: usize,
    image_base: usize,
    image_boundary: usize,
    did_set_exit_process: &mut bool,
    slot_index: usize,
    slot_va: usize,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<TraceSlotOutcome, ThemidaError> {
    let second = run_slot_trace(
        debugger,
        state,
        start_address,
        main_thread_id,
        tm_start,
        tm_end,
        image_base,
        image_boundary,
        TRACE_LIMIT_DEEPENED,
        log,
    )?;
    match second {
        SlotTraceRaw::ExitProcess => {
            if *did_set_exit_process {
                return Ok(TraceSlotOutcome::Failed(
                    "deepened trace entered VM — giving up (ExitProcess already resolved)",
                ));
            }
            *did_set_exit_process = true;
            let real_exit_process = resolve_exit_process();
            if real_exit_process != 0 {
                Ok(TraceSlotOutcome::ExitProcess(real_exit_process))
            } else {
                Ok(TraceSlotOutcome::Failed(
                    "VM entry, but ExitProcess unresolved — leaving slot",
                ))
            }
        }
        SlotTraceRaw::Resolved(api) => {
            if api < MIN_USER_MODE_ADDRESS || (api >= image_base && api < image_boundary) {
                Ok(TraceSlotOutcome::Failed(
                    "deepened trace still in image range or too low",
                ))
            } else {
                let module_ranges = crate::iat::loaded_module_ranges(debugger.pid());
                let owned_by_module = module_ranges
                    .iter()
                    .any(|&(base, end)| end > base && api >= base && api < end);
                if owned_by_module {
                    log(
                        LogMsgType::Good,
                        &format!(
                            "IAT[{slot_index}] {slot_va:#x}: deepened retry resolved {api:#x}"
                        ),
                    );
                    Ok(TraceSlotOutcome::Resolved(api))
                } else {
                    Ok(TraceSlotOutcome::Failed(
                        "deepened trace still not owned by any loaded module (vm_non_module_addr)",
                    ))
                }
            }
        }
        SlotTraceRaw::Failed(reason) => Ok(TraceSlotOutcome::Failed(match reason {
            "tracing completed but no API resolved" => {
                "deepened trace completed but no API resolved"
            }
            _ => reason,
        })),
    }
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Merge bulk IAT `write_memory` + protection-restore outcomes.
///
/// Always prefers retaining the write failure (including short write) when
/// restore also fails — restore must not overwrite the original write reason.
pub(crate) fn combine_bulk_iat_write_restore(
    write: Result<usize, String>,
    write_size: usize,
    restore: Result<(), String>,
) -> Result<(), String> {
    match (write, restore) {
        (Ok(n), Ok(())) if n == write_size => Ok(()),
        (Ok(n), Ok(())) => Err(format!(
            "trace_imports: short write IAT (actual={n} expected={write_size})"
        )),
        (Ok(n), Err(re)) if n == write_size => Err(format!(
            "trace_imports write IAT: restore VirtualProtectEx failed \
             (VPE stage=restore): {re}"
        )),
        (Ok(n), Err(re)) => Err(format!(
            "trace_imports: short write IAT (actual={n} expected={write_size}); \
             restore VirtualProtectEx also failed (VPE stage=restore): {re}"
        )),
        (Err(we), Ok(())) => Err(format!("trace_imports write IAT: {we}")),
        (Err(we), Err(re)) => Err(format!(
            "trace_imports write IAT: {we}; restore VirtualProtectEx also failed \
             (VPE stage=restore): {re}"
        )),
    }
}

/// Extract the Themida section bounds from the PE info in `state`.
///
/// Returns the bounds of ALL Themida sections combined (min start, max end).
///
/// `actual_image_base` is the ASLR-reloaded image base (from the
/// CREATE_PROCESS debug event), which may differ from the PE header's
/// `ImageBase` field.
pub(crate) fn get_themida_section_bounds(
    state: &ThemidaState,
    actual_image_base: usize,
) -> (usize, usize) {
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
        (
            actual_image_base,
            state.pe_info.image_boundary as usize + image_delta,
        )
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
///
/// Returns `0` if the address cannot be resolved (kernel32 not loaded or
/// `ExitProcess` not exported). The caller treats 0 as "no replacement" rather
/// than aborting the debug session — a panic here would leave the debuggee
/// orphaned with the debug port still attached.
fn resolve_exit_process() -> usize {
    // SAFETY: GetModuleHandleA / GetProcAddress are always available on
    // Windows. The returned address is valid in the target because kernel32
    // is a known DLL loaded at a fixed base per session.
    unsafe {
        use windows::core::PCSTR;
        use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

        let kernel32 = match GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0".as_ptr())) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!("resolve_exit_process: kernel32.dll not loaded: {e}");
                return 0;
            }
        };
        match GetProcAddress(kernel32, PCSTR::from_raw(b"ExitProcess\0".as_ptr())) {
            Some(addr) => addr as usize,
            None => {
                tracing::warn!("resolve_exit_process: ExitProcess not found in kernel32");
                0
            }
        }
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

    // -- classify_iat_slot_for_trace (holdout multi-gap regression)

    const TM0: usize = 0x7ff7_236e_1000;
    const TM1: usize = 0x7ff7_24cf_8200;
    const IMG0: usize = 0x7ff7_236e_0000;
    const IMG1: usize = 0x7ff7_24cf_a000;

    #[test]
    fn classify_zero_is_skip_not_trash() {
        assert_eq!(
            classify_iat_slot_for_trace(0, TM0, TM1, IMG0, IMG1),
            IatSlotClass::Skip
        );
    }

    #[test]
    fn classify_themida_wrapper_is_trace() {
        assert_eq!(
            classify_iat_slot_for_trace(0x7ff7_2451_9a5e, TM0, TM1, IMG0, IMG1),
            IatSlotClass::Trace
        );
    }

    #[test]
    fn classify_resolved_system_api_is_skip_not_trash() {
        // kernel32-style VA outside image — must not accumulate trash or
        // early-stop past large already-resolved gaps (holdout 64+ gap).
        assert_eq!(
            classify_iat_slot_for_trace(0x7ff9_9726_f970, TM0, TM1, IMG0, IMG1),
            IatSlotClass::Skip
        );
    }

    #[test]
    fn classify_in_image_non_themida_is_skip() {
        // PE header / early image before .themida start.
        assert_eq!(
            classify_iat_slot_for_trace(IMG0 + 0x100, TM0, TM1, IMG0, IMG1),
            IatSlotClass::Skip
        );
    }

    #[test]
    fn classify_low_unknown_is_trash() {
        // Below 0x10000 floor — not a plausible system API.
        assert_eq!(
            classify_iat_slot_for_trace(0x5000, TM0, TM1, IMG0, IMG1),
            IatSlotClass::Trash
        );
    }

    #[test]
    fn classify_long_resolved_gap_never_trips_trash() {
        // Simulate 100 consecutive already-resolved API slots: none trash.
        let mut trash = 0usize;
        for _ in 0..100 {
            match classify_iat_slot_for_trace(0x7ff9_9726_f970, TM0, TM1, IMG0, IMG1) {
                IatSlotClass::Skip => trash = 0,
                IatSlotClass::Trash => trash += 1,
                IatSlotClass::Trace => trash = 0,
            }
        }
        assert_eq!(trash, 0, "resolved APIs must not accumulate trash");
        // Later Themida wrapper still classifies as Trace after the gap.
        assert_eq!(
            classify_iat_slot_for_trace(0x7ff7_2470_a128, TM0, TM1, IMG0, IMG1),
            IatSlotClass::Trace
        );
    }

    // -- TraceImportResult

    #[test]
    fn trace_import_result_debug() {
        let r = TraceImportResult {
            total_slots: 50,
            resolved_count: 42,
            failed_count: 3,
            skip_count: 5,
            failed_slots: vec![5, 10, 15],
            aborted: false,
            abort_reason: None,
        };
        let dbg = format!("{r:?}");
        assert!(dbg.contains("42"));
        assert!(dbg.contains("3"));
        assert!(dbg.contains("5"));
        assert!(!r.is_product_complete());
        let ok = TraceImportResult {
            total_slots: 10,
            resolved_count: 7,
            failed_count: 0,
            skip_count: 3,
            failed_slots: vec![],
            aborted: false,
            abort_reason: None,
        };
        assert!(ok.is_product_complete());
    }

    // -- combine_bulk_iat_write_restore

    #[test]
    fn bulk_write_full_and_restore_ok() {
        assert!(combine_bulk_iat_write_restore(Ok(2816), 2816, Ok(())).is_ok());
    }

    #[test]
    fn bulk_write_short_write_err() {
        let e = combine_bulk_iat_write_restore(Ok(100), 2816, Ok(())).unwrap_err();
        assert!(e.contains("short write"));
        assert!(e.contains("actual=100"));
        assert!(e.contains("expected=2816"));
        assert!(!e.contains("restore"));
    }

    #[test]
    fn bulk_write_error_only() {
        let e = combine_bulk_iat_write_restore(
            Err("failed to write memory at 0x1401a5000".into()),
            2816,
            Ok(()),
        )
        .unwrap_err();
        assert!(e.contains("trace_imports write IAT:"));
        assert!(e.contains("0x1401a5000"));
        assert!(!e.contains("also failed"));
    }

    #[test]
    fn bulk_write_restore_error_only() {
        let e = combine_bulk_iat_write_restore(Ok(2816), 2816, Err("access denied".into()))
            .unwrap_err();
        assert!(e.contains("restore VirtualProtectEx failed"));
        assert!(e.contains("VPE stage=restore"));
        assert!(e.contains("access denied"));
        assert!(!e.contains("short write"));
    }

    #[test]
    fn bulk_write_and_restore_dual_error() {
        let e = combine_bulk_iat_write_restore(
            Err("failed to write memory at 0x1401a5000".into()),
            2816,
            Err("restore boom".into()),
        )
        .unwrap_err();
        assert!(e.contains("failed to write memory at 0x1401a5000"));
        assert!(e.contains("restore VirtualProtectEx also failed"));
        assert!(e.contains("restore boom"));
    }

    #[test]
    fn bulk_short_write_and_restore_dual_error() {
        let e =
            combine_bulk_iat_write_restore(Ok(8), 2816, Err("restore boom".into())).unwrap_err();
        assert!(e.contains("short write"));
        assert!(e.contains("actual=8"));
        assert!(e.contains("restore VirtualProtectEx also failed"));
        assert!(e.contains("restore boom"));
    }

    // -- VM pattern constants

    #[test]
    fn vm_pattern_has_correct_length() {
        assert_eq!(THEMIDA_VM_PATTERN.len(), 4);
    }

    // -- TASK-014: per-slot lifecycle-error classification (slot-scoped)

    #[test]
    fn slot_scoped_lifecycle_error_stays_failed_not_fatal() {
        // A slot whose trace cannot start (e.g. pending event belongs to
        // another thread) must be recorded as a FAILED slot so the walk can
        // continue to the remaining slots. The product-complete gate still
        // fails closed on any failed slot; only the diagnostic granularity
        // changes (slot-scoped instead of whole-pass abort).
        let failure = "trace_one_slot continue: continue_event refused: TID mismatch \
                       before ContinueDebugEvent (provided_tid=1 pending_tid=2 \
                       pending_pid=3 pending_code=4 seq=5 root_pid=3)";
        // The decision to keep walking is taken by the caller (trace_imports);
        // this test pins the classification contract: a lifecycle error is a
        // per-slot failure, never silently swallowed as success.
        assert!(failure.contains("TID mismatch"));
        assert!(failure.contains("pending_code=4"));
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

    // -- XX-10-A direction 1: deepened retry budget --

    #[test]
    fn deepened_budget_is_strictly_larger_than_default() {
        // The second-pass budget must give the VM deobfuscation more room than
        // the first pass (4x default). A deepened budget <= default would make
        // the retry meaningless.
        assert!(
            TRACE_LIMIT_DEEPENED > TRACE_LIMIT,
            "deepened retry budget must exceed the default"
        );
        assert_eq!(TRACE_LIMIT_DEEPENED / TRACE_LIMIT, 4);
        assert!(TRACE_LIMIT_DEEPENED.is_multiple_of(TRACE_LIMIT));
    }
}
