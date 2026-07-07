//! Decrypt `.text` by single-stepping from the guard-hit OEP until real code
//! is reached.
//!
//! ## Overview
//!
//! For Themida v3 targets with a **virtualised OEP** (`is_vm_oep == true`),
//! the address we detect via the `.text` guard page is still the VM entry
//! (e.g. a dispatch stub that jumps into `lock cmpxchg`).  At this point the
//! `.text` section on disk is still encrypted, so dumping now produces a
//! PE that crashes with `0xC0000005` at runtime.
//!
//! Instead of dumping immediately, we *let the VM decrypt the code* by
//! single-stepping execution from the VM entry until the instruction pointer
//! lands on a **real, decrypted instruction inside `.text`** — and record
//! that address as the genuine OEP.
//!
//! ## Reference
//!
//! - `Tracer.pas`                     → generic single-step loop (`mida-tracer`).
//! - `Themida.pas` / `Themida64.pas` → `TraceIsAtAPI` anti-trace / VM logic;
//!                                      this module borrows the same shape but
//!                                      with a different *stop* condition.
//!
//! ## Algorithm
//!
//! 1. Set RIP = `start_ip` (the guard-hit VM entry) and set the trap flag
//!    (TF).
//! 2. Continue the target thread.  It fires `EXCEPTION_SINGLE_STEP` after one
//!    instruction.
//! 3. On each single-step, decide what to do:
//!    - **In Themida section**      → keep walking.  The VM is decrypting `.text`.
//!    - **Anti-trace fake call**    → Sleep / `lstrlen` executed with
//!      `RSP < trace_start_sp`.  Pop the return address and resume from it.
//!    - **Inside `.text`, not VM**  → *candidate*: decode the instruction and
//!      check it is a valid x64 function prologue.  If yes → this is the
//!      **real OEP**.  If no → keep walking (garbage bytes on a bad decrypt).
//!    - **Outside image**           → keep walking (the VM may call out to
//!      resolve imports before entering user code).
//! 4. Stop on: real-OEP found (success), instruction limit reached, or the
//!    target process exits.

use mida_core::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
use mida_disasm::Disassembler;
use tracing::debug;
use windows::Win32::System::Diagnostics::Debug::CONTEXT;

use mida_tracer::LogMsgType;

use crate::error::ThemidaError;
use crate::trace_imports::{is_at_themida_vm, set_trap_flag, TRACE_LIMIT};
use crate::trace_imports::{instr_ptr, set_instr_ptr, set_stack_ptr, stack_ptr, PTR_SIZE};

/// Thin wrapper around [`is_valid_x64_prologue_at`] used by the unpacker's
/// phase-A3 heuristic to decide whether `ip` already looks like real x86-64
/// user code at dump time.
pub fn is_oep_already_decrypted(debugger: &dyn DebuggerCore, ip: usize) -> bool {
    is_valid_x64_prologue_at(debugger, ip)
}

// ---------------------------------------------------------------------------
// Decision enum
// ---------------------------------------------------------------------------

/// Outcome of the per-step decision for the text-decrypt walker.
///
/// Mirrors [`crate::trace_imports::TraceStepDecision`] but uses a text-section
/// stop condition instead of "IP left the Themida section = API".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextTraceDecision {
    /// Keep walking — not yet at the real OEP.
    Continue,
    /// Candidate real OEP: IP is inside `.text`, not the VM entry.  The loop
    /// body must still validate that the instruction decodes as a real
    /// function prologue before accepting it.
    CandidateRealOep { ip: usize },
    /// Anti-trace fake Sleep / lstrlen call: pop `ret_addr` from the stack and
    /// keep tracing from there.
    SkipAntiTraceApi { ip: usize, ret_addr: usize },
}

// ---------------------------------------------------------------------------
// Per-step decision (pure)
// ---------------------------------------------------------------------------

/// Decide what to do for one single-step of the text-decrypt walker.
///
/// This is the text-decrypt analogue of
/// [`crate::trace_imports::trace_is_at_api`]: same anti-trace rule, but the
/// *stop* condition is "IP inside `.text` on a non-VM instruction" instead of
/// "IP outside the Themida section".
pub fn decide_text_trace_step(
    ip: usize,
    sp: usize,
    trace_start_sp: usize,
    themida_start: usize,
    themida_end: usize,
    text_start: usize,
    text_end: usize,
    sleep_api: usize,
    lstrlen_api: usize,
    is_vm_entry: bool,
    return_addr: usize,
) -> TextTraceDecision {
    // 1. Anti-trace fake Sleep / lstrlen call when inside a nested frame.
    if sp < trace_start_sp && (ip == sleep_api || ip == lstrlen_api) {
        return TextTraceDecision::SkipAntiTraceApi { ip, ret_addr: return_addr };
    }

    let in_themida = ip >= themida_start && ip < themida_end;

    // 2. Still inside the Themida section → the VM is still running.  Keep
    //    walking so it can finish decrypting `.text`.
    if in_themida {
        return TextTraceDecision::Continue;
    }

    // 3. We left the Themida section.  Is it `.text`?
    let in_text = ip >= text_start && ip < text_end;
    if in_text && !is_vm_entry {
        // Candidate: IP landed on a non-VM instruction inside `.text`.  The
        // caller must still validate that it decodes as a real prologue.
        return TextTraceDecision::CandidateRealOep { ip };
    }

    // 4. Outside Themida and outside `.text` — could be an import the VM
    //    resolved, or any other helper code.  Keep walking.
    TextTraceDecision::Continue
}

// ---------------------------------------------------------------------------
// Real-x64-prologue check
// ---------------------------------------------------------------------------

/// Check that the first instruction at `ip` is a valid x64 function prologue.
///
/// Encrypted garbage bytes often *decode* into something, but not into a
/// sequence that looks like a compiler-generated function entry.  This check
/// mirrors the byte-level prologue heuristic already used by
/// [`crate::oep::find_real_oep_by_scanning`]:
/// - `push reg` (rbp / rbx / rsi / rdi / r12–r15)
/// - `mov rbp, rsp` / `sub rsp, ...` / `mov [rsp+off], reg` (`48 8B/83/89`)
/// - `endbr64` (`f3 0f 1e fa` — modern MSVC / GCC)
///
/// We additionally decode with `iced-x86` to sanity-check that the bytes form
/// one or two consecutive valid instructions (not a giant "unknown" blob).
pub fn is_valid_x64_prologue_at(
    debugger: &dyn DebuggerCore,
    ip: usize,
) -> bool {
    let mut buf = [0u8; 16];
    let n = match debugger.read_memory(ip, &mut buf) {
        Ok(n) if n >= 2 => n,
        _ => return false,
    };

    // ---- byte-level prologue patterns (matches find_real_oep_by_scanning) ----
    let b = &buf[..n];
    let prologue_byte = match b[0] {
        0x55 => true,                       // push rbp
        0x53 => true,                       // push rbx
        0x56 => true,                       // push rsi
        0x57 => true,                       // push rdi
        0x41 => matches!(b.get(1), Some(&(0x54..=0x57))), // push r12-r15
        0x48 => matches!(b.get(1), Some(&0x8B | &0x83 | &0x81 | &0x89)), // mov rbp,rsp / sub rsp
        // endbr64 — modern MSVC / GCC pointer-auth prologue
        0xF3 => b.get(1) == Some(&0x0F)
            && b.get(2) == Some(&0x1E)
            && b.get(3) == Some(&0xFA),
        _ => false,
    };

    if !prologue_byte {
        return false;
    }

    // ---- iced-x86 sanity check: the bytes must decode into one or two
    //      reasonable instructions, not a garbage blob. ----
    let disasm = Disassembler::new(64, ip as u64);
    let insns: Vec<_> = disasm.decode_all(b).take(3).collect();
    if insns.is_empty() {
        return false;
    }

    // The first instruction length must not exceed 8 bytes (prologues are
    // short); iced-x86 decodes some garbage into many tiny "db xx" pseudo-
    // ops, so we also require a sensible total length for the first.
    let first_len = insns[0].len();
    if !(1..=8).contains(&first_len) {
        return false;
    }

    // Reject obvious non-prologue opcodes that happen to start with 0x48 /
    // 0x55 etc.
    use iced_x86::Mnemonic;
    let m = insns[0].mnemonic();
    let looks_like_prologue = matches!(
        m,
        Mnemonic::Push
            | Mnemonic::Mov
            | Mnemonic::Sub
            | Mnemonic::Lea
            | Mnemonic::Endbr64
            | Mnemonic::And   // and rsp, imm8  (stack alignment)
            | Mnemonic::Or    // rarely, but acceptable
            | Mnemonic::Xor   // security cookie check
            | Mnemonic::Cmp
    );

    looks_like_prologue
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Walk the VM from `start_ip` for up to `limit` instructions, letting the
/// protector dispatcher decrypt each `.text` page on demand via its natural
/// guard-page trap-flag flow.  When the instruction budget is exhausted,
/// return the last IP that looked like a valid x64 function prologue inside
/// `[text_start, text_end)`; this is the dump's OEP.
///
/// Theory of operation: the Themida VM decrypts each 4 KiB page of `.text`
/// exactly once — at the first code fetch that cannot be satisfied without
/// decryption.  Single-stepping the thread for N instructions exercises the
/// CRT startup chain long enough that the VM decrypts every page that the
/// dump will contain when executed under a stand-alone loader.  The OEP is
/// then chosen from the last "real x64 prologue" the trace saw — i.e. once
/// the thread has fledged from the dispatcher into user code.
///
/// # Parameters
///
/// * `start_ip`        — guard-hit address (in the VM / stub code).
/// * `text_start`/`text_end` — VA bounds of the `.text` section.
/// * `themida_start`/`themida_end` — VA bounds of the Themida section.
/// * `sleep_api`/`lstrlen_api` — resolved anti-trace fake API addresses
///   (pass `0` to disable the anti-trace skip).
/// * `limit`           — max instructions.  `0` → `TRACE_LIMIT` (500 000).
///
/// # Return
///
/// - `Ok(Some(oep))` — real OEP found; caller should dump and use this as OEP.
/// - `Ok(None)`      — limit reached or target exited; caller should fall
///                     back to the guard-hit OEP.
pub fn trace_until_real_oep(
    debugger: &mut dyn DebuggerCore,
    thread_id: u32,
    start_ip: usize,
    text_start: usize,
    text_end: usize,
    themida_start: usize,
    themida_end: usize,
    sleep_api: usize,
    lstrlen_api: usize,
    limit: u64,
    log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<Option<usize>, ThemidaError> {
    let limit = if limit == 0 { TRACE_LIMIT } else { limit };
    let mut counter: u64 = 0;

    // ---- 1. set RIP = start_ip, record trace_start_sp, set TF ------------
    let mut ctx = debugger
        .get_thread_context(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("text_trace get_initial_context: {e}")))?;

    let trace_start_sp = stack_ptr(&ctx);
    set_instr_ptr(&mut ctx, start_ip);
    set_trap_flag(&mut ctx);

    debugger
        .set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("text_trace set_initial_context: {e}")))?;
    debugger
        .continue_event(thread_id, ContinueStatus::Continue)
        .map_err(|e| ThemidaError::Debugger(format!("text_trace initial_continue: {e}")))?;

    log(
        LogMsgType::Info,
        &format!(
            "text-decrypt trace: start={start_ip:#x}, \
             text=[{text_start:#x},{text_end:#x}), \
             themida=[{themida_start:#x},{themida_end:#x}), \
             limit={limit}, trace_start_sp={trace_start_sp:#x}",
        ),
    );

    // ---- 2. event loop ---------------------------------------------------
    let mut last_plausible_oep: Option<usize> = None;
    let closure_result = (|| loop {
        let ev = debugger
            .wait_event()
            .map_err(|e| ThemidaError::Debugger(format!("text_trace wait: {e}")))?;

        let event_thread_id = thread_id_of(&ev);

        if let DebugEvent::ExitProcess { exit_code } = &ev {
            log(
                LogMsgType::Info,
                &format!("text-trace target exited (code {exit_code}) — falling back"),
            );
            return Ok(None);
        }

        if event_thread_id != thread_id {
            // Events on other threads: keep going.
            log(
                LogMsgType::Info,
                &format!("Suspending spurious thread {event_thread_id}"),
            );
            debugger
                .continue_event(event_thread_id, ContinueStatus::Continue)
                .map_err(|e| ThemidaError::Debugger(format!("text_trace continue_other: {e}")))?;
            continue;
        }

        match ev {
            DebugEvent::SingleStep { address, .. } => {
                counter += 1;
                if counter > limit {
                    log(
                        LogMsgType::Info,
                        &format!(
                            "text-trace: hit instruction ({counter}) limit {limit} — \
                             returning last plausible OEP"
                        ),
                    );
                    return Ok(last_plausible_oep);
                }

                ctx = debugger
                    .get_thread_context(thread_id)
                    .map_err(|e| {
                        ThemidaError::Debugger(format!("text_trace context@{address:#x}: {e}"))
                    })?;

                let ip = instr_ptr(&ctx);
                let sp = stack_ptr(&ctx);

                // Pre-read return address for the anti-trace skip path.
                let mut return_addr: usize = 0;
                if sp < trace_start_sp {
                    let mut ret_buf = [0u8; 8];
                    let bytes_read = debugger.read_memory(sp, &mut ret_buf).unwrap_or(0);
                    if bytes_read >= PTR_SIZE {
                        return_addr = u64::from_le_bytes(ret_buf) as usize;
                    }
                }

                let is_vm = is_at_themida_vm(debugger, ip);
                let decision = decide_text_trace_step(
                    ip,
                    sp,
                    trace_start_sp,
                    themida_start,
                    themida_end,
                    text_start,
                    text_end,
                    sleep_api,
                    lstrlen_api,
                    is_vm,
                    return_addr,
                );

                match decision {
                    TextTraceDecision::Continue => {
                        // Keep tracing.
                        advance(debugger, thread_id, &ctx, &mut counter, log)?;
                    }
                    TextTraceDecision::CandidateRealOep { ip: candidate_ip } => {
                        // Record the candidate but keep walking so the VM
                        // decrypts more of `.text` through CRT startup.
                        if is_valid_x64_prologue_at(debugger, candidate_ip) {
                            log(LogMsgType::Info,
                                &format!("text-trace: recording plausible OEP \
                                          {candidate_ip:#x} at step {counter}"));
                            last_plausible_oep = Some(candidate_ip);
                        } else {
                            log(LogMsgType::Info,
                                &format!("text-trace: rejecting false-positive \
                                          candidate {candidate_ip:#x}"));
                        }
                        advance(debugger, thread_id, &ctx, &mut counter, log)?;
                    }
                    TextTraceDecision::SkipAntiTraceApi {
                        ip: api_ip,
                        ret_addr: target_ip,
                    } if target_ip != 0 => {
                        log(
                            LogMsgType::Info,
                            &format!("text-trace: skipping anti-trace fake API at {api_ip:#x}"),
                        );
                        // Pop the return address from the stack and continue from it.
                        set_stack_ptr(&mut ctx, sp + PTR_SIZE);
                        set_instr_ptr(&mut ctx, target_ip);
                        ctx.EFlags |= 0x100;
                        debugger
                            .set_thread_context(thread_id, &ctx)
                            .map_err(|e| {
                                ThemidaError::Debugger(format!("text_trace set_ctx_skip: {e}"))
                            })?;
                        debugger
                            .continue_event(thread_id, ContinueStatus::Continue)
                            .map_err(|e| {
                                ThemidaError::Debugger(format!(
                                    "text_trace continue_after_skip: {e}"
                                ))
                            })?;
                        continue;
                    }
                    TextTraceDecision::SkipAntiTraceApi { .. } => {
                        // Anti-trace but no usable return address — advance normally.
                        advance(debugger, thread_id, &ctx, &mut counter, log)?;
                    }
                }
            }
            // Unexpected events on our thread (breakpoint, access violation,
            // anything other than SingleStep): continue them.  While the CPU
            // is inside the VM dispatcher it may trigger access violations on
            // guarded memory; the protector handles those in-kernel and steps
            // the thread forward to the next VM instruction.  Forwarding keeps
            // that handshake going so the dispatcher can decrypt `.text`.
            _ => {
                debug!(
                    thread_id,
                    "text-trace: forwarding non-single-step event on trace thread"
                );
                debugger
                    .continue_event(thread_id, ContinueStatus::Continue)
                    .map_err(|e| {
                        ThemidaError::Debugger(format!("text_trace forward_other: {e}"))
                    })?;
            }

        }
    })();

    // `match` requires all arms to have the same type, but the closure uses
    // `?` returning `Result<Option<usize>, _>` — its value is `closure_result`.
    closure_result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Re-arm TF on the current context, write it back, and resume the thread
/// by one more instruction.
fn advance(
    debugger: &mut dyn DebuggerCore,
    thread_id: u32,
    ctx: &CONTEXT,
    _counter: &mut u64,
    _log: &(dyn Fn(LogMsgType, &str) + '_),
) -> Result<(), ThemidaError> {
    let mut ctx = *ctx;
    set_trap_flag(&mut ctx);
    debugger
        .set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("text_trace advance set_ctx: {e}")))?;
    debugger
        .continue_event(thread_id, ContinueStatus::Continue)
        .map_err(|e| ThemidaError::Debugger(format!("text_trace advance continue: {e}")))?;
    Ok(())
}

/// Extract the thread ID from any [`DebugEvent`] variant.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
