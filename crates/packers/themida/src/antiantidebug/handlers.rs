//! Handler functions for NtSetInformationThread and NtQueryInformationProcess
//! anti-debug bypasses.

use mida_core::DebuggerCore;
use tracing::{debug, info, trace, warn};

use crate::error::ThemidaError;

use super::{
    ctx_arch, ptr_from_bytes, PTR_SIZE, STATUS_SUCCESS, THREAD_HIDE_FROM_DEBUGGER,
};

// ---------------------------------------------------------------------------
// NtSetInformationThread bypass
// ---------------------------------------------------------------------------

/// Handle a call to `NtSetInformationThread(ThreadHideFromDebugger)`.
///
/// ## What Themida does
///
/// Themida calls `NtSetInformationThread(GetCurrentThread(),
/// ThreadHideFromDebugger, NULL, 0)` to hide a thread from the debugger.
/// Once hidden, the thread no longer generates debug events — so we lose
/// it entirely.
///
/// ## How we counteract
///
/// When the debug loop detects execution at `NtSetInformationThread` (via a
/// hardware or software breakpoint on its address), it calls this function.
/// If the `ThreadInformationClass` parameter is `ThreadHideFromDebugger`
/// (0x11), we:
///
/// 1. Skip the call entirely by jumping EIP/RIP over the function body and
///    adjusting ESP/RSP past the 4 parameters + return address.
/// 2. Set EAX/RAX to `STATUS_SUCCESS` (0) so Themida thinks the call
///    succeeded.
///
/// ## Return value
///
/// - `Ok(true)` — the call was intercepted and patched.
/// - `Ok(false)` — not a `ThreadHideFromDebugger` call; caller should let it
///   execute normally.
///
/// ## Reference
///
/// `Themida.pas` → `OnHardwareBreakpoint`, NtSIT branch (lines 260–271):
/// ```pascal
/// else if EIP = NtSIT then
/// begin
///   if RPM(C.Esp, @Buf, 4) and (Buf < FImageBoundary)
///      and RPM(C.Esp + 8, @InfoClass, 4)
///      and (InfoClass = 17) then
///   begin
///     Log(ltGood, 'Ignoring NtSetInformationThread(ThreadHideFromDebugger)');
///     Inc(C.Esp, 5 * 4); // 4 parameters + ret
///     C.Eip := Buf;
///     C.Eax := STATUS_SUCCESS;
///     ...
///   end;
/// end;
/// ```
pub fn handle_nt_set_information_thread(
    debugger: &dyn DebuggerCore,
    thread_id: u32,
) -> Result<bool, ThemidaError> {
    // 1. Read the current thread context (control + integer only; avoid
    //    ERROR_PARTIAL_COPY from CONTEXT_ALL on Themida targets).
    let mut ctx = debugger
        .get_thread_context_control_integer(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("get_thread_context_control_integer: {e}")))?;

    let sp = ctx_arch::stack_ptr(&ctx);

    // 2. Read the return address from [ESP] (4 or 8 bytes depending on arch).
    //    This is the address the `call` instruction pushed.
    let mut ret_addr_bytes = vec![0u8; PTR_SIZE];
    let read = debugger
        .read_memory(sp, &mut ret_addr_bytes)
        .map_err(|e| ThemidaError::Debugger(format!("read ret addr: {e}")))?;
    if read != PTR_SIZE {
        warn!(thread_id, sp, "Short read of return address");
        return Ok(false);
    }
    let ret_addr = ptr_from_bytes(&ret_addr_bytes);

    // 3. Read ThreadInformationClass from [ESP + 2*PTR_SIZE].
    //    The stack layout at NtSetInformationThread entry is:
    //      [ESP + 0*PTR_SIZE] = return address
    //      [ESP + 1*PTR_SIZE] = ThreadHandle  (arg 1)
    //      [ESP + 2*PTR_SIZE] = ThreadInformationClass (arg 2)
    let info_class_offset = sp + 2 * PTR_SIZE;
    let mut info_class_bytes = vec![0u8; 4];
    let read = debugger
        .read_memory(info_class_offset, &mut info_class_bytes)
        .map_err(|e| ThemidaError::Debugger(format!("read info class: {e}")))?;
    if read != 4 {
        warn!(thread_id, "Short read of ThreadInformationClass");
        return Ok(false);
    }
    let info_class = info_class_bytes.get(..4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| ThemidaError::Debugger("Failed to parse info_class".into()))?;

    // 4. Check whether this is ThreadHideFromDebugger.
    if info_class != THREAD_HIDE_FROM_DEBUGGER {
        trace!(
            thread_id,
            info_class,
            "NtSetInformationThread called, but not ThreadHideFromDebugger"
        );
        return Ok(false);
    }

    debug!(thread_id, %ret_addr, "NtSetInformationThread(ThreadHideFromDebugger) detected — skipping");

    // 5. Skip the call: adjust ESP past 4 parameters + return address
    //    (5 × PTR_SIZE), set EIP to the return address, and set EAX to
    //    STATUS_SUCCESS.
    let new_sp = sp + 5 * PTR_SIZE;
    ctx_arch::set_stack_ptr(&mut ctx, new_sp);
    ctx_arch::set_instr_ptr(&mut ctx, ret_addr);
    ctx_arch::set_ret_val(&mut ctx, STATUS_SUCCESS);

    // 6. Write the modified context back.
    debugger
        .set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("set_thread_context: {e}")))?;

    info!("Ignored NtSetInformationThread(ThreadHideFromDebugger)");
    Ok(true)
}

// ---------------------------------------------------------------------------
// NtQueryInformationProcess bypass
// ---------------------------------------------------------------------------

