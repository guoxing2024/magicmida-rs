//! Handler functions for NtSetInformationThread and NtQueryInformationProcess
//! anti-debug bypasses.

use mida_core::DebuggerCore;
use tracing::{debug, info, trace, warn};

use crate::error::ThemidaError;

use super::{
    ctx_arch, ptr_from_bytes, PROCESS_DEBUG_FLAGS, PROCESS_DEBUG_OBJECT_HANDLE,
    PROCESS_DEBUG_PORT, PTR_SIZE, STATUS_PORT_NOT_SET, STATUS_SUCCESS,
    THREAD_HIDE_FROM_DEBUGGER,
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

/// Handle a call to `NtQueryInformationProcess` with a debug-detection class.
///
/// ## What Themida does
///
/// Themida queries:
///
/// | Class | Name                     | Honest response         |
/// |-------|--------------------------|-------------------------|
/// | 7     | ProcessDebugPort         | Non-zero debug port     |
/// | 30    | ProcessDebugObjectHandle | Debug object handle     |
/// | 31    | ProcessDebugFlags        | NoDebugInherit = 0      |
///
/// Any of these reveals that a debugger is attached.
///
/// ## How we counteract
///
/// We read the output-buffer pointer from the stack, write a fake value to it
/// in the target's memory, skip the call by adjusting EIP/RIP + ESP/RSP, and
/// set EAX/RAX to the appropriate NTSTATUS:
///
/// | Class | Written value | Returned NTSTATUS    |
/// |-------|---------------|----------------------|
/// | 7     | 0             | STATUS_SUCCESS (0)   |
/// | 30    | 0             | STATUS_PORT_NOT_SET  |
/// | 31    | 1             | STATUS_SUCCESS (0)   |
///
/// If `process_information_class` is not one of the three debug-related
/// classes, this function is a no-op (returns `Ok(())` without modifying
/// anything).
///
/// ## Reference
///
/// `Themida.pas` → `OnHardwareBreakpoint`, NtQIP64 / KiFastSystemCall branch
/// (lines 273–293, 356–382):
/// ```pascal
/// if RPM(C.Esp, @Buf, 4) and RPM(C.Esp + 8, @InfoClass, 4)
///    and ((InfoClass = 7) or (InfoClass = 30) or (InfoClass = 31)) then
/// begin
///   ... fake the result ...
/// end;
/// ```
pub fn handle_nt_query_information_process(
    debugger: &mut dyn DebuggerCore,
    thread_id: u32,
    process_information_class: u32,
) -> Result<(), ThemidaError> {
    // Early return if this isn't a debug-related query.
    if process_information_class != PROCESS_DEBUG_PORT
        && process_information_class != PROCESS_DEBUG_OBJECT_HANDLE
        && process_information_class != PROCESS_DEBUG_FLAGS
    {
        trace!(
            thread_id,
            process_information_class,
            "NtQueryInformationProcess called but not a debug class"
        );
        return Ok(());
    }

    let description = match process_information_class {
        PROCESS_DEBUG_PORT => "ProcessDebugPort",
        PROCESS_DEBUG_OBJECT_HANDLE => "ProcessDebugObjectHandle",
        PROCESS_DEBUG_FLAGS => "ProcessDebugFlags",
        _ => unreachable!(),
    };

    debug!(thread_id, description, "Faking NtQueryInformationProcess");

    // 1. Read the current thread context (control + integer only; avoid
    //    ERROR_PARTIAL_COPY from CONTEXT_ALL on Themida targets).
    let mut ctx = debugger
        .get_thread_context_control_integer(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("get_thread_context_control_integer: {e}")))?;

    let sp = ctx_arch::stack_ptr(&ctx);

    // 2. Read the return address from [ESP].
    let mut ret_addr_bytes = vec![0u8; PTR_SIZE];
    let read = debugger
        .read_memory(sp, &mut ret_addr_bytes)
        .map_err(|e| ThemidaError::Debugger(format!("read ret addr: {e}")))?;
    if read != PTR_SIZE {
        warn!(thread_id, "Short read of return address");
        return Ok(());
    }
    let ret_addr = ptr_from_bytes(&ret_addr_bytes);

    // 3. Read ProcessInformation (the output buffer) from [ESP + 3*PTR_SIZE].
    //    The stack layout at NtQueryInformationProcess entry is:
    //      [ESP + 0*PTR_SIZE] = return address
    //      [ESP + 1*PTR_SIZE] = ProcessHandle
    //      [ESP + 2*PTR_SIZE] = ProcessInformationClass
    //      [ESP + 3*PTR_SIZE] = ProcessInformation (the output buffer ptr)
    let out_buf_offset = sp + 3 * PTR_SIZE;
    let mut out_buf_bytes = vec![0u8; PTR_SIZE];
    let read = debugger
        .read_memory(out_buf_offset, &mut out_buf_bytes)
        .map_err(|e| ThemidaError::Debugger(format!("read output buf ptr: {e}")))?;
    if read != PTR_SIZE {
        warn!(thread_id, "Short read of output buffer pointer");
        return Ok(());
    }
    let out_buf_addr = ptr_from_bytes(&out_buf_bytes);

    // 4. Determine the fake value and NTSTATUS to return.
    let (fake_value, ret_status): (usize, u32) = match process_information_class {
        PROCESS_DEBUG_PORT => (0, STATUS_SUCCESS),
        PROCESS_DEBUG_OBJECT_HANDLE => (0, STATUS_PORT_NOT_SET),
        PROCESS_DEBUG_FLAGS => (1, STATUS_SUCCESS),
        _ => unreachable!(),
    };

    // 5. Write the fake value to the output buffer in the target.
    let value_bytes = if PTR_SIZE == 4 {
        (fake_value as u32).to_le_bytes().to_vec()
    } else {
        (fake_value as u64).to_le_bytes().to_vec()
    };
    let written = debugger
        .write_memory(out_buf_addr, &value_bytes)
        .map_err(|e| ThemidaError::Debugger(format!("write fake value: {e}")))?;
    if written != PTR_SIZE {
        warn!(
            thread_id,
            expected = PTR_SIZE,
            actual = written,
            "Partial write of fake NtQueryInformationProcess result"
        );
    }

    // 6. Skip the call: adjust ESP past 5 parameters + return address
    //    (6 × PTR_SIZE), set EIP to the return address, and set EAX to the
    //    status code.
    let new_sp = sp + 6 * PTR_SIZE;
    ctx_arch::set_stack_ptr(&mut ctx, new_sp);
    ctx_arch::set_instr_ptr(&mut ctx, ret_addr);
    ctx_arch::set_ret_val(&mut ctx, ret_status);

    // 7. Write the modified context back.
    debugger
        .set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("set_thread_context: {e}")))?;

    info!(
        thread_id,
        description,
        "Faked NtQueryInformationProcess({description})"
    );
    Ok(())
}
