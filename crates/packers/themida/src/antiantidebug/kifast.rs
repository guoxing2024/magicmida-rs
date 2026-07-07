//! KiFastSystemCall hook — x86 only.
//!
//! On 32-bit Windows, `KiFastSystemCall` is the ring-3 trampoline through
//! which `sysenter` is invoked. Themida may call it directly to bypass
//! user-mode API hooks. This module installs a software breakpoint and fakes
//! the return for debug-sensitive queries.

#![cfg(target_arch = "x86")]

use mida_core::DebuggerCore;
use tracing::{debug, info, warn};

use crate::error::ThemidaError;

use super::{
    PROCESS_DEBUG_FLAGS, PROCESS_DEBUG_OBJECT_HANDLE, PROCESS_DEBUG_PORT,
    NtQIP_SYSCALL_NUMBER, STATUS_PORT_NOT_SET, STATUS_SUCCESS,
};

/// Install a `KiFastSystemCall` hook for x86 targets.
///
/// ## Background
///
/// On 32-bit Windows, `KiFastSystemCall` is the ring-3 trampoline through
/// which `sysenter` is invoked:
///
/// ```asm
/// KiFastSystemCall:
///     mov  edx, esp       ; save user stack pointer
///     sysenter            ; enter kernel
///     ret                 ; (KiFastSystemCallRet — the kernel updates EIP to
///                         ;  this address before returning)
/// ```
///
/// Themida may call `KiFastSystemCall` directly (with the syscall number in
/// EAX) to bypass any user-mode API hooks we install.  By placing a software
/// breakpoint at the start of `KiFastSystemCall`, we can inspect the
/// syscall-number before it enters the kernel and fake the return for
/// debug-sensitive queries.
///
/// ## What this function does
///
/// 1. Checks that `kifast_syscall_addr` is valid.
/// 2. Sets a software (int3) breakpoint at that address via the debugger.
/// 3. The caller's debug loop must then watch for the INT3 at
///    `kifast_syscall_addr` and invoke [`handle_kifast_syscall`] when it
///    fires.
///
/// ## Reference
///
/// `Themida.pas` → `OnDebugStart` (lines 147–152):
/// ```pascal
/// KiFastSystemCall := GetProcAddress(GetModuleHandle('ntdll.dll'),
///     'KiFastSystemCall');
/// ...
/// SetSoftBP(KiFastSystemCall);
/// NtQIP := PCardinal(Cardinal(GetProcAddress(GetModuleHandle('ntdll.dll'),
///     'ZwQueryInformationProcess')) + 1)^;
/// ```
///
/// ## Safety
///
/// This function must only be called for x86 targets. It is gated behind
/// `#[cfg(target_arch = "x86")]` at compile time.
pub fn install_kifast_syscall_hook(
    debugger: &mut mida_core::WindowsDebugger,
    kifast_syscall_addr: usize,
) -> Result<(), ThemidaError> {
    if kifast_syscall_addr == 0 {
        return Err(ThemidaError::Debugger(
            "Invalid KiFastSystemCall address (0)".into(),
        ));
    }

    debug!(%kifast_syscall_addr, "Installing KiFastSystemCall hook");

    // Set a software breakpoint (INT3 / 0xCC) at KiFastSystemCall.
    // When the debug loop detects a breakpoint at this address, it must call
    // `handle_kifast_syscall()`.
    debugger
        .set_soft_breakpoint(kifast_syscall_addr)
        .map_err(|e| ThemidaError::Debugger(format!("set_soft_breakpoint: {e}")))?;

    info!(%kifast_syscall_addr, "KiFastSystemCall hook installed");
    Ok(())
}

/// Handle a hit on the `KiFastSystemCall` software breakpoint.
///
/// Called from the debug event loop when a breakpoint fires at
/// `KiFastSystemCall`'s address.
///
/// ## Logic
///
/// 1. Read EAX (the syscall number).
///    0x16 = `NtQueryInformationProcess`.
/// 2. If the syscall is `NtQueryInformationProcess`, read `ProcessInformationClass`
///    from the user stack (EDX points to the stack).
/// 3. If it's a debug-detection class (7, 30, or 31), fake the result by
///    writing to the output buffer and adjusting EIP/ESP/EAX — same approach
///    as [`super::handle_nt_query_information_process`].
/// 4. If it's NOT a debug-related syscall, let it execute normally by
///    restoring EDX (from ESP) and advancing EIP past the `sysenter`
///    instruction (EIP = kifast_syscall_addr + 2).
///
/// ## Reference
///
/// `Themida.pas` → `OnSoftwareBreakpoint`, KiFastSystemCall branch
/// (lines 356–382):
/// ```pascal
/// if not FWow64 and (BPA = KiFastSystemCall) then
/// begin
///   if (C.Eax = NtQIP) ... then
///   begin
///     ... fake the result ...
///   end
///   else
///   begin
///     C.Edx := C.Esp;
///     C.Eip := NativeUInt(KiFastSystemCall) + 2;
///   end;
/// end;
/// ```
pub fn handle_kifast_syscall(
    debugger: &mut dyn DebuggerCore,
    thread_id: u32,
    kifast_syscall_addr: usize,
    nt_qip_syscall_num: u32,
) -> Result<(), ThemidaError> {
    let mut ctx = debugger
        .get_thread_context_control_integer(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("get_thread_context_control_integer: {e}")))?;

    let sp = ctx.Esp as usize;
    let syscall_num = ctx.Eax;

    // Is this NtQueryInformationProcess?
    if syscall_num == nt_qip_syscall_num {
        // The user stack pointer is in EDX (set by KiFastSystemCall's
        // `mov edx, esp`). The stack layout is the same as for a direct
        // `NtQueryInformationProcess` call:
        //   [EDX + 0]  = return address
        //   [EDX + 4]  = ProcessHandle
        //   [EDX + 8]  = ProcessInformationClass
        //   [EDX + 12] = ProcessInformation (output buffer)
        let user_sp = ctx.Edx as usize;

        // Read return address.
        let mut ret_addr_bytes = [0u8; 4];
        let read = debugger
            .read_memory(user_sp, &mut ret_addr_bytes)
            .map_err(|e| ThemidaError::Debugger(format!("kifs: read ret addr: {e}")))?;
        if read != 4 {
            warn!(thread_id, "Short read of return address in KiFastSystemCall");
            return Ok(());
        }
        let ret_addr = u32::from_le_bytes(ret_addr_bytes) as usize;

        // Read ProcessInformationClass.
        let mut info_class_bytes = [0u8; 4];
        let read = debugger
            .read_memory(user_sp + 8, &mut info_class_bytes)
            .map_err(|e| ThemidaError::Debugger(format!("kifs: read info class: {e}")))?;
        if read != 4 {
            warn!(thread_id, "Short read of ProcessInformationClass in KiFastSystemCall");
            return Ok(());
        }
        let info_class = u32::from_le_bytes(info_class_bytes);

        // Handle debug-detection classes.
        if info_class == PROCESS_DEBUG_PORT
            || info_class == PROCESS_DEBUG_OBJECT_HANDLE
            || info_class == PROCESS_DEBUG_FLAGS
        {
            let description = match info_class {
                PROCESS_DEBUG_PORT => "ProcessDebugPort",
                PROCESS_DEBUG_OBJECT_HANDLE => "ProcessDebugObjectHandle",
                PROCESS_DEBUG_FLAGS => "ProcessDebugFlags",
                _ => unreachable!(),
            };

            debug!(thread_id, description, "Faking via KiFastSystemCall");

            // Read output buffer pointer from [user_sp + 12].
            let mut out_buf_bytes = [0u8; 4];
            let read = debugger
                .read_memory(user_sp + 12, &mut out_buf_bytes)
                .map_err(|e| ThemidaError::Debugger(format!("kifs: read out buf: {e}")))?;
            if read != 4 {
                warn!(thread_id, "Short read of output buf ptr in KiFastSystemCall");
                return Ok(());
            }
            let out_buf_addr = u32::from_le_bytes(out_buf_bytes) as usize;

            // Determine fake value and return status.
            let (fake_value, ret_status): (u32, u32) = match info_class {
                PROCESS_DEBUG_PORT => (0, STATUS_SUCCESS),
                PROCESS_DEBUG_OBJECT_HANDLE => (0, STATUS_PORT_NOT_SET),
                PROCESS_DEBUG_FLAGS => (1, STATUS_SUCCESS),
                _ => unreachable!(),
            };

            // Write the fake value to the output buffer.
            let value_bytes = fake_value.to_le_bytes();
            debugger
                .write_memory(out_buf_addr, &value_bytes)
                .map_err(|e| ThemidaError::Debugger(format!("kifs: write fake value: {e}")))?;

            // Skip the call: adjust the user stack past 5 params + ret
            // (6 * 4 bytes), set EIP to the return address, and set EAX.
            ctx.Esp = (user_sp + 6 * 4) as u32;
            ctx.Eip = ret_addr as u32;
            ctx.Eax = ret_status;

            debugger
                .set_thread_context(thread_id, &ctx)
                .map_err(|e| ThemidaError::Debugger(format!("kifs: set_thread_context: {e}")))?;

            info!(thread_id, description, "Faked NtQueryInformationProcess({description}) via KiFastSystemCall");
        } else {
            // Not a debug class — execute normally.
            // Restore EDX to point to the user stack (required by
            // KiFastSystemCall: `mov edx, esp`) and advance EIP past the
            // `sysenter` (2 bytes at `kifast_syscall_addr + 2` is
            // `KiFastSystemCallRet`).
            ctx.Edx = ctx.Esp;
            ctx.Eip = (kifast_syscall_addr + 2) as u32;

            debugger
                .set_thread_context(thread_id, &ctx)
                .map_err(|e| ThemidaError::Debugger(format!("kifs: set_thread_context (normal): {e}")))?;
        }
    } else {
        // Not NtQueryInformationProcess — let it execute normally.
        // Set EDX = ESP (KiFastSystemCall convention) and EIP = syscall_addr + 2
        // (skip the `mov edx, esp; sysenter` pair).
        ctx.Edx = ctx.Esp;
        ctx.Eip = (kifast_syscall_addr + 2) as u32;

        debugger
            .set_thread_context(thread_id, &ctx)
            .map_err(|e| ThemidaError::Debugger(format!("kifs: set_thread_context: {e}")))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers for looking up addresses in the target
// ---------------------------------------------------------------------------

/// NT syscall number for `NtQueryInformationProcess` on x86.
///
/// This is the value expected in EAX when `KiFastSystemCall` is invoked for
/// `NtQueryInformationProcess`. It can be obtained by reading
/// `*(ZwQueryInformationProcess + 1)` — the second byte of the stub:
///
/// ```asm
/// mov eax, <syscall_number>   ; 5 bytes
/// call/wait                    ; etc.
/// ```
///
/// This value varies across Windows versions. The caller should read it
/// from the target's ntdll.dll export `ZwQueryInformationProcess`.
#[must_use]
pub fn get_nt_qip_syscall_number(zw_qip_addr: usize) -> u32 {
    // The syscall number is at offset +1 (after the `mov eax, ...` opcode).
    // But we can't read it here — the caller must provide it.
    // This function is a placeholder for documentation.
    let _ = zw_qip_addr;
    NtQIP_SYSCALL_NUMBER // fallback default
}
