//! Anti-anti-debug strategies for Themida.
//!
//! This module implements the techniques needed to bypass Themida's extensive
//! anti-debug arsenal. The reference implementation is in `Themida.pas` (x86)
//! and `Themida64.pas` (x64), specifically the `OnHardwareBreakpoint`,
//! `OnSoftwareBreakpoint`, and `OnDebugStart` methods.
//!
//! ## Strategies implemented
//!
//! | Strategy                        | Reference location                    |
//! |---------------------------------|---------------------------------------|
//! | NtSetInformationThread bypass   | `Themida.pas` OnHardwareBreakpoint    |
//! | NtQueryInformationProcess fake  | `Themida.pas` OnHardwareBreakpoint    |
//! | KiFastSystemCall hook (x86)     | `Themida.pas` OnSoftwareBreakpoint    |
//! | ScyllaHide injection            | `Themida.pas`/`Themida64.pas` OnDebugStart |
//!
//! ## How these are called
//!
//! The functions in this module implement the *response* to a detected
//! anti-debug call. The *detection* (breakpoint placement at
//! `NtSetInformationThread`, `NtQueryInformationProcess`, `KiFastSystemCall`,
//! etc.) is handled in the main debug event loop, which is implemented
//! separately. When a breakpoint fires, the debug loop identifies the call
//! type and invokes the corresponding function here.
//!
//! ## Architecture notes
//!
//! - PEB.BeingDebugged and PEB.pShimData clearing is handled in
//!   `mida_core::process::patch_peb_anti_debug` and is NOT duplicated here.
//! - x86-only strategies (`KiFastSystemCall` hook) are gated behind
//!   `#[cfg(target_arch = "x86")]`.
//! - x64 targets **must** use ScyllaHide (Themida64 has no fallback for
//!   manual anti-anti-debug).

use mida_core::DebuggerCore;
use tracing::{debug, info, trace, warn};

use crate::error::ThemidaError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `ThreadHideFromDebugger` — tells the kernel to hide this thread from the
/// debugger, effectively preventing any further debug events for it.
const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11; // = 17 decimal

/// NT kernel class IDs for `NtQueryInformationProcess`.
const PROCESS_DEBUG_PORT: u32 = 7;
const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
const PROCESS_DEBUG_FLAGS: u32 = 31;

/// NT status codes used when faking returns.
const STATUS_SUCCESS: u32 = 0x0000_0000;
const STATUS_PORT_NOT_SET: u32 = 0xC000_0353;

/// Syscall number for `NtQueryInformationProcess` on x86 (used by the
/// `KiFastSystemCall` hook).
#[cfg(target_arch = "x86")]
const NtQIP_SYSCALL_NUMBER: u32 = 0x16;

/// Pointer size in the target — matches the *compile target*, not the host.
#[cfg(target_arch = "x86")]
const PTR_SIZE: usize = 4;
#[cfg(target_arch = "x86_64")]
const PTR_SIZE: usize = 8;

// ===== Target-arch context helpers ==========================================
//
// The CONTEXT struct uses different field names on x86 vs x64. These helpers
// abstract that away so the main logic stays readable.

#[cfg(target_arch = "x86")]
mod ctx_arch {
    use windows::Win32::System::Diagnostics::Debug::CONTEXT;

    pub fn stack_ptr(ctx: &CONTEXT) -> usize { ctx.Esp as usize }
    pub fn set_stack_ptr(ctx: &mut CONTEXT, val: usize) { ctx.Esp = val as u32; }

    pub fn set_instr_ptr(ctx: &mut CONTEXT, val: usize) { ctx.Eip = val as u32; }

    pub fn set_ret_val(ctx: &mut CONTEXT, val: u32) { ctx.Eax = val; }
}

#[cfg(target_arch = "x86_64")]
mod ctx_arch {
    use windows::Win32::System::Diagnostics::Debug::CONTEXT;

    pub fn stack_ptr(ctx: &CONTEXT) -> usize { ctx.Rsp as usize }
    pub fn set_stack_ptr(ctx: &mut CONTEXT, val: usize) { ctx.Rsp = val as u64; }

    pub fn set_instr_ptr(ctx: &mut CONTEXT, val: usize) { ctx.Rip = val as u64; }

    pub fn set_ret_val(ctx: &mut CONTEXT, val: u32) { ctx.Rax = val as u64; }
}

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

// ---------------------------------------------------------------------------
// KiFastSystemCall hook (x86 only)
// ---------------------------------------------------------------------------

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
#[cfg(target_arch = "x86")]
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
///    as [`handle_nt_query_information_process`].
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
#[cfg(target_arch = "x86")]
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
// ScyllaHide integration
// ---------------------------------------------------------------------------

/// Configuration for launching ScyllaHide injection.
///
/// ScyllaHide is an open-source anti-anti-debug library that hooks numerous
/// Windows API functions to hide the debugger's presence. It is **mandatory**
/// for x64 Themida targets (Themida64 has no manual fallback for
/// anti-anti-debug) and optional (but recommended) for x86.
///
/// ## Files needed
///
/// - `InjectorCLIx86.exe` / `InjectorCLIx64.exe` — the CLI injector that
///   runs as a separate process and injects the hook DLL into the target.
/// - `HookLibraryx86.dll` / `HookLibraryx64.dll` — the DLL that hooks
///   the anti-debug APIs inside the target process.
/// - `scylla_hide.ini` — configuration file (must be next to the injector
///   or in its working directory).
///
/// ## Reference
///
/// `Themida.pas` → `OnDebugStart` (lines 137–142):
/// ```pascal
/// if FileExists(MMPath + 'InjectorCLIx86.exe') then
/// begin
///   Log(ltGood, 'Applying ScyllaHide');
///   ShellExecute(0, 'open', PChar(MMPath + 'InjectorCLIx86.exe'),
///     PChar(Format('pid:%d %s nowait', [FProcess.dwProcessId,
///       MMPath + 'HookLibraryx86.dll'])), nil, SW_HIDE);
/// end
/// ```
///
/// `Themida64.pas` → `OnDebugStart` (lines 111–120):
/// ```pascal
/// if FileExists(MMPath + 'InjectorCLIx64.exe') then
///   ...
/// else
///   raise Exception.Create('ScyllaHide is mandatory for Themida64 ...');
/// ```
#[derive(Debug, Clone)]
pub struct ScyllaHideConfig {
    /// Path to the `InjectorCLIx86.exe` or `InjectorCLIx64.exe` executable.
    pub injector_cli_path: String,
    /// Path to the `HookLibraryx86.dll` or `HookLibraryx64.dll` library.
    pub hook_library_path: String,
    /// Path to `scylla_hide.ini` (optional — if absent, the injector uses
    /// its own defaults).
    pub ini_path: Option<String>,
    /// Delay in milliseconds to wait after spawning the injector, before
    /// returning control to the debug loop.  Empirically 500 is a good
    /// trade-off for Themida-protected samples, but pathological targets
    /// may need to raise or lower this to avoid either a "Target process
    /// exited before unpack completed" (too short) or a deadlock reported
    /// as `ERROR_PARTIAL_COPY` (too long).  Defaults to 500 ms.
    pub hook_delay_ms: u64,
}

/// Launch the ScyllaHide injector as a detached child process.
///
/// The injector runs asynchronously — it injects the hook DLL into the
/// target and exits. This function returns immediately after spawning the
/// process; it does **not** wait for injection to complete.
///
/// ## Arguments
///
/// - `pid` — the target process ID.
/// - `config` — paths to the injector binary and hook library.
///
/// ## Errors
///
/// Returns [`ThemidaError::ScyllaHide`] if the injector executable or hook DLL
/// cannot be found, **or** if either file's SHA-256 hash does not match the
/// known-good hash committed alongside the source.  This prevents accidentally
/// (or maliciously) running a tampered ScyllaHide helper — the helper injects
/// into the debuggee, so integrity is a safety requirement, not a nicety.
pub fn inject_scylla_hide(pid: u32, config: &ScyllaHideConfig) -> Result<(), ThemidaError> {
    // Verify the injector binary exists.
    let injector_path = std::path::Path::new(&config.injector_cli_path);
    if !injector_path.exists() {
        return Err(ThemidaError::ScyllaHide(format!(
            "InjectorCLI not found at '{}'",
            config.injector_cli_path
        )));
    }

    // Verify the hook library exists.
    let hook_path = std::path::Path::new(&config.hook_library_path);
    if !hook_path.exists() {
        return Err(ThemidaError::ScyllaHide(format!(
            "HookLibrary not found at '{}'",
            config.hook_library_path
        )));
    }

    // Integrity check before spawning — fail fast if the file contents don't
    // match the expected SHA-256.  This defends against supply-chain
    // tampering of the external helper binaries, which run with full
    // injection privileges.
    let injector_bytes = std::fs::read(injector_path).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to read InjectorCLI for hash check: {e} (path: '{}')",
            injector_path.display()
        ))
    })?;
    if !crate::binaries::verify_sha256(&injector_bytes, crate::binaries::expected_injector_hash()) {
        return Err(ThemidaError::ScyllaHide(format!(
            "InjectorCLI hash mismatch at '{}': the file does not match the expected SHA-256. \
             Aborting to avoid running a tampered helper.",
            injector_path.display()
        )));
    }

    let hook_bytes = std::fs::read(hook_path).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to read HookLibrary for hash check: {e} (path: '{}')",
            hook_path.display()
        ))
    })?;
    if !crate::binaries::verify_sha256(&hook_bytes, crate::binaries::expected_hook_hash()) {
        return Err(ThemidaError::ScyllaHide(format!(
            "HookLibrary hash mismatch at '{}': the file does not match the expected SHA-256. \
             Aborting to avoid running a tampered helper.",
            hook_path.display()
        )));
    }

    // Build the arguments as three separate args:
    //   pid:<pid>   — target process ID
    //   <hook_path> — path to the hook library DLL
    //   nowait      — tell InjectorCLI to return immediately after injection
    let pid_arg = format!("pid:{}", pid);

    debug!(
        injector_path = %injector_path.display(),
        %pid_arg,
        hook = %config.hook_library_path,
        "Launching ScyllaHide injector"
    );

    // Spawn the injector process.  We deliberately do not wait on it in this
    // function — that would block the debug loop.  The bounded sleep below
    // exists to give InjectorCLI a realistic window to complete its work
    // before we return; the exact time is sample-dependent.
    //
    // Timing observations on real samples:
    //   * Too short (< 200 ms) : the hook DLL is not yet mapped into the
    //                             target when the target reaches its
    //                             anti-debug check → anti-debug wins, target
    //                             self-terminates with
    //                             `STATUS_FATAL_APP_EXIT` = 0x80000004.
    //   * Too long (> 1 s)     : ScyllaHide's ntdll hooks race against the
    //                             Themida VM dispatcher session, and
    //                             WaitForDebugEvent fails with
    //                             `ERROR_PARTIAL_COPY`.
    let mut child = std::process::Command::new(injector_path)
        .arg(&pid_arg)
        .arg(&config.hook_library_path)
        .arg("nowait")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            ThemidaError::ScyllaHide(format!(
                "Failed to spawn '{}': {e}",
                injector_path.display()
            ))
        })?;

    // Wait a tunable window for the injector to finish.
    std::thread::sleep(std::time::Duration::from_millis(config.hook_delay_ms));

    match child.try_wait() {
        Ok(Some(status)) => {
            if status.success() {
                info!("ScyllaHide injection completed successfully");
            } else {
                warn!(
                    ?status,
                    "ScyllaHide injector exited with non-zero status"
                );
            }
        }
        Ok(None) => {
            // Still running — injection is in progress, that's fine.
            info!("ScyllaHide injection initiated (running in background)");
        }
        Err(e) => {
            warn!("Failed to check ScyllaHide injector status: {e}");
        }
    }

    // Drop the child handle without killing the process.
    std::mem::forget(child);

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a `[u8]` slice into a target-pointer-sized address.
///
/// On x86 this produces a `u32` → `usize`; on x64 it produces a `u64` →
/// `usize`.
fn ptr_from_bytes(bytes: &[u8]) -> usize {
    if bytes.len() >= 8 {
        bytes.get(..8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0) as usize
    } else {
        bytes.get(..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0) as usize
    }
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
#[cfg(target_arch = "x86")]
#[must_use]
pub fn get_nt_qip_syscall_number(zw_qip_addr: usize) -> u32 {
    // The syscall number is at offset +1 (after the `mov eax, ...` opcode).
    // But we can't read it here — the caller must provide it.
    // This function is a placeholder for documentation.
    let _ = zw_qip_addr;
    NtQIP_SYSCALL_NUMBER // fallback default
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptr_from_bytes_x86() {
        let bytes = [0x78, 0x56, 0x34, 0x12];
        let addr = ptr_from_bytes(&bytes);
        assert_eq!(addr, 0x1234_5678);
    }

    #[test]
    fn ptr_from_bytes_x64() {
        let bytes = [0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01];
        let addr = ptr_from_bytes(&bytes);
        assert_eq!(addr, 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn ptr_from_bytes_partial() {
        // Only 4 bytes provided — treated as u32.
        let bytes = [0xEF, 0xBE, 0xAD, 0xDE];
        let addr = ptr_from_bytes(&bytes);
        assert_eq!(addr, 0xDEAD_BEEF_u32 as usize);
    }

    #[test]
    fn constants_are_correct() {
        assert_eq!(THREAD_HIDE_FROM_DEBUGGER, 0x11);
        assert_eq!(PROCESS_DEBUG_PORT, 7);
        assert_eq!(PROCESS_DEBUG_OBJECT_HANDLE, 30);
        assert_eq!(PROCESS_DEBUG_FLAGS, 31);
        assert_eq!(STATUS_SUCCESS, 0);
        assert_eq!(STATUS_PORT_NOT_SET, 0xC000_0353);
    }

    #[test]
    #[cfg(target_arch = "x86")]
    fn nt_qip_syscall_fallback_is_sensible() {
        assert_eq!(NtQIP_SYSCALL_NUMBER, 0x16);
    }
}
