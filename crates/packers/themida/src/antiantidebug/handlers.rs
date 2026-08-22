//! Handler functions for NtSetInformationThread and NtQueryInformationProcess
//! anti-debug bypasses.

use mida_core::DebuggerCore;
use tracing::{debug, info, trace, warn};

use crate::error::ThemidaError;

use super::{
    ctx_arch, ptr_from_bytes, PROCESS_DEBUG_FLAGS, PROCESS_DEBUG_OBJECT_HANDLE, PROCESS_DEBUG_PORT,
    PTR_SIZE, STATUS_PORT_NOT_SET, STATUS_SUCCESS, THREAD_HIDE_FROM_DEBUGGER,
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
    let info_class = info_class_bytes
        .get(..4)
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
        // The early-return guard above already filters out non-debug classes,
        // so this branch is unreachable in the current control flow. Kept as a
        // safe fallback rather than `unreachable!()` so a future refactor that
        // loosens the guard cannot panic inside the debug loop.
        _ => {
            trace!(
                thread_id,
                process_information_class,
                "NtQueryInformationProcess: unhandled class, ignoring"
            );
            return Ok(());
        }
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
        // Unreachable thanks to the early-return guard above, but fall back to
        // a no-op success rather than panicking inside the debug loop.
        _ => {
            trace!(
                thread_id,
                process_information_class,
                "NtQueryInformationProcess: unhandled class at fake-value stage, skipping"
            );
            return Ok(());
        }
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
        description, "Faked NtQueryInformationProcess({description})"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// WO-1002: CheckRemoteDebuggerPresent (CRDP) counteraction
// ---------------------------------------------------------------------------

/// Handle a call to `CheckRemoteDebuggerPresent(hProcess, &pbDebuggerPresent)`.
///
/// ## What protected code does
///
/// A common auxiliary probe: calls CRDP with the current process handle and
/// a BOOL output pointer; a debugger present makes it write TRUE.
///
/// ## How we counteract (forged-false model)
///
/// When the debug loop detects execution at the CRDP address, we:
/// 1. Read the output pointer (2nd stack arg, PTR_SIZE-aligned).
/// 2. Write FALSE (0) to that output pointer in the target.
/// 3. Skip the call (ESP past 3 args + ret) and set RAX = STATUS_SUCCESS.
///
/// This is the "forged return" model from WO-902 Phase 2 — behaviour-level
/// parity with the public ScyllaHide technique list, no source reference.
///
/// ## Return value
///
/// Ok(()) when intercepted and forged; Err otherwise (caller should not
/// treat a failure as a successful counteraction).
pub fn handle_check_remote_debugger_present(
    debugger: &mut dyn DebuggerCore,
    thread_id: u32,
    output_ptr: u64,
) -> Result<(), ThemidaError> {
    // 1. Forge FALSE into the output pointer (target memory write is part of
    //    the counteraction contract, allowed by core debugger semantics).
    let false_val = 0u32.to_le_bytes();
    let _ = debugger.write_memory(output_ptr as usize, &false_val);
    // 2. Read the full context to skip the call.
    let mut ctx = debugger
        .get_thread_context(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("get_thread_context: {e}")))?;
    let sp = ctx_arch::stack_ptr(&ctx);
    let ret_addr = {
        let mut buf = [0u8; 8];
        let _ = debugger.read_memory(sp as usize, &mut buf);
        u64::from_le_bytes(buf)
    };
    // 3. Skip 3 args + return address (4 * PTR_SIZE), set RAX = 0.
    let new_sp = sp + 4 * PTR_SIZE;
    ctx_arch::set_stack_ptr(&mut ctx, new_sp);
    ctx_arch::set_instr_ptr(&mut ctx, ret_addr as usize);
    ctx_arch::set_ret_val(&mut ctx, 0u32);
    debugger
        .set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("set_thread_context: {e}")))?;
    info!(
        thread_id,
        output_ptr = format_args!("{output_ptr:#x}"),
        "Forged CheckRemoteDebuggerPresent (FALSE)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// WO-1002: Timing probe interception (RDTSC / QueryPerformanceCounter)
// ---------------------------------------------------------------------------

use super::timings::{classify_probe, masked_delta, ProbeClass};

/// 时序探测状态（每个线程独立跟踪）
pub struct TimingProbeState {
    last_tick: u64,
    consecutive_suspicious: usize,
    window_open: bool,
    probes_masked_in_window: usize,
}

impl TimingProbeState {
    pub fn new() -> Self {
        Self {
            last_tick: 0,
            consecutive_suspicious: 0,
            window_open: false,
            probes_masked_in_window: 0,
        }
    }

    /// 处理一次时序探测，返回应该返回给调用者的 tick 值
    pub fn handle_probe(&mut self, real_tick: u64) -> u64 {
        // 如果这是第一次探测，直接返回真实值
        if self.last_tick == 0 {
            self.last_tick = real_tick;
            return real_tick;
        }

        let delta = real_tick.saturating_sub(self.last_tick);
        let classification = classify_probe(delta);

        match classification {
            ProbeClass::Suspicious => {
                self.consecutive_suspicious += 1;

                // 打开或维持补丁窗口
                if !self.window_open && self.consecutive_suspicious <= super::timings::TIMING_PATCH_WINDOW {
                    self.window_open = true;
                    self.probes_masked_in_window = 0;
                }

                // 在窗口内，返回掩码值
                if self.window_open && self.probes_masked_in_window < super::timings::TIMING_PATCH_WINDOW {
                    self.probes_masked_in_window += 1;
                    let masked = masked_delta(self.probes_masked_in_window - 1);
                    trace!(
                        real_tick,
                        masked,
                        consecutive = self.consecutive_suspicious,
                        "Masked suspicious timing probe"
                    );
                    // 返回掩码值（累加到上次tick）
                    let forged = self.last_tick + masked;
                    self.last_tick = forged;
                    return forged;
                } else {
                    // 窗口已满，关闭窗口，重置状态
                    self.window_open = false;
                    self.consecutive_suspicious = 0;
                    self.probes_masked_in_window = 0;
                }
            }
            ProbeClass::Benign => {
                // 良性探测，重置可疑计数
                self.consecutive_suspicious = 0;
                if self.window_open {
                    self.window_open = false;
                    self.probes_masked_in_window = 0;
                }
            }
        }

        // 返回真实值
        self.last_tick = real_tick;
        real_tick
    }
}

/// 处理 RDTSC 指令拦截
///
/// ## 工作原理
///
/// RDTSC 返回 CPU 时间戳计数器（EDX:EAX 存储 64 位值）。时序攻击通过
/// 连续调用 RDTSC 并测量 delta 来检测调试器开销。
///
/// ## 对抗策略
///
/// 1. 读取真实的 TSC 值
/// 2. 通过 `TimingProbeState` 分类（可疑/良性）
/// 3. 如果在补丁窗口内，伪造返回值（掩码 delta）
/// 4. 写入 EDX:EAX 并继续执行
///
/// ## 返回值
///
/// Ok(true) = 已拦截并伪造；Ok(false) = 未拦截（正常执行）
pub fn handle_rdtsc(
    debugger: &mut dyn DebuggerCore,
    thread_id: u32,
    state: &mut TimingProbeState,
) -> Result<bool, ThemidaError> {
    // 读取真实 TSC（通过 __rdtsc intrinsic）
    #[cfg(target_arch = "x86_64")]
    let real_tsc = unsafe { core::arch::x86_64::_rdtsc() };

    #[cfg(target_arch = "x86")]
    let real_tsc = unsafe { core::arch::x86::_rdtsc() };

    // 通过状态机决定返回值
    let returned_tsc = state.handle_probe(real_tsc);

    // 如果返回值被掩码，修改线程上下文
    if returned_tsc != real_tsc {
        let mut ctx = debugger
            .get_thread_context(thread_id)
            .map_err(|e| ThemidaError::Debugger(format!("get_thread_context: {e}")))?;

        // RDTSC 结果：EDX = 高32位，EAX = 低32位
        let low = (returned_tsc & 0xFFFF_FFFF) as u32;
        let high = (returned_tsc >> 32) as u32;

        #[cfg(target_arch = "x86_64")]
        {
            ctx.Rax = low as u64;
            ctx.Rdx = high as u64;
            // 跳过 RDTSC 指令（2 字节：0x0F 0x31）
            ctx.Rip += 2;
        }

        #[cfg(target_arch = "x86")]
        {
            ctx.Eax = low;
            ctx.Edx = high;
            // 跳过 RDTSC 指令（2 字节）
            ctx.Eip += 2;
        }

        debugger
            .set_thread_context(thread_id, &ctx)
            .map_err(|e| ThemidaError::Debugger(format!("set_thread_context: {e}")))?;

        trace!(
            thread_id,
            real_tsc,
            returned_tsc,
            "Intercepted RDTSC and forged result"
        );
        return Ok(true);
    }

    // 未掩码，正常执行
    Ok(false)
}

/// 处理 QueryPerformanceCounter 调用拦截
///
/// ## 工作原理
///
/// QPC 是 Windows 高精度计时 API，原型：
/// ```c
/// BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
/// ```
///
/// ## 对抗策略
///
/// 1. 读取真实的 QPC 值（通过 QueryPerformanceCounter）
/// 2. 通过 `TimingProbeState` 分类
/// 3. 如果在补丁窗口内，伪造输出指针的值
/// 4. 跳过调用，设置返回值为 TRUE
///
/// ## 参数
///
/// - `output_ptr`: lpPerformanceCount 参数（栈上第一个参数）
pub fn handle_query_performance_counter(
    debugger: &mut dyn DebuggerCore,
    thread_id: u32,
    output_ptr: u64,
    state: &mut TimingProbeState,
) -> Result<(), ThemidaError> {
    // 读取真实的 QPC 值
    let real_qpc = {
        use windows::Win32::System::Performance::QueryPerformanceCounter;
        let mut counter = 0i64;
        unsafe {
            let _ = QueryPerformanceCounter(&mut counter);
        }
        counter as u64
    };

    // 通过状态机决定返回值
    let returned_qpc = state.handle_probe(real_qpc);

    // 写入（可能掩码的）值到输出指针
    let qpc_bytes = returned_qpc.to_le_bytes();
    let _ = debugger.write_memory(output_ptr as usize, &qpc_bytes);

    // 跳过调用，设置返回值为 TRUE (1)
    let mut ctx = debugger
        .get_thread_context(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("get_thread_context: {e}")))?;

    let sp = ctx_arch::stack_ptr(&ctx);
    let ret_addr = {
        let mut buf = [0u8; 8];
        let _ = debugger.read_memory(sp as usize, &mut buf);
        u64::from_le_bytes(buf)
    };

    // 跳过 1 个参数 + 返回地址 (2 * PTR_SIZE)
    let new_sp = sp + 2 * PTR_SIZE;
    ctx_arch::set_stack_ptr(&mut ctx, new_sp);
    ctx_arch::set_instr_ptr(&mut ctx, ret_addr as usize);
    ctx_arch::set_ret_val(&mut ctx, 1u32); // TRUE

    debugger
        .set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("set_thread_context: {e}")))?;

    if returned_qpc != real_qpc {
        trace!(
            thread_id,
            output_ptr = format_args!("{output_ptr:#x}"),
            real_qpc,
            returned_qpc,
            "Intercepted QueryPerformanceCounter and forged result"
        );
    }

    Ok(())
}
