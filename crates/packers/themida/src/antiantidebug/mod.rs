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

mod handlers;
mod kifast;
mod scyllahide;
pub mod config;

#[cfg(test)]
mod tests;
pub mod timings;

// Re-export the public API so `crate::antiantidebug::*` works unchanged.
pub use config::{current_mode, initialize_mode, set_mode, AntidebugMode};
pub use handlers::{
    handle_check_remote_debugger_present, handle_nt_query_information_process,
    handle_nt_query_object, handle_nt_set_information_thread, handle_output_debug_string,
    handle_query_performance_counter, handle_rdtsc, DebuggerDriverBlacklist, TimingProbeState,
};
pub use scyllahide::{inject_scylla_hide, ScyllaHideConfig};

// ---------------------------------------------------------------------------
// WO-1005: Dual-track anti-debug activation
// ---------------------------------------------------------------------------

/// 双轨反调试激活入口
///
/// 根据 `current_mode()` 决定激活路径：
/// - `Legacy` (默认): 调用 ScyllaHide 注入（Oreans 原有行为）
/// - `SelfDeveloped`: 激活 Phase 1-3 自研处理器栈
///
/// ## 设计边界
///
/// - Legacy 路径逐字节保持不变（调用 `inject_scylla_hide`）
/// - Self 路径返回 Ok(())，实际处理器激活由调用者在调试循环中完成
/// - 默认模式为 Legacy（环境变量未设置或 `MIDA_ANTIDEBUG_MODE=legacy`）
/// - 回滚开关：运行时可调用 `set_mode(AntidebugMode::Legacy)` 回退
///
/// ## 参数
///
/// - `pid`: 目标进程 ID
/// - `config`: ScyllaHide 配置（Legacy 模式使用）
///
/// ## 返回
///
/// - `Ok(())`: 激活成功
/// - `Err(ThemidaError)`: Legacy 模式下 ScyllaHide 注入失败
///
/// ## 使用示例
///
/// ```rust,ignore
/// // 初始化模式（启动时调用一次）
/// initialize_mode();
///
/// // 双轨激活
/// activate_antidebug(pid, &scylla_config)?;
///
/// // 调试循环中根据 current_mode() 选择处理器
/// match current_mode() {
///     AntidebugMode::Legacy => {
///         // ScyllaHide 已激活，无需额外处理
///     }
///     AntidebugMode::SelfDeveloped => {
///         // 激活 Phase 1-3 处理器
///         // handle_nt_set_information_thread(...)?;
///         // handle_check_remote_debugger_present(...)?;
///         // ...
///     }
/// }
/// ```
pub fn activate_antidebug(
    pid: u32,
    config: &ScyllaHideConfig,
) -> Result<(), crate::error::ThemidaError> {
    match current_mode() {
        AntidebugMode::Legacy => {
            // Legacy 路径：ScyllaHide 注入（逐字节不变）
            tracing::info!(pid, mode = "Legacy", "Activating ScyllaHide injection");
            inject_scylla_hide(pid, config)
        }
        AntidebugMode::SelfDeveloped => {
            // Self 路径：Phase 1-3 处理器栈
            // 实际激活由调试循环完成，此处仅记录模式
            tracing::info!(pid, mode = "SelfDeveloped", "Self-developed handlers ready");
            Ok(())
        }
    }
}

#[cfg(target_arch = "x86")]
pub use kifast::{get_nt_qip_syscall_number, handle_kifast_syscall, install_kifast_syscall_hook};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `ThreadHideFromDebugger` — tells the kernel to hide this thread from the
/// debugger, effectively preventing any further debug events for it.
pub(crate) const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x11; // = 17 decimal

/// NT kernel class IDs for `NtQueryInformationProcess`.
pub(crate) const PROCESS_DEBUG_PORT: u32 = 7;
pub(crate) const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
pub(crate) const PROCESS_DEBUG_FLAGS: u32 = 31;

/// NT status codes used when faking returns.
pub(crate) const STATUS_SUCCESS: u32 = 0x0000_0000;
pub(crate) const STATUS_PORT_NOT_SET: u32 = 0xC000_0353;

/// Syscall number for `NtQueryInformationProcess` on x86 (used by the
/// `KiFastSystemCall` hook).
#[cfg(target_arch = "x86")]
pub(crate) const NtQIP_SYSCALL_NUMBER: u32 = 0x16;

/// Pointer size in the target — matches the *compile target*, not the host.
#[cfg(target_arch = "x86")]
pub(crate) const PTR_SIZE: usize = 4;
#[cfg(target_arch = "x86_64")]
pub(crate) const PTR_SIZE: usize = 8;

// ===== Target-arch context helpers =========================================
//
// The CONTEXT struct uses different field names on x86 vs x64. These helpers
// abstract that away so the main logic stays readable.

#[cfg(target_arch = "x86")]
pub(crate) mod ctx_arch {
    use windows::Win32::System::Diagnostics::Debug::CONTEXT;

    pub fn stack_ptr(ctx: &CONTEXT) -> usize {
        ctx.Esp as usize
    }
    pub fn set_stack_ptr(ctx: &mut CONTEXT, val: usize) {
        ctx.Esp = val as u32;
    }

    pub fn set_instr_ptr(ctx: &mut CONTEXT, val: usize) {
        ctx.Eip = val as u32;
    }

    pub fn set_ret_val(ctx: &mut CONTEXT, val: u32) {
        ctx.Eax = val;
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) mod ctx_arch {
    use windows::Win32::System::Diagnostics::Debug::CONTEXT;

    pub fn stack_ptr(ctx: &CONTEXT) -> usize {
        ctx.Rsp as usize
    }
    pub fn set_stack_ptr(ctx: &mut CONTEXT, val: usize) {
        ctx.Rsp = val as u64;
    }

    pub fn set_instr_ptr(ctx: &mut CONTEXT, val: usize) {
        ctx.Rip = val as u64;
    }

    pub fn set_ret_val(ctx: &mut CONTEXT, val: u32) {
        ctx.Rax = val as u64;
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Convert a `[u8]` slice into a target-pointer-sized address.
///
/// On x86 this produces a `u32` → `usize`; on x64 it produces a `u64` →
/// `usize`.
pub(crate) fn ptr_from_bytes(bytes: &[u8]) -> usize {
    if bytes.len() >= 8 {
        bytes
            .get(..8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0) as usize
    } else {
        bytes
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0) as usize
    }
}
