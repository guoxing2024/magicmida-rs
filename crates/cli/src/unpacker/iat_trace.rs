//! IAT trace host executor (P3-C/D).
//!
//! The decision body (slot walk, single-step classification, slot-result
//! accounting, writeback policy) lives in
//! `mida_packers_themida::runtime::iat_trace_handler`. This module is the
//! thin host: it implements the [`IatTraceQuery`] capability seam over the
//! live session and executes the returned [`IatTraceAction`] — exactly one
//! continue per action, never an implicit double-continue.

use anyhow::{anyhow, Context};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

use mida_core::{ContinueStatus, DebuggerCore};
use mida_packers_themida::{
    advance_to_next_slot as themida_advance, handle_trace_step as themida_step, IatTraceAction,
    IatTraceQuery, LogLevel,
};

use super::session::{set_thread_context_control, ProcessSession};
use crate::log::{self, LogType};

pub(super) use mida_packers_themida::{IatTraceState, TracePhase};

/// Host capability adapter over the live session.
struct IatQueryCtx<'a> {
    dbg: &'a mut ProcessSession,
    /// Protection saved by the `executable` protect call, restored by the
    /// following non-executable call (protect -> write -> restore sequence).
    iat_old_protect: Option<PAGE_PROTECTION_FLAGS>,
}

impl IatTraceQuery for IatQueryCtx<'_> {
    fn log(&mut self, level: LogLevel, message: &str) {
        let ty = match level {
            LogLevel::Debug => LogType::Info,
            LogLevel::Info => LogType::Info,
            LogLevel::Warn => LogType::Fatal,
        };
        log::log(ty, message);
    }

    fn get_rip(&mut self, thread_id: u32) -> Option<u64> {
        self.dbg
            .get_thread_context_control(thread_id)
            .ok()
            .map(|ctx| ctx.Rip)
    }

    fn get_rsp(&mut self, thread_id: u32) -> Option<u64> {
        self.dbg
            .get_thread_context_control(thread_id)
            .ok()
            .map(|ctx| ctx.Rsp)
    }

    fn read_memory(&mut self, address: usize, buf: &mut [u8]) -> Result<usize, String> {
        self.dbg
            .read_memory(address, buf)
            .map_err(|e| e.to_string())
    }

    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, String> {
        self.dbg
            .write_memory(address, data)
            .map_err(|e| e.to_string())
    }

    fn is_at_themida_vm(&mut self, ip: usize) -> bool {
        mida_packers_themida::trace_imports::is_at_themida_vm(&*self.dbg, ip)
    }

    fn resolve_exit_process(&mut self) -> Result<usize, String> {
        let resolve = || -> anyhow::Result<usize> {
            // SAFETY: kernel32.dll is always loaded; the byte literals are
            // null-terminated and live for the call duration.
            unsafe {
                use windows::core::PCSTR;
                use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
                let k32 = GetModuleHandleA(PCSTR::from_raw(b"kernel32.dll\0".as_ptr()))
                    .context("kernel32.dll must be loaded")?;
                let addr = GetProcAddress(k32, PCSTR::from_raw(b"ExitProcess\0".as_ptr()))
                    .context("ExitProcess must exist in kernel32")?;
                Ok(addr as usize)
            }
        };
        resolve().map_err(|e| e.to_string())
    }

    fn protect_iat(&mut self, address: usize, size: usize, executable: bool) -> Result<(), String> {
        if executable {
            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            // SAFETY: dbg.process_handle() is a valid process handle; address
            // and size are valid IAT bounds; old_protect is a valid out-pointer.
            unsafe {
                VirtualProtectEx(
                    self.dbg.process_handle(),
                    address as *const std::ffi::c_void,
                    size,
                    PAGE_EXECUTE_READWRITE,
                    &mut old_protect,
                )
            }
            .map_err(|e| anyhow!("VirtualProtectEx failed for IAT: {e}").to_string())?;
            self.iat_old_protect = Some(old_protect);
            Ok(())
        } else {
            // Restore the protection saved by the preceding executable call
            // (the write happens between the two capability ops).
            let old = self.iat_old_protect.take().unwrap_or_default();
            let mut _restored = PAGE_PROTECTION_FLAGS::default();
            // SAFETY: same bounds as above; old holds the pre-write value.
            unsafe {
                VirtualProtectEx(
                    self.dbg.process_handle(),
                    address as *const std::ffi::c_void,
                    size,
                    old,
                    &mut _restored,
                )
            }
            .ok();
            Ok(())
        }
    }

    fn apis(&self) -> (usize, usize) {
        self.dbg
            .apis
            .as_ref()
            .map(|a| (a.sleep, a.lstrlen))
            .unwrap_or((0, 0))
    }
}

/// Apply the IAT trace action returned by the decision: exactly one
/// continue (or stop). Aborts the trace fail-closed when the host cannot
/// apply a context or resume.
fn execute_action(
    dbg: &mut ProcessSession,
    trace: &mut IatTraceState,
    action: IatTraceAction,
) -> Result<(), anyhow::Error> {
    match action {
        IatTraceAction::ContinueWithTrap => {
            let mut ctx = dbg
                .get_thread_context_control(trace.trace_thread_id)
                .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
            ctx.EFlags |= 0x100;
            set_thread_context_control(dbg, trace.trace_thread_id, &ctx)?;
            dbg.continue_event(trace.trace_thread_id, ContinueStatus::Continue)?;
            Ok(())
        }
        IatTraceAction::ContinueWithContext { rip, rsp } => {
            let mut ctx = dbg
                .get_thread_context_control(trace.trace_thread_id)
                .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
            ctx.Rip = rip;
            ctx.Rsp = rsp;
            ctx.EFlags |= 0x100;
            set_thread_context_control(dbg, trace.trace_thread_id, &ctx)?;
            dbg.continue_event(trace.trace_thread_id, ContinueStatus::Continue)?;
            Ok(())
        }
        IatTraceAction::TraceSlot { context } => {
            let mut ctx = dbg
                .get_thread_context_control(trace.trace_thread_id)
                .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
            ctx.Rip = context.rip;
            ctx.Rsp = context.rsp;
            ctx.EFlags = (ctx.EFlags & !0x100) | (context.eflags & 0x100);
            if let Err(e) = set_thread_context_control(dbg, trace.trace_thread_id, &ctx) {
                log::log(
                    LogType::Fatal,
                    &format!("set_thread_context_control failed: {e} - skipping slot"),
                );
                trace.failed_count += 1;
                trace.failed_slots.push(trace.current_slot);
                trace.current_slot += 1;
                return advance_to_next_slot(dbg, trace);
            }
            trace.trace_phase = TracePhase::Tracing;
            if let Err(e) = dbg.continue_event(trace.trace_thread_id, ContinueStatus::Continue) {
                log::log(
                    LogType::Fatal,
                    &format!("continue_event failed: {e} - aborting tracing"),
                );
                trace.abort(format!("continue_event failed: {e}"));
                return Ok(());
            }
            Ok(())
        }
        IatTraceAction::Finished { .. } => Ok(()),
    }
}

/// Handle a single step event during IAT tracing (host executor).
///
/// Signature kept stable for the debug-loop call site; the unused legacy
/// arguments are accepted for compatibility.
pub(super) fn handle_trace_step(
    dbg: &mut ProcessSession,
    trace: &mut IatTraceState,
    _address: u64,
    _image_base: usize,
    _image_boundary: usize,
) -> Result<(), anyhow::Error> {
    let mut query = IatQueryCtx {
        dbg: &mut *dbg,
        iat_old_protect: None,
    };
    let action = themida_step(&mut query, trace).map_err(anyhow::Error::msg)?;
    execute_action(dbg, trace, action)
}

/// Move to the next IAT slot that needs tracing, or write the resolved IAT
/// back (host executor).
pub(super) fn advance_to_next_slot(
    dbg: &mut ProcessSession,
    trace: &mut IatTraceState,
) -> Result<(), anyhow::Error> {
    let mut query = IatQueryCtx {
        dbg: &mut *dbg,
        iat_old_protect: None,
    };
    let action = themida_advance(&mut query, trace).map_err(anyhow::Error::msg)?;
    execute_action(dbg, trace, action)
}
