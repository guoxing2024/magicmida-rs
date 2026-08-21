//! Host-side capability adapter for the extracted AV/OEP decision (P3-D).
//!
//! Implements `mida_packers_themida::AvOepQuery` over the live CLI session:
//! every decision-side capability maps to a concrete debugger / guard /
//! context operation. This is the only place the CLI keeps AV/OEP
//! capability execution; the decision body lives in the themida crate.

use mida_core::DebuggerCore;
use mida_packers_themida::{
    handle_tls_callbacks, install_code_section_guard, is_oep_virtualized, process_guarded_access,
    remove_code_section_guard, try_find_correct_oep, AvOepQuery, GuardAccessResult, LogLevel,
    ThemidaState, TlsCallbackResult,
};
use windows::Win32::Foundation::HANDLE;

use super::session::{set_thread_context_control, ProcessSession};
use crate::log::{self, LogType};

/// Capability adapter: holds the session pieces the decision needs. The
/// guarded `.text` range is pinned at construction (image base + section 0
/// layout), so the guard ops do not alias `ThemidaState`.
pub(super) struct AvQueryCtx<'a> {
    pub dbg: &'a mut ProcessSession,
    pub h_process: HANDLE,
    pub guard_protection: u32,
    pub image_base_usize: usize,
    pub image_boundary: usize,
    pub text_start: usize,
    pub text_end: usize,
}

impl AvOepQuery for AvQueryCtx<'_> {
    fn log(&mut self, level: LogLevel, message: &str) {
        let ty = match level {
            LogLevel::Debug => LogType::Info,
            LogLevel::Info => LogType::Info,
            LogLevel::Warn => LogType::Fatal,
        };
        log::log(ty, message);
    }

    fn image_base(&self) -> u64 {
        self.dbg.image_base()
    }

    fn process_guarded_access(
        &mut self,
        themida: &mut ThemidaState,
        target_address: usize,
        exception_addr: usize,
        thread_id: u32,
        exc_type: u8,
    ) -> Result<GuardAccessResult, String> {
        process_guarded_access(
            &mut *self.dbg,
            self.h_process,
            themida,
            target_address,
            exception_addr,
            thread_id,
            self.image_base_usize,
            self.image_boundary,
            self.text_start,
            self.text_end,
            exc_type,
        )
        .map_err(|e| e.to_string())
    }

    fn read_ret_addr(&mut self, thread_id: u32) -> Option<u64> {
        let ctx = self.dbg.get_thread_context_control(thread_id).ok()?;
        let mut ret_bytes = [0u8; 8];
        self.dbg
            .read_memory(ctx.Rsp as usize, &mut ret_bytes)
            .ok()?;
        Some(u64::from_le_bytes(ret_bytes))
    }

    fn handle_tls_callbacks(
        &mut self,
        address: usize,
        tls_total: u32,
        tls_counter: &mut u32,
    ) -> Result<TlsCallbackResult, String> {
        handle_tls_callbacks(&mut *self.dbg, address, 8u32, tls_total, tls_counter)
            .map_err(|e| e.to_string())
    }

    fn try_find_correct_oep(
        &mut self,
        themida: &mut ThemidaState,
        pe_entry_point: usize,
    ) -> Option<usize> {
        try_find_correct_oep(
            &*self.dbg,
            pe_entry_point,
            self.text_start,
            self.text_end.saturating_sub(self.text_start),
            themida.pe_info.major_linker_version,
        )
        .ok()
        .flatten()
    }

    fn scan_for_oep(&mut self, text_rva: u32, text_size: u32) -> Option<usize> {
        mida_packers_themida::find_real_oep_by_scanning(
            &*self.dbg,
            self.image_base_usize,
            text_rva,
            text_size,
        )
        .ok()
        .flatten()
    }

    fn is_oep_virtualized(&mut self, oep: usize, tm_start: usize) -> bool {
        is_oep_virtualized(&*self.dbg, oep, tm_start)
    }

    fn read_code_bytes(&mut self, address: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.dbg.read_memory(address, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    }

    fn remove_code_guard(&mut self) -> Result<(), String> {
        remove_code_section_guard(
            self.h_process,
            self.text_start,
            self.text_end.saturating_sub(self.text_start),
        )
        .map_err(|e| e.to_string())
    }

    fn install_code_guard(&mut self) -> Result<(), String> {
        install_code_section_guard(
            self.h_process,
            self.text_start,
            self.text_end.saturating_sub(self.text_start),
            self.guard_protection,
        )
        .map_err(|e| e.to_string())
    }

    fn set_redirect(&mut self, rip: u64, rsp_delta: u64) -> Result<(), String> {
        let thread_id = self
            .dbg
            .pending_event_thread_id()
            .ok_or_else(|| "set_redirect: no pending event thread".to_string())?;
        let mut ctx = self
            .dbg
            .get_thread_context_control(thread_id)
            .map_err(|e| e.to_string())?;
        ctx.Rip = rip;
        ctx.Rsp = ctx.Rsp.wrapping_add(rsp_delta);
        set_thread_context_control(&*self.dbg, thread_id, &ctx).map_err(|e| e.to_string())
    }
}
