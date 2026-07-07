use anyhow::anyhow;
use tracing::{debug, info, warn};
use windows::Win32::Foundation::HANDLE;
use mida_core::{ContinueStatus, DebugEvent, DebuggerCore};
use mida_pe::PeHeader;
use mida_packers_themida::{
    GuardAccessResult, ThemidaState,
    find_real_oep_by_scanning, install_code_section_guard, install_iat_guard,
    is_oep_virtualized, process_guarded_access, remove_code_section_guard,
    try_find_correct_oep, handle_tls_callbacks, determine_iat_address,
};
use crate::log::{self, LogType};
use super::session::ProcessSession;
use super::iat_trace::{IatTraceState, advance_to_next_slot};
use super::helpers::compute_data_section_bounds;
use super::LoopState;

/// What the debug loop should do after handling an AccessViolation.
pub(super) enum AvAction {
    Continue,
    Break,
}

/// Handle an AccessViolation event in the debug loop.
///
/// Returns `AvAction::Break` when the debug loop should exit (OEP found and
/// IAT ready), or `AvAction::Continue` otherwise.
pub(super) fn handle_access_violation(
    ls: &mut LoopState,
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    pe: &PeHeader,
    h_process: HANDLE,
    guard_protection: u32,
    image_base_usize: usize,
    image_boundary: usize,
    thread_id: u32,
    exception_addr: u64,
    target_address: u64,
    exc_type: u8,
) -> Result<AvAction, anyhow::Error> {
    debug!(
        exc = %format!("{exception_addr:#x}"),
        target = %format!("{target_address:#x}"),
        "Access violation"
    );
    log::log(LogType::Info, &format!("Access violation: exc={exception_addr:#x}, target={target_address:#x}, thread={thread_id}"));

    if !ls.guard_installed {
        dbg.continue_event(thread_id, ContinueStatus::Continue)?;
        return Ok(AvAction::Continue);
    }

    let text_start = (dbg.image_base() as usize)
        .wrapping_add(state.pe_info.pe_sections[0].virtual_address as usize);
    let text_end = dbg.image_base() as usize + state.pe_info.base_of_data as usize;

    match process_guarded_access(
        dbg,
        h_process,
        state,
        target_address as usize,
        exception_addr as usize,
        thread_id,
        image_base_usize,
        image_boundary,
        text_start,
        text_end,
        exc_type,
    )? {
        GuardAccessResult::Handled { address: _, thread_id: tid } => {
            debug!(tid, "Guarded access handled — continuing");
            dbg.continue_event(tid, ContinueStatus::Continue)?;
        }
        GuardAccessResult::TlsCallback { address } => {
            log::log(
                LogType::Info,
                &format!("TLS callback detected at {:#x} — guard switched to Themida section", address),
            );
            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
        }
        GuardAccessResult::MsvcTraceComplete { address } => {
            ls.oep = Some(address);
            remove_code_section_guard(
                h_process,
                text_start,
                text_end.saturating_sub(text_start),
            )?;
            log::log(LogType::Info, &format!(
                "MSVC OEP synthesized and written at {:#x} — breaking debug loop",
                address,
            ));
            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            return Ok(AvAction::Break);
        }
        GuardAccessResult::PossibleOEP { address } => {
            log::log(LogType::Info, &format!("Possible OEP at {:#x}", address));

            let tls_total = state.pe_info.tls_total;
            let tls_result = handle_tls_callbacks(
                dbg,
                address,
                8u32,
                tls_total,
                &mut state.tls_counter,
            )?;

            if tls_result.oep_found {
                ls.oep = tls_result.oep_address;
            } else {
                let mut ret_addr: usize = 0;
                let mut ret_bytes = [0u8; 8];
                let ctx = dbg.get_thread_context_control(thread_id)
                    .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                if dbg.read_memory(ctx.Rsp as usize, &mut ret_bytes).is_ok() {
                    ret_addr = u64::from_le_bytes(ret_bytes) as usize;
                    info!(
                        rsp = %format!("{:#x}", ctx.Rsp as usize),
                        ret_addr = %format!("{ret_addr:#x}"),
                        "Read return address from stack at PossibleOEP"
                    );
                }

                let ret_in_themida = state.pe_info.pe_sections.iter().any(|sec| {
                    if !mida_packers_themida::is_themida_section(sec) {
                        return false;
                    }
                    let sec_start = dbg.image_base() as usize + sec.virtual_address as usize;
                    let sec_end = sec_start + sec.virtual_size as usize;
                    ret_addr >= sec_start && ret_addr < sec_end
                });

                if ret_in_themida {
                    let pe_entry_point = dbg.image_base() as usize + pe.entry_point as usize;
                    let text_sec = &state.pe_info.pe_sections[0];
                    let text_base_va = dbg.image_base() as usize + text_sec.virtual_address as usize;
                    let text_end_va = dbg.image_base() as usize + state.pe_info.base_of_data as usize;
                    let text_len_va = text_end_va.saturating_sub(text_base_va);

                    let found_via_pattern_first = if state.pe_info.major_linker_version == 0
                        || [2u8, 6, 7, 8, 9, 10, 11, 12, 14]
                            .contains(&state.pe_info.major_linker_version)
                    {
                        try_find_correct_oep(
                            dbg,
                            pe_entry_point,
                            text_base_va,
                            text_len_va,
                            state.pe_info.major_linker_version,
                        )
                        .unwrap_or(None)
                    } else {
                        None
                    };

                    if let Some(real_oep) = found_via_pattern_first {
                        info!(
                            pe_entry = %format!("{pe_entry_point:#x}"),
                            real_oep = %format!("{real_oep:#x}"),
                            "Found MSVC OEP via pattern match on PE entry point"
                        );
                        ls.oep = Some(real_oep);
                        remove_code_section_guard(
                            h_process,
                            text_start,
                            text_end.saturating_sub(text_start),
                        )?;
                        return Ok(AvAction::Break);
                    }

                    ls.virtualized_oep_retries += 1;
                    info!(
                        ret_addr = %format!("{ret_addr:#x}"),
                        retry = ls.virtualized_oep_retries,
                        "Return address points into Themida section — OEP is virtualized"
                    );

                    if ls.virtualized_oep_retries >= 1000 {
                        warn!("Too many virtualized OEP retries ({}) — using last Possible OEP", ls.virtualized_oep_retries);
                        let text_sec = &state.pe_info.pe_sections[0];
                        let text_base = dbg.image_base() as usize + text_sec.virtual_address as usize;
                        let text_end = dbg.image_base() as usize + state.pe_info.base_of_data as usize;
                        let text_len = text_end.saturating_sub(text_base);

                        let found_via_pattern: Option<usize> = if state.pe_info.major_linker_version == 2 {
                            None
                        } else if state.pe_info.major_linker_version == 0
                            || [6u8, 7, 8, 9, 10, 11, 12, 14]
                                .contains(&state.pe_info.major_linker_version)
                        {
                            try_find_correct_oep(
                                dbg,
                                address,
                                text_base,
                                text_len,
                                state.pe_info.major_linker_version,
                            )
                            .unwrap_or(None)
                        } else {
                            None
                        };

                        let real_oep = if let Some(oep) = found_via_pattern {
                            info!(
                                old = %format!("{address:#x}"),
                                new = %format!("{oep:#x}"),
                                "Replaced virtualized OEP via TryFindCorrectOEP"
                            );
                            Some(oep)
                        } else if let Some(oep) = find_real_oep_by_scanning(
                            dbg,
                            dbg.image_base() as usize,
                            text_sec.virtual_address,
                            text_sec.virtual_size,
                        )? {
                            info!(
                                old = %format!("{address:#x}"),
                                new = %format!("{oep:#x}"),
                                "Replaced virtualized OEP with scanned OEP"
                            );
                            Some(oep)
                        } else {
                            None
                        };

                        ls.oep = real_oep.or_else(|| ls.last_possible_oep.or(Some(address)));
                        ls.oep_found_via_scanning = true;
                        remove_code_section_guard(
                            h_process,
                            text_start,
                            text_end.saturating_sub(text_start),
                        )?;
                        let oep_str = ls.oep.map(|a| format!("{a:#x}")).unwrap_or_else(|| "unknown".into());
                        info!(oep = %oep_str, "OEP found — removing guard");
                    } else {
                        let mut ctx = dbg.get_thread_context_control(thread_id)
                            .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                        ctx.Rip = ret_addr as u64;
                        ctx.Rsp += 8;
                        super::session::set_thread_context_control(dbg, thread_id, &ctx)?;

                        let ts_start = (dbg.image_base() as usize)
                            .wrapping_add(state.pe_info.pe_sections[0].virtual_address as usize);
                        let text_end = dbg.image_base() as usize + state.pe_info.base_of_data as usize;
                        install_code_section_guard(
                            h_process,
                            ts_start,
                            text_end.saturating_sub(ts_start),
                            guard_protection,
                        )?;

                        dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                        return Ok(AvAction::Continue);
                    }
                }

                ls.last_possible_oep = Some(address);

                let text_section = &state.pe_info.pe_sections[0];
                let text_base = (dbg.image_base() as usize)
                    .wrapping_add(text_section.virtual_address as usize);
                let text_len = state
                    .pe_info
                    .base_of_data
                    .wrapping_sub(u64::from(text_section.virtual_address))
                    as usize;

                let found_oep = if text_len >= 10 {
                    try_find_correct_oep(
                        dbg,
                        address,
                        text_base,
                        text_len,
                        state.pe_info.major_linker_version,
                    )?
                } else {
                    None
                };

                if !ls.oep_found_via_scanning {
                    ls.oep = found_oep.or(Some(address));
                }

                if found_oep.is_none()
                    && state.pe_info.major_linker_version != 0
                    && [9u8, 10, 11, 12, 14].contains(&state.pe_info.major_linker_version)
                    && state.guard_addrs.len() >= 2
                {
                    let last_addr = state.guard_addrs[state.guard_addrs.len() - 1];
                    let prev_addr = state.guard_addrs[state.guard_addrs.len() - 2];
                    info!(
                        prev = %format!("{prev_addr:#x}"),
                        last = %format!("{last_addr:#x}"),
                        oep = %format!("{address:#x}"),
                        "Virtual OEP detected — entering FTraceMSVCOEP mode (MSVC VM at OEP)"
                    );
                    state.msvc_init_cookie = address;
                    state.msvc_oep = prev_addr;
                    state.trace_msvc_oep = true;
                    ls.oep = Some(prev_addr);
                    let ctx = dbg.get_thread_context_control(thread_id)
                        .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                    let mut ret_bytes = [0u8; 8];
                    let mut ret_addr = 0usize;
                    if dbg.read_memory(ctx.Rsp as usize, &mut ret_bytes).is_ok() {
                        ret_addr = u64::from_le_bytes(ret_bytes) as usize;
                    }
                    if ret_addr != 0 {
                        let mut new_ctx = dbg.get_thread_context_control(thread_id)
                            .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                        new_ctx.Rip = ret_addr as u64;
                        new_ctx.Rsp += 8;
                        super::session::set_thread_context_control(dbg, thread_id, &new_ctx)?;
                    }
                    remove_code_section_guard(
                        h_process,
                        text_start,
                        text_end.saturating_sub(text_start),
                    )?;
                    install_code_section_guard(
                        h_process,
                        text_start,
                        text_end.saturating_sub(text_start),
                        guard_protection,
                    )?;
                    log::log(LogType::Info, &format!(
                        "FTraceMSVCOEP: waiting for CRT Startup hit after VM (init_cookie={:#x}, oep_stub={:#x})",
                        state.msvc_init_cookie, state.msvc_oep,
                    ));
                    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                    return Ok(AvAction::Continue);
                }

                if let Some(oep_addr) = ls.oep {
                    let mut tm_start = usize::MAX;
                    let mut tm_end = 0;
                    for sec in &state.pe_info.pe_sections {
                        if mida_packers_themida::is_themida_section(sec) {
                            let s = dbg.image_base() as usize + sec.virtual_address as usize;
                            let e = s + sec.virtual_size as usize;
                            tm_start = tm_start.min(s);
                            tm_end = tm_end.max(e);
                        }
                    }

                    if tm_start < tm_end && is_oep_virtualized(dbg, oep_addr, tm_start) {
                        info!(oep = %format!("{oep_addr:#x}"), "OEP is virtualized — scanning .text for real OEP");
                        let text_sec = &state.pe_info.pe_sections[0];
                        let text_rva = text_sec.virtual_address;
                        let text_size = text_sec.virtual_size;
                        if let Some(real_oep) = find_real_oep_by_scanning(
                            dbg,
                            dbg.image_base() as usize,
                            text_rva,
                            text_size,
                        )? {
                            info!(
                                old = %format!("{oep_addr:#x}"),
                                new = %format!("{real_oep:#x}"),
                                "Replaced virtualized OEP with scanned OEP"
                            );
                            ls.oep = Some(real_oep);
                        }
                    }
                }

                if found_oep.is_none() {
                    if let Some(oep_addr) = ls.oep {
                        let mut oep_bytes = [0u8; 4];
                        if dbg.read_memory(oep_addr, &mut oep_bytes).is_ok() {
                            let looks_valid = matches!(oep_bytes[0], 0x48 | 0x55 | 0x53 | 0x56 | 0x57)
                                || (oep_bytes[0] == 0x41 && matches!(oep_bytes[1], 0x54..=0x57));
                            if looks_valid {
                                info!(oep = %format!("{oep_addr:#x}"), "OEP looks like valid x64 code — using as-is for non-MSVC compiler");
                                ls.oep = Some(oep_addr);
                            }
                        }
                    }
                }
            }
        }
        GuardAccessResult::NotGuarded => {
            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            return Ok(AvAction::Continue);
        }
        GuardAccessResult::IatReady { address } => {
            info!(address = %format!("{address:#x}"), "IAT monitoring complete — IAT ready for tracing");
        }
    }

    // After OEP is found, set up IAT decryption monitoring.
    if ls.oep.is_some() && ls.iat_trace.is_none() {
        let oep_addr = ls.oep.ok_or_else(|| anyhow!("OEP not found: cannot start IAT decryption wait"))?;
        info!(oep = %format!("{oep_addr:#x}"), "OEP found — letting program execute for .text + IAT decryption");

        let mut ctx = dbg.get_thread_context_control(thread_id)
            .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
        ctx.Rip = oep_addr as u64;
        ctx.EFlags &= !0x100;
        super::session::set_thread_context_control(dbg, thread_id, &ctx)?;

        let text_section = &state.pe_info.pe_sections[0];
        let text_start_addr = image_base_usize.wrapping_add(text_section.virtual_address as usize);
        let text_size = text_section.virtual_size as usize;

        let mut text_buf = vec![0u8; text_size.min(0x100_000)];
        let _ = dbg.read_memory(text_start_addr, &mut text_buf);

        let base_of_data = state.pe_info.base_of_data as usize;
        let (data_section_base, data_section_size) =
            compute_data_section_bounds(image_base_usize, base_of_data, &state.pe_info.pe_sections);

        let iat = match determine_iat_address(
            dbg,
            oep_addr,
            text_start_addr,
            &text_buf,
            data_section_base,
            data_section_size,
            state.pe_info.is_vm_oep,
            mida_packers_themida::CompilerHint::Auto,
            &state.guard_addrs,
        ) {
            Ok(Some(iat)) => iat,
            Ok(None) => {
                warn!("IAT not found — skipping IAT monitoring");
                return Ok(AvAction::Break);
            }
            Err(e) => {
                warn!("IAT detection failed: {e} — skipping IAT monitoring");
                return Ok(AvAction::Break);
            }
        };

        info!(iat = %format!("{:#x}", iat.address), size = %format!("{:#x}", iat.size), "IAT located");

        state.guard_start = iat.address;
        state.guard_end = iat.address + iat.size;
        install_iat_guard(h_process, iat.address, iat.size)?;

        info!("Letting program execute for 5 seconds to decrypt IAT...");

        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        let mut iat_violations = 0;

        loop {
            if start_time.elapsed() > timeout {
                info!("IAT monitoring timeout reached ({} violations)", iat_violations);
                break;
            }

            let continue_result = dbg.continue_event(thread_id, ContinueStatus::Continue);
            if continue_result.is_err() {
                warn!("ContinueEvent failed: {}", continue_result.unwrap_err());
                break;
            }

            match dbg.wait_event_timeout(100) {
                Ok(event) => {
                    match event {
                        DebugEvent::AccessViolation { address, target_address, .. } => {
                            if target_address >= iat.address as u64
                                && target_address < (iat.address + iat.size) as u64
                            {
                                iat_violations += 1;
                                // Record the faulting instruction address for later fixup
                                state.guard_addrs.push(address as usize);
                                debug!("IAT access #{} at target={:#x} from={:#x}",
                                       iat_violations, target_address, address);
                            }
                        }
                        DebugEvent::ExitProcess { .. } => {
                            info!("Process exited during IAT monitoring");
                            break;
                        }
                        _ => {}
                    }
                }
                Err(mida_core::CoreError::Timeout) => {}
                Err(e) => {
                    warn!("Debug event error: {e}");
                    break;
                }
            }
        }

        remove_code_section_guard(h_process, iat.address, iat.size)?;
        info!(violations = iat_violations, "IAT monitoring complete");

        let ptr_size = std::mem::size_of::<usize>();
        let slot_count = iat.size / ptr_size;
        let mut slot_values = vec![0usize; slot_count];
        let bytes_read = dbg.read_memory(iat.address, unsafe {
            std::slice::from_raw_parts_mut(
                slot_values.as_mut_ptr() as *mut u8,
                slot_values.len() * ptr_size,
            )
        }).unwrap_or(0);
        let actual_slots = bytes_read / ptr_size;
        slot_values.truncate(actual_slots);

        let api_like_count = slot_values.iter()
            .filter(|&&v| v > 0x10000 && v < 0x7FFF_FFFF_FFFF)
            .count();
        info!(api_like = api_like_count, total = actual_slots, "IAT analysis after execution");

        let mut tm_start = usize::MAX;
        let mut tm_end = 0;
        let mut found_themida = false;
        for section in &state.pe_info.pe_sections {
            if mida_packers_themida::is_themida_section(section) {
                let start = image_base_usize + section.virtual_address as usize;
                let end = start + section.virtual_size as usize;
                tm_start = tm_start.min(start);
                tm_end = tm_end.max(end);
                found_themida = true;
            }
        }
        if !found_themida {
            tm_start = image_base_usize;
            tm_end = image_boundary;
        }

        let trace_thread_id = thread_id;
        let trace_ctx = dbg.get_thread_context_control(trace_thread_id)
            .map_err(|e| anyhow!("get_thread_context_control for trace_start_sp: {e}"))?;
        let trace_start_sp = trace_ctx.Rsp as usize;

        let mut trace = IatTraceState::new(
            iat.address,
            iat.size,
            slot_values,
            tm_start,
            tm_end,
            image_base_usize,
            image_boundary,
            trace_thread_id,
            trace_start_sp,
        );
        log::log(LogType::Info, &format!("IAT trace state created: {} slots", trace.total_slots));

        advance_to_next_slot(dbg, &mut trace)?;
        ls.iat_trace = Some(trace);

        if let Some(ref t) = ls.iat_trace {
            if t.current_slot >= t.total_slots {
                info!("IAT tracing complete — exiting debug loop immediately");
                return Ok(AvAction::Break);
            }
        }
        return Ok(AvAction::Continue);
    }

    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
    Ok(AvAction::Continue)
}
