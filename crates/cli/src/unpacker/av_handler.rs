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
use super::helpers::compute_data_section_bounds;
use super::LoopState;

/// What the debug loop should do after handling an AccessViolation.
pub(super) enum AvAction {
    Continue,
    Break,
}

// ---------------------------------------------------------------------------
// Access-violation storm watchdog
// ---------------------------------------------------------------------------

/// Number of *identical* access violations tolerated before giving up.
///
/// Themida v3 uses exception-driven obfuscation, so a legitimate run can see
/// hundreds of the same fault while a tight decode loop spins.  A real storm —
/// the target stuck in a loop that never converges — produces tens of thousands
/// within a couple of seconds.  Measured on the reference DLL sample: 36,450
/// identical faults in 1.9 s with zero forward progress.  The threshold keeps
/// two orders of magnitude of headroom over legitimate bursts.
const AV_STORM_LIMIT: u32 = 1024;

/// Seconds to let a packed DLL finish its own `DllMain` initialisation after
/// its import table is ready, before the image is dumped.
///
/// See the settle-window comment in [`handle_access_violation`]: the reference
/// `core.dll` writes its version string into `.bss` after the IAT is complete,
/// so a dump taken at the end of the IAT window yields `GetAppVersion() -> "0.0"`
/// instead of `"1.1"`.
const DLL_SETTLE_SECS: u64 = 0;

/// Counts consecutive identical access violations.
///
/// "Identical" means the same `(faulting address, target address, exception
/// type)` triple.  Any change resets the counter, so a target that is merely
/// busy is never killed — only one that is provably repeating itself.
#[derive(Default)]
pub(super) struct AvStorm {
    tuple: Option<(u64, u64, u8)>,
    count: u32,
}

impl AvStorm {
    /// Record one violation.  Returns `true` when the run should be abandoned.
    fn record(&mut self, exc: u64, target: u64, exc_type: u8) -> bool {
        let t = (exc, target, exc_type);
        if self.tuple == Some(t) {
            self.count = self.count.saturating_add(1);
        } else {
            self.tuple = Some(t);
            self.count = 1;
        }
        self.count >= AV_STORM_LIMIT
    }

    /// Reset after a guard-driven fault, which is expected and self-limiting.
    fn reset(&mut self) {
        self.tuple = None;
        self.count = 0;
    }
}

/// Union of all Themida section bounds, as `(start, end)` virtual addresses.
///
/// Returns `(0, 0)` when no Themida section was identified, which callers treat
/// as "no VM region to test against".
fn themida_bounds(state: &ThemidaState, image_base: usize) -> (usize, usize) {
    let mut start = usize::MAX;
    let mut end = 0usize;
    for sec in &state.pe_info.pe_sections {
        if mida_packers_themida::is_themida_section(sec) {
            let s = image_base.wrapping_add(sec.virtual_address as usize);
            let e = s.wrapping_add(sec.virtual_size as usize);
            start = start.min(s);
            end = end.max(e);
        }
    }
    if start < end {
        (start, end)
    } else {
        (0, 0)
    }
}

/// Handle an AccessViolation event in the debug loop.
///
/// Returns `AvAction::Break` when the debug loop should exit (OEP found and
/// IAT ready, or the target is stuck), or `AvAction::Continue` otherwise.
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
    is_dll_target: bool,
) -> Result<AvAction, anyhow::Error> {
    debug!(
        exc = %format!("{exception_addr:#x}"),
        target = %format!("{target_address:#x}"),
        "Access violation"
    );

    // ---- storm watchdog ---------------------------------------------------
    //
    // Before anything else: if this is the same fault we have already seen a
    // thousand times, the target is not making progress and continuing only
    // burns the log.  Applies even before the guard is installed, because a
    // packed DLL can storm during its own initialisation (observed on the
    // reference core.dll: 36,450 identical faults at .winlice+0x33E22E).
    if ls.av_storm.record(exception_addr, target_address, exc_type) {
        let (exc, tgt) = (exception_addr, target_address);
        return Err(anyhow!(
            "Target is stuck: {AV_STORM_LIMIT} consecutive identical access \
             violations at {exc:#x} (target {tgt:#x}).\n\
             This is an exception-driven decode loop that never converges; the \
             debuggee cannot be unpacked in this state. No product was written."
        ));
    }

    log::log(LogType::Info, &format!("Access violation: exc={exception_addr:#x}, target={target_address:#x}, thread={thread_id}"));

    if !ls.guard_installed {
        dbg.continue_event(thread_id, ContinueStatus::Continue)?;
        return Ok(AvAction::Continue);
    }

    // A guard-driven fault is expected and self-limiting; it must not count
    // toward the storm budget.
    ls.av_storm.reset();

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
            // The guard has been re-armed / trap flag set; the single-step that
            // follows will finish the cycle.  Return immediately: the tail of
            // this function continues the event again, and calling
            // `ContinueDebugEvent` twice for one event fails with
            // ERROR_INVALID_PARAMETER.
            debug!(tid, "Guarded access handled — continuing");
            dbg.continue_event(tid, ContinueStatus::Continue)?;
            return Ok(AvAction::Continue);
        }
        GuardAccessResult::TlsCallback { address } => {
            log::log(
                LogType::Info,
                &format!("TLS callback detected at {:#x} — guard switched to Themida section", address),
            );
            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            return Ok(AvAction::Continue);
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

            let mut dll_oep_accepted = false;

            // ---- DLL targets: the first execute fault into .text IS the OEP --
            //
            // A packed DLL's `DllMain` is invoked by the shell, so a return
            // address sitting in `.winlice`/`.boot` is completely normal — it is
            // NOT evidence that the OEP was virtualised.  The EXE-oriented
            // "return address points into the Themida section" heuristic below
            // therefore mis-fires here: on the reference `core.dll` it rejected
            // the genuine `DllMain` (rva 0x2bb10) and then chased three more
            // candidates until it settled on the *start of .text* (rva 0x1000),
            // producing a dump whose entry point was the first decrypted
            // function rather than the DLL entry.
            //
            // For a DLL we ask only the question that matters: is the
            // instruction here a transfer into the VM?  If not, control has
            // genuinely reached decrypted code and this is the OEP.
            if is_dll_target {
                let (tm_start, tm_end) = themida_bounds(state, dbg.image_base() as usize);
                let virtualized = tm_start < tm_end && is_oep_virtualized(dbg, address, tm_start);
                if !virtualized {
                    ls.oep = Some(address);
                    remove_code_section_guard(
                        h_process,
                        text_start,
                        text_end.saturating_sub(text_start),
                    )?;
                    log::log(
                        LogType::Info,
                        &format!(
                            "DLL OEP accepted at {address:#x} (rva {:#x}) — real decrypted code, \
                             not a VM trampoline",
                            address.wrapping_sub(dbg.image_base() as usize)
                        ),
                    );
                    // Skip the EXE-oriented virtualised-OEP heuristics entirely
                    // and fall through to the IAT decryption window at the tail
                    // of this function.  Breaking here would dump the image
                    // before the shell finishes decrypting the import table:
                    // observed on core.dll, that yields 357 of 3282 slots.
                    dll_oep_accepted = true;
                } else {
                    log::log(
                        LogType::Info,
                        &format!("DLL OEP candidate {address:#x} is a VM trampoline — continuing"),
                    );
                }
            }

            if !dll_oep_accepted {
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
            } // end: EXE-oriented virtualised-OEP heuristics (skipped for DLLs)
        }
        GuardAccessResult::NotGuarded => {
            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            return Ok(AvAction::Continue);
        }
        GuardAccessResult::IatReady { address } => {
            info!(address = %format!("{address:#x}"), "IAT monitoring complete — IAT ready for tracing");
            return Ok(AvAction::Continue);
        }
    }

    // After OEP is found, set up IAT decryption monitoring.
    //
    // This is a *passive* window: install a PAGE_NOACCESS guard over the IAT,
    // let the target run, and record which instructions touch it (they land in
    // `state.guard_addrs`, which `determine_iat_address` consumes downstream).
    // Themida v3 progressively decrypts whole IAT blocks during this window.
    //
    // The actual slot resolution happens later, in the post-loop phase via
    // `fix_iat` -> `fix_iat_v3` -> `trace_imports` (the single production trace
    // engine).  There used to be a second, in-loop trace state machine here
    // (`iat_trace.rs`) that duplicated the slot classifier, resolved 0 slots,
    // wrote its partial results back into the target, and then threw them away.
    // It was removed — see ARCHITECTURE_REVIEW.md §3.
    if ls.oep.is_some() && !ls.iat_monitoring_done {
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
                                // Record the faulting instruction address for later fixup.
                                state.guard_addrs.push(address as usize);
                                // Do NOT log per-access: this window sees 150k+ IAT
                                // touches on a real v3 target, which turned a -v run
                                // into a 16 MB log.  Report the aggregate below.
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

        // ---- DLL targets: let `DllMain` finish before dumping ----------------
        //
        // A packed DLL does not stop at "IAT decrypted".  Its `DllMain` keeps
        // initialising global state afterwards — on the reference `core.dll`
        // the version string `"1.1"` is written into `.bss` *after* the import
        // table is complete.  Dumping at the end of the IAT window therefore
        // produced a DLL that loads and exports correctly but answers
        // `GetAppVersion() -> "0.0"` instead of `"1.1"`, because `.bss` was
        // captured before the shell filled it in.
        //
        // The dump point is therefore "the import table is ready AND the target
        // has had time to finish its own initialisation".  We cannot wait for
        // `DllMain` to *return* (our guard page faults on every `.text`
        // execution and the shell never reaches its epilogue while we hold it),
        // so the window is time-based, with the guard already removed so the
        // target runs at full speed.
        if is_dll_target {
            let settle = std::time::Duration::from_secs(DLL_SETTLE_SECS);
            info!(
                secs = DLL_SETTLE_SECS,
                "DLL target — letting DllMain finish its own initialisation before dumping"
            );
            let settle_start = std::time::Instant::now();
            while settle_start.elapsed() < settle {
                if dbg.continue_event(thread_id, ContinueStatus::Continue).is_err() {
                    break;
                }
                match dbg.wait_event_timeout(100) {
                    Ok(DebugEvent::ExitProcess { .. }) => {
                        info!("Target exited while waiting for DllMain to finish");
                        break;
                    }
                    Ok(_) => {}
                    Err(mida_core::CoreError::Timeout) => {}
                    Err(_) => break,
                }
            }
            info!(
                elapsed_ms = settle_start.elapsed().as_millis() as u64,
                "DllMain settle window complete — dumping"
            );
        }

        // Report how much Themida decrypted in place during the window.  This is
        // informational: the post-loop trace engine re-reads the IAT and decides
        // per slot.  Blocks already resolved here are adopted by the classifier
        // as `IatSlotDecision::Resolved`.
        let ptr_size = std::mem::size_of::<usize>();
        let slot_count = iat.size / ptr_size;
        let mut slot_values = vec![0usize; slot_count];
        // SAFETY: slot_values is a Vec<usize>; the aliasing slice covers len * ptr_size bytes and is discarded after read_memory.
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

        ls.iat_monitoring_done = true;
        return Ok(AvAction::Break);
    }

    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
    Ok(AvAction::Continue)
}
