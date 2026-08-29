use super::av_query::AvQueryCtx;
use super::helpers::compute_data_section_bounds;
use super::iat_trace::{advance_to_next_slot, IatTraceState};
use super::loop_state::LoopState;
use super::session::ProcessSession;
use crate::log::{self, LogType};
use anyhow::anyhow;
use mida_core::{ContinueStatus, DebugEvent, DebuggerCore};
use mida_packers_themida::{
    decide_av_oep, determine_iat_address, install_iat_guard, remove_code_section_guard,
    AvOepAction, AvOepInput, AvOepState, ThemidaState,
};
use mida_pe::PeHeader;
use tracing::{debug, info, warn};
use windows::Win32::Foundation::HANDLE;

/// What the debug loop should do after handling an AccessViolation.
pub(super) enum AvAction {
    Continue,
    Break,
}

/// C-7: map the decision outcome's `Break` arm to the host's action,
/// turning a guardless constant-AV storm abort into a fail-closed `Err`.
///
/// Pure decision (no debugger/handle access), so the fail-closed mapping is
/// directly unit-testable without a live debuggee (TASK-012 ③).
///
/// - `storm_abort = Some((tuple, count))` → `Err` whose message carries the
///   identical tuple and the streak count at abort (diagnostics preserved;
///   the loop unwinds, no dump, no `[GOOD]`).
/// - `storm_abort = None` (ordinary OEP-`Break`, storm-escape freeze, etc.)
///   → `Ok(AvAction::Break)` unchanged: the pending AV stays pending for the
///   post-loop IAT phase.
fn map_storm_abort(storm_abort: &Option<(String, u32)>) -> Result<AvAction, String> {
    if let Some((tuple, count)) = storm_abort {
        return Err(format!(
            "guardless constant-AV storm abort (fail-closed): identical AV tuple {tuple} repeated {count} times without guard installed; aborting unpack"
        ));
    }
    Ok(AvAction::Break)
}

#[cfg(test)]
mod tests {
    use super::map_storm_abort;
    use super::AvAction;

    #[test]
    fn storm_abort_maps_to_fail_closed_err_with_tuple_and_count() {
        let err = match map_storm_abort(&Some((
            "(exc=0x7ffa95400bd8, target=0x204, exc_type=0, thread=25252)".to_string(),
            1024,
        ))) {
            Err(e) => e,
            Ok(_) => panic!("storm abort must fail closed"),
        };
        assert!(
            err.contains("(exc=0x7ffa95400bd8, target=0x204, exc_type=0, thread=25252)"),
            "Err must carry the identical tuple: {err}"
        );
        assert!(err.contains("1024"), "Err must carry the count: {err}");
        assert!(
            err.contains("fail-closed"),
            "Err must say fail-closed: {err}"
        );
    }

    #[test]
    fn plain_break_without_storm_abort_stays_ok_break() {
        // Ordinary Break (OEP capture / storm-escape freeze): no storm_abort,
        // so the host must still get Ok(Break) — the pending AV stays pending
        // for the post-loop IAT phase.
        let action = match map_storm_abort(&None) {
            Ok(action) => action,
            Err(e) => panic!("plain Break must stay Ok, got Err({e})"),
        };
        assert!(matches!(action, AvAction::Break));
    }
}

/// Handle an AccessViolation event in the debug loop.
///
/// P3-D: the AV/OEP decision body lives in
/// `mida_packers_themida::runtime::av_oep_handler`; this function is the
/// thin host: it maps loop state to the decision, executes the returned
/// action (exactly-once continue / context redirect / break), and keeps the
/// shared post-OEP IAT phase.
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
    guardless_av_tuple: &mut Option<(u64, u64, u8, u32)>,
    guardless_av_tuple_streak: &mut u32,
) -> Result<AvAction, anyhow::Error> {
    debug!(
        exc = %format!("{exception_addr:#x}"),
        target = %format!("{target_address:#x}"),
        "Access violation"
    );
    // Sample noisy AVs: full INFO per hit produced multi-GB logs on Lunlun.
    if ls.unrelated_av_streak <= 4 || ls.unrelated_av_streak.is_power_of_two() {
        log::log(
            LogType::Info,
            &format!(
                "Access violation: exc={exception_addr:#x}, target={target_address:#x}, thread={thread_id}"
            ),
        );
    }

    let text_start = (dbg.image_base() as usize)
        .wrapping_add(state.pe_info.pe_sections[0].virtual_address as usize);
    let text_end = dbg.image_base() as usize + state.pe_info.base_of_data as usize;

    let mut av = AvOepState {
        guard_installed: ls.guard_installed,
        oep: ls.oep,
        provenance: ls.oep_provenance.clone(),
        oep_found_via_scanning: ls.oep_found_via_scanning,
        unrelated_av_streak: ls.unrelated_av_streak,
        virtualized_oep_retries: ls.virtualized_oep_retries,
        last_possible_oep: ls.last_possible_oep,
        storm_escape_freeze: false,
        guardless_av_tuple: *guardless_av_tuple,
        guardless_av_tuple_streak: *guardless_av_tuple_streak,
        storm_abort: None,
    };
    let input = AvOepInput {
        event_thread_id: thread_id,
        exception_addr,
        target_address,
        exc_type,
        entry_point_rva: pe.entry_point,
        virtualized_oep_max_retries: ls.virtualized_oep_max_retries,
        unrelated_av_storm_threshold: ls.unrelated_av_storm_threshold,
        unrelated_av_null_storm_threshold: ls.unrelated_av_null_storm_threshold,
    };
    let mut query = AvQueryCtx {
        dbg,
        h_process,
        guard_protection,
        image_base_usize,
        image_boundary,
        text_start,
        text_end,
    };
    let outcome = decide_av_oep(&mut query, state, &mut av, &input).map_err(anyhow::Error::msg)?;

    // Write decision state back to the loop state.
    ls.guard_installed = outcome.state.guard_installed;
    ls.oep = outcome.state.oep;
    ls.oep_provenance = outcome.state.provenance;
    ls.oep_found_via_scanning = outcome.state.oep_found_via_scanning;
    ls.unrelated_av_streak = outcome.state.unrelated_av_streak;
    ls.virtualized_oep_retries = outcome.state.virtualized_oep_retries;
    ls.last_possible_oep = outcome.state.last_possible_oep;
    // C-7: persist guardless tuple tracking back to the loop for the next AV.
    *guardless_av_tuple = outcome.state.guardless_av_tuple;
    *guardless_av_tuple_streak = outcome.state.guardless_av_tuple_streak;
    if outcome.state.storm_escape_freeze {
        ls.storm_escape_freeze = true;
    }

    match outcome.action {
        AvOepAction::Continue => {
            if !outcome.epilogue {
                // No shared epilogue (no guard installed / unrelated AV):
                // resume the pending event exactly once.
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                return Ok(AvAction::Continue);
            }
            // Fall through to the shared post-OEP epilogue below.
        }
        AvOepAction::Break { .. } => {
            // C-7: a guardless constant-AV storm abort must fail closed (no
            // dump, no [GOOD], bounded logs). The decision already recorded
            // the tuple + count for diagnostics; surface it as an Err so the
            // debug loop unwinds instead of falling through to IAT/dump.
            return map_storm_abort(&outcome.state.storm_abort).map_err(anyhow::Error::msg);
        }
        AvOepAction::RedirectAndContinue { rip, rsp_delta, .. } => {
            // Redirect RIP/RSP (matching the legacy virtualized-OEP / FTrace
            // redirect: no trap-flag change) then resume exactly once.
            let mut ctx = dbg
                .get_thread_context_control(thread_id)
                .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
            ctx.Rip = rip;
            ctx.Rsp = ctx.Rsp.wrapping_add(rsp_delta);
            super::session::set_thread_context_control(dbg, thread_id, &ctx)?;
            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            return Ok(AvAction::Continue);
        }
    }

    // After OEP is found, set up IAT decryption monitoring.
    if ls.oep.is_some() && ls.iat_trace.is_none() {
        let oep_addr = ls
            .oep
            .ok_or_else(|| anyhow!("OEP not found: cannot start IAT decryption wait"))?;
        info!(oep = %format!("{oep_addr:#x}"), "OEP found — letting program execute for .text + IAT decryption");

        let mut ctx = dbg
            .get_thread_context_control(thread_id)
            .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
        ctx.Rip = oep_addr as u64;
        ctx.EFlags &= !0x100;
        if let Err(e) = super::session::set_thread_context_control(dbg, thread_id, &ctx) {
            // Without Rip redirect, .text/IAT may still decrypt if the thread
            // already sits at/near OEP. Soft-fail so we can still attempt dump.
            warn!(
                oep = %format!("{oep_addr:#x}"),
                error = %e,
                "post-OEP SetThreadContext soft-fail — continue without Rip redirect"
            );
        }

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

        let iat_secs = ls.iat_monitor_timeout_secs.max(1);
        info!("Letting program execute for {iat_secs} seconds to decrypt IAT...");

        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(iat_secs);
        let mut iat_violations = 0;
        let mut process_exited = false;

        loop {
            if start_time.elapsed() > timeout {
                info!(
                    "IAT monitoring timeout reached ({} violations)",
                    iat_violations
                );
                break;
            }

            let continue_result = dbg.continue_event(thread_id, ContinueStatus::Continue);
            if let Err(err) = continue_result {
                warn!("ContinueEvent failed: {}", err);
                break;
            }

            match dbg.wait_event_timeout(100) {
                Ok(event) => {
                    match event {
                        DebugEvent::AccessViolation {
                            address,
                            target_address,
                            ..
                        } => {
                            if target_address >= iat.address as u64
                                && target_address < (iat.address + iat.size) as u64
                            {
                                iat_violations += 1;
                                // Record the faulting instruction address for later fixup
                                state.guard_addrs.push(address as usize);
                                debug!(
                                    "IAT access #{} at target={:#x} from={:#x}",
                                    iat_violations, target_address, address
                                );
                            }
                        }
                        DebugEvent::ExitProcess { .. } => {
                            info!("Process exited during IAT monitoring");
                            process_exited = true;
                            // ContinueDebugEvent still requires the raw TID
                            // even though the public event omits it.
                            if let Err(error) = dbg.continue_pending_event(ContinueStatus::Continue)
                            {
                                warn!(
                                    error = %error,
                                    "failed to continue ExitProcess event during IAT monitoring"
                                );
                            }
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
        let requested_bytes = slot_count * ptr_size;
        let mut slot_values = vec![0usize; slot_count];
        // SAFETY: slot_values is a Vec<usize>; the aliasing slice covers
        // exactly the requested IAT bytes and is discarded after read_memory.
        let read_result = dbg.read_memory(iat.address, unsafe {
            std::slice::from_raw_parts_mut(slot_values.as_mut_ptr() as *mut u8, requested_bytes)
        });
        let bytes_read = match read_result {
            Ok(bytes_read) if bytes_read == requested_bytes => bytes_read,
            Ok(bytes_read) => {
                let detail = format!(
                    "IAT read incomplete at {:#x}: requested {} bytes, got {}",
                    iat.address, requested_bytes, bytes_read
                );
                let continue_result = if dbg.pending_event_thread_id().is_some() {
                    dbg.continue_pending_event(ContinueStatus::Continue).err()
                } else {
                    None
                };
                return Err(match continue_result {
                    Some(error) => anyhow!("{detail}; pending event continue failed: {error}"),
                    None => anyhow!(detail),
                });
            }
            Err(error) => {
                let detail = format!(
                    "IAT read failed at {:#x} for {} bytes: {error}",
                    iat.address, requested_bytes
                );
                let continue_result = if dbg.pending_event_thread_id().is_some() {
                    dbg.continue_pending_event(ContinueStatus::Continue).err()
                } else {
                    None
                };
                return Err(match continue_result {
                    Some(error) => anyhow!("{detail}; pending event continue failed: {error}"),
                    None => anyhow!(detail),
                });
            }
        };
        let actual_slots = bytes_read / ptr_size;
        debug_assert_eq!(actual_slots, slot_count);

        let api_like_count = slot_values
            .iter()
            .filter(|&&v| v > 0x10000 && v < 0x7FFF_FFFF_FFFF)
            .count();
        info!(
            api_like = api_like_count,
            total = actual_slots,
            "IAT analysis after execution"
        );

        // Lunlun: after virtualized-OEP storm escape, resuming at PossibleOEP can
        // ExitProcess immediately. v3 per-slot SingleStep then hangs forever on a
        // dead debuggee. Skip trace and dump with whatever slots we already read.
        // (PackerPlugin skip_v3_iat_trace is mirrored via process_exited / leave flags.)
        if process_exited {
            ls.process_exited = true;
            warn!(
                api_like = api_like_count,
                total = actual_slots,
                "Skipping IAT v3-trace — process already exited; proceed to dump"
            );
            return Ok(AvAction::Break);
        }

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
        let trace_ctx = match dbg.get_thread_context_control(trace_thread_id) {
            Ok(ctx) => ctx,
            Err(e) => {
                warn!(
                    error = %e,
                    "get_thread_context_control for IAT trace failed — dump without v3-trace"
                );
                return Ok(AvAction::Break);
            }
        };
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
        log::log(
            LogType::Info,
            &format!("IAT trace state created: {} slots", trace.total_slots),
        );

        match advance_to_next_slot(dbg, &mut trace) {
            Ok(()) => {}
            Err(e) => {
                warn!(
                    error = %e,
                    "advance_to_next_slot failed — dump without further IAT trace"
                );
                return Ok(AvAction::Break);
            }
        }
        ls.iat_trace = Some(trace);

        if let Some(ref t) = ls.iat_trace {
            if t.current_slot >= t.total_slots {
                if t.product_complete() {
                    info!(
                        "IAT tracing product-complete immediately (resolved={})",
                        t.resolved_count
                    );
                } else {
                    info!(
                        "IAT walk finished immediately WITHOUT product-complete (resolved={} failed={} skipped={} aborted={:?})",
                        t.resolved_count,
                        t.failed_count,
                        t.skip_count,
                        t.abort_reason
                    );
                }
                return Ok(AvAction::Break);
            }
        }
        return Ok(AvAction::Continue);
    }

    // Fall-through continue for paths that did not continue above (Handled / TlsCallback).
    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
    Ok(AvAction::Continue)
}
