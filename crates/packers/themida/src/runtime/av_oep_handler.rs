//! Pure AV/OEP decision state machine (P3-B).
//!
//! This is the decision body previously embedded in
//! `crates/cli/src/unpacker/av_handler.rs`, extracted verbatim in behavior.
//! The host (CLI) implements [`AvOepQuery`] over its debugger/engine and
//! executes the returned [`AvOepAction`]; no Win32 type and no debugger
//! reference appears here.
//!
//! Contract:
//! - every branch returns an explicit action (no implicit double-continue);
//! - `Continue`/`RedirectAndContinue` mean the host resumes the pending
//!   event exactly once;
//! - `Break` means the host stops the loop with the captured OEP and
//!   provenance;
//! - guard install/remove and context redirects are capability actions the
//!   host executes through the query seam.

use mida_core::OepProvenance;

use crate::guard::GuardAccessResult;
use crate::oep::{ftrace_enter_preserve_common_main, TlsCallbackResult};
use crate::ThemidaState;

/// What the host must do after one AV decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvOepAction {
    /// Resume the pending event exactly once.
    Continue,
    /// Stop the loop; `oep` and `provenance` are final for this run.
    Break {
        oep: usize,
        provenance: OepProvenance,
        remove_guard: bool,
    },
    /// Adjust RIP/RSP on the faulting thread, then resume exactly once.
    RedirectAndContinue {
        rip: u64,
        rsp_delta: u64,
        reinstall_guard: bool,
    },
}

/// Mutable AV/OEP decision state (host-mapped from the loop state).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AvOepState {
    pub guard_installed: bool,
    pub oep: Option<usize>,
    pub provenance: OepProvenance,
    pub oep_found_via_scanning: bool,
    pub unrelated_av_streak: u32,
    pub virtualized_oep_retries: u32,
    pub last_possible_oep: Option<usize>,
    /// Set when a non-guard AV storm forced a fallback break.
    pub storm_escape_freeze: bool,
}

/// Per-event inputs to the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvOepInput {
    pub event_thread_id: u32,
    pub exception_addr: u64,
    pub target_address: u64,
    pub exc_type: u8,
    /// Application entry point RVA (PE `AddressOfEntryPoint`).
    pub entry_point_rva: u32,
    pub virtualized_oep_max_retries: u32,
    pub unrelated_av_storm_threshold: u32,
    pub unrelated_av_null_storm_threshold: u32,
}

/// Capability seam the host implements over its debugger/engine.
///
/// The decision logic only reads structured answers; it never touches a
/// debugger, a handle, or a Win32 context directly.
pub trait AvOepQuery {
    /// Log severity for host-side logging (observable behavior preserved).
    fn log(&mut self, level: LogLevel, message: &str);

    fn image_base(&self) -> u64;

    /// Evaluate the guarded-access result for this fault. `themida` state is
    /// passed per call so the host adapter does not need to alias it.
    fn process_guarded_access(
        &mut self,
        themida: &mut ThemidaState,
        target_address: usize,
        exception_addr: usize,
        thread_id: u32,
        exc_type: u8,
    ) -> Result<GuardAccessResult, String>;

    /// Read the return address from the faulting thread's stack.
    fn read_ret_addr(&mut self, thread_id: u32) -> Option<u64>;

    /// Run the TLS-callback/OEP trace at `address`.
    fn handle_tls_callbacks(
        &mut self,
        address: usize,
        tls_total: u32,
        tls_counter: &mut u32,
    ) -> Result<TlsCallbackResult, String>;

    /// Pattern-scan the CRT for the real OEP starting at `pe_entry_point`
    /// (linker-version gating and scan bounds stay decision-side/host state).
    fn try_find_correct_oep(
        &mut self,
        themida: &mut ThemidaState,
        pe_entry_point: usize,
    ) -> Option<usize>;

    /// Scan `.text` for the real OEP.
    fn scan_for_oep(&mut self, text_rva: u32, text_size: u32) -> Option<usize>;

    /// `true` when `oep` lands inside the Themida VM section.
    fn is_oep_virtualized(&mut self, oep: usize, tm_start: usize) -> bool;

    /// Read code bytes (for the non-MSVC byte-shape heuristic).
    fn read_code_bytes(&mut self, address: usize, len: usize) -> Option<Vec<u8>>;

    /// Remove the .text code guard (host computes the guarded range).
    fn remove_code_guard(&mut self) -> Result<(), String>;

    /// (Re)install the .text code guard.
    fn install_code_guard(&mut self) -> Result<(), String>;

    /// Adjust the faulting thread's RIP/RSP. Soft-fail allowed (host decides
    /// whether to continue without the redirect).
    fn set_redirect(&mut self, rip: u64, rsp_delta: u64) -> Result<(), String>;
}

/// Host-side log severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
}

/// Outcome of one decision: the action plus updated decision state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvOepOutcome {
    pub action: AvOepAction,
    pub state: AvOepState,
    /// For `Continue` actions: `true` when the host should also run the
    /// shared post-OEP epilogue (Handled / TLS callback / IAT-ready /
    /// PossibleOEP fall-through), `false` when the host should just resume
    /// the pending event (no guard installed / unrelated AV).
    pub epilogue: bool,
}

/// Decide what to do with one AccessViolation event.
///
/// Faithful transliteration of the CLI AV handler's decision tree; every
/// side effect goes through `query`, and the returned action is the only
/// continue/break instruction for the host.
pub fn decide_av_oep(
    query: &mut dyn AvOepQuery,
    themida: &mut ThemidaState,
    state: &mut AvOepState,
    input: &AvOepInput,
) -> Result<AvOepOutcome, String> {
    if !state.guard_installed {
        return Ok(AvOepOutcome {
            action: AvOepAction::Continue,
            state: state.clone(),
            epilogue: false,
        });
    }

    let result = query.process_guarded_access(
        themida,
        input.target_address as usize,
        input.exception_addr as usize,
        input.event_thread_id,
        input.exc_type,
    )?;

    match result {
        GuardAccessResult::Handled {
            address: _,
            thread_id: _,
        } => {
            state.unrelated_av_streak = 0;
            // Fall through to the shared epilogue (host-side IAT phase).
        }
        GuardAccessResult::TlsCallback { address } => {
            query.log(
                LogLevel::Info,
                &format!(
                    "TLS callback detected at {address:#x} — guard switched to Themida section"
                ),
            );
            // Fall through to the shared epilogue.
        }
        GuardAccessResult::MsvcTraceComplete { address } => {
            state.oep = Some(address);
            state.provenance = OepProvenance::trace(
                address as u64,
                format!("GuardAccessResult::MsvcTraceComplete resolved OEP: {address:#x}"),
            );
            state.oep_found_via_scanning = false;
            query.remove_code_guard()?;
            query.log(
                LogLevel::Info,
                &format!("MSVC OEP synthesized and written at {address:#x} — breaking debug loop"),
            );
            // Break deliberately leaves the current AV pending so the
            // host-side post-loop IAT tracing can consume it.
            return Ok(AvOepOutcome {
                action: AvOepAction::Break {
                    oep: address,
                    provenance: state.provenance.clone(),
                    remove_guard: false,
                },
                state: state.clone(),
                epilogue: false,
            });
        }
        GuardAccessResult::PossibleOEP { address } => {
            if let Some(action) = decide_possible_oep(query, themida, state, input, address)? {
                // The sub-tree produced an explicit action (pattern-first
                // Break or virtualized-OEP redirect): return it directly.
                return Ok(AvOepOutcome {
                    action,
                    state: state.clone(),
                    epilogue: false,
                });
            }
            // Shared epilogue (host-side IAT phase) otherwise.
        }
        GuardAccessResult::NotGuarded => {
            state.unrelated_av_streak = state.unrelated_av_streak.saturating_add(1);
            let storm = state.unrelated_av_streak >= input.unrelated_av_storm_threshold
                || (input.target_address == 0
                    && state.unrelated_av_streak >= input.unrelated_av_null_storm_threshold);
            if storm
                && (state.virtualized_oep_retries > 0 || state.last_possible_oep.is_some())
                && state.oep.is_none()
            {
                let fallback = state
                    .last_possible_oep
                    .or(Some(input.exception_addr as usize));
                state.oep = fallback;
                state.provenance = fallback
                    .map(|va| {
                        OepProvenance::unknown(format!(
                            "non-guard AV storm accepted PossibleOEP fallback: {va:#x}"
                        ))
                    })
                    .unwrap_or_else(|| {
                        OepProvenance::unknown("non-guard AV storm produced no OEP address")
                    });
                state.oep_found_via_scanning = false;
                state.storm_escape_freeze = true;
                let _ = query.remove_code_guard();
                // Freeze here (process still alive) and let the host-side
                // post-loop IAT phase resolve wrapper slots.
                let oep = state.oep.unwrap_or(0);
                query.log(LogLevel::Info, &format!(
                    "Storm escape freeze — skip deadly OEP resume; post-loop IAT on live process (oep={oep:#x})"
                ));
                return Ok(AvOepOutcome {
                    action: AvOepAction::Break {
                        oep,
                        provenance: state.provenance.clone(),
                        remove_guard: false,
                    },
                    state: state.clone(),
                    epilogue: false,
                });
            } else if state.unrelated_av_streak <= 8 || state.unrelated_av_streak.is_power_of_two()
            {
                query.log(
                    LogLevel::Debug,
                    &format!(
                        "NotGuarded AV — continue (streak {})",
                        state.unrelated_av_streak
                    ),
                );
            }
        }
        GuardAccessResult::IatReady { address } => {
            query.log(
                LogLevel::Info,
                &format!("IAT monitoring complete — IAT ready for tracing at {address:#x}"),
            );
        }
    }

    Ok(AvOepOutcome {
        action: AvOepAction::Continue,
        state: state.clone(),
        // Handled / TLS callback / IAT-ready / PossibleOEP fall-through:
        // the host runs the shared post-OEP epilogue before resuming.
        epilogue: !matches!(result, GuardAccessResult::NotGuarded),
    })
}

/// The `PossibleOEP` sub-tree. May return `Break` directly (pattern-first
/// match) or leave the shared-epilogue continue to the caller.
fn decide_possible_oep(
    query: &mut dyn AvOepQuery,
    themida: &mut ThemidaState,
    state: &mut AvOepState,
    input: &AvOepInput,
    address: usize,
) -> Result<Option<AvOepAction>, String> {
    state.unrelated_av_streak = 0;
    query.log(LogLevel::Info, &format!("Possible OEP at {address:#x}"));

    let tls_total = themida.pe_info.tls_total;
    let tls_result = query.handle_tls_callbacks(address, tls_total, &mut themida.tls_counter)?;

    if tls_result.oep_found {
        state.oep = tls_result.oep_address;
        if let Some(oep) = tls_result.oep_address {
            state.provenance = OepProvenance::trace(
                oep as u64,
                format!("TLS callback/OEP trace resolved application OEP: {oep:#x}"),
            );
            state.oep_found_via_scanning = false;
        }
        return Ok(None);
    }

    let ret_addr = query.read_ret_addr(input.event_thread_id).unwrap_or(0);
    let ret_in_themida = ret_addr != 0
        && themida.pe_info.pe_sections.iter().any(|sec| {
            if !crate::is_themida_section(sec) {
                return false;
            }
            let sec_start = query.image_base() as usize + sec.virtual_address as usize;
            let sec_end = sec_start + sec.virtual_size as usize;
            let ret = ret_addr as usize;
            ret >= sec_start && ret < sec_end
        });

    if ret_in_themida {
        let pe_entry_point = query.image_base() as usize + input.entry_point_rva as usize;

        let found_via_pattern_first = if themida.pe_info.major_linker_version == 0
            || [2u8, 6, 7, 8, 9, 10, 11, 12, 14].contains(&themida.pe_info.major_linker_version)
        {
            query.try_find_correct_oep(themida, pe_entry_point)
        } else {
            None
        };

        if let Some(real_oep) = found_via_pattern_first {
            query.log(
                LogLevel::Info,
                &format!("Found MSVC OEP via pattern match on PE entry point: {real_oep:#x}"),
            );
            state.oep = Some(real_oep);
            state.provenance = OepProvenance::trace(
                real_oep as u64,
                format!("TryFindCorrectOEP runtime trace resolved application OEP: {real_oep:#x}"),
            );
            state.oep_found_via_scanning = false;
            query.remove_code_guard()?;
            return Ok(Some(AvOepAction::Break {
                oep: real_oep,
                provenance: state.provenance.clone(),
                remove_guard: false,
            }));
        }

        state.virtualized_oep_retries = state.virtualized_oep_retries.saturating_add(1);
        // Preserve candidate before redirect so null-AV storm escape can fall
        // back without depending on the soft-fail path.
        state.last_possible_oep = Some(address);
        query.log(
            LogLevel::Info,
            &format!(
                "Return address points into Themida section — OEP is virtualized (retry {})",
                state.virtualized_oep_retries
            ),
        );

        if state.virtualized_oep_retries >= input.virtualized_oep_max_retries {
            query.log(
                LogLevel::Warn,
                &format!(
                    "Too many virtualized OEP retries ({}) — using last Possible OEP",
                    state.virtualized_oep_retries
                ),
            );
            let (text_rva, text_size) = {
                let sec = &themida.pe_info.pe_sections[0];
                (sec.virtual_address, sec.virtual_size)
            };

            let found_via_pattern: Option<usize> = if themida.pe_info.major_linker_version == 2 {
                None
            } else if themida.pe_info.major_linker_version == 0
                || [6u8, 7, 8, 9, 10, 11, 12, 14].contains(&themida.pe_info.major_linker_version)
            {
                query.try_find_correct_oep(themida, address)
            } else {
                None
            };

            let (real_oep, real_oep_provenance) = if let Some(oep) = found_via_pattern {
                query.log(
                    LogLevel::Info,
                    &format!("Replaced virtualized OEP via TryFindCorrectOEP: {oep:#x}"),
                );
                (
                    Some(oep),
                    OepProvenance::trace(
                        oep as u64,
                        format!("virtualized-OEP retry TryFindCorrectOEP trace: {oep:#x}"),
                    ),
                )
            } else if let Some(oep) = query.scan_for_oep(text_rva, text_size) {
                query.log(
                    LogLevel::Info,
                    &format!("Replaced virtualized OEP with scanned OEP: {oep:#x}"),
                );
                (
                    Some(oep),
                    OepProvenance::scan_fallback(
                        oep as u64,
                        format!("virtualized-OEP retry live scan selected OEP: {oep:#x}"),
                    ),
                )
            } else {
                let fallback = state.last_possible_oep.or(Some(address));
                (
                    fallback,
                    OepProvenance::unknown(
                        "virtualized-OEP retry exhausted; only PossibleOEP candidate remains",
                    ),
                )
            };

            state.oep = real_oep;
            state.provenance = real_oep_provenance;
            state.oep_found_via_scanning =
                matches!(state.provenance.source, mida_core::OepSource::ScanFallback);
            query.remove_code_guard()?;
            let oep_str = state
                .oep
                .map(|a| format!("{a:#x}"))
                .unwrap_or_else(|| "unknown".into());
            query.log(
                LogLevel::Info,
                &format!("OEP found — removing guard ({oep_str})"),
            );
        } else {
            // Virtualized OEP: try to return into the Themida section so the
            // next guard hit can capture a better OEP. Soft-fail allowed.
            match query.set_redirect(ret_addr, 8) {
                Ok(()) => {
                    query.install_code_guard()?;
                    return Ok(Some(AvOepAction::RedirectAndContinue {
                        rip: ret_addr,
                        rsp_delta: 8,
                        reinstall_guard: false,
                    }));
                }
                Err(e) => {
                    query.log(LogLevel::Warn, &format!(
                        "virtualized OEP SetThreadContext soft-fail ({e}) — fall through with last Possible OEP"
                    ));
                    state.last_possible_oep = Some(address);
                    // Fall through: treat this AV as a usable OEP candidate
                    // and continue the non-virtualized epilogue below.
                }
            }
        }
    }

    state.last_possible_oep = Some(address);

    let text_len = themida
        .pe_info
        .base_of_data
        .wrapping_sub(u64::from(themida.pe_info.pe_sections[0].virtual_address))
        as usize;

    let found_oep = if text_len >= 10 {
        query.try_find_correct_oep(themida, address)
    } else {
        None
    };

    if !state.oep_found_via_scanning {
        if let Some(found) = found_oep {
            state.oep = Some(found);
            state.provenance = OepProvenance::trace(
                found as u64,
                format!("PossibleOEP runtime pattern trace resolved OEP: {found:#x}"),
            );
        } else {
            state.oep = Some(address);
            state.provenance = OepProvenance::unknown(format!(
                "PossibleOEP without confirming trace: {address:#x}"
            ));
        }
    }

    if found_oep.is_none()
        && themida.pe_info.major_linker_version != 0
        && [9u8, 10, 11, 12, 14].contains(&themida.pe_info.major_linker_version)
        && themida.guard_addrs.len() >= 2
    {
        let last_addr = themida.guard_addrs[themida.guard_addrs.len() - 1];
        let prev_addr = themida.guard_addrs[themida.guard_addrs.len() - 2];
        query.log(LogLevel::Info, &format!(
            "Virtual OEP detected — entering FTraceMSVCOEP mode (MSVC VM at OEP) prev={prev_addr:#x} last={last_addr:#x}"
        ));
        ftrace_enter_preserve_common_main(
            &mut themida.msvc_common_main_seh,
            &mut themida.msvc_init_cookie,
            &mut themida.msvc_oep,
            &mut themida.trace_msvc_oep,
            address,
            prev_addr,
        );
        state.oep = Some(prev_addr);
        state.provenance = OepProvenance::unknown(format!(
            "FTraceMSVCOEP preserved common-main/bootstrap candidate: {prev_addr:#x}"
        ));
        state.oep_found_via_scanning = false;
        let ret_addr = query.read_ret_addr(input.event_thread_id).unwrap_or(0);
        if ret_addr != 0 {
            if let Err(e) = query.set_redirect(ret_addr, 8) {
                query.log(
                    LogLevel::Warn,
                    &format!(
                    "FTraceMSVCOEP SetThreadContext soft-fail — continue without redirect ({e})"
                ),
                );
            }
        }
        query.remove_code_guard()?;
        query.install_code_guard()?;
        query.log(LogLevel::Info, &format!(
            "FTraceMSVCOEP: waiting after VM (preserved common_main={:#x}; cookie unresolved offline; oep_stub={:#x})",
            themida.msvc_common_main_seh, themida.msvc_oep
        ));
        return Ok(Some(AvOepAction::RedirectAndContinue {
            rip: ret_addr,
            rsp_delta: 8,
            reinstall_guard: false,
        }));
    }

    if let Some(oep_addr) = state.oep {
        let mut tm_start = usize::MAX;
        let mut tm_end = 0;
        for sec in &themida.pe_info.pe_sections {
            if crate::is_themida_section(sec) {
                let s = query.image_base() as usize + sec.virtual_address as usize;
                let e = s + sec.virtual_size as usize;
                tm_start = tm_start.min(s);
                tm_end = tm_end.max(e);
            }
        }

        if tm_start < tm_end && query.is_oep_virtualized(oep_addr, tm_start) {
            query.log(
                LogLevel::Info,
                &format!("OEP is virtualized — scanning .text for real OEP ({oep_addr:#x})"),
            );
            let (text_rva, text_size) = {
                let sec = &themida.pe_info.pe_sections[0];
                (sec.virtual_address, sec.virtual_size)
            };
            if let Some(real_oep) = query.scan_for_oep(text_rva, text_size) {
                query.log(
                    LogLevel::Info,
                    &format!("Replaced virtualized OEP with scanned OEP: {real_oep:#x}"),
                );
                state.oep = Some(real_oep);
                state.provenance = OepProvenance::scan_fallback(
                    real_oep as u64,
                    format!("virtualized OEP replaced by live .text scan: {real_oep:#x}"),
                );
                state.oep_found_via_scanning = true;
            }
        }
    }

    if found_oep.is_none() {
        if let Some(oep_addr) = state.oep {
            if let Some(oep_bytes) = query.read_code_bytes(oep_addr, 4) {
                if oep_bytes.len() >= 4 {
                    let looks_valid = matches!(oep_bytes[0], 0x48 | 0x55 | 0x53 | 0x56 | 0x57)
                        || (oep_bytes[0] == 0x41 && matches!(oep_bytes[1], 0x54..=0x57));
                    if looks_valid {
                        query.log(LogLevel::Info, &format!(
                            "OEP looks like valid x64 code — using as-is for non-MSVC compiler ({oep_addr:#x})"
                        ));
                        state.oep = Some(oep_addr);
                        state.provenance = OepProvenance::unknown(format!(
                            "PossibleOEP byte-shape heuristic only: {oep_addr:#x}"
                        ));
                    }
                }
            }
        }
    }

    Ok(None)
}
