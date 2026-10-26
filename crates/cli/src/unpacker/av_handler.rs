use anyhow::anyhow;
use tracing::{debug, info, warn};
use windows::Win32::Foundation::HANDLE;
use mida_core::{
    ctx_sp, set_ctx_ip, set_ctx_sp, ContinueStatus, DebugEvent, DebuggerCore,
};
use mida_pe::PeHeader;
use mida_packers_themida::{
    GuardAccessResult, ThemidaState,
    find_real_oep_by_scanning, install_code_section_guard, install_iat_guard,
    is_oep_virtualized, process_guarded_access, remove_code_section_guard,
    try_find_correct_oep, handle_tls_callbacks, determine_iat_address,
    KNOWN_MSVC_VERSIONS,
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

/// True when `code` is the HRESULT form of Windows `ERROR_SEM_TIMEOUT` (121).
///
/// `WaitForDebugEvent` uses that error to mean "the timeout expired and no debug
/// event arrived" — a normal idle interval, not a failure.  The core's
/// `wait_event_timeout` intends to convert it into `CoreError::Timeout` but
/// compares the entire HRESULT against `121`, so it never matches; the raw
/// `0x80070079` reaches the caller instead.
fn sem_timeout(code: u32) -> bool {
    code & 0xFFFF == 121
}

/// Read the page protection currently covering `addr` in the target.
///
/// Returns `None` when the range cannot be queried, so callers can fall back to
/// a safe default rather than guessing.
fn page_protection_of(h_process: HANDLE, addr: usize) -> Option<u32> {
    use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};

    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: h_process is a valid process handle; mbi is a valid out-pointer.
    let written = unsafe {
        VirtualQueryEx(
            h_process,
            Some(addr as *const std::ffi::c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        None
    } else {
        Some(mbi.Protect.0)
    }
}

/// Apply `protect` to the range [`addr`, `addr + size`) in the target.
fn set_protection(h_process: HANDLE, addr: usize, size: usize, protect: u32) -> bool {
    use windows::Win32::System::Memory::{VirtualProtectEx, PAGE_PROTECTION_FLAGS};

    let mut old = PAGE_PROTECTION_FLAGS::default();
    // SAFETY: h_process is valid; the range is a committed region of the target.
    unsafe {
        VirtualProtectEx(
            h_process,
            addr as *const std::ffi::c_void,
            size,
            PAGE_PROTECTION_FLAGS(protect),
            &mut old,
        )
        .is_ok()
    }
}

/// Extract the thread ID from any [`DebugEvent`] variant.
///
/// The packers crate has an equivalent `thread_id_of`, but it is
/// `pub(crate)` there and the settle window lives here.  Every variant except
/// [`DebugEvent::ExitProcess`] carries a thread ID; `ExitProcess` returns 0 and
/// is handled before this is ever consulted.
fn settle_thread_id_of(ev: &DebugEvent) -> u32 {
    match ev {
        DebugEvent::Breakpoint { thread_id, .. }
        | DebugEvent::SingleStep { thread_id, .. }
        | DebugEvent::AccessViolation { thread_id, .. }
        | DebugEvent::UnhandledException { thread_id, .. }
        | DebugEvent::CreateThread { thread_id, .. }
        | DebugEvent::ExitThread { thread_id, .. }
        | DebugEvent::LoadDll { thread_id, .. }
        | DebugEvent::UnloadDll { thread_id, .. }
        | DebugEvent::CreateProcess { thread_id, .. }
        | DebugEvent::Other { thread_id } => *thread_id,
        DebugEvent::ExitProcess { .. } => 0,
    }
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

/// How many times the `.text` guard may fault at an address whose return
/// address lands inside the Themida section before the caller stops waiting for
/// the shell to unwind and falls back to scanning.
///
/// Each retry is one full guard cycle (arm `PAGE_NOACCESS`, take the execute
/// fault, single-step out, re-arm), so this is a *time* budget as much as a
/// count.  It used to be 1000, which on the x86 reference sample meant the run
/// sat silent for minutes and looked hung — the retry counter never advanced
/// past 1 because the shell stops re-entering the guarded page at all.
///
/// 64 is chosen to be comfortably above the deepest observed unwind chain
/// (3 on the x64 reference EXE) while keeping a stuck run bounded to seconds.
const VIRTUALIZED_OEP_RETRY_LIMIT: u32 = 64;

/// Seconds to let a packed DLL finish its own `DllMain` initialisation after
/// its import table is ready, before the image is dumped.
///
/// # Measured status: this window does not currently change the outcome
///
/// The original rationale was that the reference `core.dll` writes its version
/// string into `.bss` *after* the import table is complete, so a dump taken at
/// the end of the IAT window would answer `GetAppVersion() -> "0.0"`.  That
/// rationale has been tested and **does not hold as stated**:
///
/// * A 0 s, 2 s and 12 s window all produce a `.bss` with **1** non-zero byte,
///   while the same DLL loaded by the real loader (`LoadLibraryW`, no debugger)
///   has **177**.  Time is not the variable.
/// * The dump's `.bss` is *byte-identical* to what an external reader sees in
///   the debuggee at 8.4 s, so the reader is faithful — this is not a
///   read-too-early defect either.
/// * In the debuggee the loader thread is frozen at rva `0x2C387`
///   (`call [InitializeCriticalSection]`) for the whole window and never leaves
///   it; `.host.log` stays empty, so `LoadLibraryW` never returns.
/// * Under a *plain* debugger (`cdb`) the same DLL raises a first-chance
///   `0xC000008E` (FLT_DIVIDE_BY_ZERO) during initialisation.  Being debugged
///   is therefore enough to divert the shell — the unpacker is not the sole
///   cause.
///
/// The window is kept because it is harmless, it is the correct place for a
/// settle phase, and the remaining non-zero bytes it does capture
/// (`.bss+0x2CCC`, `.bss+0x2D08`, `.bss+0x2D20`, `.bss+0x2D40`) match the real
/// loader's values.  It is documented as ineffective rather than presented as
/// a fix.
const DLL_SETTLE_SECS: u64 = 2;

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

/// True when a fault's *target* address lies inside the guarded `.text` range.
///
/// This is what distinguishes a guard-driven retry (expected, self-limiting, must
/// not count toward the storm budget) from the shell faulting somewhere else
/// (not expected, must count).
///
/// Measured failure this guards against: on the x86 reference sample the shell
/// faulted at `.themida+0x538866` reading address `0x5` — far outside the guarded
/// `.text` — 156,309 times.  The storm counter was reset on *every* fault
/// regardless of where it landed, so the watchdog never fired and the log grew
/// without bound instead of failing with a diagnosis.
fn is_guarded_text_fault(target_address: u64, text_start: usize, text_end: usize) -> bool {
    let t = target_address as usize;
    t >= text_start && t < text_end
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
        return (start, end);
    }

    // Fallback: the section that holds the *packed* entry point.  The
    // 1.9-generation shells let their user rename the section (`Tuts4You` in
    // the version ladder), which defeats every name heuristic, but the shell's
    // code still lives where the packed EP points — and that is the region the
    // OEP-verification probe must recognise as "the protector".
    let ep = state.pe_info.packed_entry_point;
    for sec in &state.pe_info.pe_sections {
        let va = sec.virtual_address;
        if ep >= va && ep < va.saturating_add(sec.virtual_size) {
            let s = image_base.wrapping_add(va as usize);
            let e = s.wrapping_add(sec.virtual_size as usize);
            return (s, e);
        }
    }
    (0, 0)
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

    let text_start = (dbg.image_base() as usize)
        .wrapping_add(state.pe_info.pe_sections[0].virtual_address as usize);
    let text_end = dbg.image_base() as usize + state.pe_info.base_of_data as usize;

    // Only a fault that actually lands inside the guarded `.text` range is a
    // guard-driven fault, and only those are self-limiting.
    //
    // This distinction is the difference between "expected retry" and "the shell
    // is dereferencing a null-ish pointer forever".  It used to reset
    // unconditionally, which silently disabled the storm watchdog: measured on
    // the x86 reference sample, the shell faulted at `.themida+0x538866`
    // reading address `0x5` — nowhere near the guard — and because every one of
    // those 156,309 faults reset the counter, the watchdog never fired and the
    // log grew without bound instead of failing with a diagnosis.
    let fault_in_guarded_text = is_guarded_text_fault(target_address, text_start, text_end);
    if fault_in_guarded_text {
        ls.av_storm.reset();
    }

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

            let mut direct_oep_accepted = false;

            // ---- DLL targets and classic (v1-generation) stubs ---------------
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
            // The same reasoning covers the classic v1-generation EXE stub
            // (measured on Themida 1.1.1.0, 2026-10-26): the shell jumps to the
            // OEP when it is done, and whatever is on the stack at that moment
            // belongs to the shell's own call chain, so a Themida-section
            // return address proves nothing.  For both targets the only
            // question that matters: is the instruction here a transfer into
            // the protector?  If not, control has genuinely reached decrypted
            // code and this is the OEP.
            let classic_stub = matches!(
                state.pe_info.themida_version,
                mida_packers_themida::ThemidaVersion::V1
                    | mida_packers_themida::ThemidaVersion::Ancient
            );
            if is_dll_target || classic_stub {
                let (tm_start, tm_end) = themida_bounds(state, dbg.image_base() as usize);
                let virtualized = tm_start < tm_end && is_oep_virtualized(dbg, address, tm_start);
                if !virtualized {
                    // Classic (v1-generation) candidates must prove they never
                    // return: the shell calls its own helpers inside `.text`
                    // before the real jump to the OEP, and the first execute
                    // fault is one of those helpers, not the entry (measured on
                    // Themida 1.9.1.0, 2026-10-26: the first candidate was
                    // mid-function code).  Arm an execute breakpoint on the
                    // candidate's return address; if it fires during the
                    // execution window below, the candidate was a helper and
                    // the hunt continues at the tail of this handler.
                    let mut classic_verifying = false;
                    if classic_stub {
                        // The classic shell rebuilds the original PE header in
                        // place before transferring control, so the *live*
                        // header's entry point is the ground truth for the
                        // OEP — log it against the fault candidate.
                        let read_u32_at = |va: usize| -> Option<u32> {
                            let mut b = [0u8; 4];
                            dbg.read_memory(va, &mut b).ok()?;
                            Some(u32::from_le_bytes(b))
                        };
                        if let Some(e_lfanew) = read_u32_at(dbg.image_base() as usize + 0x3C) {
                            let opt = dbg.image_base() as usize + e_lfanew as usize + 24;
                            if let Some(live_ep) = read_u32_at(opt + 16) {
                                log::log(
                                    LogType::Info,
                                    &format!(
                                        "classic OEP candidate {address:#x}: live header EP =                                          {live_ep:#x} (packed EP {:#x})",
                                        state.pe_info.packed_entry_point
                                    ),
                                );
                            }
                        }
                        let probe_fail = |why: &str| {
                            log::log(
                                LogType::Info,
                                &format!("classic OEP probe not armed: {why}"),
                            );
                        };
                        if let Ok(ctx) = dbg.get_thread_context_control(thread_id) {
                            let sp = ctx_sp(&ctx);
                            let mut ret_bytes = [0u8; 8];
                            if dbg.read_memory(sp, &mut ret_bytes).is_ok() {
                                let ret = u64::from_le_bytes(ret_bytes) as usize;
                                let (tm_start, tm_end) =
                                    themida_bounds(state, dbg.image_base() as usize);
                                if tm_start < tm_end && ret >= tm_start && ret < tm_end {
                                    dbg.clear_hw_breakpoint(0)?;
                                    dbg.set_hw_breakpoint(
                                        0,
                                        ret,
                                        mida_core::HwbpType::Execute,
                                    )?;
                                    state.classic_pending_ret = Some(ret);
                                    classic_verifying = true;
                                    log::log(
                                        LogType::Info,
                                        &format!(
                                            "classic OEP candidate {address:#x}: verifying —                                              return address {ret:#x} armed as execute breakpoint"
                                        ),
                                    );
                                } else {
                                    probe_fail(&format!(
                                        "return address {ret:#x} outside the protector bounds                                          {tm_start:#x}..{tm_end:#x}"
                                    ));
                                }
                            } else {
                                probe_fail("stack top unreadable at the candidate");
                            }
                        } else {
                            probe_fail("thread context unavailable at the candidate");
                        }
                    }
                    ls.oep = Some(address);
                    remove_code_section_guard(
                        h_process,
                        text_start,
                        text_end.saturating_sub(text_start),
                    )?;
                    let target_kind = if is_dll_target { "DLL" } else { "classic" };
                    log::log(
                        LogType::Info,
                        &format!(
                            "{target_kind} OEP accepted at {address:#x} (rva {:#x}) — real                              decrypted code, not a protector trampoline{}",
                            address.wrapping_sub(dbg.image_base() as usize),
                            if classic_verifying { " (verification armed)" } else { "" }
                        ),
                    );
                    // Skip the EXE-oriented virtualised-OEP heuristics entirely
                    // and fall through to the IAT decryption window at the tail
                    // of this function.  Breaking here would dump the image
                    // before the shell finishes decrypting the import table:
                    // observed on core.dll, that yields 357 of 3282 slots.
                    direct_oep_accepted = true;
                } else {
                    let target_kind = if is_dll_target { "DLL" } else { "classic" };
                    log::log(
                        LogType::Info,
                        &format!(
                            "{target_kind} OEP candidate {address:#x} is a protector                              trampoline — continuing"
                        ),
                    );
                }
            }

            if !direct_oep_accepted {
            let tls_total = state.pe_info.tls_total;
            let tls_result = handle_tls_callbacks(
                dbg,
                thread_id,
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
                if dbg.read_memory(ctx_sp(&ctx), &mut ret_bytes).is_ok() {
                    ret_addr = u64::from_le_bytes(ret_bytes) as usize;
                    info!(
                        rsp = %format!("{:#x}", ctx_sp(&ctx)),
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

                    if ls.virtualized_oep_retries >= VIRTUALIZED_OEP_RETRY_LIMIT {
                        warn!("Too many virtualized OEP retries ({}) — using last Possible OEP", ls.virtualized_oep_retries);
                        let text_sec = &state.pe_info.pe_sections[0];
                        let text_base = dbg.image_base() as usize + text_sec.virtual_address as usize;
                        let text_end = dbg.image_base() as usize + state.pe_info.base_of_data as usize;
                        let text_len = text_end.saturating_sub(text_base);

                        // Do **not** special-case linker version 2 here.
                        //
                        // This used to be `if version == 2 { None } else if ...`,
                        // which excluded MinGW/GCC output: its PE header reports
                        // `MajorLinkerVersion = 2` (measured on the x86 reference
                        // sample built with i686-w64-mingw32-gcc 16.2.0 — linker
                        // 2.47).  Version 2 does not mean "no CRT startup pattern
                        // to find"; it only meant that for the ancient MSVC 6
                        // builds the original Pascal code was written against.
                        // `try_find_correct_oep` already gates on
                        // `KNOWN_MSVC_VERSIONS`, which *includes* 2, so letting it
                        // decide is both simpler and correct.
                        let found_via_pattern: Option<usize> =
                            if state.pe_info.major_linker_version == 0
                                || KNOWN_MSVC_VERSIONS
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
                        set_ctx_ip(&mut ctx, ret_addr);
                        let sp = ctx_sp(&ctx) + 8;
                        set_ctx_sp(&mut ctx, sp);
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
                    if dbg.read_memory(ctx_sp(&ctx), &mut ret_bytes).is_ok() {
                        ret_addr = u64::from_le_bytes(ret_bytes) as usize;
                    }
                    if ret_addr != 0 {
                        let mut new_ctx = dbg.get_thread_context_control(thread_id)
                            .map_err(|e| anyhow!("get_thread_context_control: {e}"))?;
                        set_ctx_ip(&mut new_ctx, ret_addr);
                        let sp = ctx_sp(&new_ctx) + 8;
                        set_ctx_sp(&mut new_ctx, sp);
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
        set_ctx_ip(&mut ctx, oep_addr);
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
            &super::helpers::section_table(&state.pe_info.pe_sections),
        ) {
            Ok(Some(iat)) => iat,
            Ok(None) => {
                warn!("IAT not found — skipping IAT monitoring");
                if state.classic_pending_ret.take().is_some() {
                    state.classic_ret_hit = false;
                    let _ = dbg.clear_hw_breakpoint(0);
                }
                return Ok(AvAction::Break);
            }
            Err(e) => {
                warn!("IAT detection failed: {e} — skipping IAT monitoring");
                if state.classic_pending_ret.take().is_some() {
                    state.classic_ret_hit = false;
                    let _ = dbg.clear_hw_breakpoint(0);
                }
                return Ok(AvAction::Break);
            }
        };

        info!(iat = %format!("{:#x}", iat.address), size = %format!("{:#x}", iat.size), "IAT located");

        state.guard_start = iat.address;
        state.guard_end = iat.address + iat.size;

        // ---- DLL targets: do NOT arm the IAT guard -------------------------
        //
        // Measured, and this is the whole point of this branch:
        //
        //   IAT guard armed (PAGE_NOACCESS, 5 s, faults answered with
        //   DBG_CONTINUE):  `.bss` = 0 non-zero bytes, `hinstDLL` = 0
        //   IAT guard not armed:                    `.bss` = 177, `hinstDLL` set
        //
        // Both runs had ScyllaHide injected and were under this same debugger,
        // and the loader reached the DLL in both.  A packed DLL is still inside
        // its own `DllMain` at this point; the guard makes every IAT access fault,
        // the fault is answered "handled", the instruction retries, and the shell
        // burns the entire window in a fault storm (measured 480,055 faults in
        // 10 s) instead of initialising.  Releasing the guard afterwards does not
        // recover it — measured `nz` stayed 0 and the fault count kept climbing —
        // because the shell has already taken its "something is wrong" path.
        //
        // An EXE is different: by the time the OEP is reached the process is
        // fully initialised, so the guard only observes IAT decryption.
        //
        // The guard's only downstream product is `state.guard_addrs`, which feeds
        // `determine_iat_address` / `fixup_api_call_sites` as a *hint*.  For the
        // DLL path the IAT is already known (`iat` above), so the hint is not
        // needed; skipping the window costs nothing and preserves initialisation.
        //
        // Note this skips only the guard *window*: control falls through to the
        // DllMain settle window below, which is where the shell is supposed to
        // finish initialising.
        let mut iat_violations = 0;
        if is_dll_target {
            // The import table must be writable before the trace engine writes
            // resolved addresses back into it.  Measured on the reference DLL:
            // the shell leaves the IAT at `PAGE_READONLY` (0x2), and the final
            // `trace_imports write IAT` fails with a write fault unless this is
            // raised.  Guarding it was what used to do that indirectly.
            let before = page_protection_of(h_process, iat.address);
            let ok = set_protection(h_process, iat.address, iat.size, 0x04);
            info!(
                iat = %format!("{:#x}", iat.address),
                size = %format!("{:#x}", iat.size),
                before = ?before.map(|p| format!("{p:#x}")),
                writable = ok,
                "DLL target — skipping the IAT guard window so DllMain can initialise"
            );
        } else {
            // Record the IAT's real protection *before* the guard replaces it
            // with `PAGE_NOACCESS`.  Querying afterwards only ever returns the
            // guard's own value, which is why the restoration below must not
            // re-read it later.
            let iat_protect_before = page_protection_of(h_process, iat.address);
            debug!(
                protect = ?iat_protect_before.map(|p| format!("{p:#x}")),
                "IAT protection before guard"
            );

            install_iat_guard(h_process, iat.address, iat.size)?;

            info!("Letting program execute for 5 seconds to decrypt IAT...");

        // Classic targets get a longer window: the shell's interlude between
        // its last CloseHandle and the real OEP jump measured 37 s on Themida
        // 1.9.1.0, and a helper candidate's return must be observable inside
        // the window.  The window also ends early once the probe fires.
        let classic_stub = matches!(
            state.pe_info.themida_version,
            mida_packers_themida::ThemidaVersion::V1
                | mida_packers_themida::ThemidaVersion::Ancient
        );
        let timeout = std::time::Duration::from_secs(if classic_stub { 45 } else { 5 });
        let start_time = std::time::Instant::now();

        loop {
            if state.classic_ret_hit {
                info!("classic OEP probe fired inside the window — candidate rejected");
                break;
            }
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
                        DebugEvent::SingleStep { address, .. } => {
                            // The classic return-address probe: the candidate
                            // returned to the protector.
                            if state.classic_pending_ret == Some(address as usize) {
                                state.classic_ret_hit = true;
                                let _ = dbg.clear_hw_breakpoint(0);
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

        // ---- Restore the IAT's own protection ------------------------------
        //
        // `remove_code_section_guard` is named for a *code* section and hard-codes
        // `PAGE_EXECUTE_READ` as the restored protection.  Calling it on the IAT
        // range (a data section) therefore makes the import table read-only.
        //
        // So: restore what the IAT had before we armed the guard.  A committed
        // data section is `PAGE_READWRITE`; anything else (including a failed
        // query, or the guard's own `PAGE_NOACCESS`) falls back to that, because
        // an import table is always written to.
        remove_code_section_guard(h_process, iat.address, iat.size)?;
        let restored = match iat_protect_before {
            Some(p) if p & 0x04 != 0 && p != 0x01 => p,
            _ => 0x04, // PAGE_READWRITE — the only sane protection for an import table
        };
        if !set_protection(h_process, iat.address, iat.size, restored) {
            warn!(
                protect = %format!("{restored:#x}"),
                "Could not restore IAT page protection — target initialisation may stall"
            );
        } else {
            debug!(
                before = ?iat_protect_before.map(|p| format!("{p:#x}")),
                applied = %format!("{restored:#x}"),
                "IAT page protection restored after guard removal"
            );
        }
        } // end: non-DLL IAT guard window
        info!(violations = iat_violations, "IAT monitoring complete");

        // ---- DLL targets: let `DllMain` finish before dumping ----------------
        //
        // A packed DLL does not stop at "IAT decrypted": its `DllMain` keeps
        // initialising global state afterwards.  This window is where that is
        // meant to happen.
        //
        // It currently does *not* achieve it — see the measured status on
        // `DLL_SETTLE_SECS`.  The window is retained as the correct place for a
        // settle phase, and the loop below is kept correct so that when the real
        // blocker is fixed the window will do its job.
        //
        // The dump point is therefore "the import table is ready AND the target
        // has had time to finish its own initialisation".  We cannot wait for
        // `DllMain` to *return* (our guard page faults on every `.text`
        // execution and the shell never reaches its epilogue while we hold it),
        // so the window is time-based, with the guard already removed so the
        // target runs at full speed.
        if is_dll_target && DLL_SETTLE_SECS > 0 {
            let settle = std::time::Duration::from_secs(DLL_SETTLE_SECS);
            info!(
                secs = DLL_SETTLE_SECS,
                "DLL target — letting DllMain finish its own initialisation before dumping"
            );
            let settle_start = std::time::Instant::now();

            // This loop owns the debug session for the length of the window, so
            // it must answer every event it takes, on the thread that raised it.
            //
            // The previous version got this exactly backwards and was therefore
            // dead on arrival:
            //
            //   loop {
            //       continue_event(thread_id, ...);   // <- no event pending here
            //       match wait_event_timeout(100) {
            //           Ok(_) => {}                   // <- event swallowed, never answered
            //       }
            //   }
            //
            // `continue_event` requires a pending event; called with nothing
            // pending it fails with `E_INVALIDARG` (2147942487), which broke the
            // loop on its first iteration (`elapsed_ms=114` instead of 2000).
            // Every event it did dequeue was dropped, so the debug session was
            // already dead when `fix_iat_v3` started: measured 289 resolved → 142,
            // with every failure reporting `trace_one_slot continue: Windows API
            // error: code 2147942487`.
            //
            // The correct shape is wait → answer → repeat, answering on the
            // event's own thread (a helper thread may raise the event).
            while settle_start.elapsed() < settle {
                match dbg.wait_event_timeout(100) {
                    Ok(DebugEvent::ExitProcess { .. }) => {
                        info!("Target exited while waiting for DllMain to finish");
                        break;
                    }
                    Ok(ev) => {
                        let ev_tid = settle_thread_id_of(&ev);
                        // A fault during initialisation is not fatal for our
                        // purposes — the shell may probe and recover.  Answer it
                        // and keep the window open; the IAT is already captured.
                        if let DebugEvent::AccessViolation { address, target_address, .. } = &ev {
                            debug!(
                                address = %format!("{address:#x}"),
                                target = %format!("{target_address:#x}"),
                                "settle window: access violation, continuing"
                            );
                        }
                        if dbg.continue_event(ev_tid, ContinueStatus::Continue).is_err() {
                            warn!("settle window: continue_event failed — ending window early");
                            break;
                        }
                    }
                    Err(mida_core::CoreError::Timeout) => {}
                    Err(mida_core::CoreError::Windows(code)) if sem_timeout(code) => {
                        // Belt-and-braces.  Core now maps `ERROR_SEM_TIMEOUT`
                        // correctly (`windows_debugger::is_sem_timeout`), so an
                        // idle interval arrives as `CoreError::Timeout` and is
                        // handled by the arm above.  This guard stays because a
                        // caller that reduces the HRESULT itself would otherwise
                        // turn a benign idle tick into an early exit — the
                        // original symptom was the settle window ending at 105 ms
                        // instead of the requested 2000 ms.
                        //
                        // The loop is bounded by `settle_start.elapsed()`, so this
                        // cannot spin forever.
                    }
                    Err(e) => {
                        warn!("settle window: debug event error: {e}");
                        break;
                    }
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

        // Bound in `u64`: the upper limit does not fit a 32-bit `usize`.
        let api_like_count = slot_values.iter()
            .filter(|&&v| (v as u64) > 0x10000 && (v as u64) < 0x7FFF_FFFF_FFFFu64)
            .count();
        info!(api_like = api_like_count, total = actual_slots, "IAT analysis after execution");

        // ---- classic OEP verification verdict -------------------------------
        //
        // The candidate was accepted provisionally; the return-address probe
        // decides.  A fired probe means the candidate was a shell helper: it
        // returned to the protector after doing its work.  Reject it, re-arm
        // the `.text` guard, and let the debug loop bring the next execute
        // fault — the hunt continues until a candidate that never returns.
        if let Some(ret) = state.classic_pending_ret.take() {
            if state.classic_ret_hit {
                state.classic_ret_hit = false;
                ls.oep = None;
                ls.iat_monitoring_done = false;
                install_code_section_guard(
                    h_process,
                    text_start,
                    text_end.saturating_sub(text_start),
                    guard_protection,
                )?;
                log::log(
                    LogType::Info,
                    &format!(
                        "classic OEP candidate rejected: execution returned to the                          protector at {ret:#x} — keeping the guard and hunting on"
                    ),
                );
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                return Ok(AvAction::Continue);
            }
            let _ = dbg.clear_hw_breakpoint(0);
            log::log(
                LogType::Info,
                "classic OEP verified: the candidate never returned to the protector",
            );
        }

        ls.iat_monitoring_done = true;
        return Ok(AvAction::Break);
    }

    // Early exits above (IAT detection failures) must not leave a stale probe
    // armed: the state would leak into the next candidate.
    if state.classic_pending_ret.take().is_some() {
        state.classic_ret_hit = false;
        let _ = dbg.clear_hw_breakpoint(0);
    }

    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
    Ok(AvAction::Continue)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // is_guarded_text_fault — the storm watchdog's scope test
    // ------------------------------------------------------------------

    /// A fault whose target is inside `.text` is a guard retry.
    #[test]
    fn fault_inside_text_is_a_guard_retry() {
        // Reference x86 sample: .text at image_base+0x1000, base_of_data ends it.
        let (start, end) = (0x401000usize, 0x403000usize);
        assert!(is_guarded_text_fault(0x401810, start, end));
        assert!(is_guarded_text_fault(0x401000, start, end));
        assert!(is_guarded_text_fault(0x402fff, start, end));
    }

    /// The exact fault that produced 156,309 log lines must NOT be treated as a
    /// guard retry — it lands in `.themida`, reading address `0x5`.
    ///
    /// This is the regression test for the watchdog being silently disabled:
    /// because every fault reset the counter unconditionally, this one never
    /// tripped it.
    #[test]
    fn fault_in_themida_is_not_a_guard_retry() {
        let (start, end) = (0x401000usize, 0x403000usize);
        assert!(
            !is_guarded_text_fault(0x5, start, end),
            "reading address 0x5 is nowhere near .text"
        );
        // The faulting instruction lived at .themida+0x538866; its *target* was 0x5.
        // Either way it must not count as guarded.
        assert!(!is_guarded_text_fault(0x538866, start, end));
    }

    /// Boundaries are half-open: `end` is exclusive.
    #[test]
    fn text_range_is_half_open() {
        let (start, end) = (0x1000usize, 0x2000usize);
        assert!(is_guarded_text_fault(0x1000, start, end), "start is inside");
        assert!(!is_guarded_text_fault(0x2000, start, end), "end is outside");
        assert!(!is_guarded_text_fault(0x0fff, start, end), "below start");
    }

    /// A zero-width range (no guard identified) accepts nothing.
    #[test]
    fn empty_range_accepts_nothing() {
        assert!(!is_guarded_text_fault(0x1000, 0x1000, 0x1000));
    }

    // ------------------------------------------------------------------
    // AvStorm — consecutive-identical detection
    // ------------------------------------------------------------------

    #[test]
    fn storm_fires_on_identical_faults() {
        let mut s = AvStorm::default();
        for i in 0..AV_STORM_LIMIT {
            let fired = s.record(0x1000, 0x2000, 0);
            if i + 1 < AV_STORM_LIMIT {
                assert!(!fired, "must not fire before the limit (iteration {i})");
            } else {
                assert!(fired, "must fire at the limit");
            }
        }
    }

    #[test]
    fn storm_survives_a_changing_fault() {
        let mut s = AvStorm::default();
        // A different fault resets the count, so a merely busy target is never
        // killed.
        for _ in 0..(AV_STORM_LIMIT * 2) {
            assert!(!s.record(0x1000, 0x2000, 0));
            assert!(!s.record(0x3000, 0x4000, 0), "alternating faults never storm");
        }
    }

    #[test]
    fn reset_clears_the_streak() {
        let mut s = AvStorm::default();
        for _ in 0..(AV_STORM_LIMIT - 1) {
            s.record(0x1000, 0x2000, 0);
        }
        s.reset();
        assert!(
            !s.record(0x1000, 0x2000, 0),
            "after reset the counter starts over"
        );
    }

    /// The exc_type is part of the identity: a read fault and an execute fault at
    /// the same addresses are different events.
    #[test]
    fn exc_type_is_part_of_the_identity() {
        let mut s = AvStorm::default();
        for _ in 0..(AV_STORM_LIMIT - 1) {
            s.record(0x1000, 0x2000, 0);
        }
        assert!(
            !s.record(0x1000, 0x2000, 8),
            "changing exc_type starts a new streak"
        );
    }
}
