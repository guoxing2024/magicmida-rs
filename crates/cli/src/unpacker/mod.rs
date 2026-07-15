//! Themida unpacker main flow — ties together all modules.
//!
//! ## Reference
//!
//! This module corresponds to the combined logic of:
//! - `Themida.pas` / `Themida64.pas` — the full unpacking pipeline.
//! - `Magicmida.dpr` → `CheckCommandlineInvocation` — CLI dispatch.
//! - `Unit2.pas` → `btnUnpackClick` — per-file unpack entry point.
//!
//! ## Architecture
//!
//! ```text
//! parse PE ─▶ detect Themida ─▶ create process ─▶ init state ─▶ ScyllaHide
//!                                                                    │
//!    ┌───────────────────────────────────────────────────────────────┘
//!    ▼
//!  debug loop (simplified):
//!    · wait_event → handle anti-debug → CloseHandle bp → install guard
//!    · ACCESS_VIOLATION → process_guarded_access → detect OEP
//!    · OEP found → remove guard → IAT phase
//!    ▼
//!  determine IAT ─▶ fix IAT ─▶ [trace imports (v3)] ─▶ fix call sites
//!    ▼
//!  dump to file ─▶ postprocess (data sections / shrink) ─▶ cleanup
//! ```

mod av_handler;
mod dump;
mod helpers;
mod iat_trace;
mod oep_scan;
mod session;
mod verify;

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context};
use tracing::{debug, info, warn};
use windows::Win32::System::Memory::PAGE_NOACCESS;
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

use crate::log::{self, LogType};
use mida_core::{ContinueStatus, CreateProcessOptions, DebugEvent, DebuggerCore, HwbpType};
use mida_packers_themida::{
    create_data_sections, determine_iat_address, fix_iat, fixup_api_call_sites,
    handle_nt_set_information_thread, init_pe_details, inject_scylla_hide, install_anti_dump_fix,
    shrink_pe, CompilerHint, IatFixStrategy, ScyllaHideConfig, ThemidaState,
};
use mida_pe::{DumpOptions, EarlySectionSnapshot, PeHeader};

use av_handler::{handle_access_violation, AvAction};
use helpers::{
    compute_data_section_bounds, dotnet_dump_and_dump_output, handle_hw_breakpoint,
    pe_section_name_remote_rva, resolve_api_addrs, resolve_host_api, resolve_output_path,
    scylla_hook_path, scylla_injector_path,
};
use iat_trace::{handle_trace_step, IatTraceState, TracePhase};
use oep_scan::scan_live_memory_for_real_oep;
use session::ProcessSession;

// Re-export public functions for commands.rs
pub use dump::dump_process_code;
pub use verify::verify_unpacked;

// ---------------------------------------------------------------------------
// LoopState — mutable tracking variables for the debug loop
// ---------------------------------------------------------------------------

struct LoopState {
    guard_installed: bool,
    close_handle_bp_set: bool,
    nt_protect_bp_set: bool,
    // .text poll: true when CREATE_PROCESS received, actively polling .text
    text_polling: bool,
    /// .text poll: Instant when polling started (for 30s timeout)
    text_poll_start: Option<std::time::Instant>,
    /// .text poll: count of wait_event iterations since guard installed
    text_poll_count: u32,
    /// .text poll: previous snapshot for stability check
    text_prev_sample: [u8; 16],
    /// .text poll: true when .text content is stable (two consecutive reads match)
    text_stable: bool,
    /// .text poll: re-guard done, waiting for AV at OEP
    text_reguarded: bool,
    oep: Option<usize>,
    oep_found_via_scanning: bool,
    virtualized_oep_retries: u32,
    last_possible_oep: Option<usize>,
    iat_trace: Option<IatTraceState>,
}

// ---------------------------------------------------------------------------
// Unpack
// ---------------------------------------------------------------------------

/// Unpack a Themida-protected executable.
///
/// This is the main entry point for the `/unpack` command. It orchestrates the
/// full pipeline: PE parsing, Themida detection, process creation, debug loop,
/// IAT repair, dump, and post-processing.
///
/// # Arguments
///
/// - `input` — path to the protected executable.
/// - `output` — optional output path; defaults to `<input_stem>U<ext>` (the "U"
///   suffix convention from the Pascal reference).
/// - `create_data_sections` — restore `.rdata`/`.data` sections (`--data-sections`).
/// - `shrink` — remove Themida-specific sections from the output (`--shrink`).
///
/// # Errors
///
/// Returns an [`anyhow::Error`] on any failure.
pub fn unpack(
    input: &Path,
    output: Option<&Path>,
    do_data_sections: bool,
    shrink: bool,
) -> Result<(), anyhow::Error> {
    // ---- step 1: resolve output path ----
    let output_path = resolve_output_path(input, output);

    // ---- step 2: parse PE header ----
    log::log(LogType::Info, &format!("Loading: {}", input.display()));

    let mut pe =
        PeHeader::from_file(input).map_err(|e| anyhow!("Failed to parse PE header: {e}"))?;

    let is_64bit = pe.is_64bit;
    debug!(is_64bit, "PE architecture");

    // ---- step 3: detect Themida ----
    // Read entry-point bytes for virtualised OEP detection.
    let ep_offset_val = pe.rva_to_offset(pe.entry_point).unwrap_or(0) as usize;
    let entry_bytes = fs::read(input).ok().and_then(|data| {
        data.get(ep_offset_val..ep_offset_val.saturating_add(8))
            .map(|b| b.to_vec())
    });
    if let Some(ref bytes) = entry_bytes {
        log::log(
            LogType::Info,
            &format!(
                "Entry point RVA: {:#x}, EP offset: {:#x}, EP bytes: {:02X?}",
                pe.entry_point, ep_offset_val, bytes
            ),
        );
    }
    let entry_bytes_ref = entry_bytes.as_deref();

    let pe_info = init_pe_details(&pe, is_64bit, entry_bytes_ref, Some(input))
        .map_err(|e| anyhow!("Themida detection failed: {e}"))?;

    log::log(
        LogType::Info,
        &format!("Themida version: {:?}", pe_info.themida_version),
    );

    // ---- step 3b: detect .NET target early ----
    // .NET + Themida binaries are dumped differently: no import
    // reconstruction required. We wait for the mscoree.dll entry point
    // (_CorExeMain) to be called, then dump the raw memory.
    // Matches Magicmida: Detect via COM descriptor data directory; if
    // present, resolve _CorExeMain by iterating DLL breakpoints.
    const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
    let is_dotnet = pe.nt_headers.optional_header.data_directory
        [IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        .virtual_address
        != 0;
    if is_dotnet {
        log::log(
            LogType::Info,
            ".NET target detected — will dump via _CorExeMain breakpoint",
        );
    }

    // ---- step 3c: for .NET targets, pre-resolve _CorExeMain from host mscoree ----
    // The host-side address is usually valid in the target because mscoree.dll
    // is loaded at a per-system ASLR base shared across processes.
    let mut cor_exe_main_addr: Option<usize> = None;
    if is_dotnet {
        cor_exe_main_addr = Some(resolve_host_api("mscoree.dll", "_CorExeMain"));
        if cor_exe_main_addr == Some(0) {
            warn!("_CorExeMain not found — .NET dump may fail");
            cor_exe_main_addr = None;
        }
    }

    // ---- step 4: create debug process ----
    // Initialise Themida state first — we need pe_sections to decide
    // whether to use post-attach mode.
    let mut state = ThemidaState::new(pe_info, do_data_sections);
    state.create_data_sections = do_data_sections;
    // Propagate TLS callback count detected during init_pe_details.
    state.tls_total = state.pe_info.tls_total;

    // post-attach mode: when section 0 is plain ".text" (not a Themida
    // virtualized section) and the target isn't .NET, create the process
    // without DEBUG_ONLY_THIS_PROCESS and explicitly resume it after the early
    // loader-initialized section snapshot has been captured.
    // protectors that read EPROCESS.DebugPort from t=0 and exit with
    // 0xDEADC0DE.  See WindowsDebugger::post_attach_init.
    // post-attach: when section 0 is plain .text (not a Themida
    // virtualized section) and the target is not .NET, create the
    // process WITHOUT DEBUG_ONLY_THIS_PROCESS.
    let text_is_plain_for_attach = state
        .pe_info
        .pe_sections
        .first()
        .is_some_and(|s| s.name == ".text")
        && !is_dotnet;
    let opts = CreateProcessOptions {
        executable: input.to_path_buf(),
        command_line: None,
        is_dll: input
            .extension()
            .map(|e| e.eq_ignore_ascii_case("dll"))
            .unwrap_or(false),
        suspended: false,
        post_attach: text_is_plain_for_attach,
    };

    // ---- step 6: debug loop ----
    // The debug loop is the heart of the unpacker. It is implemented inline
    // here because it needs intimate access to the debugger and the evolving
    // ThemidaState.
    //
    // We keep a simplified version that handles the key events:
    // - CreateProcess → patch PEB, resolve APIs, apply ScyllaHide
    // - LoadDll → close file handle
    // - Breakpoint (CloseHandle) → install code section guard
    // - AccessViolation → process_guarded_access
    // - SingleStep → restore_code_section_guard
    //
    // The full IAT repair and dump happen *after* the guard loop detects OEP.

    // Build the core debugger — it owns the process, main-thread handle,
    // and stub EXE, and will clean them up via `Drop` when this struct goes
    // out of scope.  `ProcessSession` is a thin RAII wrapper: no handle of
    // its own, the only addition is the per-session `ResolvedApis` cache.
    let mut dbg = ProcessSession::new(
        mida_core::WindowsDebugger::new(&opts).context("Failed to create debuggee process")?,
    );

    log::log(
        LogType::Info,
        &format!("Process created (PID: {})", dbg.pid()),
    );

    // Capture loader-initialized zero-raw data before the post-attach main
    // thread can execute CRT or application initializers. Start with the
    // minimal `.data` policy; later phases preserve decrypted code and IAT.
    let mut early_section_snapshots = if text_is_plain_for_attach {
        capture_early_section_snapshots(&dbg, &pe, &[".data"])?
    } else {
        Vec::new()
    };

    if text_is_plain_for_attach {
        dbg.resume_post_attach_main_thread()
            .context("Failed to resume post-attach main thread")?;
    }

    // ---- post-attach: ScyllaHide pre-injection ----
    // In post-attach mode the CREATE_PROCESS_DEBUG_EVENT arrives AFTER
    // DebugActiveProcess, so we can't inject ScyllaHide from the CREATE_PROCESS
    // handler in time (Themida's anti-debug init runs during the free-run
    // window).  Inject here instead — the hooks land in the already-running
    // process before we enter the debug loop.
    //
    // PEB patching in post-attach mode is already done by WindowsDebugger while
    // the process is suspended, so no CREATE_PROCESS handler is involved.
    let post_attach_mode = text_is_plain_for_attach;
    if post_attach_mode {
        // No ScyllaHide needed — there is no debug port, so Themida's
        // anti-debug checks (DebugPort, BeingDebugged) never trigger.
        // The process started only after the early snapshot was captured, so we
        // go straight to text polling + dump without a debug port.
        //
        // Resolve kernel32 API addresses for later use (breakpoint
        // comparisons etc.).
        let apis = resolve_api_addrs()?;
        dbg.apis = Some(apis);
        info!("post-attach: no debug port — direct dump mode (SuspendThread + ReadProcessMemory)");
    }

    let mut ls = LoopState {
        guard_installed: false,
        close_handle_bp_set: false,
        nt_protect_bp_set: false,
        text_polling: post_attach_mode,
        text_poll_start: None,
        text_poll_count: 0,
        text_prev_sample: [0u8; 16],
        text_stable: false,
        text_reguarded: false,
        oep: None,
        oep_found_via_scanning: false,
        virtualized_oep_retries: 0,
        last_possible_oep: None,
        iat_trace: None,
    };
    let guard_protection = PAGE_NOACCESS.0;
    // Image boundary from PE header (pre-ASLR value). Will be rebased after
    // CreateProcess event provides the real image_base.
    let pe_image_boundary = state.pe_info.image_boundary as usize;
    let pe_image_base = state.pe_info.image_base as usize;

    // Snapshot the process handle once — the process loop passes it to packer
    // helpers that don't go through the `DebuggerCore` trait.
    let h_process = dbg.process_handle();

    // ---- post-attach fast path: no debug port, direct dump ----
    // Observe the freely running primary thread, freeze it on its first
    // transfer into decrypted .text, then go straight to the dump phase.
    if post_attach_mode {
        let image_base_usize = dbg.image_base() as usize;
        let text_sec = &state.pe_info.pe_sections[0];
        let text_start = image_base_usize + text_sec.virtual_address as usize;
        let text_rva = text_sec.virtual_address;
        let text_vsize = text_sec.virtual_size;

        // Observe startup without a debug port and freeze the primary thread
        // on its first transfer into decrypted .text. Sampling starts as soon
        // as CreateProcess resumes the thread; waiting for a resolved IAT first
        // lets CRT/application initialization persist heap state into `.data`.
        let rdata_sec = state
            .pe_info
            .pe_sections
            .iter()
            .find(|s| s.name == ".rdata")
            .or_else(|| state.pe_info.pe_sections.get(1));
        let iat_rva = rdata_sec.map(|s| s.virtual_address).unwrap_or(0xFD000);
        let iat_addr = image_base_usize + iat_rva as usize;

        log::log(
            LogType::Info,
            &format!(
                "post-attach: polling IAT at {iat_addr:#x} (RVA {iat_rva:#x}) for resolution..."
            ),
        );

        let poll_start = std::time::Instant::now();
        let max_wait = std::time::Duration::from_secs(60);
        let main_tid = dbg.main_thread_id();
        let h_thread = dbg
            .thread_handle(main_tid)
            .map_err(|e| anyhow!("thread_handle for poll: {e}"))?;
        let text_end = text_start.saturating_add(text_vsize as usize);
        let mut frozen_rip: Option<usize> = None;
        let mut iat_resolved_logged = false;

        loop {
            if poll_start.elapsed() > max_wait {
                log::log(
                    LogType::Warn,
                    "post-attach: OEP observation timeout after 60s - proceeding with scan",
                );
                break;
            }

            // Check if process is still alive.
            // `STILL_ACTIVE` (NTSTATUS 0x103) is the sentinel GetExitCodeProcess
            // returns for a process that hasn't exited. We compare explicitly rather
            // than relying on `is_ok()` so a real failure isn't silently treated as
            // "process dead".
            use windows::Win32::Foundation::STILL_ACTIVE;
            let mut exit_code: u32 = 0;
            let alive = match unsafe {
                windows::Win32::System::Threading::GetExitCodeProcess(
                    dbg.process_handle(),
                    &mut exit_code,
                )
            } {
                Ok(()) => exit_code == STILL_ACTIVE.0 as u32,
                Err(e) => {
                    // GetExitCodeProcess can fail with insufficient rights or if the
                    // process handle was never granted PROCESS_QUERY_LIMITED_INFORMATION.
                    // Don't assume the process is dead — log and keep polling; the
                    // outer 60s timeout is the real backstop.
                    log::log(
                LogType::Warn,
                &format!("post-attach: GetExitCodeProcess failed: {e} (exit_code={:#x}) — assuming still alive", exit_code),
            );
                    true
                }
            };
            if !alive {
                return Err(anyhow!(
                    "Target process exited during OEP observation (exit_code={:#x})",
                    exit_code
                ));
            }

            if !iat_resolved_logged {
                let mut iat_val = [0u8; 8];
                if dbg.read_memory(iat_addr, &mut iat_val).is_ok() {
                    let val = usize::from_le_bytes(iat_val);
                    if val != 0 {
                        iat_resolved_logged = true;
                        log::log(
                            LogType::Good,
                            &format!(
                                "post-attach: IAT resolved, first slot = {val:#x} (after {} ms)",
                                poll_start.elapsed().as_millis()
                            ),
                        );
                    }
                }
            }

            let previous = unsafe { SuspendThread(h_thread) };
            if previous != u32::MAX {
                if let Ok(ctx) = dbg.get_thread_context_control(main_tid) {
                    let rip = ctx.Rip as usize;
                    if rip >= text_start && rip < text_end {
                        let mut code = [0u8; 16];
                        let decrypted = dbg
                            .read_memory(rip, &mut code)
                            .is_ok_and(|read| read >= 8 && code.iter().any(|&byte| byte != 0));
                        if decrypted {
                            frozen_rip = Some(rip);
                            log::log(
                                LogType::Good,
                                &format!(
                                    "post-attach: first decrypted .text execution captured at {rip:#x} after {} ms",
                                    poll_start.elapsed().as_millis()
                                ),
                            );
                            break;
                        }
                    } else {
                        update_pre_text_snapshots(&dbg, &mut early_section_snapshots, rip)?;
                    }
                }
                let _ = unsafe { ResumeThread(h_thread) };
            }

            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        // If observation timed out, freeze the thread before scanning/dumping.
        if frozen_rip.is_none() {
            let previous = unsafe { SuspendThread(h_thread) };
            if previous == u32::MAX {
                return Err(anyhow!("post-attach: failed to freeze primary thread"));
            }
        }

        log::log(
            LogType::Info,
            &format!(
                "post-attach: process frozen, main RIP={}",
                frozen_rip
                    .map(|rip| format!("{rip:#x}"))
                    .unwrap_or_else(|| "outside .text".to_string())
            ),
        );

        refresh_early_snapshots_after_loader(&dbg, &mut early_section_snapshots)?;
        merge_reinitializable_data_state(
            &dbg,
            &mut early_section_snapshots,
            pe.size_of_image() as usize,
        )?;
        log_snapshot_summary(&early_section_snapshots, "selected pre-.text baseline");

        // Verify .text is decrypted.
        let mut sample = [0u8; 16];
        if dbg.read_memory(text_start, &mut sample).is_ok() {
            let non_zero = sample.iter().filter(|&&b| b != 0).count();
            log::log(
                LogType::Info,
                &format!("post-attach: .text sample {non_zero}/16 non-zero"),
            );
        }

        // Prefer the actual frozen instruction pointer. Static scanning is a
        // fallback for targets whose main thread never enters the first code
        // section during the observation window.
        let oep_addr = if let Some(rip) = frozen_rip {
            log::log(
                LogType::Good,
                &format!("post-attach: OEP captured from RIP: {rip:#x}"),
            );
            rip
        } else {
            match mida_packers_themida::find_real_oep_by_scanning(
                &dbg,
                image_base_usize,
                text_rva,
                text_vsize,
            ) {
                Ok(Some(addr)) => {
                    log::log(
                        LogType::Good,
                        &format!("post-attach: OEP found via .text scan: {addr:#x}"),
                    );
                    addr
                }
                Ok(None) => {
                    let pe_ep = image_base_usize + pe.entry_point as usize;
                    log::log(
                        LogType::Warn,
                        &format!("post-attach: OEP scan failed — using PE EP: {pe_ep:#x}"),
                    );
                    pe_ep
                }
                Err(e) => {
                    log::log(
                        LogType::Fatal,
                        &format!("post-attach: OEP scan error: {e:#}"),
                    );
                    return Err(e.into());
                }
            }
        };

        log::log(
            LogType::Info,
            "post-attach: process frozen — proceeding to IAT repair + dump",
        );

        // Go straight to post-loop phases (IAT repair, dump, postprocess).
        run_post_loop_phases(
            &mut dbg,
            &mut state,
            &mut pe,
            Some(oep_addr),
            is_dotnet,
            is_64bit,
            do_data_sections,
            shrink,
            true, // post-attach mode
            &early_section_snapshots,
            input,
            &output_path,
        )?;

        log::log(LogType::Good, "Done.");
        return Ok(());
    }

    // The main debug loop runs until we've found the OEP and finished IAT.
    loop {
        // Re-compute image_base and image_boundary every iteration so they
        // reflect the actual (ASLR-relocated) base from the CreateProcess event.
        let image_base_usize = dbg.image_base() as usize;
        // Rebase the PE-header boundary to the actual load address.
        let image_boundary = if image_base_usize != 0 {
            image_base_usize + (pe_image_boundary - pe_image_base)
        } else {
            pe_image_boundary
        };
        // Use timeout-based wait so .text polling can run every ~100ms
        // during text_polling phase. After OEP/guard is found, fall back to
        // blocking wait for efficiency.
        let event = if ls.text_polling {
            match dbg.wait_event_timeout(100) {
                Ok(ev) => ev,
                Err(mida_core::CoreError::Timeout) => {
                    // No debug event in 100ms — continue loop for polling
                    continue;
                }
                Err(_e) if post_attach_mode => {
                    // In post-attach mode there is no debug port, so
                    // WaitForDebugEvent returns an error (not timeout).
                    // Treat it as a timeout and continue polling .text.
                    continue;
                }
                Err(e) => {
                    log::log(
                        LogType::Fatal,
                        &format!("wait_event_timeout returned error: {e:#}"),
                    );
                    return Err(e.into());
                }
            }
        } else {
            dbg.wait_event().map_err(|e| {
                log::log(LogType::Fatal, &format!("wait_event returned error: {e:#}"));
                e
            })?
        };
        log::log(LogType::Info, &format!("event received: {event:?}"));
        // Reset idle timer — we got a real event, Themida is still active
        if ls.text_polling {
            ls.text_poll_start = None;
        }

        // ---- .text decryption polling (CREATE_PROCESS → guard delay) ----
        // Themida checks .text page protection during init — any non-PAGE_EXECUTE_READ
        // protection is detected. So we do NOT install guard at CREATE_PROCESS.
        // Instead: let Themida run freely, poll .text via ReadProcessMemory (which
        // is not affected by page protection), and only install guard after .text
        // is stable (decryption complete). Then SuspendThread → read RIP → decide:
        //   RIP in .text → OEP = RIP
        //   RIP elsewhere → install guard, resume, wait for AV
        if ls.text_polling && ls.oep.is_none() && ls.iat_trace.is_none() && !ls.text_reguarded {
            // 30s timeout from LAST debug event (not from CREATE_PROCESS).
            // Themida's DLL loading can take minutes; only start the timeout
            // clock when we've stopped receiving debug events.
            if ls.text_poll_start.is_none() {
                ls.text_poll_start = Some(std::time::Instant::now());
            }
            if let Some(start) = ls.text_poll_start {
                if start.elapsed() > std::time::Duration::from_secs(30) {
                    log::log(LogType::Fatal,
                        &format!(".text poll timeout (30s idle, {} polls) — Themida may not have reached decryption",
                                 ls.text_poll_count));
                    ls.text_polling = false;
                }
            }
            ls.text_poll_count += 1;
            // Poll on every iteration (each ~100ms timeout cycle)
            {
                let text_sec = &state.pe_info.pe_sections[0];
                let text_start = image_base_usize + text_sec.virtual_address as usize;
                let mut sample = [0u8; 16];
                if dbg.read_memory(text_start, &mut sample).is_ok() {
                    let non_zero = sample.iter().filter(|&&b| b != 0).count();
                    if non_zero > 8 {
                        if sample == ls.text_prev_sample {
                            // .text stable — decryption complete
                            log::log(
                                LogType::Good,
                                &format!(
                                    ".text decrypted and stable (poll #{}, {non_zero}/16 non-zero)",
                                    ls.text_poll_count
                                ),
                            );
                            ls.text_stable = true;
                            ls.text_polling = false;

                            // SuspendThread → read RIP → decide OEP vs guard
                            let main_tid = dbg.main_thread_id();
                            let h_thread = dbg
                                .thread_handle(main_tid)
                                .map_err(|e| anyhow!("thread_handle for poll: {e}"))?;
                            // SAFETY: h_thread is valid THREAD_SUSPEND_RESUME handle
                            let _ = unsafe { SuspendThread(h_thread) };

                            let ctx = session::get_thread_context_control(&dbg, main_tid)?;
                            let rip = ctx.Rip as usize;
                            let text_end = image_base_usize + state.pe_info.base_of_data as usize;
                            log::log(
                                LogType::Info,
                                &format!(
                                    "After .text stable: RIP={:#x} (text={:#x}–{:#x})",
                                    rip, text_start, text_end
                                ),
                            );

                            if rip >= text_start && rip < text_end {
                                // RIP in .text → this is OEP
                                log::log(
                                    LogType::Good,
                                    &format!("OEP captured via RIP in .text: {:#x}", rip),
                                );
                                ls.oep = Some(rip);
                                // Resume thread — will be redirected in post-loop
                                let _ = unsafe { ResumeThread(h_thread) };
                            } else {
                                // RIP not in .text — .text already decrypted,
                                // scan it for the real OEP (MSVC CRT pattern).
                                // No guard needed — we go straight to dump.
                                log::log(
                                    LogType::Info,
                                    &format!(
                                        "RIP not in .text ({:#x}) — scanning .text for OEP",
                                        rip
                                    ),
                                );
                                let text_sec = &state.pe_info.pe_sections[0];
                                let text_rva = text_sec.virtual_address;
                                let text_vsize = text_sec.virtual_size;
                                match mida_packers_themida::find_real_oep_by_scanning(
                                    &dbg,
                                    image_base_usize,
                                    text_rva,
                                    text_vsize,
                                ) {
                                    Ok(Some(real_oep)) => {
                                        log::log(
                                            LogType::Good,
                                            &format!("OEP found via .text scan: {:#x}", real_oep),
                                        );
                                        ls.oep = Some(real_oep);
                                        ls.oep_found_via_scanning = true;
                                    }
                                    Ok(None) => {
                                        // Scan failed — try PE entry point as fallback
                                        let pe_ep = image_base_usize + pe.entry_point as usize;
                                        log::log(
                                            LogType::Warn,
                                            &format!("OEP scan failed — using PE EP: {:#x}", pe_ep),
                                        );
                                        ls.oep = Some(pe_ep);
                                        ls.oep_found_via_scanning = true;
                                    }
                                    Err(e) => {
                                        warn!("OEP scan error: {e}");
                                    }
                                }
                                // Do NOT ResumeThread — keep process frozen.
                                // Themida will kill the process on resume (0xDEADC0DE),
                                // but ReadProcessMemory works on a frozen/suspended
                                // process. We break out of the debug loop immediately
                                // and dump from the frozen process's memory.
                                log::log(LogType::Info,
                                    "Process kept frozen — will dump IAT + .text from suspended state");
                            }
                        } else {
                            log::log(
                                LogType::Info,
                                &format!(
                                    ".text has content but not stable yet (poll #{})",
                                    ls.text_poll_count
                                ),
                            );
                        }
                    }
                    ls.text_prev_sample = sample;
                }
            }
        }

        // If OEP found during text polling, break immediately to dump
        // while the process is still frozen (no ResumeThread).
        if ls.oep.is_some() && ls.oep_found_via_scanning {
            log::log(
                LogType::Info,
                "OEP found via scanning — breaking debug loop for frozen dump",
            );
            break;
        }

        match event {
            // ---------------------------------------------------------------
            // CREATE_PROCESS — patch PEB, store image base, resolve APIs
            // ---------------------------------------------------------------
            DebugEvent::CreateProcess {
                process_id: pid,
                thread_id,
                image_base,
                h_thread: _evt_h_thread,
                h_process: evt_h_process,
                h_file,
            } => {
                debug!(image_base = %format!("{image_base:#x}"), "CREATE_PROCESS_DEBUG_EVENT");

                // Note: `image_base`, `process_id`, and the main-thread handle
                // are now stored by the core's `wait_event` bookkeeping
                // automatically — we no longer duplicate that state here.

                // In post-attach mode the PEB was already patched by
                // WindowsDebugger::post_attach_init (right after
                // DebugActiveProcess froze the process), and ScyllaHide +
                // API resolution were done in the pre-loop block above.
                // Skip them here to avoid redundant work / double-inject.
                if post_attach_mode {
                    debug!(
                        "post-attach: CREATE_PROCESS — PEB/ScyllaHide/APIs already done, skipping"
                    );
                } else {
                    // Patch PEB (BeingDebugged, pShimData) via the core helper.
                    let peb_base =
                        mida_core::patch_peb_anti_debug(evt_h_process).unwrap_or(image_base);
                    debug!(peb_image_base = %format!("{peb_base:#x}"), "PEB patched");

                    // Resolve kernel32 API addresses (in the debugger's own
                    // process — valid in the target on x64).
                    let apis = resolve_api_addrs()?;

                    // Apply ScyllaHide.  Capture hook_delay_ms BEFORE the move
                    // into inject_scylla_hide so we can reuse it for the post-
                    // injection settle sleep below.
                    let injector_path = scylla_injector_path();
                    let hook_delay_ms: u64 = 500;
                    let scylla_config = ScyllaHideConfig {
                        injector_cli_path: injector_path.display().to_string(),
                        hook_library_path: scylla_hook_path().display().to_string(),
                        ini_path: None,
                        hook_delay_ms,
                    };
                    if let Err(e) = inject_scylla_hide(pid, &scylla_config) {
                        warn!("ScyllaHide injection failed (non-fatal): {e}");
                    } else {
                        info!("ScyllaHide injected");
                    }

                    // Store resolved APIs for later breakpoint comparisons.
                    dbg.apis = Some(apis);
                }

                // Fix PE header anti-dump: Themida corrupts the first byte
                // of section 2's name ('p' → 'i', making .pdata look like
                // .idata).  Patch it back immediately — the .pdata section
                // is needed for x64 SEH exception dispatch during the debug
                // loop.  Mirrors Pascal TMInit lines 296-303.
                // (Run in both modes — post-attach needs it too.)
                if state.pe_info.pe_sections.len() > 2 {
                    let name_rva =
                        pe_section_name_remote_rva(evt_h_process, image_base as usize, 2);
                    if let Some(rva) = name_rva {
                        let remote_addr = image_base as usize + rva;
                        let mut name_byte = [0u8; 1];
                        if dbg.read_memory(remote_addr, &mut name_byte).is_ok()
                            && name_byte[0] == b'i'
                        {
                            let patch = [b'p'];
                            if dbg.write_memory(remote_addr, &patch).is_ok() {
                                info!(
                                    addr = format_args!("{remote_addr:#x}"),
                                    "PE header anti-dump fix applied: section 2 name byte 'i' → 'p'"
                                );
                            }
                        }
                    }
                }

                // Close the file handle (the debugger doesn't need it).
                // SAFETY: h_file is valid per the DebugEvent contract.
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(h_file);
                }

                // CRITICAL: Do NOT install guard at CREATE_PROCESS.
                // Themida checks .text page protection during init — any non-
                // PAGE_EXECUTE_READ protection is detected and causes 0xDEADC0DE.
                // Instead: set text_polling=true and let the polling block above
                // handle guard installation after .text is stable.
                // PEB patch + ScyllaHide do NOT change .text protection, so they
                // are safe to apply here.
                let text_is_plain = state
                    .pe_info
                    .pe_sections
                    .first()
                    .is_some_and(|s| s.name == ".text");

                if text_is_plain && !is_dotnet {
                    ls.text_polling = true;
                    // poll_start is set on first timeout, not here —
                    // LoadDll events can take minutes before Themida
                    // starts .text decryption
                    log::log(LogType::Info,
                        "Section 0 is .text — deferring guard to .text-stable poll (30s timeout after last event)");
                } else if !is_dotnet {
                    // Non-.text section 0: fall back to CloseHandle → .text write
                    // → VirtualAlloc → guard chain (handled by HW BP handler)
                    log::log(
                        LogType::Info,
                        "Section 0 is NOT .text — using CloseHandle HW BP chain",
                    );
                }

                // NtProtectVirtualMemory BP disabled — it fires during Themida
                // initialization (ntdll page protection changes) and causes
                // an infinite re-fire loop because RF cannot be set in the
                // Themida environment (ERROR_PARTIAL_COPY on SetThreadContext).

                // NOTE: We deliberately do NOT install the CloseHandle HW
                // breakpoint here in the CREATE_PROCESS handler.  Empirically,
                // calling SetThreadContext on the main thread at this point
                // (while ScyllaHide's remote-thread injection is still
                // in-flight) trips ERROR_PARTIAL_COPY and corrupts the
                // debug session.  The BP is installed later, on the first
                // LoadDll event, when the main thread has been resumed and
                // re-suspended and ScyllaHide's ntdll hooks are live.

                // .NET target: set HW BP on _CorExeMain in slot 3.
                // When the .NET runtime calls _CorExeMain, we dump the process
                // immediately without any import reconstruction.
                if is_dotnet {
                    if let Some(cmain) = cor_exe_main_addr {
                        match dbg.set_hw_breakpoint(3, cmain, HwbpType::Execute) {
                            Ok(()) => {
                                info!(addr = %format!("{cmain:#x}"), "_CorExeMain HW BP set (slot 3) for .NET dump")
                            }
                            Err(e) => warn!("Cannot set _CorExeMain BP for .NET: {e}"),
                        }
                    }
                }

                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }

            // ---------------------------------------------------------------
            // LOAD_DLL — close file handle
            // ---------------------------------------------------------------
            // CloseHandle HW breakpoint is already installed in the
            // CREATE_PROCESS handler (see above).  This path remains here
            // only as a backstop in case the CREATE_PROCESS handler failed
            // to set it (e.g. for .NET targets).
            DebugEvent::LoadDll {
                thread_id,
                base_address,
                h_file,
            } => {
                debug!(base = %format!("{base_address:#x}"), "DLL loaded");
                // SAFETY: h_file is valid per contract.
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(h_file);
                }

                // Only set CloseHandle BP for the non-.text path (CloseHandle chain).
                // When text_polling is true, we don't need the CloseHandle BP.
                if !ls.close_handle_bp_set && !ls.guard_installed && !ls.text_polling {
                    let close_handle_addr = dbg.apis.as_ref().map(|a| a.close_handle);
                    if let Some(addr) = close_handle_addr {
                        match dbg.set_hw_breakpoint(0, addr, HwbpType::Execute) {
                            Ok(()) => {
                                debug!("CloseHandle HW breakpoint set (slot 0) [fallback]");
                                info!(
                                    close_handle = %format!("{:#x}", addr),
                                    "CloseHandle HW breakpoint set (slot 0) [fallback]",
                                );
                                ls.close_handle_bp_set = true;
                                debug!("BP install done, about to continue_event");
                            }
                            Err(e) => {
                                warn!("Cannot set HW breakpoint yet: {e}");
                            }
                        }
                    }
                }

                debug!("LoadDll handler: calling continue_event for tid={thread_id}");
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                debug!("LoadDll handler: continue_event returned OK for tid={thread_id}");
            }

            // ---------------------------------------------------------------
            // CREATE_THREAD — store handle
            // ---------------------------------------------------------------
            DebugEvent::CreateThread {
                thread_id,
                h_thread: _new_h_thread,
                start_address,
            } => {
                debug!(
                    start = %format!("{start_address:#x}"),
                    tid = thread_id,
                    "Thread created"
                );

                // Note: the core's `wait_event` has already inserted the new
                // thread handle and propagated DR state.  Nothing else to do.
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }

            // ---------------------------------------------------------------
            // EXIT_THREAD — remove handle
            // ---------------------------------------------------------------
            DebugEvent::ExitThread {
                thread_id,
                exit_code: _,
            } => {
                debug!(tid = thread_id, "Thread exited");
                // Note: the core's `wait_event` already removed the handle
                // from its thread table and closed it.
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }

            // ---------------------------------------------------------------
            // BREAKPOINT — CloseHandle / VirtualAlloc / .text+0x1000
            // ---------------------------------------------------------------
            DebugEvent::Breakpoint { thread_id, address } => {
                debug!(addr = %format!("{address:#x}"), "Breakpoint hit");

                // .NET target special: if this is the _CorExeMain HW BP
                // (slot 3), dump raw memory and exit the debug loop.
                if is_dotnet {
                    if let Some(bp_addr) = dbg.hw_breakpoint_addr(3) {
                        if bp_addr == address {
                            info!(addr = %format!("{address:#x}"), ".NET _CorExeMain hit — dumping process memory");
                            dbg.clear_hw_breakpoint(3)?;
                            dotnet_dump_and_dump_output(&mut dbg, image_base_usize, &output_path)?;
                            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                            break;
                        }
                    }
                }

                // Check for NtProtectVirtualMemory BP (slot 1) — guard protector.
                if ls.nt_protect_bp_set {
                    if let Some(ref apis) = dbg.apis {
                        if address as usize == apis.nt_protect_virtual_memory {
                            // NtProtectVirtualMemory(HANDLE, PVOID* base, PSIZE_T size,
                            //   ULONG newProtect, PULONG oldProtect)
                            // Win64 ABI: RCX=handle, RDX=base ptr, R8=size ptr,
                            //   R9=newProtect, [RSP+0x28]=oldProtect ptr
                            if let Ok(ctx) = dbg.get_thread_context_control(thread_id) {
                                let base_ptr = ctx.Rdx as usize;
                                let new_protect = ctx.R9 as u32;
                                // Read the target base address from *RDX
                                let mut base_bytes = [0u8; 8];
                                if dbg.read_memory(base_ptr, &mut base_bytes).is_ok() {
                                    let target_base = u64::from_le_bytes(base_bytes) as usize;
                                    let text_sec = &state.pe_info.pe_sections[0];
                                    let text_start =
                                        image_base_usize + text_sec.virtual_address as usize;
                                    let text_end =
                                        image_base_usize + state.pe_info.base_of_data as usize;
                                    if target_base >= text_start && target_base < text_end {
                                        // Themida is trying to remove PAGE_NOACCESS from .text.
                                        // Force newProtect to PAGE_NOACCESS (0x01) to keep guard.
                                        debug!(
                                            target = %format!("{target_base:#x}"),
                                            orig_protect = %format!("{new_protect:#x}"),
                                            "NtProtectVirtualMemory on .text — forcing PAGE_NOACCESS"
                                        );
                                        let mut ctx2 = ctx;
                                        ctx2.R9 = 0x01; // PAGE_NOACCESS
                                        ctx2.EFlags |= 0x10000; // RF
                                        #[cfg(target_arch = "x86_64")]
                                        {
                                            ctx2.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64;
                                        }
                                        dbg.set_thread_context(thread_id, &ctx2)?;
                                    }
                                }
                            }
                            // Set RF and continue
                            let mut ctx = dbg.get_thread_context_control(thread_id)?;
                            if let Ok(dbg_ctx) = dbg.get_thread_context_dbg(thread_id) {
                                ctx.Dr0 = dbg_ctx.Dr0;
                                ctx.Dr1 = dbg_ctx.Dr1;
                                ctx.Dr2 = dbg_ctx.Dr2;
                                ctx.Dr3 = dbg_ctx.Dr3;
                                ctx.Dr6 = 0; // clear — prevent re-fire
                                ctx.Dr7 = dbg_ctx.Dr7;
                            }
                            ctx.EFlags |= 0x10000; // RF
                            #[cfg(target_arch = "x86_64")]
                            {
                                ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
                                    | windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
                            }
                            dbg.set_thread_context(thread_id, &ctx)?;
                            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                            continue;
                        }
                    }
                }

                handle_hw_breakpoint(
                    &mut dbg,
                    &mut state,
                    &mut ls.guard_installed,
                    address,
                    thread_id,
                    image_base_usize,
                    image_boundary,
                    h_process,
                    guard_protection,
                )?;

                // Handle anti-debug calls detected via breakpoint.
                if let Ok(handled) = handle_nt_set_information_thread(&dbg, thread_id) {
                    if handled {
                        debug!("NtSetInformationThread bypassed");
                    }
                }

                // Set RF flag so the breakpoint instruction can execute
                // without re-firing the hardware breakpoint on the same
                // instruction. This is the same RF (Resume Flag, bit 16)
                // logic as in the SingleStep handler.
                //
                // Split-read: CONTEXT_CONTROL (Rip/Rsp/EFlags) + CONTEXT_DEBUG_REGISTERS
                // (DR0-DR7) separately to avoid ERROR_PARTIAL_COPY on
                // Themida-protected targets where CONTEXT_ALL fails.
                let mut ctx = dbg.get_thread_context_control(thread_id)?;
                let dbg_ctx = dbg.get_thread_context_dbg(thread_id)?;
                // Merge debug registers from the narrow debug read into the
                // control context so SetThreadContext writes both groups.
                ctx.Dr0 = dbg_ctx.Dr0;
                ctx.Dr1 = dbg_ctx.Dr1;
                ctx.Dr2 = dbg_ctx.Dr2;
                ctx.Dr3 = dbg_ctx.Dr3;
                ctx.Dr6 = 0; // clear — prevent re-fire
                ctx.Dr7 = dbg_ctx.Dr7;
                ctx.EFlags |= 0x10000; // RF (Resume Flag)
                                       // Tell the kernel to write both groups.
                #[cfg(target_arch = "x86_64")]
                {
                    ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
                        | windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
                }
                #[cfg(target_arch = "x86")]
                {
                    ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86
                        | windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_X86;
                }
                dbg.set_thread_context(thread_id, &ctx)?;

                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }

            // ---------------------------------------------------------------
            // ACCESS_VIOLATION — process_guarded_access
            // ---------------------------------------------------------------
            DebugEvent::AccessViolation {
                thread_id,
                address: exception_addr,
                is_write: _,
                target_address,
                exc_type,
            } => {
                // If we re-guarded .text and get an AV in .text range, this is OEP
                if ls.text_reguarded && ls.oep.is_none() {
                    let text_sec = &state.pe_info.pe_sections[0];
                    let text_start = image_base_usize + text_sec.virtual_address as usize;
                    let text_end = image_base_usize + state.pe_info.base_of_data as usize;
                    let exc = exception_addr as usize;
                    if exc >= text_start && exc < text_end {
                        log::log(
                            LogType::Good,
                            &format!("OEP captured via re-guard AV: {exception_addr:#x}"),
                        );
                        ls.oep = Some(exception_addr as usize);
                        // Remove guard
                        let text_size = text_end - text_start;
                        let _ = mida_packers_themida::remove_code_section_guard(
                            h_process, text_start, text_size,
                        );
                        // Continue to IAT phase — set RIP to OEP and let program run
                        // for IAT decryption
                        dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                        continue;
                    }
                }
                match handle_access_violation(
                    &mut ls,
                    &mut dbg,
                    &mut state,
                    &pe,
                    h_process,
                    guard_protection,
                    image_base_usize,
                    image_boundary,
                    thread_id,
                    exception_addr,
                    target_address,
                    exc_type,
                )? {
                    AvAction::Continue => {}
                    AvAction::Break => break,
                }
            }
            // ---------------------------------------------------------------
            // SINGLE_STEP — may be real single-step or hardware breakpoint
            // Also handles IAT tracing for v3 targets.
            // ---------------------------------------------------------------
            DebugEvent::SingleStep { thread_id, address } => {
                // Check if we're in IAT tracing mode.
                let is_tracing = ls.iat_trace.as_ref().is_some_and(|t| {
                    t.trace_phase == TracePhase::Tracing && t.trace_thread_id == thread_id
                });

                if is_tracing {
                    // Handle IAT trace step.
                    if let Some(ref mut trace) = ls.iat_trace {
                        handle_trace_step(
                            &mut dbg,
                            trace,
                            address,
                            image_base_usize,
                            image_boundary,
                        )?;
                    }

                    // After handling the trace step, check if tracing is complete.
                    // If so, break immediately to avoid the target process exiting.
                    if let Some(ref t) = ls.iat_trace {
                        if t.current_slot >= t.total_slots {
                            info!("IAT tracing complete — exiting debug loop");
                            break;
                        }
                    }
                    continue;
                }

                // Re-arm the guard after a guard-related single-step
                // (Pascal: FGuardStepping in OnSinglestep).
                // When a library reads .text or Themida writes a call target,
                // process_guarded_access removes the guard and enables TF.
                // After the single-step completes, we must restore PAGE_NOACCESS.
                if state.guard_stepping {
                    let text_sec = &state.pe_info.pe_sections[0];
                    let text_base = dbg.image_base() as usize + text_sec.virtual_address as usize;
                    // Pascal: FGuardEnd - FGuardStart = BaseOfData - PESections[0].VirtualAddress
                    let text_size =
                        state.pe_info.base_of_data as usize - text_sec.virtual_address as usize;
                    mida_packers_themida::restore_code_section_guard(
                        h_process,
                        text_base,
                        text_size,
                        guard_protection,
                    )?;
                    state.guard_stepping = false;
                    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                    continue;
                }

                // Reading DR6 via GetThreadContext fails with
                // ERROR_PARTIAL_COPY on threads in protector-packaged
                // targets, even though the kernel has successfully armed
                // the breakpoint.  Since the SingleStep exception at an
                // address matching a slot we armed can only mean our
                // hardware breakpoint fired, skip the DR6 inspection and
                // handle it as a HW BP hit directly.  Re-arm the slot
                // afterwards via a fresh SetThreadContext (which does NOT
                // require prior GetThreadContext).
                debug!(
                    addr = %format!("{address:#x}"),
                    "SingleStep at known HW-BP address — treating as CloseHandle hit"
                );

                log::log(
                    LogType::Info,
                    &format!("SINGLE STEP at {address:#x} — checking NtProtectVirtualMemory"),
                );

                // Check for NtProtectVirtualMemory BP (slot 1) — guard protector.
                // NtProtectVirtualMemory(HANDLE, PVOID* base, PSIZE_T size,
                //   ULONG newProtect, PULONG oldProtect)
                // Win64 ABI: RCX=handle, RDX=base ptr, R8=size ptr,
                //   R9=newProtect, [RSP+0x28]=oldProtect ptr
                if ls.nt_protect_bp_set {
                    let nt_protect_addr = dbg
                        .apis
                        .as_ref()
                        .map(|a| a.nt_protect_virtual_memory)
                        .unwrap_or(0);
                    if nt_protect_addr != 0 && address as usize == nt_protect_addr {
                        if let Ok(ctx) = dbg.get_thread_context_control(thread_id) {
                            let base_ptr = ctx.Rdx as usize;
                            let new_protect = ctx.R9 as u32;
                            let mut base_bytes = [0u8; 8];
                            if dbg.read_memory(base_ptr, &mut base_bytes).is_ok() {
                                let target_base = u64::from_le_bytes(base_bytes) as usize;
                                let text_sec = &state.pe_info.pe_sections[0];
                                let text_start =
                                    image_base_usize + text_sec.virtual_address as usize;
                                let text_end =
                                    image_base_usize + state.pe_info.base_of_data as usize;
                                if target_base >= text_start && target_base < text_end {
                                    debug!(
                                        target = %format!("{target_base:#x}"),
                                        orig_protect = %format!("{new_protect:#x}"),
                                        "NtProtectVirtualMemory on .text — forcing PAGE_NOACCESS"
                                    );
                                    let mut ctx2 = ctx;
                                    ctx2.R9 = 0x01; // PAGE_NOACCESS
                                                    // Merge debug registers — must propagate errors
                                                    // (if let Ok silently skips DR clearing on ERROR_PARTIAL_COPY,
                                                    // causing the BP to re-fire infinitely)
                                    let dbg_ctx = dbg.get_thread_context_dbg(thread_id)?;
                                    ctx2.Dr0 = dbg_ctx.Dr0;
                                    ctx2.Dr1 = dbg_ctx.Dr1;
                                    ctx2.Dr2 = dbg_ctx.Dr2;
                                    ctx2.Dr3 = dbg_ctx.Dr3;
                                    ctx2.Dr6 = 0; // clear — prevent re-fire
                                    ctx2.Dr7 = dbg_ctx.Dr7;
                                    ctx2.EFlags |= 0x10000; // RF
                                    #[cfg(target_arch = "x86_64")]
                                    {
                                        ctx2.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
                                            | windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
                                    }
                                    dbg.set_thread_context(thread_id, &ctx2)?;
                                    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                                    continue;
                                }
                            }
                        }
                        // Not targeting .text — just set RF and continue
                        let mut ctx = dbg.get_thread_context_control(thread_id)?;
                        if let Ok(dbg_ctx) = dbg.get_thread_context_dbg(thread_id) {
                            ctx.Dr0 = dbg_ctx.Dr0;
                            ctx.Dr1 = dbg_ctx.Dr1;
                            ctx.Dr2 = dbg_ctx.Dr2;
                            ctx.Dr3 = dbg_ctx.Dr3;
                            ctx.Dr6 = 0; // clear — prevent re-fire
                            ctx.Dr7 = dbg_ctx.Dr7;
                        }
                        ctx.EFlags |= 0x10000; // RF
                        #[cfg(target_arch = "x86_64")]
                        {
                            ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64
                                | windows::Win32::System::Diagnostics::Debug::CONTEXT_DEBUG_REGISTERS_AMD64;
                        }
                        dbg.set_thread_context(thread_id, &ctx)?;
                        dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                        continue;
                    }
                }

                log::log(
                    LogType::Info,
                    &format!(
                        "SINGLE STEP at {address:#x} — handle_hw_breakpoint about to be called"
                    ),
                );

                // Delegate to the shared HW breakpoint handler.
                if let Err(e) = handle_hw_breakpoint(
                    &mut dbg,
                    &mut state,
                    &mut ls.guard_installed,
                    address,
                    thread_id,
                    image_base_usize,
                    image_boundary,
                    h_process,
                    guard_protection,
                ) {
                    log::log(
                        LogType::Fatal,
                        &format!("handle_hw_breakpoint FAILED: {e:#}"),
                    );
                    return Err(e);
                }

                log::log(
                    LogType::Info,
                    "handle_hw_breakpoint returned OK — about to continue_event",
                );
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                log::log(LogType::Info, "continue_event returned OK");
            }

            // ---------------------------------------------------------------
            // EXIT_PROCESS — target exited (unexpected before dump)
            // ---------------------------------------------------------------
            DebugEvent::ExitProcess { exit_code } => {
                if ls.oep.is_some() {
                    info!(
                        exit_code,
                        "Target exited after OEP found — proceeding to dump"
                    );
                } else {
                    warn!(exit_code, "Target process exited before unpack completed");
                }
                break;
            }

            // ---------------------------------------------------------------
            // Other events — continue
            // ---------------------------------------------------------------
            DebugEvent::UnloadDll {
                thread_id,
                base_address: _,
            } => {
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }

            DebugEvent::Other { thread_id } => {
                debug!(thread_id, "Other debug event — continuing");
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }
        }
    }

    // ---- phases B/C/D: IAT repair, post-processing, dump ----
    run_post_loop_phases(
        &mut dbg,
        &mut state,
        &mut pe,
        ls.oep,
        is_dotnet,
        is_64bit,
        do_data_sections,
        shrink,
        false, // traditional debug path
        &early_section_snapshots,
        input,
        &output_path,
    )?;

    log::log(LogType::Good, "Done.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Early post-attach snapshots
// ---------------------------------------------------------------------------

fn capture_early_section_snapshots(
    dbg: &ProcessSession,
    pe: &PeHeader,
    selected_names: &[&str],
) -> Result<Vec<EarlySectionSnapshot>, anyhow::Error> {
    let image_base = dbg.image_base() as usize;
    let mut snapshots = Vec::new();

    for section in &pe.sections {
        if section.raw_size != 0 || !selected_names.contains(&section.name.as_str()) {
            continue;
        }

        let size = section.virtual_size as usize;
        if size == 0 {
            continue;
        }
        let address = image_base
            .checked_add(section.virtual_address as usize)
            .ok_or_else(|| anyhow!("early snapshot address overflow for {}", section.name))?;
        let mut bytes = vec![0u8; size];
        let read = dbg
            .read_memory(address, &mut bytes)
            .map_err(|e| anyhow!("failed to capture early {} snapshot: {e}", section.name))?;
        if read != size {
            return Err(anyhow!(
                "short early {} snapshot read: got {read} bytes, expected {size}",
                section.name
            ));
        }

        let non_zero = bytes.iter().filter(|&&byte| byte != 0).count();
        let hash = fnv1a64(&bytes);
        log::log(
            LogType::Info,
            &format!(
                "early snapshot: {} RVA {:#x}, size {:#x}, non-zero {}, fnv1a64 {:#018x} (main thread suspended)",
                section.name, section.virtual_address, size, non_zero, hash
            ),
        );
        snapshots.push(EarlySectionSnapshot {
            section_name: section.name.clone(),
            rva: section.virtual_address,
            bytes,
        });
    }

    Ok(snapshots)
}

fn update_pre_text_snapshots(
    dbg: &ProcessSession,
    snapshots: &mut [EarlySectionSnapshot],
    rip: usize,
) -> Result<(), anyhow::Error> {
    let image_base = dbg.image_base() as usize;
    for snapshot in snapshots {
        let address = image_base
            .checked_add(snapshot.rva as usize)
            .ok_or_else(|| anyhow!("pre-text snapshot address overflow for {}", snapshot.section_name))?;
        let mut candidate = vec![0u8; snapshot.bytes.len()];
        let read = dbg
            .read_memory(address, &mut candidate)
            .map_err(|e| anyhow!("failed to sample pre-text {} snapshot: {e}", snapshot.section_name))?;
        if read != candidate.len() {
            return Err(anyhow!(
                "short pre-text {} snapshot read: got {read} bytes, expected {}",
                snapshot.section_name,
                candidate.len()
            ));
        }
        if candidate != snapshot.bytes {
            let previous_non_zero = snapshot.bytes.iter().filter(|&&byte| byte != 0).count();
            let non_zero = candidate.iter().filter(|&&byte| byte != 0).count();
            *snapshot = EarlySectionSnapshot {
                section_name: snapshot.section_name.clone(),
                rva: snapshot.rva,
                bytes: candidate,
            };
            debug!(
                section = %snapshot.section_name,
                rip = format_args!("{rip:#x}"),
                previous_non_zero,
                non_zero,
                "updated latest pre-.text loader snapshot"
            );
        }
    }
    Ok(())
}

fn refresh_early_snapshots_after_loader(
    dbg: &ProcessSession,
    snapshots: &mut [EarlySectionSnapshot],
) -> Result<(), anyhow::Error> {
    let image_base = dbg.image_base() as usize;
    for snapshot in snapshots {
        if snapshot.bytes.iter().any(|&byte| byte != 0) {
            continue;
        }

        let address = image_base
            .checked_add(snapshot.rva as usize)
            .ok_or_else(|| anyhow!("loader snapshot address overflow for {}", snapshot.section_name))?;
        let read = dbg
            .read_memory(address, &mut snapshot.bytes)
            .map_err(|e| anyhow!("failed to refresh {} loader snapshot: {e}", snapshot.section_name))?;
        if read != snapshot.bytes.len() {
            return Err(anyhow!(
                "short {} loader snapshot read: got {read} bytes, expected {}",
                snapshot.section_name,
                snapshot.bytes.len()
            ));
        }

        let non_zero = snapshot.bytes.iter().filter(|&&byte| byte != 0).count();
        let hash = fnv1a64(&snapshot.bytes);
        log::log(
            LogType::Info,
            &format!(
                "loader snapshot refresh: {} RVA {:#x}, size {:#x}, non-zero {}, fnv1a64 {:#018x} (main thread frozen at first .text execution)",
                snapshot.section_name,
                snapshot.rva,
                snapshot.bytes.len(),
                non_zero,
                hash
            ),
        );
    }
    Ok(())
}

fn merge_reinitializable_data_state(
    dbg: &ProcessSession,
    snapshots: &mut [EarlySectionSnapshot],
    image_size: usize,
) -> Result<(), anyhow::Error> {
    let image_base = dbg.image_base() as usize;
    let image_end = image_base.saturating_add(image_size);
    for snapshot in snapshots {
        let address = image_base
            .checked_add(snapshot.rva as usize)
            .ok_or_else(|| anyhow!("late data snapshot address overflow for {}", snapshot.section_name))?;
        let mut late = vec![0u8; snapshot.bytes.len()];
        let read = dbg
            .read_memory(address, &mut late)
            .map_err(|e| anyhow!("failed to read late {} snapshot: {e}", snapshot.section_name))?;
        if read != late.len() {
            return Err(anyhow!(
                "short late {} snapshot read: got {read} bytes, expected {}",
                snapshot.section_name,
                late.len()
            ));
        }

        let mut merged = 0usize;
        for (early_chunk, late_chunk) in snapshot
            .bytes
            .chunks_exact_mut(8)
            .zip(late.chunks_exact(8))
        {
            let early = u64::from_le_bytes(early_chunk.try_into().unwrap_or_default());
            let late = u64::from_le_bytes(late_chunk.try_into().unwrap_or_default());
            let late_address = late as usize;
            if early == 0 && (image_base..image_end).contains(&late_address) {
                early_chunk.copy_from_slice(late_chunk);
                merged += 1;
            }
        }
        debug!(
            section = %snapshot.section_name,
            merged,
            "merged reinitializable image-relative data globals"
        );
    }
    Ok(())
}

fn log_snapshot_summary(snapshots: &[EarlySectionSnapshot], stage: &str) {
    for snapshot in snapshots {
        let non_zero = snapshot.bytes.iter().filter(|&&byte| byte != 0).count();
        log::log(
            LogType::Info,
            &format!(
                "{stage}: {} RVA {:#x}, size {:#x}, non-zero {}, fnv1a64 {:#018x}",
                snapshot.section_name,
                snapshot.rva,
                snapshot.bytes.len(),
                non_zero,
                fnv1a64(&snapshot.bytes)
            ),
        );
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

// ---------------------------------------------------------------------------
// Post-loop phases (B/C/D) — extracted from unpack()
// ---------------------------------------------------------------------------

/// Phases B (IAT repair), C (post-processing), and D (dump to file).
///
/// Runs after the debug loop has found the OEP and completed IAT tracing.
fn run_post_loop_phases(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    pe: &mut PeHeader,
    oep: Option<usize>,
    is_dotnet: bool,
    is_64bit: bool,
    do_data_sections: bool,
    shrink: bool,
    post_attach: bool,
    early_section_snapshots: &[EarlySectionSnapshot],
    input: &Path,
    output_path: &Path,
) -> Result<(), anyhow::Error> {
    if is_dotnet {
        log::log(
            LogType::Good,
            ".NET dump completed via _CorExeMain breakpoint",
        );
        return Ok(());
    }

    let mut oep_addr = oep.ok_or_else(|| anyhow!("OEP not found"))?;
    log::log(LogType::Info, &format!("Initial OEP: {:#x}", oep_addr));
    let image_base = dbg.image_base() as usize;
    let text_section = &state.pe_info.pe_sections[0];
    let text_start = image_base.wrapping_add(text_section.virtual_address as usize);
    let text_size = text_section.virtual_size as usize;

    let base_of_data = state.pe_info.base_of_data as usize;
    let (data_section_base, data_section_size) =
        compute_data_section_bounds(image_base, base_of_data, &state.pe_info.pe_sections);

    log::log(
        LogType::Info,
        &format!(
            "Text base: {text_start:#x}, code size: {text_size:#x}, \
             data section: {data_section_base:#x} ({data_section_size:#x} bytes), \
             VM OEP: {}",
            state.pe_info.is_vm_oep
        ),
    );

    let mut text_buf = vec![0u8; text_size.min(0x100_000)];
    let _ = dbg.read_memory(text_start, &mut text_buf);

    let iat = determine_iat_address(
        dbg,
        oep_addr,
        text_start,
        &text_buf,
        data_section_base,
        data_section_size,
        state.pe_info.is_vm_oep,
        CompilerHint::Auto,
        &state.guard_addrs,
    )?
    .ok_or_else(|| anyhow!("IAT not found"))?;

    log::log(
        LogType::Info,
        &format!("IAT at {:#x}, size {:#x}", iat.address, iat.size),
    );

    let strategy = match state.pe_info.themida_version {
        mida_packers_themida::ThemidaVersion::V1 => IatFixStrategy::V1,
        mida_packers_themida::ThemidaVersion::V2 => IatFixStrategy::V2,
        mida_packers_themida::ThemidaVersion::V3 => IatFixStrategy::V3,
        _ => IatFixStrategy::V3,
    };

    let trace_thread_id = dbg.main_thread_id();
    if post_attach {
        // In post-attach mode, IAT slots already contain resolved API
        // addresses (no Themida wrappers to trace). dump_process will
        // rebuild the import table directly from the live IAT.
        log::log(
            LogType::Info,
            "Skipping V3 IAT trace (post-attach: slots already resolved)",
        );
    } else {
        fix_iat(dbg, state, &iat, trace_thread_id, strategy)
            .map_err(|e| anyhow!("IAT fix failed: {e}"))?;
        log::log(LogType::Info, "IAT fixed");
    }

    let themida_section = state
        .pe_info
        .themida_section
        .map(|idx| &state.pe_info.pe_sections[idx]);

    // Pascal Themida64.pas FinishUnpacking does NOT call FixupAPICallSites on x64.
    // Themida V3 x64 uses `mov reg,[rip+disp]; call reg` instead of replacing API calls
    // with rel32 call/jmp (which is an x86-only behavior).  Calling fixup on x64 would
    // never match anything useful and wastes time.
    if !is_64bit {
        if let Some(ts) = themida_section {
            let ts_start = image_base.wrapping_add(ts.virtual_address as usize);
            let ts_end = ts_start.wrapping_add(ts.virtual_size as usize);

            let fixed = fixup_api_call_sites(
                dbg,
                text_start,
                text_size,
                &iat,
                ts_start,
                ts_end,
                &state.guard_addrs,
            )
            .map_err(|e| anyhow!("API call site fixup failed: {e}"))?;

            log::log(LogType::Info, &format!("Fixed {} API call sites", fixed));
        }
    } else {
        log::log(
            LogType::Info,
            "Skipping API call site fixup on x64 (matches Pascal Themida64)",
        );
    }

    // ---- phase C: post-processing ----
    let image_base_for_scan = dbg.image_base() as usize;
    // Phase C2: compare live memory with the captured OEP. A post-attach
    // capture is only a snapshot of the suspended primary thread; if the CRT
    // scanner finds a different executable startup candidate, prefer it.
    if let Some(real_oep) = scan_live_memory_for_real_oep(
        dbg,
        image_base_for_scan,
        &state.pe_info.pe_sections,
        state.pe_info.base_of_data,
        state.pe_info.major_linker_version,
    )? {
        if real_oep != oep_addr {
            if post_attach {
                info!(
                    captured_oep = %format!("{oep_addr:#x}"),
                    scan_oep = %format!("{real_oep:#x}"),
                    "Replacing post-attach RIP snapshot with scanned OEP"
                );
                oep_addr = real_oep;
            } else {
                info!(
                    captured_oep = %format!("{oep_addr:#x}"),
                    scan_oep = %format!("{real_oep:#x}"),
                    "Live-memory scan found a different candidate — keeping runtime OEP"
                );
            }
        }
    }

    log::log(LogType::Info, &format!("Final OEP: {:#x}", oep_addr));

    if shrink {
        match shrink_pe(pe) {
            Ok(removed) => log::log(
                LogType::Info,
                &format!("Removed {removed} Themida sections"),
            ),
            Err(e) => warn!("shrink_pe failed (non-fatal): {e}"),
        }
    }

    if do_data_sections {
        let (text_rva, text_size) = {
            let text_sec = &pe.sections[0];
            (text_sec.virtual_address, text_sec.virtual_size)
        };
        let text_va = image_base.wrapping_add(text_rva as usize);
        let read_size = text_size.min(0x800_000);
        let mut text_buf = vec![0u8; read_size as usize];
        let bytes_read = dbg.read_memory(text_va, &mut text_buf).unwrap_or(0);
        text_buf.truncate(bytes_read);

        match create_data_sections(pe, &text_buf, text_rva, CompilerHint::Msvc) {
            Ok(result) => {
                if result.rdata_created {
                    log::log(
                        LogType::Info,
                        &format!(
                            "Created .rdata section at {:#x} ({} bytes)",
                            result.rdata_rva, result.rdata_size,
                        ),
                    );
                }
                if result.data_created {
                    log::log(
                        LogType::Info,
                        &format!(
                            "Created .data section at {:#x} ({} bytes)",
                            result.data_rva, result.data_size,
                        ),
                    );
                }
            }
            Err(e) => warn!("create_data_sections failed (non-fatal): {e}"),
        }
    }

    // Install anti-dump fix at OEP (x86 only).
    // Pascal Themida64.pas does NOT install this stub on x64 — it leaves the
    // OEP code intact.  Installing the stub on x64 overwrites the real OEP
    // with a VirtualProtect-based fixup that assumes the OEP starts with
    // `jmp rel32`, which is not true for x64 Themida targets.  The result is
    // a corrupted entry point that crashes on startup.
    if !is_64bit {
        let virtual_protect_addr = resolve_host_api("kernel32.dll", "VirtualProtect");
        if virtual_protect_addr != 0 {
            match install_anti_dump_fix(
                dbg,
                oep_addr,
                image_base,
                virtual_protect_addr,
                oep_addr,
                is_64bit,
            ) {
                Ok(()) => log::log(LogType::Info, "Installed anti-dump fix at OEP"),
                Err(e) => warn!("install_anti_dump_fix failed (non-fatal): {e}"),
            }
        }
    } else {
        log::log(
            LogType::Info,
            "Skipping anti-dump fix on x64 (matches Pascal Themida64.pas)",
        );
    }

    // ---- phase D: dump to file ----
    log::log(
        LogType::Info,
        &format!("Dumping to: {}", output_path.display()),
    );

    let entry_point_u32 =
        u32::try_from(oep_addr.wrapping_sub(image_base)).context("OEP RVA exceeds u32 range")?;

    // Use the IAT detected by determine_iat_address (don't override with code scanning)
    let dump_opts = DumpOptions {
        image_base: dbg.image_base(),
        entry_point: entry_point_u32,
        fix_imports: true,
        create_data_sections: do_data_sections,
        shrink,
        output_path: output_path.to_path_buf(),
        executable_path: Some(input.to_path_buf()),
        iat_location: Some((iat.address, iat.size)),
        additional_iat_locations: Vec::new(),
        early_section_snapshots: early_section_snapshots.to_vec(),
    };

    mida_pe::dump_process(dbg, &dump_opts).map_err(|e| anyhow!("Dump failed: {e}"))?;

    log::log(
        LogType::Good,
        &format!("Unpacked: {}", output_path.display()),
    );
    Ok(())
}
