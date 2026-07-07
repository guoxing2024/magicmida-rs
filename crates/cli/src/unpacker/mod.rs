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

mod session;
mod iat_trace;
mod oep_scan;
mod verify;
mod dump;
mod helpers;
mod av_handler;

use std::fs;
use std::path::Path;

use anyhow::{Context, anyhow};
use tracing::{debug, info, warn};
use windows::Win32::System::Memory::PAGE_NOACCESS;

use mida_core::{
    CreateProcessOptions, ContinueStatus, DebugEvent, DebuggerCore, HwbpType,
};
use mida_pe::{DumpOptions, PeHeader};
use mida_packers_themida::{
    CompilerHint, IatFixStrategy, ScyllaHideConfig, ThemidaState,
    create_data_sections, determine_iat_address, fix_iat,
    fixup_api_call_sites, handle_nt_set_information_thread, init_pe_details,
    inject_scylla_hide, install_anti_dump_fix, shrink_pe,
};
use crate::log::{self, LogType};

use session::ProcessSession;
use iat_trace::{IatTraceState, TracePhase, handle_trace_step};
use oep_scan::scan_live_memory_for_real_oep;
use helpers::{
    scylla_injector_path, scylla_hook_path, resolve_output_path, resolve_api_addrs,
    resolve_host_api, compute_data_section_bounds, pe_section_name_remote_rva,
    dotnet_dump_and_dump_output, handle_hw_breakpoint,
};
use av_handler::{AvAction, handle_access_violation};

// Re-export public functions for commands.rs
pub use verify::verify_unpacked;
pub use dump::dump_process_code;

// ---------------------------------------------------------------------------
// LoopState — mutable tracking variables for the debug loop
// ---------------------------------------------------------------------------

struct LoopState {
    guard_installed: bool,
    close_handle_bp_set: bool,
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

    let mut pe = PeHeader::from_file(input)
        .map_err(|e| anyhow!("Failed to parse PE header: {e}"))?;

    let is_64bit = pe.is_64bit;
    debug!(is_64bit, "PE architecture");

    // ---- step 3: detect Themida ----
    // Read entry-point bytes for virtualised OEP detection.
    let ep_offset_val = pe.rva_to_offset(pe.entry_point).unwrap_or(0) as usize;
    let entry_bytes = fs::read(input)
        .ok()
        .and_then(|data| {
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
        .virtual_address != 0;
    if is_dotnet {
        log::log(LogType::Info, ".NET target detected — will dump via _CorExeMain breakpoint");
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
    let opts = CreateProcessOptions {
        executable: input.to_path_buf(),
        command_line: None,
        is_dll: input.extension().map(|e| e.eq_ignore_ascii_case("dll")).unwrap_or(false),
        suspended: false,
    };

    // ---- step 5: initialise Themida state ----
    let mut state = ThemidaState::new(pe_info, do_data_sections);
    state.create_data_sections = do_data_sections;
    // Propagate TLS callback count detected during init_pe_details.
    state.tls_total = state.pe_info.tls_total;

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
        mida_core::WindowsDebugger::new(&opts)
            .context("Failed to create debuggee process")?,
    );

    log::log(LogType::Info, &format!("Process created (PID: {})", dbg.pid()));

    let mut ls = LoopState {
        guard_installed: false,
        close_handle_bp_set: false,
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
        let event = dbg.wait_event().map_err(|e| {
            log::log(LogType::Fatal, &format!("wait_event returned error: {e:#}"));
            e
        })?;
        log::log(LogType::Info, &format!("event received: {event:?}"));

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
                //
                // Patch PEB (BeingDebugged, pShimData) via the core helper.
                let peb_base = mida_core::patch_peb_anti_debug(evt_h_process)
                    .unwrap_or(image_base);
                debug!(peb_image_base = %format!("{peb_base:#x}"), "PEB patched");

                // Fix PE header anti-dump: Themida corrupts the first byte
                // of section 2's name ('p' → 'i', making .pdata look like
                // .idata).  Patch it back immediately — the .pdata section
                // is needed for x64 SEH exception dispatch during the debug
                // loop.  Mirrors Pascal TMInit lines 296-303.
                if state.pe_info.pe_sections.len() > 2 {
                    let name_rva = pe_section_name_remote_rva(
                        evt_h_process,
                        image_base as usize,
                        2,
                    );
                    if let Some(rva) = name_rva {
                        let remote_addr = image_base as usize + rva;
                        let mut name_byte = [0u8; 1];
                        if dbg.read_memory(remote_addr, &mut name_byte).is_ok() && name_byte[0] == b'i' {
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
                            Ok(()) => info!(addr = %format!("{cmain:#x}"), "_CorExeMain HW BP set (slot 3) for .NET dump"),
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

                if !ls.close_handle_bp_set {
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
                            dotnet_dump_and_dump_output(
                                &mut dbg,
                                image_base_usize,
                                &output_path,
                            )?;
                            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                            break;
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
                match handle_access_violation(
                    &mut ls, &mut dbg, &mut state, &pe,
                    h_process, guard_protection,
                    image_base_usize, image_boundary,
                    thread_id, exception_addr, target_address, exc_type,
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
                        handle_trace_step(&mut dbg, trace, address, image_base_usize, image_boundary)?;
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
                    let text_base = dbg.image_base() as usize
                        + text_sec.virtual_address as usize;
                    // Pascal: FGuardEnd - FGuardStart = BaseOfData - PESections[0].VirtualAddress
                    let text_size = state.pe_info.base_of_data as usize
                        - text_sec.virtual_address as usize;
                    mida_packers_themida::restore_code_section_guard(
                        h_process, text_base, text_size, guard_protection,
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

                log::log(LogType::Info, &format!("SINGLE STEP at {address:#x} — handle_hw_breakpoint about to be called"));

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
                    log::log(LogType::Fatal, &format!("handle_hw_breakpoint FAILED: {e:#}"));
                    return Err(e);
                }

                log::log(LogType::Info, "handle_hw_breakpoint returned OK — about to continue_event");
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                log::log(LogType::Info, "continue_event returned OK");
            }

            // ---------------------------------------------------------------
            // EXIT_PROCESS — target exited (unexpected before dump)
            // ---------------------------------------------------------------
            DebugEvent::ExitProcess { exit_code } => {
                warn!(exit_code, "Target process exited before unpack completed");
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
        input,
        &output_path,
    )?;

    log::log(LogType::Good, "Done.");
    Ok(())
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
    input: &Path,
    output_path: &Path,
) -> Result<(), anyhow::Error> {
    if is_dotnet {
        log::log(LogType::Good, ".NET dump completed via _CorExeMain breakpoint");
        return Ok(());
    }

    let oep_addr = oep.ok_or_else(|| anyhow!("OEP not found — cannot continue"))?;
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
    fix_iat(dbg, state, &iat, trace_thread_id, strategy)
        .map_err(|e| anyhow!("IAT fix failed: {e}"))?;
    log::log(LogType::Info, "IAT fixed");

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

            let fixed = fixup_api_call_sites(dbg, text_start, text_size, &iat, ts_start, ts_end, &state.guard_addrs)
                .map_err(|e| anyhow!("API call site fixup failed: {e}"))?;

            log::log(LogType::Info, &format!("Fixed {} API call sites", fixed));
        }
    } else {
        log::log(LogType::Info, "Skipping API call site fixup on x64 (matches Pascal Themida64)");
    }

    // ---- phase C: post-processing ----
    let image_base_for_scan = dbg.image_base() as usize;

    // Phase C2: scan live memory for the real OEP and log the result.
    // (We intentionally keep the guard-detected OEP as the entry point
    //  and install the anti-dump stub at that address — aligning with
    //  Magicmida's approach.  The live-memory scan is informational.)
    if let Some(real_oep) = scan_live_memory_for_real_oep(
        dbg,
        image_base_for_scan,
        &state.pe_info.pe_sections,
        state.pe_info.base_of_data,
        state.pe_info.major_linker_version,
    )? {
        if real_oep != oep_addr {
            info!(
                guard_oep = %format!("{oep_addr:#x}"),
                scan_oep = %format!("{real_oep:#x}"),
                "Live-memory scan found different OEP — using guard-detected OEP"
            );
        }
    }

    log::log(LogType::Info, &format!("Final OEP: {:#x}", oep_addr));

    if shrink {
        match shrink_pe(pe) {
            Ok(removed) => log::log(LogType::Info, &format!("Removed {removed} Themida sections")),
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
                    log::log(LogType::Info, &format!(
                        "Created .rdata section at {:#x} ({} bytes)",
                        result.rdata_rva, result.rdata_size,
                    ));
                }
                if result.data_created {
                    log::log(LogType::Info, &format!(
                        "Created .data section at {:#x} ({} bytes)",
                        result.data_rva, result.data_size,
                    ));
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
            match install_anti_dump_fix(dbg, oep_addr, image_base, virtual_protect_addr, oep_addr, is_64bit) {
                Ok(()) => log::log(LogType::Info, "Installed anti-dump fix at OEP"),
                Err(e) => warn!("install_anti_dump_fix failed (non-fatal): {e}"),
            }
        }
    } else {
        log::log(LogType::Info, "Skipping anti-dump fix on x64 (matches Pascal Themida64.pas)");
    }

    // ---- phase D: dump to file ----
    log::log(LogType::Info, &format!("Dumping to: {}", output_path.display()));

    let entry_point_u32 = u32::try_from(oep_addr.wrapping_sub(image_base))
        .context("OEP RVA exceeds u32 range")?;

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
    };

    mida_pe::dump_process(dbg, &dump_opts)
        .map_err(|e| anyhow!("Dump failed: {e}"))?;

    log::log(LogType::Good, &format!("Unpacked: {}", output_path.display()));
    Ok(())
}
