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
    inject_scylla_hide, install_anti_dump_fix, select_profile, shrink_pe,
};
use crate::args::PackerChoice;
use crate::log::{self, LogType};

use session::ProcessSession;
use oep_scan::scan_live_memory_for_real_oep;
use helpers::{
    live_data_nonzero,
    read_tls_callback_oep,
    scylla_ini_path, scylla_injector_path, scylla_hook_path, resolve_output_path, resolve_api_addrs,
    resolve_host_api, compute_data_section_bounds, detect_packed_dll, pe_section_name_remote_rva,
    dotnet_dump_and_dump_output, handle_hw_breakpoint, section_table, step_until_in_image,
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
    /// Set once the packed DLL has been located in `LOAD_DLL` and `image_base`
    /// has been retargeted from the loader host onto the DLL.
    dll_base_found: bool,
    oep: Option<usize>,
    oep_found_via_scanning: bool,
    virtualized_oep_retries: u32,
    last_possible_oep: Option<usize>,
    /// Set once the post-OEP IAT decryption window has run.  Guards against
    /// re-entering the 5-second monitoring loop on a later access violation.
    iat_monitoring_done: bool,
    /// Watchdog for identical-access-violation storms.  See
    /// [`AvStorm`](av_handler::AvStorm).
    av_storm: av_handler::AvStorm,
}

// ---------------------------------------------------------------------------
// Unpack
// ---------------------------------------------------------------------------

/// Print a packer verdict, its evidence, and the static structure report.
///
/// The structure report is the VMProtect one and only runs for a VMProtect
/// verdict — the gate used to attach it to *any* detection, which printed a
/// meaningless "large resources: none" VMProtect report under a UPX verdict
/// (measured the moment UPX entered the gate chain).
fn log_detection(detection: &mida_packer_api::Detection, pe: &PeHeader, image: &[u8]) {
    log::log(
        LogType::Info,
        &format!("Packer detection: {}", detection.summary()),
    );
    for line in detection.render_evidence() {
        log::log(LogType::Info, &format!("  {line}"));
    }
    if detection.is_vmprotect() {
        log::log(
            LogType::Info,
            &format!(
                "Static report:\n{}",
                mida_packers_vmprotect::analyze(pe, image)
            ),
        );
    }
}

/// Unpack a Themida-protected executable.
///
/// This is the main entry point for the `/unpack` command. It orchestrates the
/// full pipeline: PE parsing, Themida detection, process creation, debug loop,
/// IAT repair, dump, and post-processing.  UPX targets never reach the debug
/// loop — they are handled entirely in-file by [`unpack_upx_static`] (selected
/// by `--packer upx`, or by auto-detection).
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
    packer: PackerChoice,
    no_scylla: bool,
) -> Result<(), anyhow::Error> {
    // ---- step 1: resolve output path ----
    let output_path = resolve_output_path(input, output);

    // A `.dll` extension means the target is a library.  The flag drives two
    // real behaviours downstream: the "packed DLL located" image-base retarget
    // and the DLL-specific OEP acceptance rule in `handle_access_violation`.
    // It no longer gates the run — the loader-host path (see
    // `mida_core::create_debug_process`) loads a packed DLL through the real
    // `LoadLibraryW`, which is exactly what its shell expects, so a native DLL
    // target is supported.  The .NET case is handled separately via the COM
    // descriptor directory.
    let looks_like_dll = input
        .extension()
        .map(|e| e.eq_ignore_ascii_case("dll"))
        .unwrap_or(false);

    log::log(LogType::Info, &format!("Loading: {}", input.display()));

    let mut pe = PeHeader::from_file(input)
        .map_err(|e| anyhow!("Failed to parse PE header: {e}"))?;

    let is_64bit = pe.is_64bit;
    debug!(is_64bit, "PE architecture");

    // ---- step 2b: identify the packer BEFORE any per-packer heuristic ----
    //
    // Themida's `is_themida_section` keys on an executable section with
    // `raw_size == 0` and a large virtual size.  Measured over 87 protected
    // samples on this machine, that shape occurs in 6 genuine Themida samples
    // *and* in the VMProtect `Packed` sample `D:\Projects\zz_test.exe`
    // (section `.rdata0`).  So the heuristic is correct for Themida and
    // **cannot** be tightened into rejecting VMProtect: before this gate,
    // `/unpack zz_test.exe` logged `Themida version: V3`, created the
    // debuggee and ran the whole Themida loop against a VMProtect target.
    // The packer decision therefore has to be made here, first, with evidence.
    let image = fs::read(input)
        .map_err(|e| anyhow!("Failed to read input for packer detection: {e}"))?;

    // The packer gate, in the same order as `/analyze`: the structured
    // detectors first (VMProtect, then UPX), and the Themida heuristic only
    // when neither fires.  The order is load-bearing twice over — UPX's
    // `UPX0` section is an executable `raw_size == 0` section with a large
    // virtual size, which is exactly what `is_themida_section` keys on
    // (measured on real UPX output, see the upx crate's gate).
    let detection = mida_packers_vmprotect::detect(&pe, &image)
        .or_else(|| mida_packers_upx::detect(&pe, &image));

    // The packer choice is an explicit, logged decision rather than a silent
    // fall-through, because the `Auto` refusal is the only thing standing
    // between a non-Themida target and the Themida loop.
    let packer_kind = match (packer, detection.as_ref()) {
        (PackerChoice::Upx, _) => {
            return unpack_upx_static(&pe, &image, &output_path);
        }
        (PackerChoice::Auto, Some(d)) if d.is_upx() => {
            log_detection(d, &pe, &image);
            return unpack_upx_static(&pe, &image, &output_path);
        }
        (PackerChoice::Auto, Some(d)) => {
            log_detection(d, &pe, &image);
            return Err(anyhow!(
                "{} target — the Themida pipeline cannot unpack it; \
                 the static structure report is above",
                d.summary()
            ));
        }
        (PackerChoice::Auto, None) => mida_packer_api::PackerKind::Themida,

        (PackerChoice::Themida, Some(d)) => {
            log::log(
                LogType::Info,
                &format!(
                    "Overriding detection: forcing the Themida branch for a {} target",
                    d.summary()
                ),
            );
            log_detection(d, &pe, &image);
            mida_packer_api::PackerKind::Themida
        }
        (PackerChoice::Themida, None) => mida_packer_api::PackerKind::Themida,

        (PackerChoice::VmProtect, Some(d)) => {
            log::log(
                LogType::Info,
                &format!(
                    "Selecting the experimental VMProtect branch for a {} target \
                     (shares the one debug loop that exists)",
                    d.summary()
                ),
            );
            log_detection(d, &pe, &image);
            d.kind
        }
        (PackerChoice::VmProtect, None) => {
            return Err(anyhow!(
                "--packer vmprotect was requested but no VMProtect evidence was \
                 found in {}; use /analyze to see what it is",
                input.display()
            ));
        }
    };

    // ScyllaHide profile for whichever packer we are about to run.  The
    // injector takes no ini argument, so this is applied by rewriting
    // `CurrentProfile` in the ini beside the injector — see
    // `mida_packers_themida::select_profile`.
    //
    // This is done here, in pre-flight, rather than in the CREATE_PROCESS
    // handler where the profile is *used*: the choice is a per-run decision
    // with no dependency on the debuggee existing, and keeping it late meant a
    // run that could not create its process (measured: `ERROR_ELEVATION_REQUIRED`
    // when a `RUNASADMIN` AppCompat layer flag is registered for the target)
    // silently never applied the profile at all.
    let scylla_profile = packer_kind.scylla_profile();
    let scylla_ini = scylla_ini_path();
    if scylla_ini.exists() {
        match select_profile(&scylla_ini, scylla_profile) {
            Ok(()) => log::log(
                LogType::Info,
                &format!("ScyllaHide profile: {scylla_profile}"),
            ),
            Err(e) => warn!("Could not select ScyllaHide profile '{scylla_profile}': {e}"),
        }
    } else {
        log::log(
            LogType::Info,
            &format!(
                "No scylla_hide.ini at '{}' — the injector will use whatever profile \
                 it finds by itself",
                scylla_ini.display()
            ),
        );
    }

    // ---- step 3: detect Themida ----
    // Read entry-point bytes for virtualised OEP detection.
    let ep_offset_val = pe.rva_to_offset(pe.entry_point).unwrap_or(0) as usize;
    let entry_bytes = image
        .get(ep_offset_val..ep_offset_val.saturating_add(8))
        .map(|b| b.to_vec());
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

    let pe_info = init_pe_details(&pe, is_64bit, entry_bytes_ref, Some(input), &image)
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
        dll_base_found: false,
        oep: None,
        oep_found_via_scanning: false,
        virtualized_oep_retries: 0,
        last_possible_oep: None,
        iat_monitoring_done: false,
        av_storm: av_handler::AvStorm::default(),
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
        let event = match dbg.wait_event_timeout(500) {
            Ok(ev) => ev,
            // Periodic wake-up: the classic shells go silent while
            // decompressing (no debug events), and the materialised image
            // appears during that silence — scanning only after events
            // would miss it (measured: the CloseHandle hit never fired and
            // the image existed only during the quiet phase).
            Err(mida_core::CoreError::Timeout) => {
                try_map_scan(&mut dbg, &mut state, image_base_usize, &output_path);
                try_ancient_watch_scan(&mut dbg, &mut state, image_base_usize, &output_path);
                continue;
            }
            Err(e) => {
                log::log(LogType::Fatal, &format!("wait_event returned error: {e:#}"));
                return Err(e.into());
            }
        };
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

                // The shell's main thread: the jump into the materialised
                // image (Themida 1.1.1) happens on it.
                state.main_thread_id = thread_id;

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

                // Apply ScyllaHide — asynchronously, and *without* blocking.
                //
                // `--no-scylla` skips the injection entirely: for some shells
                // (measured: Themida 1.1.1 file-mapping shells) the hook's
                // presence changes the shell's runtime behaviour — the
                // shell's decompression completes in only 1/7 runs with the
                // hook injected.  The flag runs the pipeline without injecting
                // the hook, for diagnostics and for shells that misbehave
                // under hooks.
                if no_scylla {
                    info!("ScyllaHide injection skipped (--no-scylla)");
                } else {
                    let injector_path = scylla_injector_path();
                    let scylla_config = ScyllaHideConfig {
                        injector_cli_path: injector_path.display().to_string(),
                        hook_library_path: scylla_hook_path().display().to_string(),
                    };
                    if let Err(e) = inject_scylla_hide(pid, &scylla_config) {
                        warn!("ScyllaHide injection failed (non-fatal): {e}");
                    }
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

                // ---- DLL targets: retarget onto the packed DLL and arm .text --
                //
                // The debuggee is our loader host, so `CREATE_PROCESS` reported
                // the *host* EXE's base.  Every downstream computation is
                // `image_base + rva`, so the base has to move to the packed DLL
                // before any guard or OEP logic runs.
                //
                // The DLL is recognised by its `.winlice` section, which the
                // host EXE does not have.  The `.text` guard is armed here —
                // during `LOAD_DLL`, i.e. before `DllMain` executes — so the
                // first execute fault into `.text` is the real entry point.
                if looks_like_dll && !ls.dll_base_found {
                    if let Some(dll_base) =
                        detect_packed_dll(&dbg, base_address as usize, state.pe_info.pe_sections[0].virtual_address)
                    {
                        ls.dll_base_found = true;
                        dbg.set_image_base(dll_base as u64);
                        info!(
                            dll_base = %format!("{dll_base:#x}"),
                            "Packed DLL located — image_base retargeted from the loader host"
                        );

                        let text_sec = &state.pe_info.pe_sections[0];
                        let text_start = dll_base + text_sec.virtual_address as usize;
                        let text_size = text_sec.virtual_size as usize;

                        // ---- DLL targets: no `.text` guard -------------------
                        //
                        // The guard exists to catch "first execution inside
                        // `.text`", which is how an EXE's OEP is found.  For a
                        // packed DLL that mechanism is both unnecessary and
                        // harmful:
                        //
                        // * Unnecessary: the shell publishes the real `DllMain`
                        //   into its own TLS callback array during startup.
                        //   Measured on the reference `core.dll` after a full
                        //   boot: `[rva 0x170010] = image_base + 0x2BB10`, which
                        //   is exactly the OEP the guard path was discovering.
                        // * Harmful: measured with an identical debugger and
                        //   ScyllaHide, `.text` guarded (PAGE_NOACCESS) gives
                        //   `.bss` = 0 non-zero bytes and `hinstDLL` = 0, while
                        //   unguarded gives `.bss` = 177 and `hinstDLL` set.  The
                        //   shell is still inside its own `DllMain` at this point,
                        //   and the guard's fault/retry cycle derails it.
                        //
                        // So the DLL path skips the guard and takes its OEP from
                        // the TLS callback array instead, after the shell has had
                        // a chance to write it.
                        if looks_like_dll {
                            // The debuggee is suspended at this LOAD_DLL event, so
                            // the shell cannot run and the array cannot be written
                            // until the event is answered.  Answer it, then let the
                            // shell run freely while polling the array.
                            dbg.continue_event(thread_id, ContinueStatus::Continue)?;

                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(12);
                            let mut oep_from_tls = None;
                            let mut last_activity = usize::MAX;
                            let mut quiet = 0u32;
                            while std::time::Instant::now() < deadline {
                                // Do not stop the moment the OEP is published:
                                // measured on the reference DLL, the shell goes
                                // from 0 to 177 non-zero data bytes in one step and
                                // the callback array becomes non-zero a few
                                // instructions earlier.  Stopping on the callback
                                // alone captures `.bss` with the OEP present but
                                // `hinstDLL` still unwritten (measured nz=75,
                                // hinst=0), which is exactly why `GetAppVersion()`
                                // then answers "0.0".
                                //
                                // So: remember the OEP when it appears, then keep
                                // running until the writable-data non-zero count
                                // stops changing for a few consecutive samples.
                                let activity = live_data_nonzero(
                                    &dbg,
                                    dll_base,
                                    &state.pe_info.pe_sections,
                                );
                                if let Some(oep) = read_tls_callback_oep(
                                    &dbg,
                                    dll_base,
                                    state.pe_info.image_boundary as usize,
                                ) {
                                    if oep_from_tls.is_none() {
                                        info!(
                                            oep = %format!("{oep:#x}"),
                                            activity,
                                            "DLL OEP published — waiting for initialisation to settle"
                                        );
                                    }
                                    oep_from_tls = Some(oep);
                                }
                                if oep_from_tls.is_some() {
                                    if activity == last_activity {
                                        quiet += 1;
                                    } else {
                                        quiet = 0;
                                        last_activity = activity;
                                    }
                                    if quiet >= 6 {
                                        info!(
                                            activity,
                                            quiet_samples = quiet,
                                            "DLL initialisation settled — dumping"
                                        );
                                        break;
                                    }
                                }
                                match dbg.wait_event_timeout(100) {
                                    Ok(DebugEvent::ExitProcess { .. }) => {
                                        warn!("Target exited while waiting for the DLL OEP");
                                        break;
                                    }
                                    Ok(ev) => {
                                        let tid = match &ev {
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
                                        };
                                        if tid != 0 {
                                            // First-chance exceptions must go to the
                                            // program's own SEH, not back through the
                                            // faulting instruction.
                                            //
                                            // `DBG_CONTINUE` means "the debugger handled
                                            // it" and resumes *at* the fault, which for a
                                            // privileged-instruction probe re-raises the
                                            // same exception forever — and before it
                                            // loops, it derails the shell's own
                                            // initialisation, which is how this surfaced:
                                            // the reference DLL's IAT came out as 357
                                            // slots instead of 3283 and the trace
                                            // resolved 14 imports instead of 289.
                                            //
                                            // Everything else (loads, threads, plain
                                            // single-steps) is resumed normally.
                                            let status = if matches!(
                                                ev,
                                                DebugEvent::UnhandledException { .. }
                                            ) {
                                                ContinueStatus::ExceptionNotHandled
                                            } else {
                                                ContinueStatus::Continue
                                            };
                                            let _ = dbg.continue_event(tid, status);
                                        }
                                    }
                                    Err(mida_core::CoreError::Timeout) => {}
                                    // Belt-and-braces: core maps
                                    // `ERROR_SEM_TIMEOUT` itself now, so the arm
                                    // above is the normal path.  Kept so a code
                                    // path that reduced the HRESULT early still
                                    // treats an idle tick as idle rather than as
                                    // a fatal debug-event error.
                                    Err(mida_core::CoreError::Windows(code))
                                        if code & 0xFFFF == 121 => {}
                                    Err(e) => {
                                        warn!("DLL free-run: debug event error: {e}");
                                        break;
                                    }
                                }
                            }

                            match oep_from_tls {
                                Some(oep) => {
                                    ls.oep = Some(oep);
                                    info!(
                                        oep = %format!("{oep:#x}"),
                                        rva = %format!("{:#x}", oep - dll_base),
                                        "DLL OEP taken from the shell's TLS callback array \
                                         (free-run, no .text guard, no IAT guard)"
                                    );
                                }
                                None => warn!(
                                    "TLS callback array stayed empty — DLL OEP not published"
                                ),
                            }

                            // ---- leave one event pending for the trace engine ---
                            //
                            // `trace_one_slot` starts by calling `continue_event`
                            // for the event "that brought us here", so the debug
                            // session must have one pending when the post-loop
                            // phases begin.  The EXE path inherits that naturally:
                            // its IAT window exits with an event already dequeued.
                            // The DLL path has just free-run with every event
                            // answered, so it has none — measured as
                            // `trace_one_slot continue: Windows API error: code
                            // 2147942487` (`E_INVALIDARG`) on every slot.
                            //
                            // Synthesise one: trap-flag the loader thread and let
                            // it raise a single-step, then dequeue that event
                            // without answering it.
                            if let Some(tid) = Some(dbg.main_thread_id()) {
                                if let Ok(mut ctx) = dbg.get_thread_context_control(tid) {
                                    ctx.EFlags |= 0x100; // TF
                                    let _ = session::set_thread_context_control(
                                        &dbg, tid, &ctx,
                                    );
                                    if let Ok(ev) = dbg.wait_event_timeout(2000) {
                                        let ev_tid = match &ev {
                                            DebugEvent::SingleStep { thread_id, .. }
                                            | DebugEvent::Breakpoint { thread_id, .. }
                                            | DebugEvent::AccessViolation { thread_id, .. }
                                            | DebugEvent::Other { thread_id } => *thread_id,
                                            _ => 0,
                                        };
                                        debug!(
                                            pending = ev_tid,
                                            "DLL path: synthesised a pending debug event for the trace engine"
                                        );
                                    }
                                }
                            }

                            // The shell has now run to completion, so the image is
                            // fully initialised.  Raise the IAT to writable before
                            // leaving: the shell leaves it `PAGE_READONLY` (0x2), and
                            // the trace engine writes resolved addresses back into it
                            // afterwards (measured: `trace_imports write IAT: failed to
                            // write memory` unless this is raised).
                            if let Ok(iat) = determine_iat_address(
                                &dbg,
                                ls.oep.unwrap_or(dll_base),
                                dll_base + state.pe_info.pe_sections[0].virtual_address as usize,
                                &{
                                    let mut b = vec![0u8; state.pe_info.pe_sections[0]
                                        .virtual_size.min(0x100_000) as usize];
                                    let _ = dbg.read_memory(
                                        dll_base + state.pe_info.pe_sections[0]
                                            .virtual_address as usize,
                                        &mut b,
                                    );
                                    b
                                },
                                dll_base + state.pe_info.base_of_data as usize,
                                (state.pe_info.image_boundary - state.pe_info.base_of_data) as usize,
                                state.pe_info.is_vm_oep,
                                CompilerHint::Auto,
                                &state.guard_addrs,
                                &section_table(&state.pe_info.pe_sections),
                            ) {
                                match iat {
                                    Some(i) => {
                                        let ok = mida_packers_themida::install_iat_guard;
                                        let _ = ok;
                                        // set PAGE_READWRITE over the IAT
                                        use windows::Win32::System::Memory::{
                                            VirtualProtectEx, PAGE_READWRITE,
                                        };
                                        let mut old = Default::default();
                                        let r = unsafe {
                                            VirtualProtectEx(
                                                h_process,
                                                i.address as *const std::ffi::c_void,
                                                i.size,
                                                PAGE_READWRITE,
                                                &mut old,
                                            )
                                        };
                                        info!(
                                            iat = %format!("{:#x}", i.address),
                                            size = %format!("{:#x}", i.size),
                                            writable = r.is_ok(),
                                            "DLL path: IAT raised to PAGE_READWRITE for the trace write-back"
                                        );
                                    }
                                    None => warn!("DLL path: could not re-locate IAT to make it writable"),
                                }
                            }
                            // go straight to the post-loop phases and dump it.
                            break;
                        } else if text_size > 0 {
                            match mida_packers_themida::install_code_section_guard(
                                h_process,
                                text_start,
                                text_size,
                                guard_protection,
                            ) {
                                Ok(()) => {
                                    ls.guard_installed = true;
                                    info!(
                                        text = %format!("{text_start:#x}"),
                                        size = %format!("{text_size:#x}"),
                                        "Code section guard armed on the packed DLL before DllMain"
                                    );
                                }
                                Err(e) => warn!("Cannot arm DLL .text guard: {e}"),
                            }
                        }
                    }
                }

                if !ls.close_handle_bp_set {
                    let close_handle_addr = dbg.apis.as_ref().map(|a| a.close_handle);
                    // ---- DLL targets: no CloseHandle breakpoint --------------
                    //
                    // This breakpoint exists to catch the *EXE* shell's
                    // self-delete/cleanup call so the process can be dumped just
                    // before it exits.  A packed DLL has no such call: the shell
                    // is still inside `DllMain`, and it calls `CloseHandle`
                    // routinely while setting up its own state.
                    //
                    // Measured: with this breakpoint armed, the loader thread
                    // parks on `kernel32!CloseHandle` and never leaves it — the
                    // thread was sampled at that exact address at 2 s and again at
                    // 5 s, with `.bss` at 0 non-zero bytes and `hinstDLL` never
                    // written.  Without it the same DLL, same debugger, same
                    // ScyllaHide reaches `.bss` = 177 with `hinstDLL` set.
                    if looks_like_dll {
                        debug!("DLL target — skipping the CloseHandle breakpoint");
                    } else if let Some(addr) = close_handle_addr {
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

                // ---- Classic v1 file-mapping: check if this LoadDll is
                // the materialised image (Themida 1.1.1). -----------------
                //
                // The shell LoadLibrary's the decompressed program mid-run.
                // Its header has `import_rva == 0` (the shell resolved
                // imports itself and scrubbed the import directory) and
                // `entry_point == 0` (the shell keeps the real OEP in its
                // own records).  System DLLs and the packed image itself
                // carry a real import directory, so they are excluded.
                //
                // The import_rva offset was previously wrong (read the
                // Export directory at dd_off + 8 instead of the Import
                // directory at dd_off + 0), which made the check match
                // system DLLs whose export RVA happened to be zero.
                // Fixed: the Import directory VirtualAddress is at
                // dd_off + 0.
                //
                // This check fires on the LoadDll event, which is the
                // moment the image is guaranteed to be present — more
                // reliable than waiting for the CloseHandle BP (the
                // shell's variance means CloseHandle sometimes never
                // fires within the timeout).
                if !looks_like_dll
                    && state.pending_mapped_dump.is_none()
                    && matches!(
                        state.pe_info.themida_version,
                        mida_packers_themida::ThemidaVersion::V1
                            | mida_packers_themida::ThemidaVersion::Ancient
                    )
                    && base_address as u64 != image_base_usize as u64
                {
                    let mut head = [0u8; 0x400];
                    if dbg.read_memory(base_address as usize, &mut head).is_ok()
                        && head[0] == b'M' && head[1] == b'Z'
                    {
                        let e_lfanew = u32::from_le_bytes(
                            head[0x3C..0x40].try_into().unwrap_or([0; 4]),
                        ) as usize;
                        if e_lfanew + 0x200 <= head.len()
                            && head[e_lfanew] == b'P'
                            && head[e_lfanew + 1] == b'E'
                        {
                            let opt = e_lfanew + 24;
                            let is64 = u16::from_le_bytes(
                                head[opt..opt + 2].try_into().unwrap_or([0; 2]),
                            ) == 0x20B;
                            let dd_off = opt + if is64 { 112 } else { 96 };
                            // DataDirectory[0] (Import): VirtualAddress at
                            // dd_off + 0, Size at dd_off + 4.
                            let import_rva = u32::from_le_bytes(
                                head[dd_off..dd_off + 4].try_into().unwrap_or([0; 4]),
                            );
                            let size_of_image = u32::from_le_bytes(
                                head[opt + 56..opt + 60].try_into().unwrap_or([0; 4]),
                            );
                            let entry_point = u32::from_le_bytes(
                                head[opt + 16..opt + 20].try_into().unwrap_or([0; 4]),
                            );
                            if import_rva == 0 && entry_point == 0 && size_of_image >= 0x10000 {
                                let import_size = u32::from_le_bytes(
                                    head[dd_off + 4..dd_off + 8].try_into().unwrap_or([0; 4]),
                                );
                                info!(
                                    base = %format!("{:#x}", base_address),
                                    size_img = %format!("{:#x}", size_of_image),
                                    "Classic file-mapping shape: materialised image found (LoadDll event)",
                                );
                                state.pending_mapped_dump = Some(
                                    mida_pe::dumper::MappedImage {
                                        base: base_address as u64,
                                        region_size: size_of_image as u64,
                                        size_of_image,
                                        entry_point,
                                        import_rva,
                                        import_size,
                                        sections: Vec::new(),
                                        is_mapped: true,
                                    },
                                );
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

                // ---- FTMGuard re-arm trigger --------------------------------
                //
                // The TLS-callback branch plants an `int3` at the callback's
                // return site because the FTMGuard re-arm depends on that return
                // faulting, and it does not fault when DEP is not enforced for
                // the image (measured on `x86_c.exe`, which omits NX_COMPAT:
                // `.text` stayed PAGE_EXECUTE_READWRITE and the real EP ran
                // unguarded).  Consuming the breakpoint re-arms `.text` exactly
                // as the fault path would have.
                {
                    let ts_start = image_base_usize
                        .wrapping_add(state.pe_info.pe_sections[0].virtual_address as usize);
                    let ts_end = image_base_usize + state.pe_info.base_of_data as usize;
                    if mida_packers_themida::consume_tm_return_int3(
                        &mut dbg,
                        h_process,
                        &mut state,
                        address as usize,
                        thread_id,
                        ts_start,
                        ts_end,
                        guard_protection,
                    )? {
                        ls.guard_installed = true;
                        // The breakpoint byte is gone, so no RF juggling is
                        // needed: the shell's own instruction resumes normally.
                        dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                        continue;
                    }
                }

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

                // Classic file-mapping shape: the shell materialised the
                // original program as a mapped image (Themida 1.1.1).  Step
                // into it to find the OEP and dump the image directly — the
                // `.text` guard path never fires for these shells.
                if try_mapped_dump(&mut dbg, &mut state, thread_id, &output_path)? {
                    break;
                }

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
                    thread_id, exception_addr, target_address, exc_type, looks_like_dll,
                )? {
                    AvAction::Continue => {}
                    AvAction::Break => break,
                }
            }
            // ---------------------------------------------------------------
            // SINGLE_STEP — re-arm the code section guard after a guarded access
            // ---------------------------------------------------------------
            DebugEvent::SingleStep { thread_id, address } => {
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

                // Classic file-mapping shape: the mapped dump arm must also
                // fire from the SingleStep path.  HW breakpoint hits on
                // protector-packaged targets arrive as SingleStep events
                // (the kernel delivers them that way), so an arm that only
                // lives in the Breakpoint handler never runs — measured:
                // 7/7 1.1.1 runs hit "OEP not found" because the arm was
                // missing here.
                if try_mapped_dump(&mut dbg, &mut state, thread_id, &output_path)? {
                    break;
                }

                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                log::log(LogType::Info, "continue_event returned OK");
            }

            // ---------------------------------------------------------------
            // EXIT_PROCESS — target exited (unexpected before dump)
            // ---------------------------------------------------------------
            DebugEvent::ExitProcess { exit_code } => {
                warn!(exit_code, "Target process exiting — attempting final raw dump");
                // Last chance: the shell has finished decompressing and is
                // calling ExitProcess.  The materialised image is in memory
                // right now.  The periodic scan never caught it because
                // (a) the 2.75 s full-address-space scan is too slow for
                // the ~65 ms window between the CloseHandle hit and exit,
                // and (b) the `seen_image_bases` filter excludes images
                // at bases that were previously used by unloaded DLLs
                // (measured: the 1.1.1 shell reuses a DLL base for the
                // materialised image).  This final scan ignores
                // `seen_image_bases` and dumps any candidate with the
                // materialised image signature (import_rva==0 OR ep==0).
                try_exit_dump(&mut dbg, &mut state, image_base_usize, &output_path);
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

            // A first-chance exception we do not model specifically.
            //
            // Under `DEBUG_ONLY_THIS_PROCESS` the debugger is handed every
            // exception before the program's own SEH sees it.
            //
            // The continue status here is `ExceptionNotHandled`, **not**
            // `Continue`.  That distinction is the whole fix:
            //
            // * `DBG_CONTINUE` means "the debugger handled it" and resumes at
            //   the faulting instruction.  For a privileged-instruction fault
            //   that re-executes the same instruction, raises the same
            //   exception, and loops forever — measured on the x86 reference
            //   sample: the same `0xC0000096` at `0x42f396` repeating until the
            //   log reached 1.6 GB.
            // * `DBG_EXCEPTION_NOT_HANDLED` delivers the exception to the
            //   program's own SEH.  Themida's shell has a handler for this
            //   probe, so it proceeds exactly as it does without a debugger.
            //
            // This is what unblocks x86 Themida.  The x64 reference samples
            // never raised this exception, which is why the wrong status went
            // unnoticed for so long.
            DebugEvent::UnhandledException {
                thread_id,
                address,
                code,
            } => {
                debug!(
                    thread_id,
                    address = %format!("{address:#x}"),
                    code = %format!("{code:#x}"),
                    "First-chance exception — handing to the program's SEH"
                );
                dbg.continue_event(thread_id, ContinueStatus::ExceptionNotHandled)?;
            }
        }

        // Also scan after events: the materialised image loads during busy
        // periods (the decompression storm), where no 2 s quiet gap ever
        // arrives for the timeout scan to fire.
        try_map_scan(&mut dbg, &mut state, image_base_usize, &output_path);
        // Ancient exit-window watch: after the CloseHandle hit, snapshot
        // the materialised image at every event freeze (the image exists
        // only for the last tens of milliseconds before ExitProcess, and
        // each debug event is a freeze inside that window).
        try_ancient_watch_scan(&mut dbg, &mut state, image_base_usize, &output_path);
    }

/// Periodic scan for the classic shells' materialised image (Themida
/// 1.1.1).  Two call sites: the event-loop timeout (quiet periods) and the
/// loop tail (busy periods); both are 2 s-gated.  First scan records the
/// startup image set; later scans only consider new images.
fn try_map_scan(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    image_base_usize: usize,
    output_path: &std::path::Path,
) {
    if matches!(
        state.pe_info.themida_version,
        mida_packers_themida::ThemidaVersion::V1
            | mida_packers_themida::ThemidaVersion::Ancient
    ) && state.pending_mapped_dump.is_none()
    {
        if state.last_map_scan.elapsed().as_millis() >= 500 {
            state.last_map_scan = std::time::Instant::now();
            if let Ok(images) = mida_pe::dumper::scan_mapped_images(dbg, false) {
                for img in &images {
                    debug!(
                        base = format!("{:#x}", img.base),
                        size_img = format!("{:#x}", img.size_of_image),
                        ep = format!("{:#x}", img.entry_point),
                        import_rva = format!("{:#x}", img.import_rva),
                        mapped = img.is_mapped,
                        "periodic scan: image",
                    );
                }
                let packed_base = image_base_usize as u64;
                // First scan: record the startup image set (the shell's own
                // DLLs + the system DLLs).  Later scans only consider images
                // that appeared afterwards — the materialised program is
                // LoadLibrary'd by the shell mid-run (measured: its base is
                // in the 0x61xxxxxx family the shell unloads at exit).
                //
                // Two filters narrow the candidate to the materialised
                // image:
                //   * `import_rva == 0` — the shell scrubs the mapped
                //     image's import directory (it resolved the imports
                //     itself).  System DLLs and the packed image itself
                //     carry a real import directory, so they are excluded.
                //   * `size_of_image >= 0x10000` — the materialised
                //     program is at least 64 KiB; tiny mappings are
                //     shell helper structures.
                let is_first_scan = state.seen_image_bases.is_empty();
                let candidate = if is_first_scan {
                    None
                } else {
                    images
                        .iter()
                        .filter(|img| {
                            img.base != packed_base
                                && img.size_of_image >= 0x10000
                                && img.import_rva == 0
                                && !state.seen_image_bases.contains(&img.base)
                        })
                        .max_by_key(|img| img.size_of_image)
                        .cloned()
                };
                // Record the current scan's bases (after the candidate
                // decision, so the current images count as "seen" for the
                // next scan).
                for img in &images {
                    state.seen_image_bases.insert(img.base);
                }
                if let Some(img) = candidate {
                    info!(
                        base = format!("{:#x}", img.base),
                        size_img = format!("{:#x}", img.size_of_image),
                        ep = format!("{:#x}", img.entry_point),
                        "Classic file-mapping shape: materialised image found (periodic scan)",
                    );
                    // Raw dump at scan time is an Ancient-only convenience:
                    // for V1 the pending-dump → OEP-stepping → product path
                    // below must stay in charge, and an Ancient candidate
                    // that first appears mid-run is usually still mid-
                    // decompression (the bytes get overwritten by the
                    // pre-wipe CloseHandle dump or the ExitProcess fallback
                    // anyway — same output path).
                    if state.pe_info.themida_version
                        == mida_packers_themida::ThemidaVersion::Ancient
                    {
                        if let Err(e) =
                            mida_pe::dumper::dump_mapped_image_raw(dbg, &img, output_path)
                        {
                            warn!(error = %e, "Raw dump at scan time failed");
                        }
                    }
                    state.pending_mapped_dump = Some(img);
                }
            }
        }
    }
}

/// Last-chance raw dump at the `ExitProcess` event.  The periodic scan
/// (`try_map_scan`) and the CloseHandle-hit scan (`try_mapped_dump`) both
/// use the `seen_image_bases` filter, which excludes images at bases that
/// were previously used by DLLs that have since been unloaded.  The 1.1.1
/// shell reuses such a base for the materialised image, so every earlier
/// scan misses it.  At `ExitProcess` the shell has finished decompressing
/// and the image is present — this scan ignores `seen_image_bases` and
/// dumps any candidate with the materialised signature (import_rva==0
/// OR entry_point==0).  The process is still alive (the debugger holds
/// the handle), so `VirtualQueryEx` / `read_memory` work normally.
fn try_exit_dump(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    image_base_usize: usize,
    output_path: &std::path::Path,
) {
    if !matches!(
        state.pe_info.themida_version,
        mida_packers_themida::ThemidaVersion::V1
            | mida_packers_themida::ThemidaVersion::Ancient
    ) || state.pending_mapped_dump.is_some()
    {
        return;
    }
    match mida_pe::dumper::scan_mapped_images(dbg, false) {
        Ok(images) => {
            let packed_base = image_base_usize as u64;
        // Log every image found — the debug-level log in try_map_scan
        // is suppressed at INFO level, so we log here at WARN to see
        // what the process memory looks like at exit.
        for img in &images {
            warn!(
                base = format!("{:#x}", img.base),
                size_img = format!("{:#x}", img.size_of_image),
                ep = format!("{:#x}", img.entry_point),
                import_rva = format!("{:#x}", img.import_rva),
                mapped = img.is_mapped,
                "ExitProcess scan: image in memory",
            );
        }
        // Candidate filter: not the packed base, large enough, and BOTH
        // import_rva==0 AND entry_point==0 (the shell scrubs both).
        // Deliberately does NOT check `seen_image_bases` — the image may
        // be at a base that was previously used by an unloaded DLL.
        //
        // Requiring both fields zero is critical: at ExitProcess the
        // shell has finished decompressing and some DLLs may have had
        // their entry point scrubbed (ep==0) but still carry a valid
        // import directory (import_rva != 0).  Such images are false
        // positives — measured: 0x76ec0000 (a DLL with ep==0 but
        // import_rva=0x120750) was picked over the real materialised
        // image at 0x4c00000 (ep==0, import_rva==0, mapped=true).
        let candidate = images
            .iter()
            .filter(|img| {
                img.base != packed_base
                    && img.size_of_image >= 0x10000
                    && img.import_rva == 0
                    && img.entry_point == 0
            })
            .max_by_key(|img| img.size_of_image)
            .cloned();
        if let Some(img) = candidate {
            info!(
                base = format!("{:#x}", img.base),
                size_img = format!("{:#x}", img.size_of_image),
                ep = format!("{:#x}", img.entry_point),
                import_rva = format!("{:#x}", img.import_rva),
                "Materialised image found at ExitProcess — dumping raw bytes for offline rebuild",
            );
            if let Err(e) = mida_pe::dumper::dump_mapped_image_raw(dbg, &img, output_path) {
                warn!(error = %e, "Raw dump at ExitProcess failed");
            }
        } else {
            warn!(
                image_count = images.len(),
                "No materialised image candidate at ExitProcess — offline rebuild unavailable",
            );
        }
        }
        Err(e) => {
            warn!(error = %e, "ExitProcess scan failed — offline rebuild unavailable");
        }
    }
}

/// Ancient (1.1.1) exit-window watch scan.  Runs after EVERY debug event
/// once `state.ancient_watch` is armed (armed at the CloseHandle hit).
///
/// The materialised image is created and wiped inside the last tens of
/// milliseconds before `ExitProcess`, and no debug event marks either
/// boundary — but the `ExitThread` storm in that window freezes the
/// process at a dozen points, and each freeze is a chance to snapshot the
/// image in a pre-wipe (possibly mid-decompression) state.  Every snapshot
/// is written under a numbered name (`<stem>.raw000.bin`, …) so the offline
/// analysis can pick the most complete one; the canonical `raw.bin` is
/// overwritten each time, so the LAST catch wins there.
fn try_ancient_watch_scan(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    image_base_usize: usize,
    output_path: &std::path::Path,
) {
    if !state.ancient_watch {
        return;
    }
    let packed_base = image_base_usize as u64;
    let Ok(images) = mida_pe::dumper::scan_mapped_images(dbg, false) else {
        return;
    };
    // Candidates: not a registered module, big enough.  The PACKED IMAGE's
    // own first section is deliberately INCLUDED as a synthetic candidate
    // (rotated in every 3rd freeze): the shell may have decompressed the
    // original program in place BEFORE the CloseHandle hit — at which point
    // the `.text` guard did not exist yet — or may clear the guard with its
    // own VirtualProtect and execute from there.  Both are invisible to the
    // guard machinery and to the MZ-image scan (the packed base was excluded
    // from every earlier sampling pass — measured gap).
    //
    // Selection ROTATES across candidates instead of picking the largest:
    // measured on 1.1.1, the exit window loads bystander DLLs that are
    // LARGER than anything else (wetype_tip_core.dll 4.5 MB, d2d1.dll 5.1
    // MB — loaded because the original program's UI touched TSF/Direct2D;
    // the 0xb0000 "materialised image" itself turned out to be
    // KernelBase.dll.mui, a Chinese MUI resource DLL).  max_by_key let one
    // candidate monopolise every freeze.
    let mut candidates: Vec<mida_pe::dumper::MappedImage> = images
        .iter()
        .filter(|img| {
            img.size_of_image >= 0x10000
                && !state.ancient_module_bases.contains(&img.base)
        })
        .cloned()
        .collect();
    if let Some(sec0) = state.pe_info.pe_sections.first() {
        candidates.push(mida_pe::dumper::MappedImage {
            base: packed_base + sec0.virtual_address as u64,
            region_size: sec0.virtual_size as u64,
            size_of_image: sec0.virtual_size,
            entry_point: 0,
            import_rva: 0,
            import_size: 0,
            sections: Vec::new(),
            is_mapped: false,
        });
    }
    if candidates.is_empty() {
        return;
    }
    let img = candidates[state.ancient_snapshots as usize % candidates.len()].clone();
    let n = state.ancient_snapshots;
    state.ancient_snapshots += 1;
    let snap_path = output_path.with_extension(format!("raw{n:03}.bin"));
    match mida_pe::dumper::dump_mapped_image_raw_to(dbg, &img, &snap_path) {
        Ok(written) => {
            info!(
                snapshot = %snap_path.display(),
                base = format!("{:#x}", img.base),
                size = written,
                watch_index = n,
                "Exit-window watch: raw snapshot taken"
            );
        }
        Err(e) => {
            warn!(error = %e, snapshot = %snap_path.display(), "Exit-window watch snapshot failed");
        }
    }
}

/// Try to dump the materialised mapped image (Themida 1.1.1 file-mapping
/// shells).  Called from both the `Breakpoint` and `SingleStep` handlers
/// after `handle_hw_breakpoint` — HW breakpoint hits arrive as `SingleStep`
/// events on protector-packaged targets, so the arm must live in both paths
/// or it never fires (measured: 7/7 runs hit "OEP not found" because the
/// arm was only in the `Breakpoint` handler).
///
/// Returns `true` when the dump was written and the caller should `break`
/// out of the debug loop.
fn try_mapped_dump(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    thread_id: u32,
    output_path: &std::path::Path,
) -> Result<bool, anyhow::Error> {
    // Ancient (1.1.1) file-mapping shape: the shell WIPES the materialised
    // image right before ExitProcess (measured: at the ExitProcess event the
    // code region at RVA 0x1000 is high-entropy re-encrypted content, the
    // import names are gone, and 2 of 176 pages read-fail — while the
    // CloseHandle hit fires ~65 ms of runtime earlier, with the image still
    // intact).  The process is SUSPENDED inside this debug event, so the
    // scan + page-by-page dump (~3 s wall) run against the pre-wipe state.
    //
    // Two earlier filters both missed this catch point: the periodic scan's
    // `seen_image_bases` check records the image's base at the FIRST scan
    // (the mapping exists from process start) and then excludes it forever,
    // and the CloseHandle scan inherited that filter.  Here the scan ignores
    // `seen_image_bases` and uses the strict double-zero signature
    // (import_rva==0 AND entry_point==0), which system DLLs and the packed
    // image itself never match.
    //
    // The dump is RAW (no OEP stepping): the offline rebuild route consumes
    // `raw.bin` + `raw.modules.txt` directly, and `step_until_in_image`
    // cannot complete anyway — the shell exits ~65 ms after resume.
    if state.pe_info.themida_version == mida_packers_themida::ThemidaVersion::Ancient {
        let packed_base = dbg.image_base() as u64;
        if let Ok(images) = mida_pe::dumper::scan_mapped_images(dbg, false) {
            // Diagnostics: the pre-wipe header state is not known a priori
            // (measured: at ExitProcess the shell has zeroed ep/import_rva
            // and re-encrypted content, but at CloseHandle the header may
            // still carry REAL values).  Log every image so the offline
            // analysis can see what the scan actually saw.
            for img in &images {
                if img.base < 0x7000_0000 {
                    warn!(
                        base = format!("{:#x}", img.base),
                        size_img = format!("{:#x}", img.size_of_image),
                        ep = format!("{:#x}", img.entry_point),
                        import_rva = format!("{:#x}", img.import_rva),
                        mapped = img.is_mapped,
                        "CloseHandle scan: low image"
                    );
                }
            }
            // Candidate cascade — strictest first:
            //  1. double-zero signature (post-scrub shape)
            //  2. either field zero, below the system-DLL range
            //  3. largest mapping that is neither the packed image nor a
            //     registered module (the materialised image is a raw
            //     MapViewOfFile copy — LoadLibrary never registered it,
            //     so it is absent from the module list regardless of what
            //     the shell wrote into its header)
            let strict = images
                .iter()
                .filter(|img| {
                    img.base != packed_base
                        && img.size_of_image >= 0x10000
                        && img.import_rva == 0
                        && img.entry_point == 0
                })
                .max_by_key(|img| img.size_of_image)
                .cloned();
            let relaxed = if strict.is_some() {
                None
            } else {
                images
                    .iter()
                    .filter(|img| {
                        img.base != packed_base
                            && img.base < 0x7000_0000
                            && img.size_of_image >= 0x10000
                            && (img.import_rva == 0 || img.entry_point == 0)
                    })
                    .max_by_key(|img| img.size_of_image)
                    .cloned()
            };
            let fallback = if strict.is_some() || relaxed.is_some() {
                None
            } else {
                let module_bases: std::collections::HashSet<u64> =
                    match mida_pe::dumper::take_module_snapshot(
                        dbg.process_handle(),
                        dbg.pid(),
                        packed_base,
                        false,
                    ) {
                        Ok(mods) => mods.iter().map(|m| m.base()).collect(),
                        Err(_) => std::collections::HashSet::new(),
                    };
                images
                    .iter()
                    .filter(|img| {
                        img.base != packed_base
                            && img.size_of_image >= 0x10000
                            && !module_bases.contains(&img.base)
                    })
                    .max_by_key(|img| img.size_of_image)
                    .cloned()
            };
            let picked = strict.or(relaxed).or(fallback);
            if let Some(img) = picked {
                info!(
                    base = format!("{:#x}", img.base),
                    size_img = format!("{:#x}", img.size_of_image),
                    ep = format!("{:#x}", img.entry_point),
                    import_rva = format!("{:#x}", img.import_rva),
                    "Ancient file-mapping shape: dumping materialised image at CloseHandle (pre-wipe)",
                );
                match mida_pe::dumper::dump_mapped_image_raw(dbg, &img, output_path) {
                    Ok(raw_path) => {
                        info!(
                            path = %raw_path.display(),
                            "Pre-wipe raw dump written — offline rebuild can proceed"
                        );
                        // Clear TF if a previous step armed it, then report
                        // the dump as complete.
                        let step_thread = if state.main_thread_id != 0 {
                            state.main_thread_id
                        } else {
                            thread_id
                        };
                        if let Ok(mut ctx) = dbg.get_thread_context_control(step_thread) {
                            ctx.EFlags &= !0x100;
                            let _ = session::set_thread_context_control(dbg, step_thread, &ctx);
                        }
                        return Ok(true);
                    }
                    Err(e) => {
                        warn!(error = %e, "Pre-wipe raw dump at CloseHandle failed — falling through");
                    }
                }
            }
        }
        // Whether or not the CloseHandle scan saw the image: from here on
        // the shell materialises AND wipes the image inside the last tens
        // of milliseconds before `ExitProcess` (measured: the CloseHandle
        // scan finds only the packed image and system DLLs, while the
        // `ExitProcess` scan finds the image with its content already
        // destroyed).  Arm the exit-window watch: every subsequent debug
        // event freezes the process, and each freeze is a snapshot
        // opportunity before the wipe.
        state.ancient_watch = true;
        if state.ancient_module_bases.is_empty() {
            if let Ok(mods) = mida_pe::dumper::take_module_snapshot(
                dbg.process_handle(),
                dbg.pid(),
                dbg.image_base(),
                false,
            ) {
                state.ancient_module_bases = mods.iter().map(|m| m.base()).collect();
            }
        }
        return Ok(false);
    }
    // If the periodic scan hasn't found the image yet, run an immediate
    // scan at the CloseHandle hit.  The shell jumps into the image at this
    // moment, so the image is guaranteed to be present.  In the no-hook
    // environment the shell decompresses in ~11 s (vs ~90 s with hooks),
    // so the image only exists for ~80 ms — the 2 s periodic scan misses
    // it, but an immediate scan at the CloseHandle hit catches it.
    if state.pending_mapped_dump.is_none() {
        let packed_base = dbg.image_base() as u64;
        if let Ok(images) = mida_pe::dumper::scan_mapped_images(dbg, false) {
            let candidate = images
                .iter()
                .filter(|img| {
                    img.base != packed_base
                        && img.size_of_image >= 0x10000
                        && img.import_rva == 0
                        && !state.seen_image_bases.contains(&img.base)
                })
                .max_by_key(|img| img.size_of_image)
                .cloned();
            if let Some(img) = candidate {
                info!(
                    base = format!("{:#x}", img.base),
                    size_img = format!("{:#x}", img.size_of_image),
                    ep = format!("{:#x}", img.entry_point),
                    "Classic file-mapping shape: materialised image found (immediate scan at CloseHandle hit)",
                );
                state.pending_mapped_dump = Some(img);
            }
        }
    }
    let Some(img) = state.pending_mapped_dump.take() else {
        return Ok(false);
    };
    let img_end = img.base + img.size_of_image as u64;
    // The jump into the image happens on the shell's main thread; worker
    // threads deliver events during the decompression storm, so arm TF on
    // the main thread.
    let step_thread = if state.main_thread_id != 0 {
        state.main_thread_id
    } else {
        thread_id
    };
    match step_until_in_image(dbg, step_thread, img.base, img_end, 5000) {
        Ok(Some(oep_addr)) => {
            let oep_rva = (oep_addr - img.base) as u32;
            info!(oep = %format!("{oep_addr:#x}"), "OEP found inside mapped image");
            match mida_pe::dumper::dump_mapped_image_product(
                dbg, &img, oep_rva, true, output_path,
            ) {
                Ok(()) => {
                    info!("Mapped image product written");
                    dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                    return Ok(true);
                }
                Err(e) => {
                    warn!(error = %e, "Mapped image dump failed — falling back to .text guard path");
                }
            }
        }
        Ok(None) => {
            warn!("OEP not found inside mapped image — falling back to .text guard path");
        }
        Err(e) => {
            warn!(error = %e, "OEP stepping failed — falling back to .text guard path");
        }
    }
    // Offline raw dump: even when the OEP discovery failed, the image bytes
    // are still the original program.  Dump them verbatim so an offline
    // script can locate the MZ+PE, parse the header, find the IAT by
    // content, and assemble the product without a live debugger.
    match mida_pe::dumper::dump_mapped_image_raw(dbg, &img, output_path) {
        Ok(raw_path) => {
            warn!(
                path = %raw_path.display(),
                "Raw mapped image dumped for offline post-processing"
            );
        }
        Err(e) => {
            warn!(error = %e, "Raw mapped image dump also failed");
        }
    }
    // Clear TF (step_until_in_image leaves it armed) so the
    // guard path's events behave normally.
    let step_thread = if state.main_thread_id != 0 {
        state.main_thread_id
    } else {
        thread_id
    };
    if let Ok(mut ctx) = dbg.get_thread_context_control(step_thread) {
        ctx.EFlags &= !0x100;
        let _ = session::set_thread_context_control(dbg, step_thread, &ctx);
    }
    Ok(false)
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
// UPX static unpack
// ---------------------------------------------------------------------------

/// UPX's static unpack: decode the single-block stream, undo the call-trick
/// filter, rebuild imports/relocations/resources and write the original file.
///
/// The whole pipeline is file work (`mida_packers_upx::unpack_static`), so
/// unlike the Themida branch there is no debuggee, no injection and no
/// desktop-session requirement — headless environments can unpack UPX.  The
/// product is byte-for-byte what `upx -d` produces (verified against the
/// corpus in the packer crate's gate); note UPX itself rewrites the DOS stub
/// area when packing and never restores it, so "byte-for-byte" means `upx -d`'s
/// output, not the pre-pack original.
fn unpack_upx_static(pe: &PeHeader, image: &[u8], output_path: &Path) -> Result<(), anyhow::Error> {
    log::log(
        LogType::Info,
        "UPX target — running the static unpacker (no process is created)",
    );
    let product = mida_packers_upx::unpack_static(pe, image)
        .map_err(|e| anyhow!("static UPX unpack failed: {e}"))?;
    std::fs::write(output_path, &product)
        .with_context(|| format!("writing {}", output_path.display()))?;
    let ph = mida_packers_upx::find_pack_header(image);
    let shape = ph
        .map(|h| format!("method {} / filter {:#x}", h.method_label(), h.filter))
        .unwrap_or_else(|| "unknown shape".to_string());
    log::log(
        LogType::Good,
        &format!(
            "Wrote {} ({} bytes), decoded with {}",
            output_path.display(),
            product.len(),
            shape
        ),
    );
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
        &section_table(&state.pe_info.pe_sections),
    )?
    .ok_or_else(|| anyhow!("IAT not found"))?;

    log::log(
        LogType::Info,
        &format!("IAT at {:#x}, size {:#x}", iat.address, iat.size),
    );

    let strategy = match state.pe_info.themida_version {
        // The classic v1-generation stubs (including the `"Themida "`-named
        // Ancient shape) use the Pascal classic IAT repair; only V3 has the
        // trace-based machinery its own strategy expects.
        mida_packers_themida::ThemidaVersion::V1
        | mida_packers_themida::ThemidaVersion::Ancient => IatFixStrategy::V1,
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
            // The scan is informational: a classic candidate that reaches this
            // point has already been VERIFIED by single-stepping (it never
            // returned to the shell), and a v3 guard OEP carries the VM
            // machinery's proof.  The scan alone is not evidence strong
            // enough to override either.
            info!(
                guard_oep = %format!("{oep_addr:#x}"),
                scan_oep = %format!("{real_oep:#x}"),
                "Live-memory scan found different OEP — using the verified/guard-detected OEP"
            );
        }
    }

    log::log(LogType::Info, &format!("Final OEP: {:#x}", oep_addr));

    if shrink {
        match shrink_pe(pe) {
            Ok(removed) => log::log(LogType::Info, &format!("PE model shrink: dropped {removed} Themida section(s)")),
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
        classic_imports: matches!(
            state.pe_info.themida_version,
            mida_packers_themida::ThemidaVersion::V1
                | mida_packers_themida::ThemidaVersion::Ancient
        ),
    };

    mida_pe::dump_process(dbg, &dump_opts)
        .map_err(|e| anyhow!("Dump failed: {e}"))?;

    log::log(LogType::Good, &format!("Unpacked: {}", output_path.display()));
    Ok(())
}

