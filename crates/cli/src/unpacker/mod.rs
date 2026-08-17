//! Themida unpacker main flow ??ties together all modules.
//!
//! ## Reference
//!
//! This module corresponds to the combined logic of:
//! - `Themida.pas` / `Themida64.pas` ??the full unpacking pipeline.
//! - `Magicmida.dpr` ??`CheckCommandlineInvocation` ??CLI dispatch.
//! - `Unit2.pas` ??`btnUnpackClick` ??per-file unpack entry point.
//!
//! ## Architecture
//!
//! ```text
//! parse PE ─??dual identify ─??host layout (ThemidaPeInfo) ─??create process ─??ScyllaHide
//!                                                                    ??//!    ┌───────────────────────────────────────────────────────────────??//!    ??//!  debug loop (simplified):
//!    · wait_event ??handle anti-debug ??CloseHandle bp ??install guard
//!    · ACCESS_VIOLATION ??process_guarded_access ??detect OEP
//!    · OEP found ??remove guard ??IAT phase
//!    ??//!  determine IAT ─??fix IAT ─??[trace imports (v3)] ─??fix call sites
//!    ??//!  dump to file ─??postprocess (data sections / shrink) ─??cleanup
//! ```

mod antidebug_controller;
mod av_handler;
mod av_query;
pub mod bundle_assembler;
mod dump;
mod early_snapshots;
pub(crate) mod evidence_schema;
mod generic;
pub mod generic_bundle_assembler;
mod generic_gate;
mod gto_host;
mod helpers;
mod iat_evidence;
mod iat_trace;
mod loop_state;
mod oep_evidence;
mod oep_scan;
mod plugin_host;
mod post_attach;
mod post_loop;
mod relocation_evidence;
mod section_rebuild_evidence;
mod session;
pub(crate) mod sidecar_io;
mod tls_evidence;
mod verify;

#[cfg(test)]
mod production_e2e;

use std::fs;
use std::path::Path;

use anyhow::{anyhow, Context};
use tracing::{debug, warn};
use windows::Win32::System::Memory::PAGE_NOACCESS;
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

use crate::log::{self, LogType};
use mida_core::{
    ContinueStatus, CreateProcessOptions, DebugEvent, DebuggerCore, HwbpType, OepProvenance,
    PackerPlugin, PluginAdvice, PluginCtx, PreferredBase, UnpackPhase,
};
use mida_packers_themida::{handle_nt_set_information_thread, init_pe_details, ThemidaState};
use mida_pe::{ContainerRestoreMode, DumpProfile, OepPolicy, PeHeader};

use av_handler::{handle_access_violation, AvAction};
use early_snapshots::capture_early_section_snapshots;
use helpers::{
    dotnet_dump_and_dump_output, handle_hw_breakpoint, pe_section_name_remote_rva,
    resolve_api_addrs, resolve_host_api, resolve_output_path,
};
use iat_trace::{handle_trace_step, TracePhase};
use loop_state::LoopState;
use plugin_host::{
    dual_select_packer, enter_dump_phase, gto_heavy_capabilities_enabled, note_plugin_av_break,
    note_plugin_iat_complete, plugin_leave_reason, refresh_plugin_loop_policy,
    sync_plugin_milestones, validate_gto_route,
};
use post_attach::run_post_attach_path;
use post_loop::run_post_loop_phases;
use session::ProcessSession;

// Re-export public functions for commands.rs
pub use dump::dump_process_code;
pub use generic::generic_unpack;
pub use generic_gate::{
    gate_inputs_from_pe, is_ahk_export_name, validate_generic_dump, GenericGateFailure,
    GenericGateInputs, GenericGateProfile, GenericGateResult, AHK_EXPORT_NAMES,
};
pub use verify::verify_unpacked;

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
/// - `input` ??path to the protected executable.
/// - `output` ??optional output path; defaults to `<input_stem>U<ext>` (the "U"
///   suffix convention from the Pascal reference).
/// - `create_data_sections` ??restore `.rdata`/`.data` sections (`--data-sections`).
/// - `shrink` ??remove Themida-specific sections from the output (`--shrink`).
/// - `oep_policy` ??how to choose the final PE entry point.
/// - `container_restore` ??SecurityCookie heap container restore mode.
/// - `profile` ??dump behaviour profile (default OreansClassic; GTO is opt-in).
///
/// # Errors
///
/// Returns an [`anyhow::Error`] on any failure.
pub fn unpack(
    input: &Path,
    output: Option<&Path>,
    do_data_sections: bool,
    shrink: bool,
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    pure_rebuild: bool,
    capture_policy: mida_pe::DumpCapturePolicy,
    capture_policy_digest: &str,
    preflight_dir: Option<&Path>,
    snapshot_root: Option<&Path>,
) -> Result<(), anyhow::Error> {
    use tracing::info;
    info!("=== UNPACK START ===");
    info!("Input: {}", input.display());
    info!(
        ?oep_policy,
        ?container_restore,
        ?profile,
        capture_source = capture_policy.source_label(),
        hot_roots = capture_policy.hot_root_rvas.len(),
        "Unpack policy"
    );

    // ---- step 1: resolve output path ----
    let output_path = resolve_output_path(input, output);
    info!("Output: {}", output_path.display());

    // ---- step 1b: P6.2/P6.3 launch boundary ----
    // When a preflight directory is supplied, the run may not create the
    // sample process until the launch attestation passes (P6.3-B): the
    // Ready report is re-verified by the independent acceptance verifier
    // against the current run context, every identity (input, output, CLI
    // binary, actual run config) is re-checked locally, and the actual
    // configuration — including the resolved pure-rebuild value with the
    // Origin Macro D3 default — must match the envelope digest and the P7
    // fixed-mode policy for this input. A hand-written `ready` JSON is
    // never an authorization credential. Runs without --preflight-dir keep
    // legacy behaviour.
    // P6.3-D: the attested evidence context flows into sidecar and bundle
    // production after a successful gated run.
    // G2-R1: the packer family is bound at STAGING time into the envelope case
    // for this input (from the case manifest's `protection_family`). It is
    // resolved HERE — before the actual/frozen policy and the digest are built
    // and before the Ready attestation — so a run can never attest under one
    // family and then switch to another. There is no rebind path.
    let mut evidence_ctx: Option<crate::runner_preflight::RunEvidenceContext> = None;
    let mut attested_family: Option<String> = None;
    if let Some(preflight_dir) = preflight_dir {
        let envelope = crate::runner_preflight::RunnerConfigEnvelope::read(preflight_dir)
            .map_err(|e| anyhow!("launch blocked: runner-config envelope unavailable: {e:#}"))?;
        let cli_binary = std::env::current_exe()
            .map_err(|e| anyhow!("launch blocked: cannot resolve the current executable: {e}"))?;
        let cli_binary_sha256 = crate::runner_preflight::sha256_file(&cli_binary)
            .map_err(|e| anyhow!("launch blocked: cannot digest the current executable: {e}"))?;
        // Resolve the envelope-bound family for THIS input before building the
        // actual config (the input is matched by identity, not yet parsed). If
        // the input is not a staged case input (e.g. a hermetic synthetic
        // input in tests), case-selection fails here and the run is refused by
        // the attestation below; the actual config is still built with a
        // conservative (Oreans-compat) family so the P7 policy divergence
        // reasons remain visible before the case-selection refusal.
        let mut family = mida_core::runner_config::packer_family::OREANS.to_string();
        if let Ok(current_identity) = crate::runner_preflight::file_identity(input) {
            if let Ok(staged) =
                crate::runner_preflight::select_case_config(&envelope, &current_identity)
            {
                family = staged.family_id.clone();
            }
        }
        let actual_config = crate::run_spec::runner_config_from_unpack_args_family(
            &family,
            oep_policy,
            container_restore,
            profile,
            shrink,
            do_data_sections,
            pure_rebuild,
            capture_policy_digest,
            &envelope.tool_revision,
            &cli_binary_sha256,
        );
        if let Some(reason) = crate::run_spec::policy_matches(
            &actual_config,
            &crate::run_spec::frozen_run_policy_for_family(input, &family),
        ) {
            return Err(anyhow!(
                "launch blocked: run config diverges from the P7 fixed-mode policy for this \
                 input: {reason}"
            ));
        }
        // The trusted immutable-snapshot root for this launch is the CALLER-
        // supplied root (must equal the root used at staging). It is never
        // re-derived from preflight_dir unless the caller omitted it, in which
        // case the default `<preflight_dir>/sample-snapshots` is used.
        let snapshot_root = match snapshot_root {
            Some(root) => root.to_path_buf(),
            None => preflight_dir.join(crate::commands::GTO_SNAPSHOT_DIRNAME),
        };
        let launch_ctx = crate::runner_preflight::LaunchAttestationContext {
            input,
            output: &output_path,
            cli_binary: &cli_binary,
            runner_config: &actual_config,
            snapshot_root: &snapshot_root,
        };
        // The attestation binds the ENVELOPE's family (staging-sealed) into
        // the single-use evidence context — never a caller-supplied or
        // rebindable family. `attest_ready_before_launch` reads it from the
        // matched case and fails closed if the actual config family differs.
        let context = crate::runner_preflight::attest_ready_before_launch(
            preflight_dir,
            &launch_ctx,
        )
        .map_err(|e| {
            anyhow!("launch blocked by preflight attestation before any process creation: {e:#}")
        })?;
        // P6.3.1: the attestation outcome is a hard gate event — emit a
        // stable, filter-independent line (the `info!` below is for verbose
        // logging only and must not be the sole signal tests rely on).
        eprintln!(
            "launch attestation: Ready (case {}; family {}; runner-config digest {})",
            context.case_id(),
            context.packer_family(),
            context.runner_config_digest()
        );
        info!(
            "Launch attestation: Ready — case {} (family {}) bound to envelope digest {}",
            context.case_id(),
            context.packer_family(),
            context.runner_config_digest()
        );
        attested_family = Some(family);
        evidence_ctx = Some(context);

        // ---- deterministic test-only launch-stop boundary ----
        // The launch attestation has produced Ready. Before any PE parse or
        // process creation, the #[cfg(test)] seam may stop the dispatch
        // deterministically with a stable, unique sentinel error so the
        // production-shaped /unpack tests terminate here — never by relying on
        // a malformed synthetic PE failing to parse. Production is a compile-
        // time no-op (always Ok), so real runs proceed to `PeHeader::from_file`
        // and the sample process exactly as before.
        crate::runner_preflight::maybe_test_launch_stop()?;
    }
    // ---- step 2: parse PE header ----
    log::log(LogType::Info, &format!("Loading: {}", input.display()));

    let mut pe =
        PeHeader::from_file(input).map_err(|e| anyhow!("Failed to parse PE header: {e}"))?;

    let is_64bit = pe.is_64bit;
    debug!(is_64bit, "PE architecture");

    // ---- step 2b: dual identify BEFORE host state / process create (P1) ----
    // Family selection is independent of ThemidaState. Dump stages for GTO
    // still require explicit --profile=ahk-gto-experimental.
    let (mut packer, oreans_id, gto_id, selected_family) = dual_select_packer(
        is_64bit,
        pe.entry_point,
        pe.size_of_image(),
        pe.sections.iter().map(|s| s.name.clone()).collect(),
    );
    info!(
        selected = packer.family_id(),
        oreans = ?oreans_id,
        ahk_gto = ?gto_id,
        conf = packer.last_identify_confidence(),
        "PackerPlugin identify: dual-family select (pre-process)"
    );
    match selected_family {
        "oreans_themida" => match &oreans_id {
            mida_core::IdentifyResult::Match { confidence } => {
                info!(
                    family = packer.family_id(),
                    confidence, "PackerPlugin identify: Match"
                );
            }
            mida_core::IdentifyResult::Ambiguous => {
                info!(
                    family = packer.family_id(),
                    "PackerPlugin identify: Ambiguous"
                );
            }
            mida_core::IdentifyResult::NoMatch => {
                warn!(
                    family = packer.family_id(),
                    "PackerPlugin identify: NoMatch (continuing Oreans host path)"
                );
            }
        },
        "ahk_gto" => {
            info!(
                family = packer.family_id(),
                confidence = packer.last_identify_confidence(),
                "PackerPlugin identify: Match"
            );
            if !matches!(profile, DumpProfile::AhkGtoExperimental) {
                warn!(
                    "AHK/GTO family identified but dump profile is not ahk-gto-experimental ??\
                     heap/container stages stay disabled (pass --profile=ahk-gto-experimental)"
                );
            }
        }
        other => {
            warn!(
                family = other,
                "PackerPlugin identify: no strong family match (default Oreans host path)"
            );
        }
    }

    // ---- G2-R1: PE-identified family must match the attested family ----
    // The packer family was bound at STAGING into the envelope, resolved and
    // attested BEFORE any policy/digest/process work above. Now that the input
    // PE is parsed, the PE-identified family must equal the attested envelope
    // family. Any mismatch (or an unknown attestation family) fails closed
    // BEFORE the sample process is created — there is no rebind path.
    if let Some(attested) = attested_family.as_deref() {
        if selected_family != attested {
            return Err(anyhow!(
                "launch blocked: PE-identified packer family {selected_family:?} != attested \
                 envelope family {attested:?}; refusing to launch (fail-closed before process \
                 creation)"
            ));
        }
    }

    // ---- family host PE layout probe (shared post-attach/post-loop skeleton) ----
    // Both Oreans and AHK/GTO continue down the shared main flow from here
    // (G1): same create-process, same post-attach observation loop, same
    // post-loop dump. Family differences are decided in the plugin/policy
    // layer. Oreans builds full ThemidaPeInfo (version / virtualised OEP /
    // Themida section); AHK/GTO builds a minimal layout (no Oreans assumptions).
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

    let pe_info = if selected_family == "ahk_gto" {
        log::log(
            LogType::Info,
            "GTO family: minimal shared-host PE layout (no Oreans version/OEP probe)",
        );
        mida_packers_themida::themida_pe_info_basic(&pe, is_64bit)
    } else {
        init_pe_details(&pe, is_64bit, entry_bytes_ref, Some(input))
            .map_err(|e| anyhow!("Host PE layout probe failed (family={selected_family}): {e}"))?
    };

    log::log(
        LogType::Info,
        &format!(
            "Host layout: family={selected_family} themida_version={:?} (shared host state)",
            pe_info.themida_version
        ),
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
            ".NET target detected ??will dump via _CorExeMain breakpoint",
        );
    }

    // ---- step 3c: for .NET targets, pre-resolve _CorExeMain from host mscoree ----
    // The host-side address is usually valid in the target because mscoree.dll
    // is loaded at a per-system ASLR base shared across processes.
    let mut cor_exe_main_addr: Option<usize> = None;
    if is_dotnet {
        cor_exe_main_addr = Some(resolve_host_api("mscoree.dll", "_CorExeMain"));
        if cor_exe_main_addr == Some(0) {
            warn!("_CorExeMain not found ??.NET dump may fail");
            cor_exe_main_addr = None;
        }
    }

    // ---- step 4: create debug process ----
    // Host still uses ThemidaState for sections / guards / IAT helpers even
    // when family=ahk_gto (shared host; not independent GTO pipeline).
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
    if packer.uses_gto_observation() {
        validate_gto_route(profile, text_is_plain_for_attach)
            .map_err(|reason| anyhow!("GTO preflight blocked before process creation: {reason}"))?;
        if !gto_heavy_capabilities_enabled(profile) {
            warn!(
                "GTO shared observation enabled; heavy capabilities remain disabled without --profile=ahk-gto-experimental"
            );
        }
    }
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
    // - CreateProcess ??patch PEB, resolve APIs, apply ScyllaHide
    // - LoadDll ??close file handle
    // - Breakpoint (CloseHandle) ??install code section guard
    // - AccessViolation ??process_guarded_access
    // - SingleStep ??restore_code_section_guard
    //
    // The full IAT repair and dump happen *after* the guard loop detects OEP.

    // Build the core debugger ??it owns the process, main-thread handle,
    // and stub EXE, and will clean them up via `Drop` when this struct goes
    // out of scope.  `ProcessSession` wraps it in `DebuggerCoreEngine` (R2
    // wait/continue pump) and caches per-session `ResolvedApis`.
    // Record the real sample-process launch boundary (test-only). This fires
    // immediately before the actual process creation; the dispatch tests
    // assert it stays empty because the launch-stop sentinel fires earlier.
    // Production is a compile-time no-op.
    crate::runner_preflight::note_sample_launch_attempted();
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
    // window).  Inject here instead ??the hooks land in the already-running
    // process before we enter the debug loop.
    //
    // PEB patching in post-attach mode is already done by WindowsDebugger while
    // the process is suspended, so no CREATE_PROCESS handler is involved.
    let post_attach_mode = text_is_plain_for_attach;
    if post_attach_mode {
        // No ScyllaHide needed ??there is no debug port, so Themida's
        // anti-debug checks (DebugPort, BeingDebugged) never trigger.
        // The process started only after the early snapshot was captured, so we
        // go straight to text polling + dump without a debug port.
        //
        // Resolve kernel32 API addresses for later use (breakpoint
        // comparisons etc.).
        let apis = resolve_api_addrs()?;
        dbg.apis = Some(apis);
        info!("post-attach: no debug port ??direct dump mode (SuspendThread + ReadProcessMemory)");
    }

    // ---- plugin session context (packer already selected pre-process) ----
    let section0_is_plain_text = state
        .pe_info
        .pe_sections
        .first()
        .is_some_and(|s| s.name == ".text");
    let mut plugin_ctx = PluginCtx {
        preferred_base: Some(PreferredBase(pe.image_base)),
        is_dotnet,
        section0_is_plain_text,
        ..PluginCtx::default()
    };
    packer.apply_session_defaults(&mut plugin_ctx);

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
        oep_provenance: OepProvenance::default(),
        oep_found_via_scanning: false,
        virtualized_oep_retries: 0,
        last_possible_oep: None,
        unrelated_av_streak: 0,
        process_exited: false,
        storm_escape_freeze: false,
        iat_trace: None,
        text_poll_idle_timeout_secs: plugin_ctx.text_poll_idle_timeout_secs,
        iat_monitor_timeout_secs: plugin_ctx.iat_monitor_timeout_secs,
        virtualized_oep_max_retries: plugin_ctx.virtualized_oep_max_retries,
        unrelated_av_storm_threshold: plugin_ctx.unrelated_av_storm_threshold,
        unrelated_av_null_storm_threshold: plugin_ctx.unrelated_av_null_storm_threshold,
        text_poll_min_nonzero: plugin_ctx.text_poll_min_nonzero,
    };

    let guard_protection = PAGE_NOACCESS.0;
    // Image boundary from PE header (pre-ASLR value). Will be rebased after
    // CreateProcess event provides the real image_base.
    let pe_image_boundary = state.pe_info.image_boundary as usize;
    let pe_image_base = state.pe_info.image_base as usize;

    // Snapshot the process handle once ??the process loop passes it to packer
    // helpers that don't go through the `DebuggerCore` trait.
    let h_process = dbg.process_handle();

    // ---- post-attach fast path: no debug port, direct dump ----
    // Observe the freely running primary thread, freeze it on its first
    // transfer into decrypted .text, then go straight to the dump phase.
    // Body: `post_attach::run_post_attach_path`.
    //
    // MIDA-ADR-3B: this path produces candidates, so it must NOT bypass the
    // anti-debug controller gate. The post-attach launch has no debug port
    // (debugger presence is structurally invisible), but we cannot assert
    // the target performs no other anti-debug checks without a MIDA runtime.
    // Until the runtime exists (ADR-4+), this path fails closed exactly like
    // the CREATE_PROCESS path: AntiDebugRuntimeUnavailable, structured
    // evidence, no candidate.
    if post_attach_mode {
        let evidence_dir = output_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let mut ad_controller = antidebug_controller::AntidebugController::new(
            antidebug_controller::AntidebugStageOptions {
                sample_id: None,
                target_pid: dbg.pid(),
                evidence_dir: Some(evidence_dir.clone()),
                oracle: None,
                cleanup_backend: Some(Box::new(antidebug_controller::Win32CleanupBackend::new(
                    dbg.process_handle(),
                ))),
            },
        );
        let outcome = ad_controller.run();
        if let antidebug_controller::AntidebugOutcome::Failed {
            state,
            fail_code,
            message,
        } = &outcome
        {
            let evidence = ad_controller
                .failure_evidence(&outcome)
                .expect("failure outcome must produce evidence");
            if let Err(ew) = antidebug_controller::write_failure_evidence(&evidence, &evidence_dir)
            {
                return Err(anyhow::anyhow!(
                    "anti-debug failure evidence write failed: {ew:#}; original: {message}"
                ));
            }
            return Err(anyhow::anyhow!(
                "post-attach blocked by anti-debug lifecycle: {message} (state={state:?} fail_code={})",
                fail_code.as_str(),
            ));
        }
        run_post_attach_path(
            &mut dbg,
            &mut state,
            &mut pe,
            &mut packer,
            &mut plugin_ctx,
            &mut early_section_snapshots,
            is_dotnet,
            is_64bit,
            do_data_sections,
            shrink,
            oep_policy,
            container_restore,
            profile,
            pure_rebuild,
            capture_policy,
            input,
            &output_path,
        )?;
        // P6.3-D: after a successful gated run, produce the evidence bundle
        // from the attested single-use context (consumed by value).
        if let Some(ctx) = evidence_ctx.take() {
            crate::runner_preflight::complete_run_evidence(ctx, &output_path)
                .map_err(|e| anyhow!("evidence bundle assembly failed after a gated run: {e:#}"))?;
        }
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

        // Slice 3b-3/3b-6: recompute flags; leave via shared helper.
        refresh_plugin_loop_policy(&mut packer, &mut plugin_ctx, &ls);
        if let Some(reason) = plugin_leave_reason(&plugin_ctx) {
            log::log(
                LogType::Info,
                &format!("PackerPlugin leave_debug_loop before wait ({reason})"),
            );
            break;
        }

        // Prefer finite wait while plugin says so (text-poll); else blocking.
        // R2: wait via engine so we retain EngineEvent.sequence for PackerPlugin.
        let engine_event = if plugin_ctx.prefer_short_wait {
            let wait_ms = plugin_ctx.short_wait_ms;
            match dbg.wait_engine(Some(wait_ms)) {
                Ok(ev) => ev,
                Err(mida_core::CoreError::Timeout) => {
                    // No debug event ??continue loop for polling
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
            dbg.wait_engine(None).map_err(|e| {
                log::log(LogType::Fatal, &format!("wait_event returned error: {e:#}"));
                e
            })?
        };
        log::log(
            LogType::Info,
            &format!(
                "event received (seq={}): {:?}",
                engine_event.sequence, engine_event.event
            ),
        );

        // PackerPlugin consult (Slice 3b): policy flags + Abort/Done only.
        // Handler bodies still run below; plugin does not own Win32.
        let plugin_advice = packer.on_event(&mut plugin_ctx, &engine_event);
        match &plugin_advice {
            PluginAdvice::Abort { message } => {
                log::log(LogType::Fatal, &format!("PackerPlugin abort: {message}"));
                if let Err(continue_error) = dbg.continue_pending_event(ContinueStatus::Continue) {
                    return Err(anyhow!(
                        "PackerPlugin abort: {message}; pending event continue failed: {continue_error}"
                    ));
                }
                return Err(anyhow!("PackerPlugin abort: {message}"));
            }
            PluginAdvice::Transition(UnpackPhase::Done) => {
                ls.process_exited = plugin_ctx.process_exited || ls.process_exited;
                // Host ExitProcess arm still breaks; keep flag consistent.
            }
            PluginAdvice::Transition(phase) => {
                debug!(?phase, "PackerPlugin phase transition (host may act later)");
            }
            PluginAdvice::Continue(_) => {}
        }
        // Move event after consult (DebugEvent is not Clone ??HANDLE fields).
        let event = engine_event.event;

        // Reset idle timer ??we got a real event, Themida is still active
        if ls.text_polling {
            ls.text_poll_start = None;
        }

        // ---- .text decryption polling (CREATE_PROCESS ??guard delay) ----
        // Themida checks .text page protection during init ??any non-PAGE_EXECUTE_READ
        // protection is detected. So we do NOT install guard at CREATE_PROCESS.
        // Instead: let Themida run freely, poll .text via ReadProcessMemory (which
        // is not affected by page protection), and only install guard after .text
        // is stable (decryption complete). Then SuspendThread ??read RIP ??decide:
        //   RIP in .text ??OEP = RIP
        //   RIP elsewhere ??install guard, resume, wait for AV
        if ls.text_polling && ls.oep.is_none() && ls.iat_trace.is_none() && !ls.text_reguarded {
            // 30s timeout from LAST debug event (not from CREATE_PROCESS).
            // Themida's DLL loading can take minutes; only start the timeout
            // clock when we've stopped receiving debug events.
            if ls.text_poll_start.is_none() {
                ls.text_poll_start = Some(std::time::Instant::now());
            }
            if let Some(start) = ls.text_poll_start {
                let idle_secs = ls.text_poll_idle_timeout_secs;
                if start.elapsed() > std::time::Duration::from_secs(idle_secs) {
                    log::log(LogType::Fatal,
                        &format!(".text poll timeout ({idle_secs}s idle, {} polls) ??Themida may not have reached decryption",
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
                    let min_nz = ls.text_poll_min_nonzero as usize;
                    if non_zero > min_nz {
                        if sample == ls.text_prev_sample {
                            // .text stable ??decryption complete
                            log::log(
                                LogType::Good,
                                &format!(
                                    ".text decrypted and stable (poll #{}, {non_zero}/16 non-zero)",
                                    ls.text_poll_count
                                ),
                            );
                            ls.text_stable = true;
                            ls.text_polling = false;

                            // SuspendThread ??read RIP ??decide OEP vs guard
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
                                // RIP in .text ??this is OEP
                                log::log(
                                    LogType::Good,
                                    &format!("OEP captured via RIP in .text: {:#x}", rip),
                                );
                                ls.oep = Some(rip);
                                ls.oep_provenance = OepProvenance::runtime_rip(
                                    rip as u64,
                                    format!(
                                        "debug-loop text-poll RIP inside decrypted .text: {rip:#x}"
                                    ),
                                );
                                ls.oep_found_via_scanning = false;
                                // Resume thread ??will be redirected in post-loop
                                let _ = unsafe { ResumeThread(h_thread) };
                            } else {
                                // RIP not in .text ??.text already decrypted,
                                // scan it for the real OEP (MSVC CRT pattern).
                                // No guard needed ??we go straight to dump.
                                log::log(
                                    LogType::Info,
                                    &format!(
                                        "RIP not in .text ({:#x}) ??scanning .text for OEP",
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
                                        ls.oep_provenance = OepProvenance::scan_fallback(
                                            real_oep as u64,
                                            format!("live .text scan selected OEP: {real_oep:#x}"),
                                        );
                                        ls.oep_found_via_scanning = true;
                                    }
                                    Ok(None) => {
                                        // Scan failed ??try PE entry point as fallback
                                        let pe_ep = image_base_usize + pe.entry_point as usize;
                                        log::log(
                                            LogType::Warn,
                                            &format!("OEP scan failed ??using PE EP: {:#x}", pe_ep),
                                        );
                                        ls.oep = Some(pe_ep);
                                        ls.oep_provenance = OepProvenance::scan_fallback(
                                            pe_ep as u64,
                                            format!("live OEP scan failed; PE entry-point fallback: {pe_ep:#x}"),
                                        );
                                        ls.oep_found_via_scanning = true;
                                    }
                                    Err(e) => {
                                        warn!("OEP scan error: {e}");
                                    }
                                }
                                // Do NOT ResumeThread ??keep process frozen.
                                // Themida will kill the process on resume (0xDEADC0DE),
                                // but ReadProcessMemory works on a frozen/suspended
                                // process. We break out of the debug loop immediately
                                // and dump from the frozen process's memory.
                                log::log(LogType::Info,
                                    "Process kept frozen ??will dump IAT + .text from suspended state");
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

        // Frozen-dump / leave decisions from plugin (e.g. OEP via scan).
        refresh_plugin_loop_policy(&mut packer, &mut plugin_ctx, &ls);
        if let Some(reason) = plugin_leave_reason(&plugin_ctx) {
            log::log(
                LogType::Info,
                &format!("PackerPlugin leave_debug_loop ({reason})"),
            );
            break;
        }

        match event {
            // ---------------------------------------------------------------
            // CREATE_PROCESS ??patch PEB, store image base, resolve APIs
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
                // automatically ??we no longer duplicate that state here.

                // In post-attach mode the PEB was already patched by
                // WindowsDebugger::post_attach_init (right after
                // DebugActiveProcess froze the process), and ScyllaHide +
                // API resolution were done in the pre-loop block above.
                // Skip them here to avoid redundant work / double-inject.
                if post_attach_mode {
                    debug!(
                        "post-attach: CREATE_PROCESS ??PEB/ScyllaHide/APIs already done, skipping"
                    );
                } else {
                    // Patch PEB (BeingDebugged, pShimData) via the core helper.
                    let peb_base =
                        mida_core::patch_peb_anti_debug(evt_h_process).unwrap_or(image_base);
                    debug!(peb_image_base = %format!("{peb_base:#x}"), "PEB patched");

                    // Resolve kernel32 API addresses (in the debugger's own
                    // process ??valid in the target on x64).
                    let apis = resolve_api_addrs()?;

                    // ---- MIDA-ADR-3B: anti-debug lifecycle (fail-closed) ----
                    //
                    // The self-owned MIDA anti-debug runtime does not exist yet
                    // (ADR-4+). Until it does, the anti-debug runtime dependency
                    // is *unavailable by definition*, so the controller
                    // deterministically enters DependencyUnavailable and the
                    // unpack must abort with AntiDebugRuntimeUnavailable.
                    //
                    // ScyllaHide is NOT a MIDA success proof. It is never used
                    // as a silent fallback here; it may only run in explicit
                    // oracle mode (future differential experiments, ADR-7).
                    let evidence_dir = output_path
                        .parent()
                        .map(|p| p.to_path_buf())
                        .unwrap_or_else(|| std::path::PathBuf::from("."));
                    let mut ad_controller = antidebug_controller::AntidebugController::new(
                        antidebug_controller::AntidebugStageOptions {
                            sample_id: None, // case binding happens in preflight
                            target_pid: pid,
                            evidence_dir: Some(evidence_dir.clone()),
                            oracle: None, // oracle mode is opt-in and never production
                            cleanup_backend: Some(Box::new(
                                antidebug_controller::Win32CleanupBackend::new(
                                    dbg.process_handle(),
                                ),
                            )),
                        },
                    );
                    let outcome = ad_controller.run();
                    match &outcome {
                        antidebug_controller::AntidebugOutcome::Proceed { .. } => {
                            // Only reachable once a real MIDA runtime exists.
                            // Keep the success path explicit so ADR-4 wiring has
                            // a deterministic seam.
                            info!("anti-debug lifecycle: Proceed (MIDA runtime ready)");
                        }
                        antidebug_controller::AntidebugOutcome::Failed {
                            state,
                            fail_code,
                            message,
                        } => {
                            // Structured evidence sidecar (atomic, schema'd,
                            // mida.antidebug-evidence/v1 record_kind=cli-failure).
                            // cleanup_result reflects the explicit cleanup backend
                            // outcome (ok / failed / not-run).
                            let evidence = ad_controller
                                .failure_evidence(&outcome)
                                .expect("failure outcome must produce evidence");
                            if let Err(ew) = antidebug_controller::write_failure_evidence(
                                &evidence,
                                &evidence_dir,
                            ) {
                                // Evidence write failure must itself fail closed.
                                return Err(anyhow::anyhow!(
                                    "anti-debug failure evidence write failed: {ew:#}; original: {message}"
                                ));
                            }
                            // Fail-closed: hard error, no candidate, no TLS/OEP
                            // success evidence. Target cleanup was driven by the
                            // explicit cleanup backend (CleanupFailed upgrade when
                            // the backend failed).
                            return Err(anyhow::anyhow!(
                                "anti-debug lifecycle failed: {message} (state={state:?} fail_code={})",
                                fail_code.as_str(),
                            ));
                        }
                    }

                    // Store resolved APIs for later breakpoint comparisons.
                    dbg.apis = Some(apis);
                }

                // Fix PE header anti-dump: Themida corrupts the first byte
                // of section 2's name ('p' ??'i', making .pdata look like
                // .idata).  Patch it back immediately ??the .pdata section
                // is needed for x64 SEH exception dispatch during the debug
                // loop.  Mirrors Pascal TMInit lines 296-303.
                // (Run in both modes ??post-attach needs it too.)
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
                                    "PE header anti-dump fix applied: section 2 name byte 'i' ??'p'"
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
                // Themida checks .text page protection during init ??any non-
                // PAGE_EXECUTE_READ protection is detected and causes 0xDEADC0DE.
                // Guard-path policy comes from SelectedPacker::on_event (Slice 3b / R4-A1):
                // request_text_poll vs request_close_handle_chain. Host still
                // owns PEB/ScyllaHide/HW BP install; PEB + ScyllaHide do NOT
                // change .text protection so they remain safe here.
                if plugin_ctx.request_text_poll {
                    ls.text_polling = true;
                    // poll_start is set on first timeout, not here ??                    // LoadDll events can take minutes before Themida
                    // starts .text decryption
                    log::log(
                        LogType::Info,
                        "PackerPlugin: text-poll path ??deferring guard to .text-stable poll (30s idle timeout)",
                    );
                } else if plugin_ctx.request_close_handle_chain {
                    // Non-.text section 0: CloseHandle ??.text write ??                    // VirtualAlloc ??guard chain (handled by HW BP handler)
                    log::log(LogType::Info, "PackerPlugin: CloseHandle HW BP chain path");
                }

                // NtProtectVirtualMemory BP disabled ??it fires during Themida
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
            // LOAD_DLL ??close file handle
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

                // CloseHandle BP only when plugin allows (CloseHandle chain path).
                // refresh_loop_policy sets allow_close_handle_bp; do not install
                // during text-poll or after guard/OEP.
                refresh_plugin_loop_policy(&mut packer, &mut plugin_ctx, &ls);
                if plugin_ctx.allow_close_handle_bp && !ls.close_handle_bp_set {
                    let close_handle_addr = dbg.apis.as_ref().map(|a| a.close_handle);
                    if let Some(addr) = close_handle_addr {
                        match dbg.set_hw_breakpoint(0, addr, HwbpType::Execute) {
                            Ok(()) => {
                                debug!("CloseHandle HW breakpoint set (slot 0) [plugin path]");
                                info!(
                                    close_handle = %format!("{:#x}", addr),
                                    "CloseHandle HW breakpoint set (slot 0) [plugin path]",
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
            // CREATE_THREAD ??store handle
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
            // EXIT_THREAD ??remove handle
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
            // BREAKPOINT ??CloseHandle / VirtualAlloc / .text+0x1000
            // ---------------------------------------------------------------
            DebugEvent::Breakpoint { thread_id, address } => {
                debug!(addr = %format!("{address:#x}"), "Breakpoint hit");

                // .NET target special: if this is the _CorExeMain HW BP
                // (slot 3), dump raw memory and exit the debug loop.
                if is_dotnet {
                    if let Some(bp_addr) = dbg.hw_breakpoint_addr(3) {
                        if bp_addr == address {
                            info!(addr = %format!("{address:#x}"), ".NET _CorExeMain hit ??dumping process memory");
                            dbg.clear_hw_breakpoint(3)?;
                            dotnet_dump_and_dump_output(
                                &mut dbg,
                                image_base_usize,
                                &output_path,
                                input,
                            )?;
                            dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                            break;
                        }
                    }
                }

                // Check for NtProtectVirtualMemory BP (slot 1) ??guard protector.
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
                                            "NtProtectVirtualMemory on .text ??forcing PAGE_NOACCESS"
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
                                ctx.Dr6 = 0; // clear ??prevent re-fire
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
                ctx.Dr6 = 0; // clear ??prevent re-fire
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
            // ACCESS_VIOLATION ??process_guarded_access
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
                        ls.oep_provenance = OepProvenance::runtime_rip(
                            exception_addr,
                            format!("re-guard AV captured runtime OEP RIP: {exception_addr:#x}"),
                        );
                        ls.oep_found_via_scanning = false;
                        // Remove guard
                        let text_size = text_end - text_start;
                        let _ = mida_packers_themida::remove_code_section_guard(
                            h_process, text_start, text_size,
                        );
                        // Continue to IAT phase ??set RIP to OEP and let program run
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
                    AvAction::Break => {
                        // 3b-5: complete vs skip IAT milestone, then leave.
                        note_plugin_av_break(&mut packer, &mut plugin_ctx, &ls, dbg.image_base());
                        break;
                    }
                }
            }
            // ---------------------------------------------------------------
            // SINGLE_STEP ??may be real single-step or hardware breakpoint
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

                    // After handling the trace step, check if the slot walk finished.
                    // Product-complete is stricter than current_slot>=total (audit P1).
                    if let Some(ref t) = ls.iat_trace {
                        if t.current_slot >= t.total_slots {
                            if t.product_complete() {
                                note_plugin_iat_complete(&mut packer, &mut plugin_ctx);
                                info!(
                                    "IAT tracing product-complete ??exiting debug loop (resolved={})",
                                    t.resolved_count
                                );
                            } else {
                                info!(
                                    "IAT tracing finished WITHOUT product-complete (resolved={} failed={} skipped={} aborted={:?}) ??exiting loop, not marking complete",
                                    t.resolved_count,
                                    t.failed_count,
                                    t.skip_count,
                                    t.abort_reason
                                );
                            }
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
                    "SingleStep at known HW-BP address ??treating as CloseHandle hit"
                );

                log::log(
                    LogType::Info,
                    &format!("SINGLE STEP at {address:#x} ??checking NtProtectVirtualMemory"),
                );

                // Check for NtProtectVirtualMemory BP (slot 1) ??guard protector.
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
                                        "NtProtectVirtualMemory on .text ??forcing PAGE_NOACCESS"
                                    );
                                    let mut ctx2 = ctx;
                                    ctx2.R9 = 0x01; // PAGE_NOACCESS
                                                    // Merge debug registers ??must propagate errors
                                                    // (if let Ok silently skips DR clearing on ERROR_PARTIAL_COPY,
                                                    // causing the BP to re-fire infinitely)
                                    let dbg_ctx = dbg.get_thread_context_dbg(thread_id)?;
                                    ctx2.Dr0 = dbg_ctx.Dr0;
                                    ctx2.Dr1 = dbg_ctx.Dr1;
                                    ctx2.Dr2 = dbg_ctx.Dr2;
                                    ctx2.Dr3 = dbg_ctx.Dr3;
                                    ctx2.Dr6 = 0; // clear ??prevent re-fire
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
                        // Not targeting .text ??just set RF and continue
                        let mut ctx = dbg.get_thread_context_control(thread_id)?;
                        if let Ok(dbg_ctx) = dbg.get_thread_context_dbg(thread_id) {
                            ctx.Dr0 = dbg_ctx.Dr0;
                            ctx.Dr1 = dbg_ctx.Dr1;
                            ctx.Dr2 = dbg_ctx.Dr2;
                            ctx.Dr3 = dbg_ctx.Dr3;
                            ctx.Dr6 = 0; // clear ??prevent re-fire
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
                        "SINGLE STEP at {address:#x} ??handle_hw_breakpoint about to be called"
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
                    "handle_hw_breakpoint returned OK ??about to continue_event",
                );
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
                log::log(LogType::Info, "continue_event returned OK");
            }

            // ---------------------------------------------------------------
            // EXIT_PROCESS ??target exited (unexpected before dump)
            // ---------------------------------------------------------------
            DebugEvent::ExitProcess { exit_code } => {
                // Plugin consult already set process_exited + phase Done.
                ls.process_exited = true;
                debug_assert!(plugin_ctx.process_exited);
                debug_assert_eq!(plugin_ctx.phase, UnpackPhase::Done);
                if ls.oep.is_some() {
                    info!(
                        exit_code,
                        "Target exited after OEP found ??proceeding to dump"
                    );
                } else {
                    warn!(exit_code, "Target process exited before unpack completed");
                }
                // ExitProcess is abstracted without a TID; the engine retains
                // the raw pending identity for ContinueDebugEvent.
                dbg.continue_pending_event(ContinueStatus::Continue)?;
                break;
            }

            // ---------------------------------------------------------------
            // Other events ??continue
            // ---------------------------------------------------------------
            DebugEvent::UnloadDll {
                thread_id,
                base_address: _,
            } => {
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }

            DebugEvent::Other { thread_id } => {
                debug!(thread_id, "Other debug event ??continuing");
                dbg.continue_event(thread_id, ContinueStatus::Continue)?;
            }
        }

        // Slice 3b-2: after handlers, sync guard/OEP/IAT milestones into plugin.
        // Skipped when a match arm `break`s; post-loop sync covers that case.
        sync_plugin_milestones(&mut packer, &mut plugin_ctx, &ls, dbg.image_base());
    }

    // Final milestone sync (covers break paths that skipped end-of-iteration).
    sync_plugin_milestones(&mut packer, &mut plugin_ctx, &ls, dbg.image_base());
    // 3b-6: dump-enter via shared helper (also used by post-attach).
    let post_loop_advice = if ls.oep.is_some() || plugin_ctx.oep_rva.is_some() {
        enter_dump_phase(&mut packer, &mut plugin_ctx, "PackerPlugin dump_advice")
    } else {
        packer.dump_advice(&plugin_ctx)
    };

    // ---- phases B/C/D: IAT repair, post-processing, dump ----
    // If process already exited during AV-handler IAT wait, still dump.
    if ls.process_exited {
        // process_exited may already be set from ExitProcess; also set when
        // AV handler skipped v3-trace after ExitProcess during IAT wait.
    }
    // Propagate exit from AV handler path (storm escape + ExitProcess in wait).
    // The AV handler cannot mutate LoopState.process_exited after return, so
    // re-detect: if OEP was accepted via unrelated_av storm and main thread is
    // gone, fix_iat_v3 will hang ??use process_exited flag set on ExitProcess.
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
        ls.process_exited || plugin_ctx.skip_v3_iat_trace,
        packer.uses_oreans_iat_trace(),
        packer.family_id(),
        None,
        oep_policy,
        container_restore,
        profile,
        pure_rebuild,
        capture_policy,
        &early_section_snapshots,
        input,
        &output_path,
        plugin_ctx.oep_rva,
        &plugin_ctx.oep_provenance,
        post_loop_advice,
    )?;

    // P6.3-D: after a successful gated run, produce the evidence bundle
    // from the attested single-use context (seven members, atomic).
    if let Some(ctx) = evidence_ctx.take() {
        crate::runner_preflight::complete_run_evidence(ctx, &output_path)
            .map_err(|e| anyhow!("evidence bundle assembly failed after a gated run: {e:#}"))?;
    }

    log::log(LogType::Good, "Done.");
    Ok(())
}

// Early post-attach snapshots live in `early_snapshots`.
// Post-loop phases B/C/D live in `post_loop` (`run_post_loop_phases`).
// Family select lives in `plugin_host` (`dual_select_packer` / `select_packer_family`).
