//! Post-attach fast path (no debug port): observe .text, freeze, dump.
//!
//! Extracted from `mod.rs` (P1 host thin split / unattended engineering).
//! Used when section 0 is plain `.text` and the target is not .NET — create
//! without DEBUG_ONLY_THIS_PROCESS, capture early snapshots, poll until
//! decrypted .text execution, then hand off to [`run_post_loop_phases`].
//!
//! Shared `ThemidaState` host remains; this is not an independent GTO pipeline.

use std::path::Path;

use anyhow::anyhow;
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

use crate::log::{self, LogType};
use mida_core::{DebuggerCore, PackerPlugin, PluginCtx};
use mida_packers_themida::ThemidaState;
use mida_pe::{ContainerRestoreMode, DumpProfile, EarlySectionSnapshot, OepPolicy, PeHeader};

use super::early_snapshots::{
    log_snapshot_summary, merge_reinitializable_data_state, refresh_early_snapshots_after_loader,
    update_pre_text_snapshots,
};
use super::plugin_host::{enter_dump_phase, SelectedPacker};
use super::post_loop::run_post_loop_phases;
use super::session::ProcessSession;

/// Post-attach observation + freeze + post-loop dump.
///
/// Caller has already created the process, captured early snapshots, resumed
/// the main thread, and applied plugin session defaults.
pub(super) fn run_post_attach_path(
    mut dbg: &mut ProcessSession,
    mut state: &mut ThemidaState,
    mut pe: &mut PeHeader,
    mut packer: &mut SelectedPacker,
    mut plugin_ctx: &mut PluginCtx,
    mut early_section_snapshots: &mut Vec<EarlySectionSnapshot>,
    is_dotnet: bool,
    is_64bit: bool,
    do_data_sections: bool,
    shrink: bool,
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    pure_rebuild: bool,
    capture_policy: mida_pe::DumpCapturePolicy,
    input: &Path,
    output_path: &Path,
) -> Result<(), anyhow::Error> {
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

    let mut loop_count = 0;

    loop {
        loop_count += 1;
        if loop_count % 10 == 0 {
            eprintln!("[TRACE] OEP observation loop iteration {}", loop_count);
        }

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
            if loop_count == 1 {
                eprintln!("[TRACE] Checking IAT resolution");
            }
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
        if loop_count <= 3 {
            eprintln!("[TRACE] SuspendThread returned: {}", previous);
        }

        if previous != u32::MAX {
            if let Ok(ctx) = dbg.get_thread_context_control(main_tid) {
                let rip = ctx.Rip as usize;

                if loop_count <= 3 {
                    eprintln!(
                        "[TRACE] RIP=0x{:X}, text_start=0x{:X}, text_end=0x{:X}, in_range={}",
                        rip,
                        text_start,
                        text_end,
                        rip >= text_start && rip < text_end
                    );
                }

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

                        // FINAL PUSH: Try 750ms (between 500ms and 1000ms)
                        log::log(LogType::Info, "FINAL PUSH: Waiting 1000ms...");
                        let _ = unsafe { ResumeThread(h_thread) };
                        std::thread::sleep(std::time::Duration::from_millis(1000));

                        break;
                    }
                } else {
                    update_pre_text_snapshots(&dbg, &mut early_section_snapshots, rip)?;
                }
            }
            let _ = unsafe { ResumeThread(h_thread) };
        }

        std::thread::sleep(std::time::Duration::from_millis(1000));
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
            dbg as &dyn DebuggerCore,
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

    // Slice 3b-2/3b-6: OEP + dump phase via plugin_host (no Win32).
    plugin_ctx.ensure_runtime_base(image_base_usize as u64);
    packer.note_oep_accepted(
        &mut plugin_ctx,
        oep_addr as u64,
        frozen_rip.is_none(), // scan / PE-EP when RIP was outside .text
    );
    let post_attach_advice =
        enter_dump_phase(&mut packer, &mut plugin_ctx, "PackerPlugin dump_advice (post-attach)");

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
        true,  // post-attach mode
        false, // process still attached
        packer.uses_oreans_iat_trace(),
        packer.family_id(),
        oep_policy,
        container_restore,
        profile,
        pure_rebuild,
        capture_policy,
        &early_section_snapshots,
        input,
        &output_path,
        plugin_ctx.oep_rva,
        post_attach_advice,
    )?;

    log::log(LogType::Good, "Done.");
    return Ok(());
}
