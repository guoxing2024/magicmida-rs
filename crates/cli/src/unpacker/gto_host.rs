//! Independent AHK/GTO host path (operator decision D4, 2026-07-24).
//!
//! **Does not construct [`ThemidaState`] or call `init_pe_details`.**
//! Layout comes from [`PeHeader`] only. Oreans V3 IAT / Themida shrink /
//! ScyllaHide post-attach are out of this path.
//!
//! Dump experimental stages still require
//! [`DumpProfile::AhkGtoExperimental`]; identify alone does not enable them.
//!
//! Exit Ok means a candidate PE was written, not R0B or behavioral Accepted.

use std::path::Path;

use anyhow::{anyhow, Context};
use tracing::{info, warn};
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

use crate::log::{self, LogType};
use mida_core::{
    CreateProcessOptions, DebuggerCore, PackerPlugin, PluginCtx, PreferredBase,
};
use mida_pe::{
    ContainerRestoreMode, DumpOptions, DumpProfile, OepPolicy, PeHeader,
};

use super::early_snapshots::{
    capture_early_section_snapshots, log_snapshot_summary, merge_reinitializable_data_state,
    refresh_early_snapshots_after_loader, update_pre_text_snapshots,
};
use super::helpers::{resolve_api_addrs, resolve_output_path};
use super::plugin_host::{enter_dump_phase, SelectedPacker};
use super::session::ProcessSession;

/// Run the AHK/GTO-only unpack host (no `ThemidaState`).
pub(super) fn run_gto_host(
    input: &Path,
    output: Option<&Path>,
    do_data_sections: bool,
    shrink: bool,
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    pure_rebuild: bool,
    mut packer: SelectedPacker,
) -> Result<(), anyhow::Error> {
    info!("=== GTO HOST START (independent; no ThemidaState) ===");
    info!("Input: {}", input.display());
    info!(?oep_policy, ?container_restore, ?profile, pure_rebuild, "GTO host policy");

    if !matches!(profile, DumpProfile::AhkGtoExperimental) {
        warn!(
            "GTO independent host running without ahk-gto-experimental profile — \
             heap/container dump stages stay disabled"
        );
    }

    let output_path = resolve_output_path(input, output);
    info!("Output: {}", output_path.display());

    log::log(LogType::Info, &format!("GTO host loading: {}", input.display()));
    let mut pe =
        PeHeader::from_file(input).map_err(|e| anyhow!("GTO host PE parse failed: {e}"))?;
    let is_64bit = pe.is_64bit;
    if !is_64bit {
        return Err(anyhow!(
            "GTO independent host currently supports PE32+ only (got PE32)"
        ));
    }

    // .NET COM descriptor — GTO research samples are native; refuse managed here.
    const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;
    let is_dotnet = pe.nt_headers.optional_header.data_directory
        [IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        .virtual_address
        != 0;
    if is_dotnet {
        return Err(anyhow!(
            "GTO independent host does not unpack managed (.NET) images"
        ));
    }

    let section0_is_plain_text = pe
        .sections
        .first()
        .is_some_and(|s| s.name == ".text");
    if !section0_is_plain_text {
        return Err(anyhow!(
            "GTO independent host requires section 0 named .text (post-attach path); got {:?}",
            pe.sections.first().map(|s| s.name.as_str())
        ));
    }

    let opts = CreateProcessOptions {
        executable: input.to_path_buf(),
        command_line: None,
        is_dll: input
            .extension()
            .map(|e| e.eq_ignore_ascii_case("dll"))
            .unwrap_or(false),
        suspended: false,
        post_attach: true,
    };

    let mut dbg = ProcessSession::new(
        mida_core::WindowsDebugger::new(&opts).context("GTO host: create process failed")?,
    );
    log::log(
        LogType::Info,
        &format!("GTO host process created (PID: {})", dbg.pid()),
    );

    let mut early_section_snapshots = capture_early_section_snapshots(&dbg, &pe, &[".data"])?;
    dbg.resume_post_attach_main_thread()
        .context("GTO host: resume post-attach main thread")?;

    let apis = resolve_api_addrs()?;
    dbg.apis = Some(apis);
    info!("GTO host: post-attach no debug port — observe .text then dump");

    let mut plugin_ctx = PluginCtx {
        preferred_base: Some(PreferredBase(pe.image_base)),
        is_dotnet: false,
        section0_is_plain_text: true,
        ..PluginCtx::default()
    };
    packer.apply_session_defaults(&mut plugin_ctx);

    let image_base_usize = dbg.image_base() as usize;
    let text_sec = pe
        .sections
        .first()
        .ok_or_else(|| anyhow!("GTO host: PE has no sections"))?;
    let text_start = image_base_usize + text_sec.virtual_address as usize;
    let text_rva = text_sec.virtual_address;
    let text_vsize = text_sec.virtual_size;
    let text_end = text_start.saturating_add(text_vsize as usize);

    let rdata_sec = pe
        .sections
        .iter()
        .find(|s| s.name == ".rdata")
        .or_else(|| pe.sections.get(1));
    let iat_rva = rdata_sec.map(|s| s.virtual_address).unwrap_or(0xFD000);
    let iat_addr = image_base_usize + iat_rva as usize;
    // dump_process caps a single IAT read (max 40960). Stay under that.
    const MAX_IAT_READ: u32 = 40_960;
    let iat_size = rdata_sec
        .map(|s| s.virtual_size.min(MAX_IAT_READ).min(0x8000))
        .unwrap_or(0x1000) as usize;

    log::log(
        LogType::Info,
        &format!(
            "GTO host: polling IAT at {iat_addr:#x} (RVA {iat_rva:#x}) size={iat_size:#x}"
        ),
    );

    let poll_start = std::time::Instant::now();
    let max_wait = std::time::Duration::from_secs(
        plugin_ctx
            .text_poll_idle_timeout_secs
            .max(60),
    );
    let main_tid = dbg.main_thread_id();
    let h_thread = dbg
        .thread_handle(main_tid)
        .map_err(|e| anyhow!("GTO host thread_handle: {e}"))?;
    let mut frozen_rip: Option<usize> = None;
    let mut iat_resolved_logged = false;
    let mut loop_count = 0u32;

    loop {
        loop_count = loop_count.saturating_add(1);
        if poll_start.elapsed() > max_wait {
            log::log(
                LogType::Warn,
                "GTO host: OEP observation timeout — proceeding with scan/fallback",
            );
            break;
        }

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
                log::log(
                    LogType::Warn,
                    &format!("GTO host: GetExitCodeProcess failed: {e} — assuming alive"),
                );
                true
            }
        };
        if !alive {
            return Err(anyhow!(
                "GTO host: target exited during observation (exit_code={exit_code:#x})"
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
                            "GTO host: IAT first slot = {val:#x} (after {} ms)",
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
                        .is_ok_and(|read| read >= 8 && code.iter().any(|&b| b != 0));
                    if decrypted {
                        frozen_rip = Some(rip);
                        log::log(
                            LogType::Good,
                            &format!(
                                "GTO host: first decrypted .text at {rip:#x} after {} ms",
                                poll_start.elapsed().as_millis()
                            ),
                        );
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

        // Tighter poll than Oreans post_attach default — GTO decrypt window is short.
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    if frozen_rip.is_none() {
        let previous = unsafe { SuspendThread(h_thread) };
        if previous == u32::MAX {
            return Err(anyhow!("GTO host: failed to freeze primary thread"));
        }
    }

    refresh_early_snapshots_after_loader(&dbg, &mut early_section_snapshots)?;
    merge_reinitializable_data_state(
        &dbg,
        &mut early_section_snapshots,
        pe.size_of_image() as usize,
    )?;
    log_snapshot_summary(&early_section_snapshots, "GTO host pre-.text baseline");

    let oep_addr = if let Some(rip) = frozen_rip {
        log::log(
            LogType::Good,
            &format!("GTO host: OEP from RIP {rip:#x}"),
        );
        rip
    } else {
        // Byte-pattern OEP scan on live .text (shared utility; not ThemidaState).
        match mida_packers_themida::find_real_oep_by_scanning(
            &dbg as &dyn DebuggerCore,
            image_base_usize,
            text_rva,
            text_vsize,
        ) {
            Ok(Some(addr)) => {
                log::log(
                    LogType::Good,
                    &format!("GTO host: OEP via .text scan {addr:#x}"),
                );
                addr
            }
            Ok(None) => {
                let pe_ep = image_base_usize + pe.entry_point as usize;
                log::log(
                    LogType::Warn,
                    &format!("GTO host: OEP scan empty — PE EP {pe_ep:#x}"),
                );
                pe_ep
            }
            Err(e) => {
                let pe_ep = image_base_usize + pe.entry_point as usize;
                log::log(
                    LogType::Warn,
                    &format!("GTO host: OEP scan error {e:#} — PE EP {pe_ep:#x}"),
                );
                pe_ep
            }
        }
    };

    // Apply oep_policy only for Fixed RVA; Captured/Crt keep frozen/PE-EP above.
    let oep_addr = match oep_policy {
        OepPolicy::Captured => oep_addr,
        OepPolicy::Crt => {
            warn!("GTO host: --oep=crt ignored on independent host; using captured/fallback");
            oep_addr
        }
        OepPolicy::Fixed(rva) => image_base_usize + rva as usize,
    };

    plugin_ctx.ensure_runtime_base(image_base_usize as u64);
    packer.note_oep_accepted(&mut plugin_ctx, oep_addr as u64, frozen_rip.is_none());
    let dump_advice =
        enter_dump_phase(&mut packer, &mut plugin_ctx, "PackerPlugin dump_advice (GTO host)");
    if let Some(ref advice) = dump_advice {
        info!(
            prefer_pure = advice.prefer_pure_rebuild,
            note = advice.note,
            "GTO host dump_advice"
        );
    }

    let runtime_base = mida_core::RuntimeBase(dbg.image_base());
    let entry_rva = mida_core::Va(oep_addr as u64)
        .to_rva(runtime_base)
        .context("GTO host: OEP not in runtime image")?;
    let entry_point_u32 = entry_rva.get();

    log::log(
        LogType::Info,
        &format!(
            "GTO host dumping to {} (entry_rva={entry_point_u32:#x}, pure={pure_rebuild})",
            output_path.display()
        ),
    );

    let dump_opts = DumpOptions {
        image_base: dbg.image_base(),
        entry_point: entry_point_u32,
        fix_imports: true,
        create_data_sections: do_data_sections,
        shrink,
        output_path: output_path.clone(),
        executable_path: Some(input.to_path_buf()),
        iat_location: Some((iat_addr, iat_size)),
        additional_iat_locations: Vec::new(),
        early_section_snapshots: early_section_snapshots.clone(),
        container_restore,
        profile,
        security_cookie_rva: None,
        security_cookie_complement_rva: None,
        pure_rebuild,
    };

    mida_pe::dump_process(&mut dbg, &dump_opts).map_err(|e| anyhow!("GTO host dump failed: {e}"))?;

    let mut structure_ep_ok = false;
    if let Ok(out_pe) = PeHeader::from_file(&output_path) {
        let ep = out_pe.entry_point;
        let tls = out_pe.nt_headers.optional_header.data_directory[9];
        structure_ep_ok = out_pe.sections.iter().any(|s| {
            (s.characteristics & 0x2000_0000) != 0
                && ep >= s.virtual_address
                && ep < s.virtual_address.saturating_add(s.virtual_size)
        });
        log::log(
            LogType::Info,
            &format!(
                "Structure gate: EP={ep:#x} exec_ok={structure_ep_ok} TLS={:#x}/{:#x} (hint only; not R0B)",
                tls.virtual_address, tls.size
            ),
        );
    }

    log::log(
        LogType::Good,
        &format!(
            "GTO host candidate written: {} (independent host; R0B/behavior external; structure_ep_ok={structure_ep_ok})",
            output_path.display()
        ),
    );
    log::log(
        LogType::Info,
        &format!(
            "Unpacked: {} (candidate; acceptance external)",
            output_path.display()
        ),
    );
    log::log(LogType::Good, "GTO host Done.");
    Ok(())
}
