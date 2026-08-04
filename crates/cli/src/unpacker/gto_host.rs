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
use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowThreadProcessId,
};

use crate::log::{self, LogType};
use mida_core::{CreateProcessOptions, DebuggerCore, PackerPlugin, PluginCtx, PreferredBase};
use mida_pe::{ContainerRestoreMode, DumpOptions, DumpProfile, OepPolicy, PeHeader};

use super::early_snapshots::{
    capture_early_section_snapshots, log_snapshot_summary, merge_reinitializable_data_state,
    refresh_early_snapshots_after_loader, update_pre_text_snapshots,
};
use super::helpers::{resolve_api_addrs, resolve_output_path};
use super::plugin_host::{enter_dump_phase, SelectedPacker};
use super::session::ProcessSession;

/// Product login window class for this GTO research sample (protected baseline).
const GTO_UI_WINDOW_CLASS: &str = "NewClassName";
/// After the product window appears, wait this long so IAT wrappers / script
/// settle, then dump (R-GTO-UI). Protected shows the window ~1s after start.
const GTO_UI_POST_WINDOW_SETTLE: std::time::Duration = std::time::Duration::from_secs(3);
/// Route H / no-bypass: extra settle after NewClassName so gscript/heap roots
/// include post-GUI state (H1: early dump incomplete for cold UI).
const GTO_NO_BYPASS_UI_POST_WINDOW_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);

/// True when `pid` owns a top-level window with the given class name.
fn process_has_window_class(pid: u32, class_name: &str) -> bool {
    struct EnumState {
        pid: u32,
        want: Vec<u16>,
        found: bool,
    }
    let mut want: Vec<u16> = class_name.encode_utf16().collect();
    want.push(0);
    let mut state = EnumState {
        pid,
        want,
        found: false,
    };
    unsafe extern "system" fn enum_cb(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = &mut *(lparam.0 as *mut EnumState);
        if state.found {
            return BOOL(0);
        }
        let mut win_pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut win_pid));
        if win_pid != state.pid {
            return BOOL(1);
        }
        let mut buf = [0u16; 256];
        let n = GetClassNameW(hwnd, &mut buf);
        if n > 0 {
            let got = &buf[..n as usize];
            let want = &state.want[..state.want.len().saturating_sub(1)];
            if got == want {
                state.found = true;
                return BOOL(0);
            }
        }
        BOOL(1)
    }
    let _ = unsafe { EnumWindows(Some(enum_cb), LPARAM(&mut state as *mut _ as isize)) };
    state.found
}

/// Run the AHK/GTO-only unpack host (no `ThemidaState`).
///
/// The default build fails closed before the first statement, so everything
/// after the feature gate is unreachable unless `gto-product-recovery` is on.
#[allow(unreachable_code)]
pub(super) fn run_gto_host(
    input: &Path,
    output: Option<&Path>,
    do_data_sections: bool,
    shrink: bool,
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    pure_rebuild: bool,
    // CLI / case-manifest capture policy (may be empty → plugin defaults).
    cli_capture_policy: mida_pe::DumpCapturePolicy,
    #[allow(unused_mut)] // mutable only under the gto-product-recovery feature
    mut packer: SelectedPacker,
) -> Result<(), anyhow::Error> {
    #[cfg(not(feature = "gto-product-recovery"))]
    {
        let _ = (
            input,
            output,
            do_data_sections,
            shrink,
            oep_policy,
            container_restore,
            profile,
            pure_rebuild,
            cli_capture_policy,
            packer,
        );
        return Err(anyhow!(
            "GTO product-recovery route is disabled in the default build; \
             rebuild mida-cli with --features gto-product-recovery to opt in"
        ));
    }

    info!("=== GTO HOST START (independent; no ThemidaState) ===");
    info!("Input: {}", input.display());
    info!(
        ?oep_policy,
        ?container_restore,
        ?profile,
        pure_rebuild,
        capture_source = cli_capture_policy.source_label(),
        "GTO host policy"
    );

    if !matches!(profile, DumpProfile::AhkGtoExperimental) {
        warn!(
            "GTO independent host running without ahk-gto-experimental profile — \
             heap/container dump stages stay disabled"
        );
    }

    let output_path = resolve_output_path(input, output);
    info!("Output: {}", output_path.display());

    log::log(
        LogType::Info,
        &format!("GTO host loading: {}", input.display()),
    );
    let pe = PeHeader::from_file(input).map_err(|e| anyhow!("GTO host PE parse failed: {e}"))?;
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

    let section0_is_plain_text = pe.sections.first().is_some_and(|s| s.name == ".text");
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

    // GTO real OEP often lands in `.boot` (or the PE EP section), not only section0
    // `.text`. Watch every executable range so observation does not wait until exit.
    let mut oep_watch: Vec<(usize, usize, String)> = Vec::new();
    for s in &pe.sections {
        let exec = (s.characteristics & 0x2000_0000) != 0;
        let named_boot =
            s.name.eq_ignore_ascii_case(".boot") || s.name.eq_ignore_ascii_case(".text");
        let holds_ep = pe.entry_point >= s.virtual_address
            && pe.entry_point < s.virtual_address.saturating_add(s.virtual_size.max(1));
        if exec || named_boot || holds_ep {
            let start = image_base_usize + s.virtual_address as usize;
            let end = start.saturating_add(s.virtual_size.max(1) as usize);
            oep_watch.push((start, end, s.name.clone()));
        }
    }
    if oep_watch.is_empty() {
        oep_watch.push((text_start, text_end, text_sec.name.clone()));
    }
    log::log(
        LogType::Info,
        &format!(
            "GTO host: OEP watch ranges={} (section0 .text + exec/boot/EP)",
            oep_watch.len()
        ),
    );

    let rdata_sec = pe
        .sections
        .iter()
        .find(|s| s.name == ".rdata")
        .or_else(|| pe.sections.get(1));
    let iat_rva = rdata_sec.map(|s| s.virtual_address).unwrap_or(0xFD000);
    let iat_addr = image_base_usize + iat_rva as usize;
    // Initial poll window: just enough to detect first-slot resolve.
    // After IAT settles we re-measure a tight multi-block span (r4c used
    // ~0x11e0 / 572 slots). Dumping with full .rdata (0x8000) made rebuild
    // see 3876 zero-padded slots and fall back to incomplete original ILT.
    const MAX_IAT_READ: usize = 40_960;
    let mut iat_size: usize = 0x2000; // 1 page of slots for poll; refined later

    log::log(
        LogType::Info,
        &format!(
            "GTO host: polling IAT at {iat_addr:#x} (RVA {iat_rva:#x}) size={iat_size:#x} (tightened post-resolve)"
        ),
    );

    let poll_start = std::time::Instant::now();
    // Cap observation: GTO targets often self-exit after a short GUI/init window.
    // Prefer dump-before-exit over waiting the full Oreans idle timeout.
    // r4c green: full 60s post-attach observation. Do not let a lower
    // text_poll_idle_timeout_secs shrink this (plugin default ~30s left us
    // dumping at IAT+28s with smaller .boot / stub_size than r4c).
    // Route H / no-bypass: hold the full upper cap so UI-seen has room before
    // any no-UI fallback (H1 rejects pure IAT+10s early dump).
    let no_bypass = std::env::var("MIDA_GTO_NO_BYPASS").ok().as_deref() == Some("1");
    let max_wait = if no_bypass {
        std::time::Duration::from_secs(90)
    } else {
        std::time::Duration::from_secs(plugin_ctx.text_poll_idle_timeout_secs.max(60).min(90))
    };
    if no_bypass {
        log::log(
            LogType::Info,
            "GTO host: Route H no-bypass timing — prefer UI-seen settle; \
             no IAT+10s early dump; dump-before-exit only if process dies after IAT",
        );
    }
    let main_tid = dbg.main_thread_id();
    let h_thread = dbg
        .thread_handle(main_tid)
        .map_err(|e| anyhow!("GTO host thread_handle: {e}"))?;
    // Always dump via .text scan after settle (r4c green); live RIP freeze disabled.
    let frozen_rip: Option<usize> = None;
    let mut observed_text_rips: Vec<usize> = Vec::new();
    let mut iat_resolved_at: Option<std::time::Instant> = None;
    let mut ui_seen_at: Option<std::time::Instant> = None;
    let mut loop_count = 0u32;
    // Route G: process may self-exit after IAT (exit 0) before UI/settle.
    // Prefer dump-before-exit over hard FATAL when IAT already resolved.
    let mut exited_after_iat = false;
    let target_pid = dbg.pid();

    // True when an IAT slot is a resolved external API pointer.
    // Reject image-local values (hint/name RVAs, packer trampolines) — those
    // caused early "resolved" and dumped mid-.KI3 before real IAT filled.
    // Green r4c path saw first slot = 0x7ff9… after ~1s.
    let iat_slot_looks_resolved = |val: usize, image_base: usize| -> bool {
        if val == 0 || val < 0x1_0000 {
            return false;
        }
        // Anything inside the main image is not a system import.
        if val >= image_base && val < image_base.saturating_add(0x1000_0000) {
            return false;
        }
        // Typical Win64 user-mode module range (kernel32/ntdll etc.; ASLR varies).
        val >= 0x7FF0_0000_0000 || (val >= 0x1800_0000 && val < 0x7FFF_FFFF_FFFF)
    };

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
            if iat_resolved_at.is_some() {
                // Route G R1: acquisition reliability — dump while the process
                // handle still allows VM reads instead of aborting with no PE.
                exited_after_iat = true;
                log::log(
                    LogType::Warn,
                    &format!(
                        "GTO host: target exited after IAT resolve (exit_code={exit_code:#x}, \
                         ui_seen={}, after {} ms) — dump-before-exit via .text scan \
                         (Route G acquisition reliability)",
                        ui_seen_at.is_some(),
                        poll_start.elapsed().as_millis()
                    ),
                );
                break;
            }
            return Err(anyhow!(
                "GTO host: target exited during observation before IAT resolve \
                 (exit_code={exit_code:#x}); frozen_rip={frozen_rip:?} — \
                 re-run with quieter host or pin last-good dump"
            ));
        }

        if iat_resolved_at.is_none() {
            let mut iat_val = [0u8; 8];
            if dbg.read_memory(iat_addr, &mut iat_val).is_ok() {
                let val = usize::from_le_bytes(iat_val);
                if iat_slot_looks_resolved(val, image_base_usize) {
                    iat_resolved_at = Some(std::time::Instant::now());
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

        // R-GTO-UI: dump shortly after product login window appears so heap
        // capture includes post-GUI gscript / title roots (not only IAT+60s).
        if iat_resolved_at.is_some() && ui_seen_at.is_none() {
            if process_has_window_class(target_pid, GTO_UI_WINDOW_CLASS) {
                ui_seen_at = Some(std::time::Instant::now());
                log::log(
                    LogType::Good,
                    &format!(
                        "GTO host: product window class {GTO_UI_WINDOW_CLASS} seen (after {} ms) — short settle then dump",
                        poll_start.elapsed().as_millis()
                    ),
                );
            }
        }
        if let Some(ui_t) = ui_seen_at {
            let ui_settle = if no_bypass {
                GTO_NO_BYPASS_UI_POST_WINDOW_SETTLE
            } else {
                GTO_UI_POST_WINDOW_SETTLE
            };
            if ui_t.elapsed() >= ui_settle {
                log::log(
                    LogType::Info,
                    &format!(
                        "GTO host: UI settle {} ms complete (need {} ms, no_bypass={}) — dump via .text scan",
                        ui_t.elapsed().as_millis(),
                        ui_settle.as_millis(),
                        no_bypass
                    ),
                );
                break;
            }
        }

        // After IAT resolves without UI:
        // - Default/bypass: hold most of max_wait (r4c wrapper quality).
        // - Route H / no-bypass: prefer UI for full max_wait, but take a
        //   **last-resort alive dump at IAT+9s** if UI never appears — hosts
        //   often self-exit ~12s post-IAT; dump-after-exit cannot RPM.
        //   Prefer UI when it appears before that deadline.
        if ui_seen_at.is_none() {
            if let Some(iat_t) = iat_resolved_at {
                let settle = if no_bypass {
                    // Last-resort alive window (before typical ~12s exit).
                    std::time::Duration::from_secs(9)
                } else {
                    max_wait.saturating_sub(std::time::Duration::from_secs(2))
                };
                if iat_t.elapsed() >= settle && frozen_rip.is_none() {
                    log::log(
                        LogType::Info,
                        &format!(
                            "GTO host: IAT+{} ms without UI/.text freeze — dump via .text scan \
                             (no_bypass={} settle_ms={} route_h_ui_prefer={} last_resort_alive={})",
                            iat_t.elapsed().as_millis(),
                            no_bypass,
                            settle.as_millis(),
                            no_bypass,
                            no_bypass
                        ),
                    );
                    break;
                }
            }
        }

        // Route H / no-bypass: suspend less often so the UI thread can paint
        // NewClassName before we freeze/dump (H1: thrashing may hide UI).
        let do_suspend = if no_bypass && iat_resolved_at.is_some() && ui_seen_at.is_none() {
            loop_count % 4 == 0
        } else {
            true
        };
        let previous = if do_suspend {
            unsafe { SuspendThread(h_thread) }
        } else {
            u32::MAX - 1 // skip suspend this tick; treat as "not suspended"
        };
        if do_suspend && previous != u32::MAX {
            if let Ok(ctx) = dbg.get_thread_context_control(main_tid) {
                let rip = ctx.Rip as usize;
                let in_watch = oep_watch
                    .iter()
                    .find(|(s, e, _)| rip >= *s && rip < *e)
                    .map(|(_, _, n)| n.as_str());
                if let Some(sec_name) = in_watch {
                    // r27 round 5: record .text RIPs to find the real OEP.
                    // The .text byte-scan finds WindowProc (0x70b0), not WinMain.
                    // Capture every distinct .text RIP so we can pick the real
                    // WinMain (the one that calls RegisterClass/CreateWindow).
                    if sec_name == ".text" {
                        let rva = rip - image_base_usize;
                        if !observed_text_rips.contains(&rva) {
                            observed_text_rips.push(rva);
                            if observed_text_rips.len() <= 40 {
                                log::log(
                                    LogType::Info,
                                    &format!(
                                        "GTO host: .text RIP #{} at {:#x} (rva {:#x}); iat_ok={}",
                                        observed_text_rips.len(),
                                        rip,
                                        rva,
                                        iat_resolved_at.is_some()
                                    ),
                                );
                            }
                        }
                    }
                    if loop_count % 50 == 1 {
                        log::log(
                            LogType::Info,
                            &format!(
                                "GTO host: observe only at {rip:#x} ({sec_name}); \
                                 iat_ok={} — dump after settle via .text scan",
                                iat_resolved_at.is_some()
                            ),
                        );
                    }
                } else if rip < text_start || rip >= text_end {
                    update_pre_text_snapshots(&dbg, &mut early_section_snapshots, rip)?;
                }
            }
            let _ = unsafe { ResumeThread(h_thread) };
        }

        // Slightly less aggressive than 50ms — SuspendThread thrashing can
        // destabilize short-lived GTO launchers. Route H no-bypass: longer
        // tick when not suspending so UI can appear.
        let tick_ms = if no_bypass && !do_suspend { 120 } else { 80 };
        std::thread::sleep(std::time::Duration::from_millis(tick_ms));
    }

    if frozen_rip.is_none() {
        let previous = unsafe { SuspendThread(h_thread) };
        if previous == u32::MAX {
            if exited_after_iat {
                // Process already gone; keep going — CreateProcess handle often
                // still permits ReadProcessMemory until we drop the session.
                log::log(
                    LogType::Warn,
                    "GTO host: primary thread freeze failed after post-IAT exit — \
                     continuing dump while process handle remains open",
                );
            } else {
                return Err(anyhow!("GTO host: failed to freeze primary thread"));
            }
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
        log::log(LogType::Good, &format!("GTO host: OEP from RIP {rip:#x}"));
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
    let dump_advice = enter_dump_phase(
        &mut packer,
        &mut plugin_ctx,
        "PackerPlugin dump_advice (GTO host)",
    );
    if let Some(ref advice) = dump_advice {
        info!(
            prefer_pure = advice.prefer_pure_rebuild,
            note = advice.note,
            has_capture_hint = advice.capture_policy.is_some(),
            "GTO host dump_advice"
        );
    }
    // Merge: CLI/case-manifest roots win; else plugin hint; then profile.
    // Experimental stages still gated by DumpProfile.
    let capture_policy = mida_pe::DumpCapturePolicy::resolve_with_plugin_hint(
        cli_capture_policy,
        dump_advice.as_ref().and_then(|a| a.capture_policy.as_ref()),
        profile,
    );
    info!(
        capture_source = capture_policy.source_label(),
        hot_roots = capture_policy.hot_root_rvas.len(),
        gscript = ?capture_policy.gscript_root().map(|r| format!("{r:#x}")),
        "GTO host resolved capture_policy"
    );

    let runtime_base = mida_core::RuntimeBase(dbg.image_base());
    let entry_rva = mida_core::Va(oep_addr as u64)
        .to_rva(runtime_base)
        .context("GTO host: OEP not in runtime image")?;
    let entry_point_u32 = entry_rva.get();

    // Tighten IAT window from live memory. Only count *external* API-looking
    // QWORDs (r4c: ~572 slots / 0x11e0). Counting any non-zero bloated the
    // window with .rdata constants → rebuild saw thousands of "empty" slots
    // and fell back to incomplete original ILT (load AV).
    {
        let scan_cap = rdata_sec
            .map(|s| s.virtual_size as usize)
            .unwrap_or(0x8000)
            .min(MAX_IAT_READ)
            .min(0x3000); // hard cap ~1.5k slots; real GTO IAT is far smaller
        let mut buf = vec![0u8; scan_cap];
        if let Ok(n) = dbg.read_memory(iat_addr, &mut buf) {
            let nslots = (n / 8).max(1);
            let mut first_api: Option<usize> = None;
            let mut last_api = 0usize;
            let mut miss_run = 0usize;
            for i in 0..nslots {
                let off = i * 8;
                if off + 8 > n {
                    break;
                }
                let val = usize::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0; 8]));
                // External user-mode module pointer (same bar as IAT resolved).
                let is_api = val >= 0x7FF0_0000_0000
                    || (val >= 0x1800_0000
                        && val < 0x7FFF_FFFF_FFFF
                        && !(val >= image_base_usize
                            && val < image_base_usize.saturating_add(0x1000_0000)));
                if is_api {
                    if first_api.is_none() {
                        first_api = Some(i);
                    }
                    last_api = i;
                    miss_run = 0;
                } else if first_api.is_some() {
                    miss_run = miss_run.saturating_add(1);
                    // Themida multi-block allows internal gaps; stop after a
                    // long non-API run past the last real slot (r4c ~64).
                    if miss_run >= 48 {
                        break;
                    }
                }
            }
            // r4c green: fixed multi-block size 0x11e0 (572 slots). Prefer that
            // exact window when last_api is in range; do not grow past it or
            // rebuild coverage drops and original-ILT fallback reappears.
            const R4C_IAT_SIZE: usize = 0x11e0;
            const R4C_IAT_SLOTS: usize = R4C_IAT_SIZE / 8;
            let slots = if first_api.is_some() {
                // Include through last API, but never larger than r4c span.
                last_api
                    .saturating_add(2)
                    .max(R4C_IAT_SLOTS.saturating_sub(16))
                    .min(nslots)
                    .min(R4C_IAT_SLOTS)
            } else {
                R4C_IAT_SLOTS
            };
            iat_size = (slots * 8).min(MAX_IAT_READ).max(0x400);
            // Prefer exact green size when live span is at least that large.
            if first_api.is_some() && last_api + 2 >= R4C_IAT_SLOTS.saturating_sub(32) {
                iat_size = R4C_IAT_SIZE;
            }
            log::log(
                LogType::Info,
                &format!(
                    "GTO host: IAT live span first_api={first_api:?} last_api={last_api} \
                     size={iat_size:#x} ({slots} slots)"
                ),
            );
        }
    }

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
        // From DumpAdvice.capture_policy (plugin) + profile resolve.
        capture_policy,
    };

    mida_pe::dump_process(&mut dbg, &dump_opts)
        .map_err(|e| anyhow!("GTO host dump failed: {e}"))?;

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
