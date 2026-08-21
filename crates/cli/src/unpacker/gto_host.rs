//! AHK/GTO post-attach observation stage (G1).
//!
//! Since G1, the GTO family no longer runs a full independent host: it shares
//! the main `unpack` flow in `mod.rs` (create-process, early section snapshots,
//! `ThemidaState` layout) and the post-attach / post-loop / dump skeleton with
//! Oreans. This module now contributes only the **GTO-specific observation
//! policy** (UI-window detection, multi-section OEP watch, IAT-resolved
//! heuristic, no-bypass timing) that `run_post_attach_path` selects by
//! `packer.family_id()`.
//!
//! Oreans V3 IAT trace / Themida shrink / ScyllaHide post-attach remain out of
//! the GTO policy. Dump experimental stages still require
//! [`DumpProfile::AhkGtoExperimental`]; identify alone does not enable them.
//!
//! Exit Ok means an observation + OEP decision was produced, not R0B or
//! behavioral Accepted. The dump itself is done by the shared
//! `run_post_loop_phases`.

use anyhow::anyhow;
use tracing::warn;
use windows::Win32::Foundation::{BOOL, HWND, LPARAM};
use windows::Win32::System::Threading::{ResumeThread, SuspendThread};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowThreadProcessId,
};

use crate::log::{self, LogType};
use mida_core::DebuggerCore;
use mida_pe::{DumpProfile, EarlySectionSnapshot, PeHeader};

use super::early_snapshots::update_pre_text_snapshots;
use super::plugin_host::IatLocationHint;
use super::session::ProcessSession;

/// Product login window class for this GTO research sample (protected baseline).
const GTO_UI_WINDOW_CLASS: &str = "NewClassName";
/// After the product window appears, wait this long so IAT wrappers / script
/// settle, then dump (R-GTO-UI). Protected shows the window ~1s after start.
const GTO_UI_POST_WINDOW_SETTLE: std::time::Duration = std::time::Duration::from_secs(3);
/// Route H / no-bypass: extra settle after NewClassName so gscript/heap roots
/// include post-GUI state (H1: early dump incomplete for cold UI).
const GTO_NO_BYPASS_UI_POST_WINDOW_SETTLE: std::time::Duration = std::time::Duration::from_secs(5);
const GTO_R4C_IAT_SIZE: usize = 0x11e0;
const GTO_MAX_IAT_READ: usize = 40_960;
const GTO_IAT_SCAN_CAP: usize = 0x3000;
const GTO_MIN_IAT_SIZE: usize = 0x400;

/// Outcome of the GTO observation stage: the recovered OEP candidate and
/// whether it came from a frozen RIP (always `None` today — GTO uses scan).
#[derive(Debug, Clone)]
pub(super) struct GtoObservation {
    pub oep_addr: usize,
    pub frozen_rip: Option<usize>,
    pub iat_override: Option<IatLocationHint>,
}

fn gto_iat_hint_from_live_span(
    address: usize,
    image_base: usize,
    bytes: &[u8],
) -> Option<IatLocationHint> {
    if address == 0 || bytes.len() < 8 {
        return None;
    }

    let slot_count = bytes.len() / 8;
    let mut first_api = None;
    let mut last_api = 0usize;
    let mut miss_run = 0usize;
    for slot in 0..slot_count {
        let offset = slot * 8;
        let value = u64::from_le_bytes(bytes[offset..offset + 8].try_into().ok()?) as usize;
        let is_api = value >= 0x7FF0_0000_0000
            || ((0x1800_0000..0x7FFF_FFFF_FFFF).contains(&value)
                && !(value >= image_base && value < image_base.saturating_add(0x1000_0000)));
        if is_api {
            if first_api.is_none() {
                first_api = Some(slot);
            }
            last_api = slot;
            miss_run = 0;
        } else if first_api.is_some() {
            miss_run = miss_run.saturating_add(1);
            if miss_run >= 48 {
                break;
            }
        }
    }

    first_api?;
    let r4c_slots = GTO_R4C_IAT_SIZE / 8;
    let slots = last_api
        .saturating_add(2)
        .max(r4c_slots.saturating_sub(16))
        .min(slot_count)
        .min(r4c_slots);
    let mut size = (slots * 8).min(GTO_MAX_IAT_READ).max(GTO_MIN_IAT_SIZE);
    if last_api + 2 >= r4c_slots.saturating_sub(32) {
        size = GTO_R4C_IAT_SIZE;
    }
    if size == 0
        || !(GTO_MIN_IAT_SIZE..=GTO_R4C_IAT_SIZE).contains(&size)
        || size > bytes.len()
        || !size.is_multiple_of(8)
    {
        return None;
    }
    Some(IatLocationHint { address, size })
}

fn observe_gto_iat_override(
    dbg: &ProcessSession,
    address: usize,
    image_base: usize,
    section_size: usize,
) -> Option<IatLocationHint> {
    let scan_size = section_size.min(GTO_MAX_IAT_READ).min(GTO_IAT_SCAN_CAP);
    if address == 0 || scan_size < GTO_MIN_IAT_SIZE {
        return None;
    }
    let mut bytes = vec![0u8; scan_size];
    let bytes_read = dbg.read_memory(address, &mut bytes).ok()?;
    let live_bytes = &bytes[..bytes_read.min(bytes.len())];
    gto_iat_hint_from_live_span(address, image_base, live_bytes)
}

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

/// GTO-specific post-attach observation.
///
/// Caller (shared `run_post_attach_path`) has already created the process,
/// captured early snapshots, resumed the main thread, and applied plugin
/// session defaults. This function observes the freely-running target until
/// the GTO OEP is established (via UI settle / IAT-resolved timing / `.text`
/// scan), updates the early snapshots, and returns the OEP candidate. The
/// caller then hands off to the shared `run_post_loop_phases` for dump.
///
/// This is family policy, not a full unpack host.
pub(super) fn observe_gto(
    dbg: &mut ProcessSession,
    pe: &PeHeader,
    profile: DumpProfile,
    early_section_snapshots: &mut Vec<EarlySectionSnapshot>,
) -> Result<GtoObservation, anyhow::Error> {
    if !matches!(profile, DumpProfile::AhkGtoExperimental) {
        warn!(
            "GTO observation without ahk-gto-experimental profile — \
             heap/container dump stages stay disabled"
        );
    }

    let image_base_usize = dbg.image_base() as usize;
    let text_sec = pe
        .sections
        .first()
        .ok_or_else(|| anyhow!("GTO observation: PE has no sections"))?;
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
            "GTO observation: OEP watch ranges={} (section0 .text + exec/boot/EP)",
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
    let iat_section_size = rdata_sec.map(|s| s.virtual_size as usize).unwrap_or(0x8000);

    log::log(
        LogType::Info,
        &format!("GTO observation: polling IAT at {iat_addr:#x} (RVA {iat_rva:#x}) for resolution"),
    );

    let poll_start = std::time::Instant::now();
    // Cap observation: GTO targets often self-exit after a short GUI/init window.
    // Prefer dump-before-exit over waiting the full Oreans idle timeout.
    // Route H / no-bypass: hold the full upper cap so UI-seen has room before
    // any no-UI fallback.
    let no_bypass = std::env::var("MIDA_GTO_NO_BYPASS").ok().as_deref() == Some("1");
    let max_wait = if no_bypass {
        std::time::Duration::from_secs(90)
    } else {
        std::time::Duration::from_secs(60)
    };
    if no_bypass {
        log::log(
            LogType::Info,
            "GTO observation: Route H no-bypass timing — prefer UI-seen settle; \
             dump-before-exit only if process dies after IAT",
        );
    }
    let main_tid = dbg.main_thread_id();
    let h_thread = dbg
        .thread_handle(main_tid)
        .map_err(|e| anyhow!("GTO observation thread_handle: {e}"))?;
    // Always dump via .text scan after settle; live RIP freeze disabled.
    let frozen_rip: Option<usize> = None;
    let mut observed_text_rips: Vec<usize> = Vec::new();
    let mut iat_resolved_at: Option<std::time::Instant> = None;
    let mut ui_seen_at: Option<std::time::Instant> = None;
    let mut loop_count = 0u32;
    // Route G: process may self-exit after IAT (exit 0) before UI/settle.
    let mut exited_after_iat = false;
    let target_pid = dbg.pid();

    // True when an IAT slot is a resolved external API pointer.
    let iat_slot_looks_resolved = |val: usize, image_base: usize| -> bool {
        if val == 0 || val < 0x1_0000 {
            return false;
        }
        if val >= image_base && val < image_base.saturating_add(0x1000_0000) {
            return false;
        }
        val >= 0x7FF0_0000_0000 || (0x1800_0000..0x7FFF_FFFF_FFFF).contains(&val)
    };

    loop {
        loop_count = loop_count.saturating_add(1);
        if poll_start.elapsed() > max_wait {
            log::log(
                LogType::Warn,
                "GTO observation: OEP observation timeout — proceeding with scan/fallback",
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
                    &format!("GTO observation: GetExitCodeProcess failed: {e} — assuming alive"),
                );
                true
            }
        };
        if !alive {
            if iat_resolved_at.is_some() {
                exited_after_iat = true;
                log::log(
                    LogType::Warn,
                    &format!(
                        "GTO observation: target exited after IAT resolve (exit_code={exit_code:#x}, \
                         ui_seen={}, after {} ms) — proceed via .text scan (Route G acquisition reliability)",
                        ui_seen_at.is_some(),
                        poll_start.elapsed().as_millis()
                    ),
                );
                break;
            }
            return Err(anyhow!(
                "GTO observation: target exited before IAT resolve (exit_code={exit_code:#x})"
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
                            "GTO observation: IAT first slot = {val:#x} (after {} ms)",
                            poll_start.elapsed().as_millis()
                        ),
                    );
                }
            }
        }

        // R-GTO-UI: dump shortly after product login window appears so heap
        // capture includes post-GUI gscript / title roots.
        if iat_resolved_at.is_some()
            && ui_seen_at.is_none()
            && process_has_window_class(target_pid, GTO_UI_WINDOW_CLASS)
        {
            ui_seen_at = Some(std::time::Instant::now());
            log::log(
                    LogType::Good,
                    &format!(
                        "GTO observation: product window class {GTO_UI_WINDOW_CLASS} seen (after {} ms) — short settle",
                        poll_start.elapsed().as_millis()
                    ),
                );
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
                        "GTO observation: UI settle {} ms complete (need {} ms, no_bypass={})",
                        ui_t.elapsed().as_millis(),
                        ui_settle.as_millis(),
                        no_bypass
                    ),
                );
                break;
            }
        }

        // After IAT resolves without UI: hold max_wait; Route H takes a
        // last-resort alive dump at IAT+9s if UI never appears.
        if ui_seen_at.is_none() {
            if let Some(iat_t) = iat_resolved_at {
                let settle = if no_bypass {
                    std::time::Duration::from_secs(9)
                } else {
                    max_wait.saturating_sub(std::time::Duration::from_secs(2))
                };
                if iat_t.elapsed() >= settle {
                    log::log(
                        LogType::Info,
                        &format!(
                            "GTO observation: IAT+{} ms without UI — proceed via .text scan (no_bypass={})",
                            iat_t.elapsed().as_millis(),
                            no_bypass
                        ),
                    );
                    break;
                }
            }
        }

        // Route H / no-bypass: suspend less often so the UI thread can paint
        // NewClassName before we freeze/dump.
        let do_suspend = if no_bypass && iat_resolved_at.is_some() && ui_seen_at.is_none() {
            loop_count.is_multiple_of(4)
        } else {
            true
        };
        let previous = if do_suspend {
            unsafe { SuspendThread(h_thread) }
        } else {
            u32::MAX - 1
        };
        if do_suspend && previous != u32::MAX {
            if let Ok(ctx) = dbg.get_thread_context_control(main_tid) {
                let rip = ctx.Rip as usize;
                let in_watch = oep_watch
                    .iter()
                    .find(|(s, e, _)| rip >= *s && rip < *e)
                    .map(|(_, _, n)| n.as_str());
                if let Some(sec_name) = in_watch {
                    if sec_name == ".text" {
                        let rva = rip - image_base_usize;
                        if !observed_text_rips.contains(&rva) {
                            observed_text_rips.push(rva);
                            if observed_text_rips.len() <= 40 {
                                log::log(
                                    LogType::Info,
                                    &format!(
                                        "GTO observation: .text RIP #{} at {:#x} (rva {:#x}); iat_ok={}",
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
                                "GTO observation: observe only at {rip:#x} ({sec_name}); iat_ok={}",
                                iat_resolved_at.is_some()
                            ),
                        );
                    }
                } else if rip < text_start || rip >= text_end {
                    update_pre_text_snapshots(dbg, early_section_snapshots, rip)?;
                }
            }
            let _ = unsafe { ResumeThread(h_thread) };
        }

        let tick_ms = if no_bypass && !do_suspend { 120 } else { 80 };
        std::thread::sleep(std::time::Duration::from_millis(tick_ms));
    }

    if frozen_rip.is_none() {
        let previous = unsafe { SuspendThread(h_thread) };
        if previous == u32::MAX && !exited_after_iat {
            return Err(anyhow!("GTO observation: failed to freeze primary thread"));
        }
    }

    let oep_addr = match mida_packers_themida::find_real_oep_by_scanning(
        dbg as &dyn DebuggerCore,
        image_base_usize,
        text_rva,
        text_vsize,
    ) {
        Ok(Some(addr)) => {
            log::log(
                LogType::Good,
                &format!("GTO observation: OEP via .text scan {addr:#x}"),
            );
            addr
        }
        Ok(None) => {
            let pe_ep = image_base_usize + pe.entry_point as usize;
            log::log(
                LogType::Warn,
                &format!("GTO observation: OEP scan empty — PE EP {pe_ep:#x}"),
            );
            pe_ep
        }
        Err(e) => {
            let pe_ep = image_base_usize + pe.entry_point as usize;
            log::log(
                LogType::Warn,
                &format!("GTO observation: OEP scan error {e:#} — PE EP {pe_ep:#x}"),
            );
            pe_ep
        }
    };

    let iat_override = observe_gto_iat_override(dbg, iat_addr, image_base_usize, iat_section_size);
    match iat_override {
        Some(hint) => log::log(
            LogType::Info,
            &format!(
                "GTO observation: live IAT override address={:#x} size={:#x}",
                hint.address, hint.size
            ),
        ),
        None => log::log(
            LogType::Warn,
            "GTO observation: no valid live IAT span; shared discovery fallback remains active",
        ),
    }

    Ok(GtoObservation {
        oep_addr,
        frozen_rip,
        iat_override,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_span_with_api_at(slot: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; GTO_IAT_SCAN_CAP];
        let offset = slot * 8;
        bytes[offset..offset + 8].copy_from_slice(&0x7FF9_1234_5678u64.to_le_bytes());
        bytes
    }

    #[test]
    fn gto_r4c_policy_preserves_11e0_size() {
        let r4c_slots = GTO_R4C_IAT_SIZE / 8;
        let bytes = live_span_with_api_at(r4c_slots - 34);
        let hint = gto_iat_hint_from_live_span(0x1400_4000, 0x1400_0000, &bytes)
            .expect("valid GTO live span");
        assert_eq!(hint.address, 0x1400_4000);
        assert_eq!(hint.size, GTO_R4C_IAT_SIZE);
    }

    #[test]
    fn valid_gto_live_span_produces_hint() {
        let bytes = live_span_with_api_at(16);
        let hint = gto_iat_hint_from_live_span(0x1400_4000, 0x1400_0000, &bytes);
        assert!(hint.is_some());
    }

    #[test]
    fn missing_live_api_span_falls_back_to_none() {
        let bytes = vec![0u8; GTO_IAT_SCAN_CAP];
        assert_eq!(
            gto_iat_hint_from_live_span(0x1400_4000, 0x1400_0000, &bytes),
            None
        );
    }
}
