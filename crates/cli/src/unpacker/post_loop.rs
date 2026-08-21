//! Post-loop phases B/C/D (IAT repair, post-process, dump).
//!
//! Extracted from `mod.rs` (P1 host thin split). Host still uses
//! [`ThemidaState`] for both Oreans and AHK/GTO —not an independent GTO
//! pipeline. Family gates:
//! - `uses_oreans_iat_trace` —skip Oreans V3 wrapper single-step for AHK/GTO
//! - x86-only API call-site fixup under Oreans
//!
//! Exit Ok means a candidate PE was written, not R0B/behavioral acceptance.

use std::path::Path;

use anyhow::{anyhow, Context};
use tracing::{info, warn};

use crate::log::{self, LogType};
use mida_core::{DebuggerCore, OepProvenance, RuntimeBase, Rva, Va};
use mida_packers_themida::{
    create_data_sections, determine_iat_address, fix_iat, fixup_api_call_sites,
    install_anti_dump_fix, shrink_pe, CompilerHint, IatFixStrategy, IatLocation, ThemidaState,
};
use mida_pe::{
    ContainerRestoreMode, DumpCapturePolicy, DumpOptions, DumpProfile, EarlySectionSnapshot,
    OepPolicy, PeHeader,
};

use super::helpers::{compute_data_section_bounds, resolve_host_api};
use super::iat_evidence::write_iat_evidence;
use super::oep_evidence::write_oep_evidence;
use super::oep_scan::{resolve_oep_va, scan_live_memory_for_real_oep};
use super::plugin_host::IatLocationHint;
use super::relocation_evidence::write_relocation_evidence;
use super::section_rebuild_evidence::write_section_rebuild_evidence;
use super::session::ProcessSession;
use super::tls_evidence::write_tls_evidence;

/// Phases B (IAT repair), C (post-processing), and D (dump to file).
///
/// Runs after the debug loop has found the OEP and completed IAT tracing.
///
/// `uses_oreans_iat_trace` / `family_id` gate Oreans V3 wrapper tracing so
/// AHK/GTO does not unconditionally inherit Themida IAT strategy.
pub(super) fn run_post_loop_phases(
    dbg: &mut ProcessSession,
    state: &mut ThemidaState,
    pe: &mut PeHeader,
    oep: Option<usize>,
    is_dotnet: bool,
    is_64bit: bool,
    do_data_sections: bool,
    shrink: bool,
    post_attach: bool,
    // True when host saw ExitProcess or plugin set skip_v3_iat_trace.
    skip_v3_iat_trace: bool,
    uses_oreans_iat_trace: bool,
    family_id: &str,
    iat_override: Option<IatLocationHint>,
    oep_policy: OepPolicy,
    container_restore: ContainerRestoreMode,
    profile: DumpProfile,
    pure_rebuild: bool,
    // CLI / case-manifest capture policy (may be empty).
    cli_capture_policy: DumpCapturePolicy,
    early_section_snapshots: &[EarlySectionSnapshot],
    input: &Path,
    output_path: &Path,
    // Loop-captured OEP RVA from PackerPlugin (diagnostic / dump-boundary).
    plugin_oep_rva: Option<Rva>,
    oep_provenance: &OepProvenance,
    dump_advice: Option<mida_core::DumpAdvice>,
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

    let iat = if let Some(hint) = iat_override {
        info!(
            address = %format!("{:#x}", hint.address),
            size = %format!("{:#x}", hint.size),
            family = family_id,
            "Using family-observed IAT override"
        );
        IatLocation {
            address: hint.address,
            size: hint.size,
            requires_writable_section: false,
        }
    } else {
        determine_iat_address(
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
        .ok_or_else(|| anyhow!("IAT not found"))?
    };

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
    if !uses_oreans_iat_trace {
        // Non-Oreans family (e.g. ahk_gto): do not run Themida V3 wrapper
        // single-step. Dump rebuilds imports from live / residual IAT slots.
        log::log(
            LogType::Info,
            &format!("Skipping Oreans V3 IAT trace (family={family_id}; live IAT rebuild at dump)"),
        );
    } else if post_attach {
        // In post-attach mode, IAT slots already contain resolved API
        // addresses (no Themida wrappers to trace). dump_process will
        // rebuild the import table directly from the live IAT.
        log::log(
            LogType::Info,
            "Skipping V3 IAT trace (post-attach: slots already resolved)",
        );
    } else if skip_v3_iat_trace {
        // Plugin / host: process dead or policy skip (Lunlun storm escape, etc.).
        // V3 single-step would hang; dump with residual IAT slots.
        log::log(
            LogType::Warn,
            "Skipping V3 IAT trace (plugin/host skip_v3) —dump with raw IAT slots",
        );
    } else {
        match fix_iat(dbg, state, &iat, trace_thread_id, strategy) {
            Ok(()) => log::log(LogType::Info, "IAT fixed"),
            Err(e) => {
                // Prefer a structural candidate over hanging/aborting with no dump.
                warn!(error = %e, "IAT fix failed —continuing to dump with partial IAT");
                log::log(
                    LogType::Warn,
                    &format!("IAT fix failed ({e:#}) —dump with partial IAT"),
                );
            }
        }
    }

    let themida_section = state
        .pe_info
        .themida_section
        .map(|idx| &state.pe_info.pe_sections[idx]);

    // Oreans x86 only: FixupAPICallSites. GTO and x64 skip.
    // Pascal Themida64.pas FinishUnpacking does NOT call FixupAPICallSites on x64.
    if uses_oreans_iat_trace && !is_64bit {
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
    } else if !uses_oreans_iat_trace {
        log::log(
            LogType::Info,
            &format!("Skipping Oreans API call site fixup (family={family_id})"),
        );
    } else {
        log::log(
            LogType::Info,
            "Skipping API call site fixup on x64 (matches Pascal Themida64)",
        );
    }

    // ---- phase C: post-processing ----
    let image_base_for_scan = dbg.image_base() as usize;
    let captured_oep = oep_addr;
    let scanned_oep = scan_live_memory_for_real_oep(
        dbg,
        image_base_for_scan,
        &state.pe_info.pe_sections,
        state.pe_info.base_of_data,
        state.pe_info.major_linker_version,
        Some(captured_oep),
    )?;

    // OEP policy (CLI --oep=...):
    // - captured (default): keep frozen first decrypted .text RIP; scanner ignored
    // - crt: unique strong MSVC PE-entry wrapper only (fail-closed; no unwrap_or)
    // - fixed RVA: force PE entry
    oep_addr = resolve_oep_va(oep_policy, image_base_for_scan, captured_oep, scanned_oep)?;

    info!(
        policy = ?oep_policy,
        captured = %format!("{captured_oep:#x}"),
        scanned = scanned_oep
            .map(|a| format!("{a:#x}"))
            .unwrap_or_else(|| "none".into()),
        final_ep = %format!("{oep_addr:#x}"),
        post_attach,
        "Resolved PE entry point"
    );

    log::log(LogType::Info, &format!("Final OEP: {:#x}", oep_addr));

    // Slice 3b-4: dump-boundary diagnostics via addr types + plugin advice.
    let runtime_base = RuntimeBase(dbg.image_base());
    if let Some(plugin_rva) = plugin_oep_rva {
        if let Some(final_rva) = Va(oep_addr as u64).to_rva(runtime_base) {
            if final_rva != plugin_rva {
                info!(
                    plugin = %format!("{:#x}", plugin_rva.get()),
                    final_ep = %format!("{:#x}", final_rva.get()),
                    "PackerPlugin OEP RVA differs from post-loop resolved EP (oep_policy may have retargeted)"
                );
            }
        }
    }
    if let Some(ref advice) = dump_advice {
        info!(
            advice_ep = ?advice.entry_point_rva,
            prefer_pure = advice.prefer_pure_rebuild,
            note = advice.note,
            has_capture_hint = advice.capture_policy.is_some(),
            "PackerPlugin dump_advice at dump boundary"
        );
        // prefer_pure_rebuild is advisory only; CLI `--pure-rebuild` still owns emit.
        let _ = advice.prefer_pure_rebuild;
    }
    // Merge order: CLI/case-manifest roots win over plugin preset; then profile.
    let capture_policy = DumpCapturePolicy::resolve_with_plugin_hint(
        cli_capture_policy,
        dump_advice.as_ref().and_then(|a| a.capture_policy.as_ref()),
        profile,
    );
    info!(
        capture_source = capture_policy.source_label(),
        hot_roots = capture_policy.hot_root_rvas.len(),
        "post_loop resolved capture_policy"
    );

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
    // Pascal Themida64.pas does NOT install this stub on x64 —it leaves the
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

    // Slice 3b-4: dump entry via RuntimeBase + Va →Rva (no raw wrapping_sub).
    let entry_rva = Va(oep_addr as u64)
        .to_rva(runtime_base)
        .context("OEP not in runtime image (Va→Rva failed)")?;
    let entry_point_u32 = entry_rva.get();

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
        container_restore,
        profile,
        // B7.2: authoritative cookie site from offline CRT resolve —no dump rescan.
        security_cookie_rva: if state.msvc_cookie_rva != 0 {
            Some(state.msvc_cookie_rva)
        } else {
            None
        },
        security_cookie_complement_rva: if state.msvc_cookie_complement_rva != 0 {
            Some(state.msvc_cookie_complement_rva)
        } else {
            None
        },
        pure_rebuild,
        capture_policy,
    };

    let dump_report = mida_pe::dump_process_with_report(dbg, &dump_opts)
        .map_err(|e| anyhow!("Dump failed: {e}"))?;

    let iat_sidecar_path = write_iat_evidence(input, output_path, &dump_report, family_id)
        .context("write candidate-bound IAT evidence sidecar")?;
    log::log(
        LogType::Info,
        &format!(
            "IAT evidence sidecar written: {}",
            iat_sidecar_path.display()
        ),
    );

    let tls_sidecar_path = write_tls_evidence(input, output_path, &dump_report, family_id)
        .context("write candidate-bound TLS evidence sidecar")?;
    log::log(
        LogType::Info,
        &format!(
            "TLS evidence sidecar written: {}",
            tls_sidecar_path.display()
        ),
    );

    let relocation_sidecar_path =
        write_relocation_evidence(input, output_path, &dump_report, family_id)
            .context("write candidate-bound relocation evidence sidecar")?;
    log::log(
        LogType::Info,
        &format!(
            "Relocation evidence sidecar written: {}",
            relocation_sidecar_path.display()
        ),
    );

    // GTO-H4-D: candidate-bound exception evidence (independent final decode
    // + no-reloc state cross-check). Final relocation base state is derived
    // from the candidate's own PE header (fresh reparse, never the dump
    // object): if the on-disk image base differs from the runtime base, the
    // D2.2-4 cross-check must fail closed.
    let final_reloc_state = {
        use mida_pe::header::PeHeader;
        let candidate_bytes =
            std::fs::read(output_path).context("read candidate for exception evidence")?;
        let candidate_pe = PeHeader::from_bytes(&candidate_bytes)
            .context("parse candidate PE for exception evidence")?;
        let ch = candidate_pe.nt_headers.file_header.characteristics;
        let dc = candidate_pe.nt_headers.optional_header.dll_characteristics;
        // IMAGE_DIRECTORY_ENTRY_BASERELOC == 5;
        // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE == 0x0040 (mida_pe keeps both
        // crate-private; literal here with a comment, pinned by the acceptance
        // sidecar tests).
        let reloc_dd = candidate_pe.nt_headers.optional_header.data_directory[5];
        let dynamic_base_bit: u16 = 0x0040;
        super::exception_evidence::NoRelocFinalState {
            image_base_changed: candidate_pe.image_base
                != dump_report.relocation_report.runtime_image_base,
            directory_absent: reloc_dd.virtual_address == 0 && reloc_dd.size == 0,
            directory_present_but_empty: reloc_dd.virtual_address != 0 && reloc_dd.size == 0,
            relocs_stripped: ch & 0x0001 != 0,
            dynamic_base: dc & dynamic_base_bit != 0,
            runtime_image_base: dump_report.relocation_report.runtime_image_base,
            preferred_image_base: candidate_pe.image_base,
        }
    };
    let exception_sidecar_path = super::exception_evidence::write_exception_evidence(
        input,
        output_path,
        &dump_report,
        family_id,
        &final_reloc_state,
    )
    .context("write candidate-bound exception evidence sidecar")?;
    log::log(
        LogType::Info,
        &format!(
            "Exception evidence sidecar written: {}",
            exception_sidecar_path.display()
        ),
    );

    let section_rebuild_sidecar_path =
        write_section_rebuild_evidence(input, output_path, family_id)
            .context("write candidate-bound section rebuild evidence sidecar")?;
    log::log(
        LogType::Info,
        &format!(
            "Section rebuild evidence sidecar written: {}",
            section_rebuild_sidecar_path.display()
        ),
    );

    let sidecar_path = write_oep_evidence(input, output_path, oep_provenance, family_id)
        .context("write native OEP provenance sidecar")?;
    log::log(
        LogType::Info,
        &format!("OEP evidence sidecar written: {}", sidecar_path.display()),
    );

    // Lightweight structural hints only —non-fatal. Exit Ok means a candidate
    // PE was written, not that mida-acceptance (R0B) or behavioral gates passed.
    // Lab harnesses must run `mida-acceptance check-static` (and future behavior
    // evidence) separately; this CLI path does not depend on mida-acceptance.
    let mut structure_ep_ok = false;
    if let Ok(out_pe) = PeHeader::from_file(output_path) {
        let ep = out_pe.entry_point;
        let tls = out_pe.nt_headers.optional_header.data_directory[9];
        let ep_in_exec = out_pe.sections.iter().any(|s| {
            (s.characteristics & 0x2000_0000) != 0
                && ep >= s.virtual_address
                && ep < s.virtual_address.saturating_add(s.virtual_size)
        });
        structure_ep_ok = ep_in_exec;
        if !ep_in_exec {
            warn!(
                ep = format_args!("{ep:#x}"),
                "Output EP not in an executable section (candidate still written)"
            );
        }
        if tls.virtual_address == 0 {
            info!("Output TLS directory empty (expected under clean CRT + post-crt restore)");
        }
        // Keep "Structure gate:" prefix —lab smoke parsers match this line.
        // Semantics remain non-authoritative (not mida-acceptance R0B).
        log::log(
            LogType::Info,
            &format!(
                "Structure gate: EP={ep:#x} exec_ok={ep_in_exec} TLS={:#x}/{:#x} (hint only; not R0B)",
                tls.virtual_address, tls.size
            ),
        );
    } else {
        warn!("Could not re-parse output PE for structure hint (candidate still written)");
    }

    log::log(
        LogType::Good,
        &format!(
            "Candidate written: {} (not acceptance-verified; R0B/behavior are external gates; structure_ep_ok={structure_ep_ok})",
            output_path.display()
        ),
    );
    // Keep a secondary line that older lab parsers grep for "Unpacked:".
    log::log(
        LogType::Info,
        &format!(
            "Unpacked: {} (candidate; acceptance external)",
            output_path.display()
        ),
    );
    Ok(())
}
