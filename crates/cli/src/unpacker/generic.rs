//! Generic packer-agnostic unpack path.
//!
//! Does NOT run Themida detection / shrink / guard logic.
//! Flow: create process (post-attach) -> resume -> poll .text restore
//! -> dump full image with shrink=false.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context};

use mida_core::{CreateProcessOptions, DebuggerCore, WindowsDebugger};
use mida_pe::{ContainerRestoreMode, DumpOptions, DumpProfile, PeHeader};

use super::generic_gate::{
    check_generic_dump, gate_inputs_from_pe, is_ahk_export_name, validate_generic_dump,
    GenericGateProfile,
};
use super::helpers::resolve_output_path;
use crate::log::{self, LogType};

const IMAGE_FILE_DLL: u16 = 0x2000;

fn nz_ratio(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let nz = buf.iter().filter(|&&b| b != 0).count();
    nz as f64 / buf.len() as f64
}

fn looks_code(buf: &[u8]) -> bool {
    let head = if buf.len() > 0x4000 {
        &buf[..0x4000]
    } else {
        buf
    };
    let sigs: &[&[u8]] = &[
        b"\x48\x89\x5c\x24",
        b"\x48\x83\xec",
        b"\x40\x53",
        b"\x48\x8b\xc4",
        b"\x55\x48",
    ];
    if sigs.iter().any(|s| head.windows(s.len()).any(|w| w == *s)) {
        return true;
    }
    nz_ratio(head) > 0.35
}

/// Generic unpack: no Themida shrink, keep all restored sections.
///
/// `gate_profile` selects which hard gates are enforced on the dumped PE:
/// [`GenericGateProfile::PackerAgnostic`] (default, packer-agnostic) or
/// [`GenericGateProfile::AhkLauncher`] (explicit opt-in for AutoHotkey-derived
/// packed launchers that require a large RX section).
///
/// A gate failure returns [`GenericGateFailure`] which the CLI maps to exit
/// code `2`.
pub fn generic_unpack(
    input: &Path,
    output: Option<&Path>,
    wait_sec: u64,
    stable_needed: u32,
    gate_profile: GenericGateProfile,
) -> Result<(), anyhow::Error> {
    let pe = PeHeader::from_file(input).map_err(|e| anyhow!("parse PE failed: {e}"))?;
    let output_path = resolve_output_path(input, output);
    // Prefer custom suffix for generic outputs when default path is used.
    let output_path = if output.is_none() {
        let stem = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("output");
        let ext = input.extension().and_then(|s| s.to_str()).unwrap_or("exe");
        input
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(format!("{stem}_genericU.{ext}"))
    } else {
        output_path
    };

    let is_dll = (pe.nt_headers.file_header.characteristics & IMAGE_FILE_DLL) != 0;
    let opts = CreateProcessOptions {
        executable: input.to_path_buf(),
        command_line: None,
        is_dll,
        suspended: false,
        post_attach: true,
    };

    let mut dbg = WindowsDebugger::new(&opts).context("create process failed")?;
    let image_base = dbg.image_base() as usize;
    log::log(
        LogType::Info,
        &format!(
            "generic: pid={} image_base={:#x} out={}",
            dbg.pid(),
            image_base,
            output_path.display()
        ),
    );

    // Oreans/Themida often wipe section names (spaces). Prefer ".text*", else
    // first executable image section, else section 0 — same convention as the
    // Oreans unpack path which uses pe_sections[0] as code.
    let text = pe
        .sections
        .iter()
        .find(|s| s.name.starts_with(".text"))
        .or_else(|| {
            pe.sections.iter().find(|s| {
                const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
                const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
                (s.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) != 0
                    && s.virtual_size > 0
            })
        })
        .or_else(|| pe.sections.first())
        .ok_or_else(|| anyhow!("no .text section (and no executable/section-0 fallback)"))?;
    log::log(
        LogType::Info,
        &format!(
            "generic: poll section name={:?} va={:#x} vsize={:#x}",
            text.name, text.virtual_address, text.virtual_size
        ),
    );
    let text_va = text.virtual_address as usize;
    let text_size = (text.virtual_size as usize).min(0x20000);

    dbg.resume_post_attach_main_thread()
        .context("resume post-attach main thread failed")?;

    let deadline = Instant::now() + Duration::from_secs(wait_sec);
    let mut last = [0u8; 16];
    let mut have_last = false;
    let mut stable = 0u32;
    let mut last_nz = 0.0;
    while Instant::now() < deadline {
        let mut buf = vec![0u8; text_size];
        let n = dbg.read_memory(image_base + text_va, &mut buf).unwrap_or(0);
        if n > 0 {
            buf.truncate(n);
            last_nz = nz_ratio(&buf);
            let code = looks_code(&buf);
            let mut sample = [0u8; 16];
            let m = n.min(16);
            sample[..m].copy_from_slice(&buf[..m]);
            if have_last && sample == last && last_nz >= 0.5 && code {
                stable += 1;
            } else {
                stable = 0;
            }
            last = sample;
            have_last = true;
            log::log(
                LogType::Info,
                &format!(
                    "generic poll: .text_nz={:.3} code={} stable={}/{}",
                    last_nz, code, stable, stable_needed
                ),
            );
            if stable >= stable_needed {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(400));
    }

    if last_nz < 0.5 {
        return Err(anyhow!(
            "generic: .text not restored (nz={:.3}) within {}s",
            last_nz,
            wait_sec
        ));
    }

    let dump_opts = DumpOptions {
        image_base: dbg.image_base(),
        entry_point: pe.entry_point,
        fix_imports: true,
        create_data_sections: true,
        shrink: false,
        output_path: output_path.clone(),
        executable_path: Some(input.to_path_buf()),
        iat_location: None,
        additional_iat_locations: Vec::new(),
        early_section_snapshots: Vec::new(),
        container_restore: ContainerRestoreMode::Off,
        profile: DumpProfile::OreansClassic,
        security_cookie_rva: None,
        security_cookie_complement_rva: None,
        pure_rebuild: false,
        capture_policy: mida_pe::DumpCapturePolicy::default(),
    };

    mida_pe::dump_process(&mut dbg, &dump_opts).map_err(|e| anyhow!("dump failed: {e}"))?;

    let out_pe = PeHeader::from_file(&output_path).map_err(|e| anyhow!("read output PE: {e}"))?;

    // --- Unified generic gate (packer-agnostic by default) ---
    // The large-RX requirement is an AHK-launcher profile gate, NOT a generic
    // global hard gate.  Callers opt in via --gate-profile=ahk-launcher.
    let has_ahk_export = exports_contain_ahk(&out_pe, &output_path);
    let inputs = gate_inputs_from_pe(&out_pe, has_ahk_export);
    let result = validate_generic_dump(inputs, gate_profile);
    log::log(
        LogType::Info,
        &format!(
            "generic gate: profile={:?} pass={} text_has_raw={} large_rx_present={} large_rx_has_raw={} has_ahk_export={} failures={:?} warnings={:?}",
            gate_profile,
            result.pass,
            inputs.text_has_raw,
            inputs.large_rx_present,
            inputs.large_rx_has_raw,
            inputs.has_ahk_export,
            result.failures,
            result.warnings,
        ),
    );
    check_generic_dump(&out_pe, gate_profile, has_ahk_export).map_err(anyhow::Error::from)?;

    log::log(
        LogType::Good,
        &format!(
            "generic unpacked: {} (shrink=false, gate={:?})",
            output_path.display(),
            gate_profile,
        ),
    );
    Ok(())
}

/// Best-effort export scan for the `AhkExec` marker, used only as an input to
/// the AHK-launcher gate profile.  Falls back to `false` on any parse error
/// so a missing export never crashes the generic path.
fn exports_contain_ahk(pe: &PeHeader, path: &Path) -> bool {
    const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
    let dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if dir.virtual_address == 0 || dir.size == 0 {
        return false;
    }
    // Read the export directory from the file at its raw offset.
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let dir_off = match pe.rva_to_offset(dir.virtual_address) {
        Some(o) => o as usize,
        None => return false,
    };
    if data.len() < dir_off + 40 {
        return false;
    }
    let addr_names = u32::from_le_bytes(data[dir_off + 0x20..dir_off + 0x24].try_into().unwrap());
    let num_names = u32::from_le_bytes(data[dir_off + 0x18..dir_off + 0x1C].try_into().unwrap());
    if addr_names == 0 || num_names == 0 {
        return false;
    }
    let names_off = match pe.rva_to_offset(addr_names) {
        Some(o) => o as usize,
        None => return false,
    };
    for i in 0..num_names as usize {
        let entry = names_off + i * 4;
        if data.len() < entry + 4 {
            return false;
        }
        let name_rva = u32::from_le_bytes(data[entry..entry + 4].try_into().unwrap());
        if name_rva == 0 {
            continue;
        }
        let name_off = match pe.rva_to_offset(name_rva) {
            Some(o) => o as usize,
            None => continue,
        };
        // Read a NUL-terminated ASCII name.
        let end = data[name_off..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_off + p)
            .unwrap_or(data.len());
        let name = &data[name_off..end];
        if is_ahk_export_name(std::str::from_utf8(name).unwrap_or("")) {
            return true;
        }
    }
    false
}
