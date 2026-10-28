//! Stub-referenced IAT recovery for images with an unusable import directory.
//!
//! When a protector shell materialises the original program as a PE image,
//! it typically resolves the imports itself — into its own workspace or an
//! external IAT region — and wipes the image's import directory, leaving
//! call sites as `ff 15 [abs32]` / `ff 25 [abs32]` stubs into the external
//! slot array.  This module recovers that IAT from the suspended debuggee:
//!
//! 1. Read the image (VA layout) and collect every `ff 15` / `ff 25`
//!    abs32 target — live pointers into the external IAT.
//! 2. Cluster the targets; the largest cluster is the IAT.  Expand the
//!    boundaries slot-by-slot while slots hold addresses inside loaded
//!    modules — the shell also fills slots the payload never calls
//!    directly, so the referenced span alone undercounts.
//! 3. Read the IAT bytes and resolve every slot against the live module
//!    snapshot's export tables (same mechanism as `import_rebuild`
//!    Pass 1).
//! 4. Write `<stem>.v2iat.bin` (raw slot bytes) and `<stem>.v2iat.txt`
//!    (slot → `module function` report) next to the raw image dump.
//!
//! The offline rebuild script consumes both files to relocate the IAT into
//! the image and rebuild a loadable import directory.
//!
//! Status (2026-10-28): no confirmed consumer yet.  The SecureEngine 2.x
//! (V2) campaign that motivated it turned out to have never seen a
//! materialised payload — the "payload PE" was CoreUIComponents.dll, a
//! bystander system DLL kept alive by a `parse_image` bug that read the
//! export directory as the import directory (see POSTMORTEMS).  The
//! machinery stays: the gate (`materialised_image_gate`) now requires the
//! EXE flag and an unusable import directory, so bystanders cannot pass,
//! and any future shell that really does materialise its payload lands
//! here with the capture ready.

use tracing::{info, warn};

use mida_core::DebuggerCore;

use crate::error::PeError;

use super::remote_modules::take_module_snapshot;
use super::types::RemoteModule;
use super::mapped_images::MappedImage;

/// Maximum bytes to expand the IAT boundaries past the referenced span in
/// each direction (1024 slots).  The expansion stops earlier at the first
/// slot that is not inside any loaded module.
const MAX_EXPAND: u64 = 0x4000;

/// Gate: is this a materialised image whose imports the shell processed?
///
/// Reads the image's own header from target memory (callers may pass a
/// `MappedImage` with placeholder fields) and requires ALL of:
///
/// - entry point intact (the shell keeps the payload's EP),
/// - `IMAGE_FILE_DLL` clear — original programs are EXEs; bystander
///   system DLLs are DLLs.  This is the honest discriminator: the
///   2026-10-28 "V2 payload PE" was CoreUIComponents.dll, kept passing
///   every import/EP shape check until this flag was consulted,
/// - import directory unusable: dd[1] zero, or the first descriptor
///   block all-zero (the shell's post-resolve wipe).
///
/// Returns `Some(import_rva)` when the gate passes (0 when dd[1] itself
/// is zero), `None` otherwise.
fn materialised_image_gate(
    debugger: &dyn DebuggerCore,
    image: &MappedImage,
) -> Option<u32> {
    let mut head = [0u8; 0x400];
    if debugger.read_memory(image.base as usize, &mut head).is_err() {
        return None;
    }
    if head[0] != b'M' || head[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(head[0x3C..0x40].try_into().ok()?) as usize;
    if e_lfanew + 24 + 2 > head.len() || head[e_lfanew] != b'P' || head[e_lfanew + 1] != b'E' {
        return None;
    }
    let opt = e_lfanew + 24;
    let magic = u16::from_le_bytes(head[opt..opt + 2].try_into().ok()?);
    let dd_off = opt + if magic == 0x20B { 112 } else { 96 };
    if dd_off + 16 > head.len() {
        return None;
    }
    let entry_point = u32::from_le_bytes(head[opt + 16..opt + 20].try_into().ok()?);
    let file_chars = u16::from_le_bytes(head[e_lfanew + 22..e_lfanew + 24].try_into().ok()?);
    if entry_point == 0 || file_chars & 0x2000 != 0 {
        return None;
    }
    let import_rva = u32::from_le_bytes(head[dd_off + 8..dd_off + 12].try_into().ok()?);
    if import_rva == 0 {
        return Some(0);
    }
    if import_rva as u64 >= image.size_of_image as u64 {
        return None;
    }
    let mut desc = [0u8; 20];
    if debugger
        .read_memory(image.base as usize + import_rva as usize, &mut desc)
        .is_err()
    {
        return None;
    }
    if desc.iter().all(|&b| b == 0) {
        Some(import_rva)
    } else {
        None
    }
}

/// Find the IAT by stub references and capture it with slot resolutions.
///
/// Returns `Ok(None)` when the image does not carry the scrubbed-descriptor
/// shape (not a V2 payload — callers skip without logging an error), and
/// `Ok(Some((bin_path, txt_path)))` after writing the two sidecar files
/// derived from `base_path` (`<stem>.v2iat.bin` / `<stem>.v2iat.txt`).
pub fn capture_stub_iat(
    debugger: &mut dyn DebuggerCore,
    image: &MappedImage,
    base_path: &std::path::Path,
) -> Result<Option<(std::path::PathBuf, std::path::PathBuf)>, PeError> {
    let import_rva = match materialised_image_gate(debugger, image) {
        Some(rva) => rva,
        None => return Ok(None),
    };
    info!(
        base = format!("{:#x}", image.base),
        import_rva = format!("{import_rva:#x}"),
        "V2 IAT capture: materialised image with unusable import directory — scanning for stub references"
    );

    // 1. Read the full image (VA layout), page-by-page with tolerated
    //    failures (same discipline as `dump_mapped_image_raw`).
    let total = image.size_of_image as usize;
    let mut content = vec![0u8; total];
    for off in (0..total).step_by(0x1000) {
        let len = std::cmp::min(0x1000, total - off);
        let _ = debugger.read_memory(image.base as usize + off, &mut content[off..off + len]);
    }

    // 2. Collect `ff 15 [abs32]` (call) and `ff 25 [abs32]` (jmp) targets.
    //    These are 6-byte stubs; the abs32 operand is a live pointer into
    //    the shell's external IAT.
    let mut targets: Vec<u64> = Vec::new();
    for w in content.windows(6) {
        if w[0] == 0xFF && (w[1] == 0x15 || w[1] == 0x25) {
            let t = u32::from_le_bytes(w[2..6].try_into().expect("6-byte window")) as u64;
            if t > 0x10000 && t != 0xffff_ffff {
                targets.push(t);
            }
        }
    }
    if targets.is_empty() {
        warn!("V2 IAT capture: no ff 15/ff 25 stubs found in image — nothing to recover");
        return Ok(None);
    }
    targets.sort_unstable();
    targets.dedup();

    // 3. Largest cluster (gap tolerance 0x10000): the IAT is contiguous by
    //    construction; stray data references land far away or in tiny
    //    clusters.
    let mut best: (usize, usize) = (0, 1); // [start, end) index range into targets
    let mut start = 0;
    for i in 1..=targets.len() {
        if i == targets.len() || targets[i] - targets[i - 1] > 0x10000 {
            if i - start > best.1 - best.0 {
                best = (start, i);
            }
            start = i;
        }
    }
    let mut lo = targets[best.0];
    let mut hi = targets[best.1 - 1] + 4;

    // 4. Expand the boundaries: slots the payload never calls directly are
    //    still valid imports.  A slot belongs to the IAT while it holds an
    //    address inside a loaded module (terminators are zero and fail the
    //    check).
    let modules = take_module_snapshot(debugger.process_handle(), debugger.pid(), image.base, false)?;
    let in_module = |modules: &[RemoteModule], v: u64| -> bool {
        modules.iter().any(|m| v > m.base && v < m.end_off)
    };
    if modules.is_empty() {
        warn!("V2 IAT capture: module snapshot empty — boundaries stay at the referenced span");
    }
    let lo_floor = lo.saturating_sub(MAX_EXPAND).max(0x10000);
    while lo > lo_floor {
        let mut slot = [0u8; 4];
        if debugger.read_memory((lo - 4) as usize, &mut slot).is_err() {
            break;
        }
        let v = u32::from_le_bytes(slot) as u64;
        if v == 0 || !in_module(&modules, v) {
            break;
        }
        lo -= 4;
    }
    let hi_ceil = hi.saturating_add(MAX_EXPAND);
    while hi < hi_ceil {
        let mut slot = [0u8; 4];
        if debugger.read_memory(hi as usize, &mut slot).is_err() {
            break;
        }
        let v = u32::from_le_bytes(slot) as u64;
        if v == 0 || !in_module(&modules, v) {
            break;
        }
        hi += 4;
    }

    // 5. Read the exact IAT span.
    let span = (hi - lo) as usize;
    let mut iat = vec![0u8; span];
    let mut read_ok = true;
    for off in (0..span).step_by(0x1000) {
        let len = std::cmp::min(0x1000, span - off);
        if debugger
            .read_memory(lo as usize + off, &mut iat[off..off + len])
            .is_err()
        {
            read_ok = false;
        }
    }
    if !read_ok {
        warn!("V2 IAT capture: partial read of the IAT span — unresolved slots reported as zero");
    }

    // 6. Resolve every slot against the module snapshot.
    let mut lines = String::new();
    lines.push_str(&format!("# image_base {:#x}\n", image.base));
    lines.push_str(&format!("# import_rva {import_rva:#x}\n"));
    lines.push_str(&format!("# iat_lo {lo:#x}\n"));
    lines.push_str(&format!("# iat_hi {hi:#x}\n"));
    lines.push_str(&format!("# slot_count {}\n", span / 4));
    lines.push_str(&format!("# stub_refs {}\n", best.1 - best.0));
    let mut resolved = 0usize;
    for (idx, slot) in iat.chunks_exact(4).enumerate() {
        let v = u32::from_le_bytes(slot.try_into().expect("4-byte chunk")) as u64;
        let (module, func) = match modules.iter().find(|m| v > m.base && v < m.end_off) {
            Some(m) => match m.exports.get(&v) {
                Some(name) => (m.name(), name.as_str()),
                // Inside a module but not an export: thunk/forwarder tail.
                None => (m.name(), "-"),
            },
            None if v == 0 => ("-", "zero"),
            None => ("-", "unresolved"),
        };
        if func != "zero" && func != "unresolved" && func != "-" {
            resolved += 1;
        }
        lines.push_str(&format!("{idx} {:#x} {module} {func}\n", lo + 4 * idx as u64));
    }
    lines.push_str(&format!("# resolved {resolved}\n"));

    // 7. Write the sidecar files.  Derive from the dump file NAME (not
    //    `with_extension`, which would replace the numbered stem —
    //    `CISC-1U2.v2raw027` + "v2iat.bin" would clobber across
    //    candidates in one run).
    let stem = base_path.with_extension("");
    let mut bin_name = stem.file_name().expect("dump path has a file name").to_os_string();
    bin_name.push(".v2iat.bin");
    let mut txt_name = stem.file_name().expect("dump path has a file name").to_os_string();
    txt_name.push(".v2iat.txt");
    let bin_path = stem.with_file_name(bin_name);
    let txt_path = stem.with_file_name(txt_name);
    std::fs::write(&bin_path, &iat).map_err(PeError::Io)?;
    std::fs::write(&txt_path, lines).map_err(PeError::Io)?;
    info!(
        bin = %bin_path.display(),
        txt = %txt_path.display(),
        slots = span / 4,
        resolved,
        stub_refs = best.1 - best.0,
        iat_lo = format!("{lo:#x}"),
        iat_hi = format!("{hi:#x}"),
        "V2 IAT captured from stub references"
    );
    Ok(Some((bin_path, txt_path)))
}

/// Resolve every pointer-shaped DWORD in `buf` (a dump whose first byte
/// sits at `region_base`) against the live module snapshot's export
/// tables, and return the report.
///
/// Built for the SecureEngine 2.x payload rounds: the shell materialises
/// headless native code whose API calls go through a dense
/// `call [abs32]` page in the region following the code (measured
/// 2026-10-29 on CISC-1.exe: 272 distinct call targets in the 4 KB page
/// at 0x56162000, immediately after the 0x560b5000 code region).  The
/// resolved import NAMES identify what the materialised code is — shell
/// engine or original program — without any PE header to parse.
///
/// The measured instance of that page turned out to belong to **WeType
/// (微信输入法) injected worker threads** — the import profile
/// (crashrpt1500.dll, imm32.dll, input.dll, d2d1) is the IME stack's, and
/// `crashrpt1500.dll` exists on disk at
/// `C:\Program Files\Tencent\WeType\3.0.0.38\`.  `per_module` is exposed
/// so callers can run that classification themselves.
///
/// `skip_base` is passed to the module snapshot as the module to omit
/// (the packed main image).
pub struct PointerReport {
    /// Full text report (header lines + one line per resolved slot).
    pub text: String,
    /// Resolved-slot count per owning module name.
    pub per_module: std::collections::BTreeMap<String, usize>,
}

pub fn resolve_pointer_report(
    debugger: &mut dyn DebuggerCore,
    buf: &[u8],
    region_base: u64,
    skip_base: u64,
) -> Result<PointerReport, PeError> {
    let modules = take_module_snapshot(
        debugger.process_handle(),
        debugger.pid(),
        skip_base,
        false,
    )?;
    let mut lines = String::new();
    lines.push_str(&format!("# region_base {region_base:#x}\n"));
    lines.push_str(&format!("# dump_size {:#x}\n", buf.len()));
    lines.push_str(&format!("# modules {}\n", modules.len()));
    let mut resolved = 0usize;
    let mut in_module_unnamed = 0usize;
    // Per-module resolved-slot counts, so one glance says which DLL set
    // this pointer page belongs to.
    let mut per_module: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for (i, chunk) in buf.chunks_exact(4).enumerate() {
        let v = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk")) as u64;
        if v < 0x10000 {
            continue;
        }
        let owner = modules.iter().find(|m| v > m.base && v < m.end_off);
        let Some(m) = owner else { continue };
        match m.exports.get(&v) {
            Some(name) => {
                resolved += 1;
                *per_module.entry(m.name().to_string()).or_insert(0) += 1;
                lines.push_str(&format!(
                    "{:#x} {v:#x} {} {}\n",
                    region_base + 4 * i as u64,
                    m.name(),
                    name
                ));
            }
            None => {
                in_module_unnamed += 1;
                lines.push_str(&format!(
                    "{:#x} {v:#x} {} -\n",
                    region_base + 4 * i as u64,
                    m.name()
                ));
            }
        }
    }
    lines.push_str(&format!("# resolved {resolved}\n"));
    lines.push_str(&format!("# in_module_unnamed {in_module_unnamed}\n"));
    for (m, c) in &per_module {
        lines.push_str(&format!("# per_module {} {c}\n", m));
    }
    info!(
        region_base = format!("{region_base:#x}"),
        resolved,
        per_module = ?per_module.iter().map(|(k, v)| (k.clone(), *v)).collect::<Vec<_>>(),
        "V2 payload pointer page resolved"
    );
    Ok(PointerReport { text: lines, per_module })
}
