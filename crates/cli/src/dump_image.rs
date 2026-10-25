//! `/dump-image` — flatten a running process's loaded image to a file.
//!
//! ## Why this exists
//!
//! A `Packed` VMProtect sample has `SizeOfRawData == 0` on every original
//! code section: the file does not contain the code, and VMProtect's loader
//! rebuilds the image in memory.  Measured on `D:\Projects\zz_test.exe`:
//! `.text` (`virtual_size 0x12b05c`), `.rdata`, `.data`, `.pdata`, `.fptable`
//! and `.rdata0` are all absent from the file while `.rdata2` carries 21.4 MB
//! of packed blob.
//!
//! There is no static way back: VMProtect's unpacker is the only thing that
//! can materialise those sections, so the image has to be read out of a live
//! process.
//!
//! ## Debugger-free on purpose
//!
//! Measured: the same sample run under a debugger exits with `0xDEADBEEF`
//! (`3735929054`) at ~7 s, while a bare run of the same binary exits with `0`
//! — the debugger is the only changed variable.  So this path deliberately
//! does exactly what `/dump-process` does: `OpenProcess(PROCESS_QUERY_INFORMATION
//! | PROCESS_VM_READ)` plus `ReadProcessMemory`, and never `DebugActiveProcess`.
//!
//! ## Output shape
//!
//! A **flat image**: file offset equals RVA for every section, the headers sit
//! at offset 0.  This is the shape of the reference artefact this project was
//! given (`qidongqi\out\ida\main.exe`, 43,315,200 B, sha256 `b6355439…`,
//! where `.text` has `PointerToRawData == VirtualAddress == 0x1000` and
//! `.rdata2` `… == 0x73e000`).  Flat is also what keeps the copy usable: every
//! data-directory RVA still resolves, because RVA and offset coincide.

use std::path::Path;

use anyhow::anyhow;
use mida_pe::PeHeader;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ,
};

use crate::log::{self, LogType};

/// Largest single section read, as a guard against a bogus section table
/// asking for tens of gigabytes.
const MAX_SECTION_BYTES: u64 = 64 * 1024 * 1024;

/// Read a region page by page, zero-filling pages that cannot be read.
///
/// `ReadProcessMemory` fails the whole call if any byte is unreadable, and a
/// loaded image legitimately contains uncommitted pages (a `Packed` sample's
/// not-yet-touched regions, for instance).  A section-by-section
/// all-or-nothing read would therefore fail on exactly the samples this
/// command is for.
fn read_region(h: HANDLE, address: u64, len: usize) -> (Vec<u8>, usize) {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

    const PAGE: usize = 0x1000;
    let mut out = Vec::with_capacity(len);
    let mut unreadable = 0usize;

    let mut done = 0usize;
    while done < len {
        let take = PAGE.min(len - done);
        let mut page = [0u8; PAGE];
        let mut got = 0usize;
        // SAFETY: h is a valid process handle; `page` is valid for `take`
        // bytes; the address is inside the target's image.
        let ok = unsafe {
            ReadProcessMemory(
                h,
                (address + done as u64) as *const std::ffi::c_void,
                page.as_mut_ptr() as *mut std::ffi::c_void,
                take,
                Some(&mut got),
            )
            .is_ok()
        };
        if ok && got == take {
            out.extend_from_slice(&page[..take]);
        } else {
            unreadable += 1;
            out.extend_from_slice(&[0u8; PAGE][..take]);
        }
        done += take;
    }
    (out, unreadable)
}

/// `base` of the module whose file name matches `wanted`.
fn find_module_base(pid: u32, wanted: &str) -> Option<u64> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W,
        TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32,
    };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) }
        .ok()?;

    let mut entry = MODULEENTRY32W::default();
    entry.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;

    let mut found = None;
    let mut ok = unsafe { Module32FirstW(snap, &mut entry) }.is_ok();
    while ok {
        let name = String::from_utf16_lossy(&entry.szModule);
        if name.trim_end_matches('\0').eq_ignore_ascii_case(wanted) {
            found = Some(entry.modBaseAddr as u64);
            break;
        }
        ok = unsafe { Module32NextW(snap, &mut entry) }.is_ok();
    }

    // SAFETY: the snapshot handle came from CreateToolhelp32Snapshot and the
    // handle is not needed once we have stopped iterating.
    let _ = unsafe { CloseHandle(snap) };
    found
}

/// Undo an ASLR relocation so the dump matches the image's preferred base.
///
/// ## Why this is not optional
///
/// A live image's absolute pointers hold the **load** address.  Measured:
/// `伦伦软件.exe` loaded at `0x7ff789eb0000` instead of its preferred
/// `0x140000000`, and dumping it verbatim left `.rdata` with 7,479 bytes
/// differing from the file, `.data` 789, `.fptable` 72 and `.vmp0` 80 — while
/// `.text`, `.pdata`, `.reloc` and `.rsrc` were byte-identical.  A dump in that
/// form is only usable by a tool that already knows the live base, and every
/// pointer disagrees with the RVAs in its own headers.
///
/// Walking `.reloc` and subtracting the delta restores the "as loaded at the
/// preferred base" form.  That is also the form the sections present in the
/// file already have, so the two become comparable — which is how this
/// function is verified.
///
/// Returns `(patched, skipped)` where `skipped` counts entries whose type is
/// not `DIR64`/`HIGHLOW` or whose slot falls outside the buffer.
fn rebase_to_preferred(out: &mut [u8], pe: &PeHeader, delta: i64) -> (usize, usize) {
    /// Directory index of `.reloc`.
    const BASERELOC_DIRECTORY_INDEX: usize = 5;

    if delta == 0 {
        return (0, 0);
    }
    let dd = &pe.nt_headers.optional_header.data_directory[BASERELOC_DIRECTORY_INDEX];
    if dd.virtual_address == 0 || dd.size == 0 {
        return (0, 0);
    }
    apply_relocations(out, dd.virtual_address as usize, dd.size as usize, delta)
}

/// Walk an `IMAGE_BASE_RELOCATION` table that lives at `reloc_rva` inside the
/// (flat) buffer and subtract `delta` from every relocated slot.
///
/// Split out from [`rebase_to_preferred`] so it can be tested without a PE
/// fixture: the table is just bytes at an offset.
///
/// Returns `(patched, skipped)`.
fn apply_relocations(out: &mut [u8], reloc_rva: usize, reloc_size: usize, delta: i64) -> (usize, usize) {
    const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
    const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
    const IMAGE_REL_BASED_DIR64: u16 = 10;

    // Nothing to undo.  Short-circuiting here rather than only in the caller
    // keeps "patched" meaningful: subtracting zero changes no byte, so
    // reporting patches would be a lie.
    if delta == 0 {
        return (0, 0);
    }

    let start = reloc_rva;
    let end = start.saturating_add(reloc_size);
    let mut off = start;
    let mut patched = 0usize;
    let mut skipped = 0usize;

    while off + 8 <= end && off + 8 <= out.len() {
        let page = u32::from_le_bytes([out[off], out[off + 1], out[off + 2], out[off + 3]]);
        let block_size =
            u32::from_le_bytes([out[off + 4], out[off + 5], out[off + 6], out[off + 7]]) as usize;
        if block_size < 8 {
            break;
        }
        let entries = (block_size - 8) / 2;

        for i in 0..entries {
            let at = off + 8 + i * 2;
            if at + 2 > out.len() || at >= end {
                break;
            }
            let entry = u16::from_le_bytes([out[at], out[at + 1]]);
            let slot = page as usize + (entry & 0x0fff) as usize;
            match entry >> 12 {
                IMAGE_REL_BASED_DIR64 => {
                    if slot + 8 <= out.len() {
                        let v = i64::from_le_bytes(out[slot..slot + 8].try_into().unwrap());
                        out[slot..slot + 8].copy_from_slice(&(v - delta).to_le_bytes());
                        patched += 1;
                    } else {
                        skipped += 1;
                    }
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    if slot + 4 <= out.len() {
                        let v = i32::from_le_bytes(out[slot..slot + 4].try_into().unwrap()) as i64;
                        out[slot..slot + 4]
                            .copy_from_slice(&((v - delta) as i32).to_le_bytes());
                        patched += 1;
                    } else {
                        skipped += 1;
                    }
                }
                IMAGE_REL_BASED_ABSOLUTE => {}
                _ => skipped += 1,
            }
        }
        off += block_size;
    }

    (patched, skipped)
}

fn align_up(value: u32, alignment: u32) -> u32 {
    if alignment == 0 {
        return value;
    }
    value.div_ceil(alignment) * alignment
}

/// Flatten the loaded image of `pid` into `output` **once**, immediately.
///
/// Kept for callers that know the image is already settled.  Prefer
/// [`dump_image_stable`] for a `Packed` target, whose payload is decrypted in
/// place after start-up.
pub fn dump_image(pid: u32, output: &Path) -> Result<(), anyhow::Error> {
    // SAFETY: pid is a valid OS process id; the handle is closed before return.
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| anyhow!("Cannot open process {pid}: {e}"))?;
    let result = read_image(h, pid).and_then(|image| write_image(&image, output));
    // SAFETY: the handle was opened by this function and is no longer needed.
    let _ = unsafe { CloseHandle(h) };
    result
}

/// The full path of the executable image behind `h`.
fn process_image_path(h: HANDLE) -> Option<std::path::PathBuf> {
    let mut path_buf: Vec<u16> = vec![0u16; 512];
    let mut len = path_buf.len() as u32;
    // SAFETY: h is valid; path_buf is valid and sized.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(path_buf.as_mut_ptr()),
            &mut len,
        )
    };
    if ok.is_err() || len == 0 {
        return None;
    }
    Some(std::path::PathBuf::from(String::from_utf16_lossy(
        &path_buf[..len as usize],
    )))
}

/// Read, rebase and flatten the loaded image of `pid` into memory.
///
/// Split from writing so a caller can sample it repeatedly and decide *when*
/// the image is worth keeping — see [`dump_image_stable`].
fn read_image(h: HANDLE, pid: u32) -> Result<Vec<u8>, anyhow::Error> {
    let mut path_buf: Vec<u16> = vec![0u16; 512];
    let mut len = path_buf.len() as u32;
    // SAFETY: h is valid; path_buf is valid and sized.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            windows::core::PWSTR(path_buf.as_mut_ptr()),
            &mut len,
        )
    };
    if ok.is_err() || len == 0 {
        return Err(anyhow!(
            "Cannot determine the image path for PID {pid} — the process may have \
             exited or access is denied"
        ));
    }
    let module_path = std::path::PathBuf::from(String::from_utf16_lossy(&path_buf[..len as usize]));
    let file_name = module_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| anyhow!("Image path '{}' has no file name", module_path.display()))?;

    let pe = PeHeader::from_file(&module_path)
        .map_err(|e| anyhow!("Failed to parse the PE of '{}': {e}", module_path.display()))?;

    let load_base = find_module_base(pid, &file_name).ok_or_else(|| {
        anyhow!(
            "Module '{file_name}' (PID {pid}) is not in the target's module list — \
             it may have exited, or the module list is not readable"
        )
    })?;

    let preferred = pe.image_base;
    let log_message = format!(
        "Image '{}' loaded at {load_base:#x} (preferred {preferred:#x}, ASLR delta {})",
        module_path.display(),
        if load_base == preferred {
            "0 — absolute pointers are already at their file values".to_string()
        } else {
            format!(
                "{:#x} — absolute pointers will be rebased back to the preferred base",
                load_base as i64 - preferred as i64
            )
        }
    );
    log::log(LogType::Info, &log_message);

    let section_alignment = pe.section_alignment.max(1);
    let file_alignment = pe.file_alignment.max(1);
    let size_of_headers = pe.nt_headers.optional_header.size_of_headers as usize;

    // Buffer big enough for the headers, every section, and the declared image.
    let mut need = pe.nt_headers.optional_header.size_of_image;
    for s in pe.sections.iter() {
        need = need.max(s.virtual_address.saturating_add(align_up(
            s.virtual_size.max(s.raw_size),
            section_alignment,
        )));
    }
    let total = align_up(need, file_alignment).max(size_of_headers as u32) as usize;

    let file_bytes = std::fs::read(&module_path)
        .map_err(|e| anyhow!("Failed to read '{}': {e}", module_path.display()))?;
    let mut out = vec![0u8; total];
    if size_of_headers <= file_bytes.len() {
        out[..size_of_headers].copy_from_slice(&file_bytes[..size_of_headers]);
    }

    log::log(
        LogType::Info,
        &format!(
            "Flattening {total} bytes ({total:#x}); headers at 0, section data at its own RVA"
        ),
    );

    let mut unreadable_total = 0usize;
    for s in pe.sections.iter() {
        let name = s.name.trim_matches(|c: char| c == '\0' || c == ' ');
        let want = s.virtual_size.max(s.raw_size) as u64;
        if want == 0 {
            continue;
        }
        let want = want.min(MAX_SECTION_BYTES) as usize;
        let (data, unreadable) = read_region(h, load_base + s.virtual_address as u64, want);
        unreadable_total += unreadable;

        let start = s.virtual_address as usize;
        if start + data.len() > out.len() {
            return Err(anyhow!(
                "section {name:?} at {:#x} runs past the {total}-byte image buffer",
                s.virtual_address
            ));
        }
        out[start..start + data.len()].copy_from_slice(&data);

        let raws = align_up(s.virtual_size.max(s.raw_size), section_alignment);
        log::log(
            LogType::Info,
            &format!(
                "  {name:12} rva {:#09x} {want:>9} B read ({raws:#x} raw), {unreadable} page(s) unreadable",
                s.virtual_address
            ),
        );
    }

    // Rewrite every section header so the file describes itself as a flat
    // image: `PointerToRawData == VirtualAddress`.
    //
    // Rebase first: the relocation walk reads `.reloc` out of this same buffer,
    // and the header fields it touches are not relocation slots.
    let delta = load_base as i64 - preferred as i64;
    if delta != 0 {
        let (patched, skipped) = rebase_to_preferred(&mut out, &pe, delta);
        log::log(
            LogType::Info,
            &format!(
                "Rebased to the preferred base: {patched} relocation slot(s) applied, \
                 {skipped} skipped — the dump now reads as if loaded at {preferred:#x}"
            ),
        );
    }

    let e_lfanew = pe.dos_header.e_lfanew as usize;
    let opt = pe.nt_headers.file_header.size_of_optional_header as usize;
    let section_table = e_lfanew + 4 + 20 + opt;
    for (i, s) in pe.sections.iter().enumerate() {
        let base = section_table + i * 40;
        if base + 40 > out.len() {
            break;
        }
        let raws = align_up(s.virtual_size.max(s.raw_size), section_alignment);
        out[base + 16..base + 20].copy_from_slice(&raws.to_le_bytes()); // SizeOfRawData
        out[base + 20..base + 24].copy_from_slice(&s.virtual_address.to_le_bytes()); // PointerToRawData
    }

    log::log(
        LogType::Info,
        &format!(
            "Flattened {total} bytes: {nsec} section(s), {unreadable_total} unreadable page(s)",
            nsec = pe.sections.len()
        ),
    );
    Ok(out)
}

/// Write an already-flattened image, then carve its payloads.
fn write_image(out: &[u8], output: &Path) -> Result<(), anyhow::Error> {
    let total = out.len();
    std::fs::write(output, out)
        .map_err(|e| anyhow!("Failed to write '{}': {e}", output.display()))?;

    log::log(
        LogType::Good,
        &format!("Wrote {total} bytes to {}", output.display()),
    );

    // Carve the embedded payloads out of the *dumped image*.
    //
    // In a flat image `file offset == RVA`, so a resource that the packer only
    // materialises at run time becomes extractable with the same code that
    // reads a file.  Measured on the `Packed` sample: the input file has
    // `0/12782080` bytes of `RT_RCDATA` id 131, while the dumped image yields
    // all 12,782,080 B — byte-identical (`14596cbd…`) to the payload inside the
    // reference image this project was given.
    carve_payloads(out, output);
    Ok(())
}

/// The old single-shot tail: read, then write.

/// Extract every large resource present in `image` next to `output`.
///
/// Failures are reported and swallowed: the image dump itself already
/// succeeded, and turning a carve failure into a non-zero exit would make a
/// usable product look like a failed run.
fn carve_payloads(image: &[u8], output: &Path) {
    use mida_packers_vmprotect::resources::large_resources;
    use mida_packers_vmprotect::{looks_like_pe_image, transform_for};

    let pe = match PeHeader::from_bytes(image) {
        Ok(pe) => pe,
        Err(e) => {
            log::log(
                LogType::Info,
                &format!("No payload carve: the dumped image does not parse ({e})"),
            );
            return;
        }
    };

    let resources = large_resources(&pe, image);
    if resources.is_empty() {
        return;
    }

    let dir = output.parent().unwrap_or_else(|| Path::new("."));
    let stem = output
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "dump".to_string());

    for r in &resources {
        let Some(bytes) = r.bytes(image) else {
            log::log(
                LogType::Info,
                &format!(
                    "Payload {} is not fully inside the dumped image ({}/{} B) — skipped",
                    describe(r),
                    r.bytes_in_file,
                    r.size
                ),
            );
            continue;
        };
        let path = dir.join(payload_name(&stem, r));
        match std::fs::write(&path, bytes) {
            Ok(()) => log::log(
                LogType::Good,
                &format!(
                    "Carved payload {} to {} ({} B, sha256 {})",
                    describe(r),
                    path.display(),
                    bytes.len(),
                    r.sha256.as_deref().unwrap_or("?")
                ),
            ),
            Err(e) => log::log(
                LogType::Warn,
                &format!("Cannot write {}: {e}", path.display()),
            ),
        }

        // A container is not a product.  When a measured transform exists for
        // this resource, apply it and accept the result only if it is a valid
        // PE image — a wrong key must be rejected by the data, not trusted.
        let Some(t) = transform_for(r.type_id, r.name_id) else {
            continue;
        };
        let decoded = t.apply(bytes);
        if !looks_like_pe_image(&decoded) {
            log::log(
                LogType::Warn,
                &format!(
                    "Transform for {} did not produce a PE image; keeping the container only. \
                     Key provenance: {}",
                    describe(r),
                    t.provenance
                ),
            );
            continue;
        }
        let decoded_path = dir.join(decoded_name(&stem, r));
        match std::fs::write(&decoded_path, &decoded) {
            Ok(()) => log::log(
                LogType::Good,
                &format!(
                    "Decoded payload {} to {} ({} B, sha256 {})",
                    describe(r),
                    decoded_path.display(),
                    decoded.len(),
                    sha256_hex(&decoded)
                ),
            ),
            Err(e) => log::log(
                LogType::Warn,
                &format!("Cannot write {}: {e}", decoded_path.display()),
            ),
        }
    }
}

/// `<stem>.rcdata<id>.decoded.exe` — the decoded form, kept beside the container
/// so the two can be compared byte for byte.
fn decoded_name(stem: &str, r: &mida_packers_vmprotect::resources::LargeResource) -> String {
    let id = r
        .name_id
        .map(|i| i.to_string())
        .unwrap_or_else(|| "named".to_string());
    format!("{stem}.rcdata{id}.decoded.exe")
}

fn describe(r: &mida_packers_vmprotect::resources::LargeResource) -> String {
    match (r.type_id, r.name_id) {
        (Some(t), Some(id)) => format!("type {t} id {id}"),
        (Some(t), None) => format!("type {t}"),
        _ => "resource".to_string(),
    }
}

/// `<stem>.rcdata<id>.<ext>`, with `.exe` when the payload is a PE image.
fn payload_name(stem: &str, r: &mida_packers_vmprotect::resources::LargeResource) -> String {
    let id = r
        .name_id
        .map(|i| i.to_string())
        .unwrap_or_else(|| "named".to_string());
    let ext = if r.looks_like_pe { "exe" } else { "bin" };
    format!("{stem}.rcdata{id}.{ext}")
}

/// How long to keep sampling for a stable image before giving up.
const STABLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How often to re-read the image while waiting for it to settle.
const STABLE_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// Consecutive identical samples required before the image is accepted.
const STABLE_SAMPLES: usize = 2;

/// Read the loaded image of `pid` repeatedly until the payloads it carries have
/// stopped changing, then flatten that.
///
/// ## Why a fixed delay does not work
///
/// The `Packed` sample rewrites its 12,782,080 B payload **in place** after it
/// starts.  Measured, sampling every 100 ms: `db4c050e…` (still zero-filled) at
/// t=0.02 s, then `b8991af0…`, `3e6f024f…`, `4aa50cf5…`, `2fd77393…`,
/// `36fb4454…`, `0a6a75e1…`, `73bafb30…`, `8f4c94ab…`, and finally `14596cbd…`
/// at t≈1.65 s — after which it does not change again before the process exits
/// at t≈6.6 s.  A dump at the wrong moment captures one of the intermediate
/// values and looks entirely plausible.
///
/// ## Why "two identical samples" alone is not enough
///
/// The first two samples can both be the *untouched* file bytes, so a naive
/// stability check succeeds before decryption has even started.  Measured: that
/// produced payload hashes `fcee1cb1…` and "no payload at all" across runs.
///
/// The fix is to derive, from the input file itself, what the payload looks like
/// **before** the packer touches it, and require the image's copy to differ from
/// that — plus stability.  It needs no knowledge of the cipher and no clock.
pub fn dump_image_stable(pid: u32, output: &Path) -> Result<(), anyhow::Error> {
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| anyhow!("Cannot open process {pid}: {e}"))?;
    let result = dump_stable_inner(h, pid, output);
    let _ = unsafe { CloseHandle(h) };
    result
}

/// Bytes of the input file as they would appear at each payload's RVA.
///
/// A payload's `data_rva` is an RVA into the *image*; the file only holds the
/// part of that range that a section's raw data covers.  Everything else reads
/// as zero, which is exactly what the loader would have produced.
fn pre_decryption_payloads(pe: &PeHeader, file: &[u8]) -> Vec<(u32, Vec<u8>)> {
    use mida_packers_vmprotect::resources::large_resources;

    large_resources(pe, file)
        .into_iter()
        .filter_map(|r| {
            let start = r.data_rva as usize;
            let end = start.checked_add(r.size as usize)?;
            let mut buf = vec![0u8; r.size as usize];
            for s in pe.sections.iter() {
                let s_va = s.virtual_address as usize;
                let s_end = s_va.checked_add(s.virtual_size.max(s.raw_size) as usize)?;
                let lo = start.max(s_va);
                let hi = end.min(s_end);
                if lo >= hi || s.raw_size == 0 {
                    continue;
                }
                // Only the part covered by raw data exists in the file.
                let raw_end = s_va + s.raw_size as usize;
                let hi = hi.min(raw_end);
                if lo >= hi {
                    continue;
                }
                let from = s.raw_offset as usize + (lo - s_va);
                let to = from + (hi - lo);
                if to > file.len() {
                    continue;
                }
                buf[lo - start..hi - start].copy_from_slice(&file[from..to]);
            }
            Some((r.data_rva, buf))
        })
        .collect()
}

/// `true` when every payload in `image` differs from its pre-decryption form.
fn payloads_moved(image: &[u8], expected: &[(u32, Vec<u8>)]) -> bool {
    if expected.is_empty() {
        return true;
    }
    expected.iter().all(|(rva, before)| {
        let start = *rva as usize;
        match image.get(start..start + before.len()) {
            Some(now) => now != before.as_slice(),
            None => false,
        }
    })
}

fn dump_stable_inner(h: HANDLE, pid: u32, output: &Path) -> Result<(), anyhow::Error> {
    use std::time::Instant;

    let started = Instant::now();
    let mut previous: Option<Vec<u8>> = None;
    let mut same = 0usize;
    let mut attempt = 0usize;
    let mut expected: Option<Vec<(u32, Vec<u8>)>> = None;

    loop {
        attempt += 1;
        match read_image(h, pid) {
            Ok(image) => {
                // The input file is read once, lazily: it is only needed to tell
                // "the packer has touched this" from "this is still the file".
                if expected.is_none() {
                    expected = Some(match process_image_path(h) {
                        Some(p) => match (PeHeader::from_file(&p), std::fs::read(&p)) {
                            (Ok(pe), Ok(file)) => pre_decryption_payloads(&pe, &file),
                            _ => Vec::new(),
                        },
                        None => Vec::new(),
                    });
                }
                let expected_ref = expected.as_deref().unwrap_or(&[]);
                let moved = payloads_moved(&image, expected_ref);

                let digest = sha256_hex(&image);
                if let Some(prev) = &previous {
                    if *prev == image {
                        same += 1;
                    } else {
                        same = 0;
                    }
                }
                previous = Some(image);

                let elapsed = started.elapsed();
                if moved && same + 1 >= STABLE_SAMPLES {
                    log::log(
                        LogType::Info,
                        &format!(
                            "Image settled after {attempt} sample(s) in {:.2}s (sha256 {digest})",
                            elapsed.as_secs_f32()
                        ),
                    );
                    break;
                }
                if elapsed >= STABLE_TIMEOUT {
                    log::log(
                        LogType::Warn,
                        &format!(
                            "Image still changing after {:.0}s ({attempt} samples, last sha256 \
                             {digest}, payloads {}); dumping it anyway — the payload may be \
                             mid-decryption",
                            elapsed.as_secs_f32(),
                            if moved { "have changed" } else { "are still the file's bytes" }
                        ),
                    );
                    break;
                }
                std::thread::sleep(STABLE_INTERVAL);
            }
            Err(e) => {
                // A sample already in hand beats no product at all.  Measured:
                // this sample family exits a couple of seconds after start-up,
                // and the first version of this loop turned "the process went
                // away between samples" into a fatal error that discarded a
                // perfectly good 43,315,200-byte image.
                if previous.is_some() {
                    log::log(
                        LogType::Warn,
                        &format!(
                            "The process went away between samples ({e}); writing the last \
                             complete image instead"
                        ),
                    );
                    break;
                }
                return Err(e);
            }
        }
    }

    let image = previous.expect("the loop always assigns at least one sample");
    write_image(&image, output)
}

/// SHA-256 of `bytes`, lowercase hex.  Small local helper so this module does
/// not need a dependency the rest of the CLI does not use.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Measured on `伦伦软件.exe`: loaded at `0x7ff789eb0000` instead of the
    /// preferred `0x140000000`.
    const LOAD: u64 = 0x7ff7_89eb_0000;
    const PREFERRED: u64 = 0x0000_0001_4000_0000;

    /// One block at `rva` containing `entries` as `(type, offset)` pairs, all in
/// page 0 so each entry's slot is exactly its offset.
    fn block_with(rva: usize, entries: &[(u16, u16)]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x100];
        let size = (8 + entries.len() * 2) as u32;
        buf[rva..rva + 4].copy_from_slice(&0u32.to_le_bytes()); // page rva 0
        buf[rva + 4..rva + 8].copy_from_slice(&size.to_le_bytes());
        for (i, (typ, off)) in entries.iter().enumerate() {
            let at = rva + 8 + i * 2;
            buf[at..at + 2].copy_from_slice(&((typ << 12) | off).to_le_bytes());
        }
        buf
    }

    /// The table used by most of these tests: a DIR64 slot at `0x40`, a HIGHLOW
    /// slot at `0x50` and an ABSOLUTE (padding) entry at `0x60`.  Distinct
    /// offsets matter — two entries on the same slot would patch each other.
    fn mixed_block(rva: usize) -> Vec<u8> {
        block_with(rva, &[(10, 0x40), (3, 0x50), (0, 0x60)])
    }

    #[test]
    fn apply_relocations_subtracts_the_delta_from_dir64_and_higlow_slots() {
        let mut buf = mixed_block(0x10);
        // A pointer into the image at its *load* address, and the 32-bit form.
        buf[0x40..0x48].copy_from_slice(&(LOAD + 0x40).to_le_bytes());
        buf[0x50..0x54].copy_from_slice(&((LOAD as u32) + 0x50).to_le_bytes());
        buf[0x60..0x68].copy_from_slice(&0xdead_beef_0000_0000u64.to_le_bytes());

        let delta = LOAD as i64 - PREFERRED as i64;
        let (patched, skipped) = apply_relocations(&mut buf, 0x10, 16, delta);

        assert_eq!(patched, 2);
        assert_eq!(skipped, 0);
        assert_eq!(
            u64::from_le_bytes(buf[0x40..0x48].try_into().unwrap()),
            PREFERRED + 0x40,
            "a DIR64 slot must end up at the preferred base"
        );
        assert_eq!(
            u32::from_le_bytes(buf[0x50..0x54].try_into().unwrap()),
            (PREFERRED as u32) + 0x50
        );
        // IMAGE_REL_BASED_ABSOLUTE means "padding", never a slot to patch.
        assert_eq!(
            u64::from_le_bytes(buf[0x60..0x68].try_into().unwrap()),
            0xdead_beef_0000_0000
        );
    }

    #[test]
    fn apply_relocations_is_a_no_op_for_a_zero_delta_or_an_empty_table() {
        let mut buf = mixed_block(0x10);
        buf[0x40..0x48].copy_from_slice(&(LOAD + 0x40).to_le_bytes());
        let before = buf.clone();

        assert_eq!(apply_relocations(&mut buf, 0x10, 16, 0), (0, 0));
        assert_eq!(buf, before);
        // A table of zero bytes, and one whose header cannot be read.
        assert_eq!(apply_relocations(&mut buf, 0x10, 0, 1234), (0, 0));
        assert_eq!(apply_relocations(&mut buf, 0xfe, 16, 1234), (0, 0));
    }

    #[test]
    fn apply_relocations_skips_slots_that_fall_outside_the_buffer() {
        // A block claiming a slot far past the end: counted as skipped, never a
        // panic and never a silent out-of-range write.
        let mut buf = block_with(0x10, &[(10, 0xff0), (3, 0x50), (0, 0x60)]);
        assert_eq!(apply_relocations(&mut buf, 0x10, 16, 1234), (1, 1));

        // A block size that is not even a header is a corrupt table: stop.
        let mut buf = mixed_block(0x10);
        buf[0x14..0x18].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(apply_relocations(&mut buf, 0x10, 16, 1234), (0, 0));
    }

    #[test]
    fn measured_values_from_the_live_dump_round_trip() {
        // The exact delta measured on the 伦伦 dump.  Applying it and then
        // undoing it must return the original value, which is what makes the
        // rebase safe to offer as the default.
        let delta = LOAD as i64 - PREFERRED as i64;
        let mut buf = block_with(0x10, &[(10, 0x40)]);
        buf[0x40..0x48].copy_from_slice(&(LOAD + 0x1000).to_le_bytes());

        assert_eq!(apply_relocations(&mut buf, 0x10, 16, delta), (1, 0));
        assert_eq!(
            u64::from_le_bytes(buf[0x40..0x48].try_into().unwrap()),
            PREFERRED + 0x1000
        );

        assert_eq!(apply_relocations(&mut buf, 0x10, 16, -delta), (1, 0));
        assert_eq!(
            u64::from_le_bytes(buf[0x40..0x48].try_into().unwrap()),
            LOAD + 0x1000
        );
    }
}