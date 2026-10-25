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

/// Flatten the loaded image of `pid` into `output`.
///
/// # Errors
///
/// Returns an error when the process cannot be opened, its image path cannot
/// be determined, the module cannot be found in the target's module list, the
/// PE cannot be parsed, or the output cannot be written.
pub fn dump_image(pid: u32, output: &Path) -> Result<(), anyhow::Error> {
    // SAFETY: pid is a valid OS process id; the handle is closed before return.
    let h = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) }
        .map_err(|e| anyhow!("Cannot open process {pid}: {e}"))?;
    let result = dump_image_inner(h, pid, output);
    // SAFETY: the handle was opened by this function and is no longer needed.
    let _ = unsafe { CloseHandle(h) };
    result
}

fn dump_image_inner(h: HANDLE, pid: u32, output: &Path) -> Result<(), anyhow::Error> {
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

    std::fs::write(output, &out)
        .map_err(|e| anyhow!("Failed to write '{}': {e}", output.display()))?;

    log::log(
        LogType::Good,
        &format!(
            "Wrote {total} bytes to {} ({} section(s), {unreadable_total} unreadable page(s))",
            output.display(),
            pe.sections.len()
        ),
    );
    Ok(())
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