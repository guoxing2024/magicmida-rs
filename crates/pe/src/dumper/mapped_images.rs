//! Scan a live process's address space for MZ+PE images.
//!
//! Used to locate Themida 1.1.1 shells' materialised original program: the
//! shell decompresses the program into a file mapping and executes it from
//! there, so the classic `.text` guard path (write faults on the packed
//! image's first section) never fires — the program simply runs and exits.
//! At the moment the shell's first `CloseHandle` lands (decompression
//! complete, program about to run) this scan finds the image and the
//! pipeline dumps it directly.
//!
//! Measured shape (2026-10-27, t111.exe): the original program appears as a
//! `MEM_MAPPED` view whose PE header carries `AddressOfEntryPoint = 0`
//! (the shell keeps the real OEP in its own records) and no import
//! directory (the shell resolved the imports itself).  The scan reports the
//! header facts; the caller decides which image is the program.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_MAPPED, MEM_PRIVATE, VirtualQueryEx,
};

use crate::error::PeError;
use mida_core::DebuggerCore;

use super::helpers::{read_ptr, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE};
use super::remote_modules::take_module_snapshot;
use super::types::{is_api_address, RemoteModule};

/// One MZ+PE image found in the target's address space.
#[derive(Debug, Clone)]
pub struct MappedImage {
    /// Base address of the image.
    pub base: u64,

    /// Region size as reported by `VirtualQueryEx`.
    pub region_size: u64,

    /// `SizeOfImage` from the image's own optional header.
    pub size_of_image: u32,

    /// `AddressOfEntryPoint` RVA (0 when the header scrubbed it).
    pub entry_point: u32,

    /// Import directory RVA/size from the image's optional header.
    pub import_rva: u32,
    pub import_size: u32,

    /// Section table: (name, virtual address, virtual size).
    pub sections: Vec<(String, u32, u32)>,

    /// `MEM_MAPPED` (file view) or `MEM_PRIVATE` (VirtualAlloc).
    pub is_mapped: bool,
}

/// Walk the target's committed regions and return every one whose head
/// contains an MZ+PE signature.
///
/// The walk covers the full 32-bit address space (`0..0x7FFFFFFF`): classic
/// v1 targets are 32-bit, and that is the only caller.  For a 64-bit target
/// the caller should bound the walk itself.
pub fn scan_mapped_images(
    debugger: &mut dyn DebuggerCore,
    _is_64bit: bool,
) -> Result<Vec<MappedImage>, PeError> {
    let h_process: HANDLE = debugger.process_handle();

    let mut images: Vec<MappedImage> = Vec::new();
    let mut addr: usize = 0;

    while addr < 0x7FFF_FFFF {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let rc = unsafe {
            VirtualQueryEx(
                h_process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if rc != std::mem::size_of::<MEMORY_BASIC_INFORMATION>() {
            // At `ExitProcess` the debuggee is in teardown and some
            // regions may already be freed, causing `VirtualQueryEx`
            // to return 0 for those addresses.  The old code `break`
            // on the first failure, which meant the scan returned
            // `Ok(vec![])` (or fewer images than were actually
            // present) right when the last-chance dump needed it
            // most.  Skip forward by one page and keep walking.
            addr = addr.checked_add(0x1000).unwrap_or(0x7FFF_FFFF);
            continue;
        }

        if mbi.State == MEM_COMMIT && (mbi.RegionSize as u64) >= 0x1000 {
            let region_base = mbi.BaseAddress as u64;
            let mut head = [0u8; 0x400];
            let read = debugger.read_memory(region_base as usize, &mut head);
            if let Ok(n) = read {
                if n >= 0x100 {
                    if let Some(mz_off) = find_mz(&head[..n]) {
                        if let Some(img) = parse_image(&head[..n], mz_off, region_base, mbi.RegionSize as u64, mbi.Type == MEM_MAPPED) {
                            images.push(img);
                        }
                    }
                }
            }
        }

        addr = mbi.BaseAddress as usize + mbi.RegionSize as usize;
    }

    Ok(images)
}

/// Deep scan: find MZ+PE images ANYWHERE inside committed `MEM_PRIVATE`
/// regions — not just at region heads.
///
/// [`scan_mapped_images`] reads the first 0x400 bytes of each region; a PE
/// decompressed into the MIDDLE of a shell workspace region (Themida 1.8.2's
/// payload lives around 0x12xxxxx inside a large private allocation) is
/// invisible to it.  This walk probes every page of every private region
/// for the `MZ` signature, then parses a full header on a hit.
///
/// Cost is bounded by private-region size (the 1.8.2 workspace is ~0x200000:
/// ~512 page probes per scan, ~1–2 ms).  Only `MEM_PRIVATE` is probed —
/// module-backed (`MEM_IMAGE`) and file-backed (`MEM_MAPPED`) regions are
/// covered by the head scan and the module list.
pub fn scan_private_images(
    debugger: &mut dyn DebuggerCore,
) -> Result<Vec<MappedImage>, PeError> {
    let h_process: HANDLE = debugger.process_handle();

    let mut images: Vec<MappedImage> = Vec::new();
    let mut addr: usize = 0;

    while addr < 0x7FFF_FFFF {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let rc = unsafe {
            VirtualQueryEx(
                h_process,
                Some(addr as *const _),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if rc != std::mem::size_of::<MEMORY_BASIC_INFORMATION>() {
            addr = addr.checked_add(0x1000).unwrap_or(0x7FFF_FFFF);
            continue;
        }
        let region_base = mbi.BaseAddress as usize;
        let region_size = mbi.RegionSize as usize;
        let next_region = region_base.checked_add(region_size).unwrap_or(0x7FFF_FFFF);

        // Probe only committed private regions large enough to hold an image.
        if mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && region_size >= 0x10000 {
            let mut page = 0usize;
            while page + 0x400 <= region_size {
                let mut head = [0u8; 0x400];
                let ok = matches!(
                    debugger.read_memory(region_base + page, &mut head),
                    Ok(n) if n >= 0x200
                );
                if ok {
                    if let Some(mz_off) = find_mz(&head) {
                        if head[mz_off] == b'M' {
                            if let Some(img) = parse_image(
                                &head,
                                mz_off,
                                (region_base + page) as u64,
                                (region_size - page) as u64,
                                false,
                            ) {
                                images.push(img);
                            }
                        }
                    }
                }
                page += 0x1000;
            }
        }

        addr = next_region;
    }

    Ok(images)
}

/// First offset of an MZ signature in `buf`, or `None`.
fn find_mz(buf: &[u8]) -> Option<usize> {
    buf.iter().position(|&b| b == b'M').and_then(|i| {
        if i + 1 < buf.len() && buf[i + 1] == b'Z' {
            Some(i)
        } else {
            None
        }
    })
}

/// Parse the PE at `mz_off` inside `buf` (which starts at the region base).
fn parse_image(
    buf: &[u8],
    mz_off: usize,
    base: u64,
    region_size: u64,
    is_mapped: bool,
) -> Option<MappedImage> {
    let need = mz_off + 0x400;
    if buf.len() < need {
        return None;
    }
    let el = mz_off + 0x3C;
    let e_lfanew = u32::from_le_bytes(
        buf[el..el + 4].try_into().ok()?,
    ) as usize;
    let pe_off = mz_off + e_lfanew;
    if pe_off + 0x200 > buf.len() || buf[pe_off] != b'P' || buf[pe_off + 1] != b'E' {
        return None;
    }

    let opt = pe_off + 24;
    let magic = u16::from_le_bytes(buf[opt..opt + 2].try_into().ok()?);
    let is64 = magic == 0x20B;

    let size_of_image = u32::from_le_bytes(buf[opt + 56..opt + 60].try_into().ok()?);
    let entry_point = u32::from_le_bytes(buf[opt + 16..opt + 20].try_into().ok()?);

    // Import directory: data directory 0.  The VirtualAddress is at
    // dd_off + 0, the Size at dd_off + 4 (each entry is 8 bytes: 4 RVA
    // + 4 Size).  An earlier revision read dd_off + 8, which is the
    // *Export* directory — the filter then matched system DLLs whose
    // export RVA happened to be zero.
    let dd_off = opt + if is64 { 112 } else { 96 };
    let import_rva = u32::from_le_bytes(
        buf[dd_off..dd_off + 4].try_into().ok()?,
    );
    let import_size = u32::from_le_bytes(
        buf[dd_off + 4..dd_off + 8].try_into().ok()?,
    );

    // Section table.
    let nsec = u16::from_le_bytes(buf[pe_off + 6..pe_off + 8].try_into().ok()?);
    let size_of_opt = u16::from_le_bytes(buf[pe_off + 20..pe_off + 22].try_into().ok()?);
    let sec_off = opt + size_of_opt as usize;
    let mut sections = Vec::with_capacity(nsec as usize);
    for i in 0..nsec {
        let so = sec_off + 40 * i as usize;
        if so + 40 > buf.len() {
            break;
        }
        let name: String = buf[so..so + 8]
            .iter()
            .map(|&b| if b >= 32 && b < 127 { b as char } else { '.' })
            .collect();
        let va = u32::from_le_bytes(buf[so + 12..so + 16].try_into().ok()?);
        let vs = u32::from_le_bytes(buf[so + 8..so + 12].try_into().ok()?);
        sections.push((name, va, vs));
    }

    Some(MappedImage {
        base,
        region_size,
        size_of_image,
        entry_point,
        import_rva,
        import_size,
        sections,
        is_mapped,
    })
}

/// Locate the IAT inside a mapped image's content: the longest run of
/// API-address slots across the image's sections.
///
/// The shell resolves the program's imports itself and writes the resolved
/// addresses back into the image's IAT slots, but scrubs the PE header's
/// import directory — so the location must be found by content, exactly
/// like the main-image IAT scan, just on the mapped buffer.
fn locate_iat_rva(
    content: &[u8],
    modules: &[RemoteModule],
    is_64bit: bool,
) -> Result<(u32, usize), PeError> {
    let ptr = if is_64bit { 8 } else { 4 };

    let e_lfanew = u32::from_le_bytes(
        content[0x3C..0x40].try_into().map_err(|_| PeError::Parse("short header".into()))?,
    ) as usize;
    if e_lfanew + 0x200 > content.len() || content[e_lfanew] != b'P' {
        return Err(PeError::Parse("no PE signature in mapped image".into()));
    }
    let nsec = u16::from_le_bytes(
        content[e_lfanew + 6..e_lfanew + 8]
            .try_into()
            .map_err(|_| PeError::Parse("short header".into()))?,
    ) as usize;
    let soh = e_lfanew
        + 20
        + u16::from_le_bytes(
            content[e_lfanew + 20..e_lfanew + 22]
                .try_into()
                .map_err(|_| PeError::Parse("short header".into()))?,
        ) as usize;

    let mut best: Option<(u32, usize)> = None;
    for i in 0..nsec {
        let so = soh + 40 * i;
        if so + 40 > content.len() {
            break;
        }
        let vs = u32::from_le_bytes(content[so + 8..so + 12].try_into().ok().unwrap_or([0; 4]));
        let va = u32::from_le_bytes(content[so + 12..so + 16].try_into().ok().unwrap_or([0; 4]));
        // In-memory the raw pointer equals the VA; the content buffer is the
        // image's memory, so section content sits at `va`.
        let sec_off = va as usize;
        let sec_end = (sec_off + vs as usize).min(content.len());

        let mut run_start: Option<usize> = None;
        let mut best_run = 0usize;
        let mut best_rva = 0u32;
        let mut off = sec_off;
        while off + ptr <= sec_end {
            let val = read_ptr(content, off, is_64bit);
            if is_api_address(modules, val) {
                if run_start.is_none() {
                    run_start = Some(off);
                }
                let len = off - run_start.unwrap() + ptr;
                if len > best_run {
                    best_run = len;
                    best_rva = va + (off - sec_off) as u32;
                }
            } else {
                run_start = None;
            }
            off += ptr;
        }
        if best_run > 0 && best.map_or(true, |(_, l)| best_run > l) {
            best = Some((best_rva, best_run));
        }
    }

    best.ok_or_else(|| PeError::Parse("no IAT found in mapped image".into()))
}

/// Dump the materialised original program straight from its file mapping:
/// read the image, patch the header (entry point, base, ASLR), rebuild the
/// imports from the mapped IAT, and write the product.
///
/// This replaces the classic `.text` guard chain for Themida 1.1.1-shape
/// shells: the shell decompresses the program into a mapping and jumps to it
/// — there is no in-place decompression for the guard to catch, and the
/// mapped image's own header is the cleanest source for the product.
pub fn dump_mapped_image_product(
    debugger: &mut dyn DebuggerCore,
    image: &MappedImage,
    oep_rva: u32,
    classic_imports: bool,
    output_path: &std::path::Path,
) -> Result<(), PeError> {
    use tracing::{info, warn};

    // 1. Read the mapped image content.
    let mut content = vec![0u8; image.size_of_image as usize];
    let read = debugger
        .read_memory(image.base as usize, &mut content)
        .map_err(|e| PeError::Parse(format!("Failed to read mapped image: {e}")))?;
    if read < content.len() {
        warn!(expected = content.len(), actual = read, "Short read on mapped image");
    }

    // 2. Parse + patch the header.
    let mut pe = crate::header::PeHeader::from_bytes(&content[..0x400])
        .map_err(|e| PeError::Parse(format!("Mapped image header: {e}")))?;
    pe.nt_headers.optional_header.address_of_entry_point = oep_rva;
    pe.nt_headers.optional_header.image_base = 0x400000;
    pe.nt_headers.optional_header.dll_characteristics &= !IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;

    let is_64bit = pe.is_64bit;

    // 3. Locate the IAT inside the mapped image.
    let modules = take_module_snapshot(
        debugger.process_handle(),
        debugger.pid(),
        image.base,
        is_64bit,
    )?;
    let (iat_rva, iat_size) = locate_iat_rva(&content, &modules, is_64bit)?;
    info!(
        iat = %format!("{iat_rva:#x}"),
        size = %format!("{iat_size:#x}"),
        "IAT located in mapped image",
    );

    // 4. Rebuild the imports from the mapped IAT.
    let iat_override = Some((image.base as usize + iat_rva as usize, iat_size));
    let (_iat_image, _iat_image_size, import_builder) =
        crate::dumper::import_rebuild::rebuild_import_table_complete(
            debugger,
            &mut pe,
            image.base,
            is_64bit,
            iat_override,
            classic_imports,
        )?;

    // 5. Assemble the product (same tail as the main-image dump).
    pe.sanitize();

    let original_iat_rva = iat_rva;
    let mut import_thunks: Vec<u64> = Vec::new();
    if let Some(ref builder) = import_builder {
        let (thunks, _section_idx) = crate::dumper::import_section::create_import_section(
            &mut pe,
            builder,
            original_iat_rva,
            &mut content,
            is_64bit,
            classic_imports,
        );
        import_thunks = thunks;
    }

    let opts = crate::dumper::types::DumpOptions {
        image_base: 0x400000,
        entry_point: oep_rva,
        fix_imports: true,
        create_data_sections: false,
        shrink: false,
        output_path: output_path.to_path_buf(),
        iat_location: iat_override,
        classic_imports,
        additional_iat_locations: Vec::new(),
        executable_path: None,
    };

    let mut out_data = crate::dumper::output_writer::write_output_file(
        &mut pe,
        &content,
        import_builder.as_ref(),
        &import_thunks,
        original_iat_rva,
        is_64bit,
        &opts,
    )?;

    // Rebase the image's internal absolute pointers from the mapped base
    // (e.g. 0x61b20000) to the product's 0x400000.
    crate::postprocess::fix_hardcoded_addresses(&mut out_data, Some(image.base), is_64bit)?;
    crate::postprocess::build_relocation_table(&mut out_data, None, is_64bit)?;

    std::fs::write(output_path, &out_data)
        .map_err(|e| PeError::Io(e))?;

    info!(
        path = %output_path.display(),
        size = out_data.len(),
        "Mapped image product written",
    );
    Ok(())
}

/// Dump the raw bytes of a mapped image to a file, for offline
/// post-processing.
///
/// When the in-pipeline OEP discovery (single-stepping into the image) fails
/// — the shell's main thread may have already jumped through the image and
/// exited before TF could catch it — the raw image bytes are still the
/// original program, just without a patched header or rebuilt imports.  This
/// function writes them verbatim; an offline script can then locate the
/// MZ+PE, parse the header, find the IAT by content, and run the same
/// product-assembly logic that [`dump_mapped_image_product`] does in-pipeline.
///
/// The output path is derived from `output_path` by replacing the extension
/// with `raw.bin` (e.g. `t111U.exe` → `t111U.raw.bin`).
///
/// Also writes a module snapshot next to the raw dump (`<stem>.raw.modules.txt`)
/// so an offline script can resolve IAT slots to module names and function
/// names without a live process.
pub fn dump_mapped_image_raw(
    debugger: &mut dyn DebuggerCore,
    image: &MappedImage,
    output_path: &std::path::Path,
) -> Result<std::path::PathBuf, PeError> {
    use tracing::{info, warn};

    let total = image.size_of_image as usize;
    let mut content = vec![0u8; total];

    // At `ExitProcess` the debuggee is in teardown and some pages may
    // already be freed, causing a single large `read_memory` to fail
    // entirely (measured: "Failed to read memory at 0x2990000
    // (requested 720896 bytes)").  Read page-by-page (0x1000) and
    // skip failures — the offline script can still work with partial
    // data (the MZ+PE header and section table are almost always
    // intact because they are in the first few pages).
    let page_size = 0x1000usize;
    let mut pages_read = 0usize;
    let mut pages_failed = 0usize;
    let mut failed_offsets: Vec<usize> = Vec::new();
    for off in (0..total).step_by(page_size) {
        let len = std::cmp::min(page_size, total - off);
        match debugger.read_memory(image.base as usize + off, &mut content[off..off + len]) {
            Ok(n) => {
                if n < len {
                    // Partial page — zero the tail.
                    content[off + n..off + len].fill(0);
                }
                pages_read += 1;
            }
            Err(_) => {
                pages_failed += 1;
                failed_offsets.push(off);
            }
        }
    }
    if failed_offsets.is_empty() {
        info!(total = total, pages = pages_read, "Raw dump: page-by-page read complete");
    } else {
        warn!(
            total = total,
            pages_read = pages_read,
            pages_failed = pages_failed,
            failed_rvas = ?failed_offsets.iter().map(|o| format!("{o:#x}")).collect::<Vec<_>>(),
            "Raw dump: page-by-page read complete with failures"
        );
    }

    let raw_path = output_path.with_extension("raw.bin");
    std::fs::write(&raw_path, &content)
        .map_err(|e| PeError::Io(e))?;

    // Determine architecture from the image header.
    let e_lfanew = u32::from_le_bytes(
        content[0x3C..0x40].try_into().map_err(|_| PeError::Parse("short header".into()))?,
    ) as usize;
    let opt = e_lfanew + 24;
    let is_64bit = u16::from_le_bytes(
        content[opt..opt + 2].try_into().map_err(|_| PeError::Parse("short header".into()))?,
    ) == 0x20B;

    // Dump the module snapshot so the offline script can resolve IAT slots.
    let modules_path = output_path.with_extension("raw.modules.txt");
    let modules = take_module_snapshot(
        debugger.process_handle(),
        debugger.pid(),
        image.base,
        is_64bit,
    )?;
    let mut mod_text = String::new();
    for m in &modules {
        mod_text.push_str(&format!("{} {} {:#x}\n", m.name, format!("{:#x}", m.base), m.end_off));
        for (&addr, name) in &m.exports {
            mod_text.push_str(&format!("{:#x} {}\n", addr, name));
        }
    }
    std::fs::write(&modules_path, mod_text).map_err(|e| PeError::Io(e))?;

    info!(
        path = %raw_path.display(),
        modules = %modules_path.display(),
        size = content.len(),
        base = %format!("{:#x}", image.base),
        "Raw mapped image dumped for offline post-processing",
    );
    Ok(raw_path)
}

/// Read the image bytes page-by-page (failure-tolerant) and write them to
/// `raw_path` verbatim.  No module snapshot, no path derivation — the
/// exit-window watch calls this once per debug event with a numbered
/// snapshot path, where re-taking the module list every time would be too
/// slow and the path is caller-chosen.
///
/// Returns the number of bytes written.
pub fn dump_mapped_image_raw_to(
    debugger: &mut dyn DebuggerCore,
    image: &MappedImage,
    raw_path: &std::path::Path,
) -> Result<usize, PeError> {
    let total = image.size_of_image as usize;
    let mut content = vec![0u8; total];
    let page_size = 0x1000usize;
    for off in (0..total).step_by(page_size) {
        let len = std::cmp::min(page_size, total - off);
        // Errors are tolerated: teardown may free pages under us.  The
        // offline analysis sees zeroed pages for the misses.
        let _ = debugger.read_memory(image.base as usize + off, &mut content[off..off + len]);
    }
    std::fs::write(raw_path, &content).map_err(|e| PeError::Io(e))?;
    Ok(content.len())
}
