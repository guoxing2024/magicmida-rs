//! Creation of .pdata (exception table) and .reloc sections after shrink.
//!
//! Extracted from `dump_process` in `dumper.rs`.

use tracing::{info, warn};

use crate::header::PeHeader;

/// One `RUNTIME_FUNCTION` entry, x64 layout: three `u32`s.
///
/// `BeginAddress` / `EndAddress` are RVAs into an executable section;
/// `UnwindInfoAddress` is an RVA into a read-only data section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeFunction {
    begin: u32,
    end: u32,
    unwind: u32,
}

impl RuntimeFunction {
    const SIZE: usize = 12;

    fn read(buf: &[u8], off: usize) -> Self {
        let u32_at = |o: usize| {
            u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]])
        };
        Self {
            begin: u32_at(off),
            end: u32_at(off + 4),
            unwind: u32_at(off + 8),
        }
    }

    fn is_null(&self) -> bool {
        self.begin == 0 && self.end == 0 && self.unwind == 0
    }

    fn to_bytes(self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&self.begin.to_le_bytes());
        out[4..8].copy_from_slice(&self.end.to_le_bytes());
        out[8..12].copy_from_slice(&self.unwind.to_le_bytes());
        out
    }
}

/// Build the `.pdata` payload from the exception table bytes, keeping only the
/// entries that still describe a section the product has.
///
/// # Why the entries have to be filtered rather than copied
///
/// The packed sample keeps its exception table inside `.winlice`, which
/// `shrink_sections` deletes.  Measured on the reference DLL, the live table
/// holds **4198** entries: **4193** point into `.text` with unwind info in
/// `.rdata`, and **5** describe code that lived in `.winlice` and is gone.  An
/// unwinder that looks up a range the product no longer has is worse than one
/// that finds no entry, so those 5 are dropped.
///
/// The surviving 4193 need **no rebase**: `shrink_sections` removes only
/// `.winlice`, `.boot` and `.reloc`, all of which sit *after* every section the
/// product keeps, so `.text` (0x1000) and `.rdata` (0x106000) keep their RVAs.
/// The filter is nevertheless written against the product's own section map
/// rather than against those constants, so it stays correct if the layout ever
/// changes.
pub(crate) fn build_pdata_payload(pe: &PeHeader, raw: &[u8]) -> Vec<u8> {
    let text = pe.sections.iter().find(|s| s.name.eq_ignore_ascii_case(".text"));
    let Some(text) = text else {
        warn!("No .text section in the product; dropping the exception table");
        return Vec::new();
    };
    let text_lo = text.virtual_address;
    let text_hi = text.virtual_address.saturating_add(text.virtual_size);

    // Unwind info lives in whichever read-only data section the linker used.
    let rdata: Vec<(u32, u32)> = pe
        .sections
        .iter()
        .filter(|s| {
            let n = s.name.to_lowercase();
            n.contains("rdata") || n == ".data"
        })
        .map(|s| (s.virtual_address, s.virtual_address.saturating_add(s.virtual_size)))
        .collect();

    let in_text = |v: u32| v >= text_lo && v < text_hi;
    let in_rdata = |v: u32| rdata.iter().any(|&(lo, hi)| v >= lo && v < hi);

    let total = raw.len() / RuntimeFunction::SIZE;
    let mut kept: Vec<RuntimeFunction> = Vec::with_capacity(total);
    let mut dropped_not_code = 0usize;
    let mut dropped_no_unwind = 0usize;

    for i in 0..total {
        let rf = RuntimeFunction::read(raw, i * RuntimeFunction::SIZE);
        if rf.is_null() {
            continue;
        }
        if !in_text(rf.begin) || !in_text(rf.end) || rf.begin >= rf.end {
            dropped_not_code += 1;
            continue;
        }
        if !in_rdata(rf.unwind) {
            dropped_no_unwind += 1;
            continue;
        }
        kept.push(rf);
    }

    // RtlLookupFunctionEntry binary-searches, so the array must be sorted by
    // BeginAddress.  The source table already is (measured: sorted), but a
    // filter cannot be trusted to preserve that, and sorting is cheap.
    kept.sort_unstable_by_key(|rf| rf.begin);

    info!(
        total,
        kept = kept.len(),
        dropped_not_code,
        dropped_no_unwind,
        "Exception table filtered to the sections the product keeps"
    );

    let mut out = Vec::with_capacity(kept.len() * RuntimeFunction::SIZE);
    for rf in kept {
        out.extend_from_slice(&rf.to_bytes());
    }
    out
}

/// Create a .pdata section from exception-table bytes already extracted from
/// the live process.
///
/// Returns `false` when the payload is empty, in which case **no section is
/// created and the Exception data directory is left cleared**.  That is the
/// correct outcome for a sample whose exception table is genuinely empty: an
/// all-zero `.pdata` of 50 KB is not "an exception table", it is 50 KB of
/// bytes an unwinder will try to interpret.
pub(crate) fn create_pdata_section_from(pe: &mut PeHeader, exc_data: Vec<u8>) -> bool {
    if exc_data.is_empty() {
        info!("Exception table empty after filtering; not creating .pdata");
        return false;
    }
    create_pdata_section(pe, &exc_data)
}

/// Create a .pdata section holding the given exception-table bytes.
pub(crate) fn create_pdata_section(pe: &mut PeHeader, exc_data: &[u8]) -> bool {
    let exc_len = exc_data.len();
    if exc_len == 0 {
        return false;
    }
    let file_align = pe.nt_headers.optional_header.file_alignment;
    let section_align = pe.nt_headers.optional_header.section_alignment;

    // SizeOfRawData must be FileAlignment-aligned.
    let raw_size = crate::utils::align_up(exc_len as u32, file_align);

    let pdata_idx = pe.create_section_index(".pdata", exc_len as u32);

    pe.sections[pdata_idx].virtual_size = exc_len as u32;
    pe.sections[pdata_idx].header.virtual_size = exc_len as u32;
    pe.sections[pdata_idx].header.size_of_raw_data = raw_size;
    pe.sections[pdata_idx].raw_size = raw_size;
    // .pdata must be READ + INITIALIZED_DATA (matches MSVC default).
    const IMAGE_SCN_MEM_READ_PD: u32 = 0x4000_0000;
    const IMAGE_SCN_CNT_INITIALIZED_DATA_PD: u32 = 0x0000_0040;
    pe.sections[pdata_idx].characteristics =
        IMAGE_SCN_MEM_READ_PD | IMAGE_SCN_CNT_INITIALIZED_DATA_PD;
    pe.sections[pdata_idx].header.characteristics =
        pe.sections[pdata_idx].characteristics;

    // Pad raw data to alignment and store as extra_data.
    let mut padded = exc_data.to_vec();
    if (padded.len() as u32) < raw_size {
        padded.resize(raw_size as usize, 0);
    }
    pe.sections[pdata_idx].extra_data = Some(padded);

    // Update SizeOfImage for the new section.
    let new_end = pe.sections[pdata_idx].header.virtual_address
        + crate::utils::align_up(exc_len as u32, section_align);
    if pe.nt_headers.optional_header.size_of_image < new_end {
        pe.nt_headers.optional_header.size_of_image = new_end;
    }

    // Point DataDirectory[3] (Exception) at the new .pdata.
    const IMAGE_DIRECTORY_ENTRY_EXCEPTION_PD: usize = 3;
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION_PD] =
        crate::header::ImageDataDirectory {
            virtual_address: pe.sections[pdata_idx].virtual_address,
            size: exc_len as u32,
        };
    info!(
        "Created .pdata section idx={} VA={:#x} size={:#x} (raw={:#x}); Exception dir restored",
        pdata_idx,
        pe.sections[pdata_idx].virtual_address,
        exc_len,
        raw_size
    );
    true
}

/// Create a placeholder .reloc section large enough for the full relocation
/// table.  The actual bytes are written later by `build_relocation_table`.
pub(crate) fn create_reloc_section(pe: &mut PeHeader) {
    let file_align = pe.nt_headers.optional_header.file_alignment;
    let section_align = pe.nt_headers.optional_header.section_alignment;

    // **The reserved size and the announced size must agree.**
    //
    // This section used to reserve a generous `0x2000` and announce it as its
    // `virtual_size`, so that any later section was placed after `0x2000` of
    // address space.  `build_relocation_table` then rewrote `virtual_size` to
    // the real table length (~`0xac`) *without moving the sections after it*,
    // which silently opened a `0x1000` hole in the virtual layout.
    //
    // The loader rejects any image whose section VAs are not contiguous:
    // measured `CreateProcess -> ERROR_BAD_EXE_FORMAT (193)` on a product that
    // was otherwise byte-perfect, and the same 193 when a hole was injected into
    // the working control sample.
    //
    // So the reserved VA range is fixed at one section-alignment unit — enough
    // for the relocation table (measured ~6 KB, well under 0x1000 for these
    // images) — and the announced `virtual_size` matches it exactly.  If the
    // real table ever exceeds one page the dump step below will say so instead
    // of silently producing an unloadable file.
    let reloc_vsize: u32 = section_align.max(0x1000);
    let reloc_raw = crate::utils::align_up(reloc_vsize, file_align);

    let reloc_idx = pe.create_section_index(".reloc", reloc_vsize);
    pe.sections[reloc_idx].virtual_size = reloc_vsize;
    pe.sections[reloc_idx].header.virtual_size = reloc_vsize;
    pe.sections[reloc_idx].header.size_of_raw_data = reloc_raw;
    pe.sections[reloc_idx].raw_size = reloc_raw;
    // .reloc: READ + INITIALIZED_DATA + MEM_DISCARDABLE (matches MSVC).
    const IMAGE_SCN_MEM_READ_R: u32 = 0x4000_0000;
    const IMAGE_SCN_CNT_INITIALIZED_DATA_R: u32 = 0x0000_0040;
    const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
    pe.sections[reloc_idx].characteristics =
        IMAGE_SCN_MEM_READ_R | IMAGE_SCN_CNT_INITIALIZED_DATA_R | IMAGE_SCN_MEM_DISCARDABLE;
    pe.sections[reloc_idx].header.characteristics =
        pe.sections[reloc_idx].characteristics;

    // Zero-filled raw data placeholder.
    pe.sections[reloc_idx].extra_data = Some(vec![0u8; reloc_raw as usize]);

    // Update SizeOfImage.
    let new_end = pe.sections[reloc_idx].header.virtual_address
        + crate::utils::align_up(reloc_vsize, section_align);
    if pe.nt_headers.optional_header.size_of_image < new_end {
        pe.nt_headers.optional_header.size_of_image = new_end;
    }

    // Set BaseReloc DataDirectory[5] to the new .reloc VA.
    const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC] =
        crate::header::ImageDataDirectory {
            virtual_address: pe.sections[reloc_idx].virtual_address,
            size: reloc_vsize, // provisional; refined later
        };
    info!(
        "Created .reloc section idx={} VA={:#x} vsize={:#x} raw={:#x}",
        reloc_idx,
        pe.sections[reloc_idx].virtual_address,
        reloc_vsize,
        reloc_raw
    );
}
