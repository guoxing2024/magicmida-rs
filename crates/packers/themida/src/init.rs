//! PE initialisation for Themida targets — corresponds to
//! `ThemidaCommon.pas` `InitPEDetails`, `TMInit` in `Themida.pas` /
//! `Themida64.pas`, and `SelectThemidaSection`.
//!
//! The central entry point is [`init_pe_details`], which parses a PE header,
//! fingerprints the Themida version, checks whether the OEP is virtualised,
//! and computes the dependent fields (`image_boundary`, `base_of_data`,
//! `themida_section` index).

use crate::error::ThemidaError;
use crate::version::{self, ThemidaVersion};
use mida_pe::PeHeader;

/// Parsed Themida-specific information extracted from a target PE.
///
/// Corresponds to the fields in `TTMCommon` plus `TTMDebugger.TMInit` /
/// `TTMDebugger64.TMInit` that are set during initialisation.
#[derive(Debug, Clone)]
pub struct ThemidaPeInfo {
    /// Preferred load address (`ImageBase`).
    pub image_base: u64,
    /// End of the image in memory: `ImageBase + SizeOfImage`.
    ///
    /// Corresponds to `FImageBoundary` in the Pascal source.
    pub image_boundary: u64,
    /// RVA of the data section start — used as the boundary between code and
    /// data regions when installing the section guard.
    ///
    /// Corresponds to `FBaseOfData` in the Pascal source.
    pub base_of_data: u64,
    /// All PE sections, in order.
    pub pe_sections: Vec<mida_pe::PeSection>,
    /// The `MajorLinkerVersion` from the optional header.
    pub major_linker_version: u8,
    /// Identified Themida version (static detection).
    /// The packed file's entry-point RVA — for generations whose section
    /// names are user-renamed, this locates the protector's code section.
    pub packed_entry_point: u32,
    pub themida_version: ThemidaVersion,
    /// Whether the OEP is virtualised (jumps directly into the Themida VM).
    pub is_vm_oep: bool,
    /// Index into `pe_sections` that contains (or is most likely to contain)
    /// the Themida protection stub, or `None` if none was identified.
    pub themida_section: Option<usize>,
    /// Number of TLS callbacks expected. Derived from the PE TLS directory
    /// using the MSVC-ism in `Themida64.pas` `TMInit` (assume TLS callback
    /// pointers live immediately before the TLS directory, up to 4 entries).
    /// Zero if the binary has no TLS directory or we cannot resolve it.
    pub tls_total: u32,
}

/// Initialise Themida-specific PE information from a parsed PE header.
///
/// This is the Rust equivalent of `TTMCommon.InitPEDetails` combined with the
/// version-detection and section-selection logic from
/// `TTMDebugger.TMInit` / `TTMDebugger64.TMInit`.
///
/// # Steps
///
/// 1. Verify that the entry point is *not* in the first section (`.text`).
///    If it is, the binary is likely not packed.
/// 2. Compute `image_boundary` = `ImageBase + SizeOfImage`.
/// 3. Determine `base_of_data` — for PE32+ this is derived from the first
///    section's `VirtualAddress + SizeOfCode`; for PE32 the optional header
///    `BaseOfData` field is used directly.
/// 4. Run [`detect_version`] to fingerprint the Themida generation.
/// 5. Attempt to locate the Themida section via [`locate_themida_section`].
/// 6. If `entry_point_bytes` is provided (at least 5 bytes), check whether
///    the OEP is virtualised via [`check_virtualized_oep`].
/// 7. Resolve the TLS callback count from the PE TLS directory (MSVC-ism).
///
/// # Parameters
///
/// - `pe` — the parsed PE header.
/// - `is_64bit` — `true` if the target is a 64-bit binary.
/// - `entry_point_bytes` — optional raw bytes at the entry point.
/// - `executable_path` — path to the on-disk PE file. Required for TLS
///   callback count resolution; pass `None` to skip.
/// - `image` — the file bytes, for the measured import-surface version
///   fingerprints; pass `&[]` to skip them.
///
/// # Errors
///
/// Returns [`ThemidaError::NotThemida`] if the entry point falls inside the
/// `.text` section, indicating the binary is probably not packed.
pub fn init_pe_details(
    pe: &PeHeader,
    is_64bit: bool,
    entry_point_bytes: Option<&[u8]>,
    executable_path: Option<&std::path::Path>,
    image: &[u8],
) -> Result<ThemidaPeInfo, ThemidaError> {
    // Step 1: Verify entry point is not in the first section.
    // (ThemidaCommon.pas InitPEDetails: entry point inside .text → not packed)
    if let Some(first_section) = pe.sections.first() {
        let first_end = first_section.virtual_address + first_section.virtual_size;
        if pe.entry_point < first_end {
            return Err(ThemidaError::NotThemida);
        }
    }

    // Step 2: Compute image_boundary = ImageBase + SizeOfImage.
    let image_base = pe.image_base;
    let image_boundary = image_base + u64::from(pe.size_of_image());

    // Step 4: Detect Themida version.
    let themida_version = version::detect_version_with_image(pe, is_64bit, image);

    // Step 3: Determine base_of_data.
    // For PE32, we use the BaseOfData field from the optional header.
    // For PE32+, we compute it as first_section.VirtualAddress + SizeOfCode
    // (matching Themida64.pas TMInit).
    //
    // Classic v1-generation exception: the packed header's BaseOfData is
    // garbage there (measured `0x1000` on Themida 1.1.1.0 while its first
    // section spans `0x1000..0x63000`), and every consumer of this field —
    // the `.text` guard range, the guard-fault routing, the data-region
    // start for IAT discovery — derives the code span from it.  Give the
    // classic generations the first section's own virtual span, or the OEP
    // sits outside the guarded range and the run finds nothing (measured
    // failure shape: guard `0x401000–0x44b000`, OEP beyond it, zero faults).
    let base_of_data = if matches!(
        themida_version,
        ThemidaVersion::V1 | ThemidaVersion::Ancient
    ) {
        let first_section = &pe.sections[0];
        u64::from(first_section.virtual_address) + u64::from(first_section.virtual_size)
    } else if is_64bit {
        let first_section = &pe.sections[0];
        u64::from(first_section.virtual_address)
            + u64::from(pe.nt_headers.optional_header.size_of_code)
    } else {
        pe.nt_headers
            .optional_header
            .base_of_data
            .map(u64::from)
            .unwrap_or(0)
    };

    // Step 5: Locate the Themida section.
    let themida_section = locate_themida_section(pe);

    // Step 6: Check virtualised OEP.
    let is_vm_oep = entry_point_bytes
        .is_some_and(|bytes| version::check_virtualized_oep(pe, bytes));

    let packed_entry_point = pe.entry_point;
    let pe_sections = pe.sections.clone();

    // Step 7: Resolve the number of TLS callbacks from the PE TLS directory
    // using the heuristic in `Themida64.pas` `TMInit`.  MSVC places the TLS
    // callback pointers immediately before the TLS directory, so the distance
    // from the TLS directory's file position to AddressOfCallBacks allows us
    // to infer the count (at most 4 entries + zero terminator).
    let tls_total = resolve_tls_callback_count(pe, is_64bit, executable_path);

    Ok(ThemidaPeInfo {
        image_base,
        image_boundary,
        base_of_data,
        pe_sections,
        major_linker_version: pe.nt_headers.optional_header.major_linker_version,
        packed_entry_point,
        themida_version,
        is_vm_oep,
        themida_section,
        tls_total,
    })
}

/// Walk the section table and return the index of the section most likely to
/// be the Themida protection stub.
///
/// Corresponds to `TTMDebugger.SelectThemidaSection` / `TTMDebugger64.SelectThemidaSection`.
///
/// Preference order:
/// 1. The first section that matches [`is_themida_section`], scanning from
///    the **last** section backwards (because Themida sections are usually
///    appended at the end).
/// 2. If no section matches the heuristic, returns `None`.
#[must_use]
pub fn locate_themida_section(pe: &PeHeader) -> Option<usize> {
    // Scan backwards — Themida sections are almost always after .text.
    for (i, section) in pe.sections.iter().enumerate().rev() {
        if version::is_themida_section(section) {
            return Some(i);
        }
    }
    None
}

/// TLS directory index (PE data directory).
const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

/// Maximum number of TLS callbacks we assume + zero terminator.
/// Match `Themida64.pas` `TMInit`: at most 4 TLS entries + zero terminator.
const MAX_TLS_CALLBACKS_GUESS: usize = 4;

/// Resolve the count of TLS callbacks expected for this binary.
///
/// Uses the MSVC-ism documented in `Themida64.pas` `TMInit`: for MSVC
/// binaries, TLS callback pointers are placed immediately before the TLS
/// directory.  We find that distance and divide by pointer size (rounded
/// down, minus 1 for the zero terminator) to recover the count.  Bails
/// safely to 0 if anything doesn't add up or if `executable_path` is `None`.
fn resolve_tls_callback_count(
    pe: &PeHeader,
    is_64bit: bool,
    executable_path: Option<&std::path::Path>,
) -> u32 {
    let Some(path) = executable_path else {
        return 0;
    };
    let tls_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    // The data-directory `Size` for TLS is the size of the TLS directory
    // *structure*, which differs by architecture:
    //   IMAGE_TLS_DIRECTORY32 = 24 bytes (0x18)
    //   IMAGE_TLS_DIRECTORY64 = 40 bytes (0x28)
    //
    // This used to be a flat `< 40`, which silently rejected **every** PE32
    // target: the x86 reference sample reports 0x18, so `tls_total` was always
    // 0.  x64 was unaffected only because 0x28 >= 40.
    let min_tls_dir_size = if is_64bit { 40 } else { 24 };
    if tls_dir.virtual_address == 0 || tls_dir.size < min_tls_dir_size {
        return 0;
    }

    // Find which section holds the TLS directory (for its raw offset).
    let Some(_tls_section) = pe.get_section_by_rva(tls_dir.virtual_address) else {
        return 0;
    };

    // TLS directory field layout — the field offsets differ by architecture
    // because the first three fields are pointer-sized:
    //   IMAGE_TLS_DIRECTORY32 (24 bytes):
    //     0x00 StartAddressOfRawData (4)   0x04 EndAddressOfRawData (4)
    //     0x08 AddressOfIndex        (4)   0x0C AddressOfCallBacks   (4)
    //   IMAGE_TLS_DIRECTORY64 (40 bytes):
    //     0x00 StartAddressOfRawData (8)   0x08 EndAddressOfRawData (8)
    //     0x10 AddressOfIndex        (8)   0x18 AddressOfCallBacks   (8)
    //
    // This used to read a flat `+ 0x18`, correct only for PE32+.  Measured on
    // the x86 reference sample, the directory is
    // `00 60 41 00 | 04 60 41 00 | 08 60 41 00 | 10 60 41 00 | 00...`:
    // AddressOfCallBacks = 0x416010 sits at 0x0C and offset 0x18 is zero.
    let cb_field_offset = if is_64bit { 0x18 } else { 0x0C };
    let cb_rva = tls_dir.virtual_address + cb_field_offset;
    let Some(cb_section) = pe.get_section_by_rva(cb_rva) else {
        return 0;
    };
    let cb_file_offset = cb_section.raw_offset as usize
        + (cb_rva - cb_section.virtual_address) as usize;

    let ptr_size = if is_64bit { 8usize } else { 4usize };
    let Ok(file_data) = std::fs::read(path) else {
        return 0;
    };
    if cb_file_offset + ptr_size > file_data.len() {
        return 0;
    }
    let mut cb_bytes = [0u8; 8];
    cb_bytes[..ptr_size].copy_from_slice(&file_data[cb_file_offset..cb_file_offset + ptr_size]);
    let callbacks_va = if is_64bit {
        u64::from_le_bytes(cb_bytes)
    } else {
        cb_bytes.get(..4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .map(u64::from)
            .unwrap_or(0)
    };
    if callbacks_va == 0 {
        return 0;
    }

    // A valid TLS directory with a non-null `AddressOfCallBacks` proves callbacks
    // exist, but the array itself may be **unreadable on disk**.
    //
    // Measured on both packed reference samples: the callback array is entirely
    // zero in the packed input, because the shell encrypts it and only writes it
    // at run time.
    //   x86 `x86_c.exe`     : .tls raw at file 0x4410, 16 bytes, all 0x00
    //   x64 `时光一键宏.exe` : callback array 64 bytes, all 0x00
    // The same array in the *unpacked* original holds the real pointers
    // (`0x401810`, `0x4017d0` on the x86 sample).
    //
    // So counting from disk can never succeed on a packed binary, and live
    // memory is not available here (this runs before the debug session exists).
    //
    // The fallback is applied to **x86 only**, and that is a measured decision,
    // not a convenience:
    //
    // * x86 `handle_tls_callbacks` validates the callback *argument signature*
    //   `(hInstance & 0xFFF) == 0 && fdwReason <= 3` before skipping, so a
    //   non-zero budget is safe: a real OEP that is not a callback simply fails
    //   the signature test and is accepted as the OEP.  Without a budget the
    //   function bails out at `tls_total == 0` and the correct TLS-callback OEP
    //   at `0x401810` gets rejected by the "return address points into the
    //   Themida section" heuristic, which then retries until the shell stalls.
    // * x64 `handle_tls_callbacks` skips on `execution_type == 8` alone, with no
    //   argument check.  Giving it a non-zero budget makes it treat the *real*
    //   OEP as a callback and skip it: measured `TLS callback 1/4 at
    //   0x7ff6c13e2820` followed by `FATAL: OEP not found`, turning a green gate
    //   into a 466 s failure.  x64 must therefore keep the budget at 0.
    if cfg!(target_arch = "x86") {
        let count = count_callbacks_in(&file_data, callbacks_va, ptr_size, is_64bit, pe);
        if count == 0 {
            tracing::debug!(
                callbacks_va = format_args!("{callbacks_va:#x}"),
                "TLS callback array is unreadable on disk (packer-encrypted) — \
                 using the bounded Themida budget (x86 only)"
            );
            return MAX_TLS_CALLBACKS_GUESS as u32;
        }
        return count as u32;
    }

    let count = count_callbacks_in(&file_data, callbacks_va, ptr_size, is_64bit, pe);
    count as u32
}

/// Count non-null entries in the on-disk TLS callback array, if readable.
///
/// Returns 0 when the array cannot be resolved or is packed (all zeroes).
fn count_callbacks_in(
    file_data: &[u8],
    callbacks_va: u64,
    ptr_size: usize,
    is_64bit: bool,
    pe: &PeHeader,
) -> usize {
    let image_base = pe.nt_headers.optional_header.image_base;
    let array_rva = callbacks_va.wrapping_sub(image_base);
    // `wrapping_sub` underflows to a huge value when the VA sits below the image
    // base, which also means it cannot be inside this image.
    if array_rva >= image_base {
        return 0;
    }
    let Some(array_section) = pe.get_section_by_rva(array_rva as u32) else {
        return 0;
    };
    let array_file_offset =
        array_section.raw_offset as usize + (array_rva as usize - array_section.virtual_address as usize);

    let mut count = 0usize;
    for i in 0..=MAX_TLS_CALLBACKS_GUESS {
        let off = array_file_offset + i * ptr_size;
        if off + ptr_size > file_data.len() {
            break;
        }
        let mut bytes = [0u8; 8];
        bytes[..ptr_size].copy_from_slice(&file_data[off..off + ptr_size]);
        let entry = if is_64bit {
            u64::from_le_bytes(bytes)
        } else {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64
        };
        if entry == 0 {
            break;
        }
        count += 1;
    }
    count
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal packed PE64 with an entry point outside .text.
    fn make_packed_pe64() -> PeHeader {
        let mut buf = vec![0u8; 512];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[60] = 0x40;
        let nt = 0x40;
        buf[nt] = 0x50;
        buf[nt + 1] = 0x45;
        let fh = nt + 4;
        buf[fh] = 0x64;
        buf[fh + 1] = 0x86;
        buf[fh + 2] = 2;
        buf[fh + 16] = 0xF0;
        buf[fh + 18] = 0x22;
        let oh = nt + 24;
        buf[oh] = 0x0B;
        buf[oh + 1] = 0x02;
        buf[oh + 16] = 0x00;
        buf[oh + 17] = 0x30; // EntryPoint = 0x3000 (outside .text)
        buf[oh + 27] = 0x40;
        buf[oh + 28] = 0x01;
        buf[oh + 32] = 0x00;
        buf[oh + 33] = 0x10;
        buf[oh + 36] = 0x00;
        buf[oh + 37] = 0x02;
        buf[oh + 56] = 0x00;
        buf[oh + 57] = 0x60;
        buf[oh + 60] = 0x00;
        buf[oh + 61] = 0x02;
        buf[oh + 108] = 0x10;

        // .text at 0x1000, VS=0x1000
        let s1 = nt + 24 + 240;
        buf[s1] = b'.';
        buf[s1 + 1] = b't';
        buf[s1 + 2] = b'e';
        buf[s1 + 3] = b'x';
        buf[s1 + 4] = b't';
        buf[s1 + 8] = 0x00;
        buf[s1 + 9] = 0x10;
        buf[s1 + 12] = 0x00;
        buf[s1 + 13] = 0x10;
        buf[s1 + 16] = 0x00;
        buf[s1 + 17] = 0x02;
        buf[s1 + 20] = 0x00;
        buf[s1 + 21] = 0x02;
        buf[s1 + 36] = 0x20;
        buf[s1 + 39] = 0x60;

        // Themida section at 0x4000
        let s2 = s1 + 40;
        buf[s2] = b'T';
        buf[s2 + 1] = b'h';
        buf[s2 + 2] = b'e';
        buf[s2 + 3] = b'm';
        buf[s2 + 4] = b'i';
        buf[s2 + 5] = b'd';
        buf[s2 + 6] = b'a';
        buf[s2 + 8] = 0x00;
        buf[s2 + 9] = 0x50;
        buf[s2 + 12] = 0x00;
        buf[s2 + 13] = 0x40;
        buf[s2 + 16] = 0x00;
        buf[s2 + 17] = 0x02;
        buf[s2 + 20] = 0x00;
        buf[s2 + 21] = 0x02;
        buf[s2 + 36] = 0x20;
        buf[s2 + 39] = 0xE0;

        PeHeader::from_bytes(&buf).unwrap()
    }

    /// Build a minimal *unpacked* PE32 where the EP is in .text.
    fn make_unpacked_pe32() -> PeHeader {
        let mut buf = vec![0u8; 512];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[60] = 0x40;
        let nt = 0x40;
        buf[nt] = 0x50;
        buf[nt + 1] = 0x45;
        let fh = nt + 4;
        buf[fh] = 0x4C;
        buf[fh + 1] = 0x01;
        buf[fh + 2] = 1;
        buf[fh + 16] = 0xE0;
        buf[fh + 18] = 0x22;
        let oh = nt + 24;
        buf[oh] = 0x0B;
        buf[oh + 1] = 0x01;
        buf[oh + 16] = 0x00;
        buf[oh + 17] = 0x10; // EntryPoint = 0x1000 (inside .text!)
        buf[oh + 28] = 0x00;
        buf[oh + 29] = 0x40;
        buf[oh + 32] = 0x00;
        buf[oh + 33] = 0x10;
        buf[oh + 36] = 0x00;
        buf[oh + 37] = 0x02;
        buf[oh + 56] = 0x00;
        buf[oh + 57] = 0x20;
        buf[oh + 60] = 0x00;
        buf[oh + 61] = 0x02;
        buf[oh + 92] = 0x10;

        let s1 = nt + 24 + 224;
        buf[s1] = b'.';
        buf[s1 + 1] = b't';
        buf[s1 + 2] = b'e';
        buf[s1 + 3] = b'x';
        buf[s1 + 4] = b't';
        buf[s1 + 8] = 0x00;
        buf[s1 + 9] = 0x10;
        buf[s1 + 12] = 0x00;
        buf[s1 + 13] = 0x10;
        buf[s1 + 16] = 0x00;
        buf[s1 + 17] = 0x02;
        buf[s1 + 20] = 0x00;
        buf[s1 + 21] = 0x02;
        buf[s1 + 36] = 0x20;
        buf[s1 + 39] = 0x60;

        PeHeader::from_bytes(&buf).unwrap()
    }

    #[test]
    fn init_packed_pe64_succeeds() {
        let pe = make_packed_pe64();
        let info = init_pe_details(&pe, true, None, None, &[]).unwrap();

        assert_eq!(info.image_base, 0x140000000);
        assert_eq!(info.themida_version, ThemidaVersion::V3); // x64
        assert!(info.themida_section.is_some());
        assert_eq!(info.themida_section.unwrap(), 1); // second section
        assert!(!info.is_vm_oep); // no entry point bytes provided
    }

    #[test]
    fn init_unpacked_returns_not_themida() {
        let pe = make_unpacked_pe32();
        let err = init_pe_details(&pe, false, None, None, &[]).unwrap_err();
        assert!(matches!(err, ThemidaError::NotThemida));
    }

    #[test]
    fn locate_themida_section_finds_by_name() {
        let pe = make_packed_pe64();
        let idx = locate_themida_section(&pe);
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn locate_themida_section_none_for_clean_pe() {
        let pe = make_unpacked_pe32();
        let idx = locate_themida_section(&pe);
        assert!(idx.is_none());
    }

    #[test]
    fn init_with_vm_oep_detection() {
        let pe = make_packed_pe64();
        // jmp +0x0FFB → target 0x4000 inside Themida section
        let entry_bytes = [0xE9u8, 0xFB, 0x0F, 0x00, 0x00];
        let info = init_pe_details(&pe, true, Some(&entry_bytes), None, &[]).unwrap();
        assert!(info.is_vm_oep);
    }
}
