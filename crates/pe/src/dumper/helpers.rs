//! Small helper functions used across the dumper submodules.
//!
//! Extracted from `dumper.rs`.

use tracing::debug;

use windows::Win32::System::Memory::{
    VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_NOACCESS,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY,
};

use crate::header::PeHeader;

/// Maximum number of IAT slots to scan when determining IAT size.
/// Corresponds to `MAX_IAT_SIZE` in `Dumper.pas` (5120 * SizeOf(Pointer)).
pub(crate) const MAX_IAT_SLOTS: usize = 5120;

/// Maximum gap (in slots) between valid API addresses before we consider the
/// IAT to have ended.  Corresponds to the `$100` byte-gap in the Pascal code.
pub(crate) const MAX_GAP_SLOTS: usize = 0x100 / core::mem::size_of::<usize>();

/// Preference scores for module names (higher = preferred).
/// Corresponds to `PreferenceScore` and `ForwardPreferences` in `Dumper.pas`.
pub(crate) const FORWARD_PREFERENCES: &[&str] = &[
    "kernel32.dll",
    "ole32.dll",
    "advapi32.dll",
    "netapi32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "gdi32.dll",
    "dbghelp.dll",
    "setupapi.dll",
];

/// Data directory index for the COM descriptor (used for .NET detection).
pub(crate) const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

/// Data directory index for the import table.
pub(crate) const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;

/// Data directory index for the IAT.
pub(crate) const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

/// DLL characteristics flags
pub(crate) const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
#[allow(dead_code)]
pub(crate) const IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: u16 = 0x0020;

// -----------------------------------------------------------------------
// preference_score
// -----------------------------------------------------------------------

/// Return a preference score for a module name.
/// Higher = more preferred.  Zero for unrecognised names.
pub(crate) fn preference_score(name: &str) -> usize {
    for (i, pref) in FORWARD_PREFERENCES.iter().enumerate() {
        if name.eq_ignore_ascii_case(pref) {
            return FORWARD_PREFERENCES.len() - i;
        }
    }
    0
}

// -----------------------------------------------------------------------
// read_ptr / write_ptr
// -----------------------------------------------------------------------

/// Read a pointer-sized value from `data` at `offset`.
/// On x86_64 this is 8 bytes; on x86 this is 4 bytes.
#[inline]
pub(crate) fn read_ptr(data: &[u8], offset: usize, is_64bit: bool) -> u64 {
    if is_64bit {
        data.get(offset..offset + 8)
            .and_then(|s| s.try_into().ok())
            .map(u64::from_le_bytes)
            .unwrap_or(0)
    } else {
        data.get(offset..offset + 4)
            .and_then(|s| s.try_into().ok())
            .map(u32::from_le_bytes)
            .map(u64::from)
            .unwrap_or(0)
    }
}

/// Write a pointer-sized value into `data` at `offset`.
#[inline]
pub(crate) fn write_ptr(data: &mut [u8], offset: usize, value: u64, is_64bit: bool) {
    if is_64bit {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    } else {
        data[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
    }
}

// -----------------------------------------------------------------------
// make_memory_readable
// -----------------------------------------------------------------------

/// Make all memory pages in the range [`base`, `base + size`) readable.
///
/// Corresponds to `TDumper.MakeMemoryReadable` in `Dumper.pas`.
///
/// Walks the region page-by-page via `VirtualQueryEx` and calls
/// `VirtualProtectEx` on any `PAGE_NOACCESS` pages to set `PAGE_READONLY`.
pub(crate) fn make_memory_readable(
    debugger: &dyn mida_core::DebuggerCore,
    base: u64,
    size: u64,
) {
    let process_handle = debugger.process_handle();
    let mut addr = base;
    let end = base.saturating_add(size);
    let page_size = 0x1000usize; // 4 KiB pages

    while addr < end {
        let mut mbi: MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION::default();

        // SAFETY: process_handle is valid; mbi is a valid pointer.
        let query_ok = unsafe {
            VirtualQueryEx(
                process_handle,
                Some(addr as *const std::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if query_ok == 0 {
            // VirtualQueryEx failed (e.g. invalid region). Skip to next page.
            addr = addr.saturating_add(page_size as u64);
            continue;
        }

        // Only act on committed, no-access pages.
        // MEM_COMMIT = 0x1000, PAGE_NOACCESS = 0x01.
        let is_committed = mbi.State == MEM_COMMIT;
        let is_no_access = mbi.Protect == PAGE_PROTECTION_FLAGS(PAGE_NOACCESS.0);

        if is_committed && is_no_access {
            let mut old_protect = PAGE_PROTECTION_FLAGS::default();
            let region_start = mbi.BaseAddress as u64;
            let region_size = mbi.RegionSize.min((end - region_start) as usize);

            if region_size > 0 {
                // SAFETY: process_handle is valid; region_start is a valid
                // committed address range in the target.
                let _ = unsafe {
                    VirtualProtectEx(
                        process_handle,
                        region_start as *const std::ffi::c_void,
                        region_size,
                        PAGE_READONLY,
                        &mut old_protect,
                    )
                };
                debug!(
                    "make_memory_readable: {:#x}..{:#x} NOACCESS → READONLY",
                    region_start,
                    region_start.saturating_add(region_size as u64),
                );
            }
        }

        // Advance past this region.
        let next = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
        if next <= addr {
            addr = addr.saturating_add(page_size as u64);
        } else {
            addr = next;
        }
    }
}

// -----------------------------------------------------------------------
// is_dotnet
// -----------------------------------------------------------------------

/// Check whether a PE has a COM descriptor (DataDirectory[14]), indicating
/// a .NET assembly.
#[must_use]
pub fn is_dotnet(pe: &PeHeader) -> bool {
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
        .virtual_address
        != 0
}

// -----------------------------------------------------------------------
// create_dos_header
// -----------------------------------------------------------------------

/// Create a minimal DOS header for the output PE file.
///
/// The dump buffer is a memory dump (no DOS header), but the output file
/// needs a valid DOS header for the PE loader to recognize it.
pub(crate) fn create_dos_header() -> Vec<u8> {
    let mut header = vec![0u8; 0x80];

    // DOS signature "MZ"
    header[0] = 0x4D; // 'M'
    header[1] = 0x5A; // 'Z'

    // DOS header fields
    header[2] = 0x90; // Bytes on last page of file
    header[4] = 0x03; // Pages in file
    header[8] = 0x04; // Size of header in paragraphs
    header[12] = 0xFF; // Minimum extra paragraphs (e_minalloc) - low byte
    header[13] = 0xFF; // Minimum extra paragraphs (e_minalloc) - high byte
    header[14] = 0x00; // Maximum extra paragraphs (e_maxalloc) - low byte
    header[15] = 0x00; // Maximum extra paragraphs (e_maxalloc) - high byte
    header[16] = 0xB8; // Initial SP value
    header[20] = 0x00; // Initial IP value
    header[24] = 0x40; // File address of relocation table

    // PE header offset at offset 0x3C
    header[0x3C] = 0x80; // PE header at offset 0x80

    // DOS stub program (minimal)
    let dos_stub: &[u8] = &[
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21,
        0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63,
        0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69,
        0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    for (i, &byte) in dos_stub.iter().enumerate() {
        if 0x40 + i < header.len() {
            header[0x40 + i] = byte;
        }
    }

    header
}

// -----------------------------------------------------------------------
// section_rva_to_file_offset
// -----------------------------------------------------------------------

/// Map an RVA to a file offset using the section headers.
pub(crate) fn section_rva_to_file_offset(sections: &[crate::PeSection], rva: u32) -> usize {
    for section in sections {
        let start = section.virtual_address;
        let end = start + section.virtual_size;
        if rva >= start && rva < end {
            let offset = rva - start;
            return (section.header.pointer_to_raw_data + offset) as usize;
        }
    }
    rva as usize // fallback
}

// Silence unused-import warnings in configurations that don't use everything.
#[allow(unused_imports)]
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
