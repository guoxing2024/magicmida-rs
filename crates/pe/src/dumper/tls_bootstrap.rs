//! TLS callback-based container bootstrap for proper initialization timing.
//!
//! This module creates a TLS Directory and registers the container restoration
//! bootstrap as a TLS callback. TLS callbacks execute after CRT initialization
//! but before the main entry point, which is the correct timing for restoring
//! heap-backed SecurityCookie-encoded containers.
//!
//! ## Execution Order
//!
//! ```text
//! Windows Loader
//!   ↓
//! CRT Initialization (__scrt_common_main_seh at 0x1000)
//!   ↓
//! TLS Callbacks (our bootstrap runs here)
//!   ↓
//! Global Constructors
//!   ↓
//! main() / WinMain()
//! ```
//!
//! ## TLS Directory Structure (x64)
//!
//! ```text
//! IMAGE_TLS_DIRECTORY64:
//!   +0x00: u64 StartAddressOfRawData   — VA of TLS data start
//!   +0x08: u64 EndAddressOfRawData     — VA of TLS data end
//!   +0x10: u64 AddressOfIndex          — VA of TLS index
//!   +0x18: u64 AddressOfCallBacks      — VA of callback array
//!   +0x20: u32 SizeOfZeroFill
//!   +0x24: u32 Characteristics
//!
//! Callback Array (NULL-terminated):
//!   +0x00: u64 callback1_va
//!   +0x08: u64 callback2_va
//!   ...
//!   +0xXX: u64 0 (terminator)
//! ```

use tracing::{debug, info, warn};

use crate::header::PeHeader;

use super::container_snapshot::ContainerSnapshot;

// TLS restoration machinery is pending the P2 TLS gate; keep it compiled and
// documented so the section/table/callback work can be wired without archaeology.
#[allow(dead_code)]
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
#[allow(dead_code)]
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
#[allow(dead_code)]
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

#[allow(dead_code)]
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
#[allow(dead_code)]
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

#[allow(dead_code)]
const TLS_DIRECTORY_SIZE: usize = 0x28; // sizeof(IMAGE_TLS_DIRECTORY64)
#[allow(dead_code)]
const TLS_INDEX_SIZE: usize = 4;
#[allow(dead_code)]
const TLS_CALLBACK_ARRAY_SIZE: usize = 16; // 1 callback + NULL terminator

/// Install container restoration bootstrap as a TLS callback.
///
/// Creates:
/// - `.tls` section: TLS Directory + TLS index + callback array
/// - `.boot` section: bootstrap code + metadata + heap snapshots
///
/// Returns the original entry point (unchanged).
#[allow(dead_code)] // pending P2 TLS restoration
pub(crate) fn install_tls_callback_bootstrap(
    pe: &mut PeHeader,
    containers: &[ContainerSnapshot],
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    heap_global_rva: Option<u32>,
    original_entry_point: u32,
) -> Option<u32> {
    if !pe.is_64bit {
        warn!("TLS callback bootstrap only supports x64");
        return None;
    }

    if containers.is_empty() {
        return None;
    }

    let image_base = pe.nt_headers.optional_header.image_base;

    // Find .data section RVA for SecurityCookie reading
    let data_section_rva = pe
        .sections
        .iter()
        .find(|s| {
            let name = std::str::from_utf8(&s.header.name)
                .ok()
                .and_then(|n| n.split('\0').next());
            name == Some(".data")
        })
        .map(|s| s.virtual_address)
        .unwrap_or(0);

    tracing::debug!("Found .data section at RVA: {:#x}", data_section_rva);

    // 1. Create .boot section with bootstrap code
    let boot_section_idx = pe.create_section_index(".boot", 0x1000);
    let boot_rva = pe.sections[boot_section_idx].virtual_address;

    // Note: We use a dummy OEP for bootstrap since it won't jump anywhere
    // (TLS callbacks just return)
    // TODO: global_vars are detected but not yet used - need to implement global var restoration
    let boot_stub = match super::container_bootstrap::build_tls_bootstrap_stub(
        boot_rva,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
        None, // data_snapshot - not using full .data restoration for now
        image_base,
        data_section_rva,
        heap_global_rva,
        None, // cookie_rva: TLS path uses metadata cookie fallback
    ) {
        Some(stub) => stub,
        None => {
            pe.sections.remove(boot_section_idx);
            pe.nt_headers.optional_header.size_of_image = pe
                .sections
                .last()
                .map(|section| {
                    crate::utils::align_up(
                        section.virtual_address.saturating_add(section.virtual_size),
                        pe.nt_headers.optional_header.section_alignment,
                    )
                })
                .unwrap_or(pe.nt_headers.optional_header.size_of_headers);
            warn!("TLS bootstrap targets are outside the x64 relative-address range");
            return None;
        }
    };

    let boot_len = boot_stub.len();
    let boot_aligned_size = crate::utils::align_up(boot_len as u32, 0x1000);

    let boot_section = &mut pe.sections[boot_section_idx];
    boot_section.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    boot_section.header.characteristics = boot_section.characteristics;
    boot_section.header.virtual_size = boot_aligned_size;
    boot_section.virtual_size = boot_aligned_size;
    boot_section.header.size_of_raw_data = boot_aligned_size;
    boot_section.raw_size = boot_aligned_size;
    // Pad to claimed SizeOfRawData (section-aligned). Output writer also
    // enforces raw-range ≤ file length independently.
    let mut boot_stub = boot_stub;
    if (boot_stub.len() as u32) < boot_aligned_size {
        boot_stub.resize(boot_aligned_size as usize, 0);
    }
    boot_section.extra_data = Some(boot_stub);

    // 2. Create .tls section with TLS Directory
    let tls_section_idx = pe.create_section_index(".tls", 0x200);
    let tls_rva = pe.sections[tls_section_idx].virtual_address;

    let tls_data = build_tls_directory(
        image_base, tls_rva, boot_rva, // bootstrap is the TLS callback
    );

    let tls_section = &mut pe.sections[tls_section_idx];
    tls_section.characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    tls_section.header.characteristics = tls_section.characteristics;
    tls_section.header.virtual_size = 0x200;
    tls_section.virtual_size = 0x200;
    tls_section.header.size_of_raw_data = 0x200;
    tls_section.raw_size = 0x200;
    tls_section.extra_data = Some(tls_data);

    // 3. Update TLS Data Directory
    pe.nt_headers.optional_header.data_directory[9].virtual_address = tls_rva;
    pe.nt_headers.optional_header.data_directory[9].size = TLS_DIRECTORY_SIZE as u32;

    info!(
        tls_rva = format_args!("{tls_rva:#x}"),
        boot_rva = format_args!("{boot_rva:#x}"),
        containers = containers.len(),
        original_entry_point = format_args!("{original_entry_point:#x}"),
        "Installed TLS callback container restoration bootstrap"
    );

    // CRITICAL DEBUG: Verify TLS was set
    debug!(
        "AFTER TLS INSTALL: DataDirectory[9] = {{ RVA={:#x}, Size={:#x} }}",
        pe.nt_headers.optional_header.data_directory[9].virtual_address,
        pe.nt_headers.optional_header.data_directory[9].size
    );

    // Return original entry point unchanged
    Some(original_entry_point)
}

/// Build TLS Directory structure and associated data.
///
/// Layout:
/// ```text
/// +0x000: IMAGE_TLS_DIRECTORY64 (0x28 bytes)
/// +0x028: TLS Index (u32, initially 0)
/// +0x02C: padding
/// +0x030: Callback Array (2 * u64: callback VA + NULL)
/// +0x040: padding to 0x200
/// ```
#[allow(dead_code)] // pending P2 TLS restoration
fn build_tls_directory(image_base: u64, tls_rva: u32, bootstrap_rva: u32) -> Vec<u8> {
    let mut data = vec![0u8; 0x200];

    // Offsets within .tls section
    let tls_index_offset = TLS_DIRECTORY_SIZE;
    let callbacks_offset = TLS_DIRECTORY_SIZE + 8; // after index + padding

    // Virtual addresses
    let tls_data_start_va = image_base + tls_rva as u64 + TLS_DIRECTORY_SIZE as u64;
    let tls_data_end_va = tls_data_start_va; // No actual TLS data
    let tls_index_va = image_base + tls_rva as u64 + tls_index_offset as u64;
    let callbacks_array_va = image_base + tls_rva as u64 + callbacks_offset as u64;
    let bootstrap_va = image_base + bootstrap_rva as u64;

    // IMAGE_TLS_DIRECTORY64
    data[0x00..0x08].copy_from_slice(&tls_data_start_va.to_le_bytes());
    data[0x08..0x10].copy_from_slice(&tls_data_end_va.to_le_bytes());
    data[0x10..0x18].copy_from_slice(&tls_index_va.to_le_bytes());
    data[0x18..0x20].copy_from_slice(&callbacks_array_va.to_le_bytes());
    data[0x20..0x24].copy_from_slice(&0u32.to_le_bytes()); // SizeOfZeroFill
    data[0x24..0x28].copy_from_slice(&0u32.to_le_bytes()); // Characteristics

    // TLS Index (initialized to 0)
    data[tls_index_offset..tls_index_offset + 4].copy_from_slice(&0u32.to_le_bytes());

    // Callback Array
    data[callbacks_offset..callbacks_offset + 8].copy_from_slice(&bootstrap_va.to_le_bytes());
    data[callbacks_offset + 8..callbacks_offset + 16].copy_from_slice(&0u64.to_le_bytes()); // NULL terminator

    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_directory_size_correct() {
        assert_eq!(TLS_DIRECTORY_SIZE, 0x28);
    }

    #[test]
    fn tls_data_has_callback() {
        let data = build_tls_directory(0x140000000, 0x1000, 0x2000);

        // Check callback array VA in TLS Directory
        let callbacks_va = u64::from_le_bytes(data[0x18..0x20].try_into().unwrap());
        assert_eq!(callbacks_va, 0x140001030); // image_base + tls_rva + callbacks_offset

        // Check callback entry
        let callback_offset = TLS_DIRECTORY_SIZE + 8;
        let callback_va = u64::from_le_bytes(
            data[callback_offset..callback_offset + 8]
                .try_into()
                .unwrap(),
        );
        assert_eq!(callback_va, 0x140002000); // image_base + bootstrap_rva
    }
}
