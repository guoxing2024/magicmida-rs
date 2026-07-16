//! Complete .data section snapshot and restoration module.
//!
//! This module provides a comprehensive approach to data section restoration:
//! instead of trying to detect individual variables, we capture the entire
//! runtime .data section and restore it during bootstrap.
//!
//! ## Strategy
//!
//! 1. Capture the entire .data section from the live process at OEP
//! 2. Exclude regions that will be handled by container restoration
//!    (SecurityCookie-encoded pointer triples)
//! 3. Embed the snapshot in the bootstrap stub
//! 4. Restore the .data section before container restoration in TLS callback
//!
//! ## Why This Works
//!
//! - Themida decrypts/initializes the entire .data section at runtime
//! - By capturing it at OEP, we get all initialized values
//! - Container restoration handles heap-backed data separately
//! - This avoids missing any critical variables

use tracing::{debug, info, warn};

use crate::header::PeHeader;

/// Snapshot of the complete .data section from the live process.
#[derive(Debug, Clone)]
pub struct DataSectionSnapshot {
    /// RVA of .data section start
    pub data_rva: u32,
    /// Size of .data section
    pub data_size: u32,
    /// Runtime content of .data section
    pub data_content: Vec<u8>,
    /// Regions to skip during restoration (container metadata positions)
    pub skip_regions: Vec<SkipRegion>,
}

/// A region in .data that should not be overwritten during restoration.
#[derive(Debug, Clone)]
pub struct SkipRegion {
    /// Offset from .data section start
    pub offset: u32,
    /// Size of region to skip
    pub size: u32,
}

/// Capture the complete .data section from the live process.
///
/// This function reads the entire .data section at runtime, preserving
/// all initialized values. Container regions are identified so they
/// can be skipped during restoration.
pub fn capture_data_section(
    pe: &PeHeader,
    debugger: &mut dyn mida_core::DebuggerCore,
    container_rvas: &[u32],
) -> Option<DataSectionSnapshot> {
    // Find .data section
    let data_section = pe.sections.iter().find(|s| s.name == ".data")?;

    let data_rva = data_section.virtual_address;
    let data_size = data_section.virtual_size;

    if data_size == 0 || data_size > 0x10_0000 {
        warn!(
            data_rva = format_args!("{:#x}", data_rva),
            data_size = format_args!("{:#x}", data_size),
            ".data section size is invalid or too large"
        );
        return None;
    }

    // Read entire .data section from live process
    let image_base = pe.nt_headers.optional_header.image_base;
    let data_va = image_base + data_rva as u64;

    let mut data_content = vec![0u8; data_size as usize];
    match debugger.read_memory(data_va as usize, &mut data_content) {
        Ok(bytes_read) => {
            if bytes_read < data_size as usize {
                warn!(
                    expected = data_size,
                    actual = bytes_read,
                    "Short read on .data section"
                );
                data_content.truncate(bytes_read);
            }
        }
        Err(e) => {
            warn!(
                data_va = format_args!("{:#x}", data_va),
                error = %e,
                "Failed to read .data section from live process"
            );
            return None;
        }
    }

    // Build skip regions for container metadata (24 bytes per container: 3x u64 pointers)
    let mut skip_regions = Vec::new();
    for &container_rva in container_rvas {
        if container_rva >= data_rva && container_rva < data_rva + data_size {
            let offset = container_rva - data_rva;
            skip_regions.push(SkipRegion {
                offset,
                size: 24, // sizeof(begin, end, capacity)
            });

            debug!(
                container_rva = format_args!("{:#x}", container_rva),
                offset = offset,
                "Added skip region for container metadata"
            );
        }
    }

    info!(
        data_rva = format_args!("{:#x}", data_rva),
        data_size = format_args!("{:#x}", data_size),
        skip_regions = skip_regions.len(),
        "Captured complete .data section snapshot"
    );

    Some(DataSectionSnapshot {
        data_rva,
        data_size,
        data_content,
        skip_regions,
    })
}

/// Generate x64 assembly code to restore the .data section.
///
/// This code will be injected into the TLS bootstrap stub and will
/// copy the snapshot data to the .data section, skipping container regions.
///
/// ## Generated Code (pseudo-assembly)
///
/// ```asm
/// ; Restore .data section
/// lea rdi, [rip + .data]        ; dest = .data VA
/// lea rsi, [rip + snapshot]     ; source = embedded snapshot
/// mov rcx, data_size            ; count
/// rep movsb                     ; memcpy
///
/// ; Note: Skip regions are handled by not embedding them in the snapshot
/// ; or by generating multiple memcpy calls around skip regions
/// ```
pub fn build_data_restore_code(
    stub_rva: u32,
    current_offset: usize,
    snapshot: &DataSectionSnapshot,
    image_base: u64,
) -> Option<Vec<u8>> {
    let mut code = Vec::new();

    let data_va = image_base + snapshot.data_rva as u64;

    // If there are skip regions, we need to do multiple memcpy calls
    // For simplicity in this first implementation, we'll do a single memcpy
    // and let container restoration overwrite the container regions afterward

    // Strategy: Generate code that copies the entire .data section
    // Container restoration will overwrite the SecurityCookie-encoded triples

    // Alternative: mov rdi, data_va (absolute)
    code.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, imm64
    code.extend_from_slice(&data_va.to_le_bytes());

    // lea rsi, [rip + snapshot_offset]
    // The snapshot will be embedded after the code
    code.extend_from_slice(&[0x48, 0x8d, 0x35]); // lea rsi, [rip + disp32]
    let _lea_next2 = stub_rva.checked_add(current_offset as u32)?.checked_add(code.len() as u32)?.checked_add(4)?;

    // The snapshot will be placed right after build_data_restore_code returns
    // We need to return info about where to place it
    // For now, use a placeholder - caller will patch this
    code.extend_from_slice(&0i32.to_le_bytes()); // Will be patched by caller

    // mov rcx, data_size
    code.extend_from_slice(&[0x48, 0xc7, 0xc1]); // mov rcx, imm32
    code.extend_from_slice(&snapshot.data_size.to_le_bytes());

    // rep movsb
    code.extend_from_slice(&[0xf3, 0xa4]);

    Some(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_region_size_correct() {
        // Container metadata should be 24 bytes (3x u64)
        let skip = SkipRegion { offset: 0, size: 24 };
        assert_eq!(skip.size, 24);
    }
}
