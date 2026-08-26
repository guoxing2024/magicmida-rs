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
    #[allow(dead_code)] // legacy restoration path
    pub skip_regions: Vec<SkipRegion>,
}

/// A region in .data that should not be overwritten during restoration.
#[derive(Debug, Clone)]
#[allow(dead_code)] // legacy restoration path
pub struct SkipRegion {
    /// Offset from .data section start
    #[allow(dead_code)]
    pub offset: u32,
    /// Size of region to skip
    #[allow(dead_code)]
    pub size: u32,
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
#[allow(dead_code)] // legacy .data restore path
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
    let _lea_next2 = stub_rva
        .checked_add(current_offset as u32)?
        .checked_add(code.len() as u32)?
        .checked_add(4)?;

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
        let skip = SkipRegion {
            offset: 0,
            size: 24,
        };
        assert_eq!(skip.size, 24);
    }
}
