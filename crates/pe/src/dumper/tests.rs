//! Tests for the dumper module.
//!
//! Extracted from `dumper.rs`.

#[cfg(test)]
mod tests {
    use super::super::helpers::{preference_score, read_ptr, write_ptr, MAX_GAP_SLOTS};
    use super::super::helpers::is_dotnet;
    use super::super::original_imports::get_original_imports;
    use super::super::types::RemoteModule;
    use super::super::types::is_api_address;
    use crate::header::PeHeader;
    use crate::import_table::iat_slot_size;

    #[allow(dead_code)]
    fn make_minimal_pe() -> Vec<u8> {
        crate::header::make_minimal_pe64()
    }

    #[test]
    fn preference_score_kernel32_highest() {
        let ks = preference_score("kernel32.dll");
        let kb = preference_score("kernelbase.dll");
        assert!(ks > kb, "kernel32 should score higher than kernelbase");
    }

    #[test]
    fn preference_score_unknown_is_zero() {
        assert_eq!(preference_score("unknown.dll"), 0);
    }

    #[test]
    fn is_dotnet_detection() {
        // Build a PE header with a COM descriptor
        let data = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&data).unwrap();
        assert!(!is_dotnet(&pe));

        pe.nt_headers.optional_header.data_directory[14].virtual_address = 0x2000;
        assert!(is_dotnet(&pe));
    }

    #[test]
    fn get_original_imports_empty_on_no_imports() {
        // The minimal PE64 has no import directory
        let data = crate::header::make_minimal_pe64();

        // Write to a temp file
        let tmp = std::env::temp_dir().join("test_pe_no_imports.exe");
        std::fs::write(&tmp, &data).unwrap();

        let result = get_original_imports(&tmp).unwrap();
        assert!(result.is_empty());

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn read_ptr_32bit() {
        let data = [0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_ptr(&data, 0, false), 0x12345678);
    }

    #[test]
    fn read_ptr_64bit() {
        let data = [
            0xEF, 0xCD, 0xAB, 0x90, 0x78, 0x56, 0x34, 0x12,
        ];
        assert_eq!(read_ptr(&data, 0, true), 0x1234567890ABCDEF);
    }

    #[test]
    fn write_ptr_round_trip() {
        let mut data = vec![0u8; 16];
        write_ptr(&mut data, 0, 0xDEADBEEF, false);
        assert_eq!(read_ptr(&data, 0, false), 0xDEADBEEF);

        write_ptr(&mut data, 8, 0xCAFEBABEDEADBEEF, true);
        assert_eq!(read_ptr(&data, 8, true), 0xCAFEBABEDEADBEEF);
    }

    #[test]
    fn determine_iat_size_empty_modules() {
        let is_64bit = true;
        let iat_data = vec![0u8; 64]; // all zeros — no valid API addresses
        // With no modules, all addresses are invalid, so result = sizeof(pointer)
        let size = determine_iat_size_internal(&iat_data, &[], is_64bit);
        assert_eq!(size, 8); // just the base pointer size
    }

    /// Internal version of determine_iat_size that doesn't need a debugger.
    fn determine_iat_size_internal(
        iat_data: &[u8],
        modules: &[RemoteModule],
        is_64bit: bool,
    ) -> usize {
        let ptr_size = iat_slot_size(is_64bit);
        let max_slots = iat_data.len() / ptr_size;

        let mut last_valid_offset: usize = 0;
        let mut i: usize = 0;

        while i < max_slots
            && (last_valid_offset == 0 || i < last_valid_offset / ptr_size + MAX_GAP_SLOTS)
        {
            let val = read_ptr(iat_data, i * ptr_size, is_64bit);

            if is_api_address(modules, val) {
                last_valid_offset = i * ptr_size;
            }

            i += 1;
        }

        last_valid_offset + ptr_size
    }
}
