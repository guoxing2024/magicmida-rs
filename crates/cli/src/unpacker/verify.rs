//! Verify an unpacked file against a known-good reference.

use crate::log::{self, LogType};
use anyhow::{anyhow, bail};
use mida_pe::{read_original_import_table, PeHeader};
use std::collections::HashMap;
use std::path::Path;

const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Verify an unpacked file against a known-good reference.
///
/// Compares loader-critical PE structure (architecture, entry point, section
/// layout, import modules/functions, and Import/IAT directories). Differences
/// that can make the output unloadable cause an error exit; benign layout
/// differences remain warnings because rebuilt files need not be byte-identical.
pub fn verify_unpacked(unpacked: &Path, reference: &Path) -> Result<(), anyhow::Error> {
    let pe_unpacked =
        PeHeader::from_file(unpacked).map_err(|e| anyhow!("Failed to parse unpacked PE: {e}"))?;
    let pe_reference =
        PeHeader::from_file(reference).map_err(|e| anyhow!("Failed to parse reference PE: {e}"))?;

    let mut hard_failures = Vec::new();
    let mut warnings = 0usize;

    if pe_unpacked.is_64bit != pe_reference.is_64bit {
        record_failure(
            &mut hard_failures,
            format!(
                "Architecture mismatch: unpacked={}, reference={}",
                architecture(&pe_unpacked),
                architecture(&pe_reference)
            ),
        );
    } else {
        log::log(
            LogType::Good,
            &format!("Architecture: {} ✓", architecture(&pe_unpacked)),
        );
    }

    validate_entry_point(&pe_unpacked, "unpacked", &mut hard_failures);
    validate_directories(&pe_unpacked, "unpacked", &mut hard_failures);

    let unpacked_bytes =
        std::fs::read(unpacked).map_err(|e| anyhow!("Failed to read unpacked PE bytes: {e}"))?;
    validate_import_lookups(
        &pe_unpacked,
        &unpacked_bytes,
        "unpacked",
        &mut hard_failures,
    );

    if pe_unpacked.entry_point != pe_reference.entry_point {
        record_warning(
            &mut warnings,
            format!(
                "Entry point differs: unpacked=0x{:X}, reference=0x{:X}",
                pe_unpacked.entry_point, pe_reference.entry_point
            ),
        );
    } else {
        log::log(
            LogType::Good,
            &format!("Entry point: 0x{:X} ✓", pe_unpacked.entry_point),
        );
    }

    compare_sections(&pe_unpacked, &pe_reference, &mut warnings);
    compare_imports(unpacked, reference, &mut hard_failures, &mut warnings);

    let unpacked_size = std::fs::metadata(unpacked).map(|m| m.len()).unwrap_or(0);
    let reference_size = std::fs::metadata(reference).map(|m| m.len()).unwrap_or(0);
    log::log(
        LogType::Info,
        &format!(
            "File sizes: unpacked={} bytes ({} MB), reference={} bytes ({} MB)",
            unpacked_size,
            unpacked_size / 1024 / 1024,
            reference_size,
            reference_size / 1024 / 1024
        ),
    );

    if !hard_failures.is_empty() {
        bail!(
            "Verification FAILED with {} loader-critical error(s)",
            hard_failures.len()
        );
    }

    if warnings == 0 {
        log::log(LogType::Good, "Verification PASSED ✓");
    } else {
        log::log(
            LogType::Warn,
            &format!("Verification PASSED with {warnings} warning(s)"),
        );
    }

    Ok(())
}

fn architecture(pe: &PeHeader) -> &'static str {
    if pe.is_64bit {
        "x64"
    } else {
        "x86"
    }
}

fn validate_entry_point(pe: &PeHeader, label: &str, failures: &mut Vec<String>) {
    let executable = pe.sections.iter().any(|section| {
        let start = section.virtual_address;
        let end = start.saturating_add(section.virtual_size.max(section.raw_size));
        pe.entry_point >= start
            && pe.entry_point < end
            && section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    });
    if !executable {
        record_failure(
            failures,
            format!(
                "{label} entry point 0x{:X} is not in an executable section",
                pe.entry_point
            ),
        );
    }
}

fn validate_directories(pe: &PeHeader, label: &str, failures: &mut Vec<String>) {
    for (name, index) in [
        ("Import", IMAGE_DIRECTORY_ENTRY_IMPORT),
        ("IAT", IMAGE_DIRECTORY_ENTRY_IAT),
    ] {
        let directory = pe.nt_headers.optional_header.data_directory[index];
        if directory.virtual_address == 0 || directory.size == 0 {
            record_failure(failures, format!("{label} {name} directory is missing"));
            continue;
        }
        if !range_within_image(directory.virtual_address, directory.size, pe) {
            record_failure(
                failures,
                format!(
                    "{label} {name} directory RVA 0x{:X} size 0x{:X} is outside the image",
                    directory.virtual_address, directory.size
                ),
            );
        }
    }
}

fn range_within_image(rva: u32, size: u32, pe: &PeHeader) -> bool {
    range_within_image_size(rva, size, pe.nt_headers.optional_header.size_of_image)
}

fn range_within_image_size(rva: u32, size: u32, image_size: u32) -> bool {
    rva < image_size && rva.checked_add(size).is_some_and(|end| end <= image_size)
}

/// Hard-fail when a non-ordinal import lookup is not a valid image RVA that
/// can resolve to a hint/name entry. Live process pointers left in FirstThunk
/// (when OFT is zero) make the PE unloadable and must never PASS with warnings.
fn validate_import_lookups(pe: &PeHeader, bytes: &[u8], label: &str, failures: &mut Vec<String>) {
    let import_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if import_dir.virtual_address == 0 || import_dir.size == 0 {
        return;
    }
    let failures_before = failures.len();

    let Some(desc_file_off) = pe.rva_to_offset(import_dir.virtual_address) else {
        record_failure(
            failures,
            format!(
                "{label} import directory RVA 0x{:X} is not mapped to a file offset",
                import_dir.virtual_address
            ),
        );
        return;
    };
    let desc_off = desc_file_off as usize;
    let desc_size = 20usize;
    let ordinal_flag = if pe.is_64bit {
        0x8000_0000_0000_0000u64
    } else {
        0x8000_0000u64
    };
    let thunk_size = if pe.is_64bit { 8usize } else { 4usize };
    let image_size = pe.nt_headers.optional_header.size_of_image;

    let mut desc_index = 0usize;
    let mut offset = desc_off;
    while offset + desc_size <= bytes.len() {
        let desc = &bytes[offset..offset + desc_size];
        let original_first_thunk = u32::from_le_bytes(desc[0..4].try_into().unwrap());
        let name_rva = u32::from_le_bytes(desc[12..16].try_into().unwrap());
        let first_thunk = u32::from_le_bytes(desc[16..20].try_into().unwrap());

        if name_rva == 0 {
            break;
        }

        let lookup_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        if lookup_rva == 0 {
            record_failure(
                failures,
                format!(
                    "{label} import descriptor {desc_index} has zero lookup table (OFT and FirstThunk)"
                ),
            );
            offset += desc_size;
            desc_index += 1;
            continue;
        }

        let mut thunk_rva = lookup_rva;
        let mut thunk_index = 0usize;
        loop {
            let Some(thunk_file_off) = pe.rva_to_offset(thunk_rva) else {
                record_failure(
                    failures,
                    format!(
                        "{label} import descriptor {desc_index} thunk[{thunk_index}] RVA 0x{thunk_rva:X} is outside the image sections"
                    ),
                );
                break;
            };
            let thunk_file_off = thunk_file_off as usize;
            if thunk_file_off + thunk_size > bytes.len() {
                record_failure(
                    failures,
                    format!(
                        "{label} import descriptor {desc_index} thunk[{thunk_index}] extends past end of file"
                    ),
                );
                break;
            }

            let value = if pe.is_64bit {
                u64::from_le_bytes(
                    bytes[thunk_file_off..thunk_file_off + 8]
                        .try_into()
                        .unwrap(),
                )
            } else {
                u32::from_le_bytes(
                    bytes[thunk_file_off..thunk_file_off + 4]
                        .try_into()
                        .unwrap(),
                ) as u64
            };

            if value == 0 {
                break;
            }

            if value & ordinal_flag != 0 {
                // Ordinal imports are valid without a hint/name RVA.
            } else {
                // Non-ordinal: must be a legitimate image RVA to a hint/name entry.
                if value > u32::MAX as u64 {
                    record_failure(
                        failures,
                        format!(
                            "{label} import descriptor {desc_index} thunk[{thunk_index}] non-ordinal value 0x{value:X} is not a 32-bit image RVA (likely a live process pointer)"
                        ),
                    );
                } else {
                    let hint_rva = value as u32;
                    if !range_within_image_size(hint_rva, 3, image_size) {
                        record_failure(
                            failures,
                            format!(
                                "{label} import descriptor {desc_index} thunk[{thunk_index}] non-ordinal value 0x{hint_rva:X} is outside SizeOfImage"
                            ),
                        );
                    } else if pe.rva_to_offset(hint_rva).is_none() {
                        record_failure(
                            failures,
                            format!(
                                "{label} import descriptor {desc_index} thunk[{thunk_index}] non-ordinal value 0x{hint_rva:X} is not a mapped hint/name RVA"
                            ),
                        );
                    } else if let Some(hn_off) = pe.rva_to_offset(hint_rva) {
                        let hn_off = hn_off as usize;
                        // hint (2 bytes) + at least one name byte or null
                        if hn_off + 3 > bytes.len() {
                            record_failure(
                                failures,
                                format!(
                                    "{label} import descriptor {desc_index} thunk[{thunk_index}] hint/name at 0x{hint_rva:X} extends past end of file"
                                ),
                            );
                        }
                    }
                }
            }

            thunk_rva = match thunk_rva.checked_add(thunk_size as u32) {
                Some(next) => next,
                None => break,
            };
            thunk_index += 1;
            if thunk_index > 10_000 {
                record_failure(
                    failures,
                    format!(
                        "{label} import descriptor {desc_index} thunk run exceeds safety limit"
                    ),
                );
                break;
            }
        }

        offset += desc_size;
        desc_index += 1;
        if desc_index > 512 {
            record_failure(
                failures,
                format!("{label} import descriptor count exceeds safety limit"),
            );
            break;
        }
    }

    if failures.len() == failures_before && desc_index > 0 {
        log::log(
            LogType::Good,
            &format!("{label} import lookups: {desc_index} descriptor(s) ✓"),
        );
    }
}

fn compare_sections(unpacked: &PeHeader, reference: &PeHeader, warnings: &mut usize) {
    if unpacked.sections.len() != reference.sections.len() {
        record_warning(
            warnings,
            format!(
                "Section count differs: unpacked={}, reference={}",
                unpacked.sections.len(),
                reference.sections.len()
            ),
        );
    } else {
        log::log(
            LogType::Good,
            &format!("Section count: {} ✓", unpacked.sections.len()),
        );
    }

    for (index, (actual, expected)) in unpacked
        .sections
        .iter()
        .zip(reference.sections.iter())
        .enumerate()
    {
        if actual.name == expected.name
            && actual.virtual_address == expected.virtual_address
            && actual.virtual_size == expected.virtual_size
            && actual.characteristics == expected.characteristics
        {
            continue;
        }
        record_warning(
            warnings,
            format!(
                "Section {index} differs: unpacked={} VA=0x{:X} VS=0x{:X}, reference={} VA=0x{:X} VS=0x{:X}",
                actual.name,
                actual.virtual_address,
                actual.virtual_size,
                expected.name,
                expected.virtual_address,
                expected.virtual_size
            ),
        );
    }
}

fn compare_imports(
    unpacked: &Path,
    reference: &Path,
    failures: &mut Vec<String>,
    warnings: &mut usize,
) {
    let actual = coalesce_import_descriptors(read_original_import_table(unpacked));
    let expected = coalesce_import_descriptors(read_original_import_table(reference));

    if actual.is_empty() {
        record_failure(
            failures,
            "Unpacked import table is empty or malformed".to_string(),
        );
        return;
    }
    if expected.is_empty() {
        record_warning(
            warnings,
            "Reference import table is empty or malformed; exact import comparison skipped"
                .to_string(),
        );
        return;
    }

    let actual_count = actual
        .iter()
        .map(|(_, functions)| functions.len())
        .sum::<usize>();
    let expected_count = expected
        .iter()
        .map(|(_, functions)| functions.len())
        .sum::<usize>();

    if actual == expected {
        log::log(
            LogType::Good,
            &format!("Imports: {} modules, {actual_count} thunks ✓", actual.len()),
        );
        return;
    }

    record_failure(
        failures,
        format!(
            "Import table differs: unpacked={} modules/{actual_count} thunks, reference={} modules/{expected_count} thunks",
            actual.len(),
            expected.len()
        ),
    );

    let actual_modules: Vec<&str> = actual.iter().map(|(name, _)| name.as_str()).collect();
    let expected_modules: Vec<&str> = expected.iter().map(|(name, _)| name.as_str()).collect();
    if actual_modules != expected_modules {
        log::log(
            LogType::Warn,
            &format!(
                "Import module order differs: unpacked=[{}], reference=[{}]",
                actual_modules.join(", "),
                expected_modules.join(", ")
            ),
        );
    }
}

fn coalesce_import_descriptors(imports: Vec<(String, Vec<String>)>) -> Vec<(String, Vec<String>)> {
    let mut result: Vec<(String, Vec<String>)> = Vec::new();
    let mut module_indices: HashMap<String, usize> = HashMap::new();

    for (module, functions) in imports {
        let key = module.to_ascii_lowercase();
        if let Some(&index) = module_indices.get(&key) {
            result[index].1.extend(functions);
        } else {
            module_indices.insert(key, result.len());
            result.push((module, functions));
        }
    }

    result
}

fn record_failure(failures: &mut Vec<String>, message: String) {
    log::log(LogType::Fatal, &message);
    failures.push(message);
}

fn record_warning(warnings: &mut usize, message: String) {
    log::log(LogType::Warn, &message);
    *warnings += 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_pe::PeHeader;

    #[test]
    fn coalesces_split_descriptors_without_reordering_functions() {
        let imports = vec![
            ("kernel32.dll".to_string(), vec!["A".to_string()]),
            ("user32.dll".to_string(), vec!["B".to_string()]),
            (
                "KERNEL32.DLL".to_string(),
                vec!["C".to_string(), "D".to_string()],
            ),
        ];

        assert_eq!(
            coalesce_import_descriptors(imports),
            vec![
                (
                    "kernel32.dll".to_string(),
                    vec!["A".to_string(), "C".to_string(), "D".to_string()]
                ),
                ("user32.dll".to_string(), vec!["B".to_string()])
            ]
        );
    }

    #[test]
    fn range_validation_rejects_overflow_and_image_end() {
        assert!(range_within_image_size(0x1000, 0x2000, 0x5000));
        assert!(!range_within_image_size(0x5000, 1, 0x5000));
        assert!(!range_within_image_size(u32::MAX - 1, 8, 0x5000));
    }

    /// Build a tiny PE32+ with one import descriptor and a controllable lookup slot.
    /// Layout in section raw (file 0x200 / RVA 0x1000):
    ///   +0x00 descriptor (OFT=0, Name, FirstThunk)
    ///   +0x14 null descriptor
    ///   +0x28 DLL name "a.dll\0"
    ///   +0x30 IAT: one slot + terminator
    ///   +0x40 hint/name for "Foo"
    fn synthetic_pe_with_import_lookup(lookup_value: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 0x400];

        // DOS header
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[60] = 0x40; // e_lfanew

        let nt = 0x40usize;
        buf[nt] = 0x50;
        buf[nt + 1] = 0x45;
        // Machine AMD64
        buf[nt + 4] = 0x64;
        buf[nt + 5] = 0x86;
        // NumberOfSections = 1
        buf[nt + 6] = 1;
        // SizeOfOptionalHeader = 0xF0
        buf[nt + 20] = 0xF0;
        // Characteristics
        buf[nt + 22] = 0x22;

        let oh = nt + 24;
        // Magic PE32+
        buf[oh] = 0x0B;
        buf[oh + 1] = 0x02;
        // AddressOfEntryPoint = 0x1000
        buf[oh + 16] = 0x00;
        buf[oh + 17] = 0x10;
        // ImageBase = 0x140000000
        buf[oh + 24] = 0x00;
        buf[oh + 25] = 0x00;
        buf[oh + 26] = 0x00;
        buf[oh + 27] = 0x40;
        buf[oh + 28] = 0x01;
        // SectionAlignment / FileAlignment
        buf[oh + 32] = 0x00;
        buf[oh + 33] = 0x10;
        buf[oh + 36] = 0x00;
        buf[oh + 37] = 0x02;
        // SizeOfImage = 0x2000, SizeOfHeaders = 0x200
        buf[oh + 56] = 0x00;
        buf[oh + 57] = 0x20;
        buf[oh + 60] = 0x00;
        buf[oh + 61] = 0x02;
        // Subsystem = WINDOWS_CUI (3)
        buf[oh + 68] = 0x03;
        // NumberOfRvaAndSizes = 16
        buf[oh + 108] = 0x10;

        // DataDirectory[1] = Import at RVA 0x1000 size 0x28
        let dd = oh + 112;
        let import_dd = dd + 8; // index 1
        buf[import_dd..import_dd + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        buf[import_dd + 4..import_dd + 8].copy_from_slice(&0x28u32.to_le_bytes());
        // DataDirectory[12] = IAT at RVA 0x1030 size 0x10
        let iat_dd = dd + 12 * 8;
        buf[iat_dd..iat_dd + 4].copy_from_slice(&0x1030u32.to_le_bytes());
        buf[iat_dd + 4..iat_dd + 8].copy_from_slice(&0x10u32.to_le_bytes());

        // Section header
        let sh = nt + 24 + 240;
        buf[sh..sh + 6].copy_from_slice(b".rdata");
        buf[sh + 8..sh + 12].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        buf[sh + 12..sh + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        buf[sh + 16..sh + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        buf[sh + 20..sh + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        buf[sh + 36..sh + 40].copy_from_slice(&0x4000_0040u32.to_le_bytes()); // READ|INIT

        // Section raw at 0x200
        let raw = 0x200usize;
        // IMAGE_IMPORT_DESCRIPTOR: OFT=0, Name=0x1028, FirstThunk=0x1030
        // Name RVA 0x1028 → offset 0x228
        // IAT RVA 0x1030 → offset 0x230
        // Hint/Name RVA 0x1040 → offset 0x240
        let name_rva = 0x1028u32;
        let ft_rva = 0x1030u32;
        buf[raw..raw + 4].copy_from_slice(&0u32.to_le_bytes()); // OFT
        buf[raw + 12..raw + 16].copy_from_slice(&name_rva.to_le_bytes());
        buf[raw + 16..raw + 20].copy_from_slice(&ft_rva.to_le_bytes());
        // null descriptor already zero

        // DLL name
        buf[raw + 0x28..raw + 0x2e].copy_from_slice(b"a.dll\0");

        // IAT: lookup slot + terminator
        buf[raw + 0x30..raw + 0x38].copy_from_slice(&lookup_value.to_le_bytes());
        buf[raw + 0x38..raw + 0x40].copy_from_slice(&0u64.to_le_bytes());

        // Hint/Name "Foo" at 0x1040
        buf[raw + 0x40] = 0; // hint lo
        buf[raw + 0x41] = 0; // hint hi
        buf[raw + 0x42..raw + 0x46].copy_from_slice(b"Foo\0");

        buf
    }

    #[test]
    fn invalid_non_ordinal_lookup_hard_fails() {
        // Live process pointer (not a valid image RVA / hint-name RVA).
        let bytes = synthetic_pe_with_import_lookup(0x0000_7FF8_1234_5678);
        let pe = PeHeader::from_bytes(&bytes).expect("parse synthetic pe");
        let mut failures = Vec::new();
        validate_import_lookups(&pe, &bytes, "unpacked", &mut failures);
        assert!(
            !failures.is_empty(),
            "live pointer in import lookup must hard-fail, got: {failures:?}"
        );
        assert!(
            failures.iter().any(|m| m.contains("live process pointer")
                || m.contains("outside SizeOfImage")
                || m.contains("not a mapped hint/name")),
            "expected loader-invalid lookup message, got: {failures:?}"
        );
    }

    #[test]
    fn invalid_small_non_mapped_rva_hard_fails() {
        // Fits in 32 bits but not mapped to any section raw.
        let bytes = synthetic_pe_with_import_lookup(0x50u64);
        let pe = PeHeader::from_bytes(&bytes).expect("parse synthetic pe");
        let mut failures = Vec::new();
        validate_import_lookups(&pe, &bytes, "unpacked", &mut failures);
        assert!(
            !failures.is_empty(),
            "unmapped non-ordinal RVA must hard-fail, got: {failures:?}"
        );
    }

    #[test]
    fn valid_hint_name_lookup_passes() {
        let bytes = synthetic_pe_with_import_lookup(0x1040u64);
        let pe = PeHeader::from_bytes(&bytes).expect("parse synthetic pe");
        let mut failures = Vec::new();
        validate_import_lookups(&pe, &bytes, "unpacked", &mut failures);
        assert!(
            failures.is_empty(),
            "valid hint/name RVA must pass, got: {failures:?}"
        );
    }

    #[test]
    fn valid_ordinal_lookup_passes() {
        let ordinal = 0x8000_0000_0000_0000u64 | 42;
        let bytes = synthetic_pe_with_import_lookup(ordinal);
        let pe = PeHeader::from_bytes(&bytes).expect("parse synthetic pe");
        let mut failures = Vec::new();
        validate_import_lookups(&pe, &bytes, "unpacked", &mut failures);
        assert!(
            failures.is_empty(),
            "ordinal import must pass, got: {failures:?}"
        );
    }

    #[test]
    fn verify_unpacked_hard_fails_on_invalid_lookup_not_passed_with_warnings() {
        let bad = synthetic_pe_with_import_lookup(0x0000_7FFA_DEAD_BEEF);
        // Reference is also invalid — still must hard-fail on unpacked lookups
        // before any "PASSED with warnings" path.
        let tmp = std::env::temp_dir();
        let unpacked = tmp.join("mida_verify_bad_lookup_unpacked.exe");
        let reference = tmp.join("mida_verify_bad_lookup_reference.exe");
        std::fs::write(&unpacked, &bad).unwrap();
        std::fs::write(&reference, &bad).unwrap();

        let result = verify_unpacked(&unpacked, &reference);
        let _ = std::fs::remove_file(&unpacked);
        let _ = std::fs::remove_file(&reference);

        assert!(
            result.is_err(),
            "invalid lookup must not end as PASSED (with or without warnings)"
        );
        let msg = format!("{:#}", result.unwrap_err());
        assert!(
            msg.contains("FAILED") || msg.contains("loader-critical"),
            "expected hard-fail message, got: {msg}"
        );
    }
}
