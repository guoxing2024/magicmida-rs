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
}
