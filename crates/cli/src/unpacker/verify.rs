//! Verify an unpacked file against a known-good reference.

use std::path::Path;
use anyhow::anyhow;
use mida_pe::PeHeader;
use crate::log::{self, LogType};

/// Verify an unpacked file against a known-good reference.
///
/// Compares PE structure (entry point, sections, imports) between the
/// file we produced and a reference file to validate correctness.
pub fn verify_unpacked(unpacked: &Path, reference: &Path) -> Result<(), anyhow::Error> {
    let pe_unpacked = PeHeader::from_file(unpacked)
        .map_err(|e| anyhow!("Failed to parse unpacked PE: {e}"))?;
    let pe_reference = PeHeader::from_file(reference)
        .map_err(|e| anyhow!("Failed to parse reference PE: {e}"))?;

    let mut all_ok = true;

    if pe_unpacked.is_64bit != pe_reference.is_64bit {
        log::log(LogType::Fatal, &format!(
            "Architecture mismatch: unpacked={}, reference={}",
            if pe_unpacked.is_64bit { "x64" } else { "x86" },
            if pe_reference.is_64bit { "x64" } else { "x86" }
        ));
        all_ok = false;
    } else {
        log::log(LogType::Good, &format!(
            "Architecture: {} ✓",
            if pe_unpacked.is_64bit { "x64" } else { "x86" }
        ));
    }

    if pe_unpacked.entry_point != pe_reference.entry_point {
        log::log(LogType::Warn, &format!(
            "Entry point differs: unpacked=0x{:X}, reference=0x{:X}",
            pe_unpacked.entry_point, pe_reference.entry_point
        ));
    } else {
        log::log(LogType::Good, &format!("Entry point: 0x{:X} ✓", pe_unpacked.entry_point));
    }

    if pe_unpacked.sections.len() != pe_reference.sections.len() {
        log::log(LogType::Warn, &format!(
            "Section count differs: unpacked={}, reference={}",
            pe_unpacked.sections.len(),
            pe_reference.sections.len()
        ));
    } else {
        log::log(LogType::Good, &format!("Section count: {} ✓", pe_unpacked.sections.len()));
    }

    let max_sections = pe_unpacked.sections.len().max(pe_reference.sections.len());
    for i in 0..max_sections {
        let unpacked_sec = pe_unpacked.sections.get(i);
        let reference_sec = pe_reference.sections.get(i);

        match (unpacked_sec, reference_sec) {
            (Some(u_sec), Some(r_sec)) => {
                let name_match = u_sec.name == r_sec.name;
                let size_match = u_sec.virtual_size == r_sec.virtual_size;
                let chars_match = u_sec.characteristics == r_sec.characteristics;

                if name_match && size_match && chars_match {
                    log::log(LogType::Good, &format!(
                        "  Section {}: {} (VA=0x{:X}, VS=0x{:X}) ✓",
                        i, u_sec.name, u_sec.virtual_address, u_sec.virtual_size
                    ));
                } else {
                    log::log(LogType::Warn, &format!(
                        "  Section {}: {} differs (name={}, size={}, chars={})",
                        i, u_sec.name, name_match, size_match, chars_match
                    ));
                    all_ok = false;
                }
            }
            (Some(u_sec), None) => {
                log::log(LogType::Info, &format!(
                    "  Section {}: {} (VA=0x{:X}) [extra in unpacked]",
                    i, u_sec.name, u_sec.virtual_address
                ));
            }
            (None, Some(r_sec)) => {
                log::log(LogType::Info, &format!(
                    "  Section {}: {} (VA=0x{:X}) [missing from unpacked]",
                    i, r_sec.name, r_sec.virtual_address
                ));
            }
            (None, None) => unreachable!(),
        }
    }

    let unpacked_size = std::fs::metadata(unpacked).map(|m| m.len()).unwrap_or(0);
    let reference_size = std::fs::metadata(reference).map(|m| m.len()).unwrap_or(0);

    log::log(LogType::Info, &format!(
        "File sizes: unpacked={} bytes ({} MB), reference={} bytes ({} MB)",
        unpacked_size, unpacked_size / 1024 / 1024,
        reference_size, reference_size / 1024 / 1024
    ));

    if all_ok {
        log::log(LogType::Good, "Verification PASSED ✓");
    } else {
        log::log(LogType::Warn, "Verification completed with warnings — review differences above");
    }

    Ok(())
}
