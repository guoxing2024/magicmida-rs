//! Immutable runtime observation of a PE base-relocation directory.
//!
//! Production `.expect()`s are invariants (WO-12): each site follows a guard
//! that makes the expected value unreachable-None/Err (len-matched slices,
//! `if has_x` + `plan.x` co-check, `match`-bound states, caller-validated
//! member names, re-serialization of an already-parsed Value, FFI
//! kernel32/Sleep existence, or caller pre-checked Option). No production
//! fallible path is masked; the one genuinely reachable panic (bundle_gate
//! member lookup) was converted to error propagation. Test-block expects are
//! ordinary assertions (WO-14).
#![allow(clippy::expect_used)]
//!
//! The caller supplies the live-memory reader. This module only records the
//! relocation table and normalizes relocated values before dump mutation.

use std::fmt;

use crate::header::PeHeader;

pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
const MAX_RELOCATION_DIRECTORY_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationTargetStatus {
    Normalized,
    ShortRead,
    InvalidAddress,
    InvalidType,
    ValueOutsideImage,
    ReadError,
}

impl fmt::Display for RelocationTargetStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Normalized => "Normalized",
            Self::ShortRead => "ShortRead",
            Self::InvalidAddress => "InvalidAddress",
            Self::InvalidType => "InvalidType",
            Self::ValueOutsideImage => "ValueOutsideImage",
            Self::ReadError => "ReadError",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationTargetObservation {
    pub block_index: u32,
    pub entry_index: u32,
    pub page_rva: u32,
    pub target_rva: u32,
    pub relocation_type: u8,
    pub bytes_read: usize,
    pub runtime_value: Option<u64>,
    pub normalized_value: Option<u64>,
    pub status: RelocationTargetStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationObservationReport {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
    pub size_of_image: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_bytes_read: usize,
    pub dynamic_base: bool,
    pub relocs_stripped: bool,
    pub block_count: u32,
    pub entry_count: u32,
    pub non_absolute_entry_count: u32,
    pub observed_types: Vec<u8>,
    pub targets: Vec<RelocationTargetObservation>,
    pub blockers: Vec<String>,
}

impl Default for RelocationObservationReport {
    fn default() -> Self {
        Self {
            directory_present: false,
            pe32_plus: false,
            pointer_size: 4,
            runtime_image_base: 0,
            preferred_image_base: 0,
            size_of_image: 0,
            directory_rva: 0,
            directory_size: 0,
            directory_bytes_read: 0,
            dynamic_base: false,
            relocs_stripped: false,
            block_count: 0,
            entry_count: 0,
            non_absolute_entry_count: 0,
            observed_types: Vec::new(),
            targets: Vec::new(),
            blockers: Vec::new(),
        }
    }
}

impl RelocationObservationReport {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.blockers.is_empty()
    }
}

pub fn observe_relocations_runtime<F, E>(
    pe: &PeHeader,
    load_base: u64,
    preferred_image_base: u64,
    mut read_memory: F,
) -> RelocationObservationReport
where
    F: FnMut(u64, &mut [u8]) -> Result<usize, E>,
    E: fmt::Display,
{
    let directory = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    let pointer_size = if pe.is_64bit { 8 } else { 4 };
    let directory_present = directory.virtual_address != 0 || directory.size != 0;
    let mut report = RelocationObservationReport {
        directory_present,
        pe32_plus: pe.is_64bit,
        pointer_size,
        runtime_image_base: load_base,
        preferred_image_base,
        size_of_image: pe.size_of_image(),
        directory_rva: directory.virtual_address,
        directory_size: directory.size,
        directory_bytes_read: 0,
        dynamic_base: (pe.nt_headers.optional_header.dll_characteristics
            & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
            != 0,
        relocs_stripped: (pe.nt_headers.file_header.characteristics & IMAGE_FILE_RELOCS_STRIPPED)
            != 0,
        block_count: 0,
        entry_count: 0,
        non_absolute_entry_count: 0,
        observed_types: Vec::new(),
        targets: Vec::new(),
        blockers: Vec::new(),
    };

    if !directory_present {
        return report;
    }
    if (directory.virtual_address == 0) != (directory.size == 0) {
        report
            .blockers
            .push("base relocation data-directory tuple is partial".to_string());
        return report;
    }
    let Ok(directory_size) = usize::try_from(directory.size) else {
        report
            .blockers
            .push("base relocation directory size does not fit host usize".to_string());
        return report;
    };
    if directory_size > MAX_RELOCATION_DIRECTORY_BYTES {
        report
            .blockers
            .push("base relocation directory exceeds observation limit".to_string());
        return report;
    }
    if directory_size < 8 {
        report
            .blockers
            .push("base relocation directory is shorter than one block header".to_string());
        return report;
    }
    if !valid_image_range(
        directory.virtual_address,
        directory.size,
        pe.size_of_image(),
    ) {
        report
            .blockers
            .push("base relocation directory is outside SizeOfImage".to_string());
        return report;
    }
    let Some(directory_address) = load_base.checked_add(u64::from(directory.virtual_address))
    else {
        report
            .blockers
            .push("base relocation directory VA overflow".to_string());
        return report;
    };
    let mut bytes = vec![0u8; directory_size];
    match read_memory(directory_address, &mut bytes) {
        Ok(read) if read == bytes.len() => report.directory_bytes_read = read,
        Ok(read) => {
            report.directory_bytes_read = read;
            report.blockers.push(format!(
                "base relocation directory short read {read}/{}",
                bytes.len()
            ));
            return report;
        }
        Err(error) => {
            report
                .blockers
                .push(format!("base relocation directory read failed: {error}"));
            return report;
        }
    }

    let relocation_type = if pe.is_64bit { 10u8 } else { 3u8 };
    let mut cursor = 0usize;
    while cursor < bytes.len() {
        let remaining = bytes.len() - cursor;
        if remaining < 8 {
            report
                .blockers
                .push("base relocation directory has a partial block header".to_string());
            break;
        }
        let page_rva = read_u32(&bytes, cursor).expect("checked block header");
        let block_size = read_u32(&bytes, cursor + 4).expect("checked block header") as usize;
        if block_size < 8 || block_size > remaining || block_size % 2 != 0 {
            report
                .blockers
                .push(format!("invalid base relocation block size {block_size}"));
            break;
        }
        if page_rva >= pe.size_of_image() || page_rva % 0x1000 != 0 {
            report
                .blockers
                .push(format!("invalid base relocation page RVA {page_rva:#x}"));
            break;
        }
        report.block_count = report.block_count.saturating_add(1);
        let entry_count = (block_size - 8) / 2;
        report.entry_count = report
            .entry_count
            .saturating_add(u32::try_from(entry_count).unwrap_or(u32::MAX));
        for entry_index in 0..entry_count {
            let word = u16::from_le_bytes([
                bytes[cursor + 8 + entry_index * 2],
                bytes[cursor + 9 + entry_index * 2],
            ]);
            let kind = (word >> 12) as u8;
            let offset = u32::from(word & 0x0fff);
            if !report.observed_types.contains(&kind) {
                report.observed_types.push(kind);
            }
            if kind == 0 {
                continue;
            }
            report.non_absolute_entry_count = report.non_absolute_entry_count.saturating_add(1);
            let target_rva = match page_rva.checked_add(offset) {
                Some(value) => value,
                None => {
                    report
                        .blockers
                        .push("relocation target RVA overflow".to_string());
                    continue;
                }
            };
            let valid_target =
                valid_image_range(target_rva, pointer_size as u32, pe.size_of_image());
            let mut target = RelocationTargetObservation {
                block_index: report.block_count - 1,
                entry_index: u32::try_from(entry_index).unwrap_or(u32::MAX),
                page_rva,
                target_rva,
                relocation_type: kind,
                bytes_read: 0,
                runtime_value: None,
                normalized_value: None,
                status: if kind == relocation_type && valid_target {
                    RelocationTargetStatus::Normalized
                } else if kind != relocation_type {
                    RelocationTargetStatus::InvalidType
                } else {
                    RelocationTargetStatus::InvalidAddress
                },
            };
            if kind != relocation_type {
                report.blockers.push(format!(
                    "relocation type {kind} is invalid for this architecture"
                ));
                report.targets.push(target);
                continue;
            }
            if !valid_target {
                report.blockers.push(format!(
                    "relocation target RVA {target_rva:#x} is outside image"
                ));
                report.targets.push(target);
                continue;
            }
            let Some(target_address) = load_base.checked_add(u64::from(target_rva)) else {
                target.status = RelocationTargetStatus::InvalidAddress;
                report
                    .blockers
                    .push("relocation target VA overflow".to_string());
                report.targets.push(target);
                continue;
            };
            let mut value_bytes = vec![0u8; pointer_size];
            match read_memory(target_address, &mut value_bytes) {
                Ok(read) if read == pointer_size => target.bytes_read = read,
                Ok(read) => {
                    target.bytes_read = read;
                    target.status = RelocationTargetStatus::ShortRead;
                    report.blockers.push(format!(
                        "relocation target {target_rva:#x} short read {read}/{pointer_size}"
                    ));
                    report.targets.push(target);
                    continue;
                }
                Err(error) => {
                    target.status = RelocationTargetStatus::ReadError;
                    report.blockers.push(format!(
                        "relocation target {target_rva:#x} read failed: {error}"
                    ));
                    report.targets.push(target);
                    continue;
                }
            }
            let runtime_value = if pe.is_64bit {
                u64::from_le_bytes(value_bytes.try_into().expect("64-bit relocation width"))
            } else {
                u32::from_le_bytes(value_bytes.try_into().expect("32-bit relocation width")) as u64
            };
            target.runtime_value = Some(runtime_value);
            let runtime_end = load_base.checked_add(u64::from(pe.size_of_image()));
            let Some(runtime_end) = runtime_end else {
                target.status = RelocationTargetStatus::ValueOutsideImage;
                report
                    .blockers
                    .push("runtime image range overflow".to_string());
                report.targets.push(target);
                continue;
            };
            if runtime_value < load_base || runtime_value >= runtime_end {
                target.status = RelocationTargetStatus::ValueOutsideImage;
                report.blockers.push(format!(
                    "runtime relocation value {runtime_value:#x} is not in the loaded image"
                ));
                report.targets.push(target);
                continue;
            }
            let normalized = match pe.image_base.checked_add(runtime_value - load_base) {
                Some(value) => value,
                None => {
                    target.status = RelocationTargetStatus::ValueOutsideImage;
                    report
                        .blockers
                        .push("normalized relocation value overflow".to_string());
                    report.targets.push(target);
                    continue;
                }
            };
            target.normalized_value = Some(normalized);
            report.targets.push(target);
        }
        cursor += block_size;
    }
    report.observed_types.sort_unstable();
    report.observed_types.dedup();
    report
}

fn valid_image_range(rva: u32, width: u32, size_of_image: u32) -> bool {
    rva.checked_add(width)
        .is_some_and(|end| end <= size_of_image)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let bytes = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PeHeader;

    fn synthetic_header() -> PeHeader {
        let mut bytes = vec![0u8; 0x800];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x96..0x98].copy_from_slice(&0x0002u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0x98 + 24..0x98 + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        bytes[0x98 + 56..0x98 + 60].copy_from_slice(&0x4000u32.to_le_bytes());
        bytes[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x98 + 70..0x98 + 72].copy_from_slice(&0x40u16.to_le_bytes());
        bytes[0x98 + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8
            ..0x98 + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4]
            .copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[0x98 + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 4
            ..0x98 + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8 + 8]
            .copy_from_slice(&12u32.to_le_bytes());
        let section = 0x188usize;
        bytes[section..section + 8].copy_from_slice(b".text\0\0\0");
        bytes[section + 8..section + 12].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[section + 20..section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        PeHeader::from_bytes(&bytes).expect("synthetic header")
    }

    #[test]
    fn normalizes_runtime_value_before_mutation() {
        let pe = synthetic_header();
        let runtime_base = 0x150000000u64;
        let mut memory = vec![0u8; 0x5000];
        let directory = 0x2000usize;
        memory[directory..directory + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        memory[directory + 4..directory + 8].copy_from_slice(&12u32.to_le_bytes());
        memory[directory + 8..directory + 10].copy_from_slice(&0xA100u16.to_le_bytes());
        let target = 0x1100usize;
        memory[target..target + 8].copy_from_slice(&(runtime_base + 0x1234).to_le_bytes());
        let report =
            observe_relocations_runtime(&pe, runtime_base, pe.image_base, |address, buffer| {
                let offset = usize::try_from(address - runtime_base).expect("offset");
                buffer.copy_from_slice(&memory[offset..offset + buffer.len()]);
                Ok::<usize, String>(buffer.len())
            });
        assert!(report.is_complete(), "{report:#?}");
        assert_eq!(report.non_absolute_entry_count, 1);
        assert_eq!(report.targets[0].normalized_value, Some(0x140001234));
    }
}
