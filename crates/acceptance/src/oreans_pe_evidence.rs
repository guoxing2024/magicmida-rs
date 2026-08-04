//! Structured Oreans PE evidence built only from final serialized candidate bytes.
//!
//! This module deliberately depends only on the acceptance crate's own PE view,
//! safe read helpers, `sha2`, and serde. It never opens, launches, or inspects a
//! live process.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::pe::view::{
    try_parse, DataDirectory, ParseIssue, PeImage, IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_I386,
    IMAGE_FILE_RELOCS_STRIPPED, IMAGE_NT_OPTIONAL_HDR64_MAGIC,
};

pub const OREANS_PE_EVIDENCE_SCHEMA_VERSION: &str = "mida.oreans-pe-evidence/v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct OreansPeEvidenceError {
    pub code: String,
    pub message: String,
}

impl OreansPeEvidenceError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    fn parse(issue: ParseIssue) -> Self {
        Self::new(issue.code, issue.message)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansPeCandidateIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansPeSectionEvidence {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansPeDirectoryCoverage {
    pub rva: u32,
    pub size: u32,
    pub present: bool,
    pub raw_backed: bool,
    pub in_image: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansTlsEvidence {
    pub directory_size: u32,
    pub address_of_index_rva: Option<u32>,
    pub callback_array_rva: Option<u32>,
    pub callback_rvas: Vec<u32>,
    pub null_terminated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansRelocationEvidence {
    pub block_count: u32,
    pub entry_count: u32,
    pub non_absolute_entry_count: u32,
    pub observed_types: Vec<u8>,
    pub all_targets_in_image: bool,
    pub dynamic_base: bool,
    pub relocs_stripped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansRuntimeFunctionEvidence {
    pub begin_rva: u32,
    pub end_rva: u32,
    pub unwind_rva: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansExceptionEvidence {
    pub runtime_function_count: u32,
    pub runtime_functions: Vec<OreansRuntimeFunctionEvidence>,
    pub ranges_raw_backed: bool,
    pub unwind_rvas_raw_backed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OreansPeEvidence {
    pub schema_version: String,
    pub valid: bool,
    pub candidate: OreansPeCandidateIdentity,
    pub machine: u16,
    pub pe32_plus: bool,
    pub image_base: u64,
    pub entry_rva: u32,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub coff_characteristics: u16,
    pub dll_characteristics: u16,
    pub sections: Vec<OreansPeSectionEvidence>,
    pub tls: OreansPeDirectoryCoverage,
    pub base_reloc: OreansPeDirectoryCoverage,
    pub exception: OreansPeDirectoryCoverage,
    pub tls_detail: Option<OreansTlsEvidence>,
    pub relocation_detail: Option<OreansRelocationEvidence>,
    pub exception_detail: Option<OreansExceptionEvidence>,
}

/// Build structured evidence from the exact final serialized candidate bytes.
///
/// The candidate digest and size are always computed here; callers cannot
/// substitute an identity record. All selected directories and architecture-
/// specific structures are validated before a report is returned.
pub fn build_oreans_pe_evidence(
    candidate_bytes: &[u8],
) -> Result<OreansPeEvidence, OreansPeEvidenceError> {
    let digest = hex_lower(&Sha256::digest(candidate_bytes));
    let image = try_parse(candidate_bytes).map_err(OreansPeEvidenceError::parse)?;
    validate_image(&image, candidate_bytes)?;

    let tls = coverage(&image, IMAGE_DIRECTORY_ENTRY_TLS)?;
    let base_reloc = coverage(&image, IMAGE_DIRECTORY_ENTRY_BASERELOC)?;
    let exception = coverage(&image, IMAGE_DIRECTORY_ENTRY_EXCEPTION)?;

    let tls_detail = if tls.present {
        Some(parse_tls(&image, tls.rva, tls.size)?)
    } else {
        None
    };
    let relocation_detail = if base_reloc.present {
        Some(parse_relocations(&image, base_reloc.rva, base_reloc.size)?)
    } else {
        None
    };
    if let Some(detail) = relocation_detail.as_ref() {
        if detail.dynamic_base && detail.non_absolute_entry_count == 0 {
            return Err(err(
                "dynamic_base_without_non_absolute_reloc",
                "DYNAMIC_BASE requires at least one non-ABSOLUTE relocation entry",
            ));
        }
    }
    let exception_detail = if exception.present {
        Some(parse_exceptions(&image, exception.rva, exception.size)?)
    } else {
        None
    };

    let sections = image
        .sections
        .iter()
        .map(|section| OreansPeSectionEvidence {
            name: section_name(&section.name),
            virtual_address: section.virtual_address,
            virtual_size: section.virtual_size,
            raw_offset: section.pointer_to_raw_data,
            raw_size: section.size_of_raw_data,
            characteristics: section.characteristics,
        })
        .collect();

    Ok(OreansPeEvidence {
        schema_version: OREANS_PE_EVIDENCE_SCHEMA_VERSION.to_string(),
        valid: true,
        candidate: OreansPeCandidateIdentity {
            sha256: digest,
            size_bytes: candidate_bytes.len() as u64,
        },
        machine: image.machine,
        pe32_plus: image.optional.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC,
        image_base: image.optional.image_base,
        entry_rva: image.optional.address_of_entry_point,
        file_alignment: image.optional.file_alignment,
        section_alignment: image.optional.section_alignment,
        size_of_headers: image.optional.size_of_headers,
        size_of_image: image.optional.size_of_image,
        coff_characteristics: image.characteristics,
        dll_characteristics: image.optional.dll_characteristics,
        sections,
        tls,
        base_reloc,
        exception,
        tls_detail,
        relocation_detail,
        exception_detail,
    })
}

fn validate_image(
    image: &PeImage<'_>,
    candidate_bytes: &[u8],
) -> Result<(), OreansPeEvidenceError> {
    let is_pe32_plus = image.optional.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    match (image.machine, is_pe32_plus) {
        (IMAGE_FILE_MACHINE_AMD64, true) | (IMAGE_FILE_MACHINE_I386, false) => {}
        (machine, pe32_plus) => {
            return Err(err(
                "machine_magic_mismatch",
                format!("machine 0x{machine:04x} is incompatible with PE32+={pe32_plus}"),
            ))
        }
    }

    if image.optional.section_alignment == 0 || image.optional.file_alignment == 0 {
        return Err(err(
            "alignment_zero",
            "SectionAlignment and FileAlignment must be non-zero",
        ));
    }
    if !image.optional.section_alignment.is_power_of_two()
        || !image.optional.file_alignment.is_power_of_two()
    {
        return Err(err(
            "alignment_not_power_of_two",
            "SectionAlignment and FileAlignment must be powers of two",
        ));
    }
    if image.optional.size_of_image == 0 {
        return Err(err("size_of_image_zero", "SizeOfImage must be non-zero"));
    }
    if image.optional.size_of_headers == 0
        || image.optional.size_of_headers > image.optional.size_of_image
        || image.optional.size_of_headers as usize > candidate_bytes.len()
    {
        return Err(err(
            "headers_invalid",
            "SizeOfHeaders must be positive, in the file, and no larger than SizeOfImage",
        ));
    }
    if image.optional.address_of_entry_point >= image.optional.size_of_image {
        return Err(err(
            "entry_out_of_image",
            format!(
                "entry RVA 0x{:x} exceeds SizeOfImage",
                image.optional.address_of_entry_point
            ),
        ));
    }
    if image
        .rva_to_offset(image.optional.address_of_entry_point)
        .is_none()
    {
        return Err(err(
            "entry_unmapped",
            format!(
                "entry RVA 0x{:x} has no raw backing",
                image.optional.address_of_entry_point
            ),
        ));
    }

    let header_end = (image.section_table_offset as u64)
        .checked_add(
            (image.number_of_sections as u64)
                .checked_mul(40)
                .ok_or_else(|| {
                    err(
                        "section_table_overflow",
                        "section table multiplication overflow",
                    )
                })?,
        )
        .ok_or_else(|| err("section_table_overflow", "section table end overflow"))?;
    if header_end > image.optional.size_of_headers as u64 {
        return Err(err(
            "section_table_not_in_headers",
            "section table is not covered by SizeOfHeaders",
        ));
    }

    let mut virtual_ranges = Vec::with_capacity(image.sections.len());
    for section in &image.sections {
        let extent = section.virtual_extent();
        let virtual_end = (section.virtual_address as u64)
            .checked_add(extent)
            .ok_or_else(|| err("section_va_overflow", "section virtual range overflow"))?;
        if extent == 0 || virtual_end > image.optional.size_of_image as u64 {
            return Err(err(
                "section_virtual_range_invalid",
                format!(
                    "section {} exceeds SizeOfImage",
                    section_name(&section.name)
                ),
            ));
        }
        if section.virtual_address % image.optional.section_alignment != 0 {
            return Err(err(
                "section_va_alignment",
                format!(
                    "section {} VA is not section-aligned",
                    section_name(&section.name)
                ),
            ));
        }
        if section.size_of_raw_data != 0 {
            if section.pointer_to_raw_data == 0 {
                return Err(err(
                    "section_raw_pointer_zero",
                    format!(
                        "section {} has raw bytes but zero raw pointer",
                        section_name(&section.name)
                    ),
                ));
            }
            if section.pointer_to_raw_data % image.optional.file_alignment != 0 {
                return Err(err(
                    "section_raw_alignment",
                    format!(
                        "section {} raw pointer is not file-aligned",
                        section_name(&section.name)
                    ),
                ));
            }
            let raw_end = (section.pointer_to_raw_data as u64)
                .checked_add(section.size_of_raw_data as u64)
                .ok_or_else(|| err("section_raw_overflow", "section raw range overflow"))?;
            if raw_end > candidate_bytes.len() as u64 {
                return Err(err(
                    "section_raw_oob",
                    format!(
                        "section {} raw range exceeds candidate bytes",
                        section_name(&section.name)
                    ),
                ));
            }
        }
        virtual_ranges.push((
            section.virtual_address as u64,
            virtual_end,
            section_name(&section.name),
        ));
    }
    virtual_ranges.sort_by_key(|range| range.0);
    for pair in virtual_ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(err(
                "section_virtual_overlap",
                format!("sections {} and {} overlap", pair[0].2, pair[1].2),
            ));
        }
    }

    for (index, directory) in image.optional.data_directories.iter().enumerate() {
        let present = directory.virtual_address != 0 || directory.size != 0;
        if !present {
            continue;
        }
        if directory.size == 0 {
            return Err(err(
                "directory_zero_size",
                format!("directory {index} has an address but zero size"),
            ));
        }
        if index == 4 {
            let offset = directory.virtual_address as usize;
            let end = offset.checked_add(directory.size as usize).ok_or_else(|| {
                err(
                    "security_directory_offset_overflow",
                    "security directory file range overflow",
                )
            })?;
            if end > candidate_bytes.len() {
                return Err(err(
                    "security_directory_out_of_file",
                    format!("security directory file range 0x{offset:x}..0x{end:x} exceeds candidate bytes"),
                ));
            }
            continue;
        }
        if !image.directory_in_image(directory.virtual_address, directory.size) {
            return Err(err(
                "directory_out_of_image",
                format!("directory {index} is outside SizeOfImage"),
            ));
        }
        if !image.directory_has_raw_backing(directory.virtual_address, directory.size) {
            return Err(err(
                "directory_without_raw_backing",
                format!("directory {index} has no complete raw backing"),
            ));
        }
    }

    let dynamic_base =
        (image.optional.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    let relocs_stripped = (image.characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;
    let reloc_present = image
        .directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        .map(|d| d.virtual_address != 0 || d.size != 0)
        .unwrap_or(false);
    if relocs_stripped && reloc_present {
        return Err(err(
            "relocs_stripped_with_directory",
            "RELOCS_STRIPPED is set while a base relocation directory is present",
        ));
    }
    if dynamic_base && !reloc_present {
        return Err(err(
            "dynamic_base_without_relocs",
            "DYNAMIC_BASE requires a base relocation directory",
        ));
    }

    Ok(())
}

fn coverage(
    image: &PeImage<'_>,
    index: usize,
) -> Result<OreansPeDirectoryCoverage, OreansPeEvidenceError> {
    let directory = image.directory(index).cloned().unwrap_or(DataDirectory {
        virtual_address: 0,
        size: 0,
    });
    let present = directory.virtual_address != 0 || directory.size != 0;
    let in_image = !present || image.directory_in_image(directory.virtual_address, directory.size);
    let raw_backed =
        !present || image.directory_has_raw_backing(directory.virtual_address, directory.size);
    if present && (!in_image || !raw_backed) {
        return Err(err(
            "directory_coverage_invalid",
            format!("directory {index} is not fully covered by image and raw bytes"),
        ));
    }
    Ok(OreansPeDirectoryCoverage {
        rva: directory.virtual_address,
        size: directory.size,
        present,
        raw_backed,
        in_image,
    })
}

fn parse_tls(
    image: &PeImage<'_>,
    directory_rva: u32,
    directory_size: u32,
) -> Result<OreansTlsEvidence, OreansPeEvidenceError> {
    let pointer_size = if image.optional.is_pe32_plus { 8 } else { 4 };
    let required = if image.optional.is_pe32_plus { 40 } else { 24 };
    if directory_size < required || !image.directory_has_raw_backing(directory_rva, required) {
        return Err(err(
            "tls_directory_truncated",
            "TLS directory is smaller than its architecture layout",
        ));
    }
    let start = read_u64_or_u32(image, directory_rva, image.optional.is_pe32_plus)?;
    let end = read_u64_or_u32(
        image,
        add_rva(directory_rva, pointer_size as u32, "TLS end")?,
        image.optional.is_pe32_plus,
    )?;
    let index_offset = if image.optional.is_pe32_plus { 16 } else { 8 };
    let callback_offset = if image.optional.is_pe32_plus { 24 } else { 12 };
    let address_of_index = read_pointer(image, add_rva(directory_rva, index_offset, "TLS index")?)?;
    let address_of_callbacks = read_pointer(
        image,
        add_rva(directory_rva, callback_offset, "TLS callbacks")?,
    )?;

    let start_rva = va_to_rva(image, start, "TLS StartAddressOfRawData")?;
    let end_rva = va_to_rva(image, end, "TLS EndAddressOfRawData")?;
    match (start_rva, end_rva) {
        (None, None) => {}
        (Some(start_rva), Some(end_rva)) => {
            if end_rva < start_rva {
                return Err(err(
                    "tls_raw_range_reversed",
                    "TLS raw-data range is reversed",
                ));
            }
            let range_size = end_rva
                .checked_sub(start_rva)
                .ok_or_else(|| err("tls_raw_range_overflow", "TLS raw-data range underflow"))?;
            if !raw_backed_range(image, start_rva, range_size) {
                return Err(err(
                    "tls_raw_range_unmapped",
                    "TLS raw-data range is not fully raw-backed",
                ));
            }
        }
        _ => {
            return Err(err(
                "tls_raw_range_pair",
                "TLS StartAddressOfRawData and EndAddressOfRawData must be both zero or both non-zero",
            ));
        }
    }
    if address_of_index == 0 {
        return Err(err("tls_index_zero", "TLS AddressOfIndex must be non-zero"));
    }
    let address_of_index_rva = va_to_rva(image, address_of_index, "TLS AddressOfIndex")?
        .ok_or_else(|| err("tls_index_zero", "TLS AddressOfIndex must be non-zero"))?;
    if !raw_backed_range(image, address_of_index_rva, 4) {
        return Err(err(
            "tls_index_unmapped",
            "TLS AddressOfIndex is not raw-backed",
        ));
    }
    let callback_array_rva = va_to_rva(image, address_of_callbacks, "TLS callback array")?;
    let (callback_rvas, null_terminated) = if let Some(array_rva) = callback_array_rva {
        scan_callbacks(image, array_rva, pointer_size)?
    } else {
        (Vec::new(), true)
    };

    Ok(OreansTlsEvidence {
        directory_size,
        address_of_index_rva: Some(address_of_index_rva),
        callback_array_rva,
        callback_rvas,
        null_terminated,
    })
}

fn parse_relocations(
    image: &PeImage<'_>,
    directory_rva: u32,
    directory_size: u32,
) -> Result<OreansRelocationEvidence, OreansPeEvidenceError> {
    if directory_size < 8 {
        return Err(err(
            "reloc_directory_truncated",
            "base relocation directory is shorter than one block header",
        ));
    }
    let mut cursor = 0u32;
    let mut block_count = 0u32;
    let mut entry_count = 0u32;
    let mut non_absolute_entry_count = 0u32;
    let mut observed_types = Vec::new();
    let relocation_type = if image.optional.is_pe32_plus {
        10u16
    } else {
        3u16
    };
    let relocation_width = if image.optional.is_pe32_plus {
        8u32
    } else {
        4u32
    };

    while cursor < directory_size {
        let remaining = directory_size - cursor;
        if remaining < 8 {
            return Err(err(
                "reloc_trailing_bytes",
                "base relocation directory has a partial block header",
            ));
        }
        let block_rva = add_rva(directory_rva, cursor, "relocation block")?;
        let page_rva = read_u32(image, block_rva)?;
        let block_size = read_u32(image, add_rva(block_rva, 4, "relocation block size")?)?;
        if block_size < 8 || block_size % 2 != 0 || block_size > remaining {
            return Err(err(
                "reloc_block_invalid",
                "base relocation block size is invalid",
            ));
        }
        if page_rva >= image.optional.size_of_image || page_rva % 0x1000 != 0 {
            return Err(err(
                "reloc_page_invalid",
                "base relocation page RVA is outside/alignment-invalid",
            ));
        }
        if !raw_backed_range(image, block_rva, block_size) {
            return Err(err(
                "reloc_block_unmapped",
                "base relocation block is not raw-backed",
            ));
        }
        let entries = (block_size - 8) / 2;
        block_count = block_count
            .checked_add(1)
            .ok_or_else(|| err("reloc_count_overflow", "relocation block count overflow"))?;
        entry_count = entry_count
            .checked_add(entries)
            .ok_or_else(|| err("reloc_count_overflow", "relocation entry count overflow"))?;
        for i in 0..entries {
            let word_rva = add_rva(block_rva, 8 + i * 2, "relocation entry")?;
            let word = read_u16(image, word_rva)?;
            let kind = word >> 12;
            let offset = (word & 0x0fff) as u32;
            if !observed_types.contains(&(kind as u8)) {
                observed_types.push(kind as u8);
            }
            if kind == 0 {
                continue;
            }
            if kind != relocation_type {
                return Err(err(
                    "reloc_type_invalid",
                    format!("relocation type {kind} is invalid for this architecture"),
                ));
            }
            let target = page_rva
                .checked_add(offset)
                .ok_or_else(|| err("reloc_target_overflow", "relocation target RVA overflow"))?;
            let target_end = target
                .checked_add(relocation_width)
                .ok_or_else(|| err("reloc_target_overflow", "relocation target width overflow"))?;
            if target_end > image.optional.size_of_image {
                return Err(err(
                    "reloc_target_out_of_image",
                    "relocation target exceeds SizeOfImage",
                ));
            }
            non_absolute_entry_count =
                non_absolute_entry_count.checked_add(1).ok_or_else(|| {
                    err(
                        "reloc_count_overflow",
                        "non-absolute relocation count overflow",
                    )
                })?;
        }
        cursor = cursor
            .checked_add(block_size)
            .ok_or_else(|| err("reloc_cursor_overflow", "relocation cursor overflow"))?;
    }
    observed_types.sort_unstable();
    Ok(OreansRelocationEvidence {
        block_count,
        entry_count,
        non_absolute_entry_count,
        observed_types,
        all_targets_in_image: true,
        dynamic_base: (image.optional.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
            != 0,
        relocs_stripped: (image.characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0,
    })
}

fn parse_exceptions(
    image: &PeImage<'_>,
    directory_rva: u32,
    directory_size: u32,
) -> Result<OreansExceptionEvidence, OreansPeEvidenceError> {
    if image.machine != IMAGE_FILE_MACHINE_AMD64 || !image.optional.is_pe32_plus {
        return Err(err(
            "exception_architecture",
            "x64 exception directory requires AMD64 PE32+",
        ));
    }
    if directory_size == 0 || directory_size % 12 != 0 {
        return Err(err(
            "exception_size_invalid",
            "x64 exception directory size must be a non-zero multiple of 12",
        ));
    }
    let count = directory_size / 12;
    let capacity = usize::try_from(count).map_err(|_| {
        err(
            "exception_count_overflow",
            "exception record count does not fit usize",
        )
    })?;
    let mut functions = Vec::with_capacity(capacity);
    let mut ranges_raw_backed = true;
    let mut unwind_rvas_raw_backed = true;
    for i in 0..count {
        let record_rva = add_rva(
            directory_rva,
            i.checked_mul(12).ok_or_else(|| {
                err(
                    "exception_offset_overflow",
                    "exception record offset overflow",
                )
            })?,
            "exception record",
        )?;
        let begin = read_u32(image, record_rva)?;
        let end = read_u32(image, add_rva(record_rva, 4, "exception end")?)?;
        let unwind = read_u32(image, add_rva(record_rva, 8, "exception unwind")?)?;
        if begin >= end || end > image.optional.size_of_image {
            return Err(err(
                "exception_range_invalid",
                "RUNTIME_FUNCTION begin/end range is invalid",
            ));
        }
        let range_raw = raw_backed_range(image, begin, end - begin);
        let unwind_raw = unwind != 0 && raw_backed_range(image, unwind, 4);
        ranges_raw_backed &= range_raw;
        unwind_rvas_raw_backed &= unwind_raw;
        if !range_raw {
            return Err(err(
                "exception_range_unmapped",
                "RUNTIME_FUNCTION range is not raw-backed",
            ));
        }
        if !rva_in_executable_section(image, begin) || !rva_in_executable_section(image, end - 1) {
            return Err(err(
                "exception_range_not_executable",
                "RUNTIME_FUNCTION begin/end range must lie within an executable section",
            ));
        }
        if !unwind_raw {
            return Err(err(
                "exception_unwind_unmapped",
                "RUNTIME_FUNCTION unwind RVA is not raw-backed",
            ));
        }
        let unwind_version = read_rva(image, unwind, 1)?[0] & 0x07;
        if unwind_version != 1 && unwind_version != 2 {
            return Err(err(
                "exception_unwind_version_invalid",
                format!("UNWIND_INFO version {unwind_version} is not 1 or 2"),
            ));
        }
        functions.push(OreansRuntimeFunctionEvidence {
            begin_rva: begin,
            end_rva: end,
            unwind_rva: unwind,
        });
    }
    Ok(OreansExceptionEvidence {
        runtime_function_count: count,
        runtime_functions: functions,
        ranges_raw_backed,
        unwind_rvas_raw_backed,
    })
}

fn scan_callbacks(
    image: &PeImage<'_>,
    array_rva: u32,
    pointer_size: u32,
) -> Result<(Vec<u32>, bool), OreansPeEvidenceError> {
    let max_entries = (image.optional.size_of_image / pointer_size)
        .checked_add(1)
        .ok_or_else(|| {
            err(
                "tls_callback_count_overflow",
                "TLS callback scan bound overflow",
            )
        })?;
    let mut callbacks = Vec::new();
    for index in 0..max_entries {
        let offset = index.checked_mul(pointer_size).ok_or_else(|| {
            err(
                "tls_callback_offset_overflow",
                "TLS callback offset overflow",
            )
        })?;
        let item_rva = add_rva(array_rva, offset, "TLS callback array")?;
        if !raw_backed_range(image, item_rva, pointer_size) {
            return Err(err(
                "tls_callbacks_not_terminated",
                "TLS callback array has no null terminator within raw-backed image bytes",
            ));
        }
        let value = read_pointer(image, item_rva)?;
        if value == 0 {
            return Ok((callbacks, true));
        }
        let callback_rva = va_to_rva(image, value, "TLS callback")?
            .ok_or_else(|| err("tls_callback_zero", "non-zero TLS callback became zero RVA"))?;
        if image.rva_to_offset(callback_rva).is_none() {
            return Err(err(
                "tls_callback_unmapped",
                "TLS callback RVA is not raw-backed",
            ));
        }
        if !rva_in_executable_section(image, callback_rva) {
            return Err(err(
                "tls_callback_not_executable",
                "TLS callback RVA is not within an executable section",
            ));
        }
        callbacks.push(callback_rva);
    }
    Err(err(
        "tls_callbacks_not_terminated",
        "TLS callback array has no null terminator within the image",
    ))
}

fn va_to_rva(
    image: &PeImage<'_>,
    va: u64,
    label: &str,
) -> Result<Option<u32>, OreansPeEvidenceError> {
    if va == 0 {
        return Ok(None);
    }
    if va < image.optional.image_base {
        return Err(err(
            "va_below_image_base",
            format!("{label} VA is below ImageBase"),
        ));
    }
    let delta = va - image.optional.image_base;
    let rva = u32::try_from(delta).map_err(|_| {
        err(
            "va_rva_overflow",
            format!("{label} VA-to-RVA conversion overflow"),
        )
    })?;
    if rva >= image.optional.size_of_image {
        return Err(err(
            "va_rva_out_of_image",
            format!("{label} RVA is outside SizeOfImage"),
        ));
    }
    Ok(Some(rva))
}

fn read_pointer(image: &PeImage<'_>, rva: u32) -> Result<u64, OreansPeEvidenceError> {
    if image.optional.is_pe32_plus {
        Ok(read_u64(image, rva)?)
    } else {
        Ok(read_u32(image, rva)? as u64)
    }
}

fn read_u64_or_u32(
    image: &PeImage<'_>,
    rva: u32,
    pe32_plus: bool,
) -> Result<u64, OreansPeEvidenceError> {
    if pe32_plus {
        read_u64(image, rva)
    } else {
        Ok(read_u32(image, rva)? as u64)
    }
}

fn read_u16(image: &PeImage<'_>, rva: u32) -> Result<u16, OreansPeEvidenceError> {
    let bytes = read_rva(image, rva, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(image: &PeImage<'_>, rva: u32) -> Result<u32, OreansPeEvidenceError> {
    let bytes = read_rva(image, rva, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(image: &PeImage<'_>, rva: u32) -> Result<u64, OreansPeEvidenceError> {
    let bytes = read_rva(image, rva, 8)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_rva<'a>(
    image: &'a PeImage<'a>,
    rva: u32,
    size: u32,
) -> Result<&'a [u8], OreansPeEvidenceError> {
    if !image.directory_in_image(rva, size) || !image.directory_has_raw_backing(rva, size) {
        return Err(err(
            "rva_unmapped",
            format!("RVA 0x{rva:x} size 0x{size:x} is not safely mapped"),
        ));
    }
    let offset = image
        .rva_to_offset(rva)
        .ok_or_else(|| err("rva_unmapped", format!("RVA 0x{rva:x} has no raw mapping")))?;
    let end = offset
        .checked_add(size as usize)
        .ok_or_else(|| err("file_offset_overflow", "RVA file offset range overflow"))?;
    image.bytes.get(offset..end).ok_or_else(|| {
        err(
            "file_offset_oob",
            "RVA file offset range exceeds candidate bytes",
        )
    })
}

fn raw_backed_range(image: &PeImage<'_>, rva: u32, size: u32) -> bool {
    image.directory_in_image(rva, size) && image.directory_has_raw_backing(rva, size)
}

fn rva_in_executable_section(image: &PeImage<'_>, rva: u32) -> bool {
    image.sections.iter().any(|section| {
        let start = section.virtual_address;
        let end = match start.checked_add(section.virtual_extent() as u32) {
            Some(end) => end,
            None => return false,
        };
        rva >= start && rva < end && section.is_executable()
    })
}

fn add_rva(base: u32, delta: u32, label: &str) -> Result<u32, OreansPeEvidenceError> {
    base.checked_add(delta)
        .ok_or_else(|| err("rva_overflow", format!("{label} RVA addition overflow")))
}

fn section_name(name: &[u8; 8]) -> String {
    let end = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    String::from_utf8_lossy(&name[..end]).to_string()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::new();
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn err(code: &str, message: impl Into<String>) -> OreansPeEvidenceError {
    OreansPeEvidenceError::new(code, message)
}
