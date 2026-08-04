//! Pure-byte tests for structured Oreans PE evidence.
//!
//! Fixtures are synthetic bytes only. No executable is launched or unpacked.

#[path = "../src/test_support/pe_builder.rs"]
mod pe_builder;

use mida_acceptance::{
    build_oreans_pe_evidence, sha256_hex, OreansPeEvidenceError, OREANS_PE_EVIDENCE_SCHEMA_VERSION,
};
use pe_builder::{build_pe, PeBuildOptions};

const IMAGE_BASE64: u64 = 0x0000_0001_4000_0000;
const TEXT_RVA: u32 = 0x1000;
const TEXT_RAW: u32 = 0x200;
const RELOC_RAW: usize = 0x400;
const DD_OFFSET64: usize = 0x108;
const TEXT_CHARACTERISTICS_OFFSET: usize = 0x1ac;

fn base_pe() -> Vec<u8> {
    build_pe(&PeBuildOptions::pe32_plus())
}

fn rva_offset(rva: u32) -> usize {
    (TEXT_RAW + (rva - TEXT_RVA)) as usize
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_dd(bytes: &mut [u8], index: usize, rva: u32, size: u32) {
    let offset = DD_OFFSET64 + index * 8;
    write_u32(bytes, offset, rva);
    write_u32(bytes, offset + 4, size);
}

fn set_tls(bytes: &mut [u8], null_terminated: bool) {
    let tls_rva = 0x1010;
    let index_rva = 0x1060;
    let callbacks_rva = 0x1050;
    write_dd(bytes, 9, tls_rva, 40);
    let tls = rva_offset(tls_rva);
    write_u64(bytes, tls, IMAGE_BASE64 + 0x1000);
    write_u64(bytes, tls + 8, IMAGE_BASE64 + 0x1100);
    write_u64(bytes, tls + 16, IMAGE_BASE64 + index_rva as u64);
    write_u64(bytes, tls + 24, IMAGE_BASE64 + callbacks_rva as u64);
    write_u32(bytes, tls + 32, 0);
    write_u32(bytes, tls + 36, 0);
    write_u32(bytes, rva_offset(index_rva), 1);

    let start = rva_offset(callbacks_rva);
    if null_terminated {
        write_u64(bytes, start, IMAGE_BASE64 + 0x1000);
        write_u64(bytes, start + 8, 0);
    } else {
        for offset in (start..rva_offset(0x1200)).step_by(8) {
            write_u64(bytes, offset, IMAGE_BASE64 + 0x1000);
        }
    }
}

fn set_exception(bytes: &mut [u8], begin: u32, end: u32, unwind: u32) {
    let directory_rva = 0x1100;
    write_dd(bytes, 3, directory_rva, 12);
    let record = rva_offset(directory_rva);
    write_u32(bytes, record, begin);
    write_u32(bytes, record + 4, end);
    write_u32(bytes, record + 8, unwind);
    if unwind < 0x1200 {
        write_u32(bytes, rva_offset(unwind), 1);
    }
}

fn set_reloc(bytes: &mut [u8], page_rva: u32, entry: u16) {
    let reloc_rva = 0x2000;
    write_dd(bytes, 5, reloc_rva, 12);
    let block = RELOC_RAW;
    write_u32(bytes, block, page_rva);
    write_u32(bytes, block + 4, 12);
    bytes[block + 8..block + 10].copy_from_slice(&entry.to_le_bytes());
    bytes[block + 10..block + 12].copy_from_slice(&0u16.to_le_bytes());
}

#[test]
fn minimal_legal_pe_evidence_is_byte_bound_and_serializable() {
    let bytes = base_pe();
    let evidence = build_oreans_pe_evidence(&bytes).expect("minimal PE evidence");
    assert_eq!(evidence.schema_version, OREANS_PE_EVIDENCE_SCHEMA_VERSION);
    assert!(evidence.valid);
    assert_eq!(evidence.candidate.size_bytes, bytes.len() as u64);
    assert_eq!(evidence.candidate.sha256, sha256_hex(&bytes));
    assert_eq!(evidence.machine, 0x8664);
    assert!(evidence.pe32_plus);
    assert_eq!(evidence.sections.len(), 1);

    let encoded = serde_json::to_string(&evidence).expect("serialize evidence");
    let decoded: mida_acceptance::OreansPeEvidence =
        serde_json::from_str(&encoded).expect("deserialize evidence");
    assert_eq!(decoded, evidence);
}

#[test]
fn changing_one_byte_changes_computed_candidate_digest() {
    let bytes = base_pe();
    let mut changed = bytes.clone();
    changed[0x220] ^= 0x01;
    let before = build_oreans_pe_evidence(&bytes).expect("before evidence");
    let after = build_oreans_pe_evidence(&changed).expect("after evidence");
    assert_ne!(before.candidate.sha256, after.candidate.sha256);
    assert_eq!(after.candidate.sha256, sha256_hex(&changed));
}

#[test]
fn security_directory_uses_file_offset_and_valid_certificate_table_passes() {
    let mut bytes = base_pe();
    let certificate_offset = bytes.len();
    bytes.extend_from_slice(b"CERTDATA");
    write_dd(&mut bytes, 4, certificate_offset as u32, 8);

    let evidence = build_oreans_pe_evidence(&bytes).expect("certificate table file range is valid");
    assert!(evidence.valid);
}

#[test]
fn security_directory_past_candidate_bytes_fails_closed() {
    let mut bytes = base_pe();
    let invalid_offset = bytes.len() as u32 - 4;
    write_dd(&mut bytes, 4, invalid_offset, 8);

    let error = build_oreans_pe_evidence(&bytes).expect_err("certificate table must stay in file");
    assert_eq!(error.code, "security_directory_out_of_file");
}

#[test]
fn relocation_size_of_block_is_read_as_u32_not_truncated_to_u16() {
    let mut bytes = build_pe(&PeBuildOptions {
        include_reloc: true,
        dll_characteristics: 0x0040,
        ..PeBuildOptions::pe32_plus()
    });
    set_reloc(&mut bytes, 0x1000, 0xA000);
    write_u32(&mut bytes, RELOC_RAW + 4, 0x0001_000c);

    let error = build_oreans_pe_evidence(&bytes)
        .expect_err("u32 block size must exceed directory and fail");
    assert_eq!(error.code, "reloc_block_invalid");
}

#[test]
fn dynamic_base_with_non_absolute_relocation_passes() {
    let mut bytes = build_pe(&PeBuildOptions {
        include_reloc: true,
        dll_characteristics: 0x0040,
        ..PeBuildOptions::pe32_plus()
    });
    set_reloc(&mut bytes, 0x1000, 0xA000);

    let evidence = build_oreans_pe_evidence(&bytes).expect("DYNAMIC_BASE with DIR64 relocation");
    let relocation = evidence.relocation_detail.expect("relocation detail");
    assert_eq!(relocation.non_absolute_entry_count, 1);
}

#[test]
fn dynamic_base_with_only_absolute_relocations_fails_closed() {
    let mut bytes = build_pe(&PeBuildOptions {
        include_reloc: true,
        dll_characteristics: 0x0040,
        ..PeBuildOptions::pe32_plus()
    });
    set_reloc(&mut bytes, 0x1000, 0x0000);

    let error = build_oreans_pe_evidence(&bytes)
        .expect_err("ABSOLUTE-only relocations cannot satisfy DYNAMIC_BASE");
    assert_eq!(error.code, "dynamic_base_without_non_absolute_reloc");
}

#[test]
fn tls_address_of_index_must_be_non_zero() {
    let mut bytes = base_pe();
    set_tls(&mut bytes, true);
    write_u64(&mut bytes, rva_offset(0x1010) + 16, 0);

    let error = build_oreans_pe_evidence(&bytes).expect_err("TLS AddressOfIndex must be non-zero");
    assert_eq!(error.code, "tls_index_zero");
}

#[test]
fn tls_raw_data_addresses_must_be_paired() {
    let mut bytes = base_pe();
    set_tls(&mut bytes, true);
    write_u64(&mut bytes, rva_offset(0x1010), 0);

    let error =
        build_oreans_pe_evidence(&bytes).expect_err("TLS raw-data addresses must be paired");
    assert_eq!(error.code, "tls_raw_range_pair");
}

#[test]
fn tls_address_of_index_must_have_four_bytes_of_raw_backing() {
    let mut bytes = base_pe();
    set_tls(&mut bytes, true);
    write_u64(&mut bytes, rva_offset(0x1010) + 16, IMAGE_BASE64 + 0x11fe);

    let error = build_oreans_pe_evidence(&bytes)
        .expect_err("TLS AddressOfIndex must have four raw-backed bytes");
    assert_eq!(error.code, "tls_index_unmapped");
}

#[test]
fn tls_raw_data_range_must_be_raw_backed() {
    let mut bytes = base_pe();
    set_tls(&mut bytes, true);
    write_u64(&mut bytes, rva_offset(0x1010), IMAGE_BASE64 + 0x1180);
    write_u64(&mut bytes, rva_offset(0x1010) + 8, IMAGE_BASE64 + 0x1300);

    let error =
        build_oreans_pe_evidence(&bytes).expect_err("TLS raw-data range must be fully backed");
    assert_eq!(error.code, "tls_raw_range_unmapped");
}

#[test]
fn tls_callback_must_be_in_an_executable_section() {
    let mut bytes = base_pe();
    set_tls(&mut bytes, true);
    write_u64(&mut bytes, rva_offset(0x1050), IMAGE_BASE64 + 0x100);

    let error = build_oreans_pe_evidence(&bytes)
        .expect_err("TLS callback outside executable section must fail");
    assert_eq!(error.code, "tls_callback_not_executable");
}

#[test]
fn valid_tls_structure_passes_all_structural_checks() {
    let mut bytes = base_pe();
    set_tls(&mut bytes, true);

    let evidence = build_oreans_pe_evidence(&bytes).expect("valid TLS structure");
    let tls = evidence.tls_detail.expect("TLS detail");
    assert_eq!(tls.address_of_index_rva, Some(0x1060));
    assert_eq!(tls.callback_rvas, vec![0x1000]);
    assert!(tls.null_terminated);
}

#[test]
fn x64_exception_range_must_be_in_executable_section() {
    let mut bytes = base_pe();
    set_exception(&mut bytes, 0x1000, 0x1100, 0x1150);
    write_u32(&mut bytes, TEXT_CHARACTERISTICS_OFFSET, 0x4000_0000);

    let error = build_oreans_pe_evidence(&bytes)
        .expect_err("exception range in non-executable section must fail");
    assert_eq!(error.code, "exception_range_not_executable");
}

#[test]
fn valid_x64_exception_structure_passes() {
    let mut bytes = base_pe();
    set_exception(&mut bytes, 0x1000, 0x1100, 0x1150);

    let evidence = build_oreans_pe_evidence(&bytes).expect("valid x64 exception structure");
    let exception = evidence.exception_detail.expect("exception detail");
    assert_eq!(exception.runtime_function_count, 1);
    assert!(exception.ranges_raw_backed);
    assert!(exception.unwind_rvas_raw_backed);
}

#[test]
fn x64_exception_unwind_version_zero_fails_closed() {
    let mut bytes = base_pe();
    set_exception(&mut bytes, 0x1000, 0x1100, 0x1150);
    write_u32(&mut bytes, rva_offset(0x1150), 0);

    let error = build_oreans_pe_evidence(&bytes).expect_err("UNWIND_INFO version zero must fail");
    assert_eq!(error.code, "exception_unwind_version_invalid");
}

#[test]
fn x64_exception_unwind_version_two_is_accepted_from_low_three_bits() {
    let mut bytes = base_pe();
    set_exception(&mut bytes, 0x1000, 0x1100, 0x1150);
    write_u32(&mut bytes, rva_offset(0x1150), 0xf2);

    build_oreans_pe_evidence(&bytes).expect("UNWIND_INFO version two must pass");
}

#[test]
fn x64_exception_unwind_version_other_than_one_or_two_fails_closed() {
    let mut bytes = base_pe();
    set_exception(&mut bytes, 0x1000, 0x1100, 0x1150);
    write_u32(&mut bytes, rva_offset(0x1150), 3);

    let error = build_oreans_pe_evidence(&bytes).expect_err("UNWIND_INFO version three must fail");
    assert_eq!(error.code, "exception_unwind_version_invalid");
}

#[test]
fn tls_callback_array_without_null_terminator_fails_closed() {
    let mut bytes = base_pe();
    set_tls(&mut bytes, false);
    let error = build_oreans_pe_evidence(&bytes).expect_err("unterminated callbacks must fail");
    assert_eq!(error.code, "tls_callbacks_not_terminated");
}

#[test]
fn relocation_target_beyond_size_of_image_fails_closed() {
    let mut bytes = build_pe(&PeBuildOptions {
        include_reloc: true,
        dll_characteristics: 0x0040,
        ..PeBuildOptions::pe32_plus()
    });
    // The fixture's .reloc raw section begins at 0x400. Page 0x2000 plus
    // offset 0xfff produces a DIR64 target whose eight-byte width exceeds
    // SizeOfImage (0x3000).
    set_reloc(&mut bytes, 0x2000, 0xAFFF);
    let error = build_oreans_pe_evidence(&bytes).expect_err("relocation target must be in image");
    assert_eq!(error.code, "reloc_target_out_of_image");
}

#[test]
fn relocation_type_wrong_for_x64_fails_closed() {
    let mut bytes = build_pe(&PeBuildOptions {
        include_reloc: true,
        dll_characteristics: 0x0040,
        ..PeBuildOptions::pe32_plus()
    });
    set_reloc(&mut bytes, 0x1000, 0x3000);
    let error = build_oreans_pe_evidence(&bytes).expect_err("HIGHLOW is invalid in PE32+");
    assert_eq!(error.code, "reloc_type_invalid");
}

#[test]
fn x64_exception_begin_must_be_less_than_end() {
    let mut bytes = base_pe();
    set_exception(&mut bytes, 0x1100, 0x1100, 0x1150);
    let error = build_oreans_pe_evidence(&bytes).expect_err("empty runtime range must fail");
    assert_eq!(error.code, "exception_range_invalid");
}

#[test]
fn x64_exception_unwind_must_be_raw_backed() {
    let mut bytes = base_pe();
    set_exception(&mut bytes, 0x1000, 0x1100, 0x1200);
    let error = build_oreans_pe_evidence(&bytes).expect_err("unmapped unwind must fail");
    assert_eq!(error.code, "exception_unwind_unmapped");
}

#[test]
fn malformed_header_errors_are_structured() {
    let error = build_oreans_pe_evidence(&[0u8; 16]).expect_err("short input must fail");
    assert!(!error.code.is_empty());
    assert!(!error.message.is_empty());
    let _: OreansPeEvidenceError = error;
}
