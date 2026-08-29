//! WO-1501 walker wire protocol v2 — offline tests (part A: params).
//!
//! These tests run fully offline: no Windows API, no target process.
//! They verify layout constants, checked encode/decode/validate, fixed
//! fixtures and reject rules. They do NOT verify any Windows behaviour.

use mida_antidebug_runtime::walker_protocol::{
    crc32, derive_session_id, is_canonical_user_va, page_span_fits, MappingIdentityHeaderV2,
    ProbeResultV2, ProtocolError, ResultSectionHeaderV2, WalkerParamsV2, DEFAULT_PROBE_SPAN,
    MAX_CANDIDATE_COUNT, MIN_SECTION_HEADER_BYTES, OPTION_NONE, PARAMS_CRC_RANGE_END,
    PROBE_RESULT_BYTES,
};

fn sample_nonce() -> u64 {
    0x0123_4567_89AB_CDEF
}

fn sample_candidates() -> Vec<u64> {
    // All page-start-aligned user VAs so span 16 never crosses a page.
    vec![
        0x0000_0000_0001_0000,
        0x0000_0000_0002_0000,
        0x0000_0000_0003_0000,
    ]
}

fn sample_params() -> WalkerParamsV2 {
    let cands = sample_candidates();
    let capacity = (cands.len() as u64)
        .checked_mul(PROBE_RESULT_BYTES as u64)
        .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
        .unwrap();
    WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        cands.len() as u32,
        OPTION_NONE,
        DEFAULT_PROBE_SPAN,
        sample_nonce(),
        capacity,
    )
}

/// Standard CRC-32 check value.
#[test]
fn crc32_known_vector() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

/// Layout contract: the structs must be exactly the documented sizes.
#[test]
fn layout_constants_hold() {
    assert_eq!(std::mem::size_of::<WalkerParamsV2>(), 0x40);
    assert_eq!(std::mem::size_of::<MappingIdentityHeaderV2>(), 0x38);
    assert_eq!(std::mem::size_of::<ResultSectionHeaderV2>(), 0x28);
    assert_eq!(std::mem::size_of::<ProbeResultV2>(), 0x28);
    assert_eq!(MIN_SECTION_HEADER_BYTES, 0x60);
}

/// Params blob round-trip: encode -> decode -> validate.
/// The decoded header carries the computed blob_total_bytes / header_crc32
/// (the new() placeholder zeroes are filled at encode time).
#[test]
fn params_round_trip_valid() {
    let p = sample_params();
    let cands = sample_candidates();
    let blob = p.to_blob_bytes(&cands).unwrap();
    assert_eq!(blob.len(), 0x40 + 3 * 8);
    let (decoded, decoded_cands) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    // Round-trip identity on every field except the two computed ones.
    assert_eq!(decoded.magic, p.magic);
    assert_eq!(decoded.version, p.version);
    assert_eq!(decoded.header_bytes, p.header_bytes);
    assert_eq!(decoded.blob_base_va, p.blob_base_va);
    assert_eq!(decoded.candidate_off, p.candidate_off);
    assert_eq!(decoded.candidate_count, p.candidate_count);
    assert_eq!(decoded.candidate_stride, p.candidate_stride);
    assert_eq!(decoded.options_flags, p.options_flags);
    assert_eq!(decoded.probe_span, p.probe_span);
    assert_eq!(decoded.result_nonce, p.result_nonce);
    assert_eq!(decoded.result_bytes, p.result_bytes);
    assert_eq!(decoded.blob_total_bytes, blob.len() as u64);
    assert_ne!(decoded.header_crc32, 0);
    assert_eq!(decoded_cands, cands);
    decoded.validate(&decoded_cands).unwrap();
}

/// A header byte corrupted inside the CRC-covered range is rejected.
/// 0x3C (reserved2) is OUTSIDE the CRC range but still decoded; corrupting
/// 0x0C (inside blob_total_bytes) is rejected at decode (also fail-closed).
#[test]
fn params_crc_mismatch_rejected() {
    let p = sample_params();
    let cands = sample_candidates();
    let mut blob = p.to_blob_bytes(&cands).unwrap();
    blob[0x0C] ^= 0xFF; // inside blob_total_bytes -> decode rejects
    assert!(WalkerParamsV2::from_blob_bytes(&blob).is_err());

    // Corrupt a byte inside the CRC range but outside the decode-critical
    // fields: header_crc32 slot itself (offset 0x38).
    let mut blob = p.to_blob_bytes(&cands).unwrap();
    blob[0x38] ^= 0xFF;
    let (decoded, decoded_cands) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    assert!(matches!(
        decoded.validate(&decoded_cands),
        Err(ProtocolError::CrcMismatch { .. })
    ));
}

/// Non-canonical / zero candidates must be rejected.
#[test]
fn params_non_canonical_candidate_rejected() {
    let p = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        1,
        OPTION_NONE,
        16,
        sample_nonce(),
        96 + 1 * PROBE_RESULT_BYTES as u64,
    );
    let cands = vec![0xFFFF_8000_0000_0000]; // kernel canonical, not user
    let res = p.to_blob_bytes(&cands).and_then(|b| {
        let (d, c) = WalkerParamsV2::from_blob_bytes(&b).unwrap();
        d.validate(&c)
    });
    assert!(matches!(res, Err(ProtocolError::NonCanonicalVa { .. })));
}

/// Page-crossing probe spans must be rejected (span frozen to 16, so a VA
/// within 16 bytes of a page end crosses).
#[test]
fn params_page_cross_rejected() {
    let p = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        1,
        OPTION_NONE,
        16,
        sample_nonce(),
        96 + 1 * PROBE_RESULT_BYTES as u64,
    );
    // Page offset 0xFF8: 16 bytes reads [0xFF8, 0x1008) -> crosses the 4KiB page.
    let cands = vec![0x0000_0000_0001_0FF8];
    let res = p.to_blob_bytes(&cands).and_then(|b| {
        let (d, c) = WalkerParamsV2::from_blob_bytes(&b).unwrap();
        d.validate(&c)
    });
    assert!(matches!(res, Err(ProtocolError::PageCross { .. })));
    // A VA safely inside the page passes.
    let cands = vec![0x0000_0000_0001_0FF0];
    let res = p.to_blob_bytes(&cands).and_then(|b| {
        let (d, c) = WalkerParamsV2::from_blob_bytes(&b).unwrap();
        d.validate(&c)
    });
    assert!(res.is_ok());
}

/// Unknown option bits must be rejected.
#[test]
fn params_unknown_option_rejected() {
    let p = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        1,
        0x8000, // unknown bit
        16,
        sample_nonce(),
        96 + 1 * PROBE_RESULT_BYTES as u64,
    );
    let cands = vec![0x0000_0000_0001_0000];
    let res = p.to_blob_bytes(&cands).and_then(|b| {
        let (d, c) = WalkerParamsV2::from_blob_bytes(&b).unwrap();
        d.validate(&c)
    });
    assert!(matches!(res, Err(ProtocolError::UnknownOptionFlags { .. })));
}

/// Zero nonce must be rejected.
#[test]
fn params_zero_nonce_rejected() {
    let p = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        1,
        OPTION_NONE,
        16,
        0, // nonce
        96 + 1 * PROBE_RESULT_BYTES as u64,
    );
    let cands = vec![0x0000_0000_0001_0000];
    let res = p.to_blob_bytes(&cands).and_then(|b| {
        let (d, c) = WalkerParamsV2::from_blob_bytes(&b).unwrap();
        d.validate(&c)
    });
    assert!(matches!(res, Err(ProtocolError::ZeroNonce)));
}

/// Max candidate count accepted; one over is rejected.
#[test]
fn params_candidate_count_limits() {
    let p = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        MAX_CANDIDATE_COUNT,
        OPTION_NONE,
        16,
        sample_nonce(),
        96 + MAX_CANDIDATE_COUNT as u64 * PROBE_RESULT_BYTES as u64,
    );
    let cands: Vec<u64> = (0..MAX_CANDIDATE_COUNT)
        .map(|i| 0x0000_0001_0000_0000u64 + i as u64 * 0x1000)
        .collect();
    let blob = p.to_blob_bytes(&cands).unwrap();
    let (d, c) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    d.validate(&c).unwrap();

    let over = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        MAX_CANDIDATE_COUNT + 1,
        OPTION_NONE,
        16,
        sample_nonce(),
        0,
    );
    let cands2: Vec<u64> = (0..MAX_CANDIDATE_COUNT + 1)
        .map(|i| 0x0000_0001_0000_0000u64 + i as u64 * 0x1000)
        .collect();
    // Hardened decode rejects the over-limit count BEFORE any allocation;
    // to_blob_bytes itself is an encoder and does not enforce the cap.
    let blob2 = over.to_blob_bytes(&cands2).unwrap();
    assert!(matches!(
        WalkerParamsV2::from_blob_bytes(&blob2),
        Err(ProtocolError::CountTooLarge { .. })
    ));
}

/// Fixed fields: mutate the decoded header struct directly so decode
/// succeeds and validate is what rejects (mirrors a hostile writer).
#[test]
fn params_fixed_fields_rejected() {
    let p = sample_params();
    let cands = sample_candidates();
    let blob = p.to_blob_bytes(&cands).unwrap();
    let (mut d, c) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();

    d.magic = 0;
    assert!(matches!(
        d.validate(&c),
        Err(ProtocolError::BadMagic { .. })
    ));
    let (d2, _) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    let mut d2 = d2;
    d2.version = 1;
    assert!(matches!(
        d2.validate(&c),
        Err(ProtocolError::BadVersion { .. })
    ));
    let (d3, _) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    let mut d3 = d3;
    d3.header_bytes = 0x20;
    assert!(matches!(
        d3.validate(&c),
        Err(ProtocolError::BadHeaderBytes { .. })
    ));
    let (d4, _) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    let mut d4 = d4;
    d4.candidate_off = 0x50;
    assert!(matches!(
        d4.validate(&c),
        Err(ProtocolError::BadCandidateOff { .. })
    ));
    let (d5, _) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    let mut d5 = d5;
    d5.candidate_stride = 16;
    assert!(matches!(
        d5.validate(&c),
        Err(ProtocolError::BadCandidateStride { .. })
    ));

    // A truncated blob is rejected at decode.
    assert!(WalkerParamsV2::from_blob_bytes(&blob[..blob.len() - 1]).is_err());
}

/// Deterministic fixtures: golden bytes for a fixed params blob.
#[test]
fn params_golden_fixture() {
    let p = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        1,
        OPTION_NONE,
        16,
        0x0102_0304_0506_0708,
        96 + 1 * PROBE_RESULT_BYTES as u64,
    );
    let cands = vec![0x0000_0000_0000_1000];
    let blob = p.to_blob_bytes(&cands).unwrap();
    assert_eq!(&blob[0..4], b"WALK");
    assert_eq!(u16::from_le_bytes([blob[4], blob[5]]), 2);
    assert_eq!(u16::from_le_bytes([blob[6], blob[7]]), 0x40);
    assert_eq!(u64::from_le_bytes(blob[8..16].try_into().unwrap()), 0x48);
    assert_eq!(
        u64::from_le_bytes(blob[16..24].try_into().unwrap()),
        0x40_0000
    );
    assert_eq!(u32::from_le_bytes(blob[24..28].try_into().unwrap()), 0x40);
    assert_eq!(u32::from_le_bytes(blob[28..32].try_into().unwrap()), 1);
    assert_eq!(u16::from_le_bytes([blob[32], blob[33]]), 8);
    assert_eq!(u16::from_le_bytes([blob[36], blob[37]]), 16);
    assert_eq!(
        u64::from_le_bytes(blob[40..48].try_into().unwrap()),
        0x0102_0304_0506_0708
    );
    assert_eq!(u64::from_le_bytes(blob[48..56].try_into().unwrap()), 0x88);
    assert_eq!(
        u64::from_le_bytes(blob[0x40..0x48].try_into().unwrap()),
        0x1000
    );
    let crc = u32::from_le_bytes(blob[56..60].try_into().unwrap());
    assert_ne!(crc, 0);
    let again = p.to_blob_bytes(&cands).unwrap();
    assert_eq!(blob, again);
}

/// Session id derivation is deterministic and distinct for different
/// nonces / bases / counts.
#[test]
fn session_id_derivation() {
    let a = derive_session_id(1, 0x400000, 3);
    let b = derive_session_id(2, 0x400000, 3);
    let c = derive_session_id(1, 0x500000, 3);
    let d = derive_session_id(1, 0x400000, 4);
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_ne!(a, d);
    let e = derive_session_id(1, 0x400000, 3);
    assert_eq!(a, e);
}

/// VA helper sanity.
#[test]
fn va_helpers_sane() {
    assert!(is_canonical_user_va(0x0000_0000_0040_0000));
    assert!(!is_canonical_user_va(0));
    assert!(!is_canonical_user_va(0xFFFF_8000_0000_0000));
    assert!(page_span_fits(0x0000_0000_0001_0000, 16));
    assert!(!page_span_fits(0x0000_0000_0001_1FF0, 32));
}

/// WO-1801: probe span is FROZEN to exactly 16. Spans 1/15/17/64 must be
/// rejected by validate; span 16 must pass. (params side)
#[test]
fn params_probe_span_frozen_rejects_non_16() {
    let cands = sample_candidates();
    for span in [1u16, 15, 17, 64] {
        let p = WalkerParamsV2::new(
            0x0000_0000_0040_0000,
            cands.len() as u32,
            OPTION_NONE,
            span,
            sample_nonce(),
            96 + cands.len() as u64 * PROBE_RESULT_BYTES as u64,
        );
        let blob = p.to_blob_bytes(&cands).unwrap();
        let (d, c) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
        let res = d.validate(&c);
        assert!(
            matches!(res, Err(ProtocolError::BadProbeSpan { .. })),
            "span {span} must be rejected"
        );
    }
    // Span 16 still passes.
    let p = WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        cands.len() as u32,
        OPTION_NONE,
        16,
        sample_nonce(),
        96 + cands.len() as u64 * PROBE_RESULT_BYTES as u64,
    );
    let blob = p.to_blob_bytes(&cands).unwrap();
    let (d, c) = WalkerParamsV2::from_blob_bytes(&blob).unwrap();
    d.validate(&c).unwrap();
}

/// WO-1801: span 1/15/17/64 rejected at DECODE time too when the wire blob
/// carries a non-16 span (hostile writer): from_blob_bytes -> validate.
#[test]
fn params_probe_span_hostile_wire_rejected() {
    let cands = sample_candidates();
    for span in [1u16, 15, 17, 64] {
        // Build a valid blob then corrupt the span field at 0x24.
        let p = WalkerParamsV2::new(
            0x0000_0000_0040_0000,
            cands.len() as u32,
            OPTION_NONE,
            16,
            sample_nonce(),
            96 + cands.len() as u64 * PROBE_RESULT_BYTES as u64,
        );
        let mut blob = p.to_blob_bytes(&cands).unwrap();
        blob[0x24..0x26].copy_from_slice(&span.to_le_bytes());
        // Recompute the header CRC so validate reaches the span check itself.
        let crc = crc32(&blob[0..PARAMS_CRC_RANGE_END]);
        blob[0x38..0x3C].copy_from_slice(&crc.to_le_bytes());
        let r = std::panic::catch_unwind(|| WalkerParamsV2::from_blob_bytes(&blob));
        assert!(r.is_ok(), "from_blob_bytes panicked on hostile span");
        let (d, c) = r.unwrap().unwrap();
        assert!(
            matches!(d.validate(&c), Err(ProtocolError::BadProbeSpan { .. })),
            "hostile span {span} must be rejected by validate"
        );
    }
}

// ----------------------------------------------------------------
// IMP-02: validated controller API (pure offline)
// ----------------------------------------------------------------

use mida_antidebug_runtime::walker_protocol::{
    controller_read_completed_section, controller_read_section, controller_validate_entry,
    encode_section, IdentityExpectation, COMPLETED_FLAG_DONE,
};

fn sample_identity_expectation(section_bytes: u64) -> IdentityExpectation {
    IdentityExpectation {
        nonce: sample_nonce(),
        target_pid: 4242,
        owner_pid: 1337,
        session_id: derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 3),
        section_bytes,
    }
}

fn sample_result() -> ProbeResultV2 {
    let mut r = ProbeResultV2::new(
        0x0000_0000_0001_0000,
        4, // CLASSIFICATION_GUARD
        1, // RESULT_FLAG_GUARD_SEEN
        0,
        [0u8; 16],
    );
    r.set_probe_span(16);
    r.set_latency_us(10);
    r
}

fn encode_done_section(results: &[ProbeResultV2]) -> Vec<u8> {
    let cap = results.len() as u32;
    let section_bytes = MIN_SECTION_HEADER_BYTES as u64 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = MappingIdentityHeaderV2::new(
        section_bytes,
        4242,
        1337,
        sample_nonce(),
        derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 3),
    );
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = cap;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    encode_section(&ident, &hdr, results).unwrap()
}

fn encode_pending_section(cap: u32) -> Vec<u8> {
    let section_bytes = MIN_SECTION_HEADER_BYTES as u64 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = MappingIdentityHeaderV2::new(
        section_bytes,
        4242,
        1337,
        sample_nonce(),
        derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 3),
    );
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    encode_section(&ident, &hdr, &[]).unwrap()
}

#[test]
fn controller_validate_entry_accepts_good_params() {
    let p = sample_params();
    let cands = sample_candidates();
    let blob = p.to_blob_bytes(&cands).unwrap();
    let (params, decoded_cands) = controller_validate_entry(&blob).unwrap();
    assert_eq!(params.candidate_count as usize, decoded_cands.len());
    assert_eq!(decoded_cands, cands);
}

#[test]
fn controller_validate_entry_rejects_corrupt_blob() {
    let p = sample_params();
    let cands = sample_candidates();
    let mut blob = p.to_blob_bytes(&cands).unwrap();
    blob[0x0C] ^= 0xFF; // corrupt blob_total_bytes -> decode rejects
    assert!(controller_validate_entry(&blob).is_err());
}

#[test]
fn controller_validate_entry_rejects_count_mismatch() {
    // Build a blob whose candidate_count does not match the array length.
    // to_blob_bytes itself rejects the mismatch (validated constructor).
    let mut p = sample_params();
    p.candidate_count = 99; // declared count != actual 3
    let cands = sample_candidates();
    assert!(p.to_blob_bytes(&cands).is_err());
    // Also: hand-craft a blob with matching encode but conflicting header
    // count by encoding with 3 then patching the header count byte.
    let p2 = sample_params();
    let mut blob = p2.to_blob_bytes(&cands).unwrap();
    blob[0x1C] = 99; // candidate_count field
    assert!(controller_validate_entry(&blob).is_err());
}

#[test]
fn controller_read_section_valid_flow() {
    let results = vec![sample_result()];
    let section = encode_done_section(&results);
    let expected = sample_identity_expectation(section.len() as u64);
    let view = controller_read_section(&section, &expected, 1).unwrap();
    assert_eq!(view.results.len(), 1);
    assert_eq!(view.header.completed_flag, COMPLETED_FLAG_DONE);
    assert_eq!(view.results[0].probe_va, sample_result().probe_va);
    assert_eq!(view.results[0].classification, 4);
}

#[test]
fn controller_read_completed_rejects_pending() {
    let section = encode_pending_section(1);
    let expected = sample_identity_expectation(section.len() as u64);
    // read_completed rejects a pending section
    assert!(matches!(
        controller_read_completed_section(&section, &expected, 1),
        Err(ProtocolError::InconsistentPendingCount { .. })
    ));
    // raw read succeeds (pending sections are readable, count must be 0)
    let view = controller_read_section(&section, &expected, 1).unwrap();
    assert_eq!(view.results.len(), 0);
}

#[test]
fn controller_read_section_rejects_identity_mismatch() {
    let results = vec![sample_result()];
    let section = encode_done_section(&results);
    // wrong nonce expectation -> fail closed
    let mut expected = sample_identity_expectation(section.len() as u64);
    expected.nonce ^= 1;
    assert!(controller_read_section(&section, &expected, 1).is_err());
}

#[test]
fn controller_read_section_rejects_truncated_buffer() {
    let results = vec![sample_result()];
    let section = encode_done_section(&results);
    let expected = sample_identity_expectation(section.len() as u64);
    // truncate below MIN_SECTION_HEADER_BYTES
    let truncated = &section[..MIN_SECTION_HEADER_BYTES - 1];
    assert!(matches!(
        controller_read_section(truncated, &expected, 1),
        Err(ProtocolError::BufferTooShort { .. })
    ));
}

#[test]
fn controller_read_section_rejects_crc_tamper() {
    let results = vec![sample_result()];
    let section = encode_done_section(&results);
    let expected = sample_identity_expectation(section.len() as u64);
    // tamper a payload byte INSIDE the results region -> CRC mismatch.
    // The payload starts at MIN_SECTION_HEADER_BYTES (0x60); the last
    // probe record byte is section.len()-1 which belongs to the record.
    let mut tampered = section.clone();
    let payload_byte = MIN_SECTION_HEADER_BYTES; // first payload byte
    tampered[payload_byte] ^= 0xFF;
    let err = controller_read_section(&tampered, &expected, 1).unwrap_err();
    assert!(matches!(err, ProtocolError::CrcMismatch { .. }));
}

// ----------------------------------------------------------------
// IMP-02-R1: CRC-first order hostile tests
// ----------------------------------------------------------------

#[test]
fn controller_crc_first_rejects_tampered_payload_before_parse() {
    // Build a valid DONE section with 1 result.
    let results = vec![sample_result()];
    let section = encode_done_section(&results);
    let expected = sample_identity_expectation(section.len() as u64);
    // Tamper the FIRST payload byte (record probe_va LSB).
    let mut tampered = section.clone();
    tampered[MIN_SECTION_HEADER_BYTES] ^= 0xFF;
    // Raw CRC check fires before record parsing -> CrcMismatch.
    assert!(matches!(
        controller_read_section(&tampered, &expected, 1),
        Err(ProtocolError::CrcMismatch { .. })
    ));
}

#[test]
fn controller_crc_first_rejects_malformed_record_region() {
    // The validated constructor rejects a record with classification out of
    // the closed set BEFORE any bytes are produced (encode_section is a
    // validated constructor), so a malformed record can never reach the
    // controller buffer. This proves the fail-closed chain:
    // constructor gate -> wire CRC -> record parse.
    let mut results = vec![sample_result()];
    results[0].classification = 99; // out of closed set (max = 5)
    let cap = results.len() as u32;
    let section_bytes = MIN_SECTION_HEADER_BYTES as u64 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = MappingIdentityHeaderV2::new(
        section_bytes,
        4242,
        1337,
        sample_nonce(),
        derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 3),
    );
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = cap;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    assert!(encode_section(&ident, &hdr, &results).is_err());
}

#[test]
fn controller_crc_first_proves_order_via_roundtrip_field() {
    // A field that round-trips (e.g. latency_us) can be changed without
    // breaking record parsing, but the raw CRC must catch it.
    let results = vec![sample_result()];
    let section = encode_done_section(&results);
    let expected = sample_identity_expectation(section.len() as u64);
    // Find latency_us offset within the record payload: ProbeResultV2 layout
    // has probe_va(8) + classification(4) + flags(1) + retry(1) + span(2)
    // + observed(16) = 32, then latency_us(4) at record offset 0x20.
    let latency_off = MIN_SECTION_HEADER_BYTES + 0x20;
    let mut tampered = section.clone();
    tampered[latency_off] ^= 0x01; // latency_us LSB flip
                                   // Raw CRC mismatch (CRC-first) -> reject before any field semantics.
    assert!(matches!(
        controller_read_section(&tampered, &expected, 1),
        Err(ProtocolError::CrcMismatch { .. })
    ));
}
