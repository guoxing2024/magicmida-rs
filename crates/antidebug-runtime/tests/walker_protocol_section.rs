//! WO-1501 walker wire protocol v2 — offline tests (part B: result section
//! and mapping identity). Pure offline; no Windows API.

use mida_antidebug_runtime::walker_protocol::{
    derive_session_id, encode_section, parse_section, validate_section, IdentityExpectation,
    MappingIdentityHeaderV2, ProbeResultV2, ProtocolError, ResultSectionHeaderV2,
    CLASSIFICATION_TYPE_C, COMPLETED_FLAG_ABORT, COMPLETED_FLAG_DONE,
    COMPLETED_FLAG_PENDING, PROBE_RESULT_BYTES, RESULT_FLAG_GUARD_SEEN, RESULT_FLAG_NONE,
    WALKER_STATUS_ERROR_MAP_FAILED, WALKER_STATUS_ERROR_PROBE_ABORTED,
    WALKER_STATUS_OK,
};

fn sample_nonce() -> u64 {
    0x0123_4567_89AB_CDEF
}

fn sample_expectation() -> IdentityExpectation {
    IdentityExpectation {
        nonce: sample_nonce(),
        target_pid: 4242,
        owner_pid: 1234,
        session_id: derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 1),
        section_bytes: 96 + 1 * PROBE_RESULT_BYTES as u64,
    }
}

fn make_ident(section_bytes: u64) -> MappingIdentityHeaderV2 {
    MappingIdentityHeaderV2::new(
        section_bytes,
        4242,
        1234,
        sample_nonce(),
        derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 1),
    )
}

fn make_probe(va: u64, class: u32, flags: u8, retry: u8, fill: u8) -> ProbeResultV2 {
    let mut r = ProbeResultV2::new(va, class, flags, retry, [fill; 16]);
    r.set_probe_span(16);
    r
}

/// Result section: pending state has no payload; done/abort expose it.
#[test]
fn section_states_and_payload() {
    let cap = 3u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = MappingIdentityHeaderV2::new(
        section_bytes,
        4242,
        1234,
        sample_nonce(),
        derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 3),
    );
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let bytes = encode_section(&ident, &hdr, &[]).unwrap();
    assert_eq!(bytes.len(), section_bytes as usize);
    let (i2, h2, r2) = parse_section(&bytes).unwrap();
    // Decoded identity equals the local one except for the CRC which is
    // computed at encode time; the decoded copy must validate.
    assert_eq!(i2.magic, ident.magic);
    assert_eq!(i2.section_bytes, ident.section_bytes);
    assert_eq!(i2.target_pid, ident.target_pid);
    assert_eq!(i2.owner_pid, ident.owner_pid);
    assert_eq!(i2.nonce, ident.nonce);
    assert_eq!(i2.session_id, ident.session_id);
    assert_ne!(i2.header_crc32, 0);
    assert_eq!(h2.completed_flag, COMPLETED_FLAG_PENDING);
    assert!(r2.is_empty());
    let mut exp = sample_expectation();
    exp.section_bytes = section_bytes;
    exp.session_id = derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 3);
    validate_section(&i2, &h2, &r2, &exp, cap).unwrap();

    // Done: payload with 3 records round-trips.
    let mut results = Vec::new();
    for (i, va) in [0x1000u64, 0x2000, 0x3000].iter().enumerate() {
        let mut r = make_probe(
            *va,
            CLASSIFICATION_TYPE_C,
            RESULT_FLAG_GUARD_SEEN,
            i as u8,
            0xCC,
        );
        r.set_latency_us(42 + i as u32);
        results.push(r);
    }
    let mut hdr2 = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr2.result_count = 3;
    hdr2.completed_flag = COMPLETED_FLAG_DONE;
    let bytes = encode_section(&ident, &hdr2, &results).unwrap();
    let (i3, h3, r3) = parse_section(&bytes).unwrap();
    assert_eq!(i3.magic, ident.magic);
    assert_eq!(i3.section_bytes, ident.section_bytes);
    assert_eq!(i3.nonce, ident.nonce);
    assert_ne!(i3.header_crc32, 0);
    assert_eq!(h3.result_count, 3);
    assert_eq!(h3.completed_flag, COMPLETED_FLAG_DONE);
    assert_eq!(r3, results);
    validate_section(&i3, &h3, &r3, &exp, cap).unwrap();

    // Abort: status error, partial payload still CRC-validated.
    let mut hdr_a = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr_a.result_count = 1;
    hdr_a.completed_flag = COMPLETED_FLAG_ABORT;
    hdr_a.walker_status = WALKER_STATUS_ERROR_PROBE_ABORTED;
    let bytes = encode_section(&ident, &hdr_a, &results[..1]).unwrap();
    let (i4, h4, r4) = parse_section(&bytes).unwrap();
    assert_eq!(h4.completed_flag, COMPLETED_FLAG_ABORT);
    assert_eq!(r4.len(), 1);
    validate_section(&i4, &h4, &r4, &exp, cap).unwrap();
}

/// Done flag with a non-OK status is inconsistent and rejected.
#[test]
fn section_status_flag_consistency() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    hdr.walker_status = WALKER_STATUS_ERROR_PROBE_ABORTED; // inconsistent
    let r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    let res = encode_section(&ident, &hdr, &[r]).and_then(|b| {
        let (i, h, r2) = parse_section(&b).unwrap();
        validate_section(&i, &h, &r2, &sample_expectation(), cap)
    });
    assert!(matches!(res, Err(ProtocolError::BadStatusForState { .. })));
}

/// Payload CRC tampering is detected.
#[test]
fn section_payload_crc_detected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    let r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0xAA);
    let mut bytes = encode_section(&ident, &hdr, &[r]).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let res = parse_section(&bytes).and_then(|(i, h, r2)| {
        validate_section(&i, &h, &r2, &sample_expectation(), cap)
    });
    assert!(matches!(res, Err(ProtocolError::CrcMismatch { .. })));
}

/// Identity echo mismatches are rejected by the controller-side check.
#[test]
fn identity_echo_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let bytes = encode_section(&ident, &hdr, &[]).unwrap();
    let (i, h, r) = parse_section(&bytes).unwrap();

    let mut exp = sample_expectation();
    exp.nonce ^= 1;
    assert!(matches!(
        validate_section(&i, &h, &r, &exp, cap),
        Err(ProtocolError::IdentityMismatch { .. })
    ));

    let mut exp = sample_expectation();
    exp.target_pid = 9999;
    assert!(matches!(
        validate_section(&i, &h, &r, &exp, cap),
        Err(ProtocolError::IdentityMismatch { .. })
    ));

    let mut exp = sample_expectation();
    exp.owner_pid = 9999;
    assert!(matches!(
        validate_section(&i, &h, &r, &exp, cap),
        Err(ProtocolError::IdentityMismatch { .. })
    ));

    let mut exp = sample_expectation();
    exp.session_id[0] ^= 0xFF;
    assert!(matches!(
        validate_section(&i, &h, &r, &exp, cap),
        Err(ProtocolError::SessionIdMismatch)
    ));

    let mut exp = sample_expectation();
    exp.section_bytes += 8;
    assert!(matches!(
        validate_section(&i, &h, &r, &exp, cap),
        Err(ProtocolError::IdentityMismatch { .. })
    ));
}

/// Target-side validation: nonce / own PID / session / size echoed.
#[test]
fn identity_target_side_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    // Encode + parse first so the identity carries a valid CRC (target-side
    // validation requires a well-formed on-wire header).
    let valid_hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let bytes = encode_section(&ident, &valid_hdr, &[]).unwrap();
    let (ident, _h, _r) = parse_section(&bytes).unwrap();
    ident
        .validate_target(
            sample_nonce(),
            4242,
            derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 1),
            section_bytes,
        )
        .unwrap();
    assert!(ident
        .validate_target(
            sample_nonce(),
            4243,
            derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 1),
            section_bytes,
        )
        .is_err());
    assert!(ident
        .validate_target(
            sample_nonce() ^ 1,
            4242,
            derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 1),
            section_bytes,
        )
        .is_err());
    let mut sid = derive_session_id(sample_nonce(), 0x0000_0000_0040_0000, 1);
    sid[15] ^= 1;
    assert!(ident
        .validate_target(sample_nonce(), 4242, sid, section_bytes)
        .is_err());
}

/// Truncated buffers are rejected everywhere.
#[test]
fn truncated_buffers_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    let r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    let bytes = encode_section(&ident, &hdr, &[r]).unwrap();
    for cut in 0..bytes.len() {
        assert!(parse_section(&bytes[..cut]).is_err(), "cut={cut}");
    }
}

/// Hostile fields are rejected via checked arithmetic.
#[test]
fn hostile_counts_rejected() {
    let p = mida_antidebug_runtime::walker_protocol::WalkerParamsV2::new(
        0x0000_0000_0040_0000,
        u32::MAX,
        mida_antidebug_runtime::walker_protocol::OPTION_NONE,
        16,
        sample_nonce(),
        0,
    );
    let res = p.to_blob_bytes(&[]).and_then(|b| {
        let (d, c) = mida_antidebug_runtime::walker_protocol::WalkerParamsV2::from_blob_bytes(&b)
            .unwrap();
        d.validate(&c)
    });
    assert!(res.is_err());

    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    // Encode + parse a valid section, then mutate the parsed header so the
    // identity CRC stays valid and validate_section reaches the capacity rule.
    let valid_hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let bytes = encode_section(&ident, &valid_hdr, &[]).unwrap();
    let (i, h, r) = parse_section(&bytes).unwrap();
    let mut hostile = h;
    hostile.result_count = u32::MAX;
    hostile.completed_flag = COMPLETED_FLAG_DONE;
    assert!(matches!(
        validate_section(&i, &hostile, &r, &sample_expectation(), cap),
        Err(ProtocolError::ResultCountExceedsCapacity { .. })
    ));
}

/// Unknown completed_flag / unknown walker_status / wrong stride / small or
/// unaligned results_off are all rejected.
#[test]
fn header_closed_sets_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let _ident = make_ident(section_bytes);
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();

    let mut h = hdr;
    h.completed_flag = 0x1234_5678;
    assert!(matches!(h.validate_layout(), Err(ProtocolError::BadCompletedFlag { .. })));

    let mut h = hdr;
    h.completed_flag = COMPLETED_FLAG_ABORT;
    h.walker_status = WALKER_STATUS_OK; // abort requires non-OK status
    assert!(matches!(h.validate_layout(), Err(ProtocolError::BadStatusForState { .. })));

    let mut h = hdr;
    h.completed_flag = COMPLETED_FLAG_PENDING;
    h.walker_status = WALKER_STATUS_ERROR_MAP_FAILED;
    assert!(matches!(h.validate_layout(), Err(ProtocolError::BadStatusForState { .. })));

    let mut h = hdr;
    h.walker_status = 99;
    assert!(matches!(h.validate_layout(), Err(ProtocolError::UnknownWalkerStatus { .. })));

    let mut h = hdr;
    h.result_stride = 8;
    assert!(matches!(h.validate_layout(), Err(ProtocolError::BadResultStride { .. })));

    let mut h = hdr;
    h.results_off = 8;
    assert!(matches!(h.validate_layout(), Err(ProtocolError::ResultsOffTooSmall { .. })));

    let mut h = hdr;
    h.results_off = 100; // not 8-aligned
    assert!(matches!(h.validate_layout(), Err(ProtocolError::ResultsOffUnaligned { .. })));
}