//! WO-1501 walker wire protocol v2 — offline tests (part B: result section
//! and mapping identity). Pure offline; no Windows API.

use mida_antidebug_runtime::walker_protocol::{
    derive_session_id, encode_section, parse_section, validate_section, IdentityExpectation,
    MappingIdentityHeaderV2, ProbeResultV2, ProtocolError, ResultSectionHeaderV2, WalkerParamsV2,
    CLASSIFICATION_TYPE_B, CLASSIFICATION_TYPE_C, COMPLETED_FLAG_ABORT, COMPLETED_FLAG_DONE,
    COMPLETED_FLAG_PENDING, PROBE_RESULT_BYTES, RESULT_FLAG_GUARD_SEEN, RESULT_FLAG_NONE,
    WALKER_STATUS_ERROR_MAP_FAILED, WALKER_STATUS_ERROR_PROBE_ABORTED, WALKER_STATUS_OK,
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
        // retry_count must stay within the frozen contract cap [0, 1].
        let mut r = make_probe(
            *va,
            CLASSIFICATION_TYPE_C,
            RESULT_FLAG_GUARD_SEEN,
            (i as u8) & 1,
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
    // The validated constructor (WO-1701) rejects the inconsistent
    // combination at ENCODE time, so no half-valid section can ever be
    // emitted; parse_section additionally rejects it if a hostile writer
    // crafts one on the wire.
    let res = encode_section(&ident, &hdr, &[r]);
    assert!(matches!(res, Err(ProtocolError::BadStatusForState { .. })));
    // Hostile wire: build a VALID done section, then corrupt the status byte
    // on the wire so encode cannot be blamed; parse must reject it.
    let mut hdr_ok = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr_ok.result_count = 1;
    hdr_ok.completed_flag = COMPLETED_FLAG_DONE;
    let mut bytes = encode_section(&ident, &hdr_ok, &[r]).unwrap();
    let soff = 0x38 + 0x1C; // identity(0x38) + walker_status offset(0x1C)
    bytes[soff..soff + 4].copy_from_slice(&WALKER_STATUS_ERROR_PROBE_ABORTED.to_le_bytes());
    let res = parse_section(&bytes);
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
    // Corrupt a byte INSIDE the payload region (results_off = 0x60, record
    // size 0x28): the trailing zero-fill is outside payload CRC coverage.
    let payload_off = 0x60usize;
    bytes[payload_off] ^= 0xFF;
    let res = parse_section(&bytes)
        .and_then(|(i, h, r2)| validate_section(&i, &h, &r2, &sample_expectation(), cap));
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
        let (d, c) =
            mida_antidebug_runtime::walker_protocol::WalkerParamsV2::from_blob_bytes(&b).unwrap();
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
    assert!(matches!(
        h.validate_layout(),
        Err(ProtocolError::BadCompletedFlag { .. })
    ));

    let mut h = hdr;
    h.completed_flag = COMPLETED_FLAG_ABORT;
    h.walker_status = WALKER_STATUS_OK; // abort requires non-OK status
    assert!(matches!(
        h.validate_layout(),
        Err(ProtocolError::BadStatusForState { .. })
    ));

    let mut h = hdr;
    h.completed_flag = COMPLETED_FLAG_PENDING;
    h.walker_status = WALKER_STATUS_ERROR_MAP_FAILED;
    assert!(matches!(
        h.validate_layout(),
        Err(ProtocolError::BadStatusForState { .. })
    ));

    let mut h = hdr;
    h.walker_status = 99;
    assert!(matches!(
        h.validate_layout(),
        Err(ProtocolError::UnknownWalkerStatus { .. })
    ));

    let mut h = hdr;
    h.result_stride = 8;
    assert!(matches!(
        h.validate_layout(),
        Err(ProtocolError::BadResultStride { .. })
    ));

    let mut h = hdr;
    h.results_off = 8;
    assert!(matches!(
        h.validate_layout(),
        Err(ProtocolError::ResultsOffTooSmall { .. })
    ));

    let mut h = hdr;
    h.results_off = 100; // not 8-aligned
    assert!(matches!(
        h.validate_layout(),
        Err(ProtocolError::ResultsOffUnaligned { .. })
    ));
}

// =========================================================================
// WO-1601: hostile-input hardening tests.
// Every hostile buffer must be rejected with an Err, never a panic, and
// never an untrusted-size allocation. catch_unwind proves panic-freedom.
// =========================================================================

/// from_blob_bytes with candidate_count = u32::MAX must be rejected without
/// allocating (previously Vec::with_capacity(u32::MAX) -> OOM).
#[test]
fn hostile_params_count_max_no_alloc() {
    let mut blob = vec![0u8; 0x40 + 8];
    blob[0..4].copy_from_slice(b"WALK");
    blob[4..6].copy_from_slice(&2u16.to_le_bytes());
    blob[6..8].copy_from_slice(&0x40u16.to_le_bytes());
    blob[8..16].copy_from_slice(&((0x40 + 8) as u64).to_le_bytes());
    blob[16..24].copy_from_slice(&0x400000u64.to_le_bytes());
    blob[24..28].copy_from_slice(&0x40u32.to_le_bytes());
    blob[28..32].copy_from_slice(&u32::MAX.to_le_bytes()); // hostile count
    blob[32..34].copy_from_slice(&8u16.to_le_bytes());
    blob[34..36].copy_from_slice(&16u16.to_le_bytes());
    blob[40..48].copy_from_slice(&1u64.to_le_bytes()); // nonce
    let r = std::panic::catch_unwind(|| WalkerParamsV2::from_blob_bytes(&blob));
    assert!(r.is_ok(), "from_blob_bytes panicked on hostile count");
    assert!(matches!(
        r.unwrap(),
        Err(ProtocolError::CountTooLarge { .. })
    ));
}

/// from_blob_bytes with candidate_off / stride violations must be rejected.
#[test]
fn hostile_params_fixed_field_reject_no_panic() {
    let mut blob = vec![0u8; 0x40 + 8];
    blob[0..4].copy_from_slice(b"WALK");
    blob[4..6].copy_from_slice(&2u16.to_le_bytes());
    blob[6..8].copy_from_slice(&0x40u16.to_le_bytes());
    blob[8..16].copy_from_slice(&((0x40 + 8) as u64).to_le_bytes());
    blob[24..28].copy_from_slice(&0x50u32.to_le_bytes()); // hostile off
    blob[28..32].copy_from_slice(&1u32.to_le_bytes());
    blob[32..34].copy_from_slice(&8u16.to_le_bytes());
    blob[34..36].copy_from_slice(&16u16.to_le_bytes());
    blob[40..48].copy_from_slice(&1u64.to_le_bytes());
    let r = std::panic::catch_unwind(|| WalkerParamsV2::from_blob_bytes(&blob));
    assert!(r.is_ok());
    assert!(matches!(
        r.unwrap(),
        Err(ProtocolError::BadCandidateOff { .. })
    ));

    let mut blob = vec![0u8; 0x40 + 8];
    blob[0..4].copy_from_slice(b"WALK");
    blob[4..6].copy_from_slice(&2u16.to_le_bytes());
    blob[6..8].copy_from_slice(&0x40u16.to_le_bytes());
    blob[8..16].copy_from_slice(&((0x40 + 8) as u64).to_le_bytes());
    blob[24..28].copy_from_slice(&0x40u32.to_le_bytes());
    blob[28..32].copy_from_slice(&1u32.to_le_bytes());
    blob[32..34].copy_from_slice(&1u16.to_le_bytes()); // hostile stride
    blob[34..36].copy_from_slice(&16u16.to_le_bytes());
    blob[40..48].copy_from_slice(&1u64.to_le_bytes());
    let r = std::panic::catch_unwind(|| WalkerParamsV2::from_blob_bytes(&blob));
    assert!(r.is_ok());
    assert!(matches!(
        r.unwrap(),
        Err(ProtocolError::BadCandidateStride { .. })
    ));
}

/// parse_section with result_count = u32::MAX (or over cap) must reject
/// without allocating; stride = 0 / stride = 1 must reject at layout.
#[test]
fn hostile_section_count_stride_reject_no_panic() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    // Build a well-formed identity header (CRC computed by encode_section).
    let ident = MappingIdentityHeaderV2::new(
        section_bytes,
        4242,
        1234,
        0x0123_4567_89AB_CDEF,
        derive_session_id(0x0123_4567_89AB_CDEF, 0x0000_0000_0040_0000, 1),
    );
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let bytes = encode_section(&ident, &hdr, &[]).unwrap();
    let _ = &bytes; // well-formed baseline used for corruption offsets below

    // Corrupt the header in place: result_count = u32::MAX.
    let mut hostile = bytes.clone();
    let hoff = 0x38 + 0x10; // identity(0x38) + result_count offset(0x10)
    hostile[hoff..hoff + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let r = std::panic::catch_unwind(|| parse_section(&hostile));
    assert!(r.is_ok(), "parse_section panicked on hostile count");
    assert!(matches!(
        r.unwrap(),
        Err(ProtocolError::CountTooLarge { .. })
    ));

    // result_stride = 0 -> BadResultStride at validate_layout.
    let mut hostile = bytes.clone();
    let soff = 0x38 + 0x14;
    hostile[soff..soff + 4].copy_from_slice(&0u32.to_le_bytes());
    let r = std::panic::catch_unwind(|| parse_section(&hostile));
    assert!(r.is_ok());
    assert!(matches!(
        r.unwrap(),
        Err(ProtocolError::BadResultStride { .. })
    ));

    // result_stride = 1 -> BadResultStride.
    let mut hostile = bytes.clone();
    hostile[soff..soff + 4].copy_from_slice(&1u32.to_le_bytes());
    let r = std::panic::catch_unwind(|| parse_section(&hostile));
    assert!(r.is_ok());
    assert!(matches!(
        r.unwrap(),
        Err(ProtocolError::BadResultStride { .. })
    ));
}

/// parse_section with section_bytes beyond the hard cap must reject, and
/// encode_section must refuse to emit a section whose section_bytes exceeds
/// the frozen cap (never allocate from an untrusted size).
#[test]
fn hostile_section_bytes_max_reject_no_panic() {
    let big: u64 = 0x7FFF_FFFF_FFFF_FFFF; // absurd section size

    // 1) encode_section must reject at entry (no allocation).
    let ident = MappingIdentityHeaderV2::new(
        big,
        4242,
        1234,
        0x0123_4567_89AB_CDEF,
        derive_session_id(0x0123_4567_89AB_CDEF, 0x0000_0000_0040_0000, 1),
    );
    let hdr = ResultSectionHeaderV2::new(96 + 1 * PROBE_RESULT_BYTES as u64, 1).unwrap();
    let mut hostile_hdr = hdr;
    hostile_hdr.section_bytes = big;
    let r = std::panic::catch_unwind(|| encode_section(&ident, &hostile_hdr, &[]));
    assert!(
        r.is_ok(),
        "encode_section panicked on hostile section_bytes"
    );
    assert!(matches!(
        r.unwrap(),
        Err(ProtocolError::CountTooLarge { .. }) | Err(ProtocolError::BadSectionBytes { .. })
    ));

    // 2) parse_section with a manually crafted hostile buffer (identity and
    //    header both claim section_bytes = big while the buffer is small).
    let mut small = vec![0u8; 96 + 40];
    small[0..4].copy_from_slice(b"MIDA");
    small[4..6].copy_from_slice(&2u16.to_le_bytes());
    small[8..16].copy_from_slice(&big.to_le_bytes()); // hostile section_bytes
    small[16..20].copy_from_slice(&4242u32.to_le_bytes());
    small[20..24].copy_from_slice(&1234u32.to_le_bytes());
    small[24..32].copy_from_slice(&0x0123_4567_89AB_CDEFu64.to_le_bytes());
    small[32..48].copy_from_slice(&derive_session_id(
        0x0123_4567_89AB_CDEF,
        0x0000_0000_0040_0000,
        1,
    ));
    small[0x38..0x3C].copy_from_slice(b"WRES");
    small[0x3C..0x3E].copy_from_slice(&2u16.to_le_bytes());
    small[0x40..0x48].copy_from_slice(&big.to_le_bytes());
    small[0x48..0x4C].copy_from_slice(&1u32.to_le_bytes()); // result_count=1
    small[0x4C..0x50].copy_from_slice(&40u32.to_le_bytes()); // stride
    small[0x50..0x54].copy_from_slice(&96u32.to_le_bytes()); // results_off
    small[0x54..0x58].copy_from_slice(&0u32.to_le_bytes()); // status OK
    small[0x5C..0x60].copy_from_slice(&1u32.to_le_bytes()); // completed DONE
    let r = std::panic::catch_unwind(|| parse_section(&small));
    assert!(r.is_ok(), "parse_section panicked on hostile section_bytes");
    let res = r.unwrap();
    assert!(res.is_err(), "hostile section_bytes must be rejected");
    // Either BadSectionBytes (len mismatch) or CountTooLarge (cap) is correct.
    assert!(matches!(
        res,
        Err(ProtocolError::BadSectionBytes { .. }) | Err(ProtocolError::CountTooLarge { .. })
    ));
}

/// parse_section with truncated buffers (every cut) must never panic.
#[test]
fn hostile_truncated_never_panics() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = MappingIdentityHeaderV2::new(
        section_bytes,
        4242,
        1234,
        0x0123_4567_89AB_CDEF,
        derive_session_id(0x0123_4567_89AB_CDEF, 0x0000_0000_0040_0000, 1),
    );
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    let mut pr = ProbeResultV2::new(
        0x1000,
        mida_antidebug_runtime::walker_protocol::CLASSIFICATION_TYPE_C,
        0,
        0,
        [0xAA; 16],
    );
    pr.set_probe_span(16);
    let bytes = encode_section(&ident, &hdr, &[pr]).unwrap();
    for cut in 0..bytes.len() {
        let r = std::panic::catch_unwind(|| parse_section(&bytes[..cut]));
        assert!(r.is_ok(), "parse_section panicked at cut={cut}");
    }
}

// =========================================================================
// WO-1701: encode_section validated-constructor tests.
// encode_section must reject every input combination that validate_section /
// parse_section would later reject: never emit an invalid wire record.
// =========================================================================

/// Identity with wrong magic must be rejected at encode time.
#[test]
fn encode_invalid_identity_magic_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let mut ident = make_ident(section_bytes);
    ident.magic = 0xDEAD_BEEF;
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::BadMagic { .. })));
}

/// Identity with wrong version must be rejected at encode time.
#[test]
fn encode_invalid_identity_version_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let mut ident = make_ident(section_bytes);
    ident.version = 1;
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::BadVersion { .. })));
}

/// Identity with non-zero reserved must be rejected at encode time.
#[test]
fn encode_invalid_identity_reserved_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let mut ident = make_ident(section_bytes);
    ident._reserved = 0x1234;
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::BadReserved { .. })));
}

/// Header magic corruption must be rejected at encode time.
#[test]
fn encode_invalid_header_magic_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.magic = 0;
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::BadMagic { .. })));
}

/// Header with wrong stride must be rejected at encode time.
#[test]
fn encode_invalid_header_stride_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_stride = 8;
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::BadResultStride { .. })));
}

/// Header with results_off below minimum / unaligned must be rejected.
#[test]
fn encode_invalid_results_off_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.results_off = 8; // below MIN_SECTION_HEADER_BYTES
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::ResultsOffTooSmall { .. })));

    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.results_off = 100; // not 8-aligned
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(
        res,
        Err(ProtocolError::ResultsOffUnaligned { .. })
    ));
}

/// Header with invalid completed_flag / status consistency must be rejected
/// at encode time (previously only rejected at parse/validate time).
#[test]
fn encode_invalid_completed_flag_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.completed_flag = 0x1234_5678;
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::BadCompletedFlag { .. })));

    // done flag + non-OK status: inconsistent
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    hdr.walker_status = WALKER_STATUS_ERROR_MAP_FAILED;
    let r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    let res = encode_section(&ident, &hdr, &[r]);
    assert!(matches!(res, Err(ProtocolError::BadStatusForState { .. })));
}

/// Section size / identity size mismatch must be rejected at encode time.
#[test]
fn encode_invalid_section_bytes_mismatch_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let mut ident = make_ident(section_bytes);
    ident.section_bytes = section_bytes + 8; // identity disagrees with header
    let hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    let res = encode_section(&ident, &hdr, &[]);
    assert!(matches!(res, Err(ProtocolError::BadSectionBytes { .. })));
}

/// ProbeResult with retry_count above the contract cap must be rejected.
#[test]
fn encode_invalid_retry_count_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    let mut r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 2, 0);
    r.retry_count = 2; // contract cap is 1
    let res = encode_section(&ident, &hdr, &[r]);
    assert!(matches!(res, Err(ProtocolError::BadRetryCount { .. })));
}

/// ProbeResult with non-zero reserved must be rejected at encode time.
#[test]
fn encode_invalid_reserved_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    let mut r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    r._reserved = 0xDEAD_BEEF;
    let res = encode_section(&ident, &hdr, &[r]);
    assert!(matches!(res, Err(ProtocolError::BadReserved { .. })));
}

/// ProbeResult with bad classification / unknown flags / bad span must be
/// rejected at encode time.
#[test]
fn encode_invalid_probe_fields_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;

    let mut r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    r.classification = 99;
    assert!(matches!(
        encode_section(&ident, &hdr, &[r]),
        Err(ProtocolError::BadClassification { .. })
    ));

    let mut r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    r.flags = 0x80;
    assert!(matches!(
        encode_section(&ident, &hdr, &[r]),
        Err(ProtocolError::UnknownResultFlags { .. })
    ));

    let mut r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    r.set_probe_span(0);
    assert!(matches!(
        encode_section(&ident, &hdr, &[r]),
        Err(ProtocolError::BadProbeSpan { .. })
    ));

    // Non-canonical probe VA must be rejected.
    let r = make_probe(
        0xFFFF_8000_0000_0000,
        CLASSIFICATION_TYPE_C,
        RESULT_FLAG_NONE,
        0,
        0,
    );
    assert!(matches!(
        encode_section(&ident, &hdr, &[r]),
        Err(ProtocolError::NonCanonicalVa { .. })
    ));
}

/// WO-1801: ProbeResultV2.probe_span is FROZEN to exactly 16; 1/15/17/64
/// must be rejected by validate() and therefore by encode_section.
#[test]
fn probe_result_span_frozen_rejects_non_16() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    for span in [1u16, 15, 17, 64] {
        let mut r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
        r.set_probe_span(span);
        let res = encode_section(&ident, &hdr, &[r]);
        assert!(
            matches!(res, Err(ProtocolError::BadProbeSpan { .. })),
            "span {span} must be rejected by encode_section"
        );
    }
    // Span 16 passes and round-trips.
    let mut r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    r.set_probe_span(16);
    let bytes = encode_section(&ident, &hdr, &[r]).unwrap();
    let (_i, h2, r2) = parse_section(&bytes).unwrap();
    assert_eq!(h2.result_count, 1);
    assert_eq!(r2[0].probe_span, 16);
}

/// WO-1801: hostile wire record with probe_span != 16 is rejected at parse.
#[test]
fn probe_result_span_hostile_wire_rejected() {
    let cap = 1u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 1;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    let r = make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0);
    let bytes = encode_section(&ident, &hdr, &[r]).unwrap();
    // Corrupt the record's probe_span field: record starts at 0x60, span at +14.
    let span_off = 0x60usize + 14;
    for span in [1u16, 15, 17, 64] {
        let mut hostile = bytes.clone();
        hostile[span_off..span_off + 2].copy_from_slice(&span.to_le_bytes());
        let res = parse_section(&hostile)
            .and_then(|(i, h, r2)| validate_section(&i, &h, &r2, &sample_expectation(), cap));
        assert!(
            matches!(res, Err(ProtocolError::BadProbeSpan { .. })),
            "hostile span {span} must be rejected"
        );
    }
}

/// encode_section never emits a trailing-byte / oversized buffer: the encoded
/// length is exactly section_bytes and parse_section round-trips it.
#[test]
fn encode_exact_section_bytes_round_trip() {
    let cap = 3u32;
    let section_bytes = 96 + cap as u64 * PROBE_RESULT_BYTES as u64;
    let ident = make_ident(section_bytes);
    let mut hdr = ResultSectionHeaderV2::new(section_bytes, cap).unwrap();
    hdr.result_count = 2;
    hdr.completed_flag = COMPLETED_FLAG_DONE;
    let results = vec![
        make_probe(0x1000, CLASSIFICATION_TYPE_C, RESULT_FLAG_NONE, 0, 0xAA),
        make_probe(
            0x2000,
            CLASSIFICATION_TYPE_B,
            RESULT_FLAG_GUARD_SEEN,
            1,
            0xBB,
        ),
    ];
    let bytes = encode_section(&ident, &hdr, &results).unwrap();
    assert_eq!(bytes.len(), section_bytes as usize);
    let (i2, h2, r2) = parse_section(&bytes).unwrap();
    assert_eq!(i2.section_bytes, section_bytes);
    assert_eq!(h2.result_count, 2);
    assert_eq!(r2, results);
}
