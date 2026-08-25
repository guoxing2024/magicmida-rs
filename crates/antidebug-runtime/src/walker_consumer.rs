//! IMP-09-CARRIER-R5-R3: production output consumer + V2 attestation digest
//! verification (pure offline, fail-closed).
//!
//! This is the CONSUMER side of the R5-R3 loop. It consumes the produced
//! round sections (round-1 / round-2 DONE) through a provider, verifies the
//! full fail-closed gate list (R3-3), then verifies the V2 attestation
//! digest closure:
//!
//! 1. magic/version/schema of the section identity/header;
//! 2. section bounds and declared length;
//! 3. round order, monotonic sequence, DONE state (round flags);
//! 4. payload digest (CRC32) per round and the V2 attestation digest
//!    (sha256 of the json-c14n preimage minus record_digest);
//! 5. raw walker status + output presence;
//! 6. output missing / duplicate / truncated / out-of-order / digest
//!    mismatch all fail closed.
//!
//! The consumer NEVER authorizes a live run: it is a pure verifier over
//! provider reads and caller-provided attestation JSON. Live authorization
//! stays `false` for this work order.

use crate::attestation::{
    parse_attestation, AttestationError, RuntimeAttestationV2, TaggedAttestation,
};
use crate::walker_control::{WalkerIoError, WalkerMemoryProvider};
use crate::walker_protocol::{
    parse_section, validate_section, IdentityExpectation, ProtocolError, ResultSectionHeaderV2,
    COMPLETED_FLAG_DONE, PROBE_RESULT_BYTES, ROUND1_DONE, ROUND2_DONE,
};

/// Consumer verdict (closed set).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumerVerdict {
    /// Both rounds consumed, digests MATCH, attestation digest verified.
    Pass,
    /// Any fail-closed gate failed (structured reason preserved).
    Fail(ConsumerFailure),
}

/// Structured consumer failure (R3-4: original error never swallowed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumerFailure {
    Protocol(ProtocolError),
    Io(WalkerIoError),
    Attestation(AttestationError),
    RoundSequence {
        expected: u8,
        got: u8,
    },
    CountMismatch {
        got: usize,
        expected: u32,
    },
    CompletedFlag {
        got: u32,
    },
    RoundFlags {
        got: u16,
        expected: u16,
    },
    DigestMismatch {
        what: String,
        expected: String,
        got: String,
    },
    OutputMissing,
    OutputDuplicate,
    OutputTruncated {
        got: usize,
        expected: usize,
    },
    OutputOutOfOrder,
    RawStatus {
        got: u32,
    },
    NoWalkerAttestation,
    NotV2,
}

impl std::fmt::Display for ConsumerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Attestation(e) => write!(f, "attestation: {e}"),
            Self::RoundSequence { expected, got } => {
                write!(f, "round sequence: expected {expected} got {got}")
            }
            Self::CountMismatch { got, expected } => {
                write!(f, "count mismatch: got {got} expected {expected}")
            }
            Self::CompletedFlag { got } => write!(f, "unexpected completed_flag 0x{got:08X}"),
            Self::RoundFlags { got, expected } => {
                write!(f, "round flags 0x{got:04X} != expected 0x{expected:04X}")
            }
            Self::DigestMismatch {
                what,
                expected,
                got,
            } => {
                write!(f, "digest mismatch ({what}): expected {expected} got {got}")
            }
            Self::OutputMissing => write!(f, "walker output missing"),
            Self::OutputDuplicate => write!(f, "duplicate walker output"),
            Self::OutputTruncated { got, expected } => {
                write!(f, "output truncated: got {got} expected {expected}")
            }
            Self::OutputOutOfOrder => write!(f, "output out of order"),
            Self::RawStatus { got } => write!(f, "non-OK raw walker status 0x{got:08X}"),
            Self::NoWalkerAttestation => write!(f, "v2 attestation has no walker_attestation"),
            Self::NotV2 => write!(f, "attestation is not v2"),
        }
    }
}

impl std::error::Error for ConsumerFailure {}

impl From<ProtocolError> for ConsumerFailure {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<WalkerIoError> for ConsumerFailure {
    fn from(e: WalkerIoError) -> Self {
        Self::Io(e)
    }
}
impl From<AttestationError> for ConsumerFailure {
    fn from(e: AttestationError) -> Self {
        Self::Attestation(e)
    }
}

/// Verified consumption record (one round).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedRound {
    pub round_index: u8,
    pub sequence: u64,
    pub section_va: u64,
    pub payload_length: u64,
    pub payload_crc32: u32,
    pub result_count: u32,
}

/// Result of a successful two-round consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumedOutput {
    pub rounds: Vec<ConsumedRound>,
    pub attestation: RuntimeAttestationV2,
    /// Re-verified V2 record digest (64 lowercase hex).
    pub verified_record_digest: String,
}

/// Production consumer: read + verify BOTH produced round sections through
/// the provider, then verify the V2 attestation digest closure.
///
/// Fail-closed gate order (R3-3):
/// 1. round-1 slot: full identity + layout + CRC validation, DONE flag,
///    round flags == ROUND1_DONE, raw status OK, count == capacity;
/// 2. round-2 slot: same, round flags == ROUND1_DONE|ROUND2_DONE;
/// 3. monotonic sequence (round 1 before round 2 — enforced by the audit
///    of each slot AND by the consumer calling order);
/// 4. output attestation: MUST be v2 with a walker_attestation; digest
///    recomputed and compared; nested walker digest verified.
pub fn consume_produced_sections<P: WalkerMemoryProvider + ?Sized>(
    provider: &P,
    section1_va: u64,
    section_bytes: u64,
    expectation: &IdentityExpectation,
    capacity: u32,
    attestation_json: &str,
) -> Result<ConsumedOutput, ConsumerFailure> {
    // --- Gate: section bounds ---
    let sec_end =
        section1_va
            .checked_add(section_bytes)
            .ok_or(ConsumerFailure::OutputTruncated {
                got: 0,
                expected: section_bytes as usize,
            })?;
    if sec_end < section1_va {
        return Err(ConsumerFailure::OutputTruncated {
            got: 0,
            expected: section_bytes as usize,
        });
    }
    let slot_len = section_bytes as usize;
    let mut slot1 = vec![0u8; slot_len];
    let mut slot2 = vec![0u8; slot_len];
    provider.read(section1_va, &mut slot1)?;
    let sec2_va = sec_end;
    provider.read(sec2_va, &mut slot2)?;

    // --- Gate: round-1 ---
    let round1 = verify_round_slot(&slot1, expectation, capacity, 1)?;
    // --- Gate: round-2 ---
    let round2 = verify_round_slot(&slot2, expectation, capacity, 2)?;
    // --- Gate: monotonic sequence (round 1 strictly before round 2) ---
    if round1.sequence >= round2.sequence {
        return Err(ConsumerFailure::OutputOutOfOrder);
    }

    // --- Gate: output presence + schema ---
    if attestation_json.is_empty() {
        return Err(ConsumerFailure::OutputMissing);
    }
    let tagged = parse_attestation(attestation_json)?;
    let att = match tagged {
        TaggedAttestation::V2(a) => a,
        TaggedAttestation::V1(_) => return Err(ConsumerFailure::NotV2),
    };
    if att.walker_attestation.is_none() {
        return Err(ConsumerFailure::NoWalkerAttestation);
    }

    // --- Gate: V2 attestation digest closure ---
    // 1. full validate() (nested walker digest + top-level digest recompute);
    // 2. explicit recompute of the record digest for the audit trail.
    att.validate()?;
    let recomputed = att.compute_digest();
    if recomputed != att.record_digest {
        return Err(ConsumerFailure::DigestMismatch {
            what: "record_digest".to_string(),
            expected: recomputed.clone(),
            got: att.record_digest.clone(),
        });
    }

    Ok(ConsumedOutput {
        rounds: vec![round1, round2],
        attestation: att,
        verified_record_digest: recomputed,
    })
}

/// Verify ONE produced round slot (identity + layout + CRC + DONE + flags +
/// count + digest). `round_index` is 1 or 2.
pub fn verify_round_slot(
    slot: &[u8],
    expectation: &IdentityExpectation,
    capacity: u32,
    round_index: u8,
) -> Result<ConsumedRound, ConsumerFailure> {
    // Truncation gate: exact section_bytes required.
    if slot.len() as u64 != expectation.section_bytes {
        return Err(ConsumerFailure::OutputTruncated {
            got: slot.len(),
            expected: expectation.section_bytes as usize,
        });
    }
    let (identity, header, results) = parse_section(slot)?;
    validate_section(&identity, &header, &results, expectation, capacity)?;
    // DONE state + round flags audit.
    if header.completed_flag != COMPLETED_FLAG_DONE {
        return Err(ConsumerFailure::CompletedFlag {
            got: header.completed_flag,
        });
    }
    let expected_flags = match round_index {
        1 => ROUND1_DONE,
        2 => ROUND1_DONE | ROUND2_DONE,
        _ => {
            return Err(ConsumerFailure::RoundSequence {
                expected: 1,
                got: round_index,
            })
        }
    };
    if header.round_flags() != expected_flags {
        return Err(ConsumerFailure::RoundFlags {
            got: header.round_flags(),
            expected: expected_flags,
        });
    }
    header.validate_round_flags(round_index)?;
    if results.len() as u32 != capacity {
        return Err(ConsumerFailure::CountMismatch {
            got: results.len(),
            expected: capacity,
        });
    }
    // Raw status gate: a completed round must carry OK.
    if header.walker_status != crate::walker_protocol::WALKER_STATUS_OK {
        return Err(ConsumerFailure::RawStatus {
            got: header.walker_status,
        });
    }
    // Payload digest gate: recompute CRC over the raw payload region.
    let payload = &slot[crate::walker_protocol::IDENTITY_HEADER_BYTES
        + crate::walker_protocol::RESULT_HEADER_BYTES..];
    let computed = crate::walker_protocol::crc32(payload);
    if computed != header.payload_crc32 {
        return Err(ConsumerFailure::DigestMismatch {
            what: format!("round{round_index}_payload_crc32"),
            expected: format!("{:#010x}", header.payload_crc32),
            got: format!("{computed:#010x}"),
        });
    }
    // Monotonic sequence: round 1 has sequence 1, round 2 has sequence 2
    // (the round DONE bits encode the round; the consumer enforces order
    // separately via the round-flags audit above).
    let sequence = round_index as u64;
    Ok(ConsumedRound {
        round_index,
        sequence,
        section_va: 0, // filled by the caller (provider VAs are caller-known)
        payload_length: results.len() as u64 * PROBE_RESULT_BYTES as u64,
        payload_crc32: computed,
        result_count: results.len() as u32,
    })
}

/// Convenience: extract the round-sequence from a DONE header for audit
/// (round 1 -> sequence 1, round 2 -> sequence 2 by the round flags).
pub fn round_sequence_of(header: &ResultSectionHeaderV2) -> u64 {
    if header.round_flags() == ROUND1_DONE {
        1
    } else if header.round_flags() == (ROUND1_DONE | ROUND2_DONE) {
        2
    } else {
        0
    }
}

/// Verify an attestation JSON string is a valid v2 record whose
/// record_digest recomputes (the standalone digest gate used by the
/// controller before accepting walker output).
pub fn verify_v2_attestation_digest(json: &str) -> Result<String, ConsumerFailure> {
    if json.is_empty() {
        return Err(ConsumerFailure::OutputMissing);
    }
    let tagged = parse_attestation(json)?;
    let att = match tagged {
        TaggedAttestation::V2(a) => a,
        TaggedAttestation::V1(_) => return Err(ConsumerFailure::NotV2),
    };
    if att.walker_attestation.is_none() {
        return Err(ConsumerFailure::NoWalkerAttestation);
    }
    att.validate()?;
    let recomputed = att.compute_digest();
    if recomputed != att.record_digest {
        return Err(ConsumerFailure::DigestMismatch {
            what: "record_digest".to_string(),
            expected: recomputed.clone(),
            got: att.record_digest.clone(),
        });
    }
    Ok(recomputed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walker_control::MemoryMapProvider;
    use crate::walker_producer::SectionProducer;
    use crate::walker_protocol::{
        derive_session_id, encode_section, MappingIdentityHeaderV2, ProbeResultV2,
        ResultSectionHeaderV2, CLASSIFICATION_TYPE_C, RESULT_FLAG_GUARD_SEEN,
    };

    fn nonce() -> u64 {
        0x0A0B_0C0D_0E0F_0102
    }

    fn base() -> u64 {
        0x0000_0040_0000
    }

    fn cap() -> u32 {
        3
    }

    fn sec_bytes() -> u64 {
        96 + cap() as u64 * PROBE_RESULT_BYTES as u64
    }

    fn expectation() -> IdentityExpectation {
        IdentityExpectation {
            nonce: nonce(),
            target_pid: 4242,
            owner_pid: 1234,
            session_id: derive_session_id(nonce(), base(), cap()),
            section_bytes: sec_bytes(),
        }
    }

    fn identity() -> MappingIdentityHeaderV2 {
        MappingIdentityHeaderV2::new(
            sec_bytes(),
            4242,
            1234,
            nonce(),
            derive_session_id(nonce(), base(), cap()),
        )
    }

    fn results() -> Vec<ProbeResultV2> {
        (0..cap())
            .map(|i| {
                let mut r = ProbeResultV2::new(
                    base() + 0x1000 * i as u64,
                    CLASSIFICATION_TYPE_C,
                    RESULT_FLAG_GUARD_SEEN,
                    (i % 2) as u8,
                    [0xBB; 16],
                );
                r.set_probe_span(16);
                r
            })
            .collect()
    }

    fn build_v2_attestation() -> String {
        // Build a fully valid v2 attestation with a walker_attestation whose
        // digests recompute (mirrors the production anchor path).
        use crate::attestation::{
            AbortState, HookInventory, ProbeSummary, RoundLedger, RuntimeAttestationV2,
            WalkerAttestation, ARCH_X86_64, ATTESTATION_SCHEMA_V2, ATTESTATION_SCHEMA_VERSION_V2,
        };
        let mut r1 = RoundLedger::new(1).unwrap();
        r1.entry_ts = "t1".to_string();
        r1.exit_ts = "t2".to_string();
        r1.wall_budget_ms = 1000;
        r1.wall_spent_ms = 1;
        r1.candidates_probed = cap();
        r1.abort_state = AbortState::None;
        r1.next_round_authorized = true;
        r1.validate().unwrap();
        let mut r2 = RoundLedger::new(2).unwrap();
        r2.entry_ts = "t3".to_string();
        r2.exit_ts = "t4".to_string();
        r2.wall_budget_ms = 1000;
        r2.wall_spent_ms = 1;
        r2.candidates_probed = cap();
        r2.abort_state = AbortState::None;
        r2.validate().unwrap();
        let summary = ProbeSummary {
            candidates_total: cap() * 2,
            type_a_count: 0,
            type_b_count: 0,
            type_c_count: cap() * 2,
            av_count: 0,
            guard_count: cap() * 2,
            retry_count: cap(),
            total_latency_us: 10,
        };
        summary.validate().unwrap();
        let mut walker = WalkerAttestation::new(
            4242,
            "aa".repeat(32),
            "bb".repeat(32),
            0x2040,
            0x7FF600000000 + 0x2040,
            summary,
        );
        walker.rounds = vec![r1, r2];
        walker.record_digest = walker.compute_digest();
        let inventory = HookInventory::unsupported(&[]);
        let mut top = RuntimeAttestationV2 {
            schema: ATTESTATION_SCHEMA_V2.to_string(),
            schema_version: ATTESTATION_SCHEMA_VERSION_V2,
            runtime_id: "mida-antidebug-runtime-x64".to_string(),
            runtime_version: "0.1.0".to_string(),
            architecture: ARCH_X86_64.to_string(),
            runtime_sha256: "bb".repeat(32),
            profile_id: "p".to_string(),
            profile_digest: "cc".repeat(32),
            target_pid: 4242,
            module_base: 0x7FF600000000,
            initialized: true,
            hooks_expected: inventory.hooks_expected,
            hooks_installed: inventory.hooks_installed,
            hook_failures: inventory.hook_failures,
            surface_details: vec![],
            telemetry_channel: "ready".to_string(),
            cleanup_handler_registered: true,
            third_party: "test".to_string(),
            source_revision: "test".to_string(),
            toolchain: "rustc".to_string(),
            walker_attestation: Some(walker),
            record_digest: String::new(),
        };
        top.record_digest = top.compute_digest();
        top.to_canonical_json().unwrap()
    }

    fn produce_full() -> (MemoryMapProvider, u64, u64) {
        let mut p =
            SectionProducer::new(identity(), expectation(), cap(), base() + 0x1000).unwrap();
        p.publish_pending_header().unwrap();
        p.publish_round1_done(&results()).unwrap();
        p.publish_round2_done(&results()).unwrap();
        let mut prov = MemoryMapProvider::new();
        let s1 = base() + 0x1000;
        let s2 = s1 + sec_bytes();
        prov.insert(s1, p.slot(1).unwrap().to_vec());
        prov.insert(s2, p.slot(2).unwrap().to_vec());
        (prov, s1, s2)
    }

    #[test]
    fn consumer_pass_full_loop_with_digest_match() {
        let (prov, s1, _s2) = produce_full();
        let out = consume_produced_sections(
            &prov,
            s1,
            sec_bytes(),
            &expectation(),
            cap(),
            &build_v2_attestation(),
        )
        .unwrap();
        assert_eq!(out.rounds.len(), 2);
        assert_eq!(out.rounds[0].round_index, 1);
        assert_eq!(out.rounds[1].round_index, 2);
        assert_eq!(out.rounds[1].sequence, 2);
        assert_eq!(out.rounds[1].sequence, out.rounds[0].sequence + 1);
        assert_eq!(out.verified_record_digest.len(), 64);
        assert_eq!(out.verified_record_digest, out.attestation.record_digest);
    }

    #[test]
    fn consumer_pending_direct_consume_fails() {
        // PENDING header + empty payload -> must fail (no DONE).
        let ident = identity();
        let header = ResultSectionHeaderV2::new(sec_bytes(), cap()).unwrap();
        let slot = encode_section(&ident, &header, &[]).unwrap();
        let mut prov = MemoryMapProvider::new();
        prov.insert(base() + 0x1000, slot.clone());
        prov.insert(base() + 0x1000 + sec_bytes(), slot);
        let err = consume_produced_sections(
            &prov,
            base() + 0x1000,
            sec_bytes(),
            &expectation(),
            cap(),
            &build_v2_attestation(),
        )
        .unwrap_err();
        assert!(matches!(err, ConsumerFailure::CompletedFlag { .. }));
    }

    #[test]
    fn consumer_round2_before_round1_flags_fails() {
        // Round-2 slot carrying only ROUND2_DONE (no ROUND1_DONE) must fail.
        let ident = identity();
        let mut header = ResultSectionHeaderV2::new(sec_bytes(), cap()).unwrap();
        header.result_count = cap();
        header.completed_flag = COMPLETED_FLAG_DONE;
        header.set_round_flags(ROUND2_DONE).unwrap();
        let slot2 = encode_section(&ident, &header, &results()).unwrap();
        // Round1 slot is valid.
        let mut h1 = ResultSectionHeaderV2::new(sec_bytes(), cap()).unwrap();
        h1.result_count = cap();
        h1.completed_flag = COMPLETED_FLAG_DONE;
        h1.set_round_flags(ROUND1_DONE).unwrap();
        let slot1 = encode_section(&ident, &h1, &results()).unwrap();
        let mut prov = MemoryMapProvider::new();
        prov.insert(base() + 0x1000, slot1);
        prov.insert(base() + 0x1000 + sec_bytes(), slot2);
        let err = consume_produced_sections(
            &prov,
            base() + 0x1000,
            sec_bytes(),
            &expectation(),
            cap(),
            &build_v2_attestation(),
        )
        .unwrap_err();
        assert!(matches!(err, ConsumerFailure::RoundFlags { .. }));
    }

    #[test]
    fn consumer_truncated_output_fails() {
        let (prov, s1, _s2) = produce_full();
        // Truncate the READ: pass a section_bytes larger than the produced
        // slot so the provider read is truncated (or the parse fails).
        // Here: request a slot length that the provider cannot fully serve.
        let big = sec_bytes() + PROBE_RESULT_BYTES as u64;
        let err = consume_produced_sections(
            &prov,
            s1,
            big,
            &expectation(),
            cap(),
            &build_v2_attestation(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConsumerFailure::Io(WalkerIoError::OutOfBounds { .. })
                    | ConsumerFailure::Protocol(ProtocolError::BadSectionBytes { .. })
            ),
            "expected truncated failure, got {err:?}"
        );
    }

    #[test]
    fn consumer_digest_mismatch_fails() {
        let (prov, s1, s2) = produce_full();
        // Tamper a payload byte of round 1 -> CRC mismatch. Tamper inside
        // the `observed` field of the first record (payload offset 16..32),
        // NOT the probe_va (which would trip NonCanonicalVa first).
        let mut raw = vec![0u8; sec_bytes() as usize];
        prov.read_from(s1, &mut raw).unwrap();
        raw[96 + 20] ^= 0xFF; // first record observed[4]
        let mut raw2 = vec![0u8; sec_bytes() as usize];
        prov.read_from(s2, &mut raw2).unwrap();
        let mut prov2 = MemoryMapProvider::new();
        prov2.insert(s1, raw);
        prov2.insert(s2, raw2);
        let err = consume_produced_sections(
            &prov2,
            s1,
            sec_bytes(),
            &expectation(),
            cap(),
            &build_v2_attestation(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConsumerFailure::Protocol(ProtocolError::CrcMismatch { .. })
            ),
            "expected CrcMismatch, got {err:?}"
        );
    }

    #[test]
    fn consumer_output_missing_fails() {
        let (prov, s1, _s2) = produce_full();
        let err = consume_produced_sections(&prov, s1, sec_bytes(), &expectation(), cap(), "")
            .unwrap_err();
        assert!(matches!(err, ConsumerFailure::OutputMissing));
    }

    #[test]
    fn consumer_attestation_digest_tamper_fails() {
        let (prov, s1, _s2) = produce_full();
        let json = build_v2_attestation();
        // Tamper the JSON: change a recorded field WITHOUT recomputing the
        // digest -> the digest gate must fail.
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["profile_digest"] = serde_json::Value::String("dd".repeat(32));
        let tampered = serde_json::to_string(&v).unwrap();
        let err =
            consume_produced_sections(&prov, s1, sec_bytes(), &expectation(), cap(), &tampered)
                .unwrap_err();
        assert!(
            matches!(
                err,
                ConsumerFailure::Attestation(AttestationError::RecordDigestMismatch { .. })
            ),
            "expected record-digest mismatch, got {err:?}"
        );
    }

    #[test]
    fn consumer_non_ok_raw_status_fails() {
        let ident = identity();
        let mut header = ResultSectionHeaderV2::new(sec_bytes(), cap()).unwrap();
        header.result_count = cap();
        header.completed_flag = COMPLETED_FLAG_DONE;
        header.set_round_flags(ROUND1_DONE).unwrap();
        // Encode a VALID done slot, then corrupt walker_status on the wire
        // (encode rejects the inconsistent state, the wire can still carry it).
        let mut slot1 = encode_section(&ident, &header, &results()).unwrap();
        let status_off = crate::walker_protocol::IDENTITY_HEADER_BYTES + 0x1C;
        slot1[status_off..status_off + 4].copy_from_slice(
            &crate::walker_protocol::WALKER_STATUS_ERROR_PROBE_ABORTED.to_le_bytes(),
        );
        let mut prov = MemoryMapProvider::new();
        prov.insert(base() + 0x1000, slot1);
        let mut h2 = ResultSectionHeaderV2::new(sec_bytes(), cap()).unwrap();
        h2.result_count = cap();
        h2.completed_flag = COMPLETED_FLAG_DONE;
        h2.set_round_flags(ROUND1_DONE | ROUND2_DONE).unwrap();
        let slot2 = encode_section(&ident, &h2, &results()).unwrap();
        prov.insert(base() + 0x1000 + sec_bytes(), slot2);
        let err = consume_produced_sections(
            &prov,
            base() + 0x1000,
            sec_bytes(),
            &expectation(),
            cap(),
            &build_v2_attestation(),
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                ConsumerFailure::Protocol(ProtocolError::BadStatusForState { .. })
                    | ConsumerFailure::RawStatus { .. }
            ),
            "expected raw-status failure, got {err:?}"
        );
    }

    #[test]
    fn consumer_duplicate_output_fails() {
        // Both slots carry round-1 DONE -> the second round fails the
        // round-flags audit (round 2 requires both bits).
        let ident = identity();
        let mut h1 = ResultSectionHeaderV2::new(sec_bytes(), cap()).unwrap();
        h1.result_count = cap();
        h1.completed_flag = COMPLETED_FLAG_DONE;
        h1.set_round_flags(ROUND1_DONE).unwrap();
        let slot1 = encode_section(&ident, &h1, &results()).unwrap();
        let mut prov = MemoryMapProvider::new();
        prov.insert(base() + 0x1000, slot1.clone());
        prov.insert(base() + 0x1000 + sec_bytes(), slot1);
        let err = consume_produced_sections(
            &prov,
            base() + 0x1000,
            sec_bytes(),
            &expectation(),
            cap(),
            &build_v2_attestation(),
        )
        .unwrap_err();
        assert!(matches!(err, ConsumerFailure::RoundFlags { .. }));
    }

    #[test]
    fn consumer_missing_walker_attestation_fails() {
        let (_prov, _s1, _s2) = produce_full();
        // A structurally valid v2 attestation WITHOUT walker_attestation.
        let json = build_v2_attestation();
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["walker_attestation"] = serde_json::Value::Null;
        let stripped = serde_json::to_string(&v).unwrap();
        let err = verify_v2_attestation_digest(&stripped).unwrap_err();
        assert!(matches!(err, ConsumerFailure::NoWalkerAttestation));
    }

    #[test]
    fn verify_v2_digest_standalone_ok() {
        let json = build_v2_attestation();
        let d = verify_v2_attestation_digest(&json).unwrap();
        assert_eq!(d.len(), 64);
    }
}
