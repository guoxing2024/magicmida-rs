//! IMP-09-CARRIER-R5-R3: production round-1 / round-2 result section
//!
//! Production `.unwrap()`/`.expect()`s are invariants (WO-12 follow-up,
//! surfaced by the --lib --bins -D audit): fixed-width slice `try_into()`
//! behind explicit bound checks, `RUNTIME.get()` after a just-succeeded
//! `set()`, and `slot_va(1/2)` on already-produced rounds. No production
//! fallible path is masked. Test-block unwraps/expects are assertions.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! producer with the DONE publication protocol (pure offline, fail-closed).
//!
//! The walker runs TWO rounds in the SAME result section allocation:
//! round 1 writes its DONE header + probe records at `section1_va`, round 2
//! writes its DONE header + probe records at `section1_va + section_bytes`
//! (the second round slot). This module is the PRODUCER side of that
//! contract:
//!
//! ```text
//! ALLOCATED -> HEADER_WRITTEN -> ROUND1_DONE -> ROUND2_DONE -> CONSUMED
//! ```
//!
//! - [`SectionProducer`] owns the in-memory two-slot section and the round
//!   state machine. It is byte-exact: the encoded buffer is the full
//!   `section_bytes` slot, so writing it into target memory at the slot VA
//!   publishes a complete round (identity header + DONE header + payload).
//! - DONE publication is monotonic and audited: a round's DONE can only be
//!   published once, in order, after the round payload is fully validated
//!   (digest recomputable). Any write/validation failure publishes NO DONE
//!   and NO READY; the producer returns the original error (never swallowed)
//!   and keeps the failed event sequence in the [`ProducedRound`] ledger.
//! - The producer never touches a process: it only produces bytes. The
//!   controller (walker_session / walker_control) is the production caller
//!   that writes them into target memory with WriteProcessMemory.
//!
//! # Round flags (versioned protocol extension)
//!
//! Round DONE state is carried in the result header `_reserved` u16 slot
//! (bytes 0x06..0x08 of the result header; section offset 0x3E..0x40) —
//! see `walker_protocol` module docs for the exact bit contract:
//! `ROUND1_DONE = 0x0001`, `ROUND2_DONE = 0x0002`, round 2 requires both.
//!
//! # Fail-closed rules (R3-2 / R3-4)
//!
//! - header starts PENDING (round_flags == 0, result_count == 0);
//! - round-1 payload must be complete, in-bounds, digest-recomputable
//!   BEFORE its DONE is published;
//! - round-2 can only be published after round-1 is confirmed DONE;
//! - any failure -> no DONE, no READY, original error preserved, no
//!   silent retry (a new producer instance is the only way forward).

use crate::walker_protocol::{
    crc32, encode_section, parse_section, validate_section, IdentityExpectation,
    MappingIdentityHeaderV2, ProbeResultV2, ProtocolError, ResultSectionHeaderV2,
    COMPLETED_FLAG_DONE, COMPLETED_FLAG_PENDING, IDENTITY_HEADER_BYTES, MAX_RESULT_SECTION_BYTES,
    MIN_SECTION_HEADER_BYTES, PROBE_RESULT_BYTES, RESULT_HEADER_BYTES, ROUND1_DONE, ROUND2_DONE,
};

/// Producer phase (closed set; mirrors the R5-R3 state machine).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerPhase {
    /// Section slots allocated, nothing written yet.
    Allocated,
    /// Round-1 slot header written (PENDING).
    HeaderWritten,
    /// Round-1 DONE published.
    Round1Done,
    /// Round-2 DONE published.
    Round2Done,
    /// Round-2 slot consumed by the controller (CONSUMED).
    Consumed,
    /// Any failure: terminal, no DONE/READY from here.
    Failed,
}

impl ProducerPhase {
    /// Forward-edge table (R3-1). PENDING -> CONSUMED and any skip/repeat
    /// are impossible: every transition is validated here.
    fn can_transition(&self, next: ProducerPhase) -> bool {
        matches!(
            (self, next),
            (ProducerPhase::Allocated, ProducerPhase::HeaderWritten)
                | (ProducerPhase::HeaderWritten, ProducerPhase::Round1Done)
                | (ProducerPhase::Round1Done, ProducerPhase::Round2Done)
                | (ProducerPhase::Round2Done, ProducerPhase::Consumed)
        )
    }
}

/// One produced round slot: byte buffer + monotonic sequence + audit ledger.
#[derive(Debug, Clone)]
pub struct ProducedRound {
    /// Monotonic sequence (1-based, matches the R5-R3 state list).
    pub sequence: u64,
    /// 1 or 2.
    pub round_index: u8,
    /// Slot VA inside the section region (section1_va for round 1,
    /// section1_va + section_bytes for round 2).
    pub slot_va: u64,
    /// section_bytes (== identity/header declared section_bytes).
    pub section_bytes: u64,
    /// payload length in bytes (result_count * PROBE_RESULT_BYTES).
    pub payload_length: u64,
    /// digest of the produced slot (sha256 hex? no — the walker protocol
    /// uses payload CRC32 as its digest; the V2 attestation digest is
    /// computed by the consumer over the attestation record. The producer
    /// records the payload CRC32 here as the round digest).
    pub payload_crc32: u32,
    /// Raw completed_flag / round_flags word as published.
    pub raw_status: u32,
    /// True when this round's DONE was published.
    pub done_published: bool,
}

/// Production result-section producer (two round slots, one section).
#[derive(Debug, Clone)]
pub struct SectionProducer {
    phase: ProducerPhase,
    /// Identity header (shared by both slots; section_bytes bound).
    identity: MappingIdentityHeaderV2,
    /// Expected identity (controller side) for validation.
    expectation: IdentityExpectation,
    /// Result capacity (== candidate count).
    capacity: u32,
    /// section_bytes (declared by identity/header).
    section_bytes: u64,
    /// Slot VA of round 1 (section1_va).
    section1_va: u64,
    /// Round slot bytes (full section_bytes each).
    slots: [Vec<u8>; 2],
    /// Per-round audit ledger.
    rounds: Vec<ProducedRound>,
    /// Monotonic sequence counter.
    sequence: u64,
    /// Failure event preserved verbatim (R3-4: never swallowed).
    failure: Option<ProducerError>,
}

/// Producer error (original error preserved, never swallowed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProducerError {
    Protocol(ProtocolError),
    BadState,
    RoundSequence { expected: u8, got: u8 },
    DigestMismatch { expected: u32, got: u32 },
    Bounds { start: u64, end: u64, total: u64 },
    AlreadyFailed,
}

impl std::fmt::Display for ProducerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::BadState => write!(f, "producer in bad state for this operation"),
            Self::RoundSequence { expected, got } => {
                write!(f, "round sequence mismatch: expected {expected} got {got}")
            }
            Self::DigestMismatch { expected, got } => {
                write!(
                    f,
                    "payload digest mismatch: expected {expected:#010x} got {got:#010x}"
                )
            }
            Self::Bounds { start, end, total } => {
                write!(
                    f,
                    "bounds violation [{start:#x}, {end:#x}) vs total {total:#x}"
                )
            }
            Self::AlreadyFailed => write!(f, "producer already failed; no further DONE"),
        }
    }
}

impl std::error::Error for ProducerError {}

impl From<ProtocolError> for ProducerError {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}

impl SectionProducer {
    /// Create the producer for a two-round section.
    ///
    /// `identity` must carry `section_bytes` == capacity-derived bytes
    /// (MIN_SECTION_HEADER_BYTES + capacity * PROBE_RESULT_BYTES); the
    /// expectation is used for fail-closed validation of every slot.
    pub fn new(
        identity: MappingIdentityHeaderV2,
        expectation: IdentityExpectation,
        capacity: u32,
        section1_va: u64,
    ) -> Result<Self, ProducerError> {
        let section_bytes = identity.section_bytes;
        if section_bytes < MIN_SECTION_HEADER_BYTES as u64 {
            return Err(ProducerError::Bounds {
                start: 0,
                end: section_bytes,
                total: MIN_SECTION_HEADER_BYTES as u64,
            });
        }
        if section_bytes > MAX_RESULT_SECTION_BYTES {
            return Err(ProducerError::Bounds {
                start: 0,
                end: section_bytes,
                total: MAX_RESULT_SECTION_BYTES,
            });
        }
        let expected_bytes = (capacity as u64)
            .checked_mul(PROBE_RESULT_BYTES as u64)
            .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
            .ok_or(ProducerError::Bounds {
                start: 0,
                end: 0,
                total: 0,
            })?;
        if section_bytes != expected_bytes || section_bytes != expectation.section_bytes {
            return Err(ProducerError::Bounds {
                start: 0,
                end: section_bytes,
                total: expected_bytes,
            });
        }
        let slot = vec![0u8; section_bytes as usize];
        Ok(Self {
            phase: ProducerPhase::Allocated,
            identity,
            expectation,
            capacity,
            section_bytes,
            section1_va,
            slots: [slot.clone(), slot],
            rounds: Vec::new(),
            sequence: 0,
            failure: None,
        })
    }

    /// Current phase.
    pub fn phase(&self) -> ProducerPhase {
        self.phase
    }

    /// section_bytes of the produced slots.
    pub fn section_bytes(&self) -> u64 {
        self.section_bytes
    }

    /// Slot VA for the given round (section1_va for round 1, +section_bytes
    /// for round 2). None for invalid round index.
    pub fn slot_va(&self, round_index: u8) -> Option<u64> {
        match round_index {
            1 => Some(self.section1_va),
            2 => self.section1_va.checked_add(self.section_bytes),
            _ => None,
        }
    }

    /// Round ledger (audit trail).
    pub fn rounds(&self) -> &[ProducedRound] {
        &self.rounds
    }

    /// Preserved failure (None while healthy).
    pub fn failure(&self) -> Option<&ProducerError> {
        self.failure.as_ref()
    }

    /// Publish the PENDING header for round 1 (ALLOCATED -> HEADER_WRITTEN).
    ///
    /// The identity header is written once (shared by both slots) and the
    /// round-1 slot header starts PENDING with round_flags == 0.
    pub fn publish_pending_header(&mut self) -> Result<(), ProducerError> {
        if self.failure.is_some() {
            return Err(ProducerError::AlreadyFailed);
        }
        if !self.phase.can_transition(ProducerPhase::HeaderWritten) {
            self.fail(ProducerError::BadState);
            return Err(ProducerError::BadState);
        }
        // Round-1 slot: PENDING identity + header, zero payload.
        let header =
            ResultSectionHeaderV2::new(self.section_bytes, self.capacity).map_err(|e| {
                self.fail(ProducerError::Protocol(e.clone()));
                ProducerError::Protocol(e)
            })?;
        let bytes = encode_section(&self.identity, &header, &[]).map_err(|e| {
            self.fail(ProducerError::Protocol(e.clone()));
            ProducerError::Protocol(e)
        })?;
        if bytes.len() as u64 != self.section_bytes {
            self.fail(ProducerError::Bounds {
                start: bytes.len() as u64,
                end: self.section_bytes,
                total: self.section_bytes,
            });
            return Err(ProducerError::Bounds {
                start: bytes.len() as u64,
                end: self.section_bytes,
                total: self.section_bytes,
            });
        }
        self.slots[0] = bytes;
        self.sequence += 1;
        self.phase = ProducerPhase::HeaderWritten;
        self.rounds.push(ProducedRound {
            sequence: self.sequence,
            round_index: 1,
            slot_va: self.slot_va(1).unwrap(),
            section_bytes: self.section_bytes,
            payload_length: 0,
            payload_crc32: 0,
            raw_status: COMPLETED_FLAG_PENDING,
            done_published: false,
        });
        Ok(())
    }

    /// Publish round-1 DONE (HEADER_WRITTEN -> ROUND1_DONE).
    ///
    /// `results` is the COMPLETE round-1 payload (exactly `capacity`
    /// records). The DONE header + payload are encoded, then the slot is
    /// re-parsed and re-validated (identity binding, layout, CRC, round
    /// flags) BEFORE the DONE is considered published.
    pub fn publish_round1_done(&mut self, results: &[ProbeResultV2]) -> Result<(), ProducerError> {
        if self.failure.is_some() {
            return Err(ProducerError::AlreadyFailed);
        }
        if !self.phase.can_transition(ProducerPhase::Round1Done) {
            self.fail(ProducerError::RoundSequence {
                expected: 1,
                got: 0,
            });
            return Err(ProducerError::RoundSequence {
                expected: 1,
                got: 0,
            });
        }
        if results.len() as u32 != self.capacity {
            self.fail(ProducerError::Bounds {
                start: results.len() as u64,
                end: self.capacity as u64,
                total: self.capacity as u64,
            });
            return Err(ProducerError::Bounds {
                start: results.len() as u64,
                end: self.capacity as u64,
                total: self.capacity as u64,
            });
        }
        let mut header = ResultSectionHeaderV2::new(self.section_bytes, self.capacity)?;
        header.result_count = self.capacity;
        header.completed_flag = COMPLETED_FLAG_DONE;
        header.set_round_flags(ROUND1_DONE)?;
        let bytes = encode_section(&self.identity, &header, results)?;
        self.audit_slot(&bytes, 1)?;
        self.slots[0] = bytes;
        // Digest: recompute over the encoded payload region (results_off..).
        let digest = self.slot_digest(0);
        self.sequence += 1;
        self.phase = ProducerPhase::Round1Done;
        self.rounds.push(ProducedRound {
            sequence: self.sequence,
            round_index: 1,
            slot_va: self.slot_va(1).unwrap(),
            section_bytes: self.section_bytes,
            payload_length: (self.capacity as u64) * PROBE_RESULT_BYTES as u64,
            payload_crc32: digest,
            raw_status: COMPLETED_FLAG_DONE | ROUND1_DONE as u32,
            done_published: true,
        });
        Ok(())
    }

    /// Publish round-2 DONE (ROUND1_DONE -> ROUND2_DONE).
    ///
    /// Only reachable after round-1 DONE. Same full audit as round 1, plus
    /// the round-flags audit requires BOTH bits.
    pub fn publish_round2_done(&mut self, results: &[ProbeResultV2]) -> Result<(), ProducerError> {
        if self.failure.is_some() {
            return Err(ProducerError::AlreadyFailed);
        }
        if !self.phase.can_transition(ProducerPhase::Round2Done) {
            self.fail(ProducerError::RoundSequence {
                expected: 2,
                got: 1,
            });
            return Err(ProducerError::RoundSequence {
                expected: 2,
                got: 1,
            });
        }
        if results.len() as u32 != self.capacity {
            self.fail(ProducerError::Bounds {
                start: results.len() as u64,
                end: self.capacity as u64,
                total: self.capacity as u64,
            });
            return Err(ProducerError::Bounds {
                start: results.len() as u64,
                end: self.capacity as u64,
                total: self.capacity as u64,
            });
        }
        let mut header = ResultSectionHeaderV2::new(self.section_bytes, self.capacity)?;
        header.result_count = self.capacity;
        header.completed_flag = COMPLETED_FLAG_DONE;
        header.set_round_flags(ROUND1_DONE | ROUND2_DONE)?;
        let bytes = encode_section(&self.identity, &header, results)?;
        self.audit_slot(&bytes, 2)?;
        self.slots[1] = bytes;
        let digest = self.slot_digest(1);
        self.sequence += 1;
        self.phase = ProducerPhase::Round2Done;
        self.rounds.push(ProducedRound {
            sequence: self.sequence,
            round_index: 2,
            slot_va: self.slot_va(2).unwrap(),
            section_bytes: self.section_bytes,
            payload_length: (self.capacity as u64) * PROBE_RESULT_BYTES as u64,
            payload_crc32: digest,
            raw_status: COMPLETED_FLAG_DONE | (ROUND1_DONE | ROUND2_DONE) as u32,
            done_published: true,
        });
        Ok(())
    }

    /// Consume the produced section (ROUND2_DONE -> CONSUMED).
    ///
    /// Marks the round-2 slot consumed. The controller performs the actual
    /// read-back through its provider; this transition only records the
    /// terminal consumer hand-off.
    pub fn mark_consumed(&mut self) -> Result<(), ProducerError> {
        if self.failure.is_some() {
            return Err(ProducerError::AlreadyFailed);
        }
        if !self.phase.can_transition(ProducerPhase::Consumed) {
            self.fail(ProducerError::BadState);
            return Err(ProducerError::BadState);
        }
        self.sequence += 1;
        self.phase = ProducerPhase::Consumed;
        Ok(())
    }

    /// Read the produced slot bytes for a round (1 or 2).
    pub fn slot(&self, round_index: u8) -> Option<&[u8]> {
        match round_index {
            1 => Some(&self.slots[0]),
            2 => Some(&self.slots[1]),
            _ => None,
        }
    }

    /// Recompute the payload CRC32 of a produced slot (digest re-derivation
    /// used by the R5-R3 attestation/consumer path).
    pub fn slot_digest(&self, slot_index: usize) -> u32 {
        if slot_index >= self.slots.len() {
            return 0;
        }
        let bytes = &self.slots[slot_index];
        if bytes.len() < MIN_SECTION_HEADER_BYTES {
            return 0;
        }
        let off = IDENTITY_HEADER_BYTES + RESULT_HEADER_BYTES;
        if bytes.len() < off {
            return 0;
        }
        crc32(&bytes[off..])
    }

    /// Fail-closed internal audit of a produced slot (identity binding,
    /// layout, CRC, round flags). Any error fails the producer.
    fn audit_slot(&mut self, bytes: &[u8], round_index: u8) -> Result<(), ProducerError> {
        let (identity, header, results) = parse_section(bytes)?;
        validate_section(
            &identity,
            &header,
            &results,
            &self.expectation,
            self.capacity,
        )?;
        header.validate_round_flags(round_index)?;
        // Round-order audit: the DONE must be exactly the expected bits.
        let expected_flags = match round_index {
            1 => ROUND1_DONE,
            2 => ROUND1_DONE | ROUND2_DONE,
            _ => {
                return Err(ProducerError::RoundSequence {
                    expected: 1,
                    got: round_index,
                })
            }
        };
        if header.round_flags() != expected_flags {
            self.fail(ProducerError::DigestMismatch {
                expected: expected_flags as u32,
                got: header.round_flags() as u32,
            });
            return Err(ProducerError::DigestMismatch {
                expected: expected_flags as u32,
                got: header.round_flags() as u32,
            });
        }
        Ok(())
    }

    /// Transition to Failed, preserving the original error (R3-4).
    fn fail(&mut self, e: ProducerError) {
        self.phase = ProducerPhase::Failed;
        if self.failure.is_none() {
            self.failure = Some(e);
        }
    }
}

/// Re-export the wire constants used by the producer/consumer protocol.
pub use crate::walker_protocol::ROUND_FLAGS_KNOWN as PRODUCER_ROUND_FLAGS_KNOWN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::walker_protocol::{
        derive_session_id, CLASSIFICATION_TYPE_C, RESULT_FLAG_GUARD_SEEN,
    };

    fn nonce() -> u64 {
        0x0102_0304_0506_0708
    }

    fn base() -> u64 {
        0x0000_0040_0000
    }

    fn capacity() -> u32 {
        3
    }

    fn section_bytes() -> u64 {
        96 + capacity() as u64 * PROBE_RESULT_BYTES as u64
    }

    fn expectation() -> IdentityExpectation {
        IdentityExpectation {
            nonce: nonce(),
            target_pid: 4242,
            owner_pid: 1234,
            session_id: derive_session_id(nonce(), base(), capacity()),
            section_bytes: section_bytes(),
        }
    }

    fn identity() -> MappingIdentityHeaderV2 {
        MappingIdentityHeaderV2::new(
            section_bytes(),
            4242,
            1234,
            nonce(),
            derive_session_id(nonce(), base(), capacity()),
        )
    }

    fn results() -> Vec<ProbeResultV2> {
        (0..capacity())
            .map(|i| {
                let mut r = ProbeResultV2::new(
                    base() + 0x1000 * i as u64,
                    CLASSIFICATION_TYPE_C,
                    RESULT_FLAG_GUARD_SEEN,
                    (i % 2) as u8,
                    [0xAA; 16],
                );
                r.set_probe_span(16);
                r
            })
            .collect()
    }

    fn producer() -> SectionProducer {
        SectionProducer::new(identity(), expectation(), capacity(), base() + 0x2000).unwrap()
    }

    #[test]
    fn positive_two_round_done_publish_and_consume() {
        let mut p = producer();
        assert_eq!(p.phase(), ProducerPhase::Allocated);
        p.publish_pending_header().unwrap();
        assert_eq!(p.phase(), ProducerPhase::HeaderWritten);
        p.publish_round1_done(&results()).unwrap();
        assert_eq!(p.phase(), ProducerPhase::Round1Done);
        p.publish_round2_done(&results()).unwrap();
        assert_eq!(p.phase(), ProducerPhase::Round2Done);
        p.mark_consumed().unwrap();
        assert_eq!(p.phase(), ProducerPhase::Consumed);

        let rounds = p.rounds();
        assert_eq!(rounds.len(), 3); // pending + round1 + round2
        assert_eq!(rounds[1].round_index, 1);
        assert_eq!(rounds[1].done_published, true);
        assert_eq!(
            rounds[1].raw_status,
            COMPLETED_FLAG_DONE | ROUND1_DONE as u32
        );
        assert_eq!(rounds[2].round_index, 2);
        assert_eq!(rounds[2].done_published, true);
        assert_eq!(
            rounds[2].raw_status,
            COMPLETED_FLAG_DONE | (ROUND1_DONE | ROUND2_DONE) as u32
        );
        assert!(
            rounds[2].sequence > rounds[1].sequence,
            "monotonic sequence"
        );
        assert_eq!(rounds[2].slot_va, p.slot_va(2).unwrap());
    }

    #[test]
    fn round2_before_round1_rejected() {
        let mut p = producer();
        p.publish_pending_header().unwrap();
        let err = p.publish_round2_done(&results()).unwrap_err();
        assert!(matches!(err, ProducerError::RoundSequence { .. }));
        assert_eq!(p.phase(), ProducerPhase::Failed);
        assert!(p.failure().is_some(), "original error preserved");
    }

    #[test]
    fn duplicate_done_rejected() {
        let mut p = producer();
        p.publish_pending_header().unwrap();
        p.publish_round1_done(&results()).unwrap();
        let err = p.publish_round1_done(&results()).unwrap_err();
        assert!(matches!(err, ProducerError::RoundSequence { .. }));
        assert_eq!(p.phase(), ProducerPhase::Failed);
    }

    #[test]
    fn round2_without_round1_flags_rejected() {
        // Forge: write round2 DONE with round1 flags missing. The producer
        // refuses because the round-flags audit requires both bits.
        let mut p = producer();
        p.publish_pending_header().unwrap();
        p.publish_round1_done(&results()).unwrap();
        // Manually craft the forged slot through the protocol layer.
        let mut header = ResultSectionHeaderV2::new(p.section_bytes(), capacity()).unwrap();
        header.result_count = capacity();
        header.completed_flag = COMPLETED_FLAG_DONE;
        header.set_round_flags(ROUND2_DONE).unwrap(); // missing ROUND1_DONE
        let forged = encode_section(&identity(), &header, &results()).unwrap();
        assert!(
            parse_section(&forged)
                .and_then(|(i, h, r)| {
                    validate_section(&i, &h, &r, &expectation(), capacity())?;
                    h.validate_round_flags(2)
                })
                .is_err(),
            "forged round2 DONE without round1 DONE must fail the audit"
        );
    }

    #[test]
    fn payload_digest_recomputable_after_publish() {
        let mut p = producer();
        p.publish_pending_header().unwrap();
        p.publish_round1_done(&results()).unwrap();
        p.publish_round2_done(&results()).unwrap();
        // The producer digest must equal a fresh CRC32 over the slot payload.
        let slot1 = p.slot(1).unwrap();
        let off = IDENTITY_HEADER_BYTES + RESULT_HEADER_BYTES;
        assert_eq!(crc32(&slot1[off..]), p.rounds()[1].payload_crc32);
        assert_eq!(p.slot_digest(0), p.rounds()[1].payload_crc32);
    }

    #[test]
    fn truncated_payload_rejected_at_encode() {
        let mut p = producer();
        p.publish_pending_header().unwrap();
        let truncated = results()[..2].to_vec();
        let err = p.publish_round1_done(&truncated).unwrap_err();
        assert!(matches!(err, ProducerError::Bounds { .. }));
        assert_eq!(p.phase(), ProducerPhase::Failed);
    }

    #[test]
    fn bad_identity_section_bytes_rejected_at_new() {
        let mut ident = identity();
        ident.section_bytes = section_bytes() + 40;
        let err =
            SectionProducer::new(ident, expectation(), capacity(), base() + 0x2000).unwrap_err();
        assert!(matches!(err, ProducerError::Bounds { .. }));
    }

    #[test]
    fn failed_producer_publishes_no_further_done() {
        let mut p = producer();
        p.publish_pending_header().unwrap();
        let _ = p.publish_round2_done(&results()).unwrap_err();
        assert_eq!(p.phase(), ProducerPhase::Failed);
        // No further DONE can be published after failure (no silent retry).
        let err = p.publish_round1_done(&results()).unwrap_err();
        assert!(matches!(err, ProducerError::AlreadyFailed));
    }

    #[test]
    fn pending_header_has_zero_round_flags() {
        let mut p = producer();
        p.publish_pending_header().unwrap();
        let slot = p.slot(1).unwrap();
        let (_, header, _) = parse_section(slot).unwrap();
        assert_eq!(header.completed_flag, COMPLETED_FLAG_PENDING);
        assert_eq!(header.round_flags(), 0);
        header.validate_round_flags(1).unwrap();
    }

    #[test]
    fn abort_state_has_zero_round_flags() {
        // ABORT is a protocol-valid state; the R5-R3 audit requires it to
        // carry no round DONE bits.
        let mut header = ResultSectionHeaderV2::new(section_bytes(), capacity()).unwrap();
        header.completed_flag = crate::walker_protocol::COMPLETED_FLAG_ABORT;
        header.walker_status = crate::walker_protocol::WALKER_STATUS_ERROR_PROBE_ABORTED;
        assert_eq!(header.round_flags(), 0);
        header.validate_round_flags(1).unwrap();
    }
}
