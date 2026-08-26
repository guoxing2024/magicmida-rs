# IMP-09-CARRIER-R5-R3 - Section Producer / Consumer Design & Protocol Spec

Work order: WORK_ORDER_IMP-09-CARRIER-R5-R3-SECTION-PRODUCER_20260825.md
Dispatch: WORK_ORDER_IMP-09-R5-R3-DISPATCH_20260825.md
Branch: codex/imp09-carrier-r5-r2
Baseline HEAD: affb992f2b30b2c9f8243c72296456b5515f6e86
Status: offline_mock=true / live_authorized=false / protected_sample=NOT_AUTHORIZED
Date: 2026-08-25

---

## 1. Protocol extension (round-1 / round-2 dual DONE fields)

The existing ResultSectionHeaderV2 has no round-1/round-2 dual DONE fields.
Per dispatch section 0.3 the protocol is EXTENDED: PROTOCOL_VERSION is
UNCHANGED; the free reserved u16 slot in the result header
(offset 0x06..0x08) carries the round-flags word.

| Constant | Value | Meaning |
|---|---|---|
| ROUND_FLAGS_KNOWN | 0x0003 | known-bit mask for this field (1 | 2) |
| ROUND1_DONE | 0x0001 | round-1 DONE published |
| ROUND2_DONE | 0x0002 | round-2 DONE published |
| RESULT_HEADER_ROUND_FLAGS_OFF | 0x06 | byte offset of round-flags in result header |

- Frozen semantics unchanged: validate_layout() does NOT check the
  round-flags field, so frozen R5-R2 validators always pass on the reserved
  slot (identical behaviour to before).
- Round-2 DONE requires BOTH bits (ROUND1_DONE|ROUND2_DONE), so forging
  round-2 without round-1 is impossible at the protocol layer.
- PENDING / ABORT states carry round-flags == 0.
- New APIs: set_round_flags(u16), round_flags() -> u16,
  validate_round_flags(round_index: u8).

## 2. State transition table (R3-1)

### Producer (walker_producer.rs - ProducerPhase)

```
ALLOCATED -> HEADER_WRITTEN -> ROUND1_DONE -> ROUND2_DONE -> CONSUMED
```

| From | Event | To | Guards (all must hold) |
|---|---|---|---|
| Allocated | new(identity, expectation, capacity, section1_va) | HeaderWritten | identity/expectation consistent; capacity <= 4096; exact section bytes |
| HeaderWritten | publish_pending_header() | HeaderWritten (write header + guard region) | PENDING header; payload all-zero; round-flags=0 |
| HeaderWritten | publish_round1_done(results) | Round1Done | internal audit_slot: identity/validate_section/round-flags==ROUND1_DONE/CRC recomputable |
| Round1Done | publish_round2_done(results) | Round2Done | audit_slot: round-flags==ROUND1_DONE|ROUND2_DONE; monotonic sequence |
| Round1Done | publish_round1_done again (duplicate) | Failed (terminal) | duplicate DONE never counts as a new round |
| Round2Done | mark_consumed() | Consumed | only after consumer success |
| any | any write/validate failure | Failed (terminal) | no DONE published, no READY published |

Forbidden: PENDING -> CONSUMED; skipping round-1; duplicate DONE as success;
any Failed state continuing to publish.

Every state change records (ProducedRound ledger): monotonic sequence, round
id, section VA, payload length, payload CRC32, raw status, done_published.

### Consumer (walker_consumer.rs)

```
round1 slot verify -> round2 slot verify -> order audit -> V2 attestation digest verify -> Pass
```

| Step | Check | Failure -> |
|---|---|---|
| 1 | section bounds (section1_va + section_bytes overflow; provider read) | ConsumerFailure::Io / OutputTruncated |
| 2 | round-1 slot: identity + layout + CRC + DONE + round-flags==ROUND1_DONE + count + raw status==OK | Protocol / CompletedFlag / RoundFlags / CountMismatch / RawStatus |
| 3 | round-2 slot: same, round-flags==ROUND1_DONE|ROUND2_DONE | same |
| 4 | order: round1.sequence < round2.sequence | OutputOutOfOrder |
| 5 | attestation present; schema==v2; walker_attestation present | OutputMissing / NotV2 / NoWalkerAttestation |
| 6 | RuntimeAttestationV2::validate() (nested walker digest + top-level digest) | Attestation(..) |
| 7 | compute_digest() explicit compare vs record_digest | DigestMismatch |

## 3. Production caller graph (real call sites)

```
SectionProducer::new / publish_pending_header / publish_round1_done / publish_round2_done
  -> encode_section            (walker_protocol.rs)   [production write point]
  -> parse_section             (walker_protocol.rs)   [internal audit]
  -> validate_section          (walker_protocol.rs)   [internal audit]
  -> header.validate_round_flags (walker_protocol.rs)
  -> crc32                     (walker_protocol.rs)   [digest recompute]

WalkerDriver::consume_production_output (walker_control.rs)   [production consume point]
  -> walker_consumer::consume_produced_sections
      -> verify_round_slot (per round)   [DONE + flags + digest audit]
      -> verify_v2_attestation_digest    [V2 digest closure]
          -> RuntimeAttestationV2::validate() / compute_digest (attestation.rs)
  -> success -> session.transition(Completed)
  -> failure -> fail_abort(Consumer(e))  [original error kept; ABORTED terminal]

AntidebugController::verify_walker_output_v2 (crates/cli/.../antidebug_controller.rs)
  -> RuntimeAttestationV2::to_canonical_json
  -> walker_consumer::verify_v2_attestation_digest   [CLI consumption closure]
  -> failure -> AntidebugOutcome::Failed + output_verify_fail event (no Proceed)
```

## 4. Production code file list (exact modifications of this work order)

| File | Change |
|---|---|
| crates/antidebug-runtime/src/walker_protocol.rs | round-flags extension (constants + methods) |
| crates/antidebug-runtime/src/walker_producer.rs | NEW: production section producer (R3-2) |
| crates/antidebug-runtime/src/walker_consumer.rs | NEW: production consumer (R3-3) |
| crates/antidebug-runtime/src/walker_control.rs | WalkerDriver::consume_production_output, verify_walker_output_v2, WalkerControlError::Consumer |
| crates/antidebug-runtime/src/lib.rs | module exports |
| crates/cli/src/unpacker/antidebug_controller.rs | R5-R3 CLI consumer gate (V2 digest after execute Success) |

NOT modified: runner_preflight.rs; R5-R2 lifecycle window order; mapping
proof / envelope / liveness / execute gates; VirtualFreeEx/GetLastError
teardown; no live dispatch; no CreateRemoteThread; no silent retry.

## 5. Test inventory (section 4.4 coverage)

Positive (1 group): positive_two_round_done_publish_and_consume (producer
dual DONE + consumer full loop digest MATCH), consumer_pass_full_loop_with_digest_match,
imp09_r5r3_ok_bridge_passes_v2_digest_gate_and_reaches_proceed (CLI closure).

Negative (>=9):
1. consumer_pending_direct_consume_fails - PENDING direct consume;
2. round2_before_round1_rejected / consumer_round2_before_round1_flags_fails - round2 before round1;
3. duplicate_done_rejected / consumer_duplicate_output_fails - duplicate DONE;
4. truncated_payload_rejected_at_encode / consumer_truncated_output_fails - truncated output;
5. consumer_digest_mismatch_fails / consumer_attestation_digest_tamper_fails - digest mismatch;
6. consumer_non_ok_raw_status_fails - non-OK raw status;
7. consumer_output_missing_fails - output missing;
8. bad_identity_section_bytes_rejected_at_new - section bounds violation;
9. failed_producer_publishes_no_further_done - failure stops publishing (rollback);
10. imp09_r5r3_output_tampered_digest_blocks_proceed /
    imp09_r5r3_output_missing_walker_attestation_blocks_proceed - CLI negative gates.

## 6. Rollback (R3-4)

- Producer/consumer failure -> no READY / no Proceed (CLI returns
  AntidebugOutcome::Failed);
- Original error preserved: ConsumerFailure / WalkerControlError::Consumer(e)
  forwarded in Display;
- Failure event sequence + raw status kept: output_verify_fail event,
  execute_exit raw status;
- Existing R5-R2 allocations released transactionally by WalkerSessionMemory
  Drop;
- No silent retry (no retry loop anywhere).
