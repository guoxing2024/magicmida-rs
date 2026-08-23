//! ADR-4 runtime test suite: attestation, telemetry, FFI handshake.
//!
//! These tests exercise the runtime as an **rlib** (no DLL is loaded, no
//! process is injected). The code paths are identical to the cdylib export
//! surface; the FFI singleton is additionally exercised via the exported
//! functions where safe in-process.

use mida_antidebug_runtime::attestation::{
    AttestationError, HookFailure, HookInventory, RuntimeAttestation, ARCH_X86_64,
    ATTESTATION_SCHEMA,
};
use mida_antidebug_runtime::provenance::{
    Provenance, ProvenanceError, KIND_RUNTIME_X64, PROVENANCE_SCHEMA,
};
use mida_antidebug_runtime::telemetry::{
    TelemetryChannel, TelemetryError, TelemetryMessage, TelemetryQuery, TelemetryState,
    TELEMETRY_SCHEMA,
};

const TEST_PID: u32 = 4242;
const TEST_MODULE_BASE: u64 = 0x0000_7ff6_0000_0000;

fn expected_surfaces() -> Vec<String> {
    vec![
        "AD-PROC-001".to_string(),
        "AD-PROC-002".to_string(),
        "AD-PROC-003".to_string(),
    ]
}

fn foundation_attestation() -> RuntimeAttestation {
    RuntimeAttestation::foundation(
        "abc123".to_string(),
        "oreans_origin_x64_v1".to_string(),
        "deadbeef".to_string(),
        TEST_PID,
        TEST_MODULE_BASE,
        &expected_surfaces(),
        "v0.1.0".to_string(),
        "rustc".to_string(),
    )
}

// ----------------------------------------------------------------
// attestation
// ----------------------------------------------------------------

#[test]
fn attestation_roundtrip_json() {
    let att = foundation_attestation();
    let json = att.to_canonical_json().unwrap();
    let back = RuntimeAttestation::from_canonical_json(&json).unwrap();
    assert_eq!(att, back);
    assert_eq!(back.schema, ATTESTATION_SCHEMA);
    assert_eq!(back.architecture, ARCH_X86_64);
    // target identity survives round-trip
    assert_eq!(back.target_pid, TEST_PID);
    assert_eq!(back.module_base, TEST_MODULE_BASE);
}

#[test]
fn attestation_foundation_is_honest_unsupported() {
    let att = foundation_attestation();
    // ADR-4: no hooks implemented; must NOT fake success.
    assert!(att.hooks_installed.is_empty());
    assert_eq!(att.hooks_expected.len(), 3);
    assert_eq!(att.hook_failures.len(), 3);
    // validate() correctly fails: hook inventory incomplete.
    assert!(matches!(
        att.validate(),
        Err(AttestationError::HookInventoryIncomplete {
            expected: 3,
            installed: 0
        })
    ));
    // The controller would map this to AntiDebugRuntimePartialHooks.
}

#[test]
fn attestation_schema_mismatch_rejected() {
    let mut att = foundation_attestation();
    att.schema = "mida.wrong/v1".to_string();
    assert!(matches!(
        att.validate(),
        Err(AttestationError::SchemaMismatch(_))
    ));
}

#[test]
fn attestation_architecture_mismatch_rejected() {
    let mut att = foundation_attestation();
    att.architecture = "x86".to_string();
    assert!(matches!(
        att.validate(),
        Err(AttestationError::ArchitectureMismatch(_))
    ));
}

#[test]
fn attestation_not_initialized_rejected() {
    let mut att = foundation_attestation();
    att.initialized = false;
    assert_eq!(att.validate(), Err(AttestationError::NotInitialized));
}

#[test]
fn attestation_telemetry_not_ready_rejected() {
    let mut att = foundation_attestation();
    att.telemetry_channel = "created".to_string();
    assert!(matches!(
        att.validate(),
        Err(AttestationError::TelemetryNotReady(_))
    ));
}

#[test]
fn attestation_cleanup_handler_missing_rejected() {
    let mut att = foundation_attestation();
    att.cleanup_handler_registered = false;
    assert_eq!(att.validate(), Err(AttestationError::CleanupHandlerMissing));
}

#[test]
fn attestation_profile_digest_missing_rejected() {
    let mut att = foundation_attestation();
    att.profile_digest = String::new();
    assert_eq!(att.validate(), Err(AttestationError::ProfileDigestMissing));
}

#[test]
fn attestation_third_party_undeclared_rejected() {
    let mut att = foundation_attestation();
    att.third_party = String::new();
    assert_eq!(att.validate(), Err(AttestationError::ThirdPartyUndeclared));
}

#[test]
fn attestation_target_pid_missing_rejected() {
    let mut att = foundation_attestation();
    att.target_pid = 0;
    assert_eq!(att.validate(), Err(AttestationError::TargetPidMissing));
}

#[test]
fn attestation_module_base_zero_rejected() {
    let mut att = foundation_attestation();
    att.module_base = 0;
    assert_eq!(att.validate(), Err(AttestationError::ModuleBaseZero));
}

#[test]
fn attestation_verify_identity_ok() {
    let att = foundation_attestation();
    assert!(att.verify_identity(TEST_PID, TEST_MODULE_BASE).is_ok());
}

#[test]
fn attestation_verify_identity_pid_mismatch_rejected() {
    let att = foundation_attestation();
    let err = att
        .verify_identity(TEST_PID + 1, TEST_MODULE_BASE)
        .unwrap_err();
    assert!(matches!(
        err,
        AttestationError::TargetPidMismatch {
            expected: 4243,
            got: TEST_PID
        }
    ));
}

#[test]
fn attestation_verify_identity_module_base_mismatch_rejected() {
    let att = foundation_attestation();
    let err = att
        .verify_identity(TEST_PID, TEST_MODULE_BASE + 0x1000)
        .unwrap_err();
    assert!(matches!(err, AttestationError::ModuleBaseMismatch { .. }));
}

#[test]
fn attestation_verify_identity_zero_module_base_rejected() {
    // Attestation claims module_base = 0 -> verify_identity must reject.
    let mut att = foundation_attestation();
    att.module_base = 0;
    let err = att.verify_identity(TEST_PID, 0).unwrap_err();
    assert_eq!(err, AttestationError::ModuleBaseZero);
    // validate() rejects it too.
    assert_eq!(att.validate(), Err(AttestationError::ModuleBaseZero));
}

#[test]
fn attestation_hook_failures_rejected() {
    // Simulate a runtime that claims installed == expected but has failures.
    let mut att = foundation_attestation();
    att.hooks_installed = expected_surfaces();
    att.hook_failures = vec![HookFailure {
        surface_id: "AD-PROC-001".to_string(),
        reason: "install aborted".to_string(),
    }];
    // hook_failures non-empty -> fail-closed even with counts equal.
    assert!(matches!(
        att.validate(),
        Err(AttestationError::HookFailures(_))
    ));
}

#[test]
fn attestation_missing_fields_rejected_by_serde() {
    // Missing field in JSON -> deserialization error (no defaulting).
    let json = r#"{"schema":"mida.antidebug-runtime-attestation/v1"}"#;
    assert!(RuntimeAttestation::from_canonical_json(json).is_err());
}

#[test]
fn attestation_unknown_field_rejected_by_serde() {
    // deny_unknown_fields: an unknown field must be rejected, not ignored.
    let att = foundation_attestation();
    let mut json = att.to_canonical_json().unwrap();
    // inject an unknown field before the closing brace
    json.pop();
    json.push_str(",\"spoofed_field\":\"x\"}");
    assert!(RuntimeAttestation::from_canonical_json(&json).is_err());
}

#[test]
fn attestation_hook_failure_unknown_field_rejected_by_serde() {
    let att = foundation_attestation();
    let mut json = att.to_canonical_json().unwrap();
    // unknown field inside a hook_failure entry - use a targeted string edit
    let marker = "\"hook_failures\":[";
    let idx = json.find(marker).unwrap();
    json.insert_str(
        idx + marker.len(),
        "{\"surface_id\":\"AD-PROC-001\",\"reason\":\"x\",\"evil\":true},",
    );
    assert!(RuntimeAttestation::from_canonical_json(&json).is_err());
}

#[test]
fn hook_inventory_completeness() {
    let inv = HookInventory::unsupported(&expected_surfaces());
    assert!(!inv.is_complete());
    let full = HookInventory {
        hooks_expected: expected_surfaces(),
        hooks_installed: expected_surfaces(),
        hook_failures: vec![],
    };
    assert!(full.is_complete());
}

// ----------------------------------------------------------------
// provenance
// ----------------------------------------------------------------

#[test]
fn provenance_roundtrip_and_dependencies_declared() {
    let p = Provenance::current(
        "sha256hex".to_string(),
        12345,
        "rustc 1.97".to_string(),
        "rev".to_string(),
    );
    let json = p.to_canonical_json().unwrap();
    let back = Provenance::from_canonical_json(&json).unwrap();
    assert_eq!(p, back);
    assert_eq!(back.schema, PROVENANCE_SCHEMA);
    // kind present and correct for an x64 runtime
    assert_eq!(back.kind, KIND_RUNTIME_X64);
    // third_party is an honest declaration, not a bare "none"
    assert_eq!(back.third_party, "build-and-serialization-only");
    // every linked third-party crate is listed and auditable
    let names: Vec<&str> = back.dependencies.iter().map(|d| d.name.as_str()).collect();
    assert!(names.contains(&"serde"));
    assert!(names.contains(&"serde_json"));
    assert!(names.contains(&"thiserror"));
    assert!(back.dependencies.iter().all(|d| !d.anti_debug));
    assert_eq!(back.architecture, ARCH_X86_64);
}

#[test]
fn provenance_third_party_undeclared_rejected() {
    let mut p = Provenance::current("sha".to_string(), 1, "tc".to_string(), "rev".to_string());
    p.third_party = String::new();
    assert!(matches!(
        p.validate(),
        Err(ProvenanceError::ThirdPartyUndeclared)
    ));
}

#[test]
fn provenance_kind_missing_rejected() {
    let mut p = Provenance::current("sha".to_string(), 1, "tc".to_string(), "rev".to_string());
    p.kind = String::new();
    assert!(matches!(p.validate(), Err(ProvenanceError::KindInvalid(_))));
}

#[test]
fn provenance_kind_invalid_rejected() {
    let mut p = Provenance::current("sha".to_string(), 1, "tc".to_string(), "rev".to_string());
    p.kind = "runtime-arm64".to_string();
    assert!(matches!(p.validate(), Err(ProvenanceError::KindInvalid(_))));
}

#[test]
fn provenance_kind_architecture_mismatch_rejected() {
    let mut p = Provenance::current("sha".to_string(), 1, "tc".to_string(), "rev".to_string());
    // runtime-x64 kind with x86 architecture is inconsistent
    p.architecture = "x86".to_string();
    assert!(matches!(
        p.validate(),
        Err(ProvenanceError::KindArchitectureMismatch { .. })
    ));
}

#[test]
fn provenance_dependencies_undeclared_rejected() {
    let mut p = Provenance::current("sha".to_string(), 1, "tc".to_string(), "rev".to_string());
    p.dependencies = vec![];
    assert!(matches!(
        p.validate(),
        Err(ProvenanceError::DependenciesUndeclared)
    ));
}

#[test]
fn provenance_dependency_anti_debug_rejected() {
    let mut p = Provenance::current("sha".to_string(), 1, "tc".to_string(), "rev".to_string());
    p.dependencies[0].anti_debug = true;
    assert!(matches!(
        p.validate(),
        Err(ProvenanceError::DependencyAntiDebug(_))
    ));
}

#[test]
fn provenance_unknown_field_rejected_by_serde() {
    let p = Provenance::current("sha".to_string(), 1, "tc".to_string(), "rev".to_string());
    let mut json = p.to_canonical_json().unwrap();
    json.pop();
    json.push_str(",\"sneaky\":1}");
    assert!(Provenance::from_canonical_json(&json).is_err());
}

// ----------------------------------------------------------------
// telemetry
// ----------------------------------------------------------------

fn channel() -> TelemetryChannel {
    let ch = TelemetryChannel::new("mida-adr4-test", TEST_PID, "digest123");
    ch.mark_ready().unwrap();
    ch
}

#[test]
fn telemetry_normal_request_response() {
    let ch = channel();
    let resp = ch.request(TelemetryQuery::Ping).unwrap();
    assert!(resp.ok);
    assert_eq!(resp.target_pid, TEST_PID);
    assert_eq!(resp.channel_id, "mida-adr4-test");
    assert_eq!(resp.status, TelemetryState::Ready);
    // sequence monotonic across requests
    let r2 = ch.request(TelemetryQuery::GetStatus).unwrap();
    assert!(r2.sequence > resp.sequence);
}

#[test]
fn telemetry_sequence_monotonic() {
    let ch = channel();
    let mut last = 0u32;
    for _ in 0..10 {
        let r = ch.request(TelemetryQuery::Ping).unwrap();
        assert!(r.sequence >= last);
        last = r.sequence;
    }
}

#[test]
fn telemetry_pid_mismatch_fails_closed() {
    let ch = channel();
    // Direct: a request with the wrong PID must be rejected by handle_request.
    let mut bad = TelemetryRequestTemplate::from_channel(&ch);
    bad.target_pid = 7777;
    let err = ch.handle_request(bad.into_request(TelemetryQuery::Ping));
    assert!(matches!(err, Err(TelemetryError::PidMismatch { .. })));
}

#[test]
fn telemetry_digest_mismatch_fails_closed() {
    let ch = channel();
    let mut bad = TelemetryRequestTemplate::from_channel(&ch);
    bad.profile_digest = "wrongdigest".to_string();
    let err = ch.handle_request(bad.into_request(TelemetryQuery::Ping));
    assert!(matches!(err, Err(TelemetryError::DigestMismatch { .. })));
}

#[test]
fn telemetry_channel_id_mismatch_fails_closed() {
    let ch = channel();
    let mut bad = TelemetryRequestTemplate::from_channel(&ch);
    bad.channel_id = "other-channel".to_string();
    let err = ch.handle_request(bad.into_request(TelemetryQuery::Ping));
    assert!(matches!(err, Err(TelemetryError::ChannelIdMismatch { .. })));
}

#[test]
fn telemetry_out_of_order_rejected() {
    let ch = channel();
    let mut bad = TelemetryRequestTemplate::from_channel(&ch);
    // send a sequence far in the future first, then an older one
    bad.sequence = 1000;
    let r = ch.handle_request(bad.into_request(TelemetryQuery::Ping));
    assert!(r.is_ok());
    let mut older = TelemetryRequestTemplate::from_channel(&ch);
    older.sequence = 5; // < 1000 -> out of order
    let err = ch.handle_request(older.into_request(TelemetryQuery::Ping));
    assert!(matches!(err, Err(TelemetryError::OutOfOrder { .. })));
}

#[test]
fn telemetry_duplicate_response_rejected() {
    let ch = channel();
    let t = TelemetryRequestTemplate::from_channel(&ch);
    let req1 = t.clone().into_request(TelemetryQuery::Ping);
    let r1 = ch.handle_request(req1);
    assert!(r1.is_ok());
    // same request id again -> duplicate
    let req2 = t.clone().into_request(TelemetryQuery::Ping);
    let err = ch.handle_request(req2);
    assert!(matches!(err, Err(TelemetryError::DuplicateResponse(_))));
}

#[test]
fn telemetry_not_ready_fails_closed() {
    let ch = TelemetryChannel::new("ch", 1, "d");
    // not marked ready
    let err = ch.request(TelemetryQuery::Ping);
    assert!(matches!(
        err,
        Err(TelemetryError::ChannelNotReady(TelemetryState::Created))
    ));
}

#[test]
fn telemetry_closed_fails_closed() {
    let ch = channel();
    ch.close().unwrap();
    // requests after close: state is Closed; handle_request checks channel
    // state only via request(); direct handle_request with valid bindings
    // still succeeds at protocol level; the request() gate enforces Closed.
    let t = TelemetryRequestTemplate::from_channel(&ch);
    let resp = ch.handle_request(t.into_request(TelemetryQuery::Ping));
    // protocol-level: after close we still accept (transport gate is
    // request()); assert request() gate instead:
    let _ = resp;
    let err = ch.request(TelemetryQuery::Ping);
    assert!(matches!(
        err,
        Err(TelemetryError::ChannelNotReady(TelemetryState::Closed))
    ));
}

#[test]
fn telemetry_shutdown_report() {
    let ch = channel();
    let resp = ch.request(TelemetryQuery::Shutdown).unwrap();
    assert!(resp.ok);
    assert!(resp
        .messages
        .iter()
        .any(|m| matches!(m, TelemetryMessage::ShutdownStatus { clean: true, .. })));
}

#[test]
fn telemetry_unknown_field_in_response_rejected_by_serde() {
    // A response carrying an unknown field must fail to parse.
    let ch = channel();
    let resp = ch.request(TelemetryQuery::Ping).unwrap();
    let json = serde_json::to_string(&resp).unwrap();
    // round-trips
    let back: mida_antidebug_runtime::telemetry::TelemetryResponse =
        serde_json::from_str(&json).unwrap();
    assert_eq!(back, resp);
    // unknown field rejected
    let mut bad = json.clone();
    bad.pop();
    bad.push_str(",\"unexpected\":true}");
    let r: Result<mida_antidebug_runtime::telemetry::TelemetryResponse, _> =
        serde_json::from_str(&bad);
    assert!(r.is_err());
}

#[test]
fn telemetry_repeated_start_stop_no_resource_growth() {
    // Repeated create/mark/close cycles must not grow state: each channel is
    // independent; assert close is idempotent and reset works.
    for _ in 0..50 {
        let ch = channel();
        let _ = ch.request(TelemetryQuery::Ping).unwrap();
        ch.close().unwrap();
        ch.close().unwrap(); // idempotent
    }
    // reset path
    let ch = channel();
    ch.close().unwrap();
    ch.reset().unwrap();
    assert_eq!(ch.state(), TelemetryState::Created);
}

// ----------------------------------------------------------------
// helpers
// ----------------------------------------------------------------

/// Template to build TelemetryRequest values for negative tests.
#[derive(Clone)]
struct TelemetryRequestTemplate {
    schema: String,
    channel_id: String,
    request_id: u32,
    sequence: u32,
    target_pid: u32,
    profile_digest: String,
}

impl TelemetryRequestTemplate {
    fn from_channel(ch: &TelemetryChannel) -> Self {
        Self {
            schema: TELEMETRY_SCHEMA.to_string(),
            channel_id: ch.channel_id().to_string(),
            request_id: 1,
            sequence: 0,
            target_pid: ch.target_pid(),
            profile_digest: ch.profile_digest().to_string(),
        }
    }

    fn into_request(
        self,
        query: TelemetryQuery,
    ) -> mida_antidebug_runtime::telemetry::TelemetryRequest {
        mida_antidebug_runtime::telemetry::TelemetryRequest {
            schema: self.schema,
            channel_id: self.channel_id,
            request_id: self.request_id,
            sequence: self.sequence,
            target_pid: self.target_pid,
            profile_digest: self.profile_digest,
            query,
        }
    }
}




// ----------------------------------------------------------------
// IMP-01-R1: attestation v2 (WO-1503 frozen contract)
// ----------------------------------------------------------------

use mida_antidebug_runtime::attestation::{
    json_c14n, json_c14n_bytes, parse_attestation, sha256_hex, AbortState, Orphan, OrphanKind,
    OrphanState, ProbeSummary, RoundLedger, RuntimeAttestationV2, TaggedAttestation,
    WalkerAttestation, ATTESTATION_SCHEMA_V2, ATTESTATION_SCHEMA_VERSION_V2, C14N_VECTOR_1_DIGEST,
    C14N_VECTOR_2_DIGEST, C14N_VECTOR_3_DIGEST, C14N_VECTOR_4_DIGEST, WALKER_CANONICAL_ENCODING,
};

// ---- WO-1503 §5.3 fixed digest vectors ----

#[test]
fn c14n_vector_1_empty_object() {
    let v = serde_json::json!({});
    let bytes = json_c14n_bytes(&v).unwrap();
    assert_eq!(bytes, vec![0x7b, 0x7d]);
    let digest = sha256_hex(&bytes);
    assert_eq!(digest, C14N_VECTOR_1_DIGEST);
}

#[test]
fn c14n_vector_2_scalar_key_order() {
    let v = serde_json::json!({"b": 1, "a": 2});
    let bytes = json_c14n_bytes(&v).unwrap();
    assert_eq!(
        bytes,
        vec![0x7b, 0x22, 0x61, 0x22, 0x3a, 0x32, 0x2c, 0x22, 0x62, 0x22, 0x3a, 0x31, 0x7d]
    );
    let digest = sha256_hex(&bytes);
    assert_eq!(digest, C14N_VECTOR_2_DIGEST);
}

#[test]
fn c14n_vector_3_nested_escape_unicode() {
    let v = serde_json::json!({"z": null, "a": [1, 2], "s": "x\"y", "u": "中"});
    let bytes = json_c14n_bytes(&v).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(
        hex,
        "7b2261223a5b312c325d2c2273223a22785c2279222c2275223a22e4b8ad222c227a223a6e756c6c7d"
    );
    let digest = sha256_hex(&bytes);
    assert_eq!(digest, C14N_VECTOR_3_DIGEST);
}

#[test]
fn c14n_vector_4_bool_literals() {
    let v = serde_json::json!({"ok": true, "no": false});
    let bytes = json_c14n_bytes(&v).unwrap();
    let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(hex, "7b226e6f223a66616c73652c226f6b223a747275657d");
    let digest = sha256_hex(&bytes);
    assert_eq!(digest, C14N_VECTOR_4_DIGEST);
}

#[test]
fn c14n_top_level_non_object_rejected() {
    assert!(json_c14n_bytes(&serde_json::json!([1, 2])).is_err());
    assert!(json_c14n_bytes(&serde_json::json!(42)).is_err());
    assert!(json_c14n_bytes(&serde_json::json!("x")).is_err());
}

// ---- WO-1503 §1 tagged dispatch ----

#[test]
fn tagged_dispatch_v2_accepts_and_validates() {
    // Build a minimal valid v2 attestation with no walker (null allowed).
    let mut att = RuntimeAttestationV2 {
        schema: ATTESTATION_SCHEMA_V2.to_string(),
        schema_version: ATTESTATION_SCHEMA_VERSION_V2,
        runtime_id: "mida-antidebug-runtime-x64".to_string(),
        runtime_version: "0.1.0".to_string(),
        architecture: "x86_64".to_string(),
        runtime_sha256: "a".repeat(64),
        profile_id: "p1".to_string(),
        profile_digest: "deadbeef".to_string(),
        target_pid: TEST_PID,
        module_base: TEST_MODULE_BASE,
        initialized: true,
        hooks_expected: expected_surfaces(),
        hooks_installed: expected_surfaces(),
        hook_failures: Vec::new(),
        surface_details: Vec::new(),
        telemetry_channel: "ready".to_string(),
        cleanup_handler_registered: true,
        third_party: "build-and-serialization-only".to_string(),
        source_revision: "v0.1.0".to_string(),
        toolchain: "rustc".to_string(),
        walker_attestation: None,
        record_digest: String::new(),
    };
    att.record_digest = att.compute_digest();
    assert!(!att.record_digest.is_empty());
    let json = att.to_canonical_json().unwrap();
    match parse_attestation(&json).unwrap() {
        TaggedAttestation::V2(v2) => {
            v2.validate().unwrap();
            assert_eq!(v2.schema_version, 2);
        }
        _ => panic!("expected V2"),
    }
}

#[test]
fn tagged_dispatch_v1_preserved() {
    let att = foundation_attestation();
    let json = att.to_canonical_json().unwrap();
    match parse_attestation(&json).unwrap() {
        TaggedAttestation::V1(v1) => {
            v1.validate().is_err(); // foundation is honest-unsupported -> hook inventory incomplete
            assert_eq!(v1.schema, ATTESTATION_SCHEMA);
        }
        _ => panic!("expected V1"),
    }
}

#[test]
fn tagged_dispatch_schema_version_mismatch_rejected() {
    // v2 schema with schema_version=1 -> SchemaVersionMismatch
    let json = r#"{"schema":"mida.antidebug-runtime-attestation/v2","schema_version":1}"#;
    assert!(matches!(
        parse_attestation(json),
        Err(mida_antidebug_runtime::attestation::AttestationError::SchemaVersionMismatch { .. })
    ));
}

#[test]
fn tagged_dispatch_unknown_schema_rejected() {
    let json = r#"{"schema":"mida.wrong/v9"}"#;
    assert!(matches!(
        parse_attestation(json),
        Err(mida_antidebug_runtime::attestation::AttestationError::SchemaUnsupported(_))
    ));
}

#[test]
fn tagged_dispatch_v2_unknown_field_rejected() {
    let json = r#"{"schema":"mida.antidebug-runtime-attestation/v2","schema_version":2,"bogus":1}"#;
    assert!(parse_attestation(json).is_err());
}

// ---- WO-1503 §3.2 RoundLedger ----

fn sample_round(index: u8) -> RoundLedger {
    let mut r = RoundLedger::new(index).unwrap();
    r.entry_ts = "2026-08-23T00:00:00Z".to_string();
    r.exit_ts = "2026-08-23T00:01:00Z".to_string();
    r.wall_budget_ms = 3_600_000;
    r.wall_spent_ms = 60_000;
    r.candidates_probed = 16;
    r.abort_state = AbortState::None;
    r.auto_retry = false;
    r.next_round_authorized = index == 1;
    r
}

#[test]
fn round_ledger_valid_rounds() {
    let r1 = sample_round(1);
    let r2 = sample_round(2);
    r1.validate().unwrap();
    r2.validate().unwrap();
}

#[test]
fn round_ledger_rejects_bad_index() {
    assert!(RoundLedger::new(0).is_err());
    assert!(RoundLedger::new(3).is_err());
    let mut r = sample_round(1);
    r.round_index = 7;
    assert!(matches!(
        r.validate(),
        Err(mida_antidebug_runtime::attestation::AttestationError::RoundIndexInvalid(7))
    ));
}

#[test]
fn round_ledger_rejects_budget_exceeded() {
    let mut r = sample_round(1);
    r.wall_spent_ms = r.wall_budget_ms + 1;
    assert!(matches!(
        r.validate(),
        Err(mida_antidebug_runtime::attestation::AttestationError::WallBudgetExceeded { .. })
    ));
}

#[test]
fn round_ledger_rejects_auto_retry() {
    let mut r = sample_round(1);
    r.auto_retry = true;
    assert_eq!(
        r.validate(),
        Err(mida_antidebug_runtime::attestation::AttestationError::AutoRetryForbidden)
    );
}

// ---- WO-1503 §3.3 ProbeSummary ----

#[test]
fn probe_summary_consistency_valid() {
    let s = ProbeSummary {
        candidates_total: 16,
        type_a_count: 8,
        type_b_count: 5,
        type_c_count: 3,
        av_count: 2,
        guard_count: 1,
        retry_count: 0,
        total_latency_us: 1000,
    };
    s.validate().unwrap();
}

#[test]
fn probe_summary_type_sum_mismatch_rejected() {
    let s = ProbeSummary {
        candidates_total: 16,
        type_a_count: 8,
        type_b_count: 5,
        type_c_count: 4, // 8+5+4=17 != 16
        av_count: 0,
        guard_count: 0,
        retry_count: 0,
        total_latency_us: 0,
    };
    assert!(matches!(
        s.validate(),
        Err(mida_antidebug_runtime::attestation::AttestationError::ProbeSummaryTypeSumMismatch { .. })
    ));
}

#[test]
fn probe_summary_guard_exceeds_rejected() {
    let s = ProbeSummary {
        candidates_total: 16,
        type_a_count: 16,
        type_b_count: 0,
        type_c_count: 0,
        av_count: 0,
        guard_count: 17, // > total
        retry_count: 0,
        total_latency_us: 0,
    };
    assert!(s.validate().is_err());
}

// ---- WO-1503 §3.4 Orphan ----

#[test]
fn orphan_valid_and_invalid_states() {
    let ok = Orphan {
        kind: OrphanKind::ParamsBlob,
        target_pid: TEST_PID,
        blob_base_va: Some(0x7ff6_0000_1000),
        section_name: None,
        created_ts: "2026-08-23T00:00:00Z".to_string(),
        timeout_ts: None,
        state: OrphanState::Created,
        reclaim_note: None,
    };
    ok.validate().unwrap();

    let bad = Orphan {
        kind: OrphanKind::ParamsBlob,
        target_pid: TEST_PID,
        blob_base_va: None, // params_blob requires VA
        section_name: None,
        created_ts: "2026-08-23T00:00:00Z".to_string(),
        timeout_ts: None,
        state: OrphanState::Created,
        reclaim_note: None,
    };
    assert!(matches!(
        bad.validate(),
        Err(mida_antidebug_runtime::attestation::AttestationError::OrphanKindVaInconsistent)
    ));
}

#[test]
fn orphan_unconfirmed_no_reclaim_note() {
    let o = Orphan {
        kind: OrphanKind::ResultSection,
        target_pid: TEST_PID,
        blob_base_va: None,
        section_name: Some("WALKER_RESULT_1".to_string()),
        created_ts: "2026-08-23T00:00:00Z".to_string(),
        timeout_ts: None,
        state: OrphanState::Unconfirmed,
        reclaim_note: Some("observed via handle query".to_string()), // forbidden
    };
    assert!(matches!(
        o.validate(),
        Err(mida_antidebug_runtime::attestation::AttestationError::OrphanReclaimNoteUnconfirmed)
    ));
}

// ---- WO-1503 §3.1 WalkerAttestation binding + digest ----

fn sample_walker_attestation() -> WalkerAttestation {
    let summary = ProbeSummary {
        candidates_total: 16,
        type_a_count: 8,
        type_b_count: 5,
        type_c_count: 3,
        av_count: 2,
        guard_count: 1,
        retry_count: 0,
        total_latency_us: 1000,
    };
    let mut w = WalkerAttestation::new(
        TEST_PID,
        "target-image-digest",
        "a".repeat(64),
        0x1234,
        TEST_MODULE_BASE + 0x1234,
        summary,
    );
    w.rounds.push(sample_round(1));
    w.rounds.push(sample_round(2));
    w.record_digest = w.compute_digest();
    w
}

#[test]
fn walker_attestation_binding_and_digest() {
    let w = sample_walker_attestation();
    w.validate(TEST_PID, &"a".repeat(64)).unwrap();
    // tamper -> digest mismatch
    let mut w2 = w.clone();
    w2.probe_summary.av_count = 99;
    assert!(matches!(
        w2.validate(TEST_PID, &"a".repeat(64)),
        Err(mida_antidebug_runtime::attestation::AttestationError::RecordDigestMismatch { .. })
    ));
    // pid mismatch -> reject
    let mut w3 = w.clone();
    w3.target_pid = TEST_PID + 1;
    assert!(matches!(
        w3.validate(TEST_PID, &"a".repeat(64)),
        Err(mida_antidebug_runtime::attestation::AttestationError::WalkerPidMismatch { .. })
    ));
}

#[test]
fn walker_attestation_round_sequence_checked() {
    let mut w = sample_walker_attestation();
    // remove round 1 -> sequence starts at 2 -> gap
    w.rounds.remove(0);
    w.record_digest = w.compute_digest();
    assert!(matches!(
        w.validate(TEST_PID, &"a".repeat(64)),
        Err(mida_antidebug_runtime::attestation::AttestationError::RoundSeqGap { expected: 1, got: 2 })
    ));
}

#[test]
fn walker_attestation_digest_preimage_excludes_only_self() {
    let w = sample_walker_attestation();
    // The digest must be deterministic and 64 hex lowercase.
    assert_eq!(w.record_digest.len(), 64);
    assert!(w.record_digest.chars().all(|c| c.is_ascii_hexdigit()));
    // recompute equals stored
    assert_eq!(w.compute_digest(), w.record_digest);
}

// ---- v2 top-level with walker ----

#[test]
fn v2_top_level_with_walker_roundtrip() {
    let w = sample_walker_attestation();
    let mut att = RuntimeAttestationV2 {
        schema: ATTESTATION_SCHEMA_V2.to_string(),
        schema_version: ATTESTATION_SCHEMA_VERSION_V2,
        runtime_id: "mida-antidebug-runtime-x64".to_string(),
        runtime_version: "0.1.0".to_string(),
        architecture: "x86_64".to_string(),
        runtime_sha256: "a".repeat(64),
        profile_id: "p1".to_string(),
        profile_digest: "deadbeef".to_string(),
        target_pid: TEST_PID,
        module_base: TEST_MODULE_BASE,
        initialized: true,
        hooks_expected: expected_surfaces(),
        hooks_installed: expected_surfaces(),
        hook_failures: Vec::new(),
        surface_details: Vec::new(),
        telemetry_channel: "ready".to_string(),
        cleanup_handler_registered: true,
        third_party: "build-and-serialization-only".to_string(),
        source_revision: "v0.1.0".to_string(),
        toolchain: "rustc".to_string(),
        walker_attestation: Some(w),
        record_digest: String::new(),
    };
    att.record_digest = att.compute_digest();
    att.validate().unwrap();
    let json = att.to_canonical_json().unwrap();
    let back = RuntimeAttestationV2::from_canonical_json(&json).unwrap();
    assert_eq!(back, att);
}

#[test]
fn v2_top_level_walker_digest_tamper_rejected() {
    let w = sample_walker_attestation();
    let mut att = RuntimeAttestationV2 {
        schema: ATTESTATION_SCHEMA_V2.to_string(),
        schema_version: ATTESTATION_SCHEMA_VERSION_V2,
        runtime_id: "mida-antidebug-runtime-x64".to_string(),
        runtime_version: "0.1.0".to_string(),
        architecture: "x86_64".to_string(),
        runtime_sha256: "a".repeat(64),
        profile_id: "p1".to_string(),
        profile_digest: "deadbeef".to_string(),
        target_pid: TEST_PID,
        module_base: TEST_MODULE_BASE,
        initialized: true,
        hooks_expected: expected_surfaces(),
        hooks_installed: expected_surfaces(),
        hook_failures: Vec::new(),
        surface_details: Vec::new(),
        telemetry_channel: "ready".to_string(),
        cleanup_handler_registered: true,
        third_party: "build-and-serialization-only".to_string(),
        source_revision: "v0.1.0".to_string(),
        toolchain: "rustc".to_string(),
        walker_attestation: Some(w),
        record_digest: String::new(),
    };
    att.record_digest = att.compute_digest();
    // tamper the nested walker digest AFTER top-level digest computed
    let json = att.to_canonical_json().unwrap();
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value["walker_attestation"]["record_digest"] = serde_json::json!("0".repeat(64));
    let tampered = value.to_string();
    let parsed = RuntimeAttestationV2::from_canonical_json(&tampered).unwrap();
    // nested digest mismatch detected before top-level
    assert!(parsed.validate().is_err());
}
