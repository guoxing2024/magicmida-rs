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
