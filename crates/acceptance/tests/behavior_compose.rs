//! B-A2: library compose path with pre-recorded behavior evidence.

use mida_acceptance::behavior::{
    BehaviorCandidate, BehaviorPolicy, BehaviorProbe, BehaviorProbeResult, BehaviorProducer,
    BehaviorReference,
};
use mida_acceptance::{
    check_static, check_with_behavior, check_with_behavior_managed,
    check_with_behavior_managed_lab, sha256_hex, BehaviorEvidence, BehaviorVerdict,
    CheckStaticOptions, TrustTier, Verdict, VerifiedManagedCandidate,
    BEHAVIOR_EVIDENCE_SCHEMA_VERSION, ROLE_CANDIDATE,
};

#[allow(dead_code)]
mod synth {
    include!("../src/test_support/pe_builder.rs");
}

use synth::{build_pe, PeBuildOptions};

fn opts() -> CheckStaticOptions {
    CheckStaticOptions {
        role: Some(ROLE_CANDIDATE.to_string()),
        ..Default::default()
    }
}

fn evidence_for(pe: &[u8], verdict: BehaviorVerdict, result_status: &str) -> BehaviorEvidence {
    let reference = if verdict == BehaviorVerdict::Pass {
        BehaviorReference {
            kind: "bilateral".to_string(),
            sha256: Some("dd".repeat(32)),
            notes: Some("compose test reference".into()),
        }
    } else {
        BehaviorReference {
            kind: "none".to_string(),
            sha256: None,
            notes: None,
        }
    };
    BehaviorEvidence {
        schema_version: BEHAVIOR_EVIDENCE_SCHEMA_VERSION.to_string(),
        candidate: BehaviorCandidate {
            sha256: sha256_hex(pe),
            size_bytes: pe.len() as u64,
            role: ROLE_CANDIDATE.to_string(),
        },
        reference,
        probe: BehaviorProbe {
            id: "exit_code_marker_v0".to_string(),
            policy: BehaviorPolicy {
                network: "deny".to_string(),
                max_wall_ms: 5000,
                max_output_bytes: 65536,
            },
            result: BehaviorProbeResult {
                status: result_status.to_string(),
                exit_code: Some(0),
                markers_found: vec!["MIDA_BEH_MARKER=1".to_string()],
                error_class: None,
            },
        },
        verdict,
        residual_risks: vec![],
        producer: BehaviorProducer {
            name: "test".to_string(),
            version: "0".to_string(),
        },
        transform_ledger: vec![],
    }
}

fn empty_managed_for(pe: &[u8]) -> VerifiedManagedCandidate {
    // Production mint path is dump-side JSON + verify only (no public empty ctor).
    let dig = sha256_hex(pe);
    let json = format!(
        r#"{{"schema_version":"mida.transform-manifest/v0","taxonomy_version":"mida.transform-taxonomy/v1","candidate_sha256":"{dig}","candidate_size_bytes":{},"entries":[],"note":"test"}}"#,
        pe.len()
    );
    VerifiedManagedCandidate::verify(pe, json.as_bytes()).expect("bind empty manifest")
}

#[test]
fn manifest_missing_taxonomy_version_rejected() {
    use mida_acceptance::BehaviorEvidenceError;
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let dig = sha256_hex(&pe);
    let json = format!(
        r#"{{"schema_version":"mida.transform-manifest/v0","candidate_sha256":"{dig}","candidate_size_bytes":{},"entries":[]}}"#,
        pe.len()
    );
    let err = VerifiedManagedCandidate::verify(&pe, json.as_bytes()).unwrap_err();
    assert!(
        matches!(err, BehaviorEvidenceError::TaxonomyVersionMissing),
        "expected TaxonomyVersionMissing, got: {err:?}"
    );
}

#[test]
fn manifest_unknown_taxonomy_version_rejected() {
    use mida_acceptance::BehaviorEvidenceError;
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let dig = sha256_hex(&pe);
    let json = format!(
        r#"{{"schema_version":"mida.transform-manifest/v0","taxonomy_version":"mida.transform-taxonomy/v0-legacy","candidate_sha256":"{dig}","candidate_size_bytes":{},"entries":[]}}"#,
        pe.len()
    );
    let err = VerifiedManagedCandidate::verify(&pe, json.as_bytes()).unwrap_err();
    assert!(
        matches!(err, BehaviorEvidenceError::TaxonomyVersionMismatch { .. }),
        "expected TaxonomyVersionMismatch, got: {err:?}"
    );
}

#[test]
fn manifest_exact_taxonomy_v1_binds_for_managed() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let m = empty_managed_for(&pe);
    assert_eq!(
        m.manifest().taxonomy_version(),
        "mida.transform-taxonomy/v1"
    );
    let ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    // Unsigned managed is product-capped at Pending; taxonomy still binds.
    let report = check_with_behavior_managed(&pe, &opts(), &ev, &m);
    assert_eq!(
        report.verdict,
        Verdict::StructuralPassBehaviorPending,
        "{:?}",
        report.failures
    );
    let lab = check_with_behavior_managed_lab(&pe, &opts(), &ev, &m);
    assert_eq!(lab.verdict, Verdict::Accepted, "{:?}", lab.failures);
    assert_eq!(lab.trust_tier, TrustTier::Lab);
    assert!(!lab.product_acceptable);
}

#[test]
fn check_static_never_accepted_even_with_good_pe() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert_ne!(report.verdict, Verdict::Accepted);
    // Static path has no envelope: never product-acceptable.
    assert!(!report.product_acceptable);
}

#[test]
fn check_with_behavior_unmanaged_never_accepted() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    let report = check_with_behavior(&pe, &opts(), &ev);
    // Library unmanaged path is capped (audit residual).
    assert_ne!(report.verdict, Verdict::Accepted);
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
}

#[test]
fn check_with_behavior_managed_unsigned_capped_at_pending() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    let m = empty_managed_for(&pe);
    let report = check_with_behavior_managed(&pe, &opts(), &ev, &m);
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert_ne!(report.verdict, Verdict::Accepted);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.code == "unsigned_managed_no_accepted"),
        "{:?}",
        report.warnings
    );
    // Unsigned managed is never product-acceptable.
    assert!(!report.product_acceptable);
    assert_eq!(report.trust_tier, TrustTier::Unsigned);
}

#[test]
fn check_with_behavior_managed_lab_may_accept_but_not_product() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    let m = empty_managed_for(&pe);
    let report = check_with_behavior_managed_lab(&pe, &opts(), &ev, &m);
    // Lab may return a Pass-shaped verdict, but it is NOT product-acceptable:
    // trust_tier must be Lab and product_acceptable false (P1).
    assert_eq!(report.verdict, Verdict::Accepted);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.trust_tier, TrustTier::Lab);
    assert!(
        !report.product_acceptable,
        "lab Accept must not be product-acceptable"
    );
    assert!(report
        .warnings
        .iter()
        .any(|w| w.code == "unsigned_managed_lab_accept"));
}

/// P1: a machine consumer reading the report must see a lab Accept as
/// `trust_tier=lab` and `product_acceptable=false` in the serialized JSON —
/// never a product acceptance.
#[test]
fn lab_accept_report_explicitly_marks_trust_tier_lab() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    let m = empty_managed_for(&pe);
    let report = check_with_behavior_managed_lab(&pe, &opts(), &ev, &m);
    let json = report.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["trust_tier"], "lab");
    assert_eq!(value["product_acceptable"], false);
    assert_eq!(value["verdict"], "Accepted");
}

/// P1: a product pipeline consuming the report MUST reject a lab Accept
/// (product_acceptable == false), even though the verdict field says Accepted.
#[test]
fn product_pipeline_rejects_lab_accept_report() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    let m = empty_managed_for(&pe);
    let report = check_with_behavior_managed_lab(&pe, &opts(), &ev, &m);
    assert_eq!(report.verdict, Verdict::Accepted);
    // The product gate is `product_acceptable`; a lab Accept is refused.
    assert!(
        !report.product_acceptable,
        "lab Accept must be refused by product gate"
    );
    // A product consumer that only checks `verdict == Accepted` is unsound; the
    // report contract mandates checking `product_acceptable`.
    assert!(
        report.trust_tier != TrustTier::Product,
        "lab tier must never be Product"
    );
}

#[test]
fn check_with_behavior_fail_rejects() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let mut ev = evidence_for(&pe, BehaviorVerdict::Fail, "fail");
    ev.probe.result.exit_code = Some(1);
    ev.probe.result.markers_found.clear();
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Rejected);
    assert_eq!(report.verdict.exit_code(), 2);
}

#[test]
fn check_with_behavior_inconclusive_pending() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let mut ev = evidence_for(&pe, BehaviorVerdict::Inconclusive, "timeout");
    ev.probe.result.exit_code = None;
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert_eq!(report.verdict.exit_code(), 0);
}

#[test]
fn check_with_behavior_identity_mismatch_rejects() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let mut ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    ev.candidate.sha256 = "bb".repeat(32);
    ev.candidate.size_bytes = 1;
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == "evidence_identity_mismatch"),
        "{:?}",
        report.failures
    );
}

#[test]
fn check_with_behavior_structural_reject_not_upgraded() {
    let pe = b"not-a-pe";
    let dig = sha256_hex(pe);
    let mut ev = evidence_for(pe, BehaviorVerdict::Pass, "pass");
    ev.candidate.sha256 = dig;
    ev.candidate.size_bytes = pe.len() as u64;
    let report = check_with_behavior(pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Rejected);
}

#[test]
fn parse_json_roundtrip_from_harness_shape() {
    let pe = build_pe(&PeBuildOptions::pe32());
    let dig = sha256_hex(&pe);
    let ref_sha = "ee".repeat(32);
    let json = format!(
        r#"{{
  "schema_version": "mida.behavior-evidence/v0",
  "candidate": {{
    "sha256": "{dig}",
    "size_bytes": {},
    "role": "candidate"
  }},
  "reference": {{ "kind": "bilateral", "sha256": "{ref_sha}", "notes": "harness" }},
  "probe": {{
    "id": "exit_code_marker_v0",
    "policy": {{ "network": "deny", "max_wall_ms": 5000, "max_output_bytes": 65536 }},
    "result": {{
      "status": "pass",
      "exit_code": 0,
      "markers_found": ["MIDA_BEH_MARKER=1"],
      "error_class": null
    }}
  }},
  "verdict": "Pass",
  "residual_risks": [],
  "producer": {{ "name": "tools/_behavior_probe.py", "version": "0" }},
  "transform_ledger": []
}}"#,
        pe.len()
    );
    let ev = BehaviorEvidence::parse_json(json.as_bytes()).expect("parse");
    let m = empty_managed_for(&pe);
    // Harness-shaped evidence binds; unsigned managed stays Pending (product posture).
    let report = check_with_behavior_managed(&pe, &opts(), &ev, &m);
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    let lab = check_with_behavior_managed_lab(&pe, &opts(), &ev, &m);
    assert_eq!(lab.verdict, Verdict::Accepted);
    assert_eq!(lab.trust_tier, TrustTier::Lab);
    assert!(!lab.product_acceptable);
}

#[test]
fn load_no_crash_probe_cannot_product_accept() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let mut ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    ev.probe.id = "load_no_crash_v0".to_string();
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == "unregistered_product_probe"),
        "{:?}",
        report.failures
    );
}

#[test]
fn none_reference_cannot_product_accept() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let mut ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    ev.reference = BehaviorReference {
        kind: "none".to_string(),
        sha256: None,
        notes: None,
    };
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == "reference_required_for_accept"),
        "{:?}",
        report.failures
    );
}

#[test]
fn transform_ledger_without_rule_blocks_accept() {
    use mida_acceptance::behavior::TransformLedgerEntry;
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let mut ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    ev.transform_ledger.push(TransformLedgerEntry {
        id: "gto_bypass_messagebox".into(),
        kind: "sample_bypass".into(),
        equivalence_rule: None,
    });
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(
        report
            .failures
            .iter()
            .any(|f| f.code == "transform_ledger_blocks_accept"),
        "{:?}",
        report.failures
    );
}
