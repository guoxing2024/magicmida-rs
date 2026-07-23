//! B-A2: library compose path with pre-recorded behavior evidence.

use mida_acceptance::{
    check_static, check_with_behavior, sha256_hex, BehaviorEvidence, BehaviorVerdict,
    CheckStaticOptions, Verdict, BEHAVIOR_EVIDENCE_SCHEMA_VERSION, ROLE_CANDIDATE,
};
use mida_acceptance::behavior::{
    BehaviorCandidate, BehaviorPolicy, BehaviorProbe, BehaviorProbeResult, BehaviorProducer,
    BehaviorReference,
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

fn evidence_for(
    pe: &[u8],
    verdict: BehaviorVerdict,
    result_status: &str,
) -> BehaviorEvidence {
    BehaviorEvidence {
        schema_version: BEHAVIOR_EVIDENCE_SCHEMA_VERSION.to_string(),
        candidate: BehaviorCandidate {
            sha256: sha256_hex(pe),
            size_bytes: pe.len() as u64,
            role: ROLE_CANDIDATE.to_string(),
        },
        reference: BehaviorReference {
            kind: "none".to_string(),
            sha256: None,
            notes: None,
        },
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
    }
}

#[test]
fn check_static_never_accepted_even_with_good_pe() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let report = check_static(&pe, &opts());
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert_ne!(report.verdict, Verdict::Accepted);
}

#[test]
fn check_with_behavior_pass_accepts() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let ev = evidence_for(&pe, BehaviorVerdict::Pass, "pass");
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Accepted);
    assert!(report.failures.is_empty(), "{:?}", report.failures);
    assert_eq!(report.verdict.exit_code(), 0);
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
    let json = format!(
        r#"{{
  "schema_version": "mida.behavior-evidence/v0",
  "candidate": {{
    "sha256": "{dig}",
    "size_bytes": {},
    "role": "candidate"
  }},
  "reference": {{ "kind": "none", "sha256": null, "notes": null }},
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
  "producer": {{ "name": "tools/_behavior_probe.py", "version": "0" }}
}}"#,
        pe.len()
    );
    let ev = BehaviorEvidence::parse_json(json.as_bytes()).expect("parse");
    let report = check_with_behavior(&pe, &opts(), &ev);
    assert_eq!(report.verdict, Verdict::Accepted);
}
