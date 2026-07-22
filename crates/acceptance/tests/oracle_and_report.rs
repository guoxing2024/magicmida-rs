//! Oracle isolation and report determinism.

use mida_acceptance::{
    check_static, observe_oracle, sha256_hex, CheckStaticOptions, Verdict, ROLE_CANDIDATE,
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

#[test]
fn oracle_match_does_not_accept() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let report = check_static(
        &pe,
        &CheckStaticOptions {
            oracle_bytes: Some(pe.clone()),
            ..opts()
        },
    );
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert_ne!(report.verdict, Verdict::Accepted);
    assert_eq!(report.oracle_observations.len(), 1);
    assert_eq!(report.oracle_observations[0].comparison, "byte_identical");
}

#[test]
fn oracle_mismatch_does_not_override_reject() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let bad = b"not-the-oracle";
    // Force reject via digest mismatch
    let report = check_static(
        &pe,
        &CheckStaticOptions {
            expected_sha256: Some(
                "1111111111111111111111111111111111111111111111111111111111111111".into(),
            ),
            oracle_bytes: Some(bad.to_vec()),
            ..opts()
        },
    );
    assert_eq!(report.verdict, Verdict::Rejected);
    assert!(!report.oracle_observations.is_empty());
    // Still rejected despite oracle presence
    assert!(report.failures.iter().any(|f| f.code == "digest_mismatch"));
}

#[test]
fn oracle_mismatch_on_passing_pe_stays_structural_pending() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let other = build_pe(&PeBuildOptions::pe32());
    let report = check_static(
        &pe,
        &CheckStaticOptions {
            oracle_bytes: Some(other),
            ..opts()
        },
    );
    // Oracle mismatch must not reject a structurally valid PE
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
    assert_eq!(report.oracle_observations[0].comparison, "digest_mismatch");
}

#[test]
fn oracle_absent_ok() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let report = check_static(&pe, &opts());
    assert!(report.oracle_observations.is_empty());
    assert_eq!(report.verdict, Verdict::StructuralPassBehaviorPending);
}

#[test]
fn observe_oracle_helper() {
    let pe = build_pe(&PeBuildOptions::pe32());
    let report = check_static(&pe, &opts());
    let obs = observe_oracle(&report.artifact, Some(&pe)).unwrap();
    assert_eq!(obs.comparison, "byte_identical");
}

#[test]
fn report_determinism_byte_identical() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let o = CheckStaticOptions {
        expected_sha256: Some(sha256_hex(&pe)),
        oracle_bytes: Some(pe.clone()),
        ..opts()
    };
    let a = check_static(&pe, &o).to_json().unwrap();
    let b = check_static(&pe, &o).to_json().unwrap();
    assert_eq!(a, b);
    // No timestamps or absolute paths
    assert!(!a.contains("T00:"));
    assert!(!a.contains(":\\"));
    assert!(!a.contains("C:/"));
    assert!(!a.contains("timestamp"));
}

#[test]
fn report_schema_fields_present() {
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let report = check_static(&pe, &opts());
    let v: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
    for key in [
        "schema_version",
        "artifact",
        "verdict",
        "gates",
        "failures",
        "warnings",
        "residual_risks",
        "oracle_observations",
    ] {
        assert!(v.get(key).is_some(), "missing {key}");
    }
    assert_eq!(v["schema_version"], "mida.acceptance-report/v1");
    assert_eq!(v["verdict"], "StructuralPassBehaviorPending");
    let gates = v["gates"].as_array().unwrap();
    assert!(!gates.is_empty());
    // ordered: first structural gate after optional identity is headers or identity
    let ids: Vec<&str> = gates.iter().map(|g| g["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"headers_bounds"));
    assert!(ids.contains(&"entry_point"));
}
