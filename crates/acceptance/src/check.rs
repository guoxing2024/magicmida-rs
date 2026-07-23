//! Top-level static acceptance evaluation (+ optional behavioral compose, B-A2).

use crate::behavior::{compose_with_behavior, BehaviorEvidence};
use crate::gates;
use crate::identity::{ArtifactIdentity, IdentityError, ROLE_CANDIDATE};
use crate::oracle::{observe_oracle, OracleObservation};
use crate::report::{AcceptanceReport, FailureRecord, GateResult, GateStatus};
use crate::verdict::Verdict;
use thiserror::Error;

/// Options for a static structural evaluation.
#[derive(Debug, Clone, Default)]
pub struct CheckStaticOptions {
    pub role: Option<String>,
    pub expected_sha256: Option<String>,
    pub expected_size: Option<u64>,
    /// Optional oracle file bytes (comparison only).
    pub oracle_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Error)]
pub enum CheckError {
    #[error("invalid expected SHA-256 hex")]
    InvalidExpectedHex,
}

/// Evaluate candidate bytes with R0B static gates.
///
/// Never returns [`Verdict::Accepted`].
pub fn check_static(bytes: &[u8], opts: &CheckStaticOptions) -> AcceptanceReport {
    let role = opts
        .role
        .clone()
        .unwrap_or_else(|| ROLE_CANDIDATE.to_string());

    let identity = match ArtifactIdentity::from_bytes(
        bytes,
        role,
        opts.expected_sha256.as_deref(),
        opts.expected_size,
    ) {
        Ok(id) => id,
        Err(e) => {
            return report_identity_failure(bytes, opts, e);
        }
    };

    let mut report = AcceptanceReport::new(identity);
    gates::run_all_gates(
        bytes,
        &mut report.gates,
        &mut report.failures,
        &mut report.warnings,
    );

    if let Some(obs) = observe_oracle(&report.artifact, opts.oracle_bytes.as_deref()) {
        report.oracle_observations.push(obs);
    }

    report.finalize_r0b();
    // Contract hard-stop: never Accepted in R0B static path.
    if report.verdict == Verdict::Accepted {
        report.verdict = Verdict::Rejected;
        report.failures.push(FailureRecord {
            gate_id: "contract".to_string(),
            code: "accepted_forbidden_in_r0b".to_string(),
            message: "R0B contract forbids Accepted verdict".to_string(),
        });
    }
    report
}

/// Static gates plus **pre-recorded** behavioral evidence (B-A2).
///
/// This is the only library path that may return [`Verdict::Accepted`].
/// `check_static` remains R0B-only (Accepted forbidden).
pub fn check_with_behavior(
    bytes: &[u8],
    opts: &CheckStaticOptions,
    evidence: &BehaviorEvidence,
) -> AcceptanceReport {
    let structural = check_static(bytes, opts);
    compose_with_behavior(structural, evidence, bytes)
}

fn report_identity_failure(
    bytes: &[u8],
    opts: &CheckStaticOptions,
    err: IdentityError,
) -> AcceptanceReport {
    // Still record computed digest when possible for the report body.
    let sha = crate::identity::sha256_hex(bytes);
    let role = opts
        .role
        .clone()
        .unwrap_or_else(|| ROLE_CANDIDATE.to_string());
    let expected = opts
        .expected_sha256
        .as_ref()
        .map(|s| s.trim().to_ascii_lowercase());
    let artifact = ArtifactIdentity {
        sha256: sha,
        size_bytes: bytes.len() as u64,
        role,
        expected_sha256: expected,
    };
    let mut report = AcceptanceReport::new(artifact);
    report.gates.push(GateResult {
        id: "artifact_identity".to_string(),
        status: GateStatus::Fail,
        detail: Some(err.to_string()),
    });
    let (code, message) = match &err {
        IdentityError::DigestMismatch { expected, actual } => (
            "digest_mismatch".to_string(),
            format!("expected {expected}, got {actual}"),
        ),
        IdentityError::SizeMismatch { expected, actual } => (
            "size_mismatch".to_string(),
            format!("expected {expected}, got {actual}"),
        ),
        IdentityError::InvalidExpectedHex(s) => ("invalid_expected_hex".to_string(), s.clone()),
    };
    report.failures.push(FailureRecord {
        gate_id: "artifact_identity".to_string(),
        code,
        message,
    });
    // Remaining structural gates skipped (fail-closed on identity).
    for id in [
        "headers_bounds",
        "machine_magic_consistency",
        "sections_ranges",
        "alignment_and_sizes",
        "entry_point",
        "imports_iat",
        "export_directory",
        "tls_directory",
        "reloc_directory",
        "exception_directory",
        "aslr_reloc_consistency",
        "directories_bounds",
    ] {
        report.gates.push(GateResult {
            id: id.to_string(),
            status: GateStatus::Skip,
            detail: Some("skipped: artifact identity failed".to_string()),
        });
    }
    if let Some(obs) = observe_oracle(&report.artifact, opts.oracle_bytes.as_deref()) {
        report.oracle_observations.push(obs);
    }
    report.finalize_r0b();
    report
}

/// Convenience: evaluate and return verdict.
pub fn check_static_verdict(bytes: &[u8], opts: &CheckStaticOptions) -> Verdict {
    check_static(bytes, opts).verdict
}

/// Attach an external oracle observation list (for tests).
pub fn push_oracle_observation(report: &mut AcceptanceReport, obs: OracleObservation) {
    report.oracle_observations.push(obs);
}
