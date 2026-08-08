//! Top-level static acceptance evaluation (+ optional behavioral compose, B-A2).

use crate::behavior::{compose_with_behavior, BehaviorEvidence, VerifiedManagedCandidate};
use crate::envelope::VerifiedSignedBundle;
use crate::gates;
use crate::identity::{ArtifactIdentity, IdentityError, ROLE_CANDIDATE};
use crate::oracle::{observe_oracle, OracleObservation};
use crate::report::{
    AcceptanceReport, FailureRecord, GateResult, GateStatus, TrustTier, WarningRecord,
};
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
    // Static path never has a signature envelope → not product-acceptable.
    report.trust_tier = if report.verdict == Verdict::Rejected {
        TrustTier::Rejected
    } else {
        TrustTier::Unsigned
    };
    report.refresh_product_acceptable();
    report
}

/// Static gates plus **pre-recorded** behavioral evidence (B-A2).
///
/// **Unmanaged path** (no [`TransformManifest`]): may compose, but **never**
/// upgrades to [`Verdict::Accepted`] — max
/// [`Verdict::StructuralPassBehaviorPending`] (audit residual: library API
/// must not bypass CLI manifest enforcement).
///
/// Prefer [`check_with_behavior_signed`] for product Accepted, or
/// [`check_with_behavior_managed_lab`] for unsigned lab diagnostics.
pub fn check_with_behavior(
    bytes: &[u8],
    opts: &CheckStaticOptions,
    evidence: &BehaviorEvidence,
) -> AcceptanceReport {
    let structural = check_static(bytes, opts);
    let mut report = compose_with_behavior(structural, evidence, bytes);
    if report.verdict == Verdict::Accepted {
        report.verdict = Verdict::StructuralPassBehaviorPending;
        report.warnings.push(WarningRecord {
            code: "unmanaged_candidate_no_accepted".to_string(),
            message: "Accepted requires VerifiedSignedBundle (or explicit lab managed); \
                 unmanaged library path capped at StructuralPassBehaviorPending"
                .to_string(),
        });
    }
    // Unmanaged (no signed envelope) is never product-acceptable.
    report.trust_tier = if report.verdict == Verdict::Rejected {
        TrustTier::Rejected
    } else {
        TrustTier::Unsigned
    };
    report.refresh_product_acceptable();
    report
}

/// Managed compose **without** signature envelope.
///
/// Product posture: never returns [`Verdict::Accepted`] — capped at
/// [`Verdict::StructuralPassBehaviorPending`]. Use
/// [`check_with_behavior_signed`] for product Accept, or
/// [`check_with_behavior_managed_lab`] for explicit unsigned lab Accept.
pub fn check_with_behavior_managed(
    bytes: &[u8],
    opts: &CheckStaticOptions,
    evidence: &BehaviorEvidence,
    managed: &VerifiedManagedCandidate,
) -> AcceptanceReport {
    let mut report = compose_managed_uncapped(bytes, opts, evidence, managed);
    if report.verdict == Verdict::Accepted {
        report.verdict = Verdict::StructuralPassBehaviorPending;
        report.warnings.push(WarningRecord {
            code: "unsigned_managed_no_accepted".to_string(),
            message: "Accepted requires VerifiedSignedBundle; unsigned managed library \
                 path capped at StructuralPassBehaviorPending (use \
                 check_with_behavior_managed_lab for lab-only Accept)"
                .to_string(),
        });
    }
    // Unsigned managed has no verified envelope → not product-acceptable.
    report.trust_tier = if report.verdict == Verdict::Rejected {
        TrustTier::Rejected
    } else {
        TrustTier::Unsigned
    };
    report.refresh_product_acceptable();
    report
}

/// Lab-only: managed compose may return [`Verdict::Accepted`] without a
/// signature envelope. **Not** product authenticity.
pub fn check_with_behavior_managed_lab(
    bytes: &[u8],
    opts: &CheckStaticOptions,
    evidence: &BehaviorEvidence,
    managed: &VerifiedManagedCandidate,
) -> AcceptanceReport {
    let mut report = compose_managed_uncapped(bytes, opts, evidence, managed);
    if report.verdict == Verdict::Accepted {
        report.warnings.push(WarningRecord {
            code: "unsigned_managed_lab_accept".to_string(),
            message: "Accepted via check_with_behavior_managed_lab — lab diagnostic only, \
                 not product authenticity"
                .to_string(),
        });
    }
    // P1: lab-only Accept. Never product-acceptable even when verdict == Accepted.
    report.trust_tier = if report.verdict == Verdict::Rejected {
        TrustTier::Rejected
    } else {
        TrustTier::Lab
    };
    report.refresh_product_acceptable();
    report
}

fn compose_managed_uncapped(
    bytes: &[u8],
    opts: &CheckStaticOptions,
    evidence: &BehaviorEvidence,
    managed: &VerifiedManagedCandidate,
) -> AcceptanceReport {
    // Defense: re-bind in case caller mismatched bytes vs verified handle.
    if managed.candidate_sha256() != crate::identity::sha256_hex(bytes)
        || managed.candidate_size_bytes() != bytes.len() as u64
    {
        let structural = check_static(bytes, opts);
        let mut report = structural;
        report.verdict = Verdict::Rejected;
        report.failures.push(FailureRecord {
            gate_id: "transform_manifest".to_string(),
            code: "managed_candidate_bytes_mismatch".to_string(),
            message: "VerifiedManagedCandidate does not match provided candidate bytes".to_string(),
        });
        return report;
    }
    let mut ev = evidence.clone();
    if let Err(e) = managed.manifest().enforce_into_evidence(&mut ev, bytes) {
        let structural = check_static(bytes, opts);
        let mut report = structural;
        report.verdict = Verdict::Rejected;
        report.failures.push(FailureRecord {
            gate_id: "transform_manifest".to_string(),
            code: "manifest_enforce_failed".to_string(),
            message: e.to_string(),
        });
        return report;
    }
    let structural = check_static(bytes, opts);
    compose_with_behavior(structural, &ev, bytes)
}

/// Authenticated product path: requires a pre-verified [`VerifiedSignedBundle`]
/// (envelope + managed manifest + **sealed** evidence). Dumper must never
/// produce the signature; CI signs offline.
///
/// Evidence comes **only** from the bundle (parsed from hashed JSON at verify).
/// Callers cannot inject a replacement evidence document (audit P0).
///
/// This is the **only** non-lab library path that may return [`Verdict::Accepted`].
pub fn check_with_behavior_signed(
    bytes: &[u8],
    opts: &CheckStaticOptions,
    signed: &VerifiedSignedBundle,
) -> AcceptanceReport {
    let mut report = compose_managed_uncapped(bytes, opts, signed.evidence(), signed.managed());
    // P1: a verified signature envelope (non-caller-controlled trust root) is
    // the product trust tier. product_acceptable is true only when the verdict
    // is Accepted.
    report.trust_tier = if report.verdict == Verdict::Rejected {
        TrustTier::Rejected
    } else {
        TrustTier::Product
    };
    report.refresh_product_acceptable();
    report
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
    report.trust_tier = TrustTier::Rejected;
    report.refresh_product_acceptable();
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
