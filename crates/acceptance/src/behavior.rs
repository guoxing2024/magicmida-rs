//! Pre-recorded behavioral evidence (B-A2).
//!
//! The acceptance kernel only **loads and binds** evidence produced by an
//! external harness (see `tools/_behavior_probe.py`). It does not run probes,
//! unpack, or call Win32.
//!
//! Schema: `mida.behavior-evidence/v0` (`docs/VNEXT_BEHAVIORAL_PATH.md`).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::sha256_hex;
use crate::report::{FailureRecord, GateResult, GateStatus, WarningRecord};
use crate::verdict::Verdict;

pub const BEHAVIOR_EVIDENCE_SCHEMA_VERSION: &str = "mida.behavior-evidence/v0";

/// Top-level evidence document (harness output).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorEvidence {
    pub schema_version: String,
    pub candidate: BehaviorCandidate,
    pub reference: BehaviorReference,
    pub probe: BehaviorProbe,
    pub verdict: BehaviorVerdict,
    #[serde(default)]
    pub residual_risks: Vec<String>,
    pub producer: BehaviorProducer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorCandidate {
    pub sha256: String,
    pub size_bytes: u64,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorReference {
    pub kind: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorProbe {
    pub id: String,
    pub policy: BehaviorPolicy,
    pub result: BehaviorProbeResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorPolicy {
    pub network: String,
    pub max_wall_ms: u64,
    pub max_output_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorProbeResult {
    pub status: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub markers_found: Vec<String>,
    #[serde(default)]
    pub error_class: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BehaviorVerdict {
    Pass,
    Fail,
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehaviorProducer {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Error)]
pub enum BehaviorEvidenceError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported schema_version '{0}' (expected {BEHAVIOR_EVIDENCE_SCHEMA_VERSION})")]
    SchemaVersion(String),
    #[error("probe.policy.network must be 'deny' (got '{0}')")]
    NetworkPolicy(String),
    #[error("probe.result.status invalid: '{0}'")]
    ResultStatus(String),
    #[error("candidate.sha256 must be 64 lowercase hex chars")]
    BadSha256,
}

impl BehaviorEvidence {
    /// Parse and validate structural shape (not candidate binding).
    pub fn parse_json(bytes: &[u8]) -> Result<Self, BehaviorEvidenceError> {
        let ev: Self = serde_json::from_slice(bytes)?;
        if ev.schema_version != BEHAVIOR_EVIDENCE_SCHEMA_VERSION {
            return Err(BehaviorEvidenceError::SchemaVersion(ev.schema_version));
        }
        if ev.probe.policy.network != "deny" {
            return Err(BehaviorEvidenceError::NetworkPolicy(
                ev.probe.policy.network.clone(),
            ));
        }
        match ev.probe.result.status.as_str() {
            "pass" | "fail" | "error" | "timeout" => {}
            other => return Err(BehaviorEvidenceError::ResultStatus(other.to_string())),
        }
        let sha = ev.candidate.sha256.trim().to_ascii_lowercase();
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BehaviorEvidenceError::BadSha256);
        }
        Ok(Self {
            candidate: BehaviorCandidate {
                sha256: sha,
                ..ev.candidate
            },
            ..ev
        })
    }

    /// Whether evidence.candidate matches on-disk / in-memory candidate bytes.
    pub fn binds_to_candidate(&self, candidate_bytes: &[u8]) -> bool {
        let dig = sha256_hex(candidate_bytes);
        dig == self.candidate.sha256
            && (candidate_bytes.len() as u64) == self.candidate.size_bytes
    }
}

/// Compose static structural report with pre-recorded behavior evidence.
///
/// Rules (VNEXT_BEHAVIORAL_PATH):
/// - structural `Rejected` stays `Rejected`
/// - identity mismatch → `Rejected`
/// - evidence `Fail` → `Rejected`
/// - evidence `Inconclusive` → stay `StructuralPassBehaviorPending` (never upgrade)
/// - evidence `Pass` + structural pass → `Accepted`
///
/// Call only from the explicit behavioral CLI/API path — not from `check_static`.
pub fn compose_with_behavior(
    mut report: crate::report::AcceptanceReport,
    evidence: &BehaviorEvidence,
    candidate_bytes: &[u8],
) -> crate::report::AcceptanceReport {
    // Identity binding gate
    if !evidence.binds_to_candidate(candidate_bytes) {
        report.gates.push(GateResult {
            id: "behavior_identity".to_string(),
            status: GateStatus::Fail,
            detail: Some(format!(
                "evidence sha256={} size={} vs candidate sha256={} size={}",
                evidence.candidate.sha256,
                evidence.candidate.size_bytes,
                sha256_hex(candidate_bytes),
                candidate_bytes.len()
            )),
        });
        report.failures.push(FailureRecord {
            gate_id: "behavior_identity".to_string(),
            code: "evidence_identity_mismatch".to_string(),
            message: "behavior evidence does not bind to candidate bytes".to_string(),
        });
        report.verdict = Verdict::Rejected;
        return report;
    }

    report.gates.push(GateResult {
        id: "behavior_identity".to_string(),
        status: GateStatus::Pass,
        detail: Some("evidence binds to candidate".to_string()),
    });

    let beh_status = match evidence.verdict {
        BehaviorVerdict::Pass => GateStatus::Pass,
        BehaviorVerdict::Fail => GateStatus::Fail,
        BehaviorVerdict::Inconclusive => GateStatus::Skip,
    };
    report.gates.push(GateResult {
        id: "behavior_evidence".to_string(),
        status: beh_status,
        detail: Some(format!(
            "probe={} evidence_verdict={:?} result_status={}",
            evidence.probe.id, evidence.verdict, evidence.probe.result.status
        )),
    });

    // Structural already rejected → keep rejected (do not upgrade).
    if report.verdict == Verdict::Rejected || !report.failures.is_empty() {
        report.verdict = Verdict::Rejected;
        report.warnings.push(WarningRecord {
            code: "behavior_not_composed_after_structural_reject".to_string(),
            message: "structural rejection takes precedence over behavior evidence".to_string(),
        });
        return report;
    }

    match evidence.verdict {
        BehaviorVerdict::Pass => {
            report.verdict = Verdict::Accepted;
        }
        BehaviorVerdict::Fail => {
            report.failures.push(FailureRecord {
                gate_id: "behavior_evidence".to_string(),
                code: "behavior_fail".to_string(),
                message: format!(
                    "behavior evidence verdict Fail (probe={}, status={})",
                    evidence.probe.id, evidence.probe.result.status
                ),
            });
            report.verdict = Verdict::Rejected;
        }
        BehaviorVerdict::Inconclusive => {
            // Must not upgrade to Accepted.
            report.verdict = Verdict::StructuralPassBehaviorPending;
            report.warnings.push(WarningRecord {
                code: "behavior_inconclusive".to_string(),
                message: "behavior evidence Inconclusive; verdict remains StructuralPassBehaviorPending"
                    .to_string(),
            });
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_evidence(sha: &str, size: u64, verdict: BehaviorVerdict) -> BehaviorEvidence {
        BehaviorEvidence {
            schema_version: BEHAVIOR_EVIDENCE_SCHEMA_VERSION.to_string(),
            candidate: BehaviorCandidate {
                sha256: sha.to_string(),
                size_bytes: size,
                role: "candidate".to_string(),
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
                    status: match verdict {
                        BehaviorVerdict::Pass => "pass".to_string(),
                        BehaviorVerdict::Fail => "fail".to_string(),
                        BehaviorVerdict::Inconclusive => "timeout".to_string(),
                    },
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
    fn parse_rejects_wrong_schema() {
        let j = br#"{"schema_version":"nope","candidate":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1,"role":"c"},"reference":{"kind":"none"},"probe":{"id":"x","policy":{"network":"deny","max_wall_ms":1,"max_output_bytes":1},"result":{"status":"pass","exit_code":0,"markers_found":[],"error_class":null}},"verdict":"Pass","residual_risks":[],"producer":{"name":"t","version":"0"}}"#;
        assert!(matches!(
            BehaviorEvidence::parse_json(j),
            Err(BehaviorEvidenceError::SchemaVersion(_))
        ));
    }

    #[test]
    fn bind_matches_sha_and_size() {
        let bytes = b"hello-behavior";
        let dig = sha256_hex(bytes);
        let ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Pass);
        assert!(ev.binds_to_candidate(bytes));
        assert!(!ev.binds_to_candidate(b"other"));
    }

    fn structural_pass_report(bytes: &[u8]) -> crate::report::AcceptanceReport {
        let mut report = crate::report::AcceptanceReport::new(crate::identity::ArtifactIdentity {
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
            role: "candidate".to_string(),
            expected_sha256: None,
        });
        report.verdict = Verdict::StructuralPassBehaviorPending;
        report
    }

    fn structural_reject_report(bytes: &[u8]) -> crate::report::AcceptanceReport {
        let mut report = structural_pass_report(bytes);
        report.verdict = Verdict::Rejected;
        report.failures.push(FailureRecord {
            gate_id: "headers_bounds".to_string(),
            code: "test_structural_fail".to_string(),
            message: "synthetic structural reject".to_string(),
        });
        report
    }

    #[test]
    fn compose_pass_upgrades_to_accepted() {
        let bytes = b"compose-pass-candidate";
        let dig = sha256_hex(bytes);
        let ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Pass);
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Accepted);
        assert!(out.failures.is_empty(), "{:?}", out.failures);
    }

    #[test]
    fn compose_fail_rejects() {
        let bytes = b"compose-fail-candidate";
        let dig = sha256_hex(bytes);
        let ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Fail);
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(
            out.failures.iter().any(|f| f.code == "behavior_fail"),
            "{:?}",
            out.failures
        );
    }

    #[test]
    fn compose_inconclusive_stays_pending() {
        let bytes = b"compose-inconclusive-candidate";
        let dig = sha256_hex(bytes);
        let ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Inconclusive);
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::StructuralPassBehaviorPending);
        assert!(out.failures.is_empty(), "{:?}", out.failures);
        assert!(
            out.warnings
                .iter()
                .any(|w| w.code == "behavior_inconclusive"),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn compose_identity_mismatch_rejects() {
        let bytes = b"compose-mismatch-candidate";
        let dig = sha256_hex(b"other-bytes");
        let ev = sample_evidence(&dig, 999, BehaviorVerdict::Pass);
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(
            out.failures
                .iter()
                .any(|f| f.code == "evidence_identity_mismatch"),
            "{:?}",
            out.failures
        );
    }

    #[test]
    fn compose_does_not_upgrade_structural_reject() {
        let bytes = b"compose-structural-reject";
        let dig = sha256_hex(bytes);
        let ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Pass);
        let out = compose_with_behavior(structural_reject_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(
            out.warnings
                .iter()
                .any(|w| w.code == "behavior_not_composed_after_structural_reject"),
            "{:?}",
            out.warnings
        );
    }
}
