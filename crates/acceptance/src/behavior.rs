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

/// Dump/acceptance transform taxonomy version (see docs/TRANSFORM_TAXONOMY_V1.md).
/// Future signature envelopes must carry this string.
pub const TRANSFORM_TAXONOMY_VERSION: &str = "mida.transform-taxonomy/v1";

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
    /// Semantic transforms applied to the candidate (bypass patches, forced UI, …).
    /// Non-empty ledger blocks product [`Verdict::Accepted`] unless an entry
    /// carries `equivalence_rule` (audit residual P1).
    #[serde(default)]
    pub transform_ledger: Vec<TransformLedgerEntry>,
}

/// One recorded transform on the candidate under test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformLedgerEntry {
    pub id: String,
    #[serde(default)]
    pub kind: String,
    /// If set, compose may still Accept (registered equivalence rule id).
    #[serde(default)]
    pub equivalence_rule: Option<String>,
}

/// Dump-side bound artifact (`*.transform_manifest.json`).
///
/// Fields are private — construct only via [`Self::parse_json`] so schema and
/// sha shape are validated (audit residual: no raw struct literal bypass).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformManifest {
    schema_version: String,
    /// Required for managed Accept — must equal [`TRANSFORM_TAXONOMY_VERSION`].
    /// Missing field fails parse (no serde default; audit residual P1).
    taxonomy_version: String,
    candidate_sha256: String,
    candidate_size_bytes: u64,
    entries: Vec<TransformLedgerEntry>,
    #[serde(default)]
    note: Option<String>,
}

/// Wire shape for parse: taxonomy_version is Option so we can distinguish
/// missing field from wrong value without scraping serde error text (P2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformManifestWire {
    schema_version: String,
    #[serde(default)]
    taxonomy_version: Option<String>,
    candidate_sha256: String,
    candidate_size_bytes: u64,
    #[serde(default)]
    entries: Vec<TransformLedgerEntry>,
    #[serde(default)]
    note: Option<String>,
}

impl TransformManifest {
    pub const SCHEMA: &'static str = "mida.transform-manifest/v0";

    pub fn parse_json(bytes: &[u8]) -> Result<Self, BehaviorEvidenceError> {
        let w: TransformManifestWire = serde_json::from_slice(bytes)?;
        if w.schema_version != Self::SCHEMA {
            return Err(BehaviorEvidenceError::SchemaVersion(w.schema_version));
        }
        let tax = w
            .taxonomy_version
            .filter(|s| !s.is_empty())
            .ok_or(BehaviorEvidenceError::TaxonomyVersionMissing)?;
        if tax != TRANSFORM_TAXONOMY_VERSION {
            return Err(BehaviorEvidenceError::TaxonomyVersionMismatch {
                got: tax,
                expected: TRANSFORM_TAXONOMY_VERSION.to_string(),
            });
        }
        let sha = w.candidate_sha256.trim().to_ascii_lowercase();
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BehaviorEvidenceError::BadSha256);
        }
        Ok(Self {
            schema_version: w.schema_version,
            taxonomy_version: tax,
            candidate_sha256: sha,
            candidate_size_bytes: w.candidate_size_bytes,
            entries: w.entries,
            note: w.note,
        })
    }

    pub fn taxonomy_version(&self) -> &str {
        &self.taxonomy_version
    }

    pub fn candidate_sha256(&self) -> &str {
        &self.candidate_sha256
    }

    pub fn candidate_size_bytes(&self) -> u64 {
        self.candidate_size_bytes
    }

    pub fn entries(&self) -> &[TransformLedgerEntry] {
        &self.entries
    }

    /// Fail-closed: manifest must bind to candidate bytes; then merge entries
    /// into evidence ledger. Manifest is **authoritative** for matching
    /// `(id, kind)` keys — evidence cannot invent a stronger equivalence_rule
    /// than the dump-side manifest (audit residual).
    pub fn enforce_into_evidence(
        &self,
        evidence: &mut BehaviorEvidence,
        candidate_bytes: &[u8],
    ) -> Result<(), BehaviorEvidenceError> {
        // Re-check schema / taxonomy even if constructed outside parse_json.
        if self.schema_version != Self::SCHEMA {
            return Err(BehaviorEvidenceError::SchemaVersion(
                self.schema_version.clone(),
            ));
        }
        if self.taxonomy_version != TRANSFORM_TAXONOMY_VERSION {
            return Err(BehaviorEvidenceError::TaxonomyVersionMismatch {
                got: self.taxonomy_version.clone(),
                expected: TRANSFORM_TAXONOMY_VERSION.to_string(),
            });
        }
        let dig = sha256_hex(candidate_bytes);
        if dig != self.candidate_sha256
            || (candidate_bytes.len() as u64) != self.candidate_size_bytes
        {
            return Err(BehaviorEvidenceError::ManifestCandidateMismatch {
                manifest_sha: self.candidate_sha256.clone(),
                candidate_sha: dig,
            });
        }
        for ment in &self.entries {
            if let Some(exist) = evidence
                .transform_ledger
                .iter_mut()
                .find(|e| e.id == ment.id && e.kind == ment.kind)
            {
                if exist.equivalence_rule != ment.equivalence_rule {
                    if ment.equivalence_rule.is_none() && exist.equivalence_rule.is_some() {
                        exist.equivalence_rule = None; // manifest veto
                    } else if ment.equivalence_rule != exist.equivalence_rule {
                        return Err(BehaviorEvidenceError::ManifestLedgerConflict {
                            id: ment.id.clone(),
                            kind: ment.kind.clone(),
                        });
                    }
                }
            } else {
                evidence.transform_ledger.push(ment.clone());
            }
        }
        if !self.entries.is_empty() && evidence.transform_ledger.is_empty() {
            return Err(BehaviorEvidenceError::TransformLedgerBlocksAccept);
        }
        Ok(())
    }
}

/// Candidate bytes + parsed manifest that have already been bound together.
///
/// Only constructible via [`Self::verify`]. The public managed check API takes
/// this type so callers cannot pass a hand-built unparsed manifest
/// (audit residual P2).
#[derive(Debug, Clone)]
pub struct VerifiedManagedCandidate {
    candidate_sha256: String,
    candidate_size_bytes: u64,
    manifest: TransformManifest,
}

impl VerifiedManagedCandidate {
    /// Parse manifest JSON and bind to `candidate_bytes`.
    pub fn verify(
        candidate_bytes: &[u8],
        manifest_json: &[u8],
    ) -> Result<Self, BehaviorEvidenceError> {
        let manifest = TransformManifest::parse_json(manifest_json)?;
        let dig = sha256_hex(candidate_bytes);
        if dig != manifest.candidate_sha256
            || (candidate_bytes.len() as u64) != manifest.candidate_size_bytes
        {
            return Err(BehaviorEvidenceError::ManifestCandidateMismatch {
                manifest_sha: manifest.candidate_sha256.clone(),
                candidate_sha: dig,
            });
        }
        Ok(Self {
            candidate_sha256: dig,
            candidate_size_bytes: candidate_bytes.len() as u64,
            manifest,
        })
    }

    pub fn manifest(&self) -> &TransformManifest {
        &self.manifest
    }

    pub fn candidate_sha256(&self) -> &str {
        &self.candidate_sha256
    }

    pub fn candidate_size_bytes(&self) -> u64 {
        self.candidate_size_bytes
    }
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
    /// Fail-closed: top-level verdict must agree with probe.result.status.
    #[error("verdict/status inconsistency: verdict={verdict:?} status='{status}'")]
    VerdictStatusInconsistent { verdict: String, status: String },
    #[error("probe.id '{0}' is not a registered product probe for Accepted")]
    UnregisteredProbe(String),
    #[error("product Accepted requires bilateral reference (got kind='{0}')")]
    ReferenceRequired(String),
    #[error("transform_ledger non-empty without equivalence rule — diagnostic only")]
    TransformLedgerBlocksAccept,
    #[error(
        "transform_manifest candidate mismatch: manifest={manifest_sha} candidate={candidate_sha}"
    )]
    ManifestCandidateMismatch {
        manifest_sha: String,
        candidate_sha: String,
    },
    #[error("transform_manifest conflicts with evidence ledger for id={id} kind={kind}")]
    ManifestLedgerConflict { id: String, kind: String },
    #[error("transform_manifest missing required taxonomy_version")]
    TaxonomyVersionMissing,
    #[error("transform_manifest taxonomy_version mismatch: got='{got}' expected='{expected}'")]
    TaxonomyVersionMismatch { got: String, expected: String },
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
        // Fail-closed semantic gate (audit P0): never accept
        // `verdict=Pass` with `status=fail|error|timeout`, or Fail with status=pass.
        let status = ev.probe.result.status.as_str();
        if !verdict_status_consistent(ev.verdict, status) {
            return Err(BehaviorEvidenceError::VerdictStatusInconsistent {
                verdict: format!("{:?}", ev.verdict),
                status: status.to_string(),
            });
        }
        let sha = ev.candidate.sha256.trim().to_ascii_lowercase();
        if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(BehaviorEvidenceError::BadSha256);
        }
        // Product Pass cannot be self-certified with loader-only probes or
        // reference.kind=none (audit residual: Accepted still call-side forgeable).
        if ev.verdict == BehaviorVerdict::Pass {
            if !is_product_probe_id(&ev.probe.id) {
                return Err(BehaviorEvidenceError::UnregisteredProbe(
                    ev.probe.id.clone(),
                ));
            }
            if !reference_supports_product_accept(&ev.reference) {
                return Err(BehaviorEvidenceError::ReferenceRequired(
                    ev.reference.kind.clone(),
                ));
            }
            if ledger_blocks_product_accept(&ev.transform_ledger) {
                return Err(BehaviorEvidenceError::TransformLedgerBlocksAccept);
            }
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
        dig == self.candidate.sha256 && (candidate_bytes.len() as u64) == self.candidate.size_bytes
    }
}

/// Fail-closed pairing of top-level verdict with probe.result.status.
fn verdict_status_consistent(verdict: BehaviorVerdict, status: &str) -> bool {
    match verdict {
        BehaviorVerdict::Pass => status == "pass",
        BehaviorVerdict::Fail => matches!(status, "fail" | "error"),
        // Inconclusive may carry any recorded status (including pass with residual).
        BehaviorVerdict::Inconclusive => true,
    }
}

/// Probes allowed to drive product [`Verdict::Accepted`].
/// Loader-only probes (`load_no_crash_v0`, …) are **not** listed.
fn is_product_probe_id(id: &str) -> bool {
    matches!(
        id,
        "exit_code_marker_v0"
            | "business_dialog_v0"
            | "license_path_bilateral_v0"
            | "window_class_bilateral_v0"
    )
}

fn reference_supports_product_accept(reference: &BehaviorReference) -> bool {
    match reference.kind.as_str() {
        "none" | "" => false,
        // Bilateral / protected-input reference must carry a digest.
        "protected_input" | "bilateral" | "oracle" | "reference_pe" => reference
            .sha256
            .as_ref()
            .map(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false),
        _ => false,
    }
}

/// Registered `(transform_id, kind, rule_id)` triples — not free-form strings.
/// A rule only unlocks the **matching** transform id+kind.
/// Must stay aligned with docs/TRANSFORM_TAXONOMY_V1.md §5.
/// GTO `sample_bypass` ids are intentionally **absent** (diagnostic only).
const REGISTERED_TRANSFORM_RULES: &[(&str, &str, &str)] = &[
    ("iat_rebuild", "pe_repair", "pe_iat_rebuild_v0"),
    ("reloc_rebind", "pe_repair", "pe_reloc_rebind_v0"),
    (
        "clear_stale_ptrs",
        "pe_repair",
        "clear_stale_process_ptrs_v0",
    ),
];

fn transform_rule_allowed(id: &str, kind: &str, rule: &str) -> bool {
    REGISTERED_TRANSFORM_RULES
        .iter()
        .any(|&(rid, rkind, rrule)| rid == id && rkind == kind && rrule == rule)
}

fn ledger_blocks_product_accept(ledger: &[TransformLedgerEntry]) -> bool {
    ledger.iter().any(|e| match e.equivalence_rule.as_deref() {
        Some(rule) if !rule.is_empty() && transform_rule_allowed(&e.id, &e.kind, rule) => false,
        _ => true, // missing/empty/unregistered/mismatched → block
    })
}

/// Compose static structural report with pre-recorded behavior evidence.
///
/// Rules (VNEXT_BEHAVIORAL_PATH):
/// - structural `Rejected` stays `Rejected`
/// - identity mismatch → `Rejected`
/// - verdict/status inconsistency → `Rejected` (fail-closed; audit P0)
/// - evidence `Fail` → `Rejected`
/// - evidence `Inconclusive` → stay `StructuralPassBehaviorPending` (never upgrade)
/// - evidence `Pass` + structural pass + status=pass → `Accepted`
///
/// Internal compose used by [`crate::check::check_with_behavior`] /
/// [`crate::check::check_with_behavior_managed`].
///
/// **Not** part of the public crate API — external callers must use the check
/// entry points so unmanaged paths cannot Accept without a manifest
/// (audit residual P1).
pub(crate) fn compose_with_behavior(
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

    // Fail-closed: even if evidence was constructed without parse_json,
    // refuse Pass when probe.result.status is not "pass".
    if !verdict_status_consistent(evidence.verdict, evidence.probe.result.status.as_str()) {
        report.gates.push(GateResult {
            id: "behavior_verdict_status".to_string(),
            status: GateStatus::Fail,
            detail: Some(format!(
                "verdict={:?} status={} inconsistent",
                evidence.verdict, evidence.probe.result.status
            )),
        });
        report.failures.push(FailureRecord {
            gate_id: "behavior_verdict_status".to_string(),
            code: "verdict_status_inconsistent".to_string(),
            message: format!(
                "behavior evidence verdict {:?} disagrees with probe.result.status '{}'",
                evidence.verdict, evidence.probe.result.status
            ),
        });
        report.verdict = Verdict::Rejected;
        return report;
    }

    // Product Accepted gates (also enforced in parse_json for harness files).
    if evidence.verdict == BehaviorVerdict::Pass {
        if !is_product_probe_id(&evidence.probe.id) {
            report.failures.push(FailureRecord {
                gate_id: "behavior_probe_profile".to_string(),
                code: "unregistered_product_probe".to_string(),
                message: format!(
                    "probe.id '{}' cannot produce product Accepted (loader-only / unknown)",
                    evidence.probe.id
                ),
            });
            report.verdict = Verdict::Rejected;
            return report;
        }
        if !reference_supports_product_accept(&evidence.reference) {
            report.failures.push(FailureRecord {
                gate_id: "behavior_reference".to_string(),
                code: "reference_required_for_accept".to_string(),
                message: format!(
                    "product Accepted requires bilateral reference with sha256 (got kind='{}')",
                    evidence.reference.kind
                ),
            });
            report.verdict = Verdict::Rejected;
            return report;
        }
        if ledger_blocks_product_accept(&evidence.transform_ledger) {
            report.failures.push(FailureRecord {
                gate_id: "behavior_transform_ledger".to_string(),
                code: "transform_ledger_blocks_accept".to_string(),
                message: "non-empty transform_ledger without equivalence_rule — diagnostic only"
                    .to_string(),
            });
            report.verdict = Verdict::Rejected;
            return report;
        }
    }

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
            // Double-check status (defense in depth; also covered above).
            if evidence.probe.result.status != "pass" {
                report.failures.push(FailureRecord {
                    gate_id: "behavior_evidence".to_string(),
                    code: "verdict_status_inconsistent".to_string(),
                    message: "Pass verdict requires probe.result.status=pass".to_string(),
                });
                report.verdict = Verdict::Rejected;
            } else {
                report.verdict = Verdict::Accepted;
            }
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
                message:
                    "behavior evidence Inconclusive; verdict remains StructuralPassBehaviorPending"
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
        // Product Pass needs a bilateral reference digest; other verdicts may use none.
        let reference = if verdict == BehaviorVerdict::Pass {
            BehaviorReference {
                kind: "bilateral".to_string(),
                sha256: Some("cc".repeat(32)),
                notes: Some("unit-test reference".into()),
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
                sha256: sha.to_string(),
                size_bytes: size,
                role: "candidate".to_string(),
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
            transform_ledger: vec![],
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

    #[test]
    fn parse_rejects_pass_verdict_with_fail_status() {
        let j = br#"{"schema_version":"mida.behavior-evidence/v0","candidate":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1,"role":"c"},"reference":{"kind":"none"},"probe":{"id":"x","policy":{"network":"deny","max_wall_ms":1,"max_output_bytes":1},"result":{"status":"fail","exit_code":1,"markers_found":[],"error_class":null}},"verdict":"Pass","residual_risks":[],"producer":{"name":"t","version":"0"}}"#;
        assert!(matches!(
            BehaviorEvidence::parse_json(j),
            Err(BehaviorEvidenceError::VerdictStatusInconsistent { .. })
        ));
    }

    #[test]
    fn compose_rejects_pass_verdict_with_fail_status() {
        let bytes = b"compose-inconsistent-status";
        let dig = sha256_hex(bytes);
        let mut ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Pass);
        // Bypass parse_json and forge inconsistent fields (old harness bug).
        ev.probe.result.status = "fail".to_string();
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(
            out.failures
                .iter()
                .any(|f| f.code == "verdict_status_inconsistent"),
            "{:?}",
            out.failures
        );
    }

    #[test]
    fn arbitrary_equivalence_rule_string_blocks_accept() {
        let bytes = b"forge-equivalence-rule";
        let dig = sha256_hex(bytes);
        let mut ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Pass);
        ev.transform_ledger.push(TransformLedgerEntry {
            id: "gto_bypass_messagebox".into(),
            kind: "sample_bypass".into(),
            // Attacker-chosen free-form rule must NOT unlock Accept.
            equivalence_rule: Some("i_pinky_promise".into()),
        });
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(
            out.failures
                .iter()
                .any(|f| f.code == "transform_ledger_blocks_accept"),
            "{:?}",
            out.failures
        );
    }

    #[test]
    fn registered_equivalence_rule_allows_ledger_entry() {
        let bytes = b"registered-equivalence-rule";
        let dig = sha256_hex(bytes);
        let mut ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Pass);
        ev.transform_ledger.push(TransformLedgerEntry {
            id: "iat_rebuild".into(),
            kind: "pe_repair".into(),
            equivalence_rule: Some("pe_iat_rebuild_v0".into()),
        });
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Accepted, "{:?}", out.failures);
    }

    #[test]
    fn mismatched_transform_id_with_registered_rule_blocks() {
        let bytes = b"mismatched-transform-rule";
        let dig = sha256_hex(bytes);
        let mut ev = sample_evidence(&dig, bytes.len() as u64, BehaviorVerdict::Pass);
        // Wrong pairing: gto bypass claiming pe_iat_rebuild_v0.
        ev.transform_ledger.push(TransformLedgerEntry {
            id: "gto_bypass_messagebox".into(),
            kind: "sample_bypass".into(),
            equivalence_rule: Some("pe_iat_rebuild_v0".into()),
        });
        let out = compose_with_behavior(structural_pass_report(bytes), &ev, bytes);
        assert_eq!(out.verdict, Verdict::Rejected);
        assert!(
            out.failures
                .iter()
                .any(|f| f.code == "transform_ledger_blocks_accept"),
            "{:?}",
            out.failures
        );
    }
}
