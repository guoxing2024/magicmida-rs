//! P9-Prep-B: first-class survival and structural evidence (verifier side).
//!
//! Production `.expect()`s are invariants (WO-12): each site follows a guard
//! that makes the expected value unreachable-None/Err (len-matched slices,
//! `if has_x` + `plan.x` co-check, `match`-bound states, caller-validated
//! member names, re-serialization of an already-parsed Value, FFI
//! kernel32/Sleep existence, or caller pre-checked Option). No production
//! fallible path is masked; the one genuinely reachable panic (bundle_gate
//! member lookup) was converted to error propagation. Test-block expects are
//! ordinary assertions (WO-14).
#![allow(clippy::expect_used)]
//!
//! Survival and structural evidence are made first-class, case-bound,
//! independently verifiable artifacts. A gate's `survival` / `structural` bool
//! must be **derived** from one of these artifacts by this verifier — a caller
//! cannot set it directly.
//!
//! # `OreansEvidenceRef.artifact_sha256` semantics (audited & pinned)
//!
//! The existing gate contract (`crates/acceptance/src/oreans_gate.rs`,
//! [`crate::oreans_gate::OreansEvidenceRef::validate_for_candidate`]) requires
//! `artifact_sha256 == candidate.sha256`: the reference field points at the
//! **candidate artifact** the prerequisite evidence is bound to. It is NOT the
//! hash of the evidence JSON document itself. That existing contract is
//! preserved unchanged here.
//!
//! Because an evidence document needs its own integrity hash, this module adds a
//! **separate, semantically distinct** `artifact_self_sha256` field on each
//! first-class evidence type: it is the sealed hash of the evidence document
//! itself (computed over the canonical document **excluding** the
//! `artifact_self_sha256` field, to avoid self-reference). It must never be
//! mistaken for the candidate hash. The two are independent and both verified.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::oreans_gate::OreansArtifactIdentity;

/// Fixed schema for survival evidence.
pub const SURVIVAL_EVIDENCE_SCHEMA_VERSION: &str = "mida.oreans-survival-evidence/v1";
/// Fixed schema for structural evidence.
pub const STRUCTURAL_EVIDENCE_SCHEMA_VERSION: &str = "mida.oreans-structural-evidence/v1";

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

fn artifact_well_formed(id: &OreansArtifactIdentity) -> bool {
    is_sha256(&id.sha256) && id.size_bytes > 0
}

/// Chain identity (runner / tool / verifier) reused by both evidence types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurvivalChainIdentity {
    pub sha256: String,
    pub version: String,
}

impl SurvivalChainIdentity {
    fn is_well_formed(&self) -> bool {
        is_sha256(&self.sha256) && !self.version.trim().is_empty()
    }
}

/// Completion marker shared by both evidence types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurvivalCompletionMarker {
    pub marker: String,
    pub done: bool,
}

impl SurvivalCompletionMarker {
    fn is_valid(&self) -> bool {
        !self.marker.trim().is_empty() && self.done
    }
}

/// One structural domain result (OEP / IAT / TLS+relocation / section).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralDomainResult {
    pub domain: String,
    pub verdict: StructuralDomainVerdict,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralDomainVerdict {
    Pass,
    Fail,
    Open,
}

/// The sealed Evidence Bundle v2 validation result referenced by structural
/// evidence. `valid`/`complete` come from the independent bundle validator, not
/// from the producer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralBundleValidation {
    pub valid: bool,
    pub complete: bool,
    pub members_sha256: String,
    pub manifest_sha256: String,
    pub reasons: Vec<String>,
}

impl StructuralBundleValidation {
    fn is_well_formed(&self) -> bool {
        self.valid
            && self.complete
            && is_sha256(&self.members_sha256)
            && is_sha256(&self.manifest_sha256)
    }
}

/// First-class structural evidence. The structural gate bool is derived from
/// this artifact by the verifier; it is never caller-set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StructuralEvidence {
    pub schema_version: String,
    pub case_id: String,
    pub candidate: OreansArtifactIdentity,
    pub bundle_validation: StructuralBundleValidation,
    pub domains: Vec<StructuralDomainResult>,
    pub runner_identity: SurvivalChainIdentity,
    pub tool_identity: SurvivalChainIdentity,
    pub verifier_identity: SurvivalChainIdentity,
    pub tool_revision: String,
    pub completion: SurvivalCompletionMarker,
    pub reason: String,
    /// Sealed hash of this evidence document (excluding this field). Distinct
    /// from `candidate.sha256`.
    pub artifact_self_sha256: String,
}

/// Process creation / lifecycle observation for survival evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurvivalProcessObservation {
    pub observed_creation: bool,
    pub pid: u64,
    pub start_time: String,
    pub end_time: String,
    pub observation_window_ms: u64,
}

impl SurvivalProcessObservation {
    fn is_well_formed(&self) -> bool {
        self.observed_creation
            && self.pid != 0
            && !self.start_time.trim().is_empty()
            && !self.end_time.trim().is_empty()
            && self.observation_window_ms > 0
    }
}

/// Exit / termination observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurvivalExitObservation {
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub timeout: bool,
    pub forced_termination: bool,
}

impl SurvivalExitObservation {
    fn is_clean_exit(&self) -> bool {
        self.exit_code == Some(0)
            && self.signal.is_none()
            && !self.timeout
            && !self.forced_termination
    }
}

/// Survival verdict. A survival Pass requires a clean observed exit within the
/// window; it is independent of behavior equivalence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurvivalVerdict {
    Pass,
    Fail,
    Timeout,
    ForcedTermination,
    NotRun,
}

/// First-class survival evidence. The survival gate bool is derived from this
/// artifact by the verifier; it is never caller-set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurvivalEvidence {
    pub schema_version: String,
    pub case_id: String,
    pub protected_input: OreansArtifactIdentity,
    pub candidate: OreansArtifactIdentity,
    pub process: SurvivalProcessObservation,
    pub exit: SurvivalExitObservation,
    pub verdict: SurvivalVerdict,
    pub runner_identity: SurvivalChainIdentity,
    pub tool_identity: SurvivalChainIdentity,
    pub verifier_identity: SurvivalChainIdentity,
    pub tool_revision: String,
    pub candidate_digest: String,
    pub completion: SurvivalCompletionMarker,
    pub reason: String,
    /// Sealed hash of this evidence document (excluding this field). Distinct
    /// from `candidate_digest` / `candidate.sha256`.
    pub artifact_self_sha256: String,
}

#[derive(Debug, Error)]
pub enum SurvivalStructuralEvidenceError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("survival schema_version '{0}' is not {SURVIVAL_EVIDENCE_SCHEMA_VERSION}")]
    SurvivalSchema(String),
    #[error("structural schema_version '{0}' is not {STRUCTURAL_EVIDENCE_SCHEMA_VERSION}")]
    StructuralSchema(String),
    #[error("case_id is empty or not a fixed Oreans case")]
    BadCase,
    #[error("protected_input identity is malformed")]
    BadProtected,
    #[error("candidate identity is malformed")]
    BadCandidate,
    #[error("tool_revision is empty")]
    EmptyToolRevision,
    #[error("candidate_digest does not match candidate.sha256")]
    CandidateDigestMismatch,
    #[error("chain identity is malformed")]
    BadChainIdentity,
    #[error("completion marker is incomplete")]
    BadCompletion,
    #[error("reason is empty")]
    EmptyReason,
    #[error("process observation is malformed or creation not observed")]
    BadProcess,
    #[error("exit observation is malformed")]
    BadExit,
    #[error("survival verdict is not pass")]
    SurvivalNotPass,
    #[error("structural bundle validation is invalid/incomplete or hash malformed")]
    BadBundleValidation,
    #[error("no structural domains present")]
    EmptyDomains,
    #[error("structural domain '{0}' is not pass")]
    DomainNotPass(String),
    #[error("sealed self hash mismatch: document '{0}' != declared '{1}'")]
    SelfHashMismatch(String, String),
    #[error("unknown field present in schema (deny_unknown_fields)")]
    UnknownField,
}

/// Compute the sealed self-hash of an evidence document: serialize, drop the
/// `artifact_self_sha256` field, hash the remainder.
fn sealed_self_hash(value: &serde_json::Value) -> String {
    let mut v = value.clone();
    if let serde_json::Value::Object(map) = &mut v {
        map.remove("artifact_self_sha256");
    }
    crate::sha256_hex(&serde_json::to_vec(&v).expect("canonical doc"))
}

fn check_self_hash(
    doc: &serde_json::Value,
    declared: &str,
) -> Result<(), SurvivalStructuralEvidenceError> {
    if !is_sha256(declared) {
        return Err(SurvivalStructuralEvidenceError::SelfHashMismatch(
            "not-64-hex".into(),
            declared.to_string(),
        ));
    }
    let computed = sealed_self_hash(doc);
    if computed != declared {
        return Err(SurvivalStructuralEvidenceError::SelfHashMismatch(
            computed,
            declared.to_string(),
        ));
    }
    Ok(())
}

/// Trusted expected identities the verifier binds survival/structural evidence
/// to. Supplied by the caller from trusted source (locked manifest + rebuilt
/// binaries). `runner`/`tool`/`verifier` are the chain identities expected; for
/// structural evidence, `expected_bundle_members_sha256` /
/// `expected_bundle_manifest_sha256` are the sealed bundle hashes.
#[derive(Debug, Clone)]
pub struct ExpectedEvidenceBinding {
    pub runner: SurvivalChainIdentity,
    pub tool: SurvivalChainIdentity,
    pub verifier: SurvivalChainIdentity,
    pub bundle_members_sha256: Option<String>,
    pub bundle_manifest_sha256: Option<String>,
}

impl ExpectedEvidenceBinding {
    pub fn new(
        runner: SurvivalChainIdentity,
        tool: SurvivalChainIdentity,
        verifier: SurvivalChainIdentity,
    ) -> Self {
        Self {
            runner,
            tool,
            verifier,
            bundle_members_sha256: None,
            bundle_manifest_sha256: None,
        }
    }

    pub fn with_bundle_hashes(mut self, members_sha256: String, manifest_sha256: String) -> Self {
        self.bundle_members_sha256 = Some(members_sha256);
        self.bundle_manifest_sha256 = Some(manifest_sha256);
        self
    }
}

/// Bind the chain identities in an evidence document to the trusted expectation.
fn check_chain_binding(
    evidence_runner: &SurvivalChainIdentity,
    evidence_tool: &SurvivalChainIdentity,
    evidence_verifier: &SurvivalChainIdentity,
    expected: &ExpectedEvidenceBinding,
) -> Result<(), SurvivalStructuralEvidenceError> {
    if evidence_runner != &expected.runner
        || evidence_tool != &expected.tool
        || evidence_verifier != &expected.verifier
    {
        return Err(SurvivalStructuralEvidenceError::BadChainIdentity);
    }
    Ok(())
}

/// Parse + fully verify survival evidence against an expected binding and the
/// sealed self-hash. Returns the derived survival bool (and the verdict).
pub fn verify_survival_evidence(
    bytes: &[u8],
    expected_case: &str,
    expected_candidate: &OreansArtifactIdentity,
    expected_protected: &OreansArtifactIdentity,
    expected_binding: &ExpectedEvidenceBinding,
) -> Result<(SurvivalVerdict, bool), SurvivalStructuralEvidenceError> {
    let doc: serde_json::Value = serde_json::from_slice(bytes)?;
    let evidence: SurvivalEvidence = serde_json::from_slice(bytes)?;
    if evidence.schema_version != SURVIVAL_EVIDENCE_SCHEMA_VERSION {
        return Err(SurvivalStructuralEvidenceError::SurvivalSchema(
            evidence.schema_version,
        ));
    }
    check_self_hash(&doc, &evidence.artifact_self_sha256)?;
    if evidence.case_id != expected_case {
        return Err(SurvivalStructuralEvidenceError::BadCase);
    }
    if !artifact_well_formed(&evidence.protected_input)
        || &evidence.protected_input != expected_protected
    {
        return Err(SurvivalStructuralEvidenceError::BadProtected);
    }
    if !artifact_well_formed(&evidence.candidate) || &evidence.candidate != expected_candidate {
        return Err(SurvivalStructuralEvidenceError::BadCandidate);
    }
    if evidence.tool_revision.trim().is_empty() {
        return Err(SurvivalStructuralEvidenceError::EmptyToolRevision);
    }
    if evidence.candidate_digest != evidence.candidate.sha256 {
        return Err(SurvivalStructuralEvidenceError::CandidateDigestMismatch);
    }
    if !evidence.runner_identity.is_well_formed()
        || !evidence.tool_identity.is_well_formed()
        || !evidence.verifier_identity.is_well_formed()
    {
        return Err(SurvivalStructuralEvidenceError::BadChainIdentity);
    }
    check_chain_binding(
        &evidence.runner_identity,
        &evidence.tool_identity,
        &evidence.verifier_identity,
        expected_binding,
    )?;
    if !evidence.completion.is_valid() {
        return Err(SurvivalStructuralEvidenceError::BadCompletion);
    }
    if evidence.reason.trim().is_empty() {
        return Err(SurvivalStructuralEvidenceError::EmptyReason);
    }
    if !evidence.process.is_well_formed() {
        return Err(SurvivalStructuralEvidenceError::BadProcess);
    }
    if evidence.exit.signal.is_some() && evidence.exit.signal.as_deref() == Some("") {
        return Err(SurvivalStructuralEvidenceError::BadExit);
    }
    if evidence.verdict == SurvivalVerdict::NotRun {
        return Err(SurvivalStructuralEvidenceError::SurvivalNotPass);
    }
    // The survival bool is derived: Pass iff clean observed exit within window.
    let derived = evidence.verdict == SurvivalVerdict::Pass && evidence.exit.is_clean_exit();
    Ok((evidence.verdict, derived))
}

/// Parse + fully verify structural evidence against an expected binding and the
/// sealed self-hash. Returns the derived structural bool.
pub fn verify_structural_evidence(
    bytes: &[u8],
    expected_case: &str,
    expected_candidate: &OreansArtifactIdentity,
    expected_binding: &ExpectedEvidenceBinding,
) -> Result<bool, SurvivalStructuralEvidenceError> {
    let doc: serde_json::Value = serde_json::from_slice(bytes)?;
    let evidence: StructuralEvidence = serde_json::from_slice(bytes)?;
    if evidence.schema_version != STRUCTURAL_EVIDENCE_SCHEMA_VERSION {
        return Err(SurvivalStructuralEvidenceError::StructuralSchema(
            evidence.schema_version,
        ));
    }
    check_self_hash(&doc, &evidence.artifact_self_sha256)?;
    if evidence.case_id != expected_case {
        return Err(SurvivalStructuralEvidenceError::BadCase);
    }
    if !artifact_well_formed(&evidence.candidate) || &evidence.candidate != expected_candidate {
        return Err(SurvivalStructuralEvidenceError::BadCandidate);
    }
    if evidence.tool_revision.trim().is_empty() {
        return Err(SurvivalStructuralEvidenceError::EmptyToolRevision);
    }
    if !evidence.runner_identity.is_well_formed()
        || !evidence.tool_identity.is_well_formed()
        || !evidence.verifier_identity.is_well_formed()
    {
        return Err(SurvivalStructuralEvidenceError::BadChainIdentity);
    }
    check_chain_binding(
        &evidence.runner_identity,
        &evidence.tool_identity,
        &evidence.verifier_identity,
        expected_binding,
    )?;
    if !evidence.completion.is_valid() {
        return Err(SurvivalStructuralEvidenceError::BadCompletion);
    }
    if evidence.reason.trim().is_empty() {
        return Err(SurvivalStructuralEvidenceError::EmptyReason);
    }
    if !evidence.bundle_validation.is_well_formed() {
        return Err(SurvivalStructuralEvidenceError::BadBundleValidation);
    }
    // Bind the sealed bundle hashes to the trusted expectation when provided.
    if let Some(expected_members) = &expected_binding.bundle_members_sha256 {
        if evidence.bundle_validation.members_sha256 != *expected_members {
            return Err(SurvivalStructuralEvidenceError::BadBundleValidation);
        }
    }
    if let Some(expected_manifest) = &expected_binding.bundle_manifest_sha256 {
        if evidence.bundle_validation.manifest_sha256 != *expected_manifest {
            return Err(SurvivalStructuralEvidenceError::BadBundleValidation);
        }
    }
    if evidence.domains.is_empty() {
        return Err(SurvivalStructuralEvidenceError::EmptyDomains);
    }
    // The structural bool is derived from the bundle validator + every domain.
    let all_domains_pass = evidence
        .domains
        .iter()
        .all(|d| d.verdict == StructuralDomainVerdict::Pass && !d.reason.trim().is_empty());
    if !all_domains_pass {
        let first = evidence
            .domains
            .iter()
            .find(|d| d.verdict != StructuralDomainVerdict::Pass)
            .map(|d| d.domain.clone())
            .unwrap_or_else(|| "unknown".to_string());
        return Err(SurvivalStructuralEvidenceError::DomainNotPass(first));
    }
    Ok(evidence.bundle_validation.valid && evidence.bundle_validation.complete)
}

/// The documented, pinned contract of the existing `OreansEvidenceRef` field
/// (see module docs): `artifact_sha256` equals the candidate SHA-256, not the
/// evidence document's own hash. Any evidence artifact's own integrity hash is
/// carried separately in `artifact_self_sha256`.
pub const ARTIFACT_SHA256_SEMANTIC_PIN: &str = concat!(
    "OreansEvidenceRef.artifact_sha256 == candidate.sha256 (existing gate ",
    "contract, unchanged). It references the candidate artifact the prerequisite ",
    "evidence is bound to; it is NOT the hash of the evidence JSON document. ",
    "Evidence document integrity is carried separately in the first-class ",
    "artifact_self_sha256 (sealed hash of the document excluding that field). ",
    "The two must never be conflated."
);

#[cfg(test)]
mod tests {
    use super::*;

    fn sha(s: &str) -> String {
        crate::sha256_hex(s.as_bytes())
    }

    fn id(tag: &str) -> OreansArtifactIdentity {
        OreansArtifactIdentity {
            sha256: sha(tag),
            size_bytes: 4096,
        }
    }

    fn expected_binding() -> ExpectedEvidenceBinding {
        ExpectedEvidenceBinding::new(
            SurvivalChainIdentity {
                sha256: sha("runner"),
                version: "r1".to_string(),
            },
            SurvivalChainIdentity {
                sha256: sha("tool"),
                version: "t1".to_string(),
            },
            SurvivalChainIdentity {
                sha256: sha("verifier"),
                version: "v1".to_string(),
            },
        )
    }

    /// Expected binding that also pins the sealed bundle hashes used by the
    /// structural evidence fixtures (`sha("members")`, `sha("manifest")`).
    fn expected_binding_with_bundle() -> ExpectedEvidenceBinding {
        ExpectedEvidenceBinding::new(
            SurvivalChainIdentity {
                sha256: sha("runner"),
                version: "r1".to_string(),
            },
            SurvivalChainIdentity {
                sha256: sha("tool"),
                version: "t1".to_string(),
            },
            SurvivalChainIdentity {
                sha256: sha("verifier"),
                version: "v1".to_string(),
            },
        )
        .with_bundle_hashes(sha("members"), sha("manifest"))
    }

    /// Build a valid survival evidence JSON, then compute and inject the sealed
    /// self-hash so the document is internally consistent.
    fn survival_json() -> serde_json::Value {
        let mut v = serde_json::json!({
            "schema_version": SURVIVAL_EVIDENCE_SCHEMA_VERSION,
            "case_id": "origin_macro",
            "protected_input": { "sha256": sha("protected"), "size_bytes": 4096 },
            "candidate": { "sha256": sha("candidate"), "size_bytes": 4096 },
            "process": {
                "observed_creation": true,
                "pid": 1234,
                "start_time": "2026-08-06T00:00:00Z",
                "end_time": "2026-08-06T00:00:05Z",
                "observation_window_ms": 5000
            },
            "exit": { "exit_code": 0, "signal": null, "timeout": false, "forced_termination": false },
            "verdict": "pass",
            "runner_identity": { "sha256": sha("runner"), "version": "r1" },
            "tool_identity": { "sha256": sha("tool"), "version": "t1" },
            "verifier_identity": { "sha256": sha("verifier"), "version": "v1" },
            "tool_revision": "oreans/two-sample-mainline@1",
            "candidate_digest": sha("candidate"),
            "completion": { "marker": "done", "done": true },
            "reason": "process survived the observation window with a clean exit"
        });
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        v
    }

    fn structural_json() -> serde_json::Value {
        let mut v = serde_json::json!({
            "schema_version": STRUCTURAL_EVIDENCE_SCHEMA_VERSION,
            "case_id": "origin_macro",
            "candidate": { "sha256": sha("candidate"), "size_bytes": 4096 },
            "bundle_validation": {
                "valid": true,
                "complete": true,
                "members_sha256": sha("members"),
                "manifest_sha256": sha("manifest"),
                "reasons": []
            },
            "domains": [
                { "domain": "oep", "verdict": "pass", "reason": "OEP provenance matches" },
                { "domain": "iat", "verdict": "pass", "reason": "IAT resolved" },
                { "domain": "tls_reloc", "verdict": "pass", "reason": "TLS and relocation coherent" },
                { "domain": "section", "verdict": "pass", "reason": "sections rebuilt" }
            ],
            "runner_identity": { "sha256": sha("runner"), "version": "r1" },
            "tool_identity": { "sha256": sha("tool"), "version": "t1" },
            "verifier_identity": { "sha256": sha("verifier"), "version": "v1" },
            "tool_revision": "oreans/two-sample-mainline@1",
            "completion": { "marker": "done", "done": true },
            "reason": "all structured domains pass and bundle is valid"
        });
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        v
    }

    #[test]
    fn verifies_valid_survival_evidence() {
        let (verdict, derived) = verify_survival_evidence(
            &serde_json::to_vec(&survival_json()).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap();
        assert_eq!(verdict, SurvivalVerdict::Pass);
        assert!(derived);
    }

    #[test]
    fn verifies_valid_structural_evidence() {
        let derived = verify_structural_evidence(
            &serde_json::to_vec(&structural_json()).unwrap(),
            "origin_macro",
            &id("candidate"),
            &expected_binding_with_bundle(),
        )
        .unwrap();
        assert!(derived);
    }

    #[test]
    fn rejects_unknown_field() {
        let mut v = survival_json();
        v["bogus"] = serde_json::json!(1);
        assert!(verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding()
        )
        .is_err());
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let mut v = survival_json();
        v["schema_version"] = "mida.unknown/v9".into();
        assert!(verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding()
        )
        .is_err());
    }

    #[test]
    fn rejects_wrong_candidate_sha() {
        let mut v = survival_json();
        v["candidate"] = serde_json::json!({ "sha256": sha("other"), "size_bytes": 4096 });
        // Re-seal so the document is self-consistent but binds to a wrong candidate.
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        assert!(matches!(err, SurvivalStructuralEvidenceError::BadCandidate));
    }

    #[test]
    fn rejects_candidate_digest_mismatch_with_candidate_hash() {
        let mut v = survival_json();
        v["candidate_digest"] = sha("other").into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SurvivalStructuralEvidenceError::CandidateDigestMismatch
        ));
    }

    #[test]
    fn rejects_report_hash_mistaken_for_candidate_hash() {
        // If a producer mistakes the evidence report hash for the candidate hash,
        // artifact_self_sha256 would equal candidate.sha256 and fail the sealed
        // self-hash recomputation. This proves the two are distinct.
        let mut v = survival_json();
        // Overwrite the sealed self-hash with the candidate hash: not the sealed doc hash.
        v["artifact_self_sha256"] = sha("candidate").into();
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SurvivalStructuralEvidenceError::SelfHashMismatch(_, _)
        ));
    }

    #[test]
    fn rejects_stale_artifact_via_self_hash_tamper() {
        // Tamper a field after sealing: the sealed self-hash no longer matches.
        let mut v = survival_json();
        v["process"]["pid"] = serde_json::json!(9999);
        // Do NOT re-seal: this simulates a stale/partial artifact whose content
        // changed after sealing.
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SurvivalStructuralEvidenceError::SelfHashMismatch(_, _)
        ));
    }

    #[test]
    fn rejects_identity_swap_survival() {
        let mut v = survival_json();
        let cand = v["candidate"].clone();
        let prot = v["protected_input"].clone();
        v["candidate"] = prot;
        v["protected_input"] = cand;
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        // After swap, protected_input no longer matches the expected protected
        // identity (verifier checks protected before candidate).
        assert!(matches!(err, SurvivalStructuralEvidenceError::BadProtected));
    }

    #[test]
    fn rejects_runner_digest_drift_survival() {
        let mut v = survival_json();
        v["runner_identity"]["sha256"] = sha("other-runner").into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SurvivalStructuralEvidenceError::BadChainIdentity
        ));
    }

    #[test]
    fn rejects_empty_reason() {
        let mut v = survival_json();
        v["reason"] = "".into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        assert!(matches!(err, SurvivalStructuralEvidenceError::EmptyReason));
    }

    #[test]
    fn rejects_survival_timeout() {
        let mut v = survival_json();
        v["exit"]["timeout"] = serde_json::json!(true);
        v["verdict"] = "timeout".into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        // Timeout is not a Pass; the derived bool must be false.
        let (verdict, derived) = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap();
        assert_eq!(verdict, SurvivalVerdict::Timeout);
        assert!(!derived);
    }

    #[test]
    fn rejects_survival_forced_kill() {
        let mut v = survival_json();
        v["exit"]["forced_termination"] = serde_json::json!(true);
        v["verdict"] = "forced_termination".into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let (verdict, derived) = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap();
        assert_eq!(verdict, SurvivalVerdict::ForcedTermination);
        assert!(!derived);
    }

    #[test]
    fn survival_pass_does_not_imply_behavior_pass() {
        // Survival Pass derives true; behavior equivalence is a separate contract
        // (P9-Prep-A). This documents that the two bools are independent.
        let (_, survival_derived) = verify_survival_evidence(
            &serde_json::to_vec(&survival_json()).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap();
        assert!(survival_derived);
        // No behavior gate is touched by this module.
    }

    #[test]
    fn rejects_structural_bundle_hash_drift() {
        let mut v = structural_json();
        v["bundle_validation"]["members_sha256"] = sha("drifted-members").into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_structural_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &expected_binding_with_bundle(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SurvivalStructuralEvidenceError::BadBundleValidation
        ));
    }

    #[test]
    fn rejects_structural_domain_open_or_fail() {
        // One domain Open -> not pass.
        let mut v = structural_json();
        v["domains"][1]["verdict"] = "open".into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_structural_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &expected_binding_with_bundle(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SurvivalStructuralEvidenceError::DomainNotPass(_)
        ));

        // One domain Fail with empty reason -> fail.
        let mut v = structural_json();
        v["domains"][0]["verdict"] = "fail".into();
        v["domains"][0]["reason"] = "".into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        assert!(verify_structural_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &expected_binding_with_bundle()
        )
        .is_err());
    }

    #[test]
    fn rejects_bundle_invalid_in_structural() {
        let mut v = structural_json();
        v["bundle_validation"]["valid"] = serde_json::json!(false);
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_structural_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &expected_binding_with_bundle(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            SurvivalStructuralEvidenceError::BadBundleValidation
        ));
    }

    #[test]
    fn bool_derived_not_caller_set() {
        // The schema carries no caller bool. Verify there is no survival/structural
        // bool field a caller could set directly.
        let v = survival_json();
        assert!(v.get("survival").is_none());
        let v = structural_json();
        assert!(v.get("structural").is_none());
    }

    #[test]
    fn rejects_empty_structural_domains() {
        let mut v = structural_json();
        v["domains"] = serde_json::json!([]);
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_structural_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &expected_binding_with_bundle(),
        )
        .unwrap_err();
        assert!(matches!(err, SurvivalStructuralEvidenceError::EmptyDomains));
    }

    #[test]
    fn honest_recompute_self_hash_identity_attack() {
        // Attacker swaps the case and re-seals honestly; the trusted expected
        // binding still rejects the wrong case.
        let mut v = survival_json();
        v["case_id"] = "lunlun_software".into();
        let h = sealed_self_hash(&v);
        v["artifact_self_sha256"] = h.into();
        let err = verify_survival_evidence(
            &serde_json::to_vec(&v).unwrap(),
            "origin_macro",
            &id("candidate"),
            &id("protected"),
            &expected_binding(),
        )
        .unwrap_err();
        assert!(matches!(err, SurvivalStructuralEvidenceError::BadCase));
    }
}
