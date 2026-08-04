//! Bundle-envelope gate entry (P5): the v8 gate consumes evidence bundles.
//!
//! `evaluate_bundle_gate` is the only gate entry that accepts raw evidence
//! bundles (`mida.oreans-evidence-bundle/v2`). It is fail-closed by
//! construction:
//!
//! 1. every bundle must first pass `validate_evidence_bundle` — bare
//!    sidecars, v1 manifests, partial markers, hash/identity tampering,
//!    schema drift and unknown fields are rejected before any gate logic
//!    runs;
//! 2. the bundle `case_id` must be one of the two fixed Oreans cases, and
//!    the bundle's `protected_input` identity must match the locked
//!    manifest (cross-checked against `lab/cases/v2` via
//!    [`locked_manifest`]);
//! 3. every required sidecar is re-parsed from the envelope bytes into the
//!    gate's structured types — a sidecar that the independent consumer
//!    cannot parse aborts the gate;
//! 4. the resulting observations are evaluated by the v8 two-sample gate.
//!
//! Prerequisite, behavior-oracle and isolated-replay evidence are not part
//! of the v2 bundle contract; they enter as explicit empty/not-run records,
//! which keeps the corresponding gates open until their evidence exists.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::evidence_bundle::{validate_evidence_bundle, OreansEvidenceBundle};
use crate::oreans_gate::{
    evaluate_oreans_two_sample_gate, locked_manifest, OreansArtifactIdentity,
    OreansBehaviorEvidence, OreansEvidenceRef, OreansFinalBehaviorVerdict, OreansIsolatedReplay,
    OreansPrerequisites, OreansSampleObservation, OreansTwoSampleGateReport,
    OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION, OREANS_ISOLATED_REPLAY_SCHEMA_VERSION,
    OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION,
};

/// Schema id of the bundle-gate report.
pub const BUNDLE_GATE_SCHEMA_VERSION: &str = "mida.oreans-two-sample-bundle-gate/v1";

/// Stable gate id.
pub const BUNDLE_GATE_ID: &str = "oreans_two_sample_bundle_gate";

/// One envelope (bundle manifest + member bytes) for one sample.
#[derive(Debug, Clone)]
pub struct BundleInput<'a> {
    pub bundle: &'a OreansEvidenceBundle,
    pub files: &'a BTreeMap<String, Vec<u8>>,
}

/// Per-case envelope binding recorded in the gate report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleEnvelopeBinding {
    pub case_id: String,
    pub members_sha256: String,
    pub manifest_sha256: String,
    /// `protected_input` in the bundle matched the locked case manifest.
    pub protected_input_matched: bool,
}

/// Fail-closed errors raised before/while running the gate on envelopes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BundleGateError {
    #[error("bundle is not a valid run: {0:?}")]
    InvalidBundle(Vec<String>),
    #[error("bundle case_id '{0}' is not one of the two fixed Oreans cases")]
    CaseNotAllowed(String),
    #[error(
        "bundle protected_input {sha256} ({size_bytes} bytes) does not match the locked manifest for '{case_id}'"
    )]
    ProtectedInputMismatch {
        case_id: String,
        sha256: String,
        size_bytes: u64,
    },
    #[error("member '{0}' did not parse into the gate schema: {1}")]
    SidecarParse(String, String),
    #[error("gate evaluation failed: {0}")]
    Gate(String),
}

/// Report binding the two-sample gate verdict to the envelope digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleGateReport {
    pub schema_version: String,
    pub gate_id: String,
    pub envelopes: Vec<BundleEnvelopeBinding>,
    pub gate: OreansTwoSampleGateReport,
}

fn empty_evidence_ref(summary: &str) -> OreansEvidenceRef {
    OreansEvidenceRef {
        schema_version: OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION.to_string(),
        producer: "bundle-gate".to_string(),
        artifact_sha256: String::new(),
        summary: summary.to_string(),
    }
}

fn empty_prerequisites() -> OreansPrerequisites {
    OreansPrerequisites {
        survival: false,
        structural: false,
        survival_evidence: empty_evidence_ref("no survival evidence in bundle"),
        structural_evidence: empty_evidence_ref("no structural evidence in bundle"),
    }
}

fn empty_behavior(
    protected: &OreansArtifactIdentity,
    candidate: &OreansArtifactIdentity,
) -> OreansBehaviorEvidence {
    OreansBehaviorEvidence {
        schema_version: OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION.to_string(),
        stimuli: Vec::new(),
        observables: Vec::new(),
        candidate_identity: candidate.clone(),
        protected_identity: protected.clone(),
        verdict: OreansFinalBehaviorVerdict::NotRun,
        reason: "no behavior oracle evidence in bundle".to_string(),
    }
}

fn empty_replay() -> OreansIsolatedReplay {
    OreansIsolatedReplay {
        schema_version: OREANS_ISOLATED_REPLAY_SCHEMA_VERSION.to_string(),
        attempts: Vec::new(),
    }
}

/// Re-parse one envelope member into the gate's structured type.
fn parse_member<T: serde::de::DeserializeOwned>(
    name: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<T, BundleGateError> {
    let bytes = files
        .get(name)
        .expect("required member verified present by bundle validation");
    serde_json::from_slice(bytes)
        .map_err(|e| BundleGateError::SidecarParse(name.to_string(), e.to_string()))
}

/// Build the v8 observation for one envelope.
fn parse_observation(
    bundle: &OreansEvidenceBundle,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<OreansSampleObservation, BundleGateError> {
    let protected_input = OreansArtifactIdentity {
        sha256: bundle.protected_input.sha256.clone(),
        size_bytes: bundle.protected_input.size_bytes,
    };
    let candidate = OreansArtifactIdentity {
        sha256: bundle.candidate.sha256.clone(),
        size_bytes: bundle.candidate.size_bytes,
    };
    Ok(OreansSampleObservation {
        case_id: bundle.case_id.clone(),
        protected_input: protected_input.clone(),
        candidate: candidate.clone(),
        pe_evidence: parse_member("pe_evidence", files)?,
        oep_evidence: parse_member("oep_evidence", files)?,
        iat_evidence: parse_member("iat_evidence", files)?,
        tls_evidence: parse_member("tls_evidence", files)?,
        relocation_evidence: parse_member("relocation_evidence", files)?,
        section_rebuild_evidence: parse_member("section_rebuild_evidence", files)?,
        prerequisites: empty_prerequisites(),
        behavior_evidence: empty_behavior(&protected_input, &candidate),
        isolated_replay: empty_replay(),
    })
}

/// Evaluate the v8 two-sample gate strictly from bundle envelopes.
///
/// `inputs` must contain exactly one valid envelope per fixed Oreans case.
/// Any invalid envelope, non-gate case, manifest mismatch, or unparsable
/// sidecar aborts the whole gate (fail-closed, nothing is reported as
/// passed).
pub fn evaluate_bundle_gate(
    inputs: &[BundleInput<'_>],
) -> Result<BundleGateReport, BundleGateError> {
    let mut observations = Vec::with_capacity(inputs.len());
    let mut envelopes = Vec::with_capacity(inputs.len());
    for input in inputs {
        let verdict = validate_evidence_bundle(input.bundle, input.files);
        if !verdict.valid {
            return Err(BundleGateError::InvalidBundle(verdict.reasons));
        }
        let manifest = locked_manifest(&input.bundle.case_id)
            .ok_or_else(|| BundleGateError::CaseNotAllowed(input.bundle.case_id.clone()))?;
        let protected_matched = input.bundle.protected_input.sha256.to_lowercase()
            == manifest.protected_input_sha256.to_lowercase()
            && input.bundle.protected_input.size_bytes == manifest.protected_input_size_bytes;
        if !protected_matched {
            return Err(BundleGateError::ProtectedInputMismatch {
                case_id: input.bundle.case_id.clone(),
                sha256: input.bundle.protected_input.sha256.clone(),
                size_bytes: input.bundle.protected_input.size_bytes,
            });
        }
        observations.push(parse_observation(input.bundle, input.files)?);
        envelopes.push(BundleEnvelopeBinding {
            case_id: input.bundle.case_id.clone(),
            members_sha256: input.bundle.members_sha256.clone(),
            manifest_sha256: input.bundle.manifest_sha256.clone(),
            protected_input_matched: true,
        });
    }

    let gate = evaluate_oreans_two_sample_gate(&observations)
        .map_err(|e| BundleGateError::Gate(e.to_string()))?;
    Ok(BundleGateReport {
        schema_version: BUNDLE_GATE_SCHEMA_VERSION.to_string(),
        gate_id: BUNDLE_GATE_ID.to_string(),
        envelopes,
        gate,
    })
}
