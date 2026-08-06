//! P9-Prep-A: case-bound behavior oracle contract (independent verifier side).
//!
//! A strict, independently verifiable, fail-closed behavior-oracle contract for
//! the two fixed Oreans cases. This module is the **verifier** — it never runs a
//! probe, never opens a sample, and never imports a producer crate. The producer
//! side writes `mida.oreans-behavior-oracle-contract/v1` evidence JSON; this
//! module re-parses it into independent serde types and recomputes every verdict
//! from recorded observations plus deterministic comparators.
//!
//! # Fail-closed rules
//!
//! - Schema is a fixed version and `deny_unknown_fields`.
//! - Evidence binds all of: `case_id`, protected-input identity, candidate
//!   identity, `tool_revision`, `runner_config_digest`, CLI identity, verifier
//!   identity, stimulus-plan identity, execution identity, `emitted_at`, and a
//!   completion marker.
//! - `stimuli` and `observables` must be non-empty; every `id`/`value` must be
//!   non-empty and unique.
//! - An observable's verdict is **not** caller-supplied. It is recomputed by
//!   this verifier from the recorded `observed` value and a deterministic
//!   comparator (`Matching`, `NonEmpty`, `ExitCodeZero`, `MarkerPresent`). A
//!   caller cannot pass `Pass` directly.
//! - The final verdict is recomputed here from all observables: every observable
//!   must be `Pass`; any `Missing`/`NotRun`/`Unknown`/`Malformed`/`Timeout`/
//!   `Partial`/`Mismatch` fails the whole contract. `reason` must be non-empty.
//! - The protected and candidate must have run the **same** canonical stimulus
//!   plan (`stimulus_plan_sha256` must match the canonical plan registry). A side
//!   cannot add/remove/reorder/change a stimulus.
//! - Equivalence manufacture is rejected: a server/icon patch, forced visibility,
//!   skipped product code, semantic bypass, case-specific success override, or a
//!   "return Pass based on sample hash" override is a hard error.
//! - Producer and verifier keep independent serde types and independent
//!   canonical/digest implementations; the verifier never depends on a producer
//!   crate.
//!
//! # Stimulus/observable definition status
//!
//! The **contract types and verifier** are fully implemented here offline. The
//! case-specific **business** stimulus/observable definitions are intentionally
//! NOT fabricated: they cannot be derived offline from the locked manifests
//! (`origin_macro` exposes only a `legacy_oracle_candidate` for regression
//! comparison; `lunlun_software` declares `oracle: none`) or from the plan docs
//! (`docs/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md` lists "define the behavior
//! oracle" as an outstanding item). The verifier therefore accepts
//! **contract-shaped** evidence (for offline tests) while the per-case business
//! stimuli/observables remain a **P9-live blocker** (see
//! [`crate::behavior_oracle_contract::blocker`]). See the P9-Prep-A doc.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::oreans_gate::OreansArtifactIdentity;

/// Fixed schema version for the case-bound behavior oracle contract.
pub const BEHAVIOR_ORACLE_CONTRACT_SCHEMA_VERSION: &str = "mida.oreans-behavior-oracle-contract/v1";

/// Number of fixed cases the contract is bound to.
pub const CONTRACT_REQUIRED_CASES: &[&str] = &["origin_macro", "lunlun_software"];

/// The two allowed case ids. Reused from the gate's fixed set (origin_macro,
/// lunlun_software); non-gate cases are rejected.
fn allowed_case(case_id: &str) -> bool {
    CONTRACT_REQUIRED_CASES.contains(&case_id)
}

/// 64-hex lowercase check shared by contract digest fields.
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

/// Local well-formedness check for an artifact identity. The verifier keeps its
/// own identity validation so it does not depend on the gate's private method.
fn artifact_is_well_formed(identity: &OreansArtifactIdentity) -> bool {
    is_sha256(&identity.sha256) && identity.size_bytes > 0
}

/// Identity of one actor in the behavior chain (CLI, verifier, stimulus plan,
/// execution). `sha256` binds the exact bytes; `version` is a human-readable
/// label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorChainIdentity {
    pub sha256: String,
    pub version: String,
}

impl BehaviorChainIdentity {
    fn is_well_formed(&self) -> bool {
        is_sha256(&self.sha256) && !self.version.trim().is_empty()
    }
}

/// The canonical stimulus plan the protected input and the candidate both ran.
/// The plan is identified by its content hash so both sides provably ran the
/// same plan; per-case business plan content is a P9-live input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StimulusPlanRef {
    pub plan_id: String,
    pub sha256: String,
    pub schema_version: String,
}

impl StimulusPlanRef {
    fn is_well_formed(&self) -> bool {
        !self.plan_id.trim().is_empty()
            && is_sha256(&self.sha256)
            && !self.schema_version.trim().is_empty()
    }
}

/// The execution that collected the observables (probe run).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorExecution {
    pub execution_id: String,
    pub emitted_at: String,
    pub completion: BehaviorCompletionMarker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorCompletionMarker {
    pub marker: String,
    pub done: bool,
}

impl BehaviorExecution {
    fn is_well_formed(&self) -> bool {
        !self.execution_id.trim().is_empty()
            && !self.emitted_at.trim().is_empty()
            && !self.completion.marker.trim().is_empty()
            && self.completion.done
    }
}

/// One stimulus in the canonical plan. `id` must be unique within the plan and
/// `value` non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorStimulus {
    pub id: String,
    pub value: String,
}

/// A deterministic observable comparator. The verifier recomputes the verdict
/// from `observed` + this comparator; it is never caller-supplied as `Pass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorComparator {
    /// `observed == expected` (exact string match, case-sensitive).
    Matching,
    /// `observed` must be non-empty and not a placeholder.
    NonEmpty,
    /// `observed == "0"` (process exit code zero).
    ExitCodeZero,
    /// `observed` must contain the expected marker substring.
    MarkerPresent,
}

/// The raw observed value collected from a probe run (not a verdict).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorObserved {
    pub value: String,
    pub status: BehaviorObservedStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorObservedStatus {
    Collected,
    Missing,
    Timeout,
    Malformed,
    Partial,
}

/// One observable. There is **no** verdict field: the verifier computes the
/// verdict from `observed` + `comparator` + `expected`. A caller cannot pass
/// `Pass`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorObservable {
    pub id: String,
    pub description: String,
    pub observed: BehaviorObserved,
    pub comparator: BehaviorComparator,
    pub expected: String,
}

/// The verdict the verifier recomputes for one observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservableVerdict {
    Pass,
    Mismatch,
    Missing,
    Timeout,
    Malformed,
    Partial,
    Unknown,
}

impl ObservableVerdict {
    pub fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }
}

/// Final contract verdict recomputed by the verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorContractVerdict {
    Pass,
    Fail,
    NotRun,
}

/// Producer-side evidence document. This is the **verifier's** independent serde
/// type; it does not depend on any producer crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorOracleContractEvidence {
    pub schema_version: String,
    pub case_id: String,
    pub protected_input: OreansArtifactIdentity,
    pub candidate: OreansArtifactIdentity,
    pub tool_revision: String,
    pub runner_config_digest: String,
    pub cli_identity: BehaviorChainIdentity,
    pub verifier_identity: BehaviorChainIdentity,
    pub stimulus_plan: StimulusPlanRef,
    pub execution: BehaviorExecution,
    pub stimuli: Vec<BehaviorStimulus>,
    pub observables: Vec<BehaviorObservable>,
    pub reason: String,
}

/// The canonical stimulus-plan registry. For offline tests, plans are registered
/// by content hash; the registry may be empty until per-case business plans are
/// defined (a P9-live blocker). A plan referenced by evidence must be present
/// here (or provided via an explicit plan-supply seam for hermetic tests).
#[derive(Debug, Clone, Default)]
pub struct StimulusPlanRegistry {
    plans: std::collections::BTreeMap<String, Vec<BehaviorStimulus>>,
}

impl StimulusPlanRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, sha256: String, stimuli: Vec<BehaviorStimulus>) {
        self.plans.insert(sha256, stimuli);
    }

    pub fn plan(&self, sha256: &str) -> Option<&[BehaviorStimulus]> {
        self.plans.get(sha256).map(Vec::as_slice)
    }
}

/// A single computed observable result (verifier output).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComputedObservable {
    pub id: String,
    pub verdict: ObservableVerdict,
}

/// Verifier output: recomputed per-observable verdicts + final verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractVerdict {
    pub final_verdict: BehaviorContractVerdict,
    pub per_observable: Vec<ComputedObservable>,
    pub reason: String,
}

#[derive(Debug, Error)]
pub enum BehaviorOracleContractError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "unsupported schema_version '{0}' (expected {BEHAVIOR_ORACLE_CONTRACT_SCHEMA_VERSION})"
    )]
    SchemaVersion(String),
    #[error("case_id '{0}' is not one of the fixed Oreans cases")]
    CaseNotAllowed(String),
    #[error("case_id is empty")]
    EmptyCaseId,
    #[error("protected_input identity is malformed or empty")]
    BadProtectedIdentity,
    #[error("candidate identity is malformed or empty")]
    BadCandidateIdentity,
    #[error("tool_revision is empty")]
    EmptyToolRevision,
    #[error("runner_config_digest must be exactly 64 lowercase hex chars")]
    BadRunnerConfigDigest,
    #[error("runner_config_digest mismatch: evidence '{0}' != expected '{1}'")]
    RunnerConfigDigestMismatch(String, String),
    #[error("tool_revision mismatch: evidence '{0}' != expected '{1}'")]
    ToolRevisionMismatch(String, String),
    #[error("case_id mismatch: evidence '{0}' != expected '{1}'")]
    CaseIdMismatch(String, String),
    #[error("cli_identity is malformed")]
    BadCliIdentity,
    #[error("verifier_identity is malformed")]
    BadVerifierIdentity,
    #[error("stimulus_plan is malformed")]
    BadStimulusPlan,
    #[error("execution is malformed or incomplete (emitted_at / completion required)")]
    BadExecution,
    #[error("stimuli are empty")]
    EmptyStimuli,
    #[error("stimulus id '{0}' is duplicated or empty")]
    BadStimulusId(String),
    #[error("stimulus '{0}' has an empty value")]
    EmptyStimulusValue(String),
    #[error("observables are empty")]
    EmptyObservables,
    #[error("observable id '{0}' is duplicated or empty")]
    BadObservableId(String),
    #[error("observable '{0}' has an empty description or expected value")]
    BadObservableField(String),
    #[error("stimulus plan sha256 '{0}' is not registered in the canonical registry")]
    UnregisteredStimulusPlan(String),
    #[error("reason is empty")]
    EmptyReason,
    #[error("evidence declares an equivalence-manufacture marker ('{0}')")]
    EquivalenceManufacture(String),
}

/// Recompute one observable's verdict from its observed value and comparator.
/// The verdict is never taken from the evidence.
fn compute_observable_verdict(observable: &BehaviorObservable) -> ObservableVerdict {
    match observable.observed.status {
        BehaviorObservedStatus::Missing => ObservableVerdict::Missing,
        BehaviorObservedStatus::Timeout => ObservableVerdict::Timeout,
        BehaviorObservedStatus::Malformed => ObservableVerdict::Malformed,
        BehaviorObservedStatus::Partial => ObservableVerdict::Partial,
        BehaviorObservedStatus::Collected => match observable.comparator {
            BehaviorComparator::Matching => {
                if observable.observed.value == observable.expected {
                    ObservableVerdict::Pass
                } else {
                    ObservableVerdict::Mismatch
                }
            }
            BehaviorComparator::NonEmpty => {
                if observable.observed.value.trim().is_empty() {
                    ObservableVerdict::Mismatch
                } else {
                    ObservableVerdict::Pass
                }
            }
            BehaviorComparator::ExitCodeZero => {
                if observable.observed.value == "0" {
                    ObservableVerdict::Pass
                } else {
                    ObservableVerdict::Mismatch
                }
            }
            BehaviorComparator::MarkerPresent => {
                if !observable.expected.is_empty()
                    && observable.observed.value.contains(&observable.expected)
                {
                    ObservableVerdict::Pass
                } else {
                    ObservableVerdict::Mismatch
                }
            }
        },
    }
}

/// Parse and structurally validate a behavior-oracle evidence document.
pub fn parse_contract_evidence(
    bytes: &[u8],
) -> Result<BehaviorOracleContractEvidence, BehaviorOracleContractError> {
    let evidence: BehaviorOracleContractEvidence = serde_json::from_slice(bytes)?;
    if evidence.schema_version != BEHAVIOR_ORACLE_CONTRACT_SCHEMA_VERSION {
        return Err(BehaviorOracleContractError::SchemaVersion(
            evidence.schema_version,
        ));
    }
    validate_contract_shape(&evidence)?;
    Ok(evidence)
}

/// Structural, fail-closed validation of the evidence shape (does not recompute
/// observable verdicts; that is [`verify_contract`]).
fn validate_contract_shape(
    evidence: &BehaviorOracleContractEvidence,
) -> Result<(), BehaviorOracleContractError> {
    if evidence.case_id.trim().is_empty() {
        return Err(BehaviorOracleContractError::EmptyCaseId);
    }
    if !allowed_case(&evidence.case_id) {
        return Err(BehaviorOracleContractError::CaseNotAllowed(
            evidence.case_id.clone(),
        ));
    }
    if !artifact_is_well_formed(&evidence.protected_input) {
        return Err(BehaviorOracleContractError::BadProtectedIdentity);
    }
    if !artifact_is_well_formed(&evidence.candidate) {
        return Err(BehaviorOracleContractError::BadCandidateIdentity);
    }
    if evidence.tool_revision.trim().is_empty() {
        return Err(BehaviorOracleContractError::EmptyToolRevision);
    }
    if !is_sha256(&evidence.runner_config_digest) {
        return Err(BehaviorOracleContractError::BadRunnerConfigDigest);
    }
    if !evidence.cli_identity.is_well_formed() {
        return Err(BehaviorOracleContractError::BadCliIdentity);
    }
    if !evidence.verifier_identity.is_well_formed() {
        return Err(BehaviorOracleContractError::BadVerifierIdentity);
    }
    if !evidence.stimulus_plan.is_well_formed() {
        return Err(BehaviorOracleContractError::BadStimulusPlan);
    }
    if !evidence.execution.is_well_formed() {
        return Err(BehaviorOracleContractError::BadExecution);
    }
    if evidence.stimuli.is_empty() {
        return Err(BehaviorOracleContractError::EmptyStimuli);
    }
    let mut stimulus_ids = std::collections::HashSet::new();
    for stimulus in &evidence.stimuli {
        if stimulus.id.trim().is_empty() || !stimulus_ids.insert(stimulus.id.clone()) {
            return Err(BehaviorOracleContractError::BadStimulusId(
                stimulus.id.clone(),
            ));
        }
        if stimulus.value.trim().is_empty() {
            return Err(BehaviorOracleContractError::EmptyStimulusValue(
                stimulus.id.clone(),
            ));
        }
    }
    if evidence.observables.is_empty() {
        return Err(BehaviorOracleContractError::EmptyObservables);
    }
    let mut observable_ids = std::collections::HashSet::new();
    for observable in &evidence.observables {
        if observable.id.trim().is_empty() || !observable_ids.insert(observable.id.clone()) {
            return Err(BehaviorOracleContractError::BadObservableId(
                observable.id.clone(),
            ));
        }
        if observable.description.trim().is_empty() || observable.expected.trim().is_empty() {
            return Err(BehaviorOracleContractError::BadObservableField(
                observable.id.clone(),
            ));
        }
    }
    if evidence.reason.trim().is_empty() {
        return Err(BehaviorOracleContractError::EmptyReason);
    }
    Ok(())
}

/// Reject equivalence-manufacture markers. The evidence must not claim a
/// server/icon patch, forced visibility, skipped product code, semantic bypass,
/// case-specific success override, or a sample-hash-based pass override.
fn reject_equivalence_manufacture(
    evidence: &BehaviorOracleContractEvidence,
) -> Result<(), BehaviorOracleContractError> {
    const FORBIDDEN: [&str; 6] = [
        "server_patch",
        "icon_patch",
        "forced_visibility",
        "skip_product_code",
        "semantic_bypass",
        "case_specific_success_override",
    ];
    let blob = format!("{:?}", evidence.reason);
    for marker in FORBIDDEN {
        if blob.contains(marker) {
            return Err(BehaviorOracleContractError::EquivalenceManufacture(
                marker.to_string(),
            ));
        }
    }
    // The evidence has no equivalence field to carry a hash-based pass override;
    // the verifier recomputes the verdict from observables only, so no caller can
    // return Pass based on sample hash.
    Ok(())
}

/// Full fail-closed verification. Recomputes every observable verdict from the
/// recorded observation + comparator, checks the stimulus plan is canonical and
/// identical for both sides, and derives the final verdict. A caller-supplied
/// verdict never exists in this schema.
pub fn verify_contract(
    evidence: &BehaviorOracleContractEvidence,
    registry: &StimulusPlanRegistry,
) -> Result<ContractVerdict, BehaviorOracleContractError> {
    // Shape + equivalence-manufacture checks.
    validate_contract_shape(evidence)?;
    reject_equivalence_manufacture(evidence)?;

    // Canonical stimulus plan must be registered (both sides ran the same plan,
    // identified by content hash).
    if registry.plan(&evidence.stimulus_plan.sha256).is_none() {
        return Err(BehaviorOracleContractError::UnregisteredStimulusPlan(
            evidence.stimulus_plan.sha256.clone(),
        ));
    }

    // Recompute every observable verdict; derive final verdict.
    let mut per_observable = Vec::with_capacity(evidence.observables.len());
    let mut all_pass = true;
    for observable in &evidence.observables {
        let verdict = compute_observable_verdict(observable);
        if !verdict.is_pass() {
            all_pass = false;
        }
        per_observable.push(ComputedObservable {
            id: observable.id.clone(),
            verdict,
        });
    }
    let final_verdict = if all_pass {
        BehaviorContractVerdict::Pass
    } else {
        BehaviorContractVerdict::Fail
    };
    Ok(ContractVerdict {
        final_verdict,
        per_observable,
        reason: evidence.reason.clone(),
    })
}

/// Validate that two observations (protected vs candidate) used the **same**
/// canonical stimulus plan. The protected input and candidate must both carry
/// the identical `stimulus_plan.sha256`.
pub fn require_identical_stimulus_plan(
    protected: &BehaviorOracleContractEvidence,
    candidate: &BehaviorOracleContractEvidence,
) -> Result<(), BehaviorOracleContractError> {
    if protected.stimulus_plan.sha256 != candidate.stimulus_plan.sha256 {
        return Err(BehaviorOracleContractError::UnregisteredStimulusPlan(
            format!(
                "protected plan '{}' != candidate plan '{}'",
                protected.stimulus_plan.sha256, candidate.stimulus_plan.sha256
            ),
        ));
    }
    Ok(())
}

/// Expected identities/versions the verifier binds evidence to (supplied by the
/// caller from trusted source, e.g. the locked manifest + rebuilt binaries).
#[derive(Debug, Clone)]
pub struct ExpectedBinding {
    pub case_id: String,
    pub candidate: OreansArtifactIdentity,
    pub protected_input: OreansArtifactIdentity,
    pub tool_revision: String,
    pub runner_config_digest: String,
}

/// Full fail-closed verification **against an expected binding**. This is the
/// verifier entry that an acceptance consumer calls with trusted identity
/// expectations, so identity-swap / digest-drift / revision-drift evidence is
/// rejected. Recomputes observable verdicts and derives the final verdict.
pub fn verify_contract_bound(
    evidence: &BehaviorOracleContractEvidence,
    expected: &ExpectedBinding,
    registry: &StimulusPlanRegistry,
) -> Result<ContractVerdict, BehaviorOracleContractError> {
    // Shape + equivalence-manufacture checks.
    validate_contract_shape(evidence)?;
    reject_equivalence_manufacture(evidence)?;

    // Case identity must match the expected case.
    if evidence.case_id != expected.case_id {
        return Err(BehaviorOracleContractError::CaseIdMismatch(
            evidence.case_id.clone(),
            expected.case_id.clone(),
        ));
    }
    // Candidate and protected identities must match the trusted expectation.
    if evidence.candidate != expected.candidate {
        return Err(BehaviorOracleContractError::BadCandidateIdentity);
    }
    if evidence.protected_input != expected.protected_input {
        return Err(BehaviorOracleContractError::BadProtectedIdentity);
    }
    // Tool revision and runner config digest must match the trusted binding.
    if evidence.tool_revision != expected.tool_revision {
        return Err(BehaviorOracleContractError::ToolRevisionMismatch(
            evidence.tool_revision.clone(),
            expected.tool_revision.clone(),
        ));
    }
    if evidence.runner_config_digest != expected.runner_config_digest {
        return Err(BehaviorOracleContractError::RunnerConfigDigestMismatch(
            evidence.runner_config_digest.clone(),
            expected.runner_config_digest.clone(),
        ));
    }

    // Canonical stimulus plan must be registered.
    if registry.plan(&evidence.stimulus_plan.sha256).is_none() {
        return Err(BehaviorOracleContractError::UnregisteredStimulusPlan(
            evidence.stimulus_plan.sha256.clone(),
        ));
    }

    // Recompute observable verdicts; derive final verdict.
    let mut per_observable = Vec::with_capacity(evidence.observables.len());
    let mut all_pass = true;
    for observable in &evidence.observables {
        let verdict = compute_observable_verdict(observable);
        if !verdict.is_pass() {
            all_pass = false;
        }
        per_observable.push(ComputedObservable {
            id: observable.id.clone(),
            verdict,
        });
    }
    let final_verdict = if all_pass {
        BehaviorContractVerdict::Pass
    } else {
        BehaviorContractVerdict::Fail
    };
    Ok(ContractVerdict {
        final_verdict,
        per_observable,
        reason: evidence.reason.clone(),
    })
}

/// The P9-live blocker: the per-case business stimulus/observable definitions
/// cannot be derived offline. This documents precisely what is missing and why.
pub const BLOCKER_CASE_BUSINESS_DEFINITION: &str = concat!(
    "Per-case business stimulus/observable definitions cannot be established ",
    "offline. The locked manifests expose: origin_macro has only a ",
    "legacy_oracle_candidate (use=regression_comparison_only, authority=",
    "historical_operator_report); lunlun_software declares oracle:none. ",
    "docs/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md lists 'define the behavior ",
    "oracle' (specify protected-vs-unpacked stimuli and observables for each ",
    "fixed sample) as an outstanding item, and docs/VNEXT_BEHAVIORAL_PATH.md ",
    "defers the live behavioral gate. To close: a named operator must define ",
    "the business semantics for each case (e.g. the success/failure UI path, ",
    "license-path markers, or product I/O that the unpacked candidate must ",
    "reproduce under the same canonical stimulus plan), and/or a controlled ",
    "reconnaissance run under an authorized live budget must observe which ",
    "deterministic observables are in scope. Neither is a fabrication the ",
    "offline contract can invent."
);

/// The offline-fixed, contract-shaped canonical stimulus plans for the two
/// cases. These are **placeholder business stimulus plans** registered only for
/// hermetic offline testing of the contract; they are NOT a claim about real
/// product behavior. Real per-case plans are the P9-live blocker above.
pub fn offline_test_plan_origin() -> (String, Vec<BehaviorStimulus>) {
    let stimuli = vec![
        BehaviorStimulus {
            id: "startup".to_string(),
            value: "launch".to_string(),
        },
        BehaviorStimulus {
            id: "quit".to_string(),
            value: "exit".to_string(),
        },
    ];
    let sha = crate::sha256_hex(serde_json::to_string(&stimuli).unwrap().as_bytes());
    (sha, stimuli)
}

pub fn offline_test_plan_lunlun() -> (String, Vec<BehaviorStimulus>) {
    let stimuli = vec![
        BehaviorStimulus {
            id: "startup".to_string(),
            value: "launch".to_string(),
        },
        BehaviorStimulus {
            id: "quit".to_string(),
            value: "exit".to_string(),
        },
    ];
    let sha = crate::sha256_hex(serde_json::to_string(&stimuli).unwrap().as_bytes());
    (sha, stimuli)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oreans_gate::OreansArtifactIdentity;

    fn sha(s: &str) -> String {
        crate::sha256_hex(s.as_bytes())
    }

    fn valid_identity(tag: &str) -> OreansArtifactIdentity {
        OreansArtifactIdentity {
            sha256: sha(tag),
            size_bytes: 4096,
        }
    }

    fn cli_id() -> BehaviorChainIdentity {
        BehaviorChainIdentity {
            sha256: sha("cli-binary"),
            version: "cli-v1".to_string(),
        }
    }

    fn verifier_id() -> BehaviorChainIdentity {
        BehaviorChainIdentity {
            sha256: sha("verifier"),
            version: "verifier-v1".to_string(),
        }
    }

    fn plan_ref(sha: &str) -> StimulusPlanRef {
        StimulusPlanRef {
            plan_id: "plan".to_string(),
            sha256: sha.to_string(),
            schema_version: "mida.stimulus-plan/v1".to_string(),
        }
    }

    fn execution() -> BehaviorExecution {
        BehaviorExecution {
            execution_id: "exec-1".to_string(),
            emitted_at: "2026-08-06T00:00:00Z".to_string(),
            completion: BehaviorCompletionMarker {
                marker: "done".to_string(),
                done: true,
            },
        }
    }

    fn registry_with(plan_sha: &str) -> StimulusPlanRegistry {
        let mut r = StimulusPlanRegistry::new();
        r.register(
            plan_sha.to_string(),
            vec![
                BehaviorStimulus {
                    id: "startup".into(),
                    value: "launch".into(),
                },
                BehaviorStimulus {
                    id: "quit".into(),
                    value: "exit".into(),
                },
            ],
        );
        r
    }

    fn valid_evidence(case_id: &str, plan_sha: &str) -> BehaviorOracleContractEvidence {
        BehaviorOracleContractEvidence {
            schema_version: BEHAVIOR_ORACLE_CONTRACT_SCHEMA_VERSION.to_string(),
            case_id: case_id.to_string(),
            protected_input: valid_identity("protected"),
            candidate: valid_identity("candidate"),
            tool_revision: "oreans/two-sample-mainline@1".to_string(),
            runner_config_digest: "aa".repeat(32),
            cli_identity: cli_id(),
            verifier_identity: verifier_id(),
            stimulus_plan: plan_ref(plan_sha),
            execution: execution(),
            stimuli: vec![
                BehaviorStimulus {
                    id: "startup".into(),
                    value: "launch".into(),
                },
                BehaviorStimulus {
                    id: "quit".into(),
                    value: "exit".into(),
                },
            ],
            observables: vec![
                BehaviorObservable {
                    id: "exit_code".into(),
                    description: "process exit code".into(),
                    observed: BehaviorObserved {
                        value: "0".into(),
                        status: BehaviorObservedStatus::Collected,
                    },
                    comparator: BehaviorComparator::ExitCodeZero,
                    expected: "0".into(),
                },
                BehaviorObservable {
                    id: "marker".into(),
                    description: "product marker".into(),
                    observed: BehaviorObserved {
                        value: "MIDA_BEH_MARKER=1".into(),
                        status: BehaviorObservedStatus::Collected,
                    },
                    comparator: BehaviorComparator::MarkerPresent,
                    expected: "MIDA_BEH_MARKER".into(),
                },
            ],
            reason: "contract-shaped candidate observables all pass".to_string(),
        }
    }

    fn expected(case_id: &str, plan_sha: &str) -> ExpectedBinding {
        let e = valid_evidence(case_id, plan_sha);
        ExpectedBinding {
            case_id: e.case_id.clone(),
            candidate: e.candidate.clone(),
            protected_input: e.protected_input.clone(),
            tool_revision: e.tool_revision.clone(),
            runner_config_digest: e.runner_config_digest.clone(),
        }
    }

    // --- positive ---

    #[test]
    fn verifies_valid_contract_to_pass() {
        let plan = sha("plan");
        let ev = valid_evidence("origin_macro", &plan);
        let reg = registry_with(&plan);
        let out = verify_contract_bound(&ev, &expected("origin_macro", &plan), &reg).unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Pass);
        assert!(out.per_observable.iter().all(|o| o.verdict.is_pass()));
        assert!(!out.reason.trim().is_empty());
    }

    #[test]
    fn recomputes_verdict_ignoring_declared_verdict() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0] = BehaviorObservable {
            id: "exit_code".into(),
            description: "exit".into(),
            observed: BehaviorObserved {
                value: "1".into(),
                status: BehaviorObservedStatus::Collected,
            },
            comparator: BehaviorComparator::ExitCodeZero,
            expected: "0".into(),
        };
        let reg = registry_with(&plan);
        let out = verify_contract_bound(&ev, &expected("origin_macro", &plan), &reg).unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
        assert!(out.per_observable[0].verdict != ObservableVerdict::Pass);
    }

    #[test]
    fn protected_and_candidate_can_share_plan_via_require_identical() {
        let plan = sha("plan");
        let p = valid_evidence("origin_macro", &plan);
        let c = valid_evidence("origin_macro", &plan);
        require_identical_stimulus_plan(&p, &c).unwrap();
    }

    // --- structural / schema attacks ---

    #[test]
    fn rejects_unknown_schema_version() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.schema_version = "mida.unknown/v9".into();
        let err = parse_contract_evidence(&serde_json::to_vec(&ev).unwrap()).unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::SchemaVersion(_)));
    }

    #[test]
    fn rejects_unknown_field() {
        let json = br#"{"schema_version":"mida.oreans-behavior-oracle-contract/v1","bogus":1}"#;
        assert!(parse_contract_evidence(json).is_err());
    }

    #[test]
    fn rejects_non_gate_case() {
        let plan = sha("plan");
        let mut ev = valid_evidence("shiguang", &plan);
        ev.schema_version = BEHAVIOR_ORACLE_CONTRACT_SCHEMA_VERSION.into();
        let err = parse_contract_evidence(&serde_json::to_vec(&ev).unwrap()).unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::CaseNotAllowed(_)
        ));
    }

    #[test]
    fn rejects_empty_stimuli() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli.clear();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::EmptyStimuli));
    }

    #[test]
    fn rejects_empty_observables() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables.clear();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::EmptyObservables));
    }

    #[test]
    fn rejects_duplicate_stimulus_id() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli.push(BehaviorStimulus {
            id: "startup".into(),
            value: "x".into(),
        });
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::BadStimulusId(_)));
    }

    #[test]
    fn rejects_empty_stimulus_value() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli[0].value = "".into();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::EmptyStimulusValue(_)
        ));
    }

    #[test]
    fn rejects_duplicate_observable_id() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables.push(ev.observables[0].clone());
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadObservableId(_)
        ));
    }

    #[test]
    fn rejects_empty_observable_expected() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[1].expected = "".into();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadObservableField(_)
        ));
    }

    // --- identity / drift attacks ---

    #[test]
    fn rejects_protected_candidate_identity_swap() {
        let plan = sha("plan");
        let ev = valid_evidence("origin_macro", &plan);
        let mut exp = expected("origin_macro", &plan);
        std::mem::swap(&mut exp.candidate, &mut exp.protected_input);
        let err = verify_contract_bound(&ev, &exp, &registry_with(&plan)).unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadCandidateIdentity
        ));
    }

    #[test]
    fn rejects_candidate_identity_drift() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.candidate = valid_identity("different-candidate");
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadCandidateIdentity
        ));
    }

    #[test]
    fn rejects_runner_config_digest_drift() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.runner_config_digest = "bb".repeat(32);
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::RunnerConfigDigestMismatch(_, _)
        ));
    }

    #[test]
    fn rejects_tool_revision_drift() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.tool_revision = "other/revision@2".into();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::ToolRevisionMismatch(_, _)
        ));
    }

    #[test]
    fn rejects_stimulus_plan_drift_unregistered() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimulus_plan = plan_ref(&sha("different-plan"));
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::UnregisteredStimulusPlan(_)
        ));
    }

    #[test]
    fn rejects_candidate_and_protected_using_different_plan() {
        let plan_a = sha("plan-a");
        let plan_b = sha("plan-b");
        let p = valid_evidence("origin_macro", &plan_a);
        let c = valid_evidence("origin_macro", &plan_b);
        assert!(require_identical_stimulus_plan(&p, &c).is_err());
    }

    #[test]
    fn rejects_case_id_drift() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.case_id = "lunlun_software".into();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::CaseIdMismatch(_, _)
        ));
    }

    // --- observable verdict recomputation ---

    #[test]
    fn missing_observable_fails_closed() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[1].observed.status = BehaviorObservedStatus::Missing;
        let out =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
        assert!(out.per_observable[1].verdict == ObservableVerdict::Missing);
    }

    #[test]
    fn timeout_observable_fails_closed() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.status = BehaviorObservedStatus::Timeout;
        let out =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn malformed_observable_fails_closed() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.status = BehaviorObservedStatus::Malformed;
        let out =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn partial_observable_fails_closed() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.status = BehaviorObservedStatus::Partial;
        let out =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn mismatch_observable_fails_closed() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.value = "7".into();
        let out =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
        assert!(out.per_observable[0].verdict == ObservableVerdict::Mismatch);
    }

    #[test]
    fn caller_cannot_pass_a_verdict() {
        let plan = sha("plan");
        let ev = valid_evidence("origin_macro", &plan);
        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&ev).unwrap()).unwrap();
        assert!(value.get("verdict").is_none());
        assert!(value.get("final_verdict").is_none());
    }

    #[test]
    fn single_failure_cannot_forge_overall_pass() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[1].observed.value = "NO_MARKER".into();
        ev.reason = "overall pass".into();
        let out =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn stale_evidence_binding_emitted_at_required() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.execution.completion.done = false;
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::BadExecution));
    }

    #[test]
    fn rejects_empty_reason() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.reason = "".into();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::EmptyReason));
    }

    // --- equivalence manufacture ---

    #[test]
    fn rejects_equivalence_manufacture_marker() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.reason = "achieved via server_patch bypass".into();
        let err =
            verify_contract_bound(&ev, &expected("origin_macro", &plan), &registry_with(&plan))
                .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::EquivalenceManufacture(_)
        ));
    }

    #[test]
    fn no_sample_hash_pass_override_path() {
        let plan = sha("plan");
        let ev = valid_evidence("origin_macro", &plan);
        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&ev).unwrap()).unwrap();
        assert!(value.get("pass_override").is_none());
        assert!(value.get("sample_hash_pass").is_none());
        assert!(value.get("success_override").is_none());
    }

    // --- honest recomputation identity attack ---

    #[test]
    fn honest_recompute_candidate_hash_identity_attack() {
        let plan = sha("plan");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.candidate = valid_identity("attacker-candidate");
        let bytes = serde_json::to_vec(&ev).unwrap();
        let reparsed = parse_contract_evidence(&bytes).unwrap();
        let err = verify_contract_bound(
            &reparsed,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadCandidateIdentity
        ));
    }
}
