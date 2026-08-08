//! P9-Prep-A: case-bound behavior oracle contract (independent verifier side).
//!
//! A strict, independently verifiable, fail-closed behavior-oracle contract for
//! the two fixed Oreans cases. This module is the **verifier** — it never runs a
//! probe, never opens a sample, and never imports a producer crate. The producer
//! side writes `mida.oreans-behavior-oracle-contract/v2` evidence JSON; this
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
//!   plan (`stimulus_plan_sha256` must match the canonical plan registry), and
//!   the evidence's `stimuli` must match the registered canonical plan CONTENT
//!   exactly. Registration is content-bound: `register` recomputes the
//!   canonical content hash and refuses a declared hash that does not match,
//!   and verification compares the full canonical stimulus set (add/remove/
//!   reorder/id/value changes all fail). Preserving a valid hash while
//!   tampering `evidence.stimuli` is rejected.
//! - Equivalence manufacture is rejected from a STRUCTURED `equivalence_proof`
//!   block (P1): a server/icon patch, forced visibility, skipped product code,
//!   injected modules, or a transform/patch outside the allowlist is a hard
//!   error. The free-text `reason` is human explanation only and is never
//!   consulted for a verdict — the old substring blacklist is gone.
//! - The structured proof must bind a real runtime observation; when the probe
//!   did not run offline the verdict is `NotRun` (Pending), never a fabricated
//!   `Pass`.
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
///
/// v2: adds the required structured `equivalence_proof` block (P1 — free-text
/// `reason` is no longer a security gate) and the order-bound stimulus-plan
/// content binding. v1 evidence (no `equivalence_proof`) is rejected.
pub const BEHAVIOR_ORACLE_CONTRACT_SCHEMA_VERSION: &str = "mida.oreans-behavior-oracle-contract/v2";

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

// ---------------------------------------------------------------------------
// Structured equivalence proof (P1: no free-text-reason security control)
// ---------------------------------------------------------------------------
//
// The previous `reject_equivalence_manufacture` scanned the free-text `reason`
// for a fixed list of markers. That is not a security control: a caller can
// change case, insert whitespace, use synonyms, omit the reason, or drive a
// patch through runtime injection. The security state now lives in a
// structured `equivalence_proof` block; `reason` is human explanation only and
// is never consulted for a verdict.

/// A registered, allowlisted repair transform that does NOT manufacture
/// equivalence (mirrors the taxonomy in `crate::behavior`). `kind` is the
/// transform class; `rule_id` the allowlisted rule. Any transform outside this
/// set fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedTransform {
    pub id: &'static str,
    pub kind: &'static str,
    pub rule_id: &'static str,
}

/// The allowlisted, benign repair transforms (PE IAT rebuild, reloc rebind,
/// stale-pointer clear). A transform outside this set — regardless of how it is
/// spelled in a reason or a ledger — is an equivalence-manufacture marker.
pub const ALLOWED_EQUIVALENCE_TRANSFORMS: &[AllowedTransform] = &[
    AllowedTransform {
        id: "iat_rebuild",
        kind: "pe_repair",
        rule_id: "pe_iat_rebuild_v0",
    },
    AllowedTransform {
        id: "reloc_rebind",
        kind: "pe_repair",
        rule_id: "pe_reloc_rebind_v0",
    },
    AllowedTransform {
        id: "clear_stale_ptrs",
        kind: "pe_repair",
        rule_id: "clear_stale_process_ptrs_v0",
    },
];

/// One structured transform actually applied to the candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformProofEntry {
    pub id: String,
    pub kind: String,
    /// The allowlisted rule id, when the transform is a registered benign repair.
    #[serde(default)]
    pub equivalence_rule: Option<String>,
}

/// One structured runtime patch (bytes/state patched after load).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchProofEntry {
    pub id: String,
    /// Description of the patched region (never a security gate by itself).
    pub description: String,
}

/// Structured equivalence proof bound to the evidence.
///
/// The verifier reads equivalence-manufacture state ONLY from this block:
///
/// - `skipped_product_code` / `forced_visibility` / a non-empty
///   `server_patch_state` / `icon_patch_state` / `injected_module_list`, or a
///   `transform_ledger` / `runtime_patch_ledger` entry outside the allowlist
///   → the verdict is `Fail` (equivalence manufacture).
/// - A missing or malformed block (or a missing required binding such as probe
///   identity) → the evidence is rejected.
/// - A complete block that cannot establish real runtime observation
///   (`observation_source_hash` / `execution_environment_digest` are `None`,
///   i.e. offline, no real probe) → the verdict is `NotRun` (Pending), never
///   `Pass`. The offline contract cannot fabricate a real behavioral Pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EquivalenceProof {
    pub probe_binary_identity: BehaviorChainIdentity,
    pub runner_binary_identity: BehaviorChainIdentity,
    /// Modules loaded into the probe process (by name or digest).
    #[serde(default)]
    pub loaded_modules: Vec<String>,
    /// Transforms actually applied to the candidate (structured). Required:
    /// a proof without a transform ledger is incomplete and fails parse
    /// (fail-closed — the absence of a ledger cannot silently pass).
    pub transform_ledger: Vec<TransformProofEntry>,
    /// Runtime patches applied after load (structured). Required for the same
    /// reason as `transform_ledger`.
    pub runtime_patch_ledger: Vec<PatchProofEntry>,
    /// Modules injected into the candidate (non-empty → manufacture).
    #[serde(default)]
    pub injected_module_list: Vec<String>,
    /// Product code deliberately skipped (true → manufacture).
    #[serde(default)]
    pub skipped_product_code: bool,
    /// Forced UI visibility override (true → manufacture).
    #[serde(default)]
    pub forced_visibility: bool,
    /// Server-side patch/response override state (Some → manufacture).
    #[serde(default)]
    pub server_patch_state: Option<String>,
    /// Icon patch state (Some → manufacture).
    #[serde(default)]
    pub icon_patch_state: Option<String>,
    /// Opaque trust token minted ONLY by the verifier's real artifact-verification
    /// step (see [`TrustedObservationRegistry::issue`]). It is an unguessable,
    /// non-caller-derivable value (derived from a verifier-held secret salt +
    /// the verified observation), so a caller who merely knows the observation
    /// hashes cannot forge a token. The verdict is `Pass` only when this token
    /// resolves to a trusted, issued observation that exactly matches the
    /// declared `observation_source_hash` / `execution_environment_digest`.
    pub trust_token: String,
    /// Hash of the raw observation source (probe logs). **Descriptive**: this
    /// field is cross-checked against the observation bound to the `trust_token`.
    /// It is not, by itself, proof of a real observation — only the opaque
    /// `trust_token` is.
    pub observation_source_hash: String,
    /// Digest of the execution environment that produced the observation.
    /// **Descriptive** and cross-checked against the observation bound to the
    /// `trust_token`.
    pub execution_environment_digest: String,
}

impl EquivalenceProof {
    fn is_well_formed(&self) -> bool {
        self.probe_binary_identity.is_well_formed() && self.runner_binary_identity.is_well_formed()
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
    /// Structured equivalence proof (P1). `reason` is human-only; all
    /// equivalence-manufacture state is read from here.
    pub equivalence_proof: EquivalenceProof,
    pub reason: String,
}

/// Canonical, stable serialization of an ordered stimulus plan.
///
/// The encoding is length-prefixed and injective (commas/semicolons/`=`
/// inside `id`/`value` bytes cannot collide), and it **preserves the plan's
/// execution order** (the order of the `Vec`). This is the single source of
/// truth for "same stimulus plan" — the registry and the evidence content both
/// canonicalize through it, so add/remove/reorder/id/value changes all change
/// the digest. Because the order is preserved (not sorted), two plans that run
/// the same stimuli in a different order produce different hashes, binding the
/// order into the hash.
pub fn canonical_stimulus_serialization(stimuli: &[BehaviorStimulus]) -> String {
    let mut out = String::new();
    for s in stimuli {
        out.push_str(&format!(
            "id={}:{};value={}:{};",
            s.id.len(),
            s.id,
            s.value.len(),
            s.value
        ));
    }
    out
}

/// SHA-256 (64 lowercase hex) of the canonical stimulus serialization.
pub fn canonical_stimuli_hash(stimuli: &[BehaviorStimulus]) -> String {
    crate::sha256_hex(canonical_stimulus_serialization(stimuli).as_bytes())
}

/// The canonical stimulus-plan registry. For offline tests, plans are registered
/// by content hash; the registry may be empty until per-case business plans are
/// defined (a P9-live blocker). A plan referenced by evidence must be present
/// here (or provided via an explicit plan-supply seam for hermetic tests).
///
/// Registration is **content-bound**: `register` recomputes the canonical hash
/// of the supplied stimuli and rejects any entry whose `sha256` does not match
/// that content (or that silently overwrites a different plan under the same
/// hash). This closes the "keep a valid hash, tamper the stimuli" gap — a
/// registered hash always maps to exactly one canonical stimulus set.
#[derive(Debug, Clone, Default)]
pub struct StimulusPlanRegistry {
    plans: std::collections::BTreeMap<String, Vec<BehaviorStimulus>>,
}

impl StimulusPlanRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a canonical stimulus plan under its content hash.
    ///
    /// Returns `Err` (and records nothing) when:
    /// - the supplied `sha256` is not the canonical content hash of `stimuli`;
    /// - a different stimulus set is already registered under the same hash
    ///   (silent overwrite is refused).
    pub fn register(
        &mut self,
        sha256: String,
        stimuli: Vec<BehaviorStimulus>,
    ) -> Result<(), BehaviorOracleContractError> {
        let actual = canonical_stimuli_hash(&stimuli);
        if !actual.eq_ignore_ascii_case(&sha256) {
            return Err(BehaviorOracleContractError::StimulusPlanHashMismatch {
                declared: sha256,
                computed: actual,
            });
        }
        if let Some(existing) = self.plans.get(&sha256.to_lowercase()) {
            if existing != &stimuli {
                return Err(BehaviorOracleContractError::StimulusPlanHashCollision(
                    sha256,
                ));
            }
            return Ok(());
        }
        self.plans.insert(sha256.to_lowercase(), stimuli);
        Ok(())
    }

    /// Look up the canonical plan by content hash.
    pub fn plan(&self, sha256: &str) -> Option<&[BehaviorStimulus]> {
        self.plans.get(&sha256.to_lowercase()).map(Vec::as_slice)
    }

    /// Fail-closed content check: the evidence's stimuli must canonicalize to
    /// exactly the canonical plan registered under the evidence's plan hash.
    /// `None` when the plan is not registered (never a silent accept).
    pub fn validate_evidence_plan_content(
        &self,
        evidence: &BehaviorOracleContractEvidence,
    ) -> Result<(), BehaviorOracleContractError> {
        let canonical = self.plan(&evidence.stimulus_plan.sha256).ok_or_else(|| {
            BehaviorOracleContractError::UnregisteredStimulusPlan(
                evidence.stimulus_plan.sha256.clone(),
            )
        })?;
        if canonical != evidence.stimuli.as_slice() {
            return Err(BehaviorOracleContractError::StimulusPlanContentMismatch {
                plan_sha: evidence.stimulus_plan.sha256.clone(),
            });
        }
        Ok(())
    }
}

/// An opaque trust token minted by the verifier's real artifact-verification
/// step. The token is an unguessable, non-caller-derivable 64-hex value; a
/// caller who only knows the observation hashes cannot produce it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustToken(String);

impl TrustToken {
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Verifier-held secret salt used to mint opaque observation trust tokens. This
/// lives only inside the verifier crate and is NEVER serialized into evidence,
/// so a caller cannot recompute a valid token from the observation hashes.
const OBSERVER_TOKEN_SECRET_SALT: &[u8] = b"mida-acceptance-v2-observer-secret-salt";

/// Derive the opaque token for a given observation (source hash + environment
/// digest) under the verifier's secret salt.
fn observer_token_for(source: &str, env: &str) -> TrustToken {
    let mut msg = Vec::with_capacity(OBSERVER_TOKEN_SECRET_SALT.len() + source.len() + env.len());
    msg.extend_from_slice(OBSERVER_TOKEN_SECRET_SALT);
    msg.extend_from_slice(source.trim().to_lowercase().as_bytes());
    msg.extend_from_slice(env.trim().to_lowercase().as_bytes());
    TrustToken(crate::sha256_hex(&msg))
}

/// Verifier-side registry of TRUSTED runtime observations (P1 issue 1: no
/// self-reported-`Some` false-green).
///
/// A behavioral `Pass` must be backed by an OPAQUE [`TrustToken`] minted by the
/// verifier's real artifact-verification step — never by a caller-supplied
/// `observation_source_hash` / `execution_environment_digest` pair. [`issue`]
/// is the only way to mint a token, and it binds the observation to the
/// verifier secret salt. `observation_is_trusted` requires the evidence's token
/// to exactly match the verifier-minted token for its declared observation AND
/// that observation to have been actually issued. Offline (no real probe
/// verification) no token is issued, so the verdict is `NotRun` (Pending); a
/// forged token is rejected.
///
/// [`issue`]: Self::issue
#[derive(Debug, Clone, Default)]
pub struct TrustedObservationRegistry {
    /// `token_secret -> (observation_source_hash, execution_environment_digest)`.
    observations: std::collections::BTreeMap<String, (String, String)>,
}

impl TrustedObservationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint an opaque trust token for an observation that the verifier actually
    /// verified (real artifact-verification step). Both inputs must be
    /// well-formed 64-hex. Returns `Err` on malformed input; on success returns
    /// the opaque token to embed in the evidence.
    pub fn issue(
        &mut self,
        observation_source_hash: &str,
        execution_environment_digest: &str,
    ) -> Result<TrustToken, BehaviorOracleContractError> {
        let source = observation_source_hash.trim().to_lowercase();
        let env = execution_environment_digest.trim().to_lowercase();
        if !is_sha256(&source) || !is_sha256(&env) {
            return Err(BehaviorOracleContractError::BadObservationIdentity);
        }
        let token = observer_token_for(&source, &env);
        self.observations
            .insert(token.as_str().to_string(), (source, env));
        Ok(token)
    }

    /// Whether the evidence's observation is backed by a verifier-minted opaque
    /// trust token that (a) exactly matches the verifier's token for the
    /// declared observation and (b) corresponds to an actually-issued
    /// observation. A forged/unregistered token yields `NotRun` (Pending),
    /// never `Pass`.
    pub fn observation_is_trusted(&self, evidence: &BehaviorOracleContractEvidence) -> bool {
        let proof = &evidence.equivalence_proof;
        let source = proof.observation_source_hash.trim().to_lowercase();
        let env = proof.execution_environment_digest.trim().to_lowercase();
        // The declared token must be the verifier-minted token for this
        // (source, env) pair, AND the pair must have been issued.
        let expected = observer_token_for(&source, &env);
        proof
            .trust_token
            .trim()
            .eq_ignore_ascii_case(expected.as_str())
            && self
                .observations
                .get(expected.as_str())
                .map(|(s, e)| *s == source && *e == env)
                .unwrap_or(false)
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
    #[error(
        "registered plan hash '{declared}' does not match the canonical hash of the supplied \
         stimuli '{computed}' (content-bound registration refused)"
    )]
    StimulusPlanHashMismatch { declared: String, computed: String },
    #[error(
        "a different canonical stimulus set is already registered under plan hash '{0}'; \
         silently overwriting a plan with the same hash is refused"
    )]
    StimulusPlanHashCollision(String),
    #[error(
        "evidence stimuli do not match the canonical plan '{plan_sha}' (add/remove/reorder/id/\
         value drift refused)"
    )]
    StimulusPlanContentMismatch { plan_sha: String },
    #[error("reason is empty")]
    EmptyReason,
    #[error("equivalence_proof is malformed or missing required identities")]
    BadEquivalenceProof,
    #[error(
        "equivalence_proof observation_source_hash / execution_environment_digest must be \
         well-formed 64-hex"
    )]
    BadObservationIdentity,
    #[error(
        "equivalence_proof declares an equivalence-manufacture marker: {0} (structured; never \
         reason text)"
    )]
    EquivalenceManufacture(String),
    #[error(
        "equivalence_proof transform '{id}' (kind '{kind}') is not in the allowlist — \
         fail-closed (equivalence manufacture)"
    )]
    UnallowedTransform { id: String, kind: String },
    #[error(
        "equivalence_proof runtime patch '{id}' cannot be bound to an allowlisted transform — \
         fail-closed (equivalence manufacture)"
    )]
    UnallowedPatch { id: String },
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
    // P1: the structured equivalence proof must be well-formed (required
    // identities present). `reason` text is human-only and never a gate.
    validate_equivalence_proof_shape(evidence)?;
    Ok(())
}

/// Validate the structured equivalence proof is well-formed (required
/// identities present). The `reason` field is never consulted here.
fn validate_equivalence_proof_shape(
    evidence: &BehaviorOracleContractEvidence,
) -> Result<(), BehaviorOracleContractError> {
    if !evidence.equivalence_proof.is_well_formed() {
        return Err(BehaviorOracleContractError::BadEquivalenceProof);
    }
    // The observation source hash, environment digest, and the opaque trust
    // token must all be well-formed 64-hex. A malformed value is rejected up
    // front; a well-formed but UNREGISTERED / FORGED token is not trusted for a
    // Pass (see `TrustedObservationRegistry::observation_is_trusted`).
    let proof = &evidence.equivalence_proof;
    if !is_sha256(proof.observation_source_hash.trim())
        || !is_sha256(proof.execution_environment_digest.trim())
        || !is_sha256(proof.trust_token.trim())
    {
        return Err(BehaviorOracleContractError::BadObservationIdentity);
    }
    Ok(())
}

/// Return the allowlist rule id for a transform `(id, kind)`, if registered.
fn allowlisted_transform_rule(id: &str, kind: &str) -> Option<&'static str> {
    ALLOWED_EQUIVALENCE_TRANSFORMS
        .iter()
        .find(|t| t.id == id && t.kind == kind)
        .map(|t| t.rule_id)
}

/// Reject equivalence manufacture from the STRUCTURED proof (P1). The evidence
/// must not declare a server/icon patch, forced visibility, skipped product
/// code, injected modules, or a transform/patch outside the allowlist. Any such
/// marker is a hard error regardless of how the free-text `reason` is phrased.
fn reject_equivalence_manufacture(
    evidence: &BehaviorOracleContractEvidence,
) -> Result<(), BehaviorOracleContractError> {
    let proof = &evidence.equivalence_proof;

    // Boolean / string manufacture markers (structured, not reason text).
    if proof.skipped_product_code {
        return Err(BehaviorOracleContractError::EquivalenceManufacture(
            "skipped_product_code=true".to_string(),
        ));
    }
    if proof.forced_visibility {
        return Err(BehaviorOracleContractError::EquivalenceManufacture(
            "forced_visibility=true".to_string(),
        ));
    }
    if let Some(state) = proof.server_patch_state.as_deref() {
        if !state.trim().is_empty() {
            return Err(BehaviorOracleContractError::EquivalenceManufacture(
                format!("server_patch_state={state:?}"),
            ));
        }
    }
    if let Some(state) = proof.icon_patch_state.as_deref() {
        if !state.trim().is_empty() {
            return Err(BehaviorOracleContractError::EquivalenceManufacture(
                format!("icon_patch_state={state:?}"),
            ));
        }
    }
    if !proof.injected_module_list.is_empty() {
        return Err(BehaviorOracleContractError::EquivalenceManufacture(
            "injected_module_list is non-empty".to_string(),
        ));
    }

    // Structured transform ledger: every transform must be allowlisted.
    for entry in &proof.transform_ledger {
        let Some(rule) = allowlisted_transform_rule(&entry.id, &entry.kind) else {
            return Err(BehaviorOracleContractError::UnallowedTransform {
                id: entry.id.clone(),
                kind: entry.kind.clone(),
            });
        };
        // The entry's equivalence_rule must match the allowlisted rule exactly;
        // a mismatched/missing rule fails closed.
        if entry.equivalence_rule.as_deref() != Some(rule) {
            return Err(BehaviorOracleContractError::UnallowedTransform {
                id: entry.id.clone(),
                kind: entry.kind.clone(),
            });
        }
    }

    // Structured runtime patch ledger: a runtime patch is only acceptable when
    // it is a binding of an allowlisted transform; any patch with no matching
    // allowlisted transform in the ledger fails closed.
    if !proof.runtime_patch_ledger.is_empty() {
        for patch in &proof.runtime_patch_ledger {
            let bound = proof
                .transform_ledger
                .iter()
                .any(|t| allowlisted_transform_rule(&t.id, &t.kind).is_some() && t.id == patch.id);
            if !bound {
                return Err(BehaviorOracleContractError::UnallowedPatch {
                    id: patch.id.clone(),
                });
            }
        }
    }

    Ok(())
}

/// Derive the final contract verdict from the recomputed observables.
///
/// - any observable failing → `Fail`;
/// - all observables passing but the observation is NOT verifier-trusted
///   (offline: no opaque token issued for a real probe run) → `NotRun`
///   (Pending), never `Pass`. A self-reported observation hash or a forged
///   trust token is never sufficient — the evidence must carry a token minted
///   by the verifier-side [`TrustedObservationRegistry`];
/// - all observables passing AND the observation is verifier-trusted → `Pass`.
fn derive_final_verdict(
    all_pass: bool,
    evidence: &BehaviorOracleContractEvidence,
    trusted_observations: &TrustedObservationRegistry,
) -> BehaviorContractVerdict {
    if !all_pass {
        return BehaviorContractVerdict::Fail;
    }
    if trusted_observations.observation_is_trusted(evidence) {
        BehaviorContractVerdict::Pass
    } else {
        BehaviorContractVerdict::NotRun
    }
}

/// Full fail-closed verification. Recomputes every observable verdict from the
/// recorded observation + comparator, checks the stimulus plan is canonical and
/// identical for both sides, and derives the final verdict. A caller-supplied
/// verdict never exists in this schema.
pub fn verify_contract(
    evidence: &BehaviorOracleContractEvidence,
    registry: &StimulusPlanRegistry,
    trusted_observations: &TrustedObservationRegistry,
) -> Result<ContractVerdict, BehaviorOracleContractError> {
    // Shape + equivalence-manufacture checks.
    validate_contract_shape(evidence)?;
    reject_equivalence_manufacture(evidence)?;

    // Canonical stimulus plan must be registered AND the evidence's stimuli
    // must match the registered canonical plan content exactly. A registered
    // hash alone is not enough: preserving a valid hash while tampering
    // `evidence.stimuli` must fail.
    registry.validate_evidence_plan_content(evidence)?;

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
    let final_verdict = derive_final_verdict(all_pass, evidence, trusted_observations);
    Ok(ContractVerdict {
        final_verdict,
        per_observable,
        reason: evidence.reason.clone(),
    })
}

/// Validate that two observations (protected vs candidate) used the **same**
/// canonical stimulus plan. The protected input and candidate must both carry
/// the identical `stimulus_plan.sha256`, AND both evidences' `stimuli` must
/// match the canonical plan registered under that hash (a hash alone is not
/// sufficient — see [`StimulusPlanRegistry::validate_evidence_plan_content`]).
pub fn require_identical_stimulus_plan(
    protected: &BehaviorOracleContractEvidence,
    candidate: &BehaviorOracleContractEvidence,
    registry: &StimulusPlanRegistry,
) -> Result<(), BehaviorOracleContractError> {
    if protected.stimulus_plan.sha256 != candidate.stimulus_plan.sha256 {
        return Err(BehaviorOracleContractError::UnregisteredStimulusPlan(
            format!(
                "protected plan '{}' != candidate plan '{}'",
                protected.stimulus_plan.sha256, candidate.stimulus_plan.sha256
            ),
        ));
    }
    // Both sides must already have passed canonical plan-content validation;
    // enforce it here so a caller that skips `verify_contract*` cannot feed a
    // tampered plan to this comparison.
    registry.validate_evidence_plan_content(protected)?;
    registry.validate_evidence_plan_content(candidate)?;
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
    trusted_observations: &TrustedObservationRegistry,
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

    // Canonical stimulus plan must be registered AND the evidence's stimuli
    // must match the registered canonical plan content exactly (hash alone is
    // not sufficient; see `validate_evidence_plan_content`).
    registry.validate_evidence_plan_content(evidence)?;

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
    let final_verdict = derive_final_verdict(all_pass, evidence, trusted_observations);
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
    let sha = canonical_stimuli_hash(&stimuli);
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
    let sha = canonical_stimuli_hash(&stimuli);
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

    /// The canonical (startup/quit) stimulus set shared by the default
    /// `valid_evidence` and the default registered plan.
    fn canonical_stimuli() -> Vec<BehaviorStimulus> {
        vec![
            BehaviorStimulus {
                id: "startup".into(),
                value: "launch".into(),
            },
            BehaviorStimulus {
                id: "quit".into(),
                value: "exit".into(),
            },
        ]
    }

    /// Content-bound registration: registers `stimuli` under their real
    /// canonical hash, or under `overridden_sha` when supplied (to build a
    /// tampered-hash collision test).
    fn register_stimuli(
        reg: &mut StimulusPlanRegistry,
        stimuli: Vec<BehaviorStimulus>,
        overridden_sha: Option<&str>,
    ) {
        let sha = overridden_sha
            .map(str::to_string)
            .unwrap_or_else(|| canonical_stimuli_hash(&stimuli));
        reg.register(sha, stimuli).unwrap();
    }

    fn registry_with(plan_sha: &str) -> StimulusPlanRegistry {
        let mut r = StimulusPlanRegistry::new();
        // Register the canonical stimuli under the given plan hash only when it
        // equals the content hash (otherwise this is a mismatch-reject test).
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
        )
        .unwrap();
        r
    }

    /// The plan sha the default `valid_evidence` must carry to match the
    /// canonical startup/quit stimuli registered by `registry_with`.
    fn default_plan_sha() -> String {
        canonical_stimuli_hash(&canonical_stimuli())
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
            stimuli: canonical_stimuli(),
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
            equivalence_proof: clean_proof(),
            reason: "contract-shaped candidate observables all pass".to_string(),
        }
    }

    /// A clean, complete, allowlist-clean structured equivalence proof that
    /// establishes a verifier-trusted runtime observation (so the contract may
    /// `Pass`). The `trust_token` must be the one minted by the
    /// [`TrustedObservationRegistry`] returned by [`trusted_observations`] for
    /// the same (source, env) pair — it is opaque and not caller-derivable.
    fn clean_proof() -> EquivalenceProof {
        EquivalenceProof {
            probe_binary_identity: cli_id(),
            runner_binary_identity: verifier_id(),
            loaded_modules: Vec::new(),
            transform_ledger: Vec::new(),
            runtime_patch_ledger: Vec::new(),
            injected_module_list: Vec::new(),
            skipped_product_code: false,
            forced_visibility: false,
            server_patch_state: None,
            icon_patch_state: None,
            trust_token: observer_token_for(&sha("observation-source"), &sha("exec-env"))
                .as_str()
                .to_string(),
            observation_source_hash: sha("observation-source"),
            execution_environment_digest: sha("exec-env"),
        }
    }

    /// The verifier-side trusted observation registry that issues the opaque
    /// token for the clean proof's observation, so `valid_evidence` may `Pass`.
    fn trusted_observations() -> TrustedObservationRegistry {
        let mut reg = TrustedObservationRegistry::new();
        reg.issue(&sha("observation-source"), &sha("exec-env"))
            .expect("issue clean observation token");
        reg
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
        let plan = default_plan_sha();
        let ev = valid_evidence("origin_macro", &plan);
        let reg = registry_with(&plan);
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &reg,
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Pass);
        assert!(out.per_observable.iter().all(|o| o.verdict.is_pass()));
        assert!(!out.reason.trim().is_empty());
    }

    #[test]
    fn recomputes_verdict_ignoring_declared_verdict() {
        let plan = default_plan_sha();
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
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &reg,
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
        assert!(out.per_observable[0].verdict != ObservableVerdict::Pass);
    }

    #[test]
    fn protected_and_candidate_can_share_plan_via_require_identical() {
        let plan = default_plan_sha();
        let p = valid_evidence("origin_macro", &plan);
        let c = valid_evidence("origin_macro", &plan);
        let reg = registry_with(&plan);
        require_identical_stimulus_plan(&p, &c, &reg).unwrap();
    }

    // --- structural / schema attacks ---

    #[test]
    fn rejects_unknown_schema_version() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.schema_version = "mida.unknown/v9".into();
        let err = parse_contract_evidence(&serde_json::to_vec(&ev).unwrap()).unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::SchemaVersion(_)));
    }

    #[test]
    fn rejects_unknown_field() {
        let json = br#"{"schema_version":"mida.oreans-behavior-oracle-contract/v2","bogus":1}"#;
        assert!(parse_contract_evidence(json).is_err());
    }

    #[test]
    fn rejects_non_gate_case() {
        let plan = default_plan_sha();
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
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli.clear();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::EmptyStimuli));
    }

    #[test]
    fn rejects_empty_observables() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables.clear();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::EmptyObservables));
    }

    #[test]
    fn rejects_duplicate_stimulus_id() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli.push(BehaviorStimulus {
            id: "startup".into(),
            value: "x".into(),
        });
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::BadStimulusId(_)));
    }

    #[test]
    fn rejects_empty_stimulus_value() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli[0].value = "".into();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::EmptyStimulusValue(_)
        ));
    }

    #[test]
    fn rejects_duplicate_observable_id() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables.push(ev.observables[0].clone());
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadObservableId(_)
        ));
    }

    #[test]
    fn rejects_empty_observable_expected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[1].expected = "".into();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadObservableField(_)
        ));
    }

    // --- identity / drift attacks ---

    #[test]
    fn rejects_protected_candidate_identity_swap() {
        let plan = default_plan_sha();
        let ev = valid_evidence("origin_macro", &plan);
        let mut exp = expected("origin_macro", &plan);
        std::mem::swap(&mut exp.candidate, &mut exp.protected_input);
        let err = verify_contract_bound(&ev, &exp, &registry_with(&plan), &trusted_observations())
            .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadCandidateIdentity
        ));
    }

    #[test]
    fn rejects_candidate_identity_drift() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.candidate = valid_identity("different-candidate");
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadCandidateIdentity
        ));
    }

    #[test]
    fn rejects_runner_config_digest_drift() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.runner_config_digest = "bb".repeat(32);
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::RunnerConfigDigestMismatch(_, _)
        ));
    }

    #[test]
    fn rejects_tool_revision_drift() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.tool_revision = "other/revision@2".into();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::ToolRevisionMismatch(_, _)
        ));
    }

    #[test]
    fn rejects_stimulus_plan_drift_unregistered() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimulus_plan = plan_ref(&sha("different-plan"));
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::UnregisteredStimulusPlan(_)
        ));
    }

    #[test]
    fn rejects_candidate_and_protected_using_different_plan() {
        // Two genuinely different canonical plans (different content → different
        // hash). Both are registered so the failure is the plan divergence, not
        // an unregistered-plan error.
        let plan_a_stim = canonical_stimuli();
        let plan_b_stim = vec![
            BehaviorStimulus {
                id: "startup".into(),
                value: "launch".into(),
            },
            BehaviorStimulus {
                id: "quit".into(),
                value: "exit-now".into(),
            },
        ];
        let plan_a = canonical_stimuli_hash(&plan_a_stim);
        let plan_b = canonical_stimuli_hash(&plan_b_stim);
        let mut p = valid_evidence("origin_macro", &plan_a);
        p.stimuli = plan_a_stim;
        let mut c = valid_evidence("origin_macro", &plan_b);
        c.stimuli = plan_b_stim;
        let mut reg = StimulusPlanRegistry::new();
        register_stimuli(&mut reg, p.stimuli.clone(), None);
        register_stimuli(&mut reg, c.stimuli.clone(), None);
        assert!(require_identical_stimulus_plan(&p, &c, &reg).is_err());
    }

    #[test]
    fn rejects_case_id_drift() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.case_id = "lunlun_software".into();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::CaseIdMismatch(_, _)
        ));
    }

    // --- observable verdict recomputation ---

    #[test]
    fn missing_observable_fails_closed() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[1].observed.status = BehaviorObservedStatus::Missing;
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
        assert!(out.per_observable[1].verdict == ObservableVerdict::Missing);
    }

    #[test]
    fn timeout_observable_fails_closed() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.status = BehaviorObservedStatus::Timeout;
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn malformed_observable_fails_closed() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.status = BehaviorObservedStatus::Malformed;
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn partial_observable_fails_closed() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.status = BehaviorObservedStatus::Partial;
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn mismatch_observable_fails_closed() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[0].observed.value = "7".into();
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
        assert!(out.per_observable[0].verdict == ObservableVerdict::Mismatch);
    }

    #[test]
    fn caller_cannot_pass_a_verdict() {
        let plan = default_plan_sha();
        let ev = valid_evidence("origin_macro", &plan);
        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&ev).unwrap()).unwrap();
        assert!(value.get("verdict").is_none());
        assert!(value.get("final_verdict").is_none());
    }

    #[test]
    fn single_failure_cannot_forge_overall_pass() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.observables[1].observed.value = "NO_MARKER".into();
        ev.reason = "overall pass".into();
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    #[test]
    fn stale_evidence_binding_emitted_at_required() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.execution.completion.done = false;
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::BadExecution));
    }

    #[test]
    fn rejects_empty_reason() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.reason = "".into();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(err, BehaviorOracleContractError::EmptyReason));
    }

    // --- equivalence manufacture ---

    #[test]
    fn rejects_equivalence_manufacture_marker() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // P1: manufacture is a STRUCTURED field, not reason text. Setting the
        // structured server-patch state must reject.
        ev.equivalence_proof.server_patch_state = Some("patched".into());
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::EquivalenceManufacture(_)
        ));
    }

    /// P1: the free-text `reason` is human-only — it must NOT trigger a verdict
    /// on its own, in either direction. A manufacture-sounding reason with a
    /// CLEAN structured proof does not fail (the structured proof is the gate).
    #[test]
    fn reason_text_is_not_a_security_control() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.reason = "we used server_patch, SERVER_PATCH, forced_visibility and \
                     semantic_bypass to make it work"
            .into();
        // Clean structured proof → still verifies (passes or NotRun, never a
        // manufacture rejection from reason text alone).
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_ne!(out.final_verdict, BehaviorContractVerdict::Fail);
    }

    /// P1: reason text with case/spacing/synonym variants must NOT be treated
    /// as a manufacture marker (the old substring blacklist is gone).
    #[test]
    fn reason_text_variants_do_not_mark_manufacture() {
        for reason in [
            "server patch",
            "SERVER_PATCH",
            "server_patch ",
            "semantic bypass",
            "case specific success override",
            "",
        ] {
            let plan = default_plan_sha();
            let mut ev = valid_evidence("origin_macro", &plan);
            ev.reason = reason.to_string();
            // Empty reason is still rejected by shape (human text must exist);
            // other variants with a clean structured proof are not manufacture.
            let err = verify_contract_bound(
                &ev,
                &expected("origin_macro", &plan),
                &registry_with(&plan),
                &trusted_observations(),
            )
            .err();
            if reason.is_empty() {
                assert!(matches!(
                    err,
                    Some(BehaviorOracleContractError::EmptyReason)
                ));
            } else {
                assert!(!matches!(
                    err,
                    Some(BehaviorOracleContractError::EquivalenceManufacture(_))
                ));
            }
        }
    }

    #[test]
    fn structured_server_patch_without_reason_marker_still_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // Structured patch state set, but reason says nothing about it.
        ev.reason = "clean run".into();
        ev.equivalence_proof.server_patch_state = Some("on".into());
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::EquivalenceManufacture(_)
        ));
    }

    #[test]
    fn unknown_transform_in_ledger_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.equivalence_proof
            .transform_ledger
            .push(TransformProofEntry {
                id: "gto_bypass".into(),
                kind: "sample_bypass".into(),
                equivalence_rule: Some("whatever".into()),
            });
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::UnallowedTransform { .. }
        ));
    }

    #[test]
    fn allowlisted_transform_with_mismatched_rule_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // iat_rebuild is allowlisted ONLY with rule pe_iat_rebuild_v0.
        ev.equivalence_proof
            .transform_ledger
            .push(TransformProofEntry {
                id: "iat_rebuild".into(),
                kind: "pe_repair".into(),
                equivalence_rule: Some("pe_iat_rebuild_v0".into()),
            });
        // Matching rule → clean proof, still passes (real observation bound).
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Pass);

        // Mismatched rule → reject.
        ev.equivalence_proof.transform_ledger[0].equivalence_rule = Some("wrong_rule".into());
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::UnallowedTransform { .. }
        ));
    }

    #[test]
    fn unbound_runtime_patch_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.equivalence_proof
            .runtime_patch_ledger
            .push(PatchProofEntry {
                id: "raw_patch".into(),
                description: "patched the IAT bytes directly".into(),
            });
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::UnallowedPatch { .. }
        ));
    }

    #[test]
    fn missing_observation_source_returns_not_run_not_pass() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // A well-formed but UNREGISTERED observation (self-reported Some-equivalent)
        // is not verifier-trusted → NotRun (Pending), never a fabricated Pass.
        ev.equivalence_proof.observation_source_hash = sha("self-reported-fake-observation");
        ev.equivalence_proof.execution_environment_digest = sha("self-reported-fake-env");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        // Self-reported observation is not registered → Pending, never Pass.
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// P1 issue 1: a caller self-reporting `Some(observation_hash)` must NOT
    /// green-light a `Pass`. The observation must be registered in the
    /// verifier-side trusted registry. This is the false-green regression test.
    #[test]
    fn self_reported_observation_cannot_produce_pass() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // The caller fabricates a well-formed but unregistered observation.
        ev.equivalence_proof.observation_source_hash = sha("forged-source");
        ev.equivalence_proof.execution_environment_digest = sha("forged-env");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// A REGISTERED observation with a DIFFERENT environment digest is also not
    /// trusted (the pair must match exactly).
    #[test]
    fn registered_observation_wrong_environment_is_not_run() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.equivalence_proof.execution_environment_digest = sha("different-env");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// The opaque trust token is NOT caller-derivable: a forged token (even for
    /// the exact issued (source, env) pair) that does not match the
    /// verifier-minted value is rejected → NotRun, never Pass.
    #[test]
    fn forged_trust_token_is_not_trusted() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // Same (source, env) as the issued observation, but a GUESSED token.
        ev.equivalence_proof.trust_token = sha("attacker-guessed-token");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// A token minted for observation A cannot authorize observation B (token
    /// is observation-bound).
    #[test]
    fn token_bound_to_one_observation_does_not_authorize_another() {
        let plan = default_plan_sha();
        // Mint a token for observation A, but evidence claims observation B with
        // A's token → not trusted.
        let mut reg = TrustedObservationRegistry::new();
        reg.issue(&sha("observation-a"), &sha("env-a"))
            .expect("issue A");
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.equivalence_proof.trust_token = observer_token_for(&sha("observation-a"), &sha("env-a"))
            .as_str()
            .to_string();
        ev.equivalence_proof.observation_source_hash = sha("observation-b");
        ev.equivalence_proof.execution_environment_digest = sha("env-b");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &reg,
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    #[test]
    fn missing_probe_identity_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.equivalence_proof.probe_binary_identity = BehaviorChainIdentity {
            sha256: String::new(),
            version: String::new(),
        };
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadEquivalenceProof
        ));
    }

    #[test]
    fn missing_transform_ledger_rejected_on_parse() {
        // A structured proof missing the `transform_ledger` field must be
        // rejected by the strict schema (it is a required security field).
        let plan = default_plan_sha();
        let ev = valid_evidence("origin_macro", &plan);
        let mut value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&ev).unwrap()).unwrap();
        value["equivalence_proof"]
            .as_object_mut()
            .unwrap()
            .remove("transform_ledger");
        let bytes = serde_json::to_vec(&value).unwrap();
        assert!(parse_contract_evidence(&bytes).is_err());
    }

    #[test]
    fn no_sample_hash_pass_override_path() {
        let plan = default_plan_sha();
        let ev = valid_evidence("origin_macro", &plan);
        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&ev).unwrap()).unwrap();
        assert!(value.get("pass_override").is_none());
        assert!(value.get("sample_hash_pass").is_none());
        assert!(value.get("success_override").is_none());
    }

    // --- stimulus plan CONTENT binding (P1: keep-hash / tamper-stimuli) ---

    /// Retains the valid registered hash but replaces `evidence.stimuli` with a
    /// do-nothing plan (the exact acceptance criterion). Must reject. The
    /// replacement is shape-valid (non-empty ids/values) so the failure is the
    /// content mismatch, not an earlier shape rejection.
    #[test]
    fn keep_valid_hash_tamper_stimuli_do_nothing_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli = vec![BehaviorStimulus {
            id: "noop".into(),
            value: "noop".into(),
        }];
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanContentMismatch { .. }
        ));
    }

    #[test]
    fn same_hash_different_value_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli[0].value = "altered-launch".into();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanContentMismatch { .. }
        ));
    }

    #[test]
    fn same_hash_one_fewer_stimulus_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli.pop(); // remove one stimulus
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanContentMismatch { .. }
        ));
    }

    #[test]
    fn same_hash_reordered_stimuli_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli.reverse(); // reorder
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanContentMismatch { .. }
        ));
    }

    /// P5: the stimulus-plan hash is ORDER-bound — two plans running the same
    /// stimuli in a different order produce different canonical hashes, so the
    /// registry keys them as distinct plans (order matters for behavior).
    #[test]
    fn stimulus_hash_binds_order() {
        let forward = canonical_stimuli();
        let reversed = {
            let mut v = canonical_stimuli();
            v.reverse();
            v
        };
        let h_forward = canonical_stimuli_hash(&forward);
        let h_reversed = canonical_stimuli_hash(&reversed);
        assert_ne!(
            h_forward, h_reversed,
            "reordering must change the canonical hash (order-bound)"
        );
        // Both register independently as distinct plans (no collision).
        let mut reg = StimulusPlanRegistry::new();
        register_stimuli(&mut reg, forward, None);
        register_stimuli(&mut reg, reversed, None);
        assert!(reg.plan(&h_forward).is_some());
        assert!(reg.plan(&h_reversed).is_some());
    }

    #[test]
    fn same_hash_modified_stimulus_id_rejected() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli[1].id = "rename".into();
        let err = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanContentMismatch { .. }
        ));
    }

    #[test]
    fn register_rejects_hash_content_mismatch() {
        let mut reg = StimulusPlanRegistry::new();
        let wrong_hash = sha("not-the-content-hash");
        let err = reg
            .register(wrong_hash.clone(), canonical_stimuli())
            .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanHashMismatch { .. }
        ));
        // Nothing was recorded under the bogus hash.
        assert!(reg.plan(&wrong_hash).is_none());
    }

    #[test]
    fn register_rejects_duplicate_hash_different_content() {
        let mut reg = StimulusPlanRegistry::new();
        register_stimuli(&mut reg, canonical_stimuli(), None);
        // The same declared hash but a different stimulus set must be refused:
        // content-bound registration means the declared hash binds the exact
        // content, so a different set under the canonical hash is rejected
        // (a real SHA-256 collision between two distinct sets is cryptographically
        // infeasible; the hash binding is the effective guard).
        let different = vec![BehaviorStimulus {
            id: "startup".into(),
            value: "other".into(),
        }];
        let err = reg
            .register(canonical_stimuli_hash(&canonical_stimuli()), different)
            .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanHashMismatch { .. }
        ));
        // The canonical plan is untouched.
        assert!(reg.plan(&default_plan_sha()).is_some());
    }

    #[test]
    fn verify_contract_also_enforces_plan_content() {
        // `verify_contract` (non-bound) must enforce the same content binding.
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.stimuli = vec![BehaviorStimulus {
            id: "x".into(),
            value: "y".into(),
        }];
        let err = verify_contract(&ev, &registry_with(&plan), &trusted_observations()).unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::StimulusPlanContentMismatch { .. }
        ));
    }

    // --- honest recomputation identity attack ---

    #[test]
    fn honest_recompute_candidate_hash_identity_attack() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.candidate = valid_identity("attacker-candidate");
        let bytes = serde_json::to_vec(&ev).unwrap();
        let reparsed = parse_contract_evidence(&bytes).unwrap();
        let err = verify_contract_bound(
            &reparsed,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::BadCandidateIdentity
        ));
    }
}
