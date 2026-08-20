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
//! (`archive/routes/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md` lists "define the behavior
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
    /// Opaque trust token produced ONLY by the real verifier seam
    /// ([`verify_observation_artifact`]) for an artifact it actually verified
    /// under an externally-injected verifier key. A caller cannot mint or
    /// recompute one. The verdict is `Pass` only when this token resolves, in
    /// the verifier-side [`TrustedObservationRegistry`], to a verified
    /// observation whose every trust binding (case/candidate/protected/probe/
    /// runner/tool revision/runner config digest) matches this evidence exactly.
    pub trust_token: String,
    /// Hash of the raw observation source (probe logs). **Descriptive**: this
    /// field is cross-checked against the observation bound to the `trust_token`
    /// and must equal the hash the verifier recomputed from the observation
    /// artifact bytes. It is not, by itself, proof of a real observation.
    pub observation_source_hash: String,
    /// Digest of the execution environment that produced the observation.
    /// **Descriptive** and cross-checked against the environment digest the
    /// verifier recomputed from the canonicalized environment manifest.
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

/// An opaque trust token held ONLY by the verifier. It is derived with HMAC-
/// SHA256 over every bound artifact field, keyed by an EXTERNALLY-INJECTED
/// verifier key (from a real trust root — never a hardcoded or serialized
/// secret). It is intentionally NOT `Serialize`/`Deserialize`: the value is
/// carried in evidence as a plain opaque string, but a caller can neither mint
/// one (no public API) nor recompute one (key not in the library). It is also
/// NOT re-exported from the crate root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustToken(String);

impl TrustToken {
    fn as_str(&self) -> &str {
        &self.0
    }
}

/// Trusted bindings the real verifier must cross-check an observation artifact
/// against before it may enter the trusted registry. These are the artifact's
/// identity and scope: the observation is ONLY trusted for the exact candidate,
/// case, protected input, probe, runner, tool revision and runner-config digest
/// that were verified together. Reusing an observation across any other
/// artifact is rejected (token replay / scope confusion).
#[derive(Debug, Clone)]
pub(crate) struct VerifiedObservationBindings {
    pub case_id: String,
    pub candidate_sha256: String,
    pub protected_sha256: String,
    pub probe_sha256: String,
    pub runner_sha256: String,
    pub tool_revision: String,
    pub runner_config_digest: String,
}

/// A real, verifier-verified runtime observation. All fields are private and
/// there is NO public constructor: a value of this type can only be produced by
/// the real verifier seam (`observation_verifier_proto::verify_observation_artifact`,
/// a `#[cfg(test)]` prototype — see below), which reads the actual observation
/// bytes and environment manifest, recomputes their hashes, binds every trust
/// field, and HMAC-signs the whole binding under the externally-injected
/// verifier key. External callers cannot manufacture one.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedObservationArtifact {
    observation_source_hash: String,
    execution_environment_digest: String,
    token: TrustToken,
    bindings: VerifiedObservationBindings,
}

// ---------------------------------------------------------------------------
// PRODUCTION BOUNDARY (P2 / P9-live blocker)
// ---------------------------------------------------------------------------
//
// The observation-verification machinery that mints a `VerifiedObservationArtifact`
// and ingests it into the trusted registry (`verify_observation_artifact`,
// `canonical_environment_digest`, `observer_token_for`, `hmac_sha256`, ...) is a
// **test-only prototype**. There is NO real production artifact verifier and NO
// configured production trust root in this codebase (the per-case business
// oracle is a documented P9-live blocker). Therefore:
//
//   - these functions live in a `#[cfg(test)]` module and are NOT compiled into
//     production (no dead_code, no false "wired" claim);
//   - production always keeps the `TrustedObservationRegistry` EMPTY, so the
//     offline verdict is always `NotRun`/`Pending`;
//   - the prototype is deliberately NOT reachable by library consumers
//     (`verify_observation_artifact` is not `pub`), so a caller cannot pick its
//     own key and establish a trust root;
//   - wiring a real production verifier (external observation attestation +
//     fixed public-key allowlist) is outstanding P9 work; until then the Product
//     behavior-Pass path is NOT implemented.
//
// See `mod observation_verifier_proto` at the end of this file for the
// prototype implementation and its regression tests.

/// Verifier-side registry of TRUSTED runtime observations (P1 issue 1: no
/// self-reported-`Some` false-green, no caller self-minting).
///
/// A behavioral `Pass` is ONLY possible for an observation that was actually
/// verified by the real verifier seam
/// (`observation_verifier_proto::verify_observation_artifact`, a `#[cfg(test)]`
/// prototype) and ingested here. There is NO public minting API and the
/// registry is empty by default; a caller cannot construct a Product trust root
/// from raw strings.
///
/// `observation_is_trusted` is replay-resistant: it requires the evidence's
/// opaque token to exactly match the token bound to the verified observation
/// AND every trust binding (case/candidate/protected/probe/runner/tool revision/
/// runner config digest) declared on the evidence to equal the verified
/// artifact's binding. So a token minted for observation A on candidate A
/// cannot authorize observation B, candidate B, another case, another runner,
/// a drifted observation, or a drifted environment.
#[derive(Debug, Clone, Default)]
pub struct TrustedObservationRegistry {
    /// `observation_source_hash -> verified artifact`.
    artifacts: std::collections::BTreeMap<String, VerifiedObservationArtifact>,
}

impl TrustedObservationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a real verifier-verified observation. Reachable only from the
    /// `#[cfg(test)]` prototype seam (`observation_verifier_proto`) — there is
    /// no production verifier, so this is not compiled into production. A
    /// duplicate observation_source_hash with different content is refused
    /// (fail-closed, never silently overwritten).
    #[cfg(test)]
    pub(crate) fn ingest(
        &mut self,
        artifact: VerifiedObservationArtifact,
    ) -> Result<(), BehaviorOracleContractError> {
        let key = artifact.observation_source_hash.clone();
        if let Some(existing) = self.artifacts.get(&key) {
            if existing.token != artifact.token {
                return Err(BehaviorOracleContractError::ObservationCollision(key));
            }
            // Same token ⇒ same binding; idempotent re-ingest is allowed.
            return Ok(());
        }
        self.artifacts.insert(key, artifact);
        Ok(())
    }

    /// Whether the evidence's observation is trusted. See the type docs for the
    /// full binding requirements (token + all trust fields must match).
    ///
    /// The token comparison is CONSTANT-TIME (no early exit on the first
    /// differing byte), so a remote oracle cannot use timing to recover token
    /// bytes from a query boundary.
    pub fn observation_is_trusted(&self, evidence: &BehaviorOracleContractEvidence) -> bool {
        let proof = &evidence.equivalence_proof;
        let source = proof.observation_source_hash.trim().to_lowercase();
        let Some(artifact) = self.artifacts.get(&source) else {
            // Not a verifier-verified observation (empty offline registry → false).
            return false;
        };
        // Defensive: the artifact's stored source must equal the map key.
        if artifact.observation_source_hash.trim().to_lowercase() != source {
            return false;
        }
        // Constant-time token comparison.
        if !ct_eq_hex(proof.trust_token.trim(), artifact.token.as_str()) {
            return false;
        }
        // Environment digest must match.
        if proof.execution_environment_digest.trim().to_lowercase()
            != artifact.execution_environment_digest
        {
            return false;
        }
        // Every trust binding must match (replay / scope-confusion resistant).
        let b = &artifact.bindings;
        evidence.case_id.trim() == b.case_id.trim()
            && evidence.candidate.sha256.trim().to_lowercase() == b.candidate_sha256
            && evidence.protected_input.sha256.trim().to_lowercase() == b.protected_sha256
            && evidence.cli_identity.sha256.trim().to_lowercase() == b.probe_sha256
            && evidence.verifier_identity.sha256.trim().to_lowercase() == b.runner_sha256
            && evidence.tool_revision.trim() == b.tool_revision
            && evidence.runner_config_digest.trim().to_lowercase() == b.runner_config_digest
    }
}

/// Constant-time equality over two lowercase hex strings of equal length.
/// Returns `false` immediately only on a length mismatch; otherwise every byte
/// pair is compared and the result is the XOR of all differences (no early exit
/// on the first differing byte).
fn ct_eq_hex(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
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
        "no trusted verifier key configured — observation trust cannot be established offline"
    )]
    NoTrustedVerifierKey,
    #[error("environment manifest is missing or malformed")]
    BadEnvironmentManifest,
    #[error("environment manifest rejected: {0}")]
    EnvironmentManifestRejected(String),
    #[error(
        "observation artifact bindings are malformed (must be non-empty + well-formed hashes)"
    )]
    BadObservationBindings,
    #[error("conflicting observation artifact re-registered under the same source hash")]
    ObservationCollision(String),
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
    "archive/routes/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md lists 'define the behavior ",
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
    use super::observation_verifier_proto::{
        canonical_environment_digest, observer_token_for, verify_observation_artifact,
    };
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
    /// `Pass`). The `trust_token` and the observation hashes are the ones the
    /// REAL verifier seam [`verify_observation_artifact`] produces for
    /// `TEST_OBSERVATION_BYTES` / `TEST_ENV_MANIFEST` under the externally
    /// injected `TEST_VERIFIER_KEY` and the case's trust bindings — so
    /// `valid_evidence` claims exactly an observation the verifier actually
    /// verified (matching what [`trusted_observations`] ingested).
    fn clean_proof() -> EquivalenceProof {
        let bindings = test_bindings("origin_macro");
        let obs = sha256_bytes(TEST_OBSERVATION_BYTES);
        let env = canonical_environment_digest(TEST_ENV_MANIFEST).expect("canonical env");
        let token = observer_token_for(TEST_VERIFIER_KEY, &obs, &env, &bindings);
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
            trust_token: token.as_str().to_string(),
            observation_source_hash: obs,
            execution_environment_digest: env,
        }
    }

    /// The verifier-side trusted observation registry populated through the REAL
    /// verifier seam: it verifies `TEST_OBSERVATION_BYTES` / `TEST_ENV_MANIFEST`
    /// under the injected test key and ingests the resulting artifact. This is
    /// the only way a `Pass` can occur in tests — exactly as in production, a
    /// `Pass` requires a verifier-verified observation.
    fn trusted_observations() -> TrustedObservationRegistry {
        let mut reg = TrustedObservationRegistry::new();
        let artifact = verify_observation_artifact(
            TEST_OBSERVATION_BYTES,
            TEST_ENV_MANIFEST,
            TEST_VERIFIER_KEY,
            &test_bindings("origin_macro"),
        )
        .expect("verify real observation artifact");
        reg.ingest(artifact).expect("ingest verified artifact");
        reg
    }

    /// Test observation artifact bytes (non-empty, verifier-verified in tests).
    const TEST_OBSERVATION_BYTES: &[u8] = b"real-probe-observation-log";
    /// Test environment manifest — a strict `EnvironmentManifestV1` (with
    /// schema_version), canonicalized by the verifier.
    const TEST_ENV_MANIFEST: &[u8] =
        br#"{"schema_version":"mida.environment-manifest/v1","arch":"x86_64","os":"win","budget":"controlled"}"#;
    /// Externally-injected verifier key used by the tests. This is NOT a
    /// hardcoded library secret — it is injected at the seam exactly as a real
    /// deployment would inject a verifier trust-root key.
    const TEST_VERIFIER_KEY: &[u8] = b"unit-test-injected-verifier-key-material";

    fn sha256_bytes(b: &[u8]) -> String {
        crate::sha256_hex(b)
    }

    /// The trust bindings the tests use, matching the identity fields that
    /// `valid_evidence(case_id)` produces.
    fn test_bindings(case_id: &str) -> VerifiedObservationBindings {
        VerifiedObservationBindings {
            case_id: case_id.to_string(),
            candidate_sha256: sha("candidate"),
            protected_sha256: sha("protected"),
            probe_sha256: sha("cli-binary"),
            runner_sha256: sha("verifier"),
            tool_revision: "oreans/two-sample-mainline@1".to_string(),
            runner_config_digest: "aa".repeat(32),
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
        // A well-formed but UNVERIFIED observation (self-reported Some-equivalent)
        // is not verifier-trusted → NotRun (Pending), never a fabricated Pass.
        ev.equivalence_proof.observation_source_hash = sha("self-reported-fake-observation");
        ev.equivalence_proof.execution_environment_digest = sha("self-reported-fake-env");
        ev.equivalence_proof.trust_token = sha("self-reported-fake-token");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        // Self-reported observation is not verifier-verified → Pending, never Pass.
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// P1 issue 1: a caller self-reporting an observation hash + environment
    /// digest must NOT green-light a `Pass`, even with a well-formed token.
    /// Only an observation the real verifier seam verified is trusted. This is
    /// the false-green regression test.
    #[test]
    fn self_reported_observation_cannot_produce_pass() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // The caller fabricates a well-formed but never-verified observation.
        ev.equivalence_proof.observation_source_hash = sha("forged-source");
        ev.equivalence_proof.execution_environment_digest = sha("forged-env");
        ev.equivalence_proof.trust_token = sha("forged-token");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// A verifier-verified observation with a DIFFERENT environment digest is
    /// not trusted (environment digest drift).
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
    /// the exact verified (source, env) pair) that does not match the
    /// verifier-minted value is rejected → NotRun, never Pass.
    #[test]
    fn forged_trust_token_is_not_trusted() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // Same (source, env) as the verified observation, but a GUESSED token.
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

    /// A token minted (via the real verifier seam) for observation A cannot
    /// authorize observation B: the token is observation-bound.
    #[test]
    fn token_bound_to_one_observation_does_not_authorize_another() {
        let plan = default_plan_sha();
        // Verify observation A through the real seam.
        let obs_a: &[u8] = b"observation-a-log";
        let mut reg = TrustedObservationRegistry::new();
        let artifact_a = verify_observation_artifact(
            obs_a,
            TEST_ENV_MANIFEST,
            TEST_VERIFIER_KEY,
            &test_bindings("origin_macro"),
        )
        .expect("verify A");
        reg.ingest(artifact_a).expect("ingest A");
        // Evidence claims observation B with A's token → not trusted.
        let mut ev = valid_evidence("origin_macro", &plan);
        let obs_a_hash = sha256_bytes(obs_a);
        ev.equivalence_proof.observation_source_hash = sha("observation-b");
        ev.equivalence_proof.execution_environment_digest =
            canonical_environment_digest(TEST_ENV_MANIFEST).expect("env");
        // Reuse A's token: it must NOT authorize observation B.
        ev.equivalence_proof.trust_token = observer_token_for(
            TEST_VERIFIER_KEY,
            &obs_a_hash,
            &canonical_environment_digest(TEST_ENV_MANIFEST).expect("env"),
            &test_bindings("origin_macro"),
        )
        .as_str()
        .to_string();
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &reg,
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// Caller cannot self-issue a trusted observation: the real verifier seam
    /// requires the externally-injected key and real artifact bytes; an empty
    /// registry (no real verification) yields NotRun. This proves there is no
    /// public path for a caller to mint a Pass.
    #[test]
    fn caller_cannot_self_issue_a_trusted_observation() {
        let plan = default_plan_sha();
        // Offline: no real artifact verifier has run, so the registry is empty.
        let empty_reg = TrustedObservationRegistry::new();
        let ev = valid_evidence("origin_macro", &plan);
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &empty_reg,
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
        // And even a caller-supplied token can never become trusted without the
        // real verifier seam ingesting an artifact for it.
        assert!(!empty_reg.observation_is_trusted(&ev));
    }

    /// Without a real verifier key (empty), the artifact verification fails
    /// closed — there is no way to mint an observation trust token offline.
    #[test]
    fn artifact_verification_requires_verifier_key() {
        let err = verify_observation_artifact(
            TEST_OBSERVATION_BYTES,
            TEST_ENV_MANIFEST,
            b"", // no key
            &test_bindings("origin_macro"),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            BehaviorOracleContractError::NoTrustedVerifierKey
        ));
    }

    /// The empty-offline-registry must not trust any evidence, so a caller
    /// cannot manufacture Product trust without the real verifier.
    #[test]
    fn empty_offline_registry_never_trusts() {
        let reg = TrustedObservationRegistry::new();
        let ev = valid_evidence("origin_macro", &default_plan_sha());
        assert!(!reg.observation_is_trusted(&ev));
    }

    /// Observation bytes drift: the verifier verified one observation log; the
    /// evidence claims a different observation_source_hash → NotRun.
    #[test]
    fn observation_bytes_drift_is_not_trusted() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        // The verifier verified TEST_OBSERVATION_BYTES; drift the claimed hash.
        ev.equivalence_proof.observation_source_hash = sha256_bytes(b"drifted-observation-log");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// Environment manifest drift: the verifier canonicalized TEST_ENV_MANIFEST;
    /// a different environment digest → NotRun.
    #[test]
    fn environment_digest_drift_is_not_trusted() {
        let plan = default_plan_sha();
        let mut ev = valid_evidence("origin_macro", &plan);
        ev.equivalence_proof.execution_environment_digest =
            canonical_environment_digest(br#"{"schema_version":"mida.environment-manifest/v1","arch":"arm64","os":"win","budget":"unlimited"}"#)
                .expect("env");
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &trusted_observations(),
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::NotRun);
    }

    /// Replay across a different CANDIDATE is rejected: a token verified for
    /// candidate A cannot authorize candidate B.
    #[test]
    fn token_verified_for_candidate_a_does_not_authorize_candidate_b() {
        let reg = trusted_observations();
        let mut ev = valid_evidence("origin_macro", &default_plan_sha());
        ev.candidate = valid_identity("attacker-candidate");
        // The registry must refuse to trust this evidence: the token is bound
        // to the original candidate, not attacker-candidate.
        assert!(!reg.observation_is_trusted(&ev));
    }

    /// Replay across a different CASE is rejected.
    #[test]
    fn token_verified_for_case_a_does_not_authorize_case_b() {
        let reg = trusted_observations(); // minted for origin_macro
        let ev = valid_evidence("lunlun_software", &default_plan_sha());
        assert!(!reg.observation_is_trusted(&ev));
    }

    /// Replay across a different RUNNER (verifier identity) is rejected.
    #[test]
    fn token_verified_for_runner_a_does_not_authorize_runner_b() {
        let reg = trusted_observations();
        let mut ev = valid_evidence("origin_macro", &default_plan_sha());
        ev.verifier_identity = BehaviorChainIdentity {
            sha256: sha("attacker-verifier"),
            version: "attacker-v1".to_string(),
        };
        assert!(!reg.observation_is_trusted(&ev));
    }

    /// Replay across a different PROBE (cli identity) is rejected.
    #[test]
    fn token_verified_for_probe_a_does_not_authorize_probe_b() {
        let reg = trusted_observations();
        let mut ev = valid_evidence("origin_macro", &default_plan_sha());
        ev.cli_identity = BehaviorChainIdentity {
            sha256: sha("attacker-cli"),
            version: "attacker-cli-v1".to_string(),
        };
        assert!(!reg.observation_is_trusted(&ev));
    }

    /// Replay across a different RUNNER CONFIG DIGEST is rejected.
    #[test]
    fn token_verified_for_runner_config_a_does_not_authorize_config_b() {
        let reg = trusted_observations();
        let mut ev = valid_evidence("origin_macro", &default_plan_sha());
        ev.runner_config_digest = "bb".repeat(32);
        assert!(!reg.observation_is_trusted(&ev));
    }

    /// A duplicate observation_source_hash re-verified with DIFFERENT content
    /// must fail closed (ObservationCollision), never silently overwrite.
    #[test]
    fn duplicate_observation_source_with_different_content_fails_closed() {
        let mut reg = TrustedObservationRegistry::new();
        let a = verify_observation_artifact(
            TEST_OBSERVATION_BYTES,
            TEST_ENV_MANIFEST,
            TEST_VERIFIER_KEY,
            &test_bindings("origin_macro"),
        )
        .expect("first verify");
        reg.ingest(a).expect("ingest first");
        // Re-verify the SAME source hash but different content under a different
        // key would produce a different token → collision. But the source hash
        // here is determined by the bytes; to force a collision we must reuse the
        // same bytes (same hash) yet a different binding ⇒ different token.
        let different_bindings = VerifiedObservationBindings {
            candidate_sha256: sha("different-candidate"),
            ..test_bindings("origin_macro")
        };
        let b = verify_observation_artifact(
            TEST_OBSERVATION_BYTES,
            TEST_ENV_MANIFEST,
            TEST_VERIFIER_KEY,
            &different_bindings,
        )
        .expect("second verify");
        // Same source hash, different token → must fail closed.
        assert!(reg.ingest(b).is_err());
    }

    /// Only an artifact the real verifier seam actually verified can produce a
    /// Pass — the positive control.
    #[test]
    fn only_real_verifier_verified_artifact_can_pass() {
        let plan = default_plan_sha();
        // Build a registry through the real seam.
        let reg = trusted_observations();
        let ev = valid_evidence("origin_macro", &plan);
        assert!(reg.observation_is_trusted(&ev));
        let out = verify_contract_bound(
            &ev,
            &expected("origin_macro", &plan),
            &registry_with(&plan),
            &reg,
        )
        .unwrap();
        assert_eq!(out.final_verdict, BehaviorContractVerdict::Pass);
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

// ===========================================================================
// `observation_verifier_proto` — TEST-ONLY PRODUCTION BOUNDARY (P2 / P9-live)
// ===========================================================================
//
// This module contains the OBSERVATION-VERIFIER PROTOTYPE. It is `#[cfg(test)]`
// only: there is NO real production artifact verifier and NO configured
// production trust root in this codebase (the per-case business oracle is a
// documented P9-live blocker). These functions are NOT compiled into production
// and are NOT reachable by library consumers, so no caller can pick its own key
// and establish a trust root. Production keeps the `TrustedObservationRegistry`
// empty and the offline verdict is always `NotRun`/`Pending`.
//
// The environment-manifest canonicalization here is a real, injective encoding
// (P1): type-tagged, UTF-8-length-prefixed, sorted keys, explicit counts — so
// `{"a":1,"b":2}` and `{"a:1,b":2}` canonicalize to DIFFERENT digests and keys
// or values containing `:`, `,`, `"`, `\`, NUL or control bytes cannot collide.
// The token binding is likewise domain-separated and length-prefixed.
#[cfg(test)]
mod observation_verifier_proto {
    use super::*;

    /// Domain prefix for the environment-manifest canonical encoding.
    const ENV_DOMAIN_PREFIX: &[u8] = b"mida.environment-manifest/v1";
    /// Domain prefix for the observation-token HMAC binding.
    const TOKEN_DOMAIN_PREFIX: &[u8] = b"mida.observation-token/v1";
    /// Minimum verifier-key strength (256-bit = 32 bytes) required to mint.
    const MIN_VERIFIER_KEY_BYTES: usize = 32;

    /// A JSON value parsed injectively: objects preserve every key and reject
    /// DUPLICATE keys (a `serde_json::Value` would silently dedupe). Only
    /// integers are kept for numbers (floats are ambiguous and rejected).
    #[derive(Debug, Clone)]
    pub(super) enum RawJson {
        Null,
        Bool(bool),
        I64(i64),
        Str(String),
        Arr(Vec<RawJson>),
        /// Object entries in document order (duplicate keys rejected at parse).
        Obj(Vec<(String, RawJson)>),
    }

    impl<'de> Deserialize<'de> for RawJson {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = RawJson;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("any JSON value")
                }
                fn visit_unit<E: serde::de::Error>(self) -> Result<RawJson, E> {
                    Ok(RawJson::Null)
                }
                fn visit_none<E: serde::de::Error>(self) -> Result<RawJson, E> {
                    Ok(RawJson::Null)
                }
                fn visit_some<D: serde::Deserializer<'de>>(
                    self,
                    d: D,
                ) -> Result<RawJson, D::Error> {
                    RawJson::deserialize(d)
                }
                fn visit_bool<E: serde::de::Error>(self, b: bool) -> Result<RawJson, E> {
                    Ok(RawJson::Bool(b))
                }
                fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<RawJson, E> {
                    Ok(RawJson::I64(n))
                }
                fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<RawJson, E> {
                    i64::try_from(n)
                        .map(RawJson::I64)
                        .map_err(serde::de::Error::custom)
                }
                fn visit_f64<E: serde::de::Error>(self, _n: f64) -> Result<RawJson, E> {
                    Err(serde::de::Error::custom(
                        "floating-point numbers are not allowed in an environment manifest \
                         (ambiguous canonical representation)",
                    ))
                }
                fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<RawJson, E> {
                    Ok(RawJson::Str(s.to_string()))
                }
                fn visit_string<E: serde::de::Error>(self, s: String) -> Result<RawJson, E> {
                    Ok(RawJson::Str(s))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<RawJson, A::Error> {
                    let mut items = Vec::new();
                    while let Some(v) = seq.next_element::<RawJson>()? {
                        items.push(v);
                    }
                    Ok(RawJson::Arr(items))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> Result<RawJson, A::Error> {
                    let mut out: Vec<(String, RawJson)> = Vec::new();
                    while let Some(key) = map.next_key::<String>()? {
                        if out.iter().any(|(k, _)| k == &key) {
                            return Err(serde::de::Error::custom(format!(
                                "duplicate object key '{key}'"
                            )));
                        }
                        let val: RawJson = map.next_value()?;
                        out.push((key, val));
                    }
                    Ok(RawJson::Obj(out))
                }
            }
            d.deserialize_any(V)
        }
    }

    /// Parse raw manifest bytes into an injective [`RawJson`]. Rejects malformed
    /// JSON and duplicate keys.
    pub(super) fn parse_raw_json(bytes: &[u8]) -> Result<RawJson, BehaviorOracleContractError> {
        serde_json::from_slice(bytes).map_err(BehaviorOracleContractError::Json)
    }

    /// The strict typed environment manifest. `deny_unknown_fields` + required
    /// fields reject unknown/missing keys; `schema_version` is validated. A
    /// real environment manifest must conform to exactly this schema.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EnvironmentManifestV1 {
        schema_version: String,
        arch: String,
        os: String,
        budget: String,
    }

    const ENV_MANIFEST_SCHEMA: &str = "mida.environment-manifest/v1";

    /// Canonical, INJECTIVE serialization of a JSON value (domain-prefixed,
    /// type-tagged, UTF-8-length-prefixed, sorted object keys, explicit array/
    /// object counts). Two JSON documents canonicalize to equal bytes ONLY if
    /// they are semantically identical (same type, same key multiset with equal
    /// bytes, same array order, same values). Key/value boundaries never rely on
    /// `:`, `,` or unescaped delimiters, so those characters cannot collide.
    pub(super) fn canonical_environment_serialization(value: &RawJson) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ENV_DOMAIN_PREFIX);
        encode_value(value, &mut out);
        out
    }

    fn encode_value(v: &RawJson, out: &mut Vec<u8>) {
        match v {
            RawJson::Null => out.push(0x00),
            RawJson::Bool(false) => out.push(0x01),
            RawJson::Bool(true) => out.push(0x02),
            RawJson::Str(s) => {
                out.push(0x03);
                out.extend_from_slice(&(s.len() as u64).to_le_bytes());
                out.extend_from_slice(s.as_bytes());
            }
            RawJson::I64(n) => {
                out.push(0x04);
                out.extend_from_slice(&n.to_le_bytes());
            }
            RawJson::Arr(items) => {
                out.push(0x05);
                out.extend_from_slice(&(items.len() as u64).to_le_bytes());
                for it in items {
                    encode_value(it, out);
                }
            }
            RawJson::Obj(entries) => {
                out.push(0x06);
                out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
                let mut sorted: Vec<&(String, RawJson)> = entries.iter().collect();
                // Object keys sorted by UTF-8 bytes (order-independent digest).
                sorted.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                for (k, v) in sorted {
                    out.extend_from_slice(&(k.len() as u64).to_le_bytes());
                    out.extend_from_slice(k.as_bytes());
                    encode_value(v, out);
                }
            }
        }
    }

    /// Generic injective digest of a JSON object (no strict-schema check). Used
    /// by the collision / injectivity regression tests to prove the encoder is
    /// injective on arbitrary JSON.
    pub(super) fn raw_env_digest(bytes: &[u8]) -> Result<String, BehaviorOracleContractError> {
        let raw = parse_raw_json(bytes)?;
        if !matches!(raw, RawJson::Obj(ref e) if !e.is_empty()) {
            return Err(BehaviorOracleContractError::BadEnvironmentManifest);
        }
        Ok(crate::sha256_hex(&canonical_environment_serialization(
            &raw,
        )))
    }

    /// STRICT environment-manifest digest for the verifier path: parses (rejecting
    /// duplicate keys / malformed JSON), requires a non-empty object, validates
    /// the strict [`EnvironmentManifestV1`] schema (rejecting unknown/missing
    /// fields and a bad `schema_version`), then canonicalizes injectively.
    pub(super) fn canonical_environment_digest(
        env_manifest: &[u8],
    ) -> Result<String, BehaviorOracleContractError> {
        let raw = parse_raw_json(env_manifest)?;
        if !matches!(raw, RawJson::Obj(ref e) if !e.is_empty()) {
            return Err(BehaviorOracleContractError::BadEnvironmentManifest);
        }
        // Strict schema validation: unknown / missing / wrong-version / float /
        // duplicate keys all rejected here (duplicates already rejected by RawJson).
        let typed: EnvironmentManifestV1 = serde_json::from_slice(env_manifest)
            .map_err(|e| BehaviorOracleContractError::EnvironmentManifestRejected(e.to_string()))?;
        if typed.schema_version != ENV_MANIFEST_SCHEMA {
            return Err(BehaviorOracleContractError::EnvironmentManifestRejected(format!(
                "unsupported environment-manifest schema_version '{}' (expected {ENV_MANIFEST_SCHEMA})",
                typed.schema_version
            )));
        }
        Ok(crate::sha256_hex(&canonical_environment_serialization(
            &raw,
        )))
    }

    /// HMAC-SHA256 (RFC 2104), returned as 64-hex. Self-contained; validated
    /// against RFC 4231 test vectors below.
    pub(super) fn hmac_sha256(key: &[u8], msg: &[u8]) -> String {
        const BLOCK: usize = 64;
        let mut key_block = [0u8; BLOCK];
        if key.len() > BLOCK {
            let d = crate::sha256_hex(key);
            let bytes = hex_to_bytes(&d);
            key_block[..32.min(bytes.len())].copy_from_slice(&bytes[..32.min(bytes.len())]);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0x36u8; BLOCK];
        let mut opad = [0x5cu8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] ^= key_block[i];
            opad[i] ^= key_block[i];
        }
        let inner = crate::sha256_hex(&[ipad.as_slice(), msg].concat());
        let inner_bytes = hex_to_bytes(&inner);
        crate::sha256_hex(&[opad.as_slice(), inner_bytes.as_slice()].concat())
    }

    /// Decode a 64-char lowercase hex SHA-256 into 32 raw bytes. Panics on
    /// malformed input (only ever called on freshly-computed 64-hex values).
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    /// Domain-separated, length-prefixed binary encoding of every trust binding.
    /// Replaces the old `format!("k=v;")` text so future non-hash fields cannot
    /// create boundary ambiguity.
    fn bindings_serialization(
        observation_source_hash: &str,
        execution_environment_digest: &str,
        bindings: &VerifiedObservationBindings,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(TOKEN_DOMAIN_PREFIX);
        for field in [
            observation_source_hash,
            execution_environment_digest,
            &bindings.case_id,
            &bindings.candidate_sha256,
            &bindings.protected_sha256,
            &bindings.probe_sha256,
            &bindings.runner_sha256,
            &bindings.tool_revision,
            &bindings.runner_config_digest,
        ] {
            out.extend_from_slice(&(field.len() as u64).to_le_bytes());
            out.extend_from_slice(field.as_bytes());
        }
        out
    }

    /// Compute the opaque observation token: HMAC-SHA256 over the domain-separated
    /// length-prefixed binding, keyed by the injected verifier key.
    pub(super) fn observer_token_for(
        key: &[u8],
        observation_source_hash: &str,
        execution_environment_digest: &str,
        bindings: &VerifiedObservationBindings,
    ) -> TrustToken {
        let msg = bindings_serialization(
            observation_source_hash,
            execution_environment_digest,
            bindings,
        );
        TrustToken(hmac_sha256(key, &msg))
    }

    /// The REAL verifier seam (prototype): turns observation bytes into a trusted
    /// artifact. Requires a 256-bit-or-stronger externally-injected verifier key,
    /// re-hashes the observation, canonicalizes the environment manifest, binds
    /// every trust field, and HMAC-signs the whole binding. Only this function
    /// can produce a [`VerifiedObservationArtifact`]; it is reachable only from
    /// this `#[cfg(test)]` module and the crate's own tests.
    pub(super) fn verify_observation_artifact(
        observation_bytes: &[u8],
        env_manifest: &[u8],
        verifier_key: &[u8],
        bindings: &VerifiedObservationBindings,
    ) -> Result<VerifiedObservationArtifact, BehaviorOracleContractError> {
        if verifier_key.len() < MIN_VERIFIER_KEY_BYTES {
            return Err(BehaviorOracleContractError::NoTrustedVerifierKey);
        }
        if observation_bytes.is_empty() {
            return Err(BehaviorOracleContractError::BadObservationIdentity);
        }
        if !is_sha256(&bindings.candidate_sha256)
            || !is_sha256(&bindings.protected_sha256)
            || !is_sha256(&bindings.probe_sha256)
            || !is_sha256(&bindings.runner_sha256)
            || !is_sha256(&bindings.runner_config_digest)
            || bindings.case_id.trim().is_empty()
            || bindings.tool_revision.trim().is_empty()
        {
            return Err(BehaviorOracleContractError::BadObservationBindings);
        }
        let observation_source_hash = crate::sha256_hex(observation_bytes);
        let execution_environment_digest = canonical_environment_digest(env_manifest)?;
        let token = observer_token_for(
            verifier_key,
            &observation_source_hash,
            &execution_environment_digest,
            bindings,
        );
        Ok(VerifiedObservationArtifact {
            observation_source_hash,
            execution_environment_digest,
            token,
            bindings: bindings.clone(),
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// RFC 4231 Test Case 1: key=0x0b * 20, data="Hi There".
        const RFC4231_CASE1_KEY: [u8; 20] = [0x0b; 20];
        const RFC4231_CASE1_DATA: &[u8] = b"Hi There";
        const RFC4231_CASE1_EXPECTED: &str =
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        #[test]
        fn rfc4231_case1_hmac_sha256() {
            assert_eq!(
                hmac_sha256(&RFC4231_CASE1_KEY, RFC4231_CASE1_DATA),
                RFC4231_CASE1_EXPECTED
            );
        }

        #[test]
        fn collision_key_value_delimiter_objects_differ() {
            // {"a":1,"b":2} vs {"a:1,b":2} must canonicalize to DIFFERENT digests.
            let a = raw_env_digest(br#"{"a":1,"b":2}"#).unwrap();
            let b = raw_env_digest(br#"{"a:1,b":2}"#).unwrap();
            assert_ne!(a, b, "canonicalization must be injective");
        }

        #[test]
        fn keys_with_metacharacters_do_not_collide() {
            let plain = raw_env_digest(br#"{"k":"v"}"#).unwrap();
            for key in [
                ":", ",", "\"", "\\", "a:b", "a,b", "a\"b", "a\\b", "a\u{0}b",
            ] {
                // Build the JSON with proper escaping so the special character is
                // genuinely part of the key.
                let mut obj = serde_json::Map::new();
                obj.insert(key.to_string(), serde_json::Value::String("v".to_string()));
                let json = serde_json::Value::Object(obj).to_string();
                let digest = raw_env_digest(json.as_bytes()).unwrap();
                assert_ne!(plain, digest, "key {:?} must not collide", key);
            }
        }

        #[test]
        fn string_values_with_metacharacters_do_not_collide() {
            let plain = raw_env_digest(br#"{"k":"plain"}"#).unwrap();
            for val in [
                ":", ",", "\"", "\\", "a:b", "a,b", "a\"b", "a\\b", "a\u{0}b",
            ] {
                let json = serde_json::json!({ "k": val }).to_string();
                let digest = raw_env_digest(json.as_bytes()).unwrap();
                assert_ne!(plain, digest, "value {:?} must not collide", val);
            }
        }

        #[test]
        fn key_reorder_same_digest() {
            let a = raw_env_digest(br#"{"a":1,"b":2,"c":3}"#).unwrap();
            let b = raw_env_digest(br#"{"c":3,"a":1,"b":2}"#).unwrap();
            assert_eq!(a, b, "key reorder must be order-independent (same digest)");
        }

        #[test]
        fn value_change_different_digest() {
            let a = raw_env_digest(br#"{"a":1,"b":2}"#).unwrap();
            let b = raw_env_digest(br#"{"a":1,"b":3}"#).unwrap();
            assert_ne!(a, b);
        }

        #[test]
        fn duplicate_key_rejected() {
            assert!(
                raw_env_digest(br#"{"a":1,"a":2}"#).is_err(),
                "duplicate keys must be rejected"
            );
        }

        #[test]
        fn unknown_field_rejected_by_strict_manifest() {
            let err = canonical_environment_digest(
                br#"{"schema_version":"mida.environment-manifest/v1","arch":"x86_64","os":"win","budget":"c","extra":"x"}"#,
            )
            .unwrap_err();
            assert!(matches!(
                err,
                BehaviorOracleContractError::EnvironmentManifestRejected(_)
            ));
        }

        #[test]
        fn missing_required_field_rejected_by_strict_manifest() {
            let err = canonical_environment_digest(
                br#"{"schema_version":"mida.environment-manifest/v1","arch":"x86_64","os":"win"}"#,
            )
            .unwrap_err();
            assert!(matches!(
                err,
                BehaviorOracleContractError::EnvironmentManifestRejected(_)
            ));
        }

        #[test]
        fn wrong_schema_version_rejected() {
            let err = canonical_environment_digest(
                br#"{"schema_version":"mida.environment-manifest/v0","arch":"x86_64","os":"win","budget":"c"}"#,
            )
            .unwrap_err();
            assert!(matches!(
                err,
                BehaviorOracleContractError::EnvironmentManifestRejected(_)
            ));
        }

        #[test]
        fn malformed_json_rejected() {
            assert!(raw_env_digest(b"not json {").is_err());
        }

        #[test]
        fn empty_object_rejected() {
            assert!(raw_env_digest(b"{}").is_err());
            assert!(canonical_environment_digest(b"{}").is_err());
        }

        #[test]
        fn array_order_is_bound() {
            let a = raw_env_digest(br#"{"a":[1,2,3]}"#).unwrap();
            let b = raw_env_digest(br#"{"a":[3,2,1]}"#).unwrap();
            assert_ne!(a, b, "array order must change the digest");
        }

        #[test]
        fn valid_strict_manifest_hashes() {
            let d = canonical_environment_digest(
                br#"{"schema_version":"mida.environment-manifest/v1","arch":"x86_64","os":"win","budget":"controlled"}"#,
            )
            .unwrap();
            assert_eq!(d.len(), 64);
        }

        #[test]
        fn float_rejected() {
            assert!(raw_env_digest(br#"{"a":1.5}"#).is_err());
        }
    }
}
