//! # mida-acceptance
//!
//! Independent acceptance kernel for MagicMida vNext (R0B + B-A2 compose).
//!
//! Default path judges candidate PE files by **static structure only**.
//! Optional `check_with_behavior` composes **pre-recorded** behavioral
//! evidence (produced outside this crate). It must not depend on
//! `mida-core`, `mida-pe`, `mida-tracer`, `mida-packers-*`, or `mida-cli`.
//! It does not call Win32, launch processes, or run packer heuristics.
//!
//! See `docs/ACCEPTANCE_CONTRACT.md` and `docs/VNEXT_BEHAVIORAL_PATH.md`.

pub mod behavior;
pub mod behavior_oracle_contract;
pub mod bundle_gate;
pub mod check;
pub mod envelope;
pub mod evidence_bundle;
pub mod failure_taxonomy;
pub mod gates;
pub mod generic_bundle;
pub mod identity;
pub mod isolated_replay_ledger;
pub mod oracle;
pub mod pe;
pub mod preflight;
pub mod report;
pub mod snapshot_path;
pub mod survival_structural_evidence;
pub mod verdict;

#[cfg(test)]
#[allow(dead_code)]
mod test_support;

pub use behavior::{
    BehaviorEvidence, BehaviorEvidenceError, BehaviorVerdict, TransformLedgerEntry,
    TransformManifest, VerifiedManagedCandidate, BEHAVIOR_EVIDENCE_SCHEMA_VERSION,
    TRANSFORM_TAXONOMY_VERSION,
};
// compose_with_behavior is deliberately NOT re-exported; use check_* entry points.
pub use behavior_oracle_contract::{
    parse_contract_evidence, require_identical_stimulus_plan, verify_contract,
    verify_contract_bound, BehaviorChainIdentity, BehaviorComparator, BehaviorCompletionMarker,
    BehaviorContractVerdict, BehaviorExecution, BehaviorObservable, BehaviorObserved,
    BehaviorObservedStatus, BehaviorOracleContractError, BehaviorOracleContractEvidence,
    BehaviorStimulus, ComputedObservable, ContractVerdict, ExpectedBinding, ObservableVerdict,
    StimulusPlanRef, StimulusPlanRegistry, BEHAVIOR_ORACLE_CONTRACT_SCHEMA_VERSION,
    BLOCKER_CASE_BUSINESS_DEFINITION, CONTRACT_REQUIRED_CASES,
};
pub use check::{
    check_static, check_static_verdict, check_with_behavior, check_with_behavior_managed,
    check_with_behavior_managed_lab, check_with_behavior_signed, CheckStaticOptions,
};
pub use envelope::{
    sign_hmac_sha256_for_test, EnvelopeError, EnvelopePayload, EnvelopePolicy, EnvelopeSignature,
    HmacSha256Verifier, RejectAllVerifier, SignatureEnvelope, SignatureVerifier,
    VerifiedSignedBundle, ENVELOPE_SCHEMA_VERSION, SIG_ALG_ED25519_V1, SIG_ALG_HMAC_SHA256_V0,
};
pub use identity::{sha256_hex, ArtifactIdentity, ROLE_CANDIDATE, ROLE_LEGACY_ORACLE};
pub use isolated_replay_ledger::{
    verify_replay_ledger, IsolatedReplayLedger, ReplayAttemptRecord, ReplayAttemptState,
    ReplayChainIdentity, ReplayCompletionMarker, ReplayLedgerError, ReplayObservableVerdict,
    ReplayVerifierIdentity, ISOLATED_REPLAY_LEDGER_SCHEMA_VERSION, REPLAY_ATTEMPTS_EXACT,
};
pub use oracle::{observe_oracle, OracleObservation};
pub use report::{
    AcceptanceReport, FailureRecord, GateResult, GateStatus, ResidualRisk, WarningRecord,
    REPORT_SCHEMA_VERSION,
};
pub use survival_structural_evidence::{
    verify_structural_evidence, verify_survival_evidence, ExpectedEvidenceBinding,
    StructuralBundleValidation, StructuralDomainResult, StructuralDomainVerdict,
    StructuralEvidence, SurvivalChainIdentity, SurvivalCompletionMarker, SurvivalEvidence,
    SurvivalExitObservation, SurvivalProcessObservation, SurvivalStructuralEvidenceError,
    SurvivalVerdict, ARTIFACT_SHA256_SEMANTIC_PIN, STRUCTURAL_EVIDENCE_SCHEMA_VERSION,
    SURVIVAL_EVIDENCE_SCHEMA_VERSION,
};
pub use verdict::Verdict;
pub mod oreans_gate;
pub mod oreans_pe_evidence;

pub use bundle_gate::{
    evaluate_bundle_gate, evaluate_bundle_gate_with_manifest, BundleEnvelopeBinding,
    BundleGateError, BundleGateReport, BundleInput, BUNDLE_GATE_ID, BUNDLE_GATE_SCHEMA_VERSION,
};
pub use evidence_bundle::{
    canonical_manifest_hash, canonical_members_hash, validate_evidence_bundle,
    BundleArtifactIdentity, BundleCompletionMarker, BundleMemberRef, BundleVerdict,
    OreansEvidenceBundle, OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION, REQUIRED_BUNDLE_MEMBERS,
    TRANSFORM_MANIFEST_SCHEMA_VERSION,
};
pub use generic_bundle::{
    canonical_manifest_hash as generic_canonical_manifest_hash,
    canonical_members_hash as generic_canonical_members_hash, consume_unpack_bundle,
    validate_unpack_bundle, UnpackArtifactIdentity, UnpackBundleVerdict, UnpackCompletionMarker,
    UnpackEvidenceBundle, UnpackMemberRef, GENERIC_PACKER_FAMILY, OREANS_PACKER_FAMILY,
    REQUIRED_UNPACK_MEMBERS, UNPACK_EVIDENCE_BUNDLE_SCHEMA_VERSION,
};
pub use oreans_gate::{
    evaluate_oreans_two_sample_gate, locked_manifest, OreansArtifactIdentity,
    OreansAslrSimulationCase, OreansAslrSimulationEvidence, OreansBehaviorEvidence,
    OreansBehaviorObservable, OreansBehaviorStimulus, OreansEvidenceRef,
    OreansFinalBehaviorVerdict, OreansFinalImportEvidence, OreansFinalRelocationBlockEvidence,
    OreansFinalRelocationEvidence, OreansFinalRelocationTargetEvidence, OreansFinalTlsEvidence,
    OreansGateError, OreansGateVerdict, OreansIatArtifactIdentity, OreansIatEvidence,
    OreansIatReasonCounts, OreansIatReportEvidence, OreansIatSlotEvidence, OreansIsolatedReplay,
    OreansManifestBindingReport, OreansPrerequisites,
    OreansRelocationEvidence as OreansGateRelocationEvidence,
    OreansRelocationPreservationComparison, OreansReplayAttempt, OreansRuntimeRelocationEvidence,
    OreansRuntimeRelocationTargetEvidence, OreansRuntimeTlsCallbackEvidence,
    OreansRuntimeTlsEvidence, OreansSampleGateReport, OreansSampleManifestLock,
    OreansSampleObservation, OreansSectionRebuildArtifactIdentity, OreansSectionRebuildDirectory,
    OreansSectionRebuildEvidence, OreansSectionRebuildSection, OreansTlsArtifactIdentity,
    OreansTlsEvidence, OreansTlsPreservationComparison, OreansTwoSampleGateReport,
    OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION, OREANS_IAT_EVIDENCE_SCHEMA_VERSION,
    OREANS_ISOLATED_REPLAY_ATTEMPTS, OREANS_ISOLATED_REPLAY_SCHEMA_VERSION, OREANS_NON_GATE_CASES,
    OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION, OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION,
    OREANS_SAMPLE_MANIFESTS, OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
    OREANS_TLS_EVIDENCE_SCHEMA_VERSION, OREANS_TWO_SAMPLE_GATE_ID,
    OREANS_TWO_SAMPLE_GATE_SCHEMA_VERSION,
};
pub use oreans_pe_evidence::{
    build_oreans_pe_evidence, build_unpack_pe_evidence, OreansExceptionEvidence,
    OreansPeCandidateIdentity, OreansPeDirectoryCoverage, OreansPeEvidence, OreansPeEvidenceError,
    OreansPeSectionEvidence, OreansRelocationEvidence, OreansRuntimeFunctionEvidence,
    OreansTlsEvidence as OreansPeTlsEvidence, OREANS_PE_EVIDENCE_SCHEMA_VERSION,
    UNPACK_PE_EVIDENCE_SCHEMA_VERSION,
};
pub use preflight::{
    canonical_runner_config, check_case_identity, is_generic_packer_family, is_gto_lane_manifest,
    is_known_packer_family, run_offline_preflight, runner_config_digest, write_preflight_report,
    CaseIdentity, CaseManifestV2, CasePreflight, FileIdentity, FsOutputProbe, IdentityVerdict,
    IsolationConfig, OutputProbe, PreflightReport, PreflightRequest, PreflightStatus, RunnerConfig,
    WorktreeProbe, WorktreeState, FIXED_CASE_IDS, GTO_CASE_ID, GTO_PROTECTION_FAMILY,
    PREFLIGHT_REPORT_SCHEMA_VERSION,
};
