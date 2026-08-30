//! Fixed-scope Oreans two-sample perfect-unpack acceptance gate.
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
//! This module is evidence-only. It never opens or executes a sample. Callers
//! provide pre-recorded behavior-oracle evidence and isolated replay records;
//! the gate validates their contract and binds them to the two locked cases.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::oreans_pe_evidence::{
    OreansExceptionEvidence, OreansPeEvidence, OreansPeSectionEvidence,
    OreansTlsEvidence as OreansPeTlsEvidence, OREANS_PE_EVIDENCE_SCHEMA_VERSION,
};

pub const OREANS_TWO_SAMPLE_GATE_SCHEMA_VERSION: &str = "mida.oreans-two-sample-gate/v8";
pub const OREANS_TWO_SAMPLE_OBSERVATIONS_SCHEMA_VERSION: &str =
    "mida.oreans-two-sample-observations/v6";
pub const OREANS_IAT_EVIDENCE_SCHEMA_VERSION: &str = "mida.oreans-iat-evidence/v1";
pub const OREANS_TLS_EVIDENCE_SCHEMA_VERSION: &str = "mida.oreans-tls-evidence/v1";
pub const OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION: &str = "mida.oreans-relocation-evidence/v1";
pub const OREANS_OEP_EVIDENCE_SCHEMA_VERSION: &str = "mida.oreans-oep-evidence/v1";
pub const OREANS_TWO_SAMPLE_GATE_ID: &str = "oreans_two_sample_perfect_unpack";
pub const OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION: &str = "mida.oreans-behavior-oracle/v1";
pub const OREANS_ISOLATED_REPLAY_SCHEMA_VERSION: &str = "mida.oreans-isolated-replay/v1";
pub const OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION: &str =
    "mida.oreans-prerequisite-evidence/v1";
pub const OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION: &str =
    "mida.oreans-section-rebuild-evidence/v1";
pub const OREANS_ISOLATED_REPLAY_ATTEMPTS: usize = 10;

/// Locked gate-case binding: which `case_id`s are the fixed Oreans gate cases
/// and where each case's manifest lives (`lab/cases/v2/<case_id>.json`).
///
/// The protected-input identity is **not** embedded here — it is loaded from
/// the manifest (the contract data source) at gate time via
/// [`load_locked_manifest_identity`], so swapping a sample never requires a
/// code edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OreansSampleManifestLock {
    pub case_id: &'static str,
    pub manifest_path: &'static str,
}

pub const OREANS_SAMPLE_MANIFESTS: [OreansSampleManifestLock; 2] = [
    OreansSampleManifestLock {
        case_id: "origin_macro",
        manifest_path: "lab/cases/v2/origin_macro.json",
    },
    OreansSampleManifestLock {
        case_id: "lunlun_software",
        manifest_path: "lab/cases/v2/lunlun_software.json",
    },
];

/// Why a locked case's manifest could not supply the protected-input identity.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum OreansManifestError {
    #[error("cannot read locked case manifest {0}: {1}")]
    Read(String, String),
    #[error("locked case manifest {0} rejected (malformed/unknown fields): {1}")]
    Parse(String, String),
    #[error("locked case manifest {0} declares case_id {1:?}, expected {2:?}")]
    CaseIdMismatch(String, String, String),
    #[error("locked case manifest {0} has no protected_input artifact")]
    NoProtectedInput(String),
}

/// Resolve a locked manifest path: as given (relative to the current working
/// directory), falling back to the workspace-root-anchored location
/// (`CARGO_MANIFEST_DIR/../..`). The fallback keeps `cargo test` and
/// repo-checkout invocations working regardless of the CWD.
fn resolve_manifest_path(manifest_path: &str) -> std::path::PathBuf {
    let as_given = Path::new(manifest_path);
    if as_given.exists() {
        return as_given.to_path_buf();
    }
    let anchored = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(manifest_path);
    if anchored.exists() {
        anchored
    } else {
        as_given.to_path_buf()
    }
}

/// Load the protected-input identity declared by a locked case's manifest.
///
/// Fail-closed: a missing or malformed manifest, a `case_id` mismatch, or the
/// absence of a `protected_input` artifact is an explicit error — never a
/// silent default. The manifest is the contract data source; production code
/// carries no sample hash literal.
pub fn load_locked_manifest_identity(
    lock: &OreansSampleManifestLock,
) -> Result<OreansArtifactIdentity, OreansManifestError> {
    let path = resolve_manifest_path(lock.manifest_path);
    let bytes = std::fs::read(&path)
        .map_err(|e| OreansManifestError::Read(lock.manifest_path.to_string(), e.to_string()))?;
    let manifest: crate::preflight::CaseManifestV2 = serde_json::from_slice(&bytes)
        .map_err(|e| OreansManifestError::Parse(lock.manifest_path.to_string(), e.to_string()))?;
    if manifest.case_id != lock.case_id {
        return Err(OreansManifestError::CaseIdMismatch(
            lock.manifest_path.to_string(),
            manifest.case_id,
            lock.case_id.to_string(),
        ));
    }
    manifest
        .artifacts
        .into_iter()
        .find(|artifact| artifact.role == "protected_input")
        .map(|artifact| OreansArtifactIdentity {
            sha256: artifact.sha256.to_ascii_lowercase(),
            size_bytes: artifact.size_bytes,
        })
        .ok_or_else(|| OreansManifestError::NoProtectedInput(lock.manifest_path.to_string()))
}

/// Historical or adjacent workstreams are explicitly not gate inputs.
pub const OREANS_NON_GATE_CASES: [&str; 3] = ["gto_launcher", "xiongxiong_duokai", "shiguang"];

pub fn locked_manifest(case_id: &str) -> Option<&'static OreansSampleManifestLock> {
    OREANS_SAMPLE_MANIFESTS
        .iter()
        .find(|manifest| manifest.case_id == case_id)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansArtifactIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

impl OreansArtifactIdentity {
    fn is_well_formed(&self) -> bool {
        self.sha256.len() == 64
            && self.sha256.chars().all(|c| c.is_ascii_hexdigit())
            && self.sha256 == self.sha256.to_ascii_lowercase()
            && self.size_bytes > 0
    }
}

/// First-class evidence binding for one prerequisite. A caller-supplied bool
/// is never sufficient to satisfy a prerequisite without this reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansEvidenceRef {
    pub schema_version: String,
    pub producer: String,
    pub artifact_sha256: String,
    pub summary: String,
}

impl OreansEvidenceRef {
    pub fn validate_for_candidate(&self, candidate: &OreansArtifactIdentity) -> Result<(), String> {
        if self.schema_version != OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION {
            return Err(format!(
                "schema_version '{}' is not {}",
                self.schema_version, OREANS_PREREQUISITE_EVIDENCE_SCHEMA_VERSION
            ));
        }
        if self.producer.trim().is_empty() {
            return Err("producer is empty".to_string());
        }
        if !is_sha256(&self.artifact_sha256) {
            return Err("artifact_sha256 is not a lowercase 64-hex SHA-256".to_string());
        }
        if self.artifact_sha256 != candidate.sha256 {
            return Err("artifact_sha256 does not match candidate.sha256".to_string());
        }
        if self.summary.trim().is_empty() {
            return Err("summary is empty".to_string());
        }
        Ok(())
    }
}

/// Structured evidence that binds the OEP provenance sidecar to both input
/// artifacts and to the final serialized candidate PE. The sidecar is parsed
/// strictly; the gate recomputes every pass condition instead of trusting its
/// `prerequisite_passes` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansOepArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OreansOepSource {
    RuntimeRip,
    Trace,
    ScanFallback,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansOepEvidence {
    pub schema_version: String,
    pub protected_input: OreansOepArtifactIdentity,
    pub candidate: OreansOepArtifactIdentity,
    pub source: OreansOepSource,
    pub va: Option<u64>,
    pub rva: Option<u32>,
    pub final_entry_rva: u32,
    pub evidence: String,
    pub application_oep: bool,
    pub bootstrap_or_ambiguous: bool,
    pub entry_rva_matches_provenance: bool,
    pub prerequisite_passes: bool,
    pub blocker: Option<String>,
}

/// Facts that must already be established before final behavior can pass.
/// Section rebuild is deliberately absent: it is a required first-class
/// structured sidecar on `OreansSampleObservation`, never a caller bool or a
/// generic reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansPrerequisites {
    pub survival: bool,
    pub structural: bool,
    pub survival_evidence: OreansEvidenceRef,
    pub structural_evidence: OreansEvidenceRef,
}

impl OreansPrerequisites {
    pub fn all_pass(&self, candidate: &OreansArtifactIdentity) -> bool {
        self.survival && self.structural && self.evidence_failures(candidate).is_empty()
    }

    fn evidence_failures(&self, candidate: &OreansArtifactIdentity) -> Vec<String> {
        [
            ("survival", &self.survival_evidence),
            ("structural", &self.structural_evidence),
        ]
        .into_iter()
        .filter_map(|(name, evidence)| {
            evidence
                .validate_for_candidate(candidate)
                .err()
                .map(|error| format!("prerequisite failed: {name} evidence: {error}"))
        })
        .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansSectionRebuildArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansSectionRebuildSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub virtual_end: u64,
    pub raw_end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansSectionRebuildDirectory {
    pub index: u8,
    pub name: String,
    pub rva: u32,
    pub size: u32,
    pub present: bool,
    pub in_image: bool,
    pub raw_backed: bool,
    pub security_file_offset: bool,
}

/// Final-disk section/header evidence. The gate recomputes all pass conditions
/// from these facts and cross-checks them against the independent PE evidence;
/// `section_rebuild_evidence_pass` is diagnostic only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansSectionRebuildEvidence {
    pub schema_version: String,
    pub protected_input: OreansSectionRebuildArtifactIdentity,
    pub candidate: OreansSectionRebuildArtifactIdentity,
    pub machine: u16,
    pub pe32_plus: bool,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub section_table_offset: u64,
    pub section_table_size: u64,
    pub entry_rva: u32,
    pub entry_section: Option<String>,
    pub executable_sections: Vec<String>,
    pub sections: Vec<OreansSectionRebuildSection>,
    pub directories: Vec<OreansSectionRebuildDirectory>,
    pub overlay_offset: u64,
    pub overlay_size: u64,
    pub section_rebuild_evidence_pass: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansTlsArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansRuntimeTlsCallbackEvidence {
    pub slot_index: usize,
    pub slot_address: u64,
    pub bytes_read: usize,
    pub observed_value: Option<u64>,
    pub callback_rva: Option<u32>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansRuntimeTlsEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_bytes_read: usize,
    pub start_address_of_raw_data: u64,
    pub start_rva: Option<u32>,
    pub end_address_of_raw_data: u64,
    pub end_rva: Option<u32>,
    pub address_of_index: u64,
    pub index_rva: Option<u32>,
    pub address_of_callbacks: u64,
    pub callbacks_rva: Option<u32>,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub index_bytes_read: usize,
    pub index_value: Option<u32>,
    pub callback_slots: Vec<OreansRuntimeTlsCallbackEvidence>,
    pub null_terminated: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansFinalTlsEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub image_base: u64,
    pub size_of_image: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_raw_offset: Option<u64>,
    pub directory_raw_backed: bool,
    pub start_rva: Option<u32>,
    pub end_rva: Option<u32>,
    pub index_rva: Option<u32>,
    pub index_raw_backed: bool,
    pub callbacks_rva: Option<u32>,
    pub callback_rvas: Vec<u32>,
    pub null_terminated: bool,
    pub size_of_zero_fill: u32,
    pub characteristics: u32,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansTlsPreservationComparison {
    pub pe_kind_preserved: bool,
    pub pointer_size_preserved: bool,
    pub tls_presence_preserved: bool,
    pub directory_preserved: bool,
    pub raw_data_range_preserved: bool,
    pub index_rva_preserved: bool,
    pub callbacks_rva_preserved: bool,
    pub callbacks_preserved: bool,
    pub null_terminator_preserved: bool,
    pub zero_fill_preserved: bool,
    pub characteristics_preserved: bool,
    pub all_preserved: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansTlsEvidence {
    pub schema_version: String,
    pub protected_input: OreansTlsArtifactIdentity,
    pub candidate: OreansTlsArtifactIdentity,
    pub runtime: OreansRuntimeTlsEvidence,
    pub final_candidate: OreansFinalTlsEvidence,
    pub preservation: OreansTlsPreservationComparison,
    pub reported_tls_evidence_present: bool,
    pub reported_tls_evidence_complete: bool,
    pub runtime_evidence_present: bool,
    pub runtime_evidence_complete: bool,
    pub prerequisite_passes: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansRuntimeRelocationTargetEvidence {
    pub block_index: u32,
    pub entry_index: u32,
    pub page_rva: u32,
    pub target_rva: u32,
    pub relocation_type: u8,
    pub bytes_read: usize,
    pub runtime_value: Option<u64>,
    pub normalized_value: Option<u64>,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansRuntimeRelocationEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub runtime_image_base: u64,
    pub preferred_image_base: u64,
    pub size_of_image: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_bytes_read: usize,
    pub dynamic_base: bool,
    pub relocs_stripped: bool,
    pub block_count: u32,
    pub entry_count: u32,
    pub non_absolute_entry_count: u32,
    pub observed_types: Vec<u8>,
    pub targets: Vec<OreansRuntimeRelocationTargetEvidence>,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansFinalRelocationBlockEvidence {
    pub block_index: u32,
    pub page_rva: u32,
    pub block_size: u32,
    pub entry_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansFinalRelocationTargetEvidence {
    pub block_index: u32,
    pub entry_index: u32,
    pub target_rva: u32,
    pub relocation_type: u8,
    pub raw_offset: Option<u64>,
    pub raw_backed: bool,
    pub stored_value: Option<u64>,
    pub normalized_value: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansFinalRelocationEvidence {
    pub directory_present: bool,
    pub pe32_plus: bool,
    pub pointer_size: usize,
    pub image_base: u64,
    pub size_of_image: u32,
    pub directory_rva: u32,
    pub directory_size: u32,
    pub directory_raw_offset: Option<u64>,
    pub directory_raw_backed: bool,
    pub dynamic_base: bool,
    pub relocs_stripped: bool,
    pub block_count: u32,
    pub entry_count: u32,
    pub non_absolute_entry_count: u32,
    pub observed_types: Vec<u8>,
    pub blocks: Vec<OreansFinalRelocationBlockEvidence>,
    pub targets: Vec<OreansFinalRelocationTargetEvidence>,
    pub all_targets_raw_backed: bool,
    pub has_non_absolute_entry: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansRelocationPreservationComparison {
    pub pe_kind_preserved: bool,
    pub pointer_size_preserved: bool,
    pub relocation_presence_preserved: bool,
    pub directory_raw_backed: bool,
    pub target_set_preserved: bool,
    pub normalized_values_preserved: bool,
    pub dynamic_base_preserved: bool,
    pub relocs_stripped_preserved: bool,
    pub all_preserved: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansAslrSimulationCase {
    pub new_image_base: u64,
    pub delta: i64,
    pub target_count: u32,
    pub passed: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansAslrSimulationEvidence {
    pub pure_delta: bool,
    pub covers_positive_delta: bool,
    pub covers_negative_delta: bool,
    pub normalized_values_used: bool,
    pub cases: Vec<OreansAslrSimulationCase>,
    pub all_passed: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansRelocationEvidence {
    pub schema_version: String,
    pub protected_input: OreansTlsArtifactIdentity,
    pub candidate: OreansTlsArtifactIdentity,
    pub runtime: OreansRuntimeRelocationEvidence,
    pub final_candidate: OreansFinalRelocationEvidence,
    pub preservation: OreansRelocationPreservationComparison,
    pub simulation: OreansAslrSimulationEvidence,
    pub reported_relocation_evidence_present: bool,
    pub reported_relocation_evidence_complete: bool,
    pub runtime_evidence_present: bool,
    pub runtime_evidence_complete: bool,
    pub prerequisite_passes: bool,
    pub blockers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatArtifactIdentity {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatSlotEvidence {
    pub slot_index: usize,
    pub slot_address: u64,
    pub slot_rva: Option<u32>,
    pub observed_value: Option<u64>,
    pub rebuilt_value: Option<u64>,
    pub slot_value: Option<u64>,
    pub status: String,
    /// Deterministic root-cause reason for a non-resolved slot, when known.
    /// Absent on resolved/zero-terminator slots; `None` on a non-resolved slot
    /// means pending live confirmation.
    pub unresolved_reason: Option<String>,
    pub module_name: Option<String>,
    pub function_name: Option<String>,
    pub ordinal: Option<u16>,
    /// Provenance of a resolved slot's address (XX-10-A direction 2).
    /// `live` or `static_corroborated`; absent on older sidecars.
    #[serde(default)]
    pub resolution_source: Option<String>,
}

/// Stable per-reason counts over a recovery report's non-resolved slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatReasonCounts {
    /// Map from unresolved reason to count.  `unknown`, if present, is never
    /// folded away.
    pub by_reason: std::collections::BTreeMap<String, usize>,
    /// Non-resolved slots whose reason could not be established without a live
    /// run.  Never fabricated or counted as `unknown`.
    pub pending_live_confirmation: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatReportEvidence {
    pub requested_bytes: usize,
    pub bytes_read: usize,
    pub slot_size: usize,
    pub slots: Vec<OreansIatSlotEvidence>,
    pub unresolved_reason_counts: OreansIatReasonCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansFinalImportEvidence {
    pub slot_rva: u32,
    pub module_name: String,
    pub function_name: Option<String>,
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatEvidence {
    pub schema_version: String,
    pub protected_input: OreansIatArtifactIdentity,
    pub candidate: OreansIatArtifactIdentity,
    pub fix_imports_requested: bool,
    pub iat_evidence_present: bool,
    pub iat_evidence_complete: bool,
    pub iat_report: Option<OreansIatReportEvidence>,
    pub final_imports: Vec<OreansFinalImportEvidence>,
    /// Whether a graded (partial) acceptance of an incomplete IAT report was
    /// produced and accepted by the dump emitter (XX-9-A direction 2).
    /// Diagnostic-only; never affects the perfect-prerequisite gate verdict.
    #[serde(default)]
    pub iat_partial_accepted: bool,
    /// The full graded-acceptance decision, when one was produced.
    #[serde(default)]
    pub iat_partial_accept: Option<OreansIatPartialAcceptEvidence>,
    pub prerequisite_passes: bool,
    pub blocker: Option<String>,
}

/// One rejected slot from a graded (partial) IAT acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatRejectedSlotEvidence {
    pub slot_index: usize,
    pub slot_rva: Option<u32>,
    pub observed_value: Option<u64>,
    pub unresolved_reason: Option<String>,
}

/// One stale slot from a graded (partial) IAT acceptance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatStaleSlotEvidence {
    pub slot_index: usize,
    pub slot_rva: Option<u32>,
    pub observed_value: Option<u64>,
}

/// One static back-fill record (XX-10-A direction 2), carrying the full
/// three-evidence chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatStaticCorroborationEvidence {
    pub slot_index: usize,
    pub slot_rva: Option<u32>,
    pub unresolved_reason: Option<String>,
    pub original_module: String,
    pub original_function: String,
    pub resolved_address: u64,
    pub ownership_verified: bool,
    pub call_site_semantics: String,
}

/// The graded-acceptance decision carried on the IAT evidence sidecar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIatPartialAcceptEvidence {
    pub partial_accepted: bool,
    pub resolved_fraction_num: usize,
    pub resolved_fraction_den: usize,
    pub fraction_ok: bool,
    pub rejected_within_budget: bool,
    pub structural_failures: Vec<String>,
    pub rejected_slots: Vec<OreansIatRejectedSlotEvidence>,
    pub stale_slots: Vec<OreansIatStaleSlotEvidence>,
    pub accepted_resolved_slots: Vec<usize>,
    /// Static back-fills (XX-10-A direction 2); empty on older sidecars.
    #[serde(default)]
    pub static_corroborations: Vec<OreansIatStaticCorroborationEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OreansFinalBehaviorVerdict {
    Pass,
    Fail,
    Inconclusive,
    NotRun,
}

/// One stimulus fed to the candidate/reference behavior oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansBehaviorStimulus {
    pub id: String,
    pub value: String,
}

/// One observable returned by the behavior oracle. A final Pass requires every
/// observable to be Pass; an inconclusive observable can never be upgraded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansBehaviorObservable {
    pub id: String,
    pub value: String,
    pub verdict: OreansFinalBehaviorVerdict,
}

/// Final behavior-oracle contract. All six fields are required evidence:
/// stimuli, observables, candidate identity, protected identity, verdict, and
/// reason. This is deliberately separate from structural/survival evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansBehaviorEvidence {
    pub schema_version: String,
    pub stimuli: Vec<OreansBehaviorStimulus>,
    pub observables: Vec<OreansBehaviorObservable>,
    pub candidate_identity: OreansArtifactIdentity,
    pub protected_identity: OreansArtifactIdentity,
    pub verdict: OreansFinalBehaviorVerdict,
    pub reason: String,
}

impl OreansBehaviorEvidence {
    fn validate(
        &self,
        candidate: &OreansArtifactIdentity,
        protected_input: &OreansArtifactIdentity,
    ) -> Vec<String> {
        let mut failures = Vec::new();
        if self.schema_version != OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION {
            failures.push(format!(
                "behavior evidence schema_version '{}' is not {}",
                self.schema_version, OREANS_BEHAVIOR_ORACLE_SCHEMA_VERSION
            ));
        }
        if self.stimuli.is_empty() {
            failures.push("behavior evidence has no stimuli".to_string());
        }
        for stimulus in &self.stimuli {
            if stimulus.id.trim().is_empty() || stimulus.value.trim().is_empty() {
                failures.push("behavior evidence contains an empty stimulus id/value".to_string());
            }
        }
        if self.observables.is_empty() {
            failures.push("behavior evidence has no observables".to_string());
        }
        for observable in &self.observables {
            if observable.id.trim().is_empty() || observable.value.trim().is_empty() {
                failures
                    .push("behavior evidence contains an empty observable id/value".to_string());
            }
            if self.verdict == OreansFinalBehaviorVerdict::Pass
                && observable.verdict != OreansFinalBehaviorVerdict::Pass
            {
                failures.push(format!(
                    "observable '{}' is {:?}, so behavior cannot be pass",
                    observable.id, observable.verdict
                ));
            }
        }
        if !self.candidate_identity.is_well_formed() {
            failures.push("behavior candidate identity is malformed".to_string());
        } else if &self.candidate_identity != candidate {
            failures.push("behavior candidate identity does not match candidate".to_string());
        }
        if !self.protected_identity.is_well_formed() {
            failures.push("behavior protected identity is malformed".to_string());
        } else if &self.protected_identity != protected_input {
            failures.push("behavior protected identity does not match protected input".to_string());
        }
        if self.reason.trim().is_empty() {
            failures.push("behavior evidence reason is empty".to_string());
        }
        if self.verdict != OreansFinalBehaviorVerdict::Pass {
            failures.push(format!(
                "final behavior verdict is {:?}, not pass",
                self.verdict
            ));
        }
        failures
    }
}

/// One isolated replay attempt. Every attempt is retained; a successful retry
/// cannot be selected in place of a failed earlier attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansReplayAttempt {
    pub attempt_index: u32,
    pub candidate_sha256: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub observable_verdict: OreansFinalBehaviorVerdict,
    pub timestamp: String,
    pub runner_config_digest: String,
    #[serde(default)]
    pub retry_picked: bool,
}

/// Exactly ten ordered attempts are required. This record is the source of
/// truth for the isolated-replay prerequisite; callers cannot opt into a bool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansIsolatedReplay {
    pub schema_version: String,
    pub attempts: Vec<OreansReplayAttempt>,
}

impl OreansIsolatedReplay {
    fn validate(&self, candidate: &OreansArtifactIdentity) -> Vec<String> {
        let mut failures = Vec::new();
        if self.schema_version != OREANS_ISOLATED_REPLAY_SCHEMA_VERSION {
            failures.push(format!(
                "isolated replay schema_version '{}' is not {}",
                self.schema_version, OREANS_ISOLATED_REPLAY_SCHEMA_VERSION
            ));
        }
        if self.attempts.len() != OREANS_ISOLATED_REPLAY_ATTEMPTS {
            failures.push(format!(
                "isolated replay has {} attempts; exactly {} required",
                self.attempts.len(),
                OREANS_ISOLATED_REPLAY_ATTEMPTS
            ));
        }

        for (position, attempt) in self.attempts.iter().enumerate() {
            let expected_index = (position + 1) as u32;
            if attempt.attempt_index != expected_index {
                failures.push(format!(
                    "isolated replay attempt_index is {}, expected {} at record {}",
                    attempt.attempt_index, expected_index, position
                ));
            }
            if !is_sha256(&attempt.candidate_sha256) {
                failures.push(format!(
                    "isolated replay attempt {} has malformed candidate digest",
                    attempt.attempt_index
                ));
            } else if attempt.candidate_sha256 != candidate.sha256 {
                failures.push(format!(
                    "isolated replay attempt {} candidate digest does not match candidate",
                    attempt.attempt_index
                ));
            }
            if attempt.exit_code != Some(0) {
                failures.push(format!(
                    "isolated replay attempt {} did not exit cleanly",
                    attempt.attempt_index
                ));
            }
            if attempt.signal.is_some() {
                failures.push(format!(
                    "isolated replay attempt {} terminated by signal",
                    attempt.attempt_index
                ));
            }
            if attempt.observable_verdict != OreansFinalBehaviorVerdict::Pass {
                failures.push(format!(
                    "isolated replay attempt {} observable verdict is {:?}",
                    attempt.attempt_index, attempt.observable_verdict
                ));
            }
            if attempt.timestamp.trim().is_empty() {
                failures.push(format!(
                    "isolated replay attempt {} timestamp is empty",
                    attempt.attempt_index
                ));
            }
            if !is_sha256(&attempt.runner_config_digest) {
                failures.push(format!(
                    "isolated replay attempt {} runner config digest is malformed",
                    attempt.attempt_index
                ));
            }
            if attempt.retry_picked {
                failures.push(format!(
                    "isolated replay attempt {} is marked retry_picked; retries cannot replace an attempt",
                    attempt.attempt_index
                ));
            }
        }

        if let Some(first_attempt) = self.attempts.first() {
            for attempt in self.attempts.iter().skip(1) {
                if attempt.runner_config_digest != first_attempt.runner_config_digest {
                    failures.push(format!(
                        "isolated replay runner_config_digest mismatch: attempt {} differs from attempt {}",
                        attempt.attempt_index, first_attempt.attempt_index
                    ));
                }
            }
        }
        failures
    }
}

fn validate_pe_evidence(
    evidence: &OreansPeEvidence,
    candidate: &OreansArtifactIdentity,
) -> Vec<String> {
    let mut failures = Vec::new();

    if evidence.schema_version != OREANS_PE_EVIDENCE_SCHEMA_VERSION {
        failures.push(format!(
            "structured PE evidence schema_version '{}' is not {}",
            evidence.schema_version, OREANS_PE_EVIDENCE_SCHEMA_VERSION
        ));
    }
    if !evidence.valid {
        failures.push("structured PE evidence valid=false".to_string());
    }
    if evidence.candidate.sha256 != candidate.sha256 {
        failures.push(
            "structured PE evidence candidate SHA-256 does not match observation.candidate"
                .to_string(),
        );
    }
    if evidence.candidate.size_bytes != candidate.size_bytes {
        failures.push(
            "structured PE evidence candidate size does not match observation.candidate"
                .to_string(),
        );
    }

    if evidence.machine != 0x8664 {
        failures.push(format!(
            "structured PE evidence machine 0x{:04x} is not AMD64 (0x8664)",
            evidence.machine
        ));
    }
    if !evidence.pe32_plus {
        failures.push("structured PE evidence is not PE32+".to_string());
    }
    if evidence.image_base == 0 {
        failures.push("structured PE evidence image_base is zero".to_string());
    }
    if evidence.file_alignment == 0 || !evidence.file_alignment.is_power_of_two() {
        failures.push(
            "structured PE evidence file_alignment is not a non-zero power of two".to_string(),
        );
    }
    if evidence.section_alignment == 0 || !evidence.section_alignment.is_power_of_two() {
        failures.push(
            "structured PE evidence section_alignment is not a non-zero power of two".to_string(),
        );
    }
    if evidence.file_alignment > evidence.section_alignment {
        failures
            .push("structured PE evidence file_alignment exceeds section_alignment".to_string());
    }
    if evidence.size_of_image == 0 {
        failures.push("structured PE evidence size_of_image is zero".to_string());
    }
    if evidence.size_of_headers == 0 {
        failures.push("structured PE evidence size_of_headers is zero".to_string());
    }
    if evidence.file_alignment != 0
        && !evidence
            .size_of_headers
            .is_multiple_of(evidence.file_alignment)
    {
        failures.push("structured PE evidence size_of_headers is not file-aligned".to_string());
    }
    if evidence.size_of_headers as u64 > candidate.size_bytes {
        failures.push("structured PE evidence size_of_headers exceeds candidate".to_string());
    }
    if evidence.size_of_headers > evidence.size_of_image {
        failures.push("structured PE evidence size_of_headers exceeds size_of_image".to_string());
    }
    if evidence.section_alignment != 0
        && !evidence
            .size_of_image
            .is_multiple_of(evidence.section_alignment)
    {
        failures.push("structured PE evidence size_of_image is not section-aligned".to_string());
    }
    if evidence.entry_rva >= evidence.size_of_image {
        failures.push("structured PE evidence entry_rva is outside size_of_image".to_string());
    }
    if evidence.sections.is_empty() {
        failures.push("structured PE evidence has no sections".to_string());
    }

    let mut virtual_ranges = Vec::with_capacity(evidence.sections.len());
    let mut raw_ranges = Vec::with_capacity(evidence.sections.len());
    let mut entry_is_executable = false;
    for section in &evidence.sections {
        let extent = u64::from(section.virtual_size.max(section.raw_size));
        if extent == 0 {
            failures.push(format!(
                "structured PE evidence section '{}' has an empty virtual/raw extent",
                section.name
            ));
            continue;
        }
        let virtual_start = u64::from(section.virtual_address);
        let Some(virtual_end) = virtual_start.checked_add(extent) else {
            failures.push(format!(
                "structured PE evidence section '{}' virtual range overflows",
                section.name
            ));
            continue;
        };
        if evidence.section_alignment != 0
            && section.virtual_address % evidence.section_alignment != 0
        {
            failures.push(format!(
                "structured PE evidence section '{}' RVA is not section-aligned",
                section.name
            ));
        }
        if virtual_start < u64::from(evidence.size_of_headers) {
            failures.push(format!(
                "structured PE evidence section '{}' starts inside headers",
                section.name
            ));
        }
        if virtual_end > u64::from(evidence.size_of_image) {
            failures.push(format!(
                "structured PE evidence section '{}' exceeds size_of_image",
                section.name
            ));
        }
        if section.raw_size != 0 {
            let raw_start = u64::from(section.raw_offset);
            let Some(raw_end) = raw_start.checked_add(u64::from(section.raw_size)) else {
                failures.push(format!(
                    "structured PE evidence section '{}' raw range overflows",
                    section.name
                ));
                continue;
            };
            raw_ranges.push((raw_start, raw_end, section.name.as_str()));
            if evidence.file_alignment != 0 && section.raw_offset % evidence.file_alignment != 0 {
                failures.push(format!(
                    "structured PE evidence section '{}' raw offset is not file-aligned",
                    section.name
                ));
            }
            if raw_start < u64::from(evidence.size_of_headers) {
                failures.push(format!(
                    "structured PE evidence section '{}' raw range starts inside headers",
                    section.name
                ));
            }
            if raw_end > candidate.size_bytes {
                failures.push(format!(
                    "structured PE evidence section '{}' raw range exceeds candidate",
                    section.name
                ));
            }
        }
        if (section.characteristics & 0x2000_0000) != 0
            && u64::from(evidence.entry_rva) >= virtual_start
            && u64::from(evidence.entry_rva) < virtual_end
        {
            entry_is_executable = true;
        }
        virtual_ranges.push((virtual_start, virtual_end, section.name.as_str()));
    }
    virtual_ranges.sort_by_key(|range| range.0);
    for pair in virtual_ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            failures.push(format!(
                "structured PE evidence sections '{}' and '{}' have overlapping virtual ranges",
                pair[0].2, pair[1].2
            ));
        }
    }
    if !entry_is_executable {
        failures.push(
            "structured PE evidence entry_rva is not inside an executable section".to_string(),
        );
    }
    if !rva_range_raw_backed(&evidence.sections, evidence.entry_rva, 1) {
        failures.push(
            "structured PE evidence entry_rva is not raw-backed for at least one byte".to_string(),
        );
    }

    raw_ranges.sort_by_key(|range| range.0);
    for pair in raw_ranges.windows(2) {
        if pair[1].0 < pair[0].1 {
            failures.push(format!(
                "structured PE evidence sections '{}' and '{}' have overlapping raw ranges",
                pair[0].2, pair[1].2
            ));
        }
    }

    failures.extend(validate_directory_coverage(
        "TLS",
        &evidence.tls,
        true,
        evidence.size_of_image,
    ));
    match evidence.tls_detail.as_ref() {
        Some(detail) => failures.extend(validate_tls_detail(
            detail,
            &evidence.sections,
            evidence.size_of_image,
            evidence.tls.size,
        )),
        None => failures.push("structured PE evidence TLS detail is missing".to_string()),
    }

    failures.extend(validate_directory_coverage(
        "base relocation",
        &evidence.base_reloc,
        true,
        evidence.size_of_image,
    ));
    match evidence.relocation_detail.as_ref() {
        Some(detail) => {
            if detail.block_count == 0 {
                failures.push("structured PE evidence relocation block_count is zero".to_string());
            }
            if detail.entry_count == 0 {
                failures.push("structured PE evidence relocation entry_count is zero".to_string());
            }
            if detail.non_absolute_entry_count == 0 {
                failures.push(
                    "structured PE evidence relocation non_absolute_entry_count is zero"
                        .to_string(),
                );
            }
            let has_absolute = detail.observed_types.contains(&0);
            let has_dir64 = detail.observed_types.contains(&10);
            for relocation_type in &detail.observed_types {
                if *relocation_type != 0 && *relocation_type != 10 {
                    failures.push(format!(
                        "structured PE evidence relocation observed type {} is invalid for AMD64",
                        relocation_type
                    ));
                }
            }
            if detail.entry_count > 0 && detail.observed_types.is_empty() {
                failures.push(
                    "structured PE evidence relocation observed_types is empty despite entries"
                        .to_string(),
                );
            }
            match u32::try_from(detail.observed_types.len()) {
                Ok(observed_type_count) if observed_type_count > detail.entry_count => {
                    failures.push(
                        "structured PE evidence relocation observed_types exceeds entry_count"
                            .to_string(),
                    );
                }
                Err(_) => failures.push(
                    "structured PE evidence relocation observed_types count overflows".to_string(),
                ),
                _ => {}
            }
            if detail.non_absolute_entry_count > 0 && !has_dir64 {
                failures.push(
                    "structured PE evidence relocation non-absolute entries require observed type 10"
                        .to_string(),
                );
            }
            if detail.non_absolute_entry_count == 0 && has_dir64 {
                failures.push(
                    "structured PE evidence relocation observed type 10 contradicts zero non-absolute entries"
                        .to_string(),
                );
            }
            if detail.entry_count == 0 && (has_absolute || has_dir64) {
                failures.push(
                    "structured PE evidence relocation observed_types contradicts zero entries"
                        .to_string(),
                );
            }
            if !detail.all_targets_in_image {
                failures.push("structured PE evidence relocation target leaves image".to_string());
            }
            if detail.relocs_stripped {
                failures.push("structured PE evidence relocation relocs_stripped=true".to_string());
            }
            let dynamic_base = (evidence.dll_characteristics & 0x0040) != 0;
            if detail.dynamic_base != dynamic_base {
                failures.push(
                    "structured PE evidence relocation dynamic_base disagrees with DYNAMIC_BASE"
                        .to_string(),
                );
            }
            let relocs_stripped = (evidence.coff_characteristics & 0x0001) != 0;
            if detail.relocs_stripped != relocs_stripped {
                failures.push("structured PE evidence relocation relocs_stripped disagrees with COFF RELOCS_STRIPPED".to_string());
            }
        }
        None => failures.push("structured PE evidence relocation detail is missing".to_string()),
    }

    failures.extend(validate_directory_coverage(
        "exception",
        &evidence.exception,
        false,
        evidence.size_of_image,
    ));
    match (
        evidence.exception.present,
        evidence.exception_detail.as_ref(),
    ) {
        (true, Some(detail)) => failures.extend(validate_exception_detail(
            detail,
            &evidence.sections,
            evidence.size_of_image,
            evidence.exception.size,
        )),
        (true, None) => {
            failures.push("structured PE evidence exception detail is missing".to_string())
        }
        (false, Some(_)) => failures
            .push("structured PE evidence exception detail exists without coverage".to_string()),
        (false, None) => {}
    }

    failures
}

fn validate_directory_coverage(
    name: &str,
    coverage: &crate::oreans_pe_evidence::OreansPeDirectoryCoverage,
    required: bool,
    size_of_image: u32,
) -> Vec<String> {
    let mut failures = Vec::new();
    if !coverage.present {
        if required {
            failures.push(format!("structured PE evidence {name} coverage is absent"));
        }
        if coverage.rva != 0 || coverage.size != 0 || !coverage.in_image || !coverage.raw_backed {
            failures.push(format!(
                "structured PE evidence {name} absent coverage is not canonical"
            ));
        }
        return failures;
    }
    if coverage.rva == 0 {
        failures.push(format!(
            "structured PE evidence {name} coverage has zero RVA"
        ));
    }
    if coverage.size == 0 {
        failures.push(format!(
            "structured PE evidence {name} coverage has zero size"
        ));
    }
    let Some(end) = coverage.rva.checked_add(coverage.size) else {
        failures.push(format!(
            "structured PE evidence {name} coverage range overflows"
        ));
        return failures;
    };
    if end > size_of_image {
        failures.push(format!(
            "structured PE evidence {name} coverage exceeds size_of_image"
        ));
    }
    if !coverage.in_image {
        failures.push(format!(
            "structured PE evidence {name} coverage is not in image"
        ));
    }
    if !coverage.raw_backed {
        failures.push(format!(
            "structured PE evidence {name} coverage is not raw-backed"
        ));
    }
    failures
}

fn validate_tls_detail(
    detail: &OreansPeTlsEvidence,
    sections: &[OreansPeSectionEvidence],
    size_of_image: u32,
    directory_size: u32,
) -> Vec<String> {
    let mut failures = Vec::new();
    if detail.directory_size != directory_size {
        failures.push("structured PE evidence TLS detail size disagrees with coverage".to_string());
    }
    let Some(index_rva) = detail.address_of_index_rva else {
        failures.push("structured PE evidence TLS AddressOfIndex is missing".to_string());
        return failures;
    };
    if index_rva >= size_of_image {
        failures.push("structured PE evidence TLS AddressOfIndex is outside image".to_string());
    }
    if !rva_range_raw_backed(sections, index_rva, 4) {
        failures.push("structured PE evidence TLS AddressOfIndex is not raw-backed".to_string());
    }
    if !detail.null_terminated {
        failures.push("structured PE evidence TLS callbacks are not null-terminated".to_string());
    }
    if let Some(callback_array_rva) = detail.callback_array_rva {
        if callback_array_rva >= size_of_image {
            failures.push("structured PE evidence TLS callback array is outside image".to_string());
        }
        let slots = u32::try_from(detail.callback_rvas.len())
            .ok()
            .and_then(|count| count.checked_add(1));
        let array_size = slots.and_then(|slots| slots.checked_mul(8));
        match array_size {
            Some(array_size) if rva_range_raw_backed(sections, callback_array_rva, array_size) => {}
            Some(_) => failures.push(
                "structured PE evidence TLS callback array is not raw-backed through its NULL terminator"
                    .to_string(),
            ),
            None => failures.push(
                "structured PE evidence TLS callback array size overflows".to_string(),
            ),
        }
    } else if !detail.callback_rvas.is_empty() {
        failures.push("structured PE evidence TLS callbacks lack an array RVA".to_string());
    }
    for callback_rva in &detail.callback_rvas {
        if !rva_in_executable_section(sections, *callback_rva) {
            failures.push(format!(
                "structured PE evidence TLS callback RVA 0x{callback_rva:x} is not executable"
            ));
        }
        if !rva_range_raw_backed(sections, *callback_rva, 1) {
            failures.push(format!(
                "structured PE evidence TLS callback RVA 0x{callback_rva:x} is not raw-backed"
            ));
        }
    }
    failures
}

fn validate_exception_detail(
    detail: &OreansExceptionEvidence,
    sections: &[OreansPeSectionEvidence],
    size_of_image: u32,
    coverage_size: u32,
) -> Vec<String> {
    let mut failures = Vec::new();
    let expected_size = detail.runtime_function_count.checked_mul(12);
    if expected_size != Some(coverage_size) {
        failures.push(
            "structured PE evidence exception coverage size does not equal runtime_function_count * 12"
                .to_string(),
        );
    }
    if detail.runtime_function_count == 0 {
        failures
            .push("structured PE evidence exception runtime_function_count is zero".to_string());
    }
    if detail.runtime_function_count as usize != detail.runtime_functions.len() {
        failures.push(
            "structured PE evidence exception count does not match runtime_functions length"
                .to_string(),
        );
    }
    if !detail.ranges_raw_backed {
        failures.push("structured PE evidence exception ranges are not raw-backed".to_string());
    }
    if !detail.unwind_rvas_raw_backed {
        failures
            .push("structured PE evidence exception unwind RVAs are not raw-backed".to_string());
    }
    for (index, function) in detail.runtime_functions.iter().enumerate() {
        if function.begin_rva >= function.end_rva {
            failures.push(format!(
                "structured PE evidence exception runtime function {index} has begin >= end"
            ));
            continue;
        }
        if function.end_rva > size_of_image {
            failures.push(format!(
                "structured PE evidence exception runtime function {index} exceeds size_of_image"
            ));
        }
        if !rva_in_executable_section(sections, function.begin_rva)
            || !rva_in_executable_section(sections, function.end_rva - 1)
        {
            failures.push(format!(
                "structured PE evidence exception runtime function {index} is not executable at both bounds"
            ));
        }
        let code_size = function.end_rva.checked_sub(function.begin_rva);
        if code_size.is_none_or(|size| !rva_range_raw_backed(sections, function.begin_rva, size)) {
            failures.push(format!(
                "structured PE evidence exception runtime function {index} is not fully raw-backed"
            ));
        }
        if function.unwind_rva == 0 {
            failures.push(format!(
                "structured PE evidence exception runtime function {index} has zero unwind RVA"
            ));
        } else if !rva_range_raw_backed(sections, function.unwind_rva, 4) {
            failures.push(format!(
                "structured PE evidence exception runtime function {index} unwind RVA is not raw-backed"
            ));
        }
    }
    failures
}

fn rva_range_raw_backed(sections: &[OreansPeSectionEvidence], rva: u32, size: u32) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = rva.checked_add(size) else {
        return false;
    };
    sections.iter().any(|section| {
        if section.raw_size == 0 {
            return false;
        }
        let start = section.virtual_address;
        let Some(raw_end) = start.checked_add(section.raw_size) else {
            return false;
        };
        rva >= start && end <= raw_end
    })
}

fn rva_in_executable_section(sections: &[OreansPeSectionEvidence], rva: u32) -> bool {
    sections.iter().any(|section| {
        let extent = u64::from(section.virtual_size.max(section.raw_size));
        let start = u64::from(section.virtual_address);
        let end = start.checked_add(extent);
        (section.characteristics & 0x2000_0000) != 0
            && end.is_some_and(|end| u64::from(rva) >= start && u64::from(rva) < end)
    })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value.chars().all(|c| c.is_ascii_hexdigit())
        && value == value.to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansSampleObservation {
    pub case_id: String,
    pub protected_input: OreansArtifactIdentity,
    pub candidate: OreansArtifactIdentity,
    pub pe_evidence: OreansPeEvidence,
    pub oep_evidence: OreansOepEvidence,
    pub iat_evidence: OreansIatEvidence,
    pub tls_evidence: OreansTlsEvidence,
    pub relocation_evidence: OreansRelocationEvidence,
    pub section_rebuild_evidence: OreansSectionRebuildEvidence,
    pub prerequisites: OreansPrerequisites,
    pub behavior_evidence: OreansBehaviorEvidence,
    pub isolated_replay: OreansIsolatedReplay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OreansManifestBindingReport {
    pub manifest_path: String,
    pub case_id: String,
    pub expected_protected_input: OreansArtifactIdentity,
    pub observed_protected_input: OreansArtifactIdentity,
    pub matched: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OreansSampleGateReport {
    pub case_id: String,
    pub manifest: OreansManifestBindingReport,
    pub candidate: OreansArtifactIdentity,
    pub protected_input: OreansArtifactIdentity,
    pub pe_evidence: OreansPeEvidence,
    pub oep_evidence: OreansOepEvidence,
    pub oep_evidence_pass: bool,
    pub iat_evidence: OreansIatEvidence,
    pub iat_evidence_pass: bool,
    pub tls_evidence: OreansTlsEvidence,
    pub tls_evidence_pass: bool,
    pub relocation_evidence: OreansRelocationEvidence,
    pub relocation_evidence_pass: bool,
    pub section_rebuild_evidence: OreansSectionRebuildEvidence,
    pub section_rebuild_evidence_pass: bool,
    pub behavior_evidence: OreansBehaviorEvidence,
    pub isolated_replay: OreansIsolatedReplay,
    pub prerequisites: OreansPrerequisites,
    pub prerequisites_pass: bool,
    pub isolated_replay_pass: bool,
    pub final_behavior_verdict: OreansFinalBehaviorVerdict,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OreansTwoSampleGateReport {
    pub schema_version: String,
    pub gate_id: String,
    pub required_cases: Vec<String>,
    pub excluded_cases: Vec<String>,
    pub samples: Vec<OreansSampleGateReport>,
    /// `open` until both fixed samples pass every prerequisite and final behavior.
    pub final_verdict: OreansGateVerdict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OreansGateVerdict {
    Open,
    Closed,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OreansGateError {
    #[error(
        "unknown or non-gate Oreans case '{0}'; only origin_macro and lunlun_software are allowed"
    )]
    CaseNotAllowed(String),
    #[error("duplicate Oreans case '{0}'")]
    DuplicateCase(String),
    #[error("missing required Oreans case '{0}'")]
    MissingCase(String),
}

/// Evaluate exactly the two fixed Oreans cases from pre-recorded observations.
///
/// A GTO launcher, holdout, Shiguang artifact, or any other sample cannot
/// satisfy a missing required case or be silently ignored.
pub fn evaluate_oreans_two_sample_gate(
    observations: &[OreansSampleObservation],
) -> Result<OreansTwoSampleGateReport, OreansGateError> {
    let mut seen = Vec::with_capacity(observations.len());
    for observation in observations {
        if locked_manifest(&observation.case_id).is_none() {
            return Err(OreansGateError::CaseNotAllowed(observation.case_id.clone()));
        }
        if seen.iter().any(|case_id| case_id == &observation.case_id) {
            return Err(OreansGateError::DuplicateCase(observation.case_id.clone()));
        }
        seen.push(observation.case_id.clone());
    }
    for manifest in OREANS_SAMPLE_MANIFESTS {
        if !seen.iter().any(|case_id| case_id == manifest.case_id) {
            return Err(OreansGateError::MissingCase(manifest.case_id.to_string()));
        }
    }

    let mut samples = observations.iter().map(evaluate_sample).collect::<Vec<_>>();
    samples.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    let final_verdict = if samples.iter().all(|sample| sample.passed) {
        OreansGateVerdict::Closed
    } else {
        OreansGateVerdict::Open
    };

    Ok(OreansTwoSampleGateReport {
        schema_version: OREANS_TWO_SAMPLE_GATE_SCHEMA_VERSION.to_string(),
        gate_id: OREANS_TWO_SAMPLE_GATE_ID.to_string(),
        required_cases: OREANS_SAMPLE_MANIFESTS
            .iter()
            .map(|manifest| manifest.case_id.to_string())
            .collect(),
        excluded_cases: OREANS_NON_GATE_CASES
            .iter()
            .map(|case_id| (*case_id).to_string())
            .collect(),
        samples,
        final_verdict,
    })
}

fn validate_oep_evidence(
    evidence: &OreansOepEvidence,
    protected_input: &OreansArtifactIdentity,
    candidate: &OreansArtifactIdentity,
    pe_evidence: &OreansPeEvidence,
) -> Vec<String> {
    let mut failures = Vec::new();
    if evidence.schema_version != OREANS_OEP_EVIDENCE_SCHEMA_VERSION {
        failures.push(format!(
            "schema_version '{}' is not {}",
            evidence.schema_version, OREANS_OEP_EVIDENCE_SCHEMA_VERSION
        ));
    }
    if evidence.protected_input.path.trim().is_empty() {
        failures.push("protected_input.path is empty".to_string());
    }
    if evidence.candidate.path.trim().is_empty() {
        failures.push("candidate.path is empty".to_string());
    }
    if !is_sha256(&evidence.protected_input.sha256)
        || evidence.protected_input.sha256 != protected_input.sha256
        || evidence.protected_input.size_bytes != protected_input.size_bytes
    {
        failures.push("protected_input SHA-256/size does not match observation".to_string());
    }
    if !is_sha256(&evidence.candidate.sha256)
        || evidence.candidate.sha256 != candidate.sha256
        || evidence.candidate.size_bytes != candidate.size_bytes
    {
        failures.push("candidate SHA-256/size does not match observation".to_string());
    }
    if !matches!(
        evidence.source,
        OreansOepSource::RuntimeRip | OreansOepSource::Trace
    ) {
        failures.push(format!(
            "source {:?} is not runtime_rip or trace",
            evidence.source
        ));
    }
    if evidence.va.is_none() {
        failures.push("VA is missing".to_string());
    }
    if evidence.rva.is_none() {
        failures.push("RVA is missing".to_string());
    }
    if evidence.evidence.trim().is_empty() {
        failures.push("evidence is empty".to_string());
    }
    if !evidence.application_oep {
        failures.push("application_oep must be true".to_string());
    }
    if evidence.bootstrap_or_ambiguous {
        failures.push("bootstrap_or_ambiguous must be false".to_string());
    }
    if !evidence.entry_rva_matches_provenance {
        failures.push("entry_rva_matches_provenance must be true".to_string());
    }
    if evidence.rva != Some(evidence.final_entry_rva) {
        failures.push("RVA does not match final_entry_rva".to_string());
    }
    if evidence.final_entry_rva != pe_evidence.entry_rva {
        failures.push(format!(
            "final_entry_rva {:#x} does not match structured PE AddressOfEntryPoint {:#x}",
            evidence.final_entry_rva, pe_evidence.entry_rva
        ));
    }
    if !evidence.prerequisite_passes {
        failures.push("prerequisite_passes must be true".to_string());
    }
    if evidence.blocker.is_some() {
        failures.push("blocker must be null".to_string());
    }
    failures
}

fn validate_iat_identity(
    label: &str,
    identity: &OreansIatArtifactIdentity,
    expected: &OreansArtifactIdentity,
) -> Vec<String> {
    let mut failures = Vec::new();
    if identity.path.trim().is_empty() {
        failures.push(format!("{label}.path is empty"));
    }
    if !is_sha256(&identity.sha256)
        || identity.sha256 != expected.sha256
        || identity.size_bytes != expected.size_bytes
    {
        failures.push(format!("{label} SHA-256/size does not match observation"));
    }
    failures
}

fn validate_iat_report(report: &OreansIatReportEvidence, pe32_plus: bool) -> Vec<String> {
    let mut failures = Vec::new();
    let expected_slot_size = if pe32_plus { 8 } else { 4 };
    if report.slot_size != expected_slot_size {
        failures.push(format!(
            "slot_size {} does not match PE pointer size {}",
            report.slot_size, expected_slot_size
        ));
    }
    if report.requested_bytes == 0 {
        failures.push("requested_bytes must be nonzero".to_string());
    }
    if report.slot_size == 0 || !report.requested_bytes.is_multiple_of(report.slot_size) {
        failures.push("requested_bytes is not slot-aligned".to_string());
    }
    if report.bytes_read != report.requested_bytes {
        failures.push(format!(
            "short-read {}/{} bytes",
            report.bytes_read, report.requested_bytes
        ));
    }
    let expected_slots = if report.slot_size != 0 {
        report.requested_bytes / report.slot_size
    } else {
        0
    };
    if report.slots.len() != expected_slots {
        failures.push(format!(
            "incomplete slot coverage {}/{} slots",
            report.slots.len(),
            expected_slots
        ));
    }

    let mut slots = report.slots.iter().collect::<Vec<_>>();
    slots.sort_by_key(|slot| slot.slot_index);
    let mut indices = HashSet::new();
    let mut addresses = HashSet::new();
    let mut rvas = HashSet::new();
    let mut resolved = 0usize;
    for (position, slot) in slots.iter().enumerate() {
        if !indices.insert(slot.slot_index) {
            failures.push("duplicate slot_index".to_string());
        }
        if !addresses.insert(slot.slot_address) {
            failures.push("duplicate slot_address".to_string());
        }
        let Some(slot_rva) = slot.slot_rva else {
            failures.push(format!("slot {position} missing slot_rva"));
            continue;
        };
        if !rvas.insert(slot_rva) {
            failures.push("duplicate slot_rva".to_string());
        }
        if slot.slot_index != position {
            failures.push("slot_index coverage is not continuous".to_string());
        }
        if let Some(first) = slots.first() {
            let expected_address = first
                .slot_address
                .checked_add(position.saturating_mul(report.slot_size) as u64);
            let expected_rva = first
                .slot_rva
                .and_then(|rva| rva.checked_add(position.saturating_mul(report.slot_size) as u32));
            if expected_address != Some(slot.slot_address) || expected_rva != Some(slot_rva) {
                failures.push("slot address/RVA coverage is not continuous".to_string());
            }
        }
        if slot.slot_value != slot.observed_value {
            failures.push(format!(
                "slot {position} slot_value differs from observed_value"
            ));
        }

        match slot.status.as_str() {
            "Resolved" => {
                resolved += 1;
                let has_name = slot
                    .function_name
                    .as_ref()
                    .is_some_and(|name| !name.is_empty());
                let has_ordinal = slot.ordinal.is_some();
                if slot.observed_value.is_none_or(|value| value == 0)
                    || slot.rebuilt_value.is_none_or(|value| value == 0)
                    || slot.module_name.as_ref().is_none_or(|name| name.is_empty())
                    || has_name == has_ordinal
                {
                    failures.push(format!(
                        "Resolved slot {position} has invalid identity metadata"
                    ));
                }
            }
            "ZeroTerminator" => {
                if slot.observed_value != Some(0)
                    || slot.slot_value != Some(0)
                    || slot.rebuilt_value.is_some()
                    || slot.module_name.is_some()
                    || slot.function_name.is_some()
                    || slot.ordinal.is_some()
                {
                    failures.push(format!(
                        "ZeroTerminator slot {position} has invalid metadata"
                    ));
                }
            }
            "Stale" | "Unresolved" | "ShortRead" | "InvalidModule" => {
                failures.push(format!("{} status at slot {position}", slot.status));
                if slot.rebuilt_value.is_some() {
                    failures.push(format!("{} slot {position} has rebuilt_value", slot.status));
                }
                // A deterministic unresolved reason is required on every
                // non-resolved slot.  A missing reason is pending live
                // confirmation; `unknown` must never be silently accepted.
                match slot.unresolved_reason.as_deref() {
                    None => failures.push(format!(
                        "{} slot {position} missing unresolved_reason (pending live confirmation)",
                        slot.status
                    )),
                    Some(reason) => {
                        if reason == "unknown" {
                            failures.push(format!(
                                "{} slot {position} has unresolved reason 'unknown' (fail-closed)",
                                slot.status
                            ));
                        }
                    }
                }
            }
            other => failures.push(format!("unknown IAT slot status '{other}'")),
        }
    }
    if resolved == 0 {
        failures.push("no resolved thunk slots".to_string());
    }
    failures
}

/// Recompute the per-reason counts over the report's non-resolved slots and
/// compare them to the sidecar's `unresolved_reason_counts`.  A mismatch, a
/// folded `unknown`, or a fabricated pending count fails closed.
fn validate_reason_counts(report: &OreansIatReportEvidence) -> Vec<String> {
    let mut failures = Vec::new();
    let mut recomputed: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut pending = 0usize;
    for slot in &report.slots {
        if matches!(slot.status.as_str(), "Resolved" | "ZeroTerminator") {
            continue;
        }
        match slot.unresolved_reason.as_deref() {
            Some(reason) => *recomputed.entry(reason.to_string()).or_insert(0) += 1,
            None => pending += 1,
        }
    }
    if recomputed != report.unresolved_reason_counts.by_reason {
        failures.push(format!(
            "unresolved_reason_counts mismatch: sidecar={:?} recomputed={:?}",
            report.unresolved_reason_counts.by_reason, recomputed
        ));
    }
    if pending != report.unresolved_reason_counts.pending_live_confirmation {
        failures.push(format!(
            "pending_live_confirmation count mismatch: sidecar={} recomputed={pending}",
            report.unresolved_reason_counts.pending_live_confirmation
        ));
    }
    // `unknown` and pending must never be silently accepted as a pass signal.
    if let Some(unknown) = recomputed.get("unknown") {
        failures.push(format!(
            "{unknown} slots have unresolved reason 'unknown' (fail-closed)"
        ));
    }
    if pending != 0 {
        failures.push(format!(
            "{pending} non-resolved slots are pending live confirmation (fail-closed)"
        ));
    }
    failures
}

fn validate_final_imports(
    final_imports: &[OreansFinalImportEvidence],
    report: Option<&OreansIatReportEvidence>,
) -> Vec<String> {
    let mut failures = Vec::new();
    if final_imports.is_empty() {
        failures.push("final imports are empty".to_string());
    }
    let mut import_rvas = HashSet::new();
    for import in final_imports {
        if !import_rvas.insert(import.slot_rva) {
            failures.push("duplicate final import slot_rva".to_string());
        }
        if import.module_name.is_empty()
            || !import.module_name.is_ascii()
            || import.module_name != import.module_name.to_ascii_lowercase()
        {
            failures.push(format!(
                "final import module '{}' is not lowercase ASCII",
                import.module_name
            ));
        }
        let has_name = import
            .function_name
            .as_ref()
            .is_some_and(|name| !name.is_empty());
        let has_ordinal = import.ordinal.is_some();
        if has_name == has_ordinal {
            failures.push(format!(
                "final import at RVA 0x{:x} must have exactly one function_name or ordinal",
                import.slot_rva
            ));
        }
    }

    let Some(report) = report else {
        failures.push("final imports cannot be matched without IAT report".to_string());
        return failures;
    };
    let resolved = report
        .slots
        .iter()
        .filter(|slot| slot.status == "Resolved")
        .collect::<Vec<_>>();
    if resolved.len() != final_imports.len() {
        failures.push(format!(
            "resolved/final import count mismatch {}/{}",
            resolved.len(),
            final_imports.len()
        ));
    }
    for slot in resolved {
        let Some(slot_rva) = slot.slot_rva else {
            continue;
        };
        let matches = final_imports
            .iter()
            .filter(|import| import.slot_rva == slot_rva)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            failures.push(format!(
                "resolved slot RVA 0x{slot_rva:x} does not map to exactly one final import"
            ));
            continue;
        }
        let import = matches[0];
        if slot
            .module_name
            .as_ref()
            .is_none_or(|module| !module.eq_ignore_ascii_case(&import.module_name))
        {
            failures.push(format!(
                "module mismatch for resolved slot RVA 0x{slot_rva:x}"
            ));
        }
        if slot.function_name != import.function_name {
            failures.push(format!(
                "function mismatch for resolved slot RVA 0x{slot_rva:x}"
            ));
        }
        if slot.ordinal != import.ordinal {
            failures.push(format!(
                "ordinal mismatch for resolved slot RVA 0x{slot_rva:x}"
            ));
        }
    }
    for import in final_imports {
        let matched = report
            .slots
            .iter()
            .any(|slot| slot.status == "Resolved" && slot.slot_rva == Some(import.slot_rva));
        if !matched {
            failures.push(format!(
                "final import RVA 0x{:x} has no resolved IAT slot",
                import.slot_rva
            ));
        }
    }
    failures
}

fn validate_iat_evidence(
    evidence: &OreansIatEvidence,
    protected_input: &OreansArtifactIdentity,
    candidate: &OreansArtifactIdentity,
    pe_evidence: &OreansPeEvidence,
) -> Vec<String> {
    let mut failures = Vec::new();
    if evidence.schema_version != OREANS_IAT_EVIDENCE_SCHEMA_VERSION {
        failures.push(format!(
            "schema_version '{}' is not {}",
            evidence.schema_version, OREANS_IAT_EVIDENCE_SCHEMA_VERSION
        ));
    }
    failures.extend(validate_iat_identity(
        "protected_input",
        &evidence.protected_input,
        protected_input,
    ));
    failures.extend(validate_iat_identity(
        "candidate",
        &evidence.candidate,
        candidate,
    ));
    if !evidence.fix_imports_requested {
        failures.push("fix_imports_requested must be true".to_string());
    }
    let report_present = evidence.iat_report.is_some();
    if evidence.iat_evidence_present != report_present {
        failures.push("iat_evidence_present disagrees with iat_report presence".to_string());
    }
    let report_failures = evidence
        .iat_report
        .as_ref()
        .map(|report| validate_iat_report(report, pe_evidence.pe32_plus))
        .unwrap_or_else(|| vec!["iat_report missing".to_string()]);
    let structured_complete = report_failures.is_empty();
    if evidence.iat_evidence_complete != structured_complete {
        failures.push(format!(
            "iat_evidence_complete disagrees with structured report ({}/{})",
            evidence.iat_evidence_complete, structured_complete
        ));
    }
    failures.extend(
        report_failures
            .iter()
            .map(|failure| format!("structured IAT report: {failure}")),
    );
    if let Some(report) = evidence.iat_report.as_ref() {
        failures.extend(
            validate_reason_counts(report)
                .iter()
                .map(|failure| format!("structured IAT report: {failure}")),
        );
    }
    failures.extend(validate_final_imports(
        &evidence.final_imports,
        evidence.iat_report.as_ref(),
    ));

    let computed_pass = failures.is_empty();
    if evidence.prerequisite_passes != computed_pass {
        failures.push(format!(
            "prerequisite_passes diagnostic disagrees with recomputed result ({}/{})",
            evidence.prerequisite_passes, computed_pass
        ));
    }
    match (&evidence.blocker, computed_pass) {
        (None, true) => {}
        (Some(blocker), false) if !blocker.trim().is_empty() => {}
        (None, false) => failures.push("failed IAT evidence must include a blocker".to_string()),
        (Some(_), true) => {
            failures.push("passing IAT evidence must not include a blocker".to_string())
        }
        (Some(_), false) => failures.push("IAT evidence blocker is empty".to_string()),
    }
    failures
}

fn validate_tls_identity(
    label: &str,
    identity: &OreansTlsArtifactIdentity,
    expected: &OreansArtifactIdentity,
) -> Vec<String> {
    let mut failures = Vec::new();
    if !is_sha256(&identity.sha256)
        || identity.sha256 != expected.sha256
        || identity.size_bytes != expected.size_bytes
    {
        failures.push(format!("{label} SHA-256/size does not match observation"));
    }
    // Independent disk re-read: the acceptance consumer never trusts the
    // producer-written hash/size strings alone. When the artifact path is
    // present and the file exists, the bytes on disk MUST match the declared
    // identity. When the path is absent or the file is missing (sealed-bundle
    // consumption where the disk is not available), the envelope binding
    // chain already guarantees identity consistency, so this is not a failure.
    failures.extend(verify_tls_identity_from_disk(label, identity));
    failures
}

/// Re-read an artifact from disk and cross-check the declared identity.
///
/// Returns failures when the file exists but its SHA-256/size disagree with
/// the sidecar's declared identity (stale, tampered, or mis-bound artifact).
/// A missing file is NOT a failure: bundle consumers may not have the disk
/// artifact; the envelope binding chain covers that path.
fn verify_tls_identity_from_disk(label: &str, identity: &OreansTlsArtifactIdentity) -> Vec<String> {
    if identity.path.is_empty() {
        return Vec::new();
    }
    let Ok(bytes) = std::fs::read(&identity.path) else {
        // Artifact absent on disk: sealed-bundle consumption. Not a failure.
        return Vec::new();
    };
    let mut failures = Vec::new();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual_sha = format!("{:064x}", hasher.finalize());
    if actual_sha != identity.sha256 {
        failures.push(format!(
            "{label} disk SHA-256 {actual_sha} disagrees with sidecar {}",
            identity.sha256
        ));
    }
    let actual_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_size != identity.size_bytes {
        failures.push(format!(
            "{label} disk size {actual_size} disagrees with sidecar {}",
            identity.size_bytes
        ));
    }
    failures
}

fn stable_blocker_list(blockers: &[String]) -> bool {
    blockers.iter().all(|blocker| !blocker.trim().is_empty())
        && blockers.windows(2).all(|pair| pair[0] < pair[1])
}

fn recompute_tls_preservation(
    runtime: &OreansRuntimeTlsEvidence,
    final_candidate: &OreansFinalTlsEvidence,
) -> OreansTlsPreservationComparison {
    let runtime_callbacks = runtime
        .callback_slots
        .iter()
        .filter_map(|slot| slot.callback_rva)
        .collect::<Vec<_>>();
    let both_absent = !runtime.directory_present && !final_candidate.directory_present;
    let fields = [
        ("pe kind", runtime.pe32_plus == final_candidate.pe32_plus),
        (
            "pointer size",
            runtime.pointer_size == final_candidate.pointer_size,
        ),
        (
            "TLS directory presence",
            runtime.directory_present == final_candidate.directory_present,
        ),
        (
            "TLS directory",
            both_absent
                || (runtime.directory_rva == final_candidate.directory_rva
                    && runtime.directory_size == final_candidate.directory_size
                    && final_candidate.directory_raw_backed),
        ),
        (
            "TLS raw-data range",
            both_absent
                || (runtime.start_rva == final_candidate.start_rva
                    && runtime.end_rva == final_candidate.end_rva),
        ),
        (
            "TLS index RVA",
            both_absent
                || (runtime.index_rva == final_candidate.index_rva
                    && final_candidate.index_raw_backed),
        ),
        (
            "TLS callbacks RVA",
            both_absent || runtime.callbacks_rva == final_candidate.callbacks_rva,
        ),
        (
            "TLS callback list",
            both_absent || runtime_callbacks == final_candidate.callback_rvas,
        ),
        (
            "TLS NULL terminator",
            both_absent || runtime.null_terminated == final_candidate.null_terminated,
        ),
        (
            "TLS SizeOfZeroFill",
            both_absent || runtime.size_of_zero_fill == final_candidate.size_of_zero_fill,
        ),
        (
            "TLS Characteristics",
            both_absent || runtime.characteristics == final_candidate.characteristics,
        ),
    ];
    let mut blockers = fields
        .iter()
        .filter(|(_, pass)| !*pass)
        .map(|(label, _)| format!("{label} mismatch"))
        .collect::<Vec<_>>();
    blockers.sort();
    blockers.dedup();
    OreansTlsPreservationComparison {
        pe_kind_preserved: fields[0].1,
        pointer_size_preserved: fields[1].1,
        tls_presence_preserved: fields[2].1,
        directory_preserved: fields[3].1,
        raw_data_range_preserved: fields[4].1,
        index_rva_preserved: fields[5].1,
        callbacks_rva_preserved: fields[6].1,
        callbacks_preserved: fields[7].1,
        null_terminator_preserved: fields[8].1,
        zero_fill_preserved: fields[9].1,
        characteristics_preserved: fields[10].1,
        all_preserved: blockers.is_empty(),
        blockers,
    }
}

fn validate_tls_evidence(
    evidence: &OreansTlsEvidence,
    protected_input: &OreansArtifactIdentity,
    candidate: &OreansArtifactIdentity,
    pe_evidence: &OreansPeEvidence,
) -> Vec<String> {
    let mut failures = Vec::new();
    if evidence.schema_version != OREANS_TLS_EVIDENCE_SCHEMA_VERSION {
        failures.push(format!(
            "schema_version '{}' is not {}",
            evidence.schema_version, OREANS_TLS_EVIDENCE_SCHEMA_VERSION
        ));
    }
    failures.extend(validate_tls_identity(
        "protected_input",
        &evidence.protected_input,
        protected_input,
    ));
    failures.extend(validate_tls_identity(
        "candidate",
        &evidence.candidate,
        candidate,
    ));

    let runtime = &evidence.runtime;
    if !matches!(runtime.pointer_size, 4 | 8) {
        failures.push("runtime pointer_size must be 4 or 8".to_string());
    }
    if runtime.pointer_size != if runtime.pe32_plus { 8 } else { 4 } {
        failures.push("runtime pointer_size disagrees with PE kind".to_string());
    }
    if runtime.directory_present {
        if runtime.directory_rva == 0 || runtime.directory_size == 0 {
            failures.push("runtime TLS directory is present but RVA/size is zero".to_string());
        }
        if runtime.directory_bytes_read != runtime.directory_size as usize {
            failures
                .push("runtime TLS directory bytes_read disagrees with directory_size".to_string());
        }
        if (runtime.start_rva.is_some()) != (runtime.end_rva.is_some()) {
            failures.push("runtime TLS raw-data RVAs must be paired".to_string());
        }
        if let (Some(start), Some(end)) = (runtime.start_rva, runtime.end_rva) {
            if start > end {
                failures.push("runtime TLS raw-data range is reversed".to_string());
            }
        }
        if runtime.address_of_index == 0 || runtime.index_rva.is_none() {
            failures.push("runtime TLS AddressOfIndex is missing".to_string());
        }
        if runtime.index_bytes_read != 4 {
            failures.push("runtime TLS index bytes_read must be 4".to_string());
        }
    }
    if !stable_blocker_list(&runtime.blockers) {
        failures.push("runtime TLS blockers must be sorted and deduplicated".to_string());
    }
    if evidence.reported_tls_evidence_present != runtime.directory_present {
        failures.push(
            "reported_tls_evidence_present disagrees with runtime directory_present".to_string(),
        );
    }
    let runtime_complete = runtime.blockers.is_empty();
    if evidence.reported_tls_evidence_complete != runtime_complete {
        failures.push("reported_tls_evidence_complete disagrees with runtime blockers".to_string());
    }
    if evidence.runtime_evidence_present != runtime.directory_present {
        failures
            .push("runtime_evidence_present disagrees with runtime directory_present".to_string());
    }
    if evidence.runtime_evidence_complete != runtime_complete {
        failures.push("runtime_evidence_complete disagrees with runtime blockers".to_string());
    }
    if !runtime.blockers.is_empty() {
        failures.push("runtime TLS evidence contains blockers".to_string());
    }
    if !runtime.directory_present {
        failures.push("runtime TLS directory is absent".to_string());
    }

    let mut terminators = 0usize;
    for (position, slot) in runtime.callback_slots.iter().enumerate() {
        if slot.slot_index != position {
            failures.push("runtime TLS callback slot indices are not continuous".to_string());
        }
        if slot.bytes_read != runtime.pointer_size {
            failures.push(format!(
                "runtime TLS callback slot {position} bytes_read mismatch"
            ));
        }
        match slot.status.as_str() {
            "Resolved" => {
                if slot.callback_rva.is_none() || slot.observed_value.is_none_or(|value| value == 0)
                {
                    failures.push(format!(
                        "runtime TLS resolved callback slot {position} is incomplete"
                    ));
                }
                if terminators != 0 {
                    failures.push("runtime TLS callback slot follows NULL terminator".to_string());
                }
            }
            "ZeroTerminator" => {
                terminators += 1;
                if slot.callback_rva.is_some() || slot.observed_value != Some(0) {
                    failures.push(format!(
                        "runtime TLS zero terminator slot {position} is invalid"
                    ));
                }
                if position + 1 != runtime.callback_slots.len() {
                    failures.push("runtime TLS zero terminator is not final".to_string());
                }
            }
            other => failures.push(format!("runtime TLS callback status '{other}' is invalid")),
        }
    }
    if runtime.callbacks_rva.is_some() && terminators != 1 {
        failures
            .push("runtime TLS callback list must contain exactly one NULL terminator".to_string());
    }
    if runtime.callbacks_rva.is_none()
        && (!runtime.callback_slots.is_empty() || !runtime.null_terminated)
    {
        failures.push(
            "runtime TLS callback array is absent but callback evidence is non-empty".to_string(),
        );
    }
    if runtime.callbacks_rva.is_some() && runtime.null_terminated != (terminators == 1) {
        failures.push("runtime TLS null_terminated disagrees with callback slots".to_string());
    }

    let final_candidate = &evidence.final_candidate;
    if !matches!(final_candidate.pointer_size, 4 | 8) {
        failures.push("final TLS pointer_size must be 4 or 8".to_string());
    }
    if final_candidate.pointer_size != if final_candidate.pe32_plus { 8 } else { 4 } {
        failures.push("final TLS pointer_size disagrees with PE kind".to_string());
    }
    if !stable_blocker_list(&final_candidate.blockers) {
        failures.push("final TLS blockers must be sorted and deduplicated".to_string());
    }
    if !final_candidate.blockers.is_empty() {
        failures.push("final TLS evidence contains blockers".to_string());
    }
    if final_candidate.directory_present {
        let required = if final_candidate.pe32_plus { 40 } else { 24 };
        if final_candidate.directory_rva == 0
            || final_candidate.directory_size < required
            || !final_candidate.directory_raw_backed
        {
            failures.push("final TLS directory is not complete and raw-backed".to_string());
        }
        if final_candidate.index_rva.is_none() || !final_candidate.index_raw_backed {
            failures.push("final TLS AddressOfIndex is not raw-backed".to_string());
        }
        if final_candidate.start_rva.is_some() != final_candidate.end_rva.is_some() {
            failures.push("final TLS raw-data RVAs must be paired".to_string());
        }
        if let (Some(start), Some(end)) = (final_candidate.start_rva, final_candidate.end_rva) {
            if start > end {
                failures.push("final TLS raw-data range is reversed".to_string());
            } else if start == end {
                if start > pe_evidence.size_of_image {
                    failures
                        .push("final TLS zero-size raw-data range is outside image".to_string());
                }
            } else if !rva_range_raw_backed(&pe_evidence.sections, start, end - start) {
                failures.push("final TLS raw-data range is not raw-backed".to_string());
            }
        }
    }
    if final_candidate.directory_present != pe_evidence.tls.present
        || final_candidate.directory_rva != pe_evidence.tls.rva
        || final_candidate.directory_size != pe_evidence.tls.size
        || final_candidate.directory_raw_backed != pe_evidence.tls.raw_backed
        || !pe_evidence.tls.in_image
    {
        failures.push("final TLS directory disagrees with structured PE evidence".to_string());
    }
    if final_candidate.pe32_plus != pe_evidence.pe32_plus
        || final_candidate.pointer_size != if pe_evidence.pe32_plus { 8 } else { 4 }
        || final_candidate.image_base != pe_evidence.image_base
        || final_candidate.size_of_image != pe_evidence.size_of_image
    {
        failures.push(
            "final TLS architecture/image identity disagrees with structured PE evidence"
                .to_string(),
        );
    }
    match pe_evidence.tls_detail.as_ref() {
        Some(detail) => {
            if final_candidate.index_rva != detail.address_of_index_rva
                || final_candidate.callbacks_rva != detail.callback_array_rva
                || final_candidate.callback_rvas != detail.callback_rvas
                || final_candidate.null_terminated != detail.null_terminated
                || final_candidate.directory_size != detail.directory_size
            {
                failures
                    .push("final TLS fields disagree with structured PE TLS detail".to_string());
            }
        }
        None => failures.push("structured PE TLS detail is missing".to_string()),
    }

    let expected_preservation = recompute_tls_preservation(runtime, final_candidate);
    if evidence.preservation != expected_preservation {
        failures.push("TLS preservation comparison disagrees with recomputed fields".to_string());
    }
    if !stable_blocker_list(&evidence.preservation.blockers) {
        failures.push("TLS preservation blockers must be sorted and deduplicated".to_string());
    }
    if !stable_blocker_list(&evidence.blockers) {
        failures.push("TLS evidence blockers must be sorted and deduplicated".to_string());
    }
    let underlying_pass = failures.is_empty();
    if evidence.blockers.is_empty() {
        if !underlying_pass {
            failures.push("failed TLS evidence must include a blocker".to_string());
        }
    } else if underlying_pass {
        failures.push("passing TLS evidence must not include blockers".to_string());
    }
    let computed_pass = failures.is_empty();
    if evidence.prerequisite_passes != computed_pass {
        failures.push(format!(
            "prerequisite_passes diagnostic disagrees with recomputed result ({}/{})",
            evidence.prerequisite_passes, computed_pass
        ));
    }
    failures
}

fn sorted_unique_u8(values: &[u8]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_relocation_rva(rva: u32, width: usize, size_of_image: u32) -> bool {
    u32::try_from(width)
        .ok()
        .and_then(|width| rva.checked_add(width))
        .is_some_and(|end| end <= size_of_image)
}

fn recompute_relocation_preservation(
    runtime: &OreansRuntimeRelocationEvidence,
    final_candidate: &OreansFinalRelocationEvidence,
) -> OreansRelocationPreservationComparison {
    let pe_kind_preserved = runtime.pe32_plus == final_candidate.pe32_plus;
    let pointer_size_preserved = runtime.pointer_size == final_candidate.pointer_size;
    let relocation_presence_preserved =
        runtime.directory_present && final_candidate.directory_present;
    let directory_raw_backed = final_candidate.directory_raw_backed;
    let target_set_preserved = runtime.targets.len() == final_candidate.targets.len()
        && runtime
            .targets
            .iter()
            .zip(&final_candidate.targets)
            .all(|(left, right)| {
                left.block_index == right.block_index
                    && left.entry_index == right.entry_index
                    && left.target_rva == right.target_rva
                    && left.relocation_type == right.relocation_type
            });
    let normalized_values_preserved = runtime.targets.len() == final_candidate.targets.len()
        && runtime
            .targets
            .iter()
            .zip(&final_candidate.targets)
            .all(|(left, right)| {
                left.normalized_value.is_some() && left.normalized_value == right.normalized_value
            });
    let dynamic_base_preserved = runtime.dynamic_base == final_candidate.dynamic_base;
    let relocs_stripped_preserved = runtime.relocs_stripped == final_candidate.relocs_stripped;
    let fields = [
        ("PE kind", pe_kind_preserved),
        ("pointer size", pointer_size_preserved),
        ("relocation presence", relocation_presence_preserved),
        ("directory raw backing", directory_raw_backed),
        ("relocation target set", target_set_preserved),
        ("normalized relocation values", normalized_values_preserved),
        ("DYNAMIC_BASE", dynamic_base_preserved),
        ("RELOCS_STRIPPED", relocs_stripped_preserved),
        (
            "all final relocation targets raw-backed",
            final_candidate.all_targets_raw_backed,
        ),
    ];
    let mut blockers = fields
        .iter()
        .filter(|(_, passed)| !*passed)
        .map(|(label, _)| format!("{label} was not preserved"))
        .collect::<Vec<_>>();
    blockers.sort();
    blockers.dedup();
    OreansRelocationPreservationComparison {
        pe_kind_preserved,
        pointer_size_preserved,
        relocation_presence_preserved,
        directory_raw_backed,
        target_set_preserved,
        normalized_values_preserved,
        dynamic_base_preserved,
        relocs_stripped_preserved,
        all_preserved: blockers.is_empty(),
        blockers,
    }
}

fn recompute_aslr_simulation(
    final_candidate: &OreansFinalRelocationEvidence,
) -> OreansAslrSimulationEvidence {
    let preferred = final_candidate.image_base;
    let delta = 0x100000u64;
    let mut blockers = Vec::new();
    let mut bases = Vec::new();
    if let Some(base) = preferred.checked_add(delta) {
        bases.push((base, i64::try_from(delta).unwrap_or(i64::MAX)));
    } else {
        blockers.push("positive ASLR base overflows".to_string());
    }
    if let Some(base) = preferred.checked_sub(delta) {
        bases.push((base, -i64::try_from(delta).unwrap_or(i64::MAX)));
    } else {
        blockers.push("negative ASLR base underflows".to_string());
    }
    let mut cases = Vec::new();
    for (new_image_base, signed_delta) in bases {
        let mut case_blockers = Vec::new();
        if new_image_base == preferred {
            case_blockers.push("simulated base is not different from preferred base".to_string());
        }
        if !final_candidate.pe32_plus
            && new_image_base
                .checked_add(u64::from(final_candidate.size_of_image))
                .is_none_or(|end| end > u64::from(u32::MAX) + 1)
        {
            case_blockers.push("PE32 simulated image range overflows".to_string());
        }
        for target in &final_candidate.targets {
            let Some(normalized) = target.normalized_value else {
                case_blockers.push(format!(
                    "target {:#x} lacks normalized value",
                    target.target_rva
                ));
                continue;
            };
            let simulated = if signed_delta >= 0 {
                normalized.checked_add(signed_delta as u64)
            } else {
                normalized.checked_sub(signed_delta.unsigned_abs())
            };
            let Some(simulated) = simulated else {
                case_blockers.push(format!(
                    "target {:#x} delta arithmetic overflow",
                    target.target_rva
                ));
                continue;
            };
            if !final_candidate.pe32_plus && simulated > u64::from(u32::MAX) {
                case_blockers.push(format!(
                    "target {:#x} exceeds PE32 value width",
                    target.target_rva
                ));
                continue;
            }
            let de_relocated = if signed_delta >= 0 {
                simulated.checked_sub(signed_delta as u64)
            } else {
                simulated.checked_add(signed_delta.unsigned_abs())
            };
            if de_relocated != Some(normalized) {
                case_blockers.push(format!(
                    "target {:#x} failed pure delta round-trip",
                    target.target_rva
                ));
            }
        }
        cases.push(OreansAslrSimulationCase {
            new_image_base,
            delta: signed_delta,
            target_count: u32::try_from(final_candidate.targets.len()).unwrap_or(u32::MAX),
            passed: case_blockers.is_empty(),
            blockers: case_blockers,
        });
    }
    let covers_positive_delta = cases.iter().any(|case| case.delta > 0);
    let covers_negative_delta = cases.iter().any(|case| case.delta < 0);
    let normalized_values_used = !final_candidate.targets.is_empty()
        && final_candidate
            .targets
            .iter()
            .all(|target| target.normalized_value.is_some());
    let all_passed = cases.len() >= 2
        && covers_positive_delta
        && covers_negative_delta
        && normalized_values_used
        && cases.iter().all(|case| case.passed);
    if !covers_positive_delta {
        blockers.push("ASLR simulation lacks a positive delta".to_string());
    }
    if !covers_negative_delta {
        blockers.push("ASLR simulation lacks a negative delta".to_string());
    }
    if !normalized_values_used {
        blockers.push("ASLR simulation did not use normalized values".to_string());
    }
    OreansAslrSimulationEvidence {
        pure_delta: true,
        covers_positive_delta,
        covers_negative_delta,
        normalized_values_used,
        cases,
        all_passed,
        blockers,
    }
}

fn validate_relocation_evidence(
    evidence: &OreansRelocationEvidence,
    protected_input: &OreansArtifactIdentity,
    candidate: &OreansArtifactIdentity,
    pe_evidence: &OreansPeEvidence,
) -> Vec<String> {
    let mut failures = Vec::new();
    if evidence.schema_version != OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION {
        failures.push(format!(
            "schema_version '{}' is not {}",
            evidence.schema_version, OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION
        ));
    }
    for (label, identity) in [
        ("protected_input", &evidence.protected_input),
        ("candidate", &evidence.candidate),
    ] {
        if identity.path.trim().is_empty() {
            failures.push(format!("{label}.path is empty"));
        }
        let expected = if label == "protected_input" {
            protected_input
        } else {
            candidate
        };
        if !is_sha256(&identity.sha256)
            || identity.sha256 != expected.sha256
            || identity.size_bytes != expected.size_bytes
        {
            failures.push(format!("{label} SHA-256/size does not match observation"));
        }
    }
    let runtime = &evidence.runtime;
    let expected_pointer_size = if pe_evidence.pe32_plus { 8 } else { 4 };
    if runtime.pointer_size != expected_pointer_size
        || runtime.pointer_size != if runtime.pe32_plus { 8 } else { 4 }
    {
        failures.push("runtime pointer_size disagrees with PE kind".to_string());
    }
    if runtime.pe32_plus != pe_evidence.pe32_plus
        || runtime.preferred_image_base != pe_evidence.image_base
        || runtime.size_of_image != pe_evidence.size_of_image
    {
        failures.push("runtime relocation image identity disagrees with PE evidence".to_string());
    }
    if !runtime.directory_present || runtime.directory_rva == 0 || runtime.directory_size < 8 {
        failures.push("runtime relocation directory is absent or incomplete".to_string());
    }
    if runtime.directory_bytes_read != runtime.directory_size as usize {
        failures.push("runtime relocation directory bytes_read mismatch".to_string());
    }
    if runtime.block_count == 0 || runtime.entry_count == 0 || runtime.non_absolute_entry_count == 0
    {
        failures
            .push("runtime relocation blocks/entries/non-ABS coverage is incomplete".to_string());
    }
    if runtime.targets.len() != runtime.non_absolute_entry_count as usize {
        failures.push("runtime relocation target count disagrees with non-ABS count".to_string());
    }
    if !sorted_unique_u8(&runtime.observed_types) {
        failures.push("runtime relocation observed_types must be sorted and unique".to_string());
    }
    let expected_type = if runtime.pe32_plus { 10 } else { 3 };
    if runtime
        .observed_types
        .iter()
        .any(|kind| *kind != 0 && *kind != expected_type)
    {
        failures.push("runtime relocation contains an architecture-invalid type".to_string());
    }
    for target in &runtime.targets {
        if target.status != "Normalized" || target.bytes_read != runtime.pointer_size {
            failures.push(format!(
                "runtime relocation target {:#x} is not normalized",
                target.target_rva
            ));
        }
        if target.relocation_type != expected_type
            || !valid_relocation_rva(
                target.target_rva,
                runtime.pointer_size,
                runtime.size_of_image,
            )
        {
            failures.push(format!(
                "runtime relocation target {:#x} is invalid",
                target.target_rva
            ));
        }
        let normalized = target.normalized_value;
        let runtime_value = target.runtime_value;
        let expected_normalized = runtime_value
            .filter(|value| *value >= runtime.runtime_image_base)
            .and_then(|value| {
                runtime
                    .preferred_image_base
                    .checked_add(value - runtime.runtime_image_base)
            });
        if normalized.is_none() || normalized != expected_normalized {
            failures.push(format!(
                "runtime relocation target {:#x} is not de-relocated",
                target.target_rva
            ));
        }
    }
    if !runtime.blockers.is_empty() || !stable_blocker_list(&runtime.blockers) {
        failures.push("runtime relocation blockers are present or unstable".to_string());
    }
    if evidence.reported_relocation_evidence_present != runtime.directory_present
        || evidence.runtime_evidence_present != runtime.directory_present
        || evidence.reported_relocation_evidence_complete != runtime.blockers.is_empty()
        || evidence.runtime_evidence_complete != runtime.blockers.is_empty()
    {
        failures.push(
            "reported runtime relocation diagnostics disagree with runtime evidence".to_string(),
        );
    }

    let final_candidate = &evidence.final_candidate;
    if final_candidate.pe32_plus != pe_evidence.pe32_plus
        || final_candidate.pointer_size != expected_pointer_size
        || final_candidate.image_base != pe_evidence.image_base
        || final_candidate.size_of_image != pe_evidence.size_of_image
    {
        failures.push("final relocation image identity disagrees with PE evidence".to_string());
    }
    if !final_candidate.directory_present
        || final_candidate.directory_rva != pe_evidence.base_reloc.rva
        || final_candidate.directory_size != pe_evidence.base_reloc.size
        || !final_candidate.directory_raw_backed
        || !pe_evidence.base_reloc.raw_backed
        || !pe_evidence.base_reloc.in_image
    {
        failures.push(
            "final relocation directory is not present, in-image, and raw-backed".to_string(),
        );
    }
    if final_candidate.block_count == 0
        || final_candidate.entry_count == 0
        || final_candidate.non_absolute_entry_count == 0
        || !final_candidate.has_non_absolute_entry
        || !final_candidate.all_targets_raw_backed
    {
        failures.push(
            "final relocation coverage lacks blocks, entries, non-ABS entry, or raw-backed targets"
                .to_string(),
        );
    }
    if final_candidate.blocks.len() != final_candidate.block_count as usize
        || final_candidate.targets.len() != final_candidate.non_absolute_entry_count as usize
    {
        failures.push("final relocation block/target counts disagree".to_string());
    }
    if !sorted_unique_u8(&final_candidate.observed_types) {
        failures.push("final relocation observed_types must be sorted and unique".to_string());
    }
    if !final_candidate.dynamic_base {
        failures.push("final relocation DYNAMIC_BASE is not set".to_string());
    }
    if final_candidate.relocs_stripped {
        failures.push("final relocation RELOCS_STRIPPED is set".to_string());
    }
    for (expected_block_index, block) in final_candidate.blocks.iter().enumerate() {
        if block.block_index != u32::try_from(expected_block_index).unwrap_or(u32::MAX)
            || block.page_rva % 0x1000 != 0
            || block.block_size < 8
            || block.block_size % 2 != 0
            || block.entry_count != (block.block_size - 8) / 2
        {
            failures.push(format!(
                "final relocation block {} is malformed",
                block.block_index
            ));
        }
    }
    let mut previous_target_index: Option<(u32, u32)> = None;
    for target in &final_candidate.targets {
        let target_block = usize::try_from(target.block_index)
            .ok()
            .and_then(|index| final_candidate.blocks.get(index));
        if target_block.is_none_or(|block| {
            block.block_index != target.block_index || target.entry_index >= block.entry_count
        }) {
            failures.push(format!(
                "final relocation target block/entry index is out of range ({}/{})",
                target.block_index, target.entry_index
            ));
        }
        if previous_target_index
            .is_some_and(|previous| (target.block_index, target.entry_index) <= previous)
        {
            failures.push("final relocation targets are not in block/entry order".to_string());
        }
        previous_target_index = Some((target.block_index, target.entry_index));
        if target.relocation_type != expected_type
            || !target.raw_backed
            || target.raw_offset.is_none()
            || target.stored_value.is_none()
            || target.normalized_value.is_none()
            || !valid_relocation_rva(
                target.target_rva,
                expected_pointer_size,
                final_candidate.size_of_image,
            )
            || !rva_range_raw_backed(
                &pe_evidence.sections,
                target.target_rva,
                expected_pointer_size as u32,
            )
        {
            failures.push(format!(
                "final relocation target {:#x} is not independently raw-backed",
                target.target_rva
            ));
        }
        if target.normalized_value
            != target.stored_value.filter(|value| {
                value
                    .checked_sub(final_candidate.image_base)
                    .is_some_and(|delta| delta < u64::from(final_candidate.size_of_image))
            })
        {
            failures.push(format!(
                "final relocation target {:#x} is not normalized",
                target.target_rva
            ));
        }
    }
    if let Some(detail) = pe_evidence.relocation_detail.as_ref() {
        if detail.block_count != final_candidate.block_count
            || detail.entry_count != final_candidate.entry_count
            || detail.non_absolute_entry_count != final_candidate.non_absolute_entry_count
            || detail.observed_types != final_candidate.observed_types
            || !detail.all_targets_in_image
            || detail.dynamic_base != final_candidate.dynamic_base
            || detail.relocs_stripped != final_candidate.relocs_stripped
        {
            failures.push(
                "final relocation evidence disagrees with OreansPeEvidence.relocation_detail"
                    .to_string(),
            );
        }
    } else {
        failures.push("OreansPeEvidence relocation_detail is missing".to_string());
    }

    let expected_preservation = recompute_relocation_preservation(runtime, final_candidate);
    if evidence.preservation != expected_preservation {
        failures
            .push("relocation preservation comparison disagrees with recomputation".to_string());
    }
    if !stable_blocker_list(&evidence.preservation.blockers)
        || !stable_blocker_list(&evidence.blockers)
    {
        failures.push("relocation blocker lists must be sorted and deduplicated".to_string());
    }
    let expected_simulation = recompute_aslr_simulation(final_candidate);
    if evidence.simulation != expected_simulation {
        failures.push(
            "ASLR simulation disagrees with independent pure-delta recomputation".to_string(),
        );
    }
    if !evidence.simulation.pure_delta
        || !evidence.simulation.covers_positive_delta
        || !evidence.simulation.covers_negative_delta
        || !evidence.simulation.normalized_values_used
        || !evidence.simulation.all_passed
    {
        failures.push(
            "ASLR simulation does not prove positive and negative normalized deltas".to_string(),
        );
    }
    let underlying_pass = failures.is_empty();
    if evidence.blockers.is_empty() && !underlying_pass {
        failures.push("failed relocation evidence must include a blocker".to_string());
    } else if !evidence.blockers.is_empty() && underlying_pass {
        failures.push("passing relocation evidence must not include blockers".to_string());
    }
    let computed_pass = failures.is_empty();
    if evidence.prerequisite_passes != computed_pass {
        failures.push(format!(
            "prerequisite_passes diagnostic disagrees with recomputed result ({}/{})",
            evidence.prerequisite_passes, computed_pass
        ));
    }
    failures
}

fn validate_section_rebuild_evidence(
    evidence: &OreansSectionRebuildEvidence,
    protected_input: &OreansArtifactIdentity,
    candidate: &OreansArtifactIdentity,
    pe_evidence: &OreansPeEvidence,
    iat_evidence: &OreansIatEvidence,
    tls_evidence: &OreansTlsEvidence,
    relocation_evidence: &OreansRelocationEvidence,
) -> Vec<String> {
    let mut failures = Vec::new();
    if evidence.schema_version != OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION {
        failures.push(format!(
            "schema_version '{}' is not {}",
            evidence.schema_version, OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION
        ));
    }
    for (label, identity, expected) in [
        (
            "protected_input",
            &evidence.protected_input,
            protected_input,
        ),
        ("candidate", &evidence.candidate, candidate),
    ] {
        if identity.path.trim().is_empty() {
            failures.push(format!("{label}.path is empty"));
        }
        if !is_sha256(&identity.sha256)
            || identity.sha256 != expected.sha256
            || identity.size_bytes != expected.size_bytes
        {
            failures.push(format!("{label} SHA-256/size does not match observation"));
        }
    }
    if evidence.machine != pe_evidence.machine {
        failures.push("section evidence machine disagrees with PE evidence".to_string());
    }
    if evidence.pe32_plus != pe_evidence.pe32_plus
        || evidence.file_alignment != pe_evidence.file_alignment
        || evidence.section_alignment != pe_evidence.section_alignment
        || evidence.size_of_headers != pe_evidence.size_of_headers
        || evidence.size_of_image != pe_evidence.size_of_image
    {
        failures.push("section/header scalar facts disagree with PE evidence".to_string());
    }
    if evidence.file_alignment == 0
        || !evidence.file_alignment.is_power_of_two()
        || evidence.section_alignment == 0
        || !evidence.section_alignment.is_power_of_two()
        || evidence.file_alignment > evidence.section_alignment
    {
        failures.push("section/header alignment contract is invalid".to_string());
    }
    if evidence.size_of_headers == 0
        || u64::from(evidence.size_of_headers) > candidate.size_bytes
        || (evidence.file_alignment != 0
            && !evidence
                .size_of_headers
                .is_multiple_of(evidence.file_alignment))
    {
        failures.push("SizeOfHeaders is not aligned or does not fit candidate".to_string());
    }
    let expected_table_size = u64::try_from(pe_evidence.sections.len())
        .ok()
        .and_then(|count| count.checked_mul(40));
    if expected_table_size != Some(evidence.section_table_size)
        || evidence
            .section_table_offset
            .checked_add(evidence.section_table_size)
            .is_none_or(|end| end > u64::from(evidence.size_of_headers))
    {
        failures.push("section table is not fully covered by SizeOfHeaders".to_string());
    }

    if evidence.sections.len() != pe_evidence.sections.len() {
        failures.push("section evidence count disagrees with PE evidence".to_string());
    }
    let mut virtual_ranges = Vec::new();
    let mut raw_ranges = Vec::new();
    let mut expected_exec = Vec::new();
    let mut section_by_name = HashMap::new();
    for (index, section) in evidence.sections.iter().enumerate() {
        let Some(pe_section) = pe_evidence.sections.get(index) else {
            failures.push(format!(
                "section evidence has unexpected section {}",
                section.name
            ));
            continue;
        };
        if section.name != pe_section.name
            || section.virtual_address != pe_section.virtual_address
            || section.virtual_size != pe_section.virtual_size
            || section.raw_offset != pe_section.raw_offset
            || section.raw_size != pe_section.raw_size
            || section.characteristics != pe_section.characteristics
        {
            failures.push(format!(
                "section '{}' disagrees with PE evidence",
                section.name
            ));
        }
        let extent = u64::from(section.virtual_size.max(section.raw_size));
        let virtual_end = u64::from(section.virtual_address).checked_add(extent);
        let raw_end = u64::from(section.raw_offset).checked_add(u64::from(section.raw_size));
        if section.virtual_end != virtual_end.unwrap_or(u64::MAX) {
            failures.push(format!(
                "section '{}' virtual_end is not recomputed",
                section.name
            ));
        }
        if section.raw_end != raw_end.unwrap_or(u64::MAX) {
            failures.push(format!(
                "section '{}' raw_end is not recomputed",
                section.name
            ));
        }
        let Some(virtual_end) = virtual_end else {
            failures.push(format!(
                "section '{}' virtual range overflows",
                section.name
            ));
            continue;
        };
        if extent == 0
            || section.virtual_address % evidence.section_alignment.max(1) != 0
            || u64::from(section.virtual_address) < u64::from(evidence.size_of_headers)
            || virtual_end > u64::from(evidence.size_of_image)
        {
            failures.push(format!(
                "section '{}' virtual range/alignment is invalid",
                section.name
            ));
        }
        virtual_ranges.push((u64::from(section.virtual_address), virtual_end, index));
        if section.raw_size != 0 {
            let Some(raw_end) = raw_end else {
                failures.push(format!("section '{}' raw range overflows", section.name));
                continue;
            };
            if section.raw_offset % evidence.file_alignment.max(1) != 0
                || section.raw_size % evidence.file_alignment.max(1) != 0
                || u64::from(section.raw_offset) < u64::from(evidence.size_of_headers)
                || raw_end > candidate.size_bytes
            {
                failures.push(format!(
                    "section '{}' raw pointer/size range/alignment is invalid",
                    section.name
                ));
            }
            raw_ranges.push((u64::from(section.raw_offset), raw_end, index));
        }
        if (section.characteristics & 0x2000_0000) != 0 {
            expected_exec.push(section.name.clone());
        }
        if section_by_name
            .insert(section.name.clone(), index)
            .is_some()
        {
            failures.push(format!("duplicate section name '{}'", section.name));
        }
    }
    if virtual_ranges.windows(2).any(|pair| pair[1].0 < pair[0].0) {
        failures.push("section VA ranges are not in table order".to_string());
    }
    let mut virtual_sorted = virtual_ranges.clone();
    virtual_sorted.sort_by_key(|range| range.0);
    for pair in virtual_sorted.windows(2) {
        if pair[1].0 < pair[0].1 {
            failures.push("section VA ranges overlap".to_string());
        }
    }
    let mut raw_sorted = raw_ranges.clone();
    raw_sorted.sort_by_key(|range| range.0);
    if raw_ranges.windows(2).any(|pair| pair[1].0 < pair[0].0) {
        failures.push("section raw ranges are not in table order".to_string());
    }
    for pair in raw_sorted.windows(2) {
        if pair[1].0 < pair[0].1 {
            failures.push("section raw ranges overlap".to_string());
        }
    }
    if evidence.executable_sections != expected_exec {
        failures
            .push("executable section list was not recomputed from characteristics".to_string());
    }

    let max_virtual_end = virtual_ranges
        .iter()
        .map(|range| range.1)
        .max()
        .unwrap_or(0);
    let section_aligned_image =
        align_up_u64(max_virtual_end, u64::from(evidence.section_alignment));
    if section_aligned_image != u64::from(evidence.size_of_image) {
        failures.push("SizeOfImage does not equal aligned section extent".to_string());
    }
    if evidence.entry_rva != pe_evidence.entry_rva {
        failures.push("entry RVA disagrees with PE evidence".to_string());
    }
    let entry_section = evidence.sections.iter().find(|section| {
        let end = u64::from(section.virtual_address)
            .checked_add(u64::from(section.virtual_size.max(section.raw_size)));
        end.is_some_and(|end| {
            u64::from(evidence.entry_rva) >= u64::from(section.virtual_address)
                && u64::from(evidence.entry_rva) < end
        })
    });
    if evidence.entry_section.as_deref() != entry_section.map(|section| section.name.as_str()) {
        failures.push("entry section was not independently recomputed".to_string());
    }
    let entry_is_valid = entry_section.is_some_and(|section| {
        (section.characteristics & 0x2000_0000) != 0
            && section.raw_size != 0
            && u64::from(evidence.entry_rva) >= u64::from(section.virtual_address)
            && u64::from(evidence.entry_rva)
                < u64::from(section.virtual_address)
                    + u64::from(section.raw_size.min(section.virtual_size.max(1)))
    });
    if !entry_is_valid {
        failures.push("entry is not executable and raw-backed".to_string());
    }

    let expected_directory_names = [
        "export",
        "import",
        "resource",
        "exception",
        "security",
        "base_reloc",
        "debug",
        "architecture",
        "global_ptr",
        "tls",
        "load_config",
        "bound_import",
        "iat",
        "delay_import",
        "com_descriptor",
        "reserved",
    ];
    if evidence.directories.len() != expected_directory_names.len() {
        failures.push("directory coverage does not enumerate all PE directories".to_string());
    }
    let mut directories = HashMap::new();
    for directory in &evidence.directories {
        let index = usize::from(directory.index);
        if index >= expected_directory_names.len()
            || expected_directory_names
                .get(index)
                .is_none_or(|expected| directory.name != *expected)
        {
            failures.push(format!(
                "directory {} has an invalid name/index",
                directory.index
            ));
        }
        if directories.insert(directory.index, directory).is_some() {
            failures.push(format!("duplicate directory index {}", directory.index));
        }
        let expected_present = directory.rva != 0 || directory.size != 0;
        if directory.present != expected_present {
            failures.push(format!(
                "directory {} present flag is not recomputed",
                directory.index
            ));
        }
        if directory.present {
            if directory.size == 0 {
                failures.push(format!("directory {} has zero size", directory.index));
            }
            if directory.security_file_offset {
                if directory.index != 4
                    || u64::from(directory.rva) + u64::from(directory.size) > candidate.size_bytes
                {
                    failures.push(format!(
                        "security directory {} is not file-backed",
                        directory.index
                    ));
                }
            } else {
                let end = directory.rva.checked_add(directory.size);
                let backed = end.is_some_and(|end| {
                    evidence.sections.iter().any(|section| {
                        section.raw_size != 0
                            && directory.rva >= section.virtual_address
                            && end <= section.virtual_address.saturating_add(section.raw_size)
                    })
                });
                let in_image =
                    directory.rva != 0 && end.is_some_and(|end| end <= evidence.size_of_image);
                if directory.in_image != in_image || directory.raw_backed != backed {
                    failures.push(format!(
                        "directory {} coverage flags are not recomputed",
                        directory.index
                    ));
                }
                if !in_image || !backed {
                    failures.push(format!(
                        "directory {} is not in a raw-backed section",
                        directory.index
                    ));
                }
            }
        } else if directory.in_image || directory.raw_backed || directory.security_file_offset {
            failures.push(format!(
                "absent directory {} has non-canonical coverage",
                directory.index
            ));
        }
    }
    for index in 0..expected_directory_names.len() {
        if !directories.contains_key(&(index as u8)) {
            failures.push(format!("directory {} coverage is missing", index));
        }
    }
    for (index, coverage) in [
        (9u8, &pe_evidence.tls),
        (5u8, &pe_evidence.base_reloc),
        (3u8, &pe_evidence.exception),
    ] {
        if let Some(directory) = directories.get(&index) {
            if (directory.rva, directory.size, directory.present)
                != (coverage.rva, coverage.size, coverage.present)
                || (coverage.present
                    && (directory.in_image != coverage.in_image
                        || directory.raw_backed != coverage.raw_backed))
            {
                failures.push(format!(
                    "directory {} disagrees with OreansPeEvidence",
                    index
                ));
            }
        }
    }
    if let Some(directory) = directories.get(&9) {
        if let Some(final_tls) = Some(&tls_evidence.final_candidate) {
            if final_tls.directory_rva != directory.rva
                || final_tls.directory_size != directory.size
                || final_tls.directory_raw_backed != directory.raw_backed
            {
                failures.push("section TLS directory disagrees with TLS evidence".to_string());
            }
        }
    }
    if let Some(directory) = directories.get(&5) {
        if directory.rva != relocation_evidence.final_candidate.directory_rva
            || directory.size != relocation_evidence.final_candidate.directory_size
            || directory.raw_backed != relocation_evidence.final_candidate.directory_raw_backed
        {
            failures.push(
                "section relocation directory disagrees with relocation evidence".to_string(),
            );
        }
    }
    for import in &iat_evidence.final_imports {
        if !raw_backed_rva(&evidence.sections, import.slot_rva, 1) {
            failures.push(format!(
                "IAT slot {:#x} is not raw-backed by section evidence",
                import.slot_rva
            ));
        }
    }
    if pe_evidence.exception.present {
        if let Some(detail) = pe_evidence.exception_detail.as_ref() {
            for function in &detail.runtime_functions {
                if !raw_backed_rva(
                    &evidence.sections,
                    function.begin_rva,
                    function.end_rva.saturating_sub(function.begin_rva),
                ) {
                    failures.push(
                        "exception runtime range is not raw-backed by section evidence".to_string(),
                    );
                }
            }
        }
    }
    let overlay_offset = raw_ranges
        .iter()
        .map(|range| range.1)
        .max()
        .unwrap_or(u64::from(evidence.size_of_headers));
    if evidence.overlay_offset != overlay_offset
        || evidence.overlay_size != candidate.size_bytes.saturating_sub(overlay_offset)
    {
        failures.push("overlay offset/size was not recomputed from raw layout".to_string());
    }
    if !stable_blocker_list(&evidence.blockers) {
        failures.push("section evidence blockers are not sorted and deduplicated".to_string());
    }
    let computed_pass = failures.is_empty();
    if evidence.section_rebuild_evidence_pass != computed_pass {
        failures.push(format!(
            "section_rebuild_evidence_pass disagrees with recomputed result ({}/{})",
            evidence.section_rebuild_evidence_pass, computed_pass
        ));
    }
    if computed_pass && !evidence.blockers.is_empty() {
        failures.push("passing section evidence must not include blockers".to_string());
    }
    if !computed_pass && evidence.blockers.is_empty() {
        failures.push("failed section evidence must include blockers".to_string());
    }
    failures
}

fn raw_backed_rva(sections: &[OreansSectionRebuildSection], rva: u32, size: u32) -> bool {
    let Some(end) = rva.checked_add(size) else {
        return false;
    };
    sections.iter().any(|section| {
        section.raw_size != 0
            && rva >= section.virtual_address
            && end <= section.virtual_address.saturating_add(section.raw_size)
    })
}

fn align_up_u64(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    value
        .checked_add(alignment - 1)
        .map(|value| value / alignment * alignment)
        .unwrap_or(u64::MAX)
}

fn evaluate_sample(observation: &OreansSampleObservation) -> OreansSampleGateReport {
    let manifest = locked_manifest(&observation.case_id).expect("validated by caller");
    // Protected-input identity comes from the case manifest (the contract data
    // source), never from a production literal. A manifest that cannot supply
    // the identity fails closed: the sample is not bound, with an explicit
    // failure reason.
    let loaded_identity = load_locked_manifest_identity(manifest);
    let expected = loaded_identity
        .as_ref()
        .map(|identity| OreansArtifactIdentity {
            sha256: identity.sha256.clone(),
            size_bytes: identity.size_bytes,
        });
    let manifest_matched = expected.as_ref().ok() == Some(&observation.protected_input);
    let candidate_well_formed = observation.candidate.is_well_formed();
    let pe_failures = validate_pe_evidence(&observation.pe_evidence, &observation.candidate);
    let oep_failures = validate_oep_evidence(
        &observation.oep_evidence,
        &observation.protected_input,
        &observation.candidate,
        &observation.pe_evidence,
    );
    let iat_failures = validate_iat_evidence(
        &observation.iat_evidence,
        &observation.protected_input,
        &observation.candidate,
        &observation.pe_evidence,
    );
    let tls_failures = validate_tls_evidence(
        &observation.tls_evidence,
        &observation.protected_input,
        &observation.candidate,
        &observation.pe_evidence,
    );
    let relocation_failures = validate_relocation_evidence(
        &observation.relocation_evidence,
        &observation.protected_input,
        &observation.candidate,
        &observation.pe_evidence,
    );
    let section_rebuild_failures = validate_section_rebuild_evidence(
        &observation.section_rebuild_evidence,
        &observation.protected_input,
        &observation.candidate,
        &observation.pe_evidence,
        &observation.iat_evidence,
        &observation.tls_evidence,
        &observation.relocation_evidence,
    );
    let replay_failures = observation.isolated_replay.validate(&observation.candidate);
    let behavior_failures = observation
        .behavior_evidence
        .validate(&observation.candidate, &observation.protected_input);
    let replay_pass = replay_failures.is_empty();
    let oep_evidence_pass = oep_failures.is_empty();
    let iat_evidence_pass = iat_failures.is_empty();
    let tls_evidence_pass = tls_failures.is_empty();
    let relocation_evidence_pass = relocation_failures.is_empty();
    let section_rebuild_evidence_pass = section_rebuild_failures.is_empty();
    let behavior_pass = behavior_failures.is_empty();
    let evidence_failures = observation
        .prerequisites
        .evidence_failures(&observation.candidate);
    let prerequisites_pass = observation.prerequisites.all_pass(&observation.candidate)
        && replay_pass
        && pe_failures.is_empty()
        && oep_evidence_pass
        && iat_evidence_pass;
    let prerequisites_pass = prerequisites_pass && tls_evidence_pass;
    let prerequisites_pass = prerequisites_pass && relocation_evidence_pass;
    let prerequisites_pass = prerequisites_pass && section_rebuild_evidence_pass;
    let mut failures = Vec::new();

    if !manifest_matched {
        failures.push(match &loaded_identity {
            Err(e) => format!(
                "protected input cannot be bound: locked case manifest unavailable: {e} (fail-closed)"
            ),
            Ok(_) => {
                "protected input does not match locked manifest SHA-256/size".to_string()
            }
        });
    }
    if !candidate_well_formed {
        failures
            .push("candidate SHA-256/size is not a valid recorded artifact identity".to_string());
    }
    if !observation.prerequisites.survival {
        failures.push("prerequisite failed: process survival".to_string());
    }
    if !observation.prerequisites.structural {
        failures.push("prerequisite failed: structural PE acceptance".to_string());
    }
    failures.extend(evidence_failures);
    failures.extend(
        oep_failures
            .into_iter()
            .map(|failure| format!("prerequisite failed: structured OEP evidence: {failure}")),
    );
    failures.extend(
        iat_failures
            .into_iter()
            .map(|failure| format!("prerequisite failed: structured IAT evidence: {failure}")),
    );
    failures.extend(
        tls_failures
            .into_iter()
            .map(|failure| format!("prerequisite failed: structured TLS evidence: {failure}")),
    );
    failures.extend(
        relocation_failures.into_iter().map(|failure| {
            format!("prerequisite failed: structured relocation evidence: {failure}")
        }),
    );
    failures.extend(section_rebuild_failures.into_iter().map(|failure| {
        format!("prerequisite failed: structured section rebuild evidence: {failure}")
    }));
    failures.extend(
        pe_failures
            .into_iter()
            .map(|failure| format!("prerequisite failed: {failure}")),
    );
    for failure in replay_failures {
        failures.push(format!("prerequisite failed: {failure}"));
    }
    failures.extend(behavior_failures);
    if behavior_pass && !manifest_matched {
        failures.push("final behavior cannot pass an unbound protected input".to_string());
    }

    let passed = manifest_matched && candidate_well_formed && prerequisites_pass && behavior_pass;

    OreansSampleGateReport {
        case_id: observation.case_id.clone(),
        manifest: OreansManifestBindingReport {
            manifest_path: manifest.manifest_path.to_string(),
            case_id: manifest.case_id.to_string(),
            expected_protected_input: expected.unwrap_or_else(|_| OreansArtifactIdentity {
                sha256: String::new(),
                size_bytes: 0,
            }),
            observed_protected_input: observation.protected_input.clone(),
            matched: manifest_matched,
        },
        candidate: observation.candidate.clone(),
        protected_input: observation.protected_input.clone(),
        pe_evidence: observation.pe_evidence.clone(),
        oep_evidence: observation.oep_evidence.clone(),
        oep_evidence_pass,
        iat_evidence: observation.iat_evidence.clone(),
        iat_evidence_pass,
        tls_evidence: observation.tls_evidence.clone(),
        tls_evidence_pass,
        relocation_evidence: observation.relocation_evidence.clone(),
        relocation_evidence_pass,
        section_rebuild_evidence: observation.section_rebuild_evidence.clone(),
        section_rebuild_evidence_pass,
        behavior_evidence: observation.behavior_evidence.clone(),
        isolated_replay: observation.isolated_replay.clone(),
        prerequisites: observation.prerequisites.clone(),
        prerequisites_pass,
        isolated_replay_pass: replay_pass,
        final_behavior_verdict: observation.behavior_evidence.verdict,
        passed,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_contains_exactly_the_two_mainline_manifests() {
        assert_eq!(OREANS_SAMPLE_MANIFESTS.len(), 2);
        assert_eq!(OREANS_SAMPLE_MANIFESTS[0].case_id, "origin_macro");
        assert_eq!(OREANS_SAMPLE_MANIFESTS[1].case_id, "lunlun_software");
        // The locked case binding carries no hash literal; the protected-input
        // identity is loaded from the repository manifest (contract source).
        for manifest in OREANS_SAMPLE_MANIFESTS {
            let identity = load_locked_manifest_identity(&manifest)
                .expect("repository case manifest must load");
            assert_eq!(identity.sha256.len(), 64);
            assert!(identity.size_bytes > 0);
            assert_eq!(
                identity.sha256,
                identity.sha256.to_ascii_lowercase(),
                "manifest sha256 must be lowercase"
            );
        }
        for excluded in OREANS_NON_GATE_CASES {
            assert!(locked_manifest(excluded).is_none());
        }
    }

    #[test]
    fn manifest_loader_fails_closed_on_missing_manifest() {
        // A lock whose manifest does not exist anywhere must surface an
        // explicit Read error, never a silent empty/default identity.
        let lock = OreansSampleManifestLock {
            case_id: "origin_macro",
            manifest_path: "lab/cases/v2/definitely-missing-oreans-case.json",
        };
        let err =
            load_locked_manifest_identity(&lock).expect_err("missing manifest must fail closed");
        assert!(matches!(err, OreansManifestError::Read(_, _)));
    }

    #[test]
    fn manifest_loader_rejects_case_id_mismatch_and_missing_protected_input() {
        let dir = std::env::temp_dir().join(format!("mida-oreans-manifest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Minimal but schema-complete case-manifest v2 (the loader parses the
        // strict `CaseManifestV2` shape, so required fields are present).
        fn manifest_json(case_id: &str, artifact_role: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "$schema": "./case-manifest.schema.json",
                "schema_version": "mida.case-manifest/v2",
                "manifest_revision": 1,
                "case_id": case_id,
                "display_name": "test",
                "primary_artifact_sha256": "11",
                "artifacts": [{"sha256": "11", "size_bytes": 1, "role": artifact_role}],
                "capability_cell": {
                    "platform": "windows",
                    "binary_format": "pe",
                    "architecture": "x86_64",
                    "execution_model": "native",
                    "protection_family": "oreans_candidate",
                    "engine_route": "mida_plugin_oreans",
                    "corpus_role": "regression"
                },
                "static_fingerprint": {},
                "execution_policy": {},
                "oracle": {}
            }))
            .unwrap()
        }

        // Case_id mismatch.
        let mismatch_path = dir.join("mismatch.json");
        std::fs::write(
            &mismatch_path,
            manifest_json("lunlun_software", "protected_input"),
        )
        .unwrap();
        let mismatch_lock = OreansSampleManifestLock {
            case_id: "origin_macro",
            // Test-only: leak the path string to satisfy the 'static lock.
            manifest_path: Box::leak(
                mismatch_path
                    .to_string_lossy()
                    .into_owned()
                    .into_boxed_str(),
            ),
        };
        let err = load_locked_manifest_identity(&mismatch_lock)
            .expect_err("case_id mismatch must fail closed");
        assert!(matches!(err, OreansManifestError::CaseIdMismatch(_, _, _)));

        // No protected_input artifact.
        let no_protected_path = dir.join("no_protected.json");
        std::fs::write(
            &no_protected_path,
            manifest_json("origin_macro", "legacy_oracle_candidate"),
        )
        .unwrap();
        let no_protected_lock = OreansSampleManifestLock {
            case_id: "origin_macro",
            manifest_path: Box::leak(
                no_protected_path
                    .to_string_lossy()
                    .into_owned()
                    .into_boxed_str(),
            ),
        };
        let err = load_locked_manifest_identity(&no_protected_lock)
            .expect_err("missing protected_input artifact must fail closed");
        assert!(matches!(err, OreansManifestError::NoProtectedInput(_)));

        // Malformed manifest.
        let malformed_path = dir.join("malformed.json");
        std::fs::write(&malformed_path, b"{ not json !").unwrap();
        let malformed_lock = OreansSampleManifestLock {
            case_id: "origin_macro",
            manifest_path: Box::leak(
                malformed_path
                    .to_string_lossy()
                    .into_owned()
                    .into_boxed_str(),
            ),
        };
        let err = load_locked_manifest_identity(&malformed_lock)
            .expect_err("malformed manifest must fail closed");
        assert!(matches!(err, OreansManifestError::Parse(_, _)));

        std::fs::remove_dir_all(&dir).ok();
    }
    #[test]
    fn tls_disk_reread_accepts_matching_file_and_skips_missing() {
        let dir = std::env::temp_dir().join(format!("mida-t5b-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("artifact.bin");
        let bytes = b"unit-test-artifact-bytes".to_vec();
        std::fs::write(&path, &bytes).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let identity = OreansTlsArtifactIdentity {
            path: path.to_string_lossy().into_owned(),
            sha256: format!("{:064x}", hasher.finalize()),
            size_bytes: bytes.len() as u64,
        };
        // File present and matching: no failure.
        assert!(verify_tls_identity_from_disk("protected", &identity).is_empty());
        // File missing: sealed-bundle consumption, no failure.
        let missing = OreansTlsArtifactIdentity {
            path: dir.join("absent.bin").to_string_lossy().into_owned(),
            sha256: identity.sha256.clone(),
            size_bytes: identity.size_bytes,
        };
        assert!(verify_tls_identity_from_disk("protected", &missing).is_empty());
        // Empty path: no failure (bundle envelope path).
        let no_path = OreansTlsArtifactIdentity {
            path: String::new(),
            sha256: identity.sha256.clone(),
            size_bytes: identity.size_bytes,
        };
        assert!(verify_tls_identity_from_disk("protected", &no_path).is_empty());
        // File present but tampered: failure on both hash and size.
        std::fs::write(&path, b"tampered-bytes").unwrap();
        let failures = verify_tls_identity_from_disk("protected", &identity);
        assert!(!failures.is_empty(), "tampered disk must fail");
        std::fs::remove_dir_all(&dir).ok();
    }

    // -- TASK-015: serde-default backward compatibility for IAT evidence ----

    /// A minimal full-shape `OreansIatEvidence` JSON WITHOUT the newer
    /// diagnostic fields (`resolution_source`, `iat_partial_accepted`,
    /// `iat_partial_accept`, `static_corroborations`). This is the shape an
    /// older sidecar (pre-XX-9/XX-10-A) would have serialized. The
    /// `#[serde(default)]` attributes must let it deserialize.
    fn legacy_iat_evidence_json() -> serde_json::Value {
        serde_json::json!({
            "schema_version": "mida.oreans-iat-evidence/v1",
            "protected_input": {
                "path": "protected.exe",
                "sha256": "a".repeat(64),
                "size_bytes": 100
            },
            "candidate": {
                "path": "candidate.exe",
                "sha256": "b".repeat(64),
                "size_bytes": 200
            },
            "fix_imports_requested": true,
            "iat_evidence_present": true,
            "iat_evidence_complete": true,
            "iat_report": {
                "requested_bytes": 16,
                "bytes_read": 16,
                "slot_size": 8,
                "slots": [{
                    "slot_index": 0,
                    "slot_address": 1234,
                    "slot_rva": 4096,
                    "observed_value": 7777,
                    "rebuilt_value": 7777,
                    "slot_value": 7777,
                    "status": "Resolved",
                    "unresolved_reason": null,
                    "module_name": "kernel32.dll",
                    "function_name": "ExitProcess",
                    "ordinal": null
                }],
                "unresolved_reason_counts": {
                    "by_reason": {},
                    "pending_live_confirmation": 0
                }
            },
            "final_imports": [{
                "slot_rva": 4096,
                "module_name": "kernel32.dll",
                "function_name": "ExitProcess",
                "ordinal": null
            }],
            "prerequisite_passes": true,
            "blocker": null
        })
    }

    #[test]
    fn legacy_iat_sidecar_without_new_diagnostic_fields_still_deserializes() {
        // TASK-015: `#[serde(default)]` on the newer diagnostic fields
        // (`resolution_source`, `iat_partial_accepted`, `iat_partial_accept`,
        // `static_corroborations`) must let a pre-XX-9/XX-10-A sidecar
        // deserialize with the defaults filled in — the acceptance gate must
        // consume older evidence without failing on missing fields.
        let value = legacy_iat_evidence_json();
        let evidence: OreansIatEvidence =
            serde_json::from_value(value).expect("legacy sidecar must deserialize");
        assert!(!evidence.iat_partial_accepted, "default must be false");
        assert!(
            evidence.iat_partial_accept.is_none(),
            "default must be None"
        );
        assert!(evidence.blocker.is_none());
        assert!(evidence.prerequisite_passes);
        let report = evidence.iat_report.expect("report must be present");
        assert_eq!(report.slots.len(), 1);
        assert_eq!(
            report.slots[0].resolution_source, None,
            "default resolution_source must be None"
        );
        assert_eq!(report.slots[0].status, "Resolved");
    }

    #[test]
    fn iat_sidecar_still_rejects_unknown_fields() {
        // TASK-015: the `#[serde(default)]` additions must NOT weaken
        // `deny_unknown_fields` — an unknown top-level field must still fail
        // closed, so future schema drift is caught at parse time.
        let mut value = legacy_iat_evidence_json();
        value["unexpected_field"] = serde_json::json!(123);
        let result: Result<OreansIatEvidence, _> = serde_json::from_value(value);
        assert!(
            result.is_err(),
            "unknown field must still be rejected (deny_unknown_fields preserved)"
        );
    }

    #[test]
    fn iat_sidecar_round_trips_new_diagnostic_fields() {
        // TASK-015: a sidecar produced with the newer diagnostic fields must
        // serialize AND deserialize without loss (round-trip), so a modern
        // producer's output is fully preserved by the gate.
        let value = legacy_iat_evidence_json();
        let mut evidence: OreansIatEvidence =
            serde_json::from_value(value).expect("legacy sidecar must deserialize");
        evidence.iat_partial_accepted = true;
        evidence.iat_partial_accept = Some(OreansIatPartialAcceptEvidence {
            partial_accepted: true,
            resolved_fraction_num: 74,
            resolved_fraction_den: 201,
            fraction_ok: false,
            rejected_within_budget: false,
            structural_failures: vec![],
            rejected_slots: vec![],
            stale_slots: vec![],
            accepted_resolved_slots: vec![],
            static_corroborations: vec![],
        });
        let bytes = serde_json::to_vec(&evidence).expect("serialize");
        let decoded: OreansIatEvidence =
            serde_json::from_slice(&bytes).expect("round-trip deserialize");
        assert!(decoded.iat_partial_accepted);
        assert!(decoded.iat_partial_accept.is_some());
        assert_eq!(decoded.iat_report.unwrap().slots.len(), 1);
    }
}
