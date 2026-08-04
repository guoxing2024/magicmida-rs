//! Unified run bundle contract (`mida.oreans-evidence-bundle/v1`).
//!
//! A bundle is the aggregate artifact one isolated unpack run must produce:
//! the protected-input identity, the emitted-candidate identity, the tool
//! revision, the runner configuration digest, the transform manifest, the
//! structured PE evidence, and the five candidate-bound sidecars (OEP, IAT,
//! TLS, relocation, section rebuild).
//!
//! This module is the independent (black-box) consumer of that contract. It
//! deliberately does not share types with the producers in `mida-cli` /
//! `mida-pe`; a producer-to-consumer schema drift must be caught here, not
//! hidden by shared codegen.
//!
//! Fail-closed rules enforced here:
//! - the manifest schema version is exactly `mida.oreans-evidence-bundle/v1`;
//! - `runner_config_digest` is exactly 64 hexadecimal characters;
//! - every declared member file is present and its SHA-256 / size match;
//! - the recomputed bundle hash (canonical form, see below) matches
//!   `bundle_sha256`;
//! - every required member is declared *and* its JSON top-level
//!   `schema_version` matches the expected schema id (black-box producer
//!   compatibility);
//! - the transform manifest binds the same candidate identity;
//! - a `partial` completion marker, a missing required member, or any hash
//!   mismatch makes the bundle **not a valid run**, even when every other
//!   field parses.
//!
//! Canonical bundle hash: SHA-256 over the concatenation of lines
//! `name|sha256|size\n` for all members sorted lexicographically by name
//! (UTF-8, `\n` line terminator, lowercase hex SHA-256).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::identity::sha256_hex;
use crate::oreans_gate::{
    OREANS_IAT_EVIDENCE_SCHEMA_VERSION, OREANS_OEP_EVIDENCE_SCHEMA_VERSION,
    OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION, OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
    OREANS_TLS_EVIDENCE_SCHEMA_VERSION,
};
use crate::oreans_pe_evidence::OREANS_PE_EVIDENCE_SCHEMA_VERSION;

/// Schema id of the bundle manifest itself.
pub const OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION: &str = "mida.oreans-evidence-bundle/v1";

/// Schema id of the bound transform manifest written next to a candidate.
pub const TRANSFORM_MANIFEST_SCHEMA_VERSION: &str = "mida.transform-manifest/v0";

/// Logical member names required for a bundle to be a complete valid run.
pub const REQUIRED_BUNDLE_MEMBERS: [(&str, &str); 7] = [
    ("oep_evidence", OREANS_OEP_EVIDENCE_SCHEMA_VERSION),
    ("iat_evidence", OREANS_IAT_EVIDENCE_SCHEMA_VERSION),
    ("tls_evidence", OREANS_TLS_EVIDENCE_SCHEMA_VERSION),
    (
        "relocation_evidence",
        OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION,
    ),
    (
        "section_rebuild_evidence",
        OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
    ),
    ("pe_evidence", OREANS_PE_EVIDENCE_SCHEMA_VERSION),
    ("transform_manifest", TRANSFORM_MANIFEST_SCHEMA_VERSION),
];

/// Fixed identity of one input or output artifact inside a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleArtifactIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

/// A member file declared by the bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleMemberRef {
    pub name: String,
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Completion state of a run. Only `complete` may yield a valid bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BundleCompletionMarker {
    Complete,
    Partial { reason: String },
}

/// Unified bundle manifest (`mida.oreans-evidence-bundle/v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OreansEvidenceBundle {
    pub schema_version: String,
    pub case_id: String,
    pub tool_revision: String,
    pub runner_config_digest: String,
    pub emitted_at: String,
    pub completion_marker: BundleCompletionMarker,
    pub protected_input: BundleArtifactIdentity,
    pub candidate: BundleArtifactIdentity,
    pub bundle_sha256: String,
    pub members: Vec<BundleMemberRef>,
}

/// Fail-closed result of bundle validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleVerdict {
    /// True only when the bundle is a valid complete run record.
    pub valid: bool,
    /// True only when every required member is present and correct.
    pub complete: bool,
    /// Human-readable reasons for every rejected check.
    pub reasons: Vec<String>,
}

impl BundleVerdict {
    fn ok() -> Self {
        Self {
            valid: true,
            complete: true,
            reasons: Vec::new(),
        }
    }

    fn invalid(reason: impl Into<String>) -> Self {
        Self {
            valid: false,
            complete: false,
            reasons: vec![reason.into()],
        }
    }
}

/// Canonical bundle hash over the sorted member lines `name|sha256|size\n`.
pub fn canonical_bundle_hash(members: &[BundleMemberRef]) -> String {
    let mut lines: Vec<String> = members
        .iter()
        .map(|m| format!("{}|{}|{}", m.name, m.sha256.to_lowercase(), m.size_bytes))
        .collect();
    lines.sort();
    let mut canonical = String::new();
    for line in lines {
        canonical.push_str(&line);
        canonical.push('\n');
    }
    sha256_hex(canonical.as_bytes())
}

fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate a bundle manifest against the raw member files.
///
/// `files` maps logical member name to raw bytes. Fail-closed: any missing
/// member, hash mismatch, schema mismatch, malformed digest, or partial
/// marker makes `valid == false`; a `complete` marker is only honored when
/// every check passed.
pub fn validate_evidence_bundle(
    bundle: &OreansEvidenceBundle,
    files: &BTreeMap<String, Vec<u8>>,
) -> BundleVerdict {
    let mut reasons = Vec::new();

    if bundle.schema_version != OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION {
        return BundleVerdict::invalid(format!(
            "unexpected bundle schema {} (expected {})",
            bundle.schema_version, OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION
        ));
    }

    if bundle.runner_config_digest.is_empty() || !is_64_hex(&bundle.runner_config_digest) {
        reasons.push(format!(
            "runner_config_digest must be exactly 64 hex chars, got {:?}",
            bundle.runner_config_digest
        ));
    }
    if bundle.case_id.trim().is_empty() {
        reasons.push("case_id must be non-empty".to_string());
    }
    if bundle.tool_revision.trim().is_empty() {
        reasons.push("tool_revision must be non-empty".to_string());
    }
    if bundle.emitted_at.trim().is_empty() {
        reasons.push("emitted_at must be non-empty".to_string());
    }
    if !is_64_hex(&bundle.protected_input.sha256) || bundle.protected_input.size_bytes == 0 {
        reasons.push("protected_input identity must be a 64-hex SHA-256 with size > 0".to_string());
    }
    if !is_64_hex(&bundle.candidate.sha256) || bundle.candidate.size_bytes == 0 {
        reasons.push("candidate identity must be a 64-hex SHA-256 with size > 0".to_string());
    }

    // Member names must be unique.
    let mut seen = std::collections::HashSet::new();
    for member in &bundle.members {
        if !seen.insert(member.name.clone()) {
            reasons.push(format!("duplicate member name {}", member.name));
        }
        if !is_64_hex(&member.sha256) {
            reasons.push(format!("member {} has non-64-hex sha256", member.name));
        }
    }

    // Every declared member must have a present, hash-matching file.
    for member in &bundle.members {
        match files.get(&member.name) {
            None => reasons.push(format!("member file missing: {}", member.name)),
            Some(bytes) => {
                if bytes.len() as u64 != member.size_bytes {
                    reasons.push(format!(
                        "member {} size mismatch: declared {} got {}",
                        member.name,
                        member.size_bytes,
                        bytes.len()
                    ));
                }
                let actual = sha256_hex(bytes);
                if actual != member.sha256.to_lowercase() {
                    reasons.push(format!(
                        "member {} sha256 mismatch: declared {} got {}",
                        member.name,
                        member.sha256.to_lowercase(),
                        actual
                    ));
                }
            }
        }
    }

    // Recompute the canonical bundle hash.
    let recomputed = canonical_bundle_hash(&bundle.members);
    if recomputed != bundle.bundle_sha256.to_lowercase() {
        reasons.push(format!(
            "bundle_sha256 mismatch: declared {} recomputed {}",
            bundle.bundle_sha256.to_lowercase(),
            recomputed
        ));
    }

    // Required members must all be declared.
    for (required_name, expected_schema) in REQUIRED_BUNDLE_MEMBERS {
        if !bundle.members.iter().any(|m| m.name == required_name) {
            reasons.push(format!(
                "required member {} ({}) is not declared",
                required_name, expected_schema
            ));
            continue;
        }
        // Black-box producer compatibility: the sidecar's own schema_version
        // must equal the schema id this consumer expects.
        if let Some(bytes) = files.get(required_name) {
            let value: Result<serde_json::Value, _> = serde_json::from_slice(bytes);
            match value {
                Ok(value) => {
                    let actual = value.get("schema_version").and_then(|v| v.as_str());
                    if actual != Some(expected_schema) {
                        reasons.push(format!(
                            "member {} schema_version {:?} != expected {}",
                            required_name, actual, expected_schema
                        ));
                    }
                }
                Err(e) => reasons.push(format!("member {} is not valid JSON: {e}", required_name)),
            }
        }
    }

    // Transform manifest must bind the same candidate identity.
    if let Some(bytes) = files.get("transform_manifest") {
        match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(value) => {
                let bound_sha = value
                    .get("candidate_sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_lowercase();
                let bound_size = value.get("candidate_size_bytes").and_then(|v| v.as_u64());
                if bound_sha != bundle.candidate.sha256.to_lowercase()
                    || bound_size != Some(bundle.candidate.size_bytes)
                {
                    reasons.push(format!(
                        "transform_manifest binds candidate {bound_sha}/{bound_size:?}, \
                         bundle declares {}/{}",
                        bundle.candidate.sha256.to_lowercase(),
                        bundle.candidate.size_bytes
                    ));
                }
            }
            Err(e) => reasons.push(format!("transform_manifest is not valid JSON: {e}")),
        }
    }

    // Completion marker semantics: a partial run is never a valid run.
    match &bundle.completion_marker {
        BundleCompletionMarker::Partial { reason } => {
            reasons.push(format!("completion_marker is partial: {reason}"));
        }
        BundleCompletionMarker::Complete => {}
    }

    if reasons.is_empty() {
        BundleVerdict::ok()
    } else {
        BundleVerdict {
            valid: false,
            complete: false,
            reasons,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sidecar_json(schema: &str, candidate_sha: &str) -> Vec<u8> {
        serde_json::json!({
            "schema_version": schema,
            "candidate_sha256": candidate_sha,
            "candidate_size_bytes": 4096,
        })
        .to_string()
        .into_bytes()
    }

    fn transform_manifest_json(candidate_sha: &str, candidate_size: u64) -> Vec<u8> {
        serde_json::json!({
            "schema_version": TRANSFORM_MANIFEST_SCHEMA_VERSION,
            "taxonomy_version": "mida.transform-taxonomy/v1",
            "candidate_sha256": candidate_sha,
            "candidate_size_bytes": candidate_size,
            "entries": [],
        })
        .to_string()
        .into_bytes()
    }

    fn synthetic_bundle() -> (OreansEvidenceBundle, BTreeMap<String, Vec<u8>>) {
        let candidate_sha = sha256_hex(b"synthetic-candidate");
        let members = REQUIRED_BUNDLE_MEMBERS
            .iter()
            .map(|(name, schema)| {
                let bytes = if *name == "transform_manifest" {
                    transform_manifest_json(&candidate_sha, 4096)
                } else {
                    sidecar_json(schema, &candidate_sha)
                };
                BundleMemberRef {
                    name: (*name).to_string(),
                    relative_path: format!("{name}.json"),
                    sha256: sha256_hex(&bytes),
                    size_bytes: bytes.len() as u64,
                }
            })
            .collect::<Vec<_>>();
        let bundle_hash = canonical_bundle_hash(&members);
        let bundle = OreansEvidenceBundle {
            schema_version: OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
            case_id: "origin_macro".to_string(),
            tool_revision: "oreans/two-sample-mainline@0000000".to_string(),
            runner_config_digest: "a".repeat(64),
            emitted_at: "2026-08-04T00:00:00Z".to_string(),
            completion_marker: BundleCompletionMarker::Complete,
            protected_input: BundleArtifactIdentity {
                sha256: "b".repeat(64),
                size_bytes: 5_232_656,
            },
            candidate: BundleArtifactIdentity {
                sha256: candidate_sha.clone(),
                size_bytes: 4096,
            },
            bundle_sha256: bundle_hash,
            members,
        };
        let files = REQUIRED_BUNDLE_MEMBERS
            .iter()
            .map(|(name, schema)| {
                let bytes = if *name == "transform_manifest" {
                    transform_manifest_json(&candidate_sha, 4096)
                } else {
                    sidecar_json(schema, &candidate_sha)
                };
                ((*name).to_string(), bytes)
            })
            .collect::<BTreeMap<_, _>>();
        (bundle, files)
    }

    #[test]
    fn complete_bundle_is_valid() {
        let (bundle, files) = synthetic_bundle();
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(verdict.valid, "{:?}", verdict.reasons);
        assert!(verdict.complete);
    }

    #[test]
    fn missing_required_member_is_never_valid() {
        let (mut bundle, mut files) = synthetic_bundle();
        files.remove("tls_evidence");
        bundle.members.retain(|m| m.name != "tls_evidence");
        bundle.bundle_sha256 = canonical_bundle_hash(&bundle.members);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(!verdict.complete);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("required member tls_evidence")));
    }

    #[test]
    fn partial_marker_is_never_a_valid_run() {
        let (mut bundle, files) = synthetic_bundle();
        bundle.completion_marker = BundleCompletionMarker::Partial {
            reason: "dump aborted before IAT evidence".to_string(),
        };
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("completion_marker is partial")));
    }

    #[test]
    fn member_hash_mismatch_fails_closed() {
        let (mut bundle, files) = synthetic_bundle();
        for member in &mut bundle.members {
            if member.name == "iat_evidence" {
                member.sha256 = "0".repeat(64);
            }
        }
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("iat_evidence sha256 mismatch")));
    }

    #[test]
    fn bundle_hash_mismatch_fails_closed() {
        let (mut bundle, files) = synthetic_bundle();
        bundle.bundle_sha256 = "0".repeat(64);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("bundle_sha256 mismatch")));
    }

    #[test]
    fn malformed_runner_config_digest_fails_closed() {
        let (mut bundle, files) = synthetic_bundle();
        bundle.runner_config_digest = "abc".to_string();
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("runner_config_digest")));
    }

    #[test]
    fn sidecar_schema_drift_is_detected() {
        let (bundle, mut files) = synthetic_bundle();
        files.insert(
            "tls_evidence".to_string(),
            sidecar_json("mida.oreans-tls-evidence/v2", &"x".repeat(64)),
        );
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("tls_evidence schema_version")));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let (bundle, files) = synthetic_bundle();
        let mut value = serde_json::to_value(&bundle).expect("bundle serializes to JSON");
        value["sneaky_extra"] = serde_json::json!("x");
        let parsed: Result<OreansEvidenceBundle, _> = serde_json::from_value(value.clone());
        assert!(
            parsed.is_err(),
            "deny_unknown_fields must reject extra fields"
        );
        let _ = value;
        // The files are irrelevant; deserialization itself must fail.
        let _ = files;
    }

    #[test]
    fn transform_manifest_candidate_mismatch_fails_closed() {
        let (bundle, mut files) = synthetic_bundle();
        files.insert(
            "transform_manifest".to_string(),
            transform_manifest_json(&"c".repeat(64), 4096),
        );
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("transform_manifest binds candidate")));
    }

    #[test]
    fn duplicate_member_names_fail_closed() {
        let (mut bundle, files) = synthetic_bundle();
        let dup = bundle.members[0].clone();
        bundle.members.push(dup);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("duplicate member name")));
    }
}
