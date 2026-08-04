//! Unified run bundle contract (`mida.oreans-evidence-bundle/v2`).
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
//! v2 amendments over the withdrawn v1 draft:
//! - `bundle_sha256` (member list only) is renamed `members_sha256`;
//! - a new sealed `manifest_sha256` covers *every* top-level field and every
//!   member field (including `relative_path`);
//! - every required sidecar's `protected_input`/`candidate` identity objects
//!   are re-parsed and cross-checked against the bundle identities, so
//!   tampering a sidecar's identity and recomputing all hashes still fails;
//! - `relative_path` is validated: relative only, no `..`/`.` components, no
//!   drive letters or `:`, and unique across members.
//!
//! Fail-closed rules enforced here:
//! - the manifest schema version is exactly `mida.oreans-evidence-bundle/v2`;
//! - `runner_config_digest` is exactly 64 hexadecimal characters;
//! - every declared member file is present and its SHA-256 / size match;
//! - the recomputed `members_sha256` and `manifest_sha256` match the declared
//!   values (canonical forms below);
//! - every required member is declared, its JSON top-level `schema_version`
//!   matches the expected schema id, and its embedded protected/candidate
//!   identities match the bundle identities (black-box producer
//!   compatibility and identity-chain sealing);
//! - the transform manifest binds the same candidate identity;
//! - a `partial` completion marker, a missing required member, or any hash or
//!   identity mismatch makes the bundle **not a valid run**, even when every
//!   other field parses.
//!
//! Canonical member-set hash (`members_sha256`): SHA-256 over the
//! concatenation of lines `name|sha256|size\n` for all members sorted
//! lexicographically by name (UTF-8, `\n` terminator, lowercase hex).
//!
//! Canonical manifest hash (`manifest_sha256`): SHA-256 over the concatenation
//! of lines below, in this exact order, with member lines sorted by name:
//! ```text
//! schema_version=<v>
//! case_id=<id>
//! tool_revision=<rev>
//! runner_config_digest=<digest>
//! emitted_at=<ts>
//! completion_marker=complete            (or "partial:<reason>")
//! protected_input=<sha>:<size>
//! candidate=<sha>:<size>
//! members_sha256=<members hash>
//! member=<name>:<relative_path>:<sha256>:<size>
//! ```
//! The `manifest_sha256` field itself is excluded (self-reference would be
//! uncomputable); every other field, including `members_sha256` and each
//! member's `relative_path`, is covered.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::identity::sha256_hex;
use crate::oreans_gate::{
    OREANS_IAT_EVIDENCE_SCHEMA_VERSION, OREANS_OEP_EVIDENCE_SCHEMA_VERSION,
    OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION, OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
    OREANS_TLS_EVIDENCE_SCHEMA_VERSION,
};
use crate::oreans_pe_evidence::OREANS_PE_EVIDENCE_SCHEMA_VERSION;

/// Schema id of the bundle manifest itself (v2; v1 was withdrawn pre-production).
pub const OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION: &str = "mida.oreans-evidence-bundle/v2";

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
    /// Repo/bundle-relative location of the member file. Must be relative,
    /// free of `.`/`..` components, drive letters, and `:`; unique per member.
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

/// Unified bundle manifest (`mida.oreans-evidence-bundle/v2`).
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
    /// SHA-256 over the canonical member-set lines (see module docs).
    pub members_sha256: String,
    /// SHA-256 over the canonical full manifest lines (see module docs).
    pub manifest_sha256: String,
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

/// Canonical member-set hash over the sorted lines `name|sha256|size\n`.
pub fn canonical_members_hash(members: &[BundleMemberRef]) -> String {
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

fn member_line(m: &BundleMemberRef) -> String {
    format!(
        "member={}:{}:{}:{}",
        m.name,
        m.relative_path,
        m.sha256.to_lowercase(),
        m.size_bytes
    )
}

/// Canonical full-manifest hash. Covers every top-level field (including
/// `members_sha256`) and every member field except `manifest_sha256` itself.
/// Member lines are sorted by name; see module docs for the exact layout.
pub fn canonical_manifest_hash(bundle: &OreansEvidenceBundle) -> String {
    let mut canonical = String::new();
    canonical.push_str(&format!("schema_version={}\n", bundle.schema_version));
    canonical.push_str(&format!("case_id={}\n", bundle.case_id));
    canonical.push_str(&format!("tool_revision={}\n", bundle.tool_revision));
    canonical.push_str(&format!(
        "runner_config_digest={}\n",
        bundle.runner_config_digest
    ));
    canonical.push_str(&format!("emitted_at={}\n", bundle.emitted_at));
    canonical.push_str(&match &bundle.completion_marker {
        BundleCompletionMarker::Complete => "completion_marker=complete\n".to_string(),
        BundleCompletionMarker::Partial { reason } => {
            format!("completion_marker=partial:{reason}\n")
        }
    });
    canonical.push_str(&format!(
        "protected_input={}:{}\n",
        bundle.protected_input.sha256.to_lowercase(),
        bundle.protected_input.size_bytes
    ));
    canonical.push_str(&format!(
        "candidate={}:{}\n",
        bundle.candidate.sha256.to_lowercase(),
        bundle.candidate.size_bytes
    ));
    canonical.push_str(&format!(
        "members_sha256={}\n",
        bundle.members_sha256.to_lowercase()
    ));
    let mut lines: Vec<String> = bundle.members.iter().map(member_line).collect();
    lines.sort();
    for line in lines {
        canonical.push_str(&line);
        canonical.push('\n');
    }
    sha256_hex(canonical.as_bytes())
}

fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate one `relative_path`: relative only, no `.`/`..`, no drive
/// letters or `:`. Returns the normalized (`\` -> `/`) path on success.
fn normalize_relative_path(path: &str) -> Result<String, String> {
    if path.trim().is_empty() {
        return Err("relative_path must be non-empty".to_string());
    }
    if path.contains(':') {
        return Err(format!("relative_path {path:?} must not contain ':'"));
    }
    let normalized = path.replace('\\', "/");
    if normalized.starts_with('/') {
        return Err(format!(
            "relative_path {path:?} must be relative, not absolute"
        ));
    }
    for component in normalized.split('/') {
        if component.is_empty() {
            return Err(format!("relative_path {path:?} has empty components"));
        }
        if component == "." || component == ".." {
            return Err(format!(
                "relative_path {path:?} must not contain '{component}' components"
            ));
        }
    }
    Ok(normalized)
}

/// Extract `{sha256, size_bytes}` from a JSON object field.
fn identity_from(value: &serde_json::Value, field: &str) -> Option<(String, u64)> {
    let object = value.get(field)?;
    let sha = object.get("sha256")?.as_str()?;
    let size = object.get("size_bytes")?.as_u64()?;
    Some((sha.to_string(), size))
}

/// Cross-check one required sidecar's embedded identities against the bundle.
///
/// `protected` is `None` for members that only bind the candidate
/// (`pe_evidence`).
fn check_sidecar_identity(
    name: &str,
    value: &serde_json::Value,
    bundle: &OreansEvidenceBundle,
    protected: bool,
    reasons: &mut Vec<String>,
) {
    if protected {
        if let Some((sha, size)) = identity_from(value, "protected_input") {
            if sha.to_lowercase() != bundle.protected_input.sha256.to_lowercase()
                || size != bundle.protected_input.size_bytes
            {
                reasons.push(format!(
                    "member {name} protected_input {sha}/{size} != bundle \
                     {}/{}",
                    bundle.protected_input.sha256.to_lowercase(),
                    bundle.protected_input.size_bytes
                ));
            }
        } else {
            reasons.push(format!(
                "member {name} is missing a protected_input identity object"
            ));
        }
    }
    match identity_from(value, "candidate") {
        Some((sha, size)) => {
            if sha.to_lowercase() != bundle.candidate.sha256.to_lowercase()
                || size != bundle.candidate.size_bytes
            {
                reasons.push(format!(
                    "member {name} candidate {sha}/{size} != bundle {}/{}",
                    bundle.candidate.sha256.to_lowercase(),
                    bundle.candidate.size_bytes
                ));
            }
        }
        None => reasons.push(format!(
            "member {name} is missing a candidate identity object"
        )),
    }
}

/// Validate a bundle manifest against the raw member files.
///
/// `files` maps logical member name to raw bytes. Fail-closed: any missing
/// member, hash mismatch, path violation, schema mismatch, identity mismatch,
/// malformed digest, or partial marker makes `valid == false`; a `complete`
/// marker is only honored when every check passed.
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
    if !is_64_hex(&bundle.members_sha256) {
        reasons.push("members_sha256 must be 64 hex chars".to_string());
    }
    if !is_64_hex(&bundle.manifest_sha256) {
        reasons.push("manifest_sha256 must be 64 hex chars".to_string());
    }

    // Member names and relative paths must both be unique and valid.
    let mut seen_names = std::collections::HashSet::new();
    let mut seen_paths = std::collections::HashSet::new();
    for member in &bundle.members {
        if !seen_names.insert(member.name.clone()) {
            reasons.push(format!("duplicate member name {}", member.name));
        }
        if !is_64_hex(&member.sha256) {
            reasons.push(format!("member {} has non-64-hex sha256", member.name));
        }
        match normalize_relative_path(&member.relative_path) {
            Ok(normalized) => {
                if !seen_paths.insert(normalized.clone()) {
                    reasons.push(format!(
                        "duplicate relative_path {} across members",
                        member.relative_path
                    ));
                }
            }
            Err(e) => reasons.push(format!("member {}: {e}", member.name)),
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

    // Recompute both canonical hashes.
    let recomputed_members = canonical_members_hash(&bundle.members);
    if recomputed_members != bundle.members_sha256.to_lowercase() {
        reasons.push(format!(
            "members_sha256 mismatch: declared {} recomputed {}",
            bundle.members_sha256.to_lowercase(),
            recomputed_members
        ));
    }
    let recomputed_manifest = canonical_manifest_hash(bundle);
    if recomputed_manifest != bundle.manifest_sha256.to_lowercase() {
        reasons.push(format!(
            "manifest_sha256 mismatch: declared {} recomputed {}",
            bundle.manifest_sha256.to_lowercase(),
            recomputed_manifest
        ));
    }

    // Required members: schema id, embedded identity chain, transform binding.
    for (required_name, expected_schema) in REQUIRED_BUNDLE_MEMBERS {
        if !bundle.members.iter().any(|m| m.name == required_name) {
            reasons.push(format!(
                "required member {} ({}) is not declared",
                required_name, expected_schema
            ));
            continue;
        }
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
                    match required_name {
                        "transform_manifest" => {
                            let bound_sha = value
                                .get("candidate_sha256")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default()
                                .to_lowercase();
                            let bound_size =
                                value.get("candidate_size_bytes").and_then(|v| v.as_u64());
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
                        "pe_evidence" => {
                            check_sidecar_identity(
                                required_name,
                                &value,
                                bundle,
                                false,
                                &mut reasons,
                            );
                        }
                        _ => {
                            check_sidecar_identity(
                                required_name,
                                &value,
                                bundle,
                                true,
                                &mut reasons,
                            );
                        }
                    }
                }
                Err(e) => reasons.push(format!("member {} is not valid JSON: {e}", required_name)),
            }
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

    fn sidecar_json(schema: &str, protected_sha: &str, candidate_sha: &str) -> Vec<u8> {
        serde_json::json!({
            "schema_version": schema,
            "protected_input": { "sha256": protected_sha, "size_bytes": 5_232_656 },
            "candidate": { "sha256": candidate_sha, "size_bytes": 4096 },
        })
        .to_string()
        .into_bytes()
    }

    fn pe_evidence_json(candidate_sha: &str) -> Vec<u8> {
        serde_json::json!({
            "schema_version": OREANS_PE_EVIDENCE_SCHEMA_VERSION,
            "candidate": { "sha256": candidate_sha, "size_bytes": 4096 },
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
        let protected_sha = "b".repeat(64);
        let candidate_sha = sha256_hex(b"synthetic-candidate");
        let mut files = BTreeMap::new();
        let mut members = Vec::new();
        for (name, schema) in REQUIRED_BUNDLE_MEMBERS {
            let bytes = match name {
                "transform_manifest" => transform_manifest_json(&candidate_sha, 4096),
                "pe_evidence" => pe_evidence_json(&candidate_sha),
                _ => sidecar_json(schema, &protected_sha, &candidate_sha),
            };
            files.insert(name.to_string(), bytes.clone());
            members.push(BundleMemberRef {
                name: name.to_string(),
                relative_path: format!("evidence/{name}.json"),
                sha256: sha256_hex(&bytes),
                size_bytes: bytes.len() as u64,
            });
        }
        let members_hash = canonical_members_hash(&members);
        let mut bundle = OreansEvidenceBundle {
            schema_version: OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
            case_id: "origin_macro".to_string(),
            tool_revision: "oreans/two-sample-mainline@0000000".to_string(),
            runner_config_digest: "a".repeat(64),
            emitted_at: "2026-08-04T00:00:00Z".to_string(),
            completion_marker: BundleCompletionMarker::Complete,
            protected_input: BundleArtifactIdentity {
                sha256: protected_sha.clone(),
                size_bytes: 5_232_656,
            },
            candidate: BundleArtifactIdentity {
                sha256: candidate_sha.clone(),
                size_bytes: 4096,
            },
            members_sha256: members_hash,
            manifest_sha256: String::new(),
            members,
        };
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
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
        bundle.members_sha256 = canonical_members_hash(&bundle.members);
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
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
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
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
    fn members_hash_mismatch_fails_closed() {
        let (mut bundle, files) = synthetic_bundle();
        bundle.members_sha256 = "0".repeat(64);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("members_sha256 mismatch")));
    }

    #[test]
    fn manifest_hash_covers_top_level_metadata() {
        let (mut bundle, files) = synthetic_bundle();
        bundle.case_id = "lunlun_software".to_string();
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("manifest_sha256 mismatch")));
    }

    #[test]
    fn manifest_hash_covers_relative_path() {
        let (mut bundle, files) = synthetic_bundle();
        for member in &mut bundle.members {
            if member.name == "iat_evidence" {
                member.relative_path = "evidence/swapped_iat.json".to_string();
            }
        }
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("manifest_sha256 mismatch")));
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
            sidecar_json(
                "mida.oreans-tls-evidence/v2",
                &"b".repeat(64),
                &"x".repeat(64),
            ),
        );
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("tls_evidence schema_version")));
    }

    #[test]
    fn sidecar_identity_swap_with_recomputed_hashes_fails() {
        // Attacker-style test: swap the candidate identity inside a normal
        // sidecar, then recompute the member hash and both bundle hashes.
        // The identity chain must still fail closed.
        let (mut bundle, mut files) = synthetic_bundle();
        let swapped = sidecar_json(
            OREANS_IAT_EVIDENCE_SCHEMA_VERSION,
            &"b".repeat(64),
            &"c".repeat(64),
        );
        for member in &mut bundle.members {
            if member.name == "iat_evidence" {
                member.sha256 = sha256_hex(&swapped);
                member.size_bytes = swapped.len() as u64;
            }
        }
        files.insert("iat_evidence".to_string(), swapped);
        bundle.members_sha256 = canonical_members_hash(&bundle.members);
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("iat_evidence candidate")),
            "reasons: {:?}",
            verdict.reasons
        );
    }

    #[test]
    fn sidecar_protected_identity_swap_fails() {
        let (mut bundle, mut files) = synthetic_bundle();
        let swapped = sidecar_json(
            OREANS_TLS_EVIDENCE_SCHEMA_VERSION,
            &"d".repeat(64),
            &sha256_hex(b"synthetic-candidate"),
        );
        for member in &mut bundle.members {
            if member.name == "tls_evidence" {
                member.sha256 = sha256_hex(&swapped);
                member.size_bytes = swapped.len() as u64;
            }
        }
        files.insert("tls_evidence".to_string(), swapped);
        bundle.members_sha256 = canonical_members_hash(&bundle.members);
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("tls_evidence protected_input")),
            "reasons: {:?}",
            verdict.reasons
        );
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
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("duplicate member name")));
    }

    #[test]
    fn absolute_relative_path_is_rejected() {
        let (mut bundle, files) = synthetic_bundle();
        for member in &mut bundle.members {
            if member.name == "iat_evidence" {
                member.relative_path = "C:\\evidence\\iat.json".to_string();
            }
        }
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("must not contain ':'")));
    }

    #[test]
    fn parent_traversal_relative_path_is_rejected() {
        let (mut bundle, files) = synthetic_bundle();
        for member in &mut bundle.members {
            if member.name == "iat_evidence" {
                member.relative_path = "evidence/../../iat.json".to_string();
            }
        }
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("must not contain '..'")));
    }

    #[test]
    fn duplicate_relative_path_is_rejected() {
        let (mut bundle, files) = synthetic_bundle();
        for member in &mut bundle.members {
            if member.name == "tls_evidence" {
                member.relative_path = "evidence/iat_evidence.json".to_string();
            }
        }
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict
            .reasons
            .iter()
            .any(|r| r.contains("duplicate relative_path")));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let (bundle, _files) = synthetic_bundle();
        let value = serde_json::to_value(&bundle).expect("bundle serializes to JSON");
        let mut tampered = value.clone();
        tampered["sneaky_extra"] = serde_json::json!("x");
        assert!(
            serde_json::from_value::<OreansEvidenceBundle>(tampered).is_err(),
            "deny_unknown_fields must reject extra fields"
        );
        let _ = value;
    }
}
