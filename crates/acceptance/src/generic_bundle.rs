//! Generic, family-agnostic unpack-evidence bundle contract
//! (`mida.unpack-evidence-bundle/v1`).
//!
//! G2: GTO (family `ahk_gto`) produces and consumes evidence through this
//! generic contract so its products are never disguised as Oreans evidence.
//! The Oreans family (`oreans_themida`) keeps the legacy
//! `mida.oreans-evidence-bundle/v2` contract untouched.
//!
//! The generic bundle is the family-agnostic sibling of the Oreans v2 bundle:
//! it carries the same input/candidate identity, runner-config digest, member
//! manifest, completion marker and the two sealed canonical hashes, and adds a
//! `family_id` field that names the packer family a run belongs to.
//!
//! Consumer-side fail-closed dispatch ([`validate_unpack_bundle`] and
//! [`consume_unpack_bundle`]):
//! - a missing or empty `family_id` is rejected;
//! - an unknown generic schema version is rejected;
//! - the family must be `ahk_gto` for this generic contract (Oreans bundles
//!   belong to the Oreans consumer and are rejected here);
//! - an Oreans v2 bundle masquerading as a generic bundle (wrong
//!   `schema_version`, or `family_id` absent) is rejected;
//! - any member schema that does not match the expected family schema is
//!   rejected (no cross-family member smuggling).
//!
//! The black-box boundary is the same as the Oreans contract: this module is
//! the only authority on generic-bundle validity, and the producer
//! (`mida-cli`) never imports these consumer types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::identity::sha256_hex;
use crate::oreans_gate::{
    OREANS_IAT_EVIDENCE_SCHEMA_VERSION, OREANS_OEP_EVIDENCE_SCHEMA_VERSION,
    OREANS_RELOCATION_EVIDENCE_SCHEMA_VERSION, OREANS_SECTION_REBUILD_EVIDENCE_SCHEMA_VERSION,
    OREANS_TLS_EVIDENCE_SCHEMA_VERSION,
};
use crate::oreans_pe_evidence::OREANS_PE_EVIDENCE_SCHEMA_VERSION;

/// Schema id of the generic unpack-evidence bundle.
pub const UNPACK_EVIDENCE_BUNDLE_SCHEMA_VERSION: &str = "mida.unpack-evidence-bundle/v1";

/// The packer family allowed under the generic contract (AHK/GTO). Oreans runs
/// must NOT use the generic contract — they keep `mida.oreans-evidence-bundle/v2`.
pub const GENERIC_PACKER_FAMILY: &str = "ahk_gto";
/// The Oreans family id (rejected by this generic consumer).
pub const OREANS_PACKER_FAMILY: &str = "oreans_themida";

/// Schema id of the bound transform manifest written next to a candidate.
pub const TRANSFORM_MANIFEST_SCHEMA_VERSION: &str = "mida.transform-manifest/v0";

/// Logical member names required for a generic bundle to be a complete valid
/// run, with their expected sidecar schema ids. These are the same
/// family-agnostic sidecars the Oreans contract binds; the generic bundle
/// manifests them under a family-agnostic envelope and a `family_id`.
pub const REQUIRED_UNPACK_MEMBERS: [(&str, &str); 7] = [
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

/// Fixed identity of one input or output artifact inside a generic bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnpackArtifactIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

/// A member file declared by the generic bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnpackMemberRef {
    pub name: String,
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// Completion state of a run. Only `complete` may yield a valid generic bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UnpackCompletionMarker {
    Complete,
    Partial { reason: String },
}

/// Generic unpack-evidence bundle manifest (`mida.unpack-evidence-bundle/v1`).
///
/// `deny_unknown_fields` is enforced: an Oreans v2 bundle cannot deserialize
/// into this type (it lacks `family_id` and carries the v2 schema id), and a
/// generic bundle cannot deserialize into `OreansEvidenceBundle`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnpackEvidenceBundle {
    pub schema_version: String,
    /// Packer family this run belongs to (must be `ahk_gto` for this contract).
    pub family_id: String,
    pub case_id: String,
    pub tool_revision: String,
    pub runner_config_digest: String,
    pub emitted_at: String,
    pub completion_marker: UnpackCompletionMarker,
    pub protected_input: UnpackArtifactIdentity,
    pub candidate: UnpackArtifactIdentity,
    pub members_sha256: String,
    pub manifest_sha256: String,
    pub members: Vec<UnpackMemberRef>,
}

/// Fail-closed result of generic-bundle validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackBundleVerdict {
    pub valid: bool,
    pub complete: bool,
    pub reasons: Vec<String>,
}

impl UnpackBundleVerdict {
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
pub fn canonical_members_hash(members: &[UnpackMemberRef]) -> String {
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

fn member_line(m: &UnpackMemberRef) -> String {
    format!(
        "member={}:{}:{}:{}",
        m.name,
        m.relative_path,
        m.sha256.to_lowercase(),
        m.size_bytes
    )
}

/// Canonical full-manifest hash. Covers every top-level field (including
/// `family_id`) and every member field except `manifest_sha256` itself.
pub fn canonical_manifest_hash(bundle: &UnpackEvidenceBundle) -> String {
    let mut canonical = String::new();
    canonical.push_str(&format!("schema_version={}\n", bundle.schema_version));
    canonical.push_str(&format!("family_id={}\n", bundle.family_id));
    canonical.push_str(&format!("case_id={}\n", bundle.case_id));
    canonical.push_str(&format!("tool_revision={}\n", bundle.tool_revision));
    canonical.push_str(&format!(
        "runner_config_digest={}\n",
        bundle.runner_config_digest
    ));
    canonical.push_str(&format!("emitted_at={}\n", bundle.emitted_at));
    canonical.push_str(&match &bundle.completion_marker {
        UnpackCompletionMarker::Complete => "completion_marker=complete\n".to_string(),
        UnpackCompletionMarker::Partial { reason } => {
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

fn validate_plain_field(value: &str, field: &str, allow_colon: bool, reasons: &mut Vec<String>) {
    for c in value.chars() {
        if c == '|' || c == '=' {
            reasons.push(format!(
                "{field} must not contain the canonical-hash separator {c:?}"
            ));
            return;
        }
        if !allow_colon && c == ':' {
            reasons.push(format!(
                "{field} must not contain the canonical-hash separator ':'"
            ));
            return;
        }
        if c.is_control() {
            reasons.push(format!("{field} must not contain control character {c:?}"));
            return;
        }
    }
}

fn normalize_relative_path(path: &str) -> Result<String, String> {
    if path.trim().is_empty() {
        return Err("relative_path must be non-empty".to_string());
    }
    if path.contains(':') {
        return Err(format!("relative_path {path:?} must not contain ':'"));
    }
    if path.contains('|') || path.contains('=') {
        return Err(format!(
            "relative_path {path:?} must not contain canonical-hash separators"
        ));
    }
    if path.chars().any(char::is_control) {
        return Err(format!(
            "relative_path {path:?} must not contain control characters"
        ));
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

/// Validate the embedded candidate/protected identity of a sidecar against the
/// bundle identities (identity-chain sealing).
fn check_sidecar_identity(
    name: &str,
    value: &serde_json::Value,
    bundle: &UnpackEvidenceBundle,
    require_protected: bool,
    reasons: &mut Vec<String>,
) {
    if name == "transform_manifest" {
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
        return;
    }
    let candidate = value.get("candidate").and_then(|c| c.get("sha256"));
    let candidate_size = value.get("candidate").and_then(|c| c.get("size_bytes"));
    if candidate.and_then(|s| s.as_str()) != Some(bundle.candidate.sha256.to_lowercase().as_str())
        || candidate_size.and_then(|s| s.as_u64()) != Some(bundle.candidate.size_bytes)
    {
        reasons.push(format!(
            "member {name} candidate identity does not match bundle"
        ));
    }
    if require_protected {
        let protected = value.get("protected_input").and_then(|p| p.get("sha256"));
        let protected_size = value
            .get("protected_input")
            .and_then(|p| p.get("size_bytes"));
        if protected.and_then(|s| s.as_str())
            != Some(bundle.protected_input.sha256.to_lowercase().as_str())
            || protected_size.and_then(|s| s.as_u64()) != Some(bundle.protected_input.size_bytes)
        {
            reasons.push(format!(
                "member {name} protected_input identity does not match bundle"
            ));
        }
    }
}

/// Fail-closed validation of a generic bundle. `files` maps logical member name
/// to raw bytes. Rejects: wrong schema, missing/invalid `family_id`, non-GTO
/// family, unknown member schemas, missing/tampered members, mismatched
/// embedded identities, partial markers, and canonical-hash mismatch.
pub fn validate_unpack_bundle(
    bundle: &UnpackEvidenceBundle,
    files: &BTreeMap<String, Vec<u8>>,
) -> UnpackBundleVerdict {
    let mut reasons = Vec::new();

    if bundle.schema_version != UNPACK_EVIDENCE_BUNDLE_SCHEMA_VERSION {
        return UnpackBundleVerdict::invalid(format!(
            "unexpected generic bundle schema {} (expected {})",
            bundle.schema_version, UNPACK_EVIDENCE_BUNDLE_SCHEMA_VERSION
        ));
    }
    if bundle.family_id.trim().is_empty() {
        return UnpackBundleVerdict::invalid("family_id is missing or empty; refuse (fail-closed)");
    }
    if bundle.family_id != GENERIC_PACKER_FAMILY {
        return UnpackBundleVerdict::invalid(format!(
            "family_id {:?} is not the generic GTO family {:?}; \
             Oreans evidence belongs to the Oreans consumer",
            bundle.family_id, GENERIC_PACKER_FAMILY
        ));
    }
    validate_plain_field(&bundle.family_id, "family_id", false, &mut reasons);

    if bundle.runner_config_digest.is_empty() || !is_64_hex(&bundle.runner_config_digest) {
        reasons.push(format!(
            "runner_config_digest must be exactly 64 hex chars, got {:?}",
            bundle.runner_config_digest
        ));
    }
    if bundle.case_id.trim().is_empty() {
        reasons.push("case_id must be non-empty".to_string());
    } else {
        validate_plain_field(&bundle.case_id, "case_id", false, &mut reasons);
    }
    if bundle.tool_revision.trim().is_empty() {
        reasons.push("tool_revision must be non-empty".to_string());
    } else {
        validate_plain_field(&bundle.tool_revision, "tool_revision", false, &mut reasons);
    }
    if bundle.emitted_at.trim().is_empty() {
        reasons.push("emitted_at must be non-empty".to_string());
    } else {
        validate_plain_field(&bundle.emitted_at, "emitted_at", true, &mut reasons);
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

    let mut seen_names = std::collections::HashSet::new();
    let mut seen_paths = std::collections::HashSet::new();
    for member in &bundle.members {
        if !seen_names.insert(member.name.clone()) {
            reasons.push(format!("duplicate member name {}", member.name));
        }
        validate_plain_field(&member.name, "member name", false, &mut reasons);
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

    for (required_name, expected_schema) in REQUIRED_UNPACK_MEMBERS {
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
                    let require_protected =
                        !matches!(required_name, "pe_evidence" | "transform_manifest");
                    check_sidecar_identity(
                        required_name,
                        &value,
                        bundle,
                        require_protected,
                        &mut reasons,
                    );
                }
                Err(e) => reasons.push(format!("member {} is not valid JSON: {e}", required_name)),
            }
        }
    }

    match &bundle.completion_marker {
        UnpackCompletionMarker::Partial { reason } => {
            reasons.push(format!("completion_marker is partial: {reason}"));
        }
        UnpackCompletionMarker::Complete => {}
    }

    if reasons.is_empty() {
        UnpackBundleVerdict::ok()
    } else {
        UnpackBundleVerdict {
            valid: false,
            complete: false,
            reasons,
        }
    }
}

/// High-level fail-closed family dispatch for a raw bundle manifest. Returns
/// a descriptive reason on any rejection and `Ok` only when the bundle is a
/// valid GTO-family generic bundle. This is the seam a consumer uses to route
/// evidence by family; it never falls through to a wrong-family gate.
pub fn consume_unpack_bundle(
    bundle: &UnpackEvidenceBundle,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let verdict = validate_unpack_bundle(bundle, files);
    if !verdict.valid {
        return Err(format!("generic bundle rejected: {:?}", verdict.reasons));
    }
    if bundle.completion_marker != UnpackCompletionMarker::Complete {
        return Err("generic bundle is not complete".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sidecar(schema: &str, protected_sha: &str, candidate_sha: &str) -> Vec<u8> {
        serde_json::json!({
            "schema_version": schema,
            "protected_input": { "sha256": protected_sha, "size_bytes": 10 },
            "candidate": { "sha256": candidate_sha, "size_bytes": 20 },
        })
        .to_string()
        .into_bytes()
    }

    fn pe_evidence(candidate_sha: &str) -> Vec<u8> {
        serde_json::json!({
            "schema_version": OREANS_PE_EVIDENCE_SCHEMA_VERSION,
            "candidate": { "sha256": candidate_sha, "size_bytes": 20 },
        })
        .to_string()
        .into_bytes()
    }

    fn transform(candidate_sha: &str) -> Vec<u8> {
        serde_json::json!({
            "schema_version": TRANSFORM_MANIFEST_SCHEMA_VERSION,
            "taxonomy_version": "mida.transform-taxonomy/v1",
            "candidate_sha256": candidate_sha,
            "candidate_size_bytes": 20,
            "entries": [],
        })
        .to_string()
        .into_bytes()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        crate::identity::sha256_hex(bytes)
    }

    fn files_for(bundle: &UnpackEvidenceBundle) -> BTreeMap<String, Vec<u8>> {
        member_bytes_for(bundle)
    }

    /// Build the byte payload for each required member, using the correct
    /// expected schema and the bundle's embedded identities.
    fn member_bytes_for(bundle: &UnpackEvidenceBundle) -> BTreeMap<String, Vec<u8>> {
        let protected_sha = &bundle.protected_input.sha256;
        let candidate_sha = &bundle.candidate.sha256;
        let mut files = BTreeMap::new();
        for (name, schema) in REQUIRED_UNPACK_MEMBERS {
            let bytes = match name {
                "transform_manifest" => transform(candidate_sha),
                "pe_evidence" => pe_evidence(candidate_sha),
                _ => sidecar(schema, protected_sha, candidate_sha),
            };
            files.insert(name.to_string(), bytes);
        }
        files
    }

    fn complete_gto_bundle() -> UnpackEvidenceBundle {
        let protected_sha = sha256_hex(b"PROTECTED");
        let candidate_sha = sha256_hex(b"CANDIDATE");
        let mut bundle = UnpackEvidenceBundle {
            schema_version: UNPACK_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
            family_id: GENERIC_PACKER_FAMILY.to_string(),
            case_id: "gto_launcher".to_string(),
            tool_revision: "oreans/two-sample-mainline@test".to_string(),
            runner_config_digest: "ab12".repeat(16),
            emitted_at: "2026-08-04T12:00:00Z".to_string(),
            completion_marker: UnpackCompletionMarker::Complete,
            protected_input: UnpackArtifactIdentity {
                sha256: protected_sha.clone(),
                size_bytes: 10,
            },
            candidate: UnpackArtifactIdentity {
                sha256: candidate_sha.clone(),
                size_bytes: 20,
            },
            members_sha256: String::new(),
            manifest_sha256: String::new(),
            members: Vec::new(),
        };
        // Build members to match the fixture files exactly (same schema bytes).
        let payloads = member_bytes_for(&bundle);
        let mut members = Vec::new();
        for (name, _schema) in REQUIRED_UNPACK_MEMBERS {
            let bytes = payloads.get(name).expect("member payload").clone();
            members.push(UnpackMemberRef {
                name: name.to_string(),
                relative_path: format!("evidence/{name}.json"),
                sha256: sha256_hex(&bytes),
                size_bytes: bytes.len() as u64,
            });
        }
        bundle.members = members;
        bundle.members_sha256 = canonical_members_hash(&bundle.members);
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
        bundle
    }

    #[test]
    fn gto_round_trip_is_valid_and_complete() {
        let bundle = complete_gto_bundle();
        let files = files_for(&bundle);
        let verdict = validate_unpack_bundle(&bundle, &files);
        assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
        assert!(verdict.complete);
        assert!(consume_unpack_bundle(&bundle, &files).is_ok());
    }

    #[test]
    fn missing_family_id_fails_closed() {
        let mut bundle = complete_gto_bundle();
        bundle.family_id = String::new();
        let files = files_for(&bundle);
        let verdict = validate_unpack_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(
            verdict.reasons.iter().any(|r| r.contains("family_id")),
            "reasons: {:?}",
            verdict.reasons
        );
        assert!(consume_unpack_bundle(&bundle, &files).is_err());
    }

    #[test]
    fn oreans_family_in_generic_contract_fails_closed() {
        let mut bundle = complete_gto_bundle();
        bundle.family_id = OREANS_PACKER_FAMILY.to_string();
        let files = files_for(&bundle);
        let verdict = validate_unpack_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(
            verdict.reasons.iter().any(|r| r.contains("family_id")),
            "reasons: {:?}",
            verdict.reasons
        );
    }

    #[test]
    fn unknown_generic_schema_fails_closed() {
        let mut bundle = complete_gto_bundle();
        bundle.schema_version = "mida.unpack-evidence-bundle/v99".to_string();
        let files = files_for(&bundle);
        let verdict = validate_unpack_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict.reasons.iter().any(|r| r.contains("schema")));
    }

    #[test]
    fn oreans_v2_bundle_cannot_deserialize_as_generic() {
        // An Oreans v2 bundle (no family_id, v2 schema) must fail to even parse
        // as a generic bundle: family_id is required and deny_unknown_fields is
        // on, so a v2 manifest is never a generic manifest.
        let json = serde_json::json!({
            "schema_version": "mida.oreans-evidence-bundle/v2",
            "case_id": "origin_macro",
            "tool_revision": "rev",
            "runner_config_digest": "ab12".repeat(16),
            "emitted_at": "2026-08-04T12:00:00Z",
            "completion_marker": { "state": "complete" },
            "protected_input": { "sha256": "a".repeat(64), "size_bytes": 10 },
            "candidate": { "sha256": "b".repeat(64), "size_bytes": 20 },
            "members_sha256": "c".repeat(64),
            "manifest_sha256": "d".repeat(64),
            "members": [],
        });
        assert!(
            serde_json::from_value::<UnpackEvidenceBundle>(json).is_err(),
            "an Oreans v2 manifest must not parse as a generic bundle"
        );
    }

    #[test]
    fn wrong_member_schema_fails_closed() {
        let bundle = complete_gto_bundle();
        let mut files = files_for(&bundle);
        // Sneak an Oreans-only schema under the iat_evidence member name.
        files.insert(
            "iat_evidence".to_string(),
            sidecar(
                "mida.oreans-iat-evidence/v9",
                &bundle.protected_input.sha256,
                &bundle.candidate.sha256,
            ),
        );
        let verdict = validate_unpack_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(
            verdict.reasons.iter().any(|r| r.contains("schema_version")),
            "reasons: {:?}",
            verdict.reasons
        );
    }

    #[test]
    fn partial_marker_fails_closed() {
        let mut bundle = complete_gto_bundle();
        bundle.completion_marker = UnpackCompletionMarker::Partial {
            reason: "interrupted".to_string(),
        };
        // Recompute manifest hash for the partial marker so the only failure is
        // the marker itself.
        bundle.manifest_sha256 = canonical_manifest_hash(&bundle);
        let files = files_for(&bundle);
        let verdict = validate_unpack_bundle(&bundle, &files);
        assert!(!verdict.valid);
        assert!(verdict.reasons.iter().any(|r| r.contains("partial")));
        assert!(consume_unpack_bundle(&bundle, &files).is_err());
    }
}
