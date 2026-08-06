//! Generic (family-agnostic) evidence-bundle assembler — producer side of
//! `mida.unpack-evidence-bundle/v1`.
//!
//! G2: GTO (`ahk_gto`) products are recorded through this generic contract so
//! they are never disguised as Oreans evidence. The Oreans family keeps the
//! legacy `mida.oreans-evidence-bundle/v2` assembler.
//!
//! This module is the producer half of the black-box generic contract: it
//! implements its own copy of the canonical hash forms and the field
//! constraints, and must never import consumer types from `mida-acceptance`.
//! The consumer (`mida_acceptance::validate_unpack_bundle`) is the only
//! authority on generic-bundle validity.
//!
//! Fail-closed rules (same as the Oreans assembler, plus family binding):
//! - the `family_id` is never caller-supplied — it comes exclusively from the
//!   attested [`crate::runner_preflight::RunEvidenceContext`] (which carries
//!   the family the launch attestation bound);
//! - `runner_config_digest` is exactly 64 hexadecimal characters;
//! - free-text fields reject control characters and the canonical-hash
//!   separators `|`/`=` (identifiers also `:`);
//! - the protected input and the candidate are re-read from disk and their
//!   SHA-256/size bound into the manifest;
//! - every required member is present exactly once, its path is unique, its
//!   JSON top-level `schema_version` matches the expected schema, and its
//!   embedded identities match the re-read artifacts;
//! - the manifest is written atomically (temp file + fsync + rename).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::iat_evidence::same_file;
use super::sidecar_io::atomic_write;

/// Schema id of the emitted generic manifest (producer-side copy).
pub const GENERIC_BUNDLE_SCHEMA_VERSION: &str = "mida.unpack-evidence-bundle/v1";

/// Schema id of the bound transform manifest.
pub const TRANSFORM_MANIFEST_SCHEMA_VERSION: &str = "mida.transform-manifest/v0";

/// Logical member names and their expected sidecar schema ids (the
/// family-agnostic sidecars shared with the Oreans contract).
pub const EXPECTED_MEMBER_SCHEMAS: [(&str, &str); 7] = [
    ("oep_evidence", "mida.oreans-oep-evidence/v1"),
    ("iat_evidence", "mida.oreans-iat-evidence/v1"),
    ("tls_evidence", "mida.oreans-tls-evidence/v1"),
    ("relocation_evidence", "mida.oreans-relocation-evidence/v1"),
    (
        "section_rebuild_evidence",
        "mida.oreans-section-rebuild-evidence/v1",
    ),
    ("pe_evidence", "mida.oreans-pe-evidence/v1"),
    ("transform_manifest", TRANSFORM_MANIFEST_SCHEMA_VERSION),
];

/// Fixed identity of one input/output artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleArtifactIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

/// Completion state — the assembler only ever emits `Complete`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum BundleCompletionMarker {
    Complete,
}

/// One member file reference in the emitted manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BundleMemberRef {
    pub name: String,
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

/// The emitted generic manifest (producer-side copy of the v1 contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenericEvidenceBundleManifest {
    pub schema_version: String,
    pub family_id: String,
    pub case_id: String,
    pub tool_revision: String,
    pub runner_config_digest: String,
    pub emitted_at: String,
    pub completion_marker: BundleCompletionMarker,
    pub protected_input: BundleArtifactIdentity,
    pub candidate: BundleArtifactIdentity,
    pub members_sha256: String,
    pub manifest_sha256: String,
    pub members: Vec<BundleMemberRef>,
}

/// Inputs for one generic bundle assemble. `family_id`, `case_id`,
/// `tool_revision` and `runner_config_digest` are NOT caller-supplied — they
/// come exclusively from the attested
/// [`crate::runner_preflight::RunEvidenceContext`].
#[derive(Debug, Clone)]
pub struct AssembleRequest {
    pub emitted_at: String,
    pub protected_input: PathBuf,
    pub candidate: PathBuf,
    /// Logical member name -> evidence file path.
    pub members: Vec<(String, PathBuf)>,
    /// Destination for the bundle manifest (written atomically).
    pub output: PathBuf,
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Producer-side copy of the canonical member-set hash.
fn canonical_members_hash(members: &[BundleMemberRef]) -> String {
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

/// Producer-side copy of the canonical full-manifest hash (covers `family_id`).
fn canonical_manifest_hash(bundle: &GenericEvidenceBundleManifest) -> String {
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
    canonical.push_str("completion_marker=complete\n");
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
    let mut lines: Vec<String> = bundle
        .members
        .iter()
        .map(|m| {
            format!(
                "member={}:{}:{}:{}",
                m.name,
                m.relative_path,
                m.sha256.to_lowercase(),
                m.size_bytes
            )
        })
        .collect();
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

fn validate_plain_field(value: &str, field: &str, allow_colon: bool) -> anyhow::Result<()> {
    for c in value.chars() {
        if c == '|' || c == '=' {
            bail!("{field} must not contain the canonical-hash separator {c:?}");
        }
        if !allow_colon && c == ':' {
            bail!("{field} must not contain the canonical-hash separator ':'");
        }
        if c.is_control() {
            bail!("{field} must not contain control character {c:?}");
        }
    }
    Ok(())
}

fn artifact_identity(path: &Path, label: &str) -> anyhow::Result<(String, u64)> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "read {label} for generic bundle assemble: {}",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        bail!(
            "{label} {} is empty; refusing to assemble a generic bundle around it",
            path.display()
        );
    }
    let digest = sha256_hex(&bytes);
    Ok((digest, bytes.len() as u64))
}

fn identity_from(value: &serde_json::Value, field: &str) -> Option<(String, u64)> {
    let object = value.get(field)?;
    let sha = object.get("sha256")?.as_str()?;
    let size = object.get("size_bytes")?.as_u64()?;
    Some((sha.to_string(), size))
}

fn embedded_candidate_identity(
    name: &str,
    value: &serde_json::Value,
) -> Option<(String, Option<u64>)> {
    if name == "transform_manifest" {
        let sha = value
            .get("candidate_sha256")
            .and_then(|v| v.as_str())?
            .to_lowercase();
        let size = value.get("candidate_size_bytes").and_then(|v| v.as_u64());
        Some((sha, size))
    } else {
        identity_from(value, "candidate").map(|(s, z)| (s.to_lowercase(), Some(z)))
    }
}

fn check_embedded_identity(
    name: &str,
    value: &serde_json::Value,
    protected: Option<&(String, u64)>,
    candidate: &(String, u64),
) -> anyhow::Result<()> {
    let (candidate_sha, candidate_size) = candidate;
    match embedded_candidate_identity(name, value) {
        Some((sha, size)) => {
            if sha != candidate_sha.to_lowercase() || size != Some(*candidate_size) {
                bail!(
                    "member {name} embeds candidate {sha}/{size:?} but the candidate file is {}/{}",
                    candidate_sha.to_lowercase(),
                    candidate_size
                );
            }
        }
        None => bail!("member {name} is missing a candidate identity"),
    }
    if let Some((protected_sha, protected_size)) = protected {
        match identity_from(value, "protected_input") {
            Some((sha, size)) => {
                if sha.to_lowercase() != protected_sha.to_lowercase() || size != *protected_size {
                    bail!(
                        "member {name} embeds protected_input {}/{} but the protected input file is {}/{}",
                        sha.to_lowercase(),
                        size,
                        protected_sha.to_lowercase(),
                        protected_size
                    );
                }
            }
            None => bail!("member {name} is missing a protected_input identity"),
        }
    }
    Ok(())
}

/// Assemble the generic bundle manifest for one GTO-family run and write it
/// atomically. `family_id`, `case_id`, `tool_revision` and the runner-config
/// digest come exclusively from `context` (the attested evidence context).
///
/// `context` is consumed BY VALUE (single-use authorization).
pub fn assemble_generic_evidence_bundle(
    request: &AssembleRequest,
    context: crate::runner_preflight::RunEvidenceContext,
) -> anyhow::Result<PathBuf> {
    let family_id = context.packer_family().to_string();
    let case_id = context.case_id().to_string();
    let tool_revision = context.tool_revision().to_string();
    let runner_config_digest = context.runner_config_digest().to_string();
    validate_plain_field(&family_id, "family_id", false)?;
    validate_plain_field(&case_id, "case_id", false)?;
    validate_plain_field(&tool_revision, "tool_revision", false)?;
    validate_plain_field(&request.emitted_at, "emitted_at", true)?;
    if family_id.trim().is_empty() {
        bail!("family_id must be non-empty");
    }
    if case_id.trim().is_empty() {
        bail!("case_id must be non-empty");
    }
    if tool_revision.trim().is_empty() {
        bail!("tool_revision must be non-empty");
    }
    if request.emitted_at.trim().is_empty() {
        bail!("emitted_at must be non-empty");
    }
    if !is_64_hex(&runner_config_digest) {
        bail!(
            "runner_config_digest must be exactly 64 hex chars, got {:?}",
            runner_config_digest
        );
    }

    let (protected_sha, protected_size) =
        artifact_identity(&request.protected_input, "protected input")?;
    let (candidate_sha, candidate_size) = artifact_identity(&request.candidate, "candidate")?;

    let mut names = BTreeSet::new();
    for (name, _path) in &request.members {
        validate_plain_field(name, "member name", false)?;
        if !names.insert(name.clone()) {
            bail!("duplicate member name {name}");
        }
    }
    let required: BTreeSet<&str> = EXPECTED_MEMBER_SCHEMAS.iter().map(|(n, _)| *n).collect();
    let provided: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    if provided != required {
        let missing: Vec<&str> = required.difference(&provided).copied().collect();
        let extra: Vec<&str> = provided.difference(&required).copied().collect();
        bail!("member set mismatch: missing {missing:?}, unexpected {extra:?}");
    }

    for i in 0..request.members.len() {
        for j in (i + 1)..request.members.len() {
            if same_file(&request.members[i].1, &request.members[j].1)? {
                bail!(
                    "members {} and {} resolve to the same file ({})",
                    request.members[i].0,
                    request.members[j].0,
                    request.members[j].1.display()
                );
            }
        }
    }

    let mut members = Vec::with_capacity(request.members.len());
    for (name, path) in &request.members {
        let bytes = fs::read(path)
            .with_context(|| format!("read member {name} from {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("member {name} is not valid JSON"))?;
        let expected_schema = EXPECTED_MEMBER_SCHEMAS
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| *s)
            .expect("member name validated against required set");
        let actual_schema = value.get("schema_version").and_then(|v| v.as_str());
        if actual_schema != Some(expected_schema) {
            bail!("member {name} schema_version {actual_schema:?} != expected {expected_schema}");
        }
        let protected = match name.as_str() {
            "pe_evidence" | "transform_manifest" => None,
            _ => Some((protected_sha.clone(), protected_size)),
        };
        check_embedded_identity(
            name,
            &value,
            protected.as_ref(),
            &(candidate_sha.clone(), candidate_size),
        )?;

        let file_name = path
            .file_name()
            .ok_or_else(|| anyhow!("member path {} has no file name", path.display()))?
            .to_string_lossy()
            .to_string();
        validate_plain_field(&file_name, "relative_path", false)?;
        if file_name.trim().is_empty() || file_name == "." || file_name == ".." {
            bail!("member {name} file name {file_name:?} is not usable as relative_path");
        }
        members.push(BundleMemberRef {
            name: name.clone(),
            relative_path: file_name,
            sha256: sha256_hex(&bytes),
            size_bytes: bytes.len() as u64,
        });
    }

    let members_sha256 = canonical_members_hash(&members);
    let mut manifest = GenericEvidenceBundleManifest {
        schema_version: GENERIC_BUNDLE_SCHEMA_VERSION.to_string(),
        family_id,
        case_id,
        tool_revision,
        runner_config_digest,
        emitted_at: request.emitted_at.clone(),
        completion_marker: BundleCompletionMarker::Complete,
        protected_input: BundleArtifactIdentity {
            sha256: protected_sha,
            size_bytes: protected_size,
        },
        candidate: BundleArtifactIdentity {
            sha256: candidate_sha,
            size_bytes: candidate_size,
        },
        members_sha256,
        manifest_sha256: String::new(),
        members,
    };
    manifest.manifest_sha256 = canonical_manifest_hash(&manifest);

    let json = serde_json::to_vec_pretty(&manifest).context("serialize generic bundle manifest")?;
    atomic_write(&request.output, &json)
        .with_context(|| format!("write generic bundle manifest {}", request.output.display()))?;
    Ok(request.output.clone())
}
