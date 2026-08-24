//! Atomic evidence-bundle assembler — producer side of
//! `mida.oreans-evidence-bundle/v2` (see `docs/VNEXT_EVIDENCE_BUNDLE_V1.md`).
//!
//! Aggregates the transform manifest, the structured PE evidence and the five
//! candidate-bound sidecars into one sealed bundle manifest written
//! atomically next to the evidence files.
//!
//! This module is the producer half of the black-box contract: it implements
//! its own copy of the canonical hash forms and the field constraints, and
//! must never import consumer types from `mida-acceptance`. The consumer
//! (`mida_acceptance::validate_evidence_bundle`) is the only authority on
//! bundle validity; the integration tests feed the assembler output to the
//! consumer to prove the wire contract.
//!
//! Fail-closed rules enforced here, before anything is written:
//! - `runner_config_digest` is exactly 64 hexadecimal characters;
//! - free-text fields reject control characters and the canonical-hash
//!   separators `|`/`=` (identifiers also `:`);
//! - the protected input and the candidate are re-read from disk and their
//!   SHA-256/size bound into the manifest;
//! - every required member is present exactly once, its path is unique, its
//!   JSON top-level `schema_version` matches the expected schema, and its
//!   embedded `protected_input`/`candidate` identities match the re-read
//!   artifacts (stale sidecars abort the assemble);
//! - the manifest is written via [`super::sidecar_io::atomic_write`]: a
//!   temp file is synced and atomically renamed into place, so an
//!   interrupted run can never leave a half-written bundle at the output
//!   path, and a leftover `.tmp-*` file is never a valid bundle.
//!
//! A partial bundle is never produced: missing members abort the assemble
//! with an error instead of emitting a `partial` marker.
//!
//! P6.3-D: the manifest's `runner_config_digest`, `case_id` and
//! `tool_revision` are never caller-supplied — they come exclusively from
//! the attested single-use [`crate::runner_preflight::RunEvidenceContext`]
//! produced by the launch attestation, and the assemble consumes it
//! (one-time authorization). The production chain is:
//!
//! ```text
//! launch attestation -> RunEvidenceContext -> sidecar producers
//! -> atomic bundle assembler -> v8 gate consumer
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::iat_evidence::same_file;
use super::sidecar_io::atomic_write;

/// Schema id of the emitted manifest (producer-side copy of the contract).
pub const BUNDLE_SCHEMA_VERSION: &str = "mida.oreans-evidence-bundle/v2";

/// Schema id of the bound transform manifest.
pub const TRANSFORM_MANIFEST_SCHEMA_VERSION: &str = "mida.transform-manifest/v0";

/// Logical member names and their expected sidecar schema ids.
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

/// The emitted manifest (producer-side copy of the v2 contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OreansEvidenceBundleManifest {
    pub schema_version: String,
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

/// Inputs for one bundle assemble.
///
/// P6.3-D: `case_id`, `tool_revision` and `runner_config_digest` are NOT
/// caller-supplied — they come exclusively from the attested
/// [`crate::runner_preflight::RunEvidenceContext`] passed alongside the
/// request, which is single-use (consumed by the assemble).
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

/// Producer-side copy of the canonical member-set hash (sorted
/// `name|sha256|size\n` lines).
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

/// Producer-side copy of the canonical full-manifest hash.
fn canonical_manifest_hash(bundle: &OreansEvidenceBundleManifest) -> String {
    let mut canonical = String::new();
    canonical.push_str(&format!("schema_version={}\n", bundle.schema_version));
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

/// Producer-side copy of the free-text field constraints.
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

/// Re-read one artifact and bind its identity. Fails closed on unreadable
/// files, zero-size files, or non-64-hex digests (the latter cannot happen
/// with SHA-256 but keeps the contract explicit).
fn artifact_identity(path: &Path, label: &str) -> anyhow::Result<(String, u64)> {
    let bytes = fs::read(path)
        .with_context(|| format!("read {label} for bundle assemble: {}", path.display()))?;
    if bytes.is_empty() {
        bail!(
            "{label} {} is empty; refusing to assemble a bundle around it",
            path.display()
        );
    }
    let digest = sha256_hex(&bytes);
    Ok((digest, bytes.len() as u64))
}

/// Extract `{sha256, size_bytes}` from a JSON object field.
fn identity_from(value: &serde_json::Value, field: &str) -> Option<(String, u64)> {
    let object = value.get(field)?;
    let sha = object.get("sha256")?.as_str()?;
    let size = object.get("size_bytes")?.as_u64()?;
    Some((sha.to_string(), size))
}

/// Extract the candidate identity embedded in a sidecar: object form
/// (`candidate: {sha256, size_bytes}`) for structured sidecars, flat form
/// (`candidate_sha256` + `candidate_size_bytes`) for the transform manifest.
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

/// Producer-side identity pre-check: the sidecar's embedded identities must
/// match the artifacts this bundle is being assembled around.
///
/// `protected` is `None` for `pe_evidence` (candidate-only binding) and the
/// transform manifest (flat fields).
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

/// Assemble the bundle manifest for one run and write it atomically.
///
/// P6.3-D: the runner-config digest, case id and tool revision come
/// exclusively from `context` (the attested evidence context); no
/// caller-supplied digest is accepted.
///
/// P6.3.1: `context` is consumed BY VALUE — the type is not `Clone` and has
/// no public constructor, so one attestation authorizes exactly one bundle
/// (a second assemble is a compile error, not a runtime concern).
///
/// Returns the output path on success. On any failure nothing is written to
/// the output path (a leftover `.tmp-*` file may exist and is harmless).
pub fn assemble_evidence_bundle(
    request: &AssembleRequest,
    context: crate::runner_preflight::RunEvidenceContext,
) -> anyhow::Result<PathBuf> {
    let case_id = context.case_id().to_string();
    let tool_revision = context.tool_revision().to_string();
    let runner_config_digest = context.runner_config_digest().to_string();
    validate_plain_field(&case_id, "case_id", false)?;
    validate_plain_field(&tool_revision, "tool_revision", false)?;
    validate_plain_field(&request.emitted_at, "emitted_at", true)?;
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

    // Member names: exactly the required set, no duplicates, no unknowns.
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

    // Paths must point at distinct physical files (hard-link/alias detection).
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

    // Read every member, verify schema + embedded identities, build refs.
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
    let mut manifest = OreansEvidenceBundleManifest {
        schema_version: BUNDLE_SCHEMA_VERSION.to_string(),
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

    let json = serde_json::to_vec_pretty(&manifest).context("serialize bundle manifest")?;
    atomic_write(&request.output, &json)
        .with_context(|| format!("write bundle manifest {}", request.output.display()))?;
    Ok(request.output.clone())
}

#[cfg(test)]
mod tests {
    //! Unit tests for the atomic bundle assembler (producer), validated by
    //! the independent consumer `mida_acceptance::validate_evidence_bundle`.
    //! These live in the crate so they can construct a sealed
    //! `RunEvidenceContext` (crate-private `new`) and exercise the by-value
    //! ownership consume (P6.3.1): one attestation authorizes exactly one
    //! bundle — a second assemble is a compile error.

    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use mida_acceptance::{
        validate_evidence_bundle, BundleCompletionMarker, OreansEvidenceBundle,
        OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION,
    };
    use sha2::{Digest, Sha256};

    use crate::runner_preflight::RunEvidenceContext;
    use crate::unpacker::bundle_assembler::{
        assemble_evidence_bundle, AssembleRequest, EXPECTED_MEMBER_SCHEMAS,
        TRANSFORM_MANIFEST_SCHEMA_VERSION,
    };

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        let mut out = String::with_capacity(64);
        for byte in digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "mida_bundle_test_{}_{}_{}",
            tag,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Build a synthetic run directory: protected input, candidate, and the
    /// seven evidence files with correct schema ids and embedded identities.
    struct RunDir {
        root: PathBuf,
        protected: PathBuf,
        candidate: PathBuf,
        members: Vec<(String, PathBuf)>,
        protected_sha: String,
        candidate_sha: String,
    }

    fn sidecar_json(
        schema: &str,
        protected_sha: &str,
        protected_size: u64,
        candidate_sha: &str,
        candidate_size: u64,
    ) -> Vec<u8> {
        serde_json::json!({
            "schema_version": schema,
            "protected_input": { "sha256": protected_sha, "size_bytes": protected_size },
            "candidate": { "sha256": candidate_sha, "size_bytes": candidate_size },
        })
        .to_string()
        .into_bytes()
    }

    fn pe_evidence_json(candidate_sha: &str, candidate_size: u64) -> Vec<u8> {
        serde_json::json!({
            "schema_version": "mida.oreans-pe-evidence/v1",
            "candidate": { "sha256": candidate_sha, "size_bytes": candidate_size },
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
            "note": "synthetic bundle fixture",
        })
        .to_string()
        .into_bytes()
    }

    fn build_run_dir(tag: &str) -> RunDir {
        let root = temp_dir(tag);
        let protected = root.join("protected.bin");
        let candidate = root.join("candidate.exe");
        fs::write(&protected, b"PROTECTED-INPUT-BYTES-000").expect("write protected");
        fs::write(&candidate, b"CANDIDATE-BYTES-1234567890").expect("write candidate");
        let protected_sha = sha256_hex(&fs::read(&protected).unwrap());
        let candidate_sha = sha256_hex(&fs::read(&candidate).unwrap());
        let protected_size = fs::metadata(&protected).unwrap().len();
        let candidate_size = fs::metadata(&candidate).unwrap().len();

        let mut members = Vec::new();
        for (name, schema) in EXPECTED_MEMBER_SCHEMAS {
            let bytes = match name {
                "transform_manifest" => transform_manifest_json(&candidate_sha, candidate_size),
                "pe_evidence" => pe_evidence_json(&candidate_sha, candidate_size),
                _ => sidecar_json(
                    schema,
                    &protected_sha,
                    protected_size,
                    &candidate_sha,
                    candidate_size,
                ),
            };
            let path = root.join(format!("{name}.json"));
            fs::write(&path, bytes).expect("write sidecar");
            members.push((name.to_string(), path));
        }
        RunDir {
            root,
            protected,
            candidate,
            members,
            protected_sha,
            candidate_sha,
        }
    }

    /// A sealed evidence context (crate-private constructor, no Clone).
    fn context(run: &RunDir) -> RunEvidenceContext {
        RunEvidenceContext::new(
            "origin_macro".to_string(),
            "oreans/two-sample-mainline@test".to_string(),
            "ab12".repeat(16),
            "ef12".repeat(16), // verifier identity
            run.protected.clone(),
            run.candidate.clone(),
            "cd34".repeat(16),
            crate::runner_preflight::VerifiedTargetIdentity::from_attested(
                "origin_macro",
                &crate::runner_preflight::FileIdentityGate {
                    sha256: "ab12".repeat(16),
                    size_bytes: 4096,
                },
                "x86_64",
            )
            .expect("test target identity seals"),
        )
        .expect("build evidence context")
    }

    fn request(run: &RunDir, output: &Path) -> AssembleRequest {
        AssembleRequest {
            emitted_at: "2026-08-04T12:00:00Z".to_string(),
            protected_input: run.protected.clone(),
            candidate: run.candidate.clone(),
            members: run.members.clone(),
            output: output.to_path_buf(),
        }
    }

    fn read_bundle(path: &Path) -> OreansEvidenceBundle {
        let json = fs::read_to_string(path).expect("read bundle manifest");
        serde_json::from_str(&json).expect("parse bundle manifest")
    }

    fn files_map(run: &RunDir) -> BTreeMap<String, Vec<u8>> {
        let mut files = BTreeMap::new();
        for (name, path) in &run.members {
            files.insert(name.clone(), fs::read(path).expect("read member"));
        }
        files
    }

    #[test]
    fn assembled_bundle_is_accepted_by_independent_validator() {
        let run = build_run_dir("happy");
        let output = run.root.join("evidence.bundle.json");
        let written =
            assemble_evidence_bundle(&request(&run, &output), context(&run)).expect("assemble");
        assert_eq!(written, output);
        assert!(output.is_file());

        let bundle = read_bundle(&output);
        assert_eq!(bundle.schema_version, OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION);
        assert_eq!(bundle.completion_marker, BundleCompletionMarker::Complete);

        let files = files_map(&run);
        let verdict = validate_evidence_bundle(&bundle, &files);
        assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
        assert!(verdict.complete);

        // No leftover temp files after a successful assemble.
        let leftovers: Vec<_> = fs::read_dir(&run.root)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
    }

    #[test]
    fn missing_member_fails_closed_and_writes_nothing() {
        let run = build_run_dir("missing");
        let output = run.root.join("evidence.bundle.json");
        let mut req = request(&run, &output);
        req.members.retain(|(name, _)| name != "tls_evidence");
        let err =
            assemble_evidence_bundle(&req, context(&run)).expect_err("missing member must fail");
        assert!(err.to_string().contains("member set mismatch"));
        assert!(!output.exists(), "no bundle may be written on failure");
    }

    #[test]
    fn duplicate_member_path_fails_closed() {
        let run = build_run_dir("dup_path");
        let output = run.root.join("evidence.bundle.json");
        let mut req = request(&run, &output);
        req.members
            .push(("oep_evidence".to_string(), run.members[0].1.clone()));
        let err =
            assemble_evidence_bundle(&req, context(&run)).expect_err("duplicate name must fail");
        assert!(err.to_string().contains("duplicate member name"));
    }

    #[test]
    fn alias_member_path_fails_closed() {
        let run = build_run_dir("alias");
        let output = run.root.join("evidence.bundle.json");
        let alias = run.root.join("alias_of_iat.json");
        fs::hard_link(&run.members[1].1, &alias).expect("hard link");
        let mut req = request(&run, &output);
        for (name, path) in &mut req.members {
            if name == "tls_evidence" {
                *path = alias.clone();
            }
        }
        let err =
            assemble_evidence_bundle(&req, context(&run)).expect_err("alias member path must fail");
        assert!(err.to_string().contains("same file"));
    }

    #[test]
    fn stale_embedded_candidate_identity_fails_closed() {
        let run = build_run_dir("stale_cand");
        let output = run.root.join("evidence.bundle.json");
        let (_, path) = &run.members[1]; // iat_evidence
        let stale = sidecar_json(
            "mida.oreans-iat-evidence/v1",
            &run.protected_sha,
            fs::metadata(&run.protected).unwrap().len(),
            &"9".repeat(64),
            fs::metadata(&run.candidate).unwrap().len(),
        );
        fs::write(path, stale).expect("rewrite sidecar");
        let err = assemble_evidence_bundle(&request(&run, &output), context(&run))
            .expect_err("stale candidate identity must fail");
        assert!(err.to_string().contains("embeds candidate"));
        assert!(!output.exists());
    }

    #[test]
    fn stale_embedded_protected_identity_fails_closed() {
        let run = build_run_dir("stale_prot");
        let output = run.root.join("evidence.bundle.json");
        let (_, path) = &run.members[2]; // tls_evidence
        let stale = sidecar_json(
            "mida.oreans-tls-evidence/v1",
            &"d".repeat(64),
            1234,
            &run.candidate_sha,
            fs::metadata(&run.candidate).unwrap().len(),
        );
        fs::write(path, stale).expect("rewrite sidecar");
        let err = assemble_evidence_bundle(&request(&run, &output), context(&run))
            .expect_err("stale protected identity must fail");
        assert!(err.to_string().contains("embeds protected_input"));
        assert!(!output.exists());
    }

    #[test]
    fn schema_drift_in_member_fails_closed() {
        let run = build_run_dir("schema_drift");
        let output = run.root.join("evidence.bundle.json");
        let (_, path) = &run.members[3]; // relocation_evidence
        let drifted = sidecar_json(
            "mida.oreans-relocation-evidence/v2",
            &run.protected_sha,
            fs::metadata(&run.protected).unwrap().len(),
            &run.candidate_sha,
            fs::metadata(&run.candidate).unwrap().len(),
        );
        fs::write(path, drifted).expect("rewrite sidecar");
        let err = assemble_evidence_bundle(&request(&run, &output), context(&run))
            .expect_err("schema drift must fail");
        assert!(err.to_string().contains("schema_version"));
        assert!(!output.exists());
    }

    #[test]
    fn malformed_runner_digest_and_fields_fail_closed() {
        let run = build_run_dir("bad_fields");
        let output = run.root.join("evidence.bundle.json");
        // The digest is never caller-supplied: a malformed digest is rejected at
        // RunEvidenceContext construction (the only path into the assembler).
        assert!(
            RunEvidenceContext::new(
                "origin_macro".to_string(),
                "rev".to_string(),
                "not-hex".to_string(),
                "ef12".repeat(16),
                run.protected.clone(),
                run.candidate.clone(),
                "cd34".repeat(16),
                crate::runner_preflight::VerifiedTargetIdentity::from_attested(
                    "origin_macro",
                    &crate::runner_preflight::FileIdentityGate {
                        sha256: "ab12".repeat(16),
                        size_bytes: 4096,
                    },
                    "x86_64",
                )
                .expect("test target identity seals"),
            )
            .is_err(),
            "malformed digest must be rejected at context construction"
        );
        // A case id carrying a canonical-hash separator is rejected by the
        // assembler (the seal prevents field mutation, so a fresh context is
        // constructed with the offending case id).
        let bad = RunEvidenceContext::new(
            "origin_macro|evil".to_string(),
            "rev".to_string(),
            "ab12".repeat(16),
            "ef12".repeat(16),
            run.protected.clone(),
            run.candidate.clone(),
            "cd34".repeat(16),
            crate::runner_preflight::VerifiedTargetIdentity::from_attested(
                "origin_macro",
                &crate::runner_preflight::FileIdentityGate {
                    sha256: "ab12".repeat(16),
                    size_bytes: 4096,
                },
                "x86_64",
            )
            .expect("test target identity seals"),
        )
        .expect("separator case id passes the constructor");
        let err = assemble_evidence_bundle(&request(&run, &output), bad)
            .expect_err("separator must fail");
        assert!(
            err.to_string().contains("case_id"),
            "unexpected error: {err:?}"
        );
        assert!(!output.exists());
    }

    /// P6.3-D (#13): the bundle's runner-config digest must equal the attested
    /// launch-attestation digest carried by the sealed evidence context.
    #[test]
    fn bundle_digest_equals_attested_context_digest() {
        let run = build_run_dir("digest_chain");
        let output = run.root.join("evidence.bundle.json");
        let ctx = context(&run);
        let expected_digest = ctx.runner_config_digest().to_string();
        let written = assemble_evidence_bundle(&request(&run, &output), ctx).expect("assemble");
        let bundle = read_bundle(&written);
        assert_eq!(
            bundle.runner_config_digest, expected_digest,
            "bundle digest must equal the launch attestation digest"
        );
        assert_eq!(bundle.case_id, "origin_macro");
        assert_eq!(bundle.tool_revision, "oreans/two-sample-mainline@test");
        let verdict = validate_evidence_bundle(&bundle, &files_map(&run));
        assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
    }

    /// P6.3.1 seal proof: the context is consumed BY VALUE — holding it in an
    /// `Option` and `take()`-ing it for the assemble leaves the holder empty,
    /// so there is no way to assemble a second bundle from the same
    /// authorization (and the type is not `Clone`).
    #[test]
    fn attested_context_is_single_use_by_ownership() {
        let run = build_run_dir("single_use");
        let output = run.root.join("evidence.bundle.json");
        let mut holder = Some(context(&run));
        // The context is moved out of the holder into the assembler.
        assemble_evidence_bundle(&request(&run, &output), holder.take().unwrap())
            .expect("first assemble");
        assert!(
            holder.is_none(),
            "the attested context was moved out and cannot be reused"
        );
        // The value is gone: there is no second `context` to hand to a second
        // assemble without a fresh attestation, and `RunEvidenceContext` is
        // not `Clone` (a duplicate cannot be produced).
        assert!(
            output.is_file(),
            "one attestation produced exactly one Complete bundle"
        );
    }

    #[test]
    fn restart_recovers_over_corrupt_destination_and_stale_temp() {
        let run = build_run_dir("restart");
        let output = run.root.join("evidence.bundle.json");
        fs::write(&output, b"{ broken json ").expect("corrupt destination");
        let stale_temp = run.root.join(".evidence.bundle.json.tmp-999-0");
        fs::write(&stale_temp, b"partial garbage").expect("stale temp");

        let parsed: Result<OreansEvidenceBundle, _> =
            serde_json::from_slice(&fs::read(&stale_temp).unwrap());
        assert!(parsed.is_err(), "leftover temp is never a valid bundle");

        assemble_evidence_bundle(&request(&run, &output), context(&run)).expect("restart assemble");
        let bundle = read_bundle(&output);
        let verdict = validate_evidence_bundle(&bundle, &files_map(&run));
        assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
    }
}
