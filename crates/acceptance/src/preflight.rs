//! Offline preflight: case identity, runner-config digest, and the
//! ready/not_ready orchestrator (P6-A/B/C).
//!
//! This module is pure: it never spawns a process, never calls Win32, and
//! never opens a sample beyond read-only hashing. The worktree probe is
//! injected (the CLI/test harness runs `git`; there is no reachable
//! process-launch path in this module).
//!
//! - [`check_case_identity`] (P6-A): independently parses the locked
//!   `lab/cases/v2` manifest, recomputes the protected input SHA-256/size,
//!   validates case id / architecture / input-output path aliasing.
//! - [`RunnerConfig`] + [`runner_config_digest`] (P6-B): canonical
//!   line-based serialization; stable across runs, no timestamps or random
//!   directories, any valid field change flips the digest, unknown/missing
//!   fields fail closed.
//! - [`run_offline_preflight`] (P6-C): aggregates every check into a
//!   deterministic `ready`/`not_ready` report written atomically.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::evidence_bundle::{validate_evidence_bundle, REQUIRED_BUNDLE_MEMBERS};
use crate::identity::sha256_hex;
use crate::oreans_gate::locked_manifest;

/// Schema id of the preflight report.
pub const PREFLIGHT_REPORT_SCHEMA_VERSION: &str = "mida.preflight-report/v1";

// ---------------------------------------------------------------------------
// P6-A: case identity
// ---------------------------------------------------------------------------

/// Strict top-level shape of `mida.case-manifest/v2`. `deny_unknown_fields`
/// rejects manifest drift; fields we do not consume stay `Value`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseManifestV2 {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub schema_version: String,
    pub manifest_revision: u64,
    pub case_id: String,
    pub display_name: String,
    pub primary_artifact_sha256: String,
    #[serde(rename = "artifacts")]
    pub artifacts: Vec<ManifestArtifact>,
    pub capability_cell: CapabilityCell,
    pub static_fingerprint: serde_json::Value,
    pub execution_policy: serde_json::Value,
    pub oracle: serde_json::Value,
    #[serde(default)]
    pub capture_policy: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestArtifact {
    pub sha256: String,
    pub size_bytes: u64,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityCell {
    pub platform: String,
    pub binary_format: String,
    pub architecture: String,
    pub execution_model: String,
    pub protection_family: String,
    pub engine_route: String,
    pub corpus_role: String,
}

/// Recompute the identity of a file on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

/// Read-only identity of one case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaseIdentity {
    pub case_id: String,
    pub manifest_path: String,
    pub protected_input_sha256: String,
    pub protected_input_size_bytes: u64,
    pub architecture: String,
}

/// Result of one case-identity check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityVerdict {
    pub ok: bool,
    pub reasons: Vec<String>,
    pub identity: Option<CaseIdentity>,
    pub file: Option<FileIdentity>,
}

fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check one case's locked manifest against the protected input file.
///
/// Read-only: only `fs::metadata` / `fs::read` / `fs::canonicalize`.
/// Rejects unknown manifest fields, mismatched case ids (vs the embedded
/// locked manifest), wrong digests/sizes, non-x86_64 architecture, and
/// input/output path aliases.
pub fn check_case_identity(
    manifest_path: &Path,
    protected_input: &Path,
    candidate_output: Option<&Path>,
) -> IdentityVerdict {
    let mut reasons = Vec::new();

    let bytes = match fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            return IdentityVerdict {
                ok: false,
                reasons: vec![format!(
                    "cannot read manifest {}: {e}",
                    manifest_path.display()
                )],
                identity: None,
                file: None,
            };
        }
    };
    let manifest: CaseManifestV2 = match serde_json::from_slice(&bytes) {
        Ok(m) => m,
        Err(e) => {
            return IdentityVerdict {
                ok: false,
                reasons: vec![format!(
                    "manifest {} rejected (unknown/malformed fields): {e}",
                    manifest_path.display()
                )],
                identity: None,
                file: None,
            };
        }
    };

    if manifest.schema_version != "mida.case-manifest/v2" {
        reasons.push(format!(
            "manifest schema_version {:?} != mida.case-manifest/v2",
            manifest.schema_version
        ));
    }

    // Cross-check against the embedded locked manifest (v8 gate source).
    let locked = locked_manifest(&manifest.case_id).map(|l| {
        (
            l.case_id,
            l.protected_input_sha256,
            l.protected_input_size_bytes,
        )
    });
    if locked.is_none() {
        reasons.push(format!(
            "case_id {:?} is not one of the two fixed Oreans cases",
            manifest.case_id
        ));
    }

    let protected = manifest
        .artifacts
        .iter()
        .find(|a| a.role == "protected_input");
    let (declared_sha, declared_size) = match protected {
        Some(a) => {
            if !is_64_hex(&a.sha256) || a.size_bytes == 0 {
                reasons.push(format!(
                    "protected_input artifact identity invalid (sha={} size={})",
                    a.sha256, a.size_bytes
                ));
                (String::new(), 0)
            } else {
                (a.sha256.to_lowercase(), a.size_bytes)
            }
        }
        None => {
            reasons.push("manifest has no protected_input artifact".to_string());
            (String::new(), 0)
        }
    };

    if let Some((locked_case_id, locked_sha, locked_size)) = locked {
        if manifest.case_id != locked_case_id {
            reasons.push(format!(
                "case_id mismatch: manifest {:?} vs locked {:?}",
                manifest.case_id, locked_case_id
            ));
        }
        if declared_sha != locked_sha.to_lowercase() || declared_size != locked_size {
            reasons.push(format!(
                "declared protected input ({declared_sha}/{declared_size}) does not match the locked manifest ({}/{})",
                locked_sha, locked_size
            ));
        }
    }

    if manifest.capability_cell.architecture != "x86_64" {
        reasons.push(format!(
            "architecture {:?} is not x86_64",
            manifest.capability_cell.architecture
        ));
    }
    if manifest.capability_cell.platform != "windows"
        || manifest.capability_cell.binary_format != "pe"
    {
        reasons.push(format!(
            "platform/binary format unexpected: {:?}/{:?}",
            manifest.capability_cell.platform, manifest.capability_cell.binary_format
        ));
    }

    // Recompute the protected input identity (read-only).
    let file = match fs::read(protected_input) {
        Ok(data) if !data.is_empty() => {
            let size = data.len() as u64;
            let sha = sha256_hex(&data);
            if declared_sha.is_empty() {
                // already reported
            } else if sha != declared_sha || size != declared_size {
                reasons.push(format!(
                    "protected input recompute mismatch: file {sha}/{size}, manifest {declared_sha}/{declared_size}"
                ));
            }
            Some(FileIdentity {
                sha256: sha,
                size_bytes: size,
            })
        }
        Ok(_) => {
            reasons.push(format!(
                "protected input {} is empty",
                protected_input.display()
            ));
            None
        }
        Err(e) => {
            reasons.push(format!(
                "cannot read protected input {}: {e}",
                protected_input.display()
            ));
            None
        }
    };

    // Input/output alias: identical canonical path, or the same bytes on
    // disk (a hard-link alias would make the output overwrite the input).
    if let Some(out) = candidate_output {
        let same_canonical = fs::canonicalize(out)
            .ok()
            .zip(fs::canonicalize(protected_input).ok())
            .is_some_and(|(a, b)| a == b);
        if same_canonical {
            reasons.push(format!(
                "candidate output {} aliases the protected input (same canonical path)",
                out.display()
            ));
        }
        if let (Some(f), Ok(out_bytes)) = (&file, fs::read(out)) {
            if !out_bytes.is_empty()
                && sha256_hex(&out_bytes) == f.sha256
                && out_bytes.len() as u64 == f.size_bytes
            {
                reasons.push(format!(
                    "candidate output {} is byte-identical to the protected input (hard-link alias risk)",
                    out.display()
                ));
            }
        }
    }

    let identity = if manifest.case_id.is_empty() || declared_sha.is_empty() {
        None
    } else {
        Some(CaseIdentity {
            case_id: manifest.case_id.clone(),
            manifest_path: manifest_path.display().to_string(),
            protected_input_sha256: declared_sha,
            protected_input_size_bytes: declared_size,
            architecture: manifest.capability_cell.architecture.clone(),
        })
    };

    IdentityVerdict {
        ok: reasons.is_empty(),
        reasons,
        identity,
        file,
    }
}

// ---------------------------------------------------------------------------
// P6-B: runner config digest
// ---------------------------------------------------------------------------

/// Canonical runner configuration. `deny_unknown_fields` + required fields
/// fail closed on drift; no timestamps or random identifiers exist in the
/// type, so the digest is stable across runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    pub tool_revision: String,
    /// SHA-256 of the CLI binary that performs the run.
    pub cli_binary_sha256: String,
    /// Enabled feature set (canonical order applied at digest time).
    pub features: Vec<String>,
    /// Debugger backend identifier, e.g. "windows_debug_api".
    pub debugger_backend: String,
    pub oep_policy: String,
    pub container_restore: String,
    pub shrink: bool,
    pub data_sections: bool,
    pub pure_rebuild: bool,
    /// 64-hex digest of the capture policy, or empty when none is used.
    pub capture_policy_digest: String,
    pub iat_fix_strategy: String,
    pub timeout_secs: u64,
    pub isolation: IsolationConfig,
    /// Attempt numbering policy, e.g. "continuous-1-based".
    pub attempt_numbering: String,
    pub evidence_bundle_schema: String,
    pub gate_schema: String,
    /// Environment variable names the runner may inherit (canonical order).
    pub env_allowlist: Vec<String>,
}

/// Isolation parameters (names/policies only — no machine paths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationConfig {
    pub workspace_policy: String,
    pub process_tree_policy: String,
    pub network_policy: String,
}

impl RunnerConfig {
    /// Validate shapes (digests, non-empty identifiers). Returns the first
    /// reason or `None` when valid.
    pub fn validate(&self) -> Option<String> {
        if self.tool_revision.trim().is_empty() {
            return Some("tool_revision must be non-empty".to_string());
        }
        if !is_64_hex(&self.cli_binary_sha256) {
            return Some("cli_binary_sha256 must be exactly 64 hex chars".to_string());
        }
        if !self.capture_policy_digest.is_empty() && !is_64_hex(&self.capture_policy_digest) {
            return Some("capture_policy_digest must be empty or 64 hex chars".to_string());
        }
        if self.oep_policy.trim().is_empty()
            || self.debugger_backend.trim().is_empty()
            || self.attempt_numbering.trim().is_empty()
            || self.evidence_bundle_schema.trim().is_empty()
            || self.gate_schema.trim().is_empty()
        {
            return Some("runner config identifiers must be non-empty".to_string());
        }
        None
    }
}

/// Canonical line-based serialization of the runner config.
///
/// Lists are sorted; booleans render `true`/`false`; no whitespace variance
/// can change the digest. Producer/consumer implement this form
/// independently (the CLI mirrors it at run time).
pub fn canonical_runner_config(config: &RunnerConfig) -> String {
    let mut features: Vec<String> = config.features.clone();
    features.sort();
    let mut env: Vec<String> = config.env_allowlist.clone();
    env.sort();
    format!(
        concat!(
            "tool_revision={}\n",
            "cli_binary_sha256={}\n",
            "features={}\n",
            "debugger_backend={}\n",
            "oep_policy={}\n",
            "container_restore={}\n",
            "shrink={}\n",
            "data_sections={}\n",
            "pure_rebuild={}\n",
            "capture_policy_digest={}\n",
            "iat_fix_strategy={}\n",
            "timeout_secs={}\n",
            "isolation.workspace_policy={}\n",
            "isolation.process_tree_policy={}\n",
            "isolation.network_policy={}\n",
            "attempt_numbering={}\n",
            "evidence_bundle_schema={}\n",
            "gate_schema={}\n",
            "env_allowlist={}\n",
        ),
        config.tool_revision,
        config.cli_binary_sha256.to_lowercase(),
        features.join(","),
        config.debugger_backend,
        config.oep_policy,
        config.container_restore,
        config.shrink,
        config.data_sections,
        config.pure_rebuild,
        config.capture_policy_digest.to_lowercase(),
        config.iat_fix_strategy,
        config.timeout_secs,
        config.isolation.workspace_policy,
        config.isolation.process_tree_policy,
        config.isolation.network_policy,
        config.attempt_numbering,
        config.evidence_bundle_schema,
        config.gate_schema,
        env.join(","),
    )
}

/// SHA-256 digest of the canonical runner config.
pub fn runner_config_digest(config: &RunnerConfig) -> String {
    sha256_hex(canonical_runner_config(config).as_bytes())
}

// ---------------------------------------------------------------------------
// P6-C: offline preflight orchestrator
// ---------------------------------------------------------------------------

/// Worktree state probed outside this module (no process launch here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeState {
    pub head_revision: String,
    pub clean: bool,
    /// `None` when the probe could not determine cleanliness (fail closed).
    pub clean_determined: bool,
}

/// Injected probe; the CLI/test harness runs `git`.
pub trait WorktreeProbe {
    fn probe(&self) -> WorktreeState;
}

/// Per-case preflight result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasePreflight {
    pub case_id: String,
    pub identity_ok: bool,
    pub reasons: Vec<String>,
}

/// Preflight report (deterministic: no timestamps, no random identifiers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    pub schema_version: String,
    pub status: PreflightStatus,
    pub reasons: Vec<String>,
    pub runner_config_digest: String,
    pub head_revision: Option<String>,
    pub worktree_clean: Option<bool>,
    pub toolchain_matches: Option<bool>,
    pub cli_binary_sha256: Option<String>,
    pub cli_binary_matches: Option<bool>,
    pub cases: Vec<CasePreflight>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Ready,
    NotReady,
}

/// Everything the orchestrator needs.
pub struct PreflightRequest<'a> {
    /// (manifest path, protected input path, candidate output path) per case.
    pub cases: Vec<(&'a Path, &'a Path, &'a Path)>,
    pub output_dir: &'a Path,
    pub cli_binary: Option<&'a Path>,
    pub expected_cli_sha256: Option<&'a str>,
    pub runner_config: &'a RunnerConfig,
    pub worktree: &'a dyn WorktreeProbe,
    pub toolchain_pin_file: &'a Path,
    pub expected_toolchain: &'a str,
}

/// Write `data` to `destination` atomically (temp + rename, same directory).
fn atomic_write(destination: &Path, data: &[u8]) -> std::io::Result<()> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent)?;
    let tmp = parent.join(format!(".preflight-{}.tmp", std::process::id()));
    fs::write(&tmp, data)?;
    fs::rename(&tmp, destination)?;
    Ok(())
}

/// Run every offline check and return the deterministic report.
///
/// `status == Ready` only when every case passes identity, the toolchain is
/// pinned, the worktree is clean (when determinable), the CLI binary hash
/// matches (when expected), the output directory is usable, and no stale or
/// partial evidence would be overwritten. Never writes outside `output_dir`.
pub fn run_offline_preflight(request: &PreflightRequest<'_>) -> PreflightReport {
    let mut reasons: Vec<String> = Vec::new();

    // Toolchain pin.
    let toolchain_matches = match fs::read_to_string(request.toolchain_pin_file) {
        Ok(text) => {
            let ok = text.contains(&format!("channel = \"{}\"", request.expected_toolchain));
            if !ok {
                reasons.push(format!(
                    "rust-toolchain.toml does not pin channel {:?}",
                    request.expected_toolchain
                ));
            }
            Some(ok)
        }
        Err(e) => {
            reasons.push(format!(
                "cannot read toolchain pin {}: {e}",
                request.toolchain_pin_file.display()
            ));
            None
        }
    };

    // Worktree (injected probe).
    let worktree = request.worktree.probe();
    let worktree_clean = if worktree.clean_determined {
        if !worktree.clean {
            reasons.push(format!(
                "worktree is dirty at revision {}",
                worktree.head_revision
            ));
        }
        if !worktree.head_revision.is_empty()
            && worktree.head_revision != request.runner_config.tool_revision
        {
            reasons.push(format!(
                "tool revision drift: worktree HEAD {} vs runner config {}",
                worktree.head_revision, request.runner_config.tool_revision
            ));
        }
        Some(worktree.clean)
    } else {
        reasons.push("worktree cleanliness could not be determined".to_string());
        None
    };

    // CLI binary hash.
    let (cli_binary_sha256, cli_binary_matches) = match request.cli_binary {
        Some(path) => match fs::read(path) {
            Ok(data) => {
                let digest = sha256_hex(&data);
                let matches = request
                    .expected_cli_sha256
                    .map(|e| e.to_lowercase() == digest)
                    .unwrap_or(true);
                if !matches {
                    reasons.push(format!(
                        "CLI binary {} digest {digest} does not match expected {:?}",
                        path.display(),
                        request.expected_cli_sha256
                    ));
                }
                (Some(digest), Some(matches))
            }
            Err(e) => {
                reasons.push(format!("cannot read CLI binary {}: {e}", path.display()));
                (None, None)
            }
        },
        None => {
            reasons.push("no CLI binary supplied for preflight".to_string());
            (None, None)
        }
    };

    // Runner config.
    if let Some(problem) = request.runner_config.validate() {
        reasons.push(format!("runner config invalid: {problem}"));
    }
    let config_digest = runner_config_digest(request.runner_config);

    // Output directory usability (read-only probe; no creation here).
    match fs::metadata(request.output_dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => reasons.push(format!(
            "output path {} exists and is not a directory",
            request.output_dir.display()
        )),
        Err(_) => {
            // Missing is fine only if the parent is creatable; report and let
            // the caller create it. Fail closed: require an existing parent.
            let parent = request.output_dir.parent();
            match parent.and_then(|p| fs::metadata(p).ok()) {
                Some(m) if m.is_dir() => {}
                _ => reasons.push(format!(
                    "output dir {} has no usable parent",
                    request.output_dir.display()
                )),
            }
        }
    }

    // Stale sidecars / partial bundles / overwrite risk in the output dir.
    if let Ok(entries) = fs::read_dir(request.output_dir) {
        let mut found_stale = false;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with("_evidence.json")
                || name.ends_with(".transform_manifest.json")
                || name.ends_with(".bundle.json")
            {
                found_stale = true;
                reasons.push(format!(
                    "stale evidence in output dir would be overwritten: {name}"
                ));
            }
            if name.ends_with(".tmp") {
                found_stale = true;
                reasons.push(format!("leftover temp file in output dir: {name}"));
            }
        }
        if found_stale {
            reasons
                .push("output dir must be empty of evidence/temp files before a run".to_string());
        }
    }

    // Case identities.
    let mut cases = Vec::with_capacity(request.cases.len());
    for (manifest_path, input_path, output_path) in &request.cases {
        let verdict = check_case_identity(manifest_path, input_path, Some(output_path));
        if !verdict.ok {
            reasons.extend(verdict.reasons.clone());
        }
        cases.push(CasePreflight {
            case_id: verdict
                .identity
                .as_ref()
                .map(|i| i.case_id.clone())
                .unwrap_or_else(|| manifest_path.display().to_string()),
            identity_ok: verdict.ok,
            reasons: verdict.reasons,
        });
    }

    // Bundle path rehearsal: the seven members must be accepted by the
    // independent validator contract and must not collide with inputs.
    let bundle_rehearsal_ok = {
        let member_names: BTreeSet<&str> =
            REQUIRED_BUNDLE_MEMBERS.iter().map(|(n, _)| *n).collect();
        let expected = member_names.len() == 7;
        if !expected {
            reasons.push(format!(
                "bundle contract requires exactly 7 members, got {}",
                member_names.len()
            ));
        }
        // The validator is in-process and fail-closed by construction; an
        // empty bundle must be rejected — proving it is callable.
        let files = std::collections::BTreeMap::new();
        let empty_bundle = crate::evidence_bundle::OreansEvidenceBundle {
            schema_version: "mida.oreans-evidence-bundle/v2".to_string(),
            case_id: String::new(),
            tool_revision: String::new(),
            runner_config_digest: String::new(),
            emitted_at: String::new(),
            completion_marker: crate::evidence_bundle::BundleCompletionMarker::Complete,
            protected_input: crate::evidence_bundle::BundleArtifactIdentity {
                sha256: String::new(),
                size_bytes: 0,
            },
            candidate: crate::evidence_bundle::BundleArtifactIdentity {
                sha256: String::new(),
                size_bytes: 0,
            },
            members_sha256: String::new(),
            manifest_sha256: String::new(),
            members: Vec::new(),
        };
        let verdict = validate_evidence_bundle(&empty_bundle, &files);
        if verdict.valid {
            reasons.push("bundle validator unexpectedly accepted an empty bundle".to_string());
            false
        } else {
            expected
        }
    };
    let _ = bundle_rehearsal_ok;

    let status = if reasons.is_empty() {
        PreflightStatus::Ready
    } else {
        PreflightStatus::NotReady
    };

    PreflightReport {
        schema_version: PREFLIGHT_REPORT_SCHEMA_VERSION.to_string(),
        status,
        reasons,
        runner_config_digest: config_digest,
        head_revision: if worktree.head_revision.is_empty() {
            None
        } else {
            Some(worktree.head_revision)
        },
        worktree_clean,
        toolchain_matches,
        cli_binary_sha256,
        cli_binary_matches,
        cases,
    }
}

/// Serialize and atomically write the preflight report under `output_dir`.
pub fn write_preflight_report(
    output_dir: &Path,
    report: &PreflightReport,
) -> std::io::Result<PathBuf> {
    let json =
        serde_json::to_vec_pretty(report).map_err(|e| std::io::Error::other(e.to_string()))?;
    let destination = output_dir.join("preflight.json");
    atomic_write(&destination, &json)?;
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_runner_config() -> RunnerConfig {
        RunnerConfig {
            tool_revision: "oreans/two-sample-mainline@frozen".to_string(),
            cli_binary_sha256: "a".repeat(64),
            features: vec!["default".to_string()],
            debugger_backend: "windows_debug_api".to_string(),
            oep_policy: "captured".to_string(),
            container_restore: "off".to_string(),
            shrink: true,
            data_sections: true,
            pure_rebuild: false,
            capture_policy_digest: String::new(),
            iat_fix_strategy: "v3-trace".to_string(),
            timeout_secs: 120,
            isolation: IsolationConfig {
                workspace_policy: "isolated-temp".to_string(),
                process_tree_policy: "single-process".to_string(),
                network_policy: "blocked".to_string(),
            },
            attempt_numbering: "continuous-1-based".to_string(),
            evidence_bundle_schema: "mida.oreans-evidence-bundle/v2".to_string(),
            gate_schema: "mida.oreans-two-sample-gate/v8".to_string(),
            env_allowlist: vec!["CARGO_TARGET_DIR".to_string()],
        }
    }

    #[test]
    fn runner_digest_is_stable_and_serialization_canonical() {
        let a = sample_runner_config();
        let b = sample_runner_config();
        assert_eq!(runner_config_digest(&a), runner_config_digest(&b));
        assert_eq!(canonical_runner_config(&a), canonical_runner_config(&b));
        assert_eq!(runner_config_digest(&a).len(), 64);
    }

    #[test]
    fn runner_digest_changes_with_any_valid_field() {
        let base = sample_runner_config();
        let d0 = runner_config_digest(&base);
        let mut c = base.clone();
        c.timeout_secs += 1;
        assert_ne!(d0, runner_config_digest(&c), "timeout must change digest");
        let mut c = base.clone();
        c.shrink = !c.shrink;
        assert_ne!(d0, runner_config_digest(&c), "shrink must change digest");
        let mut c = base.clone();
        c.features.push("gto-product-recovery".to_string());
        assert_ne!(d0, runner_config_digest(&c), "features must change digest");
        let mut c = base.clone();
        c.env_allowlist.push("PATH".to_string());
        assert_ne!(
            d0,
            runner_config_digest(&c),
            "env allowlist must change digest"
        );
        // List order must not matter (canonical sort).
        let mut c = base.clone();
        c.features.reverse();
        assert_eq!(d0, runner_config_digest(&c), "list order is canonicalized");
    }

    #[test]
    fn runner_digest_rejects_unknown_and_missing_fields() {
        let json = serde_json::json!({
            "tool_revision": "x", "cli_binary_sha256": "a".repeat(64),
            "features": [], "debugger_backend": "b", "oep_policy": "p",
            "container_restore": "off", "shrink": true, "data_sections": true,
            "pure_rebuild": false, "capture_policy_digest": "",
            "iat_fix_strategy": "s", "timeout_secs": 1,
            "isolation": {"workspace_policy": "w", "process_tree_policy": "p", "network_policy": "n"},
            "attempt_numbering": "a", "evidence_bundle_schema": "e", "gate_schema": "g",
            "env_allowlist": [],
            "sneaky_extra": 1,
        });
        assert!(
            serde_json::from_value::<RunnerConfig>(json).is_err(),
            "unknown field must be rejected"
        );
        let mut minimal = serde_json::to_value(sample_runner_config()).unwrap();
        minimal.as_object_mut().unwrap().remove("timeout_secs");
        assert!(
            serde_json::from_value::<RunnerConfig>(minimal).is_err(),
            "missing field must be rejected"
        );
    }

    #[test]
    fn runner_config_validate_fails_closed() {
        let mut c = sample_runner_config();
        c.cli_binary_sha256 = "not-hex".to_string();
        assert!(c.validate().is_some());
        let c = sample_runner_config();
        assert!(c.validate().is_none());
    }

    #[test]
    fn identity_check_rejects_digest_mismatch_and_alias() {
        let dir = std::env::temp_dir().join(format!(
            "mida_preflight_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let input = dir.join("protected.bin");
        fs::write(&input, b"PAYLOAD-0123456789").unwrap();
        // Manifest declares the REAL locked origin_macro identity (so the
        // locked cross-check passes) while the file is synthetic — the
        // recompute must fail closed.
        let digest = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
        let size = 5_232_656u64;
        let manifest = dir.join("case.json");
        fs::write(
            &manifest,
            serde_json::to_vec_pretty(&serde_json::json!({
                "$schema": "./case-manifest.schema.json",
                "schema_version": "mida.case-manifest/v2",
                "manifest_revision": 1,
                "case_id": "origin_macro",
                "display_name": "synthetic",
                "primary_artifact_sha256": digest,
                "artifacts": [{"sha256": digest, "size_bytes": size, "role": "protected_input"}],
                "capability_cell": {
                    "platform": "windows", "binary_format": "pe", "architecture": "x86_64",
                    "execution_model": "native", "protection_family": "oreans_candidate",
                    "engine_route": "mida_plugin_oreans", "corpus_role": "regression"
                },
                "static_fingerprint": {}, "execution_policy": {}, "oracle": {}
            }))
            .unwrap(),
        )
        .unwrap();

        // Wrong digest/size (synthetic file vs real locked identity).
        let bad = check_case_identity(&manifest, &input, None);
        assert!(!bad.ok);
        assert!(
            bad.reasons.iter().any(|r| r.contains("recompute mismatch")),
            "{:?}",
            bad.reasons
        );

        // Byte-identical output alias must also be flagged.
        let alias = dir.join("candidate.exe");
        fs::copy(&input, &alias).unwrap();
        let alias_check = check_case_identity(&manifest, &input, Some(&alias));
        assert!(
            alias_check
                .reasons
                .iter()
                .any(|r| r.contains("byte-identical")),
            "{:?}",
            alias_check.reasons
        );

        // Same canonical path alias must be flagged too.
        let same_check = check_case_identity(&manifest, &input, Some(&input));
        assert!(
            same_check
                .reasons
                .iter()
                .any(|r| r.contains("same canonical path")),
            "{:?}",
            same_check.reasons
        );

        // Unknown manifest field must be rejected.
        let mut manifest_value: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
        manifest_value["sneaky_extra"] = serde_json::json!(1);
        let bad_manifest = dir.join("case_bad.json");
        fs::write(&bad_manifest, serde_json::to_vec(&manifest_value).unwrap()).unwrap();
        let unknown = check_case_identity(&bad_manifest, &input, None);
        assert!(!unknown.ok);
        assert!(
            unknown
                .reasons
                .iter()
                .any(|r| r.contains("unknown/malformed")),
            "{:?}",
            unknown.reasons
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
