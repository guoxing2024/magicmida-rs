//! Offline preflight: case identity, runner-config digest, and the
//! ready/not_ready orchestrator (P6-A/B/C, hardened per P6.1).
//!
//! This module never spawns a process and never calls Win32; the worktree
//! probe is injected (the CLI/test harness runs `git`; there is no reachable
//! process-launch path in this module). It may create files only inside the
//! caller-controlled `output_dir` (directory creation, a transient
//! writability probe, and the atomic report write).
//!
//! - [`check_case_identity`] (P6-A): independently parses the locked
//!   `lab/cases/v2` manifest, recomputes the protected input SHA-256/size,
//!   validates case id / architecture / input-output path aliasing.
//! - [`RunnerConfig`] + [`runner_config_digest`] (P6-B): the canonical
//!   length-prefixed encoding is implemented *independently* on the runner
//!   side (`mida-core::runner_config`, consumed by `mida-cli` in production)
//!   and mirrored here as the verifier copy. The acceptance crate never
//!   depends on production crates (see `tests/dependency_boundary.rs`); the
//!   two implementations are kept honest by the cross-check test in
//!   `mida-cli` (`tests/runner_config_digest_crosscheck.rs`) which asserts
//!   both digests agree for the same JSON config. The encoding is injective
//!   for arbitrary value bytes (commas/newlines/colons cannot collide),
//!   stable across runs, and unknown/missing fields fail closed.
//! - [`run_offline_preflight`] (P6-C): aggregates every check into a
//!   deterministic `ready`/`not_ready` report written atomically (unique
//!   `create_new` temp file, `flush` + `sync_all`, Windows replace-existing;
//!   a failed replace preserves the previous report).

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::evidence_bundle::{validate_evidence_bundle, REQUIRED_BUNDLE_MEMBERS};
use crate::identity::sha256_hex;
use crate::oreans_gate::locked_manifest;

/// Schema id of the preflight report.
///
/// v2 (P6.3-B): per-case artifact identities and canonical paths are added
/// so the launch boundary can attest that the current input/output/cli/config
/// are unchanged since staging.
///
/// v3 (P6.3.3): each case entry carries its own `runner_config_digest`, and
/// the report's top-level `runner_config_digest` is the envelope's sealed
/// case-set digest — so the report can cross-validate every case's config
/// against the v4 envelope.
pub const PREFLIGHT_REPORT_SCHEMA_VERSION: &str = "mida.preflight-report/v3";

/// The two fixed Oreans cases; preflight is Ready only for exactly this set
/// (the Oreans fixed regression lane).
pub const FIXED_CASE_IDS: [&str; 2] = ["origin_macro", "lunlun_software"];

/// The independent GTO generic/no-gate lane case id. It is NOT part of the
/// Oreans fixed regression gate; it carries family `ahk_gto`, a `no-gate`
/// acceptance state, and produces generic `mida.unpack-*` evidence.
pub const GTO_CASE_ID: &str = "gto_launcher";

/// The manifest `capability_cell.protection_family` value that identifies the
/// AHK/GTO lane (mirrors the CLI `packer_family_from_protection_family`).
pub const GTO_PROTECTION_FAMILY: &str = "ahk_gto_candidate";

/// Whether a case manifest declares the GTO generic/no-gate lane.
pub fn is_gto_lane_manifest(case_id: &str, protection_family: &str) -> bool {
    case_id == GTO_CASE_ID && protection_family == GTO_PROTECTION_FAMILY
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    // Cross-check against the embedded locked manifest (v8 gate source) for
    // the Oreans fixed lane. The GTO generic/no-gate lane has no locked
    // manifest (it is not an accepted sample); its identity is bound from the
    // manifest declaration and the on-disk recompute below.
    let gto_lane = is_gto_lane_manifest(
        &manifest.case_id,
        &manifest.capability_cell.protection_family,
    );
    let locked = if gto_lane {
        None
    } else {
        locked_manifest(&manifest.case_id).map(|l| {
            (
                l.case_id,
                l.protected_input_sha256,
                l.protected_input_size_bytes,
            )
        })
    };
    if locked.is_none() && !gto_lane {
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
// P6-B: runner config digest — verifier-side copy.
//
// The runner side (`mida-core::runner_config`, consumed by `mida-cli` in
// production) implements the same canonical contract independently; the
// cross-check test in `mida-cli/tests/runner_config_digest_crosscheck.rs`
// asserts both digests agree for the same JSON config. Encoding contract
// (length-prefixed, injective):
//
// - Every scalar field renders as `name=len:value` where `len` is the
//   decimal ASCII byte length of `value`; fields are separated by `\n` in a
//   fixed order.
// - Every list field renders as `name=count:len:elem...` where `count` is
//   the element count and each element is `len:elem`; elements are sorted
//   before encoding.
// - Booleans render `true`/`false`, integers as decimal ASCII.
//
// Because every segment is delimited by its own byte length, values may
// contain commas, newlines, colons or any other byte without ever colliding
// with another configuration.
// ---------------------------------------------------------------------------

/// Canonical runner configuration (verifier copy; see module docs).
/// `deny_unknown_fields` + required fields fail closed on drift; no
/// timestamps or random identifiers exist in the type, so the digest is
/// stable across runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    /// Packer family (Oreans-compat default; GTO sets `ahk_gto` explicitly).
    #[serde(default = "default_packer_family")]
    pub packer_family: String,
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

/// Default family for a family-less (legacy) runner config. Oreans-compat
/// wrapper: legacy wire JSON and the old no-family policy builders parse and
/// behave exactly as before. GTO configs must set `packer_family = "ahk_gto"`
/// explicitly so their digest differs from Oreans.
pub fn default_packer_family() -> String {
    "oreans_themida".to_string()
}

/// The packer family that routes to the legacy Oreans evidence contract.
pub const PACKER_FAMILY_OREANS: &str = "oreans_themida";
/// The AHK/GTO packer family that routes to the generic
/// `mida.unpack-evidence-bundle/v1` contract.
pub const PACKER_FAMILY_AHK_GTO: &str = "ahk_gto";

/// Families this toolchain can bind to an evidence contract. Kept independent
/// of `mida-core` (the acceptance crate must not depend on production crates);
/// must stay in sync with `mida_core::runner_config::packer_family`.
pub fn is_known_packer_family(family: &str) -> bool {
    matches!(family, PACKER_FAMILY_OREANS | PACKER_FAMILY_AHK_GTO)
}

/// A family that records evidence through the generic
/// `mida.unpack-evidence-bundle/v1` contract (currently `ahk_gto`). Extend
/// when a new family adopts the generic contract; kept independent of
/// `mida-core` because the acceptance crate must not depend on production
/// crates.
pub fn is_generic_packer_family(family: &str) -> bool {
    family == PACKER_FAMILY_AHK_GTO
}

impl RunnerConfig {
    /// Validate shapes (digests, non-empty identifiers). Returns the first
    /// reason or `None` when valid.
    pub fn validate(&self) -> Option<String> {
        if self.packer_family.trim().is_empty() {
            return Some("packer_family must be non-empty".to_string());
        }
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

    /// A placeholder for the v4 (case-bound) preflight path: the per-case
    /// configs are verified individually, so this shared value only carries
    /// the tool revision / CLI identity for the top-level consistency checks
    /// and never represents any single case's run. Its digest is NOT used for
    /// a case — per-case digests come from the envelope.
    pub fn placeholder_for_preflight(tool_revision: &str, cli_binary_sha256: &str) -> Self {
        use crate::preflight::IsolationConfig as IC;
        Self {
            packer_family: default_packer_family(),
            tool_revision: tool_revision.to_string(),
            cli_binary_sha256: cli_binary_sha256.to_string(),
            features: vec!["default".to_string()],
            debugger_backend: "windows_debug_api".to_string(),
            oep_policy: "captured".to_string(),
            container_restore: "off".to_string(),
            shrink: true,
            data_sections: false,
            pure_rebuild: false,
            capture_policy_digest: String::new(),
            iat_fix_strategy: "v3-trace".to_string(),
            timeout_secs: 120,
            isolation: IC {
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
}

fn push_scalar(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push('=');
    out.push_str(&value.len().to_string());
    out.push(':');
    out.push_str(value);
    out.push('\n');
}

fn push_list(out: &mut String, name: &str, elements: &mut Vec<String>) {
    elements.sort();
    out.push_str(name);
    out.push('=');
    out.push_str(&elements.len().to_string());
    out.push(':');
    for element in elements.iter() {
        out.push_str(&element.len().to_string());
        out.push(':');
        out.push_str(element);
    }
    out.push('\n');
}

/// Canonical, injective serialization of the runner config (verifier copy).
pub fn canonical_runner_config(config: &RunnerConfig) -> String {
    let mut out = String::new();
    push_scalar(&mut out, "packer_family", &config.packer_family);
    push_scalar(&mut out, "tool_revision", &config.tool_revision);
    push_scalar(
        &mut out,
        "cli_binary_sha256",
        &config.cli_binary_sha256.to_lowercase(),
    );
    push_list(&mut out, "features", &mut config.features.clone());
    push_scalar(&mut out, "debugger_backend", &config.debugger_backend);
    push_scalar(&mut out, "oep_policy", &config.oep_policy);
    push_scalar(&mut out, "container_restore", &config.container_restore);
    push_scalar(&mut out, "shrink", &config.shrink.to_string());
    push_scalar(&mut out, "data_sections", &config.data_sections.to_string());
    push_scalar(&mut out, "pure_rebuild", &config.pure_rebuild.to_string());
    push_scalar(
        &mut out,
        "capture_policy_digest",
        &config.capture_policy_digest.to_lowercase(),
    );
    push_scalar(&mut out, "iat_fix_strategy", &config.iat_fix_strategy);
    push_scalar(&mut out, "timeout_secs", &config.timeout_secs.to_string());
    push_scalar(
        &mut out,
        "isolation.workspace_policy",
        &config.isolation.workspace_policy,
    );
    push_scalar(
        &mut out,
        "isolation.process_tree_policy",
        &config.isolation.process_tree_policy,
    );
    push_scalar(
        &mut out,
        "isolation.network_policy",
        &config.isolation.network_policy,
    );
    push_scalar(&mut out, "attempt_numbering", &config.attempt_numbering);
    push_scalar(
        &mut out,
        "evidence_bundle_schema",
        &config.evidence_bundle_schema,
    );
    push_scalar(&mut out, "gate_schema", &config.gate_schema);
    push_list(&mut out, "env_allowlist", &mut config.env_allowlist.clone());
    out
}

/// SHA-256 digest of the canonical runner config (64 lowercase hex chars).
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

/// Injected probe for the worktree; the CLI/test harness runs `git`.
pub trait WorktreeProbe {
    fn probe(&self) -> WorktreeState;
}

/// P6.2: injected seam for output-directory operations. Every step of the
/// writability probe (create_new -> write_all -> flush -> sync_all -> close
/// -> remove) and the stale-evidence enumeration must succeed; any failure
/// is a NotReady reason. The seam lets tests inject deterministic failures
/// instead of relying only on ACL tricks that may skip.
pub trait OutputProbe {
    /// Create a unique probe file in `output_dir`, fully write/sync it,
    /// close it, and remove it. `Err(reason)` = the directory is not
    /// writable (or cleanup failed).
    fn probe_writable(&self, output_dir: &Path) -> Result<(), String>;
    /// List file names inside `output_dir`. `Err(reason)` = the directory
    /// cannot be enumerated (fail closed — stale evidence is undetectable).
    fn list_entries(&self, output_dir: &Path) -> Result<Vec<String>, String>;
}

/// Real filesystem implementation of [`OutputProbe`].
pub struct FsOutputProbe;

impl OutputProbe for FsOutputProbe {
    fn probe_writable(&self, output_dir: &Path) -> Result<(), String> {
        let probe_name = format!(
            ".preflight-probe-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let probe_path = output_dir.join(probe_name);
        let mut probe = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe_path)
            .map_err(|e| format!("output dir {} is not writable: {e}", output_dir.display()))?;
        probe
            .write_all(b"probe")
            .and_then(|_| probe.flush())
            .and_then(|_| probe.sync_all())
            .map_err(|e| {
                let _ = fs::remove_file(&probe_path);
                format!(
                    "output dir {} probe write/sync failed: {e}",
                    output_dir.display()
                )
            })?;
        drop(probe);
        fs::remove_file(&probe_path).map_err(|e| {
            format!(
                "output dir {} probe cleanup failed ({}): {e}",
                output_dir.display(),
                probe_path.display()
            )
        })
    }

    fn list_entries(&self, output_dir: &Path) -> Result<Vec<String>, String> {
        let mut names = Vec::new();
        for entry in fs::read_dir(output_dir).map_err(|e| {
            format!(
                "cannot enumerate output dir {} (stale evidence undetectable): {e}",
                output_dir.display()
            )
        })? {
            let entry = entry.map_err(|e| {
                format!("cannot enumerate output dir {}: {e}", output_dir.display())
            })?;
            names.push(entry.file_name().to_string_lossy().to_string());
        }
        Ok(names)
    }
}

/// Per-case preflight result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasePreflight {
    pub case_id: String,
    pub identity_ok: bool,
    pub reasons: Vec<String>,
    /// P6.3-B: recomputed protected-input identity at preflight time.
    pub protected_input: Option<FileIdentity>,
    /// P6.3-B: canonical protected-input path (for the launch re-run).
    pub protected_input_path: String,
    /// P6.3-B: canonical case-manifest path (for the launch re-run).
    pub manifest_path: String,
    /// P6.3-B: canonical candidate-output path the launch must match.
    pub candidate_output: String,
    /// P6.3.3: the per-case runner-config digest (the envelope-recomputed,
    /// independently-verified value). Present only when the v4 envelope
    /// supplied one; the launch boundary requires it for every case.
    pub runner_config_digest: Option<String>,
}

/// Preflight report (deterministic: no timestamps, no random identifiers).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    pub schema_version: String,
    pub status: PreflightStatus,
    pub reasons: Vec<String>,
    /// P6.3.3: the sealed case-set digest of the v4 envelope (the whole
    /// envelope identity). For the legacy single-config path this holds the
    /// single config digest.
    pub runner_config_digest: String,
    pub head_revision: Option<String>,
    pub worktree_clean: Option<bool>,
    pub toolchain_matches: Option<bool>,
    pub cli_binary_sha256: Option<String>,
    pub cli_binary_matches: Option<bool>,
    /// P6.3-B: canonical CLI binary path pinned at preflight time.
    pub cli_binary_path: String,
    /// P6.3-B: runner context recorded so the launch boundary can re-run
    /// the verifier with the same inputs.
    pub repo_root: String,
    pub toolchain_pin_file: String,
    pub expected_toolchain: String,
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
    /// Required: the pinned CLI identity. Empty/malformed means NotReady;
    /// it must equal `runner_config.cli_binary_sha256` and the actual binary
    /// digest.
    pub expected_cli_sha256: &'a str,
    pub runner_config: &'a RunnerConfig,
    pub worktree: &'a dyn WorktreeProbe,
    /// P6.2: injected output-dir probe (filesystem in production, failure
    /// stubs in tests).
    pub output_probe: &'a dyn OutputProbe,
    pub toolchain_pin_file: &'a Path,
    pub expected_toolchain: &'a str,
    /// P6.3-B: repository root the worktree probe ran against (recorded in
    /// the report so the launch boundary re-runs the verifier identically).
    pub repo_root: &'a Path,
    /// P6.3.3.2: per-case runner-config digest from the v4 envelope, KEYED
    /// by `case_id` (never aligned by array index — a reordered `--case`
    /// vector must not re-bind a digest to a different case). When a case's
    /// key is absent, the orchestrator records `None` (legacy single-config
    /// path). When present, it is recorded in the matching
    /// `CasePreflight.runner_config_digest`.
    pub case_config_digests: std::collections::BTreeMap<String, String>,
    /// P6.3.3: the sealed case-set digest of the v4 envelope. When
    /// non-empty, it is recorded as `PreflightReport.runner_config_digest`.
    pub case_set_digest: String,
}

/// Canonicalize `p`, falling back to canonicalizing its parent when the
/// path itself does not exist yet (e.g. a candidate output file).
fn canonicalize_loose(p: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(p) {
        return c;
    }
    match (
        p.parent().and_then(|parent| fs::canonicalize(parent).ok()),
        p.file_name(),
    ) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => p.to_path_buf(),
    }
}

/// Write `data` to `destination` durably and atomically (P6.1):
///
/// - a uniquely-named temp file next to the destination, created with
///   `create_new` (no PID-only collision window; concurrent writers get
///   distinct names);
/// - `write_all` + `flush` + `sync_all` before the swap;
/// - on Windows, `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`; elsewhere
///   `rename`. A failed replace removes the temp and leaves the previous
///   destination untouched.
fn atomic_write(destination: &Path, data: &[u8]) -> io::Result<()> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent)?;
    let destination_name = destination
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut temp = None;
    for attempt in 0..32u32 {
        let name = format!(
            ".{destination_name}.tmp-{}-{}",
            std::process::id(),
            now.saturating_add(u128::from(attempt))
        );
        let path = parent.join(name);
        let mut file = match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let result = file
            .write_all(data)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all());
        drop(file);
        if let Err(e) = result {
            let _ = fs::remove_file(&path);
            return Err(e);
        }
        temp = Some(path);
        break;
    }
    let temp = temp.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "unable to allocate a unique temporary file",
        )
    })?;
    match atomic_replace(&temp, destination) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&temp);
            Err(e)
        }
    }
}

#[cfg(unix)]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temp, destination)
}

#[cfg(windows)]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let temp_w: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_w: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let result = unsafe {
        MoveFileExW(
            temp_w.as_ptr(),
            destination_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Run every offline check and return the deterministic report.
///
/// `status == Ready` only when every case passes identity, the case set is
/// exactly the two fixed Oreans cases (no empty/missing/duplicate/extra
/// entries), the toolchain is pinned, the worktree HEAD is non-empty and
/// matches the runner config (clean when determinable), the CLI binary digest
/// equals the required `expected_cli_sha256` which itself equals
/// `runner_config.cli_binary_sha256`, candidate outputs stay inside
/// `output_dir`, the output directory is writable, and no stale or partial
/// evidence would be overwritten. Writes nothing outside `output_dir`.
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
    // P6.1: an empty HEAD cannot pin the run — NotReady regardless of
    // cleanliness.
    if worktree.head_revision.trim().is_empty() {
        reasons.push("worktree head revision is empty; the run cannot be pinned".to_string());
    }
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

    // P6.1/P6.2: CLI identity is mandatory and must bind to the runner
    // config. The pin is validated on the ORIGINAL string — whitespace is
    // not trimmed before `is_64_hex`, so `" <64 hex> "` is malformed and
    // NotReady. After validation, lowercase normalization is used only for
    // comparison.
    let expected_cli_original = request.expected_cli_sha256;
    let expected_well_formed = is_64_hex(expected_cli_original);
    if expected_cli_original.is_empty() {
        reasons.push(
            "expected CLI sha256 is missing; refusing to run without a pinned CLI identity"
                .to_string(),
        );
    } else if !expected_well_formed {
        reasons.push(format!(
            "expected CLI sha256 {:?} is malformed (must be exactly 64 hex chars)",
            request.expected_cli_sha256
        ));
    }
    let expected_cli = expected_cli_original.to_lowercase();
    if expected_well_formed
        && expected_cli != request.runner_config.cli_binary_sha256.to_lowercase()
    {
        reasons.push(format!(
            "expected CLI sha256 {expected_cli} does not match runner_config.cli_binary_sha256 {}",
            request.runner_config.cli_binary_sha256
        ));
    }
    let (cli_binary_sha256, cli_binary_matches) = match request.cli_binary {
        Some(path) => match fs::read(path) {
            Ok(data) => {
                let digest = sha256_hex(&data);
                let matches = expected_well_formed && digest == expected_cli;
                if !matches {
                    reasons.push(format!(
                        "CLI binary {} digest {digest} does not match expected {expected_cli_original}",
                        path.display()
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

    // Output directory: must exist (created if missing), be writable, and
    // every candidate output must live inside it. The writability probe
    // checks the FULL chain (create_new -> write_all -> flush -> sync_all
    // -> close -> remove); any failure is NotReady.
    match fs::create_dir_all(request.output_dir) {
        Ok(()) => {}
        Err(e) => reasons.push(format!(
            "output dir {} cannot be created: {e}",
            request.output_dir.display()
        )),
    }
    if let Err(reason) = request.output_probe.probe_writable(request.output_dir) {
        reasons.push(reason);
    }
    let output_canonical = canonicalize_loose(request.output_dir);

    // Stale sidecars / partial bundles / overwrite risk in the output dir.
    // P6.2: enumeration failure is NotReady — stale evidence must never be
    // undetectable. Leftover probe files (.preflight-probe-*) are stale too.
    match request.output_probe.list_entries(request.output_dir) {
        Ok(names) => {
            let mut found_stale = false;
            for name in names {
                if name.ends_with("_evidence.json")
                    || name.ends_with(".transform_manifest.json")
                    || name.ends_with(".bundle.json")
                {
                    found_stale = true;
                    reasons.push(format!(
                        "stale evidence in output dir would be overwritten: {name}"
                    ));
                }
                if name.ends_with(".tmp")
                    || name.contains(".tmp-")
                    || name.starts_with(".preflight-probe-")
                {
                    found_stale = true;
                    reasons.push(format!("leftover temp file in output dir: {name}"));
                }
            }
            if found_stale {
                reasons.push(
                    "output dir must be empty of evidence/temp files before a run".to_string(),
                );
            }
        }
        Err(reason) => reasons.push(reason),
    }

    // Case identities: exactly the two fixed Oreans cases, each once.
    let mut cases = Vec::with_capacity(request.cases.len());
    for (manifest_path, input_path, output_path) in request.cases.iter() {
        let verdict = check_case_identity(manifest_path, input_path, Some(output_path));
        if !verdict.ok {
            reasons.extend(verdict.reasons.clone());
        }
        let output_canonical_case = canonicalize_loose(output_path);
        if !output_canonical_case.starts_with(&output_canonical) {
            reasons.push(format!(
                "candidate output {} is outside the controlled output dir {}",
                output_path.display(),
                request.output_dir.display()
            ));
        }
        // P6.3.3.2: the per-case runner-config digest is looked up KEYED by
        // case_id — never by `idx`. A reordered `--case` vector (or a
        // reordered envelope `case_configs`) must NOT re-bind a digest to a
        // different case. The case_id comes from the manifest identity when
        // present; otherwise the manifest path is used as a stable fallback
        // so a missing sample never masks a digest-bind error.
        let case_id = verdict
            .identity
            .as_ref()
            .map(|i| i.case_id.clone())
            .unwrap_or_else(|| manifest_path.display().to_string());
        let case_digest = request.case_config_digests.get(&case_id).cloned();
        if let Some(d) = &case_digest {
            if !is_64_hex(d) {
                reasons.push(format!(
                    "case {:?} runner_config_digest is malformed",
                    verdict.identity.as_ref().map(|i| i.case_id.as_str())
                ));
            }
        }
        cases.push(CasePreflight {
            case_id: verdict
                .identity
                .as_ref()
                .map(|i| i.case_id.clone())
                .unwrap_or_else(|| manifest_path.display().to_string()),
            identity_ok: verdict.ok,
            reasons: verdict.reasons,
            protected_input: verdict.file.clone(),
            protected_input_path: canonicalize_loose(input_path).display().to_string(),
            manifest_path: canonicalize_loose(manifest_path).display().to_string(),
            candidate_output: output_canonical_case.display().to_string(),
            runner_config_digest: case_digest.map(|d| d.to_lowercase()),
        });
    }

    // P6.1/P6.2: the case set must be exactly the two Oreans fixed cases
    // (each once) plus, optionally, the independent GTO no-gate lane case.
    // No empty, missing, duplicate, or unknown entries.
    let present_ids: Vec<String> = cases.iter().map(|c| c.case_id.clone()).collect();
    let mut seen = std::collections::BTreeMap::<String, usize>::new();
    for id in &present_ids {
        *seen.entry(id.clone()).or_insert(0) += 1;
    }
    // Every case id must be recognized (Oreans fixed or GTO lane).
    for id in &present_ids {
        if !FIXED_CASE_IDS.contains(&id.as_str()) && id != GTO_CASE_ID {
            reasons.push(format!(
                "case {:?} is neither an Oreans fixed case nor the GTO lane case (fail-closed)",
                id
            ));
        }
        if seen[id] != 1 {
            reasons.push(format!(
                "case {id} must appear exactly once, got {}",
                seen[id]
            ));
        }
    }
    // The Oreans fixed regression lane must be complete.
    let oreans_ok = FIXED_CASE_IDS
        .iter()
        .all(|id| present_ids.iter().filter(|p| *p == id).count() == 1);
    if !oreans_ok {
        reasons.push(format!(
            "Oreans fixed lane must contain exactly [{}, {}] with no duplicates, got {:?}",
            FIXED_CASE_IDS[0], FIXED_CASE_IDS[1], present_ids
        ));
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
        // P6.3.3: the v4 path records the sealed case-set digest (the whole
        // envelope identity); the legacy single-config path records the
        // single config digest.
        runner_config_digest: if request.case_set_digest.is_empty() {
            config_digest
        } else {
            request.case_set_digest.to_lowercase()
        },
        head_revision: if worktree.head_revision.is_empty() {
            None
        } else {
            Some(worktree.head_revision)
        },
        worktree_clean,
        toolchain_matches,
        cli_binary_sha256,
        cli_binary_matches,
        cli_binary_path: request
            .cli_binary
            .map(|p| canonicalize_loose(p).display().to_string())
            .unwrap_or_default(),
        repo_root: canonicalize_loose(request.repo_root).display().to_string(),
        toolchain_pin_file: canonicalize_loose(request.toolchain_pin_file)
            .display()
            .to_string(),
        expected_toolchain: request.expected_toolchain.to_string(),
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

    /// G3: a GTO no-gate lane manifest (`case_id=gto_launcher`,
    /// `protection_family=ahk_gto_candidate`) with a file matching its declared
    /// identity passes `check_case_identity` WITHOUT a locked manifest (the GTO
    /// lane has no locked/accepted sample). The `no-gate` state means the
    /// identity chain passed, NOT that the sample is accepted.
    #[test]
    fn gto_lane_case_identity_passes_no_gate() {
        let dir =
            std::env::temp_dir().join(format!("mida_preflight_gto_lane_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let payload = b"GTO-LANE-SYNTHETIC-PROTECTED-INPUT-000000";
        let input = dir.join("gto_protected.bin");
        fs::write(&input, payload).unwrap();
        let digest = sha256_hex(payload);
        let size = payload.len() as u64;
        let manifest = dir.join("gto_launcher.json");
        fs::write(
            &manifest,
            serde_json::to_vec_pretty(&serde_json::json!({
                "$schema": "./case-manifest.schema.json",
                "schema_version": "mida.case-manifest/v2",
                "manifest_revision": 1,
                "case_id": "gto_launcher",
                "display_name": "gto lane",
                "primary_artifact_sha256": digest,
                "artifacts": [{"sha256": digest, "size_bytes": size, "role": "protected_input"}],
                "capability_cell": {
                    "platform": "windows", "binary_format": "pe", "architecture": "x86_64",
                    "execution_model": "native", "protection_family": "ahk_gto_candidate",
                    "engine_route": "mida_plugin_ahk_gto", "corpus_role": "holdout"
                },
                "static_fingerprint": {}, "execution_policy": {}, "oracle": {}
            }))
            .unwrap(),
        )
        .unwrap();
        let verdict = check_case_identity(&manifest, &input, None);
        assert!(
            verdict.ok,
            "GTO lane identity chain must pass (no-gate): {:?}",
            verdict.reasons
        );
        assert_eq!(
            verdict.identity.as_ref().map(|i| i.case_id.as_str()),
            Some("gto_launcher")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// G3: `is_gto_lane_manifest` requires BOTH the `gto_launcher` case id AND
    /// the `ahk_gto_candidate` protection family — a GTO id with a different
    /// protection family is NOT a valid GTO lane and must fail closed.
    #[test]
    fn gto_lane_manifest_requires_id_and_protection_family() {
        assert!(is_gto_lane_manifest("gto_launcher", "ahk_gto_candidate"));
        assert!(!is_gto_lane_manifest("origin_macro", "ahk_gto_candidate"));
        assert!(!is_gto_lane_manifest("gto_launcher", "gto"));
        assert!(!is_gto_lane_manifest("gto_launcher", "oreans_candidate"));
        assert!(!is_gto_lane_manifest("", "ahk_gto_candidate"));
    }
}
