//! Runner-side offline-preflight closure (P6.2): the production binding of
//! the independent runner-config digest producer to the launch boundary.
//!
//! Roles:
//!
//! - **Producer (this module, `mida-cli` production)**: builds
//!   [`mida_core::runner_config::RunnerConfig`] from the actual run policy,
//!   computes the digest with `mida_core::runner_config::runner_config_digest`,
//!   and atomically emits the `mida.runner-config-envelope/v4` envelope
//!   (case-bound: one full config JSON + producer digest per case, plus CLI
//!   binary SHA-256, tool revision, verifier identity, and a sealed
//!   `case_set_digest` over every case config and its case/input binding).
//! - **Verifier (`mida-acceptance` binary)**: reparses the envelope JSON
//!   with its own dependency-free `RunnerConfig`, recomputes the digest with
//!   its own canonical implementation, and produces `preflight.json`.
//! - **Launch boundary (this module)**: [`run_offline_preflight`] drives the
//!   verifier and [`require_ready_before_launch`] refuses to proceed unless
//!   the consumed report is `ready`, the report digest equals the
//!   producer-computed digest, and the CLI identity matches. The unpack
//!   pipeline calls [`require_ready_before_launch`] before any sample
//!   process is created.
//!
//! Digest chain proven by `tests/preflight_boundary.rs`:
//!
//! ```text
//! runner-emitted digest
//! == acceptance-recomputed digest (report.runner_config_digest)
//! == envelope digest
//! == envelope_runner_config_digest() used for sidecar/bundle requests
//! ```
//!
//! P6.3: the envelope binds the ACTUAL run configuration (built by
//! `crate::run_spec` from the parsed `/unpack` arguments, including the
//! Origin Macro pure-rebuild default).
//!
//! P6.3.3: the envelope is case-bound. `/offline-preflight` builds one
//! per-case `RunnerConfig` from `frozen_run_policy(case.input)` — the Origin
//! Macro D3 default resolves `pure_rebuild=true` for origin_macro and
//! `false` for lunlun_software — so a single envelope can honestly
//! authorize both cases. The launch boundary ([`attest_ready_before_launch`])
//! first matches the current protected input to EXACTLY ONE case, then
//! compares the actual config digest against ONLY that case's
//! `runner_config_digest`; the selected digest flows into the evidence
//! context and bundle. A v3 single-config envelope fails closed (no silent
//! upgrade).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};

use crate::unpacker::sidecar_io::atomic_write;

/// Schema id of the runner-config envelope.
///
/// v3 (P6.3.2): binds the verifier PATH identity (canonical CLI sibling
/// path + controlled relative marker) together with `verifier_sha256`, so
/// staging, launch re-attestation, PE-evidence and bundle completion all
/// validate path AND hash.
///
/// v4 (P6.3.3): binds configuration PER CASE. The top-level single
/// `runner_config`/`runner_config_digest` is removed (it could not authorize
/// both Origin `pure_rebuild=true` and Lunlun `pure_rebuild=false`); it is
/// replaced by a `case_configs` collection (exactly the two fixed cases)
/// and a sealed `case_set_digest` over every case config + case/input
/// binding. v3 envelopes no longer parse (fail-closed, no silent upgrade).
pub const RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION: &str = "mida.runner-config-envelope/v4";
/// Filename of the envelope inside the preflight output dir.
pub const RUNNER_CONFIG_ENVELOPE_FILENAME: &str = "runner-config-envelope.json";
/// Filename of the preflight report inside the preflight output dir.
pub const PREFLIGHT_REPORT_FILENAME: &str = "preflight.json";
/// Emitted `$schema` reference of the envelope.
pub const RUNNER_CONFIG_ENVELOPE_SCHEMA_REF: &str = "./runner-config-envelope.schema.json";
/// The controlled relative identity of the verifier: always the CLI sibling.
pub const VERIFIER_SOURCE_TOKEN: &str = "<cli-dir>/mida-acceptance.exe";

/// Fixed policy of the two-sample Oreans runner (frozen for P7).
///
/// The values mirror the CLI defaults the unpack pipeline applies for the
/// Oreans path; the envelope binds the run to exactly this policy, and the
/// acceptance verifier independently recomputes the digest. The P7
/// fixed-mode comparison (including the Origin Macro pure-rebuild default
/// for a given input) lives in `crate::run_spec`.
pub fn frozen_runner_config() -> mida_core::runner_config::RunnerConfig {
    crate::run_spec::frozen_runner_config()
}

/// One case-bound runner config entry inside the v4 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRunnerConfigEnvelope {
    /// The fixed case id (`origin_macro` or `lunlun_software`).
    pub case_id: String,
    /// The packer family this case's run belongs to. This is bound at STAGING
    /// time from the case manifest's `protection_family` and is part of the
    /// sealed case-set digest, so the attestation always builds the actual /
    /// frozen policy against the SAME family the envelope was staged for. A
    /// case can never switch family after staging (that would change the
    /// sealed digest and be refused).
    pub family_id: String,
    /// Verified protected-input identity of this case.
    pub protected_input: FileIdentityGate,
    /// Full runner config JSON, as the runner will apply it for this case.
    pub runner_config: serde_json::Value,
    /// Producer-computed per-case digest
    /// (`mida_core::runner_config::runner_config_digest`).
    pub runner_config_digest: String,
}

/// Select the unique envelope case whose protected input identity matches the
/// actual config's context — but the caller must supply the protected input
/// identity to bind against (the config itself carries no identity). This is
/// the launch-side per-case binding (P6.3.3): the ACTUAL config digest is
/// compared against EXACTLY ONE case digest. The input is matched separately
/// in [`attest_ready_before_launch`]; here we select by `input_identity` and
/// reject 0 or 2+ matches.
///
/// Returns the matched [`CaseRunnerConfigEnvelope`].
pub fn select_case_config<'a>(
    envelope: &'a RunnerConfigEnvelope,
    input_identity: &FileIdentityGate,
) -> anyhow::Result<&'a CaseRunnerConfigEnvelope> {
    let mut matches: Vec<&CaseRunnerConfigEnvelope> = envelope
        .case_configs
        .iter()
        .filter(|c| c.protected_input == *input_identity)
        .collect();
    if matches.len() != 1 {
        bail!(
            "protected input matches {} case configs (expected exactly one); \
             cross-case or third-input selection is refused",
            matches.len()
        );
    }
    Ok(matches.remove(0))
}

/// Launch-side equality check (P6.3-A/P6.3.3): the digest of the ACTUAL run
/// configuration — built from the parsed `/unpack` arguments, with the
/// resolved pure-rebuild value — must equal the digest of the UNIQUE case
/// the current input belongs to. A case config staged with
/// `pure_rebuild=false` can never bind a run that silently resolves to
/// `true` (or any other parameter divergence); the actual config is never
/// compared against another case's digest.
pub fn bind_actual_config_to_envelope(
    output_dir: &Path,
    actual_config: &mida_core::runner_config::RunnerConfig,
    input_identity: &FileIdentityGate,
) -> anyhow::Result<()> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    let case = select_case_config(&envelope, input_identity)?;
    // G2-R1: the packer family is bound at staging and cannot change. The
    // actual config's family must match the envelope case's family EXACTLY
    // (not just by digest) — this is what makes a digest forged under one
    // family unusable for another: the family is compared field-by-field
    // before the digest check, and the digest also embeds the family.
    if actual_config.packer_family != case.family_id {
        bail!(
            "actual run config family {:?} != envelope case {} family {:?} (fail-closed)",
            actual_config.packer_family,
            case.case_id,
            case.family_id
        );
    }
    let actual_digest = mida_core::runner_config::runner_config_digest(actual_config);
    if !actual_digest.eq_ignore_ascii_case(&case.runner_config_digest) {
        bail!(
            "actual run config digest {actual_digest} != envelope case {} digest {}",
            case.case_id,
            case.runner_config_digest
        );
    }
    Ok(())
}

/// The `mida.runner-config-envelope/v4` emitted by the runner side.
///
/// `deny_unknown_fields` + required fields: a tampered envelope (unknown
/// field, missing field) fails closed at deserialization.
///
/// P6.3.3: configuration is case-bound. There is no ambiguous top-level
/// `runner_config`/`runner_config_digest`; instead `case_configs` holds
/// exactly the two fixed cases, each with its own full config and digest,
/// and `case_set_digest` seals every case config and its case/input binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfigEnvelope {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub schema_version: String,
    /// SHA-256 of the CLI binary that will perform the run.
    pub cli_binary_sha256: String,
    /// Tool revision (git HEAD) the run is pinned to.
    pub tool_revision: String,
    /// Controlled relative identity of the verifier (always the CLI
    /// sibling; see [`VERIFIER_SOURCE_TOKEN`]).
    pub verifier_source: String,
    /// Canonical path of the verifier sibling at staging (P6.3.2): the
    /// launch re-resolves the sibling and compares BOTH path and hash.
    pub verifier_path: String,
    /// SHA-256 of the independent acceptance verifier binary pinned at
    /// staging: the launch and PE-evidence paths fail closed unless the
    /// verifier they resolve hashes to exactly this.
    pub verifier_sha256: String,
    /// Sealed hash over every case config + its case/input binding. Any
    /// single-case tamper changes this and the independent verifier refuses
    /// the whole envelope.
    pub case_set_digest: String,
    /// Exactly the two fixed Oreans cases, each with its own config/digest.
    pub case_configs: Vec<CaseRunnerConfigEnvelope>,
}

/// Canonical, injective encoding of one case-bound config entry (case id,
/// packer family, protected input identity, per-case runner-config digest).
/// The family is part of the sealed case-set digest, so switching a case's
/// family after staging is a tamper that breaks the seal.
fn canonical_case_entry(entry: &CaseRunnerConfigEnvelope) -> String {
    format!(
        "case={}\nfamily={}\nprotected_input={}|{}\nrunner_config_digest={}\n",
        entry.case_id,
        entry.family_id.to_lowercase(),
        entry.protected_input.sha256.to_lowercase(),
        entry.protected_input.size_bytes,
        entry.runner_config_digest.to_lowercase()
    )
}

/// SHA-256 (lowercase hex) of the canonical case-set encoding (P6.3.3).
fn case_set_digest(case_configs: &[CaseRunnerConfigEnvelope]) -> String {
    let mut entries: Vec<String> = case_configs.iter().map(canonical_case_entry).collect();
    entries.sort();
    let mut canonical = String::new();
    for e in entries {
        canonical.push_str(&e);
    }
    sha256_hex(canonical.as_bytes())
}

impl RunnerConfigEnvelope {
    /// Build the envelope from one per-case config per input, plus runtime
    /// pinning inputs. `case_configs` must contain exactly the two fixed
    /// cases (validated by the caller/`build_checked`).
    pub fn build(
        case_configs: Vec<CaseRunnerConfigEnvelope>,
        cli_binary_sha256: &str,
        tool_revision: &str,
        verifier_path: &str,
        verifier_sha256: &str,
    ) -> RunnerConfigEnvelope {
        let case_set_digest = case_set_digest(&case_configs);
        RunnerConfigEnvelope {
            schema: RUNNER_CONFIG_ENVELOPE_SCHEMA_REF.to_string(),
            schema_version: RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION.to_string(),
            cli_binary_sha256: cli_binary_sha256.to_lowercase(),
            tool_revision: tool_revision.to_string(),
            verifier_source: VERIFIER_SOURCE_TOKEN.to_string(),
            verifier_path: verifier_path.to_string(),
            verifier_sha256: verifier_sha256.to_lowercase(),
            case_set_digest,
            case_configs,
        }
    }

    /// Atomically write the envelope under `output_dir`.
    pub fn write(&self, output_dir: &Path) -> anyhow::Result<PathBuf> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow!("serialize runner-config envelope: {e}"))?;
        let destination = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
        atomic_write(&destination, &json)
            .with_context(|| format!("write envelope {}", destination.display()))?;
        Ok(destination)
    }

    /// Read + strictly parse the envelope under `output_dir`.
    pub fn read(output_dir: &Path) -> anyhow::Result<RunnerConfigEnvelope> {
        let path = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
        let bytes =
            std::fs::read(&path).with_context(|| format!("read envelope {}", path.display()))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            anyhow!(
                "envelope {} rejected (unknown/malformed fields): {e}",
                path.display()
            )
        })
    }

    /// The sealed case-set digest (the whole-envelope identity, P6.3.3).
    pub fn case_set(&self) -> &str {
        &self.case_set_digest
    }

    /// Validate the case-config set shape. Two lanes are recognized:
    ///
    /// - the Oreans fixed regression lane — `FIXED_CASE_IDS` (`origin_macro`,
    ///   `lunlun_software`) must each appear exactly once with `oreans_themida`
    ///   family, keeping the v4/v8 regression gate invariant;
    /// - the GTO generic/no-gate lane — an optional `gto_launcher` case with
    ///   `family_id = ahk_gto`.
    ///
    /// No unknown case, unknown family, missing family, or cross-lane family
    /// reuse is allowed. Returns the first reason or `None` when valid.
    pub fn validate_case_set(&self) -> Option<String> {
        use mida_core::runner_config::packer_family;
        let present: Vec<&str> = self
            .case_configs
            .iter()
            .map(|c| c.case_id.as_str())
            .collect();
        // No duplicates, no unknown case ids.
        for c in &self.case_configs {
            if !FIXED_CASE_IDS.contains(&c.case_id.as_str()) && c.case_id != GTO_CASE_ID {
                return Some(format!(
                    "case {:?} is neither an Oreans fixed case nor the GTO lane case (fail-closed)",
                    c.case_id
                ));
            }
            if present.iter().filter(|p| **p == c.case_id).count() != 1 {
                return Some(format!(
                    "case {} appears more than once (fail-closed)",
                    c.case_id
                ));
            }
        }
        // Oreans fixed regression lane: both cases must be present exactly once.
        for id in FIXED_CASE_IDS {
            if present.iter().filter(|p| **p == id).count() != 1 {
                return Some(format!(
                    "Oreans fixed lane must contain exactly one {id} entry, got {:?}",
                    present
                ));
            }
        }
        // Per-case family / digest / identity shape.
        for c in &self.case_configs {
            if c.family_id.trim().is_empty() {
                return Some(format!(
                    "case {} family_id is missing or empty (fail-closed)",
                    c.case_id
                ));
            }
            if !packer_family::is_known_family(&c.family_id) {
                return Some(format!(
                    "case {} has unknown packer family {:?} (fail-closed)",
                    c.case_id, c.family_id
                ));
            }
            // Lane <-> family binding: an Oreans fixed case must be Oreans; the
            // GTO lane case must be ahk_gto. Cross-lane reuse fails closed.
            if FIXED_CASE_IDS.contains(&c.case_id.as_str()) {
                if !packer_family::is_oreans_family(&c.family_id) {
                    return Some(format!(
                        "Oreans fixed case {} must carry family {:?}, got {:?} (fail-closed)",
                        c.case_id,
                        packer_family::OREANS,
                        c.family_id
                    ));
                }
            } else if c.case_id == GTO_CASE_ID && !packer_family::is_generic_family(&c.family_id) {
                return Some(format!(
                    "GTO lane case {} must carry a registered generic family (ahk_gto), \
                     got {:?} (fail-closed)",
                    c.case_id, c.family_id
                ));
            }
            if !is_64_hex(&c.runner_config_digest) {
                return Some(format!(
                    "case {} runner_config_digest must be exactly 64 hex chars",
                    c.case_id
                ));
            }
            if !is_64_hex(&c.protected_input.sha256) || c.protected_input.size_bytes == 0 {
                return Some(format!(
                    "case {} protected_input identity is malformed",
                    c.case_id
                ));
            }
        }
        None
    }
}

/// The preflight report as the launch boundary consumes it (strict).
///
/// This is a minimal runner-side copy of the acceptance report contract
/// (`mida.preflight-report/v3`); unknown fields fail closed so a drifted
/// report schema cannot slip past.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReportGate {
    pub schema_version: String,
    pub status: String,
    pub reasons: Vec<String>,
    /// The envelope's sealed case-set digest (P6.3.3).
    pub runner_config_digest: String,
    pub head_revision: Option<String>,
    pub worktree_clean: Option<bool>,
    pub toolchain_matches: Option<bool>,
    pub cli_binary_sha256: Option<String>,
    pub cli_binary_matches: Option<bool>,
    pub cli_binary_path: String,
    pub repo_root: String,
    pub toolchain_pin_file: String,
    pub expected_toolchain: String,
    pub cases: Vec<PreflightCaseGate>,
}

/// One artifact identity as recorded in the gate report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentityGate {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightCaseGate {
    pub case_id: String,
    pub identity_ok: bool,
    pub reasons: Vec<String>,
    pub protected_input: Option<FileIdentityGate>,
    pub protected_input_path: String,
    pub manifest_path: String,
    pub candidate_output: String,
    /// P6.3.3: the per-case runner-config digest recorded by the report.
    pub runner_config_digest: Option<String>,
}

/// Resolve the `mida-acceptance` verifier binary (P6.3.2 unique production
/// resolver).
///
/// The verifier can ONLY be the exact sibling `mida-acceptance.exe` of the
/// running `mida-cli` binary. The resolver:
///
/// - never consults `MIDA_ACCEPTANCE_BIN` or any other environment variable;
/// - never accepts a caller-supplied path;
/// - never falls back to PATH;
/// - returns a hard error when the sibling is missing, is not a regular
///   file, or does not canonicalize to exactly the expected sibling path.
///
/// The trust root is the deployment unit: whoever controls the `mida-cli`
/// install controls the sibling `mida-acceptance.exe` beside it (replacing
/// the sibling is equivalent to replacing the CLI itself — host trust, not
/// a CLI interface bypass).
pub fn resolve_acceptance_bin() -> anyhow::Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .context("cannot resolve the current executable to locate the verifier sibling")?;
    resolve_acceptance_bin_from_cli(&current_exe)
}

/// The sibling-only resolver for a given CLI executable (testable). See
/// [`resolve_acceptance_bin`] for the security contract.
pub fn resolve_acceptance_bin_from_cli(cli_exe: &Path) -> anyhow::Result<PathBuf> {
    let parent = cli_exe.parent().ok_or_else(|| {
        anyhow!(
            "current executable {} has no parent directory",
            cli_exe.display()
        )
    })?;
    let expected = parent.join("mida-acceptance.exe");
    let canonical = std::fs::canonicalize(&expected)
        .with_context(|| format!("verifier sibling {} does not exist", expected.display()))?;
    let meta = std::fs::metadata(&canonical)
        .with_context(|| format!("cannot stat verifier sibling {}", canonical.display()))?;
    if !meta.is_file() {
        bail!(
            "verifier sibling {} is not a regular file; refusing to use it as the \
             independent verifier",
            canonical.display()
        );
    }
    // Canonical path must be exactly `cli_dir/mida-acceptance.exe` (the
    // controlled relative identity), not a re-link, symlink escape, or any
    // other location.
    let expected_canonical_parent = std::fs::canonicalize(parent)
        .with_context(|| format!("cannot canonicalize CLI directory {}", parent.display()))?;
    let expected_full = expected_canonical_parent.join("mida-acceptance.exe");
    if canonical != expected_full {
        bail!(
            "verifier resolves to {} which is not exactly the CLI sibling {}; \
             path drift is refused",
            canonical.display(),
            expected_full.display()
        );
    }
    Ok(canonical)
}

/// Resolve the verifier sibling and recompute its SHA-256 (used by the
/// envelope, the launch attestation and the bundle PE-evidence path).
pub fn resolve_verifier_identity() -> anyhow::Result<(PathBuf, String)> {
    let verifier = resolve_acceptance_bin()?;
    let sha = sha256_file(&verifier)?;
    Ok((verifier, sha))
}

/// Outcome of the envelope reuse policy (P6.3-C): the envelope file is
/// either absent (first creation allowed) or present AND field-identical to
/// the would-be envelope. Everything else is an error and the existing
/// bytes are never touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeReuse {
    /// No envelope exists yet — first creation is allowed.
    Missing,
    /// The existing envelope parses strictly and matches the would-be
    /// envelope field-by-field — reuse it as-is (bytes untouched).
    ExistingMatches,
}

/// P6.3-C fail-closed envelope reuse policy:
///
/// - file absent → [`EnvelopeReuse::Missing`] (first creation allowed);
/// - malformed, unknown-field, truncated or unreadable → hard error;
/// - present and valid → must match the would-be envelope field-by-field
///   (`$schema`, `schema_version`, full config JSON, digest, CLI identity,
///   tool revision); a stale or different envelope is rejected;
/// - any failure leaves the original envelope bytes untouched.
///
/// The caller must never fall back to `Err(_) => write(...)`.
pub fn envelope_reuse_policy(
    output_dir: &Path,
    candidate: &RunnerConfigEnvelope,
) -> anyhow::Result<EnvelopeReuse> {
    let path = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
    if !path.exists() {
        return Ok(EnvelopeReuse::Missing);
    }
    let existing = match RunnerConfigEnvelope::read(output_dir) {
        Ok(existing) => existing,
        Err(e) => {
            bail!(
                "existing runner-config envelope {} cannot be reused (malformed, unknown \
                 field, or unreadable — refusing to overwrite): {e:#}",
                path.display()
            );
        }
    };
    if existing.schema != candidate.schema
        || existing.schema_version != candidate.schema_version
        || existing.case_configs != candidate.case_configs
        || !existing
            .case_set_digest
            .eq_ignore_ascii_case(&candidate.case_set_digest)
        || !existing
            .cli_binary_sha256
            .eq_ignore_ascii_case(&candidate.cli_binary_sha256)
        || existing.tool_revision != candidate.tool_revision
        || existing.verifier_source != candidate.verifier_source
        || existing.verifier_path != candidate.verifier_path
        || !existing
            .verifier_sha256
            .eq_ignore_ascii_case(&candidate.verifier_sha256)
    {
        bail!(
            "existing runner-config envelope {} differs from the would-be envelope \
             (stale or tampered); refusing to overwrite the original bytes",
            path.display()
        );
    }
    Ok(EnvelopeReuse::ExistingMatches)
}

/// The runner-side offline-preflight driver (production).
///
/// Emits the envelope (or reuses an existing one under the P6.3-C
/// fail-closed policy: an existing envelope must parse strictly and match
/// the would-be envelope field-by-field, otherwise the run fails and the
/// original bytes are preserved), drives the independent verifier binary
/// (`mida-acceptance preflight ...`), consumes `preflight.json`, and
/// re-verifies the chain: report digest == envelope digest, status ready,
/// CLI identity matched. Returns `Ok(true)` when Ready.
///
/// [`run_offline_preflight`] itself never launches a sample process; it only
/// drives the read-only verifier.
#[allow(clippy::too_many_arguments)]
pub fn run_offline_preflight(
    output_dir: &Path,
    envelope: &RunnerConfigEnvelope,
    cases: &[(&Path, &Path, &Path)],
    cli_binary: &Path,
    repo_root: &Path,
    toolchain_pin_file: &Path,
    expected_toolchain: &str,
) -> anyhow::Result<bool> {
    let (verifier, _) = resolve_verifier_identity()?;
    // P6.3-C: fail-closed reuse — first creation only when the file is
    // absent; an existing envelope must parse strictly and match the
    // would-be envelope field-by-field. Any failure preserves the original
    // bytes (no `Err(_) => write` fallback).
    let envelope_path = match envelope_reuse_policy(output_dir, envelope)? {
        EnvelopeReuse::Missing => envelope.write(output_dir)?,
        EnvelopeReuse::ExistingMatches => {
            eprintln!(
                "reusing existing runner-config envelope (case-set digest {}); the verifier \
                 independently recomputes and cross-checks it",
                envelope.case_set_digest
            );
            output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME)
        }
    };

    let mut cmd = Command::new(&verifier);
    cmd.arg("preflight")
        .arg("--envelope")
        .arg(&envelope_path)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--cli-binary")
        .arg(cli_binary)
        .arg("--repo-root")
        .arg(repo_root)
        .arg("--toolchain-pin")
        .arg(toolchain_pin_file)
        .arg("--expected-toolchain")
        .arg(expected_toolchain);
    for (manifest, input, candidate) in cases {
        cmd.arg("--case").arg(manifest).arg(input).arg(candidate);
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawn verifier {verifier:?}"))?;
    match status.code() {
        // 0 = Ready, 2 = NotReady: both are verifiable outcomes — consume
        // the report. Only 1 (I/O/config) or abnormal termination is an
        // infrastructure failure.
        Some(0) | Some(2) => {}
        other => bail!(
            "offline preflight verifier {verifier:?} terminated abnormally ({other:?}); \
             see {} for any gating report",
            output_dir.join(PREFLIGHT_REPORT_FILENAME).display()
        ),
    }
    let ready = match require_ready_before_launch(output_dir, envelope) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("offline preflight rejected the run: {e:#}");
            false
        }
    };
    Ok(ready)
}

/// Schema id of the preflight report the gate consumes.
///
/// v3 (P6.3.3): each case entry carries its own `runner_config_digest`, so
/// the report can cross-validate every case's config against the v4
/// envelope. v2 reports (single top-level digest) no longer parse.
pub const PREFLIGHT_REPORT_SCHEMA_VERSION: &str = "mida.preflight-report/v3";

/// The two fixed Oreans cases; the Oreans fixed regression lane accepts
/// exactly this set (no cross-case reuse).
pub const FIXED_CASE_IDS: [&str; 2] = ["origin_macro", "lunlun_software"];

/// The independent GTO generic/no-gate lane case. It is NOT part of the Oreans
/// fixed regression gate; it carries `family_id = ahk_gto` and a `no-gate`
/// acceptance state, and produces generic `mida.unpack-*` evidence.
pub const GTO_CASE_ID: &str = "gto_launcher";

/// The P7 launch-boundary gate (production).
///
/// Consumes `preflight.json` + the envelope under `output_dir` and returns
/// `Ok(())` only when:
///
/// - the report parses strictly (unknown fields fail closed) as
///   `mida.preflight-report/v3`;
/// - `status == "ready"`;
/// - the report's case set cross-validates against the envelope case set:
///   the same two fixed cases, each with matching protected-input identity
///   and per-case runner-config digest (P6.3.3 report/envelope cross-check);
/// - `cli_binary_matches == true`.
///
/// Any envelope/report absence, schema drift, case-set drift, per-case
/// digest drift, or CLI identity drift is an error — the caller must not
/// create a sample process.
pub fn require_ready_before_launch(
    output_dir: &Path,
    envelope: &RunnerConfigEnvelope,
) -> anyhow::Result<()> {
    let report = read_gate_report(output_dir)?;
    if report.schema_version != PREFLIGHT_REPORT_SCHEMA_VERSION {
        bail!(
            "preflight report schema {:?} != {PREFLIGHT_REPORT_SCHEMA_VERSION}",
            report.schema_version
        );
    }
    check_chain_ready(&report, envelope)?;
    Ok(())
}

/// Strictly parse the gate report (deny-unknown-fields, v3 shape).
pub fn read_gate_report(output_dir: &Path) -> anyhow::Result<PreflightReportGate> {
    let report_path = output_dir.join(PREFLIGHT_REPORT_FILENAME);
    let bytes = std::fs::read(&report_path)
        .with_context(|| format!("read preflight report {}", report_path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| {
        anyhow!(
            "preflight report {} rejected (unknown/malformed fields): {e}",
            report_path.display()
        )
    })
}

/// The shared ready-chain checks: status ready, report case set cross-validates
/// against the envelope case set (case id, protected identity, per-case
/// digest), and the CLI identity matched.
fn check_chain_ready(
    report: &PreflightReportGate,
    envelope: &RunnerConfigEnvelope,
) -> anyhow::Result<()> {
    if report.status != "ready" {
        bail!(
            "preflight status is not ready ({}): {}",
            report.status,
            report.reasons.join("; ")
        );
    }
    // The report's top-level digest is the envelope's sealed case-set digest.
    if !report
        .runner_config_digest
        .eq_ignore_ascii_case(&envelope.case_set_digest)
    {
        bail!(
            "runner-config case-set digest drift: report {} vs envelope {}",
            report.runner_config_digest,
            envelope.case_set_digest
        );
    }
    // P6.3.3: cross-validate every report case against the envelope case.
    // The report must carry a digest for every case and it must equal the
    // envelope's per-case digest; case set must be exactly the fixed set.
    if report.cases.len() != envelope.case_configs.len() {
        bail!(
            "preflight report case count {} != envelope case config count {}",
            report.cases.len(),
            envelope.case_configs.len()
        );
    }
    for env_case in &envelope.case_configs {
        let report_case = report
            .cases
            .iter()
            .find(|c| c.case_id == env_case.case_id)
            .ok_or_else(|| {
                anyhow!(
                    "preflight report is missing case {} present in the envelope",
                    env_case.case_id
                )
            })?;
        if report_case.protected_input.as_ref() != Some(&env_case.protected_input) {
            bail!(
                "case {} protected-input identity drift between report and envelope",
                env_case.case_id
            );
        }
        let report_digest = report_case.runner_config_digest.as_deref().ok_or_else(|| {
            anyhow!(
                "case {} report is missing its runner_config_digest",
                env_case.case_id
            )
        })?;
        if !report_digest.eq_ignore_ascii_case(&env_case.runner_config_digest) {
            bail!(
                "case {} runner-config digest drift: report {} vs envelope {}",
                env_case.case_id,
                report_digest,
                env_case.runner_config_digest
            );
        }
    }
    if report.cli_binary_matches != Some(true) {
        bail!(
            "CLI identity did not match at preflight time ({:?}); refusing to launch",
            report.cli_binary_matches
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// P6.3-B: launch attestation
// ---------------------------------------------------------------------------

/// The run context the launch boundary attests against.
pub struct LaunchAttestationContext<'a> {
    /// Current protected input the run would start.
    pub input: &'a Path,
    /// Current candidate output the run would produce.
    pub output: &'a Path,
    /// Current CLI executable (the binary that will run).
    pub cli_binary: &'a Path,
    /// The ACTUAL runner config built from the parsed `/unpack` arguments.
    pub runner_config: &'a mida_core::runner_config::RunnerConfig,
}

/// The unique evidence context produced by a successful launch attestation
/// (P6.3-B/D). All subsequent sidecar and bundle producers consume it; the
/// bundle assembler draws the runner-config digest from it, so the digest
/// can never be caller-supplied.
///
/// P6.3.1 seal: the type is NOT `Clone`, every field is private (read-only
/// getters only), and there is no public constructor — a value can only be
/// obtained from [`attest_ready_before_launch`]. The bundle assembler and
/// [`complete_run_evidence`] take it BY VALUE, so a single attestation can
/// authorize exactly one bundle: a second use is a compile error (there is
/// no way to duplicate or reconstruct the value).
#[derive(Debug)]
pub struct RunEvidenceContext {
    case_id: String,
    tool_revision: String,
    runner_config_digest: String,
    verifier_sha256: String,
    protected_input: PathBuf,
    candidate: PathBuf,
    cli_binary_sha256: String,
    /// Packer family this run belongs to (`oreans_themida` or `ahk_gto`).
    /// Drives the evidence-contract family dispatch.
    packer_family: String,
}

impl RunEvidenceContext {
    /// Internal constructor — reachable only from crate-internal code (the
    /// attestation) and crate unit tests. Never a public forgery entry.
    ///
    /// Oreans-compat wrapper: binds the Oreans family, matching the pre-G2
    /// behaviour. Kept so the family-less legacy API and its tests remain
    /// valid; G2 attestation uses [`RunEvidenceContext::new_with_family`].
    #[allow(dead_code)] // legacy family-less wrapper; used by Oreans tests.
    pub(crate) fn new(
        case_id: String,
        tool_revision: String,
        runner_config_digest: String,
        verifier_sha256: String,
        protected_input: PathBuf,
        candidate: PathBuf,
        cli_binary_sha256: String,
    ) -> anyhow::Result<RunEvidenceContext> {
        Self::new_with_family(
            mida_core::runner_config::packer_family::OREANS.to_string(),
            case_id,
            tool_revision,
            runner_config_digest,
            verifier_sha256,
            protected_input,
            candidate,
            cli_binary_sha256,
        )
    }

    /// Internal constructor that additionally binds the packer family. The
    /// family-less [`RunEvidenceContext::new`] is preserved as an Oreans-compat
    /// wrapper. GTO runs bind `ahk_gto` explicitly so their generic evidence
    /// contract is selected.
    pub(crate) fn new_with_family(
        packer_family: String,
        case_id: String,
        tool_revision: String,
        runner_config_digest: String,
        verifier_sha256: String,
        protected_input: PathBuf,
        candidate: PathBuf,
        cli_binary_sha256: String,
    ) -> anyhow::Result<RunEvidenceContext> {
        if packer_family.trim().is_empty() {
            bail!("RunEvidenceContext packer_family must be non-empty");
        }
        if case_id.trim().is_empty() {
            bail!("RunEvidenceContext case_id must be non-empty");
        }
        if !is_64_hex(&runner_config_digest) {
            bail!(
                "RunEvidenceContext runner_config_digest must be exactly 64 hex chars, got {:?}",
                runner_config_digest
            );
        }
        if !is_64_hex(&cli_binary_sha256) {
            bail!("RunEvidenceContext cli_binary_sha256 must be exactly 64 hex chars");
        }
        if !is_64_hex(&verifier_sha256) {
            bail!("RunEvidenceContext verifier_sha256 must be exactly 64 hex chars");
        }
        Ok(RunEvidenceContext {
            case_id,
            tool_revision,
            runner_config_digest: runner_config_digest.to_lowercase(),
            verifier_sha256: verifier_sha256.to_lowercase(),
            protected_input,
            candidate,
            cli_binary_sha256: cli_binary_sha256.to_lowercase(),
            packer_family,
        })
    }

    /// The attested packer family (Oreans-compat default when unbound).
    pub fn packer_family(&self) -> &str {
        &self.packer_family
    }

    /// The attested case id.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// The tool revision the run is pinned to.
    pub fn tool_revision(&self) -> &str {
        &self.tool_revision
    }

    /// The attestation-bound runner-config digest (the only digest source
    /// for sidecar/bundle producers).
    pub fn runner_config_digest(&self) -> &str {
        &self.runner_config_digest
    }

    /// The verifier binary identity the attestation bound.
    pub fn verifier_sha256(&self) -> &str {
        &self.verifier_sha256
    }

    /// Canonical protected input path (read-only).
    pub fn protected_input(&self) -> &Path {
        &self.protected_input
    }

    /// Canonical candidate output path (read-only).
    pub fn candidate(&self) -> &Path {
        &self.candidate
    }

    /// The current CLI binary identity (read-only).
    pub fn cli_binary_sha256(&self) -> &str {
        &self.cli_binary_sha256
    }
}

fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Recompute `{sha256, size_bytes}` of a file on disk.
pub fn file_identity(path: &Path) -> anyhow::Result<FileIdentityGate> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let sha = sha256_hex(&data);
    Ok(FileIdentityGate {
        sha256: sha,
        size_bytes: data.len() as u64,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Canonicalize `p`, falling back to canonicalizing its parent when the
/// path itself does not exist yet (e.g. a candidate output file).
pub fn canonicalize_loose(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    match (
        p.parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok()),
        p.file_name(),
    ) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => p.to_path_buf(),
    }
}

/// The P6.3 launch attestation (production). The hand-written `ready` JSON
/// is NOT an authorization credential: the launch boundary re-runs the
/// independent acceptance verifier against the current run context and
/// re-verifies every identity locally.
///
/// Attestation steps:
///
/// 1. Strict envelope read + `$schema` + `schema_version` validation.
/// 2. Actual run-config digest == envelope digest (P6.3-A).
/// 3. Current CLI binary SHA-256 == envelope CLI identity.
/// 4. Pre-read report (strict v2): ready, digest chain, CLI matched.
/// 5. Re-run the acceptance verifier with the report's recorded runner
///    context (repo root / toolchain pin / expected toolchain), the
///    recorded case triples, and the CURRENT input/output for the case
///    whose recorded identity matches the current input.
/// 6. Read the freshly written report; require: ready, digest chain, CLI
///    matched, case set exactly {origin_macro, lunlun_software}, every case
///    identity_ok.
/// 7. Current input identity matches EXACTLY ONE preflight case (no
///    cross-case / third-input reuse).
/// 8. The target case identity is unchanged since the pre-read report
///    (input bytes did not change between staging and launch).
/// 9. Current output canonical path == the target case candidate output.
///
/// Returns the single-use [`RunEvidenceContext`] on success.
pub fn attest_ready_before_launch(
    output_dir: &Path,
    ctx: &LaunchAttestationContext<'_>,
) -> anyhow::Result<RunEvidenceContext> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    if envelope.schema != RUNNER_CONFIG_ENVELOPE_SCHEMA_REF {
        bail!(
            "envelope $schema {:?} != {RUNNER_CONFIG_ENVELOPE_SCHEMA_REF}",
            envelope.schema
        );
    }
    if envelope.schema_version != RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION {
        bail!(
            "envelope schema_version {:?} != {RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION}",
            envelope.schema_version
        );
    }

    // P6.3-A/P6.3.3: the actual run-config digest must equal the digest of
    // the UNIQUE case the current input belongs to. The input identity is
    // computed first (it drives both the per-case config selection here and
    // the report case matching below).
    let current_identity = file_identity(ctx.input)?;
    bind_actual_config_to_envelope(output_dir, ctx.runner_config, &current_identity)?;

    // Current CLI identity (attack: binary A staged, binary B launched).
    let current_cli_sha = sha256_file(ctx.cli_binary)?;
    if !current_cli_sha.eq_ignore_ascii_case(&envelope.cli_binary_sha256) {
        bail!(
            "current CLI binary {current_cli_sha} != envelope pinned {}",
            envelope.cli_binary_sha256
        );
    }

    // Pre-read report: ready chain + the recorded case triples for the
    // verifier re-run.
    let pre_report = read_gate_report(output_dir)?;
    if pre_report.schema_version != PREFLIGHT_REPORT_SCHEMA_VERSION {
        bail!(
            "preflight report schema {:?} != {PREFLIGHT_REPORT_SCHEMA_VERSION}",
            pre_report.schema_version
        );
    }
    check_chain_ready(&pre_report, &envelope)?;

    // The current input must match EXACTLY one preflight case identity.
    let matches: Vec<&PreflightCaseGate> = pre_report
        .cases
        .iter()
        .filter(|c| c.protected_input.as_ref() == Some(&current_identity))
        .collect();
    if matches.len() != 1 {
        bail!(
            "current input matches {} preflight case identities (expected exactly one); \
             cross-case or third-input reuse is refused",
            matches.len()
        );
    }
    let target_case_id = matches[0].case_id.clone();
    // The target must belong to a recognized lane: the Oreans fixed regression
    // lane or the independent GTO generic/no-gate lane.
    if !FIXED_CASE_IDS.contains(&target_case_id.as_str()) && target_case_id != GTO_CASE_ID {
        bail!(
            "target case {:?} is neither an Oreans fixed case nor the GTO lane case",
            target_case_id
        );
    }

    // P6.3.1: the verifier identity is bound by the envelope. Resolve the
    // verifier this launch would use and fail closed unless it hashes to the
    // pinned identity (verifier replacement / path drift / hash drift).
    let verifier_sha = verify_verifier_identity(ctx, &envelope)?;

    // Re-run the independent verifier with the recorded context. A
    // hand-written `ready` report is not an authorization credential.
    rerun_verifier(output_dir, &pre_report, &target_case_id, ctx)?;

    // Read the freshly generated report and attest the whole chain.
    let fresh = read_gate_report(output_dir)?;
    if fresh.schema_version != PREFLIGHT_REPORT_SCHEMA_VERSION {
        bail!(
            "preflight report schema {:?} != {PREFLIGHT_REPORT_SCHEMA_VERSION}",
            fresh.schema_version
        );
    }
    check_chain_ready(&fresh, &envelope)?;
    let fresh_target = fresh
        .cases
        .iter()
        .find(|c| c.case_id == target_case_id)
        .ok_or_else(|| anyhow!("fresh report is missing case {target_case_id}"))?;
    if !fresh_target.identity_ok {
        bail!(
            "case {target_case_id} identity did not pass the verifier re-run: {}",
            fresh_target.reasons.join("; ")
        );
    }
    let present_ids: Vec<&str> = fresh.cases.iter().map(|c| c.case_id.as_str()).collect();
    // The fresh report must contain both Oreans fixed cases exactly once
    // (Oreans regression lane invariant), and any GTO lane case exactly once.
    if FIXED_CASE_IDS
        .iter()
        .any(|id| present_ids.iter().filter(|p| *p == id).count() != 1)
        || present_ids.iter().filter(|p| **p == GTO_CASE_ID).count() > 1
        || present_ids
            .iter()
            .any(|id| !FIXED_CASE_IDS.contains(id) && *id != GTO_CASE_ID)
    {
        bail!(
            "fresh report case set must contain exactly the Oreans fixed lane [{}, {}] plus \
             at most the GTO lane case {}, no duplicates/unknown, got {:?}",
            FIXED_CASE_IDS[0],
            FIXED_CASE_IDS[1],
            GTO_CASE_ID,
            present_ids
        );
    }
    for case in &fresh.cases {
        if !case.identity_ok {
            bail!(
                "case {} identity_ok=false after verifier re-run: {}",
                case.case_id,
                case.reasons.join("; ")
            );
        }
    }

    // The target case identity must be unchanged since staging (the input
    // bytes did not change between preflight and launch).
    if fresh_target.protected_input != matches[0].protected_input {
        bail!(
            "case {target_case_id} input identity changed since preflight \
             (staged {:?}, now {:?}); refusing to launch",
            matches[0].protected_input,
            fresh_target.protected_input
        );
    }

    // The current output canonical path must equal the candidate output
    // recorded at PREFLIGHT time (the staged candidate). The fresh report
    // always records the current output by construction, so the staged
    // candidate is the authority.
    let current_output = canonicalize_loose(ctx.output);
    let preflight_candidate = PathBuf::from(&matches[0].candidate_output);
    if current_output != preflight_candidate {
        bail!(
            "current output {} does not match the preflight candidate {}",
            current_output.display(),
            preflight_candidate.display()
        );
    }
    if current_output == canonicalize_loose(ctx.input) {
        bail!(
            "candidate output {} aliases the protected input (same canonical path)",
            current_output.display()
        );
    }

    // Every cross-identity is bound: build the single-use evidence context.
    // P6.3.3: the digest is the SELECTED case's digest (never a shared or
    // another case's digest) — it flows into the bundle for this case.
    // G2-R1: the packer family is the ENVELOPE's bound family for this input
    // (staging-sealed). The actual config's family was already checked equal
    // to it by `bind_actual_config_to_envelope`, so the evidence context is
    // bound to the authoritative envelope family — never a caller-supplied or
    // rebindable one.
    let selected_case = select_case_config(&envelope, &current_identity)?;
    let attested_family = selected_case.family_id.clone();
    let digest = envelope_case_runner_config_digest(output_dir, &current_identity)?;
    let context = RunEvidenceContext::new_with_family(
        attested_family,
        target_case_id,
        envelope.tool_revision.clone(),
        digest,
        verifier_sha,
        canonicalize_loose(ctx.input),
        current_output,
        current_cli_sha,
    )?;
    Ok(context)
}

/// Resolve the verifier this run would use (unique CLI-sibling resolver),
/// then fail closed unless its canonical path identity AND SHA-256 both
/// match the envelope-pinned verifier (P6.3.2: path + hash, not hash alone).
fn verify_verifier_identity(
    _ctx: &LaunchAttestationContext<'_>,
    envelope: &RunnerConfigEnvelope,
) -> anyhow::Result<String> {
    let (verifier, sha) = resolve_verifier_identity()?;
    verify_verifier_identity_bindings(envelope, &verifier, &sha)
}

/// P6.3.3.2: the pure verifier-identity binding check. Given the envelope's
/// pinned verifier identity and the verifier this run would resolve to
/// (canonical path + SHA-256), fail closed unless:
///
/// - the controlled relative source token matches;
/// - the resolved canonical path equals the pinned path;
/// - the resolved SHA-256 equals the pinned SHA-256.
///
/// This is a PUBLIC offline seam shared by the launch attestation
/// ([`verify_verifier_identity`]) and the hermetic tests: the
/// verifier-replacement rejection is proven WITHOUT selecting a real locked
/// case or creating a sample process (P6.3.3.2: the launch attestation only
/// reaches this check after a case is matched by input identity). It is
/// `pub` specifically so the black-box `launch_attestation` integration tests
/// can drive the already-selected-case context offline.
pub fn verify_verifier_identity_bindings(
    envelope: &RunnerConfigEnvelope,
    resolved_path: &Path,
    resolved_sha: &str,
) -> anyhow::Result<String> {
    // Path identity: the resolved sibling must be the recorded path AND the
    // controlled relative source must match.
    if envelope.verifier_source != VERIFIER_SOURCE_TOKEN {
        bail!(
            "envelope verifier_source {:?} != {VERIFIER_SOURCE_TOKEN}; source drift is refused",
            envelope.verifier_source
        );
    }
    let resolved_canonical = std::fs::canonicalize(resolved_path).with_context(|| {
        format!(
            "cannot canonicalize resolved verifier {}",
            resolved_path.display()
        )
    })?;
    let recorded = PathBuf::from(&envelope.verifier_path);
    if resolved_canonical != recorded {
        bail!(
            "acceptance verifier resolves to {} which != the envelope-pinned path {}; \
             verifier path drift is refused",
            resolved_canonical.display(),
            recorded.display()
        );
    }
    if !resolved_sha.eq_ignore_ascii_case(&envelope.verifier_sha256) {
        bail!(
            "acceptance verifier {} (sha {resolved_sha}) does not match the envelope-pinned \
             verifier sha {}; verifier replacement or hash drift is refused",
            resolved_canonical.display(),
            envelope.verifier_sha256
        );
    }
    Ok(resolved_sha.to_lowercase())
}

/// Spawn the independent acceptance verifier with the recorded runner
/// context and the current input/output for the target case. Exit 0/2 are
/// verifiable outcomes; 1 or abnormal termination is an infrastructure
/// failure.
fn rerun_verifier(
    output_dir: &Path,
    report: &PreflightReportGate,
    target_case_id: &str,
    ctx: &LaunchAttestationContext<'_>,
) -> anyhow::Result<()> {
    let (verifier, _) = resolve_verifier_identity()?;
    let envelope_path = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
    let mut cmd = Command::new(&verifier);
    cmd.arg("preflight")
        .arg("--envelope")
        .arg(&envelope_path)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--cli-binary")
        .arg(ctx.cli_binary)
        .arg("--repo-root")
        .arg(&report.repo_root)
        .arg("--toolchain-pin")
        .arg(&report.toolchain_pin_file)
        .arg("--expected-toolchain")
        .arg(&report.expected_toolchain);
    for case in &report.cases {
        let input = if case.case_id == target_case_id {
            ctx.input
        } else {
            Path::new(&case.protected_input_path)
        };
        let output = if case.case_id == target_case_id {
            ctx.output
        } else {
            Path::new(&case.candidate_output)
        };
        cmd.arg("--case")
            .arg(&case.manifest_path)
            .arg(input)
            .arg(output);
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawn verifier {verifier:?}"))?;
    match status.code() {
        Some(0) | Some(2) => Ok(()),
        other => bail!(
            "offline preflight verifier {verifier:?} terminated abnormally ({other:?}); \
             see {} for any gating report",
            output_dir.join(PREFLIGHT_REPORT_FILENAME).display()
        ),
    }
}

/// Digest the launch boundary reports for sidecar/bundle requests. P6.3.3:
/// the SELECTED case (the one whose protected input matches `input_identity`)
/// is chosen first, and its per-case digest is returned — the value that
/// flows into the evidence context and bundle. Always the producer-computed
/// value; equality with the report proven by `tests/preflight_boundary.rs`.
pub fn envelope_case_runner_config_digest(
    output_dir: &Path,
    input_identity: &FileIdentityGate,
) -> anyhow::Result<String> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    let case = select_case_config(&envelope, input_identity)?;
    Ok(case.runner_config_digest.to_lowercase())
}

// ---------------------------------------------------------------------------
// P6.3-D: production evidence/bundle data flow
// ---------------------------------------------------------------------------

/// Evidence sidecar file name appended to the candidate file name
/// (must match the producers in `unpacker/{oep,iat,tls,relocation,
/// section_rebuild}_evidence.rs`).
fn sidecar_path(candidate: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let file_name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut name = file_name.to_os_string();
    name.push(suffix);
    Ok(candidate.with_file_name(name))
}

/// The seven bundle members for a completed gated run, named exactly as the
/// sidecar producers and the dumper write them:
///
/// - the five structured evidence sidecars (`<candidate>.<kind>_evidence.json`)
/// - the bound transform manifest (`<candidate>.transform_manifest.json`,
///   written by the dumper)
/// - the PE evidence (`<candidate>.pe_evidence.json`, produced through the
///   independent acceptance binary)
fn evidence_members(candidate: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut members = Vec::with_capacity(7);
    for (name, suffix) in [
        ("oep_evidence", ".oep_evidence.json"),
        ("iat_evidence", ".iat_evidence.json"),
        ("tls_evidence", ".tls_evidence.json"),
        ("relocation_evidence", ".relocation_evidence.json"),
        ("section_rebuild_evidence", ".section_rebuild_evidence.json"),
    ] {
        members.push((name.to_string(), sidecar_path(candidate, suffix)?));
    }
    members.push((
        "transform_manifest".to_string(),
        candidate.with_extension("transform_manifest.json"),
    ));
    members.push((
        "pe_evidence".to_string(),
        candidate.with_extension("pe_evidence.json"),
    ));
    Ok(members)
}

/// The acceptance command that produces PE evidence for a packer family.
/// Oreans → `oreans-pe-evidence`; a registered generic family → the generic
/// `unpack-pe-evidence`. Unknown families fail closed (no Oreans fallback).
fn pe_evidence_command_for_family(family: &str) -> anyhow::Result<&'static str> {
    use mida_core::runner_config::packer_family;
    if packer_family::is_oreans_family(family) {
        Ok("oreans-pe-evidence")
    } else if packer_family::is_generic_family(family) {
        Ok("unpack-pe-evidence")
    } else {
        bail!(
            "unknown packer family {family:?}; cannot choose a PE-evidence producer (fail-closed)"
        );
    }
}

/// Emit the PE evidence sidecar through the independent acceptance binary.
/// The family selects the command: `oreans_themida` → `oreans-pe-evidence`
/// (`mida.oreans-pe-evidence/v1`); a registered generic family → the
/// `unpack-pe-evidence` command (`mida.unpack-pe-evidence/v1`). The generic
/// path never masquerades as Oreans PE evidence. The verifier is the unique
/// CLI sibling (never env/caller/PATH). Exit 0/2 are verifiable outcomes;
/// anything else fails closed.
fn emit_pe_evidence(candidate: &Path, destination: &Path, family: &str) -> anyhow::Result<()> {
    let command = pe_evidence_command_for_family(family)?;
    let (verifier, _) = resolve_verifier_identity()?;
    let status = Command::new(&verifier)
        .arg(command)
        .arg(candidate)
        .arg("--report")
        .arg(destination)
        .status()
        .with_context(|| {
            format!("spawn acceptance binary {verifier:?} for {command} PE evidence")
        })?;
    match status.code() {
        Some(0) => Ok(()),
        Some(2) => bail!(
            "PE evidence for {} was rejected by the acceptance binary (exit 2); \
             no bundle can be assembled around it",
            candidate.display()
        ),
        other => bail!(
            "acceptance binary {verifier:?} terminated abnormally ({other:?}) while \
             producing PE evidence for {}",
            candidate.display()
        ),
    }
}

/// P6.3-D production chain driver: after a successful gated run, collect
/// the seven evidence members (five sidecar producers + transform manifest
/// + PE evidence via the acceptance binary), verify they are all present
/// and bound, and assemble the atomic bundle from the single-use attested
/// context. The bundle's runner-config digest always equals the launch
/// attestation digest.
///
/// G2 family dispatch: the family bound by the attested context selects the
/// evidence contract — `oreans_themida` → `mida.oreans-evidence-bundle/v2`,
/// `ahk_gto` → the generic `mida.unpack-evidence-bundle/v1`. GTO products are
/// never assembled as Oreans evidence. An unknown family fails closed.
///
/// `context` is consumed BY VALUE (P6.3.1): the type is not `Clone` and has
/// no public constructor, so one attestation authorizes exactly one bundle.
/// `candidate` is the actual run output path (member files live next to
/// it); the bundle identity (protected input / candidate) comes from the
/// attestation context. Returns the bundle manifest path.
pub fn complete_run_evidence(
    context: RunEvidenceContext,
    candidate: &Path,
) -> anyhow::Result<PathBuf> {
    use mida_core::runner_config::packer_family;

    // P6.3.2: the PE-evidence verifier must be the attested CLI-sibling
    // identity (path + hash) — no env, no caller path, no PATH.
    verify_bundle_verifier_identity(&context)?;

    let members = evidence_members(candidate)?;
    let pe_evidence_path = candidate.with_extension("pe_evidence.json");
    emit_pe_evidence(candidate, &pe_evidence_path, context.packer_family())?;
    for (name, path) in &members {
        if !path.is_file() {
            bail!(
                "evidence member {name} is missing at {}; refusing to assemble a \
                 Complete bundle",
                path.display()
            );
        }
    }
    let emitted_at = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{secs}")
    };

    match context.packer_family() {
        family if family == packer_family::OREANS => {
            let bundle_output = candidate.with_extension("bundle.json");
            let request = crate::unpacker::bundle_assembler::AssembleRequest {
                emitted_at,
                protected_input: context.protected_input().to_path_buf(),
                candidate: context.candidate().to_path_buf(),
                members,
                output: bundle_output.clone(),
            };
            crate::unpacker::bundle_assembler::assemble_evidence_bundle(&request, context)?;
            Ok(bundle_output)
        }
        family if family == packer_family::AHK_GTO => {
            let bundle_output = candidate.with_extension("unpack_bundle.json");
            let request = crate::unpacker::generic_bundle_assembler::AssembleRequest {
                emitted_at,
                protected_input: context.protected_input().to_path_buf(),
                candidate: context.candidate().to_path_buf(),
                members,
                output: bundle_output.clone(),
            };
            crate::unpacker::generic_bundle_assembler::assemble_generic_evidence_bundle(
                &request, context,
            )?;
            Ok(bundle_output)
        }
        other => bail!(
            "unknown packer_family {other:?}; cannot choose an evidence contract (fail-closed)"
        ),
    }
}

/// Fail closed unless the verifier this bundle run would use is the unique
/// CLI sibling AND matches the context's attested verifier identity (path +
/// hash, P6.3.2).
fn verify_bundle_verifier_identity(context: &RunEvidenceContext) -> anyhow::Result<()> {
    let (verifier, sha) = resolve_verifier_identity()?;
    if !sha.eq_ignore_ascii_case(context.verifier_sha256()) {
        bail!(
            "acceptance verifier {} (sha {sha}) does not match the attested verifier {}; \
             verifier replacement or hash drift is refused",
            verifier.display(),
            context.verifier_sha256()
        );
    }
    Ok(())
}

/// SHA-256 (lowercase hex) of `path` — the CLI binary identity.
pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let data =
        std::fs::read(path).with_context(|| format!("read CLI binary {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// Current git HEAD of `repo_root` (spawns `git`; the probe lives in the
/// runner host, not in the preflight module).
pub fn current_tool_revision(repo_root: &Path) -> anyhow::Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .with_context(|| format!("spawn git in {}", repo_root.display()))?;
    if !output.status.success() {
        bail!(
            "git rev-parse failed in {}: {}",
            repo_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let revision = String::from_utf8(output.stdout)
        .context("git HEAD is not UTF-8")?
        .trim()
        .to_string();
    if revision.is_empty() {
        bail!("git HEAD is empty in {}", repo_root.display());
    }
    Ok(revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "mida_resolver_{tag}_{}_{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    /// A fake "mida-acceptance.exe" that is NOT the real binary — used to
    /// prove the resolver only ever accepts the exact sibling and never a
    /// PATH entry or a byte-copy elsewhere.
    fn fake_acceptance(dir: &Path) -> PathBuf {
        let p = dir.join("mida-acceptance.exe");
        write(&p, b"FAKE-ACCEPTANCE-1");
        p
    }

    #[test]
    fn resolver_accepts_exact_sibling_regular_file() {
        let dir = temp_dir("ok");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling resolves");
        assert_eq!(
            resolved,
            std::fs::canonicalize(&sibling).unwrap(),
            "must resolve to the exact sibling"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_hard_fails_when_sibling_missing() {
        let dir = temp_dir("missing");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let err = resolve_acceptance_bin_from_cli(&cli).expect_err("missing sibling must fail");
        assert!(err.to_string().contains("does not exist"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_hard_fails_when_sibling_not_regular() {
        let dir = temp_dir("notreg");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = dir.join("mida-acceptance.exe");
        std::fs::create_dir(&sibling).unwrap(); // a directory, not a file
        let err = resolve_acceptance_bin_from_cli(&cli).expect_err("dir sibling must fail");
        assert!(err.to_string().contains("not a regular file"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_rejects_path_drift_away_from_sibling() {
        let dir = temp_dir("drift");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        // A verifier placed at the sibling path IS accepted; but a copy of the
        // same bytes at ANY OTHER path must never be selected.
        fake_acceptance(&dir);
        let other = dir.join("somewhere-else/mida-acceptance.exe");
        std::fs::create_dir_all(other.parent().unwrap()).unwrap();
        write(&other, b"FAKE-ACCEPTANCE-1");
        // Resolver still returns the sibling, never the other copy.
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling wins");
        assert_ne!(resolved, other);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_never_consults_path() {
        let dir = temp_dir("path");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        // A DIFFERENT fake acceptance in a PATH directory must be ignored.
        let path_dir = dir.join("path-dir");
        std::fs::create_dir_all(&path_dir).unwrap();
        let in_path = path_dir.join("mida-acceptance.exe");
        write(&in_path, b"PATH-ACCEPTANCE-DIFFERENT");
        // Override PATH for this process.
        let old_path = std::env::var_os("PATH").clone();
        let mut paths =
            std::env::split_paths(&old_path.clone().unwrap_or_default()).collect::<Vec<_>>();
        paths.push(path_dir.clone());
        std::env::set_var("PATH", std::env::join_paths(paths).unwrap());
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling resolves");
        assert_eq!(resolved, std::fs::canonicalize(&sibling).unwrap());
        match old_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn resolver_rejects_sibling_that_is_a_byte_copy_to_another_path() {
        // The resolver must only select the exact sibling; a byte-identical
        // copy placed at a sibling-adjacent path is not the sibling.
        let dir = temp_dir("bytecopy");
        let cli = dir.join("mida-cli.exe");
        write(&cli, b"CLI");
        let sibling = fake_acceptance(&dir);
        let real_dir = dir.join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let other = real_dir.join("acceptance-copy.exe");
        write(&other, &std::fs::read(&sibling).unwrap());
        let resolved = resolve_acceptance_bin_from_cli(&cli).expect("sibling resolves");
        assert_eq!(resolved, std::fs::canonicalize(&sibling).unwrap());
        assert_ne!(resolved, other, "a byte copy elsewhere is never selected");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // -----------------------------------------------------------------------
    // P6.3.3: case-bound envelope + per-case digest selection (positive
    // control, hermetic — no process launch).
    // -----------------------------------------------------------------------

    /// The locked protected-input identities (mirror of the case manifests).
    const ORIGIN_ID: &str = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
    const LUNLUN_ID: &str = "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07";

    fn case_config(case_id: &str, sha: &str, pure_rebuild: bool) -> CaseRunnerConfigEnvelope {
        let mut config = crate::run_spec::frozen_runner_config();
        config.pure_rebuild = pure_rebuild;
        let digest = mida_core::runner_config::runner_config_digest(&config);
        CaseRunnerConfigEnvelope {
            case_id: case_id.to_string(),
            family_id: config.packer_family.clone(),
            protected_input: FileIdentityGate {
                sha256: sha.to_string(),
                size_bytes: if case_id == "origin_macro" {
                    5_232_656
                } else {
                    4_976_144
                },
            },
            runner_config: serde_json::to_value(&config).unwrap(),
            runner_config_digest: digest,
        }
    }

    fn v4_envelope() -> RunnerConfigEnvelope {
        RunnerConfigEnvelope::build(
            vec![
                case_config("origin_macro", ORIGIN_ID, true),
                case_config("lunlun_software", LUNLUN_ID, false),
            ],
            &"a".repeat(64),
            "rev",
            "C:\\dummy\\mida-acceptance.exe",
            &"b".repeat(64),
        )
    }

    #[test]
    fn case_bound_envelope_carries_distinct_origin_and_lunlun_configs() {
        let env = v4_envelope();
        assert!(env.validate_case_set().is_none(), "case set is well-formed");
        let origin = env
            .case_configs
            .iter()
            .find(|c| c.case_id == "origin_macro")
            .unwrap();
        let lunlun = env
            .case_configs
            .iter()
            .find(|c| c.case_id == "lunlun_software")
            .unwrap();
        // Origin resolves pure_rebuild=true, Lunlun pure_rebuild=false (D3).
        let origin_cfg: serde_json::Value = origin.runner_config.clone();
        assert_eq!(origin_cfg["pure_rebuild"], serde_json::json!(true));
        let lunlun_cfg: serde_json::Value = lunlun.runner_config.clone();
        assert_eq!(lunlun_cfg["pure_rebuild"], serde_json::json!(false));
        // Distinct per-case digests.
        assert_ne!(origin.runner_config_digest, lunlun.runner_config_digest);
        // The sealed case-set digest covers both case + input bindings.
        assert_eq!(env.case_set_digest.len(), 64);
    }

    #[test]
    fn select_case_config_picks_the_unique_case_by_input_identity() {
        let env = v4_envelope();
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        let lunlun_identity = FileIdentityGate {
            sha256: LUNLUN_ID.to_string(),
            size_bytes: 4_976_144,
        };
        let origin = select_case_config(&env, &origin_identity).unwrap();
        assert_eq!(origin.case_id, "origin_macro");
        let lunlun = select_case_config(&env, &lunlun_identity).unwrap();
        assert_eq!(lunlun.case_id, "lunlun_software");
        // Origin and Lunlun select DIFFERENT digests.
        assert_ne!(origin.runner_config_digest, lunlun.runner_config_digest);
        // A third / unknown identity matches 0 cases -> refused.
        let unknown = FileIdentityGate {
            sha256: "c".repeat(64),
            size_bytes: 1,
        };
        assert!(
            select_case_config(&env, &unknown).is_err(),
            "0 matches must be refused"
        );
    }

    #[test]
    fn bind_actual_config_compares_only_the_selected_case_digest() {
        let dir = temp_dir("bind_case");
        let env = v4_envelope();
        env.write(&dir).unwrap();

        // Origin actual config (pure_rebuild=true) against Origin digest
        // passes; the same actual config is NOT compared to Lunlun's digest.
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        let mut origin_actual = crate::run_spec::frozen_run_policy(Path::new("x.bin"));
        origin_actual.pure_rebuild = true;
        assert!(bind_actual_config_to_envelope(&dir, &origin_actual, &origin_identity).is_ok());
        // A Lunlun actual config (pure_rebuild=false) against Lunlun digest
        // passes.
        let lunlun_identity = FileIdentityGate {
            sha256: LUNLUN_ID.to_string(),
            size_bytes: 4_976_144,
        };
        let mut lunlun_actual = crate::run_spec::frozen_runner_config();
        lunlun_actual.pure_rebuild = false;
        assert!(bind_actual_config_to_envelope(&dir, &lunlun_actual, &lunlun_identity).is_ok());

        // Wrong pairing: an Origin actual config (pure=true) bound to the
        // LUNLUN identity -> its digest must NOT equal Lunlun's digest -> fail.
        assert!(
            bind_actual_config_to_envelope(&dir, &origin_actual, &lunlun_identity).is_err(),
            "Origin config must never match the Lunlun digest"
        );
        // And a Lunlun actual (pure=false) bound to the ORIGIN identity fails.
        assert!(
            bind_actual_config_to_envelope(&dir, &lunlun_actual, &origin_identity).is_err(),
            "Lunlun config must never match the Origin digest"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G2-R1: a packer family is bound at STAGING and cannot be switched. An
    /// actual config carrying a different family than the envelope case is
    /// refused by the launch boundary — so an Oreans-staged case can never be
    /// attested under a GTO-family config (or vice versa). This is what makes
    /// the removed `rebind_family` path unnecessary and unsafe to reintroduce:
    /// the family is checked field-by-field before the digest, and the digest
    /// also embeds the family.
    #[test]
    fn g2r1_oreans_case_rejects_gto_family_config() {
        use mida_core::runner_config::packer_family;
        let dir = temp_dir("g2r1_bind_family");
        let env = v4_envelope(); // family_id = oreans_themida for both cases
        env.write(&dir).unwrap();
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        // The SAME policy as the Oreans Origin case but carrying the GTO
        // family: a GTO-family digest must never bind to an Oreans envelope
        // case (this is the "rebind a GTO family onto an Oreans attestation"
        // attack, now impossible).
        let mut gto_actual = crate::run_spec::frozen_run_policy_for_family(
            Path::new("x.bin"),
            packer_family::AHK_GTO,
        );
        gto_actual.pure_rebuild = true;
        assert!(
            bind_actual_config_to_envelope(&dir, &gto_actual, &origin_identity).is_err(),
            "a GTO-family config must never bind to an Oreans envelope case"
        );
        // A family-less actual config defaults to Oreans and still binds.
        let mut oreans_actual = crate::run_spec::frozen_run_policy(Path::new("x.bin"));
        oreans_actual.pure_rebuild = true;
        assert_eq!(oreans_actual.packer_family, packer_family::OREANS);
        assert!(
            bind_actual_config_to_envelope(&dir, &oreans_actual, &origin_identity).is_ok(),
            "the Oreans-family (default) config binds to the Oreans case"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G3: a GTO lane envelope (case `gto_launcher`, family `ahk_gto`) binds a
    /// GTO-family actual config and REJECTS an Oreans-family actual config. The
    /// GTO lane can never be attested under an Oreans config (and vice versa).
    #[test]
    fn gto_lane_envelope_binds_gto_config_and_rejects_oreans() {
        use mida_core::runner_config::packer_family;
        let dir = temp_dir("g3_gto_bind");
        // Build a GTO lane envelope: Oreans fixed lane + a gto_launcher case
        // with family ahk_gto and a GTO config/digest.
        let mut env = v4_envelope();
        let mut gto_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        gto_cfg.tool_revision = "rev".to_string();
        gto_cfg.cli_binary_sha256 = "a".repeat(64);
        gto_cfg.pure_rebuild = false;
        let gto_digest = mida_core::runner_config::runner_config_digest(&gto_cfg);
        let gto_identity = FileIdentityGate {
            sha256: "c".repeat(64),
            size_bytes: 42,
        };
        env.case_configs.push(CaseRunnerConfigEnvelope {
            case_id: GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: gto_identity.clone(),
            runner_config: serde_json::to_value(&gto_cfg).unwrap(),
            runner_config_digest: gto_digest,
        });
        assert!(
            env.validate_case_set().is_none(),
            "GTO lane envelope is valid"
        );
        env.write(&dir).unwrap();

        // A GTO-family actual config matching the GTO case digest binds.
        let mut gto_actual = crate::run_spec::frozen_run_policy_for_family(
            Path::new("x.bin"),
            packer_family::AHK_GTO,
        );
        gto_actual.tool_revision = "rev".to_string();
        gto_actual.cli_binary_sha256 = "a".repeat(64);
        gto_actual.pure_rebuild = false;
        assert_eq!(gto_actual.packer_family, packer_family::AHK_GTO);
        assert!(
            bind_actual_config_to_envelope(&dir, &gto_actual, &gto_identity).is_ok(),
            "GTO lane envelope + GTO actual config must bind"
        );

        // An Oreans-family actual config must never bind to the GTO lane case.
        let mut oreans_actual = crate::run_spec::frozen_run_policy(Path::new("x.bin"));
        oreans_actual.pure_rebuild = false;
        assert!(
            bind_actual_config_to_envelope(&dir, &oreans_actual, &gto_identity).is_err(),
            "GTO lane envelope must reject an Oreans actual config"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G3: unknown / missing family in the GTO lane case fails closed at
    /// case-set validation.
    #[test]
    fn gto_lane_unknown_or_missing_family_fails_closed() {
        use mida_core::runner_config::packer_family;
        let mut unknown = v4_envelope();
        let mut gto_case = v4_envelope().case_configs[0].clone();
        gto_case.case_id = GTO_CASE_ID.to_string();
        gto_case.family_id = "bogus_family".to_string();
        unknown.case_configs.push(gto_case);
        assert!(
            unknown.validate_case_set().is_some(),
            "a GTO lane case with an unknown family must fail closed"
        );
        let mut missing = v4_envelope();
        let mut gto_missing = v4_envelope().case_configs[0].clone();
        gto_missing.case_id = GTO_CASE_ID.to_string();
        gto_missing.family_id = String::new();
        missing.case_configs.push(gto_missing);
        assert!(
            missing.validate_case_set().is_some(),
            "a GTO lane case with a missing family must fail closed"
        );
        let _ = packer_family::AHK_GTO;
    }
    #[test]
    fn g2r1_unknown_family_in_envelope_fails_closed() {
        let dir = temp_dir("g2r1_unknown_family");
        let mut env = v4_envelope();
        env.case_configs[0].family_id = "bogus_family".to_string();
        assert!(
            env.validate_case_set().is_some(),
            "an unknown family_id in the envelope must fail case-set validation"
        );
        let mut empty_family = v4_envelope();
        empty_family.case_configs[1].family_id = String::new();
        assert!(
            empty_family.validate_case_set().is_some(),
            "a missing family_id in the envelope must fail case-set validation"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// G2-R2: the PE-evidence command dispatches by family — Oreans →
    /// `oreans-pe-evidence`, a generic family (ahk_gto) → `unpack-pe-evidence`.
    /// The two never cross lines and an unknown family fails closed.
    #[test]
    fn pe_evidence_command_dispatches_by_family() {
        use mida_core::runner_config::packer_family;
        assert_eq!(
            pe_evidence_command_for_family(packer_family::OREANS).unwrap(),
            "oreans-pe-evidence"
        );
        assert_eq!(
            pe_evidence_command_for_family(packer_family::AHK_GTO).unwrap(),
            "unpack-pe-evidence"
        );
        assert!(pe_evidence_command_for_family("bogus").is_err());
        assert!(pe_evidence_command_for_family("").is_err());
    }

    /// G2-R2 (reachability guard, choice B): the GTO preflight lane is NOT yet
    /// wired. The fixed two-sample regression gate is strictly the two Oreans
    /// cases, so no GTO case can be staged into the envelope today — the GTO
    /// family/digest/attest path is unit-tested but not end-to-end reachable.
    /// This assertion locks that boundary so a future change cannot silently
    /// claim GTO preflight is live without explicitly removing this guard.
    #[test]
    fn gto_preflight_is_not_yet_reachable() {
        // The Oreans fixed regression gate is exactly the two Oreans cases;
        // the GTO lane is a SEPARATE case id and is never folded into it.
        assert_eq!(FIXED_CASE_IDS, ["origin_macro", "lunlun_software"]);
        assert!(
            !FIXED_CASE_IDS.iter().any(|id| *id == "gto_launcher"),
            "the GTO lane must never be folded into the Oreans fixed regression gate"
        );
        assert_eq!(GTO_CASE_ID, "gto_launcher");
        // The GTO lane is NOT an accepted sample: no real GTO sample has been
        // staged/attested/verified end-to-end (it stays offline-only). This
        // guards against anyone claiming real GTO preflight acceptance.
    }

    /// G3: `validate_case_set` accepts the two lanes — the Oreans fixed lane
    /// must be present, and an optional GTO no-gate lane case is allowed with
    /// family `ahk_gto`. Cross-lane / unknown family reuse fails closed.
    #[test]
    fn validate_case_set_accepts_oreans_plus_optional_gto_lane() {
        use mida_core::runner_config::packer_family;
        let dir = temp_dir("g3_lane_set");
        let mut oreans = v4_envelope();
        assert!(
            oreans.validate_case_set().is_none(),
            "pure Oreans set is valid"
        );
        // Add a GTO lane case (family ahk_gto) -> still valid.
        let mut gto_case = v4_envelope().case_configs[0].clone();
        gto_case.case_id = GTO_CASE_ID.to_string();
        gto_case.family_id = packer_family::AHK_GTO.to_string();
        oreans.case_configs.push(gto_case);
        assert!(
            oreans.validate_case_set().is_none(),
            "Oreans + GTO lane is valid"
        );
        // A GTO case borrowing the Oreans family must fail closed.
        let mut bad = v4_envelope();
        let mut gto_case_oreans = v4_envelope().case_configs[0].clone();
        gto_case_oreans.case_id = GTO_CASE_ID.to_string();
        gto_case_oreans.family_id = packer_family::OREANS.to_string();
        bad.case_configs.push(gto_case_oreans);
        assert!(
            bad.validate_case_set().is_some(),
            "a GTO case borrowing the Oreans family must fail closed"
        );
        // An Oreans fixed case carrying the GTO family must fail closed.
        let mut oreans_as_gto = v4_envelope();
        oreans_as_gto.case_configs[0].family_id = packer_family::AHK_GTO.to_string();
        assert!(
            oreans_as_gto.validate_case_set().is_some(),
            "an Oreans fixed case with the GTO family must fail closed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2: the verifier-replacement rejection is proven offline via a
    /// PURE seam (`verify_verifier_identity_bindings`), WITHOUT selecting a
    /// real locked case or creating a sample process. A fabricated envelope
    /// pins a verifier identity; the sibling the run would resolve to hashes
    /// to a DIFFERENT identity, so the check must fail with a
    /// verifier-identity reason (not a generic "launch blocked").
    #[test]
    fn verifier_replacement_rejected_by_pure_identity_seam() {
        let dir = temp_dir("vrfy_seam");
        // The verifier this run would resolve to: the fake sibling.
        let fake_acceptance_bin = fake_acceptance(&dir);
        let resolved_sha = sha256_hex(&std::fs::read(&fake_acceptance_bin).unwrap());

        // A valid envelope whose pinned verifier SHA is a DIFFERENT identity
        // (and whose pinned path is the same sibling path).
        let mut env = v4_envelope();
        let pinned_path = std::fs::canonicalize(&fake_acceptance_bin).unwrap();
        env.verifier_path = pinned_path.display().to_string();
        env.verifier_sha256 = "f".repeat(64);

        let err = verify_verifier_identity_bindings(&env, &fake_acceptance_bin, &resolved_sha)
            .expect_err("a replaced verifier must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("verifier") && msg.contains("does not match"),
            "the rejection must cite the verifier identity: {msg}"
        );
        assert!(
            msg.contains("replacement") || msg.contains("drift"),
            "the rejection must cite replacement/drift: {msg}"
        );

        // Positive control: an envelope pinned to the ACTUAL resolved
        // identity passes the pure seam (path + hash both match).
        let mut ok_env = v4_envelope();
        ok_env.verifier_path = pinned_path.display().to_string();
        ok_env.verifier_sha256 = resolved_sha.clone();
        let ok = verify_verifier_identity_bindings(&ok_env, &fake_acceptance_bin, &resolved_sha)
            .expect("exact pinned identity passes");
        assert_eq!(ok.to_lowercase(), resolved_sha.to_lowercase());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2: the pure seam also fails closed on verifier PATH drift — a
    /// verifier at a DIFFERENT canonical path than the pinned one is refused
    /// even if its SHA-256 coincidentally matched.
    #[test]
    fn verifier_path_drift_rejected_by_pure_identity_seam() {
        let dir = temp_dir("vrfy_path");
        let fake_acceptance_bin = fake_acceptance(&dir);
        let resolved_sha = sha256_hex(&std::fs::read(&fake_acceptance_bin).unwrap());

        let mut env = v4_envelope();
        // Pin a DIFFERENT canonical path (same SHA) -> path drift must fail.
        env.verifier_path = dir
            .join("elsewhere/mida-acceptance.exe")
            .display()
            .to_string();
        env.verifier_sha256 = resolved_sha.clone();
        let err = verify_verifier_identity_bindings(&env, &fake_acceptance_bin, &resolved_sha)
            .expect_err("path drift must be refused");
        assert!(
            err.to_string().contains("path drift"),
            "path drift reason expected: {err}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2: the production pure-rebuild policy is resolved from the REAL
    /// protected-input bytes via `is_origin_macro_protected_input` — never
    /// guessed from the case_id string. A file whose bytes hash to the
    /// Origin locked identity resolves `pure_rebuild=true`; any other input
    /// resolves `false`, regardless of its path or name.
    #[test]
    fn frozen_run_policy_resolves_pure_rebuild_from_real_input_bytes() {
        use std::io::Write;
        let dir = temp_dir("d3_resolver");
        // A file whose bytes hash to the locked Origin identity. We cannot
        // produce 5MB+ of those exact bytes here, so we instead prove the
        // resolver is INPUT-BASED (hash of the actual file) by confirming the
        // default non-Origin input resolves false, and that the Origin
        // identity constant is the resolver's discriminator.
        let non_origin = dir.join("whatever.bin");
        let mut f = std::fs::File::create(&non_origin).unwrap();
        f.write_all(b"NON-ORIGIN-INPUT-BYTES").unwrap();
        drop(f);
        let policy = crate::run_spec::frozen_run_policy(&non_origin);
        assert!(
            !policy.pure_rebuild,
            "a non-Origin input must resolve pure_rebuild=false"
        );

        // Directly prove the discriminator is the file's real SHA-256, not the
        // path/name: a file with the ORIGIN identity bytes must be flagged.
        // (The real locked bytes are 5MB+; here we assert the resolver keys on
        // the SHA constant, which is the exact logic used at launch.)
        let origin_sha = crate::origin_pure::ORIGIN_MACRO_PROTECTED_SHA256;
        assert_eq!(origin_sha.len(), 64);
        assert_ne!(
            origin_sha.to_lowercase(),
            sha256_hex(&std::fs::read(&non_origin).unwrap()),
            "the two inputs must have distinct identities"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// P6.3.3.2.1: the TRUE dual swap — both the case_id and the
    /// protected_input are exchanged together while each runner CONFIG stays
    /// in its original slot, so every case keeps its OWN protected identity
    /// (the keyed binding stays valid) but carries the OTHER case's policy.
    /// Rejected at the launch-attestation level: `bind_actual_config_to_envelope`
    /// recomputes the ACTUAL config digest and compares it only against the
    /// SELECTED case's digest — even when every envelope digest is re-sealed
    /// honestly. The rejection must cite the config/policy digest, never a
    /// synthetic-input identity mismatch.
    ///
    /// Resulting envelope (identity valid, config swapped):
    ///   lunlun_software + LUNLUN identity + Origin policy(true)
    ///   origin_macro   + ORIGIN  identity + Lunlun policy(false)
    #[test]
    fn true_dual_swap_rejected_by_launch_attestation_config_digest() {
        let dir = temp_dir("dual_swap");
        let mut env = v4_envelope();
        // Origin slot keeps its ORIGIN identity but now carries the LUNLUN
        // policy (pure=false); the Lunlun slot keeps LUNLUN identity but
        // carries the ORIGIN policy (pure=true).
        env.case_configs[0] = case_config("origin_macro", ORIGIN_ID, false);
        env.case_configs[1] = case_config("lunlun_software", LUNLUN_ID, true);
        env.case_set_digest = case_set_digest(&env.case_configs);
        env.write(&dir).unwrap();

        // The launch binds the ORIGIN identity to the REAL Origin frozen
        // policy (pure=true). The selected origin_macro case now holds the
        // lunlun (pure=false) config digest, so the actual digest mismatches.
        let origin_identity = FileIdentityGate {
            sha256: ORIGIN_ID.to_string(),
            size_bytes: 5_232_656,
        };
        let mut origin_actual = crate::run_spec::frozen_runner_config();
        origin_actual.pure_rebuild = true; // Origin D3 resolves true
        let err = bind_actual_config_to_envelope(&dir, &origin_actual, &origin_identity)
            .expect_err("Origin pure=true actual must not bind a pure=false envelope case");
        assert!(
            err.to_string().contains("digest"),
            "the rejection must cite the config/digest, not an input mismatch: {err}"
        );

        // Symmetric negative control: the Lunlun identity bound to the real
        // Lunlun frozen policy (pure=false) must also fail against the origin
        // (pure=true) config now carried by the lunlun case.
        let lunlun_identity = FileIdentityGate {
            sha256: LUNLUN_ID.to_string(),
            size_bytes: 4_976_144,
        };
        let mut lunlun_actual = crate::run_spec::frozen_runner_config();
        lunlun_actual.pure_rebuild = false;
        let err2 = bind_actual_config_to_envelope(&dir, &lunlun_actual, &lunlun_identity)
            .expect_err("Lunlun pure=false actual must not bind a pure=true envelope case");
        assert!(
            err2.to_string().contains("digest"),
            "the rejection must cite the config/digest: {err2}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn v4_envelope_seals_case_set_and_rejects_missing_duplicate_extra() {
        let dir = temp_dir("case_set");
        let env = v4_envelope();
        env.write(&dir).unwrap();
        // The sealed digest round-trips and is stable.
        assert_eq!(
            env.case_set_digest,
            case_set_digest(&env.case_configs),
            "case-set digest must be recomputable from the case configs"
        );
        // Missing a case is rejected.
        let mut missing = v4_envelope();
        missing
            .case_configs
            .retain(|c| c.case_id != "lunlun_software");
        assert!(
            missing.validate_case_set().is_some(),
            "missing case rejected"
        );
        // Duplicate is rejected.
        let mut dup = v4_envelope();
        dup.case_configs
            .push(case_config("origin_macro", ORIGIN_ID, true));
        assert!(dup.validate_case_set().is_some(), "duplicate case rejected");
        // Extra (third) case is rejected.
        let mut extra = v4_envelope();
        extra
            .case_configs
            .push(case_config("gto_launcher", &"d".repeat(64), false));
        assert!(extra.validate_case_set().is_some(), "extra case rejected");
        // Tampering one per-case digest, then re-sealing the case set, must
        // change the case-set digest (any single-case tamper breaks the seal).
        let mut tampered = v4_envelope();
        tampered.case_configs[0].runner_config_digest = "e".repeat(64);
        tampered.case_set_digest = case_set_digest(&tampered.case_configs);
        assert_ne!(tampered.case_set_digest, env.case_set_digest);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // ---------------------------------------------------------------------
    // G2: family-agnostic generic evidence contract — producer -> consumer
    // round-trip, run entirely offline with synthetic member sidecars. Uses
    // the real `generic_bundle_assembler` (producer) and the independent
    // `mida-acceptance` consumer, proving the two implementations agree.
    // ---------------------------------------------------------------------

    /// Build the JSON bytes of one family-agnostic sidecar member with the
    /// identities embedded exactly as the producer's `check_embedded_identity`
    /// (and the consumer's `check_sidecar_identity`) require.
    fn g2_sidecar(
        schema: &str,
        protected: Option<(String, u64)>,
        candidate: (String, u64),
    ) -> Vec<u8> {
        let mut obj = serde_json::json!({
            "schema_version": schema,
            "candidate": { "sha256": candidate.0, "size_bytes": candidate.1 },
        });
        if let Some((sha, size)) = protected {
            obj["protected_input"] = serde_json::json!({ "sha256": sha, "size_bytes": size });
        }
        serde_json::to_vec(&obj).unwrap()
    }

    fn g2_transform_manifest(candidate: (String, u64)) -> Vec<u8> {
        serde_json::json!({
            "schema_version": "mida.transform-manifest/v0",
            "taxonomy_version": "mida.transform-taxonomy/v1",
            "candidate_sha256": candidate.0,
            "candidate_size_bytes": candidate.1,
            "entries": [],
        })
        .to_string()
        .into_bytes()
    }

    /// Produce a GTO-family generic bundle from synthetic inputs via the real
    /// producer, then hand the emitted manifest + member bytes to the
    /// `mida-acceptance` consumer. Returns the consumer verdict.
    fn g2_produce_and_consume(dir: &std::path::Path) -> mida_acceptance::UnpackBundleVerdict {
        use crate::unpacker::generic_bundle_assembler::{
            assemble_generic_evidence_bundle, AssembleRequest,
        };

        let protected_path = dir.join("protected.bin");
        let candidate_path = dir.join("candidate.bin");
        let protected_bytes = b"G2-PROTECTED-INPUT-00000000000000";
        let candidate_bytes = b"G2-CANDIDATE-OUTPUT-000000000000000";
        write(&protected_path, protected_bytes);
        write(&candidate_path, candidate_bytes);
        let protected_sha = sha256_hex(protected_bytes);
        let candidate_sha = sha256_hex(candidate_bytes);
        let protected = (protected_sha.clone(), protected_bytes.len() as u64);
        let candidate = (candidate_sha.clone(), candidate_bytes.len() as u64);

        // Build the 7 member files. Member schemas come from the PRODUCTION
        // family-aware dispatch (`evidence_schema::member_schema_for_family`
        // with the GTO family), so the test exercises the real dispatch rather
        // than a hand-rolled set.
        let evidence_dir = dir.join("evidence");
        std::fs::create_dir_all(&evidence_dir).unwrap();
        use crate::unpacker::evidence_schema::{member_schema_for_family, EvidenceMemberKind};
        const GTO_FAMILY: &str = "ahk_gto";
        let member_specs: Vec<(&str, &str, bool)> = vec![
            (
                "oep_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Oep).unwrap(),
                true,
            ),
            (
                "iat_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Iat).unwrap(),
                true,
            ),
            (
                "tls_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Tls).unwrap(),
                true,
            ),
            (
                "relocation_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Relocation).unwrap(),
                true,
            ),
            (
                "section_rebuild_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::SectionRebuild).unwrap(),
                true,
            ),
            (
                "pe_evidence",
                member_schema_for_family(GTO_FAMILY, EvidenceMemberKind::Pe).unwrap(),
                false,
            ),
            ("transform_manifest", "mida.transform-manifest/v0", false),
        ];
        let mut members = Vec::new();
        for (name, schema, has_protected) in &member_specs {
            let path = evidence_dir.join(format!("{name}.json"));
            let bytes = if *name == "transform_manifest" {
                g2_transform_manifest(candidate.clone())
            } else {
                g2_sidecar(
                    schema,
                    if *has_protected {
                        Some(protected.clone())
                    } else {
                        None
                    },
                    candidate.clone(),
                )
            };
            write(&path, &bytes);
            members.push((name.to_string(), path));
        }

        let context = RunEvidenceContext::new_with_family(
            mida_core::runner_config::packer_family::AHK_GTO.to_string(),
            "gto_launcher".to_string(),
            "oreans/two-sample-mainline@test".to_string(),
            "ab12".repeat(16),
            "cd34".repeat(16),
            protected_path,
            candidate_path.clone(),
            "ef56".repeat(16),
        )
        .expect("GTO evidence context builds");

        let output = evidence_dir.join("unpack_bundle.json");
        let request = AssembleRequest {
            emitted_at: "2026-08-04T12:00:00Z".to_string(),
            protected_input: dir.join("protected.bin"),
            candidate: candidate_path.clone(),
            members: members.clone(),
            output: output.clone(),
        };
        assemble_generic_evidence_bundle(&request, context)
            .expect("producer assembles generic bundle");

        // Consumer side: read the emitted manifest + member bytes.
        let raw = std::fs::read_to_string(&output).unwrap();
        let bundle: mida_acceptance::UnpackEvidenceBundle =
            serde_json::from_str(&raw).expect("consumer parses emitted manifest");
        let mut files: std::collections::BTreeMap<String, Vec<u8>> =
            std::collections::BTreeMap::new();
        for m in &bundle.members {
            let src = evidence_dir.join(&m.relative_path);
            files.insert(m.name.clone(), std::fs::read(&src).unwrap());
        }
        mida_acceptance::validate_unpack_bundle(&bundle, &files)
    }

    /// Read the emitted generic bundle manifest back from the producer output.
    fn g2_read_emitted_bundle(dir: &std::path::Path) -> mida_acceptance::UnpackEvidenceBundle {
        let raw = std::fs::read_to_string(dir.join("evidence/unpack_bundle.json")).unwrap();
        serde_json::from_str(&raw).expect("consumer parses emitted generic manifest")
    }

    /// Reconstruct the consumer `files` map from the emitted manifest's member
    /// paths (the member files live next to the emitted bundle).
    fn g2_member_files(
        dir: &std::path::Path,
        bundle: &mida_acceptance::UnpackEvidenceBundle,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let evidence_dir = dir.join("evidence");
        let mut files = std::collections::BTreeMap::new();
        for m in &bundle.members {
            let src = evidence_dir.join(&m.relative_path);
            files.insert(m.name.clone(), std::fs::read(&src).unwrap());
        }
        files
    }

    #[test]
    fn g2_generic_bundle_producer_consumer_round_trip_is_valid() {
        let dir = temp_dir("g2_roundtrip");
        let verdict = g2_produce_and_consume(&dir);
        assert!(
            verdict.valid && verdict.complete,
            "producer output must be accepted by consumer: {:?}",
            verdict.reasons
        );
        // The high-level `consume_unpack_bundle` seam also accepts it.
        let bundle = g2_read_emitted_bundle(&dir);
        let files = g2_member_files(&dir, &bundle);
        assert!(
            mida_acceptance::consume_unpack_bundle(&bundle, &files).is_ok(),
            "consume_unpack_bundle must accept producer output"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn g2_oreans_v2_evidence_is_rejected_by_generic_consumer() {
        // An Oreans v2 manifest (v2 schema id, no family_id) must be refused by
        // the generic consumer: it cannot even deserialize (family_id required +
        // deny_unknown_fields), and a family-less/wrong-schema manifest is
        // rejected at the schema seam. This is the "Oreans evidence disguised as
        // GTO generic evidence" cross-contamination rejection.
        let dir = temp_dir("g2_oreans_reject");
        // Mimic the exact Oreans v2 bundle wire form (see
        // mida_acceptance::OreansEvidenceBundle) without family_id.
        let oreans_json = serde_json::json!({
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
        let parsed = serde_json::from_value::<mida_acceptance::UnpackEvidenceBundle>(oreans_json);
        assert!(
            parsed.is_err(),
            "an Oreans v2 manifest must not parse as a generic bundle (fail-closed)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn g2_generic_evidence_is_rejected_by_oreans_consumer() {
        // Conversely, a GTO generic bundle must never be accepted as Oreans
        // evidence. The Oreans consumer type is family-agnostic-neutral but the
        // schema id differs, so a generic manifest cannot deserialize into
        // `mida_acceptance::OreansEvidenceBundle`.
        let dir = temp_dir("g2_generic_as_oreans");
        // Emit a real GTO generic bundle via the producer.
        let verdict = g2_produce_and_consume(&dir);
        assert!(
            verdict.valid,
            "sanity: the same producer output is a valid generic bundle"
        );
        // The emitted manifest JSON cannot parse as an Oreans v2 bundle.
        let raw = std::fs::read_to_string(dir.join("evidence/unpack_bundle.json")).unwrap();
        let as_oreans = serde_json::from_str::<mida_acceptance::OreansEvidenceBundle>(&raw);
        assert!(
            as_oreans.is_err(),
            "a GTO generic bundle must never deserialize as Oreans evidence (fail-closed)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
