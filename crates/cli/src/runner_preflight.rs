//! Runner-side offline-preflight closure (P6.2): the production binding of
//! the independent runner-config digest producer to the launch boundary.
//!
//! Roles:
//!
//! - **Producer (this module, `mida-cli` production)**: builds
//!   [`mida_core::runner_config::RunnerConfig`] from the actual run policy,
//!   computes the digest with `mida_core::runner_config::runner_config_digest`,
//!   and atomically emits the `mida.runner-config-envelope/v1` envelope
//!   (full config JSON + producer digest + CLI binary SHA-256 + tool
//!   revision).
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
//! Origin Macro pure-rebuild default); [`bind_actual_config_to_envelope`]
//! is the launch-side equality check.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context};
use serde::{Deserialize, Serialize};

use crate::unpacker::sidecar_io::atomic_write;

/// Schema id of the runner-config envelope.
pub const RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION: &str = "mida.runner-config-envelope/v1";
/// Filename of the envelope inside the preflight output dir.
pub const RUNNER_CONFIG_ENVELOPE_FILENAME: &str = "runner-config-envelope.json";
/// Filename of the preflight report inside the preflight output dir.
pub const PREFLIGHT_REPORT_FILENAME: &str = "preflight.json";
/// Emitted `$schema` reference of the envelope.
pub const RUNNER_CONFIG_ENVELOPE_SCHEMA_REF: &str = "./runner-config-envelope.schema.json";

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

/// Launch-side equality check (P6.3-A): the digest of the ACTUAL run
/// configuration — built from the parsed `/unpack` arguments, with the
/// resolved pure-rebuild value — must equal the envelope digest. An
/// envelope staged as `pure_rebuild=false` can never bind a run that
/// silently resolves to `true` (or any other parameter divergence).
pub fn bind_actual_config_to_envelope(
    output_dir: &Path,
    actual_config: &mida_core::runner_config::RunnerConfig,
) -> anyhow::Result<()> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    let actual_digest = mida_core::runner_config::runner_config_digest(actual_config);
    if !actual_digest.eq_ignore_ascii_case(&envelope.runner_config_digest) {
        bail!(
            "actual run config digest {actual_digest} != envelope digest {}",
            envelope.runner_config_digest
        );
    }
    Ok(())
}

/// The `mida.runner-config-envelope/v1` emitted by the runner side.
///
/// `deny_unknown_fields` + required fields: a tampered envelope (unknown
/// field, missing field) fails closed at deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfigEnvelope {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub schema_version: String,
    /// Full runner config JSON, as the runner will apply it.
    pub runner_config: serde_json::Value,
    /// Producer-computed digest (`mida_core::runner_config::runner_config_digest`).
    pub runner_config_digest: String,
    /// SHA-256 of the CLI binary that will perform the run.
    pub cli_binary_sha256: String,
    /// Tool revision (git HEAD) the run is pinned to.
    pub tool_revision: String,
}

impl RunnerConfigEnvelope {
    /// Build the envelope from the frozen policy + runtime pinning inputs.
    pub fn build(
        runner_config: &mida_core::runner_config::RunnerConfig,
        cli_binary_sha256: &str,
        tool_revision: &str,
    ) -> RunnerConfigEnvelope {
        let digest = mida_core::runner_config::runner_config_digest(runner_config);
        RunnerConfigEnvelope {
            schema: RUNNER_CONFIG_ENVELOPE_SCHEMA_REF.to_string(),
            schema_version: RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION.to_string(),
            runner_config: serde_json::to_value(runner_config).expect("runner config serializes"),
            runner_config_digest: digest,
            cli_binary_sha256: cli_binary_sha256.to_lowercase(),
            tool_revision: tool_revision.to_string(),
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

    /// Producer-computed digest, as the launch boundary uses it.
    pub fn digest(&self) -> &str {
        &self.runner_config_digest
    }
}

/// The preflight report as the launch boundary consumes it (strict).
///
/// This is a minimal runner-side copy of the acceptance report contract
/// (`mida.preflight-report/v2`); unknown fields fail closed so a drifted
/// report schema cannot slip past.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReportGate {
    pub schema_version: String,
    pub status: String,
    pub reasons: Vec<String>,
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
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
}

/// Resolve the `mida-acceptance` verifier binary: `MIDA_ACCEPTANCE_BIN`
/// overrides, then a sibling `mida-acceptance(.exe)` next to the CLI binary,
/// then PATH.
pub fn resolve_acceptance_bin() -> PathBuf {
    if let Ok(explicit) = std::env::var("MIDA_ACCEPTANCE_BIN") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = parent.join("mida-acceptance.exe");
            if sibling.exists() {
                return sibling;
            }
            let sibling_naked = parent.join("mida-acceptance");
            if sibling_naked.exists() {
                return sibling_naked;
            }
        }
    }
    PathBuf::from("mida-acceptance")
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
        || existing.runner_config != candidate.runner_config
        || !existing
            .runner_config_digest
            .eq_ignore_ascii_case(&candidate.runner_config_digest)
        || !existing
            .cli_binary_sha256
            .eq_ignore_ascii_case(&candidate.cli_binary_sha256)
        || existing.tool_revision != candidate.tool_revision
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
    acceptance_bin: Option<&Path>,
) -> anyhow::Result<bool> {
    let verifier = acceptance_bin
        .map(Path::to_path_buf)
        .unwrap_or_else(resolve_acceptance_bin);
    // P6.3-C: fail-closed reuse — first creation only when the file is
    // absent; an existing envelope must parse strictly and match the
    // would-be envelope field-by-field. Any failure preserves the original
    // bytes (no `Err(_) => write` fallback).
    let envelope_path = match envelope_reuse_policy(output_dir, envelope)? {
        EnvelopeReuse::Missing => envelope.write(output_dir)?,
        EnvelopeReuse::ExistingMatches => {
            eprintln!(
                "reusing existing runner-config envelope (digest {}); the verifier \
                 independently recomputes and cross-checks it",
                envelope.runner_config_digest
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
pub const PREFLIGHT_REPORT_SCHEMA_VERSION: &str = "mida.preflight-report/v2";

/// The two fixed Oreans cases; the launch attestation accepts exactly this
/// set (no cross-case reuse).
pub const FIXED_CASE_IDS: [&str; 2] = ["origin_macro", "lunlun_software"];

/// The P7 launch-boundary gate (production).
///
/// Consumes `preflight.json` + the envelope under `output_dir` and returns
/// `Ok(())` only when:
///
/// - the report parses strictly (unknown fields fail closed) as
///   `mida.preflight-report/v2`;
/// - `status == "ready"`;
/// - `report.runner_config_digest == envelope.runner_config_digest`
///   (the acceptance-recomputed digest equals the runner-emitted digest);
/// - `cli_binary_matches == true`.
///
/// Any envelope/report absence, schema drift, digest drift, or CLI identity
/// drift is an error — the caller must not create a sample process.
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

/// Strictly parse the gate report (deny-unknown-fields, v2 shape).
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

/// The shared ready-chain checks: status ready, digest equality with the
/// envelope, CLI identity matched.
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
    if report.runner_config_digest.to_lowercase() != envelope.runner_config_digest.to_lowercase() {
        bail!(
            "runner-config digest drift: report {} vs envelope {}",
            report.runner_config_digest,
            envelope.runner_config_digest
        );
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
    /// Verifier override (tests); `None` resolves the acceptance binary.
    pub acceptance_bin: Option<&'a Path>,
}

/// The unique evidence context produced by a successful launch attestation
/// (P6.3-B/D). All subsequent sidecar and bundle producers consume it; the
/// bundle assembler draws the runner-config digest from it, so the digest
/// can never be caller-supplied. Single-use: [`RunEvidenceContext::consume`]
/// turns a consumed context into an error on any further use.
#[derive(Debug, Clone)]
pub struct RunEvidenceContext {
    pub case_id: String,
    pub tool_revision: String,
    pub runner_config_digest: String,
    pub protected_input: PathBuf,
    pub candidate: PathBuf,
    pub cli_binary_sha256: String,
    consumed: bool,
}

impl RunEvidenceContext {
    /// Construct with validation (digest must be 64 hex, case id non-empty).
    pub fn new(
        case_id: String,
        tool_revision: String,
        runner_config_digest: String,
        protected_input: PathBuf,
        candidate: PathBuf,
        cli_binary_sha256: String,
    ) -> anyhow::Result<RunEvidenceContext> {
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
        Ok(RunEvidenceContext {
            case_id,
            tool_revision,
            runner_config_digest: runner_config_digest.to_lowercase(),
            protected_input,
            candidate,
            cli_binary_sha256: cli_binary_sha256.to_lowercase(),
            consumed: false,
        })
    }

    /// The attestation-bound runner-config digest (the only digest source
    /// for sidecar/bundle producers).
    pub fn digest(&self) -> &str {
        &self.runner_config_digest
    }

    /// Consume the one-time authorization. Any second consume (or any use
    /// after the first) fails closed.
    pub fn consume(&mut self) -> anyhow::Result<()> {
        if self.consumed {
            bail!(
                "run evidence context for case {case_id} is already consumed (one-time authorization)",
                case_id = self.case_id
            );
        }
        self.consumed = true;
        Ok(())
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

    // P6.3-A: the actual run-config digest must equal the envelope digest.
    bind_actual_config_to_envelope(output_dir, ctx.runner_config)?;

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
    let current_identity = file_identity(ctx.input)?;
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
    if !FIXED_CASE_IDS.contains(&target_case_id.as_str()) {
        bail!(
            "target case {:?} is not one of the two fixed Oreans cases",
            target_case_id
        );
    }

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
    if FIXED_CASE_IDS
        .iter()
        .any(|id| present_ids.iter().filter(|p| *p == id).count() != 1)
        || present_ids.len() != FIXED_CASE_IDS.len()
    {
        bail!(
            "fresh report case set must be exactly [{}, {}] with no duplicates, got {:?}",
            FIXED_CASE_IDS[0],
            FIXED_CASE_IDS[1],
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

    // The current output canonical path must equal the preflight candidate.
    let current_output = canonicalize_loose(ctx.output);
    let preflight_candidate = PathBuf::from(&fresh_target.candidate_output);
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
    let digest = envelope_runner_config_digest(output_dir)?;
    let context = RunEvidenceContext::new(
        target_case_id,
        envelope.tool_revision.clone(),
        digest,
        canonicalize_loose(ctx.input),
        current_output,
        current_cli_sha,
    )?;
    Ok(context)
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
    let verifier = ctx
        .acceptance_bin
        .map(Path::to_path_buf)
        .unwrap_or_else(resolve_acceptance_bin);
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

/// Digest the launch boundary reports for sidecar/bundle requests. Always
/// the producer-computed value, equality with the report proven by
/// `tests/preflight_boundary.rs`.
pub fn envelope_runner_config_digest(output_dir: &Path) -> anyhow::Result<String> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    Ok(envelope.runner_config_digest.to_lowercase())
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

/// Emit the PE evidence sidecar through the independent acceptance binary
/// (`mida-acceptance oreans-pe-evidence <candidate> --report <dest>`).
/// Exit 0/2 are verifiable outcomes; anything else fails closed.
fn emit_pe_evidence(
    candidate: &Path,
    destination: &Path,
    acceptance_bin: Option<&Path>,
) -> anyhow::Result<()> {
    let verifier = acceptance_bin
        .map(Path::to_path_buf)
        .unwrap_or_else(resolve_acceptance_bin);
    let status = Command::new(&verifier)
        .arg("oreans-pe-evidence")
        .arg(candidate)
        .arg("--report")
        .arg(destination)
        .status()
        .with_context(|| format!("spawn acceptance binary {verifier:?} for PE evidence"))?;
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
/// `candidate` is the actual run output path (member files live next to
/// it); the bundle identity (protected input / candidate) comes from the
/// attestation context. Returns the bundle manifest path.
pub fn complete_run_evidence(
    context: &mut RunEvidenceContext,
    acceptance_bin: Option<&Path>,
    candidate: &Path,
) -> anyhow::Result<PathBuf> {
    let members = evidence_members(candidate)?;
    let pe_evidence_path = candidate.with_extension("pe_evidence.json");
    emit_pe_evidence(candidate, &pe_evidence_path, acceptance_bin)?;
    for (name, path) in &members {
        if !path.is_file() {
            bail!(
                "evidence member {name} is missing at {}; refusing to assemble a \
                 Complete bundle",
                path.display()
            );
        }
    }
    let bundle_output = candidate.with_extension("bundle.json");
    let emitted_at = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{secs}")
    };
    let request = crate::unpacker::bundle_assembler::AssembleRequest {
        emitted_at,
        protected_input: context.protected_input.clone(),
        candidate: context.candidate.clone(),
        members,
        output: bundle_output.clone(),
    };
    crate::unpacker::bundle_assembler::assemble_evidence_bundle(&request, context)?;
    Ok(bundle_output)
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
