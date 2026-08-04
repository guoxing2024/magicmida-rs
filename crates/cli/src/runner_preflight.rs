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

/// Fixed policy of the two-sample Oreans runner (frozen for P7).
///
/// The values mirror the CLI defaults the unpack pipeline applies for the
/// Oreans path; the envelope binds the run to exactly this policy, and the
/// acceptance verifier independently recomputes the digest.
pub fn frozen_runner_config() -> mida_core::runner_config::RunnerConfig {
    use mida_core::runner_config::IsolationConfig;
    mida_core::runner_config::RunnerConfig {
        tool_revision: String::new(),     // filled at emission time
        cli_binary_sha256: String::new(), // filled at emission time
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
            schema: "./runner-config-envelope.schema.json".to_string(),
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
/// This is a minimal runner-side copy of the acceptance report contract;
/// unknown fields fail closed so a drifted report schema cannot slip past.
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
    pub cases: Vec<PreflightCaseGate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightCaseGate {
    pub case_id: String,
    pub identity_ok: bool,
    pub reasons: Vec<String>,
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

/// The runner-side offline-preflight driver (production).
///
/// Emits the envelope (or reuses an existing one — re-runs are idempotent;
/// an existing envelope is still fully validated by the verifier, which
/// reparses its config and recomputes the digest, so a stale or tampered
/// envelope is rejected), drives the independent verifier binary
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
    let envelope_path = match RunnerConfigEnvelope::read(output_dir) {
        Ok(existing) => {
            eprintln!(
                "reusing existing runner-config envelope (digest {}); the verifier \
                 independently recomputes and cross-checks it",
                existing.runner_config_digest
            );
            output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME)
        }
        Err(_) => envelope.write(output_dir)?,
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

/// The P7 launch-boundary gate (production).
///
/// Consumes `preflight.json` + the envelope under `output_dir` and returns
/// `Ok(())` only when:
///
/// - the report parses strictly (unknown fields fail closed);
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
    let report_path = output_dir.join(PREFLIGHT_REPORT_FILENAME);
    let bytes = std::fs::read(&report_path)
        .with_context(|| format!("read preflight report {}", report_path.display()))?;
    let report: PreflightReportGate = serde_json::from_slice(&bytes).map_err(|e| {
        anyhow!(
            "preflight report {} rejected (unknown/malformed fields): {e}",
            report_path.display()
        )
    })?;
    if report.schema_version != "mida.preflight-report/v1" {
        bail!(
            "preflight report schema {:?} != mida.preflight-report/v1",
            report.schema_version
        );
    }
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

/// Digest the launch boundary reports for sidecar/bundle requests. Always
/// the producer-computed value, equality with the report proven by
/// `tests/preflight_boundary.rs`.
pub fn envelope_runner_config_digest(output_dir: &Path) -> anyhow::Result<String> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    Ok(envelope.runner_config_digest.to_lowercase())
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
