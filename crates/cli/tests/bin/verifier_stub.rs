//! Test-support verifier stub (P6.3-QA).
//!
//! A deterministic stand-in for the `mida-acceptance` binary used ONLY by
//! the launch-attestation pass-path tests (positive control, bundle digest
//! chain, output-path and input-identity checks that must not depend on the
//! real locked samples). Tests inject it explicitly via `--acceptance-bin`
//! (P6.3.1) — never through the environment.
//!
//! Supported subcommands (mirroring the acceptance CLI surface the runner
//! spawns):
//!
//! - `preflight --envelope <p> --output-dir <d> --cli-binary <b>
//!   --repo-root <r> --toolchain-pin <t> --expected-toolchain <v>
//!   --case <manifest> <input> <output> [...]`: re-parses the envelope,
//!   copies the producer digest and CLI identity, recomputes the CLI binary
//!   digest and every case input identity from disk, and writes a
//!   `mida.preflight-report/v2` Ready report. Exit 0.
//! - `oreans-pe-evidence <candidate> --report <dest>`: writes a minimal
//!   `mida.oreans-pe-evidence/v1` document bound to the candidate identity.
//!   Exit 0.
//!
//! The stub is deliberately dumb: it reports Ready for whatever cases it is
//! given (identity recompute only). It never validates against the locked
//! manifests — that is exactly why every negative attack test uses the REAL
//! acceptance binary.

use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `{sha256, size_bytes}` of a file, or `None` when unreadable/empty.
fn file_identity(path: &Path) -> Option<(String, u64)> {
    match std::fs::read(path) {
        Ok(data) if !data.is_empty() => Some((sha256_hex(&data), data.len() as u64)),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: mida-verifier-stub <preflight|oreans-pe-evidence> ...");
        return ExitCode::from(1);
    }
    match args[0].as_str() {
        "preflight" => cmd_preflight(&args[1..]),
        "oreans-pe-evidence" => cmd_pe_evidence(&args[1..]),
        other => {
            eprintln!("mida-verifier-stub: unknown command {other}");
            ExitCode::from(1)
        }
    }
}

/// Canonicalize `p`, falling back to canonicalizing its parent when the
/// path itself does not exist yet (mirrors the acceptance verifier, which
/// the launch boundary compares against).
fn canonicalize_loose(p: &Path) -> PathBuf {
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

fn cmd_preflight(args: &[String]) -> ExitCode {
    let mut envelope_path: Option<PathBuf> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut cli_binary: Option<PathBuf> = None;
    let mut repo_root: Option<PathBuf> = None;
    let mut toolchain_pin: Option<PathBuf> = None;
    let mut expected_toolchain = String::new();
    let mut cases: Vec<(PathBuf, PathBuf, PathBuf)> = Vec::new();

    let mut i = 0;
    let take = |i: &mut usize, label: &str| -> Option<PathBuf> {
        *i += 1;
        if *i >= args.len() {
            eprintln!("mida-verifier-stub: missing value after {label}");
            return None;
        }
        Some(PathBuf::from(&args[*i]))
    };
    while i < args.len() {
        match args[i].as_str() {
            "--envelope" => envelope_path = take(&mut i, "--envelope"),
            "--output-dir" => output_dir = take(&mut i, "--output-dir"),
            // The acceptance verifier receives the caller's trusted snapshot root;
            // the stub accepts and ignores it (it does not do disk verification).
            "--snapshot-root" => {
                let _ = take(&mut i, "--snapshot-root");
            }
            "--cli-binary" => cli_binary = take(&mut i, "--cli-binary"),
            "--repo-root" => repo_root = take(&mut i, "--repo-root"),
            "--toolchain-pin" => toolchain_pin = take(&mut i, "--toolchain-pin"),
            "--expected-toolchain" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("mida-verifier-stub: missing value after --expected-toolchain");
                    return ExitCode::from(1);
                }
                expected_toolchain = args[i].clone();
            }
            "--case" => {
                let Some(manifest) = take(&mut i, "--case") else {
                    return ExitCode::from(1);
                };
                let Some(input) = take(&mut i, "--case") else {
                    return ExitCode::from(1);
                };
                let Some(output) = take(&mut i, "--case") else {
                    return ExitCode::from(1);
                };
                cases.push((manifest, input, output));
            }
            other => {
                eprintln!("mida-verifier-stub: unknown preflight option {other}");
                return ExitCode::from(1);
            }
        }
        i += 1;
    }
    let (
        Some(envelope_path),
        Some(output_dir),
        Some(cli_binary),
        Some(repo_root),
        Some(toolchain_pin),
    ) = (
        envelope_path,
        output_dir,
        cli_binary,
        repo_root,
        toolchain_pin,
    )
    else {
        eprintln!("mida-verifier-stub: missing required preflight argument");
        return ExitCode::from(1);
    };

    let envelope_bytes = match std::fs::read(&envelope_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("mida-verifier-stub: cannot read envelope: {e}");
            return ExitCode::from(1);
        }
    };
    let envelope: serde_json::Value = match serde_json::from_slice(&envelope_bytes) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("mida-verifier-stub: cannot parse envelope: {e}");
            return ExitCode::from(1);
        }
    };
    let runner_config_digest = envelope["case_set_digest"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    let pinned_cli_sha = envelope["cli_binary_sha256"]
        .as_str()
        .unwrap_or_default()
        .to_lowercase();
    let cli_actual = file_identity(&cli_binary)
        .map(|(s, _)| s)
        .unwrap_or_default();

    // P6.3.3: the v4 envelope is case-bound. For each case, report the
    // envelope's per-case protected-input identity (from case_configs) and
    // per-case runner-config digest so the report cross-validates against
    // the envelope. The stub is deliberately dumb and does not recompute the
    // file — it mirrors the envelope so pass-path tests are hermetic.
    let case_configs = envelope["case_configs"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let case_by_id = |case_id: &str| -> Option<&serde_json::Value> {
        case_configs
            .iter()
            .find(|c| c["case_id"].as_str() == Some(case_id))
    };
    let case_entries: Vec<serde_json::Value> = cases
        .iter()
        .map(|(manifest, input, output)| {
            let case_id = manifest
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let protected = case_by_id(&case_id)
                .and_then(|c| c.get("protected_input").cloned())
                .unwrap_or_else(|| {
                    file_identity(input)
                        .map(|(s, z)| serde_json::json!({"sha256": s, "size_bytes": z}))
                        .unwrap_or(serde_json::Value::Null)
                });
            serde_json::json!({
                "case_id": case_id,
                "identity_ok": true,
                "reasons": [],
                "protected_input": protected,
                "protected_input_path": canonicalize_loose(input).to_string_lossy().to_string(),
                "manifest_path": canonicalize_loose(manifest).to_string_lossy().to_string(),
                "candidate_output": canonicalize_loose(output).to_string_lossy().to_string(),
                "runner_config_digest": case_by_id(&case_id)
                    .and_then(|c| c["runner_config_digest"].as_str())
                    .map(|s| serde_json::json!(s.to_lowercase()))
                    .unwrap_or(serde_json::Value::Null),
            })
        })
        .collect();

    let report = serde_json::json!({
        "schema_version": "mida.preflight-report/v3",
        "status": "ready",
        "reasons": [],
        "runner_config_digest": runner_config_digest,
        "head_revision": "verifier-stub",
        "worktree_clean": true,
        "toolchain_matches": true,
        "cli_binary_sha256": if cli_actual.is_empty() { serde_json::Value::Null } else { serde_json::json!(cli_actual) },
        "cli_binary_matches": !cli_actual.is_empty() && cli_actual == pinned_cli_sha,
        "cli_binary_path": cli_binary.to_string_lossy().to_string(),
        "repo_root": repo_root.to_string_lossy().to_string(),
        "toolchain_pin_file": toolchain_pin.to_string_lossy().to_string(),
        "expected_toolchain": expected_toolchain,
        "cases": case_entries,
    });

    let destination = output_dir.join("preflight.json");
    if let Err(e) = std::fs::write(&destination, serde_json::to_vec_pretty(&report).unwrap()) {
        eprintln!("mida-verifier-stub: cannot write report: {e}");
        return ExitCode::from(1);
    }
    eprintln!("mida-verifier-stub: READY ({})", destination.display());
    ExitCode::from(0)
}

fn cmd_pe_evidence(args: &[String]) -> ExitCode {
    let mut candidate: Option<PathBuf> = None;
    let mut report: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--report" => {
                i += 1;
                if i >= args.len() {
                    eprintln!("mida-verifier-stub: missing value after --report");
                    return ExitCode::from(1);
                }
                report = Some(PathBuf::from(&args[i]));
            }
            other if other.starts_with('-') => {
                eprintln!("mida-verifier-stub: unknown pe-evidence option {other}");
                return ExitCode::from(1);
            }
            other => {
                if candidate.is_some() {
                    eprintln!("mida-verifier-stub: unexpected argument {other}");
                    return ExitCode::from(1);
                }
                candidate = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }
    let (Some(candidate), Some(report)) = (candidate, report) else {
        eprintln!("mida-verifier-stub: missing candidate or --report");
        return ExitCode::from(1);
    };
    let Some((sha, size)) = file_identity(&candidate) else {
        eprintln!(
            "mida-verifier-stub: cannot read candidate {}",
            candidate.display()
        );
        return ExitCode::from(1);
    };
    let evidence = serde_json::json!({
        "schema_version": "mida.oreans-pe-evidence/v1",
        "candidate": { "sha256": sha, "size_bytes": size },
    });
    if let Err(e) = std::fs::write(&report, serde_json::to_vec_pretty(&evidence).unwrap()) {
        eprintln!("mida-verifier-stub: cannot write pe evidence: {e}");
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}
