//! P6.2 production-closure black-box tests: the REAL `mida-cli` binary's
//! offline-preflight path and the launch-boundary gate.
//!
//! Proven end-to-end:
//!
//! - the runner emits `mida.runner-config-envelope/v2` (full config JSON +
//!   producer digest + CLI binary SHA-256 + tool revision + verifier
//!   identity);
//! - the acceptance verifier reparses the envelope with its own types and
//!   recomputes the digest;
//! - runner-emitted digest == acceptance-recomputed digest ==
//!   report.runner_config_digest == envelope_runner_config_digest();
//! - tampering the config, digest, CLI hash, or tool revision is rejected;
//! - the unpack launch boundary consumes the Ready report BEFORE any
//!   process creation (a garbage input never even reaches PE parsing).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mida_cli_preflight_{tag}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn real_manifest(case_id: &str) -> PathBuf {
    workspace_root()
        .join("lab/cases/v2")
        .join(format!("{case_id}.json"))
}

fn acceptance_bin() -> PathBuf {
    let cli_bin = PathBuf::from(env!("CARGO_BIN_EXE_mida-cli"));
    let sibling = cli_bin
        .parent()
        .expect("cli binary has a parent")
        .join("mida-acceptance.exe");
    assert!(
        sibling.exists(),
        "acceptance binary missing: {}",
        sibling.display()
    );
    assert_acceptance_fresh(&sibling);
    sibling
}

/// Fail closed on a stale sibling acceptance binary (P6.3.1 hermetic tests):
/// the binary must be newer than every acceptance source file, otherwise the
/// test would silently run against a verifier that does not match the
/// current build. The `cargo test --workspace` gate rebuilds it fresh.
fn assert_acceptance_fresh(sibling: &Path) {
    let acc_root = workspace_root().join("crates/acceptance");
    let binary_mtime = fs::metadata(sibling)
        .and_then(|m| m.modified())
        .expect("acceptance binary mtime");
    let mut stale = false;
    for path in source_files(&acc_root) {
        let mtime = match fs::metadata(&path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        if mtime > binary_mtime {
            stale = true;
            break;
        }
    }
    assert!(
        !stale,
        "stale acceptance binary {} (newer than acceptance source); \
         run `cargo test --workspace` to rebuild it before testing",
        sibling.display()
    );
}

/// Recursively collect the `.rs` sources (plus Cargo.toml) of a crate.
fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().map(|e| e == "rs").unwrap_or(false)
                    || p.file_name().map(|n| n == "Cargo.toml").unwrap_or(false)
                {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn run_cli(args: &[&str], env: &[(&str, String)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mida-cli"));
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.args(args).output().expect("spawn mida-cli")
}

fn fake_binary(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, b"FAKE-CLI-BINARY-PAYLOAD").unwrap();
    path
}

fn missing_input(dir: &Path) -> PathBuf {
    let p = dir.join("protected_input.bin");
    let _ = fs::remove_file(&p);
    p
}

/// Deterministic scratch git repo: the worktree probe sees a clean tree
/// with a stable HEAD regardless of the state of the real repository the
/// tests run from (the probe must not depend on uncommitted changes).
fn scratch_repo(parent: &Path) -> PathBuf {
    let repo = parent.join("scratch-repo");
    fs::create_dir_all(&repo).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&["init", "-q", "-b", "main"]);
    run(&["config", "user.email", "test@mida.local"]);
    run(&["config", "user.name", "mida test"]);
    fs::write(repo.join("probe.txt"), "probe").unwrap();
    run(&["add", "probe.txt"]);
    run(&["commit", "-q", "-m", "seed"]);
    repo
}

/// Full offline-preflight argument vector for the two fixed cases.
fn preflight_args(dir: &Path, repo_root: &Path) -> Vec<String> {
    preflight_args_with_cli(dir, repo_root, &fake_binary(dir, "mida_cli.exe"))
}

/// Same as [`preflight_args`] but with an explicit `--cli-binary` (used by
/// the launch-gate positive control, which must stage the envelope for the
/// REAL mida-cli binary so the actual run-config digest matches at launch).
fn preflight_args_with_cli(dir: &Path, repo_root: &Path, cli_binary: &Path) -> Vec<String> {
    vec![
        "/offline-preflight".to_string(),
        dir.display().to_string(),
        format!("--cli-binary={}", cli_binary.display()),
        format!("--repo-root={}", repo_root.display()),
        format!(
            "--toolchain-pin={}",
            workspace_root().join("rust-toolchain.toml").display()
        ),
        "--expected-toolchain=1.97.1".to_string(),
        // P6.3.1: the verifier is injected explicitly (never the
        // environment). Staging with the real acceptance binary.
        format!("--acceptance-bin={}", acceptance_bin().display()),
        "--case".to_string(),
        real_manifest("origin_macro").display().to_string(),
        missing_input(dir).display().to_string(),
        dir.join("origin_candidate.exe").display().to_string(),
        "--case".to_string(),
        real_manifest("lunlun_software").display().to_string(),
        missing_input(dir).display().to_string(),
        dir.join("lunlun_candidate.exe").display().to_string(),
    ]
}

fn run_preflight(dir: &Path, repo_root: &Path) -> Output {
    let args = preflight_args(dir, repo_root);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cli(&arg_refs, &[])
}

/// Baseline: two real locked manifests, missing samples, pinned CLI. The
/// ONLY expected outcome is NotReady (missing protected inputs), and the
/// digest chain must hold: envelope == report == acceptance-recomputed.
#[test]
fn offline_preflight_rejects_without_samples_and_chain_is_consistent() {
    let dir = temp_dir("chain");
    let repo_root = scratch_repo(&dir);
    let output = run_preflight(&dir, &repo_root);
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing samples must be NotReady (exit 2): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "missing samples must be NotReady (exit 2): {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let envelope_path = dir.join("runner-config-envelope.json");
    let report_path = dir.join("preflight.json");
    assert!(envelope_path.exists(), "envelope must be emitted");
    assert!(report_path.exists(), "report must be written");

    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();

    assert_eq!(
        report["status"].as_str(),
        Some("not_ready"),
        "status: {report}"
    );
    let reasons: Vec<&str> = report["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("cannot read protected input")),
        "reasons: {reasons:?}"
    );

    // Chain: runner-emitted digest == report digest == acceptance-recomputed.
    let envelope_digest = envelope["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_lowercase();
    let report_digest = report["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert_eq!(envelope_digest, report_digest, "envelope vs report digest");
    let parsed: mida_acceptance::RunnerConfig =
        serde_json::from_value(envelope["runner_config"].clone()).unwrap();
    let recomputed = mida_acceptance::runner_config_digest(&parsed);
    assert_eq!(
        envelope_digest, recomputed,
        "producer vs acceptance recompute"
    );
    assert_eq!(
        mida_cli::runner_preflight::envelope_runner_config_digest(&dir).unwrap(),
        envelope_digest,
        "bundle-path digest source must match"
    );
    assert_eq!(envelope_digest.len(), 64);

    // The envelope carries the full contract fields (v2, with the pinned
    // verifier identity).
    assert_eq!(
        envelope["schema_version"].as_str(),
        Some("mida.runner-config-envelope/v2")
    );
    assert!(!envelope["cli_binary_sha256"].as_str().unwrap().is_empty());
    assert!(!envelope["tool_revision"].as_str().unwrap().is_empty());
    assert!(
        envelope["verifier_sha256"].as_str().unwrap().len() == 64,
        "envelope must pin the verifier identity"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Tampering the producer digest must be a hard, fail-closed error: the
/// existing envelope no longer matches the would-be envelope, so the
/// staging run refuses to overwrite it and the original bytes are
/// preserved (P6.3-C).
#[test]
fn tampered_digest_rejected() {
    let dir = temp_dir("tamper_digest");
    let repo_root = scratch_repo(&dir);
    let env: &[(&str, String)] = &[];
    let args = preflight_args(&dir, &repo_root);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let baseline = run_cli(&arg_refs, env);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    // Flip one hex char of the producer digest.
    let envelope_path = dir.join("runner-config-envelope.json");
    let original_bytes = fs::read(&envelope_path).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
    let digest = envelope["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = format!(
        "{}{}{}",
        &digest[..0],
        if digest.as_bytes()[0] == b'a' {
            "b"
        } else {
            "a"
        },
        &digest[1..]
    );
    envelope["runner_config_digest"] = serde_json::json!(flipped);
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_cli(&arg_refs, env);
    assert_eq!(
        tampered.status.code(),
        Some(1),
        "tampered digest must be a hard config error"
    );
    let stderr = String::from_utf8_lossy(&tampered.stderr);
    assert!(stderr.contains("refusing to overwrite"), "stderr: {stderr}");
    // The tampered bytes must be preserved exactly (no overwrite).
    assert_eq!(
        fs::read(&envelope_path).unwrap(),
        tampered_bytes,
        "the original envelope bytes must remain untouched"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Unknown fields in the envelope must fail closed with the original bytes
/// preserved (P6.3-C).
#[test]
fn tampered_unknown_field_rejected() {
    let dir = temp_dir("tamper_unknown");
    let repo_root = scratch_repo(&dir);
    let env: &[(&str, String)] = &[];
    let args = preflight_args(&dir, &repo_root);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let baseline = run_cli(&arg_refs, env);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    let envelope_path = dir.join("runner-config-envelope.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    envelope["sneaky_extra"] = serde_json::json!(1);
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_cli(&arg_refs, env);
    assert_eq!(
        tampered.status.code(),
        Some(1),
        "unknown envelope field must be a hard config error"
    );
    assert_eq!(
        fs::read(&envelope_path).unwrap(),
        tampered_bytes,
        "the tampered envelope bytes must remain untouched"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Tampering the CLI binary identity in the envelope must be a hard,
/// fail-closed error with the original bytes preserved (P6.3-C).
#[test]
fn tampered_cli_hash_rejected() {
    let dir = temp_dir("tamper_cli");
    let repo_root = scratch_repo(&dir);
    let env: &[(&str, String)] = &[];
    let args = preflight_args(&dir, &repo_root);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let baseline = run_cli(&arg_refs, env);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    let envelope_path = dir.join("runner-config-envelope.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    envelope["cli_binary_sha256"] = serde_json::json!("f".repeat(64));
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_cli(&arg_refs, env);
    assert_eq!(
        tampered.status.code(),
        Some(1),
        "tampered CLI hash must be a hard config error"
    );
    let stderr = String::from_utf8_lossy(&tampered.stderr);
    assert!(stderr.contains("refusing to overwrite"), "stderr: {stderr}");
    assert_eq!(
        fs::read(&envelope_path).unwrap(),
        tampered_bytes,
        "the tampered envelope bytes must remain untouched"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Tampering the tool revision (in the config inside the envelope) must be
/// a hard, fail-closed error with the original bytes preserved (P6.3-C).
#[test]
fn tampered_tool_revision_rejected() {
    let dir = temp_dir("tamper_revision");
    let repo_root = scratch_repo(&dir);
    let env: &[(&str, String)] = &[];
    let args = preflight_args(&dir, &repo_root);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let baseline = run_cli(&arg_refs, env);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    let envelope_path = dir.join("runner-config-envelope.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    envelope["runner_config"]["tool_revision"] =
        serde_json::json!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_cli(&arg_refs, env);
    assert_eq!(
        tampered.status.code(),
        Some(1),
        "tampered revision must be a hard config error"
    );
    let stderr = String::from_utf8_lossy(&tampered.stderr);
    assert!(stderr.contains("refusing to overwrite"), "stderr: {stderr}");
    assert_eq!(
        fs::read(&envelope_path).unwrap(),
        tampered_bytes,
        "the tampered envelope bytes must remain untouched"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// The launch boundary must consume the Ready report BEFORE any process
/// creation: with a NotReady report (or no envelope at all), the unpack run
/// is blocked even before PE parsing — proven with a garbage input that is
/// not a valid PE and would fail later in the pipeline if the gate did not
/// exist.
#[test]
fn launch_gate_blocks_before_process_creation() {
    // A gated run with an unavailable envelope must be blocked immediately.
    let dir = temp_dir("launch_no_envelope");
    let garbage = dir.join("input.bin");
    fs::write(&garbage, b"NOT-A-PE-NOT-A-PE-NOT-A-PE").unwrap();
    let candidate = dir.join("candidate.exe");
    let output = run_cli(
        &[
            "/unpack",
            garbage.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            dir.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "missing envelope must block launch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("launch blocked") && stderr.contains("envelope"),
        "stderr: {stderr}"
    );
    assert!(!candidate.exists(), "no candidate may be produced");
    let _ = fs::remove_dir_all(&dir);

    // A gated run with a NotReady report must be blocked before PE parsing.
    let dir = temp_dir("launch_not_ready");
    let repo_root = scratch_repo(&dir);
    let env: &[(&str, String)] = &[];
    // Stage for the REAL mida-cli binary so the launch-side config digest
    // check passes and the report gate is the deciding check.
    let real_cli = PathBuf::from(env!("CARGO_BIN_EXE_mida-cli"));
    let args = preflight_args_with_cli(&dir, &repo_root, &real_cli);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let preflight = run_cli(&arg_refs, env);
    assert_eq!(preflight.status.code(), Some(2), "preflight NotReady");

    let garbage = dir.join("input.bin");
    fs::write(&garbage, b"NOT-A-PE-NOT-A-PE-NOT-A-PE").unwrap();
    let candidate = dir.join("candidate.exe");
    let output = run_cli(
        &[
            "/unpack",
            garbage.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            dir.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "NotReady report must block launch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("launch blocked") && stderr.contains("preflight attestation"),
        "stderr: {stderr}"
    );
    assert!(!candidate.exists(), "no candidate may be produced");
    let _ = fs::remove_dir_all(&dir);
}

/// A syntactically valid `ready` report whose digest no longer matches the
/// envelope must be blocked by the launch gate (defense in depth at the
/// boundary), before any process creation.
#[test]
fn launch_gate_rejects_digest_drift() {
    let dir = temp_dir("launch_drift");
    let repo_root = scratch_repo(&dir);
    let env: &[(&str, String)] = &[];
    let real_cli = PathBuf::from(env!("CARGO_BIN_EXE_mida-cli"));
    let args = preflight_args_with_cli(&dir, &repo_root, &real_cli);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let preflight = run_cli(&arg_refs, env);
    assert_eq!(preflight.status.code(), Some(2), "preflight NotReady");

    // Build a syntactically valid READY report, then tamper its digest so it
    // no longer matches the envelope.
    let envelope_path = dir.join("runner-config-envelope.json");
    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    let correct_digest = envelope["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let flipped = format!(
        "{}{}",
        if correct_digest.as_bytes()[0] == b'a' {
            "b"
        } else {
            "a"
        },
        &correct_digest[1..]
    );
    let report_path = dir.join("preflight.json");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "mida.preflight-report/v2",
            "status": "ready",
            "reasons": [],
            "runner_config_digest": flipped,
            "head_revision": null,
            "worktree_clean": true,
            "toolchain_matches": true,
            "cli_binary_sha256": envelope["cli_binary_sha256"],
            "cli_binary_matches": true,
            "cli_binary_path": "",
            "repo_root": "",
            "toolchain_pin_file": "",
            "expected_toolchain": "1.97.1",
            "cases": [
                {"case_id": "origin_macro", "identity_ok": true, "reasons": [],
                 "protected_input": null, "protected_input_path": "", "manifest_path": "",
                 "candidate_output": ""},
                {"case_id": "lunlun_software", "identity_ok": true, "reasons": [],
                 "protected_input": null, "protected_input_path": "", "manifest_path": "",
                 "candidate_output": ""}
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let garbage = dir.join("input.bin");
    fs::write(&garbage, b"NOT-A-PE-NOT-A-PE-NOT-A-PE").unwrap();
    let candidate = dir.join("candidate.exe");
    let output = run_cli(
        &[
            "/unpack",
            garbage.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            dir.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "digest drift must block launch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("digest drift"), "stderr: {stderr}");
    assert!(!candidate.exists(), "no candidate may be produced");
    let _ = fs::remove_dir_all(&dir);
}

/// A hand-written `ready` report is NOT an authorization credential
/// (P6.3-B): the launch boundary re-runs the independent acceptance
/// verifier against the current run context, so a fabricated Ready report
/// (whose digest chain matches the envelope) is still blocked when the
/// verifier re-run is NotReady — proven with a garbage input and missing
/// samples, before any process creation.
#[test]
fn launch_gate_blocks_hand_written_ready_after_verifier_rerun() {
    let dir = temp_dir("launch_fake_ready");
    let repo_root = scratch_repo(&dir);
    let env: &[(&str, String)] = &[];
    // Stage the envelope for the REAL mida-cli binary so the actual
    // run-config digest matches at launch; the real preflight is NotReady
    // (missing samples).
    let real_cli = PathBuf::from(env!("CARGO_BIN_EXE_mida-cli"));
    let args = preflight_args_with_cli(&dir, &repo_root, &real_cli);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let preflight = run_cli(&arg_refs, env);
    assert_eq!(preflight.status.code(), Some(2), "preflight NotReady");

    // Launch input: garbage bytes whose identity is then recorded into the
    // fabricated Ready report (so the attestation reaches the verifier
    // re-run instead of failing the local identity match first).
    let garbage = dir.join("input.bin");
    fs::write(&garbage, b"NOT-A-PE-NOT-A-PE-NOT-A-PE").unwrap();
    let candidate = dir.join("candidate.exe");
    let garbage_identity = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(fs::read(&garbage).unwrap());
        let mut hex = String::with_capacity(64);
        for byte in digest {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    };

    // Fabricate a syntactically valid Ready report with the correct digest
    // chain, CLI identity, and the current input identity.
    let envelope_path = dir.join("runner-config-envelope.json");
    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    let correct_digest = envelope["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let report_path = dir.join("preflight.json");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "mida.preflight-report/v2",
            "status": "ready",
            "reasons": [],
            "runner_config_digest": correct_digest,
            "head_revision": null,
            "worktree_clean": true,
            "toolchain_matches": true,
            "cli_binary_sha256": envelope["cli_binary_sha256"],
            "cli_binary_matches": true,
            "cli_binary_path": "",
            "repo_root": repo_root.display().to_string(),
            "toolchain_pin_file": workspace_root().join("rust-toolchain.toml").display().to_string(),
            "expected_toolchain": "1.97.1",
            "cases": [
                {"case_id": "origin_macro", "identity_ok": true, "reasons": [],
                 "protected_input": {"sha256": garbage_identity, "size_bytes": 25},
                 "protected_input_path": garbage.display().to_string(),
                 "manifest_path": real_manifest("origin_macro").display().to_string(),
                 "candidate_output": candidate.display().to_string()},
                {"case_id": "lunlun_software", "identity_ok": true, "reasons": [],
                 "protected_input": null, "protected_input_path": "",
                 "manifest_path": real_manifest("lunlun_software").display().to_string(),
                 "candidate_output": ""}
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    // The attestation re-runs the REAL verifier against the current
    // context: the fresh report is NotReady (the garbage input does not
    // match the locked identity), so the fabricated Ready is refused.
    let output = run_cli(
        &[
            "/unpack",
            garbage.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            dir.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "hand-written ready must not authorize a launch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("launch blocked"), "stderr: {stderr}");
    assert!(!candidate.exists(), "no candidate may be produced");
    let _ = fs::remove_dir_all(&dir);
}
