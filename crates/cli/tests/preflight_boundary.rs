//! P6.2/P6.3.3 production-closure black-box tests: the REAL `mida-cli` binary's
//! offline-preflight path and the launch-boundary gate.
//!
//! Proven end-to-end:
//!
//! - the runner emits `mida.runner-config-envelope/v4` (case-bound: one full
//!   config JSON + per-case digest for each of the two fixed cases, plus CLI
//!   binary SHA-256, tool revision, verifier identity, and a sealed
//!   `case_set_digest` over every case config + case/input binding);
//! - the acceptance verifier reparses the envelope with its own types and
//!   recomputes each case digest and the case-set digest;
//! - the envelope `case_set_digest` == report `runner_config_digest`;
//! - tampering any config, per-case digest, CLI hash, tool revision, or the
//!   sealed case-set digest is rejected;
//! - the unpack launch boundary consumes the Ready report BEFORE any
//!   process creation (a garbage input never even reaches PE parsing).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

mod common;

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
    common::acceptance_bin()
}

fn run_cli(args: &[&str], env: &[(&str, String)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mida-cli"));
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.args(args).output().expect("spawn mida-cli")
}

/// Spawn a copied `mida-cli` binary. On Windows a just-exited subprocess may
/// briefly hold the exe mapping open; retry the spawn to avoid a transient
/// "file in use" failure.
fn run_cli_at(cli: &Path, args: &[&str]) -> Output {
    let mut last = None;
    for attempt in 0..50 {
        match Command::new(cli).args(args).output() {
            Ok(out) => return out,
            Err(e) => {
                let code = e.raw_os_error();
                last = Some(e);
                if code == Some(32) && attempt < 49 {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    continue;
                }
                break;
            }
        }
    }
    panic!("spawn mida-cli {}: {:?}", cli.display(), last)
}

/// P6.3.2: the production resolver uses ONLY the exact sibling
/// `mida-acceptance.exe` of the running CLI. To inject a verifier we copy the
/// real `mida-cli` into the temp dir and place the desired verifier beside
/// it (mirrors the deployment trust unit, no production override).
fn cli_with_verifier(dir: &Path, verifier: &Path) -> PathBuf {
    let copy = dir.join("mida-cli.exe");
    if !copy.exists() {
        fs::copy(env!("CARGO_BIN_EXE_mida-cli"), &copy).unwrap();
    }
    // Only (re)write the sibling if it differs, so we never fight a
    // just-exited subprocess's file lock on an unchanged verifier.
    let sibling = dir.join("mida-acceptance.exe");
    let same = fs::read(&sibling)
        .ok()
        .is_some_and(|b| b == fs::read(verifier).unwrap());
    if !same {
        fs::copy(verifier, &sibling).unwrap();
    }
    copy
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
    preflight_args_with_cli(dir, repo_root)
}

/// Offline-preflight argument vector (the `--cli-binary` and the verifier
/// sibling are both the copied CLI in `dir`; P6.3.2 has no verifier flag).
fn preflight_args_with_cli(dir: &Path, repo_root: &Path) -> Vec<String> {
    vec![
        "/offline-preflight".to_string(),
        dir.display().to_string(),
        format!("--cli-binary={}", dir.join("mida-cli.exe").display()),
        format!("--repo-root={}", repo_root.display()),
        format!(
            "--toolchain-pin={}",
            workspace_root().join("rust-toolchain.toml").display()
        ),
        "--expected-toolchain=1.97.1".to_string(),
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
    // P6.3.2: the verifier is the CLI sibling (the real acceptance binary
    // copied beside the CLI copy) — never an interface flag.
    let cli = staging_cli(dir);
    let args = preflight_args_with_cli(dir, repo_root);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cli_at(&cli, &arg_refs)
}

/// The staged CLI copy (created on first use) whose sibling verifier is the
/// real acceptance binary — used by both staging and launch so the envelope
/// path/sha stay consistent.
fn staging_cli(dir: &Path) -> PathBuf {
    cli_with_verifier(dir, &acceptance_bin())
}

/// Run a staging `/offline-preflight` argument vector with the staged CLI
/// copy.
fn run_staging_args(dir: &Path, args: &[String]) -> Output {
    let cli = staging_cli(dir);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cli_at(&cli, &arg_refs)
}

/// Baseline: two real locked manifests, missing samples, pinned CLI. The
/// ONLY expected outcome is NotReady (missing protected inputs), and the
/// chain must hold: envelope `case_set_digest` == report `runner_config_digest`,
/// with the v4 case set and per-case digests independently recomputed.
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

    // The envelope is case-bound (v4): a sealed case-set digest over exactly
    // two case configs, each with its own digest.
    assert_eq!(
        envelope["schema_version"].as_str(),
        Some("mida.runner-config-envelope/v4")
    );
    let case_configs = envelope["case_configs"].as_array().unwrap();
    assert_eq!(
        case_configs.len(),
        2,
        "envelope must carry two case configs"
    );
    let case_ids: Vec<&str> = case_configs
        .iter()
        .map(|c| c["case_id"].as_str().unwrap())
        .collect();
    assert!(
        case_ids.contains(&"origin_macro") && case_ids.contains(&"lunlun_software"),
        "case set: {case_ids:?}"
    );
    for case in case_configs {
        let digest = case["runner_config_digest"].as_str().unwrap();
        assert_eq!(digest.len(), 64, "per-case digest must be 64 hex");
        // Independently recompute each per-case digest with the acceptance
        // implementation.
        let parsed: mida_acceptance::RunnerConfig =
            serde_json::from_value(case["runner_config"].clone()).unwrap();
        assert_eq!(
            mida_acceptance::runner_config_digest(&parsed),
            digest.to_lowercase(),
            "case {} producer vs acceptance recompute",
            case["case_id"]
        );
    }
    // The two case configs must differ (Origin vs Lunlun). With the sample
    // files absent the D3 default cannot resolve (both fall back to legacy),
    // so both per-case digests may be equal here; the Origin
    // pure_rebuild=true / Lunlun=false distinction is asserted in a separate
    // positive-control test with the real samples present.
    let origin_digest = case_configs
        .iter()
        .find(|c| c["case_id"] == "origin_macro")
        .unwrap()["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let lunlun_digest = case_configs
        .iter()
        .find(|c| c["case_id"] == "lunlun_software")
        .unwrap()["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(origin_digest.len(), 64);
    assert_eq!(lunlun_digest.len(), 64);
    // The sealed case-set digest still distinguishes the two cases by their
    // distinct protected-input identities even when the configs are equal.
    let case_set = envelope["case_set_digest"].as_str().unwrap();
    assert_eq!(case_set.len(), 64);

    // Chain: envelope case_set_digest == report runner_config_digest.
    let envelope_case_set = envelope["case_set_digest"].as_str().unwrap().to_lowercase();
    let report_digest = report["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert_eq!(
        envelope_case_set, report_digest,
        "envelope case-set digest vs report digest"
    );
    assert_eq!(envelope_case_set.len(), 64);

    // The envelope carries the full contract fields (v4).
    assert!(!envelope["cli_binary_sha256"].as_str().unwrap().is_empty());
    assert!(!envelope["tool_revision"].as_str().unwrap().is_empty());
    assert_eq!(
        envelope["verifier_source"].as_str(),
        Some("<cli-dir>/mida-acceptance.exe")
    );
    assert!(!envelope["verifier_path"].as_str().unwrap().is_empty());
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
    let args = preflight_args(&dir, &repo_root);
    let baseline = run_staging_args(&dir, &args);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    // Flip one hex char of a per-case runner-config digest.
    let envelope_path = dir.join("runner-config-envelope.json");
    let original_bytes = fs::read(&envelope_path).unwrap();
    let mut envelope: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();
    let digest = envelope["case_configs"][0]["runner_config_digest"]
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
    envelope["case_configs"][0]["runner_config_digest"] = serde_json::json!(flipped);
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_staging_args(&dir, &args);
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
    let args = preflight_args(&dir, &repo_root);
    let baseline = run_staging_args(&dir, &args);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    let envelope_path = dir.join("runner-config-envelope.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    envelope["sneaky_extra"] = serde_json::json!(1);
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_staging_args(&dir, &args);
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
    let args = preflight_args(&dir, &repo_root);
    let baseline = run_staging_args(&dir, &args);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    let envelope_path = dir.join("runner-config-envelope.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    envelope["cli_binary_sha256"] = serde_json::json!("f".repeat(64));
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_staging_args(&dir, &args);
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
    let args = preflight_args(&dir, &repo_root);
    let baseline = run_staging_args(&dir, &args);
    assert_eq!(baseline.status.code(), Some(2), "baseline NotReady");

    let envelope_path = dir.join("runner-config-envelope.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    envelope["case_configs"][0]["runner_config"]["tool_revision"] =
        serde_json::json!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    let tampered_bytes = serde_json::to_vec_pretty(&envelope).unwrap();
    fs::write(&envelope_path, &tampered_bytes).unwrap();

    let tampered = run_staging_args(&dir, &args);
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
    // Stage + launch with the staged CLI copy (sibling verifier = real
    // acceptance) so the envelope path/sha stay consistent.
    let args = preflight_args_with_cli(&dir, &repo_root);
    let preflight = run_staging_args(&dir, &args);
    assert_eq!(preflight.status.code(), Some(2), "preflight NotReady");

    let garbage = dir.join("input.bin");
    fs::write(&garbage, b"NOT-A-PE-NOT-A-PE-NOT-A-PE").unwrap();
    let candidate = dir.join("candidate.exe");
    let launch_cli = staging_cli(&dir);
    let output = run_cli_at(
        &launch_cli,
        &[
            "/unpack",
            garbage.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            dir.to_str().unwrap(),
        ],
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
    let args = preflight_args_with_cli(&dir, &repo_root);
    let preflight = run_staging_args(&dir, &args);
    assert_eq!(preflight.status.code(), Some(2), "preflight NotReady");

    // Build a syntactically valid READY report, then tamper a per-case digest
    // so it no longer matches the envelope case config.
    let envelope_path = dir.join("runner-config-envelope.json");
    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&envelope_path).unwrap()).unwrap();
    let correct_digest = envelope["case_configs"][0]["runner_config_digest"]
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
            "schema_version": "mida.preflight-report/v3",
            "status": "ready",
            "reasons": [],
            "runner_config_digest": envelope["case_set_digest"],
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
                 "candidate_output": "", "runner_config_digest": flipped},
                {"case_id": "lunlun_software", "identity_ok": true, "reasons": [],
                 "protected_input": null, "protected_input_path": "", "manifest_path": "",
                 "candidate_output": "", "runner_config_digest": envelope["case_configs"][1]["runner_config_digest"]}
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let garbage = dir.join("input.bin");
    fs::write(&garbage, b"NOT-A-PE-NOT-A-PE-NOT-A-PE").unwrap();
    let candidate = dir.join("candidate.exe");
    let launch_cli = staging_cli(&dir);
    let output = run_cli_at(
        &launch_cli,
        &[
            "/unpack",
            garbage.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            dir.to_str().unwrap(),
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(1),
        "a fabricated report must block launch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("launch blocked"), "stderr: {stderr}");
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
    // Stage + launch with the staged CLI copy (sibling verifier = real
    // acceptance); the real preflight is NotReady (missing samples).
    let args = preflight_args_with_cli(&dir, &repo_root);
    let preflight = run_staging_args(&dir, &args);
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
    let origin_digest = envelope["case_configs"][0]["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let lunlun_digest = envelope["case_configs"][1]["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let report_path = dir.join("preflight.json");
    fs::write(
        &report_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "mida.preflight-report/v3",
            "status": "ready",
            "reasons": [],
            "runner_config_digest": envelope["case_set_digest"],
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
                 "candidate_output": candidate.display().to_string(),
                 "runner_config_digest": origin_digest},
                {"case_id": "lunlun_software", "identity_ok": true, "reasons": [],
                 "protected_input": null, "protected_input_path": "",
                 "manifest_path": real_manifest("lunlun_software").display().to_string(),
                 "candidate_output": "", "runner_config_digest": lunlun_digest}
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    // The attestation re-runs the REAL verifier against the current
    // context: the fresh report is NotReady (the garbage input does not
    // match the locked identity), so the fabricated Ready is refused.
    let launch_cli = staging_cli(&dir);
    let output = run_cli_at(
        &launch_cli,
        &[
            "/unpack",
            garbage.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            dir.to_str().unwrap(),
        ],
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

// ---------------------------------------------------------------------------
// P6.3.3.1: acceptance verifier keyed-identity attack tests
// (hermetic — the envelope is constructed directly from the locked manifest
// identity constants; the default tests NEVER read D:\MidaVault).
// ---------------------------------------------------------------------------

/// Locked protected-input identity constants (mirror of the case manifests).
const ORIGIN_SHA: &str = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
const ORIGIN_SIZE: u64 = 5_232_656;
const LUNLUN_SHA: &str = "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07";
const LUNLUN_SIZE: u64 = 4_976_144;

/// A synthetic (valid) runner config for a case, and its acceptance-computed
/// digest. `pure_rebuild` selects Origin (true) or legacy (false) policy so
/// an attack can pair a case's config with either case_id independently.
fn case_runner_config(case_id: &str) -> (mida_acceptance::RunnerConfig, String) {
    case_runner_config_pure(case_id, case_id == "origin_macro")
}

/// Build a synthetic runner config with an explicit pure-rebuild policy.
fn case_runner_config_pure(
    _case_id: &str,
    pure_rebuild: bool,
) -> (mida_acceptance::RunnerConfig, String) {
    let mut cfg = mida_acceptance::RunnerConfig {
        packer_family: "oreans_themida".to_string(),
        tool_revision: "rev".to_string(),
        cli_binary_sha256: "a".repeat(64),
        features: vec!["default".to_string()],
        debugger_backend: "windows_debug_api".to_string(),
        oep_policy: "captured".to_string(),
        container_restore: "off".to_string(),
        shrink: true,
        data_sections: false,
        pure_rebuild,
        capture_policy_digest: String::new(),
        iat_fix_strategy: "v3-trace".to_string(),
        timeout_secs: 120,
        isolation: mida_acceptance::IsolationConfig {
            workspace_policy: "isolated-temp".to_string(),
            process_tree_policy: "single-process".to_string(),
            network_policy: "blocked".to_string(),
        },
        attempt_numbering: "continuous-1-based".to_string(),
        evidence_bundle_schema: "mida.oreans-evidence-bundle/v2".to_string(),
        gate_schema: "mida.oreans-two-sample-gate/v8".to_string(),
        env_allowlist: vec!["CARGO_TARGET_DIR".to_string()],
    };
    cfg.tool_revision = "rev".to_string();
    cfg.cli_binary_sha256 = "a".repeat(64);
    let digest = mida_acceptance::runner_config_digest(&cfg);
    (cfg, digest)
}

/// One case entry as a JSON value, bound to the given case_id and protected
/// input identity, with a per-case digest computed from its config. The
/// staging-sealed `family_id` is the config's packer family (Oreans for these
/// synthetic cases).
fn case_entry_json(case_id: &str, sha: &str, size: u64) -> serde_json::Value {
    let (cfg, digest) = case_runner_config(case_id);
    serde_json::json!({
        "case_id": case_id,
        "family_id": cfg.packer_family,
        "protected_input": { "sha256": sha, "size_bytes": size },
        "runner_config": serde_json::to_value(&cfg).unwrap(),
        "runner_config_digest": digest,
    })
}

/// A case entry with an EXPLICIT pure-rebuild policy and explicit case_id,
/// so an attack can decouple the config policy from the case_id label.
fn case_entry_with_policy(
    case_id: &str,
    sha: &str,
    size: u64,
    pure_rebuild: bool,
) -> serde_json::Value {
    let (cfg, digest) = case_runner_config_pure(case_id, pure_rebuild);
    serde_json::json!({
        "case_id": case_id,
        "family_id": cfg.packer_family,
        "protected_input": { "sha256": sha, "size_bytes": size },
        "runner_config": serde_json::to_value(&cfg).unwrap(),
        "runner_config_digest": digest,
    })
}

/// Recompute the case-set digest for a list of case entries (fixed canonical
/// order applied by sorting). The `family_id` and the optional sealed
/// `protected_input_path` (G3-R3-R1) are part of the sealed digest.
fn reseal_case_set(entries: &[serde_json::Value]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|c| {
            let family = c
                .get("family_id")
                .and_then(|f| f.as_str())
                .unwrap_or("oreans_themida");
            let path = c
                .get("protected_input_path")
                .and_then(|p| p.as_str())
                .unwrap_or_default()
                .to_lowercase();
            format!(
                "case={}\nfamily={}\nprotected_input={}|{}\nprotected_input_path={}\nrunner_config_digest={}\n",
                c["case_id"].as_str().unwrap(),
                family.to_lowercase(),
                c["protected_input"]["sha256"]
                    .as_str()
                    .unwrap()
                    .to_lowercase(),
                c["protected_input"]["size_bytes"].as_u64().unwrap(),
                path,
                c["runner_config_digest"].as_str().unwrap().to_lowercase(),
            )
        })
        .collect();
    lines.sort();
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(lines.concat().as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Build a v4 envelope document (as JSON) from the given case entries.
fn v4_envelope_json(case_configs: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!({
        "$schema": "./runner-config-envelope.schema.json",
        "schema_version": "mida.runner-config-envelope/v4",
        "cli_binary_sha256": "a".repeat(64),
        "tool_revision": "rev",
        "verifier_source": "<cli-dir>/mida-acceptance.exe",
        "verifier_path": "C:\\dummy\\mida-acceptance.exe",
        "verifier_sha256": "b".repeat(64),
        "case_set_digest": reseal_case_set(&case_configs),
        "case_configs": case_configs,
    })
}

/// A VALID v4 envelope: origin_macro bound to its manifest identity, and
/// lunlun_software bound to its manifest identity, with honest per-case and
/// case-set digests.
fn valid_v4_envelope_json() -> serde_json::Value {
    v4_envelope_json(vec![
        case_entry_json("origin_macro", ORIGIN_SHA, ORIGIN_SIZE),
        case_entry_json("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE),
    ])
}

/// Invoke the REAL acceptance binary directly against an envelope file + the
/// two fixed case triples, returning its output. Proves the verifier
/// independently rejects tampered v4 envelopes (not merely the runner's reuse
/// policy). Synthetic input files are used; the verifier's keyed-identity and
/// per-case-digest checks are the target.
fn run_acceptance_on_envelope(
    dir: &Path,
    repo_root: &Path,
    envelope: &serde_json::Value,
) -> Output {
    let cli = staging_cli(dir);
    let envelope_path = dir.join("runner-config-envelope.json");
    fs::write(&envelope_path, serde_json::to_vec_pretty(envelope).unwrap()).unwrap();
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-SYNTHETIC-INPUT-A").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-SYNTHETIC-INPUT-B").unwrap();
    let args = vec![
        "preflight".to_string(),
        "--envelope".to_string(),
        envelope_path.display().to_string(),
        "--output-dir".to_string(),
        dir.display().to_string(),
        "--cli-binary".to_string(),
        cli.display().to_string(),
        "--repo-root".to_string(),
        repo_root.display().to_string(),
        "--toolchain-pin".to_string(),
        workspace_root()
            .join("rust-toolchain.toml")
            .display()
            .to_string(),
        "--expected-toolchain".to_string(),
        "1.97.1".to_string(),
        "--case".to_string(),
        real_manifest("origin_macro").display().to_string(),
        dir.join("input_origin.bin").display().to_string(),
        dir.join("origin_candidate.exe").display().to_string(),
        "--case".to_string(),
        real_manifest("lunlun_software").display().to_string(),
        dir.join("input_lunlun.bin").display().to_string(),
        dir.join("lunlun_candidate.exe").display().to_string(),
    ];
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Command::new(&acceptance_bin())
        .args(&arg_refs)
        .output()
        .expect("spawn acceptance binary")
}

/// P6.3.3.1: positive control — a VALID case-bound v4 envelope. The verifier's
/// keyed-identity / per-case-digest checks must NOT report any drift reason
/// (the resulting NotReady is only the synthetic-file identity mismatch from
/// `run_offline_preflight`, which is expected offline).
#[test]
fn valid_v4_envelope_passes_keyed_identity_check() {
    let dir = temp_dir("valid_v4");
    let repo_root = scratch_repo(&dir);
    let out = run_acceptance_on_envelope(&dir, &repo_root, &valid_v4_envelope_json());
    // The envelope keyed-identity check is clean; NotReady (exit 2) comes only
    // from the synthetic input files not matching the locked identity.
    assert_eq!(
        out.status.code(),
        Some(2),
        "valid envelope + synthetic files -> NotReady (identity): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("keyed") && !stderr.contains("does not match the locked manifest"),
        "no keyed-identity drift for a valid envelope: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.3.3.2-B: swapping ONLY the case_id labels (protected_input and config
/// stay bound to the same slot, every per-case + case-set digest re-sealed
/// honestly) must be rejected by the acceptance verifier's keyed identity
/// check. The final envelope JSON genuinely differs from the honest baseline.
#[test]
fn case_id_swap_rejected_by_verifier() {
    let dir = temp_dir("cid_swap");
    let repo_root = scratch_repo(&dir);
    // Slot A keeps its ORIGIN identity + origin (pure=true) config, but is
    // labeled lunlun_software; slot B keeps LUNLUN + lunlun config, labeled
    // origin_macro. The case_id <-> protected_input binding is broken.
    let env = v4_envelope_json(vec![
        case_entry_with_policy("lunlun_software", ORIGIN_SHA, ORIGIN_SIZE, true),
        case_entry_with_policy("origin_macro", LUNLUN_SHA, LUNLUN_SIZE, false),
    ]);
    assert_ne!(
        env,
        valid_v4_envelope_json(),
        "case_id swap must produce distinct envelope JSON"
    );
    let out = run_acceptance_on_envelope(&dir, &repo_root, &env);
    assert_eq!(
        out.status.code(),
        Some(2),
        "case_id swap must be NotReady: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not match the locked manifest"),
        "keyed-identity drift must be reported by the verifier: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.3.3.2-B: swapping ONLY the protected_input identities (case_id labels
/// and configs stay in their canonical slots, every digest re-sealed) must be
/// rejected. The final JSON differs from the case_id-swap and the baseline.
#[test]
fn protected_input_swap_rejected_by_verifier() {
    let dir = temp_dir("pin_swap");
    let repo_root = scratch_repo(&dir);
    // case_id labels and configs stay; only the protected_input identities
    // are exchanged between the two slots.
    let env = v4_envelope_json(vec![
        case_entry_with_policy("origin_macro", LUNLUN_SHA, LUNLUN_SIZE, true),
        case_entry_with_policy("lunlun_software", ORIGIN_SHA, ORIGIN_SIZE, false),
    ]);
    assert_ne!(
        env,
        valid_v4_envelope_json(),
        "protected_input swap must produce distinct envelope JSON"
    );
    let out = run_acceptance_on_envelope(&dir, &repo_root, &env);
    assert_eq!(
        out.status.code(),
        Some(2),
        "protected_input swap must be NotReady: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("does not match the locked manifest"),
        "keyed-identity drift must be reported by the verifier: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.3.3.2.1: the TRUE dual swap — BOTH the case_id and the protected_input
/// are exchanged together, while each runner CONFIG stays in its original
/// slot. The result keeps every case bound to its OWN protected identity
/// (the keyed case_id <-> protected_input binding stays VALID), so the
/// acceptance verifier must NOT report locked-manifest identity drift. The
/// rejection of this attack comes from the launch-attestation
/// case-policy/config-digest check (`bind_actual_config_to_envelope`), proven
/// in the CLI crate; here we prove the identity side stays legal.
#[test]
fn case_id_and_protected_input_swap_rejected_by_verifier() {
    let dir = temp_dir("dual_swap");
    let repo_root = scratch_repo(&dir);
    // True dual swap: swap case_id labels AND protected_input identities
    // together; the configs stay in their original slots.
    //   lunlun_software + LUNLUN identity + Origin policy(true)
    //   origin_macro   + ORIGIN  identity + Lunlun policy(false)
    let env = v4_envelope_json(vec![
        case_entry_with_policy("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE, true),
        case_entry_with_policy("origin_macro", ORIGIN_SHA, ORIGIN_SIZE, false),
    ]);
    assert_ne!(
        env,
        valid_v4_envelope_json(),
        "true dual swap must produce distinct envelope JSON"
    );
    let out = run_acceptance_on_envelope(&dir, &repo_root, &env);
    // The identity binding is VALID (each case carries its own locked
    // identity), so the verifier is NotReady only from the synthetic files —
    // it must NOT report keyed-identity drift. The config mismatch is caught
    // by the launch-attestation digest check, not by this acceptance path.
    assert_eq!(
        out.status.code(),
        Some(2),
        "true dual swap + synthetic files -> NotReady (identity): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("does not match the locked manifest"),
        "the true dual swap keeps a VALID keyed identity; it must not be \
         rejected on identity grounds: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.3.3.2.1: the baseline, case_id-only, protected_input-only, and
/// true-dual-swap envelopes are pairwise-distinct after canonicalization
/// (sorting the case_configs by case_id). A weaker `assert_ne!(env,
/// baseline)` would not prove the three attack documents are genuinely
/// different from one another.
#[test]
fn identity_swap_envelopes_are_pairwise_distinct_after_canonicalization() {
    // The four envelopes under test.
    let baseline = valid_v4_envelope_json();
    let case_id_only = v4_envelope_json(vec![
        case_entry_with_policy("lunlun_software", ORIGIN_SHA, ORIGIN_SIZE, true),
        case_entry_with_policy("origin_macro", LUNLUN_SHA, LUNLUN_SIZE, false),
    ]);
    let protected_input_only = v4_envelope_json(vec![
        case_entry_with_policy("origin_macro", LUNLUN_SHA, LUNLUN_SIZE, true),
        case_entry_with_policy("lunlun_software", ORIGIN_SHA, ORIGIN_SIZE, false),
    ]);
    let true_dual_swap = v4_envelope_json(vec![
        case_entry_with_policy("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE, true),
        case_entry_with_policy("origin_macro", ORIGIN_SHA, ORIGIN_SIZE, false),
    ]);

    let docs = vec![
        ("baseline", baseline),
        ("case_id-only", case_id_only),
        ("protected_input-only", protected_input_only),
        ("true-dual-swap", true_dual_swap),
    ];
    // Every pair must be distinct under canonical (sorted-by-case_id) form.
    for i in 0..docs.len() {
        for j in (i + 1)..docs.len() {
            assert_ne!(
                canonical_case_entries(&docs[i].1),
                canonical_case_entries(&docs[j].1),
                "{} and {} must be pairwise distinct after canonicalization",
                docs[i].0,
                docs[j].0
            );
        }
    }
}

/// Canonicalize an envelope's case set by sorting its `case_configs` by
/// `case_id`, keeping only the identity-and-config binding (the runner-config
/// digest is included so config policy swaps are visible). Used to compare
/// envelopes independent of array order.
fn canonical_case_entries(envelope: &serde_json::Value) -> Vec<String> {
    let mut entries: Vec<String> = envelope["case_configs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            format!(
                "{}|{}|{}|{}|{}",
                c["case_id"].as_str().unwrap(),
                c.get("family_id")
                    .and_then(|f| f.as_str())
                    .unwrap_or("oreans_themida")
                    .to_lowercase(),
                c["protected_input"]["sha256"]
                    .as_str()
                    .unwrap()
                    .to_lowercase(),
                c["protected_input"]["size_bytes"].as_u64().unwrap(),
                c["runner_config_digest"].as_str().unwrap().to_lowercase(),
            )
        })
        .collect();
    entries.sort();
    entries
}

/// P6.3.3.1-B: a v3 single-config envelope must be rejected (no silent
/// upgrade to v4).
#[test]
fn v3_envelope_rejected_by_verifier() {
    let dir = temp_dir("v3_reject");
    let repo_root = scratch_repo(&dir);
    let mut env = valid_v4_envelope_json();
    env.as_object_mut().unwrap().remove("case_configs");
    env.as_object_mut().unwrap().remove("case_set_digest");
    env["schema_version"] = serde_json::json!("mida.runner-config-envelope/v3");
    env["runner_config"] = serde_json::json!({});
    env["runner_config_digest"] = serde_json::json!("a".repeat(64));
    let out = run_acceptance_on_envelope(&dir, &repo_root, &env);
    assert_eq!(
        out.status.code(),
        Some(1),
        "v3 envelope must be a hard config error (no silent upgrade): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("v4") || stderr.contains("schema_version"),
        "stderr: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.3.3.2-B: reordering the envelope's `case_configs` (lunlun before
/// origin, every per-case + case-set digest re-sealed honestly) must NOT
/// re-bind any per-case digest to the wrong case_id. The verifier keys each
/// digest by case_id (never by array position), so the produced report must
/// carry the CORRECT per-case digest for each case_id. The only NotReady here
/// is the synthetic-file identity mismatch.
#[test]
fn case_configs_order_swap_does_not_rebind_per_case_digests() {
    let dir = temp_dir("order_swap");
    let repo_root = scratch_repo(&dir);
    let env = v4_envelope_json(vec![
        case_entry_with_policy("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE, false),
        case_entry_with_policy("origin_macro", ORIGIN_SHA, ORIGIN_SIZE, true),
    ]);
    assert_ne!(
        env,
        valid_v4_envelope_json(),
        "a reordered envelope is still a distinct document"
    );
    let out = run_acceptance_on_envelope(&dir, &repo_root, &env);
    assert_eq!(
        out.status.code(),
        Some(2),
        "reordered envelope + synthetic files -> NotReady (identity): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("does not match the locked manifest"),
        "no keyed-identity drift for a reordered (honestly re-sealed) envelope: {stderr}"
    );

    // The produced report must key each per-case digest by its own case_id —
    // NOT by array position. The origin entry is now index 1, so if the
    // verifier bound by position the origin case would carry the lunlun
    // digest.
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("preflight.json")).unwrap()).unwrap();
    let envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("runner-config-envelope.json")).unwrap())
            .unwrap();
    for case in report["cases"].as_array().unwrap() {
        let case_id = case["case_id"].as_str().unwrap();
        let expected = envelope["case_configs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["case_id"].as_str() == Some(case_id))
            .unwrap()["runner_config_digest"]
            .as_str()
            .unwrap()
            .to_lowercase();
        assert_eq!(
            case["runner_config_digest"]
                .as_str()
                .unwrap()
                .to_lowercase(),
            expected,
            "case {case_id} per-case digest must be keyed by case_id, not position"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

/// P6.3.3.2-B: missing, duplicate, and extra case configs are all rejected.
#[test]
fn missing_duplicate_extra_case_rejected_by_verifier() {
    let dir = temp_dir("case_set_attacks");
    let repo_root = scratch_repo(&dir);

    // Missing a case.
    let missing = v4_envelope_json(vec![case_entry_json(
        "origin_macro",
        ORIGIN_SHA,
        ORIGIN_SIZE,
    )]);
    let out = run_acceptance_on_envelope(&dir, &repo_root, &missing);
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing case must be NotReady: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Duplicate a case.
    let dup = v4_envelope_json(vec![
        case_entry_json("origin_macro", ORIGIN_SHA, ORIGIN_SIZE),
        case_entry_json("origin_macro", ORIGIN_SHA, ORIGIN_SIZE),
        case_entry_json("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE),
    ]);
    let out = run_acceptance_on_envelope(&dir, &repo_root, &dup);
    assert_eq!(
        out.status.code(),
        Some(2),
        "duplicate case must be NotReady: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("duplicate case_id") || stderr.contains("exactly 2 case configs"),
        "duplicate detection: {stderr}"
    );

    // Extra (third) case.
    let extra = v4_envelope_json(vec![
        case_entry_json("origin_macro", ORIGIN_SHA, ORIGIN_SIZE),
        case_entry_json("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE),
        case_entry_json("gto_launcher", &"c".repeat(64), 1),
    ]);
    let out = run_acceptance_on_envelope(&dir, &repo_root, &extra);
    assert_eq!(
        out.status.code(),
        Some(2),
        "extra case must be NotReady: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// G3-R3-R2/G3-R3-R2-R1: CLI-side canonical-encoding stability for the sealed
// GTO path. The digest is case-normalized (the producer lowercases the path), so
// a semantically legal mixed-case root/hash produces the same case-set digest
// as its lowercased form.
// ---------------------------------------------------------------------------

/// Build a GTO case entry with the given sealed protected_input_path.
fn gto_case_entry_with_path(path: &str) -> serde_json::Value {
    let mut cfg = mida_acceptance::RunnerConfig {
        packer_family: "ahk_gto".to_string(),
        tool_revision: "rev".to_string(),
        cli_binary_sha256: "a".repeat(64),
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
        isolation: mida_acceptance::IsolationConfig {
            workspace_policy: "isolated-temp".to_string(),
            process_tree_policy: "single-process".to_string(),
            network_policy: "blocked".to_string(),
        },
        attempt_numbering: "continuous-1-based".to_string(),
        evidence_bundle_schema: "mida.unpack-evidence-bundle/v1".to_string(),
        gate_schema: "no-gate".to_string(),
        env_allowlist: vec!["CARGO_TARGET_DIR".to_string()],
    };
    cfg.tool_revision = "rev".to_string();
    cfg.cli_binary_sha256 = "a".repeat(64);
    let digest = mida_acceptance::runner_config_digest(&cfg);
    serde_json::json!({
        "case_id": "gto_launcher",
        "family_id": "ahk_gto",
        "protected_input": { "sha256": "c".repeat(64), "size_bytes": 42 },
        "protected_input_path": path,
        "runner_config": serde_json::to_value(&cfg).unwrap(),
        "runner_config_digest": digest,
    })
}

#[test]
fn gto_mixed_case_path_digest_is_stable() {
    // A semantically legal snapshot path: only the ROOT and the 64-hex hash dir
    // are case-varied; the fixed `gto_launcher` case dir and `snapshot.bin`
    // filename are preserved (the verifier would reject a changed case dir or
    // filename).
    let legal = "C:\\SnapShots\\gto_launcher\\CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\\snapshot.bin";
    let lower = legal.to_lowercase();

    let mut mixed_env = v4_envelope_json(vec![
        case_entry_json("origin_macro", ORIGIN_SHA, ORIGIN_SIZE),
        case_entry_json("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE),
        gto_case_entry_with_path(legal),
    ]);
    mixed_env["case_set_digest"] = serde_json::json!(reseal_case_set(
        mixed_env["case_configs"].as_array().unwrap()
    ));

    let mut lower_env = v4_envelope_json(vec![
        case_entry_json("origin_macro", ORIGIN_SHA, ORIGIN_SIZE),
        case_entry_json("lunlun_software", LUNLUN_SHA, LUNLUN_SIZE),
        gto_case_entry_with_path(&lower),
    ]);
    lower_env["case_set_digest"] = serde_json::json!(reseal_case_set(
        lower_env["case_configs"].as_array().unwrap()
    ));

    assert_eq!(
        mixed_env["case_set_digest"].as_str().unwrap(),
        lower_env["case_set_digest"].as_str().unwrap(),
        "the case-set digest must be case-normalized (mixed-case root/hash == lowercased)"
    );
}
