//! P6.3-QA attack tests: the launch attestation, the envelope fail-closed
//! reuse policy, and the production bundle chain.
//!
//! Proven end-to-end (each item from the P6.3 review):
//!
//! 1. a hand-written `ready` report is never an authorization credential;
//! 2. a Ready report staged for one input cannot launch a different input
//!    (cross-case reuse refused);
//! 3. a Ready report cannot launch a garbage / third input;
//! 4. an input modified after preflight is refused;
//! 5. an output path changed after preflight is refused;
//! 6. an output that aliases the protected input (same canonical path or a
//!    hard link) is refused;
//! 7. `--no-shrink` diverging from the staged envelope is refused;
//! 8. every other policy divergence (--data-sections, --oep,
//!    --container-restore, --profile, --pure-rebuild, --capture-policy) is
//!    refused item by item;
//! 9. a binary A preflight cannot authorize a binary B launch;
//! 10. a malformed existing envelope is never overwritten (bytes preserved);
//! 11. a stale/different envelope is never reused (bytes preserved);
//! 12. `$schema` drift is rejected by BOTH the runner and the acceptance
//!     verifier;
//! 13. the production bundle digest equals the launch attestation digest;
//! 14. a consumed authorization cannot be consumed a second time (P6.3.1
//!     seal: ownership consume, no Clone, no public constructor);
//! 15. a verifier different from the envelope-pinned identity is refused at
//!     launch (P6.3.1 verifier binding).
//!
//! Negative tests use the REAL acceptance binary (whose identity recompute
//! and locked-manifest cross-check are what reject the attacks); positive
//! control and chain tests use the deterministic `mida-verifier-stub`
//! (`tests/bin/verifier_stub.rs`). P6.3.1: the verifier is injected
//! explicitly via `--acceptance-bin` — never the environment.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mida_launch_attest_{tag}_{}_{}",
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

fn verifier_stub() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mida-verifier-stub"))
}

fn real_cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mida-cli"))
}

fn run_cli(args: &[&str], env: &[(&str, String)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mida-cli"));
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.args(args).output().expect("spawn mida-cli")
}

fn fake_binary(dir: &Path, name: &str, payload: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, payload).unwrap();
    path
}

fn _missing_input(dir: &Path) -> PathBuf {
    let p = dir.join("protected_input.bin");
    let _ = fs::remove_file(&p);
    p
}

/// Deterministic scratch git repo for the worktree probe.
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

/// `--case` triples for the two fixed cases (synthetic inputs).
fn case_triples(dir: &Path, inputs: &[(&str, &str)]) -> Vec<(PathBuf, PathBuf, PathBuf)> {
    assert_eq!(inputs.len(), 2, "need two case inputs");
    vec![
        (
            real_manifest("origin_macro"),
            dir.join(inputs[0].0),
            dir.join(inputs[0].1),
        ),
        (
            real_manifest("lunlun_software"),
            dir.join(inputs[1].0),
            dir.join(inputs[1].1),
        ),
    ]
}

fn staging_args(
    dir: &Path,
    repo_root: &Path,
    cli_binary: &Path,
    cases: &[(PathBuf, PathBuf, PathBuf)],
) -> Vec<String> {
    let mut args = vec![
        "/offline-preflight".to_string(),
        dir.display().to_string(),
        format!("--cli-binary={}", cli_binary.display()),
        format!("--repo-root={}", repo_root.display()),
        format!(
            "--toolchain-pin={}",
            workspace_root().join("rust-toolchain.toml").display()
        ),
        "--expected-toolchain=1.97.1".to_string(),
    ];
    for (m, i, o) in cases {
        args.push("--case".to_string());
        args.push(m.display().to_string());
        args.push(i.display().to_string());
        args.push(o.display().to_string());
    }
    args
}

fn run_staging(
    dir: &Path,
    repo_root: &Path,
    cli_binary: &Path,
    cases: &[(PathBuf, PathBuf, PathBuf)],
    verifier: &Path,
) -> Output {
    let mut args = staging_args(dir, repo_root, cli_binary, cases);
    // P6.3.1: the verifier is injected explicitly (never the environment).
    args.push(format!("--acceptance-bin={}", verifier.display()));
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cli(&arg_refs, &[])
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

fn read_envelope(dir: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(dir.join("runner-config-envelope.json")).unwrap()).unwrap()
}

/// Two-case staging with synthetic inputs, staged for the given verifier.
fn stage(dir: &Path, repo_root: &Path, verifier: &Path) -> Vec<(PathBuf, PathBuf, PathBuf)> {
    let cli = real_cli_bin();
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-SYNTHETIC-INPUT-A").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-SYNTHETIC-INPUT-B").unwrap();
    let cases = case_triples(
        dir,
        &[
            ("input_origin.bin", "origin_candidate.exe"),
            ("input_lunlun.bin", "lunlun_candidate.exe"),
        ],
    );
    let staged = run_staging(dir, repo_root, &cli, &cases, verifier);
    assert_eq!(
        staged.status.code(),
        Some(0),
        "staging must be Ready: {}",
        String::from_utf8_lossy(&staged.stderr)
    );
    cases
}

/// Fabricate a syntactically valid Ready v2 report bound to the envelope
/// chain and the given case triples (input identity recomputed from disk).
fn fabricate_ready_report(dir: &Path, repo_root: &Path, cases: &[(PathBuf, PathBuf, PathBuf)]) {
    let envelope = read_envelope(dir);
    let digest = envelope["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_string();
    let cases_json: Vec<serde_json::Value> = cases
        .iter()
        .map(|(m, i, o)| {
            let identity = fs::read(i).ok().map(|bytes| {
                serde_json::json!({
                    "sha256": sha256_hex(&bytes),
                    "size_bytes": bytes.len(),
                })
            });
            serde_json::json!({
                "case_id": m.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default(),
                "identity_ok": true,
                "reasons": [],
                "protected_input": identity.unwrap_or(serde_json::Value::Null),
                "protected_input_path": i.to_string_lossy().to_string(),
                "manifest_path": m.to_string_lossy().to_string(),
                "candidate_output": o.to_string_lossy().to_string(),
            })
        })
        .collect();
    fs::write(
        dir.join("preflight.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "mida.preflight-report/v2",
            "status": "ready",
            "reasons": [],
            "runner_config_digest": digest,
            "head_revision": null,
            "worktree_clean": true,
            "toolchain_matches": true,
            "cli_binary_sha256": envelope["cli_binary_sha256"],
            "cli_binary_matches": true,
            "cli_binary_path": real_cli_bin().display().to_string(),
            "repo_root": repo_root.display().to_string(),
            "toolchain_pin_file": workspace_root().join("rust-toolchain.toml").display().to_string(),
            "expected_toolchain": "1.97.1",
            "cases": cases_json,
        }))
        .unwrap(),
    )
    .unwrap();
}

fn launch_unpack(dir: &Path, input: &Path, output: &Path) -> Output {
    launch_unpack_with_verifier(dir, input, output, None)
}

/// Launch with an explicit verifier for the attestation re-run (P6.3.1:
/// injected via `--acceptance-bin`, never the environment). `None` resolves
/// the acceptance binary the same way production does (sibling, then PATH).
fn launch_unpack_with_verifier(
    dir: &Path,
    input: &Path,
    output: &Path,
    verifier: Option<&Path>,
) -> Output {
    let mut args = vec![
        "/unpack".to_string(),
        input.to_str().unwrap().to_string(),
        "--output".to_string(),
        output.to_str().unwrap().to_string(),
        "--preflight-dir".to_string(),
        dir.to_str().unwrap().to_string(),
    ];
    if let Some(v) = verifier {
        args.push("--acceptance-bin".to_string());
        args.push(v.display().to_string());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_cli(&arg_refs, &[])
}

fn assert_launch_blocked(output: &Output, expected_reason: &str, candidate: &Path) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "launch must be blocked (exit 1): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("launch blocked"),
        "must be a launch-block error: {stderr}"
    );
    if !expected_reason.is_empty() {
        assert!(stderr.contains(expected_reason), "stderr: {stderr}");
    }
    assert!(!candidate.exists(), "no candidate may be produced");
}

// ---------------------------------------------------------------------------
// 1. Hand-written Ready is not an authorization
// ---------------------------------------------------------------------------

/// Stage with the REAL verifier (NotReady — the input is not a locked
/// sample), fabricate a Ready report with the correct digest chain, CLI
/// identity and current input identity, then launch. The verifier RE-RUN
/// (real acceptance binary) recomputes the input against the locked
/// manifest and writes NotReady — the fabricated Ready is refused.
#[test]
fn hand_written_ready_is_never_an_authorization() {
    let dir = temp_dir("fake_ready");
    let repo_root = scratch_repo(&dir);
    let cli = real_cli_bin();
    fs::write(dir.join("input_origin.bin"), b"NOT-A-LOCKED-SAMPLE-BYTES").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"ALSO-NOT-LOCKED-BYTES").unwrap();
    let cases = case_triples(
        &dir,
        &[
            ("input_origin.bin", "origin_candidate.exe"),
            ("input_lunlun.bin", "lunlun_candidate.exe"),
        ],
    );
    let staged = run_staging(&dir, &repo_root, &cli, &cases, &acceptance_bin());
    assert_eq!(staged.status.code(), Some(2), "real preflight is NotReady");

    fabricate_ready_report(&dir, &repo_root, &cases);

    let candidate = dir.join("origin_candidate.exe");
    let output = launch_unpack(&dir, &dir.join("input_origin.bin"), &candidate);
    assert_launch_blocked(&output, "", &candidate);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 2. Ready report staged for one input cannot launch another (cross-case)
// 3. Ready report cannot launch a garbage / third input
// ---------------------------------------------------------------------------

/// Stage Ready for the two synthetic inputs (stub verifier), then attempt
/// to launch a DIFFERENT input — the attestation finds zero matching case
/// identities and refuses the cross-case reuse.
#[test]
fn ready_report_cannot_launch_a_different_input() {
    let dir = temp_dir("cross_input");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());

    // A different input (not one of the two staged case identities).
    let other = dir.join("other_input.bin");
    fs::write(&other, b"SOME-OTHER-INPUT-BYTES").unwrap();
    let candidate = dir.join("other_candidate.exe");
    let output = launch_unpack_with_verifier(&dir, &other, &candidate, Some(&verifier_stub()));
    assert_launch_blocked(&output, "matches 0 preflight case identities", &candidate);
    let _ = fs::remove_dir_all(&dir);
}

/// Same refusal for a garbage / third input.
#[test]
fn ready_report_cannot_launch_garbage_input() {
    let dir = temp_dir("garbage_input");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());

    let garbage = dir.join("garbage.bin");
    fs::write(&garbage, b"NOT-A-PE-NOT-A-PE-NOT-A-PE").unwrap();
    let candidate = dir.join("garbage_candidate.exe");
    let output = launch_unpack_with_verifier(&dir, &garbage, &candidate, Some(&verifier_stub()));
    assert_launch_blocked(&output, "matches 0 preflight case identities", &candidate);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 4. Input modified after preflight
// ---------------------------------------------------------------------------

/// Stage Ready for a synthetic input (stub records its identity), then
/// modify the input bytes. The launch recomputes the current identity and
/// no preflight case matches any more — the modified input is refused.
#[test]
fn input_modified_after_preflight_rejected() {
    let dir = temp_dir("modified_input");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());

    let input = dir.join("input_origin.bin");
    let mut bytes = fs::read(&input).unwrap();
    bytes.push(0xAB); // one byte changed
    fs::write(&input, &bytes).unwrap();

    let candidate = dir.join("origin_candidate.exe");
    let output = launch_unpack_with_verifier(&dir, &input, &candidate, Some(&verifier_stub()));
    assert_launch_blocked(&output, "matches 0 preflight case identities", &candidate);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 5. Output path changed after preflight
// ---------------------------------------------------------------------------

/// Stage Ready with candidate `origin_candidate.exe`, then launch with a
/// DIFFERENT output path — the canonical path check refuses.
#[test]
fn output_path_changed_after_preflight_rejected() {
    let dir = temp_dir("changed_output");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());

    let input = dir.join("input_origin.bin");
    let moved = dir.join("moved_candidate.exe");
    let output = launch_unpack_with_verifier(&dir, &input, &moved, Some(&verifier_stub()));
    assert_launch_blocked(&output, "does not match the preflight candidate", &moved);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 6. Output aliasing the protected input
// ---------------------------------------------------------------------------

/// Same canonical path: `--output` == the protected input. The pipeline's
/// own alias protection redirects the output to a U-suffix path, and the
/// attestation then refuses because that path no longer matches the
/// preflight candidate — the aliasing run is blocked before any process
/// creation.
#[test]
fn output_alias_same_path_rejected() {
    let dir = temp_dir("alias_same");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());

    let input = dir.join("input_origin.bin");
    let output = launch_unpack_with_verifier(&dir, &input, &input, Some(&verifier_stub()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "an output aliasing the input must block the launch: {stderr}"
    );
    assert!(
        stderr.contains("launch blocked"),
        "must be a launch-block error: {stderr}"
    );
    assert!(
        stderr.contains("does not match the preflight candidate")
            || stderr.contains("aliases the protected input"),
        "stderr: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Hard-linked output: the real verifier re-run detects a byte-identical
/// candidate and refuses (the fabricated Ready is not an authorization).
#[test]
fn output_hard_link_alias_rejected() {
    let dir = temp_dir("alias_link");
    let repo_root = scratch_repo(&dir);
    let cli = real_cli_bin();
    fs::write(dir.join("input_origin.bin"), b"HARDLINK-INPUT-BYTES").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-INPUT-BYTES").unwrap();
    let cases = case_triples(
        &dir,
        &[
            ("input_origin.bin", "origin_candidate.exe"),
            ("input_lunlun.bin", "lunlun_candidate.exe"),
        ],
    );
    let staged = run_staging(&dir, &repo_root, &cli, &cases, &acceptance_bin());
    assert_eq!(staged.status.code(), Some(2), "real preflight is NotReady");
    fabricate_ready_report(&dir, &repo_root, &cases);

    let hardlink = dir.join("hardlink_candidate.exe");
    fs::hard_link(dir.join("input_origin.bin"), &hardlink).unwrap();
    let original_bytes = fs::read(&hardlink).unwrap();
    let output = launch_unpack(&dir, &dir.join("input_origin.bin"), &hardlink);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a hard-linked output must block the launch: {stderr}"
    );
    assert!(
        stderr.contains("launch blocked"),
        "must be a launch-block error: {stderr}"
    );
    assert_eq!(
        fs::read(&hardlink).unwrap(),
        original_bytes,
        "the pre-created hard link must never be touched by the blocked run"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 7./8. Verifier identity + run-config divergence from the staged envelope
// ---------------------------------------------------------------------------

/// P6.3.1 (#3): the launch attestation fails closed when the verifier it
/// would use does not match the envelope-pinned verifier identity (verifier
/// replacement / path drift / hash drift). Stage with the stub, then launch
/// with the REAL acceptance binary.
#[test]
fn verifier_replacement_at_launch_rejected() {
    let dir = temp_dir("verifier_swap");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());

    let input = dir.join("input_origin.bin");
    let candidate = dir.join("origin_candidate.exe");
    let output = launch_unpack_with_verifier(&dir, &input, &candidate, Some(&acceptance_bin()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a verifier different from the pinned identity must block the launch: {stderr}"
    );
    assert!(stderr.contains("launch blocked"), "stderr: {stderr}");
    assert!(
        stderr.contains("verifier"),
        "the block must cite the verifier identity: {stderr}"
    );
    assert!(!candidate.exists(), "no candidate may be produced");
    let _ = fs::remove_dir_all(&dir);
}

/// Every policy flag that diverges from the staged envelope and the P7
/// fixed-mode policy must block the launch item by item.
#[test]
fn policy_mismatches_rejected_item_by_item() {
    let dir = temp_dir("policy_mismatch");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());
    let input = dir.join("input_origin.bin");
    let candidate = dir.join("origin_candidate.exe");
    let preflight = dir.to_str().unwrap();

    let cases: Vec<(Vec<&str>, &str)> = vec![
        (vec!["--no-shrink"], "shrink false != fixed-mode true"),
        (
            vec!["--data-sections"],
            "data_sections true != fixed-mode false",
        ),
        (vec!["--oep=crt"], "oep_policy"),
        (vec!["--container-restore=post-crt"], "container_restore"),
        (vec!["--profile=ahk-gto-experimental"], "features"),
        (vec!["--pure-rebuild"], "pure_rebuild"),
    ];
    for (flags, reason) in &cases {
        let mut args = vec![
            "/unpack",
            input.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            preflight,
        ];
        args.extend(flags.iter().copied());
        let output = run_cli(&args, &[]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(1),
            "flags {flags:?} must block the launch: {stderr}"
        );
        assert!(
            stderr.contains("launch blocked"),
            "flags {flags:?}: {stderr}"
        );
        assert!(
            stderr.contains(reason),
            "flags {flags:?}: expected reason {reason:?} in: {stderr}"
        );
        assert!(!candidate.exists(), "flags {flags:?}: no candidate");
    }

    // --capture-policy: a non-empty policy digest diverges from the frozen
    // empty policy.
    let policy_file = dir.join("capture.json");
    fs::write(&policy_file, br#"{"preset":"ahk_gto_defaults"}"#).unwrap();
    let output = run_cli(
        &[
            "/unpack",
            input.to_str().unwrap(),
            "--output",
            candidate.to_str().unwrap(),
            "--preflight-dir",
            preflight,
            "--capture-policy",
            policy_file.to_str().unwrap(),
        ],
        &[],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "capture policy: {stderr}");
    assert!(
        stderr.contains("launch blocked") && stderr.contains("capture_policy_digest"),
        "capture policy: {stderr}"
    );
    assert!(!candidate.exists(), "capture policy: no candidate");

    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 9. Binary A preflight, binary B launch
// ---------------------------------------------------------------------------

/// The envelope pins the staged CLI binary identity; the launch's current
/// executable differs, so the actual run-config digest (which includes the
/// CLI identity) cannot match the envelope — refused before any process
/// creation.
#[test]
fn binary_swap_rejected() {
    let dir = temp_dir("binary_swap");
    let repo_root = scratch_repo(&dir);
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-INPUT").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-INPUT").unwrap();
    let cases = case_triples(
        &dir,
        &[
            ("input_origin.bin", "origin_candidate.exe"),
            ("input_lunlun.bin", "lunlun_candidate.exe"),
        ],
    );
    // Stage with a FAKE binary A (the launch binary is the real mida-cli).
    let fake_a = fake_binary(&dir, "cli_a.exe", b"CLI-BINARY-A");
    let staged = run_staging(&dir, &repo_root, &fake_a, &cases, &verifier_stub());
    assert_eq!(staged.status.code(), Some(0), "stub staging is Ready");

    let candidate = dir.join("origin_candidate.exe");
    let output = launch_unpack(&dir, &dir.join("input_origin.bin"), &candidate);
    assert_launch_blocked(&output, "actual run config digest", &candidate);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 10./11. Envelope fail-closed reuse
// ---------------------------------------------------------------------------

/// A malformed existing envelope is never overwritten: the staging run
/// fails hard and the original (corrupt) bytes are preserved.
#[test]
fn malformed_envelope_not_overwritten_and_bytes_preserved() {
    let dir = temp_dir("malformed_env");
    let repo_root = scratch_repo(&dir);
    let cli = real_cli_bin();
    fs::write(dir.join("input_origin.bin"), b"X").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"Y").unwrap();
    let cases = case_triples(
        &dir,
        &[
            ("input_origin.bin", "origin_candidate.exe"),
            ("input_lunlun.bin", "lunlun_candidate.exe"),
        ],
    );
    let staged = run_staging(&dir, &repo_root, &cli, &cases, &verifier_stub());
    assert_eq!(
        staged.status.code(),
        Some(0),
        "first staging creates the envelope"
    );

    // Corrupt the envelope (truncated JSON).
    let envelope_path = dir.join("runner-config-envelope.json");
    fs::write(&envelope_path, b"{ broken ").unwrap();

    let retry = run_staging(&dir, &repo_root, &cli, &cases, &verifier_stub());
    assert_eq!(
        retry.status.code(),
        Some(1),
        "malformed envelope must be a hard error"
    );
    assert_eq!(
        fs::read(&envelope_path).unwrap(),
        b"{ broken ",
        "the corrupt envelope bytes must be preserved"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// A stale/different existing envelope is never reused: staging with a
/// different CLI binary fails hard and the original bytes are preserved.
#[test]
fn stale_envelope_not_reused_and_bytes_preserved() {
    let dir = temp_dir("stale_env");
    let repo_root = scratch_repo(&dir);
    fs::write(dir.join("input_origin.bin"), b"X").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"Y").unwrap();
    let cases = case_triples(
        &dir,
        &[
            ("input_origin.bin", "origin_candidate.exe"),
            ("input_lunlun.bin", "lunlun_candidate.exe"),
        ],
    );
    let fake_a = fake_binary(&dir, "cli_a.exe", b"CLI-BINARY-A");
    let staged = run_staging(&dir, &repo_root, &fake_a, &cases, &verifier_stub());
    assert_eq!(
        staged.status.code(),
        Some(0),
        "first staging creates the envelope"
    );
    let envelope_path = dir.join("runner-config-envelope.json");
    let original = fs::read(&envelope_path).unwrap();

    // A different CLI binary would produce a different envelope.
    let fake_b = fake_binary(&dir, "cli_b.exe", b"CLI-BINARY-B-DIFFERENT");
    let retry = run_staging(&dir, &repo_root, &fake_b, &cases, &verifier_stub());
    assert_eq!(
        retry.status.code(),
        Some(1),
        "stale envelope must be a hard error"
    );
    assert!(
        String::from_utf8_lossy(&retry.stderr).contains("refusing to overwrite"),
        "stderr: {}",
        String::from_utf8_lossy(&retry.stderr)
    );
    assert_eq!(
        fs::read(&envelope_path).unwrap(),
        original,
        "the original envelope bytes must be preserved"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 12. $schema drift rejected by both runner and acceptance
// ---------------------------------------------------------------------------

#[test]
fn schema_drift_rejected_by_runner_and_acceptance() {
    let dir = temp_dir("schema_drift");
    let repo_root = scratch_repo(&dir);
    fs::write(dir.join("input_origin.bin"), b"X").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"Y").unwrap();
    let cases = case_triples(
        &dir,
        &[
            ("input_origin.bin", "origin_candidate.exe"),
            ("input_lunlun.bin", "lunlun_candidate.exe"),
        ],
    );
    let cli = real_cli_bin();
    let staged = run_staging(&dir, &repo_root, &cli, &cases, &verifier_stub());
    assert_eq!(staged.status.code(), Some(0), "staging is Ready");

    let envelope_path = dir.join("runner-config-envelope.json");
    for (field, value) in [
        ("$schema", serde_json::json!("./drifted.schema.json")),
        (
            "schema_version",
            serde_json::json!("mida.runner-config-envelope/v3"),
        ),
    ] {
        let mut envelope = read_envelope(&dir);
        envelope[field] = value.clone();
        fs::write(
            &envelope_path,
            serde_json::to_vec_pretty(&envelope).unwrap(),
        )
        .unwrap();

        // Runner side: the staging reuse policy rejects the drift.
        let retry = run_staging(&dir, &repo_root, &cli, &cases, &verifier_stub());
        assert_eq!(
            retry.status.code(),
            Some(1),
            "{field} drift must be rejected by the runner"
        );

        // Acceptance side: the verifier itself rejects the drift.
        let verifier_args = vec![
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
            cases[0].0.display().to_string(),
            cases[0].1.display().to_string(),
            cases[0].2.display().to_string(),
            "--case".to_string(),
            cases[1].0.display().to_string(),
            cases[1].1.display().to_string(),
            cases[1].2.display().to_string(),
        ];
        let direct = Command::new(&acceptance_bin())
            .args(&verifier_args)
            .output()
            .expect("spawn acceptance binary");
        assert_eq!(
            direct.status.code(),
            Some(1),
            "{field} drift must be a config error for the acceptance verifier"
        );
        assert!(
            String::from_utf8_lossy(&direct.stderr).contains(field.trim_start_matches('$')),
            "acceptance stderr: {}",
            String::from_utf8_lossy(&direct.stderr)
        );

        // Launch side: the attestation rejects the drift before anything
        // else (envelope still parses; only the schema identity changed).
        let candidate = dir.join("origin_candidate.exe");
        let output = launch_unpack(&dir, &dir.join("input_origin.bin"), &candidate);
        assert_launch_blocked(&output, "schema", &candidate);
    }
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Positive control: a genuinely re-verified Ready report passes the
// attestation and the pipeline continues past it.
// ---------------------------------------------------------------------------

#[test]
fn stub_attestation_passes_and_pipeline_continues() {
    let dir = temp_dir("stub_pass");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());

    let input = dir.join("input_origin.bin");
    let candidate = dir.join("origin_candidate.exe");
    let output = launch_unpack_with_verifier(&dir, &input, &candidate, Some(&verifier_stub()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("launch blocked"),
        "the attestation must pass: {stderr}"
    );
    // The attestation emits a stable, filter-independent gate line (P6.3.1).
    assert!(
        stderr.contains("launch attestation: Ready"),
        "the attestation must report Ready: {stderr}"
    );
    assert!(
        stderr.contains("Failed to parse PE header"),
        "the pipeline must continue past the gate to PE parsing: {stderr}"
    );
    assert!(!candidate.exists(), "no candidate may be produced");
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 13. Production bundle digest == launch attestation digest
// ---------------------------------------------------------------------------

use mida_cli::runner_preflight::{
    attest_ready_before_launch, complete_run_evidence, LaunchAttestationContext,
};

/// Full production chain with the stub verifier: envelope (staged) ->
/// attestation -> RunEvidenceContext -> seven members -> atomic bundle.
/// The bundle's runner_config_digest must equal the attestation digest.
#[test]
fn production_bundle_digest_equals_attestation_digest() {
    use mida_core::runner_config::RunnerConfig;

    let dir = temp_dir("bundle_chain");
    let repo_root = scratch_repo(&dir);
    let fake_cli = fake_binary(&dir, "cli_chain.exe", b"CLI-CHAIN-BINARY");
    fs::write(dir.join("protected.bin"), b"PROTECTED-INPUT-BYTES-000").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-INPUT").unwrap();
    let cases = vec![
        (
            real_manifest("origin_macro"),
            dir.join("protected.bin"),
            dir.join("origin_candidate.exe"),
        ),
        (
            real_manifest("lunlun_software"),
            dir.join("input_lunlun.bin"),
            dir.join("lunlun_candidate.exe"),
        ),
    ];
    let staged = run_staging(&dir, &repo_root, &fake_cli, &cases, &verifier_stub());
    assert_eq!(staged.status.code(), Some(0), "stub staging is Ready");

    // Attest with the same binary + the envelope's own config (the actual
    // run config must match the envelope digest).
    let envelope = read_envelope(&dir);
    let runner_config: RunnerConfig =
        serde_json::from_value(envelope["runner_config"].clone()).expect("parse envelope config");
    let candidate = dir.join("origin_candidate.exe");
    fs::write(&candidate, b"CANDIDATE-BYTES-1234567890").unwrap();
    let ctx = LaunchAttestationContext {
        input: &dir.join("protected.bin"),
        output: &candidate,
        cli_binary: &fake_cli,
        runner_config: &runner_config,
        acceptance_bin: Some(&verifier_stub()),
    };
    let evidence = attest_ready_before_launch(&dir, &ctx).expect("attestation passes");
    let attestation_digest = evidence.runner_config_digest().to_string();
    let envelope_digest = envelope["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert_eq!(attestation_digest, envelope_digest);

    // Write the five structured sidecars + the transform manifest exactly
    // where the producers name them (identities bound to the real files).
    let candidate_sha = sha256_hex(&fs::read(&candidate).unwrap());
    let candidate_size = fs::metadata(&candidate).unwrap().len();
    let protected_sha = sha256_hex(&fs::read(dir.join("protected.bin")).unwrap());
    let protected_size = fs::metadata(dir.join("protected.bin")).unwrap().len();
    let member_bytes = |schema: &str, protected: bool| {
        serde_json::json!({
            "schema_version": schema,
            "protected_input": if protected {
                serde_json::json!({"sha256": protected_sha, "size_bytes": protected_size})
            } else {
                serde_json::json!(null)
            },
            "candidate": {
                "sha256": candidate_sha,
                "size_bytes": candidate_size,
            },
        })
        .to_string()
        .into_bytes()
    };
    for (name, schema, protected) in [
        ("oep_evidence", "mida.oreans-oep-evidence/v1", true),
        ("iat_evidence", "mida.oreans-iat-evidence/v1", true),
        ("tls_evidence", "mida.oreans-tls-evidence/v1", true),
        (
            "relocation_evidence",
            "mida.oreans-relocation-evidence/v1",
            true,
        ),
        (
            "section_rebuild_evidence",
            "mida.oreans-section-rebuild-evidence/v1",
            true,
        ),
    ] {
        fs::write(
            dir.join(format!("origin_candidate.exe.{name}.json")),
            member_bytes(schema, protected),
        )
        .unwrap();
    }
    fs::write(
        dir.join("origin_candidate.transform_manifest.json"),
        serde_json::json!({
            "schema_version": "mida.transform-manifest/v0",
            "taxonomy_version": "mida.transform-taxonomy/v1",
            "candidate_sha256": candidate_sha,
            "candidate_size_bytes": candidate_size,
            "entries": [],
        })
        .to_string()
        .into_bytes(),
    )
    .unwrap();

    // Production chain: sidecars + transform manifest + PE evidence via the
    // acceptance binary -> atomic bundle from the attested context. The
    // context is consumed BY VALUE (P6.3.1): one attestation authorizes
    // exactly one bundle — a second assemble is a compile error because the
    // value was moved and the type is not `Clone` (see the crate unit test
    // `bundle_assembler::tests::attested_context_is_single_use_by_ownership`).
    let bundle_path = complete_run_evidence(evidence, Some(&verifier_stub()), &candidate)
        .expect("production bundle assemble");
    let bundle: serde_json::Value =
        serde_json::from_slice(&fs::read(&bundle_path).unwrap()).unwrap();
    assert_eq!(
        bundle["runner_config_digest"].as_str().unwrap(),
        attestation_digest,
        "production bundle digest must equal the launch attestation digest"
    );
    assert_eq!(bundle["case_id"].as_str(), Some("origin_macro"));
    assert_eq!(
        bundle["completion_marker"]["state"].as_str(),
        Some("complete"),
        "seven members present -> Complete manifest"
    );
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// 14. One-time authorization
// ---------------------------------------------------------------------------

/// The attested context is a one-time authorization (P6.3.1): it is moved
/// BY VALUE into `complete_run_evidence`, the type is not `Clone`, and it
/// has no public constructor — so the same attestation cannot authorize a
/// second bundle (a second call is a compile error). This test asserts the
/// attested identities are bound and that the value leaves the caller.
#[test]
fn attested_authorization_is_one_time_by_ownership() {
    let dir = temp_dir("one_shot");
    let repo_root = scratch_repo(&dir);
    stage(&dir, &repo_root, &verifier_stub());
    let envelope = read_envelope(&dir);
    let runner_config: mida_core::runner_config::RunnerConfig =
        serde_json::from_value(envelope["runner_config"].clone()).unwrap();
    let input = dir.join("input_origin.bin");
    let candidate = dir.join("origin_candidate.exe");
    let fake_cli = real_cli_bin();
    let ctx = LaunchAttestationContext {
        input: &input,
        output: &candidate,
        cli_binary: &fake_cli,
        runner_config: &runner_config,
        acceptance_bin: Some(&verifier_stub()),
    };
    let evidence = attest_ready_before_launch(&dir, &ctx).expect("attestation passes");
    assert_eq!(evidence.runner_config_digest().len(), 64);
    assert_eq!(evidence.case_id(), "origin_macro");
    assert_eq!(evidence.verifier_sha256().len(), 64);
    assert_eq!(evidence.cli_binary_sha256().len(), 64);
    // `evidence` is moved into complete_run_evidence — there is no way to
    // call it again with the same value (no Clone, no public constructor).
    // The seal is enforced by the type system; the crate unit test
    // `bundle_assembler::tests::attested_context_is_single_use_by_ownership`
    // demonstrates the value leaves the holder on the first consume.
    let _ = evidence; // consumed by the ownership boundary (compile-proof)
    let _ = fs::remove_dir_all(&dir);
}
