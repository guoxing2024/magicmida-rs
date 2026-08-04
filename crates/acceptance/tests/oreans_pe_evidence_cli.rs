use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "../src/test_support/pe_builder.rs"]
mod pe_builder;

use pe_builder::{build_pe, PeBuildOptions};

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "mida-oreans-pe-evidence-cli-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mida-acceptance"))
        .args(args)
        .output()
        .expect("spawn mida-acceptance")
}

fn write_pe(dir: &TestDir, name: &str) -> (PathBuf, Vec<u8>) {
    let bytes = build_pe(&PeBuildOptions::pe32_plus());
    let path = dir.path().join(name);
    fs::write(&path, &bytes).expect("write synthetic PE");
    (path, bytes)
}

#[test]
fn emits_pretty_v1_evidence_with_exact_identity_for_pe32_plus() {
    let dir = TestDir::new();
    let (candidate, bytes) = write_pe(&dir, "candidate.bin");
    let output = run(&["oreans-pe-evidence", candidate.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 JSON");
    assert!(stdout.starts_with("{\n"), "expected pretty JSON: {stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("parse evidence JSON");
    assert_eq!(value["schema_version"], "mida.oreans-pe-evidence/v1");
    assert_eq!(value["valid"], true);
    assert_eq!(value["machine"], 0x8664);
    assert_eq!(value["pe32_plus"], true);
    assert_eq!(value["candidate"]["size_bytes"], bytes.len() as u64);
    assert_eq!(
        value["candidate"]["sha256"],
        mida_acceptance::sha256_hex(&bytes)
    );
}

#[test]
fn expected_size_and_digest_mismatches_fail_closed_with_exit_two() {
    let dir = TestDir::new();
    let (candidate, bytes) = write_pe(&dir, "candidate.bin");
    let actual_digest = mida_acceptance::sha256_hex(&bytes);

    let wrong_size = (bytes.len() as u64 + 1).to_string();
    let output = run(&[
        "oreans-pe-evidence",
        candidate.to_str().unwrap(),
        "--expected-size",
        &wrong_size,
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("expected size"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );

    let wrong_digest = "0".repeat(64);
    let output = run(&[
        "oreans-pe-evidence",
        candidate.to_str().unwrap(),
        "--expected-sha256",
        &wrong_digest,
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("expected SHA-256"), "stderr: {stderr}");
    assert!(stderr.contains(&actual_digest), "stderr: {stderr}");
}

#[test]
fn invalid_pe_returns_exit_two_with_diagnostic() {
    let dir = TestDir::new();
    let candidate = dir.path().join("invalid.bin");
    fs::write(&candidate, b"not a PE").expect("write invalid candidate");

    let output = run(&["oreans-pe-evidence", candidate.to_str().unwrap()]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("PE evidence construction failed") && stderr.contains("error"),
        "stderr: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "invalid candidate must not emit evidence"
    );
}

#[test]
fn report_hard_link_alias_is_rejected_without_modifying_candidate() {
    let dir = TestDir::new();
    let (candidate, bytes) = write_pe(&dir, "candidate.bin");
    let report_alias = dir.path().join("report-alias.json");
    fs::hard_link(&candidate, &report_alias).expect("create candidate hard link");

    let output = run(&[
        "oreans-pe-evidence",
        candidate.to_str().unwrap(),
        "--report",
        report_alias.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("aliases"), "stderr: {stderr}");
    assert_eq!(fs::read(&candidate).expect("candidate preserved"), bytes);
}

#[test]
fn report_candidate_alias_is_rejected_without_modifying_candidate() {
    let dir = TestDir::new();
    let (candidate, bytes) = write_pe(&dir, "candidate.bin");

    let output = run(&[
        "oreans-pe-evidence",
        candidate.to_str().unwrap(),
        "--report",
        candidate.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("aliases candidate"), "stderr: {stderr}");
    assert_eq!(fs::read(&candidate).expect("candidate preserved"), bytes);
}
