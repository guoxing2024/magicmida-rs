//! CLI regression tests for report/input path collisions.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let sequence = NEXT_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mida-acceptance-report-path-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&Path]) -> Output {
    let bin = env!("CARGO_BIN_EXE_mida-acceptance");
    let mut command = Command::new(bin);
    command.arg("check-static");
    for arg in args {
        command.arg(arg);
    }
    command
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"))
}

fn assert_alias_rejected(output: &Output, input: &Path, original: &[u8]) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("aliases"), "stderr: {stderr}");
    assert_eq!(fs::read(input).expect("read preserved input"), original);
}

#[test]
fn report_cannot_overwrite_candidate() {
    let dir = TestDir::new();
    let candidate = dir.path().join("candidate.bin");
    let original = b"candidate must remain byte-identical";
    fs::write(&candidate, original).expect("write candidate");

    let output = run(&[&candidate, Path::new("--report"), &candidate]);

    assert_alias_rejected(&output, &candidate, original);
}

#[test]
fn report_cannot_overwrite_candidate_through_hard_link() {
    let dir = TestDir::new();
    let candidate = dir.path().join("candidate.bin");
    let report_alias = dir.path().join("candidate-report.json");
    let original = b"hard-linked candidate must remain byte-identical";
    fs::write(&candidate, original).expect("write candidate");
    fs::hard_link(&candidate, &report_alias).expect("create report hard link");

    let output = run(&[&candidate, Path::new("--report"), &report_alias]);

    assert_alias_rejected(&output, &candidate, original);
}

#[test]
fn report_cannot_overwrite_oracle() {
    let dir = TestDir::new();
    let candidate = dir.path().join("candidate.bin");
    let oracle = dir.path().join("oracle.bin");
    let oracle_original = b"oracle must remain byte-identical";
    fs::write(&candidate, b"candidate").expect("write candidate");
    fs::write(&oracle, oracle_original).expect("write oracle");

    let output = run(&[
        &candidate,
        Path::new("--oracle"),
        &oracle,
        Path::new("--report"),
        &oracle,
    ]);

    assert_alias_rejected(&output, &oracle, oracle_original);
}

#[test]
fn distinct_report_is_written_without_changing_candidate() {
    let dir = TestDir::new();
    let candidate = dir.path().join("candidate.bin");
    let report = dir.path().join("report.json");
    let original = b"not a PE";
    fs::write(&candidate, original).expect("write candidate");

    let output = run(&[&candidate, Path::new("--report"), &report]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(fs::read(&candidate).expect("read candidate"), original);
    let report_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&report).expect("read report"))
            .expect("valid JSON report");
    assert_eq!(report_json["verdict"], "Rejected");
    assert!(report_json["residual_risks"]
        .as_array()
        .expect("residual_risks")
        .is_empty());
}

#[test]
fn expected_size_mismatch_rejects_without_touching_candidate() {
    let dir = TestDir::new();
    let candidate = dir.path().join("candidate.bin");
    let original = b"size-check";
    fs::write(&candidate, original).expect("write candidate");

    let output = run(&[&candidate, Path::new("--expected-size"), Path::new("9999")]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(fs::read(&candidate).expect("read candidate"), original);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("size_mismatch") || stdout.contains("Rejected"),
        "{stdout}"
    );
}

fn run_behavior(args: &[&Path]) -> Output {
    let bin = env!("CARGO_BIN_EXE_mida-acceptance");
    let mut command = Command::new(bin);
    command.arg("check-with-behavior");
    // Lab fixtures are not dump products — no sibling transform_manifest.
    command.arg("--allow-unmanaged-candidate");
    for arg in args {
        command.arg(arg);
    }
    command
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"))
}

fn write_minimal_evidence(path: &Path, sha: &str, size: u64, verdict: &str, status: &str) {
    // Product Pass requires bilateral reference + registered probe (audit residual).
    let reference = if verdict == "Pass" {
        r#"{ "kind": "bilateral", "sha256": "ff00000000000000000000000000000000000000000000000000000000000000", "notes": "cli-test" }"#
    } else {
        r#"{ "kind": "none", "sha256": null, "notes": null }"#
    };
    let body = format!(
        r#"{{
  "schema_version": "mida.behavior-evidence/v0",
  "candidate": {{
    "sha256": "{sha}",
    "size_bytes": {size},
    "role": "candidate"
  }},
  "reference": {reference},
  "probe": {{
    "id": "exit_code_marker_v0",
    "policy": {{ "network": "deny", "max_wall_ms": 5000, "max_output_bytes": 65536 }},
    "result": {{
      "status": "{status}",
      "exit_code": 0,
      "markers_found": ["MIDA_BEH_MARKER=1"],
      "error_class": null
    }}
  }},
  "verdict": "{verdict}",
  "residual_risks": [],
  "producer": {{ "name": "cli-test", "version": "0" }},
  "transform_ledger": []
}}"#
    );
    fs::write(path, body).expect("write evidence");
}

#[test]
fn check_with_behavior_report_cannot_overwrite_evidence() {
    let dir = TestDir::new();
    let candidate = dir.path().join("candidate.bin");
    let evidence = dir.path().join("evidence.json");
    fs::write(&candidate, b"not a pe").expect("write candidate");
    let sha = format!("{:0>64}", "aa");
    write_minimal_evidence(&evidence, &sha, 8, "Pass", "pass");
    let evidence_bytes = fs::read(&evidence).expect("read evidence");

    let output = run_behavior(&[
        &candidate,
        Path::new("--behavior-evidence"),
        &evidence,
        Path::new("--report"),
        &evidence,
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("aliases"), "stderr: {stderr}");
    assert_eq!(fs::read(&evidence).expect("preserved"), evidence_bytes);
}

#[test]
fn check_with_behavior_identity_mismatch_exit_2() {
    let dir = TestDir::new();
    let candidate = dir.path().join("candidate.bin");
    let evidence = dir.path().join("evidence.json");
    let original = b"not-a-pe-bytes";
    fs::write(&candidate, original).expect("write candidate");
    write_minimal_evidence(&evidence, &"bb".repeat(32), 9999, "Pass", "pass");

    let output = run_behavior(&[&candidate, Path::new("--behavior-evidence"), &evidence]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert_eq!(fs::read(&candidate).expect("read candidate"), original);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Rejected") || stdout.contains("evidence_identity_mismatch"),
        "{stdout}"
    );
}

#[allow(dead_code)]
mod synth {
    include!("../src/test_support/pe_builder.rs");
}

fn write_empty_manifest(path: &Path, pe: &[u8]) {
    let dig = mida_acceptance::sha256_hex(pe);
    let body = format!(
        r#"{{"schema_version":"mida.transform-manifest/v0","taxonomy_version":"mida.transform-taxonomy/v1","candidate_sha256":"{dig}","candidate_size_bytes":{},"entries":[],"note":"cli-unsigned-test"}}"#,
        pe.len()
    );
    fs::write(path, body).expect("write manifest");
}

fn run_behavior_raw(args: &[&str]) -> Output {
    let bin = env!("CARGO_BIN_EXE_mida-acceptance");
    Command::new(bin)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn {bin}: {e}"))
}

/// CLI product posture: managed without signature envelope cannot Accept.
#[test]
fn unsigned_managed_capped_at_pending() {
    use synth::{build_pe, PeBuildOptions};
    let dir = TestDir::new();
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let candidate = dir.path().join("cand.exe");
    let evidence = dir.path().join("evidence.json");
    let manifest = dir.path().join("cand.transform_manifest.json");
    fs::write(&candidate, &pe).expect("write pe");
    write_empty_manifest(&manifest, &pe);
    let dig = mida_acceptance::sha256_hex(&pe);
    write_minimal_evidence(&evidence, &dig, pe.len() as u64, "Pass", "pass");

    let output = run_behavior_raw(&[
        "check-with-behavior",
        candidate.to_str().unwrap(),
        "--behavior-evidence",
        evidence.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("StructuralPassBehaviorPending"),
        "expected Pending cap without envelope, got: {stdout}"
    );
    assert!(
        !stdout.contains("\"verdict\":\"Accepted\""),
        "unsigned managed must not Accept: {stdout}"
    );
    assert!(
        stdout.contains("unsigned_managed_no_accepted")
            || String::from_utf8_lossy(&output.stderr).contains("unsigned"),
        "expected unsigned warning in report, got: {stdout}"
    );
}

/// Lab escape restores managed Accept without envelope.
#[test]
fn allow_unsigned_managed_can_accept() {
    use synth::{build_pe, PeBuildOptions};
    let dir = TestDir::new();
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let candidate = dir.path().join("cand.exe");
    let evidence = dir.path().join("evidence.json");
    let manifest = dir.path().join("cand.transform_manifest.json");
    fs::write(&candidate, &pe).expect("write pe");
    write_empty_manifest(&manifest, &pe);
    let dig = mida_acceptance::sha256_hex(&pe);
    write_minimal_evidence(&evidence, &dig, pe.len() as u64, "Pass", "pass");

    let output = run_behavior_raw(&[
        "check-with-behavior",
        candidate.to_str().unwrap(),
        "--behavior-evidence",
        evidence.to_str().unwrap(),
        "--allow-unsigned-managed",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"verdict\":\"Accepted\""),
        "lab flag should allow Accepted, got: {stdout}"
    );
}

#[test]
fn report_cannot_overwrite_transform_manifest() {
    use synth::{build_pe, PeBuildOptions};
    let dir = TestDir::new();
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let candidate = dir.path().join("cand.exe");
    let evidence = dir.path().join("evidence.json");
    let manifest = dir.path().join("cand.transform_manifest.json");
    fs::write(&candidate, &pe).expect("write pe");
    write_empty_manifest(&manifest, &pe);
    let original = fs::read(&manifest).expect("read manifest");
    let dig = mida_acceptance::sha256_hex(&pe);
    write_minimal_evidence(&evidence, &dig, pe.len() as u64, "Pass", "pass");

    let output = run_behavior_raw(&[
        "check-with-behavior",
        candidate.to_str().unwrap(),
        "--behavior-evidence",
        evidence.to_str().unwrap(),
        "--allow-unsigned-managed",
        "--report",
        manifest.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("aliases") && stderr.contains("transform_manifest"),
        "stderr: {stderr}"
    );
    assert_eq!(fs::read(&manifest).expect("preserved"), original);
}

#[test]
fn report_cannot_overwrite_transform_manifest_through_hard_link() {
    use synth::{build_pe, PeBuildOptions};
    let dir = TestDir::new();
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let candidate = dir.path().join("cand.exe");
    let evidence = dir.path().join("evidence.json");
    let manifest = dir.path().join("cand.transform_manifest.json");
    let report_alias = dir.path().join("manifest-report.json");
    fs::write(&candidate, &pe).expect("write pe");
    write_empty_manifest(&manifest, &pe);
    let original = fs::read(&manifest).expect("read manifest");
    fs::hard_link(&manifest, &report_alias).expect("hard link manifest");
    let dig = mida_acceptance::sha256_hex(&pe);
    write_minimal_evidence(&evidence, &dig, pe.len() as u64, "Pass", "pass");

    let output = run_behavior_raw(&[
        "check-with-behavior",
        candidate.to_str().unwrap(),
        "--behavior-evidence",
        evidence.to_str().unwrap(),
        "--allow-unsigned-managed",
        "--report",
        report_alias.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("aliases"), "stderr: {stderr}");
    assert_eq!(fs::read(&manifest).expect("preserved"), original);
}

/// Even when envelope verification fails before report write, the envelope path
/// used as `--report` must not be truncated (open-without-truncate + early exit,
/// or alias reject if write is reached).
#[test]
fn report_cannot_clobber_signature_envelope_on_failed_verify() {
    use synth::{build_pe, PeBuildOptions};
    let dir = TestDir::new();
    let pe = build_pe(&PeBuildOptions::pe32_plus());
    let candidate = dir.path().join("cand.exe");
    let evidence = dir.path().join("evidence.json");
    let manifest = dir.path().join("cand.transform_manifest.json");
    let envelope = dir.path().join("cand.signature_envelope.json");
    fs::write(&candidate, &pe).expect("write pe");
    write_empty_manifest(&manifest, &pe);
    fs::write(&envelope, b"ENVELOPE_MUST_NOT_BE_TRUNCATED").expect("write envelope");
    let original = fs::read(&envelope).expect("read envelope");
    let dig = mida_acceptance::sha256_hex(&pe);
    write_minimal_evidence(&evidence, &dig, pe.len() as u64, "Pass", "pass");

    let output = run_behavior_raw(&[
        "check-with-behavior",
        candidate.to_str().unwrap(),
        "--behavior-evidence",
        evidence.to_str().unwrap(),
        "--signature-envelope",
        envelope.to_str().unwrap(),
        "--allow-hmac-lab",
        "--envelope-key-id",
        "lab",
        "--envelope-hmac-key-hex",
        "00",
        "--report",
        envelope.to_str().unwrap(),
    ]);
    assert_ne!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(fs::read(&envelope).expect("preserved"), original);
}
