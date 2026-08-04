//! P6-QA (P6.1-hardened): attack-style preflight tests.
//!
//! Wrong case, wrong digest/size, path aliases, stale/partial evidence,
//! dirty worktree, tool-revision drift, runner-digest drift, unknown config
//! fields, missing bundle members, overwrite-of-input risk — all must yield
//! `not_ready` reports with precise reasons. P6.1 adds: exact case-set
//! enforcement (0/1/duplicate/extra cases), mandatory CLI identity bound to
//! `RunnerConfig.cli_binary_sha256`, injective length-prefixed canonical
//! digest (comma/newline collisions), durable atomic report writes
//! (overwrite, stale temp, replace-failure preserves old report), empty HEAD,
//! and output-dir containment/writability. The orchestrator module itself has
//! no process-launch path; the worktree probe is injected.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use mida_acceptance::{
    canonical_runner_config, check_case_identity, run_offline_preflight, runner_config_digest,
    sha256_hex, write_preflight_report, FsOutputProbe, IsolationConfig, OutputProbe,
    PreflightReport, PreflightRequest, PreflightStatus, RunnerConfig, WorktreeProbe, WorktreeState,
    REQUIRED_BUNDLE_MEMBERS,
};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mida_preflight_qa_{tag}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn real_manifest(case_id: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../lab/cases/v2")
        .join(format!("{case_id}.json"))
}

fn runner_config(revision: &str) -> RunnerConfig {
    RunnerConfig {
        tool_revision: revision.to_string(),
        cli_binary_sha256: "a".repeat(64),
        features: vec!["default".to_string()],
        debugger_backend: "windows_debug_api".to_string(),
        oep_policy: "captured".to_string(),
        container_restore: "off".to_string(),
        shrink: true,
        data_sections: true,
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

/// Deterministic fake CLI binary; returns (path, sha256_hex of content).
fn fake_cli(dir: &Path, tag: &str) -> (PathBuf, String) {
    let content = format!("FAKE-CLI-{tag}");
    let path = dir.join(format!("mida_cli_{tag}.exe"));
    fs::write(&path, content.as_bytes()).unwrap();
    let digest = sha256_hex(content.as_bytes());
    (path, digest)
}

struct FakeProbe {
    head: String,
    clean: bool,
}

impl WorktreeProbe for FakeProbe {
    fn probe(&self) -> WorktreeState {
        WorktreeState {
            head_revision: self.head.clone(),
            clean: self.clean,
            clean_determined: true,
        }
    }
}

/// Deterministic failure injection for the output-probe seam (P6.2).
#[derive(Clone)]
enum ProbeStage {
    Create,
    Write,
    Sync,
    Cleanup,
    Enumerate,
}

struct FailingOutputProbe {
    stage: ProbeStage,
}

impl OutputProbe for FailingOutputProbe {
    fn probe_writable(&self, output_dir: &Path) -> Result<(), String> {
        match self.stage {
            ProbeStage::Create => Err(format!(
                "output dir {} is not writable: injected create failure",
                output_dir.display()
            )),
            ProbeStage::Write => Err(format!(
                "output dir {} probe write/sync failed: injected write failure",
                output_dir.display()
            )),
            ProbeStage::Sync => Err(format!(
                "output dir {} probe write/sync failed: injected sync failure",
                output_dir.display()
            )),
            ProbeStage::Cleanup => Err(format!(
                "output dir {} probe cleanup failed: injected cleanup failure",
                output_dir.display()
            )),
            ProbeStage::Enumerate => Ok(()),
        }
    }

    fn list_entries(&self, output_dir: &Path) -> Result<Vec<String>, String> {
        match self.stage {
            ProbeStage::Enumerate => Err(format!(
                "cannot enumerate output dir {}: injected enumeration failure",
                output_dir.display()
            )),
            _ => Ok(Vec::new()),
        }
    }
}

fn request<'a>(
    output_dir: &'a Path,
    config: &'a RunnerConfig,
    probe: &'a dyn WorktreeProbe,
    cli: Option<(&'a Path, &'a str)>,
    cases: Vec<(&'a Path, &'a Path, &'a Path)>,
) -> PreflightRequest<'a> {
    request_with_probe(output_dir, config, probe, cli, cases, &FsOutputProbe)
}

fn request_with_probe<'a>(
    output_dir: &'a Path,
    config: &'a RunnerConfig,
    probe: &'a dyn WorktreeProbe,
    cli: Option<(&'a Path, &'a str)>,
    cases: Vec<(&'a Path, &'a Path, &'a Path)>,
    output_probe: &'a dyn OutputProbe,
) -> PreflightRequest<'a> {
    PreflightRequest {
        cases,
        output_dir,
        cli_binary: cli.map(|(path, _)| path),
        expected_cli_sha256: cli.map(|(_, sha)| sha).unwrap_or(""),
        runner_config: config,
        worktree: probe,
        output_probe,
        toolchain_pin_file: Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rust-toolchain.toml"
        )),
        expected_toolchain: "1.97.1",
        repo_root: Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")),
    }
}

fn missing_input(dir: &Path) -> PathBuf {
    let p = dir.join("protected_input.bin");
    let _ = fs::remove_file(&p);
    p
}

fn two_cases(dir: &Path) -> Vec<(PathBuf, PathBuf, PathBuf)> {
    vec![
        (
            real_manifest("origin_macro"),
            missing_input(dir),
            dir.join("origin_candidate.exe"),
        ),
        (
            real_manifest("lunlun_software"),
            missing_input(dir),
            dir.join("lunlun_candidate.exe"),
        ),
    ]
}

fn borrow_cases(cases: &[(PathBuf, PathBuf, PathBuf)]) -> Vec<(&Path, &Path, &Path)> {
    cases
        .iter()
        .map(|(m, i, o)| (m.as_path(), i.as_path(), o.as_path()))
        .collect()
}

/// The two real locked manifests parse strictly and cross-check against the
/// embedded locked manifest; the missing sample file is the only reason.
#[test]
fn real_manifests_parse_and_locked_crosscheck() {
    for case in ["origin_macro", "lunlun_software"] {
        let dir = temp_dir(case);
        let verdict = check_case_identity(&real_manifest(case), &missing_input(&dir), None);
        assert!(!verdict.ok);
        assert!(
            verdict
                .reasons
                .iter()
                .any(|r| r.contains("cannot read protected input")),
            "{case}: {:?}",
            verdict.reasons
        );
        assert!(
            !verdict
                .reasons
                .iter()
                .any(|r| r.contains("locked manifest") || r.contains("unknown/malformed")),
            "{case}: locked cross-check or parse must pass: {:?}",
            verdict.reasons
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

/// With a fully consistent runner (pinned CLI identity, clean worktree,
/// exact two-case set, empty output dir) the ONLY reasons are the missing
/// sample files; repeated runs produce identical reports (no timestamps).
#[test]
fn orchestrator_not_ready_deterministic_without_samples() {
    let dir = temp_dir("orchestrator");
    let (cli_path, cli_digest) = fake_cli(&dir, "det");
    let mut config = runner_config("oreans/two-sample-mainline@frozen");
    config.cli_binary_sha256 = cli_digest.clone();
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, Some((&cli_path, &cli_digest)), cases);
    let r1 = run_offline_preflight(&req);
    let r2 = run_offline_preflight(&req);
    assert_eq!(r1, r2, "report must be fully deterministic");
    assert_eq!(r1.status, PreflightStatus::NotReady);
    assert_eq!(r1.cases.len(), 2);
    assert_eq!(
        r1.reasons.len(),
        2,
        "only the missing inputs: {:?}",
        r1.reasons
    );
    assert!(
        r1.reasons
            .iter()
            .all(|r| r.contains("cannot read protected input")),
        "{:?}",
        r1.reasons
    );
    assert_eq!(r1.worktree_clean, Some(true));
    assert_eq!(r1.toolchain_matches, Some(true));
    assert_eq!(r1.cli_binary_matches, Some(true));

    // Atomic report write: parses back to the same report.
    let path = write_preflight_report(&dir, &r1).expect("write report");
    let back: PreflightReport = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(back, r1);

    let _ = fs::remove_dir_all(&dir);
}

/// Wrong case id must be reported, not silently accepted.
#[test]
fn wrong_case_fails_closed() {
    let dir = temp_dir("wrong_case");
    // A manifest whose case_id is gto_launcher (unknown manifest content).
    let bad_manifest = dir.join("gto.json");
    fs::write(
        &bad_manifest,
        serde_json::to_vec(&serde_json::json!({
            "$schema": "./case-manifest.schema.json",
            "schema_version": "mida.case-manifest/v2",
            "manifest_revision": 1,
            "case_id": "gto_launcher",
            "display_name": "gto",
            "primary_artifact_sha256": "a".repeat(64),
            "artifacts": [{"sha256": "a".repeat(64), "size_bytes": 1, "role": "protected_input"}],
            "capability_cell": {
                "platform": "windows", "binary_format": "pe", "architecture": "x86_64",
                "execution_model": "native", "protection_family": "gto",
                "engine_route": "mida_plugin_ahk_gto", "corpus_role": "holdout"
            },
            "static_fingerprint": {}, "execution_policy": {}, "oracle": {}
        }))
        .unwrap(),
    )
    .unwrap();
    let input = missing_input(&dir);
    let verdict = check_case_identity(&bad_manifest, &input, None);
    assert!(!verdict.ok);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| r.contains("not one of the two fixed Oreans cases")),
        "{:?}",
        verdict.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.1: the case set must be exactly [origin_macro, lunlun_software] —
/// empty, single, and duplicate sets must all fail closed.
#[test]
fn case_set_requires_exactly_two_fixed_cases() {
    for (tag, cases) in [
        ("zero", vec![]),
        (
            "one",
            vec![(
                real_manifest("origin_macro"),
                PathBuf::from("missing.bin"),
                PathBuf::from("out.exe"),
            )],
        ),
        (
            "duplicate",
            vec![
                (
                    real_manifest("origin_macro"),
                    PathBuf::from("missing.bin"),
                    PathBuf::from("out.exe"),
                ),
                (
                    real_manifest("origin_macro"),
                    PathBuf::from("missing2.bin"),
                    PathBuf::from("out2.exe"),
                ),
            ],
        ),
    ] {
        let dir = temp_dir(tag);
        let config = runner_config("oreans/two-sample-mainline@frozen");
        let probe = FakeProbe {
            head: "oreans/two-sample-mainline@frozen".to_string(),
            clean: true,
        };
        let borrowed: Vec<(&Path, &Path, &Path)> = cases
            .iter()
            .map(|(m, i, o)| (m.as_path(), i.as_path(), o.as_path()))
            .collect();
        let req = request(&dir, &config, &probe, None, borrowed);
        let report = run_offline_preflight(&req);
        assert_eq!(report.status, PreflightStatus::NotReady, "{tag}");
        assert!(
            report
                .reasons
                .iter()
                .any(|r| r.contains("fixed cases") || r.contains("case set must be exactly")),
            "{tag}: {:?}",
            report.reasons
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

/// P6.1: CLI identity is mandatory and must bind to the runner config.
#[test]
fn cli_identity_missing_or_drift_blocks_ready() {
    let dir = temp_dir("cli_identity");
    let (cli_path, cli_digest) = fake_cli(&dir, "drift");
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };

    // Missing expected: no CLI at all.
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let req = request(&dir, &config, &probe, None, cases.clone());
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("expected CLI sha256 is missing")),
        "{:?}",
        report.reasons
    );

    // Drift: expected pin does not match the actual binary digest.
    let mut config = runner_config("oreans/two-sample-mainline@frozen");
    config.cli_binary_sha256 = "b".repeat(64);
    let expected_b = "b".repeat(64);
    let req = request(
        &dir,
        &config,
        &probe,
        Some((&cli_path, &expected_b)),
        cases.clone(),
    );
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("does not match expected")),
        "{:?}",
        report.reasons
    );

    // Config mismatch: expected pin matches the binary but not the runner
    // config's declared cli_binary_sha256.
    let mut config = runner_config("oreans/two-sample-mainline@frozen");
    config.cli_binary_sha256 = "c".repeat(64);
    let req = request(&dir, &config, &probe, Some((&cli_path, &cli_digest)), cases);
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("does not match runner_config.cli_binary_sha256")),
        "{:?}",
        report.reasons
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Stale evidence in the output dir must block readiness.
#[test]
fn stale_evidence_blocks_ready() {
    let dir = temp_dir("stale");
    fs::write(dir.join("candidate.exe.iat_evidence.json"), b"{}").unwrap();
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    assert!(
        report.reasons.iter().any(|r| r.contains("stale evidence")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.1: any leftover temp file (old PID-style or new create_new-style) must
/// block readiness.
#[test]
fn stale_temp_blocks_ready() {
    let dir = temp_dir("stale_temp");
    fs::write(dir.join(".preflight.json.tmp-1234-5678"), b"{}").unwrap();
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    assert!(
        report.reasons.iter().any(|r| r.contains("leftover temp")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Dirty worktree and tool-revision drift must both be reported.
#[test]
fn dirty_worktree_and_revision_drift_block_ready() {
    let dir = temp_dir("dirty");
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@other".to_string(),
        clean: false,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("worktree is dirty")),
        "{:?}",
        report.reasons
    );
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("tool revision drift")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.1: an empty worktree HEAD must fail closed.
#[test]
fn empty_head_blocks_ready() {
    let dir = temp_dir("empty_head");
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: String::new(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("head revision is empty")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Runner digest is stable for a fixed config and changes on any drift.
#[test]
fn runner_digest_stability_and_drift() {
    let a = runner_config("rev-1");
    let b = runner_config("rev-1");
    assert_eq!(runner_config_digest(&a), runner_config_digest(&b));
    let mut drifted = runner_config("rev-1");
    drifted.timeout_secs = 999;
    assert_ne!(runner_config_digest(&a), runner_config_digest(&drifted));
}

/// P6.1: the length-prefixed canonical encoding must be injective for
/// commas and newlines — ["a,b"] and ["a","b"] can no longer collide.
#[test]
fn canonical_digest_injective_on_separators() {
    let mut with_comma = runner_config("rev");
    with_comma.features = vec!["a,b".to_string()];
    let mut split = runner_config("rev");
    split.features = vec!["a".to_string(), "b".to_string()];
    assert_ne!(
        canonical_runner_config(&with_comma),
        canonical_runner_config(&split)
    );
    assert_ne!(
        runner_config_digest(&with_comma),
        runner_config_digest(&split)
    );

    let mut with_newline = runner_config("rev");
    with_newline.features = vec!["a\nb".to_string()];
    assert_ne!(
        runner_config_digest(&with_newline),
        runner_config_digest(&split)
    );

    let mut scalar_nl = runner_config("rev");
    scalar_nl.oep_policy = "x\ny".to_string();
    let mut scalar_plain = runner_config("rev");
    scalar_plain.oep_policy = "x y".to_string();
    assert_ne!(
        runner_config_digest(&scalar_nl),
        runner_config_digest(&scalar_plain)
    );
}

/// P6.1: the runner-side producer contract — a config serialized to JSON
/// (as the runner would emit it) parses strictly and the digest is
/// independently recomputed and verified by the acceptance crate.
#[test]
fn runner_emitted_digest_is_independently_verifiable() {
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let emitted_json = serde_json::to_string(&config).unwrap();
    let parsed: RunnerConfig = serde_json::from_str(&emitted_json).expect("strict parse");
    let digest = runner_config_digest(&parsed);
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    // Unknown field must fail closed in the strict contract.
    let mut value: serde_json::Value = serde_json::from_str(&emitted_json).unwrap();
    value["sneaky_extra"] = serde_json::json!(1);
    assert!(serde_json::from_value::<RunnerConfig>(value).is_err());
}

/// The seven-member bundle contract is pinned: any missing member is a
/// contract-drift detection at preflight time.
#[test]
fn bundle_member_contract_is_pinned() {
    let names: Vec<&str> = REQUIRED_BUNDLE_MEMBERS.iter().map(|(n, _)| *n).collect();
    let expected = [
        "oep_evidence",
        "iat_evidence",
        "tls_evidence",
        "relocation_evidence",
        "section_rebuild_evidence",
        "pe_evidence",
        "transform_manifest",
    ];
    assert_eq!(names.len(), expected.len());
    for name in expected {
        assert!(names.contains(&name), "missing member {name}");
    }
}

/// Output overwrites input: a byte-identical candidate path must be flagged
/// before any run can start.
#[test]
fn output_overwrites_input_blocked() {
    let dir = temp_dir("overwrite");
    let input = dir.join("protected.bin");
    fs::write(&input, b"THE-SAMPLE-BYTES").unwrap();
    // Manifest with the real locked identity; the recompute already fails
    // (synthetic file), and the identical output must add the alias reason.
    let manifest = dir.join("case.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&serde_json::json!({
            "$schema": "./case-manifest.schema.json",
            "schema_version": "mida.case-manifest/v2",
            "manifest_revision": 1,
            "case_id": "origin_macro",
            "display_name": "synthetic",
            "primary_artifact_sha256": "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7",
            "artifacts": [{"sha256": "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7", "size_bytes": 5232656, "role": "protected_input"}],
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
    let verdict = check_case_identity(&manifest, &input, Some(&input));
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| r.contains("same canonical path")),
        "{:?}",
        verdict.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.1: candidate outputs must stay inside the controlled output dir.
#[test]
fn candidate_output_outside_output_dir_blocked() {
    let dir = temp_dir("out_of_bounds");
    let outside = std::env::temp_dir().join(format!(
        "mida_preflight_qa_outside_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let cases = vec![
        (
            real_manifest("origin_macro"),
            missing_input(&dir),
            outside.join("origin_candidate.exe"),
        ),
        (
            real_manifest("lunlun_software"),
            missing_input(&dir),
            dir.join("lunlun_candidate.exe"),
        ),
    ];
    let req = request(&dir, &config, &probe, None, borrow_cases(&cases));
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("outside the controlled output dir")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.1: an unwritable output dir must fail closed.
///
/// On Windows the directory read-only attribute does not block file
/// creation, so the test denies the "Everyone" write ACE via `icacls`. If
/// `icacls` is unavailable or refuses, the test skips (the check itself is
/// still exercised in production paths).
#[cfg(windows)]
#[test]
fn unwritable_output_dir_blocks_ready() {
    let dir = temp_dir("readonly");
    let dir_str = dir.to_str().expect("temp path is UTF-8");
    let sid = "*S-1-1-0";
    let denied = std::process::Command::new("icacls")
        .args([dir_str, "/deny", &format!("{sid}:(W)")])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !denied {
        // Cannot force the condition on this host; the check is covered by
        // the other output-dir tests.
        let _ = fs::remove_dir_all(&dir);
        return;
    }
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    let _ = std::process::Command::new("icacls")
        .args([dir_str, "/remove:d", sid])
        .status();
    assert!(
        report.reasons.iter().any(|r| r.contains("not writable")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.1: an existing report is durably replaced (old garbage is gone, new
/// report parses back), and no temp files are left behind.
#[test]
fn existing_report_replaced_atomically() {
    let dir = temp_dir("replace");
    fs::write(dir.join("preflight.json"), b"OLD-GARBAGE").unwrap();
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    let path = write_preflight_report(&dir, &report).expect("write report");
    let back: PreflightReport = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        back, report,
        "old garbage must be replaced by the new report"
    );
    let leftovers: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp-"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "no temp files may remain: {leftovers:?}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.1: when the atomic replace fails (destination is a directory), the
/// previous destination is preserved and the temp file is cleaned up.
#[test]
fn replace_failure_preserves_old_destination() {
    let dir = temp_dir("replace_fail");
    let destination = dir.join("preflight.json");
    fs::create_dir(&destination).unwrap();
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    let result = write_preflight_report(&dir, &report);
    assert!(result.is_err(), "replace over a directory must fail");
    assert!(
        destination.is_dir(),
        "the previous destination must be preserved untouched"
    );
    let leftovers: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "temp must be removed: {leftovers:?}");
    let _ = fs::remove_dir_all(&dir);
}

/// P6.2: a whitespace-wrapped CLI pin must be malformed — validation runs on
/// the ORIGINAL string, not a trimmed copy.
#[test]
fn whitespace_wrapped_cli_sha_is_malformed() {
    let dir = temp_dir("ws_sha");
    let (cli_path, _) = fake_cli(&dir, "ws");
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let wrapped = format!(" {}", "a".repeat(64));
    let req = request(&dir, &config, &probe, Some((&cli_path, &wrapped)), cases);
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("malformed") && r.contains("exactly 64 hex chars")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.2: every step of the output probe is fail-closed — create, write,
/// sync, and cleanup failures are all NotReady (injected deterministically
/// through the OutputProbe seam).
#[test]
fn output_probe_failures_block_ready_deterministically() {
    for (tag, stage) in [
        ("create", ProbeStage::Create),
        ("write", ProbeStage::Write),
        ("sync", ProbeStage::Sync),
        ("cleanup", ProbeStage::Cleanup),
    ] {
        let dir = temp_dir(&format!("probe_{tag}"));
        let config = runner_config("oreans/two-sample-mainline@frozen");
        let probe = FakeProbe {
            head: "oreans/two-sample-mainline@frozen".to_string(),
            clean: true,
        };
        let owned_cases = two_cases(&dir);
        let cases = borrow_cases(&owned_cases);
        let output_probe = FailingOutputProbe {
            stage: stage.clone(),
        };
        let req = request_with_probe(&dir, &config, &probe, None, cases, &output_probe);
        let report = run_offline_preflight(&req);
        assert_eq!(report.status, PreflightStatus::NotReady, "{tag}");
        let expected_fragment = match stage {
            ProbeStage::Create => "is not writable",
            ProbeStage::Write => "injected write failure",
            ProbeStage::Sync => "injected sync failure",
            ProbeStage::Cleanup => "probe cleanup failed",
            ProbeStage::Enumerate => unreachable!(),
        };
        assert!(
            report.reasons.iter().any(|r| r.contains(expected_fragment)),
            "{tag}: {:?}",
            report.reasons
        );
        let _ = fs::remove_dir_all(&dir);
    }
}

/// P6.2: output-dir enumeration failure must be NotReady — stale evidence
/// must never be silently undetectable.
#[test]
fn output_enumeration_failure_blocks_ready() {
    let dir = temp_dir("enum_fail");
    fs::write(dir.join("candidate.exe.iat_evidence.json"), b"{}").unwrap();
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let output_probe = FailingOutputProbe {
        stage: ProbeStage::Enumerate,
    };
    let req = request_with_probe(&dir, &config, &probe, None, cases, &output_probe);
    let report = run_offline_preflight(&req);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("cannot enumerate output dir")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.2: leftover .preflight-probe-* files are stale and block readiness.
#[test]
fn leftover_probe_file_blocks_ready() {
    let dir = temp_dir("probe_leftover");
    fs::write(dir.join(".preflight-probe-123-456"), b"x").unwrap();
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    assert!(
        report.reasons.iter().any(|r| r.contains("leftover temp")),
        "{:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P6.2: two correct cases plus a third extra case must be NotReady for
/// both the cardinality and the set-contract reason.
#[test]
fn extra_case_rejected() {
    let dir = temp_dir("extra_case");
    let extra_manifest = dir.join("extra.json");
    fs::write(
        &extra_manifest,
        serde_json::to_vec(&serde_json::json!({
            "$schema": "./case-manifest.schema.json",
            "schema_version": "mida.case-manifest/v2",
            "manifest_revision": 1,
            "case_id": "origin_macro",
            "display_name": "extra",
            "primary_artifact_sha256": "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7",
            "artifacts": [{"sha256": "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7", "size_bytes": 5232656, "role": "protected_input"}],
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
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let cases = vec![
        (
            real_manifest("origin_macro"),
            missing_input(&dir),
            dir.join("origin_candidate.exe"),
        ),
        (
            real_manifest("lunlun_software"),
            missing_input(&dir),
            dir.join("lunlun_candidate.exe"),
        ),
        (
            extra_manifest.clone(),
            missing_input(&dir),
            dir.join("extra_candidate.exe"),
        ),
    ];
    let req = request(&dir, &config, &probe, None, borrow_cases(&cases));
    let report = run_offline_preflight(&req);
    assert_eq!(report.status, PreflightStatus::NotReady);
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("requires exactly 2 fixed cases")),
        "cardinality reason missing: {:?}",
        report.reasons
    );
    assert!(
        report
            .reasons
            .iter()
            .any(|r| r.contains("case set must be exactly")),
        "set-contract reason missing: {:?}",
        report.reasons
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Failed preflight still yields a machine-readable not_ready report: the
/// gating contract for any future launch path.
#[test]
fn failed_preflight_produces_actionable_report() {
    let dir = temp_dir("gating");
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let owned_cases = two_cases(&dir);
    let cases = borrow_cases(&owned_cases);
    let req = request(&dir, &config, &probe, None, cases);
    let report = run_offline_preflight(&req);
    assert_eq!(report.status, PreflightStatus::NotReady);
    assert!(!report.reasons.is_empty());
    assert!(!report.runner_config_digest.is_empty());
    // Gating contract: a not_ready report must never be mistaken for ready.
    let _: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    let _ = fs::remove_dir_all(&dir);
}
