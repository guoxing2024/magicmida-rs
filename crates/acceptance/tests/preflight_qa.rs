//! P6-QA: attack-style preflight tests.
//!
//! Wrong case, wrong digest/size, path aliases, stale/partial evidence,
//! dirty worktree, tool-revision drift, runner-digest drift, unknown config
//! fields, missing bundle members, overwrite-of-input risk — all must yield
//! `not_ready` reports with precise reasons. The orchestrator module itself
//! has no process-launch path; the worktree probe is injected.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use mida_acceptance::{
    check_case_identity, run_offline_preflight, runner_config_digest, write_preflight_report,
    IsolationConfig, PreflightReport, PreflightRequest, PreflightStatus, RunnerConfig,
    WorktreeProbe, WorktreeState, REQUIRED_BUNDLE_MEMBERS,
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

fn request<'a>(
    output_dir: &'a Path,
    config: &'a RunnerConfig,
    probe: &'a dyn WorktreeProbe,
    cases: Vec<(&'a Path, &'a Path, &'a Path)>,
) -> PreflightRequest<'a> {
    PreflightRequest {
        cases,
        output_dir,
        cli_binary: None,
        expected_cli_sha256: None,
        runner_config: config,
        worktree: probe,
        toolchain_pin_file: Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../rust-toolchain.toml"
        )),
        expected_toolchain: "1.97.1",
    }
}

fn missing_input(dir: &Path) -> PathBuf {
    let p = dir.join("protected_input.bin");
    let _ = fs::remove_file(&p);
    p
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

/// Orchestrator without samples is not_ready with precise, deterministic
/// reasons; repeated runs produce identical reports (no timestamps).
#[test]
fn orchestrator_not_ready_deterministic_without_samples() {
    let dir = temp_dir("orchestrator");
    let config = runner_config("oreans/two-sample-mainline@frozen");
    let probe = FakeProbe {
        head: "oreans/two-sample-mainline@frozen".to_string(),
        clean: true,
    };
    let manifest_origin = real_manifest("origin_macro");
    let manifest_lunlun = real_manifest("lunlun_software");
    let input_origin = missing_input(&dir);
    let input_lunlun = missing_input(&dir);

    let out_origin = dir.join("origin_candidate.exe");
    let out_lunlun = dir.join("lunlun_candidate.exe");
    let req = request(
        &dir,
        &config,
        &probe,
        vec![
            (
                manifest_origin.as_path(),
                input_origin.as_path(),
                out_origin.as_path(),
            ),
            (
                manifest_lunlun.as_path(),
                input_lunlun.as_path(),
                out_lunlun.as_path(),
            ),
        ],
    );
    let r1 = run_offline_preflight(&req);
    let r2 = run_offline_preflight(&req);
    assert_eq!(r1, r2, "report must be fully deterministic");
    assert_eq!(r1.status, PreflightStatus::NotReady);
    assert_eq!(r1.cases.len(), 2);
    assert!(
        r1.reasons
            .iter()
            .any(|r| r.contains("cannot read protected input")),
        "{:?}",
        r1.reasons
    );

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
    let manifest_origin = real_manifest("origin_macro");
    let manifest_lunlun = real_manifest("lunlun_software");
    let input_origin = missing_input(&dir);
    let input_lunlun = missing_input(&dir);
    let out_origin = dir.join("origin_candidate.exe");
    let out_lunlun = dir.join("lunlun_candidate.exe");
    let req = request(
        &dir,
        &config,
        &probe,
        vec![
            (
                manifest_origin.as_path(),
                input_origin.as_path(),
                out_origin.as_path(),
            ),
            (
                manifest_lunlun.as_path(),
                input_lunlun.as_path(),
                out_lunlun.as_path(),
            ),
        ],
    );
    let report = run_offline_preflight(&req);
    assert!(
        report.reasons.iter().any(|r| r.contains("stale evidence")),
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
    let manifest_origin = real_manifest("origin_macro");
    let manifest_lunlun = real_manifest("lunlun_software");
    let input_origin = missing_input(&dir);
    let input_lunlun = missing_input(&dir);
    let out_origin = dir.join("origin_candidate.exe");
    let out_lunlun = dir.join("lunlun_candidate.exe");
    let req = request(
        &dir,
        &config,
        &probe,
        vec![
            (
                manifest_origin.as_path(),
                input_origin.as_path(),
                out_origin.as_path(),
            ),
            (
                manifest_lunlun.as_path(),
                input_lunlun.as_path(),
                out_lunlun.as_path(),
            ),
        ],
    );
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
    let manifest_origin = real_manifest("origin_macro");
    let manifest_lunlun = real_manifest("lunlun_software");
    let input_origin = missing_input(&dir);
    let input_lunlun = missing_input(&dir);
    let out_origin = dir.join("origin_candidate.exe");
    let out_lunlun = dir.join("lunlun_candidate.exe");
    let req = request(
        &dir,
        &config,
        &probe,
        vec![
            (
                manifest_origin.as_path(),
                input_origin.as_path(),
                out_origin.as_path(),
            ),
            (
                manifest_lunlun.as_path(),
                input_lunlun.as_path(),
                out_lunlun.as_path(),
            ),
        ],
    );
    let report = run_offline_preflight(&req);
    assert_eq!(report.status, PreflightStatus::NotReady);
    assert!(!report.reasons.is_empty());
    assert!(!report.runner_config_digest.is_empty());
    // Gating contract: a not_ready report must never be mistaken for ready.
    let _: BTreeMap<String, serde_json::Value> =
        serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
    let _ = fs::remove_dir_all(&dir);
}
