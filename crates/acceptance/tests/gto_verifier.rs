//! G3-R3-R2-R1: the independent `mida-acceptance` verifier binds the actual
//! GTO `--case` input to the envelope's sealed immutable snapshot path, and
//! the GTO positive control has no GTO-specific rejection reasons.
//!
//! These are the acceptance package's OWN integration tests: they invoke the
//! real `mida-acceptance` binary via `CARGO_BIN_EXE_mida-acceptance`, so
//! `cargo test -p mida-acceptance --offline` is self-contained (no dependency
//! on the CLI package or a pre-existing sibling binary).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn real_manifest(case_id: &str) -> PathBuf {
    workspace_root()
        .join("lab/cases/v2")
        .join(format!("{case_id}.json"))
}

fn acceptance_bin() -> &'static str {
    env!("CARGO_BIN_EXE_mida-acceptance")
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mida_acc_gto_{tag}_{}_{}",
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Build a temporary GTO case manifest declaring the given protected-input
/// identity. Uses the same shape as `lab/cases/v2/gto_launcher.json`
/// (case_id=gto_launcher, protection_family=ahk_gto_candidate).
fn write_gto_manifest(dir: &Path, sha: &str, size: u64) -> PathBuf {
    let path = dir.join("gto_launcher.json");
    let json = serde_json::json!({
        "$schema": "./case-manifest.schema.json",
        "schema_version": "mida.case-manifest/v2",
        "manifest_revision": 1,
        "case_id": "gto_launcher",
        "display_name": "GTO launcher sample (synthetic)",
        "primary_artifact_sha256": sha,
        "artifacts": [
            { "sha256": sha, "size_bytes": size, "role": "protected_input" }
        ],
        "capability_cell": {
            "platform": "windows",
            "binary_format": "pe",
            "architecture": "x86_64",
            "execution_model": "native",
            "protection_family": "ahk_gto_candidate",
            "engine_route": "mida_plugin_ahk_gto",
            "corpus_role": "research"
        },
        "static_fingerprint": {},
        "execution_policy": {},
        "oracle": {}
    });
    fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    path
}

/// Write a real content-addressed snapshot and return `(sha, size, path)`.
fn write_snapshot(dir: &Path) -> (String, u64, PathBuf) {
    let payload = b"G3-R3-R2-R1-REAL-SNAPSHOT-PAYLOAD";
    let sha = sha256_hex(payload);
    let path = dir
        .join("snapshots")
        .join("gto_launcher")
        .join(&sha)
        .join("snapshot.bin");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, payload).unwrap();
    (sha, payload.len() as u64, path)
}

/// A fake CLI binary (the verifier reads it only to check its SHA against the
/// envelope; the envelope's pinned CLI sha is a fake 64-hex that no real file
/// matches, so the overall report is NotReady — but GTO reasons stay empty).
fn fake_cli_binary(dir: &Path) -> PathBuf {
    let p = dir.join("fake_mida_cli.exe");
    fs::write(&p, b"FAKE-CLI-FOR-ACCEPTANCE-TEST").unwrap();
    p
}

/// Oreans fixed identities (mirror of the locked manifests).
const ORIGIN_SHA: &str = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
const ORIGIN_SIZE: u64 = 5_232_656;
const LUNLUN_SHA: &str = "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07";
const LUNLUN_SIZE: u64 = 4_976_144;

/// Build an Oreans runner config (family oreans_themida) + its digest.
fn oreans_config() -> (mida_acceptance::RunnerConfig, String) {
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
        pure_rebuild: true,
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

/// Build a GTO (generic/no-gate) runner config + its digest.
fn gto_config() -> (mida_acceptance::RunnerConfig, String) {
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
    (cfg, digest)
}

/// One case entry (JSON) for the v4 envelope.
fn case_entry(
    case_id: &str,
    family: &str,
    sha: &str,
    size: u64,
    protected_input_path: Option<&str>,
) -> serde_json::Value {
    let (cfg, digest) = if family == "ahk_gto" {
        gto_config()
    } else {
        oreans_config()
    };
    let path_json = match protected_input_path {
        Some(p) => serde_json::json!(p),
        None => serde_json::Value::Null,
    };
    serde_json::json!({
        "case_id": case_id,
        "family_id": family,
        "protected_input": { "sha256": sha, "size_bytes": size },
        "protected_input_path": path_json,
        "runner_config": serde_json::to_value(&cfg).unwrap(),
        "runner_config_digest": digest,
    })
}

/// Recompute the case-set digest (mirrors the CLI producer's canonical
/// encoding: path lowercased).
fn reseal_case_set(entries: &[serde_json::Value]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|c| {
            let family = c["family_id"].as_str().unwrap_or("oreans_themida");
            let path = c
                .get("protected_input_path")
                .and_then(|p| p.as_str())
                .unwrap_or_default()
                .to_lowercase();
            format!(
                "case={}\nfamily={}\nprotected_input={}|{}\nprotected_input_path={}\nrunner_config_digest={}\n",
                c["case_id"].as_str().unwrap(),
                family.to_lowercase(),
                c["protected_input"]["sha256"].as_str().unwrap().to_lowercase(),
                c["protected_input"]["size_bytes"].as_u64().unwrap(),
                path,
                c["runner_config_digest"].as_str().unwrap().to_lowercase(),
            )
        })
        .collect();
    lines.sort();
    sha256_hex(lines.concat().as_bytes())
}

/// Build a full v4 envelope: 2 Oreans fixed + the given GTO case.
fn full_envelope(gto_case: serde_json::Value) -> serde_json::Value {
    let configs = vec![
        case_entry(
            "origin_macro",
            "oreans_themida",
            ORIGIN_SHA,
            ORIGIN_SIZE,
            None,
        ),
        case_entry(
            "lunlun_software",
            "oreans_themida",
            LUNLUN_SHA,
            LUNLUN_SIZE,
            None,
        ),
        gto_case,
    ];
    let case_set = reseal_case_set(&configs);
    serde_json::json!({
        "$schema": "./runner-config-envelope.schema.json",
        "schema_version": "mida.runner-config-envelope/v4",
        "cli_binary_sha256": "a".repeat(64),
        "tool_revision": "rev",
        "verifier_source": "<cli-dir>/mida-acceptance.exe",
        "verifier_path": "C:\\dummy\\mida-acceptance.exe",
        "verifier_sha256": "b".repeat(64),
        "case_set_digest": case_set,
        "case_configs": configs,
    })
}

/// Invoke the real acceptance binary against the envelope + the given GTO case
/// input path. The Oreans triples use synthetic input files (so they contribute
/// NotReady reasons); the GTO case uses `gto_input`.
fn run_verifier(
    dir: &Path,
    envelope: &serde_json::Value,
    gto_manifest: &Path,
    gto_input: &Path,
) -> Output {
    let envelope_path = dir.join("runner-config-envelope.json");
    fs::write(&envelope_path, serde_json::to_vec_pretty(envelope).unwrap()).unwrap();
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-SYNTHETIC-INPUT").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-SYNTHETIC-INPUT").unwrap();
    let cli = fake_cli_binary(dir);
    let args = vec![
        "preflight".to_string(),
        "--envelope".to_string(),
        envelope_path.display().to_string(),
        "--output-dir".to_string(),
        dir.display().to_string(),
        "--snapshot-root".to_string(),
        dir.join("snapshots").display().to_string(),
        "--cli-binary".to_string(),
        cli.display().to_string(),
        "--repo-root".to_string(),
        workspace_root().display().to_string(),
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
        "--case".to_string(),
        gto_manifest.display().to_string(),
        gto_input.display().to_string(),
        dir.join("gto_candidate.exe").display().to_string(),
    ];
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Command::new(acceptance_bin())
        .args(&arg_refs)
        .output()
        .expect("spawn acceptance binary")
}

/// Invoke the acceptance binary WITHOUT `--snapshot-root` (to prove Oreans-only
/// compatibility / GTO fail-closed when the root is omitted).
fn run_verifier_without_snapshot_root(
    dir: &Path,
    envelope: &serde_json::Value,
    gto_manifest: &Path,
    gto_input: &Path,
) -> Output {
    let envelope_path = dir.join("runner-config-envelope.json");
    fs::write(&envelope_path, serde_json::to_vec_pretty(envelope).unwrap()).unwrap();
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-SYNTHETIC-INPUT").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-SYNTHETIC-INPUT").unwrap();
    let cli = fake_cli_binary(dir);
    let args = vec![
        "preflight".to_string(),
        "--envelope".to_string(),
        envelope_path.display().to_string(),
        "--output-dir".to_string(),
        dir.display().to_string(),
        "--cli-binary".to_string(),
        cli.display().to_string(),
        "--repo-root".to_string(),
        workspace_root().display().to_string(),
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
        "--case".to_string(),
        gto_manifest.display().to_string(),
        gto_input.display().to_string(),
        dir.join("gto_candidate.exe").display().to_string(),
    ];
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Command::new(acceptance_bin())
        .args(&arg_refs)
        .output()
        .expect("spawn acceptance binary")
}

/// A generic `--case` triple: (manifest, input, output).
type CaseTriple = (PathBuf, PathBuf, PathBuf);

/// Invoke the real acceptance binary against an envelope with an arbitrary
/// list of `--case` triples.
fn run_verifier_with_triples(
    dir: &Path,
    envelope: &serde_json::Value,
    triples: &[CaseTriple],
) -> Output {
    let envelope_path = dir.join("runner-config-envelope.json");
    fs::write(&envelope_path, serde_json::to_vec_pretty(envelope).unwrap()).unwrap();
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-SYNTHETIC-INPUT").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-SYNTHETIC-INPUT").unwrap();
    let cli = fake_cli_binary(dir);
    let mut args = vec![
        "preflight".to_string(),
        "--envelope".to_string(),
        envelope_path.display().to_string(),
        "--output-dir".to_string(),
        dir.display().to_string(),
        "--snapshot-root".to_string(),
        dir.join("snapshots").display().to_string(),
        "--cli-binary".to_string(),
        cli.display().to_string(),
        "--repo-root".to_string(),
        workspace_root().display().to_string(),
        "--toolchain-pin".to_string(),
        workspace_root()
            .join("rust-toolchain.toml")
            .display()
            .to_string(),
        "--expected-toolchain".to_string(),
        "1.97.1".to_string(),
    ];
    for (manifest, input, output) in triples {
        args.push("--case".to_string());
        args.push(manifest.display().to_string());
        args.push(input.display().to_string());
        args.push(output.display().to_string());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    Command::new(acceptance_bin())
        .args(&arg_refs)
        .output()
        .expect("spawn acceptance binary")
}

/// Read the preflight report emitted by the acceptance binary.
fn read_report(dir: &Path) -> serde_json::Value {
    let raw = fs::read(dir.join("preflight.json")).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

/// Find the GTO case in the report.
fn gto_report_case(report: &serde_json::Value) -> serde_json::Value {
    report["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["case_id"].as_str() == Some("gto_launcher"))
        .cloned()
        .expect("report contains gto_launcher case")
}

/// A real GTO snapshot + matching temp manifest + envelope with the sealed path.
fn setup_positive(dir: &Path) -> (serde_json::Value, PathBuf, PathBuf, String, u64) {
    let (sha, size, snap_path) = write_snapshot(dir);
    let manifest = write_gto_manifest(dir, &sha, size);
    let gto_case = case_entry(
        "gto_launcher",
        "ahk_gto",
        &sha,
        size,
        Some(&snap_path.display().to_string()),
    );
    let envelope = full_envelope(gto_case);
    (envelope, manifest, snap_path, sha, size)
}

/// P1. The verifier accepts the exact bound GTO snapshot: a real snapshot whose
/// sealed path equals the actual input, with a matching temp manifest.
#[test]
fn verifier_accepts_exact_bound_gto_snapshot() {
    let dir = temp_dir("accept_exact");
    let (envelope, manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let out = run_verifier(&dir, &envelope, &manifest, &snap_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "overall NotReady expected: {stderr}"
    );
    // No GTO path/verifier/digest rejection reasons.
    assert!(
        !stderr.contains("protected_input_path")
            && !stderr.contains("hash dir")
            && !stderr.contains("digest drift")
            && !stderr.contains("runner config rejected")
            && !stderr.contains("must be the staged immutable snapshot"),
        "no GTO rejection for the exact bound snapshot: {stderr}"
    );
    // The report's GTO case is identity_ok with empty reasons.
    let report = read_report(&dir);
    let gto = gto_report_case(&report);
    assert_eq!(
        gto["identity_ok"].as_bool(),
        Some(true),
        "GTO identity_ok: {gto}"
    );
    assert!(
        gto["reasons"].as_array().unwrap().is_empty(),
        "GTO reasons must be empty: {gto}"
    );
    // Report protected_input_path == sealed snapshot path.
    assert_eq!(
        gto["protected_input_path"].as_str().unwrap(),
        snap_path.display().to_string(),
        "report must bind the sealed snapshot path"
    );
    // GTO per-case digest == envelope digest.
    let gto_digest = gto["runner_config_digest"].as_str().unwrap().to_lowercase();
    let env_gto_digest = envelope["case_configs"][2]["runner_config_digest"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert_eq!(gto_digest, env_gto_digest, "GTO per-case digest mismatch");
    // Report case-set digest == envelope case_set_digest.
    assert_eq!(
        report["runner_config_digest"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        envelope["case_set_digest"].as_str().unwrap().to_lowercase(),
        "report case-set digest mismatch"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P2. The verifier independently rejects a same-bytes different-path GTO input
/// (a live source alias), even though the manifest hash/size match.
#[test]
fn verifier_rejects_same_bytes_different_gto_path() {
    let dir = temp_dir("same_bytes_diff_path");
    let (envelope, _manifest, snap_path, sha, size) = setup_positive(&dir);
    // A live source OUTSIDE snapshot_root with the SAME bytes/hash as the
    // snapshot. Its canonical path differs from the sealed snapshot path.
    let live = dir.join("live_source.exe");
    fs::write(&live, fs::read(&snap_path).unwrap()).unwrap();
    // Rebuild the manifest so its declared identity matches the live source
    // (same bytes, so same sha/size) — the path binding must still reject.
    let manifest2 = write_gto_manifest(&dir, &sha, size);
    let out = run_verifier(&dir, &envelope, &manifest2, &live);
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Overall state is NotReady.
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    // Per-case verdict: the GTO case must be identity_ok=false with a clear
    // path-binding failure reason, and its protected_input_path must NOT be the
    // live source (it is unverified/empty).
    let report = read_report(&dir);
    let gto = gto_report_case(&report);
    assert_eq!(
        gto["identity_ok"].as_bool(),
        Some(false),
        "GTO case must be identity_ok=false on path binding failure: {gto}"
    );
    let reasons: Vec<&str> = gto["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("GTO path binding failed")),
        "GTO case reasons must include the path-binding failure: {gto}"
    );
    assert!(
        !reasons
            .iter()
            .any(|r| r.contains("must be the staged immutable snapshot"))
            || reasons
                .iter()
                .any(|r| r.contains("same-bytes live source/alias is refused")
                    || r.contains("GTO path binding failed")),
        "the reason must cite the path/alias refusal: {gto}"
    );
    // The report must NOT record the live source path as a verified path.
    let report_path = gto["protected_input_path"].as_str().unwrap();
    assert!(
        report_path.is_empty() || !report_path.contains("live_source.exe"),
        "report GTO protected_input_path must not be the live source alias: {report_path}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P3. The verifier rejects a raw `..` in the sealed GTO path even though it
/// could canonicalize to the same snapshot.
#[test]
fn verifier_rejects_gto_raw_dotdot_path() {
    let dir = temp_dir("raw_dotdot");
    let (_envelope, _manifest, snap_path, _sha, size) = setup_positive(&dir);
    let sha = sha256_hex(&fs::read(&snap_path).unwrap());
    let manifest = write_gto_manifest(&dir, &sha, size);
    // Rebuild the envelope with a `..`-containing raw sealed path.
    let gto_case = case_entry(
        "gto_launcher",
        "ahk_gto",
        &sha,
        size,
        Some(&format!(
            "{}\\snapshots\\..\\snapshots\\gto_launcher\\{}\\snapshot.bin",
            dir.display(),
            sha
        )),
    );
    let env_dotdot = full_envelope(gto_case);
    let out = run_verifier(&dir, &env_dotdot, &manifest, &snap_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("relative") || stderr.contains("parent") || stderr.contains("`..`"),
        "a raw `..` sealed path must be rejected by the verifier: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P4. The report binds the verified sealed GTO path (not the raw input).
#[test]
fn verifier_report_binds_sealed_gto_path() {
    let dir = temp_dir("report_binds");
    let (envelope, manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let out = run_verifier(&dir, &envelope, &manifest, &snap_path);
    let _ = String::from_utf8_lossy(&out.stderr);
    let report = read_report(&dir);
    let gto = gto_report_case(&report);
    // The report's GTO protected_input_path is the sealed snapshot path (the
    // verified binding), and it matches the canonical snapshot path.
    let report_path = gto["protected_input_path"].as_str().unwrap();
    assert_eq!(
        report_path,
        snap_path.display().to_string(),
        "report GTO protected_input_path must be the sealed snapshot path"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// P5. The positive control's overall report is NotReady only for non-GTO
/// reasons (synthetic Oreans files / fake CLI), never for GTO envelope/path/
/// family/digest/identity.
#[test]
fn gto_positive_control_has_no_gto_rejection_reasons() {
    let dir = temp_dir("no_gto_reasons");
    let (envelope, manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let out = run_verifier(&dir, &envelope, &manifest, &snap_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "overall NotReady expected: {stderr}"
    );
    // The NotReady reasons must NOT mention GTO at all.
    let report = read_report(&dir);
    let reasons: Vec<&str> = report["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    for r in &reasons {
        assert!(
            !r.contains("GTO")
                && !r.contains("gto_launcher")
                && !r.contains("protected_input_path"),
            "a NotReady reason must not be GTO-related: {r}"
        );
    }
    // GTO case identity_ok == true.
    let gto = gto_report_case(&report);
    assert_eq!(gto["identity_ok"].as_bool(), Some(true));
    let _ = fs::remove_dir_all(&dir);
}

/// N1. Negative: tampering the GTO runner config family is rejected.
#[test]
fn gto_runner_config_family_tamper_rejected() {
    let dir = temp_dir("cfg_tamper");
    let (envelope, manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let mut env = envelope;
    env["case_configs"][2]["runner_config"]["packer_family"] = serde_json::json!("oreans_themida");
    env["case_set_digest"] =
        serde_json::json!(reseal_case_set(env["case_configs"].as_array().unwrap()));
    let out = run_verifier(&dir, &env, &manifest, &snap_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("packer_family") && stderr.contains("oreans_themida"),
        "GTO runner-config family tamper must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// N2. Negative: tampering the GTO runner_config_digest is rejected.
#[test]
fn gto_runner_config_digest_tamper_rejected() {
    let dir = temp_dir("dig_tamper");
    let (envelope, manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let mut env = envelope;
    env["case_configs"][2]["runner_config_digest"] = serde_json::json!("0".repeat(64));
    env["case_set_digest"] =
        serde_json::json!(reseal_case_set(env["case_configs"].as_array().unwrap()));
    let out = run_verifier(&dir, &env, &manifest, &snap_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("digest drift") || stderr.contains("recomputed"),
        "GTO runner-config digest tamper must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// N3. Negative: missing GTO protected_input_path is rejected.
#[test]
fn gto_missing_path_rejected() {
    let dir = temp_dir("missing_path");
    let (envelope, manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let mut env = envelope;
    env["case_configs"][2]["protected_input_path"] = serde_json::Value::Null;
    env["case_set_digest"] =
        serde_json::json!(reseal_case_set(env["case_configs"].as_array().unwrap()));
    let out = run_verifier(&dir, &env, &manifest, &snap_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("protected_input_path"),
        "a GTO case without a protected_input_path must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// N4. Negative: an Oreans fixed case carrying a protected_input_path is rejected.
#[test]
fn oreans_with_path_rejected() {
    let dir = temp_dir("oreans_path");
    let (envelope, manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let mut env = envelope;
    env["case_configs"][0]["protected_input_path"] = serde_json::json!("C:\\evil\\origin.bin");
    env["case_set_digest"] =
        serde_json::json!(reseal_case_set(env["case_configs"].as_array().unwrap()));
    let out = run_verifier(&dir, &env, &manifest, &snap_path);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("origin_macro") && stderr.contains("protected_input_path"),
        "an Oreans fixed case with a protected_input_path must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// N5. Negative: the snapshot hash directory differs from protected_input.sha256.
#[test]
fn gto_hash_dir_mismatch_rejected() {
    let dir = temp_dir("hash_mismatch");
    let (envelope, manifest, _snap_path, _sha, _size) = setup_positive(&dir);
    let wrong_sha = "d".repeat(64);
    let wrong_snap = dir
        .join("snapshots")
        .join("gto_launcher")
        .join(&wrong_sha)
        .join("snapshot.bin");
    fs::create_dir_all(wrong_snap.parent().unwrap()).unwrap();
    fs::write(&wrong_snap, b"WRONG-HASH-DIR-PAYLOAD").unwrap();
    // The manifest + protected_input still declare the REAL snapshot sha, but
    // the sealed path points at a different hash dir.
    let mut env = envelope;
    env["case_configs"][2]["protected_input_path"] =
        serde_json::json!(wrong_snap.display().to_string());
    env["case_set_digest"] =
        serde_json::json!(reseal_case_set(env["case_configs"].as_array().unwrap()));
    let out = run_verifier(&dir, &env, &manifest, &wrong_snap);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("hash dir") || stderr.contains("!= sealed protected_input sha"),
        "a hash-directory mismatch must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// Build an envelope with ONLY the two Oreans fixed cases (no GTO lane).
fn oreans_only_envelope() -> serde_json::Value {
    let configs = vec![
        case_entry(
            "origin_macro",
            "oreans_themida",
            ORIGIN_SHA,
            ORIGIN_SIZE,
            None,
        ),
        case_entry(
            "lunlun_software",
            "oreans_themida",
            LUNLUN_SHA,
            LUNLUN_SIZE,
            None,
        ),
    ];
    let case_set = reseal_case_set(&configs);
    serde_json::json!({
        "$schema": "./runner-config-envelope.schema.json",
        "schema_version": "mida.runner-config-envelope/v4",
        "cli_binary_sha256": "a".repeat(64),
        "tool_revision": "rev",
        "verifier_source": "<cli-dir>/mida-acceptance.exe",
        "verifier_path": "C:\\dummy\\mida-acceptance.exe",
        "verifier_sha256": "b".repeat(64),
        "case_set_digest": case_set,
        "case_configs": configs,
    })
}

/// Build the standard Oreans + GTO `--case` triples (with a real snapshot path).
fn standard_triples(dir: &Path, gto_manifest: &Path, gto_input: &Path) -> Vec<CaseTriple> {
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-SYNTHETIC-INPUT").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-SYNTHETIC-INPUT").unwrap();
    vec![
        (
            real_manifest("origin_macro"),
            dir.join("input_origin.bin"),
            dir.join("origin_candidate.exe"),
        ),
        (
            real_manifest("lunlun_software"),
            dir.join("input_lunlun.bin"),
            dir.join("lunlun_candidate.exe"),
        ),
        (
            gto_manifest.to_path_buf(),
            gto_input.to_path_buf(),
            dir.join("gto_candidate.exe"),
        ),
    ]
}

/// R1: envelope has GTO but `--case` lacks GTO — must fail closed.
#[test]
fn envelope_has_gto_case_input_lacks_gto_rejected() {
    let dir = temp_dir("env_gto_no_case");
    let (envelope, _manifest, snap_path, _sha, _size) = setup_positive(&dir);
    // `--case` triples: Oreans only (no GTO).
    let mut triples = standard_triples(&dir, &dir.join("nonexistent.json"), &snap_path);
    triples.pop(); // drop the GTO triple
    let out = run_verifier_with_triples(&dir, &envelope, &triples);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    assert!(
        stderr.contains("GTO lane correspondence mismatch"),
        "envelope-has-GTO / --case-lacks-GTO must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// R1: `--case` has GTO but envelope lacks GTO — must fail closed.
#[test]
fn case_input_has_gto_envelope_lacks_gto_rejected() {
    let dir = temp_dir("case_gto_no_env");
    let envelope = oreans_only_envelope();
    let (_, _manifest, snap_path, sha, size) = setup_positive(&dir);
    let gto_manifest = write_gto_manifest(&dir, &sha, size);
    let triples = standard_triples(&dir, &gto_manifest, &snap_path);
    let out = run_verifier_with_triples(&dir, &envelope, &triples);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    assert!(
        stderr.contains("GTO lane correspondence mismatch"),
        "--case-has-GTO / envelope-lacks-GTO must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// R1: duplicate GTO `--case` input — must fail closed.
#[test]
fn duplicate_gto_case_input_rejected() {
    let dir = temp_dir("dup_gto_case");
    let (envelope, gto_manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let mut triples = standard_triples(&dir, &gto_manifest, &snap_path);
    // Add a duplicate GTO `--case` triple.
    triples.push((
        gto_manifest.clone(),
        snap_path.clone(),
        dir.join("gto_dup.exe"),
    ));
    let out = run_verifier_with_triples(&dir, &envelope, &triples);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    assert!(
        stderr.contains("GTO lane must appear at most once") || stderr.contains("exactly one"),
        "duplicate GTO --case must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// R1: duplicate GTO envelope case — must fail closed.
#[test]
fn duplicate_gto_envelope_case_rejected() {
    let dir = temp_dir("dup_gto_env");
    let (envelope, _manifest, snap_path, _sha, _size) = setup_positive(&dir);
    // Duplicate the GTO case in the envelope.
    let mut env = envelope;
    let gto_case = env["case_configs"][2].clone();
    env["case_configs"].as_array_mut().unwrap().push(gto_case);
    env["case_set_digest"] =
        serde_json::json!(reseal_case_set(env["case_configs"].as_array().unwrap()));
    let gto_manifest = write_gto_manifest(
        &dir,
        &sha256_hex(&fs::read(&snap_path).unwrap()),
        fs::metadata(&snap_path).unwrap().len(),
    );
    let triples = standard_triples(&dir, &gto_manifest, &snap_path);
    let out = run_verifier_with_triples(&dir, &env, &triples);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    assert!(
        stderr.contains("GTO lane must appear at most once") || stderr.contains("exactly one"),
        "duplicate GTO envelope case must be rejected: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// R1: a malformed/unreadable `--case` manifest case_id must fail closed and
/// must not silently skip GTO binding.
#[test]
fn malformed_case_manifest_id_rejected() {
    let dir = temp_dir("malformed_manifest");
    let (envelope, _manifest, snap_path, sha, size) = setup_positive(&dir);
    let good_gto_manifest = write_gto_manifest(&dir, &sha, size);
    // A malformed manifest (invalid JSON) as a `--case`.
    let bad_manifest = dir.join("bad_manifest.json");
    fs::write(&bad_manifest, b"NOT-JSON{{{{").unwrap();
    let mut triples = standard_triples(&dir, &good_gto_manifest, &snap_path);
    triples.push((
        bad_manifest,
        snap_path.clone(),
        dir.join("bad_candidate.exe"),
    ));
    let out = run_verifier_with_triples(&dir, &envelope, &triples);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    assert!(
        stderr.contains("unreadable/malformed case_id"),
        "a malformed --case manifest case_id must fail closed: {stderr}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// G3-R5-R1: a sealed logical-id directory that is a junction pointing OUTSIDE
/// the snapshot_root must be rejected by the independent acceptance verifier,
/// even though the actual input uses the same sealed path and hash/size/bytes
/// all match. Per-case identity_ok=false with a clear path-binding reason.
#[cfg(windows)]
#[test]
fn acceptance_junction_escape_of_logical_dir_identity_ok_false() {
    let dir = temp_dir("acc_junction_logical");
    let (envelope, manifest, snap_path, sha, _size) = setup_positive(&dir);
    let _ = manifest;
    // Move the real snapshot dir content into an OUTSIDE dir, then replace
    // <snapshot_root>/gto_launcher with a junction to outside/gto_launcher.
    let snap_root = dir.join("snapshots");
    let outside = dir.join("outside_real");
    let outside_gto = outside.join("gto_launcher");
    let sha_dir = outside_gto.join(&sha);
    std::fs::create_dir_all(&sha_dir).unwrap();
    // Copy the real snapshot into the outside structure.
    std::fs::copy(&snap_path, sha_dir.join("snapshot.bin")).unwrap();
    // Remove the real gto_launcher dir and junction it to outside/gto_launcher.
    std::fs::remove_dir_all(snap_root.join("gto_launcher")).unwrap();
    let mklink = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(snap_root.join("gto_launcher"))
        .arg(&outside_gto)
        .output()
        .expect("mklink must be invocable");
    assert!(
        mklink.status.success(),
        "junction creation failed: {}",
        String::from_utf8_lossy(&mklink.stderr)
    );
    // The sealed path (and the actual --case input) is the same snapshot path,
    // which now resolves through the junction to OUTSIDE the snapshot_root.
    let sealed = snap_root
        .join("gto_launcher")
        .join(&sha)
        .join("snapshot.bin");
    assert!(sealed.is_file(), "junction must expose the snapshot");

    // The original envelope's sealed protected_input_path already points at the
    // junctioned snapshot path; the manifest declares the real sha/size.
    let out = run_verifier(&dir, &envelope, &dir.join("gto_launcher.json"), &sealed);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    let report = read_report(&dir);
    let gto = gto_report_case(&report);
    assert_eq!(
        gto["identity_ok"].as_bool(),
        Some(false),
        "junction-escaped GTO case must be identity_ok=false: {gto}"
    );
    let reasons: Vec<&str> = gto["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons.iter().any(|r| r.contains("path")
            || r.contains("escape")
            || r.contains("failed disk verification")),
        "GTO case reasons must cite the path-binding failure: {gto}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// G3-R5-R1-R1: a snapshot_root that is ITSELF a junction (reparse alias) to a
/// directory holding a VALID snapshot tree must be rejected by the independent
/// acceptance verifier. Per-case identity_ok=false with a root-alias reason.
#[cfg(windows)]
#[test]
fn acceptance_root_junction_alias_to_valid_tree_identity_ok_false() {
    let dir = temp_dir("acc_root_junction");
    let (envelope, manifest, _snap_path, sha, _size) = setup_positive(&dir);
    let _ = manifest;
    // setup_positive created <dir>/snapshots/gto_launcher/<sha>/snapshot.bin.
    let snap_root = dir.join("snapshots");
    let physical = dir.join("physical_root");
    // Move the real snapshot tree under a physical dir.
    let physical_gto = physical.join("gto_launcher");
    let sha_dir = physical_gto.join(&sha);
    std::fs::create_dir_all(&sha_dir).unwrap();
    std::fs::copy(
        snap_root
            .join("gto_launcher")
            .join(&sha)
            .join("snapshot.bin"),
        sha_dir.join("snapshot.bin"),
    )
    .unwrap();
    // Replace the snapshot_root with a junction to the physical dir.
    std::fs::remove_dir_all(&snap_root).unwrap();
    let mklink = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&snap_root)
        .arg(&physical)
        .output()
        .expect("mklink must be invocable");
    assert!(
        mklink.status.success(),
        "junction creation failed: {}",
        String::from_utf8_lossy(&mklink.stderr)
    );
    let sealed = snap_root
        .join("gto_launcher")
        .join(&sha)
        .join("snapshot.bin");
    assert!(sealed.is_file(), "junction must expose the snapshot");

    let out = run_verifier(&dir, &envelope, &dir.join("gto_launcher.json"), &sealed);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    let report = read_report(&dir);
    let gto = gto_report_case(&report);
    assert_eq!(
        gto["identity_ok"].as_bool(),
        Some(false),
        "a root-junction-aliased GTO case must be identity_ok=false: {gto}"
    );
    let reasons: Vec<&str> = gto["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons.iter().any(|r| r.contains("path")
            || r.contains("root")
            || r.contains("reparse")
            || r.contains("junction")),
        "GTO case reasons must cite the root path-binding failure: {gto}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// G3-R5-R1-R1-R1: a GTO case present without `--snapshot-root` must fail
/// closed per-case (never guess the root).
#[test]
fn gto_present_without_snapshot_root_rejected() {
    let dir = temp_dir("gto_no_snapshot_root");
    let (envelope, _manifest, snap_path, _sha, _size) = setup_positive(&dir);
    let out = run_verifier_without_snapshot_root(
        &dir,
        &envelope,
        &dir.join("gto_launcher.json"),
        &snap_path,
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    let report = read_report(&dir);
    let gto = gto_report_case(&report);
    assert_eq!(
        gto["identity_ok"].as_bool(),
        Some(false),
        "GTO without --snapshot-root must be identity_ok=false: {gto}"
    );
    let reasons: Vec<&str> = gto["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("--snapshot-root") || r.contains("path")),
        "GTO reasons must cite the missing snapshot root: {gto}"
    );
    let _ = fs::remove_dir_all(&dir);
}

/// G3-R5-R1-R1-R1: an Oreans-only envelope WITHOUT `--snapshot-root` must still
/// run the legacy live-input verification (no GTO case -> no root required).
#[test]
fn oreans_only_without_snapshot_root_compatible() {
    let dir = temp_dir("oreans_no_snapshot_root");
    let envelope = oreans_only_envelope();
    let envelope_path = dir.join("runner-config-envelope.json");
    fs::write(
        &envelope_path,
        serde_json::to_vec_pretty(&envelope).unwrap(),
    )
    .unwrap();
    fs::write(dir.join("input_origin.bin"), b"ORIGIN-SYNTHETIC-INPUT").unwrap();
    fs::write(dir.join("input_lunlun.bin"), b"LUNLUN-SYNTHETIC-INPUT").unwrap();
    let cli = fake_cli_binary(&dir);
    let args = vec![
        "preflight".to_string(),
        "--envelope".to_string(),
        envelope_path.display().to_string(),
        "--output-dir".to_string(),
        dir.display().to_string(),
        "--cli-binary".to_string(),
        cli.display().to_string(),
        "--repo-root".to_string(),
        workspace_root().display().to_string(),
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
    let out = Command::new(acceptance_bin())
        .args(&arg_refs)
        .output()
        .expect("spawn acceptance binary");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Oreans-only runs the legacy live-input verification WITHOUT --snapshot-root;
    // overall NotReady is expected (synthetic files), but there is no config
    // error about a missing snapshot root.
    assert_eq!(out.status.code(), Some(2), "expected NotReady: {stderr}");
    assert!(
        !stderr.contains("--snapshot-root"),
        "Oreans-only must not require --snapshot-root: {stderr}"
    );
    let report = read_report(&dir);
    // Both Oreans cases present; neither is a GTO path-binding failure.
    assert!(
        report["cases"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["case_id"].as_str() != Some("gto_launcher")),
        "Oreans-only envelope has no GTO case"
    );
    let _ = fs::remove_dir_all(&dir);
}
