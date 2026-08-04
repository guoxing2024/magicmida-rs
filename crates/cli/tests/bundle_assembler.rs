//! Black-box tests for the atomic bundle assembler (producer) consumed by
//! `mida_acceptance::validate_evidence_bundle` (consumer).
//!
//! The assembler and the validator must not share any code; these tests prove
//! the wire contract (`mida.oreans-evidence-bundle/v2`) end to end:
//! - a complete assemble is accepted by the independent validator;
//! - missing members, duplicate names/paths, stale embedded identities,
//!   unknown members, malformed inputs and corrupt destinations all fail
//!   closed, and a failed assemble never leaves a bundle at the output path;
//! - a leftover `.tmp-*` file from an interrupted run is never a valid
//!   bundle and does not block the next assemble (restart recovery).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use mida_acceptance::{
    validate_evidence_bundle, BundleCompletionMarker, OreansEvidenceBundle,
    OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION,
};
use mida_cli::runner_preflight::RunEvidenceContext;
use mida_cli::unpacker::bundle_assembler::{
    assemble_evidence_bundle, AssembleRequest, EXPECTED_MEMBER_SCHEMAS,
    TRANSFORM_MANIFEST_SCHEMA_VERSION,
};
use sha2::{Digest, Sha256};

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "mida_bundle_test_{}_{}_{}",
        tag,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Build a synthetic run directory: protected input, candidate, and the
/// seven evidence files with correct schema ids and embedded identities.
struct RunDir {
    root: PathBuf,
    protected: PathBuf,
    candidate: PathBuf,
    members: Vec<(String, PathBuf)>,
    protected_sha: String,
    candidate_sha: String,
}

fn sidecar_json(
    schema: &str,
    protected_sha: &str,
    protected_size: u64,
    candidate_sha: &str,
    candidate_size: u64,
) -> Vec<u8> {
    serde_json::json!({
        "schema_version": schema,
        "protected_input": { "sha256": protected_sha, "size_bytes": protected_size },
        "candidate": { "sha256": candidate_sha, "size_bytes": candidate_size },
    })
    .to_string()
    .into_bytes()
}

fn pe_evidence_json(candidate_sha: &str, candidate_size: u64) -> Vec<u8> {
    serde_json::json!({
        "schema_version": "mida.oreans-pe-evidence/v1",
        "candidate": { "sha256": candidate_sha, "size_bytes": candidate_size },
    })
    .to_string()
    .into_bytes()
}

fn transform_manifest_json(candidate_sha: &str, candidate_size: u64) -> Vec<u8> {
    serde_json::json!({
        "schema_version": TRANSFORM_MANIFEST_SCHEMA_VERSION,
        "taxonomy_version": "mida.transform-taxonomy/v1",
        "candidate_sha256": candidate_sha,
        "candidate_size_bytes": candidate_size,
        "entries": [],
        "note": "synthetic bundle fixture",
    })
    .to_string()
    .into_bytes()
}

fn build_run_dir(tag: &str) -> RunDir {
    let root = temp_dir(tag);
    let protected = root.join("protected.bin");
    let candidate = root.join("candidate.exe");
    fs::write(&protected, b"PROTECTED-INPUT-BYTES-000").expect("write protected");
    fs::write(&candidate, b"CANDIDATE-BYTES-1234567890").expect("write candidate");
    let protected_sha = sha256_hex(&fs::read(&protected).unwrap());
    let candidate_sha = sha256_hex(&fs::read(&candidate).unwrap());
    let protected_size = fs::metadata(&protected).unwrap().len();
    let candidate_size = fs::metadata(&candidate).unwrap().len();

    let mut members = Vec::new();
    for (name, schema) in EXPECTED_MEMBER_SCHEMAS {
        let bytes = match name {
            "transform_manifest" => transform_manifest_json(&candidate_sha, candidate_size),
            "pe_evidence" => pe_evidence_json(&candidate_sha, candidate_size),
            _ => sidecar_json(
                schema,
                &protected_sha,
                protected_size,
                &candidate_sha,
                candidate_size,
            ),
        };
        let path = root.join(format!("{name}.json"));
        fs::write(&path, bytes).expect("write sidecar");
        members.push((name.to_string(), path));
    }
    RunDir {
        root,
        protected,
        candidate,
        members,
        protected_sha,
        candidate_sha,
    }
}

/// The attested evidence context the assembler draws case id, tool revision
/// and the runner-config digest from (never caller-supplied, single-use).
fn context(run: &RunDir) -> RunEvidenceContext {
    RunEvidenceContext::new(
        "origin_macro".to_string(),
        "oreans/two-sample-mainline@test".to_string(),
        "ab12".repeat(16),
        run.protected.clone(),
        run.candidate.clone(),
        "cd34".repeat(16),
    )
    .expect("build evidence context")
}

fn request(run: &RunDir, output: &Path) -> AssembleRequest {
    AssembleRequest {
        emitted_at: "2026-08-04T12:00:00Z".to_string(),
        protected_input: run.protected.clone(),
        candidate: run.candidate.clone(),
        members: run.members.clone(),
        output: output.to_path_buf(),
    }
}

fn read_bundle(path: &Path) -> OreansEvidenceBundle {
    let json = fs::read_to_string(path).expect("read bundle manifest");
    serde_json::from_str(&json).expect("parse bundle manifest")
}

fn files_map(run: &RunDir) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    for (name, path) in &run.members {
        files.insert(name.clone(), fs::read(path).expect("read member"));
    }
    files
}

#[test]
fn assembled_bundle_is_accepted_by_independent_validator() {
    let run = build_run_dir("happy");
    let output = run.root.join("evidence.bundle.json");
    let written =
        assemble_evidence_bundle(&request(&run, &output), &mut context(&run)).expect("assemble");
    assert_eq!(written, output);
    assert!(output.is_file());

    let bundle = read_bundle(&output);
    assert_eq!(bundle.schema_version, OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION);
    assert_eq!(bundle.completion_marker, BundleCompletionMarker::Complete);

    let files = files_map(&run);
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
    assert!(verdict.complete);

    // No leftover temp files after a successful assemble.
    let leftovers: Vec<_> = fs::read_dir(&run.root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
        .collect();
    assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
}

#[test]
fn missing_member_fails_closed_and_writes_nothing() {
    let run = build_run_dir("missing");
    let output = run.root.join("evidence.bundle.json");
    let mut req = request(&run, &output);
    req.members.retain(|(name, _)| name != "tls_evidence");
    let err =
        assemble_evidence_bundle(&req, &mut context(&run)).expect_err("missing member must fail");
    assert!(err.to_string().contains("member set mismatch"));
    assert!(!output.exists(), "no bundle may be written on failure");
}

#[test]
fn duplicate_member_path_fails_closed() {
    let run = build_run_dir("dup_path");
    let output = run.root.join("evidence.bundle.json");
    let mut req = request(&run, &output);
    req.members
        .push(("oep_evidence".to_string(), run.members[0].1.clone()));
    let err =
        assemble_evidence_bundle(&req, &mut context(&run)).expect_err("duplicate name must fail");
    assert!(err.to_string().contains("duplicate member name"));
}

#[test]
fn alias_member_path_fails_closed() {
    let run = build_run_dir("alias");
    let output = run.root.join("evidence.bundle.json");
    // Two different member names resolving to the same file via a hard link
    // must be rejected.
    let alias = run.root.join("alias_of_iat.json");
    fs::hard_link(&run.members[1].1, &alias).expect("hard link");
    let mut req = request(&run, &output);
    for (name, path) in &mut req.members {
        if name == "tls_evidence" {
            *path = alias.clone();
        }
    }
    let err = assemble_evidence_bundle(&req, &mut context(&run))
        .expect_err("alias member path must fail");
    assert!(err.to_string().contains("same file"));
}

#[test]
fn stale_embedded_candidate_identity_fails_closed() {
    let run = build_run_dir("stale_cand");
    let output = run.root.join("evidence.bundle.json");
    // Rewrite one sidecar to embed a different candidate identity.
    let (_, path) = &run.members[1]; // iat_evidence
    let stale = sidecar_json(
        "mida.oreans-iat-evidence/v1",
        &run.protected_sha,
        fs::metadata(&run.protected).unwrap().len(),
        &"9".repeat(64),
        fs::metadata(&run.candidate).unwrap().len(),
    );
    fs::write(path, stale).expect("rewrite sidecar");
    let err = assemble_evidence_bundle(&request(&run, &output), &mut context(&run))
        .expect_err("stale candidate identity must fail");
    assert!(err.to_string().contains("embeds candidate"));
    assert!(!output.exists());
}

#[test]
fn stale_embedded_protected_identity_fails_closed() {
    let run = build_run_dir("stale_prot");
    let output = run.root.join("evidence.bundle.json");
    let (_, path) = &run.members[2]; // tls_evidence
    let stale = sidecar_json(
        "mida.oreans-tls-evidence/v1",
        &"d".repeat(64),
        1234,
        &run.candidate_sha,
        fs::metadata(&run.candidate).unwrap().len(),
    );
    fs::write(path, stale).expect("rewrite sidecar");
    let err = assemble_evidence_bundle(&request(&run, &output), &mut context(&run))
        .expect_err("stale protected identity must fail");
    assert!(err.to_string().contains("embeds protected_input"));
    assert!(!output.exists());
}

#[test]
fn schema_drift_in_member_fails_closed() {
    let run = build_run_dir("schema_drift");
    let output = run.root.join("evidence.bundle.json");
    let (_, path) = &run.members[3]; // relocation_evidence
    let drifted = sidecar_json(
        "mida.oreans-relocation-evidence/v2",
        &run.protected_sha,
        fs::metadata(&run.protected).unwrap().len(),
        &run.candidate_sha,
        fs::metadata(&run.candidate).unwrap().len(),
    );
    fs::write(path, drifted).expect("rewrite sidecar");
    let err = assemble_evidence_bundle(&request(&run, &output), &mut context(&run))
        .expect_err("schema drift must fail");
    assert!(err.to_string().contains("schema_version"));
    assert!(!output.exists());
}

#[test]
fn malformed_runner_digest_and_fields_fail_closed() {
    let run = build_run_dir("bad_fields");
    let output = run.root.join("evidence.bundle.json");
    // The digest is never caller-supplied: a malformed digest is rejected at
    // RunEvidenceContext construction (the only path into the assembler).
    assert!(
        RunEvidenceContext::new(
            "origin_macro".to_string(),
            "rev".to_string(),
            "not-hex".to_string(),
            run.protected.clone(),
            run.candidate.clone(),
            "cd34".repeat(16),
        )
        .is_err(),
        "malformed digest must be rejected at context construction"
    );
    // A case id with a canonical-hash separator is rejected by the assembler.
    let mut bad = context(&run);
    bad.case_id = "origin_macro|evil".to_string();
    let err = assemble_evidence_bundle(&request(&run, &output), &mut bad)
        .expect_err("separator must fail");
    assert!(
        err.to_string().contains("case_id"),
        "unexpected error: {err:?}"
    );
    assert!(!output.exists());
}

/// P6.3-D (#13): the bundle's runner-config digest must equal the attested
/// launch-attestation digest carried by the single-use evidence context.
#[test]
fn bundle_digest_equals_attested_context_digest() {
    let run = build_run_dir("digest_chain");
    let output = run.root.join("evidence.bundle.json");
    let mut ctx = context(&run);
    let expected_digest = ctx.digest().to_string();
    let written = assemble_evidence_bundle(&request(&run, &output), &mut ctx).expect("assemble");
    let bundle = read_bundle(&written);
    assert_eq!(
        bundle.runner_config_digest, expected_digest,
        "bundle digest must equal the launch attestation digest"
    );
    assert_eq!(bundle.case_id, "origin_macro");
    assert_eq!(bundle.tool_revision, "oreans/two-sample-mainline@test");
    let verdict = validate_evidence_bundle(&bundle, &files_map(&run));
    assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
}

/// P6.3-D (#14): the attested context is a one-time authorization — a
/// second assemble with the same context must fail closed.
#[test]
fn attested_context_is_single_use() {
    let run = build_run_dir("single_use");
    let output = run.root.join("evidence.bundle.json");
    let mut ctx = context(&run);
    assemble_evidence_bundle(&request(&run, &output), &mut ctx).expect("first assemble");
    let second = run.root.join("evidence.bundle.again.json");
    let err = assemble_evidence_bundle(&request(&run, &second), &mut ctx)
        .expect_err("second assemble must be refused");
    assert!(
        err.to_string().contains("already consumed"),
        "unexpected error: {err:?}"
    );
    assert!(
        !second.exists(),
        "a consumed authorization must not produce a second bundle"
    );
}

#[test]
fn restart_recovers_over_corrupt_destination_and_stale_temp() {
    let run = build_run_dir("restart");
    let output = run.root.join("evidence.bundle.json");
    // Simulate an interrupted previous run: corrupt destination + stale temp.
    fs::write(&output, b"{ broken json ").expect("corrupt destination");
    let stale_temp = run.root.join(".evidence.bundle.json.tmp-999-0");
    fs::write(&stale_temp, b"partial garbage").expect("stale temp");

    // The stale temp must not be a valid bundle on its own.
    let parsed: Result<OreansEvidenceBundle, _> =
        serde_json::from_slice(&fs::read(&stale_temp).unwrap());
    assert!(parsed.is_err(), "leftover temp is never a valid bundle");

    // The next assemble replaces the corrupt destination atomically.
    assemble_evidence_bundle(&request(&run, &output), &mut context(&run))
        .expect("restart assemble");
    let bundle = read_bundle(&output);
    let verdict = validate_evidence_bundle(&bundle, &files_map(&run));
    assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
}
