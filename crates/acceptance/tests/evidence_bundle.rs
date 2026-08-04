//! Black-box evidence-bundle tests: synthetic producer -> bundle -> consumer.
//!
//! The "producer" here is a synthetic standalone function that emits JSON the
//! way `mida-cli` sidecars are written today. The consumer is
//! `mida_acceptance::validate_evidence_bundle`, which must not share any
//! producer types. These tests pin the wire contract so producer/consumer
//! schema drift fails here, offline, before any live run.

use std::collections::BTreeMap;

use mida_acceptance::{
    canonical_members_hash, sha256_hex, validate_evidence_bundle, BundleArtifactIdentity,
    BundleCompletionMarker, BundleMemberRef, OreansEvidenceBundle,
    OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION, REQUIRED_BUNDLE_MEMBERS,
    TRANSFORM_MANIFEST_SCHEMA_VERSION,
};

/// Stand-in for the CLI sidecar producer: emits a minimal-but-schema-valid
/// JSON document for one logical member, binding both identities.
fn producer_sidecar(
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

/// Stand-in for the acceptance `build_oreans_pe_evidence` writer.
fn producer_pe_evidence(candidate_sha: &str, candidate_size: u64) -> Vec<u8> {
    serde_json::json!({
        "schema_version": "mida.oreans-pe-evidence/v1",
        "candidate": { "sha256": candidate_sha, "size_bytes": candidate_size },
    })
    .to_string()
    .into_bytes()
}

/// Stand-in for the `mida-pe` transform-manifest writer.
fn producer_transform_manifest(candidate_sha: &str, candidate_size: u64) -> Vec<u8> {
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

const PROTECTED_SHA: &str = "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";
const PROTECTED_SIZE: u64 = 5_232_656;
const CANDIDATE_SIZE: u64 = 4096;

fn producer_run(candidate_sha: &str) -> (OreansEvidenceBundle, BTreeMap<String, Vec<u8>>) {
    let mut files = BTreeMap::new();
    let mut members = Vec::new();
    for (name, schema) in REQUIRED_BUNDLE_MEMBERS {
        let bytes = match name {
            "transform_manifest" => producer_transform_manifest(candidate_sha, CANDIDATE_SIZE),
            "pe_evidence" => producer_pe_evidence(candidate_sha, CANDIDATE_SIZE),
            _ => producer_sidecar(
                schema,
                PROTECTED_SHA,
                PROTECTED_SIZE,
                candidate_sha,
                CANDIDATE_SIZE,
            ),
        };
        files.insert(name.to_string(), bytes.clone());
        members.push(BundleMemberRef {
            name: name.to_string(),
            relative_path: format!("evidence/{name}.json"),
            sha256: sha256_hex(&bytes),
            size_bytes: bytes.len() as u64,
        });
    }
    let members_hash = canonical_members_hash(&members);
    let mut bundle = OreansEvidenceBundle {
        schema_version: OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
        case_id: "origin_macro".to_string(),
        tool_revision: "oreans/two-sample-mainline@<frozen-commit>".to_string(),
        runner_config_digest: "ab12".repeat(16),
        emitted_at: "2026-08-04T12:00:00Z".to_string(),
        completion_marker: BundleCompletionMarker::Complete,
        protected_input: BundleArtifactIdentity {
            sha256: PROTECTED_SHA.to_string(),
            size_bytes: PROTECTED_SIZE,
        },
        candidate: BundleArtifactIdentity {
            sha256: candidate_sha.to_string(),
            size_bytes: CANDIDATE_SIZE,
        },
        members_sha256: members_hash,
        manifest_sha256: String::new(),
        members,
    };
    bundle.manifest_sha256 = mida_acceptance::canonical_manifest_hash(&bundle);
    (bundle, files)
}

#[test]
fn producer_emitted_complete_bundle_passes_consumer() {
    let candidate_sha = sha256_hex(b"candidate-bytes");
    let (bundle, files) = producer_run(&candidate_sha);
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
    assert!(verdict.complete);
    assert!(verdict.reasons.is_empty());
}

#[test]
fn producer_dropping_one_sidecar_yields_invalid_run() {
    let candidate_sha = sha256_hex(b"candidate-bytes");
    let (mut bundle, mut files) = producer_run(&candidate_sha);
    files.remove("section_rebuild_evidence");
    bundle
        .members
        .retain(|m| m.name != "section_rebuild_evidence");
    bundle.members_sha256 = canonical_members_hash(&bundle.members);
    bundle.manifest_sha256 = mida_acceptance::canonical_manifest_hash(&bundle);
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(!verdict.valid);
    assert!(!verdict.complete);
}

#[test]
fn producer_swapping_ordinary_sidecar_identity_fails_even_with_recomputed_hashes() {
    let candidate_sha = sha256_hex(b"candidate-bytes");
    let (mut bundle, mut files) = producer_run(&candidate_sha);
    // The producer (or an attacker) swaps the candidate identity inside a
    // *normal* sidecar, then recomputes the member hash and both bundle
    // hashes so every checksum is internally consistent. The identity chain
    // must still reject the run.
    let swapped = producer_sidecar(
        "mida.oreans-iat-evidence/v1",
        PROTECTED_SHA,
        PROTECTED_SIZE,
        &"9".repeat(64),
        CANDIDATE_SIZE,
    );
    for member in &mut bundle.members {
        if member.name == "iat_evidence" {
            member.sha256 = sha256_hex(&swapped);
            member.size_bytes = swapped.len() as u64;
        }
    }
    files.insert("iat_evidence".to_string(), swapped);
    bundle.members_sha256 = canonical_members_hash(&bundle.members);
    bundle.manifest_sha256 = mida_acceptance::canonical_manifest_hash(&bundle);
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(!verdict.valid);
    assert!(
        verdict
            .reasons
            .iter()
            .any(|r| r.contains("iat_evidence candidate")),
        "reasons: {:?}",
        verdict.reasons
    );
}

#[test]
fn producer_emitting_stale_candidate_transform_fails_identity_chain() {
    let candidate_sha = sha256_hex(b"candidate-bytes");
    let (bundle, mut files) = producer_run(&candidate_sha);
    files.insert(
        "transform_manifest".to_string(),
        producer_transform_manifest(&"9".repeat(64), CANDIDATE_SIZE),
    );
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(!verdict.valid);
    assert!(verdict
        .reasons
        .iter()
        .any(|r| r.contains("transform_manifest binds candidate")));
}

#[test]
fn tampered_top_level_metadata_fails_manifest_hash() {
    let candidate_sha = sha256_hex(b"candidate-bytes");
    let (mut bundle, files) = producer_run(&candidate_sha);
    bundle.tool_revision = "oreans/two-sample-mainline@<other-commit>".to_string();
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(!verdict.valid);
    assert!(verdict
        .reasons
        .iter()
        .any(|r| r.contains("manifest_sha256 mismatch")));
}

#[test]
fn bundle_manifest_is_round_trip_stable() {
    let candidate_sha = sha256_hex(b"candidate-bytes");
    let (bundle, files) = producer_run(&candidate_sha);
    let json = serde_json::to_string(&bundle).expect("serialize");
    let parsed: OreansEvidenceBundle = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, bundle);
    let verdict = validate_evidence_bundle(&parsed, &files);
    assert!(verdict.valid, "reasons: {:?}", verdict.reasons);
}
