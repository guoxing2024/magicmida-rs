//! Black-box evidence-bundle tests: synthetic producer -> bundle -> consumer.
//!
//! The "producer" here is a synthetic standalone function that emits JSON the
//! way `mida-cli` sidecars are written today. The consumer is
//! `mida_acceptance::validate_evidence_bundle`, which must not share any
//! producer types. These tests pin the wire contract so producer/consumer
//! schema drift fails here, offline, before any live run.

use std::collections::BTreeMap;

use mida_acceptance::{
    canonical_bundle_hash, sha256_hex, validate_evidence_bundle, BundleArtifactIdentity,
    BundleCompletionMarker, BundleMemberRef, OreansEvidenceBundle,
    OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION, REQUIRED_BUNDLE_MEMBERS,
    TRANSFORM_MANIFEST_SCHEMA_VERSION,
};

/// Stand-in for the CLI sidecar producer: emits a minimal-but-schema-valid
/// JSON document for one logical member.
fn producer_sidecar(schema: &str, candidate_sha: &str) -> Vec<u8> {
    serde_json::json!({
        "schema_version": schema,
        "candidate_sha256": candidate_sha,
        "candidate_size_bytes": 4096,
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

fn producer_run(candidate_sha: &str) -> (OreansEvidenceBundle, BTreeMap<String, Vec<u8>>) {
    let mut files = BTreeMap::new();
    let mut members = Vec::new();
    for (name, schema) in REQUIRED_BUNDLE_MEMBERS {
        let bytes = if name == "transform_manifest" {
            producer_transform_manifest(candidate_sha, 4096)
        } else {
            producer_sidecar(schema, candidate_sha)
        };
        files.insert(name.to_string(), bytes.clone());
        members.push(BundleMemberRef {
            name: name.to_string(),
            relative_path: format!("{name}.json"),
            sha256: sha256_hex(&bytes),
            size_bytes: bytes.len() as u64,
        });
    }
    let bundle = OreansEvidenceBundle {
        schema_version: OREANS_EVIDENCE_BUNDLE_SCHEMA_VERSION.to_string(),
        case_id: "origin_macro".to_string(),
        tool_revision: "oreans/two-sample-mainline@<frozen-commit>".to_string(),
        runner_config_digest: "ab12".repeat(16),
        emitted_at: "2026-08-04T12:00:00Z".to_string(),
        completion_marker: BundleCompletionMarker::Complete,
        protected_input: BundleArtifactIdentity {
            sha256: "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7".to_string(),
            size_bytes: 5_232_656,
        },
        candidate: BundleArtifactIdentity {
            sha256: candidate_sha.to_string(),
            size_bytes: 4096,
        },
        bundle_sha256: canonical_bundle_hash(&members),
        members,
    };
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
    bundle.bundle_sha256 = canonical_bundle_hash(&bundle.members);
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(!verdict.valid);
    assert!(!verdict.complete);
}

#[test]
fn producer_emitting_stale_candidate_sidecar_fails_identity_chain() {
    let candidate_sha = sha256_hex(b"candidate-bytes");
    let (bundle, mut files) = producer_run(&candidate_sha);
    // One sidecar was written for an older candidate digest; the bundle
    // hash covers the new bytes, but the transform manifest now disagrees
    // with the declared candidate identity.
    files.insert(
        "transform_manifest".to_string(),
        producer_transform_manifest(&"9".repeat(64), 4096),
    );
    let verdict = validate_evidence_bundle(&bundle, &files);
    assert!(!verdict.valid);
    assert!(verdict
        .reasons
        .iter()
        .any(|r| r.contains("transform_manifest binds candidate")));
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
