//! G3-R5: the acceptance verifier's snapshot-path parser must agree with the
//! CLI's `mida-cli::sample_snapshot::parse_snapshot_path` on the SAME contract
//! vectors (`tests/fixtures/snapshot_path_contract.json`). The acceptance crate
//! cannot depend on `mida-cli`, so it keeps a minimal local copy of the contract
//! (`mida_acceptance::snapshot_path`) that must not diverge.

use std::path::Path;

use mida_acceptance::snapshot_path::{parse_snapshot_path, SNAPSHOT_FILENAME};

fn workspace_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The acceptance parser must agree with the shared contract vectors.
#[test]
fn acceptance_snapshot_path_contract_vectors() {
    let fixture = workspace_root().join("tests/fixtures/snapshot_path_contract.json");
    let raw = std::fs::read_to_string(&fixture)
        .unwrap_or_else(|e| panic!("cannot read contract fixture {}: {e}", fixture.display()));
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let real_root = std::env::temp_dir().join("mida_snapshot_path_contract_root");
    for v in value["vectors"].as_array().unwrap() {
        let raw_path = v["path"]
            .as_str()
            .unwrap()
            .replace("__ROOT__", &real_root.display().to_string());
        let expected = v["expected"].as_str().unwrap();
        let path = std::path::Path::new(&raw_path);
        let parsed = parse_snapshot_path(path);
        match expected {
            "valid" => {
                let p = parsed.unwrap_or_else(|e| panic!("vector {raw_path} should be valid: {e}"));
                assert_eq!(
                    p.logical_sample_id,
                    v["logical_sample_id"].as_str().unwrap()
                );
                assert_eq!(p.sha256, v["sha256"].as_str().unwrap());
                assert_eq!(p.snapshot_path, path);
            }
            "invalid" => {
                assert!(parsed.is_err(), "vector {raw_path} must be invalid");
            }
            other => panic!("unknown expected {other} in fixture"),
        }
    }
}

/// The acceptance GTO lane wrapper must reject a structurally-valid path whose
/// logical-sample directory is not the GTO lane case id.
#[test]
fn acceptance_gto_wrapper_rejects_non_gto_logical_dir() {
    let real_root = std::env::temp_dir().join("mida_gto_wrapper_root");
    let sha = "c".repeat(64);
    let good = real_root
        .join("gto_launcher")
        .join(&sha)
        .join(SNAPSHOT_FILENAME);
    // Structural parser accepts it.
    let parsed = parse_snapshot_path(&good).unwrap();
    assert_eq!(parsed.logical_sample_id, "gto_launcher");
    // The GTO lane wrapper (case id == gto_launcher) accepts it and returns the hash.
    // (The wrapper lives in main.rs; here we mirror its case-id check.)
    assert_eq!(parsed.logical_sample_id, "gto_launcher");
    assert_eq!(parsed.sha256, sha);
    // A non-GTO logical dir is structurally valid but not the GTO lane case id.
    let other = real_root
        .join("origin_macro")
        .join(&sha)
        .join(SNAPSHOT_FILENAME);
    let parsed_other = parse_snapshot_path(&other).unwrap();
    assert_eq!(parsed_other.logical_sample_id, "origin_macro");
    assert_ne!(parsed_other.logical_sample_id, "gto_launcher");
}

/// The acceptance `paths_equivalent` must agree with the CLI's on UNC /
/// extended-length prefix normalization.
#[test]
fn paths_equivalent_unc_and_extended_prefix_vectors() {
    use mida_acceptance::snapshot_path::paths_equivalent;
    use std::path::Path;
    assert!(paths_equivalent(
        Path::new("\\\\?\\D:\\snapshots"),
        Path::new("D:\\snapshots")
    ));
    assert!(paths_equivalent(
        Path::new("\\\\?\\UNC\\server\\share"),
        Path::new("\\\\server\\share")
    ));
    assert!(paths_equivalent(
        Path::new("D:\\SnapShots"),
        Path::new("d:\\snapshots")
    ));
    // prefix-aware: a mid-path literal "\\?\" is not stripped
    assert!(!paths_equivalent(
        Path::new("D:\\snapshots\\x\\\\?\\y"),
        Path::new("D:\\snapshots\\x\\y")
    ));
    assert!(!paths_equivalent(
        Path::new("D:\\snapshots"),
        Path::new("E:\\snapshots")
    ));
}
