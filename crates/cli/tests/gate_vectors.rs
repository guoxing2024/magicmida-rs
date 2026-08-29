//! Cross-language canonical gate-vector parity test.
//!
//! Loads `gate_vectors.json` (workspace root) and asserts the Rust
//! `validate_generic_dump` produces exactly the same `pass`, `failures`, and
//! `warnings` declared by each vector.  The Python test
//! `tools/test_generic_gate.py` loads the **same** JSON file and asserts the
//! same — proving Rust/Python parity against a single shared vector set.

use mida_cli::unpacker::{validate_generic_dump, GenericGateInputs, GenericGateProfile};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Inputs {
    text_present: bool,
    text_has_raw: bool,
    text_looks_code: bool,
    large_rx_present: bool,
    large_rx_has_raw: bool,
    has_ahk_export: bool,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    inputs: Inputs,
    profile: String,
    expected_pass: bool,
    expected_failures: Vec<String>,
    expected_warnings: Vec<String>,
}

fn profile_from_str(s: &str) -> GenericGateProfile {
    match s {
        "packer-agnostic" => GenericGateProfile::PackerAgnostic,
        "ahk-launcher" => GenericGateProfile::AhkLauncher,
        other => panic!("unknown profile in vector: {other}"),
    }
}

fn load_vectors() -> Vec<Vector> {
    // CARGO_MANIFEST_DIR = .../crates/cli; vectors live at workspace root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = std::path::Path::new(manifest_dir).join("../../gate_vectors.json");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&data).unwrap_or_else(|e| panic!("invalid vectors JSON: {e}"))
}

#[test]
fn gate_vectors_match_rust_implementation() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "vectors file must not be empty");
    for v in &vectors {
        let inputs = GenericGateInputs {
            text_present: v.inputs.text_present,
            text_has_raw: v.inputs.text_has_raw,
            text_looks_code: v.inputs.text_looks_code,
            large_rx_present: v.inputs.large_rx_present,
            large_rx_has_raw: v.inputs.large_rx_has_raw,
            has_ahk_export: v.inputs.has_ahk_export,
            shell_sections_present: false,
        };
        let profile = profile_from_str(&v.profile);
        let r = validate_generic_dump(inputs, profile);
        assert_eq!(r.pass, v.expected_pass, "vector {} pass mismatch", v.name);
        let got_failures: Vec<&str> = r.failures.to_vec();
        let want_failures: Vec<&str> = v.expected_failures.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            got_failures, want_failures,
            "vector {} failures mismatch",
            v.name
        );
        let got_warnings: Vec<&str> = r.warnings.to_vec();
        let want_warnings: Vec<&str> = v.expected_warnings.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            got_warnings, want_warnings,
            "vector {} warnings mismatch",
            v.name
        );
    }
}
