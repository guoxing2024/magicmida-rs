//! Runner-side digest producer vs. independent acceptance verifier (P6.1).
//!
//! The runner side (`mida-core::runner_config`, consumed by `mida-cli` in
//! production) and the acceptance verifier (`mida_acceptance::RunnerConfig`,
//! a dependency-free mirror in `mida-acceptance`) implement the canonical
//! length-prefixed encoding independently. This cross-check proves both
//! implementations agree on the same JSON config, including adversarial
//! values (commas/newlines/colons in list elements and scalars).

use serde_json::json;

fn config_json(features: &[&str], oep_policy: &str, env: &[&str]) -> serde_json::Value {
    json!({
        "tool_revision": "oreans/two-sample-mainline@frozen",
        "cli_binary_sha256": "a".repeat(64),
        "features": features,
        "debugger_backend": "windows_debug_api",
        "oep_policy": oep_policy,
        "container_restore": "off",
        "shrink": true,
        "data_sections": true,
        "pure_rebuild": false,
        "capture_policy_digest": "",
        "iat_fix_strategy": "v3-trace",
        "timeout_secs": 120,
        "isolation": {
            "workspace_policy": "isolated-temp",
            "process_tree_policy": "single-process",
            "network_policy": "blocked"
        },
        "attempt_numbering": "continuous-1-based",
        "evidence_bundle_schema": "mida.oreans-evidence-bundle/v2",
        "gate_schema": "mida.oreans-two-sample-gate/v8",
        "env_allowlist": env,
    })
}

/// Family-less legacy JSON must parse identically on both sides (Oreans
/// default) and a family-less config must produce a DIFFERENT digest from the
/// same config carrying the GTO family — on both the producer and the verifier.
#[test]
fn gto_and_oreans_digests_differ_on_both_sides() {
    let legacy = config_json(&["default"], "captured", &["CARGO_TARGET_DIR"]);
    let legacy_json = serde_json::to_string(&legacy).unwrap();
    let r_legacy: mida_core::runner_config::RunnerConfig =
        serde_json::from_str(&legacy_json).expect("family-less parses on runner side");
    let v_legacy: mida_acceptance::RunnerConfig =
        serde_json::from_str(&legacy_json).expect("family-less parses on verifier side");
    assert_eq!(r_legacy.packer_family, "oreans_themida");
    assert_eq!(v_legacy.packer_family, "oreans_themida");

    // Explicit GTO family (same everything else) must change the digest on BOTH
    // independent implementations — the frozen GTO policy never equals the
    // frozen Oreans policy.
    let mut gto = config_json(&["default"], "captured", &["CARGO_TARGET_DIR"]);
    gto["packer_family"] = json!("ahk_gto");
    let gto_json = serde_json::to_string(&gto).unwrap();
    let r_gto: mida_core::runner_config::RunnerConfig =
        serde_json::from_str(&gto_json).expect("GTO parses on runner side");
    let v_gto: mida_acceptance::RunnerConfig =
        serde_json::from_str(&gto_json).expect("GTO parses on verifier side");
    assert_eq!(r_gto.packer_family, "ahk_gto");

    // Producer and verifier agree on each digest...
    assert_eq!(
        mida_core::runner_config::runner_config_digest(&r_legacy),
        mida_acceptance::runner_config_digest(&v_legacy)
    );
    assert_eq!(
        mida_core::runner_config::runner_config_digest(&r_gto),
        mida_acceptance::runner_config_digest(&v_gto)
    );
    // ...and Oreans vs GTO differ on both sides.
    assert_ne!(
        mida_core::runner_config::runner_config_digest(&r_legacy),
        mida_core::runner_config::runner_config_digest(&r_gto)
    );
    assert_ne!(
        mida_acceptance::runner_config_digest(&v_legacy),
        mida_acceptance::runner_config_digest(&v_gto)
    );
}

/// Both implementations must produce the identical canonical digest for the
/// same emitted JSON config.
#[test]
fn runner_producer_and_acceptance_verifier_agree() {
    for value in [
        config_json(&["default"], "captured", &["CARGO_TARGET_DIR"]),
        config_json(&["a,b"], "captured", &["CARGO_TARGET_DIR"]),
        config_json(&["a", "b"], "captured", &["CARGO_TARGET_DIR"]),
        config_json(&["a\nb"], "captured", &["CARGO_TARGET_DIR"]),
        config_json(&["default"], "x\ny", &["A", "B"]),
    ] {
        let json = serde_json::to_string(&value).unwrap();
        let runner_config: mida_core::runner_config::RunnerConfig =
            serde_json::from_str(&json).expect("strict parse on runner side");
        let verifier_config: mida_acceptance::RunnerConfig =
            serde_json::from_str(&json).expect("strict parse on verifier side");
        let producer_digest = mida_core::runner_config::runner_config_digest(&runner_config);
        let verifier_digest = mida_acceptance::runner_config_digest(&verifier_config);
        assert_eq!(
            producer_digest, verifier_digest,
            "digests must agree for config {json}"
        );
        assert_eq!(producer_digest.len(), 64);
        assert!(producer_digest.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

/// Both sides must canonicalize lists identically (order-insensitive) and
/// both must reject unknown fields.
#[test]
fn runner_producer_and_acceptance_verifier_canonicalize_identically() {
    let a = config_json(&["gto", "default"], "captured", &["PATH", "TMP"]);
    let b = config_json(&["default", "gto"], "captured", &["TMP", "PATH"]);
    let json_a = serde_json::to_string(&a).unwrap();
    let json_b = serde_json::to_string(&b).unwrap();
    let r_a: mida_core::runner_config::RunnerConfig = serde_json::from_str(&json_a).unwrap();
    let r_b: mida_core::runner_config::RunnerConfig = serde_json::from_str(&json_b).unwrap();
    let v_a: mida_acceptance::RunnerConfig = serde_json::from_str(&json_a).unwrap();
    let v_b: mida_acceptance::RunnerConfig = serde_json::from_str(&json_b).unwrap();
    assert_eq!(
        mida_core::runner_config::runner_config_digest(&r_a),
        mida_core::runner_config::runner_config_digest(&r_b),
        "runner side canonicalizes list order"
    );
    assert_eq!(
        mida_acceptance::runner_config_digest(&v_a),
        mida_acceptance::runner_config_digest(&v_b),
        "verifier side canonicalizes list order"
    );

    let mut sneaky = config_json(&["default"], "captured", &["PATH"]);
    sneaky["sneaky_extra"] = json!(1);
    let bad = serde_json::to_string(&sneaky).unwrap();
    assert!(serde_json::from_str::<mida_core::runner_config::RunnerConfig>(&bad).is_err());
    assert!(serde_json::from_str::<mida_acceptance::RunnerConfig>(&bad).is_err());
}
