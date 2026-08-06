//! Canonical runner configuration and its digest (P6-B producer).
//!
//! This module lives in `mida-core` so that the runner side (`mida-cli`,
//! production dependency) and the independent acceptance verifier share the
//! single canonical encoding. The acceptance crate only *verifies* digests
//! (recomputed from the JSON the runner emits, cross-checked against the
//! report), it no longer owns the producer.
//!
//! Encoding contract (length-prefixed, injective):
//!
//! - Every scalar field renders as `name=len:value` where `len` is the
//!   decimal ASCII byte length of `value`; fields are separated by `\n` in a
//!   fixed order.
//! - Every list field renders as `name=count:len:elem...` where `count` is
//!   the element count and each element is `len:elem`; elements are sorted
//!   before encoding.
//! - Booleans render `true`/`false`, integers as decimal ASCII.
//!
//! Because every segment is delimited by its own byte length, values may
//! contain commas, newlines, colons or any other byte without ever colliding
//! with another configuration (`["a,b"]` != `["a","b"]`,
//! `["a\nb"]` != `["a","b"]`).
//!
//! The type is `deny_unknown_fields` + all fields required: unknown or
//! missing fields fail closed at deserialization. No timestamps or random
//! identifiers exist in the type, so the digest is stable across runs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical packer-family identity used by the runner config. Distinct
/// families route to distinct evidence contracts and never share a digest.
pub mod packer_family {
    /// Oreans/Themida family — routes to `mida.oreans-evidence-bundle/v2` and
    /// the `mida.oreans-two-sample-gate/v8` consumer.
    pub const OREANS: &str = "oreans_themida";
    /// AHK/GTO family — routes to the generic `mida.unpack-evidence-bundle/v1`
    /// contract. Its products must never be disguised as Oreans evidence.
    pub const AHK_GTO: &str = "ahk_gto";
}

/// Default family for a family-less (legacy) runner config. Kept as the
/// Oreans family so that pre-family wire JSON and old no-family policy
/// builders continue to parse and behave exactly as before (Oreans-compat
/// wrapper). GTO runs must set [`packer_family::AHK_GTO`] explicitly.
pub fn default_packer_family() -> String {
    packer_family::OREANS.to_string()
}

/// Canonical runner configuration. `deny_unknown_fields` + required fields
/// fail closed on drift; no timestamps or random identifiers exist in the
/// type, so the digest is stable across runs.
///
/// `packer_family` carries the identity of the packer family a run belongs to
/// ([`packer_family::OREANS`] / [`packer_family::AHK_GTO`]). It defaults to
/// Oreans for backward compatibility (family-less wire JSON parses as Oreans),
/// so the old Oreans API is preserved unchanged; GTO configs set it explicitly
/// and therefore produce a different runner digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    /// Packer family (see [`packer_family`]). Defaults to Oreans for
    /// backward compatibility; GTO must set it explicitly.
    #[serde(default = "default_packer_family")]
    pub packer_family: String,
    pub tool_revision: String,
    /// SHA-256 of the CLI binary that performs the run.
    pub cli_binary_sha256: String,
    /// Enabled feature set (canonical order applied at digest time).
    pub features: Vec<String>,
    /// Debugger backend identifier, e.g. "windows_debug_api".
    pub debugger_backend: String,
    pub oep_policy: String,
    pub container_restore: String,
    pub shrink: bool,
    pub data_sections: bool,
    pub pure_rebuild: bool,
    /// 64-hex digest of the capture policy, or empty when none is used.
    pub capture_policy_digest: String,
    pub iat_fix_strategy: String,
    pub timeout_secs: u64,
    pub isolation: IsolationConfig,
    /// Attempt numbering policy, e.g. "continuous-1-based".
    pub attempt_numbering: String,
    pub evidence_bundle_schema: String,
    pub gate_schema: String,
    /// Environment variable names the runner may inherit (canonical order).
    pub env_allowlist: Vec<String>,
}

/// Isolation parameters (names/policies only — no machine paths).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IsolationConfig {
    pub workspace_policy: String,
    pub process_tree_policy: String,
    pub network_policy: String,
}

fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

impl RunnerConfig {
    /// Validate shapes (digests, non-empty identifiers). Returns the first
    /// reason or `None` when valid.
    pub fn validate(&self) -> Option<String> {
        if self.packer_family.trim().is_empty() {
            return Some("packer_family must be non-empty".to_string());
        }
        if self.tool_revision.trim().is_empty() {
            return Some("tool_revision must be non-empty".to_string());
        }
        if !is_64_hex(&self.cli_binary_sha256) {
            return Some("cli_binary_sha256 must be exactly 64 hex chars".to_string());
        }
        if !self.capture_policy_digest.is_empty() && !is_64_hex(&self.capture_policy_digest) {
            return Some("capture_policy_digest must be empty or 64 hex chars".to_string());
        }
        if self.oep_policy.trim().is_empty()
            || self.debugger_backend.trim().is_empty()
            || self.attempt_numbering.trim().is_empty()
            || self.evidence_bundle_schema.trim().is_empty()
            || self.gate_schema.trim().is_empty()
        {
            return Some("runner config identifiers must be non-empty".to_string());
        }
        None
    }
}

fn push_scalar(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push('=');
    out.push_str(&value.len().to_string());
    out.push(':');
    out.push_str(value);
    out.push('\n');
}

fn push_list(out: &mut String, name: &str, elements: &mut Vec<String>) {
    elements.sort();
    out.push_str(name);
    out.push('=');
    out.push_str(&elements.len().to_string());
    out.push(':');
    for element in elements.iter() {
        out.push_str(&element.len().to_string());
        out.push(':');
        out.push_str(element);
    }
    out.push('\n');
}

/// Canonical, injective serialization of the runner config.
///
/// Length-prefixed segments make the encoding collision-free for arbitrary
/// value bytes (commas, newlines, colons). Lists are sorted; booleans render
/// `true`/`false`; no whitespace variance can change the digest. Producer and
/// verifier share this form via `mida-core`.
pub fn canonical_runner_config(config: &RunnerConfig) -> String {
    let mut out = String::new();
    push_scalar(&mut out, "packer_family", &config.packer_family);
    push_scalar(&mut out, "tool_revision", &config.tool_revision);
    push_scalar(
        &mut out,
        "cli_binary_sha256",
        &config.cli_binary_sha256.to_lowercase(),
    );
    push_list(&mut out, "features", &mut config.features.clone());
    push_scalar(&mut out, "debugger_backend", &config.debugger_backend);
    push_scalar(&mut out, "oep_policy", &config.oep_policy);
    push_scalar(&mut out, "container_restore", &config.container_restore);
    push_scalar(&mut out, "shrink", &config.shrink.to_string());
    push_scalar(&mut out, "data_sections", &config.data_sections.to_string());
    push_scalar(&mut out, "pure_rebuild", &config.pure_rebuild.to_string());
    push_scalar(
        &mut out,
        "capture_policy_digest",
        &config.capture_policy_digest.to_lowercase(),
    );
    push_scalar(&mut out, "iat_fix_strategy", &config.iat_fix_strategy);
    push_scalar(&mut out, "timeout_secs", &config.timeout_secs.to_string());
    push_scalar(
        &mut out,
        "isolation.workspace_policy",
        &config.isolation.workspace_policy,
    );
    push_scalar(
        &mut out,
        "isolation.process_tree_policy",
        &config.isolation.process_tree_policy,
    );
    push_scalar(
        &mut out,
        "isolation.network_policy",
        &config.isolation.network_policy,
    );
    push_scalar(&mut out, "attempt_numbering", &config.attempt_numbering);
    push_scalar(
        &mut out,
        "evidence_bundle_schema",
        &config.evidence_bundle_schema,
    );
    push_scalar(&mut out, "gate_schema", &config.gate_schema);
    push_list(&mut out, "env_allowlist", &mut config.env_allowlist.clone());
    out
}

/// SHA-256 digest of the canonical runner config (64 lowercase hex chars).
pub fn runner_config_digest(config: &RunnerConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update(canonical_runner_config(config).as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample_runner_config() -> RunnerConfig {
        RunnerConfig {
            packer_family: packer_family::OREANS.to_string(),
            tool_revision: "oreans/two-sample-mainline@frozen".to_string(),
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

    #[test]
    fn runner_digest_is_stable_and_encoding_canonical() {
        let a = sample_runner_config();
        let b = sample_runner_config();
        assert_eq!(runner_config_digest(&a), runner_config_digest(&b));
        assert_eq!(canonical_runner_config(&a), canonical_runner_config(&b));
        assert_eq!(runner_config_digest(&a).len(), 64);
        assert!(
            runner_config_digest(&a)
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "digest must be hex"
        );
    }

    #[test]
    fn runner_digest_changes_with_any_valid_field() {
        let base = sample_runner_config();
        let d0 = runner_config_digest(&base);
        let mut c = base.clone();
        c.timeout_secs += 1;
        assert_ne!(d0, runner_config_digest(&c), "timeout must change digest");
        let mut c = base.clone();
        c.shrink = !c.shrink;
        assert_ne!(d0, runner_config_digest(&c), "shrink must change digest");
        let mut c = base.clone();
        c.features.push("gto-product-recovery".to_string());
        assert_ne!(d0, runner_config_digest(&c), "features must change digest");
        let mut c = base.clone();
        c.env_allowlist.push("PATH".to_string());
        assert_ne!(
            d0,
            runner_config_digest(&c),
            "env allowlist must change digest"
        );
        // List order must not matter (canonical sort).
        let mut c = base.clone();
        c.features.reverse();
        assert_eq!(d0, runner_config_digest(&c), "list order is canonicalized");
    }

    #[test]
    fn runner_digest_is_injective_against_separator_collisions() {
        // Comma collision: ["a,b"] must never canonicalize like ["a","b"].
        let mut with_comma = sample_runner_config();
        with_comma.features = vec!["a,b".to_string()];
        let mut split = sample_runner_config();
        split.features = vec!["a".to_string(), "b".to_string()];
        assert_ne!(
            canonical_runner_config(&with_comma),
            canonical_runner_config(&split)
        );
        assert_ne!(
            runner_config_digest(&with_comma),
            runner_config_digest(&split)
        );

        // Newline inside an element must not collide with a split list.
        let mut with_newline = sample_runner_config();
        with_newline.features = vec!["a\nb".to_string()];
        assert_ne!(
            runner_config_digest(&with_newline),
            runner_config_digest(&split)
        );
        assert_ne!(
            runner_config_digest(&with_newline),
            runner_config_digest(&with_comma)
        );

        // Scalar control characters must not collide with other scalars.
        let mut scalar_nl = sample_runner_config();
        scalar_nl.oep_policy = "x\ny".to_string();
        let mut scalar_plain = sample_runner_config();
        scalar_plain.oep_policy = "x y".to_string();
        assert_ne!(
            runner_config_digest(&scalar_nl),
            runner_config_digest(&scalar_plain)
        );
        let mut scalar_empty = sample_runner_config();
        scalar_empty.oep_policy = String::new();
        let mut scalar_colon = sample_runner_config();
        scalar_colon.oep_policy = "0:".to_string();
        assert_ne!(
            runner_config_digest(&scalar_empty),
            runner_config_digest(&scalar_colon)
        );

        // Same values always produce the same encoding.
        let copy = with_comma.clone();
        assert_eq!(
            canonical_runner_config(&with_comma),
            canonical_runner_config(&copy)
        );
    }

    #[test]
    fn runner_digest_rejects_unknown_and_missing_fields() {
        let json = serde_json::json!({
            "tool_revision": "x", "cli_binary_sha256": "a".repeat(64),
            "features": [], "debugger_backend": "b", "oep_policy": "p",
            "container_restore": "off", "shrink": true, "data_sections": true,
            "pure_rebuild": false, "capture_policy_digest": "",
            "iat_fix_strategy": "s", "timeout_secs": 1,
            "isolation": {"workspace_policy": "w", "process_tree_policy": "p", "network_policy": "n"},
            "attempt_numbering": "a", "evidence_bundle_schema": "e", "gate_schema": "g",
            "env_allowlist": [],
            "sneaky_extra": 1,
        });
        assert!(
            serde_json::from_value::<RunnerConfig>(json).is_err(),
            "unknown field must be rejected"
        );
        let mut minimal = serde_json::to_value(sample_runner_config()).unwrap();
        minimal.as_object_mut().unwrap().remove("timeout_secs");
        assert!(
            serde_json::from_value::<RunnerConfig>(minimal).is_err(),
            "missing field must be rejected"
        );
    }

    #[test]
    fn runner_config_validate_fails_closed() {
        let mut c = sample_runner_config();
        c.cli_binary_sha256 = "not-hex".to_string();
        assert!(c.validate().is_some());
        let c = sample_runner_config();
        assert!(c.validate().is_none());
    }

    #[test]
    fn packer_family_distinguishes_oreans_and_gto_digests() {
        let oreans = sample_runner_config();
        let mut gto = sample_runner_config();
        gto.packer_family = packer_family::AHK_GTO.to_string();
        // The packer family is part of the config identity: GTO and Oreans
        // never share a runner digest.
        assert_ne!(
            runner_config_digest(&oreans),
            runner_config_digest(&gto),
            "packer_family must change the runner digest"
        );
        assert_eq!(oreans.packer_family, packer_family::OREANS);
    }

    #[test]
    fn familyless_wire_json_defaults_to_oreans() {
        // Backward compatibility: a family-less legacy config parses as the
        // Oreans family and yields the same digest as an explicit Oreans one.
        let mut json = serde_json::to_value(sample_runner_config()).unwrap();
        json.as_object_mut().unwrap().remove("packer_family");
        let parsed: RunnerConfig = serde_json::from_value(json).expect("family-less JSON parses");
        assert_eq!(parsed.packer_family, packer_family::OREANS);
        assert_eq!(
            runner_config_digest(&parsed),
            runner_config_digest(&sample_runner_config())
        );
    }
}
