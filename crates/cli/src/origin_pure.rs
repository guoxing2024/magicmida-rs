//! Origin-only pure-rebuild default (operator decision D3, 2026-07-24).
//!
//! When the **protected input** SHA-256 matches the vault `origin_macro`
//! primary artifact, unpack defaults to pure rebuild unless the operator
//! passes `--no-pure-rebuild`. All other samples remain legacy unless
//! `--pure-rebuild` is explicit.
//!
//! This is **not** a global pure flip.
//!
//! The discriminator hash is **not** a production literal: it is loaded from
//! the case manifest (`lab/cases/v2/origin_macro.json`), which is embedded at
//! build time — the manifest is the contract data source, so swapping a
//! sample never requires a code edit. If the manifest cannot be resolved at
//! build time (compile error) or its `protected_input` artifact is absent /
//! malformed (runtime `None`), the resolver fails closed: the input is never
//! treated as Origin, and the reason string makes the fallback explicit.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Minimal case-manifest v2 subset: only the fields the Origin discriminator
/// consumes. Unknown manifest fields are ignored (the full strict shape is
/// validated by the acceptance side's `CaseManifestV2`).
#[derive(Debug, Deserialize)]
struct OriginMacroManifest {
    case_id: String,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Debug, Deserialize)]
struct ManifestArtifact {
    sha256: String,
    role: String,
}

/// Resolve the Origin Macro protected-input SHA-256 from its case manifest.
///
/// The manifest (`lab/cases/v2/origin_macro.json`) is embedded at build time,
/// so this never depends on the current working directory. Returns `None`
/// when the manifest does not parse or does not declare a `protected_input`
/// artifact — callers then fail closed (never treated as Origin).
pub fn origin_macro_protected_sha256() -> Option<String> {
    let bytes = include_str!("../../../lab/cases/v2/origin_macro.json");
    let manifest: OriginMacroManifest = serde_json::from_str(bytes).ok()?;
    if manifest.case_id != "origin_macro" {
        return None;
    }
    manifest
        .artifacts
        .into_iter()
        .find(|artifact| artifact.role == "protected_input")
        .map(|artifact| artifact.sha256.to_ascii_lowercase())
}

/// Compute lowercase hex SHA-256 of an on-disk file.
pub fn file_sha256_hex(path: &Path) -> Result<String, std::io::Error> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

/// True when `path` bytes match the Origin Macro protected corpus object.
///
/// Fail-closed: when the manifest-declared identity cannot be resolved, the
/// input is never treated as Origin.
pub fn is_origin_macro_protected_input(path: &Path) -> bool {
    let Some(expected) = origin_macro_protected_sha256() else {
        return false;
    };
    file_sha256_hex(path).is_ok_and(|hex| hex.eq_ignore_ascii_case(&expected))
}

/// Resolve pure-rebuild for unpack after CLI flags are parsed.
///
/// - `cli_pure`: `--pure-rebuild` was set
/// - `cli_no_pure`: `--no-pure-rebuild` was set (wins over Origin default)
/// - Origin protected input → default true unless `cli_no_pure`
/// - Manifest unavailable → fail closed to the legacy default (never an
///   unverified pure default) with an explicit reason
#[must_use]
pub fn resolve_pure_rebuild(
    input: &Path,
    cli_pure: bool,
    cli_no_pure: bool,
) -> (bool, &'static str) {
    if cli_no_pure {
        return (false, "cli --no-pure-rebuild");
    }
    if cli_pure {
        return (true, "cli --pure-rebuild");
    }
    if is_origin_macro_protected_input(input) {
        return (true, "origin_macro protected input default (D3)");
    }
    if origin_macro_protected_sha256().is_none() {
        return (
            false,
            "origin_macro manifest unavailable (fail-closed legacy default)",
        );
    }
    (false, "legacy default (non-Origin)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_manifest_identity_is_64_hex() {
        // The discriminator must come from the embedded manifest and be a
        // well-formed SHA-256 (64 lowercase hex chars).
        let sha = origin_macro_protected_sha256().expect("embedded origin_macro manifest");
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(sha, sha.to_ascii_lowercase());
    }

    #[test]
    fn resolve_prefers_no_pure() {
        // Path may not exist; cli_no_pure short-circuits before hash.
        let p = Path::new("does-not-matter.bin");
        let (v, why) = resolve_pure_rebuild(p, true, true);
        assert!(!v);
        assert!(why.contains("no-pure"));
    }

    #[test]
    fn resolve_cli_pure_without_origin() {
        let p = Path::new("does-not-matter.bin");
        let (v, why) = resolve_pure_rebuild(p, true, false);
        assert!(v);
        assert!(why.contains("--pure-rebuild"));
    }
}
