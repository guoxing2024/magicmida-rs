//! Origin-only pure-rebuild default (operator decision D3, 2026-07-24).
//!
//! When the **protected input** SHA-256 matches the vault `origin_macro`
//! primary artifact, unpack defaults to pure rebuild unless the operator
//! passes `--no-pure-rebuild`. All other samples remain legacy unless
//! `--pure-rebuild` is explicit.
//!
//! This is **not** a global pure flip.

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Vault `origin_macro` protected_input SHA-256 (lab/cases/v2/origin_macro.json).
pub const ORIGIN_MACRO_PROTECTED_SHA256: &str =
    "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7";

/// Compute lowercase hex SHA-256 of an on-disk file.
pub fn file_sha256_hex(path: &Path) -> Result<String, std::io::Error> {
    let data = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

/// True when `path` bytes match the Origin Macro protected corpus object.
pub fn is_origin_macro_protected_input(path: &Path) -> bool {
    match file_sha256_hex(path) {
        Ok(hex) => hex.eq_ignore_ascii_case(ORIGIN_MACRO_PROTECTED_SHA256),
        Err(_) => false,
    }
}

/// Resolve pure-rebuild for unpack after CLI flags are parsed.
///
/// - `cli_pure`: `--pure-rebuild` was set  
/// - `cli_no_pure`: `--no-pure-rebuild` was set (wins over Origin default)  
/// - Origin protected input → default true unless `cli_no_pure`
#[must_use]
pub fn resolve_pure_rebuild(input: &Path, cli_pure: bool, cli_no_pure: bool) -> (bool, &'static str) {
    if cli_no_pure {
        return (false, "cli --no-pure-rebuild");
    }
    if cli_pure {
        return (true, "cli --pure-rebuild");
    }
    if is_origin_macro_protected_input(input) {
        return (true, "origin_macro protected input default (D3)");
    }
    (false, "legacy default (non-Origin)")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_constant_is_64_hex() {
        assert_eq!(ORIGIN_MACRO_PROTECTED_SHA256.len(), 64);
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
