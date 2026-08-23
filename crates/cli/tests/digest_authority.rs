//! IMP-06-R2 — Digest Authority Provenance Sealing tests.
//!
//! Covers the public digest gates (`is_valid_digest_hex` /
//! `validate_digest_hex`), the placeholder fail-closed blocking, and the
//! REAL `verify_file()` path against a real minimal x64 PE.
//!
//! These are offline tests only. They prove the local authority logic; they
//! do NOT prove any runtime echo is wired (`runtime echo consumer = NOT
//! WIRED` — no V2 runtime export exists yet).
//!
//! # Provenance sealing
//!
//! The authority/identity types under test are SEALED by Rust visibility,
//! not by test comments:
//! - `RuntimeFileIdentity` has no public fields, no public constructor and
//!   no `Deserialize` — a raw literal is a COMPILE ERROR outside the
//!   defining module;
//! - `RuntimeDigestAuthority` has no public fields and its only constructor
//!   is `pub(crate)` — a raw literal or an external constructor call is a
//!   COMPILE ERROR outside the crate.
//!
//! Integration tests therefore exercise only the public surface:
//! `verify_file()` (which returns the sealed identity) and the pure digest
//! gates. Construction of the digest authority from the verified identity is
//! exercised by in-crate unit tests (same module as the type).

use mida_cli::unpacker::runtime_loader::{
    is_valid_digest_hex, validate_digest_hex, DigestValidationError, PLACEHOLDER_RUNTIME_DIGEST,
    RuntimeAuthorityManifest, RuntimeLoadError, DIGEST_HEX_LEN,
};

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

fn valid_digest() -> String {
    "a".repeat(64)
}

/// Build a minimal valid x64 PE (MZ + PE sig + Machine=AMD64 + PE32+ magic).
fn minimal_pe() -> Vec<u8> {
    let mut b = vec![0u8; 0x100];
    b[0] = b'M';
    b[1] = b'Z';
    b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
    b
}

fn manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
    RuntimeAuthorityManifest {
        schema: "mida.antidebug-runtime-authority/v1".to_string(),
        kind: "runtime-x64".to_string(),
        artifact_id: "mida-antidebug-runtime-x64".to_string(),
        sha256: sha256.to_string(),
        size_bytes: size,
        architecture: "x86_64".to_string(),
        source_ref: "test-commit".to_string(),
        provenance_ref: "provenance.json".to_string(),
    }
}

fn tmp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("mida-imp06-test");
    let _ = std::fs::create_dir_all(&dir);
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

// ---------------------------------------------------------------------------
// valid digest / lexical gates
// ---------------------------------------------------------------------------

#[test]
fn valid_64_char_lowercase_digest_accepted() {
    let d = valid_digest();
    assert!(is_valid_digest_hex(&d));
    assert_eq!(validate_digest_hex(&d), Ok(()));
    assert_eq!(d.len(), DIGEST_HEX_LEN);
}

#[test]
fn placeholder_digest_rejected_everywhere() {
    assert_eq!(PLACEHOLDER_RUNTIME_DIGEST, "adr4-foundation-unbound");
    assert!(!is_valid_digest_hex(PLACEHOLDER_RUNTIME_DIGEST));
    assert_eq!(
        validate_digest_hex(PLACEHOLDER_RUNTIME_DIGEST),
        Err(DigestValidationError::Placeholder)
    );
    // The placeholder can NEVER pass verify_file(): the manifest digest
    // check rejects it before any identity exists.
    let pe = minimal_pe();
    let path = tmp_file("imp06_placeholder.dll", &pe);
    let authority = manifest(PLACEHOLDER_RUNTIME_DIGEST, pe.len() as u64);
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
}

#[test]
fn uppercase_hex_rejected() {
    let d = "A".repeat(64);
    assert!(!is_valid_digest_hex(&d));
    assert_eq!(
        validate_digest_hex(&d),
        Err(DigestValidationError::NotLowercaseHex)
    );
    // Mixed case also rejected.
    let mixed = format!("{}F", "a".repeat(63));
    assert_eq!(
        validate_digest_hex(&mixed),
        Err(DigestValidationError::NotLowercaseHex)
    );
    // A manifest with an uppercase digest cannot verify any file: the
    // computed file digest is lowercase and will never match.
    let pe = minimal_pe();
    let path = tmp_file("imp06_uppercase.dll", &pe);
    let authority = manifest(&"A".repeat(64), pe.len() as u64);
    assert!(authority.verify_file(&path).is_err());
}

#[test]
fn non_hex_rejected() {
    let d = "z".repeat(64);
    assert!(!is_valid_digest_hex(&d));
    assert_eq!(
        validate_digest_hex(&d),
        Err(DigestValidationError::NotLowercaseHex)
    );
    // 'g' is not hex.
    let g = format!("{}g", "a".repeat(63));
    assert_eq!(
        validate_digest_hex(&g),
        Err(DigestValidationError::NotLowercaseHex)
    );
}

#[test]
fn wrong_length_rejected() {
    for bad in vec![
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "a".repeat(32),
    ] {
        assert!(!is_valid_digest_hex(&bad), "len {} must be rejected", bad.len());
    }
    assert_eq!(
        validate_digest_hex(""),
        Err(DigestValidationError::Missing)
    );
    assert_eq!(
        validate_digest_hex(&"a".repeat(63)),
        Err(DigestValidationError::WrongLength { got: 63 })
    );
    assert_eq!(
        validate_digest_hex(&"a".repeat(65)),
        Err(DigestValidationError::WrongLength { got: 65 })
    );
    // A 64-hex value WITH a NUL terminator is 65 chars -> wrong length (the
    // NUL can never ride inside digest_value).
    let nul_terminated = format!("{}\0", "a".repeat(64));
    assert_eq!(
        validate_digest_hex(&nul_terminated),
        Err(DigestValidationError::WrongLength { got: 65 })
    );
}

#[test]
fn nul_and_trailing_bytes_rejected() {
    // NUL inside a 64-char string is explicitly rejected as TrailingData
    // (the wire 65th-NUL case, named before the hex gate).
    let mut d = valid_digest().into_bytes();
    d[32] = 0;
    let s = String::from_utf8(d).unwrap();
    assert_eq!(
        validate_digest_hex(&s),
        Err(DigestValidationError::TrailingData)
    );
    // Trailing non-hex data after 64 hex chars is wrong length.
    let trailing = format!("{}X", "a".repeat(64));
    assert_eq!(
        validate_digest_hex(&trailing),
        Err(DigestValidationError::WrongLength { got: 65 })
    );
}

// ---------------------------------------------------------------------------
// verify_file() path (public surface)
// ---------------------------------------------------------------------------

#[test]
fn verify_file_produces_sealed_identity() {
    let pe = minimal_pe();
    let path = tmp_file("imp06_verify_ok.dll", &pe);
    let expected = sha256_hex(&pe);
    let authority = manifest(&expected, pe.len() as u64);
    let id = authority.verify_file(&path).unwrap();
    assert_eq!(id.sha256(), expected);
    assert_eq!(id.size_bytes(), pe.len() as u64);
    assert_eq!(id.architecture(), "x86_64");
    assert!(id.path().is_absolute());
}

#[test]
fn verify_file_rejects_digest_mismatch() {
    let pe = minimal_pe();
    let path = tmp_file("imp06_verify_mismatch.dll", &pe);
    let authority = manifest(&"00".repeat(32), pe.len() as u64);
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("sha256"));
}

#[test]
fn verify_file_rejects_size_mismatch() {
    let pe = minimal_pe();
    let path = tmp_file("imp06_verify_sizemismatch.dll", &pe);
    let authority = manifest(&sha256_hex(&pe), pe.len() as u64 + 1);
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("size"));
}

#[test]
fn verify_file_rejects_invalid_manifest_digests() {
    for (label, bad) in [
        ("placeholder", PLACEHOLDER_RUNTIME_DIGEST.to_string()),
        ("uppercase", "A".repeat(64)),
        ("non-hex", "z".repeat(64)),
        ("short", "a".repeat(32)),
    ] {
        let pe = minimal_pe();
        let path = tmp_file(&format!("imp06_bad_{label}.dll"), &pe);
        let authority = manifest(&bad, pe.len() as u64);
        let err = authority.verify_file(&path).unwrap_err();
        assert!(
            matches!(err, RuntimeLoadError::AuthorityMismatch(_)),
            "{label}: verify_file must fail closed, got {err:?}"
        );
    }
}
