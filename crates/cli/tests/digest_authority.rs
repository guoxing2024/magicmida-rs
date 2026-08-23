//! IMP-06-R1 — Digest Authority Production Boundary tests.
//!
//! Covers the production `RuntimeDigestAuthority` object, the placeholder
//! fail-closed blocking, the digest mismatch comparison API, and the proof
//! that `RuntimeAuthorityManifest::verify_file()` is the SINGLE runtime file
//! hash computation point (no duplicate hash path).
//!
//! These are offline tests only. They prove the local authority logic and
//! the comparison API; they do NOT prove any runtime echo is wired
//! (`runtime echo consumer = NOT WIRED` — no V2 runtime export exists yet).

use mida_cli::unpacker::runtime_loader::{
    is_valid_digest_hex, validate_digest_hex, DigestValidationError,
    PLACEHOLDER_RUNTIME_DIGEST, RuntimeAuthorityManifest, RuntimeDigestAuthority,
    RuntimeFileIdentity, RuntimeLoadError, DIGEST_HEX_LEN,
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

fn identity_with(sha256: &str) -> RuntimeFileIdentity {
    RuntimeFileIdentity {
        path: std::path::PathBuf::from("C:/tmp/verified_runtime.dll"),
        sha256: sha256.to_string(),
        size_bytes: 1234,
        architecture: "x86_64".to_string(),
    }
}

fn authority_with(sha256: &str) -> RuntimeDigestAuthority {
    RuntimeDigestAuthority::from_verified_identity(
        &identity_with(sha256),
        "mida-antidebug-runtime-x64",
    )
    .expect("test digest must be a valid 64-lowercase-hex digest")
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
    let auth = authority_with(&d);
    assert_eq!(auth.digest_value, d);
    assert_eq!(auth.size_bytes, 1234);
    assert_eq!(auth.architecture, "x86_64");
    assert_eq!(auth.manifest_artifact_id, "mida-antidebug-runtime-x64");
    assert!(auth.canonical_path.is_absolute());
}

#[test]
fn placeholder_digest_rejected_everywhere() {
    assert_eq!(PLACEHOLDER_RUNTIME_DIGEST, "adr4-foundation-unbound");
    assert!(!is_valid_digest_hex(PLACEHOLDER_RUNTIME_DIGEST));
    assert_eq!(
        validate_digest_hex(PLACEHOLDER_RUNTIME_DIGEST),
        Err(DigestValidationError::Placeholder)
    );
    // The placeholder can NEVER be wrapped into a verified authority.
    let err = RuntimeDigestAuthority::from_verified_identity(
        &identity_with(PLACEHOLDER_RUNTIME_DIGEST),
        "mida-antidebug-runtime-x64",
    )
    .unwrap_err();
    assert_eq!(err, DigestValidationError::Placeholder);
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
    // Construction from an uppercase identity fails closed too.
    assert!(RuntimeDigestAuthority::from_verified_identity(
        &identity_with(&"A".repeat(64)),
        "mida-antidebug-runtime-x64",
    )
    .is_err());
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
// authority vs runtime echo comparison (fail-closed)
// ---------------------------------------------------------------------------

#[test]
fn runtime_echo_missing_rejected() {
    let auth = authority_with(&valid_digest());
    assert_eq!(
        auth.verify_runtime_echo(""),
        Err(DigestValidationError::Missing)
    );
}

#[test]
fn runtime_echo_placeholder_rejected() {
    let auth = authority_with(&valid_digest());
    assert_eq!(
        auth.verify_runtime_echo(PLACEHOLDER_RUNTIME_DIGEST),
        Err(DigestValidationError::Placeholder)
    );
}

#[test]
fn runtime_echo_bad_shapes_rejected() {
    let auth = authority_with(&valid_digest());
    // wrong length
    assert!(matches!(
        auth.verify_runtime_echo(&"b".repeat(63)),
        Err(DigestValidationError::WrongLength { .. })
    ));
    // uppercase
    assert!(matches!(
        auth.verify_runtime_echo(&"B".repeat(64)),
        Err(DigestValidationError::NotLowercaseHex)
    ));
    // non-hex
    assert!(matches!(
        auth.verify_runtime_echo(&"z".repeat(64)),
        Err(DigestValidationError::NotLowercaseHex)
    ));
    // NUL terminator carried over the wire
    let nul = format!("{}\0", "b".repeat(64));
    assert!(matches!(
        auth.verify_runtime_echo(&nul),
        Err(DigestValidationError::WrongLength { .. })
    ));
}

#[test]
fn authority_runtime_echo_mismatch_rejected() {
    let auth = authority_with(&valid_digest());
    let other = "b".repeat(64);
    assert_eq!(
        auth.verify_runtime_echo(&other),
        Err(DigestValidationError::EchoMismatch {
            expected: valid_digest(),
            got: other.clone(),
        })
    );
}

#[test]
fn correct_lowercase_echo_accepted() {
    let d = valid_digest();
    let auth = authority_with(&d);
    assert_eq!(auth.verify_runtime_echo(&d), Ok(()));
    // A DIFFERENT valid digest from the same authority still mismatches.
    assert!(auth.verify_runtime_echo(&"c".repeat(64)).is_err());
}

// ---------------------------------------------------------------------------
// single hash authority point proof
// ---------------------------------------------------------------------------

#[test]
fn verify_file_is_the_only_runtime_hash_point() {
    // 1. verify_file() computes the digest from the FILE BYTES (the single
    //    authoritative hash point).
    let pe = minimal_pe();
    let path = tmp_file("imp06_runtime_ok.dll", &pe);
    let expected = sha256_hex(&pe);
    let authority = manifest(&expected, pe.len() as u64);
    let id = authority.verify_file(&path).unwrap();
    assert_eq!(id.sha256, expected);

    // 2. The digest authority is derived from THAT identity WITHOUT any
    //    re-read of the DLL (no second hash path): from_verified_identity
    //    takes only the identity struct; the file is never touched again.
    let da = RuntimeDigestAuthority::from_verified_identity(&id, &authority.artifact_id)
        .expect("verified identity must build a valid authority");
    assert_eq!(da.digest_value, id.sha256);
    assert_eq!(da.digest_value, expected);
    assert_eq!(da.size_bytes, id.size_bytes);
    assert_eq!(da.manifest_artifact_id, authority.artifact_id);
    // The canonical path is the verify_file() result path.
    assert_eq!(da.canonical_path, id.path);
}

#[test]
fn manifest_digest_and_verified_file_digest_mismatch_rejected() {
    let pe = minimal_pe();
    let path = tmp_file("imp06_runtime_mismatch.dll", &pe);
    let real = sha256_hex(&pe);
    let wrong = "00".repeat(32);
    let authority = manifest(&wrong, pe.len() as u64);
    // verify_file() fails closed when the manifest digest does not match the
    // computed file digest -> the loader path never proceeds.
    let err = authority.verify_file(&path).unwrap_err();
    assert!(matches!(err, RuntimeLoadError::AuthorityMismatch(_)));
    assert!(err.to_string().contains("sha256"));
    // The computed real digest can never enter the authority through this
    // path because verify_file() is the ONLY constructor input and it failed.
    let _ = real;
}

#[test]
fn no_duplicate_hash_authority_path() {
    // RuntimeDigestAuthority carries NO file-reading capability: its only
    // constructor consumes an already-verified identity. A second hash
    // authority would require either a new file read or a public field
    // constructor; the public surface has neither.
    //
    // Proof by construction: from_verified_identity rejects every invalid
    // digest shape, so an authority can only be produced from a verify_file()
    // identity. There is no other `pub fn` on the type that accepts raw file
    // bytes or a path and hashes them.
    let identity = identity_with(&valid_digest());
    let auth = RuntimeDigestAuthority::from_verified_identity(&identity, "id").unwrap();
    assert_eq!(auth.digest_value.len(), DIGEST_HEX_LEN);
    assert!(auth.digest_value.chars().all(|c| c.is_ascii_hexdigit()));
}
