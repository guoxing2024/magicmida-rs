//! Artifact identity: digest, size, role, optional expected digest.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Role label for the artifact under evaluation.
pub const ROLE_CANDIDATE: &str = "candidate";
pub const ROLE_LEGACY_ORACLE: &str = "legacy_oracle_candidate";

/// Bound identity of bytes under evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactIdentity {
    /// Lowercase hex SHA-256 of the file bytes.
    pub sha256: String,
    /// Exact byte length.
    pub size_bytes: u64,
    /// Declared role (for example `candidate`).
    pub role: String,
    /// Optional caller-supplied expected digest (lowercase hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("expected SHA-256 digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("expected size mismatch: expected {expected}, got {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("invalid expected SHA-256 hex: {0}")]
    InvalidExpectedHex(String),
}

impl ArtifactIdentity {
    /// Compute identity from raw bytes and optional expected digest/size.
    pub fn from_bytes(
        bytes: &[u8],
        role: impl Into<String>,
        expected_sha256: Option<&str>,
        expected_size: Option<u64>,
    ) -> Result<Self, IdentityError> {
        let sha256 = sha256_hex(bytes);
        let size_bytes = bytes.len() as u64;

        if let Some(exp_size) = expected_size {
            if exp_size != size_bytes {
                return Err(IdentityError::SizeMismatch {
                    expected: exp_size,
                    actual: size_bytes,
                });
            }
        }

        let expected_norm = match expected_sha256 {
            None => None,
            Some(raw) => {
                let n = normalize_sha256_hex(raw)
                    .map_err(|_| IdentityError::InvalidExpectedHex(raw.to_string()))?;
                if n != sha256 {
                    return Err(IdentityError::DigestMismatch {
                        expected: n,
                        actual: sha256,
                    });
                }
                Some(n)
            }
        };

        Ok(Self {
            sha256,
            size_bytes,
            role: role.into(),
            expected_sha256: expected_norm,
        })
    }
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Normalize a SHA-256 hex string to lowercase 64 hex chars.
pub fn normalize_sha256_hex(raw: &str) -> Result<String, ()> {
    let t = raw.trim();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(());
    }
    Ok(t.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_mismatch_fail_closed() {
        let bytes = b"hello";
        let err = ArtifactIdentity::from_bytes(
            bytes,
            ROLE_CANDIDATE,
            Some("0000000000000000000000000000000000000000000000000000000000000000"),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, IdentityError::DigestMismatch { .. }));
    }

    #[test]
    fn size_mismatch_fail_closed() {
        let err = ArtifactIdentity::from_bytes(b"ab", ROLE_CANDIDATE, None, Some(99)).unwrap_err();
        assert!(matches!(err, IdentityError::SizeMismatch { .. }));
    }
}
