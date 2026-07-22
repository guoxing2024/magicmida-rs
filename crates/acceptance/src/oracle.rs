//! Legacy oracle comparison observations only — never authority for verdicts.

use serde::{Deserialize, Serialize};

use crate::identity::{sha256_hex, ArtifactIdentity, ROLE_LEGACY_ORACLE};

/// Observation produced by comparing a candidate to a legacy oracle file.
///
/// Oracle match or mismatch must not alter structural failures or produce
/// `Accepted`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleObservation {
    pub kind: String,
    pub oracle_role: String,
    pub oracle_sha256: String,
    pub oracle_size_bytes: u64,
    pub candidate_sha256: String,
    pub comparison: String,
    pub message: String,
}

/// Compare candidate identity to optional oracle bytes.
///
/// Returns an observation only. Callers must not use the result to flip
/// structural verdicts.
pub fn observe_oracle(
    candidate: &ArtifactIdentity,
    oracle_bytes: Option<&[u8]>,
) -> Option<OracleObservation> {
    let bytes = oracle_bytes?;
    let oracle_sha = sha256_hex(bytes);
    let oracle_size = bytes.len() as u64;
    let comparison = if oracle_sha == candidate.sha256 && oracle_size == candidate.size_bytes {
        "byte_identical"
    } else if oracle_sha == candidate.sha256 {
        "digest_match_size_mismatch"
    } else {
        "digest_mismatch"
    };
    Some(OracleObservation {
        kind: "legacy_oracle_comparison".to_string(),
        oracle_role: ROLE_LEGACY_ORACLE.to_string(),
        oracle_sha256: oracle_sha,
        oracle_size_bytes: oracle_size,
        candidate_sha256: candidate.sha256.clone(),
        comparison: comparison.to_string(),
        message: "Legacy oracle produces comparison observations only; it cannot grant acceptance or override structural failures.".to_string(),
    })
}
