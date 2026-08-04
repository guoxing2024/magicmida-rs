//! CI signature envelope (verify-only; dumper must never self-sign).
//!
//! Schema: `mida.signature-envelope/v0` — see docs/TRANSFORM_TAXONOMY_V1.md §7.
//!
//! Product authenticity path:
//! 1. Parse envelope JSON
//! 2. Bind candidate / manifest / evidence digests
//! 3. Enforce taxonomy + dirty + key allowlist policy
//! 4. Verify detached signature via injected [`SignatureVerifier`]
//!
//! No private keys live in this crate. HMAC-SHA256 is provided for CI lab
//! keys (shared secret held outside acceptance). Ed25519 is reserved and
//! currently rejected as unimplemented.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::behavior::{BehaviorEvidence, VerifiedManagedCandidate, TRANSFORM_TAXONOMY_VERSION};
use crate::identity::sha256_hex;

pub const ENVELOPE_SCHEMA_VERSION: &str = "mida.signature-envelope/v0";
pub const SIG_ALG_HMAC_SHA256_V0: &str = "mida.hmac-sha256/v0";
pub const SIG_ALG_ED25519_V1: &str = "mida.ed25519/v1";

/// Fail-closed verification policy for product Accept under a signed envelope.
#[derive(Debug, Clone)]
pub struct EnvelopePolicy {
    /// When false (default product), `git_dirty=true` rejects.
    pub allow_git_dirty: bool,
    /// Empty list = no key is trusted (fail-closed).
    ///
    /// Product path must load this from a **fixed** allowlist (not caller-supplied
    /// secrets). HMAC lab mode may populate it only under `allow_hmac_lab`.
    pub allowed_key_ids: Vec<String>,
    /// When true, `mida.hmac-sha256/v0` may verify (lab only). Default false —
    /// product posture rejects caller-controlled HMAC trust roots (audit P0).
    pub allow_hmac_lab: bool,
    /// Maximum age of `created_utc` relative to verification time (seconds).
    /// `None` = do not enforce max-age (still requires parseable non-empty UTC).
    pub max_age_secs: Option<u64>,
    /// Allowed clock skew into the future for `created_utc` (seconds). Default 300.
    pub max_clock_skew_secs: u64,
    /// Optional allowlist of producer tool digests. Empty = any non-empty digest.
    pub allowed_producer_tool_sha256: Vec<String>,
    /// Optional allowlist of git commits. Empty = any non-empty commit id.
    pub allowed_git_commits: Vec<String>,
    /// Verification "now" as Unix UTC seconds. `None` = wall clock at verify time.
    /// Tests inject a fixed instant; production leaves this unset.
    pub now_unix_secs: Option<i64>,
}

impl Default for EnvelopePolicy {
    fn default() -> Self {
        Self {
            allow_git_dirty: false,
            allowed_key_ids: Vec::new(),
            allow_hmac_lab: false,
            // 7 days default freshness window for product/lab verify alike.
            max_age_secs: Some(7 * 24 * 60 * 60),
            max_clock_skew_secs: 300,
            allowed_producer_tool_sha256: Vec::new(),
            allowed_git_commits: Vec::new(),
            now_unix_secs: None,
        }
    }
}

impl EnvelopePolicy {
    /// Lab helper: allow a single HMAC key id. Still forbids dirty trees and
    /// enforces default freshness. **Not** a product trust root.
    pub fn hmac_lab_key(key_id: impl Into<String>) -> Self {
        Self {
            allow_git_dirty: false,
            allowed_key_ids: vec![key_id.into()],
            allow_hmac_lab: true,
            ..Self::default()
        }
    }
}

/// Detached signature block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeSignature {
    pub algorithm: String,
    /// Lowercase hex of the signature bytes.
    pub value_hex: String,
}

/// Unsigned payload fields (canonical hash input).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePayload {
    pub taxonomy_version: String,
    pub candidate_sha256: String,
    pub candidate_size_bytes: u64,
    pub manifest_sha256: String,
    pub evidence_sha256: String,
    pub probe_id: String,
    pub reference_kind: String,
    #[serde(default)]
    pub reference_sha256: Option<String>,
    pub producer_tool_sha256: String,
    pub git_commit: String,
    pub git_dirty: bool,
    pub toolchain: String,
    pub run_uuid: String,
    pub created_utc: String,
    /// Optional absolute expiry (RFC3339 UTC). When set, verify rejects after it.
    #[serde(default)]
    pub expires_utc: Option<String>,
    pub key_id: String,
}

/// Top-level envelope document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignatureEnvelope {
    schema_version: String,
    payload: EnvelopePayload,
    signature: EnvelopeSignature,
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("invalid envelope JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported envelope schema_version '{0}' (expected {ENVELOPE_SCHEMA_VERSION})")]
    SchemaVersion(String),
    #[error("envelope taxonomy_version mismatch: got='{got}' expected='{expected}'")]
    TaxonomyMismatch { got: String, expected: String },
    #[error("envelope candidate digest/size mismatch")]
    CandidateMismatch,
    #[error("envelope manifest_sha256 mismatch")]
    ManifestDigestMismatch,
    #[error("envelope evidence_sha256 mismatch")]
    EvidenceDigestMismatch,
    #[error("envelope probe_id mismatch: envelope='{envelope}' evidence='{evidence}'")]
    ProbeMismatch { envelope: String, evidence: String },
    #[error("envelope reference mismatch")]
    ReferenceMismatch,
    #[error("git_dirty=true rejected by EnvelopePolicy")]
    GitDirtyForbidden,
    #[error("key_id '{0}' is not in EnvelopePolicy allowlist")]
    KeyNotAllowed(String),
    #[error("signature algorithm '{0}' is not implemented for verification")]
    AlgorithmUnsupported(String),
    #[error("signature value_hex is not valid lowercase hex of expected length")]
    BadSignatureHex,
    #[error("digest field is not valid 64-char lowercase hex")]
    BadDigestHex,
    #[error("created_utc is missing or not valid RFC3339 UTC: {0}")]
    BadCreatedUtc(String),
    #[error("expires_utc is not valid RFC3339 UTC: {0}")]
    BadExpiresUtc(String),
    #[error("envelope created_utc is in the future beyond allowed clock skew")]
    CreatedInFuture,
    #[error("envelope exceeded max_age_secs policy")]
    EnvelopeExpiredAge,
    #[error("envelope past expires_utc")]
    EnvelopeExpiredAbsolute,
    #[error("run_uuid must be non-empty UUID-like (8-4-4-4-12 hex)")]
    BadRunUuid,
    #[error("toolchain must be non-empty")]
    BadToolchain,
    #[error("git_commit not in EnvelopePolicy allowlist")]
    GitCommitNotAllowed,
    #[error("producer_tool_sha256 not in EnvelopePolicy allowlist")]
    ProducerToolNotAllowed,
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("canonical payload serialization failed: {0}")]
    Canonical(String),
    #[error(transparent)]
    Behavior(#[from] crate::behavior::BehaviorEvidenceError),
}

/// Verifier for detached envelope signatures. Implementations hold key material
/// **outside** the dumper; acceptance only calls verify.
pub trait SignatureVerifier {
    fn verify(
        &self,
        algorithm: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EnvelopeError>;
}

/// Rejects every signature (default product posture until CI wires keys).
#[derive(Debug, Default, Clone, Copy)]
pub struct RejectAllVerifier;

impl SignatureVerifier for RejectAllVerifier {
    fn verify(
        &self,
        _algorithm: &str,
        _key_id: &str,
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), EnvelopeError> {
        Err(EnvelopeError::SignatureInvalid)
    }
}

/// HMAC-SHA256 verifier for a single lab/CI key (shared secret not shipped in dumps).
#[derive(Debug, Clone)]
pub struct HmacSha256Verifier {
    pub key_id: String,
    pub key: Vec<u8>,
}

impl SignatureVerifier for HmacSha256Verifier {
    fn verify(
        &self,
        algorithm: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), EnvelopeError> {
        if algorithm != SIG_ALG_HMAC_SHA256_V0 {
            return Err(EnvelopeError::AlgorithmUnsupported(algorithm.to_string()));
        }
        if key_id != self.key_id {
            return Err(EnvelopeError::KeyNotAllowed(key_id.to_string()));
        }
        if signature.len() != 32 {
            return Err(EnvelopeError::BadSignatureHex);
        }
        let expected = hmac_sha256(&self.key, message);
        if !constant_time_eq(&expected, signature) {
            return Err(EnvelopeError::SignatureInvalid);
        }
        Ok(())
    }
}

/// Candidate + manifest + evidence + envelope that passed structural + crypto checks.
///
/// Evidence is **sealed** from the hashed `evidence_json` at verify time — callers
/// cannot swap a different [`BehaviorEvidence`] into signed compose (audit P0).
#[derive(Debug, Clone)]
pub struct VerifiedSignedBundle {
    managed: VerifiedManagedCandidate,
    envelope: SignatureEnvelope,
    evidence: BehaviorEvidence,
    evidence_sha256: String,
    manifest_sha256: String,
}

impl VerifiedSignedBundle {
    pub fn managed(&self) -> &VerifiedManagedCandidate {
        &self.managed
    }

    pub fn envelope(&self) -> &SignatureEnvelope {
        &self.envelope
    }

    /// Sealed evidence parsed from the hashed JSON at verify time.
    pub fn evidence(&self) -> &BehaviorEvidence {
        &self.evidence
    }

    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn key_id(&self) -> &str {
        &self.envelope.payload.key_id
    }

    pub fn run_uuid(&self) -> &str {
        &self.envelope.payload.run_uuid
    }
}

impl SignatureEnvelope {
    pub const SCHEMA: &'static str = ENVELOPE_SCHEMA_VERSION;

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn payload(&self) -> &EnvelopePayload {
        &self.payload
    }

    pub fn signature(&self) -> &EnvelopeSignature {
        &self.signature
    }

    pub fn parse_json(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let env: Self = serde_json::from_slice(bytes)?;
        if env.schema_version != ENVELOPE_SCHEMA_VERSION {
            return Err(EnvelopeError::SchemaVersion(env.schema_version));
        }
        if env.payload.taxonomy_version != TRANSFORM_TAXONOMY_VERSION {
            return Err(EnvelopeError::TaxonomyMismatch {
                got: env.payload.taxonomy_version.clone(),
                expected: TRANSFORM_TAXONOMY_VERSION.to_string(),
            });
        }
        let cand = normalize_sha(&env.payload.candidate_sha256)?;
        let man = normalize_sha(&env.payload.manifest_sha256)?;
        let evi = normalize_sha(&env.payload.evidence_sha256)?;
        let tool = normalize_sha(&env.payload.producer_tool_sha256)?;
        let ref_sha = match &env.payload.reference_sha256 {
            Some(s) => Some(normalize_sha(s)?),
            None => None,
        };
        if env.signature.value_hex.is_empty()
            || !env
                .signature
                .value_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit())
            || env.signature.value_hex.len() % 2 != 0
        {
            return Err(EnvelopeError::BadSignatureHex);
        }
        if env.payload.key_id.trim().is_empty() {
            return Err(EnvelopeError::KeyNotAllowed(String::new()));
        }
        if env.payload.git_commit.trim().is_empty() {
            return Err(EnvelopeError::Canonical(
                "git_commit must be non-empty".into(),
            ));
        }
        if env.payload.toolchain.trim().is_empty() {
            return Err(EnvelopeError::BadToolchain);
        }
        if !is_uuid_like(env.payload.run_uuid.trim()) {
            return Err(EnvelopeError::BadRunUuid);
        }
        // Parse created_utc early so malformed timestamps never reach verify.
        parse_rfc3339_utc(&env.payload.created_utc).map_err(EnvelopeError::BadCreatedUtc)?;
        if let Some(ref exp) = env.payload.expires_utc {
            parse_rfc3339_utc(exp).map_err(EnvelopeError::BadExpiresUtc)?;
        }
        Ok(Self {
            schema_version: env.schema_version,
            payload: EnvelopePayload {
                candidate_sha256: cand,
                manifest_sha256: man,
                evidence_sha256: evi,
                producer_tool_sha256: tool,
                reference_sha256: ref_sha,
                ..env.payload
            },
            signature: EnvelopeSignature {
                algorithm: env.signature.algorithm,
                value_hex: env.signature.value_hex.to_ascii_lowercase(),
            },
        })
    }

    /// Canonical message bytes that the detached signature covers.
    ///
    /// Stable JSON object with fixed key order (serde struct field order).
    pub fn canonical_message(&self) -> Result<Vec<u8>, EnvelopeError> {
        serde_json::to_vec(&self.payload).map_err(|e| EnvelopeError::Canonical(e.to_string()))
    }

    /// Full bind + policy + signature verify. Returns a sealed bundle.
    ///
    /// Evidence is **parsed from `evidence_json`** (the hashed bytes) — callers
    /// cannot pass a separate struct that diverges from the signed digest.
    pub fn verify_bundle(
        &self,
        candidate_bytes: &[u8],
        manifest_json: &[u8],
        evidence_json: &[u8],
        policy: &EnvelopePolicy,
        verifier: &dyn SignatureVerifier,
    ) -> Result<VerifiedSignedBundle, EnvelopeError> {
        // Taxonomy already checked in parse; re-check for non-parse construction.
        if self.payload.taxonomy_version != TRANSFORM_TAXONOMY_VERSION {
            return Err(EnvelopeError::TaxonomyMismatch {
                got: self.payload.taxonomy_version.clone(),
                expected: TRANSFORM_TAXONOMY_VERSION.to_string(),
            });
        }

        let cand_dig = sha256_hex(candidate_bytes);
        if cand_dig != self.payload.candidate_sha256
            || (candidate_bytes.len() as u64) != self.payload.candidate_size_bytes
        {
            return Err(EnvelopeError::CandidateMismatch);
        }

        let man_dig = sha256_hex(manifest_json);
        if man_dig != self.payload.manifest_sha256 {
            return Err(EnvelopeError::ManifestDigestMismatch);
        }

        let evi_dig = sha256_hex(evidence_json);
        if evi_dig != self.payload.evidence_sha256 {
            return Err(EnvelopeError::EvidenceDigestMismatch);
        }

        // Parse evidence from the *same* bytes that were hashed (audit P0).
        let evidence = BehaviorEvidence::parse_json(evidence_json)?;

        if evidence.probe.id != self.payload.probe_id {
            return Err(EnvelopeError::ProbeMismatch {
                envelope: self.payload.probe_id.clone(),
                evidence: evidence.probe.id.clone(),
            });
        }
        if evidence.reference.kind != self.payload.reference_kind {
            return Err(EnvelopeError::ReferenceMismatch);
        }
        match (&self.payload.reference_sha256, &evidence.reference.sha256) {
            (None, None) => {}
            (Some(a), Some(b)) if a.eq_ignore_ascii_case(b) => {}
            _ => return Err(EnvelopeError::ReferenceMismatch),
        }

        // Evidence must bind to the same candidate.
        if !evidence.binds_to_candidate(candidate_bytes) {
            return Err(EnvelopeError::CandidateMismatch);
        }

        if self.payload.git_dirty && !policy.allow_git_dirty {
            return Err(EnvelopeError::GitDirtyForbidden);
        }

        if !policy
            .allowed_key_ids
            .iter()
            .any(|k| k == &self.payload.key_id)
        {
            return Err(EnvelopeError::KeyNotAllowed(self.payload.key_id.clone()));
        }

        if !policy.allowed_git_commits.is_empty()
            && !policy
                .allowed_git_commits
                .iter()
                .any(|c| c == &self.payload.git_commit)
        {
            return Err(EnvelopeError::GitCommitNotAllowed);
        }
        if !policy.allowed_producer_tool_sha256.is_empty()
            && !policy
                .allowed_producer_tool_sha256
                .iter()
                .any(|h| h.eq_ignore_ascii_case(&self.payload.producer_tool_sha256))
        {
            return Err(EnvelopeError::ProducerToolNotAllowed);
        }

        enforce_freshness(&self.payload, policy)?;

        // Product algorithm reserved; HMAC is lab-only via explicit policy/flag.
        if self.signature.algorithm == SIG_ALG_ED25519_V1 {
            return Err(EnvelopeError::AlgorithmUnsupported(
                SIG_ALG_ED25519_V1.to_string(),
            ));
        }
        if self.signature.algorithm == SIG_ALG_HMAC_SHA256_V0 && !policy.allow_hmac_lab {
            return Err(EnvelopeError::AlgorithmUnsupported(format!(
                "{SIG_ALG_HMAC_SHA256_V0} requires EnvelopePolicy.allow_hmac_lab / --allow-hmac-lab"
            )));
        }

        let sig_bytes = hex_decode(&self.signature.value_hex)?;
        let message = self.canonical_message()?;
        verifier.verify(
            &self.signature.algorithm,
            &self.payload.key_id,
            &message,
            &sig_bytes,
        )?;

        let managed = VerifiedManagedCandidate::verify(candidate_bytes, manifest_json)?;

        Ok(VerifiedSignedBundle {
            managed,
            envelope: self.clone(),
            evidence,
            evidence_sha256: evi_dig,
            manifest_sha256: man_dig,
        })
    }
}

/// Build a correctly signed envelope for tests / offline CI tooling.
///
/// **Not** for dumper use — product dumps must not self-sign.
pub fn sign_hmac_sha256_for_test(
    payload: EnvelopePayload,
    key_id: &str,
    key: &[u8],
) -> Result<SignatureEnvelope, EnvelopeError> {
    if payload.key_id != key_id {
        return Err(EnvelopeError::KeyNotAllowed(payload.key_id.clone()));
    }
    let env = SignatureEnvelope {
        schema_version: ENVELOPE_SCHEMA_VERSION.to_string(),
        payload,
        signature: EnvelopeSignature {
            algorithm: SIG_ALG_HMAC_SHA256_V0.to_string(),
            value_hex: String::new(),
        },
    };
    let message = env.canonical_message()?;
    let mac = hmac_sha256(key, &message);
    Ok(SignatureEnvelope {
        signature: EnvelopeSignature {
            algorithm: SIG_ALG_HMAC_SHA256_V0.to_string(),
            value_hex: hex_encode(&mac),
        },
        ..env
    })
}

fn normalize_sha(s: &str) -> Result<String, EnvelopeError> {
    let sha = s.trim().to_ascii_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EnvelopeError::BadDigestHex);
    }
    Ok(sha)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, EnvelopeError> {
    if s.len() % 2 != 0 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(EnvelopeError::BadSignatureHex);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, EnvelopeError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(EnvelopeError::BadSignatureHex),
    }
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = Sha256::digest(key);
        key_block[..32].copy_from_slice(&d);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(&inner_hash);
    let out = outer.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Convenience: hash arbitrary bytes to lowercase hex (re-export shape for CI tools).
pub fn digest_hex(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

fn is_uuid_like(s: &str) -> bool {
    // 8-4-4-4-12 hex with dashes (canonical UUID text form).
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    let dash = |i: usize| b[i] == b'-';
    let hex = |i: usize| b[i].is_ascii_hexdigit();
    if !(dash(8) && dash(13) && dash(18) && dash(23)) {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            continue;
        }
        if !c.is_ascii_hexdigit() {
            return false;
        }
        let _ = hex(i);
    }
    true
}

fn enforce_freshness(
    payload: &EnvelopePayload,
    policy: &EnvelopePolicy,
) -> Result<(), EnvelopeError> {
    let created = parse_rfc3339_utc(&payload.created_utc).map_err(EnvelopeError::BadCreatedUtc)?;
    let now = policy.now_unix_secs.unwrap_or_else(unix_now_secs);
    let skew = policy.max_clock_skew_secs as i64;
    if created > now.saturating_add(skew) {
        return Err(EnvelopeError::CreatedInFuture);
    }
    if let Some(max_age) = policy.max_age_secs {
        let age = now.saturating_sub(created);
        if age > max_age as i64 {
            return Err(EnvelopeError::EnvelopeExpiredAge);
        }
    }
    if let Some(ref exp) = payload.expires_utc {
        let exp_ts = parse_rfc3339_utc(exp).map_err(EnvelopeError::BadExpiresUtc)?;
        if now > exp_ts.saturating_add(skew) {
            return Err(EnvelopeError::EnvelopeExpiredAbsolute);
        }
    }
    Ok(())
}

fn unix_now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Minimal RFC3339 / ISO-8601 UTC parser → Unix seconds.
/// Accepts `YYYY-MM-DDTHH:MM:SSZ`, optional fractional seconds, and `±HH:MM` offsets.
fn parse_rfc3339_utc(s: &str) -> Result<i64, String> {
    let t = s.trim();
    if t.len() < 20 {
        return Err(format!("too short: {t}"));
    }
    let b = t.as_bytes();
    if b[4] != b'-'
        || b[7] != b'-'
        || (b[10] != b'T' && b[10] != b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(format!("bad layout: {t}"));
    }
    let year: i64 = std::str::from_utf8(&b[0..4])
        .ok()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("year: {t}"))?;
    let month: i64 = std::str::from_utf8(&b[5..7])
        .ok()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("month: {t}"))?;
    let day: i64 = std::str::from_utf8(&b[8..10])
        .ok()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("day: {t}"))?;
    let hour: i64 = std::str::from_utf8(&b[11..13])
        .ok()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("hour: {t}"))?;
    let min: i64 = std::str::from_utf8(&b[14..16])
        .ok()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("min: {t}"))?;
    let sec: i64 = std::str::from_utf8(&b[17..19])
        .ok()
        .and_then(|x| x.parse().ok())
        .ok_or_else(|| format!("sec: {t}"))?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return Err(format!("range: {t}"));
    }
    let mut idx = 19;
    // Optional fractional seconds.
    if idx < b.len() && b[idx] == b'.' {
        idx += 1;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
    }
    let mut offset_secs: i64 = 0;
    if idx >= b.len() {
        return Err(format!("missing timezone: {t}"));
    }
    match b[idx] {
        b'Z' | b'z' => {
            if idx + 1 != b.len() {
                return Err(format!("trailing after Z: {t}"));
            }
        }
        b'+' | b'-' => {
            let sign = if b[idx] == b'+' { 1 } else { -1 };
            let rest = &t[idx + 1..];
            // HH:MM or HHMM
            let (oh, om) = if rest.len() == 5 && rest.as_bytes()[2] == b':' {
                let oh: i64 = rest[0..2].parse().map_err(|_| format!("off hour: {t}"))?;
                let om: i64 = rest[3..5].parse().map_err(|_| format!("off min: {t}"))?;
                (oh, om)
            } else if rest.len() == 4 {
                let oh: i64 = rest[0..2].parse().map_err(|_| format!("off hour: {t}"))?;
                let om: i64 = rest[2..4].parse().map_err(|_| format!("off min: {t}"))?;
                (oh, om)
            } else {
                return Err(format!("bad offset: {t}"));
            };
            if oh > 23 || om > 59 {
                return Err(format!("offset range: {t}"));
            }
            offset_secs = sign * (oh * 3600 + om * 60);
        }
        _ => return Err(format!("bad timezone: {t}")),
    }
    let days = days_from_civil(year, month, day)?;
    let sod = hour * 3600 + min * 60 + sec;
    Ok(days * 86400 + sod - offset_secs)
}

/// Howard Hinnant civil_from_days inverse (proleptic Gregorian) → days since 1970-01-01.
fn days_from_civil(y: i64, m: i64, d: i64) -> Result<i64, String> {
    // Basic month length check (no need perfect leap for reject path beyond range).
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
            if leap {
                29
            } else {
                28
            }
        }
        _ => return Err(format!("month {m}")),
    };
    if d < 1 || d > dim {
        return Err(format!("day {d} in month {m}"));
    }
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146097 + doe - 719468)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behavior::{
        BehaviorCandidate, BehaviorEvidence, BehaviorPolicy, BehaviorProbe, BehaviorProbeResult,
        BehaviorProducer, BehaviorReference, BehaviorVerdict, BEHAVIOR_EVIDENCE_SCHEMA_VERSION,
    };

    fn tiny_pe() -> Vec<u8> {
        // Minimal bytes — envelope tests bind digests, not PE structure.
        b"MZ-envelope-test-candidate-bytes-v0".to_vec()
    }

    fn empty_manifest_for(pe: &[u8]) -> String {
        let dig = sha256_hex(pe);
        format!(
            r#"{{"schema_version":"mida.transform-manifest/v0","taxonomy_version":"{TRANSFORM_TAXONOMY_VERSION}","candidate_sha256":"{dig}","candidate_size_bytes":{},"entries":[]}}"#,
            pe.len()
        )
    }

    fn evidence_for(pe: &[u8]) -> (BehaviorEvidence, String) {
        let dig = sha256_hex(pe);
        let ev = BehaviorEvidence {
            schema_version: BEHAVIOR_EVIDENCE_SCHEMA_VERSION.to_string(),
            candidate: BehaviorCandidate {
                sha256: dig.clone(),
                size_bytes: pe.len() as u64,
                role: "candidate".into(),
            },
            reference: BehaviorReference {
                kind: "bilateral".into(),
                sha256: Some(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                ),
                notes: None,
            },
            probe: BehaviorProbe {
                id: "exit_code_marker_v0".into(),
                policy: BehaviorPolicy {
                    network: "deny".into(),
                    max_wall_ms: 1000,
                    max_output_bytes: 1024,
                },
                result: BehaviorProbeResult {
                    status: "pass".into(),
                    exit_code: Some(0),
                    markers_found: vec!["ok".into()],
                    error_class: None,
                },
            },
            verdict: BehaviorVerdict::Pass,
            residual_risks: vec![],
            producer: BehaviorProducer {
                name: "test".into(),
                version: "0".into(),
            },
            transform_ledger: vec![],
        };
        let json = serde_json::to_string(&ev).unwrap();
        (ev, json)
    }

    fn base_payload(pe: &[u8], man: &[u8], evi: &[u8]) -> EnvelopePayload {
        EnvelopePayload {
            taxonomy_version: TRANSFORM_TAXONOMY_VERSION.to_string(),
            candidate_sha256: sha256_hex(pe),
            candidate_size_bytes: pe.len() as u64,
            manifest_sha256: sha256_hex(man),
            evidence_sha256: sha256_hex(evi),
            probe_id: "exit_code_marker_v0".into(),
            reference_kind: "bilateral".into(),
            reference_sha256: Some(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            ),
            producer_tool_sha256: sha256_hex(b"fake-tool"),
            git_commit: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            git_dirty: false,
            toolchain: "rustc-test".into(),
            run_uuid: "00000000-0000-4000-8000-000000000001".into(),
            created_utc: "2026-01-01T00:00:00Z".into(),
            expires_utc: None,
            key_id: "ci-lab-test-key".into(),
        }
    }

    /// Pin verification clock to envelope created_utc so max_age is deterministic.
    fn lab_policy(key_id: &str) -> EnvelopePolicy {
        let mut p = EnvelopePolicy::hmac_lab_key(key_id);
        p.now_unix_secs = Some(parse_rfc3339_utc("2026-01-01T12:00:00Z").unwrap());
        p
    }

    #[test]
    fn hmac_roundtrip_verifies() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (ev, evi_json) = evidence_for(&pe);
        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = lab_policy("ci-lab-test-key");
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let bundle = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap();
        assert_eq!(bundle.key_id(), "ci-lab-test-key");
        assert_eq!(
            bundle.managed().candidate_sha256(),
            sha256_hex(&pe).as_str()
        );
        assert_eq!(bundle.manifest_sha256(), sha256_hex(man.as_bytes()));
        assert_eq!(bundle.evidence().verdict, BehaviorVerdict::Pass);
        assert_eq!(bundle.evidence().candidate.sha256, sha256_hex(&pe));
        let _ = ev;
    }

    #[test]
    fn dirty_tree_rejected_by_default_policy() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let mut payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        payload.git_dirty = true;
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = lab_policy("ci-lab-test-key");
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let err = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::GitDirtyForbidden));
    }

    #[test]
    fn unknown_key_rejected() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = lab_policy("other-key");
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let err = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::KeyNotAllowed(_)));
    }

    #[test]
    fn tampered_manifest_digest_rejected() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = lab_policy("ci-lab-test-key");
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let tampered = man.replace("entries\":[]", "entries\":[],\"note\":\"x\"");
        let err = env
            .verify_bundle(
                &pe,
                tampered.as_bytes(),
                evi_json.as_bytes(),
                &policy,
                &verifier,
            )
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::ManifestDigestMismatch));
    }

    #[test]
    fn reject_all_verifier_blocks() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = lab_policy("ci-lab-test-key");
        let err = env
            .verify_bundle(
                &pe,
                man.as_bytes(),
                evi_json.as_bytes(),
                &policy,
                &RejectAllVerifier,
            )
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::SignatureInvalid));
    }

    #[test]
    fn empty_allowlist_fail_closed() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = EnvelopePolicy {
            allowed_key_ids: Vec::new(),
            allow_hmac_lab: true,
            now_unix_secs: Some(parse_rfc3339_utc("2026-01-01T12:00:00Z").unwrap()),
            ..EnvelopePolicy::default()
        };
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let err = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::KeyNotAllowed(_)));
    }

    #[test]
    fn hmac_without_lab_flag_rejected() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = EnvelopePolicy {
            allowed_key_ids: vec!["ci-lab-test-key".into()],
            allow_hmac_lab: false,
            now_unix_secs: Some(parse_rfc3339_utc("2026-01-01T12:00:00Z").unwrap()),
            ..EnvelopePolicy::default()
        };
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let err = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::AlgorithmUnsupported(_)));
    }

    #[test]
    fn max_age_rejects_stale_envelope() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let mut policy = lab_policy("ci-lab-test-key");
        // created 2026-01-01; now 30 days later with 7-day max_age → expired
        policy.now_unix_secs = Some(parse_rfc3339_utc("2026-01-31T00:00:00Z").unwrap());
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let err = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::EnvelopeExpiredAge));
    }

    #[test]
    fn absolute_expires_utc_rejects() {
        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev, evi_json) = evidence_for(&pe);
        let mut payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        payload.expires_utc = Some("2026-01-02T00:00:00Z".into());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let mut policy = lab_policy("ci-lab-test-key");
        policy.now_unix_secs = Some(parse_rfc3339_utc("2026-01-03T00:00:00Z").unwrap());
        policy.max_age_secs = None; // only absolute expiry matters here
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let err = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap_err();
        assert!(matches!(err, EnvelopeError::EnvelopeExpiredAbsolute));
    }

    #[test]
    fn sealed_evidence_used_by_signed_check() {
        use crate::check::{check_with_behavior_signed, CheckStaticOptions};
        use crate::verdict::Verdict;

        let pe = tiny_pe();
        let man = empty_manifest_for(&pe);
        let (_ev_a, evi_json) = evidence_for(&pe);
        let mut ev_b = evidence_for(&pe).0;
        ev_b.verdict = BehaviorVerdict::Fail;
        ev_b.probe.result.status = "fail".into();

        let payload = base_payload(&pe, man.as_bytes(), evi_json.as_bytes());
        let key = b"unit-test-hmac-key-material";
        let env = sign_hmac_sha256_for_test(payload, "ci-lab-test-key", key).unwrap();
        let policy = lab_policy("ci-lab-test-key");
        let verifier = HmacSha256Verifier {
            key_id: "ci-lab-test-key".into(),
            key: key.to_vec(),
        };
        let bundle = env
            .verify_bundle(&pe, man.as_bytes(), evi_json.as_bytes(), &policy, &verifier)
            .unwrap();
        assert_eq!(bundle.evidence().verdict, BehaviorVerdict::Pass);
        let report = check_with_behavior_signed(&pe, &CheckStaticOptions::default(), &bundle);
        assert_ne!(report.verdict, Verdict::Accepted);
        let _ = ev_b;
    }

    #[test]
    fn parse_rfc3339_epoch_smoke() {
        // 1970-01-01T00:00:00Z
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z").unwrap(), 0);
        // 2026-01-01 known non-zero
        assert!(parse_rfc3339_utc("2026-01-01T00:00:00Z").unwrap() > 0);
    }
}
