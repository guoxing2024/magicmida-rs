//! G3-R4: GTO sample-authority adjudication dossier + explicit revision
//! promotion gate.
//!
//! This is an OFFLINE, audit-only contract. It never decides which revision is
//! the current authority, never mutates a manifest, never writes into
//! `lab/cases/v2`, and never launches a sample process. It only:
//!
//! 1. produces a machine-readable `mida.sample-authority-dossier/v1` dossier of
//!    the observed sample revisions (from immutable snapshots + historical
//!    records), all with `authority_status = pending_human_decision`;
//! 2. validates an externally-provided `mida.sample-authority-decision/v1`
//!    human decision against a dossier (fail-closed on any mismatch);
//! 3. for a `promote_revision` decision, emits a *promotion plan* that a human
//!    may use to update the manifest manually — it is NEVER wired to a manifest
//!    write.
//!
//! The sealed `dossier_sha256` covers the canonical dossier content, so any
//! tamper (revision, size, path, identity) is detected by the decision verifier
//! and the promotion gate.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::sample_snapshot::{self, capture_snapshot, verified_read_snapshot, PeIdentitySnapshot};

/// `mida.sample-authority-dossier/v1`
pub const DOSSIER_SCHEMA: &str = "mida.sample-authority-dossier/v1";
/// `mida.sample-authority-decision/v1`
pub const DECISION_SCHEMA: &str = "mida.sample-authority-decision/v1";
/// A revision whose snapshot is verified on disk.
pub const AVAIL_VERIFIED: &str = "verified";
/// A revision declared but whose source file is absent (never snapshotted).
pub const AVAIL_MISSING: &str = "missing";
/// A revision only retained in investigation records (file is gone, no snapshot).
pub const AVAIL_HISTORICAL_RECORD_ONLY: &str = "historical-record-only";
/// The dossier's authority status until a human decides.
pub const STATUS_PENDING: &str = "pending_human_decision";

/// A comparison verdict for an observed revision against the manifest identity.
pub const MATCHES_MANIFEST: &str = "matches_manifest";
pub const DIFFERS_FROM_MANIFEST: &str = "differs_from_manifest";

/// `decision` values in `mida.sample-authority-decision/v1`.
pub const DECISION_RETAIN_MANIFEST: &str = "retain_manifest";
pub const DECISION_PROMOTE_REVISION: &str = "promote_revision";
pub const DECISION_REJECT_REVISION: &str = "reject_revision";

/// The completion marker that seals a finished dossier.
pub const COMPLETION_MARKER: &str = "authority_dossier_complete";

// ---------------------------------------------------------------------------
// Dossier schema (`mida.sample-authority-dossier/v1`)
// ---------------------------------------------------------------------------

/// The identity the sealed manifest declares for the protected input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestIdentity {
    pub sha256: String,
    pub size_bytes: u64,
}

/// Read-only PE base identity captured from the snapshot (never launch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeBaseIdentity {
    pub machine: u16,
    pub pe32_plus: bool,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub sections: Vec<String>,
}

impl From<&PeIdentitySnapshot> for PeBaseIdentity {
    fn from(p: &PeIdentitySnapshot) -> Self {
        PeBaseIdentity {
            machine: p.machine,
            pe32_plus: p.pe32_plus,
            entry_rva: p.entry_point_rva,
            size_of_image: p.size_of_image,
            sections: p.section_names.clone(),
        }
    }
}

/// Read-only packer-family observation (best-effort; never an authority call).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyObservation {
    /// The family the observation selected (`oreans_themida` / `ahk_gto`).
    pub selected_family: String,
    /// The identify verdict text from the recognizer (Oreans / GTO).
    pub identify_verdict: String,
}

/// One observed revision of the logical sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRevision {
    pub sha256: String,
    pub size_bytes: u64,
    /// Path of the immutable snapshot for this revision, when captured. For
    /// `missing` / `historical-record-only` this is empty (no snapshot exists).
    pub immutable_snapshot_path: String,
    /// `verified` / `missing` / `historical-record-only`.
    pub availability: String,
    /// `matches_manifest` / `differs_from_manifest`.
    pub comparison_verdict: String,
    /// PE base identity, when the snapshot was parsed. `None` otherwise.
    pub pe_identity: Option<PeBaseIdentity>,
}

/// `mida.sample-authority-dossier/v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDossier {
    pub schema: String,
    pub logical_sample_id: String,
    pub packer_family: String,
    pub manifest_path: String,
    pub manifest_declared_identity: ManifestIdentity,
    pub observed_revisions: Vec<ObservedRevision>,
    /// Dynamic source path (provenance only, NOT part of any identity).
    pub source_path: String,
    /// Tool/provenance revision that performed the capture.
    pub capture_tool_revision: String,
    /// Capture timestamp (provenance only, NOT part of any identity).
    pub captured_at: String,
    /// Always `pending_human_decision` until a human decides.
    pub authority_status: String,
    /// Read-only family observation (best-effort recognizer output; never an
    /// authority call).
    pub family_observation: FamilyObservation,
    /// Non-empty when a revision could not be safely captured or a historical
    /// record is incomplete.
    pub blockers: Vec<String>,
    /// The member manifest this dossier is bound to.
    pub dossier_member_manifest: String,
    pub completion_marker: String,
    /// SHA-256 over the canonical dossier content (excludes this field).
    pub sealed_dossier_hash: String,
}

impl AuthorityDossier {
    /// Canonical, deterministic encoding of the dossier content EXCLUDING the
    /// `sealed_dossier_hash` field itself (which is the hash over this).
    fn canonical_content(&self) -> String {
        // Sort observed revisions by sha256 for determinism.
        let mut revs: Vec<&ObservedRevision> = self.observed_revisions.iter().collect();
        revs.sort_by(|a, b| a.sha256.cmp(&b.sha256));
        let mut out = String::new();
        out.push_str(&format!("schema={}\n", self.schema));
        out.push_str(&format!("logical_sample_id={}\n", self.logical_sample_id));
        out.push_str(&format!("packer_family={}\n", self.packer_family));
        out.push_str(&format!(
            "manifest_path={}\n",
            self.manifest_path.to_lowercase()
        ));
        out.push_str(&format!(
            "manifest_declared_identity={}|{}\n",
            self.manifest_declared_identity.sha256.to_lowercase(),
            self.manifest_declared_identity.size_bytes
        ));
        out.push_str(&format!(
            "source_path={}\n",
            self.source_path.to_lowercase()
        ));
        out.push_str(&format!(
            "capture_tool_revision={}\n",
            self.capture_tool_revision
        ));
        out.push_str(&format!("authority_status={}\n", self.authority_status));
        out.push_str(&format!(
            "family_observation={}|{}\n",
            self.family_observation.selected_family, self.family_observation.identify_verdict
        ));
        for b in &self.blockers {
            out.push_str(&format!("blocker={}\n", b));
        }
        out.push_str(&format!(
            "dossier_member_manifest={}\n",
            self.dossier_member_manifest.to_lowercase()
        ));
        out.push_str(&format!("completion_marker={}\n", self.completion_marker));
        for r in &revs {
            let pe = match &r.pe_identity {
                Some(p) => format!(
                    "machine={};pe32_plus={};entry={};image={};sections={}",
                    p.machine,
                    p.pe32_plus,
                    p.entry_rva,
                    p.size_of_image,
                    p.sections.join(",")
                ),
                None => String::new(),
            };
            out.push_str(&format!(
                "revision={}|{}|{}|{}|{}|{}\n",
                r.sha256.to_lowercase(),
                r.size_bytes,
                r.immutable_snapshot_path.to_lowercase(),
                r.availability,
                r.comparison_verdict,
                pe
            ));
        }
        out
    }

    /// Compute the sealed dossier hash (SHA-256, lowercase) over the canonical
    /// content. Deterministic: timestamps / source path are lowercased and are
    /// part of the content but never of any revision identity.
    pub fn compute_sealed_hash(&self) -> String {
        sha256_hex(self.canonical_content().as_bytes())
    }

    /// Fail-closed: recompute the sealed hash and require it equals the stored
    /// `sealed_dossier_hash`, and that the schema/completion/status invariants
    /// hold.
    pub fn verify_sealed(&self) -> Result<(), String> {
        if self.schema != DOSSIER_SCHEMA {
            return Err(format!(
                "dossier schema {:?} != {DOSSIER_SCHEMA}",
                self.schema
            ));
        }
        if self.completion_marker != COMPLETION_MARKER {
            return Err("dossier completion marker is missing".to_string());
        }
        if self.authority_status != STATUS_PENDING {
            return Err(format!(
                "dossier authority_status {:?} is not {STATUS_PENDING}",
                self.authority_status
            ));
        }
        let recomputed = self.compute_sealed_hash();
        if !recomputed.eq_ignore_ascii_case(&self.sealed_dossier_hash) {
            return Err(format!(
                "dossier sealed hash drift: recomputed {recomputed}, stored {}",
                self.sealed_dossier_hash
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Offline dossier producer
// ---------------------------------------------------------------------------

/// Input describing one candidate source to observe for the dossier.
#[derive(Debug, Clone)]
pub struct CandidateRevisionInput {
    /// The sha256 this candidate is believed to be (for `historical-record-only`
    /// entries whose file is gone).
    pub declared_sha256: String,
    /// The size this candidate is believed to be (historical-record-only).
    pub declared_size_bytes: u64,
    /// The live source path to capture, if the file still exists. `None` for a
    /// historical-record-only entry (file is gone).
    pub source_path: Option<PathBuf>,
}

/// A captured/observed revision for the dossier.
#[derive(Debug, Clone)]
struct ObservedOutcome {
    sha256: String,
    size_bytes: u64,
    availability: String,
    immutable_snapshot_path: String,
    comparison_verdict: String,
    pe_identity: Option<PeBaseIdentity>,
}

/// Produce an authority dossier for a logical sample.
///
/// - For each candidate with a live source, capture an immutable snapshot,
///   verify it, and extract hash/size/PE identity. Fail-closed if the source
///   changes during capture.
/// - For a candidate whose file is gone (historical record), register it as
///   `historical-record-only` (no fake snapshot).
/// - Comparison verdict is `matches_manifest` iff sha+size equal the manifest
///   identity, else `differs_from_manifest`.
/// - `authority_status` is always `pending_human_decision`.
///
/// `output_path` must be caller-provided (never `lab/cases/v2`). Returns the
/// dossier (already sealed) and writes the JSON dossier to `output_path`.
#[allow(clippy::too_many_arguments)]
pub fn produce_authority_dossier(
    logical_sample_id: &str,
    packer_family: &str,
    manifest_path: &Path,
    manifest_sha256: &str,
    manifest_size_bytes: u64,
    snapshot_root: &Path,
    candidates: &[CandidateRevisionInput],
    source_path: &Path,
    capture_tool_revision: &str,
    captured_at: &str,
    family_selected: &str,
    family_identify_verdict: &str,
    output_path: &Path,
) -> Result<AuthorityDossier, String> {
    sample_snapshot::validate_logical_sample_id(logical_sample_id)
        .map_err(|e| format!("invalid logical_sample_id: {e}"))?;
    let manifest_sha = sample_snapshot::canonical_hash(manifest_sha256);
    if !crate::sample_snapshot::validate_hash(&manifest_sha).is_ok() {
        return Err("manifest sha256 is malformed".to_string());
    }

    let mut observed = Vec::new();
    let mut blockers = Vec::new();
    for cand in candidates {
        match &cand.source_path {
            Some(src) => {
                // Fail-closed capture: any capture error (incl. source changed
                // during the two reads) aborts the whole dossier.
                let snap =
                    capture_snapshot(src, snapshot_root, logical_sample_id, capture_tool_revision)
                        .map_err(|e| {
                            format!(
                                "capture failed for {} ({}): {e}",
                                src.display(),
                                cand.declared_sha256
                            )
                        })?;
                if snap.capture_status != sample_snapshot::CaptureStatus::Captured {
                    return Err(format!(
                        "source changed during capture of {}; refusing to seal dossier",
                        src.display()
                    ));
                }
                // Verified resolve: re-read the snapshot from disk and require it
                // to match the captured hash/size (never trust the in-memory struct
                // alone).
                let verified =
                    verified_read_snapshot(snapshot_root, logical_sample_id, &snap.snapshot_sha256)
                        .map_err(|e| {
                            format!(
                                "verified resolve failed after capture for {}: {e}",
                                src.display()
                            )
                        })?;
                let pe = snap.pe_identity.clone();
                observed.push(ObservedOutcome {
                    sha256: verified.snapshot_sha256.clone(),
                    size_bytes: verified.snapshot_size_bytes,
                    availability: AVAIL_VERIFIED.to_string(),
                    immutable_snapshot_path: verified.snapshot_abs_path.display().to_string(),
                    comparison_verdict: if verified
                        .snapshot_sha256
                        .eq_ignore_ascii_case(&manifest_sha)
                        && verified.snapshot_size_bytes == manifest_size_bytes
                    {
                        MATCHES_MANIFEST.to_string()
                    } else {
                        DIFFERS_FROM_MANIFEST.to_string()
                    },
                    pe_identity: pe.map(|p| PeBaseIdentity::from(&p)),
                });
            }
            None => {
                // Historical record only: file is gone, no snapshot to create.
                let sha = sample_snapshot::canonical_hash(&cand.declared_sha256);
                if !crate::sample_snapshot::validate_hash(&sha).is_ok() {
                    return Err("historical revision sha256 is malformed".to_string());
                }
                observed.push(ObservedOutcome {
                    sha256: sha.clone(),
                    size_bytes: cand.declared_size_bytes,
                    availability: AVAIL_HISTORICAL_RECORD_ONLY.to_string(),
                    immutable_snapshot_path: String::new(),
                    comparison_verdict: if sha.eq_ignore_ascii_case(&manifest_sha)
                        && cand.declared_size_bytes == manifest_size_bytes
                    {
                        MATCHES_MANIFEST.to_string()
                    } else {
                        DIFFERS_FROM_MANIFEST.to_string()
                    },
                    pe_identity: None,
                });
                blockers.push(format!(
                    "revision {sha} is historical-record-only (file absent); no snapshot"
                ));
            }
        }
    }

    let observed_revisions: Vec<ObservedRevision> = observed
        .into_iter()
        .map(|o| ObservedRevision {
            sha256: o.sha256,
            size_bytes: o.size_bytes,
            immutable_snapshot_path: o.immutable_snapshot_path,
            availability: o.availability,
            comparison_verdict: o.comparison_verdict,
            pe_identity: o.pe_identity,
        })
        .collect();

    let mut dossier = AuthorityDossier {
        schema: DOSSIER_SCHEMA.to_string(),
        logical_sample_id: logical_sample_id.to_string(),
        packer_family: packer_family.to_string(),
        manifest_path: manifest_path.display().to_string(),
        manifest_declared_identity: ManifestIdentity {
            sha256: manifest_sha.clone(),
            size_bytes: manifest_size_bytes,
        },
        observed_revisions,
        source_path: source_path.display().to_string(),
        capture_tool_revision: capture_tool_revision.to_string(),
        captured_at: captured_at.to_string(),
        authority_status: STATUS_PENDING.to_string(),
        family_observation: FamilyObservation {
            selected_family: family_selected.to_string(),
            identify_verdict: family_identify_verdict.to_string(),
        },
        blockers,
        dossier_member_manifest: manifest_path.display().to_string(),
        completion_marker: COMPLETION_MARKER.to_string(),
        sealed_dossier_hash: String::new(),
    };
    let sealed = dossier.compute_sealed_hash();
    dossier.sealed_dossier_hash = sealed;
    dossier
        .verify_sealed()
        .map_err(|e| format!("internal seal error: {e}"))?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create output dir {}: {e}", parent.display()))?;
    }
    let json = serde_json::to_vec_pretty(&dossier)
        .map_err(|e| format!("cannot serialize dossier: {e}"))?;
    std::fs::write(output_path, json)
        .map_err(|e| format!("cannot write dossier {}: {e}", output_path.display()))?;
    Ok(dossier)
}

// ---------------------------------------------------------------------------
// Decision schema (`mida.sample-authority-decision/v1`)
// ---------------------------------------------------------------------------

/// `mida.sample-authority-decision/v1` — an externally-provided human decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityDecision {
    pub schema: String,
    pub logical_sample_id: String,
    pub selected_revision_sha256: String,
    pub selected_revision_size: u64,
    /// The dossier this decision applies to.
    pub dossier_sha256: String,
    /// `retain_manifest` / `promote_revision` / `reject_revision`.
    pub decision: String,
    pub decision_reason: String,
    pub decided_by: String,
    pub decided_at: String,
    /// Human acknowledgements (all must be present).
    pub acknowledgement: Vec<String>,
}

// ---------------------------------------------------------------------------
// Promotion gate (pure offline verifier)
// ---------------------------------------------------------------------------

/// The acknowledgement lines a valid decision must carry.
pub const ACK_SOURCE_NOT_AUTHORITY: &str = "dynamic source path is not authority";
pub const ACK_NO_AUTOMATIC_MANIFEST_MUTATION: &str = "no automatic manifest mutation";
pub const ACK_NO_PERFECT_UNPACK_ACCEPTANCE: &str = "no perfect-unpack acceptance implied";

/// A promotion plan emitted for a `promote_revision` decision. It NEVER mutates
/// a manifest; it only tells a human what the manifest update would look like.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionPlan {
    pub logical_sample_id: String,
    pub promote_sha256: String,
    pub promote_size_bytes: u64,
    /// The immutable snapshot path the promoted revision came from.
    pub snapshot_path: String,
    /// The manifest path that WOULD be updated (human applies it manually).
    pub target_manifest_path: String,
    /// Human-only instructions; never wired to a write.
    pub note: String,
}

/// Outcome of applying a human decision through the promotion gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionOutcome {
    /// `retain_manifest`: keep the current manifest identity. Safe to keep
    /// staging as-is (manifest protected_input remains the authority).
    RetainManifest,
    /// `promote_revision`: emit a promotion plan for a human to apply.
    Promote(PromotionPlan),
    /// `reject_revision`: the revision must not enter staging.
    RejectRevision,
}

/// Validate a human decision against a dossier and apply it (offline). Fail
/// closed on:
/// - missing/unknown decision;
/// - dossier sealed hash mismatch;
/// - selected revision not present in the dossier;
/// - hash/size mismatch;
/// - missing acknowledgements;
/// - `retain_manifest` selecting a non-manifest revision;
/// - `promote_revision` selecting a revision with no verified snapshot
///   (e.g. historical-record-only cannot be promoted).
///
/// Never mutates a manifest. For `promote_revision` it returns a plan only.
#[allow(clippy::too_many_arguments)]
pub fn apply_decision(
    dossier: &AuthorityDossier,
    decision: &AuthorityDecision,
    snapshot_root: &Path,
    target_manifest_path: &Path,
) -> Result<DecisionOutcome, String> {
    // Dossier must be well-formed and sealed.
    dossier.verify_sealed()?;
    if decision.schema != DECISION_SCHEMA {
        return Err(format!(
            "decision schema {:?} != {DECISION_SCHEMA}",
            decision.schema
        ));
    }
    if decision.logical_sample_id != dossier.logical_sample_id {
        return Err("decision logical_sample_id does not match the dossier".to_string());
    }
    if !decision
        .dossier_sha256
        .eq_ignore_ascii_case(&dossier.sealed_dossier_hash)
    {
        return Err(format!(
            "decision dossier_sha256 {} != dossier sealed {}",
            decision.dossier_sha256, dossier.sealed_dossier_hash
        ));
    }
    // Acknowledgements must all be present.
    for ack in [
        ACK_SOURCE_NOT_AUTHORITY,
        ACK_NO_AUTOMATIC_MANIFEST_MUTATION,
        ACK_NO_PERFECT_UNPACK_ACCEPTANCE,
    ] {
        if !decision.acknowledgement.iter().any(|a| a == ack) {
            return Err(format!("decision is missing acknowledgement {ack:?}"));
        }
    }
    let sel_sha = sample_snapshot::canonical_hash(&decision.selected_revision_sha256);
    // The selected revision must be present in the dossier.
    let rev = dossier
        .observed_revisions
        .iter()
        .find(|r| r.sha256.eq_ignore_ascii_case(&sel_sha))
        .ok_or_else(|| format!("decision revision {sel_sha} is not in the dossier"))?;
    if rev.size_bytes != decision.selected_revision_size {
        return Err(format!(
            "decision size {} != dossier revision size {}",
            decision.selected_revision_size, rev.size_bytes
        ));
    }

    match decision.decision.as_str() {
        DECISION_RETAIN_MANIFEST => {
            // retain_manifest may only select the current manifest identity.
            let manifest_sha =
                sample_snapshot::canonical_hash(&dossier.manifest_declared_identity.sha256);
            if !rev.sha256.eq_ignore_ascii_case(&manifest_sha)
                || rev.size_bytes != dossier.manifest_declared_identity.size_bytes
            {
                return Err("retain_manifest must select the current manifest identity".to_string());
            }
            Ok(DecisionOutcome::RetainManifest)
        }
        DECISION_PROMOTE_REVISION => {
            // Only a verified snapshot can be promoted (never historical-record-only).
            if rev.availability != AVAIL_VERIFIED {
                return Err(format!(
                    "revision {sel_sha} is {}. A {AVAIL_HISTORICAL_RECORD_ONLY} revision \
                     cannot be promoted (no snapshot)",
                    rev.availability
                ));
            }
            // Re-read the verified snapshot and re-check hash/size from disk.
            let verified =
                verified_read_snapshot(snapshot_root, &dossier.logical_sample_id, &rev.sha256)
                    .map_err(|e| format!("cannot re-verify promoted snapshot: {e}"))?;
            if !verified.snapshot_sha256.eq_ignore_ascii_case(&rev.sha256)
                || verified.snapshot_size_bytes != rev.size_bytes
            {
                return Err("promoted snapshot re-verification failed (hash/size)".to_string());
            }
            Ok(DecisionOutcome::Promote(PromotionPlan {
                logical_sample_id: dossier.logical_sample_id.clone(),
                promote_sha256: rev.sha256.clone(),
                promote_size_bytes: rev.size_bytes,
                snapshot_path: rev.immutable_snapshot_path.clone(),
                target_manifest_path: target_manifest_path.display().to_string(),
                note: "HUMAN-APPLY ONLY: update the manifest protected_input to this \
                       hash/size; no automatic manifest write is performed by this verifier."
                    .to_string(),
            }))
        }
        DECISION_REJECT_REVISION => Ok(DecisionOutcome::RejectRevision),
        other => Err(format!("unknown decision {other:?}")),
    }
}

/// A `mida.sample-authority-decision/v1` template with a given decision and the
/// three required acknowledgements pre-filled. Does NOT mark anything accepted.
pub fn pending_decision_template(
    logical_sample_id: &str,
    dossier_sha256: &str,
    decision: &str,
) -> AuthorityDecision {
    AuthorityDecision {
        schema: DECISION_SCHEMA.to_string(),
        logical_sample_id: logical_sample_id.to_string(),
        selected_revision_sha256: String::new(),
        selected_revision_size: 0,
        dossier_sha256: dossier_sha256.to_string(),
        decision: decision.to_string(),
        decision_reason: "pending human review".to_string(),
        decided_by: "pending".to_string(),
        decided_at: "pending".to_string(),
        acknowledgement: vec![
            ACK_SOURCE_NOT_AUTHORITY.to_string(),
            ACK_NO_AUTOMATIC_MANIFEST_MUTATION.to_string(),
            ACK_NO_PERFECT_UNPACK_ACCEPTANCE.to_string(),
        ],
    }
}

/// SHA-256 (lowercase) of a byte slice.
fn sha256_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in d {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Deterministic JSON (for stable snapshot of a dossier/decision in tests).
pub fn to_deterministic_json<T: Serialize>(v: &T) -> Result<String, serde_json::Error> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"  ");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    v.serialize(&mut ser)?;
    String::from_utf8(buf).map_err(|_| {
        serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "non-utf8 json",
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("mida_authority_{tag}_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn write_bytes(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    fn sha256(bytes: &[u8]) -> String {
        crate::sample_snapshot::sha256_hex(bytes)
    }

    /// Build a candidate with a live source.
    fn live_candidate(src: &Path, declared_sha: &str, size: u64) -> CandidateRevisionInput {
        CandidateRevisionInput {
            declared_sha256: declared_sha.to_string(),
            declared_size_bytes: size,
            source_path: Some(src.to_path_buf()),
        }
    }

    /// A historical-record-only candidate (file gone).
    fn historical_candidate(sha: &str, size: u64) -> CandidateRevisionInput {
        CandidateRevisionInput {
            declared_sha256: sha.to_string(),
            declared_size_bytes: size,
            source_path: None,
        }
    }

    /// Produce a dossier for the given candidates against a manifest identity.
    fn make_dossier(
        root: &Path,
        manifest_sha: &str,
        manifest_size: u64,
        candidates: &[CandidateRevisionInput],
        output: &Path,
    ) -> Result<AuthorityDossier, String> {
        produce_authority_dossier(
            "gto_launcher",
            "ahk_gto",
            &root.join("gto_launcher.json"),
            manifest_sha,
            manifest_size,
            &root.join("snapshots"),
            candidates,
            &root.join("launcher.exe"),
            "rev@r4",
            "2026-08-07T00:00:00Z",
            "ahk_gto",
            "identify: GTO generic-no-gate",
            output,
        )
    }

    fn make_decision(
        dossier: &AuthorityDossier,
        selected_sha: &str,
        selected_size: u64,
        decision: &str,
    ) -> AuthorityDecision {
        AuthorityDecision {
            schema: DECISION_SCHEMA.to_string(),
            logical_sample_id: dossier.logical_sample_id.clone(),
            selected_revision_sha256: selected_sha.to_string(),
            selected_revision_size: selected_size,
            dossier_sha256: dossier.sealed_dossier_hash.clone(),
            decision: decision.to_string(),
            decision_reason: "test".to_string(),
            decided_by: "test-human".to_string(),
            decided_at: "2026-08-07T12:00:00Z".to_string(),
            acknowledgement: vec![
                ACK_SOURCE_NOT_AUTHORITY.to_string(),
                ACK_NO_AUTOMATIC_MANIFEST_MUTATION.to_string(),
                ACK_NO_PERFECT_UNPACK_ACCEPTANCE.to_string(),
            ],
        }
    }

    // ------------------------------------------------------------------
    // 1. Manifest-bound revision -> matches_manifest; new dynamic -> differs.
    // ------------------------------------------------------------------
    #[test]
    fn manifest_and_dynamic_revision_verdicts_and_pending() {
        let root = temp_dir("dossier_basic");
        // The manifest-bound revision (matches the manifest identity).
        let manifest_bytes = b"MANIFEST-AUTHORITY-REVISION";
        let manifest_sha = sha256(manifest_bytes);
        let manifest_size = manifest_bytes.len() as u64;
        let src_manifest = root.join("launcher.exe");
        write_bytes(&src_manifest, manifest_bytes);
        // A new dynamic revision (differs from the manifest identity).
        let dynamic_bytes = b"NEW-DYNAMIC-REVISION-UNKNOWN";
        let dynamic_sha = sha256(dynamic_bytes);
        let dynamic_size = dynamic_bytes.len() as u64;
        let src_dynamic = root.join("launcher_dynamic.exe");
        write_bytes(&src_dynamic, dynamic_bytes);

        let candidates = vec![
            live_candidate(&src_manifest, &manifest_sha, manifest_size),
            live_candidate(&src_dynamic, &dynamic_sha, dynamic_size),
        ];
        let output = root.join("dossier.json");
        let dossier = make_dossier(&root, &manifest_sha, manifest_size, &candidates, &output)
            .expect("dossier produced");
        dossier.verify_sealed().unwrap();
        assert!(output.is_file(), "dossier written to caller-provided path");

        // Manifest-bound revision -> matches_manifest.
        let manifest_rev = dossier
            .observed_revisions
            .iter()
            .find(|r| r.sha256 == manifest_sha)
            .expect("manifest revision present");
        assert_eq!(manifest_rev.comparison_verdict, MATCHES_MANIFEST);
        assert_eq!(manifest_rev.availability, AVAIL_VERIFIED);
        // New dynamic revision -> differs_from_manifest.
        let dynamic_rev = dossier
            .observed_revisions
            .iter()
            .find(|r| r.sha256 == dynamic_sha)
            .expect("dynamic revision present");
        assert_eq!(dynamic_rev.comparison_verdict, DIFFERS_FROM_MANIFEST);
        assert_eq!(dynamic_rev.availability, AVAIL_VERIFIED);
        // Everything is pending.
        assert_eq!(dossier.authority_status, STATUS_PENDING);
        // No accepted/promoted/authority fields are auto-populated.
        let json = to_deterministic_json(&dossier).unwrap();
        assert!(
            !json.contains("accepted") && !json.contains("current_authority"),
            "{json}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 3. Source changes between the two capture reads -> dossier fails closed.
    // ------------------------------------------------------------------
    #[test]
    fn source_change_during_capture_fails_dossier() {
        let root = temp_dir("dossier_source_change");
        let bytes = b"UNSTABLE-SOURCE";
        let _sha = sha256(bytes);
        let _size = bytes.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, bytes);
        let snap_root = root.join("snapshots");

        // Use the capture test seam to change the source between the two reads.
        let hook_src = src.clone();
        let err = crate::sample_snapshot::capture_snapshot_with_hooks(
            &src,
            &snap_root,
            "gto_launcher",
            "rev@r4",
            Some(Box::new(move || {
                std::fs::write(&hook_src, b"CHANGED-DURING-CAPTURE").unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            crate::sample_snapshot::CaptureError::SourceChangedDuringCapture
        );
        // The dossier producer propagates a capture failure fail-closed. Use a
        // fresh (stable) source that fails capture deterministically — an EMPTY
        // source is a capture error the producer must propagate, so no dossier is
        // sealed.
        let empty_src = root.join("empty_source.exe");
        write_bytes(&empty_src, b"");
        let candidates = vec![live_candidate(&empty_src, &"0".repeat(64), 0)];
        let output = root.join("dossier.json");
        let err = make_dossier(&root, &"0".repeat(64), 0, &candidates, &output).unwrap_err();
        assert!(
            err.contains("capture failed"),
            "a capture failure must fail the dossier: {err}"
        );
        // No dossier written.
        assert!(!output.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 4. Snapshot truncated/replaced/deleted -> dossier or decision verifier
    //    rejects.
    // ------------------------------------------------------------------
    #[test]
    fn tampered_snapshot_rejected_by_dossier_or_gate() {
        let root = temp_dir("dossier_tamper");
        let bytes = b"AUTHORITY-REVISION-PAYLOAD";
        let sha = sha256(bytes);
        let size = bytes.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, bytes);
        let candidates = vec![live_candidate(&src, &sha, size)];
        let output = root.join("dossier.json");
        let dossier = make_dossier(&root, &sha, size, &candidates, &output).unwrap();
        let rev = dossier
            .observed_revisions
            .iter()
            .find(|r| r.sha256 == sha)
            .unwrap();
        let snap_path = Path::new(&rev.immutable_snapshot_path);
        let manifest_path = root.join("gto_launcher.json");
        let snap_root = root.join("snapshots");

        // (a) Truncate the snapshot -> re-verification at the gate fails.
        let truncated = std::fs::read(snap_path).unwrap();
        std::fs::write(snap_path, &truncated[..truncated.len() / 2]).unwrap();
        let dec = make_decision(&dossier, &sha, size, DECISION_PROMOTE_REVISION);
        let err = apply_decision(&dossier, &dec, &snap_root, &manifest_path).unwrap_err();
        assert!(
            err.contains("re-verify"),
            "truncated snapshot rejected: {err}"
        );

        // (b) Delete the snapshot -> re-verification fails.
        std::fs::remove_file(snap_path).unwrap();
        let err = apply_decision(&dossier, &dec, &snap_root, &manifest_path).unwrap_err();
        assert!(
            err.contains("re-verify") || err.contains("cannot re-verify"),
            "deleted snapshot: {err}"
        );

        // (c) Tampering the dossier sealed hash is caught by verify_sealed.
        let mut tampered = dossier.clone();
        tampered.sealed_dossier_hash = "0".repeat(64);
        assert!(
            tampered.verify_sealed().is_err(),
            "tampered sealed hash rejected"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 5. Historical-record-only revision cannot be promoted.
    // ------------------------------------------------------------------
    #[test]
    fn historical_record_only_cannot_be_promoted() {
        let root = temp_dir("dossier_historical");
        let bytes = b"MANIFEST-REV";
        let sha = sha256(bytes);
        let size = bytes.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, bytes);
        // A historical revision whose file is gone (79e26e91... shape).
        let hist_sha = "7".repeat(64);
        let hist_size = 13_633_536;
        let candidates = vec![
            live_candidate(&src, &sha, size),
            historical_candidate(&hist_sha, hist_size),
        ];
        let output = root.join("dossier.json");
        let dossier = make_dossier(&root, &sha, size, &candidates, &output).unwrap();
        let hist_rev = dossier
            .observed_revisions
            .iter()
            .find(|r| r.sha256 == hist_sha)
            .unwrap();
        assert_eq!(hist_rev.availability, AVAIL_HISTORICAL_RECORD_ONLY);
        assert_eq!(hist_rev.comparison_verdict, DIFFERS_FROM_MANIFEST);
        assert!(
            !dossier.blockers.is_empty(),
            "historical record is a blocker"
        );

        // Promoting the historical-record-only revision must be rejected.
        let dec = make_decision(&dossier, &hist_sha, hist_size, DECISION_PROMOTE_REVISION);
        let err = apply_decision(
            &dossier,
            &dec,
            &root.join("snapshots"),
            &root.join("gto_launcher.json"),
        )
        .unwrap_err();
        assert!(
            err.contains("cannot be promoted"),
            "historical-record-only cannot be promoted: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 6-9. Decision verifier fail-closed cases.
    // ------------------------------------------------------------------
    #[test]
    fn decision_fail_closed_cases() {
        let root = temp_dir("dossier_decision");
        let bytes = b"MANIFEST-REV";
        let sha = sha256(bytes);
        let size = bytes.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, bytes);
        let candidates = vec![live_candidate(&src, &sha, size)];
        let output = root.join("dossier.json");
        let dossier = make_dossier(&root, &sha, size, &candidates, &output).unwrap();
        let snap_root = root.join("snapshots");
        let manifest_path = root.join("gto_launcher.json");

        // (6) Decision references a revision outside the dossier.
        let outside_sha = "a".repeat(64);
        let dec = make_decision(&dossier, &outside_sha, 1, DECISION_PROMOTE_REVISION);
        let err = apply_decision(&dossier, &dec, &snap_root, &manifest_path).unwrap_err();
        assert!(
            err.contains("not in the dossier"),
            "outside revision: {err}"
        );

        // (7) Decision dossier hash mismatch.
        let mut dec2 = make_decision(&dossier, &sha, size, DECISION_RETAIN_MANIFEST);
        dec2.dossier_sha256 = "f".repeat(64);
        let err = apply_decision(&dossier, &dec2, &snap_root, &manifest_path).unwrap_err();
        assert!(
            err.contains("dossier_sha256"),
            "dossier hash mismatch: {err}"
        );

        // (8) Decision hash correct but size wrong.
        let dec3 = make_decision(&dossier, &sha, size + 1, DECISION_RETAIN_MANIFEST);
        let err = apply_decision(&dossier, &dec3, &snap_root, &manifest_path).unwrap_err();
        assert!(err.contains("size"), "size mismatch: {err}");

        // (9) retain_manifest selecting a non-manifest revision.
        let other_bytes = b"NOT-MANIFEST-REV";
        let other_sha = sha256(other_bytes);
        let other_size = other_bytes.len() as u64;
        let src2 = root.join("other.exe");
        write_bytes(&src2, other_bytes);
        let candidates2 = vec![live_candidate(&src2, &other_sha, other_size)];
        let output2 = root.join("dossier2.json");
        let dossier2 = make_dossier(&root, &sha, size, &candidates2, &output2).unwrap();
        let dec4 = make_decision(&dossier2, &other_sha, other_size, DECISION_RETAIN_MANIFEST);
        let err =
            apply_decision(&dossier2, &dec4, &root.join("snapshots"), &manifest_path).unwrap_err();
        assert!(
            err.contains("must select the current manifest identity"),
            "retain_manifest non-manifest: {err}"
        );

        // Missing acknowledgements -> reject.
        let mut dec5 = make_decision(&dossier, &sha, size, DECISION_RETAIN_MANIFEST);
        dec5.acknowledgement = vec!["no automatic manifest mutation".to_string()];
        let err = apply_decision(&dossier, &dec5, &snap_root, &manifest_path).unwrap_err();
        assert!(err.contains("acknowledgement"), "missing ack: {err}");

        // Unknown decision -> reject.
        let dec6 = make_decision(&dossier, &sha, size, "bogus_decision");
        let err = apply_decision(&dossier, &dec6, &snap_root, &manifest_path).unwrap_err();
        assert!(err.contains("unknown decision"), "unknown decision: {err}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 10. promote_revision only generates a plan; never mutates the manifest.
    // ------------------------------------------------------------------
    #[test]
    fn promote_revision_generates_plan_and_does_not_touch_manifest() {
        let root = temp_dir("dossier_promote");
        let bytes = b"PROMOTE-REV";
        let sha = sha256(bytes);
        let size = bytes.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, bytes);
        let manifest_path = root.join("gto_launcher.json");
        let manifest_before = br#"{"case_id":"gto_launcher","sha":"4d5770af..."}"#;
        write_bytes(&manifest_path, manifest_before);
        // The dossier's manifest identity is the OLD manifest sha; the promoted
        // revision differs from it.
        let old_sha = "4".repeat(64);
        let old_size = 8_583_680;
        let candidates = vec![live_candidate(&src, &sha, size)];
        let output = root.join("dossier.json");
        let dossier = make_dossier(&root, &old_sha, old_size, &candidates, &output).unwrap();

        let dec = make_decision(&dossier, &sha, size, DECISION_PROMOTE_REVISION);
        let outcome =
            apply_decision(&dossier, &dec, &root.join("snapshots"), &manifest_path).unwrap();
        match outcome {
            DecisionOutcome::Promote(plan) => {
                assert_eq!(plan.promote_sha256, sha);
                assert_eq!(plan.promote_size_bytes, size);
                assert!(plan.note.contains("HUMAN-APPLY ONLY"), "plan is human-only");
            }
            _ => panic!("expected a promotion plan"),
        }
        // The manifest is byte-identical (verifier never writes it).
        assert_eq!(
            std::fs::read(&manifest_path).unwrap(),
            manifest_before,
            "manifest must not be mutated"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 11. pending/missing decision blocks staging.
    // ------------------------------------------------------------------
    #[test]
    fn pending_decision_blocks_staging() {
        let root = temp_dir("dossier_pending");
        let bytes = b"PENDING-REV";
        let sha = sha256(bytes);
        let size = bytes.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, bytes);
        let candidates = vec![live_candidate(&src, &sha, size)];
        let output = root.join("dossier.json");
        let dossier = make_dossier(&root, &sha, size, &candidates, &output).unwrap();

        // A pending template (empty selected revision) must be rejected by the
        // decision verifier (revision not in dossier / size 0 mismatch).
        let pending = pending_decision_template(
            "gto_launcher",
            &dossier.sealed_dossier_hash,
            DECISION_PROMOTE_REVISION,
        );
        let err = apply_decision(
            &dossier,
            &pending,
            &root.join("snapshots"),
            &root.join("gto_launcher.json"),
        )
        .unwrap_err();
        assert!(
            err.contains("not in the dossier") || err.contains("size"),
            "a pending/empty decision must block staging: {err}"
        );
        // authority_status stays pending.
        assert_eq!(dossier.authority_status, STATUS_PENDING);
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 12. Timestamp / source path change does not change revision identity.
    // ------------------------------------------------------------------
    #[test]
    fn timestamp_and_source_path_do_not_affect_revision_identity() {
        let root = temp_dir("dossier_time");
        let bytes = b"TIME-INDEPENDENT-REV";
        let sha = sha256(bytes);
        let size = bytes.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, bytes);
        let candidates = vec![live_candidate(&src, &sha, size)];
        let out_a = root.join("a.json");
        let out_b = root.join("b.json");

        // Two dossiers with different timestamps/source paths.
        let d_a = produce_authority_dossier(
            "gto_launcher",
            "ahk_gto",
            &root.join("gto_launcher.json"),
            &sha,
            size,
            &root.join("snapshots"),
            &candidates,
            &root.join("src_a.exe"),
            "rev@r4",
            "2026-08-07T00:00:00Z",
            "ahk_gto",
            "identify",
            &out_a,
        )
        .unwrap();
        let d_b = produce_authority_dossier(
            "gto_launcher",
            "ahk_gto",
            &root.join("gto_launcher.json"),
            &sha,
            size,
            &root.join("snapshots"),
            &candidates,
            &root.join("src_b.exe"),
            "rev@r4",
            "2026-08-08T00:00:00Z",
            "ahk_gto",
            "identify",
            &out_b,
        )
        .unwrap();

        // The revision ID (sha) is identical; the source path / timestamp are
        // provenance only and never part of the identity.
        let rev_a = d_a.observed_revisions[0].sha256.clone();
        let rev_b = d_b.observed_revisions[0].sha256.clone();
        assert_eq!(rev_a, rev_b);
        assert_eq!(rev_a, sha);
        assert_eq!(d_a.observed_revisions[0].size_bytes, size);
        assert_ne!(
            d_a.source_path, d_b.source_path,
            "source path is provenance"
        );
        assert_ne!(d_a.captured_at, d_b.captured_at, "timestamp is provenance");
        // But the sealed dossier hash differs (the provenance fields are in the
        // sealed content) — identity is unaffected.
        assert_ne!(d_a.sealed_dossier_hash, d_b.sealed_dossier_hash);
        std::fs::remove_dir_all(&root).unwrap();
    }

    // ------------------------------------------------------------------
    // 13. PE base identity is captured when the snapshot is a valid PE.
    // ------------------------------------------------------------------
    #[test]
    fn pe_identity_captured_for_pe_snapshot() {
        let root = temp_dir("dossier_pe");
        let pe = minimal_pe_bytes();
        let sha = sha256(&pe);
        let size = pe.len() as u64;
        let src = root.join("launcher.exe");
        write_bytes(&src, &pe);
        let candidates = vec![live_candidate(&src, &sha, size)];
        let output = root.join("dossier.json");
        let dossier = make_dossier(&root, &sha, size, &candidates, &output).unwrap();
        let rev = &dossier.observed_revisions[0];
        let pe_id = rev.pe_identity.as_ref().expect("PE identity captured");
        assert!(pe_id.pe32_plus);
        assert_eq!(pe_id.machine, 0x14c); // the minimal PE declares machine 0x14c
        assert_eq!(pe_id.sections, vec![".text".to_string()]);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A tiny valid PE (PE32+ DOS + NT headers + one section).
    fn minimal_pe_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"MZ");
        v.resize(0x40, 0);
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        v.resize(0x80, 0);
        v.extend_from_slice(b"PE\0\0");
        v.extend_from_slice(&0x14cu16.to_le_bytes()); // machine AMD64
        v.extend_from_slice(&1u16.to_le_bytes()); // sections
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&240u16.to_le_bytes()); // opt header size PE32+
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0x20bu16.to_le_bytes()); // PE32+ magic
        let nt_offset = 0x80usize;
        let opt_start = nt_offset + 4 + 20;
        v.resize(opt_start + 240, 0);
        let base = opt_start + 240;
        v.resize(base + 40 + 48, 0);
        v[base..base + 8].copy_from_slice(b".text\0\0\0");
        v
    }
}
