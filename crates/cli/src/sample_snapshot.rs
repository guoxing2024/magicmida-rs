//! Immutable sample snapshot & revisioned identity lifecycle (G3-R2).
//!
//! The protected GTO sample at `D:\Tools\RE\dumps\gto\启动器.exe` is a DYNAMIC
//! source path that is frequently overwritten by automation, so binding a case
//! manifest directly to that path is unstable. This module establishes a
//! "freeze the sample, then stage/preflight" flow: a source file is captured
//! into a content-addressed, immutable snapshot; the snapshot hash/size become
//! the case identity; the source path is recorded only as provenance.
//!
//! Key properties:
//! - revision is hash-derived (`<logical_id>@sha256-<fullhash>`), not a bare
//!   timestamp, so the same bytes always map to the same revision and a change
//!   of bytes always yields a different revision;
//! - snapshots are content-addressed under a snapshot root, so a same-name file
//!   update never overwrites an older revision;
//! - a source file that changes during capture is rejected
//!   (`source_changed_during_capture`) and no half-written snapshot is kept;
//! - this module is pure offline: it reads/copies files and computes hashes. It
//!   never launches a process and never touches `lab/cases/v2/*` sealed
//!   manifests.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// The filename used for a snapshot inside its content-addressed directory.
pub const SNAPSHOT_FILENAME: &str = "snapshot.bin";

/// Status of a capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureStatus {
    /// The snapshot was accepted: source stable before/after and snapshot
    /// bytes match the source bytes.
    Captured,
    /// The source changed size/hash during capture; the snapshot was rejected.
    SourceChangedDuringCapture,
}

impl fmt::Display for CaptureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Captured => write!(f, "captured"),
            Self::SourceChangedDuringCapture => write!(f, "source_changed_during_capture"),
        }
    }
}

/// Basic PE identity captured during snapshot (read-only parse; never launch).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeIdentitySnapshot {
    pub pe32_plus: bool,
    pub machine: u16,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub section_names: Vec<String>,
}

/// One immutable snapshot of one logical sample revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SampleSnapshot {
    pub logical_sample_id: String,
    /// Hash-derived revision id: `<logical_id>@sha256-<fullhash>`.
    pub revision: String,
    /// The source path this snapshot was captured from (provenance only).
    pub source_path: PathBuf,
    /// ISO-ish capture time (seconds since epoch is fine; not part of the id).
    pub captured_at: String,
    pub source_sha256: String,
    pub snapshot_sha256: String,
    pub source_size_bytes: u64,
    pub snapshot_size_bytes: u64,
    pub pe_identity: Option<PeIdentitySnapshot>,
    /// Packer-family observation from `dual_select_packer` (best-effort; the
    /// snapshot module does not decide authority).
    pub packer_family_observation: Option<String>,
    pub capture_status: CaptureStatus,
    /// Tool/provenance revision that performed the capture.
    pub provenance_tool_revision: String,
    /// Absolute path of the immutable snapshot file on disk.
    pub snapshot_abs_path: PathBuf,
    /// The snapshot root this snapshot lives under.
    pub snapshot_root: PathBuf,
}

/// Build a hash-derived revision id for a logical sample.
pub fn revision_id(logical_sample_id: &str, sha256: &str) -> String {
    format!("{logical_sample_id}@sha256-{sha256}")
}

/// Compute the SHA-256 (lowercase hex) of a file's bytes.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let data = fs::read(path)?;
    Ok(sha256_hex(&data))
}

/// Compute the SHA-256 (lowercase hex) of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Read-only PE identity parse of a byte buffer (best-effort).
fn pe_identity_of(bytes: &[u8]) -> Option<PeIdentitySnapshot> {
    use mida_pe::PeHeader;
    let header = PeHeader::from_bytes(bytes).ok()?;
    let pe32_plus = header.nt_headers.optional_header.magic == 0x20b; // IMAGE_NT_OPTIONAL_HDR64_MAGIC
    let machine = header.nt_headers.file_header.machine;
    Some(PeIdentitySnapshot {
        pe32_plus,
        machine,
        entry_point_rva: header.entry_point,
        size_of_image: header.size_of_image(),
        section_names: header.sections.iter().map(|s| s.name.clone()).collect(),
    })
}

/// Errors from a snapshot capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    SourceUnreadable(String),
    SnapshotWriteFailed(String),
    SourceChangedDuringCapture,
    SourceEmpty,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceUnreadable(e) => write!(f, "source unreadable: {e}"),
            Self::SnapshotWriteFailed(e) => write!(f, "snapshot write failed: {e}"),
            Self::SourceChangedDuringCapture => {
                write!(f, "source_changed_during_capture")
            }
            Self::SourceEmpty => write!(f, "source is empty; refusing to snapshot"),
        }
    }
}

/// Capture an immutable snapshot of `source` into `snapshot_root`.
///
/// Procedure (fail-closed):
/// 1. read source bytes + size (first sample);
/// 2. if empty -> `SourceEmpty`;
/// 3. write snapshot to a temp file in a content-addressed temp dir named by
///    the source hash;
/// 4. recompute the snapshot's hash/size;
/// 5. re-read the source bytes + size (second sample);
/// 6. accept only if: first==second size, first==second hash,
///    snapshot hash == source hash, snapshot size == source size;
/// 7. otherwise delete the temp snapshot and return
///    `SourceChangedDuringCapture` (no staging).
///
/// Snapshots are content-addressed: `<snapshot_root>/<logical_id>/<sha256>/snapshot.bin`,
/// so a same-name source update never overwrites an older revision.
pub fn capture_snapshot(
    source: &Path,
    snapshot_root: &Path,
    logical_sample_id: &str,
    provenance_tool_revision: &str,
) -> Result<SampleSnapshot, CaptureError> {
    capture_snapshot_impl(
        source,
        snapshot_root,
        logical_sample_id,
        provenance_tool_revision,
        None,
    )
}

/// Internal capture with an optional hook invoked between the two source reads.
/// The hook is a pure TEST seam (production passes `None`): it lets a test
/// mutate the source file mid-capture to deterministically exercise the
/// `SourceChangedDuringCapture` fail-closed path without racing.
fn capture_snapshot_impl(
    source: &Path,
    snapshot_root: &Path,
    logical_sample_id: &str,
    provenance_tool_revision: &str,
    mut before_second_read: Option<Box<dyn FnMut() + Send>>,
) -> Result<SampleSnapshot, CaptureError> {
    // First read of the source.
    let first = fs::read(source).map_err(|e| CaptureError::SourceUnreadable(e.to_string()))?;
    if first.is_empty() {
        return Err(CaptureError::SourceEmpty);
    }
    let first_sha = sha256_hex(&first);
    let first_size = first.len() as u64;

    // Content-addressed target directory.
    let revision = revision_id(logical_sample_id, &first_sha);
    let target_dir = snapshot_root.join(logical_sample_id).join(&first_sha);
    fs::create_dir_all(&target_dir)
        .map_err(|e| CaptureError::SnapshotWriteFailed(e.to_string()))?;
    let target_file = target_dir.join(SNAPSHOT_FILENAME);

    // Write snapshot to a temp file first, then verify before promoting to the
    // final content-addressed name.
    let temp_file = target_dir.join(".capturing.tmp");
    if let Err(e) = fs::write(&temp_file, &first) {
        let _ = fs::remove_file(&temp_file);
        return Err(CaptureError::SnapshotWriteFailed(e.to_string()));
    }

    // Recompute snapshot hash/size from the temp bytes.
    let snap_bytes =
        fs::read(&temp_file).map_err(|e| CaptureError::SnapshotWriteFailed(e.to_string()))?;
    let snap_sha = sha256_hex(&snap_bytes);
    let snap_size = snap_bytes.len() as u64;

    // TEST seam: allow a test to mutate the source before the second read.
    if let Some(hook) = before_second_read.as_mut() {
        hook();
    }

    // Second read of the source.
    let second = fs::read(source).map_err(|e| CaptureError::SourceUnreadable(e.to_string()))?;
    let second_sha = sha256_hex(&second);
    let second_size = second.len() as u64;

    // Fail-closed acceptance: source must be stable, snapshot must equal source.
    let stable = first_size == second_size
        && first_sha == second_sha
        && first_sha == snap_sha
        && first_size == snap_size;
    if !stable {
        // Delete the imperfect temp snapshot; never keep a half-written file.
        let _ = fs::remove_file(&temp_file);
        // Remove the content-addressed dir only if empty (don't clobber other revisions).
        let _ = fs::remove_dir(&target_dir);
        return Err(CaptureError::SourceChangedDuringCapture);
    }

    // Promote temp -> final content-addressed name.
    if let Err(e) = fs::rename(&temp_file, &target_file) {
        let _ = fs::remove_file(&temp_file);
        return Err(CaptureError::SnapshotWriteFailed(e.to_string()));
    }

    Ok(SampleSnapshot {
        logical_sample_id: logical_sample_id.to_string(),
        revision,
        source_path: source.to_path_buf(),
        captured_at: now_epoch().to_string(),
        source_sha256: first_sha.clone(),
        snapshot_sha256: snap_sha,
        source_size_bytes: first_size,
        snapshot_size_bytes: snap_size,
        pe_identity: pe_identity_of(&first),
        packer_family_observation: None, // caller may fill from dual_select
        capture_status: CaptureStatus::Captured,
        provenance_tool_revision: provenance_tool_revision.to_string(),
        snapshot_abs_path: target_file,
        snapshot_root: snapshot_root.to_path_buf(),
    })
}

/// Resolve the immutable snapshot file for a known content address
/// (`<logical_id>/<sha256>/snapshot.bin`) if it exists. Used to reproduce an
/// older revision by hash without re-capturing.
pub fn resolve_snapshot(
    snapshot_root: &Path,
    logical_sample_id: &str,
    sha256: &str,
) -> Option<PathBuf> {
    let p = snapshot_root
        .join(logical_sample_id)
        .join(sha256)
        .join(SNAPSHOT_FILENAME);
    p.is_file().then_some(p)
}

/// Offline snapshot-to-staging seam (G3-R2, stage C).
///
/// A staging entry must be driven by an immutable snapshot, NOT by a live
/// source path. `StagingIdentity` carries the snapshot's hash/size as the case
/// identity and keeps the source path only as provenance. `matches_expected`
/// fails closed unless the snapshot's identity equals an expected manifest
/// identity (hash + size), so a new revision never passes an old manifest bound
/// identity and vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingIdentity {
    pub logical_sample_id: String,
    pub revision: String,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    /// The source path this snapshot was captured from (provenance only; never
    /// used as the case identity).
    pub source_path: PathBuf,
}

impl SampleSnapshot {
    /// Derive the staging identity for this immutable snapshot. The identity is
    /// the snapshot hash/size; the source path is provenance only.
    pub fn to_staging_identity(&self) -> StagingIdentity {
        StagingIdentity {
            logical_sample_id: self.logical_sample_id.clone(),
            revision: self.revision.clone(),
            snapshot_sha256: self.snapshot_sha256.clone(),
            snapshot_size_bytes: self.snapshot_size_bytes,
            source_path: self.source_path.clone(),
        }
    }
}

/// Fail-closed: true only when the staging identity's snapshot hash AND size
/// match an expected manifest identity exactly. A mismatch (wrong revision,
/// tampered hash/size) is refused.
pub fn staging_identity_matches(
    staging: &StagingIdentity,
    expected_sha256: &str,
    expected_size_bytes: u64,
) -> bool {
    staging
        .snapshot_sha256
        .eq_ignore_ascii_case(expected_sha256)
        && staging.snapshot_size_bytes == expected_size_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root(tag: &str) -> PathBuf {
        let nonce = now_epoch();
        let dir = std::env::temp_dir().join(format!(
            "mida_snapshot_{tag}_{}_{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// D1: a stable source captures successfully with source==snapshot identity.
    #[test]
    fn stable_source_captures_with_matching_identity() {
        let root = temp_root("stable");
        let src = root.join("src.bin");
        let payload = b"GTO-STABLE-SNAPSHOT-PAYLOAD-0123456789";
        fs::write(&src, payload).unwrap();
        let snap_root = root.join("snapshots");

        let snap = capture_snapshot(&src, &snap_root, "gto_launcher", "rev@test").unwrap();
        assert_eq!(snap.capture_status, CaptureStatus::Captured);
        assert_eq!(snap.source_sha256, snap.snapshot_sha256);
        assert_eq!(snap.source_size_bytes, payload.len() as u64);
        assert_eq!(snap.snapshot_size_bytes, payload.len() as u64);
        // Revision is hash-derived, not a bare timestamp.
        assert_eq!(
            snap.revision,
            format!("gto_launcher@sha256-{}", snap.snapshot_sha256)
        );
        assert!(snap.revision.starts_with("gto_launcher@sha256-"));
        // Snapshot file exists and matches the source bytes.
        let disk = fs::read(&snap.snapshot_abs_path).unwrap();
        assert_eq!(sha256_hex(&disk), snap.snapshot_sha256);
        assert_eq!(disk, payload);
        let _ = fs::remove_dir_all(&root);
    }

    /// D2: a source that changes during capture fails closed with
    /// `SourceChangedDuringCapture`, and no snapshot file is kept.
    #[test]
    fn source_change_during_capture_fails_closed() {
        let root = temp_root("changed");
        let src = root.join("src.bin");
        fs::write(&src, b"VERSION-ONE-PAYLOAD").unwrap();
        let snap_root = root.join("snapshots");

        // Use the internal capture with a TEST seam that mutates the source
        // between the two reads.
        let hook_src = src.clone();
        let result = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::write(&hook_src, b"VERSION-TWO-PAYLOAD-DIFFERENT").unwrap();
            })),
        );
        assert_eq!(result, Err(CaptureError::SourceChangedDuringCapture));
        // No snapshot file was kept (temp deleted, dir removed if empty).
        let addr = snap_root
            .join("gto_launcher")
            .join(sha256_hex(b"VERSION-ONE-PAYLOAD"));
        assert!(
            !addr.join(SNAPSHOT_FILENAME).exists(),
            "no imperfect snapshot may be kept"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// D2b: an empty source is also fail-closed.
    #[test]
    fn empty_source_fails_closed() {
        let root = temp_root("empty");
        let src = root.join("src.bin");
        fs::write(&src, b"").unwrap();
        let snap_root = root.join("snapshots");
        let err = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap_err();
        assert_eq!(err, CaptureError::SourceEmpty);
        let _ = fs::remove_dir_all(&root);
    }

    /// D3: same path updated to new content yields a new revision without
    /// overwriting the old one (content-addressed).
    #[test]
    fn same_path_update_creates_new_revision_not_overwrite() {
        let root = temp_root("update");
        let src = root.join("src.bin");
        fs::write(&src, b"REV-1-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        let r1 = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        fs::write(&src, b"REV-2-CONTENT-DIFFERENT").unwrap();
        let r2 = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        assert_ne!(r1.revision, r2.revision);
        // Both snapshots exist and are byte-distinct (D4: old reproducible).
        assert_eq!(fs::read(&r1.snapshot_abs_path).unwrap(), b"REV-1-CONTENT");
        assert_eq!(
            fs::read(&r2.snapshot_abs_path).unwrap(),
            b"REV-2-CONTENT-DIFFERENT"
        );
        assert_ne!(r1.snapshot_abs_path, r2.snapshot_abs_path);
        // D4: resolve the old revision purely by its hash.
        let old = resolve_snapshot(&snap_root, "gto_launcher", &r1.snapshot_sha256)
            .expect("reproducible");
        assert_eq!(fs::read(&old).unwrap(), b"REV-1-CONTENT");
        let _ = fs::remove_dir_all(&root);
    }

    /// D5: a manifest bound to an old snapshot hash rejects a new snapshot.
    #[test]
    fn manifest_bound_to_old_revision_rejects_new() {
        let root = temp_root("manifest_bind");
        let src = root.join("src.bin");
        fs::write(&src, b"MANIFEST-BOUND-V1").unwrap();
        let snap_root = root.join("snapshots");
        let old = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let bound_sha = old.snapshot_sha256.clone();
        fs::write(&src, b"MANIFEST-BOUND-V2-DIFFERENT").unwrap();
        let new = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        // A staging seam requiring snapshot hash == manifest-bound hash rejects.
        assert_ne!(new.snapshot_sha256, bound_sha);
        assert_ne!(new.revision, old.revision);
        let _ = fs::remove_dir_all(&root);
    }

    /// D6: same source path, different hash -> different identity.
    #[test]
    fn same_path_different_hash_different_identity() {
        let root = temp_root("path_identity");
        let src = root.join("src.bin");
        fs::write(&src, b"PATH-HASH-A").unwrap();
        let snap_root = root.join("snapshots");
        let a = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        fs::write(&src, b"PATH-HASH-B-XXXX").unwrap();
        let b = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        assert_ne!(a.snapshot_sha256, b.snapshot_sha256);
        assert_ne!(a.revision, b.revision);
        assert_eq!(a.logical_sample_id, b.logical_sample_id);
        let _ = fs::remove_dir_all(&root);
    }

    /// C: the offline snapshot-to-staging seam derives a staging identity from
    /// the snapshot hash/size (source path is provenance only) and matches it
    /// against an expected manifest identity. A snapshot that does not match the
    /// expected identity (wrong revision) is rejected.
    #[test]
    fn staging_seam_matches_snapshot_identity_and_rejects_wrong_revision() {
        let root = temp_root("staging");
        let src = root.join("src.bin");
        fs::write(&src, b"STAGING-REV-A").unwrap();
        let snap_root = root.join("snapshots");
        let a = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let staging = a.to_staging_identity();
        assert_eq!(staging.snapshot_sha256, a.snapshot_sha256);
        assert_eq!(staging.snapshot_size_bytes, a.snapshot_size_bytes);
        // Source path is provenance only; identity is the snapshot hash/size.
        assert_eq!(staging.source_path, src);

        // Matches an expected manifest identity with the same hash/size.
        assert!(staging_identity_matches(
            &staging,
            &a.snapshot_sha256,
            a.snapshot_size_bytes
        ));

        // A different revision (new source content) does not match the old
        // manifest-bound identity.
        fs::write(&src, b"STAGING-REV-B-DIFFERENT").unwrap();
        let b = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        assert_ne!(a.revision, b.revision);
        assert!(!staging_identity_matches(
            &staging,
            &b.snapshot_sha256,
            b.snapshot_size_bytes
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// D7: tampered snapshot hash/size is rejected by the staging seam.
    #[test]
    fn tampered_snapshot_hash_or_size_is_rejected() {
        let root = temp_root("tamper");
        let src = root.join("src.bin");
        fs::write(&src, b"TAMPER-CHECK").unwrap();
        let snap_root = root.join("snapshots");
        let snap = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let staging = snap.to_staging_identity();
        // Correct identity passes.
        assert!(staging_identity_matches(
            &staging,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));
        // Wrong hash (tampered) rejected.
        assert!(!staging_identity_matches(
            &staging,
            &"0".repeat(64),
            snap.snapshot_size_bytes
        ));
        // Wrong size (tampered) rejected.
        assert!(!staging_identity_matches(
            &staging,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes + 1
        ));
        // Both wrong rejected.
        assert!(!staging_identity_matches(
            &staging,
            "0".repeat(64).as_str(),
            0
        ));
        let _ = fs::remove_dir_all(&root);
    }
}
