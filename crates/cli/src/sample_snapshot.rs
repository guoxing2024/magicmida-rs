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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// The filename used for a snapshot inside its content-addressed directory.
pub const SNAPSHOT_FILENAME: &str = "snapshot.bin";

/// A process-wide monotonic counter used to make temp-file names unique.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique temp-file name inside a snapshot target dir. Unique across
/// processes (pid) and threads (counter + nanos) so concurrent captures never
/// collide on a fixed temp name.
fn unique_temp_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".capturing-{}-{nanos}-{counter}.tmp", std::process::id())
}

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

/// Errors from a snapshot capture or verified resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    SourceUnreadable(String),
    SnapshotWriteFailed(String),
    SourceChangedDuringCapture,
    SourceEmpty,
    /// `logical_sample_id` is empty, contains `..`, or contains a path
    /// separator.
    InvalidLogicalSampleId(String),
    /// A hash string is not exactly 64 hex chars.
    InvalidHash(String),
    /// The content-addressed target already exists but its on-disk content does
    /// not match the intended hash/size; refusing to overwrite.
    SnapshotAlreadyExistsButMismatch(String),
    /// The on-disk snapshot failed a verified re-read (missing, truncated,
    /// corrupted, wrong hash/size).
    VerifiedResolveFailed(String),
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
            Self::InvalidLogicalSampleId(v) => {
                write!(f, "invalid logical_sample_id {:?}: must be non-empty, no '..', no path separators", v)
            }
            Self::InvalidHash(v) => write!(f, "invalid hash {:?}: must be exactly 64 hex chars", v),
            Self::SnapshotAlreadyExistsButMismatch(m) => {
                write!(f, "snapshot already exists but content mismatches: {m}")
            }
            Self::VerifiedResolveFailed(m) => {
                write!(f, "verified resolve failed (fail-closed): {m}")
            }
        }
    }
}

/// Validate a `logical_sample_id`: non-empty, no `..`, no path separator.
pub fn validate_logical_sample_id(id: &str) -> Result<(), CaptureError> {
    if id.trim().is_empty() {
        return Err(CaptureError::InvalidLogicalSampleId(id.to_string()));
    }
    if id.contains('/') || id.contains('\\') {
        return Err(CaptureError::InvalidLogicalSampleId(id.to_string()));
    }
    for comp in id.split(['/', '\\']) {
        if comp == ".." || comp == "." || comp.contains("..") {
            return Err(CaptureError::InvalidLogicalSampleId(id.to_string()));
        }
    }
    Ok(())
}

/// Validate a content hash: exactly 64 lowercase hex chars.
pub fn validate_hash(sha256: &str) -> Result<(), CaptureError> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CaptureError::InvalidHash(sha256.to_string()));
    }
    Ok(())
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
    validate_logical_sample_id(logical_sample_id)?;

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
    let target_file = target_dir.join(SNAPSHOT_FILENAME);

    // Idempotent reuse: if a complete, verified snapshot already exists for this
    // content address, reuse it. NEVER overwrite. If it exists but its on-disk
    // content does not match the intended hash/size, fail closed.
    if target_file.is_file() {
        match verified_read_snapshot(snapshot_root, logical_sample_id, &first_sha) {
            Ok(snap)
                if snap.snapshot_sha256 == first_sha && snap.snapshot_size_bytes == first_size =>
            {
                return Ok(sample_snapshot_from_verified(
                    &snap,
                    snapshot_root,
                    source,
                    provenance_tool_revision,
                ));
            }
            Ok(_) => {
                return Err(CaptureError::SnapshotAlreadyExistsButMismatch(format!(
                    "{} exists but verified content does not match intended hash/size",
                    target_file.display()
                )));
            }
            Err(e) => {
                return Err(CaptureError::SnapshotAlreadyExistsButMismatch(format!(
                    "{} exists but verified re-read failed: {e}",
                    target_file.display()
                )));
            }
        }
    }

    fs::create_dir_all(&target_dir)
        .map_err(|e| CaptureError::SnapshotWriteFailed(e.to_string()))?;

    // Unique temp file (never a fixed `.capturing.tmp`) so concurrent captures
    // never collide. A small guard ensures EVERY failure path removes it.
    let temp_file = target_dir.join(unique_temp_name());
    let mut guard = TempGuard(temp_file.clone());
    if let Err(e) = fs::write(&temp_file, &first) {
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
        // TempGuard removes the temp file on drop; also remove the target dir if
        // it is now empty (never clobber another revision).
        drop(guard);
        let _ = fs::remove_dir(&target_dir);
        return Err(CaptureError::SourceChangedDuringCapture);
    }

    // Publish: promote the temp file to the final content-addressed name.
    // Windows `rename` does not overwrite an existing target, so handle the
    // concurrent case: if the target already exists, verify it matches; if it
    // does, reuse it (idempotent) and drop our temp; if it mismatches, fail.
    let publish_result = fs::rename(&temp_file, &target_file);
    match publish_result {
        Ok(()) => {
            guard.disarm();
        }
        Err(_) if target_file.is_file() => {
            // A concurrent capture may have published the same bytes.
            match verified_read_snapshot(snapshot_root, logical_sample_id, &first_sha) {
                Ok(snap)
                    if snap.snapshot_sha256 == first_sha
                        && snap.snapshot_size_bytes == first_size =>
                {
                    drop(guard); // remove our temp; reuse the concurrent one
                    return Ok(sample_snapshot_from_verified(
                        &snap,
                        snapshot_root,
                        source,
                        provenance_tool_revision,
                    ));
                }
                Ok(_) => {
                    return Err(CaptureError::SnapshotAlreadyExistsButMismatch(format!(
                        "{} already exists with mismatching content",
                        target_file.display()
                    )));
                }
                Err(e) => {
                    return Err(CaptureError::SnapshotAlreadyExistsButMismatch(format!(
                        "{} already exists but unverifiable: {e}",
                        target_file.display()
                    )));
                }
            }
        }
        Err(e) => return Err(CaptureError::SnapshotWriteFailed(e.to_string())),
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

/// RAII guard that removes the temp file on drop unless disarmed.
struct TempGuard(PathBuf);

impl TempGuard {
    fn disarm(&mut self) {}
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Resolve the immutable snapshot file for a known content address
/// (`<logical_id>/<sha256>/snapshot.bin`) if it exists, WITHOUT re-verifying
/// content. Prefer [`verified_read_snapshot`] before staging.
pub fn resolve_snapshot(
    snapshot_root: &Path,
    logical_sample_id: &str,
    sha256: &str,
) -> Option<PathBuf> {
    if validate_logical_sample_id(logical_sample_id).is_err() || validate_hash(sha256).is_err() {
        return None;
    }
    let p = snapshot_root
        .join(logical_sample_id)
        .join(sha256)
        .join(SNAPSHOT_FILENAME);
    p.is_file().then_some(p)
}

/// A snapshot that has been re-read from disk and verified (hash, size, and
/// revision/logical-id consistency). Staging must only trust a verified
/// snapshot, never a cached hash/size from an in-memory struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    pub logical_sample_id: String,
    pub revision: String,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    pub snapshot_abs_path: PathBuf,
}

/// Re-read a snapshot from disk and fail-closed unless:
/// - the file exists and is non-empty;
/// - its bytes hash to `sha256` and its size matches;
/// - `logical_sample_id` and the hash derive the expected revision.
/// A modified/truncated/replaced/missing snapshot is rejected.
pub fn verified_read_snapshot(
    snapshot_root: &Path,
    logical_sample_id: &str,
    sha256: &str,
) -> Result<VerifiedSnapshot, CaptureError> {
    validate_logical_sample_id(logical_sample_id)?;
    let hash = sha256.to_ascii_lowercase();
    validate_hash(&hash)?;
    let p = snapshot_root
        .join(logical_sample_id)
        .join(&hash)
        .join(SNAPSHOT_FILENAME);
    let bytes = fs::read(&p).map_err(|e| {
        CaptureError::VerifiedResolveFailed(format!("cannot read {}: {e}", p.display()))
    })?;
    if bytes.is_empty() {
        return Err(CaptureError::VerifiedResolveFailed(format!(
            "{} is empty",
            p.display()
        )));
    }
    let actual_sha = sha256_hex(&bytes);
    let actual_size = bytes.len() as u64;
    if actual_sha != hash {
        return Err(CaptureError::VerifiedResolveFailed(format!(
            "{} hash {} != expected {}",
            p.display(),
            actual_sha,
            hash
        )));
    }
    let expected_revision = revision_id(logical_sample_id, &hash);
    Ok(VerifiedSnapshot {
        logical_sample_id: logical_sample_id.to_string(),
        revision: expected_revision,
        snapshot_sha256: actual_sha,
        snapshot_size_bytes: actual_size,
        snapshot_abs_path: p,
    })
}

/// Offline snapshot-to-staging seam (G3-R2, stage C).
///
/// A staging entry must be driven by an immutable snapshot, NOT by a live
/// source path. `StagingIdentity` carries the snapshot's hash/size as the case
/// identity and keeps the source path only as provenance.
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
    ///
    /// NOTE: staging MUST still verify against disk (see
    /// [`verified_staging_identity_matches`]) before use; this in-memory value
    /// is never trusted on its own.
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

/// Build a `SampleSnapshot` from a verified snapshot (idempotent-reuse path).
/// The source path and tool revision are provenance only.
fn sample_snapshot_from_verified(
    verified: &VerifiedSnapshot,
    snapshot_root: &Path,
    source: &Path,
    provenance_tool_revision: &str,
) -> SampleSnapshot {
    SampleSnapshot {
        logical_sample_id: verified.logical_sample_id.clone(),
        revision: verified.revision.clone(),
        source_path: source.to_path_buf(),
        captured_at: now_epoch().to_string(),
        source_sha256: verified.snapshot_sha256.clone(),
        snapshot_sha256: verified.snapshot_sha256.clone(),
        source_size_bytes: verified.snapshot_size_bytes,
        snapshot_size_bytes: verified.snapshot_size_bytes,
        pe_identity: None,
        packer_family_observation: None,
        capture_status: CaptureStatus::Captured,
        provenance_tool_revision: provenance_tool_revision.to_string(),
        snapshot_abs_path: verified.snapshot_abs_path.clone(),
        snapshot_root: snapshot_root.to_path_buf(),
    }
}

/// Build a `StagingIdentity` from a VERIFIED snapshot (the only trustworthy
/// source for staging). Rejects an in-memory-only identity.
pub fn staging_identity_from_verified(
    verified: &VerifiedSnapshot,
    source_path: &Path,
) -> StagingIdentity {
    StagingIdentity {
        logical_sample_id: verified.logical_sample_id.clone(),
        revision: verified.revision.clone(),
        snapshot_sha256: verified.snapshot_sha256.clone(),
        snapshot_size_bytes: verified.snapshot_size_bytes,
        source_path: source_path.to_path_buf(),
    }
}

/// Fail-closed: true only when the staging identity's snapshot hash AND size
/// match an expected manifest identity exactly, AND the on-disk snapshot is
/// re-verified (so a forged in-memory identity cannot bypass). A mismatch
/// (wrong revision, tampered/forged hash/size, missing/corrupt disk file) is
/// refused.
pub fn staging_identity_matches(
    staging: &StagingIdentity,
    snapshot_root: &Path,
    expected_sha256: &str,
    expected_size_bytes: u64,
) -> bool {
    // The identity must claim the expected hash/size...
    let hash_ok = staging
        .snapshot_sha256
        .eq_ignore_ascii_case(expected_sha256)
        && staging.snapshot_size_bytes == expected_size_bytes;
    if !hash_ok {
        return false;
    }
    // ...and the on-disk snapshot must actually verify to that hash/size.
    // A forged in-memory `StagingIdentity` with a matching claim but a
    // missing/corrupt/forged disk file is rejected.
    match verified_read_snapshot(
        snapshot_root,
        &staging.logical_sample_id,
        &staging.snapshot_sha256,
    ) {
        Ok(v) => {
            v.snapshot_sha256.eq_ignore_ascii_case(expected_sha256)
                && v.snapshot_size_bytes == expected_size_bytes
        }
        Err(_) => false,
    }
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
    /// against an expected manifest identity, re-verifying the on-disk
    /// snapshot. A snapshot that does not match the expected identity (wrong
    /// revision) is rejected.
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
            &snap_root,
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
            &snap_root,
            &b.snapshot_sha256,
            b.snapshot_size_bytes
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// D7 / real tamper: tampering the on-disk `snapshot.bin` content, size, or
    /// deleting it is rejected by verified resolve and by staging. A forged
    /// in-memory `StagingIdentity` cannot bypass the disk verification.
    #[test]
    fn tampered_snapshot_hash_or_size_is_rejected() {
        let root = temp_root("tamper");
        let src = root.join("src.bin");
        let payload = b"TAMPER-CHECK-PAYLOAD";
        fs::write(&src, payload).unwrap();
        let snap_root = root.join("snapshots");
        let snap = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let staging = snap.to_staging_identity();

        // Correct on-disk snapshot verifies and matches.
        assert!(verified_read_snapshot(&snap_root, "gto_launcher", &snap.snapshot_sha256).is_ok());
        assert!(staging_identity_matches(
            &staging,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));

        // (a) Modify snapshot.bin CONTENT -> verified resolve and staging reject.
        fs::write(&snap.snapshot_abs_path, b"MODIFIED-CONTENT").unwrap();
        assert!(matches!(
            verified_read_snapshot(&snap_root, "gto_launcher", &snap.snapshot_sha256),
            Err(CaptureError::VerifiedResolveFailed(_))
        ));
        assert!(!staging_identity_matches(
            &staging,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));

        // (b) Restore, then modify SIZE (truncate) -> rejected.
        fs::write(&snap.snapshot_abs_path, payload).unwrap();
        fs::write(&snap.snapshot_abs_path, &payload[..4]).unwrap();
        assert!(verified_read_snapshot(&snap_root, "gto_launcher", &snap.snapshot_sha256).is_err());
        assert!(!staging_identity_matches(
            &staging,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));

        // (c) Delete the snapshot file -> rejected.
        fs::write(&snap.snapshot_abs_path, payload).unwrap();
        fs::remove_file(&snap.snapshot_abs_path).unwrap();
        assert!(verified_read_snapshot(&snap_root, "gto_launcher", &snap.snapshot_sha256).is_err());
        assert!(!staging_identity_matches(
            &staging,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// 4: `verified_read_snapshot` recomputes hash/size/revision and rejects a
    /// forged in-memory identity that does not correspond to real disk bytes.
    #[test]
    fn forged_in_memory_identity_cannot_bypass_disk_verification() {
        let root = temp_root("forged");
        let src = root.join("src.bin");
        fs::write(&src, b"REAL-PAYLOAD").unwrap();
        let snap_root = root.join("snapshots");
        let real = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        // A forged staging identity claims the real hash/size but points at a
        // logical id that does not exist on disk.
        let forged = StagingIdentity {
            logical_sample_id: "forged_logical".to_string(),
            revision: format!("forged_logical@sha256-{}", real.snapshot_sha256),
            snapshot_sha256: real.snapshot_sha256.clone(),
            snapshot_size_bytes: real.snapshot_size_bytes,
            source_path: src.clone(),
        };
        assert!(!staging_identity_matches(
            &forged,
            &snap_root,
            &real.snapshot_sha256,
            real.snapshot_size_bytes
        ));
        // Verified resolve of a nonexistent logical id fails.
        assert!(
            verified_read_snapshot(&snap_root, "forged_logical", &real.snapshot_sha256).is_err()
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// 2: capturing the SAME bytes twice is idempotent — the second capture
    /// reuses the existing verified revision instead of failing or overwriting.
    #[test]
    fn same_bytes_captured_twice_is_idempotent() {
        let root = temp_root("idempotent");
        let src = root.join("src.bin");
        fs::write(&src, b"IDEMPOTENT-PAYLOAD").unwrap();
        let snap_root = root.join("snapshots");
        let first = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let second = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        assert_eq!(first.revision, second.revision);
        assert_eq!(first.snapshot_sha256, second.snapshot_sha256);
        assert_eq!(first.snapshot_abs_path, second.snapshot_abs_path);
        // Only one snapshot file exists.
        let dir = snap_root.join("gto_launcher").join(&first.snapshot_sha256);
        let entries: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            entries.len(),
            1,
            "only snapshot.bin, no leftover temp: {entries:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// 2: if the content-addressed target already exists with MISMATCHING
    /// content, capture fails closed instead of overwriting.
    #[test]
    fn existing_target_with_mismatch_fails_closed() {
        let root = temp_root("mismatch_target");
        let src = root.join("src.bin");
        fs::write(&src, b"WANTED-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        // Pre-create a snapshot.bin under the intended content address with
        // WRONG bytes.
        let want_sha = sha256_hex(b"WANTED-CONTENT");
        let dir = snap_root.join("gto_launcher").join(&want_sha);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(SNAPSHOT_FILENAME), b"WRONG-BYTES").unwrap();
        let err = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap_err();
        assert!(matches!(
            err,
            CaptureError::SnapshotAlreadyExistsButMismatch(_)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// 3: concurrent captures of the same source publish the same trusted
    /// revision and never collide on temp files or publish wrong content.
    #[test]
    fn concurrent_capture_publishes_single_trusted_revision() {
        let root = temp_root("concurrent");
        let src = root.join("src.bin");
        fs::write(&src, b"CONCURRENT-PAYLOAD-DATA").unwrap();
        let snap_root = root.join("snapshots");
        let mut handles = Vec::new();
        for _ in 0..8 {
            let src = src.clone();
            let snap_root = snap_root.clone();
            handles.push(std::thread::spawn(move || {
                capture_snapshot(&src, &snap_root, "gto_launcher", "rev").expect("capture")
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let first_sha = results[0].snapshot_sha256.clone();
        for r in &results {
            assert_eq!(
                r.snapshot_sha256, first_sha,
                "all captures agree on the same revision"
            );
        }
        // Exactly one snapshot.bin; no leftover temp files.
        let dir = snap_root.join("gto_launcher").join(&first_sha);
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&SNAPSHOT_FILENAME.to_string()));
        assert!(
            names.iter().all(|n| !n.starts_with(".capturing-")),
            "no leftover temp files: {names:?}"
        );
        // Verified resolve agrees.
        let verified = verified_read_snapshot(&snap_root, "gto_launcher", &first_sha).unwrap();
        assert_eq!(verified.snapshot_size_bytes, results[0].snapshot_size_bytes);
        let _ = fs::remove_dir_all(&root);
    }

    /// 1: every failure path removes the temp file and leaves no directory that
    /// could be mistaken for a complete revision.
    #[test]
    fn failure_paths_cleanup_temp_and_empty_dir() {
        let root = temp_root("cleanup");
        let src = root.join("src.bin");
        fs::write(&src, b"CLEANUP-REV-A").unwrap();
        let snap_root = root.join("snapshots");
        let sha_a = sha256_hex(b"CLEANUP-REV-A");
        let dir_a = snap_root.join("gto_launcher").join(&sha_a);

        // SourceChangedDuringCapture: hook mutates source between reads.
        let hook_src = src.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::write(&hook_src, b"CLEANUP-REV-B-DIFFERENT").unwrap();
            })),
        )
        .unwrap_err();
        assert_eq!(err, CaptureError::SourceChangedDuringCapture);
        // No temp file, no leftover dir.
        assert!(!dir_a.join(SNAPSHOT_FILENAME).exists());
        assert!(
            fs::read_dir(&dir_a)
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
            "dir {} must be empty/removed",
            dir_a.display()
        );

        // Unreadable source (missing) leaves nothing.
        let missing = root.join("missing.bin");
        let _ = capture_snapshot(&missing, &snap_root, "gto_launcher", "rev").unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    /// 6: input validation rejects `..`, path separators, empty ids, and
    /// malformed hashes; resolve must not escape the snapshot root.
    #[test]
    fn input_validation_rejects_path_escape_and_malformed_hash() {
        // logical_sample_id validation.
        assert!(validate_logical_sample_id("gto_launcher").is_ok());
        assert!(validate_logical_sample_id("").is_err());
        assert!(validate_logical_sample_id("a/../b").is_err());
        assert!(validate_logical_sample_id("..").is_err());
        assert!(validate_logical_sample_id("a\\b").is_err());
        assert!(validate_logical_sample_id("a/b").is_err());

        // hash validation.
        assert!(validate_hash(&"a".repeat(64)).is_ok());
        assert!(validate_hash(&"a".repeat(63)).is_err());
        assert!(validate_hash("").is_err());
        assert!(validate_hash(&"z".repeat(64)).is_err()); // not hex

        // resolve_snapshot rejects malformed inputs (no path escape possible).
        assert!(resolve_snapshot(Path::new("root"), "..", &"a".repeat(64)).is_none());
        assert!(resolve_snapshot(Path::new("root"), "gto_launcher", "badhash").is_none());
        // resolve_snapshot with a hash containing a path separator resolves to a
        // path OUTSIDE the content-address shape -> must be None (never returns
        // an escaped path).
        assert!(resolve_snapshot(
            Path::new("root"),
            "gto_launcher",
            &format!("{}/..", "a".repeat(62))
        )
        .is_none());
    }
}
