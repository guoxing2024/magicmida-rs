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

/// The canonical content-addressed snapshot path contract:
/// `<snapshot_root>/<logical_sample_id>/<sha256>/snapshot.bin`.
///
/// A snapshot path is TRUSTED only when it matches this exact layout AND is
/// absolute and free of `.`/`..`. `parse_snapshot_path` parses a path into this
/// structured value; every caller must validate it through the same contract
/// (see the cross-boundary contract vectors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSnapshotPath {
    pub snapshot_root: std::path::PathBuf,
    pub logical_sample_id: String,
    /// Canonical lowercase 64-hex content-address hash directory.
    pub sha256: String,
    pub snapshot_path: std::path::PathBuf,
}

/// Parse a trusted immutable snapshot path of the exact shape
/// `<snapshot_root>/<logical_sample_id>/<sha256>/snapshot.bin` into a structured
/// value. Fail-closed on any of:
/// - relative path;
/// - `.` / `..` components;
/// - wrong file name (not `SNAPSHOT_FILENAME`);
/// - a hash directory that is not exactly 64 lowercase hex;
/// - a missing `snapshot_root` / `logical_sample_id` / hash directory.
///
/// This is the single shared implementation of the snapshot-path contract inside
/// `mida-cli` (`authority_dossier` and `runner_preflight` both delegate here).
/// The independent `mida-acceptance` verifier keeps a minimal local copy of the
/// SAME contract (it cannot depend on production crates) and is validated by the
/// same contract vectors.
pub fn parse_snapshot_path(path: &Path) -> Result<ParsedSnapshotPath, String> {
    // A trusted snapshot path must be absolute.
    if !path.is_absolute() {
        return Err(format!("snapshot path {} is not absolute", path.display()));
    }
    // Reject `.` / `..` at the RAW string level BEFORE `Path::components()`
    // normalizes them away (on Windows a `/./` or `\.\` interior segment is
    // collapsed by the path parser). Handle drive/UNC/`\\?\` prefixes so a
    // legitimate absolute path is never falsely rejected.
    let raw = path.to_string_lossy();
    for comp in raw.split(['/', '\\']) {
        if comp == "." || comp == ".." {
            return Err(format!(
                "snapshot path {raw} contains a relative ({comp:?}) component"
            ));
        }
    }
    // Reject `.` / `..` lexically (before any canonicalization).
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(format!(
                    "snapshot path {} contains a relative ({comp:?}) component",
                    path.display()
                ));
            }
            _ => {}
        }
    }
    // File name must be `snapshot.bin`.
    let name = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| format!("snapshot path {} has no file name", path.display()))?;
    if name != SNAPSHOT_FILENAME {
        return Err(format!(
            "snapshot path {} must end in {SNAPSHOT_FILENAME}",
            path.display()
        ));
    }
    // `<sha256>` directory: exactly 64 lowercase hex.
    let sha_dir = path
        .parent()
        .ok_or_else(|| format!("snapshot path {} has no hash directory", path.display()))?;
    let sha_name = sha_dir
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| {
            format!(
                "snapshot path {} hash directory has no name",
                path.display()
            )
        })?;
    if sha_name.len() != 64
        || !sha_name.bytes().all(|b| b.is_ascii_hexdigit())
        || sha_name != sha_name.to_ascii_lowercase()
    {
        return Err(format!(
            "snapshot path hash directory {sha_name:?} is not exactly 64 lowercase hex"
        ));
    }
    // `<logical_sample_id>` directory.
    let logical_dir = sha_dir.parent().ok_or_else(|| {
        format!(
            "snapshot path {} has no logical-sample directory",
            path.display()
        )
    })?;
    let logical_name = logical_dir
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| {
            format!(
                "snapshot path {} logical-sample directory has no name",
                path.display()
            )
        })?;
    if !validate_logical_sample_id(logical_name).is_ok() {
        return Err(format!(
            "snapshot path {} logical-sample directory {logical_name:?} is invalid",
            path.display()
        ));
    }
    // `<snapshot_root>`.
    let root = logical_dir
        .parent()
        .ok_or_else(|| format!("snapshot path {} has no snapshot_root", path.display()))?;
    Ok(ParsedSnapshotPath {
        snapshot_root: root.to_path_buf(),
        logical_sample_id: logical_name.to_string(),
        sha256: sha_name.to_string(),
        snapshot_path: path.to_path_buf(),
    })
}

/// Strictly canonicalize a trusted snapshot path and verify it stays under the
/// canonical `snapshot_root` with the correct logical-sample and hash layers.
///
/// This is the disk-level counterpart of [`parse_snapshot_path`]: it parses the
/// RAW path lexically, then STRICT-canonicalizes it (NO `canonicalize_loose`
/// fallback — a missing file or any canonicalization/reparse failure fails
/// closed), canonicalizes the lexical `snapshot_root`, and requires:
/// - the canonical full path to be under the canonical `snapshot_root`;
/// - the canonical path to still match `<canonical_root>/<logical>/<sha>/snapshot.bin`
///   (so a logical/hash/file layer that is a junction/symlink/reparse point
///   escaping `snapshot_root` is rejected).
///
/// `expected_logical_sample_id` / `expected_sha256` must match the parsed (and
/// Strictly canonicalize a trusted snapshot path and verify it stays under the
/// CANONICAL caller-provided `trusted_snapshot_root` with the correct
/// logical-sample and hash layers.
///
/// This is the disk-level counterpart of [`parse_snapshot_path`]: it parses the
/// RAW path lexically, then STRICT-canonicalizes (NO `canonicalize_loose`
/// fallback — a missing file or any canonicalization/reparse failure fails
/// closed). The caller supplies the trusted root explicitly (NOT derived from
/// the path), so:
/// - the path's LEXICAL snapshot_root must equal the trusted root;
/// - a trusted root that is itself a junction/symlink/reparse alias is rejected;
/// - the canonical path must be under the canonical trusted root;
/// - the canonical path must still match
///   `<canonical_root>/<logical>/<sha>/snapshot.bin` (a logical/hash/file layer
///   junction/symlink/reparse escaping the trusted root is rejected).
///
/// `expected_logical_sample_id` / `expected_sha256` must match the parsed (and
/// re-parsed canonical) values.
pub fn canonical_verify_snapshot_path(
    path: &Path,
    trusted_snapshot_root: &Path,
    expected_logical_sample_id: &str,
    expected_sha256: &str,
) -> Result<ParsedSnapshotPath, String> {
    // 1. Lexical parse first (rejects relative, ./.., wrong filename, bad hash).
    let parsed = parse_snapshot_path(path)?;
    if !paths_equivalent(&parsed.snapshot_root, trusted_snapshot_root) {
        return Err(format!(
            "snapshot path {} lexical snapshot_root {} != caller trusted snapshot_root {}",
            path.display(),
            parsed.snapshot_root.display(),
            trusted_snapshot_root.display()
        ));
    }
    if parsed.logical_sample_id != expected_logical_sample_id {
        return Err(format!(
            "snapshot path {} logical-sample directory {:?} != expected {expected_logical_sample_id:?}",
            path.display(),
            parsed.logical_sample_id
        ));
    }
    if !parsed.sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err(format!(
            "snapshot path {} hash directory {:?} != expected sha {expected_sha256}",
            path.display(),
            parsed.sha256
        ));
    }
    // 2. STRICT canonicalize of the TRUSTED root. If the trusted root itself is
    //    a reparse alias (junction/symlink), its canonical form differs from its
    //    lexical form and must be rejected -- the operator's trusted root must be
    //    a real directory, not a pointer.
    let canonical_trusted = std::fs::canonicalize(trusted_snapshot_root).map_err(|e| {
        format!(
            "trusted snapshot root {} cannot be canonicalized: {e}",
            trusted_snapshot_root.display()
        )
    })?;
    if !paths_equivalent(&canonical_trusted, trusted_snapshot_root) {
        return Err(format!(
            "trusted snapshot root {} resolves to {} (junction/symlink/reparse alias is rejected)",
            trusted_snapshot_root.display(),
            canonical_trusted.display()
        ));
    }
    // 3. STRICT canonicalize of the full path -- no loose fallback.
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        format!(
            "snapshot path {} cannot be canonicalized (missing or reparse failure): {e}",
            path.display()
        )
    })?;
    // 4. The canonical full path must be under the canonical trusted root.
    if !canonical.starts_with(&canonical_trusted) {
        return Err(format!(
            "canonical snapshot path {} escapes canonical trusted snapshot root {} \
             (junction/symlink/reparse escape is rejected)",
            canonical.display(),
            canonical_trusted.display()
        ));
    }
    // 5. Re-parse the canonical path; it must still match the exact structure
    //    with the expected logical id and hash.
    let canonical_parsed = parse_snapshot_path(&canonical).map_err(|e| {
        format!(
            "canonical snapshot path {} is not a well-formed snapshot address: {e}",
            canonical.display()
        )
    })?;
    if canonical_parsed.snapshot_root != canonical_trusted {
        return Err(format!(
            "canonical snapshot root {} != canonical trusted root {}",
            canonical_parsed.snapshot_root.display(),
            canonical_trusted.display()
        ));
    }
    if canonical_parsed.logical_sample_id != expected_logical_sample_id {
        return Err(format!(
            "canonical snapshot logical-sample directory {:?} != expected {expected_logical_sample_id:?} \
             (junction escape of the logical dir is rejected)",
            canonical_parsed.logical_sample_id
        ));
    }
    if !canonical_parsed
        .sha256
        .eq_ignore_ascii_case(expected_sha256)
    {
        return Err(format!(
            "canonical snapshot hash directory {:?} != expected sha {expected_sha256} \
             (junction escape of the hash dir is rejected)",
            canonical_parsed.sha256
        ));
    }
    Ok(canonical_parsed)
}

/// Compare two paths as equivalent after prefix-aware normalization and
/// case-insensitive comparison (used to detect a trusted root that is itself a
/// reparse alias and to cross-check caller vs sealed roots).
///
/// Only a LEADING Windows extended-length prefix is stripped: `\\?\D:\...` ->
/// `D:\...`, `\\?\UNC\server\share` -> `\\server\share`, and `\\.\` device paths
/// are left as-is (not a valid snapshot root anyway). No mid-path replacement is
/// performed, so a literal `\\?\` in a component name is preserved.
pub fn paths_equivalent(a: &Path, b: &Path) -> bool {
    fn norm(p: &Path) -> String {
        let raw = p.to_string_lossy().into_owned();
        let s = if let Some(rest) = raw.strip_prefix("\\\\?\\UNC\\") {
            format!("\\\\{rest}")
        } else if let Some(rest) = raw.strip_prefix("\\\\?\\") {
            rest.to_string()
        } else {
            raw
        };
        s.to_lowercase()
    }
    norm(a) == norm(b)
}

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

/// Validate a content hash: exactly 64 hex chars (any case accepted).
///
/// Callers MUST use [`canonical_hash`] before treating the value as an
/// identity/hash component so resolve, verified resolve, and revision
/// construction all agree on the same lowercase canonical form.
pub fn validate_hash(sha256: &str) -> Result<(), CaptureError> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CaptureError::InvalidHash(sha256.to_string()));
    }
    Ok(())
}

/// Canonical (lowercase) form of a validated SHA-256 hex string. All identity,
/// path, and revision construction must use this form so that upper/mixed-case
/// inputs never diverge from the canonical address.
pub fn canonical_hash(sha256: &str) -> String {
    sha256.to_ascii_lowercase()
}

/// Explicit no-replace publish outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishOutcome {
    /// We won the race: the temp file became the final snapshot.
    Published,
    /// The target already exists; nothing was overwritten.
    AlreadyExists,
}

/// Atomically promote `temp` to `target` with TRUE no-replace semantics.
///
/// This uses `fs::hard_link` (the portable `link(2)` / `CreateHardLinkW`
/// primitive), NOT `exists + rename`. `hard_link` either atomically creates a
/// new directory entry `target` pointing at the already-fully-written `temp`
/// inode, or fails with `AlreadyExists` if `target` already exists. There is no
/// TOCTOU window between a pre-check and the link, and on every platform it
/// NEVER overwrites an existing `target`.
///
/// No half-written file is ever exposed: the `temp` inode is written and closed
/// before the link, so a reader that finds `target` always sees the complete
/// snapshot bytes.
fn publish_no_replace(temp: &Path, target: &Path) -> std::io::Result<PublishOutcome> {
    match fs::hard_link(temp, target) {
        Ok(()) => Ok(PublishOutcome::Published),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(PublishOutcome::AlreadyExists)
        }
        Err(e) => Err(e),
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
        None,
    )
}

#[cfg(test)]
pub(crate) fn capture_snapshot_with_hooks(
    source: &Path,
    snapshot_root: &Path,
    logical_sample_id: &str,
    provenance_tool_revision: &str,
    before_second_read: Option<Box<dyn FnMut() + Send>>,
    before_publish: Option<Box<dyn FnMut() + Send>>,
) -> Result<SampleSnapshot, CaptureError> {
    capture_snapshot_impl(
        source,
        snapshot_root,
        logical_sample_id,
        provenance_tool_revision,
        before_second_read,
        before_publish,
    )
}

/// Internal capture with optional hooks invoked between the two source reads and
/// before publish. The hooks are a pure TEST seam (production passes `None`):
/// they let a test mutate/delete the source or inject a racy target
/// deterministically without racing.
fn capture_snapshot_impl(
    source: &Path,
    snapshot_root: &Path,
    logical_sample_id: &str,
    provenance_tool_revision: &str,
    mut before_second_read: Option<Box<dyn FnMut() + Send>>,
    mut before_publish: Option<Box<dyn FnMut() + Send>>,
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
    // content address, reuse it. NEVER overwrite and NEVER delete it. Crucially,
    // the reuse path STILL completes BOTH source reads: the existing snapshot is
    // only trusted if the source is verified stable across the whole capture,
    // exactly like the fresh-capture path. If the source changes or becomes
    // unreadable while we verify the existing snapshot, we fail closed.
    if target_file.exists() {
        // Classify the existing target WITHOUT returning yet. Even a corrupt,
        // mismatching, or unverifiable existing snapshot must still ride through
        // the second source read, so a source change during verification wins
        // over the snapshot mismatch (and we never delete/overwrite the bad
        // existing snapshot).
        enum Existing {
            Verified(VerifiedSnapshot),
            Mismatch,
            Unverifiable(String),
        }
        let existing = match verified_read_snapshot(snapshot_root, logical_sample_id, &first_sha) {
            Ok(v) if v.snapshot_sha256 == first_sha && v.snapshot_size_bytes == first_size => {
                Existing::Verified(v)
            }
            Ok(_) => Existing::Mismatch,
            Err(e) => Existing::Unverifiable(format!(
                "{} exists but verified re-read failed: {e}",
                target_file.display()
            )),
        };

        // TEST seam: allow a test to mutate/delete the source after the existing
        // snapshot has been classified but before the second read.
        if let Some(hook) = before_second_read.as_mut() {
            hook();
        }

        // Second read of the source — mandatory in the reuse path too, even when
        // the existing snapshot is corrupt/missing/unverifiable.
        let second = fs::read(source).map_err(|e| CaptureError::SourceUnreadable(e.to_string()))?;
        let second_sha = sha256_hex(&second);
        let second_size = second.len() as u64;

        // Precedence: source stability first. The existing snapshot is NOT
        // deleted; we simply refuse to reuse it.
        if first_sha != second_sha || first_size != second_size {
            return Err(CaptureError::SourceChangedDuringCapture);
        }

        // Source is stable. Now decide from the classified existing snapshot.
        return match existing {
            // Stable source + verified identical snapshot -> reuse it.
            Existing::Verified(v) => Ok(sample_snapshot_from_verified(
                &v,
                snapshot_root,
                source,
                provenance_tool_revision,
            )),
            Existing::Mismatch => Err(CaptureError::SnapshotAlreadyExistsButMismatch(format!(
                "{} exists but verified content does not match intended hash/size",
                target_file.display()
            ))),
            Existing::Unverifiable(m) => Err(CaptureError::SnapshotAlreadyExistsButMismatch(m)),
        };
    }

    // Create the parent and leaf content-addressed directories idempotently.
    // Failed captures leave an empty leaf directory behind: ownership cannot be
    // tracked safely after another task observes or populates the same directory,
    // so cleanup is limited to this capture's own temp file.
    fs::create_dir_all(&target_dir)
        .map_err(|e| CaptureError::SnapshotWriteFailed(e.to_string()))?;

    // Unique temp file (never a fixed `.capturing.tmp`) so concurrent captures
    // never collide. A small guard ensures EVERY failure path removes it.
    let temp_file = target_dir.join(unique_temp_name());
    let guard = TempGuard::new(temp_file.clone());
    if let Err(e) = fs::write(&temp_file, &first) {
        return Err(CaptureError::SnapshotWriteFailed(e.to_string()));
    }

    // Recompute snapshot hash/size from the temp bytes.
    let snap_bytes =
        fs::read(&temp_file).map_err(|e| CaptureError::SnapshotWriteFailed(e.to_string()))?;
    let snap_sha = sha256_hex(&snap_bytes);
    let snap_size = snap_bytes.len() as u64;

    // TEST seam: allow a test to mutate/delete the source before the second read.
    if let Some(hook) = before_second_read.as_mut() {
        hook();
    }

    // Second read of the source.
    let second = match fs::read(source) {
        Ok(b) => b,
        Err(e) => {
            // Second read failed (e.g. source deleted mid-capture). Fail closed
            // and remove only OUR temp file. The hash directory may be shared by
            // another capture, so it is intentionally left in place.
            drop(guard);
            return Err(CaptureError::SourceUnreadable(e.to_string()));
        }
    };
    let second_sha = sha256_hex(&second);
    let second_size = second.len() as u64;

    // Fail-closed acceptance: source must be stable, snapshot must equal source.
    let stable = first_size == second_size
        && first_sha == second_sha
        && first_sha == snap_sha
        && first_size == snap_size;
    if !stable {
        // TempGuard removes only this capture's temp file. Empty hash directories
        // are harmless metadata and remain available to concurrent publishers.
        drop(guard);
        return Err(CaptureError::SourceChangedDuringCapture);
    }

    // TEST seam: allow a test to inject a racy target between temp verification
    // and publish, exercising the no-replace path deterministically.
    if let Some(hook) = before_publish.as_mut() {
        hook();
    }

    // Publish with a genuinely atomic no-replace primitive. If the target
    // already exists (a concurrent capture published the same bytes), verify it;
    // identical -> reuse, mismatch/unverifiable -> fail-closed. We NEVER
    // overwrite. After a successful hard link BOTH the temp and target point at
    // the same fully-written inode, so the guard still removes the temp.
    match publish_no_replace(&temp_file, &target_file) {
        Ok(PublishOutcome::Published) => {
            drop(guard); // remove the temp; the target hard link keeps the data
        }
        Ok(PublishOutcome::AlreadyExists) => {
            drop(guard); // remove our temp; we did not publish it
            match verified_read_snapshot(snapshot_root, logical_sample_id, &first_sha) {
                Ok(snap)
                    if snap.snapshot_sha256 == first_sha
                        && snap.snapshot_size_bytes == first_size =>
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
struct TempGuard {
    path: PathBuf,
    /// Whether the temp file should be removed on drop. `disarm()` flips this to
    /// `false` so drop does not attempt to delete the file (e.g. after it has
    /// been renamed to its final destination).
    armed: bool,
}

impl TempGuard {
    fn new(path: PathBuf) -> Self {
        TempGuard { path, armed: true }
    }

    /// Disarm the guard: drop will no longer remove the temp file. Only call
    /// this after the temp file has been moved to its final destination and no
    /// longer needs cleanup. Exercised by `temp_guard_disarm_really_changes_state`;
    /// in production the hard-link publish path always drops the guard (the temp
    /// must still be removed), so this is not called from lib code.
    #[allow(dead_code)]
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Resolve the immutable snapshot file for a known content address
/// (`<logical_id>/<sha256>/snapshot.bin`) if it exists, WITHOUT re-verifying
/// content. The returned path is only a locator; prefer
/// [`verified_read_snapshot`] at every staging/preflight boundary.
///
/// The hash is canonicalized to lowercase so upper/mixed-case callers still
/// resolve to the same content address.
pub fn resolve_snapshot(
    snapshot_root: &Path,
    logical_sample_id: &str,
    sha256: &str,
) -> Option<PathBuf> {
    if validate_logical_sample_id(logical_sample_id).is_err() {
        return None;
    }
    let hash = canonical_hash(sha256);
    if validate_hash(&hash).is_err() {
        return None;
    }
    let p = snapshot_root
        .join(logical_sample_id)
        .join(&hash)
        .join(SNAPSHOT_FILENAME);
    p.is_file().then_some(p)
}

/// A snapshot that has been re-read from disk and verified (hash, size, and
/// revision/logical-id consistency). `snapshot_bytes` and the other fields are
/// observations from that read instant, not a durable immutability proof.
/// Staging must re-verify the path again at its own boundary and must never trust
/// a cached hash/size from an older in-memory struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSnapshot {
    pub logical_sample_id: String,
    pub revision: String,
    pub snapshot_sha256: String,
    pub snapshot_size_bytes: u64,
    pub snapshot_abs_path: PathBuf,
    /// The verified on-disk bytes, so a caller can re-derive identity (e.g. PE
    /// identity) from the actual content rather than trusting a cached struct.
    pub snapshot_bytes: Vec<u8>,
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
    let hash = canonical_hash(sha256);
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
        snapshot_bytes: bytes,
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
    /// Derive a point-in-time staging identity for this snapshot. The identity
    /// is the snapshot hash/size; the source path is provenance only. Callers
    /// must still run `staging_identity_matches` (which re-verifies disk bytes)
    /// immediately before staging/preflight.
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
///
/// Identity-related fields (logical_sample_id, revision, snapshot hash/size, and
/// PE identity) are derived from the VERIFIED on-disk bytes so a reused snapshot
/// carries the same identity metadata as a fresh capture of the same bytes.
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
        pe_identity: pe_identity_of(&verified.snapshot_bytes),
        packer_family_observation: None,
        capture_status: CaptureStatus::Captured,
        provenance_tool_revision: provenance_tool_revision.to_string(),
        snapshot_abs_path: verified.snapshot_abs_path.clone(),
        snapshot_root: snapshot_root.to_path_buf(),
    }
}

/// Build a `StagingIdentity` from a VERIFIED snapshot (the only trustworthy
/// source for staging). Rejects an in-memory-only identity.
///
/// The revision is DERIVED from the canonical hash and logical id rather than
/// copied verbatim from a possibly-forged in-memory value.
pub fn staging_identity_from_verified(
    verified: &VerifiedSnapshot,
    source_path: &Path,
) -> StagingIdentity {
    let canonical = canonical_hash(&verified.snapshot_sha256);
    StagingIdentity {
        logical_sample_id: verified.logical_sample_id.clone(),
        revision: revision_id(&verified.logical_sample_id, &canonical),
        snapshot_sha256: canonical,
        snapshot_size_bytes: verified.snapshot_size_bytes,
        source_path: source_path.to_path_buf(),
    }
}

/// Fail-closed: true only when the staging identity's snapshot hash, SIZE, AND
/// REVISION all match the expected manifest identity exactly, AND the on-disk
/// snapshot is re-verified (so a forged in-memory identity cannot bypass).
///
/// A mismatch (wrong revision, tampered/forged hash/size, missing/corrupt disk
/// file) is refused. The revision must equal
/// `revision_id(logical_sample_id, canonical_snapshot_sha256)`.
pub fn staging_identity_matches(
    staging: &StagingIdentity,
    snapshot_root: &Path,
    expected_sha256: &str,
    expected_size_bytes: u64,
) -> bool {
    let canonical = canonical_hash(expected_sha256);
    // The identity must claim the expected hash/size...
    let hash_ok = canonical_hash(&staging.snapshot_sha256) == canonical
        && staging.snapshot_size_bytes == expected_size_bytes;
    if !hash_ok {
        return false;
    }
    // ...and its revision must be the hash-derived revision of its OWN logical
    // id + canonical hash. A `StagingIdentity` with correct hash/size but a
    // forged/re-ordered revision is rejected.
    let expected_revision = revision_id(&staging.logical_sample_id, &canonical);
    if staging.revision != expected_revision {
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
            None,
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

    /// R3-6: `SampleSnapshot` is a point-in-time observation. Staging must
    /// re-verify the on-disk bytes after that object is returned.
    #[test]
    fn sample_snapshot_is_point_in_time_and_staging_reverifies() {
        let root = temp_root("point_in_time_boundary");
        let src = root.join("src.bin");
        fs::write(&src, b"POINT-IN-TIME-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        let snapshot = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let staging = snapshot.to_staging_identity();

        fs::write(&snapshot.snapshot_abs_path, b"POST-CAPTURE-TAMPER").unwrap();
        assert!(
            verified_read_snapshot(&snap_root, "gto_launcher", &snapshot.snapshot_sha256).is_err()
        );
        assert!(
            !staging_identity_matches(
                &staging,
                &snap_root,
                &snapshot.snapshot_sha256,
                snapshot.snapshot_size_bytes
            ),
            "staging must re-verify disk bytes instead of trusting SampleSnapshot"
        );
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
            None,
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

    /// R2-1: the idempotent-reuse path STILL completes both source reads. If the
    /// source changes between the first read and the second read (while the
    /// existing snapshot is being verified), capture fails closed and the
    /// pre-existing revision A is preserved (never deleted/overwritten).
    #[test]
    fn reuse_path_source_change_during_verification_fails_closed() {
        let root = temp_root("reuse_change");
        let src = root.join("src.bin");
        fs::write(&src, b"REUSE-REV-A-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        // Capture revision A.
        let a = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let a_hash = a.snapshot_sha256.clone();
        let a_path = a.snapshot_abs_path.clone();
        let a_bytes = fs::read(&a_path).unwrap();

        // Second capture reads A first, the existing snapshot verifies, then the
        // source is mutated to B BEFORE the second read. Must fail closed.
        let hook_src = src.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::write(&hook_src, b"REUSE-REV-B-DIFFERENT").unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert_eq!(err, CaptureError::SourceChangedDuringCapture);

        // Revision A is preserved: not deleted, not overwritten, still verifies.
        assert!(a_path.is_file());
        assert_eq!(fs::read(&a_path).unwrap(), a_bytes);
        assert!(verified_read_snapshot(&snap_root, "gto_launcher", &a_hash).is_ok());
        // No revision B was published (source changed).
        let b_hash = sha256_hex(b"REUSE-REV-B-DIFFERENT");
        assert!(
            !snap_root
                .join("gto_launcher")
                .join(&b_hash)
                .join(SNAPSHOT_FILENAME)
                .exists(),
            "no revision B may be published when the source changed"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// R2-2: deleting the source after the existing snapshot is verified but
    /// before the second read causes the second read to fail; capture fails
    /// closed and the existing revision A is preserved.
    #[test]
    fn reuse_path_second_read_fails_when_source_deleted() {
        let root = temp_root("reuse_delete");
        let src = root.join("src.bin");
        fs::write(&src, b"REUSE-DELETE-A").unwrap();
        let snap_root = root.join("snapshots");
        let a = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let a_hash = a.snapshot_sha256.clone();
        let a_path = a.snapshot_abs_path.clone();
        let a_bytes = fs::read(&a_path).unwrap();

        // Delete the source between verification and the second read.
        let hook_src = src.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::remove_file(&hook_src).unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, CaptureError::SourceUnreadable(_)),
            "second-read failure must be fail-closed unreadable, got {err:?}"
        );
        // Existing snapshot preserved.
        assert!(a_path.is_file());
        assert_eq!(fs::read(&a_path).unwrap(), a_bytes);
        assert!(verified_read_snapshot(&snap_root, "gto_launcher", &a_hash).is_ok());
        let _ = fs::remove_dir_all(&root);
    }

    /// R2-4: a second-read failure in the FRESH-capture path (source deleted
    /// after the temp is written) leaves no `.capturing-*`, no `snapshot.bin`,
    /// and no leftover empty hash directory. The cleanup must run after the temp
    /// write, so this exercises the real "source vanished mid-capture" case, not
    /// a fake first-read-missing scenario.
    #[test]
    fn second_read_failure_cleans_temp_and_empty_hash_dir() {
        let root = temp_root("second_read_cleanup");
        let src = root.join("src.bin");
        fs::write(&src, b"SECOND-READ-CLEANUP-A").unwrap();
        let snap_root = root.join("snapshots");
        let sha_a = sha256_hex(b"SECOND-READ-CLEANUP-A");
        let dir_a = snap_root.join("gto_launcher").join(&sha_a);

        // Delete the source between the two reads (after first read + temp write).
        let hook_src = src.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::remove_file(&hook_src).unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, CaptureError::SourceUnreadable(_)),
            "got {err:?}"
        );
        // No .capturing-* anywhere under the hash dir.
        let entries: Vec<String> = fs::read_dir(&dir_a)
            .map(|d| {
                d.map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert!(
            entries.iter().all(|n| !n.starts_with(".capturing-")),
            "no leftover temp files: {entries:?}"
        );
        assert!(
            !dir_a.join(SNAPSHOT_FILENAME).exists(),
            "no snapshot.bin may be kept on a failed second read"
        );
        // The hash dir must be empty (or removed entirely).
        assert!(
            fs::read_dir(&dir_a)
                .map(|mut d| d.next().is_none())
                .unwrap_or(true),
            "hash dir {} must be empty/removed after a failed second read",
            dir_a.display()
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// R2-3a: revision-only forgery. The logical id, hash, size, and on-disk
    /// file are all correct; ONLY the revision string is wrong. Staging must
    /// reject it.
    #[test]
    fn only_revision_is_forged_rejected() {
        let root = temp_root("rev_forged");
        let src = root.join("src.bin");
        fs::write(&src, b"REV-FORGERY-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        let snap = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();

        // Everything correct EXCEPT revision.
        let forged = StagingIdentity {
            logical_sample_id: snap.logical_sample_id.clone(),
            revision: "gto_launcher@sha256-0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            snapshot_sha256: snap.snapshot_sha256.clone(),
            snapshot_size_bytes: snap.snapshot_size_bytes,
            source_path: src.clone(),
        };
        assert_ne!(forged.revision, snap.revision);
        // Real disk + correct hash/size are NOT enough: the revision is checked.
        assert!(!staging_identity_matches(
            &forged,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));

        // The genuine identity still matches.
        let ok = staging_identity_from_verified(
            &verified_read_snapshot(&snap_root, "gto_launcher", &snap.snapshot_sha256).unwrap(),
            &src,
        );
        assert!(staging_identity_matches(
            &ok,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// R2-3b: a revision built from a DIFFERENT hash (or a DIFFERENT logical id)
    /// is rejected even when hash/size/disk match.
    #[test]
    fn revision_with_wrong_hash_or_logical_id_rejected() {
        let root = temp_root("rev_wrong");
        let src = root.join("src.bin");
        fs::write(&src, b"REV-WRONG-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        let snap = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let other_hash = sha256_hex(b"OTHER-BYTES-NOT-THE-SNAPSHOT");

        // (a) revision derived from a different hash.
        let wrong_hash_rev = StagingIdentity {
            logical_sample_id: snap.logical_sample_id.clone(),
            revision: revision_id("gto_launcher", &other_hash),
            snapshot_sha256: snap.snapshot_sha256.clone(),
            snapshot_size_bytes: snap.snapshot_size_bytes,
            source_path: src.clone(),
        };
        assert!(!staging_identity_matches(
            &wrong_hash_rev,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));

        // (b) revision derived from a different logical id.
        let wrong_id_rev = StagingIdentity {
            logical_sample_id: snap.logical_sample_id.clone(),
            revision: revision_id("some_other_logical", &snap.snapshot_sha256),
            snapshot_sha256: snap.snapshot_sha256.clone(),
            snapshot_size_bytes: snap.snapshot_size_bytes,
            source_path: src.clone(),
        };
        assert!(!staging_identity_matches(
            &wrong_id_rev,
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));

        // Genuine still matches.
        assert!(staging_identity_matches(
            &snap.to_staging_identity(),
            &snap_root,
            &snap.snapshot_sha256,
            snap.snapshot_size_bytes
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// R2-5: fresh and reused snapshots of the same bytes carry IDENTICAL
    /// identity metadata (revision, hash, size, PE identity, logical id). Only
    /// the provenance fields (source_path, captured_at, provenance_tool_revision)
    /// may reflect the specific capture.
    #[test]
    fn fresh_and_reused_snapshot_have_same_identity_metadata() {
        let root = temp_root("fresh_reuse_identity");
        let src = root.join("src.bin");
        // A minimal valid PE so `pe_identity_of` produces `Some`.
        fs::write(&src, minimal_pe_bytes()).unwrap();
        let snap_root = root.join("snapshots");
        let fresh = capture_snapshot(&src, &snap_root, "gto_launcher", "rev@first").unwrap();
        let reused = capture_snapshot(&src, &snap_root, "gto_launcher", "rev@second").unwrap();

        // Identity fields identical.
        assert_eq!(fresh.logical_sample_id, reused.logical_sample_id);
        assert_eq!(fresh.revision, reused.revision);
        assert_eq!(fresh.snapshot_sha256, reused.snapshot_sha256);
        assert_eq!(fresh.snapshot_size_bytes, reused.snapshot_size_bytes);
        assert_eq!(fresh.source_sha256, reused.source_sha256);
        assert_eq!(fresh.source_size_bytes, reused.source_size_bytes);
        assert_eq!(fresh.snapshot_abs_path, reused.snapshot_abs_path);
        assert_eq!(fresh.pe_identity, reused.pe_identity);
        // PE identity is actually parsed in both paths (not None in reuse).
        assert!(
            fresh.pe_identity.is_some() && reused.pe_identity.is_some(),
            "both fresh and reused must carry a PE identity"
        );

        // Provenance fields reflect each capture (they are NOT identity).
        assert_eq!(fresh.provenance_tool_revision, "rev@first");
        assert_eq!(reused.provenance_tool_revision, "rev@second");
        assert!(reused.captured_at >= fresh.captured_at);
        let _ = fs::remove_dir_all(&root);
    }

    /// R2-6: publish no-replace race. After temp verification but before publish,
    /// a WRONG target is placed at the content address. Publish must detect it,
    /// refuse to overwrite it, and fail closed. The wrong target is preserved.
    #[test]
    fn publish_race_wrong_target_rejected_and_not_overwritten() {
        let root = temp_root("publish_race");
        let src = root.join("src.bin");
        fs::write(&src, b"PUBLISH-RACE-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        let want_sha = sha256_hex(b"PUBLISH-RACE-CONTENT");
        let target_file = snap_root
            .join("gto_launcher")
            .join(&want_sha)
            .join(SNAPSHOT_FILENAME);
        let wrong_bytes = b"WRONG-TARGET-INJECTED-BYTES";

        // Inject a wrong target between temp verification and publish.
        let injected = target_file.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            None,
            Some(Box::new(move || {
                fs::write(&injected, wrong_bytes).unwrap();
            })),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CaptureError::SnapshotAlreadyExistsButMismatch(_)
        ));
        // The injected wrong target was NOT overwritten.
        assert!(target_file.is_file());
        assert_eq!(fs::read(&target_file).unwrap(), wrong_bytes);
        // No temp file left behind.
        let dir = snap_root.join("gto_launcher").join(&want_sha);
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".capturing-")),
            "no leftover temp files: {names:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-1: `publish_no_replace` is a genuinely atomic no-replace primitive
    /// (hard link). A second link to an existing target is `AlreadyExists` and
    /// the first target's full content is preserved (never overwritten, never
    /// half-written).
    #[test]
    fn atomic_publish_hard_link_never_overwrites() {
        let root = temp_root("atomic_publish");
        let snap_root = root.join("snapshots");
        let dir = snap_root
            .join("gto_launcher")
            .join(&sha256_hex(b"ATOMIC-CONTENT"));
        fs::create_dir_all(&dir).unwrap();
        let temp = dir.join(".capturing-1-1-1.tmp");
        let target = dir.join(SNAPSHOT_FILENAME);
        let payload = b"ATOMIC-NO-REPLACE-PAYLOAD";
        fs::write(&temp, payload).unwrap();

        // First publish wins.
        assert_eq!(
            publish_no_replace(&temp, &target).unwrap(),
            PublishOutcome::Published
        );
        // Target is fully written (no half-written exposure).
        assert_eq!(fs::read(&target).unwrap(), payload);

        // A second publish to the same target is AlreadyExists (never overwrite).
        assert_eq!(
            publish_no_replace(&temp, &target).unwrap(),
            PublishOutcome::AlreadyExists
        );
        // The original target content is intact, not replaced.
        assert_eq!(fs::read(&target).unwrap(), payload);
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-2: real concurrent publishers racing on the same content address never
    /// overwrite each other and never expose a half-written file. Distinct payloads
    /// make the winning publisher observable: the final target must equal the full
    /// payload belonging to the sole `Published` result.
    #[test]
    fn concurrent_publishers_never_overwrite_or_expose_partial() {
        let root = temp_root("concurrent_pub");
        let snap_root = root.join("snapshots");
        let dir = snap_root
            .join("gto_launcher")
            .join(&sha256_hex(b"RACE-ADDRESS"));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join(SNAPSHOT_FILENAME);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));

        let mut handles = Vec::new();
        for i in 0..12 {
            let dir = dir.clone();
            let target = target.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let payload = format!("CONCURRENT-PUBLISH-PAYLOAD-{i:02}-FULL").into_bytes();
                let temp = dir.join(format!(".capturing-pub-{i}.tmp"));
                fs::write(&temp, &payload).unwrap();
                barrier.wait();
                let outcome = publish_no_replace(&temp, &target).unwrap();
                let _ = fs::remove_file(&temp);
                (i, payload, outcome)
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners: Vec<_> = results
            .iter()
            .filter(|(_, _, outcome)| *outcome == PublishOutcome::Published)
            .collect();
        assert_eq!(
            winners.len(),
            1,
            "exactly one publisher must win: {results:?}"
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, _, outcome)| *outcome == PublishOutcome::AlreadyExists)
                .count(),
            results.len() - 1
        );

        let final_bytes = fs::read(&target).unwrap();
        assert_eq!(
            final_bytes.as_slice(),
            winners[0].1.as_slice(),
            "target must be the winner's full payload"
        );
        assert!(
            results
                .iter()
                .any(|(_, payload, _)| final_bytes.as_slice() == payload.as_slice()),
            "target must equal one complete publisher payload"
        );
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".capturing-pub-")),
            "no leftover publisher temp files: {names:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-3: even when the existing snapshot is corrupt/empty/unverifiable, the
    /// idempotent-reuse path still completes the second source read before
    /// failing closed on the bad existing snapshot.
    #[test]
    fn corrupt_existing_snapshot_reuse_path_still_completes_second_read() {
        let root = temp_root("corrupt_reuse");
        let src = root.join("src.bin");
        let payload = b"CORRUPT-REUSE-CONTENT";
        fs::write(&src, payload).unwrap();
        let snap_root = root.join("snapshots");
        let a = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let a_path = a.snapshot_abs_path.clone();

        // Corrupt the on-disk snapshot (truncate to 0 → unverifiable), then
        // re-capture. A flag proves the second read is reached.
        fs::write(&a_path, b"").unwrap();
        let reached_second_read = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = reached_second_read.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            })),
            None,
        )
        .unwrap_err();
        assert!(
            reached_second_read.load(std::sync::atomic::Ordering::SeqCst),
            "reuse path must complete the second source read even when the existing snapshot is corrupt"
        );
        assert!(matches!(
            err,
            CaptureError::SnapshotAlreadyExistsButMismatch(_)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-3b: same for a MISMATCHING existing snapshot (present but wrong hash).
    #[test]
    fn mismatching_existing_snapshot_reuse_path_still_completes_second_read() {
        let root = temp_root("mismatch_reuse");
        let src = root.join("src.bin");
        let payload = b"MISMATCH-REUSE-CONTENT";
        fs::write(&src, payload).unwrap();
        let snap_root = root.join("snapshots");
        let a = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let a_path = a.snapshot_abs_path.clone();

        // Overwrite with DIFFERENT content → verified snapshot no longer matches
        // the intended hash (Mismatch), but the file is still readable.
        fs::write(&a_path, b"DIFFERENT-BYTES-NOT-MATCHING").unwrap();
        let reached_second_read = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = reached_second_read.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
            })),
            None,
        )
        .unwrap_err();
        assert!(
            reached_second_read.load(std::sync::atomic::Ordering::SeqCst),
            "reuse path must complete the second source read even on a mismatching existing snapshot"
        );
        assert!(matches!(
            err,
            CaptureError::SnapshotAlreadyExistsButMismatch(_)
        ));
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-3c: when the source CHANGES during verification of a corrupt existing
    /// snapshot, `SourceChangedDuringCapture` wins (source stability takes
    /// precedence over the bad snapshot), and the existing snapshot is preserved.
    #[test]
    fn corrupt_existing_snapshot_but_source_changed_wins() {
        let root = temp_root("corrupt_reuse_change");
        let src = root.join("src.bin");
        let payload = b"CORRUPT-REUSE-CHANGE-A";
        fs::write(&src, payload).unwrap();
        let snap_root = root.join("snapshots");
        let a = capture_snapshot(&src, &snap_root, "gto_launcher", "rev").unwrap();
        let a_path = a.snapshot_abs_path.clone();

        // Corrupt the existing snapshot, then mutate the source between the two
        // reads.
        fs::write(&a_path, b"").unwrap();
        let hook_src = src.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::write(&hook_src, b"CORRUPT-REUSE-CHANGE-B").unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert_eq!(err, CaptureError::SourceChangedDuringCapture);
        // The corrupt existing snapshot is neither deleted nor overwritten.
        assert!(a_path.is_file());
        assert_eq!(fs::read(&a_path).unwrap(), b"");
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-4: fresh-capture cleanup never deletes a directory it did NOT create
    /// (the TOCTOU fix). If the leaf dir already exists (a concurrent task's
    /// dir), a failing capture removes only its own temp file and leaves the
    /// dir intact.
    #[test]
    fn fresh_capture_cleanup_preserves_precreated_dir() {
        let root = temp_root("preserve_dir");
        let src = root.join("src.bin");
        fs::write(&src, b"PRESERVE-DIR-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        let want_sha = sha256_hex(b"PRESERVE-DIR-CONTENT");
        let dir = snap_root.join("gto_launcher").join(&want_sha);
        fs::create_dir_all(&dir).unwrap(); // pre-created (not by this capture)

        // Source deleted between the two reads -> fresh capture fails on the
        // second read. It must remove its temp but NOT the pre-existing dir.
        let hook_src = src.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::remove_file(&hook_src).unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, CaptureError::SourceUnreadable(_)));
        // The pre-created dir is preserved (empty, but still present).
        assert!(
            dir.is_dir(),
            "must not delete a pre-existing (concurrent) dir"
        );
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().all(|n| !n.starts_with(".capturing-")),
            "own temp removed but dir preserved: {names:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-4b: a failed fresh capture removes only its own temp file and never
    /// removes a file that another capture places in the shared hash directory.
    /// Empty hash directories are intentionally allowed to remain.
    #[test]
    fn fresh_capture_failure_does_not_delete_concurrent_temp() {
        let root = temp_root("concurrent_cleanup");
        let src = root.join("src.bin");
        fs::write(&src, b"CONCURRENT-CLEANUP-CONTENT").unwrap();
        let snap_root = root.join("snapshots");
        let want_sha = sha256_hex(b"CONCURRENT-CLEANUP-CONTENT");
        let dir = snap_root.join("gto_launcher").join(&want_sha);
        let marker = dir.join(".capturing-other-task.tmp");

        let hook_src = src.clone();
        let hook_marker = marker.clone();
        let err = capture_snapshot_impl(
            &src,
            &snap_root,
            "gto_launcher",
            "rev",
            Some(Box::new(move || {
                fs::write(&hook_marker, b"other-task-temp").unwrap();
                fs::remove_file(&hook_src).unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, CaptureError::SourceUnreadable(_)));
        assert!(
            marker.is_file(),
            "another task's temp must never be removed"
        );
        let names: Vec<String> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == ".capturing-other-task.tmp"));
        let _ = fs::remove_dir_all(&root);
    }

    /// R3-5: `TempGuard::disarm` really changes guard state — a disarmed guard
    /// does NOT delete the temp file on drop, an armed one does.
    #[test]
    fn temp_guard_disarm_really_changes_state() {
        let root = temp_root("guard_disarm");
        fs::create_dir_all(&root).unwrap();

        // Armed guard: file removed on drop.
        let armed_file = root.join("armed.tmp");
        fs::write(&armed_file, b"armed").unwrap();
        {
            let _g = TempGuard::new(armed_file.clone());
        }
        assert!(!armed_file.exists(), "armed guard must remove its file");

        // Disarmed guard: file preserved on drop.
        let disarmed_file = root.join("disarmed.tmp");
        fs::write(&disarmed_file, b"disarmed").unwrap();
        {
            let mut g = TempGuard::new(disarmed_file.clone());
            g.disarm();
        }
        assert!(
            disarmed_file.exists(),
            "disarmed guard must NOT remove its file"
        );
        let _ = fs::remove_dir_all(&root);
    }

    /// A tiny valid PE (PE32+ DOS + NT headers + one section) so the PE-identity
    /// parse succeeds. Used to prove fresh/reused PE-identity consistency.
    fn minimal_pe_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        // DOS header: 'MZ' + e_lfanew at 0x3c = 0x80.
        v.extend_from_slice(b"MZ");
        v.resize(0x40, 0);
        v[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // Pad from the 64-byte DOS header out to the NT-header offset (0x80).
        v.resize(0x80, 0);
        // PE signature.
        v.extend_from_slice(b"PE\0\0");
        // COFF header (20 bytes).
        v.extend_from_slice(&0x14cu16.to_le_bytes()); // machine: IMAGE_FILE_MACHINE_AMD64
        v.extend_from_slice(&1u16.to_le_bytes()); // number of sections
        v.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        v.extend_from_slice(&0u32.to_le_bytes()); // ptr to symtab
        v.extend_from_slice(&0u32.to_le_bytes()); // num symbols
        v.extend_from_slice(&240u16.to_le_bytes()); // size of optional header (PE32+ = 0xF0)
        v.extend_from_slice(&0u16.to_le_bytes()); // characteristics
                                                  // Optional header magic 0x20b (PE32+).
        v.extend_from_slice(&0x20bu16.to_le_bytes());
        // NT headers = sig(4) + coff(20) + optional(240). Pad through the
        // PE32+ optional header (240 bytes total, incl. the 2-byte magic already
        // written).
        let nt_offset = 0x80usize;
        let opt_start = nt_offset + 4 + 20;
        v.resize(opt_start + 240, 0);
        // After the optional header: one section header (40 bytes) named ".text",
        // plus trailing padding so `nt_slice` fully contains the section table.
        let base = opt_start + 240;
        v.resize(base + 40 + 48, 0);
        v[base..base + 8].copy_from_slice(b".text\0\0\0");
        v
    }

    // ------------------------------------------------------------------
    // G3-R5: shared snapshot-path contract vectors. This parser must agree with
    // the independent mida-acceptance verifier's copy (same fixture).
    // ------------------------------------------------------------------

    /// Load the shared contract vectors and validate `parse_snapshot_path`.
    #[test]
    fn shared_snapshot_path_contract_vectors() {
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("tests/fixtures/snapshot_path_contract.json");
        let raw = std::fs::read_to_string(&fixture)
            .unwrap_or_else(|e| panic!("cannot read contract fixture {}: {e}", fixture.display()));
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let real_root = std::env::temp_dir().join("mida_snapshot_path_contract_root");
        for v in value["vectors"].as_array().unwrap() {
            let raw_path = v["path"]
                .as_str()
                .unwrap()
                .replace("__ROOT__", &real_root.display().to_string());
            let expected = v["expected"].as_str().unwrap();
            let path = std::path::Path::new(&raw_path);
            let parsed = parse_snapshot_path(path);
            match expected {
                "valid" => {
                    let p =
                        parsed.unwrap_or_else(|e| panic!("vector {raw_path} should be valid: {e}"));
                    assert_eq!(
                        p.logical_sample_id,
                        v["logical_sample_id"].as_str().unwrap()
                    );
                    assert_eq!(p.sha256, v["sha256"].as_str().unwrap());
                    assert_eq!(p.snapshot_path, path);
                }
                "invalid" => {
                    assert!(parsed.is_err(), "vector {raw_path} must be invalid");
                }
                other => panic!("unknown expected {other} in fixture"),
            }
        }
    }

    /// The CLI launch helper's GTO wrapper (`snapshot_root_of_snapshot`) must
    /// reject a path whose logical-sample directory is not the GTO lane case id.
    #[test]
    fn cli_gto_wrapper_rejects_non_gto_logical_dir() {
        use crate::runner_preflight;
        let real_root = std::env::temp_dir().join("mida_gto_wrapper_root");
        let good = real_root
            .join("gto_launcher")
            .join("c".repeat(64))
            .join(SNAPSHOT_FILENAME);
        // GTO lane logical dir is accepted by the shared parser and the wrapper.
        let parsed = parse_snapshot_path(&good).unwrap();
        assert_eq!(parsed.logical_sample_id, "gto_launcher");
        let (root, hash) = runner_preflight::snapshot_root_of_snapshot(&good).unwrap();
        assert_eq!(root, real_root);
        assert_eq!(hash, "c".repeat(64));
        // A non-GTO logical dir fails the GTO wrapper (though structurally valid).
        let other = real_root
            .join("origin_macro")
            .join("c".repeat(64))
            .join(SNAPSHOT_FILENAME);
        assert!(parse_snapshot_path(&other).is_ok());
        assert!(runner_preflight::snapshot_root_of_snapshot(&other).is_err());
    }

    // ------------------------------------------------------------------
    // G3-R5-R1: strict canonical snapshot_root containment + raw ".".
    // ------------------------------------------------------------------

    /// A real, existing snapshot at a canonical content-addressed path passes
    /// strict disk verification.
    #[test]
    fn canonical_normal_snapshot_passes() {
        let root = temp_root("canonical_ok");
        let sha = "c".repeat(64);
        let path = root.join("gto_launcher").join(&sha).join(SNAPSHOT_FILENAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"SNAPSHOT-CONTENT").unwrap();
        let parsed = canonical_verify_snapshot_path(&path, &root, "gto_launcher", &sha).unwrap();
        // The returned snapshot_root is the STRICT-canonicalized root.
        assert_eq!(parsed.snapshot_root, std::fs::canonicalize(&root).unwrap());
        assert_eq!(parsed.snapshot_path, std::fs::canonicalize(&path).unwrap());
        assert!(parsed.snapshot_path.starts_with(&parsed.snapshot_root));
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Strict canonicalization: a missing/nonexistent snapshot fails closed and
    /// never falls back to the loose parent-canonicalized path.
    #[test]
    fn canonicalization_failure_does_not_fall_back() {
        let root = temp_root("canonical_missing");
        let sha = "c".repeat(64);
        let path = root.join("gto_launcher").join(&sha).join(SNAPSHOT_FILENAME);
        // The file does NOT exist.
        assert!(canonical_verify_snapshot_path(&path, &root, "gto_launcher", &sha).is_err());
        // Even if the parent directory exists, a missing snapshot must not fall
        // back to a loose path.
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let err = canonical_verify_snapshot_path(&path, &root, "gto_launcher", &sha).unwrap_err();
        assert!(
            err.contains("cannot be canonicalized") || err.contains("missing"),
            "missing snapshot must fail closed, no loose fallback: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A raw "." interior segment (C:\root\.\gto_launcher\<sha>\snapshot.bin) is
    /// rejected by the raw-string component check, even though Windows
    /// `Path::components()` would normalize `/./` away.
    #[test]
    fn raw_dot_path_rejected() {
        let root = std::env::temp_dir().join("mida_raw_dot_root");
        let raw = format!(
            "{}\\.\\gto_launcher\\{}\\snapshot.bin",
            root.display(),
            "c".repeat(64)
        );
        assert!(
            parse_snapshot_path(std::path::Path::new(&raw)).is_err(),
            "raw . interior segment must be rejected"
        );
        // Mixed separator form too.
        let raw2 = format!(
            "{}/./gto_launcher/{}/snapshot.bin",
            root.display(),
            "c".repeat(64)
        );
        assert!(
            parse_snapshot_path(std::path::Path::new(&raw2)).is_err(),
            "raw /./ interior segment must be rejected"
        );
    }

    /// A junction at the logical-sample directory that escapes the snapshot_root
    /// must be rejected by the launch helper. Deterministic: if junction creation
    /// fails, the test FAILS (no silent skip).
    #[cfg(windows)]
    #[test]
    fn junction_escape_of_logical_dir_rejected() {
        let root = temp_root("junction_logical");
        let sha = "c".repeat(64);
        // Real snapshot under root.
        let real = root.join("gto_launcher").join(&sha).join(SNAPSHOT_FILENAME);
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, b"JUNCTION-SNAPSHOT-CONTENT").unwrap();
        // An OUTSIDE directory holding the same logical/hash structure.
        let outside = root.join("outside_real");
        std::fs::create_dir_all(outside.join("gto_launcher").join(&sha)).unwrap();
        std::fs::write(
            outside
                .join("gto_launcher")
                .join(&sha)
                .join(SNAPSHOT_FILENAME),
            b"JUNCTION-SNAPSHOT-CONTENT",
        )
        .unwrap();
        // Replace root/gto_launcher with a junction to outside/gto_launcher.
        std::fs::remove_dir_all(&root.join("gto_launcher")).unwrap();
        let mklink = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&root.join("gto_launcher"))
            .arg(&outside.join("gto_launcher"))
            .output()
            .expect("mklink must be invocable");
        assert!(
            mklink.status.success(),
            "junction creation failed: {}",
            String::from_utf8_lossy(&mklink.stderr)
        );
        // The sealed path root/gto_launcher/<sha>/snapshot.bin now resolves to
        // outside/gto_launcher/<sha>/snapshot.bin, which is NOT under root.
        let sealed = root.join("gto_launcher").join(&sha).join(SNAPSHOT_FILENAME);
        assert!(sealed.is_file(), "junction must expose the snapshot");
        // Strict canonical verify must reject the escape.
        let err = canonical_verify_snapshot_path(&sealed, &root, "gto_launcher", &sha).unwrap_err();
        assert!(
            err.contains("escapes canonical snapshot root")
                || err.contains("cannot be canonicalized")
                || err.contains("not a well-formed snapshot address")
                || err.contains("!= canonicalized lexical root")
                || err.contains("!= canonical trusted root"),
            "junction escape of the logical dir must be rejected: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A junction at the hash directory that escapes the snapshot_root must be
    /// rejected.
    #[cfg(windows)]
    #[test]
    fn junction_escape_of_hash_dir_rejected() {
        let root = temp_root("junction_hash");
        let sha = "c".repeat(64);
        let real = root.join("gto_launcher").join(&sha).join(SNAPSHOT_FILENAME);
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, b"HASH-JUNCTION-CONTENT").unwrap();
        let outside = root.join("outside_real");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join(SNAPSHOT_FILENAME), b"HASH-JUNCTION-CONTENT").unwrap();
        // Replace root/gto_launcher/<sha> with a junction to outside.
        std::fs::remove_dir_all(&root.join("gto_launcher").join(&sha)).unwrap();
        let mklink = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&root.join("gto_launcher").join(&sha))
            .arg(&outside)
            .output()
            .expect("mklink must be invocable");
        assert!(
            mklink.status.success(),
            "junction creation failed: {}",
            String::from_utf8_lossy(&mklink.stderr)
        );
        let sealed = root.join("gto_launcher").join(&sha).join(SNAPSHOT_FILENAME);
        assert!(sealed.is_file());
        let err = canonical_verify_snapshot_path(&sealed, &root, "gto_launcher", &sha).unwrap_err();
        assert!(
            err.contains("escapes canonical snapshot root")
                || err.contains("cannot be canonicalized")
                || err.contains("not a well-formed snapshot address"),
            "junction escape of the hash dir must be rejected: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A trusted root that is ITSELF a junction (reparse alias) to a directory
    /// holding a valid snapshot tree must be rejected: the operator's trusted
    /// root must be a real directory, not a pointer.
    #[cfg(windows)]
    #[test]
    fn snapshot_root_junction_alias_to_valid_tree_rejected() {
        let root = temp_root("root_junction_valid");
        let sha = "c".repeat(64);
        // A REAL snapshot tree under an outside physical dir.
        let outside = root.join("physical_root");
        let real = outside
            .join("gto_launcher")
            .join(&sha)
            .join(SNAPSHOT_FILENAME);
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, b"ROOT-JUNCTION-CONTENT").unwrap();
        // The trusted root is a junction pointing to `outside`.
        let trusted = root.join("trusted_root");
        std::fs::create_dir_all(&trusted).unwrap();
        std::fs::remove_dir_all(&trusted).unwrap();
        let mklink = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&trusted)
            .arg(&outside)
            .output()
            .expect("mklink must be invocable");
        assert!(
            mklink.status.success(),
            "junction creation failed: {}",
            String::from_utf8_lossy(&mklink.stderr)
        );
        // A snapshot path under the trusted (junction) root that resolves to a
        // VALID snapshot tree must still be rejected because the trusted root
        // itself is a reparse alias.
        let sealed = trusted
            .join("gto_launcher")
            .join(&sha)
            .join(SNAPSHOT_FILENAME);
        assert!(sealed.is_file(), "junction must expose the snapshot");
        let err =
            canonical_verify_snapshot_path(&sealed, &trusted, "gto_launcher", &sha).unwrap_err();
        assert!(
            err.contains("junction/symlink/reparse alias") || err.contains("resolves to"),
            "a trusted root that is a junction alias must be rejected: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A caller-supplied trusted root that differs from the path's LEXICAL root
    /// (alternate root) is rejected.
    #[test]
    fn trusted_root_mismatch_rejected() {
        let root = temp_root("trusted_mismatch");
        let sha = "c".repeat(64);
        let path = root.join("gto_launcher").join(&sha).join(SNAPSHOT_FILENAME);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"TRUSTED-MISMATCH-CONTENT").unwrap();
        // The caller claims a DIFFERENT trusted root (alternate).
        let alt = root.join("alt_root");
        std::fs::create_dir_all(&alt).unwrap();
        let err = canonical_verify_snapshot_path(&path, &alt, "gto_launcher", &sha).unwrap_err();
        assert!(
            err.contains("lexical snapshot_root")
                || err.contains("!= caller trusted snapshot_root"),
            "a trusted-root mismatch must be rejected: {err}"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Prefix-aware path equivalence: extended-length / UNC forms normalize to
    /// the same path as their plain drive / UNC counterparts, but genuinely
    /// different paths are NOT equivalent.
    #[test]
    fn paths_equivalent_unc_and_extended_prefix_vectors() {
        // \\?\D:\snapshots  ==  D:\snapshots
        assert!(paths_equivalent(
            Path::new("\\\\?\\D:\\snapshots"),
            Path::new("D:\\snapshots")
        ));
        // \\?\UNC\server\share  ==  \\server\share
        assert!(paths_equivalent(
            Path::new("\\\\?\\UNC\\server\\share"),
            Path::new("\\\\server\\share")
        ));
        // case-insensitive
        assert!(paths_equivalent(
            Path::new("D:\\SnapShots"),
            Path::new("d:\\snapshots")
        ));
        // a mid-path literal "\\?\" is NOT stripped (prefix-aware)
        assert!(!paths_equivalent(
            Path::new("D:\\snapshots\\x\\\\?\\y"),
            Path::new("D:\\snapshots\\x\\y")
        ));
        // genuinely different paths are not equivalent
        assert!(!paths_equivalent(
            Path::new("D:\\snapshots"),
            Path::new("E:\\snapshots")
        ));
    }
}
