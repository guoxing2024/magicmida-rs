//! The canonical content-addressed snapshot path contract, acceptance-side copy.
//!
//! The independent `mida-acceptance` verifier cannot depend on `mida-cli`
//! (dependency boundary is one-way: production never depends on acceptance), so
//! it keeps a MINIMAL local copy of the snapshot-path parser with the SAME rules
//! as `mida-cli::sample_snapshot::parse_snapshot_path`:
//!
//! `<snapshot_root>/<logical_sample_id>/<sha256>/snapshot.bin`
//!
//! Rules enforced (identical to the CLI contract):
//! - absolute path;
//! - no `.` / `..` components;
//! - file name exactly `snapshot.bin`;
//! - hash directory exactly 64 LOWERCASE hex;
//! - a valid `logical_sample_id` directory and a `snapshot_root` present.
//!
//! Both parsers are validated against the SAME contract vectors
//! (`tests/fixtures/snapshot_path_contract.json`), so no parser may diverge. If
//! the layout ever changes, both the CLI and this module must be audited
//! together.

use std::path::{Path, PathBuf};

/// The immutable snapshot file name (must match the CLI producer's
/// `crate::sample_snapshot::SNAPSHOT_FILENAME`).
pub const SNAPSHOT_FILENAME: &str = "snapshot.bin";

/// The canonical parsed snapshot path: snapshot_root, logical_sample_id, sha256,
/// snapshot_path. Callers must NOT re-derive or extend these rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSnapshotPath {
    pub snapshot_root: PathBuf,
    pub logical_sample_id: String,
    pub sha256: String,
    pub snapshot_path: PathBuf,
}

/// Parse a trusted immutable snapshot path into a structured value, enforcing the
/// exact contract above. Fail-closed on relative path, `.`/`..`, wrong filename,
/// a non-64-lowercase-hex hash dir, or a missing component.
pub fn parse_snapshot_path(path: &Path) -> Result<ParsedSnapshotPath, String> {
    if !path.is_absolute() {
        return Err(format!(
            "GTO snapshot path {} is not absolute",
            path.display()
        ));
    }
    // Reject `.` / `..` at the RAW string level BEFORE `Path::components()`
    // normalizes them away (on Windows a `/./` or `\.\` interior segment is
    // collapsed). Handle drive/UNC/`\\?\` prefixes so a legitimate absolute path
    // is never falsely rejected.
    let raw = path.to_string_lossy();
    for comp in raw.split(['/', '\\']) {
        if comp == "." || comp == ".." {
            return Err(format!(
                "GTO snapshot path {raw} contains a relative ({comp:?}) component"
            ));
        }
    }
    for comp in path.components() {
        match comp {
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err(format!(
                    "GTO snapshot path {} contains a relative ({comp:?}) component",
                    path.display()
                ));
            }
            _ => {}
        }
    }
    let name = path
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| format!("GTO snapshot path {} has no file name", path.display()))?;
    if name != SNAPSHOT_FILENAME {
        return Err(format!(
            "GTO snapshot path {} must end in {SNAPSHOT_FILENAME}",
            path.display()
        ));
    }
    let sha_dir = path
        .parent()
        .ok_or_else(|| format!("GTO snapshot path {} has no hash directory", path.display()))?;
    let sha_name = sha_dir
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| format!("GTO snapshot path {} hash dir has no name", path.display()))?;
    if sha_name.len() != 64
        || !sha_name.bytes().all(|b| b.is_ascii_hexdigit())
        || sha_name != sha_name.to_ascii_lowercase()
    {
        return Err(format!(
            "GTO snapshot path hash dir {sha_name:?} is not exactly 64 lowercase hex"
        ));
    }
    let logical_dir = sha_dir.parent().ok_or_else(|| {
        format!(
            "GTO snapshot path {} has no logical-sample directory",
            path.display()
        )
    })?;
    let logical_name = logical_dir
        .file_name()
        .and_then(|f| f.to_str())
        .ok_or_else(|| {
            format!(
                "GTO snapshot path {} logical-sample dir has no name",
                path.display()
            )
        })?;
    // logical_sample_id validation must EXACTLY mirror
    // `mida-cli::sample_snapshot::validate_logical_sample_id`: non-empty, no `/`
    // or `\`, no `.`/`..`/contains-`..` component. Locked by the shared contract
    // vectors (bad..id and separator cases).
    if logical_name.trim().is_empty()
        || logical_name.contains('/')
        || logical_name.contains('\\')
        || logical_name == ".."
        || logical_name == "."
        || logical_name.contains("..")
    {
        return Err(format!(
            "GTO snapshot path logical-sample directory {logical_name:?} is invalid"
        ));
    }
    let root = logical_dir
        .parent()
        .ok_or_else(|| format!("GTO snapshot path {} has no snapshot_root", path.display()))?;
    Ok(ParsedSnapshotPath {
        snapshot_root: root.to_path_buf(),
        logical_sample_id: logical_name.to_string(),
        sha256: sha_name.to_string(),
        snapshot_path: path.to_path_buf(),
    })
}

/// Strictly canonicalize a trusted snapshot path and verify it stays under the
/// canonical `snapshot_root` with the correct logical-sample and hash layers
/// (mirror of `mida-cli::sample_snapshot::canonical_verify_snapshot_path`).
///
/// STRICT `std::fs::canonicalize` with NO loose fallback: a missing file or any
/// canonicalization/reparse failure fails closed. A junction/symlink/reparse
/// whose logical/hash/file layer resolves OUTSIDE the canonical snapshot_root is
/// rejected. Both the CLI and this copy are validated by the same contract tests.
pub fn canonical_verify_snapshot_path(
    path: &Path,
    expected_logical_sample_id: &str,
    expected_sha256: &str,
) -> Result<ParsedSnapshotPath, String> {
    let parsed = parse_snapshot_path(path)?;
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
    let canonical = std::fs::canonicalize(path).map_err(|e| {
        format!(
            "snapshot path {} cannot be canonicalized (missing or reparse failure): {e}",
            path.display()
        )
    })?;
    let canonical_root = std::fs::canonicalize(&parsed.snapshot_root).map_err(|e| {
        format!(
            "snapshot root {} cannot be canonicalized: {e}",
            parsed.snapshot_root.display()
        )
    })?;
    if !canonical.starts_with(&canonical_root) {
        return Err(format!(
            "canonical snapshot path {} escapes canonical snapshot root {} \
             (junction/symlink/reparse escape is rejected)",
            canonical.display(),
            canonical_root.display()
        ));
    }
    let canonical_parsed = parse_snapshot_path(&canonical).map_err(|e| {
        format!(
            "canonical snapshot path {} is not a well-formed snapshot address: {e}",
            canonical.display()
        )
    })?;
    if canonical_parsed.snapshot_root != canonical_root {
        return Err(format!(
            "canonical snapshot root {} != canonicalized lexical root {}",
            canonical_parsed.snapshot_root.display(),
            canonical_root.display()
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
