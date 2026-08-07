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
