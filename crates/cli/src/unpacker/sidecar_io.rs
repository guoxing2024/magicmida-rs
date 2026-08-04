//! Shared atomic file I/O for sidecars and evidence bundles.
//!
//! [`atomic_write`] writes `contents` to a uniquely-named temp file in the
//! destination directory, flushes and fsyncs it, then atomically replaces the
//! destination (`MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)` on Windows,
//! `rename` elsewhere). A crash or kill before the rename leaves only a
//! `.<name>.tmp-*` file that is never a valid sidecar or bundle; the next run
//! simply allocates a fresh temp file and overwrites the destination.
//!
//! The temp file is created with `create_new`, so concurrent writers never
//! collide on the same temp path.
//!
//! NOTE (P3 hygiene): `tls_evidence.rs`, `relocation_evidence.rs` and
//! `section_rebuild_evidence.rs` still carry local copies of this logic;
//! dedup them during the runtime-consolidation work.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};

/// Atomically write `contents` to `destination` (parent is created if needed).
pub(crate) fn atomic_write(destination: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| anyhow!("destination has no parent: {}", destination.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create destination directory {}", parent.display()))?;
    let temp = create_temp_file(
        parent,
        destination.file_name().unwrap_or_default(),
        contents,
    )?;
    if let Err(error) = atomic_replace(&temp, destination) {
        let _ = fs::remove_file(&temp);
        return Err(error).with_context(|| format!("atomically replace {}", destination.display()));
    }
    Ok(())
}

/// Create and fully sync a uniquely-named temp file next to the destination.
fn create_temp_file(
    parent: &Path,
    destination_name: &OsStr,
    contents: &[u8],
) -> anyhow::Result<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..32u32 {
        let name = format!(
            ".{}.tmp-{}-{}",
            destination_name.to_string_lossy(),
            std::process::id(),
            now.saturating_add(u128::from(attempt))
        );
        let path = parent.join(name);
        let mut file = match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("create temporary file {}", path.display()))
            }
        };
        let result = file
            .write_all(contents)
            .and_then(|_| file.flush())
            .and_then(|_| file.sync_all());
        drop(file);
        if let Err(error) = result {
            let _ = fs::remove_file(&path);
            return Err(error).with_context(|| format!("sync temporary file {}", path.display()));
        }
        return Ok(path);
    }
    Err(anyhow!("unable to allocate unique temporary file"))
}

#[cfg(unix)]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(temp, destination)
}

#[cfg(windows)]
fn atomic_replace(temp: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let temp_w: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination_w: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let result = unsafe {
        MoveFileExW(
            temp_w.as_ptr(),
            destination_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
