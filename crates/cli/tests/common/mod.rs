//! Shared test helper: resolve (and if necessary build) the `mida-acceptance`
//! binary so the CLI integration tests are self-contained under a fresh
//! `CARGO_TARGET_DIR` (`cargo test -p mida-cli --offline`).
//!
//! G3-R3-R2-R1 (section 四): a fresh `CARGO_TARGET_DIR` does not contain the
//! acceptance sibling binary. `cargo test -p mida-cli` builds only the CLI and
//! its verifier stub, not `mida-acceptance`. This helper builds the acceptance
//! binary on demand into a DEDICATED, per-process target directory:
//!
//! - hermetic: it never writes into the shared `CARGO_TARGET_DIR` (so it cannot
//!   corrupt or race a concurrent `cargo test --workspace` build), and it uses a
//!   unique temp dir per process id;
//! - concurrency-safe: cargo's own build locking serializes concurrent
//!   invocations of the same target dir, and each test process uses a distinct
//!   dir so parallel test binaries never collide;
//! - offline: `--offline` reuses the global `~/.cargo/registry` cache, so a
//!   fresh target dir still resolves all dependencies.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A unique, dedicated target dir for building the acceptance binary (one per
/// process). Kept distinct from the shared `CARGO_TARGET_DIR` so it is hermetic.
fn dedicated_target_dir() -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "mida_acceptance_build_{}_{}",
            std::process::id(),
            nanos
        ));
        dir
    })
    .clone()
}

/// Resolve the `mida-acceptance.exe` binary, building it on demand into a
/// dedicated target dir if it is not already present there. Cached per process.
///
/// Returns the canonical path to the freshly built acceptance binary.
pub fn acceptance_bin() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let target_dir = dedicated_target_dir();
        let bin = target_dir.join("debug").join("mida-acceptance.exe");
        if bin.exists() {
            return bin;
        }
        // Build the acceptance package into the dedicated target dir. `--offline`
        // uses the global registry cache; the dedicated target dir keeps this
        // hermetic and concurrency-safe (distinct from the shared target).
        let status = Command::new(env!("CARGO"))
            .arg("build")
            .arg("-p")
            .arg("mida-acceptance")
            .arg("--offline")
            .env("CARGO_TARGET_DIR", &target_dir)
            .current_dir(workspace_root())
            .status()
            .expect("spawn cargo to build the acceptance binary");
        assert!(
            status.success() && bin.exists(),
            "failed to build mida-acceptance into {}",
            target_dir.display()
        );
        bin
    })
    .clone()
}
