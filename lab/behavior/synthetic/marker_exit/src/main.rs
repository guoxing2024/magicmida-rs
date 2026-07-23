//! Synthetic console PE for VNEXT behavioral B-A1.
//!
//! Modes (first arg or `MIDA_BEH_MODE`):
//! - `pass`      — exit 0 and write marker line to `MIDA_BEH_MARKER_PATH`
//! - `fail_exit` — write marker, exit 1
//! - `no_marker` — exit 0, do not write marker
//! - `hang`      — sleep forever (probe must time out → Inconclusive)

use std::env;
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const MARKER_LINE: &str = "MIDA_BEH_MARKER=1\n";

fn mode_from_args() -> String {
    if let Some(a) = env::args().nth(1) {
        return a;
    }
    env::var("MIDA_BEH_MODE").unwrap_or_else(|_| "pass".to_string())
}

fn marker_path() -> Option<PathBuf> {
    env::var_os("MIDA_BEH_MARKER_PATH").map(PathBuf::from)
}

fn write_marker() -> Result<(), String> {
    let path = marker_path().ok_or_else(|| "MIDA_BEH_MARKER_PATH unset".to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&path, MARKER_LINE).map_err(|e| e.to_string())
}

fn main() {
    let mode = mode_from_args();
    match mode.as_str() {
        "pass" => {
            if let Err(e) = write_marker() {
                eprintln!("marker write failed: {e}");
                std::process::exit(2);
            }
            std::process::exit(0);
        }
        "fail_exit" => {
            let _ = write_marker();
            std::process::exit(1);
        }
        "no_marker" => {
            std::process::exit(0);
        }
        "hang" => loop {
            thread::sleep(Duration::from_secs(3600));
        },
        other => {
            eprintln!("unknown mode: {other}");
            std::process::exit(3);
        }
    }
}
