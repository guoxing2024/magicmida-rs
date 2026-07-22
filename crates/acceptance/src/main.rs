//! Read-only CLI for the independent acceptance kernel.
//!
//! ```text
//! mida-acceptance check-static <candidate> [--expected-sha256 HEX]
//!                                          [--role ROLE]
//!                                          [--oracle PATH]
//!                                          [--report PATH]
//! ```
//!
//! Exit codes: 0 = StructuralPassBehaviorPending, 2 = Rejected, 1 = I/O or config error.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use mida_acceptance::{check_static, CheckStaticOptions, Verdict};

fn main() {
    let code = match run() {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("error: {msg}");
            1
        }
    };
    process::exit(code);
}

fn run() -> Result<i32, String> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_help();
        return Ok(1);
    }
    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_help();
            Ok(0)
        }
        "-V" | "--version" | "version" => {
            println!("mida-acceptance {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        "check-static" => {
            args.remove(0);
            cmd_check_static(&args)
        }
        other => Err(format!(
            "unknown command '{other}'. Use: mida-acceptance check-static <candidate>"
        )),
    }
}

fn print_help() {
    println!(
        "\
mida-acceptance - independent static PE acceptance kernel (R0B)

Usage:
  mida-acceptance check-static <candidate> [options]

Options:
  --expected-sha256 <hex>  Fail-closed if file digest does not match
  --role <role>            Artifact role label (default: candidate)
  --oracle <path>          Legacy oracle file (comparison observation only)
  --report <path>          Write deterministic JSON report to path
  -h, --help               Show help
  -V, --version            Show version

Exit codes:
  0  StructuralPassBehaviorPending
  2  Rejected
  1  I/O, configuration, or internal error
"
    );
}

fn cmd_check_static(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err(
            "Usage: mida-acceptance check-static <candidate> [--expected-sha256 HEX]".into(),
        );
    }
    let mut candidate: Option<PathBuf> = None;
    let mut expected_sha256: Option<String> = None;
    let mut role: Option<String> = None;
    let mut oracle: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--expected-sha256" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-sha256".into());
                }
                expected_sha256 = Some(args[i].clone());
            }
            flag if flag.starts_with("--expected-sha256=") => {
                expected_sha256 = Some(flag["--expected-sha256=".len()..].to_string());
            }
            "--role" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --role".into());
                }
                role = Some(args[i].clone());
            }
            flag if flag.starts_with("--role=") => {
                role = Some(flag["--role=".len()..].to_string());
            }
            "--oracle" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --oracle".into());
                }
                oracle = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--oracle=") => {
                oracle = Some(PathBuf::from(&flag["--oracle=".len()..]));
            }
            "--report" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --report".into());
                }
                report_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--report=") => {
                report_path = Some(PathBuf::from(&flag["--report=".len()..]));
            }
            "-h" | "--help" => {
                print_help();
                return Ok(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'"));
            }
            other => {
                if candidate.is_some() {
                    return Err(format!("unexpected argument '{other}'"));
                }
                candidate = Some(PathBuf::from(other));
            }
        }
        i += 1;
    }

    let candidate = candidate.ok_or_else(|| "missing <candidate> path".to_string())?;
    let bytes = fs::read(&candidate)
        .map_err(|e| format!("failed to read candidate '{}': {e}", candidate.display()))?;

    let oracle_bytes = match oracle {
        None => None,
        Some(p) => Some(
            fs::read(&p).map_err(|e| format!("failed to read oracle '{}': {e}", p.display()))?,
        ),
    };

    let opts = CheckStaticOptions {
        role,
        expected_sha256,
        expected_size: None,
        oracle_bytes,
    };

    let report = check_static(&bytes, &opts);
    let json = report
        .to_json()
        .map_err(|e| format!("failed to serialize report: {e}"))?;

    // Always print report to stdout for piping; optional file copy.
    println!("{json}");
    if let Some(path) = report_path {
        // Trailing newline for text-file friendliness; body without path/timestamp.
        let mut file_body = json.clone();
        file_body.push('\n');
        fs::write(&path, file_body)
            .map_err(|e| format!("failed to write report '{}': {e}", path.display()))?;
    }

    match report.verdict {
        Verdict::StructuralPassBehaviorPending => Ok(0),
        Verdict::Rejected => Ok(2),
        Verdict::Accepted => {
            // Contract violation if ever reached.
            eprintln!("error: internal contract violation: Accepted verdict in R0B");
            Ok(1)
        }
    }
}
