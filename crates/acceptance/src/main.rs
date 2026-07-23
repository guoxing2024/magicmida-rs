//! Read-only CLI for the independent acceptance kernel.
//!
//! ```text
//! mida-acceptance check-static <candidate> [options]
//! mida-acceptance check-with-behavior <candidate> --behavior-evidence <json> [options]
//! ```
//!
//! Exit codes: 0 = StructuralPassBehaviorPending or Accepted,
//! 2 = Rejected, 1 = I/O or config error.
//! Report writes never alias candidate, oracle, or evidence inputs.

use std::env;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process;

use mida_acceptance::{
    check_static, check_with_behavior, BehaviorEvidence, CheckStaticOptions, Verdict,
};

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
        "check-with-behavior" => {
            args.remove(0);
            cmd_check_with_behavior(&args)
        }
        other => Err(format!(
            "unknown command '{other}'. Use: check-static | check-with-behavior"
        )),
    }
}

fn print_help() {
    println!(
        "\
mida-acceptance - independent PE acceptance kernel (R0B + B-A2 compose)

Usage:
  mida-acceptance check-static <candidate> [options]
  mida-acceptance check-with-behavior <candidate> --behavior-evidence <path> [options]

Options:
  --expected-sha256 <hex>  Fail-closed if file digest does not match
  --expected-size <bytes>  Fail-closed if file length does not match
  --role <role>            Artifact role label (default: candidate)
  --oracle <path>          Legacy oracle file (comparison observation only)
  --behavior-evidence <p>  Pre-recorded mida.behavior-evidence/v0 JSON (compose only)
  --report <path>          Write deterministic JSON report to path
                           (must not alias candidate, oracle, or evidence)
  -h, --help               Show help
  -V, --version            Show version

Exit codes:
  0  StructuralPassBehaviorPending or Accepted (check-with-behavior only for Accepted)
  2  Rejected
  1  I/O, configuration, or internal error

Notes:
  check-static never returns Accepted (R0B).
  check-with-behavior may return Accepted when structure passes and evidence Pass binds.
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
    let mut expected_size: Option<u64> = None;
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
            "--expected-size" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-size".into());
                }
                expected_size = Some(parse_expected_size(&args[i])?);
            }
            flag if flag.starts_with("--expected-size=") => {
                expected_size = Some(parse_expected_size(&flag["--expected-size=".len()..])?);
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
    let (bytes, candidate_file) = read_input(&candidate, "candidate")?;

    let (oracle_bytes, oracle_file) = match oracle.as_deref() {
        None => (None, None),
        Some(path) => {
            let (bytes, file) = read_input(path, "oracle")?;
            (Some(bytes), Some(file))
        }
    };

    let opts = CheckStaticOptions {
        role,
        expected_sha256,
        expected_size,
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
        write_report(
            &path,
            file_body.as_bytes(),
            (&candidate, &candidate_file),
            oracle.as_deref().zip(oracle_file.as_ref()),
        )?;
    }

    match report.verdict {
        Verdict::StructuralPassBehaviorPending => Ok(0),
        Verdict::Rejected => Ok(2),
        Verdict::Accepted => {
            // Contract violation if ever reached on static path.
            eprintln!("error: internal contract violation: Accepted verdict in check-static");
            Ok(1)
        }
    }
}

fn cmd_check_with_behavior(args: &[String]) -> Result<i32, String> {
    if args.is_empty() {
        return Err(
            "Usage: mida-acceptance check-with-behavior <candidate> --behavior-evidence <path>"
                .into(),
        );
    }
    let mut candidate: Option<PathBuf> = None;
    let mut expected_sha256: Option<String> = None;
    let mut expected_size: Option<u64> = None;
    let mut role: Option<String> = None;
    let mut oracle: Option<PathBuf> = None;
    let mut report_path: Option<PathBuf> = None;
    let mut evidence_path: Option<PathBuf> = None;

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
            "--expected-size" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --expected-size".into());
                }
                expected_size = Some(parse_expected_size(&args[i])?);
            }
            flag if flag.starts_with("--expected-size=") => {
                expected_size = Some(parse_expected_size(&flag["--expected-size=".len()..])?);
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
            "--behavior-evidence" => {
                i += 1;
                if i >= args.len() {
                    return Err("missing value after --behavior-evidence".into());
                }
                evidence_path = Some(PathBuf::from(&args[i]));
            }
            flag if flag.starts_with("--behavior-evidence=") => {
                evidence_path = Some(PathBuf::from(&flag["--behavior-evidence=".len()..]));
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
    let evidence_path =
        evidence_path.ok_or_else(|| "missing --behavior-evidence <path>".to_string())?;

    let (bytes, candidate_file) = read_input(&candidate, "candidate")?;
    let (ev_bytes, evidence_file) = read_input(&evidence_path, "behavior-evidence")?;
    let evidence = BehaviorEvidence::parse_json(&ev_bytes)
        .map_err(|e| format!("invalid behavior evidence: {e}"))?;

    let (oracle_bytes, oracle_file) = match oracle.as_deref() {
        None => (None, None),
        Some(path) => {
            let (b, file) = read_input(path, "oracle")?;
            (Some(b), Some(file))
        }
    };

    let opts = CheckStaticOptions {
        role,
        expected_sha256,
        expected_size,
        oracle_bytes,
    };

    let report = check_with_behavior(&bytes, &opts, &evidence);
    let json = report
        .to_json()
        .map_err(|e| format!("failed to serialize report: {e}"))?;

    println!("{json}");
    if let Some(path) = report_path {
        let mut file_body = json.clone();
        file_body.push('\n');
        // Also refuse aliasing the evidence path.
        write_report_with_extra(
            &path,
            file_body.as_bytes(),
            (&candidate, &candidate_file),
            oracle.as_deref().zip(oracle_file.as_ref()),
            Some((evidence_path.as_path(), &evidence_file)),
        )?;
    }

    Ok(report.verdict.exit_code())
}

fn parse_expected_size(raw: &str) -> Result<u64, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err("empty --expected-size value".into());
    }
    t.parse::<u64>()
        .map_err(|_| format!("invalid --expected-size value '{raw}' (expected unsigned integer)"))
}

fn read_input(path: &Path, label: &str) -> Result<(Vec<u8>, File), String> {
    let mut file = File::open(path)
        .map_err(|e| format!("failed to open {label} '{}': {e}", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| format!("failed to read {label} '{}': {e}", path.display()))?;
    Ok((bytes, file))
}

fn write_report(
    report_path: &Path,
    body: &[u8],
    candidate: (&Path, &File),
    oracle: Option<(&Path, &File)>,
) -> Result<(), String> {
    write_report_with_extra(report_path, body, candidate, oracle, None)
}

/// Write report after rejecting alias against candidate, optional oracle, and
/// optional behavior-evidence inputs (B-A2).
fn write_report_with_extra(
    report_path: &Path,
    body: &[u8],
    candidate: (&Path, &File),
    oracle: Option<(&Path, &File)>,
    evidence: Option<(&Path, &File)>,
) -> Result<(), String> {
    // Open without truncate so alias checks cannot damage an input file.
    let mut report_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(report_path)
        .map_err(|e| format!("failed to open report '{}': {e}", report_path.display()))?;
    let report_metadata = report_file
        .metadata()
        .map_err(|e| format!("failed to inspect report '{}': {e}", report_path.display()))?;

    reject_input_alias(
        report_path,
        &report_file,
        &report_metadata,
        "candidate",
        candidate.0,
        candidate.1,
    )?;
    if let Some((oracle_path, oracle_file)) = oracle {
        reject_input_alias(
            report_path,
            &report_file,
            &report_metadata,
            "oracle",
            oracle_path,
            oracle_file,
        )?;
    }
    if let Some((evidence_path, evidence_file)) = evidence {
        reject_input_alias(
            report_path,
            &report_file,
            &report_metadata,
            "behavior-evidence",
            evidence_path,
            evidence_file,
        )?;
    }

    report_file
        .set_len(0)
        .and_then(|_| report_file.write_all(body))
        .map_err(|e| format!("failed to write report '{}': {e}", report_path.display()))
}

fn reject_input_alias(
    report_path: &Path,
    report_file: &File,
    report_metadata: &Metadata,
    input_label: &str,
    input_path: &Path,
    input_file: &File,
) -> Result<(), String> {
    let input_metadata = input_file.metadata().map_err(|e| {
        format!(
            "failed to inspect {input_label} '{}': {e}",
            input_path.display()
        )
    })?;

    let aliases =
        same_file(input_file, &input_metadata, report_file, report_metadata).map_err(|e| {
            format!(
                "failed to compare report '{}' with {input_label} '{}': {e}",
                report_path.display(),
                input_path.display()
            )
        })?;
    if aliases {
        return Err(format!(
            "report path '{}' aliases {input_label} '{}'; input files are protected from report writes",
            report_path.display(),
            input_path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn same_file(
    _left_file: &File,
    left: &Metadata,
    _right_file: &File,
    right: &Metadata,
) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

#[cfg(windows)]
fn same_file(
    left_file: &File,
    _left: &Metadata,
    right_file: &File,
    _right: &Metadata,
) -> std::io::Result<bool> {
    Ok(windows_file_id(left_file)? == windows_file_id(right_file)?)
}

#[cfg(windows)]
fn windows_file_id(file: &File) -> std::io::Result<(u32, u64)> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Default)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    #[derive(Default)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: *mut c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = ByHandleFileInformation::default();
    // SAFETY: the raw handle remains owned by `file`, and `information` is a valid output buffer.
    let success = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    if success == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file_index =
        (u64::from(information.file_index_high) << 32) | u64::from(information.file_index_low);
    Ok((information.volume_serial_number, file_index))
}

#[cfg(not(any(unix, windows)))]
fn same_file(
    _left_file: &File,
    _left: &Metadata,
    _right_file: &File,
    _right: &Metadata,
) -> std::io::Result<bool> {
    Ok(false)
}
