//! CLI argument parsing — `/unpack` and `/dump-process` commands.
//!
//! Mirrors the command-line invocation logic from `Magicmida.dpr`
//! (`CheckCommandlineInvocation`) and the GUI flow from `Unit2.pas`.

use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Command enum
// ---------------------------------------------------------------------------

/// CLI command parsed from the program arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Unpack a Themida-protected executable.
    ///
    /// Usage: `magicmida /unpack <filename> [options]`
    Unpack {
        /// Path to the input executable.
        input: PathBuf,
        /// Optional output path. Defaults to `<input>U.exe` (matching the
        /// Pascal reference's "U" suffix convention).
        output: Option<PathBuf>,
        /// Restore `.rdata` / `.data` sections from the target process
        /// (`--data-sections`).
        create_data_sections: bool,
        /// Remove Themida-specific sections from the output (`--shrink`).
        shrink: bool,
        /// Enable verbose (debug-level) logging (`-v`).
        verbose: bool,
    },

    /// Dump the de-virtualised `.text` section from a running process.
    ///
    /// Usage: `magicmida /dump-process <pid> <unpacked-file>`
    DumpProcess {
        /// PID of the running (unpacked) target process.
        pid: u32,
        /// Path where the dumped `.text` section will be written.
        unpacked_file: PathBuf,
    },

    /// Verify an unpacked file against a reference.
    ///
    /// Compares the PE structure (sections, imports, entry point) of an
    /// unpacked file against a known-good reference to validate correctness.
    ///
    /// Usage: `magicmida /verify <unpacked-file> <reference-file>`
    Verify {
        /// Path to the file we unpacked (the one to verify).
        unpacked: PathBuf,
        /// Path to the known-good reference file.
        reference: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// Parse
// ---------------------------------------------------------------------------

/// Parse CLI arguments into a [`Command`].
///
/// # Errors
///
/// Returns a human-readable error string when arguments are missing or
/// malformed.
pub fn parse_args() -> Result<Command, String> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        return Err("No command specified. Use /unpack or /dump-process.".into());
    }

    match args[1].as_str() {
        "/unpack" | "--unpack" | "unpack" => parse_unpack(&args),
        "/dump-process" | "--dump-process" | "dump-process" => parse_dump_process(&args),
        "/verify" | "--verify" | "verify" => parse_verify(&args),
        other => Err(format!(
            "Unknown command '{}'. Use /unpack, /dump-process, or /verify.",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// Sub-parsers
// ---------------------------------------------------------------------------

fn parse_unpack(args: &[String]) -> Result<Command, String> {
    if args.len() < 3 {
        return Err("Usage: magicmida /unpack <filename> [--data-sections] [--shrink] [-v]".into());
    }

    let input = PathBuf::from(&args[2]);

    // If the file doesn't exist on disk, bail early — there's no point
    // continuing.
    if !input.exists() {
        return Err(format!("File not found: {}", input.display()));
    }
    if !input.is_file() {
        return Err(format!("Not a file: {}", input.display()));
    }

    let mut output: Option<PathBuf> = None;
    let mut create_data_sections = false;
    let mut shrink = true; // Default: shrink Themida sections (surpasses Pascal)
    let mut verbose = false;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing output path after -o/--output.".into());
                }
                output = Some(PathBuf::from(&args[i]));
            }
            "--data-sections" | "--create-data-sections" => {
                create_data_sections = true;
            }
            "--shrink" => {
                shrink = true;
            }
            "--no-shrink" => {
                shrink = false;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            other if other.starts_with('-') => {
                return Err(format!("Unknown option: {}", other));
            }
            // Positional argument treated as output path.
            other => {
                if output.is_none() {
                    output = Some(PathBuf::from(other));
                } else {
                    return Err(format!("Unexpected argument: {}", other));
                }
            }
        }
        i += 1;
    }

    Ok(Command::Unpack {
        input,
        output,
        create_data_sections,
        shrink,
        verbose,
    })
}

fn parse_dump_process(args: &[String]) -> Result<Command, String> {
    if args.len() < 4 {
        return Err(
            "Usage: magicmida /dump-process <pid> <unpacked-file>".into(),
        );
    }

    let pid: u32 = args[2]
        .parse()
        .map_err(|e| format!("Invalid PID '{}': {}", args[2], e))?;

    let unpacked_file = PathBuf::from(&args[3]);

    Ok(Command::DumpProcess {
        pid,
        unpacked_file,
    })
}

fn parse_verify(args: &[String]) -> Result<Command, String> {
    if args.len() < 4 {
        return Err(
            "Usage: magicmida /verify <unpacked-file> <reference-file>".into(),
        );
    }

    let unpacked = PathBuf::from(&args[2]);
    let reference = PathBuf::from(&args[3]);

    if !unpacked.exists() {
        return Err(format!("Unpacked file not found: {}", unpacked.display()));
    }
    if !reference.exists() {
        return Err(format!("Reference file not found: {}", reference.display()));
    }

    Ok(Command::Verify {
        unpacked,
        reference,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // These tests directly call the sub-parsers rather than `parse_args` so
    // they are independent of the actual process command line.

    #[test]
    fn unpack_minimal() {
        // We can't easily test file existence from a unit test, so test the
        // argument-count branch first.
        let args = vec![
            "prog".into(),
            "/unpack".into(),
        ];
        let err = parse_unpack(&args).unwrap_err();
        assert!(err.contains("Usage"), "expected usage hint, got: {err}");
    }

    #[test]
    fn unpack_with_options() {
        // Test flag parsing (no file-existence check since the file doesn't
        // exist).
        let args = vec![
            "prog".into(),
            "/unpack".into(),
            "Cargo.toml".into(), // exists relative to cwd
            "--data-sections".into(),
            "--shrink".into(),
            "-v".into(),
        ];
        let cmd = parse_unpack(&args).unwrap();
        match cmd {
            Command::Unpack {
                input,
                output,
                create_data_sections,
                shrink,
                verbose,
            } => {
                assert!(input.ends_with("Cargo.toml"));
                assert!(output.is_none());
                assert!(create_data_sections);
                assert!(shrink);
                assert!(verbose);
            }
            _ => panic!("expected Unpack, got {cmd:?}"),
        }
    }

    #[test]
    fn unpack_output_flag() {
        let args = vec![
            "prog".into(),
            "/unpack".into(),
            "Cargo.toml".into(),
            "-o".into(),
            "out.exe".into(),
        ];
        let cmd = parse_unpack(&args).unwrap();
        match cmd {
            Command::Unpack { output, .. } => {
                assert_eq!(output, Some(PathBuf::from("out.exe")));
            }
            _ => panic!("expected Unpack"),
        }
    }

    #[test]
    fn unpack_unknown_flag() {
        let args = vec![
            "prog".into(),
            "/unpack".into(),
            "Cargo.toml".into(),
            "--bogus".into(),
        ];
        let err = parse_unpack(&args).unwrap_err();
        assert!(err.contains("Unknown option"), "got: {err}");
    }

    #[test]
    fn dump_process_minimal() {
        let args = vec![
            "prog".into(),
            "/dump-process".into(),
            "1234".into(),
            "dump.bin".into(),
        ];
        let cmd = parse_dump_process(&args).unwrap();
        match cmd {
            Command::DumpProcess { pid, unpacked_file } => {
                assert_eq!(pid, 1234);
                assert_eq!(unpacked_file, PathBuf::from("dump.bin"));
            }
            _ => panic!("expected DumpProcess"),
        }
    }

    #[test]
    fn dump_process_missing_args() {
        let args = vec!["prog".into(), "/dump-process".into()];
        let err = parse_dump_process(&args).unwrap_err();
        assert!(err.contains("Usage"), "got: {err}");
    }

    #[test]
    fn dump_invalid_pid() {
        let args = vec![
            "prog".into(),
            "/dump-process".into(),
            "abc".into(),
            "dump.bin".into(),
        ];
        let err = parse_dump_process(&args).unwrap_err();
        assert!(err.contains("Invalid PID"), "got: {err}");
    }

    #[test]
    fn verify_minimal() {
        let args = vec![
            "prog".into(),
            "/verify".into(),
        ];
        let err = parse_verify(&args).unwrap_err();
        assert!(err.contains("Usage"), "expected usage hint, got: {err}");
    }

    // -- DLL auto-detection tests ------------------------------------------

    #[test]
    fn is_dll_by_extension() {
        // Helper that mimics the logic in unpack().
        let is_dll =
            |path: &std::path::Path| path.extension().map(|e| e.eq_ignore_ascii_case("dll")).unwrap_or(false);
        assert!(is_dll(std::path::Path::new("test.dll")));
        assert!(is_dll(std::path::Path::new("test.DLL")));
        assert!(is_dll(std::path::Path::new("test.Dll")));
        assert!(!is_dll(std::path::Path::new("test.exe")));
        assert!(!is_dll(std::path::Path::new("test")));
        assert!(!is_dll(std::path::Path::new("")));
    }
}
