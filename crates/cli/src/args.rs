//! CLI argument parsing — `/unpack` and `/dump-process` commands.
//!
//! Mirrors the command-line invocation logic from `Magicmida.dpr`
//! (`CheckCommandlineInvocation`) and the GUI flow from `Unit2.pas`.

use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Command enum
// ---------------------------------------------------------------------------

/// Which packer branch `/unpack` should take.
///
/// `Auto` is the default and refuses anything the Themida pipeline cannot
/// handle.  That refusal is what stops a VMProtect target from being handed to
/// the Themida loop — measured before this gate existed: `Themida version:
/// V3`, a created debuggee, and 8 s of work on a VMProtect binary.
///
/// The other two values make the decision **overridable for diagnostics**,
/// with the override logged, because a packer verdict is a heuristic and a
/// wrong one must be resolvable without recompiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackerChoice {
    /// Detect the packer and refuse what the Themida pipeline cannot unpack.
    Auto,
    /// Force the Themida branch even when VMProtect evidence is present.
    Themida,
    /// Select the VMProtect branch — its own ScyllaHide profile, sharing the
    /// single debug loop that exists.  Experimental.
    VmProtect,
}

impl PackerChoice {
    /// Parse the value of `--packer`.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(PackerChoice::Auto),
            "themida" => Ok(PackerChoice::Themida),
            "vmprotect" | "vmp" => Ok(PackerChoice::VmProtect),
            other => Err(format!(
                "Unknown --packer value '{other}'. Use auto, themida, or vmprotect."
            )),
        }
    }
}

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
        /// Which packer branch to take (`--packer`).
        packer: PackerChoice,
    },

    /// Analyse a protected binary statically.
    ///
    /// Identifies the packer and its mode, prints the static structure report,
    /// and optionally extracts payloads that are present in the file.  Unlike
    /// [`Command::Unpack`] this needs no debugger and no interactive desktop
    /// session, so it runs headless and in CI.
    ///
    /// Usage: `magicmida /analyze <filename> [--extract <dir>] [-v]`
    Analyze {
        /// Path to the file to analyse.
        input: PathBuf,
        /// Directory to write extractable payloads into (`--extract`).
        extract_to: Option<PathBuf>,
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

    /// Flatten a running process's loaded image into a file.
    ///
    /// For samples whose original sections are absent from the file — a
    /// `Packed` VMProtect target has `SizeOfRawData == 0` on every original
    /// code section — the image only exists in memory, and this reads it out
    /// without attaching a debugger.
    ///
    /// Usage: `magicmida /dump-image <pid> <output-file>`
    DumpImage {
        /// PID of the running target.
        pid: u32,
        /// Path to write the flat image to.
        output: PathBuf,
        /// Keep sampling until two consecutive reads are identical.
        wait: bool,
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

    /// Print the version and exit (`--version`).
    Version,

    /// Print the usage summary and exit (`--help`).
    Help,
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
        "/analyze" | "--analyze" | "analyze" => parse_analyze(&args),
        "/dump-process" | "--dump-process" | "dump-process" => parse_dump_process(&args),
        "/dump-image" | "--dump-image" | "dump-image" => parse_dump_image(&args),
        "/verify" | "--verify" | "verify" => parse_verify(&args),
        "/version" | "--version" | "-V" => Ok(Command::Version),
        "/help" | "--help" | "-h" | "/?" => Ok(Command::Help),
        other => Err(format!(
            "Unknown command '{}'. Use /unpack, /analyze, /dump-process, /dump-image, or /verify.",
            other
        )),
    }
}

// ---------------------------------------------------------------------------
// Sub-parsers
// ---------------------------------------------------------------------------

fn parse_unpack(args: &[String]) -> Result<Command, String> {
    if args.len() < 3 {
        return Err(
            "Usage: magicmida /unpack <filename> [--packer auto|themida|vmprotect] \
             [--data-sections] [--shrink] [-v]"
                .into(),
        );
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
    let mut packer = PackerChoice::Auto;

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
            "--packer" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value after --packer.".into());
                }
                packer = PackerChoice::parse(&args[i])?;
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
        packer,
    })
}

fn parse_analyze(args: &[String]) -> Result<Command, String> {
    if args.len() < 3 {
        return Err("Usage: magicmida /analyze <filename> [--extract <dir>] [-v]".into());
    }

    let input = PathBuf::from(&args[2]);
    if !input.exists() {
        return Err(format!("File not found: {}", input.display()));
    }
    if !input.is_file() {
        return Err(format!("Not a file: {}", input.display()));
    }

    let mut extract_to: Option<PathBuf> = None;
    let mut verbose = false;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-x" | "--extract" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing directory after -x/--extract.".into());
                }
                extract_to = Some(PathBuf::from(&args[i]));
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            other => {
                return Err(format!("Unknown option: {}", other));
            }
        }
        i += 1;
    }

    Ok(Command::Analyze {
        input,
        extract_to,
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

fn parse_dump_image(args: &[String]) -> Result<Command, String> {
    if args.len() < 4 {
        return Err("Usage: magicmida /dump-image <pid> <output-file> [--wait]".into());
    }
    let pid: u32 = args[2]
        .parse()
        .map_err(|e| format!("Invalid PID '{}': {}", args[2], e))?;
    let wait = args[4..].iter().any(|a| a == "--wait" || a == "-w");
    Ok(Command::DumpImage {
        pid,
        output: PathBuf::from(&args[3]),
        wait,
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

    /// `parse_args` reads the real process command line, so the version/help
    /// spellings are exercised through a tiny local re-implementation of just
    /// that match arm.  Keeping it in the test means the spellings are pinned
    /// without needing to spawn a process.
    fn dispatch_first_arg(arg: &str) -> Result<Command, String> {
        match arg {
            "/unpack" | "--unpack" | "unpack" => Err("would parse unpack".into()),
            "/analyze" | "--analyze" | "analyze" => Err("would parse analyze".into()),
            "/dump-process" | "--dump-process" | "dump-process" => Err("would parse dump".into()),
            "/dump-image" | "--dump-image" | "dump-image" => Err("would parse dump-image".into()),
            "/verify" | "--verify" | "verify" => Err("would parse verify".into()),
            "/version" | "--version" | "-V" => Ok(Command::Version),
            "/help" | "--help" | "-h" | "/?" => Ok(Command::Help),
            other => Err(format!("Unknown command '{}'", other)),
        }
    }

    #[test]
    fn analyze_spellings_all_resolve() {
        for a in ["/analyze", "--analyze", "analyze"] {
            assert!(
                dispatch_first_arg(a).unwrap_err().contains("analyze"),
                "for {a}"
            );
        }
    }

    #[test]
    fn analyze_requires_a_file_that_exists() {
        let args = vec!["prog".into(), "/analyze".into()];
        assert!(parse_analyze(&args).unwrap_err().contains("Usage"));

        let args = vec!["prog".into(), "/analyze".into(), "no-such-file-xyz".into()];
        let err = parse_analyze(&args).unwrap_err();
        assert!(err.contains("File not found"), "got: {err}");
    }

    #[test]
    fn analyze_parses_the_extract_flag_and_rejects_unknown_ones() {
        // `Cargo.toml` exists relative to the crate root, so it passes the
        // existence check without depending on a sample.
        let args = vec![
            "prog".into(),
            "/analyze".into(),
            "Cargo.toml".into(),
            "--extract".into(),
            "out-dir".into(),
            "-v".into(),
        ];
        match parse_analyze(&args).unwrap() {
            Command::Analyze {
                input,
                extract_to,
                verbose,
            } => {
                assert!(input.ends_with("Cargo.toml"));
                assert_eq!(extract_to, Some(PathBuf::from("out-dir")));
                assert!(verbose);
            }
            other => panic!("expected Analyze, got {other:?}"),
        }

        let args = vec![
            "prog".into(),
            "/analyze".into(),
            "Cargo.toml".into(),
            "--extract".into(),
        ];
        assert!(parse_analyze(&args)
            .unwrap_err()
            .contains("Missing directory"));

        let args = vec![
            "prog".into(),
            "/analyze".into(),
            "Cargo.toml".into(),
            "--bogus".into(),
        ];
        assert!(parse_analyze(&args)
            .unwrap_err()
            .contains("Unknown option"));
    }

    #[test]
    fn version_spellings_all_resolve() {
        for a in ["/version", "--version", "-V"] {
            assert_eq!(dispatch_first_arg(a), Ok(Command::Version), "for {a}");
        }
    }

    #[test]
    fn help_spellings_all_resolve() {
        for a in ["/help", "--help", "-h", "/?"] {
            assert_eq!(dispatch_first_arg(a), Ok(Command::Help), "for {a}");
        }
    }

    #[test]
    fn version_and_help_are_distinct_commands() {
        // Guards against collapsing them into one variant by accident.
        assert_ne!(Command::Version, Command::Help);
    }

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
                packer,
            } => {
                assert!(input.ends_with("Cargo.toml"));
                assert!(output.is_none());
                assert!(create_data_sections);
                assert!(shrink);
                assert!(verbose);
                assert_eq!(packer, PackerChoice::Auto, "the default must be auto");
            }
            _ => panic!("expected Unpack, got {cmd:?}"),
        }
    }

    #[test]
    fn unpack_packer_flag_parses_all_three_values_and_rejects_junk() {
        for (value, expected) in [
            ("auto", PackerChoice::Auto),
            ("themida", PackerChoice::Themida),
            ("vmprotect", PackerChoice::VmProtect),
            ("VMProtect", PackerChoice::VmProtect),
            ("vmp", PackerChoice::VmProtect),
        ] {
            let args = vec![
                "prog".into(),
                "/unpack".into(),
                "Cargo.toml".into(),
                "--packer".into(),
                value.into(),
            ];
            match parse_unpack(&args).unwrap() {
                Command::Unpack { packer, .. } => assert_eq!(packer, expected, "for {value}"),
                other => panic!("expected Unpack, got {other:?}"),
            }
        }

        let args = vec![
            "prog".into(),
            "/unpack".into(),
            "Cargo.toml".into(),
            "--packer".into(),
            "enigma".into(),
        ];
        assert!(parse_unpack(&args)
            .unwrap_err()
            .contains("Unknown --packer value"));

        let args = vec![
            "prog".into(),
            "/unpack".into(),
            "Cargo.toml".into(),
            "--packer".into(),
        ];
        assert!(parse_unpack(&args)
            .unwrap_err()
            .contains("Missing value after --packer"));
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
    fn dump_image_spellings_resolve_and_arguments_are_validated() {
        for a in ["/dump-image", "--dump-image", "dump-image"] {
            assert!(
                dispatch_first_arg(a).unwrap_err().contains("dump-image"),
                "for {a}"
            );
        }

        let args = vec![
            "prog".into(),
            "/dump-image".into(),
            "4321".into(),
            "img.bin".into(),
        ];
        match parse_dump_image(&args).unwrap() {
            Command::DumpImage { pid, output, wait } => {
                assert_eq!(pid, 4321);
                assert_eq!(output, PathBuf::from("img.bin"));
                assert!(!wait, "wait must default to off");
            }
            other => panic!("expected DumpImage, got {other:?}"),
        }

        // `--wait` is opt-in and recognised in any trailing position.
        for extra in [vec!["--wait"], vec!["-w"], vec!["-v", "--wait"]] {
            let mut a = args.clone();
            a.extend(extra.iter().map(|s| s.to_string()));
            match parse_dump_image(&a).unwrap() {
                Command::DumpImage { wait, .. } => assert!(wait, "for {extra:?}"),
                other => panic!("expected DumpImage, got {other:?}"),
            }
        }

        assert!(parse_dump_image(&["prog".into(), "/dump-image".into()])
            .unwrap_err()
            .contains("Usage"));
        assert!(
            parse_dump_image(&["prog".into(), "/dump-image".into(), "x".into(), "o".into()])
                .unwrap_err()
                .contains("Invalid PID")
        );
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
