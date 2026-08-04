//! CLI argument parsing — `/unpack`, `/generic-unpack`, `/dump-process`, `/verify`.

use std::path::PathBuf;

use mida_pe::{ContainerRestoreMode, DumpCapturePolicy, DumpProfile, OepPolicy};

use crate::unpacker::GenericGateProfile;

const DEFAULT_OEP_POLICY: OepPolicy = OepPolicy::Captured;
const DEFAULT_DUMP_PROFILE: DumpProfile = DumpProfile::OreansClassic;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Unpack {
        input: PathBuf,
        output: Option<PathBuf>,
        create_data_sections: bool,
        shrink: bool,
        oep_policy: OepPolicy,
        /// Resolved container restore mode (profile default or explicit CLI).
        container_restore: ContainerRestoreMode,
        /// Dump behaviour profile (default OreansClassic).
        profile: DumpProfile,
        /// R1-D/E: emit via pure rebuild boundary (opt-in; preserves host VAs/DDs).
        pure_rebuild: bool,
        /// Optional capture policy from `--capture-policy=PATH` (case-manifest shape).
        /// Empty = plugin/profile defaults only.
        capture_policy: DumpCapturePolicy,
        /// P6.3: SHA-256 of the capture-policy file bytes (empty when none).
        /// Part of the actual run-config identity bound into the envelope.
        capture_policy_digest: String,
        /// P6.2: when set, the launch boundary consumes a Ready offline
        /// preflight report from this directory before any sample process
        /// is created.
        preflight_dir: Option<PathBuf>,
        /// P6.3.1: explicit acceptance-verifier binary for the launch
        /// attestation / PE evidence (test injection seam). `None` resolves
        /// the sibling `mida-acceptance`; the environment is never trusted.
        acceptance_bin: Option<PathBuf>,
        verbose: bool,
    },
    /// Packer-agnostic full dump (no Themida shrink).
    GenericUnpack {
        input: PathBuf,
        output: Option<PathBuf>,
        wait_sec: u64,
        stable: u32,
        /// Which hard-gate profile to enforce on the dumped PE.
        gate_profile: GenericGateProfile,
        verbose: bool,
    },
    DumpProcess {
        pid: u32,
        unpacked_file: PathBuf,
    },
    Verify {
        unpacked: PathBuf,
        reference: PathBuf,
    },
    /// P6.2: offline preflight gate — emit the runner-config envelope, drive
    /// the independent verifier, and consume the ready/not_ready report.
    OfflinePreflight {
        output_dir: PathBuf,
        /// (manifest, protected input, candidate output) per case.
        cases: Vec<(PathBuf, PathBuf, PathBuf)>,
        cli_binary: PathBuf,
        repo_root: PathBuf,
        toolchain_pin_file: PathBuf,
        expected_toolchain: String,
        acceptance_bin: Option<PathBuf>,
    },
    Help,
    Version,
}

pub fn parse_args() -> Result<Command, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return Ok(Command::Help);
    }
    match args[1].as_str() {
        "-h" | "--help" | "/?" | "help" => Ok(Command::Help),
        "-V" | "--version" | "version" => Ok(Command::Version),
        "/unpack" | "--unpack" | "unpack" => parse_unpack(&args),
        "/generic-unpack" | "--generic-unpack" | "generic-unpack" | "/generic" | "generic" => {
            parse_generic(&args)
        }
        "/dump-process" | "--dump-process" | "dump-process" => parse_dump_process(&args),
        "/verify" | "--verify" | "verify" => parse_verify(&args),
        "/offline-preflight" | "--offline-preflight" | "offline-preflight" => {
            parse_offline_preflight(&args)
        }
        other => Err(format!(
            "Unknown command '{}'. Use --help for usage information.",
            other
        )),
    }
}

fn parse_unpack(args: &[String]) -> Result<Command, String> {
    if args.len() < 3 {
        return Err(
            "Usage: mida-cli /unpack <filename> [--data-sections] [--shrink|--no-shrink] \
             [--oep=crt|captured|rva=N] [--profile=oreans-classic|ahk-gto-experimental] \
             [--container-restore=off|post-crt|tls-pre] [--pure-rebuild|--no-pure-rebuild] \
             [--capture-policy=PATH] [-v]"
                .into(),
        );
    }
    let input = PathBuf::from(&args[2]);
    if !input.exists() {
        return Err(format!("File not found: {}", input.display()));
    }
    if !input.is_file() {
        return Err(format!("Not a file: {}", input.display()));
    }

    let mut output: Option<PathBuf> = None;
    let mut create_data_sections = false;
    let mut shrink = true;
    // Preserve the runtime-observed application entry point by default.
    // The CRT scanner is heuristic and can select an earlier helper function
    // (for example RVA 0x101C instead of the runnable RVA 0x13E0).
    let mut oep_policy = DEFAULT_OEP_POLICY;
    let mut profile = DEFAULT_DUMP_PROFILE;
    // None = user did not pass --container-restore; use profile default.
    let mut container_restore_explicit: Option<ContainerRestoreMode> = None;
    let mut verbose = false;
    let mut cli_pure_rebuild = false;
    let mut cli_no_pure_rebuild = false;
    let mut capture_policy = DumpCapturePolicy::default();
    let mut capture_policy_path: Option<PathBuf> = None;
    let mut preflight_dir: Option<PathBuf> = None;
    let mut acceptance_bin: Option<PathBuf> = None;

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
            "--preflight-dir" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing directory after --preflight-dir.".into());
                }
                preflight_dir = Some(PathBuf::from(&args[i]));
            }
            "--acceptance-bin" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing path after --acceptance-bin.".into());
                }
                acceptance_bin = Some(PathBuf::from(&args[i]));
            }
            "--data-sections" | "--create-data-sections" => create_data_sections = true,
            "--shrink" => shrink = true,
            "--no-shrink" => shrink = false,
            "-v" | "--verbose" => verbose = true,
            "--pure-rebuild" => cli_pure_rebuild = true,
            "--no-pure-rebuild" => cli_no_pure_rebuild = true,
            other if other.starts_with("--oep=") => {
                oep_policy = parse_oep_policy(&other["--oep=".len()..])?;
            }
            "--oep" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value after --oep (crt|captured|rva=N).".into());
                }
                oep_policy = parse_oep_policy(&args[i])?;
            }
            other if other.starts_with("--profile=") => {
                profile = parse_profile(&other["--profile=".len()..])?;
            }
            "--profile" => {
                i += 1;
                if i >= args.len() {
                    return Err(
                        "Missing value after --profile (oreans-classic|ahk-gto-experimental)."
                            .into(),
                    );
                }
                profile = parse_profile(&args[i])?;
            }
            other if other.starts_with("--container-restore=") => {
                container_restore_explicit = Some(parse_container_restore(
                    &other["--container-restore=".len()..],
                )?);
            }
            "--container-restore" => {
                i += 1;
                if i >= args.len() {
                    return Err(
                        "Missing value after --container-restore (off|post-crt|tls-pre).".into(),
                    );
                }
                container_restore_explicit = Some(parse_container_restore(&args[i])?);
            }
            other if other.starts_with("--capture-policy=") => {
                capture_policy_path = Some(PathBuf::from(&other["--capture-policy=".len()..]));
            }
            "--capture-policy" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing path after --capture-policy.".into());
                }
                capture_policy_path = Some(PathBuf::from(&args[i]));
            }
            other if other.starts_with('-') => return Err(format!("Unknown option: {}", other)),
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

    if let Some(ref path) = capture_policy_path {
        if !path.is_file() {
            return Err(format!("capture policy file not found: {}", path.display()));
        }
        capture_policy = crate::capture_policy_file::load_capture_policy_file(path)?;
    }
    let capture_policy_digest = match capture_policy_path.as_ref() {
        Some(path) => crate::runner_preflight::sha256_file(path)
            .map_err(|e| format!("cannot digest capture policy {}: {e}", path.display()))?,
        None => String::new(),
    };

    let container_restore = resolve_container_restore(profile, container_restore_explicit);

    // D3: Origin Macro protected input defaults pure; others legacy.
    let (pure_rebuild, pure_reason) =
        crate::origin_pure::resolve_pure_rebuild(&input, cli_pure_rebuild, cli_no_pure_rebuild);
    if pure_rebuild || cli_no_pure_rebuild || cli_pure_rebuild {
        // Always log when operator touched pure flags or Origin default engaged.
        let _ = pure_reason;
    }
    // Surface reason via stderr only when Origin default or explicit flags change
    // behavior relative to historical global legacy default.
    if pure_rebuild && !cli_pure_rebuild {
        eprintln!(
            "mida-cli: pure-rebuild enabled by default for Origin Macro protected input ({pure_reason}); pass --no-pure-rebuild to force legacy"
        );
    }

    Ok(Command::Unpack {
        input,
        output,
        create_data_sections,
        shrink,
        oep_policy,
        container_restore,
        profile,
        pure_rebuild,
        capture_policy,
        capture_policy_digest,
        preflight_dir,
        acceptance_bin,
        verbose,
    })
}

fn parse_generic(args: &[String]) -> Result<Command, String> {
    if args.len() < 3 {
        return Err(
            "Usage: mida-cli /generic-unpack <filename> [-o out.exe] [--wait-sec N] [--stable N] [-v]"
                .into(),
        );
    }
    let input = PathBuf::from(&args[2]);
    if !input.exists() {
        return Err(format!("File not found: {}", input.display()));
    }
    let mut output = None;
    let mut wait_sec = 60u64;
    let mut stable = 2u32;
    let mut gate_profile = GenericGateProfile::PackerAgnostic;
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
            other if other.starts_with("--wait-sec=") => {
                wait_sec = other["--wait-sec=".len()..]
                    .parse()
                    .map_err(|_| "invalid --wait-sec".to_string())?;
            }
            "--wait-sec" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value after --wait-sec".into());
                }
                wait_sec = args[i]
                    .parse()
                    .map_err(|_| "invalid --wait-sec".to_string())?;
            }
            other if other.starts_with("--stable=") => {
                stable = other["--stable=".len()..]
                    .parse()
                    .map_err(|_| "invalid --stable".to_string())?;
            }
            "--stable" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value after --stable".into());
                }
                stable = args[i]
                    .parse()
                    .map_err(|_| "invalid --stable".to_string())?;
            }
            "-v" | "--verbose" => verbose = true,
            other if other.starts_with("--gate-profile=") => {
                gate_profile = parse_gate_profile(&other["--gate-profile=".len()..])?;
            }
            "--gate-profile" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value after --gate-profile (agnostic|ahk-launcher)".into());
                }
                gate_profile = parse_gate_profile(&args[i])?;
            }
            other if other.starts_with('-') => return Err(format!("Unknown option: {}", other)),
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
    Ok(Command::GenericUnpack {
        input,
        output,
        wait_sec,
        stable,
        gate_profile,
        verbose,
    })
}

fn parse_dump_process(args: &[String]) -> Result<Command, String> {
    if args.len() < 4 {
        return Err("Usage: mida-cli /dump-process <pid> <unpacked-file>".into());
    }
    let pid: u32 = args[2]
        .parse()
        .map_err(|_| format!("Invalid PID: {}", args[2]))?;
    Ok(Command::DumpProcess {
        pid,
        unpacked_file: PathBuf::from(&args[3]),
    })
}

fn parse_verify(args: &[String]) -> Result<Command, String> {
    if args.len() < 4 {
        return Err("Usage: mida-cli /verify <unpacked-file> <reference-file>".into());
    }
    Ok(Command::Verify {
        unpacked: PathBuf::from(&args[2]),
        reference: PathBuf::from(&args[3]),
    })
}

fn parse_offline_preflight(args: &[String]) -> Result<Command, String> {
    if args.len() < 3 {
        return Err(
            "Usage: mida-cli /offline-preflight <output-dir> --cli-binary=<path> \
             --repo-root=<path> --toolchain-pin=<path> --expected-toolchain=<ver> \
             --case <manifest> <input> <output> [--case ...] [--acceptance-bin=<path>]"
                .into(),
        );
    }
    let output_dir = PathBuf::from(&args[2]);
    let mut cli_binary: Option<PathBuf> = None;
    let mut repo_root: Option<PathBuf> = None;
    let mut toolchain_pin_file: Option<PathBuf> = None;
    let mut expected_toolchain: Option<String> = None;
    let mut acceptance_bin: Option<PathBuf> = None;
    let mut cases: Vec<(PathBuf, PathBuf, PathBuf)> = Vec::new();
    let mut i = 3;
    while i < args.len() {
        let arg = &args[i];
        if let Some(v) = arg.strip_prefix("--cli-binary=") {
            cli_binary = Some(PathBuf::from(v));
        } else if let Some(v) = arg.strip_prefix("--repo-root=") {
            repo_root = Some(PathBuf::from(v));
        } else if let Some(v) = arg.strip_prefix("--toolchain-pin=") {
            toolchain_pin_file = Some(PathBuf::from(v));
        } else if let Some(v) = arg.strip_prefix("--expected-toolchain=") {
            expected_toolchain = Some(v.to_string());
        } else if let Some(v) = arg.strip_prefix("--acceptance-bin=") {
            acceptance_bin = Some(PathBuf::from(v));
        } else if arg == "--case" {
            if i + 3 >= args.len() {
                return Err("Missing manifest/input/output after --case.".into());
            }
            cases.push((
                PathBuf::from(&args[i + 1]),
                PathBuf::from(&args[i + 2]),
                PathBuf::from(&args[i + 3]),
            ));
            i += 3;
        } else {
            return Err(format!("Unknown offline-preflight option: {arg}"));
        }
        i += 1;
    }
    let cli_binary = cli_binary.ok_or("Missing --cli-binary=<path>.")?;
    let repo_root = repo_root.ok_or("Missing --repo-root=<path>.")?;
    let toolchain_pin_file = toolchain_pin_file.ok_or("Missing --toolchain-pin=<path>.")?;
    let expected_toolchain = expected_toolchain.ok_or("Missing --expected-toolchain=<ver>.")?;
    if cases.is_empty() {
        return Err("At least one --case triple is required.".into());
    }
    Ok(Command::OfflinePreflight {
        output_dir,
        cases,
        cli_binary,
        repo_root,
        toolchain_pin_file,
        expected_toolchain,
        acceptance_bin,
    })
}

fn parse_oep_policy(s: &str) -> Result<OepPolicy, String> {
    match s {
        "crt" => Ok(OepPolicy::Crt),
        "captured" => Ok(OepPolicy::Captured),
        other if other.starts_with("rva=") => {
            let v = &other[4..];
            let rva = if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                u32::from_str_radix(hex, 16)
            } else {
                v.parse::<u32>()
            }
            .map_err(|_| format!("invalid oep rva: {other}"))?;
            Ok(OepPolicy::Fixed(rva))
        }
        other => Err(format!("unknown --oep value: {other}")),
    }
}

/// Parse `--profile` CLI value (pure; no auto-detect from path/hash).
pub fn parse_profile(s: &str) -> Result<DumpProfile, String> {
    match s {
        "oreans-classic" | "classic" => Ok(DumpProfile::OreansClassic),
        "ahk-gto-experimental" | "ahk-gto" | "gto" => Ok(DumpProfile::AhkGtoExperimental),
        other => Err(format!(
            "unknown --profile value: {other} (expected oreans-classic|ahk-gto-experimental)"
        )),
    }
}

/// Parse `--gate-profile` for the generic pipeline (pure).
pub fn parse_gate_profile(s: &str) -> Result<GenericGateProfile, String> {
    match s {
        "agnostic" | "packer-agnostic" | "default" => Ok(GenericGateProfile::PackerAgnostic),
        "ahk-launcher" | "ahk" => Ok(GenericGateProfile::AhkLauncher),
        other => Err(format!(
            "unknown --gate-profile value: {other} (expected agnostic|ahk-launcher)"
        )),
    }
}

fn parse_container_restore(s: &str) -> Result<ContainerRestoreMode, String> {
    match s {
        "off" => Ok(ContainerRestoreMode::Off),
        "post-crt" => Ok(ContainerRestoreMode::PostCrt),
        "tls-pre" | "pre-crt" => Ok(ContainerRestoreMode::PreCrt),
        other => Err(format!("unknown --container-restore value: {other}")),
    }
}

/// Resolve container restore: explicit CLI wins; otherwise profile default.
///
/// Distinguishes "user did not pass --container-restore" (`None`) from an
/// explicit value so GTO profile + `--container-restore=off` stays Off.
pub fn resolve_container_restore(
    profile: DumpProfile,
    explicit: Option<ContainerRestoreMode>,
) -> ContainerRestoreMode {
    explicit.unwrap_or_else(|| profile.capabilities().default_container_restore)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_pe::{ContainerRestoreMode, DumpProfile, OepPolicy};

    #[test]
    fn default_unpack_oep_policy_preserves_runtime_capture() {
        assert_eq!(DEFAULT_OEP_POLICY, OepPolicy::Captured);
    }

    #[test]
    fn default_profile_is_oreans_classic() {
        assert_eq!(DEFAULT_DUMP_PROFILE, DumpProfile::OreansClassic);
        assert_eq!(DumpProfile::default(), DumpProfile::OreansClassic);
    }

    #[test]
    fn default_cli_disables_all_gto_capabilities() {
        let caps = DEFAULT_DUMP_PROFILE.capabilities();
        assert!(!caps.any_experimental());
        assert!(!caps.capture_containers);
        assert!(!caps.capture_heap_graph);
        assert!(!caps.install_heap_bootstrap);
        assert!(!caps.materialize_wrappers);
        assert!(!caps.patch_wrapper_calls);
    }

    #[test]
    fn profile_ahk_gto_experimental_enables_capabilities() {
        let profile = parse_profile("ahk-gto-experimental").unwrap();
        assert_eq!(profile, DumpProfile::AhkGtoExperimental);
        assert!(profile.capabilities().any_experimental());
    }

    #[test]
    fn oreans_classic_default_container_mode_is_off() {
        assert_eq!(
            resolve_container_restore(DumpProfile::OreansClassic, None),
            ContainerRestoreMode::Off
        );
    }

    #[test]
    fn ahk_gto_default_container_mode_is_post_crt() {
        assert_eq!(
            resolve_container_restore(DumpProfile::AhkGtoExperimental, None),
            ContainerRestoreMode::PostCrt
        );
    }

    #[test]
    fn explicit_container_restore_off_overrides_gto_default() {
        assert_eq!(
            resolve_container_restore(
                DumpProfile::AhkGtoExperimental,
                Some(ContainerRestoreMode::Off)
            ),
            ContainerRestoreMode::Off
        );
    }

    #[test]
    fn parse_profile_aliases() {
        assert_eq!(
            parse_profile("oreans-classic").unwrap(),
            DumpProfile::OreansClassic
        );
        assert_eq!(
            parse_profile("classic").unwrap(),
            DumpProfile::OreansClassic
        );
        assert_eq!(
            parse_profile("ahk-gto-experimental").unwrap(),
            DumpProfile::AhkGtoExperimental
        );
        assert_eq!(
            parse_profile("ahk-gto").unwrap(),
            DumpProfile::AhkGtoExperimental
        );
        assert!(parse_profile("auto").is_err());
    }

    #[test]
    fn default_gate_profile_is_packer_agnostic() {
        assert_eq!(
            parse_gate_profile("agnostic").unwrap(),
            GenericGateProfile::PackerAgnostic
        );
        assert_eq!(
            parse_gate_profile("packer-agnostic").unwrap(),
            GenericGateProfile::PackerAgnostic
        );
        assert_eq!(
            parse_gate_profile("default").unwrap(),
            GenericGateProfile::PackerAgnostic
        );
        assert_eq!(
            parse_gate_profile("ahk-launcher").unwrap(),
            GenericGateProfile::AhkLauncher
        );
        assert_eq!(
            parse_gate_profile("ahk").unwrap(),
            GenericGateProfile::AhkLauncher
        );
        assert!(parse_gate_profile("universal").is_err());
    }
}
