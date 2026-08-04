//! Command dispatch — maps CLI commands to unpacker functions.

use std::path::Path;

use crate::args::Command;

pub fn run_command(cmd: Command) -> Result<(), anyhow::Error> {
    match cmd {
        Command::Unpack {
            input,
            output,
            create_data_sections,
            shrink,
            oep_policy,
            container_restore,
            profile,
            pure_rebuild,
            capture_policy,
            preflight_dir,
            verbose: _,
        } => crate::unpacker::unpack(
            &input,
            output.as_deref(),
            create_data_sections,
            shrink,
            oep_policy,
            container_restore,
            profile,
            pure_rebuild,
            capture_policy,
            preflight_dir.as_deref(),
        ),
        Command::GenericUnpack {
            input,
            output,
            wait_sec,
            stable,
            gate_profile,
            verbose: _,
        } => crate::unpacker::generic_unpack(
            &input,
            output.as_deref(),
            wait_sec,
            stable,
            gate_profile,
        ),
        Command::DumpProcess { pid, unpacked_file } => {
            crate::unpacker::dump_process_code(pid, &unpacked_file)
        }
        Command::Verify {
            unpacked,
            reference,
        } => crate::unpacker::verify_unpacked(&unpacked, &reference),
        Command::OfflinePreflight {
            output_dir,
            cases,
            cli_binary,
            repo_root,
            toolchain_pin_file,
            expected_toolchain,
            acceptance_bin,
        } => run_offline_preflight_command(
            &output_dir,
            &cases,
            &cli_binary,
            &repo_root,
            &toolchain_pin_file,
            &expected_toolchain,
            acceptance_bin.as_deref(),
        ),
        Command::Help | Command::Version => {
            unreachable!("Help and Version commands should be handled before run_command")
        }
    }
}

/// Production runner-side offline preflight (P6.2): build the frozen
/// runner-config envelope, drive the independent verifier, consume the
/// ready/not_ready report. Exit semantics: Ok(false) = NotReady (gate
/// failure), Ok(true) = Ready, Err = verifier/reporting failure.
pub fn run_offline_preflight_command(
    output_dir: &Path,
    cases: &[(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)],
    cli_binary: &Path,
    repo_root: &Path,
    toolchain_pin_file: &Path,
    expected_toolchain: &str,
    acceptance_bin: Option<&Path>,
) -> Result<(), anyhow::Error> {
    std::fs::create_dir_all(output_dir)?;
    let mut runner_config = crate::runner_preflight::frozen_runner_config();
    let tool_revision = crate::runner_preflight::current_tool_revision(repo_root)?;
    let cli_binary_sha256 = crate::runner_preflight::sha256_file(cli_binary)?;
    runner_config.tool_revision = tool_revision.clone();
    runner_config.cli_binary_sha256 = cli_binary_sha256.clone();
    let envelope = crate::runner_preflight::RunnerConfigEnvelope::build(
        &runner_config,
        &cli_binary_sha256,
        &tool_revision,
    );
    let borrowed: Vec<(&Path, &Path, &Path)> = cases
        .iter()
        .map(|(m, i, o)| (m.as_path(), i.as_path(), o.as_path()))
        .collect();
    let ready = crate::runner_preflight::run_offline_preflight(
        output_dir,
        &envelope,
        &borrowed,
        cli_binary,
        repo_root,
        toolchain_pin_file,
        expected_toolchain,
        acceptance_bin,
    )?;
    if !ready {
        return Err(crate::unpacker::GenericGateFailure {
            failures: vec!["offline preflight is not ready; see preflight.json"],
        }
        .into());
    }
    Ok(())
}
