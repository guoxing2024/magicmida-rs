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
            capture_policy_digest,
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
            &capture_policy_digest,
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
        } => run_offline_preflight_command(
            &output_dir,
            &cases,
            &cli_binary,
            &repo_root,
            &toolchain_pin_file,
            &expected_toolchain,
        ),
        Command::Help | Command::Version => {
            unreachable!("Help and Version commands should be handled before run_command")
        }
    }
}

/// Production runner-side offline preflight (P6.2/P6.3.3): build the
/// case-bound runner-config envelope v4 (one per-case config derived from
/// `frozen_run_policy(case.input)` — the Origin Macro D3 default resolves
/// `pure_rebuild=true` only for the verified origin_macro input), drive the
/// independent verifier, consume the ready/not_ready report. Exit semantics:
/// Ok(false) = NotReady (gate failure), Ok(true) = Ready, Err =
/// verifier/reporting failure.
pub fn run_offline_preflight_command(
    output_dir: &Path,
    cases: &[(std::path::PathBuf, std::path::PathBuf, std::path::PathBuf)],
    cli_binary: &Path,
    repo_root: &Path,
    toolchain_pin_file: &Path,
    expected_toolchain: &str,
) -> Result<(), anyhow::Error> {
    use crate::runner_preflight::CaseRunnerConfigEnvelope;
    std::fs::create_dir_all(output_dir)?;
    let tool_revision = crate::runner_preflight::current_tool_revision(repo_root)?;
    let cli_binary_sha256 = crate::runner_preflight::sha256_file(cli_binary)?;
    // P6.3.2: the verifier can ONLY be the unique CLI sibling
    // (`resolve_verifier_identity` — no env, no caller path, no PATH). The
    // canonical path and SHA-256 are both pinned into the envelope.
    let (verifier_path, verifier_sha256) = crate::runner_preflight::resolve_verifier_identity()?;

    // P6.3.3: one per-case config from the REAL case input (frozen_run_policy
    // resolves the Origin D3 default from the verified input identity/path,
    // never from the case_id string). The protected-input identity bound into
    // the envelope comes from the LOCKED manifest's declared protected_input
    // artifact (the authoritative identity the verifier cross-references),
    // so the case-set seal is stable even when the sample file is absent
    // (the verifier reports NotReady; the envelope stays well-formed).
    // G2-R1: the packer family is bound at STAGING time from the case
    // manifest's `protection_family`, and becomes part of the sealed envelope
    // (family_id). The launch attestation uses exactly this family for the
    // actual/frozen policy and the digest — a case can never change family
    // after staging.
    let mut case_configs = Vec::with_capacity(cases.len());
    for (manifest, input, _output) in cases {
        let (case_id, protected_input, family_id) = case_identity_from_manifest(manifest)?;
        let mut config = crate::run_spec::frozen_run_policy_for_family(input, &family_id);
        config.tool_revision = tool_revision.clone();
        config.cli_binary_sha256 = cli_binary_sha256.clone();
        case_configs.push(CaseRunnerConfigEnvelope {
            case_id,
            family_id,
            protected_input,
            runner_config: serde_json::to_value(&config)
                .expect("per-case runner config serializes"),
            runner_config_digest: mida_core::runner_config::runner_config_digest(&config),
        });
    }

    let envelope = crate::runner_preflight::RunnerConfigEnvelope::build(
        case_configs,
        &cli_binary_sha256,
        &tool_revision,
        &verifier_path.display().to_string(),
        &verifier_sha256,
    );
    if let Some(reason) = envelope.validate_case_set() {
        return Err(anyhow::Error::msg(format!(
            "case-bound envelope is invalid: {reason}"
        )));
    }
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
    )?;
    if !ready {
        return Err(crate::unpacker::GenericGateFailure {
            failures: vec!["offline preflight is not ready; see preflight.json"],
        }
        .into());
    }
    Ok(())
}

/// Read the fixed `case_id`, the locked protected-input identity, and the
/// packer family (from `protection_family`) of a `mida.case-manifest/v2`
/// manifest. The envelope's per-case id and input identity must agree with the
/// verifier's `check_case_identity` (which derives them the same way from the
/// manifest). G2-R1: the family is bound at staging and becomes the envelope's
/// `family_id`; an unknown `protection_family` fails closed (no guessed family).
fn case_identity_from_manifest(
    manifest: &Path,
) -> Result<(String, crate::runner_preflight::FileIdentityGate, String), anyhow::Error> {
    let bytes = std::fs::read(manifest)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("manifest {}: {e}", manifest.display()))?;
    let case_id = value
        .get("case_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("manifest {} has no case_id", manifest.display()))?
        .to_string();
    let protection_family = value
        .get("capability_cell")
        .and_then(|c| c.get("protection_family"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manifest {} has no capability_cell.protection_family; cannot bind a packer \
                 family",
                manifest.display()
            )
        })?;
    let family_id = crate::run_spec::packer_family_from_protection_family(protection_family)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manifest {} protection_family {protection_family:?} is not a known packer \
                 family; refusing to stage (fail-closed)",
                manifest.display()
            )
        })?
        .to_string();
    let protected = value
        .get("artifacts")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|a| a.get("role").and_then(|r| r.as_str()) == Some("protected_input"))
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manifest {} has no protected_input artifact",
                manifest.display()
            )
        })?;
    let sha = protected
        .get("sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manifest {} protected_input has no sha256",
                manifest.display()
            )
        })?
        .to_lowercase();
    let size = protected
        .get("size_bytes")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manifest {} protected_input has no size_bytes",
                manifest.display()
            )
        })?;
    Ok((
        case_id,
        crate::runner_preflight::FileIdentityGate {
            sha256: sha,
            size_bytes: size,
        },
        family_id,
    ))
}
