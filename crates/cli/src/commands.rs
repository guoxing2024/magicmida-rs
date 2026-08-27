//! Command dispatch — maps CLI commands to unpacker functions.

use std::path::{Path, PathBuf};

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
            snapshot_root,
            dump_timing,
            verbose: _,
        } => {
            // WO-401A P0-2: explicit authorization gate for PostSelfDecrypt.
            // The CLI hard-rejects unless MIDA_GTO_LIVE2_AUTHORIZED=1 is set
            // (the only unlock). Variable absent => behaviour identical to
            // WO-201 (fail-closed). The manifest records live2_authorized=true
            // for audit (see unpacker::unpack).
            if dump_timing == mida_pe::DumpTiming::PostSelfDecrypt
                && std::env::var("MIDA_GTO_LIVE2_AUTHORIZED").ok().as_deref() != Some("1")
            {
                return Err(anyhow::anyhow!(
                    "--dump-timing=post-self-decrypt requires MIDA_GTO_LIVE2_AUTHORIZED=1 "
                        .to_string()
                        + "(GTO-H5-LIVE-AUTHORIZATION-2 Round 2 written gate); not set -- refusing to run"
                ));
            }
            // WO-702: coverage-measure requires MIDA_GTO_LIVE3_AUTHORIZED=1.
            if dump_timing == mida_pe::DumpTiming::CoverageMeasure
                && std::env::var("MIDA_GTO_LIVE3_AUTHORIZED").ok().as_deref() != Some("1")
            {
                return Err(anyhow::anyhow!(
                    "--dump-timing=coverage-measure requires MIDA_GTO_LIVE3_AUTHORIZED=1 "
                        .to_string()
                        + "(GTO-H5-LIVE-AUTHORIZATION-3 written gate); not set -- refusing to run"
                ));
            }
            crate::unpacker::unpack(
                &input,
                output.as_deref(),
                create_data_sections,
                shrink,
                oep_policy,
                container_restore,
                profile,
                pure_rebuild,
                dump_timing,
                capture_policy,
                &capture_policy_digest,
                preflight_dir.as_deref(),
                snapshot_root.as_deref(),
            )
        }
        Command::GenericUnpack {
            input,
            output,
            wait_sec,
            stable,
            gate_profile,
            iat_location,
            oep_policy,
            verbose: _,
        } => crate::unpacker::generic_unpack(
            &input,
            output.as_deref(),
            wait_sec,
            stable,
            gate_profile,
            iat_location,
            oep_policy,
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
        Command::BuildCapabilities => {
            // Handled in `run()` before run_command (pure query, returns 0);
            // this arm is a defensive no-op to keep the match exhaustive.
            crate::print_build_capabilities_json();
            Ok(())
        }
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
    let snapshot_root = output_dir.join(GTO_SNAPSHOT_DIRNAME);
    run_offline_preflight_command_with_snapshot_root(
        output_dir,
        &snapshot_root,
        cases,
        cli_binary,
        repo_root,
        toolchain_pin_file,
        expected_toolchain,
    )
}

/// Snapshot-aware variant of [`run_offline_preflight_command`]. The legacy API
/// uses `<output_dir>/sample-snapshots`; callers that manage a durable snapshot
/// store can provide it explicitly here.
///
/// Only the independent GTO lane is snapshotted. The two fixed Oreans cases
/// retain their existing manifest/input/output behavior and v2/v8 gate.
#[allow(clippy::too_many_arguments)]
pub fn run_offline_preflight_command_with_snapshot_root(
    output_dir: &Path,
    snapshot_root: &Path,
    cases: &[(PathBuf, PathBuf, PathBuf)],
    cli_binary: &Path,
    repo_root: &Path,
    toolchain_pin_file: &Path,
    expected_toolchain: &str,
) -> Result<(), anyhow::Error> {
    std::fs::create_dir_all(output_dir)?;
    let tool_revision = crate::runner_preflight::current_tool_revision(repo_root)?;
    let cli_binary_sha256 = crate::runner_preflight::sha256_file(cli_binary)?;
    // P6.3.2: the verifier can ONLY be the unique CLI sibling
    // (`resolve_verifier_identity` — no env, no caller path, no PATH). The
    // canonical path and SHA-256 are both pinned into the envelope.
    let (verifier_path, verifier_sha256) = crate::runner_preflight::resolve_verifier_identity()?;

    // P6.3.3: Oreans keeps its existing live-input staging behavior. GTO first
    // captures an immutable content-addressed snapshot, verifies it from disk,
    // and requires that identity to match the manifest before an envelope can
    // be produced. The source path is provenance only.
    // G2-R1: the packer family is bound at STAGING time from the case
    // manifest's `protection_family`, and becomes part of the sealed envelope
    // (family_id). The launch attestation uses exactly this family for the
    // actual/frozen policy and the digest — a case can never change family
    // after staging.
    let mut capture = |source: &Path, root: &Path, logical_id: &str, revision: &str| {
        crate::sample_snapshot::capture_snapshot(source, root, logical_id, revision)
    };
    let mut after_capture = |_snapshot: &crate::sample_snapshot::SampleSnapshot| {};
    let prepared = prepare_offline_preflight_staging(
        snapshot_root,
        cases,
        &cli_binary_sha256,
        &tool_revision,
        &verifier_path.display().to_string(),
        &verifier_sha256,
        &mut capture,
        &mut after_capture,
    )?;
    let borrowed: Vec<(&Path, &Path, &Path)> = prepared
        .cases
        .iter()
        .map(|(m, i, o)| (m.as_path(), i.as_path(), o.as_path()))
        .collect();
    // P6.3-G3-R3 last-trusted boundary: re-verify every staged GTO snapshot
    // from disk against the locked manifest identity immediately before the
    // verifier is invoked. A snapshot tampered/truncated/deleted/replaced
    // between staging and launch fails closed here; we never trust a cached
    // SampleSnapshot/StagingIdentity, and we never re-read the live dynamic
    // source path as the protected input.
    for (manifest, input, _output) in &borrowed {
        reverify_gto_case_input(snapshot_root, manifest, input)?;
    }
    let ready = crate::runner_preflight::run_offline_preflight(
        output_dir,
        &prepared.envelope,
        &borrowed,
        cli_binary,
        repo_root,
        toolchain_pin_file,
        expected_toolchain,
        snapshot_root,
    )?;
    if !ready {
        return Err(crate::unpacker::GenericGateFailure {
            failures: vec!["offline preflight is not ready; see preflight.json"],
        }
        .into());
    }
    Ok(())
}

/// Default content-addressed snapshot store below the controlled preflight
/// output directory. It is intentionally separate from candidate outputs.
pub const GTO_SNAPSHOT_DIRNAME: &str = "sample-snapshots";

#[derive(Debug)]
struct PreparedOfflinePreflight {
    envelope: crate::runner_preflight::RunnerConfigEnvelope,
    /// `(manifest, verified protected input, candidate output)`. GTO entries
    /// point at `snapshot.bin`; Oreans entries preserve the caller input path.
    cases: Vec<(PathBuf, PathBuf, PathBuf)>,
}

type SnapshotCaptureResult =
    Result<crate::sample_snapshot::SampleSnapshot, crate::sample_snapshot::CaptureError>;

#[allow(clippy::too_many_arguments)]
fn prepare_offline_preflight_staging(
    snapshot_root: &Path,
    cases: &[(PathBuf, PathBuf, PathBuf)],
    cli_binary_sha256: &str,
    tool_revision: &str,
    verifier_path: &str,
    verifier_sha256: &str,
    capture: &mut dyn FnMut(&Path, &Path, &str, &str) -> SnapshotCaptureResult,
    after_capture: &mut dyn FnMut(&crate::sample_snapshot::SampleSnapshot),
) -> Result<PreparedOfflinePreflight, anyhow::Error> {
    use crate::runner_preflight::{CaseRunnerConfigEnvelope, GTO_CASE_ID};
    use mida_core::runner_config::packer_family;

    let mut case_configs = Vec::with_capacity(cases.len());
    let mut staged_cases = Vec::with_capacity(cases.len());

    for (manifest, source_input, output) in cases {
        let (case_id, manifest_identity, family_id) = case_identity_from_manifest(manifest)?;
        let (verified_input, bound_identity) = if case_id == GTO_CASE_ID {
            if family_id != packer_family::AHK_GTO {
                return Err(gto_snapshot_not_ready(format!(
                    "case {case_id} manifest bound family {family_id:?}, expected {:?}",
                    packer_family::AHK_GTO
                )));
            }

            let snapshot =
                capture(source_input, snapshot_root, &case_id, tool_revision).map_err(|e| {
                    gto_snapshot_not_ready(format!(
                        "case {case_id} could not capture protected input {}: {e}",
                        source_input.display()
                    ))
                })?;
            // Test seam only: production passes a no-op. The real boundary
            // below always re-reads disk and never trusts this cached object.
            after_capture(&snapshot);

            let verified = crate::sample_snapshot::verified_read_snapshot(
                snapshot_root,
                &case_id,
                &snapshot.snapshot_sha256,
            )
            .map_err(|e| {
                gto_snapshot_not_ready(format!(
                    "case {case_id} snapshot verified resolve failed after capture: {e}"
                ))
            })?;
            let staging =
                crate::sample_snapshot::staging_identity_from_verified(&verified, source_input);
            if !crate::sample_snapshot::staging_identity_matches(
                &staging,
                snapshot_root,
                &manifest_identity.sha256,
                manifest_identity.size_bytes,
            ) {
                return Err(gto_snapshot_not_ready(format!(
                    "case {case_id} snapshot identity mismatch: captured {}/{} revision {}, manifest {}/{}; source {} remains provenance only",
                    staging.snapshot_sha256,
                    staging.snapshot_size_bytes,
                    staging.revision,
                    manifest_identity.sha256,
                    manifest_identity.size_bytes,
                    staging.source_path.display()
                )));
            }

            eprintln!(
                "staged GTO immutable snapshot {} from source provenance {}",
                staging.revision,
                staging.source_path.display()
            );
            (
                verified.snapshot_abs_path,
                crate::runner_preflight::FileIdentityGate {
                    sha256: staging.snapshot_sha256,
                    size_bytes: staging.snapshot_size_bytes,
                },
            )
        } else {
            // Oreans compatibility boundary: no GTO snapshot semantics are
            // introduced into the fixed two-sample v2/v8 lane.
            (source_input.clone(), manifest_identity)
        };

        let mut config = crate::run_spec::frozen_run_policy_for_family(&verified_input, &family_id);
        config.tool_revision = tool_revision.to_string();
        config.cli_binary_sha256 = cli_binary_sha256.to_string();
        // G3-R3-R1: the GTO lane seals its immutable snapshot PATH into the
        // envelope so launch can require identity+path double-binding. The
        // snapshot path is under snapshot_root; Oreans keeps live-input
        // semantics and carries None (no path binding).
        let is_gto = case_id == crate::runner_preflight::GTO_CASE_ID;
        let sealed_input_path = if is_gto {
            Some(verified_input.display().to_string())
        } else {
            None
        };
        case_configs.push(CaseRunnerConfigEnvelope {
            case_id,
            family_id,
            protected_input: bound_identity,
            protected_input_path: sealed_input_path,
            runner_config: serde_json::to_value(&config)
                .expect("per-case runner config serializes"),
            runner_config_digest: mida_core::runner_config::runner_config_digest(&config),
        });
        staged_cases.push((manifest.clone(), verified_input, output.clone()));
    }

    // G3-R3 boundary (pre-seal): re-verify every staged GTO snapshot from disk
    // against its manifest identity immediately before the runner-config
    // envelope is sealed. A snapshot modified/truncated/deleted/replaced since
    // the staging-entry check fails closed here, so the sealed envelope can
    // only ever be built on a verified identity.
    for (manifest, verified_input, _output) in &staged_cases {
        reverify_gto_case_input(snapshot_root, manifest, verified_input)?;
    }

    let envelope = crate::runner_preflight::RunnerConfigEnvelope::build(
        case_configs,
        cli_binary_sha256,
        tool_revision,
        verifier_path,
        verifier_sha256,
    );
    if let Some(reason) = envelope.validate_case_set() {
        return Err(anyhow::Error::msg(format!(
            "case-bound envelope is invalid: {reason}"
        )));
    }

    Ok(PreparedOfflinePreflight {
        envelope,
        cases: staged_cases,
    })
}

fn gto_snapshot_not_ready(reason: String) -> anyhow::Error {
    anyhow::Error::new(crate::unpacker::GenericGateFailure {
        failures: vec!["GTO immutable snapshot staging is not ready"],
    })
    .context(reason)
}

/// Re-verify a staged case's protected input from disk against the locked
/// manifest identity. Only the GTO lane is snapshot-staged (Oreans cases keep
/// their existing live-input behavior, so this is a no-op for them).
///
/// This is the G3-R3 boundary re-verification helper used both before the
/// envelope is sealed and at the last trusted boundary before the verifier is
/// invoked. It re-reads the on-disk snapshot (`input_path`, which for GTO is
/// `snapshot.bin`, never the live dynamic source) and recomputes hash + size;
/// any read failure, truncation, deletion, replacement, or hash/size mismatch
/// with the manifest identity fails closed. It never trusts a cached
/// [`crate::sample_snapshot::SampleSnapshot`] or
/// [`crate::sample_snapshot::StagingIdentity`] field.
fn reverify_gto_case_input(
    snapshot_root: &Path,
    manifest: &Path,
    input_path: &Path,
) -> Result<(), anyhow::Error> {
    let (case_id, manifest_identity, family_id) = case_identity_from_manifest(manifest)?;
    // Only the GTO lane carries an immutable snapshot; Oreans inputs are left
    // to their existing v2/v8 gate and are not snapshot-verified here.
    if case_id != crate::runner_preflight::GTO_CASE_ID {
        return Ok(());
    }
    if family_id != mida_core::runner_config::packer_family::AHK_GTO {
        return Err(gto_snapshot_not_ready(format!(
            "case {case_id} re-verification: manifest family {family_id:?} is not {:?}",
            mida_core::runner_config::packer_family::AHK_GTO
        )));
    }
    // The protected input consumed by the envelope/preflight MUST be an
    // immutable snapshot under the controlled snapshot store — never the live
    // dynamic source path. This structural guard prevents a caller from wiring
    // the source as a trusted input.
    if !input_path.starts_with(snapshot_root) {
        return Err(gto_snapshot_not_ready(format!(
            "case {case_id} re-verification: protected input {} is not under snapshot root {}",
            input_path.display(),
            snapshot_root.display()
        )));
    }
    // Re-read the immutable snapshot from disk and recompute its identity. This
    // is the file the envelope/preflight consumes, NOT the live source path.
    let observed = crate::runner_preflight::file_identity(input_path).map_err(|e| {
        gto_snapshot_not_ready(format!(
            "case {case_id} re-verification could not read snapshot {}: {e}",
            input_path.display()
        ))
    })?;
    if observed.sha256 != manifest_identity.sha256
        || observed.size_bytes != manifest_identity.size_bytes
    {
        return Err(gto_snapshot_not_ready(format!(
            "case {case_id} snapshot re-verification failed at boundary: observed {}/{} on {}, manifest expects {}/{}",
            observed.sha256,
            observed.size_bytes,
            input_path.display(),
            manifest_identity.sha256,
            manifest_identity.size_bytes
        )));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Write a synthetic GTO-case manifest with the given protected-input
    /// identity (hash + size). Mirrors `lab/cases/v2/gto_launcher.json`'s shape:
    /// case_id = gto_launcher, protection_family = ahk_gto_candidate (which the
    /// family resolver maps to `packer_family::AHK_GTO`).
    fn write_gto_manifest(manifest: &Path, sha256: &str, size_bytes: u64) -> PathBuf {
        let json = serde_json::json!({
            "$schema": "./case-manifest.schema.json",
            "schema_version": "mida.case-manifest/v2",
            "case_id": "gto_launcher",
            "artifacts": [
                {
                    "sha256": sha256,
                    "size_bytes": size_bytes,
                    "role": "protected_input"
                }
            ],
            "capability_cell": {
                "protection_family": "ahk_gto_candidate",
                "engine_route": "mida_plugin_ahk_gto"
            }
        });
        std::fs::write(manifest, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        manifest.to_path_buf()
    }

    /// Write a synthetic OREANS-case manifest (`origin_macro` / `lunlun_software`)
    /// with the given protected-input identity. `protection_family =
    /// oreans_candidate` maps to `packer_family::OREANS`. Used to build a valid
    /// 3-case envelope (two Oreans fixed cases + the GTO lane case).
    fn write_oreans_manifest(manifest: &Path, case_id: &str, sha256: &str, size: u64) -> PathBuf {
        let json = serde_json::json!({
            "schema_version": "mida.case-manifest/v2",
            "case_id": case_id,
            "artifacts": [
                { "sha256": sha256, "size_bytes": size, "role": "protected_input" }
            ],
            "capability_cell": {
                "protection_family": "oreans_candidate",
                "engine_route": "mida_plugin_oreans"
            }
        });
        std::fs::write(manifest, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
        manifest.to_path_buf()
    }

    /// A minimal valid 64-hex SHA-256, unique per `tag`.
    fn fake_sha(tag: u8) -> String {
        format!("{tag:02x}") + &"ab".repeat(31)
    }

    /// Build a full staging `cases` slice: the two Oreans fixed cases plus a
    /// GTO case whose source is `gto_src` and whose manifest declares the given
    /// identity. Oreans cases get dummy sources (their identity only needs to be
    /// internally consistent with their manifests for `validate_case_set`).
    fn full_cases(
        root: &Path,
        gto_manifest: &Path,
        gto_src: &Path,
        oreans_sha: u8,
        lunlun_sha: u8,
    ) -> Vec<(PathBuf, PathBuf, PathBuf)> {
        let origin_manifest = write_oreans_manifest(
            &root.join("origin_macro.json"),
            "origin_macro",
            &fake_sha(oreans_sha),
            2048,
        );
        let lunlun_manifest = write_oreans_manifest(
            &root.join("lunlun_software.json"),
            "lunlun_software",
            &fake_sha(lunlun_sha),
            1024,
        );
        let origin_src = root.join("origin.bin");
        let lunlun_src = root.join("lunlun.bin");
        std::fs::write(&origin_src, vec![0u8; 2048]).unwrap();
        std::fs::write(&lunlun_src, vec![0u8; 1024]).unwrap();
        vec![
            (origin_manifest, origin_src, root.join("out_origin")),
            (lunlun_manifest, lunlun_src, root.join("out_lunlun")),
            (
                gto_manifest.to_path_buf(),
                gto_src.to_path_buf(),
                root.join("out_gto"),
            ),
        ]
    }

    /// Run full staging over a GTO case (plus dummy Oreans cases) and return the
    /// prepared envelope / staged cases.
    fn stage_full(
        root: &Path,
        gto_manifest: &Path,
        gto_src: &Path,
    ) -> Result<PreparedOfflinePreflight, anyhow::Error> {
        let snap = snapshot_root(root);
        let cases = full_cases(root, gto_manifest, gto_src, 0x11, 0x22);
        prepare_offline_preflight_staging(
            &snap,
            &cases,
            "CLI-SHA",
            "rev@staging",
            "verifier",
            "VERIFIER-SHA",
            &mut *real_capture(),
            &mut *noop_after(),
        )
    }

    /// Deterministic snapshot-store path under a temp root.
    fn snapshot_root(root: &Path) -> PathBuf {
        root.join("sample-snapshots")
    }

    /// A no-op `after_capture` seam (production path).
    fn noop_after() -> Box<dyn FnMut(&crate::sample_snapshot::SampleSnapshot)> {
        Box::new(|_s: &crate::sample_snapshot::SampleSnapshot| {})
    }

    /// A real `capture` closure bound to `crate::sample_snapshot::capture_snapshot`.
    fn real_capture() -> Box<dyn FnMut(&Path, &Path, &str, &str) -> SnapshotCaptureResult> {
        Box::new(
            |source: &Path, snap_root: &Path, logical_id: &str, rev: &str| {
                crate::sample_snapshot::capture_snapshot(source, snap_root, logical_id, rev)
            },
        )
    }

    /// Assert an error is a GTO NotReady fail-closed (GenericGateFailure or a
    /// not-ready context), never a plain success path.
    fn assert_rejected(err: &anyhow::Error) {
        let msg = format!("{err:#}");
        assert!(
            msg.contains("GTO")
                || msg.contains("not ready")
                || msg.contains("snapshot re-verification")
                || msg.contains("verified resolve"),
            "expected a GTO NotReady fail-closed error, got: {msg}"
        );
    }

    /// R3-1: a manifest-matching GTO source is accepted end-to-end: content-
    /// addressed capture -> verified resolve -> staging identity -> GTO envelope
    /// with family=ahk_gto, generic evidence + no-gate schema. Staged alongside
    /// the two Oreans fixed cases (the envelope's case-set invariant requires
    /// them), the GTO lane case carries its own family and generic no-gate config.
    #[test]
    fn gto_snapshot_staging_accepts_manifest_matching_revision() {
        let root = temp_root("gto_staging_accept");
        let src = root.join("launcher.bin");
        let src_bytes = b"SYNTHETIC-GTO-PROTECTED-INPUT-CONTENT";
        std::fs::write(&src, src_bytes).unwrap();
        let want_sha = crate::sample_snapshot::sha256_hex(src_bytes);
        let want_size = src_bytes.len() as u64;
        let manifest = write_gto_manifest(&root.join("gto_launcher.json"), &want_sha, want_size);
        let snap = snapshot_root(&root);

        let prepared = stage_full(&root, &manifest, &src).unwrap();

        // Three cases: the two Oreans fixed cases (unchanged) plus the GTO lane.
        assert_eq!(prepared.envelope.case_configs.len(), 3);
        assert_eq!(prepared.envelope.case_configs[0].case_id, "origin_macro");
        assert_eq!(prepared.envelope.case_configs[1].case_id, "lunlun_software");
        assert_eq!(
            prepared.envelope.case_configs[2].case_id,
            crate::runner_preflight::GTO_CASE_ID
        );
        // The GTO case is bound with family ahk_gto, generic evidence + no-gate.
        let c = &prepared.envelope.case_configs[2];
        assert_eq!(
            c.family_id,
            mida_core::runner_config::packer_family::AHK_GTO
        );
        assert_eq!(c.protected_input.sha256, want_sha);
        assert_eq!(c.protected_input.size_bytes, want_size);
        let cfg = c.runner_config.as_object().unwrap();
        assert_eq!(
            cfg["packer_family"].as_str().unwrap(),
            mida_core::runner_config::packer_family::AHK_GTO
        );
        assert_eq!(
            cfg["gate_schema"].as_str().unwrap(),
            crate::run_spec::UNPACK_GATE_ABSENT
        );
        // The staged protected input for GTO is the snapshot path, NOT the live
        // source. (Oreans entries preserve their caller input path.)
        let gto_staged = &prepared.cases[2];
        let staged_input = &gto_staged.1;
        assert!(
            staged_input.starts_with(&snap),
            "input must be snapshot path"
        );
        assert_ne!(
            staged_input, &src,
            "live source must not be the trusted input"
        );
        assert!(staged_input.ends_with("snapshot.bin"));
        // The Oreans staged inputs remain the caller source paths (isolation).
        assert_eq!(prepared.cases[0].1, prepared.cases[0].1); // origin input preserved
        assert!(!prepared.cases[0].1.starts_with(&snap));
        // The staged GTO snapshot verifies to the manifest identity at the
        // last-trusted boundary.
        reverify_gto_case_input(&snap, &manifest, staged_input).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    /// R3-2: a GTO source whose hash/size differ from the manifest is captured
    /// content-addressed but staging FAILS CLOSED. No envelope is produced, the
    /// manifest is untouched, and the observed live revision is retained but not
    /// treated as the authority.
    #[test]
    fn gto_snapshot_staging_rejects_manifest_mismatch() {
        let root = temp_root("gto_staging_mismatch");
        let src = root.join("launcher.bin");
        let src_bytes = b"OBSERVED-LIVE-REVISION-B";
        std::fs::write(&src, src_bytes).unwrap();
        let observed_sha = crate::sample_snapshot::sha256_hex(src_bytes);
        let manifest_bytes = b"DECLARED-REVISION-A-MANIFEST-IDENTITY";
        let manifest_sha = crate::sample_snapshot::sha256_hex(manifest_bytes);
        let manifest_size = manifest_bytes.len() as u64;
        let manifest = write_gto_manifest(
            &root.join("gto_launcher.json"),
            &manifest_sha,
            manifest_size,
        );
        let manifest_before = std::fs::read(&manifest).unwrap();
        let snap = snapshot_root(&root);
        let cases = vec![(manifest.clone(), src.clone(), root.join("out"))];

        let err = prepare_offline_preflight_staging(
            &snap,
            &cases,
            "CLI-SHA",
            "rev",
            "verifier",
            "VSHA",
            &mut *real_capture(),
            &mut *noop_after(),
        )
        .unwrap_err();
        assert_rejected(&err);
        let msg = format!("{err:#}");
        assert!(
            msg.contains("identity mismatch"),
            "error must diagnose the mismatch: {msg}"
        );
        assert!(
            msg.contains(&manifest_sha) && msg.contains(&observed_sha),
            "error must carry expected+observed hashes: {msg}"
        );
        // Manifest is NOT rewritten.
        assert_eq!(std::fs::read(&manifest).unwrap(), manifest_before);
        // The observed live revision was content-addressed and retained.
        let observed_snap = snap
            .join(crate::runner_preflight::GTO_CASE_ID)
            .join(&observed_sha)
            .join("snapshot.bin");
        assert!(observed_snap.is_file(), "observed revision retained");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// R3-3: source changing (or being deleted) between the two capture reads
    /// fails closed: no staging entry, no envelope, old revision preserved, no
    /// temp residue mistaken for a complete revision.
    #[test]
    fn gto_snapshot_source_changes_during_capture_fails_closed() {
        let root = temp_root("gto_staging_source_change");
        let src = root.join("launcher.bin");
        let src_bytes = b"REVISION-A-STABLE-SOURCE".to_vec();
        std::fs::write(&src, &src_bytes).unwrap();
        let want_sha = crate::sample_snapshot::sha256_hex(&src_bytes);
        let snap = snapshot_root(&root);

        // First a stable capture establishes revision A.
        crate::sample_snapshot::capture_snapshot(
            &src,
            &snap,
            crate::runner_preflight::GTO_CASE_ID,
            "rev",
        )
        .unwrap();
        let rev_a = snap
            .join(crate::runner_preflight::GTO_CASE_ID)
            .join(&want_sha);
        assert!(rev_a.join("snapshot.bin").is_file());

        // Second capture changes the source between reads -> fail-closed; the
        // manifest is untouched; revision A preserved.
        let hook_src = src.clone();
        let err = crate::sample_snapshot::capture_snapshot_with_hooks(
            &src,
            &snap,
            crate::runner_preflight::GTO_CASE_ID,
            "rev",
            Some(Box::new(move || {
                std::fs::write(&hook_src, b"REVISION-B-CHANGED-DURING-CAPTURE").unwrap();
            })),
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            crate::sample_snapshot::CaptureError::SourceChangedDuringCapture
        );
        assert!(rev_a.join("snapshot.bin").is_file());
        // No temp residue in any content-addressed dir.
        let case_dir = snap.join(crate::runner_preflight::GTO_CASE_ID);
        for entry in std::fs::read_dir(&case_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                let names: Vec<String> = std::fs::read_dir(entry.path())
                    .unwrap()
                    .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                    .collect();
                assert!(
                    names.iter().all(|n| !n.starts_with(".capturing-")),
                    "no temp residue: {names:?}"
                );
                for n in names {
                    assert!(
                        n == "snapshot.bin",
                        "unexpected file {n} in content-addressed dir"
                    );
                }
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// R3-4: a snapshot tampered (modified/truncated/deleted) AFTER capture but
    /// BEFORE the envelope is sealed / pre-launch is rejected at the boundary.
    #[test]
    fn gto_snapshot_tampered_before_envelope_is_rejected() {
        let root = temp_root("gto_tamper_boundary");
        let src = root.join("launcher.bin");
        let src_bytes = b"TAMPER-BOUNDARY-SNAPSHOT-CONTENT";
        std::fs::write(&src, src_bytes).unwrap();
        let want_sha = crate::sample_snapshot::sha256_hex(src_bytes);
        let want_size = src_bytes.len() as u64;
        let manifest = write_gto_manifest(&root.join("gto_launcher.json"), &want_sha, want_size);
        let snap = snapshot_root(&root);

        let snap_res = crate::sample_snapshot::capture_snapshot(
            &src,
            &snap,
            crate::runner_preflight::GTO_CASE_ID,
            "rev",
        )
        .unwrap();
        let snap_path = snap_res.snapshot_abs_path.clone();
        assert!(snap_path.is_file());

        // Case A: TRUNCATION after capture -> boundary re-verify rejects.
        let full = std::fs::read(&snap_path).unwrap();
        std::fs::write(&snap_path, &full[..full.len() / 2]).unwrap();
        let err = reverify_gto_case_input(&snap, &manifest, &snap_path).unwrap_err();
        assert_rejected(&err);

        // Case B: CONTENT modification (same length, different bytes) -> reject.
        let mut modded = src_bytes.to_vec();
        modded[0] ^= 0xFF;
        std::fs::write(&snap_path, &modded).unwrap();
        let err = reverify_gto_case_input(&snap, &manifest, &snap_path).unwrap_err();
        assert_rejected(&err);

        // Case C: DELETE the snapshot -> boundary read fails closed.
        std::fs::remove_file(&snap_path).unwrap();
        let err = reverify_gto_case_input(&snap, &manifest, &snap_path).unwrap_err();
        assert_rejected(&err);

        // Case D: pre-seal boundary — tamper via the after_capture seam so the
        // in-staging verified resolve sees a bad snapshot and fails closed.
        let src2 = root.join("src2.bin");
        std::fs::write(&src2, src_bytes).unwrap();
        let manifest2 = write_gto_manifest(&root.join("gto_launcher2.json"), &want_sha, want_size);
        let snap2 = root.join("caseD-snapshots");
        let cases = vec![(manifest2.clone(), src2.clone(), root.join("out2"))];
        let after = Box::new(move |s: &crate::sample_snapshot::SampleSnapshot| {
            // Replace the just-captured snapshot.bin with tampered bytes.
            std::fs::write(&s.snapshot_abs_path, b"TAMPERED-BEFORE-SEAL").unwrap();
        });
        let err = prepare_offline_preflight_staging(
            &snap2,
            &cases,
            "CLI-SHA",
            "rev",
            "verifier",
            "VSHA",
            &mut *real_capture(),
            &mut Box::new(after),
        )
        .unwrap_err();
        assert_rejected(&err);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// R3-5: a live dynamic revision B does not replace manifest authority A.
    /// B is content-addressed and retained; A (if present) is preserved; B is
    /// not written into the manifest; B cannot become the launch identity;
    /// staging returns NotReady.
    #[test]
    fn live_revision_does_not_replace_manifest_authority() {
        let root = temp_root("gto_live_revision");
        let src = root.join("launcher.bin");
        let rev_a = b"REVISION-A-AUTHORITY";
        std::fs::write(&src, rev_a).unwrap();
        let a_sha = crate::sample_snapshot::sha256_hex(rev_a);
        let a_size = rev_a.len() as u64;
        let manifest = write_gto_manifest(&root.join("gto_launcher.json"), &a_sha, a_size);
        let manifest_before = std::fs::read(&manifest).unwrap();
        let snap = snapshot_root(&root);

        // Authoritative revision A is captured.
        crate::sample_snapshot::capture_snapshot(
            &src,
            &snap,
            crate::runner_preflight::GTO_CASE_ID,
            "rev",
        )
        .unwrap();
        let rev_a_dir = snap.join(crate::runner_preflight::GTO_CASE_ID).join(&a_sha);
        assert!(rev_a_dir.join("snapshot.bin").is_file());

        // The live source updates to revision B (different bytes).
        let rev_b = b"REVISION-B-LIVE-DYNAMIC-UPDATE";
        std::fs::write(&src, rev_b).unwrap();
        let b_sha = crate::sample_snapshot::sha256_hex(rev_b);
        let cases = vec![(manifest.clone(), src.clone(), root.join("out"))];

        // Staging against manifest identity A with live source B -> fail-closed.
        let err = prepare_offline_preflight_staging(
            &snap,
            &cases,
            "CLI-SHA",
            "rev",
            "verifier",
            "VSHA",
            &mut *real_capture(),
            &mut *noop_after(),
        )
        .unwrap_err();
        assert_rejected(&err);

        // Revision A preserved; revision B captured content-addressed but never
        // became the manifest authority; manifest untouched.
        assert!(rev_a_dir.join("snapshot.bin").is_file());
        let rev_b_dir = snap.join(crate::runner_preflight::GTO_CASE_ID).join(&b_sha);
        assert!(rev_b_dir.join("snapshot.bin").is_file());
        assert_eq!(std::fs::read(&manifest).unwrap(), manifest_before);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// R3-6: the GTO envelope and its config keep the GTO family. A GTO family
    /// envelope + GTO config is accepted and passes launch attestation; GTO
    /// config with Oreans family (or vice versa), unknown/missing family, and
    /// cross-lane configs are all rejected BEFORE CreateProcess.
    #[test]
    fn envelope_and_attestation_keep_gto_family() {
        use mida_core::runner_config::packer_family;

        let gto_config = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        let oreans_config = crate::run_spec::frozen_runner_config_for_family(packer_family::OREANS);
        assert_eq!(gto_config.gate_schema, crate::run_spec::UNPACK_GATE_ABSENT);
        assert_eq!(oreans_config.gate_schema, "mida.oreans-two-sample-gate/v8");

        // Build the two Oreans fixed cases with their own (valid) configs.
        fn oreans_case(
            case_id: &str,
            identity: crate::runner_preflight::FileIdentityGate,
        ) -> crate::runner_preflight::CaseRunnerConfigEnvelope {
            let config = crate::run_spec::frozen_runner_config_for_family(
                mida_core::runner_config::packer_family::OREANS,
            );
            crate::runner_preflight::CaseRunnerConfigEnvelope {
                case_id: case_id.to_string(),
                family_id: mida_core::runner_config::packer_family::OREANS.to_string(),
                protected_input: identity,
                protected_input_path: None, // Oreans live-input lane: no path binding
                runner_config: serde_json::to_value(&config).unwrap(),
                runner_config_digest: mida_core::runner_config::runner_config_digest(&config),
            }
        }
        let origin = oreans_case(
            "origin_macro",
            crate::runner_preflight::FileIdentityGate {
                sha256: fake_sha(0x10),
                size_bytes: 2048,
            },
        );
        let lunlun = oreans_case(
            "lunlun_software",
            crate::runner_preflight::FileIdentityGate {
                sha256: fake_sha(0x20),
                size_bytes: 1024,
            },
        );

        let gto_identity = crate::runner_preflight::FileIdentityGate {
            sha256: fake_sha(0x30),
            size_bytes: 128,
        };

        // Valid GTO case (family=ahk_gto + GTO config + a sealed snapshot path).
        let gto_case = crate::runner_preflight::CaseRunnerConfigEnvelope {
            case_id: crate::runner_preflight::GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: gto_identity.clone(),
            protected_input_path: Some(
                "C:\\snapshots\\gto_launcher\\cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\snapshot.bin"
                    .to_string(),
            ),
            runner_config: serde_json::to_value(&gto_config).unwrap(),
            runner_config_digest: mida_core::runner_config::runner_config_digest(&gto_config),
        };
        // A 3-case envelope (2 Oreans fixed + GTO) is accepted.
        let ok_env = crate::runner_preflight::RunnerConfigEnvelope::build(
            vec![origin.clone(), lunlun.clone(), gto_case.clone()],
            "CLI",
            "REV",
            "verifier",
            "VSHA",
        );
        assert_eq!(
            ok_env.validate_case_set(),
            None,
            "GTO family envelope + GTO config must be accepted"
        );

        // Launch attestation: writing the envelope and binding a GTO actual
        // config against the GTO identity succeeds (family + digest match).
        let root = temp_root("gto_family");
        let out = root.join("out");
        std::fs::create_dir_all(&out).unwrap();
        ok_env.write(&out).unwrap();
        crate::runner_preflight::bind_actual_config_to_envelope(&out, &gto_config, &gto_identity)
            .unwrap();

        // Launch attestation: an OREANS actual config against the GTO identity
        // is a family mismatch -> rejected before CreateProcess.
        let err = crate::runner_preflight::bind_actual_config_to_envelope(
            &out,
            &oreans_config,
            &gto_identity,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("family"),
            "family mismatch must be rejected at launch: {err:#}"
        );

        // GTO lane case carrying an OREANS config (family=ahk_gto) — a case-set
        // shape violation (the embedded config family must be the lane family).
        let gto_with_oreans_cfg = crate::runner_preflight::CaseRunnerConfigEnvelope {
            case_id: crate::runner_preflight::GTO_CASE_ID.to_string(),
            family_id: packer_family::AHK_GTO.to_string(),
            protected_input: gto_identity.clone(),
            protected_input_path: Some(
                "C:\\snapshots\\gto_launcher\\cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\\snapshot.bin"
                    .to_string(),
            ),
            runner_config: serde_json::to_value(&oreans_config).unwrap(),
            runner_config_digest: mida_core::runner_config::runner_config_digest(&oreans_config),
        };
        // This still passes validate_case_set (family_id is ahk_gto), but the
        // digest is that of an Oreans config, so launch binding against the GTO
        // actual config fails on digest. It is rejected downstream by the
        // launch boundary (family/digest bind), never accepted as GTO.
        let cross_env = crate::runner_preflight::RunnerConfigEnvelope::build(
            vec![origin.clone(), lunlun.clone(), gto_with_oreans_cfg],
            "CLI",
            "REV",
            "verifier",
            "VSHA",
        );
        assert_eq!(cross_env.validate_case_set(), None);
        let out2 = root.join("out2");
        std::fs::create_dir_all(&out2).unwrap();
        cross_env.write(&out2).unwrap();
        let err = crate::runner_preflight::bind_actual_config_to_envelope(
            &out2,
            &gto_config,
            &gto_identity,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("digest"),
            "Oreans config under GTO envelope must fail launch digest binding: {err:#}"
        );

        // Oreans envelope + GTO config -> rejected at the launch family check.
        // Binding an actual GTO config against the origin_macro case (whose
        // family is oreans_themida) fails closed on family BEFORE CreateProcess.
        let origin_identity = crate::runner_preflight::FileIdentityGate {
            sha256: fake_sha(0x10),
            size_bytes: 2048,
        };
        let err = crate::runner_preflight::bind_actual_config_to_envelope(
            &out,
            &gto_config,
            &origin_identity,
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("family"),
            "Oreans envelope + GTO config must be rejected at launch: {err:#}"
        );

        // Unknown family on the GTO case -> rejected.
        let unknown = crate::runner_preflight::CaseRunnerConfigEnvelope {
            case_id: crate::runner_preflight::GTO_CASE_ID.to_string(),
            family_id: "not_a_family".to_string(),
            protected_input: gto_identity.clone(),
            protected_input_path: None,
            runner_config: serde_json::to_value(&gto_config).unwrap(),
            runner_config_digest: mida_core::runner_config::runner_config_digest(&gto_config),
        };
        let unknown_env = crate::runner_preflight::RunnerConfigEnvelope::build(
            vec![origin.clone(), lunlun.clone(), unknown],
            "CLI",
            "REV",
            "verifier",
            "VSHA",
        );
        assert!(
            unknown_env.validate_case_set().is_some(),
            "unknown family must be rejected"
        );

        // Missing (empty) family on the GTO case -> rejected.
        let empty = crate::runner_preflight::CaseRunnerConfigEnvelope {
            case_id: crate::runner_preflight::GTO_CASE_ID.to_string(),
            family_id: String::new(),
            protected_input: crate::runner_preflight::FileIdentityGate {
                sha256: fake_sha(0x40),
                size_bytes: 64,
            },
            protected_input_path: None,
            runner_config: serde_json::to_value(&gto_config).unwrap(),
            runner_config_digest: mida_core::runner_config::runner_config_digest(&gto_config),
        };
        let empty_env = crate::runner_preflight::RunnerConfigEnvelope::build(
            vec![origin, lunlun, empty],
            "CLI",
            "REV",
            "verifier",
            "VSHA",
        );
        assert!(
            empty_env.validate_case_set().is_some(),
            "missing family must be rejected"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// R3-7: Oreans regression is unchanged — FIXED_CASE_IDS still exactly the
    /// two Oreans cases, the Oreans gate schema is still mida.oreans-*, and the
    /// GTO snapshot lane never enters the Oreans gate.
    #[test]
    fn oreans_regression_is_unchanged() {
        use mida_core::runner_config::packer_family;

        // FIXED_CASE_IDS is still exactly the two Oreans cases.
        assert_eq!(
            crate::runner_preflight::FIXED_CASE_IDS,
            ["origin_macro", "lunlun_software"]
        );
        // Oreans gate schema is still mida.oreans-*; GTO gate is no-gate.
        assert_eq!(
            crate::run_spec::gate_schema_for_family(packer_family::OREANS),
            "mida.oreans-two-sample-gate/v8"
        );
        assert_eq!(
            crate::run_spec::gate_schema_for_family(packer_family::AHK_GTO),
            crate::run_spec::UNPACK_GATE_ABSENT
        );
        // Oreans is a fixed (non-generic) family; GTO is generic — distinct lanes.
        assert!(packer_family::is_oreans_family(packer_family::OREANS));
        assert!(!packer_family::is_generic_family(packer_family::OREANS));
        assert!(packer_family::is_generic_family(packer_family::AHK_GTO));
        // GTO is not in FIXED_CASE_IDS.
        assert!(!crate::runner_preflight::FIXED_CASE_IDS
            .contains(&crate::runner_preflight::GTO_CASE_ID));
        // Oreans frozen config digest is stable and distinct from GTO's.
        let oreans_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::OREANS);
        let gto_cfg = crate::run_spec::frozen_runner_config_for_family(packer_family::AHK_GTO);
        assert_eq!(oreans_cfg.packer_family, packer_family::OREANS);
        assert_eq!(gto_cfg.packer_family, packer_family::AHK_GTO);
        assert_ne!(
            mida_core::runner_config::runner_config_digest(&oreans_cfg),
            mida_core::runner_config::runner_config_digest(&gto_cfg)
        );
    }

    /// A unique temp root per test (parallel-safe).
    fn temp_root(tag: &str) -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("mida_g3r3_{tag}_{}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// G3-R5-R1-R1-R1: a CUSTOM snapshot root (outside the default
    /// `<output_dir>/sample-snapshots`) is honored by staging — the staged GTO
    /// immutable snapshot path is under the custom root, never the default.
    #[test]
    fn custom_snapshot_root_is_used_for_staging() {
        let root = temp_root("custom_root_staging");
        let src = root.join("launcher.bin");
        let src_bytes = b"CUSTOM-ROOT-PROTECTED-INPUT";
        std::fs::write(&src, src_bytes).unwrap();
        let want_sha = crate::sample_snapshot::sha256_hex(src_bytes);
        let want_size = src_bytes.len() as u64;
        let manifest = write_gto_manifest(&root.join("gto_launcher.json"), &want_sha, want_size);
        // The custom root is OUTSIDE the default output-dir/sample-snapshots.
        let custom_root = root.join("custom_durable_store");
        let cases = full_cases(root.as_path(), &manifest, &src, 0x11, 0x22);

        let prepared = prepare_offline_preflight_staging(
            &custom_root,
            &cases,
            "CLI-SHA",
            "rev",
            "verifier",
            "VSHA",
            &mut *real_capture(),
            &mut *noop_after(),
        )
        .unwrap();
        // The GTO staged protected input must be under the CUSTOM root.
        let gto_staged = &prepared.cases[2].1;
        assert!(
            gto_staged.starts_with(&custom_root),
            "GTO staged input must be under the custom root, got {}",
            gto_staged.display()
        );
        assert!(
            !gto_staged.starts_with(snapshot_root(root.as_path())),
            "GTO staged input must NOT be under the default output-dir/sample-snapshots"
        );
        // The Oreans staged inputs remain their caller sources (not snapshotted).
        assert!(!prepared.cases[0].1.starts_with(&custom_root));
        let _ = std::fs::remove_dir_all(&root);
    }
}
