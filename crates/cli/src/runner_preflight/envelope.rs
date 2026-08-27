//! Runner-config envelope producer (WO-19 split from runner_preflight).

use super::*;
pub fn frozen_runner_config() -> mida_core::runner_config::RunnerConfig {
    crate::run_spec::frozen_runner_config()
}

/// One case-bound runner config entry inside the v4 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseRunnerConfigEnvelope {
    /// The fixed case id (`origin_macro` or `lunlun_software`).
    pub case_id: String,
    /// The packer family this case's run belongs to. This is bound at STAGING
    /// time from the case manifest's `protection_family` and is part of the
    /// sealed case-set digest, so the attestation always builds the actual /
    /// frozen policy against the SAME family the envelope was staged for. A
    /// case can never switch family after staging (that would change the
    /// sealed digest and be refused).
    pub family_id: String,
    /// Verified protected-input identity of this case.
    pub protected_input: FileIdentityGate,
    /// Optional trusted protected-input PATH (G3-R3-R1). The immutable GTO lane
    /// seals the exact `snapshot.bin` path under its snapshot_root so the launch
    /// attestation can require identity AND path double-binding — a live source
    /// with identical bytes/hash is still refused. Oreans fixed cases keep their
    /// live-input semantics and leave this `None` (no path binding). `default`
    /// keeps old-schema envelopes readable (family-agnostic, non-breaking).
    #[serde(default)]
    pub protected_input_path: Option<String>,
    /// Full runner config JSON, as the runner will apply it for this case.
    pub runner_config: serde_json::Value,
    /// Producer-computed per-case digest
    /// (`mida_core::runner_config::runner_config_digest`).
    pub runner_config_digest: String,
}

/// Select the unique envelope case whose protected input identity matches the
/// actual config's context — but the caller must supply the protected input
/// identity to bind against (the config itself carries no identity). This is
/// the launch-side per-case binding (P6.3.3): the ACTUAL config digest is
/// compared against EXACTLY ONE case digest. The input is matched separately
/// in [`attest_ready_before_launch`]; here we select by `input_identity` and
/// reject 0 or 2+ matches.
///
/// Returns the matched [`CaseRunnerConfigEnvelope`].
pub fn select_case_config<'a>(
    envelope: &'a RunnerConfigEnvelope,
    input_identity: &FileIdentityGate,
) -> anyhow::Result<&'a CaseRunnerConfigEnvelope> {
    let mut matches: Vec<&CaseRunnerConfigEnvelope> = envelope
        .case_configs
        .iter()
        .filter(|c| c.protected_input == *input_identity)
        .collect();
    if matches.len() != 1 {
        bail!(
            "protected input matches {} case configs (expected exactly one); \
             cross-case or third-input selection is refused",
            matches.len()
        );
    }
    Ok(matches.remove(0))
}

/// Launch-side equality check (P6.3-A/P6.3.3): the digest of the ACTUAL run
/// configuration — built from the parsed `/unpack` arguments, with the
/// resolved pure-rebuild value — must equal the digest of the UNIQUE case
/// the current input belongs to. A case config staged with
/// `pure_rebuild=false` can never bind a run that silently resolves to
/// `true` (or any other parameter divergence); the actual config is never
/// compared against another case's digest.
pub fn bind_actual_config_to_envelope(
    output_dir: &Path,
    actual_config: &mida_core::runner_config::RunnerConfig,
    input_identity: &FileIdentityGate,
) -> anyhow::Result<()> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    let case = select_case_config(&envelope, input_identity)?;
    // G2-R1: the packer family is bound at staging and cannot change. The
    // actual config's family must match the envelope case's family EXACTLY
    // (not just by digest) — this is what makes a digest forged under one
    // family unusable for another: the family is compared field-by-field
    // before the digest check, and the digest also embeds the family.
    if actual_config.packer_family != case.family_id {
        bail!(
            "actual run config family {:?} != envelope case {} family {:?} (fail-closed)",
            actual_config.packer_family,
            case.case_id,
            case.family_id
        );
    }
    let actual_digest = mida_core::runner_config::runner_config_digest(actual_config);
    if !actual_digest.eq_ignore_ascii_case(&case.runner_config_digest) {
        bail!(
            "actual run config digest {actual_digest} != envelope case {} digest {}",
            case.case_id,
            case.runner_config_digest
        );
    }
    Ok(())
}

/// The `mida.runner-config-envelope/v4` emitted by the runner side.
///
/// `deny_unknown_fields` + required fields: a tampered envelope (unknown
/// field, missing field) fails closed at deserialization.
///
/// P6.3.3: configuration is case-bound. There is no ambiguous top-level
/// `runner_config`/`runner_config_digest`; instead `case_configs` holds
/// exactly the two fixed cases, each with its own full config and digest,
/// and `case_set_digest` seals every case config and its case/input binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfigEnvelope {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub schema_version: String,
    /// SHA-256 of the CLI binary that will perform the run.
    pub cli_binary_sha256: String,
    /// Tool revision (git HEAD) the run is pinned to.
    pub tool_revision: String,
    /// Controlled relative identity of the verifier (always the CLI
    /// sibling; see [`VERIFIER_SOURCE_TOKEN`]).
    pub verifier_source: String,
    /// Canonical path of the verifier sibling at staging (P6.3.2): the
    /// launch re-resolves the sibling and compares BOTH path and hash.
    pub verifier_path: String,
    /// SHA-256 of the independent acceptance verifier binary pinned at
    /// staging: the launch and PE-evidence paths fail closed unless the
    /// verifier they resolve hashes to exactly this.
    pub verifier_sha256: String,
    /// Sealed hash over every case config + its case/input binding. Any
    /// single-case tamper changes this and the independent verifier refuses
    /// the whole envelope.
    pub case_set_digest: String,
    /// Exactly the two fixed Oreans cases, each with its own config/digest.
    pub case_configs: Vec<CaseRunnerConfigEnvelope>,
}

/// Canonical, injective encoding of one case-bound config entry (case id,
/// packer family, protected input identity + optional path, per-case
/// runner-config digest). The family and the optional protected-input path are
/// part of the sealed case-set digest, so switching a case's family OR its
/// trusted protected-input path after staging is a tamper that breaks the seal.
pub(crate) fn canonical_case_entry(entry: &CaseRunnerConfigEnvelope) -> String {
    let path = match &entry.protected_input_path {
        Some(p) => p.to_lowercase(),
        None => String::new(),
    };
    format!(
        "case={}\nfamily={}\nprotected_input={}|{}\nprotected_input_path={}\nrunner_config_digest={}\n",
        entry.case_id,
        entry.family_id.to_lowercase(),
        entry.protected_input.sha256.to_lowercase(),
        entry.protected_input.size_bytes,
        path,
        entry.runner_config_digest.to_lowercase()
    )
}

/// SHA-256 (lowercase hex) of the canonical case-set encoding (P6.3.3).
pub(crate) fn case_set_digest(case_configs: &[CaseRunnerConfigEnvelope]) -> String {
    let mut entries: Vec<String> = case_configs.iter().map(canonical_case_entry).collect();
    entries.sort();
    let mut canonical = String::new();
    for e in entries {
        canonical.push_str(&e);
    }
    sha256_hex(canonical.as_bytes())
}

impl RunnerConfigEnvelope {
    /// Build the envelope from one per-case config per input, plus runtime
    /// pinning inputs. `case_configs` must contain exactly the two fixed
    /// cases (validated by the caller/`build_checked`).
    pub fn build(
        case_configs: Vec<CaseRunnerConfigEnvelope>,
        cli_binary_sha256: &str,
        tool_revision: &str,
        verifier_path: &str,
        verifier_sha256: &str,
    ) -> RunnerConfigEnvelope {
        let case_set_digest = case_set_digest(&case_configs);
        RunnerConfigEnvelope {
            schema: RUNNER_CONFIG_ENVELOPE_SCHEMA_REF.to_string(),
            schema_version: RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION.to_string(),
            cli_binary_sha256: cli_binary_sha256.to_lowercase(),
            tool_revision: tool_revision.to_string(),
            verifier_source: VERIFIER_SOURCE_TOKEN.to_string(),
            verifier_path: verifier_path.to_string(),
            verifier_sha256: verifier_sha256.to_lowercase(),
            case_set_digest,
            case_configs,
        }
    }

    /// Atomically write the envelope under `output_dir`.
    pub fn write(&self, output_dir: &Path) -> anyhow::Result<PathBuf> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| anyhow!("serialize runner-config envelope: {e}"))?;
        let destination = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
        atomic_write(&destination, &json)
            .with_context(|| format!("write envelope {}", destination.display()))?;
        Ok(destination)
    }

    /// Read + strictly parse the envelope under `output_dir`.
    pub fn read(output_dir: &Path) -> anyhow::Result<RunnerConfigEnvelope> {
        let path = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
        let bytes =
            std::fs::read(&path).with_context(|| format!("read envelope {}", path.display()))?;
        serde_json::from_slice(&bytes).map_err(|e| {
            anyhow!(
                "envelope {} rejected (unknown/malformed fields): {e}",
                path.display()
            )
        })
    }

    /// The sealed case-set digest (the whole-envelope identity, P6.3.3).
    pub fn case_set(&self) -> &str {
        &self.case_set_digest
    }

    /// Validate the case-config set shape. Two lanes are recognized:
    ///
    /// - the Oreans fixed regression lane — `FIXED_CASE_IDS` (`origin_macro`,
    ///   `lunlun_software`) must each appear exactly once with `oreans_themida`
    ///   family, keeping the v4/v8 regression gate invariant;
    /// - the GTO generic/no-gate lane — an optional `gto_launcher` case with
    ///   `family_id = ahk_gto`.
    ///
    /// No unknown case, unknown family, missing family, or cross-lane family
    /// reuse is allowed. Returns the first reason or `None` when valid.
    pub fn validate_case_set(&self) -> Option<String> {
        use mida_core::runner_config::packer_family;
        let present: Vec<&str> = self
            .case_configs
            .iter()
            .map(|c| c.case_id.as_str())
            .collect();
        // No duplicates, no unknown case ids.
        for c in &self.case_configs {
            if !FIXED_CASE_IDS.contains(&c.case_id.as_str()) && c.case_id != GTO_CASE_ID {
                return Some(format!(
                    "case {:?} is neither an Oreans fixed case nor the GTO lane case (fail-closed)",
                    c.case_id
                ));
            }
            if present.iter().filter(|p| **p == c.case_id).count() != 1 {
                return Some(format!(
                    "case {} appears more than once (fail-closed)",
                    c.case_id
                ));
            }
        }
        // Oreans fixed regression lane: both cases must be present exactly once.
        for id in FIXED_CASE_IDS {
            if present.iter().filter(|p| **p == id).count() != 1 {
                return Some(format!(
                    "Oreans fixed lane must contain exactly one {id} entry, got {:?}",
                    present
                ));
            }
        }
        // Per-case family / digest / identity shape.
        for c in &self.case_configs {
            if c.family_id.trim().is_empty() {
                return Some(format!(
                    "case {} family_id is missing or empty (fail-closed)",
                    c.case_id
                ));
            }
            if !packer_family::is_known_family(&c.family_id) {
                return Some(format!(
                    "case {} has unknown packer family {:?} (fail-closed)",
                    c.case_id, c.family_id
                ));
            }
            // G3-R3-R2 lane/path schema: the GTO lane MUST seal a non-empty
            // immutable protected-input path; Oreans fixed cases MUST carry None
            // (live-input lane — injecting a path is a tamper that fails closed).
            if c.case_id == GTO_CASE_ID {
                match c.protected_input_path.as_deref() {
                    Some(p) if !p.trim().is_empty() => {}
                    _ => {
                        return Some(format!(
                            "GTO lane case {} must carry a non-empty protected_input_path \
                             (immutable snapshot) (fail-closed)",
                            c.case_id
                        ));
                    }
                }
            } else if FIXED_CASE_IDS.contains(&c.case_id.as_str())
                && c.protected_input_path.is_some()
            {
                return Some(format!(
                    "Oreans fixed case {} must NOT carry a protected_input_path \
                         (live-input lane) (fail-closed)",
                    c.case_id
                ));
            }
            // Lane <-> family binding: an Oreans fixed case must be Oreans; the
            // GTO lane case must be ahk_gto. Cross-lane reuse fails closed.
            if FIXED_CASE_IDS.contains(&c.case_id.as_str()) {
                if !packer_family::is_oreans_family(&c.family_id) {
                    return Some(format!(
                        "Oreans fixed case {} must carry family {:?}, got {:?} (fail-closed)",
                        c.case_id,
                        packer_family::OREANS,
                        c.family_id
                    ));
                }
            } else if c.case_id == GTO_CASE_ID && !packer_family::is_generic_family(&c.family_id) {
                return Some(format!(
                    "GTO lane case {} must carry a registered generic family (ahk_gto), \
                     got {:?} (fail-closed)",
                    c.case_id, c.family_id
                ));
            }
            if !is_64_hex(&c.runner_config_digest) {
                return Some(format!(
                    "case {} runner_config_digest must be exactly 64 hex chars",
                    c.case_id
                ));
            }
            if !is_64_hex(&c.protected_input.sha256) || c.protected_input.size_bytes == 0 {
                return Some(format!(
                    "case {} protected_input identity is malformed",
                    c.case_id
                ));
            }
        }
        None
    }
}
