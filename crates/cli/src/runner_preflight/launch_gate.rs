//! Launch-boundary attestation gate (WO-19 split from runner_preflight).

use super::*;
pub struct LaunchAttestationContext<'a> {
    /// Current protected input the run would start.
    pub input: &'a Path,
    /// Current candidate output the run would produce.
    pub output: &'a Path,
    /// Current CLI executable (the binary that will run).
    pub cli_binary: &'a Path,
    /// The ACTUAL runner config built from the parsed `/unpack` arguments.
    pub runner_config: &'a mida_core::runner_config::RunnerConfig,
    /// The TRUSTED immutable-snapshot root for this launch, provided by the
    /// caller (the same root used at staging). It is NOT derived from the sealed
    /// protected_input_path; it is cross-checked against the sealed path's root
    /// so a staging/launch root mismatch fails closed.
    pub snapshot_root: &'a Path,
}

/// The unique evidence context produced by a successful launch attestation
/// (P6.3-B/D). All subsequent sidecar and bundle producers consume it; the
/// bundle assembler draws the runner-config digest from it, so the digest
/// can never be caller-supplied.
///
/// P6.3.1 seal: the type is NOT `Clone`, every field is private (read-only
/// getters only), and there is no public constructor — a value can only be
/// obtained from [`attest_ready_before_launch`]. The bundle assembler and
/// [`complete_run_evidence`] take it BY VALUE, so a single attestation can
/// authorize exactly one bundle: a second use is a compile error (there is
/// no way to duplicate or reconstruct the value).
/// IMP-09-CARRIER-R3: sealed verified TARGET-SAMPLE identity.
///
/// Produced ONLY by `attest_ready_before_launch` after the full
/// preflight + independent-verifier re-run chain passes (the input
/// identity is re-computed from disk, matched exactly once against the
/// preflight case, and re-confirmed by the fresh report). Private
/// fields; NOT Serialize/Deserialize — there is no disk/JSON form that
/// can forge this carrier. Distinct from the runtime DLL identity
/// (runtime_module_sha256) by construction: this is the protected input
/// (sample) identity from the attested preflight case.
#[derive(Debug, Clone)]
pub struct VerifiedTargetIdentity {
    case_id: String,
    sha256: String,
    size_bytes: u64,
    architecture: String,
}

impl VerifiedTargetIdentity {
    /// Sealed constructor — reachable only from crate-internal attested
    /// code (the attestation) and crate unit tests. Rejects malformed
    /// input: sha256 must be canonical 64-lowercase-hex, size non-zero,
    /// case_id and architecture non-empty.
    pub(crate) fn from_attested(
        case_id: &str,
        gate: &FileIdentityGate,
        architecture: &str,
    ) -> Result<Self, String> {
        if case_id.trim().is_empty() {
            return Err("VerifiedTargetIdentity case_id must be non-empty".to_string());
        }
        let sha = crate::sample_snapshot::canonical_hash(&gate.sha256);
        crate::sample_snapshot::validate_hash(&sha)
            .map_err(|e| format!("VerifiedTargetIdentity sha256 invalid: {e}"))?;
        if gate.size_bytes == 0 {
            return Err("VerifiedTargetIdentity size_bytes must be non-zero".to_string());
        }
        if architecture.trim().is_empty() {
            return Err("VerifiedTargetIdentity architecture must be non-empty".to_string());
        }
        Ok(Self {
            case_id: case_id.to_string(),
            sha256: sha,
            size_bytes: gate.size_bytes,
            architecture: architecture.to_string(),
        })
    }

    /// Attested case id (e.g. `origin_macro`).
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// Verified target sample SHA-256 (64 lowercase hex).
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Verified target sample size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Verified target architecture (e.g. `x86_64`).
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
}

/// IMP-09-PROFILE-SOURCE-R1: sealed verified PROFILE identity.
///
/// Produced ONLY by `attest_ready_before_launch` from the verified
/// `mida_antidebug::profile::Profile` object bound to the attested case:
/// the profile's `profile_id` and the SHA-256 of its canonical JSON bytes
/// come from the SAME source object (never two different sources, never a
/// bare string). Fields are private; the type is Debug+Clone only — NOT
/// Serialize/Deserialize — so there is no disk/JSON form that can forge
/// this carrier. The FNV-1a `Profile::profile_digest()` placeholder is
/// deliberately NOT used here: this carrier's digest is
/// SHA-256(canonical_json_bytes), 64 lowercase hex, computed by the
/// attestation from the verified profile object.
#[derive(Debug, Clone)]
pub struct VerifiedProfileIdentity {
    profile_id: String,
    profile_digest: String,
    sample_id: String,
    architecture: String,
}

impl VerifiedProfileIdentity {
    /// Sealed constructor — reachable only from crate-internal attested
    /// code (the attestation) and crate unit tests. Rejects: profile
    /// schema mismatch, sample/case mismatch, architecture mismatch,
    /// non-canonical digest (must be 64 lowercase hex), empty fields.
    /// The digest is recomputed here as SHA-256 of the profile's canonical
    /// JSON bytes; the FNV-1a `Profile::profile_digest()` is never used.
    pub(crate) fn from_verified_profile(
        profile: &mida_antidebug::profile::Profile,
        case_id: &str,
        architecture: &str,
    ) -> Result<Self, String> {
        if profile.schema != "mida.antidebug-profile/v1" {
            return Err(format!(
                "VerifiedProfileIdentity schema mismatch: {:?} != mida.antidebug-profile/v1",
                profile.schema
            ));
        }
        if profile.sample_id != case_id {
            return Err(format!(
                "VerifiedProfileIdentity sample/case mismatch: profile sample {:?} != case {:?}",
                profile.sample_id, case_id
            ));
        }
        if profile.architecture != architecture {
            return Err(format!(
                "VerifiedProfileIdentity architecture mismatch: profile {:?} != target {:?}",
                profile.architecture, architecture
            ));
        }
        if profile.profile_id.trim().is_empty() {
            return Err("VerifiedProfileIdentity profile_id must be non-empty".to_string());
        }
        // IMP-09-PROFILE-SOURCE-R1: SHA-256 of the canonical profile bytes
        // (canonical_json is deterministic — hostile test proves byte-level
        // stability). The FNV-1a Profile::profile_digest() is NOT the
        // carrier digest.
        let digest = sha256_hex(profile.canonical_json().as_bytes());
        if !is_64_lower_hex(&digest) {
            return Err(format!(
                "VerifiedProfileIdentity digest must be 64 lowercase hex, got {digest:?}"
            ));
        }
        Ok(Self {
            profile_id: profile.profile_id.clone(),
            profile_digest: digest,
            sample_id: profile.sample_id.clone(),
            architecture: profile.architecture.clone(),
        })
    }

    /// The verified profile id (from the profile object, never a bare string).
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// SHA-256 of the canonical profile bytes (64 lowercase hex).
    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    /// The profile-bound sample id (== attested case id).
    pub fn sample_id(&self) -> &str {
        &self.sample_id
    }

    /// The profile-bound architecture (== attested target architecture).
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
}

/// IMP-09-PROFILE-SOURCE-R1: case -> verified profile object binding.
///
/// The ONLY production profile selection: the attested case id selects the
/// ADR-2 profile object (origin_macro -> origin profile, lunlun_software ->
/// lunlun profile). The GTO lane case has NO profile object today — None
/// means the profile carrier is absent and the controller/loader fail
/// closed (no substitution, no bare-string identity).
pub(crate) fn profile_for_case(case_id: &str) -> Option<mida_antidebug::profile::Profile> {
    use mida_antidebug::profile::{lunlun_profile, origin_profile, SAMPLE_LUNLUN, SAMPLE_ORIGIN};
    match case_id {
        SAMPLE_ORIGIN => Some(origin_profile()),
        SAMPLE_LUNLUN => Some(lunlun_profile()),
        _ => None,
    }
}

/// True when `value` is exactly 64 chars and all lowercase hex.
/// Strict canonical SHA-256 lowercase-hex contract: exactly 64 chars,
/// each in `[0-9a-f]`. Any other lowercase letter (`g-z`), uppercase
/// letter, non-hex digit, or wrong length is rejected.
pub(crate) fn is_64_lower_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

#[derive(Debug)]
/// The run context the launch boundary attests against.
pub struct RunEvidenceContext {
    case_id: String,
    tool_revision: String,
    runner_config_digest: String,
    verifier_sha256: String,
    protected_input: PathBuf,
    candidate: PathBuf,
    cli_binary_sha256: String,
    /// Packer family this run belongs to (`oreans_themida` or `ahk_gto`).
    /// Drives the evidence-contract family dispatch.
    packer_family: String,
    /// IMP-09-CARRIER-R3: sealed verified target-sample identity (private,
    /// non-deserializable). Bound by the attestation only.
    target_identity: VerifiedTargetIdentity,
    /// IMP-09-PROFILE-SOURCE-R1: sealed verified PROFILE identity (private,
    /// non-deserializable, Debug+Clone only). Bound by the attestation from
    /// the verified profile object for the attested case; None for cases
    /// with no profile object (GTO lane) — the controller/loader then fail
    /// closed. Same-source guarantee: profile_id and the SHA-256 digest
    /// both come from this one sealed object.
    profile_identity: Option<VerifiedProfileIdentity>,
}

impl RunEvidenceContext {
    /// Internal constructor — reachable only from crate-internal code (the
    /// attestation) and crate unit tests. Never a public forgery entry.
    ///
    /// Oreans-compat wrapper: binds the Oreans family, matching the pre-G2
    /// behaviour. Kept so the family-less legacy API and its tests remain
    /// valid; G2 attestation uses [`RunEvidenceContext::new_with_family`].
    #[allow(dead_code)] // legacy family-less wrapper; used by Oreans tests.
    pub(crate) fn new(
        case_id: String,
        tool_revision: String,
        runner_config_digest: String,
        verifier_sha256: String,
        protected_input: PathBuf,
        candidate: PathBuf,
        cli_binary_sha256: String,
        target_identity: VerifiedTargetIdentity,
        profile_identity: Option<VerifiedProfileIdentity>,
    ) -> anyhow::Result<RunEvidenceContext> {
        Self::new_with_family(
            mida_core::runner_config::packer_family::OREANS.to_string(),
            case_id,
            tool_revision,
            runner_config_digest,
            verifier_sha256,
            protected_input,
            candidate,
            cli_binary_sha256,
            target_identity,
            profile_identity,
        )
    }

    /// Internal constructor that additionally binds the packer family. The
    /// family-less [`RunEvidenceContext::new`] is preserved as an Oreans-compat
    /// wrapper. GTO runs bind `ahk_gto` explicitly so their generic evidence
    /// contract is selected.
    pub(crate) fn new_with_family(
        packer_family: String,
        case_id: String,
        tool_revision: String,
        runner_config_digest: String,
        verifier_sha256: String,
        protected_input: PathBuf,
        candidate: PathBuf,
        cli_binary_sha256: String,
        target_identity: VerifiedTargetIdentity,
        profile_identity: Option<VerifiedProfileIdentity>,
    ) -> anyhow::Result<RunEvidenceContext> {
        if packer_family.trim().is_empty() {
            bail!("RunEvidenceContext packer_family must be non-empty");
        }
        if case_id.trim().is_empty() {
            bail!("RunEvidenceContext case_id must be non-empty");
        }
        if !is_64_hex(&runner_config_digest) {
            bail!(
                "RunEvidenceContext runner_config_digest must be exactly 64 hex chars, got {:?}",
                runner_config_digest
            );
        }
        if !is_64_hex(&cli_binary_sha256) {
            bail!("RunEvidenceContext cli_binary_sha256 must be exactly 64 hex chars");
        }
        if !is_64_hex(&verifier_sha256) {
            bail!("RunEvidenceContext verifier_sha256 must be exactly 64 hex chars");
        }
        Ok(RunEvidenceContext {
            case_id,
            tool_revision,
            runner_config_digest: runner_config_digest.to_lowercase(),
            verifier_sha256: verifier_sha256.to_lowercase(),
            protected_input,
            candidate,
            cli_binary_sha256: cli_binary_sha256.to_lowercase(),
            packer_family,
            target_identity,
            profile_identity,
        })
    }

    /// The attested packer family (Oreans-compat default when unbound).
    pub fn packer_family(&self) -> &str {
        &self.packer_family
    }

    /// IMP-09-CARRIER-R3: the sealed verified target identity.
    pub fn target_identity(&self) -> &VerifiedTargetIdentity {
        &self.target_identity
    }

    /// IMP-09-PROFILE-SOURCE-R1: the sealed verified profile identity
    /// (None when the attested case has no profile object — fail-closed).
    pub fn profile_identity(&self) -> Option<&VerifiedProfileIdentity> {
        self.profile_identity.as_ref()
    }

    /// The attested case id.
    pub fn case_id(&self) -> &str {
        &self.case_id
    }

    /// The tool revision the run is pinned to.
    pub fn tool_revision(&self) -> &str {
        &self.tool_revision
    }

    /// The attestation-bound runner-config digest (the only digest source
    /// for sidecar/bundle producers).
    pub fn runner_config_digest(&self) -> &str {
        &self.runner_config_digest
    }

    /// The verifier binary identity the attestation bound.
    pub fn verifier_sha256(&self) -> &str {
        &self.verifier_sha256
    }

    /// Canonical protected input path (read-only).
    pub fn protected_input(&self) -> &Path {
        &self.protected_input
    }

    /// Canonical candidate output path (read-only).
    pub fn candidate(&self) -> &Path {
        &self.candidate
    }

    /// The current CLI binary identity (read-only).
    pub fn cli_binary_sha256(&self) -> &str {
        &self.cli_binary_sha256
    }
}

pub(crate) fn is_64_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Recompute `{sha256, size_bytes}` of a file on disk.
pub fn file_identity(path: &Path) -> anyhow::Result<FileIdentityGate> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let sha = sha256_hex(&data);
    Ok(FileIdentityGate {
        sha256: sha,
        size_bytes: data.len() as u64,
    })
}

/// IMP-09-CARRIER-R3: single-read verified file identity + architecture.
///
/// One read of the protected input returns the identity gate AND the PE
/// architecture parsed from the SAME bytes, so the attested target
/// identity is bound to exactly the bytes that were hash-verified (no
/// second-read TOCTOU for the architecture field).
pub(crate) fn file_identity_with_architecture(
    path: &Path,
) -> anyhow::Result<(FileIdentityGate, String)> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let sha = sha256_hex(&data);
    let architecture = pe_architecture_of(&data);
    Ok((
        FileIdentityGate {
            sha256: sha,
            size_bytes: data.len() as u64,
        },
        architecture,
    ))
}

/// PE architecture label for the given bytes ("x86_64" / "x86" /
/// "unknown"). Non-PE bytes still yield an identity (hash/size are
/// authoritative); architecture is best-effort evidence metadata.
fn pe_architecture_of(bytes: &[u8]) -> String {
    use mida_pe::PeHeader;
    match PeHeader::from_bytes(bytes) {
        Ok(h) => {
            let magic = h.nt_headers.optional_header.magic;
            if magic == 0x20b {
                "x86_64".to_string()
            } else if magic == 0x10b {
                "x86".to_string()
            } else {
                "unknown".to_string()
            }
        }
        Err(_) => "unknown".to_string(),
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Canonicalize `p`, falling back to canonicalizing its parent when the
/// path itself does not exist yet (e.g. a candidate output file).
pub fn canonicalize_loose(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    match (
        p.parent()
            .and_then(|parent| std::fs::canonicalize(parent).ok()),
        p.file_name(),
    ) {
        (Some(parent), Some(name)) => parent.join(name),
        _ => p.to_path_buf(),
    }
}

/// Derive the controlled snapshot_root and the 64-hex hash directory from a GTO
/// immutable snapshot path of the exact shape
/// `<root>/<case_id>/<sha256>/snapshot.bin`. Returns `(snapshot_root, hash_dir)`.
///
/// This delegates to the shared `sample_snapshot::parse_snapshot_path` contract
/// (absolute, no `.`/`..`, exact filename, 64-lowercase-hex hash directory) and
/// then requires the logical-sample directory to be the GTO lane case id. It
/// rejects malformed, non-canonical, relative, `..`/`.`-containing, or otherwise
/// non-snapshot paths so a caller cannot smuggle a path outside the snapshot
/// store.
pub(crate) fn snapshot_root_of_snapshot(snapshot_path: &Path) -> anyhow::Result<(PathBuf, String)> {
    let parsed = crate::sample_snapshot::parse_snapshot_path(snapshot_path).map_err(|e| {
        anyhow::anyhow!(
            "GTO protected input {} invalid: {e}",
            snapshot_path.display()
        )
    })?;
    if parsed.logical_sample_id != GTO_CASE_ID {
        bail!(
            "GTO snapshot case directory {:?} != {GTO_CASE_ID}",
            parsed.logical_sample_id
        );
    }
    Ok((parsed.snapshot_root, parsed.sha256))
}

/// G3-R3-R1 GTO launch path binding. For the GTO lane the launch attestation
/// requires the protected input to be the EXACT immutable snapshot path sealed
/// into the envelope at staging (and recorded by the report), located under a
/// well-formed snapshot_root. A live dynamic source is refused even when its
/// bytes/hash equal the snapshot's — identity is bound together with the trusted
/// path.
pub(crate) fn enforce_gto_snapshot_path_binding(
    envelope: &RunnerConfigEnvelope,
    matched: &PreflightCaseGate,
    current_identity: &FileIdentityGate,
    ctx: &LaunchAttestationContext<'_>,
    trusted_snapshot_root: &Path,
) -> anyhow::Result<()> {
    // 1. The envelope's sealed GTO case must carry a protected_input_path.
    let env_case = select_case_config(envelope, current_identity)?;
    let sealed_path = env_case.protected_input_path.as_deref().ok_or_else(|| {
        anyhow!(
            "GTO case {GTO_CASE_ID} envelope has no sealed protected_input_path; \
                 refusing to launch without a path binding"
        )
    })?;

    // 2. Validate the RAW sealed_path lexically/shape-wise BEFORE any
    //    canonicalization (G3-R3-R2-R1): it must be absolute, free of `.`/`..`,
    //    of the exact shape `<root>/gto_launcher/<sha256>/snapshot.bin`, and its
    //    content-address hash directory must equal the sealed protected-input
    //    hash. A raw `..`/relative path is refused even if it would later
    //    canonicalize to the same snapshot.
    let (_, sealed_hash_dir) = snapshot_root_of_snapshot(Path::new(sealed_path))?;
    if !sealed_hash_dir.eq_ignore_ascii_case(&current_identity.sha256) {
        bail!(
            "GTO snapshot path hash dir {sealed_hash_dir:?} != protected_input sha {} \
             (content-address path/identity mismatch; fail-closed)",
            current_identity.sha256.to_lowercase()
        );
    }

    // 3. The report's recorded protected_input_path must equal the sealed path
    //    (canonical form), so a tampered report path is caught.
    if canonicalize_loose(Path::new(&matched.protected_input_path))
        != canonicalize_loose(Path::new(sealed_path))
    {
        bail!(
            "GTO report protected_input_path {} != sealed envelope path {} \
             (path tamper or drift)",
            matched.protected_input_path,
            sealed_path
        );
    }

    // 4. STRICT disk-level canonicalization of the sealed snapshot path and the
    //    launch input, with canonical snapshot_root containment. `canonical_verify_snapshot_path`
    //    strictly canonicalizes (NO loose fallback) and requires the canonical
    //    path to stay under the canonical snapshot_root with the correct
    //    logical/hash layers, so a junction/symlink/reparse escape of the sealed
    //    path's logical/hash/file layer is rejected. The launch input's canonical
    //    form must equal the sealed path's canonical form.
    let sealed_canonical = crate::sample_snapshot::canonical_verify_snapshot_path(
        Path::new(sealed_path),
        trusted_snapshot_root,
        GTO_CASE_ID,
        &current_identity.sha256,
    )
    .map_err(|e| anyhow::anyhow!("GTO sealed snapshot path failed disk verification: {e}"))?;
    let input_canonical = crate::sample_snapshot::canonical_verify_snapshot_path(
        ctx.input,
        trusted_snapshot_root,
        GTO_CASE_ID,
        &current_identity.sha256,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "GTO launch input {} failed disk verification (missing/reparse/escape): {e}",
            ctx.input.display()
        )
    })?;
    if input_canonical.snapshot_path != sealed_canonical.snapshot_path {
        bail!(
            "GTO launch input {} (canonical {}) must be the staged immutable \
             snapshot {} (canonical {}); a live source or alias with identical \
             bytes is still refused (identity+path double binding)",
            ctx.input.display(),
            input_canonical.snapshot_path.display(),
            sealed_path,
            sealed_canonical.snapshot_path.display()
        );
    }
    Ok(())
}

/// Sealed+caller cross-check for the GTO launch trusted root: the caller's
/// trusted snapshot_root must lexically match the root embedded in the sealed
/// protected_input_path (the root that staging used). A mismatch means a
/// staging/launch root divergence and fails closed before any process creation.
/// This is the shared seam that keeps the launch root equal to the staging root
/// without deriving it from the path.
pub(crate) fn verify_gto_sealed_root_matches(
    caller_snapshot_root: &Path,
    sealed_protected_input_path: &str,
) -> anyhow::Result<()> {
    let sealed_root =
        crate::sample_snapshot::parse_snapshot_path(Path::new(sealed_protected_input_path))
            .map_err(|e| {
                anyhow::anyhow!(
                    "sealed GTO path {} invalid: {e}",
                    sealed_protected_input_path
                )
            })?
            .snapshot_root;
    if !crate::sample_snapshot::paths_equivalent(&sealed_root, caller_snapshot_root) {
        anyhow::bail!(
            "GTO launch trusted snapshot_root {} does not match the sealed path root {} \
             (staging/launch root mismatch; fail-closed)",
            caller_snapshot_root.display(),
            sealed_root.display()
        );
    }
    Ok(())
}

/// The P6.3 launch attestation (production). The hand-written `ready` JSON
/// is NOT an authorization credential: the launch boundary re-runs the
/// independent acceptance verifier against the current run context and
/// re-verifies every identity locally.
///
/// Attestation steps:
///
/// 1. Strict envelope read + `$schema` + `schema_version` validation.
/// 2. Actual run-config digest == envelope digest (P6.3-A).
/// 3. Current CLI binary SHA-256 == envelope CLI identity.
/// 4. Pre-read report (strict v2): ready, digest chain, CLI matched.
/// 5. Re-run the acceptance verifier with the report's recorded runner
///    context (repo root / toolchain pin / expected toolchain), the
///    recorded case triples, and the CURRENT input/output for the case
///    whose recorded identity matches the current input.
/// 6. Read the freshly written report; require: ready, digest chain, CLI
///    matched, case set exactly {origin_macro, lunlun_software}, every case
///    identity_ok.
/// 7. Current input identity matches EXACTLY ONE preflight case (no
///    cross-case / third-input reuse).
/// 8. The target case identity is unchanged since the pre-read report
///    (input bytes did not change between staging and launch).
/// 9. Current output canonical path == the target case candidate output.
///
/// Returns the single-use [`RunEvidenceContext`] on success.
pub fn attest_ready_before_launch(
    output_dir: &Path,
    ctx: &LaunchAttestationContext<'_>,
) -> anyhow::Result<RunEvidenceContext> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    if envelope.schema != RUNNER_CONFIG_ENVELOPE_SCHEMA_REF {
        bail!(
            "envelope $schema {:?} != {RUNNER_CONFIG_ENVELOPE_SCHEMA_REF}",
            envelope.schema
        );
    }
    if envelope.schema_version != RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION {
        bail!(
            "envelope schema_version {:?} != {RUNNER_CONFIG_ENVELOPE_SCHEMA_VERSION}",
            envelope.schema_version
        );
    }

    // P6.3-A/P6.3.3: the actual run-config digest must equal the digest of
    // the UNIQUE case the current input belongs to. The input identity is
    // computed first (it drives both the per-case config selection here and
    // the report case matching below).
    let (current_identity, target_architecture) = file_identity_with_architecture(ctx.input)?;
    bind_actual_config_to_envelope(output_dir, ctx.runner_config, &current_identity)?;

    // Current CLI identity (attack: binary A staged, binary B launched).
    let current_cli_sha = sha256_file(ctx.cli_binary)?;
    if !current_cli_sha.eq_ignore_ascii_case(&envelope.cli_binary_sha256) {
        bail!(
            "current CLI binary {current_cli_sha} != envelope pinned {}",
            envelope.cli_binary_sha256
        );
    }

    // Pre-read report: ready chain + the recorded case triples for the
    // verifier re-run.
    let pre_report = read_gate_report(output_dir)?;
    if pre_report.schema_version != PREFLIGHT_REPORT_SCHEMA_VERSION {
        bail!(
            "preflight report schema {:?} != {PREFLIGHT_REPORT_SCHEMA_VERSION}",
            pre_report.schema_version
        );
    }
    check_chain_ready(&pre_report, &envelope)?;

    // The current input must match EXACTLY one preflight case identity.
    let matches: Vec<&PreflightCaseGate> = pre_report
        .cases
        .iter()
        .filter(|c| c.protected_input.as_ref() == Some(&current_identity))
        .collect();
    if matches.len() != 1 {
        bail!(
            "current input matches {} preflight case identities (expected exactly one); \
             cross-case or third-input reuse is refused",
            matches.len()
        );
    }
    let target_case_id = matches[0].case_id.clone();
    // The target must belong to a recognized lane: the Oreans fixed regression
    // lane or the independent GTO generic/no-gate lane.
    if !FIXED_CASE_IDS.contains(&target_case_id.as_str()) && target_case_id != GTO_CASE_ID {
        bail!(
            "target case {:?} is neither an Oreans fixed case nor the GTO lane case",
            target_case_id
        );
    }

    // G3-R3-R1: GTO launch requires identity AND trusted-path double binding.
    // The GTO protected input must be the exact immutable snapshot.bin sealed at
    // staging (under snapshot_root), never a live dynamic source — even one with
    // identical bytes/hash. Oreans fixed cases keep their live-input lane and are
    // not path-bound. The trusted snapshot_root is the CALLER-provided anchor
    // (`ctx.snapshot_root`, the same root used at staging), NOT derived from the
    // sealed path. A sealed+caller cross-check requires the caller root to match
    // the sealed path's lexical root, so a staging/launch root mismatch fails
    // closed.
    if target_case_id == GTO_CASE_ID {
        let trusted_snapshot_root = ctx.snapshot_root;
        // Sealed+caller cross-check: the caller's trusted root must lexically
        // match the root embedded in the sealed protected_input_path.
        verify_gto_sealed_root_matches(trusted_snapshot_root, &matches[0].protected_input_path)?;
        enforce_gto_snapshot_path_binding(
            &envelope,
            matches[0],
            &current_identity,
            ctx,
            trusted_snapshot_root,
        )?;
    }

    // P6.3.1: the verifier identity is bound by the envelope. Resolve the
    // verifier this launch would use and fail closed unless it hashes to the
    // pinned identity (verifier replacement / path drift / hash drift).
    let verifier_sha = verify_verifier_identity(ctx, &envelope)?;

    // Re-run the independent verifier with the recorded context. A
    // hand-written `ready` report is not an authorization credential.
    rerun_verifier(output_dir, &pre_report, &target_case_id, ctx)?;

    // Read the freshly generated report and attest the whole chain.
    let fresh = read_gate_report(output_dir)?;
    if fresh.schema_version != PREFLIGHT_REPORT_SCHEMA_VERSION {
        bail!(
            "preflight report schema {:?} != {PREFLIGHT_REPORT_SCHEMA_VERSION}",
            fresh.schema_version
        );
    }
    check_chain_ready(&fresh, &envelope)?;
    let fresh_target = fresh
        .cases
        .iter()
        .find(|c| c.case_id == target_case_id)
        .ok_or_else(|| anyhow!("fresh report is missing case {target_case_id}"))?;
    if !fresh_target.identity_ok {
        bail!(
            "case {target_case_id} identity did not pass the verifier re-run: {}",
            fresh_target.reasons.join("; ")
        );
    }
    let present_ids: Vec<&str> = fresh.cases.iter().map(|c| c.case_id.as_str()).collect();
    // The fresh report must contain both Oreans fixed cases exactly once
    // (Oreans regression lane invariant), and any GTO lane case exactly once.
    if FIXED_CASE_IDS
        .iter()
        .any(|id| present_ids.iter().filter(|p| *p == id).count() != 1)
        || present_ids.iter().filter(|p| **p == GTO_CASE_ID).count() > 1
        || present_ids
            .iter()
            .any(|id| !FIXED_CASE_IDS.contains(id) && *id != GTO_CASE_ID)
    {
        bail!(
            "fresh report case set must contain exactly the Oreans fixed lane [{}, {}] plus \
             at most the GTO lane case {}, no duplicates/unknown, got {:?}",
            FIXED_CASE_IDS[0],
            FIXED_CASE_IDS[1],
            GTO_CASE_ID,
            present_ids
        );
    }
    for case in &fresh.cases {
        if !case.identity_ok {
            bail!(
                "case {} identity_ok=false after verifier re-run: {}",
                case.case_id,
                case.reasons.join("; ")
            );
        }
    }

    // The target case identity must be unchanged since staging (the input
    // bytes did not change between preflight and launch).
    if fresh_target.protected_input != matches[0].protected_input {
        bail!(
            "case {target_case_id} input identity changed since preflight \
             (staged {:?}, now {:?}); refusing to launch",
            matches[0].protected_input,
            fresh_target.protected_input
        );
    }

    // The current output canonical path must equal the candidate output
    // recorded at PREFLIGHT time (the staged candidate). The fresh report
    // always records the current output by construction, so the staged
    // candidate is the authority.
    let current_output = canonicalize_loose(ctx.output);
    let preflight_candidate = PathBuf::from(&matches[0].candidate_output);
    if current_output != preflight_candidate {
        bail!(
            "current output {} does not match the preflight candidate {}",
            current_output.display(),
            preflight_candidate.display()
        );
    }
    if current_output == canonicalize_loose(ctx.input) {
        bail!(
            "candidate output {} aliases the protected input (same canonical path)",
            current_output.display()
        );
    }

    // Every cross-identity is bound: build the single-use evidence context.
    // P6.3.3: the digest is the SELECTED case's digest (never a shared or
    // another case's digest) — it flows into the bundle for this case.
    // G2-R1: the packer family is the ENVELOPE's bound family for this input
    // (staging-sealed). The actual config's family was already checked equal
    // to it by `bind_actual_config_to_envelope`, so the evidence context is
    // bound to the authoritative envelope family — never a caller-supplied or
    // rebindable one.
    let selected_case = select_case_config(&envelope, &current_identity)?;
    let attested_family = selected_case.family_id.clone();
    let digest = envelope_case_runner_config_digest(output_dir, &current_identity)?;
    // G3-R3-R1: the evidence context's protected input must be the immutable
    // snapshot path for GTO (never a live-source alias — even same bytes), and
    // the live input for Oreans. For GTO the sealed envelope path is the
    // authority and equals ctx.input canonical (already enforced).
    let evidence_input = protected_input_for_evidence(&target_case_id, selected_case, ctx.input);
    // IMP-09-CARRIER-R3: seal the verified target identity. The input
    // identity was re-computed from disk, matched EXACTLY once against
    // the preflight case, and re-confirmed by the fresh report; this is
    // the only construction site (private fields, no Deserialize).
    let sealed_target_identity = VerifiedTargetIdentity::from_attested(
        &target_case_id,
        &current_identity,
        &target_architecture,
    )
    .map_err(|e| anyhow::anyhow!("target identity seal failed: {e}"))?;
    // IMP-09-PROFILE-SOURCE-R1: seal the verified PROFILE identity from the
    // case-bound ADR-2 profile object (profile_id + SHA-256 of canonical
    // profile bytes, SAME source object). Cases with no profile object
    // (GTO lane) carry None — the controller/loader fail closed rather than
    // substitute a bare-string profile identity.
    let sealed_profile_identity = match profile_for_case(&target_case_id) {
        Some(profile) => Some(
            VerifiedProfileIdentity::from_verified_profile(
                &profile,
                &target_case_id,
                &target_architecture,
            )
            .map_err(|e| anyhow::anyhow!("profile identity seal failed: {e}"))?,
        ),
        None => None,
    };
    let context = RunEvidenceContext::new_with_family(
        attested_family,
        target_case_id,
        envelope.tool_revision.clone(),
        digest,
        verifier_sha,
        evidence_input,
        current_output,
        current_cli_sha,
        sealed_target_identity,
        sealed_profile_identity,
    )?;
    Ok(context)
}

/// G3-R3-R1: select the evidence context's protected-input path. The GTO lane
/// must carry the immutable snapshot path sealed in the envelope (never a
/// live-source alias), while Oreans keeps the live input path. If the GTO
/// envelope somehow lacks a sealed path, fall back to `ctx_input` (the
/// path-binding check in `enforce_gto_snapshot_path_binding` already refused
/// that scenario, so this fallback is unreachable in production).
pub(crate) fn protected_input_for_evidence(
    target_case_id: &str,
    selected_case: &CaseRunnerConfigEnvelope,
    ctx_input: &Path,
) -> PathBuf {
    if target_case_id == GTO_CASE_ID {
        match selected_case.protected_input_path.as_deref() {
            Some(p) => canonicalize_loose(Path::new(p)),
            None => canonicalize_loose(ctx_input),
        }
    } else {
        canonicalize_loose(ctx_input)
    }
}

/// Resolve the verifier this run would use (unique CLI-sibling resolver),
/// then fail closed unless its canonical path identity AND SHA-256 both
/// match the envelope-pinned verifier (P6.3.2: path + hash, not hash alone).
pub(crate) fn verify_verifier_identity(
    _ctx: &LaunchAttestationContext<'_>,
    envelope: &RunnerConfigEnvelope,
) -> anyhow::Result<String> {
    // P2: resolve + validate + hash the verifier, binding it to the
    // envelope-pinned identity in one step before the launch proceeds.
    let verifier = resolve_verifier_identity_checked(Some(&envelope.verifier_sha256))?;
    verify_verifier_identity_bindings(envelope, &verifier.path, &verifier.sha256)
}

/// P6.3.3.2: the pure verifier-identity binding check. Given the envelope's
/// pinned verifier identity and the verifier this run would resolve to
/// (canonical path + SHA-256), fail closed unless:
///
/// - the controlled relative source token matches;
/// - the resolved canonical path equals the pinned path;
/// - the resolved SHA-256 equals the pinned SHA-256.
///
/// This is a PUBLIC offline seam shared by the launch attestation
/// ([`verify_verifier_identity`]) and the hermetic tests: the
/// verifier-replacement rejection is proven WITHOUT selecting a real locked
/// case or creating a sample process (P6.3.3.2: the launch attestation only
/// reaches this check after a case is matched by input identity). It is
/// `pub` specifically so the black-box `launch_attestation` integration tests
/// can drive the already-selected-case context offline.
pub fn verify_verifier_identity_bindings(
    envelope: &RunnerConfigEnvelope,
    resolved_path: &Path,
    resolved_sha: &str,
) -> anyhow::Result<String> {
    // Path identity: the resolved sibling must be the recorded path AND the
    // controlled relative source must match.
    if envelope.verifier_source != VERIFIER_SOURCE_TOKEN {
        bail!(
            "envelope verifier_source {:?} != {VERIFIER_SOURCE_TOKEN}; source drift is refused",
            envelope.verifier_source
        );
    }
    let resolved_canonical = std::fs::canonicalize(resolved_path).with_context(|| {
        format!(
            "cannot canonicalize resolved verifier {}",
            resolved_path.display()
        )
    })?;
    let recorded = PathBuf::from(&envelope.verifier_path);
    if resolved_canonical != recorded {
        bail!(
            "acceptance verifier resolves to {} which != the envelope-pinned path {}; \
             verifier path drift is refused",
            resolved_canonical.display(),
            recorded.display()
        );
    }
    if !resolved_sha.eq_ignore_ascii_case(&envelope.verifier_sha256) {
        bail!(
            "acceptance verifier {} (sha {resolved_sha}) does not match the envelope-pinned \
             verifier sha {}; verifier replacement or hash drift is refused",
            resolved_canonical.display(),
            envelope.verifier_sha256
        );
    }
    Ok(resolved_sha.to_lowercase())
}

/// Spawn the independent acceptance verifier with the recorded runner
/// context and the current input/output for the target case. Exit 0/2 are
/// verifiable outcomes; 1 or abnormal termination is an infrastructure
/// failure.
pub(crate) fn rerun_verifier(
    output_dir: &Path,
    report: &PreflightReportGate,
    target_case_id: &str,
    ctx: &LaunchAttestationContext<'_>,
) -> anyhow::Result<()> {
    // P2 TOCTOU: re-read the envelope (authoritative identity) and resolve +
    // validate + hash the verifier, binding it to the envelope-pinned identity
    // immediately before the spawn. The spawn uses exactly the verified path.
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    let verifier = verified_verifier_for_spawn(&envelope)?;
    let envelope_path = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
    let mut cmd = Command::new(&verifier.path);
    cmd.arg("preflight")
        .arg("--envelope")
        .arg(&envelope_path)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--snapshot-root")
        .arg(ctx.snapshot_root)
        .arg("--cli-binary")
        .arg(ctx.cli_binary)
        .arg("--repo-root")
        .arg(&report.repo_root)
        .arg("--toolchain-pin")
        .arg(&report.toolchain_pin_file)
        .arg("--expected-toolchain")
        .arg(&report.expected_toolchain);
    for case in &report.cases {
        // G3-R3-R1: the GTO target case must feed the verifier the staged
        // immutable SNAPSHOT path, never the live dynamic source (which may be
        // an alias with identical bytes). `enforce_gto_snapshot_path_binding`
        // already proved ctx.input canonical == the sealed snapshot path, so
        // handing the verifier the recorded snapshot path is correct and can
        // never be a live-source alias. Oreans fixed cases keep their live
        // input lane.
        let input = if case.case_id == target_case_id {
            if case.case_id == GTO_CASE_ID {
                Path::new(&case.protected_input_path)
            } else {
                ctx.input
            }
        } else {
            Path::new(&case.protected_input_path)
        };
        let output = if case.case_id == target_case_id {
            ctx.output
        } else {
            Path::new(&case.candidate_output)
        };
        cmd.arg("--case")
            .arg(&case.manifest_path)
            .arg(input)
            .arg(output);
    }
    // `#[cfg(test)]` seam: if a test injected a verifier override, record the
    // exact args (esp. `--snapshot-root`) and short-circuit the spawn so no
    // process is created and the test path terminates here. Production always
    // really spawns (the seam is a no-op and returns false).
    let recorded_args: Vec<std::ffi::OsString> = cmd.get_args().map(|a| a.to_os_string()).collect();
    if maybe_record_verifier_spawn(&recorded_args) {
        return Ok(()); // test seam: exit-0 Ready, no process created
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawn verifier {verifier:?}"))?;
    match status.code() {
        Some(0) | Some(2) => Ok(()),
        other => bail!(
            "offline preflight verifier {:?} terminated abnormally ({other:?}); \
             see {} for any gating report",
            verifier.path,
            output_dir.join(PREFLIGHT_REPORT_FILENAME).display()
        ),
    }
}

/// Digest the launch boundary reports for sidecar/bundle requests. P6.3.3:
/// the SELECTED case (the one whose protected input matches `input_identity`)
/// is chosen first, and its per-case digest is returned — the value that
/// flows into the evidence context and bundle. Always the producer-computed
/// value; equality with the report proven by `tests/preflight_boundary.rs`.
pub fn envelope_case_runner_config_digest(
    output_dir: &Path,
    input_identity: &FileIdentityGate,
) -> anyhow::Result<String> {
    let envelope = RunnerConfigEnvelope::read(output_dir)?;
    let case = select_case_config(&envelope, input_identity)?;
    Ok(case.runner_config_digest.to_lowercase())
}

// ---------------------------------------------------------------------------
// P6.3-D: production evidence/bundle data flow
// ---------------------------------------------------------------------------

/// Evidence sidecar file name appended to the candidate file name
/// (must match the producers in `unpacker/{oep,iat,tls,relocation,
/// section_rebuild}_evidence.rs`).
pub(crate) fn sidecar_path(candidate: &Path, suffix: &str) -> anyhow::Result<PathBuf> {
    let file_name = candidate
        .file_name()
        .ok_or_else(|| anyhow!("candidate path has no file name"))?;
    let mut name = file_name.to_os_string();
    name.push(suffix);
    Ok(candidate.with_file_name(name))
}

/// The seven bundle members for a completed gated run, named exactly as the
/// sidecar producers and the dumper write them:
///
/// - the five structured evidence sidecars (`<candidate>.<kind>_evidence.json`)
/// - the bound transform manifest (`<candidate>.transform_manifest.json`,
///   written by the dumper)
/// - the PE evidence (`<candidate>.pe_evidence.json`, produced through the
///   independent acceptance binary)
pub(crate) fn evidence_members(candidate: &Path) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let mut members = Vec::with_capacity(7);
    for (name, suffix) in [
        ("oep_evidence", ".oep_evidence.json"),
        ("iat_evidence", ".iat_evidence.json"),
        ("tls_evidence", ".tls_evidence.json"),
        ("relocation_evidence", ".relocation_evidence.json"),
        ("section_rebuild_evidence", ".section_rebuild_evidence.json"),
    ] {
        members.push((name.to_string(), sidecar_path(candidate, suffix)?));
    }
    members.push((
        "transform_manifest".to_string(),
        candidate.with_extension("transform_manifest.json"),
    ));
    members.push((
        "pe_evidence".to_string(),
        candidate.with_extension("pe_evidence.json"),
    ));
    Ok(members)
}

/// The acceptance command that produces PE evidence for a packer family.
/// Oreans → `oreans-pe-evidence`; a registered generic family → the generic
/// `unpack-pe-evidence`. Unknown families fail closed (no Oreans fallback).
pub(crate) fn pe_evidence_command_for_family(family: &str) -> anyhow::Result<&'static str> {
    use mida_core::runner_config::packer_family;
    if packer_family::is_oreans_family(family) {
        Ok("oreans-pe-evidence")
    } else if packer_family::is_generic_family(family) {
        Ok("unpack-pe-evidence")
    } else {
        bail!(
            "unknown packer family {family:?}; cannot choose a PE-evidence producer (fail-closed)"
        );
    }
}

/// Emit the PE evidence sidecar through the independent acceptance binary.
/// The family selects the command: `oreans_themida` → `oreans-pe-evidence`
/// (`mida.oreans-pe-evidence/v1`); a registered generic family → the
/// `unpack-pe-evidence` command (`mida.unpack-pe-evidence/v1`). The generic
/// path never masquerades as Oreans PE evidence. The verifier is the unique
/// CLI sibling (never env/caller/PATH). Exit 0/2 are verifiable outcomes;
/// anything else fails closed.
fn emit_pe_evidence(candidate: &Path, destination: &Path, family: &str) -> anyhow::Result<()> {
    let command = pe_evidence_command_for_family(family)?;
    // P2 TOCTOU: resolve + validate + hash the sibling immediately before the
    // spawn, and spawn from the verified path only.
    let verifier = resolve_verifier_identity_checked(None)?;
    let status = Command::new(&verifier.path)
        .arg(command)
        .arg(candidate)
        .arg("--report")
        .arg(destination)
        .status()
        .with_context(|| {
            format!(
                "spawn acceptance binary {:?} for {command} PE evidence",
                verifier.path
            )
        })?;
    match status.code() {
        Some(0) => Ok(()),
        Some(2) => bail!(
            "PE evidence for {} was rejected by the acceptance binary (exit 2); \
             no bundle can be assembled around it",
            candidate.display()
        ),
        other => bail!(
            "acceptance binary {:?} terminated abnormally ({other:?}) while \
             producing PE evidence for {}",
            verifier.path,
            candidate.display()
        ),
    }
}

/// P6.3-D production chain driver: after a successful gated run, collect
/// the seven evidence members (five sidecar producers + transform manifest
/// + PE evidence via the acceptance binary), verify they are all present
/// and bound, and assemble the atomic bundle from the single-use attested
/// context. The bundle's runner-config digest always equals the launch
/// attestation digest.
///
/// G2 family dispatch: the family bound by the attested context selects the
/// evidence contract — `oreans_themida` → `mida.oreans-evidence-bundle/v2`,
/// `ahk_gto` → the generic `mida.unpack-evidence-bundle/v1`. GTO products are
/// never assembled as Oreans evidence. An unknown family fails closed.
///
/// `context` is consumed BY VALUE (P6.3.1): the type is not `Clone` and has
/// no public constructor, so one attestation authorizes exactly one bundle.
/// `candidate` is the actual run output path (member files live next to
/// it); the bundle identity (protected input / candidate) comes from the
/// attestation context. Returns the bundle manifest path.
pub fn complete_run_evidence(
    context: RunEvidenceContext,
    candidate: &Path,
) -> anyhow::Result<PathBuf> {
    use mida_core::runner_config::packer_family;

    // P6.3.2: the PE-evidence verifier must be the attested CLI-sibling
    // identity (path + hash) — no env, no caller path, no PATH.
    verify_bundle_verifier_identity(&context)?;

    let members = evidence_members(candidate)?;
    let pe_evidence_path = candidate.with_extension("pe_evidence.json");
    emit_pe_evidence(candidate, &pe_evidence_path, context.packer_family())?;
    for (name, path) in &members {
        if !path.is_file() {
            bail!(
                "evidence member {name} is missing at {}; refusing to assemble a \
                 Complete bundle",
                path.display()
            );
        }
    }
    let emitted_at = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("{secs}")
    };

    match context.packer_family() {
        family if family == packer_family::OREANS => {
            let bundle_output = candidate.with_extension("bundle.json");
            let request = crate::unpacker::bundle_assembler::AssembleRequest {
                emitted_at,
                protected_input: context.protected_input().to_path_buf(),
                candidate: context.candidate().to_path_buf(),
                members,
                output: bundle_output.clone(),
            };
            crate::unpacker::bundle_assembler::assemble_evidence_bundle(&request, context)?;
            Ok(bundle_output)
        }
        family if family == packer_family::AHK_GTO => {
            let bundle_output = candidate.with_extension("unpack_bundle.json");
            let request = crate::unpacker::generic_bundle_assembler::AssembleRequest {
                emitted_at,
                protected_input: context.protected_input().to_path_buf(),
                candidate: context.candidate().to_path_buf(),
                members,
                output: bundle_output.clone(),
            };
            crate::unpacker::generic_bundle_assembler::assemble_generic_evidence_bundle(
                &request, context,
            )?;
            Ok(bundle_output)
        }
        other => bail!(
            "unknown packer_family {other:?}; cannot choose an evidence contract (fail-closed)"
        ),
    }
}

/// Fail closed unless the verifier this bundle run would use is the unique
/// CLI sibling AND matches the context's attested verifier identity (path +
/// hash, P6.3.2). The sibling resolver guarantees the controlled relative
/// path; `resolve_verifier_identity_checked` binds the attested sha at
/// resolution time (P2 TOCTOU).
pub(crate) fn verify_bundle_verifier_identity(context: &RunEvidenceContext) -> anyhow::Result<()> {
    resolve_verifier_identity_checked(Some(context.verifier_sha256()))?;
    Ok(())
}

/// SHA-256 (lowercase hex) of `path` — the CLI binary identity.
pub fn sha256_file(path: &Path) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    let data =
        std::fs::read(path).with_context(|| format!("read CLI binary {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    Ok(hex)
}

/// Current git HEAD of `repo_root` (spawns `git`; the probe lives in the
/// runner host, not in the preflight module).
pub fn current_tool_revision(repo_root: &Path) -> anyhow::Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .with_context(|| format!("spawn git in {}", repo_root.display()))?;
    if !output.status.success() {
        bail!(
            "git rev-parse failed in {}: {}",
            repo_root.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let revision = String::from_utf8(output.stdout)
        .context("git HEAD is not UTF-8")?
        .trim()
        .to_string();
    if revision.is_empty() {
        bail!("git HEAD is empty in {}", repo_root.display());
    }
    Ok(revision)
}
