//! Offline preflight runner + gate report (WO-19 split from runner_preflight).

use super::*;
/// The preflight report as the launch boundary consumes it (strict).
///
/// This is a minimal runner-side copy of the acceptance report contract
/// (`mida.preflight-report/v3`); unknown fields fail closed so a drifted
/// report schema cannot slip past.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReportGate {
    pub schema_version: String,
    pub status: String,
    pub reasons: Vec<String>,
    /// The envelope's sealed case-set digest (P6.3.3).
    pub runner_config_digest: String,
    pub head_revision: Option<String>,
    pub worktree_clean: Option<bool>,
    pub toolchain_matches: Option<bool>,
    pub cli_binary_sha256: Option<String>,
    pub cli_binary_matches: Option<bool>,
    pub cli_binary_path: String,
    pub repo_root: String,
    pub toolchain_pin_file: String,
    pub expected_toolchain: String,
    pub cases: Vec<PreflightCaseGate>,
}

/// One artifact identity as recorded in the gate report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileIdentityGate {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightCaseGate {
    pub case_id: String,
    pub identity_ok: bool,
    pub reasons: Vec<String>,
    pub protected_input: Option<FileIdentityGate>,
    pub protected_input_path: String,
    pub manifest_path: String,
    pub candidate_output: String,
    /// P6.3.3: the per-case runner-config digest recorded by the report.
    pub runner_config_digest: Option<String>,
}

/// Resolve the `mida-acceptance` verifier binary (P6.3.2 unique production
/// resolver).
///
/// The verifier can ONLY be the exact sibling `mida-acceptance.exe` of the
/// running `mida-cli` binary. The resolver:
///
/// - never consults `MIDA_ACCEPTANCE_BIN` or any other environment variable;
/// - never accepts a caller-supplied path;
/// - never falls back to PATH;
/// - returns a hard error when the sibling is missing, is not a regular
///   file, or does not canonicalize to exactly the expected sibling path.
///
/// The trust root is the deployment unit: whoever controls the `mida-cli`
/// install controls the sibling `mida-acceptance.exe` beside it (replacing
/// the sibling is equivalent to replacing the CLI itself — host trust, not
/// a CLI interface bypass).
pub fn resolve_acceptance_bin() -> anyhow::Result<PathBuf> {
    let current_exe = std::env::current_exe()
        .context("cannot resolve the current executable to locate the verifier sibling")?;
    resolve_acceptance_bin_from_cli(&current_exe)
}

/// The sibling-only resolver for a given CLI executable (testable). See
/// [`resolve_acceptance_bin`] for the security contract.
pub fn resolve_acceptance_bin_from_cli(cli_exe: &Path) -> anyhow::Result<PathBuf> {
    let parent = cli_exe.parent().ok_or_else(|| {
        anyhow!(
            "current executable {} has no parent directory",
            cli_exe.display()
        )
    })?;
    let expected = parent.join("mida-acceptance.exe");
    let canonical = std::fs::canonicalize(&expected)
        .with_context(|| format!("verifier sibling {} does not exist", expected.display()))?;
    let meta = std::fs::metadata(&canonical)
        .with_context(|| format!("cannot stat verifier sibling {}", canonical.display()))?;
    if !meta.is_file() {
        bail!(
            "verifier sibling {} is not a regular file; refusing to use it as the \
             independent verifier",
            canonical.display()
        );
    }
    // Canonical path must be exactly `cli_dir/mida-acceptance.exe` (the
    // controlled relative identity), not a re-link, symlink escape, or any
    // other location.
    let expected_canonical_parent = std::fs::canonicalize(parent)
        .with_context(|| format!("cannot canonicalize CLI directory {}", parent.display()))?;
    let expected_full = expected_canonical_parent.join("mida-acceptance.exe");
    if canonical != expected_full {
        bail!(
            "verifier resolves to {} which is not exactly the CLI sibling {}; \
             path drift is refused",
            canonical.display(),
            expected_full.display()
        );
    }
    Ok(canonical)
}

/// Resolve the verifier sibling and recompute its SHA-256 (used by the
/// envelope, the launch attestation and the bundle PE-evidence path).
pub fn resolve_verifier_identity() -> anyhow::Result<(PathBuf, String)> {
    #[cfg(test)]
    if let Some(path) = test_verifier_override() {
        let sha = sha256_file(&path)?;
        return Ok((path, sha));
    }
    let verifier = resolve_acceptance_bin()?;
    let sha = sha256_file(&verifier)?;
    Ok((verifier, sha))
}

/// Verified identity of the independent acceptance verifier binary (P2
/// TOCTOU hardening).
///
/// This is the single resolved+validated identity used immediately before a
/// spawn. It holds the canonical path (verified to be exactly the CLI sibling,
/// a regular file) plus the SHA-256 computed at resolution time. Spawn sites
/// re-resolve **and** re-hash through this type immediately before
/// `Command::new`, so the path used to launch is the same path whose identity
/// was verified.
///
/// **RESIDUAL RISK (documented, not fully closed):** this narrows but does NOT
/// eliminate the TOCTOU window. Between the final hash and `Command::new` a
/// privileged local actor could still swap the file at the (immutable-looking)
/// canonical path, and a true handle-based launch (open the verifier with
/// no-write/no-delete sharing, hold the handle across the spawn, or launch from
/// an immutable staging copy) is NOT implemented on this platform. The sibling-
/// only resolver is the trust boundary: a swapped verifier must be placed at
/// the exact CLI sibling path. Treat this as a REDUCED-RISK mitigation, not a
/// TOCTOU elimination.
#[derive(Debug, Clone)]
pub struct VerifierIdentity {
    /// Canonical path used for the spawn (never re-derived after this).
    pub path: PathBuf,
    /// SHA-256 (lowercase hex) of the verifier bytes at resolution time.
    pub sha256: String,
}

/// Resolve the verifier sibling, validate it, and compute its identity in one
/// step (P2). Combines canonicalization, regular-file validation, the sibling
/// path identity, and the SHA-256 digest so the spawn sites can re-verify
/// immediately before `Command::new` without re-deriving the path.
///
/// `bind_expected_sha` (when `Some`) cross-checks the computed digest against a
/// pinned value (e.g. the envelope's `verifier_sha256`) and refuses to execute
/// a drifted verifier. The spawn sites always bind before launching.
///
/// **TOCTOU residual:** this reduces the swap window but does not eliminate it
/// (see [`VerifierIdentity`]). Handle-based launch is not implemented.
pub fn resolve_verifier_identity_checked(
    bind_expected_sha: Option<&str>,
) -> anyhow::Result<VerifierIdentity> {
    #[cfg(test)]
    if let Some(path) = test_verifier_override() {
        let canonical = std::fs::canonicalize(&path)
            .with_context(|| format!("cannot canonicalize injected verifier {}", path.display()))?;
        let meta = std::fs::metadata(&canonical)
            .with_context(|| format!("cannot stat injected verifier {}", canonical.display()))?;
        if !meta.is_file() {
            bail!(
                "injected verifier {} is not a regular file; refusing to use it",
                canonical.display()
            );
        }
        // NOTE: the parent-directory policy applies to the PRODUCTION sibling
        // deployment (below). An explicit `#[cfg(test)]` injected verifier is a
        // hermetic-test seam, not a real product deployment, so it is not
        // subject to the caller-writable-parent check (which would otherwise
        // reject every temp-dir test fixture).
        let sha = sha256_file(&canonical)?;
        if let Some(expected) = bind_expected_sha {
            if !sha.eq_ignore_ascii_case(expected) {
                bail!(
                    "verifier {} (sha {sha}) does not match the pinned verifier sha {expected}; \
                     verifier replacement or hash drift is refused",
                    canonical.display()
                );
            }
        }
        return Ok(VerifierIdentity {
            path: canonical,
            sha256: sha,
        });
    }

    let verifier = resolve_acceptance_bin()?;
    // The sibling resolver already canonicalized and verified regular-file +
    // exact sibling path (the verifier trust boundary). A swapped binary
    // between this resolution and the spawn is closed by re-binding the pinned
    // sha below and re-resolving at each spawn site immediately before use.
    let sha = sha256_file(&verifier)?;
    if let Some(expected) = bind_expected_sha {
        if !sha.eq_ignore_ascii_case(expected) {
            bail!(
                "verifier {} (sha {sha}) does not match the pinned verifier sha {expected}; \
                 verifier replacement or hash drift is refused",
                verifier.display()
            );
        }
    }
    Ok(VerifierIdentity {
        path: verifier,
        sha256: sha,
    })
}

/// Run `sha256_file`, and then bind the verifier path+hash against the
/// envelope-pinned identity (path equality + hash equality). This is the
/// single "verify identity, then it is the ONLY path we will spawn" guard used
/// by the spawn sites.
pub(crate) fn verified_verifier_for_spawn(
    envelope: &RunnerConfigEnvelope,
) -> anyhow::Result<VerifierIdentity> {
    let identity = resolve_verifier_identity_checked(Some(&envelope.verifier_sha256))?;
    verify_verifier_identity_bindings(envelope, &identity.path, &identity.sha256)?;
    Ok(identity)
}

/// `#[cfg(test)]` dependency-injection seam for the verifier spawn sites and
/// the deterministic launch-stop boundary.
///
/// The production `resolve_verifier_identity` / `rerun_verifier` /
/// `run_offline_preflight` / `unpack` are never altered in non-test builds:
/// there is no verifier override, no recorded-args capture, no caller-
/// selectable launch-stop, no short-circuit and no injectable verifier —
/// every spawn and every process creation really runs. The non-test variants
/// below are compile-time no-ops with identical signatures, so the production
/// dispatch path is byte-for-byte untouched.
///
/// In tests only, a hook can (a) inject a stub verifier path, (b) record the
/// exact args (especially `--snapshot-root`) the verifier WOULD receive, then
/// short-circuit the spawn so no verifier process is created, and (c) enable a
/// deterministic launch-stop boundary so the /unpack dispatch test terminates
/// with a stable, unique sentinel error AFTER the launch attestation produced
/// Ready but BEFORE any PE parse / real process creation — never by relying on
/// a malformed synthetic PE failing to parse.
///
/// All of this state is thread-local: a fake verifier / launch-stop armed on
/// one test thread is invisible to every other test thread, so parallel tests
/// can never observe the seam. Each test arms the seams through
/// [`DispatchTestGuard`] (RAII), which restores the prior override, recorders
/// and launch-stop flag on drop — including when a test panics.
// ---------------------------------------------------------------------------

/// Stable, unique sentinel returned by the test-only launch-stop boundary
/// after the launch attestation produced Ready and before any PE parse /
/// process creation. The exact message (with the unique token) is what the
/// positive dispatch tests assert on, so they never accept a malformed-PE
/// parse failure as a substitute.
#[cfg(test)]
pub(crate) const TEST_LAUNCH_STOP_MESSAGE: &str =
    "test-only launch-stop: attestation Ready, refusing real sample launch";

/// Unique sentinel token embedded in the launch-stop error, so tests can
/// match exactly without ambiguity.
#[cfg(test)]
pub(crate) const TEST_LAUNCH_STOP_TOKEN: &str = "TEST_LAUNCH_STOP_SENTINEL";

// Thread-local test seam state. Because it is thread-local, one test thread
// arming the seam never leaks the fake verifier / launch-stop / recorders to
// any other thread — the state-isolation requirement is met structurally,
// not by a coarse global test lock.
#[cfg(test)]
thread_local! {
    static TEST_VERIFIER_OVERRIDE: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
    static TEST_RECORDED_VERIFIER_ARGS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static TEST_RECORDED_SNAPSHOT_ROOTS: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
    static TEST_LAUNCH_STOP_ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static TEST_SAMPLE_LAUNCH_ATTEMPTED: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Read the current thread's injected verifier override (if any).
#[cfg(test)]
pub(crate) fn test_verifier_override() -> Option<PathBuf> {
    TEST_VERIFIER_OVERRIDE.with(|c| c.borrow().clone())
}

/// The current thread's recorded verifier spawn arg-strings (full command
/// line per spawn, including `--snapshot-root`). Empty until a spawn is
/// short-circuited by the seam.
#[cfg(test)]
pub(crate) fn test_verifier_recorder() -> Vec<String> {
    TEST_RECORDED_VERIFIER_ARGS.with(|c| c.borrow().clone())
}

/// The current thread's recorded `--snapshot-root` values the verifier WOULD
/// have received. Empty when the seam never reached `rerun_verifier` (e.g. a
/// root mismatch fails closed first).
#[cfg(test)]
pub(crate) fn test_snapshot_root_recorder() -> Vec<String> {
    TEST_RECORDED_SNAPSHOT_ROOTS.with(|c| c.borrow().clone())
}

/// Record a verifier spawn's args (test seam) and return `true` to short-circuit
/// the spawn (no process created). Production calls the plain spawn path.
#[cfg(test)]
pub(crate) fn maybe_record_verifier_spawn(args: &[std::ffi::OsString]) -> bool {
    if TEST_VERIFIER_OVERRIDE.with(|c| c.borrow().is_none()) {
        return false;
    }
    let arg_strs: Vec<String> = args
        .iter()
        .filter_map(|a| a.to_str().map(|s| s.to_string()))
        .collect();
    TEST_RECORDED_VERIFIER_ARGS.with(|c| c.borrow_mut().push(arg_strs.join(" ")));
    // Extract `--snapshot-root <val>` (and `--snapshot-root=<val>`).
    for (i, a) in arg_strs.iter().enumerate() {
        if let Some(v) = a.strip_prefix("--snapshot-root=") {
            TEST_RECORDED_SNAPSHOT_ROOTS.with(|c| c.borrow_mut().push(v.to_string()));
        } else if a == "--snapshot-root" {
            if let Some(v) = arg_strs.get(i + 1) {
                TEST_RECORDED_SNAPSHOT_ROOTS.with(|c| c.borrow_mut().push(v.clone()));
            }
        }
    }
    true
}

#[cfg(not(test))]
pub(crate) fn maybe_record_verifier_spawn(_args: &[std::ffi::OsString]) -> bool {
    false
}

/// Deterministic test-only launch-stop boundary. Called from `unpack` after
/// the launch attestation produced Ready and immediately before any PE parse /
/// process creation. When a test armed the seam (via [`DispatchTestGuard`]),
/// it returns the stable, unique sentinel error so the dispatch test
/// terminates deterministically at exactly this point — never by relying on a
/// malformed synthetic PE failing to parse, and never reaching
/// `PeHeader::from_file` / `WindowsDebugger::new` / `CreateProcess`. The
/// production build has no caller-selectable stop: this is a compile-time
/// no-op (`Ok(())`).
#[cfg(test)]
pub(crate) fn maybe_test_launch_stop() -> anyhow::Result<()> {
    if TEST_LAUNCH_STOP_ENABLED.with(|c| c.get()) {
        anyhow::bail!("{TEST_LAUNCH_STOP_MESSAGE} [{TEST_LAUNCH_STOP_TOKEN}]");
    }
    Ok(())
}

#[cfg(not(test))]
pub(crate) fn maybe_test_launch_stop() -> anyhow::Result<()> {
    Ok(())
}

/// Test-only sample-process boundary recorder: fired immediately before the
/// real `WindowsDebugger::new`/`CreateProcess` boundary to record that a real
/// sample launch was about to be attempted. The dispatch tests assert this
/// stays empty — the launch-stop sentinel fires earlier, proving the process-
/// creation path is never reached. Production is a compile-time no-op.
#[cfg(test)]
pub(crate) fn note_sample_launch_attempted() {
    TEST_SAMPLE_LAUNCH_ATTEMPTED.with(|c| c.set(c.get() + 1));
}

#[cfg(not(test))]
pub(crate) fn note_sample_launch_attempted() {}

/// Test-only read of the current thread's sample-process boundary recorder:
/// `true` if a real sample-process launch was about to be attempted on this
/// thread. The dispatch tests assert this stays `false`.
#[cfg(test)]
pub(crate) fn test_sample_launch_attempted_any() -> bool {
    TEST_SAMPLE_LAUNCH_ATTEMPTED.with(|c| c.get() > 0)
}

/// RAII guard that arms the test-only launch seams for the CURRENT thread and
/// restores every piece of prior state on drop — including when a test panics
/// (Rust runs `Drop` during unwinding). Because all seam state is thread-local,
/// the guard only affects the arming thread; concurrent tests on other threads
/// never observe the override, launch-stop or recorders, so the seam cannot
/// pollute parallel tests even without a coarse global lock.
#[cfg(test)]
pub(crate) struct DispatchTestGuard {
    prev_override: Option<PathBuf>,
    prev_verifier_args: Vec<String>,
    prev_snapshot_roots: Vec<String>,
    prev_launch_stop: bool,
    prev_sample_attempted: u32,
}

#[cfg(test)]
impl DispatchTestGuard {
    /// Arm the seam on this thread: inject `verifier_path`, enable the
    /// launch-stop boundary, and snapshot + clear the recorders.
    pub(crate) fn arm(verifier_path: PathBuf) -> Self {
        let prev_override = TEST_VERIFIER_OVERRIDE.with(|c| c.borrow().clone());
        let prev_verifier_args = test_verifier_recorder();
        let prev_snapshot_roots = test_snapshot_root_recorder();
        let prev_launch_stop = TEST_LAUNCH_STOP_ENABLED.with(|c| c.get());
        let prev_sample_attempted = TEST_SAMPLE_LAUNCH_ATTEMPTED.with(|c| c.get());
        TEST_VERIFIER_OVERRIDE.with(|c| *c.borrow_mut() = Some(verifier_path));
        TEST_LAUNCH_STOP_ENABLED.with(|c| c.set(true));
        TEST_RECORDED_VERIFIER_ARGS.with(|c| c.borrow_mut().clear());
        TEST_RECORDED_SNAPSHOT_ROOTS.with(|c| c.borrow_mut().clear());
        TEST_SAMPLE_LAUNCH_ATTEMPTED.with(|c| c.set(0));
        DispatchTestGuard {
            prev_override,
            prev_verifier_args,
            prev_snapshot_roots,
            prev_launch_stop,
            prev_sample_attempted,
        }
    }

    /// Whether the sample-process boundary recorder fired on this thread
    /// while the guard was armed. Every dispatch test asserts this is `false`.
    pub(crate) fn sample_launch_attempted(&self) -> bool {
        TEST_SAMPLE_LAUNCH_ATTEMPTED.with(|c| c.get() > 0)
    }
}

#[cfg(test)]
impl Drop for DispatchTestGuard {
    fn drop(&mut self) {
        TEST_VERIFIER_OVERRIDE.with(|c| *c.borrow_mut() = self.prev_override.take());
        TEST_RECORDED_VERIFIER_ARGS
            .with(|c| *c.borrow_mut() = std::mem::take(&mut self.prev_verifier_args));
        TEST_RECORDED_SNAPSHOT_ROOTS
            .with(|c| *c.borrow_mut() = std::mem::take(&mut self.prev_snapshot_roots));
        TEST_LAUNCH_STOP_ENABLED.with(|c| c.set(self.prev_launch_stop));
        TEST_SAMPLE_LAUNCH_ATTEMPTED.with(|c| c.set(self.prev_sample_attempted));
    }
}

/// Outcome of the envelope reuse policy (P6.3-C): the envelope file is
/// either absent (first creation allowed) or present AND field-identical to
/// the would-be envelope. Everything else is an error and the existing
/// bytes are never touched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeReuse {
    /// No envelope exists yet — first creation is allowed.
    Missing,
    /// The existing envelope parses strictly and matches the would-be
    /// envelope field-by-field — reuse it as-is (bytes untouched).
    ExistingMatches,
}

/// P6.3-C fail-closed envelope reuse policy:
///
/// - file absent → [`EnvelopeReuse::Missing`] (first creation allowed);
/// - malformed, unknown-field, truncated or unreadable → hard error;
/// - present and valid → must match the would-be envelope field-by-field
///   (`$schema`, `schema_version`, full config JSON, digest, CLI identity,
///   tool revision); a stale or different envelope is rejected;
/// - any failure leaves the original envelope bytes untouched.
///
/// The caller must never fall back to `Err(_) => write(...)`.
pub fn envelope_reuse_policy(
    output_dir: &Path,
    candidate: &RunnerConfigEnvelope,
) -> anyhow::Result<EnvelopeReuse> {
    let path = output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME);
    if !path.exists() {
        return Ok(EnvelopeReuse::Missing);
    }
    let existing = match RunnerConfigEnvelope::read(output_dir) {
        Ok(existing) => existing,
        Err(e) => {
            bail!(
                "existing runner-config envelope {} cannot be reused (malformed, unknown \
                 field, or unreadable — refusing to overwrite): {e:#}",
                path.display()
            );
        }
    };
    if existing.schema != candidate.schema
        || existing.schema_version != candidate.schema_version
        || existing.case_configs != candidate.case_configs
        || !existing
            .case_set_digest
            .eq_ignore_ascii_case(&candidate.case_set_digest)
        || !existing
            .cli_binary_sha256
            .eq_ignore_ascii_case(&candidate.cli_binary_sha256)
        || existing.tool_revision != candidate.tool_revision
        || existing.verifier_source != candidate.verifier_source
        || existing.verifier_path != candidate.verifier_path
        || !existing
            .verifier_sha256
            .eq_ignore_ascii_case(&candidate.verifier_sha256)
    {
        bail!(
            "existing runner-config envelope {} differs from the would-be envelope \
             (stale or tampered); refusing to overwrite the original bytes",
            path.display()
        );
    }
    Ok(EnvelopeReuse::ExistingMatches)
}

/// The runner-side offline-preflight driver (production).
///
/// Emits the envelope (or reuses an existing one under the P6.3-C
/// fail-closed policy: an existing envelope must parse strictly and match
/// the would-be envelope field-by-field, otherwise the run fails and the
/// original bytes are preserved), drives the independent verifier binary
/// (`mida-acceptance preflight ...`), consumes `preflight.json`, and
/// re-verifies the chain: report digest == envelope digest, status ready,
/// CLI identity matched. Returns `Ok(true)` when Ready.
///
/// [`run_offline_preflight`] itself never launches a sample process; it only
/// drives the read-only verifier.
#[allow(clippy::too_many_arguments)]
pub fn run_offline_preflight(
    output_dir: &Path,
    envelope: &RunnerConfigEnvelope,
    cases: &[(&Path, &Path, &Path)],
    cli_binary: &Path,
    repo_root: &Path,
    toolchain_pin_file: &Path,
    expected_toolchain: &str,
    snapshot_root: &Path,
) -> anyhow::Result<bool> {
    // P6.3-C: fail-closed reuse — first creation only when the file is
    // absent; an existing envelope must parse strictly and match the
    // would-be envelope field-by-field. Any failure preserves the original
    // bytes (no `Err(_) => write` fallback).
    let envelope_path = match envelope_reuse_policy(output_dir, envelope)? {
        EnvelopeReuse::Missing => envelope.write(output_dir)?,
        EnvelopeReuse::ExistingMatches => {
            eprintln!(
                "reusing existing runner-config envelope (case-set digest {}); the verifier \
                 independently recomputes and cross-checks it",
                envelope.case_set_digest
            );
            output_dir.join(RUNNER_CONFIG_ENVELOPE_FILENAME)
        }
    };

    // P2 TOCTOU: resolve + validate + hash the verifier and bind it to the
    // envelope-pinned identity immediately before the spawn. The spawn uses
    // exactly the verified `path`, so a swapped binary between an earlier
    // resolution and this point cannot be executed.
    let verifier = verified_verifier_for_spawn(envelope)?;

    let mut cmd = Command::new(&verifier.path);
    cmd.arg("preflight")
        .arg("--envelope")
        .arg(&envelope_path)
        .arg("--output-dir")
        .arg(output_dir)
        .arg("--snapshot-root")
        .arg(snapshot_root)
        .arg("--cli-binary")
        .arg(cli_binary)
        .arg("--repo-root")
        .arg(repo_root)
        .arg("--toolchain-pin")
        .arg(toolchain_pin_file)
        .arg("--expected-toolchain")
        .arg(expected_toolchain);
    for (manifest, input, candidate) in cases {
        cmd.arg("--case").arg(manifest).arg(input).arg(candidate);
    }
    let status = cmd
        .status()
        .with_context(|| format!("spawn verifier {:?}", verifier.path))?;
    match status.code() {
        // 0 = Ready, 2 = NotReady: both are verifiable outcomes — consume
        // the report. Only 1 (I/O/config) or abnormal termination is an
        // infrastructure failure.
        Some(0) | Some(2) => {}
        other => bail!(
            "offline preflight verifier {:?} terminated abnormally ({other:?}); \
             see {} for any gating report",
            verifier.path,
            output_dir.join(PREFLIGHT_REPORT_FILENAME).display()
        ),
    }
    let ready = match require_ready_before_launch(output_dir, envelope) {
        Ok(()) => true,
        Err(e) => {
            eprintln!("offline preflight rejected the run: {e:#}");
            false
        }
    };
    Ok(ready)
}

/// The P7 launch-boundary gate (production).
///
/// Consumes `preflight.json` + the envelope under `output_dir` and returns
/// `Ok(())` only when:
///
/// - the report parses strictly (unknown fields fail closed) as
///   `mida.preflight-report/v3`;
/// - `status == "ready"`;
/// - the report's case set cross-validates against the envelope case set:
///   the same two fixed cases, each with matching protected-input identity
///   and per-case runner-config digest (P6.3.3 report/envelope cross-check);
/// - `cli_binary_matches == true`.
///
/// Any envelope/report absence, schema drift, case-set drift, per-case
/// digest drift, or CLI identity drift is an error — the caller must not
/// create a sample process.
pub fn require_ready_before_launch(
    output_dir: &Path,
    envelope: &RunnerConfigEnvelope,
) -> anyhow::Result<()> {
    let report = read_gate_report(output_dir)?;
    if report.schema_version != PREFLIGHT_REPORT_SCHEMA_VERSION {
        bail!(
            "preflight report schema {:?} != {PREFLIGHT_REPORT_SCHEMA_VERSION}",
            report.schema_version
        );
    }
    check_chain_ready(&report, envelope)?;
    Ok(())
}

/// Strictly parse the gate report (deny-unknown-fields, v3 shape).
pub fn read_gate_report(output_dir: &Path) -> anyhow::Result<PreflightReportGate> {
    let report_path = output_dir.join(PREFLIGHT_REPORT_FILENAME);
    let bytes = std::fs::read(&report_path)
        .with_context(|| format!("read preflight report {}", report_path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| {
        anyhow!(
            "preflight report {} rejected (unknown/malformed fields): {e}",
            report_path.display()
        )
    })
}

/// The shared ready-chain checks: status ready, report case set cross-validates
/// against the envelope case set (case id, protected identity, per-case
/// digest), and the CLI identity matched.
pub(crate) fn check_chain_ready(
    report: &PreflightReportGate,
    envelope: &RunnerConfigEnvelope,
) -> anyhow::Result<()> {
    if report.status != "ready" {
        bail!(
            "preflight status is not ready ({}): {}",
            report.status,
            report.reasons.join("; ")
        );
    }
    // The report's top-level digest is the envelope's sealed case-set digest.
    if !report
        .runner_config_digest
        .eq_ignore_ascii_case(&envelope.case_set_digest)
    {
        bail!(
            "runner-config case-set digest drift: report {} vs envelope {}",
            report.runner_config_digest,
            envelope.case_set_digest
        );
    }
    // P6.3.3: cross-validate every report case against the envelope case.
    // The report must carry a digest for every case and it must equal the
    // envelope's per-case digest; case set must be exactly the fixed set.
    if report.cases.len() != envelope.case_configs.len() {
        bail!(
            "preflight report case count {} != envelope case config count {}",
            report.cases.len(),
            envelope.case_configs.len()
        );
    }
    for env_case in &envelope.case_configs {
        let report_case = report
            .cases
            .iter()
            .find(|c| c.case_id == env_case.case_id)
            .ok_or_else(|| {
                anyhow!(
                    "preflight report is missing case {} present in the envelope",
                    env_case.case_id
                )
            })?;
        if report_case.protected_input.as_ref() != Some(&env_case.protected_input) {
            bail!(
                "case {} protected-input identity drift between report and envelope",
                env_case.case_id
            );
        }
        let report_digest = report_case.runner_config_digest.as_deref().ok_or_else(|| {
            anyhow!(
                "case {} report is missing its runner_config_digest",
                env_case.case_id
            )
        })?;
        if !report_digest.eq_ignore_ascii_case(&env_case.runner_config_digest) {
            bail!(
                "case {} runner-config digest drift: report {} vs envelope {}",
                env_case.case_id,
                report_digest,
                env_case.runner_config_digest
            );
        }
    }
    if report.cli_binary_matches != Some(true) {
        bail!(
            "CLI identity did not match at preflight time ({:?}); refusing to launch",
            report.cli_binary_matches
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// P6.3-B: launch attestation
// ---------------------------------------------------------------------------
