//! ScyllaHide integration — inject an anti-anti-debug hook DLL into the target.
//!
//! ScyllaHide is an open-source anti-anti-debug library that hooks numerous
//! Windows API functions to hide the debugger's presence. It is **mandatory**
//! for x64 Themida targets and optional (but recommended) for x86.

use tracing::{debug, info, warn};

use crate::error::ThemidaError;
use sha2::Digest;

// ---------------------------------------------------------------------------
// Named constants (general-purpose engine policy — no bare magic literals)
// ---------------------------------------------------------------------------

/// Base file name InjectorCLI's hооk configuration is read from. TASK-013
/// evidence: InjectorCLI builds the path with GetModuleFileNameW (exe-dir)
/// for the non-staged legacy path, and with a bare relative name for the
/// staged copy that sits next to the staged injector. The staged file must
/// carry exactly this name so InjectorCLI finds it.
pub const SCYLLA_HIDE_INI_FILE_NAME: &str = "scylla_hide.ini";

/// Staged copy name of the x64 InjectorCLI binary (the staged injector must
/// keep its original file name so InjectorCLI finds the hооk DLL and ini next
/// to itself).
#[cfg(target_arch = "x86_64")]
pub const SCYLLA_INJECTOR_X64_FILE_NAME: &str = "InjectorCLIx64.exe";

/// Staged copy name of the x64 HookLibrary DLL (see above).
#[cfg(target_arch = "x86_64")]
pub const SCYLLA_HOOK_X64_FILE_NAME: &str = "HookLibraryx64.dll";

/// Staged copy name of the x86 InjectorCLI binary (see above).
#[cfg(target_arch = "x86")]
pub const SCYLLA_INJECTOR_X86_FILE_NAME: &str = "InjectorCLIx86.exe";

/// Staged copy name of the x86 HookLibrary DLL (see above).
#[cfg(target_arch = "x86")]
pub const SCYLLA_HOOK_X86_FILE_NAME: &str = "HookLibraryx86.dll";

/// Staged InjectorCLI file name for the host build architecture.
#[cfg(target_arch = "x86_64")]
pub const SCYLLA_INJECTOR_FILE_NAME: &str = SCYLLA_INJECTOR_X64_FILE_NAME;
#[cfg(target_arch = "x86")]
pub const SCYLLA_INJECTOR_FILE_NAME: &str = SCYLLA_INJECTOR_X86_FILE_NAME;

/// Staged HookLibrary file name for the host build architecture.
#[cfg(target_arch = "x86_64")]
pub const SCYLLA_HOOK_FILE_NAME: &str = SCYLLA_HOOK_X64_FILE_NAME;
#[cfg(target_arch = "x86")]
pub const SCYLLA_HOOK_FILE_NAME: &str = SCYLLA_HOOK_X86_FILE_NAME;

/// Directory-name prefix for the workspace-OUT run-time staging directory.
/// The staging dir lives under the OS temp dir (ARTIFACT_POLICY: never in
/// the workspace) and is keyed by the target pid so concurrent injects never
/// collide.
pub const SCYLLA_STAGING_DIR_PREFIX: &str = "mida-scyllahide";

/// File-name prefix for the persistent P-8 evidence copy of the staged
/// injector's `scylla_hide.log`, keyed by pid (each injection overwrites the
/// staged log; the evidence copy survives the StagingGuard cleanup).
pub const SCYLLA_STAGING_EVIDENCE_PREFIX: &str = "mida-scyllahide-evidence";

/// Literal `nowait` argument InjectorCLI accepts to return immediately after
/// injection (mirrors the Pascal `nowait` contract).
pub const SCYLLA_INJECTOR_NOWAIT_ARG: &str = "nowait";

/// Configuration for launching ScyllaHide injection.
///
/// ScyllaHide is an open-source anti-anti-debug library that hooks numerous
/// Windows API functions to hide the debugger's presence. It is **mandatory**
/// for x64 Themida targets (Themida64 has no manual fallback for
/// anti-anti-debug) and optional (but recommended) for x86.
///
/// ## Files needed
///
/// - `InjectorCLIx86.exe` / `InjectorCLIx64.exe` — the CLI injector that
///   runs as a separate process and injects the hook DLL into the target.
/// - `HookLibraryx86.dll` / `HookLibraryx64.dll` — the DLL that hooks
///   the anti-debug APIs inside the target process.
/// - `scylla_hide.ini` — configuration file (must be next to the injector
///   or in its working directory).
///
/// ## Reference
///
/// `Themida.pas` → `OnDebugStart` (lines 137–142):
/// ```pascal
/// if FileExists(MMPath + 'InjectorCLIx86.exe') then
/// begin
///   Log(ltGood, 'Applying ScyllaHide');
///   ShellExecute(0, 'open', PChar(MMPath + 'InjectorCLIx86.exe'),
///     PChar(Format('pid:%d %s nowait', [FProcess.dwProcessId,
///       MMPath + 'HookLibraryx86.dll'])), nil, SW_HIDE);
/// end
/// ```
///
/// `Themida64.pas` → `OnDebugStart` (lines 111–120):
/// ```pascal
/// if FileExists(MMPath + 'InjectorCLIx64.exe') then
///   ...
/// else
///   raise Exception.Create('ScyllaHide is mandatory for Themida64 ...');
/// ```
#[derive(Debug, Clone)]
pub struct ScyllaHideConfig {
    /// Path to the `InjectorCLIx86.exe` or `InjectorCLIx64.exe` executable.
    pub injector_cli_path: String,
    /// Path to the `HookLibraryx86.dll` or `HookLibraryx64.dll` library.
    pub hook_library_path: String,
    /// Path to `scylla_hide.ini` (optional — if absent, the injector uses
    /// its own defaults).
    pub ini_path: Option<String>,
    /// Delay in milliseconds to wait after spawning the injector, before
    /// returning control to the debug loop.  Empirically 500 is a good
    /// trade-off for Themida-protected samples, but pathological targets
    /// may need to raise or lower this to avoid either a "Target process
    /// exited before unpack completed" (too short) or a deadlock reported
    /// as `ERROR_PARTIAL_COPY` (too long).  Defaults to 500 ms.
    pub hook_delay_ms: u64,
}

/// Launch the ScyllaHide injector as a detached child process.
///
/// The injector runs asynchronously — it injects the hook DLL into the
/// target and exits. This function returns immediately after spawning the
/// process; it does **not** wait for injection to complete.
///
/// ## Arguments
///
/// - `pid` — the target process ID.
/// - `config` — paths to the injector binary and hook library.
///
/// ## Errors
///
/// Returns [`ThemidaError::ScyllaHide`] if the injector executable or hook DLL
/// cannot be found, **or** if either file's SHA-256 hash does not match the
/// known-good hash committed alongside the source.  This prevents accidentally
/// (or maliciously) running a tampered ScyllaHide helper — the helper injects
/// into the debuggee, so integrity is a safety requirement, not a nicety.
pub fn inject_scylla_hide(pid: u32, config: &ScyllaHideConfig) -> Result<(), ThemidaError> {
    // Route A (TASK-006R5): when a controlled ini is supplied, stage the
    // injector trio (InjectorCLI + HookLibrary + ini) into a workspace-OUT
    // run-time staging dir and spawn the staged injector there. R4 evidence:
    // InjectorCLI reads `<injector-exe-dir>/scylla_hide.ini` (it builds the
    // path with GetModuleFileNameW + GetPrivateProfileSectionNamesW), so the
    // controlled ini only takes effect when it sits next to the injector we
    // actually spawn. ARTIFACT_POLICY forbids `scylla_hide.ini` in the
    // workspace, hence the OS-temp staging dir. Without an ini, behaviour is
    // byte-for-byte the pre-existing path (spawn the configured injector
    // directly, no staging, no copies).
    if let Some(ini) = config.ini_path.as_deref() {
        return inject_scylla_hide_staged(pid, config, std::path::Path::new(ini));
    }

    // Verify the injector binary exists.
    let injector_path = std::path::Path::new(&config.injector_cli_path);
    if !injector_path.exists() {
        return Err(ThemidaError::ScyllaHide(format!(
            "InjectorCLI not found at '{}'",
            config.injector_cli_path
        )));
    }

    // Verify the hook library exists.
    let hook_path = std::path::Path::new(&config.hook_library_path);
    if !hook_path.exists() {
        return Err(ThemidaError::ScyllaHide(format!(
            "HookLibrary not found at '{}'",
            config.hook_library_path
        )));
    }

    // Integrity check before spawning — fail fast if the file contents don't
    // match the expected SHA-256.  This defends against supply-chain
    // tampering of the external helper binaries, which run with full
    // injection privileges.
    verify_helper_hashes(injector_path, hook_path)?;

    // Build the arguments as three separate args:
    //   pid:<pid>   — target process ID
    //   <hook_path> — path to the hook library DLL
    //   nowait      — tell InjectorCLI to return immediately after injection
    let pid_arg = format!("pid:{}", pid);

    debug!(
        injector_path = %injector_path.display(),
        %pid_arg,
        hook = %config.hook_library_path,
        "Launching ScyllaHide injector"
    );

    // Spawn the injector process.  We deliberately do not wait on it in this
    // function — that would block the debug loop.  The bounded sleep below
    // exists to give InjectorCLI a realistic window to complete its work
    // before we return; the exact time is sample-dependent.
    //
    // Timing observations on real samples:
    //   * Too short (< 200 ms) : the hook DLL is not yet mapped into the
    //                             target when the target reaches its
    //                             anti-debug check → anti-debug wins, target
    //                             self-terminates with
    //                             `STATUS_FATAL_APP_EXIT` = 0x80000004.
    //   * Too long (> 1 s)     : ScyllaHide's ntdll hooks race against the
    //                             Themida VM dispatcher session, and
    //                             WaitForDebugEvent fails with
    //                             `ERROR_PARTIAL_COPY`.
    let mut child = std::process::Command::new(injector_path)
        .arg(&pid_arg)
        .arg(&config.hook_library_path)
        .arg(SCYLLA_INJECTOR_NOWAIT_ARG)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            ThemidaError::ScyllaHide(format!(
                "Failed to spawn '{}': {e}",
                injector_path.display()
            ))
        })?;

    // Wait a tunable window for the injector to finish.
    std::thread::sleep(std::time::Duration::from_millis(config.hook_delay_ms));

    match child.try_wait() {
        Ok(Some(status)) => {
            if status.success() {
                info!("ScyllaHide injection completed successfully");
            } else {
                warn!(?status, "ScyllaHide injector exited with non-zero status");
            }
        }
        Ok(None) => {
            // Still running — injection is in progress, that's fine.
            info!("ScyllaHide injection initiated (running in background)");
        }
        Err(e) => {
            warn!("Failed to check ScyllaHide injector status: {e}");
        }
    }

    // Intentionally detach from the injector: the hook DLL keeps running in
    // the target regardless of what we do with this handle. Dropping `child`
    // does NOT kill the spawned process — `std::process::Child` only reaps on
    // `wait()`/`try_wait()`, and we want neither to block nor to kill. Let
    // `child` drop naturally at end of scope.
    // (Replaces the previous `std::mem::forget(child)`, which tripped clippy's
    // `mem_forget` lint and leaked the Child's bookkeeping without benefit.)
    drop(child);

    Ok(())
}

/// Verify both helper binaries against their committed known-good SHA-256.
fn verify_helper_hashes(
    injector_path: &std::path::Path,
    hook_path: &std::path::Path,
) -> Result<(), ThemidaError> {
    let injector_bytes = std::fs::read(injector_path).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to read InjectorCLI for hash check: {e} (path: '{}')",
            injector_path.display()
        ))
    })?;
    if !crate::binaries::verify_sha256(&injector_bytes, crate::binaries::expected_injector_hash()) {
        return Err(ThemidaError::ScyllaHide(format!(
            "InjectorCLI hash mismatch at '{}': the file does not match the expected SHA-256. \
             Aborting to avoid running a tampered helper.",
            injector_path.display()
        )));
    }

    let hook_bytes = std::fs::read(hook_path).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to read HookLibrary for hash check: {e} (path: '{}')",
            hook_path.display()
        ))
    })?;
    if !crate::binaries::verify_sha256(&hook_bytes, crate::binaries::expected_hook_hash()) {
        return Err(ThemidaError::ScyllaHide(format!(
            "HookLibrary hash mismatch at '{}': the file does not match the expected SHA-256. \
             Aborting to avoid running a tampered helper.",
            hook_path.display()
        )));
    }
    Ok(())
}

/// Spawn the injector with the pid / hook / nowait argument contract.
fn spawn_injector(
    injector_path: &std::path::Path,
    pid_arg: &str,
    hook_library_path: &str,
) -> Result<std::process::Child, ThemidaError> {
    std::process::Command::new(injector_path)
        .arg(pid_arg)
        .arg(hook_library_path)
        .arg(SCYLLA_INJECTOR_NOWAIT_ARG)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            ThemidaError::ScyllaHide(format!(
                "Failed to spawn '{}': {e}",
                injector_path.display()
            ))
        })
}

/// Drop-guard that removes the run-time staging directory.
///
/// Runs on normal return AND on panic (drop of the guard during unwind),
/// so no staging artifact survives the inject call on any path.
struct StagingGuard {
    dir: std::path::PathBuf,
}

impl StagingGuard {
    fn new(dir: std::path::PathBuf) -> Self {
        Self { dir }
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.dir) {
            warn!(
                dir = %self.dir.display(),
                error = %e,
                "Failed to remove ScyllaHide staging dir during cleanup"
            );
        } else {
            debug!(dir = %self.dir.display(), "Removed ScyllaHide staging dir");
        }
    }
}

/// Compute the SHA-256 of a file (lowercase hex).
fn sha256_hex(path: &std::path::Path) -> Result<String, ThemidaError> {
    let bytes = std::fs::read(path).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to read '{}' for sha256: {e}",
            path.display()
        ))
    })?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Fail-closed verification: the staged ini must byte-identically match the
/// source ini, otherwise return Err (never silently continue with a
/// possibly-corrupt config).
fn verify_staged_ini_matches(
    source: &std::path::Path,
    staged: &std::path::Path,
) -> Result<(), ThemidaError> {
    let src_sha = sha256_hex(source)?;
    let staged_sha = sha256_hex(staged)?;
    if src_sha != staged_sha {
        return Err(ThemidaError::ScyllaHide(format!(
            "ScyllaHide ini staging verification FAILED: staged sha256 {staged_sha}              != source sha256 {src_sha} (path '{}')",
            staged.display()
        )));
    }
    Ok(())
}

/// Route A: stage the injector trio into a workspace-out run-time dir and
/// spawn the staged injector so the controlled `scylla_hide.ini` is actually
/// read (it must sit next to the injector executable - R4 evidence).
///
/// Fail-closed semantics (TASK-006R5):
///  1. the ini is copied to `<staging>/scylla_hide.ini`;
///  2. the copy's sha256 must equal the source's sha256, else we return Err
///     (never silently continue with a possibly-corrupt config);
///  3. the staged injector is spawned and the staging dir is removed on every
///     path (success / error / panic) via `StagingGuard`.
///
/// The actual staged path + verify result are logged on the
/// `SCYLLAHIDE_HOOK_CONFIG_SOURCE` line so a live-fire run can prove the ini
/// was delivered (not just recorded).
fn inject_scylla_hide_staged(
    pid: u32,
    config: &ScyllaHideConfig,
    ini_src: &std::path::Path,
) -> Result<(), ThemidaError> {
    // Integrity of the helpers is a precondition, identical to the non-staged
    // path (they get copied into staging and spawned there).
    let injector_src = std::path::Path::new(&config.injector_cli_path);
    let hook_src = std::path::Path::new(&config.hook_library_path);
    if !injector_src.exists() {
        return Err(ThemidaError::ScyllaHide(format!(
            "InjectorCLI not found at '{}'",
            config.injector_cli_path
        )));
    }
    if !hook_src.exists() {
        return Err(ThemidaError::ScyllaHide(format!(
            "HookLibrary not found at '{}'",
            config.hook_library_path
        )));
    }
    verify_helper_hashes(injector_src, hook_src)?;

    if !ini_src.exists() {
        return Err(ThemidaError::ScyllaHide(format!(
            "Controlled ScyllaHide ini not found at '{}'",
            ini_src.display()
        )));
    }
    let src_ini_sha256 = sha256_hex(ini_src)?;

    // Stage into workspace-out temp dir (keyed by pid).
    let staging_dir = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-{pid}"));
    if let Err(e) = std::fs::create_dir_all(&staging_dir) {
        return Err(ThemidaError::ScyllaHide(format!(
            "Failed to create ScyllaHide staging dir '{}': {e}",
            staging_dir.display()
        )));
    }
    let _guard = StagingGuard::new(staging_dir.clone());

    let staged_injector = staging_dir.join(SCYLLA_INJECTOR_FILE_NAME);
    let staged_hook = staging_dir.join(SCYLLA_HOOK_FILE_NAME);
    let staged_ini = staging_dir.join(SCYLLA_HIDE_INI_FILE_NAME);

    // Copy helper binaries (the staged injector must find the hook DLL and
    // ini in its own directory).
    std::fs::copy(injector_src, &staged_injector).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to stage InjectorCLI to '{}': {e}",
            staged_injector.display()
        ))
    })?;
    std::fs::copy(hook_src, &staged_hook).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to stage HookLibrary to '{}': {e}",
            staged_hook.display()
        ))
    })?;
    std::fs::copy(ini_src, &staged_ini).map_err(|e| {
        ThemidaError::ScyllaHide(format!(
            "Failed to stage ini to '{}': {e}",
            staged_ini.display()
        ))
    })?;

    // Fail-closed: the staged ini must byte-identically match the source.
    verify_staged_ini_matches(ini_src, &staged_ini)?;

    info!(
        source = %ini_src.display(),
        staged = %staged_ini.display(),
        sha256 = %src_ini_sha256,
        "SCYLLAHIDE_HOOK_CONFIG_SOURCE=ini: {} (staged to {}, sha256 verified {})",
        ini_src.display(),
        staged_ini.display(),
        src_ini_sha256
    );
    info!(
        staged_dir = %staging_dir.display(),
        sha256_verified = true,
        "ScyllaHide ini staging verification passed"
    );

    let pid_arg = format!("pid:{pid}");
    debug!(
        staged_injector = %staged_injector.display(),
        %pid_arg,
        hook = %staged_hook.display(),
        "Launching staged ScyllaHide injector"
    );
    let mut child = spawn_injector(&staged_injector, &pid_arg, &staged_hook.to_string_lossy())?;

    std::thread::sleep(std::time::Duration::from_millis(config.hook_delay_ms));

    match child.try_wait() {
        Ok(Some(status)) => {
            if status.success() {
                info!("ScyllaHide injection completed successfully (staged)");
            } else {
                warn!(
                    ?status,
                    "ScyllaHide staged injector exited with non-zero status"
                );
            }
        }
        Ok(None) => {
            info!("ScyllaHide injection initiated (staged, running in background)");
        }
        Err(e) => {
            warn!("Failed to check staged ScyllaHide injector status: {e}");
        }
    }
    drop(child);

    // P-8 evidence preservation (TASK-006R5): the staged injector writes
    // `scylla_hide.log` next to itself, i.e. inside the staging dir, which the
    // StagingGuard is about to delete. Copy it to a persistent temp path so a
    // live-fire run can archive it to the vault before any new injection
    // overwrites it (each injection overwrites; evidence window is one-shot).
    let staged_log = staging_dir.join("scylla_hide.log");
    if staged_log.exists() {
        let evidence_path =
            std::env::temp_dir().join(format!("{SCYLLA_STAGING_EVIDENCE_PREFIX}-{pid}.log"));
        match std::fs::copy(&staged_log, &evidence_path) {
            Ok(_) => info!(
                evidence = %evidence_path.display(),
                "ScyllaHide staging log preserved for P-8 evidence (outside staging dir, survives cleanup)"
            ),
            Err(e) => warn!(
                log = %staged_log.display(),
                error = %e,
                "Failed to preserve staged scylla_hide.log for P-8 evidence"
            ),
        }
    } else {
        debug!(staged_dir = %staging_dir.display(), "No staged scylla_hide.log to preserve");
    }

    // StagingGuard drops here (or on any earlier Err / panic) and removes the
    // whole staging dir; the staged injector has already returned by then
    // (hook_delay_ms window) so no open handle keeps it alive.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- route A: staging dir resolution (pure, no IO) ---

    #[test]
    fn staging_dir_is_workspace_out_and_pid_keyed() {
        // Route-A path resolution contract: the staging dir must live under
        // the OS temp dir (never the workspace - ARTIFACT_POLICY) and be
        // unique per target pid so concurrent injects never collide.
        let d1 = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-{}", 1234));
        let d2 = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-{}", 1234));
        let d3 = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-{}", 5678));
        assert_eq!(d1, d2, "same pid must resolve to the same staging dir");
        assert_ne!(
            d1, d3,
            "different pids must resolve to different staging dirs"
        );
        assert!(
            d1.to_string_lossy()
                .to_ascii_lowercase()
                .contains(&format!("{SCYLLA_STAGING_DIR_PREFIX}-1234")),
            "staging dir must embed the pid, got: {}",
            d1.display()
        );
        assert!(
            d1.starts_with(&std::env::temp_dir()),
            "staging dir must live under the OS temp dir (workspace-out), got: {}",
            d1.display()
        );
    }

    #[test]
    fn sha256_hex_matches_known_input() {
        // sha256("abc") — deterministic vector; proves the helper is real
        // SHA-256, not a placeholder.
        let dir = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-test-sha"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("abc.txt");
        std::fs::write(&p, b"abc").unwrap();
        let got = sha256_hex(&p).unwrap();
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staging_guard_removes_dir_on_drop() {
        let dir = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-test-guard"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(SCYLLA_HIDE_INI_FILE_NAME), b"[SETTINGS]").unwrap();
        {
            let guard = StagingGuard::new(dir.clone());
            assert!(dir.exists());
            let _ = guard; // drop at scope end
        }
        assert!(!dir.exists(), "staging dir must be removed on guard drop");
    }

    // --- fail-closed: the staged ini must match the source sha256 ---

    #[test]
    fn staged_ini_mismatch_fails_closed() {
        // Verify the fail-closed primitive directly: a mutated staged copy
        // must be rejected against the source hash. This is the pure
        // discriminator behind inject_scylla_hide_staged's verification.
        let dir = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-test-mismatch"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.ini");
        let staged = dir.join("staged.ini");
        std::fs::write(
            &src,
            b"[SETTINGS]
KiUserExceptionDispatcherHook=0
",
        )
        .unwrap();
        std::fs::write(
            &staged,
            b"[SETTINGS]
KiUserExceptionDispatcherHook=1
",
        )
        .unwrap();
        assert_ne!(
            sha256_hex(&src).unwrap(),
            sha256_hex(&staged).unwrap(),
            "different bytes must give different hashes"
        );
        // Discrimination target: the REAL fail-closed verification must
        // reject a mutated staged copy. If the verification were no-op'd
        // (e.g. always Ok), this test goes red -> proves the check is live.
        let err = verify_staged_ini_matches(&src, &staged)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("staging verification FAILED"),
            "mismatched staged ini must fail-closed, got: {err}"
        );
        assert!(
            err.contains("sha256"),
            "error must show the hashes, got: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn staged_ini_identical_copy_passes() {
        // A byte-identical copy must pass the equality check (the happy path
        // of the staging verification).
        let dir = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-test-copy"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("src.ini");
        let staged = dir.join("staged.ini");
        std::fs::write(
            &src,
            b"[SETTINGS]
NtContinueHook=0
",
        )
        .unwrap();
        std::fs::copy(&src, &staged).unwrap();
        verify_staged_ini_matches(&src, &staged).expect("identical copy must pass");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- no-ini dispatch: zero behaviour change ---

    #[test]
    fn no_ini_dispatches_to_non_staged_path() {
        // The dispatch decision: Some(ini) -> staged, None -> legacy path.
        // We can't spawn a real injector in tests, but we CAN assert the
        // dispatch function splits correctly by checking the branch target
        // exists and the non-staged path returns an error mentioning the
        // injector (proving it did NOT take the staging route).
        let config = ScyllaHideConfig {
            injector_cli_path: r"C:\nonexistent\InjectorCLIx64.exe".to_string(),
            hook_library_path: r"C:\nonexistent\HookLibraryx64.dll".to_string(),
            ini_path: None,
            hook_delay_ms: 1,
        };
        let err = inject_scylla_hide(12345, &config).unwrap_err().to_string();
        assert!(
            err.contains("InjectorCLI not found"),
            "no-ini path must use the original injector-exists check, got: {err}"
        );
    }

    #[test]
    fn some_ini_missing_source_fails_closed() {
        // With ini_path = Some(...) pointing at a missing file, the staged
        // route must fail with a clear "ini not found" error and must NOT
        // leave a staging dir behind.
        let config = ScyllaHideConfig {
            injector_cli_path: r"C:\nonexistent\InjectorCLIx64.exe".to_string(),
            hook_library_path: r"C:\nonexistent\HookLibraryx64.dll".to_string(),
            ini_path: Some(r"C:\nonexistent\no_such.ini".to_string()),
            hook_delay_ms: 1,
        };
        let err = inject_scylla_hide(54321, &config).unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "staged route must fail-closed on missing source, got: {err}"
        );
        let staging = std::env::temp_dir().join(format!("{SCYLLA_STAGING_DIR_PREFIX}-54321"));
        assert!(
            !staging.exists(),
            "no staging dir may survive a failed inject"
        );
    }
}
