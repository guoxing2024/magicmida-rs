//! ScyllaHide integration — inject an anti-anti-debug hook DLL into the target.
//!
//! ScyllaHide is an open-source anti-anti-debug library that hooks numerous
//! Windows API functions to hide the debugger's presence. It is **mandatory**
//! for x64 Themida targets and optional (but recommended) for x86.

use tracing::{debug, info, warn};

use crate::error::ThemidaError;

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
        .arg("nowait")
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
                warn!(
                    ?status,
                    "ScyllaHide injector exited with non-zero status"
                );
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

    // Drop the child handle without killing the process.
    std::mem::forget(child);

    Ok(())
}
