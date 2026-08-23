//! CLI-side anti-debug controller wiring (ADR-3B + correction).
//!
//! Drives the pure [`mida_antidebug`] lifecycle from the CREATE_PROCESS
//! handler with **fail-closed** semantics:
//!
//! ```text
//! Unresolved
//!   -> DependencyVerified   (runtime artifact discovery + identity)
//!   -> ... success path ...
//!   -> Proceed              (only when a MIDA runtime is present)
//!
//! any failure:
//!   -> terminal failure state + fail_code + structured evidence
//!   -> explicit cleanup backend (TerminateProcess + bounded wait)
//!   -> cleanup failure upgrades to ControllerState::CleanupFailed
//!   -> non-zero error return; candidate never created
//! ```
//!
//! ## ADR-3B status: no MIDA runtime yet
//!
//! The self-owned runtime DLL does not exist yet (ADR-4+). Until it does,
//! the production path **must fail closed** at the dependency stage: the
//! anti-debug runtime dependency is unavailable by definition, so the
//! lifecycle deterministically enters [`ControllerState::DependencyUnavailable`]
//! with [`FailCode::AntiDebugRuntimeUnavailable`], writes evidence, cleans up,
//! and aborts unpack with a non-zero exit code.
//!
//! ## Cleanup feedback (ADR-3B-CORRECTION)
//!
//! Cleanup is an **injectable backend** ([`CleanupBackend`]), not a Drop
//! side effect. The controller receives the cleanup result explicitly:
//!
//! - cleanup ok     -> keep the original failure state;
//! - cleanup failed -> drive [`ControllerEvent::CleanupFailed`], final state
//!   becomes [`ControllerState::CleanupFailed`] with
//!   [`FailCode::CleanupFailed`], evidence records `cleanup_result=failed`,
//!   return stays non-zero, candidate stays false.
//!
//! ## Evidence schema
//!
//! The failure sidecar uses the **registered** `mida.antidebug-evidence/v1`
//! schema with `record_kind = "cli-failure"` (ADR-3B-CORRECTION: unified,
//! no separate unregistered schema). It is a CLI-local fail-closed record
//! that follows the run output directory; it never substitutes for
//! TLS/PE/behavior success evidence and is never consumed by the
//! acceptance gate as a success record.
//!
//! ScyllaHide is **not** a MIDA success proof. It may only run in explicit
//! oracle mode (future differential experiments, ADR-7); its results are
//! recorded with `source=scyllahide-oracle` and never upgrade the profile.

use std::path::Path;

use mida_antidebug::evidence::EvidenceLog;
use mida_antidebug::profile::Profile;
use mida_antidebug::state::{transition, ControllerEvent, ControllerState, FailCode};

use crate::log::{self, LogType};
use crate::unpacker::runtime_loader::{
    RuntimeAuthorityManifest, RuntimeDigestAuthority, RuntimeFileIdentity,
};

/// Registered anti-debug evidence schema (ADR-0 evidence contract).
/// The CLI failure sidecar is a `record_kind = "cli-failure"` record of
/// this schema - unified, no unregistered schema variants.
pub const ANTIDEBUG_EVIDENCE_SCHEMA: &str = "mida.antidebug-evidence/v1";

/// Discriminator for the CLI failure record inside the evidence schema.
pub const EVIDENCE_RECORD_KIND_CLI_FAILURE: &str = "cli-failure";

/// Runtime artifact name the dependency resolver looks for (ADR-4+).
pub const MIDA_RUNTIME_ARTIFACT: &str = "mida-antidebug-runtime-x64.dll";

/// Oracle-mode marker: ScyllaHide results are only ever recorded under
/// this source tag and never treated as MIDA success.
pub const SCYLLAHIDE_ORACLE_SOURCE: &str = "scyllahide-oracle";

/// Cleanup backend error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupError {
    pub message: String,
}

impl CleanupError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Injectable cleanup backend (ADR-3B-CORRECTION).
///
/// Production uses [`Win32CleanupBackend`]; tests inject a mock so the
/// CleanupFailed escalation is verified without launching a process.
pub trait CleanupBackend: std::fmt::Debug {
    /// Terminate the target process and wait for exit (bounded).
    /// Returns `Ok(())` only when terminate succeeded and the wait
    /// signaled; any other outcome is a cleanup failure.
    fn cleanup(&self, target_pid: u32) -> Result<(), CleanupError>;
}

/// Production cleanup backend: TerminateProcess + bounded wait on the
/// owned process handle (mirrors core Drop semantics but returns a
/// structured result to the controller).
#[derive(Debug)]
pub struct Win32CleanupBackend {
    process_handle: windows::Win32::Foundation::HANDLE,
}

impl Win32CleanupBackend {
    pub fn new(process_handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self { process_handle }
    }
}

impl CleanupBackend for Win32CleanupBackend {
    fn cleanup(&self, _target_pid: u32) -> Result<(), CleanupError> {
        use windows::Win32::System::Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, PROCESS_TERMINATE,
        };
        const TERMINATE_TIMEOUT_MS: u32 = 5000;

        if self.process_handle.is_invalid() {
            return Err(CleanupError::new("process handle invalid"));
        }
        // R1-HARDENING-CLEANUP-1: a protected target may revoke/degrade the
        // original CreateProcessW handle rights (observed: TerminateProcess ->
        // ERROR_ACCESS_DENIED 0x80070005 against Themida targets). Re-open with
        // PROCESS_TERMINATE | SYNCHRONIZE so termination is not hostage to the
        // original handle's current rights.
        let mut term_handle = self.process_handle;
        let mut reopened = false;
        // SAFETY: OpenProcess with the target pid and minimal rights.
        let reopened_handle = unsafe {
            OpenProcess(
                PROCESS_TERMINATE | windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                false,
                _target_pid,
            )
        };
        if let Ok(h) = reopened_handle {
            if !h.is_invalid() {
                term_handle = h;
                reopened = true;
            }
        }
        // SAFETY: valid process handle (original or freshly re-opened).
        let tp = unsafe { TerminateProcess(term_handle, 1) };
        if tp.is_err() {
            let code = tp.err().map(|e| e.code().0).unwrap_or(0);
            // SAFETY: close the re-opened handle if we created one.
            if reopened {
                let _ = unsafe { windows::Win32::Foundation::CloseHandle(term_handle) };
            }
            return Err(CleanupError::new(format!(
                "TerminateProcess failed win32={code}"
            )));
        }
        // SAFETY: bounded wait on the process handle.
        let mut wait = unsafe { WaitForSingleObject(term_handle, TERMINATE_TIMEOUT_MS) }.0;
        // R1-HARDENING-CLEANUP-1: while the debugger is still attached, the
        // process handle does not become signaled even after the target exits
        // (observed: terminate wait TIMEOUT against Themida targets whose
        // process was already gone). Detach the debug session, then re-wait on
        // a fresh handle so the wait reflects the real process state.
        if wait == 0x102 {
            // SAFETY: DebugActiveProcessStop with the target pid.
            let _ = unsafe {
                windows::Win32::System::Diagnostics::Debug::DebugActiveProcessStop(_target_pid)
            };
            // SAFETY: OpenProcess with minimal rights for the wait.
            let fresh = unsafe {
                OpenProcess(
                    windows::Win32::System::Threading::PROCESS_SYNCHRONIZE,
                    false,
                    _target_pid,
                )
            };
            if let Ok(fh) = fresh {
                if !fh.is_invalid() {
                    // SAFETY: bounded wait on the fresh handle.
                    let r2 = unsafe { WaitForSingleObject(fh, TERMINATE_TIMEOUT_MS) }.0;
                    wait = r2;
                    // SAFETY: close the fresh handle.
                    let _ = unsafe { windows::Win32::Foundation::CloseHandle(fh) };
                }
            }
        }
        // SAFETY: close the re-opened handle if we created one.
        if reopened {
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(term_handle) };
        }
        match wait {
            0 => Ok(()), // WAIT_OBJECT_0: signaled
            0x102 => Err(CleanupError::new("terminate wait TIMEOUT")),
            code => Err(CleanupError::new(format!(
                "terminate wait failed win32={code}"
            ))),
        }
    }
}

/// Outcome of the anti-debug lifecycle stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntidebugOutcome {
    /// Full success path reached (requires an actual MIDA runtime).
    Proceed { final_state: ControllerState },
    /// Terminal failure; unpack must abort with non-zero exit.
    Failed {
        state: ControllerState,
        fail_code: FailCode,
        message: String,
    },
}

/// Structured cleanup result recorded in evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupResult {
    Ok,
    Failed(String),
    NotRun,
}

impl CleanupResult {
    pub fn as_str(&self) -> &str {
        match self {
            CleanupResult::Ok => "ok",
            CleanupResult::Failed(_) => "failed",
            CleanupResult::NotRun => "not-run",
        }
    }
}

/// Structured evidence record (schema `mida.antidebug-evidence/v1`,
/// record_kind `cli-failure`).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AntidebugFailureEvidence {
    pub schema: String,
    pub record_kind: String,
    pub decision: String,
    pub controller_state_before: String,
    pub failure_state: String,
    pub fail_code: String,
    pub sample_id: Option<String>,
    pub target_pid: Option<u32>,
    pub runtime_identity: Option<String>,
    pub profile_id: Option<String>,
    pub profile_digest: Option<String>,
    pub sequence: u32,
    pub cleanup_result: String,
    pub cleanup_detail: Option<String>,
    pub candidate_created: bool,
    /// ADR-7-A-CAPTURE-1: exception capture context from the drain window.
    /// Null when no exception receipt was captured (e.g. dependency-stage
    /// failures before any debug event).
    pub exception_code: Option<u32>,
    /// ADR7-A1-CORRECTION-1: raw dwThreadId from the DEBUG_EVENT for the
    /// captured exception. None when no exception receipt was captured.
    pub exception_thread_id: Option<u32>,
    pub first_chance: Option<bool>,
    pub exception_address: Option<String>,
    pub instruction_pointer: Option<String>,
    pub stack_pointer: Option<String>,
    pub faulting_module: Option<String>,
    pub faulting_module_base: Option<String>,
    pub faulting_module_rva: Option<String>,
    pub context_capture_error: Option<String>,
}

/// Options for the anti-debug stage.
#[derive(Debug)]
pub struct AntidebugStageOptions {
    /// Case id when known (bound at preflight); recorded in evidence.
    #[allow(dead_code)] // consumed by ADR-4 evidence binding
    pub sample_id: Option<String>,
    /// Target process id; recorded in evidence.
    #[allow(dead_code)] // consumed by ADR-4 evidence binding
    pub target_pid: u32,
    /// Where to write the failure evidence sidecar (run output directory).
    #[allow(dead_code)] // evidence binding (ADR-4); consumed by callers
    pub evidence_dir: Option<std::path::PathBuf>,
    /// Explicit opt-in oracle mode (ScyllaHide). `None` in production.
    pub oracle: Option<OracleMode>,
    /// Cleanup backend (injectable for tests).
    pub cleanup_backend: Option<Box<dyn CleanupBackend>>,
    /// Audited runtime authority manifest (ADR-6-CORRECTION). None keeps
    /// the old fail-closed placeholder behaviour (DependencyUnavailable).
    pub runtime_authority: Option<RuntimeAuthorityManifest>,
    /// Path to the runtime DLL to verify + load.
    pub runtime_path: Option<std::path::PathBuf>,
    /// Loader result injected by the CREATE_PROCESS handler after it ran the
    /// real loader (attestation JSON + module base + identity).
    pub loader_result: Option<LoaderResult>,
}

/// Oracle-mode configuration (future differential experiments only).
#[derive(Debug, Clone)]
pub struct OracleMode {
    /// Path to the ScyllaHide injector (external vault artifact).
    pub injector_path: std::path::PathBuf,
    /// Path to the ScyllaHide hook library (external vault artifact).
    pub hook_library_path: std::path::PathBuf,
    /// ScyllaHide `scylla_hide.ini` (external vault artifact; optional).
    #[allow(dead_code)] // future oracle seam (ADR-7)
    pub ini_path: Option<std::path::PathBuf>,
}

/// Result of a real loader execution, injected by the caller (the
/// CREATE_PROCESS handler) so the controller can drive the lifecycle from
/// actual runtime evidence (ADR-6).
#[derive(Debug, Clone)]
pub struct LoaderResult {
    /// Module base in the target (evidence + controller cross-check).
    #[allow(dead_code)] // consumed by evidence bindings
    module_base: u64,
    attestation_json: String,
    /// Verified file identity (evidence).
    #[allow(dead_code)] // consumed by evidence bindings
    file_identity: RuntimeFileIdentity,
    /// Production digest authority (IMP-06-R1): the verified runtime file
    /// digest + identity. Constructed by the loader from verify_file()'s
    /// identity; the placeholder can never appear here (fail-closed).
    ///
    /// `runtime echo consumer = NOT WIRED`: no V2 runtime export exists yet,
    /// so no runtime-returned digest is compared against this authority in
    /// any production path. The comparison API is
    /// `RuntimeDigestAuthority::verify_runtime_echo`; it is exercised only
    /// by unit/integration tests until the IMP-08 V2 wiring order lands.
    #[allow(dead_code)] // echo comparison wired in IMP-08 (NOT WIRED today)
    digest_authority: RuntimeDigestAuthority,
    target_pid: u32,
}

impl LoaderResult {
    /// Sealed constructor (IMP-06-R2): the loader (`run_runtime_loader`)
    /// is the only producer. Fields are private so a forged result cannot be
    /// assembled from fake identity/authority values.
    pub(crate) fn new(
        module_base: u64,
        attestation_json: String,
        file_identity: RuntimeFileIdentity,
        digest_authority: RuntimeDigestAuthority,
        target_pid: u32,
    ) -> Self {
        Self {
            module_base,
            attestation_json,
            file_identity,
            digest_authority,
            target_pid,
        }
    }

    /// Target process id the runtime was loaded into.
    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }

    /// Attestation JSON returned by the runtime (evidence).
    pub fn attestation_json(&self) -> &str {
        &self.attestation_json
    }

    /// Verified runtime file identity (evidence; produced by verify_file()).
    pub fn file_identity(&self) -> &RuntimeFileIdentity {
        &self.file_identity
    }

    /// Production digest authority (never a placeholder).
    pub fn digest_authority(&self) -> &RuntimeDigestAuthority {
        &self.digest_authority
    }

    /// Module base in the target (evidence + controller cross-check).
    pub fn module_base(&self) -> u64 {
        self.module_base
    }
}

/// The anti-debug lifecycle driver.
#[derive(Debug)]
pub struct AntidebugController {
    state: ControllerState,
    log: EvidenceLog,
    options: AntidebugStageOptions,
    #[allow(dead_code)] // bound during ADR-4 runtime wiring
    profile: Option<Profile>,
    /// Cleanup outcome from the most recent run(); recorded in evidence.
    cleanup: Option<CleanupResult>,
    /// ADR-7-A-CAPTURE-1: last exception capture receipt from the drain
    /// window (exception_address, RIP/RSP, module base/RVA). Recorded in
    /// the failure evidence sidecar when present; None when no exception
    /// receipt was captured.
    capture_receipt: Option<mida_core::DrainReceipt>,
}

impl AntidebugController {
    pub fn new(options: AntidebugStageOptions) -> Self {
        Self {
            state: ControllerState::Unresolved,
            log: EvidenceLog::new(),
            options,
            profile: None,
            cleanup: None,
            capture_receipt: None,
        }
    }

    /// ADR-7-A-CAPTURE-1: record the last exception capture receipt from
    /// the drain window so the failure evidence sidecar can carry the
    /// full exception/module context (address, RIP/RSP, module base/RVA).
    pub fn set_capture_receipt(&mut self, receipt: mida_core::DrainReceipt) {
        self.capture_receipt = Some(receipt);
    }

    /// Inject the loader result (ADR-6). Called by the CREATE_PROCESS
    /// handler after the runtime loader ran against the suspended target.
    pub fn set_loader_result(&mut self, result: LoaderResult) {
        self.options.loader_result = Some(result);
    }

    /// Inject the explicit cleanup outcome (R1-HARDENING-CLEANUP-2).
    ///
    /// The production path runs `WindowsDebugger::terminate_and_wait()`
    /// ONCE (exactly-once ownership) and records the structured report
    /// here. The controller does not run a second independent termination
    /// backend: that produced duplicate cleanup (Drop cleanup issue) in
    /// R4B 12/12.
    pub fn set_cleanup_report(&mut self, report: &mida_core::cleanup::CleanupReport) {
        if report.is_clean() {
            self.cleanup = Some(CleanupResult::Ok);
        } else {
            let detail = report.summary();
            self.cleanup = Some(CleanupResult::Failed(detail.clone()));
            // Escalate to CleanupFailed when the explicit cleanup failed.
            self.escalate_cleanup_failed(format!("explicit cleanup failed: {detail}"));
        }
    }
    /// Current lifecycle state.
    #[allow(dead_code)] // used by tests and ADR-4 wiring
    pub fn state(&self) -> ControllerState {
        self.state
    }

    /// Evidence accumulated so far (successful events are retained on failure).
    #[allow(dead_code)] // used by tests and ADR-4 wiring
    pub fn evidence(&self) -> &EvidenceLog {
        &self.log
    }

    /// Drive one event through the lifecycle (pure transition + accumulation).
    fn drive(&mut self, event: ControllerEvent) {
        let seq = self.log.len() as u32 + 1;
        let result = transition(self.state, event, seq);
        self.state = result.next_state;
        self.log.extend(result.evidence_events);
        if let Some(code) = result.fail_code {
            log::log(
                LogType::Fatal,
                &format!(
                    "anti-debug controller failure: {:?} ({})",
                    self.state,
                    code.as_str()
                ),
            );
        }
    }

    /// Run the cleanup backend and upgrade to CleanupFailed when it fails.
    ///
    /// This is the explicit cleanup feedback seam (ADR-3B-CORRECTION): the
    /// controller does NOT rely on `Drop` warnings. Returns the cleanup
    /// result so callers can record it in evidence.
    fn run_cleanup(&mut self) -> CleanupResult {
        // R1-HARDENING-CLEANUP-2: the production path injects the explicit
        // cleanup report via set_cleanup_report() BEFORE run(). If a result
        // is already recorded, reuse it and do NOT run a second independent
        // termination backend (that produced duplicate cleanup in R4B).
        if let Some(existing) = &self.cleanup {
            return existing.clone();
        }
        let Some(backend) = &self.options.cleanup_backend else {
            // No backend configured (pure test path): treat as not-run;
            // production always supplies one.
            return CleanupResult::NotRun;
        };
        let target_pid = self.options.target_pid;
        let result = match backend.cleanup(target_pid) {
            Ok(()) => CleanupResult::Ok,
            Err(e) => {
                // Cleanup failed: escalate to CleanupFailed, fail-closed.
                self.escalate_cleanup_failed(e.message.clone());
                CleanupResult::Failed(e.message)
            }
        };
        self.cleanup = Some(result.clone());
        result
    }

    /// Escalate a cleanup failure to the CleanupFailed terminal state.
    ///
    /// The sealed pure state machine (ADR-3A, crates/antidebug) treats
    /// failure states as terminal and cannot express a failure-to-failure
    /// upgrade (CleanupFailed from an already-failed state). ADR-3B-CORRECTION
    /// requires cleanup failure to be the FINAL terminal state with
    /// FailCode::CleanupFailed, so the CLI controller performs the
    /// escalation explicitly and appends the evidence event itself.
    ///
    /// This is a documented seam, not a state-machine bypass: the lifecycle
    /// success path is unaffected, and the evidence log records the
    /// CleanupFailed event with its fail code for audit.
    fn escalate_cleanup_failed(&mut self, detail: String) {
        log::log(
            LogType::Fatal,
            &format!("anti-debug cleanup failed: {detail} (escalated to CleanupFailed)"),
        );
        let seq = self.log.len() as u32 + 1;
        let ev = mida_antidebug::evidence::EvidenceEvent::new(
            ControllerState::CleanupFailed,
            ControllerEvent::CleanupFailed,
            seq,
            Some(FailCode::CleanupFailed),
        );
        self.log.extend(std::iter::once(ev));
        self.state = ControllerState::CleanupFailed;
    }

    /// Resolve the anti-debug runtime dependency (ADR-6: real authority).
    ///
    /// Without an authority configured this stays fail-closed
    /// (DependencyUnavailable), preserving the ADR-3B placeholder semantics
    /// for tests and for configurations that do not ship a runtime.
    fn resolve_dependency(&mut self) {
        let Some(authority) = &self.options.runtime_authority else {
            // No authority configured: dependency unavailable -> fail closed.
            self.drive(ControllerEvent::DependenciesMissing);
            return;
        };
        let Some(runtime_path) = &self.options.runtime_path else {
            self.drive(ControllerEvent::DependenciesMissing);
            return;
        };
        match authority.verify_file(runtime_path) {
            Ok(_identity) => {
                // Identity verified: canonical path + size + sha256 + arch.
                self.drive(ControllerEvent::DependenciesVerified);
            }
            Err(e) => {
                log::log(
                    LogType::Fatal,
                    &format!("anti-debug runtime authority verification failed: {e}"),
                );
                let msg = e.to_string();
                if msg.contains("sha256") || msg.contains("size") {
                    self.drive(ControllerEvent::DependencyHashMismatch);
                } else if msg.contains("x64 only") {
                    self.drive(ControllerEvent::ArchitectureMismatch);
                } else {
                    self.drive(ControllerEvent::DependenciesMissing);
                }
            }
        }
    }

    /// Oracle-mode only: record that ScyllaHide would run as an oracle.
    fn note_oracle_if_requested(&self) {
        if let Some(oracle) = &self.options.oracle {
            log::log(
                LogType::Info,
                &format!(
                    "anti-debug oracle mode requested (source={SCYLLAHIDE_ORACLE_SOURCE});
                    oracle injector={} hook={} - not executed in ADR-3B (no live differential authorized)",
                    oracle.injector_path.display(),
                    oracle.hook_library_path.display(),
                ),
            );
        }
    }

    /// Run the anti-debug stage to completion.
    ///
    /// On failure: runs cleanup, upgrades to `CleanupFailed` when cleanup
    /// fails, and returns [`AntidebugOutcome::Failed`] with the final
    /// terminal state. Evidence is always accumulated.
    pub fn run(&mut self) -> AntidebugOutcome {
        self.note_oracle_if_requested();

        // Stage 1: dependency resolution (fails closed without a runtime).
        self.resolve_dependency();
        if self.state.is_failure() {
            let _code = self.fail_code_of_state(self.state);
            let message = format!(
                "anti-debug runtime dependency unavailable: {} not found;
                fail-closed (MIDA runtime ships in ADR-4+)",
                MIDA_RUNTIME_ARTIFACT,
            );
            // Explicit cleanup + CleanupFailed escalation.
            let cleanup_result = self.run_cleanup();
            if let CleanupResult::Failed(detail) = &cleanup_result {
                log::log(
                    LogType::Fatal,
                    &format!("anti-debug cleanup failed: {detail} (upgraded to CleanupFailed)"),
                );
            }
            return AntidebugOutcome::Failed {
                state: self.state,
                fail_code: self.fail_code_of_state(self.state),
                message,
            };
        }

        // Stages 2-10: driven from the real loader result when present.
        // ADR-6: the CREATE_PROCESS handler runs the loader and injects the
        // attestation; the controller consumes it. Without a loader result
        // the lifecycle fails closed at RuntimeLoadFailed (no blind Proceed).
        let Some(loader) = self.options.loader_result.clone() else {
            self.drive(ControllerEvent::RuntimeLoadFailed);
            let message = format!(
                "anti-debug runtime not loaded: no loader result injected (state={:?})",
                self.state
            );
            let cleanup_result = self.run_cleanup();
            if let CleanupResult::Failed(detail) = &cleanup_result {
                log::log(
                    LogType::Fatal,
                    &format!("anti-debug cleanup failed: {detail} (upgraded to CleanupFailed)"),
                );
            }
            return AntidebugOutcome::Failed {
                state: self.state,
                fail_code: self.fail_code_of_state(self.state),
                message,
            };
        };

        // Identity cross-checks against the loader result.
        if loader.target_pid() != self.options.target_pid {
            self.drive(ControllerEvent::TargetIdentityRejected);
            return AntidebugOutcome::Failed {
                state: self.state,
                fail_code: self.fail_code_of_state(self.state),
                message: format!(
                    "loader target pid {} != controller target pid {}",
                    loader.target_pid(), self.options.target_pid
                ),
            };
        }

        // Parse + validate the attestation (transport parse; validate is the
        // decision gate).
        let att = match mida_antidebug_runtime::attestation::RuntimeAttestation::from_canonical_json(
            loader.attestation_json(),
        ) {
            Ok(a) => a,
            Err(e) => {
                self.drive(ControllerEvent::RuntimeInitFailed);
                return AntidebugOutcome::Failed {
                    state: self.state,
                    fail_code: self.fail_code_of_state(self.state),
                    message: format!("attestation parse failed: {e}"),
                };
            }
        };
        match att.validate() {
            Ok(()) => {}
            Err(e) => {
                self.drive(ControllerEvent::HealthCheckFailed);
                return AntidebugOutcome::Failed {
                    state: self.state,
                    fail_code: self.fail_code_of_state(self.state),
                    message: format!("attestation validate failed: {e}"),
                };
            }
        }

        // Drive the success path.
        self.drive(ControllerEvent::ProfileValidated);
        self.drive(ControllerEvent::TargetIdentityValidated);
        self.drive(ControllerEvent::LaunchPrepared);
        self.drive(ControllerEvent::RuntimeLoadStarted);
        self.drive(ControllerEvent::RuntimeInitialized);
        self.drive(ControllerEvent::HealthCheckStarted);
        self.drive(ControllerEvent::HealthCheckPassed);
        self.drive(ControllerEvent::ProbeSetPassed);
        self.drive(ControllerEvent::ProceedApproved);

        if self.state.is_proceed() {
            AntidebugOutcome::Proceed {
                final_state: self.state,
            }
        } else {
            let code = self.fail_code_of_state(self.state);
            AntidebugOutcome::Failed {
                state: self.state,
                fail_code: code,
                message: format!(
                    "anti-debug lifecycle stopped at {:?} ({})",
                    self.state,
                    code.as_str()
                ),
            }
        }
    }

    /// Map a terminal failure state to its fail code (ADR-3B table).
    pub fn fail_code_of_state(&self, state: ControllerState) -> FailCode {
        match state {
            ControllerState::DependencyUnavailable => FailCode::AntiDebugRuntimeUnavailable,
            ControllerState::DependencyIdentityMismatch
            | ControllerState::TargetIdentityMismatch => FailCode::AntiDebugRuntimeIdentityMismatch,
            ControllerState::ArchitectureMismatch => FailCode::AntiDebugRuntimeArchitectureMismatch,
            ControllerState::ProfileMismatch => FailCode::AntiDebugProfileMismatch,
            ControllerState::RuntimeLoadFailed => FailCode::AntiDebugRuntimeUnavailable,
            ControllerState::RuntimeInitializationFailed => {
                FailCode::AntiDebugRuntimeInitializationFailed
            }
            ControllerState::PartialHooks => FailCode::AntiDebugRuntimePartialHooks,
            ControllerState::TelemetryLost => FailCode::AntiDebugRuntimeTelemetryLost,
            ControllerState::ProbeInconsistent => FailCode::ProbeInconsistent,
            ControllerState::CleanupFailed => FailCode::CleanupFailed,
            _ => FailCode::AntiDebugRuntimeUnavailable,
        }
    }

    /// Build the failure evidence record from the current outcome.
    pub fn failure_evidence(&self, outcome: &AntidebugOutcome) -> Option<AntidebugFailureEvidence> {
        let AntidebugOutcome::Failed {
            state,
            fail_code,
            message: _,
        } = outcome
        else {
            return None;
        };
        Some(AntidebugFailureEvidence {
            schema: ANTIDEBUG_EVIDENCE_SCHEMA.to_string(),
            record_kind: EVIDENCE_RECORD_KIND_CLI_FAILURE.to_string(),
            decision: "fail-closed".to_string(),
            controller_state_before: "Unresolved".to_string(),
            failure_state: format!("{state:?}"),
            fail_code: fail_code.as_str().to_string(),
            sample_id: self.options.sample_id.clone(),
            target_pid: Some(self.options.target_pid),
            runtime_identity: None,
            profile_id: None,
            profile_digest: None,
            sequence: self.log.len() as u32,
            cleanup_result: self
                .cleanup
                .as_ref()
                .map(|c| c.as_str().to_string())
                .unwrap_or_else(|| CleanupResult::NotRun.as_str().to_string()),
            cleanup_detail: match &self.cleanup {
                Some(CleanupResult::Failed(d)) => Some(d.clone()),
                _ => None,
            },
            candidate_created: false,
            exception_code: self.capture_receipt.as_ref().and_then(|r| r.exception_code),
            exception_thread_id: self.capture_receipt.as_ref().map(|r| r.thread_id),
            first_chance: self.capture_receipt.as_ref().and_then(|r| r.first_chance),
            exception_address: self
                .capture_receipt
                .as_ref()
                .and_then(|r| r.exception_address)
                .map(|a| format!("{a:#x}")),
            instruction_pointer: self
                .capture_receipt
                .as_ref()
                .and_then(|r| r.instruction_pointer)
                .map(|a| format!("{a:#x}")),
            stack_pointer: self
                .capture_receipt
                .as_ref()
                .and_then(|r| r.stack_pointer)
                .map(|a| format!("{a:#x}")),
            faulting_module: self
                .capture_receipt
                .as_ref()
                .and_then(|r| r.faulting_module.clone()),
            faulting_module_base: self
                .capture_receipt
                .as_ref()
                .and_then(|r| r.faulting_module_base)
                .map(|b| format!("{b:#x}")),
            faulting_module_rva: self
                .capture_receipt
                .as_ref()
                .and_then(|r| r.faulting_module_rva)
                .map(|v| format!("{v:#x}")),
            context_capture_error: self
                .capture_receipt
                .as_ref()
                .and_then(|r| r.context_capture_error.clone()),
        })
    }
}

/// Write the failure evidence sidecar (atomic: write temp + rename).
///
/// Fail-closed: an evidence write failure returns `Err` so the caller
/// cannot proceed as if evidence were recorded.
pub fn write_failure_evidence(
    evidence: &AntidebugFailureEvidence,
    dir: &Path,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let dir = dir.to_path_buf();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(evidence)?;
    let tmp = dir.join("mida_antidebug_failure.evidence.json.tmp");
    let final_path = dir.join("mida_antidebug_failure.evidence.json");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &final_path)?;
    Ok(final_path)
}

/// Structured evidence for the GTO observation-only research channel
/// (schema `mida.gto-observation-only/v1`).
///
/// This record tags a run that deliberately skipped runtime injection and the
/// anti-debug controller gate (H3 option 1): the cold-start heap/container
/// epoch was captured with debugger-side reads ONLY. It is research evidence,
/// never a product verdict — acceptance kernels must treat
/// `candidate_created=false` + `observation_only=true` as fail-closed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ObservationOnlyEvidence {
    pub schema: String,
    pub record_kind: String,
    pub target_pid: Option<u32>,
    pub observation_only: bool,
    pub runtime_injected: bool,
    pub candidate_created: bool,
    pub wall: String,
    pub note: String,
    pub recorded_utc: String,
}

impl ObservationOnlyEvidence {
    pub fn new(target_pid: u32) -> Self {
        Self {
            schema: "mida.gto-observation-only/v1".to_string(),
            record_kind: "observation-only".to_string(),
            target_pid: Some(target_pid),
            observation_only: true,
            runtime_injected: false,
            candidate_created: false,
            wall: "GTO cold-start heap-rebasing wall (H3 option 1)".to_string(),
            note: "debugger-side read-only observation; runtime injection skipped; \
                   no product candidate claimed; target terminated after observation"
                .to_string(),
            recorded_utc: {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                format!("{now}s-utc")
            },
        }
    }
}

/// Write the observation-only evidence sidecar (atomic: write temp + rename).
pub fn write_observation_only_evidence(
    evidence: &ObservationOnlyEvidence,
    dir: &Path,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let dir = dir.to_path_buf();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(evidence)?;
    let tmp = dir.join("observation_only_evidence.json.tmp");
    let final_path = dir.join("observation_only_evidence.json");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &final_path)?;
    Ok(final_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock cleanup backend that always succeeds.
    #[derive(Debug)]
    struct OkCleanup;
    impl CleanupBackend for OkCleanup {
        fn cleanup(&self, _pid: u32) -> Result<(), CleanupError> {
            Ok(())
        }
    }

    /// Mock cleanup backend that always fails with a fixed detail.
    #[derive(Debug)]
    struct FailCleanup;
    impl CleanupBackend for FailCleanup {
        fn cleanup(&self, _pid: u32) -> Result<(), CleanupError> {
            Err(CleanupError::new("mock terminate refused"))
        }
    }

    fn options_with(
        temp: &std::path::Path,
        backend: Box<dyn CleanupBackend>,
    ) -> AntidebugStageOptions {
        AntidebugStageOptions {
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: Some(temp.to_path_buf()),
            oracle: None,
            cleanup_backend: Some(backend),
            runtime_authority: None,
            runtime_path: None,
            loader_result: None,
        }
    }

    #[test]
    fn no_runtime_fails_closed_with_unavailable_and_cleanup_ok() {
        let temp = std::env::temp_dir().join("mida-adr3bc-test-noruntime");
        let _ = std::fs::remove_dir_all(&temp);
        let mut c = AntidebugController::new(options_with(&temp, Box::new(OkCleanup)));
        let outcome = c.run();
        match &outcome {
            AntidebugOutcome::Failed {
                state, fail_code, ..
            } => {
                // cleanup ok -> original failure state preserved
                assert_eq!(*state, ControllerState::DependencyUnavailable);
                assert_eq!(*fail_code, FailCode::AntiDebugRuntimeUnavailable);
            }
            other => panic!("expected failure, got {other:?}"),
        }
        // failure state terminal: cannot reach Proceed
        let r = transition(c.state(), ControllerEvent::ProceedApproved, 99);
        assert!(!r.next_state.is_proceed());
        // evidence accumulated and monotonic
        assert!(!c.evidence().events().is_empty());
        assert!(c.evidence().has_failure());
        assert_eq!(
            c.evidence().first_fail_code(),
            Some(FailCode::AntiDebugRuntimeUnavailable)
        );
        // evidence carries cleanup_result=ok
        let ev = c.failure_evidence(&outcome).unwrap();
        assert_eq!(ev.cleanup_result, "ok");
        assert!(!ev.candidate_created);
        assert_eq!(ev.schema, ANTIDEBUG_EVIDENCE_SCHEMA);
        assert_eq!(ev.record_kind, EVIDENCE_RECORD_KIND_CLI_FAILURE);
        assert_eq!(ev.decision, "fail-closed");
    }

    #[test]
    fn cleanup_failure_upgrades_to_cleanup_failed() {
        let temp = std::env::temp_dir().join("mida-adr3bc-test-cleanupfail");
        let _ = std::fs::remove_dir_all(&temp);
        let mut c = AntidebugController::new(options_with(&temp, Box::new(FailCleanup)));
        let outcome = c.run();
        match &outcome {
            AntidebugOutcome::Failed {
                state, fail_code, ..
            } => {
                // cleanup failed -> upgraded to CleanupFailed
                assert_eq!(*state, ControllerState::CleanupFailed);
                assert_eq!(*fail_code, FailCode::CleanupFailed);
            }
            other => panic!("expected failure, got {other:?}"),
        }
        // fail code from evidence matches
        let ev = c.failure_evidence(&outcome).unwrap();
        assert_eq!(ev.fail_code, "CleanupFailed");
        assert_eq!(ev.failure_state, "CleanupFailed");
        assert_eq!(ev.cleanup_result, "failed");
        assert_eq!(ev.cleanup_detail.as_deref(), Some("mock terminate refused"));
        assert!(!ev.candidate_created);
        // terminal: no escape
        let r = transition(c.state(), ControllerEvent::ProceedApproved, 1);
        assert!(!r.next_state.is_proceed());
    }

    #[test]
    fn observation_only_evidence_writes_and_fails_closed_on_acceptance() {
        let temp = std::env::temp_dir().join("mida-gto-observation-only-test");
        let _ = std::fs::remove_dir_all(&temp);
        let ev = ObservationOnlyEvidence::new(1234);
        assert!(ev.observation_only);
        assert!(!ev.runtime_injected);
        assert!(!ev.candidate_created);
        assert_eq!(ev.schema, "mida.gto-observation-only/v1");
        assert_eq!(ev.target_pid, Some(1234));
        let path = write_observation_only_evidence(&ev, &temp).unwrap();
        assert!(path.is_file());
        let written: ObservationOnlyEvidence =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(written.observation_only);
        assert!(!written.candidate_created);
        // acceptance fail-closed contract: no product verdict possible
        assert!(!written.candidate_created && written.observation_only);
        let _ = std::fs::remove_dir_all(&temp);
    }

    #[test]
    fn cleanup_ok_preserves_original_failure_state() {
        let temp = std::env::temp_dir().join("mida-adr3bc-test-cleanupok");
        let _ = std::fs::remove_dir_all(&temp);
        let mut c = AntidebugController::new(options_with(&temp, Box::new(OkCleanup)));
        let outcome = c.run();
        let AntidebugOutcome::Failed { state, .. } = outcome else {
            panic!("expected failure");
        };
        // NOT upgraded: original failure state stays DependencyUnavailable
        assert_eq!(state, ControllerState::DependencyUnavailable);
        assert!(!state.is_proceed());
    }

    #[test]
    fn failure_evidence_file_written_atomically_and_roundtrips() {
        let temp = std::env::temp_dir().join("mida-adr3bc-test-evidence");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let ev = AntidebugFailureEvidence {
            schema: ANTIDEBUG_EVIDENCE_SCHEMA.to_string(),
            record_kind: EVIDENCE_RECORD_KIND_CLI_FAILURE.to_string(),
            decision: "fail-closed".to_string(),
            controller_state_before: "Unresolved".to_string(),
            failure_state: "DependencyUnavailable".to_string(),
            fail_code: FailCode::AntiDebugRuntimeUnavailable.as_str().to_string(),
            sample_id: Some("origin_macro".to_string()),
            target_pid: Some(1234),
            runtime_identity: None,
            profile_id: Some("oreans_origin_x64_v1".to_string()),
            profile_digest: Some("deadbeef".to_string()),
            sequence: 3,
            cleanup_result: "ok".to_string(),
            cleanup_detail: None,
            candidate_created: false,
            exception_code: None,
            exception_thread_id: Some(7777),
            first_chance: None,
            exception_address: None,
            instruction_pointer: None,
            stack_pointer: None,
            faulting_module: None,
            faulting_module_base: None,
            faulting_module_rva: None,
            context_capture_error: None,
        };
        let p = write_failure_evidence(&ev, &temp).unwrap();
        assert!(p.exists());
        // JSON round-trip
        let back: AntidebugFailureEvidence =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(back.fail_code, "AntiDebugRuntimeUnavailable");
        assert!(!back.candidate_created);
        assert_eq!(back.schema, ANTIDEBUG_EVIDENCE_SCHEMA);
        assert_eq!(back.exception_thread_id, Some(7777));
        assert_eq!(back.record_kind, EVIDENCE_RECORD_KIND_CLI_FAILURE);
        assert_eq!(back.decision, "fail-closed");
    }

    #[test]
    fn evidence_write_failure_is_fail_closed() {
        let temp = std::env::temp_dir().join("mida-adr3bc-test-evidence-fail");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let blocker = temp.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let ev = AntidebugFailureEvidence {
            schema: ANTIDEBUG_EVIDENCE_SCHEMA.to_string(),
            record_kind: EVIDENCE_RECORD_KIND_CLI_FAILURE.to_string(),
            decision: "fail-closed".to_string(),
            controller_state_before: "Unresolved".to_string(),
            failure_state: "DependencyUnavailable".to_string(),
            fail_code: "AntiDebugRuntimeUnavailable".to_string(),
            sample_id: None,
            target_pid: Some(1),
            runtime_identity: None,
            profile_id: None,
            profile_digest: None,
            sequence: 1,
            cleanup_result: "not-run".to_string(),
            cleanup_detail: None,
            candidate_created: false,
            exception_code: None,
            exception_thread_id: None,
            first_chance: None,
            exception_address: None,
            instruction_pointer: None,
            stack_pointer: None,
            faulting_module: None,
            faulting_module_base: None,
            faulting_module_rva: None,
            context_capture_error: None,
        };
        // blocker is a file: create_dir_all fails -> Err
        let r = write_failure_evidence(&ev, &blocker);
        assert!(r.is_err());
    }

    #[test]
    fn oracle_mode_never_silently_falls_back() {
        let temp = std::env::temp_dir().join("mida-adr3bc-test-oracle");
        let _ = std::fs::remove_dir_all(&temp);
        let mut c = AntidebugController::new(AntidebugStageOptions {
            sample_id: Some("origin_macro".to_string()),
            target_pid: 42,
            evidence_dir: Some(temp.clone()),
            oracle: Some(OracleMode {
                injector_path: std::path::PathBuf::from("C:\\vault\\InjectorCLIx64.exe"),
                hook_library_path: std::path::PathBuf::from("C:\\vault\\HookLibraryx64.dll"),
                ini_path: None,
            }),
            cleanup_backend: Some(Box::new(OkCleanup)),
            runtime_authority: None,
            runtime_path: None,
            loader_result: None,
        });
        let outcome = c.run();
        // Oracle mode still fails closed: no runtime, no proceed.
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
        assert!(c.state().is_failure());
    }

    #[test]
    fn fail_code_mapping_table() {
        let c = AntidebugController::new(AntidebugStageOptions {
            sample_id: None,
            target_pid: 1,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: None,
            runtime_path: None,
            loader_result: None,
        });
        assert_eq!(
            c.fail_code_of_state(ControllerState::DependencyUnavailable),
            FailCode::AntiDebugRuntimeUnavailable
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::DependencyIdentityMismatch),
            FailCode::AntiDebugRuntimeIdentityMismatch
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::ArchitectureMismatch),
            FailCode::AntiDebugRuntimeArchitectureMismatch
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::ProfileMismatch),
            FailCode::AntiDebugProfileMismatch
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::RuntimeInitializationFailed),
            FailCode::AntiDebugRuntimeInitializationFailed
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::PartialHooks),
            FailCode::AntiDebugRuntimePartialHooks
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::TelemetryLost),
            FailCode::AntiDebugRuntimeTelemetryLost
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::ProbeInconsistent),
            FailCode::ProbeInconsistent
        );
        assert_eq!(
            c.fail_code_of_state(ControllerState::CleanupFailed),
            FailCode::CleanupFailed
        );
    }

    // ---------------------------------------------------------------
    // IMP-06-R2: loader-result lifecycle tests (identity + authority
    // produced ONLY via the real verify_file() path — sealed types)
    // ---------------------------------------------------------------

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let d = h.finalize();
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Minimal valid x64 PE (MZ + PE sig + Machine=AMD64 + PE32+ magic).
    fn minimal_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x100];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        b
    }

    fn manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
        RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        }
    }

    fn default_attestation_json() -> String {
        serde_json::json!({
            "schema": "mida.antidebug-runtime-attestation/v1",
            "runtime_id": "mida-antidebug-runtime-x64",
            "runtime_version": "0.1.0",
            "architecture": "x86_64",
            "runtime_sha256": "ab".repeat(32),
            "profile_id": "oreans_origin_x64_v1",
            "profile_digest": "adr6-profile-digest",
            "target_pid": 1234,
            "module_base": 0x7000,
            "initialized": true,
            "hooks_expected": ["AD-PROC-002", "AD-PROC-003"],
            "hooks_installed": ["AD-PROC-002", "AD-PROC-003"],
            "hook_failures": [],
            "surface_details": [],
            "telemetry_channel": "ready",
            "cleanup_handler_registered": true,
            "third_party": "build-and-serialization-only",
            "source_revision": "0.1.0",
            "toolchain": "rustc",
        })
        .to_string()
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    static FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn next_file(name: &str) -> std::path::PathBuf {
        let n = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join("mida-adr6-test")
            .join(format!("{name}_{}_{n}.dll", std::process::id()))
    }

    fn loader_result_with(target_pid: u32, attestation_json: String) -> LoaderResult {
        // IMP-06-R2: the identity + authority MUST come from the real
        // verify_file() path (no forged literals):
        //   real PE file -> manifest -> verify_file() -> identity -> authority.
        let content = minimal_pe();
        let _ = std::fs::create_dir_all(std::env::temp_dir().join("mida-adr6-test"));
        let p = next_file("loader_runtime");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&sha256_hex(&content), content.len() as u64);
        let identity = authority.verify_file(&p).unwrap();
        let digest_authority = RuntimeDigestAuthority::from_verified_identity(
            &identity,
            &authority.artifact_id,
        )
        .expect("verified identity must build a valid authority");
        LoaderResult::new(0x7000, attestation_json, identity, digest_authority, target_pid)
    }

    fn controller_with_loader_result(loader: Option<LoaderResult>) -> AntidebugController {
        let content = minimal_pe();
        let _ = std::fs::create_dir_all(std::env::temp_dir().join("mida-adr6-test"));
        let p = next_file("r");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&sha256_hex(&content), content.len() as u64);
        AntidebugController::new(AntidebugStageOptions {
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: Some(authority),
            runtime_path: Some(p),
            loader_result: loader,
        })
    }

    #[test]
    fn imp06_controller_proceeds_with_valid_loader_result() {
        let mut c = controller_with_loader_result(Some(loader_result_with(
            1234,
            default_attestation_json(),
        )));
        let outcome = c.run();
        match &outcome {
            AntidebugOutcome::Failed {
                state,
                fail_code,
                message,
            } => panic!(
                "expected Proceed, got Failed state={state:?} code={} msg={message}",
                fail_code.as_str()
            ),
            _ => {}
        }
        assert!(matches!(outcome, AntidebugOutcome::Proceed { .. }));
    }

    #[test]
    fn imp06_controller_fails_closed_without_loader_result() {
        let mut c = controller_with_loader_result(None);
        let outcome = c.run();
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
    }

    #[test]
    fn imp06_controller_fails_closed_on_target_pid_mismatch() {
        let loader = loader_result_with(9999, default_attestation_json());
        let mut c = controller_with_loader_result(Some(loader));
        let outcome = c.run();
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
    }

    #[test]
    fn imp06_controller_fails_closed_on_bad_attestation() {
        let loader = loader_result_with(1234, "{ not json".to_string());
        let mut c = controller_with_loader_result(Some(loader));
        let outcome = c.run();
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
    }

    #[test]
    fn imp06_controller_fails_closed_on_incomplete_attestation() {
        // hooks_installed missing AD-PROC-003 -> validate fails -> PartialHooks.
        let loader = loader_result_with(
            1234,
            serde_json::json!({
                "schema": "mida.antidebug-runtime-attestation/v1",
                "runtime_id": "mida-antidebug-runtime-x64",
                "runtime_version": "0.1.0",
                "architecture": "x86_64",
                "runtime_sha256": "ab".repeat(32),
                "profile_id": "oreans_origin_x64_v1",
                "profile_digest": "adr6-profile-digest",
                "target_pid": 1234,
                "module_base": 0x7000,
                "initialized": true,
                "hooks_expected": ["AD-PROC-002", "AD-PROC-003"],
                "hooks_installed": ["AD-PROC-002"],
                "hook_failures": [{"surface_id": "AD-PROC-003", "reason": "failed"}],
                "surface_details": [],
                "telemetry_channel": "ready",
                "cleanup_handler_registered": true,
                "third_party": "build-and-serialization-only",
                "source_revision": "0.1.0",
                "toolchain": "rustc",
            })
            .to_string(),
        );
        let mut c = controller_with_loader_result(Some(loader));
        let outcome = c.run();
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
    }

    #[test]
    fn imp06_controller_authority_mismatch_fails_before_loader() {
        let content = minimal_pe();
        let dir = std::env::temp_dir().join("mida-adr6-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = next_file("mismatch");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&"cd".repeat(32), content.len() as u64); // wrong digest
        let mut c = AntidebugController::new(AntidebugStageOptions {
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: Some(authority),
            runtime_path: Some(p),
            loader_result: Some(loader_result_with(1234, default_attestation_json())),
        });
        let outcome = c.run();
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
    }
}
