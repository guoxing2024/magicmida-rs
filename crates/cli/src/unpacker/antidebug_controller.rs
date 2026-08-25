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
use windows::Win32::Foundation::HANDLE;

use crate::log::{self, LogType};
use crate::unpacker::runtime_loader::{
    RuntimeAuthorityManifest, RuntimeDigestAuthority, RuntimeFileIdentity,
};
use crate::unpacker::walker_session::{
    probe_process_liveness, prove_candidate_mappings, CandidateMappingProofSet, LivenessProbe,
    WalkerDispatchBridge,
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
/// IMP-09-CARRIER-R5-R1 P1: RAII teardown for the walker session.
///
/// Constructed at the top of [`AntidebugController::run`]; on Drop it
/// frees the target-side walker allocations (params + both-round
/// section region) if the controller still holds them. This makes
/// every run() exit path — success, early return, panic/unwind —
/// release the remote memory exactly once (cleanup is idempotent).
///
/// # Safety
/// Holds a raw pointer to the controller's `walker_mem` field. The
/// guard is a local of run() and drops before the controller is ever
/// dropped; no other thread can touch the field (single-threaded
/// lifecycle). The pointer is only used through `Option::take`, so
/// the field becomes None after the first drop (idempotent).
struct WalkerTeardownGuard {
    mem_ptr: *mut Option<crate::unpacker::walker_session::WalkerSessionMemory>,
    handle: Option<HANDLE>,
}

impl WalkerTeardownGuard {
    fn new(c: &mut AntidebugController) -> Self {
        let mem_ptr =
            &mut c.walker_mem as *mut Option<crate::unpacker::walker_session::WalkerSessionMemory>;
        let handle = c.options.target_handle;
        Self { mem_ptr, handle }
    }
}

impl Drop for WalkerTeardownGuard {
    fn drop(&mut self) {
        // SAFETY: see struct docs. The controller outlives the guard;
        // the field access is exclusive (single-threaded lifecycle).
        unsafe {
            if let Some(mem) = (*self.mem_ptr).take() {
                if let Some(h) = self.handle {
                    let mut mem = mem;
                    mem.cleanup(h);
                }
            }
        }
    }
}
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
    /// IMP-09-CARRIER-R5-R2-4: monotonic raw walker event sequence
    /// (loader_complete, bind_enter, bind_exit, execute_enter,
    /// execute_exit, terminate_enter) with the raw WalkerExecute status.
    pub walker_events: Vec<WalkerRawEvent>,
    /// IMP-09-CARRIER-R5-R2-3: per-candidate pre-bind mapping proof
    /// (canonical VA, image envelope, MEM_COMMIT, region bounds, page
    /// span, readable protection). None when no proof was attempted.
    pub candidate_mapping: Option<CandidateMappingProofSet>,
    /// IMP-09-CARRIER-R5-R2-1: liveness probe result from the bind window.
    pub liveness_probe: Option<String>,
}

/// IMP-09-CARRIER-R5-R2-4: one raw walker lifecycle event.
///
/// The production path records a monotonic sequence (1-based) covering the
/// provably-alive window AND the termination window:
/// `loader_complete` -> `bind_enter` -> `bind_exit` ->
/// `execute_enter` -> `execute_exit` -> `terminate_enter`.
/// `walker_status_raw` carries the RAW i32 returned by the target-side
/// dispatch (never a boolean); non-OK statuses fail closed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalkerRawEvent {
    pub sequence: u32,
    pub phase: String,
    pub detail: Option<String>,
    pub walker_status_raw: Option<i32>,
}

/// Registered walker evidence schema (R5-R2 evidence contract).
pub const WALKER_EVIDENCE_SCHEMA: &str = "mida.antidebug-walker/v1";

/// Structured walker evidence record written by the production paths
/// (CREATE_PROCESS + post-attach) after the controller gate, covering the
/// alive-window bind/execute plus the termination entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalkerEvidenceRecord {
    pub schema: String,
    pub record_kind: String,
    pub target_pid: Option<u32>,
    /// Which production path captured this record: create_process or
    /// post_attach (R5-R2-2 capture_phase).
    pub capture_phase: String,
    /// Liveness probe result from the BIND window (R5-R2-1).
    pub liveness_probe: Option<String>,
    /// Liveness probe result from the EXECUTE window (R5-R2-1).
    pub execute_liveness: Option<String>,
    pub candidate_mapping: Option<CandidateMappingProofSet>,
    pub events: Vec<WalkerRawEvent>,
}

/// Outcome of the production walker execute gate (R5-R2-4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkerExecuteOutcome {
    /// Authorized target-side dispatch bridge returned WALKER_STATUS_OK and
    /// the marshaled V2 output was present. The output attestation is
    /// carried so the R5-R3 consumer gate can verify its digest closure.
    Success {
        output: mida_antidebug_runtime::attestation::RuntimeAttestationV2,
    },
    /// No authorized target-side dispatch bridge: NOT_IMPLEMENTED
    /// (fail-closed; in-process exports::WalkerExecute is engineering-only).
    NotImplemented,
    /// Dispatch returned a raw non-OK walker status.
    NonOk { raw_status: i32 },
    /// Dispatch returned OK but no walker output was marshaled back.
    OutputMissing,
}

/// Short stable name for an execute outcome (evidence/event detail).
fn execute_outcome_name(o: &WalkerExecuteOutcome) -> &'static str {
    match o {
        WalkerExecuteOutcome::Success { .. } => "Success",
        WalkerExecuteOutcome::NotImplemented => "NotImplemented",
        WalkerExecuteOutcome::NonOk { .. } => "NonOk",
        WalkerExecuteOutcome::OutputMissing => "OutputMissing",
    }
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
    /// IMP-09-CARRIER-R5-R1 P0-1: production target process handle.
    /// Injected by the debugger (CREATE_PROCESS / post-attach paths);
    /// used by the walker session (allocation, provider, teardown).
    /// None -> the walker binding stays NOT_WIRED (fail-closed).
    pub target_handle: Option<HANDLE>,
    /// Audited runtime authority manifest (ADR-6-CORRECTION). None keeps
    /// the old fail-closed placeholder behaviour (DependencyUnavailable).
    pub runtime_authority: Option<RuntimeAuthorityManifest>,
    /// Path to the runtime DLL to verify + load.
    pub runtime_path: Option<std::path::PathBuf>,
    /// Loader result injected by the CREATE_PROCESS handler after it ran the
    /// real loader (attestation JSON + module base + identity).
    pub loader_result: Option<LoaderResult>,
    /// IMP-09-CARRIER-R3: sealed verified TARGET-sample identity from the
    /// launch attestation (private fields, never Deserialize). None when the
    /// run had no preflight/attestation — the controller must fail closed
    /// (UNBOUND) rather than substitute any other digest.
    pub target_identity: Option<crate::runner_preflight::VerifiedTargetIdentity>,
    /// IMP-09-PROFILE-SOURCE-R1: sealed verified PROFILE identity from the
    /// launch attestation (profile_id + SHA-256 digest from the SAME profile
    /// object). None when the attested case has no profile object or no
    /// preflight ran — the controller must fail closed (UNBOUND) rather
    /// than substitute a bare-string profile identity.
    pub profile_identity: Option<crate::runner_preflight::VerifiedProfileIdentity>,
    /// IMP-09-CARRIER-R5-R2-4: AUTHORIZED target-side WalkerExecute
    /// dispatch bridge. Production wiring in R5-R2 ALWAYS passes None
    /// (live authorization is deferred to R5-R3/R5-R4): the controller
    /// then records + returns NOT_IMPLEMENTED (fail-closed) instead of
    /// calling the in-process engineering runtime. Tests inject a mock
    /// bridge to exercise the gate logic offline; a mock is never a
    /// live Windows PASS.
    pub walker_dispatch: Option<Box<dyn WalkerDispatchBridge>>,
    /// IMP-09-CARRIER-R5-R2-1: when true, run() MUST NOT fire the cleanup
    /// backend on failure — the caller drives the debugger termination
    /// (terminate_and_wait) after run() and injects the cleanup report.
    /// Production paths (CREATE_PROCESS + post-attach) set this so the
    /// walker bind/execute run in the provably-alive window BEFORE
    /// terminate_and_wait and the exactly-once cleanup evidence comes
    /// from the debugger report.
    pub defer_cleanup_to_caller: bool,
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
    /// IMP-09-CARRIER-R2: WalkerExecute export RVA resolved from the
    /// VERIFIED runtime DLL file bytes (pure-file resolver; NO live
    /// process access). Some() only after a fully validated pure-file
    /// resolution; None when the runtime file has no resolvable
    /// WalkerExecute export (loader itself still succeeds — the walker
    /// carrier is simply absent and binding fails closed).
    walker_export_rva: Option<u64>,
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
        walker_export_rva: Option<u64>,
    ) -> Self {
        Self {
            module_base,
            attestation_json,
            file_identity,
            digest_authority,
            target_pid,
            walker_export_rva,
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

    /// IMP-09-CARRIER-R2: sealed WalkerExecute export-RVA carrier.
    ///
    /// None when the verified runtime file has no resolvable
    /// WalkerExecute export; the controller MUST keep refusing to bind
    /// (fail-closed) in that case. The value (when present) was resolved
    /// by the pure-file export resolver over the verified runtime DLL
    /// bytes — never from a live process, never from a raw string.
    pub fn walker_export_rva(&self) -> Option<u64> {
        self.walker_export_rva
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
    /// IMP-09-CARRIER-R5: the live walker session memory owner (params +
    /// section allocations in the target). Held until teardown, then freed
    /// via `WalkerSessionMemory::cleanup`. None when no session is
    /// installed (UNBOUND / NOT_WIRED).
    walker_mem: Option<crate::unpacker::walker_session::WalkerSessionMemory>,
    /// IMP-09-CARRIER-R5-R2-4: monotonic raw walker event record.
    walker_events: Vec<WalkerRawEvent>,
    /// IMP-09-CARRIER-R5-R2-3: last candidate mapping proof set (kept even
    /// on failure for evidence).
    candidate_mapping: Option<CandidateMappingProofSet>,
    /// IMP-09-CARRIER-R5-R2-1: liveness probe from the bind window.
    liveness_probe: Option<LivenessProbe>,
    /// IMP-09-CARRIER-R5-R2-1: liveness probe from the execute window.
    execute_liveness: Option<LivenessProbe>,
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
            walker_mem: None,
            walker_events: Vec::new(),
            candidate_mapping: None,
            liveness_probe: None,
            execute_liveness: None,
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

    /// IMP-09-R4-R2: install the walker session from the SEALED loader
    /// digest authority (provenance caller).
    ///
    /// The ONLY production caller of
    /// `mida_antidebug_runtime::exports::install_walker_session_verified`:
    /// the digest values come from [`LoaderResult::digest_authority`]
    /// which is constructed exclusively by
    /// [`RuntimeDigestAuthority::from_verified_identity`] from a
    /// [`RuntimeFileIdentity`] produced by
    /// [`RuntimeAuthorityManifest::verify_file`]. Raw caller strings
    /// cannot reach this path — the authority is sealed and its fields are
    /// private.
    ///
    /// Caller graph (file:line evidence):
    /// ```text
    /// RuntimeAuthorityManifest::verify_file (runtime_loader.rs)
    ///   -> RuntimeFileIdentity (sealed)
    ///   -> RuntimeDigestAuthority::from_verified_identity (sealed)
    ///   -> LoaderResult (sealed ctor)
    ///   -> AntidebugController::bind_walker_from_loader (THIS method)
    ///   -> install_walker_session_verified (exports.rs)
    ///   -> install_walker_session (pub(crate), transactional)
    ///   -> WalkerDigestAuthority (walker_control.rs)
    /// ```
    pub fn bind_walker_from_loader(
        &mut self,
        target: HANDLE,
        candidates: &[u64],
        result_nonce: u64,
    ) -> bool {
        use crate::unpacker::walker_session::install_walker_session_production;
        // IMP-09-R1-R4: EXACT authority source matrix. Every field must
        // come from its sealed source; substitution is FORBIDDEN.
        let Some(loader) = self.options.loader_result.as_ref() else {
            return false;
        };
        let da = loader.digest_authority();
        // target_image_sha256: the verified TARGET SAMPLE digest. Without
        // it we MUST refuse — never substitute the runtime digest.
        let Some(target_image_sha256) = self.target_image_sha256() else {
            return false;
        };
        // IMP-09-CARRIER-R3: target digest must NEVER equal the runtime
        // DLL digest (distinct artifacts, distinct chains).
        if target_image_sha256.eq_ignore_ascii_case(da.digest_value()) {
            return false;
        }
        // profile_id / profile_digest from the sealed profile carrier.
        let Some(profile_id) = self.verified_profile_id() else {
            return false;
        };
        let Some(profile_digest) = self.verified_profile_digest() else {
            return false;
        };
        // walker_export_rva from the sealed pure-file resolver carrier.
        let Some(walker_export_rva) = self.resolved_walker_export_rva() else {
            return false;
        };
        // Candidates must be non-empty and bounded (protocol: 1..=4096).
        if candidates.is_empty() || candidates.len() > 4096 {
            return false;
        }
        // Production carriers: allocate + write + provider + install in
        // one transaction; any failure frees both allocations (no READY).
        let Some(mem) = install_walker_session_production(
            target,
            loader.target_pid(),
            std::process::id(), // owner_pid: REAL controller PID
            candidates,
            result_nonce,
            0,  // options_flags: none (frozen default)
            16, // probe_span: FROZEN protocol width
            target_image_sha256,
            da.digest_value(),
            loader.module_base(),
            walker_export_rva,
            profile_id,
            profile_digest,
        ) else {
            return false;
        };
        // Retain the owner: allocations live exactly as long as the
        // controller-held session. Teardown frees them (see
        // teardown_walker_session).
        self.walker_mem = Some(mem);
        true
    }
    /// IMP-09-CARRIER-R5-R1 P0-1 / R5-R2: production bind entry point
    /// (real lifecycle caller). Returns true iff the session reached READY.
    ///
    /// Candidate list: derived from the VERIFIED runtime module base in
    /// the target (real mapped pages: module base + 0/0x1000/0x2000/0x3000),
    /// restricted to the VERIFIED image envelope
    /// [module_base, module_base + verified_size_of_image).
    ///
    /// R5-R2-1: the target must be provably ALIVE (GetExitCodeProcess ==
    /// STILL_ACTIVE) before any bind — unknown/dead fails closed.
    /// R5-R2-2/3: every candidate gets a per-item VirtualQueryEx mapping
    /// proof (canonical VA, envelope, MEM_COMMIT, region bounds, page
    /// span, readable protection) BEFORE
    /// `install_walker_session_production()`; any item failing rejects
    /// the whole candidate set. The proof set is retained on the
    /// controller for evidence even when the bind fails.
    fn bind_walker_from_loader_production(&mut self) -> bool {
        let Some(handle) = self.options.target_handle else {
            self.liveness_probe = Some(LivenessProbe::Unknown);
            return false;
        };
        let Some(loader) = self.options.loader_result.as_ref() else {
            self.liveness_probe = Some(LivenessProbe::Unknown);
            return false;
        };
        // R5-R2-1: liveness window proof. Never bind a dead/unknown target.
        let liveness = probe_process_liveness(handle);
        self.liveness_probe = Some(liveness);
        if liveness != LivenessProbe::Alive {
            return false;
        }
        let base = loader.module_base();
        // Fail-closed: a zero/noncanonical base can never happen (the
        // loader verified the runtime), but never derive from garbage.
        if base == 0 || base > 0x0000_7FFF_FFFF_FFFF {
            return false;
        }
        // R5-R2-3: the image envelope MUST come from the VERIFIED file
        // identity (sealed at verify_file time), never from a live-process
        // header. 0 / missing -> no envelope -> fail closed.
        let image_size = loader.file_identity().verified_size_of_image();
        if image_size < 0x1000 {
            return false;
        }
        let envelope_end = match base.checked_add(image_size) {
            Some(v) if v > base => v,
            _ => return false,
        };
        // Candidates: base + k*0x1000 for k in 0..4, all inside envelope.
        let mut candidates: Vec<u64> = Vec::with_capacity(4);
        for i in 0..4u64 {
            match base.checked_add(i * 0x1000) {
                Some(v) if v > 0 && v < envelope_end => candidates.push(v),
                _ => break,
            }
        }
        if candidates.is_empty() || candidates.len() > 4096 {
            return false;
        }
        // R5-R2-2: per-item mapping proof BEFORE install. Any failure
        // rejects the whole set (fail-closed; no partial bind).
        let proof = prove_candidate_mappings(handle, &candidates, base, image_size, 16);
        self.candidate_mapping = Some(proof.clone());
        if !proof.all_passed {
            return false;
        }
        let Some(nonce) = self.csprng_nonce() else {
            return false;
        };
        self.bind_walker_from_loader(handle, &candidates, nonce)
    }

    /// IMP-09-CARRIER-R5-R2-4: production walker execute gate.
    ///
    /// Returns the execute outcome WITHOUT forging success:
    /// - no walker session / no params VA        -> NotImplemented (fail-closed)
    /// - no AUTHORIZED target-side dispatch bridge -> NotImplemented
    ///   (calling the CLI-linked `exports::WalkerExecute` in-process is
    ///   the ENGINEERING runtime only and is NOT production dispatch)
    /// - bridge dispatch raw status != OK        -> NonOk { raw_status }
    /// - status OK but no marshaled output       -> OutputMissing
    /// - status OK + output present              -> Success
    ///
    /// Raw statuses are recorded verbatim in the walker event record; the
    /// caller must gate Proceed on the outcome.
    fn execute_walker_production(&mut self) -> WalkerExecuteOutcome {
        let Some(mem) = self.walker_mem.as_ref() else {
            return WalkerExecuteOutcome::NotImplemented;
        };
        let Some(params_va) = mem.params_va() else {
            return WalkerExecuteOutcome::NotImplemented;
        };
        // R5-R2-1: the EXECUTE window also needs a provable liveness
        // probe. A dead/unknown target fails closed BEFORE dispatch.
        let Some(handle) = self.options.target_handle else {
            self.execute_liveness = Some(LivenessProbe::Unknown);
            return WalkerExecuteOutcome::NotImplemented;
        };
        let execute_liveness = probe_process_liveness(handle);
        self.execute_liveness = Some(execute_liveness);
        if execute_liveness != LivenessProbe::Alive {
            return WalkerExecuteOutcome::NotImplemented;
        }
        let Some(bridge) = self.options.walker_dispatch.as_ref() else {
            // R5-R2-4: no authorized target-side dispatch bridge.
            return WalkerExecuteOutcome::NotImplemented;
        };
        let (raw_status, output) = bridge.dispatch(params_va);
        if raw_status != mida_antidebug_runtime::walker_protocol::WALKER_STATUS_OK as i32 {
            return WalkerExecuteOutcome::NonOk { raw_status };
        }
        match output {
            Some(att) => WalkerExecuteOutcome::Success { output: att },
            None => WalkerExecuteOutcome::OutputMissing,
        }
    }

    /// IMP-09-CARRIER-R5-R3: production consumer gate — V2 attestation
    /// digest closure over the marshaled walker output.
    ///
    /// Real production caller of
    /// [`mida_antidebug_runtime::walker_consumer::verify_v2_attestation_digest`]:
    /// the output attestation is serialized to canonical JSON (the same
    /// encoding the runtime writes) and the digest is recomputed; schema,
    /// binding matrix and digest MUST all validate, else Proceed is
    /// blocked with the original failure preserved (fail-closed, R3-3/R3-4).
    fn verify_walker_output_v2(
        &self,
        output: &mida_antidebug_runtime::attestation::RuntimeAttestationV2,
    ) -> Result<String, AntidebugOutcome> {
        let json = match output.to_canonical_json() {
            Ok(j) => j,
            Err(e) => {
                return Err(AntidebugOutcome::Failed {
                    state: self.state,
                    fail_code: FailCode::ProbeInconsistent,
                    message: format!("walker output attestation serialization failed: {e}"),
                })
            }
        };
        match mida_antidebug_runtime::walker_consumer::verify_v2_attestation_digest(&json) {
            Ok(digest) => Ok(digest),
            Err(e) => Err(AntidebugOutcome::Failed {
                state: self.state,
                fail_code: FailCode::ProbeInconsistent,
                message: format!("walker output V2 attestation digest gate failed: {e}"),
            }),
        }
    }

    /// IMP-09-CARRIER-R5-R2-4: record one raw walker lifecycle event
    /// (monotonic 1-based sequence). `walker_status_raw` is the raw i32
    /// from the target-side dispatch (None for non-execute phases).
    pub fn record_walker_event(&mut self, phase: &str, detail: Option<String>, raw: Option<i32>) {
        let sequence = self.walker_events.len() as u32 + 1;
        self.walker_events.push(WalkerRawEvent {
            sequence,
            phase: phase.to_string(),
            detail,
            walker_status_raw: raw,
        });
    }

    /// Record the `terminate_enter` event. Called by the production
    /// paths immediately before `terminate_and_wait()` so the monotonic
    /// record proves bind/execute ran in the alive window (before any
    /// termination).
    pub fn record_terminate_enter(&mut self) {
        self.record_walker_event("terminate_enter", None, None);
    }

    /// The monotonic raw walker event record (evidence).
    pub fn walker_events(&self) -> &[WalkerRawEvent] {
        &self.walker_events
    }

    /// The last candidate mapping proof set (evidence; kept on failure).
    pub fn candidate_mapping(&self) -> Option<&CandidateMappingProofSet> {
        self.candidate_mapping.as_ref()
    }

    /// The liveness probe from the bind window (evidence).
    pub fn liveness_probe(&self) -> Option<LivenessProbe> {
        self.liveness_probe
    }

    /// Build the walker evidence record (R5-R2-4): schema + liveness +
    /// candidate mapping + monotonic raw events.
    pub fn walker_evidence_record(&self, capture_phase: &str) -> WalkerEvidenceRecord {
        WalkerEvidenceRecord {
            schema: WALKER_EVIDENCE_SCHEMA.to_string(),
            record_kind: "cli-walker".to_string(),
            target_pid: Some(self.options.target_pid),
            capture_phase: capture_phase.to_string(),
            liveness_probe: self.liveness_probe.map(|p| p.as_str().to_string()),
            execute_liveness: self.execute_liveness.map(|p| p.as_str().to_string()),
            candidate_mapping: self.candidate_mapping.clone(),
            events: self.walker_events.clone(),
        }
    }
    /// IMP-09-CARRIER-R5-R1 P0-1: CSPRNG nonce for the walker session.
    /// Uses RtlGenRandom (SystemFunction036, advapi32) — the documented
    /// Windows user-mode CSPRNG. Fails closed (None) on any error.
    fn csprng_nonce(&self) -> Option<u64> {
        use windows::Win32::Security::Authentication::Identity::RtlGenRandom;
        let mut out = 0u64;
        let ok = unsafe { RtlGenRandom(&mut out as *mut u64 as *mut core::ffi::c_void, 8) };
        if ok.as_bool() {
            // Protocol rejects zero nonce; retry loop would be wasteful —
            // a zero draw is astronomically unlikely, but fail closed anyway.
            if out != 0 {
                Some(out)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// IMP-09-CARRIER-R5: teardown the walker session memory (free both
    /// target allocations). Idempotent; safe when no session is installed.
    pub fn teardown_walker_session(&mut self, target: HANDLE) {
        if let Some(mem) = self.walker_mem.take() {
            let mut mem = mem;
            mem.cleanup(target);
        }
    }

    /// IMP-09-CARRIER-R3: verified target-image digest carrier. Sealed by
    /// the launch attestation only (VerifiedTargetIdentity, private fields,
    /// no Deserialize). None means no attested preflight — callers MUST
    /// refuse to bind (UNBOUND, NOT_WIRED) — no magic substitution.
    fn target_image_sha256(&self) -> Option<&str> {
        self.options.target_identity.as_ref().map(|t| t.sha256())
    }

    /// IMP-09-PROFILE-SOURCE-R1: verified profile id carrier. Read from the
    /// sealed VerifiedProfileIdentity (produced by the launch attestation
    /// from the verified profile object — never a bare string). None when no
    /// attested profile exists -> bind must fail closed.
    fn verified_profile_id(&self) -> Option<&str> {
        self.options
            .profile_identity
            .as_ref()
            .map(|p| p.profile_id())
    }

    /// IMP-09-PROFILE-SOURCE-R1: verified profile digest carrier
    /// (SHA-256 of the canonical profile bytes, 64 lowercase hex). Same
    /// sealed source object as profile_id (same-source guarantee). None
    /// when no attested profile exists -> bind must fail closed.
    fn verified_profile_digest(&self) -> Option<&str> {
        self.options
            .profile_identity
            .as_ref()
            .map(|p| p.profile_digest())
    }

    /// IMP-09-CARRIER-R2: WalkerExecute export RVA from the SEALED
    /// LoaderResult carrier (pure-file resolver over the verified runtime
    /// DLL bytes; no live process access, no raw string, no magic
    /// constant). None -> bind must fail closed (never hard-code).
    fn resolved_walker_export_rva(&self) -> Option<u64> {
        self.options.loader_result.as_ref()?.walker_export_rva()
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
        // cleanup report via set_cleanup_report(). If a result is already
        // recorded, reuse it and do NOT run a second independent
        // termination backend (that produced duplicate cleanup in R4B).
        if let Some(existing) = &self.cleanup {
            return existing.clone();
        }
        // IMP-09-CARRIER-R5-R2-1: when the caller drives the debugger
        // termination itself (CREATE_PROCESS + post-attach run the
        // controller gate BEFORE terminate_and_wait, in the alive
        // window), run() must NOT fire the termination backend — the
        // backend would TerminateProcess the live target and then the
        // caller's terminate_and_wait would mis-report cleanup. Deferred
        // cleanup returns NotRun; the caller injects the real report via
        // set_cleanup_report() immediately after terminate_and_wait.
        if self.options.defer_cleanup_to_caller {
            return CleanupResult::NotRun;
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
        // IMP-09-CARRIER-R5-R1 P1: RAII teardown guard. Every exit path of
        // run() (success, failure, early return, unwind) frees the walker
        // session allocations in the target exactly once. The guard holds
        // the target handle captured at entry.
        let mut _walker_teardown = WalkerTeardownGuard::new(self);
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
                    loader.target_pid(),
                    self.options.target_pid
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

        // R5-R2-4: the verified loader result is the first raw walker
        // event of the monotonic production sequence.
        self.record_walker_event(
            "loader_complete",
            Some(format!(
                "target_pid={} module_base={:#x}",
                loader.target_pid(),
                loader.module_base()
            )),
            None,
        );

        // Drive the success path. ProceedApproved is deliberately NOT
        // driven yet: R5-R2 gates Proceed on the walker bind + execute
        // gates below (bind failure / execute non-OK / missing output
        // MUST block Proceed).
        self.drive(ControllerEvent::ProfileValidated);
        self.drive(ControllerEvent::TargetIdentityValidated);
        self.drive(ControllerEvent::LaunchPrepared);
        self.drive(ControllerEvent::RuntimeLoadStarted);
        self.drive(ControllerEvent::RuntimeInitialized);
        self.drive(ControllerEvent::HealthCheckStarted);
        self.drive(ControllerEvent::HealthCheckPassed);
        self.drive(ControllerEvent::ProbeSetPassed);

        // IMP-09-CARRIER-R5-R1 P0-1 / R5-R2: production walker bind.
        //
        // Real production caller: the controller lifecycle itself.
        // Every input comes from a sealed carrier:
        //   - target HANDLE: injected by the debugger (options.target_handle)
        //   - loader_result: injected after the real loader ran
        //   - target/profile identities: launch attestation
        //   - walker_export_rva: pure-file resolver over verified runtime
        //   - candidates: derived from the VERIFIED runtime module base
        //     (real mapped pages in the target), proven per-item BEFORE
        //     install (VirtualQueryEx mapping proof)
        //   - result_nonce: CSPRNG (RtlGenRandom)
        // Any carrier missing / proof failure / liveness unknown-or-dead
        // -> bind fails closed (NOT_WIRED, UNBOUND); no magic values are
        // ever substituted.
        self.record_walker_event(
            "bind_enter",
            Some(format!(
                "module_base={:#x} image_size={:#x}",
                loader.module_base(),
                loader.file_identity().verified_size_of_image()
            )),
            None,
        );
        let walker_bound = self.bind_walker_from_loader_production();
        self.record_walker_event(
            "bind_exit",
            Some(if walker_bound {
                "WIRED".to_string()
            } else {
                format!(
                    "NOT_WIRED liveness={:?} proof={}",
                    self.liveness_probe,
                    self.candidate_mapping
                        .as_ref()
                        .map(|p| p.all_passed)
                        .unwrap_or(false)
                )
            }),
            None,
        );
        log::log(
            LogType::Info,
            &format!(
                "IMP-09: WALKER_BINDING={} (production lifecycle bind)",
                if walker_bound { "WIRED" } else { "NOT_WIRED" }
            ),
        );
        // R5-R2-3: bind failure MUST block Proceed (fail-closed).
        if !walker_bound {
            return AntidebugOutcome::Failed {
                state: self.state,
                fail_code: FailCode::AntiDebugRuntimeUnavailable,
                message:
                    "walker bind failed closed (liveness/mapping/install gate); Proceed blocked"
                        .to_string(),
            };
        }

        // IMP-09-CARRIER-R5-R2-4: production walker execute gate. The raw
        // status is recorded verbatim; any non-OK status, missing output,
        // or absent authorized dispatch bridge blocks Proceed.
        self.record_walker_event(
            "execute_enter",
            Some("authorized target-side dispatch".to_string()),
            None,
        );
        let execute_outcome = self.execute_walker_production();
        let raw_status = match &execute_outcome {
            WalkerExecuteOutcome::Success { .. } => {
                Some(mida_antidebug_runtime::walker_protocol::WALKER_STATUS_OK as i32)
            }
            WalkerExecuteOutcome::NonOk { raw_status } => Some(*raw_status),
            WalkerExecuteOutcome::NotImplemented | WalkerExecuteOutcome::OutputMissing => None,
        };
        self.record_walker_event(
            "execute_exit",
            Some(format!(
                "outcome={}",
                execute_outcome_name(&execute_outcome)
            )),
            raw_status,
        );
        log::log(
            LogType::Info,
            &format!(
                "IMP-09: WALKER_EXECUTE={} (production dispatch gate)",
                execute_outcome_name(&execute_outcome)
            ),
        );
        match execute_outcome {
            WalkerExecuteOutcome::Success { output } => {
                // IMP-09-CARRIER-R5-R3: V2 attestation digest closure gate.
                // The marshaled output MUST be a valid v2 attestation whose
                // record digest recomputes (schema/binding matrix checked
                // inside verify_v2_attestation_digest). Any failure blocks
                // Proceed with the ORIGINAL error preserved (R3-3/R3-4).
                let _verified = match self.verify_walker_output_v2(&output) {
                    Ok(d) => d,
                    Err(fail) => {
                        self.record_walker_event(
                            "output_verify_fail",
                            Some("V2 attestation digest gate failed; Proceed blocked".to_string()),
                            None,
                        );
                        return fail;
                    }
                };
            }
            WalkerExecuteOutcome::NotImplemented => {
                // R5-R2-4: no authorized target-side dispatch bridge.
                return AntidebugOutcome::Failed {
                    state: self.state,
                    fail_code: FailCode::AntiDebugRuntimeUnavailable,
                    message: "walker execute NOT_IMPLEMENTED: no authorized target-side dispatch bridge; Proceed blocked"
                        .to_string(),
                };
            }
            WalkerExecuteOutcome::NonOk { raw_status } => {
                return AntidebugOutcome::Failed {
                    state: self.state,
                    fail_code: FailCode::ProbeInconsistent,
                    message: format!(
                        "walker execute returned non-OK raw status {raw_status}; Proceed blocked"
                    ),
                };
            }
            WalkerExecuteOutcome::OutputMissing => {
                return AntidebugOutcome::Failed {
                    state: self.state,
                    fail_code: FailCode::ProbeInconsistent,
                    message:
                        "walker execute returned OK but output channel was empty; Proceed blocked"
                            .to_string(),
                };
            }
        }

        // All walker gates passed: approve Proceed.
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
            walker_events: self.walker_events.clone(),
            candidate_mapping: self.candidate_mapping.clone(),
            liveness_probe: self.liveness_probe.map(|p| p.as_str().to_string()),
        })
    }
}

/// Write the walker evidence sidecar (atomic: write temp + rename).
///
/// R5-R2-4: the production paths write this after the controller gate —
/// after recording `terminate_enter` — so the file carries the full
/// monotonic raw event sequence (loader_complete, bind_enter, bind_exit,
/// execute_enter, execute_exit, terminate_enter) plus the liveness probe
/// and the per-candidate mapping proof. Fail-closed on write error.
pub fn write_walker_evidence(
    record: &WalkerEvidenceRecord,
    dir: &Path,
) -> Result<std::path::PathBuf, anyhow::Error> {
    let dir = dir.to_path_buf();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(record)?;
    let tmp = dir.join("mida_antidebug_walker.evidence.json.tmp");
    let final_path = dir.join("mida_antidebug_walker.evidence.json");
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &final_path)?;
    Ok(final_path)
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

    /// Serializes tests that touch the process-global walker runtime
    /// singletons (the runtime walker session is process-global, so only
    /// one install/bind test may hold the lifecycle at a time; the
    /// walker_session tests use their own INSTALL_LOCK, and the cargo
    /// test harness runs tests in parallel — the controller R5-R2 gate
    /// tests take this lock to avoid cross-test singleton interference).
    static WALKER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn self_handle() -> windows::Win32::Foundation::HANDLE {
        unsafe { windows::Win32::System::Threading::GetCurrentProcess() }
    }
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
            target_handle: None, // tests: no live target
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: Some(temp.to_path_buf()),
            oracle: None,
            cleanup_backend: Some(backend),
            runtime_authority: None,
            runtime_path: None,
            loader_result: None,
            target_identity: None,
            profile_identity: None,
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
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
            walker_events: vec![],
            candidate_mapping: None,
            liveness_probe: None,
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
            walker_events: vec![],
            candidate_mapping: None,
            liveness_probe: None,
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
            target_handle: None, // tests: no live target
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
            target_identity: None,
            profile_identity: None,
            loader_result: None,
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        });
        let outcome = c.run();
        // Oracle mode still fails closed: no runtime, no proceed.
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
        assert!(c.state().is_failure());
    }

    #[test]
    fn fail_code_mapping_table() {
        let c = AntidebugController::new(AntidebugStageOptions {
            target_handle: None, // tests: no live target
            sample_id: None,
            target_pid: 1,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: None,
            runtime_path: None,
            target_identity: None,
            profile_identity: None,
            loader_result: None,
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
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

    /// Synthetic x64 PE with a real SizeOfImage (0x4000) so the R5-R2
    /// image-envelope gate can be exercised: verified_size_of_image()
    /// derives 0x4000 from these bytes (never a live-process header).
    fn r5r2_pe_with_image_size() -> Vec<u8> {
        let mut b = minimal_pe();
        b.resize(0x1000, 0);
        // SizeOfImage at optional+0x50 = 0x80+0x18+0x50 = 0xE8
        b[0xE8..0xEC].copy_from_slice(&0x4000u32.to_le_bytes());
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
        let digest_authority =
            RuntimeDigestAuthority::from_verified_identity(&identity, &authority.artifact_id)
                .expect("verified identity must build a valid authority");
        LoaderResult::new(
            0x7000,
            attestation_json,
            identity,
            digest_authority,
            target_pid,
            None,
        )
    }

    fn controller_with_loader_result(loader: Option<LoaderResult>) -> AntidebugController {
        let content = minimal_pe();
        let _ = std::fs::create_dir_all(std::env::temp_dir().join("mida-adr6-test"));
        let p = next_file("r");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&sha256_hex(&content), content.len() as u64);
        AntidebugController::new(AntidebugStageOptions {
            target_handle: None, // tests: no live target
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: Some(authority),
            runtime_path: Some(p),
            target_identity: None,
            profile_identity: None,
            loader_result: loader,
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        })
    }

    #[test]
    fn imp06_controller_proceeds_with_valid_loader_result() {
        // IMP-06 baseline: a valid loader result drives the lifecycle to
        // ProbeSetPassed. IMP-09-CARRIER-R5-R2 then adds the walker gates:
        // without a target handle / walker carrier / dispatch bridge the
        // production bind fails closed and Proceed is BLOCKED — this is the
        // R5-R2 fail-closed contract, not an IMP-06 regression.
        let mut c = controller_with_loader_result(Some(loader_result_with(
            1234,
            default_attestation_json(),
        )));
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Failed { .. }),
            "R5-R2: missing walker carrier must fail closed, got {outcome:?}"
        );
        assert!(!c.state().is_proceed());
        // The raw event record proves the gate was reached and stopped at
        // the bind: loader_complete, bind_enter, bind_exit (NOT_WIRED).
        let phases: Vec<&str> = c.walker_events().iter().map(|e| e.phase.as_str()).collect();
        assert_eq!(
            phases,
            vec!["loader_complete", "bind_enter", "bind_exit"],
            "expected bind fail-closed sequence, got {phases:?}"
        );
        assert!(c.walker_events()[2]
            .detail
            .as_deref()
            .unwrap()
            .contains("NOT_WIRED"));
    }

    #[test]
    fn imp09_bind_walker_from_loader_refuses_without_carriers() {
        // IMP-09-R1-R4: the EXACT authority matrix has no sealed carriers
        // for target_image_sha256 / profile / resolved export RVA in the
        // current chain, so the bind MUST deterministically refuse and
        // MUST NOT publish a session (no magic substitution).
        let mut c = controller_with_loader_result(Some(loader_result_with(
            1234,
            default_attestation_json(),
        )));
        let r = c.bind_walker_from_loader(self_handle(), &[0x400000], 0x99);
        assert!(
            !r,
            "bind must refuse while target/profile/export carriers are absent",
        );
    }
    /// Test identity carrier (sealed via the real from_attested path).
    fn test_target_identity(
        case: &str,
        sha: &str,
        size: u64,
    ) -> crate::runner_preflight::VerifiedTargetIdentity {
        crate::runner_preflight::VerifiedTargetIdentity::from_attested(
            case,
            &crate::runner_preflight::FileIdentityGate {
                sha256: sha.to_string(),
                size_bytes: size,
            },
            "x86_64",
        )
        .expect("test target identity seals")
    }

    /// Controller with a target identity carrier injected (simulating the
    /// attested preflight chain).
    fn controller_with_target(
        loader: Option<LoaderResult>,
        target: Option<crate::runner_preflight::VerifiedTargetIdentity>,
    ) -> AntidebugController {
        let content = minimal_pe();
        let _ = std::fs::create_dir_all(std::env::temp_dir().join("mida-adr6-test"));
        let p = next_file("t");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&sha256_hex(&content), content.len() as u64);
        AntidebugController::new(AntidebugStageOptions {
            target_handle: None, // tests: no live target
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: Some(authority),
            runtime_path: Some(p),
            loader_result: loader,
            target_identity: target,
            profile_identity: None,
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        })
    }

    /// LoaderResult with a REAL walker export RVA carrier (0x2040) and
    /// the given module base, built from a verified file identity.
    fn loader_with_walker_rva(target_pid: u32, module_base: u64) -> LoaderResult {
        // IMP-09-CARRIER-R5-R2: the verified identity must carry a REAL
        // SizeOfImage envelope (0x4000) so the image-envelope gate can be
        // exercised; minimal_pe() has NO SizeOfImage and would fail closed
        // by design. The identity still comes ONLY from verify_file().
        let content = r5r2_pe_with_image_size();
        let _ = std::fs::create_dir_all(std::env::temp_dir().join("mida-adr6-test"));
        let p = next_file("lr_walker");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&sha256_hex(&content), content.len() as u64);
        let identity = authority.verify_file(&p).unwrap();
        assert_eq!(identity.verified_size_of_image(), 0x4000);
        let digest_authority =
            RuntimeDigestAuthority::from_verified_identity(&identity, &authority.artifact_id)
                .expect("verified identity must build authority");
        LoaderResult::new(
            module_base,
            default_attestation_json(),
            identity,
            digest_authority,
            target_pid,
            Some(0x2040), // sealed pure-file WalkerExecute export RVA
        )
    }

    /// Reserve a real committed region in the CURRENT process and return
    /// (base, guard). The guard frees it on drop. Used so the R5-R2
    /// mapping proof sees real MEM_COMMIT pages (never a fake VA).
    struct MappedRegionGuard {
        base: u64,
    }
    impl Drop for MappedRegionGuard {
        fn drop(&mut self) {
            use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};
            unsafe {
                let _ = VirtualFree(self.base as *mut core::ffi::c_void, 0, MEM_RELEASE);
            }
        }
    }
    fn alloc_mapped_region(size: usize) -> MappedRegionGuard {
        use windows::Win32::System::Memory::{
            VirtualAlloc, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE,
        };
        let p = unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        assert!(!p.is_null(), "VirtualAlloc failed");
        MappedRegionGuard { base: p as u64 }
    }

    /// Controller with ALL sealed carriers + a real target handle.
    /// target_pid must match the running process for the provider bind
    /// to succeed (engineering runtime: own process).
    ///
    /// R5-R2: module_base is a REAL committed 0x4000-byte region in this
    /// process (VirtualAlloc), and the verified identity carries
    /// SizeOfImage=0x4000, so the mapping proof passes: candidates
    /// base..base+0x3000 are committed, in-envelope, readable.
    /// Returns (controller, region guard) — the caller MUST keep the
    /// guard alive while the controller runs.
    fn controller_with_full_carriers(target_pid: u32) -> (AntidebugController, MappedRegionGuard) {
        let content = r5r2_pe_with_image_size();
        let _ = std::fs::create_dir_all(std::env::temp_dir().join("mida-adr6-test"));
        let p = next_file("full");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&sha256_hex(&content), content.len() as u64);
        let region = alloc_mapped_region(0x4000);
        let base = region.base;
        let c = AntidebugController::new(AntidebugStageOptions {
            target_handle: Some(self_handle()), // real process handle
            sample_id: Some("origin_macro".to_string()),
            target_pid,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: Some(authority),
            runtime_path: Some(p),
            loader_result: Some(loader_with_walker_rva(target_pid, base)),
            target_identity: Some(test_target_identity(
                "origin_macro",
                &"ab12".repeat(16),
                4096,
            )),
            profile_identity: Some(test_profile_identity("origin_macro", "x86_64")),
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        });
        // target digest must NOT equal runtime digest: the test sha is
        // distinct from the runtime file digest (r5r2_pe_with_image_size).
        (c, region)
    }
    #[test]
    fn imp09_verified_target_identity_reaches_controller() {
        // The sealed target identity from the attestation chain reaches the
        // controller's target_image_sha256() carrier unchanged.
        let sha = "ab12".repeat(16);
        let c = controller_with_target(
            Some(loader_result_with(1234, default_attestation_json())),
            Some(test_target_identity("origin_macro", &sha, 4096)),
        );
        assert_eq!(c.target_image_sha256(), Some(sha.as_str()));
        // The carrier is distinct from the runtime digest by construction.
        let loader = loader_result_with(1234, default_attestation_json());
        assert_ne!(
            c.target_image_sha256().unwrap(),
            loader.digest_authority().digest_value()
        );
    }

    #[test]
    fn imp09_missing_target_identity_rejected() {
        // No attested preflight -> target_image_sha256() is None.
        let c = controller_with_loader_result(Some(loader_result_with(
            1234,
            default_attestation_json(),
        )));
        assert_eq!(c.target_image_sha256(), None);
    }

    #[test]
    fn imp09_target_digest_placeholder_rejected() {
        // A placeholder digest string must never seal into the carrier.
        let err = crate::runner_preflight::VerifiedTargetIdentity::from_attested(
            "origin_macro",
            &crate::runner_preflight::FileIdentityGate {
                sha256: "adr6-profile-digest".to_string(),
                size_bytes: 4096,
            },
            "x86_64",
        )
        .expect_err("placeholder target digest must not seal");
        assert!(err.contains("sha256 invalid"), "{err}");
    }

    #[test]
    fn imp09_target_runtime_digest_substitution_rejected() {
        // Attack: the target digest carrier is populated with the RUNTIME
        // DLL digest (substitution). The bind must refuse — the two artifacts
        // are distinct by contract (target sample vs runtime module).
        let loader = loader_result_with(1234, default_attestation_json());
        let runtime_digest = loader.digest_authority().digest_value().to_string();
        let mut c = controller_with_target(
            Some(loader),
            Some(test_target_identity("origin_macro", &runtime_digest, 4096)),
        );
        assert!(
            !c.bind_walker_from_loader(self_handle(), &[0x400000], 0x99),
            "bind must refuse target==runtime digest substitution",
        );
    }

    #[test]
    fn imp09_bind_remains_unbound_when_target_carrier_missing() {
        // No target carrier -> bind refuses and no session is published
        // (install never called; lifecycle stays UNBOUND / NOT_WIRED).
        let mut c = controller_with_loader_result(Some(loader_result_with(
            1234,
            default_attestation_json(),
        )));
        assert!(!c.bind_walker_from_loader(self_handle(), &[0x400000], 0x99));
        // No session was published: resetting/reading the walker output is a
        // no-op (nothing installed), and a subsequent verified install of a
        // DIFFERENT session is still possible — the refused bind left the
        // runtime untouched.
        mida_antidebug_runtime::exports::reset_for_test();
        assert!(mida_antidebug_runtime::exports::take_walker_output().is_none());
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
            target_handle: None, // tests: no live target
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: Some(authority),
            runtime_path: Some(p),
            target_identity: None,
            profile_identity: None,
            loader_result: Some(loader_result_with(1234, default_attestation_json())),
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        });
        let outcome = c.run();
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
    }

    /// Test profile carrier (sealed via the real from_verified_profile path).
    fn test_profile_identity(
        case: &str,
        arch: &str,
    ) -> crate::runner_preflight::VerifiedProfileIdentity {
        use mida_antidebug::profile::{lunlun_profile, origin_profile};
        let p = match case {
            "origin_macro" => origin_profile(),
            "lunlun_software" => lunlun_profile(),
            _ => panic!("test case {case} has no profile object"),
        };
        crate::runner_preflight::VerifiedProfileIdentity::from_verified_profile(&p, case, arch)
            .expect("test profile identity seals")
    }

    #[test]
    fn imp09_profile_missing_fail_closed_unbound() {
        // No profile carrier -> verified_profile_id/digest are None, the
        // bind refuses and no session is published (UNBOUND / NOT_WIRED).
        let mut c = controller_with_loader_result(Some(loader_result_with(
            1234,
            default_attestation_json(),
        )));
        assert_eq!(c.verified_profile_id(), None);
        assert_eq!(c.verified_profile_digest(), None);
        assert!(!c.bind_walker_from_loader(self_handle(), &[0x400000], 0x99));
        mida_antidebug_runtime::exports::reset_for_test();
        assert!(mida_antidebug_runtime::exports::take_walker_output().is_none());
    }

    #[test]
    fn imp09_both_production_callers_use_same_verified_profile_carrier() {
        // Both production callers (post-attach + CREATE_PROCESS) read the
        // SAME sealed profile carrier from the attested evidence context:
        // the carrier is cloned from RunEvidenceContext.profile_identity()
        // at both AntidebugStageOptions construction sites. This test
        // builds the carrier once (as the attestation does) and verifies
        // two independent controller instances — one per production caller
        // shape — observe identical profile_id + digest.
        let profile = test_profile_identity("origin_macro", "x86_64");
        let loader = Some(loader_result_with(1234, default_attestation_json()));
        let mut c1 = AntidebugController::new(AntidebugStageOptions {
            target_handle: None, // tests: no live target
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: None,
            runtime_path: None,
            loader_result: loader.clone(),
            target_identity: Some(test_target_identity(
                "origin_macro",
                &"ab12".repeat(16),
                4096,
            )),
            profile_identity: Some(profile.clone()),
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        });
        let mut c2 = AntidebugController::new(AntidebugStageOptions {
            target_handle: None, // tests: no live target
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: None,
            runtime_path: None,
            loader_result: loader,
            target_identity: Some(test_target_identity(
                "origin_macro",
                &"ab12".repeat(16),
                4096,
            )),
            profile_identity: Some(profile.clone()),
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        });
        assert_eq!(c1.verified_profile_id(), c2.verified_profile_id());
        assert_eq!(c1.verified_profile_digest(), c2.verified_profile_digest());
        let pid = c1.verified_profile_id().expect("carrier present");
        let dig = c1.verified_profile_digest().expect("carrier present");
        assert_eq!(pid, "oreans_origin_x64_v1");
        assert_eq!(dig.len(), 64);
        // The carrier still fails closed at the full bind (provider absent).
        assert!(!c1.bind_walker_from_loader(self_handle(), &[0x400000], 0x99));
        assert!(!c2.bind_walker_from_loader(self_handle(), &[0x400000], 0x99));
    }
    #[test]
    fn imp09_r5r1_run_calls_production_bind_and_wires() {
        // P0-1: run() is the REAL production caller. With all sealed
        // carriers + a valid target handle (own process, engineering
        // runtime) the walker session reaches READY: WALKER_BINDING=WIRED.
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        // R5-R2-4: with NO authorized dispatch bridge the execute gate
        // records NOT_IMPLEMENTED and Proceed is BLOCKED (fail-closed).
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Failed { .. }),
            "R5-R2 without dispatch bridge must fail closed, got {outcome:?}"
        );
        assert!(!c.state().is_proceed());
        // The bind DID run inside run() (liveness + mapping proved, session
        // installed): walker_mem was held and released by the RAII teardown
        // guard at exit (nothing remains).
        assert!(c.walker_mem.is_none(), "teardown guard must free session");
        // The raw event sequence proves the alive window: loader_complete,
        // bind_enter, bind_exit (WIRED), execute_enter, execute_exit
        // (NOT_IMPLEMENTED) — no terminate_enter (that is recorded by the
        // production path, not run()).
        let phases: Vec<&str> = c.walker_events().iter().map(|e| e.phase.as_str()).collect();
        assert_eq!(
            phases,
            vec![
                "loader_complete",
                "bind_enter",
                "bind_exit",
                "execute_enter",
                "execute_exit"
            ],
            "monotonic raw event sequence mismatch: {phases:?}"
        );
        // bind_exit must report WIRED: the session reached READY before
        // the execute gate.
        assert_eq!(c.walker_events()[2].detail.as_deref(), Some("WIRED"));
        // Liveness + mapping proof were recorded for evidence.
        assert_eq!(c.liveness_probe(), Some(LivenessProbe::Alive));
        let proof = c.candidate_mapping().expect("mapping proof recorded");
        assert!(proof.all_passed);
        assert_eq!(proof.items.len(), 4);
        // A second bind is possible: lifecycle was left UNBOUND by the
        // guard's release (bindings reset only in tests; the guard frees
        // memory but the runtime lifecycle may be terminal — check the
        // honest state: bindings were installed then released).
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r1_run_bind_fails_closed_without_target_handle() {
        // R5-R2-1/2/3: missing target handle -> liveness Unknown -> bind
        // refuses -> NOT_WIRED -> Proceed is BLOCKED (fail-closed).
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let content = r5r2_pe_with_image_size();
        let _ = std::fs::create_dir_all(std::env::temp_dir().join("mida-adr6-test"));
        let p = next_file("nohandle");
        std::fs::write(&p, &content).unwrap();
        let authority = manifest(&sha256_hex(&content), content.len() as u64);
        let mut c = AntidebugController::new(AntidebugStageOptions {
            target_handle: None, // missing
            sample_id: Some("origin_macro".to_string()),
            target_pid: std::process::id(),
            evidence_dir: None,
            oracle: None,
            cleanup_backend: None,
            runtime_authority: Some(authority),
            runtime_path: Some(p),
            loader_result: Some(loader_with_walker_rva(std::process::id(), 0x7FF600000000)),
            target_identity: Some(test_target_identity(
                "origin_macro",
                &"ab12".repeat(16),
                4096,
            )),
            profile_identity: Some(test_profile_identity("origin_macro", "x86_64")),
            walker_dispatch: None,
            defer_cleanup_to_caller: false,
        });
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Failed { .. }),
            "missing target handle must fail closed, got {outcome:?}"
        );
        assert!(!c.state().is_proceed());
        assert!(c.walker_mem.is_none());
        // Liveness was recorded as Unknown (fail-closed) + bind_exit
        // NOT_WIRED with liveness=Unknown in the detail.
        assert_eq!(c.liveness_probe(), Some(LivenessProbe::Unknown));
        let phases: Vec<&str> = c.walker_events().iter().map(|e| e.phase.as_str()).collect();
        assert_eq!(
            phases,
            vec!["loader_complete", "bind_enter", "bind_exit"],
            "expected bind fail-closed sequence, got {phases:?}"
        );
        assert!(c.walker_events()[2]
            .detail
            .as_deref()
            .unwrap()
            .contains("NOT_WIRED"));
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    // ---------- IMP-09-CARRIER-R5-R2: walker execute gate ----------

    /// Mock authorized dispatch bridge (offline gate tests only; a mock
    /// is never a live Windows PASS). Output is a REAL v2 attestation with
    /// recomputable digest (the R5-R3 consumer gate verifies it).
    #[derive(Debug)]
    struct TestDispatchBridge {
        status: i32,
        output: bool,
        /// When true the marshaled output is a v2 attestation whose digest
        /// does NOT recompute (R5-R3 digest gate must block Proceed).
        tampered_digest: bool,
        /// When true the output attestation carries no walker_attestation.
        no_walker: bool,
    }
    impl TestDispatchBridge {
        fn ok() -> Self {
            Self {
                status: 0,
                output: true,
                tampered_digest: false,
                no_walker: false,
            }
        }
    }
    impl WalkerDispatchBridge for TestDispatchBridge {
        fn dispatch(
            &self,
            _params_va: u64,
        ) -> (
            i32,
            Option<mida_antidebug_runtime::attestation::RuntimeAttestationV2>,
        ) {
            if !self.output {
                return (self.status, None);
            }
            let mut att = mock_attestation_v2();
            if self.tampered_digest {
                att.record_digest = "0".repeat(64);
            }
            if self.no_walker {
                att.walker_attestation = None;
            }
            (self.status, Some(att))
        }
    }

    fn mock_attestation_v2() -> mida_antidebug_runtime::attestation::RuntimeAttestationV2 {
        use mida_antidebug_runtime::attestation::{
            AbortState, HookInventory, ProbeSummary, RoundLedger, WalkerAttestation,
        };
        let mut r1 = RoundLedger::new(1).unwrap();
        r1.entry_ts = "t1".to_string();
        r1.exit_ts = "t2".to_string();
        r1.wall_budget_ms = 1000;
        r1.wall_spent_ms = 1;
        r1.candidates_probed = 3;
        r1.next_round_authorized = true;
        let mut r2 = RoundLedger::new(2).unwrap();
        r2.entry_ts = "t3".to_string();
        r2.exit_ts = "t4".to_string();
        r2.wall_budget_ms = 1000;
        r2.wall_spent_ms = 1;
        r2.candidates_probed = 3;
        let summary = ProbeSummary {
            candidates_total: 6,
            type_a_count: 0,
            type_b_count: 0,
            type_c_count: 6,
            av_count: 0,
            guard_count: 6,
            retry_count: 3,
            total_latency_us: 10,
        };
        summary.validate().unwrap();
        let mut walker = WalkerAttestation::new(
            std::process::id(),
            "ab".repeat(32),
            "ab".repeat(32),
            0x2040,
            0x7000 + 0x2040,
            summary,
        );
        walker.rounds = vec![r1, r2];
        walker.record_digest = walker.compute_digest();
        let inventory = HookInventory::unsupported(&[]);
        let mut att = mida_antidebug_runtime::attestation::RuntimeAttestationV2 {
            schema: "mida.antidebug-runtime-attestation/v2".to_string(),
            schema_version: 2,
            runtime_id: "mida-antidebug-runtime-x64".to_string(),
            runtime_version: "0.1.0".to_string(),
            architecture: "x86_64".to_string(),
            runtime_sha256: "ab".repeat(32),
            profile_id: "oreans_origin_x64_v1".to_string(),
            profile_digest: "cd".repeat(32),
            target_pid: std::process::id(),
            module_base: 0x7000,
            initialized: true,
            hooks_expected: inventory.hooks_expected,
            hooks_installed: inventory.hooks_installed,
            hook_failures: inventory.hook_failures,
            surface_details: vec![],
            telemetry_channel: "ready".to_string(),
            cleanup_handler_registered: true,
            third_party: "test".to_string(),
            source_revision: "test".to_string(),
            toolchain: "rustc".to_string(),
            walker_attestation: Some(walker),
            record_digest: String::new(),
        };
        att.record_digest = att.compute_digest();
        att
    }

    #[test]
    fn imp09_r5r2_execute_gate_ok_with_bridge_reaches_proceed() {
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        c.options.walker_dispatch = Some(Box::new(TestDispatchBridge::ok()));
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Proceed { .. }),
            "authorized bridge OK + output must reach Proceed, got {outcome:?}"
        );
        let phases: Vec<&str> = c.walker_events().iter().map(|e| e.phase.as_str()).collect();
        assert_eq!(
            phases,
            vec![
                "loader_complete",
                "bind_enter",
                "bind_exit",
                "execute_enter",
                "execute_exit"
            ],
            "sequence mismatch: {phases:?}"
        );
        assert_eq!(c.walker_events()[4].walker_status_raw, Some(0));
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r2_execute_gate_non_ok_status_blocks_proceed() {
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        c.options.walker_dispatch = Some(Box::new(TestDispatchBridge {
            status: 2,
            output: true,
            tampered_digest: false,
            no_walker: false,
        }));
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Failed { .. }),
            "non-OK raw status must fail closed, got {outcome:?}"
        );
        assert!(!c.state().is_proceed());
        let last = c.walker_events().last().unwrap();
        assert_eq!(last.phase, "execute_exit");
        assert_eq!(last.walker_status_raw, Some(2));
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r2_execute_gate_missing_output_blocks_proceed() {
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        c.options.walker_dispatch = Some(Box::new(TestDispatchBridge {
            status: 0,
            output: false,
            tampered_digest: false,
            no_walker: false,
        }));
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Failed { .. }),
            "OK status without output must fail closed, got {outcome:?}"
        );
        assert!(!c.state().is_proceed());
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r2_no_bridge_records_not_implemented_raw() {
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        let outcome = c.run();
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
        let last = c.walker_events().last().unwrap();
        assert_eq!(last.phase, "execute_exit");
        assert_eq!(last.walker_status_raw, None);
        assert!(last.detail.as_deref().unwrap().contains("NotImplemented"));
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r2_walker_evidence_record_roundtrips() {
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        c.options.walker_dispatch = Some(Box::new(TestDispatchBridge {
            status: 0,
            output: true,
            tampered_digest: false,
            no_walker: false,
        }));
        let _ = c.run();
        c.record_terminate_enter();
        let rec = c.walker_evidence_record("create_process");
        assert_eq!(rec.schema, WALKER_EVIDENCE_SCHEMA);
        assert_eq!(rec.events.len(), 6);
        assert_eq!(rec.events[0].phase, "loader_complete");
        assert_eq!(rec.events[5].phase, "terminate_enter");
        for (i, e) in rec.events.iter().enumerate() {
            assert_eq!(e.sequence as usize, i + 1, "monotonic sequence");
        }
        assert_eq!(rec.liveness_probe.as_deref(), Some("alive"));
        let proof = rec.candidate_mapping.as_ref().expect("proof recorded");
        assert!(proof.all_passed);
        let json = serde_json::to_string_pretty(&rec).unwrap();
        let back: WalkerEvidenceRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.events.len(), 6);
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r2_write_walker_evidence_atomic_roundtrip() {
        let temp = std::env::temp_dir().join("mida-r5r2-walker-evidence");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let rec = WalkerEvidenceRecord {
            schema: WALKER_EVIDENCE_SCHEMA.to_string(),
            record_kind: "cli-walker".to_string(),
            target_pid: Some(1),
            capture_phase: "post_attach".to_string(),
            liveness_probe: Some("alive".to_string()),
            execute_liveness: Some("alive".to_string()),
            candidate_mapping: None,
            events: vec![WalkerRawEvent {
                sequence: 1,
                phase: "terminate_enter".to_string(),
                detail: None,
                walker_status_raw: None,
            }],
        };
        let p = write_walker_evidence(&rec, &temp).unwrap();
        assert!(p.is_file());
        let back: WalkerEvidenceRecord =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(back.events[0].phase, "terminate_enter");
        let _ = std::fs::remove_dir_all(&temp);
    }

    // ---------- IMP-09-CARRIER-R5-R3: V2 attestation digest gate ----------

    #[test]
    fn imp09_r5r3_output_tampered_digest_blocks_proceed() {
        // R3-3: the marshaled output's record_digest does NOT recompute ->
        // the consumer digest gate must fail closed and block Proceed.
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        c.options.walker_dispatch = Some(Box::new(TestDispatchBridge {
            status: 0,
            output: true,
            tampered_digest: true,
            no_walker: false,
        }));
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Failed { .. }),
            "tampered V2 digest must fail closed, got {outcome:?}"
        );
        assert!(!c.state().is_proceed());
        let last = c.walker_events().last().unwrap();
        assert_eq!(last.phase, "output_verify_fail");
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r3_output_missing_walker_attestation_blocks_proceed() {
        // R3-3: v2 attestation without a walker_attestation must fail closed.
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        c.options.walker_dispatch = Some(Box::new(TestDispatchBridge {
            status: 0,
            output: true,
            tampered_digest: false,
            no_walker: true,
        }));
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Failed { .. }),
            "missing walker_attestation must fail closed, got {outcome:?}"
        );
        assert!(!c.state().is_proceed());
        let last = c.walker_events().last().unwrap();
        assert_eq!(last.phase, "output_verify_fail");
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }

    #[test]
    fn imp09_r5r3_ok_bridge_passes_v2_digest_gate_and_reaches_proceed() {
        // Positive R5-R3: a genuine v2 attestation (digest recomputes) passes
        // the consumer gate and reaches Proceed.
        let _walker_guard = WALKER_TEST_LOCK.lock().unwrap();
        mida_antidebug_runtime::exports::reset_walker_bindings();
        let (mut c, _region) = controller_with_full_carriers(std::process::id());
        c.options.walker_dispatch = Some(Box::new(TestDispatchBridge::ok()));
        let outcome = c.run();
        assert!(
            matches!(outcome, AntidebugOutcome::Proceed { .. }),
            "valid V2 output must pass the digest gate, got {outcome:?}"
        );
        let phases: Vec<&str> = c.walker_events().iter().map(|e| e.phase.as_str()).collect();
        assert!(
            !phases.contains(&"output_verify_fail"),
            "no verify failure expected: {phases:?}"
        );
        mida_antidebug_runtime::exports::reset_walker_bindings();
    }
}
