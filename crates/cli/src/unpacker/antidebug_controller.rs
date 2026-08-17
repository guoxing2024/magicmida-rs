//! CLI-side anti-debug controller wiring (ADR-3B).
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
//!   -> TerminateProcess + bounded wait + handle cleanup
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
//! ScyllaHide is **not** a MIDA success proof. It may only run in explicit
//! oracle mode (future differential experiments, ADR-7); its results are
//! recorded with `source=scyllahide-oracle` and never upgrade the profile.
//!
//! ## Purity
//!
//! The lifecycle drive itself is pure (delegates to `mida_antidebug::state`).
//! The only I/O in this module is: (1) evidence file writing (atomic),
//! (2) the optional oracle-mode injector spawn. Both are isolated behind
//! small functions so the unit tests can exercise the whole flow with a
//! mock backend without launching any process.

use std::path::Path;

use mida_antidebug::evidence::EvidenceLog;
use mida_antidebug::profile::Profile;
use mida_antidebug::state::{transition, ControllerEvent, ControllerState, FailCode};

use crate::log::{self, LogType};

/// Schema of the minimal anti-debug failure evidence sidecar (ADR-3B).
///
/// Deliberately **not** a T5/acceptance schema: it is a CLI-local,
/// fail-closed record that follows the run output directory. It never
/// substitutes for TLS/PE/behavior success evidence and is never consumed
/// by the acceptance gate.
pub const ANTIDEBUG_EVIDENCE_SCHEMA: &str = "mida.antidebug-cli-failure/v1";

/// Runtime artifact name the dependency resolver looks for (ADR-4+).
pub const MIDA_RUNTIME_ARTIFACT: &str = "mida-antidebug-runtime-x64.dll";

/// Oracle-mode marker: ScyllaHide results are only ever recorded under
/// this source tag and never treated as MIDA success.
pub const SCYLLAHIDE_ORACLE_SOURCE: &str = "scyllahide-oracle";

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

/// Structured evidence record written on failure (minimal sidecar).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AntidebugFailureEvidence {
    pub schema: String,
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
    pub candidate_created: bool,
}

/// Options for the anti-debug stage.
#[derive(Debug, Clone)]
pub struct AntidebugStageOptions {
    /// Case id when known (bound at preflight); recorded in evidence.
    #[allow(dead_code)] // consumed by ADR-4 evidence binding
    pub sample_id: Option<String>,
    /// Target process id; recorded in evidence.
    #[allow(dead_code)] // consumed by ADR-4 evidence binding
    pub target_pid: u32,
    /// Where to write the failure evidence sidecar (run output directory).
    pub evidence_dir: Option<std::path::PathBuf>,
    /// Explicit opt-in oracle mode (ScyllaHide). `None` in production.
    pub oracle: Option<OracleMode>,
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

/// The anti-debug lifecycle driver.
#[derive(Debug)]
pub struct AntidebugController {
    state: ControllerState,
    log: EvidenceLog,
    options: AntidebugStageOptions,
    #[allow(dead_code)] // bound during ADR-4 runtime wiring
    profile: Option<Profile>,
}

impl AntidebugController {
    pub fn new(options: AntidebugStageOptions) -> Self {
        Self {
            state: ControllerState::Unresolved,
            log: EvidenceLog::new(),
            options,
            profile: None,
        }
    }

    /// Current lifecycle state.
    #[allow(dead_code)] // used by tests and ADR-4 wiring
    pub fn state(&self) -> ControllerState {
        self.state
    }

    /// Evidence accumulated so far (successful events are retained on failure).
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

    /// Resolve the anti-debug runtime dependency (ADR-3B: deterministic fail).
    ///
    /// The self-owned MIDA runtime does not exist yet. The dependency stage
    /// therefore cannot verify a runtime artifact and must fail closed.
    /// When a runtime ships (ADR-4+), this function resolves the vault
    /// artifact, verifies hash/size/architecture, and only then advances.
    fn resolve_dependency(&mut self) {
        // Dependency discovery: look for the MIDA runtime artifact.
        // For ADR-3B there is no artifact to find - the runtime crate does
        // not exist yet. Check the conventional location so the failure is
        // honest and structured rather than an assumption.
        let runtime_path = self
            .options
            .evidence_dir
            .as_deref()
            .map(|d| d.join(MIDA_RUNTIME_ARTIFACT));

        let found = runtime_path
            .as_deref()
            .map(|p| p.exists() && p.is_file())
            .unwrap_or(false);

        if found {
            // A runtime artifact exists: verify identity (hash/arch).
            // ADR-3B has no trusted runtime to verify against, so even a
            // present artifact is an identity mismatch until ADR-4 pins
            // the expected digest.
            self.drive(ControllerEvent::DependencyHashMismatch);
            return;
        }

        // No MIDA runtime: dependency unavailable -> fail closed.
        self.drive(ControllerEvent::DependenciesMissing);
    }

    /// Oracle-mode only: record that ScyllaHide would run as an oracle.
    ///
    /// ADR-3B does **not** spawn ScyllaHide (no live differential is
    /// authorized). The hook exists so the future differential task has a
    /// clearly marked, source-tagged seam - never a silent fallback.
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
    /// Returns [`AntidebugOutcome::Proceed`] only when the full success
    /// path is reachable with an actual runtime; otherwise returns
    /// [`AntidebugOutcome::Failed`] with the terminal failure state, the
    /// fail code, and a message. Evidence is always accumulated.
    pub fn run(&mut self) -> AntidebugOutcome {
        self.note_oracle_if_requested();

        // Stage 1: dependency resolution (fails closed without a runtime).
        self.resolve_dependency();
        if self.state.is_failure() {
            let code = self.fail_code_of_state(self.state);
            return AntidebugOutcome::Failed {
                state: self.state,
                fail_code: code,
                message: format!(
                    "anti-debug runtime dependency unavailable: {} not found;
                    fail-closed (MIDA runtime ships in ADR-4+)",
                    MIDA_RUNTIME_ARTIFACT,
                ),
            };
        }

        // Stages 2-10 are unreachable until a runtime exists. Drive them
        // defensively so the state machine shape stays explicit and any
        // future runtime wiring has a deterministic path to Proceed.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a controller with no oracle and a temp evidence dir.
    fn controller_with(temp: &std::path::Path) -> AntidebugController {
        AntidebugController::new(AntidebugStageOptions {
            sample_id: Some("origin_macro".to_string()),
            target_pid: 1234,
            evidence_dir: Some(temp.to_path_buf()),
            oracle: None,
        })
    }

    #[test]
    fn no_runtime_fails_closed_with_unavailable() {
        let temp = std::env::temp_dir().join("mida-adr3b-test-noruntime");
        let _ = std::fs::remove_dir_all(&temp);
        let mut c = controller_with(&temp);
        let outcome = c.run();
        match outcome {
            AntidebugOutcome::Failed {
                state, fail_code, ..
            } => {
                assert_eq!(state, ControllerState::DependencyUnavailable);
                assert_eq!(fail_code, FailCode::AntiDebugRuntimeUnavailable);
            }
            other => panic!("expected failure, got {other:?}"),
        }
        // failure state terminal: cannot reach Proceed
        let r = transition(c.state(), ControllerEvent::ProceedApproved, 99);
        assert!(!r.next_state.is_proceed());
        // evidence accumulated and monotonic
        let evs = c.evidence().events();
        assert!(!evs.is_empty());
        assert!(c.evidence().has_failure());
        assert_eq!(
            c.evidence().first_fail_code(),
            Some(FailCode::AntiDebugRuntimeUnavailable)
        );
    }

    #[test]
    fn failure_evidence_file_written_atomically() {
        let temp = std::env::temp_dir().join("mida-adr3b-test-evidence");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let ev = AntidebugFailureEvidence {
            schema: ANTIDEBUG_EVIDENCE_SCHEMA.to_string(),
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
            candidate_created: false,
        };
        let p = write_failure_evidence(&ev, &temp).unwrap();
        assert!(p.exists());
        // parse back and verify
        let back: AntidebugFailureEvidence =
            serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(back.fail_code, "AntiDebugRuntimeUnavailable");
        assert!(!back.candidate_created);
        assert_eq!(back.schema, ANTIDEBUG_EVIDENCE_SCHEMA);
    }

    #[test]
    fn evidence_write_failure_is_fail_closed() {
        // Writing into a path that is a *file* must fail.
        let temp = std::env::temp_dir().join("mida-adr3b-test-evidence-fail");
        let _ = std::fs::remove_dir_all(&temp);
        std::fs::create_dir_all(&temp).unwrap();
        let blocker = temp.join("blocker");
        std::fs::write(&blocker, b"x").unwrap();
        let ev = AntidebugFailureEvidence {
            schema: ANTIDEBUG_EVIDENCE_SCHEMA.to_string(),
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
            candidate_created: false,
        };
        // blocker is a file: create_dir_all fails -> Err
        let r = write_failure_evidence(&ev, &blocker);
        assert!(r.is_err());
    }

    #[test]
    fn oracle_mode_never_silently_falls_back() {
        let temp = std::env::temp_dir().join("mida-adr3b-test-oracle");
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
        });
        let outcome = c.run();
        // Oracle mode still fails closed: no runtime, no proceed.
        assert!(matches!(outcome, AntidebugOutcome::Failed { .. }));
        assert!(c.state().is_failure());
    }

    #[test]
    fn fail_code_mapping_table() {
        let c = controller_with(&std::env::temp_dir());
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
}
