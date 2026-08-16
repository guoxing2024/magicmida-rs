//! Fail-closed lifecycle state machine (ADR-3A).
//!
//! The controller lifecycle is an explicit state machine:
//!
//! ```text
//! Unresolved -> DependencyVerified -> ProfileVerified -> TargetIdentityVerified
//!   -> LaunchPrepared -> RuntimeLoading -> RuntimeInitialized
//!   -> HookHealthChecking -> Attested -> ProbeReady -> Proceed
//! ```
//!
//! Every failure is a terminal state. `Proceed` is only reachable from
//! `ProbeReady`. The [`transition`] function is pure and deterministic:
//! the same `(state, event)` always produces the same `TransitionResult`.

use crate::evidence::{EvidenceEvent, EvidenceLog};

/// Explicit controller lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ControllerState {
    // --- success path ---
    Unresolved,
    DependencyVerified,
    ProfileVerified,
    TargetIdentityVerified,
    LaunchPrepared,
    RuntimeLoading,
    RuntimeInitialized,
    HookHealthChecking,
    Attested,
    ProbeReady,
    Proceed,

    // --- terminal failure states ---
    DependencyUnavailable,
    DependencyIdentityMismatch,
    ArchitectureMismatch,
    ProfileMismatch,
    TargetIdentityMismatch,
    RuntimeLoadFailed,
    RuntimeInitializationFailed,
    PartialHooks,
    TelemetryLost,
    ProbeInconsistent,
    CleanupFailed,
}

impl ControllerState {
    /// Whether this state is a terminal failure state.
    pub const fn is_failure(&self) -> bool {
        matches!(
            self,
            ControllerState::DependencyUnavailable
                | ControllerState::DependencyIdentityMismatch
                | ControllerState::ArchitectureMismatch
                | ControllerState::ProfileMismatch
                | ControllerState::TargetIdentityMismatch
                | ControllerState::RuntimeLoadFailed
                | ControllerState::RuntimeInitializationFailed
                | ControllerState::PartialHooks
                | ControllerState::TelemetryLost
                | ControllerState::ProbeInconsistent
                | ControllerState::CleanupFailed,
        )
    }

    /// Whether this state is the final success state.
    pub const fn is_proceed(&self) -> bool {
        matches!(self, ControllerState::Proceed)
    }

    /// Canonical short name (used in evidence and logs).
    pub const fn name(&self) -> &'static str {
        match self {
            ControllerState::Unresolved => "Unresolved",
            ControllerState::DependencyVerified => "DependencyVerified",
            ControllerState::ProfileVerified => "ProfileVerified",
            ControllerState::TargetIdentityVerified => "TargetIdentityVerified",
            ControllerState::LaunchPrepared => "LaunchPrepared",
            ControllerState::RuntimeLoading => "RuntimeLoading",
            ControllerState::RuntimeInitialized => "RuntimeInitialized",
            ControllerState::HookHealthChecking => "HookHealthChecking",
            ControllerState::Attested => "Attested",
            ControllerState::ProbeReady => "ProbeReady",
            ControllerState::Proceed => "Proceed",
            ControllerState::DependencyUnavailable => "DependencyUnavailable",
            ControllerState::DependencyIdentityMismatch => "DependencyIdentityMismatch",
            ControllerState::ArchitectureMismatch => "ArchitectureMismatch",
            ControllerState::ProfileMismatch => "ProfileMismatch",
            ControllerState::TargetIdentityMismatch => "TargetIdentityMismatch",
            ControllerState::RuntimeLoadFailed => "RuntimeLoadFailed",
            ControllerState::RuntimeInitializationFailed => "RuntimeInitializationFailed",
            ControllerState::PartialHooks => "PartialHooks",
            ControllerState::TelemetryLost => "TelemetryLost",
            ControllerState::ProbeInconsistent => "ProbeInconsistent",
            ControllerState::CleanupFailed => "CleanupFailed",
        }
    }
}

/// Fail codes (ADR-0 EVIDENCE_CONTRACT §4.1 + ADR-3A `AntiDebugProfileMismatch`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailCode {
    AntiDebugRuntimeUnavailable,
    AntiDebugRuntimeIdentityMismatch,
    AntiDebugRuntimeArchitectureMismatch,
    /// Dedicated profile error (ADR-3A decision): profile/sample/arch/digest
    /// mismatch, unknown surface in hard_required, or required_candidate
    /// misused as hard_required. Kept separate from runtime identity so
    /// promotion/revision audits can be counted independently.
    AntiDebugProfileMismatch,
    AntiDebugRuntimeInitializationFailed,
    AntiDebugRuntimePartialHooks,
    AntiDebugRuntimeTelemetryLost,
    ProbeInconsistent,
    CleanupFailed,
}

impl FailCode {
    /// Canonical code string (matches evidence contract).
    pub const fn as_str(&self) -> &'static str {
        match self {
            FailCode::AntiDebugRuntimeUnavailable => "AntiDebugRuntimeUnavailable",
            FailCode::AntiDebugRuntimeIdentityMismatch => "AntiDebugRuntimeIdentityMismatch",
            FailCode::AntiDebugRuntimeArchitectureMismatch => {
                "AntiDebugRuntimeArchitectureMismatch"
            }
            FailCode::AntiDebugProfileMismatch => "AntiDebugProfileMismatch",
            FailCode::AntiDebugRuntimeInitializationFailed => {
                "AntiDebugRuntimeInitializationFailed"
            }
            FailCode::AntiDebugRuntimePartialHooks => "AntiDebugRuntimePartialHooks",
            FailCode::AntiDebugRuntimeTelemetryLost => "AntiDebugRuntimeTelemetryLost",
            FailCode::ProbeInconsistent => "ProbeInconsistent",
            FailCode::CleanupFailed => "CleanupFailed",
        }
    }
}

/// Controller events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControllerEvent {
    DependenciesVerified,
    DependenciesMissing,
    DependencyHashMismatch,
    ArchitectureMismatch,
    ProfileValidated,
    ProfileRejected,
    TargetIdentityValidated,
    TargetIdentityRejected,
    LaunchPrepared,
    LaunchFailed,
    RuntimeLoadStarted,
    RuntimeLoadFailed,
    RuntimeInitialized,
    RuntimeInitFailed,
    HealthCheckStarted,
    HealthCheckPassed,
    HealthCheckFailed,
    TelemetryLost,
    ProbeSetPassed,
    ProbeInconsistent,
    ProceedApproved,
    CleanupFailed,
}

/// Result of a single transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionResult {
    pub next_state: ControllerState,
    pub evidence_events: Vec<EvidenceEvent>,
    pub fail_code: Option<FailCode>,
}

/// Pure transition function: `(state, event) -> TransitionResult`.
///
/// Deterministic, no I/O. Failure states are terminal: no event can move
/// out of a failure state, and `Proceed` is only reachable from `ProbeReady`.
pub fn transition(
    state: ControllerState,
    event: ControllerEvent,
    sequence: u32,
) -> TransitionResult {
    use ControllerEvent as E;
    use ControllerState as S;

    let mk = |s: S, e: E, code: Option<FailCode>| TransitionResult {
        next_state: s,
        evidence_events: vec![EvidenceEvent::new(s, e, sequence, code)],
        fail_code: code,
    };

    let ret = match (state, event) {
        // ---------------- success path ----------------
        (S::Unresolved, E::DependenciesVerified) => {
            mk(S::DependencyVerified, E::DependenciesVerified, None)
        }
        (S::Unresolved, E::DependenciesMissing) => mk(
            S::DependencyUnavailable,
            E::DependenciesMissing,
            Some(FailCode::AntiDebugRuntimeUnavailable),
        ),
        (S::Unresolved, E::DependencyHashMismatch) => mk(
            S::DependencyIdentityMismatch,
            E::DependencyHashMismatch,
            Some(FailCode::AntiDebugRuntimeIdentityMismatch),
        ),
        (S::Unresolved, E::ArchitectureMismatch) => mk(
            S::ArchitectureMismatch,
            E::ArchitectureMismatch,
            Some(FailCode::AntiDebugRuntimeArchitectureMismatch),
        ),

        (S::DependencyVerified, E::ProfileValidated) => {
            mk(S::ProfileVerified, E::ProfileValidated, None)
        }
        (S::DependencyVerified, E::ProfileRejected) => mk(
            S::ProfileMismatch,
            E::ProfileRejected,
            Some(FailCode::AntiDebugProfileMismatch),
        ),

        (S::ProfileVerified, E::TargetIdentityValidated) => {
            mk(S::TargetIdentityVerified, E::TargetIdentityValidated, None)
        }
        (S::ProfileVerified, E::TargetIdentityRejected) => mk(
            S::TargetIdentityMismatch,
            E::TargetIdentityRejected,
            Some(FailCode::AntiDebugRuntimeIdentityMismatch),
        ),

        (S::TargetIdentityVerified, E::LaunchPrepared) => {
            mk(S::LaunchPrepared, E::LaunchPrepared, None)
        }
        (S::TargetIdentityVerified, E::LaunchFailed) => mk(
            S::RuntimeLoadFailed,
            E::LaunchFailed,
            Some(FailCode::AntiDebugRuntimeUnavailable),
        ),

        (S::LaunchPrepared, E::RuntimeLoadStarted) => {
            mk(S::RuntimeLoading, E::RuntimeLoadStarted, None)
        }
        (S::LaunchPrepared, E::RuntimeLoadFailed) => mk(
            S::RuntimeLoadFailed,
            E::RuntimeLoadFailed,
            Some(FailCode::AntiDebugRuntimeUnavailable),
        ),

        (S::RuntimeLoading, E::RuntimeInitialized) => {
            mk(S::RuntimeInitialized, E::RuntimeInitialized, None)
        }
        (S::RuntimeLoading, E::RuntimeInitFailed) => mk(
            S::RuntimeInitializationFailed,
            E::RuntimeInitFailed,
            Some(FailCode::AntiDebugRuntimeInitializationFailed),
        ),

        (S::RuntimeInitialized, E::HealthCheckStarted) => {
            mk(S::HookHealthChecking, E::HealthCheckStarted, None)
        }

        (S::HookHealthChecking, E::HealthCheckPassed) => {
            mk(S::Attested, E::HealthCheckPassed, None)
        }
        (S::HookHealthChecking, E::HealthCheckFailed) => mk(
            S::PartialHooks,
            E::HealthCheckFailed,
            Some(FailCode::AntiDebugRuntimePartialHooks),
        ),
        (S::HookHealthChecking, E::TelemetryLost) => mk(
            S::TelemetryLost,
            E::TelemetryLost,
            Some(FailCode::AntiDebugRuntimeTelemetryLost),
        ),

        (S::Attested, E::ProbeSetPassed) => mk(S::ProbeReady, E::ProbeSetPassed, None),
        (S::Attested, E::ProbeInconsistent) => mk(
            S::ProbeInconsistent,
            E::ProbeInconsistent,
            Some(FailCode::ProbeInconsistent),
        ),
        (S::Attested, E::TelemetryLost) => mk(
            S::TelemetryLost,
            E::TelemetryLost,
            Some(FailCode::AntiDebugRuntimeTelemetryLost),
        ),

        (S::ProbeReady, E::ProceedApproved) => mk(S::Proceed, E::ProceedApproved, None),

        // cleanup can fail from any non-terminal, non-proceed state
        (_, E::CleanupFailed) if !state.is_failure() && !state.is_proceed() => mk(
            S::CleanupFailed,
            E::CleanupFailed,
            Some(FailCode::CleanupFailed),
        ),

        // ---------------- terminal / illegal: deterministic reject ----------------
        // Failure states are terminal: any event keeps them terminal.
        (s, e) if s.is_failure() => TransitionResult {
            next_state: s,
            evidence_events: vec![EvidenceEvent::new(s, e, sequence, None)],
            fail_code: None,
        },
        // Proceed is terminal success: further events are rejected (no-op).
        (s, e) if s.is_proceed() => TransitionResult {
            next_state: s,
            evidence_events: vec![EvidenceEvent::new(s, e, sequence, None)],
            fail_code: None,
        },
        // Any other (state, event) pair is illegal: stay in state, no fail code.
        (s, e) => TransitionResult {
            next_state: s,
            evidence_events: vec![EvidenceEvent::new(s, e, sequence, None)],
            fail_code: None,
        },
    };
    ret
}

/// Drive a full success path from `Unresolved` to `Proceed`.
/// Pure helper for tests and future wiring.
pub fn run_full_success_path() -> (ControllerState, EvidenceLog) {
    use ControllerEvent as E;
    let events = [
        E::DependenciesVerified,
        E::ProfileValidated,
        E::TargetIdentityValidated,
        E::LaunchPrepared,
        E::RuntimeLoadStarted,
        E::RuntimeInitialized,
        E::HealthCheckStarted,
        E::HealthCheckPassed,
        E::ProbeSetPassed,
        E::ProceedApproved,
    ];
    let mut state = ControllerState::Unresolved;
    let mut log = EvidenceLog::new();
    for (i, ev) in events.iter().enumerate() {
        let seq = (i + 1) as u32;
        let r = transition(state, *ev, seq);
        log.extend(r.evidence_events);
        state = r.next_state;
    }
    (state, log)
}
