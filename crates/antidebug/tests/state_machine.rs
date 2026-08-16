//! ADR-3A integration tests: state machine + profile resolver + evidence.

use mida_antidebug::evidence::EvidenceLog;
use mida_antidebug::profile::demote_candidate_to_observe_only as demote_candidate;
use mida_antidebug::profile::{
    lunlun_profile, origin_profile, promote_candidate, reject_candidate_as_hard,
    validate_hard_required, validate_profile, Profile, ProofLevel, SurfaceClass, KNOWN_SURFACES,
    SAMPLE_LUNLUN, SAMPLE_ORIGIN,
};
use mida_antidebug::state::{transition, ControllerEvent, ControllerState, FailCode};

const ALL_EVENTS: [ControllerEvent; 22] = [
    ControllerEvent::DependenciesVerified,
    ControllerEvent::DependenciesMissing,
    ControllerEvent::DependencyHashMismatch,
    ControllerEvent::ArchitectureMismatch,
    ControllerEvent::ProfileValidated,
    ControllerEvent::ProfileRejected,
    ControllerEvent::TargetIdentityValidated,
    ControllerEvent::TargetIdentityRejected,
    ControllerEvent::LaunchPrepared,
    ControllerEvent::LaunchFailed,
    ControllerEvent::RuntimeLoadStarted,
    ControllerEvent::RuntimeLoadFailed,
    ControllerEvent::RuntimeInitialized,
    ControllerEvent::RuntimeInitFailed,
    ControllerEvent::HealthCheckStarted,
    ControllerEvent::HealthCheckPassed,
    ControllerEvent::HealthCheckFailed,
    ControllerEvent::TelemetryLost,
    ControllerEvent::ProbeSetPassed,
    ControllerEvent::ProbeInconsistent,
    ControllerEvent::ProceedApproved,
    ControllerEvent::CleanupFailed,
];

fn drive(events: &[ControllerEvent]) -> (ControllerState, EvidenceLog) {
    let mut state = ControllerState::Unresolved;
    let mut log = EvidenceLog::new();
    for (i, e) in events.iter().enumerate() {
        let r = transition(state, *e, (i + 1) as u32);
        log.extend(r.evidence_events);
        state = r.next_state;
        if state.is_failure() || state.is_proceed() {
            break;
        }
    }
    (state, log)
}

// ----------------------------------------------------------------
// success path
// ----------------------------------------------------------------

#[test]
fn full_success_path_reaches_proceed() {
    let events = [
        ControllerEvent::DependenciesVerified,
        ControllerEvent::ProfileValidated,
        ControllerEvent::TargetIdentityValidated,
        ControllerEvent::LaunchPrepared,
        ControllerEvent::RuntimeLoadStarted,
        ControllerEvent::RuntimeInitialized,
        ControllerEvent::HealthCheckStarted,
        ControllerEvent::HealthCheckPassed,
        ControllerEvent::ProbeSetPassed,
        ControllerEvent::ProceedApproved,
    ];
    let (state, log) = drive(&events);
    assert_eq!(state, ControllerState::Proceed);
    assert_eq!(log.len(), 10);
    assert!(!log.has_failure());
    // every success state visited in order
    let chain: Vec<ControllerState> = log.state_chain();
    assert_eq!(chain[0], ControllerState::DependencyVerified);
    assert_eq!(chain[1], ControllerState::ProfileVerified);
    assert_eq!(chain[2], ControllerState::TargetIdentityVerified);
    assert_eq!(chain[3], ControllerState::LaunchPrepared);
    assert_eq!(chain[4], ControllerState::RuntimeLoading);
    assert_eq!(chain[5], ControllerState::RuntimeInitialized);
    assert_eq!(chain[6], ControllerState::HookHealthChecking);
    assert_eq!(chain[7], ControllerState::Attested);
    assert_eq!(chain[8], ControllerState::ProbeReady);
    assert_eq!(chain[9], ControllerState::Proceed);
}

// ----------------------------------------------------------------
// each failure transition
// ----------------------------------------------------------------

#[test]
fn each_failure_transition_is_terminal_with_code() {
    let cases: &[(ControllerState, ControllerEvent, ControllerState, FailCode)] = &[
        (
            ControllerState::Unresolved,
            ControllerEvent::DependenciesMissing,
            ControllerState::DependencyUnavailable,
            FailCode::AntiDebugRuntimeUnavailable,
        ),
        (
            ControllerState::Unresolved,
            ControllerEvent::DependencyHashMismatch,
            ControllerState::DependencyIdentityMismatch,
            FailCode::AntiDebugRuntimeIdentityMismatch,
        ),
        (
            ControllerState::Unresolved,
            ControllerEvent::ArchitectureMismatch,
            ControllerState::ArchitectureMismatch,
            FailCode::AntiDebugRuntimeArchitectureMismatch,
        ),
        (
            ControllerState::DependencyVerified,
            ControllerEvent::ProfileRejected,
            ControllerState::ProfileMismatch,
            FailCode::AntiDebugProfileMismatch,
        ),
        (
            ControllerState::ProfileVerified,
            ControllerEvent::TargetIdentityRejected,
            ControllerState::TargetIdentityMismatch,
            FailCode::AntiDebugRuntimeIdentityMismatch,
        ),
        (
            ControllerState::TargetIdentityVerified,
            ControllerEvent::LaunchFailed,
            ControllerState::RuntimeLoadFailed,
            FailCode::AntiDebugRuntimeUnavailable,
        ),
        (
            ControllerState::LaunchPrepared,
            ControllerEvent::RuntimeLoadFailed,
            ControllerState::RuntimeLoadFailed,
            FailCode::AntiDebugRuntimeUnavailable,
        ),
        (
            ControllerState::RuntimeLoading,
            ControllerEvent::RuntimeInitFailed,
            ControllerState::RuntimeInitializationFailed,
            FailCode::AntiDebugRuntimeInitializationFailed,
        ),
        (
            ControllerState::HookHealthChecking,
            ControllerEvent::HealthCheckFailed,
            ControllerState::PartialHooks,
            FailCode::AntiDebugRuntimePartialHooks,
        ),
        (
            ControllerState::HookHealthChecking,
            ControllerEvent::TelemetryLost,
            ControllerState::TelemetryLost,
            FailCode::AntiDebugRuntimeTelemetryLost,
        ),
        (
            ControllerState::Attested,
            ControllerEvent::ProbeInconsistent,
            ControllerState::ProbeInconsistent,
            FailCode::ProbeInconsistent,
        ),
        (
            ControllerState::Attested,
            ControllerEvent::TelemetryLost,
            ControllerState::TelemetryLost,
            FailCode::AntiDebugRuntimeTelemetryLost,
        ),
        (
            ControllerState::RuntimeLoading,
            ControllerEvent::CleanupFailed,
            ControllerState::CleanupFailed,
            FailCode::CleanupFailed,
        ),
    ];
    for (start, ev, expect, code) in cases {
        let r = transition(*start, *ev, 1);
        assert_eq!(r.next_state, *expect, "from {:?} + {:?}", start, ev);
        assert_eq!(r.fail_code, Some(*code));
        assert!(r.next_state.is_failure());
    }
}

// ----------------------------------------------------------------
// Proceed unreachability
// ----------------------------------------------------------------

#[test]
fn proceed_unreachable_from_failure_states() {
    let fails = [
        ControllerState::DependencyUnavailable,
        ControllerState::DependencyIdentityMismatch,
        ControllerState::ArchitectureMismatch,
        ControllerState::ProfileMismatch,
        ControllerState::TargetIdentityMismatch,
        ControllerState::RuntimeLoadFailed,
        ControllerState::RuntimeInitializationFailed,
        ControllerState::PartialHooks,
        ControllerState::TelemetryLost,
        ControllerState::ProbeInconsistent,
        ControllerState::CleanupFailed,
    ];
    for f in fails {
        for e in ALL_EVENTS {
            let r = transition(f, e, 1);
            assert_eq!(r.next_state, f, "{:?} must be terminal", f);
            assert!(!r.next_state.is_proceed());
        }
    }
}

#[test]
fn no_direct_jumps_to_proceed() {
    // Unresolved -> Proceed, ProfileVerified -> Proceed, Attested -> Proceed
    // are all illegal and must stay in state.
    for (s, e) in [
        (
            ControllerState::Unresolved,
            ControllerEvent::ProceedApproved,
        ),
        (
            ControllerState::ProfileVerified,
            ControllerEvent::ProceedApproved,
        ),
        (ControllerState::Attested, ControllerEvent::ProceedApproved),
        (
            ControllerState::Unresolved,
            ControllerEvent::HealthCheckPassed,
        ),
    ] {
        let r = transition(s, e, 1);
        assert_eq!(r.next_state, s);
        assert!(!r.next_state.is_proceed());
    }
    // only ProbeReady + ProceedApproved works
    let r = transition(
        ControllerState::ProbeReady,
        ControllerEvent::ProceedApproved,
        1,
    );
    assert_eq!(r.next_state, ControllerState::Proceed);
}

// ----------------------------------------------------------------
// determinism
// ----------------------------------------------------------------

#[test]
fn same_input_same_output() {
    let mut rng_state: u64 = 0x1234;
    for _ in 0..200 {
        // deterministic pseudo-random walk
        rng_state = rng_state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let s_idx = (rng_state % 22) as usize;
        let states = [
            ControllerState::Unresolved,
            ControllerState::DependencyVerified,
            ControllerState::ProfileVerified,
            ControllerState::TargetIdentityVerified,
            ControllerState::LaunchPrepared,
            ControllerState::RuntimeLoading,
            ControllerState::RuntimeInitialized,
            ControllerState::HookHealthChecking,
            ControllerState::Attested,
            ControllerState::ProbeReady,
            ControllerState::DependencyUnavailable,
            ControllerState::DependencyIdentityMismatch,
            ControllerState::ArchitectureMismatch,
            ControllerState::ProfileMismatch,
            ControllerState::TargetIdentityMismatch,
            ControllerState::RuntimeLoadFailed,
            ControllerState::RuntimeInitializationFailed,
            ControllerState::PartialHooks,
            ControllerState::TelemetryLost,
            ControllerState::ProbeInconsistent,
            ControllerState::CleanupFailed,
            ControllerState::Proceed,
        ];
        let e_idx = (rng_state % 22) as usize;
        let r1 = transition(states[s_idx], ALL_EVENTS[e_idx], 5);
        let r2 = transition(states[s_idx], ALL_EVENTS[e_idx], 5);
        assert_eq!(r1, r2);
    }
}

// ----------------------------------------------------------------
// profile
// ----------------------------------------------------------------

#[test]
fn origin_profile_shapes() {
    let p = origin_profile();
    assert_eq!(p.sample_id, SAMPLE_ORIGIN);
    // hard_required: exactly AD-PROC-002, AD-PROC-003
    let hard: Vec<&str> = p
        .surfaces_of(SurfaceClass::HardRequired)
        .iter()
        .map(|s| s.surface_id.as_str())
        .collect();
    assert_eq!(hard, vec!["AD-PROC-002", "AD-PROC-003"]);
    // required_candidate: exactly AD-PROC-001
    let cand: Vec<&str> = p
        .surfaces_of(SurfaceClass::RequiredCandidate)
        .iter()
        .map(|s| s.surface_id.as_str())
        .collect();
    assert_eq!(cand, vec!["AD-PROC-001"]);
    // 24 surfaces total
    assert_eq!(p.surfaces.len(), 24);
    // candidate != hard_required
    assert_ne!(p.class_of("AD-PROC-001"), Some(SurfaceClass::HardRequired));
}

#[test]
fn lunlun_profile_shapes() {
    let p = lunlun_profile();
    assert_eq!(p.sample_id, SAMPLE_LUNLUN);
    let hard: Vec<&str> = p
        .surfaces_of(SurfaceClass::HardRequired)
        .iter()
        .map(|s| s.surface_id.as_str())
        .collect();
    assert_eq!(hard, vec!["AD-PROC-002", "AD-PROC-003"]);
    // no candidate (conservative)
    assert!(p.surfaces_of(SurfaceClass::RequiredCandidate).is_empty());
    // AD-PROC-001 is observe-only, NOT copied from origin
    assert_eq!(p.class_of("AD-PROC-001"), Some(SurfaceClass::ObserveOnly));
    assert_eq!(p.surfaces.len(), 24);
}

#[test]
fn origin_lunlun_profiles_are_independent() {
    let o = origin_profile();
    let l = lunlun_profile();
    assert_ne!(o.profile_id, l.profile_id);
    assert_ne!(o.profile_digest(), l.profile_digest());
    assert_ne!(o.class_of("AD-PROC-001"), l.class_of("AD-PROC-001"));
}

#[test]
fn profile_validation_pass() {
    let p = origin_profile();
    let d = p.profile_digest();
    assert!(validate_profile(&p, SAMPLE_ORIGIN, "x86_64", &d).is_ok());
    assert!(validate_hard_required(&p, &KNOWN_SURFACES).is_ok());
    // candidates not misused as hard
    assert!(reject_candidate_as_hard(&p, &["AD-PROC-001"]).is_ok());
}

#[test]
fn profile_sample_mismatch_rejected() {
    let p = origin_profile();
    let d = p.profile_digest();
    let r = validate_profile(&p, SAMPLE_LUNLUN, "x86_64", &d);
    assert!(r.is_err());
}

#[test]
fn profile_arch_mismatch_rejected() {
    let p = origin_profile();
    let d = p.profile_digest();
    let r = validate_profile(&p, SAMPLE_ORIGIN, "x86", &d);
    assert!(r.is_err());
}

#[test]
fn profile_digest_mismatch_rejected() {
    let p = origin_profile();
    let r = validate_profile(&p, SAMPLE_ORIGIN, "x86_64", "deadbeef");
    assert!(r.is_err());
}

#[test]
fn duplicate_surface_rejected() {
    let mut p = origin_profile();
    let dup = p.surfaces[0].clone();
    p.surfaces.push(dup);
    let d = p.profile_digest();
    assert!(validate_profile(&p, SAMPLE_ORIGIN, "x86_64", &d).is_err());
}

#[test]
fn unknown_surface_in_hard_required_rejected() {
    let mut p = origin_profile();
    p.surfaces.push(mida_antidebug::profile::SurfaceSpec {
        surface_id: "AD-NOPE-999".to_string(),
        class: SurfaceClass::HardRequired,
        basis: vec![],
    });
    assert!(validate_hard_required(&p, &KNOWN_SURFACES).is_err());
}

#[test]
fn candidate_misused_as_hard_rejected() {
    // Simulate a broken profile where AD-PROC-001 was serialized as hard_required
    let mut p = origin_profile();
    for s in p.surfaces.iter_mut() {
        if s.surface_id == "AD-PROC-001" {
            s.class = SurfaceClass::HardRequired;
        }
    }
    let r = reject_candidate_as_hard(&p, &["AD-PROC-001"]);
    assert!(r.is_err());
}

#[test]
fn empty_profile_rejected() {
    let p = Profile {
        schema: "mida.antidebug-profile/v1".to_string(),
        profile_id: "x".to_string(),
        sample_id: SAMPLE_ORIGIN.to_string(),
        architecture: "x86_64".to_string(),
        surfaces: vec![],
        profile_basis: vec![],
        version: 1,
    };
    assert!(validate_profile(&p, SAMPLE_ORIGIN, "x86_64", "abc").is_err());
}

// ----------------------------------------------------------------
// promotion
// ----------------------------------------------------------------

#[test]
fn promote_candidate_with_sufficient_proof() {
    let p = origin_profile();
    let rev = promote_candidate(
        &p,
        "AD-PROC-001",
        ProofLevel::CallSiteConfirmed,
        vec![
            "iat_evidence slot 92".to_string(),
            "controlled probe obs-0001".to_string(),
        ],
    )
    .expect("promotion should succeed");
    assert_eq!(rev.profile.version, 2);
    assert_eq!(rev.previous_version, 1);
    assert_eq!(
        rev.profile.class_of("AD-PROC-001"),
        Some(SurfaceClass::HardRequired)
    );
    assert_ne!(rev.new_profile_digest(), p.profile_digest());
    assert!(!rev.audit_record.is_empty());
    // promoted profile still validates
    let d = rev.profile.profile_digest();
    assert!(validate_profile(&rev.profile, SAMPLE_ORIGIN, "x86_64", &d).is_ok());
}

#[test]
fn promote_with_missing_evidence_fails() {
    let p = origin_profile();
    let r = promote_candidate(&p, "AD-PROC-001", ProofLevel::CallSiteConfirmed, vec![]);
    assert!(r.is_err());
    // profile unchanged
    assert_eq!(p.version, 1);
}

#[test]
fn promote_with_insufficient_proof_fails() {
    let p = origin_profile();
    let r = promote_candidate(
        &p,
        "AD-PROC-001",
        ProofLevel::PresenceObserved,
        vec!["iat presence".to_string()],
    );
    assert!(r.is_err());
    assert_eq!(
        p.class_of("AD-PROC-001"),
        Some(SurfaceClass::RequiredCandidate)
    );
}

#[test]
fn promote_non_candidate_fails() {
    let p = origin_profile();
    // AD-PROC-002 is hard_required, not a candidate
    let r = promote_candidate(
        &p,
        "AD-PROC-002",
        ProofLevel::RuntimeObserved,
        vec!["x".to_string()],
    );
    assert!(r.is_err());
    // lunlun AD-PROC-001 is observe-only, not a candidate
    let l = lunlun_profile();
    let r2 = promote_candidate(
        &l,
        "AD-PROC-001",
        ProofLevel::RuntimeObserved,
        vec!["x".to_string()],
    );
    assert!(r2.is_err());
}

#[test]
fn demote_candidate_to_observe_only() {
    let p = origin_profile();
    let rev = demote_candidate(&p, "AD-PROC-001").expect("demote");
    assert_eq!(
        rev.profile.class_of("AD-PROC-001"),
        Some(SurfaceClass::ObserveOnly)
    );
    assert_eq!(rev.profile.version, 2);
    // never silently keeps hard_required
    assert_ne!(
        rev.profile.class_of("AD-PROC-001"),
        Some(SurfaceClass::HardRequired)
    );
}

#[test]
fn demote_only_works_on_candidates() {
    let p = origin_profile();
    let r = demote_candidate(&p, "AD-PROC-002");
    assert!(r.is_err());
}

// ----------------------------------------------------------------
// evidence
// ----------------------------------------------------------------

#[test]
fn failure_evidence_retains_prior_successes() {
    let events = [
        ControllerEvent::DependenciesVerified,
        ControllerEvent::ProfileValidated,
        ControllerEvent::TargetIdentityValidated,
        ControllerEvent::LaunchPrepared,
        ControllerEvent::RuntimeLoadStarted,
        ControllerEvent::RuntimeInitFailed,
    ];
    let (state, log) = drive(&events);
    assert_eq!(state, ControllerState::RuntimeInitializationFailed);
    assert_eq!(log.len(), 6);
    assert!(log.has_failure());
    assert_eq!(
        log.first_fail_code(),
        Some(FailCode::AntiDebugRuntimeInitializationFailed)
    );
    // prior successes retained
    assert_eq!(log.state_chain()[0], ControllerState::DependencyVerified);
    assert_eq!(log.state_chain()[4], ControllerState::RuntimeLoading);
}

#[test]
fn cleanup_failure_is_terminal() {
    let (state, _) = drive(&[
        ControllerEvent::DependenciesVerified,
        ControllerEvent::CleanupFailed,
    ]);
    assert_eq!(state, ControllerState::CleanupFailed);
    assert!(state.is_failure());
    // terminal: no event escapes
    let r = transition(state, ControllerEvent::DependenciesVerified, 1);
    assert_eq!(r.next_state, state);
}

#[test]
fn illegal_event_rejected_deterministically() {
    // repeat-event behavior: DependenciesVerified twice is illegal the 2nd time
    let r1 = transition(
        ControllerState::Unresolved,
        ControllerEvent::DependenciesVerified,
        1,
    );
    let r2 = transition(r1.next_state, ControllerEvent::DependenciesVerified, 2);
    assert_eq!(r1.next_state, ControllerState::DependencyVerified);
    assert_eq!(r2.next_state, ControllerState::DependencyVerified); // stays
    assert_eq!(r2.fail_code, None);
}
