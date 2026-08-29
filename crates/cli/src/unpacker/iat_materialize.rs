//! XX-4 (B'): WinLicense lazy-IAT materialization wait — decision core.
//!
//! WinLicense materializes imports lazily at execution time. The XX-2/XX-3
//! frozen-dump moment catches `.text` decrypted but the IAT slot still
//! unmapped (an unmapped hole). The fix is **not** to find the IAT earlier —
//! it does not exist yet — but to let execution advance to the point where the
//! import is about to be read: the first indirect `call/jmp [mem]` site whose
//! memory operand points outside the image.
//!
//! This module owns the *decision* only (pure, host-independent). The host
//! (`mod.rs`) owns the Win32: arming software breakpoints, continuing, and
//! freezing at hit. Splitting the two keeps the fallback chain and timeout
//! policy unit-testable without a live debuggee.

/// One step the host should take in the materialization wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MaterializeStep {
    /// Set a software breakpoint at the FF15 site and continue.
    ArmSite(usize),
    /// Set a software breakpoint at the OEP and continue (fallback).
    ArmOep(usize),
    /// No anchor / timed out: freeze the process and dump (fail-closed IAT).
    FreezeAndDump,
    /// Still within the time budget: keep waiting.
    Wait,
}

/// Per-anchor budget for the materialization wait (seconds).
pub(super) const IAT_MATERIALIZE_TIMEOUT_SECS: u64 = 30;

/// XX-6 (L'): consecutive identical `(code, address, params)` AVs during the
/// materialization wait beyond this count mean the VM is deadlocked (zero
/// evolution of the exception tuple). Distinct from the 30s timeout, which
/// bounds a *progressing* VM that simply never reaches the FF15 anchor.
pub(super) const IAT_MATERIALIZE_AV_DEADLOCK_THRESHOLD: u32 = 256;

/// XX-6: log every AV up to this streak, then throttle (telemetry for the
/// "is the VM progressing?" classification).
pub(super) const IAT_MATERIALIZE_AV_TELEMETRY_FULL: u32 = 16;

/// XX-6: after the full-telemetry window, log one line per this many repeats.
pub(super) const IAT_MATERIALIZE_AV_LOG_INTERVAL: u32 = 100_000;

/// XX-6: decide whether an identical-AV streak is a VM deadlock (zero
/// evolution) warranting escape with `VmExceptionDeadlock`.
///
/// Pure so the threshold is unit-tested without a live debuggee.
pub(super) fn av_deadlock_triggered(streak: u32) -> bool {
    streak >= IAT_MATERIALIZE_AV_DEADLOCK_THRESHOLD
}

/// XX-6: decide whether to log this AV. Full telemetry for the first
/// `IAT_MATERIALIZE_AV_TELEMETRY_FULL` occurrences, then throttled to the
/// interval. `streak` is 1-based (first occurrence of a new pair = 1).
pub(super) fn should_log_materialize_av(streak: u32) -> bool {
    streak <= IAT_MATERIALIZE_AV_TELEMETRY_FULL
        || streak.is_multiple_of(IAT_MATERIALIZE_AV_LOG_INTERVAL)
}

/// Decide the initial anchor after `.text` is stable and RIP is not in `.text`.
///
/// * `site` — the first out-of-image indirect call/jmp site (from
///   [`first_out_of_image_iat_site`](mida_packers_themida::first_out_of_image_iat_site)).
/// * `oep` — the scan-resolved OEP (fallback anchor when no site exists).
pub(super) fn initial_materialize_step(site: Option<usize>, oep: Option<usize>) -> MaterializeStep {
    match (site, oep) {
        (Some(s), _) => MaterializeStep::ArmSite(s),
        (None, Some(o)) => MaterializeStep::ArmOep(o),
        (None, None) => MaterializeStep::FreezeAndDump,
    }
}

/// Decide the next step while an anchor is armed but not yet hit.
///
/// * `fallback_done` — whether we already fell back from site → OEP.
/// * `oep` — the OEP (fallback anchor; only used once).
/// * `elapsed_secs` — time since the current anchor was armed.
/// * `timeout_secs` — per-anchor budget (30s).
pub(super) fn timeout_materialize_step(
    fallback_done: bool,
    oep: Option<usize>,
    elapsed_secs: u64,
    timeout_secs: u64,
) -> MaterializeStep {
    if elapsed_secs < timeout_secs {
        return MaterializeStep::Wait;
    }
    // Budget exhausted: advance the fallback chain once, then give up.
    if !fallback_done {
        if let Some(o) = oep {
            return MaterializeStep::ArmOep(o);
        }
    }
    MaterializeStep::FreezeAndDump
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_prefers_ff15_site_over_oep() {
        assert_eq!(
            initial_materialize_step(Some(0x1400_2964e), Some(0x1400_11020)),
            MaterializeStep::ArmSite(0x1400_2964e)
        );
    }

    #[test]
    fn initial_falls_back_to_oep_when_no_site() {
        assert_eq!(
            initial_materialize_step(None, Some(0x1400_11020)),
            MaterializeStep::ArmOep(0x1400_11020)
        );
    }

    #[test]
    fn initial_freezes_when_no_anchor() {
        assert_eq!(
            initial_materialize_step(None, None),
            MaterializeStep::FreezeAndDump
        );
    }

    #[test]
    fn timeout_within_budget_waits() {
        assert_eq!(
            timeout_materialize_step(false, Some(0x1400_11020), 10, 30),
            MaterializeStep::Wait
        );
        assert_eq!(
            timeout_materialize_step(false, Some(0x1400_11020), 29, 30),
            MaterializeStep::Wait
        );
    }

    #[test]
    fn timeout_advances_fallback_chain_site_to_oep() {
        // site armed, budget exhausted, OEP available -> ArmOep.
        assert_eq!(
            timeout_materialize_step(false, Some(0x1400_11020), 30, 30),
            MaterializeStep::ArmOep(0x1400_11020)
        );
    }

    #[test]
    fn timeout_after_fallback_freezes() {
        // fallback already done, budget exhausted -> freeze.
        assert_eq!(
            timeout_materialize_step(true, Some(0x1400_11020), 30, 30),
            MaterializeStep::FreezeAndDump
        );
    }

    #[test]
    fn timeout_without_oep_freezes() {
        // site armed, budget exhausted, no OEP -> freeze.
        assert_eq!(
            timeout_materialize_step(false, None, 30, 30),
            MaterializeStep::FreezeAndDump
        );
    }

    #[test]
    fn full_fallback_chain_site_timeout_oep_timeout_freeze() {
        // site -> (timeout) -> oep -> (timeout) -> freeze
        assert_eq!(
            initial_materialize_step(Some(1), Some(2)),
            MaterializeStep::ArmSite(1)
        );
        assert_eq!(
            timeout_materialize_step(false, Some(2), 30, 30),
            MaterializeStep::ArmOep(2)
        );
        assert_eq!(
            timeout_materialize_step(true, Some(2), 30, 30),
            MaterializeStep::FreezeAndDump
        );
    }

    #[test]
    fn av_deadlock_triggers_at_threshold_not_before() {
        assert!(!av_deadlock_triggered(255));
        assert!(av_deadlock_triggered(256));
        assert!(av_deadlock_triggered(257));
        assert!(!av_deadlock_triggered(0));
    }

    #[test]
    fn av_log_full_telemetry_then_throttle() {
        // Full telemetry window (first 16 occurrences).
        assert!(should_log_materialize_av(1));
        assert!(should_log_materialize_av(16));
        // Below the throttle interval after the window: suppressed.
        assert!(!should_log_materialize_av(17));
        assert!(!should_log_materialize_av(99_999));
        // At the interval and its multiples: logged.
        assert!(should_log_materialize_av(100_000));
        assert!(should_log_materialize_av(200_000));
        // Just after an interval multiple: suppressed again.
        assert!(!should_log_materialize_av(100_001));
    }
}
