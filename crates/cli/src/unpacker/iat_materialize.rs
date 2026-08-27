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

/// Decide the initial anchor after `.text` is stable and RIP is not in `.text`.
///
/// * `site` — the first out-of-image indirect call/jmp site (from
///   [`first_out_of_image_iat_site`](mida_packers_themida::first_out_of_image_iat_site)).
/// * `oep` — the scan-resolved OEP (fallback anchor when no site exists).
pub(super) fn initial_materialize_step(
    site: Option<usize>,
    oep: Option<usize>,
) -> MaterializeStep {
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
}
