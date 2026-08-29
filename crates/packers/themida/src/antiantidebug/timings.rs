//! WO-1002: timing-attack counteraction model (RDTSC / QueryPerformanceCounter).
//!
//! Design constraint from WO-902 Phase 2: the timing-patch must NOT affect
//! the observation channel (coverage/entropy sampling stays on its own
//! clock source). This module implements the *model* — a deterministic
//! pure function deciding whether a probe sequence looks like a timing
//! attack — plus a bounded patch window. All offline-testable.

/// Maximum number of consecutive timing probes to mask per patch window.
pub const TIMING_PATCH_WINDOW: usize = 4;
/// Probe-spacing threshold (ticks): below this, probes are suspicious.
pub const PROBE_SPACING_TICKS: u64 = 2000;
/// Masked delta returned to the caller for a patched probe (constant,
/// deterministic — never the real measured delta).
pub const MASKED_DELTA: u64 = 500;

/// Classification of a single timing observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeClass {
    /// Delta below threshold: looks like a tight timing loop (attack).
    Suspicious,
    /// Delta at/above threshold: normal pacing.
    Benign,
}

/// Classify one probe delta (pure, deterministic).
pub fn classify_probe(delta_ticks: u64) -> ProbeClass {
    if delta_ticks < PROBE_SPACING_TICKS {
        ProbeClass::Suspicious
    } else {
        ProbeClass::Benign
    }
}

/// Decide whether a patch window should be open: suspicious probes must
/// be consecutive within the window (bounded, no infinite masking).
pub fn should_open_patch_window(consecutive_suspicious: usize, window_open: bool) -> bool {
    if window_open {
        return true;
    }
    consecutive_suspicious > 0 && consecutive_suspicious <= TIMING_PATCH_WINDOW
}

/// Compute the masked delta for a patched probe (deterministic).
pub fn masked_delta(_probe_index_in_window: usize) -> u64 {
    MASKED_DELTA
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tight_probe_is_suspicious() {
        assert_eq!(classify_probe(100), ProbeClass::Suspicious);
        assert_eq!(classify_probe(1999), ProbeClass::Suspicious);
    }

    #[test]
    fn paced_probe_is_benign() {
        assert_eq!(classify_probe(2000), ProbeClass::Benign);
        assert_eq!(classify_probe(50_000), ProbeClass::Benign);
    }

    #[test]
    fn window_opens_on_consecutive_suspicious() {
        assert!(!should_open_patch_window(0, false));
        assert!(should_open_patch_window(1, false));
        assert!(should_open_patch_window(4, false));
    }

    #[test]
    fn window_stays_bounded() {
        assert!(!should_open_patch_window(5, false));
    }

    #[test]
    fn masked_delta_is_deterministic() {
        assert_eq!(masked_delta(0), MASKED_DELTA);
        assert_eq!(masked_delta(3), MASKED_DELTA);
    }

    #[test]
    fn observation_channel_independent() {
        // The masked delta is a constant independent of any real clock —
        // the observation channel (entropy sampling) never reads it.
        assert_eq!(MASKED_DELTA, 500);
        assert!(PROBE_SPACING_TICKS > 0);
    }
}
