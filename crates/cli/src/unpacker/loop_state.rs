//! Debug-loop mutable tracking state (host).
//!
//! Extracted from `mod.rs` for thin-split / unattended engineering. Fields remain
//! `pub(super)` so `av_handler`, `plugin_host`, and the main loop can share them
//! without changing behavior.

use super::iat_trace::IatTraceState;
use mida_core::OepProvenance;

// LoopState — mutable tracking variables for the debug loop
// ---------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct LoopState {
    pub(super) guard_installed: bool,
    pub(super) close_handle_bp_set: bool,
    pub(super) nt_protect_bp_set: bool,
    // .text poll: true when CREATE_PROCESS received, actively polling .text
    pub(super) text_polling: bool,
    /// .text poll: Instant when polling started (for 30s timeout)
    pub(super) text_poll_start: Option<std::time::Instant>,
    /// .text poll: count of wait_event iterations since guard installed
    pub(super) text_poll_count: u32,
    /// .text poll: previous snapshot for stability check
    pub(super) text_prev_sample: [u8; 16],
    /// .text poll: true when .text content is stable (two consecutive reads match)
    pub(super) text_stable: bool,
    /// .text poll: re-guard done, waiting for AV at OEP
    pub(super) text_reguarded: bool,
    pub(super) oep: Option<usize>,
    /// Full OEP provenance; scan/PE-EP fallbacks remain non-application evidence.
    pub(super) oep_provenance: OepProvenance,
    pub(super) oep_found_via_scanning: bool,
    pub(super) virtualized_oep_retries: u32,
    pub(super) last_possible_oep: Option<usize>,
    /// Consecutive AVs that were not true code-section guard hits (null deref,
    /// heap probes).  Used to escape virtualized-OEP null storms (Lunlun).
    pub(super) unrelated_av_streak: u32,
    /// Debuggee delivered ExitProcess (or is otherwise untraceable). Skip
    /// V3 single-step IAT tracing and dump with whatever IAT memory remains.
    pub(super) process_exited: bool,
    /// Lunlun: null-AV storm after virtualized OEP accepted PossibleOEP and
    /// left the debug loop without Resuming at OEP (that resume ExitProcess).
    /// Process is still alive — post-loop should run V3 IAT trace, not skip.
    pub(super) storm_escape_freeze: bool,
    pub(super) iat_trace: Option<IatTraceState>,
    /// Copied from PackerPlugin session defaults (Slice 3b-3).
    pub(super) text_poll_idle_timeout_secs: u64,
    /// IAT PAGE_NOACCESS monitor window after OEP (seconds).
    pub(super) iat_monitor_timeout_secs: u64,
    /// Slice 3b-4: AV / text-poll thresholds from PackerPlugin.
    pub(super) virtualized_oep_max_retries: u32,
    pub(super) unrelated_av_storm_threshold: u32,
    pub(super) unrelated_av_null_storm_threshold: u32,
    pub(super) text_poll_min_nonzero: u8,
}
