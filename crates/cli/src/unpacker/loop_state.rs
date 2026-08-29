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
    /// Second region sample (offset +0x1000) for the dual-region stability
    /// check (XX-11-B / #17): Themida keeps the .text head as a fixed shell
    /// stub, so the head alone can never prove decryption of the real code.
    pub(super) text_prev_sample2: [u8; 16],
    /// .text poll: true when .text content is stable (two consecutive reads match)
    pub(super) text_stable: bool,
    /// XX-4 (B'): waiting for WinLicense lazy-IAT materialization at an FF15
    /// site (software breakpoint armed, process continued).
    pub(super) iat_materialize_wait: bool,
    /// XX-4 (B'): the site VA currently armed (cleared on hit / timeout).
    pub(super) iat_materialize_site: Option<usize>,
    /// XX-4 (B'): fallback stage already tried (true once OEP fallback runs).
    pub(super) iat_materialize_fallback: bool,
    /// XX-4 (B'): when the current materialize wait started (30s budget).
    pub(super) iat_materialize_start: Option<std::time::Instant>,
    /// XX-5: the exception address of the last unrelated AV seen during the
    /// materialization wait (for identical-AV streak detection).
    pub(super) iat_materialize_last_av_exc: Option<u64>,
    /// XX-5: the target address of the last unrelated AV seen during the
    /// materialization wait (pair key with `iat_materialize_last_av_exc`).
    pub(super) iat_materialize_last_av_target: Option<u64>,
    /// XX-6: the access type (ExceptionInformation[0]) of the last AV seen
    /// during the materialization wait (deadlock key component).
    pub(super) iat_materialize_last_av_exc_type: Option<u8>,
    /// XX-6: consecutive count of the identical `(exc_type, exc, target)` AV
    /// tuple seen during the materialization wait. Reset when the tuple
    /// changes (which indicates the VM is progressing).
    pub(super) iat_materialize_av_streak: u32,
    /// XX-6 (L'): when the faulting-thread RIP at the last telemetry-sampled
    /// AV (to distinguish "same exception, moving RIP" from a true deadlock).
    pub(super) iat_materialize_last_av_rip: Option<u64>,
    /// XX-6 (L'): an anchor address has been computed but the HW breakpoint is
    /// not yet armed. Arming is deferred to the next natural debug-event stop
    /// (thread already suspended by the event) instead of a self-owned
    /// Suspend/Resume, which breaks WinLicense's exception-driven VM timing.
    pub(super) iat_materialize_arm_pending: bool,
    /// T0.5-R2 (redump fix): when the deferred HW anchor fails to arm, the
    /// original fail-closed path froze immediately and dumped a
    /// half-initialized shell (.bss singleton lock non-zero -> the re-packed
    /// host wedged on the EP lock and never loaded core.dll). Instead the
    /// loop stays alive for this grace window so the shell finishes DLL
    /// loading / init (matching the xx11 flow that waited on IAT
    /// materialization), then the plugin's natural leave dumps.
    pub(super) iat_materialize_failclosed_delay: Option<std::time::Instant>,
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
