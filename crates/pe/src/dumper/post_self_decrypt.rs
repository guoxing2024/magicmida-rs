//! PostSelfDecrypt observation window (WO-401, GTO-H5-LIVE-2 Round 2).
//!
//! Implements WO-302 design + amendments A1 (.pdata sampling) and A2
//! (entropy timeline is the primary deliverable; candidate output is
//! secondary; C3 timeout + flat high entropy => explicit "lazy decrypt
//! hypothesis holds" conclusion).
//!
//! Zero-write constraint: only `read_memory` / `wait_event_timeout` /
//! `continue_event` / `get_thread_context` (core debugger primitives).
//! No process-memory writes, no injection, no DRx, no VEH.

use std::time::{Duration, Instant};

use mida_core::{ContinueStatus, DebugEvent, DebuggerCore};
use tracing::{info, warn};

use super::section_reference::{shannon_entropy_bits, R2_SAMPLE_BYTES};
use crate::PeError;

/// Sampling period between entropy probes (ms).
pub const SAMPLE_PERIOD_MS: u64 = 500;
/// Hard observation-window cap (seconds).
pub const WINDOW_CAP_SECS: u64 = 60;
/// C1 entropy threshold (bits/byte): both sections must stay below.
pub const DECRYPTED_ENTROPY_THRESHOLD: f64 = 6.5;
/// C1 confirmation: consecutive samples below threshold required.
pub const C1_CONSECUTIVE_SAMPLES: usize = 3;
/// C2: RIP must stay inside .text for this long (seconds).
pub const C2_TEXT_RESIDENCY_SECS: u64 = 2;

/// One entropy sample (A2 timeline point).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EntropySample {
    /// Elapsed milliseconds since window start.
    pub t_ms: u64,
    /// Section name sampled.
    pub section: String,
    /// Shannon entropy bits/byte of the 4 KiB sample.
    pub entropy_bits: f64,
}

/// Observation outcome (C1/C2/C3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationOutcome {
    /// C1: both .rdata0 and .rdata2 below threshold for N consecutive samples.
    DecryptCompleted,
    /// C2: RIP stable inside .text for the residency duration.
    TextResidency,
    /// C3: hard cap reached without C1/C2.
    Timeout,
}

/// Full observation result (A2: timeline is the primary deliverable).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PostSelfDecryptObservation {
    /// Outcome of the window.
    pub outcome: String,
    /// Wall-clock duration of the window (ms).
    pub window_ms: u64,
    /// True when C3 timeout AND all sampled entropies stayed > threshold.
    pub lazy_decrypt_hypothesis: bool,
    /// Complete entropy timeline across .rdata0/.rdata2/.pdata (A2).
    pub timeline: Vec<EntropySample>,
    /// Candidate dump refused when outcome == Timeout (A2 fail-closed).
    pub candidate_refused: bool,
    /// Reason when refused.
    pub refusal_reason: Option<String>,
}

/// Sections to sample (A1: .pdata added).
const SAMPLE_SECTIONS: [&str; 3] = [".rdata0", ".rdata2", ".pdata"];

/// Run the PostSelfDecrypt observation window.
///
/// Returns the observation record. The caller decides whether to proceed
/// with the dump based on `outcome` / `candidate_refused`.
pub fn run_post_self_decrypt_window(
    debugger: &mut dyn DebuggerCore,
    image_base: u64,
    sections: &[crate::header::PeSection],
) -> Result<PostSelfDecryptObservation, PeError> {
    // Resolve sample addresses for the three sections of interest.
    let mut targets: Vec<(String, u64)> = Vec::new();
    for name in SAMPLE_SECTIONS.iter() {
        if let Some(sec) = sections.iter().find(|s| s.name == *name) {
            let va = image_base + sec.virtual_address as u64;
            targets.push((name.to_string(), va));
        } else {
            info!(section = %name, "PostSelfDecrypt: section absent, skipped");
        }
    }
    if targets.is_empty() {
        return Err(PeError::Parse(
            "PostSelfDecrypt: none of .rdata0/.rdata2/.pdata present".into(),
        ));
    }

    let start = Instant::now();
    let cap = Duration::from_secs(WINDOW_CAP_SECS);
    let mut timeline: Vec<EntropySample> = Vec::new();
    // Per-section consecutive below-threshold counters for C1.
    let mut below_counts: Vec<usize> = vec![0; targets.len()];
    let mut text_enter_at: Option<Instant> = None;
    let mut outcome = ObservationOutcome::Timeout;
    let mut main_thread: Option<u32> = None;

    info!(
        "PostSelfDecrypt window start: sections={} cap={WINDOW_CAP_SECS}s period={SAMPLE_PERIOD_MS}ms",
        targets.len()
    );

    while start.elapsed() < cap {
        let elapsed_ms = start.elapsed().as_millis() as u64;

        // Sample each target section (4 KiB at its virtual address).
        for (i, (name, va)) in targets.iter().enumerate() {
            let mut buf = vec![0u8; R2_SAMPLE_BYTES];
            match debugger.read_memory(*va as usize, &mut buf) {
                Ok(n) if n > 0 => {
                    let sample = &buf[..n.min(R2_SAMPLE_BYTES)];
                    if let Some(h) = shannon_entropy_bits(sample) {
                        let rounded = (h * 1000.0).round() / 1000.0;
                        timeline.push(EntropySample {
                            t_ms: elapsed_ms,
                            section: name.clone(),
                            entropy_bits: rounded,
                        });
                        below_counts[i] = if rounded < DECRYPTED_ENTROPY_THRESHOLD {
                            below_counts[i] + 1
                        } else {
                            0
                        };
                        // C1 evaluated via evaluate_c1_criterion over the timeline below.
                    }
                }
                Ok(_) => {
                    // Zero-byte read: page not mapped yet (lazy commit). Keep counting.
                    below_counts[i] = 0;
                }
                Err(e) => {
                    warn!(
                        section = %name,
                        error = %e,
                        "PostSelfDecrypt sample read failed"
                    );
                    below_counts[i] = 0;
                }
            }
        }

        // C1: evaluate via the pure criterion over the accumulated timeline
        // (both .rdata0 and .rdata2 below threshold for N consecutive samples).
        let tl_entries: Vec<(String, f64)> = timeline
            .iter()
            .map(|s| (s.section.clone(), s.entropy_bits))
            .collect();
        if evaluate_c1_criterion(&tl_entries) {
            outcome = ObservationOutcome::DecryptCompleted;
            info!("PostSelfDecrypt C1 triggered: both .rdata0/.rdata2 below {DECRYPTED_ENTROPY_THRESHOLD}");
            break;
        }

        // C2: RIP stable inside .text for residency duration.
        if let Some(tid) = main_thread.or_else(|| first_thread_id(debugger)) {
            main_thread = Some(tid);
            if let Ok(ctx) = debugger.get_thread_context(tid) {
                let rip = ctx.Rip;
                let text_va = image_base + 0x1000; // .text RVA is 0x1000 on GTO
                let in_text = rip >= text_va && rip < text_va + 0x12BECB;
                if in_text {
                    let t = text_enter_at.get_or_insert_with(Instant::now);
                    if t.elapsed() >= Duration::from_secs(C2_TEXT_RESIDENCY_SECS) {
                        outcome = ObservationOutcome::TextResidency;
                        info!("PostSelfDecrypt C2 triggered: RIP stable in .text for {C2_TEXT_RESIDENCY_SECS}s");
                        break;
                    }
                } else {
                    text_enter_at = None;
                }
            }
        }

        // Drain pending debug events (keep target progressing; never write).
        if main_thread.is_none() {
            main_thread = drain_events(debugger, 4);
        } else {
            drain_events(debugger, 1);
        }

        // Sleep until next sample.
        std::thread::sleep(Duration::from_millis(SAMPLE_PERIOD_MS));
    }

    let window_ms = start.elapsed().as_millis() as u64;
    let outcome_str = match outcome {
        ObservationOutcome::DecryptCompleted => "decrypt_completed",
        ObservationOutcome::TextResidency => "text_residency",
        ObservationOutcome::Timeout => "timeout",
    }
    .to_string();

    // A2: lazy-decrypt hypothesis when timeout AND all samples stayed high.
    let tl_entries: Vec<(String, f64)> = timeline
        .iter()
        .map(|s| (s.section.clone(), s.entropy_bits))
        .collect();
    let lazy = evaluate_lazy_hypothesis(outcome, &tl_entries);
    if lazy {
        info!("PostSelfDecrypt C3: lazy-decrypt hypothesis holds (flat high entropy, no global decrypt)");
    }

    let candidate_refused = outcome == ObservationOutcome::Timeout;
    let refusal_reason = if candidate_refused {
        Some(
            "C3 timeout: no C1/C2 observed; refusing to emit candidate (A2 fail-closed)"
                .to_string(),
        )
    } else {
        None
    };

    info!(
        outcome = %outcome_str,
        window_ms,
        timeline_points = timeline.len(),
        "PostSelfDecrypt window end"
    );

    Ok(PostSelfDecryptObservation {
        outcome: outcome_str,
        window_ms,
        lazy_decrypt_hypothesis: lazy,
        timeline,
        candidate_refused,
        refusal_reason,
    })
}

/// Drain pending debug events without acting on them (target keeps running).
fn drain_events(debugger: &mut dyn DebuggerCore, max: u32) -> Option<u32> {
    let mut observed: Option<u32> = None;
    for _ in 0..max {
        match debugger.wait_event_timeout(0) {
            Ok(event) => {
                let tid = debugger.pending_event_thread_id();
                if tid.is_some() {
                    observed = tid;
                }
                if let DebugEvent::ExitProcess { .. } = event {
                    info!("PostSelfDecrypt: target exited during window");
                    return observed;
                }
                if let Some(t) = tid {
                    let _ = debugger.continue_event(t, ContinueStatus::Continue);
                }
            }
            Err(_) => break, // timeout / no event
        }
    }
    observed
}

/// Best-effort first thread id (main thread by convention).
fn first_thread_id(debugger: &dyn DebuggerCore) -> Option<u32> {
    // DebuggerCore does not enumerate threads; callers pass main thread id
    // via the observation context when available. Fallback: None.
    let _ = debugger;
    None
}
/// Pure C1 criterion evaluation (offline-testable).
///
/// Returns true when the trailing `C1_CONSECUTIVE_SAMPLES` entropy values for
/// BOTH primary sections (.rdata0, .rdata2) are below `DECRYPTED_ENTROPY_THRESHOLD`.
/// Entries are (section_name, entropy_bits) pairs in chronological order.
pub fn evaluate_c1_criterion(timeline: &[(String, f64)]) -> bool {
    let rdata0: Vec<f64> = timeline
        .iter()
        .filter(|(name, _)| name == ".rdata0")
        .map(|(_, e)| *e)
        .collect();
    let rdata2: Vec<f64> = timeline
        .iter()
        .filter(|(name, _)| name == ".rdata2")
        .map(|(_, e)| *e)
        .collect();
    if rdata0.len() < C1_CONSECUTIVE_SAMPLES || rdata2.len() < C1_CONSECUTIVE_SAMPLES {
        return false;
    }
    let tail_ok = |v: &[f64]| {
        v[v.len() - C1_CONSECUTIVE_SAMPLES..]
            .iter()
            .all(|e| *e < DECRYPTED_ENTROPY_THRESHOLD)
    };
    tail_ok(&rdata0) && tail_ok(&rdata2)
}

/// Pure lazy-decrypt hypothesis evaluation (A2, offline-testable).
///
/// True when the window timed out AND every sampled entropy stayed above
/// `DECRYPTED_ENTROPY_THRESHOLD` (flat high entropy => lazy/per-page decrypt).
pub fn evaluate_lazy_hypothesis(outcome: ObservationOutcome, timeline: &[(String, f64)]) -> bool {
    outcome == ObservationOutcome::Timeout
        && !timeline.is_empty()
        && timeline
            .iter()
            .all(|(_, e)| *e > DECRYPTED_ENTROPY_THRESHOLD)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t1_c1_triggers_on_decrypt_transition() {
        let mut tl: Vec<(String, f64)> = Vec::new();
        for _ in 0..4 {
            tl.push((".rdata0".into(), 7.9));
            tl.push((".rdata2".into(), 7.8));
        }
        for _ in 0..4 {
            tl.push((".rdata0".into(), 5.1));
            tl.push((".rdata2".into(), 5.3));
        }
        assert!(
            evaluate_c1_criterion(&tl),
            "C1 should trigger after decrypt"
        );
    }

    #[test]
    fn t2_no_decrypt_never_triggers_c1() {
        let tl: Vec<(String, f64)> = vec![
            (".rdata0".into(), 7.9),
            (".rdata2".into(), 7.8),
            (".rdata0".into(), 7.8),
            (".rdata2".into(), 7.9),
            (".rdata0".into(), 7.9),
            (".rdata2".into(), 7.8),
            (".rdata0".into(), 7.8),
            (".rdata2".into(), 7.9),
        ];
        assert!(!evaluate_c1_criterion(&tl), "no C1 on flat high entropy");
        assert!(
            evaluate_lazy_hypothesis(ObservationOutcome::Timeout, &tl),
            "lazy hypothesis holds"
        );
    }

    #[test]
    fn t3_boundary_jitter_no_false_trigger() {
        let tl: Vec<(String, f64)> = vec![
            (".rdata0".into(), 6.4),
            (".rdata2".into(), 6.6),
            (".rdata0".into(), 6.6),
            (".rdata2".into(), 6.4),
            (".rdata0".into(), 6.4),
            (".rdata2".into(), 6.6),
            (".rdata0".into(), 6.6),
            (".rdata2".into(), 6.4),
        ];
        assert!(
            !evaluate_c1_criterion(&tl),
            "alternating 6.4/6.6 must not trigger C1"
        );
    }

    #[test]
    fn t4_insufficient_samples_no_trigger() {
        let tl: Vec<(String, f64)> = vec![(".rdata0".into(), 5.0), (".rdata2".into(), 5.1)];
        assert!(
            !evaluate_c1_criterion(&tl),
            "fewer than 3 samples per section: no C1"
        );
    }

    #[test]
    fn t5_zero_write_static_audit() {
        let src = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/dumper/post_self_decrypt.rs"
        ));
        // Audit only the non-test portion: strip the #[cfg(test)] module,
        // which necessarily mentions the forbidden names in its own asserts.
        let test_marker = "#[cfg(test)]";
        let prod_src = src.split(test_marker).next().unwrap_or(src);
        assert!(
            !prod_src.contains("write_memory"),
            "post_self_decrypt must never call write_memory"
        );
        assert!(
            !prod_src.contains("WriteProcessMemory"),
            "no WriteProcessMemory"
        );
        assert!(!prod_src.contains("VirtualAllocEx"), "no VirtualAllocEx");
    }

    #[test]
    fn t6_entropy_api_deterministic() {
        let a = shannon_entropy_bits(&[0x11u8; 4096]).unwrap();
        let b = shannon_entropy_bits(&[0x11u8; 4096]).unwrap();
        assert_eq!(a, b, "entropy must be deterministic");
    }
}
