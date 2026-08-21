//! Execution-driven decrypt coverage measurement (WO-702, GTO-H5-LIVE-3).
//!
//! Implements WO-701 design + amendments A1-A3:
//! - A-1: unreadable is a THIRD state (below/above/unreadable) per strip.
//! - A-2: F2 completes the scan and records data; it only forbids using
//!   coverage for a DUMP decision, never the observation.
//! - A-3: A-phase adds a .text 4th anchor; 60% is an ECONOMIC gate.
//!
//! Zero-write: only read_memory (core primitive).

use std::time::{Duration, Instant};

use mida_core::DebuggerCore;
use tracing::{info, warn};

use super::section_reference::{shannon_entropy_bits, R2_SAMPLE_BYTES};
use crate::PeError;

/// Strip size for B-phase spatial scans (64 KiB).
pub const STRIP_SIZE: usize = 64 * 1024;
/// Entropy below this marks a strip as decrypted.
pub const DECRYPTED_ENTROPY_THRESHOLD: f64 = 6.5;
/// A-phase sampling period (ms).
pub const A_PHASE_PERIOD_MS: u64 = 500;
/// B-phase scan budget (seconds); exceeding triggers F3.
pub const B_SCAN_BUDGET_SECS: u64 = 5;
/// Unreadable fraction above which F2 forbids dump decisions.
pub const UNREADABLE_F2_THRESHOLD: f64 = 0.20;
/// Economic dump gate: coverage at/above this allows dump+smoke.
pub const DUMP_COVERAGE_GATE: f64 = 0.60;
/// Per-strip entropy state (A-1: three states).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StripState {
    /// Entropy below threshold (decrypted).
    Below,
    /// Entropy at/above threshold (still encrypted).
    Above,
    /// Read failed (unmapped / protection-hidden page). Third state (A-1).
    Unreadable,
}

/// One strip measurement in the B-phase spatial scan.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StripSample {
    /// Strip index within the section.
    pub index: usize,
    /// Section name.
    pub section: String,
    /// Strip RVA.
    pub rva: u32,
    /// Entropy bits/byte (None when unreadable).
    pub entropy_bits: Option<f64>,
    /// State (below/above/unreadable).
    pub state: StripState,
}

/// One B-phase scan snapshot at a trigger point.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BPhaseScan {
    /// Trigger label: t0 | window | +60s | +180s | end.
    pub trigger: String,
    /// Elapsed ms since observation start.
    pub t_ms: u64,
    /// All strip samples (across scanned sections).
    pub strips: Vec<StripSample>,
    /// Per-section coverage (fraction below-threshold).
    pub coverage: std::collections::BTreeMap<String, f64>,
    /// Per-section unreadable fraction.
    pub unreadable_fraction: std::collections::BTreeMap<String, f64>,
}

/// A-phase anchor sample.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnchorSample {
    /// Elapsed ms.
    pub t_ms: u64,
    /// Section name (.rdata0/.rdata2/.pdata/.text).
    pub section: String,
    /// Entropy bits/byte.
    pub entropy_bits: f64,
}

/// Full observation record (persisted regardless of outcome).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CoverageObservation {
    /// A-phase anchor timeline.
    pub anchor_timeline: Vec<AnchorSample>,
    /// B-phase scans at each trigger.
    pub scans: Vec<BPhaseScan>,
    /// Decision outcome: dump | stop | fail_closed.
    pub decision: String,
    /// Final .rdata2 coverage (B-phase last scan).
    pub final_rdata2_coverage: Option<f64>,
    /// True when the dump gate fired (A-3: economic gate, not success).
    pub dump_gate_fired: bool,
    /// Reason when fail-closed / stop.
    pub reason: Option<String>,
}
/// Generate the deterministic strip offset table for a section.
///
/// Returns (rva, sample_len) pairs: strip i at rva + i*STRIP_SIZE, sampling
/// min(4 KiB, remaining) bytes. Deterministic (T2 test).
#[cfg(test)]
pub fn strip_table(section_rva: u32, section_vsize: u32) -> Vec<(u32, usize)> {
    strip_table_with_step(section_rva, section_vsize, STRIP_SIZE as u32)
}

/// strip_table with explicit step (4 KiB for small sections like .pdata).
pub fn strip_table_with_step(section_rva: u32, section_vsize: u32, step: u32) -> Vec<(u32, usize)> {
    let step = step.max(4096);
    let n = section_vsize.div_ceil(step) as usize;
    (0..n)
        .map(|i| {
            let rva = section_rva + (i as u32) * step;
            let remaining = section_vsize as usize - (i as usize) * step as usize;
            let len = remaining.min(R2_SAMPLE_BYTES);
            (rva, len)
        })
        .collect()
}

/// Compute coverage fraction from strip states (T1 test).
///
/// unreadable counts in the DENOMINATOR but not the numerator (WO-701 §2.2).
pub fn coverage_fraction(states: &[StripState]) -> f64 {
    if states.is_empty() {
        return 0.0;
    }
    let below = states.iter().filter(|s| **s == StripState::Below).count();
    below as f64 / states.len() as f64
}

/// Compute unreadable fraction (A-1).
pub fn unreadable_fraction(states: &[StripState]) -> f64 {
    if states.is_empty() {
        return 0.0;
    }
    let unread = states
        .iter()
        .filter(|s| **s == StripState::Unreadable)
        .count();
    unread as f64 / states.len() as f64
}

/// Decision rule (A-2: F2 forbids dump but completes scan; A-3: 60% is an
/// economic gate, not a success predictor).
///
/// Returns (decision, reason). decision in {dump, stop, fail_closed}.
pub fn decide_dump(
    final_rdata2_coverage: f64,
    rdata2_unreadable: f64,
    anchors_below: bool,
) -> (String, Option<String>) {
    if rdata2_unreadable > UNREADABLE_F2_THRESHOLD {
        return (
            "fail_closed".into(),
            Some(format!("F2: unreadable fraction {rdata2_unreadable:.2} > {UNREADABLE_F2_THRESHOLD}; scan completed but dump decision forbidden")),
        );
    }
    if final_rdata2_coverage >= DUMP_COVERAGE_GATE && anchors_below {
        return (
            "dump".into(),
            Some(format!("gate fired: coverage {final_rdata2_coverage:.2} >= {DUMP_COVERAGE_GATE} and anchors below threshold (economic gate, not success predictor)")),
        );
    }
    (
        "stop".into(),
        Some(format!("coverage {final_rdata2_coverage:.2} < {DUMP_COVERAGE_GATE} or anchors not below; data is the deliverable")),
    )
}
/// Run a B-phase strip scan of one section (read-only).
pub fn scan_section(
    debugger: &mut dyn DebuggerCore,
    image_base: u64,
    section_rva: u32,
    section_vsize: u32,
    step: u32,
) -> Vec<StripSample> {
    let table = strip_table_with_step(section_rva, section_vsize, step);
    let name = section_name_for_rva(section_rva);
    let mut out = Vec::with_capacity(table.len());
    for (i, (rva, len)) in table.into_iter().enumerate() {
        let va = image_base + rva as u64;
        let mut buf = vec![0u8; len];
        match debugger.read_memory(va as usize, &mut buf) {
            Ok(n) if n > 0 => {
                let sample = &buf[..n.min(len)];
                let h = shannon_entropy_bits(sample).unwrap_or(0.0);
                out.push(StripSample {
                    index: i,
                    section: name.clone(),
                    rva,
                    entropy_bits: Some(h),
                    state: if h < DECRYPTED_ENTROPY_THRESHOLD {
                        StripState::Below
                    } else {
                        StripState::Above
                    },
                });
            }
            _ => {
                out.push(StripSample {
                    index: i,
                    section: name.clone(),
                    rva,
                    entropy_bits: None,
                    state: StripState::Unreadable,
                });
            }
        }
    }
    out
}

/// Map RVA to section name.
fn section_name_for_rva(rva: u32) -> String {
    match rva {
        0x15a3000 => ".rdata2".to_string(),
        0x191000 => ".rdata0".to_string(),
        0x185000 => ".pdata".to_string(),
        _ => "?".to_string(),
    }
}

/// Full B-phase scan across all sections at a trigger.
pub fn run_b_phase_scan(
    debugger: &mut dyn DebuggerCore,
    image_base: u64,
    trigger: &str,
    t_ms: u64,
    sections: &[(u32, u32)], // (rva, vsize) per section
) -> Result<BPhaseScan, PeError> {
    let start = Instant::now();
    let mut strips = Vec::new();
    let mut coverage = std::collections::BTreeMap::new();
    let mut unreadable = std::collections::BTreeMap::new();
    for (rva, vsize) in sections.iter() {
        let step = if *rva == 0x185000 {
            4096
        } else {
            STRIP_SIZE as u32
        };
        let samples = scan_section(debugger, image_base, *rva, *vsize, step);
        let name = section_name_for_rva(*rva);
        let states: Vec<StripState> = samples.iter().map(|s| s.state).collect();
        coverage.insert(name.clone(), coverage_fraction(&states));
        unreadable.insert(name.clone(), unreadable_fraction(&states));
        strips.extend(samples);
    }
    let elapsed = start.elapsed();
    if elapsed > Duration::from_secs(B_SCAN_BUDGET_SECS) {
        warn!("B-phase scan exceeded budget: {elapsed:?}");
    }
    info!(
        "B-phase scan {trigger} done: {} strips in {:?}",
        strips.len(),
        elapsed
    );
    Ok(BPhaseScan {
        trigger: trigger.to_string(),
        t_ms,
        strips,
        coverage,
        unreadable_fraction: unreadable,
    })
}

/// A-phase anchor sample (single point).
pub fn sample_anchor(
    debugger: &mut dyn DebuggerCore,
    image_base: u64,
    section_rva: u32,
    section_name: &str,
    t_ms: u64,
) -> Option<AnchorSample> {
    let va = image_base + section_rva as u64;
    let mut buf = vec![0u8; R2_SAMPLE_BYTES];
    match debugger.read_memory(va as usize, &mut buf) {
        Ok(n) if n > 0 => {
            let h = shannon_entropy_bits(&buf[..n.min(R2_SAMPLE_BYTES)]).unwrap_or(0.0);
            Some(AnchorSample {
                t_ms,
                section: section_name.to_string(),
                entropy_bits: h,
            })
        }
        _ => None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // T1: coverage pure function with unreadable in denominator.
    #[test]
    fn t1_coverage_fraction_unreadable_in_denominator() {
        // 4 below, 4 above, 2 unreadable of 10
        let states = vec![
            StripState::Below,
            StripState::Below,
            StripState::Below,
            StripState::Below,
            StripState::Above,
            StripState::Above,
            StripState::Above,
            StripState::Above,
            StripState::Unreadable,
            StripState::Unreadable,
        ];
        let cov = coverage_fraction(&states);
        assert!((cov - 0.4).abs() < 1e-9, "4/10 = 0.4, got {cov}");
        assert!((unreadable_fraction(&states) - 0.2).abs() < 1e-9);
    }

    #[test]
    fn t1b_empty_states_zero() {
        assert_eq!(coverage_fraction(&[]), 0.0);
        assert_eq!(unreadable_fraction(&[]), 0.0);
    }

    // T2: strip table determinism and counts.
    #[test]
    fn t2_strip_table_deterministic_counts() {
        // .rdata2: 24,607,744 B → 376 strips
        let t2 = strip_table(0x15a3000, 0x1777b78);
        assert_eq!(t2.len(), 376, ".rdata2 strip count");
        assert_eq!(t2[0], (0x15a3000, 4096));
        assert_eq!(t2[1], (0x15b3000, 4096));
        // .rdata0: 21,026,845 → 321
        let t0 = strip_table(0x191000, 0x140d61d);
        assert_eq!(t0.len(), 321, ".rdata0 strip count");
        // .pdata: 43,524 with 4 KiB step → 11 samples (full coverage)
        let tp = strip_table_with_step(0x185000, 0xaa04, 4096);
        assert_eq!(tp.len(), 11, ".pdata 4K-step count");
        // Determinism
        assert_eq!(strip_table(0x15a3000, 0x1777b78), t2);
    }

    // T3: decision rule three branches.
    #[test]
    fn t3_decision_dump_stop_fail_closed() {
        // dump: coverage >= 0.6 and anchors below
        let (d, r) = decide_dump(0.65, 0.05, true);
        assert_eq!(d, "dump");
        assert!(r.unwrap().contains("economic gate"));
        // stop: coverage < 0.6
        let (d2, _) = decide_dump(0.30, 0.05, true);
        assert_eq!(d2, "stop");
        // stop: anchors not below
        let (d3, _) = decide_dump(0.80, 0.05, false);
        assert_eq!(d3, "stop");
        // fail_closed: unreadable > 0.2 (A-2: completes scan, forbids dump)
        let (d4, r4) = decide_dump(0.80, 0.30, true);
        assert_eq!(d4, "fail_closed");
        assert!(r4.unwrap().contains("F2"));
    }

    // T4: unreadable boundary 0% / 20% / 21%.
    #[test]
    fn t4_unreadable_boundary() {
        // exactly 20% does NOT fail (threshold is strict >)
        let (d, _) = decide_dump(0.7, 0.20, true);
        assert_eq!(d, "dump");
        // 21% fails closed
        let (d2, _) = decide_dump(0.7, 0.21, true);
        assert_eq!(d2, "fail_closed");
        // 0% normal
        let (d3, _) = decide_dump(0.7, 0.0, true);
        assert_eq!(d3, "dump");
    }

    // T5: scan budget static assertion.
    #[test]
    fn t5_scan_budget_static() {
        let total_strips = 376 + 321 + 11;
        // 1ms per strip worst case → well under 5s budget
        let worst_ms = total_strips as u64;
        assert!(worst_ms < B_SCAN_BUDGET_SECS * 1000, "budget headroom");
    }

    // T6: entropy API determinism (R2 reuse).
    #[test]
    fn t6_entropy_api_deterministic() {
        let a = shannon_entropy_bits(&[0x22u8; 4096]).unwrap();
        let b = shannon_entropy_bits(&[0x22u8; 4096]).unwrap();
        assert_eq!(a, b);
        // High-entropy random data above threshold
        let mut state = 0xdeadbeefu64;
        let mut buf = [0u8; 4096];
        for x in buf.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *x = (state & 0xff) as u8;
        }
        let h = shannon_entropy_bits(&buf).unwrap();
        assert!(h > DECRYPTED_ENTROPY_THRESHOLD);
    }
}
/// Sections scanned in B-phase with (rva, vsize) — real values filled by
/// the caller from the parsed PE (design: .rdata2/.rdata0/.pdata).
pub fn default_b_sections() -> Vec<(u32, u32)> {
    vec![
        (0x15a3000, 0x1777b78),
        (0x191000, 0x140d61d),
        (0x185000, 0xaa04),
    ]
}

/// A-phase anchors: (rva, name) — .rdata0/.rdata2/.pdata + .text (A-3).
pub const A_ANCHORS: [(u32, &str); 4] = [
    (0x191000, ".rdata0"),
    (0x15a3000, ".rdata2"),
    (0x185000, ".pdata"),
    (0x1000, ".text"),
];

/// Full dual-phase observation: A-phase continuous anchors + B-phase scans
/// at each trigger. Returns the observation record (persist regardless).
pub fn run_coverage_observation(
    debugger: &mut dyn DebuggerCore,
    image_base: u64,
    b_sections: &[(u32, u32)],
    triggers: &[&str], // [t0, window, +60s, +180s, end]
    max_wait_ms: u64,
) -> Result<CoverageObservation, PeError> {
    let start = Instant::now();
    let mut anchor_timeline: Vec<AnchorSample> = Vec::new();
    let mut scans: Vec<BPhaseScan> = Vec::new();

    // A-phase continuous sampling (every A_PHASE_PERIOD_MS).
    let mut next_a = Instant::now();
    let mut trigger_idx = 0usize;
    let mut _last_scan_ms: u64 = 0;
    let deadline = Instant::now() + Duration::from_millis(max_wait_ms);

    loop {
        let t_ms = start.elapsed().as_millis() as u64;
        // A-phase anchors
        if next_a <= Instant::now() {
            for (rva, name) in A_ANCHORS.iter() {
                if let Some(s) = sample_anchor(debugger, image_base, *rva, name, t_ms) {
                    anchor_timeline.push(s);
                }
            }
            next_a = Instant::now() + Duration::from_millis(A_PHASE_PERIOD_MS);
        }
        // B-phase scan at each trigger (once per trigger)
        if trigger_idx < triggers.len() {
            let due = match triggers[trigger_idx] {
                "t0" => scans.is_empty(),
                "window" => t_ms >= 1000 && scans.len() == 1,
                "+60s" => t_ms >= 60_000 && scans.len() <= 2,
                "+180s" => t_ms >= 180_000 && scans.len() <= 3,
                "end" => t_ms >= max_wait_ms.saturating_sub(1000),
                _ => false,
            };
            if due {
                let scan = run_b_phase_scan(
                    debugger,
                    image_base,
                    triggers[trigger_idx],
                    t_ms,
                    b_sections,
                )?;
                _last_scan_ms = t_ms;
                scans.push(scan);
                trigger_idx += 1;
            }
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Final decision from last scan.
    let last = scans.last();
    let (decision, reason, gate_fired, final_cov) = if let Some(s) = last {
        let cov = s.coverage.get(".rdata2").copied().unwrap_or(0.0);
        let unread = s.unreadable_fraction.get(".rdata2").copied().unwrap_or(0.0);
        let anchors_below = A_ANCHORS.iter().all(|(_rva, name)| {
            if *name == ".text" {
                return true;
            } // text anchor informational
            anchor_timeline
                .iter()
                .rev()
                .find(|a| &a.section == name)
                .map(|a| a.entropy_bits < DECRYPTED_ENTROPY_THRESHOLD)
                .unwrap_or(false)
        });
        let (d, r) = decide_dump(cov, unread, anchors_below);
        (
            d,
            r,
            cov >= DUMP_COVERAGE_GATE && anchors_below && unread <= UNREADABLE_F2_THRESHOLD,
            Some(cov),
        )
    } else {
        (
            "fail_closed".into(),
            Some("no B-phase scan completed".into()),
            false,
            None,
        )
    };

    Ok(CoverageObservation {
        anchor_timeline,
        scans,
        decision,
        final_rdata2_coverage: final_cov,
        dump_gate_fired: gate_fired,
        reason,
    })
}
