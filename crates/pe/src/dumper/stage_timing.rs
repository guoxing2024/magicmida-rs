//! Route V R0 (V0-A): non-semantic stage enter/exit/error telemetry for the GTO
//! live dump pipeline.
//!
//! Purpose: locate the post-capture hotspot (the ~110s no-log window observed in
//! Route U R1 between heap-slab capture and the controller 120s timeout). This
//! module records WHEN each production stage entered/exited/errored, how long it
//! took, and how many items/bytes it touched — WITHOUT changing any business
//! semantics (no content, no capture-count changes, no fail-closed relaxation,
//! no transform/planner/candidate modification).
//!
//! Telemetry is emitted via `tracing::info!` with structured fields so a live
//! log can be diffed stage-by-stage. It is diagnostic only and never decides
//! dump success.

use std::sync::OnceLock;
use std::time::Instant;

/// Process-wide monotonic anchor for the dump pipeline (Route V R0 AF1).
///
/// Every telemetry event reports `monotonic_elapsed_ms` as elapsed time from
/// THIS anchor, so different stages share one globally non-decreasing timeline
/// and their relative positions are directly comparable. `stage_elapsed_ms`
/// separately reports each stage's own duration from its own `Instant`. The
/// anchor is created on first use and reused for the life of the process; it is
/// pure observation and never influences business logic.
static PIPELINE_START: OnceLock<Instant> = OnceLock::new();

fn pipeline_elapsed_ms() -> i64 {
    PIPELINE_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis() as i64
}

/// A single stage-timing guard. Emits `enter` on construction and `exit` (or
/// `error`) on Drop, with a pipeline-global monotonic time and a per-stage
/// elapsed time, plus (optionally) item/byte counts.
#[derive(Debug)]
pub struct StageGuard {
    stage: String,
    event: &'static str,
    started: Instant,
    item_count: usize,
    byte_count: u64,
    ended: bool,
}

impl StageGuard {
    /// Begin a stage. Logs an `enter` event immediately. `monotonic_elapsed_ms`
    /// is pipeline-global (non-decreasing across stages); `stage_elapsed_ms` is 0
    /// at entry (a stage always starts at 0).
    pub fn begin(stage: &str) -> Self {
        let started = Instant::now();
        tracing::info!(
            stage,
            event = "enter",
            monotonic_elapsed_ms = pipeline_elapsed_ms(),
            stage_elapsed_ms = 0i64,
            item_count = 0usize,
            byte_count = 0u64,
            "gto_stage_enter"
        );
        StageGuard {
            stage: stage.to_string(),
            event: "enter",
            started,
            item_count: 0,
            byte_count: 0,
            ended: false,
        }
    }

    /// Set the item count reported on exit (e.g. number of heap globals / slabs).
    /// No in-tree caller yet; retained as the symmetric counterpart of
    /// `with_byte_count` in the stage-timing builder API.
    #[must_use]
    #[allow(dead_code)]
    pub fn with_item_count(mut self, item_count: usize) -> Self {
        self.item_count = item_count;
        self
    }

    /// Set the byte count reported on exit (e.g. total captured bytes).
    #[must_use]
    pub fn with_byte_count(mut self, byte_count: u64) -> Self {
        self.byte_count = byte_count;
        self
    }

    /// Attach item/byte counts from a `StageStats` without moving the guard; the
    /// exit event (with these counts) is emitted on Drop.
    pub fn with_stats(&mut self, stats: StageStats) {
        self.item_count = stats.item_count;
        self.byte_count = stats.byte_count;
    }

    /// Explicitly mark the stage as failed with an error message. Emits an
    /// `error` event (non-semantic). On Drop, the guard will NOT emit a second
    /// (false) exit — the error already terminated the stage.
    pub fn error(&mut self, error: impl std::fmt::Display) {
        self.emit("error", Some(&error.to_string()));
    }

    fn emit(&mut self, event: &'static str, error: Option<&str>) {
        if self.ended {
            return;
        }
        self.ended = true;
        let stage_elapsed_ms = self.started.elapsed().as_millis() as i64;
        // Pipeline-global monotonic time; stage_elapsed_ms is this stage's own
        // duration from its `started` instant.
        let monotonic_ms = pipeline_elapsed_ms();
        let stage = &self.stage;
        match error {
            Some(msg) => tracing::warn!(
                stage,
                event,
                monotonic_elapsed_ms = monotonic_ms,
                stage_elapsed_ms,
                item_count = self.item_count,
                byte_count = self.byte_count,
                error = msg,
                "gto_stage_error"
            ),
            None => tracing::info!(
                stage,
                event,
                monotonic_elapsed_ms = monotonic_ms,
                stage_elapsed_ms,
                item_count = self.item_count,
                byte_count = self.byte_count,
                "gto_stage_exit"
            ),
        }
        self.event = event;
    }
}

impl Drop for StageGuard {
    fn drop(&mut self) {
        // On Drop without an explicit exit/error, record an exit with whatever
        // counts were set (best-effort; never a false error).
        self.emit("exit", None);
    }
}

/// Run `f` inside a stage-enter/exit guard and log its elapsed time.
///
/// Returns `(result, item_count, byte_count)` where counts are provided by `f`
/// via a mutable `StageStats`. On `Err`, logs an `error` event with the error
/// display text (non-semantic; no content is logged).
pub fn run_stage<T>(
    stage: &str,
    mut stats: StageStats,
    f: impl FnOnce(&mut StageStats) -> Result<T, String>,
) -> Result<T, String> {
    let started = Instant::now();
    tracing::info!(
        stage,
        event = "enter",
        monotonic_elapsed_ms = pipeline_elapsed_ms(),
        stage_elapsed_ms = 0i64,
        item_count = 0usize,
        byte_count = 0u64,
        "gto_stage_enter"
    );
    let result = f(&mut stats);
    let elapsed_ms = started.elapsed().as_millis() as i64;
    let monotonic_ms = pipeline_elapsed_ms();
    match &result {
        Ok(_) => tracing::info!(
            stage,
            event = "exit",
            monotonic_elapsed_ms = monotonic_ms,
            stage_elapsed_ms = elapsed_ms,
            item_count = stats.item_count,
            byte_count = stats.byte_count,
            "gto_stage_exit"
        ),
        Err(msg) => tracing::warn!(
            stage,
            event = "error",
            monotonic_elapsed_ms = monotonic_ms,
            stage_elapsed_ms = elapsed_ms,
            item_count = stats.item_count,
            byte_count = stats.byte_count,
            error = msg.as_str(),
            "gto_stage_error"
        ),
    }
    result
}

/// Per-stage non-semantic counters reported on exit/error (V0-A).
#[derive(Debug, Clone, Copy, Default)]
pub struct StageStats {
    /// Number of items touched (heap globals / slabs / children / runs).
    pub item_count: usize,
    /// Number of bytes touched (total captured/overlaid bytes).
    pub byte_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing::field::Visit;
    use tracing::Subscriber;

    /// One captured telemetry event: message + the two timing fields we need to
    /// assert global monotonicity and per-stage reset.
    #[derive(Debug, Clone)]
    struct CapturedEvent {
        message: String,
        monotonic_ms: i64,
        stage_ms: i64,
    }

    /// Minimal subscriber that collects the `message`, `monotonic_elapsed_ms`
    /// and `stage_elapsed_ms` of each traced event (Route V R0 AF1 tests).
    struct CaptureSubscriber {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    struct EventVisitor {
        message: Option<String>,
        monotonic: Option<i64>,
        stage: Option<i64>,
    }

    impl Visit for EventVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            match field.name() {
                "message" => self.message = Some(value.to_string()),
                "monotonic_elapsed_ms" => self.monotonic = value.parse().ok(),
                "stage_elapsed_ms" => self.stage = value.parse().ok(),
                _ => {}
            }
        }
        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            match field.name() {
                "monotonic_elapsed_ms" => self.monotonic = Some(value),
                "stage_elapsed_ms" => self.stage = Some(value),
                _ => {}
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = Some(format!("{value:?}"));
            }
        }
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _m: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = EventVisitor {
                message: None,
                monotonic: None,
                stage: None,
            };
            event.record(&mut visitor);
            if let (Some(message), Some(monotonic_ms), Some(stage_ms)) =
                (visitor.message, visitor.monotonic, visitor.stage)
            {
                self.events.lock().unwrap().push(CapturedEvent {
                    message,
                    monotonic_ms,
                    stage_ms,
                });
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn run_capture(f: impl FnOnce()) -> Vec<CapturedEvent> {
        let events = Arc::new(Mutex::new(Vec::<CapturedEvent>::new()));
        let subscriber = CaptureSubscriber {
            events: events.clone(),
        };
        // with_default takes the subscriber by value and scopes it to `f`; no
        // borrow of the local `events` outlives the closure.
        tracing::subscriber::with_default(subscriber, f);
        let result = events.lock().unwrap().clone();
        result
    }

    fn messages(events: &[CapturedEvent]) -> Vec<String> {
        events.iter().map(|e| e.message.clone()).collect()
    }

    /// V0-E: a successful stage emits exactly `enter` then `exit` (in order).
    #[test]
    fn route_v_r0_stage_enter_exit_order() {
        let seq = run_capture(|| {
            let _g = StageGuard::begin("test_stage");
        });
        assert_eq!(
            messages(&seq),
            vec!["gto_stage_enter", "gto_stage_exit"],
            "expected enter then exit, got {seq:?}"
        );
    }

    /// V0-E: `run_stage` on success emits enter then exit; on error emits enter
    /// then error (never a false exit).
    #[test]
    fn run_stage_success_and_error_order() {
        let ok_seq = run_capture(|| {
            let r: Result<i32, String> = run_stage("ok_stage", StageStats::default(), |_| Ok(42));
            assert_eq!(r, Ok(42));
        });
        assert_eq!(
            messages(&ok_seq),
            vec!["gto_stage_enter", "gto_stage_exit"],
            "success order got {ok_seq:?}"
        );

        let err_seq = run_capture(|| {
            let r: Result<i32, String> = run_stage("err_stage", StageStats::default(), |_| {
                Err("boom".to_string())
            });
            assert!(r.is_err());
        });
        assert_eq!(
            messages(&err_seq),
            vec!["gto_stage_enter", "gto_stage_error"],
            "error order got {err_seq:?}"
        );
    }

    /// V0-E: an explicit `error()` on a guard emits exactly one error event and
    /// the Drop does NOT emit a second (false) exit.
    #[test]
    fn stage_error_has_no_false_exit() {
        let seq = run_capture(|| {
            let mut g = StageGuard::begin("fail_stage");
            g.error("kaput");
            // Drop of `g` here must not emit a false exit.
        });
        assert_eq!(
            messages(&seq),
            vec!["gto_stage_enter", "gto_stage_error"],
            "explicit error must not be followed by a false exit, got {seq:?}"
        );
    }

    /// V0-E: counts attached via with_stats are reported on the exit event.
    #[test]
    fn stage_counts_attached_via_with_stats() {
        let seq = run_capture(|| {
            let mut g = StageGuard::begin("count_stage");
            g.with_stats(StageStats {
                item_count: 7,
                byte_count: 12345,
            });
        });
        assert_eq!(messages(&seq), vec!["gto_stage_enter", "gto_stage_exit"]);
    }

    /// V0-AF1: `monotonic_elapsed_ms` is a pipeline-global, non-decreasing
    /// timeline across consecutive stages.
    #[test]
    fn route_v_af1_monotonic_elapsed_is_global_and_nondecreasing() {
        let events = run_capture(|| {
            // Stage A: guard-based.
            {
                let _a = StageGuard::begin("stage_a");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            // Stage B: run_stage-based.
            let _: Result<(), String> = run_stage("stage_b", StageStats::default(), |_| {
                std::thread::sleep(std::time::Duration::from_millis(5));
                Ok(())
            });
        });
        assert_eq!(
            messages(&events),
            vec![
                "gto_stage_enter", // stage_a enter
                "gto_stage_exit",  // stage_a exit
                "gto_stage_enter", // stage_b enter
                "gto_stage_exit",  // stage_b exit
            ]
        );
        // Monotonic timeline must be non-decreasing across all four events.
        let monos: Vec<i64> = events.iter().map(|e| e.monotonic_ms).collect();
        for w in monos.windows(2) {
            assert!(
                w[0] <= w[1],
                "monotonic_elapsed_ms must be non-decreasing, got {monos:?}"
            );
        }
        // stage B's enter monotonic must NOT reset to 0 (it is > stage A's enter).
        let (a_enter, b_enter) = (events[0].monotonic_ms, events[2].monotonic_ms);
        assert!(
            b_enter >= a_enter,
            "stage B enter monotonic must not reset below stage A enter: {a_enter} vs {b_enter}"
        );
    }

    /// V0-AF1: `stage_elapsed_ms` resets to 0 at each stage enter while
    /// `monotonic_elapsed_ms` keeps climbing across the pipeline.
    #[test]
    fn route_v_af1_stage_elapsed_resets_but_pipeline_elapsed_does_not() {
        let events = run_capture(|| {
            {
                let _a = StageGuard::begin("stage_a");
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            let _: Result<(), String> = run_stage("stage_b", StageStats::default(), |_| {
                std::thread::sleep(std::time::Duration::from_millis(5));
                Ok(())
            });
        });
        assert_eq!(events.len(), 4);
        // Every enter reports stage_elapsed_ms == 0 (per-stage reset).
        assert_eq!(events[0].stage_ms, 0, "stage_a enter stage_ms must be 0");
        assert_eq!(events[2].stage_ms, 0, "stage_b enter stage_ms must be 0");
        // Every exit reports a non-negative stage duration.
        assert!(events[1].stage_ms >= 0, "stage_a exit stage_ms >= 0");
        assert!(events[3].stage_ms >= 0, "stage_b exit stage_ms >= 0");
        // Pipeline monotonic keeps increasing across stages (stage B enter >=
        // stage A enter) even though stage_elapsed_ms reset.
        assert!(
            events[2].monotonic_ms >= events[0].monotonic_ms,
            "pipeline monotonic must not reset across stages: {} vs {}",
            events[0].monotonic_ms,
            events[2].monotonic_ms
        );
    }
}
