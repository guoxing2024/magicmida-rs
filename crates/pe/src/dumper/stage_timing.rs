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

use std::time::Instant;

/// A single stage-timing guard. Emits `enter` on construction and `exit` (or
/// `error`) on Drop, with monotonic elapsed time and (optionally) item/byte counts.
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
    /// Begin a stage. Logs an `enter` event immediately.
    pub fn begin(stage: &str) -> Self {
        let started = Instant::now();
        tracing::info!(
            stage,
            event = "enter",
            monotonic_elapsed_ms = 0i64,
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
    #[must_use]
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
        let monotonic_ms = stage_elapsed_ms; // stage-relative monotonic (this module has no global anchor)
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
        monotonic_elapsed_ms = 0i64,
        stage_elapsed_ms = 0i64,
        item_count = 0usize,
        byte_count = 0u64,
        "gto_stage_enter"
    );
    let result = f(&mut stats);
    let elapsed_ms = started.elapsed().as_millis() as i64;
    match &result {
        Ok(_) => tracing::info!(
            stage,
            event = "exit",
            monotonic_elapsed_ms = elapsed_ms,
            stage_elapsed_ms = elapsed_ms,
            item_count = stats.item_count,
            byte_count = stats.byte_count,
            "gto_stage_exit"
        ),
        Err(msg) => tracing::warn!(
            stage,
            event = "error",
            monotonic_elapsed_ms = elapsed_ms,
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

    /// Minimal subscriber that collects the `message` of each traced event into
    /// a shared Vec (for Route V R0 V0-E ordering tests).
    struct CaptureSubscriber {
        events: Arc<Mutex<Vec<String>>>,
    }

    struct MessageVisitor<'a> {
        msg: &'a mut Option<String>,
    }

    impl<'a> Visit for MessageVisitor<'a> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                *self.msg = Some(value.to_string());
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                *self.msg = Some(format!("{value:?}"));
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
            let mut msg = None;
            let mut visitor = MessageVisitor { msg: &mut msg };
            event.record(&mut visitor);
            if let Some(m) = msg {
                self.events.lock().unwrap().push(m);
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    fn run_capture(f: impl FnOnce()) -> Vec<String> {
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let subscriber = CaptureSubscriber { events: events.clone() };
        // with_default takes the subscriber by value and scopes it to `f`; no
        // borrow of the local `events` outlives the closure.
        tracing::subscriber::with_default(subscriber, f);
        let result = events.lock().unwrap().clone();
        result
    }

    /// V0-E: a successful stage emits exactly `enter` then `exit` (in order).
    #[test]
    fn route_v_r0_stage_enter_exit_order() {
        let seq = run_capture(|| {
            let _g = StageGuard::begin("test_stage");
        });
        assert_eq!(
            seq,
            vec!["gto_stage_enter", "gto_stage_exit"],
            "expected enter then exit, got {seq:?}"
        );
    }

    /// V0-E: `run_stage` on success emits enter then exit; on error emits enter
    /// then error (never a false exit).
    #[test]
    fn run_stage_success_and_error_order() {
        let ok_seq = run_capture(|| {
            let r: Result<i32, String> =
                run_stage("ok_stage", StageStats::default(), |_| Ok(42));
            assert_eq!(r, Ok(42));
        });
        assert_eq!(
            ok_seq,
            vec!["gto_stage_enter", "gto_stage_exit"],
            "success order got {ok_seq:?}"
        );

        let err_seq = run_capture(|| {
            let r: Result<i32, String> =
                run_stage("err_stage", StageStats::default(), |_| {
                    Err("boom".to_string())
                });
            assert!(r.is_err());
        });
        assert_eq!(
            err_seq,
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
            seq,
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
        assert_eq!(seq, vec!["gto_stage_enter", "gto_stage_exit"]);
    }
}
