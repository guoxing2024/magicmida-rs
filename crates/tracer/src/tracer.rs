//! Single-step tracer that drives a thread instruction-by-instruction through
//! the packer's obfuscated code, using a caller-supplied predicate to decide
//! when to stop.
//!
//! ## Reference
//!
//! This module is a direct port of `Tracer.pas` (`TTracer` class).

use mida_core::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
use tracing::debug;
use windows::Win32::System::Diagnostics::Debug::CONTEXT;

use crate::error::{TraceBreakKind, TracerError};
use crate::LogMsgType;

/// Maximum instruction count when no explicit limit is given (`limit == 0`).
///
/// Prevents infinite loops in pathological cases.  The Pascal reference
/// hard-codes 500 000 — we use the same default here.
const DEFAULT_TRACE_LIMIT: u64 = 500_000;

/// Resolve the effective instruction limit for a trace.
///
/// `limit == 0` is the explicit "no limit given" sentinel and maps to
/// [`DEFAULT_TRACE_LIMIT`]. Any nonzero `limit` is used verbatim (there is no
/// "zero instructions" limit — a caller that wants to stop immediately passes
/// `limit == 1`). This is kept explicit so `limit == 0` can never be confused
/// with a caller-specified zero-instruction limit.
pub(crate) fn resolve_trace_limit(limit: u64) -> u64 {
    if limit == 0 {
        DEFAULT_TRACE_LIMIT
    } else {
        limit
    }
}

// ---------------------------------------------------------------------------
// TracePredicate type alias
// ---------------------------------------------------------------------------

/// Trace predicate: called after every single-step with a reference to the
/// tracer (for counters / start address) and a mutable reference to the
/// current thread context (so the predicate can modify registers, e.g. to
/// skip anti-trace API calls).
///
/// Return `true` to stop tracing, `false` to continue.
pub type TracePredicate<'a> = dyn FnMut(&Tracer, &mut CONTEXT) -> bool + 'a;

// ---------------------------------------------------------------------------
// TraceResult
// ---------------------------------------------------------------------------

/// Outcome of a completed trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceResult {
    /// Address where the trace started.
    pub start_address: u64,
    /// Address of the last single-stepped instruction (the point where the
    /// predicate returned `true` or the limit was hit).
    pub end_address: u64,
    /// Number of instructions executed during the trace.
    pub instructions_executed: u64,
    /// `true` when the trace was aborted due to hitting the instruction
    /// limit, `false` when it stopped via the predicate.
    pub limit_reached: bool,
}

// ---------------------------------------------------------------------------
// Pending debug-event guard
// ---------------------------------------------------------------------------

/// Best-effort RAII handoff for a raw event delivered by `wait_event`.
///
/// A public `ExitProcess` value has no TID, so the guard records the backend's
/// pending raw identity before any handler can return early.  It deliberately
/// retries only on Drop when the explicit continue path failed; failure is
/// logged and never panics from cleanup.
struct PendingEventGuard<'a> {
    debugger: *mut (dyn DebuggerCore + 'a),
    pending_thread_id: Option<u32>,
}

impl<'a> PendingEventGuard<'a> {
    fn new(debugger: *mut (dyn DebuggerCore + 'a), pending_thread_id: Option<u32>) -> Self {
        Self {
            debugger,
            pending_thread_id,
        }
    }

    fn arm_for_event(&mut self, fallback_thread_id: u32) -> u32 {
        let thread_id =
            unsafe { (&*self.debugger).pending_event_thread_id() }.unwrap_or(fallback_thread_id);
        self.pending_thread_id = Some(thread_id);
        thread_id
    }

    fn continue_event(&mut self, fallback_thread_id: u32) -> Result<(), TracerError> {
        let thread_id = self.pending_thread_id.unwrap_or(fallback_thread_id);
        let result =
            unsafe { (&mut *self.debugger).continue_event(thread_id, ContinueStatus::Continue) };
        match result {
            Ok(()) => {
                self.pending_thread_id = None;
                Ok(())
            }
            Err(error) => Err(TracerError::Debugger {
                source: Box::new(std::io::Error::other(error.to_string())),
                context: "tracer",
            }),
        }
    }
}

impl Drop for PendingEventGuard<'_> {
    fn drop(&mut self) {
        let Some(thread_id) = self.pending_thread_id else {
            return;
        };
        let result =
            unsafe { (&mut *self.debugger).continue_event(thread_id, ContinueStatus::Continue) };
        if let Err(error) = result {
            tracing::warn!(
                thread_id,
                error = %error,
                "tracer dropped with a pending debug event; best-effort continue failed"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Tracer
// ---------------------------------------------------------------------------

/// Single-step tracer — corresponds to `TTracer` in the Pascal reference.
///
/// The tracer **temporarily takes over the debug event loop** for the
/// duration of [`trace`](Self::trace).  It sets the CPU trap flag (TF) on
/// the target thread, then watches for [`DebugEvent::SingleStep`] events.
/// After every single-step the caller's predicate is invoked with the
/// current register state; when the predicate returns `true` the trace
/// stops and leaves the thread suspended at the stop point.
pub struct Tracer<'a> {
    /// ID of the thread being traced.
    thread_id: u32,
    /// Caller-supplied stop condition.
    ///
    /// Stored as `Option` so we can temporarily take ownership during the
    /// trace loop (needed to avoid a borrow-checker conflict when the
    /// predicate receives `&Tracer` as its first argument).
    predicate: Option<Box<TracePredicate<'a>>>,
    /// Instructions executed so far in the current trace.
    counter: u64,
    /// Instruction limit (0 is replaced with [`DEFAULT_TRACE_LIMIT`]).
    limit: u64,
    /// `true` if the limit was hit.
    limit_reached: bool,
    /// Address at which the current trace began.
    start_address: u64,
    /// Log callback (matches `Utils.pas` `TLogProc`).
    log: &'a dyn Fn(LogMsgType, &str),
}

impl<'a> Tracer<'a> {
    /// Create a new single-step tracer.
    ///
    /// # Parameters
    ///
    /// * `thread_id` — the thread to trace (must be registered with the
    ///   debugger).
    /// * `predicate` — called after every single-step; return `true` to stop.
    /// * `log` — log callback matching `Utils.pas` `TLogProc`.
    pub fn new(
        thread_id: u32,
        predicate: Box<TracePredicate<'a>>,
        log: &'a dyn Fn(LogMsgType, &str),
    ) -> Self {
        Self {
            thread_id,
            predicate: Some(predicate),
            counter: 0,
            limit: 0,
            limit_reached: false,
            start_address: 0,
            log,
        }
    }

    /// Run the single-step trace starting at `address`.
    ///
    /// This method **takes over the debug event loop** — it calls
    /// [`DebuggerCore::wait_event`] and [`DebuggerCore::continue_event`]
    /// directly for the duration of the trace.  Events from threads other
    /// than `self.thread_id` are transparently continued.
    ///
    /// When the trace completes (predicate returns `true`, limit is hit, or
    /// an error occurs) the traced thread is left suspended at the last
    /// single-step location so the caller can inspect its context.
    ///
    /// # Instruction limit
    ///
    /// `limit` is "the maximum number of instructions executed": the trace
    /// stops as soon as `limit` single-steps have occurred, and on limit-hit
    /// `TraceResult::instructions_executed == limit`. `limit == 0` is the
    /// explicit "no limit given" sentinel and is replaced with
    /// [`DEFAULT_TRACE_LIMIT`]; it is not the same as a caller-specified limit
    /// of `0` (there is no "zero instructions" limit — a caller that wants to
    /// stop immediately should use `limit == 1`).
    ///
    /// # Errors
    ///
    /// Returns [`TracerError::TraceBreak`] if an unexpected exception fires
    /// on the traced thread, or [`TracerError::Debugger`] for lower-level
    /// Windows / debugger errors.
    pub fn trace(
        &mut self,
        debugger: &mut dyn DebuggerCore,
        address: u64,
        limit: u64,
    ) -> Result<TraceResult, TracerError> {
        // ---- initialise state ------------------------------------------------

        self.counter = 0;
        self.limit = resolve_trace_limit(limit);
        self.limit_reached = false;
        self.start_address = address;

        let initial_pending = debugger.pending_event_thread_id();
        let debugger_ptr: *mut dyn DebuggerCore = debugger;
        let mut pending_guard = PendingEventGuard::new(debugger_ptr, initial_pending);

        // ---- point thread to start address and set TF -----------------------

        let mut ctx =
            debugger
                .get_thread_context(self.thread_id)
                .map_err(|e| TracerError::Debugger {
                    source: Box::new(std::io::Error::other(e.to_string())),
                    context: "tracer",
                })?;

        // Set instruction pointer (architecture-dependent field name).
        #[cfg(target_arch = "x86_64")]
        {
            ctx.Rip = address;
        }
        #[cfg(target_arch = "x86")]
        {
            ctx.Eip = address as u32;
        }

        // Set the trap flag (TF, bit 8 of EFlags).
        ctx.EFlags |= 0x100;

        debugger
            .set_thread_context(self.thread_id, &ctx)
            .map_err(|e| TracerError::Debugger {
                source: Box::new(std::io::Error::other(e.to_string())),
                context: "tracer",
            })?;

        // Resume from the event that brought us here.  The thread will
        // execute one instruction and then fire a SingleStep exception.
        pending_guard.continue_event(self.thread_id)?;

        // ---- trace loop -----------------------------------------------------
        //
        // Take the predicate out of self so we can pass &self to it without
        // the borrow checker complaining about simultaneous mutable +
        // immutable borrows.

        let mut predicate = self
            .predicate
            .take()
            .ok_or(TracerError::Internal("predicate must be Some before trace"))?;

        // The closure wraps the loop so we can use `?` inside it while
        // keeping `predicate` on the stack.  After the closure we restore
        // `predicate` into self.
        let closure_result = (|| {
            loop {
                let ev = debugger.wait_event().map_err(|e| TracerError::Debugger {
                    source: Box::new(std::io::Error::other(e.to_string())),
                    context: "tracer",
                })?;

                let event_thread_id = pending_guard.arm_for_event(thread_id_of(&ev));

                // ExitProcess is a session-ending event.
                if let DebugEvent::ExitProcess { exit_code } = &ev {
                    return Err(TracerError::ProcessExited {
                        exit_code: *exit_code,
                    });
                }

                // ---- events on the traced thread ----------------------------

                if event_thread_id == self.thread_id {
                    match ev {
                        DebugEvent::SingleStep { address, .. } => {
                            self.counter += 1;

                            // Fetch context so the predicate can inspect
                            // (and optionally modify) registers. The predicate
                            // is invoked on EVERY executed instruction —
                            // including the limit-th one — so it always has a
                            // chance to stop or mutate state before the limit
                            // check (P2 issue 6: limit-hit does not skip the
                            // predicate).
                            let mut ctx =
                                debugger.get_thread_context(self.thread_id).map_err(|e| {
                                    TracerError::Debugger {
                                        source: Box::new(std::io::Error::other(e.to_string())),
                                        context: "tracer",
                                    }
                                })?;

                            // Ask the predicate whether to stop.
                            // `predicate` is a local variable, not a self
                            // field, so the borrow checker is happy.
                            if predicate(self, &mut ctx) {
                                return Ok(TraceResult {
                                    start_address: self.start_address,
                                    end_address: address,
                                    instructions_executed: self.counter,
                                    limit_reached: false,
                                });
                            }

                            // Check instruction limit. `>=` (not `>`) gives the
                            // documented semantics "at most `limit` instructions
                            // executed": when `counter` reaches `limit` we have
                            // executed exactly `limit` single-steps (the predicate
                            // already ran on this one) and stop there.
                            // `limit == 1` therefore processes exactly one
                            // single-step, and `instructions_executed` equals
                            // `limit` on limit-hit.
                            if self.counter >= self.limit {
                                self.limit_reached = true;
                                (self.log)(
                                    LogMsgType::Info,
                                    "Giving up trace due to instruction limit",
                                );
                                return Ok(TraceResult {
                                    start_address: self.start_address,
                                    end_address: address,
                                    instructions_executed: self.counter,
                                    limit_reached: true,
                                });
                            }

                            // Continue: re-set TF so the next instruction
                            // also single-steps.
                            ctx.EFlags |= 0x100;
                            debugger
                                .set_thread_context(self.thread_id, &ctx)
                                .map_err(|e| TracerError::Debugger {
                                    source: Box::new(std::io::Error::other(e.to_string())),
                                    context: "tracer",
                                })?;

                            pending_guard.continue_event(self.thread_id)?;
                        }

                        // Unexpected exceptions on the traced thread are
                        // fatal (matches Pascal reference).
                        DebugEvent::Breakpoint { address, .. } => {
                            (self.log)(
                                LogMsgType::Fatal,
                                &format!(
                                    "Unexpected breakpoint at {address:#x} in thread {}",
                                    self.thread_id
                                ),
                            );
                            return Err(TracerError::TraceBreak {
                                address,
                                kind: TraceBreakKind::UnexpectedBreakpoint,
                            });
                        }
                        DebugEvent::AccessViolation {
                            address,
                            target_address,
                            is_write,
                            ..
                        } => {
                            (self.log)(
                                LogMsgType::Fatal,
                                &format!(
                                    "Access violation at {address:#x} (target {target_address:#x}) in thread {}",
                                    self.thread_id
                                ),
                            );
                            return Err(TracerError::TraceBreak {
                                address,
                                kind: TraceBreakKind::AccessViolation {
                                    target_address,
                                    is_write,
                                },
                            });
                        }

                        // Non-exception events on our thread — continue.
                        _ => {
                            debug!(
                                thread_id = self.thread_id,
                                "Tracer continuing non-exception event \
                                 on trace thread"
                            );
                            pending_guard.continue_event(self.thread_id)?;
                        }
                    }
                } else {
                    // ---- events on other threads ----------------------------

                    (self.log)(
                        LogMsgType::Info,
                        &format!("Suspending spurious thread {event_thread_id}"),
                    );
                    pending_guard.continue_event(event_thread_id)?;
                }
            }
        })();

        // Return the predicate to self so it can be reused on the next
        // trace call.
        self.predicate = Some(predicate);

        closure_result
    }

    /// Number of instructions executed so far in the current (or last) trace.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// `true` if the last trace was aborted due to hitting the instruction
    /// limit.
    pub fn limit_reached(&self) -> bool {
        self.limit_reached
    }

    /// Address at which the last trace started.
    pub fn start_address(&self) -> u64 {
        self.start_address
    }

    /// ID of the thread this tracer is attached to.
    pub fn thread_id(&self) -> u32 {
        self.thread_id
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the thread ID from any [`DebugEvent`] variant.
///
/// Every variant except [`DebugEvent::ExitProcess`] carries a thread ID.
/// This function returns the thread ID for those variants, and `0` for
/// `ExitProcess` (which the caller should handle separately).
fn thread_id_of(ev: &DebugEvent) -> u32 {
    match ev {
        DebugEvent::Breakpoint { thread_id, .. }
        | DebugEvent::SingleStep { thread_id, .. }
        | DebugEvent::AccessViolation { thread_id, .. }
        | DebugEvent::CreateThread { thread_id, .. }
        | DebugEvent::ExitThread { thread_id, .. }
        | DebugEvent::LoadDll { thread_id, .. }
        | DebugEvent::UnloadDll { thread_id, .. }
        | DebugEvent::CreateProcess { thread_id, .. }
        | DebugEvent::Other { thread_id } => *thread_id,
        DebugEvent::ExitProcess { .. } => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mida_core::error::CoreError;

    #[test]
    fn tracer_creation() {
        let log_fn = |_: LogMsgType, _: &str| {};
        let predicate = Box::new(|_: &Tracer, _: &mut CONTEXT| false);
        let tracer = Tracer::new(1, predicate, &log_fn);
        assert_eq!(tracer.thread_id(), 1);
        assert_eq!(tracer.counter(), 0);
        assert!(!tracer.limit_reached());
    }

    #[test]
    fn thread_id_of_exit_process_uses_fallback_zero_without_backend_identity() {
        let ev = DebugEvent::ExitProcess { exit_code: 0 };
        assert_eq!(thread_id_of(&ev), 0);
    }

    #[test]
    fn thread_id_of_breakpoint_returns_thread_id() {
        let ev = DebugEvent::Breakpoint {
            thread_id: 42,
            address: 0x1000,
        };
        assert_eq!(thread_id_of(&ev), 42);
    }

    #[test]
    fn thread_id_of_access_violation_returns_thread_id() {
        let ev = DebugEvent::AccessViolation {
            thread_id: 99,
            address: 0x2000,
            is_write: true,
            target_address: 0x3000,
            exc_type: 1,
        };
        assert_eq!(thread_id_of(&ev), 99);
    }

    // -----------------------------------------------------------------------
    // Instruction-limit semantics (P2: off-by-one fix).
    // -----------------------------------------------------------------------

    #[test]
    fn limit_zero_maps_to_default_not_zero() {
        // `limit == 0` is the "no limit given" sentinel → DEFAULT_TRACE_LIMIT;
        // it must never be mistaken for a zero-instruction limit.
        assert_eq!(resolve_trace_limit(0), DEFAULT_TRACE_LIMIT);
        assert_eq!(resolve_trace_limit(1), 1);
        assert_eq!(resolve_trace_limit(2), 2);
        assert_eq!(resolve_trace_limit(10), 10);
    }

    /// A minimal `DebuggerCore` mock that serves a fixed queue of SingleStep
    /// events, then an ExitProcess. Used to exercise the `trace()` loop's
    /// instruction-limit behavior without a real debugger.
    struct StepQueueDebugger {
        steps: std::collections::VecDeque<DebugEvent>,
    }

    impl DebuggerCore for StepQueueDebugger {
        fn process_handle(&self) -> windows::Win32::Foundation::HANDLE {
            windows::Win32::Foundation::HANDLE(std::ptr::null_mut())
        }
        fn pid(&self) -> u32 {
            1
        }
        fn image_base(&self) -> u64 {
            0
        }
        fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
            self.steps
                .pop_front()
                .ok_or_else(|| CoreError::ProcessCreation("no more events".into()))
        }
        fn continue_event(&mut self, _: u32, _: ContinueStatus) -> Result<(), CoreError> {
            Ok(())
        }
        fn read_memory(&self, _: usize, _: &mut [u8]) -> Result<usize, CoreError> {
            Ok(0)
        }
        fn write_memory(&mut self, _: usize, _: &[u8]) -> Result<usize, CoreError> {
            Ok(0)
        }
        fn get_thread_context(&self, _: u32) -> Result<CONTEXT, CoreError> {
            // SAFETY: a zeroed CONTEXT is a valid initial register state for a
            // synthetic trace; the loop only touches EFlags/Rip via the struct.
            Ok(unsafe { std::mem::zeroed() })
        }
        fn set_thread_context(&self, _: u32, _: &CONTEXT) -> Result<(), CoreError> {
            Ok(())
        }
    }

    fn run_trace_with_steps(limit: u64, steps: usize) -> TraceResult {
        let mut dbg = StepQueueDebugger {
            steps: (0..steps)
                .map(|i| DebugEvent::SingleStep {
                    thread_id: 1,
                    address: 0x1000 + i as u64,
                })
                .collect(),
        };
        let log_fn = |_: LogMsgType, _: &str| {};
        // A predicate that never stops: the limit is the only stop condition.
        let predicate = Box::new(|_: &Tracer, _: &mut CONTEXT| false);
        let mut tracer = Tracer::new(1, predicate, &log_fn);
        tracer.trace(&mut dbg, 0x1000, limit).expect("trace")
    }

    /// limit=1: the trace processes EXACTLY one single-step, then stops with
    /// limit_reached and instructions_executed == 1 (no off-by-one).
    #[test]
    fn trace_limit_one_executes_exactly_one_instruction() {
        let result = run_trace_with_steps(1, 3);
        assert!(result.limit_reached);
        assert_eq!(result.instructions_executed, 1);
    }

    /// limit=2: exactly two instructions, then stops.
    #[test]
    fn trace_limit_two_executes_exactly_two_instructions() {
        let result = run_trace_with_steps(2, 3);
        assert!(result.limit_reached);
        assert_eq!(result.instructions_executed, 2);
    }

    /// limit reached: `instructions_executed` equals `limit` exactly.
    #[test]
    fn trace_limit_reached_count_equals_limit() {
        for limit in [1u64, 2, 3, 5, 8] {
            let result = run_trace_with_steps(limit, limit as usize + 2);
            assert!(result.limit_reached, "limit {limit} must be reached");
            assert_eq!(
                result.instructions_executed, limit,
                "instructions_executed must equal limit {limit}"
            );
        }
    }

    /// A predicate that returns `true` on the FIRST step stops before the limit
    /// is hit (limit not reached). This confirms the predicate path is
    /// independent of the limit counter.
    #[test]
    fn trace_stops_on_predicate_before_limit() {
        let mut dbg = StepQueueDebugger {
            steps: vec![DebugEvent::SingleStep {
                thread_id: 1,
                address: 0x1000,
            }]
            .into(),
        };
        let log_fn = |_: LogMsgType, _: &str| {};
        let predicate = Box::new(|_: &Tracer, _: &mut CONTEXT| true);
        let mut tracer = Tracer::new(1, predicate, &log_fn);
        let result = tracer.trace(&mut dbg, 0x1000, 100).expect("trace");
        assert!(!result.limit_reached);
        assert_eq!(result.instructions_executed, 1);
    }

    /// limit=0 uses the default (no practical limit); a predicate stops it, so
    /// the trace does not spin until 500_000.
    #[test]
    fn trace_limit_zero_uses_default_and_predicate_stops() {
        let mut dbg = StepQueueDebugger {
            steps: vec![DebugEvent::SingleStep {
                thread_id: 1,
                address: 0x1000,
            }]
            .into(),
        };
        let log_fn = |_: LogMsgType, _: &str| {};
        let predicate = Box::new(|_: &Tracer, _: &mut CONTEXT| true);
        let mut tracer = Tracer::new(1, predicate, &log_fn);
        let result = tracer.trace(&mut dbg, 0x1000, 0).expect("trace");
        assert!(!result.limit_reached);
        assert_eq!(result.instructions_executed, 1);
    }

    /// P2 issue 6: the predicate is invoked on EVERY executed instruction,
    /// including the limit-th one. A predicate that stops on the limit-th step
    /// must yield a predicate-stop (not a limit-stop), proving limit-hit does
    /// not swallow the predicate's decision.
    #[test]
    fn predicate_runs_on_the_limit_hit_instruction() {
        use std::cell::Cell;
        use std::rc::Rc;
        let mut dbg = StepQueueDebugger {
            steps: (0..2)
                .map(|i| DebugEvent::SingleStep {
                    thread_id: 1,
                    address: 0x1000 + i as u64,
                })
                .collect(),
        };
        let log_fn = |_: LogMsgType, _: &str| {};
        // Stop on the 2nd instruction (which is exactly the limit=2 hit).
        let invocations = Rc::new(Cell::new(0u32));
        let count = Rc::clone(&invocations);
        let predicate = Box::new(move |_: &Tracer, _: &mut CONTEXT| {
            count.set(count.get() + 1);
            count.get() >= 2
        });
        let mut tracer = Tracer::new(1, predicate, &log_fn);
        let result = tracer.trace(&mut dbg, 0x1000, 2).expect("trace");
        // The predicate fired twice (both instructions), and on the limit-th
        // instruction it returned true → predicate-stop, NOT limit-reached.
        assert_eq!(
            invocations.get(),
            2,
            "predicate must run on every step incl. limit"
        );
        assert!(
            !result.limit_reached,
            "predicate stop must win over the limit"
        );
        assert_eq!(result.instructions_executed, 2);
    }
}
