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

use crate::error::{TracerError, TraceBreakKind};
use crate::LogMsgType;

/// Maximum instruction count when no explicit limit is given (`limit == 0`).
///
/// Prevents infinite loops in pathological cases.  The Pascal reference
/// hard-codes 500 000 — we use the same default here.
const DEFAULT_TRACE_LIMIT: u64 = 500_000;

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
        self.limit = if limit == 0 { DEFAULT_TRACE_LIMIT } else { limit };
        self.limit_reached = false;
        self.start_address = address;

        // ---- point thread to start address and set TF -----------------------

        let mut ctx = debugger
            .get_thread_context(self.thread_id)
            .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;

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
            .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;

        // Resume from the event that brought us here.  The thread will
        // execute one instruction and then fire a SingleStep exception.
        debugger
            .continue_event(self.thread_id, ContinueStatus::Continue)
            .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;

        // ---- trace loop -----------------------------------------------------
        //
        // Take the predicate out of self so we can pass &self to it without
        // the borrow checker complaining about simultaneous mutable +
        // immutable borrows.

        let mut predicate = self
            .predicate
            .take()
            .ok_or(TracerError::Internal(
                "predicate must be Some before trace",
        ))?;

        // The closure wraps the loop so we can use `?` inside it while
        // keeping `predicate` on the stack.  After the closure we restore
        // `predicate` into self.
        let closure_result = (|| {
            loop {
                let ev = debugger
                    .wait_event()
                    .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;

                let event_thread_id = thread_id_of(&ev);

                // ExitProcess is a session-ending event.
                if let DebugEvent::ExitProcess { exit_code } = &ev {
                    return Err(TracerError::ProcessExited { exit_code: *exit_code });
                }

                // ---- events on the traced thread ----------------------------

                if event_thread_id == self.thread_id {
                    match ev {
                        DebugEvent::SingleStep { address, .. } => {
                            self.counter += 1;

                            // Check instruction limit.
                            if self.counter > self.limit {
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

                            // Fetch context so the predicate can inspect
                            // (and optionally modify) registers.
                            let mut ctx = debugger
                                .get_thread_context(self.thread_id)
                                .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;

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

                            // Continue: re-set TF so the next instruction
                            // also single-steps.
                            ctx.EFlags |= 0x100;
                            debugger
                                .set_thread_context(
                                    self.thread_id,
                                    &ctx,
                                )
                                .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;

                            debugger
                                .continue_event(
                                    self.thread_id,
                                    ContinueStatus::Continue,
                                )
                                .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;
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
                            debugger
                                .continue_event(
                                    self.thread_id,
                                    ContinueStatus::Continue,
                                )
                                .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;
                        }
                    }
                } else {
                    // ---- events on other threads ----------------------------

                    (self.log)(
                        LogMsgType::Info,
                        &format!(
                            "Suspending spurious thread {event_thread_id}"
                        ),
                    );
                    debugger
                        .continue_event(
                            event_thread_id,
                            ContinueStatus::Continue,
                        )
                        .map_err(|e| TracerError::Debugger { source: Box::new(std::io::Error::other(e.to_string())), context: "tracer" })?;
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
    fn thread_id_of_exit_process_returns_zero() {
        let ev = DebugEvent::ExitProcess { exit_code: 0 };
        assert_eq!(thread_id_of(&ev), 0);
    }

    #[test]
    fn thread_id_of_breakpoint_returns_thread_id() {
        let ev = DebugEvent::Breakpoint { thread_id: 42, address: 0x1000 };
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
}