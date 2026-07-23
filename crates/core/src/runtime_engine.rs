//! Runtime event engine surface (R2-Slice2).
//!
//! The long-term owner of wait/continue is a [`RuntimeEngine`], not packer CLI
//! loops. This module lands the trait + a pure [`ReplayRuntimeEngine`] so
//! offline tests can drive the same contract without Win32.
//!
//! Live unpacker still uses [`crate::DebuggerCore`] directly until a later
//! slice adapts `cli/unpacker` (behavior-preserving).

use crate::addr::RuntimeBase;
use crate::debugger::{ContinueStatus, DebugEvent};
use crate::error::CoreError;

/// Decoded event plus engine sequence (monotonic per engine instance).
#[derive(Debug)]
pub struct EngineEvent {
    /// Monotonic sequence assigned when the event is delivered (1-based).
    pub sequence: u64,
    /// Backend-decoded debug event.
    pub event: DebugEvent,
}

/// Owns the event pump: wait / continue / exit observation.
///
/// Packer plugins and CLI should eventually call this instead of raw
/// `WaitForDebugEvent` / backend wait. Backends remain pluggable.
pub trait RuntimeEngine {
    /// Error type for wait/continue failures.
    type Error;

    /// Block until the next event (or timeout if backend supports it).
    ///
    /// `timeout_ms = None` means block indefinitely when the backend allows.
    fn wait(&mut self, timeout_ms: Option<u32>) -> Result<EngineEvent, Self::Error>;

    /// Resume the pending event exactly once.
    fn continue_event(&mut self, status: ContinueStatus) -> Result<(), Self::Error>;

    /// Runtime (ASLR) image base known to the engine, if any.
    fn runtime_base(&self) -> Option<RuntimeBase>;

    /// `true` after an `ExitProcess` event was delivered.
    fn process_exited(&self) -> bool;
}

/// Scripted pure backend: delivers a fixed list of [`DebugEvent`]s.
///
/// Used for offline engine-contract tests and (later) synthetic guard→OEP
/// skeletons. No Win32. Continue is a no-op that only validates pending state.
#[derive(Debug)]
pub struct ReplayRuntimeEngine {
    events: Vec<DebugEvent>,
    index: usize,
    next_sequence: u64,
    pending: bool,
    runtime_base: Option<RuntimeBase>,
    process_exited: bool,
}

impl ReplayRuntimeEngine {
    /// Build a replay engine from an ordered event list.
    #[must_use]
    pub fn new(events: Vec<DebugEvent>) -> Self {
        let runtime_base = events.iter().find_map(|e| match e {
            DebugEvent::CreateProcess { image_base, .. } => Some(RuntimeBase(*image_base)),
            _ => None,
        });
        Self {
            events,
            index: 0,
            next_sequence: 1,
            pending: false,
            runtime_base,
            process_exited: false,
        }
    }

    /// Events remaining to deliver.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.events.len().saturating_sub(self.index)
    }
}

impl RuntimeEngine for ReplayRuntimeEngine {
    type Error = CoreError;

    fn wait(&mut self, _timeout_ms: Option<u32>) -> Result<EngineEvent, Self::Error> {
        if self.pending {
            return Err(CoreError::DebugState(
                "ReplayRuntimeEngine::wait refused: previous event not continued".into(),
            ));
        }
        if self.index >= self.events.len() {
            return Err(CoreError::DebugState(
                "ReplayRuntimeEngine::wait: event stream exhausted".into(),
            ));
        }
        // Move event out; leave a placeholder Other for Debug-only holes is
        // unnecessary — we own the vec and can swap with a dummy.
        let event = std::mem::replace(
            &mut self.events[self.index],
            DebugEvent::Other { thread_id: 0 },
        );
        self.index += 1;
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.pending = true;
        if matches!(event, DebugEvent::ExitProcess { .. }) {
            self.process_exited = true;
        }
        if let DebugEvent::CreateProcess { image_base, .. } = &event {
            self.runtime_base = Some(RuntimeBase(*image_base));
        }
        Ok(EngineEvent { sequence, event })
    }

    fn continue_event(&mut self, _status: ContinueStatus) -> Result<(), Self::Error> {
        if !self.pending {
            return Err(CoreError::DebugState(
                "ReplayRuntimeEngine::continue_event: no pending event".into(),
            ));
        }
        self.pending = false;
        Ok(())
    }

    fn runtime_base(&self) -> Option<RuntimeBase> {
        self.runtime_base
    }

    fn process_exited(&self) -> bool {
        self.process_exited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::HANDLE;

    fn create_process(image_base: u64) -> DebugEvent {
        DebugEvent::CreateProcess {
            process_id: 1,
            thread_id: 2,
            image_base,
            h_thread: HANDLE::default(),
            h_process: HANDLE::default(),
            h_file: HANDLE::default(),
        }
    }

    #[test]
    fn replay_delivers_in_order_with_sequences() {
        let mut eng = ReplayRuntimeEngine::new(vec![
            create_process(0x140000000),
            DebugEvent::Breakpoint {
                thread_id: 2,
                address: 0x140001000,
            },
            DebugEvent::ExitProcess { exit_code: 0 },
        ]);

        assert!(!eng.process_exited());
        // Pre-scanned from scripted CreateProcess (also refreshed on deliver).
        assert_eq!(eng.runtime_base(), Some(RuntimeBase(0x140000000)));

        let e1 = eng.wait(None).expect("create");
        assert_eq!(e1.sequence, 1);
        assert!(matches!(e1.event, DebugEvent::CreateProcess { .. }));
        assert_eq!(eng.runtime_base(), Some(RuntimeBase(0x140000000)));
        eng.continue_event(ContinueStatus::Continue).unwrap();

        let e2 = eng.wait(None).expect("bp");
        assert_eq!(e2.sequence, 2);
        assert!(matches!(e2.event, DebugEvent::Breakpoint { address: 0x140001000, .. }));
        eng.continue_event(ContinueStatus::Continue).unwrap();

        let e3 = eng.wait(None).expect("exit");
        assert_eq!(e3.sequence, 3);
        assert!(eng.process_exited());
        eng.continue_event(ContinueStatus::Continue).unwrap();

        assert!(eng.wait(None).is_err());
    }

    #[test]
    fn replay_rejects_wait_while_pending() {
        let mut eng = ReplayRuntimeEngine::new(vec![DebugEvent::Other { thread_id: 1 }]);
        eng.wait(None).unwrap();
        let err = eng.wait(None).unwrap_err();
        assert!(format!("{err}").contains("not continued"));
    }

    #[test]
    fn replay_rejects_double_continue() {
        let mut eng = ReplayRuntimeEngine::new(vec![DebugEvent::Other { thread_id: 1 }]);
        eng.wait(None).unwrap();
        eng.continue_event(ContinueStatus::Continue).unwrap();
        assert!(eng.continue_event(ContinueStatus::Continue).is_err());
    }

    #[test]
    fn synthetic_guard_oep_skeleton_events() {
        // Minimal ordered skeleton: create → AV (guard) → BP (OEP-ish) → exit.
        // Not a full unpack; locks the event set for future Slice4 growth.
        let base = 0x7ff6_c050_0000u64;
        let mut eng = ReplayRuntimeEngine::new(vec![
            create_process(base),
            DebugEvent::AccessViolation {
                thread_id: 2,
                address: base + 0x1000,
                is_write: false,
                target_address: base + 0x1000,
                exc_type: 8,
            },
            DebugEvent::Breakpoint {
                thread_id: 2,
                address: base + 0x13e0,
            },
            DebugEvent::ExitProcess { exit_code: 0 },
        ]);

        let mut phases = Vec::new();
        while !eng.process_exited() {
            let ev = eng.wait(None).unwrap();
            match &ev.event {
                DebugEvent::CreateProcess { .. } => phases.push("create"),
                DebugEvent::AccessViolation { exc_type: 8, .. } => phases.push("guard_av"),
                DebugEvent::Breakpoint { .. } => phases.push("oep_bp"),
                DebugEvent::ExitProcess { .. } => phases.push("exit"),
                _ => phases.push("other"),
            }
            eng.continue_event(ContinueStatus::Continue).unwrap();
        }
        assert_eq!(phases, ["create", "guard_av", "oep_bp", "exit"]);
        assert_eq!(eng.runtime_base(), Some(RuntimeBase(base)));
    }
}
