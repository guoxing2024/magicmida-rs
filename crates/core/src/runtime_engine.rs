//! Runtime event engine surface (R2-Slice2 / 2b).
//!
//! The long-term owner of wait/continue is a [`RuntimeEngine`], not packer CLI
//! loops. This module provides:
//! - pure [`ReplayRuntimeEngine`] for offline tests
//! - [`DebuggerCoreEngine`] adapter over any [`DebuggerCore`] (live path ready;
//!   CLI not switched yet)
//!
//! Live unpacker still calls [`DebuggerCore`] directly until a behavior-
//! preserving CLI pump migration.

use crate::addr::RuntimeBase;
use crate::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
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

/// Live-path adapter: [`RuntimeEngine`] over an existing [`DebuggerCore`].
///
/// Tracks pending continue identity (thread id) and stamps sequences. Does not
/// replace backend lifecycle internals; it enforces the engine-level
/// wait→continue pairing that plugins/CLI should use.
///
/// CLI migration is a separate, behavior-preserving change.
pub struct DebuggerCoreEngine<D: DebuggerCore> {
    inner: D,
    next_sequence: u64,
    pending_thread: Option<u32>,
    process_exited: bool,
}

impl<D: DebuggerCore> DebuggerCoreEngine<D> {
    /// Wrap a debugger backend.
    #[must_use]
    pub fn new(inner: D) -> Self {
        Self {
            inner,
            next_sequence: 1,
            pending_thread: None,
            process_exited: false,
        }
    }

    /// Borrow the underlying backend (memory / BP / context).
    #[must_use]
    pub fn backend(&self) -> &D {
        &self.inner
    }

    /// Mutably borrow the underlying backend.
    #[must_use]
    pub fn backend_mut(&mut self) -> &mut D {
        &mut self.inner
    }

    /// Consume the engine and return the backend.
    #[must_use]
    pub fn into_inner(self) -> D {
        self.inner
    }
}

fn thread_id_of(event: &DebugEvent) -> u32 {
    match event {
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

impl<D: DebuggerCore> RuntimeEngine for DebuggerCoreEngine<D> {
    type Error = CoreError;

    fn wait(&mut self, timeout_ms: Option<u32>) -> Result<EngineEvent, Self::Error> {
        if self.pending_thread.is_some() {
            return Err(CoreError::DebugState(
                "DebuggerCoreEngine::wait refused: previous event not continued".into(),
            ));
        }
        let event = match timeout_ms {
            None => self.inner.wait_event()?,
            Some(ms) => self.inner.wait_event_timeout(ms)?,
        };
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.pending_thread = Some(thread_id_of(&event));
        if matches!(event, DebugEvent::ExitProcess { .. }) {
            self.process_exited = true;
        }
        Ok(EngineEvent { sequence, event })
    }

    fn continue_event(&mut self, status: ContinueStatus) -> Result<(), Self::Error> {
        let Some(thread_id) = self.pending_thread.take() else {
            return Err(CoreError::DebugState(
                "DebuggerCoreEngine::continue_event: no pending event".into(),
            ));
        };
        self.inner.continue_event(thread_id, status)
    }

    fn runtime_base(&self) -> Option<RuntimeBase> {
        let base = self.inner.image_base();
        if base == 0 {
            None
        } else {
            Some(RuntimeBase(base))
        }
    }

    fn process_exited(&self) -> bool {
        self.process_exited
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Diagnostics::Debug::CONTEXT;

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

    /// Minimal `DebuggerCore` that only implements wait/continue for engine tests.
    struct ScriptedDebugger {
        events: Vec<DebugEvent>,
        index: usize,
        image_base: u64,
        continues: Vec<(u32, ContinueStatus)>,
    }

    impl ScriptedDebugger {
        fn new(events: Vec<DebugEvent>, image_base: u64) -> Self {
            Self {
                events,
                index: 0,
                image_base,
                continues: Vec::new(),
            }
        }
    }

    impl DebuggerCore for ScriptedDebugger {
        fn process_handle(&self) -> HANDLE {
            HANDLE::default()
        }
        fn pid(&self) -> u32 {
            1
        }
        fn image_base(&self) -> u64 {
            self.image_base
        }
        fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
            if self.index >= self.events.len() {
                return Err(CoreError::DebugState("script exhausted".into()));
            }
            let ev = std::mem::replace(
                &mut self.events[self.index],
                DebugEvent::Other { thread_id: 0 },
            );
            self.index += 1;
            Ok(ev)
        }
        fn continue_event(
            &mut self,
            thread_id: u32,
            status: ContinueStatus,
        ) -> Result<(), CoreError> {
            self.continues.push((thread_id, status));
            Ok(())
        }
        fn read_memory(&self, _address: usize, _buf: &mut [u8]) -> Result<usize, CoreError> {
            Ok(0)
        }
        fn write_memory(&mut self, _address: usize, data: &[u8]) -> Result<usize, CoreError> {
            Ok(data.len())
        }
        fn get_thread_context(&self, _thread_id: u32) -> Result<CONTEXT, CoreError> {
            Err(CoreError::DebugState("not implemented".into()))
        }
        fn set_thread_context(&self, _thread_id: u32, _ctx: &CONTEXT) -> Result<(), CoreError> {
            Ok(())
        }
    }

    #[test]
    fn debugger_core_engine_pairs_wait_continue() {
        let dbg = ScriptedDebugger::new(
            vec![
                create_process(0x140000000),
                DebugEvent::Breakpoint {
                    thread_id: 9,
                    address: 0x140001000,
                },
                DebugEvent::ExitProcess { exit_code: 0 },
            ],
            0x140000000,
        );
        let mut eng = DebuggerCoreEngine::new(dbg);
        assert_eq!(eng.runtime_base(), Some(RuntimeBase(0x140000000)));

        let e1 = eng.wait(None).unwrap();
        assert_eq!(e1.sequence, 1);
        eng.continue_event(ContinueStatus::Continue).unwrap();

        let e2 = eng.wait(None).unwrap();
        assert!(matches!(
            e2.event,
            DebugEvent::Breakpoint { thread_id: 9, .. }
        ));
        eng.continue_event(ContinueStatus::Continue).unwrap();

        let e3 = eng.wait(None).unwrap();
        assert!(matches!(e3.event, DebugEvent::ExitProcess { .. }));
        assert!(eng.process_exited());
        eng.continue_event(ContinueStatus::Continue).unwrap();

        let continues = eng.backend().continues.clone();
        assert_eq!(continues.len(), 3);
        assert_eq!(continues[1].0, 9); // BP thread id forwarded
        assert_eq!(continues[2].0, 0); // ExitProcess uses 0
    }

    #[test]
    fn debugger_core_engine_rejects_wait_while_pending() {
        let dbg = ScriptedDebugger::new(vec![DebugEvent::Other { thread_id: 1 }], 0);
        let mut eng = DebuggerCoreEngine::new(dbg);
        eng.wait(None).unwrap();
        assert!(eng.wait(None).is_err());
    }
}
