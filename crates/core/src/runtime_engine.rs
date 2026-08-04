//! Runtime event engine surface (R2-Slice2 / 2b / Slice4).
//!
//! The long-term owner of wait/continue is a [`RuntimeEngine`], not packer CLI
//! loops. This module provides:
//! - pure [`ReplayRuntimeEngine`] for offline tests (+ Slice4 scripted memory)
//! - [`DebuggerCoreEngine`] adapter over any [`DebuggerCore`] (live path ready)
//!
//! Live unpacker uses the engine pump; Win32 bodies remain in `cli/unpacker`.

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

/// Sparse scripted process memory for offline replay (Slice 4).
///
/// Maps absolute VAs to byte vectors. Unmapped reads fail with
/// [`CoreError::MemoryRead`] (no silent zero-fill) so tests must be explicit.
#[derive(Debug, Default, Clone)]
pub struct ReplayMemory {
    /// Regions as `(start_va, bytes)`. Overlaps are allowed; first match wins.
    regions: Vec<(u64, Vec<u8>)>,
}

impl ReplayMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Map `data` starting at absolute `address` (overwrites prior maps at same start).
    pub fn map(&mut self, address: u64, data: impl Into<Vec<u8>>) -> &mut Self {
        let data = data.into();
        if let Some((_, slot)) = self.regions.iter_mut().find(|(a, _)| *a == address) {
            *slot = data;
        } else {
            self.regions.push((address, data));
        }
        self
    }

    /// Number of mapped regions.
    #[must_use]
    pub fn region_count(&self) -> usize {
        self.regions.len()
    }

    /// Read up to `buf.len()` bytes starting at `address` from a single region.
    pub fn read(&self, address: u64, buf: &mut [u8]) -> Result<usize, CoreError> {
        if buf.is_empty() {
            return Ok(0);
        }
        for (start, data) in &self.regions {
            let end = start.saturating_add(data.len() as u64);
            if address >= *start && address < end {
                let off = (address - start) as usize;
                let n = buf.len().min(data.len().saturating_sub(off));
                buf[..n].copy_from_slice(&data[off..off + n]);
                return Ok(n);
            }
        }
        Err(CoreError::MemoryRead {
            address,
            requested: buf.len(),
        })
    }

    /// Write into an existing region, or create a new region for the full buffer.
    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<usize, CoreError> {
        if data.is_empty() {
            return Ok(0);
        }
        for (start, region) in &mut self.regions {
            let end = start.saturating_add(region.len() as u64);
            if address >= *start && address < end {
                let off = (address - *start) as usize;
                let n = data.len().min(region.len().saturating_sub(off));
                if n == 0 {
                    break;
                }
                region[off..off + n].copy_from_slice(&data[..n]);
                return Ok(n);
            }
        }
        // No covering region — map as a new sparse block.
        self.regions.push((address, data.to_vec()));
        Ok(data.len())
    }
}

/// Classic Oreans-style event skeleton (no Win32): create → guard AV → OEP BP → exit.
///
/// Used by Slice 4 tests; addresses are absolute VAs (`base + rva`).
#[must_use]
pub fn guard_oep_event_script(base: u64, oep_rva: u32, main_tid: u32) -> Vec<DebugEvent> {
    let oep_va = base.wrapping_add(u64::from(oep_rva));
    let text_va = base.wrapping_add(0x1000);
    vec![
        DebugEvent::CreateProcess {
            process_id: 1,
            thread_id: main_tid,
            image_base: base,
            h_thread: windows::Win32::Foundation::HANDLE::default(),
            h_process: windows::Win32::Foundation::HANDLE::default(),
            h_file: windows::Win32::Foundation::HANDLE::default(),
        },
        DebugEvent::LoadDll {
            thread_id: main_tid,
            base_address: 0x7ffe_0000,
            h_file: windows::Win32::Foundation::HANDLE::default(),
        },
        DebugEvent::AccessViolation {
            thread_id: main_tid,
            address: text_va,
            is_write: false,
            target_address: text_va,
            exc_type: 8, // execute AV (guard)
        },
        DebugEvent::Breakpoint {
            thread_id: main_tid,
            address: oep_va,
        },
        DebugEvent::ExitProcess { exit_code: 0 },
    ]
}

/// Scripted pure backend: fixed [`DebugEvent`] stream + optional [`ReplayMemory`].
///
/// No Win32. Continue only validates pending state. Exhausted stream:
/// - `timeout_ms = Some(_)` → [`CoreError::Timeout`] (short-wait simulation)
/// - `timeout_ms = None` → [`CoreError::DebugState`] exhausted
#[derive(Debug)]
pub struct ReplayRuntimeEngine {
    events: Vec<DebugEvent>,
    index: usize,
    next_sequence: u64,
    pending: bool,
    runtime_base: Option<RuntimeBase>,
    process_exited: bool,
    memory: ReplayMemory,
}

impl ReplayRuntimeEngine {
    /// Build a replay engine from an ordered event list (empty memory).
    #[must_use]
    pub fn new(events: Vec<DebugEvent>) -> Self {
        Self::with_memory(events, ReplayMemory::new())
    }

    /// Build a replay engine with a pre-seeded memory script.
    #[must_use]
    pub fn with_memory(events: Vec<DebugEvent>, memory: ReplayMemory) -> Self {
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
            memory,
        }
    }

    /// Events remaining to deliver.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.events.len().saturating_sub(self.index)
    }

    /// `true` when a wait delivered an event that has not been continued.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending
    }

    /// Borrow scripted memory.
    #[must_use]
    pub fn memory(&self) -> &ReplayMemory {
        &self.memory
    }

    /// Mutably borrow scripted memory (map more pages mid-replay).
    pub fn memory_mut(&mut self) -> &mut ReplayMemory {
        &mut self.memory
    }

    /// Read process memory from the script (absolute VA as `usize`).
    pub fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        self.memory.read(address as u64, buf)
    }

    /// Write process memory into the script.
    pub fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, CoreError> {
        self.memory.write(address as u64, data)
    }
}

impl RuntimeEngine for ReplayRuntimeEngine {
    type Error = CoreError;

    fn wait(&mut self, timeout_ms: Option<u32>) -> Result<EngineEvent, Self::Error> {
        if self.pending {
            return Err(CoreError::DebugState(
                "ReplayRuntimeEngine::wait refused: previous event not continued".into(),
            ));
        }
        if self.index >= self.events.len() {
            return match timeout_ms {
                Some(_) => Err(CoreError::Timeout),
                None => Err(CoreError::DebugState(
                    "ReplayRuntimeEngine::wait: event stream exhausted".into(),
                )),
            };
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
        // Replay has no fallible continue; clear only after accept.
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

    /// `true` when a wait delivered an event that has not been continued.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.pending_thread.is_some()
    }

    /// Last wait sequence number (0 if none delivered yet).
    #[must_use]
    pub fn last_sequence(&self) -> u64 {
        self.next_sequence.saturating_sub(1)
    }

    /// Continue with an explicit thread id (matches [`DebuggerCore::continue_event`]).
    ///
    /// Backend lifecycle validates `thread_id` against the pending Windows event.
    /// Engine pending is cleared **only** on success so a failed continue leaves
    /// both layers consistent.
    pub fn continue_with_thread(
        &mut self,
        thread_id: u32,
        status: ContinueStatus,
    ) -> Result<(), CoreError> {
        if self.pending_thread.is_none() {
            return Err(CoreError::DebugState(
                "DebuggerCoreEngine::continue_with_thread: no pending event".into(),
            ));
        }
        self.inner.continue_event(thread_id, status)?;
        self.pending_thread = None;
        Ok(())
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
        let pending_thread = self
            .inner
            .pending_event_thread_id()
            .unwrap_or_else(|| thread_id_of(&event));
        self.pending_thread = Some(pending_thread);
        if matches!(event, DebugEvent::ExitProcess { .. }) {
            self.process_exited = true;
        }
        Ok(EngineEvent { sequence, event })
    }

    fn continue_event(&mut self, status: ContinueStatus) -> Result<(), Self::Error> {
        let thread_id = self.pending_thread.ok_or_else(|| {
            CoreError::DebugState("DebuggerCoreEngine::continue_event: no pending event".into())
        })?;
        self.continue_with_thread(thread_id, status)
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
        assert!(matches!(
            e2.event,
            DebugEvent::Breakpoint {
                address: 0x140001000,
                ..
            }
        ));
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
        // Slice2 skeleton retained; Slice4 expands with LoadDll + memory script.
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

    #[test]
    fn slice4_replay_memory_read_write() {
        let mut mem = ReplayMemory::new();
        mem.map(0x14000_1000, vec![0x48, 0x89, 0xe5, 0x90]); // prologue-ish
        let mut buf = [0u8; 4];
        assert_eq!(mem.read(0x14000_1000, &mut buf).unwrap(), 4);
        assert_eq!(buf, [0x48, 0x89, 0xe5, 0x90]);
        // Partial read from offset
        let mut half = [0u8; 2];
        assert_eq!(mem.read(0x14000_1002, &mut half).unwrap(), 2);
        assert_eq!(half, [0xe5, 0x90]);
        // Unmapped fails (no silent zeros)
        assert!(matches!(
            mem.read(0xdead_0000, &mut buf),
            Err(CoreError::MemoryRead {
                address: 0xdead_0000,
                ..
            })
        ));
        // Write into region
        assert_eq!(mem.write(0x14000_1001, &[0x11, 0x22]).unwrap(), 2);
        assert_eq!(mem.read(0x14000_1000, &mut buf).unwrap(), 4);
        assert_eq!(buf, [0x48, 0x11, 0x22, 0x90]);
    }

    #[test]
    fn slice4_wait_timeout_on_exhausted_stream() {
        let mut eng = ReplayRuntimeEngine::new(vec![DebugEvent::Other { thread_id: 1 }]);
        eng.wait(None).unwrap();
        eng.continue_event(ContinueStatus::Continue).unwrap();
        // Blocking wait → exhausted DebugState
        assert!(matches!(eng.wait(None), Err(CoreError::DebugState(_))));
        // Finite wait → Timeout (text-poll short-wait simulation)
        assert!(matches!(eng.wait(Some(100)), Err(CoreError::Timeout)));
    }

    #[test]
    fn slice4_guard_oep_with_memory_and_plugin_milestones() {
        use crate::addr::{PreferredBase, Rva};
        use crate::plugin::{
            HostLoopFacts, NullPackerPlugin, PackerPlugin, PluginAdvice, PluginCtx, UnpackPhase,
        };

        let base = 0x7ff6_c050_0000u64;
        let oep_rva = 0x13e0u32;
        let mut mem = ReplayMemory::new();
        // Seed .text sample at section RVA 0x1000 (guard fault site).
        mem.map(base + 0x1000, vec![0xcc; 16]);
        // Seed OEP bytes (fake x64 prologue).
        mem.map(
            base + u64::from(oep_rva),
            vec![0x48, 0x83, 0xec, 0x28, 0x48, 0x8b, 0x05, 0x00],
        );

        let mut eng =
            ReplayRuntimeEngine::with_memory(guard_oep_event_script(base, oep_rva, 2), mem);
        let mut packer = NullPackerPlugin;
        let mut ctx = PluginCtx {
            preferred_base: Some(PreferredBase(0x14000_0000)),
            section0_is_plain_text: false,
            ..Default::default()
        };

        let mut phases = Vec::new();
        while eng.remaining() > 0 {
            let ev = eng.wait(None).unwrap();
            match &ev.event {
                DebugEvent::CreateProcess { image_base, .. } => {
                    phases.push("create");
                    ctx.ensure_runtime_base(*image_base);
                    ctx.request_close_handle_chain = true;
                    ctx.phase = UnpackPhase::GuardActive;
                }
                DebugEvent::LoadDll { .. } => {
                    phases.push("load_dll");
                    packer.refresh_loop_policy(
                        &mut ctx,
                        &HostLoopFacts {
                            text_polling: false,
                            guard_installed: false,
                            ..Default::default()
                        },
                    );
                    assert!(ctx.allow_close_handle_bp);
                }
                DebugEvent::AccessViolation {
                    address,
                    exc_type: 8,
                    ..
                } => {
                    phases.push("guard_av");
                    let mut sample = [0u8; 4];
                    eng.read_memory(*address as usize, &mut sample).unwrap();
                    assert_eq!(sample, [0xcc, 0xcc, 0xcc, 0xcc]);
                    packer.note_guard_installed(&mut ctx);
                    assert!(ctx.guard_installed);
                }
                DebugEvent::Breakpoint { address, .. } => {
                    phases.push("oep_bp");
                    let mut oep_bytes = [0u8; 4];
                    eng.read_memory(*address as usize, &mut oep_bytes).unwrap();
                    assert_eq!(oep_bytes[0], 0x48);
                    let advice = packer.note_oep_accepted(&mut ctx, *address, false);
                    assert_eq!(advice, PluginAdvice::Transition(UnpackPhase::OepCandidate));
                    assert_eq!(ctx.oep_rva, Some(Rva(oep_rva)));
                    assert_eq!(ctx.oep_va_to_rva(*address), Some(Rva(oep_rva)));
                }
                DebugEvent::ExitProcess { .. } => {
                    phases.push("exit");
                    packer.refresh_loop_policy(
                        &mut ctx,
                        &HostLoopFacts {
                            oep_known: true,
                            process_exited: true,
                            ..Default::default()
                        },
                    );
                    assert!(ctx.skip_v3_iat_trace);
                    assert!(ctx.request_leave_debug_loop);
                }
                _ => phases.push("other"),
            }
            eng.continue_event(ContinueStatus::Continue).unwrap();
        }

        assert_eq!(phases, ["create", "load_dll", "guard_av", "oep_bp", "exit"]);
        assert_eq!(eng.runtime_base(), Some(RuntimeBase(base)));
        assert_eq!(ctx.phase, UnpackPhase::OepCandidate);
        assert!(eng.process_exited());
        assert!(!eng.has_pending());
    }

    /// Minimal `DebuggerCore` that only implements wait/continue for engine tests.
    struct ScriptedDebugger {
        events: Vec<DebugEvent>,
        index: usize,
        image_base: u64,
        continues: Vec<(u32, ContinueStatus)>,
        pending_thread_id: Option<u32>,
    }

    impl ScriptedDebugger {
        fn new(events: Vec<DebugEvent>, image_base: u64) -> Self {
            Self {
                events,
                index: 0,
                image_base,
                continues: Vec::new(),
                pending_thread_id: None,
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
            self.pending_thread_id = Some(match &ev {
                DebugEvent::ExitProcess { .. } => 77,
                _ => thread_id_of(&ev),
            });
            Ok(ev)
        }
        fn pending_event_thread_id(&self) -> Option<u32> {
            self.pending_thread_id
        }
        fn continue_event(
            &mut self,
            thread_id: u32,
            status: ContinueStatus,
        ) -> Result<(), CoreError> {
            self.continues.push((thread_id, status));
            self.pending_thread_id = None;
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
        assert_eq!(continues[2].0, 77); // ExitProcess uses backend pending identity
    }

    #[test]
    fn debugger_core_engine_rejects_wait_while_pending() {
        let dbg = ScriptedDebugger::new(vec![DebugEvent::Other { thread_id: 1 }], 0);
        let mut eng = DebuggerCoreEngine::new(dbg);
        eng.wait(None).unwrap();
        assert!(eng.wait(None).is_err());
    }

    #[test]
    fn continue_failure_retains_engine_pending() {
        struct FailContinue {
            base: ScriptedDebugger,
        }
        impl DebuggerCore for FailContinue {
            fn process_handle(&self) -> HANDLE {
                self.base.process_handle()
            }
            fn pid(&self) -> u32 {
                self.base.pid()
            }
            fn image_base(&self) -> u64 {
                self.base.image_base()
            }
            fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
                self.base.wait_event()
            }
            fn continue_event(
                &mut self,
                _thread_id: u32,
                _status: ContinueStatus,
            ) -> Result<(), CoreError> {
                Err(CoreError::DebugState("inject continue fail".into()))
            }
            fn read_memory(&self, a: usize, b: &mut [u8]) -> Result<usize, CoreError> {
                self.base.read_memory(a, b)
            }
            fn write_memory(&mut self, a: usize, d: &[u8]) -> Result<usize, CoreError> {
                self.base.write_memory(a, d)
            }
            fn get_thread_context(&self, t: u32) -> Result<CONTEXT, CoreError> {
                self.base.get_thread_context(t)
            }
            fn set_thread_context(&self, t: u32, c: &CONTEXT) -> Result<(), CoreError> {
                self.base.set_thread_context(t, c)
            }
        }
        let mut eng = DebuggerCoreEngine::new(FailContinue {
            base: ScriptedDebugger::new(vec![DebugEvent::Other { thread_id: 3 }], 0),
        });
        eng.wait(None).unwrap();
        assert!(eng.has_pending());
        assert!(eng.continue_event(ContinueStatus::Continue).is_err());
        assert!(eng.has_pending(), "failed continue must keep pending");
        assert!(eng.wait(None).is_err());
    }
}
