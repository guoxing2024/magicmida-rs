//! Runtime event engine surface (R2-Slice2 / 2b / Slice4, P3-A capability
//! contract).
//!
//! The long-term owner of wait/continue and of every target capability
//! (memory, thread context, hardware breakpoints) is a [`RuntimeEngine`], not
//! packer CLI loops. This module provides:
//! - pure [`ReplayRuntimeEngine`] for offline tests (+ scripted memory,
//!   scripted contexts, breakpoint slots);
//! - [`DebuggerCoreEngine`] adapter over any [`DebuggerCore`] (live path);
//! - a portable capability surface that never exposes Win32 types
//!   ([`ThreadContextSnapshot`], [`HwbpType`], [`ContinueStatus`] only);
//! - a [`CapabilityRecord`] log so every capability operation is auditable
//!   with its engine sequence and thread id, and replay/live parity can be
//!   asserted offline.
//!
//! Contract:
//! - unmapped memory reads fail closed (no silent zero-fill);
//! - a delivered event may be continued exactly once, and only with the
//!   pending thread identity (`continue_thread` rejects mismatches);
//! - capability ops are recorded in execution order with sequence + thread.

use std::collections::BTreeMap;

use crate::addr::RuntimeBase;
use crate::breakpoint::HwbpType;
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

/// Portable x64 thread-context snapshot.
///
/// Deliberately small: only the fields the runtime handlers actually
/// read/write (Rip/Rsp/Rbp/Rax/EFlags). No Win32 `CONTEXT` on the public
/// surface; the live adapter converts to/from the backend's native context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThreadContextSnapshot {
    pub rip: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rax: u64,
    pub eflags: u32,
}

impl ThreadContextSnapshot {
    /// Blank snapshot (used by tests and by handlers before first read).
    #[must_use]
    pub const fn blank() -> Self {
        Self {
            rip: 0,
            rsp: 0,
            rbp: 0,
            rax: 0,
            eflags: 0,
        }
    }
}

/// One recorded capability operation.
///
/// `result` is stored as a string so the log stays `PartialEq`-comparable
/// across replay/live parity assertions without leaking error types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityRecord {
    /// Monotonic capability-op sequence (per engine instance, 1-based).
    pub sequence: u64,
    /// Thread id the operation targeted.
    pub thread_id: u32,
    /// The operation and its outcome.
    pub op: CapabilityOp,
}

/// The operation recorded in a [`CapabilityRecord`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityOp {
    ReadMemory {
        address: u64,
        len: usize,
        result: Result<usize, String>,
    },
    WriteMemory {
        address: u64,
        len: usize,
        result: Result<usize, String>,
    },
    GetThreadContext {
        result: Result<(), String>,
    },
    SetThreadContext {
        result: Result<(), String>,
    },
    SetHardwareBreakpoint {
        slot: u8,
        address: u64,
        kind: HwbpType,
        result: Result<(), String>,
    },
    ClearHardwareBreakpoint {
        slot: u8,
        result: Result<(), String>,
    },
    Continue {
        status: ContinueStatus,
        result: Result<(), String>,
    },
}

/// Owns the event pump and every target capability.
///
/// Packer plugins and CLI call this instead of raw `WaitForDebugEvent` /
/// backend calls. Backends remain pluggable; the capability surface is
/// portable (no Win32 types).
pub trait RuntimeEngine {
    /// Error type for wait/continue/capability failures.
    type Error;

    /// Block until the next event (or timeout if backend supports it).
    ///
    /// `timeout_ms = None` means block indefinitely when the backend allows.
    fn wait(&mut self, timeout_ms: Option<u32>) -> Result<EngineEvent, Self::Error>;

    /// Resume the pending event exactly once, using the engine-resolved
    /// pending thread identity.
    fn continue_event(&mut self, status: ContinueStatus) -> Result<(), Self::Error>;

    /// Runtime (ASLR) image base known to the engine, if any.
    fn runtime_base(&self) -> Option<RuntimeBase>;

    /// `true` after an `ExitProcess` event was delivered.
    fn process_exited(&self) -> bool;

    /// The thread identity that the pending (not yet continued) event
    /// belongs to, if any.
    fn pending_thread_id(&self) -> Option<u32>;

    /// Fail-closed memory read. Unmapped addresses are an error; a short
    /// read is reported by the returned length, never as silent zeros.
    fn read_memory(&mut self, address: u64, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Write target memory. Returns bytes written.
    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<usize, Self::Error>;

    /// Read the portable context snapshot of `thread_id`.
    fn get_thread_context(&mut self, thread_id: u32) -> Result<ThreadContextSnapshot, Self::Error>;

    /// Write back a portable context snapshot (read-modify-write on the
    /// live backend so untouched registers are preserved).
    fn set_thread_context(
        &mut self,
        thread_id: u32,
        context: &ThreadContextSnapshot,
    ) -> Result<(), Self::Error>;

    /// Arm one of the four hardware breakpoint slots (DR0..DR3).
    ///
    /// `slot` must be `0..4` and must not already be armed for this thread.
    fn set_hardware_breakpoint(
        &mut self,
        thread_id: u32,
        slot: u8,
        address: u64,
        kind: HwbpType,
    ) -> Result<(), Self::Error>;

    /// Disarm a hardware breakpoint slot. Clearing an unarmed slot fails
    /// closed.
    fn clear_hardware_breakpoint(&mut self, thread_id: u32, slot: u8) -> Result<(), Self::Error>;

    /// Exactly-once continue with an explicit thread identity.
    ///
    /// `thread_id` must equal the pending event's thread; a mismatch fails
    /// closed and leaves the event pending. Records a [`CapabilityOp::Continue`].
    fn continue_thread(
        &mut self,
        thread_id: u32,
        status: ContinueStatus,
    ) -> Result<(), Self::Error>;

    /// Capability operations executed so far, in execution order.
    fn capability_log(&self) -> &[CapabilityRecord];
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
    pending_thread: Option<u32>,
    runtime_base: Option<RuntimeBase>,
    process_exited: bool,
    memory: ReplayMemory,
    contexts: BTreeMap<u32, ThreadContextSnapshot>,
    breakpoints: BTreeMap<(u32, u8), (u64, HwbpType)>,
    cap_records: Vec<CapabilityRecord>,
    cap_seq: u64,
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
            pending_thread: None,
            runtime_base,
            process_exited: false,
            memory,
            contexts: BTreeMap::new(),
            breakpoints: BTreeMap::new(),
            cap_records: Vec::new(),
            cap_seq: 0,
        }
    }

    /// Seed a scripted thread context (fail-closed reads for unseeded
    /// threads).
    pub fn seed_context(&mut self, thread_id: u32, context: ThreadContextSnapshot) -> &mut Self {
        self.contexts.insert(thread_id, context);
        self
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

    fn record(&mut self, thread_id: u32, op: CapabilityOp) {
        self.cap_seq = self.cap_seq.saturating_add(1);
        self.cap_records.push(CapabilityRecord {
            sequence: self.cap_seq,
            thread_id,
            op,
        });
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
        self.pending_thread = Some(thread_id_of(&event));
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
        self.pending_thread = None;
        Ok(())
    }

    fn runtime_base(&self) -> Option<RuntimeBase> {
        self.runtime_base
    }

    fn process_exited(&self) -> bool {
        self.process_exited
    }

    fn pending_thread_id(&self) -> Option<u32> {
        self.pending_thread
    }

    fn read_memory(&mut self, address: u64, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let thread_id = self.pending_thread.unwrap_or(0);
        let result = self.memory.read(address, buf);
        let record = result.as_ref().copied().map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::ReadMemory {
                address,
                len: buf.len(),
                result: record,
            },
        );
        result
    }

    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<usize, Self::Error> {
        let thread_id = self.pending_thread.unwrap_or(0);
        let result = self.memory.write(address, data);
        let record = result.as_ref().copied().map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::WriteMemory {
                address,
                len: data.len(),
                result: record,
            },
        );
        result
    }

    fn get_thread_context(&mut self, thread_id: u32) -> Result<ThreadContextSnapshot, Self::Error> {
        let result = self.contexts.get(&thread_id).copied().ok_or_else(|| {
            CoreError::DebugState(format!(
                "ReplayRuntimeEngine::get_thread_context: no scripted context for thread {thread_id}"
            ))
        });
        self.record(
            thread_id,
            CapabilityOp::GetThreadContext {
                result: result.as_ref().map(|_| ()).map_err(|e| e.to_string()),
            },
        );
        result
    }

    fn set_thread_context(
        &mut self,
        thread_id: u32,
        context: &ThreadContextSnapshot,
    ) -> Result<(), Self::Error> {
        let result = self.contexts.insert(thread_id, *context).map(|_| ()).ok_or_else(|| {
            CoreError::DebugState(format!(
                "ReplayRuntimeEngine::set_thread_context: no scripted context for thread {thread_id}"
            ))
        });
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(thread_id, CapabilityOp::SetThreadContext { result: record });
        result
    }

    fn set_hardware_breakpoint(
        &mut self,
        thread_id: u32,
        slot: u8,
        address: u64,
        kind: HwbpType,
    ) -> Result<(), Self::Error> {
        let result = set_breakpoint_slot(&mut self.breakpoints, thread_id, slot, address, kind);
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::SetHardwareBreakpoint {
                slot,
                address,
                kind,
                result: record,
            },
        );
        result
    }

    fn clear_hardware_breakpoint(&mut self, thread_id: u32, slot: u8) -> Result<(), Self::Error> {
        let result = clear_breakpoint_slot(&mut self.breakpoints, thread_id, slot);
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::ClearHardwareBreakpoint {
                slot,
                result: record,
            },
        );
        result
    }

    fn continue_thread(
        &mut self,
        thread_id: u32,
        status: ContinueStatus,
    ) -> Result<(), Self::Error> {
        let result = (|| -> Result<(), CoreError> {
            let pending = self.pending_thread.ok_or_else(|| {
                CoreError::DebugState(
                    "ReplayRuntimeEngine::continue_thread: no pending event".into(),
                )
            })?;
            if pending != thread_id {
                return Err(CoreError::DebugState(format!(
                    "ReplayRuntimeEngine::continue_thread: thread id mismatch (pending {pending}, got {thread_id})"
                )));
            }
            self.pending = false;
            self.pending_thread = None;
            Ok(())
        })();
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::Continue {
                status,
                result: record,
            },
        );
        result
    }

    fn capability_log(&self) -> &[CapabilityRecord] {
        &self.cap_records
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
    cap_records: Vec<CapabilityRecord>,
    cap_seq: u64,
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
            cap_records: Vec::new(),
            cap_seq: 0,
        }
    }

    fn record(&mut self, thread_id: u32, op: CapabilityOp) {
        self.cap_seq = self.cap_seq.saturating_add(1);
        self.cap_records.push(CapabilityRecord {
            sequence: self.cap_seq,
            thread_id,
            op,
        });
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

/// Arm one hardware breakpoint slot with fail-closed validation.
fn set_breakpoint_slot(
    breakpoints: &mut BTreeMap<(u32, u8), (u64, HwbpType)>,
    thread_id: u32,
    slot: u8,
    address: u64,
    kind: HwbpType,
) -> Result<(), CoreError> {
    if slot >= 4 {
        return Err(CoreError::DebugState(format!(
            "hardware breakpoint slot {slot} out of range (DR0..DR3)"
        )));
    }
    if address == 0 {
        return Err(CoreError::DebugState(
            "hardware breakpoint address must be non-zero".into(),
        ));
    }
    let key = (thread_id, slot);
    if breakpoints.contains_key(&key) {
        return Err(CoreError::DebugState(format!(
            "hardware breakpoint slot {slot} already armed for thread {thread_id}"
        )));
    }
    breakpoints.insert(key, (address, kind));
    Ok(())
}

/// Disarm one hardware breakpoint slot; clearing an unarmed slot fails.
fn clear_breakpoint_slot(
    breakpoints: &mut BTreeMap<(u32, u8), (u64, HwbpType)>,
    thread_id: u32,
    slot: u8,
) -> Result<(), CoreError> {
    if breakpoints.remove(&(thread_id, slot)).is_none() {
        return Err(CoreError::DebugState(format!(
            "hardware breakpoint slot {slot} not armed for thread {thread_id}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn context_to_snapshot(
    ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
) -> ThreadContextSnapshot {
    ThreadContextSnapshot {
        rip: ctx.Rip,
        rsp: ctx.Rsp,
        rbp: ctx.Rbp,
        rax: ctx.Rax,
        eflags: ctx.EFlags,
    }
}

#[cfg(not(windows))]
fn context_to_snapshot(_ctx: &()) -> ThreadContextSnapshot {
    ThreadContextSnapshot::blank()
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

    fn pending_thread_id(&self) -> Option<u32> {
        self.pending_thread
    }

    fn read_memory(&mut self, address: u64, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let thread_id = self.pending_thread.unwrap_or(0);
        let result = self.inner.read_memory(address as usize, buf);
        let record = result.as_ref().copied().map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::ReadMemory {
                address,
                len: buf.len(),
                result: record,
            },
        );
        result
    }

    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<usize, Self::Error> {
        let thread_id = self.pending_thread.unwrap_or(0);
        let result = self.inner.write_memory(address as usize, data);
        let record = result.as_ref().copied().map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::WriteMemory {
                address,
                len: data.len(),
                result: record,
            },
        );
        result
    }

    fn get_thread_context(&mut self, thread_id: u32) -> Result<ThreadContextSnapshot, Self::Error> {
        let result = self
            .inner
            .get_thread_context(thread_id)
            .map(|ctx| context_to_snapshot(&ctx));
        self.record(
            thread_id,
            CapabilityOp::GetThreadContext {
                result: result.as_ref().map(|_| ()).map_err(|e| e.to_string()),
            },
        );
        result
    }

    fn set_thread_context(
        &mut self,
        thread_id: u32,
        context: &ThreadContextSnapshot,
    ) -> Result<(), Self::Error> {
        // Read-modify-write: pull the live context so untouched registers
        // (including debug registers) are preserved.
        let result = (|| -> Result<(), CoreError> {
            let mut ctx = self.inner.get_thread_context(thread_id)?;
            ctx.Rip = context.rip;
            ctx.Rsp = context.rsp;
            ctx.Rbp = context.rbp;
            ctx.Rax = context.rax;
            ctx.EFlags = context.eflags;
            self.inner.set_thread_context(thread_id, &ctx)
        })();
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(thread_id, CapabilityOp::SetThreadContext { result: record });
        result
    }

    fn set_hardware_breakpoint(
        &mut self,
        thread_id: u32,
        slot: u8,
        address: u64,
        kind: HwbpType,
    ) -> Result<(), Self::Error> {
        let result = (|| -> Result<(), CoreError> {
            // Validate against the engine slot table first (fail-closed),
            // then arm the debug register via a context read-modify-write.
            let mut slots = BTreeMap::new();
            set_breakpoint_slot(&mut slots, thread_id, slot, address, kind)?;
            let mut ctx = self.inner.get_thread_context(thread_id)?;
            match slot {
                0 => ctx.Dr0 = address,
                1 => ctx.Dr1 = address,
                2 => ctx.Dr2 = address,
                _ => ctx.Dr3 = address,
            }
            self.inner.set_thread_context(thread_id, &ctx)
        })();
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::SetHardwareBreakpoint {
                slot,
                address,
                kind,
                result: record,
            },
        );
        result
    }

    fn clear_hardware_breakpoint(&mut self, thread_id: u32, slot: u8) -> Result<(), Self::Error> {
        let result = (|| -> Result<(), CoreError> {
            let mut ctx = self.inner.get_thread_context(thread_id)?;
            match slot {
                0 => ctx.Dr0 = 0,
                1 => ctx.Dr1 = 0,
                2 => ctx.Dr2 = 0,
                _ => ctx.Dr3 = 0,
            }
            self.inner.set_thread_context(thread_id, &ctx)
        })();
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::ClearHardwareBreakpoint {
                slot,
                result: record,
            },
        );
        result
    }

    fn continue_thread(
        &mut self,
        thread_id: u32,
        status: ContinueStatus,
    ) -> Result<(), Self::Error> {
        let result = (|| -> Result<(), CoreError> {
            let pending = self.pending_thread.ok_or_else(|| {
                CoreError::DebugState(
                    "DebuggerCoreEngine::continue_thread: no pending event".into(),
                )
            })?;
            if pending != thread_id {
                return Err(CoreError::DebugState(format!(
                    "DebuggerCoreEngine::continue_thread: thread id mismatch (pending {pending}, got {thread_id})"
                )));
            }
            self.inner.continue_event(thread_id, status)?;
            self.pending_thread = None;
            Ok(())
        })();
        let record = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
        self.record(
            thread_id,
            CapabilityOp::Continue {
                status,
                result: record,
            },
        );
        result
    }

    fn capability_log(&self) -> &[CapabilityRecord] {
        &self.cap_records
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
                    eng.read_memory(*address, &mut sample).unwrap();
                    assert_eq!(sample, [0xcc, 0xcc, 0xcc, 0xcc]);
                    packer.note_guard_installed(&mut ctx);
                    assert!(ctx.guard_installed);
                }
                DebugEvent::Breakpoint { address, .. } => {
                    phases.push("oep_bp");
                    let mut oep_bytes = [0u8; 4];
                    eng.read_memory(*address, &mut oep_bytes).unwrap();
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
        /// Scripted thread contexts; unknown threads fail (like the live path).
        /// `DebuggerCore::set_thread_context` takes `&self`, so the map is
        /// interior-mutable.
        contexts: std::cell::RefCell<BTreeMap<u32, ThreadContextSnapshot>>,
        /// Scripted memory (used for capability read/write parity).
        memory: BTreeMap<u64, Vec<u8>>,
    }

    impl ScriptedDebugger {
        fn new(events: Vec<DebugEvent>, image_base: u64) -> Self {
            Self {
                events,
                index: 0,
                image_base,
                continues: Vec::new(),
                pending_thread_id: None,
                contexts: std::cell::RefCell::new(BTreeMap::new()),
                memory: BTreeMap::new(),
            }
        }

        fn with_contexts(
            events: Vec<DebugEvent>,
            image_base: u64,
            contexts: BTreeMap<u32, ThreadContextSnapshot>,
        ) -> Self {
            let this = Self::new(events, image_base);
            *this.contexts.borrow_mut() = contexts;
            this
        }

        fn map_memory(&mut self, address: u64, data: Vec<u8>) {
            self.memory.insert(address, data);
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
        fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
            let address = address as u64;
            let (region_start, region) = self
                .memory
                .iter()
                .find(|(start, data)| address >= **start && address < **start + data.len() as u64)
                .ok_or_else(|| CoreError::MemoryRead {
                    address,
                    requested: buf.len(),
                })?;
            let offset = (address - region_start) as usize;
            let available = region.len().saturating_sub(offset);
            let n = available.min(buf.len());
            buf[..n].copy_from_slice(&region[offset..offset + n]);
            Ok(n)
        }
        fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, CoreError> {
            let address = address as u64;
            let mut updated = None;
            for (start, region) in &mut self.memory {
                let region_start = *start;
                if address >= region_start && address < region_start + region.len() as u64 {
                    let offset = (address - region_start) as usize;
                    let n = data.len().min(region.len() - offset);
                    region[offset..offset + n].copy_from_slice(&data[..n]);
                    updated = Some(n);
                    break;
                }
            }
            updated.ok_or(CoreError::DebugState(
                "ScriptedDebugger write outside scripted region".into(),
            ))
        }
        fn get_thread_context(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
            // Convert the scripted snapshot into a native CONTEXT so the
            // engine's conversion path is exercised end to end.
            let snap = self
                .contexts
                .borrow()
                .get(&thread_id)
                .copied()
                .ok_or_else(|| {
                    CoreError::DebugState(format!(
                        "ScriptedDebugger: no context for thread {thread_id}"
                    ))
                })?;
            let mut ctx = CONTEXT::default();
            ctx.Rip = snap.rip;
            ctx.Rsp = snap.rsp;
            ctx.Rbp = snap.rbp;
            ctx.Rax = snap.rax;
            ctx.EFlags = snap.eflags;
            Ok(ctx)
        }
        fn set_thread_context(&self, thread_id: u32, ctx: &CONTEXT) -> Result<(), CoreError> {
            let mut contexts = self.contexts.borrow_mut();
            let snap = contexts.get_mut(&thread_id).ok_or_else(|| {
                CoreError::DebugState(format!(
                    "ScriptedDebugger: no context for thread {thread_id}"
                ))
            })?;
            snap.rip = ctx.Rip;
            snap.rsp = ctx.Rsp;
            snap.rbp = ctx.Rbp;
            snap.rax = ctx.Rax;
            snap.eflags = ctx.EFlags;
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

    /// Drive a `RuntimeEngine` to completion and record
    /// `(sequence, event kind, thread id)` tuples.
    fn collect_sequence(
        engine: &mut dyn RuntimeEngine<Error = CoreError>,
    ) -> Vec<(u64, &'static str, u32)> {
        let mut out = Vec::new();
        while !engine.process_exited() {
            let ev = engine.wait(None).unwrap();
            let kind = match &ev.event {
                DebugEvent::CreateProcess { .. } => "create",
                DebugEvent::LoadDll { .. } => "load_dll",
                DebugEvent::AccessViolation { .. } => "av",
                DebugEvent::Breakpoint { .. } => "bp",
                DebugEvent::ExitProcess { .. } => "exit",
                _ => "other",
            };
            let thread = match &ev.event {
                DebugEvent::ExitProcess { .. } => 0, // not carried by the abstract event
                other => thread_id_of(other),
            };
            out.push((ev.sequence, kind, thread));
            engine.continue_event(ContinueStatus::Continue).unwrap();
        }
        out
    }

    /// The live adapter must deliver exactly the same event sequence as the
    /// pure replay engine for the same scripted stream (P3 parity contract).
    #[test]
    fn live_adapter_and_replay_deliver_identical_sequences() {
        let base = 0x7ff6_c050_0000u64;
        let build_events = || {
            vec![
                create_process(base),
                DebugEvent::LoadDll {
                    thread_id: 2,
                    base_address: base + 0x10000,
                    h_file: HANDLE::default(),
                },
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
            ]
        };

        let mut replay = ReplayRuntimeEngine::new(build_events());
        let replay_seq = collect_sequence(&mut replay);

        let mut live = DebuggerCoreEngine::new(ScriptedDebugger::new(build_events(), base));
        let live_seq = collect_sequence(&mut live);

        assert_eq!(
            live_seq, replay_seq,
            "live adapter sequence must match replay"
        );
        assert_eq!(
            replay_seq.iter().map(|(s, _, _)| *s).collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
    }

    /// Same parity check on the guard->OEP skeleton script (phases + memory).
    #[test]
    fn live_adapter_matches_replay_guard_oep_phases() {
        let base = 0x7ff6_c050_0000u64;
        let oep_rva = 0x13e0u32;

        let mut replay = ReplayRuntimeEngine::new(guard_oep_event_script(base, oep_rva, 2));
        let replay_seq = collect_sequence(&mut replay);

        let mut live = DebuggerCoreEngine::new(ScriptedDebugger::new(
            guard_oep_event_script(base, oep_rva, 2),
            base,
        ));
        let live_seq = collect_sequence(&mut live);

        assert_eq!(live_seq, replay_seq);
        let kinds: Vec<&str> = replay_seq.iter().map(|(_, k, _)| *k).collect();
        assert_eq!(kinds, ["create", "load_dll", "av", "bp", "exit"]);
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

    // -----------------------------------------------------------------------
    // P3-A capability contract tests
    // -----------------------------------------------------------------------

    #[test]
    fn replay_capability_log_records_sequence_and_thread() {
        let mut eng = ReplayRuntimeEngine::new(vec![
            create_process(0x140000000),
            DebugEvent::ExitProcess { exit_code: 0 },
        ]);
        eng.wait(None).unwrap();
        // Seed a context so set/get both succeed.
        eng.seed_context(
            2,
            ThreadContextSnapshot {
                rip: 0x140001000,
                ..ThreadContextSnapshot::blank()
            },
        );
        let mut buf = [0u8; 4];
        eng.read_memory(0x140001000, &mut buf).unwrap_err(); // unmapped -> fail closed
        eng.set_hardware_breakpoint(2, 0, 0x140001234, HwbpType::Execute)
            .unwrap();
        eng.clear_hardware_breakpoint(2, 0).unwrap();
        let ctx = eng.get_thread_context(2).unwrap();
        assert_eq!(ctx.rip, 0x140001000);

        let log = eng.capability_log();
        assert_eq!(log.len(), 4);
        // Sequence is per-op monotonic.
        let seqs: Vec<u64> = log.iter().map(|r| r.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3, 4]);
        // Thread ids recorded per operation.
        assert_eq!(log[0].thread_id, 2);
        assert!(matches!(
            log[0].op,
            CapabilityOp::ReadMemory { result: Err(_), .. }
        ));
        assert!(matches!(
            log[1].op,
            CapabilityOp::SetHardwareBreakpoint { slot: 0, .. }
        ));
        assert!(matches!(
            log[2].op,
            CapabilityOp::ClearHardwareBreakpoint { slot: 0, .. }
        ));
        assert!(matches!(
            log[3].op,
            CapabilityOp::GetThreadContext { result: Ok(()) }
        ));
    }

    #[test]
    fn replay_unmapped_read_fails_closed_and_is_recorded() {
        let mut eng = ReplayRuntimeEngine::new(vec![DebugEvent::Other { thread_id: 7 }]);
        eng.wait(None).unwrap();
        let mut buf = [0u8; 8];
        let err = eng.read_memory(0xdead_beef, &mut buf).unwrap_err();
        assert!(matches!(err, CoreError::MemoryRead { .. }));
        assert!(matches!(
            &eng.capability_log()[0].op,
            CapabilityOp::ReadMemory { result: Err(_), .. }
        ));
    }

    #[test]
    fn replay_context_fail_closed_for_unseeded_thread() {
        let mut eng = ReplayRuntimeEngine::new(vec![DebugEvent::Other { thread_id: 3 }]);
        eng.wait(None).unwrap();
        assert!(eng.get_thread_context(3).is_err());
        // Set without a scripted context also fails (mirrors live RMW which
        // must read first).
        let snap = ThreadContextSnapshot::blank();
        assert!(eng.set_thread_context(3, &snap).is_err());
    }

    #[test]
    fn replay_breakpoint_slot_validation_fails_closed() {
        let mut eng = ReplayRuntimeEngine::new(vec![DebugEvent::Other { thread_id: 3 }]);
        eng.wait(None).unwrap();
        // Slot out of range.
        assert!(eng
            .set_hardware_breakpoint(3, 4, 0x1000, HwbpType::Execute)
            .is_err());
        // Zero address.
        assert!(eng
            .set_hardware_breakpoint(3, 0, 0, HwbpType::Execute)
            .is_err());
        // Duplicate slot.
        eng.set_hardware_breakpoint(3, 1, 0x1234, HwbpType::Write)
            .unwrap();
        assert!(eng
            .set_hardware_breakpoint(3, 1, 0x5678, HwbpType::Write)
            .is_err());
        // Clear an unarmed slot.
        assert!(eng.clear_hardware_breakpoint(3, 2).is_err());
        // Clear the armed one.
        eng.clear_hardware_breakpoint(3, 1).unwrap();
    }

    #[test]
    fn continue_thread_rejects_thread_id_mismatch_and_keeps_pending() {
        let mut replay = ReplayRuntimeEngine::new(vec![
            DebugEvent::Other { thread_id: 5 },
            DebugEvent::ExitProcess { exit_code: 0 },
        ]);
        replay.wait(None).unwrap();
        assert_eq!(replay.pending_thread_id(), Some(5));
        let err = replay
            .continue_thread(9, ContinueStatus::Continue)
            .unwrap_err();
        assert!(format!("{err}").contains("thread id mismatch"));
        assert!(replay.has_pending(), "mismatch must keep the event pending");
        assert_eq!(replay.pending_thread_id(), Some(5));
        replay.continue_thread(5, ContinueStatus::Continue).unwrap();
        assert!(!replay.has_pending());

        let mut live = DebuggerCoreEngine::new(ScriptedDebugger::new(
            vec![DebugEvent::Other { thread_id: 5 }],
            0,
        ));
        live.wait(None).unwrap();
        let err = live
            .continue_thread(9, ContinueStatus::Continue)
            .unwrap_err();
        assert!(format!("{err}").contains("thread id mismatch"));
        assert!(live.has_pending());
        live.continue_thread(5, ContinueStatus::Continue).unwrap();
    }

    #[test]
    fn live_context_rmw_preserves_untouched_registers() {
        let seed = ThreadContextSnapshot {
            rip: 0x140001000,
            rsp: 0x140001f00,
            rbp: 0x140001e00,
            rax: 0xaa,
            eflags: 0x202,
        };
        let dbg = ScriptedDebugger::with_contexts(
            vec![DebugEvent::Other { thread_id: 11 }],
            0x140000000,
            BTreeMap::from([(11, seed)]),
        );
        let mut eng = DebuggerCoreEngine::new(dbg);
        eng.wait(None).unwrap();
        let got = eng.get_thread_context(11).unwrap();
        assert_eq!(got, seed);
        let mut adjusted = got;
        adjusted.rip = 0x140001234;
        adjusted.rax = 0;
        eng.set_thread_context(11, &adjusted).unwrap();
        let after = eng.get_thread_context(11).unwrap();
        assert_eq!(after.rip, 0x140001234);
        assert_eq!(after.rax, 0);
        // Untouched registers survive the read-modify-write.
        assert_eq!(after.rsp, seed.rsp);
        assert_eq!(after.rbp, seed.rbp);
        assert_eq!(after.eflags, seed.eflags);
        // Live capability log parity shape: get, set, get.
        let log = eng.capability_log();
        assert_eq!(log.len(), 3);
        assert!(matches!(
            log[1].op,
            CapabilityOp::SetThreadContext { result: Ok(()) }
        ));
    }

    #[test]
    fn capability_parity_replay_vs_live_adapter() {
        let base = 0x7ff6_c050_0000u64;
        let seed = ThreadContextSnapshot {
            rip: base + 0x1000,
            rsp: base + 0x1f00,
            rbp: base + 0x1e00,
            rax: 0x10,
            eflags: 0x202,
        };
        let build_events = || {
            vec![
                create_process(base),
                DebugEvent::AccessViolation {
                    thread_id: 2,
                    address: base + 0x1000,
                    is_write: false,
                    target_address: base + 0x1000,
                    exc_type: 8,
                },
                DebugEvent::ExitProcess { exit_code: 0 },
            ]
        };

        // Drive both engines through the identical capability sequence.
        let mut replay = ReplayRuntimeEngine::with_memory(build_events(), {
            let mut mem = ReplayMemory::new();
            mem.map(base + 0x1000, vec![0xcc; 16]);
            mem
        });
        replay.seed_context(2, seed);
        replay.wait(None).unwrap();
        let mut buf = [0u8; 4];
        replay.read_memory(base + 0x1000, &mut buf).unwrap();
        let mut adjusted = replay.get_thread_context(2).unwrap();
        adjusted.rip += 0x10;
        replay.set_thread_context(2, &adjusted).unwrap();
        replay
            .set_hardware_breakpoint(2, 0, base + 0x2000, HwbpType::Execute)
            .unwrap();
        replay.continue_thread(2, ContinueStatus::Continue).unwrap();
        replay.wait(None).unwrap();

        let mut live_dbg =
            ScriptedDebugger::with_contexts(build_events(), base, BTreeMap::from([(2, seed)]));
        live_dbg.map_memory(base + 0x1000, vec![0xcc; 16]);
        let mut live = DebuggerCoreEngine::new(live_dbg);
        live.wait(None).unwrap();
        let mut buf = [0u8; 4];
        live.read_memory(base + 0x1000, &mut buf).unwrap();
        let mut adjusted = live.get_thread_context(2).unwrap();
        adjusted.rip += 0x10;
        live.set_thread_context(2, &adjusted).unwrap();
        live.set_hardware_breakpoint(2, 0, base + 0x2000, HwbpType::Execute)
            .unwrap();
        live.continue_thread(2, ContinueStatus::Continue).unwrap();
        live.wait(None).unwrap();

        // Capability logs must be identical op-for-op through the AV event.
        assert_eq!(live.capability_log(), replay.capability_log());

        // Continue the AV event with the engine-resolved pending thread, then
        // deliver and continue the ExitProcess (replay pending: abstract 0;
        // live: backend-reported real thread). Both must succeed exactly once.
        let replay_tid = replay.pending_thread_id().expect("replay AV pending");
        let live_tid = live.pending_thread_id().expect("live AV pending");
        replay
            .continue_thread(replay_tid, ContinueStatus::Continue)
            .unwrap();
        live.continue_thread(live_tid, ContinueStatus::Continue)
            .unwrap();
        replay.wait(None).unwrap();
        live.wait(None).unwrap();
        let replay_tid = replay.pending_thread_id().expect("replay exit pending");
        let live_tid = live.pending_thread_id().expect("live exit pending");
        replay
            .continue_thread(replay_tid, ContinueStatus::Continue)
            .unwrap();
        live.continue_thread(live_tid, ContinueStatus::Continue)
            .unwrap();
        assert!(replay.process_exited());
        assert!(live.process_exited());
    }
}
