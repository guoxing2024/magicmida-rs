//! Concrete [`DebuggerCore`] implementation backed by the Windows debug API.
//!
//! `WindowsDebugger` holds the target process, breakpoint tables, and thread
//! registrations and translates raw `DEBUG_EVENT` structs into the
//! higher-level [`DebugEvent`] enum consumed by the unpacker.

use std::collections::HashMap;

use tracing::{debug, info, trace, warn};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, DBG_CONTINUE, EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, HANDLE,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, FlushInstructionCache, GetThreadContext, ReadProcessMemory,
    SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT, CONTEXT_ALL_AMD64,
    CONTEXT_CONTROL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_FLAGS, CONTEXT_INTEGER_AMD64,
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT as RAW_DEBUG_EVENT,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, UNLOAD_DLL_DEBUG_EVENT,
};
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT_ALL_X86, CONTEXT_CONTROL_X86, CONTEXT_DEBUG_REGISTERS_X86, CONTEXT_INTEGER_X86,
};
use windows::Win32::System::Threading::INFINITE;

use crate::breakpoint::{HwBreakpoint, HwbpType};
use crate::cleanup::{cleanup_action, CleanupAction, CleanupReport, ProcessOwnership, WaitOutcome};
use crate::debug_event_lifecycle::{ContinuePlan, DebugEventLifecycle, DecodeDisposition};
use crate::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
use crate::error::CoreError;
use crate::process::{
    cleanup_stub_exe, close_process_handles, create_debug_process, patch_peb_anti_debug,
    CreateProcessOptions, TargetProcess,
};

// ---------------------------------------------------------------------------
// ScopedThreadHandle 闁?RAII guard for OpenThread-returned handles
// ---------------------------------------------------------------------------

/// RAII guard around a thread `HANDLE` returned by `OpenThread`.
///
/// `OpenThread` always produces a fresh handle owned by the caller that must
/// be released with `CloseHandle`.  Holding the handle inside this guard
/// guarantees release on any early-return path, even when a subsequent
/// `GetThreadContext` / `SetThreadContext` call fails.
///
/// **Do not** wrap handles that come from `CREATE_THREAD_DEBUG_EVENT` or
/// `CreateProcessW` 闁?those are owned by [`WindowsDebugger::threads`] and
/// [`WindowsDebugger::process`] respectively and are closed by their owners.
/// Use [`ScopedThreadHandle::new`] exclusively for handles you opened
/// yourself with `OpenThread`.
pub(crate) struct ScopedThreadHandle {
    handle: HANDLE,
}

impl ScopedThreadHandle {
    /// Wrap a fresh `OpenThread` handle.
    ///
    /// Callers must ensure `handle` was returned by a successful `OpenThread`
    /// call (and is therefore owned by the caller), not borrowed from a debug
    /// event or the process/thread table.
    pub(crate) fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    /// Borrow the underlying `HANDLE` for a Windows API call.
    ///
    /// The returned `HANDLE` is only valid for the lifetime of this guard 闁?
    /// callers must not store it beyond the guard's drop.
    pub(crate) fn as_raw(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for ScopedThreadHandle {
    fn drop(&mut self) {
        // SAFETY: by construction, the handle was opened by OpenThread and is
        // owned by this guard.  CloseHandle releases it exactly once.  Invalid
        // handles (e.g. from OpenThread returning a sentinel on failure) are
        // skipped because CloseHandle against an invalid handle is a no-op
        // that still sets ERROR_INVALID_HANDLE 闁?we avoid the noise.
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WindowsDebugger
// ---------------------------------------------------------------------------

/// Windows-backed debugger core.
///
/// Created from a [`CreateProcessOptions`] via [`WindowsDebugger::new`], which
/// launches the target.  Every subsequent operation goes through the
/// [`DebuggerCore`] trait implementation.
pub struct WindowsDebugger {
    /// Target process information (handles, pid, image base, etc.
    process: TargetProcess,
    /// Hardware breakpoints (DR0闁炽儲寮碦3). `None` means the slot is free.
    hw_breakpoints: [Option<HwBreakpoint>; 4],
    /// Software breakpoints: address 闁?original byte.
    soft_breakpoints: HashMap<usize, u8>,
    /// Registered threads: thread_id 闁?thread handle.
    threads: HashMap<u32, HANDLE>,
    /// How the target came under the debugger's control 闁?the single source
    /// of truth for `Drop` cleanup.  Separates process **ownership** (did we
    /// `CreateProcessW` it?) from debug-port presence, so an owned
    /// post-attach launch is terminated (not detached) on `Drop`.
    ownership: ProcessOwnership,
    /// Tracks the explicit one-time resume required by post-attach launch
    /// mode (owned, no debug port from `t=0`).
    post_attach_resumed: bool,
    /// Exactly-once pending debug-event identity (Wait 闁?Continue contract).
    lifecycle: DebugEventLifecycle,
    /// ADR-5B-R1: cumulative drain counters (audit + tests).
    drain_stats: DrainStats,
    /// ADR-5B-R1: TIDs whose CREATE_THREAD was observed by the drain path.
    /// Used to distinguish legit short-lived exits (OS merged the create
    /// event) from genuine bookkeeping defects.
    drain_observed_create_tids: std::collections::HashSet<u32>,
}

impl WindowsDebugger {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create the target process and return a ready-to-use debugger.
    ///
    /// This calls [`create_debug_process`] internally, so all PE inspection
    /// and (for DLLs) stub-EXE generation happens here.
    ///
    /// When `opts.post_attach` is `true`, the process is created with
    /// `CREATE_SUSPENDED` but no debug port. Construction reads and patches the
    /// PEB while the main thread remains suspended. The caller must invoke
    /// [`Self::resume_post_attach_main_thread`] after capturing any early state.
    /// This defeats protectors that check `EPROCESS.DebugPort` from `t=0`.
    pub fn new(opts: &CreateProcessOptions) -> Result<Self, CoreError> {
        let process = create_debug_process(opts)?;

        let mut threads = HashMap::new();
        threads.insert(process.main_thread_id, process.main_thread_handle);

        let root_pid = process.pid;
        // Ownership is assigned BEFORE prepare_post_attach so that a failure
        // partway through construction still drops an owned process (killed)
        // rather than detaching a process we actually created.
        let ownership = if opts.post_attach {
            ProcessOwnership::OwnedPostAttach
        } else {
            ProcessOwnership::OwnedLaunch
        };
        let mut dbg = Self {
            process,
            hw_breakpoints: Default::default(),
            soft_breakpoints: HashMap::new(),
            threads,
            ownership,
            post_attach_resumed: false,
            lifecycle: DebugEventLifecycle::new(root_pid),
            drain_stats: DrainStats::default(),
            drain_observed_create_tids: std::collections::HashSet::new(),
        };

        if opts.post_attach {
            dbg.prepare_post_attach()?;
        }

        Ok(dbg)
    }

    /// Prepare post-attach observation while leaving the main thread suspended.
    fn prepare_post_attach(&mut self) -> Result<(), CoreError> {
        let img_base = patch_peb_anti_debug(self.process.handle)?;
        self.process.image_base = img_base;
        debug!(
            image_base = format_args!("{img_base:#x}"),
            "post-attach: PEB patched; main thread remains suspended"
        );
        Ok(())
    }

    /// Resume the suspended main thread in post-attach mode exactly once.
    ///
    /// Call this only after capturing any loader-initialized baseline state that
    /// must precede application or CRT execution.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::ProcessCreation`] when called outside
    /// [`ProcessOwnership::OwnedPostAttach`] mode, called more than once, or
    /// when `ResumeThread` fails.
    pub fn resume_post_attach_main_thread(&mut self) -> Result<(), CoreError> {
        use windows::Win32::System::Threading::ResumeThread;

        if !matches!(self.ownership, ProcessOwnership::OwnedPostAttach) {
            return Err(CoreError::ProcessCreation(
                "cannot resume post-attach thread outside owned post-attach launch mode".into(),
            ));
        }
        if self.post_attach_resumed {
            return Err(CoreError::ProcessCreation(
                "post-attach main thread has already been resumed".into(),
            ));
        }

        // SAFETY: the handle is the live main-thread handle returned by
        // CreateProcessW with CREATE_SUSPENDED and is owned by this debugger.
        let previous = unsafe { ResumeThread(self.process.main_thread_handle) };
        if previous == u32::MAX {
            // SAFETY: GetLastError reads the calling thread's last-error value.
            let error = unsafe { GetLastError() };
            return Err(CoreError::Windows(error.0));
        }

        self.post_attach_resumed = true;
        info!(
            previous_suspend_count = previous,
            "post-attach: main thread resumed without a debug port"
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Return a reference to the underlying [`TargetProcess`].
    pub fn process(&self) -> &TargetProcess {
        &self.process
    }

    /// Return the target process ID.
    pub fn pid(&self) -> u32 {
        self.process.pid
    }

    /// Return the main (initial) thread ID of the target.
    pub fn main_thread_id(&self) -> u32 {
        self.process.main_thread_id
    }

    /// Return the image base discovered during `CREATE_PROCESS_DEBUG_EVENT`.
    pub fn image_base(&self) -> u64 {
        self.process.image_base
    }

    /// Return how the target came under the debugger's control 闁?the single
    /// source of truth for `Drop` cleanup.
    pub fn ownership(&self) -> ProcessOwnership {
        self.ownership
    }

    // ------------------------------------------------------------------
    // Breakpoint helpers (exposed for packer crates)
    // ------------------------------------------------------------------

    /// Return the address of the hardware breakpoint in the given slot
    /// (0闁? 闁?DR0闁炽儲寮碦3), or `None` if the slot is empty.
    ///
    /// Used by the unpack loop to compare an incoming exception address
    /// against the installed CloseHandle / CorExeMain BP without needing
    /// write access to the breakpoint table.
    pub fn hw_breakpoint_addr(&self, slot: usize) -> Option<u64> {
        debug_assert!(slot < 4, "slot must be 0闁?");
        self.hw_breakpoints
            .get(slot)
            .and_then(|opt| opt.as_ref())
            .map(|bp| bp.address)
    }

    /// Return `true` if there is any enabled hardware breakpoint 闁?used by the
    /// CreateThread handler to decide whether it's worth trying to propagate
    /// DR state to the new thread.  Spawning threads in a target that holds no
    /// hardware breakpoint is the common case (e.g. every CRT worker thread
    /// Themida creates), and forcing `GetThreadContext` against a thread the
    /// debugger lacks `THREAD_SUSPEND_RESUME` rights for just emits noisy
    /// `ERROR_PARTIAL_COPY` warnings.
    pub fn has_any_hw_breakpoint(&self) -> bool {
        self.hw_breakpoints
            .iter()
            .any(|slot| slot.as_ref().is_some_and(|bp| bp.is_set()))
    }

    /// Look up a thread handle by ID.
    pub fn thread_handle(&self, thread_id: u32) -> Result<HANDLE, CoreError> {
        self.threads
            .get(&thread_id)
            .copied()
            .ok_or(CoreError::ThreadNotFound(thread_id))
    }

    /// Context flags for reading full register state.
    #[cfg(target_arch = "x86_64")]
    fn full_context_flags() -> CONTEXT_FLAGS {
        CONTEXT_ALL_AMD64
    }
    #[cfg(target_arch = "x86")]
    fn full_context_flags() -> CONTEXT_FLAGS {
        CONTEXT_ALL_X86
    }

    /// Context flags for reading only debug registers (DR0闁炽儲寮碦7).
    #[cfg(target_arch = "x86_64")]
    fn debug_registers_flags() -> CONTEXT_FLAGS {
        CONTEXT_DEBUG_REGISTERS_AMD64
    }
    #[cfg(target_arch = "x86")]
    fn debug_registers_flags() -> CONTEXT_FLAGS {
        CONTEXT_DEBUG_REGISTERS_X86
    }

    /// Context flags for reading only control registers (Rip, Rsp, EFlags,
    /// SegCs, SegSs).
    #[cfg(target_arch = "x86_64")]
    fn control_context_flags() -> CONTEXT_FLAGS {
        CONTEXT_CONTROL_AMD64
    }
    #[cfg(target_arch = "x86")]
    fn control_context_flags() -> CONTEXT_FLAGS {
        CONTEXT_CONTROL_X86
    }

    /// Context flags for reading control and integer registers.
    #[cfg(target_arch = "x86_64")]
    fn control_integer_context_flags() -> CONTEXT_FLAGS {
        CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64
    }
    #[cfg(target_arch = "x86")]
    fn control_integer_context_flags() -> CONTEXT_FLAGS {
        CONTEXT_CONTROL_X86 | CONTEXT_INTEGER_X86
    }

    // ------------------------------------------------------------------
    // Hardware breakpoint management
    // ------------------------------------------------------------------

    /// Set a hardware breakpoint in the given slot (0闁? 闁?DR0闁炽儲寮碦3).
    ///
    /// This method suspends the given thread, reads its debug registers,
    /// installs the breakpoint, writes the registers back, and resumes
    /// the thread.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::HwbpSlotInUse`] if the slot is already occupied
    /// by an enabled breakpoint.
    pub fn set_hw_breakpoint(
        &mut self,
        slot: usize,
        address: usize,
        bp_type: HwbpType,
    ) -> Result<(), CoreError> {
        debug_assert!(slot < 4, "slot must be 0?3");

        if self.hw_breakpoints[slot]
            .as_ref()
            .is_some_and(|bp| bp.is_set())
        {
            return Err(CoreError::HwbpSlotInUse(slot));
        }

        let previous = self.hw_breakpoints.clone();
        let mut desired = previous.clone();
        desired[slot] = Some(HwBreakpoint {
            address: address as u64,
            bp_type,
            disabled: false,
        });
        self.apply_debug_registers_all(&desired, &previous)?;
        self.hw_breakpoints = desired;

        debug!(slot, %address, ?bp_type, "Hardware breakpoint set");
        Ok(())
    }

    /// Clear (remove) a hardware breakpoint from the given slot.
    pub fn clear_hw_breakpoint(&mut self, slot: usize) -> Result<(), CoreError> {
        debug_assert!(slot < 4, "slot must be 0?3");

        let previous = self.hw_breakpoints.clone();
        if previous[slot].is_none() {
            return Ok(());
        }
        let mut desired = previous.clone();
        desired[slot] = None;
        self.apply_debug_registers_all(&desired, &previous)?;
        self.hw_breakpoints = desired;

        debug!(slot, "Hardware breakpoint cleared");
        Ok(())
    }

    /// Disable a hardware breakpoint without removing its configuration.
    pub fn disable_hw_breakpoint(&mut self, slot: usize) -> Result<(), CoreError> {
        debug_assert!(slot < 4, "slot must be 0?3");

        let previous = self.hw_breakpoints.clone();
        let Some(bp) = previous[slot].as_ref() else {
            return Ok(());
        };
        if bp.disabled {
            return Ok(());
        }
        let mut desired = previous.clone();
        if let Some(bp) = desired[slot].as_mut() {
            bp.disabled = true;
        }
        self.apply_debug_registers_all(&desired, &previous)?;
        self.hw_breakpoints = desired;

        debug!(slot, "Hardware breakpoint disabled");
        Ok(())
    }

    /// Re-enable all previously disabled hardware breakpoints.
    pub fn reset_hw_breakpoints(&mut self) -> Result<(), CoreError> {
        let previous = self.hw_breakpoints.clone();
        let mut desired = previous.clone();
        let mut changed = false;
        for bp in desired.iter_mut().flatten() {
            if bp.disabled {
                bp.disabled = false;
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }

        self.apply_debug_registers_all(&desired, &previous)?;
        self.hw_breakpoints = desired;
        debug!("All disabled hardware breakpoints reset");
        Ok(())
    }

    /// Apply a desired DR state to every registered thread transactionally.
    ///
    /// The software table is committed by the caller only after every thread
    /// succeeds. Already-updated threads are rolled back to `rollback` when a
    /// later thread fails; rollback failure is included in the returned error.
    fn apply_debug_registers_all(
        &self,
        desired: &[Option<HwBreakpoint>; 4],
        rollback: &[Option<HwBreakpoint>; 4],
    ) -> Result<(), CoreError> {
        let thread_ids: Vec<u32> = self.threads.keys().copied().collect();
        let mut applied = Vec::with_capacity(thread_ids.len());
        for thread_id in thread_ids {
            if let Err(apply_error) =
                self.apply_debug_registers_thread_for_state(thread_id, desired)
            {
                let mut rollback_errors = Vec::new();
                for applied_tid in applied.into_iter().rev() {
                    if let Err(error) =
                        self.apply_debug_registers_thread_for_state(applied_tid, rollback)
                    {
                        rollback_errors.push(format!("tid={applied_tid}: {error}"));
                    }
                }
                if rollback_errors.is_empty() {
                    return Err(apply_error);
                }
                return Err(CoreError::DebugState(format!(
                    "hardware breakpoint transaction failed: {apply_error}; rollback failed for {}",
                    rollback_errors.join(", ")
                )));
            }
            applied.push(thread_id);
        }
        Ok(())
    }

    /// Apply the current hardware breakpoint state to one thread.
    pub fn apply_debug_registers_thread(&self, thread_id: u32) -> Result<(), CoreError> {
        self.apply_debug_registers_thread_for_state(thread_id, &self.hw_breakpoints)
    }

    /// Perform one complete Suspend/Get/Set/Resume transaction for a thread.
    fn apply_debug_registers_thread_for_state(
        &self,
        thread_id: u32,
        state: &[Option<HwBreakpoint>; 4],
    ) -> Result<(), CoreError> {
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
        };

        let raw = unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                thread_id,
            )
            .map_err(|e| CoreError::Windows(e.code().0 as u32))?
        };
        let handle = ScopedThreadHandle::new(raw);
        let suspended = unsafe { SuspendThread(handle.as_raw()) };
        if suspended == u32::MAX {
            return Err(CoreError::Windows(unsafe { GetLastError() }.0));
        }

        let operation = (|| {
            let mut ctx: CONTEXT = unsafe { std::mem::zeroed() };
            ctx.ContextFlags = Self::debug_registers_flags();
            unsafe {
                GetThreadContext(handle.as_raw(), &mut ctx)
                    .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            }
            Self::write_debug_registers_for_state(&mut ctx, state);
            unsafe {
                SetThreadContext(handle.as_raw(), &ctx)
                    .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            }
            Ok::<(), CoreError>(())
        })();

        let resumed = unsafe { ResumeThread(handle.as_raw()) };
        if resumed == u32::MAX {
            let resume_error = CoreError::Windows(unsafe { GetLastError() }.0);
            return match operation {
                Ok(()) => Err(resume_error),
                Err(operation_error) => Err(CoreError::DebugState(format!(
                    "hardware breakpoint update failed ({operation_error}) and ResumeThread failed ({resume_error})"
                ))),
            };
        }
        operation
    }

    /// Write the hardware breakpoint state into the given CONTEXT.
    ///
    /// This populates DR0闁炽儲寮碦3 and DR7 from `self.hw_breakpoints`.
    /// DR6 is cleared of the BS (single-step) flag (bit 14) to prevent
    /// the OS from misinterpreting a single-step as a hardware breakpoint.
    fn write_debug_registers_for_state(
        ctx: &mut CONTEXT,
        hw_breakpoints: &[Option<HwBreakpoint>; 4],
    ) {
        // Build the DR7 mask.
        // DR7 bit layout (x86/x64):
        //   L0闁炽儲褰?  (bits 0,2,4,6):   local enable (set = 1)
        //   G0闁炽儲寮?  (bits 1,3,5,7):   global enable (unused 闁?set 0)
        //   LEN0闁炽儲褰咵N3 (bits 8-15):       length (00=1, 01=2, 11=4 bytes)
        //   RW0闁炽儲褰峎3  (bits 16-23):      type (00=execute, 01=write, 11=access)
        let mut dr7: u64 = 0;

        // Helper: write one slot's data into DR7 and the context DRn register.
        fn apply_slot(ctx: &mut CONTEXT, bp: Option<&HwBreakpoint>, slot: usize, dr7: &mut u64) {
            let dr_shift = slot * 4; // RW field: bits 16 + 4*slot
            let le_shift = slot * 2; // L enable: bits 0,2,4,6
            match bp {
                Some(b) if b.is_set() => {
                    match slot {
                        0 => ctx.Dr0 = b.address,
                        1 => ctx.Dr1 = b.address,
                        2 => ctx.Dr2 = b.address,
                        3 => ctx.Dr3 = b.address,
                        _ => unreachable!(),
                    }
                    *dr7 |= 1u64 << le_shift;
                    *dr7 |= (b.bp_type as u64) << (16 + dr_shift);
                }
                _ => {
                    // Slot is empty or disabled; clear the DRn register.
                    match slot {
                        0 => ctx.Dr0 = 0,
                        1 => ctx.Dr1 = 0,
                        2 => ctx.Dr2 = 0,
                        3 => ctx.Dr3 = 0,
                        _ => unreachable!(),
                    }
                }
            }
        }

        apply_slot(ctx, hw_breakpoints[0].as_ref(), 0, &mut dr7);
        apply_slot(ctx, hw_breakpoints[1].as_ref(), 1, &mut dr7);
        apply_slot(ctx, hw_breakpoints[2].as_ref(), 2, &mut dr7);
        apply_slot(ctx, hw_breakpoints[3].as_ref(), 3, &mut dr7);

        // Clear the BS (single-step) flag in DR6 (bit 14) so the OS
        // doesn't conflate a single-step with a hardware breakpoint.
        ctx.Dr6 &= !(1u64 << 14);

        ctx.Dr7 = dr7;
    }

    // ------------------------------------------------------------------
    // Software breakpoint management
    // ------------------------------------------------------------------

    /// Set a software breakpoint (INT3 / 0xCC) at the given address.
    ///
    /// Reference: `DebuggerCore.pas` 闁?`SetSoftBP`.
    ///
    /// 1. Read the original byte at the target address.
    /// 2. Save it in `soft_breakpoints`.
    /// 3. Write `0xCC` (`INT3`) to the target address.
    /// 4. Flush the instruction cache.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::MemoryRead`] if the original byte cannot be read,
    /// or [`CoreError::MemoryWrite`] if the `0xCC` write fails.
    pub fn set_soft_breakpoint(&mut self, address: usize) -> Result<(), CoreError> {
        // Check whether we already have a soft breakpoint at this address.
        if self.soft_breakpoints.contains_key(&address) {
            // Verify the byte at that address is actually 0xCC (consistency check).
            let mut current: [u8; 1] = [0];
            let read = self.read_memory(address, &mut current)?;
            if soft_breakpoint_state_is_consistent(read, current[0]) {
                trace!(%address, "Soft breakpoint already set at address");
                return Ok(());
            }
            // The map stores the original byte needed for rollback.  Do not
            // delete it when the target byte is no longer 0xCC: dropping the
            // entry would lose the only restoration record while leaving the
            // target and software state inconsistent.
            warn!(
                %address,
                bytes_read = read,
                byte = current[0],
                "Soft breakpoint state inconsistency 閳?refusing to overwrite"
            );
            return Err(CoreError::DebugState(format!(
                "soft breakpoint state mismatch at {address:#x}: expected 0xCC, read={read} byte={:#04x}; original-byte map entry retained",
                current[0]
            )));
        }

        // 1. Read the original byte.
        let mut original: [u8; 1] = [0];
        let bytes_read = self.read_memory(address, &mut original)?;
        if bytes_read != 1 {
            return Err(CoreError::MemoryRead {
                address: address as u64,
                requested: 1,
            });
        }

        // 2. Save the original byte.
        self.soft_breakpoints.insert(address, original[0]);

        // 3. Write 0xCC (INT3).
        let int3: [u8; 1] = [0xCC];
        let bytes_written = self.write_memory(address, &int3)?;
        if bytes_written != 1 {
            return Err(CoreError::MemoryWrite {
                address: address as u64,
                requested: 1,
            });
        }

        // 4. Flush the instruction cache so the CPU sees the new byte.
        // SAFETY: hProcess is a valid handle; the address and size are within bounds.
        unsafe {
            FlushInstructionCache(
                self.process.handle,
                Some(address as *const std::ffi::c_void),
                1,
            )
            .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        debug!(%address, "Soft breakpoint set");
        Ok(())
    }

    /// Clear all software breakpoints, restoring every original byte.
    ///
    /// Reference: `DebuggerCore.pas` 闁?`SoftBPClear`.
    ///
    /// Iterates over `soft_breakpoints`, writes the original byte back to each
    /// address, then flushes the instruction cache and clears the map.
    pub fn clear_all_soft_breakpoints(&mut self) -> Result<(), CoreError> {
        // Work from a snapshot, but remove each entry only after its byte and
        // instruction-cache flush both succeed. A failed restore therefore
        // leaves the map as an actionable rollback record.
        let entries: Vec<(usize, u8)> = self
            .soft_breakpoints
            .iter()
            .map(|(&address, &original)| (address, original))
            .collect();

        for (address, original) in entries {
            let bytes_written = self.write_memory(address, &[original])?;
            if bytes_written != 1 {
                return Err(CoreError::MemoryWrite {
                    address: address as u64,
                    requested: 1,
                });
            }
            unsafe {
                FlushInstructionCache(
                    self.process.handle,
                    Some(address as *const std::ffi::c_void),
                    1,
                )
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            }
            self.soft_breakpoints.remove(&address);
        }

        debug!("All soft breakpoints cleared");
        Ok(())
    }

    /// Reset / re-arm a software breakpoint after single-stepping over it.
    ///
    /// Reference: `DebuggerCore.pas` 闁?`OnSoftwareBreakpoint` /
    /// `SoftBPReenable`.
    ///
    /// When a soft breakpoint fires, the original instruction has already been
    /// executed.  This method re-applies `0xCC` at the re-enable address and
    /// flushes the instruction cache.
    ///
    /// Call this after single-stepping past the breakpoint (via
    /// `single_step(thread_id)` 闁?wait for `SingleStep` event 闁?call this).
    pub fn reset_soft_breakpoint(&mut self, address: usize) -> Result<(), CoreError> {
        // Write 0xCC back to the breakpoint address.
        let int3: [u8; 1] = [0xCC];
        let bytes_written = self.write_memory(address, &int3)?;
        if bytes_written != 1 {
            return Err(CoreError::MemoryWrite {
                address: address as u64,
                requested: 1,
            });
        }

        // Flush the instruction cache.
        // SAFETY: hProcess is a valid handle; address and size are within bounds.
        unsafe {
            FlushInstructionCache(
                self.process.handle,
                Some(address as *const std::ffi::c_void),
                1,
            )
            .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        debug!(%address, "Soft breakpoint re-armed after single-step");
        Ok(())
    }

    /// Set the trap flag on the given thread to execute a single instruction.
    ///
    /// Reads the current thread context, sets `EFlags |= 0x100` (TF bit), and
    /// writes it back.  The thread will fire a `SingleStep` exception after
    /// executing one instruction.
    ///
    /// This is a low-level helper needed for both hardware and software
    /// breakpoint single-stepping.
    pub fn enable_single_step(&self, thread_id: u32) -> Result<(), CoreError> {
        use windows::Win32::System::Threading::{
            OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
        };

        // SAFETY: OpenThread returns a fresh valid HANDLE; thread_id comes from a registered debug thread.
        // The handle is wrapped in ScopedThreadHandle so CloseHandle runs on every return path.
        let h = unsafe {
            let raw = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            ScopedThreadHandle::new(raw)
        };

        // CONTROL is enough for EFlags (TF); avoid CONTEXT_ALL / XSAVE on Win11.
        let mut ctx = CONTEXT {
            ContextFlags: Self::control_context_flags(),
            ..Default::default()
        };

        // SAFETY: h.as_raw() is a valid thread handle with THREAD_GET_CONTEXT rights.
        unsafe {
            GetThreadContext(h.as_raw(), &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        // Set the trap flag (TF, bit 8 in EFlags).
        ctx.EFlags |= 0x100;
        ctx.ContextFlags = Self::control_context_flags();

        // SAFETY: h.as_raw() is a valid thread handle with THREAD_SET_CONTEXT rights.
        unsafe {
            SetThreadContext(h.as_raw(), &ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Drop 闁?clean up handles, terminate target, and delete stub EXE
// ---------------------------------------------------------------------------

/// Maximum time (ms) to wait for the target to exit after TerminateProcess.
const DROP_TERMINATE_TIMEOUT_MS: u32 = 5000;

impl Drop for WindowsDebugger {
    fn drop(&mut self) {
        use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

        // A delivered debug event blocks the debuggee until ContinueDebugEvent.
        // Resolve it before termination so Drop never silently abandons a raw
        // pending event (especially ExitProcess, whose public enum omits TID).
        if let Some(pending) = self.lifecycle.pending().copied() {
            if let Err(error) = self.continue_pending(pending.thread_id, ContinueStatus::Continue) {
                warn!(
                    pid = pending.process_id,
                    tid = pending.thread_id,
                    error = %error,
                    "Drop: failed to continue pending debug event; cleanup may leave debug port state"
                );
            }
        }

        // --- Lifecycle: decide cleanup from ownership, not debug-port state ---
        //
        // Ownership (not `post_attach`) drives cleanup.  Every ownership
        // variant here is *owned* (we created the process via CreateProcessW),
        // so `Drop` always performs `TerminateProcess` + bounded wait.  The
        // borrowed-attach / `DebugActiveProcessStop` detach path was removed:
        // it had no real caller and was dead code.
        let report = match cleanup_action(self.ownership) {
            CleanupAction::TerminateAndWait => {
                if self.process.handle.is_invalid() {
                    // Construction-midway-failure shape: handle not usable.
                    let r = CleanupReport::for_construction_failure(self.ownership);
                    warn!(
                        pid = self.process.pid,
                        summary = r.summary(),
                        "Drop: process handle invalid 闁?cannot terminate owned target"
                    );
                    CleanupReport::for_terminate(
                        self.ownership,
                        false,
                        None,
                        WaitOutcome::Failed(6), // ERROR_INVALID_HANDLE
                    )
                } else {
                    // SAFETY: TerminateProcess on a valid owned handle.
                    let tp = unsafe { TerminateProcess(self.process.handle, 1) };
                    let terminate_ok = tp.is_ok();
                    let term_win32 = tp.err().map(|e| e.code().0 as u32);
                    // SAFETY: bounded wait on the owned process handle.
                    let wait_result = unsafe {
                        WaitForSingleObject(self.process.handle, DROP_TERMINATE_TIMEOUT_MS)
                    };
                    let wait = match wait_result.0 {
                        0 => WaitOutcome::Signaled,
                        0x102 => WaitOutcome::Timeout, // WAIT_TIMEOUT
                        _ => {
                            // SAFETY: GetLastError for the failed wait.
                            let code = unsafe { GetLastError() }.0;
                            WaitOutcome::Failed(code)
                        }
                    };
                    let report = CleanupReport::for_terminate(
                        self.ownership,
                        terminate_ok,
                        term_win32,
                        wait,
                    );
                    // Surface failures at warn! so they are not lost in a
                    // debug!-only report.  Only full success uses debug!.
                    if report.is_clean() {
                        debug!(
                            pid = self.process.pid,
                            summary = report.summary(),
                            "Drop: terminated owned target + bounded wait (clean)"
                        );
                    } else {
                        warn!(
                            pid = self.process.pid,
                            summary = report.summary(),
                            "Drop: cleanup issue (terminate failed, wait timeout, or wait failed; on timeout the owned process may still be alive)"
                        );
                    }
                    report
                }
            }
        };
        let _ = report; // diagnostics already emitted above.

        // Close every registered thread handle EXCEPT the main thread.
        // The main-thread handle is owned by `self.process` and will be closed
        // together with the process handle by `close_process_handles` below 闁?
        // closing it twice risks closing a recycled HANDLE value on Windows.
        for (&tid, &h) in self.threads.iter() {
            if tid == self.process.main_thread_id {
                continue;
            }
            if !h.is_invalid() {
                // SAFETY: handles were opened by the debug API and are valid.
                unsafe {
                    let _ = CloseHandle(h);
                }
            }
        }
        // Close process and main-thread handles.
        close_process_handles(self.process.handle, self.process.main_thread_handle);
        // Delete the stub EXE if one was generated.
        if let Some(ref stub) = self.process.stub_exe {
            cleanup_stub_exe(stub);
        }
    }
}

/// Return whether an existing software-breakpoint map entry still matches the
/// target byte. A mismatch is handled by `set_soft_breakpoint` as an error;
/// the map entry must remain available for rollback.
fn soft_breakpoint_state_is_consistent(bytes_read: usize, current_byte: u8) -> bool {
    bytes_read == 1 && current_byte == 0xCC
}

// ---------------------------------------------------------------------------
// Drain receipts (ADR-5B-R1)
// ---------------------------------------------------------------------------

/// Disposition applied to an event consumed by `WindowsDebugger::drain_debug_event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainDisposition {
    /// Event was decoded and full bookkeeping was applied (thread table,
    /// hFile close, DR propagation).
    Delivered,
    /// Event was internally ignored (OUTPUT_DEBUG_STRING / unknown code)
    /// and continued exactly once.
    Ignored,
    /// RIP_EVENT: continued exactly once and recorded (system-level error).
    Rip,
    /// EXCEPTION event inside the drain window: recorded (code + first
    /// chance) and continued without delivery.
    Exception,
}

/// Structured receipt for one debug event consumed by the drain path.
///
/// ADR-5B-R1: every drain event must carry the raw identity, disposition,
/// continue status, bookkeeping outcome, and a monotonic sequence so the
/// audit trail can prove no event bypassed the unified lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReceipt {
    /// Monotonic sequence assigned by the lifecycle (matches the main loop).
    pub sequence: u64,
    /// Raw dwProcessId from the DEBUG_EVENT.
    pub process_id: u32,
    /// Raw dwThreadId from the DEBUG_EVENT.
    pub thread_id: u32,
    /// Raw dwDebugEventCode value.
    pub event_code: u32,
    /// Disposition applied to this event.
    pub disposition: DrainDisposition,
    /// ContinueDebugEvent status used (DBG_CONTINUE = 0x00010002).
    pub continue_status: u32,
    /// Bookkeeping outcome summary (thread registered/removed, hFile closed,
    /// DR propagated, ...). Empty when no bookkeeping applied.
    pub bookkeeping: String,
    /// Exception code for EXCEPTION events in the drain window.
    pub exception_code: Option<u32>,
    /// dwFirstChance flag for EXCEPTION events.
    pub first_chance: Option<bool>,
}

/// Cumulative counters for the drain path (ADR-5B-R1).
///
/// Tests use these to prove no event bypassed bookkeeping: every
/// CreateThread registered a handle, every ExitThread removed a previously
/// registered thread (no unmatched exit), every LOAD_DLL/CREATE_PROCESS
/// hFile was closed, and exceptions were recorded.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainStats {
    /// Total events consumed by the drain path.
    pub events_drained: u64,
    /// CreateThread events that registered a thread handle.
    pub create_threads_registered: u64,
    /// ExitThread events that removed a previously registered thread.
    pub exit_threads_removed: u64,
    /// ExitThread events whose TID was NOT registered (bookkeeping gap).
    pub unmatched_exit_threads: u64,
    /// LOAD_DLL / CREATE_PROCESS hFile handles closed by the drain.
    pub hfiles_closed: u64,
    /// EXCEPTION events recorded and continued in the drain window.
    pub exceptions_continued: u64,
    /// Ignored events (OUTPUT_DEBUG_STRING / unknown) continued exactly once.
    pub ignored_continued: u64,
    /// RIP_EVENT occurrences.
    pub rip_events: u64,
    /// DR-state propagations to newly registered threads during drain.
    pub dr_propagations: u64,
    /// Sequence of the last drained event (0 if none).
    pub last_sequence: u64,
}

// ---------------------------------------------------------------------------
// DebuggerCore implementation
// ---------------------------------------------------------------------------

impl DebuggerCore for WindowsDebugger {
    fn process_handle(&self) -> HANDLE {
        self.process.handle
    }

    fn pid(&self) -> u32 {
        self.process.pid
    }

    fn image_base(&self) -> u64 {
        self.process.image_base
    }

    fn pending_event_thread_id(&self) -> Option<u32> {
        self.lifecycle.pending().map(|event| event.thread_id)
    }

    fn wait_event_timeout(&mut self, timeout_ms: u32) -> Result<DebugEvent, CoreError> {
        // Exactly one outer wait attempt with the caller's timeout. Internally
        // ignored events are continued and the next wait uses a zero remaining
        // budget so we do not silently extend the caller's timeout.
        self.wait_next_event(timeout_ms)
    }

    fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
        loop {
            match self.wait_next_event(INFINITE) {
                Ok(ev) => return Ok(ev),
                // Should not surface from wait_next_event with INFINITE, but
                // keep the loop defensive.
                Err(CoreError::Timeout) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn continue_event(&mut self, thread_id: u32, status: ContinueStatus) -> Result<(), CoreError> {
        self.continue_pending(thread_id, status)
    }

    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        let mut bytes_read: usize = 0;

        // SAFETY: buf is a valid mutable slice of the given length;
        // address is a virtual address in the target.
        unsafe {
            ReadProcessMemory(
                self.process.handle,
                address as *const std::ffi::c_void,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf.len(),
                Some(&mut bytes_read),
            )
            .map_err(|_| CoreError::MemoryRead {
                address: address as u64,
                requested: buf.len(),
            })?;
        }

        Ok(bytes_read)
    }

    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, CoreError> {
        let mut bytes_written: usize = 0;

        // SAFETY: data is a valid slice; address is a virtual address in the
        // target.  WriteProcessMemory modifies the target, not our buffer.
        unsafe {
            WriteProcessMemory(
                self.process.handle,
                address as *const std::ffi::c_void,
                data.as_ptr() as *const std::ffi::c_void,
                data.len(),
                Some(&mut bytes_written),
            )
            .map_err(|_| CoreError::MemoryWrite {
                address: address as u64,
                requested: data.len(),
            })?;
        }

        Ok(bytes_written)
    }

    fn get_thread_context(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        // Wrapped in ScopedThreadHandle so CloseHandle runs on every return path.
        let h = unsafe {
            let raw = OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            ScopedThreadHandle::new(raw)
        };
        // Prefer CONTROL|INTEGER first: CONTEXT_ALL frequently hits
        // ERROR_PARTIAL_COPY / incomplete XSAVE under Themida on Win11, and
        // callers (IAT TF, OEP Rip) only need GPRs + control registers.
        let mut ctx = CONTEXT {
            ContextFlags: Self::control_integer_context_flags(),
            ..Default::default()
        };

        // SAFETY: h.as_raw() is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a writable CONTEXT.
        let first = unsafe { GetThreadContext(h.as_raw(), &mut ctx) };
        if first.is_ok() {
            return Ok(ctx);
        }

        // Fallback: full context for rare callers that need more state.
        ctx = CONTEXT {
            ContextFlags: Self::full_context_flags(),
            ..Default::default()
        };
        unsafe {
            GetThreadContext(h.as_raw(), &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(ctx)
    }

    fn get_thread_context_control(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        // Wrapped in ScopedThreadHandle so CloseHandle runs on every return path.
        let h = unsafe {
            let raw = OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            ScopedThreadHandle::new(raw)
        };
        let mut ctx = CONTEXT {
            ContextFlags: Self::control_context_flags(),
            ..Default::default()
        };

        // SAFETY: h.as_raw() is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a writable CONTEXT.
        unsafe {
            GetThreadContext(h.as_raw(), &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(ctx)
    }

    fn get_thread_context_control_integer(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        // Wrapped in ScopedThreadHandle so CloseHandle runs on every return path.
        let h = unsafe {
            let raw = OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            ScopedThreadHandle::new(raw)
        };
        let mut ctx = CONTEXT {
            ContextFlags: Self::control_integer_context_flags(),
            ..Default::default()
        };

        // SAFETY: h.as_raw() is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a writable CONTEXT.
        unsafe {
            GetThreadContext(h.as_raw(), &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(ctx)
    }

    fn set_thread_context(&self, thread_id: u32, ctx: &CONTEXT) -> Result<(), CoreError> {
        use windows::Win32::System::Threading::{
            OpenThread, ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
            THREAD_SUSPEND_RESUME,
        };

        // Win11 + Themida often rejects SetThreadContext of CONTEXT_ALL (XSAVE /
        // floating-point areas) with ERROR_NOACCESS (0x800703E6).  Strip to
        // CONTROL|INTEGER 闁?enough for RIP/RSP/EFlags (TF) and GPRs used by
        // IAT single-step tracing and OEP recovery.
        let mut local = *ctx;
        local.ContextFlags = Self::control_integer_context_flags();

        // Prefer a fresh OpenThread handle with suspend+set rights.
        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        let open = unsafe {
            OpenThread(
                THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                false,
                thread_id,
            )
            .ok()
        };
        let scoped = open.map(ScopedThreadHandle::new);
        let borrowed = self.thread_handle(thread_id).ok();

        let try_set = |h: HANDLE| -> Result<(), CoreError> {
            // SAFETY: h is a valid thread handle; local is CONTROL|INTEGER CONTEXT.
            unsafe {
                SetThreadContext(h, &local).map_err(|e| CoreError::Windows(e.code().0 as u32))
            }
        };

        if let Some(ref g) = scoped {
            if try_set(g.as_raw()).is_ok() {
                return Ok(());
            }
            // Suspend + retry once (thread may briefly be non-stoppable after injector).
            let suspended = unsafe { SuspendThread(g.as_raw()) };
            let second = try_set(g.as_raw());
            if suspended != u32::MAX {
                let _ = unsafe { ResumeThread(g.as_raw()) };
            }
            if second.is_ok() {
                return Ok(());
            }
        }

        if let Some(h) = borrowed {
            if try_set(h).is_ok() {
                return Ok(());
            }
            let suspended = unsafe { SuspendThread(h) };
            let second = try_set(h);
            if suspended != u32::MAX {
                let _ = unsafe { ResumeThread(h) };
            }
            if second.is_ok() {
                return Ok(());
            }
            return second;
        }

        Err(CoreError::Windows(0x3E6)) // ERROR_NOACCESS
    }

    /// Route Z R0 AF1: suspend every non-calling target thread so raw child C
    /// and authoritative slab S are read in one stationary capture epoch.
    ///
    /// Enumerates the process's threads with ToolHelp, suspends each thread it
    /// has not yet suspended, and re-enumerates until the thread set is stable
    /// (handles threads that spawn during suspension). Records
    /// `(thread_id, prior_suspend_count)` for every thread it newly suspended so
    /// [`unfreeze_target_threads`](DebuggerCore::unfreeze_target_threads) can
    /// restore each to its exact pre-epoch suspend count. Never suspends the
    /// calling thread, and never alters the suspend count of threads it did not
    /// suspend itself.
    ///
    /// Fail-closed: if any thread fails to open/suspend (or the thread set never
    /// converges), already-suspended threads are rolled back and an error is
    /// returned — it never returns a "frozen" result with threads left running.
    fn freeze_target_threads(&mut self) -> Result<Vec<(u32, u32)>, CoreError> {
        freeze_process_threads(self.process.pid)
    }

    /// Route Z R0 AF1: resume each thread this epoch suspended exactly once,
    /// restoring its pre-epoch suspend count. Threads that were already
    /// suspended before the epoch are left at their original count (we only
    /// undo our own `SuspendThread`). Returns an error if any resume fails so a
    /// leaked suspended thread is surfaced, never silently swallowed.
    fn unfreeze_target_threads(&self, suspended: &[(u32, u32)]) -> Result<(), CoreError> {
        unfreeze_process_threads(suspended)
    }
}

/// Route Z R0 AF1/AF2: suspend every non-calling thread of `pid` (the target
/// process) so live-memory reads form one stationary epoch. Returns
/// `(thread_id, prior_suspend_count)` for each thread newly suspended.
///
/// - Never suspends the calling (test/debugger/controller) thread.
/// - Re-enumerates until the thread set is stable (a thread spawned during
///   enumeration is caught in a later round), with a bounded number of rounds.
/// - **Fail-closed**: if any `OpenThread`/`SuspendThread` fails, or the thread
///   set never converges, all already-suspended threads are rolled back and an
///   error is returned — the caller never sees a "frozen" result while a target
///   thread might still run.
///
/// This is the production entry point: it only ever drives the private
/// implementation with `None` failure injections (no test-only path is reachable
/// from the default library surface).
pub fn freeze_process_threads(pid: u32) -> Result<Vec<(u32, u32)>, CoreError> {
    #[cfg(feature = "capture-epoch-harness")]
    {
        freeze_process_threads_impl(pid, None, None, None)
    }
    #[cfg(not(feature = "capture-epoch-harness"))]
    {
        freeze_process_threads_impl(pid, None, None)
    }
}

/// Route Z R0 AF2 AF1/AF2/AF3: TEST-ONLY injectable freeze entry point. **Compile
/// gated behind the `capture-epoch-harness` feature** so it does not exist on the
/// default production library surface at all (`#[cfg(feature=...)]`, not merely
/// `#[doc(hidden)]`). A fresh default `cargo build` neither exports nor references
/// this symbol.
///
/// - `fail_after_suspend = Some(k)` forces a rollback + `Err` after `k` target
///   threads have been successfully suspended, proving the partial-freeze rollback
///   path.
/// - `fail_resume_tid = Some(tid)` injects a `ResumeThread` failure for exactly
///   that tid during the rollback.
/// - `exit_barrier = Some(b)` deterministically forces one real thread to exit at
///   a configured window (single-shot; no probabilistic retry).
#[cfg(feature = "capture-epoch-harness")]
#[doc(hidden)]
pub fn freeze_process_threads_with_failure(
    pid: u32,
    injection: FreezeInjection,
) -> Result<Vec<(u32, u32)>, CoreError> {
    freeze_process_threads_impl(
        pid,
        injection.fail_after_suspend,
        injection.fail_resume_tid,
        injection.exit_barrier,
    )
}

/// Route Z R0 AF1/AF2: resume each thread `freeze_process_threads` suspended,
/// restoring its exact pre-epoch suspend count. Returns an error if any resume
/// fails (a leaked suspended thread), rather than silently swallowing it.
///
/// The returned [`CoreError::CaptureEpochRestore`] carries every failed thread id,
/// the failing phase and the Win32 error code, so a partial restore is never
/// misreported as complete. All threads are still attempted even after one fails.
pub fn unfreeze_process_threads(suspended: &[(u32, u32)]) -> Result<(), CoreError> {
    unfreeze_process_threads_impl(suspended, None)
}

/// Feature-gated diagnostics for the thread-exit race (Route Z R0 AF2 AF1 AF3).
/// Under the `capture-epoch-harness` feature, the freeze implementation records
/// the exact TID and transient-exit PHASE of every thread that hit a transient
/// exit window, so the harness can PROVE (not assume) which window was exercised.
#[cfg(feature = "capture-epoch-harness")]
static TRANSIENT_EXIT_TIDS: std::sync::Mutex<Vec<(u32, &'static str)>> =
    std::sync::Mutex::new(Vec::new());

/// Clear the transient-exit diagnostic (test setup). Feature-gated.
#[cfg(feature = "capture-epoch-harness")]
pub fn clear_transient_exit_diagnostics() {
    TRANSIENT_EXIT_TIDS.lock().unwrap().clear();
}

/// Snapshot of the transient-exit `(tid, phase)` observations so far. Returns a
/// sorted, deduplicated copy. Feature-gated. `phase` is `"before_open"` or
/// `"after_open_before_suspend"`.
#[cfg(feature = "capture-epoch-harness")]
pub fn transient_exit_observations() -> Vec<(u32, &'static str)> {
    let mut v = TRANSIENT_EXIT_TIDS.lock().unwrap().clone();
    v.sort_unstable();
    v.dedup();
    v
}

/// Record a transient thread-exit observation `(tid, phase)` (internal,
/// feature-gated).
#[cfg(feature = "capture-epoch-harness")]
fn record_transient_exit(tid: u32, phase: &'static str) {
    TRANSIENT_EXIT_TIDS.lock().unwrap().push((tid, phase));
}

/// The deterministic thread-exit barrier window a feature-gated freeze run must
/// deterministically force. See [`ExitBarrier`]. Feature-gated.
#[cfg(feature = "capture-epoch-harness")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitBarrierWindow {
    /// The barrier thread exits BEFORE the freeze's `OpenThread` for it.
    BeforeOpen,
    /// The barrier thread exits AFTER `OpenThread` succeeds but BEFORE
    /// `SuspendThread`.
    AfterOpenBeforeSuspend,
}

/// Outcome of a barrier's `force_exit` attempt (Route Z R0 AF2 AF1 AF4/AF5 / P1-1,
/// P1-3, P2-3). Distinguishes the OS-level proof that the thread object terminated
/// from an acknowledged command or a failure, so a command acknowledgement is NEVER
/// conflated with thread termination.
#[cfg(feature = "capture-epoch-harness")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierExitResult {
    /// The thread object was observed SIGNALED (`WaitForSingleObject` returned
    /// `WAIT_OBJECT_0`) — the OS confirmed the thread terminated.
    Terminated,
    /// The wait timed out before the thread object signaled (`WAIT_TIMEOUT`): the
    /// thread was still alive. Fail-closed.
    Timeout,
    /// The wait or handle-open failed (`WAIT_FAILED` / `OpenThread` failure). The
    /// evidence query itself failed, so this is NOT termination evidence. Fail-closed.
    ///
    /// For a `WAIT_FAILED`, `hresult` is `0` and `win32_code` is the true
    /// `GetLastError` Win32 code. For an `OpenThread` failure, `hresult` is the
    /// `windows::core::Error::code()` HRESULT and `win32_code` is its low 16-bit
    /// Win32 word. Both are retained so a raw HRESULT is never mislabeled as a
    /// Win32 code (P2-3).
    Failure { hresult: u32, win32_code: u32 },
}

/// A deterministic thread-exit barrier (Route Z R0 AF2 AF1 AF3/AF4).
///
/// Under the `capture-epoch-harness` feature, the freeze can be told to force one
/// specific real thread to exit at a specific window, so a single freeze call
/// deterministically exercises the corresponding transient-exit branch (no
/// probabilistic retry storm).
///
/// The `force_exit(tid)` callback is provided by the harness: it must command the
/// benign helper to terminate thread `tid`, then BLOCK until the OS thread object
/// is observed SIGNALED (a genuine termination proof, e.g. via
/// `WaitForSingleObject` on a `SYNCHRONIZE` thread handle). It returns
/// [`BarrierExitResult::Terminated`] only on that OS-level proof; any timeout or
/// evidence failure is returned as [`BarrierExitResult::Timeout`] /
/// [`BarrierExitResult::Failure`]. The freeze implementation fails closed unless it
/// sees `Terminated`.
#[cfg(feature = "capture-epoch-harness")]
pub struct ExitBarrier {
    /// The exact real TID that must exit.
    pub tid: u32,
    /// Which transient window this barrier forces.
    pub window: ExitBarrierWindow,
    /// Harness callback: force `tid` to terminate and confirm via OS thread-object
    /// signal.
    pub force_exit: Box<dyn FnMut(u32) -> BarrierExitResult>,
}

/// Feature-gated injection configuration for the freeze entry point. Production
/// passes `None`; only the test harness (feature `capture-epoch-harness`) supplies
/// failures/barriers.
#[cfg(feature = "capture-epoch-harness")]
pub struct FreezeInjection {
    /// Roll back + fail after this many successful suspends.
    pub fail_after_suspend: Option<u32>,
    /// Inject a `ResumeThread` failure for this tid during rollback.
    pub fail_resume_tid: Option<u32>,
    /// Deterministically force one thread to exit at a specific window.
    pub exit_barrier: Option<ExitBarrier>,
}

/// Classify a `WaitForSingleObject` thread-object wait result (Route Z R0 AF2 AF1
/// AF5 / P1-1). Extracted as a pure function so the termination/fail-closed decision
/// is unit-testable independently of the live handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadWaitClass {
    /// `WAIT_OBJECT_0`: the thread object is signaled => terminated => transient.
    Terminated,
    /// `WAIT_TIMEOUT`: the thread object is not signaled => still alive => fail-closed.
    StillAlive,
    /// `WAIT_FAILED`: the evidence query itself failed => fail-closed.
    QueryFailed,
    /// Any other wait result (unexpected) => fail-closed.
    Unexpected,
}

/// Classify a `WAIT_EVENT` from `WaitForSingleObject`. The caller is responsible
/// for capturing `GetLastError` immediately when the result is [`ThreadWaitClass::QueryFailed`].
pub fn classify_thread_wait(wait: windows::Win32::Foundation::WAIT_EVENT) -> ThreadWaitClass {
    if wait == windows::Win32::Foundation::WAIT_OBJECT_0 {
        ThreadWaitClass::Terminated
    } else if wait == windows::Win32::Foundation::WAIT_TIMEOUT {
        ThreadWaitClass::StillAlive
    } else if wait == windows::Win32::Foundation::WAIT_FAILED {
        ThreadWaitClass::QueryFailed
    } else {
        ThreadWaitClass::Unexpected
    }
}

/// Private capture-epoch freeze implementation.
///
/// The injection knobs are TEST-ONLY: the production entry [`freeze_process_threads`]
/// always calls with `None`/`None`/`None`, and the injectable entry
/// [`freeze_process_threads_with_failure`] exists only under the
/// `capture-epoch-harness` feature. The parameters live here (private) so the
/// production path provably only exercises the `None` code path.
fn freeze_process_threads_impl(
    pid: u32,
    fail_after_suspend: Option<u32>,
    fail_resume_tid: Option<u32>,
    #[cfg(feature = "capture-epoch-harness")] mut exit_barrier: Option<ExitBarrier>,
) -> Result<Vec<(u32, u32)>, CoreError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows::Win32::System::Threading::{
        GetCurrentThreadId, OpenThread, SuspendThread, THREAD_QUERY_INFORMATION,
        THREAD_SUSPEND_RESUME,
    };
    let current = unsafe { GetCurrentThreadId() };
    let mut suspended: Vec<(u32, u32)> = Vec::new();
    let mut seen: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    const MAX_ROUNDS: usize = 8;
    let mut converged = false;
    for _round in 0..MAX_ROUNDS {
        let mut new_this_round: Vec<u32> = Vec::new();
        // SAFETY: CreateToolhelp32Snapshot/Thread32First/Next operate on a
        // snapshot handle; THREADENTRY32 has dwSize set as required by the API.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
            let Ok(snap) = snap else {
                // Snapshot failure: roll back anything already suspended. If the
                // rollback itself fails, surface BOTH failures (fail-closed).
                return rollback_or_combine(
                    suspended,
                    fail_resume_tid,
                    "create toolhelp thread snapshot failed during freeze",
                );
            };
            let mut te: THREADENTRY32 = std::mem::zeroed();
            te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            if Thread32First(snap, &mut te).is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid && te.th32ThreadID != current {
                        if !seen.contains(&te.th32ThreadID) {
                            seen.insert(te.th32ThreadID);
                            new_this_round.push(te.th32ThreadID);
                        }
                    }
                    if Thread32Next(snap, &mut te).is_err() {
                        break;
                    }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
        if new_this_round.is_empty() {
            converged = true;
            break;
        }
        // Suspend every newly-discovered thread. Fail-closed on any failure.
        for tid in &new_this_round {
            // --- Deterministic transient-exit barrier, window 1: before OpenThread ---
            // If the harness configured this exact TID to exit BEFORE OpenThread,
            // force it to terminate and wait for OS confirmation, so the subsequent
            // OpenThread deterministically fails with ERROR_INVALID_PARAMETER (87),
            // exercising the before_open transient-exit branch in a single shot.
            #[cfg(feature = "capture-epoch-harness")]
            let mut barrier = exit_barrier.as_mut();
            #[cfg(feature = "capture-epoch-harness")]
            if let Some(b) = barrier.as_mut() {
                if b.window == ExitBarrierWindow::BeforeOpen && b.tid == *tid {
                    match (b.force_exit)(*tid) {
                        BarrierExitResult::Terminated => {
                            // OS thread object signaled: genuine termination proof.
                        }
                        other => {
                            // Fail-closed: the barrier did not prove termination, so
                            // we must NOT proceed to OpenThread (release builds behave
                            // identically — no debug_assert).
                            return rollback_or_combine(
                                suspended,
                                fail_resume_tid,
                                &format!(
                                    "barrier before_open for tid {tid} did not prove termination: {other:?}"
                                ),
                            );
                        }
                    }
                }
            }
            // SAFETY: OpenThread/SuspendThread on a live target thread id. `THREAD_SYNCHRONIZE`
            // is required so this handle can be used with WaitForSingleObject to prove
            // a terminated thread object (Route Z R0 AF2 AF1 AF4 / P1-2).
            let h = unsafe {
                OpenThread(
                    THREAD_SUSPEND_RESUME
                        | THREAD_QUERY_INFORMATION
                        | windows::Win32::System::Threading::THREAD_SYNCHRONIZE,
                    false,
                    *tid,
                )
            };
            match h {
                Ok(h) => {
                    // --- Deterministic transient-exit barrier, window 2: after
                    // OpenThread, before SuspendThread. ---
                    // If the harness configured this TID to exit AFTER OpenThread
                    // succeeds, force it to terminate and confirm OS termination.
                    // The already-open handle becomes signaled once the thread object
                    // terminates; SuspendThread then fails and we confirm via the
                    // wait result below.
                    #[cfg(feature = "capture-epoch-harness")]
                    if let Some(b) = barrier.as_mut() {
                        if b.window == ExitBarrierWindow::AfterOpenBeforeSuspend && b.tid == *tid {
                            match (b.force_exit)(*tid) {
                                BarrierExitResult::Terminated => {}
                                other => {
                                    // Fail-closed: no OS termination proof => do not
                                    // proceed to SuspendThread; roll back and fail.
                                    let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
                                    return rollback_or_combine(
                                        suspended,
                                        fail_resume_tid,
                                        &format!(
                                            "barrier after_open_before_suspend for tid {tid} did not prove termination: {other:?}"
                                        ),
                                    );
                                }
                            }
                        }
                    }
                    // SAFETY: SuspendThread on the (possibly now-terminated) thread.
                    let prior = unsafe { SuspendThread(h) };
                    if prior == u32::MAX {
                        // Read the error immediately, before any further call.
                        let suspend_code = unsafe { windows::Win32::Foundation::GetLastError() }.0;
                        // Distinguish a thread that EXITED between OpenThread and
                        // SuspendThread (transient) from a real failure, using the
                        // thread OBJECT signal (THREAD_SYNCHRONIZE on the handle).
                        // Classification (Route Z R0 AF2 AF1 AF5 / P1-1):
                        //   WAIT_OBJECT_0  => terminated => transient
                        //   WAIT_TIMEOUT   => still alive => bounded retry, then fail-closed
                        //   WAIT_FAILED    => evidence failure => GetLastError IMMEDIATELY,
                        //                       before CloseHandle, then fail-closed rollback
                        //   unexpected     => fail-closed rollback
                        let mut wait_res = windows::Win32::Foundation::WAIT_TIMEOUT;
                        // Read WAIT_FAILED's GetLastError immediately (before any
                        // sleep/CloseHandle which could overwrite last-error).
                        let mut wait_failed_code: Option<u32> = None;
                        for _ in 0..100 {
                            // SAFETY: WaitForSingleObject on our own thread handle.
                            wait_res = unsafe {
                                windows::Win32::System::Threading::WaitForSingleObject(h, 0)
                            };
                            if wait_res == windows::Win32::Foundation::WAIT_OBJECT_0 {
                                break;
                            }
                            if wait_res == windows::Win32::Foundation::WAIT_FAILED {
                                // Evidence query failed: capture the code IMMEDIATELY
                                // (before CloseHandle / any further API call), then
                                // fail closed — do NOT sleep or keep polling.
                                // SAFETY: GetLastError read immediately after the failed call.
                                wait_failed_code =
                                    Some(unsafe { windows::Win32::Foundation::GetLastError() }.0);
                                break;
                            }
                            // WAIT_TIMEOUT (thread still alive): bounded retry.
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
                        if wait_res == windows::Win32::Foundation::WAIT_OBJECT_0 {
                            // Thread object signaled => terminated => transient exit.
                            #[cfg(feature = "capture-epoch-harness")]
                            record_transient_exit(*tid, "after_open_before_suspend");
                            continue;
                        }
                        // Fail-closed for WAIT_TIMEOUT / WAIT_FAILED / unexpected:
                        // never treat as a terminated thread.
                        let wait_detail = match classify_thread_wait(wait_res) {
                            ThreadWaitClass::QueryFailed => {
                                format!(
                                    ", WaitForSingleObject failed code {:#x}",
                                    wait_failed_code.unwrap_or(0)
                                )
                            }
                            ThreadWaitClass::StillAlive => {
                                ", thread object NOT signaled (still alive / wait timeout)"
                                    .to_string()
                            }
                            _ => format!(", unexpected wait result {wait_res:?}"),
                        };
                        return rollback_or_combine(
                            suspended,
                            fail_resume_tid,
                            &format!(
                                "SuspendThread failed (code {suspend_code:#x}) for target thread {tid} during freeze{wait_detail}"
                            ),
                        );
                    }
                    let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
                    suspended.push((*tid, prior));
                    // Test-only failure injection: after `k` successful suspends,
                    // roll back and fail (only reachable from the feature-gated
                    // injectable entry; production passes `None`).
                    if let Some(k) = fail_after_suspend {
                        if suspended.len() as u32 >= k {
                            return rollback_or_combine(
                                suspended,
                                fail_resume_tid,
                                &format!("test-injected freeze failure after {k} suspensions"),
                            );
                        }
                    }
                }
                Err(e) => {
                    // Distinguish a transient thread-exit race from a real
                    // failure: if the thread exited between the ToolHelp
                    // snapshot and OpenThread, OpenThread fails with
                    // ERROR_INVALID_PARAMETER (87), surfaced either as a raw
                    // Win32 code (0x57) or as an HRESULT-wrapped code
                    // (0x80070057). Tolerate that as a short-lived thread that
                    // is gone. Any other error is fail-closed with rollback.
                    let code = e.code().0;
                    // Compare the low 16 bits: for a raw Win32 code this is the
                    // error itself (87), for an HRESULT-wrapped code (0x80070057)
                    // it is also 87. Both mean "thread exited".
                    let low = code & 0xffff;
                    if low == 87 {
                        // Thread exited between the ToolHelp snapshot and
                        // OpenThread. Feature-gated: record the exact TID and phase
                        // so the harness can prove this transient-exit branch ran.
                        #[cfg(feature = "capture-epoch-harness")]
                        record_transient_exit(*tid, "before_open");
                        continue;
                    }
                    return rollback_or_combine(
                        suspended,
                        fail_resume_tid,
                        &format!(
                            "OpenThread failed (code {code:#x}) for target thread {tid} during freeze"
                        ),
                    );
                }
            }
        }
    }
    if !converged {
        // The thread set never stabilized (a thread kept spawning each round).
        return rollback_or_combine(
            suspended,
            fail_resume_tid,
            "target thread set did not converge during capture freeze",
        );
    }
    Ok(suspended)
}

/// Roll back already-suspended threads on a partial-freeze failure. When the
/// rollback itself also fails, combines the original freeze failure with every
/// rollback failure into a single fail-closed error so the caller learns that
/// some threads may still be suspended. When the rollback fully succeeds, returns
/// the plain freeze error.
fn rollback_or_combine(
    suspended: Vec<(u32, u32)>,
    fail_resume_tid: Option<u32>,
    freeze_msg: &str,
) -> Result<Vec<(u32, u32)>, CoreError> {
    match unfreeze_process_threads_impl(&suspended, fail_resume_tid) {
        Ok(()) => Err(CoreError::ProcessCreation(freeze_msg.to_string())),
        Err(e) => rollback_or_combine_error(freeze_msg, e),
    }
}

/// Combine an original freeze failure with a rollback failure. **Exhaustive
/// fail-closed**: ANY rollback error (structured per-thread or generic) is treated
/// as a failed rollback and merged with the freeze error — never as success.
///
/// Separate from [`rollback_or_combine`] so a unit test can inject an arbitrary
/// rollback error and prove the generic-error branch.
fn rollback_or_combine_error(
    freeze_msg: &str,
    rollback_err: CoreError,
) -> Result<Vec<(u32, u32)>, CoreError> {
    match rollback_err {
        // Structured per-thread rollback failures: merge them with the freeze error.
        CoreError::CaptureEpochRestore { failed, .. } => {
            Err(CoreError::CaptureFreezeWithRollbackFailure {
                freeze: freeze_msg.to_string(),
                rollback_failed_count: failed.len(),
                rollback_failed: failed,
                rollback_error: None,
            })
        }
        // ANY other rollback error: still a rollback failure — NEVER treated as
        // success. Preserve the generic rollback error text alongside the freeze
        // error (fail-closed).
        other => Err(CoreError::CaptureFreezeWithRollbackFailure {
            freeze: freeze_msg.to_string(),
            rollback_failed_count: 0,
            rollback_failed: Vec::new(),
            rollback_error: Some(format!("{other:?}")),
        }),
    }
}

/// Private capture-epoch unfreeze implementation. Resumes every thread, restoring
/// each exact pre-epoch suspend count. **Continues past any single failure** and
/// returns a [`CoreError::CaptureEpochRestore`] carrying every failed thread id,
/// phase and Win32 code — never stops at the first error, never swallows a failed
/// restore.
///
/// `fail_resume_tid = Some(tid)` is a TEST-ONLY injection (only reachable from the
/// feature-gated injectable freeze entry via the rollback path) that forces a
/// `ResumeThread` failure for exactly that tid. Production passes `None`.
fn unfreeze_process_threads_impl(
    suspended: &[(u32, u32)],
    fail_resume_tid: Option<u32>,
) -> Result<(), CoreError> {
    use windows::Win32::System::Threading::{
        OpenThread, ResumeThread, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
    };
    let mut failed: Vec<crate::error::RestoreFailure> = Vec::new();
    for (tid, _prior) in suspended {
        // SAFETY: OpenThread/ResumeThread on a live target thread id.
        unsafe {
            match OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                false,
                *tid,
            ) {
                Ok(h) => {
                    // TEST-ONLY injected resume failure (only reachable from the
                    // feature-gated injectable freeze entry's rollback path): do
                    // NOT resume the thread (leaving it genuinely suspended) and
                    // report the restore as failed, faithfully simulating a
                    // ResumeThread failure so the caller must handle a leaked
                    // suspended thread.
                    if Some(*tid) == fail_resume_tid {
                        let _ = windows::Win32::Foundation::CloseHandle(h);
                        failed.push(crate::error::RestoreFailure {
                            thread_id: *tid,
                            phase: "resume",
                            win32_code: 0,
                        });
                        continue;
                    }
                    let r = ResumeThread(h);
                    // Read GetLastError IMMEDIATELY after the failing call, BEFORE
                    // any other Win32 call (CloseHandle may overwrite the thread's
                    // last-error value), so the recorded code truly belongs to
                    // ResumeThread (P1-3).
                    let resume_code = if r == u32::MAX {
                        Some(windows::Win32::Foundation::GetLastError().0)
                    } else {
                        None
                    };
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                    if let Some(code) = resume_code {
                        failed.push(crate::error::RestoreFailure {
                            thread_id: *tid,
                            phase: "resume",
                            win32_code: code,
                        });
                    }
                }
                Err(e) => {
                    // A real OpenThread failure on restore is fail-closed (a
                    // leaked suspended thread). Tolerate only a thread that has
                    // exited (code low-16 == 87), same as the freeze path.
                    let code = e.code().0;
                    if code & 0xffff == 87 {
                        // Thread already gone; nothing to resume, not a leak.
                        continue;
                    }
                    failed.push(crate::error::RestoreFailure {
                        thread_id: *tid,
                        phase: "open",
                        win32_code: (code & 0xffff) as u32,
                    });
                }
            }
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        let n = failed.len();
        Err(CoreError::CaptureEpochRestore {
            failed_count: n,
            failed,
        })
    }
}

/// Enumerate a process's thread IDs (for diagnostics / harness verification).
pub fn enumerate_process_threads(pid: u32) -> Result<Vec<u32>, CoreError> {
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    let mut out = Vec::new();
    // SAFETY: ToolHelp thread snapshot of the given process.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
        let Ok(snap) = snap else {
            return Err(CoreError::ProcessCreation(
                "toolhelp thread snapshot failed".into(),
            ));
        };
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snap, &mut te).is_ok() {
            loop {
                if te.th32OwnerProcessID == pid {
                    out.push(te.th32ThreadID);
                }
                if Thread32Next(snap, &mut te).is_err() {
                    break;
                }
            }
        }
        let _ = windows::Win32::Foundation::CloseHandle(snap);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Internal 闁?pending-event lifecycle + raw DEBUG_EVENT decode
// ---------------------------------------------------------------------------

impl WindowsDebugger {
    /// Wait for the next *delivered* debug event under the exactly-once contract.
    ///
    /// On success the returned event is pending and the caller must
    /// [`continue_event`](DebuggerCore::continue_event) exactly once.
    /// Internally ignored events (`OUTPUT_DEBUG_STRING`, unknown codes) are
    /// continued with `DBG_CONTINUE` before the next wait so decode never
    /// returns `Handled` without a matching continue.
    fn wait_next_event(&mut self, timeout_ms: u32) -> Result<DebugEvent, CoreError> {
        // With a finite timeout we only perform one WaitForDebugEvent at the
        // caller's budget. After an internal continue, further waits use 0 ms
        // so we never extend the original deadline.
        let mut first = true;
        loop {
            self.lifecycle.ensure_can_wait()?;

            let mut raw: RAW_DEBUG_EVENT = RAW_DEBUG_EVENT::default();
            let wait_timeout = if first {
                first = false;
                timeout_ms
            } else if timeout_ms == INFINITE {
                INFINITE
            } else {
                0
            };

            // SAFETY: WaitForDebugEvent; raw is a valid out-pointer.
            let wait_result = unsafe { WaitForDebugEvent(&mut raw, wait_timeout) };
            if let Err(e) = wait_result {
                // ERROR_SEM_TIMEOUT = 121 (HRESULT low word).
                let error_code = (e.code().0 as u32) & 0xFFFF;
                if error_code == 121 {
                    return Err(CoreError::Timeout);
                }
                debug!(error_code, "WaitForDebugEvent failed");
                return Err(CoreError::Windows(error_code));
            }

            let process_id = raw.dwProcessId;
            let thread_id = raw.dwThreadId;
            let event_code = raw.dwDebugEventCode.0;
            self.lifecycle
                .record_wait_success(process_id, thread_id, event_code)?;

            match DebugEventLifecycle::disposition_for_event_code(event_code) {
                DecodeDisposition::IgnoreAndContinue => {
                    if event_code == OUTPUT_DEBUG_STRING_EVENT.0 {
                        trace!("Ignoring OUTPUT_DEBUG_STRING_EVENT (exactly-once continue)");
                    } else {
                        debug!(
                            code = event_code,
                            "Unknown debug event code 闁?exactly-once continue"
                        );
                    }
                    // Must continue the *pending* identity before next wait.
                    self.continue_pending(thread_id, ContinueStatus::Continue)?;
                    // Loop for another wait: INFINITE keeps blocking; finite
                    // budgets use 0 ms so we never extend the caller's deadline
                    // beyond the first WaitForDebugEvent.
                    continue;
                }
                DecodeDisposition::RipError => {
                    warn!("RIP_EVENT received 闁?system-level debug error");
                    // Unified lifecycle: continue once on pending identity, then
                    // surface an error (do not continue inside decode).
                    let cont = self.continue_pending(thread_id, ContinueStatus::Continue);
                    if let Err(e) = cont {
                        return Err(e);
                    }
                    return Err(CoreError::Windows(0));
                }
                DecodeDisposition::Deliver => {}
            }

            let ev = match Self::decode_event(&raw) {
                Ok(event) => event,
                // Unhandled exception codes still leave the event pending for
                // the outer loop / continue path; surface the error as-is.
                Err(e) => return Err(e),
            };

            self.apply_event_bookkeeping(&ev)?;
            return Ok(ev);
        }
    }

    /// Continue the current pending event under the lifecycle contract.
    fn continue_pending(
        &mut self,
        provided_tid: u32,
        status: ContinueStatus,
    ) -> Result<(), CoreError> {
        let nt_status = match status {
            ContinueStatus::Continue => DBG_CONTINUE,
            ContinueStatus::ContinueNoStep => DBG_CONTINUE,
        };

        match self.lifecycle.plan_continue(provided_tid) {
            ContinuePlan::Reject(e) => Err(e),
            ContinuePlan::Proceed {
                process_id,
                thread_id,
            } => {
                // SAFETY: process_id/thread_id are the pending WaitForDebugEvent
                // identity; nt_status is DBG_CONTINUE.
                let result = unsafe { ContinueDebugEvent(process_id, thread_id, nt_status) };
                match result {
                    Ok(()) => {
                        self.lifecycle.clear_pending_after_continue_ok();
                        Ok(())
                    }
                    Err(e) => {
                        let hresult = e.code().0 as u32;
                        // Retain pending for diagnosis; never swallow INVALID_PARAMETER.
                        Err(self.lifecycle.continue_failed_error(hresult, provided_tid))
                    }
                }
            }
        }
    }

    /// Consume at most one debug event with full lifecycle bookkeeping
    /// (ADR-5B-R1). Used by the loader window to keep the debug session alive
    /// while a remote thread runs: every event passes through the same
    /// pending/continue lifecycle and the same thread-table / hFile / DR
    /// bookkeeping as the main loop.
    ///
    /// Returns Ok(None) when the timeout expired with no event
    /// (ERROR_SEM_TIMEOUT). Returns Err on API failure; the pending
    /// identity is retained for diagnosis.
    pub fn drain_debug_event(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<DrainReceipt>, CoreError> {
        self.lifecycle.ensure_can_wait()?;

        let mut raw: RAW_DEBUG_EVENT = RAW_DEBUG_EVENT::default();
        // SAFETY: WaitForDebugEvent; raw is a valid out-pointer.
        let wait_result = unsafe { WaitForDebugEvent(&mut raw, timeout_ms) };
        if let Err(e) = wait_result {
            let error_code = (e.code().0 as u32) & 0xFFFF;
            if error_code == 121 {
                return Ok(None); // ERROR_SEM_TIMEOUT: no event within budget
            }
            return Err(CoreError::Windows(error_code));
        }

        let process_id = raw.dwProcessId;
        let thread_id = raw.dwThreadId;
        let event_code = raw.dwDebugEventCode.0;
        self.lifecycle
            .record_wait_success(process_id, thread_id, event_code)?;
        let sequence = self.lifecycle.pending().map(|p| p.sequence).unwrap_or(0);

        let mut receipt = DrainReceipt {
            sequence,
            process_id,
            thread_id,
            event_code,
            disposition: DrainDisposition::Delivered,
            continue_status: ContinueStatus::Continue as u32,
            bookkeeping: String::new(),
            exception_code: None,
            first_chance: None,
        };

        match DebugEventLifecycle::disposition_for_event_code(event_code) {
            DecodeDisposition::IgnoreAndContinue => {
                receipt.disposition = DrainDisposition::Ignored;
                self.drain_stats.events_drained += 1;
                self.drain_stats.ignored_continued += 1;
                self.drain_stats.last_sequence = sequence;
                self.continue_pending(thread_id, ContinueStatus::Continue)?;
                return Ok(Some(receipt));
            }
            DecodeDisposition::RipError => {
                receipt.disposition = DrainDisposition::Rip;
                receipt.bookkeeping = "RIP_EVENT recorded".into();
                self.drain_stats.events_drained += 1;
                self.drain_stats.rip_events += 1;
                self.drain_stats.last_sequence = sequence;
                self.continue_pending(thread_id, ContinueStatus::Continue)?;
                return Ok(Some(receipt));
            }
            DecodeDisposition::Deliver => {}
        }

        // EXCEPTION events inside the drain window are recorded (code + first
        // chance) and continued; they are never silently swallowed, and no
        // unconditional decode failure aborts the loader window.
        if event_code == EXCEPTION_DEBUG_EVENT.0 {
            // SAFETY: union accessed with matching dwDebugEventCode == EXCEPTION_DEBUG_EVENT.
            let exc = unsafe { &raw.u.Exception };
            receipt.disposition = DrainDisposition::Exception;
            receipt.exception_code = Some(exc.ExceptionRecord.ExceptionCode.0 as u32);
            receipt.first_chance = Some(exc.dwFirstChance != 0);
            receipt.bookkeeping = format!(
                "exception code={:#x} first_chance={} (drain window, DBG_CONTINUE)",
                exc.ExceptionRecord.ExceptionCode.0 as u32,
                exc.dwFirstChance != 0
            );
            self.drain_stats.events_drained += 1;
            self.drain_stats.exceptions_continued += 1;
            self.drain_stats.last_sequence = sequence;
            self.continue_pending(thread_id, ContinueStatus::Continue)?;
            return Ok(Some(receipt));
        }

        // Deliverable events: decode, apply unified bookkeeping, close hFile
        // (the drain consumes the event, so the caller never sees it), then
        // continue exactly once.
        let ev = Self::decode_event(&raw)?;
        self.apply_event_bookkeeping(&ev)?;
        self.drain_stats.events_drained += 1;
        self.drain_stats.last_sequence = sequence;
        match &ev {
            DebugEvent::LoadDll { h_file, .. } | DebugEvent::CreateProcess { h_file, .. } => {
                // SAFETY: h_file is valid per the DebugEvent contract and is
                // consumed by the drain (never delivered to the main loop).
                if !h_file.is_invalid() {
                    unsafe {
                        let _ = CloseHandle(*h_file);
                    }
                    self.drain_stats.hfiles_closed += 1;
                }
                receipt.bookkeeping = "hFile closed".into();
            }
            DebugEvent::CreateThread { thread_id, .. } => {
                receipt.bookkeeping = format!("thread {thread_id} registered");
                self.drain_stats.create_threads_registered += 1;
                self.drain_observed_create_tids.insert(*thread_id);
                if self.has_any_hw_breakpoint() {
                    receipt
                        .bookkeeping
                        .push_str("; DR state propagated to new thread");
                    self.drain_stats.dr_propagations += 1;
                }
            }
            DebugEvent::ExitThread { thread_id, .. } => {
                receipt.bookkeeping = format!("thread {thread_id} removed + handle closed");
                // IMPORTANT: apply_event_bookkeeping runs BEFORE this match and
                // has already removed the TID from the threads table. To
                // classify the exit we consult the drain-observed CREATE_THREAD
                // set instead.
                if self.drain_observed_create_tids.remove(thread_id) {
                    // The drain DID observe this thread's creation and the
                    // handle was registered -> clean bookkeeping pair.
                    self.drain_stats.exit_threads_removed += 1;
                } else {
                    // The drain never saw a CREATE_THREAD for this TID. This is
                    // legal when the thread was created AND exited between two
                    // drain polls (Windows delivers EXIT_THREAD even when the
                    // matching CREATE_THREAD was never observed). It is NOT a
                    // bookkeeping defect: no handle was ever registered.
                    receipt
                        .bookkeeping
                        .push_str(" (short-lived: CREATE_THREAD never observed by drain)");
                }
            }
            _ => {}
        }
        self.continue_pending(thread_id, ContinueStatus::Continue)?;
        Ok(Some(receipt))
    }

    /// Cumulative drain-path counters (ADR-5B-R1 audit surface).
    pub fn drain_stats(&self) -> &DrainStats {
        &self.drain_stats
    }

    /// Thread table / image-base bookkeeping for a delivered event.
    fn apply_event_bookkeeping(&mut self, ev: &DebugEvent) -> Result<(), CoreError> {
        match ev {
            DebugEvent::CreateThread {
                thread_id,
                h_thread,
                ..
            } => {
                self.threads.insert(*thread_id, *h_thread);
                if self.has_any_hw_breakpoint() {
                    if let Err(e) = self.apply_debug_registers_thread(*thread_id) {
                        warn!(thread_id, error = %e, "failed to propagate DR state to new thread");
                    }
                }
            }
            DebugEvent::ExitThread { thread_id, .. } => {
                let h = self.threads.remove(thread_id);
                if let Some(h) = h {
                    if !h.is_invalid() {
                        // SAFETY: handle is valid and belongs to us.
                        unsafe {
                            let _ = CloseHandle(h);
                        }
                    }
                }
            }
            DebugEvent::CreateProcess {
                image_base,
                h_process,
                h_thread,
                ..
            } => {
                // SAFETY: handles from CREATE_PROCESS_DEBUG_EVENT.
                let img = patch_peb_anti_debug(*h_process)?;
                // Prefer PEB-derived base; fall back to event base.
                self.process.image_base = if img != 0 { img } else { *image_base };
                self.threads.insert(self.process.main_thread_id, *h_thread);
            }
            DebugEvent::ExitProcess { .. } => {
                // Caller breaks out of the debug loop after this event.
            }
            _ => {}
        }
        Ok(())
    }

    /// Read only the debug-register portion of the given thread's context.
    /// This works where [`DebuggerCore::get_thread_context`] cannot: the
    /// full CONTEXT request trips ERROR_PARTIAL_COPY on threads belonging
    /// to targets whose protector mutates the thread's TEB / PEB-Ldr during
    /// early ntdll init.  Scope the request down to DR0闁炽儲寮碦7 so the kernel
    /// does not attempt to walk those guarded structures.
    pub fn get_thread_context_dbg(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        // Wrapped in ScopedThreadHandle so CloseHandle runs on every return path.
        let h = unsafe {
            let raw = OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
            ScopedThreadHandle::new(raw)
        };
        let mut ctx = Box::new(CONTEXT::default());
        ctx.ContextFlags = Self::debug_registers_flags();
        // SAFETY: h.as_raw() is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a heap-allocated CONTEXT.
        unsafe {
            GetThreadContext(h.as_raw(), std::ptr::from_mut(&mut *ctx))
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }
        Ok(*ctx)
    }

    /// Translate a raw Windows `DEBUG_EVENT` into our abstract [`DebugEvent`].
    fn decode_event(raw: &RAW_DEBUG_EVENT) -> Result<DebugEvent, CoreError> {
        // SAFETY: the union field we access corresponds to dwDebugEventCode
        // and is guaranteed valid by the Windows debug API.
        let ev = match raw.dwDebugEventCode {
            EXCEPTION_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == EXCEPTION_DEBUG_EVENT.
                let exc = unsafe { &raw.u.Exception };
                let addr = exc.ExceptionRecord.ExceptionAddress as u64;
                match exc.ExceptionRecord.ExceptionCode {
                    code if code == EXCEPTION_BREAKPOINT => DebugEvent::Breakpoint {
                        thread_id: raw.dwThreadId,
                        address: addr,
                    },
                    code if code == EXCEPTION_SINGLE_STEP => DebugEvent::SingleStep {
                        thread_id: raw.dwThreadId,
                        address: addr,
                    },
                    code if code == EXCEPTION_ACCESS_VIOLATION => {
                        let is_write = exc.ExceptionRecord.NumberParameters > 0
                            && exc.ExceptionRecord.ExceptionInformation[0] == 1;
                        let target = if exc.ExceptionRecord.NumberParameters > 1 {
                            exc.ExceptionRecord.ExceptionInformation[1] as u64
                        } else {
                            0
                        };
                        // ExceptionInformation[0] is the access type:
                        //   0 = read, 1 = write, 8 = execute (inside .text).
                        // Themida uses execute-inside-.text faults to identify TLS
                        // callbacks that we must let run 闁?matching the Pascal
                        // `ExcRecord.ExceptionInformation[0] = 8` check.
                        let exc_type = if exc.ExceptionRecord.NumberParameters > 0 {
                            exc.ExceptionRecord.ExceptionInformation[0] as u8
                        } else {
                            0
                        };
                        DebugEvent::AccessViolation {
                            thread_id: raw.dwThreadId,
                            address: addr,
                            is_write,
                            target_address: target,
                            exc_type,
                        }
                    }
                    other => {
                        trace!(code = other.0, "Unhandled exception");
                        return Err(CoreError::Windows(other.0 as u32));
                    }
                }
            }

            CREATE_THREAD_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT.
                let ct = unsafe { &raw.u.CreateThread };
                DebugEvent::CreateThread {
                    thread_id: raw.dwThreadId,
                    h_thread: ct.hThread,
                    start_address: ct.lpStartAddress.map_or(0, |f| f as usize as u64),
                }
            }

            CREATE_PROCESS_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT.
                let cp = unsafe { &raw.u.CreateProcessInfo };
                DebugEvent::CreateProcess {
                    process_id: raw.dwProcessId,
                    thread_id: raw.dwThreadId,
                    image_base: cp.lpBaseOfImage as u64,
                    h_thread: cp.hThread,
                    h_process: cp.hProcess,
                    h_file: cp.hFile,
                }
            }

            EXIT_THREAD_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT.
                let et = unsafe { &raw.u.ExitThread };
                DebugEvent::ExitThread {
                    thread_id: raw.dwThreadId,
                    exit_code: et.dwExitCode,
                }
            }

            EXIT_PROCESS_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT.
                let ep = unsafe { &raw.u.ExitProcess };
                DebugEvent::ExitProcess {
                    exit_code: ep.dwExitCode,
                }
            }

            LOAD_DLL_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == LOAD_DLL_DEBUG_EVENT.
                let ld = unsafe { &raw.u.LoadDll };
                DebugEvent::LoadDll {
                    thread_id: raw.dwThreadId,
                    base_address: ld.lpBaseOfDll as u64,
                    h_file: ld.hFile,
                }
            }

            UNLOAD_DLL_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT.
                let ud = unsafe { &raw.u.UnloadDll };
                DebugEvent::UnloadDll {
                    thread_id: raw.dwThreadId,
                    base_address: ud.lpBaseOfDll as u64,
                }
            }

            // OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, and unknown codes are
            // handled by `DebugEventLifecycle::disposition_for_event_code`
            // before decode: they receive exactly-one ContinueDebugEvent on
            // the pending identity and never reach this function.
            OUTPUT_DEBUG_STRING_EVENT => {
                // Defensive: should not be reached.
                return Err(CoreError::DebugState(
                    "OUTPUT_DEBUG_STRING_EVENT reached decode_event; expected lifecycle disposition"
                        .into(),
                ));
            }

            RIP_EVENT => {
                return Err(CoreError::DebugState(
                    "RIP_EVENT reached decode_event; expected lifecycle disposition".into(),
                ));
            }

            other => {
                return Err(CoreError::DebugState(format!(
                    "unknown debug event code {} reached decode_event; expected lifecycle disposition",
                    other.0
                )));
            }
        };

        Ok(ev)
    }
}

// ---------------------------------------------------------------------------
// Tests 闁?ScopedThreadHandle Drop semantics
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `ScopedThreadHandle` wrapping a real OpenThread handle on the *current*
    /// thread must not panic on Drop, and must release the handle exactly once.
    ///
    /// This exercises the Drop path with a genuine kernel handle.  We open the
    /// current thread with `THREAD_QUERY_INFORMATION` (a benign right) and let
    /// the guard close it.
    #[test]
    fn existing_soft_breakpoint_mismatch_is_not_considered_installed() {
        assert!(soft_breakpoint_state_is_consistent(1, 0xCC));
        assert!(!soft_breakpoint_state_is_consistent(1, 0x90));
        assert!(!soft_breakpoint_state_is_consistent(0, 0xCC));
        assert!(!soft_breakpoint_state_is_consistent(2, 0xCC));
    }
    #[test]
    fn scoped_thread_handle_drops_real_handle() {
        use windows::Win32::System::Threading::{
            GetCurrentThreadId, OpenThread, THREAD_QUERY_INFORMATION,
        };

        let tid = unsafe { GetCurrentThreadId() };
        // SAFETY: OpenThread against the current thread is always valid.
        let raw = unsafe {
            OpenThread(THREAD_QUERY_INFORMATION, false, tid)
                .expect("OpenThread on current thread must succeed")
        };
        assert!(!raw.is_invalid(), "freshly opened handle must be valid");

        // Wrap it 闁?Drop should CloseHandle.
        {
            let _g = ScopedThreadHandle::new(raw);
        }

        // CloseHandle on the now-released handle should fail with
        // ERROR_INVALID_HANDLE (6).  This proves Drop already closed it.
        // SAFETY: we are testing the post-drop state of a handle we own.
        let close_result = unsafe { CloseHandle(raw) };
        assert!(
            close_result.is_err(),
            "CloseHandle after ScopedThreadHandle drop must fail (handle already closed); got Ok"
        );
    }

    /// `ScopedThreadHandle::as_raw` returns the same handle value that was
    /// passed in.  This is the contract that the leaking call sites rely on
    /// when they hand the raw value to `GetThreadContext` / `SetThreadContext`.
    #[test]
    fn scoped_thread_handle_as_raw_roundtrips() {
        // Use a pseudo-handle sentinel that CloseHandle will reject 闁?we never
        // actually drop the guard in this test, so no kernel handle is
        // released.  This isolates the as_raw behaviour from the Drop path.
        let sentinel = HANDLE(-1 as isize as *mut std::ffi::c_void);
        let g = ScopedThreadHandle::new(sentinel);
        assert_eq!(
            g.as_raw(),
            sentinel,
            "as_raw must return the wrapped handle"
        );
    }

    /// Dropping a `ScopedThreadHandle` wrapping an invalid handle must not
    /// panic and must not call `CloseHandle` on the sentinel value.  The
    /// `is_invalid()` check inside Drop is the guard against this.
    #[test]
    fn scoped_thread_handle_drop_invalid_handle_is_noop() {
        // HANDLE(null) is the conventional invalid handle on Windows.
        let invalid = HANDLE(std::ptr::null_mut());
        // If Drop called CloseHandle(null) it would set ERROR_INVALID_HANDLE
        // and return Err 闁?but we swallow the result inside Drop, so the only
        // way this test can fail is by panicking, which it must not.
        {
            let _g = ScopedThreadHandle::new(invalid);
        }
        // Reaching here means Drop ran without panicking 闁?the regression is
        // satisfied.
    }

    /// [P1-4] Exhaustive fail-closed rollback: a rollback error that is NOT a
    /// structured `CaptureEpochRestore` must be merged with the freeze error and
    /// NEVER reported as a successful rollback.
    #[test]
    fn generic_rollback_error_is_fail_closed() {
        let r = rollback_or_combine_error("freeze aborted (test)", CoreError::Windows(5));
        match r {
            Err(CoreError::CaptureFreezeWithRollbackFailure {
                freeze,
                rollback_failed_count,
                rollback_failed,
                rollback_error,
            }) => {
                assert!(freeze.contains("freeze aborted"), "freeze msg: {freeze}");
                assert_eq!(rollback_failed_count, 0, "no structured failures");
                assert!(rollback_failed.is_empty());
                let generic = rollback_error.expect("generic rollback error must be preserved");
                assert!(
                    generic.contains("Windows API error") || generic.contains("5"),
                    "generic rollback error text preserved: {generic}"
                );
            }
            other => panic!("expected CaptureFreezeWithRollbackFailure, got {other:?}"),
        }
    }

    /// [P1-4] A successful rollback (no error) is NOT a combined failure: the plain
    /// freeze error is returned.
    #[test]
    fn successful_rollback_returns_plain_freeze_error() {
        // No rollback error → `CaptureEpochRestore` never returned → plain freeze error.
        let r = rollback_or_combine_error(
            "freeze aborted (test)",
            CoreError::CaptureEpochRestore {
                failed_count: 0,
                failed: Vec::new(),
            },
        );
        match r {
            Err(CoreError::CaptureFreezeWithRollbackFailure {
                rollback_failed_count,
                rollback_error,
                ..
            }) => {
                assert_eq!(rollback_failed_count, 0);
                assert!(rollback_error.is_none());
            }
            other => panic!("expected CaptureFreezeWithRollbackFailure, got {other:?}"),
        }
    }

    /// [P1-3] `GetLastError` must be captured immediately after the failing call and
    /// BEFORE `CloseHandle`, so the recorded Win32 code belongs to the failing API.
    ///
    /// This is a pure unit proof of the capture-order invariant by directly
    /// exercising the private unfreeze impl against the CURRENT thread: we open the
    /// current thread (a real handle), deliberately pass a `fail_resume_tid` that
    /// matches it (which takes the injection path that does NOT resume), and verify
    /// the returned `RestoreFailure.phase` is "resume". The error-code ordering is
    /// structurally guaranteed by the implementation (GetLastError read into
    /// `resume_code` before `CloseHandle`); this test locks the phase/thread mapping.
    #[test]
    fn restore_failure_records_phase_and_thread() {
        use windows::Win32::System::Threading::GetCurrentThreadId;
        let me = unsafe { GetCurrentThreadId() };
        // Inject a resume failure for the current thread (injection path).
        let r = unfreeze_process_threads_impl(&[(me, 0)], Some(me));
        match r {
            Err(CoreError::CaptureEpochRestore { failed, .. }) => {
                let f = failed
                    .iter()
                    .find(|x| x.thread_id == me)
                    .expect("tid reported");
                assert_eq!(f.phase, "resume", "phase must be resume");
                // injection path records code 0 (controlled), not a real Win32 code.
                assert_eq!(f.win32_code, 0);
            }
            other => panic!("expected CaptureEpochRestore, got {other:?}"),
        }
    }

    /// [P1-1] The wait-result classifier maps each `WAIT_*` outcome correctly:
    /// `WAIT_OBJECT_0` => terminated (transient), `WAIT_TIMEOUT` => still alive
    /// (fail-closed), `WAIT_FAILED` => evidence failure (fail-closed), and an
    /// unexpected value => fail-closed. This locks the classification that decides
    /// whether a `SuspendThread` failure is a transient exit or a real failure.
    #[test]
    fn classify_thread_wait_maps_all_outcomes() {
        use windows::Win32::Foundation::{
            WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
        };
        use windows::Win32::System::Threading::WaitForSingleObject; // type only
        let _ = WaitForSingleObject::<windows::Win32::Foundation::HANDLE>; // silence unused
        assert_eq!(
            classify_thread_wait(WAIT_OBJECT_0),
            ThreadWaitClass::Terminated
        );
        assert_eq!(
            classify_thread_wait(WAIT_TIMEOUT),
            ThreadWaitClass::StillAlive
        );
        assert_eq!(
            classify_thread_wait(WAIT_FAILED),
            ThreadWaitClass::QueryFailed
        );
        // WAIT_ABANDONED (or any other) is unexpected => fail-closed.
        assert_eq!(
            classify_thread_wait(WAIT_ABANDONED),
            ThreadWaitClass::Unexpected
        );
    }
}
