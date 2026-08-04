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
}
