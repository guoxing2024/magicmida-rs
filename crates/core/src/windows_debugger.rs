//! Concrete [`DebuggerCore`] implementation backed by the Windows debug API.
//!
//! `WindowsDebugger` holds the target process, breakpoint tables, and thread
//! registrations and translates raw `DEBUG_EVENT` structs into the
//! higher-level [`DebugEvent`] enum consumed by the unpacker.

use std::collections::HashMap;

use tracing::{debug, info, trace, warn};
use windows::Win32::Foundation::{
    CloseHandle, HANDLE,
    EXCEPTION_ACCESS_VIOLATION, EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP,
    DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED,
};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, FlushInstructionCache, GetThreadContext, SetThreadContext,
    ReadProcessMemory, WriteProcessMemory, WaitForDebugEvent,
    CONTEXT, CONTEXT_FLAGS,
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    DEBUG_EVENT as RAW_DEBUG_EVENT, EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT, EXIT_THREAD_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT, UNLOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT,
};
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT_ALL_AMD64, CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_CONTROL_AMD64,
    CONTEXT_INTEGER_AMD64,
};
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT_ALL_X86, CONTEXT_DEBUG_REGISTERS_X86, CONTEXT_CONTROL_X86,
    CONTEXT_INTEGER_X86,
};
use windows::Win32::System::Threading::INFINITE;

use crate::breakpoint::{HwBreakpoint, HwbpType};
use crate::debugger::{ContinueStatus, DebugEvent, DebuggerCore};
use crate::error::CoreError;
use crate::process::{CreateProcessOptions, TargetProcess, create_debug_process, patch_peb_anti_debug, cleanup_stub_exe, close_process_handles};

// ---------------------------------------------------------------------------
// WindowsDebugger
// ---------------------------------------------------------------------------

/// Windows-backed debugger core.
///
/// Created from a [`CreateProcessOptions`] via [`WindowsDebugger::new`], which
/// launches the target.  Every subsequent operation goes through the
/// [`DebuggerCore`] trait implementation.
/// The integer type of `CONTEXT::Dr0..Dr7`.
///
/// `u64` on x64, `u32` on x86.  Exists so the hardware-breakpoint writer can be
/// written once instead of twice: pinning those fields to `u64` is what kept the
/// x86 build from compiling at all.
trait DrFields {
    type Dr: Copy
        + core::ops::Shl<usize, Output = Self::Dr>
        + core::ops::BitOrAssign
        + core::ops::Not<Output = Self::Dr>
        + core::ops::BitAndAssign;
}

#[cfg(target_arch = "x86_64")]
impl DrFields for CONTEXT {
    type Dr = u64;
}

#[cfg(target_arch = "x86")]
impl DrFields for CONTEXT {
    type Dr = u32;
}

pub struct WindowsDebugger {
    /// Target process information (handles, pid, image base, etc.
    process: TargetProcess,
    /// Hardware breakpoints (DR0–DR3). `None` means the slot is free.
    hw_breakpoints: [Option<HwBreakpoint>; 4],
    /// Software breakpoints: address → original byte.
    soft_breakpoints: HashMap<usize, u8>,
    /// Registered threads: thread_id → thread handle.
    threads: HashMap<u32, HANDLE>,
}

impl WindowsDebugger {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create the target process and return a ready-to-use debugger.
    ///
    /// This calls [`create_debug_process`] internally, so all PE inspection
    /// and (for DLLs) stub-EXE generation happens here.
    pub fn new(opts: &CreateProcessOptions) -> Result<Self, CoreError> {
        let process = create_debug_process(opts)?;

        let mut threads = HashMap::new();
        threads.insert(process.main_thread_id, process.main_thread_handle);

        Ok(Self {
            process,
            hw_breakpoints: Default::default(),
            soft_breakpoints: HashMap::new(),
            threads,
        })
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

    /// Override the image base.
    ///
    /// Used for DLL targets: `CREATE_PROCESS` reports the *loader host* EXE, so
    /// the caller must retarget this to the packed DLL once `LOAD_DLL` reveals
    /// it.  Every downstream address computation (guard bounds, OEP, dump) is
    /// expressed as `image_base + rva`, so retargeting here is what makes the
    /// rest of the pipeline operate on the DLL rather than the host.
    pub fn set_image_base(&mut self, base: u64) {
        self.process.image_base = base;
    }

    // ------------------------------------------------------------------
    // Breakpoint helpers (exposed for packer crates)
    // ------------------------------------------------------------------

    /// Return the address of the hardware breakpoint in the given slot
    /// (0–3 → DR0–DR3), or `None` if the slot is empty.
    ///
    /// Used by the unpack loop to compare an incoming exception address
    /// against the installed CloseHandle / CorExeMain BP without needing
    /// write access to the breakpoint table.
    pub fn hw_breakpoint_addr(&self, slot: usize) -> Option<u64> {
        debug_assert!(slot < 4, "slot must be 0–3");
        self.hw_breakpoints.get(slot).and_then(|opt| opt.as_ref()).map(|bp| bp.address)
    }

    /// Return `true` if there is any enabled hardware breakpoint — used by the
    /// CreateThread handler to decide whether it's worth trying to propagate
    /// DR state to the new thread.  Spawning threads in a target that holds no
    /// hardware breakpoint is the common case (e.g. every CRT worker thread
    /// Themida creates), and forcing `GetThreadContext` against a thread the
    /// debugger lacks `THREAD_SUSPEND_RESUME` rights for just emits noisy
    /// `ERROR_PARTIAL_COPY` warnings.
    pub fn has_any_hw_breakpoint(&self) -> bool {
        self.hw_breakpoints.iter().any(|slot| slot.as_ref().is_some_and(|bp| bp.is_set()))
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
    fn full_context_flags() -> CONTEXT_FLAGS { CONTEXT_ALL_AMD64 }
    #[cfg(target_arch = "x86")]
    fn full_context_flags() -> CONTEXT_FLAGS { CONTEXT_ALL_X86 }

    /// Context flags for reading only debug registers (DR0–DR7).
    #[cfg(target_arch = "x86_64")]
    fn debug_registers_flags() -> CONTEXT_FLAGS { CONTEXT_DEBUG_REGISTERS_AMD64 }
    #[cfg(target_arch = "x86")]
    fn debug_registers_flags() -> CONTEXT_FLAGS { CONTEXT_DEBUG_REGISTERS_X86 }

    /// Context flags for reading only control registers (Rip, Rsp, EFlags,
    /// SegCs, SegSs).
    #[cfg(target_arch = "x86_64")]
    fn control_context_flags() -> CONTEXT_FLAGS { CONTEXT_CONTROL_AMD64 }
    #[cfg(target_arch = "x86")]
    fn control_context_flags() -> CONTEXT_FLAGS { CONTEXT_CONTROL_X86 }

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

    /// Set a hardware breakpoint in the given slot (0–3 → DR0–DR3).
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
        debug_assert!(slot < 4, "slot must be 0–3");

        // Check that the slot is free.
        if self.hw_breakpoints[slot].as_ref().is_some_and(|bp| bp.is_set()) {
            trace!(slot, "set_hw_breakpoint: slot already has an active BP, refusing to overwrite");
            return Err(CoreError::HwbpSlotInUse(slot));
        }

        // Install the breakpoint structure in the given slot.
        self.hw_breakpoints[slot] = Some(HwBreakpoint {
            address: address as u64,
            bp_type,
            disabled: false,
        });

        // Update debug registers on every registered thread.  We attempt this
        // for ALL threads but tolerate per-thread failures: a thread the
        // debugger lacks THREAD_SUSPEND_RESUME / THREAD_GET_CONTEXT rights
        // for (common with worker threads spawned by protectors such as
        // Themida) is logged and the remaining threads are still updated.
        // The breakpoint stays installed on the slot either way.
        //
        // Only apply to the main thread on the very first HW-BP install.
        // The rest of the threads get synced on subsequent install/clear
        // operations.  This matches Pascal's flow: during CREATE_PROCESS
        // there is only FThreads[main_thread_id], and the kernel has the
        // main thread suspended on the initial breakpoint so we can
        // write DR0 without disturbing a different running thread.
        // Only apply to the main thread on the very first HW-BP install.
        // Subsequent install/clear/reset calls hit this path only after
        // worker threads have already failed to resolve their DR once, so
        // we keep the original all-threads behaviour for non-initial calls.
        for &thread_id in self.threads.keys() {
            let is_initial = self.hw_breakpoints.iter().filter(|s| s.is_some()).count() <= 1;
            if is_initial && thread_id != self.process.main_thread_id {
                continue;
            }
            if let Err(e) = self.apply_debug_registers_thread(thread_id) {
                warn!(thread_id, error = %e, "failed to apply DR state to thread on HW-BP set");
            }
        }

        debug!(
            slot, %address, ?bp_type,
            "Hardware breakpoint set (slot {})",
            slot
        );
        Ok(())
    }

    /// Clear (remove) a hardware breakpoint from the given slot.
    ///
    /// Zeros the corresponding DR register and clears the enable bit in DR7
    /// for all registered threads.
    pub fn clear_hw_breakpoint(&mut self, slot: usize) -> Result<(), CoreError> {
        debug_assert!(slot < 4, "slot must be 0–3");

        self.hw_breakpoints[slot] = None;

        // Update debug registers on every registered thread — tolerate the
        // same per-thread partial-failure pattern as `set_hw_breakpoint`.
        for &thread_id in self.threads.keys() {
            if let Err(e) = self.apply_debug_registers_thread(thread_id) {
                warn!(thread_id, error = %e, "failed to apply DR state to thread on HW-BP clear");
            }
        }

        debug!(slot, "Hardware breakpoint cleared (slot {})", slot);
        Ok(())
    }

    /// Disable a hardware breakpoint without removing its configuration.
    ///
    /// Sets `disabled = true` on the matching slot and clears only the
    /// enable bit in DR7.  The DR address register is preserved so the
    /// breakpoint can be re-enabled later via [`reset_hw_breakpoints`].
    ///
    /// Returns an error if no breakpoint is found at the given slot, or
    /// if the slot is already disabled.
    pub fn disable_hw_breakpoint(&mut self, slot: usize) -> Result<(), CoreError> {
        debug_assert!(slot < 4, "slot must be 0–3");

        match &mut self.hw_breakpoints[slot] {
            Some(bp) if !bp.disabled => {
                bp.disabled = true;
            }
            Some(_) => {
                // Already disabled — nothing to do.
                trace!(slot, "HW breakpoint slot {} already disabled", slot);
                return Ok(());
            }
            None => {
                // No breakpoint in this slot — nothing to disable.
                trace!(slot, "HW breakpoint slot {} is empty, nothing to disable", slot);
                return Ok(());
            }
        }

        // Update debug registers on every registered thread — tolerate the
        // same per-thread partial-failure pattern as `set_hw_breakpoint`.
        for &thread_id in self.threads.keys() {
            if let Err(e) = self.apply_debug_registers_thread(thread_id) {
                warn!(thread_id, error = %e, "failed to apply DR state to thread on HW-BP disable");
            }
        }

        debug!(slot, "Hardware breakpoint disabled (slot {})", slot);
        Ok(())
    }

    /// Re-enable all previously disabled hardware breakpoints.
    ///
    /// Corresponds to `EnableBreakpoints` / `ResetHWBP` in the reference
    /// Pascal implementation.  Called after a single-step completes when
    /// the debugger has temporarily stepped over an execute-type hardware
    /// breakpoint.
    ///
    /// If no breakpoints are disabled this is a no-op.
    pub fn reset_hw_breakpoints(&mut self) -> Result<(), CoreError> {
        let any_disabled = self
            .hw_breakpoints
            .iter()
            .any(|bp| bp.as_ref().is_some_and(|b| b.disabled));

        if !any_disabled {
            trace!("No disabled HW breakpoints to reset");
            return Ok(());
        }

        // Re-enable all disabled slots.
        for ref mut b in self.hw_breakpoints.iter_mut().flatten() {
            b.disabled = false;
        }

        // Update debug registers on every registered thread — tolerate the
        // same per-thread partial-failure pattern as `set_hw_breakpoint`.
        for &thread_id in self.threads.keys() {
            if let Err(e) = self.apply_debug_registers_thread(thread_id) {
                warn!(thread_id, error = %e, "failed to apply DR state to thread on HW-BP reset");
            }
        }

        debug!("All disabled hardware breakpoints reset");
        Ok(())
    }

    /// Apply the current hardware breakpoint state to the debug registers
    /// of a single thread.
    ///
    /// Suspend → get context → write DR0–DR7 → set context → resume.
    ///
    /// This is the register-level primitive used by the public
    /// `set_hw_breakpoint` / `clear_hw_breakpoint` / `reset_hw_breakpoints`
    /// methods (which iterate over every registered thread internally).
    /// It is exposed publicly so that callers who learn of a thread out of
    /// band (for example, via a `CREATE_THREAD_DEBUG_EVENT`) can bring that
    /// thread up to date with the current breakpoint configuration.
    pub fn apply_debug_registers_thread(&self, thread_id: u32) -> Result<(), CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT};

        // Build a CONTEXT populated with ONLY debug registers.  We deliberately
        // skip GetThreadContext: on modern Windows (10/11) GetThreadContext
        // against a thread whose protector is still mutating the TEB / PEB-Ldr
        // trips ERROR_PARTIAL_COPY (0x80070256).  SetThreadContext with a
        // pre-populated CONTEXT succeeds because the kernel has no need to
        // thread-walk — it only writes the debug registers we have asked it to
        // write.
        // SAFETY: CONTEXT is repr(C); zeroed() produces a valid all-zero CONTEXT that the Windows APIs accept and overwrite.
        let dr_ctx = unsafe {
            let mut c: CONTEXT = std::mem::zeroed();
            c.ContextFlags = Self::debug_registers_flags();
            self.write_debug_registers(&mut c);
            c
        };

        // Try every handle we can get a hold of, in order of preference.
        let mut handles: Vec<HANDLE> = Vec::new();
        // SAFETY: OpenThread returns a fresh valid HANDLE; thread_id comes from a registered debug thread.
        unsafe {
            if let Ok(h) = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, thread_id) {
                handles.push(h);
            }
            if let Ok(h) = self.thread_handle(thread_id) {
                if !handles.contains(&h) {
                    handles.push(h);
                }
            }
        }

        for &h in &handles {
            // SAFETY: h is a valid thread handle with THREAD_SET_CONTEXT rights; dr_ctx is a properly initialised CONTEXT.
            unsafe {
                if SetThreadContext(h, &dr_ctx).is_ok() {
                    return Ok(());
                }
            }
        }

        Err(CoreError::Windows(0x256))
    }

    /// Write the hardware breakpoint state into the given CONTEXT.
    ///
    /// This populates DR0–DR3 and DR7 from `self.hw_breakpoints`.
    /// DR6 is cleared of the BS (single-step) flag (bit 14) to prevent
    /// the OS from misinterpreting a single-step as a hardware breakpoint.
    fn write_debug_registers(&self, ctx: &mut CONTEXT) {
        // Build the DR7 mask.
        // DR7 bit layout (x86/x64):
        //   L0–L3  (bits 0,2,4,6):   local enable (set = 1)
        //   G0–G3  (bits 1,3,5,7):   global enable (unused — set 0)
        //   LEN0–LEN3 (bits 8-15):       length (00=1, 01=2, 11=4 bytes)
        //   RW0–RW3  (bits 16-23):      type (00=execute, 01=write, 11=access)
        // `Dr0..Dr7` are `u64` in the x64 CONTEXT and `u32` in the x86 one, so the
        // accumulator has to follow the target architecture rather than being
        // pinned to `u64` (pinning it is what kept the x86 build from
        // compiling at all).
        type DrWord = <CONTEXT as DrFields>::Dr;
        let mut dr7: DrWord = 0;

        // Helper: write one slot's data into DR7 and the context DRn register.
        fn apply_slot(
            ctx: &mut CONTEXT,
            bp: Option<&HwBreakpoint>,
            slot: usize,
            dr7: &mut <CONTEXT as DrFields>::Dr,
        ) {
            let dr_shift = slot * 4;       // RW field: bits 16 + 4*slot
            let le_shift = slot * 2;        // L enable: bits 0,2,4,6
            match bp {
                Some(b) if b.is_set() => {
                    let addr = b.address as <CONTEXT as DrFields>::Dr;
                    match slot {
                        0 => ctx.Dr0 = addr,
                        1 => ctx.Dr1 = addr,
                        2 => ctx.Dr2 = addr,
                        3 => ctx.Dr3 = addr,
                        _ => unreachable!(),
                    }
                    *dr7 |= (1 as <CONTEXT as DrFields>::Dr) << le_shift;
                    *dr7 |= (b.bp_type as <CONTEXT as DrFields>::Dr) << (16 + dr_shift);
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

        apply_slot(ctx, self.hw_breakpoints[0].as_ref(), 0, &mut dr7);
        apply_slot(ctx, self.hw_breakpoints[1].as_ref(), 1, &mut dr7);
        apply_slot(ctx, self.hw_breakpoints[2].as_ref(), 2, &mut dr7);
        apply_slot(ctx, self.hw_breakpoints[3].as_ref(), 3, &mut dr7);

        // Clear the BS (single-step) flag in DR6 (bit 14) so the OS
        // doesn't conflate a single-step with a hardware breakpoint.
        ctx.Dr6 &= !((1 as <CONTEXT as DrFields>::Dr) << 14);

        ctx.Dr7 = dr7;
    }

    // ------------------------------------------------------------------
    // Software breakpoint management
    // ------------------------------------------------------------------

    /// Set a software breakpoint (INT3 / 0xCC) at the given address.
    ///
    /// Reference: `DebuggerCore.pas` → `SetSoftBP`.
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
            if read == 1 && current[0] == 0xCC {
                trace!(%address, "Soft breakpoint already set at address");
                return Ok(());
            }
            // If the byte isn't 0xCC, something is inconsistent; fall through to overwrite.
            warn!(
                %address,
                byte = current[0],
                "Soft breakpoint inconsistency — re-installing"
            );
            self.soft_breakpoints.remove(&address);
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
    /// Reference: `DebuggerCore.pas` → `SoftBPClear`.
    ///
    /// Iterates over `soft_breakpoints`, writes the original byte back to each
    /// address, then flushes the instruction cache and clears the map.
    pub fn clear_all_soft_breakpoints(&mut self) -> Result<(), CoreError> {
        // Collect entries into a temporary vec to release the immutable borrow
        // before calling `write_memory` (which takes `&mut self`).
        let entries: Vec<(usize, u8)> = self.soft_breakpoints.drain().collect();

        for (address, original) in &entries {
            let bytes_written = self.write_memory(*address, &[*original])?;
            if bytes_written != 1 {
                warn!(
                    %address,
                    expected = 1,
                    actual = bytes_written,
                    "Partial write while clearing soft breakpoint"
                );
            }
            // Flush instruction cache for each restored address.
            // SAFETY: hProcess is a valid handle; address and size are within bounds.
            unsafe {
                let _ = FlushInstructionCache(
                    self.process.handle,
                    Some(*address as *const std::ffi::c_void),
                    1,
                );
            }
        }

        debug!("All soft breakpoints cleared");
        Ok(())
    }

    /// Reset / re-arm a software breakpoint after single-stepping over it.
    ///
    /// Reference: `DebuggerCore.pas` → `OnSoftwareBreakpoint` /
    /// `SoftBPReenable`.
    ///
    /// When a soft breakpoint fires, the original instruction has already been
    /// executed.  This method re-applies `0xCC` at the re-enable address and
    /// flushes the instruction cache.
    ///
    /// Call this after single-stepping past the breakpoint (via
    /// `single_step(thread_id)` → wait for `SingleStep` event → call this).
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
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT};

        // SAFETY: OpenThread returns a fresh valid HANDLE; thread_id comes from a registered debug thread.
        let h = unsafe {
            OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?
        };

        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = Self::full_context_flags();

        // SAFETY: h is a valid thread handle with THREAD_SET_CONTEXT rights; ctx is a properly initialised CONTEXT.
        unsafe {
            GetThreadContext(h, &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        // Set the trap flag (TF, bit 8 in EFlags).
        ctx.EFlags |= 0x100;

        // SAFETY: h is a valid thread handle with THREAD_SET_CONTEXT rights; ctx is a properly initialised CONTEXT.
        unsafe {
            SetThreadContext(h, &ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Drop — clean up handles and stub EXE
// ---------------------------------------------------------------------------

/// True when `hresult` is Windows `ERROR_SEM_TIMEOUT` (121) in HRESULT form.
///
/// `WaitForDebugEvent` uses that error to mean "the timeout expired and no debug
/// event arrived" — an ordinary idle interval, not a failure.  The `windows`
/// crate surfaces it as `HRESULT_FROM_WIN32(121)` = `0x80070079` =
/// 2147942521, so the Win32 code lives in the low 16 bits:
///
/// ```text
/// 0x80070079 & 0xFFFF == 0x0079 == 121   -> true
/// 0x80070079          == 121             -> false   (the original bug)
/// ```
///
/// Comparing the whole HRESULT against 121 can never match, which is why
/// `CoreError::Timeout` used to be unreachable and every idle tick surfaced as a
/// hard `CoreError::Windows` error.  Callers each worked around it locally
/// (`av_handler.rs`'s `sem_timeout`, the DLL settle loop); this is the single
/// definition they now share.
fn is_sem_timeout(hresult: u32) -> bool {
    hresult & 0xFFFF == 121
}

impl WindowsDebugger {
    /// Consume and acknowledge debug events until the debuggee's exit is seen.
    ///
    /// Called from `Drop` after `TerminateProcess` on the loader-host path.
    ///
    /// # Why this is required
    ///
    /// Windows keeps a terminated process in the "exiting" state while its
    /// debugger still owes the kernel a `ContinueDebugEvent` for the pending
    /// `EXIT_PROCESS_DEBUG_EVENT`.  Until that acknowledgement arrives the
    /// process object is not torn down, its image section stays mapped, and the
    /// file cannot be deleted — `remove_file` reports `ERROR_ACCESS_DENIED`.
    ///
    /// Measured on the reference DLL before this existed: the loader host was
    /// terminated, `DebugActiveProcessStop` was refused, and the 62 KB stub was
    /// still locked after 5 s of retries; it became deletable the instant the
    /// CLI exited.  That is exactly the signature of a pending exit event.
    ///
    /// Bounded on purpose: this runs in `Drop`, so it must never hang a failing
    /// run.  Any other event that arrives is answered normally, because leaving
    /// one unanswered would block the exit event behind it.
    fn drain_exit_events(&mut self, pid: u32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            let mut raw: RAW_DEBUG_EVENT = RAW_DEBUG_EVENT::default();
            // SAFETY: `raw` is a valid out-pointer; a short timeout keeps the
            // wait bounded.
            if let Err(e) = unsafe { WaitForDebugEvent(&mut raw, 100) } {
                // `windows` returns a full HRESULT: a timeout is
                // `0x80070079` (2147942521), whose **low 16 bits** are
                // `ERROR_SEM_TIMEOUT` (121).  Comparing the whole HRESULT
                // against 121 never matches — that mistake made this loop bail
                // out on its first idle tick.
                let code = e.code().0 as u32;
                if is_sem_timeout(code) {
                    continue; // nothing pending
                }
                debug!(error_code = code, "drain: WaitForDebugEvent failed");
                return;
            }

            let code = raw.dwDebugEventCode.0;
            let is_exit = code == EXIT_PROCESS_DEBUG_EVENT.0;
            let event_pid = raw.dwProcessId;

            // SAFETY: the event came from `WaitForDebugEvent`, so it must be
            // acknowledged exactly once.
            unsafe {
                let _ = ContinueDebugEvent(
                    event_pid,
                    raw.dwThreadId,
                    DBG_CONTINUE,
                );
            }

            if is_exit && event_pid == pid {
                debug!(pid, "Consumed the loader host's exit event");
                return;
            }
        }
        debug!(pid, "No exit event for the loader host within the timeout");
    }
}

impl Drop for WindowsDebugger {
    fn drop(&mut self) {
        // Close every registered thread handle EXCEPT the main thread.
        // The main-thread handle is owned by `self.process` and will be closed
        // together with the process handle by `close_process_handles` below —
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

        // Terminate the debuggee and then **acknowledge its exit**, or the file
        // never becomes deletable.
        //
        // A debuggee that terminates stays in the "exiting" state until its
        // debugger consumes the pending `EXIT_PROCESS_DEBUG_EVENT` and answers
        // it with `ContinueDebugEvent`.  Its image section therefore stays
        // mapped and `remove_file` keeps failing with `ERROR_ACCESS_DENIED`.
        //
        // Measured on the reference DLL: `TerminateProcess` returned success,
        // `DebugActiveProcessStop` failed with `ERROR_ACCESS_DENIED`, and the
        // 62 KB loader host was *still* locked after 5 s of retries — yet it was
        // deletable the instant the CLI process exited, i.e. as soon as the
        // kernel tore the debug session down.  Draining the exit event here is
        // what makes that happen while we are still alive.
        //
        // This only ever applies to our own child on the DLL path;
        // `/dump-process` uses `ReadOnlyProcessDebugger`, which has no such
        // teardown.
        if !self.process.handle.is_invalid() && self.process.stub_exe.is_some() {
            let pid = self.process.pid;

            // SAFETY: the handle was opened with PROCESS_ALL_ACCESS, which
            // includes PROCESS_TERMINATE.
            match unsafe {
                windows::Win32::System::Threading::TerminateProcess(
                    self.process.handle,
                    0,
                )
            } {
                Ok(()) => debug!(pid, "Terminated the loader host"),
                Err(e) => warn!(pid, "TerminateProcess on the loader host failed: {e}"),
            }

            self.drain_exit_events(pid);
        }

        // Close process and main-thread handles.
        close_process_handles(self.process.handle, self.process.main_thread_handle);

        // Delete the stub EXE if one was generated.
        //
        // Even after `TerminateProcess` the kernel needs a moment to tear the
        // section object down, so retry briefly rather than reporting a failure
        // that is really just a race with process teardown.
        if let Some(ref stub) = self.process.stub_exe {
            cleanup_stub_exe(stub);
        }
    }
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

    fn wait_event_timeout(&mut self, timeout_ms: u32) -> Result<DebugEvent, CoreError> {
        let mut raw: RAW_DEBUG_EVENT = RAW_DEBUG_EVENT::default();

        // SAFETY: WaitForDebugEvent with a custom timeout.
        let wait_result = unsafe { WaitForDebugEvent(&mut raw, timeout_ms) };

        match wait_result {
            Ok(()) => {
                match self.decode_event(&raw) {
                    Ok(event) => {
                        // Bookkeeping.
                        match &event {
                            DebugEvent::CreateThread { thread_id, h_thread, .. } => {
                                self.threads.insert(*thread_id, *h_thread);
                                // Sync DR state only when we have a HW BP to
                                // propagate — avoids `ERROR_PARTIAL_COPY`
                                // spam against threads we can't suspend.
                                if self.has_any_hw_breakpoint() {
                                    if let Err(e) = self.apply_debug_registers_thread(*thread_id) {
                                        warn!(thread_id, error = %e, "failed to propagate DR state to new thread");
                                    }
                                }
                            }
                            DebugEvent::ExitThread { thread_id, .. } => {
                                self.threads.remove(thread_id);
                            }
                            DebugEvent::CreateProcess { image_base, .. } => {
                                self.process.image_base = *image_base;
                            }
                            _ => {}
                        }
                        Ok(event)
                    }
                    Err(CoreError::Handled) => {
                        // Event was handled internally - return a dummy event
                        // that the caller can detect and handle.
                        Err(CoreError::Timeout)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => {
                // `WaitForDebugEvent` reports its timeout as a *HRESULT*, not as a
                // bare Win32 error code: `ERROR_SEM_TIMEOUT` (121) arrives as
                // `0x80070079`, which is -2147024775 as a signed 32-bit value.
                // Comparing the whole value against 121 therefore never matches,
                // so `CoreError::Timeout` was unreachable and every idle tick
                // surfaced as a hard `CoreError::Windows` failure instead.
                //
                // The Win32 code is the low 16 bits.  This is the same test the
                // callers had to duplicate locally to work around the bug
                // (`av_handler.rs`'s `sem_timeout`, `mod.rs`'s inline check); with
                // the mapping fixed here those workarounds become no-ops rather
                // than the only thing keeping the loop alive.
                let hresult = e.code().0 as u32;
                if is_sem_timeout(hresult) {
                    Err(CoreError::Timeout)
                } else {
                    Err(CoreError::Windows(hresult & 0xFFFF))
                }
            }
        }
    }

    fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
        loop {
            let mut raw: RAW_DEBUG_EVENT = RAW_DEBUG_EVENT::default();

            // SAFETY: WaitForDebugEvent with INFINITE timeout is the
            // canonical debug-loop pattern.  raw is a valid out-pointer.
            let wait_result = unsafe { WaitForDebugEvent(&mut raw, INFINITE) };
            if wait_result.is_err() {
                let err = wait_result.unwrap_err();
                // Same HRESULT-vs-Win32 distinction as the outer `continue_event`
                // loop above: the timeout arrives as 0x80070079 and must be
                // reduced to its low 16 bits before it means anything.
                let hresult = err.code().0 as u32;
                debug!(hresult, "WaitForDebugEvent failed");
                if is_sem_timeout(hresult) {
                    return Err(CoreError::Timeout);
                }
                return Err(CoreError::Windows(hresult & 0xFFFF));
            }

            let _event_code = raw.dwDebugEventCode;
            let ev = match self.decode_event(&raw) {
                        Ok(event) => event,
                        Err(CoreError::Handled) => continue,
                        Err(e) => return Err(e),
                    };
            let _is_create_process = matches!(ev, DebugEvent::CreateProcess { .. });

            // Bookkeeping before returning the event.
            match &ev {
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
                            unsafe { let _ = CloseHandle(h); }
                        }
                    }
                }
                DebugEvent::ExitProcess { .. } => {
                    // The debuggee is gone; the call site will break out of
                    // the loop after processing this event.
                }
                _ => {}
            }

            // On CREATE_PROCESS, do PEB patching and store image base.
            if let DebugEvent::CreateProcess {
                h_process,
                h_thread,
                ..
            } = &ev
            {
                // SAFETY: h_process and h_thread are valid handles from the
                // debug event; we patch anti-debug flags before the target
                // runs any code.
                let image_base = patch_peb_anti_debug(*h_process)?;
                self.process.image_base = image_base;
                self.threads.insert(self.process.main_thread_id, *h_thread);
            }

            return Ok(ev);
        }
    }

    fn continue_event(
        &mut self,
        thread_id: u32,
        status: ContinueStatus,
    ) -> Result<(), CoreError> {
        let nt_status = match status {
            ContinueStatus::Continue => DBG_CONTINUE,
            ContinueStatus::ContinueNoStep => DBG_CONTINUE,
            // DBG_EXCEPTION_NOT_HANDLED: hand the exception to the program's
            // own SEH instead of resuming at the faulting instruction.  Required
            // for first-chance faults the debugger does not handle — resuming
            // with DBG_CONTINUE re-executes the faulting instruction and loops.
            ContinueStatus::ExceptionNotHandled => DBG_EXCEPTION_NOT_HANDLED,
        };

        // SAFETY: pid and tid come from the current debug event.
        unsafe {
            ContinueDebugEvent(self.process.pid, thread_id, nt_status)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }
        Ok(())
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
        let h = unsafe {
            OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?
        };
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = Self::full_context_flags();

        // SAFETY: h is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a writable CONTEXT.
        unsafe {
            GetThreadContext(h, &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(ctx)
    }

    fn get_thread_context_control(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        let h = unsafe {
            OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?
        };
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = Self::control_context_flags();

        // SAFETY: h is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a writable CONTEXT.
        unsafe {
            GetThreadContext(h, &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(ctx)
    }

    fn get_thread_context_control_integer(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        let h = unsafe {
            OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?
        };
        let mut ctx = CONTEXT::default();
        ctx.ContextFlags = Self::control_integer_context_flags();

        // SAFETY: h is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a writable CONTEXT.
        unsafe {
            GetThreadContext(h, &mut ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(ctx)
    }

    fn set_thread_context(&self, thread_id: u32, ctx: &CONTEXT) -> Result<(), CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_SET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        let h = unsafe {
            OpenThread(THREAD_SET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?
        };

        // SAFETY: h is a valid thread handle with THREAD_SET_CONTEXT rights; ctx is a properly initialised CONTEXT.
        unsafe {
            SetThreadContext(h, ctx)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Internal — raw DEBUG_EVENT → DebugEvent decoding
// ---------------------------------------------------------------------------

impl WindowsDebugger {
    /// Read only the debug-register portion of the given thread's context.
    /// This works where [`DebuggerCore::get_thread_context`] cannot: the
    /// full CONTEXT request trips ERROR_PARTIAL_COPY on threads belonging
    /// to targets whose protector mutates the thread's TEB / PEB-Ldr during
    /// early ntdll init.  Scope the request down to DR0–DR7 so the kernel
    /// does not attempt to walk those guarded structures.
    pub fn get_thread_context_dbg(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        use windows::Win32::System::Threading::{OpenThread, THREAD_GET_CONTEXT};

        // SAFETY: OpenThread returns a valid HANDLE for the given live thread_id.
        let h = unsafe {
            OpenThread(THREAD_GET_CONTEXT, false, thread_id)
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?
        };
        let mut ctx = Box::new(CONTEXT::default());
        ctx.ContextFlags = Self::debug_registers_flags();
        // SAFETY: h is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a heap-allocated CONTEXT.
        unsafe {
            GetThreadContext(h, std::ptr::from_mut(&mut *ctx))
                .map_err(|e| CoreError::Windows(e.code().0 as u32))?;
        }
        Ok(*ctx)
    }

    /// Translate a raw Windows `DEBUG_EVENT` into our abstract [`DebugEvent`].
    fn decode_event(&self, raw: &RAW_DEBUG_EVENT) -> Result<DebugEvent, CoreError> {
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
                        let is_write =
                            exc.ExceptionRecord.NumberParameters > 0
                                && exc.ExceptionRecord.ExceptionInformation[0] == 1;
                        let target = if exc.ExceptionRecord.NumberParameters > 1 {
                            exc.ExceptionRecord.ExceptionInformation[1] as u64
                        } else {
                            0
                        };
                        // ExceptionInformation[0] is the access type:
                        //   0 = read, 1 = write, 8 = execute (inside .text).
                        // Themida uses execute-inside-.text faults to identify TLS
                        // callbacks that we must let run — matching the Pascal
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
                        // Any other exception is a *first-chance* exception the
                        // debuggee raised, not a debugger failure.
                        //
                        // This used to `return Err(CoreError::Windows(code))`,
                        // which made the whole unpack abort.  That is wrong on
                        // two counts:
                        //
                        // 1. Under `DEBUG_ONLY_THIS_PROCESS` the debugger is
                        //    handed **every** exception first, including ones
                        //    the program handles itself via SEH.  Returning an
                        //    error for them kills runs that would have worked.
                        // 2. Themida uses exactly this as an anti-debug probe.
                        //    Measured on the x86 reference sample (Themida
                        //    3.2.4, built here with `Themida.exe`): the shell
                        //    executes a privileged instruction, Windows raises
                        //    `STATUS_PRIVILEGED_INSTRUCTION` (0xC0000096), and
                        //    the run died with `Windows API error: code
                        //    3221225622` before ever reaching the OEP.  The
                        //    x64 reference samples never hit this path, which is
                        //    why it went unnoticed.
                        //
                        // Surfacing it as `DebugEvent::UnhandledException` lets
                        // the caller decide: continue the event (the normal
                        // first-chance case) or act on a specific code.
                        trace!(
                            code = %format!("{:#x}", other.0),
                            address = %format!("{addr:#x}"),
                            "First-chance exception"
                        );
                        DebugEvent::UnhandledException {
                            thread_id: raw.dwThreadId,
                            address: addr,
                            code: other.0 as u32,
                        }
                    }
                }
            }

            CREATE_THREAD_DEBUG_EVENT => {
                // SAFETY: DEBUG_EVENT union accessed with matching dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT.
                let ct = unsafe { &raw.u.CreateThread };
                DebugEvent::CreateThread {
                    thread_id: raw.dwThreadId,
                    h_thread: ct.hThread,
                    start_address: ct.lpStartAddress.map_or(0, |f| f as u64),
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

            OUTPUT_DEBUG_STRING_EVENT => {
                // The target called OutputDebugString; the kernel holds the
                // calling thread inside `kernelbase!RaiseException` until the
                // debugger continues this event.  Swallowing it without
                // `ContinueDebugEvent` freezes the thread FOREVER — measured
                // on Themida 1.8.2 (2026-10-28): after the decode converged,
                // the shell's startup hit an OutputDebugString, the whole
                // process parked (main thread in `Wait/Executive` at
                // `kernelbase!RaiseException+0x64`, 4 worker threads
                // suspended, no windows, no events, indefinitely) because
                // this arm returned `Handled` without continuing.
                //
                // Read the string (shell diagnostics are prime evidence for
                // unpacking) and continue the event with DBG_CONTINUE.
                let od = unsafe { &raw.u.DebugString };
                let want = (od.nDebugStringLength as usize).min(4096);
                let mut buf = vec![0u8; want];
                let text = if self
                    .read_memory(od.lpDebugStringData.0 as usize, &mut buf)
                    .is_ok()
                {
                    if od.fUnicode != 0 {
                        let units: Vec<u16> = buf
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .take_while(|&u| u != 0)
                            .collect();
                        String::from_utf16_lossy(&units)
                    } else {
                        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                        String::from_utf8_lossy(&buf[..end]).into_owned()
                    }
                } else {
                    "<unreadable>".to_string()
                };
                info!(
                    thread_id = raw.dwThreadId,
                    text = %text,
                    "OutputDebugString from target"
                );
                // SAFETY: pid/thread_id come from the event being handled;
                // DBG_CONTINUE is the correct status — the debugger consumed
                // the print.
                let _ =
                    unsafe { ContinueDebugEvent(raw.dwProcessId, raw.dwThreadId, DBG_CONTINUE) };
                return Err(CoreError::Handled);
            }

            RIP_EVENT => {
                warn!("RIP_EVENT received — system-level debug error");
                // SAFETY: pid and thread_id come from the RIP_EVENT being handled; DBG_CONTINUE is a valid status.
                let _ = unsafe {
                    ContinueDebugEvent(
                        raw.dwProcessId,
                        raw.dwThreadId,
                        DBG_CONTINUE,
                    )
                };
                return Err(CoreError::Windows(0));
            }

            _ => {
                debug!(
                    code = raw.dwDebugEventCode.0,
                    "Unknown debug event code"
                );
                return Err(CoreError::Handled);
            }
        };

        Ok(ev)
    }
}

#[cfg(test)]
mod sem_timeout_tests {
    use super::is_sem_timeout;

    /// The exact value `WaitForDebugEvent` returns when its timeout expires.
    ///
    /// This is the regression test for the bug: the old code compared this
    /// number against 121 directly and therefore never matched, which made
    /// `CoreError::Timeout` unreachable and turned every idle debug-loop tick
    /// into a hard error.
    #[test]
    fn real_hresult_is_recognised() {
        let hresult: u32 = 0x8007_0079;
        assert_eq!(hresult, 2147942521, "the constant must be the real one");
        assert!(
            is_sem_timeout(hresult),
            "HRESULT_FROM_WIN32(121) must map to a timeout"
        );
        // The bug in one line: the whole value is not 121.
        assert_ne!(hresult, 121, "this is why the old comparison failed");
    }

    /// The bare Win32 code must also be recognised, because some paths reach
    /// here with the code already reduced.
    #[test]
    fn bare_win32_code_is_recognised() {
        assert!(is_sem_timeout(121));
    }

    /// A genuine failure must not be mistaken for an idle interval.
    #[test]
    fn other_errors_are_not_timeouts() {
        // ERROR_PARTIAL_COPY — the real failure ScyllaHide timing races produce.
        assert!(!is_sem_timeout(0x8007_012D));
        // ERROR_ACCESS_DENIED.
        assert!(!is_sem_timeout(0x8007_0005));
        // ERROR_INVALID_HANDLE.
        assert!(!is_sem_timeout(0x8007_0006));
        // Zero is not a timeout either.
        assert!(!is_sem_timeout(0));
    }

    /// A success HRESULT (0) and a plain non-Win32 HRESULT must not match.
    #[test]
    fn non_win32_hresults_do_not_match() {
        // E_FAIL: low 16 bits are 0x8000, not 121.
        assert!(!is_sem_timeout(0x8000_4005));
    }
}
