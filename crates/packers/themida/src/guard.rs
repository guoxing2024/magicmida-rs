//! Code section guard for Themida unpacking.
//!
//! Sets `.text` to `PAGE_NOACCESS` so writes/executes from the packer
//! trigger access violations that the debugger intercepts.
//!
//! The flow closely follows `Themida64.pas` `ProcessGuardedAccess`:
//!
//! 1. FTMGuard mode: re-install .text guard after TLS callback execution.
//! 2. Exception outside image bounds (library code reading .text): record + single-step.
//! 3. Exception past guard end (Themida writing to .text): record + single-step.
//! 4. TLS callback (execute in .text, `FTLSTotal > 0`): switch guard region to
//!    Themida section and wait for next access.
//! 5. FTraceMSVCOEP mode: write MSVC OEP and finish unpacking.
//! 6. Otherwise: treat as potential OEP.

use tracing::{debug, info, trace};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    PAGE_NOACCESS, PAGE_PROTECTION_FLAGS,
};

use mida_core::DebuggerCore;

use crate::common::ThemidaState;
use crate::error::ThemidaError;

const _PROTECTION_NOACCESS: u32 = PAGE_NOACCESS.0;
const _PROTECTION_EXECUTE_READ: u32 = PAGE_EXECUTE_READ.0;
const _PROTECTION_EXECUTE_READWRITE: u32 = PAGE_EXECUTE_READWRITE.0;
/// Read-only + write page protection, used during FTMGuard mode (write by
/// Themida TLS but no execute — see `Themida64.pas` TLS branch).
const PAGE_READWRITE: u32 = 0x04;

#[inline]
fn page_protect(flags: u32) -> PAGE_PROTECTION_FLAGS {
    PAGE_PROTECTION_FLAGS(flags)
}

/// Result of processing a guarded access violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardAccessResult {
    /// The accessed address is inside `.text` and was recorded; a single-step
    /// trap-flag has been set on the thread.
    Handled { address: usize, thread_id: u32 },
    /// The faulting instruction is inside `.text` — likely the OEP or a TLS callback.
    PossibleOEP { address: usize },
    /// The accessed address is not inside the guarded region.
    NotGuarded,
    /// A TLS callback was detected.  Guard region has been switched to the
    /// Themida section (FTMGuard mode).  The caller should continue the
    /// debug loop normally — the next access will either be a TLS callback
    /// body (triggering `Handled`) or a return to real code after all TLS
    /// callbacks finish (triggering `PossibleOEP`).
    TlsCallback { address: usize },
    /// The MSVC OEP synthesis has succeeded.  The binary's real entry point is
    /// `address` (the synthetic stub written by [`crate::oep::write_msvc_oep_x64`]).
    /// The caller should exit the debug loop and proceed to IAT/shrink phases.
    MsvcTraceComplete { address: usize },
    /// IAT monitoring detected enough writes to consider the IAT fully decrypted.
    /// The caller should proceed to IAT repair.
    IatReady { address: usize },
}

#[inline]
fn in_image_bounds(address: usize, image_base: usize, image_boundary: usize) -> bool {
    address >= image_base && address < image_boundary
}

/// Install a guard on the IAT region to monitor writes.
///
/// This is used for "IAT write monitoring" mode: after OEP is found,
/// we guard the IAT region so that writes from the Themida VM trigger
/// access violations we can intercept. This lets us capture the real
/// API addresses as they are decrypted at runtime.
pub fn install_iat_guard(
    h_process: HANDLE,
    iat_start: usize,
    iat_size: usize,
) -> Result<(), ThemidaError> {
    if iat_size == 0 {
        return Err(ThemidaError::Debugger("IAT guard: size cannot be zero".into()));
    }
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
    unsafe {
        VirtualProtectEx(
            h_process,
            iat_start as *const std::ffi::c_void,
            iat_size,
            PAGE_NOACCESS,
            &mut old_protect,
        )
    }
    .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx failed for IAT guard at {iat_start:#x}: {e}")))?;
    debug!("IAT guard installed: {:#x} – {:#x} (PAGE_NOACCESS)", iat_start, iat_start + iat_size);
    Ok(())
}

/// Temporarily restore read/write access to the IAT region so a write can complete.
pub fn temporary_un_guard_iat(
    h_process: HANDLE,
    iat_start: usize,
    iat_size: usize,
) -> Result<PAGE_PROTECTION_FLAGS, ThemidaError> {
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
    unsafe {
        VirtualProtectEx(
            h_process,
            iat_start as *const std::ffi::c_void,
            iat_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx temporary unguard IAT: {e}")))?;
    Ok(old_protect)
}

/// Re-install the IAT guard after a write has completed.
pub fn re_guard_iat(
    h_process: HANDLE,
    iat_start: usize,
    iat_size: usize,
) -> Result<(), ThemidaError> {
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
    unsafe {
        VirtualProtectEx(
            h_process,
            iat_start as *const std::ffi::c_void,
            iat_size,
            PAGE_NOACCESS,
            &mut old_protect,
        )
    }
    .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx re-guard IAT: {e}")))?;
    debug!("IAT guard re-installed: {:#x} – {:#x}", iat_start, iat_start + iat_size);
    Ok(())
}

/// Install the code-section guard on the target process.
pub fn install_code_section_guard(
    h_process: HANDLE,
    text_section_start: usize,
    text_section_size: usize,
    protection: u32,
) -> Result<(), ThemidaError> {
    if text_section_size == 0 {
        return Err(ThemidaError::Debugger("Code section guard: size cannot be zero".into()));
    }
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
    unsafe {
        VirtualProtectEx(
            h_process,
            text_section_start as *const std::ffi::c_void,
            text_section_size,
            page_protect(protection),
            &mut old_protect,
        )
    }
    .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx failed for code section guard at {text_section_start:#x}: {e}")))?;
    debug!("Code section guard installed: {:#x} – {:#x} (protection: {:#x})", text_section_start, text_section_start + text_section_size, protection);
    Ok(())
}

/// Process an access violation that occurred inside the guarded code section.
///
/// This implements the full x64 logic from `Themida64.pas`
/// `ProcessGuardedAccess` (lines 373–470).  Branch ordering and semantics
/// intentionally mirror the Pascal reference:
///
///   1. FTMGuard   – previous TLS access switched the guard region away from
///                   .text. Re-arm .text PAGE_NOACCESS and resume.
///   2. exc_type = 8 + outstanding TLS – execute-inside-.text fault while TLS
///                   callbacks are still pending.  Count the hit, switch to
///                   Themida-section guard in PAGE_READWRITE, defer re-arming
///                   .text until the next fault (FTMGuard mode).
///   3. Exception outside image bounds – external library probed .text.
///                   Record the fault target, single-step, re-arm on the
///                   next trap.
///   4. Exception past guard end – Themida dispatcher writing call/jmp
///                   targets into .text.  Record + single-step, same as (3).
///   5. FTraceMSVCOEP – MSVC CRT-startup hit in trace mode.  Synthesize
///                   the OEP stub and signal the caller via MsvcTraceComplete.
///   6. Otherwise – potential OEP.  Defer to caller.
///
/// The function NEVER returns an error if it merely fails to set a guard
/// region (`VirtualProtectEx`); those errors are propagated up so the
/// caller can decide whether to continue diagnostics.  Branch detection
/// itself is infallible.
pub fn process_guarded_access(
    debugger: &mut dyn DebuggerCore,
    h_process: HANDLE,
    state: &mut ThemidaState,
    fault_address: usize,
    exception_address: usize,
    thread_id: u32,
    image_base: usize,
    image_boundary: usize,
    text_section_start: usize,
    text_section_end: usize,
    exc_type: u8,
) -> Result<GuardAccessResult, ThemidaError> {
    let text_size = text_section_end.saturating_sub(text_section_start);
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();

    // Temporarily restore full access so the faulting instruction can complete
    // (matches `VirtualProtectEx(..., PAGE_EXECUTE_READWRITE, ...)` in Pascal).
    // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
    unsafe {
        VirtualProtectEx(
            h_process,
            text_section_start as *const std::ffi::c_void,
            text_size,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx in guarded access: {e}")))?;

    // -- Branch 1: FTMGuard mode ------------------------------------------------
    // The previous access was a TLS callback execution that switched the guard
    // region to the Themida section. We just hit the new region — re-install the
    // code-section guard and continue the debug loop normally.
    if state.ftm_guard {
        state.ftm_guard = false;
        debug!("FTMGuard: re-installing .text guard after TLS execution");
        // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
        unsafe {
            VirtualProtectEx(
                h_process,
                text_section_start as *const std::ffi::c_void,
                text_size,
                PAGE_NOACCESS,
                &mut old_protect,
            )
        }
        .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx FTMGuard restore: {e}")))?;
        return Ok(GuardAccessResult::Handled {
            address: exception_address,
            thread_id,
        });
    }

    // -- Branch 2: Exception outside image bounds --------------------------------
    // Library code outside the target image probed the virtual memory covered
    // by our guard region.  Increment the guard-address counter and arm the
    // trap flag; the single-step that follows will re-guard.
    //
    // **Pascal ordering**: this check comes BEFORE the TLS branch so that
    // library-probe faults are always recorded (and the TLS counter is never
    // incremented for non-TLS execute faults from outside the image).
    if !in_image_bounds(exception_address, image_base, image_boundary) {
        state.guard_addrs.push(fault_address);
        state.guard_stepping = true;
        debug!(
            "Guard access from outside image: target={:#x} from={:#x} (count: {})",
            fault_address,
            exception_address,
            state.guard_addrs.len()
        );
        enable_trap_flag(debugger, thread_id)?;
        return Ok(GuardAccessResult::Handled {
            address: fault_address,
            thread_id,
        });
    }

    // -- Branch 3: Exception past guard end -------------------------------------
    // The faulting instruction is past the text-section end (still inside the
    // image) — typically the Themida VM dispatcher writing call/jmp targets
    // into .text.  Same handling as branch 2: record + single-step.
    //
    // **Pascal ordering**: same as branch 2 — checked before TLS.
    if exception_address >= text_section_end {
        state.guard_addrs.push(fault_address);
        state.guard_stepping = true;
        debug!(
            "Themida write to .text: target={:#x} from={:#x} (count: {})",
            fault_address,
            exception_address,
            state.guard_addrs.len()
        );
        enable_trap_flag(debugger, thread_id)?;
        return Ok(GuardAccessResult::Handled {
            address: fault_address,
            thread_id,
        });
    }

    // -- Branch 4: TLS callback ------------------------------------------------
    // Pascal uses ExceptionInformation[0] = 8 to identify execute-inside-.text
    // faults driven by TLS callbacks.  ExceptionInformation[0] values:
    //   0 = read, 1 = write, 8 = execute.
    // Combined with the outstanding-TLS counter this prevents non-TLS
    // .text execute faults (rare but possible with virtualized targets) from
    // being misclassified as TLS entries.
    //
    // **Pascal ordering**: this is branch 4, checked AFTER outside-image (2)
    // and Themida-write (3) so those common faults never increment the TLS
    // counter.
    if exc_type == 8 && state.tls_total > 0 && state.tls_counter < state.tls_total {
        state.tls_counter += 1;
        info!(
            "TLS callback {}/{} at {:#x}",
            state.tls_counter, state.tls_total, exception_address
        );

        // Compute Themida section bounds.  Fall back to full image bounds if
        // no Themida section was identified.
        let (tm_start, tm_end) = match state.pe_info.themida_section {
            Some(idx) => {
                let sec = &state.pe_info.pe_sections[idx];
                (
                    image_base + sec.virtual_address as usize,
                    image_base + sec.virtual_address as usize + sec.virtual_size as usize,
                )
            }
            None => (image_base, image_boundary),
        };
        let tm_size = tm_end.saturating_sub(tm_start);

        // Switch guard region; allow read+write but disallow execute so the
        // executing TLS callback can run.
        // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
        unsafe {
            VirtualProtectEx(
                h_process,
                tm_start as *const std::ffi::c_void,
                tm_size,
                page_protect(PAGE_READWRITE),
                &mut old_protect,
            )
        }
        .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx FTMGuard set: {e}")))?;

        // Update state so next access in this new region re-installs .text guard.
        state.guard_start = tm_start;
        state.guard_end = tm_end;
        state.ftm_guard = true;

        // Tell the debug loop we've handled this access (no OEP yet, just TLS).
        return Ok(GuardAccessResult::TlsCallback {
            address: exception_address,
        });
    }

    // -- Branch 5: FTraceMSVCOEP -------------------------------------------------
    // In the MSVC VM OEP tracing mode: the next .text hit IS the
    // CRTStartup address.  Synthesize the OEP stub and finish unpacking.
    if state.trace_msvc_oep {
        info!(
            exception_addr = format_args!("{exception_address:#x}"),
            init_cookie = format_args!("{:#x}", state.msvc_init_cookie),
            oep = format_args!("{:#x}", state.msvc_oep),
            "FTraceMSVCOEP: reached __scrt_common_main_seh — writing MSVC OEP stub"
        );
        crate::oep::write_msvc_oep_x64(
            debugger,
            h_process,
            state.msvc_oep,
            state.msvc_init_cookie,
            exception_address,
        )?;
        // Signal that the MSVC OEP has been synthesized.  The caller should
        // exit the debug loop and proceed to IAT/shrink phases.
        return Ok(GuardAccessResult::MsvcTraceComplete {
            address: state.msvc_oep,
        });
    }

    // -- Branch 6: Potential OEP -------------------------------------------------
    // The faulting instruction is inside `.text` but no TLS callback and not
    // FTraceMSVCOEP mode.  Could be the real OEP, or it could be a virtualised
    // OEP that jumps back into the Themida VM.  Defer to the caller.
    debug!(
        "Possible OEP at {:#x} (fault_addr={:#x})",
        exception_address, fault_address
    );
    Ok(GuardAccessResult::PossibleOEP {
        address: exception_address,
    })
}

/// Re-apply the code-section guard after a single-step completes.
pub fn restore_code_section_guard(
    h_process: HANDLE,
    text_section_start: usize,
    text_section_size: usize,
    protection: u32,
) -> Result<(), ThemidaError> {
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
    unsafe {
        VirtualProtectEx(
            h_process,
            text_section_start as *const std::ffi::c_void,
            text_section_size,
            page_protect(protection),
            &mut old_protect,
        )
    }
    .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx in restore guard: {e}")))?;
    trace!("Code section guard restored (protection: {:#x})", protection);
    Ok(())
}

/// Permanently remove the code-section guard, restoring `PAGE_EXECUTE_READ`.
pub fn remove_code_section_guard(
    h_process: HANDLE,
    text_section_start: usize,
    text_section_size: usize,
) -> Result<(), ThemidaError> {
    let mut old_protect = PAGE_PROTECTION_FLAGS::default();
    // SAFETY: h_process is a valid process handle; iat_start/text_section_start is a valid virtual address; old_protect is a valid out-pointer.
    unsafe {
        VirtualProtectEx(
            h_process,
            text_section_start as *const std::ffi::c_void,
            text_section_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    }
    .map_err(|e| ThemidaError::Debugger(format!("VirtualProtectEx in remove guard: {e}")))?;
    debug!("Code section guard removed (restored to PAGE_EXECUTE_READ)");
    Ok(())
}

/// Check whether an address falls within the guarded code section.
#[inline]
#[must_use]
pub fn is_guarded_address(address: usize, guard_start: usize, guard_end: usize) -> bool {
    guard_start != 0 && address >= guard_start && address < guard_end
}

/// Switch to IAT monitoring mode.
///
/// After finding OEP, this function:
/// 1. Computes IAT and Themida section bounds.
/// 2. Sets up state for IAT write monitoring.
/// 3. Installs the IAT guard.
///
/// Returns the IAT bounds for the caller to use.
pub fn switch_to_iat_monitoring(
    h_process: HANDLE,
    state: &mut ThemidaState,
) -> Result<(usize, usize), ThemidaError> {
    // Compute IAT bounds from the IAT address stored in state.
    // The IAT address is determined by the caller and stored in guard_start/guard_end
    // or we can use the IAT location from the unpacker.
    let iat_addr = state.guard_start;
    let iat_size = state.guard_end - state.guard_start;

    if iat_size == 0 {
        return Err(ThemidaError::Debugger("IAT monitoring: IAT size is zero".into()));
    }

    // Install the IAT guard.
    install_iat_guard(h_process, iat_addr, iat_size)?;

    // Update state.
    state.iat_monitoring = true;

    info!(
        "IAT monitoring enabled: guard {:#x}–{:#x} ({} bytes)",
        iat_addr, iat_addr + iat_size, iat_size
    );

    Ok((iat_addr, iat_size))
}

/// Process an access violation while in IAT monitoring mode.
///
/// This is triggered when the Themida VM writes to the guarded IAT region.
/// We:
/// 1. Temporarily un-guard the IAT so the write can complete.
/// 2. Single-step to let the write instruction execute.
/// 3. Read the new value from the IAT slot.
/// 4. Record it if it looks like a valid API address.
/// 5. Re-guard the IAT for the next write.
///
/// Returns `Some(GuardAccessResult::IatReady)` when enough writes have been
/// detected to consider the IAT fully decrypted.
pub fn process_iat_monitoring_access(
    h_process: HANDLE,
    state: &mut ThemidaState,
    fault_address: usize,
    exception_address: usize,
    debugger: &dyn DebuggerCore,
    thread_id: u32,
) -> Result<Option<GuardAccessResult>, ThemidaError> {
    let iat_addr = state.guard_start;
    let iat_size = state.guard_end - state.guard_start;

    // Temporarily un-guard the IAT so the write can complete.
    let _old_protect = temporary_un_guard_iat(h_process, iat_addr, iat_size)?;

    // Set trap flag to single-step.
    enable_trap_flag(debugger, thread_id)?;

    // Continue execution - the write instruction will execute.
    // We'll get a single-step exception after the write.

    // For now, just record the fault and continue.
    // The actual IAT value will be read after the single-step.

    debug!(
        "IAT monitoring: write to {:#x} from {:#x}",
        fault_address, exception_address
    );

    // Check if we've seen enough writes to consider IAT ready.
    state.iat_total_writes += 1;
    state.iat_write_addresses.insert(fault_address);

    // Simple heuristic: if we've seen enough unique writes, consider ready.
    // A better approach would be to check if all non-zero slots have been written.
    if state.iat_write_addresses.len() as u32 >= state.iat_write_threshold
        || state.iat_total_writes >= state.iat_timeout_threshold
    {
        info!(
            "IAT monitoring: {} unique writes ({} total), considering IAT ready",
            state.iat_write_addresses.len(),
            state.iat_total_writes
        );
        state.iat_monitoring = false;
        return Ok(Some(GuardAccessResult::IatReady {
            address: fault_address,
        }));
    }

    // Not ready yet - continue monitoring.
    // The IAT will be re-guarded after the single-step.
    Ok(None)
}
///
/// After the OEP is reached, some Themida v3 binaries delay IAT decryption
/// until the program executes for a while.  This function switches the guard
/// from `.text` to the Themida section so that writes to the IAT (which
/// Themida performs during decryption) trigger access violations that we can
/// intercept.
///
/// The guard is set to `PAGE_READWRITE` (no execute) so that:
/// - The executing code (now past OEP, outside Themida section) can still run
/// - Writes to the Themida section trigger access violations we can count
///
/// Once enough writes are detected (`iat_write_count >= iat_write_threshold`),
/// the IAT is considered ready for tracing.
///
/// # Arguments
///
/// - `h_process` — handle to the target process.
/// - `image_base` — actual (ASLR-relocated) image base.
/// - `pe_sections` — PE section headers.
/// - `state` — mutable Themida state (updated with new guard bounds).
///
/// # Returns
///
/// The new `(guard_start, guard_end)` bounds.
fn enable_trap_flag(debugger: &dyn DebuggerCore, thread_id: u32) -> Result<(), ThemidaError> {
    // Use CONTEXT_CONTROL-only read to avoid ERROR_PARTIAL_COPY on
    // Themida-protected targets.  Only EFlags is modified; debug registers
    // are preserved by scoping ContextFlags to CONTEXT_CONTROL on write.
    let mut ctx = debugger.get_thread_context_control(thread_id)
        .map_err(|e| ThemidaError::Debugger(format!("get_thread_context_control for TF: {e}")))?;
    ctx.EFlags |= 0x100;
    // Re-scope ContextFlags to CONTROL only so SetThreadContext does not
    // clobber DR0-DR7 (which are zeroed in the narrow read).
    #[cfg(target_arch = "x86_64")]
    {
        ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_AMD64;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86;
    }
    debugger.set_thread_context(thread_id, &ctx)
        .map_err(|e| ThemidaError::Debugger(format!("set_thread_context for TF: {e}")))?;
    trace!(thread_id, "Trap flag (TF) set for single-step");
    Ok(())
}