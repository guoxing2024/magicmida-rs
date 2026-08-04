//! Process session wrappers — RAII handles for the debuggee.
//!
//! - [`ResolvedApis`] — kernel32/ntdll addresses resolved in the debugger.
//! - [`ProcessSession`] — unpack session: wait/continue via [`DebuggerCoreEngine`]
//!   (R2 pump), other ops via [`WindowsDebugger`] Deref.
//! - [`ReadOnlyProcessDebugger`] — read-only wrapper for `/dump-process`.
//! - [`get_thread_context_control`] / [`set_thread_context_control`] — fast
//!   CONTEXT_CONTROL-only context helpers (avoids `ERROR_PARTIAL_COPY`).

use anyhow::anyhow;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

use mida_core::{
    ContinueStatus, CoreError, DebugEvent, DebuggerCore, DebuggerCoreEngine, EngineEvent,
    RuntimeEngine, WindowsDebugger,
};

// ---------------------------------------------------------------------------
// ResolvedApis
// ---------------------------------------------------------------------------

/// Resolved kernel32 API addresses (from the debugger's own address space).
///
/// On x64, kernel32.dll is loaded at the same base address in every process
/// (ASLR is per-boot, not per-process), so addresses resolved in the debugger
/// process are also valid in the debuggee.
pub(super) struct ResolvedApis {
    /// kernel32!CloseHandle — actual API, may be bypassed by Themida v3 (syscalls)
    pub(super) close_handle: usize,
    /// kernel32!VirtualAlloc — actual API, may be bypassed by Themida v3
    pub(super) virtual_alloc: usize,
    /// ntdll!NtClose — the syscall stub Themida v3 uses directly
    pub(super) nt_close: usize,
    /// ntdll!NtAllocateVirtualMemory — the syscall stub Themida v3 uses directly
    pub(super) nt_allocate_virtual_memory: usize,
    /// ntdll!NtProtectVirtualMemory — Themida uses this to remove PAGE_NOACCESS
    /// from .text before writing decrypted code. We intercept it to keep the
    /// guard alive.
    pub(super) nt_protect_virtual_memory: usize,
    /// kernel32!Sleep — anti-trace detection helper
    pub(super) sleep: usize,
    /// kernel32!lstrlen — anti-trace detection helper
    pub(super) lstrlen: usize,
}

// ---------------------------------------------------------------------------
// ProcessSession
// ---------------------------------------------------------------------------

/// Owns the core [`WindowsDebugger`] for the lifetime of an unpack session.
///
/// Wait/continue go through [`DebuggerCoreEngine`] (R2 pump). All other debug
/// operations are delegated to the inner `WindowsDebugger` via [`Deref`] /
/// [`DerefMut`] — callers use standard `dbg.read_memory(...)`,
/// `dbg.set_hw_breakpoint(...)`, `dbg.wait_event()`, etc. without seeing the
/// wrapper.
pub struct ProcessSession {
    eng: DebuggerCoreEngine<WindowsDebugger>,
    /// Resolved kernel32 / ntdll API addresses for the current session.
    pub(super) apis: Option<ResolvedApis>,
}

impl ProcessSession {
    /// Create a new session from an existing `WindowsDebugger`.
    pub(super) fn new(dbg: WindowsDebugger) -> Self {
        Self {
            eng: DebuggerCoreEngine::new(dbg),
            apis: None,
        }
    }

    /// R2 engine sequence of the last delivered event (0 if none).
    #[allow(dead_code)]
    pub(super) fn engine_sequence(&self) -> u64 {
        self.eng.last_sequence()
    }

    /// Whether the engine still holds a pending (waited, not continued) event.
    #[allow(dead_code)]
    pub(super) fn engine_has_pending(&self) -> bool {
        self.eng.has_pending()
    }

    /// Wait for the next debug event via the R2 engine (keeps sequence stamp).
    ///
    /// Prefer this when the host must consult [`mida_core::PackerPlugin::on_event`]
    /// with a full [`EngineEvent`]. Call sites that only need [`DebugEvent`] can
    /// keep using [`DebuggerCore::wait_event`].
    pub(super) fn wait_engine(
        &mut self,
        timeout_ms: Option<u32>,
    ) -> Result<EngineEvent, CoreError> {
        self.eng.wait(timeout_ms)
    }

    /// Continue the event currently owned by the engine using its recorded
    /// raw thread identity. This is required for abstract ExitProcess events,
    /// which intentionally do not carry a TID.
    pub(super) fn continue_pending_event(
        &mut self,
        status: ContinueStatus,
    ) -> Result<(), CoreError> {
        self.eng.continue_event(status)
    }
}

impl std::ops::Deref for ProcessSession {
    type Target = WindowsDebugger;

    fn deref(&self) -> &Self::Target {
        self.eng.backend()
    }
}

impl std::ops::DerefMut for ProcessSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.eng.backend_mut()
    }
}

impl std::fmt::Debug for ProcessSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sanitise: avoid printing raw HANDLEs in logs.
        f.debug_struct("ProcessSession")
            .field("image_base", &format_args!("{:#x}", self.image_base()))
            .field("pid", &self.pid())
            .field("engine_seq", &self.eng.last_sequence())
            .finish()
    }
}

impl DebuggerCore for ProcessSession {
    fn process_handle(&self) -> HANDLE {
        self.eng.backend().process_handle()
    }
    fn pid(&self) -> u32 {
        self.eng.backend().pid()
    }
    fn image_base(&self) -> u64 {
        self.eng.backend().image_base()
    }
    fn pending_event_thread_id(&self) -> Option<u32> {
        self.eng.backend().pending_event_thread_id()
    }
    fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
        // R2 pump: sequence stamp + pending pairing; drop stamp for call-site API.
        Ok(self.eng.wait(None)?.event)
    }
    fn wait_event_timeout(&mut self, timeout_ms: u32) -> Result<DebugEvent, CoreError> {
        Ok(self.eng.wait(Some(timeout_ms))?.event)
    }
    fn continue_event(&mut self, thread_id: u32, status: ContinueStatus) -> Result<(), CoreError> {
        // Forward caller's tid so Windows lifecycle validation stays identical.
        self.eng.continue_with_thread(thread_id, status)
    }
    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        self.eng.backend().read_memory(address, buf)
    }
    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, CoreError> {
        self.eng.backend_mut().write_memory(address, data)
    }
    fn get_thread_context(
        &self,
        thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        self.eng.backend().get_thread_context(thread_id)
    }
    fn get_thread_context_control(
        &self,
        thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        self.eng.backend().get_thread_context_control(thread_id)
    }
    fn get_thread_context_control_integer(
        &self,
        thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        self.eng
            .backend()
            .get_thread_context_control_integer(thread_id)
    }
    fn set_thread_context(
        &self,
        thread_id: u32,
        ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> Result<(), CoreError> {
        self.eng.backend().set_thread_context(thread_id, ctx)
    }
}

// ---------------------------------------------------------------------------
// CONTEXT_CONTROL fast-path helpers
// ---------------------------------------------------------------------------

/// Fast `GetThreadContext` with `CONTEXT_CONTROL` only.
///
/// Avoids `ERROR_PARTIAL_COPY` on protector-packaged targets where
/// `CONTEXT_ALL` triggers a partial-copy error even though the kernel has
/// successfully filled the control registers.
pub(super) fn get_thread_context_control(
    dbg: &ProcessSession,
    thread_id: u32,
) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, anyhow::Error> {
    use windows::Win32::System::Diagnostics::Debug::{GetThreadContext, CONTEXT_CONTROL_AMD64};

    let h = dbg.thread_handle(thread_id).map_err(|e| anyhow!("{e}"))?;
    let mut ctx: windows::Win32::System::Diagnostics::Debug::CONTEXT =
        // SAFETY: CONTEXT is repr(C); zeroing produces a valid all-zero struct that GetThreadContext will populate.
        unsafe { std::mem::zeroed() };
    #[cfg(target_arch = "x86_64")]
    {
        ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86;
    }
    // SAFETY: h is a valid thread handle with THREAD_GET_CONTEXT rights; ctx is a writable CONTEXT initialised with the right flags.
    unsafe {
        GetThreadContext(h, &mut ctx).map_err(|e| anyhow!("GetThreadContext failed: {e}"))?;
    }
    Ok(ctx)
}

/// Fast `SetThreadContext` with forced `CONTEXT_CONTROL` flags.
///
/// Themida/Win11 paths sometimes fail `SetThreadContext` with
/// `ERROR_NOACCESS` (0x800703E6) when ContextFlags are incomplete or when the
/// thread briefly leaves a stoppable state after ScyllaHide injection.  We:
/// 1. force CONTROL flags on a local copy,
/// 2. try once,
/// 3. on failure SuspendThread + retry once,
/// 4. surface a structured error for callers that can soft-fail.
pub(super) fn set_thread_context_control(
    dbg: &ProcessSession,
    thread_id: u32,
    ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
) -> Result<(), anyhow::Error> {
    use windows::Win32::System::Diagnostics::Debug::{SetThreadContext, CONTEXT_CONTROL_AMD64};
    use windows::Win32::System::Threading::{ResumeThread, SuspendThread};

    let h = dbg.thread_handle(thread_id).map_err(|e| anyhow!("{e}"))?;
    let mut local = *ctx;
    #[cfg(target_arch = "x86_64")]
    {
        local.ContextFlags = CONTEXT_CONTROL_AMD64;
    }
    #[cfg(target_arch = "x86")]
    {
        local.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86;
    }

    // SAFETY: h is a valid thread handle with THREAD_SET_CONTEXT rights; local
    // is a fully populated CONTEXT with CONTROL flags forced.
    let first = unsafe { SetThreadContext(h, &local) };
    if first.is_ok() {
        return Ok(());
    }
    let first_err = first.err().map(|e| e.to_string()).unwrap_or_default();

    // Soft retry: suspend, set again, resume.  Debugged threads are usually
    // already stopped; Suspend is best-effort for races with injector/remote
    // threads that briefly run between AV dispatch and our Set.
    let suspended = unsafe { SuspendThread(h) };
    let second = unsafe { SetThreadContext(h, &local) };
    if suspended != u32::MAX {
        let _ = unsafe { ResumeThread(h) };
    }

    match second {
        Ok(()) => {
            tracing::warn!(
                thread_id,
                first_err = %first_err,
                "SetThreadContext CONTROL succeeded after SuspendThread retry"
            );
            Ok(())
        }
        Err(e) => Err(anyhow!(
            "SetThreadContext failed: {e} (first_attempt={first_err}; suspend={suspended})"
        )),
    }
}

// ---------------------------------------------------------------------------
// ReadOnlyProcessDebugger
// ---------------------------------------------------------------------------

/// A read-only [`DebuggerCore`] wrapper over an `OpenProcess` handle.
///
/// Only [`read_memory`](DebuggerCore::read_memory) is implemented; all other
/// methods return an error code matching the pattern in `mida_core::CoreError`.
///
/// The process handle is owned by this struct and is closed automatically in
/// [`Drop`] — early-return paths (`?` propagation) no longer leak the handle.
pub(super) struct ReadOnlyProcessDebugger {
    pub(super) h_process: HANDLE,
    pub(super) image_base: u64,
}

impl ReadOnlyProcessDebugger {
    /// Wrap an already-opened process handle.
    ///
    /// Ownership of `h_process` transfers to the returned struct; it will be
    /// closed on drop.
    pub(super) fn new(h_process: HANDLE, image_base: u64) -> Self {
        Self {
            h_process,
            image_base,
        }
    }
}

impl Drop for ReadOnlyProcessDebugger {
    fn drop(&mut self) {
        // SAFETY: h_process was obtained from OpenProcess and is valid until
        // closed here; CloseHandle is safe to call exactly once.
        if !self.h_process.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.h_process);
            }
        }
    }
}

impl std::fmt::Debug for ReadOnlyProcessDebugger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadOnlyProcessDebugger")
            .field("h_process", &format_args!("{:?}", self.h_process))
            .field("image_base", &format_args!("{:#x}", self.image_base))
            .finish()
    }
}

impl DebuggerCore for ReadOnlyProcessDebugger {
    fn process_handle(&self) -> HANDLE {
        self.h_process
    }

    fn pid(&self) -> u32 {
        0
    }

    fn image_base(&self) -> u64 {
        self.image_base
    }

    fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
        Err(CoreError::Windows(0))
    }

    fn wait_event_timeout(&mut self, _timeout_ms: u32) -> Result<DebugEvent, CoreError> {
        Err(CoreError::Windows(0))
    }

    fn continue_event(
        &mut self,
        _thread_id: u32,
        _status: ContinueStatus,
    ) -> Result<(), CoreError> {
        Err(CoreError::Windows(0))
    }

    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

        let mut bytes_read: usize = 0;
        // SAFETY: h_process is a valid process handle obtained from OpenProcess;
        // buf is valid for its length; address is a valid virtual address.
        unsafe {
            ReadProcessMemory(
                self.h_process,
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

    fn write_memory(&mut self, _address: usize, _data: &[u8]) -> Result<usize, CoreError> {
        Err(CoreError::MemoryWrite {
            address: _address as u64,
            requested: _data.len(),
        })
    }

    fn get_thread_context(
        &self,
        _thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        Err(CoreError::Windows(0))
    }

    fn get_thread_context_control(
        &self,
        _thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        Err(CoreError::Windows(0))
    }

    fn get_thread_context_control_integer(
        &self,
        _thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        Err(CoreError::Windows(0))
    }

    fn set_thread_context(
        &self,
        _thread_id: u32,
        _ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> Result<(), CoreError> {
        Err(CoreError::Windows(0))
    }
}
