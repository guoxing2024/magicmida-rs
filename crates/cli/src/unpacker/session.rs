//! Process session wrappers — RAII handles for the debuggee.
//!
//! - [`ResolvedApis`] — kernel32/ntdll addresses resolved in the debugger.
//! - [`ProcessSession`] — thin RAII wrapper around [`WindowsDebugger`].
//! - [`ReadOnlyProcessDebugger`] — read-only wrapper for `/dump-process`.
//! - [`get_thread_context_control`] / [`set_thread_context_control`] — fast
//!   CONTEXT_CONTROL-only context helpers (avoids `ERROR_PARTIAL_COPY`).

use anyhow::anyhow;
use windows::Win32::Foundation::HANDLE;

use mida_core::{
    ContinueStatus, CoreError, DebugEvent, DebuggerCore, WindowsDebugger,
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
/// All debug operations are delegated to the inner `WindowsDebugger` via
/// [`Deref`] / [`DerefMut`] — callers use standard `dbg.read_memory(...)`,
/// `dbg.set_hw_breakpoint(...)`, `dbg.wait_event()`, etc. without seeing the
/// wrapper.
pub struct ProcessSession {
    pub(super) dbg: WindowsDebugger,
    /// Resolved kernel32 / ntdll API addresses for the current session.
    pub(super) apis: Option<ResolvedApis>,
}

impl ProcessSession {
    /// Create a new session from an existing `WindowsDebugger`.
    pub(super) fn new(dbg: WindowsDebugger) -> Self {
        Self { dbg, apis: None }
    }
}

impl std::ops::Deref for ProcessSession {
    type Target = WindowsDebugger;

    fn deref(&self) -> &Self::Target {
        &self.dbg
    }
}

impl std::ops::DerefMut for ProcessSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.dbg
    }
}

impl std::fmt::Debug for ProcessSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Sanitise: avoid printing raw HANDLEs in logs.
        f.debug_struct("ProcessSession")
            .field("image_base", &format_args!("{:#x}", self.image_base()))
            .field("pid", &self.pid())
            .finish()
    }
}

impl DebuggerCore for ProcessSession {
    fn process_handle(&self) -> HANDLE {
        self.dbg.process_handle()
    }
    fn pid(&self) -> u32 {
        self.dbg.pid()
    }
    fn image_base(&self) -> u64 {
        self.dbg.image_base()
    }
    fn wait_event(&mut self) -> Result<DebugEvent, CoreError> {
        self.dbg.wait_event()
    }
    fn wait_event_timeout(&mut self, timeout_ms: u32) -> Result<DebugEvent, CoreError> {
        self.dbg.wait_event_timeout(timeout_ms)
    }
    fn continue_event(&mut self, thread_id: u32, status: ContinueStatus) -> Result<(), CoreError> {
        self.dbg.continue_event(thread_id, status)
    }
    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, CoreError> {
        self.dbg.read_memory(address, buf)
    }
    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, CoreError> {
        self.dbg.write_memory(address, data)
    }
    fn get_thread_context(
        &self,
        thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        self.dbg.get_thread_context(thread_id)
    }
    fn get_thread_context_control(
        &self,
        thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        self.dbg.get_thread_context_control(thread_id)
    }
    fn get_thread_context_control_integer(
        &self,
        thread_id: u32,
    ) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, CoreError> {
        self.dbg.get_thread_context_control_integer(thread_id)
    }
    fn set_thread_context(
        &self,
        thread_id: u32,
        ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
    ) -> Result<(), CoreError> {
        self.dbg.set_thread_context(thread_id, ctx)
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
    use windows::Win32::System::Diagnostics::Debug::{CONTEXT_CONTROL_AMD64, GetThreadContext};

    let h = dbg.thread_handle(thread_id).map_err(|e| anyhow!("{e}"))?;
    let mut ctx: windows::Win32::System::Diagnostics::Debug::CONTEXT =
        unsafe { std::mem::zeroed() };
    #[cfg(target_arch = "x86_64")]
    {
        ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
    }
    #[cfg(target_arch = "x86")]
    {
        ctx.ContextFlags = windows::Win32::System::Diagnostics::Debug::CONTEXT_CONTROL_X86;
    }
    unsafe {
        GetThreadContext(h, &mut ctx)
            .map_err(|e| anyhow!("GetThreadContext failed: {e}"))?;
    }
    Ok(ctx)
}

/// Fast `SetThreadContext` with pre-filled `CONTEXT_CONTROL` flags.
pub(super) fn set_thread_context_control(
    dbg: &ProcessSession,
    thread_id: u32,
    ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT,
) -> Result<(), anyhow::Error> {
    use windows::Win32::System::Diagnostics::Debug::SetThreadContext;

    let h = dbg.thread_handle(thread_id).map_err(|e| anyhow!("{e}"))?;
    unsafe {
        SetThreadContext(h, ctx)
            .map_err(|e| anyhow!("SetThreadContext failed: {e}"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ReadOnlyProcessDebugger
// ---------------------------------------------------------------------------

/// A read-only [`DebuggerCore`] wrapper over an `OpenProcess` handle.
///
/// Only [`read_memory`](DebuggerCore::read_memory) is implemented; all other
/// methods return an error code matching the pattern in `mida_core::CoreError`.
pub(super) struct ReadOnlyProcessDebugger {
    pub(super) h_process: HANDLE,
    pub(super) image_base: u64,
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

    fn write_memory(
        &mut self,
        _address: usize,
        _data: &[u8],
    ) -> Result<usize, CoreError> {
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
