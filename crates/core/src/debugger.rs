//! Debug event loop types and the [`DebuggerCore`] trait.
//!
//! This module defines the debug-event model and the trait that every debugger
//! backend must implement. The design mirrors the Windows debug event API
//! (`WaitForDebugEvent` / `ContinueDebugEvent`) but keeps the abstraction
//! generic enough that a future non-Windows backend (or a test mock) could
//! implement the same trait.

use std::fmt;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::CONTEXT;

use crate::error::CoreError;

/// Status returned to Windows by `ContinueDebugEvent`.
///
/// Corresponds to the `dwContinueStatus` parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ContinueStatus {
    /// Resume execution normally (`DBG_CONTINUE` = `0x00010002`).
    Continue = 0x0001_0002,
    /// Signal end-of-debug-session (`DBG_CONTROL_BREAK` = `0x40010008`).
    ContinueNoStep = 0x4001_0008,
}

// ---------------------------------------------------------------------------
// DebugEvent
// ---------------------------------------------------------------------------

/// A decoded debug event produced by [`DebuggerCore::wait_event`].
///
/// Each variant carries the fields that the unpacker needs to decide on its
/// next action. Handles that must be explicitly closed (`h_file` in
/// `CreateProcess` and `LoadDll`) are passed through so the caller can close
/// them.
pub enum DebugEvent {
    /// A breakpoint exception (hardware or software `int3`).
    Breakpoint {
        /// Thread that hit the breakpoint.
        thread_id: u32,
        /// Address where the exception was raised.
        address: u64,
    },

    /// A single-step trap-flag hit (used to step over a temporarily disabled
    /// hardware breakpoint or to re-enable a software breakpoint).
    SingleStep {
        /// Thread that took the single step.
        thread_id: u32,
        /// Address at which the single-step fired (EIP/RIP after stepping).
        address: u64,
    },

    /// An access-violation exception (`EXCEPTION_ACCESS_VIOLATION`).
    AccessViolation {
        /// Thread that caused the violation.
        thread_id: u32,
        /// Address of the faulting instruction.
        address: u64,
        /// `true` when the violation was a write; `false` for a read.
        is_write: bool,
        /// The target address that was accessed.
        target_address: u64,
        /// Value of `ExceptionInformation[0]` from the exception record — the
        /// access type.  Known values: `0` (read), `1` (write), `8` (execute)
        /// inside `.text`.  Themida uses the execute path to drive TLS
        /// callbacks; the guard code relies on detecting `8` to enter FTMGuard
        /// mode (matching `Themida64.pas`'s
        /// `ExcRecord.ExceptionInformation[0] = 8` check).
        exc_type: u8,
    },

    /// The target process has been created and the initial breakpoint was hit.
    /// The caller **must** close `h_file` via
    /// [`CloseHandle`](windows::Win32::Foundation::CloseHandle) after handling
    /// this event.
    CreateProcess {
        /// Debuggee process ID.
        process_id: u32,
        /// Initial thread ID.
        thread_id: u32,
        /// Image base address read from the PEB.
        image_base: u64,
        /// Handle to the initial thread — store for later context operations.
        h_thread: windows::Win32::Foundation::HANDLE,
        /// Handle to the process — store for memory read/write.
        h_process: windows::Win32::Foundation::HANDLE,
        /// Handle to the process image file — **must close** after this event.
        h_file: windows::Win32::Foundation::HANDLE,
    },

    /// A new thread was created in the debuggee.
    CreateThread {
        /// New thread ID.
        thread_id: u32,
        /// Handle to the new thread — store for later context operations.
        h_thread: windows::Win32::Foundation::HANDLE,
        /// Thread start address reported by `lpStartAddress`.
        start_address: u64,
    },

    /// A thread in the debuggee has exited.
    ExitThread {
        /// Thread that exited.
        thread_id: u32,
        /// Thread exit code.
        exit_code: u32,
    },

    /// A DLL was loaded into the debuggee's address space.
    /// The caller **must** close `h_file` after handling this event.
    LoadDll {
        /// Thread that triggered the load.
        thread_id: u32,
        /// Base address where the DLL was mapped.
        base_address: u64,
        /// Handle to the DLL image file — **must close** after this event.
        h_file: windows::Win32::Foundation::HANDLE,
    },

    /// A DLL was unloaded from the debuggee's address space.
    UnloadDll {
        /// Thread that triggered the unload.
        thread_id: u32,
        /// Base address that was freed.
        base_address: u64,
    },

    /// The debuggee process has exited. The debug loop should terminate after
    /// processing this event.
    ExitProcess {
        /// Process exit code.
        exit_code: u32,
    },

    /// An event that does not require special handling (e.g.
    /// `OUTPUT_DEBUG_STRING`, `RIP_EVENT`, or an unhandled exception code).
    /// The caller should simply resume the thread.
    Other {
        /// Thread that reported the event.
        thread_id: u32,
    },
}

// Manual Debug impl to sanitise HANDLE fields (Guideline: public types
// containing handles/pointers must implement Debug with sanitisation).
impl fmt::Debug for DebugEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Breakpoint { thread_id, address } => f
                .debug_struct("Breakpoint")
                .field("thread_id", thread_id)
                .field("address", &format_args!("{address:#x}"))
                .finish(),
            Self::SingleStep { thread_id, address } => f
                .debug_struct("SingleStep")
                .field("thread_id", thread_id)
                .field("address", &format_args!("{address:#x}"))
                .finish(),
            Self::AccessViolation {
                thread_id,
                address,
                is_write,
                target_address,
                exc_type,
            } => f
                .debug_struct("AccessViolation")
                .field("thread_id", thread_id)
                .field("address", &format_args!("{address:#x}"))
                .field("is_write", is_write)
                .field("target_address", &format_args!("{target_address:#x}"))
                .field("exc_type", &format_args!("{exc_type}"))
                .finish(),
            Self::CreateProcess {
                process_id,
                thread_id,
                image_base,
                h_thread,
                h_process,
                h_file,
            } => f
                .debug_struct("CreateProcess")
                .field("process_id", process_id)
                .field("thread_id", thread_id)
                .field("image_base", &format_args!("{image_base:#x}"))
                .field("h_thread", &format_args!("{h_thread:?}"))
                .field("h_process", &format_args!("{h_process:?}"))
                .field("h_file", &format_args!("{h_file:?}"))
                .finish(),
            Self::CreateThread {
                thread_id,
                h_thread,
                start_address,
            } => f
                .debug_struct("CreateThread")
                .field("thread_id", thread_id)
                .field("h_thread", &format_args!("{h_thread:?}"))
                .field("start_address", &format_args!("{start_address:#x}"))
                .finish(),
            Self::ExitThread {
                thread_id,
                exit_code,
            } => f
                .debug_struct("ExitThread")
                .field("thread_id", thread_id)
                .field("exit_code", exit_code)
                .finish(),
            Self::LoadDll {
                thread_id,
                base_address,
                h_file,
            } => f
                .debug_struct("LoadDll")
                .field("thread_id", thread_id)
                .field("base_address", &format_args!("{base_address:#x}"))
                .field("h_file", &format_args!("{h_file:?}"))
                .finish(),
            Self::UnloadDll {
                thread_id,
                base_address,
            } => f
                .debug_struct("UnloadDll")
                .field("thread_id", thread_id)
                .field("base_address", &format_args!("{base_address:#x}"))
                .finish(),
            Self::ExitProcess { exit_code } => f
                .debug_struct("ExitProcess")
                .field("exit_code", exit_code)
                .finish(),
            Self::Other { thread_id } => f
                .debug_struct("Other")
                .field("thread_id", thread_id)
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// DebuggerCore trait
// ---------------------------------------------------------------------------

/// The core debugger interface.
///
/// Every backend (real Windows debug loop, test mock, …) implements this
/// trait. The unpacker logic in the `packers` crate is programmed against this
/// trait so it never touches `WaitForDebugEvent` / `ContinueDebugEvent`
/// directly.
pub trait DebuggerCore {
    /// Return the target process handle (`PROCESS_VM_READ | ...`).
    ///
    /// Used by modules that need to call Windows APIs (e.g. ToolHelp
    /// snapshots) on the target process directly.
    fn process_handle(&self) -> HANDLE;

    /// Return the target process ID.
    fn pid(&self) -> u32;

    /// Return the image base discovered during `CREATE_PROCESS_DEBUG_EVENT`.
    ///
    /// This is the ASLR-reloaded base address, which may differ from the
    /// PE header's `ImageBase` field.
    fn image_base(&self) -> u64;

    /// Block until the next debug event arrives from the target process.
    ///
    /// Returns `Ok(DebugEvent::ExitProcess { .. })` when the target exits
    /// normally. On a Windows API failure this returns
    /// [`CoreError::Windows`].
    fn wait_event(&mut self) -> Result<DebugEvent, CoreError>;

    /// Wait for the next debug event with a timeout.
    ///
    /// Returns `Ok(event)` if an event arrived within the timeout.
    /// Returns `Err(CoreError::Timeout)` if the timeout expired with no event.
    /// Returns `Err(CoreError::Windows)` on a Windows API failure.
    fn wait_event_timeout(&mut self, timeout_ms: u32) -> Result<DebugEvent, CoreError> {
        // Default implementation: fall back to blocking wait.
        let _ = timeout_ms;
        self.wait_event()
    }

    /// Resume the target thread that reported the last event.
    ///
    /// `thread_id` comes from the current [`DebugEvent`] variant.  `status`
    /// controls whether execution continues normally or the session is
    /// terminated.
    fn continue_event(
        &mut self,
        thread_id: u32,
        status: ContinueStatus,
    ) -> Result<(), CoreError>;

    /// Read `buf.len()` bytes from the target's virtual address space starting
    /// at `address`.
    ///
    /// Returns the number of bytes actually read. Fewer bytes than requested
    /// **does not** automatically indicate an error (partial reads at page
    /// boundaries are normal), but callers should check the returned length.
    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, CoreError>;

    /// Write `data` to the target's virtual address space at `address`.
    ///
    /// Returns the number of bytes actually written.
    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, CoreError>;

    /// Read the full thread context for `thread_id`.
    ///
    /// The returned [`CONTEXT`] includes control, integer, and debug
    /// registers (equivalent to `CONTEXT_CONTROL | CONTEXT_INTEGER |
    /// CONTEXT_DEBUG_REGISTERS`).
    ///
    /// **NOTE**: On Themida-protected targets this may fail with
    /// `ERROR_PARTIAL_COPY`.  Prefer [`get_thread_context_control`](Self::get_thread_context_control)
    /// when only Rip/Rsp/EFlags are needed.
    fn get_thread_context(&self, thread_id: u32) -> Result<CONTEXT, CoreError>;

    /// Read only the control portion (Rip, Rsp, EFlags, SegCs, SegSs) of the
    /// given thread's context.
    ///
    /// This scopes the kernel request to `CONTEXT_CONTROL`, avoiding
    /// `ERROR_PARTIAL_COPY` that the full `CONTEXT_ALL` request triggers on
    /// threads belonging to targets whose protector mutates thread/TEB/PEB-Ldr
    /// state during early ntdll init.
    fn get_thread_context_control(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        // Default: fall back to full context read.  Backends that can provide
        // a narrower read should override.
        self.get_thread_context(thread_id)
    }

    /// Read the control and integer portions (Rip, Rsp, EFlags, Rax, etc.) of
    /// the given thread's context.
    ///
    /// This is narrower than [`get_thread_context`](Self::get_thread_context)
    /// (it excludes debug and floating-point registers) and is used by
    /// anti-debug bypasses that need to fake syscall return values in Rax/Eax
    /// while also adjusting the stack and instruction pointer.
    fn get_thread_context_control_integer(&self, thread_id: u32) -> Result<CONTEXT, CoreError> {
        // Default: fall back to full context read.
        self.get_thread_context(thread_id)
    }

    /// Write a modified thread context back to the thread identified by
    /// `thread_id`.
    ///
    /// Typically called after adjusting EIP/RIP, eflags, or debug registers
    /// (DR0–DR7) inside the [`CONTEXT`] struct returned by
    /// [`get_thread_context`](Self::get_thread_context).
    fn set_thread_context(&self, thread_id: u32, ctx: &CONTEXT) -> Result<(), CoreError>;
}
