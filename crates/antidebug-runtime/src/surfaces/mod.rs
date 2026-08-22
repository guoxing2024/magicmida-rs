//! Anti-debug surface implementations (ADR-5).
//!
//! ADR-5 ships the two hard-required PEB surfaces:
//!
//! - AD-PROC-002: PEB.BeingDebugged
//! - AD-PROC-003: PEB.pShimData
//!
//! AD-PROC-001 remains a `required_candidate`; this module never installs
//! it and never promotes it (profile revision / evidence / audit rules of
//! ADR-3 apply before any promotion).

pub mod proc;
pub mod win32;

pub use proc::{
    install_proc_002, install_proc_003, install_proc_004, install_proc_005, install_proc_surfaces,
    restore_proc_002, restore_proc_003, PebMemory, PebView, RestorationPolicy, RestoreResult,
    SurfaceError, SurfaceInstallOutcome, HEAP_OFFSET_FLAGS, HEAP_OFFSET_FORCE_FLAGS,
    NT_GLOBAL_FLAG_CLEAN, NT_GLOBAL_FLAG_DEBUGGER, PEB_OFFSET_BEING_DEBUGGED,
    PEB_OFFSET_NT_GLOBAL_FLAG, PEB_OFFSET_PROCESS_HEAP, PEB_OFFSET_PSHIM_DATA, POINTER_SIZE_X64,
    SURFACE_AD_PROC_001, SURFACE_AD_PROC_002, SURFACE_AD_PROC_003, SURFACE_AD_PROC_004,
    SURFACE_AD_PROC_005,
};
pub use win32::Win32PebMemory;
