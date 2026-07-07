//! Hardware and software breakpoint types.
//!
//! Corresponds to `TBreakpoint` / `THWBPType` / `TSoftBPAction` in the
//! reference Pascal implementation (`DebuggerCore.pas`).

/// Hardware breakpoint type, matching the x86 debug-register encoding.
///
/// The numeric values map to the corresponding bits in DR7 (LEN/RW fields).
/// `Execute` = 0, `Write` = 1, `Access` = 3.  `Reserved` (= 2) is intentionally
/// not exposed because I/O breakpoints are unavailable in user mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HwbpType {
    /// Break on instruction execution.
    Execute = 0,
    /// Break on writes to the address.
    Write = 1,
    /// Break on reads and writes to the address.
    Access = 3,
}

/// A single hardware breakpoint, backed by one of the four debug address
/// registers (DR0–DR3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HwBreakpoint {
    /// Linear virtual address to break on.
    pub address: u64,
    /// Type of access that triggers the breakpoint.
    pub bp_type: HwbpType,
    /// When `true`, the breakpoint is temporarily disabled (still occupies a
    /// slot but does not fire).
    pub disabled: bool,
}

impl HwBreakpoint {
    /// Create a new enabled hardware breakpoint.
    pub fn new(address: usize, bp_type: HwbpType) -> Self {
        Self {
            address: address as u64,
            bp_type,
            disabled: false,
        }
    }

    /// Create an empty (unused) breakpoint slot.
    pub fn empty() -> Self {
        Self {
            address: 0,
            bp_type: HwbpType::Execute,
            disabled: false,
        }
    }

    /// Returns `true` when the breakpoint is configured and enabled.
    ///
    /// Equivalent to `TBreakpoint.IsSet` in the Pascal reference.
    pub fn is_set(&self) -> bool {
        !self.disabled && self.address > 0
    }
}

/// Action to take after handling a software breakpoint (int3).
///
/// Corresponds to `TSoftBPAction` in the Pascal reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftBpAction {
    /// Keep the breakpoint active; resume execution normally.
    KeepContinue,
    /// Remove the breakpoint permanently; resume execution normally.
    ClearContinue,
    /// Keep the breakpoint active but do not single-step over it
    /// (the handler already adjusted EIP/RIP).
    KeepContinueNoStep,
}
