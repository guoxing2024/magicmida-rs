//! AD-PROC-002 / AD-PROC-003 PEB surfaces (ADR-5).
//!
//! AD-PROC-002: PEB.BeingDebugged (offset 0x02, BYTE)
//! AD-PROC-003: PEB.pShimData   (offset 0x2D8, PVOID; x64 authority layout from
//!               crates/core/src/process.rs PEB_SHIM_DATA_OFFSET)
//!
//! ## x64-only contract
//!
//! - pointer_size must be 8; x86 / WOW64 / unknown widths are rejected.
//! - All PEB address arithmetic uses checked_add / checked_sub; unchecked
//!   pointer math is forbidden.
//! - Field offsets follow the repository authority layout
//!   (crates/core/src/process.rs): BeingDebugged at 0x02, pShimData at
//!   0x2D8 on x64. Every access validates read/write accessibility first.
//! - On any failure the surface reports a structured error and is NOT
//!   reported as installed.
//!
//! ## Modification and restoration
//!
//! - AD-PROC-002: zeroes BeingDebugged (or restores original if it was
//!   already non-zero). original/effective/restoration are all recorded.
//! - AD-PROC-003: pShimData is ZEROED when non-zero (hard-required;
//!   ADR-2 probe catalog: pShimData must be 0), then read back to confirm
//!   effective_value == 0; original value is restored on shutdown.
//! - Restoration runs on shutdown and its result enters telemetry; a failed
//!   restore is a fail-closed state (CleanupFailed path), never a silent
//!   Drop side-effect.

use serde::{Deserialize, Serialize};

/// x64 pointer width (bytes).
pub const POINTER_SIZE_X64: usize = 8;

/// x64 PEB field offsets (public x64 Windows ABI).
pub const PEB_OFFSET_BEING_DEBUGGED: u64 = 0x02;
/// x64 pShimData offset (authority: crates/core/src/process.rs
/// PEB_SHIM_DATA_OFFSET = 0x2D8 for x86_64). 0x08 is NOT pShimData.
pub const PEB_OFFSET_PSHIM_DATA: u64 = 0x2D8;

/// Surface ids.
pub const SURFACE_AD_PROC_002: &str = "AD-PROC-002";
pub const SURFACE_AD_PROC_003: &str = "AD-PROC-003";
/// Candidate surface (never installed by ADR-5; observation-only).
pub const SURFACE_AD_PROC_001: &str = "AD-PROC-001";

/// Restoration policies for modified surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestorationPolicy {
    /// Surface is observation-only; no write is performed.
    ObserveOnly,
    /// Original value is restored on shutdown.
    RestoreOriginal,
    /// Surface is zeroed on install and kept zero (no restore needed).
    ZeroKeep,
}

/// Result of a restoration attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreResult {
    NotApplicable,
    Restored,
    Failed,
}

/// A single surface installation outcome (full state record).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceInstallOutcome {
    pub surface_id: String,
    pub installed: bool,
    /// Raw value observed before any modification.
    pub original_value: Option<String>,
    /// Value in effect after install (post-modification).
    pub effective_value: Option<String>,
    pub restoration_policy: RestorationPolicy,
    pub restore_result: RestoreResult,
    /// Structured failure reason (None when installed).
    pub error: Option<String>,
}

impl SurfaceInstallOutcome {
    /// Build a successful outcome for a modified surface.
    pub fn success(
        surface_id: impl Into<String>,
        original_value: String,
        effective_value: String,
        restoration_policy: RestorationPolicy,
    ) -> Self {
        Self {
            surface_id: surface_id.into(),
            installed: true,
            original_value: Some(original_value),
            effective_value: Some(effective_value),
            restoration_policy,
            restore_result: RestoreResult::NotApplicable,
            error: None,
        }
    }

    /// Build a failure outcome.
    pub fn failure(surface_id: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            surface_id: surface_id.into(),
            installed: false,
            original_value: None,
            effective_value: None,
            restoration_policy: RestorationPolicy::ObserveOnly,
            restore_result: RestoreResult::NotApplicable,
            error: Some(error.into()),
        }
    }

    /// Build an observation-only outcome (pShimData observation).
    pub fn observation(surface_id: impl Into<String>, original_value: String) -> Self {
        Self {
            surface_id: surface_id.into(),
            installed: true,
            original_value: Some(original_value.clone()),
            effective_value: Some(original_value),
            restoration_policy: RestorationPolicy::ObserveOnly,
            restore_result: RestoreResult::NotApplicable,
            error: None,
        }
    }
}
/// Abstract PEB memory access (injectable for synthetic fixtures).
pub trait PebMemory {
    /// Read len bytes at addr (absolute address). Fail if not readable.
    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, String>;
    /// Write data at addr. Fail if not writable.
    fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<(), String>;
    /// Probe whether addr..addr+len is readable.
    fn is_readable(&self, addr: u64, len: usize) -> bool;
    /// Probe whether addr..addr+len is writable.
    fn is_writable(&self, addr: u64, len: usize) -> bool;
    /// Resolve the PEB base for a pid (synthetic fixtures return their own).
    fn peb_base(&self, pid: u32) -> Result<u64, String>;
}

/// Surface installation errors (all fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SurfaceError {
    #[error("x64 only: pointer size {0} is not supported (WOW64/x86 rejected)")]
    WrongPointerSize(usize),
    #[error("target pid mismatch: expected {expected}, got {got}")]
    TargetPidMismatch { expected: u32, got: u32 },
    #[error("profile digest mismatch: expected {expected}, got {got}")]
    ProfileDigestMismatch { expected: String, got: String },
    #[error("peb address resolution failed for pid {0}: {1}")]
    PebResolveFailed(u32, String),
    #[error("peb base is zero")]
    PebBaseZero,
    #[error("peb base overflow: {0}")]
    PebBaseOverflow(String),
    #[error("peb field offset out of range: base {base:#x} offset {offset:#x} len {len}")]
    PebFieldOutOfRange { base: u64, offset: u64, len: usize },
    #[error("peb not readable at {addr:#x} (len {len})")]
    PebNotReadable { addr: u64, len: usize },
    #[error("peb not writable at {addr:#x} (len {len})")]
    PebNotWritable { addr: u64, len: usize },
    #[error("pShimData pointer invalid: {0}")]
    ShimDataInvalid(String),
    #[error("memory access failed: {0}")]
    MemoryAccess(String),
    #[error("restore failed for {surface}: {reason}")]
    RestoreFailed { surface: String, reason: String },
}

/// A resolved, accessibility-proven PEB view.
#[derive(Debug, Clone)]
pub struct PebView {
    pub base: u64,
    pub pointer_size: usize,
}

impl PebView {
    /// Resolve the PEB base for pid and validate the pointer width.
    pub fn resolve(
        mem: &dyn PebMemory,
        pid: u32,
        pointer_size: usize,
    ) -> Result<Self, SurfaceError> {
        if pointer_size != POINTER_SIZE_X64 {
            return Err(SurfaceError::WrongPointerSize(pointer_size));
        }
        let base = mem
            .peb_base(pid)
            .map_err(|e| SurfaceError::PebResolveFailed(pid, e))?;
        if base == 0 {
            return Err(SurfaceError::PebBaseZero);
        }
        Ok(Self { base, pointer_size })
    }

    /// Compute a checked absolute address for a field.
    pub fn field_addr(&self, offset: u64, len: usize) -> Result<u64, SurfaceError> {
        let len_u64 = len as u64;
        let _end = self
            .base
            .checked_add(offset)
            .and_then(|v| v.checked_add(len_u64))
            .ok_or_else(|| {
                SurfaceError::PebBaseOverflow(format!(
                    "base {:#x} + offset {:#x} + len {len}",
                    self.base, offset
                ))
            })?;
        let addr = self.base.checked_add(offset).ok_or_else(|| {
            SurfaceError::PebBaseOverflow(format!("base {:#x} + {offset:#x}", self.base))
        })?;
        Ok(addr)
    }

    /// Read a 1-byte field.
    pub fn read_u8(&self, mem: &dyn PebMemory, offset: u64) -> Result<u8, SurfaceError> {
        let addr = self.field_addr(offset, 1)?;
        if !mem.is_readable(addr, 1) {
            return Err(SurfaceError::PebNotReadable { addr, len: 1 });
        }
        let b = mem
            .read_bytes(addr, 1)
            .map_err(SurfaceError::MemoryAccess)?;
        Ok(b[0])
    }

    /// Write a 1-byte field.
    pub fn write_u8(&self, mem: &dyn PebMemory, offset: u64, val: u8) -> Result<(), SurfaceError> {
        let addr = self.field_addr(offset, 1)?;
        if !mem.is_writable(addr, 1) {
            return Err(SurfaceError::PebNotWritable { addr, len: 1 });
        }
        mem.write_bytes(addr, &[val])
            .map_err(SurfaceError::MemoryAccess)
    }

    /// Read an 8-byte pointer field.
    pub fn read_ptr(&self, mem: &dyn PebMemory, offset: u64) -> Result<u64, SurfaceError> {
        let addr = self.field_addr(offset, self.pointer_size)?;
        if !mem.is_readable(addr, self.pointer_size) {
            return Err(SurfaceError::PebNotReadable {
                addr,
                len: self.pointer_size,
            });
        }
        let raw = mem
            .read_bytes(addr, self.pointer_size)
            .map_err(SurfaceError::MemoryAccess)?;
        let mut v = [0u8; 8];
        v.copy_from_slice(&raw);
        Ok(u64::from_le_bytes(v))
    }

    /// Write an 8-byte pointer field.
    pub fn write_ptr(
        &self,
        mem: &dyn PebMemory,
        offset: u64,
        val: u64,
    ) -> Result<(), SurfaceError> {
        let addr = self.field_addr(offset, self.pointer_size)?;
        if !mem.is_writable(addr, self.pointer_size) {
            return Err(SurfaceError::PebNotWritable {
                addr,
                len: self.pointer_size,
            });
        }
        mem.write_bytes(addr, &val.to_le_bytes())
            .map_err(SurfaceError::MemoryAccess)
    }
}
/// AD-PROC-002 installation: observe, then zero BeingDebugged.
pub fn install_proc_002(
    view: &PebView,
    mem: &dyn PebMemory,
    expected_pid: u32,
    pid: u32,
    expected_profile_digest: &str,
    profile_digest: &str,
) -> Result<SurfaceInstallOutcome, SurfaceError> {
    if pid != expected_pid {
        return Err(SurfaceError::TargetPidMismatch {
            expected: expected_pid,
            got: pid,
        });
    }
    if profile_digest != expected_profile_digest {
        return Err(SurfaceError::ProfileDigestMismatch {
            expected: expected_profile_digest.to_string(),
            got: profile_digest.to_string(),
        });
    }
    let original = view.read_u8(mem, PEB_OFFSET_BEING_DEBUGGED)?;
    let effective = if original != 0 {
        // BeingDebugged set (debugger present): zero it.
        view.write_u8(mem, PEB_OFFSET_BEING_DEBUGGED, 0)?;
        0
    } else {
        // Already clean: keep as-is.
        original
    };
    Ok(SurfaceInstallOutcome::success(
        SURFACE_AD_PROC_002,
        format!("0x{original:02x}"),
        format!("0x{effective:02x}"),
        RestorationPolicy::RestoreOriginal,
    ))
}

/// AD-PROC-003 installation: read pShimData, validate, ZERO it, confirm.
///
/// Hard-required semantics (ADR-2 probe catalog): pShimData must be 0.
/// - null original -> already clean, installed=true, effective=0;
/// - non-null original -> validated (target readable), then written 0,
///   then read back; effective must be 0 or the install FAILS;
/// - invalid pointer (non-null but unreadable target) -> fail-closed.
pub fn install_proc_003(
    view: &PebView,
    mem: &dyn PebMemory,
    expected_pid: u32,
    pid: u32,
    expected_profile_digest: &str,
    profile_digest: &str,
) -> Result<SurfaceInstallOutcome, SurfaceError> {
    if pid != expected_pid {
        return Err(SurfaceError::TargetPidMismatch {
            expected: expected_pid,
            got: pid,
        });
    }
    if profile_digest != expected_profile_digest {
        return Err(SurfaceError::ProfileDigestMismatch {
            expected: expected_profile_digest.to_string(),
            got: profile_digest.to_string(),
        });
    }
    let ptr = view.read_ptr(mem, PEB_OFFSET_PSHIM_DATA)?;
    let original = if ptr == 0 {
        "0".to_string()
    } else {
        format!("{ptr:#x}")
    };
    if ptr == 0 {
        // Already clean: pShimData == 0 satisfies the expected state.
        return Ok(SurfaceInstallOutcome::success(
            SURFACE_AD_PROC_003,
            original.clone(),
            "0".to_string(),
            RestorationPolicy::RestoreOriginal,
        ));
    }
    // Non-null: validate the target is readable before writing.
    if !mem.is_readable(ptr, 1) {
        return Err(SurfaceError::ShimDataInvalid(format!(
            "ptr {ptr:#x} not readable"
        )));
    }
    // Verify the field is writable before writing.
    {
        let addr = view.field_addr(PEB_OFFSET_PSHIM_DATA, 8)?;
        if !mem.is_writable(addr, 8) {
            return Err(SurfaceError::PebNotWritable { addr, len: 8 });
        }
    }
    // Write 0 into the pShimData field.
    view.write_ptr(mem, PEB_OFFSET_PSHIM_DATA, 0)?;
    // Read back and confirm effective value is 0.
    let effective = view.read_ptr(mem, PEB_OFFSET_PSHIM_DATA)?;
    if effective != 0 {
        return Err(SurfaceError::ShimDataInvalid(format!(
            "write-back verification failed: effective {effective:#x} != 0"
        )));
    }
    Ok(SurfaceInstallOutcome::success(
        SURFACE_AD_PROC_003,
        original,
        "0".to_string(),
        RestorationPolicy::RestoreOriginal,
    ))
}

/// x64 PEB.NtGlobalFlag offset (public x64 Windows ABI; gflags u32).
pub const PEB_OFFSET_NT_GLOBAL_FLAG: u64 = 0xBC;
/// x64 PEB.ProcessHeap pointer offset (public x64 Windows ABI).
pub const PEB_OFFSET_PROCESS_HEAP: u64 = 0x30;
/// x64 heap header Flags offset (relative to ProcessHeap base).
pub const HEAP_OFFSET_FLAGS: u64 = 0x40;
/// x64 heap header ForceFlags offset (relative to ProcessHeap base).
pub const HEAP_OFFSET_FORCE_FLAGS: u64 = 0x44;

/// Surface ids.
pub const SURFACE_AD_PROC_004: &str = "AD-PROC-004";
pub const SURFACE_AD_PROC_005: &str = "AD-PROC-005";

/// Non-debugger baseline for NtGlobalFlag: 0 (no gflags).
pub const NT_GLOBAL_FLAG_CLEAN: u32 = 0x0;
/// Debugger-present gflags value (0x70 = HEAP_ENABLE_TAIL_CHECK |
/// HEAP_ENABLE_FREE_CHECK | HEAP_VALIDATE_PARAMETERS) — what we clear.
pub const NT_GLOBAL_FLAG_DEBUGGER: u32 = 0x70;

/// AD-PROC-004 installation: observe, then clear PEB.NtGlobalFlag.
///
/// Debugger presence sets NtGlobalFlag to 0x70 (heap validation bits).
/// Clean baseline is 0x0. We record original, zero it, and confirm.
pub fn install_proc_004(
    view: &PebView,
    mem: &dyn PebMemory,
    expected_pid: u32,
    pid: u32,
    expected_profile_digest: &str,
    profile_digest: &str,
) -> Result<SurfaceInstallOutcome, SurfaceError> {
    if pid != expected_pid {
        return Err(SurfaceError::TargetPidMismatch {
            expected: expected_pid,
            got: pid,
        });
    }
    if profile_digest != expected_profile_digest {
        return Err(SurfaceError::ProfileDigestMismatch {
            expected: expected_profile_digest.to_string(),
            got: profile_digest.to_string(),
        });
    }
    let addr = view.field_addr(PEB_OFFSET_NT_GLOBAL_FLAG, 4)?;
    if !mem.is_readable(addr, 4) {
        return Err(SurfaceError::PebNotReadable { addr, len: 4 });
    }
    let raw = mem
        .read_bytes(addr, 4)
        .map_err(SurfaceError::MemoryAccess)?;
    let original = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
    let effective = if original != NT_GLOBAL_FLAG_CLEAN {
        // Debugger gflags (0x70) or any non-zero: clear to clean baseline.
        if !mem.is_writable(addr, 4) {
            return Err(SurfaceError::PebNotWritable { addr, len: 4 });
        }
        mem.write_bytes(addr, &NT_GLOBAL_FLAG_CLEAN.to_le_bytes())
            .map_err(SurfaceError::MemoryAccess)?;
        // Read back and confirm.
        let rb = mem
            .read_bytes(addr, 4)
            .map_err(SurfaceError::MemoryAccess)?;
        let effective = u32::from_le_bytes([rb[0], rb[1], rb[2], rb[3]]);
        if effective != NT_GLOBAL_FLAG_CLEAN {
            return Err(SurfaceError::MemoryAccess(format!(
                "NtGlobalFlag write-back verification failed: effective {effective:#x} != 0"
            )));
        }
        effective
    } else {
        // Already clean.
        original
    };
    Ok(SurfaceInstallOutcome::success(
        SURFACE_AD_PROC_004,
        format!("0x{original:08x}"),
        format!("0x{effective:08x}"),
        RestorationPolicy::RestoreOriginal,
    ))
}

/// AD-PROC-005 installation: observe, then clear heap ForceFlags.
///
/// Debugger presence sets ProcessHeap->ForceFlags (e.g. 0x40000060).
/// Clean baseline: ForceFlags=0. We zero ForceFlags (the debugger
/// signature) and record the Flags field for the three-state record.
pub fn install_proc_005(
    view: &PebView,
    mem: &dyn PebMemory,
    expected_pid: u32,
    pid: u32,
    expected_profile_digest: &str,
    profile_digest: &str,
) -> Result<SurfaceInstallOutcome, SurfaceError> {
    if pid != expected_pid {
        return Err(SurfaceError::TargetPidMismatch {
            expected: expected_pid,
            got: pid,
        });
    }
    if profile_digest != expected_profile_digest {
        return Err(SurfaceError::ProfileDigestMismatch {
            expected: expected_profile_digest.to_string(),
            got: profile_digest.to_string(),
        });
    }
    // Resolve ProcessHeap pointer from PEB.
    let heap_ptr = view.read_ptr(mem, PEB_OFFSET_PROCESS_HEAP)?;
    if heap_ptr == 0 {
        return Err(SurfaceError::ShimDataInvalid(
            "ProcessHeap pointer is null".into(),
        ));
    }
    // ForceFlags at heap+0x44 (x64): zero it (debugger signature).
    let force_addr = heap_ptr
        .checked_add(HEAP_OFFSET_FORCE_FLAGS)
        .ok_or_else(|| SurfaceError::PebBaseOverflow(format!("heap {heap_ptr:#x} + force")))?;
    if !mem.is_readable(force_addr, 4) {
        return Err(SurfaceError::PebNotReadable {
            addr: force_addr,
            len: 4,
        });
    }
    let raw = mem
        .read_bytes(force_addr, 4)
        .map_err(SurfaceError::MemoryAccess)?;
    let original_force = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);

    // Record also the Flags field (heap+0x40) for the three-state record.
    let flags_addr = heap_ptr
        .checked_add(HEAP_OFFSET_FLAGS)
        .ok_or_else(|| SurfaceError::PebBaseOverflow(format!("heap {heap_ptr:#x} + flags")))?;
    let flags_original = if mem.is_readable(flags_addr, 4) {
        let fr = mem
            .read_bytes(flags_addr, 4)
            .map_err(SurfaceError::MemoryAccess)?;
        Some(u32::from_le_bytes([fr[0], fr[1], fr[2], fr[3]]))
    } else {
        None
    };

    let effective = if original_force != 0 {
        // Debugger ForceFlags signature: zero it.
        if !mem.is_writable(force_addr, 4) {
            return Err(SurfaceError::PebNotWritable {
                addr: force_addr,
                len: 4,
            });
        }
        mem.write_bytes(force_addr, &0u32.to_le_bytes())
            .map_err(SurfaceError::MemoryAccess)?;
        let rb = mem
            .read_bytes(force_addr, 4)
            .map_err(SurfaceError::MemoryAccess)?;
        let effective = u32::from_le_bytes([rb[0], rb[1], rb[2], rb[3]]);
        if effective != 0 {
            return Err(SurfaceError::MemoryAccess(format!(
                "ForceFlags write-back verification failed: effective {effective:#x} != 0"
            )));
        }
        effective
    } else {
        // Already clean.
        original_force
    };
    let original_desc = format!("force=0x{original_force:08x}")
        + &flags_original.map_or(String::new(), |f| format!(" flags=0x{f:08x}"));
    Ok(SurfaceInstallOutcome::success(
        SURFACE_AD_PROC_005,
        original_desc,
        format!("force=0x{effective:08x}"),
        RestorationPolicy::RestoreOriginal,
    ))
}

/// Restore AD-PROC-002 (and any other modified surfaces).
pub fn restore_proc_002(
    view: &PebView,
    mem: &dyn PebMemory,
    original_value: Option<String>,
) -> Result<RestoreResult, SurfaceError> {
    let orig = match original_value {
        Some(v) => v,
        None => return Ok(RestoreResult::NotApplicable),
    };
    let parsed = u8::from_str_radix(orig.trim_start_matches("0x"), 16).map_err(|e| {
        SurfaceError::RestoreFailed {
            surface: SURFACE_AD_PROC_002.to_string(),
            reason: format!("cannot parse original {orig}: {e}"),
        }
    })?;
    view.write_u8(mem, PEB_OFFSET_BEING_DEBUGGED, parsed)
        .map_err(|e| SurfaceError::RestoreFailed {
            surface: SURFACE_AD_PROC_002.to_string(),
            reason: e.to_string(),
        })?;
    Ok(RestoreResult::Restored)
}
/// Restore AD-PROC-003: write back the original pShimData pointer.
pub fn restore_proc_003(
    view: &PebView,
    mem: &dyn PebMemory,
    original_value: Option<String>,
) -> Result<RestoreResult, SurfaceError> {
    let orig = match original_value {
        Some(v) => v,
        None => return Ok(RestoreResult::NotApplicable),
    };
    if orig == "0" {
        // Original was already 0; nothing to restore.
        return Ok(RestoreResult::NotApplicable);
    }
    let parsed = u64::from_str_radix(orig.trim_start_matches("0x"), 16).map_err(|e| {
        SurfaceError::RestoreFailed {
            surface: SURFACE_AD_PROC_003.to_string(),
            reason: format!("cannot parse original {orig}: {e}"),
        }
    })?;
    view.write_ptr(mem, PEB_OFFSET_PSHIM_DATA, parsed)
        .map_err(|e| SurfaceError::RestoreFailed {
            surface: SURFACE_AD_PROC_003.to_string(),
            reason: e.to_string(),
        })?;
    Ok(RestoreResult::Restored)
}

/// Install both hard-required PEB surfaces (ADR-5).
///
/// - Both succeed -> both in installed, no failures. (Order: 002, 003.)
/// - Any failure -> the failed surface reports in failures, installed
///   never includes a failed surface, and the caller must fail closed.
/// - AD-PROC-001 is NOT touched (candidate; no promotion in ADR-5).
pub fn install_proc_surfaces(
    mem: &dyn PebMemory,
    pointer_size: usize,
    pid: u32,
    expected_pid: u32,
    profile_digest: &str,
    expected_profile_digest: &str,
) -> Result<(Vec<SurfaceInstallOutcome>, Vec<SurfaceInstallOutcome>), SurfaceError> {
    let view = PebView::resolve(mem, pid, pointer_size)?;
    // AD-PROC-002 first (modifying surface).
    let o2 = match install_proc_002(
        &view,
        mem,
        expected_pid,
        pid,
        expected_profile_digest,
        profile_digest,
    ) {
        Ok(o) => o,
        Err(e) => {
            let failures = vec![SurfaceInstallOutcome::failure(
                SURFACE_AD_PROC_002,
                e.to_string(),
            )];
            return Ok((Vec::new(), failures));
        }
    };
    let o3 = match install_proc_003(
        &view,
        mem,
        expected_pid,
        pid,
        expected_profile_digest,
        profile_digest,
    ) {
        Ok(o) => o,
        Err(e) => {
            let failures = vec![SurfaceInstallOutcome::failure(
                SURFACE_AD_PROC_003,
                e.to_string(),
            )];
            return Ok((vec![o2], failures));
        }
    };
    Ok((vec![o2, o3], Vec::new()))
}
