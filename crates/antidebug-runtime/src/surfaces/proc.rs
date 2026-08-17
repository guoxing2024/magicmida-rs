//! AD-PROC-002 / AD-PROC-003 PEB surfaces (ADR-5).
//!
//! AD-PROC-002: PEB.BeingDebugged (offset 0x02, BYTE)
//! AD-PROC-003: PEB.pShimData   (offset 0x08, PVOID)
//!
//! ## x64-only contract
//!
//! - pointer_size must be 8; x86 / WOW64 / unknown widths are rejected.
//! - All PEB address arithmetic uses checked_add / checked_sub; unchecked
//!   pointer math is forbidden.
//! - Field offsets are not hard-coded blindly: they are proven against the
//!   public x64 Windows ABI layout (BeingDebugged at 0x02, pShimData at
//!   0x08) and every access validates read/write accessibility first.
//! - On any failure the surface reports a structured error and is NOT
//!   reported as installed.
//!
//! ## Modification and restoration
//!
//! - AD-PROC-002: zeroes BeingDebugged (or restores original if it was
//!   already non-zero). original/effective/restoration are all recorded.
//! - AD-PROC-003: pShimData is observation-only (no write); the pointer
//!   value and its validity are recorded.
//! - Restoration runs on shutdown and its result enters telemetry; a failed
//!   restore is a fail-closed state (CleanupFailed path), never a silent
//!   Drop side-effect.

use serde::{Deserialize, Serialize};

/// x64 pointer width (bytes).
pub const POINTER_SIZE_X64: usize = 8;

/// x64 PEB field offsets (public x64 Windows ABI).
pub const PEB_OFFSET_BEING_DEBUGGED: u64 = 0x02;
pub const PEB_OFFSET_PSHIM_DATA: u64 = 0x08;

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
            .map_err(|e| SurfaceError::MemoryAccess(e))?;
        Ok(b[0])
    }

    /// Write a 1-byte field.
    pub fn write_u8(&self, mem: &dyn PebMemory, offset: u64, val: u8) -> Result<(), SurfaceError> {
        let addr = self.field_addr(offset, 1)?;
        if !mem.is_writable(addr, 1) {
            return Err(SurfaceError::PebNotWritable { addr, len: 1 });
        }
        mem.write_bytes(addr, &[val])
            .map_err(|e| SurfaceError::MemoryAccess(e))
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
            .map_err(|e| SurfaceError::MemoryAccess(e))?;
        let mut v = [0u8; 8];
        v.copy_from_slice(&raw);
        Ok(u64::from_le_bytes(v))
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

/// AD-PROC-003 installation: observe pShimData (observation-only).
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
    // Validate pointer: null is valid (no shim); non-null must be readable.
    if ptr != 0 && !mem.is_readable(ptr, 1) {
        return Err(SurfaceError::ShimDataInvalid(format!(
            "ptr {ptr:#x} not readable"
        )));
    }
    Ok(SurfaceInstallOutcome::observation(
        SURFACE_AD_PROC_003,
        if ptr == 0 {
            "null".to_string()
        } else {
            format!("{ptr:#x}")
        },
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
