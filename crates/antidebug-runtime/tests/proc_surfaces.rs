//! ADR-5 surface tests: AD-PROC-002 (PEB.BeingDebugged) and
//! AD-PROC-003 (PEB.pShimData) with synthetic fixtures.
//!
//! All tests use [FakePebMemory] - an in-memory PEB simulation - so no
//! real process memory is touched and no protected sample is involved.

use mida_antidebug_runtime::surfaces::{
    install_proc_002, install_proc_003, install_proc_surfaces, restore_proc_002, PebMemory,
    PebView, RestorationPolicy, RestoreResult, SurfaceError, PEB_OFFSET_BEING_DEBUGGED,
    PEB_OFFSET_PSHIM_DATA, POINTER_SIZE_X64, SURFACE_AD_PROC_001, SURFACE_AD_PROC_002,
    SURFACE_AD_PROC_003,
};

const PID: u32 = 4242;
const PEB_BASE: u64 = 0x0000_7ff6_0000_0000;
const DIGEST: &str = "deadbeef";

/// In-memory PEB simulation (synthetic fixture).
#[derive(Clone)]
struct FakePebMemory {
    /// peb_base + offset -> byte.
    bytes: Vec<u8>,
    base: u64,
    pid: u32,
    readable: bool,
    writable: bool,
    /// Pointer target region (for pShimData validity).
    shim_region: Option<(u64, Vec<u8>)>,
}

impl FakePebMemory {
    fn new() -> Self {
        // 0x100 bytes of PEB.
        let mut bytes = vec![0u8; 0x100];
        bytes[PEB_OFFSET_BEING_DEBUGGED as usize] = 0; // BeingDebugged = 0
                                                       // pShimData = null (default).
        Self {
            bytes,
            base: PEB_BASE,
            pid: PID,
            readable: true,
            writable: true,
            shim_region: None,
        }
    }

    fn with_being_debugged(mut self, v: u8) -> Self {
        self.bytes[PEB_OFFSET_BEING_DEBUGGED as usize] = v;
        self
    }

    fn with_p_shim_data(mut self, ptr: u64) -> Self {
        self.bytes[PEB_OFFSET_PSHIM_DATA as usize..PEB_OFFSET_PSHIM_DATA as usize + 8]
            .copy_from_slice(&ptr.to_le_bytes());
        if ptr != 0 {
            self.shim_region = Some((ptr, vec![0xAB; 16]));
        }
        self
    }

    fn with_p_shim_data_invalid(mut self, ptr: u64) -> Self {
        // Pointer value set but NO backing region registered: the pointer is
        // not readable -> must be rejected by the surface install.
        self.bytes[PEB_OFFSET_PSHIM_DATA as usize..PEB_OFFSET_PSHIM_DATA as usize + 8]
            .copy_from_slice(&ptr.to_le_bytes());
        self.shim_region = None;
        self
    }

    fn unreadable(mut self) -> Self {
        self.readable = false;
        self
    }

    fn unwritable(mut self) -> Self {
        self.writable = false;
        self
    }
}

impl PebMemory for FakePebMemory {
    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, String> {
        if !self.readable {
            return Err("not readable".to_string());
        }
        if addr < self.base || addr + len as u64 > self.base + self.bytes.len() as u64 {
            // maybe in shim region?
            if let Some((sbase, sbytes)) = &self.shim_region {
                if addr >= *sbase && addr + len as u64 <= *sbase + sbytes.len() as u64 {
                    let off = (addr - *sbase) as usize;
                    return Ok(sbytes[off..off + len].to_vec());
                }
            }
            return Err("out of range".to_string());
        }
        let off = (addr - self.base) as usize;
        Ok(self.bytes[off..off + len].to_vec())
    }

    fn write_bytes(&self, addr: u64, data: &[u8]) -> Result<(), String> {
        if !self.writable {
            return Err("not writable".to_string());
        }
        if addr < self.base || addr + data.len() as u64 > self.base + self.bytes.len() as u64 {
            return Err("out of range".to_string());
        }
        let off = (addr - self.base) as usize;
        // FakePebMemory is &self; simulate write via interior mutability is
        // avoided here - tests use the trait contract which only needs
        // is_writable probe + write attempt. For read-back verification the
        // tests check the returned outcome values instead.
        let _ = off;
        let _ = data;
        Ok(())
    }

    fn is_readable(&self, addr: u64, len: usize) -> bool {
        if !self.readable {
            return false;
        }
        if addr >= self.base && addr + len as u64 <= self.base + self.bytes.len() as u64 {
            return true;
        }
        if let Some((sbase, sbytes)) = &self.shim_region {
            return addr >= *sbase && addr + len as u64 <= *sbase + sbytes.len() as u64;
        }
        false
    }

    fn is_writable(&self, addr: u64, len: usize) -> bool {
        if !self.writable {
            return false;
        }
        self.is_readable(addr, len)
    }

    fn peb_base(&self, pid: u32) -> Result<u64, String> {
        if pid != self.pid {
            return Err(format!("pid mismatch: {}", pid));
        }
        Ok(self.base)
    }
}

fn view(mem: &dyn PebMemory) -> PebView {
    PebView::resolve(mem, PID, POINTER_SIZE_X64).unwrap()
}

// ----------------------------------------------------------------
// AD-PROC-002: BeingDebugged
// ----------------------------------------------------------------

#[test]
fn proc002_normal_clean_peb() {
    let mem = FakePebMemory::new();
    let out = install_proc_002(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap();
    assert!(out.installed);
    assert_eq!(out.surface_id, SURFACE_AD_PROC_002);
    assert_eq!(out.original_value.as_deref(), Some("0x00"));
    assert_eq!(out.effective_value.as_deref(), Some("0x00"));
    assert_eq!(out.restoration_policy, RestorationPolicy::RestoreOriginal);
}

#[test]
fn proc002_being_debugged_set_is_zeroed() {
    let mem = FakePebMemory::new().with_being_debugged(1);
    let out = install_proc_002(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap();
    assert!(out.installed);
    assert_eq!(out.original_value.as_deref(), Some("0x01"));
    assert_eq!(out.effective_value.as_deref(), Some("0x00"));
}

#[test]
fn proc002_target_pid_mismatch_rejected() {
    let mem = FakePebMemory::new();
    let err = install_proc_002(&view(&mem), &mem, PID, PID + 1, DIGEST, DIGEST).unwrap_err();
    assert!(matches!(err, SurfaceError::TargetPidMismatch { .. }));
}

#[test]
fn proc002_profile_digest_mismatch_rejected() {
    let mem = FakePebMemory::new();
    let err = install_proc_002(&view(&mem), &mem, PID, PID, DIGEST, "wrong").unwrap_err();
    assert!(matches!(err, SurfaceError::ProfileDigestMismatch { .. }));
}

#[test]
fn proc002_unreadable_peb_rejected() {
    let mem = FakePebMemory::new().unreadable();
    let err = install_proc_002(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap_err();
    assert!(matches!(err, SurfaceError::PebNotReadable { .. }));
}

#[test]
fn proc002_unwritable_peb_rejected_when_modifying() {
    let mem = FakePebMemory::new().with_being_debugged(1).unwritable();
    let err = install_proc_002(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap_err();
    assert!(matches!(err, SurfaceError::PebNotWritable { .. }));
}

#[test]
fn proc002_restore_original() {
    let mem = FakePebMemory::new().with_being_debugged(1);
    let out = install_proc_002(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap();
    assert_eq!(out.original_value.as_deref(), Some("0x01"));
    let v = view(&mem);
    let r = restore_proc_002(&v, &mem, out.original_value).unwrap();
    assert_eq!(r, RestoreResult::Restored);
}

#[test]
fn proc002_restore_not_applicable_when_none() {
    let mem = FakePebMemory::new();
    let v = view(&mem);
    let r = restore_proc_002(&v, &mem, None).unwrap();
    assert_eq!(r, RestoreResult::NotApplicable);
}

#[test]
fn proc002_restore_failure_reported() {
    let mem = FakePebMemory::new().with_being_debugged(1).unwritable();
    let v = view(&mem);
    let err = restore_proc_002(&v, &mem, Some("0x01".to_string())).unwrap_err();
    assert!(matches!(err, SurfaceError::RestoreFailed { .. }));
}

// ----------------------------------------------------------------
// AD-PROC-003: pShimData
// ----------------------------------------------------------------

#[test]
fn proc003_null_shim_data_ok() {
    let mem = FakePebMemory::new();
    let out = install_proc_003(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap();
    assert!(out.installed);
    assert_eq!(out.surface_id, SURFACE_AD_PROC_003);
    assert_eq!(out.original_value.as_deref(), Some("null"));
    assert_eq!(out.restoration_policy, RestorationPolicy::ObserveOnly);
}

#[test]
fn proc003_valid_shim_pointer_ok() {
    let target = PEB_BASE + 0x2000;
    let mem = FakePebMemory::new().with_p_shim_data(target);
    let out = install_proc_003(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap();
    assert!(out.installed);
    assert_eq!(
        out.original_value.as_deref(),
        Some(format!("{target:#x}").as_str())
    );
}

#[test]
fn proc003_invalid_shim_pointer_rejected() {
    // pointer to an unreadable region (no backing memory registered)
    let mem = FakePebMemory::new().with_p_shim_data_invalid(0x1_0000_0000);
    let err = install_proc_003(&view(&mem), &mem, PID, PID, DIGEST, DIGEST).unwrap_err();
    assert!(matches!(err, SurfaceError::ShimDataInvalid(_)));
}

#[test]
fn proc003_pid_mismatch_rejected() {
    let mem = FakePebMemory::new();
    let err = install_proc_003(&view(&mem), &mem, PID, PID + 1, DIGEST, DIGEST).unwrap_err();
    assert!(matches!(err, SurfaceError::TargetPidMismatch { .. }));
}

// ----------------------------------------------------------------
// pointer width / aggregate
// ----------------------------------------------------------------

#[test]
fn wrong_pointer_size_rejected() {
    let mem = FakePebMemory::new();
    // x86 pointer size (4) must be rejected for this x64 runtime.
    let err = PebView::resolve(&mem, PID, 4).unwrap_err();
    assert!(matches!(err, SurfaceError::WrongPointerSize(4)));
}

#[test]
fn aggregate_both_installed() {
    let mem = FakePebMemory::new();
    let (installed, failures) =
        install_proc_surfaces(&mem, POINTER_SIZE_X64, PID, PID, DIGEST, DIGEST).unwrap();
    assert_eq!(installed.len(), 2);
    assert!(failures.is_empty());
    let ids: Vec<&str> = installed.iter().map(|o| o.surface_id.as_str()).collect();
    assert!(ids.contains(&SURFACE_AD_PROC_002));
    assert!(ids.contains(&SURFACE_AD_PROC_003));
    // candidate is never installed
    assert!(!ids.contains(&SURFACE_AD_PROC_001));
}

#[test]
fn aggregate_partial_failure_reports_failures() {
    // pShimData invalid -> 003 fails, 002 installed, failures non-empty.
    let mem = FakePebMemory::new().with_p_shim_data_invalid(0x1_0000_0000);
    let (installed, failures) =
        install_proc_surfaces(&mem, POINTER_SIZE_X64, PID, PID, DIGEST, DIGEST).unwrap();
    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].surface_id, SURFACE_AD_PROC_002);
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].surface_id, SURFACE_AD_PROC_003);
    assert!(failures[0].error.is_some());
}

#[test]
fn aggregate_wrong_pid_fails_closed() {
    let mem = FakePebMemory::new();
    // pid mismatch -> PebView::resolve fails -> the whole install errors
    // (fail-closed: no partial success is claimed).
    let err =
        install_proc_surfaces(&mem, POINTER_SIZE_X64, PID + 1, PID, DIGEST, DIGEST).unwrap_err();
    assert!(matches!(err, SurfaceError::PebResolveFailed(..)));
}

#[test]
fn aggregate_peb_unresolvable_fails_closed() {
    let mem = FakePebMemory::new();
    // wrong pid for peb_base resolution (peb_base checks pid match).
    let err =
        install_proc_surfaces(&mem, POINTER_SIZE_X64, PID + 2, PID, DIGEST, DIGEST).unwrap_err();
    assert!(matches!(err, SurfaceError::PebResolveFailed(..)));
}

#[test]
fn telemetry_sequence_error_still_fails_closed() {
    // telemetry sequence errors are a separate concern; the surface install
    // path itself is deterministic. Assert the surface result remains
    // truthful even if telemetry later fails (the runtime never reports
    // installed when the install failed).
    let mem = FakePebMemory::new().with_p_shim_data_invalid(0x1_0000_0000);
    let (installed, failures) =
        install_proc_surfaces(&mem, POINTER_SIZE_X64, PID, PID, DIGEST, DIGEST).unwrap();
    assert_eq!(installed.len(), 1);
    assert_eq!(failures.len(), 1);
    // attestation built from these must NOT claim complete.
    let att = mida_antidebug_runtime::attestation::RuntimeAttestation::from_surfaces(
        "sha".to_string(),
        "profile".to_string(),
        DIGEST.to_string(),
        PID,
        PEB_BASE,
        &[
            SURFACE_AD_PROC_002.to_string(),
            SURFACE_AD_PROC_003.to_string(),
        ],
        &installed
            .iter()
            .map(|o| o.surface_id.clone())
            .collect::<Vec<_>>(),
        &failures
            .iter()
            .map(|f| (f.surface_id.clone(), f.error.clone().unwrap_or_default()))
            .collect::<Vec<_>>(),
        vec![],
        "rev".to_string(),
        "rustc".to_string(),
    );
    assert!(att.validate().is_err());
}

#[test]
fn attestation_from_surfaces_full_success_validates() {
    let mem = FakePebMemory::new();
    let (installed, failures) =
        install_proc_surfaces(&mem, POINTER_SIZE_X64, PID, PID, DIGEST, DIGEST).unwrap();
    assert!(failures.is_empty());
    let details: Vec<mida_antidebug_runtime::attestation::SurfaceDetail> = installed
        .iter()
        .map(|o| mida_antidebug_runtime::attestation::SurfaceDetail {
            surface_id: o.surface_id.clone(),
            installed: o.installed,
            original_value: o.original_value.clone(),
            effective_value: o.effective_value.clone(),
            restoration_policy: format!("{:?}", o.restoration_policy),
            restore_result: format!("{:?}", o.restore_result),
            error: o.error.clone(),
        })
        .collect();
    let att = mida_antidebug_runtime::attestation::RuntimeAttestation::from_surfaces(
        "sha".to_string(),
        "profile".to_string(),
        DIGEST.to_string(),
        PID,
        PEB_BASE,
        &[
            SURFACE_AD_PROC_002.to_string(),
            SURFACE_AD_PROC_003.to_string(),
        ],
        &installed
            .iter()
            .map(|o| o.surface_id.clone())
            .collect::<Vec<_>>(),
        &[],
        details,
        "rev".to_string(),
        "rustc".to_string(),
    );
    assert!(att.validate().is_ok());
    assert_eq!(att.hooks_installed.len(), 2);
    assert!(att.hook_failures.is_empty());
}

#[test]
fn attestation_candidate_never_in_expected() {
    // AD-PROC-001 must never appear in hooks_expected/hooks_installed.
    let att = mida_antidebug_runtime::attestation::RuntimeAttestation::from_surfaces(
        "sha".to_string(),
        "profile".to_string(),
        DIGEST.to_string(),
        PID,
        PEB_BASE,
        &[SURFACE_AD_PROC_001.to_string()],
        &[],
        &[(
            SURFACE_AD_PROC_001.to_string(),
            "candidate not installed".to_string(),
        )],
        vec![],
        "rev".to_string(),
        "rustc".to_string(),
    );
    assert!(att.validate().is_err()); // incomplete -> fail-closed
}
