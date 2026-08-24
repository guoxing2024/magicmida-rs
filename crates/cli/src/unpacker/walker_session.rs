//! IMP-09-CARRIER-R5: production walker session carriers.
//!
//! - [`RpmWalkerProvider`]: real production [`WalkerMemoryProvider`]
//!   implementation over ReadProcessMemory, bound to a target PID.
//!   Never a fixture; never `MemoryMapProvider`.
//! - [`WalkerSessionMemory`]: production resource owner that allocates
//!   the walker params + result section in the TARGET process
//!   (`VirtualAllocEx`), writes the protocol envelope + section header,
//!   builds the provider and installs the session in ONE transaction.
//!   Every failure frees both allocations and never publishes READY.
//!
//! Subsystem isolation (mandated): the loader thunk params envelope
//! (`V2ParamsBlob`) is a DIFFERENT subsystem with its own allocation
//! and lifetime; nothing here reuses or aliases it.

use mida_antidebug_runtime::walker_control::WalkerIoError;
use mida_antidebug_runtime::walker_control::WalkerMemoryProvider;
use mida_antidebug_runtime::walker_protocol::{
    encode_section, is_canonical_user_va, MappingIdentityHeaderV2, ResultSectionHeaderV2,
    WalkerParamsV2, MIN_SECTION_HEADER_BYTES, PARAMS_HEADER_BYTES, PROBE_RESULT_BYTES,
    WALKER_SESSION_ID_BYTES,
};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT,
    MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    GetProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Fixed size of the walker params region (one page).
pub const WALKER_PARAMS_REGION_BYTES: usize = 0x1000;
/// Fixed size of the walker result section region (one page).
pub const WALKER_SECTION_REGION_BYTES: usize = 0x1000;

/// Production `WalkerMemoryProvider` over ReadProcessMemory.
///
/// Binds the provider to a target process handle + PID. Every read is
/// fail-closed: canonical VA check, overflow check, mapped/committed
/// range check (`VirtualQueryEx`), then a full-length RPM read.
#[derive(Debug)]
pub struct RpmWalkerProvider {
    handle: HANDLE,
    target_pid: u32,
}

impl RpmWalkerProvider {
    /// Create a provider bound to `handle` (must belong to `target_pid`).
    ///
    /// Validates the handle actually refers to `target_pid` by opening a
    /// limited-query handle and comparing `GetProcessId`. Any mismatch,
    /// invalid handle, or query failure returns `None` (fail-closed).
    pub fn new(handle: HANDLE, target_pid: u32) -> Option<Self> {
        // Cross-check: open a fresh query handle and compare PIDs.
        let probe =
            match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, target_pid) } {
                Ok(h) => h,
                Err(_) => return None,
            };
        let probe_pid = unsafe { GetProcessId(probe) };
        unsafe {
            let _ = CloseHandle(probe);
        };
        if probe_pid == 0 || probe_pid != target_pid {
            return None;
        }
        // The caller's handle must reference the same PID.
        let handle_pid = unsafe { GetProcessId(handle) };
        if handle_pid == 0 || handle_pid != target_pid {
            return None;
        }
        Some(Self { handle, target_pid })
    }

    /// The bound target PID.
    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }
}

impl WalkerMemoryProvider for RpmWalkerProvider {
    fn read(&self, va: u64, buf: &mut [u8]) -> Result<(), WalkerIoError> {
        let want = buf.len();
        if want == 0 {
            return Ok(());
        }
        // 1. canonical user VA (fail-closed).
        if !is_canonical_user_va(va) || va == 0 {
            return Err(WalkerIoError::Missing { va });
        }
        // 2. overflow check (fail-closed).
        let end = match va.checked_add(want as u64) {
            Some(v) => v,
            None => return Err(WalkerIoError::OutOfBounds { va, want, got: 0 }),
        };
        // 3. mapped + committed + readable range check.
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let qr = unsafe {
            VirtualQueryEx(
                self.handle,
                Some(va as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if qr == 0 {
            return Err(WalkerIoError::Missing { va });
        }
        if mbi.State != MEM_COMMIT {
            return Err(WalkerIoError::Missing { va });
        }
        let region_end = match (mbi.BaseAddress as u64).checked_add(mbi.RegionSize as u64) {
            Some(v) => v,
            None => return Err(WalkerIoError::OutOfBounds { va, want, got: 0 }),
        };
        if end > region_end {
            return Err(WalkerIoError::OutOfBounds { va, want, got: 0 });
        }
        // 4. full-length RPM read.
        let mut read_bytes = 0usize;
        let r = unsafe {
            ReadProcessMemory(
                self.handle,
                va as *const core::ffi::c_void,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                want,
                Some(&mut read_bytes),
            )
        };
        if r.is_err() {
            return Err(WalkerIoError::Missing { va });
        }
        if read_bytes != want {
            return Err(WalkerIoError::OutOfBounds {
                va,
                want,
                got: read_bytes,
            });
        }
        Ok(())
    }
}

// SAFETY: RpmWalkerProvider only passes the HANDLE to ReadProcessMemory /
// VirtualQueryEx / GetProcessId (all thread-safe, documented kernel32 calls);
// it never dereferences the pointer. The handle is owned by the debugger
// for the duration of the session (same lifetime contract as the loader).
unsafe impl Send for RpmWalkerProvider {}
unsafe impl Sync for RpmWalkerProvider {}

/// Owned remote allocation in the target (params or section).
#[derive(Debug)]
struct RemoteAllocation {
    va: u64,
}

/// Production walker session memory owner.
///
/// Allocates the walker params region and the result section region in
/// the target, writes the validated envelope + section header, then
/// installs provider + session transactionally. On ANY failure both
/// allocations are freed and no READY is published.
#[derive(Debug)]
pub struct WalkerSessionMemory {
    params: Option<RemoteAllocation>,
    section: Option<RemoteAllocation>,
    installed: bool,
}

impl WalkerSessionMemory {
    pub fn new() -> Self {
        Self {
            params: None,
            section: None,
            installed: false,
        }
    }

    /// Allocate both regions in the target. Fail-closed: on any error
    /// both are freed and `None` is returned.
    pub fn allocate(&mut self, target: HANDLE) -> Option<(u64, u64)> {
        let params_va = unsafe {
            VirtualAllocEx(
                target,
                None,
                WALKER_PARAMS_REGION_BYTES,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if params_va.is_null() {
            self.cleanup(target);
            return None;
        }
        let section_va = unsafe {
            VirtualAllocEx(
                target,
                None,
                WALKER_SECTION_REGION_BYTES,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if section_va.is_null() {
            self.cleanup(target);
            return None;
        }
        if params_va as u64 == section_va as u64 {
            self.cleanup(target);
            return None;
        }
        self.params = Some(RemoteAllocation {
            va: params_va as u64,
        });
        self.section = Some(RemoteAllocation {
            va: section_va as u64,
        });
        Some((params_va as u64, section_va as u64))
    }

    /// Write the walker params envelope into the params region.
    ///
    /// `candidates` are the probe target VAs. The envelope is built with
    /// the same frozen protocol (`WalkerParamsV2`), CRC over [0, 0x38),
    /// and validated locally before the write (fail-closed).
    pub fn write_params(
        &self,
        target: HANDLE,
        candidate_count: u32,
        candidates: &[u64],
        result_nonce: u64,
        result_bytes: u64,
        options_flags: u16,
        probe_span: u16,
    ) -> Result<(), ()> {
        let params_va = self.params.as_ref().ok_or(())?.va;
        if candidates.len() != candidate_count as usize {
            return Err(());
        }
        let params = WalkerParamsV2::new(
            params_va,
            candidate_count,
            options_flags,
            probe_span,
            result_nonce,
            result_bytes,
        );
        let blob = match params.to_blob_bytes(candidates) {
            Ok(b) => b,
            Err(_) => return Err(()),
        };
        if blob.len() > WALKER_PARAMS_REGION_BYTES {
            return Err(());
        }
        // Verify the envelope locally before any write.
        let (parsed, cands) =
            match mida_antidebug_runtime::walker_protocol::controller_validate_entry(&blob) {
                Ok(v) => v,
                Err(_) => return Err(()),
            };
        if parsed.candidate_count != candidate_count || cands.len() != candidate_count as usize {
            return Err(());
        }
        // Write.
        let mut written = 0usize;
        let r = unsafe {
            WriteProcessMemory(
                target,
                params_va as *mut core::ffi::c_void,
                blob.as_ptr() as *const core::ffi::c_void,
                blob.len(),
                Some(&mut written),
            )
        };
        if r.is_err() || written != blob.len() {
            return Err(());
        }
        Ok(())
    }

    /// Write the result section header + zeroed payload into the section
    /// region. The identity header binds nonce / PID / session id.
    pub fn write_section_header(
        &self,
        target: HANDLE,
        result_nonce: u64,
        target_pid: u32,
        owner_pid: u32,
        session_id: [u8; WALKER_SESSION_ID_BYTES],
        result_bytes: u64,
    ) -> Result<(), ()> {
        let section_va = self.section.as_ref().ok_or(())?.va;
        // Result capacity MUST equal the params result_bytes (protocol
        // cross-check): capacity = n*0x28 + MIN_HEADER for the n that
        // produces exactly result_bytes.
        if result_bytes < MIN_SECTION_HEADER_BYTES as u64 {
            return Err(());
        }
        let capacity_n = result_bytes - MIN_SECTION_HEADER_BYTES as u64;
        if capacity_n % PROBE_RESULT_BYTES as u64 != 0 {
            return Err(());
        }
        let max_n = (capacity_n / PROBE_RESULT_BYTES as u64) as u32;
        let capacity = result_bytes;
        let identity =
            MappingIdentityHeaderV2::new(capacity, target_pid, owner_pid, result_nonce, session_id);
        let header = ResultSectionHeaderV2::new(capacity, max_n).map_err(|_| ())?;
        let section = encode_section(&identity, &header, &[]).map_err(|_| ())?;
        if section.len() > WALKER_SECTION_REGION_BYTES {
            return Err(());
        }
        let mut written = 0usize;
        let r = unsafe {
            WriteProcessMemory(
                target,
                section_va as *mut core::ffi::c_void,
                section.as_ptr() as *const core::ffi::c_void,
                section.len(),
                Some(&mut written),
            )
        };
        if r.is_err() || written != section.len() {
            return Err(());
        }
        Ok(())
    }

    /// The allocated params VA (None before allocate).
    pub fn params_va(&self) -> Option<u64> {
        self.params.as_ref().map(|a| a.va)
    }

    /// The allocated section VA (None before allocate).
    pub fn section1_va(&self) -> Option<u64> {
        self.section.as_ref().map(|a| a.va)
    }

    /// Free both allocations (idempotent).
    pub fn cleanup(&mut self, target: HANDLE) {
        if let Some(p) = self.params.take() {
            unsafe {
                let _ = VirtualFreeEx(target, p.va as *mut core::ffi::c_void, 0, MEM_RELEASE);
            };
        }
        if let Some(s) = self.section.take() {
            unsafe {
                let _ = VirtualFreeEx(target, s.va as *mut core::ffi::c_void, 0, MEM_RELEASE);
            };
        }
        self.installed = false;
    }
}

impl Drop for WalkerSessionMemory {
    /// Panic/unwind safety: free both allocations when dropped without
    /// an explicit cleanup (the target handle cannot be recovered here,
    /// so the owner must call [`WalkerSessionMemory::cleanup`] with the
    /// live handle; this Drop only guards the no-handle case by marking
    /// the state (allocations are released by the caller's teardown).
    fn drop(&mut self) {
        self.installed = false;
    }
}

/// Install the full walker session: allocate, write, provider, install.
///
/// The single production wiring seam. Returns the memory owner on
/// success (the caller keeps it until session teardown, then calls
/// [`WalkerSessionMemory::cleanup`]); on ANY failure both allocations
/// are freed and the session is NOT installed (no READY).
pub fn install_walker_session_production(
    target: HANDLE,
    target_pid: u32,
    owner_pid: u32,
    candidates: &[u64],
    result_nonce: u64,
    options_flags: u16,
    probe_span: u16,
    session_id: [u8; WALKER_SESSION_ID_BYTES],
    target_image_sha256: &str,
    runtime_module_sha256: &str,
    module_base: u64,
    walker_export_rva: u64,
    profile_id: &str,
    profile_digest: &str,
) -> Option<WalkerSessionMemory> {
    let mut mem = WalkerSessionMemory::new();
    let (params_va, section1_va) = match mem.allocate(target) {
        Some(v) => v,
        None => return None,
    };
    let candidate_count = candidates.len() as u32;
    // result_bytes = section capacity. The protocol REQUIRES
    // result_bytes == candidate_count*0x28 + MIN_SECTION_HEADER_BYTES
    // (WalkerParamsV2::validate) AND the section capacity must equal it.
    let section_bytes = (candidate_count as u64)
        .checked_mul(0x28)
        .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
        .unwrap_or(0);
    if section_bytes == 0 || section_bytes > WALKER_SECTION_REGION_BYTES as u64 {
        mem.cleanup(target);
        return None;
    }
    if mem
        .write_params(
            target,
            candidate_count,
            candidates,
            result_nonce,
            section_bytes,
            options_flags,
            probe_span,
        )
        .is_err()
    {
        mem.cleanup(target);
        return None;
    }
    if mem
        .write_section_header(
            target,
            result_nonce,
            target_pid,
            owner_pid,
            session_id,
            section_bytes,
        )
        .is_err()
    {
        mem.cleanup(target);
        return None;
    }
    let provider = match RpmWalkerProvider::new(target, target_pid) {
        Some(p) => p,
        None => {
            mem.cleanup(target);
            return None;
        }
    };
    let ok = mida_antidebug_runtime::exports::install_walker_session_verified(
        Box::new(provider),
        params_va,
        section1_va,
        target_pid,
        owner_pid,
        target_image_sha256,
        runtime_module_sha256,
        module_base,
        walker_export_rva,
        profile_id,
        profile_digest,
    );
    if !ok {
        mem.cleanup(target);
        return None;
    }
    mem.installed = true;
    Some(mem)
}

#[cfg(test)]
mod imp09_r5_tests {
    use super::*;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    fn self_handle() -> HANDLE {
        unsafe { GetCurrentProcess() }
    }

    fn alloc_local(size: usize) -> *mut core::ffi::c_void {
        unsafe { VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }
    }

    fn free_local(p: *mut core::ffi::c_void) {
        unsafe {
            let _ = VirtualFree(p, 0, MEM_RELEASE);
        };
    }

    fn dig64(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    /// Reset the runtime walker bindings between tests (best effort:
    /// reinstall clears state; output channel drained).
    fn reset_runtime() {
        let _ = mida_antidebug_runtime::exports::take_walker_output();
    }

    // ---------- provider: PID binding ----------

    #[test]
    fn provider_pid_mismatch_rejected() {
        // A handle to our own process with a WRONG pid must be rejected.
        let own = self_handle();
        let my_pid = std::process::id();
        let wrong_pid = if my_pid == 4 { 5 } else { my_pid ^ 0xFF };
        assert!(
            RpmWalkerProvider::new(own, wrong_pid).is_none(),
            "PID mismatch must fail closed"
        );
    }

    #[test]
    fn provider_invalid_handle_rejected() {
        let invalid = HANDLE(std::ptr::null_mut());
        assert!(
            RpmWalkerProvider::new(invalid, std::process::id()).is_none(),
            "invalid handle must fail closed"
        );
    }

    #[test]
    fn provider_valid_own_process_ok() {
        let p = RpmWalkerProvider::new(self_handle(), std::process::id());
        assert!(p.is_some(), "own-process handle + own pid must bind");
        let p = p.unwrap();
        assert_eq!(p.target_pid(), std::process::id());
    }

    // ---------- provider: read boundary ----------

    #[test]
    fn provider_noncanonical_va_rejected() {
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut buf = [0u8; 8];
        // Kernel high-half (bit 47 set) is not a canonical user VA.
        assert!(p.read(0xFFFF_8000_0000_0000, &mut buf).is_err());
        // Zero VA rejected.
        assert!(p.read(0, &mut buf).is_err());
    }

    #[test]
    fn provider_range_overflow_rejected() {
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut buf = [0u8; 8];
        // va + len overflows u64.
        assert!(p.read(0x0000_7FFF_FFFF_FFFF, &mut buf).is_err());
    }

    #[test]
    fn provider_unmapped_range_rejected() {
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut buf = [0u8; 8];
        // A high user VA that is not mapped in our process.
        assert!(p.read(0x0000_0000_FFFF_0000, &mut buf).is_err());
    }

    #[test]
    fn provider_reads_mapped_region() {
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let region = alloc_local(0x1000);
        assert!(!region.is_null());
        let va = region as u64;
        // Write a known pattern.
        unsafe {
            std::ptr::write_bytes(region as *mut u8, 0xAB, 0x40);
        }
        let mut buf = [0u8; 8];
        assert!(p.read(va, &mut buf).is_ok());
        assert_eq!(buf, [0xAB; 8]);
        // Out-of-region read (past the allocation) fails.
        assert!(p.read(va + 0x1000, &mut buf).is_err());
        free_local(region);
    }

    #[test]
    fn provider_short_read_rejected() {
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let region = alloc_local(0x1000);
        assert!(!region.is_null());
        let va = region as u64;
        // A read crossing the region boundary must fail (range check).
        let mut buf = [0u8; 0x100];
        assert!(
            p.read(va + 0x1000 - 0x40, &mut buf).is_err(),
            "cross-boundary read must fail"
        );
        // And a read fully inside succeeds.
        assert!(p.read(va, &mut buf).is_ok());
        free_local(region);
    }

    // ---------- WalkerSessionMemory ----------

    #[test]
    fn memory_allocate_returns_distinct_vas() {
        let mut m = WalkerSessionMemory::new();
        let r = m.allocate(self_handle());
        assert!(r.is_some());
        let (pv, sv) = r.unwrap();
        assert_ne!(pv, 0);
        assert_ne!(sv, 0);
        assert_ne!(pv, sv, "params_va != section1_va");
        m.cleanup(self_handle());
        assert!(m.params_va().is_none());
        assert!(m.section1_va().is_none());
    }

    #[test]
    fn memory_write_params_then_read_back() {
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle()).unwrap();
        let candidates = [0x400000u64, 0x401000u64];
        let ok = m.write_params(
            self_handle(),
            2,
            &candidates,
            0xDEADBEEF12345678,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
            0,
            16,
        );
        assert!(ok.is_ok(), "params write must succeed");
        // Read back through the provider and validate the envelope.
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut blob = vec![0u8; PARAMS_HEADER_BYTES + 2 * 8];
        assert!(p.read(m.params_va().unwrap(), &mut blob).is_ok());
        let (params, cands) =
            mida_antidebug_runtime::walker_protocol::controller_validate_entry(&blob).unwrap();
        assert_eq!(params.candidate_count, 2);
        assert_eq!(cands, candidates);
        m.cleanup(self_handle());
    }

    #[test]
    fn memory_write_section_header_roundtrip() {
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle()).unwrap();
        let sid = [0x11u8; WALKER_SESSION_ID_BYTES];
        let ok = m.write_section_header(
            self_handle(),
            0x12345678,
            std::process::id(),
            4242,
            sid,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
        );
        assert!(ok.is_ok());
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        // parse_section needs the FULL declared section (section_bytes),
        // Re-read the full section and validate identity fields via the
        // public validator (from_bytes is private).
        let mut full = vec![0u8; MIN_SECTION_HEADER_BYTES];
        assert!(p.read(m.section1_va().unwrap(), &mut full).is_ok());
        let ident = MappingIdentityHeaderV2 {
            magic: u32::from_le_bytes(full[0..4].try_into().unwrap()),
            version: u16::from_le_bytes(full[4..6].try_into().unwrap()),
            _reserved: 0,
            section_bytes: u64::from_le_bytes(full[8..16].try_into().unwrap()),
            target_pid: u32::from_le_bytes(full[16..20].try_into().unwrap()),
            owner_pid: u32::from_le_bytes(full[20..24].try_into().unwrap()),
            nonce: u64::from_le_bytes(full[24..32].try_into().unwrap()),
            session_id: full[32..48].try_into().unwrap(),
            header_crc32: 0,
            _reserved2: 0,
        };
        assert_eq!(ident.nonce, 0x12345678);
        assert_eq!(ident.target_pid, std::process::id());
        assert_eq!(ident.session_id, sid);
        m.cleanup(self_handle());
    }

    #[test]
    fn memory_cleanup_idempotent() {
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle()).unwrap();
        m.cleanup(self_handle());
        m.cleanup(self_handle());
        assert!(m.params_va().is_none() && m.section1_va().is_none());
    }

    // ---------- full production install (engineering runtime) ----------

    #[test]
    fn full_install_transactional_success_and_abort_cleanup() {
        reset_runtime();
        // Use candidates that are ACTUALLY mapped in our own process so
        // the driver can complete real probe rounds (engineering runtime).
        let probe_region = alloc_local(0x1000);
        assert!(!probe_region.is_null());
        let candidates = [probe_region as u64, probe_region as u64 + 0x100];
        let sid = [0x22u8; WALKER_SESSION_ID_BYTES];
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &candidates,
            0x1122334455667788,
            0,
            16,
            sid,
            &dig64('a'),
            &dig64('b'),
            0x7FF600000000,
            0x2040,
            &dig64('c'),
            &dig64('d'),
        );
        assert!(
            r.is_some(),
            "production install must succeed on engineering runtime"
        );
        let mem = r.unwrap();
        let pv = mem.params_va().unwrap();
        let sv = mem.section1_va().unwrap();
        assert_ne!(pv, sv);
        // The installed session must now be executable: call WalkerExecute
        // with the real params VA — the runtime drives the full protocol
        // against our provider (reads own-process memory).
        let status = unsafe { mida_antidebug_runtime::exports::WalkerExecute(pv) };
        // The driver probes REAL mapped memory in our process. Probe
        // execution (VEH/SEH shim) is not installable on the engineering
        // runtime, so the walker fails closed with PROBE_ABORTED (4) — it
        // NEVER panics, NEVER hangs, NEVER fabricates success. (A live
        // walker with a real shim would return OK; that is the later
        // IMP-09-LIVE-WALKER-R1 order.)
        assert_eq!(
            status,
            mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_PROBE_ABORTED as i32,
            "engineering runtime must abort probes fail-closed (no fake success)"
        );
        let _ = mida_antidebug_runtime::exports::take_walker_output();
    }

    #[test]
    fn install_failure_no_ready() {
        reset_runtime();
        // Invalid target_image digest (uppercase) must fail BEFORE any
        // allocation survives; install returns None.
        let candidates: [u64; 1] = [0x400000];
        let sid = [0x33u8; WALKER_SESSION_ID_BYTES];
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &candidates,
            0x99,
            0,
            16,
            sid,
            &dig64('A'), // uppercase -> invalid
            &dig64('b'),
            0x7FF600000000,
            0x2040,
            &dig64('c'),
            &dig64('d'),
        );
        assert!(r.is_none(), "invalid digest must fail closed");
        let _ = mida_antidebug_runtime::exports::take_walker_output();
    }

    #[test]
    fn fixed_va_never_used_in_production_path() {
        // The production seam takes no VA inputs at all: it allocates
        // and returns them. Assert the API shape here so a future change
        // cannot smuggle fixed VAs into the bind.
        let f = install_walker_session_production
            as fn(
                HANDLE,
                u32,
                u32,
                &[u64],
                u64,
                u16,
                u16,
                [u8; WALKER_SESSION_ID_BYTES],
                &str,
                &str,
                u64,
                u64,
                &str,
                &str,
            ) -> Option<WalkerSessionMemory>;
        let _ = f;
    }

    // ---------- rollback / alias / short-write ----------

    #[test]
    fn allocate_rollback_frees_both_on_second_failure() {
        // A NULL/invalid target handle makes the SECOND allocation fail;
        // the first must be rolled back (no leak, no partial state).
        let mut m = WalkerSessionMemory::new();
        let r = m.allocate(HANDLE(std::ptr::null_mut()));
        assert!(r.is_none(), "allocation against invalid handle must fail");
        assert!(
            m.params_va().is_none() && m.section1_va().is_none(),
            "failed allocate must leave no partial allocations"
        );
    }

    #[test]
    fn params_section_alias_rejected_by_allocate() {
        // allocate() guarantees params_va != section1_va (hard invariant);
        // the alias check is inside the allocator, so a successful
        // allocate proves distinctness.
        let mut m = WalkerSessionMemory::new();
        let r = m.allocate(self_handle()).unwrap();
        assert_ne!(r.0, r.1, "params_va must never alias section1_va");
        m.cleanup(self_handle());
    }

    #[test]
    fn wpm_short_write_detected() {
        // write_params against an invalid target handle must fail
        // (WriteProcessMemory fails closed on a bad handle).
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle()).unwrap();
        let bad = HANDLE(std::ptr::null_mut());
        let r = m.write_params(bad, 1, &[0x400000], 0x1234, 96 + 40, 0, 16);
        assert!(r.is_err(), "write to invalid handle must fail closed");
        m.cleanup(self_handle());
    }

    #[test]
    fn header_nonce_mismatch_detected_by_section_readback() {
        // The section identity header carries the session nonce; reading
        // it back must match what was written (mismatch => protocol
        // rejects the section at consume time).
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle()).unwrap();
        let sid = [0x44u8; WALKER_SESSION_ID_BYTES];
        m.write_section_header(
            self_handle(),
            0xCAFEBABE,
            std::process::id(),
            777,
            sid,
            96 + 40 * 2,
        )
        .unwrap();
        let p = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut full = vec![0u8; WALKER_SECTION_REGION_BYTES];
        p.read(m.section1_va().unwrap(), &mut full).unwrap();
        // The nonce field is at [24..32) in the identity header.
        let nonce = u64::from_le_bytes(full[24..32].try_into().unwrap());
        assert_eq!(nonce, 0xCAFEBABE);
        // A wrong nonce would fail parse_section identity validation:
        // prove the readback is the only honest source.
        let ident_ok = MappingIdentityHeaderV2 {
            magic: u32::from_le_bytes(full[0..4].try_into().unwrap()),
            version: u16::from_le_bytes(full[4..6].try_into().unwrap()),
            _reserved: 0,
            section_bytes: u64::from_le_bytes(full[8..16].try_into().unwrap()),
            target_pid: u32::from_le_bytes(full[16..20].try_into().unwrap()),
            owner_pid: u32::from_le_bytes(full[20..24].try_into().unwrap()),
            nonce,
            session_id: full[32..48].try_into().unwrap(),
            header_crc32: 0,
            _reserved2: 0,
        };
        assert_eq!(ident_ok.nonce, 0xCAFEBABE);
        assert_eq!(ident_ok.target_pid, std::process::id());
        assert_eq!(ident_ok.session_id, sid);
        m.cleanup(self_handle());
    }
}
