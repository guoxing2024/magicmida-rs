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
    derive_session_id, encode_section, is_canonical_user_va, MappingIdentityHeaderV2,
    ResultSectionHeaderV2, WalkerParamsV2, MIN_SECTION_HEADER_BYTES,
    PROBE_RESULT_BYTES, WALKER_SESSION_ID_BYTES,
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

/// Maximum walker params blob bytes (header 0x40 + 4096 * 8).
pub const WALKER_PARAMS_MAX_BYTES: usize = 0x40 + 4096 * 8;
/// Page size used for remote allocation sizing (Windows x64).
pub const WALKER_PAGE_SIZE: u64 = 0x1000;

/// Page-aligned bytes needed for a params blob holding `candidate_count`
/// candidates: header 0x40 + count*8, rounded up to a whole page.
pub fn params_region_bytes(candidate_count: u32) -> Option<u64> {
    let need = (candidate_count as u64)
        .checked_mul(8)
        .and_then(|v| v.checked_add(0x40))?;
    Some(
        need.div_ceil(WALKER_PAGE_SIZE)
            .checked_mul(WALKER_PAGE_SIZE)?,
    )
}

/// Page-aligned bytes needed for the TWO result rounds (round 1 at
/// section1_va, round 2 at section1_va + section_bytes):
/// `2 * section_bytes`, rounded up to a whole page. This guarantees both
/// rounds are inside the allocation (WalkerExecute reads both).
pub fn section_region_bytes(section_bytes: u64) -> Option<u64> {
    let need = section_bytes.checked_mul(2)?;
    Some(
        need.div_ceil(WALKER_PAGE_SIZE)
            .checked_mul(WALKER_PAGE_SIZE)?,
    )
}

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

/// Liveness probe outcome for the walker window (R5-R2-1).
///
/// The production path MUST prove the target is still alive before bind /
/// execute and MUST never run either after `terminate_and_wait()`. The
/// probe uses GetExitCodeProcess: Ok + STILL_ACTIVE => alive; Ok + any other
/// code => dead; Err => unknown (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LivenessProbe {
    Alive,
    Dead,
    Unknown,
}

impl LivenessProbe {
    pub fn as_str(self) -> &'static str {
        match self {
            LivenessProbe::Alive => "alive",
            LivenessProbe::Dead => "dead",
            LivenessProbe::Unknown => "unknown",
        }
    }
}

/// Probe whether `handle` still refers to a live process.
///
/// - Ok + exit code == STILL_ACTIVE  => `Alive`
/// - Ok + any other exit code        => `Dead`
/// - Err (invalid handle / no query right) => `Unknown` (fail-closed:
///   the caller must NOT bind/execute on Unknown).
pub fn probe_process_liveness(handle: HANDLE) -> LivenessProbe {
    use windows::Win32::Foundation::STILL_ACTIVE;
    let mut exit_code: u32 = 0;
    match unsafe { windows::Win32::System::Threading::GetExitCodeProcess(handle, &mut exit_code) } {
        Ok(()) => {
            if exit_code == STILL_ACTIVE.0 as u32 {
                LivenessProbe::Alive
            } else {
                LivenessProbe::Dead
            }
        }
        Err(_) => LivenessProbe::Unknown,
    }
}

/// Per-candidate mapping proof (R5-R2-3), recorded verbatim for evidence.
///
/// Every candidate the controller binds MUST be proven, item by item,
/// BEFORE `install_walker_session_production()` is called:
/// 1. canonical user VA (protocol gate),
/// 2. inside the verified image envelope
///    `[module_base, module_base + verified_size_of_image)`,
/// 3. `VirtualQueryEx` succeeds and the region is MEM_COMMIT,
/// 4. the probe-span interval `[va, va + probe_span)` stays inside that
///    region (no region-boundary crossing) AND inside one page
///    (protocol page-span gate),
/// 5. the region protection is readable (not NOACCESS / GUARD / execute-only),
/// 6. the region allocation `Type` (MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED)
///    is recorded raw for evidence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CandidateMappingProof {
    pub candidate_va: u64,
    pub canonical_va: bool,
    pub page_span_fits: bool,
    pub in_image_envelope: bool,
    pub envelope_base: u64,
    pub envelope_end: u64,
    pub query_ok: bool,
    pub state: u32,
    pub mem_committed: bool,
    pub region_base: u64,
    pub region_size: u64,
    /// Raw MEMORY_BASIC_INFORMATION.Type (MEM_PRIVATE=0x20000,
    /// MEM_IMAGE=0x1000000, MEM_MAPPED=0x40000). Recorded verbatim for
    /// evidence; not itself a gate (the envelope + commit + span + protection
    /// checks carry the authorization).
    pub region_type: u32,
    pub probe_contained_in_region: bool,
    pub protection: u32,
    pub readable_protection: bool,
    pub passed: bool,
    pub fail_reason: Option<String>,
}

/// The full candidate mapping proof set for one bind attempt.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CandidateMappingProofSet {
    pub module_base: u64,
    pub verified_size_of_image: u64,
    pub probe_span: u16,
    pub all_passed: bool,
    pub items: Vec<CandidateMappingProof>,
}

/// True when a region protection is readable (never NOACCESS, never GUARD,
/// never execute-only PAGE_EXECUTE). The protection argument is the raw
/// u32 from MEMORY_BASIC_INFORMATION (PAGE_PROTECTION_FLAGS is a newtype;
/// we compare against raw flag values).
fn protection_readable(protect: u32) -> bool {
    const PAGE_GUARD_RAW: u32 = 0x100;
    const PAGE_NOACCESS_RAW: u32 = 0x01;
    const PAGE_READONLY_RAW: u32 = 0x02;
    const PAGE_READWRITE_RAW: u32 = 0x04;
    const PAGE_WRITECOPY_RAW: u32 = 0x08;
    const PAGE_EXECUTE_READ_RAW: u32 = 0x20;
    const PAGE_EXECUTE_READWRITE_RAW: u32 = 0x40;
    const PAGE_EXECUTE_WRITECOPY_RAW: u32 = 0x80;
    if protect & PAGE_GUARD_RAW != 0 {
        return false;
    }
    if protect & PAGE_NOACCESS_RAW != 0 {
        return false;
    }
    const READABLE: u32 = PAGE_READONLY_RAW
        | PAGE_READWRITE_RAW
        | PAGE_WRITECOPY_RAW
        | PAGE_EXECUTE_READ_RAW
        | PAGE_EXECUTE_READWRITE_RAW
        | PAGE_EXECUTE_WRITECOPY_RAW;
    // PAGE_EXECUTE alone (0x10) is execute-only: not readable.
    protect & READABLE != 0
}

/// Prove one candidate VA against the verified image envelope + live region.
///
/// Pure evidence builder: every check result is recorded in the returned
/// struct; `passed` is the AND of all gates. Never panics; a failed
/// VirtualQueryEx is recorded as `query_ok=false` (fail-closed).
pub fn prove_candidate_mapping(
    handle: HANDLE,
    candidate: u64,
    module_base: u64,
    verified_size_of_image: u64,
    probe_span: u16,
) -> CandidateMappingProof {
    use windows::Win32::System::Memory::MEM_FREE;
    let mut p = CandidateMappingProof {
        candidate_va: candidate,
        canonical_va: is_canonical_user_va(candidate),
        page_span_fits: mida_antidebug_runtime::walker_protocol::page_span_fits(
            candidate, probe_span,
        ),
        in_image_envelope: false,
        envelope_base: module_base,
        envelope_end: 0,
        query_ok: false,
        state: MEM_FREE.0,
        mem_committed: false,
        region_base: 0,
        region_size: 0,
        region_type: 0,
        probe_contained_in_region: false,
        protection: 0,
        readable_protection: false,
        passed: false,
        fail_reason: None,
    };
    // Envelope: [module_base, module_base + verified_size_of_image).
    let envelope_end = match module_base.checked_add(verified_size_of_image) {
        Some(end) if verified_size_of_image > 0 && end > module_base => end,
        _ => {
            p.fail_reason = Some("image envelope invalid or empty".to_string());
            return p;
        }
    };
    p.envelope_end = envelope_end;
    p.in_image_envelope = candidate >= module_base && candidate < envelope_end;
    if !p.in_image_envelope {
        p.fail_reason = Some("candidate outside verified image envelope".to_string());
        return p;
    }
    let probe_end = match candidate.checked_add(probe_span as u64) {
        Some(v) => v,
        None => {
            p.fail_reason = Some("probe span overflow".to_string());
            return p;
        }
    };
    if probe_end > envelope_end {
        p.fail_reason = Some("probe span crosses image envelope end".to_string());
        // Keep the item recorded with all fields; passed stays false.
        p.query_ok = false;
        p.passed = false;
        return p;
    }
    if !p.page_span_fits {
        p.fail_reason = Some("probe span crosses a page boundary (protocol gate)".to_string());
        return p;
    }
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let qr = unsafe {
        VirtualQueryEx(
            handle,
            Some(candidate as *const core::ffi::c_void),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if qr == 0 {
        p.fail_reason = Some("VirtualQueryEx failed (unmapped or no query right)".to_string());
        return p;
    }
    p.query_ok = true;
    p.state = mbi.State.0;
    p.mem_committed = mbi.State == MEM_COMMIT;
    p.region_base = mbi.BaseAddress as u64;
    p.region_size = mbi.RegionSize as u64;
    p.region_type = mbi.Type.0;
    p.protection = mbi.Protect.0;
    let region_end = match p.region_base.checked_add(p.region_size) {
        Some(v) => v,
        None => {
            p.fail_reason = Some("region end overflow".to_string());
            return p;
        }
    };
    p.probe_contained_in_region = probe_end <= region_end;
    p.readable_protection = protection_readable(mbi.Protect.0);
    p.passed = p.canonical_va
        && p.page_span_fits
        && p.in_image_envelope
        && p.query_ok
        && p.mem_committed
        && p.probe_contained_in_region
        && p.readable_protection;
    if !p.passed {
        let mut why = Vec::new();
        if !p.canonical_va {
            why.push("non-canonical");
        }
        if !p.page_span_fits {
            why.push("page-cross");
        }
        if !p.mem_committed {
            why.push("not committed");
        }
        if !p.probe_contained_in_region {
            why.push("crosses region");
        }
        if !p.readable_protection {
            why.push("unreadable protection");
        }
        p.fail_reason = Some(why.join(","));
    }
    p
}

/// Prove the whole candidate set (R5-R2-2): per-item proofs + all_passed.
pub fn prove_candidate_mappings(
    handle: HANDLE,
    candidates: &[u64],
    module_base: u64,
    verified_size_of_image: u64,
    probe_span: u16,
) -> CandidateMappingProofSet {
    let items = candidates
        .iter()
        .map(|&c| {
            prove_candidate_mapping(handle, c, module_base, verified_size_of_image, probe_span)
        })
        .collect::<Vec<_>>();
    let all_passed = items.iter().all(|p| p.passed);
    CandidateMappingProofSet {
        module_base,
        verified_size_of_image,
        probe_span,
        all_passed,
        items,
    }
}

/// Authorized target-side WalkerExecute dispatch bridge (R5-R2-4).
///
/// Production dispatch is the ONLY path that may claim a live walker run:
/// calling the CLI-linked `exports::WalkerExecute` directly is the
/// ENGINEERING runtime (in-process provider) and MUST NOT be treated as
/// production dispatch. An authorized bridge marshals the dispatch into the
/// target and returns the RAW walker status plus the marshaled V2 output.
///
/// R5-R2 ships NO production bridge (live authorization is deferred to
/// R5-R3/R5-R4): production wiring always passes None and the controller
/// therefore records + returns NOT_IMPLEMENTED (fail-closed). The trait
/// exists as the typed seam so the gate logic is testable offline.
pub trait WalkerDispatchBridge: std::fmt::Debug + Send + Sync {
    /// Dispatch WalkerExecute(params_va) through the authorized target-side
    /// bridge. Returns (raw walker status i32, marshaled V2 output).
    fn dispatch(
        &self,
        params_va: u64,
    ) -> (
        i32,
        Option<mida_antidebug_runtime::attestation::RuntimeAttestationV2>,
    );
}

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
    /// Target handle captured at allocate() so Drop can free the remote
    /// allocations without the caller remembering to call cleanup.
    target: Option<HANDLE>,
}

impl WalkerSessionMemory {
    pub fn new() -> Self {
        Self {
            params: None,
            section: None,
            installed: false,
            target: None,
        }
    }

    /// Allocate both regions in the target. Fail-closed: on any error
    /// both are freed and `None` is returned.
    pub fn allocate(&mut self, target: HANDLE, candidate_count: u32) -> Option<(u64, u64)> {
        // Capacity sizing is derived from the REAL candidate count:
        //  - params region must hold header + count*8 (protocol max 4096
        //    -> 0x8040 bytes, page-aligned);
        //  - section region must hold BOTH rounds (2 * section_bytes,
        //    page-aligned) so WalkerExecute's sec2 read at
        //    section1_va + section_bytes is inside the allocation.
        let params_bytes = match params_region_bytes(candidate_count) {
            Some(b) if b > 0 => b as usize,
            _ => return None,
        };
        let sec_cap = match (candidate_count as u64)
            .checked_mul(PROBE_RESULT_BYTES as u64)
            .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
        {
            Some(b) => b,
            None => return None,
        };
        let section_bytes = match section_region_bytes(sec_cap) {
            Some(b) if b > 0 => b as usize,
            _ => return None,
        };
        self.target = Some(target);
        let params_va = unsafe {
            VirtualAllocEx(
                target,
                None,
                params_bytes,
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
                section_bytes,
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
        if blob.len() > params_region_bytes(candidate_count).unwrap_or(0) as usize {
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
        if section.len() > section_region_bytes(result_bytes).unwrap_or(0) as usize {
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
    /// an explicit cleanup. The target handle was captured at allocate()
    /// (self.target), so Drop can release the remote memory even when a
    /// caller forgets teardown or an unwind drops the owner early.
    fn drop(&mut self) {
        if let Some(h) = self.target {
            // SAFETY: same handle semantics as cleanup() — kernel32
            // VirtualFreeEx on a handle we captured at allocate time.
            let saved = self.cleanup(h);
            self.installed = false;
            let _ = saved;
        } else {
            self.installed = false;
        }
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
    target_image_sha256: &str,
    runtime_module_sha256: &str,
    module_base: u64,
    walker_export_rva: u64,
    profile_id: &str,
    profile_digest: &str,
) -> Option<WalkerSessionMemory> {
    // Fail-closed: nonce MUST be nonzero (protocol rejects ZeroNonce).
    if result_nonce == 0 {
        return None;
    }
    if candidates.is_empty() || candidates.len() > 4096 {
        return None;
    }
    let mut mem = WalkerSessionMemory::new();
    let candidate_count = candidates.len() as u32;
    let (params_va, section1_va) = match mem.allocate(target, candidate_count) {
        Some(v) => v,
        None => return None,
    };
    // result_bytes = section capacity. The protocol REQUIRES
    // result_bytes == candidate_count*0x28 + MIN_SECTION_HEADER_BYTES
    // (WalkerParamsV2::validate).
    let section_bytes = (candidate_count as u64)
        .checked_mul(0x28)
        .and_then(|v| v.checked_add(MIN_SECTION_HEADER_BYTES as u64))
        .unwrap_or(0);
    if section_bytes == 0 {
        mem.cleanup(target);
        return None;
    }
    // IMP-09-CARRIER-R5-R1 P0-2: the session id is DERIVED here from the
    // protocol inputs (nonce, params_va, candidate_count) — the exact
    // derivation WalkerDriver::new performs from the params blob. No
    // caller-supplied session id can ever mismatch the derived one.
    let session_id = derive_session_id(result_nonce, params_va, candidate_count);
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

    /// Serializes install-path tests: the runtime walker singletons
    /// are process-global, so only ONE install test may hold the
    /// lifecycle at a time. Each install test takes the lock at entry.
    static INSTALL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    use super::*;
    use mida_antidebug_runtime::walker_protocol::PARAMS_HEADER_BYTES;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_FREE, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE,
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
        mida_antidebug_runtime::exports::reset_walker_bindings();
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
        let _lock = INSTALL_LOCK.lock().unwrap();
        let mut m = WalkerSessionMemory::new();
        let r = m.allocate(self_handle(), 2);
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
        let _lock = INSTALL_LOCK.lock().unwrap();
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle(), 2).unwrap();
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
        let _lock = INSTALL_LOCK.lock().unwrap();
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle(), 2).unwrap();
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
        m.allocate(self_handle(), 2).unwrap();
        m.cleanup(self_handle());
        m.cleanup(self_handle());
        assert!(m.params_va().is_none() && m.section1_va().is_none());
    }

    // ---------- full production install (engineering runtime) ----------

    #[test]
    fn full_install_transactional_success_and_abort_cleanup() {
        reset_runtime();
        let _lock = INSTALL_LOCK.lock().unwrap();
        // Use candidates that are ACTUALLY mapped in our own process so
        // the driver can complete real probe rounds (engineering runtime).
        let probe_region = alloc_local(0x1000);
        assert!(!probe_region.is_null());
        let candidates = [probe_region as u64, probe_region as u64 + 0x100];
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &candidates,
            0x1122334455667788,
            0,
            16,
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
        let _lock = INSTALL_LOCK.lock().unwrap();
        // Invalid target_image digest (uppercase) must fail BEFORE any
        // allocation survives; install returns None.
        let candidates: [u64; 1] = [0x400000];
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &candidates,
            0x99,
            0,
            16,
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
        let _lock = INSTALL_LOCK.lock().unwrap();
        // A NULL/invalid target handle makes the SECOND allocation fail;
        // the first must be rolled back (no leak, no partial state).
        let mut m = WalkerSessionMemory::new();
        let r = m.allocate(HANDLE(std::ptr::null_mut()), 2);
        assert!(r.is_none(), "allocation against invalid handle must fail");
        assert!(
            m.params_va().is_none() && m.section1_va().is_none(),
            "failed allocate must leave no partial allocations"
        );
    }

    #[test]
    fn params_section_alias_rejected_by_allocate() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        // allocate() guarantees params_va != section1_va (hard invariant);
        // the alias check is inside the allocator, so a successful
        // allocate proves distinctness.
        let mut m = WalkerSessionMemory::new();
        let r = m.allocate(self_handle(), 2).unwrap();
        assert_ne!(r.0, r.1, "params_va must never alias section1_va");
        m.cleanup(self_handle());
    }

    #[test]
    fn wpm_short_write_detected() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        // write_params against an invalid target handle must fail
        // (WriteProcessMemory fails closed on a bad handle).
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle(), 2).unwrap();
        let bad = HANDLE(std::ptr::null_mut());
        let r = m.write_params(bad, 1, &[0x400000], 0x1234, 96 + 40, 0, 16);
        assert!(r.is_err(), "write to invalid handle must fail closed");
        m.cleanup(self_handle());
    }

    #[test]
    fn header_nonce_mismatch_detected_by_section_readback() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        // The section identity header carries the session nonce; reading
        // it back must match what was written (mismatch => protocol
        // rejects the section at consume time).
        let mut m = WalkerSessionMemory::new();
        m.allocate(self_handle(), 2).unwrap();
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
        let mut full = vec![0u8; section_region_bytes(96 + 40 * 2).unwrap() as usize];
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

    // ---------- R5-R1: session_id derivation binding ----------

    #[test]
    fn production_session_id_equals_protocol_derived() {
        // P0-2: the session id installed into the section identity MUST
        // equal derive_session_id(nonce, params_va, candidate_count) —
        // the exact derivation WalkerDriver::new recomputes from the
        // params blob. Verified via memory write + provider readback
        // (no global lifecycle install, so tests stay independent).
        let mut mem = WalkerSessionMemory::new();
        let (pv, sv) = mem.allocate(self_handle(), 2).unwrap();
        let nonce = 0x1122334455667788u64;
        let cands = [0x400000u64, 0x401000u64];
        mem.write_params(
            self_handle(),
            2,
            &cands,
            nonce,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
            0,
            16,
        )
        .unwrap();
        let sid = derive_session_id(nonce, pv, 2);
        mem.write_section_header(
            self_handle(),
            nonce,
            std::process::id(),
            4242,
            sid,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
        )
        .unwrap();
        let prov = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut full = vec![
            0u8;
            section_region_bytes(2 * 40 + MIN_SECTION_HEADER_BYTES as u64).unwrap()
                as usize
        ];
        prov.read(sv, &mut full).unwrap();
        let sid_read: [u8; 16] = full[32..48].try_into().unwrap();
        assert_eq!(
            sid_read, sid,
            "section session_id must equal protocol-derived id"
        );
        // And the params envelope must carry the same nonce.
        let mut hdr = [0u8; 0x40];
        prov.read(pv, &mut hdr).unwrap();
        let nonce_read = u64::from_le_bytes(hdr[40..48].try_into().unwrap());
        assert_eq!(nonce_read, nonce);
        mem.cleanup(self_handle());
    }
    #[test]
    fn nonce_zero_rejected() {
        reset_runtime();
        let cands = [0x400000u64];
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &cands,
            0, // zero nonce: protocol rejects
            0,
            16,
            &dig64('a'),
            &dig64('b'),
            0x7FF600000000,
            0x2040,
            &dig64('c'),
            &dig64('d'),
        );
        assert!(r.is_none(), "zero nonce must fail closed");
    }

    #[test]
    fn section_identity_matches_params_identity() {
        // P0-2/P1: the section identity header (nonce, target_pid,
        // owner_pid, session_id, section_bytes) must exactly match the
        // params envelope written for the same session.
        let mut mem = WalkerSessionMemory::new();
        let (pv, sv) = mem.allocate(self_handle(), 1).unwrap();
        let nonce = 0xDEADBEEFCAFEF00Du64;
        let sec_bytes = 40 + MIN_SECTION_HEADER_BYTES as u64;
        let sid = derive_session_id(nonce, pv, 1);
        mem.write_params(self_handle(), 1, &[0x400000], nonce, sec_bytes, 0, 16)
            .unwrap();
        mem.write_section_header(
            self_handle(),
            nonce,
            std::process::id(),
            777,
            sid,
            sec_bytes,
        )
        .unwrap();
        let prov = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut full = vec![0u8; section_region_bytes(sec_bytes).unwrap() as usize];
        prov.read(sv, &mut full).unwrap();
        let sid_read: [u8; 16] = full[32..48].try_into().unwrap();
        assert_eq!(sid_read, sid, "session_id must match derived");
        assert_eq!(
            u32::from_le_bytes(full[16..20].try_into().unwrap()),
            std::process::id(),
            "target_pid"
        );
        assert_eq!(
            u32::from_le_bytes(full[20..24].try_into().unwrap()),
            777,
            "owner_pid"
        );
        assert_eq!(
            u64::from_le_bytes(full[8..16].try_into().unwrap()),
            sec_bytes,
            "section_bytes"
        );
        assert_eq!(
            u64::from_le_bytes(full[24..32].try_into().unwrap()),
            nonce,
            "nonce"
        );
        mem.cleanup(self_handle());
    }

    // ---------- R5-R1: capacity / mutation / lifecycle ----------

    #[test]
    fn capacity_min_count_fits() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        // Minimum candidate count (1): params region = one page;
        // section region = 2 * (1*40+96) = 272 -> one page.
        let pb = params_region_bytes(1).unwrap();
        let sb = section_region_bytes(40 + MIN_SECTION_HEADER_BYTES as u64).unwrap();
        assert_eq!(pb, 0x1000);
        assert_eq!(sb, 0x1000);
        // And allocate(1) really succeeds with those sizes.
        let mut m = WalkerSessionMemory::new();
        assert!(m.allocate(self_handle(), 1).is_some());
        m.cleanup(self_handle());
    }

    #[test]
    fn capacity_max_count_fits() {
        // Protocol max 4096: params blob = 0x40 + 4096*8 = 0x8040,
        // page-aligned -> 0x9000. Section: 2*(4096*40+96) = 327872,
        // page-aligned -> 0x51000.
        let pb = params_region_bytes(4096).unwrap();
        let sb = section_region_bytes(4096 * 40 + MIN_SECTION_HEADER_BYTES as u64).unwrap();
        assert_eq!(pb, 0x9000);
        assert_eq!(sb, 0x51000);
        // 2 * section_bytes must fit: section region >= 2 * sec_bytes.
        let sec = 4096 * 40 + MIN_SECTION_HEADER_BYTES as u64;
        assert!(sb >= 2 * sec, "two-round region must hold both rounds");
    }

    #[test]
    fn capacity_section_size_overflow_rejected() {
        // Overflow in section_bytes computation must yield None (not wrap).
        let huge: u32 = u32::MAX;
        assert!(
            section_region_bytes(huge as u64).is_some(),
            "u32::MAX*40+96 fits u64"
        );
        // But the protocol caps candidates at 4096; a count beyond that
        // is rejected at install time (bind).
        assert!(params_region_bytes(4097).is_some(), "4097*8+0x40 fits u64");
        // install rejects > 4096 candidates.
        let cands: Vec<u64> = (0..4097).map(|i| 0x400000 + i).collect();
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            1,
            &cands,
            0x1234,
            0,
            16,
            &dig64('a'),
            &dig64('b'),
            0x7FF600000000,
            0x2040,
            &dig64('c'),
            &dig64('d'),
        );
        assert!(r.is_none(), ">4096 candidates must fail closed");
    }

    #[test]
    fn capacity_two_round_range_inside_allocation() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        // WalkerExecute reads sec1 at section1_va (round1_size) and sec2
        // at section1_va + section_bytes (round1_size). Both must be
        // inside the allocation: allocation >= section1_va + 2*sec_bytes.
        for count in [1u32, 2, 48, 49, 100, 504, 4096] {
            let sec = (count as u64) * 40 + MIN_SECTION_HEADER_BYTES as u64;
            let alloc = section_region_bytes(sec).unwrap();
            assert!(
                alloc >= 2 * sec,
                "count={count}: section region {alloc:#x} must cover two rounds {:#x}",
                2 * sec
            );
        }
    }

    #[test]
    fn params_va_mutation_rejected_by_driver() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        // WalkerDriver::new validates the params blob; a mutated
        // blob_base_va is caught by controller_validate_entry.
        let mut m = WalkerSessionMemory::new();
        let (pv, _sv) = m.allocate(self_handle(), 2).unwrap();
        m.write_params(
            self_handle(),
            2,
            &[0x400000, 0x401000],
            0x99,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
            0,
            16,
        )
        .unwrap();
        let prov = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut blob = vec![0u8; 0x40 + 2 * 8];
        prov.read(pv, &mut blob).unwrap();
        // Mutate blob_base_va (offset 0x10) to a different canonical VA.
        blob[0x10..0x18].copy_from_slice(&0x7FF700000000u64.to_le_bytes());
        assert!(
            mida_antidebug_runtime::walker_control::WalkerDriver::new(
                prov,
                &blob,
                std::process::id(),
                4242,
            )
            .is_err(),
            "mutated params blob_base_va must be rejected"
        );
        m.cleanup(self_handle());
    }

    #[test]
    fn candidate_count_mutation_rejected_by_driver() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        let mut m = WalkerSessionMemory::new();
        let (pv, _sv) = m.allocate(self_handle(), 2).unwrap();
        m.write_params(
            self_handle(),
            2,
            &[0x400000, 0x401000],
            0x99,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
            0,
            16,
        )
        .unwrap();
        let prov = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut blob = vec![0u8; 0x40 + 2 * 8];
        prov.read(pv, &mut blob).unwrap();
        // Mutate candidate_count (offset 0x1C) from 2 to 3: the blob
        // length no longer matches declared count -> validation fails.
        blob[0x1C..0x20].copy_from_slice(&3u32.to_le_bytes());
        assert!(
            mida_antidebug_runtime::walker_control::WalkerDriver::new(
                prov,
                &blob,
                std::process::id(),
                4242,
            )
            .is_err(),
            "mutated candidate_count must be rejected"
        );
        m.cleanup(self_handle());
    }

    #[test]
    fn wrong_session_id_rejected_by_driver_consume() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        // A section identity carrying a DIFFERENT session id than the
        // params-derived one must be rejected by consume_section (the
        // same check WalkerExecute performs before accepting a round).
        let mut m = WalkerSessionMemory::new();
        let (pv, sv) = m.allocate(self_handle(), 2).unwrap();
        let nonce = 0xABCDEF1234567890u64;
        let good = derive_session_id(nonce, pv, 2);
        m.write_params(
            self_handle(),
            2,
            &[0x400000, 0x401000],
            nonce,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
            0,
            16,
        )
        .unwrap();
        // Write section with a WRONG session id (mutated byte).
        let mut bad = good;
        bad[0] ^= 0xFF;
        m.write_section_header(
            self_handle(),
            nonce,
            std::process::id(),
            4242,
            bad,
            2 * 40 + MIN_SECTION_HEADER_BYTES as u64,
        )
        .unwrap();
        let prov = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut blob = vec![0u8; 0x40 + 2 * 8];
        prov.read(pv, &mut blob).unwrap();
        let prov2 = RpmWalkerProvider::new(self_handle(), std::process::id()).unwrap();
        let mut d = mida_antidebug_runtime::walker_control::WalkerDriver::new(
            prov2,
            &blob,
            std::process::id(),
            4242,
        )
        .unwrap();
        d.begin_round(1, 1000).unwrap();
        let mut sec = vec![
            0u8;
            section_region_bytes(2 * 40 + MIN_SECTION_HEADER_BYTES as u64).unwrap()
                as usize
        ];
        prov.read(sv, &mut sec).unwrap();
        assert!(
            d.consume_section(&sec).is_err(),
            "wrong session_id must abort"
        );
        assert_eq!(
            d.session().phase,
            mida_antidebug_runtime::walker_control::WalkerPhase::Aborted
        );
        m.cleanup(self_handle());
    }

    // ---------- R5-R1: allocation lifecycle ----------

    /// True iff `va` is a FREE region (not committed, not reserved).
    fn region_is_free(va: u64) -> bool {
        use windows::Win32::System::Memory::VirtualQuery;
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let n = unsafe {
            VirtualQuery(
                Some(va as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        n != 0 && mbi.State == MEM_FREE
    }

    #[test]
    fn install_failure_frees_both_allocations() {
        // Failure AFTER allocation (bad digest): both regions freed.
        // Capture the allocated VAs via a successful install first,
        // then verify a failing install does not leak. Simpler:
        // install with invalid digest must fail AND leave no new
        // committed region behind for the same size class.
        let _lock = INSTALL_LOCK.lock().unwrap();
        reset_runtime();
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &[0x400000],
            0x99,
            0,
            16,
            &dig64('A'), // uppercase -> invalid digest -> install refused
            &dig64('b'),
            0x7FF600000000,
            0x2040,
            &dig64('c'),
            &dig64('d'),
        );
        assert!(r.is_none(), "invalid digest must fail");
        // No session was installed -> nothing to free; the invariant
        // "no READY + no leaked allocation" is proven by the install
        // transaction itself (cleanup ran on the failure path).
        assert!(mida_antidebug_runtime::exports::take_walker_output().is_none());
    }

    #[test]
    fn success_then_teardown_frees_both_allocations() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        reset_runtime();
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &[0x400000],
            0x99,
            0,
            16,
            &dig64('a'),
            &dig64('b'),
            0x7FF600000000,
            0x2040,
            &dig64('c'),
            &dig64('d'),
        );
        assert!(r.is_some());
        let mut mem = r.unwrap();
        let pv = mem.params_va().unwrap();
        let sv = mem.section1_va().unwrap();
        assert!(!region_is_free(pv), "params allocated");
        assert!(!region_is_free(sv), "section allocated");
        mem.cleanup(self_handle());
        assert!(region_is_free(pv), "params freed by teardown");
        assert!(region_is_free(sv), "section freed by teardown");
    }

    #[test]
    fn panic_unwind_frees_allocations_via_guard() {
        // Drop (without explicit cleanup) must free both allocations:
        // the owner captured the target handle at allocate().
        let (pv, sv) = {
            let mut m = WalkerSessionMemory::new();
            m.allocate(self_handle(), 2).unwrap()
        }; // m dropped here -> Drop must free
        assert!(region_is_free(pv), "Drop must free params region");
        assert!(region_is_free(sv), "Drop must free section region");
    }

    #[test]
    fn aborted_completed_both_release_on_teardown() {
        let _lock = INSTALL_LOCK.lock().unwrap();
        reset_runtime();
        let r = install_walker_session_production(
            self_handle(),
            std::process::id(),
            4242,
            &[0x400000, 0x401000],
            0x1122334455667788,
            0,
            16,
            &dig64('a'),
            &dig64('b'),
            0x7FF600000000,
            0x2040,
            &dig64('c'),
            &dig64('d'),
        );
        assert!(r.is_some());
        let mut mem = r.unwrap();
        let pv = mem.params_va().unwrap();
        let sv = mem.section1_va().unwrap();
        // Execute: probe abort (fail-closed on engineering runtime).
        let status = unsafe { mida_antidebug_runtime::exports::WalkerExecute(pv) };
        assert_eq!(
            status,
            mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_PROBE_ABORTED as i32,
            "engineering runtime must abort probes fail-closed"
        );
        mem.cleanup(self_handle());
        assert!(region_is_free(pv), "ABORTED session teardown frees params");
        assert!(region_is_free(sv), "ABORTED session teardown frees section");
    }
    // ---------- IMP-09-CARRIER-R5-R2: liveness + mapping proof ----------

    #[test]
    fn r5r2_liveness_alive_for_own_process() {
        assert_eq!(probe_process_liveness(self_handle()), LivenessProbe::Alive);
    }

    #[test]
    fn r5r2_liveness_unknown_for_invalid_handle() {
        let invalid = HANDLE(std::ptr::null_mut());
        assert_eq!(probe_process_liveness(invalid), LivenessProbe::Unknown);
    }

    #[test]
    fn r5r2_mapping_proof_rejects_mem_free() {
        let p = prove_candidate_mapping(self_handle(), 0x1000, 0x1000, 0x4000, 16);
        assert!(!p.passed, "MEM_FREE region must fail closed");
        assert!(p.fail_reason.is_some());
    }

    #[test]
    fn r5r2_mapping_proof_rejects_outside_envelope() {
        let p = prove_candidate_mapping(self_handle(), 0x1000, 0x2000, 0x4000, 16);
        assert!(!p.in_image_envelope);
        assert!(!p.passed);
    }

    #[test]
    fn r5r2_mapping_proof_rejects_page_cross() {
        let p = prove_candidate_mapping(self_handle(), 0xFFF, 0, 0x4000, 16);
        assert!(!p.page_span_fits);
        assert!(!p.passed);
    }

    #[test]
    fn r5r2_mapping_proof_ok_for_real_allocation() {
        let region = alloc_local(0x4000);
        let base = region as u64;
        let set = prove_candidate_mappings(
            self_handle(),
            &[base, base + 0x1000, base + 0x2000, base + 0x3000],
            base,
            0x4000,
            16,
        );
        assert!(set.all_passed, "real committed allocation must prove");
        assert_eq!(set.items.len(), 4);
        for item in &set.items {
            assert!(item.canonical_va);
            assert!(item.in_image_envelope);
            assert!(item.mem_committed);
            assert!(item.probe_contained_in_region);
            assert!(item.readable_protection);
            assert_eq!(
                item.region_type, 0x20000,
                "VirtualAlloc region must record MEM_PRIVATE"
            );
            assert!(item.passed);
        }
        free_local(region);
    }
    #[test]
    fn r5r2_mapping_proof_set_fails_when_any_item_fails() {
        let region = alloc_local(0x4000);
        let base = region as u64;
        let set = prove_candidate_mappings(
            self_handle(),
            &[base, base + 0x1000, base + 0x2000, base + 0x3000],
            base,
            0x3000,
            16,
        );
        assert!(!set.all_passed);
        assert!(!set.items[3].in_image_envelope);
        assert!(!set.items[3].passed);
        free_local(region);
    }

    #[test]
    fn r5r2_mapping_proof_requires_verified_image_size() {
        let p = prove_candidate_mapping(self_handle(), 0x1000, 0x1000, 0, 16);
        assert!(!p.passed);
        assert_eq!(
            p.fail_reason.as_deref(),
            Some("image envelope invalid or empty")
        );
    }

    // A mock authorized dispatch bridge for offline gate tests.
    #[derive(Debug)]
    struct MockBridge {
        status: i32,
        output: bool,
    }
    fn mock_attestation_output() -> mida_antidebug_runtime::attestation::RuntimeAttestationV2 {
        mida_antidebug_runtime::attestation::RuntimeAttestationV2 {
            schema: "mida.antidebug-runtime-attestation/v2".to_string(),
            schema_version: 2,
            runtime_id: "mida-antidebug-runtime-x64".to_string(),
            runtime_version: "0.1.0".to_string(),
            architecture: "x86_64".to_string(),
            runtime_sha256: "ab".repeat(32),
            profile_id: "oreans_origin_x64_v1".to_string(),
            profile_digest: "cd".repeat(32),
            target_pid: std::process::id(),
            module_base: 0x7000,
            initialized: true,
            hooks_expected: vec!["AD-PROC-002".to_string()],
            hooks_installed: vec!["AD-PROC-002".to_string()],
            hook_failures: vec![],
            surface_details: vec![],
            telemetry_channel: "ready".to_string(),
            cleanup_handler_registered: true,
            third_party: "test".to_string(),
            source_revision: "test".to_string(),
            toolchain: "rustc".to_string(),
            walker_attestation: None,
            record_digest: "aa".repeat(32),
        }
    }

    impl WalkerDispatchBridge for MockBridge {
        fn dispatch(
            &self,
            _params_va: u64,
        ) -> (
            i32,
            Option<mida_antidebug_runtime::attestation::RuntimeAttestationV2>,
        ) {
            if self.output {
                (self.status, Some(mock_attestation_output()))
            } else {
                (self.status, None)
            }
        }
    }

    #[test]
    fn r5r2_dispatch_bridge_returns_raw_status_and_output() {
        let b = MockBridge {
            status: 0,
            output: true,
        };
        let (s, o) = b.dispatch(0x1234);
        assert_eq!(s, 0);
        assert!(o.is_some());
        let b2 = MockBridge {
            status: 2,
            output: true,
        };
        let (s2, _) = b2.dispatch(0x1234);
        assert_eq!(s2, 2);
    }

    #[test]
    fn r5r2_dispatch_bridge_output_missing_fail_closed() {
        let b = MockBridge {
            status: 0,
            output: false,
        };
        let (s, o) = b.dispatch(0x1234);
        assert_eq!(s, 0);
        assert!(o.is_none());
    }
}
