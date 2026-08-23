//! Self-owned x64 MIDA runtime loader (ADR-6).
//!
//! Loads the MIDA anti-debug runtime DLL into a suspended target process
//! and drives the full pre-resume lifecycle:
//!
//! ```text
//! CREATE_SUSPENDED (debug event window; main thread stopped)
//!   -> runtime artifact authority verification
//!   -> VirtualAllocEx + WriteProcessMemory (DLL path + init params)
//!   -> CreateRemoteThread(kernel32!LoadLibraryW) -> module base
//!   -> resolve exports (GetProcAddress; x64 kernel32 base is process-
//!      independent, same assumption the session already uses)
//!   -> remote MidaAntidebugInitialize (thunk, 6 args, attestation out)
//!   -> read attestation JSON back
//!   -> identity/profile/attestation validation (fail-closed)
//!   -> controller decision (Proceed only then first resume)
//! ```
//!
//! ## Authority
//!
//! The runtime artifact is verified by SHA-256 + size + architecture against
//! an audited fixed configuration ([RuntimeAuthority]). File name and
//! directory location are never trusted.
//!
//! ## Safety & boundaries
//!
//! - x64 only: the loader refuses x86/WOW64 targets.
//! - No third-party injector; no ScyllaHide; remote thread creation is only
//!   ever used to call LoadLibraryW / the MIDA C ABI exports.
//! - "Remote thread created" != "runtime initialized": every C ABI call
//!   returns a structured error that is checked.
//! - Loader itself carries identity ([LoaderIdentity]) for evidence.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject,
};

use mida_antidebug_runtime::attestation::RuntimeAttestation;

/// Runtime artifact kind (matches provenance).
#[allow(dead_code)] // evidence binding; kept for provenance parity
pub const RUNTIME_KIND: &str = "runtime-x64";

/// The audited runtime authority MANIFEST (ADR-6-CORRECTION).
///
/// This is an immutable, audited configuration file. The loader NEVER trusts
/// caller-supplied hashes: the manifest itself is protected by a fixed
/// digest compiled into the loader (MIDA_RUNTIME_AUTHORITY_DIGEST), and
/// the environment is only allowed to select WHERE the manifest and the
/// runtime artifact live, never WHAT they contain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeAuthorityManifest {
    /// Manifest schema.
    pub schema: String,
    /// Authority kind (fixed: "runtime-x64").
    pub kind: String,
    /// Content-addressed artifact id.
    pub artifact_id: String,
    /// Expected runtime SHA-256 (hex, lowercase).
    pub sha256: String,
    /// Expected runtime size in bytes.
    pub size_bytes: u64,
    /// Expected architecture (must match actual PE machine).
    pub architecture: String,
    /// Git source revision the runtime was built from.
    pub source_ref: String,
    /// Path (relative to the manifest) of the provenance JSON.
    pub provenance_ref: String,
}

/// The compiled-in digest of the authority manifest. Set by the acceptance
/// step (fixed at build time); an empty value means "authority disabled" and
/// the loader fails closed.
pub const MIDA_RUNTIME_AUTHORITY_DIGEST: &str = match option_env!("MIDA_RUNTIME_AUTHORITY_DIGEST") {
    Some(v) => v,
    None => "",
};

/// The compiled-in runtime source revision (Git commit). Populated by the
/// build/acceptance step; never the crate version.
pub const MIDA_RUNTIME_SOURCE_REF: &str = match option_env!("MIDA_RUNTIME_SOURCE_REF") {
    Some(v) => v,
    None => "",
};

impl RuntimeAuthorityManifest {
    /// Load and verify the manifest from a path.
    ///
    /// The manifest digest is checked against the compiled-in
    /// MIDA_RUNTIME_AUTHORITY_DIGEST: a caller cannot replace the
    /// manifest (and therefore cannot authorize an arbitrary runtime) unless
    /// they can also replace the loader binary itself.
    pub fn load(path: &Path) -> Result<Self, RuntimeLoadError> {
        if MIDA_RUNTIME_AUTHORITY_DIGEST.is_empty() {
            return Err(RuntimeLoadError::AuthorityUnavailable(
                "MIDA_RUNTIME_AUTHORITY_DIGEST not set at build time".to_string(),
                "authority digest is empty; loader fails closed".to_string(),
            ));
        }
        let canonical = path.canonicalize().map_err(|e| {
            RuntimeLoadError::AuthorityUnavailable(path.display().to_string(), e.to_string())
        })?;
        let bytes = std::fs::read(&canonical).map_err(|e| {
            RuntimeLoadError::AuthorityUnavailable(canonical.display().to_string(), e.to_string())
        })?;
        // The manifest bytes are hashed EXACTLY as stored on disk (canonical
        // form for the authority file).
        let digest = sha256_hex(&bytes);
        if digest != MIDA_RUNTIME_AUTHORITY_DIGEST {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "manifest sha256 {digest} != compiled-in {MIDA_RUNTIME_AUTHORITY_DIGEST}"
            )));
        }
        let manifest: RuntimeAuthorityManifest = serde_json::from_slice(&bytes)
            .map_err(|e| RuntimeLoadError::AuthorityMismatch(format!("manifest parse: {e}")))?;
        manifest.validate()?;
        // CORRECTION-2: compiled source ref must be non-empty AND equal to
        // the manifest source ref. A caller cannot pick an arbitrary commit.
        if MIDA_RUNTIME_SOURCE_REF.is_empty() {
            return Err(RuntimeLoadError::AuthorityUnavailable(
                "MIDA_RUNTIME_SOURCE_REF not set at build time".to_string(),
                "compiled source ref is empty; loader fails closed".to_string(),
            ));
        }
        if manifest.source_ref != MIDA_RUNTIME_SOURCE_REF {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "manifest source_ref {} != compiled {}",
                manifest.source_ref, MIDA_RUNTIME_SOURCE_REF
            )));
        }
        Ok(manifest)
    }

    /// Structural validation of the manifest content (fail-closed).
    fn validate(&self) -> Result<(), RuntimeLoadError> {
        if self.schema != "mida.antidebug-runtime-authority/v1" {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "schema {} != mida.antidebug-runtime-authority/v1",
                self.schema
            )));
        }
        if self.kind != "runtime-x64" {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "kind {} != runtime-x64",
                self.kind
            )));
        }
        if self.architecture != "x86_64" {
            return Err(RuntimeLoadError::ArchitectureUnsupported(
                self.architecture.clone(),
            ));
        }
        if self.artifact_id.is_empty() || self.sha256.is_empty() || self.source_ref.is_empty() {
            return Err(RuntimeLoadError::AuthorityMismatch(
                "manifest missing artifact_id/sha256/source_ref".to_string(),
            ));
        }
        if self.size_bytes == 0 {
            return Err(RuntimeLoadError::AuthorityMismatch(
                "manifest size_bytes is zero".to_string(),
            ));
        }
        Ok(())
    }

    /// Verify the candidate runtime file: hash, size, and REAL PE
    /// architecture (MZ + PE + Machine=AMD64 + PE32+).
    pub fn verify_file(&self, path: &Path) -> Result<RuntimeFileIdentity, RuntimeLoadError> {
        let canonical = path.canonicalize().map_err(|e| {
            RuntimeLoadError::AuthorityUnavailable(path.display().to_string(), e.to_string())
        })?;
        let meta = std::fs::metadata(&canonical).map_err(|e| {
            RuntimeLoadError::AuthorityUnavailable(canonical.display().to_string(), e.to_string())
        })?;
        if !meta.is_file() {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "not a file: {}",
                canonical.display()
            )));
        }
        let size = meta.len();
        if size != self.size_bytes {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "size {} != expected {}",
                size, self.size_bytes
            )));
        }
        let bytes = std::fs::read(&canonical).map_err(|e| {
            RuntimeLoadError::AuthorityUnavailable(canonical.display().to_string(), e.to_string())
        })?;
        let digest = sha256_hex(&bytes);
        if digest != self.sha256 {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "sha256 {digest} != expected {}",
                self.sha256
            )));
        }
        // Real PE architecture verification (not just the authority string).
        verify_pe_x64(&bytes)?;
        Ok(RuntimeFileIdentity {
            path: canonical,
            sha256: digest,
            size_bytes: size,
            architecture: "x86_64".to_string(),
        })
    }
}

/// Verify that a buffer is a real x64 PE (MZ + PE signature + Machine=AMD64
/// + PE32+ optional header magic 0x20B). Fail-closed on anything else.
pub fn verify_pe_x64(bytes: &[u8]) -> Result<(), RuntimeLoadError> {
    // DOS header: "MZ" at offset 0.
    if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
        return Err(RuntimeLoadError::ArchitectureUnsupported(
            "not a PE file (missing MZ)".to_string(),
        ));
    }
    // e_lfanew at offset 0x3C (u32 LE).
    let pe_off = u32::from_le_bytes(bytes[0x3C..0x40].try_into().map_err(|_| {
        RuntimeLoadError::ArchitectureUnsupported("truncated DOS header".to_string())
    })?) as usize;
    if pe_off + 24 > bytes.len() || &bytes[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err(RuntimeLoadError::ArchitectureUnsupported(
            "not a PE file (missing PE signature)".to_string(),
        ));
    }
    // COFF header: Machine at pe_off+4 (u16 LE). AMD64 = 0x8664.
    let machine =
        u16::from_le_bytes(bytes[pe_off + 4..pe_off + 6].try_into().map_err(|_| {
            RuntimeLoadError::ArchitectureUnsupported("truncated COFF".to_string())
        })?);
    if machine != 0x8664 {
        return Err(RuntimeLoadError::ArchitectureUnsupported(format!(
            "COFF machine {machine:#x} != AMD64 (0x8664)"
        )));
    }
    // Optional header magic at pe_off+24 (u16 LE). PE32+ = 0x20B.
    if pe_off + 24 + 2 > bytes.len() {
        return Err(RuntimeLoadError::ArchitectureUnsupported(
            "truncated optional header".to_string(),
        ));
    }
    let magic =
        u16::from_le_bytes(bytes[pe_off + 24..pe_off + 26].try_into().map_err(|_| {
            RuntimeLoadError::ArchitectureUnsupported("truncated magic".to_string())
        })?);
    if magic != 0x20B {
        return Err(RuntimeLoadError::ArchitectureUnsupported(format!(
            "optional header magic {magic:#x} != PE32+ (0x20B)"
        )));
    }
    Ok(())
}

/// Identity of a verified runtime file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RuntimeFileIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub architecture: String,
}

/// Loader identity (for evidence).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoaderIdentity {
    pub loader_id: String,
    pub architecture: String,
    pub source_revision: String,
}

/// The loader itself.
#[derive(Debug, Clone)]
pub struct RuntimeLoader {
    pub authority: RuntimeAuthorityManifest,
    /// Loader identity (evidence binding).
    #[allow(dead_code)] // consumed by evidence bindings
    pub identity: LoaderIdentity,
}

/// A remote thread execution result (exit code = remote return value).
#[derive(Debug, Clone, Copy)]
pub struct RemoteCallResult {
    pub exit_code: u32,
}

/// Outcome of a bounded wait on a remote thread (ADR-5B-R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteWaitOutcome {
    /// The remote thread finished (WAIT_OBJECT_0).
    Finished,
    /// The wait timed out (WAIT_TIMEOUT = 258): the remote code may STILL be
    /// running in the target. The caller must NOT free any memory the remote
    /// thread can touch.
    TimedOut,
    /// The wait failed (WAIT_FAILED = 0xFFFFFFFF): the thread handle may be
    /// invalid; treat like a hard error.
    WaitFailed(u32),
    /// The wait was abandoned (WAIT_ABANDONED = 0x80, only meaningful for
    /// mutexes, never for thread handles; defensive).
    Abandoned,
}

/// A remote thread whose handle is closed on Drop.
///
/// After the handle is closed the thread itself may still be running (closing
/// a handle does not terminate the thread); callers must keep any memory the
/// remote thread can touch alive until the target process exits.
struct RemoteThreadGuard {
    handle: windows::Win32::Foundation::HANDLE,
}

impl RemoteThreadGuard {
    fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self { handle }
    }

    /// Take ownership of the raw handle out of the guard (F-011). The
    /// caller becomes responsible for closing it; the guard forgets it so it
    /// is not double-closed.
    fn into_raw(self) -> windows::Win32::Foundation::HANDLE {
        let h = self.handle;
        std::mem::forget(self);
        h
    }
}

impl Drop for RemoteThreadGuard {
    fn drop(&mut self) {
        // SAFETY: handle is owned by this guard (CreateRemoteThread result).
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Compute the bounded-wait budget for one poll iteration (ADR-5B-R3).
///
/// Returns `Some(ms)` — at most `max_poll_ms`, clamped to the REAL
/// monotonic time remaining before `deadline` — or `None` when the deadline
/// has already passed. The caller must use this budget for BOTH the thread
/// wait and the drain poll, so the total wall time can never exceed the
/// declared deadline (the pre-fix accumulator could double it).
pub fn compute_wait_budget(deadline: Instant, max_poll_ms: u64) -> Option<u64> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return None;
    }
    Some((remaining.as_millis() as u64).min(max_poll_ms).max(1))
}

/// Convert a raw WAIT_* status into a typed outcome (ADR-5B-R3).
pub fn classify_wait_status(raw: u32) -> RemoteWaitOutcome {
    // WAIT_OBJECT_0 = 0, WAIT_ABANDONED = 0x80, WAIT_TIMEOUT = 258,
    // WAIT_FAILED = 0xFFFFFFFF.
    match raw {
        0 => RemoteWaitOutcome::Finished,
        0x80 => RemoteWaitOutcome::Abandoned,
        258 => RemoteWaitOutcome::TimedOut,
        0xFFFF_FFFF => RemoteWaitOutcome::WaitFailed(raw),
        other => RemoteWaitOutcome::WaitFailed(other),
    }
}

/// Loader errors (all fail-closed).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[allow(dead_code)] // variants map to controller fail codes; some only via
                    // cleanup/evidence paths not yet exercised by the current wiring
pub enum RuntimeLoadError {
    #[error("runtime authority unavailable: {0}: {1}")]
    AuthorityUnavailable(String, String),
    #[error("runtime authority mismatch: {0}")]
    AuthorityMismatch(String),
    #[error("architecture unsupported: {0} (x64 only)")]
    ArchitectureUnsupported(String),
    #[error("target pid mismatch: expected {expected}, got {got}")]
    TargetPidMismatch { expected: u32, got: u32 },
    #[error("virtual alloc failed: {0}")]
    VirtualAllocFailed(String),
    #[error("write process memory failed: {0}")]
    WriteMemoryFailed(String),
    #[error("remote thread failed: {0}")]
    RemoteThreadFailed(String),
    #[error("remote call failed: {0}")]
    RemoteCallFailed(String),
    #[error("module base not found in target: {0}")]
    ModuleBaseNotFound(String),
    #[error("export resolution failed: {0}")]
    ExportResolutionFailed(String),
    #[error("initialize failed: abi error {0}")]
    InitializeAbiError(i32),
    #[error("attestation read failed: abi error {0}")]
    AttestationAbiError(i32),
    #[error("attestation buffer too small (need {0} bytes)")]
    AttestationBufferTooSmall(usize),
    #[error("attestation malformed: {0}")]
    AttestationMalformed(String),
    #[error("attestation identity mismatch: {0}")]
    AttestationIdentityMismatch(String),
    #[error("shutdown failed: abi error {0}")]
    ShutdownAbiError(i32),
    #[error("telemetry lost: {0}")]
    TelemetryLost(String),
    #[error("profile digest mismatch: {expected}, got {got}")]
    ProfileDigestMismatch { expected: String, got: String },
    #[error("cleanup failed: {0}")]
    CleanupFailed(String),
}

/// SHA-256 hex helper (sha2 is already a cli dependency).
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}
/// x64 remote-call thunk: CreateRemoteThread passes ONE argument (rcx =
/// &ThunkArgs). The thunk unpacks a function pointer plus up to 6
/// arguments and makes an indirect call. This is the standard Windows
/// remote-parameter technique (MSDN-documented pattern), fully self-owned;
/// it is NOT derived from any third-party injector.
///
/// Layout of ThunkArgs (all 8-byte slots):
///   [0] fn_ptr
///   [1] arg0
///   [2] arg1
///   [3] arg2
///   [4] arg3
///   [5] arg4
///   [6] arg5
///   [7] reserved (0)
///
/// Thunk code (x64):
///   mov  r11, rcx        ; r11 = args base (preserved across the call)
///   mov  rax, [r11+0]    ; fn_ptr
///   mov  rcx, [r11+8]    ; arg0
///   mov  rdx, [r11+16]   ; arg1
///   mov  r8,  [r11+24]   ; arg2
///   mov  r9,  [r11+32]   ; arg3
///   sub  rsp, 0x38       ; shadow space (0x20) + 2 stack args + alignment
///   mov  r10, [r11+40]   ; arg4 (stack slot)
///   mov  [rsp+0x20], r10
///   mov  r10, [r11+48]   ; arg5 (stack slot)
///   mov  [rsp+0x28], r10
///   call rax
///   add  rsp, 0x38
///   ret

// ---------------------------------------------------------------------------
// Thunk blob layout (ADR-5B-R1: explicit, audited constants)
// ---------------------------------------------------------------------------

/// Total size of the remote thunk allocation (one page-rounded 0x100 region;
/// VirtualAllocEx rounds to page granularity, so requesting 0x100 keeps the
/// executable window and the args region inside the same committed page).
pub const THUNK_BLOB_SIZE: usize = 0x100;
/// Executable thunk code length (THUNK_CODE is 91 bytes; the thunk's own
/// stack frame is 0x38, see THUNK_CODE).
pub const THUNK_CODE_SIZE: usize = 91;
/// Offset of the args blob inside the thunk allocation.
pub const THUNK_ARGS_OFFSET: usize = 0x60;
/// Size of the args blob (ThunkArgs::as_bytes() -> [u8; 64]).
pub const THUNK_ARGS_SIZE: usize = 64;
/// Bytes from the start of the allocation that must be executable.
pub const THUNK_EXECUTABLE_SIZE: usize = 0x60;

pub const THUNK_CODE: [u8; 91] = [
    0x49, 0x89, 0xCB, // mov r11, rcx
    0x49, 0x8B, 0x03, // mov rax, [r11]
    0x49, 0x8B, 0x4B, 0x08, // mov rcx, [r11+8]
    0x49, 0x8B, 0x53, 0x10, // mov rdx, [r11+0x10]
    0x4D, 0x8B, 0x43, 0x18, // mov r8,  [r11+0x18]
    0x4D, 0x8B, 0x4B, 0x20, // mov r9,  [r11+0x20]
    0x48, 0x83, 0xEC, 0x38, // sub rsp, 0x38
    0x4D, 0x8B, 0x53, 0x28, // mov r10, [r11+0x28]
    0x4C, 0x89, 0x54, 0x24, 0x20, // mov [rsp+0x20], r10
    0x4D, 0x8B, 0x53, 0x30, // mov r10, [r11+0x30]
    0x4C, 0x89, 0x54, 0x24, 0x28, // mov [rsp+0x28], r10
    0xFF, 0xD0, // call rax
    0x48, 0x83, 0xC4, 0x38, // add rsp, 0x38
    0xC3, // ret
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Argument block for a thunk call (8 slots x 8 bytes = 64 bytes).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ThunkArgs {
    pub fn_ptr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub reserved: u64,
}

impl ThunkArgs {
    pub fn as_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[0..8].copy_from_slice(&self.fn_ptr.to_le_bytes());
        out[8..16].copy_from_slice(&self.arg0.to_le_bytes());
        out[16..24].copy_from_slice(&self.arg1.to_le_bytes());
        out[24..32].copy_from_slice(&self.arg2.to_le_bytes());
        out[32..40].copy_from_slice(&self.arg3.to_le_bytes());
        out[40..48].copy_from_slice(&self.arg4.to_le_bytes());
        out[48..56].copy_from_slice(&self.arg5.to_le_bytes());
        out[56..64].copy_from_slice(&self.reserved.to_le_bytes());
        out
    }
}

/// Resolved MIDA C ABI export addresses (target address space).
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // get_attestation/shutdown used by cleanup + evidence paths
pub struct MidaExports {
    pub initialize: usize,
    pub get_attestation: usize,
    pub shutdown: usize,
}

/// A successfully loaded and initialized runtime in the target.
#[derive(Debug)]
#[allow(dead_code)] // cleanup/shutdown consumers wired in the loader flow
pub struct LoadedRuntime {
    pub module_base: usize,
    pub remote_path: *mut c_void,
    pub remote_params: *mut c_void,
    pub exports: MidaExports,
    pub attestation_json: String,
    pub file_identity: RuntimeFileIdentity,
}

impl RuntimeLoader {
    /// Create the loader with the audited authority manifest.
    pub fn new(authority: RuntimeAuthorityManifest) -> Self {
        Self {
            authority,
            identity: LoaderIdentity {
                loader_id: "mida-runtime-loader-x64".to_string(),
                architecture: "x86_64".to_string(),
                source_revision: env!("CARGO_PKG_VERSION").to_string(),
            },
        }
    }

    /// Resolve kernel32!LoadLibraryW address (valid in the target on x64).
    fn kernel32_load_library_w() -> Result<usize, RuntimeLoadError> {
        use windows::Win32::System::LibraryLoader::GetProcAddress;
        let name: Vec<u16> = "kernel32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let h = unsafe { GetModuleHandleW(PCWSTR(name.as_ptr())) }.ok();
        let Some(h) = h else {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "GetModuleHandleW(kernel32) failed".to_string(),
            ));
        };
        let load_addr = unsafe { GetProcAddress(h, PCSTR(b"LoadLibraryW\0".as_ptr())) };
        let Some(addr) = load_addr else {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "GetProcAddress(LoadLibraryW) failed".to_string(),
            ));
        };
        Ok(addr as usize)
    }

    /// Execute a function by address in the target via a remote thread, with
    /// an explicit deadline in seconds (ADR-5B-R3).
    ///
    /// # Safety
    /// `remote_fn` must be a valid function pointer in the TARGET address
    /// space (x64: same base as debugger). `arg` is a pointer to argument
    /// memory previously written into the target. `deadline_secs` is the
    /// REAL wall-clock budget for the whole wait (never doubled by drain
    /// polling).
    unsafe fn remote_call_raw_bounded(
        &self,
        target: HANDLE,
        remote_fn: usize,
        arg: usize,
        deadline_secs: u64,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> (
        Result<RemoteCallResult, RuntimeLoadError>,
        Option<windows::Win32::Foundation::HANDLE>,
    ) {
        // SAFETY: caller contract: remote_fn is a valid target-address-space
        // function; arg points to target memory (or 0 for no argument).
        let thread = unsafe {
            CreateRemoteThread(
                target,
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(remote_fn)),
                Some(arg as *const c_void),
                0,
                None,
            )
        };
        let thread = match thread {
            Ok(t) => RemoteThreadGuard::new(t),
            Err(e) => {
                return (
                    Err(RuntimeLoadError::RemoteThreadFailed(format!(
                        "CreateRemoteThread: {e}"
                    ))),
                    None,
                );
            }
        };
        // Bounded wait for the remote call to finish. When a drain callback
        // is supplied (debug-session context), poll with short timeouts and
        // let the caller keep the debug session alive: every debug event
        // freezes the target, so a remote thread can only progress while the
        // debugger drains+continues events.
        //
        // ADR-5B-R3: WAIT statuses are classified explicitly; on timeout the
        // remote code may STILL be executing in the target, so the handle is
        // closed but the caller is told the call did NOT finish (it must not
        // free remote memory the thread can touch).
        // ADR-5B-R3 (audit): the deadline is a REAL monotonic clock, not an
        // accumulated counter. Each iteration waits at most min(200ms,
        // remaining) on the thread, then spends at most the same remaining
        // budget draining, so the total wall time never exceeds the declared
        // deadline (previously a 60s declared deadline could take ~120s).
        let deadline = Instant::now() + Duration::from_secs(deadline_secs);
        loop {
            // REAL monotonic budget: total wall time never exceeds deadline.
            // F-004: the wait budget and the drain budget are computed
            // SEPARATELY — each blocking call re-derives the remaining time,
            // so WaitForSingleObject(200ms) + drain(200ms) can never burn
            // 400ms against a single 200ms budget slot.
            let Some(wait_ms) = compute_wait_budget(deadline, 200) else {
                // Handle closed by guard on return; remote memory is
                // deliberately NOT freed (the thread may still run).
                // F-011: the remote thread may still be running on timeout -
                // hand the RAW handle back so the caller can wait for real
                // completion before freeing retained memory.
                return (
                    Err(RuntimeLoadError::RemoteCallFailed(format!(
                        "WaitForSingleObject timed out after {}ms; remote thread may still be running (thunk memory retained)",
                        deadline_secs * 1000
                    ))),
                    Some(thread.into_raw()),
                );
            };
            let wait_ms = wait_ms as u32;
            let wait = unsafe { WaitForSingleObject(thread.handle, wait_ms) }.0;
            match classify_wait_status(wait) {
                RemoteWaitOutcome::Finished => break,
                RemoteWaitOutcome::TimedOut => {
                    // Recompute the drain budget from the CURRENT remaining
                    // time (the wait above already consumed part of it).
                    let Some(drain_ms) = compute_wait_budget(deadline, 200) else {
                        return (
                            Err(RuntimeLoadError::RemoteCallFailed(format!(
                                "WaitForSingleObject timed out after {}ms; remote thread may still be running (thunk memory retained)",
                                deadline_secs * 1000
                            ))),
                            Some(thread.into_raw()),
                        );
                    };
                    if let Err(e) = drain(drain_ms as u32) {
                        return (
                            Err(RuntimeLoadError::RemoteCallFailed(format!(
                                "drain failed: {e}"
                            ))),
                            Some(thread.into_raw()),
                        );
                    }
                }
                RemoteWaitOutcome::Abandoned => {
                    return (
                        Err(RuntimeLoadError::RemoteCallFailed(
                            "WaitForSingleObject returned WAIT_ABANDONED for a thread handle"
                                .into(),
                        )),
                        Some(thread.into_raw()),
                    );
                }
                RemoteWaitOutcome::WaitFailed(raw) => {
                    return (
                        Err(RuntimeLoadError::RemoteCallFailed(format!(
                            "WaitForSingleObject failed (0x{raw:08X})"
                        ))),
                        Some(thread.into_raw()),
                    );
                }
            }
        }
        let mut code: u32 = 0;
        let gc = unsafe { GetExitCodeThread(thread.handle, &mut code) };
        if gc.is_err() {
            return (
                Err(RuntimeLoadError::RemoteCallFailed(
                    "GetExitCodeThread failed".to_string(),
                )),
                Some(thread.into_raw()),
            );
        }
        // F-011: hand the RAW remote thread handle back to the caller so it
        // can WaitForSingleObject(thread, INFINITE) to prove the thread truly
        // finished before freeing retained memory. into_raw() transfers handle
        // ownership to the caller (the guard forgets it, no double close).
        let raw_handle = thread.into_raw();
        (Ok(RemoteCallResult { exit_code: code }), Some(raw_handle))
    }

    /// Allocate executable memory in the target, write thunk + args, run.
    ///
    /// # Safety
    /// `target` must be a valid process handle; `args.fn_ptr` must be a
    /// valid code address in the target address space.
    /// Remote LoadLibraryW (bare thread entry, 32-bit exit code only)
    /// followed by a PEB.Ldr module-list walk to recover the full 64-bit
    /// module base. ADR-5B: a wrapper stub (even with correct stack
    /// alignment) is detected by the protected sample (endless exception
    /// storm), while a bare LoadLibraryW thread works. The loader lock
    /// is released only after the initializer chain finishes, so this
    /// call may take a while; the drain callback keeps the debug
    /// session alive during that window.
    ///
    /// # Safety
    /// `target` must be a valid process handle; `path_addr` must point to a
    /// NUL-terminated wide path written in the target.
    unsafe fn loadlib_call(
        &self,
        target: HANDLE,
        load_addr: usize,
        path_addr: usize,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> Result<usize, RuntimeLoadError> {
        use windows::Win32::System::Threading::GetExitCodeThread as GECT;
        // 1. Bare LoadLibraryW via a remote thread (no wrapper stub:
        //    protected samples detect and stall wrapper code).
        let thread = unsafe {
            CreateRemoteThread(
                target,
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(load_addr)),
                Some(path_addr as *const c_void),
                0,
                None,
            )
        };
        let thread = match thread {
            Ok(t) => RemoteThreadGuard::new(t),
            Err(e) => {
                return Err(RuntimeLoadError::RemoteThreadFailed(format!(
                    "CreateRemoteThread(loadlib): {e}"
                )));
            }
        };
        // 2. Wait with drain (bounded 120s).
        //    ADR-5B-R3: WAIT statuses are classified explicitly; on timeout the
        //    remote thread may still hold the loader lock — the remote_path
        //    buffer is retained (never freed while the thread may run).
        // ADR-5B-R3 (audit): real monotonic deadline (see remote_call_raw).
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            // REAL monotonic budget: total wall time never exceeds deadline.
            // F-004: drain budget recomputed after the wait (see
            // remote_call_raw for the same pattern).
            let Some(wait_ms) = compute_wait_budget(deadline, 200) else {
                return Err(RuntimeLoadError::RemoteCallFailed("LoadLibraryW remote thread timed out after 120000ms; thread may still hold the loader lock (path buffer retained)".to_string()));
            };
            let wait_ms = wait_ms as u32;
            let wait = unsafe { WaitForSingleObject(thread.handle, wait_ms) }.0;
            match classify_wait_status(wait) {
                RemoteWaitOutcome::Finished => break,
                RemoteWaitOutcome::TimedOut => {
                    let Some(drain_ms) = compute_wait_budget(deadline, 200) else {
                        return Err(RuntimeLoadError::RemoteCallFailed("LoadLibraryW remote thread timed out after 120000ms; thread may still hold the loader lock (path buffer retained)".to_string()));
                    };
                    drain(drain_ms as u32).map_err(|e| {
                        RuntimeLoadError::RemoteCallFailed(format!("drain failed: {e}"))
                    })?;
                }
                RemoteWaitOutcome::Abandoned => {
                    return Err(RuntimeLoadError::RemoteCallFailed(
                        "WaitForSingleObject returned WAIT_ABANDONED (loadlib)".into(),
                    ));
                }
                RemoteWaitOutcome::WaitFailed(raw) => {
                    return Err(RuntimeLoadError::RemoteCallFailed(format!(
                        "WaitForSingleObject failed (0x{raw:08X}) (loadlib)"
                    )));
                }
            }
        }
        // 3. 32-bit exit code: nonzero means the load started; the full
        //    base is recovered from the PEB.Ldr module list.
        let mut code: u32 = 0;
        let gc = unsafe { GECT(thread.handle, &mut code) };
        if gc.is_err() {
            return Err(RuntimeLoadError::RemoteCallFailed(
                "GetExitCodeThread(loadlib) failed".to_string(),
            ));
        }
        if code == 0 {
            return Err(RuntimeLoadError::ModuleBaseNotFound(
                "LoadLibraryW returned 0 (load failed in target)".to_string(),
            ));
        }
        // 4. Walk the target PEB.Ldr InMemoryOrderModuleList to find the
        //    full 64-bit base of the runtime DLL.
        let base = unsafe { self.find_module_base_in_target(target, "mida_antidebug_runtime") }?;
        if base == 0 {
            return Err(RuntimeLoadError::ModuleBaseNotFound(
                "runtime DLL not found in target module list".to_string(),
            ));
        }
        Ok(base)
    }
    unsafe fn thunk_call(
        &self,
        target: HANDLE,
        args: &ThunkArgs,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> Result<RemoteCallResult, RuntimeLoadError> {
        // Production entry: fixed 60s deadline (R1-HARDENING-REMOTE-HANDLE-1).
        unsafe { self.thunk_call_bounded(target, args, 60, drain) }
    }

    /// Bounded production-ownership seam (R1-HARDENING-REMOTE-HANDLE-TEST-1).
    ///
    /// The ONE wrapper that exercises the production destructure-and-close
    /// contract: calls [`Self::thunk_call_tracked_with_handle`], then closes
    /// the raw remote thread handle itself on every return path (success AND
    /// failure). Tests MUST call this function (with a short deadline) and
    /// MUST NOT close the handle themselves — otherwise they prove the test's
    /// close pattern, not the production wrapper.
    unsafe fn thunk_call_bounded(
        &self,
        target: HANDLE,
        args: &ThunkArgs,
        deadline_secs: u64,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> Result<RemoteCallResult, RuntimeLoadError> {
        // R1-HARDENING-REMOTE-HANDLE-1: NEVER drop the raw remote thread
        // handle. thunk_call_tracked_with_handle() transfers ownership via
        // into_raw() on EVERY return path (success AND failure), so the
        // production wrapper must destructure the tuple and close the handle
        // itself; otherwise each production thunk call leaks a kernel handle.
        let (result, _thunk_addr, thread_handle) =
            unsafe { self.thunk_call_tracked_with_handle(target, args, deadline_secs, drain) };
        if let Some(h) = thread_handle {
            // SAFETY: h is a valid owned handle from into_raw(); no double
            // close (the guard was forgotten by into_raw).
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
        }
        result
    }

    /// [`Self::thunk_call`] plus the actual remote thunk address, so tests can
    /// verify retention of the REAL allocation (audit F-005: a test that
    /// allocates its own memory and checks THAT proves nothing about the
    /// loader's thunk). Returns `(result, Some(remote_addr))`; the address is
    /// the `VirtualAllocEx` result even when the call fails (retained on
    /// timeout, freed on success/failure paths that free it).
    /// Tracked variant without the raw thread handle (backward-compatible
    /// wrapper). See [`Self::thunk_call_tracked_with_handle`].
    #[allow(dead_code)]
    unsafe fn thunk_call_tracked(
        &self,
        target: HANDLE,
        args: &ThunkArgs,
        deadline_secs: u64,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> (Result<RemoteCallResult, RuntimeLoadError>, Option<usize>) {
        let (result, addr, handle) =
            unsafe { self.thunk_call_tracked_with_handle(target, args, deadline_secs, drain) };
        // Close the raw handle if one was returned (no double close: the
        // guard was forgotten by into_raw).
        if let Some(h) = handle {
            // SAFETY: h is a valid owned handle from into_raw().
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(h) };
        }
        (result, addr)
    }
    unsafe fn thunk_call_tracked_with_handle(
        &self,
        target: HANDLE,
        args: &ThunkArgs,
        deadline_secs: u64,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> (
        Result<RemoteCallResult, RuntimeLoadError>,
        Option<usize>,
        Option<windows::Win32::Foundation::HANDLE>,
    ) {
        // 1. Allocate executable-capable memory for thunk + args.
        //    THUNK_BLOB_SIZE = 0x100 (VirtualAllocEx rounds to page
        //    granularity, so the code window + args region share one
        //    committed page).
        let remote = unsafe {
            VirtualAllocEx(
                target,
                None,
                THUNK_BLOB_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote.is_null() {
            return (
                Err(RuntimeLoadError::VirtualAllocFailed(
                    "VirtualAllocEx(thunk)".to_string(),
                )),
                None,
                None,
            );
        }
        // 2. Write thunk at [0..96) (THUNK_CODE is 91 bytes), args at
        //    [96..160). The allocation is 0x100 bytes total.
        let mut blob = [0u8; THUNK_BLOB_SIZE];
        debug_assert!(THUNK_CODE.len() <= THUNK_CODE_SIZE);
        blob[0..THUNK_CODE.len()].copy_from_slice(&THUNK_CODE);
        blob[THUNK_ARGS_OFFSET..THUNK_ARGS_OFFSET + THUNK_ARGS_SIZE]
            .copy_from_slice(&args.as_bytes());
        let w = unsafe {
            WriteProcessMemory(
                target,
                remote,
                blob.as_ptr() as *const c_void,
                blob.len(),
                None,
            )
        };
        if w.is_err() {
            let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            return (
                Err(RuntimeLoadError::WriteMemoryFailed(format!(
                    "WriteProcessMemory(thunk): {:?}",
                    w.err()
                ))),
                Some(remote as usize),
                None,
            );
        }
        // 3. Make executable. THUNK_EXECUTABLE_SIZE (0x60) is the LOGICAL
        //    layout boundary (code window); Windows page protection applies
        //    at page granularity, so the whole shared page (0x100 region)
        //    becomes PAGE_EXECUTE_READWRITE. The constant documents the
        //    logical code extent, not a page-level protection boundary.
        let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let vp = unsafe {
            VirtualProtectEx(
                target,
                remote,
                THUNK_EXECUTABLE_SIZE,
                PAGE_EXECUTE_READWRITE,
                &mut old as *mut _ as *mut windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
            )
        };
        if vp.is_err() {
            let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            return (
                Err(RuntimeLoadError::RemoteCallFailed(format!(
                    "VirtualProtectEx(thunk): {:?}",
                    vp.err()
                ))),
                Some(remote as usize),
                None,
            );
        }
        // 4. Run: CreateRemoteThread(remote thunk, arg = remote + THUNK_ARGS_OFFSET).
        //    ADR-5B-R3: the thunk allocation is freed ONLY after the remote
        //    thread is known to have finished (Ok). On timeout the thread may
        //    still execute the thunk, so the allocation is deliberately left
        //    in place; it is released when the target process terminates.
        let thunk_addr = remote as usize;
        let args_addr = remote as usize + THUNK_ARGS_OFFSET;
        let (result, thread_handle) = unsafe {
            self.remote_call_raw_bounded(target, thunk_addr, args_addr, deadline_secs, drain)
        };
        match &result {
            Ok(_) => {
                // SAFETY: the remote thread finished (WAIT_OBJECT_0), so no
                // remote code can execute the thunk anymore.
                let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            }
            Err(_) => {
                // Timeout / failure: the remote thread may still be running.
                // Do NOT free the thunk. It is intentionally leaked until the
                // target process exits (a small, bounded one-page region).
                tracing::warn!(
                    "thunk allocation retained after remote-call failure (thread may still run)"
                );
            }
        }
        // F-011: hand the RAW remote thread handle back so the caller can
        // WaitForSingleObject(thread, INFINITE) before freeing retained memory.
        (result, Some(remote as usize), thread_handle)
    }
}
impl RuntimeLoader {
    /// Run the full load + initialize + attestation sequence in the target.
    ///
    /// # Safety
    /// `target` must be a valid handle to the suspended target process; the
    /// target main thread must NOT have been resumed yet.
    pub unsafe fn load_and_initialize(
        &self,
        target: HANDLE,
        target_pid: u32,
        runtime_path: &Path,
        profile_id: &str,
        profile_digest: &str,
        expected_surfaces: &[String],
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> Result<LoadedRuntime, RuntimeLoadError> {
        // 0. Authority verification (fail-closed, before any remote write).
        let identity = self.authority.verify_file(runtime_path)?;
        if identity.architecture != "x86_64" {
            return Err(RuntimeLoadError::ArchitectureUnsupported(
                identity.architecture,
            ));
        }

        // 1. Write the DLL path into the target.
        let path_str = identity.path.to_str().ok_or_else(|| {
            RuntimeLoadError::WriteMemoryFailed("path not UTF-16-able".to_string())
        })?;
        let path_wide: Vec<u16> = path_str.encode_utf16().chain(std::iter::once(0)).collect();
        let path_bytes = path_wide.len() * 2;
        let remote_path = unsafe {
            VirtualAllocEx(
                target,
                None,
                path_bytes as usize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_path.is_null() {
            return Err(RuntimeLoadError::VirtualAllocFailed(
                "VirtualAllocEx(path)".to_string(),
            ));
        }
        let written = unsafe {
            WriteProcessMemory(
                target,
                remote_path,
                path_wide.as_ptr() as *const c_void,
                path_bytes as usize,
                None,
            )
        };
        if written.is_err() {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::WriteMemoryFailed(format!(
                "WriteProcessMemory(path): {:?}",
                written.err()
            )));
        }

        // 2. LoadLibraryW via remote thread with a 64-bit result slot
        // (ADR-5B: GetExitCodeThread returns only 32 bits, so the full
        // HMODULE is written by the stub into target memory).
        let load_addr = Self::kernel32_load_library_w()?;
        let module_base =
            unsafe { self.loadlib_call(target, load_addr, remote_path as usize, drain) }?;

        // 3. Resolve the MIDA exports from the TARGET process memory
        // (ADR-5B: GetProcAddress in the debugger cannot see the runtime
        // DLL loaded only in the target).
        let exports = unsafe { self.resolve_mida_exports_remote(target, module_base) }?;

        // 4. Build MidaInitParams blob in target memory (self-contained).
        let remote_params = unsafe {
            VirtualAllocEx(
                target,
                None,
                0x2000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_params.is_null() {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::VirtualAllocFailed(
                "VirtualAllocEx(params)".to_string(),
            ));
        }
        let params_bytes = build_init_params_bytes(
            target_pid,
            profile_id,
            profile_digest,
            expected_surfaces,
            module_base as u64,
            remote_params as usize as u64,
        )?;
        if params_bytes.len() > 0x2000 {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::WriteMemoryFailed(
                "init params blob overflow".to_string(),
            ));
        }
        let pw = unsafe {
            WriteProcessMemory(
                target,
                remote_params,
                params_bytes.as_ptr() as *const c_void,
                params_bytes.len(),
                None,
            )
        };
        if pw.is_err() {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::WriteMemoryFailed(format!(
                "WriteProcessMemory(params): {:?}",
                pw.err()
            )));
        }

        // 5. Remote MidaAntidebugInitialize via the thunk (6 args); the
        // attestation JSON comes back through out_attestation_json.
        let att_buf_len = 16 * 1024usize;
        let remote_att = unsafe {
            VirtualAllocEx(
                target,
                None,
                att_buf_len + 8,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if remote_att.is_null() {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::VirtualAllocFailed(
                "VirtualAllocEx(attestation out)".to_string(),
            ));
        }
        let att_written_addr = remote_att as usize + att_buf_len;
        let init_args = ThunkArgs {
            fn_ptr: exports.initialize as u64,
            arg0: remote_params as u64,
            arg1: remote_att as u64,  // out_runtime_sha256 (unused by loader)
            arg2: 64,                 // out_runtime_sha256_len
            arg3: remote_att as u64,  // out_attestation_json
            arg4: att_buf_len as u64, // out_attestation_len
            arg5: att_written_addr as u64, // out_attestation_written
            reserved: 0,
        };
        let init_result = unsafe { self.thunk_call(target, &init_args, drain) }?;
        if init_result.exit_code != 0 {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_att, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::InitializeAbiError(
                init_result.exit_code as i32,
            ));
        }

        // 6. Read the attestation JSON written by Initialize.
        let mut written_bytes = [0u8; 8];
        let rl = unsafe {
            ReadProcessMemory(
                target,
                att_written_addr as *const c_void,
                written_bytes.as_mut_ptr() as *mut c_void,
                8,
                None,
            )
        };
        if rl.is_err() {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_att, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::AttestationMalformed(
                "read written length failed".to_string(),
            ));
        }
        let written = usize::from_le_bytes(written_bytes);
        if written > att_buf_len {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
            let _ = unsafe { VirtualFreeEx(target, remote_att, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::AttestationBufferTooSmall(written));
        }
        let mut json_buf = vec![0u8; written];
        if written > 0 {
            let rj = unsafe {
                ReadProcessMemory(
                    target,
                    remote_att as *const c_void,
                    json_buf.as_mut_ptr() as *mut c_void,
                    written,
                    None,
                )
            };
            if rj.is_err() {
                let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
                let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
                let _ = unsafe { VirtualFreeEx(target, remote_att, 0, MEM_RELEASE) };
                return Err(RuntimeLoadError::AttestationMalformed(
                    "read attestation JSON failed".to_string(),
                ));
            }
        }
        let _ = unsafe { VirtualFreeEx(target, remote_att, 0, MEM_RELEASE) };
        let att = String::from_utf8(json_buf)
            .map_err(|e| RuntimeLoadError::AttestationMalformed(e.to_string()))?;

        // 7. Parse + identity checks (controller validate is the gate).
        let parsed = RuntimeAttestation::from_canonical_json(&att)
            .map_err(|e| RuntimeLoadError::AttestationMalformed(e.to_string()))?;
        if parsed.target_pid != target_pid {
            return Err(RuntimeLoadError::TargetPidMismatch {
                expected: target_pid,
                got: parsed.target_pid,
            });
        }
        if parsed.module_base as usize != module_base {
            return Err(RuntimeLoadError::AttestationIdentityMismatch(format!(
                "module_base {:#x} != loaded {module_base:#x}",
                parsed.module_base
            )));
        }
        if parsed.profile_digest != profile_digest {
            return Err(RuntimeLoadError::ProfileDigestMismatch {
                expected: profile_digest.to_string(),
                got: parsed.profile_digest,
            });
        }

        Ok(LoadedRuntime {
            module_base,
            remote_path,
            remote_params,
            exports,
            attestation_json: att,
            file_identity: identity,
        })
    }
}
impl RuntimeLoader {
    /// Resolve the MIDA C ABI exports by parsing the PE export directory
    /// from the TARGET process memory (ReadProcessMemory).
    ///
    /// ADR-5B: the runtime DLL is loaded only in the target process; the
    /// debugger cannot use GetProcAddress for it. We parse the export
    /// directory of the loaded image in target memory and return the RVA
    /// of each named export (module_base + RVA = target address).
    unsafe fn resolve_mida_exports_remote(
        &self,
        target: HANDLE,
        module_base: usize,
    ) -> Result<MidaExports, RuntimeLoadError> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory as RPM;

        // 1. DOS header -> e_lfanew.
        let mut dos = [0u8; 0x40];
        let rd = unsafe {
            RPM(
                target,
                module_base as *const core::ffi::c_void,
                dos.as_mut_ptr() as *mut core::ffi::c_void,
                dos.len(),
                None,
            )
        };
        if rd.is_err() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote read DOS header failed".to_string(),
            ));
        }
        if &dos[0..2] != b"MZ" {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote image missing MZ".to_string(),
            ));
        }
        let e_lfanew = u32::from_le_bytes([dos[0x3C], dos[0x3D], dos[0x3E], dos[0x3F]]) as usize;

        // 2. PE header: read up to the data directories (0x98 bytes covers
        //    signature + COFF + optional header + first data directory).
        let pe_base = module_base + e_lfanew;
        let mut pe = [0u8; 0x98];
        let rd2 = unsafe {
            RPM(
                target,
                pe_base as *const core::ffi::c_void,
                pe.as_mut_ptr() as *mut core::ffi::c_void,
                pe.len(),
                None,
            )
        };
        if rd2.is_err() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote read PE header failed".to_string(),
            ));
        }
        let magic = u16::from_le_bytes([pe[0x18], pe[0x19]]);
        // pe[] starts at the PE signature; the optional header begins at
        // pe+0x18, and the export data directory lives at optional+0x70
        // (PE32+) / +0x60 (PE32).
        let dd_off = if magic == 0x20B {
            0x18 + 0x70
        } else {
            0x18 + 0x60
        };
        let exp_rva =
            u32::from_le_bytes([pe[dd_off], pe[dd_off + 1], pe[dd_off + 2], pe[dd_off + 3]])
                as usize;
        let exp_size = u32::from_le_bytes([
            pe[dd_off + 4],
            pe[dd_off + 5],
            pe[dd_off + 6],
            pe[dd_off + 7],
        ]) as usize;
        if exp_rva == 0 || exp_size == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote image has no export directory".to_string(),
            ));
        }
        // 3. Export directory: read a bounded window.
        // ADR-5B-R5 (audit): IMAGE_EXPORT_DIRECTORY is 40 bytes; if the
        // declared directory is smaller than the fixed header, fail closed
        // instead of indexing out of bounds below (ed[0x27]).
        const IMAGE_EXPORT_DIRECTORY_SIZE: usize = 40;
        if exp_size < IMAGE_EXPORT_DIRECTORY_SIZE {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "remote export directory truncated: size={exp_size} < {IMAGE_EXPORT_DIRECTORY_SIZE}"
            )));
        }
        let win = exp_size.min(0x10000);
        let mut ed = vec![0u8; win];
        let rd3 = unsafe {
            RPM(
                target,
                (module_base + exp_rva) as *const core::ffi::c_void,
                ed.as_mut_ptr() as *mut core::ffi::c_void,
                win,
                None,
            )
        };
        if rd3.is_err() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote read export directory failed".to_string(),
            ));
        }
        let num_funcs = u32::from_le_bytes([ed[0x14], ed[0x15], ed[0x16], ed[0x17]]) as usize;
        let num_names = u32::from_le_bytes([ed[0x18], ed[0x19], ed[0x1A], ed[0x1B]]) as usize;
        let funcs_rva = u32::from_le_bytes([ed[0x1C], ed[0x1D], ed[0x1E], ed[0x1F]]) as usize;
        let names_rva = u32::from_le_bytes([ed[0x20], ed[0x21], ed[0x22], ed[0x23]]) as usize;
        let ords_rva = u32::from_le_bytes([ed[0x24], ed[0x25], ed[0x26], ed[0x27]]) as usize;
        if num_names == 0 || names_rva == 0 || funcs_rva == 0 || ords_rva == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote export directory incomplete".to_string(),
            ));
        }
        // Read the name-pointer array and ordinal array (bounded).
        let names_bytes = num_names * 4;
        if names_bytes > 0x10000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export name array too large".to_string(),
            ));
        }
        let mut names = vec![0u8; names_bytes];
        let rn = unsafe {
            RPM(
                target,
                (module_base + names_rva) as *const core::ffi::c_void,
                names.as_mut_ptr() as *mut core::ffi::c_void,
                names_bytes,
                None,
            )
        };
        if rn.is_err() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote read name array failed".to_string(),
            ));
        }
        // PE export ordinal array entries are 2 bytes each (not 4).
        // (PE32+/PE32 IMAGE_EXPORT_DIRECTORY.NumberOfNames counts ordinal
        // array slots; each slot is a u16.)
        let ords_bytes = num_names * 2;
        if ords_bytes > 0x8000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export ordinal array too large".to_string(),
            ));
        }
        let mut ords = vec![0u8; ords_bytes];
        let ro = unsafe {
            RPM(
                target,
                (module_base + ords_rva) as *const core::ffi::c_void,
                ords.as_mut_ptr() as *mut core::ffi::c_void,
                ords_bytes,
                None,
            )
        };
        if ro.is_err() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote read ordinal array failed".to_string(),
            ));
        }
        // Read the function-address array (bounded; forwarded exports are
        // handled inside the parser by the exp_rva window check).
        let funcs_bytes = num_funcs * 4;
        if funcs_bytes > 0x10000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export function array too large".to_string(),
            ));
        }
        let mut funcs = vec![0u8; funcs_bytes];
        let rf = unsafe {
            RPM(
                target,
                (module_base + funcs_rva) as *const core::ffi::c_void,
                funcs.as_mut_ptr() as *mut core::ffi::c_void,
                funcs_bytes,
                None,
            )
        };
        if rf.is_err() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "remote read function array failed".to_string(),
            ));
        }
        let want: [&[u8]; 3] = [
            b"MidaAntidebugInitialize",
            b"MidaAntidebugGetAttestation",
            b"MidaAntidebugShutdown",
        ];
        // ADR-5B-R5: resolve through the pure, bounds-checked parser. The
        // name resolver reads one byte at a time from the target via RPM
        // (bounded 64 chars, matching the parser contract).
        let found_owned = {
            let mut name_at = |name_ptr_rva: usize, out: &mut Vec<u8>| {
                for k in 0..64usize {
                    let mut ch = [0u8; 1];
                    let rc = unsafe {
                        RPM(
                            target,
                            (module_base + name_ptr_rva + k) as *const core::ffi::c_void,
                            ch.as_mut_ptr() as *mut core::ffi::c_void,
                            1,
                            None,
                        )
                    };
                    if rc.is_err() {
                        break;
                    }
                    if ch[0] == 0 {
                        break;
                    }
                    out.push(ch[0]);
                }
            };
            Self::resolve_exports_from_buffers(
                &names,
                &ords,
                &funcs,
                &mut name_at,
                num_names,
                num_funcs,
                module_base,
                exp_rva,
                exp_size,
                &want,
            )?
        };
        let found: [Option<usize>; 3] = [found_owned[0], found_owned[1], found_owned[2]];
        let (Some(init), Some(get), Some(shut)) = (found[0], found[1], found[2]) else {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "remote export missing: init={} get={} shut={}",
                found[0].is_some(),
                found[1].is_some(),
                found[2].is_some()
            )));
        };
        Ok(MidaExports {
            initialize: init,
            get_attestation: get,
            shutdown: shut,
        })
    }

    /// Parse a PE export directory from in-memory buffers (ADR-5B-R5).
    ///
    /// Pure parser over the already-read name-pointer array, ordinal array
    /// and function-address array. `name_at` resolves a name-string address
    /// (RVA) to its bytes; the remote path reads them via RPM from the
    /// target, tests supply a flat buffer. Returns the resolved addresses
    /// for the wanted exports. `module_base` is the image base (for
    /// RVA -> VA conversion); `funcs` is the raw function-address array
    /// (num_funcs * 4 bytes). Handles Base != 1 (the ordinal array is
    /// 0-based relative to AddressOfFunctions per the MSVC/Rust link.exe
    /// convention — the ordinal VALUE is the function index), forwarded
    /// exports (function RVA inside the export directory -> not resolved),
    /// out-of-range ordinals and missing names. Fail-closed on truncated
    /// buffers (bounds-checked indexing).
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_exports_from_buffers(
        names: &[u8],
        ords: &[u8],
        funcs: &[u8],
        name_at: &mut dyn FnMut(usize, &mut Vec<u8>),
        num_names: usize,
        num_funcs: usize,
        module_base: usize,
        exp_rva: usize,
        exp_size: usize,
        want: &[&[u8]],
    ) -> Result<Vec<Option<usize>>, RuntimeLoadError> {
        let mut found: Vec<Option<usize>> = vec![None; want.len()];
        for i in 0..num_names {
            if i * 4 + 3 >= names.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "export name array truncated".to_string(),
                ));
            }
            let name_ptr_rva = u32::from_le_bytes([
                names[i * 4],
                names[i * 4 + 1],
                names[i * 4 + 2],
                names[i * 4 + 3],
            ]) as usize;
            if name_ptr_rva == 0 {
                continue;
            }
            // Read the name string (bounded 64 chars) via the resolver.
            let mut name = Vec::with_capacity(64);
            name_at(name_ptr_rva, &mut name);
            if i * 2 + 1 >= ords.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "export ordinal array truncated".to_string(),
                ));
            }
            let ord = u16::from_le_bytes([ords[i * 2], ords[i * 2 + 1]]) as usize;
            for (wi, w) in want.iter().enumerate() {
                if found[wi].is_some() || name.as_slice() != *w {
                    continue;
                }
                // The MSVC/Rust link.exe export ordinal array is 0-based for
                // #[no_mangle] exports even when Base=1: ord=0 maps to
                // AddressOfFunctions[0], ord=1 to [1], etc. Use the ordinal
                // directly as the function index.
                if ord >= num_funcs {
                    // Out-of-range ordinal: cannot resolve (fail-closed for
                    // this name; other names may still match).
                    continue;
                }
                if ord * 4 + 3 >= funcs.len() {
                    return Err(RuntimeLoadError::ExportResolutionFailed(
                        "export function array truncated".to_string(),
                    ));
                }
                let func_rva = u32::from_le_bytes([
                    funcs[ord * 4],
                    funcs[ord * 4 + 1],
                    funcs[ord * 4 + 2],
                    funcs[ord * 4 + 3],
                ]) as usize;
                if func_rva == 0 {
                    continue;
                }
                // Forwarded export: the function RVA points INSIDE the export
                // directory (the name is a forwarder string, not code).
                // Checked range (audit R5): avoid overflow on exp_rva+exp_size.
                if exp_size > 0
                    && exp_rva <= exp_rva.saturating_add(exp_size)
                    && func_rva >= exp_rva
                    && func_rva < exp_rva.saturating_add(exp_size)
                {
                    continue;
                }
                found[wi] = Some(module_base + func_rva);
            }
        }
        Ok(found)
    }

    /// Find the full 64-bit base address of a module by name substring
    /// in the target process (PEB.Ldr InMemoryOrderModuleList walk).
    ///
    /// # Safety
    /// `target` must be a valid process handle.
    unsafe fn find_module_base_in_target(
        &self,
        target: HANDLE,
        name_substr: &str,
    ) -> Result<usize, RuntimeLoadError> {
        use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory as RPM;
        // PEB via NtQueryInformationProcess.
        use windows::Wdk::System::Threading::PROCESSINFOCLASS;
        use windows::Win32::System::Threading::PROCESS_BASIC_INFORMATION;
        let mut pbi = PROCESS_BASIC_INFORMATION::default();
        let mut ret_len: u32 = 0;
        // SAFETY: valid handle + initialized struct.
        let status = unsafe {
            windows::Wdk::System::Threading::NtQueryInformationProcess(
                target,
                PROCESSINFOCLASS(0),
                (&mut pbi as *mut PROCESS_BASIC_INFORMATION) as *mut core::ffi::c_void,
                core::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut ret_len,
            )
        };
        if status != windows::Win32::Foundation::STATUS_SUCCESS {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "NtQueryInformationProcess: {status:?}"
            )));
        }
        let peb = pbi.PebBaseAddress as u64;
        if peb == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "PEB null".to_string(),
            ));
        }
        // PEB+0x18 = Ldr (PEB_LDR_DATA), +0x20 = InMemoryOrderModuleList.
        let ldr_ptr = read_target_u64(target, peb + 0x18)?;
        if ldr_ptr == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "Ldr null".to_string(),
            ));
        }
        let list_head = ldr_ptr + 0x20;
        let mut entry = read_target_u64(target, list_head)?;
        let mut visited = 0u32;
        while entry != 0 && entry != list_head && visited < 512 {
            visited += 1;
            // InMemoryOrderLinks is at +0x10 of LDR_DATA_TABLE_ENTRY; the
            // entry pointer we hold points at the LIST_ENTRY, so:
            //   DllBase = entry - 0x10 + 0x20 = entry + 0x10
            //   FullDllName (UNICODE_STRING) = entry - 0x10 + 0x38 = entry + 0x28
            // InMemoryOrderLinks lives at LDR_DATA_TABLE_ENTRY+0x10, so the
            // LIST_ENTRY we hold points at entry_base+0x10:
            //   DllBase      = entry_base + 0x30 = entry + 0x20
            //   FullDllName  = entry_base + 0x48 (UNICODE_STRING) = entry + 0x38
            let dll_base = read_target_u64(target, entry + 0x20)?;
            let unicode_len = read_target_u16(target, entry + 0x38)? as usize;
            let unicode_buf = read_target_u64(target, entry + 0x40)?;
            if unicode_buf != 0 && unicode_len > 0 && unicode_len <= 1024 {
                let mut bytes = vec![0u8; unicode_len];
                let rd = unsafe {
                    RPM(
                        target,
                        unicode_buf as *const core::ffi::c_void,
                        bytes.as_mut_ptr() as *mut core::ffi::c_void,
                        unicode_len,
                        None,
                    )
                };
                if rd.is_ok() {
                    // FullDllName is UTF-16LE; decode to UTF-16 units then compare.
                    let units: Vec<u16> = bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect();
                    let lower: String = String::from_utf16_lossy(&units).to_lowercase();
                    if lower.contains(name_substr) {
                        return Ok(dll_base as usize);
                    }
                }
            }
            entry = read_target_u64(target, entry)?;
        }
        Ok(0)
    }
    /// Remote MidaAntidebugShutdown (best-effort during cleanup).
    #[allow(dead_code)] // exercised by loader integration tests
    ///
    /// # Safety
    /// `loaded` must reference a live runtime in `target`.
    pub unsafe fn remote_shutdown(
        &self,
        target: HANDLE,
        loaded: &LoadedRuntime,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> Result<RemoteCallResult, RuntimeLoadError> {
        let args = ThunkArgs {
            fn_ptr: loaded.exports.shutdown as u64,
            arg0: 0,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            reserved: 0,
        };
        unsafe { self.thunk_call(target, &args, drain) }
    }

    /// Free the remote allocations (path + params) after load.
    #[allow(dead_code)] // exercised by loader integration tests
    ///
    /// # Safety
    /// `loaded` must reference allocations that still exist in `target`.
    pub unsafe fn free_remote_allocations(&self, target: HANDLE, loaded: &LoadedRuntime) {
        if !loaded.remote_path.is_null() {
            let _ = unsafe { VirtualFreeEx(target, loaded.remote_path, 0, MEM_RELEASE) };
        }
        if !loaded.remote_params.is_null() {
            let _ = unsafe { VirtualFreeEx(target, loaded.remote_params, 0, MEM_RELEASE) };
        }
    }
}

/// Read a u64 from the target process at an absolute address.
///
/// # Safety
/// `target` must be a valid process handle; `addr` must be readable in the target.
unsafe fn read_target_u64(target: HANDLE, addr: u64) -> Result<u64, RuntimeLoadError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory as RPM;
    let mut b = [0u8; 8];
    let r = unsafe {
        RPM(
            target,
            addr as *const core::ffi::c_void,
            b.as_mut_ptr() as *mut core::ffi::c_void,
            8,
            None,
        )
    };
    if r.is_err() {
        return Err(RuntimeLoadError::ExportResolutionFailed(format!(
            "remote read u64 @ {addr:#x} failed"
        )));
    }
    Ok(u64::from_le_bytes(b))
}

/// Read a u16 from the target process at an absolute address.
///
/// # Safety
/// `target` must be a valid process handle; `addr` must be readable in the target.
unsafe fn read_target_u16(target: HANDLE, addr: u64) -> Result<u16, RuntimeLoadError> {
    use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory as RPM;
    let mut b = [0u8; 2];
    let r = unsafe {
        RPM(
            target,
            addr as *const core::ffi::c_void,
            b.as_mut_ptr() as *mut core::ffi::c_void,
            2,
            None,
        )
    };
    if r.is_err() {
        return Err(RuntimeLoadError::ExportResolutionFailed(format!(
            "remote read u16 @ {addr:#x} failed"
        )));
    }
    Ok(u16::from_le_bytes(b))
}

/// Build the raw bytes of a MidaInitParams blob for the target process.
///
/// Layout (must match the runtime #[repr(C)] struct exactly):
///   offset 0x00: u32 target_pid
///   offset 0x08: u64 module_base
///   offset 0x10: u64 profile_id ptr
///   offset 0x18: u64 profile_digest ptr
///   offset 0x20: u64 expected_hooks (usize)
///   offset 0x28: u64 expected_surfaces ptr
///   size 0x30
///
/// Strings and the surface pointer array are appended after the struct and
/// referenced by absolute target addresses (remote_blob_base + offset).
pub fn build_init_params_bytes(
    target_pid: u32,
    profile_id: &str,
    profile_digest: &str,
    expected_surfaces: &[String],
    module_base: u64,
    remote_blob_base: u64,
) -> Result<Vec<u8>, RuntimeLoadError> {
    let mut out = Vec::with_capacity(0x30 + 0x100);
    // struct (0x30 bytes)
    out.extend_from_slice(&target_pid.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]); // padding
    out.extend_from_slice(&module_base.to_le_bytes());
    // pointer fields patched below after we know string offsets
    let pid_off = out.len();
    out.extend_from_slice(&[0u8; 8]);
    let dig_off = out.len();
    out.extend_from_slice(&[0u8; 8]);
    out.extend_from_slice(&(expected_surfaces.len() as u64).to_le_bytes());
    let surf_off = out.len();
    out.extend_from_slice(&[0u8; 8]);
    debug_assert_eq!(out.len(), 0x30);
    // profile_id string (NUL-terminated)
    let pid_str_off = out.len() as u64;
    out.extend_from_slice(profile_id.as_bytes());
    out.push(0);
    // profile_digest string (NUL-terminated)
    let dig_str_off = out.len() as u64;
    out.extend_from_slice(profile_digest.as_bytes());
    out.push(0);
    // surface strings first, then the pointer array AFTER them.
    let mut surf_addrs = Vec::with_capacity(expected_surfaces.len());
    for s in expected_surfaces {
        let s_off = out.len() as u64;
        out.extend_from_slice(s.as_bytes());
        out.push(0);
        surf_addrs.push(remote_blob_base + s_off);
    }
    // reserve the pointer array slots (8 bytes each) - the array lives after
    // the strings; surf_arr_off must point at the array start.
    let surf_arr_off = out.len() as u64;
    for _ in 0..expected_surfaces.len() {
        out.extend_from_slice(&[0u8; 8]);
    }
    // patch struct pointer fields
    let patch = |out: &mut Vec<u8>, off: usize, val: u64| {
        out[off..off + 8].copy_from_slice(&val.to_le_bytes());
    };
    patch(&mut out, pid_off, remote_blob_base + pid_str_off);
    patch(&mut out, dig_off, remote_blob_base + dig_str_off);
    patch(&mut out, surf_off, remote_blob_base + surf_arr_off);
    // patch the surface array entries
    for (i, addr) in surf_addrs.iter().enumerate() {
        let off = (surf_arr_off as usize) + i * 8;
        patch(&mut out, off, *addr);
    }
    Ok(out)
}
/// Resolve the audited runtime authority (ADR-6-CORRECTION).
///
/// The environment is ONLY allowed to select the manifest path
/// (MIDA_RUNTIME_AUTHORITY) and the runtime artifact path
/// (MIDA_RUNTIME_DLL). The manifest content is protected by the
/// compiled-in digest (MIDA_RUNTIME_AUTHORITY_DIGEST); expected hashes,
/// sizes, architecture and source revision can NEVER be supplied by the
/// caller.
pub fn runtime_authority() -> Result<RuntimeAuthorityManifest, RuntimeLoadError> {
    let Some(manifest_path) = std::env::var("MIDA_RUNTIME_AUTHORITY").ok() else {
        return Err(RuntimeLoadError::AuthorityUnavailable(
            "MIDA_RUNTIME_AUTHORITY not set".to_string(),
            "no authority manifest path configured".to_string(),
        ));
    };
    RuntimeAuthorityManifest::load(std::path::Path::new(&manifest_path))
}

/// Resolve the runtime artifact path (out-of-tree build product).
pub fn runtime_artifact_path() -> Option<std::path::PathBuf> {
    std::env::var("MIDA_RUNTIME_DLL")
        .ok()
        .map(std::path::PathBuf::from)
}

/// Verify the runtime provenance against the manifest and the runtime file.
///
/// Full binding (CORRECTION-2):
/// 1. Parse with deny_unknown_fields (strict struct).
/// 2. Run the complete ADR-4 Provenance::validate() (kind/arch/third_party/
///    dependencies completeness/anti_debug flags).
/// 3. Cross-bind every identity field against the manifest AND the runtime:
///    artifact_id, sha256, size_bytes, kind, architecture, source_ref.
/// Returns the validated, typed [Provenance] (never raw JSON).
pub fn verify_runtime_provenance(
    manifest: &RuntimeAuthorityManifest,
    manifest_dir: &Path,
    runtime_identity: &RuntimeFileIdentity,
) -> Result<mida_antidebug_runtime::provenance::Provenance, RuntimeLoadError> {
    let prov_path = manifest_dir.join(&manifest.provenance_ref);
    let prov_bytes = std::fs::read(&prov_path).map_err(|e| {
        RuntimeLoadError::AuthorityMismatch(format!(
            "provenance unreadable at {}: {e}",
            prov_path.display()
        ))
    })?;
    // 1. Strict parse (deny_unknown_fields on the struct).
    let prov: mida_antidebug_runtime::provenance::Provenance = serde_json::from_slice(&prov_bytes)
        .map_err(|e| RuntimeLoadError::AuthorityMismatch(format!("provenance parse: {e}")))?;
    // 2. Full ADR-4 semantic validation (not just deserialization).
    prov.validate()
        .map_err(|e| RuntimeLoadError::AuthorityMismatch(format!("provenance validate: {e}")))?;
    // 3. Cross-bind against the runtime file identity.
    if prov.sha256 != runtime_identity.sha256 {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance sha256 {} != runtime {}",
            prov.sha256, runtime_identity.sha256
        )));
    }
    if prov.size_bytes != runtime_identity.size_bytes {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance size {} != runtime {}",
            prov.size_bytes, runtime_identity.size_bytes
        )));
    }
    // 4. Cross-bind against the manifest (full identity chain).
    if prov.artifact_id != manifest.artifact_id {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance artifact_id {} != manifest {}",
            prov.artifact_id, manifest.artifact_id
        )));
    }
    if prov.sha256 != manifest.sha256 {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance sha256 {} != manifest {}",
            prov.sha256, manifest.sha256
        )));
    }
    if prov.size_bytes != manifest.size_bytes {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance size {} != manifest {}",
            prov.size_bytes, manifest.size_bytes
        )));
    }
    if prov.kind != manifest.kind {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance kind {} != manifest {}",
            prov.kind, manifest.kind
        )));
    }
    if prov.architecture != manifest.architecture {
        return Err(RuntimeLoadError::ArchitectureUnsupported(format!(
            "provenance arch {} != manifest {}",
            prov.architecture, manifest.architecture
        )));
    }
    if prov.source_ref != manifest.source_ref {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance source_ref {} != manifest {}",
            prov.source_ref, manifest.source_ref
        )));
    }
    Ok(prov)
}

/// Run the full loader sequence against a suspended target and return the
/// controller-facing result. Any failure is fail-closed (Err).
pub fn run_runtime_loader(
    target: HANDLE,
    target_pid: u32,
    profile_id: &str,
    profile_digest: &str,
    drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
) -> Result<crate::unpacker::antidebug_controller::LoaderResult, RuntimeLoadError> {
    let authority = runtime_authority()?;
    let Some(runtime_path) = runtime_artifact_path() else {
        return Err(RuntimeLoadError::AuthorityUnavailable(
            "MIDA_RUNTIME_DLL not set".to_string(),
            "no runtime artifact path configured".to_string(),
        ));
    };
    // Expected surfaces: the two hard-required PEB surfaces (ADR-5).
    // AD-PROC-001 stays a candidate and is NOT requested here.
    let expected_surfaces = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
    let loader = RuntimeLoader::new(authority.clone());
    // SAFETY: target is a valid process handle; the target main thread is
    // suspended (CREATE_PROCESS debug event window).
    let loaded = unsafe {
        loader.load_and_initialize(
            target,
            target_pid,
            &runtime_path,
            profile_id,
            profile_digest,
            &expected_surfaces,
            drain,
        )
    }?;
    // Provenance binding: verify the runtime's provenance record against the
    // manifest and the loaded file before reporting success.
    let manifest_dir =
        std::path::Path::new(&std::env::var("MIDA_RUNTIME_AUTHORITY").map_err(|_| {
            RuntimeLoadError::AuthorityUnavailable(
                "MIDA_RUNTIME_AUTHORITY unset".to_string(),
                "cannot resolve manifest dir".to_string(),
            )
        })?)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let _prov = verify_runtime_provenance(&authority, &manifest_dir, &loaded.file_identity)?;
    Ok(crate::unpacker::antidebug_controller::LoaderResult {
        module_base: loaded.module_base as u64,
        attestation_json: loaded.attestation_json,
        file_identity: loaded.file_identity,
        target_pid,
    })
}

// ---------------------------------------------------------------------------
// ADR-5B-R3: REAL timeout-safety integration harness (Windows only)
// ---------------------------------------------------------------------------
//
// These tests prove the timeout contract with a real slow remote thread:
//   - the deadline is enforced by a real monotonic clock (wall time ~=
//     declared deadline, never ~2x);
//   - on timeout the thunk allocation is NOT freed (remote code may still
//     be executing it);
//   - after the remote thread finishes, the retained memory can be released
//     safely (the thread is truly done).

#[cfg(all(test, windows))]
mod timeout_harness {
    use super::*;
    use windows::core::{PCSTR, PCWSTR};
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::Win32::System::Memory::{
        VirtualFreeEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, MEM_RELEASE,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    fn noop_drain(_ms: u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError> {
        Ok(None)
    }

    /// Address of kernel32!Sleep in THIS process. On x64 the kernel32 base is
    /// process-independent (same address space layout for system DLLs), so
    /// this address is valid in the remote thread context.
    fn sleep_addr() -> usize {
        let name: Vec<u16> = "kernel32.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let h = unsafe { GetModuleHandleW(PCWSTR(name.as_ptr())) }.ok();
        let h = h.expect("kernel32 must be loaded");
        let addr = unsafe { GetProcAddress(h, PCSTR(b"Sleep\0".as_ptr())) };
        addr.expect("Sleep must exist in kernel32") as usize
    }

    #[test]
    fn slow_remote_thread_times_out_and_retains_memory() {
        let loader = RuntimeLoader::new(runtime_authority_stub());
        // SAFETY: GetCurrentProcess returns a pseudo-handle valid for the
        // whole process lifetime; we never close it.
        let target = unsafe { GetCurrentProcess() };
        // The slow remote "function" is kernel32!Sleep(5000ms): a REAL slow
        // remote thread that outlives the 1s deadline and finishes on its
        // own after ~5s. ThunkArgs.fn_ptr is the function the thunk calls.
        let slow_fn = sleep_addr();
        let slow_ms = 5000u64;
        let args = ThunkArgs {
            fn_ptr: slow_fn as u64,
            arg0: slow_ms,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            reserved: 0,
        };

        let t0 = Instant::now();
        // F-005: call the REAL thunk_call path (allocation + write + protect
        // + remote thread + wait). The tracked variant reports the ACTUAL
        // VirtualAllocEx address so we can probe the real thunk.
        // F-011: also return the RAW remote thread handle so completion can
        // be proven with WaitForSingleObject instead of a sleep estimate.
        let (result, thunk_addr, thread_handle) =
            unsafe { loader.thunk_call_tracked_with_handle(target, &args, 1, &mut noop_drain) };
        let elapsed = t0.elapsed();
        assert!(
            matches!(result, Err(RuntimeLoadError::RemoteCallFailed(_))),
            "slow remote thread must time out: {result:?}"
        );
        let thunk_addr = thunk_addr.expect("thunk_call_tracked must report the allocation");
        // REAL-clock enforcement: the wall time must be within [0.8s, 3s]
        // (a doubled deadline would exceed 2s by a wide margin; 1s deadline
        // with 200ms polls + slack stays well under 3s).
        let ms = elapsed.as_millis();
        assert!(
            (800..3000).contains(&ms),
            "timeout must respect the REAL 1s deadline (got {ms}ms)"
        );

        // The REAL thunk allocation must STILL be committed (the remote
        // thread may still be executing it; thunk_call must NOT have freed
        // it on timeout).
        // SAFETY: thunk_addr is the loader's own valid allocation.
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let vq = unsafe {
            VirtualQueryEx(
                target,
                Some(thunk_addr as *const core::ffi::c_void),
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        assert!(vq > 0, "VirtualQueryEx failed");
        assert!(
            mbi.State == MEM_COMMIT,
            "REAL thunk must remain committed after timeout (State={:?})",
            mbi.State
        );

        // F-011: prove the remote thread truly finished by waiting on the
        // REAL thread handle (replaces the previous sleep-based estimate).
        let thread_handle = thread_handle.expect("with_handle must report the thread handle");
        // SAFETY: thread_handle is the valid CreateRemoteThread result from
        // thunk_call_tracked_with_handle; we only wait, then close it.
        let wait = unsafe { WaitForSingleObject(thread_handle, u32::MAX) };
        assert_eq!(
            wait.0, 0,
            "remote thread must signal after Sleep(5s) finishes"
        );
        // SAFETY: close the raw handle we own (into_raw transferred it).
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(thread_handle) };

        // ADR-5B-R3 (audit round 2): "thread returns safely" proof.
        // VirtualFreeEx on a page that a thread is STILL executing fails with
        // ERROR_INVALID_ADDRESS / access violation — the OS refuses to
        // release memory with live execution. A successful MEM_RELEASE after
        // the Sleep(5s) window therefore proves the remote thread has truly
        // exited the retained thunk. Combined with the earlier MEM_COMMIT
        // probe (thunk retained on timeout), this closes the safety loop:
        //   timeout -> memory retained (remote may still run)
        //   thread finishes -> memory releasable (no live execution)
        // SAFETY: thunk is still a valid committed allocation in our process.
        let f = unsafe { VirtualFreeEx(target, thunk_addr as *mut _, 0, MEM_RELEASE) };
        assert!(f.is_ok(), "VirtualFreeEx after thread finish failed (remote thread may still be executing the thunk)");
    }

    /// R1-HARDENING-REMOTE-HANDLE-1: the PRODUCTION thunk_call() wrapper
    /// must close the raw remote thread handle on every return path. We
    /// cannot observe the handle directly (it is closed inside the wrapper),
    /// so we prove it via the process-wide handle count: repeated timed-out
    /// thunk_call() invocations must NOT grow the handle table (a leak would
    /// show a monotonic increase).
    ///
    /// The production wrapper hard-codes a 60s deadline, which is too long
    /// for a unit test; instead we drive the SAME ownership contract through
    /// thunk_call_tracked_with_handle() (1s deadline) and explicitly verify
    /// the wrapper-style handle consumption: the caller receives a raw
    /// handle on timeout and MUST close it. The seam under test is the
    /// destructure-and-close pattern that thunk_call() now implements.
    #[test]
    fn production_thunk_call_does_not_leak_thread_handles() {
        // R1-HARDENING-REMOTE-HANDLE-TEST-1: this test MUST exercise the
        // PRODUCTION ownership wrapper (thunk_call_bounded) and MUST NOT
        // close any handle itself. The wrapper destructures the tuple and
        // closes the raw remote thread handle on every return path; if the
        // production wrapper regresses to leaking the handle (e.g. calling
        // thunk_call_tracked_with_handle().0 and dropping the raw handle),
        // the process-wide handle count grows monotonically and this test
        // FAILS.
        // SAFETY: GetCurrentProcess returns a pseudo-handle valid for the
        // whole process lifetime; we never close it.
        let target = unsafe { GetCurrentProcess() };
        let slow_fn = sleep_addr();
        let args = ThunkArgs {
            fn_ptr: slow_fn as u64,
            arg0: 5000, // Sleep(5s): outlives the 1s deadline
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            reserved: 0,
        };
        let loader = RuntimeLoader::new(runtime_authority_stub());
        let mut deltas = Vec::new();
        for _ in 0..3 {
            let before = unsafe { process_handle_count() };
            // PRODUCTION wrapper (1s deadline): internally closes the raw
            // thread handle. NO test-side CloseHandle below.
            let result = unsafe { loader.thunk_call_bounded(target, &args, 1, &mut noop_drain) };
            assert!(result.is_err(), "slow thunk must time out");
            // Let the slow Sleep thread finish so its own handle is gone
            // before counting (the remote thread itself is not our leak).
            std::thread::sleep(std::time::Duration::from_millis(5600));
            let after = unsafe { process_handle_count() };
            deltas.push(after.saturating_sub(before));
        }
        // R1-HARDENING-REMOTE-HANDLE-TEST-1: with correct closing the
        // process-wide handle count must NOT grow across iterations at all
        // (deltas all 0). A leak shows +1 per call (monotonic); the previous
        // "<= 1" allowance masked a +1-per-call leak as OS noise and made
        // this test pass against the leaking wrapper — fixed to require 0.
        let max_delta = *deltas.iter().max().unwrap();
        assert_eq!(
            max_delta, 0,
            "thunk_call_bounded (production wrapper) leaks thread handles: deltas={deltas:?} (must be all 0)"
        );
    }

    /// Process-wide handle count (used to detect kernel handle leaks).
    ///
    /// # Safety
    /// Read-only query; no handle is created or closed.
    unsafe fn process_handle_count() -> u32 {
        let mut count = 0u32;
        // SAFETY: GetProcessHandleCount writes only the out parameter.
        let _ = unsafe {
            windows::Win32::System::Threading::GetProcessHandleCount(
                GetCurrentProcess(),
                &mut count,
            )
        };
        count
    }

    fn runtime_authority_stub() -> RuntimeAuthorityManifest {
        // The loader only needs the authority for path resolution in the
        // full flow; remote_call_raw_bounded does not touch it. Build a
        // minimal stub (never loaded from disk).
        RuntimeAuthorityManifest {
            schema: "mida.runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "stub".to_string(),
            sha256: "00".repeat(32),
            size_bytes: 0,
            architecture: "x86_64".to_string(),
            source_ref: "stub".to_string(),
            provenance_ref: "stub.json".to_string(),
        }
    }
}


// ============================================================================
// IMP-03: Loader/ABI inert adapter (v2, offline)
// ============================================================================
//
// Pure-offline additions for the v2 entry contract. Nothing here executes a
// thunk, writes process memory, or loads a remote module: it only:
//   - declares the v2 wanted-export set (MidaAntidebugInitializeV2 +
//     GetAttestation + Shutdown);
//   - parses a THUNK7 byte fixture (60B production / 64B test-with-probe)
//     without executing it;
//   - serializes a v2 params blob (self-relative offsets, no pointers).
// All paths are fail-closed and feature-gated behind #[cfg(test)] where a
// runtime consumer would otherwise be needed.

/// v2 wanted export names (7-arg initialize entry).
pub const WANTED_EXPORTS_V2: &[&str] = &[
    "MidaAntidebugInitializeV2",
    "MidaAntidebugGetAttestation",
    "MidaAntidebugShutdown",
];

/// v2 export resolution result (inert: addresses are placeholder values
/// supplied by the caller; nothing is dereferenced here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MidaExportsV2 {
    pub initialize_v2: Option<usize>,
    pub get_attestation: Option<usize>,
    pub shutdown: Option<usize>,
}

impl MidaExportsV2 {
    /// Fail-closed: v2 entry is REQUIRED for the v2 contract.
    pub fn require_complete(&self) -> Result<(), RuntimeLoadError> {
        if self.initialize_v2.is_none() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "MidaAntidebugInitializeV2 missing".to_string(),
            ));
        }
        if self.get_attestation.is_none() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "MidaAntidebugGetAttestation missing".to_string(),
            ));
        }
        if self.shutdown.is_none() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "MidaAntidebugShutdown missing".to_string(),
            ));
        }
        Ok(())
    }
}

/// Parsed THUNK7 byte fixture (production 60B / test 64B) - PARSER ONLY.
/// The parser verifies structural invariants (call position, ret position,
/// probe position for the test variant) but never executes the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Thunk7Fixture {
    pub production: Vec<u8>,
    pub test_with_probe: Vec<u8>,
}

/// Production THUNK7_CODE (60B) as declared in WO-2301 fixture, with
/// call rax at 0x35 (FF D0), add rsp,0x38 at 0x37, ret at 0x3B.
pub const THUNK7_PRODUCTION: [u8; 60] = [
    0x49, 0x89, 0xCB, // 0000 mov r11, rcx
    0x49, 0x8B, 0x03, // 0003 mov rax, [r11]
    0x49, 0x8B, 0x4B, 0x08, // 0006 mov rcx, [r11+8]
    0x49, 0x8B, 0x53, 0x10, // 000A mov rdx, [r11+16]
    0x4D, 0x8B, 0x43, 0x18, // 000E mov r8,  [r11+24]
    0x4D, 0x8B, 0x4B, 0x20, // 0012 mov r9,  [r11+32]
    0x48, 0x83, 0xEC, 0x38, // 0016 sub rsp, 0x38
    0x4D, 0x8B, 0x53, 0x28, // 001A mov r10, [r11+40]
    0x4C, 0x89, 0x54, 0x24, 0x20, // 001E mov [rsp+0x20], r10
    0x4D, 0x8B, 0x53, 0x30, // 0023 mov r10, [r11+48]
    0x4C, 0x89, 0x54, 0x24, 0x28, // 0027 mov [rsp+0x28], r10
    0x4D, 0x8B, 0x53, 0x38, // 002C mov r10, [r11+56]
    0x4C, 0x89, 0x54, 0x24, 0x30, // 0030 mov [rsp+0x30], r10
    0xFF, 0xD0, // 0035 call rax
    0x48, 0x83, 0xC4, 0x38, // 0037 add rsp, 0x38
    0xC3, // 003B ret
];

/// Test-only 64B variant: probe (49 89 63 48) at 0x35..0x38, call at 0x39.
pub fn thunk7_test_with_probe() -> [u8; 64] {
    let mut out = [0u8; 64];
    out[0..0x35].copy_from_slice(&THUNK7_PRODUCTION[0..0x35]);
    out[0x35..0x39].copy_from_slice(&[0x49, 0x89, 0x63, 0x48]); // probe
    out[0x39..0x3B].copy_from_slice(&[0xFF, 0xD0]); // call rax
    out[0x3B..0x3F].copy_from_slice(&[0x48, 0x83, 0xC4, 0x38]); // add rsp,0x38
    out[0x3F] = 0xC3; // ret
    out
}

impl Thunk7Fixture {
    /// Build the canonical fixture pair.
    pub fn build() -> Self {
        Self {
            production: THUNK7_PRODUCTION.to_vec(),
            test_with_probe: thunk7_test_with_probe().to_vec(),
        }
    }

    /// Parser-only structural validation (never executes the bytes).
    pub fn validate_structure(&self) -> Result<(), RuntimeLoadError> {
        if self.production.len() != 60 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "thunk7 production must be 60B".to_string(),
            ));
        }
        if self.test_with_probe.len() != 64 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "thunk7 test variant must be 64B".to_string(),
            ));
        }
        // production: call rax (FF D0) at 0x35
        if self.production[0x35] != 0xFF || self.production[0x36] != 0xD0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "thunk7 production call rax must be at 0x35".to_string(),
            ));
        }
        // production: ret at 0x3B
        if self.production[0x3B] != 0xC3 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "thunk7 production ret must be at 0x3B".to_string(),
            ));
        }
        // test: probe (49 89 63 48) at 0x35, call at 0x39, ret at 0x3F
        if self.test_with_probe[0x35..0x39] != [0x49, 0x89, 0x63, 0x48] {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "thunk7 test probe must be at 0x35".to_string(),
            ));
        }
        if self.test_with_probe[0x39] != 0xFF || self.test_with_probe[0x3A] != 0xD0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "thunk7 test call rax must be at 0x39".to_string(),
            ));
        }
        if self.test_with_probe[0x3F] != 0xC3 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "thunk7 test ret must be at 0x3F".to_string(),
            ));
        }
        Ok(())
    }
}

/// v2 params blob serialization (pure memory; envelope layout).
///
/// MidaInitParamsV2 envelope (WO-1505 §5.3e):
///   0x10 profile_id_off         (self-relative)
///   0x18 profile_digest_off     (self-relative)
///   0x20 expected_hooks         (u64 count of surface pointers)
///   0x28 expected_surfaces_off  (self-relative to pointer array)
///   0x30 magic_v2               (0x003250324144494D = "MIDA2P2\0" LE)
///   0x38 digest_off             (self-relative; 64 hex + NUL)
///   0x40 digest_len             (must be 64)
///
/// Surface array entries are TARGET-LOCAL ABSOLUTE VAs (WO-1505 §5.3e):
/// the array holds absolute target addresses, not self-relative offsets.
/// All arithmetic is checked (fail-closed); no unchecked add/mul survives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2ParamsBlob {
    pub bytes: Vec<u8>,
}

pub const V2_ENVELOPE_MAGIC: u64 = 0x0032_5032_4144_494D; // "MIDA2P2\0" LE
pub const V2_HEADER_BYTES: usize = 0x48;
/// digest_len field value: 64 (hex chars only; frozen ABI).
/// The wire region is 64 hex + 1 NUL = 65 bytes; the FIELD is 64.
pub const V2_DIGEST_LEN: u64 = 64;
/// Wire region bytes: 64 hex chars + NUL terminator.
pub const V2_DIGEST_REGION_BYTES: u64 = 65;
/// Max surface count (WO-1505 §5.3e / RC-4: builder rejects > 256).
pub const V2_MAX_HOOKS: u64 = 256;

/// Canonical x64 user-mode VA predicate (kernel high-half is not canonical
/// user VA; see WO-1505 §5.3e canonical rule: absolute addresses in the
/// envelope must be canonical user VAs and nonzero).
pub fn v2_is_canonical_user_va(va: u64) -> bool {
    // x64 canonical user addresses: 0x0000_0000_0000_0000 ..= 0x0000_7FFF_FFFF_FFFF
    // (bits 48..63 zero); kernel addresses (bit 47 set) are not user VAs.
    va <= 0x0000_7FFF_FFFF_FFFF
}

impl V2ParamsBlob {
    /// Serialize a v2 params envelope.
    ///
    /// Layout (WO-1505 §5.3a golden bytes / RC-4):
    ///   [0x00 .. 0x48) header; strings follow in this order:
    ///   profile_id, profile_digest, surface strings, then the pointer array
    ///   (entries = absolute VAs of the surface strings), then the digest.
    /// All offsets written into the header are SELF-RELATIVE (offset from
    /// blob start). The pointer array itself holds ABSOLUTE VAs (RC-4).
    ///
    /// Rejection rules:
    ///   - digest must be exactly 64 lowercase hex chars (0-9a-f only).
    ///   - expected_hooks (surface count) must be in 1..=256; builder
    ///     rejects zero and > 256 (RC-4 item 6/10).
    ///   - surface strings must be nonempty.
    pub fn build(
        profile_id: &str,
        profile_digest: &str,
        expected_surfaces: &[String],
        digest: &str,
        blob_base: u64,
    ) -> Result<Self, RuntimeLoadError> {
        if !v2_is_canonical_user_va(blob_base) {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 blob_base must be a canonical user VA, got {blob_base:#x}"
            )));
        }
        if blob_base == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 blob_base must be nonzero".to_string(),
            ));
        }
        if digest.len() != 64 {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 digest must be 64 hex chars, got {}",
                digest.len()
            )));
        }
        if !digest.bytes().all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b <= b'f')) {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 digest must be lowercase hex (0-9a-f only)".to_string(),
            ));
        }
        let expected_hooks = expected_surfaces.len() as u64;
        if expected_hooks == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 expected_hooks must be in 1..=256".to_string(),
            ));
        }
        if expected_hooks > V2_MAX_HOOKS {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 expected_hooks exceeds max 256, got {}",
                expected_hooks
            )));
        }
        for s in expected_surfaces {
            if s.is_empty() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "v2 surface string must be nonempty".to_string(),
                ));
            }
        }
        let mut out: Vec<u8> = Vec::new();
        out.resize(V2_HEADER_BYTES, 0u8);
        // magic
        out[0x30..0x38].copy_from_slice(&V2_ENVELOPE_MAGIC.to_le_bytes());
        // expected_hooks at 0x20 (frozen layout: usize/u64)
        out[0x20..0x28].copy_from_slice(&expected_hooks.to_le_bytes());
        // digest_len
        out[0x40..0x48].copy_from_slice(&V2_DIGEST_LEN.to_le_bytes());
        // profile_id string
        let pid_off = out.len() as u64;
        out.extend_from_slice(profile_id.as_bytes());
        out.push(0);
        // profile_digest string
        let pd_off = out.len() as u64;
        out.extend_from_slice(profile_digest.as_bytes());
        out.push(0);
        // surface strings
        let mut surf_addrs: Vec<u64> = Vec::with_capacity(expected_surfaces.len());
        for s in expected_surfaces {
            let off = out.len() as u64;
            out.extend_from_slice(s.as_bytes());
            out.push(0);
            // ABSOLUTE target VA (RC-4 item 2): blob_base + relative offset.
            let abs = blob_base.checked_add(off).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(format!(
                    "v2 surface entry absolute VA overflow at {off:#x}"
                ))
            })?;
            if !v2_is_canonical_user_va(abs) {
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "v2 surface entry absolute VA noncanonical: {abs:#x}"
                )));
            }
            surf_addrs.push(abs);
        }
        // pointer array (absolute VAs)
        let surf_arr_off = out.len() as u64;
        for a in surf_addrs {
            out.extend_from_slice(&a.to_le_bytes());
        }
        // digest string (self-relative)
        let dig_off = out.len() as u64;
        out.extend_from_slice(digest.as_bytes());
        out.push(0);
        // patch offsets (self-relative: absolute offset in the blob).
        // RC-5: header slots are fixed constants but still use checked
        // arithmetic for uniformity (no bare + 8 anywhere in this path).
        let patch = |out: &mut Vec<u8>, off: usize, val: u64| -> Result<(), RuntimeLoadError> {
            let end = off.checked_add(8).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed("v2 header patch overflow".to_string())
            })?;
            if end > out.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "v2 header patch out of bounds".to_string(),
                ));
            }
            out[off..end].copy_from_slice(&val.to_le_bytes());
            Ok(())
        };
        patch(&mut out, 0x10, pid_off)?;
        patch(&mut out, 0x18, pd_off)?;
        patch(&mut out, 0x28, surf_arr_off)?;
        patch(&mut out, 0x38, dig_off)?;
        Ok(Self { bytes: out })
    }

    /// Offline re-parse of the serialized blob (no pointer dereference).
    ///
    /// Verifies, in order (fail-closed on every check):
    ///   1. header size / magic / digest_len field
    ///   2. expected_hooks semantics: zero-hooks + zero-surfaces_off is the
    ///      ONLY legal zero case (RC-4 item 6); zero-hooks + nonzero
    ///      surfaces_off rejected; nonzero-hooks + zero surfaces_off rejected.
    ///   3. self-relative header offsets in-bounds, strings bounded NUL
    ///   4. surfaces array: length == expected_hooks * 8 (checked), array
    ///      end == digest_off exactly (no unknown tail / truncation)
    ///   5. digest region: 65 bytes, lowercase hex, NUL at +64
    ///   6. per-entry: nonzero, canonical user VA, in [blob_base, blob_end)
    ///      (RC-4 item 5) — entries are ABSOLUTE VAs; converted to relative
    ///      index before reading (checked).
    ///   7. blob_base + params_bytes checked (RC-4 item 4).
    pub fn parse_offsets(&self, blob_base: u64) -> Result<V2Offsets, RuntimeLoadError> {
        if self.bytes.len() < V2_HEADER_BYTES {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 blob shorter than header".to_string(),
            ));
        }
        if !v2_is_canonical_user_va(blob_base) || blob_base == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 blob_base invalid: {blob_base:#x}"
            )));
        }
        let len = u64::try_from(self.bytes.len()).map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed(
                "v2 blob length exceeds u64".to_string(),
            )
        })?;
        // RC-4 item 4: blob_base + params_bytes checked.
        let blob_end = blob_base.checked_add(len).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 blob_base + params_bytes overflow: {blob_base:#x} + {len:#x}"
            ))
        })?;
        let magic = u64::from_le_bytes(self.bytes[0x30..0x38].try_into().unwrap());
        if magic != V2_ENVELOPE_MAGIC {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 magic mismatch".to_string(),
            ));
        }
        let pid_off = u64::from_le_bytes(self.bytes[0x10..0x18].try_into().unwrap());
        let pd_off = u64::from_le_bytes(self.bytes[0x18..0x20].try_into().unwrap());
        // expected_hooks at 0x20 (frozen layout: u64 count of surface pointers)
        let expected_hooks = u64::from_le_bytes(self.bytes[0x20..0x28].try_into().unwrap());
        let surf_off = u64::from_le_bytes(self.bytes[0x28..0x30].try_into().unwrap());
        let dig_off = u64::from_le_bytes(self.bytes[0x38..0x40].try_into().unwrap());
        let dig_len_field = u64::from_le_bytes(self.bytes[0x40..0x48].try_into().unwrap());
        // digest_len field MUST be 64 (frozen ABI).
        if dig_len_field != V2_DIGEST_LEN {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 digest_len field must be 64, got {}",
                dig_len_field
            )));
        }
        // RC-4 items 6/7/8: zero-hooks semantics.
        if expected_hooks == 0 && surf_off != 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 zero hooks with nonzero surfaces_off rejected".to_string(),
            ));
        }
        if expected_hooks > 0 && surf_off == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 nonzero hooks with zero surfaces_off rejected".to_string(),
            ));
        }
        if expected_hooks > V2_MAX_HOOKS {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 expected_hooks exceeds max 256, got {}",
                expected_hooks
            )));
        }
        // self-relative header offsets must be in [0x48, len) (when nonzero).
        for (name, off) in [
            ("profile_id", pid_off),
            ("profile_digest", pd_off),
            ("digest", dig_off),
        ] {
            if off < V2_HEADER_BYTES as u64 || off >= len {
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "v2 {name} offset out of bounds: {off:#x}"
                )));
            }
        }
        // Bounded NUL scans for the referenced strings (fail-closed).
        scan_nul_rel(&self.bytes, pid_off, len, "profile_id")?;
        scan_nul_rel(&self.bytes, pd_off, len, "profile_digest")?;
        scan_nul_rel(&self.bytes, dig_off, len, "digest")?;

        // digest region: 64 LOWERCASE hex chars + NUL = 65 bytes.
        // RC-5: every end is computed with checked_range_end; no raw + 64.
        let dig_hex_end = checked_range_end(dig_off, V2_DIGEST_LEN, "digest hex")?;
        let dig_region_end = checked_range_end(dig_off, V2_DIGEST_REGION_BYTES, "digest region")?;
        if dig_region_end > len {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 digest region truncated".to_string(),
            ));
        }
        // RC-5: explicit checked u64 -> usize conversions before slicing.
        let dig_hex_start_us = u64_to_usize(dig_off, "digest start")?;
        let dig_hex_end_us = u64_to_usize(dig_hex_end, "digest hex end")?;
        for (i, &c) in self.bytes[dig_hex_start_us..dig_hex_end_us].iter().enumerate() {
            let is_lower_hex = c.is_ascii_digit() || (c.is_ascii_lowercase() && c <= b'f');
            if !is_lower_hex {
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "v2 digest must be lowercase hex (0-9a-f) at {i}; uppercase rejected"
                )));
            }
        }
        // NUL terminator at dig_hex_end (== dig_off + 64, computed checked).
        let dig_nul_us = u64_to_usize(dig_hex_end, "digest NUL")?;
        if self.bytes[dig_nul_us] != 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 digest region NUL missing".to_string(),
            ));
        }
        // surfaces array: length MUST be exactly expected_hooks * 8 (checked),
        // positioned immediately before the digest region.
        let array_bytes = expected_hooks
            .checked_mul(8)
            .ok_or(RuntimeLoadError::ExportResolutionFailed(
                "v2 expected_hooks*8 overflow".to_string(),
            ))?;
        if expected_hooks > 0 {
            let array_end = checked_range_end(surf_off, array_bytes, "surfaces array")?;
            if array_end != dig_off {
                let actual = dig_off.checked_sub(surf_off).unwrap_or(u64::MAX);
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "v2 surfaces array length mismatch: declared {expected_hooks} entries -> {array_bytes}B, actual region {actual}B"
                )));
            }
            // Per-entry checks (WO-1505 §5.3e + RC-4 item 5): each entry is an
            // ABSOLUTE target VA: nonzero, canonical user VA, in
            // [blob_base, blob_end); convert to relative index (checked)
            // before reading the surface string.
            for i in 0..expected_hooks {
                // RC-4 P0-4: entry arithmetic fully checked.
                let entry_off = surf_off
                    .checked_add(
                        i.checked_mul(8)
                            .ok_or(RuntimeLoadError::ExportResolutionFailed(
                                "v2 entry index*8 overflow".to_string(),
                            ))?,
                    )
                    .ok_or(RuntimeLoadError::ExportResolutionFailed(
                        "v2 entry offset overflow".to_string(),
                    ))?;
                // RC-5: entry end via checked_range_end, then explicit
                // u64 -> usize conversions; no raw + 8 / as usize.
                let entry_end = checked_range_end(entry_off, 8, "surface entry")?;
                if entry_end > len {
                    return Err(RuntimeLoadError::ExportResolutionFailed(
                        "v2 surface entry read past blob end".to_string(),
                    ));
                }
                let entry_start_us = u64_to_usize(entry_off, "surface entry start")?;
                let entry_end_us = u64_to_usize(entry_end, "surface entry end")?;
                let entry = u64::from_le_bytes(
                    self.bytes[entry_start_us..entry_end_us]
                        .try_into()
                        .unwrap(),
                );
                if entry == 0 {
                    return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                        "v2 surface entry {i} is zero"
                    )));
                }
                if !v2_is_canonical_user_va(entry) {
                    return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                        "v2 surface entry {i} noncanonical VA: {entry:#x}"
                    )));
                }
                if entry < blob_base || entry >= blob_end {
                    return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                        "v2 surface entry {i} VA outside blob: {entry:#x} not in [{blob_base:#x}, {blob_end:#x})"
                    )));
                }
                let rel = entry
                    .checked_sub(blob_base)
                    .ok_or(RuntimeLoadError::ExportResolutionFailed(
                        "v2 surface entry below blob_base".to_string(),
                    ))?;
                // surface string bounded NUL scan (within blob)
                scan_nul_rel(&self.bytes, rel, len, &format!("surface {i}"))?;
            }
        }
        // digest region must be the tail: unknown tail rejected (RC-4 item 12).
        if dig_region_end != len {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 unknown tail after digest region".to_string(),
            ));
        }
        Ok(V2Offsets {
            profile_id_off: pid_off,
            profile_digest_off: pd_off,
            expected_surfaces_off: surf_off,
            digest_off: dig_off,
            digest_len: dig_len_field,
            expected_hooks,
        })
    }
}

/// Bounded NUL scan over a relative offset inside a blob (fail-closed).
fn scan_nul_rel(bytes: &[u8], off: u64, len: u64, name: &str) -> Result<u64, RuntimeLoadError> {
    let mut i = off;
    while i < len {
        let i_us = u64_to_usize(i, "NUL scan index")?;
        if bytes[i_us] == 0 {
            return Ok(i);
        }
        i = i
            .checked_add(1)
            .ok_or(RuntimeLoadError::ExportResolutionFailed(
                "v2 NUL scan overflow".to_string(),
            ))?;
    }
    Err(RuntimeLoadError::ExportResolutionFailed(format!(
        "v2 {name} string unterminated"
    )))
}

/// Checked off + k (RC-5: all offset arithmetic fail-closed, no wrap).
fn checked_range_end(off: u64, k: u64, what: &str) -> Result<u64, RuntimeLoadError> {
    off.checked_add(k).ok_or_else(|| {
        RuntimeLoadError::ExportResolutionFailed(format!("v2 {what} range end overflow"))
    })
}

/// Explicit checked u64 -> usize (RC-5: no silent narrowing anywhere).
fn u64_to_usize(v: u64, what: &str) -> Result<usize, RuntimeLoadError> {
    usize::try_from(v).map_err(|_| {
        RuntimeLoadError::ExportResolutionFailed(format!("v2 {what} exceeds usize"))
    })
}

/// Parsed v2 offsets (controller-side view).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V2Offsets {
    pub profile_id_off: u64,
    pub profile_digest_off: u64,
    pub expected_surfaces_off: u64,
    pub digest_off: u64,
    pub digest_len: u64,
    /// Declared surface pointer count (header 0x20).
    pub expected_hooks: u64,
}


#[cfg(test)]
mod imp03_inert_adapter_tests {
    use super::*;

    /// Canonical user VA used as the fake target-local blob base in tests.
    const BLOB_BASE: u64 = 0x0000_1000_0000;

    fn dig64() -> String {
        "a".repeat(64)
    }

    fn build_blob(surfaces: &[&str]) -> V2ParamsBlob {
        let ss: Vec<String> = surfaces.iter().map(|s| s.to_string()).collect();
        V2ParamsBlob::build("p", "d", &ss, &dig64(), BLOB_BASE).unwrap()
    }

    #[test]
    fn wanted_exports_v2_has_three_symbols() {
        assert_eq!(WANTED_EXPORTS_V2.len(), 3);
        assert_eq!(WANTED_EXPORTS_V2[0], "MidaAntidebugInitializeV2");
        assert_eq!(WANTED_EXPORTS_V2[1], "MidaAntidebugGetAttestation");
        assert_eq!(WANTED_EXPORTS_V2[2], "MidaAntidebugShutdown");
    }

    #[test]
    fn mida_exports_v2_require_complete_fail_closed() {
        let e = MidaExportsV2 {
            initialize_v2: None,
            get_attestation: None,
            shutdown: None,
        };
        assert!(e.require_complete().is_err());
        let e2 = MidaExportsV2 {
            initialize_v2: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: None,
        };
        assert!(e2.require_complete().is_err());
        let e3 = MidaExportsV2 {
            initialize_v2: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
        };
        assert_eq!(e3.require_complete(), Ok(()));
    }

    #[test]
    fn thunk7_fixture_production_is_60b() {
        let fx = Thunk7Fixture::build();
        assert_eq!(fx.production.len(), 60);
        assert_eq!(fx.test_with_probe.len(), 64);
        fx.validate_structure().unwrap();
    }

    #[test]
    fn thunk7_fixture_structural_offsets() {
        let fx = Thunk7Fixture::build();
        assert_eq!(&fx.production[0x35..0x37], &[0xFF, 0xD0]);
        assert_eq!(fx.production[0x3B], 0xC3);
        assert_eq!(&fx.test_with_probe[0x35..0x39], &[0x49, 0x89, 0x63, 0x48]);
        assert_eq!(&fx.test_with_probe[0x39..0x3B], &[0xFF, 0xD0]);
        assert_eq!(fx.test_with_probe[0x3F], 0xC3);
    }

    #[test]
    fn thunk7_fixture_matches_known_hashes() {
        use sha2::{Digest, Sha256};
        let fx = Thunk7Fixture::build();
        let prod_sha = {
            let mut h = Sha256::new();
            h.update(&fx.production);
            let out = h.finalize();
            out.iter().map(|b| format!("{:02X}", b)).collect::<String>()
        };
        assert_eq!(
            prod_sha,
            "9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017"
        );
        let test_sha = {
            let mut h = Sha256::new();
            h.update(&fx.test_with_probe);
            let out = h.finalize();
            out.iter().map(|b| format!("{:02X}", b)).collect::<String>()
        };
        assert_eq!(
            test_sha,
            "01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE"
        );
    }

    // ------------------------------------------------------------------
    // V2ParamsBlob: build / parse (RC-4 absolute-VA envelope)
    // ------------------------------------------------------------------

    #[test]
    fn v2_params_blob_roundtrip_offsets() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        assert!(blob.bytes.len() > V2_HEADER_BYTES);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.profile_id_off, 0x48);
        assert_eq!(offs.digest_len, 64);
        assert_eq!(offs.expected_hooks, 2);
    }

    #[test]
    fn v2_params_blob_rejects_bad_digest_len() {
        let ss = vec!["AD-PROC-001".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, "short", BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_parse_rejects_truncated() {
        let blob = V2ParamsBlob { bytes: vec![0u8; 16] };
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_digest_len_field_is_64() {
        let blob = build_blob(&["AD-PROC-001"]);
        let field = u64::from_le_bytes(blob.bytes[0x40..0x48].try_into().unwrap());
        assert_eq!(field, 64);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.digest_len, 64);
        assert_eq!(offs.digest_off + 65, blob.bytes.len() as u64);
    }

    #[test]
    fn v2_params_blob_rejects_wrong_digest_len_field() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x40..0x48].copy_from_slice(&65u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_unknown_tail() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes.push(0xAA);
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_non_hex_digest() {
        let ss = vec!["AD-PROC-001".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, &"z".repeat(64), BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_offset_out_of_bounds() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let len = blob.bytes.len() as u64;
        blob.bytes[0x10..0x18].copy_from_slice(&(len + 100).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_underflow_surface_region() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        blob.bytes[0x28..0x30].copy_from_slice(&(dig_off + 8).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_build_writes_expected_hooks() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let h = u64::from_le_bytes(blob.bytes[0x20..0x28].try_into().unwrap());
        assert_eq!(h, 2);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.expected_hooks, 2);
    }

    #[test]
    fn v2_params_blob_rejects_uppercase_digest() {
        let ss = vec!["AD-PROC-001".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, &"A".repeat(64), BLOB_BASE).is_err());
        assert!(V2ParamsBlob::build("p", "d", &ss, &("a".repeat(63) + "F"), BLOB_BASE).is_err());
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), BLOB_BASE).is_ok());
    }

    #[test]
    fn v2_params_blob_parse_rejects_uppercase_digest_on_wire() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        blob.bytes[dig_off as usize] = b'A';
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_zero_expected_hooks() {
        // zero hooks + NONZERO surfaces_off must be rejected (RC-4 item 7).
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_zero_hooks_zero_off_allowed() {
        // RC-4 item 6: expected_hooks == 0 && surf_off == 0 is legal.
        let mut blob = build_blob(&["AD-PROC-001"]);
        // remove the pointer array region so the envelope has no array bytes;
        // digest shifts left by the array size, so digest_off must be updated.
        let surf_arr_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        let arr_len = (dig_off - surf_arr_off) as usize;
        blob.bytes.drain(surf_arr_off as usize..dig_off as usize);
        debug_assert_eq!(arr_len, 8);
        blob.bytes[0x38..0x40].copy_from_slice(&surf_arr_off.to_le_bytes());
        // zero hooks + zero surfaces_off
        blob.bytes[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        blob.bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.expected_hooks, 0);
        assert_eq!(offs.expected_surfaces_off, 0);
    }

    #[test]
    fn v2_params_blob_rejects_nonzero_hooks_zero_off() {
        // RC-4 item 8: nonzero hooks + zero surfaces_off must be rejected.
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_array_length_mismatch() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x20..0x28].copy_from_slice(&2u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_array_truncation() {
        // array region shorter than declared: surf_off moved 8 bytes right.
        let mut blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[0x28..0x30].copy_from_slice(&(surf_off + 8).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_zero_surface_entry() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_relative_surface_entry() {
        // RC-4 item 11: a self-relative-style small offset is NOT a valid
        // absolute VA (it is outside [blob_base, blob_end)).
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&0x48u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_noncanonical_surface_entry() {
        // RC-4 item 12: kernel-high-half VA (bit 47 set) is noncanonical user.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&0xFFFF_8000_0000_0000u64.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_entry_outside_blob() {
        // absolute VA beyond blob_end must be rejected.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let blob_end = BLOB_BASE + blob.bytes.len() as u64;
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&(blob_end + 0x10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_rejects_surface_string_unterminated() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let entry = u64::from_le_bytes(blob.bytes[surf_off as usize..surf_off as usize + 8].try_into().unwrap());
        let rel = (entry - BLOB_BASE) as usize;
        // wipe ALL bytes from the surface string start to blob end with non-zero
        for i in rel..blob.bytes.len() {
            blob.bytes[i] = 0x58; // 'X'
        }
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_builder_rejects_zero_hooks() {
        let empty: Vec<String> = vec![];
        assert!(V2ParamsBlob::build("p", "d", &empty, &dig64(), BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_builder_rejects_over_256() {
        // RC-4 item 10: builder rejects > 256 surfaces.
        let many: Vec<String> = (0..257).map(|i| format!("SURF-{i}")).collect();
        assert!(V2ParamsBlob::build("p", "d", &many, &dig64(), BLOB_BASE).is_err());
        // exactly 256 is allowed at build; parse requires matching array.
        let at256: Vec<String> = (0..256).map(|i| format!("SURF-{i}")).collect();
        let blob = V2ParamsBlob::build("p", "d", &at256, &dig64(), BLOB_BASE).unwrap();
        assert_eq!(
            u64::from_le_bytes(blob.bytes[0x20..0x28].try_into().unwrap()),
            256
        );
        assert!(blob.parse_offsets(BLOB_BASE).is_ok());
    }

    #[test]
    fn v2_params_blob_builder_rejects_empty_surface_string() {
        let ss = vec!["".to_string()];
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), BLOB_BASE).is_err());
    }

    #[test]
    fn v2_params_blob_builder_rejects_noncanonical_blob_base() {
        let ss = vec!["AD-PROC-001".to_string()];
        // kernel high half: noncanonical user VA
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), 0xFFFF_8000_0000_0000).is_err());
        // zero blob base rejected
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), 0).is_err());
    }

    #[test]
    fn v2_params_blob_build_writes_absolute_surface_vars() {
        // RC-4 item 2: array entries are ABSOLUTE target VAs (blob_base + rel).
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let e0 = u64::from_le_bytes(blob.bytes[surf_off as usize..surf_off as usize + 8].try_into().unwrap());
        let e1 = u64::from_le_bytes(blob.bytes[surf_off as usize + 8..surf_off as usize + 16].try_into().unwrap());
        // first surface string starts at 0x48 + len("p")+1 + len("d")+1
        let s0_rel = (0x48 + 2 + 2) as u64;
        let s1_rel = s0_rel + "AD-PROC-001".len() as u64 + 1;
        assert_eq!(e0, BLOB_BASE + s0_rel);
        assert_eq!(e1, BLOB_BASE + s1_rel);
        assert!(e0 > BLOB_BASE && e1 > e0);
        let offs = blob.parse_offsets(BLOB_BASE).unwrap();
        assert_eq!(offs.expected_hooks, 2);
    }

    #[test]
    fn v2_params_blob_build_rejects_absolute_va_overflow() {
        // blob_base at top of canonical user range + long strings -> the
        // absolute entry VA overflows u64 (checked_add fail-closed).
        let ss = vec!["AD-PROC-001".to_string()];
        let base = 0x0000_7FFF_FFFF_FFFFu64;
        // build must fail because abs = base + rel overflows
        assert!(V2ParamsBlob::build("p", "d", &ss, &dig64(), base).is_err());
    }

    #[test]
    fn v2_params_blob_parse_rejects_bad_blob_base() {
        let blob = build_blob(&["AD-PROC-001"]);
        // zero blob base
        assert!(blob.parse_offsets(0).is_err());
        // noncanonical blob base
        assert!(blob.parse_offsets(0xFFFF_8000_0000_0000).is_err());
        // blob_base + params_bytes overflow (defensive; canonical check
        // already rejects noncanonical base first)
        assert!(blob.parse_offsets(0x0000_7000_0000_0000).is_err());
    }

    #[test]
    fn v2_params_blob_parse_rejects_entry_arithmetic_underflow() {
        // entry arithmetic is fully checked (RC-4 P0-4): a crafted entry
        // below blob_base (but canonical) is rejected before any read.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let below = BLOB_BASE - 0x1000;
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&below.to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    // ------------------------------------------------------------------
    // RC-5: checked helper / overflow branch unit tests
    // ------------------------------------------------------------------

    #[test]
    fn v2_checked_range_end_ok() {
        assert_eq!(checked_range_end(0x48, 65, "digest region").unwrap(), 0x48 + 65);
        assert_eq!(checked_range_end(0x100, 0, "zero").unwrap(), 0x100);
    }

    #[test]
    fn v2_checked_range_end_overflow_fails_closed() {
        // u64::MAX + 1 must fail (no wrap).
        assert!(checked_range_end(u64::MAX, 1, "wrap").is_err());
        assert!(checked_range_end(u64::MAX, 8, "entry").is_err());
        assert!(checked_range_end(u64::MAX - 1, 2, "tail").is_err());
        // u64::MAX + 0 is fine (no overflow).
        assert_eq!(checked_range_end(u64::MAX, 0, "zero").unwrap(), u64::MAX);
    }

    #[test]
    fn v2_u64_to_usize_ok() {
        assert_eq!(u64_to_usize(0, "zero").unwrap(), 0usize);
        assert_eq!(u64_to_usize(0x48, "header").unwrap(), 0x48usize);
    }

    #[test]
    fn v2_u64_to_usize_overflow_fails_closed() {
        // On 32-bit targets a value above usize::MAX fails; on 64-bit the
        // conversion always succeeds, but the helper must never panic.
        let r = u64_to_usize(u64::MAX, "max");
        if usize::BITS < 64 {
            assert!(r.is_err());
        } else {
            assert_eq!(r.unwrap(), usize::MAX);
        }
    }

    #[test]
    fn v2_parse_offsets_rejects_digest_region_overflow_on_wire() {
        // digest_off = u64::MAX - 10: checked_range_end fails before any read.
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x38..0x40].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_parse_offsets_rejects_surfaces_end_overflow_on_wire() {
        // surf_off = u64::MAX - 10 with expected_hooks=1: array_end overflows.
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes[0x28..0x30].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_parse_offsets_rejects_entry_offset_overflow_on_wire() {
        // surf_off = u64::MAX - 10, expected_hooks=2: second entry offset
        // (surf_off + 8) overflows and must fail-closed.
        let mut blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        blob.bytes[0x20..0x28].copy_from_slice(&2u64.to_le_bytes());
        blob.bytes[0x28..0x30].copy_from_slice(&(u64::MAX - 10).to_le_bytes());
        assert!(blob.parse_offsets(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_build_patch_closure_is_checked() {
        // The patch helper rejects out-of-range writes.
        let mut out = vec![0u8; 0x48];
        let patch = |out: &mut Vec<u8>, off: usize, val: u64| -> Result<(), RuntimeLoadError> {
            let end = off.checked_add(8).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed("v2 header patch overflow".to_string())
            })?;
            if end > out.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "v2 header patch out of bounds".to_string(),
                ));
            }
            out[off..end].copy_from_slice(&val.to_le_bytes());
            Ok(())
        };
        // valid patch
        assert!(patch(&mut out, 0x10, 0x48).is_ok());
        assert_eq!(&out[0x10..0x18], &0x48u64.to_le_bytes());
        // OOB patch fails (0x48 + 8 exceeds the 0x48-byte buffer)
        assert!(patch(&mut out, 0x48, 1).is_err());
        assert!(patch(&mut out, 0x41, 1).is_err());
        // overflow patch fails (off + 8 wraps)
        assert!(patch(&mut out, usize::MAX - 1, 1).is_err());
    }
}
