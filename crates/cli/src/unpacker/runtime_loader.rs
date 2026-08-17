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

/// Loader errors (all fail-closed).
#[derive(Debug, Clone, thiserror::Error)]
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

    /// Execute a function by address in the target via a remote thread.
    ///
    /// # Safety
    /// `remote_fn` must be a valid function pointer in the TARGET address
    /// space (x64: same base as debugger). `arg` is a pointer to argument
    /// memory previously written into the target.
    unsafe fn remote_call_raw(
        &self,
        target: HANDLE,
        remote_fn: usize,
        arg: usize,
    ) -> Result<RemoteCallResult, RuntimeLoadError> {
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
            Ok(t) => t,
            Err(e) => {
                return Err(RuntimeLoadError::RemoteThreadFailed(format!(
                    "CreateRemoteThread: {e}"
                )));
            }
        };
        // Bounded wait (10s) for the remote call to finish.
        let wait = unsafe { WaitForSingleObject(thread, 10_000) }.0;
        if wait != 0 {
            let _ = unsafe { CloseHandle(thread) };
            return Err(RuntimeLoadError::RemoteCallFailed(format!(
                "WaitForSingleObject returned {wait:#x}"
            )));
        }
        let mut code: u32 = 0;
        let gc = unsafe { GetExitCodeThread(thread, &mut code) };
        if gc.is_err() {
            let _ = unsafe { CloseHandle(thread) };
            return Err(RuntimeLoadError::RemoteCallFailed(
                "GetExitCodeThread failed".to_string(),
            ));
        }
        let _ = unsafe { CloseHandle(thread) };
        Ok(RemoteCallResult { exit_code: code })
    }

    /// Allocate executable memory in the target, write thunk + args, run.
    ///
    /// # Safety
    /// `target` must be a valid process handle; `args.fn_ptr` must be a
    /// valid code address in the target address space.
    unsafe fn thunk_call(
        &self,
        target: HANDLE,
        args: &ThunkArgs,
    ) -> Result<RemoteCallResult, RuntimeLoadError> {
        // 1. Allocate executable-capable memory for thunk + args (128 bytes).
        let remote =
            unsafe { VirtualAllocEx(target, None, 128, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };
        if remote.is_null() {
            return Err(RuntimeLoadError::VirtualAllocFailed(
                "VirtualAllocEx(thunk)".to_string(),
            ));
        }
        // 2. Write thunk at [0..64), args at [64..128).
        let mut blob = [0u8; 128];
        blob[0..64].copy_from_slice(&THUNK_CODE);
        blob[64..128].copy_from_slice(&args.as_bytes());
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
            return Err(RuntimeLoadError::WriteMemoryFailed(format!(
                "WriteProcessMemory(thunk): {:?}",
                w.err()
            )));
        }
        // 3. Make executable.
        let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
        let vp = unsafe {
            VirtualProtectEx(
                target,
                remote,
                128,
                PAGE_EXECUTE_READWRITE,
                &mut old as *mut _ as *mut windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS,
            )
        };
        if vp.is_err() {
            let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::RemoteCallFailed(format!(
                "VirtualProtectEx(thunk): {:?}",
                vp.err()
            )));
        }
        // 4. Run: CreateRemoteThread(remote thunk, arg = remote + 64).
        let thunk_addr = remote as usize;
        let args_addr = remote as usize + 64;
        let result = unsafe { self.remote_call_raw(target, thunk_addr, args_addr) };
        let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
        result
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

        // 2. LoadLibraryW via remote thread (x64: same kernel32 base).
        let load_addr = Self::kernel32_load_library_w()?;
        let load_result = unsafe { self.remote_call_raw(target, load_addr, remote_path as usize) }?;
        let module_base = load_result.exit_code as usize;
        if module_base == 0 {
            let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
            return Err(RuntimeLoadError::ModuleBaseNotFound(format!(
                "LoadLibraryW returned 0 (load failed in target)"
            )));
        }

        // 3. Resolve the MIDA exports.
        let exports = self.resolve_mida_exports(module_base)?;

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
        let init_result = unsafe { self.thunk_call(target, &init_args) }?;
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
    /// Resolve the MIDA C ABI exports from the loaded module.
    fn resolve_mida_exports(&self, module_base: usize) -> Result<MidaExports, RuntimeLoadError> {
        use windows::Win32::Foundation::HMODULE;
        use windows::Win32::System::LibraryLoader::GetProcAddress;
        let h = HMODULE(module_base as isize as *mut core::ffi::c_void);
        let init = unsafe { GetProcAddress(h, PCSTR(b"MidaAntidebugInitialize\0".as_ptr())) };
        let get = unsafe { GetProcAddress(h, PCSTR(b"MidaAntidebugGetAttestation\0".as_ptr())) };
        let shut = unsafe { GetProcAddress(h, PCSTR(b"MidaAntidebugShutdown\0".as_ptr())) };
        let (Some(init), Some(get), Some(shut)) = (init, get, shut) else {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "missing export: init={} get={} shut={}",
                init.is_some(),
                get.is_some(),
                shut.is_some()
            )));
        };
        Ok(MidaExports {
            initialize: init as usize,
            get_attestation: get as usize,
            shutdown: shut as usize,
        })
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
        unsafe { self.thunk_call(target, &args) }
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
/// Provenance is read from provenance_ref (relative to the manifest
/// directory). Checks are fail-closed:
/// - provenance.sha256 == runtime file sha256
/// - provenance.size_bytes == runtime file size
/// - provenance.kind == runtime-x64
/// - provenance.architecture == x86_64
/// - provenance.source_ref non-empty
/// - provenance.third_party valid (non-empty declared value)
/// - no dependency declares anti_debug=true
pub fn verify_runtime_provenance(
    manifest: &RuntimeAuthorityManifest,
    manifest_dir: &Path,
    runtime_identity: &RuntimeFileIdentity,
) -> Result<serde_json::Value, RuntimeLoadError> {
    let prov_path = manifest_dir.join(&manifest.provenance_ref);
    let prov_bytes = std::fs::read(&prov_path).map_err(|e| {
        RuntimeLoadError::AuthorityMismatch(format!(
            "provenance unreadable at {}: {e}",
            prov_path.display()
        ))
    })?;
    // deny_unknown_fields: parse into the strict runtime Provenance struct.
    let prov: mida_antidebug_runtime::provenance::Provenance = serde_json::from_slice(&prov_bytes)
        .map_err(|e| RuntimeLoadError::AuthorityMismatch(format!("provenance parse: {e}")))?;
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
    if prov.kind != "runtime-x64" {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance kind {} != runtime-x64",
            prov.kind
        )));
    }
    if prov.architecture != "x86_64" {
        return Err(RuntimeLoadError::ArchitectureUnsupported(
            prov.architecture.clone(),
        ));
    }
    if prov.source_ref.is_empty() {
        return Err(RuntimeLoadError::AuthorityMismatch(
            "provenance source_ref is empty".to_string(),
        ));
    }
    if prov.third_party.is_empty() {
        return Err(RuntimeLoadError::AuthorityMismatch(
            "provenance third_party is empty".to_string(),
        ));
    }
    for d in &prov.dependencies {
        if d.anti_debug {
            return Err(RuntimeLoadError::AuthorityMismatch(format!(
                "provenance dependency {} declares anti_debug=true",
                d.name
            )));
        }
    }
    // Return the raw JSON for evidence.
    Ok(serde_json::from_slice(&prov_bytes)
        .map_err(|e| RuntimeLoadError::AuthorityMismatch(format!("provenance re-parse: {e}")))?)
}

/// Run the full loader sequence against a suspended target and return the
/// controller-facing result. Any failure is fail-closed (Err).
pub fn run_runtime_loader(
    target: HANDLE,
    target_pid: u32,
    profile_id: &str,
    profile_digest: &str,
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
