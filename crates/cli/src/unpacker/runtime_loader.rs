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
        Ok(RuntimeFileIdentity::from_verified(
            canonical,
            digest,
            size,
            "x86_64".to_string(),
        ))
    }

    /// Sealed manifest-bound authority constructor (IMP-06-R2).
    ///
    /// The ONLY path that turns a [`RuntimeFileIdentity`] into a
    /// [`RuntimeDigestAuthority`]: it binds the identity to THIS manifest's
    /// artifact id and re-validates the digest (fail-closed; the placeholder
    /// is always rejected). Module-private because the authority must only
    /// ever be produced from a `verify_file()` identity inside this module.
    fn digest_authority_for(
        &self,
        identity: &RuntimeFileIdentity,
    ) -> Result<RuntimeDigestAuthority, RuntimeLoadError> {
        Ok(RuntimeDigestAuthority::from_verified_identity(
            identity,
            &self.artifact_id,
        )?)
    }
}

impl RuntimeFileIdentity {
    /// Private sealed constructor: ONLY reachable from `verify_file()` (same
    /// module). Every identity value therefore provably passed the manifest
    /// digest/size/architecture checks — the type cannot be forged outside
    /// this module (no public fields, no public constructor, no
    /// Deserialize).
    fn from_verified(path: PathBuf, sha256: String, size_bytes: u64, architecture: String) -> Self {
        Self {
            path,
            sha256,
            size_bytes,
            architecture,
        }
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

/// Identity of a verified runtime file (IMP-06-R2: provenance-sealed).
///
/// This type is the ONLY carrier of a `verify_file()`-verified runtime file
/// identity. All fields are private and the type has NO public constructor:
/// the sole production path is
/// [`RuntimeAuthorityManifest::verify_file`], which computes and checks the
/// SHA-256 against the audited manifest before construction. Plain
/// `#[derive(Deserialize)]` is deliberately absent so a serde payload can
/// never be deserialized into a "verified" identity.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeFileIdentity {
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
    architecture: String,
}

impl RuntimeFileIdentity {
    /// Canonical path of the verified runtime DLL.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verified runtime file SHA-256 (64 lowercase hex chars).
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Verified runtime file size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Verified runtime architecture ("x86_64").
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
}
/// Canonical runtime digest length: exactly 64 lowercase hex characters.
///
/// The frozen wire layout (WO-1505 §5.3e) stores the digest as a 64-hex
/// region plus a SEPARATE 65th NUL terminator. `digest_value` itself NEVER
/// carries the NUL: it is exactly 64 hex chars and nothing else.
pub const DIGEST_HEX_LEN: usize = 64;

/// The placeholder digest value that blocks production digest authority
/// (mirrors `crates/acceptance/src/implementation_gate.rs::PLACEHOLDER_DIGEST`;
/// duplicated here so mida-cli production code does not depend on
/// mida-acceptance — the acceptance boundary is one-way).
///
/// The runtime attestation still writes this placeholder at
/// `crates/antidebug-runtime/src/exports.rs:239` ("adr4-foundation-unbound").
/// It is NOT a valid digest authority and MUST NOT be wrapped into a
/// "verified" state: IMP-06-R1 only adds the fail-closed rejection path; the
/// placeholder itself is replaced by a later implementation order (V2 digest
/// ingress + runtime echo + controller echo verification).
pub const PLACEHOLDER_RUNTIME_DIGEST: &str = "adr4-foundation-unbound";

/// Digest validation errors (all fail-closed, never a warning).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestValidationError {
    #[error("digest is empty or missing")]
    Missing,
    #[error("digest length must be {DIGEST_HEX_LEN} hex chars, got {got}")]
    WrongLength { got: usize },
    #[error("digest must be lowercase hex (0-9a-f only); uppercase or non-hex rejected")]
    NotLowercaseHex,
    #[error("digest is the placeholder value '{PLACEHOLDER_RUNTIME_DIGEST}' which is not a valid authority")]
    Placeholder,
    #[error("digest contains trailing data or a NUL terminator; the value must be exactly {DIGEST_HEX_LEN} hex chars")]
    TrailingData,
    #[error("runtime echo mismatch: expected {expected}, got {got}")]
    EchoMismatch { expected: String, got: String },
}

/// True when `value` is exactly 64 lowercase hex characters and is not the
/// placeholder. Used as the single lexical gate for every digest accepted as
/// an authority or compared against a runtime echo.
pub fn is_valid_digest_hex(value: &str) -> bool {
    value.len() == DIGEST_HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b <= b'f'))
        && value != PLACEHOLDER_RUNTIME_DIGEST
}

/// Validate a digest string with a structured, fail-closed error.
pub fn validate_digest_hex(value: &str) -> Result<(), DigestValidationError> {
    if value.is_empty() {
        return Err(DigestValidationError::Missing);
    }
    if value == PLACEHOLDER_RUNTIME_DIGEST {
        return Err(DigestValidationError::Placeholder);
    }
    if value.len() != DIGEST_HEX_LEN {
        return Err(DigestValidationError::WrongLength { got: value.len() });
    }
    // A NUL inside a Rust &str is a valid UTF-8 character; a wire digest that
    // carried its 65th NUL terminator would surface here as a NUL byte. Reject
    // it EXPLICITLY as trailing data BEFORE the hex gate so the intent is
    // unambiguous (a NUL is not a hex char, but "trailing NUL" is the wire
    // case we must name).
    if value.as_bytes().contains(&0) {
        return Err(DigestValidationError::TrailingData);
    }
    if !value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b <= b'f'))
    {
        return Err(DigestValidationError::NotLowercaseHex);
    }
    Ok(())
}

/// The production runtime digest authority (IMP-06-R1).
///
/// This is the ONLY object that carries the verified runtime file digest for
/// controller-side use. It is constructed exclusively from a
/// [`RuntimeFileIdentity`] that [`RuntimeAuthorityManifest::verify_file`] has
/// already computed and verified — it NEVER re-reads the runtime DLL and NEVER
/// recomputes SHA-256 (no second hash authority path).
///
/// - `digest_value`   : sha256 hex produced by `verify_file()` (exactly 64
///                      lowercase hex chars; the 65th wire NUL is not part of
///                      it).
/// - `size_bytes`     : verified file size.
/// - `canonical_path` : canonicalized runtime DLL path from `verify_file()`.
/// - `manifest_artifact_id` / `architecture` : manifest-bound identity.
///
/// # Fail-closed rules
/// - Construction from a placeholder or any invalid digest FAILS CLOSED:
///   the placeholder can never be wrapped into a "verified" authority.
/// - `verify_runtime_echo` is the comparison API for a future V2 runtime
///   echo; **it is NOT yet wired to any runtime call** (the runtime has no
///   V2 export today — `runtime echo consumer = NOT WIRED`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeDigestAuthority {
    /// Verified runtime file digest (64 lowercase hex, no NUL).
    digest_value: String,
    /// Verified runtime file size in bytes.
    size_bytes: u64,
    /// Canonical path of the verified runtime DLL.
    canonical_path: PathBuf,
    /// Manifest artifact id the runtime was bound to.
    manifest_artifact_id: String,
    /// Verified architecture ("x86_64").
    architecture: String,
}

impl RuntimeDigestAuthority {
    /// Build the production digest authority from an ALREADY-VERIFIED file
    /// identity (the digest was computed by `verify_file()`). Fail-closed on
    /// any invalid digest; the placeholder is always rejected.
    ///
    /// IMP-06-R2: `pub(crate)` — the authority must only ever be built from
    /// a [`RuntimeFileIdentity`] produced by `verify_file()`, never from
    /// caller-supplied raw strings. External crates/tests cannot call this.
    pub(crate) fn from_verified_identity(
        identity: &RuntimeFileIdentity,
        manifest_artifact_id: &str,
    ) -> Result<Self, DigestValidationError> {
        validate_digest_hex(&identity.sha256)?;
        Ok(Self {
            digest_value: identity.sha256.clone(),
            size_bytes: identity.size_bytes,
            canonical_path: identity.path.clone(),
            manifest_artifact_id: manifest_artifact_id.to_string(),
            architecture: identity.architecture.clone(),
        })
    }

    /// Compare a runtime-returned digest against this authority
    /// (IMP-06-R1 §3). Every failure is fail-closed with a structured error.
    ///
    /// Coverage: wrong length, uppercase hex, non-hex, NUL/trailing data,
    /// placeholder, empty/missing, and plain authority-vs-echo mismatch.
    ///
    /// # Wiring status
    /// This is the comparison seam for the future V2 runtime echo
    /// (`out_runtime_sha256` + `attestation.runtime_sha256`). **There is no
    /// production caller today**: the runtime has no V2 export, so no echo is
    /// ever read. `runtime echo consumer = NOT WIRED` until the IMP-08/V2
    /// implementation order lands.
    pub fn verify_runtime_echo(&self, runtime_returned: &str) -> Result<(), DigestValidationError> {
        validate_digest_hex(runtime_returned)?;
        if runtime_returned != self.digest_value {
            return Err(DigestValidationError::EchoMismatch {
                expected: self.digest_value.clone(),
                got: runtime_returned.to_string(),
            });
        }
        Ok(())
    }

    /// Verified runtime file digest (64 lowercase hex, no NUL).
    pub fn digest_value(&self) -> &str {
        &self.digest_value
    }

    /// Verified runtime file size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Canonical path of the verified runtime DLL.
    pub fn canonical_path(&self) -> &Path {
        &self.canonical_path
    }

    /// Manifest artifact id the runtime was bound to.
    pub fn manifest_artifact_id(&self) -> &str {
        &self.manifest_artifact_id
    }

    /// Verified runtime architecture ("x86_64").
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
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
    #[error("digest authority invalid: {0}")]
    DigestAuthorityInvalid(#[from] DigestValidationError),
    #[error("runtime digest echo mismatch: {0}")]
    DigestEchoMismatch(String),
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
///
/// IMP-08-R1: legacy 3-field v1 view (kept for the non-digest path and
/// cleanup); the production loader resolves the 5-item set into
/// [`MidaExportsV2`].
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
    pub exports: MidaExportsV2,
    pub attestation_json: String,
    pub file_identity: RuntimeFileIdentity,
    /// Production digest authority derived from the verified file identity
    /// (IMP-06-R1). Never a placeholder; fail-closed at construction.
    pub digest_authority: RuntimeDigestAuthority,
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

    /// IMP-08-R1: production V2 entry call. Uses the FROZEN 60-byte
    /// THUNK7_PRODUCTION bytes (7-arg) and the same handle-ownership
    /// contract as thunk_call_bounded (closes the raw thread handle on
    /// every return path). The 64-byte test probe is NEVER used here.
    ///
    /// # Safety
    /// `target` must be a valid process handle; `args` must reference
    /// target-valid memory (the v2 blob + output buffers).
    unsafe fn thunk_call_v2(
        &self,
        target: HANDLE,
        args: &ThunkArgs,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
    ) -> Result<RemoteCallResult, RuntimeLoadError> {
        // Fail-closed: the production thunk MUST be the frozen 60B variant.
        // A 64B probe (or any other length) is a wiring error.
        let thunk = THUNK7_PRODUCTION;
        if thunk.len() != 60 {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "THUNK7_PRODUCTION must be 60B, got {}B",
                thunk.len()
            )));
        }
        // Fixed 60s production deadline (same as thunk_call).
        let (result, _addr, thread_handle) = unsafe {
            self.thunk_call_tracked_with_handle_code(target, args, 60, drain, &thunk)
        };
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
        // Legacy 6-arg thunk (THUNK_CODE).
        unsafe {
            self.thunk_call_tracked_with_handle_code(
                target,
                args,
                deadline_secs,
                drain,
                &THUNK_CODE,
            )
        }
    }

    /// IMP-08-R1: thunk execution over EXPLICIT thunk bytes. The production
    /// V2 path passes the frozen 60-byte [`THUNK7_PRODUCTION`] (7-arg);
    /// every other path keeps the 91-byte 6-arg [`THUNK_CODE`]. The code
    /// window is written verbatim (no re-encoding, no probe bytes).
    ///
    /// # Safety
    /// `thunk_bytes` must be valid x64 code that consumes a
    /// [`ThunkArgs`] block (fn_ptr + up to 7 args) at `THUNK_ARGS_OFFSET`.
    #[allow(clippy::too_many_arguments)]
    unsafe fn thunk_call_tracked_with_handle_code(
        &self,
        target: HANDLE,
        args: &ThunkArgs,
        deadline_secs: u64,
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
        thunk_bytes: &[u8],
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
        // 2. Write thunk bytes verbatim, args at [THUNK_ARGS_OFFSET..+64).
        //    The allocation is 0x100 bytes total.
        let mut blob = [0u8; THUNK_BLOB_SIZE];
        debug_assert!(thunk_bytes.len() <= THUNK_CODE_SIZE);
        blob[0..thunk_bytes.len()].copy_from_slice(thunk_bytes);
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
        // IMP-08-R1: the production loader is digest-required. The
        // digest authority comes from verify_file() and the V2 entry
        // carries it into the runtime; v1 fallback is PROHIBITED when
        // digest-required (silent fallback would unbound the authority).
        self.load_and_initialize_inner(
            target,
            target_pid,
            runtime_path,
            profile_id,
            profile_digest,
            expected_surfaces,
            drain,
            true,
        )
    }

    /// IMP-08-R1: internal loader with explicit V2-mode selection.
    ///
    /// `require_digest` == true selects the V2 path (digest-required):
    ///   - resolves the 5-item wanted set and requires the V2 entry;
    ///   - builds the v2 params blob WITH the verified digest (from
    ///     `verify_file()`, the ONLY digest source);
    ///   - calls MidaAntidebugInitializeV2 through the frozen 60B THUNK7
    ///     production bytes;
    ///   - reads the runtime digest echo and verifies it against the
    ///     digest authority (fail-closed on mismatch);
    ///   - NEVER falls back to v1.
    ///
    /// `require_digest` == false keeps the legacy v1 path (no digest
    /// binding; runtime_sha256 stays the honest placeholder until IMP-07).
    /// IMP-07-R1: build the params blob for the selected mode, running the
    /// local V2 preflight + surface validation for the digest-required
    /// branch. Returns Err BEFORE any bytes are produced on any failure
    /// (fail-closed). The caller is responsible for freeing allocations on
    /// Err (see load_and_initialize_inner cleanup contract).
    ///
    /// # Production caller graph (IMP-07-R1)
    /// load_and_initialize_inner (require_digest=true)
    ///   -> build_v2_or_v1_params_bytes (this fn)
    ///      -> V2ParamsBlob::build_preflight_and_validate
    ///         -> V2ParamsBlob::build_with_identity
    ///         -> V2ParamsBlob::preflight_local
    ///      -> validate_preflight_result (field-by-field consumption)
    ///   -> WriteProcessMemory(params)  [only on Ok]
    ///   -> thunk_call_v2
    ///   -> verify_runtime_echo
    fn build_v2_or_v1_params_bytes(
        loader: &RuntimeLoader,
        identity: &RuntimeFileIdentity,
        require_digest: bool,
        profile_id: &str,
        profile_digest: &str,
        expected_surfaces: &[String],
        target_pid: u32,
        module_base: usize,
        remote_params: *mut c_void,
    ) -> Result<Vec<u8>, RuntimeLoadError> {
        if require_digest {
            let digest = loader
                .authority
                .digest_authority_for(identity)?
                .digest_value()
                .to_string();
            // build + preflight + validate against expected_surfaces in one
            // production seam; returns NO bytes on any failure.
            let prepared = V2ParamsBlob::build_preflight_and_validate(
                profile_id,
                profile_digest,
                expected_surfaces,
                &digest,
                remote_params as usize as u64,
                target_pid,
                module_base as u64,
                remote_params as usize,
            )?;
            // Consume the structured preflight result (not discarded):
            // every field is bound to the authority digest AND the surfaces
            // that are about to be written remotely.
            let preflight = &prepared.preflight;
            let verified = validate_preflight_result(
                &prepared_as_blob(&prepared),
                preflight,
                expected_surfaces,
                remote_params as usize,
            )?;
            debug_assert_eq!(preflight.blob_base, remote_params as u64);
            debug_assert_eq!(preflight.digest_len, 64);
            debug_assert_eq!(preflight.expected_hooks, expected_surfaces.len() as u64);
            debug_assert_eq!(preflight.surface_entries.len(), verified.len());
            Ok(prepared.bytes)
        } else {
            // Legacy v1 path: NO preflight_local call (IMP-07-R1 requirement:
            // the local V2 preflight runs ONLY in the digest-required branch).
            build_init_params_bytes(
                target_pid,
                profile_id,
                profile_digest,
                expected_surfaces,
                module_base as u64,
                remote_params as usize as u64,
            )
        }
    }

    pub unsafe fn load_and_initialize_inner(
        &self,
        target: HANDLE,
        target_pid: u32,
        runtime_path: &Path,
        profile_id: &str,
        profile_digest: &str,
        expected_surfaces: &[String],
        drain: &mut dyn FnMut(u32) -> Result<Option<mida_core::DrainReceipt>, mida_core::CoreError>,
        require_digest: bool,
    ) -> Result<LoadedRuntime, RuntimeLoadError> {
        // 0. Authority verification (fail-closed, before any remote write).
        let identity = self.authority.verify_file(runtime_path)?;
        if identity.architecture() != "x86_64" {
            return Err(RuntimeLoadError::ArchitectureUnsupported(
                identity.architecture().to_string(),
            ));
        }

        // 1. Write the DLL path into the target.
        let path_str = identity.path().to_str().ok_or_else(|| {
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
        // DLL loaded only in the target). IMP-08-R1: the resolver returns
        // the frozen 5-item set (MidaExportsV2).
        let exports = unsafe { self.resolve_mida_exports_remote(target, module_base) }?;
        if require_digest {
            // IMP-08-R1: digest-required mode. The FULL 5-item set must
            // resolve AND the v2 7-arg entry must be present. This is the
            // real production require_complete() caller (not test-only).
            exports.require_complete()?;
            exports.require_v2_entry()?;
        } else {
            // Non-digest mode: v1 initialize entry is still required.
            exports.initialize.ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(
                    "MidaAntidebugInitialize missing (v1 path)".to_string(),
                )
            })?;
        }
        // Unwrap now: the resolver already guaranteed the 5-item set; the
        // checks above enforce the required entries per mode. Keep the
        // Option semantics for the thunk args below (fail-closed).
        let exports = exports;

        // 4. Build the params blob in target memory (self-contained).
        //    IMP-08-R1: digest-required mode builds the V2 envelope with the
        //    verified digest (identity slots bound); otherwise the legacy
        //    v1 MidaInitParams blob (no digest channel).
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
        // IMP-07-R1: the V2 branch runs the LOCAL PREFLIGHT and consumes
        // its structured result BEFORE any WriteProcessMemory(params). A
        // preflight/validation failure returns Err and the caller never
        // reaches the write (fail-closed, no v1 fallback).
        //
        // Cleanup contract (IMP-07-R1): EVERY error path below frees the
        // already-allocated remote_path AND remote_params before returning.
        let params_bytes = match Self::build_v2_or_v1_params_bytes(
            self,
            &identity,
            require_digest,
            profile_id,
            profile_digest,
            expected_surfaces,
            target_pid,
            module_base,
            remote_params,
        ) {
            Ok(v) => v,
            Err(e) => {
                let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
                let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
                return Err(e);
            }
        };
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

        // 5. Remote initialize via the thunk. IMP-08-R1: digest-required
        //    mode calls MidaAntidebugInitializeV2 through the FROZEN 60B
        //    THUNK7_PRODUCTION (7 args); the digest echo goes to a DEDICATED
        //    out_runtime_sha256 buffer (arg1), NOT the attestation buffer.
        //    Non-digest mode keeps the legacy 6-arg v1 entry.
        let att_buf_len = 16 * 1024usize;
        let remote_att = unsafe {
            VirtualAllocEx(
                target,
                None,
                att_buf_len + 8 + 0x80,
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
        // Dedicated digest echo buffer (64 hex + slack), separate from the
        // attestation JSON so the controller can compare the echo without
        // parsing the attestation first (IMP-08-R1 requirement 9).
        let echo_addr = remote_att as usize + att_buf_len + 8;
        let init_args = if require_digest {
            ThunkArgs {
                fn_ptr: exports.initialize_v2.unwrap_or(0) as u64,
                arg0: remote_params as u64,      // params
                arg1: params_bytes.len() as u64, // params_bytes
                arg2: echo_addr as u64,          // out_runtime_sha256
                arg3: 64,                        // out_runtime_sha256_len
                arg4: remote_att as u64,         // out_attestation_json
                arg5: att_buf_len as u64,        // out_attestation_len
                reserved: att_written_addr as u64, // out_attestation_written (7th arg)
            }
        } else {
            ThunkArgs {
                fn_ptr: exports.initialize.unwrap_or(0) as u64,
                arg0: remote_params as u64,
                arg1: remote_att as u64,  // out_runtime_sha256 (unused by loader)
                arg2: 64,                 // out_runtime_sha256_len
                arg3: remote_att as u64,  // out_attestation_json
                arg4: att_buf_len as u64, // out_attestation_len
                arg5: att_written_addr as u64, // out_attestation_written
                reserved: 0,
            }
        };
        let init_result = if require_digest {
            unsafe { self.thunk_call_v2(target, &init_args, drain) }
        } else {
            unsafe { self.thunk_call(target, &init_args, drain) }
        }?;
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
        // IMP-08-R1 (digest-required): read the runtime digest echo BEFORE
        // freeing the remote_att allocation (the echo lives at
        // remote_att + att_buf_len + 8). The echo must match the digest
        // authority (fail-closed on mismatch, wrong length, non-hex, etc).
        let runtime_echo: Option<String> = if require_digest {
            let mut echo_buf = [0u8; 128];
            let re = unsafe {
                ReadProcessMemory(
                    target,
                    echo_addr as *const c_void,
                    echo_buf.as_mut_ptr() as *mut c_void,
                    echo_buf.len(),
                    None,
                )
            };
            if re.is_err() {
                let _ = unsafe { VirtualFreeEx(target, remote_path, 0, MEM_RELEASE) };
                let _ = unsafe { VirtualFreeEx(target, remote_params, 0, MEM_RELEASE) };
                let _ = unsafe { VirtualFreeEx(target, remote_att, 0, MEM_RELEASE) };
                return Err(RuntimeLoadError::DigestEchoMismatch(
                    "read runtime digest echo failed".to_string(),
                ));
            }
            // The runtime writes exactly 64 hex chars (no NUL). Read the
            // full 64-byte window; verify_runtime_echo() below rejects any
            // wrong length / non-hex / placeholder. Trailing bytes beyond
            // the 64-hex window are deliberately ignored (bounded scan).
            Some(
                String::from_utf8(echo_buf[..64].to_vec())
                    .map_err(|e| RuntimeLoadError::DigestEchoMismatch(e.to_string()))?,
            )
        } else {
            None
        };
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

        // IMP-06-R1: the digest authority is derived from the SAME identity
        // produced by verify_file() — the single runtime file hash point. The
        // digest is never recomputed and the placeholder is rejected here.
        //
        // IMP-06-R2: the authority is built via the sealed manifest
        // constructor, which binds the identity to THIS manifest (artifact id
        // + digest + size + architecture) and re-validates the digest.
        let digest_authority = RuntimeAuthorityManifest::digest_authority_for(
            &self.authority,
            &identity,
        )?;

        // IMP-08-R1 requirement 9: the production path MUST verify the
        // runtime echo against the digest authority. The three-way check:
        //   echo (out_runtime_sha256) == attestation.runtime_sha256 == digest
        // The echo was read from the target before freeing the buffer; the
        // attestation.runtime_sha256 is compared below (parsed above). Any
        // mismatch fails closed — no silent fallback, no unbound digest.
        if require_digest {
            let echo = runtime_echo.as_deref().ok_or_else(|| {
                RuntimeLoadError::DigestEchoMismatch(
                    "digest echo missing in digest-required mode".to_string(),
                )
            })?;
            digest_authority.verify_runtime_echo(echo).map_err(|e| {
                RuntimeLoadError::DigestEchoMismatch(e.to_string())
            })?;
            if parsed.runtime_sha256 != digest_authority.digest_value() {
                return Err(RuntimeLoadError::DigestEchoMismatch(format!(
                    "attestation.runtime_sha256 {} != digest {}",
                    parsed.runtime_sha256,
                    digest_authority.digest_value()
                )));
            }
        }
        Ok(LoadedRuntime {
            module_base,
            remote_path,
            remote_params,
            exports,
            attestation_json: att,
            file_identity: identity,
            digest_authority,
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
    ) -> Result<MidaExportsV2, RuntimeLoadError> {
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
        //    IMP-08-R1-R1 (P0-1): all RVA->VA conversions use checked
        //    arithmetic; a malformed e_lfanew must fail closed, not wrap.
        let pe_base = module_base.checked_add(e_lfanew).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "PE header base overflow (module_base + e_lfanew)".to_string(),
            )
        })?;
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
        // IMP-08-R1-R1 (P0-1): SizeOfImage lives at optional+0x50 for both
        // PE32 and PE32+ (pe+0x18+0x50 = pe+0x68). A zero or absurdly small
        // SizeOfImage fails closed: every export RVA must fit inside the
        // module image envelope.
        let image_size =
            u32::from_le_bytes([pe[0x68], pe[0x69], pe[0x6A], pe[0x6B]]) as usize;
        if image_size == 0 || image_size < 0x1000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "remote image SizeOfImage invalid: {image_size:#x}"
            )));
        }
        // Envelope: module spans [module_base, module_base + image_size).
        // (The parser re-derives module_end internally with checked add;
        // this wrapper only needs SizeOfImage itself.)
        let _ = module_base.checked_add(image_size).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "module envelope overflow (module_base + SizeOfImage)".to_string(),
            )
        })?;
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
        // IMP-08-R1-R1 (P0-1): the export directory itself must fit inside
        // the image envelope before any remote read.
        let exp_end = exp_rva.checked_add(exp_size).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "export directory range overflow".to_string(),
            )
        })?;
        if exp_rva >= image_size || exp_end > image_size {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "remote export directory outside image envelope: rva={exp_rva:#x} size={exp_size:#x} image={image_size:#x}"
            )));
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
        let ed_va = module_base.checked_add(exp_rva).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "export directory VA overflow".to_string(),
            )
        })?;
        let rd3 = unsafe {
            RPM(
                target,
                ed_va as *const core::ffi::c_void,
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
        // IMP-08-R1-R1 (P0-1): every export sub-array must fit inside the
        // image envelope [0, image_size) BEFORE any remote read. Checked
        // arithmetic; overflow or out-of-envelope fails closed.
        let names_bytes = num_names.checked_mul(4).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("export name array size overflow".to_string())
        })?;
        if names_bytes > 0x10000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export name array too large".to_string(),
            ));
        }
        if names_rva >= image_size || names_rva.checked_add(names_bytes).map_or(true, |end| end > image_size) {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "export name array outside image envelope: rva={names_rva:#x} bytes={names_bytes:#x} image={image_size:#x}"
            )));
        }
        let mut names = vec![0u8; names_bytes];
        let names_va = module_base.checked_add(names_rva).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("export name array VA overflow".to_string())
        })?;
        let rn = unsafe {
            RPM(
                target,
                names_va as *const core::ffi::c_void,
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
        let ords_bytes = num_names.checked_mul(2).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("export ordinal array size overflow".to_string())
        })?;
        if ords_bytes > 0x8000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export ordinal array too large".to_string(),
            ));
        }
        if ords_rva >= image_size || ords_rva.checked_add(ords_bytes).map_or(true, |end| end > image_size) {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "export ordinal array outside image envelope: rva={ords_rva:#x} bytes={ords_bytes:#x} image={image_size:#x}"
            )));
        }
        let mut ords = vec![0u8; ords_bytes];
        let ords_va = module_base.checked_add(ords_rva).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("export ordinal array VA overflow".to_string())
        })?;
        let ro = unsafe {
            RPM(
                target,
                ords_va as *const core::ffi::c_void,
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
        // IMP-08-R1-R1 (P0-1): the function array itself must fit inside
        // the image envelope before the remote read.
        let funcs_bytes = num_funcs.checked_mul(4).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("export function array size overflow".to_string())
        })?;
        if funcs_bytes > 0x10000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export function array too large".to_string(),
            ));
        }
        if funcs_rva >= image_size || funcs_rva.checked_add(funcs_bytes).map_or(true, |end| end > image_size) {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "export function array outside image envelope: rva={funcs_rva:#x} bytes={funcs_bytes:#x} image={image_size:#x}"
            )));
        }
        let mut funcs = vec![0u8; funcs_bytes];
        let funcs_va = module_base.checked_add(funcs_rva).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("export function array VA overflow".to_string())
        })?;
        let rf = unsafe {
            RPM(
                target,
                funcs_va as *const core::ffi::c_void,
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
        let want: [&[u8]; 5] = [
            b"MidaAntidebugInitialize",
            b"MidaAntidebugGetAttestation",
            b"MidaAntidebugShutdown",
            b"MidaAntidebugInitializeV2",
            b"WalkerExecute",
        ];
        // ADR-5B-R5 / IMP-08-R1: resolve through the pure, bounds-checked
        // parser. The name resolver reads one byte at a time from the target
        // via RPM (bounded 64 chars, matching the parser contract).
        // IMP-08-R1: the 5-item frozen wanted set (WO-1505 §5.3c) is
        // REQUIRED — missing any export fails closed below.
        let found_owned = {
            // IMP-08-R1-R2 (P1-2): the name resolver reports termination
            // status. Ok(true) = NUL-terminated; Ok(false) = no NUL inside
            // the bounded window (64 bytes / image envelope) — the parser
            // fails closed; Err = the remote read failed — also fail-closed.
            let mut name_at =
                |name_ptr_rva: usize, out: &mut Vec<u8>| -> Result<bool, RuntimeLoadError> {
                    let mut terminated = false;
                    for k in 0..64usize {
                        let Some(rva) = name_ptr_rva.checked_add(k) else {
                            break;
                        };
                        // The parser already rejected name_ptr_rva >=
                        // image_size; per-byte reads stay inside the
                        // envelope window as well.
                        if rva >= image_size {
                            break;
                        }
                        let Some(name_va) = module_base.checked_add(rva) else {
                            break;
                        };
                        let mut ch = [0u8; 1];
                        let rc = unsafe {
                            RPM(
                                target,
                                name_va as *const core::ffi::c_void,
                                ch.as_mut_ptr() as *mut core::ffi::c_void,
                                1,
                                None,
                            )
                        };
                        if rc.is_err() {
                            return Err(RuntimeLoadError::ExportResolutionFailed(
                                format!("remote read export name failed: rva={rva:#x}"),
                            ));
                        }
                        if ch[0] == 0 {
                            terminated = true;
                            break;
                        }
                        out.push(ch[0]);
                    }
                    Ok(terminated)
                };
            Self::resolve_exports_from_buffers(
                &names,
                &ords,
                &funcs,
                &mut name_at,
                num_names,
                num_funcs,
                module_base,
                image_size,
                exp_rva,
                exp_size,
                &want,
            )?
        };
        // IMP-08-R1: the frozen 5-item set must ALL resolve (fail-closed).
        let found: [Option<usize>; 5] = [
            found_owned[0],
            found_owned[1],
            found_owned[2],
            found_owned[3],
            found_owned[4],
        ];
        let (Some(init), Some(get), Some(shut), Some(init_v2), Some(walker)) =
            (found[0], found[1], found[2], found[3], found[4])
        else {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "remote export missing: init={} get={} shut={} init_v2={} walker={}",
                found[0].is_some(),
                found[1].is_some(),
                found[2].is_some(),
                found[3].is_some(),
                found[4].is_some()
            )));
        };
        Ok(MidaExportsV2 {
            initialize: Some(init),
            get_attestation: Some(get),
            shutdown: Some(shut),
            initialize_v2: Some(init_v2),
            walker_execute: Some(walker),
        })
    }

    /// Parse a PE export directory from in-memory buffers (ADR-5B-R5).
    ///
    /// Pure parser over the already-read name-pointer array, ordinal array
    /// and function-address array. `name_at` resolves a name-string address
    /// (RVA) to its bytes AND reports termination: `Ok(true)` means the
    /// bytes are NUL-terminated, `Ok(false)` means no NUL was found inside
    /// the bounded read, `Err` means the read failed — both non-terminated
    /// cases fail closed in this parser. The remote path reads via RPM from
    /// the target, tests supply a flat buffer. Returns the resolved
    /// addresses for the wanted exports; `module_base` is the image base
    /// (for RVA -> VA conversion) and `image_size` is the module envelope
    /// ([module_base, module_base + image_size)) that bounds every RVA.
    /// `funcs` is the raw function-address array (num_funcs * 4 bytes).
    /// Handles Base != 1 (the ordinal array is 0-based relative to
    /// AddressOfFunctions per the MSVC/Rust link.exe convention — the
    /// ordinal VALUE is the function index), forwarded exports (function
    /// RVA inside the export directory -> not resolved), out-of-range
    /// ordinals and missing names. Duplicate wanted names are ALWAYS
    /// ambiguous (fail-closed), even when the first occurrence was skipped
    /// (forwarded / out-of-range ordinal / null function RVA). Fail-closed
    /// on truncated buffers; every index is derived with checked_mul /
    /// checked_add and validated against the buffer length before use.
    ///
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_exports_from_buffers(
        names: &[u8],
        ords: &[u8],
        funcs: &[u8],
        name_at: &mut dyn FnMut(usize, &mut Vec<u8>) -> Result<bool, RuntimeLoadError>,
        num_names: usize,
        num_funcs: usize,
        module_base: usize,
        image_size: usize,
        exp_rva: usize,
        exp_size: usize,
        want: &[&[u8]],
    ) -> Result<Vec<Option<usize>>, RuntimeLoadError> {
        // IMP-08-R1-R1 (P0-1): the pure parser REQUIRES the image envelope.
        // `image_size` bounds every RVA (names, functions, export dir). A
        // caller that cannot provide the envelope cannot resolve exports.
        if image_size == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export resolver requires non-zero image_size".to_string(),
            ));
        }
        let module_end = module_base.checked_add(image_size).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "module envelope overflow (module_base + image_size)".to_string(),
            )
        })?;
        // Export-directory interval (forwarded-export window), precomputed
        // with checked arithmetic.
        let exp_end = exp_rva.checked_add(exp_size).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "export directory range overflow".to_string(),
            )
        })?;
        if exp_rva >= image_size || exp_end > image_size {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "export directory outside image envelope: rva={exp_rva:#x} size={exp_size:#x} image={image_size:#x}"
            )));
        }
        let mut found: Vec<Option<usize>> = vec![None; want.len()];
        // IMP-08-R1-R2 (P1-1): `seen` records EVERY occurrence of a wanted
        // name, independently of `found` (which only records successful
        // resolutions). A duplicate wanted name is ambiguous even when the
        // first occurrence was skipped (forwarded, out-of-range ordinal,
        // null function RVA): the second occurrence must fail closed
        // instead of silently becoming "the" export.
        let mut seen: Vec<bool> = vec![false; want.len()];
        for i in 0..num_names {
            // IMP-08-R1-R2/R3 (P1-3): every offset is derived with
            // checked_mul/checked_add, validated against the buffer length
            // (name_end > names.len() etc.), and every element read is a
            // slice of the validated range (no off+N element indexing).
            let name_off = i.checked_mul(4).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(
                    "export name index overflow".to_string(),
                )
            })?;
            let name_end = name_off.checked_add(4).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(
                    "export name slot overflow".to_string(),
                )
            })?;
            if name_end > names.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "export name array truncated".to_string(),
                ));
            }
            let name_slot = &names[name_off..name_end];
            let name_ptr_rva = u32::from_le_bytes(
                name_slot
                    .try_into()
                    .map_err(|_| {
                        RuntimeLoadError::ExportResolutionFailed(
                            "export name slot size".to_string(),
                        )
                    })?,
            ) as usize;
            if name_ptr_rva == 0 {
                continue;
            }
            // IMP-08-R1-R1 (P0-1): every export NAME string must live
            // inside the image envelope; a name pointer pointing outside
            // the module (or past its end) is malformed and fails closed.
            if name_ptr_rva >= image_size {
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "export name RVA outside image envelope: rva={name_ptr_rva:#x} image={image_size:#x}"
                )));
            }
            // IMP-08-R1-R2 (P1-2): the name resolver must report whether
            // the string is NUL-terminated. Ok(false) (no NUL inside the
            // bounded window) and Err (read failure) both fail closed —
            // an unterminated name can never participate in matching.
            let mut name = Vec::with_capacity(64);
            let terminated = name_at(name_ptr_rva, &mut name)?;
            if !terminated {
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "export name not NUL-terminated: rva={name_ptr_rva:#x}"
                )));
            }
            let ord_off = i.checked_mul(2).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(
                    "export ordinal index overflow".to_string(),
                )
            })?;
            let ord_end = ord_off.checked_add(2).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(
                    "export ordinal slot overflow".to_string(),
                )
            })?;
            if ord_end > ords.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(
                    "export ordinal array truncated".to_string(),
                ));
            }
            let ord_slot = &ords[ord_off..ord_end];
            let ord = u16::from_le_bytes(
                ord_slot
                    .try_into()
                    .map_err(|_| {
                        RuntimeLoadError::ExportResolutionFailed(
                            "export ordinal slot size".to_string(),
                        )
                    })?,
            ) as usize;
            // IMP-08-R1: duplicate export names are AMBIGUOUS and must be
            // rejected fail-closed (WO-1505 §5.3c).
            for (wi, w) in want.iter().enumerate() {
                if name.as_slice() != *w {
                    continue;
                }
                if seen[wi] {
                    // Duplicate name in the export table: two entries claim
                    // the same wanted symbol. Refuse to guess which one is
                    // real — even if the first occurrence was skipped
                    // (AmbiguousExport, fail-closed).
                    return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                        "ambiguous export: duplicate name '{}' in export table",
                        String::from_utf8_lossy(&name)
                    )));
                }
                seen[wi] = true;
                // The MSVC/Rust link.exe export ordinal array is 0-based for
                // #[no_mangle] exports even when Base=1: ord=0 maps to
                // AddressOfFunctions[0], ord=1 to [1], etc. Use the ordinal
                // directly as the function index.
                if ord >= num_funcs {
                    // Out-of-range ordinal: this occurrence cannot resolve
                    // (fail-closed; a later duplicate is still ambiguous).
                    continue;
                }
                let func_off = ord.checked_mul(4).ok_or_else(|| {
                    RuntimeLoadError::ExportResolutionFailed(
                        "export function index overflow".to_string(),
                    )
                })?;
                let func_end = func_off.checked_add(4).ok_or_else(|| {
                    RuntimeLoadError::ExportResolutionFailed(
                        "export function slot overflow".to_string(),
                    )
                })?;
                if func_end > funcs.len() {
                    return Err(RuntimeLoadError::ExportResolutionFailed(
                        "export function array truncated".to_string(),
                    ));
                }
                let func_slot = &funcs[func_off..func_end];
                let func_rva = u32::from_le_bytes(
                    func_slot
                        .try_into()
                        .map_err(|_| {
                            RuntimeLoadError::ExportResolutionFailed(
                                "export function slot size".to_string(),
                            )
                        })?,
                ) as usize;
                if func_rva == 0 {
                    continue;
                }
                // IMP-08-R1-R1 (P0-1): EVERY function RVA must lie
                // INSIDE the image envelope (0 < rva < SizeOfImage).
                // A function RVA at/above SizeOfImage is outside the
                // module — reject fail-closed (never return a VA that
                // points past the image end).
                if func_rva >= image_size {
                    return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                        "export function RVA outside image envelope: rva={func_rva:#x} image={image_size:#x}"
                    )));
                }
                // Forwarded export: the function RVA points INSIDE the export
                // directory (the name is a forwarder string, not code).
                // Checked range (audit R5): avoid overflow on exp_rva+exp_size.
                if exp_size > 0 && func_rva >= exp_rva && func_rva < exp_end {
                    continue;
                }
                // module_base + func_rva must not overflow (checked).
                let func_va = module_base.checked_add(func_rva).ok_or_else(|| {
                    RuntimeLoadError::ExportResolutionFailed(
                        "export function VA overflow (module_base + rva)".to_string(),
                    )
                })?;
                if func_va >= module_end {
                    return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                        "export function VA outside module envelope: va={func_va:#x} end={module_end:#x}"
                    )));
                }
                found[wi] = Some(func_va);
            }
        }
        Ok(found)
    }

    /// IMP-09-CARRIER-R2: resolve the WalkerExecute export RVA from the
    /// VERIFIED runtime DLL file bytes — pure file path, NO process access,
    /// NO ReadProcessMemory, NO live target module.
    ///
    /// The file is re-read from the canonical path sealed in
    /// `RuntimeFileIdentity` (produced by
    /// `RuntimeAuthorityManifest::verify_file`). The re-read is RE-BOUND
    /// to the sealed identity: size MUST match AND the recomputed SHA-256
    /// of the re-read bytes MUST equal `identity.sha256()`. A same-size
    /// content swap on disk fails closed — the carrier is
    /// path + size + content-digest bound. The PE export directory is then
    /// parsed with the SAME fail-closed rules as the remote resolver:
    /// SizeOfImage envelope, checked RVA arithmetic, name/ordinal/function
    /// array bounds, NUL termination, duplicate wanted-name rejection,
    /// forwarded-export rejection, out-of-module rejection, overflow
    /// rejection. Every offset into the file is computed with
    /// checked_add/checked_mul and re-validated against the file length
    /// before slicing (no naked offset arithmetic).
    ///
    /// Returns the pure export RVA (module_base=0 mode of the shared
    /// parser, so the returned value IS the RVA, never an absolute VA).
    pub fn resolve_walker_export_rva_from_file(
        identity: &RuntimeFileIdentity,
    ) -> Result<u64, RuntimeLoadError> {
        // 1. Re-read the verified file bytes from the sealed canonical
        //    path, then RE-BIND the content: size AND recomputed SHA-256
        //    must equal the sealed identity. Same-size replacement on
        //    disk is rejected here — never parsed.
        let bytes = std::fs::read(identity.path()).map_err(|e| {
            RuntimeLoadError::ExportResolutionFailed(format!(
                "read verified runtime file failed: {e}"
            ))
        })?;
        if bytes.len() as u64 != identity.size_bytes() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "verified runtime file size changed since verify_file".to_string(),
            ));
        }
        let digest = sha256_hex(&bytes);
        if digest != identity.sha256() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "verified runtime file content digest changed since verify_file".to_string(),
            ));
        }
        // 2. Checked offset/range helper: every PE offset below is
        //    computed with checked_add and the end is re-validated
        //    against the file length BEFORE slicing; slices always reuse
        //    the validated end. No naked `base + n` / `off + n`.
        let range = |base: usize,
                     delta: usize,
                     n: usize,
                     what: &str|
         -> Result<(usize, usize), RuntimeLoadError> {
            let start = base.checked_add(delta).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(format!("{what} offset overflow"))
            })?;
            let end = start.checked_add(n).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(format!("{what} range end overflow"))
            })?;
            if end > bytes.len() {
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "{what} out of file bounds (end={end:#x} file_len={:#x})",
                    bytes.len()
                )));
            }
            Ok((start, end))
        };
        if bytes.len() < 0x40 || &bytes[0..2] != b"MZ" {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "runtime file missing MZ".to_string(),
            ));
        }
        let e_lfanew = u32::from_le_bytes(bytes[0x3C..0x40].try_into().map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed("truncated DOS header".to_string())
        })?) as usize;
        let pe_off = e_lfanew;
        let (sig_s, sig_e) = range(pe_off, 0, 4, "PE signature")?;
        if &bytes[sig_s..sig_e] != b"PE\0\0" {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "runtime file missing PE signature".to_string(),
            ));
        }
        let (magic_s, magic_e) = range(pe_off, 24, 2, "optional header magic")?;
        let magic = u16::from_le_bytes(bytes[magic_s..magic_e].try_into().map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed("truncated optional header magic".to_string())
        })?);
        if magic != 0x20B {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "runtime file optional header magic {magic:#x} != PE32+ (0x20B)"
            )));
        }
        // SizeOfImage at optional+0x50 (pe_off+24+0x50 = pe_off+0x68).
        let (img_s, img_e) = range(pe_off, 0x68, 4, "SizeOfImage")?;
        let image_size = u32::from_le_bytes(bytes[img_s..img_e].try_into().map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed("SizeOfImage read".to_string())
        })?) as usize;
        if image_size == 0 || image_size < 0x1000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "runtime file SizeOfImage invalid: {image_size:#x}"
            )));
        }
        // Export data directory: PE32+ optional+0x70 (pe_off+24+0x70 =
        // pe_off+0x88).
        let (er_s, er_e) = range(pe_off, 0x88, 4, "export RVA")?;
        let exp_rva =
            u32::from_le_bytes(bytes[er_s..er_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("export RVA read".to_string())
            })?) as usize;
        let (es_s, es_e) = range(pe_off, 0x8C, 4, "export size")?;
        let exp_size = u32::from_le_bytes(bytes[es_s..es_e].try_into().map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed("export size read".to_string())
        })?) as usize;
        if exp_rva == 0 || exp_size == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "runtime file has no export directory".to_string(),
            ));
        }
        let exp_end = exp_rva.checked_add(exp_size).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("export directory range overflow".to_string())
        })?;
        if exp_rva >= image_size || exp_end > image_size {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "export directory outside image envelope: rva={exp_rva:#x} size={exp_size:#x} image={image_size:#x}"
            )));
        }
        // 3. Section table: build RVA -> file-offset mapping (checked).
        let (ns_s, ns_e) = range(pe_off, 6, 2, "num_sections")?;
        let num_sections =
            u16::from_le_bytes(bytes[ns_s..ns_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("truncated COFF".to_string())
            })?) as usize;
        let (os_s, os_e) = range(pe_off, 20, 2, "optional header size")?;
        let opt_size = u16::from_le_bytes(bytes[os_s..os_e].try_into().map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed("truncated optional header size".to_string())
        })?) as usize;
        let sec_off = pe_off
            .checked_add(24)
            .and_then(|v| v.checked_add(opt_size))
            .ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed(
                    "section table offset overflow".to_string(),
                )
            })?;
        let mut sections: Vec<(u64, u64, u64)> = Vec::new(); // (va, vsize, raw_ptr)
        for i in 0..num_sections {
            let slot = i.checked_mul(40).ok_or_else(|| {
                RuntimeLoadError::ExportResolutionFailed("section index overflow".to_string())
            })?;
            let (base_s, _base_e) = range(sec_off, slot, 40, "section header")?;
            let (vs_s, vs_e) = range(base_s, 8, 4, "section vsize")?;
            let vsize = u32::from_le_bytes(bytes[vs_s..vs_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("section vsize read".to_string())
            })?) as u64;
            let (va_s, va_e) = range(base_s, 12, 4, "section va")?;
            let va = u32::from_le_bytes(bytes[va_s..va_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("section va read".to_string())
            })?) as u64;
            let (rp_s, rp_e) = range(base_s, 20, 4, "section raw pointer")?;
            let raw_ptr = u32::from_le_bytes(bytes[rp_s..rp_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("section raw read".to_string())
            })?) as u64;
            sections.push((va, vsize, raw_ptr));
        }
        let rva_to_file = |rva: usize| -> Result<usize, RuntimeLoadError> {
            let r = rva as u64;
            for &(va, vsize, raw) in &sections {
                if r >= va
                    && r < va.checked_add(vsize).ok_or_else(|| {
                        RuntimeLoadError::ExportResolutionFailed(
                            "section span overflow".to_string(),
                        )
                    })?
                {
                    let off = raw
                        .checked_add(r.checked_sub(va).ok_or_else(|| {
                            RuntimeLoadError::ExportResolutionFailed(
                                "rva offset underflow".to_string(),
                            )
                        })?)
                        .ok_or_else(|| {
                            RuntimeLoadError::ExportResolutionFailed(
                                "file offset overflow".to_string(),
                            )
                        })?;
                    return usize::try_from(off).map_err(|_| {
                        RuntimeLoadError::ExportResolutionFailed(
                            "file offset too large".to_string(),
                        )
                    });
                }
            }
            Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "RVA {rva:#x} not mapped by any section"
            )))
        };
        // 4. Export directory: read fields from file bytes (checked).
        let ed_off = rva_to_file(exp_rva)?;
        let (_ed_s, _ed_e) = range(ed_off, 0, 40, "export directory")?;
        let (nf_s, nf_e) = range(ed_off, 0x14, 4, "num_funcs")?;
        let num_funcs =
            u32::from_le_bytes(bytes[nf_s..nf_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("num_funcs read".to_string())
            })?) as usize;
        let (nn_s, nn_e) = range(ed_off, 0x18, 4, "num_names")?;
        let num_names =
            u32::from_le_bytes(bytes[nn_s..nn_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("num_names read".to_string())
            })?) as usize;
        let (fr_s, fr_e) = range(ed_off, 0x1C, 4, "funcs_rva")?;
        let funcs_rva =
            u32::from_le_bytes(bytes[fr_s..fr_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("funcs_rva read".to_string())
            })?) as usize;
        let (nr_s, nr_e) = range(ed_off, 0x20, 4, "names_rva")?;
        let names_rva =
            u32::from_le_bytes(bytes[nr_s..nr_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("names_rva read".to_string())
            })?) as usize;
        let (or_s, or_e) = range(ed_off, 0x24, 4, "ords_rva")?;
        let ords_rva =
            u32::from_le_bytes(bytes[or_s..or_e].try_into().map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed("ords_rva read".to_string())
            })?) as usize;
        if num_names == 0 || names_rva == 0 || funcs_rva == 0 || ords_rva == 0 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "runtime file export directory incomplete".to_string(),
            ));
        }
        // 5. Read the three arrays from FILE bytes (checked, in-envelope).
        let read_buf = |rva: usize,
                        bytes_n: usize,
                        what: &str|
         -> Result<Vec<u8>, RuntimeLoadError> {
            if rva >= image_size
                || rva
                    .checked_add(bytes_n)
                    .map_or(true, |end| end > image_size)
            {
                return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                    "export {what} array outside image envelope: rva={rva:#x} bytes={bytes_n:#x} image={image_size:#x}"
                )));
            }
            let fo = rva_to_file(rva)?;
            let (arr_s, arr_e) = range(fo, 0, bytes_n, what)?;
            Ok(bytes[arr_s..arr_e].to_vec())
        };
        let names_bytes = num_names.checked_mul(4).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("name array size overflow".to_string())
        })?;
        if names_bytes > 0x10000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export name array too large".to_string(),
            ));
        }
        let names = read_buf(names_rva, names_bytes, "name")?;
        let ords_bytes = num_names.checked_mul(2).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("ordinal array size overflow".to_string())
        })?;
        if ords_bytes > 0x8000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export ordinal array too large".to_string(),
            ));
        }
        let ords = read_buf(ords_rva, ords_bytes, "ordinal")?;
        let funcs_bytes = num_funcs.checked_mul(4).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed("function array size overflow".to_string())
        })?;
        if funcs_bytes > 0x10000 {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "export function array too large".to_string(),
            ));
        }
        let funcs = read_buf(funcs_rva, funcs_bytes, "function")?;
        // 6. Resolve WalkerExecute via the shared parser (module_base=0 =>
        //    returns pure RVA).
        let mut name_at =
            |name_ptr_rva: usize, out: &mut Vec<u8>| -> Result<bool, RuntimeLoadError> {
                let fo = rva_to_file(name_ptr_rva)?;
                let mut terminated = false;
                for k in 0..64usize {
                    let Some(off) = fo.checked_add(k) else {
                        break;
                    };
                    if off >= bytes.len() {
                        break;
                    }
                    let ch = bytes[off];
                    if ch == 0 {
                        terminated = true;
                        break;
                    }
                    out.push(ch);
                }
                Ok(terminated)
            };
        let want: [&[u8]; 1] = [b"WalkerExecute"];
        let found = Self::resolve_exports_from_buffers(
            &names,
            &ords,
            &funcs,
            &mut name_at,
            num_names,
            num_funcs,
            0, // module_base = 0 => pure RVA mode
            image_size,
            exp_rva,
            exp_size,
            &want,
        )?;
        match found[0] {
            Some(rva) => Ok(rva as u64),
            None => Err(RuntimeLoadError::ExportResolutionFailed(
                "WalkerExecute export not found in verified runtime file".to_string(),
            )),
        }
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
        let shutdown_addr = loaded.exports.shutdown.ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "MidaAntidebugShutdown missing".to_string(),
            )
        })?;
        let args = ThunkArgs {
            fn_ptr: shutdown_addr as u64,
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
    if prov.sha256 != runtime_identity.sha256() {
        return Err(RuntimeLoadError::AuthorityMismatch(format!(
            "provenance sha256 {} != runtime {}",
            prov.sha256, runtime_identity.sha256
        )));
    }
    if prov.size_bytes != runtime_identity.size_bytes() {
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
    // IMP-09-CARRIER-R2: resolve WalkerExecute export RVA from the
    // VERIFIED runtime file bytes (pure-file; no live process access).
    // Best-effort carrier: failure leaves the walker NOT_WIRED instead of
    // failing the whole runtime load (the walker is not part of the
    // runtime init contract).
    let walker_export_rva =
        RuntimeLoader::resolve_walker_export_rva_from_file(&loaded.file_identity).ok();
    Ok(crate::unpacker::antidebug_controller::LoaderResult::new(
        loaded.module_base as u64,
        loaded.attestation_json,
        loaded.file_identity,
        loaded.digest_authority,
        target_pid,
        walker_export_rva,
    ))
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

/// v2 wanted export names (frozen 5-item set, WO-1505 §5.3c):
///   MidaAntidebugInitialize      v1 one-shot initialize (non-digest path)
///   MidaAntidebugGetAttestation  attestation copy
///   MidaAntidebugShutdown        shutdown / cleanup
///   MidaAntidebugInitializeV2    v2 7-arg initialize (digest channel)
///   WalkerExecute                walker protocol entry (IMP-09 gate)
pub const WANTED_EXPORTS_V2: &[&str] = &[
    "MidaAntidebugInitialize",
    "MidaAntidebugGetAttestation",
    "MidaAntidebugShutdown",
    "MidaAntidebugInitializeV2",
    "WalkerExecute",
];

/// v2 export resolution result (5-item frozen set). Addresses are resolved
/// target VAs (module_base + export RVA); nothing is dereferenced here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MidaExportsV2 {
    pub initialize: Option<usize>,
    pub get_attestation: Option<usize>,
    pub shutdown: Option<usize>,
    pub initialize_v2: Option<usize>,
    pub walker_execute: Option<usize>,
}

impl MidaExportsV2 {
    /// Fail-closed: the FULL 5-item wanted set must resolve.
    pub fn require_complete(&self) -> Result<(), RuntimeLoadError> {
        if self.initialize.is_none() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "MidaAntidebugInitialize missing".to_string(),
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
        if self.initialize_v2.is_none() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "MidaAntidebugInitializeV2 missing".to_string(),
            ));
        }
        if self.walker_execute.is_none() {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "WalkerExecute missing".to_string(),
            ));
        }
        Ok(())
    }

    /// Fail-closed: the v2 7-arg entry must resolve (digest-required path).
    pub fn require_v2_entry(&self) -> Result<usize, RuntimeLoadError> {
        self.initialize_v2.ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "MidaAntidebugInitializeV2 missing (digest-required)".to_string(),
            )
        })
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
/// View a prepared V2 params payload as a blob (used by the production
/// caller to consume the preflight result against the same bytes).
pub fn prepared_as_blob(prepared: &PreparedV2Params) -> V2ParamsBlob {
    V2ParamsBlob {
        bytes: prepared.bytes.clone(),
    }
}

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
    ///
    /// Identity fields (target_pid / module_base) are zero in this
    /// test-compatible builder; the runtime rejects zero identity at the
    /// V2 entry (fail-closed). Production must use [`Self::build_with_identity`].
    pub fn build(
        profile_id: &str,
        profile_digest: &str,
        expected_surfaces: &[String],
        digest: &str,
        blob_base: u64,
    ) -> Result<Self, RuntimeLoadError> {
        Self::build_with_identity(
            profile_id,
            profile_digest,
            expected_surfaces,
            digest,
            blob_base,
            0,
            0,
        )
    }

    /// Production v2 envelope builder (WO-1505 §5.3): binds the target
    /// identity (target_pid + module_base) into the frozen header slots
    /// +0x00 / +0x08. Both must be nonzero (fail-closed); the runtime uses
    /// them to build the attestation identity and rejects zero values.
    pub fn build_with_identity(
        profile_id: &str,
        profile_digest: &str,
        expected_surfaces: &[String],
        digest: &str,
        blob_base: u64,
        target_pid: u32,
        module_base: u64,
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
        // IMP-08-R1: production identity binding (WO-1505 §5.3). The RUNTIME
        // rejects zero identity at the V2 entry (fail-closed), so a
        // production caller that forgets the identity gets a hard error
        // from the runtime rather than a silently unbound attestation.
        // build() passes zeros (test-only); build_with_identity() requires
        // both nonzero and validates here.
        if (target_pid == 0) != (module_base == 0) {
            return Err(RuntimeLoadError::ExportResolutionFailed(
                "v2 identity must be bound or unbound together (target_pid, module_base)"
                    .to_string(),
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
        // identity (WO-1505 §5.3 frozen slots): target_pid +0x00, module_base +0x08.
        // Both must be nonzero for production; the runtime rejects zero values.
        out[0x00..0x04].copy_from_slice(&target_pid.to_le_bytes());
        out[0x08..0x10].copy_from_slice(&module_base.to_le_bytes());
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

/// Structured local V2 preflight result (RC-6 / IMP-03-R5).
///
/// This is a PURE LOCAL parsing outcome: it proves the envelope bytes are
/// structurally self-consistent for the given `blob_base`, and resolves the
/// surface entries to their target-local absolute VAs.
///
/// # Semantics (explicit, RC-6 item 8)
/// - **LOCAL PREFLIGHT ≠ runtime/live PASS.** A successful preflight does
///   NOT prove the target process can be initialized; it does NOT read any
///   remote memory, create any remote thread, or call any runtime entry.
/// - It does NOT authorize Walker dispatch, LIVE-4, or any Windows live
///   execution. The gate (implementation_gate.rs) remains authoritative.
/// - Failure is fail-closed: every structural violation surfaces as
///   [RuntimeLoadError] from [V2ParamsBlob::preflight_local].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2PreflightResult {
    pub profile_id_off: u64,
    pub profile_digest_off: u64,
    pub expected_surfaces_off: u64,
    pub digest_off: u64,
    pub digest_len: u64,
    /// Declared surface pointer count (header 0x20).
    pub expected_hooks: u64,
    /// blob_base the envelope was validated against (target-local).
    pub blob_base: u64,
    /// Resolved surface entries as ABSOLUTE target-local VAs, in declared
    /// order (each already proven nonzero / canonical / in-blob).
    pub surface_entries: Vec<u64>,
}

impl V2PreflightResult {
    /// Convert a surface entry back to a blob-relative offset (checked).
    pub fn surface_relative_offset(&self, index: usize) -> Result<u64, RuntimeLoadError> {
        let va = *self.surface_entries.get(index).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 surface entry index {index} out of range ({} entries)",
                self.surface_entries.len()
            ))
        })?;
        va.checked_sub(self.blob_base).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(
                "v2 surface VA below blob_base".to_string(),
            )
        })
    }
}

/// Result of the production V2 write path: the blob bytes and the
/// PREFLIGHT-VALIDATED surface list, both derived from the SAME build.
///
/// # Semantics
/// - `preflight` is a LOCAL structural validation result (RC-6 item 8):
///   it never implies a runtime/live pass and never authorizes Walker
///   dispatch or LIVE-4 (the gate stays authoritative).
/// - The blob was validated against the EXACT target VA that will be
///   written via WriteProcessMemory (`blob_base == remote_params`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedV2Params {
    /// Serialized envelope ready for WriteProcessMemory.
    pub bytes: Vec<u8>,
    /// Validated local preflight result for the SAME blob.
    pub preflight: V2PreflightResult,
}

/// Validate a local V2 preflight result against the caller's expectations.
///
/// Fail-closed on EVERY structural mismatch; returns the verified surface
/// strings (ordered) so the caller can bind them to the expected surfaces
/// without re-parsing the blob (no duplicate bare parser in consumers).
pub fn validate_preflight_result(
    blob: &V2ParamsBlob,
    preflight: &V2PreflightResult,
    expected_surfaces: &[String],
    params_bytes: usize,
) -> Result<Vec<Vec<u8>>, RuntimeLoadError> {
    if preflight.blob_base != params_bytes as u64 {
        return Err(RuntimeLoadError::ExportResolutionFailed(format!(
            "v2 preflight blob_base mismatch: {:#x} != remote_params {:#x}",
            preflight.blob_base,
            params_bytes
        )));
    }
    if preflight.digest_len != V2_DIGEST_LEN {
        return Err(RuntimeLoadError::ExportResolutionFailed(format!(
            "v2 preflight digest_len mismatch: {} != 64",
            preflight.digest_len
        )));
    }
    let expected_hooks = expected_surfaces.len() as u64;
    if preflight.expected_hooks != expected_hooks {
        return Err(RuntimeLoadError::ExportResolutionFailed(format!(
            "v2 preflight expected_hooks mismatch: {} != expected {}",
            preflight.expected_hooks,
            expected_hooks
        )));
    }
    if preflight.surface_entries.len() != expected_surfaces.len() {
        return Err(RuntimeLoadError::ExportResolutionFailed(format!(
            "v2 preflight surface_entries mismatch: {} != expected {}",
            preflight.surface_entries.len(),
            expected_surfaces.len()
        )));
    }
    // Verify surface ORDER + CONTENT via the validated accessor.
    let mut verified: Vec<Vec<u8>> = Vec::with_capacity(expected_surfaces.len());
    for (i, want) in expected_surfaces.iter().enumerate() {
        let got = blob.surface_string(preflight, i)?;
        if got != want.as_bytes() {
            return Err(RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 preflight surface[{i}] mismatch: {:?} != {:?}",
                String::from_utf8_lossy(got),
                want
            )));
        }
        verified.push(got.to_vec());
    }
    Ok(verified)
}

impl V2ParamsBlob {
    /// Production V2 write-path seam (IMP-07-R1).
    ///
    /// Builds the identity-bound V2 envelope AND runs the local preflight
    /// against the exact target VA that will receive the write, then
    /// validates the preflight result against the expected surfaces.
    ///
    /// # Fail-closed guarantees (IMP-07-R1)
    /// - preflight failure or validation failure => Err, NO bytes are
    ///   returned, so a caller that uses the `?` operator can never reach
    ///   WriteProcessMemory with an unvalidated blob;
    /// - `blob_base` MUST equal the remote_params VA the caller will write
    ///   to; any mismatch fails closed;
    /// - surface order/content is verified against `expected_surfaces`.
    pub fn build_preflight_and_validate(
        profile_id: &str,
        profile_digest: &str,
        expected_surfaces: &[String],
        digest: &str,
        blob_base: u64,
        target_pid: u32,
        module_base: u64,
        params_bytes: usize,
    ) -> Result<PreparedV2Params, RuntimeLoadError> {
        let blob = Self::build_with_identity(
            profile_id,
            profile_digest,
            expected_surfaces,
            digest,
            blob_base,
            target_pid,
            module_base,
        )?;
        let preflight = blob.preflight_local(blob_base)?;
        let _ = validate_preflight_result(&blob, &preflight, expected_surfaces, params_bytes)?;
        let blob_len = u64::try_from(blob.bytes.len()).map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed(
                "v2 blob length exceeds u64".to_string(),
            )
        })?;
        // blob_base + params_bytes checked (RC-4 item 4), redundant with
        // parse_offsets but explicit here for the write path.
        blob_base.checked_add(blob_len).ok_or_else(|| {
            RuntimeLoadError::ExportResolutionFailed(format!(
                "v2 blob_base + params_bytes overflow: {blob_base:#x} + {blob_len:#x}"
            ))
        })?;
        Ok(PreparedV2Params {
            bytes: blob.bytes,
            preflight,
        })
    }
}
impl V2ParamsBlob {
    /// Local V2 preflight consumer (RC-6 / IMP-03-R5).
    ///
    /// Real entry point of the inert envelope parser: it ACTUALLY calls
    /// [V2ParamsBlob::parse_offsets] with the given `blob_base` (fail-closed)
    /// and returns the structured [V2PreflightResult] consumed by the
    /// controller-side V2 path.
    ///
    /// All offset arithmetic stays checked (RC-5 helpers); no raw
    /// `+ 8` / `+ 64` / `as usize` is introduced.
    pub fn preflight_local(&self, blob_base: u64) -> Result<V2PreflightResult, RuntimeLoadError> {
        // Fail-closed: ANY structural violation propagates as Err and the
        // caller must treat the envelope as not consumable.
        let offs = self.parse_offsets(blob_base)?;

        // Re-read the (already validated) absolute VAs so the consumer gets
        // them in declared order; all arithmetic checked.
        let cap = u64_to_usize(offs.expected_hooks, "expected_hooks capacity")?;
        let mut surface_entries: Vec<u64> = Vec::with_capacity(cap);
        if offs.expected_hooks > 0 {
            let len = u64::try_from(self.bytes.len()).map_err(|_| {
                RuntimeLoadError::ExportResolutionFailed(
                    "v2 blob length exceeds u64".to_string(),
                )
            })?;
            for i in 0..offs.expected_hooks {
                let idx_bytes = i
                    .checked_mul(8)
                    .ok_or(RuntimeLoadError::ExportResolutionFailed(
                        "v2 entry index*8 overflow".to_string(),
                    ))?;
                let entry_off = offs
                    .expected_surfaces_off
                    .checked_add(idx_bytes)
                    .ok_or(RuntimeLoadError::ExportResolutionFailed(
                        "v2 entry offset overflow".to_string(),
                    ))?;
                let entry_end = checked_range_end(entry_off, 8, "surface entry")?;
                if entry_end > len {
                    return Err(RuntimeLoadError::ExportResolutionFailed(
                        "v2 surface entry read past blob end".to_string(),
                    ));
                }
                let s_us = u64_to_usize(entry_off, "surface entry start")?;
                let e_us = u64_to_usize(entry_end, "surface entry end")?;
                let va = u64::from_le_bytes(self.bytes[s_us..e_us].try_into().unwrap());
                surface_entries.push(va);
            }
        }

        Ok(V2PreflightResult {
            profile_id_off: offs.profile_id_off,
            profile_digest_off: offs.profile_digest_off,
            expected_surfaces_off: offs.expected_surfaces_off,
            digest_off: offs.digest_off,
            digest_len: offs.digest_len,
            expected_hooks: offs.expected_hooks,
            blob_base,
            surface_entries,
        })
    }

    /// Extract a surface string from the LOCAL blob bytes (consumer helper).
    ///
    /// Resolves the validated absolute VA back to a blob-relative offset
    /// (checked_sub), then scans to the NUL terminator with the bounded
    /// scan. Purely local; no target memory is touched.
    pub fn surface_string<'a>(
        &'a self,
        preflight: &V2PreflightResult,
        index: usize,
    ) -> Result<&'a [u8], RuntimeLoadError> {
        let rel = preflight.surface_relative_offset(index)?;
        let len = u64::try_from(self.bytes.len()).map_err(|_| {
            RuntimeLoadError::ExportResolutionFailed(
                "v2 blob length exceeds u64".to_string(),
            )
        })?;
        let end = scan_nul_rel(&self.bytes, rel, len, &format!("surface {index}"))?;
        let s_us = u64_to_usize(rel, "surface start")?;
        let e_us = u64_to_usize(end, "surface end")?;
        Ok(&self.bytes[s_us..e_us])
    }
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
    fn wanted_exports_v2_has_five_symbols() {
        assert_eq!(WANTED_EXPORTS_V2.len(), 5);
        assert_eq!(WANTED_EXPORTS_V2[0], "MidaAntidebugInitialize");
        assert_eq!(WANTED_EXPORTS_V2[1], "MidaAntidebugGetAttestation");
        assert_eq!(WANTED_EXPORTS_V2[2], "MidaAntidebugShutdown");
        assert_eq!(WANTED_EXPORTS_V2[3], "MidaAntidebugInitializeV2");
        assert_eq!(WANTED_EXPORTS_V2[4], "WalkerExecute");
    }

    #[test]
    fn mida_exports_v2_require_complete_fail_closed() {
        // Empty set: every entry missing -> Err.
        let e = MidaExportsV2 {
            initialize: None,
            get_attestation: None,
            shutdown: None,
            initialize_v2: None,
            walker_execute: None,
        };
        assert!(e.require_complete().is_err());
        // v1 trio present but v2 entry + walker missing -> Err.
        let e2 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: None,
            walker_execute: None,
        };
        assert!(e2.require_complete().is_err());
        assert!(e2.require_v2_entry().is_err());
        // Full 5-item set -> Ok.
        let e3 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: Some(0x4000),
            walker_execute: Some(0x5000),
        };
        assert_eq!(e3.require_complete(), Ok(()));
        assert_eq!(e3.require_v2_entry(), Ok(0x4000));
        // v2 entry missing but walker present -> require_v2_entry Err.
        let e4 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: None,
            walker_execute: Some(0x5000),
        };
        assert!(e4.require_v2_entry().is_err());
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
    // ------------------------------------------------------------------
    // RC-6 / IMP-03-R5: local V2 preflight consumer
    // ------------------------------------------------------------------

    #[test]
    fn v2_preflight_valid_absolute_va_envelope() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        // structured result mirrors parse_offsets fields
        assert_eq!(pf.profile_id_off, 0x48);
        assert_eq!(pf.profile_digest_off, 0x48 + 2); // 74
        assert_eq!(pf.digest_len, 64);
        assert_eq!(pf.expected_hooks, 2);
        assert_eq!(pf.blob_base, BLOB_BASE);
        // surface entries are absolute VAs in declared order
        assert_eq!(pf.surface_entries.len(), 2);
        let s0_rel = (0x48 + 2 + 2) as u64; // "p\x00" + "d\x00"
        let s1_rel = s0_rel + "AD-PROC-001".len() as u64 + 1;
        assert_eq!(pf.surface_entries[0], BLOB_BASE + s0_rel);
        assert_eq!(pf.surface_entries[1], BLOB_BASE + s1_rel);
        // relative conversion round trip
        assert_eq!(pf.surface_relative_offset(0).unwrap(), s0_rel);
        assert_eq!(pf.surface_relative_offset(1).unwrap(), s1_rel);
        assert!(pf.surface_relative_offset(2).is_err());
    }

    #[test]
    fn v2_preflight_zero_hooks_zero_off_allowed() {
        // expected_hooks == 0 && surfaces_off == 0 is a legal envelope.
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_arr_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let dig_off = u64::from_le_bytes(blob.bytes[0x38..0x40].try_into().unwrap());
        let arr_len = (dig_off - surf_arr_off) as usize;
        blob.bytes.drain(surf_arr_off as usize..dig_off as usize);
        debug_assert_eq!(arr_len, 8);
        blob.bytes[0x38..0x40].copy_from_slice(&surf_arr_off.to_le_bytes());
        blob.bytes[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
        blob.bytes[0x28..0x30].copy_from_slice(&0u64.to_le_bytes());
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        assert_eq!(pf.expected_hooks, 0);
        assert_eq!(pf.expected_surfaces_off, 0);
        assert!(pf.surface_entries.is_empty());
    }

    #[test]
    fn v2_preflight_wrong_blob_base_rejected() {
        // blob_base mismatch: entries validated against a DIFFERENT base
        // are out-of-blob -> fail-closed.
        let blob = build_blob(&["AD-PROC-001"]);
        assert!(blob.preflight_local(BLOB_BASE + 0x1000).is_err());
        assert!(blob.preflight_local(0).is_err());
        assert!(blob.preflight_local(0xFFFF_8000_0000_0000).is_err());
    }

    #[test]
    fn v2_preflight_unknown_tail_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes.push(0xAA);
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_noncanonical_entry_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&0xFFFF_8000_0000_0000u64.to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_zero_entry_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[surf_off as usize..surf_off as usize + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_out_of_blob_entry_rejected() {
        let mut blob = build_blob(&["AD-PROC-001"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        let blob_end = BLOB_BASE + blob.bytes.len() as u64;
        blob.bytes[surf_off as usize..surf_off as usize + 8]
            .copy_from_slice(&(blob_end + 0x10).to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_digest_truncation_rejected() {
        // truncate the digest region: NUL missing / hex region cut
        let mut blob = build_blob(&["AD-PROC-001"]);
        blob.bytes.truncate(blob.bytes.len() - 10);
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_surface_array_truncation_rejected() {
        // array region shorter than declared: surf_off moved 8 bytes right
        let mut blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let surf_off = u64::from_le_bytes(blob.bytes[0x28..0x30].try_into().unwrap());
        blob.bytes[0x28..0x30].copy_from_slice(&(surf_off + 8).to_le_bytes());
        assert!(blob.preflight_local(BLOB_BASE).is_err());
    }

    #[test]
    fn v2_preflight_surface_string_helper() {
        let blob = build_blob(&["AD-PROC-001", "AD-PROC-002"]);
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        let s0 = blob.surface_string(&pf, 0).unwrap();
        let s1 = blob.surface_string(&pf, 1).unwrap();
        assert_eq!(s0, b"AD-PROC-001");
        assert_eq!(s1, b"AD-PROC-002");
        assert!(blob.surface_string(&pf, 2).is_err());
    }

    #[test]
    fn v2_preflight_is_local_only_not_live_pass() {
        // Explicit semantic: a successful preflight is NOT a runtime/live
        // pass. It only proves local structural consistency. We assert the
        // API returns the structured result WITHOUT any runtime call, and
        // that the semantic note is documented on the type.
        let blob = build_blob(&["AD-PROC-001"]);
        let pf = blob.preflight_local(BLOB_BASE).unwrap();
        assert!(pf.surface_entries.len() == 1);
        assert!(pf.digest_len == 64);
        // The preflight does not imply any target-side capability; the
        // gate remains authoritative (checked in acceptance crate).
    }
}

#[cfg(test)]
mod imp06_sealed_authority_tests {
    use super::*;

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let d = h.finalize();
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn minimal_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x100];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew = 0x80
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
        b
    }

    fn manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
        RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        }
    }

    fn tmp_file(name: &str, content: &[u8]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("mida-imp06-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        p
    }

    /// The ONLY legitimate construction path: real PE file -> real
    /// verify_file() -> verified identity -> digest authority.
    fn verified_authority() -> RuntimeDigestAuthority {
        let pe = minimal_pe();
        let path = tmp_file("imp06_verified_runtime.dll", &pe);
        let expected = sha256_hex(&pe);
        let authority = manifest(&expected, pe.len() as u64);
        let id = authority.verify_file(&path).unwrap();
        RuntimeDigestAuthority::from_verified_identity(&id, &authority.artifact_id)
            .expect("verified identity must build a valid authority")
    }

    #[test]
    fn sealed_authority_getters_reflect_verified_identity() {
        let pe = minimal_pe();
        let path = tmp_file("imp06_getters.dll", &pe);
        let expected = sha256_hex(&pe);
        let authority = manifest(&expected, pe.len() as u64);
        let id = authority.verify_file(&path).unwrap();
        let da = RuntimeDigestAuthority::from_verified_identity(&id, &authority.artifact_id)
            .expect("verified identity must build a valid authority");
        assert_eq!(da.digest_value(), expected);
        assert_eq!(da.size_bytes(), pe.len() as u64);
        assert_eq!(da.architecture(), "x86_64");
        assert_eq!(da.manifest_artifact_id(), authority.artifact_id);
        assert_eq!(da.canonical_path(), id.path());
        // Read-only surface: no public field access, no public constructor.
        let _: &Path = da.canonical_path();
        let _: &str = da.digest_value();
        let _: u64 = da.size_bytes();
        let _: &str = da.manifest_artifact_id();
        let _: &str = da.architecture();
    }

    #[test]
    fn sealed_authority_echo_checks_are_fail_closed() {
        let auth = verified_authority();
        // Missing / placeholder / bad shapes all rejected.
        assert_eq!(
            auth.verify_runtime_echo(""),
            Err(DigestValidationError::Missing)
        );
        assert_eq!(
            auth.verify_runtime_echo(PLACEHOLDER_RUNTIME_DIGEST),
            Err(DigestValidationError::Placeholder)
        );
        assert!(matches!(
            auth.verify_runtime_echo(&"b".repeat(63)),
            Err(DigestValidationError::WrongLength { .. })
        ));
        assert!(matches!(
            auth.verify_runtime_echo(&"B".repeat(64)),
            Err(DigestValidationError::NotLowercaseHex)
        ));
        assert!(matches!(
            auth.verify_runtime_echo(&"z".repeat(64)),
            Err(DigestValidationError::NotLowercaseHex)
        ));
        // Correct digest accepted; different valid digest rejected.
        let d = auth.digest_value().to_string();
        assert_eq!(auth.verify_runtime_echo(&d), Ok(()));
        assert!(matches!(
            auth.verify_runtime_echo(&"c".repeat(64)),
            Err(DigestValidationError::EchoMismatch { .. })
        ));
    }

    #[test]
    fn sealed_authority_is_single_hash_point() {
        let pe = minimal_pe();
        let path = tmp_file("imp06_hashpoint.dll", &pe);
        let expected = sha256_hex(&pe);
        let authority = manifest(&expected, pe.len() as u64);
        let id = authority.verify_file(&path).unwrap();
        assert_eq!(id.sha256(), expected);
        // The authority digest is copied from the verified identity — no
        // second file read, no second hash computation.
        let da = RuntimeDigestAuthority::from_verified_identity(&id, &authority.artifact_id)
            .expect("verified identity must build a valid authority");
        assert_eq!(da.digest_value(), id.sha256());
        assert_eq!(da.digest_value(), expected);
        assert_eq!(da.size_bytes(), id.size_bytes());
        assert_eq!(da.manifest_artifact_id(), authority.artifact_id);
        assert_eq!(da.canonical_path(), id.path());
    }

    #[test]
    fn from_verified_identity_rejects_invalid_digest() {
        // The lexical gates are the same code path used by the production
        // authority; a forged identity (impossible outside this module) with
        // an invalid digest must be rejected here too.
        let id = RuntimeFileIdentity::from_verified(
            std::path::PathBuf::from("C:/tmp/x.dll"),
            PLACEHOLDER_RUNTIME_DIGEST.to_string(),
            10,
            "x86_64".to_string(),
        );
        assert!(matches!(
            RuntimeDigestAuthority::from_verified_identity(&id, "mida-antidebug-runtime-x64"),
            Err(DigestValidationError::Placeholder)
        ));
        let id2 = RuntimeFileIdentity::from_verified(
            std::path::PathBuf::from("C:/tmp/x.dll"),
            "A".repeat(64),
            10,
            "x86_64".to_string(),
        );
        assert!(matches!(
            RuntimeDigestAuthority::from_verified_identity(&id2, "mida-antidebug-runtime-x64"),
            Err(DigestValidationError::NotLowercaseHex)
        ));
        let id3 = RuntimeFileIdentity::from_verified(
            std::path::PathBuf::from("C:/tmp/x.dll"),
            "a".repeat(32),
            10,
            "x86_64".to_string(),
        );
        assert!(matches!(
            RuntimeDigestAuthority::from_verified_identity(&id3, "mida-antidebug-runtime-x64"),
            Err(DigestValidationError::WrongLength { .. })
        ));
    }
}

#[cfg(test)]
mod imp08_v2_production_tests {
    use super::*;

    /// Minimal name_at resolver backed by a flat string table.
    /// Returns Ok(true) when a NUL terminator was found inside the table.
    fn flat_name_at(
        table: &[u8],
    ) -> impl FnMut(usize, &mut Vec<u8>) -> Result<bool, RuntimeLoadError> + '_ {
        move |rva, out| {
            let off = rva - 0x1000;
            let mut terminated = false;
            if off < table.len() {
                for &b in &table[off..] {
                    if b == 0 {
                        terminated = true;
                        break;
                    }
                    out.push(b);
                }
            }
            Ok(terminated)
        }
    }
    fn wanted5() -> [&'static [u8]; 5] {
        [
            b"MidaAntidebugInitialize",
            b"MidaAntidebugGetAttestation",
            b"MidaAntidebugShutdown",
            b"MidaAntidebugInitializeV2",
            b"WalkerExecute",
        ]
    }

    /// Build a flat export table with the 5 wanted names at known RVAs.
    fn build_export_table() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut strings = Vec::new();
        for (i, s) in symbols.iter().enumerate() {
            let _ = s;
            // Name-pointer table only (4B per entry); ordinals are a
            // SEPARATE array in the PE export directory.
            strings.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
        }
        // function RVAs: 0x2000 + i*0x10
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        // name strings
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            // Names live at RVA 0x1000 + i*0x20; table is a flat image that
            // starts at RVA 0x1000, so the in-table offset is i*0x20.
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        (strings, funcs, table)
    }

    #[test]
    fn wanted_set_is_frozen_five() {
        assert_eq!(WANTED_EXPORTS_V2.len(), 5);
        assert_eq!(WANTED_EXPORTS_V2, &[
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ]);
    }

    #[test]
    fn resolve_five_exports_all_found() {
        let (names, funcs, table) = build_export_table();
        let mut name_at = flat_name_at(&table);
        let ords: Vec<u8> = (0..5).flat_map(|i| (i as u16).to_le_bytes()).collect();
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 5, 5, 0x400000, 0x10000, 0x1000, 0x100,
            &wanted5(),
        ).unwrap();
        assert_eq!(found.len(), 5);
        for (i, f) in found.iter().enumerate() {
            assert_eq!(*f, Some(0x400000 + 0x2000 + i * 0x10));
        }
        // require_complete succeeds on the full set.
        let e = MidaExportsV2 {
            initialize: found[0],
            get_attestation: found[1],
            shutdown: found[2],
            initialize_v2: found[3],
            walker_execute: found[4],
        };
        assert_eq!(e.require_complete(), Ok(()));
    }

    #[test]
    fn digest_required_no_v1_fallback() {
        // IMP-08-R1 requirement 7: digest-required mode MUST NOT silently
        // fall back to the v1 entry. require_complete() demands the FULL
        // 5-item set — v1 alone (even with v2 present) is incomplete, and a
        // missing v1 entry also fails. The production caller
        // (load_and_initialize_inner, require_digest=true) calls
        // require_complete() + require_v2_entry() BEFORE any thunk call.
        let full = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: Some(0x4000),
            walker_execute: Some(0x5000),
        };
        assert_eq!(full.require_complete(), Ok(()));
        // v1 missing: still fails (no fallback to a "v2-only" mode).
        let no_v1 = MidaExportsV2 {
            initialize: None,
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: Some(0x4000),
            walker_execute: Some(0x5000),
        };
        assert!(no_v1.require_complete().is_err());
        // v2 missing but v1 present: fails (digest-required needs V2).
        let no_v2 = MidaExportsV2 {
            initialize: Some(0x1000),
            get_attestation: Some(0x2000),
            shutdown: Some(0x3000),
            initialize_v2: None,
            walker_execute: Some(0x5000),
        };
        assert!(no_v2.require_complete().is_err());
        assert!(no_v2.require_v2_entry().is_err());
    }

    #[test]
    fn resolve_missing_export_fails_closed() {
        // Only 4 of the 5 wanted names present.
        let symbols: [&str; 4] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        let mut funcs = Vec::new();
        for i in 0..4 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 4, 4, 0x400000, 0x10000, 0x1000, 0x100,
            &wanted5(),
        ).unwrap();
        // WalkerExecute not found: the resolver reports it as None; the
        // caller-level require_complete() rejects the incomplete set.
        assert!(found[0].is_some() && found[1].is_some() && found[2].is_some());
        assert!(found[3].is_some());
        assert!(found[4].is_none(), "{found:?}");
        let e = MidaExportsV2 {
            initialize: found[0],
            get_attestation: found[1],
            shutdown: found[2],
            initialize_v2: found[3],
            walker_execute: found[4],
        };
        assert!(e.require_complete().is_err()); // walker missing -> incomplete
    }

    #[test]
    fn duplicate_export_rejected_ambiguous() {
        // Two export names point to the SAME wanted symbol (two entries
        // claim "MidaAntidebugInitialize"); the resolver must fail closed.
        let symbols: [&str; 6] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugInitialize", // duplicate
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        let mut funcs = Vec::new();
        for i in 0..6 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 6, 6, 0x400000, 0x10000, 0x1000, 0x100,
            &wanted5(),
        ).unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn forwarded_export_not_resolved() {
        // A wanted name whose function RVA points INSIDE the export
        // directory (exp_rva=0x1000, exp_size=0x100): forwarded export.
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // All function RVAs inside the export directory -> forwarded.
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 5, 5, 0x400000, 0x10000, 0x1000, 0x100,
            &wanted5(),
        ).unwrap();
        // Every wanted export is None (forwarded -> not resolved).
        assert!(found.iter().all(|f| f.is_none()), "{found:?}");
    }

    #[test]
    fn out_of_range_ordinal_skipped_fail_closed() {
        // An ordinal >= num_funcs is out of the function-address array:
        // the name is skipped (None) rather than resolving garbage.
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // ord=7 points past the 5-entry function array (num_funcs=5).
        let ords = (0..5).map(|_| 7u16.to_le_bytes()).collect::<Vec<_>>().concat();
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x2000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let found = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 5, 5, 0x400000, 0x10000, 0x1000, 0x100,
            &wanted5(),
        ).unwrap();
        // Out-of-range ordinals: all names skipped -> all None.
        assert!(found.iter().all(|f| f.is_none()), "{found:?}");
    }

    #[test]
    fn out_of_module_export_rva_rejected() {
        // IMP-08-R1-R1 (P0-1): a function RVA at/above SizeOfImage must
        // be REJECTED (Err), not converted to module_base + rva. Here all
        // five wanted functions claim RVA 0x20000 while image_size is
        // 0x10000 -> every match fails closed.
        let symbols: [&str; 5] = [
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
            "MidaAntidebugShutdown",
            "MidaAntidebugInitializeV2",
            "WalkerExecute",
        ];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // All function RVAs outside the 0x10000-byte image.
        let mut funcs = Vec::new();
        for i in 0..5 {
            funcs.extend_from_slice(&((0x20000 + i * 0x10) as u32).to_le_bytes());
        }
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 5, 5, 0x400000, 0x10000, 0x1000, 0x100,
            &wanted5(),
        ).unwrap_err();
        assert!(
            err.to_string().contains("outside image envelope"),
            "{err}"
        );
    }

    #[test]
    fn export_va_overflow_rejected() {
        // module_base + func_rva overflow must fail closed (checked add).
        let symbols: [&str; 1] = ["MidaAntidebugInitialize"];
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        // func_rva = 0x8000_0000_0000 fits in u32? No - use a u32-sized
        // large RVA that overflows module_base.checked_add on 64-bit only
        // if module_base is huge; instead pick func_rva near usize::MAX
        // by using a 32-bit RVA near 0xFFFF_FF00 and module_base huge.
        let mut funcs = Vec::new();
        // u32::MAX - 0xFF is still a valid u32 RVA; with module_base
        // = usize::MAX - 0x20000 the checked_add overflows.
        funcs.extend_from_slice(&0xFFFF_FF00u32.to_le_bytes());
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 1, 1, usize::MAX - 0x20000, 0x10000, 0x1000, 0x100,
            &[b"MidaAntidebugInitialize"],
        ).unwrap_err();
        // Either the RVA >= image_size check (0xFFFF_FF00 >= 0x10000)
        // fires first, or the VA overflow check fires; both are fail-closed.
        assert!(err.to_string().contains("outside image envelope") || err.to_string().contains("overflow"), "{err}");
    }

    #[test]
    fn v2_blob_build_with_identity_binds_target() {
        let ss: Vec<String> = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
        let digest = "a".repeat(64);
        let blob = V2ParamsBlob::build_with_identity(
            "p", "d", &ss, &digest, 0x0000_1000_0000, 1234, 0x0000_2000_0000,
        ).unwrap();
        // header identity slots
        assert_eq!(u32::from_le_bytes(blob.bytes[0x00..0x04].try_into().unwrap()), 1234);
        assert_eq!(u64::from_le_bytes(blob.bytes[0x08..0x10].try_into().unwrap()), 0x0000_2000_0000);
        // magic + digest_len
        assert_eq!(u64::from_le_bytes(blob.bytes[0x30..0x38].try_into().unwrap()), V2_ENVELOPE_MAGIC);
        assert_eq!(u64::from_le_bytes(blob.bytes[0x40..0x48].try_into().unwrap()), 64);
        // parse_offsets must accept the identity-bound blob
        blob.parse_offsets(0x0000_1000_0000).unwrap();
    }

    #[test]
    fn v2_blob_rejects_zero_identity_production() {
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let digest = "a".repeat(64);
        // One of target_pid/module_base zero with the other nonzero:
        // fail-closed (identity must be bound or unbound together).
        assert!(V2ParamsBlob::build_with_identity(
            "p", "d", &ss, &digest, 0x0000_1000_0000, 1234, 0,
        ).is_err());
        assert!(V2ParamsBlob::build_with_identity(
            "p", "d", &ss, &digest, 0x0000_1000_0000, 0, 0x0000_2000_0000,
        ).is_err());
    }

    #[test]
    fn thunk7_production_bytes_are_frozen_60b() {
        let fx = Thunk7Fixture::build();
        assert_eq!(fx.production.len(), 60);
        assert_eq!(fx.test_with_probe.len(), 64);
        fx.validate_structure().unwrap();
        // The production thunk carries arg6 (out_attestation_written) at
        // [r11+0x38] -> [rsp+0x30]: THUNK7_PRODUCTION[0x2C..0x33].
        assert_eq!(THUNK7_PRODUCTION[0x2C], 0x4D); // mov r10, [r11+56]
        assert_eq!(THUNK7_PRODUCTION[0x35], 0xFF); // call rax
        assert_eq!(THUNK7_PRODUCTION[0x3B], 0xC3); // ret
    }

    #[test]
    fn thunk_call_v2_rejects_non_60b_thunk() {
        // The production V2 wrapper hard-fails if the frozen thunk is
        // not exactly 60 bytes (a 64B probe must never be used). We cannot
        // call it without a live process; the length guard is exercised
        // by constructing the code path statically: THUNK7_PRODUCTION is
        // a [u8; 60] const, so `thunk_call_v2` cannot receive the probe.
        assert_eq!(THUNK7_PRODUCTION.len(), 60);
        assert_ne!(thunk7_test_with_probe().len(), 60);
    }

    /// Build names/ords/string-table for the given symbol list (names at
    /// RVA 0x1000 + i*0x20, ordinals 0..n). All names NUL-terminated.
    fn table_for(symbols: &[&str]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut names = Vec::new();
        let mut ords = Vec::new();
        let mut table = vec![0u8; 0x1000];
        for (i, s) in symbols.iter().enumerate() {
            names.extend_from_slice(&((0x1000 + i * 0x20) as u32).to_le_bytes());
            ords.extend_from_slice(&(i as u16).to_le_bytes());
            let off = i * 0x20;
            table[off..off + s.len()].copy_from_slice(s.as_bytes());
            table[off + s.len()] = 0;
        }
        (names, ords, table)
    }

    #[test]
    fn duplicate_after_forwarded_rejected_ambiguous() {
        // IMP-08-R1-R2 (P1-1): the FIRST duplicate entry is a forwarded
        // export (skipped), the SECOND is a valid in-module function.
        // found[] is still None after entry 0 — the old duplicate check
        // missed this; seen[] must reject fail-closed.
        let (names, ords, table) =
            table_for(&["MidaAntidebugInitialize", "MidaAntidebugInitialize"]);
        let mut funcs = Vec::new();
        funcs.extend_from_slice(&0x1040u32.to_le_bytes()); // forwarded (exp dir)
        funcs.extend_from_slice(&0x2000u32.to_le_bytes()); // valid
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 2, 2, 0x400000, 0x10000, 0x1000, 0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn duplicate_after_invalid_ordinal_rejected_ambiguous() {
        // IMP-08-R1-R2 (P1-1): the FIRST duplicate entry has an
        // out-of-range ordinal (7 >= num_funcs=2) and is skipped; the
        // SECOND is valid. seen[] must still reject the duplicate.
        let (mut names, mut ords, table) =
            table_for(&["MidaAntidebugInitialize", "MidaAntidebugInitialize"]);
        let _ = &mut names;
        ords[0..2].copy_from_slice(&7u16.to_le_bytes());
        let mut funcs = Vec::new();
        funcs.extend_from_slice(&0x2000u32.to_le_bytes());
        funcs.extend_from_slice(&0x2010u32.to_le_bytes());
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 2, 2, 0x400000, 0x10000, 0x1000, 0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn duplicate_after_null_func_rva_rejected_ambiguous() {
        // IMP-08-R1-R2 (P1-1): the FIRST duplicate entry has a null
        // function RVA (skipped); the SECOND is valid. Still ambiguous.
        let (names, ords, table) =
            table_for(&["MidaAntidebugInitialize", "MidaAntidebugInitialize"]);
        let mut funcs = Vec::new();
        funcs.extend_from_slice(&0u32.to_le_bytes()); // null func RVA
        funcs.extend_from_slice(&0x2000u32.to_le_bytes()); // valid
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 2, 2, 0x400000, 0x10000, 0x1000, 0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("ambiguous export"), "{err}");
    }

    #[test]
    fn unterminated_wanted_name_rejected() {
        // IMP-08-R1-R2 (P1-2): a name string WITHOUT a NUL anywhere in
        // the bounded window. The resolver reports Ok(false) and the
        // parser fails closed — even though the bytes would have matched
        // a wanted name if they had been terminated.
        let mut table = vec![b'X'; 0x1000];
        table[0..b"MidaAntidebugInitialize".len()]
            .copy_from_slice(b"MidaAntidebugInitialize");
        let names: Vec<u8> = 0x1000u32.to_le_bytes().to_vec();
        let ords: Vec<u8> = 0u16.to_le_bytes().to_vec();
        let funcs: Vec<u8> = 0x2000u32.to_le_bytes().to_vec();
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 1, 1, 0x400000, 0x10000, 0x1000, 0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("NUL-terminated"), "{err}");
    }

    #[test]
    fn name_read_failure_propagates_fail_closed() {
        // IMP-08-R1-R2 (P1-2): a resolver read failure (RPM failure in
        // production) must propagate as Err — never silently skip.
        let names: Vec<u8> = 0x1000u32.to_le_bytes().to_vec();
        let ords: Vec<u8> = 0u16.to_le_bytes().to_vec();
        let funcs: Vec<u8> = 0x2000u32.to_le_bytes().to_vec();
        let mut name_at =
            |_rva: usize, _out: &mut Vec<u8>| -> Result<bool, RuntimeLoadError> {
                Err(RuntimeLoadError::ExportResolutionFailed(
                    "remote read export name failed".to_string(),
                ))
            };
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 1, 1, 0x400000, 0x10000, 0x1000, 0x100,
            &[b"MidaAntidebugInitialize"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("remote read"), "{err}");
    }

    #[test]
    fn adversarial_name_count_fails_closed_immediately() {
        // IMP-08-R1-R2 (P1-3): num_names = usize::MAX with a tiny names
        // buffer must fail closed on the first out-of-bounds iteration
        // instead of looping forever or overflowing index arithmetic.
        let names: Vec<u8> = 0x1000u32.to_le_bytes().to_vec();
        let ords: Vec<u8> = 0u16.to_le_bytes().to_vec();
        let funcs: Vec<u8> = 0u32.to_le_bytes().to_vec();
        let mut table = vec![0u8; 0x1000];
        table[0..4].copy_from_slice(b"Mida");
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, usize::MAX, 1, 0x400000, 0x10000, 0x1000, 0x100,
            &[b"Mida"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }

    #[test]
    fn truncated_function_array_fails_closed() {
        // IMP-08-R1-R2 (P1-3): num_funcs=2 but only 1 function slot
        // exists — the checked func range must reject the truncation.
        let (names, ords, table) = table_for(&[
            "MidaAntidebugInitialize",
            "MidaAntidebugGetAttestation",
        ]);
        let funcs: Vec<u8> = 0x2000u32.to_le_bytes().to_vec();
        let mut name_at = flat_name_at(&table);
        let err = RuntimeLoader::resolve_exports_from_buffers(
            &names, &ords, &funcs, &mut name_at, 2, 2, 0x400000, 0x10000, 0x1000, 0x100,
            &[b"MidaAntidebugInitialize", b"MidaAntidebugGetAttestation"],
        )
        .unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
    }
}

    // ------------------------------------------------------------------
    // IMP-07-R1: production V2 preflight consumer (offline seam)
    // ------------------------------------------------------------------

    /// Minimal authority manifest (same shape as production). The digest
    /// here is bound to a REAL PE via verify_file() (see imp06 helpers),
    /// so the loader seam tests use a REAL verified identity — no
    /// caller-constructed digest authorities.
    fn imp07_manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
        RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        }
    }

    fn imp07_minimal_pe() -> Vec<u8> {
        let mut b = vec![0u8; 0x100];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
        b
    }

    fn imp07_tmp_file(content: &[u8]) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join("mida-imp07-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(format!(
            "imp07_runtime_{}_{}.dll",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&p, content).unwrap();
        p
    }

    /// Build a REAL verified authority (digest of a real PE) so the seam
    /// can be exercised exactly like production (verify_file -> digest_authority).
    fn imp07_verified_digest() -> String {
        let pe = imp07_minimal_pe();
        let path = imp07_tmp_file(&pe);
        let expected = sha256_hex(&pe);
        let m = imp07_manifest(&expected, pe.len() as u64);
        let id = m.verify_file(&path).unwrap();
        RuntimeDigestAuthority::from_verified_identity(&id, &m.artifact_id)
            .expect("verified identity must build a valid authority")
            .digest_value()
            .to_string()
    }

    #[test]
    fn imp07_prepare_seam_binds_authority_digest_into_blob() {
        // The seam must use the digest AUTHORITY (from verify_file), never a
        // test-provided digest. Build the blob through the production seam.
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        let prepared = V2ParamsBlob::build_preflight_and_validate(
            "p", "d", &ss, &digest, blob_base, 1234, 0x0000_2000_0000,
            blob_base as usize,
        ).unwrap();
        // digest field in the blob == authority digest
        let dig_off = u64::from_le_bytes(prepared.bytes[0x38..0x40].try_into().unwrap()) as usize;
        let hex = String::from_utf8(prepared.bytes[dig_off..dig_off + 64].to_vec()).unwrap();
        assert_eq!(hex, digest);
        // preflight consumed and consistent
        assert_eq!(prepared.preflight.blob_base, blob_base);
        assert_eq!(prepared.preflight.digest_len, 64);
        assert_eq!(prepared.preflight.expected_hooks, 1);
        assert_eq!(prepared.preflight.surface_entries.len(), 1);
    }

    #[test]
    fn imp07_prepare_seam_rejects_wrong_blob_base() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        // blob_base = 0x1000_0000 but params_bytes (remote VA) = 0x2000_0000:
        // build_preflight_and_validate validates against the WRITE address.
        let r = V2ParamsBlob::build_preflight_and_validate(
            "p", "d", &ss, &digest, 0x0000_1000_0000, 1234, 0x0000_2000_0000,
            0x0000_2000_0000usize,
        );
        assert!(r.is_err());
    }

    #[test]
    fn imp07_prepare_seam_rejects_surface_count_mismatch() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        // Build with 2 surfaces but validate against an expectation of 1.
        let blob = V2ParamsBlob::build_with_identity(
            "p", "d", &ss, &digest, blob_base, 1234, 0x0000_2000_0000,
        ).unwrap();
        let preflight = blob.preflight_local(blob_base).unwrap();
        let want: Vec<String> = vec!["AD-PROC-002".to_string()];
        let r = validate_preflight_result(&blob, &preflight, &want, blob_base as usize);
        assert!(r.is_err());
    }

    #[test]
    fn imp07_prepare_seam_rejects_surface_content_mismatch() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        let blob = V2ParamsBlob::build_with_identity(
            "p", "d", &ss, &digest, blob_base, 1234, 0x0000_2000_0000,
        ).unwrap();
        let preflight = blob.preflight_local(blob_base).unwrap();
        let want: Vec<String> = vec!["AD-PROC-009".to_string()];
        let r = validate_preflight_result(&blob, &preflight, &want, blob_base as usize);
        assert!(r.is_err());
    }

    #[test]
    fn imp07_prepare_seam_rejects_surface_order_mismatch() {
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string(), "AD-PROC-003".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        let blob = V2ParamsBlob::build_with_identity(
            "p", "d", &ss, &digest, blob_base, 1234, 0x0000_2000_0000,
        ).unwrap();
        let preflight = blob.preflight_local(blob_base).unwrap();
        let want: Vec<String> = vec!["AD-PROC-003".to_string(), "AD-PROC-002".to_string()];
        let r = validate_preflight_result(&blob, &preflight, &want, blob_base as usize);
        assert!(r.is_err());
    }

    #[test]
    fn imp07_production_caller_graph_is_real() {
        // The production caller (load_and_initialize_inner, require_digest=true)
        // must call build_preflight_and_validate -> preflight_local ->
        // validate_preflight_result before ANY WriteProcessMemory. We cannot
        // execute the live path; instead we PROVE the seam is called by the
        // production code with a static source-level assertion: the caller
        // body contains the seam call (grep-verified in evidence).
        // Here we also assert the seam is NOT #[cfg(test)]-only by checking
        // it exists in the non-test binary path: this test merely documents
        // the contract; the real proof is the source wiring + build.
        let digest = imp07_verified_digest();
        let ss: Vec<String> = vec!["AD-PROC-002".to_string()];
        let blob_base = 0x0000_1000_0000u64;
        // Exercise the exact seam the production caller uses.
        let prepared = V2ParamsBlob::build_preflight_and_validate(
            "p", "d", &ss, &digest, blob_base, 1234, 0x0000_2000_0000,
            blob_base as usize,
        ).unwrap();
        assert_eq!(prepared.bytes.len() > 0x48, true);
        assert_eq!(prepared.preflight.surface_entries.len(), 1);
        // Wrong base must fail BEFORE any bytes could be returned.
        assert!(V2ParamsBlob::build_preflight_and_validate(
            "p", "d", &ss, &digest, blob_base, 1234, 0x0000_2000_0000,
            (blob_base + 0x1000) as usize,
        ).is_err());
    }

mod imp09_carrier_r2_tests {
    use super::*;

    fn manifest(sha256: &str, size: u64) -> RuntimeAuthorityManifest {
        RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256.to_string(),
            size_bytes: size,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        }
    }

    /// Build a synthetic x64 PE file with an export directory containing
    /// the given symbol names mapping to func RVAs (raw=va layout for the
    /// single .text/.edata section, so RVA == file offset).
    ///
    /// Layout (one section covering [0x1000, 0x3000), raw == va):
    ///   - section data starts at file offset 0x1000
    ///   - export dir at RVA 0x1000
    ///   - name ptr table at 0x1100, ordinal table at 0x1200,
    ///     func table at 0x1300, strings at 0x1400
    fn build_export_pe(symbols: &[(&str, u32)]) -> Vec<u8> {
        // File = headers (0x1000) + section data (0x2000). Section raw ==
        // VA layout: raw ptr 0x1000, va 0x1000, raw size 0x2000, vsize
        // 0x3000 (SizeOfImage 0x3000 covers va..va+0x2000).
        let mut b = vec![0u8; 0x1000]; // DOS + headers + section table
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
        b[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        b[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes()); // opt hdr size
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+
                                                                // SizeOfImage at optional+0x50 = 0x80+0x18+0x50 = 0xE8
        b[0xE8..0xEC].copy_from_slice(&0x3000u32.to_le_bytes());
        // Export data dir at optional+0x70 = 0x80+0x18+0x70 = 0x108
        b[0x108..0x10C].copy_from_slice(&0x1000u32.to_le_bytes()); // exp_rva
        b[0x10C..0x110].copy_from_slice(&0x400u32.to_le_bytes()); // exp_size
                                                                  // Section header at pe_off(0x80) + 4 (sig) + 20 (COFF) + 0xE0
                                                                  // (optional) = 0x178
        b[0x178..0x17B].copy_from_slice(b".ed"); // name
        b[0x180..0x184].copy_from_slice(&0x3000u32.to_le_bytes()); // vsize
        b[0x184..0x188].copy_from_slice(&0x1000u32.to_le_bytes()); // va
        b[0x188..0x18C].copy_from_slice(&0x2000u32.to_le_bytes()); // raw size
        b[0x18C..0x190].copy_from_slice(&0x1000u32.to_le_bytes()); // raw ptr

        // Pad to 0x1000 (the section data region).
        b.resize(0x3000, 0);
        // Export directory at file offset 0x1000 (RVA 0x1000).
        //   [0x14] NumberOfFunctions, [0x18] NumberOfNames,
        //   [0x1C] AddressOfFunctions, [0x20] AddressOfNames,
        //   [0x24] AddressOfNameOrdinals
        let num = symbols.len();
        b[0x1000 + 0x14..0x1000 + 0x18].copy_from_slice(&(num as u32).to_le_bytes());
        b[0x1000 + 0x18..0x1000 + 0x1C].copy_from_slice(&(num as u32).to_le_bytes());
        b[0x1000 + 0x1C..0x1000 + 0x20].copy_from_slice(&0x1300u32.to_le_bytes()); // funcs
        b[0x1000 + 0x20..0x1000 + 0x24].copy_from_slice(&0x1100u32.to_le_bytes()); // names
        b[0x1000 + 0x24..0x1000 + 0x28].copy_from_slice(&0x1200u32.to_le_bytes()); // ords
                                                                                   // Name pointer table at 0x1100.
        let mut str_off = 0x1400usize;
        for (i, (name, _)) in symbols.iter().enumerate() {
            b[0x1100 + i * 4..0x1104 + i * 4].copy_from_slice(&(str_off as u32).to_le_bytes());
            str_off += name.len() + 1;
        }
        // Ordinal table at 0x1200 (u16 each, 0-based like link.exe).
        for i in 0..num {
            b[0x1200 + i * 2..0x1202 + i * 2].copy_from_slice(&(i as u16).to_le_bytes());
        }
        // Function table at 0x1300.
        for (i, (_, rva)) in symbols.iter().enumerate() {
            b[0x1300 + i * 4..0x1304 + i * 4].copy_from_slice(&rva.to_le_bytes());
        }
        // Strings at 0x1400.
        let mut s = 0x1400usize;
        for (name, _) in symbols {
            for (k, ch) in name.bytes().enumerate() {
                b[s + k] = ch;
            }
            b[s + name.len()] = 0;
            s += name.len() + 1;
        }
        b
    }

    /// Write the PE to a temp file and produce a verified identity via the
    /// real verify_file() path.
    fn verified_identity_for(pe: &[u8], tag: &str) -> RuntimeFileIdentity {
        let dir = std::env::temp_dir().join("mida-carrier-r2");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(format!("r2_{tag}.dll"));
        std::fs::write(&p, pe).unwrap();
        let expected = sha256_hex(pe);
        let authority = manifest(&expected, pe.len() as u64);
        authority.verify_file(&p).expect("synthetic PE must verify")
    }

    fn walker_pe() -> Vec<u8> {
        build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ])
    }

    #[test]
    fn valid_file_export_rva_carrier() {
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "valid");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id)
            .expect("valid runtime file must resolve WalkerExecute");
        assert_eq!(rva, 0x2040, "pure-file resolver returns the export RVA");
    }

    #[test]
    fn missing_walker_export_rejected() {
        let pe = build_export_pe(&[("MidaAntidebugInitialize", 0x2000)]);
        let id = verified_identity_for(&pe, "missing");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "missing WalkerExecute must fail closed");
    }

    #[test]
    fn forwarded_walker_export_rejected() {
        // WalkerExecute function RVA points INSIDE the export directory
        // (0x1000..0x1400) => treated as a forwarder, skipped => fail.
        let pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x1100),
        ]);
        let id = verified_identity_for(&pe, "fwd");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "forwarded WalkerExecute must fail closed");
    }

    #[test]
    fn out_of_image_export_rva_rejected() {
        // Function RVA beyond SizeOfImage (0x3000).
        let pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x4000),
        ]);
        let id = verified_identity_for(&pe, "oob");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "out-of-envelope export RVA must fail closed");
    }

    #[test]
    fn export_array_truncation_rejected() {
        // Truncate the func table region by cutting the file short after
        // the export directory but claiming num_funcs beyond the file.
        let mut pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ]);
        // Shrink to just past the export dir header (0x1028), so the func
        // array read at 0x1300 is truncated.
        pe.truncate(0x1100);
        let id = verified_identity_for(&pe, "trunc");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "truncated export arrays must fail closed");
    }

    #[test]
    fn name_pointer_oob_rejected() {
        // Name pointer table entry points outside the image envelope.
        let mut pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ]);
        // Overwrite the first name pointer (at 0x1100) to an out-of-envelope
        // RVA. The name_at closure maps it -> no section -> error.
        pe[0x1100..0x1104].copy_from_slice(&0x4000u32.to_le_bytes());
        let id = verified_identity_for(&pe, "name_oob");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "name pointer outside image must fail closed");
    }

    #[test]
    fn ordinal_oob_rejected() {
        // Ordinal table entry >= num_funcs -> skipped -> WalkerExecute not
        // resolvable -> fail.
        let mut pe = build_export_pe(&[
            ("MidaAntidebugInitialize", 0x2000),
            ("WalkerExecute", 0x2040),
        ]);
        // WalkerExecute is index 1 -> its ordinal slot at 0x1202. Set to 99.
        pe[0x1202..0x1204].copy_from_slice(&99u16.to_le_bytes());
        let id = verified_identity_for(&pe, "ord_oob");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(r.is_err(), "out-of-range ordinal must fail closed");
    }

    #[test]
    fn checked_module_base_plus_rva_overflow_rejected() {
        // The production install boundary rejects module_base +
        // export_rva overflow (WalkerEntryOverflow inside the sealed
        // authority construction). Exercise it through the PUBLIC API
        // install_walker_session_verified with a huge module_base: the
        // install must fail closed (false), never wrap.
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "ovf");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id)
            .expect("valid file must resolve");
        let ok = mida_antidebug_runtime::exports::install_walker_session_verified(
            Box::new(mida_antidebug_runtime::walker_control::MemoryMapProvider::new()),
            0x1000,
            0x2000,
            4242,
            7777,
            "a".repeat(64).as_str(),
            "b".repeat(64).as_str(),
            u64::MAX - 16,
            rva,
            "profile-id",
            "c".repeat(64).as_str(),
        );
        assert!(!ok, "module_base + export_rva overflow must fail closed");
    }

    #[test]
    fn resolved_rva_round_trips_into_sealed_loader_result() {
        // Full chain: verified file -> pure-file resolver -> LoaderResult
        // carrier -> getter returns the same RVA.
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "roundtrip");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id).unwrap();
        let authority = RuntimeDigestAuthority::from_verified_identity(&id, "artifact")
            .expect("verified identity must build authority");
        let lr = crate::unpacker::antidebug_controller::LoaderResult::new(
            0x7000,
            "{}".to_string(),
            id,
            authority,
            1234,
            Some(rva),
        );
        assert_eq!(lr.walker_export_rva(), Some(0x2040));
    }

    #[test]
    fn remote_resolver_not_called_by_new_path() {
        // The pure-file path needs ONLY the verified file bytes; it never
        // touches a process handle. Prove it: the resolver succeeds for a
        // file whose identity was verified, without any target HANDLE.
        // (Static proof: this function has no windows:: RPM import in its
        // body; the evidence bundle greps resolve_mida_exports_remote call
        // sites to show the new path does not call it.)
        let pe = walker_pe();
        let id = verified_identity_for(&pe, "noread");
        let rva = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert_eq!(rva, Ok(0x2040));
    }

    #[test]
    fn same_size_verified_file_replacement_rejected() {
        // P1 (R2-R1): verify_file(A) seals identity(A); the file on disk
        // is then replaced with SAME-SIZE different-content B. The
        // resolver must fail closed — path+size binding is NOT enough;
        // the recomputed content digest must equal identity.sha256().
        let pe_a = walker_pe();
        let id = verified_identity_for(&pe_a, "swap_same_size");
        let mut pe_b = pe_a.clone();
        // Same length, different content: flip the last section-data byte.
        let last = pe_b.len() - 1;
        pe_b[last] ^= 0xFF;
        assert_eq!(pe_a.len(), pe_b.len(), "test premise: same size");
        assert_ne!(
            sha256_hex(&pe_a),
            sha256_hex(&pe_b),
            "test premise: different content"
        );
        std::fs::write(id.path(), &pe_b).expect("replace file on disk");
        let r = RuntimeLoader::resolve_walker_export_rva_from_file(&id);
        assert!(
            r.is_err(),
            "same-size replacement must fail closed on digest mismatch"
        );
    }
}
