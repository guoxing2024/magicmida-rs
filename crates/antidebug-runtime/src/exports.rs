//! C ABI export surface (ADR-4).
//!
//! Stable, minimal exports:
//!
//! - [`MidaAntidebugInitialize`] - one-shot initialize;
//! - [`MidaAntidebugGetAttestation`] - copy the attestation JSON into a
//!   caller buffer;
//! - [`MidaAntidebugShutdown`] - shutdown / cleanup.
//!
//! ABI rules (ADR-4 section 2):
//! - C ABI (`extern "C"`);
//! - explicit buffer rules (size in/out);
//! - structured error codes (never pass Rust panics across FFI);
//! - clear calling-thread constraint: all exports must be called from the
//!   same thread that initialized the runtime (single-threaded protocol);
//! - clear lifecycle: Initialize -> GetAttestation* -> Shutdown;
//! - target identity: MidaInitParams carries target_pid + module_base; both
//!   must be non-zero and are bound into the attestation (ADR-4-CORRECTION);
//! - no dangling pointers: every output is copied into a caller-owned buffer;
//! - panics are caught at the FFI boundary and converted to
//!   [`MidaAntidebugError::InternalPanic`].

use std::sync::OnceLock;

use crate::attestation::{RuntimeAttestation, SurfaceDetail};
use crate::provenance::Provenance;
use crate::surfaces::{
    install_proc_surfaces, restore_proc_002, SURFACE_AD_PROC_002, SURFACE_AD_PROC_003,
};
use crate::telemetry::TelemetryChannel;

/// Attestation JSON buffer size for the FFI handshake.
pub const ATTESTATION_BUFFER_SIZE: usize = 8192;
/// Hard cap on attestation bytes accepted from the runtime.
pub const MAX_ATTESTATION_BYTES: usize = 16384;

/// Structured C ABI error codes (stable).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MidaAntidebugError {
    Ok = 0,
    /// Runtime already initialized (repeat init is an error).
    AlreadyInitialized = 1,
    /// Runtime not initialized yet (query before init).
    NotInitialized = 2,
    /// Invalid argument (null pointer, bad length).
    InvalidArgument = 3,
    /// Buffer too small for the attestation JSON.
    BufferTooSmall = 4,
    /// Runtime already shut down (or shutdown requested twice).
    AlreadyShutdown = 5,
    /// Internal serialization failure.
    Serialization = 6,
    /// A Rust panic was caught at the FFI boundary.
    InternalPanic = 7,
    /// Architecture mismatch (runtime built for another target).
    ArchitectureMismatch = 8,
    /// One or more hard-required surfaces failed to install (ADR-5).
    SurfaceInstallFailed = 9,
    /// Surface restoration failed during shutdown (ADR-5).
    RestoreFailed = 10,
    /// V2 params blob is malformed (bad magic, offsets, digest, or bounds).
    InvalidV2Blob = 11,
    /// V2 digest echo buffer too small for the 64-hex digest.
    EchoBufferTooSmall = 12,
    /// Export exists but the production path is not yet implemented (IMP-09).
    NotImplemented = 13,
}

impl MidaAntidebugError {
    pub const fn as_i32(self) -> i32 {
        self as i32
    }

    pub const fn name(self) -> &'static str {
        match self {
            MidaAntidebugError::Ok => "Ok",
            MidaAntidebugError::AlreadyInitialized => "AlreadyInitialized",
            MidaAntidebugError::NotInitialized => "NotInitialized",
            MidaAntidebugError::InvalidArgument => "InvalidArgument",
            MidaAntidebugError::BufferTooSmall => "BufferTooSmall",
            MidaAntidebugError::AlreadyShutdown => "AlreadyShutdown",
            MidaAntidebugError::Serialization => "Serialization",
            MidaAntidebugError::InternalPanic => "InternalPanic",
            MidaAntidebugError::ArchitectureMismatch => "ArchitectureMismatch",
            MidaAntidebugError::SurfaceInstallFailed => "SurfaceInstallFailed",
            MidaAntidebugError::RestoreFailed => "RestoreFailed",
            MidaAntidebugError::InvalidV2Blob => "InvalidV2Blob",
            MidaAntidebugError::EchoBufferTooSmall => "EchoBufferTooSmall",
            MidaAntidebugError::NotImplemented => "NotImplemented",
        }
    }
}

/// Initialize parameters (profile binding).
#[repr(C)]
#[derive(Debug, Clone)]
pub struct MidaInitParams {
    /// Target process id the runtime is bound to.
    pub target_pid: u32,
    /// Base address of the loaded runtime module inside the target process
    /// (resolved by the controller/injector; must be non-zero).
    pub module_base: u64,
    /// Profile id chosen by the controller (runtime must not modify).
    pub profile_id: *const std::os::raw::c_char,
    /// Profile digest chosen by the controller (runtime must not modify).
    pub profile_digest: *const std::os::raw::c_char,
    /// Number of expected hook surfaces.
    pub expected_hooks: usize,
    /// Pointer to the expected surface id array (count = expected_hooks).
    pub expected_surfaces: *const *const std::os::raw::c_char,
}

/// The runtime handle (opaque).
pub struct RuntimeHandle {
    pub attestation: RuntimeAttestation,
    pub provenance: Provenance,
    pub telemetry: TelemetryChannel,
    pub shutdown_requested: bool,
    /// Surface installation outcomes (ADR-5).
    pub surface_details: Vec<SurfaceDetail>,
    /// Original BeingDebugged value for shutdown restoration (ADR-5).
    pub original_being_debugged: Option<String>,
    /// Original pShimData value for shutdown restoration (ADR-5-CORRECTION).
    pub original_shim_data: Option<String>,
}

/// Global runtime state (single instance, single thread).
static RUNTIME: OnceLock<RuntimeHandle> = OnceLock::new();

/// Build the attestation JSON for the FFI handshake.
pub fn build_attestation_json(
    runtime_sha256: String,
    profile_id: String,
    profile_digest: String,
    target_pid: u32,
    module_base: u64,
    expected_surfaces: &[String],
    source_revision: String,
    toolchain: String,
) -> Result<String, MidaAntidebugError> {
    let att = RuntimeAttestation::foundation(
        runtime_sha256,
        profile_id,
        profile_digest,
        target_pid,
        module_base,
        expected_surfaces,
        source_revision,
        toolchain,
    );
    att.to_canonical_json()
        .map_err(|_| MidaAntidebugError::Serialization)
}

/// Build the attestation from surface outcomes (ADR-5).
fn build_attestation_from_outcomes(
    runtime_sha256: String,
    profile_id: String,
    profile_digest: String,
    target_pid: u32,
    module_base: u64,
    expected_surfaces: &[String],
    installed: &[String],
    failures: &[(String, String)],
    surface_details: Vec<SurfaceDetail>,
) -> Result<RuntimeAttestation, MidaAntidebugError> {
    Ok(RuntimeAttestation::from_surfaces(
        runtime_sha256,
        profile_id,
        profile_digest,
        target_pid,
        module_base,
        expected_surfaces,
        installed,
        failures,
        surface_details,
        env!("CARGO_PKG_VERSION").to_string(),
        "rustc".to_string(),
    ))
}

/// C ABI: initialize the runtime.
///
/// # Safety
/// - `profile_id` / `profile_digest` must be valid NUL-terminated UTF-8 strings;
/// - `expected_surfaces` must point to `expected_hooks` valid string pointers;
/// - must be called once from a single thread;
/// - panics are caught and reported as [`MidaAntidebugError::InternalPanic`].
#[no_mangle]
pub unsafe extern "C" fn MidaAntidebugInitialize(
    params: *const MidaInitParams,
    out_runtime_sha256: *mut u8,
    out_runtime_sha256_len: usize,
    out_attestation_json: *mut u8,
    out_attestation_len: usize,
    out_attestation_written: *mut usize,
) -> i32 {
    std::panic::catch_unwind(|| {
        initialize_inner(
            params,
            out_runtime_sha256,
            out_runtime_sha256_len,
            out_attestation_json,
            out_attestation_len,
            out_attestation_written,
        )
    })
    .unwrap_or(MidaAntidebugError::InternalPanic.as_i32())
}

fn initialize_inner(
    params: *const MidaInitParams,
    out_runtime_sha256: *mut u8,
    out_runtime_sha256_len: usize,
    out_attestation_json: *mut u8,
    out_attestation_len: usize,
    out_attestation_written: *mut usize,
) -> i32 {
    if RUNTIME.get().is_some() {
        return MidaAntidebugError::AlreadyInitialized.as_i32();
    }
    if params.is_null()
        || out_attestation_json.is_null()
        || out_attestation_written.is_null()
        || out_attestation_len == 0
    {
        return MidaAntidebugError::InvalidArgument.as_i32();
    }
    // SAFETY: validated pointers above; caller contract requires valid strings.
    let p = unsafe { &*params };
    if p.target_pid == 0 || p.module_base == 0 {
        // Target identity binding: zero PID / module base is invalid.
        return MidaAntidebugError::InvalidArgument.as_i32();
    }
    let profile_id = unsafe { read_cstr(p.profile_id) }.unwrap_or_default();
    let profile_digest = unsafe { read_cstr(p.profile_digest) }.unwrap_or_default();
    let mut expected = Vec::new();
    if !p.expected_surfaces.is_null() && p.expected_hooks > 0 {
        // SAFETY: caller contract guarantees expected_hooks valid pointers.
        for i in 0..p.expected_hooks {
            let sp = unsafe { *p.expected_surfaces.add(i) };
            expected.push(unsafe { read_cstr(sp) }.unwrap_or_default());
        }
    }
    // Runtime artifact identity (self-hash placeholder until build-time binding;
    // the controller re-verifies the loaded module hash independently).
    let runtime_sha256 = "adr4-foundation-unbound".to_string();
    // ADR-5: install hard-required PEB surfaces against the target process.
    // The Win32PebMemory view reads the real PEB via gs:[0x60]; on failure
    // the attestation reports the failure and the controller fails closed.
    let real_peb = crate::surfaces::Win32PebMemory::new(p.target_pid);
    let (outcomes, failures) = match install_proc_surfaces(
        &real_peb,
        crate::surfaces::POINTER_SIZE_X64,
        p.target_pid,
        p.target_pid,
        &profile_digest,
        &profile_digest,
    ) {
        Ok(v) => v,
        Err(_) => {
            // Surface-level fatal (e.g. wrong pointer size): fail closed.
            return MidaAntidebugError::SurfaceInstallFailed.as_i32();
        }
    };
    let installed: Vec<String> = outcomes
        .iter()
        .filter(|o| o.installed)
        .map(|o| o.surface_id.clone())
        .collect();
    let fail_pairs: Vec<(String, String)> = failures
        .iter()
        .map(|f| (f.surface_id.clone(), f.error.clone().unwrap_or_default()))
        .collect();
    let details: Vec<SurfaceDetail> = outcomes
        .iter()
        .map(|o| SurfaceDetail {
            surface_id: o.surface_id.clone(),
            installed: o.installed,
            original_value: o.original_value.clone(),
            effective_value: o.effective_value.clone(),
            restoration_policy: format!("{:?}", o.restoration_policy),
            restore_result: format!("{:?}", o.restore_result),
            error: o.error.clone(),
        })
        .collect();
    let original_bd: Option<String> = outcomes
        .iter()
        .find(|o| o.surface_id == SURFACE_AD_PROC_002)
        .and_then(|o| o.original_value.clone());
    let original_shim: Option<String> = outcomes
        .iter()
        .find(|o| o.surface_id == SURFACE_AD_PROC_003)
        .and_then(|o| o.original_value.clone());
    // expected set for attestation = hard-required surfaces only (002, 003);
    // AD-PROC-001 stays a candidate and is NOT part of hooks_expected.
    let expected_hard: Vec<String> = expected
        .iter()
        .filter(|s| s.as_str() == SURFACE_AD_PROC_002 || s.as_str() == SURFACE_AD_PROC_003)
        .cloned()
        .collect();
    let att = match build_attestation_from_outcomes(
        runtime_sha256.clone(),
        profile_id.clone(),
        profile_digest.clone(),
        p.target_pid,
        p.module_base,
        &expected_hard,
        &installed,
        &fail_pairs,
        details,
    ) {
        Ok(a) => a,
        Err(e) => return e.as_i32(),
    };
    let att_json = match att.to_canonical_json() {
        Ok(j) => j,
        Err(_) => return MidaAntidebugError::Serialization.as_i32(),
    };
    if att_json.len() > out_attestation_len {
        return MidaAntidebugError::BufferTooSmall.as_i32();
    }
    // Copy runtime sha256
    if !out_runtime_sha256.is_null() && out_runtime_sha256_len > 0 {
        let bytes = runtime_sha256.as_bytes();
        let n = bytes.len().min(out_runtime_sha256_len);
        // SAFETY: validated output buffer.
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_runtime_sha256, n) };
    }
    // Copy attestation JSON
    let bytes = att_json.as_bytes();
    // SAFETY: validated output buffer; size checked above.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_attestation_json, bytes.len()) };
    // SAFETY: validated output pointer.
    unsafe { *out_attestation_written = bytes.len() };
    // Build the telemetry channel bound to PID + digest (attestation carries
    // the same target_pid / module_base identity).
    let telemetry = TelemetryChannel::new(
        format!("mida-adr4-{}", p.target_pid),
        p.target_pid,
        profile_digest.clone(),
    );
    let handle = RuntimeHandle {
        attestation: att,
        provenance: Provenance::current(
            runtime_sha256,
            0,
            "rustc".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        telemetry,
        shutdown_requested: false,
        surface_details: Vec::new(),
        original_being_debugged: original_bd,
        original_shim_data: original_shim,
    };
    // SAFETY: single-threaded init contract; set() fails only if already set
    // which we checked above.
    let _ = RUNTIME.set(handle);
    // SAFETY: set succeeded; get() is Some.
    RUNTIME
        .get()
        .expect("runtime set above")
        .telemetry
        .mark_ready()
        .expect("telemetry mark ready");
    MidaAntidebugError::Ok.as_i32()
}

/// C ABI: copy the attestation JSON into a caller buffer.
///
/// # Safety
/// - `out_buf` must be valid for `buf_len` bytes when non-null.
#[no_mangle]
pub unsafe extern "C" fn MidaAntidebugGetAttestation(
    out_buf: *mut u8,
    buf_len: usize,
    out_written: *mut usize,
) -> i32 {
    std::panic::catch_unwind(|| get_attestation_inner(out_buf, buf_len, out_written))
        .unwrap_or(MidaAntidebugError::InternalPanic.as_i32())
}

fn get_attestation_inner(out_buf: *mut u8, buf_len: usize, out_written: *mut usize) -> i32 {
    let Some(handle) = RUNTIME.get() else {
        return MidaAntidebugError::NotInitialized.as_i32();
    };
    if handle.shutdown_requested {
        return MidaAntidebugError::AlreadyShutdown.as_i32();
    }
    if out_buf.is_null() || out_written.is_null() || buf_len == 0 {
        return MidaAntidebugError::InvalidArgument.as_i32();
    }
    let json = match handle.attestation.to_canonical_json() {
        Ok(j) => j,
        Err(_) => return MidaAntidebugError::Serialization.as_i32(),
    };
    if json.len() > buf_len {
        return MidaAntidebugError::BufferTooSmall.as_i32();
    }
    let bytes = json.as_bytes();
    // SAFETY: validated buffer; size checked above.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len()) };
    // SAFETY: validated output pointer.
    unsafe { *out_written = bytes.len() };
    MidaAntidebugError::Ok.as_i32()
}

/// C ABI: shutdown the runtime (idempotent second call reports AlreadyShutdown).
///
/// # Safety
/// - No pointer arguments; safe to call once from the initializing thread.
#[no_mangle]
pub unsafe extern "C" fn MidaAntidebugShutdown() -> i32 {
    std::panic::catch_unwind(shutdown_inner).unwrap_or(MidaAntidebugError::InternalPanic.as_i32())
}

fn shutdown_inner() -> i32 {
    let Some(handle) = RUNTIME.get() else {
        return MidaAntidebugError::NotInitialized.as_i32();
    };
    if handle.shutdown_requested {
        return MidaAntidebugError::AlreadyShutdown.as_i32();
    }
    // ADR-5: restore modified PEB surfaces before shutdown.
    if let Some(orig) = &handle.original_being_debugged {
        let real_peb = crate::surfaces::Win32PebMemory::new(handle.attestation.target_pid);
        match crate::surfaces::PebView::resolve(
            &real_peb,
            handle.attestation.target_pid,
            crate::surfaces::POINTER_SIZE_X64,
        ) {
            Ok(view) => match restore_proc_002(&view, &real_peb, Some(orig.clone())) {
                Ok(_) => {}
                Err(er) => {
                    let _ = handle.telemetry.report_surface_restore(
                        SURFACE_AD_PROC_002,
                        "Failed",
                        Some(er.to_string()),
                    );
                    return MidaAntidebugError::RestoreFailed.as_i32();
                }
            },
            Err(er) => {
                let _ = handle.telemetry.report_surface_restore(
                    SURFACE_AD_PROC_002,
                    "Failed",
                    Some(er.to_string()),
                );
                return MidaAntidebugError::RestoreFailed.as_i32();
            }
        }
    }
    // ADR-5-CORRECTION: restore original pShimData before shutdown.
    if let Some(orig) = &handle.original_shim_data {
        let real_peb = crate::surfaces::Win32PebMemory::new(handle.attestation.target_pid);
        match crate::surfaces::PebView::resolve(
            &real_peb,
            handle.attestation.target_pid,
            crate::surfaces::POINTER_SIZE_X64,
        ) {
            Ok(view) => {
                match crate::surfaces::restore_proc_003(&view, &real_peb, Some(orig.clone())) {
                    Ok(_) => {}
                    Err(er) => {
                        let _ = handle.telemetry.report_surface_restore(
                            SURFACE_AD_PROC_003,
                            "Failed",
                            Some(er.to_string()),
                        );
                        return MidaAntidebugError::RestoreFailed.as_i32();
                    }
                }
            }
            Err(er) => {
                let _ = handle.telemetry.report_surface_restore(
                    SURFACE_AD_PROC_003,
                    "Failed",
                    Some(er.to_string()),
                );
                return MidaAntidebugError::RestoreFailed.as_i32();
            }
        }
    }
    // Close telemetry channel.
    let _ = handle.telemetry.close();
    // Mark shutdown (OnceLock cannot be cleared; the flag is the lifecycle gate).
    // SAFETY: single-threaded protocol; no concurrent access.
    unsafe {
        let ptr = std::ptr::addr_of!(handle.shutdown_requested) as *mut bool;
        *ptr = true;
    }
    MidaAntidebugError::Ok.as_i32()
}


// ============================================================================
// IMP-08: MidaAntidebugInitializeV2 (7-arg ABI, digest channel)
// ============================================================================
//
// Frozen ABI (WO-1505 §5.3 / IMPLEMENTATION_PHASE04A_READINESS):
//
//   MidaAntidebugInitializeV2(
//       const uint8_t* params,        // v2 params blob (self-relative layout)
//       size_t         params_bytes,  // blob length (bounded)
//       uint8_t*       out_runtime_sha256,    // 64-hex digest echo
//       size_t         out_runtime_sha256_len,// capacity (>= 64)
//       uint8_t*       out_attestation_json,  // attestation output
//       size_t         out_attestation_len,   // capacity
//       size_t*        out_attestation_written)
//
// The params blob uses the SAME frozen layout as loader-side
// V2ParamsBlob::build (WO-1505 §5.3a/§5.3e, RC-4):
//   [0x10] profile_id_off        self-relative
//   [0x18] profile_digest_off    self-relative
//   [0x20] expected_hooks        u64
//   [0x28] expected_surfaces_off self-relative (pointer array start)
//   [0x30] magic_v2              0x003250324144494D ("MIDA2P2\0" LE)
//   [0x38] digest_off            self-relative (64 hex + NUL)
//   [0x40] digest_len            field value MUST be 64
//
// All offsets are relative to the blob start; all arithmetic is checked;
// all string scans are bounded NUL scans (fail-closed). The digest is
// validated (64 lowercase hex) and becomes the attestation
// runtime_sha256 (replacing the v1 placeholder), then the SAME digest is
// echoed through out_runtime_sha256 for the controller to verify
// (echo == attestation.runtime_sha256 == digest_controller).

/// V2 params blob header magic ("MIDA2P2\0" LE) - matches loader side.
pub const V2_ENVELOPE_MAGIC: u64 = 0x0032_5032_4144_494D;
/// V2 params blob fixed header size.
pub const V2_HEADER_BYTES: usize = 0x48;
/// V2 digest_len field value (64 hex chars; frozen ABI).
pub const V2_DIGEST_LEN: u64 = 64;
/// V2 digest wire region bytes (64 hex + NUL).
pub const V2_DIGEST_REGION_BYTES: u64 = 65;
/// Max surface count (frozen ABI; builder rejects > 256).
pub const V2_MAX_HOOKS: u64 = 256;

/// Checked u64 addition used by the v2 blob parser (fail-closed).
fn v2_checked_add(a: usize, b: usize, what: &str) -> Result<usize, MidaAntidebugError> {
    a.checked_add(b).ok_or_else(|| {
        let _ = what;
        MidaAntidebugError::InvalidV2Blob
    })
}

/// Checked blob end (blob_base + params_bytes), fail-closed.
fn checked_blob_end(blob_base: usize, params_bytes: usize) -> Result<usize, MidaAntidebugError> {
    blob_base.checked_add(params_bytes).ok_or(MidaAntidebugError::InvalidV2Blob)
}

/// Bounded NUL-terminated string read from a blob slice (fail-closed).
fn v2_read_cstr_blob(blob: &[u8], off: usize, what: &str) -> Result<String, MidaAntidebugError> {
    if off >= blob.len() {
        return Err(MidaAntidebugError::InvalidV2Blob);
    }
    let mut end = off;
    while end < blob.len() && blob[end] != 0 {
        end += 1;
        if end - off > 4096 {
            return Err(MidaAntidebugError::InvalidV2Blob); // unbounded scan
        }
    }
    if end >= blob.len() || blob[end] != 0 {
        return Err(MidaAntidebugError::InvalidV2Blob); // missing NUL
    }
    let s = std::str::from_utf8(&blob[off..end])
        .map_err(|_| MidaAntidebugError::InvalidV2Blob)?;
    let _ = what;
    Ok(s.to_string())
}

/// C ABI: initialize the runtime with a v2 params blob (7-arg).
///
/// # Safety
/// - `params` must be valid for `params_bytes` readable bytes;
/// - output pointers must be valid for their lengths;
/// - must be called once from a single thread;
/// - panics are caught and reported as [`MidaAntidebugError::InternalPanic`].
#[no_mangle]
pub unsafe extern "C" fn MidaAntidebugInitializeV2(
    params: *const u8,
    params_bytes: usize,
    out_runtime_sha256: *mut u8,
    out_runtime_sha256_len: usize,
    out_attestation_json: *mut u8,
    out_attestation_len: usize,
    out_attestation_written: *mut usize,
) -> i32 {
    std::panic::catch_unwind(|| {
        initialize_v2_inner(
            params,
            params_bytes,
            out_runtime_sha256,
            out_runtime_sha256_len,
            out_attestation_json,
            out_attestation_len,
            out_attestation_written,
        )
    })
    .unwrap_or(MidaAntidebugError::InternalPanic.as_i32())
}

fn initialize_v2_inner(
    params: *const u8,
    params_bytes: usize,
    out_runtime_sha256: *mut u8,
    out_runtime_sha256_len: usize,
    out_attestation_json: *mut u8,
    out_attestation_len: usize,
    out_attestation_written: *mut usize,
) -> i32 {
    if RUNTIME.get().is_some() {
        return MidaAntidebugError::AlreadyInitialized.as_i32();
    }
    if params.is_null()
        || out_attestation_json.is_null()
        || out_attestation_written.is_null()
        || out_attestation_len == 0
        || params_bytes < V2_HEADER_BYTES
    {
        return MidaAntidebugError::InvalidArgument.as_i32();
    }
    // SAFETY: validated above; blob is readable for params_bytes.
    let blob = unsafe { std::slice::from_raw_parts(params, params_bytes) };

    // ---- header validation (fail-closed) ----
    let rd = |off: usize| -> Result<u64, MidaAntidebugError> {
        let end = v2_checked_add(off, 8, "v2 header field")?;
        if end > blob.len() {
            return Err(MidaAntidebugError::InvalidV2Blob);
        }
        Ok(u64::from_le_bytes(blob[off..end].try_into().unwrap()))
    };
    let magic = match rd(0x30) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    if magic != V2_ENVELOPE_MAGIC {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }
    let pid_off_u = match rd(0x10) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    let pd_off_u = match rd(0x18) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    let expected_hooks = match rd(0x20) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    let surf_off_u = match rd(0x28) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    let dig_off_u = match rd(0x38) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    let dig_len_field = match rd(0x40) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    if dig_len_field != V2_DIGEST_LEN {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }
    if expected_hooks == 0 || expected_hooks > V2_MAX_HOOKS {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }
    if surf_off_u == 0 {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }
    let pid_off = match usize::try_from(pid_off_u) {
        Ok(v) => v,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    let pd_off = match usize::try_from(pd_off_u) {
        Ok(v) => v,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    let surf_off = match usize::try_from(surf_off_u) {
        Ok(v) => v,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    let dig_off = match usize::try_from(dig_off_u) {
        Ok(v) => v,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    for (name, off) in [("profile_id", pid_off), ("profile_digest", pd_off), ("digest", dig_off)] {
        if off < V2_HEADER_BYTES || off >= blob.len() {
            let _ = name;
            return MidaAntidebugError::InvalidV2Blob.as_i32();
        }
    }

    // ---- bounded string reads ----
    let profile_id = match v2_read_cstr_blob(blob, pid_off, "profile_id") {
        Ok(s) => s,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    let profile_digest = match v2_read_cstr_blob(blob, pd_off, "profile_digest") {
        Ok(s) => s,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    let digest = match v2_read_cstr_blob(blob, dig_off, "digest") {
        Ok(s) => s,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    if digest.len() != 64 {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }
    if !digest.bytes().all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b <= b'f')) {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }

    // ---- surfaces array (absolute VAs in the target == runtime process) ----
    // IMP-08-R1-R1 (P0-2): every surface entry is an ABSOLUTE VA written
    // by the loader as blob_base + relative. The runtime MUST verify
    // blob provenance BEFORE dereferencing: the VA must lie inside
    // [blob_base, blob_end). A canonical-but-unrelated VA is rejected.
    let blob_base = params as usize;
    let blob_end = match checked_blob_end(blob_base, params_bytes) {
        Ok(v) => v,
        Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    let array_bytes = match (expected_hooks as usize).checked_mul(8) {
        Some(v) => v,
        None => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    let array_end = match surf_off.checked_add(array_bytes) {
        Some(v) if v <= blob.len() => v,
        _ => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    if array_end != dig_off {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }
    // IMP-08-R1-R1 (P0-2): strict tail policy — the digest region must
    // be the LAST thing in the blob. digest = 64 hex chars + NUL (65
    // bytes total). digest_off + 65 != params_bytes means unknown tail,
    // truncation, or overlap — all malformed, fail closed.
    let digest_region_end = match dig_off.checked_add(65) {
        Some(v) => v,
        None => return MidaAntidebugError::InvalidV2Blob.as_i32(),
    };
    if digest_region_end != params_bytes {
        return MidaAntidebugError::InvalidV2Blob.as_i32();
    }
    let mut expected = Vec::with_capacity(expected_hooks as usize);
    for i in 0..expected_hooks as usize {
        let stride = match i.checked_mul(8) {
            Some(v) => v,
            None => return MidaAntidebugError::InvalidV2Blob.as_i32(),
        };
        let entry_off = match surf_off.checked_add(stride) {
            Some(v) => v,
            None => return MidaAntidebugError::InvalidV2Blob.as_i32(),
        };
        let entry_end = match entry_off.checked_add(8) {
            Some(v) if v <= blob.len() => v,
            _ => return MidaAntidebugError::InvalidV2Blob.as_i32(),
        };
        let abs_va = u64::from_le_bytes(blob[entry_off..entry_end].try_into().unwrap());
        if abs_va == 0 {
            return MidaAntidebugError::InvalidV2Blob.as_i32();
        }
        // Canonical user VA check (kernel high-half rejected).
        if abs_va > 0x0000_7FFF_FFFF_FFFF {
            return MidaAntidebugError::InvalidV2Blob.as_i32();
        }
        // IMP-08-R1-R1 (P0-2): blob provenance — the VA must be inside
        // [blob_base, blob_end). No unchecked dereference of abs_va.
        let abs_va_usize = match usize::try_from(abs_va) {
            Ok(v) => v,
            Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
        };
        if abs_va_usize < blob_base || abs_va_usize >= blob_end {
            return MidaAntidebugError::InvalidV2Blob.as_i32();
        }
        let rel = match abs_va_usize.checked_sub(blob_base) {
            Some(v) => v,
            None => return MidaAntidebugError::InvalidV2Blob.as_i32(),
        };
        // Bounded NUL scan inside the blob slice only (no raw pointer).
        let surface_id = match v2_read_cstr_blob(blob, rel, "surface_id") {
            Ok(s) => s,
            Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32(),
        };
        expected.push(surface_id);
    }

    // ---- target identity (frozen header fields +0x00 / +0x08) ----
    let target_pid = u32::from_le_bytes(blob[0x00..0x04].try_into().unwrap());
    let module_base = match rd(0x08) { Ok(v) => v, Err(_) => return MidaAntidebugError::InvalidV2Blob.as_i32() };
    if target_pid == 0 || module_base == 0 {
        // Target identity binding: zero PID / module base is invalid.
        return MidaAntidebugError::InvalidArgument.as_i32();
    }

    // ---- digest becomes the runtime identity (replaces v1 placeholder) ----
    let runtime_sha256 = digest;

    // ---- ADR-5: install hard-required PEB surfaces (same as v1 path) ----
    let real_peb = crate::surfaces::Win32PebMemory::new(target_pid);
    let (outcomes, failures) = match install_proc_surfaces(
        &real_peb,
        crate::surfaces::POINTER_SIZE_X64,
        target_pid,
        target_pid,
        &profile_digest,
        &profile_digest,
    ) {
        Ok(v) => v,
        Err(_) => {
            // Surface-level fatal (e.g. wrong pointer size): fail closed.
            return MidaAntidebugError::SurfaceInstallFailed.as_i32();
        }
    };
    let installed: Vec<String> = outcomes
        .iter()
        .filter(|o| o.installed)
        .map(|o| o.surface_id.clone())
        .collect();
    let fail_pairs: Vec<(String, String)> = failures
        .iter()
        .map(|f| (f.surface_id.clone(), f.error.clone().unwrap_or_default()))
        .collect();
    let details: Vec<SurfaceDetail> = outcomes
        .iter()
        .map(|o| SurfaceDetail {
            surface_id: o.surface_id.clone(),
            installed: o.installed,
            original_value: o.original_value.clone(),
            effective_value: o.effective_value.clone(),
            restoration_policy: format!("{:?}", o.restoration_policy),
            restore_result: format!("{:?}", o.restore_result),
            error: o.error.clone(),
        })
        .collect();
    let original_bd: Option<String> = outcomes
        .iter()
        .find(|o| o.surface_id == SURFACE_AD_PROC_002)
        .and_then(|o| o.original_value.clone());
    let original_shim: Option<String> = outcomes
        .iter()
        .find(|o| o.surface_id == SURFACE_AD_PROC_003)
        .and_then(|o| o.original_value.clone());
    // expected set for attestation = hard-required surfaces only (002, 003);
    // AD-PROC-001 stays a candidate and is NOT part of hooks_expected.
    let expected_hard: Vec<String> = expected
        .iter()
        .filter(|s| s.as_str() == SURFACE_AD_PROC_002 || s.as_str() == SURFACE_AD_PROC_003)
        .cloned()
        .collect();
    let att = match build_attestation_from_outcomes(
        runtime_sha256.clone(),
        profile_id.clone(),
        profile_digest.clone(),
        target_pid,
        module_base,
        &expected_hard,
        &installed,
        &fail_pairs,
        details,
    ) {
        Ok(a) => a,
        Err(e) => return e.as_i32(),
    };
    let att_json = match att.to_canonical_json() {
        Ok(j) => j,
        Err(_) => return MidaAntidebugError::Serialization.as_i32(),
    };
    if att_json.len() > out_attestation_len {
        return MidaAntidebugError::BufferTooSmall.as_i32();
    }
    // Copy runtime sha256 (digest echo: MUST be the full 64 hex + no truncation).
    if out_runtime_sha256.is_null() || out_runtime_sha256_len < runtime_sha256.len() {
        return MidaAntidebugError::EchoBufferTooSmall.as_i32();
    }
    let bytes = runtime_sha256.as_bytes();
    // SAFETY: validated output buffer; capacity checked above.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_runtime_sha256, bytes.len()) };
    // Copy attestation JSON
    let bytes = att_json.as_bytes();
    // SAFETY: validated output buffer; size checked above.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), out_attestation_json, bytes.len()) };
    // SAFETY: validated output pointer.
    unsafe { *out_attestation_written = bytes.len() };
    // Build the telemetry channel bound to PID + digest (attestation carries
    // the same target_pid / module_base identity).
    let telemetry = TelemetryChannel::new(
        format!("mida-adr4-{}", target_pid),
        target_pid,
        profile_digest.clone(),
    );
    let handle = RuntimeHandle {
        attestation: att,
        provenance: Provenance::current(
            runtime_sha256,
            0,
            "rustc".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
        telemetry,
        shutdown_requested: false,
        surface_details: Vec::new(),
        original_being_debugged: original_bd,
        original_shim_data: original_shim,
    };
    // SAFETY: single-threaded init contract; set() fails only if already set
    // which we checked above.
    let _ = RUNTIME.set(handle);
    // SAFETY: set succeeded; get() is Some.
    RUNTIME
        .get()
        .expect("runtime set above")
        .telemetry
        .mark_ready()
        .expect("telemetry mark ready");
    MidaAntidebugError::Ok.as_i32()
}
/// C ABI: Walker protocol entry (IMP-08 export surface only).
///
/// IMP-08-R1 scope: the export must EXIST in the runtime DLL so the loader's
/// 5-item wanted set can resolve it (fail-closed on missing). The Walker
/// production caller/state machine is IMP-09 (LOCKED). Until IMP-09 lands,
/// this entry is fail-closed: it validates that `params_va` is a
/// canonical user VA and returns [`MidaAntidebugError::NotImplemented`]
/// (13) - it NEVER dispatches a walker, NEVER writes process memory, and
/// NEVER executes remote code. This is an honest NOT_IMPLEMENTED export,
/// not an inert stub masquerading as production.
///
/// # Safety
/// - No pointer is dereferenced in this function; `params_va` is
///   only validated as a canonical user-mode VA.
#[no_mangle]
pub unsafe extern "C" fn WalkerExecute(params_va: u64) -> i32 {
    std::panic::catch_unwind(|| walker_execute_inner(params_va))
        .unwrap_or(MidaAntidebugError::InternalPanic.as_i32())
}

fn walker_execute_inner(params_va: u64) -> i32 {
    // Fail-closed validation: the VA must be a nonzero canonical user VA
    // (kernel high-half rejected) before any IMP-09 caller may use it.
    if params_va == 0 || params_va > 0x0000_7FFF_FFFF_FFFF {
        return MidaAntidebugError::InvalidArgument.as_i32();
    }
    // IMP-09 not implemented: honest NOT_IMPLEMENTED, never fake success.
    MidaAntidebugError::NotImplemented.as_i32()
}

/// Internal: read a NUL-terminated C string (bounded).
unsafe fn read_cstr(p: *const std::os::raw::c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while unsafe { *p.add(len) } != 0 && len < 4096 {
        len += 1;
    }
    if unsafe { *p.add(len) } != 0 {
        return None;
    }
    let slice = unsafe { std::slice::from_raw_parts(p as *const u8, len) };
    String::from_utf8(slice.to_vec()).ok()
}

/// Test-only reset (used by the offline harness to re-initialize).
pub fn reset_for_test() {
    // OnceLock cannot be reset; tests use the rlib API directly instead of
    // the FFI singleton. This function exists so the FFI tests can document
    // that the global is single-instance by design.
    let _ = RUNTIME.get();
}

#[cfg(test)]
mod imp08_v2_tests {
    use super::*;

    #[test]
    fn v2_magic_bytes_match_frozen_fixture() {
        // WO-1803 fixture: LE bytes = 4D 49 44 41 32 50 32 00 ("MIDA2P2\0").
        let bytes = 0x0032_5032_4144_494Du64.to_le_bytes();
        assert_eq!(bytes, [0x4D, 0x49, 0x44, 0x41, 0x32, 0x50, 0x32, 0x00]);
        assert_eq!(u64::from_le_bytes(bytes), V2_ENVELOPE_MAGIC);
    }

    #[test]
    fn v2_read_cstr_blob_ok_and_bounds() {
        let blob = b"MIDA\0tail";
        assert_eq!(v2_read_cstr_blob(blob, 0, "x").unwrap(), "MIDA");
        assert!(v2_read_cstr_blob(blob, 9, "x").is_err());
        assert!(v2_read_cstr_blob(b"abcdef", 0, "x").is_err());
    }

    #[test]
    fn v2_checked_add_rejects_overflow() {
        assert_eq!(v2_checked_add(1, 2, "x").unwrap(), 3);
        assert!(v2_checked_add(usize::MAX, 1, "x").is_err());
    }

    #[test]
    fn walker_execute_rejects_invalid_va_fail_closed() {
        unsafe {
            assert_eq!(WalkerExecute(0), MidaAntidebugError::InvalidArgument.as_i32());
            assert_eq!(
                WalkerExecute(0xFFFF_8000_0000_0000),
                MidaAntidebugError::InvalidArgument.as_i32()
            );
        }
    }

    #[test]
    fn walker_execute_honest_not_implemented() {
        unsafe {
            assert_eq!(
                WalkerExecute(0x0000_1000_0000),
                MidaAntidebugError::NotImplemented.as_i32()
            );
        }
    }

    #[test]
    fn error_codes_stable_abi() {
        assert_eq!(MidaAntidebugError::Ok.as_i32(), 0);
        assert_eq!(MidaAntidebugError::AlreadyInitialized.as_i32(), 1);
        assert_eq!(MidaAntidebugError::NotInitialized.as_i32(), 2);
        assert_eq!(MidaAntidebugError::InvalidArgument.as_i32(), 3);
        assert_eq!(MidaAntidebugError::BufferTooSmall.as_i32(), 4);
        assert_eq!(MidaAntidebugError::AlreadyShutdown.as_i32(), 5);
        assert_eq!(MidaAntidebugError::Serialization.as_i32(), 6);
        assert_eq!(MidaAntidebugError::InternalPanic.as_i32(), 7);
        assert_eq!(MidaAntidebugError::ArchitectureMismatch.as_i32(), 8);
        assert_eq!(MidaAntidebugError::SurfaceInstallFailed.as_i32(), 9);
        assert_eq!(MidaAntidebugError::RestoreFailed.as_i32(), 10);
        assert_eq!(MidaAntidebugError::InvalidV2Blob.as_i32(), 11);
        assert_eq!(MidaAntidebugError::EchoBufferTooSmall.as_i32(), 12);
        assert_eq!(MidaAntidebugError::NotImplemented.as_i32(), 13);
    }

    // ---- IMP-08-R1-R1 (P0-2): blob provenance hostile tests ----
    // These tests build a structurally-valid V2 blob (matching the
    // loader's layout) and mutate ONE field to be hostile. They call
    // initialize_v2_inner DIRECTLY (not the FFI entry) so the RUNTIME
    // OnceLock is not touched; every case must fail with InvalidV2Blob
    // BEFORE any surface install or attestation build.
    fn build_probe_blob() -> Vec<u8> {
        // Layout mirror of V2ParamsBlob (loader side):
        // +0x00 pid, +0x08 module_base, +0x10 profile_id_off,
        // +0x18 profile_digest_off, +0x20 expected_hooks, +0x28 surf_off,
        // +0x30 magic, +0x38 digest_off, +0x40 digest_len.
        let mut b = vec![0u8; 0x48];
        b[0x00..0x04].copy_from_slice(&1234u32.to_le_bytes());
        b[0x08..0x10].copy_from_slice(&0x0000_2000_0000u64.to_le_bytes());
        b[0x10..0x18].copy_from_slice(&0x48u64.to_le_bytes());          // profile_id_off
        b[0x18..0x20].copy_from_slice(&((0x48 + 9) as u64).to_le_bytes()); // profile_digest_off
        b[0x20..0x28].copy_from_slice(&1u64.to_le_bytes());             // expected_hooks
        // surf_off filled after layout is known
        b[0x30..0x38].copy_from_slice(&V2_ENVELOPE_MAGIC.to_le_bytes());
        // digest_off filled after layout; digest_len
        b[0x40..0x48].copy_from_slice(&V2_DIGEST_LEN.to_le_bytes());
        // strings: profile_id "p" + NUL, profile_digest "d" + NUL
        b.extend_from_slice(b"p\0d\0");
        let surf_off = b.len() as u64;
        b[0x28..0x30].copy_from_slice(&surf_off.to_le_bytes());
        // surface array: one entry = blob_base + rel of "AD-PROC-002"
        let surf_str_off = (b.len() + 8) as u64;
        b.extend_from_slice(&0u64.to_le_bytes()); // placeholder, patched below
        b.extend_from_slice(b"AD-PROC-002\0");
        let dig_off = b.len() as u64;
        b[0x38..0x40].copy_from_slice(&dig_off.to_le_bytes());
        b.extend_from_slice(&"a".repeat(64).as_bytes().to_vec());
        b.push(0);
        // patch surface entry: abs_va = blob_base + surf_str_off (self-
        // relative inside the blob; blob_base = 0 for the probe).
        let entry_off = surf_off as usize;
        b[entry_off..entry_off + 8].copy_from_slice(&surf_str_off.to_le_bytes());
        b
    }

    /// Call initialize_v2_inner with VALID output buffers so the early
    /// InvalidArgument guard (null/zero outputs) does not mask the blob
    /// provenance checks under test. Returns the i32 result.
    fn initialize_v2_inner_probe(blob: &[u8]) -> i32 {
        let mut out_sha = [0u8; 64];
        let mut out_att = [0u8; 4096];
        let mut written = 0usize;
        initialize_v2_inner(
            blob.as_ptr(),
            blob.len(),
            out_sha.as_mut_ptr(),
            out_sha.len(),
            out_att.as_mut_ptr(),
            out_att.len(),
            &mut written,
        )
    }

    #[test]
    fn v2_blob_canonical_out_of_blob_va_rejected() {
        let mut b = build_probe_blob();
        // Surface VA points at a canonical but UNRELATED user address
        // (0x7FFF_FFFF_FFFF - 0x1000): inside user half, NOT in the blob.
        let entry_off = u64::from_le_bytes(b[0x28..0x30].try_into().unwrap()) as usize;
        b[entry_off..entry_off + 8].copy_from_slice(&(0x7FFF_FFFF_FFF0u64).to_le_bytes());
        let r = initialize_v2_inner_probe(&b);
        assert_eq!(r, MidaAntidebugError::InvalidV2Blob.as_i32());
    }

    #[test]
    fn v2_blob_va_below_blob_base_rejected() {
        let mut b = build_probe_blob();
        // VA below blob_base (blob_base = params ptr). Use 0x10.
        let entry_off = u64::from_le_bytes(b[0x28..0x30].try_into().unwrap()) as usize;
        b[entry_off..entry_off + 8].copy_from_slice(&0x10u64.to_le_bytes());
        let r = initialize_v2_inner_probe(&b);
        assert_eq!(r, MidaAntidebugError::InvalidV2Blob.as_i32());
    }

    #[test]
    fn v2_blob_surface_string_outside_blob_rejected() {
        let mut b = build_probe_blob();
        // Surface VA = blob_base + (blob.len() + 0x1000): beyond blob_end.
        let entry_off = u64::from_le_bytes(b[0x28..0x30].try_into().unwrap()) as usize;
        let out_va = (b.len() + 0x1000) as u64;
        b[entry_off..entry_off + 8].copy_from_slice(&out_va.to_le_bytes());
        let r = initialize_v2_inner_probe(&b);
        assert_eq!(r, MidaAntidebugError::InvalidV2Blob.as_i32());
    }

    #[test]
    fn v2_blob_unknown_tail_rejected() {
        let mut b = build_probe_blob();
        // Append a trailing byte after the digest region: digest_off+65
        // != params_bytes -> unknown tail -> fail closed.
        b.push(0x41);
        let r = initialize_v2_inner_probe(&b);
        assert_eq!(r, MidaAntidebugError::InvalidV2Blob.as_i32());
    }

    #[test]
    fn v2_blob_digest_region_truncated_rejected() {
        let mut b = build_probe_blob();
        // Truncate the digest NUL: digest region no longer 65 bytes.
        b.pop();
        let r = initialize_v2_inner_probe(&b);
        assert_eq!(r, MidaAntidebugError::InvalidV2Blob.as_i32());
    }

    #[test]
    fn v2_blob_entry_offset_overflow_rejected() {
        // expected_hooks huge + surf_off near usize::MAX: checked adds
        // must fail. (Blob stays small; array_bytes overflows first.)
        let mut b = build_probe_blob();
        b[0x20..0x28].copy_from_slice(&(V2_MAX_HOOKS as u64).to_le_bytes());
        b[0x28..0x30].copy_from_slice(&(usize::MAX as u64).to_le_bytes());
        let r = initialize_v2_inner_probe(&b);
        assert_eq!(r, MidaAntidebugError::InvalidV2Blob.as_i32());
    }

    #[test]
    fn v2_blob_digest_region_checked_add_overflow_rejected() {
        // dig_off = usize::MAX - 1: digest_off + 65 overflows the
        // checked_add guard (exports.rs:719-722). Named for the REAL
        // path it covers — the digest-region checked-add overflow.
        let mut b = build_probe_blob();
        b[0x38..0x40].copy_from_slice(&((usize::MAX - 1) as u64).to_le_bytes());
        let r = initialize_v2_inner_probe(&b);
        assert_eq!(r, MidaAntidebugError::InvalidV2Blob.as_i32());
    }

    #[test]
    fn v2_blob_blob_base_plus_bytes_overflow_rejected() {
        // The REAL blob-base overflow guard is checked_blob_end()
        // (exports.rs:701-705), the exact function the production
        // parser calls at initialize_v2_inner entry. A real
        // initialize_v2_inner call cannot overflow blob_base +
        // params_bytes (params points at a real small blob), so the
        // guard is exercised directly with adversarial inputs.
        assert!(checked_blob_end(usize::MAX, 1).is_err());
        assert!(checked_blob_end(1, usize::MAX).is_err());
        assert!(checked_blob_end(usize::MAX - 1, 2).is_err());
        assert!(checked_blob_end(usize::MAX, usize::MAX).is_err());
        assert_eq!(checked_blob_end(0, 0).unwrap(), 0);
        assert_eq!(checked_blob_end(0x1000, 0x100).unwrap(), 0x1100);
        assert_eq!(checked_blob_end(1, 1).unwrap(), 2);
    }
}
