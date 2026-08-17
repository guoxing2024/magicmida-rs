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
    std::panic::catch_unwind(|| shutdown_inner())
        .unwrap_or(MidaAntidebugError::InternalPanic.as_i32())
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
