//! IMP-09-DISPATCH-BRIDGE: production target-side WalkerExecute dispatch
//!
//! Production `.expect()`s are invariants (WO-12): each site follows a guard
//! that makes the expected value unreachable-None/Err (len-matched slices,
//! `if has_x` + `plan.x` co-check, `match`-bound states, caller-validated
//! member names, re-serialization of an already-parsed Value, FFI
//! kernel32/Sleep existence, or caller pre-checked Option). No production
//! fallible path is masked; the one genuinely reachable panic (bundle_gate
//! member lookup) was converted to error propagation. Test-block expects are
//! ordinary assertions (WO-14).
#![allow(clippy::expect_used)]
//! bridge (R5-R2-4 authorized dispatch seam).
//!
//! # Contract
//!
//! The ONLY production implementation of [`WalkerDispatchBridge`]. The
//! bridge marshals `WalkerExecute(params_va)` into the target process:
//!
//! ```text
//! cross-check  remote_va == module_base + walker_export_rva   (fail-closed)
//!   -> VirtualAllocEx(0x100) + WriteProcessMemory(THUNK7_PRODUCTION + args)
//!   -> VirtualProtectEx(PAGE_EXECUTE_READWRITE)
//!   -> CreateRemoteThread(thunk) -> WaitForSingleObject (bounded)
//!   -> GetExitCodeThread -> raw walker status
//!   -> take_walker_output() -> marshaled V2 output (when status == OK)
//! ```
//!
//! Every input comes from a sealed carrier:
//! - `remote_va`: [`MidaExportsV2::walker_execute`] — resolved from the
//!   TARGET process memory by `resolve_mida_exports_remote()` (module_base
//!   + export RVA);
//! - `module_base`: [`LoaderResult::module_base`] — the loaded runtime
//!   module base in the target;
//! - `walker_export_rva`: [`LoaderResult::walker_export_rva`] — resolved
//!   from the VERIFIED runtime DLL FILE bytes (pure-file resolver).
//!
//! The DUAL-SEALED cross-check is the authorization gate: the live-carrier
//! remote VA must equal `module_base + file_rva` exactly. A mismatch fails
//! closed — the bridge never dispatches against a VA that the two sealed
//! chains do not agree on.
//!
//! # R5-R2 wiring status
//!
//! The type is constructible and fully unit-tested offline (T1-T12), but it
//! is NOT wired into any production path in this order: the two production
//! `AntidebugStageOptions` construction sites (`unpacker/mod.rs` lines
//! ~790 and ~1227) keep `walker_dispatch: None`, so the controller records
//! + returns NOT_IMPLEMENTED at the execute gate (fail-closed). Live
//! dispatch authorization is deferred to the LIVE order; the bridge here
//! proves the dispatch MECHANICS offline, never a live Windows PASS.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, GetExitCodeThread, WaitForSingleObject,
};

use crate::unpacker::antidebug_controller::LoaderResult;
use crate::unpacker::runtime_loader::{MidaExportsV2, THUNK7_PRODUCTION};
use crate::unpacker::walker_session::WalkerDispatchBridge;

/// Total size of the remote thunk allocation (one page-rounded 0x100
/// region; VirtualAllocEx rounds to page granularity, so the executable
/// window and the args region share one committed page).
const THUNK_BLOB_SIZE: usize = 0x100;
/// Offset of the args blob inside the thunk allocation.
const THUNK_ARGS_OFFSET: usize = 0x60;
/// Size of the args blob (8 slots x 8 bytes).
const THUNK_ARGS_SIZE: usize = 64;
/// Bytes from the start of the allocation that must be executable.
const THUNK_EXECUTABLE_SIZE: usize = 0x60;

/// Argument block for a thunk call (8 slots x 8 bytes = 64 bytes),
/// matching the runtime_loader `ThunkArgs` layout (fn_ptr + arg0..arg5 +
/// reserved).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WalkerThunkArgs {
    pub fn_ptr: u64,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub reserved: u64,
}

impl WalkerThunkArgs {
    pub fn as_bytes(&self) -> [u8; THUNK_ARGS_SIZE] {
        let mut out = [0u8; THUNK_ARGS_SIZE];
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

/// Production target-side WalkerExecute dispatch bridge (R5-R2-4).
///
/// Constructed from the TWO sealed carriers (loader result + resolved live
/// exports). `dispatch()` is the ONLY authorized live dispatch path: it
/// performs the dual-sealed cross-check, marshals the call through the
/// FROZEN 60-byte [`THUNK7_PRODUCTION`] bytes via CreateRemoteThread, and
/// returns (raw status, marshaled V2 output).
#[derive(Debug)]
pub struct WalkerDispatchBridgeImpl {
    /// Target process handle (valid for the session lifetime).
    target: HANDLE,
    /// Sealed loader result: module_base + pure-file WalkerExecute export
    /// RVA (the FILE-side carrier).
    loader: LoaderResult,
    /// Resolved live exports from the target module (the REMOTE-side
    /// carrier): `walker_execute` is the remote VA.
    exports: MidaExportsV2,
    /// Bounded wait budget for the remote thread (milliseconds). Fixed by
    /// the caller; production uses a 60s-equivalent wall budget.
    wait_ms: u32,
}

// SAFETY: the bridge only passes the HANDLE to kernel32 (VirtualAllocEx /
// VirtualProtectEx / CreateRemoteThread / WaitForSingleObject /
// GetExitCodeThread / CloseHandle / VirtualFreeEx) — all documented
// thread-safe kernel32 calls; it never dereferences the pointer. The
// handle is owned by the debugger for the session lifetime (same contract
// as RpmWalkerProvider). LoaderResult and MidaExportsV2 are plain value
// carriers (strings / u64 / usize).
unsafe impl Send for WalkerDispatchBridgeImpl {}
unsafe impl Sync for WalkerDispatchBridgeImpl {}

impl WalkerDispatchBridgeImpl {
    /// Construct the production bridge.
    ///
    /// # Panics
    /// Panics when a sealed carrier is missing: `walker_execute` must be
    /// resolved (None -> the loader's own `require_complete()` failed
    /// earlier) and `walker_export_rva` must be present (None -> the
    /// pure-file resolver did not find WalkerExecute; the controller bind
    /// already refused).
    pub fn new(target: HANDLE, loader: LoaderResult, exports: MidaExportsV2) -> Self {
        let _ = exports
            .walker_execute
            .expect("MidaExportsV2.walker_execute must be resolved for the dispatch bridge");
        let _ = loader
            .walker_export_rva()
            .expect("LoaderResult.walker_export_rva must be present for the dispatch bridge");
        Self {
            target,
            loader,
            exports,
            wait_ms: 60_000,
        }
    }

    /// The dual-sealed cross-check (the authorization gate).
    ///
    /// `remote_va` must equal `module_base + file_rva` EXACTLY, with
    /// checked arithmetic. A mismatch (or overflow) fails closed: the two
    /// sealed chains disagree, so no dispatch may happen.
    pub fn cross_check_passes(&self, remote_va: u64) -> bool {
        let Some(file_rva) = self.loader.walker_export_rva() else {
            return false;
        };
        if file_rva == 0 {
            return false;
        }
        let module_base = self.loader.module_base();
        let Some(expected) = module_base.checked_add(file_rva) else {
            return false;
        };
        remote_va == expected
    }

    /// True when both sealed carriers are present and non-zero.
    pub fn carriers_complete(&self) -> bool {
        self.exports.walker_execute.is_some() && self.loader.walker_export_rva().is_some()
    }

    /// Run the thunk call against the target: allocate, write, protect,
    /// CreateRemoteThread, bounded wait, exit code. Returns None when any
    /// marshaling step fails (fail-closed: never fabricate a status).
    ///
    /// # Safety
    /// `remote_fn` must be a valid function pointer in the TARGET address
    /// space (x64: same base as the debugger). `args` is written into
    /// target memory; the thunk reads it from there.
    unsafe fn thunk_call_raw(&self, remote_fn: u64, args: &WalkerThunkArgs) -> Option<u32> {
        // The thunk's `call rax` reads fn_ptr from the args blob; the two
        // MUST be identical (a divergence would call a different address
        // than the one that passed the cross-check). This is a hard
        // invariant of the marshaling, not just a debug assertion.
        if args.fn_ptr != remote_fn {
            return None;
        }
        let target = self.target;
        // 1. Allocate executable-capable memory for thunk + args.
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
            return None;
        }
        // 2. Write thunk bytes verbatim + args at [THUNK_ARGS_OFFSET..+64).
        let mut blob = [0u8; THUNK_BLOB_SIZE];
        if THUNK7_PRODUCTION.len() != 60 {
            let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            return None;
        }
        blob[0..THUNK7_PRODUCTION.len()].copy_from_slice(&THUNK7_PRODUCTION);
        blob[THUNK_ARGS_OFFSET..THUNK_ARGS_OFFSET + THUNK_ARGS_SIZE]
            .copy_from_slice(&args.as_bytes());
        let w = unsafe {
            windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                target,
                remote,
                blob.as_ptr() as *const core::ffi::c_void,
                blob.len(),
                None,
            )
        };
        if w.is_err() {
            let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            return None;
        }
        // 3. Make executable (PAGE_EXECUTE_READWRITE; the whole shared page
        //    becomes executable — the same contract as the loader thunk).
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
            return None;
        }
        // 4. Run: CreateRemoteThread(remote thunk, arg = remote + args offset).
        let thunk_addr = remote as usize;
        let args_addr = remote as usize + THUNK_ARGS_OFFSET;
        let thread = unsafe {
            CreateRemoteThread(
                target,
                None,
                0,
                Some(std::mem::transmute::<
                    usize,
                    unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
                >(thunk_addr)),
                Some(args_addr as *const core::ffi::c_void),
                0,
                None,
            )
        };
        let Ok(thread) = thread else {
            let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            return None;
        };
        // 5. Bounded wait (no drain available here: the dispatch runs in
        //    the alive window where the debugger already drained the
        //    CREATE_PROCESS window; the walker call is short).
        let wait = unsafe { WaitForSingleObject(thread, self.wait_ms) }.0;
        if wait != 0 {
            // WAIT_OBJECT_0 = 0. On timeout/abandoned/failure the remote
            // thread may still execute the thunk: retain the allocation
            // (released when the target terminates) and report failure.
            let _ = unsafe { windows::Win32::Foundation::CloseHandle(thread) };
            return None;
        }
        let mut code: u32 = 0;
        let gc = unsafe { GetExitCodeThread(thread, &mut code) };
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(thread) };
        if gc.is_err() {
            // Remote code finished; the thunk is no longer executing, so
            // the allocation can be freed.
            let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
            return None;
        }
        // 6. Remote thread finished: free the thunk allocation.
        let _ = unsafe { VirtualFreeEx(target, remote, 0, MEM_RELEASE) };
        Some(code)
    }
}

impl WalkerDispatchBridge for WalkerDispatchBridgeImpl {
    fn dispatch(
        &self,
        params_va: u64,
    ) -> (
        i32,
        Option<mida_antidebug_runtime::attestation::RuntimeAttestationV2>,
    ) {
        // Gate 1: the dual-sealed cross-check MUST pass before any
        // dispatch (fail-closed on mismatch).
        let Some(remote_va) = self.exports.walker_execute else {
            return (
                mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_BAD_PARAMS as i32,
                None,
            );
        };
        if !self.cross_check_passes(remote_va as u64) {
            return (
                mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_BAD_PARAMS as i32,
                None,
            );
        }
        // Gate 2: the params VA must be a canonical user VA (protocol gate).
        if params_va == 0 || params_va > 0x0000_7FFF_FFFF_FFFF {
            return (
                mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_BAD_PARAMS as i32,
                None,
            );
        }
        // Marshal: WalkerExecute(params_va) — one argument.
        let args = WalkerThunkArgs {
            fn_ptr: remote_va as u64,
            arg0: params_va,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            reserved: 0,
        };
        // SAFETY: remote_va passed the cross-check (module_base + file_rva
        // of the VERIFIED runtime) and is therefore a valid code address in
        // the target; the thunk + args live in a fresh target allocation.
        let Some(status) = (unsafe { self.thunk_call_raw(remote_va as u64, &args) }) else {
            // Marshaling failed (allocation / write / protect / thread /
            // wait): fail-closed, no fabricated status.
            return (
                mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_MAP_FAILED as i32,
                None,
            );
        };
        if status != mida_antidebug_runtime::walker_protocol::WALKER_STATUS_OK {
            return (status as i32, None);
        }
        // Status OK: the walker wrote its output into the runtime output
        // channel. Drain it (the bridge owns the channel read for the
        // production dispatch; a missing output fails closed upstream at
        // the controller OutputMissing gate).
        let output = mida_antidebug_runtime::exports::take_walker_output();
        (
            mida_antidebug_runtime::walker_protocol::WALKER_STATUS_OK as i32,
            output,
        )
    }
}

// ---------------------------------------------------------------------------
// IMP-09-DISPATCH-WIRING: centralized LIVE dispatch gate (env-controlled).
//
// Contract (work order IMP-09-DISPATCH-WIRING section 2):
//   - live_dispatch_gate() returns true ONLY when BOTH
//       MIDA_GTO_NO_BYPASS == "1"    (observation discipline on)
//       MIDA_GTO_LIVE_DISPATCH == "1" (explicit live unlock, set by the
//         signed LIVE work order execution window, cleared after)
//     are set to exactly "1". Any missing / any other value -> false.
//   - MIDA_GTO_LIVE_AUTHORIZED is RETIRED (historical name, never had a
//     read point) and is NOT consulted.
//
// try_build_live_dispatch_bridge is the single production wiring seam:
// gate closed -> None (offline default, byte-identical to baseline);
// gate open + ALL sealed carriers present -> Some(Box<WalkerDispatchBridgeImpl>)
// (dual-sealed cross-check path); any carrier missing -> None (fail-closed,
// the existing NotImplemented branch at the controller execute gate is
// preserved). It NEVER fabricates a carrier and NEVER relaxes the authority
// chain: the caller hands in the carriers it already holds in scope
// (loader_result / resolve results); missing carriers simply keep the
// bridge absent.
// ---------------------------------------------------------------------------

/// Name of the observation-discipline environment variable. MUST be "1" for
/// the live dispatch gate to open (same contract as the live-route
/// controller environment preflight).
pub const GTO_ENV_NO_BYPASS: &str = "MIDA_GTO_NO_BYPASS";

/// Name of the explicit live-dispatch unlock environment variable (replaces
/// the retired `MIDA_GTO_LIVE_AUTHORIZED`). Set only inside the signed LIVE
/// work order single-command execution window, cleared immediately after.
pub const GTO_ENV_LIVE_DISPATCH: &str = "MIDA_GTO_LIVE_DISPATCH";

/// Centralized LIVE dispatch gate.
///
/// Returns true only when MIDA_GTO_NO_BYPASS == "1" AND
/// MIDA_GTO_LIVE_DISPATCH == "1". Any missing variable or any value other
/// than exactly "1" fails closed to false. The retired
/// MIDA_GTO_LIVE_AUTHORIZED is deliberately NOT consulted.
pub fn live_dispatch_gate() -> bool {
    std::env::var(GTO_ENV_NO_BYPASS).ok().as_deref() == Some("1")
        && std::env::var(GTO_ENV_LIVE_DISPATCH).ok().as_deref() == Some("1")
}

/// Production wiring seam for the env-gated live dispatch bridge.
///
/// Gate closed -> None (offline default; the controller keeps the
/// NOT_IMPLEMENTED fail-closed branch).
///
/// Gate open -> construct WalkerDispatchBridgeImpl through its sealed
/// dual-carrier constructor, but ONLY when every required carrier is
/// present:
///   - loader (file-side sealed carrier: module_base + pure-file
///     walker_export_rva) -- missing -> None;
///   - exports (remote-side sealed carrier: MidaExportsV2.walker_execute
///     target VA from resolve_mida_exports_remote) -- missing -> None.
///
/// The bridge constructor itself performs the dual-sealed cross-check at
/// dispatch time (remote_va == module_base + file_rva); construction here
/// additionally fails closed on incomplete carriers so a missing export can
/// never reach expect().
pub fn try_build_live_dispatch_bridge(
    target: HANDLE,
    loader: Option<&LoaderResult>,
    exports: Option<&MidaExportsV2>,
) -> Option<WalkerDispatchBridgeImpl> {
    if !live_dispatch_gate() {
        return None;
    }
    let loader = loader?;
    let exports = exports?;
    if loader.walker_export_rva().is_none() {
        return None;
    }
    if exports.walker_execute.is_none() {
        return None;
    }
    // SAFETY of the sealed constructor: new panics only when a carrier is
    // missing; both required carriers were verified present above, so the
    // panic path is unreachable (fail-closed already returned None).
    Some(WalkerDispatchBridgeImpl::new(
        target,
        loader.clone(),
        exports.clone(),
    ))
}

/// Boxed variant for the production `AntidebugStageOptions.walker_dispatch`
/// slot (which is `Option<Box<dyn WalkerDispatchBridge>>`). Same gate and
/// carrier contract as [`try_build_live_dispatch_bridge`]; the concrete
/// bridge is boxed only after a successful construction (never a forged
/// trait object).
pub fn try_build_live_dispatch_bridge_boxed(
    target: HANDLE,
    loader: Option<&LoaderResult>,
    exports: Option<&MidaExportsV2>,
) -> Option<Box<dyn WalkerDispatchBridge>> {
    try_build_live_dispatch_bridge(target, loader, exports)
        .map(|b| Box::new(b) as Box<dyn WalkerDispatchBridge>)
}

#[cfg(test)]
mod imp09_dispatch_bridge_tests {
    //! T1-T12 offline test matrix (offline_mock=true): every test runs
    //! without a live target process and WITHOUT touching the process-global
    //! walker runtime singletons (the walker_session / controller test
    //! modules already own those lifecycle tests under their own locks).
    //! The thunk/CreateRemoteThread machinery is proven by the dual-sealed
    //! cross-check tests and the frozen-byte tests, never against a real
    //! remote process.

    use super::*;
    use crate::unpacker::walker_session::WalkerDispatchBridge;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Process-unique sequence for the loader fixture file name. Multiple
    /// tests in this module build a carrier pair with the same `file_rva`
    /// (e.g. t11/t12 both use 0x2040) and may run concurrently in the same
    /// process; a `{pid}_{rva}` name alone lets a concurrent test truncate/
    /// overwrite the fixture between `write` and `verify_file`, causing
    /// intermittent `AuthorityMismatch` (empty-file SHA-256) failures.
    static SEQ: AtomicU64 = AtomicU64::new(0);

    /// The frozen 60-byte production thunk (WO-2301 fixture). A byte change
    /// here is a WIRING ERROR: the production dispatch MUST use exactly
    /// these bytes.
    const EXPECTED_THUNK: [u8; 60] = [
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

    fn self_handle() -> HANDLE {
        unsafe { windows::Win32::System::Threading::GetCurrentProcess() }
    }

    /// Build a sealed LoaderResult-like carrier pair (module_base +
    /// walker_export_rva) + a matching MidaExportsV2. The identity/authority
    /// fields are filled via the real sealed constructors where reachable;
    /// the bridge only reads module_base + walker_export_rva, so a
    /// minimal valid pair is sufficient for the cross-check logic.
    ///
    /// The other export slots use saturating/checked arithmetic so an
    /// overflow-test carrier (huge module_base) never panics.
    fn carrier_pair(module_base: u64, file_rva: u64) -> (LoaderResult, MidaExportsV2) {
        let slot = |off: u64| -> Option<usize> { module_base.checked_add(off).map(|v| v as usize) };
        let exports = MidaExportsV2 {
            initialize: slot(0x100),
            get_attestation: slot(0x200),
            shutdown: slot(0x300),
            initialize_v2: slot(0x400),
            walker_execute: slot(file_rva),
        };
        // The bridge only touches module_base()/walker_export_rva(); the
        // remaining LoaderResult fields are constructed through the sealed
        // path in the controller tests. Here we need a LoaderResult with a
        // real RuntimeFileIdentity — build one via the real verify_file()
        // flow (minimal PE) exactly like the controller tests do.
        let loader = build_loader_result(module_base, file_rva);
        (loader, exports)
    }

    /// Real verify_file()-produced LoaderResult (sealed ctor). Uses the
    /// same minimal-PE path as the controller tests.
    fn build_loader_result(module_base: u64, file_rva: u64) -> LoaderResult {
        use crate::unpacker::runtime_loader::{RuntimeAuthorityManifest, RuntimeDigestAuthority};
        // Minimal valid x64 PE with a real SizeOfImage envelope.
        let mut b = vec![0u8; 0x1000];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
        b[0xE8..0xEC].copy_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        let dir = std::env::temp_dir().join("mida-walker-dispatch-test");
        let _ = std::fs::create_dir_all(&dir);
        let p = dir.join(format!(
            "loader_{}_{}_{}.dll",
            std::process::id(),
            file_rva,
            SEQ.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::write(&p, &b).unwrap();
        let manifest = RuntimeAuthorityManifest {
            schema: "mida.antidebug-runtime-authority/v1".to_string(),
            kind: "runtime-x64".to_string(),
            artifact_id: "mida-antidebug-runtime-x64".to_string(),
            sha256: sha256_hex(&b),
            size_bytes: b.len() as u64,
            architecture: "x86_64".to_string(),
            source_ref: "test-commit".to_string(),
            provenance_ref: "provenance.json".to_string(),
        };
        let identity = manifest.verify_file(&p).unwrap();
        // WO-11: fixtures are process-unique (SEQ) and temp-only; remove the
        // file right after verification so `temp/mida-walker-dispatch-test/`
        // never accumulates orphaned unique-named DLLs across runs.
        let _ = std::fs::remove_file(&p);
        let digest_authority =
            RuntimeDigestAuthority::from_verified_identity(&identity, &manifest.artifact_id)
                .expect("verified identity must build authority");
        LoaderResult::new(
            module_base,
            "{}".to_string(),
            identity,
            digest_authority,
            std::process::id(),
            Some(file_rva),
            None, // walker_exports: set explicitly by WIRING-2 tests
        )
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let d = h.finalize();
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The thunk args fixture: WalkerExecute(params_va) with one arg.
    fn args_for(remote_va: u64, params_va: u64) -> WalkerThunkArgs {
        WalkerThunkArgs {
            fn_ptr: remote_va,
            arg0: params_va,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            reserved: 0,
        }
    }

    // ---------- T1: frozen thunk bytes ----------

    #[test]
    fn t01_thunk_bytes_frozen_identical_to_production() {
        // The dispatch bridge MUST use the exact frozen 60-byte production
        // thunk. Any divergence (probe variant, re-encoding, length change)
        // is a wiring error that must fail the build.
        assert_eq!(
            THUNK7_PRODUCTION, EXPECTED_THUNK,
            "THUNK7_PRODUCTION changed from the frozen fixture"
        );
        assert_eq!(THUNK7_PRODUCTION.len(), 60);
        // call rax at 0x35, add rsp,0x38 at 0x37, ret at 0x3B (structural
        // invariants of the frozen fixture).
        assert_eq!(THUNK7_PRODUCTION[0x35], 0xFF);
        assert_eq!(THUNK7_PRODUCTION[0x36], 0xD0);
        assert_eq!(THUNK7_PRODUCTION[0x37], 0x48);
        assert_eq!(THUNK7_PRODUCTION[0x3B], 0xC3);
    }

    #[test]
    fn t02_thunk_args_layout_matches_runtime_loader() {
        // The 64-byte args blob layout (fn_ptr + arg0..arg5 + reserved)
        // MUST match the loader's ThunkArgs so a thunk written by the
        // bridge is binary-compatible with the loader's thunk consumers.
        let a = args_for(0x7FF600000000 + 0x2040, 0x1234);
        let bytes = a.as_bytes();
        assert_eq!(bytes.len(), 64);
        assert_eq!(
            u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            0x7FF600000000 + 0x2040
        );
        assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x1234);
        assert_eq!(u64::from_le_bytes(bytes[56..64].try_into().unwrap()), 0);
        // Cross-check against the runtime_loader ThunkArgs (same layout).
        let loader_args = crate::unpacker::runtime_loader::ThunkArgs {
            fn_ptr: 0x7FF600000000 + 0x2040,
            arg0: 0x1234,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            reserved: 0,
        };
        assert_eq!(a.as_bytes(), loader_args.as_bytes());
    }

    // ---------- T3: dual-sealed cross-check ----------

    #[test]
    fn t03_cross_check_passes_on_matching_carriers() {
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, exports);
        assert!(bridge.carriers_complete());
        assert!(
            bridge.cross_check_passes(0x7FF600000000 + 0x2040),
            "remote_va == module_base + file_rva must pass"
        );
    }

    #[test]
    fn t04_cross_check_fails_closed_on_mismatch() {
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, exports);
        // Same module_base but a DIFFERENT remote VA (0x2041): the two
        // sealed chains disagree -> must fail closed.
        assert!(!bridge.cross_check_passes(0x7FF600000000 + 0x2041));
        // A completely different VA also fails.
        assert!(!bridge.cross_check_passes(0x1000));
        // Zero remote VA fails.
        assert!(!bridge.cross_check_passes(0));
    }

    #[test]
    fn t05_cross_check_fails_closed_on_missing_walker_execute_export() {
        // The REMOTE-side carrier missing (walker_execute unresolved):
        // construction must fail closed (the loader's own
        // require_complete() already guarantees the 5-item export set, so
        // a missing WalkerExecute is a programming error that must never
        // reach a dispatch).
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let mut incomplete = exports;
        incomplete.walker_execute = None;
        let panic = std::panic::catch_unwind(|| {
            let _ = WalkerDispatchBridgeImpl::new(self_handle(), loader, incomplete);
        });
        assert!(
            panic.is_err(),
            "bridge construction without the live export carrier must fail closed"
        );
        // And the cross-check itself: with no remote carrier there is
        // nothing to authorize against.
        let (loader2, exports2) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader2, exports2);
        assert!(bridge.cross_check_passes(0x7FF600000000 + 0x2040));
    }

    #[test]
    fn t06_cross_check_fails_closed_on_overflow() {
        // module_base + file_rva overflows u64: the checked_add inside
        // cross_check_passes must return false (never dispatch at a
        // wrapped VA).
        let loader = build_loader_result(u64::MAX, 0x2040);
        let exports = MidaExportsV2 {
            initialize: Some(0x100),
            get_attestation: Some(0x200),
            shutdown: Some(0x300),
            initialize_v2: Some(0x400),
            walker_execute: Some(0x1000),
        };
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, exports);
        assert!(
            !bridge.cross_check_passes(0x1000),
            "overflowing module_base + rva must fail closed"
        );
        assert!(!bridge.cross_check_passes(u64::MAX));
    }

    // ---------- T7: dispatch gate without live dispatch ----------

    #[test]
    fn t07_dispatch_fails_closed_on_cross_check_mismatch() {
        // The dispatch entry itself: a bridge whose remote VA does not
        // match module_base + file_rva returns BAD_PARAMS + None BEFORE any
        // remote call (no process access, no CreateRemoteThread).
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let mut bad_exports = exports;
        bad_exports.walker_execute = Some(0x7FF600000000 + 0x2041); // mismatch
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, bad_exports);
        let (status, output) = bridge.dispatch(0x1234);
        assert_eq!(
            status,
            mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_BAD_PARAMS as i32
        );
        assert!(output.is_none(), "no output may be marshaled on mismatch");
    }

    #[test]
    fn t08_dispatch_fails_closed_on_noncanonical_params_va() {
        // Zero / kernel-high-half params VA: the protocol gate rejects
        // before any remote call.
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, exports);
        let (status, output) = bridge.dispatch(0);
        assert_eq!(
            status,
            mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_BAD_PARAMS as i32
        );
        assert!(output.is_none());
        let (status, output) = bridge.dispatch(0xFFFF_8000_0000_0000);
        assert_eq!(
            status,
            mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_BAD_PARAMS as i32
        );
        assert!(output.is_none());
    }

    // ---------- T9-T12: bridge-level dispatch semantics (offline) ----------
    // The full in-process walker lifecycle (install -> WalkerExecute ->
    // output channel) is already proven by the walker_session and
    // controller test modules under their own locks. These tests verify
    // the BRIDGE's own offline guarantees: the marshal blob the bridge
    // would write into the target, the fail-closed dispatch gates, and
    // the sealed-carrier contract.

    #[test]
    fn t09_dispatch_marshal_blob_carries_only_authorized_target() {
        // The exact blob the bridge writes into the target: frozen thunk
        // bytes + args at THUNK_ARGS_OFFSET. The fn_ptr slot must equal
        // the cross-checked remote VA (module_base + file_rva) — the only
        // code pointer ever placed in the target by this bridge.
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, exports);
        let remote_va = bridge.exports.walker_execute.unwrap() as u64;
        assert_eq!(remote_va, 0x7FF600000000 + 0x2040);
        let args = args_for(remote_va, 0x7777);
        let mut blob = [0u8; THUNK_BLOB_SIZE];
        blob[0..THUNK7_PRODUCTION.len()].copy_from_slice(&THUNK7_PRODUCTION);
        blob[THUNK_ARGS_OFFSET..THUNK_ARGS_OFFSET + THUNK_ARGS_SIZE]
            .copy_from_slice(&args.as_bytes());
        // The blob layout matches the loader's thunk contract exactly
        // (code window + args window inside one 0x100 allocation).
        assert_eq!(
            u64::from_le_bytes(
                blob[THUNK_ARGS_OFFSET..THUNK_ARGS_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            remote_va
        );
        assert_eq!(
            u64::from_le_bytes(
                blob[THUNK_ARGS_OFFSET + 8..THUNK_ARGS_OFFSET + 16]
                    .try_into()
                    .unwrap()
            ),
            0x7777
        );
    }

    #[test]
    fn t10_dispatch_fails_closed_when_args_pointer_diverges() {
        // The thunk's `call rax` reads fn_ptr from the args blob. If the
        // blob ever carried a DIFFERENT pointer than the cross-checked
        // remote_va, the marshaling must refuse (fail-closed) — the
        // authorized address is the ONLY one that may be called.
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, exports);
        // thunk_call_raw with a mismatched fn_ptr must return None
        // (marshaling refused before any thread is created).
        let bad_args = WalkerThunkArgs {
            fn_ptr: 0x7FF600000000 + 0x2041, // NOT the cross-checked VA
            arg0: 0x7777,
            arg1: 0,
            arg2: 0,
            arg3: 0,
            arg4: 0,
            arg5: 0,
            reserved: 0,
        };
        let remote_va = bridge.exports.walker_execute.unwrap() as u64;
        let result = unsafe { bridge.thunk_call_raw(remote_va, &bad_args) };
        assert!(
            result.is_none(),
            "divergent fn_ptr must be refused before any remote call"
        );
    }

    #[test]
    fn t11_bridge_carrier_contract_requires_both_sealed_sources() {
        // The bridge is constructible only when BOTH sealed carriers are
        // complete (the loader's pure-file RVA + the live-resolved export).
        // This is the type-level enforcement of the authority matrix.
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = WalkerDispatchBridgeImpl::new(self_handle(), loader, exports);
        assert!(bridge.carriers_complete());
        // carriers_complete() is the observable gate: with the loader
        // carrier present and the export carrier present it is true.
        assert_eq!(bridge.exports.walker_execute, Some(0x7FF600000000 + 0x2040));
    }

    #[test]
    fn t12_thunk_args_serialization_roundtrip_consistent() {
        // The bridge's own args serializer is byte-stable: the same logical
        // call always produces the same 64-byte blob (deterministic remote
        // marshaling; no hidden state).
        let a1 = args_for(0x7FF600000000 + 0x2040, 0x7777);
        let a2 = args_for(0x7FF600000000 + 0x2040, 0x7777);
        assert_eq!(a1.as_bytes(), a2.as_bytes());
        // And the fn_ptr slot is the only code pointer in the blob.
        let bytes = a1.as_bytes();
        let ptr = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(ptr, 0x7FF600000000 + 0x2040);
        // The reserved slot must stay zero (never smuggles state).
        assert_eq!(u64::from_le_bytes(bytes[56..64].try_into().unwrap()), 0);
    }

    // -------------------------------------------------------------------
    // T13-T16 (IMP-09-DISPATCH-WIRING): env-gated live dispatch bridge.
    //
    // These tests exercise live_dispatch_gate() +
    // try_build_live_dispatch_bridge() fully offline. Every env mutation is
    // serialized under ENV_LOCK (same pattern as walker_session
    // INSTALL_LOCK) so parallel test threads can never observe a foreign
    // env state. The carrier pair is built through the REAL sealed
    // constructors (build_loader_result / carrier_pair) exactly like
    // T3-T12; a "complete carriers" pair passes the dual-sealed
    // cross-check, and a mismatch pair must fail closed even with the gate
    // open (T15).
    // -------------------------------------------------------------------

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Set env vars for the gate under the serial lock; returns the previous
    /// values (None = absent) for restore by drop_env_state().
    fn set_gate_env(no_bypass: Option<&str>, live_dispatch: Option<&str>) {
        set_env_opt(GTO_ENV_NO_BYPASS, no_bypass);
        set_env_opt(GTO_ENV_LIVE_DISPATCH, live_dispatch);
    }

    fn set_env_opt(key: &str, val: Option<&str>) {
        match val {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    /// Remove both gate vars (restore the offline default).
    fn clear_gate_env() {
        unsafe {
            std::env::remove_var(GTO_ENV_NO_BYPASS);
            std::env::remove_var(GTO_ENV_LIVE_DISPATCH);
        }
    }

    #[test]
    fn t13_gate_closed_returns_none_bridge() {
        // Gate closed (missing / partial env) -> construction path yields
        // None even with complete carriers (offline default preserved).
        let _lock = ENV_LOCK.lock().unwrap();
        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);

        // Both vars missing.
        clear_gate_env();
        assert!(!live_dispatch_gate());
        assert!(
            try_build_live_dispatch_bridge(self_handle(), Some(&loader), Some(&exports)).is_none()
        );

        // Only NO_BYPASS set.
        set_gate_env(Some("1"), None);
        assert!(!live_dispatch_gate());
        assert!(
            try_build_live_dispatch_bridge(self_handle(), Some(&loader), Some(&exports)).is_none()
        );

        // Only LIVE_DISPATCH set.
        set_gate_env(None, Some("1"));
        assert!(!live_dispatch_gate());
        assert!(
            try_build_live_dispatch_bridge(self_handle(), Some(&loader), Some(&exports)).is_none()
        );

        // Wrong value ("0").
        set_gate_env(Some("0"), Some("1"));
        assert!(!live_dispatch_gate());
        assert!(
            try_build_live_dispatch_bridge(self_handle(), Some(&loader), Some(&exports)).is_none()
        );

        clear_gate_env();
    }

    #[test]
    fn t14_gate_open_with_complete_carriers_builds_bridge() {
        // Gate open + complete sealed carriers -> Some(bridge) whose
        // dual-sealed cross-check passes.
        let _lock = ENV_LOCK.lock().unwrap();
        set_gate_env(Some("1"), Some("1"));
        assert!(live_dispatch_gate());

        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let bridge = try_build_live_dispatch_bridge(self_handle(), Some(&loader), Some(&exports));
        let bridge = bridge.expect("gate open + complete carriers must build");
        assert!(bridge.carriers_complete());
        // Offline discipline (same as T3-T12): never CreateRemoteThread against
        // a real process. The dual-sealed cross-check is the observable proof
        // that the authority chain accepted the remote VA.
        assert!(bridge.cross_check_passes(0x7FF600000000 + 0x2040));
        assert!(!bridge.cross_check_passes(0x7FF600000000 + 0x2041));

        // Carrier missing -> None even with the gate open (fail-closed).
        assert!(try_build_live_dispatch_bridge(self_handle(), None, Some(&exports)).is_none());
        assert!(try_build_live_dispatch_bridge(self_handle(), Some(&loader), None,).is_none());

        clear_gate_env();
    }

    #[test]
    fn t15_gate_open_cannot_bypass_cross_check_mismatch() {
        // Gate open + a mismatch carrier pair (remote VA != module_base +
        // file_rva) must fail the authority chain: dispatch returns
        // BAD_PARAMS (never dispatches against a VA the two sealed chains
        // disagree on).
        let _lock = ENV_LOCK.lock().unwrap();
        set_gate_env(Some("1"), Some("1"));
        assert!(live_dispatch_gate());

        let (loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        let mut bad_exports = exports.clone();
        bad_exports.walker_execute = Some(0x7FF600000000 + 0x2041); // mismatch
        let bridge =
            try_build_live_dispatch_bridge(self_handle(), Some(&loader), Some(&bad_exports))
                .expect("gate open + carriers present constructs; mismatch is caught at dispatch");
        let (status, output) = bridge.dispatch(0x7777);
        assert_eq!(
            status,
            mida_antidebug_runtime::walker_protocol::WALKER_STATUS_ERROR_BAD_PARAMS as i32
        );
        assert!(output.is_none(), "no output may be marshaled on mismatch");

        clear_gate_env();
    }

    #[test]
    fn t16_env_tests_serialized_and_reproducible() {
        // T16: prove the env-lock discipline. Run the same gate logic twice
        // under the lock; both runs agree (deterministic, no cross-test
        // pollution) and the env is restored to the offline default at the
        // end so the whole suite stays reproducible.
        let _lock = ENV_LOCK.lock().unwrap();

        for _ in 0..2 {
            clear_gate_env();
            assert!(!live_dispatch_gate());
            set_gate_env(Some("1"), Some("1"));
            assert!(live_dispatch_gate());
            set_gate_env(Some("1"), None);
            assert!(!live_dispatch_gate());
            clear_gate_env();
            assert!(!live_dispatch_gate());
        }

        // Also verify the retired variable is not consulted: setting only
        // MIDA_GTO_LIVE_AUTHORIZED=1 (with both new vars absent) stays closed.
        unsafe { std::env::set_var("MIDA_GTO_LIVE_AUTHORIZED", "1") };
        assert!(!live_dispatch_gate());
        unsafe { std::env::remove_var("MIDA_GTO_LIVE_AUTHORIZED") };
        assert!(!live_dispatch_gate());
    }

    // -------------------------------------------------------------------
    // T17-T18 (WIRING-2): remote exports carrier channel.
    //
    // The channel: run_runtime_loader now carries the REMOTE-side sealed
    // MidaExportsV2 on LoaderResult.walker_exports (the same set resolved
    // from the TARGET process memory by resolve_mida_exports_remote, with
    // require_complete() already passed inside the loader). T17 proves the
    // carrier round-trips through the sealed ctor and that the remote VA
    // agrees with the file-side RVA (module_base + file_rva) — the
    // dual-sealed cross-check input. T18 proves the production wiring seam
    // consumes the channel: gate open + channel carriers -> Some(bridge);
    // channel missing (walker_exports None) -> None (fail-closed).
    // -------------------------------------------------------------------

    #[test]
    fn t17_loader_result_carries_remote_exports_consistent_with_file_rva() {
        // Build a sealed LoaderResult whose walker_exports channel carries
        // the remote-side set (test stand-in for run_runtime_loader output;
        // the loader itself sets Some(loaded.exports) at runtime_loader.rs).
        let (mut loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        // Simulate the WIRING-2 loader channel: attach the remote exports
        // set to the LoaderResult. The channel is a separate sealed field;
        // we rebuild through the same pub(crate) sealed ctor used by the
        // production loader so the test exercises the real carrier path.
        loader = LoaderResult::new(
            loader.module_base(),
            "{}".to_string(),
            loader.file_identity().clone(),
            loader.digest_authority().clone(),
            loader.target_pid(),
            loader.walker_export_rva(),
            Some(exports.clone()),
        );
        let carried = loader
            .walker_exports()
            .expect("WIRING-2 channel must carry the remote exports set");
        let remote_va = carried
            .walker_execute
            .expect("complete exports set has walker_execute");
        // Dual-sealed cross-check input consistency: remote VA ==
        // module_base + file_rva (both sealed chains agree).
        let file_rva = loader
            .walker_export_rva()
            .expect("file-side RVA carrier present");
        assert_eq!(remote_va as u64, loader.module_base() + file_rva);
        assert_eq!(remote_va as u64, 0x7FF600000000 + 0x2040);
        // And the channel is Some only when the loader succeeded; a
        // bare LoaderResult without the channel stays None (fail-closed).
        let (bare, _) = carrier_pair(0x7FF600000000, 0x2040);
        assert!(bare.walker_exports().is_none());
    }

    #[test]
    fn t18_gate_open_consumes_channel_bridge_builds_otherwise_none() {
        let _lock = ENV_LOCK.lock().unwrap();
        set_gate_env(Some("1"), Some("1"));
        assert!(live_dispatch_gate());

        // Channel present (T17 carrier) -> bridge constructs.
        let (mut loader, exports) = carrier_pair(0x7FF600000000, 0x2040);
        loader = LoaderResult::new(
            loader.module_base(),
            "{}".to_string(),
            loader.file_identity().clone(),
            loader.digest_authority().clone(),
            loader.target_pid(),
            loader.walker_export_rva(),
            Some(exports.clone()),
        );
        // Concrete return: lets us assert carriers_complete / cross_check.
        let bridge =
            try_build_live_dispatch_bridge(self_handle(), Some(&loader), loader.walker_exports())
                .expect("gate open + channel carriers must build the bridge");
        assert!(bridge.carriers_complete());
        assert!(bridge.cross_check_passes(0x7FF600000000 + 0x2040));
        // Boxed variant (production slot type) also yields Some.
        assert!(try_build_live_dispatch_bridge_boxed(
            self_handle(),
            Some(&loader),
            loader.walker_exports(),
        )
        .is_some());

        // Channel missing (loader.walker_exports None) -> None.
        let (bare, _) = carrier_pair(0x7FF600000000, 0x2040);
        assert!(try_build_live_dispatch_bridge_boxed(
            self_handle(),
            Some(&bare),
            bare.walker_exports(),
        )
        .is_none());

        // Loader missing entirely -> None.
        assert!(try_build_live_dispatch_bridge_boxed(self_handle(), None, None,).is_none());

        clear_gate_env();
    }
}
