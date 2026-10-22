//! OEP restoration (stolen bytes) and x64 MSVC OEP synthesis.
//!
//! Contains: `restore_stolen_oep_msvc6`, `restore_stolen_oep_msvc9_dll`,
//! `write_msvc_oep_x64`, and the `resolve_get_version_addr` helpers.

use tracing::{debug, warn};

use mida_core::DebuggerCore;

use crate::error::ThemidaError;

// ===========================================================================
// OEP restoration — MSVC 6 (x86)
// ===========================================================================

/// Restore stolen OEP bytes for MSVC 6 (x86).
///
/// MSVC 6-compiled binaries have a characteristic OEP. Themida overwrites the
/// start of this function with `mov dl, ah` (8A D4). We detect this sentinel
/// and restore the original stub from a template, patching in the correct
/// `GetVersion` IAT pointer.
///
/// ## Returns
///
/// `Ok(true)` — the OEP was successfully restored.

/// calls `__security_init_cookie` and then jumps to `__scrt_common_main_seh`.
pub fn write_msvc_oep_x64(
    debugger: &mut dyn DebuggerCore,
    h_process: windows::Win32::Foundation::HANDLE,
    oep: usize,
    security_init_cookie_addr: usize,
    scrt_common_main_seh_addr: usize,
) -> Result<(), ThemidaError> {
    use windows::Win32::System::Memory::{
        VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
    };

    let mut stub: Vec<u8> = vec![
        0x48, 0x83, 0xEC, 0x28,       // sub rsp, 28h
        0xE8, 0x00, 0x00, 0x00, 0x00, // call rel32 (placeholder)
        0x48, 0x83, 0xC4, 0x28,       // add rsp, 28h
        0xE9, 0x00, 0x00, 0x00, 0x00, // jmp rel32 (placeholder)
    ];

    let call_disp: i32 = (security_init_cookie_addr as i64)
        .wrapping_sub((oep + 9) as i64) as i32;
    stub[5..9].copy_from_slice(&call_disp.to_le_bytes());

    let jmp_disp: i32 = (scrt_common_main_seh_addr as i64)
        .wrapping_sub((oep + 18) as i64) as i32;
    stub[14..18].copy_from_slice(&jmp_disp.to_le_bytes());

    let mut old_protect = PAGE_PROTECTION_FLAGS::default();

    // SAFETY: h_process is valid; the OEP address is within .text which was
    // previously guarded (now being restored).
    unsafe {
        VirtualProtectEx(
            h_process,
            oep as *const std::ffi::c_void,
            stub.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| {
        ThemidaError::Debugger(format!(
            "VirtualProtectEx at OEP {oep:#x} for MSVC stub: {e}"
        ))
    })?;

    let written = debugger
        .write_memory(oep, &stub)
        .map_err(|e| ThemidaError::Debugger(format!("write MSVC x64 OEP stub: {e}")))?;

    if written < stub.len() {
        warn!(
            expected = stub.len(),
            actual = written,
            "Partial write of MSVC x64 OEP stub"
        );
    }

    debug!(
        "MSVC x64 OEP written at {oep:#x}: call → {security_init_cookie_addr:#x}, jmp → {scrt_common_main_seh_addr:#x}"
    );

    Ok(())
}
