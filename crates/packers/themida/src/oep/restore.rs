//! OEP restoration (stolen bytes) and x64 MSVC OEP synthesis.
//!
//! Contains: `restore_stolen_oep_msvc6`, `restore_stolen_oep_msvc9_dll`,
//! `write_msvc_oep_x64`, and the `resolve_get_version_addr` helpers.

use tracing::{debug, info, trace, warn};

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
/// `Ok(false)` — the OEP doesn't look stolen (not MSVC6); nothing was done.
pub fn restore_stolen_oep_msvc6(
    debugger: &mut dyn DebuggerCore,
    oep: usize,
    image_base: usize,
    base_of_data: usize,
) -> Result<bool, ThemidaError> {
    // 1. Check for the sentinel bytes `mov dl, ah` (8A D4).
    let mut check: [u8; 2] = [0; 2];
    let read = debugger
        .read_memory(oep, &mut check)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC6 OEP sentinel: {e}")))?;

    if read < 2 || check[0] != 0x8A || check[1] != 0xD4 {
        trace!("Not MSVC6 or OEP not stolen");
        return Ok(false);
    }

    info!("Stolen MSVC6 OEP detected at {oep:#x}");

    let mut restore: [u8; 46] = [
        0x55, 0x8B, 0xEC, 0x6A, 0xFF,
        0x68, 0x00, 0x00, 0x00, 0x00, // [5..9]  exception_struct
        0x68, 0x00, 0x00, 0x00, 0x00, // [10..14] handler
        0x64, 0xA1, 0x00, 0x00, 0x00, 0x00, // [15..20] mov eax, fs:[0]
        0x50,                               // [21]     push eax
        0x64, 0x89, 0x25, 0x00, 0x00, 0x00, 0x00, // [22..28] mov fs:[0], esp
        0x83, 0xEC, 0x58,                         // [29..31] sub esp, 58h
        0x53, 0x56, 0x57,                         // [32..34] push ebx, esi, edi
        0x89, 0x65, 0xE8,                         // [35..37] mov [ebp-18h], esp
        0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,       // [38..43] call ds:GetVersion
        0x33, 0xD2,                               // [44..45] xor edx, edx
    ];

    // 2. Verify that there's a valid return instruction before the stolen OEP gap.
    let mut gap_check: [u8; 3] = [0; 3];
    let read = debugger
        .read_memory(oep.wrapping_sub(49), &mut gap_check)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC6 gap: {e}")))?;

    if read < 3 || (gap_check[0] != 0xC2 && gap_check[2] != 0xC3) {
        warn!("Stolen OEP gap mismatch — expected C2/C3 before stolen region");
        return Ok(false);
    }

    // 3. Resolve the GetVersion IAT entry.
    let get_version_addr = resolve_get_version_addr(debugger, image_base, base_of_data)?;
    if get_version_addr == 0 {
        warn!("Unable to find GetVersion in IAT — MSVC6 OEP may not resolve correctly");
        return Ok(false);
    }

    // Write the GetVersion IAT pointer into the stub at offsets [40..43].
    restore[40..44].copy_from_slice(&(get_version_addr as u32).to_le_bytes());

    // 4. Write the restored stub into the target at `oep - 46`.
    let stub_addr = oep.wrapping_sub(46);

    let written = debugger
        .write_memory(stub_addr, &restore)
        .map_err(|e| ThemidaError::Debugger(format!("write MSVC6 OEP stub: {e}")))?;

    if written < restore.len() {
        warn!(
            expected = restore.len(),
            actual = written,
            "Partial write of MSVC6 OEP stub"
        );
        return Ok(false);
    }

    info!("MSVC6 OEP restored — correct OEP at {stub_addr:#x}");
    Ok(true)
}

// ===========================================================================
// OEP restoration — MSVC 9 DLL (x86)
// ===========================================================================

/// Restore stolen OEP bytes for MSVC 9 DLLs (x86).
///
/// ## Returns
///
/// `Ok(true)`  — the OEP was restored (and `oep` was adjusted backward).
/// `Ok(false)` — not an MSVC9 DLL stolen OEP; nothing was done.
pub fn restore_stolen_oep_msvc9_dll(
    debugger: &mut dyn DebuggerCore,
    oep: usize,
    image_base: usize,
) -> Result<bool, ThemidaError> {
    let _ = image_base; // reserved for future use

    // 1. Check that OEP starts with E8 (call into VM / stolen code).
    let mut check: [u8; 1] = [0];
    let read = debugger
        .read_memory(oep, &mut check)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC9 OEP sentinel: {e}")))?;

    if read < 1 || check[0] != 0xE8 {
        trace!("Not MSVC9 DLL or OEP not stolen (missing E8 at OEP)");
        return Ok(false);
    }

    // 2. Check that the byte *before* the restored region is E9 (jmp to VM).
    let gap_addr = oep.wrapping_sub(11);
    let mut gap_byte: [u8; 1] = [0];
    let read = debugger
        .read_memory(gap_addr, &mut gap_byte)
        .map_err(|e| ThemidaError::Debugger(format!("read MSVC9 gap: {e}")))?;

    if read < 1 || gap_byte[0] != 0xE9 {
        trace!("Not MSVC9 DLL stolen OEP (missing E9 before gap)");
        return Ok(false);
    }

    info!("Stolen MSVC9 DLL OEP detected at {oep:#x}");

    // 3. Write the restore data.
    const RESTORE: [u8; 11] = [
        0x8B, 0xFF,                         // mov edi, edi
        0x55,                               // push ebp
        0x8B, 0xEC,                         // mov ebp, esp
        0x83, 0x7D, 0x0C, 0x01,            // cmp dword ptr [ebp+0Ch], 1
        0x75, 0x05,                         // jnz +5
    ];

    let stub_addr = oep.wrapping_sub(RESTORE.len());

    let written = debugger
        .write_memory(stub_addr, &RESTORE)
        .map_err(|e| ThemidaError::Debugger(format!("write MSVC9 DLL OEP stub: {e}")))?;

    if written < RESTORE.len() {
        warn!(
            expected = RESTORE.len(),
            actual = written,
            "Partial write of MSVC9 DLL OEP stub"
        );
        return Ok(false);
    }

    info!("MSVC9 DLL OEP restored — correct OEP at {stub_addr:#x}");
    Ok(true)
}

// ===========================================================================
// x64 MSVC OEP writing
// ===========================================================================

/// Write a synthetic MSVC OEP for x64 targets.
///
/// When the OEP is virtualised on x64, we synthesise a minimal OEP that
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

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Look up the IAT address of `GetVersion` in the target process (x86).
#[cfg(target_arch = "x86")]
fn resolve_get_version_addr(
    debugger: &dyn DebuggerCore,
    image_base: usize,
    base_of_data: usize,
) -> Result<usize, ThemidaError> {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::core::PCWSTR;

    let kernel32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
    // SAFETY: kernel32.dll is always loaded.
    let k32_handle = unsafe {
        GetModuleHandleW(PCWSTR::from_raw(kernel32_name.as_ptr()))
            .map_err(|e| ThemidaError::Debugger(format!("GetModuleHandle(kernel32): {e}")))?
    };
    // SAFETY: calling a Windows FFI function with validated, properly-lifetime arguments.
    let get_version_host = unsafe {
        let name = std::ffi::CStr::from_bytes_with_nul_unchecked(b"GetVersion\0");
        windows::Win32::System::LibraryLoader::GetProcAddress(k32_handle, name)
            .unwrap_or(std::ptr::null_mut())
    };

    if get_version_host.is_null() {
        warn!("GetVersion not found in host kernel32");
        return Ok(0);
    }

    let get_version_addr = get_version_host as usize;

    let iat_start = image_base.wrapping_add(base_of_data);
    let iat_size = 512 * 4;

    let mut iat_buf = vec![0u8; iat_size];
    let bytes_read = debugger
        .read_memory(iat_start, &mut iat_buf)
        .map_err(|e| ThemidaError::Debugger(format!("read IAT for GetVersion: {e}")))?;

    let dword_count = (bytes_read / 4).min(512);
    for i in 0..dword_count {
        let val = u32::from_le_bytes([
            iat_buf[i * 4],
            iat_buf[i * 4 + 1],
            iat_buf[i * 4 + 2],
            iat_buf[i * 4 + 3],
        ]);
        if (val as usize) == get_version_addr {
            let iat_slot = iat_start + i * 4;
            debug!("Found GetVersion IAT slot at {iat_slot:#x}");
            return Ok(iat_slot);
        }
    }

    warn!("GetVersion not found in target IAT");
    Ok(0)
}

/// x64 stub — no GetVersion needed (MSVC6 is x86 only).
#[cfg(target_arch = "x86_64")]
fn resolve_get_version_addr(
    _debugger: &dyn DebuggerCore,
    _image_base: usize,
    _base_of_data: usize,
) -> Result<usize, ThemidaError> {
    // MSVC6 is 32-bit only; this function should never be called on x64.
    Ok(0)
}
