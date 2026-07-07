//! Anti-dump fix: install a stub at OEP that patches the PE header before
//! jumping to the VM entry point.

use tracing::info;

use mida_core::DebuggerCore;

use crate::error::ThemidaError;

// ---------------------------------------------------------------------------
// x86 stub
// ---------------------------------------------------------------------------

/// Size of the x86 anti-dump stub in bytes.
const ANTI_DUMP_STUB_SIZE_X86: usize = 56;

/// x86: build and write the anti-dump stub.
///
/// Layout (matching `AntiDumpFix.pas`):
///
/// ```text
///   push 0                          ; OldProtect placeholder
///   push esp                        ; &OldProtect
///   push 0x400                      ; PAGE_READWRITE
///   push 0x400                      ; size
///   push ImageBase                  ; address
///   call dword ptr [VirtualProtect] ; VirtualProtect(ImageBase, 0x400, PAGE_READWRITE, &Old)
///   mov dword ptr [ImageBase+LfaNew+0x28], EntryPoint  ; fix AddressOfEntryPoint
///   push esp                        ; &OldProtect
///   push dword ptr [esp+4]          ; OldProtect (read back)
///   push 0x400                      ; size
///   push ImageBase                  ; address
///   call dword ptr [VirtualProtect] ; VirtualProtect(ImageBase, 0x400, OldProtect, _)
///   pop eax                         ; clean up
///   jmp VM_Entry                    ; jump to VM
/// ```
pub(super) fn install_anti_dump_fix_x86(
    debugger: &mut dyn DebuggerCore,
    oep: usize,
    image_base: usize,
    virtual_protect_addr: usize,
    _vm_entry: usize,
) -> Result<(), ThemidaError> {
    let stub_size = ANTI_DUMP_STUB_SIZE_X86;

    // Read the original OEP to get the jmp displacement for the VM entry.
    let mut oep_buf = [0u8; 8];
    let n = debugger
        .read_memory(oep, &mut oep_buf)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix read OEP: {e}")))?;
    if n < 5 {
        return Err(ThemidaError::PostProcess(
            "OEP is too small to read original bytes".into(),
        ));
    }

    // The OEP should start with jmp rel32 (E9) — the displacement is used
    // for the final jump (adjusted for the new stub size).
    let orig_jmp_disp = i32::from_le_bytes([oep_buf[1], oep_buf[2], oep_buf[3], oep_buf[4]]);

    // Compute PE header fields.
    // LfaNew = offset of NT headers (stored at ImageBase + 0x3C).
    // EntryPoint = NT headers + 0x28 (AddressOfEntryPoint in optional header).

    // Read the NT headers to get the real AddressOfEntryPoint.
    let mut lfa_buf = [0u8; 4];
    debugger
        .read_memory(image_base + 0x3C, &mut lfa_buf)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix read lfanew: {e}")))?;
    let lfa_new = u32::from_le_bytes(lfa_buf) as usize;

    let entry_point_offset = image_base + lfa_new + 0x28;
    let mut ep_buf = [0u8; 4];
    debugger
        .read_memory(entry_point_offset, &mut ep_buf)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix read EntryPoint: {e}")))?;
    let entry_point = u32::from_le_bytes(ep_buf);

    let opt_hdr_entrypoint = (image_base + lfa_new + 0x28) as u32;

    // Build the stub.
    let mut stub = Vec::with_capacity(stub_size);

    // push 0                          ; OldProtect placeholder
    // push esp                        ; &OldProtect
    // push 0x400                      ; PAGE_READWRITE
    // push 0x400                      ; size
    // push ImageBase                  ; address
    stub.extend_from_slice(&[0x6A, 0x00, 0x54, 0x6A, 0x04, 0x68, 0x00, 0x04, 0x00, 0x00, 0x68]);
    stub.extend_from_slice(&(image_base as u32).to_le_bytes());

    // call dword ptr [VirtualProtect_addr]  ; FF 15 ...
    stub.extend_from_slice(&[0xFF, 0x15]);
    stub.extend_from_slice(&(virtual_protect_addr as u32).to_le_bytes());

    // mov dword ptr [OptHdrEntrypoint], EntryPoint   ; C7 05 ...
    stub.extend_from_slice(&[0xC7, 0x05]);
    stub.extend_from_slice(&opt_hdr_entrypoint.to_le_bytes());
    stub.extend_from_slice(&entry_point.to_le_bytes());

    // push esp                        ; &OldProtect
    // push dword ptr [esp+4]          ; OldProtect value
    // push 0x400                      ; size
    // push ImageBase                  ; address
    stub.extend_from_slice(&[0x54, 0xFF, 0x74, 0x24, 0x04, 0x68, 0x00, 0x04, 0x00, 0x00, 0x68]);
    stub.extend_from_slice(&(image_base as u32).to_le_bytes());

    // call dword ptr [VirtualProtect_addr]  ; FF 15 ...
    stub.extend_from_slice(&[0xFF, 0x15]);
    stub.extend_from_slice(&(virtual_protect_addr as u32).to_le_bytes());

    // pop eax         ; clean up stack
    stub.push(0x58);

    // jmp VM_Entry    ; E9 rel32 (adjusted for stub size)
    let new_disp = orig_jmp_disp - (stub.len() as i32 - 5);
    stub.push(0xE9);
    stub.extend_from_slice(&new_disp.to_le_bytes());

    // Write the stub to the target process.
    let bytes_written = debugger
        .write_memory(oep, &stub)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix write stub: {e}")))?;

    if bytes_written < stub.len() {
        return Err(ThemidaError::SpaceTooSmall {
            needed: stub.len(),
            available: bytes_written,
        });
    }

    info!(
        "Installed VM anti-dump (PE header) mitigation at OEP {oep:#x}  \
         (stub: {} bytes)",
        stub.len()
    );
    info!("NOTE: We assume there is enough space at the entrypoint, which may not be the case in every binary.");

    Ok(())
}

// ---------------------------------------------------------------------------
// x64 stub
// ---------------------------------------------------------------------------

/// Size of the x64 anti-dump stub in bytes.
const ANTI_DUMP_STUB_SIZE_X64: usize = 72;

/// x64: build and write the anti-dump stub.
///
/// Layout (x64 calling convention):
///
/// ```text
///   sub rsp, 0x28                   ; shadow space + alignment
///   lea r9, [rsp+0x30]              ; &OldProtect (placeholder on stack)
///   mov r8d, 0x04                   ; PAGE_READWRITE
///   mov edx, 0x400                  ; size
///   mov ecx, ImageBase              ; address (low 32)
///   call qword ptr [VirtualProtect] ; VirtualProtect(ImageBase, 0x400, RW, &Old)
///   mov dword ptr [ImageBase+LfaNew+0x28], EntryPoint
///   lea r9, [rsp+0x30]              ; &OldProtect
///   mov r8d, [rsp+0x30]             ; OldProtect value
///   mov edx, 0x400                  ; size
///   mov ecx, ImageBase
///   call qword ptr [VirtualProtect] ; restore protection
///   add rsp, 0x28
///   jmp VM_Entry
/// ```
pub(super) fn install_anti_dump_fix_x64(
    debugger: &mut dyn DebuggerCore,
    oep: usize,
    image_base: usize,
    virtual_protect_addr: usize,
    _vm_entry: usize,
) -> Result<(), ThemidaError> {
    let stub_size = ANTI_DUMP_STUB_SIZE_X64;

    // Read original OEP bytes to get the jmp displacement.
    let mut oep_buf = [0u8; 8];
    let n = debugger
        .read_memory(oep, &mut oep_buf)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix read OEP: {e}")))?;
    if n < 5 {
        return Err(ThemidaError::PostProcess(
            "OEP is too small to read original bytes".into(),
        ));
    }

    let orig_jmp_disp = i32::from_le_bytes([oep_buf[1], oep_buf[2], oep_buf[3], oep_buf[4]]);

    // Read PE header fields.
    let mut lfa_buf = [0u8; 4];
    debugger
        .read_memory(image_base + 0x3C, &mut lfa_buf)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix read lfanew: {e}")))?;
    let lfa_new = u32::from_le_bytes(lfa_buf) as usize;

    let entry_point_offset = image_base + lfa_new + 0x28;
    let mut ep_buf = [0u8; 4];
    debugger
        .read_memory(entry_point_offset, &mut ep_buf)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix read EntryPoint: {e}")))?;
    let entry_point = u32::from_le_bytes(ep_buf);

    let opt_hdr_entrypoint = (image_base + lfa_new + 0x28) as u64;

    // Build the stub.
    let mut stub = Vec::with_capacity(stub_size);

    // sub rsp, 0x28            ; shadow space (0x20) + alignment (0x08)
    stub.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);

    // lea r9, [rsp+0x30]       ; &OldProtect
    stub.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x30]);

    // mov r8d, 0x04             ; PAGE_READWRITE
    stub.extend_from_slice(&[0x41, 0xB8, 0x04, 0x00, 0x00, 0x00]);

    // mov edx, 0x400            ; size
    stub.extend_from_slice(&[0xBA, 0x00, 0x04, 0x00, 0x00]);

    // mov ecx, ImageBase (low 32 bits must fit)
    stub.push(0xB9);
    stub.extend_from_slice(&(image_base as u32).to_le_bytes());

    // call qword ptr [VirtualProtect_addr]
    stub.extend_from_slice(&[0xFF, 0x15]);
    // For x64, FF 15 takes a RIP-relative displacement.
    let rip_after_call = (oep + stub.len() + 6) as u64;
    let vp_disp = (virtual_protect_addr as i64 - rip_after_call as i64) as i32;
    stub.extend_from_slice(&vp_disp.to_le_bytes());

    // mov dword ptr [OptHdrEntrypoint], EntryPoint
    // C7 05 disp32 imm32 — RIP-relative
    stub.extend_from_slice(&[0xC7, 0x05]);
    let rip_after_mov = (oep + stub.len() + 10) as u64;
    let mov_disp = (opt_hdr_entrypoint as i64 - rip_after_mov as i64) as i32;
    stub.extend_from_slice(&mov_disp.to_le_bytes());
    stub.extend_from_slice(&entry_point.to_le_bytes());

    // lea r9, [rsp+0x30]       ; &OldProtect
    stub.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x30]);

    // mov r8d, [rsp+0x30]      ; OldProtect value
    stub.extend_from_slice(&[0x44, 0x8B, 0x44, 0x24, 0x30]);

    // mov edx, 0x400            ; size
    stub.extend_from_slice(&[0xBA, 0x00, 0x04, 0x00, 0x00]);

    // mov ecx, ImageBase
    stub.push(0xB9);
    stub.extend_from_slice(&(image_base as u32).to_le_bytes());

    // call qword ptr [VirtualProtect_addr]
    stub.extend_from_slice(&[0xFF, 0x15]);
    let rip_after_call2 = (oep + stub.len() + 6) as u64;
    let vp_disp2 = (virtual_protect_addr as i64 - rip_after_call2 as i64) as i32;
    stub.extend_from_slice(&vp_disp2.to_le_bytes());

    // add rsp, 0x28
    stub.extend_from_slice(&[0x48, 0x83, 0xC4, 0x28]);

    // jmp VM_Entry
    let jmp_target = (oep + 5) as i64 + orig_jmp_disp as i64;
    let new_disp = (jmp_target - (oep + stub.len() + 5) as i64) as i32;
    stub.push(0xE9);
    stub.extend_from_slice(&new_disp.to_le_bytes());

    // Write the stub.
    let bytes_written = debugger
        .write_memory(oep, &stub)
        .map_err(|e| ThemidaError::Debugger(format!("anti_dump_fix write stub (x64): {e}")))?;

    if bytes_written < stub.len() {
        return Err(ThemidaError::SpaceTooSmall {
            needed: stub.len(),
            available: bytes_written,
        });
    }

    info!(
        "Installed VM anti-dump (PE header) mitigation at OEP {oep:#x}  \
         (stub: {} bytes, x64)",
        stub.len()
    );
    info!("NOTE: We assume there is enough space at the entrypoint, which may not be the case in every binary.");

    Ok(())
}
