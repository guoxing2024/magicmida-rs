//! Pre-OEP bootstrap for restoring heap-backed SecurityCookie-encoded containers.
//!
//! This module extends the basic heap bootstrap to handle containers that store
//! application data on the unpacking process heap. The stub embedded in `.boot`:
//!
//! 1. Calls GetProcessHeap to initialize the stale heap handle
//! 2. For each container snapshot:
//!    - Allocates heap memory via HeapAlloc
//!    - Copies the embedded snapshot data to the new heap
//!    - Updates the SecurityCookie-encoded pointers in `.data`
//! 3. Jumps to the original entry point
//!
//! ## Layout
//!
//! ```text
//! .boot section:
//!   [stub code ~150-200 bytes]
//!   [container metadata array]
//!   [heap snapshot data for container 0]
//!   [heap snapshot data for container 1]
//!   ...
//! ```
//!
//! ## Metadata format (per container, 40 bytes)
//!
//! ```text
//! +0x00: u32  data_rva        — RVA in `.data` where encoded triple lives
//! +0x04: u32  heap_size       — Size to allocate (decoded_end - decoded_begin)
//! +0x08: u64  cookie          — SecurityCookie for encoding
//! +0x10: u32  data_offset     — Offset in .boot to heap snapshot
//! +0x14: u32  _reserved
//! +0x18: u64  _pad
//! +0x20: u64  _pad
//! ```

use tracing::{info, warn};

use crate::header::PeHeader;

use super::container_snapshot::ContainerSnapshot;
use crate::dumper::global_vars::GlobalVarSnapshot;

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

const CONTAINER_METADATA_SIZE: usize = 40;

/// Install a pre-OEP bootstrap stub that restores heap-backed containers.
///
/// Returns the bootstrap RVA when one was installed, otherwise `None`.
pub(crate) fn install_container_bootstrap(
    pe: &mut PeHeader,
    containers: &[ContainerSnapshot],
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    original_entry_point: u32,
) -> Option<u32> {
    if !pe.is_64bit {
        warn!("Container bootstrap only supports x64");
        return None;
    }

    if containers.is_empty() {
        return None;
    }

    let section_idx = pe.create_section_index(".boot", 0x1000);
    let stub_rva = pe.sections[section_idx].virtual_address;

    let stub_result = build_container_stub(
        stub_rva,
        original_entry_point,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
    );

    let stub = match stub_result {
        Some(stub) => stub,
        None => {
            pe.sections.remove(section_idx);
            pe.nt_headers.optional_header.size_of_image = pe
                .sections
                .last()
                .map(|section| {
                    crate::utils::align_up(
                        section.virtual_address.saturating_add(section.virtual_size),
                        pe.nt_headers.optional_header.section_alignment,
                    )
                })
                .unwrap_or(pe.nt_headers.optional_header.size_of_headers);
            warn!("Container bootstrap targets are outside the x64 relative-address range");
            return None;
        }
    };

    let stub_len = stub.len();
    let aligned_size = crate::utils::align_up(stub_len as u32, 0x1000);

    let section = &mut pe.sections[section_idx];
    section.characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
    section.header.characteristics = section.characteristics;
    section.header.virtual_size = aligned_size;
    section.virtual_size = aligned_size;
    section.header.size_of_raw_data = aligned_size;
    section.raw_size = aligned_size;
    section.extra_data = Some(stub);

    info!(
        stub_rva = format_args!("{stub_rva:#x}"),
        containers = containers.len(),
        stub_size = stub_len,
        original_entry_point = format_args!("{original_entry_point:#x}"),
        "Installed pre-OEP container restoration bootstrap"
    );

    Some(stub_rva)
}

/// Build bootstrap stub for TLS callback (no jump to OEP, just returns).
pub(crate) fn build_tls_bootstrap_stub(
    stub_rva: u32,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
    global_vars: &[super::global_vars::GlobalVarSnapshot],
) -> Option<Vec<u8>> {
    build_container_stub_internal(
        stub_rva,
        None,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
        global_vars,
    )
}

/// Build the complete bootstrap: stub code + metadata + heap snapshots.
fn build_container_stub(
    stub_rva: u32,
    original_entry_point: u32,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
) -> Option<Vec<u8>> {
    build_container_stub_internal(
        stub_rva,
        Some(original_entry_point),
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
        &[],
    )
}

/// Internal builder supporting both entry-point and TLS callback modes.
fn build_container_stub_internal(
    stub_rva: u32,
    original_entry_point: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
    global_vars: &[super::global_vars::GlobalVarSnapshot],
) -> Option<Vec<u8>> {
    let mut stub = Vec::new();

    // Calculate offsets
    let code_size = estimate_code_size(containers.len());
    let metadata_offset = code_size;
    let data_base_offset = metadata_offset + containers.len() * CONTAINER_METADATA_SIZE;
    let global_vars_offset = data_base_offset + containers.iter().map(|c| c.heap_content.len()).sum::<usize>();

    // 1. Build code section
    build_stub_code(
        &mut stub,
        stub_rva,
        original_entry_point,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers.len(),
        metadata_offset as u32,
        global_vars,
        global_vars_offset,
    )?;

    // Pad to metadata_offset
    stub.resize(metadata_offset, 0xcc);

    // 2. Build metadata array
    let mut current_data_offset = data_base_offset;
    for container in containers {
        let heap_size = container.decoded_end.saturating_sub(container.decoded_begin);
        stub.extend_from_slice(&container.rva.to_le_bytes());
        stub.extend_from_slice(&(heap_size as u32).to_le_bytes());
        stub.extend_from_slice(&container.cookie.to_le_bytes());
        stub.extend_from_slice(&(current_data_offset as u32).to_le_bytes());
        stub.extend_from_slice(&[0u8; 4]); // reserved
        stub.extend_from_slice(&[0u8; 8]); // pad
        stub.extend_from_slice(&[0u8; 8]); // pad
        current_data_offset += container.heap_content.len();
    }

    // 3. Append heap snapshot data
    for container in containers {
        stub.extend_from_slice(&container.heap_content);
    }

    // 4. Append global variables data (will be read by code in build_stub_code)
    for var in global_vars {
        stub.extend_from_slice(&var.value);
    }

    Some(stub)
}

/// Build the x64 stub code that performs container restoration.
///
/// Assembly pseudo-code:
/// ```asm
/// sub rsp, 0x38          ; shadow space + alignment
/// call [GetProcessHeap]
/// mov r15, rax           ; r15 = heap handle
/// lea r14, [metadata]    ; r14 = metadata array base
/// mov r13d, count        ; r13 = container count
/// .loop:
///   mov rcx, r15         ; hHeap
///   xor edx, edx         ; dwFlags = 0
///   mov r8d, [r14+4]     ; size
///   call [HeapAlloc]
///   test rax, rax
///   jz .skip
///   lea r9, [rip + base] ; source = stub_base + data_offset
///   add r9, [r14+16]
///   mov rcx, rax         ; dest
///   mov rdx, r9          ; source
///   mov r8d, [r14+4]     ; count
///   call memcpy_inline
///   mov ecx, [r14]       ; data_rva
///   mov rdx, [r14+8]     ; cookie
///   call update_triple   ; update encoded pointers
/// .skip:
///   add r14, 40
///   dec r13d
///   jnz .loop
/// add rsp, 0x38
/// jmp [original_oep]
/// ```
fn build_stub_code(
    stub: &mut Vec<u8>,
    stub_rva: u32,
    original_entry_point: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    container_count: usize,
    metadata_offset: u32,
    global_vars: &[GlobalVarSnapshot],
    global_vars_offset: usize,
) -> Option<()> {
    // sub rsp, 0x38
    stub.extend_from_slice(&[0x48, 0x83, 0xec, 0x38]);

    // call [rip + GetProcessHeap]
    stub.extend_from_slice(&[0xff, 0x15]);
    let call_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    let gph_disp = relative_displacement(call_next, get_process_heap_iat_rva)?;
    tracing::debug!(
        "GetProcessHeap call: next_rva={:#x}, target_iat={:#x}, displacement={:#x}",
        call_next,
        get_process_heap_iat_rva,
        i32::from_le_bytes(gph_disp)
    );
    stub.extend_from_slice(&gph_disp);

    // mov r15, rax (save heap handle)
    stub.extend_from_slice(&[0x49, 0x89, 0xc7]);

    // lea r14, [rip + metadata_offset]
    let metadata_rva = stub_rva.checked_add(metadata_offset)?;
    stub.extend_from_slice(&[0x4c, 0x8d, 0x35]);
    let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(lea_next, metadata_rva)?);

    // mov r13d, container_count
    stub.extend_from_slice(&[0x41, 0xbd]);
    stub.extend_from_slice(&(container_count as u32).to_le_bytes());

    // .loop:
    let loop_start = stub.len();

    // mov rcx, r15 (hHeap)
    stub.extend_from_slice(&[0x4c, 0x89, 0xf9]);

    // xor edx, edx (dwFlags = 0)
    stub.extend_from_slice(&[0x31, 0xd2]);

    // mov r8d, [r14+4] (heap_size)
    stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x04]);

    // call [rip + HeapAlloc]
    stub.extend_from_slice(&[0xff, 0x15]);
    let alloc_call_offset_in_stub = stub.len();
    let alloc_call_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    let heap_alloc_disp = relative_displacement(alloc_call_next, heap_alloc_iat_rva)?;
    tracing::debug!(
        "HeapAlloc call: next_rva={:#x}, target_iat={:#x}, displacement={:#x}, offset_in_stub={}",
        alloc_call_next,
        heap_alloc_iat_rva,
        i32::from_le_bytes(heap_alloc_disp),
        alloc_call_offset_in_stub
    );
    stub.extend_from_slice(&heap_alloc_disp);

    // test rax, rax
    stub.extend_from_slice(&[0x48, 0x85, 0xc0]);

    // jz .skip (placeholder - will be patched)
    stub.push(0x74);
    let skip_jz_offset = stub.len();
    stub.push(0x00); // placeholder

    // mov r12, rax (save allocated ptr)
    stub.extend_from_slice(&[0x49, 0x89, 0xc4]);

    // Inline memcpy: mov rcx, dest (already in rax/r12)
    stub.extend_from_slice(&[0x4c, 0x89, 0xe1]);

    // lea rdx, [rip + base]; add rdx, [r14+16] (source = stub_base + data_offset)
    stub.extend_from_slice(&[0x48, 0x8d, 0x15]);
    let source_lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(source_lea_next, stub_rva)?);
    stub.extend_from_slice(&[0x48, 0x03, 0x56, 0x10]);

    // mov r8d, [r14+4] (size)
    stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x04]);

    // call inline_memcpy
    stub.push(0xe8);
    let memcpy_offset = stub.len();
    stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // Update encoded triple: mov ecx, [r14] (data_rva)
    stub.extend_from_slice(&[0x41, 0x8b, 0x0e]);

    // mov rdx, [r14+8] (cookie)
    stub.extend_from_slice(&[0x49, 0x8b, 0x56, 0x08]);

    // mov r8, r12 (new heap ptr)
    stub.extend_from_slice(&[0x4d, 0x89, 0xe0]);

    // mov r9d, [r14+4] (heap_size)
    stub.extend_from_slice(&[0x45, 0x8b, 0x4e, 0x04]);

    // call inline_update_triple
    stub.push(0xe8);
    let update_offset = stub.len();
    stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // .skip:
    let skip_target = stub.len();
    let skip_displacement = (skip_target - skip_jz_offset - 1) as u8;
    stub[skip_jz_offset] = skip_displacement;

    // add r14, 40 (next metadata entry)
    stub.extend_from_slice(&[0x49, 0x83, 0xc6, 0x28]);

    // dec r13d
    stub.extend_from_slice(&[0x41, 0xff, 0xcd]);

    // jnz .loop
    let loop_end = stub.len();
    let loop_disp = -((loop_end - loop_start + 2) as i8);
    stub.extend_from_slice(&[0x75, loop_disp as u8]);

    // === Helper functions come BEFORE epilogue ===
    // This ensures they don't get executed in normal flow

    // Jump over helper functions to global vars restoration
    stub.push(0xeb); // jmp short
    let jmp_over_helpers_offset = stub.len();
    stub.push(0x00); // placeholder - will be patched

    // === Helper functions ===

    // inline_memcpy: simple rep movsb
    let memcpy_start = stub.len();
    // CRITICAL FIX: memcpy_offset was captured BEFORE the jmp instruction was added
    // We need to account for the 2-byte jmp that's now between the call and the target
    let memcpy_rel = ((memcpy_start - memcpy_offset - 4) as i32).to_le_bytes();
    stub[memcpy_offset..memcpy_offset + 4].copy_from_slice(&memcpy_rel);

    tracing::debug!(
        "memcpy_offset={}, memcpy_start={}, displacement={}",
        memcpy_offset,
        memcpy_start,
        i32::from_le_bytes(memcpy_rel)
    );

    // push rdi, rsi
    stub.extend_from_slice(&[0x57, 0x56]);
    // mov rdi, rcx; mov rsi, rdx; mov rcx, r8
    stub.extend_from_slice(&[0x48, 0x89, 0xcf, 0x48, 0x89, 0xd6, 0x4c, 0x89, 0xc1]);
    // rep movsb
    stub.extend_from_slice(&[0xf3, 0xa4]);
    // pop rsi, rdi
    stub.extend_from_slice(&[0x5e, 0x5f]);
    // ret
    stub.push(0xc3);

    // inline_update_triple: encode new pointers and write to .data
    let update_start = stub.len();
    let update_rel = ((update_start - update_offset - 4) as i32).to_le_bytes();
    stub[update_offset..update_offset + 4].copy_from_slice(&update_rel);

    tracing::debug!(
        "update_offset={}, update_start={}, displacement={}",
        update_offset,
        update_start,
        i32::from_le_bytes(update_rel)
    );

    // rcx = data_rva, rdx = cookie, r8 = new_heap_ptr, r9 = size
    // Calculate addresses: rva to virtual address (assume image_base in r11)
    // For simplicity, use image_base from register (set by loader) or fixed value
    // Here we'll use a simpler approach: lea base, [rip + known]

    // Get image base: lea r10, [rip - current_rva]
    stub.extend_from_slice(&[0x4c, 0x8d, 0x15]);
    let base_lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(base_lea_next, 0)?); // points to image base (RVA 0)

    // add r10, rcx (r10 = image_base + data_rva = target address)
    stub.extend_from_slice(&[0x49, 0x01, 0xca]);

    // Encode begin: xor r8, rdx -> [r10]
    stub.extend_from_slice(&[0x4c, 0x89, 0xc0]); // mov rax, r8
    stub.extend_from_slice(&[0x48, 0x31, 0xd0]); // xor rax, rdx
    stub.extend_from_slice(&[0x49, 0x89, 0x02]); // mov [r10], rax

    // Encode end: (r8 + r9) xor rdx -> [r10+8]
    stub.extend_from_slice(&[0x4d, 0x8d, 0x04, 0x08]); // lea r8, [r8 + r9]
    stub.extend_from_slice(&[0x4c, 0x89, 0xc0]); // mov rax, r8
    stub.extend_from_slice(&[0x48, 0x31, 0xd0]); // xor rax, rdx
    stub.extend_from_slice(&[0x49, 0x89, 0x42, 0x08]); // mov [r10+8], rax

    // Encode capacity: same as end -> [r10+16]
    stub.extend_from_slice(&[0x49, 0x89, 0x42, 0x10]); // mov [r10+16], rax

    // ret
    stub.push(0xc3);

    // === Patch jump over helpers ===
    let after_helpers = stub.len();
    let jmp_disp = (after_helpers - jmp_over_helpers_offset - 1) as u8;
    stub[jmp_over_helpers_offset] = jmp_disp;

    tracing::info!(
        "Bootstrap code layout: loop_end={}, jmp_over_at={}, helpers_end={}, jmp_disp={}",
        loop_end,
        jmp_over_helpers_offset - 1,
        after_helpers,
        jmp_disp
    );

    // === Restore global variables BEFORE returning ===
    // This must happen after container restoration but before jumping to OEP
    for (idx, var) in global_vars.iter().enumerate() {
        let data_offset = global_vars_offset + idx * 8;
        let data_rva = stub_rva.checked_add(data_offset as u32)?;
        let target_rva = var.rva;

        // lea rax, [rip + data]
        stub.extend_from_slice(&[0x48, 0x8D, 0x05]);
        let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        let disp1 = relative_displacement(lea_next, data_rva)?;
        stub.extend_from_slice(&disp1);

        // mov rax, [rax] - load the 8-byte value from data
        stub.extend_from_slice(&[0x48, 0x8B, 0x00]);

        // mov [rip + target], rax
        stub.extend_from_slice(&[0x48, 0x89, 0x05]);
        let mov_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        let disp2 = relative_displacement(mov_next, target_rva)?;
        stub.extend_from_slice(&disp2);
    }

    // add rsp, 0x38
    stub.extend_from_slice(&[0x48, 0x83, 0xc4, 0x38]);

    // Epilogue depends on mode
    if let Some(oep) = original_entry_point {
        // Entry-point mode: jmp original_entry_point
        stub.push(0xe9);
        let jmp_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(jmp_next, oep)?);
    } else {
        // TLS callback mode: ret
        stub.push(0xc3);
    }

    Some(())
}

fn relative_displacement(next_rva: u32, target_rva: u32) -> Option<[u8; 4]> {
    let displacement = i64::from(target_rva) - i64::from(next_rva);
    i32::try_from(displacement).ok().map(i32::to_le_bytes)
}

fn estimate_code_size(container_count: usize) -> usize {
    // Base setup: ~40 bytes
    // Loop body: ~80 bytes
    // Helpers (memcpy + update_triple): ~60 bytes
    // Epilogue: ~10 bytes
    let _ = container_count; // Size is mostly constant since loop is counted
    200
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_size_is_40_bytes() {
        assert_eq!(CONTAINER_METADATA_SIZE, 40);
    }

    #[test]
    fn estimate_reasonable() {
        let size = estimate_code_size(3);
        assert!(size >= 150 && size <= 256);
    }
}
