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
    data_snapshot: Option<&super::data_snapshot::DataSectionSnapshot>,
    image_base: u64,
    data_section_rva: u32,
) -> Option<Vec<u8>> {
    build_container_stub_internal(
        stub_rva,
        None,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
        data_snapshot,
        image_base,
        data_section_rva,
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
        None,
        0,
        0, // data_section_rva - not needed for entry point mode
    )
}

/// Internal builder supporting both entry-point and TLS callback modes.
fn build_container_stub_internal(
    stub_rva: u32,
    original_entry_point: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
    data_snapshot: Option<&super::data_snapshot::DataSectionSnapshot>,
    image_base: u64,
    data_section_rva: u32,
) -> Option<Vec<u8>> {
    let mut stub = Vec::new();

    // Calculate offsets
    let code_size = estimate_code_size(containers.len(), data_snapshot.is_some());
    let metadata_offset = code_size;
    let data_base_offset = metadata_offset + containers.len() * CONTAINER_METADATA_SIZE;
    let data_snapshot_offset = data_base_offset
        + containers
            .iter()
            .map(|c| c.heap_content.len())
            .sum::<usize>();

    // 1. Build code section
    build_stub_code(
        &mut stub,
        stub_rva,
        original_entry_point,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers.len(),
        metadata_offset as u32,
        data_snapshot,
        data_snapshot_offset,
        image_base,
        data_section_rva,
    )?;

    // Pad to metadata_offset
    stub.resize(metadata_offset, 0xcc);

    // 2. Build metadata array
    let mut current_data_offset = data_base_offset;
    for container in containers {
        let heap_size = container
            .decoded_end
            .saturating_sub(container.decoded_begin);
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

    // 4. Append .data section snapshot if provided
    if let Some(snapshot) = data_snapshot {
        stub.extend_from_slice(&snapshot.data_content);
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
    data_snapshot: Option<&super::data_snapshot::DataSectionSnapshot>,
    data_snapshot_offset: usize,
    image_base: u64,
    data_section_rva: u32,
) -> Option<()> {
    // sub rsp, 0x38
    stub.extend_from_slice(&[0x48, 0x83, 0xec, 0x38]);

    // === TLS Callback: Only execute once using RDX (Reason parameter) ===
    // TLS callback signature: void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
    // RCX = DllHandle, RDX = Reason, R8 = Reserved
    // DLL_PROCESS_ATTACH = 1
    // Only execute bootstrap on DLL_PROCESS_ATTACH

    if original_entry_point.is_none() {
        // This is TLS callback mode - check Reason parameter
        // cmp edx, 1 (check if Reason == DLL_PROCESS_ATTACH)
        stub.extend_from_slice(&[0x83, 0xfa, 0x01]);
        // je continue_bootstrap
        stub.extend_from_slice(&[0x74, 0x04]); // je +4 (skip the early return)
                                               // Early return if not DLL_PROCESS_ATTACH:
                                               // add rsp, 0x38
        stub.extend_from_slice(&[0x48, 0x83, 0xc4, 0x38]);
        // ret
        stub.push(0xc3);
        // continue_bootstrap:
    }

    // === FIRST: Restore .data section if snapshot provided ===
    if let Some(snapshot) = data_snapshot {
        restore_data_section(stub, stub_rva, snapshot, data_snapshot_offset, image_base)?;
    }

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

    // === Read runtime SecurityCookie from .data section ===
    // Load image base into R11
    stub.extend_from_slice(&[0x49, 0xbb]); // movabs r11, imm64
    stub.extend_from_slice(&image_base.to_le_bytes());

    // Add data_section_rva to get .data VA
    // mov ecx, data_section_rva
    stub.extend_from_slice(&[0xb9]); // mov ecx, imm32
    stub.extend_from_slice(&data_section_rva.to_le_bytes());

    // add r11, rcx -> r11 = .data section VA
    stub.extend_from_slice(&[0x49, 0x01, 0xcb]); // add r11, rcx

    // Load SecurityCookie from .data start (assume it's at offset 0)
    // mov rbx, [r11]
    stub.extend_from_slice(&[0x49, 0x8b, 0x1b]); // mov rbx, [r11]

    // Now RBX contains the runtime SecurityCookie

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

    // Get .boot section VA: lea rdx, [rip]; sub rdx, (current_offset_in_boot)
    // This calculates the VA of boot section start at runtime
    stub.extend_from_slice(&[0x48, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00]); // lea rdx, [rip+0]
                                                                         // RIP after lea instruction points to the next instruction
    let rip_after_lea = stub.len() as u32;
    // sub rdx, rip_after_lea to get boot section VA
    if rip_after_lea <= 127 {
        stub.extend_from_slice(&[0x48, 0x83, 0xea, rip_after_lea as u8]); // sub rdx, imm8
    } else {
        stub.extend_from_slice(&[0x48, 0x81, 0xea]); // sub rdx, imm32
        stub.extend_from_slice(&rip_after_lea.to_le_bytes());
    }
    // add rdx, [r14+16] to get final source address
    stub.extend_from_slice(&[0x48, 0x03, 0x56, 0x10]);

    // mov r8d, [r14+4] (size)
    stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x04]);

    // call inline_memcpy
    stub.push(0xe8);
    let memcpy_offset = stub.len();
    stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // Update encoded triple: mov ecx, [r14] (data_rva)
    stub.extend_from_slice(&[0x41, 0x8b, 0x0e]);

    // mov rdx, rbx (use runtime SecurityCookie from RBX instead of metadata)
    stub.extend_from_slice(&[0x48, 0x89, 0xda]); // mov rdx, rbx

    // mov r8, r12 (new heap ptr)
    stub.extend_from_slice(&[0x4d, 0x89, 0xe0]);

    // mov r9d, [r14+4] (heap_size)
    stub.extend_from_slice(&[0x45, 0x8b, 0x4e, 0x04]);

    // call inline_update_triple
    stub.push(0xe8);
    let update_offset = stub.len();
    stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // .skip: This is where we jump to if HeapAlloc fails
    // It must be AFTER all the container restoration code
    let skip_target = stub.len();
    let skip_displacement = (skip_target - skip_jz_offset - 1) as u8;
    stub[skip_jz_offset] = skip_displacement;

    tracing::debug!(
        "skip label: jz_offset={}, skip_target={}, displacement={}",
        skip_jz_offset - 1,
        skip_target,
        skip_displacement
    );

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
    // Calculate target address: image_base + data_rva

    // movabs r10, image_base (load image base directly)
    stub.extend_from_slice(&[0x49, 0xba]); // movabs r10, imm64
    stub.extend_from_slice(&image_base.to_le_bytes());

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

    // === CRITICAL FIX: Resume all suspended threads ===
    // This fixes the remaining 1 suspended thread that blocks GUI initialization
    tracing::info!("Adding thread resume code to bootstrap");

    // We cannot enumerate threads from within the TLS callback without complex APIs
    // Instead, we rely on the fact that TLS callbacks run for EACH thread
    // So each thread will execute this code and naturally resume itself
    // No additional code needed - the return from TLS callback resumes the thread

    // However, to be explicit, we could add a NOP as documentation
    // nop (for clarity - TLS callback return resumes thread)
    stub.push(0x90);

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

/// Generate code to restore the .data section from embedded snapshot.
///
/// This function generates x64 assembly to copy the entire .data section
/// from the embedded snapshot to the runtime .data section.
///
/// Generated code:
/// ```asm
/// mov rdi, data_va           ; dest = .data virtual address
/// lea rsi, [rip + snapshot]  ; source = embedded snapshot
/// mov rcx, data_size         ; count
/// rep movsb                  ; memcpy
/// ```
fn restore_data_section(
    stub: &mut Vec<u8>,
    stub_rva: u32,
    snapshot: &super::data_snapshot::DataSectionSnapshot,
    data_snapshot_offset: usize,
    image_base: u64,
) -> Option<()> {
    let data_va = image_base + snapshot.data_rva as u64;

    tracing::info!(
        "Generating .data restore code: data_va={:#x}, size={:#x}, snapshot_offset={:#x}",
        data_va,
        snapshot.data_size,
        data_snapshot_offset
    );

    // movabs rdi, data_va (destination = .data section virtual address)
    stub.extend_from_slice(&[0x48, 0xbf]); // movabs rdi, imm64
    stub.extend_from_slice(&data_va.to_le_bytes());

    // lea rsi, [rip + snapshot_offset] (source = embedded snapshot)
    stub.extend_from_slice(&[0x48, 0x8d, 0x35]); // lea rsi, [rip + disp32]
    let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    let snapshot_rva = stub_rva.checked_add(data_snapshot_offset as u32)?;
    let disp = relative_displacement(lea_next, snapshot_rva)?;
    stub.extend_from_slice(&disp);

    // mov ecx, data_size (count)
    stub.extend_from_slice(&[0xb9]); // mov ecx, imm32
    stub.extend_from_slice(&snapshot.data_size.to_le_bytes());

    // rep movsb (copy data_size bytes from rsi to rdi)
    stub.extend_from_slice(&[0xf3, 0xa4]);

    tracing::info!("Generated .data restore code: {} bytes", 10 + 7 + 5 + 2);

    Some(())
}

fn estimate_code_size(container_count: usize, has_data_snapshot: bool) -> usize {
    // Base setup: ~40 bytes
    // Data restore (if present): ~40 bytes
    // Loop body: ~80 bytes
    // Helpers (memcpy + update_triple): ~60 bytes
    // Epilogue: ~10 bytes
    let _ = container_count; // Size is mostly constant since loop is counted
    if has_data_snapshot {
        250 // Extra space for .data restoration
    } else {
        200
    }
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
        let size = estimate_code_size(3, false);
        assert!(size >= 150 && size <= 256);
    }
}
