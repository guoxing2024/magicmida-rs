//! Bootstrap for restoring heap-backed SecurityCookie-encoded containers.
//!
//! The stub embedded in `.boot`:
//!
//! 1. Calls GetProcessHeap
//! 2. For each container snapshot: HeapAlloc → memcpy → re-encode triple
//! 3. Continues to the original target (CRT body or PE EP)
//!
//! ## Metadata format (per container, 40 bytes)
//!
//! ```text
//! +0x00: u32  data_rva        — RVA in `.data` where encoded triple lives
//! +0x04: u32  content_size    — Bytes copied (decoded_end - decoded_begin)
//! +0x08: u64  cookie          — fallback cookie (prefer runtime load)
//! +0x10: u32  data_offset     — Offset in .boot to heap snapshot
//! +0x14: u32  capacity_size   — Bytes allocated (decoded_capacity - decoded_begin)
//! +0x18: u64  _pad
//! +0x20: u64  _pad
//! ```
//!
//! ## Post-CRT mode (default for MSVC / 启动器)
//!
//! PE EP stays the MSVC CRT cookie wrapper. After `call __security_init_cookie`,
//! the following `jmp scrt_main` is rewritten to `jmp .boot`. The stub restores
//! containers using the **live** SecurityCookie, then jumps to the original
//! `scrt_main` target. CRT stdio (`_ioinit`) still runs after cookie init and
//! is not poisoned by pre-EP heap-global writes.

use tracing::{info, warn};

use crate::header::PeHeader;

use super::container_snapshot::ContainerSnapshot;
use super::heap_global_snapshot::{HeapGlobalSnapshot, HeapSlab};

const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
/// .boot must be writable: phase-1 records `new_begin` into the embedded
/// fixup map (RX-only sections AV on `mov [map+0x10], r12`).
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

const CONTAINER_METADATA_SIZE: usize = 40;
/// Plain heap-global slot metadata (per entry).
///
/// ```text
/// +0x00: u32  slot_rva
/// +0x04: u32  content_size  — 0 means heap-handle plant (GetProcessHeap)
/// +0x08: u32  data_offset   — offset in .boot to snapshot bytes
/// +0x0c: u32  flags         — bit0 = is_heap_handle, bit1 = is_image_inline
/// +0x10: u64  live_ptr      — old heap base (for multi-range fixup map)
/// ```
const HEAP_GLOBAL_METADATA_SIZE: usize = 24;
const HEAP_GLOBAL_FLAG_HANDLE: u32 = 1;
const HEAP_GLOBAL_FLAG_IMAGE_INLINE: u32 = 2;
/// Runtime fixup-map entry (containers + heap-globals, phase-2 multi remap).
///
/// ```text
/// +0x00: u64  old_begin     — dump-time heap base
/// +0x08: u32  size          — content bytes to scan
/// +0x0c: u32  _pad
/// +0x10: u64  new_begin     — filled after HeapAlloc (0 if alloc failed)
/// ```
const FIXUP_MAP_ENTRY_SIZE: usize = 24;

/// Install a pre-OEP bootstrap (PE EP becomes the stub). Experimental.
///
/// Returns the bootstrap RVA when installed.
pub(crate) fn install_container_bootstrap(
    pe: &mut PeHeader,
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slab: Option<&HeapSlab>,
    virtual_alloc_iat_rva: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    original_entry_point: u32,
    image_base: u64,
    cookie_rva: Option<u32>,
    heap_global_rva: Option<u32>,
    cookie_mirror: Option<(u32, u32)>,
) -> Option<u32> {
    install_container_section(
        pe,
        containers,
        heap_globals,
        heap_slab,
        virtual_alloc_iat_rva,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        Some(original_entry_point),
        image_base,
        cookie_rva,
        heap_global_rva,
        cookie_mirror,
        "Installed pre-OEP container restoration bootstrap",
    )
}

/// Post-CRT restore: keep PE EP at CRT wrapper; patch the post-cookie `jmp`
/// to the restore stub; stub continues into original CRT body.
///
/// Returns `Some(original_entry_point)` so the PE EP is **not** redirected to
/// `.boot` (CRT must run `__security_init_cookie` first).
///
/// **R4-A3:** When `crt_entry_rva` is not an MSVC CRT wrapper (common on GTO
/// post-attach freeze at application OEP), skip the failed patch attempt and
/// install pre-OEP bootstrap directly — same outcome, clearer log path.
pub(crate) fn install_post_crt_container_restore(
    pe: &mut PeHeader,
    dump_buf: &mut [u8],
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slab: Option<&HeapSlab>,
    virtual_alloc_iat_rva: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    crt_entry_rva: u32,
    cookie_rva: Option<u32>,
    heap_global_rva: Option<u32>,
    cookie_mirror: Option<(u32, u32)>,
) -> Option<u32> {
    if !pe.is_64bit || (containers.is_empty() && heap_globals.is_empty()) {
        return None;
    }

    let image_base = pe.nt_headers.optional_header.image_base;

    // Application OEP (or non-CRT PE EP): PostCrt patch cannot apply — use
    // pre-OEP bootstrap without treating it as a failed CRT decode.
    if !looks_like_crt_entry_wrapper(dump_buf, crt_entry_rva) {
        // R-GTO-UI script-heap-resume: GTO .text scan freezes on AHK
        // message-dispatch `0x70b0` (WM_APP gate). Cold start with that
        // continue target always takes the error path and exits 0 without
        // RegisterClass. Prefer AHK WinMain `0x5a10` (sole caller from CRT
        // post-_initterm at `0xd9261`) when the scanned entry is that handler.
        let continue_ep = retarget_gto_resume_entry(dump_buf, crt_entry_rva);
        info!(
            entry = format_args!("{crt_entry_rva:#x}"),
            continue_ep = format_args!("{continue_ep:#x}"),
            containers = containers.len(),
            heap_globals = heap_globals.len(),
            "PostCrt: entry is not MSVC CRT wrapper (frozen app OEP or non-CRT) — \
             pre-OEP container bootstrap"
        );
        return install_container_bootstrap(
            pe,
            containers,
            heap_globals,
            heap_slab,
            virtual_alloc_iat_rva,
            get_process_heap_iat_rva,
            heap_alloc_iat_rva,
            continue_ep,
            image_base,
            cookie_rva,
            heap_global_rva,
            cookie_mirror,
        );
    }

    let continue_rva = match patch_crt_wrapper_jmp_to_stub(dump_buf, crt_entry_rva, 0) {
        // First pass: decode original jmp target (without patching yet).
        Ok(cont) => cont,
        Err(msg) => {
            warn!(
                entry = format_args!("{crt_entry_rva:#x}"),
                reason = msg,
                "CRT wrapper not patchable — falling back to pre-OEP container bootstrap"
            );
            return install_container_bootstrap(
                pe,
                containers,
                heap_globals,
                heap_slab,
                virtual_alloc_iat_rva,
                get_process_heap_iat_rva,
                heap_alloc_iat_rva,
                crt_entry_rva,
                image_base,
                cookie_rva,
                heap_global_rva,
                cookie_mirror,
            );
        }
    };

    let stub_rva = install_container_section(
        pe,
        containers,
        heap_globals,
        heap_slab,
        virtual_alloc_iat_rva,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        Some(continue_rva),
        image_base,
        cookie_rva,
        heap_global_rva,
        cookie_mirror,
        "Installed post-CRT container restoration bootstrap",
    )?;

    // Rewrite CRT jmp → .boot (continue target already captured).
    if let Err(msg) = patch_crt_wrapper_jmp_to_stub(dump_buf, crt_entry_rva, stub_rva) {
        warn!(
            reason = msg,
            "Failed to patch CRT jmp after installing .boot — PE EP may miss restore"
        );
        return Some(stub_rva);
    }

    info!(
        crt_entry = format_args!("{crt_entry_rva:#x}"),
        stub_rva = format_args!("{stub_rva:#x}"),
        continue_rva = format_args!("{continue_rva:#x}"),
        containers = containers.len(),
        heap_globals = heap_globals.len(),
        cookie_rva = cookie_rva
            .map(|r| format!("{r:#x}"))
            .unwrap_or_else(|| "none".into()),
        "Post-CRT: PE EP stays CRT; jmp after cookie → restore → scrt body"
    );

    // PE entry point must remain the CRT wrapper.
    Some(crt_entry_rva)
}

/// MSVC x64 PE entry probe: `sub rsp,28h; call; add rsp,28h; jmp`.
fn looks_like_crt_entry_wrapper(dump_buf: &[u8], ep_rva: u32) -> bool {
    let off = ep_rva as usize;
    let Some(bytes) = dump_buf.get(off..off.saturating_add(14)) else {
        return false;
    };
    bytes[0..4] == [0x48, 0x83, 0xec, 0x28]
        && bytes[4] == 0xe8
        && bytes[9..13] == [0x48, 0x83, 0xc4, 0x28]
        && bytes[13] == 0xe9
}

/// Decode MSVC x64 CRT PE entry and optionally rewrite the trailing `jmp`.
///
/// Layout:
/// ```text
/// sub rsp, 28h          ; 48 83 EC 28
/// call cookie           ; E8 xx xx xx xx
/// add rsp, 28h          ; 48 83 C4 28
/// jmp scrt_main         ; E9 xx xx xx xx   ← patched when stub_rva != 0
/// ```
///
/// When `stub_rva == 0`, only returns the original jmp target RVA.
/// When `stub_rva != 0`, patches the jmp to `stub_rva` and returns the same original target.
fn patch_crt_wrapper_jmp_to_stub(
    dump_buf: &mut [u8],
    crt_entry_rva: u32,
    stub_rva: u32,
) -> Result<u32, &'static str> {
    let off = crt_entry_rva as usize;
    let bytes = dump_buf
        .get_mut(off..off.saturating_add(18))
        .ok_or("CRT entry outside dump buffer")?;
    if bytes[0..4] != [0x48, 0x83, 0xec, 0x28] {
        return Err("not sub rsp,28h");
    }
    if bytes[4] != 0xe8 {
        return Err("missing call after sub rsp");
    }
    if bytes[9..13] != [0x48, 0x83, 0xc4, 0x28] {
        return Err("missing add rsp,28h");
    }
    if bytes[13] != 0xe9 {
        return Err("missing jmp after add rsp");
    }
    let rel = i32::from_le_bytes(bytes[14..18].try_into().unwrap());
    let jmp_instr_rva = crt_entry_rva + 13;
    let next = jmp_instr_rva + 5;
    let original_target = (next as i64 + rel as i64) as u32;

    if stub_rva != 0 {
        let new_rel = (stub_rva as i64) - (next as i64);
        let new_rel = i32::try_from(new_rel).map_err(|_| "stub out of rel32 range")?;
        bytes[14..18].copy_from_slice(&new_rel.to_le_bytes());
    }

    Ok(original_target)
}

fn install_container_section(
    pe: &mut PeHeader,
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slab: Option<&HeapSlab>,
    virtual_alloc_iat_rva: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    continue_entry_point: Option<u32>,
    image_base: u64,
    cookie_rva: Option<u32>,
    heap_global_rva: Option<u32>,
    cookie_mirror: Option<(u32, u32)>,
    log_msg: &str,
) -> Option<u32> {
    if !pe.is_64bit {
        warn!("Container bootstrap only supports x64");
        return None;
    }
    if containers.is_empty() && heap_globals.is_empty() {
        return None;
    }

    // r27 Round 2: collect writable non-standard sections (Themida .,\W etc.)
    // for phase-2.5b interior heap-pointer rebase at runtime.
    const STD_SECTIONS: &[&str] = &[
        ".text", ".rdata", ".data", ".pdata", ".bss", ".tls", ".rsrc",
        ".idata", ".reloc", ".import", ".edata", ".boot",
    ];
    let scan_sections: Vec<(u32, u32)> = pe
        .sections
        .iter()
        .filter(|s| {
            s.characteristics & IMAGE_SCN_MEM_WRITE != 0
                && s.virtual_size > 0
                && !STD_SECTIONS.contains(&s.name.as_str())
        })
        .map(|s| (s.virtual_address, s.virtual_size))
        .collect();

    // Estimate payload size so create_section_index reserves enough raw space
    // before we attach extra_data (avoids RawSize=0 races with pack/sanitize).
    let approx_payload = 0x400u32
        .saturating_add(
            (containers.len() as u32).saturating_mul(CONTAINER_METADATA_SIZE as u32 + 64),
        )
        .saturating_add(
            (heap_globals.len() as u32).saturating_mul(HEAP_GLOBAL_METADATA_SIZE as u32 + 64),
        )
        .saturating_add(
            containers
                .iter()
                .map(|c| c.heap_content.len() as u32)
                .fold(0u32, u32::saturating_add),
        )
        .saturating_add(
            heap_globals
                .iter()
                .map(|g| g.content.len() as u32)
                .fold(0u32, u32::saturating_add),
        )
        .saturating_add(heap_slab.map(|s| s.content.len() as u32).unwrap_or(0));
    let reserve = crate::utils::align_up(approx_payload.max(0x1000), 0x1000);

    let section_idx = pe.create_section_index(".boot", reserve);
    let stub_rva = pe.sections[section_idx].virtual_address;

    let stub_result = build_container_stub_internal(
        stub_rva,
        continue_entry_point,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
        heap_globals,
        heap_slab,
        virtual_alloc_iat_rva,
        &scan_sections,
        None,
        image_base,
        0,
        heap_global_rva,
        cookie_rva,
        cookie_mirror,
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

    // Ensure file pointer is non-zero so write_section_data / pack keep payload.
    let mut max_end = 0u32;
    for (i, s) in pe.sections.iter().enumerate() {
        if i == section_idx {
            continue;
        }
        let end = s
            .header
            .pointer_to_raw_data
            .saturating_add(s.header.size_of_raw_data);
        if end > max_end {
            max_end = end;
        }
    }
    let fallback_ptr = crate::utils::align_up(max_end, 0x200);

    let section = &mut pe.sections[section_idx];
    // RWX: code + fixup-map writes (new_begin) after each HeapAlloc.
    section.characteristics =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    section.header.characteristics = section.characteristics;
    section.header.virtual_size = aligned_size;
    section.virtual_size = aligned_size;
    section.header.size_of_raw_data = aligned_size;
    section.raw_size = aligned_size;
    if section.header.pointer_to_raw_data == 0 {
        section.header.pointer_to_raw_data = fallback_ptr;
        section.raw_offset = fallback_ptr;
    }
    section.extra_data = Some(stub);

    info!(
        stub_rva = format_args!("{stub_rva:#x}"),
        containers = containers.len(),
        heap_globals = heap_globals.len(),
        stub_size = stub_len,
        continue_ep = continue_entry_point
            .map(|e| format!("{e:#x}"))
            .unwrap_or_else(|| "ret".into()),
        image_base = format_args!("{image_base:#x}"),
        cookie_mirror = cookie_mirror
            .map(|(s, d)| format!("{s:#x}->{d:#x}"))
            .unwrap_or_else(|| "off".into()),
        "{log_msg}"
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
    heap_global_rva: Option<u32>,
    cookie_rva: Option<u32>,
) -> Option<Vec<u8>> {
    build_container_stub_internal(
        stub_rva,
        None,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers,
        &[],
        None, // heap_slab (TLS path not used for GTO)
        None, // virtual_alloc (TLS path)
        &[], // scan_sections (TLS path)
        data_snapshot,
        image_base,
        data_section_rva,
        heap_global_rva,
        cookie_rva,
        None, // TLS path: no OEP cookie mirror
    )
}

/// Internal builder supporting both entry-point and TLS callback modes.
fn build_container_stub_internal(
    stub_rva: u32,
    original_entry_point: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    containers: &[ContainerSnapshot],
    heap_globals: &[HeapGlobalSnapshot],
    heap_slab: Option<&HeapSlab>,
    virtual_alloc_iat_rva: Option<u32>,
    scan_sections: &[(u32, u32)],
    data_snapshot: Option<&super::data_snapshot::DataSectionSnapshot>,
    image_base: u64,
    data_section_rva: u32,
    heap_global_rva: Option<u32>,
    cookie_rva: Option<u32>,
    cookie_mirror: Option<(u32, u32)>,
) -> Option<Vec<u8>> {
    // Layout:
    //   [code]
    //   [container metadata × N]  (40 bytes each)
    //   [heap-global metadata × M] (24 bytes each)
    //   [fixup map × (N+M)]       (24 bytes each: old/size/new)
    //   [container heap payloads]
    //   [heap-global payloads]
    //   [optional .data snapshot]
    let slab_present = heap_slab.is_some();
    let range_count = containers
        .len()
        .checked_add(heap_globals.len())?
        .checked_add(if slab_present { 1 } else { 0 })?;
    let slab_fixup_index = if slab_present { range_count.checked_sub(1)? } else { 0 };
    let slab_old_base = heap_slab.map(|s| s.old_base).unwrap_or(0);
    let slab_len = heap_slab.map(|s| s.content.len()).unwrap_or(0);
    let mut measured_code = Vec::new();
    build_stub_code(
        &mut measured_code,
        stub_rva,
        original_entry_point,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers.len(),
        heap_globals.len(),
        0, // container metadata offset (placeholder)
        0, // heap-global metadata offset (placeholder)
        0, // fixup map offset (placeholder)
        range_count,
        slab_fixup_index,
        virtual_alloc_iat_rva,
        slab_old_base,
        0, // slab_data_offset placeholder (measurement pass)
        0, // scan_sections_offset placeholder
        0, // scan_sections_count
        data_snapshot,
        0,
        image_base,
        data_section_rva,
        heap_global_rva,
        cookie_rva,
        cookie_mirror,
    )?;;
    let metadata_offset = measured_code.len().checked_add(15)? & !15;
    let container_meta_size = containers.len().checked_mul(CONTAINER_METADATA_SIZE)?;
    let heap_global_meta_size = heap_globals.len().checked_mul(HEAP_GLOBAL_METADATA_SIZE)?;
    let heap_global_meta_offset = metadata_offset.checked_add(container_meta_size)?;
    let fixup_map_offset = heap_global_meta_offset.checked_add(heap_global_meta_size)?;
    let fixup_map_size = range_count.checked_mul(FIXUP_MAP_ENTRY_SIZE)?;
    let data_base_offset = fixup_map_offset.checked_add(fixup_map_size)?;
    let after_containers = data_base_offset.checked_add(
        containers.iter().try_fold(0usize, |total, container| {
            total.checked_add(container.heap_content.len())
        })?,
    )?;
    let data_snapshot_offset = after_containers.checked_add(
        heap_globals
            .iter()
            .try_fold(0usize, |total, g| total.checked_add(g.content.len()))?,
    )?;
    let slab_data_offset = data_snapshot_offset.checked_add(
        data_snapshot.map(|s| s.data_content.len()).unwrap_or(0),
    )?;
    let slab_data_end = slab_data_offset.checked_add(slab_len)?;
    // scan_sections table (u32 count + (rva,size) pairs) placed after slab content.
    let scan_sections_table_size = 4usize + scan_sections.len().checked_mul(8)?;
    let scan_sections_offset = slab_data_end; // relative to stub start
    let stub_total = scan_sections_offset.checked_add(scan_sections_table_size)?;

    let mut stub = Vec::with_capacity(stub_total);
    build_stub_code(
        &mut stub,
        stub_rva,
        original_entry_point,
        get_process_heap_iat_rva,
        heap_alloc_iat_rva,
        containers.len(),
        heap_globals.len(),
        metadata_offset as u32,
        heap_global_meta_offset as u32,
        fixup_map_offset as u32,
        range_count,
        slab_fixup_index,
        virtual_alloc_iat_rva,
        slab_old_base,
        slab_data_offset,
        scan_sections_offset as u32,
        scan_sections.len() as u32,
        data_snapshot,
        data_snapshot_offset,
        image_base,
        data_section_rva,
        heap_global_rva,
        cookie_rva,
        cookie_mirror,
    )?;;

    if stub.len() > metadata_offset {
        warn!(
            measured_size = measured_code.len(),
            final_size = stub.len(),
            metadata_offset,
            "Bootstrap layout changed between measurement and final generation"
        );
        return None;
    }

    stub.resize(metadata_offset, 0xcc);

    // Container metadata (+0x18 stores live begin for diagnostics; fixup map is authoritative)
    let mut current_data_offset = data_base_offset;
    for container in containers {
        let content_size = container
            .decoded_end
            .saturating_sub(container.decoded_begin);
        let capacity_size = container
            .decoded_capacity
            .saturating_sub(container.decoded_begin);
        stub.extend_from_slice(&container.rva.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(content_size).ok()?.to_le_bytes());
        stub.extend_from_slice(&container.cookie.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(current_data_offset).ok()?.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(capacity_size).ok()?.to_le_bytes());
        stub.extend_from_slice(&container.decoded_begin.to_le_bytes()); // +0x18 live old
        stub.extend_from_slice(&[0u8; 8]); // +0x20 reserved
        current_data_offset = current_data_offset.checked_add(container.heap_content.len())?;
    }

    // Heap-global metadata (must start at heap_global_meta_offset)
    if stub.len() < heap_global_meta_offset {
        stub.resize(heap_global_meta_offset, 0xcc);
    }
    for g in heap_globals {
        let mut flags = 0u32;
        if g.is_heap_handle {
            flags |= HEAP_GLOBAL_FLAG_HANDLE;
        }
        if g.is_image_inline {
            flags |= HEAP_GLOBAL_FLAG_IMAGE_INLINE;
        }
        // Heap handles: content_size=0, no payload; plant GetProcessHeap at runtime.
        let content_len = if g.is_heap_handle { 0 } else { g.content.len() };
        stub.extend_from_slice(&g.rva.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(content_len).ok()?.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(current_data_offset).ok()?.to_le_bytes());
        stub.extend_from_slice(&flags.to_le_bytes());
        stub.extend_from_slice(&g.live_ptr.to_le_bytes());
        current_data_offset = current_data_offset.checked_add(content_len)?;
    }

    // Fixup map: old/size filled now; new_begin written by stub after each HeapAlloc
    if stub.len() < fixup_map_offset {
        stub.resize(fixup_map_offset, 0xcc);
    }
    for container in containers {
        let content_size = container
            .decoded_end
            .saturating_sub(container.decoded_begin);
        stub.extend_from_slice(&container.decoded_begin.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(content_size).ok()?.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u64.to_le_bytes()); // new_begin
    }
    for g in heap_globals {
        // Heap handles must not participate in multi_fixup ranges.
        let content_len = if g.is_heap_handle { 0 } else { g.content.len() };
        stub.extend_from_slice(&g.live_ptr.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(content_len).ok()?.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u64.to_le_bytes()); // new_begin
    }
    // Slab fixup map entry (last): old=slab.old_base, size=slab_len, new=0.
    if slab_present {
        stub.extend_from_slice(&slab_old_base.to_le_bytes());
        stub.extend_from_slice(&u32::try_from(slab_len).ok()?.to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&0u64.to_le_bytes()); // new_begin filled at runtime
    }

    for container in containers {
        stub.extend_from_slice(&container.heap_content);
    }
    for g in heap_globals {
        if !g.is_heap_handle {
            stub.extend_from_slice(&g.content);
        }
    }

    if let Some(snapshot) = data_snapshot {
        stub.extend_from_slice(&snapshot.data_content);
    }

    // Slab content payload (placed last in .boot data).
    if slab_present {
        if let Some(slab) = heap_slab {
            stub.extend_from_slice(&slab.content);
        }
    }

    // Scan-sections table for phase-2.5b (u32 count + (rva,size) pairs).
    let scan_sections_offset = stub.len();
    stub.extend_from_slice(&u32::try_from(scan_sections.len()).ok()?.to_le_bytes());
    for &(rva, size) in scan_sections {
        stub.extend_from_slice(&rva.to_le_bytes());
        stub.extend_from_slice(&size.to_le_bytes());
    }

    Some(stub)
}

/// Build the x64 stub code that performs container restoration.
///
/// Phase 1: HeapAlloc + memcpy all containers and heap-globals; record
/// `new_begin` in the fixup map; update cookie triples / image slots.
/// Phase 2: multi-range fixup — remap any qword that lands in *any* captured
/// old range (cross-object AHK graphs), not only the owning block.
fn build_stub_code(
    stub: &mut Vec<u8>,
    stub_rva: u32,
    original_entry_point: Option<u32>,
    get_process_heap_iat_rva: u32,
    heap_alloc_iat_rva: u32,
    container_count: usize,
    heap_global_count: usize,
    metadata_offset: u32,
    heap_global_meta_offset: u32,
    fixup_map_offset: u32,
    range_count: usize,
    slab_fixup_index: usize,
    virtual_alloc_iat_rva: Option<u32>,
    slab_old_base: u64,
    slab_data_offset: usize,
    scan_sections_offset: u32,
    scan_sections_count: u32,
    data_snapshot: Option<&super::data_snapshot::DataSectionSnapshot>,
    data_snapshot_offset: usize,
    image_base: u64,
    _data_section_rva: u32,
    heap_global_rva: Option<u32>,
    cookie_rva: Option<u32>,
    cookie_mirror: Option<(u32, u32)>,
) -> Option<()> {
    // Preserve non-volatile registers (six pushes keep x64 alignment).
    // rbx = fixup-map cursor during phase 1
    stub.extend_from_slice(&[
        0x53, // push rbx
        0x56, // push rsi
        0x41, 0x54, // push r12
        0x41, 0x55, // push r13
        0x41, 0x56, // push r14
        0x41, 0x57, // push r15
    ]);
    stub.extend_from_slice(&[0x48, 0x83, 0xec, 0x38]); // sub rsp, 0x38

    if original_entry_point.is_none() {
        // TLS mode: only run on DLL_PROCESS_ATTACH
        stub.extend_from_slice(&[0x83, 0xfa, 0x01]); // cmp edx, 1
        stub.extend_from_slice(&[0x74, 0x0f]); // je +0x0f
        stub.extend_from_slice(&[0x48, 0x83, 0xc4, 0x38]); // add rsp, 0x38
        emit_nonvolatile_pops(stub);
        stub.push(0xc3); // ret
    }

    if let Some(snapshot) = data_snapshot {
        restore_data_section(stub, stub_rva, snapshot, data_snapshot_offset, image_base)?;
    }

    // GetProcessHeap -> r15
    stub.extend_from_slice(&[0xff, 0x15]);
    let call_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(call_next, get_process_heap_iat_rva)?);
    stub.extend_from_slice(&[0x49, 0x89, 0xc7]); // mov r15, rax

    if let Some(heap_global_rva) = heap_global_rva {
        stub.extend_from_slice(&[0x48, 0x89, 0x05]); // mov [rip+disp], rax
        let store_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(store_next, heap_global_rva)?);
    }

    // Call-site placeholders patched after helpers are emitted.
    let mut memcpy_sites: Vec<usize> = Vec::new();
    let mut update_sites: Vec<usize> = Vec::new();
    let mut multi_fixup_sites: Vec<usize> = Vec::new();

    // rbx = fixup map cursor (phase 1 writes new_begin at +0x10)
    if range_count > 0 {
        let map_rva = stub_rva.checked_add(fixup_map_offset)?;
        stub.extend_from_slice(&[0x48, 0x8d, 0x1d]); // lea rbx, [rip+disp]
        let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(lea_next, map_rva)?);
    }

    // ========== Phase 1a: Cookie-encoded containers ==========
    if container_count > 0 {
        let metadata_rva = stub_rva.checked_add(metadata_offset)?;
        stub.extend_from_slice(&[0x4c, 0x8d, 0x35]); // lea r14, [rip+disp]
        let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(lea_next, metadata_rva)?);

        stub.extend_from_slice(&[0x41, 0xbd]); // mov r13d, imm32
        stub.extend_from_slice(&u32::try_from(container_count).ok()?.to_le_bytes());

        let loop_start = stub.len();

        // HeapAlloc(hHeap, 0, capacity)
        stub.extend_from_slice(&[0x4c, 0x89, 0xf9]); // mov rcx, r15
        stub.extend_from_slice(&[0x31, 0xd2]); // xor edx, edx
        stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x14]); // mov r8d, [r14+0x14]
        stub.extend_from_slice(&[0xff, 0x15]);
        let alloc_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(alloc_next, heap_alloc_iat_rva)?);
        stub.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax
        stub.push(0x74); // jz .skip
        let skip_jz = stub.len();
        stub.push(0x00);

        stub.extend_from_slice(&[0x49, 0x89, 0xc4]); // mov r12, rax

        // memcpy dest=r12, src=boot+data_offset, size=content
        stub.extend_from_slice(&[0x4c, 0x89, 0xe1]); // mov rcx, r12
        stub.extend_from_slice(&[0x48, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00]);
        let rip_after_lea = stub.len() as u32;
        if rip_after_lea <= 127 {
            stub.extend_from_slice(&[0x48, 0x83, 0xea, rip_after_lea as u8]);
        } else {
            stub.extend_from_slice(&[0x48, 0x81, 0xea]);
            stub.extend_from_slice(&rip_after_lea.to_le_bytes());
        }
        stub.extend_from_slice(&[0x41, 0x8b, 0x46, 0x10]); // mov eax, [r14+0x10]
        stub.extend_from_slice(&[0x48, 0x01, 0xc2]); // add rdx, rax
        stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x04]); // mov r8d, [r14+4]
        stub.push(0xe8);
        memcpy_sites.push(stub.len());
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // update_triple(data_rva, cookie, new_ptr, content, capacity)
        stub.extend_from_slice(&[0x41, 0x8b, 0x0e]); // mov ecx, [r14]
        if let Some(cookie_rva) = cookie_rva {
            stub.extend_from_slice(&[0x48, 0x8b, 0x15]); // mov rdx, [rip+cookie]
            let load_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
            stub.extend_from_slice(&relative_displacement(load_next, cookie_rva)?);
        } else {
            stub.extend_from_slice(&[0x49, 0x8b, 0x56, 0x08]); // mov rdx, [r14+8]
        }
        stub.extend_from_slice(&[0x4d, 0x89, 0xe0]); // mov r8, r12
        stub.extend_from_slice(&[0x45, 0x8b, 0x4e, 0x04]); // mov r9d, [r14+4]
        stub.extend_from_slice(&[0x45, 0x8b, 0x5e, 0x14]); // mov r11d, [r14+0x14]
        stub.push(0xe8);
        update_sites.push(stub.len());
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // map[i].new_begin = r12
        stub.extend_from_slice(&[0x4c, 0x89, 0x63, 0x10]); // mov [rbx+0x10], r12

        let skip_target = stub.len();
        let skip_disp = u8::try_from(skip_target.checked_sub(skip_jz + 1)?).ok()?;
        stub[skip_jz] = skip_disp;

        // Always advance map cursor (failed alloc leaves new_begin=0)
        stub.extend_from_slice(&[0x48, 0x83, 0xc3, 0x18]); // add rbx, 24
        stub.extend_from_slice(&[0x49, 0x83, 0xc6, 0x28]); // add r14, 40
        stub.extend_from_slice(&[0x41, 0xff, 0xcd]); // dec r13d
        let loop_end = stub.len();
        let loop_next = loop_end.checked_add(2)?;
        let loop_disp = i8::try_from(loop_start as isize - loop_next as isize).ok()?;
        stub.extend_from_slice(&[0x75, loop_disp as u8]); // jnz .loop
    }

    // ========== Phase 1b: Plain heap-global slots ==========
    if heap_global_count > 0 {
        let hg_meta_rva = stub_rva.checked_add(heap_global_meta_offset)?;
        stub.extend_from_slice(&[0x4c, 0x8d, 0x35]); // lea r14, [rip+disp]
        let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(lea_next, hg_meta_rva)?);

        stub.extend_from_slice(&[0x41, 0xbd]); // mov r13d, imm32
        stub.extend_from_slice(&u32::try_from(heap_global_count).ok()?.to_le_bytes());

        let loop_start = stub.len();

        // content_size==0 → heap-handle plant (GetProcessHeap). Keep that path
        // after the alloc body so short jumps never span the full body.
        stub.extend_from_slice(&[0x41, 0x8b, 0x46, 0x04]); // mov eax, [r14+4] size
        stub.extend_from_slice(&[0x85, 0xc0]); // test eax, eax
        stub.push(0x0f);
        stub.push(0x84); // jz rel32 .handle_path
        let jz_handle_off = stub.len();
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // flags bit1 → image-inline body restore (no HeapAlloc; dest = image+rva)
        stub.extend_from_slice(&[0x41, 0xf6, 0x46, 0x0c, 0x02]); // test byte [r14+0xc], 2
        stub.push(0x0f);
        stub.push(0x85); // jnz rel32 .inline_path
        let jnz_inline_off = stub.len();
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // ---- data object: HeapAlloc + memcpy + plant ----
        stub.extend_from_slice(&[0x4c, 0x89, 0xf9]); // mov rcx, r15
        stub.extend_from_slice(&[0x31, 0xd2]); // xor edx, edx
        stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x04]); // mov r8d, [r14+4] size
        stub.extend_from_slice(&[0xff, 0x15]);
        let alloc_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(alloc_next, heap_alloc_iat_rva)?);
        stub.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax
        stub.push(0x0f);
        stub.push(0x84); // jz rel32 .hg_advance (alloc failed)
        let jz_alloc_fail_off = stub.len();
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        stub.extend_from_slice(&[0x49, 0x89, 0xc4]); // mov r12, rax  ; new base

        // memcpy(new, boot+data_off, size)
        stub.extend_from_slice(&[0x4c, 0x89, 0xe1]); // mov rcx, r12
        stub.extend_from_slice(&[0x48, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00]);
        let rip_after_lea = stub.len() as u32;
        if rip_after_lea <= 127 {
            stub.extend_from_slice(&[0x48, 0x83, 0xea, rip_after_lea as u8]);
        } else {
            stub.extend_from_slice(&[0x48, 0x81, 0xea]);
            stub.extend_from_slice(&rip_after_lea.to_le_bytes());
        }
        stub.extend_from_slice(&[0x41, 0x8b, 0x46, 0x08]); // mov eax, [r14+8] data_offset
        stub.extend_from_slice(&[0x48, 0x01, 0xc2]); // add rdx, rax
        stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x04]); // mov r8d, [r14+4]
        stub.push(0xe8);
        memcpy_sites.push(stub.len());
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // slot = image_base + slot_rva; *slot = new_base
        // Graph children use rva==0 (no image plant) — never write image base.
        stub.extend_from_slice(&[0x41, 0x8b, 0x06]); // mov eax, [r14] ; rva
        stub.extend_from_slice(&[0x85, 0xc0]); // test eax, eax
        stub.push(0x74); // jz .skip_plant
        let skip_plant_jz = stub.len();
        stub.push(0x00);
        stub.extend_from_slice(&[0x49, 0xba]); // movabs r10, image_base
        stub.extend_from_slice(&image_base.to_le_bytes());
        stub.extend_from_slice(&[0x49, 0x01, 0xc2]); // add r10, rax
        stub.extend_from_slice(&[0x4d, 0x89, 0x22]); // mov [r10], r12
        let after_plant = stub.len();
        stub[skip_plant_jz] = u8::try_from(after_plant.checked_sub(skip_plant_jz + 1)?).ok()?;

        // map[i].new_begin = r12 (multi-range fixup in phase 2)
        stub.extend_from_slice(&[0x4c, 0x89, 0x63, 0x10]); // mov [rbx+0x10], r12
        stub.push(0xeb); // jmp .hg_advance
        let jmp_after_data_off = stub.len();
        stub.push(0x00);

        // ---- image-inline path: memcpy into image+rva; map new_begin = dest ----
        // R-GTO-UI: g_script body is addressed by lea, not via a pointer slot.
        let inline_path = stub.len();
        let jnz_inline_rel =
            i32::try_from(inline_path as isize - (jnz_inline_off as isize + 4)).ok()?;
        stub[jnz_inline_off..jnz_inline_off + 4].copy_from_slice(&jnz_inline_rel.to_le_bytes());

        stub.extend_from_slice(&[0x41, 0x8b, 0x06]); // mov eax, [r14] ; rva
        stub.extend_from_slice(&[0x85, 0xc0]); // test eax, eax
        stub.push(0x0f);
        stub.push(0x84); // jz rel32 .hg_advance
        let jz_inline_norva_off = stub.len();
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        stub.extend_from_slice(&[0x49, 0xba]); // movabs r10, image_base
        stub.extend_from_slice(&image_base.to_le_bytes());
        stub.extend_from_slice(&[0x49, 0x01, 0xc2]); // add r10, rax  ; dest
        stub.extend_from_slice(&[0x4d, 0x89, 0xd4]); // mov r12, r10  ; new base = image body

        // memcpy(dest, boot+data_off, size)
        stub.extend_from_slice(&[0x4c, 0x89, 0xe1]); // mov rcx, r12
        stub.extend_from_slice(&[0x48, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00]);
        let rip_after_lea_i = stub.len() as u32;
        if rip_after_lea_i <= 127 {
            stub.extend_from_slice(&[0x48, 0x83, 0xea, rip_after_lea_i as u8]);
        } else {
            stub.extend_from_slice(&[0x48, 0x81, 0xea]);
            stub.extend_from_slice(&rip_after_lea_i.to_le_bytes());
        }
        stub.extend_from_slice(&[0x41, 0x8b, 0x46, 0x08]); // mov eax, [r14+8] data_offset
        stub.extend_from_slice(&[0x48, 0x01, 0xc2]); // add rdx, rax
        stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x04]); // mov r8d, [r14+4]
        stub.push(0xe8);
        memcpy_sites.push(stub.len());
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        // map[i].new_begin = image body VA
        stub.extend_from_slice(&[0x4c, 0x89, 0x63, 0x10]); // mov [rbx+0x10], r12
        stub.push(0xeb); // jmp .hg_advance
        let jmp_after_inline_off = stub.len();
        stub.push(0x00);

        // ---- heap-handle path: plant GetProcessHeap, no map range ----
        let handle_path = stub.len();
        let jz_handle_rel =
            i32::try_from(handle_path as isize - (jz_handle_off as isize + 4)).ok()?;
        stub[jz_handle_off..jz_handle_off + 4].copy_from_slice(&jz_handle_rel.to_le_bytes());

        stub.extend_from_slice(&[0x41, 0x8b, 0x06]); // mov eax, [r14] ; rva
        stub.extend_from_slice(&[0x85, 0xc0]); // test eax, eax
        stub.push(0x74); // jz .hg_advance
        let jz_handle_nop = stub.len();
        stub.push(0x00);
        stub.extend_from_slice(&[0x49, 0xba]); // movabs r10, image_base
        stub.extend_from_slice(&image_base.to_le_bytes());
        stub.extend_from_slice(&[0x49, 0x01, 0xc2]); // add r10, rax
        stub.extend_from_slice(&[0x4d, 0x89, 0x3a]); // mov [r10], r15  ; GetProcessHeap
        let after_handle_plant = stub.len();
        stub[jz_handle_nop] =
            u8::try_from(after_handle_plant.checked_sub(jz_handle_nop + 1)?).ok()?;

        // .hg_advance
        let hg_advance = stub.len();
        let jz_alloc_fail_rel =
            i32::try_from(hg_advance as isize - (jz_alloc_fail_off as isize + 4)).ok()?;
        stub[jz_alloc_fail_off..jz_alloc_fail_off + 4]
            .copy_from_slice(&jz_alloc_fail_rel.to_le_bytes());
        let jz_inline_norva_rel =
            i32::try_from(hg_advance as isize - (jz_inline_norva_off as isize + 4)).ok()?;
        stub[jz_inline_norva_off..jz_inline_norva_off + 4]
            .copy_from_slice(&jz_inline_norva_rel.to_le_bytes());
        stub[jmp_after_data_off] =
            u8::try_from(hg_advance.checked_sub(jmp_after_data_off + 1)?).ok()?;
        stub[jmp_after_inline_off] =
            u8::try_from(hg_advance.checked_sub(jmp_after_inline_off + 1)?).ok()?;

        stub.extend_from_slice(&[0x48, 0x83, 0xc3, 0x18]); // add rbx, 24
        stub.extend_from_slice(&[0x49, 0x83, 0xc6, 0x18]); // add r14, 24
        stub.extend_from_slice(&[0x41, 0xff, 0xcd]); // dec r13d
        let loop_end = stub.len();
        stub.extend_from_slice(&[0x0f, 0x85]); // jnz rel32 .loop
        let loop_next = loop_end.checked_add(6)?;
        let loop_disp = i32::try_from(loop_start as isize - loop_next as isize).ok()?;
        stub.extend_from_slice(&loop_disp.to_le_bytes());
    }

    // ========== Phase 1c: Heap slab original-address remap (VirtualAlloc) ==========
    // Reserve the slab at its dump-time address (old_base) so all intra-heap
    // pointers are correct WITHOUT rebase (zero false-positives). If the
    // address is unavailable, fall back to HeapAlloc (then phase-2.5 rebase
    // handles interior pointers, but that path has false-positive risk).
    // rbx points to the slab fixup-map entry (last entry) after phase 1b.
    if slab_old_base != 0 {
        if let Some(va_iat) = virtual_alloc_iat_rva {
            // VirtualAlloc(old_base, size, MEM_COMMIT|MEM_RESERVE=0x3000, PAGE_READWRITE=0x04)
            // rcx = old_base (from [rbx]), rdx = size (from [rbx+8]), r8 = 0x3000, r9 = 0x04
            stub.extend_from_slice(&[0x48, 0x8b, 0x0b]); // mov rcx, [rbx] (old_base)
            stub.extend_from_slice(&[0x48, 0x8b, 0x53, 0x08]); // mov rdx, [rbx+8] (size)
            stub.extend_from_slice(&[0x41, 0xb8, 0x00, 0x30, 0x00, 0x00]); // mov r8d, 0x3000
            stub.extend_from_slice(&[0x41, 0xb9, 0x04, 0x00, 0x00, 0x00]); // mov r9d, 0x04
            stub.extend_from_slice(&[0xff, 0x15]); // call [rip+virtual_alloc_iat]
            let call_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
            stub.extend_from_slice(&relative_displacement(call_next, va_iat)?);
            // rax = new slab base (== old_base if reserve succeeded, else NULL)
            stub.extend_from_slice(&[0x48, 0x85, 0xc0]); // test rax, rax
            stub.push(0x74); // jz .fallback_heap_alloc
            let jz_fallback = stub.len();
            stub.push(0x00);
            // Success: store new_begin, memcpy slab content
            stub.extend_from_slice(&[0x48, 0x89, 0x43, 0x10]); // mov [rbx+0x10], rax
            // memcpy(rax, stub+slab_data_offset, size): rcx=rax, rdx=src, r8=size
            stub.extend_from_slice(&[0x48, 0x89, 0xc1]); // mov rcx, rax
            stub.extend_from_slice(&[0x48, 0x8d, 0x15]); // lea rdx, [rip+disp]
            let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
            let slab_src_rva = stub_rva.checked_add(slab_data_offset as u32)?;
            stub.extend_from_slice(&relative_displacement(lea_next, slab_src_rva)?);
            stub.extend_from_slice(&[0x44, 0x8b, 0x43, 0x08]); // mov r8d, [rbx+8] size
            stub.push(0xe8);
            memcpy_sites.push(stub.len());
            stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            // jmp .slab_done
            stub.push(0xeb);
            let jmp_done = stub.len();
            stub.push(0x00);
            // .fallback_heap_alloc: HeapAlloc(heap, 0, size)
            let fallback = stub.len();
            stub[jz_fallback] = u8::try_from(fallback.checked_sub(jz_fallback + 1)?).ok()?;
            stub.extend_from_slice(&[0x4c, 0x89, 0xf9]); // mov rcx, r15 (heap)
            stub.extend_from_slice(&[0x33, 0xd2]); // xor edx, edx
            stub.extend_from_slice(&[0x44, 0x8b, 0x43, 0x08]); // mov r8d, [rbx+8] size
            stub.extend_from_slice(&[0xff, 0x15]); // call [rip+heap_alloc_iat]
            let call2_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
            stub.extend_from_slice(&relative_displacement(call2_next, heap_alloc_iat_rva)?);
            stub.extend_from_slice(&[0x48, 0x89, 0x43, 0x10]); // mov [rbx+0x10], rax
            // memcpy(rax, stub+slab_data_offset, size)
            stub.extend_from_slice(&[0x48, 0x89, 0xc1]); // mov rcx, rax
            stub.extend_from_slice(&[0x48, 0x8d, 0x15]); // lea rdx, [rip+disp]
            let lea2_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
            stub.extend_from_slice(&relative_displacement(lea2_next, slab_src_rva)?);
            stub.extend_from_slice(&[0x44, 0x8b, 0x43, 0x08]); // mov r8d, [rbx+8] size
            stub.push(0xe8);
            memcpy_sites.push(stub.len());
            stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
            let slab_done = stub.len();
            stub[jmp_done] = u8::try_from(slab_done.checked_sub(jmp_done + 1)?).ok()?;
        } else {
            // No VirtualAlloc import: fall back to HeapAlloc (rebase path).
            stub.extend_from_slice(&[0x4c, 0x89, 0xf9]); // mov rcx, r15
            stub.extend_from_slice(&[0x33, 0xd2]); // xor edx, edx
            stub.extend_from_slice(&[0x44, 0x8b, 0x43, 0x08]); // mov r8d, [rbx+8] size
            stub.extend_from_slice(&[0xff, 0x15]); // call [rip+heap_alloc_iat]
            let call_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
            stub.extend_from_slice(&relative_displacement(call_next, heap_alloc_iat_rva)?);
            stub.extend_from_slice(&[0x48, 0x89, 0x43, 0x10]); // mov [rbx+0x10], rax
            stub.extend_from_slice(&[0x48, 0x89, 0xc1]); // mov rcx, rax
            stub.extend_from_slice(&[0x48, 0x8d, 0x15]); // lea rdx, [rip+disp]
            let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
            let slab_src_rva = stub_rva.checked_add(slab_data_offset as u32)?;
            stub.extend_from_slice(&relative_displacement(lea_next, slab_src_rva)?);
            stub.extend_from_slice(&[0x44, 0x8b, 0x43, 0x08]); // mov r8d, [rbx+8] size
            stub.push(0xe8);
            memcpy_sites.push(stub.len());
            stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        }
        // Advance rbx past the slab entry
        stub.extend_from_slice(&[0x48, 0x83, 0xc3, 0x18]); // add rbx, 24
    }

    // ========== Phase 2: multi-range fixup over every restored block ==========
    if range_count > 0 {
        let map_rva = stub_rva.checked_add(fixup_map_offset)?;
        // r14 = map base (walk entries); r13d = remaining
        stub.extend_from_slice(&[0x4c, 0x8d, 0x35]); // lea r14, [rip+disp]
        let lea_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(lea_next, map_rva)?);
        stub.extend_from_slice(&[0x41, 0xbd]); // mov r13d, imm32
        stub.extend_from_slice(&u32::try_from(range_count).ok()?.to_le_bytes());

        let p2_start = stub.len();
        // rcx = new_begin; skip if null or size 0
        stub.extend_from_slice(&[0x49, 0x8b, 0x4e, 0x10]); // mov rcx, [r14+0x10]
        stub.extend_from_slice(&[0x48, 0x85, 0xc9]); // test rcx, rcx
        stub.push(0x74); // jz .p2next
        let p2_jz_null = stub.len();
        stub.push(0x00);
        stub.extend_from_slice(&[0x45, 0x8b, 0x46, 0x08]); // mov r8d, [r14+8] size
        stub.extend_from_slice(&[0x45, 0x85, 0xc0]); // test r8d, r8d
        stub.push(0x74); // jz .p2next
        let p2_jz_size = stub.len();
        stub.push(0x00);
        // rdx = map base, r9d = range_count
        stub.extend_from_slice(&[0x48, 0x8d, 0x15]); // lea rdx, [rip+disp]
        let lea_map = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(lea_map, map_rva)?);
        stub.extend_from_slice(&[0x41, 0xb9]); // mov r9d, imm32
        stub.extend_from_slice(&u32::try_from(range_count).ok()?.to_le_bytes());
        stub.push(0xe8);
        multi_fixup_sites.push(stub.len());
        stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

        let p2_next = stub.len();
        stub[p2_jz_null] = u8::try_from(p2_next.checked_sub(p2_jz_null + 1)?).ok()?;
        stub[p2_jz_size] = u8::try_from(p2_next.checked_sub(p2_jz_size + 1)?).ok()?;
        stub.extend_from_slice(&[0x49, 0x83, 0xc6, 0x18]); // add r14, 24
        stub.extend_from_slice(&[0x41, 0xff, 0xcd]); // dec r13d
        let p2_end = stub.len();
        let p2_back = i8::try_from(p2_start as isize - (p2_end as isize + 2)).ok()?;
        stub.extend_from_slice(&[0x75, p2_back as u8]); // jnz .p2
    }

    // Jump over helpers to epilogue (near jmp — helpers exceed short-jmp range).
    stub.push(0xe9);
    let jmp_over_helpers_offset = stub.len();
    stub.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // ---- inline_memcpy(rcx=dst, rdx=src, r8=count) ----
    let memcpy_start = stub.len();
    for site in &memcpy_sites {
        let rel = ((memcpy_start as isize) - (*site as isize) - 4) as i32;
        stub[*site..*site + 4].copy_from_slice(&rel.to_le_bytes());
    }
    stub.extend_from_slice(&[0x57, 0x56]); // push rdi, rsi
    stub.extend_from_slice(&[0x48, 0x89, 0xcf, 0x48, 0x89, 0xd6, 0x4c, 0x89, 0xc1]);
    stub.extend_from_slice(&[0xf3, 0xa4]); // rep movsb
    stub.extend_from_slice(&[0x5e, 0x5f]); // pop rsi, rdi
    stub.push(0xc3);

    // ---- inline_update_triple ----
    let update_start = stub.len();
    for site in &update_sites {
        let rel = ((update_start as isize) - (*site as isize) - 4) as i32;
        stub[*site..*site + 4].copy_from_slice(&rel.to_le_bytes());
    }
    // rcx=data_rva, rdx=cookie, r8=new_begin, r9=content, r11=capacity
    stub.extend_from_slice(&[0x49, 0xba]);
    stub.extend_from_slice(&image_base.to_le_bytes());
    stub.extend_from_slice(&[0x49, 0x01, 0xca]); // add r10, rcx
    stub.extend_from_slice(&[0x8b, 0xca]); // mov ecx, edx
    stub.extend_from_slice(&[0x83, 0xe1, 0x3f]); // and ecx, 63
                                                 // begin
    stub.extend_from_slice(&[0x4c, 0x89, 0xc0]); // mov rax, r8
    stub.extend_from_slice(&[0x48, 0xd3, 0xc0]); // rol rax, cl
    stub.extend_from_slice(&[0x48, 0x31, 0xd0]); // xor rax, rdx
    stub.extend_from_slice(&[0x49, 0x89, 0x02]); // mov [r10], rax
                                                 // capacity
    stub.extend_from_slice(&[0x4c, 0x89, 0xc0]);
    stub.extend_from_slice(&[0x4c, 0x01, 0xd8]); // add rax, r11
    stub.extend_from_slice(&[0x48, 0xd3, 0xc0]);
    stub.extend_from_slice(&[0x48, 0x31, 0xd0]);
    stub.extend_from_slice(&[0x49, 0x89, 0x42, 0x10]);
    // end
    stub.extend_from_slice(&[0x4f, 0x8d, 0x04, 0x08]); // lea r8, [r8+r9]
    stub.extend_from_slice(&[0x4c, 0x89, 0xc0]);
    stub.extend_from_slice(&[0x48, 0xd3, 0xc0]);
    stub.extend_from_slice(&[0x48, 0x31, 0xd0]);
    stub.extend_from_slice(&[0x49, 0x89, 0x42, 0x08]);
    stub.push(0xc3);

    // ---- multi_fixup_block(rcx=new_base, rdx=map_base, r8d=size, r9d=map_count) ----
    // p21h: **exact-base only** — remap qword V iff some map entry has old==V
    // and new!=0 (then *slot = new). Range-interior matches (V in [old,old+size))
    // were false-positive remapping integer fields inside AHK objects → free
    // gscript → `0x149d50=0` (p21e–g). Gscript first-hop force-admit plants
    // exact children for every edge, so exact-base is sufficient for the
    // login-title graph. size field is only used to skip zero/handle rows.
    // MUST preserve Win64 nonvolatiles: phase2 keeps map cursor in r14 and
    // remaining-count in r13 across calls.
    let multi_start = stub.len();
    for site in &multi_fixup_sites {
        let rel = ((multi_start as isize) - (*site as isize) - 4) as i32;
        stub[*site..*site + 4].copy_from_slice(&rel.to_le_bytes());
    }
    stub.extend_from_slice(&[
        0x53, // push rbx
        0x56, // push rsi
        0x41, 0x54, // push r12
        0x41, 0x55, // push r13
        0x41, 0x56, // push r14
        0x41, 0x57, // push r15 (alignment pad; 6 pushes)
    ]);
    // rbx=cursor, r12=end, r13=map_base, r14d=map_count
    stub.extend_from_slice(&[0x48, 0x89, 0xcb]); // mov rbx, rcx
    stub.extend_from_slice(&[0x4c, 0x89, 0xc0]); // mov rax, r8
    stub.extend_from_slice(&[0x48, 0x01, 0xd8]); // add rax, rbx
    stub.extend_from_slice(&[0x49, 0x89, 0xc4]); // mov r12, rax  ; end
    stub.extend_from_slice(&[0x49, 0x89, 0xd5]); // mov r13, rdx  ; map_base
    stub.extend_from_slice(&[0x45, 0x89, 0xce]); // mov r14d, r9d ; map_count

    let scan_loop = stub.len();
    stub.extend_from_slice(&[0x4c, 0x39, 0xe3]); // cmp rbx, r12
    stub.extend_from_slice(&[0x73]); // jae .scan_done
    let jae_scan_done = stub.len();
    stub.push(0x00);

    stub.extend_from_slice(&[0x48, 0x8b, 0x03]); // mov rax, [rbx]  ; V
    stub.extend_from_slice(&[0x4c, 0x89, 0xee]); // mov rsi, r13
    stub.extend_from_slice(&[0x44, 0x89, 0xf1]); // mov ecx, r14d

    let search_loop = stub.len();
    stub.extend_from_slice(&[0x85, 0xc9]); // test ecx, ecx
    stub.extend_from_slice(&[0x74]); // jz .advance
    let jz_advance = stub.len();
    stub.push(0x00);

    stub.extend_from_slice(&[0x48, 0x8b, 0x16]); // mov rdx, [rsi]     ; old
    stub.extend_from_slice(&[0x44, 0x8b, 0x46, 0x08]); // mov r8d, [rsi+8] ; size
    stub.extend_from_slice(&[0x45, 0x85, 0xc0]); // test r8d, r8d
    stub.extend_from_slice(&[0x74]); // jz .next_ent  (handle / empty)
    let jz_next_zero = stub.len();
    stub.push(0x00);
    // Exact base only: V == old
    stub.extend_from_slice(&[0x48, 0x39, 0xd0]); // cmp rax, rdx
    stub.extend_from_slice(&[0x75]); // jne .next_ent
    let jne_next = stub.len();
    stub.push(0x00);
    stub.extend_from_slice(&[0x4c, 0x8b, 0x4e, 0x10]); // mov r9, [rsi+0x10] ; new
    stub.extend_from_slice(&[0x4d, 0x85, 0xc9]); // test r9, r9
    stub.extend_from_slice(&[0x74]); // jz .next_ent
    let jz_next_null = stub.len();
    stub.push(0x00);
    // *cursor = new  (V == old ⇒ V - old + new == new)
    stub.extend_from_slice(&[0x4c, 0x89, 0x0b]); // mov [rbx], r9
    stub.extend_from_slice(&[0xeb]); // jmp .advance
    let jmp_adv_after_hit = stub.len();
    stub.push(0x00);

    let next_ent = stub.len();
    stub[jz_next_zero] = u8::try_from(next_ent.checked_sub(jz_next_zero + 1)?).ok()?;
    stub[jne_next] = u8::try_from(next_ent.checked_sub(jne_next + 1)?).ok()?;
    stub[jz_next_null] = u8::try_from(next_ent.checked_sub(jz_next_null + 1)?).ok()?;
    stub.extend_from_slice(&[0x48, 0x83, 0xc6, 0x18]); // add rsi, 24
    stub.extend_from_slice(&[0xff, 0xc9]); // dec ecx
    stub.extend_from_slice(&[0x75]); // jnz .search
    let jnz_search = stub.len();
    stub.push(0x00);
    let jnz_disp = i8::try_from(search_loop as isize - (jnz_search as isize + 1)).ok()?;
    stub[jnz_search] = jnz_disp as u8;

    let advance = stub.len();
    stub[jz_advance] = u8::try_from(advance.checked_sub(jz_advance + 1)?).ok()?;
    stub[jmp_adv_after_hit] = u8::try_from(advance.checked_sub(jmp_adv_after_hit + 1)?).ok()?;
    stub.extend_from_slice(&[0x48, 0x83, 0xc3, 0x08]); // add rbx, 8
    stub.extend_from_slice(&[0xeb]); // jmp .scan_loop
    let jmp_scan = stub.len();
    stub.push(0x00);
    let jmp_scan_disp = i8::try_from(scan_loop as isize - (jmp_scan as isize + 1)).ok()?;
    stub[jmp_scan] = jmp_scan_disp as u8;

    let scan_done = stub.len();
    stub[jae_scan_done] = u8::try_from(scan_done.checked_sub(jae_scan_done + 1)?).ok()?;
    stub.extend_from_slice(&[
        0x41, 0x5f, // pop r15
        0x41, 0x5e, // pop r14
        0x41, 0x5d, // pop r13
        0x41, 0x5c, // pop r12
        0x5e, // pop rsi
        0x5b, // pop rbx
    ]);
    stub.push(0xc3);

    // Patch near jmp over helpers (rel32 from instruction after e9+disp).
    let after_helpers = stub.len();
    let jmp_rel = (after_helpers as i64) - ((jmp_over_helpers_offset as i64) + 4);
    let jmp_rel = i32::try_from(jmp_rel).ok()?;
    stub[jmp_over_helpers_offset..jmp_over_helpers_offset + 4]
        .copy_from_slice(&jmp_rel.to_le_bytes());

    tracing::info!(
        containers = container_count,
        heap_globals = heap_global_count,
        ranges = range_count,
        helpers_end = after_helpers,
        "Bootstrap code layout (phase1 alloc + phase2 multi-fixup)"
    );

    stub.push(0x90); // nop
    stub.extend_from_slice(&[0x48, 0x83, 0xc4, 0x38]); // add rsp, 0x38
    emit_nonvolatile_pops(stub);

    if let Some(oep) = original_entry_point {
        // R-GTO-UI round 9: mirror live MSVC __security_cookie → AHK
        // call-obfuscation cookie before OEP. Loader randomizes LOAD_CONFIG
        // cookie before any code runs; dump plant of DEFAULT is insufficient.
        // Uses rax only — clear_volatile_regs zeros it next.
        if let Some((src_rva, dst_rva)) = cookie_mirror {
            emit_cookie_mirror(stub, stub_rva, image_base, src_rva, dst_rva)?;
        }
        // Phase-2 multi_fixup leaves Win64 volatiles dirty: last call uses
        // r8d = range size (often 0x8000 for HOT_LARGE_TABLE). AHK OEP at
        // 0x70b0 does `mov rbx,r8; test r8,r8; mov dword [r8],ecx` — a non-null
        // garbage r8 AVs at 0x8000 (W2 / R-GTO-LATEST). CRT's original
        // `jmp OEP` did not pass size leftovers; clear volatiles before transfer.
        emit_clear_volatile_regs(stub);
        // WinMain (0x5a10) needs hInstance in rcx (CRT lea rcx,[__ImageBase]).
        // Fixed-base dumps load at image_base; use that as module handle.
        if oep == 0x5a10 {
            stub.extend_from_slice(&[0x48, 0xb9]); // movabs rcx, imm64
            stub.extend_from_slice(&image_base.to_le_bytes());
            // rdx=0 (hPrev), r8=0 (lpCmdLine ok for AHK self-read), r9=10 SW_SHOWDEFAULT
            stub.extend_from_slice(&[0x41, 0xb9, 0x0a, 0x00, 0x00, 0x00]); // mov r9d, 10
        }
        stub.push(0xe9);
        let jmp_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
        stub.extend_from_slice(&relative_displacement(jmp_next, oep)?);
    } else {
        stub.push(0xc3);
    }

    Some(())
}

/// GTO host freezes on AHK WindowProc/message gate `0x70b0`. Resume must enter
/// WinMain `0x5a10` (static sole caller from CRT). Verified by prologue match
/// before retarget so unrelated samples are untouched.
fn retarget_gto_resume_entry(dump_buf: &[u8], scanned_entry: u32) -> u32 {
    const MSG_GATE: u32 = 0x70b0;
    const WINMAIN: u32 = 0x5a10;
    if scanned_entry != MSG_GATE {
        return scanned_entry;
    }
    // 0x70b0 prologue: mov [rsp+8],rbx; push rdi; sub rsp,230h
    let gate = MSG_GATE as usize;
    let win = WINMAIN as usize;
    if dump_buf.len() < win + 16 || dump_buf.len() < gate + 16 {
        return scanned_entry;
    }
    let gate_ok = &dump_buf[gate..gate + 13]
        == [
            0x48, 0x89, 0x5c, 0x24, 0x08, // mov [rsp+8], rbx
            0x57, // push rdi
            0x48, 0x81, 0xec, 0x30, 0x02, 0x00, 0x00, // sub rsp, 230h
        ];
    // 0x5a10 prologue: mov [rsp+10h],rbx ; mov [rsp+18h],rsi
    let win_ok = &dump_buf[win..win + 10]
        == [
            0x48, 0x89, 0x5c, 0x24, 0x10, // mov [rsp+10h], rbx
            0x48, 0x89, 0x74, 0x24, 0x18, // mov [rsp+18h], rsi
        ];
    if gate_ok && win_ok {
        tracing::info!(
            from = format_args!("{MSG_GATE:#x}"),
            to = format_args!("{WINMAIN:#x}"),
            "R-GTO-UI: retarget resume entry msg-gate → WinMain"
        );
        WINMAIN
    } else {
        scanned_entry
    }
}

/// `mov rax, [rip+src]; mov [rip+dst], rax` for image-relative cookie slots.
fn emit_cookie_mirror(
    stub: &mut Vec<u8>,
    stub_rva: u32,
    _image_base: u64,
    src_rva: u32,
    dst_rva: u32,
) -> Option<()> {
    // mov rax, qword ptr [rip + disp32]  48 8B 05 xx xx xx xx
    stub.extend_from_slice(&[0x48, 0x8B, 0x05]);
    let load_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(load_next, src_rva)?);
    // mov qword ptr [rip + disp32], rax  48 89 05 xx xx xx xx
    stub.extend_from_slice(&[0x48, 0x89, 0x05]);
    let store_next = stub_rva.checked_add(stub.len() as u32)?.checked_add(4)?;
    stub.extend_from_slice(&relative_displacement(store_next, dst_rva)?);
    Some(())
}

/// Zero rax/rcx/rdx/r8–r11 before transferring control to application OEP.
fn emit_clear_volatile_regs(stub: &mut Vec<u8>) {
    stub.extend_from_slice(&[
        0x33, 0xc0, // xor eax, eax
        0x33, 0xc9, // xor ecx, ecx
        0x33, 0xd2, // xor edx, edx
        0x4d, 0x33, 0xc0, // xor r8, r8
        0x4d, 0x33, 0xc9, // xor r9, r9
        0x4d, 0x33, 0xd2, // xor r10, r10
        0x4d, 0x33, 0xdb, // xor r11, r11
    ]);
}

fn emit_nonvolatile_pops(stub: &mut Vec<u8>) {
    stub.extend_from_slice(&[
        0x41, 0x5f, // pop r15
        0x41, 0x5e, // pop r14
        0x41, 0x5d, // pop r13
        0x41, 0x5c, // pop r12
        0x5e, // pop rsi
        0x5b, // pop rbx
    ]);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_size_is_40_bytes() {
        assert_eq!(CONTAINER_METADATA_SIZE, 40);
    }

    #[test]
    fn oep_transfer_emits_cookie_mirror_before_clear_and_jmp() {
        // R-GTO-UI round 9: mov rax,[src]; mov [dst],rax before clear/jmp.
        let container = ContainerSnapshot {
            rva: 0x145710,
            decoded_begin: 0x10000,
            decoded_end: 0x10048,
            decoded_capacity: 0x100,
            cookie: 0x1111_2222_3333_4444,
            heap_content: vec![0u8; 0x48],
        };
        let oep = 0x70b0u32;
        let stub_rva = 0x2000u32;
        let src = 0x141020u32;
        let dst = 0x1454b8u32;
        let stub = build_container_stub_internal(
            stub_rva,
            Some(oep),
            0x2100,
            0x2108,
            &[container],
            &[],
            None,
            None,
            &[],
            None,
            0x140000000,
            0x141000,
            None,
            None,
            Some((src, dst)),
        )
        .expect("stub with cookie mirror");

        // Find `mov rax, [rip+disp]` then `mov [rip+disp], rax` near the end.
        let load = stub
            .windows(3)
            .rposition(|b| b == [0x48, 0x8B, 0x05])
            .expect("cookie load");
        let store = stub
            .windows(3)
            .rposition(|b| b == [0x48, 0x89, 0x05])
            .expect("cookie store");
        assert!(store > load, "store must follow load");
        let load_next = stub_rva as i64 + load as i64 + 7;
        let load_disp = i32::from_le_bytes(stub[load + 3..load + 7].try_into().unwrap());
        assert_eq!((load_next + i64::from(load_disp)) as u32, src);
        let store_next = stub_rva as i64 + store as i64 + 7;
        let store_disp = i32::from_le_bytes(stub[store + 3..store + 7].try_into().unwrap());
        assert_eq!((store_next + i64::from(store_disp)) as u32, dst);

        let clear = [
            0x33, 0xc0, 0x33, 0xc9, 0x33, 0xd2, 0x4d, 0x33, 0xc0, 0x4d, 0x33, 0xc9, 0x4d, 0x33,
            0xd2, 0x4d, 0x33, 0xdb,
        ];
        let pos = stub
            .windows(clear.len())
            .position(|w| w == clear)
            .expect("clear after mirror");
        assert!(pos > store, "clear must follow cookie store");
        assert_eq!(stub[pos + clear.len()], 0xe9, "clear precedes near jmp");
    }

    #[test]
    fn oep_transfer_clears_volatile_regs_before_jmp() {
        // GTO W2: multi_fixup leaves r8=size; OEP treats r8 as optional ptr.
        let container = ContainerSnapshot {
            rva: 0x145710,
            decoded_begin: 0x10000,
            decoded_end: 0x10048,
            decoded_capacity: 0x100,
            cookie: 0x1111_2222_3333_4444,
            heap_content: vec![0u8; 0x48],
        };
        let oep = 0x70b0u32;
        // Place stub and dummy IAT close so RIP-relative calls encode.
        let stub_rva = 0x2000u32;
        let stub = build_container_stub_internal(
            stub_rva,
            Some(oep),
            0x2100, // GetProcessHeap IAT
            0x2108, // HeapAlloc IAT
            &[container],
            &[],
            None,
            None,
            &[],
            None,
            0x140000000,
            0x141000,
            None,
            None,
            None, // cookie_mirror
        )
        .expect("container stub with OEP transfer");
        let clear = [
            0x33, 0xc0, 0x33, 0xc9, 0x33, 0xd2, 0x4d, 0x33, 0xc0, 0x4d, 0x33, 0xc9, 0x4d, 0x33,
            0xd2, 0x4d, 0x33, 0xdb,
        ];
        let pos = stub
            .windows(clear.len())
            .position(|w| w == clear)
            .expect("clear volatile regs before OEP");
        assert_eq!(stub[pos + clear.len()], 0xe9, "clear must precede near jmp");
        let rel =
            i32::from_le_bytes(stub[pos + clear.len() + 1..pos + clear.len() + 5].try_into().unwrap());
        let next = stub_rva + (pos + clear.len() + 5) as u32;
        assert_eq!((next as i64 + i64::from(rel)) as u32, oep);
    }

    #[test]
    fn patches_crt_wrapper_jmp_and_keeps_original_target() {
        // sub rsp,28; call +5; add rsp,28; jmp +0x1000 (relative)
        let mut buf = vec![0u8; 0x2000];
        let ep = 0x100u32;
        let off = ep as usize;
        buf[off..off + 4].copy_from_slice(&[0x48, 0x83, 0xec, 0x28]);
        buf[off + 4] = 0xe8;
        buf[off + 5..off + 9].copy_from_slice(&5i32.to_le_bytes()); // dummy call
        buf[off + 9..off + 13].copy_from_slice(&[0x48, 0x83, 0xc4, 0x28]);
        buf[off + 13] = 0xe9;
        // jmp next = ep+18; target = 0x1200
        let next = ep + 18;
        let target = 0x1200u32;
        let rel = (target as i64 - next as i64) as i32;
        buf[off + 14..off + 18].copy_from_slice(&rel.to_le_bytes());

        let decoded = patch_crt_wrapper_jmp_to_stub(&mut buf, ep, 0).unwrap();
        assert_eq!(decoded, target);

        let stub = 0x1500u32;
        let again = patch_crt_wrapper_jmp_to_stub(&mut buf, ep, stub).unwrap();
        assert_eq!(again, target);
        let new_rel = i32::from_le_bytes(buf[off + 14..off + 18].try_into().unwrap());
        assert_eq!((next as i64 + new_rel as i64) as u32, stub);
    }

    #[test]
    fn metadata_starts_after_complete_tls_epilogue() {
        let marker_rva = 0x141234;
        let container = ContainerSnapshot {
            rva: marker_rva,
            decoded_begin: 0x10000,
            decoded_end: 0x10008,
            decoded_capacity: 0x10020,
            cookie: 0x1234_5678_9abc_def0,
            heap_content: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let stub = build_tls_bootstrap_stub(
            0x1000,
            0x2000,
            0x2010,
            &[container],
            None,
            0x140000000,
            0x141000,
            Some(0x145d50),
            None,
        )
        .expect("TLS stub should build");

        let epilogue = [
            0x90, 0x48, 0x83, 0xc4, 0x38, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x5e,
            0x5b, 0xc3,
        ];
        let epilogue_start = stub
            .windows(epilogue.len())
            .position(|bytes| bytes == epilogue)
            .expect("complete TLS epilogue");
        let metadata_start = stub
            .windows(4)
            .position(|bytes| bytes == marker_rva.to_le_bytes())
            .expect("container metadata");

        assert_eq!(
            u32::from_le_bytes(
                stub[metadata_start + 4..metadata_start + 8]
                    .try_into()
                    .unwrap()
            ),
            8
        );
        assert_eq!(
            u32::from_le_bytes(
                stub[metadata_start + 0x14..metadata_start + 0x18]
                    .try_into()
                    .unwrap()
            ),
            0x20
        );

        assert!(epilogue_start + epilogue.len() <= metadata_start);
        assert!(stub[epilogue_start + epilogue.len()..metadata_start]
            .iter()
            .all(|byte| *byte == 0xcc));

        let store = stub
            .windows(3)
            .position(|bytes| bytes == [0x48, 0x89, 0x05])
            .expect("heap global store");
        let displacement = i32::from_le_bytes(stub[store + 3..store + 7].try_into().unwrap());
        let target = (0x1000_i64 + store as i64 + 7 + i64::from(displacement)) as u32;
        assert_eq!(target, 0x145d50);

        assert!(stub
            .windows(5)
            .any(|bytes| bytes == [0x8b, 0xca, 0x83, 0xe1, 0x3f]));
        assert_eq!(
            stub.windows(3)
                .filter(|bytes| *bytes == [0x48, 0xd3, 0xc0])
                .count(),
            3,
            "begin, end and capacity pointers must be rotated before XOR"
        );
        assert!(stub
            .windows(4)
            .any(|bytes| bytes == [0x4f, 0x8d, 0x04, 0x08]));
        assert!(stub
            .windows(4)
            .any(|bytes| bytes == [0x45, 0x8b, 0x46, 0x14]));
        assert!(stub
            .windows(4)
            .any(|bytes| bytes == [0x45, 0x8b, 0x5e, 0x14]));
        assert!(stub.windows(3).any(|bytes| bytes == [0x4c, 0x01, 0xd8]));
    }

    #[test]
    fn tls_process_attach_skips_complete_early_return() {
        let mut stub = Vec::new();
        build_stub_code(
            &mut stub,
            0x1000,
            None,
            0x2000,
            0x2010,
            0, // container_count
            0, // heap_global_count
            0, // metadata_offset
            0, // heap_global_meta_offset
            0, // fixup_map_offset
            0, // range_count
            None,
            0,
            0x140000000,
            0,
            None,
            None, // cookie_rva: metadata fallback
            None, // cookie_mirror
        )
        .expect("TLS stub should build");

        let cmp = stub
            .windows(3)
            .position(|bytes| bytes == [0x83, 0xfa, 0x01])
            .expect("Reason comparison");
        assert_eq!(&stub[cmp + 3..cmp + 5], &[0x74, 0x0f]);
        assert_eq!(
            stub[cmp + 5 + 0x0f],
            0xff,
            "branch must land on GetProcessHeap call"
        );
    }

    #[test]
    fn data_offset_uses_dword_add_not_qword() {
        let mut stub = Vec::new();
        build_stub_code(
            &mut stub,
            0x1000,
            None,
            0x2000,
            0x2010,
            1,     // container_count
            0,     // heap_global_count
            0x100, // metadata_offset
            0,     // heap_global_meta_offset
            0,     // fixup_map_offset
            0,     // range_count
            None,
            0,
            0x140000000,
            0,
            None,
            None, // cookie_rva: metadata fallback
            None, // cookie_mirror
        )
        .expect("TLS stub should build");

        // 41 8b 46 10 ; 48 01 c2  = mov eax,[r14+0x10]; add rdx,rax
        assert!(
            stub.windows(7)
                .any(|b| b == [0x41, 0x8b, 0x46, 0x10, 0x48, 0x01, 0xc2]),
            "expected mov eax,[r14+0x10]; add rdx,rax for data_offset"
        );
        assert!(
            !stub.windows(4).any(|b| b == [0x49, 0x03, 0x56, 0x10]),
            "must not use qword add of data_offset"
        );
        assert!(
            !stub.windows(4).any(|b| b == [0x41, 0x03, 0x56, 0x10]),
            "must not use 32-bit add that clears RDX high half"
        );
    }
}
