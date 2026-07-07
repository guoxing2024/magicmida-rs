//! MSVC-specific `.rdata` / `.data` section restoration.

use tracing::{debug, info, warn};

use mida_pe::PeHeader;

use crate::error::ThemidaError;

use super::helpers::{make_section, recalc_size_of_image, update_section_from_header};
use super::{IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};

// ===========================================================================
// DataSectionResult
// ===========================================================================

/// Result of restoring `.rdata` and `.data` sections.
///
/// Returned by [`super::create_data_sections`] to describe what was created and where.
#[derive(Debug, Clone, Copy)]
pub struct DataSectionResult {
    /// `true` if the `.rdata` section was successfully created.
    pub rdata_created: bool,
    /// `true` if the `.data` section was successfully created.
    pub data_created: bool,
    /// RVA of the new `.rdata` section.
    pub rdata_rva: u32,
    /// RVA of the new `.data` section.
    pub data_rva: u32,
    /// Virtual size of the new `.rdata` section.
    pub rdata_size: u32,
    /// Virtual size of the new `.data` section.
    pub data_size: u32,
}

// ===========================================================================
// MSVC data-section creation
// ===========================================================================

/// MSVC-specific data-section creation.
///
/// Implements the logic from `Patcher.pas` `MSVCCreateDataSections`.
pub(super) fn create_data_sections_msvc(
    pe: &mut PeHeader,
    text_section_data: &[u8],
    text_section_rva: u32,
) -> Result<DataSectionResult, ThemidaError> {
    // Determine base_of_data — the boundary between code and data.
    let base_of_data: u32 = if pe.is_64bit {
        pe.sections[0].virtual_address + pe.nt_headers.optional_header.size_of_code
    } else {
        pe.nt_headers
            .optional_header
            .base_of_data
            .unwrap_or(0)
    };

    // Verify that code and data are actually merged into the first section.
    // BaseOfData must fall inside section[0] and be page-aligned.
    let text_sec = &pe.sections[0];
    let text_vs = text_sec.virtual_size;
    let text_va = text_sec.virtual_address;
    let text_end = text_va + text_vs;

    if base_of_data <= text_va || base_of_data >= text_end || (base_of_data & 0xFFF) != 0 {
        info!("Code and data sections do not appear to be merged — nothing to do");
        return Ok(DataSectionResult {
            rdata_created: false,
            data_created: false,
            rdata_rva: 0,
            data_rva: 0,
            rdata_size: 0,
            data_size: 0,
        });
    }

    // Locate the dyn_tls_init_callback variable to find the .data boundary.
    let dyn_tls_rva =
        find_dyn_tls_msvc14(text_section_data, text_section_rva, pe.is_64bit, pe.image_base);

    // Compute the start of .data.
    // If we found the TLS callback, round its address up to the next page so
    // the callback itself lands in .rdata (ro) and only the writable part
    // goes into .data.  If we couldn't find it, fall back to a fixed offset.
    let data_start_rva: u32 = if let Some(rva) = dyn_tls_rva {
        (rva + 0x1000) & !0xFFF
    } else {
        info!("DynTLS callback not found — using fallback data boundary");
        base_of_data + 0x1000
    };

    let rdata_start_rva = base_of_data;
    let rdata_size = data_start_rva.saturating_sub(rdata_start_rva);

    // The .data section extends from data_start_rva up to the next section's
    // start (original section[1], which will be at index 3 after we insert
    // the two new sections).
    let original_len = pe.sections.len();
    let next_section_rva = if original_len > 1 {
        pe.sections[1].virtual_address
    } else {
        pe.size_of_image()
    };
    let data_size = next_section_rva.saturating_sub(data_start_rva);

    // Sanity-check the sizes.
    if rdata_size < 0x200 || data_size < 0x200 {
        warn!(
            rdata_size = format!("{rdata_size:#x}"),
            data_size = format!("{data_size:#x}"),
            "Computed data-section sizes are too small — aborting"
        );
        return Ok(DataSectionResult {
            rdata_created: false,
            data_created: false,
            rdata_rva: 0,
            data_rva: 0,
            rdata_size: 0,
            data_size: 0,
        });
    }

    // ---- Insert two new sections at index 1 (.rdata) and index 2 (.data).
    // This matches the Pascal: AddSectionToArray twice, then shift from index
    // 3 downward, leaving slots 1 and 2 for the new sections.

    pe.sections.push(mida_pe::PeSection::default());
    pe.sections.push(mida_pe::PeSection::default());

    // Shift: sections[1..original_len-1] → sections[3..original_len+1]
    // Walk high → low so we never read a slot we already overwrote.
    for i in (3..original_len + 2).rev() {
        pe.sections[i] = pe.sections[i - 2].clone();
    }

    // --- .data at index 2 ---
    pe.sections[2] = make_section(
        ".data",
        data_start_rva,
        data_size,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,
    );

    // --- .rdata at index 1 ---
    pe.sections[1] = make_section(
        ".rdata",
        rdata_start_rva,
        rdata_size,
        IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA,
    );

    // --- Shrink .text (section 0) ---
    let total_split = rdata_size + data_size;
    pe.sections[0].header.virtual_size =
        pe.sections[0].header.virtual_size.saturating_sub(total_split);
    pe.sections[0].header.size_of_raw_data =
        pe.sections[0].header.size_of_raw_data.saturating_sub(total_split);
    update_section_from_header(&mut pe.sections[0]);

    // --- Rename .text and drop WRITE ---
    pe.sections[0].rename(".text");
    pe.sections[0].header.characteristics &= !IMAGE_SCN_MEM_WRITE;
    update_section_from_header(&mut pe.sections[0]);

    // Update section count and size-of-image.
    pe.nt_headers.file_header.number_of_sections =
        pe.nt_headers.file_header.number_of_sections.saturating_add(2);
    recalc_size_of_image(pe);

    info!(
        ".rdata: {rdata_start_rva:#x} .. {:#x}  ({rdata_size:#x} bytes)",
        rdata_start_rva + rdata_size,
    );
    info!(
        ".data : {data_start_rva:#x} .. {:#x}  ({data_size:#x} bytes)",
        data_start_rva + data_size,
    );

    Ok(DataSectionResult {
        rdata_created: true,
        data_created: true,
        rdata_rva: rdata_start_rva,
        data_rva: data_start_rva,
        rdata_size,
        data_size,
    })
}

// ===========================================================================
// find_dyn_tls_msvc14
// ===========================================================================

/// Locate the MSVC14 `_dyn_tls_init_callback` variable by scanning `.text`.
///
/// Returns the RVA of the variable if found.  This address is used as the
/// approximate start of the `.data` section.
///
/// ## x64 detection
///
/// Scans for `lea rcx, [rip + _dyn_tls_init_callback]` — byte pattern
/// `48 8D 0D xx xx xx xx`.  The RIP-relative displacement is decoded and
/// the effective address of the variable is returned as an RVA.
///
/// ## x86 detection
///
/// Follows the `Patcher.pas` `FindDynTLSMSVC14` approach:
///
/// 1. Scan for `8B F0 33 FF 39 3E 74 ?? 56 E8` (the TLS-init code sequence).
/// 2. Follow the `call rel32` that precedes the sequence to reach
///    `__scrt_get_dyn_tls_init_callback`.
/// 3. Trace through any `jmp` indirections.
/// 4. Read the `mov eax, imm32` instruction to get the absolute VA of the
///    callback pointer.
/// 5. Subtract `image_base` to convert to an RVA.
///
/// ## References
///
/// `Patcher.pas` `FindDynTLSMSVC14`.
fn find_dyn_tls_msvc14(
    text_section_data: &[u8],
    text_section_rva: u32,
    is_64bit: bool,
    image_base: u64,
) -> Option<u32> {
    if is_64bit {
        find_dyn_tls_x64(text_section_data, text_section_rva)
    } else {
        find_dyn_tls_x86(text_section_data, image_base)
    }
}

/// x64: find `lea rcx, [rip + _dyn_tls_init_callback]` → `48 8D 0D xx xx xx xx`.
fn find_dyn_tls_x64(text_section_data: &[u8], text_section_rva: u32) -> Option<u32> {
    // The x64 CRL uses `lea rcx, [_dyn_tls_init_callback]` to pass the
    // address of the TLS callback pointer to a registration function.
    // We scan for the byte pattern and compute the effective address.
    let pattern = mida_disasm::BytePattern::parse("48 8D 0D").ok()?;

    for off in pattern.find_all(text_section_data) {
        if off + 7 > text_section_data.len() {
            continue;
        }

        let disp = i32::from_le_bytes([
            text_section_data[off + 3],
            text_section_data[off + 4],
            text_section_data[off + 5],
            text_section_data[off + 6],
        ]);

        let instr_rva = text_section_rva + off as u32;
        let next_rva = instr_rva + 7; // RIP after the lea
        let target_rva = next_rva.wrapping_add(disp as u32);

        // The target should be outside .text proper — in the data region.
        // We accept it if it's beyond the scanned range (which is .text).
        let text_end = text_section_rva + text_section_data.len() as u32;
        if target_rva > text_end || target_rva < text_section_rva {
            debug!(
                "Found lea rcx, [rip+disp] at RVA {instr_rva:#x} → target {target_rva:#x}"
            );
            return Some(target_rva);
        }
    }

    None
}

/// x86: follow the `Patcher.pas` `FindDynTLSMSVC14` call chain.
fn find_dyn_tls_x86(text_section_data: &[u8], image_base: u64) -> Option<u32> {
    // Step 1 — locate the TLS-init code sequence:
    //   mov esi, eax
    //   xor edi, edi
    //   cmp [esi], edi
    //   jz  short +??
    //   push esi
    //   call __scrt_get_dyn_tls_init_callback
    let code_off = mida_disasm::find_dynamic(text_section_data, "8B F0 33 FF 39 3E 74 ?? 56 E8")?;

    // The matched sequence starts at `code_off`.  The bytes immediately
    // *before* it should be part of a `call rel32` (E8 xx xx xx xx).
    if code_off < 5 {
        return None;
    }
    if text_section_data[code_off - 5] != 0xE8 {
        debug!(
            offset = code_off,
            "DynTLS code sequence found but preceding byte is not E8 (call)"
        );
        return None;
    }

    // Follow the call: displacement at code_off-4..code_off-1.
    let call_disp = i32::from_le_bytes([
        text_section_data[code_off - 4],
        text_section_data[code_off - 3],
        text_section_data[code_off - 2],
        text_section_data[code_off - 1],
    ]);

    // The call instruction is at code_off-5. Its target = code_off + call_disp.
    let mut ptr = (code_off as i64 + call_disp as i64) as usize;
    if ptr >= text_section_data.len() {
        return None;
    }

    // Step 2 — follow any jmp indirection (E9 rel32).
    if text_section_data[ptr] == 0xE9 && ptr + 5 <= text_section_data.len() {
        let jmp_disp = i32::from_le_bytes([
            text_section_data[ptr + 1],
            text_section_data[ptr + 2],
            text_section_data[ptr + 3],
            text_section_data[ptr + 4],
        ]);
        ptr = (ptr as i64 + 5 + jmp_disp as i64) as usize;
        if ptr >= text_section_data.len() {
            return None;
        }
    }

    // Step 3 — expect `mov eax, imm32` (B8 xx xx xx xx).
    if text_section_data[ptr] != 0xB8 || ptr + 5 > text_section_data.len() {
        debug!(offset = ptr, "DynTLS call target is not mov eax, imm32");
        return None;
    }

    let imm = u32::from_le_bytes([
        text_section_data[ptr + 1],
        text_section_data[ptr + 2],
        text_section_data[ptr + 3],
        text_section_data[ptr + 4],
    ]);

    // Convert absolute VA → RVA by subtracting the image base.
    let rva = imm.wrapping_sub(image_base as u32);

    debug!("DynTLS callback RVA = {rva:#x}");
    Some(rva)
}
