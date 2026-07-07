//! Post-processing for Themida-unpacked PE binaries.
//!
//! After the initial unpack (OEP detection, IAT repair), the dumped PE still
//! needs several fixups before it can run independently:
//!
//! 1. **Shrink** — remove Themida-specific sections that are no longer needed.
//! 2. **Data sections** — restore `.rdata` and `.data` sections that Themida
//!    merged into `.text`.
//! 3. **Dump process code** — read de-virtualised `.text` from a running
//!    process (used with Oreans Unvirtualizer).
//! 4. **Anti-dump fix** — install a stub at OEP that patches the PE header
//!    before jumping to the VM entry (bypasses VM PE-header integrity checks).
//!
//! ## References
//!
//! | Rust function              | Pascal equivalent                          |
//! |----------------------------|--------------------------------------------|
//! | [`shrink_pe`]              | `TPatcher.ShrinkPE` / `ProcessShrink`      |
//! | [`create_data_sections`]   | `TPatcher.ProcessMkData`                   |
//! | [`dump_process_code`]      | `TPatcher.DumpProcessCode`                 |
//! | [`install_anti_dump_fix`]  | `TAntiDumpFixer.RedirectOEP`               |

use std::path::Path;

use tracing::{debug, info, warn};

use mida_core::DebuggerCore;
use mida_disasm::find_dynamic;
use mida_pe::PeHeader;

use crate::error::ThemidaError;
use crate::iat::CompilerHint;
use crate::version::is_themida_section;

// ---------------------------------------------------------------------------
// Section characteristics constants
// ---------------------------------------------------------------------------

const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;

// ===========================================================================
// DataSectionResult
// ===========================================================================

/// Result of restoring `.rdata` and `.data` sections.
///
/// Returned by [`create_data_sections`] to describe what was created and where.
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
// shrink_pe
// ===========================================================================

/// Delete Themida-specific sections from a PE header.
///
/// After unpacking, the Themida protector sections (usually the last 1–2
/// sections in the section table) are no longer needed and can be safely
/// removed.  This is safe when the binary has been de-virtualised (or never
/// used virtualisation in the first place).
///
/// ## Strategy
///
/// 1. Identify Themida sections via [`is_themida_section`].
/// 2. Keep sections that are referenced by a data directory entry.
/// 3. Keep section 0 (`.text`) unconditionally.
/// 4. Delete everything else that matches the Themida heuristic.
/// 5. Update `NumberOfSections` and `SizeOfImage`.
///
/// ## Returns
///
/// The number of sections that were deleted.
///
/// ## Warning
///
/// For non-MSVC compilers this may corrupt the binary if the Themida section
/// contains data the original code relies on.  Always test the output.
///
/// ## References
///
/// `Patcher.pas` `ProcessShrink` / `ShrinkPE`.
pub fn shrink_pe(pe: &mut PeHeader) -> Result<usize, ThemidaError> {
    let mut removed: usize = 0;

    // Walk backwards so lower indices stay stable across deletions.
    let mut i = pe.sections.len().saturating_sub(1);
    loop {
        if i == 0 {
            break; // never delete section 0 (.text)
        }

        let should_delete = {
            let section = &pe.sections[i];
            is_themida_section(section) && !is_referenced_by_data_directory(pe, section)
        };

        if should_delete {
            debug!(
                index = i,
                name = pe.sections[i].name.as_str(),
                "Deleting Themida section"
            );
            // SAFETY: i > 0 is guaranteed by the loop condition above.
            pe.delete_section(i);
            removed += 1;
        }

        if i == 0 {
            break;
        }
        i = i.saturating_sub(1);
    }

    recalc_size_of_image(pe);

    info!(removed, "Shrink complete");
    Ok(removed)
}

// ===========================================================================
// create_data_sections (main entry point)
// ===========================================================================

/// Restore `.rdata` and `.data` sections that were merged into `.text`.
///
/// Themida merges the original `.rdata` and `.data` sections into `.text`.
/// This function reverses the merge, which is critical for MSVC programs that
/// use TLS — without a proper `.data` section, TLS initialisation fails at
/// startup.
///
/// ## How it works
///
/// Two strategies are available (matching the Pascal reference):
///
/// 1. **MSVC 2015+** — locate the `_dyn_tls_init_callback` variable by
///    scanning for its signature in the `.text` bytecode, then derive the
///    `.rdata` / `.data` boundary from its address.
///
/// 2. **Delphi / Go** — these compilers lay out `.text` differently;
///    data-section creation is a no-op.
///
/// `compiler_hint` determines which strategy is used.  Pass
/// [`CompilerHint::Auto`] to auto-detect (falls back to MSVC).
///
/// ## Parameters
///
/// * `pe` — the parsed PE header (mutated in-place).
/// * `text_section_data` — the raw bytes of the (merged) `.text` section.
/// * `text_section_rva` — RVA where `.text` starts.
/// * `compiler_hint` — compiler hint.
///
/// ## References
///
/// `Patcher.pas` `ProcessMkData` / `MSVCCreateDataSections`.
pub fn create_data_sections(
    pe: &mut PeHeader,
    text_section_data: &[u8],
    text_section_rva: u32,
    compiler_hint: CompilerHint,
) -> Result<DataSectionResult, ThemidaError> {
    match compiler_hint {
        CompilerHint::Msvc | CompilerHint::Auto => {
            create_data_sections_msvc(pe, text_section_data, text_section_rva)
        }
        CompilerHint::Delphi | CompilerHint::Go => {
            info!(
                "Data-section creation is not available for {:?} binaries",
                compiler_hint
            );
            Ok(DataSectionResult {
                rdata_created: false,
                data_created: false,
                rdata_rva: 0,
                data_rva: 0,
                rdata_size: 0,
                data_size: 0,
            })
        }
    }
}

// ===========================================================================
// MSVC data-section creation
// ===========================================================================

/// MSVC-specific data-section creation.
///
/// Implements the logic from `Patcher.pas` `MSVCCreateDataSections`.
fn create_data_sections_msvc(
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
    let code_off = find_dynamic(text_section_data, "8B F0 33 FF 39 3E 74 ?? 56 E8")?;

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

// ===========================================================================
// dump_process_code
// ===========================================================================

/// Dump the `.text` section from a running (de-virtualised) process.
///
/// This is used in combination with **Oreans Unvirtualizer**:
///
/// 1. Unpack the binary normally (without restoring data sections).
/// 2. Load the dumped binary in OllyDbg / x64dbg.
/// 3. Run Oreans Unvirtualizer to de-virtualise the code.
/// 4. Call this function to read the de-virtualised `.text` from the live
///    process and write it to `output_path`.
///
/// The dump range is `ImageBase + .text.VirtualAddress` to `ImageBase +
/// BaseOfData` (i.e. from the start of `.text` to the start of the data
/// region).
///
/// ## Returns
///
/// The number of bytes written to `output_path`.
///
/// ## Errors
///
/// Returns [`ThemidaError::Debugger`] if memory reads fail or
/// [`ThemidaError::PostProcess`] if the file cannot be written.
///
/// ## References
///
/// `Patcher.pas` `DumpProcessCode`.
pub fn dump_process_code(
    debugger: &dyn DebuggerCore,
    pe: &PeHeader,
    output_path: &Path,
) -> Result<usize, ThemidaError> {
    let image_base = pe.image_base as usize;
    let text_start = image_base + pe.sections[0].virtual_address as usize;

    let base_of_data = if pe.is_64bit {
        pe.sections[0].virtual_address + pe.nt_headers.optional_header.size_of_code
    } else {
        pe.nt_headers
            .optional_header
            .base_of_data
            .unwrap_or(0)
    };
    let text_end = image_base + base_of_data as usize;

    let dump_size = text_end.saturating_sub(text_start);
    if dump_size == 0 {
        return Err(ThemidaError::PostProcess(
            "Dump range is empty — check .text section bounds".into(),
        ));
    }

    info!(
        "Dumping .text: {text_start:#x} .. {text_end:#x}  ({dump_size:#x} bytes)"
    );

    let mut buf = vec![0u8; dump_size];
    let bytes_read = debugger
        .read_memory(text_start, &mut buf)
        .map_err(|e| ThemidaError::Debugger(format!("dump_process_code read: {e}")))?;

    // Truncate if short read.
    buf.truncate(bytes_read);

    std::fs::write(output_path, &buf)
        .map_err(|e| ThemidaError::PostProcess(format!("dump_process_code write: {e}")))?;

    info!("Dumped {bytes_read} bytes to {}", output_path.display());
    Ok(bytes_read)
}

// ===========================================================================
// install_anti_dump_fix
// ===========================================================================

/// Install a stub at the OEP that patches the PE header before jumping to the
/// VM entry point.
///
/// Some Themida versions place anti-dump code at the OEP that checks the PE
/// header's integrity at runtime.  If the PE header has been modified (as
/// happens after dumping), the check fails and the program crashes.
///
/// This function writes a small assembly stub at `oep` that:
///
/// 1. Calls `VirtualProtect(ImageBase, 0x400, PAGE_READWRITE, &OldProtect)`.
/// 2. Writes the correct `AddressOfEntryPoint` into the in-memory PE header.
/// 3. Calls `VirtualProtect` again to restore the original protection.
/// 4. Jumps to `vm_entry` (the real OEP / VM entry point).
///
/// ## Space requirement
///
/// The stub is approximately 60 bytes (x86) or 70 bytes (x64).  The caller
/// must ensure there is enough room at the OEP.  If the space is insufficient,
/// [`ThemidaError::SpaceTooSmall`] is returned.
///
/// ## Assumptions
///
/// This is a **pragmatic** fix — it only handles one type of PE-header
/// anti-dump.  Binaries with virtualisation in other parts of the program may
/// still crash.  Other anti-dump types (e.g. those that check `kernel32.dll`'s
/// PE header) are not addressed.
///
/// ## References
///
/// `AntiDumpFix.pas` `TAntiDumpFixer.RedirectOEP`.
pub fn install_anti_dump_fix(
    debugger: &mut dyn DebuggerCore,
    oep: usize,
    image_base: usize,
    virtual_protect_addr: usize,
    vm_entry: usize,
    is_64bit: bool,
) -> Result<(), ThemidaError> {
    if is_64bit {
        install_anti_dump_fix_x64(debugger, oep, image_base, virtual_protect_addr, vm_entry)
    } else {
        install_anti_dump_fix_x86(debugger, oep, image_base, virtual_protect_addr, vm_entry)
    }
}

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
fn install_anti_dump_fix_x86(
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
fn install_anti_dump_fix_x64(
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

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Check whether a data directory entry references the given section.
fn is_referenced_by_data_directory(pe: &PeHeader, section: &mida_pe::PeSection) -> bool {
    let sec_start = section.virtual_address;
    let sec_end = section.virtual_address + section.virtual_size;

    for dir in &pe.nt_headers.optional_header.data_directory {
        if dir.virtual_address == 0 {
            continue;
        }
        let dir_end = dir.virtual_address.saturating_add(dir.size);
        if dir.virtual_address >= sec_start && dir_end <= sec_end {
            return true;
        }
    }
    false
}

/// Recompute `SizeOfImage` from the last section's end.
fn recalc_size_of_image(pe: &mut PeHeader) {
    if let Some(last) = pe.sections.last() {
        let new_size = last.virtual_address + last.virtual_size;
        pe.nt_headers.optional_header.size_of_image = new_size;
    }
}

/// Create a [`PeSection`] from raw values.
///
/// Used internally to construct the new `.rdata` and `.data` sections.
fn make_section(name: &str, virtual_address: u32, virtual_size: u32, characteristics: u32) -> mida_pe::PeSection {
    let mut name_bytes = [0u8; 8];
    let name_slice = name.as_bytes();
    let len = name_slice.len().min(8);
    name_bytes[..len].copy_from_slice(&name_slice[..len]);

    let header = mida_pe::ImageSectionHeader {
        name: name_bytes,
        virtual_size,
        virtual_address,
        size_of_raw_data: virtual_size,
        pointer_to_raw_data: virtual_address,
        pointer_to_relocations: 0,
        pointer_to_linenumbers: 0,
        number_of_relocations: 0,
        number_of_linenumbers: 0,
        characteristics,
    };

    mida_pe::PeSection {
        header,
        name: name.to_string(),
        virtual_address,
        virtual_size,
        raw_offset: virtual_address,
        raw_size: virtual_size,
        characteristics,
        extra_data: None,
    }
}

/// Sync the public fields of a [`PeSection`] from its raw header after mutation.
fn update_section_from_header(section: &mut mida_pe::PeSection) {
    // The PeSection::update_from_header method is crate-private (pub(crate)).
    // We inline the logic here since we're outside the `mida_pe` crate.
    section.name = mida_pe::header::decode_section_name(&section.header.name);
    section.virtual_address = section.header.virtual_address;
    section.virtual_size = section.header.virtual_size;
    section.raw_offset = section.header.pointer_to_raw_data;
    section.raw_size = section.header.size_of_raw_data;
    section.characteristics = section.header.characteristics;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal packed PE64 suitable for shrink / data-section tests.
    fn make_packed_pe64() -> PeHeader {
        let mut buf = vec![0u8; 512];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[60] = 0x40;
        let nt = 0x40;
        buf[nt] = 0x50;
        buf[nt + 1] = 0x45;
        let fh = nt + 4;
        buf[fh] = 0x64;
        buf[fh + 1] = 0x86;
        buf[fh + 2] = 3; // 3 sections
        buf[fh + 16] = 0xF0;
        buf[fh + 18] = 0x22;
        let oh = nt + 24;
        buf[oh] = 0x0B;
        buf[oh + 1] = 0x02;
        buf[oh + 16] = 0x00;
        buf[oh + 17] = 0x30; // EntryPoint = 0x3000
        buf[oh + 27] = 0x40;
        buf[oh + 28] = 0x01;
        buf[oh + 32] = 0x00;
        buf[oh + 33] = 0x10;
        buf[oh + 36] = 0x00;
        buf[oh + 37] = 0x02;
        buf[oh + 56] = 0x00;
        buf[oh + 57] = 0x70; // SizeOfImage = 0x7000
        buf[oh + 60] = 0x00;
        buf[oh + 61] = 0x02;
        buf[oh + 108] = 0x10;

        // .text at 0x1000, VS=0x1000
        let s1 = nt + 24 + 240;
        buf[s1] = b'.';
        buf[s1 + 1] = b't';
        buf[s1 + 2] = b'e';
        buf[s1 + 3] = b'x';
        buf[s1 + 4] = b't';
        buf[s1 + 8] = 0x00;
        buf[s1 + 9] = 0x10;
        buf[s1 + 12] = 0x00;
        buf[s1 + 13] = 0x10;
        buf[s1 + 16] = 0x00;
        buf[s1 + 17] = 0x02;
        buf[s1 + 20] = 0x00;
        buf[s1 + 21] = 0x02;
        buf[s1 + 36] = 0x20;
        buf[s1 + 39] = 0xE0; // R+W+X (merged data)

        // Normal section at 0x2000
        let s2 = s1 + 40;
        buf[s2] = b'.';
        buf[s2 + 1] = b'd';
        buf[s2 + 2] = b'a';
        buf[s2 + 3] = b't';
        buf[s2 + 4] = b'a';
        buf[s2 + 8] = 0x00;
        buf[s2 + 9] = 0x10;
        buf[s2 + 12] = 0x00;
        buf[s2 + 13] = 0x20;
        buf[s2 + 16] = 0x00;
        buf[s2 + 17] = 0x02;
        buf[s2 + 20] = 0x00;
        buf[s2 + 21] = 0x04;
        buf[s2 + 36] = 0x40;
        buf[s2 + 39] = 0xC0; // R+W

        // Themida section at 0x4000, VS=0x3000
        let s3 = s2 + 40;
        buf[s3] = b'T';
        buf[s3 + 1] = b'h';
        buf[s3 + 2] = b'e';
        buf[s3 + 3] = b'm';
        buf[s3 + 4] = b'i';
        buf[s3 + 5] = b'd';
        buf[s3 + 6] = b'a';
        buf[s3 + 8] = 0x00;
        buf[s3 + 9] = 0x30;
        buf[s3 + 12] = 0x00;
        buf[s3 + 13] = 0x40;
        buf[s3 + 16] = 0x00;
        buf[s3 + 17] = 0x02;
        buf[s3 + 20] = 0x00;
        buf[s3 + 21] = 0x06;
        buf[s3 + 36] = 0x20;
        buf[s3 + 39] = 0xE0; // R+W+X

        PeHeader::from_bytes(&buf).unwrap()
    }

    // -- shrink_pe --------------------------------------------------------

    #[test]
    fn shrink_removes_themida_section() {
        let mut pe = make_packed_pe64();
        assert_eq!(pe.sections.len(), 3);
        let count_before = pe.nt_headers.file_header.number_of_sections;

        let removed = shrink_pe(&mut pe).unwrap();
        assert!(removed >= 1, "expected at least one section removed");
        // The Themida section at index 2 should be gone.
        assert!(pe.sections.len() < 3);
        assert!(pe.nt_headers.file_header.number_of_sections < count_before);
    }

    #[test]
    fn shrink_preserves_section_zero() {
        let mut pe = make_packed_pe64();
        let _ = shrink_pe(&mut pe).unwrap();
        // Section 0 must still be .text (or the renamed first section).
        assert!(!pe.sections.is_empty());
        // The first section may have been renamed but should be present.
    }

    #[test]
    fn shrink_on_clean_pe_is_noop() {
        // A PE with no Themida sections: nothing to delete.
        let mut buf = vec![0u8; 512];
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[60] = 0x40;
        let nt = 0x40;
        buf[nt] = 0x50;
        buf[nt + 1] = 0x45;
        let fh = nt + 4;
        buf[fh] = 0x64;
        buf[fh + 1] = 0x86;
        buf[fh + 2] = 1;
        buf[fh + 16] = 0xF0;
        buf[fh + 18] = 0x22;
        let oh = nt + 24;
        buf[oh] = 0x0B;
        buf[oh + 1] = 0x02;
        buf[oh + 16] = 0x00;
        buf[oh + 17] = 0x10;
        buf[oh + 27] = 0x40;
        buf[oh + 28] = 0x01;
        buf[oh + 32] = 0x00;
        buf[oh + 33] = 0x10;
        buf[oh + 36] = 0x00;
        buf[oh + 37] = 0x02;
        buf[oh + 56] = 0x00;
        buf[oh + 57] = 0x20;
        buf[oh + 60] = 0x00;
        buf[oh + 61] = 0x02;
        buf[oh + 108] = 0x10;
        let s1 = nt + 24 + 240;
        buf[s1] = b'.';
        buf[s1 + 1] = b't';
        buf[s1 + 2] = b'e';
        buf[s1 + 3] = b'x';
        buf[s1 + 4] = b't';
        buf[s1 + 8] = 0x00;
        buf[s1 + 9] = 0x10;
        buf[s1 + 12] = 0x00;
        buf[s1 + 13] = 0x10;
        buf[s1 + 16] = 0x00;
        buf[s1 + 17] = 0x02;
        buf[s1 + 20] = 0x00;
        buf[s1 + 21] = 0x02;
        buf[s1 + 36] = 0x20;
        buf[s1 + 39] = 0x60;

        let mut pe = PeHeader::from_bytes(&buf).unwrap();
        let sections_before = pe.sections.len();
        let removed = shrink_pe(&mut pe).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(pe.sections.len(), sections_before);
    }

    // -- find_dyn_tls_x64 -------------------------------------------------

    #[test]
    fn find_dyn_tls_x64_finds_pattern() {
        // Build a minimal text section with the lea rcx, [rip+disp] pattern.
        let mut data = vec![0xCCu8; 0x200];
        // At offset 0x100: lea rcx, [rip + 0x4000]
        // disp = target - (rva + off + 7) ... let's make it simple:
        // instr_rva = 0x1000 (text base) + 0x100 (offset) = 0x1100
        // next_rva = 0x1107
        // target = 0x1107 + disp
        // We want target = 0x5000, so disp = 0x5000 - 0x1107 = 0x3EF9
        let disp: i32 = 0x3EF9;
        data[0x100] = 0x48;
        data[0x101] = 0x8D;
        data[0x102] = 0x0D;
        data[0x103..0x107].copy_from_slice(&disp.to_le_bytes());

        let rva = find_dyn_tls_x64(&data, 0x1000);
        assert_eq!(rva, Some(0x5000));
    }

    #[test]
    fn find_dyn_tls_x64_no_pattern_returns_none() {
        let data = vec![0xCCu8; 0x100]; // all int3 — no lea rcx pattern
        assert_eq!(find_dyn_tls_x64(&data, 0x1000), None);
    }

    // -- DataSectionResult -------------------------------------------------

    #[test]
    fn data_section_result_debug() {
        let r = DataSectionResult {
            rdata_created: true,
            data_created: true,
            rdata_rva: 0x2000,
            data_rva: 0x4000,
            rdata_size: 0x2000,
            data_size: 0x1000,
        };
        let dbg = format!("{:?}", r);
        // Derived Debug uses decimal for numeric fields.
        assert!(dbg.contains("8192")); // 0x2000 in decimal
        assert!(dbg.contains("16384")); // 0x4000 in decimal
    }

    // -- make_section -----------------------------------------------------

    #[test]
    fn make_section_sets_fields() {
        let s = make_section(".testsec", 0x5000, 0x1000, IMAGE_SCN_MEM_READ);
        assert_eq!(s.name, ".testsec");
        assert_eq!(s.virtual_address, 0x5000);
        assert_eq!(s.virtual_size, 0x1000);
        assert_eq!(s.raw_offset, 0x5000);
        assert_eq!(s.raw_size, 0x1000);
        assert_eq!(s.characteristics, IMAGE_SCN_MEM_READ);
    }
}
