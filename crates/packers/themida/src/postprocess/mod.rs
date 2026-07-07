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

mod anti_dump;
mod data_sections;
mod helpers;

use tracing::{debug, info};

use mida_core::DebuggerCore;
use mida_pe::PeHeader;

use crate::error::ThemidaError;
use crate::iat::CompilerHint;
use crate::version::is_themida_section;

pub use data_sections::DataSectionResult;

// ---------------------------------------------------------------------------
// Section characteristics constants
// ---------------------------------------------------------------------------

pub(super) const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
pub(super) const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
pub(super) const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;

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
            is_themida_section(section) && !helpers::is_referenced_by_data_directory(pe, section)
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

    helpers::recalc_size_of_image(pe);

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
            data_sections::create_data_sections_msvc(pe, text_section_data, text_section_rva)
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
    output_path: &std::path::Path,
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
        anti_dump::install_anti_dump_fix_x64(debugger, oep, image_base, virtual_protect_addr, vm_entry)
    } else {
        anti_dump::install_anti_dump_fix_x86(debugger, oep, image_base, virtual_protect_addr, vm_entry)
    }
}
