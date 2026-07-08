//! Main dump orchestration — `dump_process` and `dump_dotnet`.
//!
//! Extracted from `dumper.rs` — corresponds to `TDumper.DumpToFile`
//! and `TDumperDotnet.DumpToFile` in `Dumper.pas`.

use std::path::Path;

use tracing::{debug, info, warn};

use crate::error::PeError;
use crate::header::PeHeader;
use crate::import_table::ImportTableBuilder;
use crate::original_imports::{read_original_import_table, resolve_imports_via_getprocaddress};

use super::header_patch::{shrink_sections, validate_and_patch_pe_header};
use super::helpers::{
    make_memory_readable, IMAGE_DIRECTORY_ENTRY_IAT,
};
use super::import_rebuild::rebuild_import_table_complete;
use super::import_section::{
    build_import_table_from_original, create_import_section,
};
use super::output_writer::write_output_file;
use super::sections::{create_pdata_section, create_reloc_section};
use super::types::DumpOptions;

/// Dump a PE image from the target process into a file.
///
/// This is the Rust equivalent of `TDumper.DumpToFile` in `Dumper.pas`.
///
/// # Steps
///
/// 1. Read the PE headers from the target's image base.
/// 2. If `opts.fix_imports` is true, call [`rebuild_import_table`].
/// 3. Sanitize the PE header (`PointerToRawData = VirtualAddress`).
/// 4. Read the entire dump image from the target.
/// 5. Write the image + section data + updated headers to `opts.output_path`.
///
/// # Errors
///
/// Returns [`PeError::Parse`] if the PE headers in the target are corrupt,
/// or [`PeError::Io`] if the output file cannot be written.
pub fn dump_process(
    debugger: &mut dyn mida_core::DebuggerCore,
    opts: &DumpOptions,
) -> Result<(), PeError> {
    // 1. Read PE headers
    let mut header_buf = vec![0u8; 0x1000];
    let read = debugger
        .read_memory(opts.image_base as usize, &mut header_buf)
        .map_err(|e| PeError::Parse(format!("Failed to read PE headers: {e}")))?;
    if read < 0x1000 {
        return Err(PeError::Parse(format!(
            "Short read on PE headers: got {read} bytes, expected 4096"
        )));
    }

    let mut pe = PeHeader::from_bytes(&header_buf)?;

    // 1a. Validate and patch PE header fields
    validate_and_patch_pe_header(&mut pe, opts)?;

    // 1b. Shrink: remove Themida-specific sections if requested.
    let mut saved_exception_rva: Option<(u32, u32)> = None;
    if opts.shrink {
        saved_exception_rva = shrink_sections(&mut pe);
    }

    let is_64bit = pe.is_64bit;

    // 2. Rebuild import table if requested
    let (iat_image, _iat_image_size, mut import_builder) = if opts.fix_imports {
        rebuild_import_table_complete(debugger, &mut pe, opts.image_base, is_64bit, opts.iat_location)?
    } else {
        (Vec::new(), 0usize, None)
    };

    // Determine the original IAT RVA
    let original_iat_rva = if let Some((addr, _)) = opts.iat_location {
        u32::try_from(addr.wrapping_sub(opts.image_base as usize)).unwrap_or(0)
    } else {
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address
    };

    // 2b. Magicmida fallback
    let mut _resolved_imports: std::collections::HashMap<(String, String), usize> = std::collections::HashMap::new();
    if opts.fix_imports {
        let live_empty = import_builder.as_ref().is_none_or(|b| b.thunk_count() == 0);
        if live_empty {
            if let Some(ref ep) = opts.executable_path {
                if let Some(fallback_builder) = build_import_table_from_original(&pe, ep) {
                    info!("Using original PE import table (Magicmida approach): {} modules, {} thunks",
                        fallback_builder.modules.len(), fallback_builder.thunk_count());
                    import_builder = Some(fallback_builder);
                }
            }
        }
    }

    // 2c. Build function-name → resolved address map
    if import_builder.is_some() {
        if let Some(ref builder) = import_builder {
            if !iat_image.is_empty() && original_iat_rva != 0 {
                for m in &builder.modules {
                    for t in &m.thunks {
                        if let Some(ref name) = t.function_name {
                            let slot_offset = (t.iat_address as i64) - (original_iat_rva as i64);
                            if slot_offset >= 0 && (slot_offset as usize) + std::mem::size_of::<usize>() <= iat_image.len() {
                                let addr = usize::from_le_bytes(
                                    iat_image[slot_offset as usize..slot_offset as usize + std::mem::size_of::<usize>()]
                                        .try_into()
                                        .unwrap_or([0u8; std::mem::size_of::<usize>()]),
                                );
                                if addr != 0 {
                                    _resolved_imports.insert((m.name.clone(), name.clone()), addr);
                                }
                            }
                        }
                    }
                }
                info!("Resolved {} API addresses from live IAT image", _resolved_imports.len());
            } else if let Some(ref ep) = opts.executable_path {
                let imports = read_original_import_table(ep);
                _resolved_imports = resolve_imports_via_getprocaddress(&imports);
                info!("Resolved {} API addresses for IAT slots", _resolved_imports.len());
            }
        }
    }

    // 3. Sanitize PE header
    pe.sanitize();

    info!(
        size_of_image = pe.size_of_image(),
        "Dumping process image"
    );

    // 4. Read the full dump image
    let dump_size = pe.size_of_image() as usize;
    let mut dump_buf = vec![0u8; dump_size];
    make_memory_readable(debugger, opts.image_base, dump_size as u64);

    let read = debugger
        .read_memory(opts.image_base as usize, &mut dump_buf)
        .map_err(|e| PeError::Parse(format!("Failed to read dump image: {e}")))?;
    if read < dump_size {
        warn!(expected = dump_size, actual = read, "Short read on dump image");
    }

    // 4b. Create .pdata and .reloc sections
    if opts.shrink {
        if let Some((exc_rva, exc_size)) = saved_exception_rva {
            create_pdata_section(&mut pe, &dump_buf, exc_rva, exc_size);
        }
        create_reloc_section(&mut pe);
    }

    // 5. Build import section
    let mut import_thunks: Vec<u64> = Vec::new();
    if let Some(ref builder) = import_builder {
        let (thunks, _section_idx) = create_import_section(
            &mut pe, builder, original_iat_rva, &mut dump_buf, is_64bit,
        );
        import_thunks = thunks;
    }

    // 5b. Trim huge sections
    let mut iat_raw_addr = 0u32;
    let _delta = pe.trim_huge_sections(&dump_buf, &mut iat_raw_addr);

    // 6. Write output file
    let mut out_data = write_output_file(
        &mut pe, &dump_buf, import_builder.as_ref(), &import_thunks,
        original_iat_rva, is_64bit, opts,
    )?;

    // DEBUG: Verify section 1 characteristics
    debug_section_chars(&out_data, "Before fix_hardcoded_addresses");

    // Fix hardcoded runtime addresses
    crate::postprocess::fix_hardcoded_addresses(&mut out_data, Some(opts.image_base), is_64bit)?;

    debug_section_chars(&out_data, "After fix_hardcoded_addresses");

    // ===超越 Pascal: 文件布局重排===
    if opts.shrink {
        crate::postprocess::pack_section_layout(&mut out_data, &pe)?;
    }

    // ===超越 Pascal: 生成重定位表===
    if opts.shrink {
        crate::postprocess::build_relocation_table(&mut out_data, None, is_64bit)?;
    }

    std::fs::write(&opts.output_path, &out_data)?;

    info!(
        path = %opts.output_path.display(),
        size = out_data.len(),
        sections = pe.sections.len(),
        "Dump written successfully"
    );

    Ok(())
}

/// Debug helper: verify section 1 characteristics in the output buffer.
fn debug_section_chars(out_data: &[u8], label: &str) {
    let sec1_chars_offset = 0x1d4;
    if sec1_chars_offset + 4 <= out_data.len() {
        let chars = u32::from_le_bytes([
            out_data[sec1_chars_offset],
            out_data[sec1_chars_offset + 1],
            out_data[sec1_chars_offset + 2],
            out_data[sec1_chars_offset + 3],
        ]);
        info!("{}: Section 1 chars at {:#x} = {:#x}", label, sec1_chars_offset, chars);
    }
}

// -----------------------------------------------------------------------
// dump_dotnet
// -----------------------------------------------------------------------

/// Dump a .NET assembly from the target process.
///
/// .NET assemblies don't need import table reconstruction — the CLR handles
/// method resolution at runtime.  This simply reads the dump image, trims
/// oversized sections, and writes the output.
///
/// Corresponds to `TDumperDotnet.DumpToFile` in `Dumper.pas`.
pub fn dump_dotnet(
    debugger: &mut dyn mida_core::DebuggerCore,
    image_base: u64,
    entry_point: u32,
    output_path: &Path,
) -> Result<(), PeError> {
    // Read PE headers
    let mut header = vec![0u8; 0x1000];
    let read = debugger
        .read_memory(image_base as usize, &mut header)
        .map_err(|e| PeError::Parse(format!("Failed to read header: {e}")))?;
    if read < 0x1000 {
        return Err(PeError::Parse("Short read on .NET PE header".into()));
    }

    let mut pe = PeHeader::from_bytes(&header)?;

    // Determine dump size from the last section
    let last_idx = pe.sections.len() - 1;
    let dump_size = pe.sections[last_idx].virtual_address + pe.sections[last_idx].virtual_size;

    info!(
        dump_size,
        sections = pe.sections.len(),
        "Dumping .NET assembly"
    );

    // Read the full image
    let dump_size_usize = dump_size as usize;
    let mut buf = vec![0u8; dump_size_usize];
    make_memory_readable(debugger, image_base, dump_size as u64);

    let read = debugger
        .read_memory(image_base as usize, &mut buf)
        .map_err(|e| PeError::Parse(format!("Failed to read .NET image: {e}")))?;

    // Sanitize and write
    pe.sanitize();

    // Rename first section to .text
    if !pe.sections.is_empty() {
        pe.rename_section(0, ".text");
    }

    let mut out_data = Vec::new();
    out_data.extend_from_slice(&buf[..dump_size_usize.min(read)]);

    // Pad to file alignment if needed
    let mut physical_size = dump_size;
    pe.file_align(&mut physical_size);
    if dump_size < physical_size {
        out_data.resize(physical_size as usize, 0);
    }

    // Update size of image
    let mut image_size = physical_size;
    pe.section_align(&mut image_size);
    pe.nt_headers.optional_header.size_of_image = image_size;

    // Update entry point
    let ep_rva = entry_point - image_base as u32;
    pe.nt_headers.optional_header.address_of_entry_point = ep_rva;

    // Write headers
    let header_data = pe.serialize_headers()?;
    out_data.extend_from_slice(&header_data);

    std::fs::write(output_path, &out_data)?;

    info!(
        path = %output_path.display(),
        size = out_data.len(),
        ".NET dump written successfully"
    );

    Ok(())
}
