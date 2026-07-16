//! Import section creation and IAT writing.
//!
//! Extracted from `dump_process` in `dumper.rs`.

use std::path::Path;

use tracing::{debug, info};

use crate::header::PeHeader;
use crate::import_table::{ImportTableBuilder, ImportThunk};

use super::helpers::{
    section_rva_to_file_offset, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT,
};
use super::types::DumpOptions;

/// Build an import table from the original PE file's .idata section.
///
/// This is the Magicmida fallback: when the runtime IAT is encrypted,
/// read DLL and function names from the original file and resolve them
/// using GetProcAddress in the debugger process.
pub(crate) fn build_import_table_from_original(
    _pe: &PeHeader,
    original_path: &Path,
) -> Option<ImportTableBuilder> {
    use tracing::debug;

    debug!("build_import_table_from_original: START");

    // Read import table structure (we don't need RVAs - output PE will have different layout)
    let imports = crate::original_imports::read_original_import_table(original_path);

    debug!(
        "build_import_table_from_original: Got {} DLLs",
        imports.len()
    );

    if imports.is_empty() {
        return None;
    }

    let mut builder = ImportTableBuilder::new(true); // 64-bit

    for (dll_name, functions) in &imports {
        let mut thunks: Vec<ImportThunk> = Vec::new();

        for func_name in functions {
            // Parse ordinal imports (#22 format)
            let (function_name, ordinal) = if let Some(ordinal_str) = func_name.strip_prefix('#') {
                (None, ordinal_str.parse::<u16>().ok())
            } else {
                (Some(func_name.clone()), None)
            };

            // Set iat_address to 0 - build_import_section_no_iat will assign sequential addresses
            thunks.push(ImportThunk {
                iat_address: 0,
                function_name,
                ordinal,
                is_64bit: true,
            });
        }

        if !thunks.is_empty() {
            let module = builder.add_module(dll_name);
            for t in thunks {
                module.thunks.push(t);
            }
        }
    }

    debug!(
        "build_import_table_from_original: Built table with {} modules, {} thunks",
        builder.modules.len(),
        builder.thunk_count()
    );

    Some(builder)
}

/// Write resolved API addresses into the IAT slots of the .import section.
///
/// This makes the import table "load-ready" - the PE loader won't need to
/// resolve API addresses because they're already filled in.
#[allow(dead_code)]
pub(crate) fn write_resolved_addresses_to_iat(
    section_data: &mut [u8],
    _section_va: u32,
    builder: &ImportTableBuilder,
    resolved: &std::collections::HashMap<(String, String), usize>,
) {
    let ptr_size = std::mem::size_of::<usize>();

    // Compute layout offsets (same as build_import_section_no_iat)
    let iat_slots_offset: usize = {
        let desc_count = builder.modules.len() + 1;
        let desc_size: u32 = desc_count as u32 * 20;
        let dll_names_size: u32 = builder
            .modules
            .iter()
            .map(|m| m.name.len() as u32 + 1)
            .sum();
        let hint_names_size: u32 = builder
            .modules
            .iter()
            .map(|m| {
                m.thunks
                    .iter()
                    .map(|t| {
                        t.function_name
                            .as_ref()
                            .map(|n| 2 + n.len() as u32 + 1)
                            .unwrap_or(0)
                    })
                    .sum::<u32>()
            })
            .sum();
        (desc_size + dll_names_size + hint_names_size) as usize
    };

    let mut iat_offset = iat_slots_offset;

    for m in &builder.modules {
        for t in &m.thunks {
            if iat_offset + ptr_size <= section_data.len() {
                let key = (m.name.clone(), t.function_name.clone().unwrap_or_default());
                if let Some(&addr) = resolved.get(&key) {
                    let addr_bytes = addr.to_le_bytes();
                    section_data[iat_offset..iat_offset + ptr_size].copy_from_slice(&addr_bytes);
                }
                iat_offset += ptr_size;
            }
        }
        // Skip null terminator
        iat_offset += ptr_size;
    }
}

/// Create the .import section, write IAT lookup values, and set data
/// directory entries.
///
/// Returns the list of import thunk RVAs (for later IAT writes) and the
/// section index.
pub(crate) fn create_import_section(
    pe: &mut PeHeader,
    builder: &ImportTableBuilder,
    original_iat_rva: u32,
    dump_buf: &mut [u8],
    is_64bit: bool,
) -> (Vec<u64>, Option<usize>) {
    let section_size_init = 3400u32;
    let section_idx = pe.create_section_index(".import", section_size_init);

    debug!(
        "[create_section_index] section_idx={}: va={:#x} vs={:#x} ptr={:#x} raw_sz={:#x}",
        section_idx,
        pe.sections[section_idx].header.virtual_address,
        pe.sections[section_idx].header.virtual_size,
        pe.sections[section_idx].header.pointer_to_raw_data,
        pe.sections[section_idx].header.size_of_raw_data
    );
    let section_va = pe.sections[section_idx].virtual_address;
    debug!("[import_builder] local section_va={:#x}", section_va);

    let (section_data, thunks) = builder.build_import_section_no_iat(section_va, original_iat_rva);
    let import_thunks = thunks;

    let section_data_len = section_data.len();
    let file_align = {
        let mut fa = pe.nt_headers.optional_header.file_alignment;
        if !fa.is_power_of_two() || fa < 0x200 {
            fa = 0x200;
        }
        fa
    };
    let raw_size = std::cmp::max(
        crate::utils::align_up(section_data_len as u32, file_align),
        0x2000,
    );
    pe.sections[section_idx].virtual_size = raw_size;
    pe.sections[section_idx].header.virtual_size = raw_size;
    pe.sections[section_idx].header.size_of_raw_data = raw_size;
    let new_section_end = pe.sections[section_idx].header.virtual_address
        + pe.sections[section_idx].header.virtual_size;
    let section_align = pe.nt_headers.optional_header.section_alignment;
    let aligned_end = crate::utils::align_up(new_section_end, section_align);
    if pe.nt_headers.optional_header.size_of_image < new_section_end {
        pe.nt_headers.optional_header.size_of_image = aligned_end;
    }
    let mut padded_section_data = section_data;
    if (padded_section_data.len() as u32) < raw_size {
        padded_section_data.resize(raw_size as usize, 0);
    }
    pe.sections[section_idx].extra_data = Some(padded_section_data);

    let import_dir_size = builder
        .emitted_descriptor_count()
        .saturating_mul(crate::import_table::IMPORT_DESCRIPTOR_SIZE);
    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT] =
        crate::header::ImageDataDirectory {
            virtual_address: section_va,
            size: import_dir_size as u32,
        };
    debug!(
        "[import_data_dir] post-set IMPORT data_dir: va={:#x} sz={:#x}",
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address,
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].size
    );

    // Write Import Lookup Table (Hint/Name RVAs) to the original IAT region.
    write_iat_lookup_to_dump_buf(
        dump_buf,
        builder,
        &import_thunks,
        original_iat_rva,
        is_64bit,
    );

    let lookup_iat_rva = original_iat_rva;
    let ptr_size = std::mem::size_of::<usize>();
    let max_iat_rva = compute_max_iat_rva(builder, original_iat_rva, ptr_size as u32);
    let lookup_iat_size_bytes = (max_iat_rva - original_iat_rva) as usize + ptr_size;

    pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT] =
        crate::header::ImageDataDirectory {
            virtual_address: lookup_iat_rva,
            size: lookup_iat_size_bytes as u32,
        };

    info!(
        "Set IAT Directory to: RVA={:#x} size={:#x}",
        lookup_iat_rva, lookup_iat_size_bytes
    );

    info!(
        section_va = format_args!("{section_va:#x}"),
        section_data_len = section_data_len,
        modules = builder.modules.len(),
        thunks = builder.thunk_count(),
        "Created .import section",
    );
    debug!(
        "[import_section] FINAL import section: va={:#x} vs={:#x} sz={:#x} ptr={:#x} data_dir_import[va={:#x} sz={:#x}]",
        pe.sections[section_idx].header.virtual_address,
        pe.sections[section_idx].header.virtual_size,
        pe.sections[section_idx].header.size_of_raw_data,
        pe.sections[section_idx].header.pointer_to_raw_data,
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].virtual_address,
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT].size
    );

    (import_thunks, Some(section_idx))
}

/// Write Hint/Name RVAs into the dump buffer at each thunk's IAT address.
fn write_iat_lookup_to_dump_buf(
    dump_buf: &mut [u8],
    _builder: &ImportTableBuilder,
    import_thunks: &[u64],
    original_iat_rva: u32,
    is_64bit: bool,
) {
    let ptr_size = if is_64bit { 8 } else { 4 };
    for (index, &value) in import_thunks.iter().enumerate() {
        let offset = original_iat_rva as usize + index * ptr_size;
        if offset + ptr_size > dump_buf.len() {
            break;
        }
        if is_64bit {
            dump_buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        } else {
            dump_buf[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
    }

    info!(
        iat_rva = format_args!("{original_iat_rva:#x}"),
        thunks = import_thunks.len(),
        "Writing Import Lookup Table to IAT region"
    );
}

/// Compute the highest IAT RVA used by any thunk in the builder.
fn compute_max_iat_rva(builder: &ImportTableBuilder, original_iat_rva: u32, ptr_size: u32) -> u32 {
    let mut max_iat_rva = original_iat_rva;
    for module in &builder.modules {
        let mut module_max = original_iat_rva;
        for thunk in &module.thunks {
            if thunk.iat_address > max_iat_rva {
                max_iat_rva = thunk.iat_address;
            }
            if thunk.iat_address > module_max {
                module_max = thunk.iat_address;
            }
        }
        // Account for null terminator
        let null_rva = module_max + ptr_size;
        if null_rva > max_iat_rva {
            max_iat_rva = null_rva;
        }
    }
    max_iat_rva
}

/// Write Hint/Name RVAs to the FirstThunk (IAT) location in the output file.
pub(crate) fn write_iat_to_output(
    out_data: &mut Vec<u8>,
    pe: &PeHeader,
    import_thunks: &[u64],
    original_iat_rva: u32,
    is_64bit: bool,
) {
    if import_thunks.is_empty() || original_iat_rva == 0 {
        return;
    }

    let iat_file_off = section_rva_to_file_offset(&pe.sections, original_iat_rva);
    let ptr_size = if is_64bit { 8 } else { 4 };
    let copy_size = import_thunks.len() * ptr_size;
    let end = iat_file_off + copy_size;
    if end > out_data.len() {
        out_data.resize(end, 0);
    }

    for (i, &thunk_rva) in import_thunks.iter().enumerate() {
        let off = iat_file_off + i * ptr_size;
        if ptr_size == 8 {
            out_data[off..off + 8].copy_from_slice(&thunk_rva.to_le_bytes());
        } else {
            out_data[off..off + 4].copy_from_slice(&(thunk_rva as u32).to_le_bytes());
        }
    }

    info!(
        rva = format_args!("{original_iat_rva:#x}"),
        file_off = format_args!("{iat_file_off:#x}"),
        count = import_thunks.len(),
        "Wrote Hint/Name RVAs to IAT (FirstThunk) for loader resolution"
    );
}

/// Fill additional IAT locations with the same Hint/Name RVAs (dual IAT fix).
pub(crate) fn fill_additional_iat_locations(
    out_data: &mut Vec<u8>,
    pe: &PeHeader,
    opts: &DumpOptions,
    import_thunks: &[u64],
    is_64bit: bool,
) {
    if opts.additional_iat_locations.is_empty() || import_thunks.is_empty() {
        return;
    }

    let ptr_size = if is_64bit { 8 } else { 4 };
    let mut filled_count = 0;

    for &iat_va in &opts.additional_iat_locations {
        let iat_rva = (iat_va as u64).saturating_sub(opts.image_base) as u32;
        let iat_file_off = section_rva_to_file_offset(&pe.sections, iat_rva);

        let copy_size = import_thunks.len() * ptr_size;
        let end = iat_file_off + copy_size;

        if end <= out_data.len() {
            for (i, &thunk_rva) in import_thunks.iter().enumerate() {
                let off = iat_file_off + i * ptr_size;
                if ptr_size == 8 {
                    out_data[off..off + 8].copy_from_slice(&thunk_rva.to_le_bytes());
                } else {
                    out_data[off..off + 4].copy_from_slice(&(thunk_rva as u32).to_le_bytes());
                }
            }
            filled_count += 1;
        }
    }

    if filled_count > 0 {
        info!(
            "Filled {} additional IAT locations with Hint/Name RVAs (dual IAT fix)",
            filled_count
        );
    }
}
