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
///
/// **CRITICAL FIX**: Assigns sequential IAT addresses starting from
/// `original_iat_rva` and **stops at the runtime IAT boundary** to avoid
/// overflowing into adjacent sections. Themida removes unused imports at
/// runtime, so the original PE's import table may be larger than the
/// runtime IAT.
pub(crate) fn build_import_table_from_original(
    pe: &PeHeader,
    original_path: &Path,
    original_iat_rva: u32,
) -> Option<ImportTableBuilder> {
    use tracing::{debug, warn};

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

    // Determine runtime IAT size from PE header (set by the unpacker)
    let iat_dir =
        pe.nt_headers.optional_header.data_directory[super::helpers::IMAGE_DIRECTORY_ENTRY_IAT];
    let max_iat_rva = if iat_dir.virtual_address != 0 && iat_dir.size > 0 {
        iat_dir.virtual_address + iat_dir.size
    } else {
        // Fallback: no IAT directory set, use unlimited (old behavior)
        u32::MAX
    };

    debug!(
        "build_import_table_from_original: Runtime IAT boundary at {:#x} (size {:#x})",
        max_iat_rva, iat_dir.size
    );

    let mut builder = ImportTableBuilder::new(true); // 64-bit
    let ptr_size = crate::import_table::iat_slot_size(true) as u32; // 64-bit = 8 bytes
    let mut current_iat_rva = original_iat_rva;
    let mut skipped_funcs = 0;

    for (dll_name, functions) in &imports {
        let mut thunks: Vec<ImportThunk> = Vec::new();

        for func_name in functions {
            // Check if we've reached the IAT boundary
            if current_iat_rva >= max_iat_rva {
                skipped_funcs += 1;
                continue;
            }

            // Parse ordinal imports (#22 format)
            let (function_name, ordinal) = if let Some(ordinal_str) = func_name.strip_prefix('#') {
                (None, ordinal_str.parse::<u16>().ok())
            } else {
                (Some(func_name.clone()), None)
            };

            // CRITICAL FIX: Assign sequential IAT address matching runtime location
            thunks.push(ImportThunk {
                iat_address: current_iat_rva,
                function_name,
                ordinal,
                is_64bit: true,
            });
            current_iat_rva += ptr_size;
        }

        if !thunks.is_empty() {
            let module = builder.add_module(dll_name);
            for t in thunks {
                module.thunks.push(t);
            }
            // Advance past the null terminator for this module
            if current_iat_rva + ptr_size <= max_iat_rva {
                current_iat_rva += ptr_size;
            }
        }
    }

    if skipped_funcs > 0 {
        warn!(
            "build_import_table_from_original: Skipped {} functions beyond IAT boundary ({:#x})",
            skipped_funcs, max_iat_rva
        );
    }

    debug!(
        "build_import_table_from_original: Built table with {} modules, {} thunks (skipped {}), IAT range {:#x}..{:#x}",
        builder.modules.len(),
        builder.thunk_count(),
        skipped_funcs,
        original_iat_rva,
        current_iat_rva
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
        .saturating_mul(crate::import_table::IMPORT_DESCRIPTOR_SIZE)
        // The import directory must cover the null terminator descriptor too.
        // `build_import_section_no_iat` appends a full 20-byte zero descriptor
        // immediately after the last real descriptor. The independent final-PE
        // parser (`parse_final_import_identities`) fails closed when the
        // directory does not reach that terminator ("import descriptor array is
        // not terminated within directory"). Include the terminator so the
        // emitted directory is self-terminating and the loader/parser agree.
        .saturating_add(crate::import_table::IMPORT_DESCRIPTOR_SIZE);
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
///
/// Zero entries are significant module/run terminators and must overwrite
/// any process-local value captured from the live IAT. Leaving a live pointer
/// in the lookup run makes the Windows loader interpret it as a name RVA.
fn write_iat_lookup_to_dump_buf(
    dump_buf: &mut [u8],
    _builder: &ImportTableBuilder,
    import_thunks: &[u64],
    original_iat_rva: u32,
    is_64bit: bool,
) {
    let ptr_size = if is_64bit { 8 } else { 4 };
    let mut written = 0;

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
        written += 1;
    }

    info!(
        iat_rva = format_args!("{original_iat_rva:#x}"),
        written,
        total = import_thunks.len(),
        "Wrote Import Lookup Table to IAT region"
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
///
/// Zero entries are written as terminators so no process-local address can be
/// consumed by the loader as an import lookup RVA.
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

    let mut written = 0usize;
    for (i, &thunk_rva) in import_thunks.iter().enumerate() {
        let off = iat_file_off + i * ptr_size;
        if ptr_size == 8 {
            out_data[off..off + 8].copy_from_slice(&thunk_rva.to_le_bytes());
        } else {
            out_data[off..off + 4].copy_from_slice(&(thunk_rva as u32).to_le_bytes());
        }
        written += 1;
    }

    info!(
        rva = format_args!("{original_iat_rva:#x}"),
        file_off = format_args!("{iat_file_off:#x}"),
        written,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::PeHeader;

    /// Zero terminator slots in `import_thunks` must overwrite stale live pointers.
    #[test]
    fn write_iat_lookup_overwrites_stale_nonzero_with_zero() {
        let mut dump_buf = vec![0u8; 0x40];
        // Pre-seed a live/process-local pointer where the terminator lands.
        let stale: u64 = 0x0000_7FF8_1234_5678;
        dump_buf[0x10..0x18].copy_from_slice(&0x5000u64.to_le_bytes());
        dump_buf[0x18..0x20].copy_from_slice(&stale.to_le_bytes());

        // Slot0 = hint/name RVA, slot1 = terminator 0 (must clear stale).
        let import_thunks = [0x5000u64, 0u64];
        let builder = ImportTableBuilder::new(true);
        write_iat_lookup_to_dump_buf(&mut dump_buf, &builder, &import_thunks, 0x10, true);

        let slot0 = u64::from_le_bytes(dump_buf[0x10..0x18].try_into().unwrap());
        let slot1 = u64::from_le_bytes(dump_buf[0x18..0x20].try_into().unwrap());
        assert_eq!(slot0, 0x5000);
        assert_eq!(slot1, 0, "terminator zero must overwrite live pointer");
    }

    #[test]
    fn write_iat_to_output_overwrites_stale_terminator_slots() {
        // Minimal PE: .text at RVA 0x1000, raw file offset 0x200.
        let mut pe_bytes = crate::header::make_minimal_pe64();
        pe_bytes.resize(0x400, 0);
        let pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");

        let mut out_data = pe_bytes;
        // IAT at RVA 0x1010 → file offset 0x210.
        let iat_rva = 0x1010u32;
        let iat_off = 0x210usize;
        let stale = 0x0000_7FFA_DEAD_BEEFu64;
        out_data[iat_off..iat_off + 8].copy_from_slice(&0x6000u64.to_le_bytes());
        out_data[iat_off + 8..iat_off + 16].copy_from_slice(&stale.to_le_bytes());

        let import_thunks = [0x6000u64, 0u64];
        write_iat_to_output(&mut out_data, &pe, &import_thunks, iat_rva, true);

        let slot0 = u64::from_le_bytes(out_data[iat_off..iat_off + 8].try_into().unwrap());
        let slot1 = u64::from_le_bytes(out_data[iat_off + 8..iat_off + 16].try_into().unwrap());
        assert_eq!(slot0, 0x6000);
        assert_eq!(
            slot1, 0,
            "zero terminator must overwrite stale live pointer"
        );
    }

    #[test]
    fn import_directory_size_covers_null_terminator_descriptor() {
        // P8-C: the import directory must reach the full 20-byte null
        // terminator descriptor appended by build_import_section_no_iat, so the
        // independent final-PE parser (`parse_final_import_identities`) does
        // not report "import descriptor array is not terminated within
        // directory". Regression for the P7-R2 origin candidate (296 resolved +
        // 17 terminator slots, final_imports empty).
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        // Minimal image size so create_section_index can append .import.
        pe.nt_headers.optional_header.size_of_image = 0x6000;

        let mut builder = ImportTableBuilder::new(true);
        builder.add_module("kernel32.dll");
        let thunks = [
            0x2000u32, // resolved slot (dummy IAT address)
            0x2010u32, // second resolved slot
        ];
        let mod_b = builder.modules.last_mut().expect("module");
        for addr in thunks {
            mod_b.thunks.push(ImportThunk {
                iat_address: addr,
                function_name: Some("SomeApi".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }

        let mut dump_buf = vec![0u8; 0x400];
        let _ = create_import_section(&mut pe, &builder, 0x2000, &mut dump_buf, true);

        let dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        let desc_count = builder.emitted_descriptor_count();
        // Directory must cover desc_count real descriptors PLUS the null
        // terminator descriptor (one full 20-byte record).
        let expected = (desc_count + 1) * crate::import_table::IMPORT_DESCRIPTOR_SIZE;
        assert_eq!(
            dir.size as usize, expected,
            "import directory size must include the null terminator descriptor"
        );
        // And the section data written by build_import_section_no_iat really
        // contains a null terminator immediately after the last real descriptor.
        let (section_data, _) = builder.build_import_section_no_iat(dir.virtual_address, 0x2000);
        let term_offset = desc_count * crate::import_table::IMPORT_DESCRIPTOR_SIZE;
        assert!(term_offset + 20 <= section_data.len());
        assert!(
            section_data[term_offset..term_offset + 20]
                .iter()
                .all(|&b| b == 0),
            "section data must append a full null terminator descriptor"
        );
    }

    /// Assemble a full on-disk PE image from a `PeHeader` whose sections carry
    /// `extra_data` (headers + per-section raw payloads at their raw offsets).
    /// `dos_prefix` is the original DOS/e_lfanew stub (bytes before the NT
    /// signature), because `serialize_headers` emits only the NT core.
    fn assemble_image(pe: &PeHeader, dos_prefix: &[u8]) -> Vec<u8> {
        let mut image = pe.serialize_headers().expect("serialize headers");
        let mut out = dos_prefix.to_vec();
        out.extend_from_slice(&image);
        image = out;
        for section in &pe.sections {
            let ptr = section.header.pointer_to_raw_data as usize;
            let raw_sz = section.header.size_of_raw_data as usize;
            let end = ptr.saturating_add(raw_sz);
            if image.len() < end {
                image.resize(end, 0);
            }
            if let Some(data) = &section.extra_data {
                let n = std::cmp::min(data.len(), raw_sz);
                image[ptr..ptr + n].copy_from_slice(&data[..n]);
            }
        }
        image
    }

    #[test]
    fn emission_end_to_end_parse_final_imports_reconstructs_target_set() {
        // P8-C end-to-end: ImportTableBuilder → create_import_section → full
        // on-disk image → parse_final_import_identities must reconstruct the
        // exact target set (module + function per slot). This is the
        // "negative → candidate" proof that reconstruction runs end-to-end and
        // the independent final-PE reader agrees with the emitted table.
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        pe.nt_headers.optional_header.size_of_image = 0x6000;

        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            for (i, name) in ["ExitProcess", "GetProcAddress", "LoadLibraryA"]
                .iter()
                .enumerate()
            {
                m.thunks.push(ImportThunk {
                    iat_address: 0x1100 + (i as u32) * 8, // inside .text (RVA 0x1000..)
                    function_name: Some(name.to_string()),
                    ordinal: None,
                    is_64bit: true,
                });
            }
        }
        {
            let m = builder.add_module("user32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1120,
                function_name: Some("MessageBoxA".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }

        let mut dump_buf = vec![0u8; 0x2000];
        let _ = create_import_section(&mut pe, &builder, 0x1100, &mut dump_buf, true);

        let mut image = assemble_image(&pe, &pe_bytes[..0x40]);
        // Emit the Hint/Name RVAs into the IAT (FirstThunk) region, exactly as
        // the real emission does via write_iat_to_output.
        let (_, thunks) = builder.build_import_section_no_iat(
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .virtual_address,
            0x1100,
        );
        write_iat_to_output(&mut image, &pe, &thunks, 0x1100, true);

        let final_imports = crate::original_imports::parse_final_import_identities(&image)
            .expect("parse final imports");

        // Reconstructed set must equal the builder's target set.
        let expected = builder
            .modules
            .iter()
            .flat_map(|m| {
                m.thunks
                    .iter()
                    .map(|t| (m.name.clone(), t.function_name.clone()))
            })
            .collect::<std::collections::HashSet<_>>();
        let got = final_imports
            .iter()
            .map(|item| (item.module_name.clone(), item.function_name.clone()))
            .collect::<std::collections::HashSet<_>>();

        assert_eq!(
            got, expected,
            "final imports must equal the emitted target set"
        );
        assert_eq!(
            final_imports.len(),
            4,
            "one slot per thunk, no phantom entries"
        );
    }

    #[test]
    fn unresolved_zero_slots_do_not_produce_final_imports() {
        // P8-D: an unresolved IAT slot is emitted as a zero (loader terminator),
        // so the independent final-PE reader must NOT turn it into a final
        // import. Only resolved thunks reconstruct into final imports; the
        // resolved<->final mapping stays one-to-one (gate contract).
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        pe.nt_headers.optional_header.size_of_image = 0x6000;

        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("ResolvedApi".to_string()),
                ordinal: None,
                is_64bit: true,
            });
            // Second slot models an UNRESOLVED import: its IAT entry is written
            // as 0 (loader terminator) in the emitted image.
            m.thunks.push(ImportThunk {
                iat_address: 0x1108,
                function_name: None,
                ordinal: None,
                is_64bit: true,
            });
        }

        let mut dump_buf = vec![0u8; 0x2000];
        let _ = create_import_section(&mut pe, &builder, 0x1100, &mut dump_buf, true);

        let mut image = assemble_image(&pe, &pe_bytes[..0x40]);
        let (_, thunks) = builder.build_import_section_no_iat(
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .virtual_address,
            0x1100,
        );
        // Simulate emission of an unresolved slot as zero: overwrite the second
        // IAT entry with 0 so the parser sees it as a terminator.
        let mut resolved_thunks = thunks;
        if resolved_thunks.len() >= 2 {
            resolved_thunks[1] = 0;
        }
        write_iat_to_output(&mut image, &pe, &resolved_thunks, 0x1100, true);

        let final_imports = crate::original_imports::parse_final_import_identities(&image)
            .expect("parse final imports");
        assert_eq!(
            final_imports.len(),
            1,
            "only the resolved thunk reconstructs into a final import"
        );
        assert_eq!(
            final_imports[0].function_name.as_deref(),
            Some("ResolvedApi")
        );
    }
}
