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
    use crate::original_imports::FinalImportIdentity;

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

    // --- P8.1-A: resolved<->unresolved sequence attacks ---

    /// Emit a full on-disk PE for a builder whose thunks carry explicit IAT
    /// RVAs (possibly leaving sparse gaps), then independently re-read the
    /// final import identities from the serialized bytes.
    fn emit_and_read_final(builder: &ImportTableBuilder) -> (Vec<u8>, Vec<FinalImportIdentity>) {
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        pe.nt_headers.optional_header.size_of_image = 0x6000;

        let mut dump_buf = vec![0u8; 0x2000];
        let _ = create_import_section(&mut pe, builder, 0x1100, &mut dump_buf, true);

        let mut image = assemble_image(&pe, &pe_bytes[..0x40]);
        let (_, thunks) = builder.build_import_section_no_iat(
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .virtual_address,
            0x1100,
        );
        write_iat_to_output(&mut image, &pe, &thunks, 0x1100, true);

        let final_imports = crate::original_imports::parse_final_import_identities(&image)
            .expect("parse final imports");
        (image, final_imports)
    }

    #[test]
    fn resolved_unresolved_resolved_sequence_both_reachable() {
        // P8.1-A #5: Resolved(A) -> Unresolved(gap at 0x1108) -> Resolved(B).
        // The split-into-contiguous-runs emission must NOT let the loader stop
        // at the internal zero and drop B. Independent re-read of the final PE
        // must prove BOTH A and B are reachable final imports.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            // A at 0x1100; the 0x1108 slot is UNRESOLVED (absent, stays zero in
            // the IAT); B at 0x1110.
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("ApiA".to_string()),
                ordinal: None,
                is_64bit: true,
            });
            m.thunks.push(ImportThunk {
                iat_address: 0x1110,
                function_name: Some("ApiB".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }

        let (image, final_imports) = emit_and_read_final(&builder);

        // Both A and B must be independently reachable. A parser that stops at
        // the zero terminator (0x1108) and reports only A would fail this.
        let names: Vec<String> = final_imports
            .iter()
            .filter_map(|item| item.function_name.clone())
            .collect();
        assert!(
            names.contains(&"ApiA".to_string()),
            "ApiA must be reachable, got {names:?}"
        );
        assert!(
            names.contains(&"ApiB".to_string()),
            "ApiB must be reachable after an internal unresolved gap, got {names:?}"
        );
        // Each resolved slot maps to exactly one final import; no phantom.
        let mut slot_rvas: Vec<u32> = final_imports.iter().map(|i| i.slot_rva).collect();
        slot_rvas.sort_unstable();
        assert_eq!(slot_rvas, vec![0x1100, 0x1110], "no phantom, no duplicate");
        assert!(
            !names.contains(&"".to_string()),
            "no blank-name phantom import"
        );
        // The unresolved gap slot itself must carry a zero terminator in the
        // emitted IAT (never a fabricated import).
        let iat_off = pe_section_rva_to_off(&image, 0x1108);
        assert_eq!(
            u64::from_le_bytes(image[iat_off..iat_off + 8].try_into().unwrap()),
            0,
            "unresolved gap slot must be zero, not a fabricated import"
        );
    }

    /// Resolve a raw file offset for an RVA in the assembled image (headers +
    /// minimal sections; only .text at RVA 0x1000/raw 0x200 is used here).
    /// The `image` parameter documents the buffer the RVA is relative to; it is
    /// not read because the minimal fixture has a fixed layout.
    fn pe_section_rva_to_off(_image: &[u8], rva: u32) -> usize {
        // The minimal PE's first section is at RVA 0x1000, raw offset 0x200.
        assert!(rva >= 0x1000);
        0x200 + (rva - 0x1000) as usize
    }

    #[test]
    fn unresolved_at_first_slot_fails_closed_no_phantom() {
        // #6a: unresolved in the FIRST slot. The emitted table must not turn the
        // leading zero into a phantom import; later resolved thunks stay
        // reachable via their own run.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            // 0x1100 unresolved (absent), B at 0x1108 resolved.
            m.thunks.push(ImportThunk {
                iat_address: 0x1108,
                function_name: Some("Only".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let (image, final_imports) = emit_and_read_final(&builder);
        assert_eq!(final_imports.len(), 1, "no phantom from leading unresolved");
        assert_eq!(final_imports[0].slot_rva, 0x1108);
        let iat_off = pe_section_rva_to_off(&image, 0x1100);
        assert_eq!(
            u64::from_le_bytes(image[iat_off..iat_off + 8].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn unresolved_at_last_slot_terminates_run_without_phantom() {
        // #6c: unresolved in the LAST slot. The zero terminator correctly ends
        // the run; no phantom import is produced for it.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("Only".to_string()),
                ordinal: None,
                is_64bit: true,
            });
            // 0x1108 unresolved (absent) is the trailing terminator slot.
        }
        let (image, final_imports) = emit_and_read_final(&builder);
        assert_eq!(final_imports.len(), 1);
        assert_eq!(final_imports[0].slot_rva, 0x1100);
        let iat_off = pe_section_rva_to_off(&image, 0x1108);
        assert_eq!(
            u64::from_le_bytes(image[iat_off..iat_off + 8].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn multiple_consecutive_unresolved_do_not_collapse_following_resolved() {
        // #6d: several consecutive unresolved slots (0x1100,0x1108,0x1110) with
        // a resolved slot after them (0x1118). The resolved slot must remain
        // reachable via its own contiguous run.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1118,
                function_name: Some("Survivor".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let (image, final_imports) = emit_and_read_final(&builder);
        assert_eq!(final_imports.len(), 1);
        assert_eq!(final_imports[0].slot_rva, 0x1118);
        assert_eq!(final_imports[0].function_name.as_deref(), Some("Survivor"));
        for rva in [0x1100u32, 0x1108, 0x1110] {
            let off = pe_section_rva_to_off(&image, rva);
            assert_eq!(
                u64::from_le_bytes(image[off..off + 8].try_into().unwrap()),
                0,
                "unresolved slot RVA {rva:#x} must be zero"
            );
        }
    }

    #[test]
    fn cross_module_unresolved_keeps_both_modules_imports() {
        // #6e: unresolved slots across module boundaries. Each module's resolved
        // thunks remain independently reachable via its own descriptor run.
        // Both thunk RVAs stay inside the minimal .text raw extent (0x1000..
        // 0x1200) so the IAT is raw-backed.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("KApi".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        {
            let m = builder.add_module("user32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1110,
                function_name: Some("UApi".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let (_, final_imports) = emit_and_read_final(&builder);
        let pairs: Vec<(String, String)> = final_imports
            .iter()
            .map(|i| (i.module_name.clone(), i.function_name.clone().unwrap_or_default()))
            .collect();
        assert!(
            pairs.contains(&("kernel32.dll".into(), "KApi".into())),
            "kernel32 import missing: {pairs:?}"
        );
        assert!(
            pairs.contains(&("user32.dll".into(), "UApi".into())),
            "user32 import missing: {pairs:?}"
        );
    }

    #[test]
    fn adjacent_module_runs_without_gap_fail_closed_not_truncated() {
        // P8.1-A #4: when two module runs would share a terminator slot (no gap
        // between them), the emitted IAT is ambiguous — the first run's
        // terminator is claimed by the second module's thunk. The independent
        // reader must FAIL CLOSED (reject the duplicate slot) rather than
        // silently emitting a truncated table that only reaches one module.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("KApi".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        {
            let m = builder.add_module("user32.dll");
            // 0x1108 is immediately after kernel32's thunk: no terminator gap.
            m.thunks.push(ImportThunk {
                iat_address: 0x1108,
                function_name: Some("UApi".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        pe.nt_headers.optional_header.size_of_image = 0x6000;
        let mut dump_buf = vec![0u8; 0x2000];
        let _ = create_import_section(&mut pe, &builder, 0x1100, &mut dump_buf, true);
        let mut image = assemble_image(&pe, &pe_bytes[..0x40]);
        let (_, thunks) = builder.build_import_section_no_iat(
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .virtual_address,
            0x1100,
        );
        write_iat_to_output(&mut image, &pe, &thunks, 0x1100, true);
        let result = crate::original_imports::parse_final_import_identities(&image);
        assert!(
            result.is_err(),
            "ambiguous adjacent runs must fail closed, not truncate to one module"
        );
    }

    #[test]
    fn resolved_name_and_ordinal_mix_emits_exactly_one_identity_each() {
        // #6f: resolved slots mixing name and ordinal imports. Each slot yields
        // exactly one final import identity (name XOR ordinal).
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("ByName".to_string()),
                ordinal: None,
                is_64bit: true,
            });
            m.thunks.push(ImportThunk {
                iat_address: 0x1108,
                function_name: None,
                ordinal: Some(42),
                is_64bit: true,
            });
        }
        let (_, final_imports) = emit_and_read_final(&builder);
        assert_eq!(final_imports.len(), 2);
        let by_name = final_imports
            .iter()
            .find(|i| i.slot_rva == 0x1100)
            .expect("by-name slot");
        assert_eq!(by_name.function_name.as_deref(), Some("ByName"));
        assert_eq!(by_name.ordinal, None);
        let by_ord = final_imports
            .iter()
            .find(|i| i.slot_rva == 0x1108)
            .expect("by-ordinal slot");
        assert_eq!(by_ord.function_name, None);
        assert_eq!(by_ord.ordinal, Some(42));
    }

    #[test]
    fn duplicate_resolved_slot_fails_closed_on_independent_read() {
        // #6g: two resolved thunks claiming the SAME IAT slot must fail closed —
        // the emitted PE cannot hold two identities in one slot. The independent
        // final-PE reader must reject the duplicate-slot table rather than
        // silently emitting a phantom or truncated import set.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("First".to_string()),
                ordinal: None,
                is_64bit: true,
            });
            // Second thunk illegally claims the same slot.
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("Second".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let pe_bytes = crate::header::make_minimal_pe64();
        let mut pe = PeHeader::from_bytes(&pe_bytes).expect("minimal pe");
        pe.nt_headers.optional_header.size_of_image = 0x6000;
        let mut dump_buf = vec![0u8; 0x2000];
        let _ = create_import_section(&mut pe, &builder, 0x1100, &mut dump_buf, true);
        let mut image = assemble_image(&pe, &pe_bytes[..0x40]);
        let (_, thunks) = builder.build_import_section_no_iat(
            pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                .virtual_address,
            0x1100,
        );
        write_iat_to_output(&mut image, &pe, &thunks, 0x1100, true);

        let result = crate::original_imports::parse_final_import_identities(&image);
        assert!(
            result.is_err(),
            "independent reader must fail closed on a duplicate-slot table, got {:?}",
            result
        );
        let err = format!("{}", result.err().unwrap());
        assert!(
            err.contains("duplicate final import slot RVA"),
            "error must name the duplicate slot, got: {err}"
        );
    }

    #[test]
    fn unresolved_reason_unknown_stays_fail_closed() {
        // #6h: an unresolved slot with reason "unknown" must stay fail-closed
        // and must not produce a phantom import or a silently truncated table.
        // This is enforced at the gate/evidence layer (iat_evidence and
        // oreans_gate); the emission layer guarantees an unresolved slot emits a
        // zero terminator and no final import.
        let mut builder = ImportTableBuilder::new(true);
        {
            let m = builder.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0x1100,
                function_name: Some("Known".to_string()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let (image, final_imports) = emit_and_read_final(&builder);
        assert_eq!(final_imports.len(), 1);
        assert_eq!(final_imports[0].function_name.as_deref(), Some("Known"));
        // The trailing unresolved terminator is zero.
        let off = pe_section_rva_to_off(&image, 0x1108);
        assert_eq!(
            u64::from_le_bytes(image[off..off + 8].try_into().unwrap()),
            0
        );
    }
}
