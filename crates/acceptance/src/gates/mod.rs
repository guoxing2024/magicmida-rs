//! Ordered static structural gates for R0B.

// Every `.unwrap()` in this module is a parse invariant: it follows an
// explicit `in_bounds(off, len, bytes.len())` guard whose failure branch
// returns/breaks first, so the safe u16_le/u32_le/u64_le helpers (None only
// on a short buffer) are unreachable-None at each call site (WO-10). These
// are gate assertions on an already-validated image, not fallible error
// paths.
#![allow(clippy::unwrap_used)]

use crate::pe::read::{in_bounds, u32_le, u64_le};
use crate::pe::view::{
    try_parse, PeImage, IMAGE_DIRECTORY_ENTRY_BASERELOC, IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IAT, IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_TLS, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_RELOCS_STRIPPED,
    IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64, SIZEOF_IMPORT_DESCRIPTOR,
};
use crate::report::{FailureRecord, GateResult, GateStatus, WarningRecord};

struct GateCtx<'a> {
    failures: &'a mut Vec<FailureRecord>,
    warnings: &'a mut Vec<WarningRecord>,
    gates: &'a mut Vec<GateResult>,
}

impl GateCtx<'_> {
    fn fail(&mut self, gate_id: &str, code: &str, message: impl Into<String>) {
        let message = message.into();
        self.failures.push(FailureRecord {
            gate_id: gate_id.to_string(),
            code: code.to_string(),
            message: message.clone(),
        });
        // Update last gate of this id if present, else push fail.
        if let Some(g) = self.gates.iter_mut().rev().find(|g| g.id == gate_id) {
            g.status = GateStatus::Fail;
            g.detail = Some(message);
        }
    }

    fn begin(&mut self, id: &str) {
        self.gates.push(GateResult {
            id: id.to_string(),
            status: GateStatus::Pass,
            detail: None,
        });
    }

    fn warn(&mut self, code: &str, message: impl Into<String>) {
        self.warnings.push(WarningRecord {
            code: code.to_string(),
            message: message.into(),
        });
    }
}

/// Run all structural gates in fixed order. Returns whether parse established a PE view.
pub fn run_all_gates(
    bytes: &[u8],
    gates: &mut Vec<GateResult>,
    failures: &mut Vec<FailureRecord>,
    warnings: &mut Vec<WarningRecord>,
) {
    let mut ctx = GateCtx {
        failures,
        warnings,
        gates,
    };

    // Gate 1: DOS/NT/optional header bounds
    ctx.begin("headers_bounds");
    let image = match try_parse(bytes) {
        Ok(img) => img,
        Err(issue) => {
            ctx.fail("headers_bounds", &issue.code, issue.message);
            // Remaining gates cannot run without a view; mark skip.
            for id in [
                "machine_magic_consistency",
                "sections_ranges",
                "alignment_and_sizes",
                "entry_point",
                "imports_iat",
                "export_directory",
                "tls_directory",
                "reloc_directory",
                "exception_directory",
                "aslr_reloc_consistency",
                "directories_bounds",
            ] {
                ctx.gates.push(GateResult {
                    id: id.to_string(),
                    status: GateStatus::Skip,
                    detail: Some("skipped: PE headers not established".to_string()),
                });
            }
            return;
        }
    };

    // Gate 2: PE32/PE32+ vs machine
    ctx.begin("machine_magic_consistency");
    check_machine_magic(&mut ctx, &image);

    // Gate 3: section ranges / overlap / overflow
    ctx.begin("sections_ranges");
    check_sections(&mut ctx, &image);

    // Gate 4: SizeOfHeaders, SizeOfImage, alignments
    ctx.begin("alignment_and_sizes");
    check_alignment_and_sizes(&mut ctx, &image);

    // Gate 5: entry point
    ctx.begin("entry_point");
    check_entry_point(&mut ctx, &image);

    // Gate 6: imports / IAT
    ctx.begin("imports_iat");
    check_imports_iat(&mut ctx, &image);

    // Gate 7: export
    ctx.begin("export_directory");
    check_export(&mut ctx, &image);

    // Gate 8: TLS
    ctx.begin("tls_directory");
    check_tls(&mut ctx, &image);

    // Gate 9: reloc
    ctx.begin("reloc_directory");
    check_reloc(&mut ctx, &image);

    // Gate 10: exception
    ctx.begin("exception_directory");
    check_exception(&mut ctx, &image);

    // Gate 11: ASLR vs reloc
    ctx.begin("aslr_reloc_consistency");
    check_aslr(&mut ctx, &image);

    // Gate 12: all directories bounds vs image/file
    ctx.begin("directories_bounds");
    check_directories_bounds(&mut ctx, &image);
}

fn check_machine_magic(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let pe32_plus = image.optional.is_pe32_plus;
    let m = image.machine;
    let ok = if pe32_plus {
        m == IMAGE_FILE_MACHINE_AMD64 || m == IMAGE_FILE_MACHINE_ARM64
    } else {
        m == IMAGE_FILE_MACHINE_I386
    };
    if !ok {
        ctx.fail(
            "machine_magic_consistency",
            "machine_magic_mismatch",
            format!(
                "machine 0x{m:04x} inconsistent with {} optional header",
                if pe32_plus { "PE32+" } else { "PE32" }
            ),
        );
    }
}

fn check_sections(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let file_len = image.bytes.len() as u64;
    let mut virt_ranges: Vec<(u64, u64, usize)> = Vec::new();
    let mut raw_ranges: Vec<(u64, u64, usize)> = Vec::new();

    for (i, s) in image.sections.iter().enumerate() {
        let va = s.virtual_address as u64;
        let vext = s.virtual_extent();
        if let Some(vend) = va.checked_add(vext) {
            if vext > 0 {
                virt_ranges.push((va, vend, i));
            }
        } else {
            ctx.fail(
                "sections_ranges",
                "section_va_overflow",
                format!("section {i}: virtual address/size overflow"),
            );
        }

        if s.size_of_raw_data > 0 {
            let ptr = s.pointer_to_raw_data as u64;
            let raw = s.size_of_raw_data as u64;
            match ptr.checked_add(raw) {
                None => {
                    ctx.fail(
                        "sections_ranges",
                        "section_raw_overflow",
                        format!("section {i}: raw pointer/size overflow"),
                    );
                }
                Some(rend) => {
                    if rend > file_len {
                        ctx.fail(
                            "sections_ranges",
                            "section_raw_oob",
                            format!(
                                "section {i}: raw range 0x{ptr:x}+0x{raw:x} exceeds file size 0x{file_len:x}"
                            ),
                        );
                    } else {
                        raw_ranges.push((ptr, rend, i));
                    }
                }
            }
            // PointerToRawData must be file-aligned when non-zero (checked in alignment gate too)
        }
    }

    // Virtual overlap (allow adjacent)
    virt_ranges.sort_by_key(|r| r.0);
    for w in virt_ranges.windows(2) {
        let (a0, a1, i) = w[0];
        let (b0, _b1, j) = w[1];
        if b0 < a1 {
            ctx.fail(
                "sections_ranges",
                "section_va_overlap",
                format!(
                    "sections {i} and {j} overlap in virtual space ([0x{a0:x},0x{a1:x}) vs start 0x{b0:x})"
                ),
            );
        }
    }

    // Raw overlap
    raw_ranges.sort_by_key(|r| r.0);
    for w in raw_ranges.windows(2) {
        let (a0, a1, i) = w[0];
        let (b0, _b1, j) = w[1];
        if b0 < a1 {
            ctx.fail(
                "sections_ranges",
                "section_raw_overlap",
                format!(
                    "sections {i} and {j} overlap in file raw space ([0x{a0:x},0x{a1:x}) vs start 0x{b0:x})"
                ),
            );
        }
    }
}

fn is_power_of_two(v: u32) -> bool {
    v != 0 && (v & (v - 1)) == 0
}

fn check_alignment_and_sizes(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let fa = image.optional.file_alignment;
    let sa = image.optional.section_alignment;
    let soh = image.optional.size_of_headers;
    let soi = image.optional.size_of_image;
    let file_len = image.bytes.len() as u64;

    if fa == 0 || !is_power_of_two(fa) {
        ctx.fail(
            "alignment_and_sizes",
            "file_alignment_invalid",
            format!("FileAlignment 0x{fa:x} is not a non-zero power of two"),
        );
    }
    if sa == 0 || !is_power_of_two(sa) {
        ctx.fail(
            "alignment_and_sizes",
            "section_alignment_invalid",
            format!("SectionAlignment 0x{sa:x} is not a non-zero power of two"),
        );
    }
    if sa != 0 && fa != 0 && sa < fa {
        ctx.fail(
            "alignment_and_sizes",
            "section_lt_file_alignment",
            format!("SectionAlignment 0x{sa:x} < FileAlignment 0x{fa:x}"),
        );
    }

    if soh == 0 {
        ctx.fail(
            "alignment_and_sizes",
            "size_of_headers_zero",
            "SizeOfHeaders is zero",
        );
    } else if soh as u64 > file_len {
        ctx.fail(
            "alignment_and_sizes",
            "size_of_headers_oob",
            format!("SizeOfHeaders 0x{soh:x} exceeds file size 0x{file_len:x}"),
        );
    }

    // SizeOfHeaders must cover section table end
    let headers_end =
        (image.section_table_offset as u64).saturating_add((image.number_of_sections as u64) * 40);
    if (soh as u64) < headers_end {
        ctx.fail(
            "alignment_and_sizes",
            "size_of_headers_short",
            format!(
                "SizeOfHeaders 0x{soh:x} does not cover section table ending at 0x{headers_end:x}"
            ),
        );
    }

    if soi == 0 {
        ctx.fail(
            "alignment_and_sizes",
            "size_of_image_zero",
            "SizeOfImage is zero",
        );
    }

    // SizeOfImage should be >= max section virtual end, section-aligned
    let mut max_vend: u64 = soh as u64;
    for s in &image.sections {
        let vend = (s.virtual_address as u64).saturating_add(s.virtual_extent());
        if vend > max_vend {
            max_vend = vend;
        }
    }
    if sa != 0 {
        let aligned = align_up(max_vend, sa as u64);
        if (soi as u64) < aligned {
            ctx.fail(
                "alignment_and_sizes",
                "size_of_image_too_small",
                format!("SizeOfImage 0x{soi:x} < aligned section end 0x{aligned:x}"),
            );
        }
    }

    // Section raw pointers file-aligned when non-zero
    if fa != 0 {
        for (i, s) in image.sections.iter().enumerate() {
            if s.pointer_to_raw_data != 0 && (s.pointer_to_raw_data % fa) != 0 {
                ctx.fail(
                    "alignment_and_sizes",
                    "section_raw_ptr_unaligned",
                    format!(
                        "section {i}: PointerToRawData 0x{:x} not FileAlignment 0x{fa:x}",
                        s.pointer_to_raw_data
                    ),
                );
            }
            if s.virtual_address != 0 && sa != 0 && (s.virtual_address % sa) != 0 {
                ctx.fail(
                    "alignment_and_sizes",
                    "section_va_unaligned",
                    format!(
                        "section {i}: VirtualAddress 0x{:x} not SectionAlignment 0x{sa:x}",
                        s.virtual_address
                    ),
                );
            }
        }
    }
}

fn align_up(v: u64, align: u64) -> u64 {
    if align == 0 {
        return v;
    }
    let rem = v % align;
    if rem == 0 {
        v
    } else {
        v + (align - rem)
    }
}

fn check_entry_point(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let ep = image.optional.address_of_entry_point;
    if ep == 0 {
        // Valid for some DLLs; warn but pass for EXE candidates we still require executable section
        ctx.warn("entry_point_zero", "AddressOfEntryPoint is zero");
        return;
    }
    if ep >= image.optional.size_of_image {
        ctx.fail(
            "entry_point",
            "entry_point_outside_image",
            format!(
                "AddressOfEntryPoint 0x{ep:x} >= SizeOfImage 0x{:x}",
                image.optional.size_of_image
            ),
        );
        return;
    }

    let mut found = false;
    for (i, s) in image.sections.iter().enumerate() {
        let va = s.virtual_address;
        let vend = va.saturating_add(s.virtual_extent() as u32);
        if ep >= va && ep < vend {
            found = true;
            if !s.is_executable() {
                ctx.fail(
                    "entry_point",
                    "entry_point_not_executable",
                    format!("entry point 0x{ep:x} in section {i} without execute/code flags"),
                );
            }
            // Must have raw backing at EP
            if s.pointer_to_raw_data == 0 || s.size_of_raw_data == 0 {
                ctx.fail(
                    "entry_point",
                    "entry_point_no_raw_backing",
                    format!("entry point 0x{ep:x} in section {i} without raw data"),
                );
            } else {
                let delta = ep - va;
                if delta >= s.size_of_raw_data {
                    ctx.fail(
                        "entry_point",
                        "entry_point_beyond_raw",
                        format!("entry point 0x{ep:x} is past SizeOfRawData of section {i}"),
                    );
                } else {
                    let off = (s.pointer_to_raw_data as u64) + delta as u64;
                    if off >= image.bytes.len() as u64 {
                        ctx.fail(
                            "entry_point",
                            "entry_point_raw_oob",
                            format!("entry point raw offset 0x{off:x} past file end"),
                        );
                    }
                }
            }
            break;
        }
    }
    if !found {
        // EP in headers?
        if ep < image.optional.size_of_headers {
            ctx.fail(
                "entry_point",
                "entry_point_in_headers",
                format!("entry point 0x{ep:x} lies in headers, not an executable section"),
            );
        } else {
            ctx.fail(
                "entry_point",
                "entry_point_no_section",
                format!("entry point 0x{ep:x} not inside any section"),
            );
        }
    }
}

fn check_imports_iat(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let Some(dir) = image.directory(IMAGE_DIRECTORY_ENTRY_IMPORT) else {
        return;
    };
    if dir.virtual_address == 0 || dir.size == 0 {
        // empty import dir is ok
        check_iat_dir_only(ctx, image);
        return;
    }
    if !image.directory_in_image(dir.virtual_address, dir.size) {
        ctx.fail(
            "imports_iat",
            "import_dir_image_oob",
            format!(
                "import directory RVA 0x{:x} size 0x{:x} outside SizeOfImage",
                dir.virtual_address, dir.size
            ),
        );
        return;
    }
    if !image.directory_has_raw_backing(dir.virtual_address, dir.size) {
        ctx.fail(
            "imports_iat",
            "import_dir_no_raw",
            "import directory lacks raw file backing",
        );
        return;
    }

    let mut desc_rva = dir.virtual_address;
    let dir_end = dir.virtual_address.saturating_add(dir.size);
    let mut count = 0u32;
    loop {
        if desc_rva.saturating_add(SIZEOF_IMPORT_DESCRIPTOR as u32) > dir_end && count > 0 {
            // allow last read if null terminator partially — still need full descriptor
        }
        let Some(off) = image.rva_to_offset(desc_rva) else {
            ctx.fail(
                "imports_iat",
                "import_desc_unmapped",
                format!("import descriptor at RVA 0x{desc_rva:x} not mapped"),
            );
            break;
        };
        if !in_bounds(
            off as u64,
            SIZEOF_IMPORT_DESCRIPTOR as u64,
            image.bytes.len() as u64,
        ) {
            ctx.fail(
                "imports_iat",
                "import_desc_oob",
                format!("import descriptor at file 0x{off:x} truncated"),
            );
            break;
        }
        let original_first_thunk = u32_le(image.bytes, off).unwrap();
        let name_rva = u32_le(image.bytes, off + 12).unwrap();
        let first_thunk = u32_le(image.bytes, off + 16).unwrap();
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break; // null terminator
        }
        count += 1;
        if count > 4096 {
            ctx.fail(
                "imports_iat",
                "import_desc_runaway",
                "import descriptor list exceeded 4096 entries without null terminator",
            );
            break;
        }

        if name_rva != 0 {
            if image.rva_to_offset(name_rva).is_none() {
                ctx.fail(
                    "imports_iat",
                    "import_name_unmapped",
                    format!("DLL name RVA 0x{name_rva:x} not mapped"),
                );
            } else if let Some(noff) = image.rva_to_offset(name_rva) {
                // require at least one byte and scan for NUL within reasonable bound
                if !read_c_string_ok(image.bytes, noff, 512) {
                    ctx.fail(
                        "imports_iat",
                        "import_name_truncated",
                        format!("DLL name at RVA 0x{name_rva:x} truncated or non-terminated"),
                    );
                }
            }
        }

        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        if thunk_rva != 0 {
            check_thunk_chain(ctx, image, thunk_rva);
        }
        if first_thunk != 0 && first_thunk != thunk_rva {
            check_thunk_chain(ctx, image, first_thunk);
        }

        match desc_rva.checked_add(SIZEOF_IMPORT_DESCRIPTOR as u32) {
            Some(n) => desc_rva = n,
            None => {
                ctx.fail(
                    "imports_iat",
                    "import_desc_rva_overflow",
                    "import descriptor RVA overflow",
                );
                break;
            }
        }
    }

    check_iat_dir_only(ctx, image);
}

fn check_iat_dir_only(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let Some(dir) = image.directory(IMAGE_DIRECTORY_ENTRY_IAT) else {
        return;
    };
    if dir.virtual_address == 0 || dir.size == 0 {
        return;
    }
    if !image.directory_in_image(dir.virtual_address, dir.size) {
        ctx.fail(
            "imports_iat",
            "iat_dir_image_oob",
            format!(
                "IAT directory RVA 0x{:x} size 0x{:x} outside SizeOfImage",
                dir.virtual_address, dir.size
            ),
        );
        return;
    }
    if !image.directory_has_raw_backing(dir.virtual_address, dir.size) {
        ctx.fail(
            "imports_iat",
            "iat_dir_no_raw",
            "IAT directory lacks raw file backing",
        );
    }
}

fn check_thunk_chain(ctx: &mut GateCtx<'_>, image: &PeImage<'_>, mut thunk_rva: u32) {
    let entry_size: u32 = if image.optional.is_pe32_plus { 8 } else { 4 };
    for _ in 0..65536 {
        let Some(off) = image.rva_to_offset(thunk_rva) else {
            ctx.fail(
                "imports_iat",
                "thunk_unmapped",
                format!("thunk RVA 0x{thunk_rva:x} not mapped"),
            );
            return;
        };
        if !in_bounds(off as u64, entry_size as u64, image.bytes.len() as u64) {
            ctx.fail(
                "imports_iat",
                "thunk_oob",
                format!("thunk at file 0x{off:x} truncated"),
            );
            return;
        }
        if image.optional.is_pe32_plus {
            let v = u64_le(image.bytes, off).unwrap();
            if v == 0 {
                return;
            }
            if v & IMAGE_ORDINAL_FLAG64 == 0 {
                let hint_rva = (v & 0x7FFF_FFFF) as u32;
                check_import_by_name(ctx, image, hint_rva);
            }
        } else {
            let v = u32_le(image.bytes, off).unwrap();
            if v == 0 {
                return;
            }
            if v & IMAGE_ORDINAL_FLAG32 == 0 {
                check_import_by_name(ctx, image, v);
            }
        }
        match thunk_rva.checked_add(entry_size) {
            Some(n) => thunk_rva = n,
            None => {
                ctx.fail("imports_iat", "thunk_rva_overflow", "thunk RVA overflow");
                return;
            }
        }
    }
    ctx.fail(
        "imports_iat",
        "thunk_runaway",
        "thunk chain exceeded 65536 entries without null terminator",
    );
}

fn check_import_by_name(ctx: &mut GateCtx<'_>, image: &PeImage<'_>, rva: u32) {
    let Some(off) = image.rva_to_offset(rva) else {
        ctx.fail(
            "imports_iat",
            "import_by_name_unmapped",
            format!("IMAGE_IMPORT_BY_NAME RVA 0x{rva:x} not mapped"),
        );
        return;
    };
    // Hint (2) + name
    if !in_bounds(off as u64, 3, image.bytes.len() as u64) {
        ctx.fail(
            "imports_iat",
            "import_by_name_oob",
            format!("IMAGE_IMPORT_BY_NAME at 0x{off:x} truncated"),
        );
        return;
    }
    if !read_c_string_ok(image.bytes, off + 2, 512) {
        ctx.fail(
            "imports_iat",
            "import_by_name_truncated",
            format!("import name at RVA 0x{rva:x} truncated"),
        );
    }
}

fn read_c_string_ok(bytes: &[u8], off: usize, max: usize) -> bool {
    if off >= bytes.len() {
        return false;
    }
    let end = (off + max).min(bytes.len());
    bytes[off..end].contains(&0)
}

fn check_export(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let Some(dir) = image.directory(IMAGE_DIRECTORY_ENTRY_EXPORT) else {
        return;
    };
    if dir.virtual_address == 0 || dir.size == 0 {
        return;
    }
    if !image.directory_in_image(dir.virtual_address, dir.size) {
        ctx.fail(
            "export_directory",
            "export_image_oob",
            "export directory outside SizeOfImage",
        );
        return;
    }
    if !image.directory_has_raw_backing(dir.virtual_address, dir.size.min(40)) {
        ctx.fail(
            "export_directory",
            "export_no_raw",
            "export directory lacks raw file backing",
        );
        return;
    }
    // IMAGE_EXPORT_DIRECTORY is 40 bytes
    let Some(off) = image.rva_to_offset(dir.virtual_address) else {
        ctx.fail(
            "export_directory",
            "export_unmapped",
            "export directory RVA not mapped",
        );
        return;
    };
    if !in_bounds(off as u64, 40, image.bytes.len() as u64) {
        ctx.fail(
            "export_directory",
            "export_truncated",
            "export directory truncated",
        );
        return;
    }
    let num_functions = u32_le(image.bytes, off + 20).unwrap();
    let num_names = u32_le(image.bytes, off + 24).unwrap();
    let addr_of_functions = u32_le(image.bytes, off + 28).unwrap();
    let addr_of_names = u32_le(image.bytes, off + 32).unwrap();
    let addr_of_ordinals = u32_le(image.bytes, off + 36).unwrap();

    if num_functions > 0 {
        let bytes_needed = (num_functions as u64).saturating_mul(4);
        if bytes_needed > 16 * 1024 * 1024 {
            ctx.fail(
                "export_directory",
                "export_functions_unreasonable",
                format!("NumberOfFunctions {num_functions} unreasonable"),
            );
        } else if let Some(foff) = image.rva_to_offset(addr_of_functions) {
            if !in_bounds(foff as u64, bytes_needed, image.bytes.len() as u64) {
                ctx.fail(
                    "export_directory",
                    "export_functions_oob",
                    "AddressOfFunctions table exceeds file bounds",
                );
            }
        } else if addr_of_functions != 0 {
            ctx.fail(
                "export_directory",
                "export_functions_unmapped",
                "AddressOfFunctions not mapped",
            );
        }
    }
    if num_names > 0 {
        let name_bytes = (num_names as u64).saturating_mul(4);
        let ord_bytes = (num_names as u64).saturating_mul(2);
        if let Some(noff) = image.rva_to_offset(addr_of_names) {
            if !in_bounds(noff as u64, name_bytes, image.bytes.len() as u64) {
                ctx.fail(
                    "export_directory",
                    "export_names_oob",
                    "AddressOfNames table exceeds file bounds",
                );
            }
        } else if addr_of_names != 0 {
            ctx.fail(
                "export_directory",
                "export_names_unmapped",
                "AddressOfNames not mapped",
            );
        }
        if let Some(ooff) = image.rva_to_offset(addr_of_ordinals) {
            if !in_bounds(ooff as u64, ord_bytes, image.bytes.len() as u64) {
                ctx.fail(
                    "export_directory",
                    "export_ordinals_oob",
                    "AddressOfNameOrdinals table exceeds file bounds",
                );
            }
        } else if addr_of_ordinals != 0 {
            ctx.fail(
                "export_directory",
                "export_ordinals_unmapped",
                "AddressOfNameOrdinals not mapped",
            );
        }
    }
}

fn check_tls(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let Some(dir) = image.directory(IMAGE_DIRECTORY_ENTRY_TLS) else {
        return;
    };
    if dir.virtual_address == 0 || dir.size == 0 {
        return;
    }
    if !image.directory_in_image(dir.virtual_address, dir.size) {
        ctx.fail(
            "tls_directory",
            "tls_image_oob",
            "TLS directory outside SizeOfImage",
        );
        return;
    }
    let need = if image.optional.is_pe32_plus {
        40u32
    } else {
        24u32
    };
    if dir.size < need {
        ctx.fail(
            "tls_directory",
            "tls_truncated_size",
            format!("TLS directory size 0x{:x} < minimum 0x{need:x}", dir.size),
        );
        return;
    }
    if !image.directory_has_raw_backing(dir.virtual_address, need) {
        ctx.fail(
            "tls_directory",
            "tls_no_raw",
            "TLS directory lacks raw file backing",
        );
        return;
    }
    let Some(off) = image.rva_to_offset(dir.virtual_address) else {
        ctx.fail(
            "tls_directory",
            "tls_unmapped",
            "TLS directory RVA not mapped",
        );
        return;
    };
    if !in_bounds(off as u64, need as u64, image.bytes.len() as u64) {
        ctx.fail(
            "tls_directory",
            "tls_file_truncated",
            "TLS directory truncated in file",
        );
    }
}

fn check_reloc(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let Some(dir) = image.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) else {
        return;
    };
    if dir.virtual_address == 0 || dir.size == 0 {
        return;
    }
    if !image.directory_in_image(dir.virtual_address, dir.size) {
        ctx.fail(
            "reloc_directory",
            "reloc_image_oob",
            "base reloc directory outside SizeOfImage",
        );
        return;
    }
    if !image.directory_has_raw_backing(dir.virtual_address, dir.size) {
        ctx.fail(
            "reloc_directory",
            "reloc_no_raw",
            "base reloc directory lacks raw file backing",
        );
        return;
    }
    let Some(mut off) = image.rva_to_offset(dir.virtual_address) else {
        ctx.fail(
            "reloc_directory",
            "reloc_unmapped",
            "base reloc directory RVA not mapped",
        );
        return;
    };
    let mut remaining = dir.size as usize;
    while remaining >= 8 {
        if !in_bounds(off as u64, 8, image.bytes.len() as u64) {
            ctx.fail(
                "reloc_directory",
                "reloc_block_oob",
                "reloc block header exceeds file bounds",
            );
            return;
        }
        let _page_rva = u32_le(image.bytes, off).unwrap();
        let block_size = u32_le(image.bytes, off + 4).unwrap() as usize;
        if block_size < 8 {
            ctx.fail(
                "reloc_directory",
                "reloc_block_size_invalid",
                format!("reloc block size {block_size} < 8"),
            );
            return;
        }
        if block_size > remaining {
            ctx.fail(
                "reloc_directory",
                "reloc_block_overrun",
                format!("reloc block size {block_size} exceeds remaining directory {remaining}"),
            );
            return;
        }
        if !in_bounds(off as u64, block_size as u64, image.bytes.len() as u64) {
            ctx.fail(
                "reloc_directory",
                "reloc_block_file_oob",
                "reloc block exceeds file bounds",
            );
            return;
        }
        // entries are u16
        let entries_bytes = block_size - 8;
        if !entries_bytes.is_multiple_of(2) {
            ctx.fail(
                "reloc_directory",
                "reloc_entries_odd",
                "reloc block entry region size is odd",
            );
            return;
        }
        off += block_size;
        remaining -= block_size;
    }
    if remaining != 0 {
        ctx.fail(
            "reloc_directory",
            "reloc_trailing_bytes",
            format!("reloc directory has {remaining} trailing bytes after last block"),
        );
    }
}

fn check_exception(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let Some(dir) = image.directory(IMAGE_DIRECTORY_ENTRY_EXCEPTION) else {
        return;
    };
    if dir.virtual_address == 0 || dir.size == 0 {
        return;
    }
    if !image.directory_in_image(dir.virtual_address, dir.size) {
        ctx.fail(
            "exception_directory",
            "exception_image_oob",
            "exception directory outside SizeOfImage",
        );
        return;
    }
    // PE32+ RUNTIME_FUNCTION is 12 bytes; PE32 rarely uses this directory the same way
    if image.optional.is_pe32_plus && dir.size % 12 != 0 {
        ctx.fail(
            "exception_directory",
            "exception_size_alignment",
            format!(
                "exception directory size 0x{:x} not multiple of 12",
                dir.size
            ),
        );
    }
    if !image.directory_has_raw_backing(dir.virtual_address, dir.size) {
        ctx.fail(
            "exception_directory",
            "exception_no_raw",
            "exception directory lacks raw file backing",
        );
        return;
    }
    if image.rva_to_offset(dir.virtual_address).is_none() {
        ctx.fail(
            "exception_directory",
            "exception_unmapped",
            "exception directory RVA not mapped",
        );
    }
}

fn check_aslr(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    let dynamic = (image.optional.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
    let stripped = (image.characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0;
    let reloc = image
        .directory(IMAGE_DIRECTORY_ENTRY_BASERELOC)
        .map(|d| d.virtual_address != 0 && d.size != 0)
        .unwrap_or(false);

    if dynamic && stripped {
        ctx.fail(
            "aslr_reloc_consistency",
            "dynamic_base_with_relocs_stripped",
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE set but IMAGE_FILE_RELOCS_STRIPPED is set",
        );
    }
    if dynamic && !reloc {
        ctx.fail(
            "aslr_reloc_consistency",
            "dynamic_base_without_relocs",
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE set but base relocation directory is empty",
        );
    }
    if stripped && reloc {
        ctx.fail(
            "aslr_reloc_consistency",
            "relocs_stripped_but_present",
            "IMAGE_FILE_RELOCS_STRIPPED set but base relocation directory is present",
        );
    }
}

fn check_directories_bounds(ctx: &mut GateCtx<'_>, image: &PeImage<'_>) {
    for (i, d) in image.optional.data_directories.iter().enumerate() {
        if d.virtual_address == 0 && d.size == 0 {
            continue;
        }
        if d.size != 0
            && (d.virtual_address as u64)
                .checked_add(d.size as u64)
                .is_none()
        {
            ctx.fail(
                "directories_bounds",
                "directory_rva_size_overflow",
                format!("data directory {i}: RVA+size overflow"),
            );
            continue;
        }
        if !image.directory_in_image(d.virtual_address, d.size) {
            ctx.fail(
                "directories_bounds",
                "directory_past_image",
                format!(
                    "data directory {i}: RVA 0x{:x} size 0x{:x} exceeds SizeOfImage 0x{:x}",
                    d.virtual_address, d.size, image.optional.size_of_image
                ),
            );
            continue;
        }
        // If size > 0, start must map when directory claims content in file-backed image regions
        if d.size > 0
            && d.virtual_address >= image.optional.size_of_headers
            && image.rva_to_offset(d.virtual_address).is_none()
        {
            ctx.fail(
                "directories_bounds",
                "directory_start_unmapped",
                format!(
                    "data directory {i}: start RVA 0x{:x} has no file mapping",
                    d.virtual_address
                ),
            );
        }
    }
}
