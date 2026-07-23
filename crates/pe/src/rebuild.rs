//! Pure PE image rebuild: typed model + rebuild plan → PE bytes.
//!
//! R1-C foundation for producing loader-oriented candidates offline. This module
//! accepts only byte buffers and typed PE values. It must not call Win32, touch a
//! live process, or encode packer-family policy.
//!
//! Downstream (R1-D / R2 / R3) may feed live dumps as memory maps into a
//! [`RebuildPlan`]; acceptance still judges the emitted bytes independently.

use crate::error::PeError;
use crate::exception_table::ExceptionTableBuilder;
use crate::export_table::ExportTableBuilder;
use crate::header::{
    ImageDataDirectory, ImageDosHeader, ImageFileHeader, ImageNtHeaders, ImageOptionalHeader,
    ImageSectionHeader, PeHeader, PeSection,
};
use crate::import_table::ImportTableBuilder;
use crate::relocation::RelocationTableBuilder;
use crate::tls::TlsDirectoryBuilder;
use crate::utils::align_up;

const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;
const PE32_MAGIC: u16 = 0x10B;
const PE32_PLUS_MAGIC: u16 = 0x20B;
const DEFAULT_E_LFANEW: u32 = 0x80;
const DEFAULT_FILE_ALIGNMENT: u32 = 0x200;
const DEFAULT_SECTION_ALIGNMENT: u32 = 0x1000;

/// Data-directory indices used by the rebuild pipeline.
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_EXCEPTION: usize = 3;
pub const DIR_SECURITY: usize = 4;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_DEBUG: usize = 6;
pub const DIR_TLS: usize = 9;
pub const DIR_LOAD_CONFIG: usize = 10;
pub const DIR_IAT: usize = 12;

/// One section payload in a rebuild plan.
#[derive(Debug, Clone)]
pub struct PlannedSection {
    /// Section name (truncated/padded to 8 bytes on emit).
    pub name: String,
    /// `IMAGE_SCN_*` characteristics.
    pub characteristics: u32,
    /// Virtual size; if zero, uses `data.len()` (at least 1 when empty).
    pub virtual_size: u32,
    /// Raw section bytes (truncated or zero-padded to file alignment on emit).
    pub data: Vec<u8>,
    /// Optional fixed section RVA. When set, rebuild places the section at this
    /// VA instead of packing sequentially (R1-E host-dump / content-directory
    /// parity). Must be section-aligned and non-overlapping.
    pub virtual_address: Option<u32>,
}

impl PlannedSection {
    /// Convenience constructor for a named section with raw bytes.
    #[must_use]
    pub fn new(name: impl Into<String>, characteristics: u32, data: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            characteristics,
            virtual_size: 0,
            data,
            virtual_address: None,
        }
    }

    /// Content section with an explicit host/map RVA (preserves directory targets).
    #[must_use]
    pub fn with_rva(
        name: impl Into<String>,
        characteristics: u32,
        virtual_address: u32,
        virtual_size: u32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            name: name.into(),
            characteristics,
            virtual_size,
            data,
            virtual_address: Some(virtual_address),
        }
    }
}

/// Pure rebuild plan: buffers + typed PE values only.
#[derive(Debug, Clone)]
pub struct RebuildPlan {
    pub is_64bit: bool,
    pub image_base: u64,
    /// Entry point RVA in the final image (must land in an executable section).
    pub entry_point_rva: u32,
    pub file_alignment: u32,
    pub section_alignment: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub file_characteristics: u16,
    /// Content sections in VA order (export / import / exception / tls / reloc may
    /// be appended).
    pub sections: Vec<PlannedSection>,
    /// Optional export table emitted as `.edata`.
    pub exports: Option<ExportTableBuilder>,
    /// Optional import table emitted as its own section (`.idata`).
    pub imports: Option<ImportTableBuilder>,
    /// Optional exception / `.pdata` RUNTIME_FUNCTION table.
    pub exceptions: Option<ExceptionTableBuilder>,
    /// Optional TLS directory emitted as `.tls`.
    pub tls: Option<TlsDirectoryBuilder>,
    /// Explicit relocations as `(rva, IMAGE_REL_BASED_*)` for the final layout.
    pub relocations: Vec<(u32, u16)>,
    /// When true and `relocations` is non-empty, set `DYNAMIC_BASE` if not already set.
    pub prefer_aslr: bool,
    /// Host/content-carried data directories applied when typed builders did not
    /// own that index (still zero after typed emit). R1-E: preserves import/IAT/
    /// TLS/export directories that point into content sections with fixed VAs.
    pub fallback_data_directories: Option<[ImageDataDirectory; 16]>,
}

impl Default for RebuildPlan {
    fn default() -> Self {
        Self {
            is_64bit: true,
            image_base: 0x0000_0140_0000_0000,
            entry_point_rva: DEFAULT_SECTION_ALIGNMENT,
            file_alignment: DEFAULT_FILE_ALIGNMENT,
            section_alignment: DEFAULT_SECTION_ALIGNMENT,
            subsystem: 3, // IMAGE_SUBSYSTEM_WINDOWS_CUI
            dll_characteristics: 0,
            file_characteristics: 0x0022, // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
            sections: Vec::new(),
            exports: None,
            imports: None,
            exceptions: None,
            tls: None,
            relocations: Vec::new(),
            prefer_aslr: false,
            fallback_data_directories: None,
        }
    }
}

impl RebuildPlan {
    /// Minimal PE32 plan defaults (caller still supplies at least one section).
    #[must_use]
    pub fn pe32() -> Self {
        Self {
            is_64bit: false,
            image_base: 0x0040_0000,
            file_characteristics: 0x0102, // EXECUTABLE_IMAGE | 32BIT_MACHINE
            ..Self::default()
        }
    }

    /// Minimal PE32+ plan defaults.
    #[must_use]
    pub fn pe32_plus() -> Self {
        Self::default()
    }
}

/// Result metadata useful for tests and adapters (not an acceptance verdict).
#[derive(Debug, Clone)]
pub struct RebuildResult {
    pub image: Vec<u8>,
    pub size_of_headers: u32,
    pub size_of_image: u32,
    pub export_directory: ImageDataDirectory,
    pub import_directory: ImageDataDirectory,
    pub iat_directory: ImageDataDirectory,
    pub exception_directory: ImageDataDirectory,
    pub tls_directory: ImageDataDirectory,
    pub basereloc_directory: ImageDataDirectory,
}

/// Emit a complete PE image from a pure rebuild plan.
///
/// Pipeline:
/// 1. materialize optional export / import / exception / tls / reloc sections as
///    pure buffers;
/// 2. assign section VA / raw layout with checked alignment math;
/// 3. populate a [`PeHeader`] model and splice `serialize_headers` at `e_lfanew`;
/// 4. write section payloads at raw offsets.
pub fn rebuild_pe_image(plan: &RebuildPlan) -> Result<Vec<u8>, PeError> {
    Ok(rebuild_pe_image_with_meta(plan)?.image)
}

/// Same as [`rebuild_pe_image`] but also returns directory layout metadata.
pub fn rebuild_pe_image_with_meta(plan: &RebuildPlan) -> Result<RebuildResult, PeError> {
    let fa = nonzero_align(plan.file_alignment, DEFAULT_FILE_ALIGNMENT);
    let sa = nonzero_align(plan.section_alignment, DEFAULT_SECTION_ALIGNMENT);
    if sa < fa {
        return Err(PeError::Parse(
            "section_alignment must be >= file_alignment".into(),
        ));
    }

    let content = plan.sections.clone();
    let has_exports = plan
        .exports
        .as_ref()
        .is_some_and(|b| b.function_count() > 0);
    let has_imports = plan.imports.as_ref().is_some_and(|b| b.module_count() > 0);
    let has_exceptions = plan
        .exceptions
        .as_ref()
        .is_some_and(|b| b.function_count() > 0);
    let has_tls = plan.tls.is_some();
    let has_relocs = !plan.relocations.is_empty();

    if content.is_empty() && !has_exports && !has_imports && !has_exceptions && !has_tls {
        return Err(PeError::Parse(
            "rebuild plan needs at least one section or export/import/exception/tls".into(),
        ));
    }

    if let Some(tls) = plan.tls.as_ref() {
        if tls.is_64bit != plan.is_64bit {
            return Err(PeError::Parse(
                "tls builder is_64bit must match rebuild plan".into(),
            ));
        }
    }
    if let Some(imports) = plan.imports.as_ref() {
        if has_imports && imports.is_64bit != plan.is_64bit {
            return Err(PeError::Parse(
                "import builder is_64bit must match rebuild plan".into(),
            ));
        }
    }
    if let Some(exceptions) = plan.exceptions.as_ref() {
        if has_exceptions {
            exceptions.validate()?;
        }
    }

    let e_lfanew = DEFAULT_E_LFANEW;
    let opt_size: usize = if plan.is_64bit { 0xF0 } else { 0xE0 };

    // Pre-count sections so header size is correct before assigning raw pointers.
    let section_count = content.len()
        + usize::from(has_exports)
        + usize::from(has_imports)
        + usize::from(has_exceptions)
        + usize::from(has_tls)
        + usize::from(has_relocs);
    if section_count == 0 {
        return Err(PeError::Parse("rebuild produced zero sections".into()));
    }
    if section_count > u16::MAX as usize {
        return Err(PeError::InvalidSectionCount(section_count as u32));
    }

    let nt_core = 4usize + 20 + opt_size + section_count * 40;
    let headers_end = (e_lfanew as usize)
        .checked_add(nt_core)
        .ok_or_else(|| PeError::Parse("headers end overflow".into()))?;
    let size_of_headers = align_up(
        u32::try_from(headers_end).map_err(|_| PeError::Parse("headers end too large".into()))?,
        fa,
    );

    // Assign VAs for content sections first (directories need target VAs).
    // Fixed `virtual_address` preserves host dump layout (R1-E); None packs.
    let mut next_va = sa;
    let mut laid_out: Vec<LaidSection> = Vec::with_capacity(section_count);
    for sec in &content {
        let vsize = effective_virtual_size(sec);
        let raw_size = align_up(sec.data.len() as u32, fa);
        let va = match sec.virtual_address {
            Some(fixed) => {
                if fixed < sa {
                    return Err(PeError::Parse(format!(
                        "fixed section VA {:#x} is below section alignment {:#x}",
                        fixed, sa
                    )));
                }
                if fixed % sa != 0 {
                    return Err(PeError::Parse(format!(
                        "fixed section VA {:#x} is not section-aligned ({:#x})",
                        fixed, sa
                    )));
                }
                if fixed < next_va {
                    // Allow exact placement into a gap only if it does not overlap
                    // a previously laid section.
                    for prev in &laid_out {
                        let prev_end = prev
                            .virtual_address
                            .checked_add(prev.virtual_size.max(1))
                            .ok_or_else(|| PeError::Parse("section VA overflow".into()))?;
                        let this_end = fixed
                            .checked_add(vsize.max(1))
                            .ok_or_else(|| PeError::Parse("section VA overflow".into()))?;
                        let overlaps = fixed < prev_end && this_end > prev.virtual_address;
                        if overlaps {
                            return Err(PeError::Parse(format!(
                                "fixed section VA {:#x} overlaps previous section at {:#x}",
                                fixed, prev.virtual_address
                            )));
                        }
                    }
                    fixed
                } else {
                    fixed
                }
            }
            None => next_va,
        };
        laid_out.push(LaidSection {
            name: sec.name.clone(),
            characteristics: sec.characteristics,
            virtual_address: va,
            virtual_size: vsize,
            raw_size,
            raw_offset: 0,
            data: sec.data.clone(),
        });
        let end = va
            .checked_add(vsize.max(1))
            .ok_or_else(|| PeError::Parse("section VA overflow".into()))?;
        let aligned_end = align_up(end, sa);
        if aligned_end > next_va {
            next_va = aligned_end;
        }
    }

    let mut export_directory = ImageDataDirectory::default();
    if has_exports {
        let builder = plan.exports.as_ref().expect("exports checked");
        let export_va = next_va;
        let (export_data, export_size) = builder.build_section_data(export_va)?;
        export_directory = ImageDataDirectory {
            virtual_address: export_va,
            size: export_size,
        };
        let vsize = export_data.len() as u32;
        let raw_size = align_up(vsize.max(1), fa);
        laid_out.push(LaidSection {
            name: ".edata".into(),
            characteristics: 0x4000_0040, // CNT_INITIALIZED_DATA | MEM_READ
            virtual_address: export_va,
            virtual_size: vsize.max(1),
            raw_size,
            raw_offset: 0,
            data: export_data,
        });
        next_va = align_up(
            export_va
                .checked_add(vsize.max(1))
                .ok_or_else(|| PeError::Parse("export VA overflow".into()))?,
            sa,
        );
    }

    let mut import_directory = ImageDataDirectory::default();
    let mut iat_directory = ImageDataDirectory::default();
    if has_imports {
        let builder = plan.imports.as_ref().expect("imports checked");
        let import_va = next_va;
        let (import_data, _strings_off, iat_off) = builder.build_section_data(import_va);
        let desc_size = (builder.module_count() + 1) * crate::import_table::IMPORT_DESCRIPTOR_SIZE;
        import_directory = ImageDataDirectory {
            virtual_address: import_va,
            size: desc_size as u32,
        };
        // IAT is the contiguous FirstThunk region only (ILT follows in the same section).
        let ptr_size = crate::import_table::iat_slot_size(builder.is_64bit);
        let iat_only: usize = builder
            .modules
            .iter()
            .map(|m| (m.thunks.len() + 1) * ptr_size)
            .sum();
        iat_directory = ImageDataDirectory {
            virtual_address: import_va.saturating_add(iat_off),
            size: iat_only as u32,
        };
        let vsize = import_data.len() as u32;
        let raw_size = align_up(vsize, fa);
        laid_out.push(LaidSection {
            name: ".idata".into(),
            characteristics: 0xC000_0040, // CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
            virtual_address: import_va,
            virtual_size: vsize.max(1),
            raw_size,
            raw_offset: 0,
            data: import_data,
        });
        next_va = align_up(
            import_va
                .checked_add(vsize.max(1))
                .ok_or_else(|| PeError::Parse("import VA overflow".into()))?,
            sa,
        );
    }

    let mut exception_directory = ImageDataDirectory::default();
    if has_exceptions {
        let builder = plan.exceptions.as_ref().expect("exceptions checked");
        let exception_va = next_va;
        let (exception_data, dir_size) = builder.build_section_data(exception_va)?;
        exception_directory = ImageDataDirectory {
            virtual_address: exception_va,
            size: dir_size,
        };
        let vsize = exception_data.len() as u32;
        let raw_size = align_up(vsize.max(1), fa);
        laid_out.push(LaidSection {
            name: ".pdata".into(),
            characteristics: 0x4000_0040, // CNT_INITIALIZED_DATA | MEM_READ
            virtual_address: exception_va,
            virtual_size: vsize.max(1),
            raw_size,
            raw_offset: 0,
            data: exception_data,
        });
        next_va = align_up(
            exception_va
                .checked_add(vsize.max(1))
                .ok_or_else(|| PeError::Parse("exception VA overflow".into()))?,
            sa,
        );
    }

    let mut tls_directory = ImageDataDirectory::default();
    if has_tls {
        let builder = plan.tls.as_ref().expect("tls checked");
        let tls_va = next_va;
        let (tls_data, dir_size) = builder.build_section_data(tls_va, plan.image_base)?;
        tls_directory = ImageDataDirectory {
            virtual_address: tls_va,
            size: dir_size,
        };
        let vsize = tls_data.len() as u32;
        let raw_size = align_up(vsize.max(1), fa);
        laid_out.push(LaidSection {
            name: ".tls".into(),
            characteristics: 0xC000_0040, // CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
            virtual_address: tls_va,
            virtual_size: vsize.max(1),
            raw_size,
            raw_offset: 0,
            data: tls_data,
        });
        next_va = align_up(
            tls_va
                .checked_add(vsize.max(1))
                .ok_or_else(|| PeError::Parse("tls VA overflow".into()))?,
            sa,
        );
    }

    let mut basereloc_directory = ImageDataDirectory::default();
    if has_relocs {
        let mut rb = RelocationTableBuilder::new(
            plan.image_base,
            // provisional; reloc builder only uses image_base for scan_and_add
            next_va.saturating_add(sa),
        );
        for &(rva, typ) in &plan.relocations {
            rb.add_relocation(rva, typ);
        }
        let reloc_data = rb.build();
        let reloc_va = next_va;
        let vsize = reloc_data.len() as u32;
        let raw_size = align_up(vsize.max(1), fa);
        basereloc_directory = ImageDataDirectory {
            virtual_address: reloc_va,
            size: vsize.max(1),
        };
        laid_out.push(LaidSection {
            name: ".reloc".into(),
            characteristics: 0x4200_0040, // CNT_INITIALIZED_DATA | MEM_DISCARDABLE | MEM_READ
            virtual_address: reloc_va,
            virtual_size: vsize.max(1),
            raw_size,
            raw_offset: 0,
            data: reloc_data,
        });
        next_va = align_up(
            reloc_va
                .checked_add(vsize.max(1))
                .ok_or_else(|| PeError::Parse("reloc VA overflow".into()))?,
            sa,
        );
    }

    let size_of_image = next_va;
    if size_of_image == 0 {
        return Err(PeError::Parse("size_of_image is zero".into()));
    }

    // Assign raw file offsets.
    let mut next_raw = size_of_headers;
    for sec in &mut laid_out {
        sec.raw_offset = next_raw;
        next_raw = next_raw
            .checked_add(sec.raw_size)
            .ok_or_else(|| PeError::Parse("raw offset overflow".into()))?;
    }
    let file_size = next_raw as usize;

    // Build PeHeader model for serialize_headers.
    let mut pe = synthesize_pe_header(plan, e_lfanew, fa, sa, size_of_headers, size_of_image)?;
    pe.sections = laid_out.iter().map(|s| pe_section_from_laid(s)).collect();
    pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;
    pe.entry_point = plan.entry_point_rva;
    pe.nt_headers.optional_header.address_of_entry_point = plan.entry_point_rva;
    pe.nt_headers.optional_header.base_of_code =
        pe.sections.first().map(|s| s.virtual_address).unwrap_or(sa);

    if has_exports {
        pe.nt_headers.optional_header.data_directory[DIR_EXPORT] = export_directory;
    }
    if has_imports {
        pe.nt_headers.optional_header.data_directory[DIR_IMPORT] = import_directory;
        pe.nt_headers.optional_header.data_directory[DIR_IAT] = iat_directory;
    }
    if has_exceptions {
        pe.nt_headers.optional_header.data_directory[DIR_EXCEPTION] = exception_directory;
    }
    if has_tls {
        pe.nt_headers.optional_header.data_directory[DIR_TLS] = tls_directory;
    }
    if has_relocs {
        pe.nt_headers.optional_header.data_directory[DIR_BASERELOC] = basereloc_directory;
        if plan.prefer_aslr {
            pe.nt_headers.optional_header.dll_characteristics |= 0x0040; // DYNAMIC_BASE
        }
    }

    // R1-E: apply host/content directories only where typed rebuild left zeros.
    if let Some(fallback) = plan.fallback_data_directories {
        for (i, dd) in fallback.iter().enumerate() {
            if pe.nt_headers.optional_header.data_directory[i].virtual_address == 0
                && dd.virtual_address != 0
            {
                pe.nt_headers.optional_header.data_directory[i] = *dd;
            }
        }
        // Reflect fallback into meta for directories not owned by typed builders.
        if export_directory.virtual_address == 0 {
            export_directory = pe.nt_headers.optional_header.data_directory[DIR_EXPORT];
        }
        if import_directory.virtual_address == 0 {
            import_directory = pe.nt_headers.optional_header.data_directory[DIR_IMPORT];
        }
        if iat_directory.virtual_address == 0 {
            iat_directory = pe.nt_headers.optional_header.data_directory[DIR_IAT];
        }
        if exception_directory.virtual_address == 0 {
            exception_directory = pe.nt_headers.optional_header.data_directory[DIR_EXCEPTION];
        }
        if tls_directory.virtual_address == 0 {
            tls_directory = pe.nt_headers.optional_header.data_directory[DIR_TLS];
        }
        if basereloc_directory.virtual_address == 0 {
            basereloc_directory = pe.nt_headers.optional_header.data_directory[DIR_BASERELOC];
        }
    }

    let mut nt_blob = pe.serialize_headers()?;
    // Drop legacy 0x200 pad; full-image layout owns header padding via size_of_headers.
    let nt_core_len = 4 + 20 + opt_size + pe.sections.len() * 40;
    if nt_blob.len() < nt_core_len {
        return Err(PeError::Parse(
            "serialize_headers shorter than NT core".into(),
        ));
    }
    nt_blob.truncate(nt_core_len);

    let mut out = vec![0u8; file_size];
    // DOS stub (minimal)
    out[0] = b'M';
    out[1] = b'Z';
    out[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());

    let nt_off = e_lfanew as usize;
    if nt_off
        .checked_add(nt_blob.len())
        .is_none_or(|end| end > out.len())
    {
        return Err(PeError::Parse("NT headers do not fit in image".into()));
    }
    out[nt_off..nt_off + nt_blob.len()].copy_from_slice(&nt_blob);

    for sec in &laid_out {
        let raw_off = sec.raw_offset as usize;
        let copy_len = sec.data.len().min(sec.raw_size as usize);
        let end = raw_off
            .checked_add(copy_len)
            .ok_or_else(|| PeError::Parse("section copy overflow".into()))?;
        if end > out.len() {
            return Err(PeError::Parse("section raw extends past file".into()));
        }
        out[raw_off..raw_off + copy_len].copy_from_slice(&sec.data[..copy_len]);
    }

    // Round-trip sanity: pure parse must accept the bytes we just built.
    let _check = PeHeader::from_bytes(&out)?;

    Ok(RebuildResult {
        image: out,
        size_of_headers,
        size_of_image,
        export_directory,
        import_directory,
        iat_directory,
        exception_directory,
        tls_directory,
        basereloc_directory,
    })
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct LaidSection {
    name: String,
    characteristics: u32,
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_offset: u32,
    data: Vec<u8>,
}

fn effective_virtual_size(sec: &PlannedSection) -> u32 {
    if sec.virtual_size > 0 {
        sec.virtual_size
    } else {
        (sec.data.len() as u32).max(1)
    }
}

fn nonzero_align(value: u32, fallback: u32) -> u32 {
    if value == 0 {
        fallback
    } else {
        value
    }
}

fn section_name_bytes(name: &str) -> [u8; 8] {
    let mut out = [0u8; 8];
    let bytes = name.as_bytes();
    let n = bytes.len().min(8);
    out[..n].copy_from_slice(&bytes[..n]);
    out
}

fn pe_section_from_laid(s: &LaidSection) -> PeSection {
    let name_bytes = section_name_bytes(&s.name);
    PeSection {
        header: ImageSectionHeader {
            name: name_bytes,
            virtual_size: s.virtual_size,
            virtual_address: s.virtual_address,
            size_of_raw_data: s.raw_size,
            pointer_to_raw_data: s.raw_offset,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: s.characteristics,
        },
        name: s.name.clone(),
        virtual_address: s.virtual_address,
        virtual_size: s.virtual_size,
        raw_offset: s.raw_offset,
        raw_size: s.raw_size,
        characteristics: s.characteristics,
        extra_data: None,
    }
}

fn synthesize_pe_header(
    plan: &RebuildPlan,
    e_lfanew: u32,
    fa: u32,
    sa: u32,
    size_of_headers: u32,
    size_of_image: u32,
) -> Result<PeHeader, PeError> {
    let (magic, machine, opt_size, default_chars) = if plan.is_64bit {
        (PE32_PLUS_MAGIC, 0x8664u16, 0xF0u16, 0x0022u16)
    } else {
        (PE32_MAGIC, 0x014Cu16, 0xE0u16, 0x0102u16)
    };
    let file_chars = if plan.file_characteristics == 0 {
        default_chars
    } else {
        plan.file_characteristics
    };

    let optional = ImageOptionalHeader {
        magic,
        major_linker_version: 14,
        minor_linker_version: 0,
        size_of_code: 0,
        size_of_initialized_data: 0,
        size_of_uninitialized_data: 0,
        address_of_entry_point: plan.entry_point_rva,
        base_of_code: sa,
        base_of_data: if plan.is_64bit { None } else { Some(0) },
        image_base: plan.image_base,
        section_alignment: sa,
        file_alignment: fa,
        major_operating_system_version: 6,
        minor_operating_system_version: 0,
        major_image_version: 0,
        minor_image_version: 0,
        major_subsystem_version: 6,
        minor_subsystem_version: 0,
        win32_version_value: 0,
        size_of_image,
        size_of_headers,
        check_sum: 0,
        subsystem: plan.subsystem,
        dll_characteristics: plan.dll_characteristics,
        size_of_stack_reserve: if plan.is_64bit { 0x100000 } else { 0x100000 },
        size_of_stack_commit: 0x1000,
        size_of_heap_reserve: 0x100000,
        size_of_heap_commit: 0x1000,
        loader_flags: 0,
        number_of_rva_and_sizes: 16,
        data_directory: [ImageDataDirectory::default(); 16],
    };

    Ok(PeHeader {
        dos_header: ImageDosHeader {
            e_magic: IMAGE_DOS_SIGNATURE,
            e_lfanew,
        },
        nt_headers: ImageNtHeaders {
            signature: IMAGE_NT_SIGNATURE,
            file_header: ImageFileHeader {
                machine,
                number_of_sections: 0,
                time_date_stamp: 0,
                size_of_optional_header: opt_size,
                characteristics: file_chars,
            },
            optional_header: optional,
        },
        sections: Vec::new(),
        image_base: plan.image_base,
        entry_point: plan.entry_point_rva,
        is_64bit: plan.is_64bit,
        file_alignment: fa,
        section_alignment: sa,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_table::{ImportModule, ImportThunk};

    #[test]
    fn rebuild_minimal_pe32_plus_round_trips() {
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0x90, 0xC3]));
        plan.entry_point_rva = 0x1000;
        let image = rebuild_pe_image(&plan).expect("rebuild");
        let pe = PeHeader::from_bytes(&image).expect("reparse");
        assert!(pe.is_64bit);
        assert_eq!(pe.entry_point, 0x1000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name, ".text");
    }

    #[test]
    fn rebuild_with_imports_sets_directories() {
        let mut imports = ImportTableBuilder::new(false);
        {
            let m: &mut ImportModule = imports.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0,
                function_name: Some("ExitProcess".into()),
                ordinal: None,
                is_64bit: false,
            });
        }
        let mut plan = RebuildPlan::pe32();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.entry_point_rva = 0x1000;
        plan.imports = Some(imports);
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        assert!(meta.import_directory.virtual_address != 0);
        assert!(meta.import_directory.size >= 40);
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[DIR_IMPORT].virtual_address,
            meta.import_directory.virtual_address
        );
        assert_eq!(pe.sections.len(), 2); // .text + .idata
        assert!(pe.sections.iter().any(|s| s.name == ".idata"));
    }

    #[test]
    fn rebuild_with_relocs_sets_basereloc_directory() {
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections.push(PlannedSection::new(
            ".text",
            0x6000_0020,
            vec![0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00, 0xC3],
        ));
        plan.entry_point_rva = 0x1000;
        // IMAGE_REL_BASED_DIR64 = 10
        plan.relocations = vec![(0x1000, 10)];
        plan.prefer_aslr = true;
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        assert_ne!(meta.basereloc_directory.virtual_address, 0);
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[DIR_BASERELOC].virtual_address,
            meta.basereloc_directory.virtual_address
        );
        assert!(
            pe.nt_headers.optional_header.dll_characteristics & 0x0040 != 0,
            "DYNAMIC_BASE expected when prefer_aslr"
        );
        assert!(pe.sections.iter().any(|s| s.name == ".reloc"));
    }

    #[test]
    fn rebuild_empty_plan_errors() {
        let plan = RebuildPlan::default();
        let err = rebuild_pe_image(&plan).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn rebuild_headers_size_covers_section_table() {
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0x90; 16]));
        plan.entry_point_rva = 0x1000;
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert!(pe.nt_headers.optional_header.size_of_headers >= meta.size_of_headers);
        assert!(pe.nt_headers.optional_header.size_of_image >= 0x2000);
        // First section raw data must start at or after size_of_headers
        assert!(pe.sections[0].raw_offset >= pe.nt_headers.optional_header.size_of_headers);
    }

    #[test]
    fn rebuild_with_exports_sets_directory() {
        let mut exports = ExportTableBuilder::new("sample.dll");
        exports.add_export("Foo", 0x1000);
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.entry_point_rva = 0x1000;
        plan.exports = Some(exports);
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        assert_ne!(meta.export_directory.virtual_address, 0);
        assert!(meta.export_directory.size >= 40);
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[DIR_EXPORT].virtual_address,
            meta.export_directory.virtual_address
        );
        assert!(pe.sections.iter().any(|s| s.name == ".edata"));
    }

    #[test]
    fn rebuild_with_tls_sets_directory() {
        let mut tls = TlsDirectoryBuilder::pe32_plus();
        tls.template_data = vec![0xAA, 0xBB];
        tls.callback_rvas = vec![0x1000];
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.entry_point_rva = 0x1000;
        plan.tls = Some(tls);
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        assert_ne!(meta.tls_directory.virtual_address, 0);
        assert_eq!(meta.tls_directory.size, 40);
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[DIR_TLS].virtual_address,
            meta.tls_directory.virtual_address
        );
        assert!(pe.sections.iter().any(|s| s.name == ".tls"));
    }

    #[test]
    fn rebuild_with_exceptions_sets_directory() {
        use crate::exception_table::{minimal_x64_unwind_info, ExceptionTableBuilder};

        let mut exceptions = ExceptionTableBuilder::new();
        exceptions.add_function_with_unwind(0x1000, 0x1002, minimal_x64_unwind_info());
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3, 0xC3]));
        plan.entry_point_rva = 0x1000;
        plan.exceptions = Some(exceptions);
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        assert_ne!(meta.exception_directory.virtual_address, 0);
        assert_eq!(meta.exception_directory.size, 12);
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[DIR_EXCEPTION].virtual_address,
            meta.exception_directory.virtual_address
        );
        assert!(pe.sections.iter().any(|s| s.name == ".pdata"));
    }

    #[test]
    fn rebuild_exceptions_unsorted_errors() {
        use crate::exception_table::ExceptionTableBuilder;

        let mut exceptions = ExceptionTableBuilder::new();
        exceptions
            .add_function(0x2000, 0x2010, 0x3000)
            .add_function(0x1000, 0x1010, 0x3010);
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.exceptions = Some(exceptions);
        let err = rebuild_pe_image(&plan).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn rebuild_tls_arch_mismatch_errors() {
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.tls = Some(TlsDirectoryBuilder::pe32()); // 32-bit TLS on PE32+ plan
        let err = rebuild_pe_image(&plan).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn rebuild_import_arch_mismatch_errors() {
        let imports = ImportTableBuilder::new(false); // PE32 builder
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        {
            let m = plan.imports.get_or_insert(imports).add_module("k.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0,
                function_name: Some("X".into()),
                ordinal: None,
                is_64bit: false,
            });
        }
        // Force PE32+ plan with PE32 import builder
        plan.is_64bit = true;
        // RebuildPlan has imports with is_64bit=false
        let err = rebuild_pe_image(&plan).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn rebuild_fixed_section_va_preserved() {
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections.push(PlannedSection::with_rva(
            ".text",
            0x6000_0020,
            0x1000,
            0x10,
            vec![0xC3],
        ));
        plan.sections.push(PlannedSection::with_rva(
            ".import",
            0xC000_0040,
            0x3000,
            0x40,
            vec![0x11; 0x40],
        ));
        plan.entry_point_rva = 0x1000;
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(pe.sections[0].virtual_address, 0x1000);
        assert_eq!(pe.sections[1].virtual_address, 0x3000);
        assert!(pe.nt_headers.optional_header.size_of_image >= 0x4000);
    }

    #[test]
    fn rebuild_fallback_data_directories_for_content_imports() {
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections.push(PlannedSection::with_rva(
            ".text",
            0x6000_0020,
            0x1000,
            0x10,
            vec![0xC3],
        ));
        plan.sections.push(PlannedSection::with_rva(
            ".import",
            0xC000_0040,
            0x2000,
            0x80,
            vec![0x22; 0x80],
        ));
        plan.entry_point_rva = 0x1000;
        let mut fallback = [ImageDataDirectory::default(); 16];
        fallback[DIR_IMPORT] = ImageDataDirectory {
            virtual_address: 0x2000,
            size: 0x28,
        };
        fallback[DIR_IAT] = ImageDataDirectory {
            virtual_address: 0x1500,
            size: 0x10,
        };
        plan.fallback_data_directories = Some(fallback);
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        assert_eq!(meta.import_directory.virtual_address, 0x2000);
        assert_eq!(meta.iat_directory.virtual_address, 0x1500);
        let pe = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[DIR_IMPORT].virtual_address,
            0x2000
        );
        assert_eq!(
            pe.nt_headers.optional_header.data_directory[DIR_IAT].virtual_address,
            0x1500
        );
    }

    #[test]
    fn rebuild_typed_import_wins_over_fallback() {
        let mut imports = ImportTableBuilder::new(true);
        {
            let m = imports.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0,
                function_name: Some("ExitProcess".into()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.entry_point_rva = 0x1000;
        plan.imports = Some(imports);
        let mut fallback = [ImageDataDirectory::default(); 16];
        fallback[DIR_IMPORT] = ImageDataDirectory {
            virtual_address: 0xDEAD_0000,
            size: 0x28,
        };
        plan.fallback_data_directories = Some(fallback);
        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild");
        assert_ne!(meta.import_directory.virtual_address, 0xDEAD_0000);
        assert_ne!(meta.import_directory.virtual_address, 0);
    }
}
