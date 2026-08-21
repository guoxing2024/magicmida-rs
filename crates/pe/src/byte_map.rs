//! Pure byte / memory-map adapters for feeding dumps into [`RebuildPlan`].
//!
//! R1-C remainder: live dump code may capture an image as a **byte map**
//! (VA-linear buffer + caller-supplied bases). This module turns those maps
//! into pure rebuild inputs without Win32, process handles, or packer policy.
//!
//! What this is:
//! - slice section payloads out of a memory-layout image;
//! - seed a [`RebuildPlan`] from header fields on the map;
//! - optionally parse exception (`.pdata` RUNTIME_FUNCTION) and basereloc
//!   directories into typed rebuild fields so pure rebuild can re-emit them.
//!
//! What this is **not** (R1-D / host adapters):
//! - reading a live process (host memory-read APIs stay outside pure modules);
//! - reconstructing imports from IAT slots via host symbol resolution;
//! - Oreans/Themida family strategy;
//! - acceptance verdicts.

use crate::error::PeError;
use crate::exception_table::{ExceptionTableBuilder, RuntimeFunction, RUNTIME_FUNCTION_SIZE};
use crate::header::PeHeader;
use crate::rebuild::{
    PlannedSection, RebuildPlan, DIR_BASERELOC, DIR_EXCEPTION, DIR_EXPORT, DIR_IMPORT, DIR_TLS,
};

/// Default section characteristics when a map section header is missing flags.
const DEFAULT_SCN_READ: u32 = 0x4000_0000;
const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;

/// IMAGE_REL_BASED_ABSOLUTE — skip padding entries in reloc blocks.
const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;

/// Options for converting a memory-layout image map into a [`RebuildPlan`].
#[derive(Debug, Clone)]
pub struct ByteMapPlanOptions {
    /// Override preferred image base (else use the map PE header).
    pub image_base_override: Option<u64>,
    /// Override entry-point RVA (else use the map PE header).
    pub entry_point_override: Option<u32>,
    /// When true, parse the exception data directory into `plan.exceptions`
    /// and **omit** content sections whose RVA range fully covers that
    /// directory (typical single `.pdata` section).
    pub rebind_exceptions: bool,
    /// When true, parse basereloc into `plan.relocations` and omit fully
    /// covering content sections (typical `.reloc`).
    pub rebind_relocations: bool,
    /// When true and basereloc rebinding yields entries, set `prefer_aslr`.
    pub prefer_aslr_when_relocs: bool,
    /// Drop sections whose characteristics include `IMAGE_SCN_MEM_DISCARDABLE`
    /// (often `.reloc` after load — still rebound separately if requested).
    pub drop_discardable: bool,
    /// Cap for directory / section slices (hostile-size guard).
    pub max_slice_bytes: usize,

    /// R1 opt-in content-consistency baseline (WO-102). When `Some`, EXECUTE
    /// sections whose live content differs from the reference fail with
    /// `PeError::DumpContentMismatch` instead of being emitted. `None`
    /// (default) disables the check - production paths never pass a baseline
    /// implicitly, so legal unpacking (`.text` differs from disk by design)
    /// cannot trip it.
    pub section_content_reference: Option<crate::dumper::SectionContentReference>,
}

impl Default for ByteMapPlanOptions {
    fn default() -> Self {
        Self {
            image_base_override: None,
            entry_point_override: None,
            rebind_exceptions: true,
            rebind_relocations: true,
            prefer_aslr_when_relocs: true,
            drop_discardable: false,
            max_slice_bytes: 64 * 1024 * 1024,
            section_content_reference: None,
        }
    }
}

/// View of a PE image in **memory / VA layout**: byte index `i` holds the
/// byte that would appear at `image_base + i` (or at file-relative image
/// base 0 for preferred-layout dumps).
///
/// Callers (live dump adapters) fill `bytes` via host APIs; this type never
/// touches a process.
#[derive(Debug, Clone)]
pub struct ImageByteMap {
    /// Image base associated with this map (preferred or runtime). Pure
    /// rebuild uses this as `RebuildPlan.image_base` unless overridden.
    pub image_base: u64,
    /// Linear image bytes (headers at offset 0).
    pub bytes: Vec<u8>,
}

impl ImageByteMap {
    /// Construct from owned dump bytes and a caller-supplied image base.
    #[must_use]
    pub fn new(image_base: u64, bytes: Vec<u8>) -> Self {
        Self { image_base, bytes }
    }

    /// Borrow the raw map buffer.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Read `[rva, rva + size)` from the map with checked bounds and size cap.
    pub fn slice_rva(&self, rva: u32, size: u32, max: usize) -> Result<&[u8], PeError> {
        slice_rva(&self.bytes, rva, size, max)
    }
}

/// Read `[rva, rva + size)` from a VA-linear map.
pub fn slice_rva(map: &[u8], rva: u32, size: u32, max: usize) -> Result<&[u8], PeError> {
    if size == 0 {
        return Ok(&[]);
    }
    let size_usize = size as usize;
    if size_usize > max {
        return Err(PeError::SizeLimit {
            what: "byte_map slice".into(),
            size: size_usize,
            max,
        });
    }
    let start = rva as usize;
    let end = start
        .checked_add(size_usize)
        .ok_or_else(|| PeError::Parse("byte_map slice overflow".into()))?;
    if end > map.len() {
        return Err(PeError::Parse(format!(
            "byte_map slice out of range: rva={rva:#x} size={size:#x} map_len={:#x}",
            map.len()
        )));
    }
    Ok(&map[start..end])
}

/// Extract one section's payload from a memory-layout map.
///
/// Uses `virtual_size` as the logical size (live dumps are VA-linear). When the
/// map is shorter than `va + virtual_size`, available bytes are copied and the
/// remainder is zero-padded to `virtual_size` (common for partial dumps).
pub fn section_bytes_from_map(
    map: &[u8],
    virtual_address: u32,
    virtual_size: u32,
    max: usize,
) -> Result<Vec<u8>, PeError> {
    if virtual_size == 0 {
        return Ok(Vec::new());
    }
    let need = virtual_size as usize;
    if need > max {
        return Err(PeError::SizeLimit {
            what: "section virtual_size".into(),
            size: need,
            max,
        });
    }
    let start = virtual_address as usize;
    if start >= map.len() {
        return Ok(vec![0u8; need]);
    }
    let avail = (map.len() - start).min(need);
    let mut out = vec![0u8; need];
    out[..avail].copy_from_slice(&map[start..start + avail]);
    Ok(out)
}

/// Parse RUNTIME_FUNCTION entries from the exception data directory on a map.
///
/// Unwind RVAs are kept absolute (not re-embedded). Empty / zero-size directory
/// yields an empty builder (caller decides whether to attach it).
pub fn exception_builder_from_map(
    map: &[u8],
    pe: &PeHeader,
    max: usize,
) -> Result<ExceptionTableBuilder, PeError> {
    let dd = pe
        .nt_headers
        .optional_header
        .data_directory
        .get(DIR_EXCEPTION)
        .copied()
        .unwrap_or_default();
    let mut builder = ExceptionTableBuilder::new();
    if dd.virtual_address == 0 || dd.size == 0 {
        return Ok(builder);
    }
    let raw = slice_rva(map, dd.virtual_address, dd.size, max)?;
    let n = raw.len() / RUNTIME_FUNCTION_SIZE;
    for i in 0..n {
        let off = i * RUNTIME_FUNCTION_SIZE;
        let begin = u32::from_le_bytes(raw[off..off + 4].try_into().unwrap());
        let end = u32::from_le_bytes(raw[off + 4..off + 8].try_into().unwrap());
        let unwind = u32::from_le_bytes(raw[off + 8..off + 12].try_into().unwrap());
        // Skip all-zero padding entries.
        if begin == 0 && end == 0 && unwind == 0 {
            continue;
        }
        builder.functions.push(RuntimeFunction {
            begin_rva: begin,
            end_rva: end,
            unwind_info_rva: unwind,
        });
    }
    Ok(builder)
}

/// Parse `IMAGE_BASE_RELOCATION` blocks into `(rva, type)` pairs.
pub fn relocations_from_map(
    map: &[u8],
    pe: &PeHeader,
    max: usize,
) -> Result<Vec<(u32, u16)>, PeError> {
    let dd = pe
        .nt_headers
        .optional_header
        .data_directory
        .get(DIR_BASERELOC)
        .copied()
        .unwrap_or_default();
    if dd.virtual_address == 0 || dd.size == 0 {
        return Ok(Vec::new());
    }
    let raw = slice_rva(map, dd.virtual_address, dd.size, max)?;
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < raw.len() {
        let remaining = raw.len() - pos;
        if remaining < 8 {
            if raw[pos..].iter().all(|&b| b == 0) {
                break;
            }
            return Err(PeError::Parse(format!(
                "truncated basereloc header at +{pos:#x}"
            )));
        }
        let page_rva = u32::from_le_bytes(
            raw[pos..pos + 4]
                .try_into()
                .map_err(|_| PeError::Parse("invalid basereloc page RVA width".into()))?,
        );
        let block_size_u32 = u32::from_le_bytes(
            raw[pos + 4..pos + 8]
                .try_into()
                .map_err(|_| PeError::Parse("invalid basereloc block size width".into()))?,
        );
        let block_size = usize::try_from(block_size_u32)
            .map_err(|_| PeError::Parse("basereloc block size does not fit usize".into()))?;
        if block_size < 8 || block_size % 4 != 0 {
            return Err(PeError::Parse(format!(
                "invalid basereloc block at +{pos:#x}: size={block_size:#x}"
            )));
        }
        let block_end = pos
            .checked_add(block_size)
            .ok_or_else(|| PeError::Parse("basereloc block range overflow".into()))?;
        if block_end > raw.len() {
            return Err(PeError::Parse(format!(
                "basereloc block at +{pos:#x} extends beyond directory"
            )));
        }
        let entries = (block_size - 8) / 2;
        for i in 0..entries {
            let eoff = pos
                .checked_add(8)
                .and_then(|n| n.checked_add(i.checked_mul(2)?))
                .ok_or_else(|| PeError::Parse("basereloc entry offset overflow".into()))?;
            let ent = u16::from_le_bytes(
                raw[eoff..eoff + 2]
                    .try_into()
                    .map_err(|_| PeError::Parse("invalid basereloc entry width".into()))?,
            );
            let typ = ent >> 12;
            let off = u32::from(ent & 0x0FFF);
            if typ == IMAGE_REL_BASED_ABSOLUTE {
                continue;
            }
            let rva = page_rva
                .checked_add(off)
                .ok_or_else(|| PeError::Parse(format!("basereloc RVA overflow at +{eoff:#x}")))?;
            out.push((rva, typ));
        }
        pos = block_end;
    }
    Ok(out)
}

/// True when section `[va, va+vsz)` fully covers `[dir_va, dir_va+dir_sz)`.
fn section_covers_directory(
    sec_va: u32,
    sec_vsz: u32,
    dir_va: u32,
    dir_sz: u32,
) -> Result<bool, PeError> {
    if dir_va == 0 || dir_sz == 0 || sec_vsz == 0 {
        return Ok(false);
    }
    let sec_end = sec_va
        .checked_add(sec_vsz)
        .ok_or_else(|| PeError::Parse("section directory coverage range overflow".into()))?;
    let dir_end = dir_va
        .checked_add(dir_sz)
        .ok_or_else(|| PeError::Parse("directory range overflow".into()))?;
    Ok(sec_va <= dir_va && sec_end >= dir_end)
}

/// Build a pure [`RebuildPlan`] from a memory-layout image map.
///
/// Content sections are taken from the map. Optional directory rebinding
/// moves exception / basereloc into typed plan fields so
/// [`crate::rebuild::rebuild_pe_image`] can re-emit them.
///
/// **Not rebound here (needs host resolution or richer parsers):** imports
/// (`DIR_IMPORT` / IAT), exports name tables into `ExportTableBuilder`, TLS
/// absolute callback VAs into `TlsDirectoryBuilder`. Those stay as content
/// bytes inside their sections unless a later slice lifts them.
pub fn plan_from_memory_image(
    map: &[u8],
    opts: &ByteMapPlanOptions,
) -> Result<RebuildPlan, PeError> {
    let pe = PeHeader::from_bytes(map)?;
    let image_base = opts.image_base_override.unwrap_or(pe.image_base);
    let entry = opts.entry_point_override.unwrap_or(pe.entry_point);

    let mut plan = if pe.is_64bit {
        RebuildPlan::pe32_plus()
    } else {
        RebuildPlan::pe32()
    };
    plan.image_base = image_base;
    plan.entry_point_rva = entry;
    plan.file_alignment = pe.file_alignment.max(1);
    plan.section_alignment = pe.section_alignment.max(1);
    plan.subsystem = pe.nt_headers.optional_header.subsystem;
    plan.dll_characteristics = pe.nt_headers.optional_header.dll_characteristics;
    plan.file_characteristics = pe.nt_headers.file_header.characteristics;

    let exc_dd = pe.nt_headers.optional_header.data_directory[DIR_EXCEPTION];
    let reloc_dd = pe.nt_headers.optional_header.data_directory[DIR_BASERELOC];

    let mut exceptions = if opts.rebind_exceptions {
        Some(exception_builder_from_map(map, &pe, opts.max_slice_bytes)?)
    } else {
        None
    };
    if let Some(ref b) = exceptions {
        if b.function_count() == 0 {
            exceptions = None;
        } else {
            // Validate early so plan attachment fails fast.
            b.validate()?;
        }
    }

    let relocs = if opts.rebind_relocations {
        relocations_from_map(map, &pe, opts.max_slice_bytes)?
    } else {
        Vec::new()
    };

    for sec in &pe.sections {
        if opts.drop_discardable && (sec.characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0 {
            continue;
        }
        if opts.rebind_exceptions {
            if let Some(ref b) = exceptions {
                if b.function_count() > 0
                    && section_covers_directory(
                        sec.virtual_address,
                        sec.virtual_size,
                        exc_dd.virtual_address,
                        exc_dd.size,
                    )?
                {
                    continue;
                }
            }
        }
        if opts.rebind_relocations
            && !relocs.is_empty()
            && section_covers_directory(
                sec.virtual_address,
                sec.virtual_size,
                reloc_dd.virtual_address,
                reloc_dd.size,
            )?
        {
            continue;
        }

        let data = section_bytes_from_map(
            map,
            sec.virtual_address,
            sec.virtual_size,
            opts.max_slice_bytes,
        )?;
        let chars = if sec.characteristics == 0 {
            DEFAULT_SCN_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
        } else {
            sec.characteristics
        };
        plan.sections.push(PlannedSection {
            name: sec.name.clone(),
            characteristics: chars,
            virtual_size: sec.virtual_size,
            data,
            // Preserve map section RVAs so content directories stay valid (R1-E).
            virtual_address: Some(sec.virtual_address),
        });
    }

    plan.exceptions = exceptions;
    plan.relocations = relocs;
    if opts.prefer_aslr_when_relocs && !plan.relocations.is_empty() {
        plan.prefer_aslr = true;
    }

    // Carry host data directories for content-only import/IAT/TLS/etc.
    plan.fallback_data_directories = Some(pe.nt_headers.optional_header.data_directory);

    // R1 (WO-102, opt-in): content-consistency check for EXECUTE sections.
    // Only runs when the caller explicitly provided a baseline; production
    // paths never pass one, so legal unpacking (runtime .text differs
    // from disk by design) cannot trip this. Fail-closed on divergence.
    if let Some(ref r1_ref) = opts.section_content_reference {
        for s in plan.sections.iter() {
            if s.characteristics & 0x2000_0000 == 0 {
                continue; // not EXECUTE: no check
            }
            if let Some((off, len)) = r1_ref.first_diff(&s.name, &s.data) {
                return Err(PeError::DumpContentMismatch {
                    section: s.name.clone(),
                    offset: off,
                    length: len,
                });
            }
        }
    }

    Ok(plan)
}

/// Convenience: map → plan → PE bytes (offline structural candidate only).
pub fn rebuild_from_memory_image(
    map: &[u8],
    opts: &ByteMapPlanOptions,
) -> Result<Vec<u8>, PeError> {
    let plan = plan_from_memory_image(map, opts)?;
    crate::rebuild::rebuild_pe_image(&plan)
}

/// Directory indices present on the map PE header (for adapter diagnostics).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MapDirectoryHints {
    pub export: bool,
    pub import: bool,
    pub exception: bool,
    pub basereloc: bool,
    pub tls: bool,
}

/// Which data directories are non-empty on the map (hint for R1-D adapters).
#[must_use]
pub fn directory_hints(pe: &PeHeader) -> MapDirectoryHints {
    let dd = &pe.nt_headers.optional_header.data_directory;
    MapDirectoryHints {
        export: dd[DIR_EXPORT].virtual_address != 0 && dd[DIR_EXPORT].size != 0,
        import: dd[DIR_IMPORT].virtual_address != 0 && dd[DIR_IMPORT].size != 0,
        exception: dd[DIR_EXCEPTION].virtual_address != 0 && dd[DIR_EXCEPTION].size != 0,
        basereloc: dd[DIR_BASERELOC].virtual_address != 0 && dd[DIR_BASERELOC].size != 0,
        tls: dd[DIR_TLS].virtual_address != 0 && dd[DIR_TLS].size != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exception_table::minimal_x64_unwind_info;
    use crate::rebuild::{rebuild_pe_image, rebuild_pe_image_with_meta, DIR_EXCEPTION};
    use crate::relocation::RelocationTableBuilder;

    fn synthetic_map_with_exception_and_reloc() -> Vec<u8> {
        // Build via pure rebuild first (offline synthetic — no PE fixtures).
        let mut exceptions = ExceptionTableBuilder::new();
        exceptions.add_function_with_unwind(0x1000, 0x1002, minimal_x64_unwind_info());
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3, 0xC3]));
        plan.entry_point_rva = 0x1000;
        plan.exceptions = Some(exceptions);
        // One DIR64 reloc at EP
        plan.relocations = vec![(0x1000, 10)];
        plan.prefer_aslr = true;
        rebuild_pe_image(&plan).expect("synthetic map")
    }

    /// Convert a file-layout PE into a crude VA-linear map for adapter tests.
    ///
    /// Pure rebuild emits file layout; live dumps are VA-linear. Tests expand
    /// sections to virtual addresses so `plan_from_memory_image` can slice them.
    fn file_image_to_va_map(file: &[u8]) -> Vec<u8> {
        let pe = PeHeader::from_bytes(file).expect("parse");
        let size = pe.nt_headers.optional_header.size_of_image as usize;
        let mut map = vec![0u8; size];
        // Headers
        let hdr = pe.nt_headers.optional_header.size_of_headers as usize;
        let hdr_copy = hdr.min(file.len()).min(map.len());
        map[..hdr_copy].copy_from_slice(&file[..hdr_copy]);
        for sec in &pe.sections {
            let va = sec.virtual_address as usize;
            let raw_off = sec.raw_offset as usize;
            let raw_sz = sec.raw_size as usize;
            let vsz = sec.virtual_size as usize;
            if va >= map.len() || raw_off >= file.len() {
                continue;
            }
            let take = raw_sz
                .min(file.len() - raw_off)
                .min(vsz)
                .min(map.len() - va);
            map[va..va + take].copy_from_slice(&file[raw_off..raw_off + take]);
        }
        map
    }

    #[test]
    fn slice_rva_bounds() {
        let map = vec![0u8; 0x20];
        assert!(slice_rva(&map, 0x10, 0x10, 1024).is_ok());
        assert!(slice_rva(&map, 0x10, 0x11, 1024).is_err());
        assert!(matches!(
            slice_rva(&map, 0, 8, 4),
            Err(PeError::SizeLimit { .. })
        ));
    }

    #[test]
    fn plan_from_map_round_trips_sections() {
        let file = synthetic_map_with_exception_and_reloc();
        let map = file_image_to_va_map(&file);
        let pe = PeHeader::from_bytes(&map).expect("headers on va map");
        assert!(pe.is_64bit);

        let opts = ByteMapPlanOptions::default();
        let plan = plan_from_memory_image(&map, &opts).expect("plan");
        assert!(plan.is_64bit);
        assert_eq!(plan.entry_point_rva, 0x1000);
        assert!(
            plan.sections.iter().any(|s| s.name == ".text"),
            "expected .text content section"
        );
        // Exception rebound → no content .pdata required
        assert!(
            plan.exceptions
                .as_ref()
                .is_some_and(|b| b.function_count() == 1),
            "exception builder rebound"
        );
        assert!(!plan.relocations.is_empty(), "relocs rebound");
        assert!(plan.prefer_aslr);

        let meta = rebuild_pe_image_with_meta(&plan).expect("rebuild from map plan");
        let pe2 = PeHeader::from_bytes(&meta.image).expect("reparse");
        assert_eq!(pe2.entry_point, 0x1000);
        assert_ne!(
            pe2.nt_headers.optional_header.data_directory[DIR_EXCEPTION].virtual_address,
            0
        );
        assert!(pe2.sections.iter().any(|s| s.name == ".pdata"));
        assert!(pe2.sections.iter().any(|s| s.name == ".reloc"));
    }

    #[test]
    fn plan_without_rebind_keeps_directory_sections() {
        let file = synthetic_map_with_exception_and_reloc();
        let map = file_image_to_va_map(&file);
        let opts = ByteMapPlanOptions {
            rebind_exceptions: false,
            rebind_relocations: false,
            ..Default::default()
        };
        let plan = plan_from_memory_image(&map, &opts).expect("plan");
        assert!(plan.exceptions.is_none());
        assert!(plan.relocations.is_empty());
        // Content includes .pdata / .reloc as raw sections
        assert!(plan.sections.iter().any(|s| s.name == ".pdata"));
        assert!(plan.sections.iter().any(|s| s.name == ".reloc"));
    }

    #[test]
    fn exception_builder_from_synthetic_map() {
        let file = synthetic_map_with_exception_and_reloc();
        let map = file_image_to_va_map(&file);
        let pe = PeHeader::from_bytes(&map).expect("pe");
        let b = exception_builder_from_map(&map, &pe, 16 * 1024 * 1024).expect("exc");
        assert_eq!(b.function_count(), 1);
        assert_eq!(b.functions[0].begin_rva, 0x1000);
        assert_eq!(b.functions[0].end_rva, 0x1002);
        b.validate().expect("valid");
    }

    #[test]
    fn relocations_from_synthetic_map() {
        let file = synthetic_map_with_exception_and_reloc();
        let map = file_image_to_va_map(&file);
        let pe = PeHeader::from_bytes(&map).expect("pe");
        let relocs = relocations_from_map(&map, &pe, 16 * 1024 * 1024).expect("relocs");
        assert!(
            relocs.iter().any(|(rva, typ)| *rva == 0x1000 && *typ == 10),
            "expected DIR64 at 0x1000, got {relocs:?}"
        );
    }

    #[test]
    fn malformed_relocation_block_size_is_rejected() {
        let file = synthetic_map_with_exception_and_reloc();
        let mut map = file_image_to_va_map(&file);
        let pe = PeHeader::from_bytes(&map).expect("pe");
        let dd = pe.nt_headers.optional_header.data_directory[DIR_BASERELOC];
        let off = dd.virtual_address as usize;
        map[off + 4..off + 8].copy_from_slice(&10u32.to_le_bytes());
        let err = relocations_from_map(&map, &pe, 16 * 1024 * 1024)
            .expect_err("non-aligned relocation block must fail");
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn relocation_page_rva_overflow_is_rejected() {
        let file = synthetic_map_with_exception_and_reloc();
        let mut map = file_image_to_va_map(&file);
        let pe = PeHeader::from_bytes(&map).expect("pe");
        let dd = pe.nt_headers.optional_header.data_directory[DIR_BASERELOC];
        let off = dd.virtual_address as usize;
        map[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        map[off + 4..off + 8].copy_from_slice(&8u32.to_le_bytes());
        map[off + 8..off + 10].copy_from_slice(&0x3001u16.to_le_bytes());
        let err = relocations_from_map(&map, &pe, 16 * 1024 * 1024)
            .expect_err("relocation RVA overflow must fail");
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn directory_hints_reflect_map() {
        let file = synthetic_map_with_exception_and_reloc();
        let map = file_image_to_va_map(&file);
        let pe = PeHeader::from_bytes(&map).expect("pe");
        let h = directory_hints(&pe);
        assert!(h.exception);
        assert!(h.basereloc);
        assert!(!h.import);
        assert!(!h.export);
        assert!(!h.tls);
    }

    #[test]
    fn empty_map_errors() {
        let err = plan_from_memory_image(&[], &ByteMapPlanOptions::default()).unwrap_err();
        assert!(matches!(
            err,
            PeError::BufferTooSmall(_, _) | PeError::InvalidDosSignature | PeError::Parse(_)
        ));
    }

    #[test]
    fn reloc_builder_roundtrip_matches_parser() {
        // Sanity: RelocationTableBuilder emit is what relocations_from_map reads.
        let mut b = RelocationTableBuilder::new(0x140000000, 0x3000);
        b.add_relocation(0x1000, 10);
        b.add_relocation(0x1008, 10);
        let bytes = b.build();
        // Fabricate minimal pe-less parse via a fake header path: write bytes
        // at RVA 0x2000 in a map and point DD manually through a rebuilt image.
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.entry_point_rva = 0x1000;
        plan.relocations = vec![(0x1000, 10), (0x1008, 10)];
        let file = rebuild_pe_image(&plan).expect("rebuild");
        let map = file_image_to_va_map(&file);
        let pe = PeHeader::from_bytes(&map).expect("pe");
        let parsed = relocations_from_map(&map, &pe, 16 * 1024 * 1024).expect("parse");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.contains(&(0x1000, 10)));
        assert!(parsed.contains(&(0x1008, 10)));
        // Also ensure builder output shape is non-empty (used by rebuild).
        assert!(!bytes.is_empty());
    }
}
