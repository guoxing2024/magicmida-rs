//! R1-D/E host adapter: live-dump state -> pure [`RebuildPlan`] / PE bytes.
//!
//! Lives under `dumper/` (not pure PE modules). Host code may fill `dump_buf`
//! and mutate [`PeHeader`] (imports, `.pdata`, etc.); this module only maps
//! that prepared state into pure rebuild inputs and calls
//! [`crate::rebuild::rebuild_pe_image`].
//!
//! Layout contract: `dump_buf` is **VA-linear** (byte index == RVA), as produced
//! by host memory reads at `image_base`. Section payloads prefer `extra_data`
//! when present (host-built `.import` / `.edata` / bootstrap), else a slice of
//! `dump_buf`.
//!
//! R1-E parity:
//! - preserve host section RVAs so content data directories stay valid;
//! - carry host data directories as fallback when typed rebind does not own them;
//! - gate exception/reloc rebind via [`PureRebuildEmitOptions`].

use tracing::{debug, info, warn};

use crate::byte_map::{exception_builder_from_map, relocations_from_map, section_bytes_from_map};
use crate::error::PeError;
use crate::header::PeHeader;
use crate::rebuild::{
    rebuild_pe_image_with_meta, PlannedSection, RebuildPlan, DIR_BASERELOC, DIR_EXCEPTION,
};

/// Options for the pure rebuild emit path (host side).
#[derive(Debug, Clone)]
pub struct PureRebuildEmitOptions {
    pub image_base: u64,
    pub entry_point_rva: u32,
    /// Parse exception directory from the VA map into typed rebuild fields.
    pub rebind_exceptions: bool,
    /// Parse basereloc from the VA map into typed rebuild fields.
    pub rebind_relocations: bool,
    pub prefer_aslr_when_relocs: bool,
    /// When true (default), keep host section RVAs so import/IAT/TLS directories
    /// that point into content sections remain loader-valid after rebuild.
    pub preserve_section_vas: bool,
    /// When true (default), copy host data directories for indices not set by
    /// typed builders (import/IAT/TLS/export content carry).
    pub carry_host_data_directories: bool,
    pub max_slice_bytes: usize,

    /// R1 opt-in content-consistency baseline (WO-102). When `Some`, EXECUTE
    /// sections whose live plan content differs from the reference fail with
    /// `PeError::DumpContentMismatch`. `None` (default) disables the check.
    pub section_content_reference: Option<crate::dumper::SectionContentReference>,
}

impl Default for PureRebuildEmitOptions {
    fn default() -> Self {
        Self {
            image_base: 0,
            entry_point_rva: 0,
            rebind_exceptions: true,
            rebind_relocations: true,
            prefer_aslr_when_relocs: true,
            preserve_section_vas: true,
            carry_host_data_directories: true,
            max_slice_bytes: 64 * 1024 * 1024,
            section_content_reference: None,
        }
    }
}

/// Structural snapshot used by offline pure-vs-host parity checks (not acceptance).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PureRebuildParitySnapshot {
    pub is_64bit: bool,
    pub entry_point: u32,
    pub image_base: u64,
    pub section_count: usize,
    pub section_names: Vec<String>,
    pub section_vas: Vec<u32>,
    pub import_rva: u32,
    pub import_size: u32,
    pub iat_rva: u32,
    pub iat_size: u32,
    pub exception_rva: u32,
    pub tls_rva: u32,
    pub basereloc_rva: u32,
    pub subsystem: u16,
}

impl PureRebuildParitySnapshot {
    /// Capture structural fields from a PE model (host-prepared or reparsed emit).
    #[must_use]
    pub fn from_pe(pe: &PeHeader) -> Self {
        let dd = &pe.nt_headers.optional_header.data_directory;
        Self {
            is_64bit: pe.is_64bit,
            entry_point: pe.entry_point,
            image_base: pe.image_base,
            section_count: pe.sections.len(),
            section_names: pe.sections.iter().map(|s| s.name.clone()).collect(),
            section_vas: pe.sections.iter().map(|s| s.virtual_address).collect(),
            import_rva: dd[1].virtual_address,
            import_size: dd[1].size,
            iat_rva: dd[12].virtual_address,
            iat_size: dd[12].size,
            exception_rva: dd[3].virtual_address,
            tls_rva: dd[9].virtual_address,
            basereloc_rva: dd[5].virtual_address,
            subsystem: pe.nt_headers.optional_header.subsystem,
        }
    }

    /// Compare host model vs pure emit snapshot for R1-E structural gates.
    ///
    /// Returns human-readable mismatch strings (empty => pass).
    #[must_use]
    pub fn structural_mismatches(&self, other: &Self) -> Vec<String> {
        let mut out = Vec::new();
        if self.is_64bit != other.is_64bit {
            out.push(format!(
                "is_64bit host={} pure={}",
                self.is_64bit, other.is_64bit
            ));
        }
        if self.entry_point != other.entry_point {
            out.push(format!(
                "entry_point host={:#x} pure={:#x}",
                self.entry_point, other.entry_point
            ));
        }
        if self.image_base != other.image_base {
            out.push(format!(
                "image_base host={:#x} pure={:#x}",
                self.image_base, other.image_base
            ));
        }
        if self.subsystem != other.subsystem {
            out.push(format!(
                "subsystem host={:#x} pure={:#x}",
                self.subsystem, other.subsystem
            ));
        }
        if self.import_rva != other.import_rva || self.import_size != other.import_size {
            out.push(format!(
                "import_dir host={:#x}/{:#x} pure={:#x}/{:#x}",
                self.import_rva, self.import_size, other.import_rva, other.import_size
            ));
        }
        if self.iat_rva != other.iat_rva || self.iat_size != other.iat_size {
            out.push(format!(
                "iat_dir host={:#x}/{:#x} pure={:#x}/{:#x}",
                self.iat_rva, self.iat_size, other.iat_rva, other.iat_size
            ));
        }
        if self.tls_rva != 0 && other.tls_rva != 0 && self.tls_rva != other.tls_rva {
            out.push(format!(
                "tls_dir host={:#x} pure={:#x}",
                self.tls_rva, other.tls_rva
            ));
        }
        for name in &self.section_names {
            let critical = matches!(
                name.as_str(),
                ".text" | ".rdata" | ".data" | ".import" | ".edata" | ".boot" | ".rsrc"
            ) || name.starts_with(".text")
                || name.starts_with(".import");
            if critical && !other.section_names.iter().any(|n| n == name) {
                out.push(format!("missing critical section {name}"));
            }
        }
        out
    }
}

/// Build a pure [`RebuildPlan`] from a host-prepared PE model + VA dump buffer.
///
/// Does not reconstruct imports from IAT via host symbol resolution; if the
/// host already attached import payloads as section `extra_data`, those bytes
/// are carried as content sections with host RVAs (R1-E).
pub fn plan_from_host_dump(
    pe: &PeHeader,
    dump_buf: &[u8],
    opts: &PureRebuildEmitOptions,
) -> Result<RebuildPlan, PeError> {
    let mut plan = if pe.is_64bit {
        RebuildPlan::pe32_plus()
    } else {
        RebuildPlan::pe32()
    };

    // Prefer explicit emit option when non-zero. Live dump path should pass the
    // host-patched preferred ImageBase (not runtime ASLR) for legacy parity.
    plan.image_base = if opts.image_base != 0 {
        opts.image_base
    } else {
        pe.image_base
    };
    plan.entry_point_rva = if opts.entry_point_rva != 0 {
        opts.entry_point_rva
    } else {
        pe.entry_point
    };
    plan.file_alignment = pe.file_alignment.max(1);
    plan.section_alignment = pe.section_alignment.max(1);
    plan.subsystem = pe.nt_headers.optional_header.subsystem;
    plan.dll_characteristics = pe.nt_headers.optional_header.dll_characteristics;
    plan.file_characteristics = pe.nt_headers.file_header.characteristics;

    let exc_dd = pe.nt_headers.optional_header.data_directory[DIR_EXCEPTION];
    let reloc_dd = pe.nt_headers.optional_header.data_directory[DIR_BASERELOC];

    let mut exceptions = if opts.rebind_exceptions && dump_buf.len() >= 64 {
        match exception_builder_from_map(dump_buf, pe, opts.max_slice_bytes) {
            Ok(b) if b.function_count() > 0 => {
                b.validate()?;
                Some(b)
            }
            Ok(_) => None,
            Err(e) => {
                warn!(error = %e, "pure rebuild: exception rebind skipped");
                None
            }
        }
    } else {
        None
    };

    let relocs = if opts.rebind_relocations && dump_buf.len() >= 64 {
        match relocations_from_map(dump_buf, pe, opts.max_slice_bytes) {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "pure rebuild: reloc rebind skipped");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    for sec in &pe.sections {
        let has_extra = sec
            .extra_data
            .as_ref()
            .map(|d| !d.is_empty())
            .unwrap_or(false);

        if opts.rebind_exceptions {
            if let Some(ref b) = exceptions {
                if b.function_count() > 0
                    && section_covers(
                        sec.virtual_address,
                        sec.virtual_size,
                        exc_dd.virtual_address,
                        exc_dd.size,
                    )
                    && !has_extra
                {
                    continue;
                }
            }
        }
        if opts.rebind_relocations
            && !relocs.is_empty()
            && section_covers(
                sec.virtual_address,
                sec.virtual_size,
                reloc_dd.virtual_address,
                reloc_dd.size,
            )
            && !has_extra
        {
            continue;
        }

        let data = if let Some(ref extra) = sec.extra_data {
            if !extra.is_empty() {
                if extra.len() > opts.max_slice_bytes {
                    return Err(PeError::SizeLimit {
                        what: format!("section {} extra_data", sec.name),
                        size: extra.len(),
                        max: opts.max_slice_bytes,
                    });
                }
                extra.clone()
            } else {
                section_bytes_from_map(
                    dump_buf,
                    sec.virtual_address,
                    sec.virtual_size,
                    opts.max_slice_bytes,
                )?
            }
        } else {
            section_bytes_from_map(
                dump_buf,
                sec.virtual_address,
                sec.virtual_size,
                opts.max_slice_bytes,
            )?
        };

        let chars = if sec.characteristics == 0 {
            0x4000_0000 | 0x0000_0040 // READ | INITIALIZED_DATA
        } else {
            sec.characteristics
        };

        let virtual_size = sec.virtual_size.max(data.len() as u32).max(1);
        plan.sections.push(PlannedSection {
            name: sec.name.clone(),
            characteristics: chars,
            virtual_size,
            data,
            virtual_address: if opts.preserve_section_vas {
                Some(sec.virtual_address)
            } else {
                None
            },
        });
    }

    if let Some(ref b) = exceptions {
        if b.function_count() == 0 {
            exceptions = None;
        }
    }
    plan.exceptions = exceptions;
    plan.relocations = relocs;
    if opts.prefer_aslr_when_relocs && !plan.relocations.is_empty() {
        plan.prefer_aslr = true;
    }

    if opts.carry_host_data_directories {
        plan.fallback_data_directories = Some(pe.nt_headers.optional_header.data_directory);
    }

    if plan.sections.is_empty()
        && plan.exceptions.is_none()
        && plan.relocations.is_empty()
        && plan.imports.is_none()
        && plan.exports.is_none()
        && plan.tls.is_none()
    {
        return Err(PeError::Parse(
            "pure rebuild plan empty: host dump produced no sections".into(),
        ));
    }

    debug!(
        sections = plan.sections.len(),
        exceptions = plan
            .exceptions
            .as_ref()
            .map(|b| b.function_count())
            .unwrap_or(0),
        relocs = plan.relocations.len(),
        preserve_vas = opts.preserve_section_vas,
        carry_dirs = opts.carry_host_data_directories,
        entry = format_args!("{:#x}", plan.entry_point_rva),
        "pure rebuild plan from host dump (R1-E)"
    );

    Ok(plan)
}

/// Emit PE bytes via pure rebuild from host-prepared dump state.
pub fn emit_pure_rebuild(
    pe: &PeHeader,
    dump_buf: &[u8],
    opts: &PureRebuildEmitOptions,
) -> Result<Vec<u8>, PeError> {
    let plan = plan_from_host_dump(pe, dump_buf, opts)?;
    // R1 (WO-102, opt-in): content-consistency check for EXECUTE sections.
    // Only runs when the caller explicitly provided a baseline; production
    // paths never pass one, so legal unpacking cannot trip this.
    if let Some(ref r1_ref) = opts.section_content_reference {
        for s in plan.sections.iter() {
            if s.characteristics & 0x2000_0000 == 0 {
                continue;
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
    let meta = rebuild_pe_image_with_meta(&plan)?;
    info!(
        size = meta.image.len(),
        sections = plan.sections.len(),
        import_rva = format_args!("{:#x}", meta.import_directory.virtual_address),
        iat_rva = format_args!("{:#x}", meta.iat_directory.virtual_address),
        "pure rebuild image emitted (R1-E adapter)"
    );
    Ok(meta.image)
}

/// Emit pure rebuild and return host/pure structural parity snapshots.
pub fn emit_pure_rebuild_with_parity(
    pe: &PeHeader,
    dump_buf: &[u8],
    opts: &PureRebuildEmitOptions,
) -> Result<
    (
        Vec<u8>,
        PureRebuildParitySnapshot,
        PureRebuildParitySnapshot,
    ),
    PeError,
> {
    let host = PureRebuildParitySnapshot::from_pe(pe);
    let image = emit_pure_rebuild(pe, dump_buf, opts)?;
    let re = PeHeader::from_bytes(&image)?;
    let pure = PureRebuildParitySnapshot::from_pe(&re);
    Ok((image, host, pure))
}

fn section_covers(sec_rva: u32, sec_vsize: u32, dir_rva: u32, dir_size: u32) -> bool {
    if dir_rva == 0 || dir_size == 0 || sec_vsize == 0 {
        return false;
    }
    let sec_end = sec_rva.saturating_add(sec_vsize);
    let dir_end = dir_rva.saturating_add(dir_size);
    sec_rva <= dir_rva && dir_end <= sec_end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{ImageDataDirectory, PeHeader};
    use crate::rebuild::{rebuild_pe_image, PlannedSection, RebuildPlan, DIR_IAT, DIR_IMPORT};
    use crate::utils::align_up;

    fn synthetic_va_image() -> (PeHeader, Vec<u8>) {
        let mut plan = RebuildPlan::pe32_plus();
        plan.image_base = 0x140000000;
        plan.entry_point_rva = 0x1000;
        plan.sections.push(PlannedSection::new(
            ".text",
            0x6000_0020, // CODE | EXECUTE | READ
            vec![0xC3],  // ret
        ));
        let image = rebuild_pe_image(&plan).expect("synthetic rebuild");
        let pe = PeHeader::from_bytes(&image).expect("parse synthetic");
        let size = pe.size_of_image() as usize;
        let mut va = vec![0u8; size.max(0x2000)];
        let hdr_end = pe
            .sections
            .iter()
            .filter(|s| s.header.pointer_to_raw_data > 0)
            .map(|s| s.header.pointer_to_raw_data as usize)
            .min()
            .unwrap_or(0x400)
            .min(image.len());
        let hdr_copy = hdr_end.min(va.len()).min(image.len());
        va[..hdr_copy].copy_from_slice(&image[..hdr_copy]);
        for sec in &pe.sections {
            let ptr = sec.header.pointer_to_raw_data as usize;
            let raw = sec.header.size_of_raw_data as usize;
            let va_off = sec.virtual_address as usize;
            if ptr == 0 || raw == 0 || ptr + raw > image.len() {
                continue;
            }
            let end = (va_off + raw).min(va.len());
            if va_off >= end {
                continue;
            }
            let n = end - va_off;
            va[va_off..end].copy_from_slice(&image[ptr..ptr + n]);
        }
        let mut pe = PeHeader::from_bytes(&va).unwrap_or(pe);
        let soi = align_up(va.len() as u32, pe.section_alignment.max(0x1000));
        pe.nt_headers.optional_header.size_of_image = soi;
        if va.len() < soi as usize {
            va.resize(soi as usize, 0);
        }
        (pe, va)
    }

    fn base_opts(pe: &PeHeader) -> PureRebuildEmitOptions {
        PureRebuildEmitOptions {
            image_base: pe.image_base,
            entry_point_rva: pe.entry_point,
            rebind_exceptions: false,
            rebind_relocations: false,
            prefer_aslr_when_relocs: false,
            preserve_section_vas: true,
            carry_host_data_directories: true,
            max_slice_bytes: 16 * 1024 * 1024,
            section_content_reference: None,
        }
    }

    #[test]
    fn plan_from_host_dump_emits_parseable_pe() {
        let (pe, dump_buf) = synthetic_va_image();
        let opts = base_opts(&pe);
        let out = emit_pure_rebuild(&pe, &dump_buf, &opts).expect("emit");
        let re = PeHeader::from_bytes(&out).expect("reparse pure emit");
        assert!(!re.sections.is_empty());
        assert_eq!(re.entry_point, pe.entry_point);
    }

    #[test]
    fn extra_data_preferred_over_dump_slice() {
        let (mut pe, dump_buf) = synthetic_va_image();
        if let Some(sec) = pe.sections.first_mut() {
            sec.extra_data = Some(vec![0x90, 0x90, 0xC3]);
            sec.virtual_size = 3;
        }
        let opts = base_opts(&pe);
        let plan = plan_from_host_dump(&pe, &dump_buf, &opts).expect("plan");
        assert_eq!(plan.sections[0].data, vec![0x90, 0x90, 0xC3]);
    }

    #[test]
    fn empty_sections_error() {
        let mut plan = RebuildPlan::pe32_plus();
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        let img = rebuild_pe_image(&plan).unwrap();
        let mut pe = PeHeader::from_bytes(&img).unwrap();
        pe.sections.clear();
        let opts = PureRebuildEmitOptions::default();
        let err = plan_from_host_dump(&pe, &[], &opts).unwrap_err();
        assert!(matches!(err, PeError::Parse(_)));
    }

    #[test]
    fn preserve_host_section_va_and_import_extra_data() {
        let (mut pe, mut dump_buf) = synthetic_va_image();
        let sa = pe.section_alignment.max(0x1000);
        let import_rva = pe.sections[0].virtual_address + sa;
        pe.sections.push(crate::header::PeSection {
            header: crate::header::ImageSectionHeader {
                name: *b".import\0",
                virtual_size: 0x80,
                virtual_address: import_rva,
                size_of_raw_data: 0x200,
                pointer_to_raw_data: 0,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0xC000_0040,
            },
            name: ".import".into(),
            virtual_address: import_rva,
            virtual_size: 0x80,
            raw_offset: 0,
            raw_size: 0x200,
            characteristics: 0xC000_0040,
            extra_data: Some(vec![0xAB; 0x80]),
        });
        pe.nt_headers.optional_header.data_directory[DIR_IMPORT] = ImageDataDirectory {
            virtual_address: import_rva,
            size: 0x28,
        };
        pe.nt_headers.optional_header.data_directory[DIR_IAT] = ImageDataDirectory {
            virtual_address: 0x1500,
            size: 0x10,
        };
        let need = (import_rva as usize) + 0x1000;
        if dump_buf.len() < need {
            dump_buf.resize(need, 0);
        }
        pe.nt_headers.optional_header.size_of_image =
            align_up(need as u32, pe.section_alignment.max(0x1000));

        let opts = base_opts(&pe);
        let plan = plan_from_host_dump(&pe, &dump_buf, &opts).expect("plan");
        assert!(plan.sections.iter().any(|s| s.name == ".import"));
        assert_eq!(
            plan.sections
                .iter()
                .find(|s| s.name == ".import")
                .unwrap()
                .virtual_address,
            Some(import_rva)
        );
        assert!(plan.fallback_data_directories.is_some());

        let (out, host, pure) =
            emit_pure_rebuild_with_parity(&pe, &dump_buf, &opts).expect("emit parity");
        let re = PeHeader::from_bytes(&out).expect("reparse");
        let import_sec = re
            .sections
            .iter()
            .find(|s| s.name.starts_with(".import"))
            .expect(".import present");
        assert_eq!(import_sec.virtual_address, import_rva);
        assert_eq!(
            re.nt_headers.optional_header.data_directory[DIR_IMPORT].virtual_address,
            import_rva
        );
        assert_eq!(
            re.nt_headers.optional_header.data_directory[DIR_IAT].virtual_address,
            0x1500
        );
        let mismatches = host.structural_mismatches(&pure);
        assert!(
            mismatches.is_empty(),
            "structural mismatches: {mismatches:?}"
        );
    }

    #[test]
    fn rebind_flags_off_skip_typed_exception_reloc() {
        let (pe, dump_buf) = synthetic_va_image();
        let mut opts = base_opts(&pe);
        opts.rebind_exceptions = false;
        opts.rebind_relocations = false;
        let plan = plan_from_host_dump(&pe, &dump_buf, &opts).expect("plan");
        assert!(plan.exceptions.is_none());
        assert!(plan.relocations.is_empty());
    }

    /// R1-E close-out corpus: host dump model with content-carried import/IAT,
    /// dual emit (legacy write_output_file vs pure rebuild), structural parity,
    /// and independent R0B acceptance on the pure candidate.
    ///
    /// Not byte-identical; not runtime. Typed import rebind remains out of scope.
    #[test]
    fn r1e_dual_path_import_content_structural_corpus() {
        use super::super::output_writer::write_output_file;
        use super::super::types::{ContainerRestoreMode, DumpOptions, DumpProfile};
        use crate::header::{ImageDataDirectory, ImageSectionHeader, PeSection};
        use crate::import_table::{ImportModule, ImportTableBuilder, ImportThunk};
        use mida_acceptance::{check_static, CheckStaticOptions, Verdict, ROLE_CANDIDATE};

        // --- Host-prepared model (what dump_process has after IAT rebuild) ---
        let (mut pe, mut dump_buf) = synthetic_va_image();
        let sa = pe.section_alignment.max(0x1000);
        let import_rva = pe.sections[0].virtual_address + sa;

        let mut imports = ImportTableBuilder::new(true);
        {
            let m: &mut ImportModule = imports.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0,
                function_name: Some("ExitProcess".into()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let (import_bytes, _str_base, iat_off) = imports.build_section_data(import_rva);
        let iat_rva = import_rva + iat_off;
        let import_dir_size = 40u32; // one descriptor + null
        let iat_dir_size = 16u32; // one slot + null terminator (x64)
        let fa = pe.file_alignment.max(0x200);
        // Pad import payload to file alignment so legacy write_output_file
        // (which sizes the file from extra_data.len()) keeps SizeOfRawData in-bounds.
        let mut import_payload = import_bytes;
        let import_raw_size = align_up(import_payload.len() as u32, fa);
        import_payload.resize(import_raw_size as usize, 0);
        // Realistic host layout: place .import after the first section's raw span.
        // (legacy write_output_file needs PointerToRawData for directory file mapping;
        // pure rebuild remaps regardless.)
        let import_raw_ptr = {
            let first = &pe.sections[0];
            let end = first
                .header
                .pointer_to_raw_data
                .saturating_add(first.header.size_of_raw_data);
            align_up(end.max(0x400), fa)
        };
        let import_vsize = import_payload.len() as u32;

        pe.sections.push(PeSection {
            header: ImageSectionHeader {
                name: *b".import\0",
                virtual_size: import_vsize,
                virtual_address: import_rva,
                size_of_raw_data: import_raw_size,
                pointer_to_raw_data: import_raw_ptr,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0xC000_0040,
            },
            name: ".import".into(),
            virtual_address: import_rva,
            virtual_size: import_vsize,
            raw_offset: import_raw_ptr,
            raw_size: import_raw_size,
            characteristics: 0xC000_0040,
            extra_data: Some(import_payload.clone()),
        });
        pe.nt_headers.optional_header.data_directory[DIR_IMPORT] = ImageDataDirectory {
            virtual_address: import_rva,
            size: import_dir_size,
        };
        pe.nt_headers.optional_header.data_directory[DIR_IAT] = ImageDataDirectory {
            virtual_address: iat_rva,
            size: iat_dir_size,
        };
        let need = (import_rva as usize) + import_payload.len().max(0x1000);
        if dump_buf.len() < need {
            dump_buf.resize(need, 0);
        }
        // VA-linear contract: import payload also present at import_rva.
        dump_buf[import_rva as usize..import_rva as usize + import_payload.len()]
            .copy_from_slice(&import_payload);
        pe.nt_headers.optional_header.size_of_image =
            align_up(need as u32, pe.section_alignment.max(0x1000));
        pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;

        let pure_opts = base_opts(&pe);

        // --- Pure path ---
        let (pure_bytes, host_snap, pure_snap) =
            emit_pure_rebuild_with_parity(&pe, &dump_buf, &pure_opts).expect("pure emit");
        let pure_pe = PeHeader::from_bytes(&pure_bytes).expect("reparse pure");
        assert!(
            pure_pe
                .sections
                .iter()
                .any(|s| s.name.starts_with(".import")),
            "pure emit must keep host .import content section"
        );
        assert_eq!(
            pure_pe.nt_headers.optional_header.data_directory[DIR_IMPORT].virtual_address,
            import_rva
        );
        assert_eq!(
            pure_pe.nt_headers.optional_header.data_directory[DIR_IAT].virtual_address,
            iat_rva
        );
        let mismatches = host_snap.structural_mismatches(&pure_snap);
        assert!(
            mismatches.is_empty(),
            "R1-E host↔pure structural mismatches: {mismatches:?}"
        );

        // --- Legacy path (host write_output_file) ---
        let dump_opts = DumpOptions {
            image_base: pe.image_base,
            entry_point: pe.entry_point,
            fix_imports: false,
            create_data_sections: false,
            shrink: false,
            output_path: std::path::PathBuf::from("NUL"),
            iat_location: None,
            additional_iat_locations: Vec::new(),
            executable_path: None,
            early_section_snapshots: Vec::new(),
            container_restore: ContainerRestoreMode::Off,
            profile: DumpProfile::OreansClassic,
            security_cookie_rva: None,
            security_cookie_complement_rva: None,
            pure_rebuild: false,
            dump_timing: crate::DumpTiming::Immediate,
            section_content_reference: None,
            capture_policy: crate::DumpCapturePolicy::default(),
        };
        let mut pe_legacy = pe.clone();
        let legacy_bytes = write_output_file(
            &mut pe_legacy,
            &dump_buf,
            None,
            &[],
            0,
            true,
            &dump_opts,
            pe.entry_point,
            &[],
        )
        .expect("legacy write_output_file");
        let legacy_pe = PeHeader::from_bytes(&legacy_bytes).expect("reparse legacy");
        assert!(
            legacy_pe
                .sections
                .iter()
                .any(|s| s.name.starts_with(".import")),
            "legacy emit must keep .import"
        );
        // Directory RVAs are structural contract (not file layout identity).
        assert_eq!(
            legacy_pe.nt_headers.optional_header.data_directory[DIR_IMPORT].virtual_address,
            import_rva
        );
        assert_eq!(
            legacy_pe.nt_headers.optional_header.data_directory[DIR_IAT].virtual_address,
            iat_rva
        );

        // --- Independent R0B acceptance (pure candidate; never Accepted) ---
        let acc_opts = CheckStaticOptions {
            role: Some(ROLE_CANDIDATE.to_string()),
            ..Default::default()
        };
        let pure_report = check_static(&pure_bytes, &acc_opts);
        assert_ne!(pure_report.verdict, Verdict::Accepted);
        assert_eq!(
            pure_report.verdict,
            Verdict::StructuralPassBehaviorPending,
            "pure dual-path candidate must pass R0B static gates: {:?}",
            pure_report.failures
        );
        assert!(
            pure_report.failures.is_empty(),
            "{:?}",
            pure_report.failures
        );

        // Legacy is also judged when it is a well-formed PE; pointer fixups may
        // differ, but structural loader gates should still pass on this corpus.
        let legacy_report = check_static(&legacy_bytes, &acc_opts);
        assert_ne!(legacy_report.verdict, Verdict::Accepted);
        assert_eq!(
            legacy_report.verdict,
            Verdict::StructuralPassBehaviorPending,
            "legacy dual-path candidate must pass R0B static gates: {:?}",
            legacy_report.failures
        );
    }

    /// Dual-path corpus from a pure-built oracle mapped to VA-linear dump_buf
    /// (closer to production capture → rebuild), without host extra_data.
    #[test]
    fn r1e_dual_path_from_va_mapped_oracle_structural() {
        use crate::import_table::{ImportModule, ImportTableBuilder, ImportThunk};
        use crate::rebuild::rebuild_pe_image_with_meta;
        use mida_acceptance::{check_static, CheckStaticOptions, Verdict, ROLE_CANDIDATE};

        let mut imports = ImportTableBuilder::new(true);
        {
            let m: &mut ImportModule = imports.add_module("kernel32.dll");
            m.thunks.push(ImportThunk {
                iat_address: 0,
                function_name: Some("ExitProcess".into()),
                ordinal: None,
                is_64bit: true,
            });
        }
        let mut plan = RebuildPlan::pe32_plus();
        plan.image_base = 0x140000000;
        plan.entry_point_rva = 0x1000;
        plan.sections
            .push(PlannedSection::new(".text", 0x6000_0020, vec![0xC3]));
        plan.imports = Some(imports);
        let meta = rebuild_pe_image_with_meta(&plan).expect("oracle rebuild");
        let oracle = meta.image;
        let pe_file = PeHeader::from_bytes(&oracle).expect("parse oracle");

        // VA-linear dump (index == RVA), headers + sections.
        let size = pe_file.size_of_image() as usize;
        let mut dump_buf = vec![0u8; size.max(0x3000)];
        let hdr_end = pe_file
            .sections
            .iter()
            .filter(|s| s.header.pointer_to_raw_data > 0)
            .map(|s| s.header.pointer_to_raw_data as usize)
            .min()
            .unwrap_or(0x400)
            .min(oracle.len());
        let hdr_copy = hdr_end.min(dump_buf.len()).min(oracle.len());
        dump_buf[..hdr_copy].copy_from_slice(&oracle[..hdr_copy]);
        for sec in &pe_file.sections {
            let ptr = sec.header.pointer_to_raw_data as usize;
            let raw = sec.header.size_of_raw_data as usize;
            let va_off = sec.virtual_address as usize;
            if ptr == 0 || raw == 0 || ptr + raw > oracle.len() {
                continue;
            }
            let end = (va_off + raw).min(dump_buf.len());
            if va_off >= end {
                continue;
            }
            let n = end - va_off;
            dump_buf[va_off..end].copy_from_slice(&oracle[ptr..ptr + n]);
        }

        // Host model: headers from oracle file PE (file layout), dump is VA-linear.
        let pe = pe_file;
        let pure_opts = base_opts(&pe);
        let (pure_bytes, host_snap, pure_snap) =
            emit_pure_rebuild_with_parity(&pe, &dump_buf, &pure_opts).expect("pure emit");
        let mismatches = host_snap.structural_mismatches(&pure_snap);
        // Typed .idata from oracle becomes content sections; import/IAT dirs must
        // still match host when carry_host_data_directories is on.
        assert!(
            mismatches.is_empty(),
            "oracle VA-map host↔pure structural mismatches: {mismatches:?}"
        );

        let re = PeHeader::from_bytes(&pure_bytes).expect("reparse pure");
        assert_eq!(
            re.nt_headers.optional_header.data_directory[DIR_IMPORT].virtual_address,
            pe.nt_headers.optional_header.data_directory[DIR_IMPORT].virtual_address
        );
        assert_eq!(
            re.nt_headers.optional_header.data_directory[DIR_IAT].virtual_address,
            pe.nt_headers.optional_header.data_directory[DIR_IAT].virtual_address
        );

        let report = check_static(
            &pure_bytes,
            &CheckStaticOptions {
                role: Some(ROLE_CANDIDATE.to_string()),
                ..Default::default()
            },
        );
        assert_ne!(report.verdict, Verdict::Accepted);
        assert_eq!(
            report.verdict,
            Verdict::StructuralPassBehaviorPending,
            "VA-mapped oracle pure candidate: {:?}",
            report.failures
        );
    }

    /// Phase-2 live parity: when exception/reloc rebind is off, host content
    /// sections that *contain* those directories (e.g. Themida `.winlice`) must
    /// stay in the plan. Rebind-on would skip the cover section and emit a
    /// trailing typed `.pdata` instead.
    #[test]
    fn content_cover_sections_kept_when_rebind_off() {
        let (mut pe, mut dump_buf) = synthetic_va_image();
        let sa = pe.section_alignment.max(0x1000);
        // Place a large cover section after .text that owns a synthetic exception DD.
        let cover_rva = pe.sections[0].virtual_address + sa * 2;
        let cover_vsize = 0x1000u32;
        let exc_rva = cover_rva + 0x40;
        let exc_size = 0x30u32;
        pe.sections.push(crate::header::PeSection {
            header: crate::header::ImageSectionHeader {
                // PE section name is 8 bytes; ".winlice" fills the field (no NUL).
                name: *b".winlice",
                virtual_size: cover_vsize,
                virtual_address: cover_rva,
                size_of_raw_data: cover_vsize,
                pointer_to_raw_data: 0,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0x6000_0020,
            },
            name: ".winlice".into(),
            virtual_address: cover_rva,
            virtual_size: cover_vsize,
            raw_offset: 0,
            raw_size: cover_vsize,
            characteristics: 0x6000_0020,
            extra_data: None,
        });
        pe.nt_headers.optional_header.data_directory[DIR_EXCEPTION] = ImageDataDirectory {
            virtual_address: exc_rva,
            size: exc_size,
        };
        let need = (cover_rva + cover_vsize) as usize;
        if dump_buf.len() < need {
            dump_buf.resize(need, 0xCC);
        }
        pe.nt_headers.optional_header.size_of_image =
            align_up(need as u32, pe.section_alignment.max(0x1000));
        pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;

        // Preferred base (not a runtime ASLR value).
        pe.nt_headers.optional_header.image_base = 0x0000_0140_0000_0000;
        pe.image_base = 0x0000_0140_0000_0000;

        let mut opts = base_opts(&pe);
        opts.rebind_exceptions = false;
        opts.rebind_relocations = false;
        opts.image_base = pe.image_base;

        let plan = plan_from_host_dump(&pe, &dump_buf, &opts).expect("plan");
        assert!(
            plan.sections.iter().any(|s| s.name == ".winlice"),
            "rebind-off must keep exception cover section; got {:?}",
            plan.sections
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(plan.image_base, 0x0000_0140_0000_0000);

        let out = emit_pure_rebuild(&pe, &dump_buf, &opts).expect("emit");
        let re = PeHeader::from_bytes(&out).expect("reparse");
        assert_eq!(re.image_base, 0x0000_0140_0000_0000);
        assert!(
            re.sections.iter().any(|s| s.name.starts_with(".winlice")),
            "emit must retain .winlice name"
        );
        // Exception DD carried via host fallback when rebind is off.
        assert_eq!(
            re.nt_headers.optional_header.data_directory[DIR_EXCEPTION].virtual_address,
            exc_rva
        );
    }

    /// Rebind-on skips cover sections (documents the Phase-1 live pure bug class).
    #[test]
    fn exception_rebind_skips_cover_section() {
        let (mut pe, mut dump_buf) = synthetic_va_image();
        let sa = pe.section_alignment.max(0x1000);
        let cover_rva = pe.sections[0].virtual_address + sa * 2;
        let cover_vsize = 0x1000u32;
        let exc_rva = cover_rva + 0x40;
        // Minimal RUNTIME_FUNCTION-like bytes so builder can parse something;
        // even empty builder path: section_covers skip only needs non-empty exceptions.
        pe.sections.push(crate::header::PeSection {
            header: crate::header::ImageSectionHeader {
                name: *b".winlice",
                virtual_size: cover_vsize,
                virtual_address: cover_rva,
                size_of_raw_data: cover_vsize,
                pointer_to_raw_data: 0,
                pointer_to_relocations: 0,
                pointer_to_linenumbers: 0,
                number_of_relocations: 0,
                number_of_linenumbers: 0,
                characteristics: 0x6000_0020,
            },
            name: ".winlice".into(),
            virtual_address: cover_rva,
            virtual_size: cover_vsize,
            raw_offset: 0,
            raw_size: cover_vsize,
            characteristics: 0x6000_0020,
            extra_data: None,
        });
        pe.nt_headers.optional_header.data_directory[DIR_EXCEPTION] = ImageDataDirectory {
            virtual_address: exc_rva,
            size: 12,
        };
        let need = (cover_rva + cover_vsize) as usize;
        if dump_buf.len() < need {
            dump_buf.resize(need, 0);
        }
        // One RUNTIME_FUNCTION: BeginAddress, EndAddress, UnwindInfoAddress (3 x u32)
        let off = exc_rva as usize;
        dump_buf[off..off + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        dump_buf[off + 4..off + 8].copy_from_slice(&0x1010u32.to_le_bytes());
        dump_buf[off + 8..off + 12].copy_from_slice(&0x2000u32.to_le_bytes());
        pe.nt_headers.optional_header.size_of_image =
            align_up(need as u32, pe.section_alignment.max(0x1000));
        pe.nt_headers.file_header.number_of_sections = pe.sections.len() as u16;

        let mut opts = base_opts(&pe);
        opts.rebind_exceptions = true;
        let plan = plan_from_host_dump(&pe, &dump_buf, &opts).expect("plan");
        // If rebind produced entries, cover section is skipped.
        if plan
            .exceptions
            .as_ref()
            .map(|b| b.function_count())
            .unwrap_or(0)
            > 0
        {
            assert!(
                !plan.sections.iter().any(|s| s.name == ".winlice"),
                "rebind-on should skip exception cover section"
            );
        }
    }
}
