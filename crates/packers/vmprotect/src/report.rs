//! The static structure report.
//!
//! Everything here is computed from the file alone — no debugger, no desktop
//! session — which is what makes the VMProtect branch testable in CI while
//! the Themida `unpack` path cannot be.
//!
//! ## What the report is for
//!
//! For `MinProtection` the answer to "what did VMProtect protect?" is
//! countable: the in-file `jmp rel32` stubs that leave ordinary code and land
//! in the runtime section.  Measured: **14** such stubs in
//! `D:\Projects\lunlun\伦伦软件.exe`, all landing in the tail of `.vmp0`
//! (`0x1402aee3c` … `0x1402b078c`).
//!
//! For `Packed` there are no trampolines to find — the code sections have no
//! file bytes, so nothing decodes — and the report says so instead of
//! printing a misleading zero.

use std::fmt;

use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use mida_packer_api::VmProtectMode;
use mida_pe::PeHeader;

use crate::detect::{
    classify_mode, fptable_section, is_executable, is_not_paged, packed_sections,
    plausible_runtime_function_triples, runtime_sections, scrambled_pdata, section_bytes,
    section_name,
};
use crate::resources::{large_resources, LargeResource};

/// Directory index of the exception table.
const EXCEPTION_DIRECTORY_INDEX: usize = 3;
/// `RUNTIME_FUNCTION` is three `u32`s.
const TRIPLE_BYTES: usize = 12;
/// How many triples are sampled when judging a table.
const TRIPLE_SAMPLE: usize = 64;

/// One `jmp rel32` that leaves ordinary code and lands in the runtime section.
///
/// This is the static footprint of a virtualised function: the original body
/// was replaced by a single jump into VMProtect's VM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trampoline {
    /// RVA of the `jmp`.
    pub stub_rva: u32,
    /// RVA it jumps to — inside a runtime section.
    pub target_rva: u32,
    /// Name of the target section.
    pub target_section: String,
}

/// The relocated exception table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionDirectory {
    /// RVA from the data directory.
    pub rva: u32,
    /// Declared size.
    pub size: u32,
    /// Section the table lives in.
    pub section: String,
    /// File offset, or `None` when the table is not in the file.
    pub file_offset: Option<u32>,
    /// Plausible `RUNTIME_FUNCTION` triples out of `sampled`.
    pub plausible: usize,
    /// How many triples were sampled.
    pub sampled: usize,
}

/// The static structure report for a VMProtect sample.
#[derive(Debug, Clone, PartialEq)]
pub struct VmProtectReport {
    /// Classified mode.
    pub mode: VmProtectMode,
    /// Sections carrying VMProtect's code and metadata, by name.
    pub runtime_sections: Vec<String>,
    /// Executable sections with no file bytes.
    pub packed_sections: Vec<String>,
    /// `.fptable` as `"name (raw_size 0x…)"`, when present.
    pub fptable: Option<String>,
    /// Entry point RVA.
    pub entry_point: u32,
    /// Section the entry point lands in.
    pub entry_point_section: Option<String>,
    /// `true` when the entry point's bytes are in the file.
    pub entry_point_in_file: bool,
    /// Virtualised-function stubs found in ordinary code.
    pub trampolines: Vec<Trampoline>,
    /// `(plausible, sampled)` triples in `.pdata`, when it has file bytes.
    pub scrambled_pdata: Option<(usize, usize)>,
    /// The relocated exception table, when there is one.
    pub exception_directory: Option<ExceptionDirectory>,
    /// Every resource of at least 1 MiB.
    pub large_resources: Vec<LargeResource>,
}

impl VmProtectReport {
    /// `true` when the code we would want to read is not in the file, so a
    /// static report cannot show it and only a runtime image dump can.
    pub fn requires_runtime_dump(&self) -> bool {
        self.mode == VmProtectMode::Packed || !self.entry_point_in_file
    }
}

/// Name of the section containing `rva`, using `max(virtual_size, raw_size)`
/// as the extent.
///
/// `mida_pe::PeHeader::get_section_by_rva` compares against `virtual_size`
/// only, which misses the tail of sections whose raw size exceeds their
/// virtual size — the shape of `MinProtection`'s `.rsrc`.
pub fn section_of(pe: &PeHeader, rva: u32) -> Option<String> {
    pe.sections
        .iter()
        .find(|s| {
            let end = s
                .virtual_address
                .saturating_add(s.virtual_size.max(s.raw_size));
            rva >= s.virtual_address && rva < end
        })
        .map(|s| section_name(s).to_string())
}

/// `jmp rel32` stubs in ordinary code that land in a runtime section.
///
/// The runtime section itself is skipped: its contents are VM bytecode, and
/// decoding it as x86 produces noise rather than facts.
pub fn trampolines(pe: &PeHeader, image: &[u8]) -> Vec<Trampoline> {
    let runtime: Vec<(u32, u32)> = runtime_sections(pe, image)
        .iter()
        .map(|s| {
            (
                s.virtual_address,
                s.virtual_address
                    .saturating_add(s.virtual_size.max(s.raw_size)),
            )
        })
        .collect();
    if runtime.is_empty() {
        return Vec::new();
    }

    let bitness: u32 = if pe.is_64bit { 64 } else { 32 };
    let mut out: Vec<Trampoline> = Vec::new();
    for s in pe.sections.iter() {
        if !is_executable(s) || is_not_paged(s) {
            continue;
        }
        let Some(bytes) = section_bytes(s, image) else {
            continue;
        };
        let ip = pe.image_base + s.virtual_address as u64;
        let mut dec = Decoder::with_ip(bitness, bytes, ip, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        while dec.can_decode() {
            dec.decode_out(&mut ins);
            if ins.is_invalid() || ins.mnemonic() != Mnemonic::Jmp {
                continue;
            }
            if !matches!(
                ins.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                continue;
            }
            let stub_va = ins.ip();
            let target = ins.near_branch_target();
            if stub_va < pe.image_base || target < pe.image_base {
                continue;
            }
            let stub_rva = (stub_va - pe.image_base) as u32;
            let target_rva = (target - pe.image_base) as u32;
            if !runtime.iter().any(|(lo, hi)| target_rva >= *lo && target_rva < *hi) {
                continue;
            }
            out.push(Trampoline {
                stub_rva,
                target_rva,
                target_section: section_of(pe, target_rva).unwrap_or_default(),
            });
        }
    }
    out.sort_by_key(|t| t.stub_rva);
    out.dedup_by_key(|t| t.stub_rva);
    out
}

/// The exception table, and whether it is in the file.
///
/// Measured: both samples relocate it into their runtime section
/// (`0x2b2e50` in `.vmp0`, `0x1b99770` in `.rdata2`) with 64/64 plausible
/// triples, while `.pdata` measures `0/64` (`MinProtection`) or is absent
/// (`Packed`).
pub fn exception_directory(pe: &PeHeader, image: &[u8]) -> Option<ExceptionDirectory> {
    let dd = &pe.nt_headers.optional_header.data_directory[EXCEPTION_DIRECTORY_INDEX];
    if dd.virtual_address == 0 || dd.size == 0 {
        return None;
    }
    let rva = dd.virtual_address;
    let file_offset = pe
        .rva_to_offset(rva)
        .filter(|o| (*o as usize) < image.len());
    let (plausible, sampled) = match file_offset {
        Some(off) => {
            let slice = &image[off as usize..];
            let want = (dd.size as usize / TRIPLE_BYTES).min(TRIPLE_SAMPLE) * TRIPLE_BYTES;
            let take = slice.len().min(want);
            plausible_runtime_function_triples(&slice[..take], TRIPLE_SAMPLE)
        }
        None => (0, 0),
    };
    Some(ExceptionDirectory {
        rva,
        size: dd.size,
        section: section_of(pe, rva).unwrap_or_default(),
        file_offset,
        plausible,
        sampled,
    })
}

/// Build the full static report.  Infallible by design: an unreadable part is
/// reported as absent, never as an error, so one unreadable section cannot
/// suppress the facts that *are* readable.
pub fn analyze(pe: &PeHeader, image: &[u8]) -> VmProtectReport {
    let entry_point_in_file = pe
        .rva_to_offset(pe.entry_point)
        .map(|o| (o as usize) < image.len())
        .unwrap_or(false);

    VmProtectReport {
        mode: classify_mode(pe),
        runtime_sections: runtime_sections(pe, image)
            .iter()
            .map(|s| section_name(s).to_string())
            .collect(),
        packed_sections: packed_sections(pe)
            .iter()
            .map(|s| section_name(s).to_string())
            .collect(),
        fptable: fptable_section(pe)
            .map(|s| format!("{} (raw_size {:#x})", section_name(s), s.raw_size)),
        entry_point: pe.entry_point,
        entry_point_section: section_of(pe, pe.entry_point),
        entry_point_in_file,
        trampolines: trampolines(pe, image),
        scrambled_pdata: scrambled_pdata(pe, image),
        exception_directory: exception_directory(pe, image),
        large_resources: large_resources(pe, image),
    }
}

impl fmt::Display for VmProtectReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "VMProtect ({})", self.mode.label())?;
        writeln!(
            f,
            "  entry point         {:#x} in {:?}{}",
            self.entry_point,
            self.entry_point_section.as_deref().unwrap_or("?"),
            if self.entry_point_in_file {
                ""
            } else {
                " (not in file)"
            }
        )?;
        writeln!(
            f,
            "  runtime sections    {}",
            if self.runtime_sections.is_empty() {
                "none".to_string()
            } else {
                self.runtime_sections.join(", ")
            }
        )?;
        writeln!(
            f,
            "  packed sections     {}",
            if self.packed_sections.is_empty() {
                "none".to_string()
            } else {
                self.packed_sections.join(", ")
            }
        )?;
        writeln!(
            f,
            "  .fptable            {}",
            self.fptable.as_deref().unwrap_or("absent")
        )?;
        if self.trampolines.is_empty() {
            let why = if self.requires_runtime_dump() {
                "none (code sections have no file bytes — runtime dump required)"
            } else {
                "none"
            };
            writeln!(f, "  virtualised stubs   {why}")?;
        } else {
            writeln!(
                f,
                "  virtualised stubs   {} ({} … {})",
                self.trampolines.len(),
                self.trampolines
                    .first()
                    .map(|t| format!("{:#x}", t.stub_rva))
                    .unwrap_or_default(),
                self.trampolines
                    .last()
                    .map(|t| format!("{:#x}", t.stub_rva))
                    .unwrap_or_default()
            )?;
        }
        match self.scrambled_pdata {
            Some((ok, n)) => writeln!(f, "  .pdata              {ok}/{n} plausible triples")?,
            None => writeln!(f, "  .pdata              absent")?,
        }
        match &self.exception_directory {
            Some(e) => writeln!(
                f,
                "  exception directory rva {:#x} in {:?}, {}/{} plausible triples{}",
                e.rva,
                e.section,
                e.plausible,
                e.sampled,
                if e.file_offset.is_none() {
                    " (not in file)"
                } else {
                    ""
                }
            )?,
            None => writeln!(f, "  exception directory none")?,
        }
        if self.large_resources.is_empty() {
            writeln!(f, "  large resources     none")?;
        } else {
            writeln!(f, "  large resources     {}:", self.large_resources.len())?;
            for r in &self.large_resources {
                writeln!(f, "    {}", r.one_line())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{pe_with_sections, sec_va};
    use mida_pe::ImageDataDirectory;

    const EXE: u32 = 0x6000_0020;
    const VM: u32 = 0x6800_0060;

    #[test]
    fn section_of_uses_max_virtual_and_raw_size() {
        // `MinProtection`'s `.rsrc`: raw_size 0xf6c600 > virtual_size 0xf6c54f,
        // so an rva in the last 0xb1 bytes belongs to `.rsrc` and would be
        // missed by an extent of `virtual_size` alone.
        let pe = pe_with_sections(vec![
            sec_va(".text", 0x1000, 0x722a4, 0x72400, 0x400, EXE),
            sec_va(".rsrc", 0x2b9000, 0xf6c54f, 0xf6c600, 0x2b3c00, 0x4000_0040),
        ]);
        assert_eq!(section_of(&pe, 0x1000).as_deref(), Some(".text"));
        assert_eq!(section_of(&pe, 0x732a3).as_deref(), Some(".text"));
        assert_eq!(section_of(&pe, 0x2b9000).as_deref(), Some(".rsrc"));
        assert_eq!(section_of(&pe, 0x1225550).as_deref(), Some(".rsrc"));
        // Past every section is `None`, not the last section.
        assert_eq!(section_of(&pe, 0x2b80000), None);
    }

    #[test]
    fn trampolines_finds_only_jumps_into_the_runtime_section() {
        // `.text` at VA 0x1000 holds two jumps: one into `.vmp0` at 0x2000
        // (a virtualised function) and one inside `.text` at 0x1008 (ordinary
        // control flow, which must NOT be reported).
        let mut image = vec![0u8; 0x20];
        image[0..5].copy_from_slice(&[0xe9, 0xfb, 0x0f, 0x00, 0x00]); // jmp 0x140002000
        image[5..10].copy_from_slice(&[0xe9, 0xfe, 0xff, 0xff, 0xff]); // jmp 0x140001008
        let pe = pe_with_sections(vec![
            sec_va(".text", 0x1000, 0x10, 0x10, 0x0, EXE),
            sec_va(".vmp0", 0x2000, 0x10, 0x10, 0x10, VM),
        ]);
        let t = trampolines(&pe, &image);
        assert_eq!(t.len(), 1, "intra-.text jumps are not virtualised functions");
        assert_eq!(t[0].stub_rva, 0x1000);
        assert_eq!(t[0].target_rva, 0x2000);
        assert_eq!(t[0].target_section, ".vmp0");
    }

    #[test]
    fn trampolines_is_empty_when_there_is_no_runtime_section_or_no_code_bytes() {
        let mut image = vec![0u8; 0x20];
        image[0..5].copy_from_slice(&[0xe9, 0xfb, 0x0f, 0x00, 0x00]);
        // No runtime section: nothing to virtualise into.
        let no_runtime = pe_with_sections(vec![sec_va(".text", 0x1000, 0x10, 0x10, 0x0, EXE)]);
        assert!(trampolines(&no_runtime, &image).is_empty());

        // `Packed`: `.text` has no file bytes, so nothing decodes.  The empty
        // result here is a *finding* ("code is not in the file"), which is why
        // the report says so explicitly instead of relying on the count.
        let packed = pe_with_sections(vec![
            sec_va(".text", 0x1000, 0x12b05c, 0x0, 0x0, EXE),
            sec_va(".rdata2", 0x73e000, 0x1466354, 0x1466400, 0x0, VM),
        ]);
        assert!(trampolines(&packed, &image).is_empty());
    }

    #[test]
    fn exception_directory_reads_the_directory_and_reports_absent_when_empty() {
        let mut out = vec![0u8; 0x10];
        // One real triple: start 0x1010, end 0x103d, unwind 0x8b430.
        out[0..12].copy_from_slice(&[
            0x10, 0x10, 0x00, 0x00, 0x3d, 0x10, 0x00, 0x00, 0x30, 0xb4, 0x08, 0x00,
        ]);
        let mut pe = pe_with_sections(vec![sec_va(".vmp0", 0x2000, 0x100, 0x100, 0x0, VM)]);
        pe.nt_headers.optional_header.data_directory[EXCEPTION_DIRECTORY_INDEX] =
            ImageDataDirectory {
                virtual_address: 0x2000,
                size: 0xc,
            };
        let e = exception_directory(&pe, &out).expect("directory present");
        assert_eq!(e.rva, 0x2000);
        assert_eq!(e.section, ".vmp0");
        assert_eq!(e.file_offset, Some(0));
        assert_eq!((e.plausible, e.sampled), (1, 1));

        // An empty data directory is `None`, not a fake zero.
        let empty = pe_with_sections(vec![]);
        assert!(exception_directory(&empty, &out).is_none());
    }

    #[test]
    fn analyze_reports_the_two_measured_modes_accurately() {
        // MinProtection: everything in the file.
        let mut image = vec![0u8; 0x400];
        image[0..5].copy_from_slice(&[0xe9, 0xfb, 0x0f, 0x00, 0x00]);
        let mut lunlun = pe_with_sections(vec![
            // `.text` must be readable, so its declared raw size has to fit
            // inside the fixture image.
            sec_va(".text", 0x1000, 0x10, 0x10, 0x0, EXE),
            sec_va(".vmp0", 0x2000, 0x400, 0x200, 0x200, VM),
        ]);
        lunlun.entry_point = 0x1000;
        let r = analyze(&lunlun, &image);
        assert_eq!(r.mode, VmProtectMode::MinProtection);
        assert!(!r.requires_runtime_dump());
        assert!(r.entry_point_in_file);
        assert_eq!(r.entry_point_section.as_deref(), Some(".text"));
        assert_eq!(r.runtime_sections, vec![".vmp0"]);
        assert!(r.packed_sections.is_empty());
        assert_eq!(r.trampolines.len(), 1);
        let text = r.to_string();
        assert!(text.contains("VMProtect (min-protection)"), "{text}");
        assert!(text.contains("virtualised stubs   1"), "{text}");

        // Packed: code absent, so the report has to say a runtime dump is
        // required rather than implying there is nothing to unpack.
        let mut packed = pe_with_sections(vec![
            sec_va(".text", 0x1000, 0x12b05c, 0x0, 0x0, EXE),
            sec_va(".rdata2", 0x73e000, 0x1466354, 0x1466400, 0x0, VM),
        ]);
        packed.entry_point = 0x130bbfb;
        let rp = analyze(&packed, &image);
        assert_eq!(rp.mode, VmProtectMode::Packed);
        assert!(rp.requires_runtime_dump());
        assert!(!rp.entry_point_in_file);
        assert_eq!(rp.packed_sections, vec![".text"]);
        assert!(rp.trampolines.is_empty());
        let ptext = rp.to_string();
        assert!(ptext.contains("VMProtect (packed)"), "{ptext}");
        assert!(ptext.contains("runtime dump required"), "{ptext}");
        assert!(ptext.contains("not in file"), "{ptext}");
    }
}
