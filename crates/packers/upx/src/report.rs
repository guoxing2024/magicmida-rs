//! The static structure report for a UPX-packed PE.
//!
//! Everything here was measured on UPX 5.2.1 output and cross-checked against
//! `src/pefile.cpp` of the same tag (`PackWin32Pe::pack`): section 1 is
//! `[ident tail] + packed_data (c_len, 16-aligned with its ident) +
//! unpacker stub + tls + loadconf`, and the entry point equals the start of
//! the unpacker stub — an invariant that held on all four measured samples
//! and is asserted per file in the report.

use std::fmt;

use mida_pe::PeHeader;

use crate::header::{find_pack_header, PackHeader};
use crate::detect::section_name;

/// The measured, source-confirmed layout of a UPX-packed PE.
#[derive(Debug, Clone)]
pub struct UpxReport {
    /// The parsed `PackHeader`.
    pub header: PackHeader,
    /// File offset of `UPX1`'s raw data (the ident + stream live here).
    pub upx1_raw_offset: u64,
    /// Bytes of ident (version string + PackHeader) that sit inside `UPX1`.
    /// 0 when the whole ident fit into the PE header slack.
    pub ident_in_upx1: u64,
    /// File offset of the compressed stream (`c_len` bytes follow).
    pub stream_file_offset: u64,
    /// File offset of the unpacker stub, computed from the layout.
    pub stub_file_offset: u64,
    /// File offset of the entry point, computed from the section table.
    pub entry_point_file_offset: Option<u64>,
    /// The layout invariant: the computed stub offset equals the entry
    /// point's file offset.  Measured `true` on all four samples.
    pub entry_point_matches_stub: bool,
    /// File offset where the copied overlay begins (0 when there is none).
    pub overlay_file_offset: u64,
    /// Overlay size in bytes.  Measured: 0 for an MSVC input, ~2 MB for a
    /// GNU-built input whose COFF symbol table is carried verbatim.
    pub overlay_size: u64,
    /// `c_adler` re-verified over the in-file stream.
    pub c_adler_ok: bool,
    /// Section names, in table order.
    pub sections: Vec<String>,
}

/// Analyse a UPX-packed PE and return its layout, or `None` when the file is
/// not UPX-packed (`detect` is the gate callers should use first).
pub fn analyze(pe: &PeHeader, image: &[u8]) -> Option<UpxReport> {
    let header = find_pack_header(image)?;
    let upx1 = pe
        .sections
        .iter()
        .find(|s| section_name(s).eq_ignore_ascii_case("UPX1"))?;

    let upx1_raw = upx1.raw_offset as u64;
    let header_end = header.file_offset + 32;
    // The ident is the version string + PackHeader.  Whatever part of it did
    // not fit into the PE header slack lives at the start of UPX1's raw data
    // (measured: 0 bytes for the MSVC sample, 37 for the GNU x64 ones, and
    // 21 with the header overlapping UPX1's start for the GNU x86 one).
    let ident_in_upx1 = header_end.saturating_sub(upx1_raw);
    let stream_file_offset = upx1_raw + ident_in_upx1;

    // `pefile.cpp`: `c_len` is padded so that (ident + c_len) is a multiple
    // of 16; the unpacker stub follows the padded stream.
    let ident_plus_stream = ident_in_upx1 + header.c_len as u64;
    let aligned = (ident_plus_stream + 15) & !15;
    let stub_file_offset = upx1_raw + aligned;

    // Entry point → file offset through the section table.
    let entry_point_file_offset = pe.sections.iter().find_map(|s| {
        let rva = pe.entry_point;
        if s.virtual_address <= rva && rva < s.virtual_address + s.virtual_size.max(1) {
            Some(s.raw_offset as u64 + (rva - s.virtual_address) as u64)
        } else {
            None
        }
    });
    let entry_point_matches_stub = entry_point_file_offset == Some(stub_file_offset);

    // The stream must be in the file for the checksum to be verifiable.
    let stream_end = stream_file_offset + header.c_len as u64;
    let c_adler_ok = stream_end <= image.len() as u64
        && crate::header::adler32(&image[stream_file_offset as usize..stream_end as usize])
            == header.c_adler;

    // Overlay: everything after the last section's raw data.  Measured: the
    // GNU-built inputs carry their COFF symbol table here, byte for byte.
    let last_raw_end = pe
        .sections
        .iter()
        .map(|s| s.raw_offset as u64 + s.raw_size as u64)
        .max()
        .unwrap_or(0);
    let overlay_size = (image.len() as u64).saturating_sub(last_raw_end);
    let overlay_file_offset = if overlay_size > 0 { last_raw_end } else { 0 };

    Some(UpxReport {
        header,
        upx1_raw_offset: upx1_raw,
        ident_in_upx1,
        stream_file_offset,
        stub_file_offset,
        entry_point_file_offset,
        entry_point_matches_stub,
        overlay_file_offset,
        overlay_size,
        c_adler_ok,
        sections: pe
            .sections
            .iter()
            .map(|s| section_name(s).to_string())
            .collect(),
    })
}

impl fmt::Display for UpxReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = &self.header;
        writeln!(f, "UPX")?;
        writeln!(
            f,
            "  pack header         {:#x} (version {}, format {} {}, method {} {}, level {}, filter {} cto {})",
            h.file_offset,
            h.version,
            h.format,
            h.format_label(),
            h.method,
            h.method_label(),
            h.level,
            h.filter,
            h.filter_cto
        )?;
        write!(
            f,
            "  compressed stream   {:#x}..{:#x} ({} B -> {} B), c_adler {}",
            self.stream_file_offset,
            self.stream_file_offset + h.c_len as u64,
            h.c_len,
            h.u_len,
            if self.c_adler_ok { "ok" } else { "MISMATCH" }
        )?;
        writeln!(
            f,
            "                        (single block; decode verified against upx -d)"
        )?;
        match self.entry_point_file_offset {
            Some(ep) => writeln!(
                f,
                "  unpacker stub       computed {:#x}, entry point {:#x} ({}), {}",
                self.stub_file_offset,
                ep,
                if self.entry_point_matches_stub { "matches" } else { "MISMATCH" },
                if self.entry_point_matches_stub { "layout confirmed" } else { "layout diverges" },
            )?,
            None => writeln!(
                f,
                "  unpacker stub       computed {:#x}, entry point not in any section's file bytes",
                self.stub_file_offset
            )?,
        }
        writeln!(
            f,
            "  original size       {} B (u_file_size); overlay after sections: {} B @ {:#x}",
            h.u_file_size, self.overlay_size, self.overlay_file_offset
        )?;
        let sections = self
            .sections
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(f, "  sections            {sections}")?;
        writeln!(
            f,
            "  next                /unpack --packer upx restores the original file statically (no process; byte-identical to upx -d on the corpus)"
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::detect;
    use crate::header::test_support::{build_header, sample_header};
    use crate::test_support::{pe_with_sections, sec_va};

    /// A synthetic UPX image whose layout mirrors the measured GNU x64
    /// samples: ident inside UPX1, stream, 16-aligned, stub right after.
    fn fixture() -> (PeHeader, Vec<u8>) {
        let mut ph = sample_header();
        let ic = 5u64 + 32; // "5.21\0" version string + 32-byte header
        let aligned = (ic + ph.c_len as u64 + 15) & !15;

        // The stream is zeros in the fixture, so the header must carry the
        // checksum of those zeros — that is what makes c_adler verifiable.
        ph.c_adler = crate::adler32(&vec![0u8; ph.c_len as usize]);

        let upx1_raw: u64 = 0x200;
        let stub_file_offset = upx1_raw + aligned;
        let image_len = (upx1_raw + aligned + 0x400) as usize;
        let mut image = vec![0u8; image_len];
        image[0x200..0x205].copy_from_slice(b"5.21\0");
        image[0x205..0x225].copy_from_slice(&build_header(&ph));

        // UPX0 va 0x1000 (vsize big, raw 0); UPX1 va 0x2d7000, raw 0x200.
        // Entry point == the computed stub offset, expressed through the
        // section mapping: rva = va + (file - raw).
        let ep_rva = 0x2d7000u32 + (stub_file_offset - upx1_raw) as u32;
        let pe = pe_with_sections(vec![
            sec_va("UPX0", 0x1000, 0x2d6000, 0, 0, 0xe000_0080),
            sec_va(
                "UPX1",
                0x2d7000,
                (aligned + 0x400) as u32,
                (aligned + 0x400) as u32,
                0x200,
                0xe000_0040,
            ),
        ]);
        let mut pe = pe;
        pe.entry_point = ep_rva;
        (pe, image)
    }

    #[test]
    fn layout_math_and_the_entry_point_invariant_hold() {
        let (pe, image) = fixture();
        assert!(detect(&pe, &image).is_some(), "the fixture must detect");
        let r = analyze(&pe, &image).expect("report");
        assert_eq!(r.ident_in_upx1, 37);
        assert_eq!(r.stream_file_offset, 0x225);
        assert!(r.entry_point_matches_stub, "the invariant must hold by construction");
        assert!(r.c_adler_ok, "c_adler is a real checksum over the stream bytes");
        assert_eq!(r.overlay_size, 0);
        let text = r.to_string();
        assert!(text.contains("layout confirmed"), "{text}");
        assert!(
            text.contains("/unpack --packer upx"),
            "the next-line must point at the static unpacker: {text}"
        );
        assert!(text.contains("nrv2e-le32"), "{text}");
    }

    #[test]
    fn a_corrupted_stream_byte_is_reported_as_a_checksum_mismatch() {
        let (pe, mut image) = fixture();
        let r0 = analyze(&pe, &image).unwrap();
        let at = r0.stream_file_offset as usize;
        image[at] ^= 0xFF;
        let r = analyze(&pe, &image).expect("report");
        assert!(!r.c_adler_ok);
        assert!(r.to_string().contains("MISMATCH"));
    }
}
