//! The static UPX unpacker: decode, unfilter, rebuild — no process, no
//! debugger, pure file work.
//!
//! Direct port of `PeFile::unpack0` (`src/pefile.cpp` lines 3061-3179) at
//! tag v5.2.1, including `rebuildImports`, `rebuildRelocs`,
//! `rebuildResources` (TLS and exports are no-ops for the binaries UPX PE
//! produces here) and the output assembly.  The decoded image carries its
//! own reconstruction data at the tail:
//!
//! ```text
//! obuf: [ image: sections mapped at (vaddr - rvamin) ]
//!       [ import compact-entries (le32 offset into obuf)          ]
//!       [ compressed relocation delta-stream (le32 offset)        ]
//!       [ extra_info: original PE header + original section table ]
//!         + 8 B import offsets + 5 B reloc header + 2 B icondir   ]
//!       [ le32: extra_info offset                                 ]
//! ```
//!
//! Every stage was prototyped in Python first (`OUT\upx_unpack_proto.py`)
//! and is gated byte-for-byte against `upx -d` on all four UPX 5.2.1 corpus
//! samples — three of the traps the port had to get exactly right:
//!
//! 1. the IAT cursor advances **per imported name** (`for (p += 8; *p;
//!    ++newiat)`), so missing the increment stacks every name on the first
//!    slot and the terminator zeroes a live entry;
//! 2. `size_of_block` is written back **after** the align-to-4 padding
//!    (`Reloc::finish`'s `rel->size_of_block = sob`), so the pad counts;
//! 3. the ground truth is `upx -d`'s own output, **not** the original file —
//!    UPX rewrites the DOS stub area at pack time and never restores it
//!    (measured: sizes identical, hashes differ, on every sample).
//!
//! Everything is bounds-checked: a malformed file surfaces as
//! [`UpxUnpackError`], never as a panic.

use mida_pe::PeHeader;

use super::error::UpxUnpackError;
use super::header::{adler32, find_pack_header, M_LZMA, M_NRV2E_LE32};
use super::{filter, lzma, nrv2e, reloc};

// ---------------------------------------------------------------------------
// checked byte access
// ---------------------------------------------------------------------------

fn le16(buf: &[u8], off: usize) -> Result<u16, UpxUnpackError> {
    let b = buf
        .get(off..off + 2)
        .ok_or(UpxUnpackError::BadImage("le16 out of range"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn le32(buf: &[u8], off: usize) -> Result<u32, UpxUnpackError> {
    let b = buf
        .get(off..off + 4)
        .ok_or(UpxUnpackError::BadImage("le32 out of range"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le64(buf: &[u8], off: usize) -> Result<u64, UpxUnpackError> {
    let b = buf
        .get(off..off + 8)
        .ok_or(UpxUnpackError::BadImage("le64 out of range"))?;
    Ok(u64::from_le_bytes(b.try_into().unwrap()))
}

fn put32(buf: &mut [u8], off: usize, v: u32) -> Result<(), UpxUnpackError> {
    let b = buf
        .get_mut(off..off + 4)
        .ok_or(UpxUnpackError::BadImage("put32 out of range"))?;
    b.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn put64(buf: &mut [u8], off: usize, v: u64) -> Result<(), UpxUnpackError> {
    let b = buf
        .get_mut(off..off + 8)
        .ok_or(UpxUnpackError::BadImage("put64 out of range"))?;
    b.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn align_up(v: u32, a: u32) -> u32 {
    if a == 0 {
        return v;
    }
    v.div_ceil(a) * a
}

// ---------------------------------------------------------------------------
// original section table (pe_section_t, 40 bytes each)
// ---------------------------------------------------------------------------

struct OrigSection {
    vaddr: u32,
    rawsize: u32,
    rawptr: u32,
}

fn parse_sections(raw: &[u8], count: usize) -> Result<Vec<OrigSection>, UpxUnpackError> {
    (0..count)
        .map(|i| {
            let base = i * 40;
            let b = raw
                .get(base..base + 40)
                .ok_or(UpxUnpackError::BadImage("section table truncated"))?;
            Ok(OrigSection {
                vaddr: le32(b, 12)?,
                rawsize: le32(b, 16)?,
                rawptr: le32(b, 20)?,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// the original header (pe_header_t): kept as raw bytes and patched in place
// ---------------------------------------------------------------------------

struct OrigHeader {
    raw: Vec<u8>,
    nsec: u16,
    chars: u16,
    nddirs: usize,
    ddirs_off: usize,
    codebase: u32,
    codesize: u32,
    image_base: u64,
    filealign: u32,
}

impl OrigHeader {
    fn dir(&self, i: usize) -> (u32, u32) {
        if i >= self.nddirs {
            return (0, 0);
        }
        let off = self.ddirs_off + i * 8;
        match (le32(&self.raw, off), le32(&self.raw, off + 4)) {
            (Ok(a), Ok(s)) => (a, s),
            _ => (0, 0),
        }
    }

    fn set_dir(&mut self, i: usize, addr: u32, size: u32) -> Result<(), UpxUnpackError> {
        if i >= self.nddirs {
            return Ok(()); // beyond sizeof_oh: the C patches the struct, which
            // is then truncated on write — same observable result
        }
        put32(&mut self.raw, self.ddirs_off + i * 8, addr)?;
        put32(&mut self.raw, self.ddirs_off + i * 8 + 4, size)
    }

    /// Data directory sizes differ per magic: the fixed optional-header part
    /// is 96 bytes on PE32 and 112 on PE32+.
    fn parse(raw: &[u8], is64: bool) -> Result<OrigHeader, UpxUnpackError> {
        if raw.len() < 24 + 96 {
            return Err(UpxUnpackError::BadImage("original header truncated"));
        }
        let magic = le16(raw, 24)?;
        if magic != (0x10B_u16) && magic != 0x20B {
            return Err(UpxUnpackError::BadImage("original header bad magic"));
        }
        if (magic == 0x20B) != is64 {
            return Err(UpxUnpackError::BadImage(
                "original header magic disagrees with the packed header",
            ));
        }
        let ddirs_off = 24 + if is64 { 112 } else { 96 };
        let nddirs = min_count(le32(raw, 24 + 108)?);
        Ok(OrigHeader {
            raw: raw.to_vec(),
            nsec: le16(raw, 6)?,
            chars: le16(raw, 22)?,
            nddirs,
            ddirs_off,
            codebase: le32(raw, 24 + if is64 { 32 } else { 20 })?,
            codesize: le32(raw, 24 + 4)?,
            image_base: if is64 {
                le64(raw, 24 + 24)?
            } else {
                le32(raw, 24 + 28)? as u64
            },
            filealign: le32(raw, 24 + 36)?,
        })
    }
}

fn min_count(n: u32) -> usize {
    (n as usize).min(16)
}

// ---------------------------------------------------------------------------
// unpack0
// ---------------------------------------------------------------------------

/// Statically unpack a UPX-packed PE: decode the single-block stream, undo
/// the filter, rebuild imports/relocations/resources and reassemble the
/// original file.  `pe`/`image` describe the packed input (as in
/// [`super::detect`] / [`super::analyze`]).
///
/// The result is byte-for-byte what `upx -d` produces (verified on the
/// corpus; see the crate gate), with one caveat measured on every sample:
/// UPX itself rewrites the DOS stub area when packing and never restores it,
/// so the product equals `upx -d`'s output, not the pre-pack original.
pub fn unpack_static(pe: &PeHeader, image: &[u8]) -> Result<Vec<u8>, UpxUnpackError> {
    let ph = find_pack_header(image).ok_or(UpxUnpackError::NoPackHeader)?;

    // ---- the compressed stream directly follows the PackHeader (report.rs
    // derives the same offset as `upx1_raw + ident_in_upx1 == header_end`).
    let stream_off = ph.file_offset as usize + 32;
    let c_len = ph.c_len as usize;
    let stream = image
        .get(stream_off..stream_off + c_len)
        .ok_or(UpxUnpackError::StreamTruncated)?;
    let c_adler = adler32(stream);
    if c_adler != ph.c_adler {
        return Err(UpxUnpackError::CAdlerMismatch {
            expected: ph.c_adler,
            actual: c_adler,
        });
    }

    // ---- decompress (method dispatch; u_len is both the size and the bound)
    let u_len = ph.u_len as usize;
    let mut obuf: Vec<u8> = match ph.method {
        M_NRV2E_LE32 => nrv2e::decompress(stream, u_len)?,
        M_LZMA => lzma::decompress(stream, u_len)?,
        other => return Err(UpxUnpackError::UnsupportedMethod(other)),
    };
    if obuf.len() != u_len {
        return Err(UpxUnpackError::DecodeLengthMismatch {
            expected: ph.u_len,
            actual: obuf.len(),
        });
    }
    let u_adler = adler32(&obuf);
    if u_adler != ph.u_adler {
        return Err(UpxUnpackError::UAdlerMismatch {
            expected: ph.u_adler,
            actual: u_adler,
        });
    }

    // ---- extra_info lives at the tail of the decoded image
    let skip = le32(&obuf, u_len - 4)? as usize;
    if skip >= u_len - 4 || skip > obuf.len() {
        return Err(UpxUnpackError::BadImage("extra_info offset out of range"));
    }
    let sizeof_oh = 24 + if pe.is_64bit { 112 } else { 96 } + min_count(pe.nt_headers.optional_header.number_of_rva_and_sizes) * 8;
    let extra = obuf[skip..u_len - 4].to_vec();
    if extra.len() < sizeof_oh {
        return Err(UpxUnpackError::BadImage("extra_info shorter than a header"));
    }
    let mut oh = OrigHeader::parse(&extra[..sizeof_oh], pe.is_64bit)?;
    let mut pos = sizeof_oh;

    // ---- original section table
    let oh_nsec = oh.nsec as usize;
    if oh_nsec == 0 || oh_nsec > 96 {
        return Err(UpxUnpackError::BadImage("original section count"));
    }
    let sect_len = oh_nsec * 40;
    let osection_raw = extra
        .get(pos..pos + sect_len)
        .ok_or(UpxUnpackError::BadImage("original section table truncated"))?
        .to_vec();
    let osections = parse_sections(&osection_raw, oh_nsec)?;
    pos += sect_len;
    let rvamin = osections[0].vaddr;

    // ---- the noncompressed third section (import names blob, resource data)
    let iobjs = pe.sections.len();
    let ibuf: Vec<u8> = if iobjs > 2 {
        let s2 = &pe.sections[2];
        image
            .get(s2.raw_offset as usize..s2.raw_offset as usize + s2.raw_size as usize)
            .ok_or(UpxUnpackError::BadImage(
                "the packed third section is truncated",
            ))?
            .to_vec()
    } else {
        Vec::new()
    };

    // ---- RELOCS_STRIPPED propagates from ih to oh before any rebuild
    // (pefile.cpp lines 3122-3127; the packed file's flag drives it)
    if pe.nt_headers.file_header.characteristics & 0x1 != 0 {
        oh.chars |= 0x1;
        oh.set_dir(5, 0, 0)?;
    }

    // ---- unfilter (pefile.cpp lines 3113-3120)
    if ph.filter != 0 {
        let fstart = oh.codebase.wrapping_sub(rvamin) as usize;
        let flen = oh.codesize as usize;
        if fstart + flen > obuf.len() {
            return Err(UpxUnpackError::BadImage("filter region out of range"));
        }
        let pre = if fstart >= 1 { obuf[fstart - 1] } else { 0 };
        let region = &mut obuf[fstart..fstart + flen];
        filter::unfilter(ph.filter, ph.filter_cto, fstart as u32, region, pre)?;
    }

    // ---- rebuildImports (pefile.cpp lines 2969-3058)
    let (idaddr_imp, idsize_imp) = oh.dir(1);
    let (idaddr_pimp, _idsize_pimp) = {
        let d = &pe.nt_headers.optional_header.data_directory[1];
        (d.virtual_address, d.size)
    };
    if idaddr_imp != 0 && idsize_imp > 20 {
        if iobjs <= 2 {
            return Err(UpxUnpackError::BadImage(
                "imports need the packed third section",
            ));
        }
        let s2va = pe.sections[2].virtual_address;
        let imp_off = idaddr_pimp.wrapping_sub(s2va) as usize;
        let my_import = ibuf.get(imp_off..).ok_or(UpxUnpackError::BadImage(
            "the packed import blob is out of the third section",
        ))?;
        let imdata_off = le32(&extra, pos)? as usize;
        let inamespos = le32(&extra, pos + 4)?;
        pos += 8;
        rebuild_imports(
            &mut obuf,
            my_import,
            imdata_off,
            inamespos,
            idaddr_imp,
            rvamin,
            pe.is_64bit,
        )?;
    }

    // ---- rebuildRelocs (pefile.cpp lines 2827-2905)
    let (rel_addr, rel_size) = oh.dir(5);
    if rel_addr != 0 && rel_size != 0 && oh.chars & 0x1 == 0 {
        if rel_size == 8 {
            // "some tricky dlls use this": an empty block
            put32(&mut obuf, rel_addr.wrapping_sub(rvamin) as usize, 0)?;
            put32(&mut obuf, rel_addr.wrapping_sub(rvamin) as usize + 4, 8)?;
        } else {
            let orig_crelocs = le32(&extra, pos)?;
            let big = *extra
                .get(pos + 4)
                .ok_or(UpxUnpackError::BadImage("reloc header truncated"))?;
            pos += 5;
            let bits = if pe.is_64bit { 64 } else { 32 };
            let (positions, stream_len) =
                reloc::unoptimize(&mut obuf, orig_crelocs as usize, orig_crelocs as usize, bits)?;
            let mut entries: Vec<(u32, u16)> = Vec::with_capacity(positions.len());
            let base = oh.image_base.wrapping_add(rvamin as u64);
            for &pc in &positions {
                let p = pc as usize;
                if pe.is_64bit {
                    let v = le64(&obuf, p)?.wrapping_add(base);
                    put64(&mut obuf, p, v)?;
                    entries.push((rvamin.wrapping_add(pc), 10)); // DIR64
                } else {
                    let v = le32(&obuf, p)?
                        .wrapping_add(base as u32)
                        .wrapping_add(0); // base fits 32 bits on PE32
                    put32(&mut obuf, p, v)?;
                    entries.push((rvamin.wrapping_add(pc), 3)); // HIGHLOW
                }
            }
            if big & 6 != 0 {
                // 16-bit relocation lists follow the delta stream's terminator
                let mut q = orig_crelocs as usize + stream_len;
                let first_type = if big & 4 != 0 { 2u16 } else { 1u16 }; // LOW : HIGH
                while le32(&obuf, q)? != 0 {
                    let v = le32(&obuf, q)?;
                    entries.push((rvamin.wrapping_add(v), first_type));
                    q += 4;
                }
                if big & 6 == 6 {
                    q += 4; // skip this list's terminator
                    while le32(&obuf, q)? != 0 {
                        let v = le32(&obuf, q)?;
                        entries.push((rvamin.wrapping_add(v), 1)); // HIGH
                        q += 4;
                    }
                }
            }
            let blocks = reloc::build_blocks(entries);
            let at = rel_addr.wrapping_sub(rvamin) as usize;
            let end = at + blocks.len();
            let slot = obuf
                .get_mut(at..end)
                .ok_or(UpxUnpackError::BadImage("reloc dir out of the image"))?;
            slot.copy_from_slice(&blocks);
            oh.set_dir(5, rel_addr, blocks.len() as u32)?;
        }
    }

    // ---- rebuildResources (pefile.cpp lines 2933-2967)
    let (odaddr_res, odsize_res) = oh.dir(2);
    let res_dir = &pe.nt_headers.optional_header.data_directory[2];
    if odsize_res != 0 && res_dir.size != 0 {
        // icondir_count is extra_info's last field, so pos is not consumed here
        let icondir = le16(&extra, pos)? as u32;
        let lastvaddr = pe.sections[iobjs - 1].virtual_address;
        let vaddr = res_dir.virtual_address;
        let start = vaddr.wrapping_sub(lastvaddr) as usize;
        if vaddr < lastvaddr || start > ibuf.len() {
            return Err(UpxUnpackError::BadImage("packed resource dir out of range"));
        }
        rebuild_resources(&mut obuf, &ibuf, start, vaddr, lastvaddr, rvamin, odaddr_res, icondir)?;
    }

    // ---- final header patches (pefile.cpp lines 3148-3155)
    oh.set_dir(12, 0, 0)?; // IAT
    oh.set_dir(11, 0, 0)?; // BOUND_IMPORT
    put32(&mut oh.raw, 24 + 64, 0)?; // CheckSum
    let headersize = align_up(
        pe.dos_header
            .e_lfanew
            .wrapping_add(sizeof_oh as u32)
            .wrapping_add(40u32.wrapping_mul(oh_nsec as u32)),
        oh.filealign,
    );
    put32(&mut oh.raw, 24 + 60, headersize)?;

    // ---- assemble the output (pefile.cpp lines 3157-3177)
    let pe_offset = pe.dos_header.e_lfanew as usize;
    let mut out = Vec::with_capacity(ph.u_file_size as usize);
    out.extend_from_slice(image.get(..pe_offset).ok_or(UpxUnpackError::BadImage(
        "pe_offset beyond the file",
    ))?);
    out.extend_from_slice(&oh.raw);
    out.extend_from_slice(&osection_raw);
    let first_raw = osections
        .iter()
        .map(|s| s.rawptr)
        .find(|&p| p != 0)
        .unwrap_or(0) as usize;
    let written = out.len();
    if first_raw < written {
        return Err(UpxUnpackError::BadImage(
            "first section begins inside the headers",
        ));
    }
    out.resize(out.len() + (first_raw - written), 0);
    for s in &osections {
        if s.rawptr != 0 {
            let n = align_up(s.rawsize, oh.filealign) as usize;
            let from = s.vaddr.wrapping_sub(rvamin) as usize;
            let src = obuf
                .get(from..from + n)
                .ok_or(UpxUnpackError::BadImage("section data out of the image"))?;
            out.extend_from_slice(src);
        }
    }
    // overlay: the packed file's tail, verbatim (Packer::copyOverlay)
    if let Some(last) = pe.sections.last() {
        let overlay_off =
            align_up(last.raw_offset.wrapping_add(last.raw_size), pe.file_alignment) as usize;
        if overlay_off <= image.len() {
            out.extend_from_slice(&image[overlay_off..]);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// rebuildImports
// ---------------------------------------------------------------------------

/// Compact entry kinds: `1` = name follows as a C string, `0xff` = ordinal
/// (`le16`), anything else = `le32` index into the packed import blob whose
/// `LEXX` value is copied verbatim (pre-bound entries).
fn rebuild_imports(
    obuf: &mut [u8],
    my_import: &[u8],
    imdata_off: usize,
    inamespos: u32,
    idaddr_imp: u32,
    rvamin: u32,
    is64: bool,
) -> Result<(), UpxUnpackError> {
    let lexx = if is64 { 8 } else { 4 };
    let ord_mask: u64 = if is64 { 1 << 63 } else { 1 << 31 };

    // walk the compact entries once to size the dll-names area
    let mut sdllnames: u32 = 0;
    for (name_off, _iat_off, _items) in compact_entries(obuf, imdata_off)? {
        let end = find_nul(my_import, name_off as usize)?;
        sdllnames += (end - name_off as usize + 1) as u32;
    }
    let sdllnames = align_up(sdllnames, 2);

    let mut im_pos = idaddr_imp.wrapping_sub(rvamin) as usize;
    let mut dllnames_pos = inamespos as usize;
    let importednames_start = inamespos as usize + sdllnames as usize;
    let mut importednames_pos = importednames_start;

    for (name_off, iat_off, items) in compact_entries(obuf, imdata_off)? {
        let end = find_nul(my_import, name_off as usize)?;
        let dname = my_import
            .get(name_off as usize..end + 1)
            .ok_or(UpxUnpackError::BadImage("dll name out of the blob"))?;
        let dlen = dname.len() - 1;
        let iatoffs = iat_off.wrapping_add(rvamin);
        if inamespos != 0 {
            if dllnames_pos + dlen + 1 > obuf.len() {
                return Err(UpxUnpackError::BadImage("dll names area out of range"));
            }
            obuf[dllnames_pos..dllnames_pos + dlen + 1].copy_from_slice(dname);
            put32(obuf, im_pos + 12, dllnames_pos as u32 + rvamin)?;
            dllnames_pos += dlen + 1;
        } else {
            let preset = le32(obuf, im_pos + 12)?;
            let at = preset.wrapping_sub(rvamin) as usize;
            if at + dlen + 1 > obuf.len() {
                return Err(UpxUnpackError::BadImage("dll name target out of range"));
            }
            obuf[at..at + dlen + 1].copy_from_slice(dname);
        }
        put32(obuf, im_pos + 16, iatoffs)?;
        let mut newiat = iatoffs.wrapping_sub(rvamin) as usize;

        for item in &items {
            match item {
                ImportItem::Name(name) => {
                    let ilen = name.len();
                    if inamespos != 0 {
                        if (importednames_pos - importednames_start) & 1 != 0 {
                            importednames_pos -= 1;
                        }
                        if importednames_pos + 2 + ilen > obuf.len() {
                            return Err(UpxUnpackError::BadImage("import names area"));
                        }
                        obuf[importednames_pos + 2..importednames_pos + 2 + ilen]
                            .copy_from_slice(name);
                        let val = (importednames_pos as u64).wrapping_add(rvamin as u64);
                        if is64 {
                            put64(obuf, newiat, val)?;
                        } else {
                            put32(obuf, newiat, val as u32)?;
                        }
                        importednames_pos += 2 + ilen;
                    } else {
                        // the packer preset the slot with the name's RVA; the
                        // hint word at +2 stays as the packer left it
                        let target = le32(obuf, newiat)?;
                        let at = target.wrapping_add(2).wrapping_sub(rvamin) as usize;
                        if at + ilen > obuf.len() {
                            return Err(UpxUnpackError::BadImage("import name target"));
                        }
                        obuf[at..at + ilen].copy_from_slice(name);
                    }
                }
                ImportItem::Ordinal(o) => {
                    let v = (*o as u64).wrapping_add(ord_mask);
                    if is64 {
                        put64(obuf, newiat, v)?;
                    } else {
                        put32(obuf, newiat, v as u32)?;
                    }
                }
                ImportItem::Prebound(idx) => {
                    let val = my_import
                        .get(*idx as usize..*idx as usize + lexx)
                        .ok_or(UpxUnpackError::BadImage("pre-bound import out of blob"))?;
                    obuf
                        .get_mut(newiat..newiat + lexx)
                        .ok_or(UpxUnpackError::BadImage("IAT slot out of range"))?
                        .copy_from_slice(val);
                }
            }
            // the C advances the cursor per item: `for (p += 8; *p; ++newiat)`
            newiat += lexx;
        }
        if is64 {
            put64(obuf, newiat, 0)?;
        } else {
            put32(obuf, newiat, 0)?;
        }
        im_pos += 20;
    }
    Ok(())
}

/// Compact entry kinds, per the C walk: `1` = a name follows as a C string,
/// `0xff` = ordinal (`le16`), anything else = `le32` index into the packed
/// import blob whose `LEXX` value is copied verbatim (pre-bound entries).
enum ImportItem {
    Name(Vec<u8>),
    Ordinal(u16),
    Prebound(u32),
}

/// Walk the compact import entries at `imdata_off`: `[le32 dll-name offset,
/// le32 iat offset, names..., 0]` repeated, terminated by a zero le32.
fn compact_entries(
    obuf: &[u8],
    imdata_off: usize,
) -> Result<Vec<(u32, u32, Vec<ImportItem>)>, UpxUnpackError> {
    let mut out = Vec::new();
    let mut p = imdata_off;
    while le32(obuf, p)? != 0 {
        let name_off = le32(obuf, p)?;
        let iat_off = le32(obuf, p + 4)?;
        let mut q = p + 8;
        let mut items = Vec::new();
        loop {
            let b = *obuf
                .get(q)
                .ok_or(UpxUnpackError::BadImage("compact import runs off"))?;
            if b == 0 {
                break;
            }
            if b == 1 {
                let end = find_nul(obuf, q + 1)?;
                let name = obuf
                    .get(q + 1..end + 1)
                    .ok_or(UpxUnpackError::BadImage("import name truncated"))?
                    .to_vec();
                items.push(ImportItem::Name(name));
                q = end + 1;
            } else if b == 0xFF {
                items.push(ImportItem::Ordinal(le16(obuf, q + 1)?));
                q += 3;
            } else {
                items.push(ImportItem::Prebound(le32(obuf, q + 1)?));
                q += 5;
            }
        }
        out.push((name_off, iat_off, items));
        p = q + 1;
    }
    Ok(out)
}

fn find_nul(buf: &[u8], from: usize) -> Result<usize, UpxUnpackError> {
    buf[from..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| p + from)
        .ok_or(UpxUnpackError::BadImage("unterminated string in the blob"))
}

// ---------------------------------------------------------------------------
// rebuildResources
// ---------------------------------------------------------------------------

/// Walk the packed resource tree depth-first (entries in table order), copy
/// every moved data blob to the original RVA stored 4 bytes before it, and
/// rebuild the directory in canonical order — `Resource::convert` + `build`.
///
/// Tree geometry (pefile.h `Resource`): three `res_dir` levels (16-byte
/// header + 8-byte `{tnl, child}` entries), leaves are 16-byte `res_data`
/// records; entry `child`/name offsets are relative to the packed directory
/// (`start`), the high bit of `tnl` marks a named entry whose UTF-16 name
/// sits at `child & 0x7fffffff`.
fn rebuild_resources(
    obuf: &mut [u8],
    ibuf: &[u8],
    start: usize,
    vaddr: u32,
    lastvaddr: u32,
    rvamin: u32,
    odaddr_res: u32,
    icondir_count: u32,
) -> Result<(), UpxUnpackError> {
    let dsize = res_dir_size(ibuf, start, 0, 0)?;
    let ssize = res_names_size(ibuf, start, 0, 0)?;
    let dirsize = align_up((dsize + ssize) as u32, 4) as usize;
    let mut newdir = vec![0u8; dirsize];

    let mut ctx = ResCtx {
        ibuf,
        start,
        vaddr,
        lastvaddr,
        icondir: icondir_count,
    };
    let mut bpos = 0usize;
    let mut spos = dsize;
    res_build(
        &mut ctx, &mut newdir, obuf, rvamin, 0, 0, 0, &mut bpos, &mut spos,
    )?;
    if bpos != dsize || spos != dsize + ssize {
        return Err(UpxUnpackError::Resource("directory size accounting drifted"));
    }
    // "write back when the original is zeroed" (pefile.cpp line 2964)
    let at = odaddr_res.wrapping_sub(rvamin) as usize;
    if le32(obuf, at + 12)? == 0 {
        let slot = obuf
            .get_mut(at..at + dirsize)
            .ok_or(UpxUnpackError::Resource("resource dir target out of range"))?;
        slot.copy_from_slice(&newdir);
    }
    Ok(())
}

struct ResCtx<'a> {
    ibuf: &'a [u8],
    start: usize,
    vaddr: u32,
    lastvaddr: u32,
    icondir: u32,
}

/// `Resource::convert`'s `dsize += node->Sizeof()` walk; an empty directory
/// contributes nothing (the C returns nullptr before accounting it).
fn res_dir_size(ibuf: &[u8], start: usize, off: u32, level: usize) -> Result<usize, UpxUnpackError> {
    if level == 3 {
        return Ok(16); // res_data
    }
    let node = start + off as usize;
    let n = res_dir_count(ibuf, node)?;
    if n == 0 {
        return Ok(0);
    }
    let mut total = 16 + 8 * n;
    for (_tnl, child) in res_dir_entries(ibuf, node, n)? {
        total += res_dir_size(ibuf, start, child & 0x7FFF_FFFF, level + 1)?;
    }
    Ok(total)
}

/// The `ssize` walk: UTF-16 names of named entries, `2 + 2*len` bytes each.
fn res_names_size(
    ibuf: &[u8],
    start: usize,
    off: u32,
    level: usize,
) -> Result<usize, UpxUnpackError> {
    if level == 3 {
        return Ok(0);
    }
    let node = start + off as usize;
    let n = res_dir_count(ibuf, node)?;
    if n == 0 {
        return Ok(0);
    }
    let mut total = 0;
    for (tnl, child) in res_dir_entries(ibuf, node, n)? {
        if tnl & 0x8000_0000 != 0 {
            let wlen = le16(ibuf, start + (tnl & 0x7FFF_FFFF) as usize)? as usize;
            total += 2 + 2 * wlen;
        }
        total += res_names_size(ibuf, start, child & 0x7FFF_FFFF, level + 1)?;
    }
    Ok(total)
}

/// `Resource::build`: the directory first (header, entry table, then each
/// child in table order), names appended after all dirs+data at `spos`.
/// The entry's `child` RVA is the `bpos` current when the entry is written,
/// with the subdir bit set on the type and name levels.
#[allow(clippy::too_many_arguments)]
fn res_build(
    ctx: &mut ResCtx,
    newdir: &mut [u8],
    obuf: &mut [u8],
    rvamin: u32,
    off: u32,
    level: usize,
    type_id: u32,
    bpos: &mut usize,
    spos: &mut usize,
) -> Result<(), UpxUnpackError> {
    let node = ctx.start + off as usize;
    if level == 3 {
        let (doff, dsize_) = (le32(ctx.ibuf, node)?, le32(ctx.ibuf, node + 4)?);
        let raw16 = ctx
            .ibuf
            .get(node..node + 16)
            .ok_or(UpxUnpackError::Resource("data entry truncated"))?;
        newdir[*bpos..*bpos + 16].copy_from_slice(raw16);
        if doff > ctx.vaddr {
            // the packer moved this blob: the original RVA sits 4 bytes before
            let origoffs =
                le32(ctx.ibuf, doff.wrapping_sub(4).wrapping_sub(ctx.lastvaddr) as usize)?;
            put32(newdir, *bpos, origoffs)?;
            let n = align_up(dsize_, 4) as usize;
            let src = doff.wrapping_sub(ctx.lastvaddr) as usize;
            let dst = origoffs.wrapping_sub(rvamin) as usize;
            let blob = ctx
                .ibuf
                .get(src..src + n)
                .ok_or(UpxUnpackError::Resource("resource blob out of range"))?;
            let slot = obuf
                .get_mut(dst..dst + n)
                .ok_or(UpxUnpackError::Resource("resource target out of range"))?;
            slot.copy_from_slice(blob);
            if ctx.icondir != 0 && type_id == 14 {
                // RT_GROUP_ICON: patch the icon count in GRPICONDIR
                put16(obuf, dst + 4, ctx.icondir as u16)?;
                ctx.icondir = 0;
            }
        }
        *bpos += 16;
        return Ok(());
    }
    let n = res_dir_count(ctx.ibuf, node)?;
    if n == 0 {
        // valid UPX trees have no empty dirs; convert() would hand nullptr
        // to build() and the C would dereference it
        return Err(UpxUnpackError::Resource("empty resource directory"));
    }
    let header = ctx
        .ibuf
        .get(node..node + 16)
        .ok_or(UpxUnpackError::Resource("dir header truncated"))?;
    newdir[*bpos..*bpos + 16].copy_from_slice(header);
    let entries = res_dir_entries(ctx.ibuf, node, n)?;
    // the entry table's base: C walks it with `be` — a pointer that moves
    // independently of bpos, which the recursion keeps advancing
    let table_base = *bpos + 16;
    *bpos += 16 + 8 * n;
    if std::env::var_os("MIDA_UPX_RES_TRACE").is_some() {
        eprintln!("[res_build] dir off={off:#x} level={level} n={n} bpos now {bpos}");
    }
    for (i, (tnl, child)) in entries.iter().enumerate() {
        let epos = table_base + 8 * i; // this entry's slot in the table
        if tnl & 0x8000_0000 != 0 {
            let p = (tnl & 0x7FFF_FFFF) as usize;
            let wlen = le16(ctx.ibuf, ctx.start + p)? as usize;
            let ln = 2 + 2 * wlen;
            put32(newdir, epos, (*spos as u32) | 0x8000_0000)?;
            let name = ctx
                .ibuf
                .get(ctx.start + p..ctx.start + p + ln)
                .ok_or(UpxUnpackError::Resource("resource name truncated"))?;
            if *spos + ln > newdir.len() {
                return Err(UpxUnpackError::Resource("name area overflow"));
            }
            newdir[*spos..*spos + ln].copy_from_slice(name);
            *spos += ln;
        } else {
            put32(newdir, epos, *tnl)?;
        }
        put32(
            newdir,
            epos + 4,
            (*bpos as u32) | if level < 2 { 0x8000_0000 } else { 0 },
        )?;
        let next_type = if level == 0 { *tnl } else { type_id };
        res_build(
            ctx,
            newdir,
            obuf,
            rvamin,
            child & 0x7FFF_FFFF,
            level + 1,
            next_type,
            bpos,
            spos,
        )?;
    }
    Ok(())
}

fn put16(buf: &mut [u8], off: usize, v: u16) -> Result<(), UpxUnpackError> {
    let b = buf
        .get_mut(off..off + 2)
        .ok_or(UpxUnpackError::BadImage("put16 out of range"))?;
    b.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

fn res_dir_count(ibuf: &[u8], off: usize) -> Result<usize, UpxUnpackError> {
    let named = le16(ibuf, off + 12)? as usize;
    let identr = le16(ibuf, off + 14)? as usize;
    Ok(named + identr)
}

fn res_dir_entries(ibuf: &[u8], off: usize, n: usize) -> Result<Vec<(u32, u32)>, UpxUnpackError> {
    (0..n)
        .map(|i| {
            let base = off + 16 + 8 * i;
            Ok((le32(ibuf, base)?, le32(ibuf, base + 4)?))
        })
        .collect()
}
