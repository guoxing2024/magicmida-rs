// Minimal PE32 / PE32+ synthesizers for structural gate tests.
// Self-contained (no `crate::` imports) so integration tests may `include!` it.

const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;
const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;
const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: u16 = 0x0040;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

const FA: u32 = 0x200;
const SA: u32 = 0x1000;

#[derive(Clone, Copy)]
pub enum PeKind {
    Pe32,
    Pe32Plus,
}

#[derive(Clone)]
pub struct PeBuildOptions {
    pub kind: PeKind,
    pub entry_rva: u32,
    pub text_va: u32,
    pub text_raw_size: u32,
    pub text_virt_size: u32,
    pub text_chars: u32,
    pub dll_characteristics: u16,
    pub characteristics: u16,
    pub include_reloc: bool,
    pub include_import: bool,
    pub corrupt: CorruptMode,
}

#[derive(Clone, Copy, Default)]
pub enum CorruptMode {
    #[default]
    None,
    TruncateAfterHeaders,
    SectionVaOverlap,
    SectionRawOverflow,
    BadEntryPoint,
    BadImportThunk,
    BadTlsSize,
    BadRelocBlock,
    BadExceptionSize,
    DynamicBaseNoReloc,
    TruncateFile(usize),
}

impl Default for PeBuildOptions {
    fn default() -> Self {
        Self {
            kind: PeKind::Pe32Plus,
            entry_rva: SA,
            text_va: SA,
            text_raw_size: FA,
            text_virt_size: 0x100,
            text_chars: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ,
            dll_characteristics: 0,
            characteristics: 0x0122,
            include_reloc: false,
            include_import: false,
            corrupt: CorruptMode::None,
        }
    }
}

impl PeBuildOptions {
    pub fn pe32() -> Self {
        Self {
            kind: PeKind::Pe32,
            characteristics: 0x0102,
            ..Self::default()
        }
    }

    pub fn pe32_plus() -> Self {
        Self::default()
    }
}

pub fn build_pe(opts: &PeBuildOptions) -> Vec<u8> {
    let e_lfanew: u32 = 0x80;
    let mut num_sections: u16 = if opts.include_reloc { 2 } else { 1 };
    if matches!(opts.corrupt, CorruptMode::SectionVaOverlap) && !opts.include_reloc {
        num_sections = 2;
    }
    let num_dd: u32 = 16;
    let (magic, machine, opt_fixed) = match opts.kind {
        PeKind::Pe32 => (
            IMAGE_NT_OPTIONAL_HDR32_MAGIC,
            IMAGE_FILE_MACHINE_I386,
            96u16,
        ),
        PeKind::Pe32Plus => (
            IMAGE_NT_OPTIONAL_HDR64_MAGIC,
            IMAGE_FILE_MACHINE_AMD64,
            112u16,
        ),
    };
    let size_of_optional_header = opt_fixed + (num_dd as u16) * 8;
    let section_table_off = e_lfanew as usize + 4 + 20 + size_of_optional_header as usize;
    let headers_end = section_table_off + (num_sections as usize) * 40;
    let size_of_headers = align_up(headers_end as u32, FA);

    let text_raw_ptr = size_of_headers;
    let mut reloc_raw_ptr = 0u32;
    let mut reloc_va = 0u32;
    let mut reloc_raw_size = 0u32;
    let mut size_of_image = opts.text_va + SA;

    if opts.include_reloc {
        reloc_va = opts.text_va + SA;
        reloc_raw_ptr = text_raw_ptr + align_up(opts.text_raw_size, FA);
        reloc_raw_size = FA;
        size_of_image = reloc_va + SA;
    }

    let file_size = if opts.include_reloc {
        reloc_raw_ptr + reloc_raw_size
    } else {
        text_raw_ptr + align_up(opts.text_raw_size, FA)
    };

    let mut buf = vec![0u8; file_size as usize];

    write_u16(&mut buf, 0, 0x5A4D);
    write_u32(&mut buf, 0x3C, e_lfanew);

    let nt = e_lfanew as usize;
    write_u32(&mut buf, nt, 0x0000_4550);
    write_u16(&mut buf, nt + 4, machine);
    write_u16(&mut buf, nt + 6, num_sections);
    write_u16(&mut buf, nt + 20, size_of_optional_header);
    write_u16(&mut buf, nt + 22, opts.characteristics);

    let opt = nt + 24;
    write_u16(&mut buf, opt, magic);
    let entry = match opts.corrupt {
        CorruptMode::BadEntryPoint => opts.text_va + opts.text_raw_size + 0x10,
        _ => opts.entry_rva,
    };
    write_u32(&mut buf, opt + 16, entry);

    match opts.kind {
        PeKind::Pe32 => {
            write_u32(&mut buf, opt + 28, 0x0040_0000);
            write_u32(&mut buf, opt + 32, SA);
            write_u32(&mut buf, opt + 36, FA);
            write_u32(&mut buf, opt + 56, size_of_image);
            write_u32(&mut buf, opt + 60, size_of_headers);
            write_u16(&mut buf, opt + 68, 3);
            let mut dll = opts.dll_characteristics;
            if matches!(opts.corrupt, CorruptMode::DynamicBaseNoReloc) {
                dll |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            }
            write_u16(&mut buf, opt + 70, dll);
            write_u32(&mut buf, opt + 92, num_dd);
        }
        PeKind::Pe32Plus => {
            write_u64(&mut buf, opt + 24, 0x0000_0001_4000_0000);
            write_u32(&mut buf, opt + 32, SA);
            write_u32(&mut buf, opt + 36, FA);
            write_u32(&mut buf, opt + 56, size_of_image);
            write_u32(&mut buf, opt + 60, size_of_headers);
            write_u16(&mut buf, opt + 68, 3);
            let mut dll = opts.dll_characteristics;
            if matches!(opts.corrupt, CorruptMode::DynamicBaseNoReloc) {
                dll |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
            }
            write_u16(&mut buf, opt + 70, dll);
            write_u32(&mut buf, opt + 108, num_dd);
        }
    }

    let dd_off = match opts.kind {
        PeKind::Pe32 => opt + 96,
        PeKind::Pe32Plus => opt + 112,
    };

    if opts.include_import {
        let import_rva = opts.text_va + 0x40;
        let import_size = 40u32;
        let iat_rva = opts.text_va + 0x90;
        let iat_size = if matches!(opts.kind, PeKind::Pe32Plus) {
            16u32
        } else {
            8
        };

        let text_base = text_raw_ptr as usize;
        buf[text_base] = 0xC3;

        let idt = text_base + 0x40;
        let ilt_rva = opts.text_va + 0x80;
        let name_rva = opts.text_va + 0xB0;
        let ibn_rva = opts.text_va + 0xA0;
        write_u32(&mut buf, idt, ilt_rva);
        write_u32(&mut buf, idt + 12, name_rva);
        write_u32(&mut buf, idt + 16, iat_rva);

        if matches!(opts.corrupt, CorruptMode::BadImportThunk) {
            write_u32(&mut buf, idt, 0x00FF_0000);
        } else {
            match opts.kind {
                PeKind::Pe32Plus => {
                    write_u64(&mut buf, text_base + 0x80, ibn_rva as u64);
                    write_u64(&mut buf, text_base + 0x90, ibn_rva as u64);
                }
                PeKind::Pe32 => {
                    write_u32(&mut buf, text_base + 0x80, ibn_rva);
                    write_u32(&mut buf, text_base + 0x90, ibn_rva);
                }
            }
            write_u16(&mut buf, text_base + 0xA0, 0);
            let name = b"ExitProcess\0";
            buf[text_base + 0xA2..text_base + 0xA2 + name.len()].copy_from_slice(name);
            let dll = b"kernel32.dll\0";
            buf[text_base + 0xB0..text_base + 0xB0 + dll.len()].copy_from_slice(dll);
        }

        write_dd(&mut buf, dd_off, 1, import_rva, import_size);
        write_dd(&mut buf, dd_off, 12, iat_rva, iat_size);
    } else {
        buf[text_raw_ptr as usize] = 0xC3;
    }

    match opts.corrupt {
        CorruptMode::BadTlsSize => {
            write_dd(&mut buf, dd_off, 9, opts.text_va + 0x10, 4);
        }
        CorruptMode::BadExceptionSize => {
            write_dd(&mut buf, dd_off, 3, opts.text_va + 0x10, 10);
        }
        CorruptMode::BadRelocBlock => {
            let rva = opts.text_va + 0x20;
            write_dd(&mut buf, dd_off, 5, rva, 16);
            let off = (text_raw_ptr + 0x20) as usize;
            write_u32(&mut buf, off, opts.text_va);
            write_u32(&mut buf, off + 4, 4);
        }
        _ => {}
    }

    if opts.include_reloc && !matches!(opts.corrupt, CorruptMode::DynamicBaseNoReloc) {
        write_dd(&mut buf, dd_off, 5, reloc_va, 12);
        let roff = reloc_raw_ptr as usize;
        write_u32(&mut buf, roff, opts.text_va);
        write_u32(&mut buf, roff + 4, 12);
        write_u16(&mut buf, roff + 8, 0x3000);
        write_u16(&mut buf, roff + 10, 0);
        let dll_off = opt + 70;
        let mut dll = u16::from_le_bytes([buf[dll_off], buf[dll_off + 1]]);
        dll |= IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE;
        write_u16(&mut buf, dll_off, dll);
    }

    let sh = section_table_off;
    write_section_name(&mut buf, sh, b".text");
    let text_raw = if matches!(opts.corrupt, CorruptMode::SectionRawOverflow) {
        0x7FFF_0000
    } else {
        opts.text_raw_size
    };
    write_u32(&mut buf, sh + 8, opts.text_virt_size);
    write_u32(&mut buf, sh + 12, opts.text_va);
    write_u32(&mut buf, sh + 16, text_raw);
    write_u32(&mut buf, sh + 20, text_raw_ptr);
    write_u32(&mut buf, sh + 36, opts.text_chars);

    if opts.include_reloc {
        let sh2 = section_table_off + 40;
        write_section_name(&mut buf, sh2, b".reloc");
        write_u32(&mut buf, sh2 + 8, 0x20);
        write_u32(&mut buf, sh2 + 12, reloc_va);
        write_u32(&mut buf, sh2 + 16, reloc_raw_size);
        write_u32(&mut buf, sh2 + 20, reloc_raw_ptr);
        write_u32(&mut buf, sh2 + 36, IMAGE_SCN_MEM_READ | 0x4200_0000);
    }

    if matches!(opts.corrupt, CorruptMode::SectionVaOverlap) {
        let sh2 = section_table_off + 40;
        write_section_name(&mut buf, sh2, b".data");
        write_u32(&mut buf, sh2 + 8, 0x100);
        // Overlap virtual range with .text (virt extent max(0x100, raw)=0x200)
        write_u32(&mut buf, sh2 + 12, opts.text_va + 0x50);
        write_u32(&mut buf, sh2 + 16, 0);
        write_u32(&mut buf, sh2 + 20, 0);
        write_u32(&mut buf, sh2 + 36, IMAGE_SCN_MEM_READ);
    }

    if matches!(opts.corrupt, CorruptMode::TruncateAfterHeaders) {
        buf.truncate(size_of_headers as usize);
        return buf;
    }

    if let CorruptMode::TruncateFile(n) = opts.corrupt {
        if n < buf.len() {
            buf.truncate(n);
        }
    }

    buf
}

fn write_dd(buf: &mut [u8], dd_off: usize, index: usize, rva: u32, size: u32) {
    let o = dd_off + index * 8;
    write_u32(buf, o, rva);
    write_u32(buf, o + 4, size);
}

fn write_section_name(buf: &mut [u8], off: usize, name: &[u8]) {
    let n = name.len().min(8);
    buf[off..off + n].copy_from_slice(&name[..n]);
}

fn align_up(v: u32, a: u32) -> u32 {
    let r = v % a;
    if r == 0 {
        v
    } else {
        v + (a - r)
    }
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
