//! Turn a **memory image** of a bootstrapped packed DLL into a loadable PE file.
//!
//! ## Why a file-backed debugger
//!
//! `mida_pe::dump_process` is the component that knows how to take a mapped
//! image — sections laid out at their virtual addresses, import descriptors in
//! whatever state the packer left them — and emit a proper PE file with a
//! rebuilt import table, `.pdata`, `.reloc`, and sane section headers.
//!
//! It only ever talks to the target through `mida_core::DebuggerCore`, which is
//! just `read_memory` plus a few debugger operations it never calls.  So the
//! same pipeline can run against a **file** that holds a memory image, which is
//! exactly what an external dumper produces.
//!
//! That matters because the live path is a race: the shell replaces its
//! runtime import directory with the original decoy once `DllMain` returns, so
//! attaching at the wrong moment reads 12 fake descriptors instead of the 115
//! real ones.  A saved image has no such race — the capture is a single point in
//! time and can be re-analysed as often as needed.
//!
//! ## Input requirements
//!
//! * A file whose contents are the module laid out at its virtual addresses
//!   (i.e. `PointerToRawData == VirtualAddress` for every section).  Both
//!   `pe-sieve /imp 1` and `mida-cli`'s own dumps have this shape.
//! * The image base the module was mapped at, passed on the command line
//!   (pe-sieve records it in the filename: `<base>.<name>.dll`).
//!
//! Run:
//!   cargo run --release --bin dll_image -- <image> <base-hex> <out> [oep-rva] [orig-dll] [iat-rva] [iat-size]

use std::path::Path;

use mida_core::DebuggerCore;
use windows::Win32::Foundation::HANDLE;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let image = args.get(1).ok_or("usage: dll_image <image> <base-hex> <out> [oep-rva] [orig-dll] [iat-rva] [iat-size]")?;
    let base = u64::from_str_radix(args.get(2).ok_or("missing <base-hex>")?.trim_start_matches("0x"), 16)?;
    let out = args.get(3).ok_or("missing <out>")?;
    // The protected DLL on disk.  `dump_process` uses it as the fallback source
    // of import names when the live IAT cannot be turned into a table.
    let orig_dll = args.get(5).cloned();

    let data = std::fs::read(image)?;
    println!("image = {image} ({} bytes)", data.len());
    println!("base  = {base:#x}");

    // Load every DLL the image imports into *this* process.
    //
    // `dump_process` resolves IAT slots by matching each slot against the export
    // tables of the loaded modules.  For a live target that happens naturally;
    // for a file-backed image the module list comes from the current process,
    // and a stock process has only a fraction of the 13 modules this DLL needs
    // (comctl32, urlmon, wininet, iphlpapi … are not loaded until something asks
    // for them).  Preloading them is what turns "30 thunks in 1 module" into the
    // real ~300 thunks across 12 modules.
    if let Some(dll) = &orig_dll {
        let mut loaded = 0usize;
        let mut total = 0usize;
        for name in import_dll_names(dll).unwrap_or_default() {
            total += 1;
            let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `wide` is a valid null-terminated UTF-16 string.
            let h = unsafe {
                windows::Win32::System::LibraryLoader::LoadLibraryW(
                    windows::core::PCWSTR::from_raw(wide.as_ptr()),
                )
            };
            if h.is_ok() {
                loaded += 1;
            }
        }
        println!("preloaded {loaded}/{total} import DLLs");
    }

    let mut fb = FileBacked { data, image_base: base };

    // The header must be readable through the same interface the pipeline uses.
    let mut head = vec![0u8; 0x1000];
    fb.read_memory(base as usize, &mut head)
        .map_err(|e| format!("cannot read image header: {e:?}"))?;
    let pe = mida_pe::PeHeader::from_bytes(&head)?;
    println!("sections = {}", pe.sections.len());
    println!("shell EP = {:#x}", pe.entry_point);

    // Locate the real `DllMain`: the fdwReason dispatch guarded by inter-function
    // padding.  See `dll_dump.rs` for why both tests are needed.
    let oep_rva = match args.get(4) {
        Some(v) => u32::from_str_radix(v.trim_start_matches("0x"), 16)?,
        None => find_oep_rva(&mut fb, base)?,
    };
    println!("oep rva  = {oep_rva:#x}");

    // Locate the runtime IAT.
    //
    // The shell keeps its dense import table at a fixed offset relative to the
    // image (rva 0x141a78 on the reference sample, 3282 slots).  `dump_process`
    // scans a span linearly and splits it into per-module groups on runs of zero
    // slots, which is exactly the shape this table has.
    //
    // Do NOT feed it the min..max span over all 115 import descriptors: that
    // range covers unrelated `.rdata` as well (rva 0x1032e0..0x33926a, 289k
    // slots), and the resulting import table is rejected by the loader with
    // ERROR_INVALID_PARAMETER (487).
    //
    // The offset is sample-specific.  `real_iat` still runs so its descriptor
    // census is printed, and it is the fallback when the caller overrides the
    // span on the command line.
    let (probed_rva, probed_size, desc_count, _blocks) = real_iat(&mut fb, base)?;
    let (iat_rva, iat_size) = match (args.get(6), args.get(7)) {
        (Some(r), Some(s)) => (
            u32::from_str_radix(r.trim_start_matches("0x"), 16)?,
            u32::from_str_radix(s.trim_start_matches("0x"), 16)?,
        ),
        _ => {
            println!("(probe saw {desc_count} descriptors, widest span {probed_rva:#x}+{probed_size:#x})");
            (0x141a78u32, 26256u32)
        }
    };
    println!("iat span = {iat_rva:#x} .. {:#x}", iat_rva as u64 + iat_size as u64);

    let opts = mida_pe::DumpOptions {
        image_base: base,
        entry_point: oep_rva,
        fix_imports: true,
        create_data_sections: false,
        shrink: true,
        output_path: Path::new(out).to_path_buf(),
        executable_path: orig_dll.as_deref().map(Path::new).map(|p| p.to_path_buf()),
        iat_location: Some((base as usize + iat_rva as usize, iat_size as usize)),
        additional_iat_locations: Vec::new(),
    };
    mida_pe::dump_process(&mut fb, &opts)?;
    println!("written to {out} ({} bytes)", std::fs::metadata(out)?.len());
    Ok(())
}

/// Read the DLL names out of the import directory of `path`.
///
/// These are the modules whose export tables the IAT resolver needs to see, so
/// they are loaded into this process before the dump runs.
fn import_dll_names(path: &str) -> Option<Vec<String>> {
    let mut head = vec![0u8; 0x1000];
    let f = std::fs::File::open(path).ok()?;
    use std::io::Read;
    (&f).take(0x1000).read_exact(&mut head).ok()?;
    let pe = mida_pe::PeHeader::from_bytes(&head).ok()?;
    let imp_rva = pe.nt_headers.optional_header.data_directory[1].virtual_address;
    if imp_rva == 0 {
        return None;
    }

    // Map the import directory's RVA to a file offset via the section table.
    let mut file = std::fs::read(path).ok()?;
    let off = pe
        .sections
        .iter()
        .find(|s| imp_rva >= s.virtual_address && imp_rva < s.virtual_address + s.virtual_size)
        .map(|s| (s.raw_offset as usize) + (imp_rva - s.virtual_address) as usize)?;

    let mut names = Vec::new();
    for i in 0..64usize {
        let ent = file.get(off + i * 20..off + i * 20 + 20)?;
        let name_rva = u32::from_le_bytes(ent[12..16].try_into().ok()?) as usize;
        if name_rva == 0 {
            break;
        }
        let noff = pe
            .sections
            .iter()
            .find(|s| name_rva >= s.virtual_address as usize && name_rva < (s.virtual_address + s.virtual_size) as usize)
            .map(|s| (s.raw_offset as usize) + (name_rva - s.virtual_address as usize))?;
        let end = file[noff..].iter().position(|&b| b == 0).map(|n| noff + n)?;
        let name = String::from_utf8_lossy(&file[noff..end]).to_string();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    Some(names)
}

/// A `DebuggerCore` whose "process memory" is a file holding a memory image.
struct FileBacked {
    data: Vec<u8>,
    image_base: u64,
}

impl std::fmt::Debug for FileBacked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileBacked")
            .field("len", &self.data.len())
            .field("image_base", &format_args!("{:#x}", self.image_base))
            .finish()
    }
}

impl mida_core::DebuggerCore for FileBacked {
    fn process_handle(&self) -> HANDLE {
        HANDLE::default()
    }
    fn pid(&self) -> u32 {
        0
    }
    fn image_base(&self) -> u64 {
        self.image_base
    }
    fn wait_event(&mut self) -> Result<mida_core::DebugEvent, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn wait_event_timeout(&mut self, _ms: u32) -> Result<mida_core::DebugEvent, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn continue_event(&mut self, _tid: u32, _s: mida_core::ContinueStatus) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }

    fn read_memory(&self, address: usize, buf: &mut [u8]) -> Result<usize, mida_core::CoreError> {
        let off = (address as u64).wrapping_sub(self.image_base) as usize;
        let avail = self.data.len().saturating_sub(off);
        let n = avail.min(buf.len());
        if n > 0 {
            buf[..n].copy_from_slice(&self.data[off..off + n]);
        }
        // Zero-fill the tail rather than failing: an image ends at
        // `SizeOfImage`, and callers legitimately read past the last section.
        buf[n..].fill(0);
        Ok(buf.len())
    }

    fn write_memory(&mut self, address: usize, data: &[u8]) -> Result<usize, mida_core::CoreError> {
        let off = (address as u64).wrapping_sub(self.image_base) as usize;
        let n = self.data.len().saturating_sub(off).min(data.len());
        if n > 0 {
            self.data[off..off + n].copy_from_slice(&data[..n]);
        }
        Ok(n)
    }

    fn get_thread_context(&self, _tid: u32) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn get_thread_context_control(&self, _tid: u32) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn get_thread_context_control_integer(&self, _tid: u32) -> Result<windows::Win32::System::Diagnostics::Debug::CONTEXT, mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
    fn set_thread_context(&self, _tid: u32, _ctx: &windows::Win32::System::Diagnostics::Debug::CONTEXT) -> Result<(), mida_core::CoreError> {
        Err(mida_core::CoreError::Windows(0))
    }
}

/// Locate the real `DllMain` RVA.
///
/// Requires **both** a function-boundary marker before the candidate and a
/// `cmp edx, 1|2` within the first 64 bytes:
///
/// * the padding test rejects mid-function `0x48 0x89` hits (which produced
///   rva 0x1088 on the reference image), and
/// * the `fdwReason` dispatch rejects plain functions that happen to start on
///   a boundary.
fn find_oep_rva(fb: &mut FileBacked, base: u64) -> Result<u32, Box<dyn std::error::Error>> {
    let mut head = vec![0u8; 0x1000];
    fb.read_memory(base as usize, &mut head).map_err(|e| format!("{e:?}"))?;
    let pe = mida_pe::PeHeader::from_bytes(&head)?;
    let text = &pe.sections[0];
    let text_va = text.virtual_address as u64;
    let text_vsz = text.virtual_size as u64;

    let mut buf = vec![0u8; text_vsz as usize];
    fb.read_memory((base + text_va) as usize, &mut buf).map_err(|e| format!("{e:?}"))?;

    for i in 8..buf.len().saturating_sub(64) {
        if !at_function_boundary(&buf, i) || !is_prologue(&buf, i) {
            continue;
        }
        for j in i..(i + 64).min(buf.len().saturating_sub(3)) {
            if buf[j] == 0x83 && buf[j + 1] == 0xFA && (buf[j + 2] == 0x01 || buf[j + 2] == 0x02) {
                return Ok(text_va as u32 + i as u32);
            }
        }
    }
    Err("no DllMain signature found in .text".into())
}

fn at_function_boundary(text: &[u8], i: usize) -> bool {
    if i < 8 {
        return false;
    }
    if text[i - 8..i] == [0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00] {
        return true;
    }
    if text[i - 2..i] == [0x66, 0x90] {
        return true;
    }
    text[i - 4..i].iter().all(|&b| b == 0xCC || b == 0x90)
}

fn is_prologue(text: &[u8], i: usize) -> bool {
    match text[i] {
        0x55 | 0x53 | 0x56 | 0x57 => true,
        0x48 => matches!(text[i + 1], 0x83 | 0x81 | 0x89),
        0x41 => matches!(text[i + 1], 0x54..=0x57),
        _ => false,
    }
}

/// Find the runtime import table and return `(iat_rva, iat_size, descriptors)`.
///
/// Reads the IMPORT data directory out of the **live header**, then walks the
/// descriptors looking for the widest sparse thunk array.  "Sparse" matters:
/// the shell interleaves zeros with the addresses
/// (`0x7fffe3f83f90, 0, 0x7fff2cebe120, 0, …`), so a naive scan that stops at
/// the first zero sees a single slot per module.
fn real_iat(
    fb: &mut FileBacked,
    base: u64,
) -> Result<(u32, u32, u32, Vec<(u32, u32)>), Box<dyn std::error::Error>> {
    let mut head = vec![0u8; 0x1000];
    fb.read_memory(base as usize, &mut head).map_err(|e| format!("{e:?}"))?;
    let pe = mida_pe::PeHeader::from_bytes(&head)?;
    let imp = pe.nt_headers.optional_header.data_directory[1];
    if imp.virtual_address == 0 {
        return Err("live IMPORT directory is empty".into());
    }
    let imp_rva = imp.virtual_address as u64;

    let mut blocks: Vec<(u32, u32)> = Vec::new();
    let mut count = 0u32;
    for i in 0..512u64 {
        let mut ent = [0u8; 20];
        fb.read_memory((base + imp_rva + i * 20) as usize, &mut ent)
            .map_err(|e| format!("{e:?}"))?;
        let oft = u32::from_le_bytes(ent[0..4].try_into()?) as u64;
        let name = u32::from_le_bytes(ent[12..16].try_into()?) as u64;
        let ft = u32::from_le_bytes(ent[16..20].try_into()?) as u64;
        if oft == 0 && ft == 0 && name == 0 {
            break;
        }
        count += 1;
        if ft == 0 {
            continue;
        }
        let mut last_nonzero = 0u64;
        for n in 0..4096u64 {
            let mut slot = [0u8; 8];
            if fb.read_memory((base + ft + n * 8) as usize, &mut slot).is_err() {
                break;
            }
            if u64::from_le_bytes(slot) != 0 {
                last_nonzero = n + 1;
            } else if n > last_nonzero.saturating_add(64) {
                break;
            }
        }
        let extent = last_nonzero * 8;
        // Single-slot arrays are the shell's decoy shape; skip them.
        if last_nonzero >= 2 && extent > 0 {
            blocks.push((ft as u32, extent as u32));
        }
    }
    if blocks.is_empty() {
        return Err("no multi-slot thunk arrays found".into());
    }
    // Report the span covering every block.  `dump_process` walks the span
    // linearly and splits it into per-module groups on runs of zero slots, so a
    // covering span is exactly the right input — and the gaps between blocks
    // become the group delimiters.
    let lo = blocks.iter().map(|&(rva, _)| rva).min().unwrap();
    let hi = blocks.iter().map(|&(rva, sz)| rva as u64 + sz as u64).max().unwrap();
    Ok((lo, (hi - lo as u64) as u32, count, blocks))
}
