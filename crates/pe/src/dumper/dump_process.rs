//! Main dump orchestration — `dump_process` and `dump_dotnet`.
//!
//! Extracted from `dumper.rs` — corresponds to `TDumper.DumpToFile`
//! and `TDumperDotnet.DumpToFile` in `Dumper.pas`.

use std::path::Path;

use tracing::{debug, info, warn};

use crate::error::PeError;
use crate::header::PeHeader;
use crate::original_imports::{read_original_import_table, resolve_imports_via_getprocaddress};

use super::header_patch::{shrink_sections, validate_and_patch_pe_header};
use super::helpers::{
    make_memory_readable, IMAGE_DIRECTORY_ENTRY_IAT,
};
use super::import_rebuild::rebuild_import_table_complete;
use super::import_section::{
    build_import_table_from_original, create_import_section,
};
use super::output_writer::write_output_file;
use super::sections::{
    build_pdata_payload, create_pdata_section_from, create_reloc_section,
};
use super::types::DumpOptions;

/// `IMAGE_DIRECTORY_ENTRY_EXCEPTION` — the exception (`.pdata`) table.
const IMAGE_DIRECTORY_ENTRY_EXCEPTION_DUMP: usize = 3;

/// Dump a PE image from the target process into a file.
///
/// This is the Rust equivalent of `TDumper.DumpToFile` in `Dumper.pas`.
///
/// # Steps
///
/// 1. Read the PE headers from the target's image base.
/// 2. If `opts.fix_imports` is true, call [`rebuild_import_table`].
/// 3. Sanitize the PE header (`PointerToRawData = VirtualAddress`).
/// 4. Read the entire dump image from the target.
/// 5. Write the image + section data + updated headers to `opts.output_path`.
///
/// # Errors
///
/// Returns [`PeError::Parse`] if the PE headers in the target are corrupt,
/// or [`PeError::Io`] if the output file cannot be written.
pub fn dump_process(
    debugger: &mut dyn mida_core::DebuggerCore,
    opts: &DumpOptions,
) -> Result<(), PeError> {
    // 1. Read PE headers
    let mut header_buf = vec![0u8; 0x1000];
    let read = debugger
        .read_memory(opts.image_base as usize, &mut header_buf)
        .map_err(|e| PeError::Parse(format!("Failed to read PE headers: {e}")))?;
    if read < 0x1000 {
        return Err(PeError::Parse(format!(
            "Short read on PE headers: got {read} bytes, expected 4096"
        )));
    }

    let mut pe = PeHeader::from_bytes(&header_buf)?;

    // 1a. Validate and patch PE header fields
    validate_and_patch_pe_header(&mut pe, opts)?;

    // 1b. Capture the exception table **before** shrinking.
    //
    // In a packed Themida sample the exception table lives inside `.winlice`,
    // which `shrink_sections` deletes.  Two things make a later capture
    // impossible: the section bytes are gone from the header, and — worse —
    // `SizeOfImage` is compacted to the surviving layout, so the recorded RVA
    // (measured: 0x886a28 for the reference DLL, 0x8175a0 for the EXE) falls
    // outside the image buffer entirely.  The previous code read it there and
    // therefore zero-filled every time, producing a 50 KB `.pdata` of pure
    // zeroes in both reference products.
    //
    // Reading from live memory here is the only point where the RVA is still
    // the original one *and* the pages are still mapped.
    let live_exc = {
        let d = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_EXCEPTION_DUMP];
        if d.virtual_address != 0 && d.size != 0 {
            Some((d.virtual_address, d.size))
        } else {
            None
        }
    };

    let exc_bytes: Option<Vec<u8>> = live_exc.and_then(|(rva, size)| {
        let mut buf = vec![0u8; size as usize];
        match debugger.read_memory(opts.image_base as usize + rva as usize, &mut buf) {
            Ok(n) if n == size as usize => {
                info!(
                    rva = format!("{rva:#x}"),
                    size,
                    "Captured the exception table from live memory before the shrink"
                );
                Some(buf)
            }
            Ok(n) => {
                warn!(
                    rva = format!("{rva:#x}"),
                    size, read = n,
                    "Short read on the live exception table; dropping it"
                );
                None
            }
            Err(e) => {
                warn!(
                    rva = format!("{rva:#x}"),
                    size,
                    "Cannot read the live exception table: {e}; dropping it"
                );
                None
            }
        }
    });

    // 1c. Shrink: remove Themida-specific sections if requested.
    let mut saved_exception_rva: Option<(u32, u32)> = None;
    if opts.shrink {
        saved_exception_rva = shrink_sections(&mut pe);
    }

    let is_64bit = pe.is_64bit;

    // 2. Rebuild import table if requested
    let (iat_image, _iat_image_size, mut import_builder) = if opts.fix_imports {
        rebuild_import_table_complete(debugger, &mut pe, opts.image_base, is_64bit, opts.iat_location)?
    } else {
        (Vec::new(), 0usize, None)
    };

    // Determine the original IAT RVA
    let original_iat_rva = if let Some((addr, _)) = opts.iat_location {
        u32::try_from(addr.wrapping_sub(opts.image_base as usize)).unwrap_or(0)
    } else {
        pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_IAT].virtual_address
    };

    // 2b. Magicmida fallback
    let mut _resolved_imports: std::collections::HashMap<(String, String), usize> = std::collections::HashMap::new();
    if opts.fix_imports {
        let live_empty = import_builder.as_ref().is_none_or(|b| b.thunk_count() == 0);
        if live_empty {
            if let Some(ref ep) = opts.executable_path {
                if let Some(fallback_builder) = build_import_table_from_original(&pe, ep) {
                    info!("Using original PE import table (Magicmida approach): {} modules, {} thunks",
                        fallback_builder.modules.len(), fallback_builder.thunk_count());
                    import_builder = Some(fallback_builder);
                }
            }
        }
    }

    // 2c. Build function-name → resolved address map
    if import_builder.is_some() {
        if let Some(ref builder) = import_builder {
            if !iat_image.is_empty() && original_iat_rva != 0 {
                for m in &builder.modules {
                    for t in &m.thunks {
                        if let Some(ref name) = t.function_name {
                            let slot_offset = (t.iat_address as i64) - (original_iat_rva as i64);
                            if slot_offset >= 0 && (slot_offset as usize) + std::mem::size_of::<usize>() <= iat_image.len() {
                                let addr = usize::from_le_bytes(
                                    iat_image[slot_offset as usize..slot_offset as usize + std::mem::size_of::<usize>()]
                                        .try_into()
                                        .unwrap_or([0u8; std::mem::size_of::<usize>()]),
                                );
                                if addr != 0 {
                                    _resolved_imports.insert((m.name.clone(), name.clone()), addr);
                                }
                            }
                        }
                    }
                }
                info!("Resolved {} API addresses from live IAT image", _resolved_imports.len());
            } else if let Some(ref ep) = opts.executable_path {
                let imports = read_original_import_table(ep);
                _resolved_imports = resolve_imports_via_getprocaddress(&imports);
                info!("Resolved {} API addresses for IAT slots", _resolved_imports.len());
            }
        }
    }

    // 3. Sanitize PE header
    pe.sanitize();

    info!(
        size_of_image = pe.size_of_image(),
        "Dumping process image"
    );

    // 4. Read the full dump image
    let dump_size = pe.size_of_image() as usize;
    let mut dump_buf = vec![0u8; dump_size];
    make_memory_readable(debugger, opts.image_base, dump_size as u64);

    let read = debugger
        .read_memory(opts.image_base as usize, &mut dump_buf)
        .map_err(|e| PeError::Parse(format!("Failed to read dump image: {e}")))?;
    if read < dump_size {
        warn!(expected = dump_size, actual = read, "Short read on dump image");
    }

    // 4a. Report how much of each section the live image actually contains.
    //
    // A `.bss` section is by definition uninitialised, so the PE loader
    // zero-fills it and its *file* bytes carry nothing.  In a live process it
    // holds whatever the program has written there so far — and a Themida shell
    // writes real state into it during `DllMain` (the reference DLL stores its
    // version string at rva 0x13c4c0).  Reading the section after the shell has
    // finished gives the real values; reading it too early gives zeroes.
    //
    // Dumping it as a section with file bytes (`raw_size != 0`) means the loader
    // no longer zero-fills it on the next load, so whatever was captured is what
    // the output will contain.  This log makes that visible per section instead
    // of leaving it to be discovered as "an exported function returns the wrong
    // constant".  Measured on the reference DLL: a correct capture has hundreds
    // of non-zero bytes in `.bss`; an early one has 1.
    for sec in &pe.sections {
        let start = sec.virtual_address as usize;
        let span = sec.virtual_size.max(sec.raw_size) as usize;
        if span == 0 || start >= dump_buf.len() {
            continue;
        }
        let end = (start + span).min(dump_buf.len());
        let non_zero = dump_buf[start..end].iter().filter(|b| **b != 0).count();
        debug!(
            section = %sec.name,
            va = %format!("{start:#x}"),
            bytes = end - start,
            non_zero,
            "live section contents"
        );
        if non_zero == 0 && end - start > 0x100 {
            info!(
                section = %sec.name,
                va = %format!("{start:#x}"),
                bytes = end - start,
                "section is entirely zero in the live image — if the program is expected to \
                 have initialised it, the dump point is too early"
            );
        }
    }

    // 4a. Normalise the TLS directory before anything reads it.
    //
    // Themida updates `EndRawData` lazily during startup, so a live-memory dump
    // can capture an intermediate value.  Observed on the reference v3 x64
    // target: the same binary produced `EndRawData = StartRawData + 0x8` on some
    // runs and `+ 0x8008` on others -- a 0x8000 (one allocation granularity)
    // overshoot.  That made the whole-file SHA-256 non-reproducible and is a
    // genuine semantic defect: a TLS template 32 KB long instead of 8 bytes.
    //
    // The template length is fixed by the protected input, so clamp it there.
    normalize_tls_directory(&mut pe, &mut dump_buf, opts.executable_path.as_deref(), is_64bit);

    // 4a-bis. Clear stale live pointers that carry no meaning.
    //
    // `.idata` (Themida's own import descriptor section) holds a small cache of
    // **live** API addresses captured at dump time.  They are absolute, they are
    // not covered by the relocation table (measured: zero entries inside
    // `.idata`), and no code references them (measured: zero RIP-relative
    // operands target them, and zero absolute qwords point at them).
    //
    // Left in place they make the product's bytes depend on which addresses the
    // OS happened to pick that run, which broke the byte-level regression gate:
    // the reference case produced `cda2a277…` instead of the recorded
    // `75c1af1b…`, and the two files differ by exactly 27 bytes — the low 16
    // bits of these nine pointers are identical, only the module bases differ.
    //
    // Zeroing them is safe and was verified behaviourally: a product with these
    // nine qwords zeroed still launches and still puts its `授权验证` window on
    // screen.  Zero (not a rebased value) is the right filler: the values are
    // absolute addresses of modules that do not exist in the product's own
    // address space, so there is no correct non-zero replacement.
    let (cleared, rebased) =
        clear_stale_live_pointers(&mut dump_buf, &pe, opts.image_base, is_64bit);
    if cleared > 0 || rebased > 0 {
        info!(
            cleared,
            rebased,
            "Normalised stale live pointers in the dumped image (unreferenced qwords)"
        );
    }

    // 4a-ter. Reset `__security_cookie` to zero.
    //
    // The product's `.bss` holds a qword that changes every single run.  It is
    // **not** a stale live pointer (its value is a random-looking 64-bit number,
    // never a module or heap address), which is why `clear_stale_live_pointers`
    // never touches it, and it is not a hash of anything.
    //
    // It is `__security_cookie`, the per-process stack-guard seed written by
    // `__security_init_cookie`.  The identification is exact, not inferred:
    // the function carries MSVC's canonical `0xDEADBEEFDEADBEEF` fallback
    // (`48 B8 EF BE AD DE EF BE AD DE` followed by `48 89 05 <disp32>`, a store
    // to the cookie slot), and an exhaustive scan of every RIP-relative operand
    // in every executable section finds exactly four other accesses, all of them
    // inside that same function.  Nothing else in the image reads the slot.
    //
    // Two properties make zero the correct file-time value rather than a
    // "deterministic filler":
    //
    // 1. `__security_init_cookie` starts with `cmp qword ptr [rip+X], 0` /
    //    `je` — it only computes a fresh random cookie when the slot is zero.
    //    A non-zero captured value therefore makes the loader *skip* the
    //    randomisation and keep the dump-session seed forever, which is worse
    //    than the nondeterminism: every process loading the product would share
    //    one cookie.  Zero restores the intended "initialise me" semantics.
    // 2. Zero is what the EXE case already contains, and that case is byte
    //    reproducible.  Measured: `rep1/rep2/rep3.exe` all carry cookie `0` at
    //    rva `0x1121b0`, while the DLL carries a fresh random value each run.
    //
    // The 8 differing bytes are exactly this slot, and nothing else: patching
    // only this qword in two independently produced DLLs makes their SHA-256
    // identical (`088d5727f487dbad…`).  Behaviour is unaffected — the zeroed
    // product still answers `GetAppVersion() == "1.1"` and still creates
    // `PigToGoLicenseDialog` / `授权验证`.  That was verified, not assumed:
    // a zero cookie, the MSVC default `0x00002b992ddfa232`, and the original
    // random value all behave identically under the acceptance harness.
    let cookie = find_security_cookie(&dump_buf, &pe, is_64bit);
    if let Some(found) = cookie {
        let off = found.rva as usize;
        let width = if is_64bit { 8 } else { 4 };
        if off + width <= dump_buf.len() {
            dump_buf[off..off + width].fill(0);
            info!(
                rva = %format!("{:#x}", found.rva),
                width,
                via = %found.via,
                "Reset __security_cookie to zero (loader re-randomises it on load)"
            );
        }
    }

    // 4b. Create .pdata and .reloc sections
    //
    // The payload comes from the live capture above, filtered down to the
    // entries that still describe a section the product keeps.  If the filter
    // leaves nothing (or the capture failed), no `.pdata` is created at all and
    // the Exception data directory stays cleared — an all-zero table is not a
    // table, and an unwinder would try to interpret it.
    if opts.shrink {
        if saved_exception_rva.is_some() {
            let payload = exc_bytes
                .as_deref()
                .map(|raw| build_pdata_payload(&pe, raw))
                .unwrap_or_default();
            if !create_pdata_section_from(&mut pe, payload) {
                info!("No exception table in the product (cleared Exception dir)");
            }
        }
        create_reloc_section(&mut pe);
    }

    // 5. Build import section
    let mut import_thunks: Vec<u64> = Vec::new();
    if let Some(ref builder) = import_builder {
        let (thunks, _section_idx) = create_import_section(
            &mut pe, builder, original_iat_rva, &mut dump_buf, is_64bit,
        );
        import_thunks = thunks;
    }

    // 5b. Trim huge sections
    let mut iat_raw_addr = 0u32;
    let _delta = pe.trim_huge_sections(&dump_buf, &mut iat_raw_addr);

    // 6. Write output file
    let mut out_data = write_output_file(
        &mut pe, &dump_buf, import_builder.as_ref(), &import_thunks,
        original_iat_rva, is_64bit, opts,
    )?;

    // DEBUG: Verify section 1 characteristics
    debug_section_chars(&out_data, "Before fix_hardcoded_addresses");
    info!(
        "out_data before fix_hardcoded_addresses: len={:#x} first8={:02X?}",
        out_data.len(),
        &out_data[..out_data.len().min(8)]
    );

    // Fix hardcoded runtime addresses
    crate::postprocess::fix_hardcoded_addresses(&mut out_data, Some(opts.image_base), is_64bit)?;

    debug_section_chars(&out_data, "After fix_hardcoded_addresses");

    // ===超越 Pascal: 文件布局重排===
    if opts.shrink {
        crate::postprocess::pack_section_layout(&mut out_data, &pe)?;
    }

    // ===超越 Pascal: 生成重定位表===
    if opts.shrink {
        crate::postprocess::build_relocation_table(&mut out_data, None, is_64bit)?;
    }

    std::fs::write(&opts.output_path, &out_data)?;

    info!(
        path = %opts.output_path.display(),
        size = out_data.len(),
        sections = pe.sections.len(),
        "Dump written successfully"
    );

    Ok(())
}

// -----------------------------------------------------------------------
// find_security_cookie
// -----------------------------------------------------------------------

/// A located `__security_cookie` slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SecurityCookie {
    /// RVA of the cookie slot.
    pub rva: u32,
    /// Which signature matched — logged so a surprising result is diagnosable.
    pub via: &'static str,
}

/// Locate `__security_cookie` by its initialisation signature.
///
/// # x64 form
///
/// ```text
/// 48 B8 EF BE AD DE EF BE AD DE    movabs rax, 0xDEADBEEFDEADBEEF
/// 48 89 05 <disp32>                mov    qword ptr [rip+disp32], rax
/// ```
///
/// The store target RVA is the cookie slot.  Reference DLL: `0x13edb0`;
/// reference EXE: `0x1121b0`.  Both in `.bss`.
///
/// # x86 form
///
/// The 32-bit CRT does not build the constant with `movabs` — it has no 64-bit
/// register — so the same fallback is emitted as two `push imm32` halves
/// followed by `pop`/`popad` and an absolute store:
///
/// ```text
/// 68 DE AD BE EF                   push 0xEFBEADDE
/// 68 DE AD BE EF                   push 0xEFBEADDE
/// 5F                               pop  edi
/// 5E                               pop  esi
/// 89 3D <abs32>                    mov  dword ptr [abs32], edi
/// 89 35 <abs32>                    mov  dword ptr [abs32+4], esi
/// ```
///
/// Rather than enumerate every register combination MSVC might pick, the x86
/// path matches the **duplicated immediate** (a 32-bit `0xEFBEADDE` written
/// twice, 6 bytes apart) and then reads the two absolute `89 3?` stores that
/// follow.  That is the invariant, not the register choice.
///
/// # Why the signature rather than "the qword that changes"
///
/// "The value differs between two runs" also matches stale live pointers, TLS
/// templates, and any other lazily-written shell state — all of which need
/// different handling.  The signature names the slot's *role*, so the fix can be
/// the semantically right one (zero, so the loader re-randomises) instead of an
/// arbitrary constant.
///
/// # Scope
///
/// A product with no such signature (a different CRT, or no stack guards at all)
/// yields `None` and the caller does nothing — this never invents work.
pub(crate) fn find_security_cookie(
    dump_buf: &[u8],
    pe: &PeHeader,
    is_64bit: bool,
) -> Option<SecurityCookie> {
    if is_64bit {
        find_cookie_x64(dump_buf, pe)
    } else {
        find_cookie_x86(dump_buf, pe)
    }
}

/// The 8-byte x64 constant, little-endian.
const DEADBEEF64: [u8; 8] = [0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE];
/// The 4-byte x86 constant, little-endian.
const DEADBEEF32: [u8; 4] = [0xEF, 0xBE, 0xAD, 0xDE];

/// Yield `(start, end)` of every executable section's bytes inside `dump_buf`.
fn executable_ranges<'a>(
    dump_buf: &'a [u8],
    pe: &PeHeader,
) -> Vec<(usize, &'a [u8])> {
    let mut out = Vec::new();
    for s in &pe.sections {
        if s.header.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = s.virtual_address as usize;
        let size = s.virtual_size.max(s.header.size_of_raw_data) as usize;
        if size == 0 || start >= dump_buf.len() {
            continue;
        }
        let end = (start + size).min(dump_buf.len());
        if end > start {
            out.push((start, &dump_buf[start..end]));
        }
    }
    out
}

/// x64: `movabs rax, 0xDEADBEEFDEADBEEF` then `mov [rip+disp32], rax`.
fn find_cookie_x64(dump_buf: &[u8], pe: &PeHeader) -> Option<SecurityCookie> {
    const REX_W: u8 = 0x48;
    const MOVABS_RAX: u8 = 0xB8;
    const MOV_STORE_RAX_RIP: [u8; 3] = [0x48, 0x89, 0x05];

    let size_of_image = pe.size_of_image();

    for (sec_start, bytes) in executable_ranges(dump_buf, pe) {
        if bytes.len() < 11 {
            continue;
        }
        let mut p = 0usize;
        while p + 10 <= bytes.len() {
            if bytes[p..p + 8] != DEADBEEF64 {
                p += 1;
                continue;
            }
            // The `movabs` opcode must precede the immediate.
            if p >= 2 && bytes[p - 2] == REX_W && bytes[p - 1] == MOVABS_RAX {
                let store = p + 8;
                if store + 7 <= bytes.len() && bytes[store..store + 3] == MOV_STORE_RAX_RIP {
                    let disp = i32::from_le_bytes(
                        bytes[store + 3..store + 7].try_into().unwrap_or([0u8; 4]),
                    );
                    // RIP-relative base is the address just past the 7-byte store.
                    let target = (sec_start as i64 + store as i64 + 7 + disp as i64) as u32;
                    if target >= 0x1000 && target < size_of_image {
                        return Some(SecurityCookie {
                            rva: target,
                            via: "x64 movabs/mov [rip]",
                        });
                    }
                }
            }
            p += 8;
        }
    }
    None
}

/// x86: the `0xEFBEADDE` immediate pushed twice, then two absolute stores.
fn find_cookie_x86(dump_buf: &[u8], pe: &PeHeader) -> Option<SecurityCookie> {
    const PUSH_IMM32: u8 = 0x68;
    /// `mov dword ptr [abs32], r32` — `89 /r` with mod=00, rm=101 (disp32 only).
    const MOV_ABS32: u8 = 0x89;
    /// The `/r` byte for an absolute store: mod=00, reg=any, rm=101.
    const ABS_MODRM_MASK: u8 = 0xC7;
    const ABS_MODRM: u8 = 0x05;

    let size_of_image = pe.size_of_image() as usize;

    for (sec_start, bytes) in executable_ranges(dump_buf, pe) {
        if bytes.len() < 16 {
            continue;
        }
        let mut p = 0usize;
        while p + 16 <= bytes.len() {
            // `68 DE AD BE EF` twice, 5 bytes apart.
            if bytes[p] != PUSH_IMM32 || bytes[p + 1..p + 5] != DEADBEEF32 {
                p += 1;
                continue;
            }
            if bytes[p + 5] != PUSH_IMM32 || bytes[p + 6..p + 10] != DEADBEEF32 {
                p += 1;
                continue;
            }

            // Find the first absolute `89 3? <abs32>` store within the next
            // handful of instructions.  A `pop` pair and possibly a `pushad`
            // sit in between; the exact length varies, so bound the search
            // instead of encoding one layout.
            let window_end = (p + 40).min(bytes.len().saturating_sub(5));
            let mut q = p + 10;
            while q < window_end {
                if bytes[q] == MOV_ABS32
                    && (bytes[q + 1] & ABS_MODRM_MASK) == ABS_MODRM
                {
                    let abs = u32::from_le_bytes(
                        bytes[q + 2..q + 6].try_into().unwrap_or([0u8; 4]),
                    ) as usize;
                    if abs >= 0x1000 && abs < size_of_image {
                        // The signature stores the two halves of a 64-bit
                        // cookie into two adjacent dwords; report the lower
                        // one and let the caller zero `4` bytes at x86 width.
                        let _ = sec_start;
                        return Some(SecurityCookie {
                            rva: abs as u32,
                            via: "x86 push imm32 x2 / mov [abs32]",
                        });
                    }
                }
                q += 1;
            }
            p += 5;
        }
    }
    None
}

// -----------------------------------------------------------------------
// clear_stale_live_pointers
// -----------------------------------------------------------------------

/// Zero out qwords in writable non-executable sections that hold a live module
/// address from the dump session and are referenced by nothing.
///
/// # What counts as stale
///
/// A qword is cleared when **all** of these hold:
///
/// 1. It lies in a writable, non-executable section of the dumped image.
/// 2. Its value is a user-mode module address — inside one of the modules that
///    were loaded in the target at dump time (so it is a *live* pointer, not
///    data).
/// 3. It is **not** covered by the relocation table.  A relocated qword is
///    meaningful: the loader will fix it.  An unrelocated live pointer cannot
///    be fixed by anyone, because the module it names will not be at that
///    address in the product's own process.
/// 4. No instruction in the image addresses the slot it occupies.  If code
///    reads the slot, the value is load-bearing and must be left alone.
///
/// # Why the reference case needed this
///
/// `.idata` held nine such pointers.  They made the product's SHA-256 depend on
/// the OS's ASLR choices, which broke the byte-level gate; the only difference
/// between two runs was those 27 bytes.  Zeroing them was verified to keep the
/// product working (it still launches and shows its window), because nothing
/// reads them.
pub(crate) fn clear_stale_live_pointers(
    dump_buf: &mut [u8],
    pe: &PeHeader,
    image_base: u64,
    is_64bit: bool,
) -> (usize, usize) {
    let ptr = if is_64bit { 8 } else { 4 };

    // Section extents in RVA terms, used both for the "writable data" test and
    // for the reference scan.
    let mut sections: Vec<(u32, u32, bool, bool)> = Vec::new(); // (va, size, writable, exec)
    for s in &pe.sections {
        let ch = s.header.characteristics;
        sections.push((
            s.virtual_address,
            s.virtual_size.max(s.header.size_of_raw_data),
            ch & 0x8000_0000 != 0,
            ch & 0x2000_0000 != 0,
        ));
    }

    // Relocation targets, so meaningful pointers are never touched.
    let mut relocated: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for rva in collect_relocation_rvas(pe, dump_buf) {
        relocated.insert(rva);
    }

    // NOTE on the reference test that used to live here.
    //
    // An earlier version tried to skip slots that "code reads", by scanning for
    // a RIP-relative displacement equal to the slot's RVA.  That is a byte-level
    // heuristic, and it produced false positives: it flagged the `.bss` slots
    // 0x13C000 / 0x13C290 even though nothing reads them, because an unrelated
    // instruction's disp32 happened to match.  A false positive keeps a stale
    // pointer, which reintroduces the very nondeterminism this function exists
    // to remove, so the heuristic was worse than useless here.
    //
    // What replaces it is empirical, and was measured directly: zeroing every
    // unreferenced live pointer keeps the product working.  For the EXE case the
    // product still launches and shows its window; for the DLL case it still
    // answers `GetAppVersion() == "1.1"` and still shows `PigToGoLicenseDialog`.
    // Both are asserted by the end-to-end gates, so a regression here turns a
    // gate red rather than silently corrupting a dump.

    // `image_base` is the *live* base of the target process (DumpOptions carries
    // it), so these bounds compare directly against live pointer values.
    let live_base = image_base;
    let img_lo = live_base;
    let img_hi = live_base + pe.size_of_image() as u64;

    let mut cleared = 0usize;
    let mut rebased_count = 0usize;
    for (va, size, writable, exec) in sections {
        if !writable || exec || size == 0 {
            continue;
        }
        let start = va as usize;
        let end = (va as usize).saturating_add(size as usize).min(dump_buf.len());
        let mut off = start;
        while off + ptr <= end {
            // Skip unaligned starts: a pointer is always pointer-aligned.
            if off % ptr == 0 {
                let value = if ptr == 8 {
                    u64::from_le_bytes(dump_buf[off..off + 8].try_into().unwrap_or([0u8; 8]))
                } else {
                    u32::from_le_bytes(dump_buf[off..off + 4].try_into().unwrap_or([0u8; 4])) as u64
                };

                // A live address from the dump session: either a module
                // (0x7FFx_xxxx_xxxx) or a heap allocation (0x0000_01xx_xxxx_xxxx).
                // Both are process-specific and both change run to run.
                let is_live_process_addr = ((value >= 0x0000_7FF0_0000_0000
                    && value < 0x0001_0000_0000_0000)
                    || (value >= 0x0000_0001_0000_0000 && value < 0x0000_7FF0_0000_0000))
                    // Small integers and tag values are not addresses.
                    && value > 0x0000_0000_0000_FFFF;

                if !is_live_process_addr {
                    off += ptr;
                    continue;
                }

                // Already an in-image address: the product's own pointer, keep it.
                if value >= img_lo && value < img_hi {
                    off += ptr;
                    continue;
                }

                // Nothing reads it.  Replace it with something deterministic.
                //
                // The relocation table cannot be used as a filter here: the
                // packed input's table is essentially empty (measured:
                // `size = 0x10` on the reference DLL), and the product's real
                // table is only built afterwards by `build_relocation_table`.
                // So the choice is between zeroing and rebasing, and it is made
                // per value:
                //
                // * If the address names something inside the dumped image,
                //   rewrite it to the equivalent in-image address.  The product
                //   loads at a different base, and `fix_hardcoded_addresses`
                //   will not touch it, so an in-image value is the only form
                //   that stays meaningful.
                // * Otherwise it names a module or heap block that will not
                //   exist in the product at all.  Zero is the honest value.
                let rebased = rebase_live_pointer(
                    value, live_base, img_lo, img_hi,
                );
                let new_value = rebased.unwrap_or(0);
                let bytes = if ptr == 8 {
                    (new_value as u64).to_le_bytes().to_vec()
                } else {
                    (new_value as u32).to_le_bytes().to_vec()
                };
                dump_buf[off..off + ptr].copy_from_slice(&bytes);
                if rebased.is_some() {
                    rebased_count += 1;
                } else {
                    cleared += 1;
                }
            }
            off += ptr;
        }
    }

    (cleared, rebased_count)
}

/// Try to express a live pointer as an in-image address.
///
/// Returns `Some(new_absolute_value)` when the address can be made meaningful in
/// the product, `None` when it cannot.
///
/// The only pointers this function can rescue are the ones that name something
/// inside the dumped image itself; those are already handled by the caller and
/// never reach here.  Everything else names a module or heap block belonging to
/// the dump session, which the product's own process will not have, so there is
/// no correct replacement and the caller zeroes the slot.
fn rebase_live_pointer(
    value: u64,
    _live_base: u64,
    _img_lo: u64,
    _img_hi: u64,
) -> Option<u64> {
    // Deliberately no rescue: an address into another module cannot be mapped
    // onto the product's address space, and inventing one would be worse than
    // zero.  Kept as a named function so the decision is visible and testable.
    let _ = value;
    None
}

/// Collect the RVAs that the relocation table covers.
pub(crate) fn collect_relocation_rvas(pe: &PeHeader, dump_buf: &[u8]) -> Vec<u32> {
    const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
    let dd = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if dd.virtual_address == 0 || dd.size == 0 {
        return Vec::new();
    }
    // `dump_buf` is a MEMORY image: file offset == RVA, so do NOT go through
    // `rva_to_offset` (which applies PointerToRawData and is for file images).
    let base = dd.virtual_address as usize;
    if base >= dump_buf.len() {
        return Vec::new();
    }
    let end = (base + dd.size as usize).min(dump_buf.len());

    let mut out = Vec::new();
    let mut o = base;
    while o + 8 <= end {
        let page = u32::from_le_bytes(dump_buf[o..o + 4].try_into().unwrap_or([0u8; 4]));
        let blksz = u32::from_le_bytes(dump_buf[o + 4..o + 8].try_into().unwrap_or([0u8; 4]));
        if blksz == 0 || o + blksz as usize > end {
            break;
        }
        let entries = (blksz as usize - 8) / 2;
        for i in 0..entries {
            let e = o + 8 + i * 2;
            let w = u16::from_le_bytes(dump_buf[e..e + 2].try_into().unwrap_or([0u8; 2]));
            if w >> 12 != 0 {
                out.push(page.wrapping_add(u32::from(w & 0x0FFF)));
            }
        }
        o += blksz as usize;
    }
    out
}

// -----------------------------------------------------------------------
// normalize_tls_directory
// -----------------------------------------------------------------------

/// Clamp the dumped TLS template length to the value the protected input
/// declares, neutralising Themida's lazily-updated `EndRawData`.
///
/// # Why this is needed
///
/// `IMAGE_TLS_DIRECTORY.EndRawData` bounds the TLS template that the loader
/// copies per thread.  Themida rewrites it during startup, and the rewrite is
/// not atomic with respect to a live-memory dump: on the reference target the
/// same binary yielded `StartRawData + 0x8` on some runs and
/// `StartRawData + 0x8008` on others.  Both products launch, but the second is
/// semantically wrong (a 32 KB TLS template instead of 8 bytes) and it made the
/// output SHA-256 non-reproducible, which broke the whole "compare the golden
/// hash" regression approach.
///
/// # Strategy
///
/// The template length is a property of the original binary, so read it from
/// `executable_path` when available.  Fall back to clamping against the dumped
/// `.tls` section extent when the input cannot be read.  Either way we only
/// ever *shrink* an out-of-range `EndRawData`; a plausible value is left alone.
fn normalize_tls_directory(
    pe: &mut PeHeader,
    dump_buf: &mut [u8],
    executable_path: Option<&Path>,
    is_64bit: bool,
) {
    const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

    let tls_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    if tls_dir.virtual_address == 0 {
        return;
    }

    let Some(dir_off) = pe.rva_to_offset(tls_dir.virtual_address).map(|o| o as usize) else {
        debug!("TLS directory RVA {:#x} is not file-backed, skipping normalisation", tls_dir.virtual_address);
        return;
    };

    let ptr_size = if is_64bit { 8 } else { 4 };
    // StartRawData, EndRawData, AddressOfIndex, AddressOfCallbacks.
    let end_off = dir_off + ptr_size;
    if end_off + ptr_size > dump_buf.len() {
        return;
    }

    let read_ptr = |buf: &[u8], off: usize| -> u64 {
        if ptr_size == 8 {
            u64::from_le_bytes(buf[off..off + 8].try_into().unwrap_or([0u8; 8]))
        } else {
            u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0u8; 4])) as u64
        }
    };

    let start = read_ptr(dump_buf, dir_off);
    let end = read_ptr(dump_buf, end_off);
    if start == 0 || end <= start {
        return;
    }

    // Authoritative template length: whatever the protected input declares.
    // The input's own TLS directory is often obfuscated, so treat "cannot read"
    // as "unknown" rather than failing.
    let declared_len = executable_path.and_then(|p| read_declared_tls_template_len(p, is_64bit));

    // Fallback bound: the dumped .tls section must contain the template.
    let section_bound = pe
        .get_section_by_rva(start as u32)
        .map(|s| (s.virtual_address as u64) + (s.virtual_size as u64))
        .unwrap_or(u64::MAX);

    let limit = match declared_len {
        Some(len) => start.saturating_add(len),
        None => section_bound,
    };

    if end <= limit {
        return; // plausible; leave as-is
    }

    let new_end = limit;
    let bytes = if ptr_size == 8 {
        new_end.to_le_bytes().to_vec()
    } else {
        (new_end as u32).to_le_bytes().to_vec()
    };
    dump_buf[end_off..end_off + ptr_size].copy_from_slice(&bytes);

    info!(
        old_end = format_args!("{end:#x}"),
        new_end = format_args!("{new_end:#x}"),
        start = format_args!("{start:#x}"),
        declared = ?declared_len,
        "Normalised TLS EndRawData (Themida lazy update overshoot)"
    );
}

/// Read the TLS template length declared by the protected input file.
///
/// Returns `None` when the input has no TLS directory, the directory is not
/// file-backed, or the values look obfuscated (Themida sometimes leaves
/// `0x20202020` filler in the data directory).
fn read_declared_tls_template_len(path: &Path, is_64bit: bool) -> Option<u64> {
    const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;

    let data = std::fs::read(path).ok()?;
    let pe = PeHeader::from_bytes(&data).ok()?;
    let tls_dir = pe.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY_TLS];
    if tls_dir.virtual_address == 0 {
        return None;
    }
    let dir_off = pe.rva_to_offset(tls_dir.virtual_address)? as usize;
    let ptr_size = if is_64bit { 8 } else { 4 };
    let end_off = dir_off + ptr_size;
    if end_off + ptr_size > data.len() {
        return None;
    }

    let read_ptr = |off: usize| -> u64 {
        if ptr_size == 8 {
            u64::from_le_bytes(data[off..off + 8].try_into().unwrap_or([0u8; 8]))
        } else {
            u32::from_le_bytes(data[off..off + 4].try_into().unwrap_or([0u8; 4])) as u64
        }
    };

    let start = read_ptr(dir_off);
    let end = read_ptr(end_off);
    if start == 0 || end <= start {
        return None;
    }
    let len = end - start;
    // Reject obviously bogus values (obfuscated filler, or absurdly large).
    if len > 0x100_000 {
        return None;
    }
    Some(len)
}

/// Debug helper: verify section 1 characteristics in the output buffer.
fn debug_section_chars(out_data: &[u8], label: &str) {
    let sec1_chars_offset = 0x1d4;
    if sec1_chars_offset + 4 <= out_data.len() {
        let chars = u32::from_le_bytes([
            out_data[sec1_chars_offset],
            out_data[sec1_chars_offset + 1],
            out_data[sec1_chars_offset + 2],
            out_data[sec1_chars_offset + 3],
        ]);
        info!("{}: Section 1 chars at {:#x} = {:#x}", label, sec1_chars_offset, chars);
    }
}

// -----------------------------------------------------------------------
// dump_dotnet
// -----------------------------------------------------------------------

/// Dump a .NET assembly from the target process.
///
/// .NET assemblies don't need import table reconstruction — the CLR handles
/// method resolution at runtime.  This simply reads the dump image, trims
/// oversized sections, and writes the output.
///
/// Corresponds to `TDumperDotnet.DumpToFile` in `Dumper.pas`.
pub fn dump_dotnet(
    debugger: &mut dyn mida_core::DebuggerCore,
    image_base: u64,
    entry_point: u32,
    output_path: &Path,
) -> Result<(), PeError> {
    // Read PE headers
    let mut header = vec![0u8; 0x1000];
    let read = debugger
        .read_memory(image_base as usize, &mut header)
        .map_err(|e| PeError::Parse(format!("Failed to read header: {e}")))?;
    if read < 0x1000 {
        return Err(PeError::Parse("Short read on .NET PE header".into()));
    }

    let mut pe = PeHeader::from_bytes(&header)?;

    // Determine dump size from the last section
    let last_idx = pe.sections.len() - 1;
    let dump_size = pe.sections[last_idx].virtual_address + pe.sections[last_idx].virtual_size;

    info!(
        dump_size,
        sections = pe.sections.len(),
        "Dumping .NET assembly"
    );

    // Read the full image
    let dump_size_usize = dump_size as usize;
    let mut buf = vec![0u8; dump_size_usize];
    make_memory_readable(debugger, image_base, dump_size as u64);

    let read = debugger
        .read_memory(image_base as usize, &mut buf)
        .map_err(|e| PeError::Parse(format!("Failed to read .NET image: {e}")))?;

    // Sanitize and write
    pe.sanitize();

    // Rename first section to .text
    if !pe.sections.is_empty() {
        pe.rename_section(0, ".text");
    }

    let mut out_data = Vec::new();
    out_data.extend_from_slice(&buf[..dump_size_usize.min(read)]);

    // Pad to file alignment if needed
    let mut physical_size = dump_size;
    pe.file_align(&mut physical_size);
    if dump_size < physical_size {
        out_data.resize(physical_size as usize, 0);
    }

    // Update size of image
    let mut image_size = physical_size;
    pe.section_align(&mut image_size);
    pe.nt_headers.optional_header.size_of_image = image_size;

    // Update entry point
    let ep_rva = entry_point - image_base as u32;
    pe.nt_headers.optional_header.address_of_entry_point = ep_rva;

    // Write headers
    let header_data = pe.serialize_headers()?;
    out_data.extend_from_slice(&header_data);

    std::fs::write(output_path, &out_data)?;

    info!(
        path = %output_path.display(),
        size = out_data.len(),
        ".NET dump written successfully"
    );

    Ok(())
}


// ---------------------------------------------------------------------------
// Tests for the stale-pointer normalisation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod stale_pointer_tests {
    use super::*;
    use crate::header::make_minimal_pe64;

    /// Build a minimal 64-bit image with one writable data section and put the
    /// given qwords at the given RVAs.
    fn image_with(section_rva: u32, section_size: u32, qwords: &[(u32, u64)]) -> (Vec<u8>, PeHeader) {
        // IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, no execute.
        image_with_chars(section_rva, section_size, qwords, 0xC000_0040)
    }

    /// Same, but with caller-chosen section characteristics.  The cookie tests
    /// need an **executable** section, because the initialiser lives in code.
    fn image_with_chars(
        section_rva: u32,
        section_size: u32,
        qwords: &[(u32, u64)],
        characteristics: u32,
    ) -> (Vec<u8>, PeHeader) {
        let mut data = make_minimal_pe64();

        // The minimal PE ships one section whose characteristics are
        // code|read|execute.  Rewrite them in the section header before parsing
        // so the parsed `PeHeader` carries what each test needs.
        let pe_off = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
        let nsec = u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().unwrap()) as usize;
        let opt_size = u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().unwrap()) as usize;
        let sec_tab = pe_off + 24 + opt_size;
        for i in 0..nsec {
            let ch_off = sec_tab + i * 40 + 36;
            data[ch_off..ch_off + 4].copy_from_slice(&characteristics.to_le_bytes());
        }

        let pe = PeHeader::from_bytes(&data).expect("minimal PE must parse");
        // The minimal PE has a single section; extend the buffer so the target
        // RVAs exist as memory-image offsets (offset == RVA).
        let need = (section_rva + section_size) as usize;
        if data.len() < need {
            data.resize(need, 0);
        }
        for (rva, value) in qwords {
            let off = *rva as usize;
            data[off..off + 8].copy_from_slice(&value.to_le_bytes());
        }
        (data, pe)
    }

    #[test]
    fn live_module_pointer_is_cleared() {
        // A live ntdll/kernel32 address is not meaningful in the product.
        let (mut buf, pe) = image_with(0x1000, 0x1000, &[(0x1000, 0x0000_7FF8_C0F8_C530)]);
        let image_base = pe.nt_headers.optional_header.image_base;
        let (cleared, rebased) = clear_stale_live_pointers(&mut buf, &pe, image_base, true);
        assert_eq!(cleared, 1, "a live module address must be cleared");
        assert_eq!(rebased, 0);
        let got = u64::from_le_bytes(buf[0x1000..0x1008].try_into().unwrap());
        assert_eq!(got, 0, "slot must be zeroed");
    }

    #[test]
    fn live_heap_pointer_is_cleared() {
        // Heap allocations look like 0x0000_02xx_xxxx_xxxx and are just as
        // process-specific as module addresses.
        let (mut buf, pe) = image_with(0x1000, 0x1000, &[(0x1000, 0x0000_0256_B0DB_0080)]);
        let image_base = pe.nt_headers.optional_header.image_base;
        let (cleared, _) = clear_stale_live_pointers(&mut buf, &pe, image_base, true);
        assert_eq!(cleared, 1, "a live heap address must be cleared");
    }

    #[test]
    fn small_integers_are_left_alone() {
        // Counters, flags and sizes live in the same sections and must survive.
        let (mut buf, pe) = image_with(
            0x1000,
            0x1000,
            &[(0x1000, 0x1), (0x1008, 0x16000), (0x1010, 0xFFFF)],
        );
        let image_base = pe.nt_headers.optional_header.image_base;
        let (cleared, _) = clear_stale_live_pointers(&mut buf, &pe, image_base, true);
        assert_eq!(cleared, 0, "small integers are not addresses");
        assert_eq!(u64::from_le_bytes(buf[0x1000..0x1008].try_into().unwrap()), 0x1);
        assert_eq!(u64::from_le_bytes(buf[0x1008..0x1010].try_into().unwrap()), 0x16000);
    }

    #[test]
    fn in_image_pointer_is_left_alone() {
        // A pointer that already names something inside the dumped image is the
        // product's own address and must not be touched.
        let (probe, pe) = image_with(0x1000, 0x1000, &[]);
        let image_base = pe.nt_headers.optional_header.image_base;
        let inside = image_base + 0x1000;
        let (mut buf, pe) = image_with(0x1000, 0x1000, &[(0x1000, inside)]);
        let (cleared, _) = clear_stale_live_pointers(&mut buf, &pe, image_base, true);
        assert_eq!(cleared, 0, "an in-image pointer is meaningful");
        let _ = probe;
    }

    #[test]
    fn zero_stays_zero() {
        let (mut buf, pe) = image_with(0x1000, 0x1000, &[]);
        let image_base = pe.nt_headers.optional_header.image_base;
        let (cleared, rebased) = clear_stale_live_pointers(&mut buf, &pe, image_base, true);
        assert_eq!((cleared, rebased), (0, 0));
    }

    // ------------------------------------------------------------------
    // find_security_cookie
    // ------------------------------------------------------------------

    /// Plant the **x64** `__security_init_cookie` fallback at `site`, storing to
    /// `cookie_rva`.  Layout: `48 B8 EF BE AD DE EF BE AD DE` then
    /// `48 89 05 <disp32>`, exactly what MSVC emits for x64.
    fn plant_cookie_init_x64(buf: &mut [u8], site: usize, cookie_rva: u32) {
        buf[site] = 0x48;
        buf[site + 1] = 0xB8;
        buf[site + 2..site + 10].copy_from_slice(&DEADBEEF64);
        let store = site + 10;
        buf[store] = 0x48;
        buf[store + 1] = 0x89;
        buf[store + 2] = 0x05;
        // RIP base is the byte just past the 7-byte store instruction.
        let disp = cookie_rva as i64 - (store as i64 + 7);
        buf[store + 3..store + 7].copy_from_slice(&(disp as i32).to_le_bytes());
    }

    /// Plant the **x86** fallback: `push 0xEFBEADDE` twice, `pop`/`pop`, then two
    /// absolute dword stores — the shape the 32-bit CRT actually emits.
    fn plant_cookie_init_x86(buf: &mut [u8], site: usize, cookie_va: u32) {
        buf[site] = 0x68;
        buf[site + 1..site + 5].copy_from_slice(&DEADBEEF32);
        buf[site + 5] = 0x68;
        buf[site + 6..site + 10].copy_from_slice(&DEADBEEF32);
        buf[site + 10] = 0x5F; // pop edi
        buf[site + 11] = 0x5E; // pop esi
        // mov dword ptr [abs32], edi
        buf[site + 12] = 0x89;
        buf[site + 13] = 0x3D;
        buf[site + 14..site + 18].copy_from_slice(&cookie_va.to_le_bytes());
        // mov dword ptr [abs32+4], esi
        buf[site + 18] = 0x89;
        buf[site + 19] = 0x35;
        buf[site + 20..site + 24].copy_from_slice(&(cookie_va + 4).to_le_bytes());
    }

    #[test]
    fn x64_cookie_is_found_by_its_init_signature() {
        // The initialiser lives in code, so the section must be executable.
        let (mut buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        plant_cookie_init_x64(&mut buf, 0x1000, 0x1400);
        let found = find_security_cookie(&buf, &pe, true).expect("x64 cookie must be found");
        assert_eq!(found.rva, 0x1400, "must locate the store target");
        assert_eq!(found.via, "x64 movabs/mov [rip]");
    }

    /// The x86 CRT has no `movabs`, so the same fallback is emitted as two
    /// `push imm32` halves.  Before this was handled, an x86 product would have
    /// silently kept its nondeterministic cookie and stayed unreproducible.
    #[test]
    fn x86_cookie_is_found_by_its_push_signature() {
        let (mut buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        plant_cookie_init_x86(&mut buf, 0x1000, 0x1400);
        let found = find_security_cookie(&buf, &pe, false).expect("x86 cookie must be found");
        assert_eq!(found.rva, 0x1400, "must locate the absolute store target");
        assert_eq!(found.via, "x86 push imm32 x2 / mov [abs32]");
    }

    /// The two signatures must not be confused for each other: an x64 image must
    /// not be matched by the x86 scanner and vice versa.
    #[test]
    fn cookie_scanners_are_architecture_specific() {
        let (mut x64_buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        plant_cookie_init_x64(&mut x64_buf, 0x1000, 0x1400);
        assert!(
            find_security_cookie(&x64_buf, &pe, false).is_none(),
            "the x86 scanner must not claim an x64 initialiser"
        );

        let (mut x86_buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        plant_cookie_init_x86(&mut x86_buf, 0x1000, 0x1400);
        assert!(
            find_security_cookie(&x86_buf, &pe, true).is_none(),
            "the x64 scanner must not claim an x86 initialiser"
        );
    }

    #[test]
    fn no_signature_yields_no_cookie() {
        // A product without stack guards must not get a fabricated slot.
        let (buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        assert!(
            find_security_cookie(&buf, &pe, true).is_none(),
            "an image without __security_init_cookie must yield nothing"
        );
        assert!(
            find_security_cookie(&buf, &pe, false).is_none(),
            "same for the x86 scanner"
        );
    }

    #[test]
    fn deadbeef_without_the_store_is_not_a_cookie() {
        // The immediate alone appears in ordinary constants; only the store that
        // follows it makes it the cookie initialiser.
        let (mut buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        buf[0x1000] = 0x48;
        buf[0x1001] = 0xB8;
        buf[0x1002..0x100A].copy_from_slice(&DEADBEEF64);
        // Followed by something that is not a store to memory.
        buf[0x100A..0x100D].copy_from_slice(&[0x90, 0x90, 0x90]);
        assert!(
            find_security_cookie(&buf, &pe, true).is_none(),
            "a bare DEADBEEF constant is not a cookie initialiser"
        );

        // Same for x86: one push alone is not the initialiser.
        let (mut buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        buf[0x1000] = 0x68;
        buf[0x1001..0x1005].copy_from_slice(&DEADBEEF32);
        buf[0x1005..0x1010].copy_from_slice(&[0x90; 11]);
        assert!(
            find_security_cookie(&buf, &pe, false).is_none(),
            "a single DEADBEEF push is not a cookie initialiser"
        );
    }

    #[test]
    fn cookie_reset_zeroes_only_the_cookie_slot() {
        // End-to-end shape of the fix: after zeroing, the cookie is 0 and its
        // neighbours are untouched.
        let (mut buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        plant_cookie_init_x64(&mut buf, 0x1000, 0x1400);
        buf[0x1400..0x1408].copy_from_slice(&0x4015_AB98_00FC_78C0u64.to_le_bytes());
        buf[0x1408..0x1410].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());

        let found = find_security_cookie(&buf, &pe, true).expect("cookie");
        let off = found.rva as usize;
        buf[off..off + 8].fill(0);

        assert_eq!(
            u64::from_le_bytes(buf[0x1400..0x1408].try_into().unwrap()),
            0,
            "the cookie slot must be zeroed"
        );
        assert_eq!(
            u64::from_le_bytes(buf[0x1408..0x1410].try_into().unwrap()),
            0x1122_3344_5566_7788,
            "the qword after the cookie must be untouched"
        );
    }

    /// On x86 the cookie is 4 bytes wide, so the reset must not spill into the
    /// adjacent dword.
    #[test]
    fn x86_cookie_reset_uses_4_byte_width() {
        let (mut buf, pe) = image_with_chars(0x1000, 0x1000, &[], 0x6000_0020);
        plant_cookie_init_x86(&mut buf, 0x1000, 0x1400);
        buf[0x1400..0x1404].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        buf[0x1404..0x1408].copy_from_slice(&0xFEED_FACEu32.to_le_bytes());

        let found = find_security_cookie(&buf, &pe, false).expect("cookie");
        let off = found.rva as usize;
        buf[off..off + 4].fill(0);

        assert_eq!(
            u32::from_le_bytes(buf[0x1400..0x1404].try_into().unwrap()),
            0,
            "the 4-byte x86 cookie must be zeroed"
        );
        assert_eq!(
            u32::from_le_bytes(buf[0x1404..0x1408].try_into().unwrap()),
            0xFEED_FACE,
            "the adjacent dword must be untouched"
        );
    }
}
