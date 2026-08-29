//! XC-7-A: strip Themida shell sections and rebase a fixed-base candidate to
//! a private low address.
//!
//! Input: a candidate PE already dumped at its runtime ASLR base (via
//! `/dump-module --keep-runtime-base`). The candidate carries `.winlice` +
//! `.boot` shell sections (12+ MB of VM/encrypted bytes) and every absolute
//! address reference captured in the live image points at the old runtime
//! base (e.g. `0x7FFE1DA1…`).
//!
//! This module:
//! 1. Strips `.winlice`/`.boot`/`.themida` (shrink) — shell remnants that
//!    make the candidate huge and, for `.boot`, encrypted garbage.
//! 2. Rewrites the ImageBase to `new_base` (private low address, avoiding
//!    system-DLL and default-EXE ranges).
//! 3. Re-runs hardcoded-address fixup: every 8-byte value in the old runtime
//!    base range is rewritten to `new_base + offset`.
//! 4. Clears DYNAMIC_BASE (fixed image).
//! 5. Static self-check: scan the full image for stale old-base references;
//!    if any remain, fail (no output).
//!
//! Production `.unwrap()`s are invariants (WO-12 follow-up): fixed-width
//! slice `try_into()` behind explicit bound checks (no fallible path masked).
#![allow(clippy::unwrap_used)]

use std::path::Path;

use anyhow::anyhow;
use mida_pe::PeHeader;

use crate::log::{self, LogType};

/// Zero the raw data of every UNINITIALIZED (0x80) section. Such sections
/// (e.g. .bss) capture runtime-scratch memory at dump time; the loader zeroes
/// them at image load, so persisted pointer garbage must not survive the
/// rebuild (it would trip the stale-old-base self-check).
fn zero_uninitialized_sections(data: &mut [u8], pe: &PeHeader) {
    const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    for s in &pe.sections {
        if s.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 && s.raw_size > 0 {
            let start = s.raw_offset as usize;
            let end = (start as u64 + s.raw_size as u64).min(data.len() as u64) as usize;
            if end > start {
                data[start..end].fill(0);
                log::log(
                    LogType::Info,
                    &format!(
                        "zeroed UNINITIALIZED section {:?} ({} bytes)",
                        s.name,
                        end - start
                    ),
                );
            }
        }
    }
}

/// Pure: count how many 8-byte (or 4-byte) little-endian values inside
/// `buf` fall in `[old_base, old_base + image_size)`.
pub fn count_old_base_refs(buf: &[u8], old_base: u64, image_size: u64, is_64bit: bool) -> usize {
    let ptr = if is_64bit { 8usize } else { 4usize };
    let end = old_base.saturating_add(image_size);
    let mut count = 0usize;
    let mut i = 0usize;
    while i + ptr <= buf.len() {
        let v = if is_64bit {
            u64::from_le_bytes(buf[i..i + 8].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(buf[i..i + 4].try_into().unwrap()))
        };
        if v >= old_base && v < end {
            count += 1;
        }
        i += 1;
    }
    count
}

/// Pure: does `buf` contain any 8-byte (or 4-byte) little-endian value inside
/// `[old_base, old_base + image_size)`? Used by the static self-check.
pub fn contains_old_base_ref(buf: &[u8], old_base: u64, image_size: u64, is_64bit: bool) -> bool {
    count_old_base_refs(buf, old_base, image_size, is_64bit) != 0
}

/// Rebase a fixed-base candidate to a private base, stripping shell sections.
///
/// Returns the number of absolute references rewritten.
pub fn rebase_fixed(
    input: &Path,
    output: &Path,
    old_base: u64,
    new_base: u64,
) -> Result<usize, anyhow::Error> {
    use mida_pe::rebuild::{PlannedSection, RebuildPlan};

    let data = std::fs::read(input).map_err(|e| anyhow!("read {}: {e}", input.display()))?;
    let pe = PeHeader::from_bytes(&data).map_err(|e| anyhow!("parse {}: {e}", input.display()))?;
    let is_64bit = pe.is_64bit;
    let old_image_size = pe.size_of_image() as u64;

    log::log(
        LogType::Info,
        &format!(
            "rebase-fixed: {} -> {} (old_base={old_base:#x} new_base={new_base:#x} is_64bit={is_64bit})",
            input.display(),
            output.display()
        ),
    );

    // 1. Rebuild the image with shell sections (.winlice/.boot/.themida)
    //    removed. Keep every other section at its original VA (content
    //    directories stay valid) with its raw bytes. RebuildPlan packs raw
    //    data tightly in file order, dropping the shell payloads entirely.
    const SHELL: [&str; 3] = [".winlice", ".boot", ".themida"];

    // DLL semantics (XC-7 grid-4): the shell entry point (pointing into a
    // now-removed .boot) is meaningless. Use a NOP stub in .text slack so the
    // loader accepts the image without running shell code. Entry stub:
    //   xor eax, eax; inc eax; ret   (DLL_PROCESS_ATTACH success)
    // The stub lives at the first code section's virtual-size offset.
    const NOP_STUB: [u8; 5] = [0x31, 0xC0, 0xFF, 0xC0, 0xC3]; // xor eax,eax; inc eax; ret
    let text_sec = pe
        .sections
        .iter()
        .find(|s| !SHELL.iter().any(|t| s.name.to_lowercase().contains(t)) && s.raw_size > 0)
        .ok_or_else(|| anyhow!("no code section for NOP stub"))?;
    let stub_rva = text_sec.virtual_address + text_sec.virtual_size;

    let mut sections: Vec<PlannedSection> = Vec::new();
    for s in &pe.sections {
        let lower = s.name.to_lowercase();
        if SHELL.iter().any(|t| lower.contains(t)) {
            log::log(
                LogType::Info,
                &format!("rebase-fixed: dropping shell section {:?}", s.name),
            );
            continue;
        }
        // Slice the raw bytes for this section (bounded by file length).
        let start = s.raw_offset as usize;
        let len = (s.raw_size as usize).min(data.len().saturating_sub(start));
        let mut raw = data[start..start + len].to_vec();
        // Inject the NOP entry stub at the code section's virtual-size offset.
        if s.virtual_address == text_sec.virtual_address {
            let stub_off = s.virtual_size as usize;
            if stub_off + NOP_STUB.len() <= raw.len() {
                raw[stub_off..stub_off + NOP_STUB.len()].copy_from_slice(&NOP_STUB);
            }
        }
        sections.push(PlannedSection::with_rva(
            s.name.clone(),
            s.characteristics,
            s.virtual_address,
            s.virtual_size,
            raw,
        ));
    }
    // Copy the data directories so content directory RVAs survive the rebuild.
    let fallback = Some(pe.nt_headers.optional_header.data_directory);

    let plan = RebuildPlan {
        is_64bit,
        image_base: new_base,
        entry_point_rva: stub_rva,
        file_alignment: pe.nt_headers.optional_header.file_alignment,
        section_alignment: pe.nt_headers.optional_header.section_alignment,
        subsystem: pe.nt_headers.optional_header.subsystem,
        // Fixed image: no DYNAMIC_BASE, no relocation directory needed.
        dll_characteristics: pe.nt_headers.optional_header.dll_characteristics & !0x0040,
        file_characteristics: pe.nt_headers.file_header.characteristics,
        sections,
        exports: None,
        imports: None,
        exceptions: None,
        tls: None,
        relocations: Vec::new(),
        prefer_aslr: false,
        fallback_data_directories: fallback,
    };

    let mut data = mida_pe::rebuild::rebuild_pe_image(&plan)
        .map_err(|e| anyhow!("rebuild_pe_image failed: {e}"))?;
    let new_image_size = mida_pe::PeHeader::from_bytes(&data)
        .map(|p| p.size_of_image() as u64)
        .unwrap_or(0);

    // 2. .bss / UNINITIALIZED sections hold runtime-scratch pointer garbage;
    //    fix_hardcoded skips them (0x80 flag). Zero them so stale old-base
    //    refs cannot survive into the rebuilt image (XC-7-A issue-1 gate).
    let pe_after =
        PeHeader::from_bytes(&data).map_err(|e| anyhow!("re-parse after rebuild: {e}"))?;
    zero_uninitialized_sections(&mut data, &pe_after);

    // 3. Re-run hardcoded-address fixup: old runtime base -> new private base.
    let pre_fix_count = count_old_base_refs(&data, old_base, old_image_size, is_64bit);
    mida_pe::postprocess::fix_hardcoded_addresses(&mut data, Some(old_base), is_64bit)
        .map_err(|e| anyhow!("fix_hardcoded_addresses failed: {e}"))?;
    let post_fix_count = count_old_base_refs(&data, old_base, old_image_size, is_64bit);
    let fixed = pre_fix_count.saturating_sub(post_fix_count);

    // 4. Static self-check: no stale old-base references may remain anywhere
    //    in the emitted image.
    if post_fix_count != 0 {
        return Err(anyhow!(
            "REBASE SELF-CHECK FAILED: {post_fix_count} stale references to old base              {old_base:#x} remain after fixup ({fixed} rewritten). No output written."
        ));
    }
    log::log(
        LogType::Info,
        &format!(
            "rebase self-check: no stale old-base refs (fixed={fixed}, old_image_size={old_image_size:#x}, new_image_size={new_image_size:#x})"
        ),
    );

    std::fs::write(output, &data).map_err(|e| anyhow!("write {}: {e}", output.display()))?;
    log::log(
        LogType::Good,
        &format!(
            "rebase-fixed: wrote {} ({} bytes, {fixed} absolute refs rewritten, shell sections stripped)",
            output.display(),
            data.len()
        ),
    );

    Ok(fixed)
}

#[cfg(test)]
mod tests {
    use super::contains_old_base_ref;

    #[test]
    fn detects_old_base_ref() {
        let mut buf = vec![0u8; 0x100];
        buf[0x10..0x18].copy_from_slice(&0x7FFE1DA10000u64.to_le_bytes());
        assert!(contains_old_base_ref(&buf, 0x7FFE1DA10000, 0xdb3000, true));
    }

    #[test]
    fn no_ref_when_clean() {
        let buf = vec![0u8; 0x100];
        assert!(!contains_old_base_ref(&buf, 0x7FFE1DA10000, 0xdb3000, true));
    }

    #[test]
    fn boundary_outside() {
        let mut buf = vec![0u8; 0x100];
        buf[0..8].copy_from_slice(&(0x7FFE1DA10000u64 + 0xdb3000).to_le_bytes());
        // exactly at end: outside [base, base+size)
        assert!(!contains_old_base_ref(&buf, 0x7FFE1DA10000, 0xdb3000, true));
    }

    #[test]
    fn boundary_inside() {
        let mut buf = vec![0u8; 0x100];
        buf[0..8].copy_from_slice(&(0x7FFE1DA10000u64 + 0xdb3000 - 1).to_le_bytes());
        assert!(contains_old_base_ref(&buf, 0x7FFE1DA10000, 0xdb3000, true));
    }

    #[test]
    fn empty_buf() {
        assert!(!contains_old_base_ref(&[], 0x7FFE1DA10000, 0xdb3000, true));
    }
}
