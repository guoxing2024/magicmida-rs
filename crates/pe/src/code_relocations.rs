//! Relocation discovery inside **executable** sections, x86 only.
//!
//! ## Why this exists
//!
//! [`crate::postprocess::build_relocation_table`] deliberately skips executable
//! sections.  That is correct on x64: the compiler addresses everything
//! RIP-relative, so an absolute 32-bit constant inside `.text` is an instruction
//! operand (`mov eax, 0x400000` as a flag value), never a pointer, and
//! relocating it corrupts the instruction.
//!
//! On x86 the same assumption is false.  32-bit code has no RIP-relative
//! addressing, so every global access is an absolute operand:
//!
//! ```text
//!   cmp dword ptr [0x403010], 2      ; 83 3D 10 30 40 00 02
//!   push 0x400000                   ; 68 00 00 40 00
//! ```
//!
//! Those dwords **are** addresses and the loader must rebase them.  Measured on
//! the reference x86 sample: its own relocation table has 277 entries and
//! **256 of them are in `.text`**.  Skipping the section means the product
//! crashes at the first absolute global access after the image loads at a base
//! other than the dump-time one.
//!
//! ## Why an instruction decoder, not a byte stride
//!
//! A stride-4 walk was measured against the reference's own table:
//!
//! | stride | found | correct | false positive | missed |
//! |--------|-------|---------|----------------|--------|
//! | 4      | 53    | 53      | 0              | 203    |
//! | 2      | 141   | 141     | 0              | 115    |
//! | 1      | 257   | 256     | 1              | 0      |
//!
//! Stride 4 misses 79% of the real entries because x86 absolute operands sit at
//! arbitrary offsets (`83 3D <disp32>` puts the dword at +2).  Stride 1 finds
//! everything but also relocates bytes that only *look* like an address, which
//! corrupts an instruction.
//!
//! Decoding the section and taking only the operand fields that are genuine
//! 32-bit displacements/immediates reproduces the reference table exactly:
//! **256 candidates, 256 correct, 0 false positives, 0 missed**.
//!
//! Note that register-relative forms count.  `cmp dword ptr [eax + 0x400000],
//! 0x4550` is `image_base + <offset in eax>`, so the constant has to move with
//! the image; the reference sample's own table relocates all 49 of them.
//!
//! ## What is deliberately excluded
//!
//! * `rel32` branch displacements (`jmp`/`call`/`jcc`).  Their immediate is a
//!   relative offset, not an address.  A prototype that relocated one sent EIP
//!   to `0x8b55ff8b`.
//! * Anything inside the import table's metadata — see
//!   [`crate::postprocess::import_metadata_ranges`].  The loader relocates
//!   before resolving imports, so rebasing ASCII inside a name string destroys
//!   the name and fails with `0xC0000139`.
//!
//! ## Limits, measured not assumed
//!
//! The scan cannot find an absolute operand that the decoder cannot reach.
//! When a section contains undecodable bytes the walk resynchronises one byte
//! at a time and continues; that is what makes the reference sample reach all
//! 256 entries even though its `.text` holds embedded data.

use iced_x86::{FlowControl, Instruction, OpKind};
use tracing::{debug, info};

/// One absolute address found inside an executable section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeRelocation {
    /// RVA of the 32-bit field that holds the address.
    pub rva: u32,
    /// The value found there, as an image-relative address.
    pub target: u32,
}

/// Scan executable sections for absolute operands that point inside the image.
///
/// `data` is the image at the same layout the output file uses, so file offset
/// and RVA are equal for mapped sections (the dumper's convention — see
/// `dump_buf`).  `image_base` / `image_size` define the accepted target range.
///
/// `reject` is consulted per candidate RVA and returns `true` for anything that
/// must not be relocated (import metadata, the relocation table itself).
pub fn scan_code_relocations(
    data: &[u8],
    image_base: u32,
    image_size: u32,
    sections: impl IntoIterator<Item = (u32, u32, u32)>,
    reject: impl Fn(u32) -> bool,
) -> Vec<CodeRelocation> {
    let image_end = image_base.saturating_add(image_size);
    let mut found: Vec<CodeRelocation> = Vec::new();

    for (section_rva, section_size, characteristics) in sections {
        // 0x20000000 = IMAGE_SCN_MEM_EXECUTE
        if characteristics & 0x2000_0000 == 0 {
            continue;
        }
        let start = section_rva as usize;
        let end = start.saturating_add(section_size as usize);
        if end > data.len() || section_size == 0 {
            debug!(
                "Code relocation scan: section at rva {section_rva:#x} is outside the buffer \
                 (need {end:#x}, have {:#x})",
                data.len()
            );
            continue;
        }

        let code = &data[start..end];
        let before = found.len();
        let mut undecodable = 0usize;

        let mut pos = 0usize;
        while pos < code.len() {
            let ip = section_rva as u64 + pos as u64;
            let mut decoder = iced_x86::Decoder::with_ip(
                32,
                &code[pos..],
                ip,
                iced_x86::DecoderOptions::NONE,
            );
            if !decoder.can_decode() {
                break;
            }
            let insn = decoder.decode();
            if insn.is_invalid() {
                // Not an instruction boundary — this is embedded data.  Step a
                // single byte and try again; stopping here would leave every
                // entry after the first data blob undiscovered.
                undecodable += 1;
                pos += 1;
                continue;
            }
            let offsets = decoder.get_constant_offsets(&insn);
            let len = insn.len();
            let base_ip = ip as u32;

            // Displacement: on x86 a 32-bit displacement in a memory operand is
            // a constant offset from the image base, whether or not a register
            // is added to it.  `cmp dword ptr [eax + 0x400000], 0x4550` is
            // `image_base + <offset in eax>`: rebasing the image moves that
            // constant too.  Measured: the reference sample's own table
            // relocates all 49 such operands, so excluding register-relative
            // forms would miss 19% of its entries.
            if offsets.displacement_size() == 4 {
                collect(
                    &insn,
                    base_ip + offsets.displacement_offset() as u32,
                    &code[pos..pos + len],
                    offsets.displacement_offset(),
                    image_base,
                    image_end,
                    &reject,
                    &mut found,
                );
            }

            // Immediate: a genuine 32-bit immediate is a value.  A rel32 branch
            // displacement is an offset from the next instruction, never an
            // address, so those are skipped.
            if offsets.immediate_size() == 4 && !is_relative_branch(&insn) {
                collect(
                    &insn,
                    base_ip + offsets.immediate_offset() as u32,
                    &code[pos..pos + len],
                    offsets.immediate_offset(),
                    image_base,
                    image_end,
                    &reject,
                    &mut found,
                );
            }

            pos += len;
        }

        if found.len() > before {
            info!(
                "Code relocations: section at rva {section_rva:#x} contributed {} entries",
                found.len() - before
            );
        }
        if undecodable > 0 {
            debug!(
                "Code relocation scan: section at rva {section_rva:#x} resynchronised over \
                 {undecodable} undecodable byte(s)"
            );
        }
    }

    found.sort_unstable_by_key(|r| r.rva);
    found.dedup_by_key(|r| r.rva);
    found
}

/// `true` when the instruction's 32-bit immediate is a relative branch target.
///
/// `Call`/`Jmp`/conditional jumps take a `rel32` there.  An `Indirect` flow
/// control means the immediate is something else entirely (e.g. a value pushed
/// for a register-indirect call) and is handled by the normal immediate path.
fn is_relative_branch(insn: &Instruction) -> bool {
    matches!(
        insn.flow_control(),
        FlowControl::Call
            | FlowControl::IndirectCall
            | FlowControl::UnconditionalBranch
            | FlowControl::ConditionalBranch
    ) && insn.op_kind(0) == OpKind::NearBranch32
}

#[allow(clippy::too_many_arguments)]
fn collect(
    insn: &Instruction,
    rva: u32,
    bytes: &[u8],
    field_offset: usize,
    image_base: u32,
    image_end: u32,
    reject: &impl Fn(u32) -> bool,
    out: &mut Vec<CodeRelocation>,
) {
    if field_offset + 4 > bytes.len() {
        return;
    }
    let raw = u32::from_le_bytes([
        bytes[field_offset],
        bytes[field_offset + 1],
        bytes[field_offset + 2],
        bytes[field_offset + 3],
    ]);
    if raw < image_base || raw >= image_end {
        return;
    }
    if reject(rva) {
        debug!(
            "Code relocation refused at rva {rva:#x} ({:?} {:?}): protected region",
            insn.mnemonic(),
            insn.op0_kind()
        );
        return;
    }
    out.push(CodeRelocation { rva, target: raw });
}

#[cfg(test)]
#[path = "code_relocations_tests.rs"]
mod tests;





