//! Tests for the x86 executable-section relocation scan.
//!
//! The expectations here are **not** invented: every number was measured
//! against the reference sample's own relocation table
//! (`OUT\x86\x86_sample.exe`, 277 entries, 256 of them inside `.text`).
//!
//! The fixtures are hand-assembled so the tests stay hermetic (no sample
//! dependency), but each one reproduces an instruction form that the
//! measurement showed matters.

use super::*;

/// `image_base` used by every fixture, matching the real x86 sample.
const BASE: u32 = 0x400_000;
/// `SizeOfImage` of the real x86 product — large enough that a value like
/// `0x403010` is inside it.
const SIZE: u32 = 0x1b_000;

fn exec() -> u32 {
    0x6000_0020 // IMAGE_SCN_CNT_CODE | MEM_EXECUTE | MEM_READ
}

fn data_flags() -> u32 {
    0xc000_0040 // IMAGE_SCN_CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE
}

/// Place `code` at rva 0x1000 inside a zero-filled buffer, matching the layout
/// the scanner expects (file offset == RVA for mapped sections).
fn padded(code: &[u8]) -> Vec<u8> {
    let mut data = vec![0u8; 0x1000 + code.len()];
    data[0x1000..].copy_from_slice(code);
    data
}

/// Run the scanner over one executable section at rva 0x1000.
///
/// The scanner indexes the buffer by RVA (the dumper's convention: file offset
/// == RVA for mapped sections), so the fixture must place the code at that
/// offset rather than at the start of a bare slice.
fn scan(code: &[u8]) -> Vec<CodeRelocation> {
    const SECTION_RVA: usize = 0x1000;
    let mut data = vec![0u8; SECTION_RVA + code.len()];
    data[SECTION_RVA..].copy_from_slice(code);
    scan_code_relocations(
        &data,
        BASE,
        SIZE,
        [(SECTION_RVA as u32, code.len() as u32, exec())],
        |_| false,
    )
}

/// `cmp dword ptr [0x403010], 2` — the instruction that crashed the product.
///
/// `83 3D <disp32> <imm8>`.  The displacement sits at +2, i.e. **not**
/// 4-aligned relative to the section start, which is exactly why a stride-4
/// walk missed it.
#[test]
fn absolute_memory_operand_is_found_at_an_unaligned_offset() {
    // cmp dword ptr [0x403010], 2
    let code = [0x83, 0x3d, 0x10, 0x30, 0x40, 0x00, 0x02];
    let hits = scan(&code);
    assert_eq!(
        hits,
        vec![CodeRelocation {
            rva: 0x1002,
            target: 0x403010
        }],
        "the displacement of an absolute memory operand must be relocated"
    );
}

/// A register-relative form still carries an image-relative constant.
///
/// `cmp dword ptr [eax + 0x400000], 0x4550` is `image_base + <eax>`, so the
/// constant moves with the image.  Measured: the reference sample's own table
/// relocates all 49 operands of this shape, so excluding them would lose 19%
/// of its `.text` entries.
#[test]
fn register_relative_operand_is_relocated_too() {
    // cmp dword ptr [eax + 0x400000], 0x4550
    let code = [0x81, 0xb8, 0x00, 0x00, 0x40, 0x00, 0x50, 0x45, 0x00, 0x00];
    let hits = scan(&code);
    assert_eq!(
        hits,
        vec![CodeRelocation {
            rva: 0x1002,
            target: 0x400000
        }],
        "a disp32 that names an image address must be rebased even with a base register"
    );
}

/// `push 0x400000` carries the image base as a 32-bit immediate.
#[test]
fn image_base_immediate_is_found() {
    let code = [0x68, 0x00, 0x00, 0x40, 0x00]; // push 0x400000
    let hits = scan(&code);
    assert_eq!(
        hits,
        vec![CodeRelocation {
            rva: 0x1001,
            target: 0x400000
        }]
    );
}

/// A `rel32` branch displacement must **never** be relocated.
///
/// This is not theoretical: a prototype that treated every 32-bit field as an
/// address rebased a `jmp rel32` displacement and sent EIP to `0x8b55ff8b`.
#[test]
fn relative_branch_displacement_is_never_relocated() {
    // jmp rel32 whose displacement bytes happen to encode an in-image value.
    // e8 00 00 40 00  ->  call 0x405005 (displacement 0x400000)
    let code = [0xe8, 0x00, 0x00, 0x40, 0x00];
    assert!(
        scan(&code).is_empty(),
        "a call/jmp rel32 displacement is an offset, not an address"
    );
    // e9 10 30 40 00  ->  jmp 0x804020 (displacement 0x403010)
    let code = [0xe9, 0x10, 0x30, 0x40, 0x00];
    assert!(scan(&code).is_empty());
    // 0f 84 <rel32>  ->  je rel32
    let code = [0x0f, 0x84, 0x10, 0x30, 0x40, 0x00];
    assert!(scan(&code).is_empty());
}

/// A value outside the image is not an address for this image.
#[test]
fn out_of_image_value_is_ignored() {
    let code = [0x68, 0x00, 0x00, 0x50, 0x00]; // push 0x500000 (above SizeOfImage)
    assert!(scan(&code).is_empty());
    let code = [0x68, 0x00, 0x00, 0x00, 0x00]; // push 0
    assert!(scan(&code).is_empty());
}

/// Non-executable sections are not this function's business: the pointer-stride
/// walk in `build_relocation_table` handles them.
#[test]
fn non_executable_section_is_skipped() {
    let code = [0x68, 0x00, 0x00, 0x40, 0x00];
    let data = padded(&code);
    let hits = scan_code_relocations(
        &data,
        BASE,
        SIZE,
        [(0x1000u32, code.len() as u32, data_flags())],
        |_| false,
    );
    assert!(hits.is_empty(), "only executable sections are scanned here");
}

/// The `reject` predicate must be able to veto a hit — that is how import
/// metadata is protected from exactly this scan.
#[test]
fn reject_predicate_vetoes_a_hit() {
    let code = [0x68, 0x00, 0x00, 0x40, 0x00]; // push 0x400000 at rva 0x1001
    let data = padded(&code);
    let hits = scan_code_relocations(
        &data,
        BASE,
        SIZE,
        [(0x1000u32, code.len() as u32, exec())],
        |rva| rva == 0x1001,
    );
    assert!(hits.is_empty(), "a vetoed rva must not appear");
    // Sanity: without the veto the same input does produce the hit, so the
    // assertion above is not vacuous.
    let unvetoed = scan(&code);
    assert_eq!(unvetoed.len(), 1);
}

/// Embedded data inside `.text` must not stop the walk.
///
/// The reference sample's `.text` is not pure code, and stopping at the first
/// undecodable byte loses every entry after it.  Measured: resynchronising one
/// byte at a time is what lets the reference reach all 256 entries.
///
/// The filler is `0xf0` because it is invalid at every alignment, so the walk
/// really has to step byte by byte.  `0xff` looks like filler but is not: at
/// offset +5 it forms `jmp fword ptr [eax]`, which swallows the following
/// `push` and makes the test's "after the blob" assertion unreachable.
#[test]
fn walk_resynchronises_past_undecodable_bytes() {
    let mut code = Vec::new();
    code.extend_from_slice(&[0x83, 0x3d, 0x10, 0x30, 0x40, 0x00, 0x02]); // cmp [0x403010],2
    code.extend_from_slice(&[0xf0; 6]); // undecodable at every alignment
    code.extend_from_slice(&[0x68, 0x00, 0x00, 0x40, 0x00]); // push 0x400000

    let hits = scan(&code);
    let rvas: Vec<u32> = hits.iter().map(|h| h.rva).collect();
    assert!(
        rvas.contains(&0x1002),
        "entry before the data blob must be found: {rvas:#x?}"
    );
    assert!(
        rvas.contains(&0x100e),
        "entry after the data blob must still be found — stopping at the first \
         undecodable byte would lose it: {rvas:#x?}"
    );
}

/// Two hits at the same rva must collapse, otherwise the table has duplicate
/// entries and the loader applies the delta twice.
#[test]
fn duplicate_rvas_are_deduplicated() {
    // Two instructions whose operands overlap the same dword is not
    // constructible, so this checks the sort/dedup path directly by feeding the
    // same section twice.
    let code = [0x68, 0x00, 0x00, 0x40, 0x00];
    let data = padded(&code);
    let hits = scan_code_relocations(
        &data,
        BASE,
        SIZE,
        [
            (0x1000u32, code.len() as u32, exec()),
            (0x1000u32, code.len() as u32, exec()),
        ],
        |_| false,
    );
    assert_eq!(hits.len(), 1, "duplicate entries must collapse");
}

/// Hits come back sorted, so the emitted table is deterministic.
#[test]
fn hits_are_sorted_by_rva() {
    // push 0x400010 ; push 0x400000  (second is lower, appears later)
    let code = [0x68, 0x10, 0x00, 0x40, 0x00, 0x68, 0x00, 0x00, 0x40, 0x00];
    let hits = scan(&code);
    assert_eq!(hits.len(), 2);
    assert!(
        hits[0].rva < hits[1].rva,
        "output must be ordered: {hits:#x?}"
    );
}
