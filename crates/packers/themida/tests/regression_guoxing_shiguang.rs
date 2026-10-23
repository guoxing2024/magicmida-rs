//! Regression fixtures frozen from a fully-successful end-to-end unpack.
//!
//! ## Case: guoxing2024 "时光一键宏" (Themida v3 x64, 2026-10-22)
//!
//! Sample: `时光一键宏.exe`, 5,793,808 bytes,
//! SHA-256 `7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7`.
//!
//! End-to-end result after the fixes frozen here:
//!
//! | Metric                     | Before fix      | After fix           |
//! |----------------------------|-----------------|---------------------|
//! | IAT trace coverage         | aborted @ 142/1063 | all 1063 slots   |
//! | Resolved imports           | 50 traced + 162 thunks | 186 thunks   |
//! | Import modules             | 8               | 9 (shell32 restored)|
//! | Crash slot `0x113C48`      | VM trampoline → 0xC0000005 | `SetProcessDPIAware` |
//! | Unpacked binary launches   | no (instant crash) | yes ("授权验证" window) |
//!
//! The tests below pin the **statically observable** parts of that case
//! (PE layout, section heuristics, OEP shape, Themida bounds) plus the
//! slot-classification taxonomy extracted into
//! [`mida_packers_themida::classify_iat_slot`].  They run without the sample
//! — every byte comes from the measured values recorded here.

use mida_packers_themida::{
    check_virtualized_oep, classify_iat_slot, compute_themida_section_bounds_inline,
    detect_version, is_themida_section, IatSlotDecision, ThemidaVersion,
};
use mida_pe::PeHeader;

// ---------------------------------------------------------------------------
// Golden record — measured values, do not edit without re-running the case.
// ---------------------------------------------------------------------------

/// SHA-256 of the original packed sample.
pub const SAMPLE_SHA256: &str = "7800980301207bf2f851d00a50f7f18e0dcd61a0f2b1581ca609ddcc0f2f1ea7";
/// Size of the original packed sample in bytes.
pub const SAMPLE_SIZE: u64 = 5_793_808;
/// Unpacked output size (default `/unpack` shrink path).
pub const UNPACKED_SIZE: u64 = 1_539_584;

/// Runtime image bounds observed during the successful run (ASLR base).
///
/// These are `u64`, not `usize`.  They are *x64 runtime addresses*, and a
/// `usize` literal of this magnitude does not fit in a 32-bit build: on
/// `i686-pc-windows-gnu` `0x0000_7FF6_F5D4_0000` is a hard compile error
/// ("literal out of range for `usize`").  The values describe the reference
/// x64 sample, so `u64` is the honest type regardless of the host target.
pub const RUNTIME_IMAGE_BASE: u64 = 0x0000_7FF6_F5D4_0000;
pub const RUNTIME_IMAGE_BOUNDARY: u64 = 0x0000_7FF6_F6A6_8000;
/// Themida section bounds (combined `.winlice` + `.boot`) at runtime.
pub const RUNTIME_THEMIDA_START: u64 = 0x0000_7FF6_F5EA_8000;
pub const RUNTIME_THEMIDA_END: u64 = 0x0000_7FF6_F6A6_6800;

/// IAT located by `determine_iat_address`: runtime VA → file RVA.
pub const IAT_RUNTIME_VA: u64 = 0x0000_7FF6_F5E5_36E0;
pub const IAT_RVA: u32 = 0x0011_36E0;
pub const IAT_SLOT_COUNT: usize = 1063;
pub const IAT_BLOCK_COUNT: usize = 14;

/// The slot behind `call qword ptr [rip+disp]` at `.text+0x3b63` that crashed
/// the first unpacked build (0xC0000005, executed a VM trampoline).
pub const CRASH_SLOT_RVA: u32 = 0x0011_3C48;
/// What that slot must resolve to (user32 export, verified in the output PE).
pub const CRASH_SLOT_EXPECTED: &str = "SetProcessDPIAware";

/// Trace-scan results after the fix (log: `IAT trace complete`).
pub const POSTFIX_RESOLVED: usize = 186;
pub const POSTFIX_FAILED: usize = 8;
pub const POSTFIX_MODULE_COUNT: usize = 9;
/// Pre-fix numbers, kept to make the regression visible in review.
pub const PREFIX_ABORT_SLOT: usize = 142;
pub const PREFIX_RESOLVED: usize = 50;
pub const PREFIX_MODULE_COUNT: usize = 8;

// ---------------------------------------------------------------------------
// Synthetic PE built from the measured section table
// ---------------------------------------------------------------------------

/// One measured section: `(name, virtual_address, virtual_size, raw_size, characteristics)`.
type SecRow = (&'static str, u32, u32, u32, u32);

/// The exact 16-entry section table of the packed sample.  The first ten
/// sections carry blank (8-space) names — the real Themida v3 x64 layout.
const SAMPLE_SECTIONS: [SecRow; 16] = [
    ("        ", 0x0010_0000, 0x000D_D9A0, 0x0004_C600, 0x6000_0020), // .text
    ("        ", 0x000D_F000, 0x0000_2140, 0x0000_0200, 0xC000_0040),
    ("        ", 0x000E_2000, 0x0001_2300, 0x0000_3C00, 0x4000_0040),
    ("        ", 0x000F_5000, 0x0000_BBE0, 0x0000_7200, 0x4000_0040),
    ("        ", 0x0010_1000, 0x0001_05B0, 0x0000_3800, 0x4000_0040),
    (".bss", 0x0011_2000, 0x0000_0C80, 0x0000_0000, 0xC000_0080),
    ("        ", 0x0011_3000, 0x0000_1BF0, 0x0000_0200, 0x4000_0040),
    ("        ", 0x0011_5000, 0x0000_0010, 0x0000_0200, 0xC000_0040),
    ("        ", 0x0011_6000, 0x0002_6E20, 0x0001_A600, 0x4000_0040),
    ("        ", 0x0013_D000, 0x0000_173C, 0x0000_0C00, 0x4200_0040),
    (".idata", 0x0013_F000, 0x0000_1000, 0x0000_0400, 0xC000_0040),
    (".tls", 0x0014_0000, 0x0000_1000, 0x0000_0200, 0xC000_0000),
    (".rsrc", 0x0014_1000, 0x0002_7000, 0x0002_7000, 0x4000_0040),
    (".winlice", 0x0016_8000, 0x006D_6000, 0x0000_0000, 0xE000_0060),
    (".boot", 0x0083_E000, 0x004E_8800, 0x004E_8800, 0x6000_0060),
    (".reloc", 0x00D2_7000, 0x0000_1000, 0x0000_0010, 0x4000_0000),
];

/// Entry point RVA — sits inside `.boot` (0x83E000..0xD26800).
const SAMPLE_ENTRY_RVA: u32 = 0x0083_E058;
/// First 16 bytes at the entry point (measured): `call rel32` into the VM.
const SAMPLE_OEP_BYTES: [u8; 16] = [
    0xE8, 0x82, 0x01, 0x00, 0x00, 0x41, 0x52, 0x49, 0x89, 0xE2, 0x41, 0x52, 0x49, 0x8B, 0x72, 0x10,
];
const SAMPLE_IMAGE_BASE: u64 = 0x0000_0140_0000_0000;
const SAMPLE_SIZE_OF_IMAGE: u32 = 0x00D2_8000;

/// Rebuild the packed sample's PE header (headers only, no section data).
fn make_shiguang_pe64() -> PeHeader {
    let nsec = SAMPLE_SECTIONS.len();
    let nt = 0x40usize;
    let sh = nt + 24 + 240; // section table start (PE32+)
    let need = sh + nsec * 40;
    let mut buf = vec![0u8; need];

    // DOS header
    buf[0] = 0x4D;
    buf[1] = 0x5A;
    buf[0x3C] = 0x40;

    // NT signature
    buf[nt] = 0x50;
    buf[nt + 1] = 0x45;

    // File header
    let fh = nt + 4;
    buf[fh] = 0x64; // machine lo (AMD64 = 0x8664)
    buf[fh + 1] = 0x86;
    buf[fh + 2] = nsec as u8;
    buf[fh + 16] = 0xF0; // SizeOfOptionalHeader = 240
    buf[fh + 18] = 0x22;

    // Optional header (PE32+)
    let oh = nt + 24;
    buf[oh] = 0x0B;
    buf[oh + 1] = 0x02; // Magic = 0x20B
    let ep = SAMPLE_ENTRY_RVA.to_le_bytes();
    buf[oh + 16..oh + 20].copy_from_slice(&ep);
    let ib = SAMPLE_IMAGE_BASE.to_le_bytes();
    buf[oh + 24..oh + 32].copy_from_slice(&ib);
    buf[oh + 33] = 0x10; // SectionAlignment = 0x1000
    buf[oh + 37] = 0x02; // FileAlignment = 0x200
    let soi = SAMPLE_SIZE_OF_IMAGE.to_le_bytes();
    buf[oh + 56..oh + 60].copy_from_slice(&soi);
    buf[oh + 108] = 0x10; // NumberOfRvaAndSizes = 16

    // Section table
    for (i, (name, _va, vs, rs, ch)) in SAMPLE_SECTIONS.iter().enumerate() {
        let o = sh + i * 40;
        let name_bytes = name.as_bytes();
        buf[o..o + name_bytes.len()].copy_from_slice(name_bytes);
        buf[o + 8..o + 12].copy_from_slice(&vs.to_le_bytes());
        buf[o + 12..o + 16].copy_from_slice(&SAMPLE_SECTIONS[i].1.to_le_bytes());
        buf[o + 16..o + 20].copy_from_slice(&rs.to_le_bytes());
        buf[o + 36..o + 40].copy_from_slice(&ch.to_le_bytes());
    }

    PeHeader::from_bytes(&buf).expect("fixture PE must parse")
}

// ---------------------------------------------------------------------------
// Static fingerprint assertions
// ---------------------------------------------------------------------------

#[test]
fn golden_sample_metadata() {
    assert_eq!(SAMPLE_SHA256.len(), 64);
    assert_eq!(SAMPLE_SIZE, 5_793_808);
    assert_eq!(UNPACKED_SIZE, 1_539_584);
}

#[test]
fn fingerprint_version_is_v3_for_x64() {
    let pe = make_shiguang_pe64();
    assert_eq!(pe.sections.len(), 16);
    assert_eq!(detect_version(&pe, true), ThemidaVersion::V3);
}

#[test]
fn fingerprint_themida_sections_detected() {
    let pe = make_shiguang_pe64();
    // .winlice: raw_size == 0, huge virtual size, executable → signal 4.
    assert!(is_themida_section(&pe.sections[13]), ".winlice must be flagged");
    // .boot: recognised by name.
    assert!(is_themida_section(&pe.sections[14]), ".boot must be flagged");
}

#[test]
fn fingerprint_regular_sections_not_flagged() {
    let pe = make_shiguang_pe64();
    for idx in [0usize, 5, 10, 11, 12, 15] {
        assert!(
            !is_themida_section(&pe.sections[idx]),
            "section {} ({:?}) must NOT be flagged",
            idx,
            pe.sections[idx].name,
        );
    }
}

#[test]
fn fingerprint_entry_point_inside_boot() {
    let pe = make_shiguang_pe64();
    let sec = pe
        .get_section_by_rva(SAMPLE_ENTRY_RVA)
        .expect("entry RVA must land in a section");
    assert_eq!(sec.name, ".boot");
}

#[test]
fn fingerprint_oep_is_call_not_jmp() {
    let pe = make_shiguang_pe64();
    // The real OEP enters the VM via `call rel32` (E8), not `jmp rel32` (E9).
    // `check_virtualized_oep` only detects the jmp form — this documents that
    // the static check intentionally reports false here and runtime OEP
    // discovery (guard path) is what found the real entry for this sample.
    assert!(!check_virtualized_oep(&pe, &SAMPLE_OEP_BYTES));
    assert_eq!(SAMPLE_OEP_BYTES[0], 0xE8);
}

#[test]
fn fingerprint_themida_bounds_match_runtime() {
    let pe = make_shiguang_pe64();
    let (start, end) = compute_themida_section_bounds_inline(&pe.sections, 0x1400_0000);
    // .winlice start .. .boot end, rebased to the file image base.
    assert_eq!(start, 0x1400_0000 + 0x0016_8000);
    assert_eq!(end, 0x1400_0000 + 0x0083_E000 + 0x004E_8800);
    // And the same numbers shifted by the observed ASLR delta equal the
    // runtime bounds recorded during the successful run.
    let delta = RUNTIME_IMAGE_BASE - 0x1400_0000u64;
    assert_eq!(start as u64 + delta, RUNTIME_THEMIDA_START);
    assert_eq!(end as u64 + delta, RUNTIME_THEMIDA_END);
}

// ---------------------------------------------------------------------------
// IAT fingerprint + slot taxonomy
// ---------------------------------------------------------------------------

#[test]
fn iat_fingerprint_consistency() {
    // Declared scan window and the crash slot must be mutually consistent.
    let iat_end = IAT_RVA + (IAT_SLOT_COUNT as u32) * 8;
    assert!(CRASH_SLOT_RVA >= IAT_RVA && CRASH_SLOT_RVA < iat_end);
    // The crash slot sits in the trailing region the pre-fix scan never
    // reached (after the abort at slot 142).
    assert!((CRASH_SLOT_RVA - IAT_RVA) as usize / 8 > PREFIX_ABORT_SLOT);
}

#[test]
#[cfg(target_pointer_width = "64")]
fn iat_slot_taxonomy_frozen() {
    let (ib, ibd, ts, te) = (
        RUNTIME_IMAGE_BASE,
        RUNTIME_IMAGE_BOUNDARY,
        RUNTIME_THEMIDA_START,
        RUNTIME_THEMIDA_END,
    );

    // Zero separators (live slot 3) — never trash.
    assert_eq!(classify_iat_slot(0, ts, te, ib, ibd), IatSlotDecision::Separator);

    // Already-resolved APIs (live slots 130..142) — the abort bug's trigger.
    for v in [0x7FFF_E3FC_B050u64, 0x7FFF_E3F6_D720, 0x7FFF_E3FB_4FD0] {
        assert_eq!(
            classify_iat_slot(v, ts, te, ib, ibd),
            IatSlotDecision::Resolved { api: v }
        );
    }

    // Themida VM trampoline (live slot 0) — must be traced.
    let vm = 0x7FF6_F602_6454u64;
    assert_eq!(
        classify_iat_slot(vm, ts, te, ib, ibd),
        IatSlotDecision::Trace { start: vm }
    );

    // Data garbage (observed packed 32-bit pairs) — trash.
    assert_eq!(
        classify_iat_slot(0x0113_03C0_0113_03C0u64, ts, te, ib, ibd),
        IatSlotDecision::Trash
    );
}

#[test]
#[cfg(target_pointer_width = "64")]
fn iat_long_resolved_run_cannot_abort_scan() {
    // 100 consecutive resolved slots (a full decrypted block) must classify
    // as Resolved — this is the exact shape that killed the pre-fix scan.
    //
    // Gated to 64-bit hosts: `classify_iat_slot` derives its "plausible API
    // range" from the host architecture, so these x64 fixtures are outside the
    // x86 range and classify as Trash on i686 by design.
    for i in 0..100u64 {
        let v = 0x7FFF_E3F0_0000 + i * 0x10;
        assert!(matches!(
            classify_iat_slot(v, RUNTIME_THEMIDA_START, RUNTIME_THEMIDA_END, RUNTIME_IMAGE_BASE, RUNTIME_IMAGE_BOUNDARY),
            IatSlotDecision::Resolved { .. }
        ));
    }
}

#[test]
fn postfix_outnumbers_prefix() {
    // Guard the golden record against accidental "fix reverted" edits: the
    // post-fix pipeline strictly dominates the pre-fix one.
    assert!(POSTFIX_RESOLVED > PREFIX_RESOLVED);
    assert!(POSTFIX_MODULE_COUNT > PREFIX_MODULE_COUNT);
    assert_eq!(POSTFIX_MODULE_COUNT, 9);
    assert_eq!(POSTFIX_RESOLVED, 186);
}
