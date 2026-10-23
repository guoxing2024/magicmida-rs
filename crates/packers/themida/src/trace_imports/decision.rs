//! Trace-Is-At-API decision logic and pure helpers shared between
//! [`super::trace_one_slot`] and the external `handle_trace_step` in the CLI
//! unpacker.
//!
//! Contains: [`TraceStepDecision`], [`trace_is_at_api`], [`is_real_api_address`],
//! [`IatSlotDecision`], [`classify_iat_slot`].

use super::PTR_SIZE;

// ===========================================================================
// TraceStepDecision
// ===========================================================================

/// Decision returned by [`trace_is_at_api`].
///
/// Encapsulates the "what should I do next?" outcome of examining the
/// current instruction pointer and stack pointer during a single-step trace,
/// once per step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStepDecision {
    /// Keep tracing — none of the stop/skip conditions are met.
    Continue,
    /// A real API has been reached at `ip`.  Stop tracing this slot; the
    /// resolved API address is `ip`.
    FoundApi { ip: usize },
    /// The trace walked into the Themida VM entry at `ip`.  Stop tracing this
    /// slot; the resolution failed (`trace_in_vm = true`).
    HitVm { ip: usize },
    /// Anti-trace fake call (Sleep/lstrlen) at `ip`.  Return address popped from
    /// `sp`; trace should continue from that address.
    SkipAntiTraceApi { ip: usize, ret_addr: usize },
}

/// Pure computation: given the current IP/SP and trace context, decide what
/// to do next.
///
/// This is the Rust equivalent of `Themida.pas`/`Themida64.pas` `TraceIsAtAPI`
/// predicate, extracted from `trace_one_step` and `handle_trace_step` so both
/// call sites share the exact same rules.
///
/// # Parameters
///
/// - `ip` — current instruction pointer
/// - `sp` — current stack pointer
/// - `trace_start_sp` — stack pointer at trace start (any later `sp < this`
///   means we're inside a nested call)
/// - `counter` — instruction counter for this slot (used to gate VM detection)
/// - `themida_start` / `themida_end` — Themida section bounds
/// - `image_base` / `image_boundary` — full image bounds
/// - `sleep_api` / `lstrlen_api` — resolved anti-trace API addresses (0 = unknown)
/// - `is_vm_entry` — whether the instruction at `ip` is the VM entry signature
#[allow(clippy::too_many_arguments)]
pub fn trace_is_at_api(
    ip: usize,
    sp: usize,
    trace_start_sp: usize,
    counter: u64,
    themida_start: usize,
    themida_end: usize,
    image_base: usize,
    image_boundary: usize,
    sleep_api: usize,
    lstrlen_api: usize,
    is_vm_entry: bool,
    #[allow(unused)] return_addr: usize,
) -> TraceStepDecision {
    // 1. VM entry detection — only in counter range 100..5000 (matches Pascal).
    if counter > 100 && counter < 5000 && is_vm_entry {
        return TraceStepDecision::HitVm { ip };
    }

    // 2. Anti-trace API skipping.  sp < trace_start_sp means we're in a
    //    nested call; if the target is Sleep or lstrlenA/W, pop return addr.
    if sp < trace_start_sp && (ip == sleep_api || ip == lstrlen_api) {
        return TraceStepDecision::SkipAntiTraceApi { ip, ret_addr: return_addr };
    }

    // 3. Section exit check — did we leave the Themida section?
    let in_themida = ip >= themida_start && ip < themida_end;
    if !in_themida {
        if sp < trace_start_sp {
            return TraceStepDecision::Continue;
        }

        // Not nested. Check if in-image (internal function) or outside (real API)
        if ip >= image_base && ip < image_boundary {
            return TraceStepDecision::Continue;
        }

        return TraceStepDecision::FoundApi { ip };
    }

    // 4. Still in Themida section — keep tracing.
    TraceStepDecision::Continue
}

// ===========================================================================
// IAT slot validity
// ===========================================================================

/// Check whether an IAT slot value is already a real API address (i.e. does
/// NOT need tracing).
///
/// Returns `true` when the value looks like a resolved API and can be skipped.
///
/// Logic (matches `Dumper.IsAPIAddress` + `TraceImports` range check):
/// - `0` → NOT a real API (needs tracing, but slot is empty).
/// - In the Themida section → NOT a real API (needs tracing).
/// - In the image but NOT in the Themida section → internal function (needs
///   tracing — it's not a real API from a system DLL).
/// - Outside the image → real API (skip).
#[allow(dead_code)]
pub(crate) fn is_real_api_address(
    address: usize,
    image_base: usize,
    image_boundary: usize,
    themida_section_start: usize,
    themida_section_end: usize,
) -> bool {
    if address == 0 {
        return false;
    }

    // In the Themida section → obfuscated, needs tracing.
    if address >= themida_section_start && address < themida_section_end {
        return false;
    }

    // In the image but outside the Themida section → Probably an internal
    // function, still needs tracing.
    if address >= image_base && address < image_boundary {
        return false;
    }

    // Below the minimum valid address → bogus.
    if address < 0x10000 {
        return false;
    }

    // Outside the image, above 0x10000 → likely a real API.
    true
}

// Keep PTR_SIZE referenced so the import stays consistent with the module.
const _: usize = PTR_SIZE;

// ===========================================================================
// IAT slot classification (v3 fragmented-IAT scan)
// ===========================================================================

/// Classification of one IAT slot value during the v3 trace scan.
///
/// Extracted from `trace_imports` so the taxonomy is unit-testable against
/// real-world observed values (see `tests/regression_guoxing_shiguang.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IatSlotDecision {
    /// Zero-valued block separator inside a fragmented v3 IAT.  Skip the slot
    /// and reset the trash counter — zeros are NOT trash.
    Separator,
    /// Already-resolved API address (fully-relocated `0x7FFx_xxxx_xxxx`,
    /// outside both the image and the Themida section).  Adopt as-is.
    ///
    /// **Regression guard:** the original scan counted these toward the trash
    /// threshold and aborted at slot 142 of 1063 on the guoxing/时光 sample,
    /// leaving ~900 slots — including the one behind `call [rip+disp]` at
    /// `.text+0x3b63` — still holding Themida VM trampolines.  The dumped
    /// image then crashed with 0xC0000005 on first launch.
    Resolved { api: u64 },
    /// Obfuscated pointer inside the Themida VM — single-step trace from
    /// `start` (the value as-is, already relocated).
    Trace { start: u64 },
    /// Bare in-image RVA stored unrelocated (Themida v3 x64 occasionally
    /// leaves slots as file-base-relative values).  Trace from
    /// `image_base + rva`.
    TraceRva { start: u64 },
    /// Non-zero value that is neither an API, nor in the image, nor in the
    /// Themida section — data garbage.  Counts toward the trash threshold.
    Trash,
    /// Bare in-image RVA that points at a **non-executable** section.
    ///
    /// Such a slot cannot be an import thunk: a thunk must be callable, so its
    /// target has to live in executable memory.  Themida v3 leaves a handful of
    /// slots holding pointers to read-only data (measured on the reference DLL:
    /// slots 901/965/1057 hold `0x141000`/`0x141064`/`0x1410DC`, which is the
    /// start of a `.rdata` section), and the real Windows loader leaves them
    /// exactly like that — they are data the shell keeps in the table, not
    /// imports.
    ///
    /// Counting them as failures was wrong in two ways: it made the run look
    /// less complete than it is, and it made the trace waste 500 000
    /// single-steps per slot executing into a data section.
    ///
    /// Verified on the reference DLL: these slots have **zero** code
    /// references (no RIP-relative operand targets them, and their addresses
    /// appear zero times as absolute qwords anywhere in the image), so leaving
    /// them untouched cannot break the product.
    NotAnImport,
}

/// Pure computation: classify one IAT slot value before the trace scan acts
/// on it.
///
/// Ordering matters and mirrors the fixed `trace_imports` loop:
///
/// 1. `0` → [`IatSlotDecision::Separator`] (never trash — fragmented v3 IATs
///    separate their blocks with zero runs).
/// 2. In Themida section → [`IatSlotDecision::Trace`] (obfuscated import).
/// 3. Outside image + plausible API range → [`IatSlotDecision::Resolved`]
///    (Themida decrypts IAT blocks progressively; by trace time whole blocks
///    may already be resolved).
/// 4. In image but outside Themida section → [`IatSlotDecision::Trace`] if
///    stored relocated, [`IatSlotDecision::TraceRva`] if stored as a bare RVA.
/// 5. Everything else → [`IatSlotDecision::Trash`].
/// # Why `u64` and not `usize`
///
/// An address is a `u64` concept, not a pointer-width one.  These parameters
/// used to be `usize`, which meant an x64 runtime address such as
/// `0x7FF6_F5D4_0000` could not be written as a literal at all when compiling
/// for a 32-bit target — the build failed with "literal out of range for
/// `usize`", and the same mistake elsewhere in this file had once silently
/// produced `0usize`, mis-classifying every address.  Taking `u64` makes the
/// classifier architecture-independent: the same fixture values work on both
/// hosts, and 32-bit callers widen instead of truncating.
#[must_use]
pub fn classify_iat_slot(
    value: u64,
    themida_start: u64,
    themida_end: u64,
    image_base: u64,
    image_boundary: u64,
) -> IatSlotDecision {
    classify_iat_slot_with_sections(
        value,
        themida_start,
        themida_end,
        image_base,
        image_boundary,
        &[],
    )
}

/// Section-description-free classifier, kept for the existing call sites and
/// tests.  See [`classify_iat_slot_in`] when section executability is known.
#[must_use]
pub fn classify_iat_slot_in(
    value: u64,
    themida_start: u64,
    themida_end: u64,
    image_base: u64,
    image_boundary: u64,
    sections: &[(u32, u32, bool)],
) -> IatSlotDecision {
    classify_iat_slot_with_sections(
        value,
        themida_start,
        themida_end,
        image_base,
        image_boundary,
        sections,
    )
}

/// Shared implementation.  `sections` is `(rva, size, is_executable)` triples;
/// when empty, the "points at data" check is skipped and the old behaviour is
/// preserved.
fn classify_iat_slot_with_sections(
    value: u64,
    themida_start: u64,
    themida_end: u64,
    image_base: u64,
    image_boundary: u64,
    sections: &[(u32, u32, bool)],
) -> IatSlotDecision {
    if value == 0 {
        return IatSlotDecision::Separator;
    }

    if value >= themida_start && value < themida_end {
        return IatSlotDecision::Trace { start: value };
    }

    // Already-resolved API: same heuristic as `iat::fix::is_likely_api_address`
    // (user-mode DLL range on x64/x86), inlined here so the classifier stays a
    // dependency-free pure function.
    let value64 = value;
    let plausible_api = if cfg!(target_arch = "x86_64") {
        (0x7ff0_0000_0000u64..0x0000_7FFF_FFFF_0000u64).contains(&value64)
    } else {
        (0x6000_0000u64..0x7FFF_0000u64).contains(&value64)
    };
    if plausible_api {
        return IatSlotDecision::Resolved { api: value };
    }

    let in_image_ptr = value >= image_base && value < image_boundary;
    let relocated = image_base.wrapping_add(value);
    let in_image_rva = relocated >= image_base && relocated < image_boundary;

    if in_image_ptr {
        return IatSlotDecision::Trace { start: value };
    }
    if in_image_rva {
        // A bare RVA that lands in a non-executable section is data the shell
        // parked in the table, not an import thunk — see `NotAnImport`.
        let rva = value as u32;
        let lands_in_data = sections.iter().any(|&(va, size, exec)| {
            !exec && rva >= va && (rva as u64) < va as u64 + size as u64
        });
        if lands_in_data {
            return IatSlotDecision::NotAnImport;
        }
        return IatSlotDecision::TraceRva { start: relocated };
    }

    IatSlotDecision::Trash
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_not_real_api() {
        assert!(!is_real_api_address(
            0,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn in_themida_section_needs_tracing() {
        assert!(!is_real_api_address(
            0x411000,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn in_image_but_not_themida_needs_tracing() {
        assert!(!is_real_api_address(
            0x405000,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn outside_image_is_real_api() {
        // An x64 user-mode API address.  Gated to 64-bit hosts because
        // `is_real_api_address` takes `usize`, so the literal cannot exist on
        // i686 — the 32-bit equivalent is `low_address_is_not_real_api` below.
        assert!(is_real_api_address(
            0x7FFE12345678,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn low_address_is_not_real_api() {
        assert!(!is_real_api_address(
            0x5000,
            0x400000,
            0x500000,
            0x410000,
            0x420000
        ));
    }

    #[test]
    fn trace_is_at_api_continue_inside_themida() {
        assert_eq!(
            trace_is_at_api(
                0x410500, 0x10000, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, false, 0,
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    fn trace_is_at_api_hit_vm_within_counter_range() {
        assert_eq!(
            trace_is_at_api(
                0x410500, 0x10000, 0x10000, 200,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, true, 0,
            ),
            TraceStepDecision::HitVm { ip: 0x410500 },
        );
    }

    #[test]
    fn trace_is_at_api_ignore_vm_below_counter_threshold() {
        assert_eq!(
            trace_is_at_api(
                0x410500, 0x10000, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, true, 0,
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    fn trace_is_at_api_ignore_vm_above_counter_threshold() {
        assert_eq!(
            trace_is_at_api(
                0x410500, 0x10000, 0x10000, 5001,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, true, 0,
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn trace_is_at_api_found_api_outside_image() {
        // x64 IP literal: `trace_is_at_api` takes `usize`, so this only exists
        // on a 64-bit host.
        assert_eq!(
            trace_is_at_api(
                0x7FFE12340000, 0x10000, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, false, 0,
            ),
            TraceStepDecision::FoundApi { ip: 0x7FFE12340000 },
        );
    }

    #[test]
    fn trace_is_at_api_continue_on_internal_function() {
        assert_eq!(
            trace_is_at_api(
                0x405000, 0x10000, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, false, 0,
            ),
            TraceStepDecision::Continue,
        );
    }

    #[test]
    fn trace_is_at_api_skip_anti_trace_sleep() {
        assert_eq!(
            trace_is_at_api(
                0x7FFE0000, 0x0FF00, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, false, 0xDEAD0000,
            ),
            TraceStepDecision::SkipAntiTraceApi {
                ip: 0x7FFE0000,
                ret_addr: 0xDEAD0000,
            },
        );
    }

    #[test]
    fn trace_is_at_api_skip_anti_trace_lstrlen() {
        assert_eq!(
            trace_is_at_api(
                0x7FFE1000, 0x0FF00, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, false, 0xDEAD0001,
            ),
            TraceStepDecision::SkipAntiTraceApi {
                ip: 0x7FFE1000,
                ret_addr: 0xDEAD0001,
            },
        );
    }

    #[test]
    fn trace_is_at_api_no_skip_when_sp_at_start() {
        assert_eq!(
            trace_is_at_api(
                0x7FFE0000, 0x10000, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, false, 0,
            ),
            TraceStepDecision::FoundApi { ip: 0x7FFE0000 },
        );
    }

    #[test]
    fn trace_is_at_api_continue_when_outside_themida_but_nested() {
        assert_eq!(
            trace_is_at_api(
                0x505000, 0x0FF00, 0x10000, 50,
                0x410000, 0x420000, 0x400000, 0x500000,
                0x7FFE0000, 0x7FFE1000, false, 0,
            ),
            TraceStepDecision::Continue,
        );
    }

    // -- classify_iat_slot: regression fixtures from the guoxing/时光 V3 x64
    //    case (2026-10-22).  Live runtime context of that sample:
    //      image        0x7ff6f5d40000 .. 0x7ff6f6a68000
    //      themida sect 0x7ff6f5ea8000 .. 0x7ff6f6a66800
    //    These constants reproduce that run; the assertions freeze the
    //    taxonomy that fixed the slot-142 trash-abort bug.

    /// (image_base, image_boundary, themida_start, themida_end)
    ///
    /// `u64`, not `usize`: these are x64 runtime addresses, and a `usize`
    /// literal of this magnitude does not even compile on a 32-bit target.
    const SHIGUANG: (u64, u64, u64, u64) = (
        0x0000_7FF6_F5D4_0000,
        0x0000_7FF6_F6A6_8000,
        0x0000_7FF6_F5EA_8000,
        0x0000_7FF6_F6A6_6800,
    );

    #[test]
    fn shiguang_zero_separator_is_not_trash() {
        // Live slot 3 held 0 — under the old code it incremented trash_counter.
        let d = classify_iat_slot(0, SHIGUANG.2, SHIGUANG.3, SHIGUANG.0, SHIGUANG.1);
        assert_eq!(d, IatSlotDecision::Separator);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn shiguang_resolved_api_block_is_not_trash() {
        // Live slots 130-142 held already-resolved API addresses like these
        // (ntdll/KERNELBASE range) — the old code abort the scan here.
        let samples = [
            0x0000_7FFF_E3FC_B050u64,
            0x0000_7FFF_E3FC_B180,
            0x0000_7FFF_E3F6_D720,
            0x0000_7FFF_E3FB_4FD0,
        ];
        for v in samples {
            let d = classify_iat_slot(v, SHIGUANG.2, SHIGUANG.3, SHIGUANG.0, SHIGUANG.1);
            assert_eq!(d, IatSlotDecision::Resolved { api: v }, "value {v:#x}");
        }
    }

    #[test]
    fn bare_rva_into_data_section_is_not_an_import() {
        // Reference DLL, live loader: slots 901/965/1057 hold 0x141000 /
        // 0x141064 / 0x1410DC, which is the start of a non-executable .rdata
        // section.  A thunk must be callable, so these cannot be imports.
        let image_base = 0x3205_C0000u64;
        let image_boundary = image_base + 0x1B9000;
        let themida_start = image_base + 0x198000;
        let themida_end = image_base + 0xDB2000;
        // (.rdata at 0x141000 size 0x2B98, not executable) + (.text, executable)
        let sections = [
            (0x141000u32, 0x2B98u32, false),
            (0x1000u32, 0x1017C0u32, true),
        ];
        for v in [0x141000u64, 0x141064, 0x1410DC] {
            let d = classify_iat_slot_in(
                v, themida_start, themida_end, image_base, image_boundary, &sections,
            );
            assert_eq!(d, IatSlotDecision::NotAnImport, "value {v:#x}");
        }
    }

    #[test]
    fn bare_rva_into_executable_section_is_still_traced() {
        // The data-section rule must not swallow a genuine in-image thunk that
        // happens to be stored as a bare RVA into .text.
        let image_base = 0x3205_C0000u64;
        let image_boundary = image_base + 0x1B9000;
        let themida_start = image_base + 0x198000;
        let themida_end = image_base + 0xDB2000;
        let sections = [(0x1000u32, 0x1017C0u32, true)];
        let d = classify_iat_slot_in(
            0x2BB10, themida_start, themida_end, image_base, image_boundary, &sections,
        );
        assert!(matches!(d, IatSlotDecision::TraceRva { .. }), "got {d:?}");
    }

    #[test]
    fn no_section_info_keeps_old_behaviour() {
        // Callers that cannot supply section characteristics must not suddenly
        // start skipping slots.
        let image_base = 0x3205_C0000u64;
        let image_boundary = image_base + 0x1B9000;
        let themida_start = image_base + 0x198000;
        let themida_end = image_base + 0xDB2000;
        let d = classify_iat_slot(
            0x141000, themida_start, themida_end, image_base, image_boundary,
        );
        assert!(matches!(d, IatSlotDecision::TraceRva { .. }), "got {d:?}");
    }

    #[test]
    fn shiguang_vm_pointer_is_traced() {
        // Live slot 0: 0x7ff6f6026454 — inside the Themida section.
        let v = 0x0000_7FF6_F602_6454u64;
        assert!(v >= SHIGUANG.2 && v < SHIGUANG.3);
        let d = classify_iat_slot(v, SHIGUANG.2, SHIGUANG.3, SHIGUANG.0, SHIGUANG.1);
        assert_eq!(d, IatSlotDecision::Trace { start: v });
    }

    #[test]
    fn shiguang_data_garbage_is_trash() {
        // Observed unresolvable pairs: 0x11303c0011303c / 0x11305000113050 —
        // two packed 32-bit data offsets, neither API nor image pointer.
        for v in [0x0000_0113_03C0_0113_03C0u64, 0x0000_0113_0500_0113_0500] {
            let d = classify_iat_slot(v, SHIGUANG.2, SHIGUANG.3, SHIGUANG.0, SHIGUANG.1);
            assert_eq!(d, IatSlotDecision::Trash, "value {v:#x}");
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn shiguang_image_internal_pointer_resolved_on_x64() {
        // On x64 the ASLR image base (0x7FF6_....) itself sits inside the
        // plausible-API range, so a relocated in-image non-Themida pointer
        // classifies as Resolved BEFORE the in-image Trace branch.  This is
        // the exact ordering the successful 186-thunk run used — freeze it.
        // (The Trace branch for raw in-image pointers only fires on x86-style
        // bases, see `x86_style_image_pointer_is_traced` below.)
        //
        // Gated to 64-bit hosts: `classify_iat_slot` derives its API range from
        // the host architecture, so on i686 a 0x7FF6_... base is outside the
        // x86 range and this ordering does not apply.
        let v = SHIGUANG.0 + 0x5000; // inside .text, relocated
        let d = classify_iat_slot(v, SHIGUANG.2, SHIGUANG.3, SHIGUANG.0, SHIGUANG.1);
        assert_eq!(d, IatSlotDecision::Resolved { api: v });
    }

    #[test]
    fn x86_style_image_pointer_is_traced() {
        // x86-style base (0x400000) lies below the plausible-API range, so a
        // relocated in-image pointer there must reach the Trace branch.
        let d = classify_iat_slot(
            0x0040_5000, // image 0x400000..0x500000, themida 0x410000..0x420000
            0x0041_0000,
            0x0042_0000,
            0x0040_0000,
            0x0050_0000,
        );
        assert_eq!(d, IatSlotDecision::Trace { start: 0x0040_5000 });
    }

    #[test]
    fn bare_rva_gets_rebased_for_tracing() {
        // Synthetic: file-base-relative value stored unrelocated.
        // image 0x140000000..0x140D28000; rva 0x500000 → trace at 0x140500000.
        let d = classify_iat_slot(
            0x0050_0000,
            0x1401_68000, // themida start (.winlice)
            0x140D_28000, // themida end
            0x1_4000_0000,
            0x1_40D2_8000,
        );
        assert_eq!(d, IatSlotDecision::TraceRva { start: 0x1_4050_0000 });
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn one_hundred_consecutive_resolved_slots_never_trash() {
        // The core regression: a long run of already-resolved API addresses
        // must classify as Resolved (never Trash), so the scan cannot abort
        // mid-table the way it did at slot 142/1063.
        //
        // Gated to 64-bit hosts on purpose: `classify_iat_slot` picks its
        // "plausible API range" from the *host* architecture (`cfg!` on
        // `target_arch`), which is correct because the CLI is built for the
        // architecture it unpacks.  These fixtures are x64 addresses, so on an
        // i686 host they fall outside the x86 range and are Trash by design —
        // asserting otherwise would be testing the wrong thing.
        for i in 0..100 {
            let v = 0x0000_7FFF_E3F0_0000u64 + i as u64 * 0x10;
            let d = classify_iat_slot(v, SHIGUANG.2, SHIGUANG.3, SHIGUANG.0, SHIGUANG.1);
            assert_eq!(
                d,
                IatSlotDecision::Resolved { api: v },
                "slot offset {i} — a resolved run must never feed the trash counter"
            );
        }
    }
}
