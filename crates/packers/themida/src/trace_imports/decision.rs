//! Trace-Is-At-API decision logic and pure helpers shared between
//! [`super::trace_one_slot`] and the external `handle_trace_step` in the CLI
//! unpacker.
//!
//! Contains: [`TraceStepDecision`], [`trace_is_at_api`], [`is_real_api_address`].

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
    fn outside_image_is_real_api() {
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
    fn trace_is_at_api_found_api_outside_image() {
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
}
