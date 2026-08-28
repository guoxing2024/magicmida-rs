//! Graded (partial) acceptance policy for live IAT recovery.
//!
//! XX-9-A direction 2: the old fail-closed gate was all-or-nothing. A single
//! un-attributable slot (e.g. the XX-8 `0x1b370fa3810` VM-deobfuscation error)
//! reverted the *entire* live rebuild — 185 fully-resolved thunks — back to a
//! 9-thunk Themida on-disk stub table, producing `0xC0000005` on load.
//!
//! This module keeps the strict [`crate::IatRecoveryReport::is_complete`]
//! predicate untouched (the perfect-prerequisite gate still demands it), and
//! adds a *separate* graded predicate that decides how the dump emitter may
//! use a recovery report that is not strictly complete.
//!
//! # Policy (fail-closed where it matters)
//!
//! 1. Structural defects (short-read, unaligned span, missing slot coverage,
//!    duplicate indices/addresses/RVAs, missing `slot_rva`, observed-alias
//!    mismatch, missing `unresolved_reason` on a non-resolved slot) are
//!    **never** graded — they stay fatal. A structurally unsound report cannot
//!    be partially trusted.
//!
//! 2. Non-`Resolved`/`ZeroTerminator` slots are classified into two sets:
//!    - **Rejected** (`Unresolved` / `ShortRead` / `InvalidModule`): a rejected
//!      slot is already absent from the `ImportTableBuilder` produced by the
//!      two-pass vote (it has no candidates), so the emitted table simply skips
//!      it. The loader never references the skipped slot: `build_import_section_no_iat`
//!      compacts the run and appends the module terminator.
//!    - **Stale** (`Stale`): the observed value is *inside* a loaded module but
//!      not at a current export. Also absent from the builder; surfaced here for
//!      the manifest.
//!
//! 3. Graded acceptance is allowed only when `resolved/(resolved+rejected)`
//!    is `>= PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION` (95%) and the absolute
//!    rejected count is `<= PARTIAL_ACCEPT_MAX_REJECTED` (4). The denominator
//!    intentionally *excludes* zero terminators and stale slots.
//!
//! 4. A graded acceptance always returns `partial_accepted = true` (even when
//!    the thresholds are not met and the caller must fall back), so the
//!    acceptance side can see the full decision in the manifest — the record
//!    is never silently absent.
//!
//! # Never mixed
//!
//! A graded table is built **only** from the report's own `Resolved` slots
//! (via the existing two-pass `ImportTableBuilder`). It is never merged with
//! the original on-disk stub table: a half-live / half-stub table is more
//! dangerous than an honest hole. The rejected slot is left as an honest hole,
//! never substituted with a stub thunk.

use crate::iat_completeness::{IatRecoveryReport, IatSlotStatus, IatUnresolvedReason};

/// Minimum resolved fraction (vs. resolved + rejected) required for graded
/// acceptance of an incomplete IAT report.
pub const PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION_NUMERATOR: usize = 95;
pub const PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION_DENOMINATOR: usize = 100;

/// Maximum absolute number of rejected (non-`Stale`, non-resolved) slots that
/// a graded acceptance may tolerate.
pub const PARTIAL_ACCEPT_MAX_REJECTED: usize = 4;

/// One rejected slot described for the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatRejectedSlot {
    /// Zero-based slot index within the IAT span.
    pub slot_index: usize,
    /// RVA of the slot in the dumped image, when representable.
    pub slot_rva: Option<u32>,
    /// Immutable pointer value observed before any reconstruction write.
    pub observed_value: Option<u64>,
    /// Deterministic root-cause reason for the rejection, when established.
    pub unresolved_reason: Option<IatUnresolvedReason>,
}

/// One stale slot (inside a module but not a current export), kept as an
/// explicit hole in the emitted import table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatStaleSlot {
    /// Zero-based slot index within the IAT span.
    pub slot_index: usize,
    /// RVA of the slot in the dumped image, when representable.
    pub slot_rva: Option<u32>,
    /// Immutable pointer value observed before any reconstruction write.
    pub observed_value: Option<u64>,
}

/// The full graded-acceptance decision for one incomplete IAT report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatPartialAcceptDecision {
    /// Whether the report is strictly complete (then `partial_accepted` is
    /// `false` — nothing was graded).
    pub strict_complete: bool,
    /// Whether a graded acceptance was produced. Always `true` for an
    /// incomplete report (even when the thresholds reject it), so the
    /// manifest can carry the decision record. `false` only when
    /// `strict_complete`.
    pub partial_accepted: bool,
    /// The resolved-fraction numerator/denominator actually computed.
    pub resolved_fraction_num: usize,
    pub resolved_fraction_den: usize,
    /// Whether the resolved fraction met the minimum threshold.
    pub fraction_ok: bool,
    /// Whether the absolute rejected count met the maximum threshold.
    pub rejected_within_budget: bool,
    /// Structural defects (always fatal; never graded).
    pub structural_failures: Vec<String>,
    /// Rejected (never emitted) slots, in slot order.
    pub rejected_slots: Vec<IatRejectedSlot>,
    /// Stale slots (inside a module but not a current export), in slot order.
    pub stale_slots: Vec<IatStaleSlot>,
    /// Zero-based indices of resolved slots that are safe to emit. This is
    /// every `Resolved` slot: the two-pass vote already removed rejected/stale
    /// slots from the builder, and `build_import_section_no_iat` compacts the
    /// run plus module terminator so the loader never references a skipped
    /// slot. In slot order.
    pub accepted_resolved_slots: Vec<usize>,
}

impl IatPartialAcceptDecision {
    /// A strictly complete report produces a trivial non-graded decision.
    #[must_use]
    pub fn complete() -> Self {
        Self {
            strict_complete: true,
            partial_accepted: false,
            resolved_fraction_num: 0,
            resolved_fraction_den: 0,
            fraction_ok: true,
            rejected_within_budget: true,
            structural_failures: Vec::new(),
            rejected_slots: Vec::new(),
            stale_slots: Vec::new(),
            accepted_resolved_slots: Vec::new(),
        }
    }
}

/// Compute the graded-acceptance decision for a recovery report.
///
/// Pure function; no process I/O. `report.is_complete()` stays the authority
/// for the perfect-prerequisite gate; this is a separate policy layer that the
/// dump emitter consults only when `is_complete()` is false.
#[must_use]
pub fn evaluate_partial_accept(report: &IatRecoveryReport) -> IatPartialAcceptDecision {
    if report.is_complete() {
        return IatPartialAcceptDecision::complete();
    }

    let structural_failures = structural_failures(report);

    let mut rejected_slots = Vec::new();
    let mut stale_slots = Vec::new();
    let mut accepted_resolved_slots = Vec::new();
    let mut resolved_count = 0usize;
    let mut rejected_count = 0usize;

    for slot in &report.slots {
        match slot.status {
            IatSlotStatus::Resolved => {
                resolved_count += 1;
                accepted_resolved_slots.push(slot.slot_index);
            }
            IatSlotStatus::ZeroTerminator => {}
            IatSlotStatus::Stale => {
                stale_slots.push(IatStaleSlot {
                    slot_index: slot.slot_index,
                    slot_rva: slot.slot_rva,
                    observed_value: slot.observed_value,
                });
            }
            IatSlotStatus::Unresolved
            | IatSlotStatus::ShortRead
            | IatSlotStatus::InvalidModule => {
                rejected_count += 1;
                rejected_slots.push(IatRejectedSlot {
                    slot_index: slot.slot_index,
                    slot_rva: slot.slot_rva,
                    observed_value: slot.observed_value,
                    unresolved_reason: slot.unresolved_reason,
                });
            }
        }
    }
    accepted_resolved_slots.sort_unstable();

    let resolved_fraction_num = resolved_count;
    let resolved_fraction_den = resolved_count.saturating_add(rejected_count);
    // Integer ceiling: num/den >= 95/100  <==>  num*100 >= den*95.
    let fraction_ok = resolved_fraction_den == 0
        || resolved_fraction_num
            .saturating_mul(PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION_DENOMINATOR)
            >= resolved_fraction_den
                .saturating_mul(PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION_NUMERATOR);
    let rejected_within_budget = rejected_count <= PARTIAL_ACCEPT_MAX_REJECTED;

    IatPartialAcceptDecision {
        strict_complete: false,
        partial_accepted: true,
        resolved_fraction_num,
        resolved_fraction_den,
        fraction_ok,
        rejected_within_budget,
        structural_failures,
        rejected_slots,
        stale_slots,
        accepted_resolved_slots,
    }
}

/// Extract only the structural failures from a report (never the status-count
/// rows like `Unresolved=1`). Graded acceptance may tolerate rejected slots
/// but never a structurally unsound span.
fn structural_failures(report: &IatRecoveryReport) -> Vec<String> {
    let aligned = report.slot_size != 0 && report.requested_bytes.is_multiple_of(report.slot_size);
    let expected_slots = if aligned {
        report.requested_bytes / report.slot_size
    } else {
        0
    };
    let mut failures = Vec::new();
    if !aligned {
        failures.push("unaligned IAT span".into());
    }
    if report.bytes_read != report.requested_bytes {
        failures.push(format!(
            "short-read {}/{} bytes",
            report.bytes_read, report.requested_bytes
        ));
    }
    if report.slots.len() != expected_slots {
        failures.push(format!(
            "incomplete slot coverage {}/{} slots",
            report.slots.len(),
            expected_slots
        ));
    }

    let mut indices = std::collections::HashSet::new();
    let mut addresses = std::collections::HashSet::new();
    let mut rvas = std::collections::HashSet::new();
    let mut duplicate_index = false;
    let mut duplicate_address = false;
    let mut duplicate_rva = false;
    let mut coverage_mismatch = false;
    let mut invalid_slot_metadata = false;
    let mut observed_mismatch = false;

    for (position, slot) in report.slots.iter().enumerate() {
        if !indices.insert(slot.slot_index) {
            duplicate_index = true;
        }
        if !addresses.insert(slot.slot_address) {
            duplicate_address = true;
        }
        match slot.slot_rva {
            Some(rva) => {
                if !rvas.insert(rva) {
                    duplicate_rva = true;
                }
            }
            None => invalid_slot_metadata = true,
        }
        if slot.slot_index != position {
            coverage_mismatch = true;
        }
        if let Some(first) = report.slots.first() {
            let expected_address = first
                .slot_address
                .checked_add(position.saturating_mul(report.slot_size) as u64);
            let expected_rva = first.slot_rva.and_then(|rva| {
                rva.checked_add(position.saturating_mul(report.slot_size) as u32)
            });
            if expected_address != Some(slot.slot_address) || expected_rva != slot.slot_rva {
                coverage_mismatch = true;
            }
        }
        if slot.slot_value != slot.observed_value {
            observed_mismatch = true;
        }
    }

    if duplicate_index {
        failures.push("duplicate slot_index".into());
    }
    if duplicate_address {
        failures.push("duplicate slot_address".into());
    }
    if duplicate_rva {
        failures.push("duplicate slot_rva".into());
    }
    if coverage_mismatch {
        failures.push("slot coverage mismatch".into());
    }
    if invalid_slot_metadata {
        failures.push("missing slot_rva".into());
    }
    if observed_mismatch {
        failures.push("observed value alias mismatch".into());
    }

    // Missing `unresolved_reason` on a non-resolved slot is pending live
    // confirmation. Graded acceptance cannot be applied to a report that has
    // unclassified non-resolved slots (a fabricated "stale" downgrade would be
    // dishonest). Keep them fatal via a structural failure.
    for slot in &report.slots {
        if !matches!(
            slot.status,
            IatSlotStatus::Resolved | IatSlotStatus::ZeroTerminator
        ) && slot.unresolved_reason.is_none()
        {
            failures.push(format!(
                "slot {} missing unresolved_reason (pending live confirmation)",
                slot.slot_index
            ));
        }
    }
    failures
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iat_completeness::{IatSlotReport, IatUnresolvedReason};

    fn slot(
        index: usize,
        status: IatSlotStatus,
        reason: Option<IatUnresolvedReason>,
    ) -> IatSlotReport {
        let observed = match status {
            IatSlotStatus::ZeroTerminator => Some(0),
            _ => Some(0x7ff8_0000_1000 + index as u64),
        };
        let resolved = status == IatSlotStatus::Resolved;
        IatSlotReport {
            slot_index: index,
            slot_address: 0x1400_0000 + (index as u64 * 8),
            slot_rva: Some(0x1136e0 + (index as u32 * 8)),
            observed_value: observed,
            rebuilt_value: resolved.then_some(observed.unwrap_or(0)),
            slot_value: observed,
            status,
            unresolved_reason: reason,
            module_name: resolved.then(|| "kernel32.dll".into()),
            function_name: resolved.then(|| "CreateFileW".into()),
            ordinal: None,
        }
    }

    fn report(slots: Vec<IatSlotReport>) -> IatRecoveryReport {
        IatRecoveryReport {
            requested_bytes: slots.len() * 8,
            bytes_read: slots.len() * 8,
            slot_size: 8,
            slots,
        }
    }

    #[test]
    fn complete_report_is_never_graded() {
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(1, IatSlotStatus::ZeroTerminator, None),
        ]);
        let d = evaluate_partial_accept(&r);
        assert!(d.strict_complete);
        assert!(!d.partial_accepted);
    }

    #[test]
    fn xx8_shape_is_graded_and_keeps_all_resolved() {
        // Mirror XX-8: slot 0 rejected, 185 resolved, 15 zero terminators.
        let mut slots = vec![slot(
            0,
            IatSlotStatus::Unresolved,
            Some(IatUnresolvedReason::ModuleNotFound),
        )];
        for i in 1..=185 {
            slots.push(slot(i, IatSlotStatus::Resolved, None));
        }
        for i in 186..201 {
            slots.push(slot(i, IatSlotStatus::ZeroTerminator, None));
        }
        let d = evaluate_partial_accept(&report(slots));
        assert!(!d.strict_complete);
        assert!(d.partial_accepted);
        assert_eq!(d.resolved_fraction_num, 185);
        assert_eq!(d.resolved_fraction_den, 186);
        assert!(d.fraction_ok, "185/186 >= 95%");
        assert!(d.rejected_within_budget, "1 <= 4");
        assert_eq!(d.rejected_slots.len(), 1);
        assert_eq!(d.rejected_slots[0].slot_index, 0);
        // Every resolved slot survives: the two-pass vote already dropped the
        // rejected slot and build_import_section_no_iat compacts the run.
        assert_eq!(d.accepted_resolved_slots.len(), 185);
        assert_eq!(d.accepted_resolved_slots.first(), Some(&1));
        assert_eq!(d.accepted_resolved_slots.last(), Some(&185));
    }

    #[test]
    fn stale_slots_are_classified_but_not_rejected() {
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(
                1,
                IatSlotStatus::Stale,
                Some(IatUnresolvedReason::AddressNotExported),
            ),
            slot(2, IatSlotStatus::Resolved, None),
            slot(3, IatSlotStatus::ZeroTerminator, None),
        ]);
        let d = evaluate_partial_accept(&r);
        assert_eq!(d.rejected_slots.len(), 0);
        assert_eq!(d.stale_slots.len(), 1);
        assert_eq!(d.stale_slots[0].slot_index, 1);
        assert_eq!(d.accepted_resolved_slots, vec![0, 2]);
    }

    #[test]
    fn fraction_thresholds_at_95_percent_boundary() {
        // 95 resolved, 5 rejected => 95/100 = 95% but 5 > 4 budget.
        let mut slots = Vec::new();
        for i in 0..95 {
            slots.push(slot(i, IatSlotStatus::Resolved, None));
        }
        for i in 0..5 {
            slots.push(slot(
                95 + i,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ));
        }
        let d = evaluate_partial_accept(&report(slots));
        assert!(d.fraction_ok, "95/100 meets the fraction floor");
        assert!(!d.rejected_within_budget, "5 rejected exceeds 4");

        // 96 resolved, 4 rejected => 96/100 = 96%, within budget.
        let mut slots = Vec::new();
        for i in 0..96 {
            slots.push(slot(i, IatSlotStatus::Resolved, None));
        }
        for i in 0..4 {
            slots.push(slot(
                96 + i,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ));
        }
        let d = evaluate_partial_accept(&report(slots));
        assert!(d.fraction_ok);
        assert!(d.rejected_within_budget);

        // 94 resolved, 1 rejected => 94/95 = 98.9% >= 95%, within budget.
        let mut slots = Vec::new();
        for i in 0..94 {
            slots.push(slot(i, IatSlotStatus::Resolved, None));
        }
        slots.push(slot(
            94,
            IatSlotStatus::Unresolved,
            Some(IatUnresolvedReason::ModuleNotFound),
        ));
        let d = evaluate_partial_accept(&report(slots));
        assert!(d.fraction_ok);
        assert!(d.rejected_within_budget);

        // 1 resolved, 1 rejected => 1/2 = 50%, under the floor.
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(
                1,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ),
        ]);
        let d = evaluate_partial_accept(&r);
        assert!(!d.fraction_ok);
        assert!(d.rejected_within_budget);
    }

    #[test]
    fn structural_short_read_is_fatal_regardless_of_thresholds() {
        let mut r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(1, IatSlotStatus::Resolved, None),
        ]);
        r.bytes_read = 8; // short read
        let d = evaluate_partial_accept(&r);
        assert!(!d.strict_complete);
        assert!(
            d.structural_failures
                .iter()
                .any(|f| f.contains("short-read"))
        );
    }

    #[test]
    fn missing_reason_is_structural_fatal_not_stale() {
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(1, IatSlotStatus::Unresolved, None), // missing reason
            slot(2, IatSlotStatus::Resolved, None),
        ]);
        let d = evaluate_partial_accept(&r);
        assert!(
            d.structural_failures
                .iter()
                .any(|f| f.contains("missing unresolved_reason"))
        );
    }

    #[test]
    fn rejected_slot_does_not_poison_its_neighbors() {
        // A resolved slot adjacent to a rejected slot survives: the two-pass
        // vote already attributed it, and build_import_section_no_iat emits
        // the module run with a terminator after it.
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(1, IatSlotStatus::Resolved, None),
            slot(2, IatSlotStatus::ZeroTerminator, None),
            slot(3, IatSlotStatus::Resolved, None),
            slot(
                4,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ),
        ]);
        let d = evaluate_partial_accept(&r);
        assert_eq!(d.accepted_resolved_slots, vec![0, 1, 3]);
        assert_eq!(d.rejected_slots.len(), 1);
        assert_eq!(d.rejected_slots[0].slot_index, 4);
    }
}
