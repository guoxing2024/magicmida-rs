//! Fail-closed completeness reporting for live IAT recovery.
//!
//! A percentage is not a completeness proof: a single stale or short-read slot
//! is enough to make a recovery unusable for the two-sample perfect gate.  This
//! module keeps an auditable record for every slot and makes completeness a
//! strict predicate over the recorded states.

use std::collections::HashSet;

/// Per-slot result of IAT recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IatSlotStatus {
    /// The slot was read completely and matched a current module export.
    Resolved,
    /// The slot points inside a currently loaded module, but not at a current
    /// exported address.  This is commonly a stale dump/runtime pointer.
    Stale,
    /// The slot was read completely, but no loaded module/export could resolve
    /// it.
    Unresolved,
    /// The slot bytes were not fully returned by the memory read.
    ShortRead,
    /// The slot or its chosen candidate referenced malformed/missing module
    /// metadata.
    InvalidModule,
    /// Zero slot used as an import-group separator, not a thunk.
    ZeroTerminator,
}

/// Provenance of a resolved IAT slot's address.
///
/// XX-10-A direction 2: a slot resolved by live trace/export matching is
/// `Live`; a slot whose address was back-filled from the original PE's import
/// table (with the three-evidence corroboration chain) is
/// `StaticCorroborated`. The distinction is recorded on the IAT evidence
/// sidecar so the acceptance side can see exactly which slots were second-
/// sourced rather than observed live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IatResolutionSource {
    /// Address observed from the live IAT / trace (the normal path).
    Live,
    /// Address back-filled from the original PE import table via
    /// `GetProcAddress`, after the three-evidence corroboration chain.
    StaticCorroborated,
}

impl IatResolutionSource {
    /// Stable lowercase machine identifier for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::StaticCorroborated => "static_corroborated",
        }
    }
}

/// Deterministic reason a non-resolved IAT slot failed to resolve.
///
/// This is an auditable root-cause classification, not a pass signal.  Every
/// non-`Resolved` slot keeps exactly one of these reasons (when it can be
/// established deterministically) so the 1423-style "Unresolved" counts can be
/// decomposed into verifiable buckets instead of being collapsed into one
/// opaque number.
///
/// `unknown` is a first-class variant and MUST remain a fail-closed blocker —
/// it is never silently merged into another bucket.  Reasons that can only be
/// established from a live run (`trace_abort`, `timeout`, and any memory-fault
/// dependent classification) are never fabricated from static bytes; when such
/// a slot is reconstructed offline and its root cause cannot be proven, the
/// slot's reason stays `None` and the report records it as pending live
/// confirmation (see [`IatSlotReport::unresolved_reason`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IatUnresolvedReason {
    /// The slot memory could not be read at all (read error, not a short span).
    MemoryRead,
    /// The IAT span read returned fewer bytes than requested, so later slots
    /// are unreliable.
    ShortRead,
    /// The slot or its candidate referenced malformed/missing module metadata.
    InvalidModule,
    /// The observed value points outside every loaded module's range.
    ModuleNotFound,
    /// The observed value is inside a loaded module but not at an exported
    /// address (e.g. inside a module at a non-export).
    AddressNotExported,
    /// A candidate module was found but the export name could not be resolved.
    NameResolution,
    /// A candidate module was found but the export ordinal could not be
    /// resolved.
    OrdinalResolution,
    /// The observed value is inside a loaded module at a currently
    /// non-exported (relocated/unmapped) address — a stale pointer.
    Stale,
    /// The live trace aborted before this slot's resolution completed.
    TraceAbort,
    /// The live resolution exceeded its time budget.
    Timeout,
    /// The reason could not be determined.  Always fail-closed.
    Unknown,
}

impl IatUnresolvedReason {
    /// Whether this reason can only be established from a live run.  When a
    /// slot is reconstructed offline with one of these reasons absent, it must
    /// be marked pending live confirmation rather than fabricated.
    #[must_use]
    pub const fn requires_live_run(self) -> bool {
        matches!(self, Self::TraceAbort | Self::Timeout)
    }

    /// Stable lowercase machine identifier for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryRead => "memory_read",
            Self::ShortRead => "short_read",
            Self::InvalidModule => "invalid_module",
            Self::ModuleNotFound => "module_not_found",
            Self::AddressNotExported => "address_not_exported",
            Self::NameResolution => "name_resolution",
            Self::OrdinalResolution => "ordinal_resolution",
            Self::Stale => "stale",
            Self::TraceAbort => "trace_abort",
            Self::Timeout => "timeout",
            Self::Unknown => "unknown",
        }
    }
}

impl core::fmt::Display for IatUnresolvedReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl IatSlotStatus {
    /// Whether this status is a successful thunk resolution.
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::Resolved)
    }
}

/// Auditable result for one IAT slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatSlotReport {
    /// Zero-based slot index within the requested IAT span.
    pub slot_index: usize,
    /// Absolute address of the slot in the target process.
    pub slot_address: u64,
    /// RVA of the slot in the dumped image, when it can be represented.
    pub slot_rva: Option<u32>,
    /// Immutable pointer value observed before any reconstruction write.
    pub observed_value: Option<u64>,
    /// Final pointer value selected for the rebuilt IAT, if one was written.
    pub rebuilt_value: Option<u64>,
    /// Compatibility alias for older consumers.  It is always the same value
    /// as [`Self::observed_value`] and is never read from the rewritten buffer.
    pub slot_value: Option<u64>,
    /// Final fail-closed status.
    pub status: IatSlotStatus,
    /// Deterministic root-cause reason for a non-`Resolved` slot, when it can
    /// be established.  `None` on a non-`Resolved` slot means the reason is not
    /// deterministically provable and the slot is marked pending live
    /// confirmation; it is never silently assigned a fabricated reason.
    pub unresolved_reason: Option<IatUnresolvedReason>,
    /// Module selected for a resolved slot, when available.
    pub module_name: Option<String>,
    /// Export name selected for a resolved slot, when available.
    pub function_name: Option<String>,
    /// Export ordinal selected for an ordinal-only resolved slot.
    pub ordinal: Option<u16>,
    /// Provenance of a resolved slot's address. `None` for non-resolved slots
    /// (or for callers that predate the field); `Some(Live)` for live-observed
    /// resolutions, `Some(StaticCorroborated)` for back-filled resolutions
    /// (XX-10-A direction 2).
    pub resolution_source: Option<IatResolutionSource>,
}

/// Complete IAT recovery report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatRecoveryReport {
    /// Requested number of bytes in the IAT span.
    pub requested_bytes: usize,
    /// Bytes actually returned by the read used for reconstruction.
    pub bytes_read: usize,
    /// Pointer size used to split the IAT into slots.
    pub slot_size: usize,
    /// One entry for every slot in the requested span.
    pub slots: Vec<IatSlotReport>,
}

impl IatRecoveryReport {
    /// Construct an empty report for a requested IAT span.
    #[must_use]
    pub fn new(requested_bytes: usize, bytes_read: usize, slot_size: usize) -> Self {
        Self {
            requested_bytes,
            bytes_read,
            slot_size,
            slots: Vec::new(),
        }
    }

    /// Strict completeness predicate used by the perfect-prerequisite gate.
    ///
    /// No percentage or threshold is involved.  The memory read must be exact,
    /// the IAT span must be pointer-aligned, every slot must be present exactly
    /// once and in order, zero separators must be explicit non-thunks, every
    /// non-zero slot must be a resolved thunk, and at least one resolved thunk
    /// must exist.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.validation_reasons().is_empty()
    }

    /// Count slots by exact state.  This is diagnostic only; callers must use
    /// [`Self::is_complete`] for gating.
    #[must_use]
    pub fn count_status(&self, status: IatSlotStatus) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.status == status)
            .count()
    }

    /// Stable per-reason count over every non-`Resolved` slot that carries a
    /// deterministic [`IatUnresolvedReason`].
    ///
    /// The result is ordered by the enum's `Ord` to guarantee a stable, keyed
    /// output.  Slots with a missing reason are not folded into `unknown`;
    /// they are counted separately via [`Self::pending_live_confirmation`].
    #[must_use]
    pub fn count_unresolved_by_reason(
        &self,
    ) -> std::collections::BTreeMap<IatUnresolvedReason, usize> {
        let mut counts = std::collections::BTreeMap::new();
        for slot in &self.slots {
            if slot.status == IatSlotStatus::Resolved
                || slot.status == IatSlotStatus::ZeroTerminator
            {
                continue;
            }
            if let Some(reason) = slot.unresolved_reason {
                *counts.entry(reason).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Number of non-`Resolved`, non-`ZeroTerminator` slots whose reason could
    /// not be established deterministically.  These require a live run to
    /// confirm; they are never fabricated or folded into `unknown`.
    #[must_use]
    pub fn pending_live_confirmation(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| {
                !matches!(
                    slot.status,
                    IatSlotStatus::Resolved | IatSlotStatus::ZeroTerminator
                ) && slot.unresolved_reason.is_none()
            })
            .count()
    }

    /// Return a compact, deterministic reason suitable for a fail-closed
    /// error/log message.
    #[must_use]
    pub fn failure_summary(&self) -> String {
        let reasons = self.validation_reasons();
        if reasons.is_empty() {
            "complete".into()
        } else {
            reasons.join(", ")
        }
    }

    fn validation_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        let aligned = self.slot_size != 0 && self.requested_bytes % self.slot_size == 0;
        if !aligned {
            reasons.push("unaligned IAT span".into());
        }

        let expected_slots = if aligned {
            self.requested_bytes / self.slot_size
        } else {
            0
        };
        if self.bytes_read != self.requested_bytes {
            reasons.push(format!(
                "short-read {}/{} bytes",
                self.bytes_read, self.requested_bytes
            ));
        }
        if self.slots.len() != expected_slots {
            reasons.push(format!(
                "incomplete slot coverage {}/{} slots",
                self.slots.len(),
                expected_slots
            ));
        }

        let mut indices = HashSet::new();
        let mut addresses = HashSet::new();
        let mut rvas = HashSet::new();
        let mut resolved_count = 0usize;
        let mut duplicate_index = false;
        let mut duplicate_address = false;
        let mut duplicate_rva = false;
        let mut coverage_mismatch = false;
        let mut observed_mismatch = false;
        let mut rebuilt_identity_mismatch = false;
        let mut invalid_slot_metadata = false;

        for (position, slot) in self.slots.iter().enumerate() {
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
            if let Some(first) = self.slots.first() {
                let expected_address = first
                    .slot_address
                    .checked_add(position.saturating_mul(self.slot_size) as u64);
                let expected_rva = first.slot_rva.and_then(|rva| {
                    rva.checked_add(position.saturating_mul(self.slot_size) as u32)
                });
                if expected_address != Some(slot.slot_address) || expected_rva != slot.slot_rva {
                    coverage_mismatch = true;
                }
            }
            if slot.slot_value != slot.observed_value {
                observed_mismatch = true;
            }

            match slot.status {
                IatSlotStatus::Resolved => {
                    resolved_count += 1;
                    let has_name = slot
                        .function_name
                        .as_ref()
                        .is_some_and(|name| !name.is_empty());
                    let has_ordinal = slot.ordinal.is_some();
                    if slot.observed_value.is_none_or(|value| value == 0)
                        || slot.rebuilt_value.is_none_or(|value| value == 0)
                        || slot.module_name.as_ref().is_none_or(|name| name.is_empty())
                        || has_name == has_ordinal
                    {
                        rebuilt_identity_mismatch = true;
                    }
                }
                IatSlotStatus::ZeroTerminator => {
                    if slot.observed_value != Some(0)
                        || slot.rebuilt_value.is_some()
                        || slot.module_name.is_some()
                        || slot.function_name.is_some()
                        || slot.ordinal.is_some()
                    {
                        rebuilt_identity_mismatch = true;
                    }
                }
                IatSlotStatus::Stale
                | IatSlotStatus::Unresolved
                | IatSlotStatus::ShortRead
                | IatSlotStatus::InvalidModule => {
                    if slot.rebuilt_value.is_some() {
                        rebuilt_identity_mismatch = true;
                    }
                    // A deterministic reason is required for fail-closed
                    // auditing of any non-resolved slot; a missing reason is
                    // pending live confirmation and keeps the report
                    // incomplete.  `unknown` must never be silently accepted.
                    if slot.unresolved_reason.is_none() {
                        reasons.push(format!(
                            "slot {} missing unresolved_reason (pending live confirmation)",
                            slot.slot_index
                        ));
                    }
                }
            }
        }

        if duplicate_index {
            reasons.push("duplicate slot_index".into());
        }
        if duplicate_address {
            reasons.push("duplicate slot_address".into());
        }
        if duplicate_rva {
            reasons.push("duplicate slot_rva".into());
        }
        if coverage_mismatch {
            reasons.push("slot coverage mismatch".into());
        }
        if invalid_slot_metadata {
            reasons.push("missing slot_rva".into());
        }
        if observed_mismatch {
            reasons.push("observed value alias mismatch".into());
        }
        if rebuilt_identity_mismatch {
            reasons.push("inconsistent rebuilt identity".into());
        }

        for status in [
            IatSlotStatus::Stale,
            IatSlotStatus::Unresolved,
            IatSlotStatus::ShortRead,
            IatSlotStatus::InvalidModule,
        ] {
            let count = self.count_status(status);
            if count != 0 {
                reasons.push(format!("{status:?}={count}"));
            }
        }
        if resolved_count == 0 {
            reasons.push("no resolved thunk slots".into());
        }
        reasons
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slot(index: usize, status: IatSlotStatus) -> IatSlotReport {
        let observed = if status == IatSlotStatus::ZeroTerminator {
            Some(0)
        } else {
            Some(0x1800 + index as u64)
        };
        let resolved = status == IatSlotStatus::Resolved;
        IatSlotReport {
            slot_index: index,
            slot_address: 0x1400 + (index as u64 * 8),
            slot_rva: Some(0x400 + (index as u32 * 8)),
            observed_value: observed,
            rebuilt_value: resolved.then_some(0x2800 + index as u64),
            slot_value: observed,
            status,
            unresolved_reason: match status {
                IatSlotStatus::Resolved | IatSlotStatus::ZeroTerminator => None,
                IatSlotStatus::Stale => Some(IatUnresolvedReason::AddressNotExported),
                IatSlotStatus::Unresolved => Some(IatUnresolvedReason::ModuleNotFound),
                IatSlotStatus::ShortRead => Some(IatUnresolvedReason::ShortRead),
                IatSlotStatus::InvalidModule => Some(IatUnresolvedReason::InvalidModule),
            },
            module_name: resolved.then(|| "kernel32.dll".into()),
            function_name: resolved.then(|| "CreateFileW".into()),
            ordinal: None,
            resolution_source: resolved.then_some(IatResolutionSource::Live),
        }
    }

    #[test]
    fn incomplete_statuses_fail_closed_even_with_high_resolution_count() {
        for bad in [
            IatSlotStatus::Stale,
            IatSlotStatus::Unresolved,
            IatSlotStatus::ShortRead,
            IatSlotStatus::InvalidModule,
        ] {
            let mut report = IatRecoveryReport::new(16, 16, 8);
            report.slots = vec![slot(0, IatSlotStatus::Resolved), slot(1, bad)];
            assert!(!report.is_complete(), "{bad:?} must fail closed");
        }
    }

    #[test]
    fn missing_slot_fails_closed_even_when_bytes_read_is_exact() {
        let mut report = IatRecoveryReport::new(16, 16, 8);
        report.slots = vec![slot(0, IatSlotStatus::Resolved)];
        assert!(!report.is_complete());
    }

    #[test]
    fn zero_terminator_is_not_a_thunk_failure() {
        let mut report = IatRecoveryReport::new(16, 16, 8);
        report.slots = vec![
            slot(0, IatSlotStatus::Resolved),
            slot(1, IatSlotStatus::ZeroTerminator),
        ];
        assert!(report.is_complete());
        assert_eq!(report.count_status(IatSlotStatus::Resolved), 1);
    }

    #[test]
    fn duplicate_slot_metadata_fails_but_duplicate_api_identity_does_not() {
        let mut report = IatRecoveryReport::new(16, 16, 8);
        report.slots = vec![
            slot(0, IatSlotStatus::Resolved),
            slot(1, IatSlotStatus::Resolved),
        ];
        report.slots[1].function_name = report.slots[0].function_name.clone();
        assert!(report.is_complete(), "same API in distinct slots is valid");

        report.slots[1].slot_rva = report.slots[0].slot_rva;
        assert!(!report.is_complete());
        assert!(report.failure_summary().contains("duplicate slot_rva"));
    }

    #[test]
    fn bad_rebuilt_identity_and_observed_alias_fail_closed() {
        let mut report = IatRecoveryReport::new(8, 8, 8);
        report.slots = vec![slot(0, IatSlotStatus::Resolved)];
        report.slots[0].slot_value = Some(0xdead);
        assert!(!report.is_complete());
        assert!(report
            .failure_summary()
            .contains("observed value alias mismatch"));

        report.slots[0].slot_value = report.slots[0].observed_value;
        report.slots[0].rebuilt_value = None;
        assert!(!report.is_complete());
        assert!(report
            .failure_summary()
            .contains("inconsistent rebuilt identity"));
    }

    #[test]
    fn every_bad_status_is_fail_closed() {
        for status in [
            IatSlotStatus::Stale,
            IatSlotStatus::Unresolved,
            IatSlotStatus::ShortRead,
            IatSlotStatus::InvalidModule,
        ] {
            let mut report = IatRecoveryReport::new(8, 8, 8);
            report.slots = vec![slot(0, status)];
            assert!(!report.is_complete(), "{status:?}");
        }
    }

    #[test]
    fn ordinal_is_first_class_and_zero_separator_is_not_resolved() {
        let mut report = IatRecoveryReport::new(16, 16, 8);
        let mut ordinal_slot = slot(0, IatSlotStatus::Resolved);
        ordinal_slot.function_name = None;
        ordinal_slot.ordinal = Some(42);
        report.slots = vec![ordinal_slot, slot(1, IatSlotStatus::ZeroTerminator)];
        assert!(report.is_complete());
        assert_eq!(report.slots[0].ordinal, Some(42));
        assert_eq!(report.count_status(IatSlotStatus::Resolved), 1);
    }

    // --- P8.1-A: deterministic unresolved reason classification ---

    fn slot_with_reason(
        index: usize,
        status: IatSlotStatus,
        reason: Option<IatUnresolvedReason>,
    ) -> IatSlotReport {
        let mut s = slot(index, status);
        s.unresolved_reason = reason;
        s
    }

    #[test]
    fn reason_as_str_is_stable_and_round_trips() {
        for (reason, expected) in [
            (IatUnresolvedReason::MemoryRead, "memory_read"),
            (IatUnresolvedReason::ShortRead, "short_read"),
            (IatUnresolvedReason::InvalidModule, "invalid_module"),
            (IatUnresolvedReason::ModuleNotFound, "module_not_found"),
            (
                IatUnresolvedReason::AddressNotExported,
                "address_not_exported",
            ),
            (IatUnresolvedReason::NameResolution, "name_resolution"),
            (IatUnresolvedReason::OrdinalResolution, "ordinal_resolution"),
            (IatUnresolvedReason::Stale, "stale"),
            (IatUnresolvedReason::TraceAbort, "trace_abort"),
            (IatUnresolvedReason::Timeout, "timeout"),
            (IatUnresolvedReason::Unknown, "unknown"),
        ] {
            assert_eq!(reason.as_str(), expected, "{reason:?}");
            assert_eq!(format!("{reason}"), expected, "{reason:?}");
        }
    }

    #[test]
    fn live_only_reasons_are_flag_enumerated() {
        assert!(IatUnresolvedReason::TraceAbort.requires_live_run());
        assert!(IatUnresolvedReason::Timeout.requires_live_run());
        for reason in [
            IatUnresolvedReason::MemoryRead,
            IatUnresolvedReason::ShortRead,
            IatUnresolvedReason::InvalidModule,
            IatUnresolvedReason::ModuleNotFound,
            IatUnresolvedReason::AddressNotExported,
            IatUnresolvedReason::NameResolution,
            IatUnresolvedReason::OrdinalResolution,
            IatUnresolvedReason::Stale,
            IatUnresolvedReason::Unknown,
        ] {
            assert!(!reason.requires_live_run(), "{reason:?}");
        }
    }

    #[test]
    fn reason_counts_are_stable_and_unknown_is_never_folded() {
        let mut report = IatRecoveryReport::new(40, 40, 8);
        report.slots = vec![
            slot_with_reason(0, IatSlotStatus::Resolved, None),
            slot_with_reason(
                1,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ),
            slot_with_reason(
                2,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ),
            slot_with_reason(
                3,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::Unknown),
            ),
            slot_with_reason(4, IatSlotStatus::ZeroTerminator, None),
        ];
        let counts = report.count_unresolved_by_reason();
        assert_eq!(counts.get(&IatUnresolvedReason::ModuleNotFound), Some(&2));
        assert_eq!(counts.get(&IatUnresolvedReason::Unknown), Some(&1));
        assert_eq!(counts.len(), 2, "unknown must stay its own bucket");
        assert_eq!(report.pending_live_confirmation(), 0);
        assert!(!report.is_complete(), "unknown reason must fail closed");
    }

    #[test]
    fn pending_live_confirmation_is_separate_from_unknown() {
        let mut report = IatRecoveryReport::new(24, 24, 8);
        report.slots = vec![
            slot_with_reason(0, IatSlotStatus::Resolved, None),
            slot_with_reason(1, IatSlotStatus::Unresolved, None),
            slot_with_reason(2, IatSlotStatus::ShortRead, None),
        ];
        assert_eq!(report.pending_live_confirmation(), 2);
        assert!(report.count_unresolved_by_reason().is_empty());
        assert!(
            !report.is_complete(),
            "pending live confirmation must fail closed"
        );
        assert!(
            report
                .failure_summary()
                .contains("pending live confirmation"),
            "failure summary must name pending live confirmation, got: {}",
            report.failure_summary()
        );
    }

    #[test]
    fn missing_reason_is_never_reported_as_unknown() {
        // The `unknown` reason is only assignable when explicitly classified;
        // a missing reason is pending live confirmation and must not be folded
        // into the unknown bucket or counted as a known reason.
        let mut report = IatRecoveryReport::new(16, 16, 8);
        report.slots = vec![
            slot_with_reason(0, IatSlotStatus::Resolved, None),
            slot_with_reason(1, IatSlotStatus::Unresolved, None),
        ];
        assert_eq!(report.pending_live_confirmation(), 1);
        assert!(!report
            .count_unresolved_by_reason()
            .contains_key(&IatUnresolvedReason::Unknown));
    }

    #[test]
    fn every_specific_reason_must_be_diagnosable() {
        // The eleven required reason buckets must all be reachable so the
        // classifier can emit them deterministically rather than collapsing
        // everything into `Unresolved`.
        let mut report = IatRecoveryReport::new(11 * 8, 11 * 8, 8);
        let reasons = [
            IatUnresolvedReason::MemoryRead,
            IatUnresolvedReason::ShortRead,
            IatUnresolvedReason::InvalidModule,
            IatUnresolvedReason::ModuleNotFound,
            IatUnresolvedReason::AddressNotExported,
            IatUnresolvedReason::NameResolution,
            IatUnresolvedReason::OrdinalResolution,
            IatUnresolvedReason::Stale,
            IatUnresolvedReason::TraceAbort,
            IatUnresolvedReason::Timeout,
            IatUnresolvedReason::Unknown,
        ];
        for (i, reason) in reasons.iter().enumerate() {
            let status = if *reason == IatUnresolvedReason::ShortRead {
                IatSlotStatus::ShortRead
            } else if *reason == IatUnresolvedReason::InvalidModule {
                IatSlotStatus::InvalidModule
            } else if *reason == IatUnresolvedReason::AddressNotExported {
                IatSlotStatus::Stale
            } else {
                IatSlotStatus::Unresolved
            };
            report
                .slots
                .push(slot_with_reason(i, status, Some(*reason)));
        }
        let counts = report.count_unresolved_by_reason();
        assert_eq!(
            counts.len(),
            11,
            "all eleven reason buckets must be present"
        );
        assert!(!report.is_complete(), "unresolved slots always fail closed");
    }
}
