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
    /// Module selected for a resolved slot, when available.
    pub module_name: Option<String>,
    /// Export name selected for a resolved slot, when available.
    pub function_name: Option<String>,
    /// Export ordinal selected for an ordinal-only resolved slot.
    pub ordinal: Option<u16>,
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
            module_name: resolved.then(|| "kernel32.dll".into()),
            function_name: resolved.then(|| "CreateFileW".into()),
            ordinal: None,
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
}
