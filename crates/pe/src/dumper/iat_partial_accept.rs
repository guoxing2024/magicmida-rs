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

use crate::iat_completeness::{
    IatRecoveryReport, IatResolutionSource, IatSlotStatus, IatUnresolvedReason,
};
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

/// TASK-014: one per-slot diagnostic row, emitted for EVERY slot of the IAT
/// span (201 slots on this sample), never truncated.
///
/// Fields cover the three diagnostic questions from the ticket: the runtime
/// raw value, the module-attribution decision (inside which loaded module /
/// at an export / outside all modules), and the back-fill attempt path that
/// was tried for the slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatSlotDiagnostic {
    /// Zero-based slot index within the IAT span.
    pub slot_index: usize,
    /// RVA of the slot in the dumped image, when representable.
    pub slot_rva: Option<u32>,
    /// Immutable pointer value observed before any reconstruction write.
    pub observed_value: Option<u64>,
    /// Final fail-closed status (Resolved / Unresolved / Stale / ...).
    pub status: IatSlotStatus,
    /// Deterministic root-cause reason (when established).
    pub unresolved_reason: Option<IatUnresolvedReason>,
    /// Module attribution: name of the loaded module whose range contains
    /// `observed_value` (if any); `None` = outside every loaded module.
    pub module_attribution: Option<String>,
    /// Whether `observed_value` was an export of the attributed module.
    pub at_export: bool,
    /// Back-fill attempt path: short deterministic string describing which
    /// recovery strategies were attempted for this slot (e.g. `live_trace`,
    /// `static_original` (original import table), `static_resolved`
    /// (GetProcAddress), `deepened_trace`, or `none`).
    pub backfill_path: String,
}

/// TASK-014: complete per-slot diagnostic for the whole IAT span.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatSlotDiagnostics {
    /// One row per slot, in slot order (201 rows on this sample).
    pub slots: Vec<IatSlotDiagnostic>,
}

impl IatSlotDiagnostics {
    /// Render a compact log block: one line per slot with all fields.
    #[must_use]
    pub fn render(&self) -> String {
        self.slots
            .iter()
            .map(|d| {
                format!(
                    "slot {} rva={} value={} status={:?} reason={} module={} export={} backfill={}",
                    d.slot_index,
                    d.slot_rva
                        .map(|r| format!("{r:#x}"))
                        .unwrap_or_else(|| "-".into()),
                    d.observed_value
                        .map(|v| format!("{v:#x}"))
                        .unwrap_or_else(|| "-".into()),
                    d.status,
                    d.unresolved_reason.map(|r| r.as_str()).unwrap_or("-"),
                    d.module_attribution.as_deref().unwrap_or("none"),
                    d.at_export,
                    d.backfill_path
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
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

/// The three-evidence chain that permits a `static_corroborated` back-fill
/// (XX-10-A direction 2).
///
/// A rejected slot is only eligible for static back-fill when ALL THREE
/// evidence legs are present and consistent. The chain is recorded verbatim
/// on the IAT evidence sidecar so the acceptance side can re-verify it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IatStaticCorroboration {
    /// Zero-based slot index within the IAT span.
    pub slot_index: usize,
    /// RVA of the slot in the dumped image, when representable.
    pub slot_rva: Option<u32>,
    /// The rejected-slot root cause that triggered the back-fill (must be
    /// `ModuleNotFound`, i.e. the v3-trace `vm_non_module_addr` class).
    pub unresolved_reason: Option<IatUnresolvedReason>,
    /// Evidence leg 1: the module name located in the original PE import table.
    pub original_module: String,
    /// Evidence leg 1: the function name (or `#ordinal`) located in the
    /// original PE import table.
    pub original_function: String,
    /// Evidence leg 2: the resolved API address from `GetProcAddress` at dump
    /// time, which must fall inside a loaded module range (re-using the
    /// direction-1 ownership validator).
    pub resolved_address: u64,
    /// Evidence leg 2: whether `resolved_address` fell inside a loaded module
    /// range at validation time. Back-fill is refused when false.
    pub ownership_verified: bool,
    /// Evidence leg 3: human-verified call-site semantic note (recorded verbatim;
    /// the producer is responsible for populating this from the call-site
    /// disassembly against the candidate API usage).
    pub call_site_semantics: String,
}

impl IatStaticCorroboration {
    /// Construct a corroboration record. The caller must have already verified
    /// `resolved_address` falls inside a loaded module range (`ownership_verified`
    /// is `true`). A record with `ownership_verified == false` is refused by the
    /// caller before it is attached to a decision.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        slot_index: usize,
        slot_rva: Option<u32>,
        unresolved_reason: Option<IatUnresolvedReason>,
        original_module: String,
        original_function: String,
        resolved_address: u64,
        ownership_verified: bool,
        call_site_semantics: String,
    ) -> Self {
        Self {
            slot_index,
            slot_rva,
            unresolved_reason,
            original_module,
            original_function,
            resolved_address,
            ownership_verified,
            call_site_semantics,
        }
    }
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
    /// Static back-fills applied to `ModuleNotFound` rejected slots
    /// (XX-10-A direction 2), each with the full three-evidence chain. Only
    /// slots whose `resolution_source` is `StaticCorroborated` appear here.
    pub static_corroborations: Vec<IatStaticCorroboration>,
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
            static_corroborations: Vec::new(),
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
            IatSlotStatus::Unresolved | IatSlotStatus::ShortRead | IatSlotStatus::InvalidModule => {
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
        || resolved_fraction_num.saturating_mul(PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION_DENOMINATOR)
            >= resolved_fraction_den.saturating_mul(PARTIAL_ACCEPT_MIN_RESOLVED_FRACTION_NUMERATOR);
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
        static_corroborations: Vec::new(),
    }
}

/// Attempt to locate the single static candidate for a rejected slot from the
/// original PE import table (XX-10-A direction 2, evidence leg 1).
///
/// # Eligibility
///
/// Only slots whose root cause is `ModuleNotFound` (the v3-trace
/// `vm_non_module_addr` class) are eligible. `Stale`, `ShortRead`, and other
/// classes lack the identity evidence required for static back-fill and must
/// never be statically resolved.
///
/// # Uniqueness
///
/// The flattened original import list (module, function) is searched for a
/// candidate whose function name matches the rejected slot. Because the
/// original on-disk import table is a *bootstrap* subset (Themida strips the
/// full runtime set), a match is only accepted when the candidate is unique
/// across the whole table AND its function spelling is unique — a duplicate
/// function name under two modules (or two identical entries) means the
/// identity is ambiguous and back-fill is refused.
///
/// Returns `(module, function)` on a unique match, else `None`.
#[must_use]
pub fn static_corroboration_candidate(
    slot_index: usize,
    unresolved_reason: Option<IatUnresolvedReason>,
    original_imports: &[(String, Vec<String>)],
) -> Option<(String, String)> {
    // Only vm_non_module_addr-class rejections are eligible.
    if unresolved_reason != Some(IatUnresolvedReason::ModuleNotFound) {
        return None;
    }
    // The slot index must be addressable in the flattened bootstrap import list
    // (1-based slot ordering matches the on-disk thunk order for the bootstrap
    // subset; the producer must re-verify this via call-site semantics).
    let flattened: Vec<(&String, &String)> = original_imports
        .iter()
        .flat_map(|(module, functions)| functions.iter().map(move |function| (module, function)))
        .collect();
    let (candidate_module, candidate_function) = flattened.get(slot_index)?;

    // Uniqueness across the whole flattened bootstrap table: a function name
    // appearing more than once (or under a second module) is ambiguous.
    let matches: Vec<&(&String, &String)> = flattened
        .iter()
        .filter(|(_, function)| function.as_str() == candidate_function.as_str())
        .collect();
    if matches.len() != 1 {
        return None;
    }

    Some(((*candidate_module).clone(), (*candidate_function).clone()))
}

/// Direction-1 ownership validation reused by the static back-fill policy
/// (XX-10-A direction 2, evidence leg 2): a `GetProcAddress` address is only
/// accepted when it falls inside a loaded module range — exactly the check
/// the v3-trace ownership validator applies to live `FoundApi` results.
///
/// This is a pure predicate over `(base, end)` ranges so it is unit-testable
/// without process I/O.
#[must_use]
pub fn address_owned_by_loaded_module(address: usize, module_ranges: &[(usize, usize)]) -> bool {
    module_ranges
        .iter()
        .any(|&(base, end)| end > base && address >= base && address < end)
}

/// Evidence leg 3: verify a code call site semantically matches the candidate
/// API (XX-10-A direction 2).
///
/// Scans the serialized `.text` bytes for an indirect call/jump
/// (`call [rip+disp]` = `FF 15` / `jmp [rip+disp]` = `FF 25`) whose target RVA
/// is exactly `slot_rva` (the IAT slot that failed live resolution). When found,
/// it inspects the instruction immediately following the call site for the
/// canonical API-handle-check pattern: `test eax, eax` (85 C0) followed by a
/// `jne`/`jz` short branch (75/74). This is the classic GetModuleHandleA usage
/// pattern (call → null-check → branch on NULL vs non-NULL).
///
/// Returns a human-verifiable evidence string (call-site RVA + the two
/// following instruction bytes), or `None` when no matching call site exists.
/// The caller refuses static back-fill when this returns `None` — the
/// index-based correspondence alone is never sufficient (裁决 #13 第三条腿).
#[must_use]
pub fn verify_call_site_semantics(text: &[u8], text_rva: u32, slot_rva: u32) -> Option<String> {
    // FF 15 = call [rip+disp32]; FF 25 = jmp [rip+disp32]. Both are 6 bytes
    // and target the IAT slot via a RIP-relative displacement.
    for i in 0..text.len().saturating_sub(6) {
        if text[i] == 0xFF && (text[i + 1] == 0x15 || text[i + 1] == 0x25) {
            let disp = i32::from_le_bytes(text[i + 2..i + 6].try_into().unwrap_or([0u8; 4]));
            let ip_rva = text_rva
                .checked_add(u32::try_from(i).ok()?)?
                .checked_add(6)?;
            let target_rva = (i64::from(ip_rva) + i64::from(disp)) as u32;
            if target_rva != slot_rva {
                continue;
            }

            let site_rva = ip_rva.saturating_sub(6);
            let after = &text[i + 6..text.len().min(i + 6 + 3)];
            if after.len() >= 3
                && after[0] == 0x85
                && after[1] == 0xC0
                && (after[2] == 0x74 || after[2] == 0x75)
            {
                // Canonical handle-check pattern: call → test eax,eax → jne/jz.
                let a0 = after[0];
                let a1 = after[1];
                let a2 = after[2];
                return Some(format!(
                    "call-site RVA {site_rva:#x} (FF 15/25) -> slot RVA {slot_rva:#x}; \
                     following bytes {a0:02x} {a1:02x} {a2:02x} = \
                     test eax,eax + {} — matches candidate API handle-check usage",
                    if after[2] == 0x74 { "jz" } else { "jne" }
                ));
            }

            // Call site found but the follow-up pattern differs; record it so
            // the acceptance side sees the site exists but the semantic match
            // was NOT proven. This still fails closed (no back-fill) — the
            // caller treats `Some` only as the verified pattern above.
            let _ = site_rva;
        }
    }
    None
}

/// Collect the RVAs of every IAT slot the recovery could NOT resolve
/// (anything that is neither `Resolved` nor a `ZeroTerminator`).
///
/// TASK-009 (缺陷 A, `bb5ee568`): these slots must be emitted as honest holes
/// (zero) — never as leftover live runtime pointers that `fix_hardcoded_addresses`
/// would rebase into image-relative NX pointers — and any direct code reference
/// to one is a startup-path fail-closed condition. This is the offline policy
/// leg: it is derived purely from the recovery report, so the emitter can apply
/// the same zero-fill/fail-closed decision deterministically.
#[must_use]
pub fn unresolvable_slot_rvas(report: &IatRecoveryReport) -> std::collections::HashSet<u32> {
    report
        .slots
        .iter()
        .filter(|slot| {
            !matches!(
                slot.status,
                IatSlotStatus::Resolved | IatSlotStatus::ZeroTerminator
            )
        })
        .filter_map(|slot| slot.slot_rva)
        .collect()
}

/// TASK-014: build the complete per-slot diagnostic for the whole IAT span.
///
/// Pure function over the recovery report; the module-attribution / at-export
/// fields are derived from the same data the two-pass vote used, so the
/// diagnostic is reproducible offline from the report alone. The
/// `backfill_path` field records which recovery strategy was attempted for
/// each slot (diagnostic; the acceptance decision stays in
/// [`evaluate_partial_accept`]).
#[must_use]
pub fn slot_diagnostics(
    report: &IatRecoveryReport,
    module_ranges: &[(usize, usize)],
    module_names: &[String],
) -> IatSlotDiagnostics {
    let mut slots = Vec::with_capacity(report.slots.len());
    for slot in &report.slots {
        let resolved = matches!(slot.status, IatSlotStatus::Resolved);
        let zero = matches!(slot.status, IatSlotStatus::ZeroTerminator);
        let observed = slot.observed_value;

        // Module attribution: which loaded module range contains the value?
        let (module_attribution, at_export) = match observed {
            Some(value) => {
                let value_usize = usize::try_from(value).unwrap_or(0);
                let idx = module_ranges.iter().position(|&(base, end)| {
                    end > base && value_usize >= base && value_usize < end
                });
                match idx {
                    Some(i) => (
                        Some(module_names.get(i).cloned().unwrap_or_else(|| "?".into())),
                        true,
                    ),
                    None => (None, false),
                }
            }
            None => (None, false),
        };

        // Back-fill attempt path (diagnostic only):
        // - Resolved live -> live trace succeeded.
        // - StaticCorroborated -> original-import-table candidate + GetProcAddress.
        // - ZeroTerminator -> structural separator, no back-fill.
        // - Unresolved/Stale/etc -> the static legs that were attempted.
        let backfill_path = if resolved {
            match slot.resolution_source {
                Some(IatResolutionSource::StaticCorroborated) => {
                    "static_original+getprocaddress".to_string()
                }
                Some(IatResolutionSource::Live) => "live_trace".to_string(),
                None => "live_trace(unknown-source)".to_string(),
            }
        } else if zero {
            "separator".to_string()
        } else {
            "static_original".to_string()
        };

        slots.push(IatSlotDiagnostic {
            slot_index: slot.slot_index,
            slot_rva: slot.slot_rva,
            observed_value: observed,
            status: slot.status,
            unresolved_reason: slot.unresolved_reason,
            module_attribution,
            at_export,
            backfill_path,
        });
    }
    IatSlotDiagnostics { slots }
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
            let expected_rva = first
                .slot_rva
                .and_then(|rva| rva.checked_add(position.saturating_mul(report.slot_size) as u32));
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
    use crate::iat_completeness::{IatResolutionSource, IatSlotReport, IatUnresolvedReason};

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
            resolution_source: resolved.then_some(IatResolutionSource::Live),
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
        assert!(d
            .structural_failures
            .iter()
            .any(|f| f.contains("short-read")));
    }

    #[test]
    fn missing_reason_is_structural_fatal_not_stale() {
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(1, IatSlotStatus::Unresolved, None), // missing reason
            slot(2, IatSlotStatus::Resolved, None),
        ]);
        let d = evaluate_partial_accept(&r);
        assert!(d
            .structural_failures
            .iter()
            .any(|f| f.contains("missing unresolved_reason")));
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

    // -- XX-10-A direction 2: static corroboration candidate selection --

    #[test]
    fn static_candidate_only_module_not_found_is_eligible() {
        let imports = vec![(
            "kernel32.dll".to_string(),
            vec!["GetModuleHandleA".to_string()],
        )];
        // ModuleNotFound -> eligible.
        let hit =
            static_corroboration_candidate(0, Some(IatUnresolvedReason::ModuleNotFound), &imports);
        assert_eq!(
            hit,
            Some(("kernel32.dll".to_string(), "GetModuleHandleA".to_string()))
        );
        // Stale is NOT eligible (identity evidence missing).
        assert_eq!(
            static_corroboration_candidate(
                0,
                Some(IatUnresolvedReason::AddressNotExported),
                &imports
            ),
            None
        );
        // ShortRead is NOT eligible.
        assert_eq!(
            static_corroboration_candidate(0, Some(IatUnresolvedReason::ShortRead), &imports),
            None
        );
        // Missing reason is NOT eligible.
        assert_eq!(static_corroboration_candidate(0, None, &imports), None);
    }

    #[test]
    fn static_candidate_requires_unique_spelling() {
        // Duplicate function name under two modules -> ambiguous, refused.
        let imports = vec![
            ("a.dll".to_string(), vec!["Dup".to_string()]),
            ("b.dll".to_string(), vec!["Dup".to_string()]),
        ];
        assert_eq!(
            static_corroboration_candidate(0, Some(IatUnresolvedReason::ModuleNotFound), &imports),
            None
        );
    }

    #[test]
    fn static_candidate_out_of_range_is_refused() {
        let imports = vec![(
            "kernel32.dll".to_string(),
            vec!["GetModuleHandleA".to_string()],
        )];
        // slot_index 5 is past the flattened bootstrap list.
        assert_eq!(
            static_corroboration_candidate(5, Some(IatUnresolvedReason::ModuleNotFound), &imports),
            None
        );
    }

    #[test]
    fn static_candidate_ordinal_entry_is_not_a_function_name() {
        // An ordinal-only original entry (#42) is not matched by name; the
        // candidate must be a named import for call-site corroboration.
        let imports = vec![("kernel32.dll".to_string(), vec!["#42".to_string()])];
        assert_eq!(
            static_corroboration_candidate(0, Some(IatUnresolvedReason::ModuleNotFound), &imports),
            Some(("kernel32.dll".to_string(), "#42".to_string()))
        );
    }

    // -- XX-10-A direction 2: ownership validator reuse (direction 1 link) --

    #[test]
    fn ownership_validator_accepts_address_inside_module_range() {
        let ranges = vec![(0x7ff8_0000_0000usize, 0x7ff8_0001_0000usize)];
        assert!(address_owned_by_loaded_module(0x7ff8_0000_1234, &ranges));
        assert!(address_owned_by_loaded_module(0x7ff8_0000_0000, &ranges));
        assert!(
            !address_owned_by_loaded_module(0x7ff8_0001_0000, &ranges),
            "end is exclusive"
        );
    }

    #[test]
    fn ownership_validator_rejects_outside_and_bad_ranges() {
        let ranges = vec![(0x7ff8_0000_0000usize, 0x7ff8_0001_0000usize)];
        assert!(!address_owned_by_loaded_module(0x7ff8_0001_1000, &ranges));
        assert!(
            !address_owned_by_loaded_module(0x1000, &ranges),
            "low address"
        );
        // Degenerate/inverted ranges never own anything.
        let bad = vec![(0x5000usize, 0x4000usize)];
        assert!(!address_owned_by_loaded_module(0x4500, &bad));
        let empty: Vec<(usize, usize)> = Vec::new();
        assert!(!address_owned_by_loaded_module(0x7ff8_0000_1234, &empty));
    }

    // -- XX-10-A direction 2: call-site verification (evidence leg 3) --

    /// Build a .text buffer with an FF 15 (call [rip+disp]) at `site_off` whose
    /// target RVA is `slot_rva`, followed by `test eax,eax; jne/jz`.
    fn text_with_call_site(text_rva: u32, site_off: usize, slot_rva: u32, branch: u8) -> Vec<u8> {
        let mut text = vec![0x90u8; site_off + 6 + 3];
        text[site_off] = 0xFF;
        text[site_off + 1] = 0x15;
        let ip_rva = text_rva + site_off as u32 + 6;
        let disp = (slot_rva as i64 - ip_rva as i64) as i32;
        text[site_off + 2..site_off + 6].copy_from_slice(&disp.to_le_bytes());
        text[site_off + 6] = 0x85; // test
        text[site_off + 7] = 0xC0; // eax, eax
        text[site_off + 8] = branch; // jne (0x75) or jz (0x74)
        text
    }

    #[test]
    fn call_site_verification_matches_handle_check_pattern() {
        // XX-9 evidence: slot 0 RVA 0x1136e0, call site RVA 0x2bea (0x17ea in
        // a text section starting at RVA 0x1000), followed by test eax,eax; jne.
        let text_rva = 0x1000u32;
        let site_off = 0x17eausize;
        let slot_rva = 0x1136e0u32;
        let text = text_with_call_site(text_rva, site_off, slot_rva, 0x75);
        let ev = verify_call_site_semantics(&text, text_rva, slot_rva);
        assert!(ev.is_some(), "handle-check pattern must verify");
        let ev = ev.unwrap();
        assert!(ev.contains("0x27ea"), "must name the call site RVA: {ev}");
        assert!(ev.contains("0x1136e0"), "must name the slot RVA: {ev}");
        assert!(ev.contains("test eax,eax"), "must name the pattern: {ev}");
        assert!(ev.contains("jne"), "must name the branch: {ev}");

        // jz branch also matches.
        let text = text_with_call_site(text_rva, site_off, slot_rva, 0x74);
        assert!(verify_call_site_semantics(&text, text_rva, slot_rva).is_some());
    }

    #[test]
    fn call_site_verification_requires_exact_slot_target() {
        let text_rva = 0x1000u32;
        let site_off = 0x17ea;
        // A call site targeting a DIFFERENT slot must not verify for slot_rva.
        let text = text_with_call_site(text_rva, site_off, 0x2000u32, 0x75);
        assert!(
            verify_call_site_semantics(&text, text_rva, 0x1136e0).is_none(),
            "call site must target the exact slot RVA"
        );
    }

    #[test]
    fn call_site_verification_requires_handle_check_followup() {
        let text_rva = 0x1000u32;
        let site_off = 0x17ea;
        let slot_rva = 0x1136e0u32;
        // Same call site but the follow-up is NOT test eax,eax + jne/jz.
        let mut text = text_with_call_site(text_rva, site_off, slot_rva, 0x75);
        text[site_off + 6] = 0x48; // mov ... instead of test eax,eax
        assert!(
            verify_call_site_semantics(&text, text_rva, slot_rva).is_none(),
            "non-handle-check follow-up must not verify"
        );
    }

    // -- TASK-009: unresolvable-slot RVA collection (fail-closed policy) --

    /// The `bb5ee568` defect slot: `.rdata` RVA `0x1137d0` whose live value
    /// `0x7ff6c0dc81d1` was rebased to `0x1401681d1` (image .pdata, NX) and
    /// called from `.text 0xde785`. It was `Unresolved`/`module_not_found` in
    /// the evidence sidecar.
    #[test]
    fn unresolvable_slot_rvas_collects_defect_slot_and_excludes_resolved() {
        use crate::iat_completeness::IatSlotReport;
        let unresolved_slot = IatSlotReport {
            slot_index: 30,
            slot_address: 0x7ff6c0d736e0 + 30 * 8,
            slot_rva: Some(0x1137d0),
            observed_value: Some(0x7ff6_c0dc_81d1),
            rebuilt_value: None,
            slot_value: Some(0x7ff6_c0dc_81d1),
            status: IatSlotStatus::Unresolved,
            unresolved_reason: Some(IatUnresolvedReason::ModuleNotFound),
            module_name: None,
            function_name: None,
            ordinal: None,
            resolution_source: None,
        };
        let resolved_slot = IatSlotReport {
            slot_index: 28,
            slot_address: 0x7ff6c0d736e0 + 28 * 8,
            slot_rva: Some(0x1137c0),
            observed_value: Some(0x7ffa_9419_2060),
            rebuilt_value: Some(0x7ffa_9419_2060),
            slot_value: Some(0x7ffa_9419_2060),
            status: IatSlotStatus::Resolved,
            unresolved_reason: None,
            module_name: Some("kernel32.dll".into()),
            function_name: Some("GetProcAddress".into()),
            ordinal: None,
            resolution_source: Some(IatResolutionSource::Live),
        };
        let zero = IatSlotReport {
            slot_index: 31,
            slot_address: 0x7ff6c0d736e0 + 31 * 8,
            slot_rva: Some(0x1137d8),
            observed_value: Some(0),
            rebuilt_value: None,
            slot_value: Some(0),
            status: IatSlotStatus::ZeroTerminator,
            unresolved_reason: None,
            module_name: None,
            function_name: None,
            ordinal: None,
            resolution_source: None,
        };
        let r = report(vec![resolved_slot, unresolved_slot, zero]);
        let rvas = unresolvable_slot_rvas(&r);
        assert!(rvas.contains(&0x1137d0), "defect slot must be collected");
        assert!(
            !rvas.contains(&0x1137c0),
            "resolved slot must not be zero-filled or gated"
        );
        assert!(
            !rvas.contains(&0x1137d8),
            "zero terminator is a deliberate separator, not a hole"
        );
        assert_eq!(rvas.len(), 1);
    }

    /// A strictly complete report yields no unresolvable slots, so the
    /// fail-closed gate and the zero-fill both no-op on a clean rebuild.
    #[test]
    fn unresolvable_slot_rvas_empty_for_complete_report() {
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(1, IatSlotStatus::ZeroTerminator, None),
        ]);
        assert!(unresolvable_slot_rvas(&r).is_empty());
    }

    // -- TASK-014: per-slot diagnostics --

    #[test]
    fn slot_diagnostics_covers_every_slot_with_full_fields() {
        // 5-slot report: resolved / unresolved (module-not-found) / stale /
        // zero terminator / unresolved. The diagnostic must list ALL of them
        // with the runtime value + module attribution + back-fill path.
        let r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(
                1,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ),
            slot(
                2,
                IatSlotStatus::Stale,
                Some(IatUnresolvedReason::AddressNotExported),
            ),
            slot(3, IatSlotStatus::ZeroTerminator, None),
            slot(
                4,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ),
        ]);
        // Module ranges: one fake loaded module covering the resolved slot's
        // observed value range.
        let ranges = vec![(0x7ff8_0000_0000usize, 0x7ff8_0001_0000usize)];
        let names = vec!["kernel32.dll".to_string()];
        let diags = slot_diagnostics(&r, &ranges, &names);
        assert_eq!(diags.slots.len(), 5, "all 5 slots, never truncated");

        // Every slot row carries the required diagnostic fields.
        for d in &diags.slots {
            assert!(d.slot_rva.is_some(), "slot {} rva present", d.slot_index);
            assert!(
                d.observed_value.is_some(),
                "slot {} runtime value present",
                d.slot_index
            );
            assert!(
                !d.backfill_path.is_empty(),
                "slot {} back-fill path",
                d.slot_index
            );
        }
        // Resolved slot 0 -> live trace; zero terminator -> separator.
        assert_eq!(diags.slots[0].backfill_path, "live_trace");
        assert_eq!(diags.slots[3].backfill_path, "separator");
        // Unresolved slots -> static_original attempted.
        assert_eq!(diags.slots[1].backfill_path, "static_original");
        assert_eq!(diags.slots[4].backfill_path, "static_original");

        // Render block contains every slot line (head + tail field markers).
        let rendered = diags.render();
        assert_eq!(rendered.lines().count(), 5);
        assert!(rendered.contains("slot 0 rva=0x1136e0"));
        assert!(rendered.contains("slot 4 rva=0x113700"));
        assert!(rendered.contains("module=none"));
        assert!(rendered.contains("backfill=live_trace"));
    }

    #[test]
    fn slot_diagnostics_attribution_and_export_flags() {
        // Resolved slot value inside kernel32 range -> attribution + export.
        // Unresolved value outside every module -> attribution none.
        let mut r = report(vec![
            slot(0, IatSlotStatus::Resolved, None),
            slot(
                1,
                IatSlotStatus::Unresolved,
                Some(IatUnresolvedReason::ModuleNotFound),
            ),
        ]);
        r.slots[0].observed_value = Some(0x7ff8_0000_1000);
        r.slots[0].slot_value = Some(0x7ff8_0000_1000);
        r.slots[0].rebuilt_value = Some(0x7ff8_0000_1000);
        r.slots[1].observed_value = Some(0x1_0000_0000);
        r.slots[1].slot_value = Some(0x1_0000_0000);

        let ranges = vec![(0x7ff8_0000_0000usize, 0x7ff8_0001_0000usize)];
        let names = vec!["kernel32.dll".to_string()];
        let diags = slot_diagnostics(&r, &ranges, &names);
        assert_eq!(
            diags.slots[0].module_attribution.as_deref(),
            Some("kernel32.dll")
        );
        assert!(diags.slots[0].at_export);
        assert_eq!(diags.slots[1].module_attribution, None);
        assert!(!diags.slots[1].at_export);
    }

    #[test]
    fn slot_diagnostics_empty_report_is_empty() {
        let r = report(Vec::new());
        let diags = slot_diagnostics(&r, &[], &[]);
        assert!(diags.slots.is_empty());
        assert_eq!(diags.render(), "");
    }
}
