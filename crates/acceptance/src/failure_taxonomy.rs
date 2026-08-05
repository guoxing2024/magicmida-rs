//! P8-A: stable failure taxonomy for the v8 two-sample gate report.
//!
//! The v8 gate emits a `Vec<String>` of human-readable failures per sample.
//! P7-R2 showed these span nine conceptual classes. This module classifies
//! each failure into exactly one stable bucket so that producer/gate gaps can
//! be tracked across revisions without depending on the prose order or exact
//! wording of a given message.
//!
//! Classification is deterministic and order-independent: the same string
//! always maps to the same bucket. Unknown / unrecognized failures are
//! surfaced as [`TaxonomyBucket::Other`] and never silently dropped, so a new
//! gate message is visible to the audit instead of being folded into an
//! existing class.
//!
//! The classification here is intentionally conservative and lexical. It does
//! not re-derive any gate decision; it only buckets already-emitted failure
//! text. Negative tests cover order independence, repeated failures, unknown
//! failures, and missing fields.

use std::collections::BTreeMap;

/// Stable, order-independent buckets for one v8 gate sample's failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaxonomyBucket {
    /// `prerequisite failed: process survival` / `structural PE acceptance`.
    PrerequisiteSurvivalStructural,
    /// Structured PE evidence gaps (PE32+ identity / directory consistency).
    StructuredPe,
    /// Structured OEP evidence gaps.
    Oep,
    /// Structured IAT evidence gaps: a slot is `Unresolved` / not resolved.
    IatUnresolved,
    /// Structured IAT evidence gaps: resolved slot / final-import mapping.
    IatFinalImportMapping,
    /// Structured TLS evidence gaps.
    Tls,
    /// Structured relocation / ASLR evidence gaps.
    Relocation,
    /// Structured section-rebuild evidence gaps.
    SectionRebuild,
    /// Behavior-oracle gaps (no stimuli / observables / NotRun).
    Behavior,
    /// Isolated-replay gaps (attempt count / reproducibility).
    IsolatedReplay,
    /// Anything not matching a known bucket.
    Other,
}

impl TaxonomyBucket {
    /// Human-readable stable label (used in reports and tests).
    pub fn label(self) -> &'static str {
        match self {
            Self::PrerequisiteSurvivalStructural => "prerequisite/survival/structural",
            Self::StructuredPe => "structured-pe",
            Self::Oep => "oep",
            Self::IatUnresolved => "iat-unresolved",
            Self::IatFinalImportMapping => "iat-final-import-mapping",
            Self::Tls => "tls",
            Self::Relocation => "relocation",
            Self::SectionRebuild => "section-rebuild",
            Self::Behavior => "behavior",
            Self::IsolatedReplay => "isolated-replay",
            Self::Other => "other",
        }
    }
}

/// Classify one failure string into exactly one bucket.
pub fn classify(failure: &str) -> TaxonomyBucket {
    let f = failure.trim();
    // Behavior / replay first (they carry distinctive tokens and must not be
    // absorbed by a generic "prerequisite failed" prefix).
    if f.contains("behavior")
        && (f.contains("stimuli") || f.contains("observables") || f.contains("NotRun"))
    {
        return TaxonomyBucket::Behavior;
    }
    if f.contains("isolated replay") {
        return TaxonomyBucket::IsolatedReplay;
    }

    // OEP-specific tokens (checked before generic prerequisite because OEP
    // failures may appear with or without the "prerequisite failed:" prefix).
    if f.contains("OEP evidence") || f.contains("oep evidence") || f.contains("OEP provenance") {
        if f.contains("Unresolved") && f.contains("IAT") {
            // IAT unresolved wins over OEP only when the string names both and
            // the operative clause is about an IAT slot. OEP evidence strings
            // do not name IAT slots, so this is a guard only.
        }
        if f.contains("slot") && f.contains("Unresolved") {
            return TaxonomyBucket::IatUnresolved;
        }
        return TaxonomyBucket::Oep;
    }

    // Structured IAT: split unresolved vs final-import mapping.
    if f.contains("IAT evidence") || f.contains("iat evidence") {
        if f.contains("Unresolved") {
            return TaxonomyBucket::IatUnresolved;
        }
        if f.contains("final import")
            || f.contains("final_import")
            || f.contains("resolved slot")
            || f.contains("mapping")
            || f.contains("one-to-one")
        {
            return TaxonomyBucket::IatFinalImportMapping;
        }
        return TaxonomyBucket::IatFinalImportMapping;
    }

    if f.contains("TLS evidence") || f.contains("tls evidence") || f.contains("TLS directory") {
        return TaxonomyBucket::Tls;
    }

    // Relocation: must be checked before generic "prerequisite" and before
    // anything that would swallow DYNAMIC_BASE / ASLR.
    if f.contains("relocation") || f.contains("DYNAMIC_BASE") || f.contains("ASLR") {
        return TaxonomyBucket::Relocation;
    }

    // Section rebuild.
    if f.contains("section rebuild") || f.contains("section_rebuild") {
        return TaxonomyBucket::SectionRebuild;
    }

    // Structured PE evidence.
    if f.contains("PE evidence") || f.contains("pe_evidence") || f.contains("PE32+") {
        return TaxonomyBucket::StructuredPe;
    }

    // Prerequisite survival / structural.
    if f.starts_with("prerequisite failed: process survival")
        || f.starts_with("prerequisite failed: structural PE")
        || f.contains("survival evidence")
        || f.contains("structural evidence")
        || f.contains("process survival")
        || f.contains("structural PE acceptance")
    {
        return TaxonomyBucket::PrerequisiteSurvivalStructural;
    }

    TaxonomyBucket::Other
}

/// Count failures per bucket for one sample's failure list.
pub fn summarize(failures: &[String]) -> BTreeMap<TaxonomyBucket, usize> {
    let mut counts: BTreeMap<TaxonomyBucket, usize> = BTreeMap::new();
    for failure in failures {
        *counts.entry(classify(failure)).or_insert(0) += 1;
    }
    counts
}

/// Total number of failures across all buckets.
pub fn total(counts: &BTreeMap<TaxonomyBucket, usize>) -> usize {
    counts.values().sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(value: &str) -> String {
        value.to_string()
    }

    #[test]
    fn classifies_each_p7r2_observed_failure_bucket() {
        assert_eq!(
            classify("prerequisite failed: process survival"),
            TaxonomyBucket::PrerequisiteSurvivalStructural
        );
        assert_eq!(
            classify("prerequisite failed: structural PE acceptance"),
            TaxonomyBucket::PrerequisiteSurvivalStructural
        );
        assert_eq!(classify("prerequisite failed: structured OEP evidence: source Unknown is not runtime_rip or trace"), TaxonomyBucket::Oep);
        assert_eq!(
            classify("prerequisite failed: structured OEP evidence: VA is missing"),
            TaxonomyBucket::Oep
        );
        assert_eq!(
            classify(
                "prerequisite failed: structured OEP evidence: RVA does not match final_entry_rva"
            ),
            TaxonomyBucket::Oep
        );
        assert_eq!(classify("prerequisite failed: structured IAT evidence: structured IAT report: Unresolved status at slot 1"), TaxonomyBucket::IatUnresolved);
        assert_eq!(
            classify("prerequisite failed: structured IAT evidence: final imports are empty"),
            TaxonomyBucket::IatFinalImportMapping
        );
        assert_eq!(classify("prerequisite failed: structured IAT evidence: resolved slot RVA 0x138a88 does not map to exactly one final import"), TaxonomyBucket::IatFinalImportMapping);
        assert_eq!(classify("prerequisite failed: structured IAT evidence: resolved/final import count mismatch 296/0"), TaxonomyBucket::IatFinalImportMapping);
        assert_eq!(
            classify(
                "prerequisite failed: structured TLS evidence: callback ordering is not preserved"
            ),
            TaxonomyBucket::Tls
        );
        assert_eq!(classify("prerequisite failed: structured relocation evidence: final relocation DYNAMIC_BASE is not set"), TaxonomyBucket::Relocation);
        assert_eq!(classify("prerequisite failed: structured relocation evidence: runtime relocation image identity disagrees with PE evidence"), TaxonomyBucket::Relocation);
        assert_eq!(classify("prerequisite failed: structured section rebuild evidence: absent directory 4 has non-canonical coverage"), TaxonomyBucket::SectionRebuild);
        assert_eq!(
            classify(
                "prerequisite failed: structured section rebuild evidence: duplicate section name"
            ),
            TaxonomyBucket::SectionRebuild
        );
        assert_eq!(
            classify("behavior evidence has no stimuli"),
            TaxonomyBucket::Behavior
        );
        assert_eq!(
            classify("behavior evidence has no observables"),
            TaxonomyBucket::Behavior
        );
        assert_eq!(
            classify("final behavior verdict is NotRun, not pass"),
            TaxonomyBucket::Behavior
        );
        assert_eq!(
            classify("prerequisite failed: isolated replay has 0 attempts; exactly 10 required"),
            TaxonomyBucket::IsolatedReplay
        );
        assert_eq!(
            classify("prerequisite failed: structured PE evidence: candidate digest mismatch"),
            TaxonomyBucket::StructuredPe
        );
    }

    #[test]
    fn classification_is_order_independent() {
        let a = vec![s("oep"), s("iat"), s("reloc"), s("section")];
        let b = vec![s("reloc"), s("section"), s("iat"), s("oep")];
        assert_eq!(summarize(&a), summarize(&b));
    }

    #[test]
    fn repeated_failures_are_counted() {
        let failures = vec![
            s("prerequisite failed: structured OEP evidence: VA is missing"),
            s("prerequisite failed: structured OEP evidence: VA is missing"),
            s("prerequisite failed: structured OEP evidence: RVA is missing"),
        ];
        let counts = summarize(&failures);
        assert_eq!(counts[&TaxonomyBucket::Oep], 3);
        assert_eq!(total(&counts), 3);
    }

    #[test]
    fn unknown_failures_are_never_dropped() {
        let failures = vec![s("some brand new gate message we have not seen")];
        let counts = summarize(&failures);
        assert_eq!(counts[&TaxonomyBucket::Other], 1);
        assert_eq!(total(&counts), 1);
    }

    #[test]
    fn empty_failure_list_classifies_to_empty() {
        let counts = summarize(&[]);
        assert_eq!(total(&counts), 0);
        assert!(counts.is_empty());
    }

    #[test]
    fn missing_field_style_is_handled() {
        // A failure with no recognizable token falls to Other, never panics.
        assert_eq!(classify(""), TaxonomyBucket::Other);
        assert_eq!(classify("  "), TaxonomyBucket::Other);
    }

    #[test]
    fn reloc_wins_over_generic_prerequisite_prefix() {
        assert_eq!(
            classify("prerequisite failed: structured relocation evidence: blockers must be sorted and deduplicated"),
            TaxonomyBucket::Relocation
        );
    }

    #[test]
    fn survival_structural_evidence_artifact_sha256_gaps_classify() {
        assert_eq!(
            classify("prerequisite failed: survival evidence: artifact_sha256 is not a lowercase 64-hex SHA-256"),
            TaxonomyBucket::PrerequisiteSurvivalStructural
        );
        assert_eq!(
            classify("prerequisite failed: structural evidence: artifact_sha256 is not a lowercase 64-hex SHA-256"),
            TaxonomyBucket::PrerequisiteSurvivalStructural
        );
    }
}
