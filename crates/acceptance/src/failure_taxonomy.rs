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

use serde::{Deserialize, Serialize};

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

/// Stable per-sample classification of a v8 two-sample gate report.
///
/// This is the P8.1-C reproducible taxonomy output. It is derived from the
/// gate report's per-sample `failures` lists only; it never re-derives a gate
/// decision, never accesses D:/MidaVault, and never opens a real sample. The
/// input SHA-256 lets an audit reproduce the exact classification from the
/// same bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateReportClassification {
    /// SHA-256 of the exact input report bytes (64 lowercase hex chars).
    pub input_sha256: String,
    /// Total failures across all samples.
    pub total_failures: usize,
    /// Per-sample bucket counts keyed by case_id.
    pub samples: Vec<SampleClassification>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SampleClassification {
    pub case_id: String,
    /// Total failures for this sample.
    pub total_failures: usize,
    /// Bucket -> count, stable BTreeMap order.
    pub buckets: BTreeMap<String, usize>,
    /// Number of failures that fell into `Other` (always surfaced, never
    /// dropped).
    pub other_count: usize,
    /// The raw text of every `Other` failure, in original report order.
    pub other_failures: Vec<String>,
    /// Number of non-`Other` failures that did not reach a known bucket. This
    /// is always 0 here; `other` is the only catch-all.
    pub unclassified: usize,
}

/// Classify an already-serialized v8 two-sample gate report.
///
/// The caller provides the exact report bytes so the input SHA-256 is bound to
/// the same bytes the classification was derived from. The report is parsed
/// with a lean schema that mirrors the `failures` and `case_id` fields of
/// [`crate::OreansTwoSampleGateReport`] — the only fields classification reads
/// — so a real gate report (which carries many additional evidence fields)
/// classifies without re-deriving any gate decision.
///
/// # Fail-closed schema selection (P8.1.1.1-A)
///
/// Exactly two report shapes are accepted, and they are discriminated
/// explicitly rather than by an ambiguous "top-level samples non-empty wins,
/// else `gate.samples`" fallback:
///
/// 1. **Raw v8** — `mida.oreans-two-sample-gate/v8` with
///    `gate_id = oreans_two_sample_perfect_unpack`. Samples are read from the
///    **top-level** `samples`. A raw v8 report must not carry a `gate`.
/// 2. **Bundle v1** — `mida.oreans-two-sample-bundle-gate/v1` with
///    `gate_id = oreans_two_sample_bundle_gate`. It must contain a `gate`
///    object whose inner `schema_version` is exactly `mida.oreans-two-sample-gate/v8`
///    and inner `gate_id` is exactly `oreans_two_sample_perfect_unpack`.
///    Samples are read from **`gate.samples`**. A bundle v1 report must not
///    carry top-level `samples`.
///
/// Any of the following is a hard `Err` (never an empty success):
/// missing `schema_version`, unknown `schema_version`, wrong inner gate
/// `schema_version`/`gate_id`, missing/empty samples, missing or duplicate
/// required cases, a case outside `{origin_macro, lunlun_software}`, or an
/// empty/duplicate `case_id`. Conflicting shapes (a raw v8 carrying `gate`, or
/// a bundle v1 carrying top-level `samples`) are rejected rather than resolved
/// by priority.
///
/// The required case set must be exactly present: `origin_macro` and
/// `lunlun_software`. A non-empty case set is required; `failure` text may be
/// empty, but the case set may not.
pub fn classify_gate_report(report_bytes: &[u8]) -> Result<GateReportClassification, String> {
    let input_sha256 = crate::sha256_hex(report_bytes);
    #[derive(Clone, Deserialize)]
    struct LeanSample {
        #[serde(default)]
        case_id: String,
        #[serde(default)]
        failures: Vec<String>,
    }
    #[derive(Deserialize)]
    struct LeanGate {
        #[serde(default)]
        schema_version: String,
        #[serde(default)]
        gate_id: String,
        #[serde(default)]
        samples: Vec<LeanSample>,
    }
    #[derive(Deserialize)]
    struct LeanReport {
        #[serde(default)]
        schema_version: String,
        #[serde(default)]
        gate_id: String,
        #[serde(default)]
        samples: Vec<LeanSample>,
        #[serde(default)]
        gate: Option<LeanGate>,
    }
    let report: LeanReport = serde_json::from_slice(report_bytes)
        .map_err(|error| format!("report is not a valid Oreans two-sample gate report: {error}"))?;

    let v8_schema = crate::OREANS_TWO_SAMPLE_GATE_SCHEMA_VERSION;
    let v8_id = crate::OREANS_TWO_SAMPLE_GATE_ID;
    let bundle_schema = crate::BUNDLE_GATE_SCHEMA_VERSION;
    let bundle_id = crate::BUNDLE_GATE_ID;

    // Missing / unknown schema_version is always a hard error.
    if report.schema_version.is_empty() {
        return Err("report is missing schema_version".to_string());
    }

    // Explicit, mutually exclusive shape discrimination. Never fall back from
    // one source to the other.
    let lean_samples: Vec<LeanSample> = if report.schema_version == v8_schema {
        // Raw v8 two-sample gate report. Samples live at the top level.
        if report.gate_id != v8_id {
            return Err(format!(
                "raw v8 report has unexpected gate_id {report_gate_id:?}; expected {v8_id:?}",
                report_gate_id = report.gate_id
            ));
        }
        if report.gate.is_some() {
            return Err(
                "raw v8 report must not carry a `gate`; its samples live at the top level"
                    .to_string(),
            );
        }
        report.samples
    } else if report.schema_version == bundle_schema {
        // Bundle-gate report. Samples live under `gate.samples` and the inner
        // gate must itself be an exact v8 two-sample gate.
        if report.gate_id != bundle_id {
            return Err(format!(
                "bundle-gate report has unexpected gate_id {report_gate_id:?}; expected {bundle_id:?}",
                report_gate_id = report.gate_id
            ));
        }
        if !report.samples.is_empty() {
            return Err(
                "bundle-gate report must not carry top-level `samples`; its samples live under `gate`"
                    .to_string(),
            );
        }
        let gate = report
            .gate
            .as_ref()
            .ok_or_else(|| "bundle-gate report is missing its inner `gate` object".to_string())?;
        if gate.schema_version != v8_schema {
            return Err(format!(
                "bundle-gate inner `gate` has schema_version {:?}; expected the exact v8 schema {v8_schema:?}",
                gate.schema_version
            ));
        }
        if gate.gate_id != v8_id {
            return Err(format!(
                "bundle-gate inner `gate` has gate_id {:?}; expected {v8_id:?}",
                gate.gate_id
            ));
        }
        gate.samples.clone()
    } else {
        return Err(format!(
            "report has unknown schema_version {:?}; expected {v8_schema:?} or {bundle_schema:?}",
            report.schema_version
        ));
    };

    // A non-empty case set is required (failure text may be empty).
    if lean_samples.is_empty() {
        return Err("report samples are empty; no cases to classify".to_string());
    }

    // The required case set must be exactly present: origin_macro and
    // lunlun_software. Missing, duplicate, extra, or empty case_id is rejected.
    let required: &[&str] = &["origin_macro", "lunlun_software"];
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for sample in &lean_samples {
        if sample.case_id.is_empty() {
            return Err("report contains a sample with an empty case_id".to_string());
        }
        *seen.entry(sample.case_id.clone()).or_insert(0) += 1;
    }
    for case in required {
        let count = seen.get(*case).copied().unwrap_or(0);
        if count == 0 {
            return Err(format!(
                "report is missing required case {case:?}; present cases: {present:?}",
                present = seen.keys().collect::<Vec<_>>()
            ));
        }
        if count > 1 {
            return Err(format!("report contains duplicate case {case:?}"));
        }
    }
    for case in seen.keys() {
        if !required.contains(&case.as_str()) {
            return Err(format!(
                "report contains unexpected case {case:?}; only {required:?} are accepted"
            ));
        }
    }

    let mut samples = Vec::new();
    let mut total_failures = 0usize;
    for sample in &lean_samples {
        let counts = summarize(&sample.failures);
        let sample_total = total(&counts);
        total_failures = total_failures.saturating_add(sample_total);
        let other_count = counts.get(&TaxonomyBucket::Other).copied().unwrap_or(0);
        let other_failures: Vec<String> = sample
            .failures
            .iter()
            .filter(|f| classify(f) == TaxonomyBucket::Other)
            .cloned()
            .collect();
        let buckets: BTreeMap<String, usize> = counts
            .into_iter()
            .filter(|(bucket, _)| *bucket != TaxonomyBucket::Other)
            .map(|(bucket, count)| (bucket.label().to_string(), count))
            .collect();
        samples.push(SampleClassification {
            case_id: sample.case_id.clone(),
            total_failures: sample_total,
            other_count,
            other_failures,
            unclassified: 0,
            buckets,
        });
    }
    // Keep required-case ordering stable for deterministic output regardless
    // of report order (raw v8 and bundle v1 may list cases in either order).
    samples.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    Ok(GateReportClassification {
        input_sha256,
        total_failures,
        samples,
    })
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

    // --- P8.1-C: reproducible gate-report classification ---

    /// Build a minimal v8 gate report JSON with the given per-sample failures.
    fn report_json(case_failures: &[(&str, Vec<&str>)]) -> serde_json::Value {
        let samples: Vec<serde_json::Value> = case_failures
            .iter()
            .map(|(case_id, failures)| {
                serde_json::json!({
                    "case_id": case_id,
                    "failures": failures,
                    "prerequisites_pass": false,
                    "passed": false,
                    "final_behavior_verdict": "NotRun",
                })
            })
            .collect();
        serde_json::json!({
            "schema_version": "mida.oreans-two-sample-gate/v8",
            "gate_id": "oreans_two_sample_perfect_unpack",
            "required_cases": ["origin_macro", "lunlun_software"],
            "excluded_cases": [],
            "samples": samples,
            "final_verdict": "open"
        })
    }

    #[test]
    fn classify_gate_report_produces_stable_counts_and_input_hash() {
        let json = report_json(&[
            (
                "origin_macro",
                vec![
                    "prerequisite failed: structured OEP evidence: VA is missing",
                    "prerequisite failed: structured IAT evidence: structured IAT report: Unresolved status at slot 1",
                    "prerequisite failed: structured section rebuild evidence: duplicate section name",
                    "a brand-new gate message not yet in the taxonomy",
                ],
            ),
            ("lunlun_software", vec![]),
        ]);
        let bytes = serde_json::to_vec(&json).unwrap();
        let report = classify_gate_report(&bytes).expect("classify");
        assert_eq!(report.total_failures, 4);
        assert_eq!(report.samples.len(), 2);
        // Output is deterministic and case-sorted, so lunlun_software is first.
        let lunlun = &report.samples[0];
        assert_eq!(lunlun.case_id, "lunlun_software");
        assert_eq!(lunlun.total_failures, 0);
        let origin = &report.samples[1];
        assert_eq!(origin.case_id, "origin_macro");
        assert_eq!(origin.total_failures, 4);
        assert_eq!(origin.buckets["oep"], 1);
        assert_eq!(origin.buckets["iat-unresolved"], 1);
        assert_eq!(origin.buckets["section-rebuild"], 1);
        assert_eq!(origin.other_count, 1);
        assert_eq!(origin.other_failures.len(), 1);
        assert!(origin.other_failures[0].contains("brand-new"));
        // Input SHA-256 is 64 lowercase hex and bound to the same bytes.
        assert_eq!(report.input_sha256.len(), 64);
        assert!(report.input_sha256.chars().all(|c| c.is_ascii_hexdigit()));
        let expected_hash = crate::sha256_hex(&bytes);
        assert_eq!(report.input_sha256, expected_hash);
    }

    #[test]
    fn classify_gate_report_handles_multiple_samples_and_unknown() {
        let json = report_json(&[
            (
                "origin_macro",
                vec![
                    "prerequisite failed: structured TLS evidence: callback ordering is not preserved",
                    "unknown text one",
                ],
            ),
            (
                "lunlun_software",
                vec![
                    "prerequisite failed: structured relocation evidence: final relocation DYNAMIC_BASE is not set",
                    "unknown text two",
                    "unknown text three",
                ],
            ),
        ]);
        let bytes = serde_json::to_vec(&json).unwrap();
        let report = classify_gate_report(&bytes).expect("classify");
        assert_eq!(report.total_failures, 5);
        assert_eq!(report.samples.len(), 2);
        // Output is case-sorted: lunlun_software before origin_macro.
        let lunlun = &report.samples[0];
        assert_eq!(lunlun.case_id, "lunlun_software");
        assert_eq!(lunlun.buckets["relocation"], 1);
        assert_eq!(lunlun.other_count, 2);
        assert_eq!(lunlun.other_failures.len(), 2);
        let origin = &report.samples[1];
        assert_eq!(origin.case_id, "origin_macro");
        assert_eq!(origin.buckets["tls"], 1);
        assert_eq!(origin.other_count, 1);
        // `unknown` buckets are never silently folded; Other carries the raw
        // text and is always surfaced in the output.
        assert!(!report.samples.iter().all(|s| s.other_count == 0));
    }

    #[test]
    fn classify_gate_report_rejects_non_gate_json() {
        assert!(classify_gate_report(b"not json").is_err());
        assert!(
            classify_gate_report(br#"{"hello": 1}"#).is_err(),
            "unknown schema must be rejected"
        );
    }

    #[test]
    fn classify_gate_report_empty_failures_yield_zero_buckets() {
        let json = report_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let bytes = serde_json::to_vec(&json).unwrap();
        let report = classify_gate_report(&bytes).expect("classify");
        assert_eq!(report.total_failures, 0);
        assert_eq!(report.samples.len(), 2);
        for sample in &report.samples {
            assert_eq!(sample.total_failures, 0);
            assert!(sample.buckets.is_empty());
            assert_eq!(sample.other_count, 0);
            assert!(sample.other_failures.is_empty());
        }
    }

    #[test]
    fn classify_gate_report_other_raw_text_preserves_order() {
        let json = report_json(&[
            (
                "origin_macro",
                vec![
                    "zzz first",
                    "aaa second",
                    "known failure: structured OEP evidence: VA is missing",
                ],
            ),
            ("lunlun_software", vec![]),
        ]);
        let bytes = serde_json::to_vec(&json).unwrap();
        let report = classify_gate_report(&bytes).expect("classify");
        let sample = report
            .samples
            .iter()
            .find(|s| s.case_id == "origin_macro")
            .expect("origin_macro present");
        // Other text keeps original report order (not sorted).
        assert_eq!(sample.other_failures, vec!["zzz first", "aaa second"]);
    }

    #[test]
    fn classify_gate_report_accepts_bundle_gate_shape() {
        // P8.1.1-A: the real P7-R2 report is a bundle-gate report
        // (mida.oreans-two-sample-bundle-gate/v1) whose samples live under
        // `gate.samples`, not at the top level. The classifier must read them.
        let inner = report_json(&[
            (
                "origin_macro",
                vec!["prerequisite failed: structured OEP evidence: VA is missing"],
            ),
            ("lunlun_software", vec![]),
        ]);
        let bundle = serde_json::json!({
            "schema_version": "mida.oreans-two-sample-bundle-gate/v1",
            "gate_id": "oreans_two_sample_bundle_gate",
            "envelopes": [],
            "gate": inner,
        });
        let bytes = serde_json::to_vec(&bundle).unwrap();
        let report = classify_gate_report(&bytes).expect("classify bundle-gate shape");
        assert_eq!(report.samples.len(), 2);
        assert_eq!(report.samples[0].case_id, "lunlun_software");
        assert_eq!(report.samples[0].buckets.len(), 0);
        assert_eq!(report.samples[1].case_id, "origin_macro");
        assert_eq!(report.samples[1].buckets["oep"], 1);
        assert_eq!(report.samples[1].other_count, 0);
    }

    // --- P8.1.1.1-A: fail-closed schema selection ---

    /// Build a raw v8 gate report JSON with the given per-sample failures,
    /// defaulting to the exact required case set.
    fn raw_v8_json(case_failures: &[(&str, Vec<&str>)]) -> serde_json::Value {
        serde_json::json!({
            "schema_version": "mida.oreans-two-sample-gate/v8",
            "gate_id": "oreans_two_sample_perfect_unpack",
            "required_cases": ["origin_macro", "lunlun_software"],
            "excluded_cases": [],
            "samples": case_failures
                .iter()
                .map(|(case_id, failures)| serde_json::json!({
                    "case_id": case_id,
                    "failures": failures,
                }))
                .collect::<Vec<_>>(),
            "final_verdict": "open"
        })
    }

    /// Build a bundle-gate v1 report JSON wrapping the given inner v8 gate JSON.
    fn bundle_v1_json(inner: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "schema_version": "mida.oreans-two-sample-bundle-gate/v1",
            "gate_id": "oreans_two_sample_bundle_gate",
            "envelopes": [],
            "gate": inner,
        })
    }

    /// Assert that classifying the given JSON errors (never succeeds).
    fn assert_rejects(json: serde_json::Value) {
        let bytes = serde_json::to_vec(&json).unwrap();
        assert!(
            classify_gate_report(&bytes).is_err(),
            "expected fail-closed rejection for {json}"
        );
    }

    #[test]
    fn taxonomy_rejects_missing_schema_version() {
        let mut json = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let obj = json.as_object_mut().unwrap();
        obj.remove("schema_version");
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_unknown_schema_version() {
        let mut json = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let obj = json.as_object_mut().unwrap();
        obj.insert(
            "schema_version".into(),
            "mida.oreans-two-sample-gate/v9".into(),
        );
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_raw_v8_missing_samples() {
        let mut json = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let obj = json.as_object_mut().unwrap();
        obj.remove("samples");
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_raw_v8_empty_samples() {
        let json = raw_v8_json(&[]);
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_bundle_v1_missing_gate() {
        let mut json = bundle_v1_json(raw_v8_json(&[
            ("origin_macro", vec![]),
            ("lunlun_software", vec![]),
        ]));
        let obj = json.as_object_mut().unwrap();
        obj.remove("gate");
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_bundle_v1_gate_samples_empty() {
        let mut inner = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let inner_obj = inner.as_object_mut().unwrap();
        inner_obj.insert("samples".into(), serde_json::json!([]));
        assert_rejects(bundle_v1_json(inner));
    }

    #[test]
    fn taxonomy_rejects_bundle_v1_inner_gate_wrong_schema() {
        let mut inner = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let inner_obj = inner.as_object_mut().unwrap();
        inner_obj.insert(
            "schema_version".into(),
            "mida.oreans-two-sample-gate/v8-drift".into(),
        );
        assert_rejects(bundle_v1_json(inner));
    }

    #[test]
    fn taxonomy_rejects_wrong_gate_id() {
        // Raw v8 with a wrong gate_id must be rejected.
        let mut json = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let obj = json.as_object_mut().unwrap();
        obj.insert("gate_id".into(), "some_other_gate".into());
        assert_rejects(json);

        // Bundle v1 with a wrong top-level gate_id must be rejected.
        let mut bundle = bundle_v1_json(raw_v8_json(&[
            ("origin_macro", vec![]),
            ("lunlun_software", vec![]),
        ]));
        let bundle_obj = bundle.as_object_mut().unwrap();
        bundle_obj.insert("gate_id".into(), "wrong_bundle_gate".into());
        assert_rejects(bundle);

        // Bundle v1 whose inner gate has a wrong gate_id must be rejected.
        let mut inner = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let inner_obj = inner.as_object_mut().unwrap();
        inner_obj.insert("gate_id".into(), "not_perfect_unpack".into());
        assert_rejects(bundle_v1_json(inner));
    }

    #[test]
    fn taxonomy_rejects_duplicate_case() {
        let json = raw_v8_json(&[
            ("origin_macro", vec![]),
            ("origin_macro", vec![]),
            ("lunlun_software", vec![]),
        ]);
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_missing_case() {
        // Only one of the two required cases present -> missing case.
        let json = raw_v8_json(&[("origin_macro", vec![])]);
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_extra_case() {
        let json = raw_v8_json(&[
            ("origin_macro", vec![]),
            ("lunlun_software", vec![]),
            ("some_other_case", vec![]),
        ]);
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_empty_case_id() {
        let json = raw_v8_json(&[("", vec![]), ("lunlun_software", vec![])]);
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_raw_schema_carrying_contradictory_gate_samples() {
        // A raw v8 report must not carry a `gate`; samples must live at the
        // top level. Carrying both is a conflicting shape and is rejected.
        let mut json = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let obj = json.as_object_mut().unwrap();
        obj.insert(
            "gate".into(),
            serde_json::json!({
                "schema_version": "mida.oreans-two-sample-gate/v8",
                "gate_id": "oreans_two_sample_perfect_unpack",
                "samples": [],
            }),
        );
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_bundle_schema_carrying_contradictory_top_level_samples() {
        // A bundle v1 report must not carry top-level `samples`; its samples
        // live under `gate`. Carrying both is a conflicting shape and is
        // rejected rather than resolved by priority.
        let mut json = bundle_v1_json(raw_v8_json(&[
            ("origin_macro", vec![]),
            ("lunlun_software", vec![]),
        ]));
        let obj = json.as_object_mut().unwrap();
        obj.insert(
            "samples".into(),
            serde_json::json!([{
                "case_id": "origin_macro",
                "failures": ["prerequisite failed: structured OEP evidence: VA is missing"],
            }]),
        );
        assert_rejects(json);
    }

    #[test]
    fn taxonomy_rejects_unknown_top_level_shape_without_empty_success() {
        // A drifted / unknown top-level report shape must not silently return
        // an empty success classification.
        for json in [
            serde_json::json!({"hello": 1}),
            serde_json::json!({"schema_version": "totally.unknown/schema", "samples": []}),
            serde_json::json!({"schema_version": "mida.oreans-two-sample-gate/v8"}),
        ] {
            assert_rejects(json);
        }
    }

    #[test]
    fn taxonomy_accepts_both_cases_with_empty_failure_text() {
        // failure text may be empty, but the case set must be non-empty.
        let json = raw_v8_json(&[("origin_macro", vec![]), ("lunlun_software", vec![])]);
        let bytes = serde_json::to_vec(&json).unwrap();
        let report = classify_gate_report(&bytes).expect("empty failures but full case set");
        assert_eq!(report.total_failures, 0);
        assert_eq!(report.samples.len(), 2);
        for sample in &report.samples {
            assert_eq!(sample.total_failures, 0);
            assert!(sample.buckets.is_empty());
        }
    }
}
