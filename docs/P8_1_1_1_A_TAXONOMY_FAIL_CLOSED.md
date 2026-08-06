# P8.1.1.1-A: Taxonomy Input Fail-Closed

> Batch: P8.1.1.1 — Taxonomy Fail-Closed / E2E Claim Boundary Closure
> Start HEAD: `4b5f7c785a536c1630dc562790320d9b6d3c682b`
> Offline engineering only. No real samples launched. No P9.

## Scope

`crates/acceptance/src/failure_taxonomy.rs::classify_gate_report` previously
selected its sample source with an ambiguous fallback: "top-level `samples`
non-empty wins, else `gate.samples`". That silently accepted contradictory or
drifted report shapes and could return an empty success classification for a
shape it did not understand. This change makes schema selection **fail-closed**:
exactly two report schemas are recognized, discriminated explicitly, and
everything else is a hard `Err`.

## Recognized schemas

Exactly two report shapes are accepted. They are mutually exclusive; a report
must match one shape precisely and must not carry the other shape's sample
source.

1. **Raw v8** — `schema_version = mida.oreans-two-sample-gate/v8` with
   `gate_id = oreans_two_sample_perfect_unpack`.
   - Samples are read from the **top-level** `samples`.
   - A raw v8 report **must not** carry a `gate`.
2. **Bundle v1** — `schema_version = mida.oreans-two-sample-bundle-gate/v1`
   with `gate_id = oreans_two_sample_bundle_gate`.
   - Must contain a `gate` object whose inner `schema_version` is exactly
     `mida.oreans-two-sample-gate/v8` and inner `gate_id` is exactly
     `oreans_two_sample_perfect_unpack`.
   - Samples are read from **`gate.samples`**.
   - A bundle v1 report **must not** carry top-level `samples`.

Constants are reused from the acceptance crate root
(`OREANS_TWO_SAMPLE_GATE_SCHEMA_VERSION` / `OREANS_TWO_SAMPLE_GATE_ID` /
`BUNDLE_GATE_SCHEMA_VERSION` / `BUNDLE_GATE_ID`), so a drift in the gate's own
schema string is automatically rejected here.

## Hard errors (never an empty success)

- missing `schema_version`
- unknown `schema_version`
- raw v8 missing / empty `samples`
- bundle v1 missing inner `gate`
- bundle v1 with empty `gate.samples`
- bundle v1 inner gate wrong `schema_version` or wrong `gate_id`
- wrong top-level `gate_id`
- duplicate case
- missing required case (`origin_macro` or `lunlun_software` absent)
- extra case outside `{origin_macro, lunlun_software}`
- empty `case_id`
- raw v8 carrying `gate` (contradictory shape)
- bundle v1 carrying top-level `samples` (contradictory shape)
- unknown / drifted top-level shape

`failure` text may be empty, but the case set must be non-empty and must be
exactly `{origin_macro, lunlun_software}`.

## Output determinism

Classification output is now case-sorted (`lunlun_software` before
`origin_macro`) so raw v8 and bundle v1 reports produce identical ordering
regardless of the report's own case order. Bucket text rules and the
`classify` function are unchanged — taxonomy text-to-bucket logic was **not**
modified to satisfy any test count.

## Real P7-R2 read-only replay

Command (P8.1.1-A granted read-only access to the P7-R2 report):

```
target/debug/mida-acceptance.exe classify-gate-report \
  D:/MidaVault/scratch/p7_r2_live_smoke_c8258b3_20260805_205032/report/bundle_gate_report.json \
  --report D:/Temp/p8111_classify.json
```

- exit 0
- Input SHA-256 before = after = `29b7dfb93034989fb32bae88833670ff6fe8304804d90482e0c08768e9568b40`
  (report bytes unchanged; the real report was not modified)
- **origin_macro = 337**: prerequisite/survival/structural 4, oep 9,
  iat-final-import-mapping 298, relocation 4, section-rebuild 18,
  behavior 3, isolated-replay 1  (buckets 4/9/298/4/18/3/1)
- **lunlun_software = 1504**: prerequisite/survival/structural 4, oep 9,
  iat-unresolved 1423, iat-final-import-mapping 43, relocation 4,
  section-rebuild 17, behavior 3, isolated-replay 1  (buckets 4/9/1423/43/4/17/3/1)
- **Other = 0, unclassified = 0**

These match the counts already pinned by P8.1.1-A.

## New negative tests (in `failure_taxonomy.rs::tests`)

- `taxonomy_rejects_missing_schema_version`
- `taxonomy_rejects_unknown_schema_version`
- `taxonomy_rejects_raw_v8_missing_samples`
- `taxonomy_rejects_raw_v8_empty_samples`
- `taxonomy_rejects_bundle_v1_missing_gate`
- `taxonomy_rejects_bundle_v1_gate_samples_empty`
- `taxonomy_rejects_bundle_v1_inner_gate_wrong_schema`
- `taxonomy_rejects_wrong_gate_id` (raw v8, bundle top-level, bundle inner)
- `taxonomy_rejects_duplicate_case`
- `taxonomy_rejects_missing_case`
- `taxonomy_rejects_extra_case`
- `taxonomy_rejects_empty_case_id`
- `taxonomy_rejects_raw_schema_carrying_contradictory_gate_samples`
- `taxonomy_rejects_bundle_schema_carrying_contradictory_top_level_samples`
- `taxonomy_rejects_unknown_top_level_shape_without_empty_success`

Positive coverage added:
- `taxonomy_accepts_both_cases_with_empty_failure_text` (empty failure text is
  allowed, but the case set must be non-empty)
- Existing positive tests updated to the deterministic case-sorted output.

Result: `30 passed; 0 failed` for `failure_taxonomy` unit tests.
