# P8.1.1.1-B: E2E Claim Boundary & Transform-Manifest API Boundary

> Batch: P8.1.1.1 — Taxonomy Fail-Closed / E2E Claim Boundary Closure
> Start HEAD: `4b5f7c785a536c1630dc562790320d9b6d3c682b`
> Offline engineering only. No real samples launched. No P9.

## Scope

Two boundary closures on the P8.1.1-B production evidence pipeline:

1. **E2E claim boundary** — the test and its documentation now use the accurate
   name **single-production-bundle structured-domain E2E**, and explicitly
   record what it does and does not prove.
2. **Transform-manifest API boundary** — `write_bound_transform_manifest` is
   closed as a supported production API (formal contract + independent unit
   tests), removing the "solely exposed for tests" rationale.

## E2E claim boundary

Renamed positive test:
- Old: `production_evidence_pipeline_four_domains_pass`
- New: `single_production_bundle_structured_domain_e2e_four_domains_pass`

Explicitly recorded boundaries (module doc + test doc):
- **Only the origin bundle comes from the real atomic assembler.** Its four
  structured domains (OEP / IAT / relocation / section-rebuild) are what the
  test asserts pass.
- **The lunlun companion is a synthetic observation.** It only satisfies the
  raw v8 two-sample gate's fixed case-set `{origin_macro, lunlun_software}`;
  it is not a separately-assembled production bundle, and its domains are left
  open / NotRun and never asserted.
- **This test does not prove the two-bundle envelope consumer**
  (`mida.oreans-two-sample-bundle-gate/v1` requires two sealed bundles).
  Proving the two-bundle envelope consumer is deferred to **P9** with real
  evidence.

The test is no longer described as a complete two-bundle / bundle-gate E2E.

## Transform-manifest API boundary

`write_bound_transform_manifest` (in `crates/pe/src/dumper/dump_process.rs`)
was made `pub` by P8.1.1-B with the reason "Exposed so crate tests call the
real production writer". P8.1.1.1-B closes it as a **supported production
API**:

- **It is a real production function**, not a test seam: it is called by both
  real dump paths `dump_process_with_report` and `dump_dotnet_with_source`, and
  is the writer the production evidence pipeline uses for the transform-manifest
  bundle member.
- **Formal API contract** documented on the function:
  - Parameters: `output` (candidate path → sibling `.transform_manifest.json`),
    `candidate_bytes` (exact bytes; digest computed by the writer, never
    caller-supplied), `transforms` (ordered `(id, kind)` ledger; empty = clean
    dump), `input` (optional protected/source path for the alias guard).
  - Identity constraints: recorded `candidate_sha256` / `candidate_size_bytes`
    are computed from `candidate_bytes`, so a manifest is always self-consistent
    with the exact bytes passed and cannot record a digest for different bytes.
  - Atomic write semantics: `replace_file_atomic` (temp-then-`MoveFileExW`
    REPLACE_EXISTING|WRITE_THROUGH on Windows; rename-onto-non-existing
    elsewhere), no delete-then-rename gap. Alias collision is refused
    (`output_aliases_input`) rather than overwriting the input.
  - Error contract: `Err(PeError)` on alias collision or I/O failure; written in
    full or not at all.
- **Independent unit tests** added (`transform_manifest_tests`, 5 tests):
  - `writes_manifest_with_candidate_digest_and_sibling_path`
  - `manifest_digest_binds_to_passed_bytes_not_path`
  - `records_transform_entries`
  - `refuses_to_overwrite_input_alias`
  - `manifest_is_well_formed_json_and_reads_back`
- No CLI flag, environment variable, or attestation bypass seam was added.

## Unchanged invariants

- `RunEvidenceContext` remains `#[derive(Debug)]` (not `Clone`), all fields
  private (read-only getters), constructor `pub(crate)` (not public), and is
  consumed **by value** by the assembler / `complete_run_evidence` so a single
  attestation authorizes exactly one bundle. (P8.1.1.1-B #8)
- The production E2E still calls the five real producers and the real atomic
  assembler (positive test); the tamper negative
  `production_tampered_candidate_rejected_by_independent_validator` is retained
  and is allowed to honestly recompute post-attack hashes (positive test still
  never hand-constructs a bundle). (P8.1.1.1-B #5/#6)
- No CLI flag / env var / attestation bypass seam was introduced. (#7/#8)

## Verification (B-phase local)

- `cargo test -p mida-pe --lib transform_manifest_tests --offline`:
  5 passed, 0 failed.
- `cargo test -p mida-cli --lib production_e2e --offline`:
  2 passed (positive + tamper negative), 0 failed.
