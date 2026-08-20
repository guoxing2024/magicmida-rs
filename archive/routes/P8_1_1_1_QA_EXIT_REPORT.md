# P8.1.1.1-QA: Exit Gates & Compliance Proofs

> Batch: P8.1.1.1 — Taxonomy Fail-Closed / E2E Claim Boundary Closure
> Start HEAD: `4b5f7c785a536c1630dc562790320d9b6d3c682b`
> All A/B/QA phases completed offline. No real samples launched. No P9.

## Exit gates

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | exit 0 |
| `cargo test --workspace --locked --offline` | **962 passed, 0 failed** |
| `RUSTFLAGS="-D warnings" cargo check --workspace --tests --locked` (CI-equivalent) | exit 0, 0 warnings |
| `cargo check -p mida-cli --features gto-product-recovery --locked` | exit 0 |
| `cargo deny --offline check` | advisories/bans/licenses/sources ok |
| `git diff --check` | clean |
| `git show --check` (both new commits) | clean |
| `git status --short` | empty (after final commit) |

Workspace test count grew from 941 (P8.1.1) to 962 (+21): 15 new taxonomy
negative tests, 5 new transform-manifest unit tests, 1 empty-failure positive
test.

## Additional proofs

1. **Real P7-R2 taxonomy still 337/1504, Other=0** — read-only replay through
   the new fail-closed classifier:
   - input SHA-256 `29b7dfb93034989fb32bae88833670ff6fe8304804d90482e0c08768e9568b40`
     unchanged before/after (report not modified)
   - origin_macro = 337, lunlun_software = 1504, Other = 0, unclassified = 0
2. **Malformed / empty / unknown schema no longer returns an empty success
   classification** — three malformed inputs (`{"hello":1}`, unknown schema,
   empty v8 samples) each exit 1 and never yield a successful empty result.
3. **Taxonomy bucket text rules unchanged vs `4b5f7c7`** — the `classify`
   (text-to-bucket) function is byte-for-byte unchanged; only the
   `classify_gate_report` schema-selection layer and its tests changed.
4. **Positive test still calls the five real producers and the atomic
   assembler** — `single_production_bundle_structured_domain_e2e_four_domains_pass`
   drives `write_oep/iat/tls/relocation/section_rebuild_evidence`,
   `write_bound_transform_manifest`, `build_oreans_pe_evidence`,
   `assemble_evidence_bundle`; `assert_not_hand_built` guards the sealed
   `manifest_sha256`.
5. **Docs no longer claim a two-bundle envelope E2E** —
   `docs/P8_1_1_B_PRODUCTION_E2E.md` and the module doc now name it a
   *single-production-bundle structured-domain E2E* and defer the two-bundle
   envelope consumer to P9.
6. **No test-only public API remains** — `write_bound_transform_manifest` is
   closed as a supported production API with a formal contract and 5
   independent unit tests (`transform_manifest_tests`).
7. **Default tests do not access D:/MidaVault** — the P7-R2 read is explicit,
   granted by the work order, and not part of the default test suite.
8. **0 real sample processes created** — no process creation in any changed
   code path.
9. **`validation_summary.json` blob unchanged** — verified `cf72b7a` (see
   below).
10. **P7 execution roots not modified** — the P7-R2 report was only read
    (SHA-256 verified before/after); classification output went to `D:/Temp`.
11. **P9 not executed.**
12. **v8 gate stays Open.**

## Compliance declarations

- **validation_summary.json**: blob unchanged from start HEAD.
- **P7 roots**: not modified (read-only P7-R2 replay).
- **P9**: not executed.
- **Live acceptance**: not declared (live/perfect/universal/10/10/final).
  Four-domain pass is a synthetic offline proof only; real-sample revalidation
  of the v8 gate, behavior oracle, isolated replay 10/10, and the two-bundle
  envelope consumer remain pinned for an authorized live run (P9).

## Fix folded into this QA commit

- Removed an unused import (`OreansIatReasonCounts`) in
  `crates/acceptance/tests/oreans_two_sample_gate.rs`. It was a pre-existing
  warning (present at start HEAD) that blocked the CI-equivalent
  `RUSTFLAGS="-D warnings"` gate; the file uses the fully-qualified
  `mida_acceptance::OreansIatReasonCounts` on line 245, so the import was
  redundant. Behavior unchanged; the gate test still passes (38 passed).
