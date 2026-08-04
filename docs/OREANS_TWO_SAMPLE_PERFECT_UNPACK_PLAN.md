# Oreans Two-Sample Perfect Unpack Plan

**Status:** current mainline goal and gate definition (2026-08-01)

**Scope:** exactly two fixed Oreans samples: `origin_macro` and
`lunlun_software`. This document is a goal/gate contract, not a success report.
No sample executable is run by the documentation-only work that introduced this
file.

## 1. Authority and scope correction

For the current Oreans mainline, this document is the focused source of truth.
The older GTO-centered goal documents remain tracked historical governance
records; they do not redefine this mainline. In particular:

- `gto_launcher` is **not** one of the two samples in this gate.
- `xiongxiong_duokai` is a historical/R3 holdout and is **not** a required
  third sample for this two-sample product gate.
- GTO product-recovery and GTO research routes are separate workstreams. They
  must not be used to declare either Oreans sample perfectly unpacked.
- The Shiguang server/icon patch workflow is compatibility/product patch work,
  not an unpack-success criterion.

The following older records are useful evidence/history only and must be read
with the scope correction above:

- `docs/PROJECT_GOAL_20260725.md` - older goal definition with a GTO target.
- `docs/VNEXT_R3_OREANS_PATH.md` - Oreans structural/R3 history and residuals.
- `docs/AUDIT_PACKAGE_20260724.md` - historical acceptance-package results;
  it explicitly says product 1.0 was not claimed.
- `docs/COURSE_CORRECTION_WORK_ORDER.md` - explains that `Accepted` means
  structure plus bounded process survival, not UI/script/business equivalence.
- `archive/gto-20260730/docs/GTO_PRODUCT_RECOVERY_CHARTER_20260729.md` and
  `docs/GTO_RESEARCH_CHARTER_20260728.md` - GTO-only governance/research
  records (product-recovery route sealed under `archive/gto-20260730/`), not
  this gate.

## 2. Fixed sample identities

These identities are immutable for this mainline. A result from a different
file, renamed copy, rebuilt input, or unpinned vault object is not evidence for
the corresponding case.

| case_id | protected input SHA-256 | size_bytes | PE facts from manifest | role |
|---|---|---:|---|---|
| `origin_macro` | `1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7` | `5232656` | PE32+, x86_64, entry RVA `0x8c8058`, `.boot`, 16 sections, 11 import descriptors, TLS=yes, relocations=yes | regression primary |
| `lunlun_software` | `8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07` | `4976144` | PE32+, x86_64, entry RVA `0x885058`, `.boot`, 13 sections, 17 import descriptors, TLS=yes, relocations=yes | development second path |

Manifest sources:

- `lab/cases/v2/origin_macro.json`
- `lab/cases/v2/lunlun_software.json`

`origin_macro` has a legacy oracle candidate
`fe92f992bcf07e630c82ff3a1cfc138a8c2463e3e03f862da171e8781119268f` at
`1696768` bytes. It is a regression comparison input only, not an oracle that
can self-certify a candidate. `lunlun_software` has no oracle in its manifest.

## 3. What "perfect unpack"means here

A candidate is perfect for this mainline only when **both** fixed cases pass all
of the gates below, with evidence tied to the fixed input digest and the exact
candidate digest. Passing one case, passing a structural checker, or loading
long enough is not enough.

### Gate A0 - fail-closed prerequisite evidence

The generic prerequisite evidence contract covers only the remaining generic
prerequisite claims. Its required refs are `survival_evidence` and
`structural_evidence`. TLS is first-class structured evidence; the generic
contract does **not**
accept `iat_complete` or a generic `iat_evidence` ref; those legacy/self-certifying
paths are rejected under `deny_unknown_fields` and by gate validation.

Structured OEP evidence remains independently required under
`mida.oreans-oep-evidence/v1`. This contract is fail-closed: missing,
malformed, schema-mismatched, candidate-unbound, or legacy self-certification
cannot close the gate. It does not produce runtime sample evidence or claim
perfect/universal unpack success.

### Gate A - identity and provenance

- The protected input matches the manifest `case_id`, SHA-256, and byte size.
- The output is a newly emitted candidate; reports never overwrite candidate or
  historical oracle files.
- The run records tool revision, command line, output digest/size, isolation
  parameters, and the gate result.

### Gate B - deterministic OEP recovery

- The dump's entry point is the recovered application OEP, not the Oreans
  bootstrap/packer entry in `.boot` and not an unexplained scan fallback.
- The OEP evidence is reproducible for each case and is tied to the same dump
  and trace that produced the rebuild.
- Historical observations include Origin around `0x13e0` and Lunlun around
  `0x1656f4`; these are engineering observations, not a permission to hardcode
  an OEP or call the gate closed.
- Any `via_scan`, bootstrap EP, ambiguous freeze, or missing RIP capture is a
  blocker until resolved or explicitly classified as a fail-closed result.

### Gate C - complete IAT recovery

The candidate-bound IAT sidecar and structured gate integration are implemented
and offline-accepted under:

- sidecar schema: `mida.oreans-iat-evidence/v1`;
- gate schema: `mida.oreans-two-sample-gate/v8`;
- observations schema: `mida.oreans-two-sample-observations/v6`.
- section rebuild sidecar: `mida.oreans-section-rebuild-evidence/v1`, emitted as
  `<candidate>.section_rebuild_evidence.json`.

The first-class structured evidence contains protected-input and final-candidate
identity, `fix_imports_requested`, present/completeness fields, the structured
report (`requested_bytes`, `bytes_read`, `slot_size`, and `slots`), per-slot
observed/rebuilt/slot values and status metadata, and final import identities.
The acceptance gate independently recomputes and fails closed on identity,
`fix_imports_requested`, present/report consistency, PE32+ pointer size, exact
reads, alignment, complete continuous unique slot coverage, `slot_value == observed_value`,
status metadata, at least one resolved slot, final import identity and one-to-one
mapping, module/function/ordinal matching, and diagnostic consistency. Stale,
unresolved, short-read, invalid-module, missing, malformed, or legacy generic IAT
fields cannot pass.

Acceptance is offline only: `oreans_two_sample_gate` 38 passed,
`oreans_two_sample_gate_cli` 9 passed, and the complete
`cargo test -p mida-acceptance --offline` suite is green.
No real `origin_macro` or `lunlun_software` candidate evidence has been generated,
no sample executable has been run, and no live unpack has been executed.

### Gate D0 - final-byte structured PE evidence (extractor fixed; gate v8 enforced)

The independent acceptance kernel exposes `build_oreans_pe_evidence(candidate_bytes)` under
schema `mida.oreans-pe-evidence/v1`. Gate report schema `mida.oreans-two-sample-gate/v8` and
observations schema `mida.oreans-two-sample-observations/v6` hard-wire structured PE and
OEP evidence on every `OreansSampleObservation`; legacy prerequisite booleans or generic
evidence references cannot stand in for structured OEP or structured IAT evidence.

For each observation, the structured evidence must bind exactly to the final serialized candidate digest and byte size, identify a valid AMD64 PE32+ image, prove required TLS and base-relocation coverage with valid detail, and pass section, directory, and internal consistency checks. If exception data is present, its ranges, unwind data, and raw backing must also agree. The builder fails closed on integer/range overflow, directory or raw-backing gaps, unterminated TLS callbacks, architecture-invalid relocation types or targets, and invalid/unmapped x64 exception records. The evidence types are serde round-trippable with unknown fields rejected.

Previously recorded PE evidence regression was **24/24 passed**. The current
structured IAT/TLS integrated results are **two-sample gate: 38/38 passed** and
**two-sample gate CLI: 9/9 passed**, with the complete `mida-acceptance` offline
test suite green. These are contract tests only: no real `origin_macro` or
`lunlun_software` candidate evidence has been generated, no sample executable
has been run, no live unpack has been executed, and the overall gate remains
**open**.

### Gate D - loader directories and relocation semantics

Both manifests declare `has_tls=true` and `has_relocations=true`. The rebuild
must therefore preserve and validate, at minimum:

- TLS directory layout, callback table, TLS index address, raw/virtual mapping,
  and loader-visible alignment;
- relocation directory contents and correct image-base/ASLR behavior; and
- directory RVAs/sizes after section placement, with no header flags that
  falsely describe stripped or absent relocations.

A file that merely parses while TLS callbacks or relocation fixups are lost is a
failed unpack, even if its entry point looks plausible.

The candidate-bound TLS sidecar `mida.oreans-tls-evidence/v1` is now first-class
in gate v8 / observations v6. The acceptance kernel strictly parses its runtime,
final-candidate, and preservation records, binds protected/candidate SHA-256 and
size, cross-checks final TLS detail against structured PE evidence, validates
runtime callback ordering/status/termination, rechecks raw-backed ranges, and
recomputes every diagnostic/pass field. This is an offline synthetic contract
only; no real sample TLS evidence or loader-behavior proof exists yet.

### Gate D1 - relocation and ASLR evidence

The candidate-bound sidecar `mida.oreans-relocation-evidence/v1` is first-class
in gate v8 / observations v6. Runtime relocation facts are frozen before dump
header patching, shrink, or `.reloc` reconstruction. The CLI re-reads the
protected input and final candidate from disk, binds both by SHA-256 and size,
rejects same-path/hard-link aliases, and writes the sidecar atomically with
unknown fields rejected.

The final candidate is parsed independently for raw-backed relocation blocks,
entries, architecture-correct types, every individual raw-backed target,
`DYNAMIC_BASE`, `RELOCS_STRIPPED`, and at least one non-ABS entry. Runtime target
values are normalized/de-relocated before comparison. The gate independently
recomputes preservation and pure-delta ASLR simulations at distinct positive and
negative deltas, then cross-checks `OreansPeEvidence.relocation_detail`.
This is an offline synthetic contract only; no real sample relocation evidence
or loader-behavior proof exists yet. Legacy v6/v4 bundle schemas remain rejected.

### Gate E - section and PE rebuild integrity

The emitted PE must be a coherent loader image, not a byte collage:

The first-class sidecar is `mida.oreans-section-rebuild-evidence/v1` and is
written as `<candidate>.section_rebuild_evidence.json`. It is built only after
the final candidate write by re-reading both protected and candidate files,
binding their SHA-256/size identities, rejecting same-path/hard-link aliases,
and atomically replacing the sidecar. The v8 gate rejects v7/v5 observations
and all historical generic section bool/ref fields.

- section table, names, characteristics, RVA order, raw offsets, raw sizes,
  virtual sizes, and file/image alignment are internally consistent;
- code/data recovered from the runtime image is mapped to the right sections;
- exception/unwind data and other loader-relevant directories are preserved
  when present;
- imports, TLS, relocations, entry point, and section bounds point inside the
  emitted image; and
- the rebuild is deterministic for the same trace/input and does not rely on a
  historical pin, stale dump, or post-build manual patch.

The gate independently recomputes section table/header coverage, raw and VA
ranges, overlap/EOF/alignment, `SizeOfHeaders`, `SizeOfImage`, entry section
and executable/raw-backed status, all PE directory coverage including the
security file-offset form, overlay extent, and cross-evidence consistency with
PE/IAT/TLS/relocation/exception records. The sidecar pass flag is diagnostic
only and cannot grant acceptance.

### Gate F - behavior acceptance

The current R0B/B-B vocabulary is deliberately weaker than perfect unpack:
`StructuralPassBehaviorPending` or `Accepted` can represent structural success
plus bounded process survival. It does **not** prove UI, script loading,
license-path behavior, or business-logic equivalence.

For each sample, the perfect gate requires a documented behavior oracle that
runs the protected input and the unpacked candidate under the same controlled
stimulus and compares the agreed observable results. The comparison must be
fail-closed and must not use a server/icon patch, forced visibility, skipped
product code, semantic bypass, or other sample-specific detour.

### Gate G - isolated replay and reproducibility

- Each case passes **10 consecutive isolated runs**, attempt=1, using the fixed
  input digest and the same declared runner policy.
- The ten runs must independently reproduce OEP, complete IAT, TLS/reloc/section
  integrity, behavior acceptance, and the final candidate evidence.
- Every attempt record must contain `runner_config_digest` as exactly 64 hexadecimal
  characters (SHA-256-shaped). For one `case_id`, all ten values must be exactly
  identical; a missing, malformed, or non-uniform value fails closed, including a
  different valid SHA-256-shaped digest on any attempt.
- Retry-picking, historical `pin` reuse, "2 attempts and one happened to pass"
  or mixing evidence from different revisions does not satisfy this gate.
- A formal result is closed only when both cases are 10/10 and the evidence is
  readable and auditable. The repository's old R3/R4 records may show structural
  or holdout closure; they do not automatically close this two-sample perfect
  gate.

## 4. Fail-closed conditions

The two-sample gate is **failed/open**, not partially passed, if any of the
following occurs for either `origin_macro` or `lunlun_software`:

- the input case ID, SHA-256, byte size, tool revision, candidate digest, or
  provenance record does not match the declared evidence;
- the recovered entry is the Oreans `.boot` bootstrap, an unexplained scan
  fallback, an ambiguous freeze, or otherwise lacks reproducible application-OEP
  evidence;
- any imported API/thunk is unresolved, stale, duplicated, zero-filled, or only
  counted by percentage without identity-level proof;
- structured PE evidence is missing for either observation, its candidate digest/size
  is not exact, the image is not AMD64 PE32+, required TLS/base-relocation detail is
  invalid or absent, section/directory/internal consistency fails, exception detail is
  inconsistent when present, or legacy bool/evidence refs are used as a substitute;
- TLS callbacks/index, relocation semantics, section mapping, directory bounds,
  unwind data, alignment, or loader behavior is missing or inconsistent;
- the candidate only parses or survives process startup but fails the agreed
  protected-vs-unpacked behavior oracle;
- any one of the 10 isolated attempt=1 runs fails, requires retry selection, uses
  a historical pin/stale dump, mixes revisions, produces unreadable evidence, or
  has a missing, malformed, or non-uniform `runner_config_digest` (including a
  different valid SHA-256-shaped digest for one attempt);
  or
- the result depends on a Shiguang patch, forced visibility, skipped product code,
  semantic bypass, manual post-build patch, GTO/holdout result, or structural
  `Accepted` alone.

One sample passing does not compensate for the other sample failing. Until both
cases pass every gate and the evidence bundle is readable and auditable, the
mainline remains **open** and no perfect/universal claim is allowed.

## 5. Current status: open and not completed

The only target samples are `origin_macro` and `lunlun_software`. The repository
now contains the v8/v6 gate contract, strict structured OEP evidence, the
candidate-bound IAT, TLS, relocation, and section rebuild sidecars, and first-class structured
IAT/TLS/relocation/section-rebuild gate
validation. It
still does **not** provide a basis for declaring either sample, or the pair,
perfectly unpacked.

Current status is intentionally explicit:

- **gate status:** `open`
- **perfect unpack:** `not_completed`
- **universal unpack:** `not_completed`
- **samples executed:** `false`
- **sample binaries opened:** `false`
- **live unpack executed:** `false`

Completed in the current offline audit:

1. Candidate-bound IAT sidecar `mida.oreans-iat-evidence/v1`.
2. First-class structured IAT evidence in gate v8 / observations v6; old
   `prerequisites.iat_complete` and generic `prerequisites.iat_evidence` are removed/rejected.
3. Gate-side recomputation of IAT identity, import-fix request, report presence,
   pointer size, exact reads, alignment, slot coverage/continuity/uniqueness,
   observed alias, status metadata, resolved>=1, final import identity and
   one-to-one mapping, and diagnostic consistency.
4. Candidate-bound TLS sidecar `mida.oreans-tls-evidence/v1` and first-class
   structured TLS gate recomputation are implemented; real sample evidence is absent.
5. Candidate-bound relocation/ASLR sidecar `mida.oreans-relocation-evidence/v1`,
   pre-mutation runtime capture, raw-backed target checks, and positive/negative
    normalized delta simulation are implemented; real sample evidence is absent.
6. Candidate-bound structured section rebuild sidecar `mida.oreans-section-rebuild-evidence/v1`,
   final-disk layout recomputation, directory/overlay checks, cross-evidence checks,
   and strict v8/v6 gate integration are implemented; real sample evidence is absent.
7. Offline acceptance: gate 38 passed, CLI 9 passed, plus the complete
   `cargo test -p mida-acceptance --offline` suite is green.
8. Evidence bundle v1 contract (`mida.oreans-evidence-bundle/v1`) defined and
   offline-tested: unified run inventory binding the candidate, protected
   input, tool revision, runner config digest, transform manifest, PE
   evidence, and the five sidecars with a canonical bundle hash. Partial
   bundles are never valid runs. See
   [docs/VNEXT_EVIDENCE_BUNDLE_V1.md](VNEXT_EVIDENCE_BUNDLE_V1.md).

Remaining blockers, in order:

1. **TLS evidence:** prove callback/table/index preservation and loader behavior
   on both fixed samples after rebuild.
2. **Real relocation/ASLR evidence:** prove relocation-directory and ASLR correctness
   on both fixed samples; no false `RELOCS_STRIPPED`/missing-directory state.
3. **Real section rebuild evidence:** produce candidate-bound evidence for both
   fixed samples and prove loader-coherent emitted bytes.
4. **Behavior oracle:** compare protected and unpacked behavior under the same
   controlled stimuli for both fixed samples; process survival alone is not enough.
5. **Fixed runner 10/10:** produce fresh isolated replay evidence for each sample
   with one fixed runner configuration, no retry-picked result, and no historical
   pin substitution.
6. **Authorization boundary:** only after the above offline work and explicit user
   authorization may the real two-sample execution/live-unpack loop run.

## 6. Explicit non-gates

The following are not success criteria for this mainline:

- Shiguang server endpoint edits, server-response changes, icon replacement, or
  the scripts/docs under the Shiguang update workflow;
- matching a historical Origin oracle byte-for-byte;
- GTO launcher UI/product recovery, GTO holdout behavior, or GTO research-route
  milestones;
- `xiongxiong_duokai` holdout closure, by itself;
- a structural `Accepted` result without behavior equivalence; or
- a green result produced from a different digest, stale candidate, manual patch,
  or unrecorded environment.

## 7. Next engineering work, ordered by priority

### P0 - unblock the two-sample gate

1. **Keep the v8/v6 contract strict.** Preserve manifest-driven checks for the
   two fixed case IDs, digests, and sizes. Structured OEP, IAT, and TLS evidence
   are mandatory; reject legacy/generic self-certification paths.
2. **Finish TLS sample evidence.** The structured TLS gate integration is complete;
   produce real candidate-bound evidence and loader-visible semantics for both fixed
   samples only after the offline contract is accepted.
3. **Finish relocation/ASLR evidence.** Prove relocation directory coverage,
   architecture-correct targets, and loader behavior without false stripped flags.
4. **Finish section rebuild evidence.** Prove deterministic section/directory
   mapping, alignment, unwind preservation, and loader-coherent emitted bytes.
5. **Define the behavior oracle.** Specify protected-vs-unpacked stimuli and
   observables for each fixed sample; load survival remains only a prerequisite.
6. **Build the fixed 10/10 replay record.** Make the runner emit immutable,
   digest-pinned attempts with one runner configuration per sample and no retry
   selection.

### P1 - prove repeatable product-equivalent output

1. Run the authorized future replay for each fixed case at attempt=1 for ten
   consecutive isolated runs; archive complete readable evidence outside Git.
2. Compare protected and unpacked behavior under the agreed oracle, including
   the failure/success paths that are actually in scope; investigate every
   mismatch instead of weakening the oracle.
3. Re-run the same gate from a clean workspace/tool revision and verify that the
   result does not depend on a historical candidate or manual post-processing.
4. Update `validation_summary.json` only with a named two-sample gate result;
   do not relabel a GTO/R3/R4 or holdout summary as this product gate.

### P2 - generalize only after closure

1. Extract the stable Oreans mechanisms into family-level tests and interfaces
   without broadening the success claim.
2. Only after both fixed samples close, evaluate whether a broader or universal
   claim is justified by separately named future coverage.

## 8. Close condition

The mainline closes only with a signed/readable evidence bundle showing, for
**both** `origin_macro` and `lunlun_software`:

- fixed input digest and size;
- recovered application OEP;
- complete IAT;
- valid TLS and relocation semantics;
- coherent deterministic section/PE rebuild;
- behavior equivalence under the agreed oracle; and
- 10/10 consecutive isolated replay.

Until that bundle exists, the repository status must remain **goal in progress /
gate open**: perfect unpack is not completed, universal unpack is not completed,
and no sample or live unpack execution may be implied by this document.
