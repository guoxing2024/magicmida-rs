# GTO Preflight Lane — G3 (family-aware / no-gate)

**Status:** G3 lane implementation complete **offline**. The lane is wired into
the CLI and acceptance code paths and covered by offline tests, but no real GTO
sample has been run — it is NOT `completed`/`perfect`/accepted. The fixed Oreans
two-sample v4/v8 regression gate is unchanged.

## 0. What is wired (G3)

- `validate_case_set` (CLI) recognizes two lanes: the Oreans fixed lane
  (`origin_macro` + `lunlun_software`, family `oreans_themida`) plus an
  optional GTO no-gate lane case (`gto_launcher`, family `ahk_gto`).
  Cross-lane / unknown / missing family fails closed.
- `attest_ready_before_launch` (CLI) accepts a `gto_launcher` target case and
  binds the evidence context to `ahk_gto` (no rebind). The Oreans lane keeps
  its v8 gate unchanged.
- staging (`commands.rs`) derives `family_id` from the manifest
  `capability_cell.protection_family` via
  `packer_family_from_protection_family` (`ahk_gto_candidate` → `ahk_gto`).
- acceptance `check_case_identity` passes a GTO no-gate manifest (case id
  `gto_launcher` + `protection_family=ahk_gto_candidate`) through the identity
  chain WITHOUT a locked manifest; `run_offline_preflight` and the envelope
  case-set check accept the optional GTO lane.
- The GTO lane keeps `gate_schema = UNPACK_GATE_ABSENT = "no-gate"` and
  produces generic `mida.unpack-*` evidence. `no-gate` means "no acceptance
  gate yet", never "accepted".

## 1. Goal

Give AHK/GTO (`gto_launcher`) a **separate, family-aware, no-gate preflight
lane** so a GTO run can be staged, attested, and produce generic
`mida.unpack-*` evidence — without disturbing the Oreans two-sample regression
gate (`origin_macro` + `lunlun_software`, `mida.oreans-evidence-bundle/v2`,
`mida.oreans-two-sample-gate/v8`).

## 2. Design principles

1. **Oreans gate is invariant.** `FIXED_CASE_IDS` (`origin_macro`,
   `lunlun_software`) stays the Oreans-only regression gate. The GTO lane is a
   distinct case identity, never inserted into the Oreans fixed set.
2. **Family is bound at staging** into the envelope per-case `family_id`
   (from the case manifest's `capability_cell.protection_family` →
   `run_spec::packer_family_from_protection_family`). `ahk_gto_candidate` →
   `ahk_gto`.
3. **Attestation uses the envelope family.** `attest_ready_before_launch`
   resolves the matched case's `family_id` and builds the actual/frozen policy
   and the single-use evidence context against that family — never a
   caller-supplied or rebindable family (G2-R1 already removed `rebind_family`).
4. **PE-identified family is checked before CreateProcess.** After
   `dual_select_packer` parses the input, the PE-identified family must equal
   the attested envelope family; mismatch / unknown / missing fails closed
   before any process is created.
5. **`no-gate` is an explicit absent state, not acceptance.** A GTO case has
   `gate_schema = UNPACK_GATE_ABSENT = "no-gate"` — it records "no acceptance
   gate yet", never "accepted".
6. **Evidence context stays `ahk_gto` end-to-end.** There is no
   "attest Oreans then rebind" path.
7. **Generic output.** A GTO lane run produces exactly the generic members
   (`mida.unpack-oep/iat/tls/relocation/section-rebuild/pe-evidence/v1`) and
   the generic bundle (`mida.unpack-evidence-bundle/v1`).
8. **No silent heavy recovery.** A normal unpack never auto-enters the
   experimental GTO recovery path; it stays gated by the `gto-product-recovery`
   feature and `ahk-gto-experimental` profile.

## 3. Case set shape

The envelope `case_configs` may contain the two Oreans cases **and** the GTO
case. `validate_case_set` must verify:

- every Oreans fixed case is present exactly once (gate invariant);
- every present case has a known `family_id` and a well-formed digest;
- a GTO case (`case_id == "gto_launcher"`) must carry `family_id == ahk_gto`;
- an unknown / duplicated / missing-family case fails closed.

This is a change to `validate_case_set` (currently it demands exactly the two
Oreans cases). It is NOT wired in this commit; it is part of the lane
implementation.

## 4. Attestation split

`attest_ready_before_launch` currently restricts `target_case_id` to
`FIXED_CASE_IDS` and requires the fresh report's case set to be exactly the two
Oreans cases. The lane must split:

- **Oreans case** → existing v8 two-sample gate path (unchanged).
- **GTO case** (`family_id == ahk_gto`) → a no-gate attestation that still:
  - verifies the envelope family / CLI / verifier / input-output identity;
  - binds the evidence context to `ahk_gto`;
  - does NOT claim any gate acceptance (`no-gate`).

Not wired in this commit.

## 5. Evidence production

For a GTO case, `complete_run_evidence` already dispatches by family:
`ahk_gto` → generic PE evidence (`unpack-pe-evidence`) + generic assembler
(`mida.unpack-evidence-bundle/v1`). The sidecar producers already resolve
`mida.unpack-*` schemas for `ahk_gto` (G2-R2). This part is production-wired and
offline-tested.

## 6. Reachability today

The GTO lane is wired into the code paths and verified **offline**, but a real
GTO sample has NOT been run — the lane is not real-sample-verified. The Oreans
fixed regression lane is unchanged and its v4/v8 gate stays green. The
reachability-guard test (`gto_preflight_is_not_yet_reachable`) still asserts the
GTO lane is a separate case id and that no real GTO sample has been accepted.

## 7. Verification posture

- Offline synthetic tests only; no real GTO/Oreans sample is executed.
- Oreans v2/v8 vectors and the two-sample gate remain green.
- Lane components are tested through the real `evidence_schema` dispatch, the
  real sidecar/PE producers, the generic assembler + consumer, and the
  family/digest binding.
- G3 lane tests: `validate_case_set` accepts Oreans + optional GTO lane and
  rejects cross-lane/unknown/missing family; a GTO lane envelope binds a
  GTO-family config and rejects an Oreans one; acceptance `check_case_identity`
  passes a GTO no-gate manifest without a locked manifest.


## 8. G3-R1: GTO sample identity & `.rdataN` recognizer analysis

A real-sample identity audit found the protected GTO sample `启动器.exe` does
NOT match the `gto_launcher.json` protected-input identity, and its current
layout (`.fptable/.rdata0/.rdata1/.rdata2`, no `.KI3`) is only `Ambiguous` for
`dual_select_packer` (falls back to `oreans_themida`). See
`D:\Tools\RE\dumps\gto\g3-acceptance\<run>\g3r1\`.

Key findings:

- The manifest (`lab/cases/v2/gto_launcher.json`) binds `4d5770af…/8583680`,
  which matches `_dyncdb/launcher.exe` (`.KI3` layout, recognized as `ahk_gto`).
- The current `启动器.exe` was updated (08-07 01:10) to `bd7366d6…/13373952`
  with a `.rdataN` layout and NO `.KI3`, so `dual_select_packer` scores it 30
  (< 40) → `Ambiguous` → falls back to Oreans. Authority adjudication is
  BLOCKED (which file is the authoritative main sample).
- The recognizer (`AhkGtoPlugin::identify`) is section-name–only; `.rdataN` is
  NOT a strong GTO signal without characteristics/entropy/raw-virtual-size
  evidence (which `IdentifyInput` does not carry). **It is kept conservative**
  (`Ambiguous`, not `Match`), per the "lowest false-positive risk" rule — no
  threshold change, no unconditional `.rdataN` match. `.dataN` numbering remains
  a strong GTO signal. Locked by tests
  `rdata_numbered_payload_without_ki3_is_ambiguous_not_match` and
  `data_numbered_payload_remains_match_without_ki3`.

## 9. Immutable sample identity (G3-R2)

Before a GTO case is staged, the protected sample must be **frozen into an
immutable snapshot** (see `docs/SAMPLE_IDENTITY_LIFECYCLE.md` and
`crate::sample_snapshot`). The dynamic path
`D:\Tools\RE\dumps\gto\启动器.exe` is a source, not an identity: each capture
yields a hash-derived revision, and the manifest binds a frozen revision, never
the live path. Capture is fail-closed (`source_changed_during_capture`), and the
offline snapshot-to-staging seam (`StagingIdentity` + `staging_identity_matches`)
drives staging from the snapshot hash/size. The authoritative GTO sample
revision is still under adjudication. The offline production staging wiring that
consumes a snapshot path as the GTO input identity is described in section 10.

## 10. Production snapshot-to-preflight wiring (G3-R3)

The immutable snapshot is now wired into the **production GTO staging boundary**
offline (no real sample was run). `run_offline_preflight_command` and its new
snapshot-aware variant `run_offline_preflight_command_with_snapshot_root` stage
each GTO case through the immutable-snapshot lifecycle before any envelope is
sealed:

1. **Capture / reuse.** `capture_snapshot` freezes the caller's protected input
   into a content-addressed `snapshot.bin` under
   `<snapshot_root>/<case_id>/<sha256>/`. The `logical_sample_id` is bound to
   `gto_launcher`. Reuse is idempotent and fail-closed on source change.
2. **Verified resolve.** `verified_read_snapshot` re-reads the snapshot from disk
   and recomputes hash/size/revision. A cached `SampleSnapshot` is never trusted.
3. **Staging identity.** `staging_identity_matches` requires the snapshot hash,
   size, AND hash-derived revision to match the **locked manifest** `protected_input`
   identity. The dynamic source path is provenance only.
4. **Envelope.** On success, the GTO case's `family_id` is `ahk_gto`, the
   protected-input identity is the verified snapshot hash/size, the runner config
   uses the generic evidence schema, and the gate schema is `no-gate`
   (`UNPACK_GATE_ABSENT`). The two Oreans fixed cases retain their existing
   v2/v8 live-input lane (isolated by case_id dispatch).
5. **Boundary re-verification.** The snapshot is re-verified from disk (a) at the
   staging entry, (b) before the runner-config envelope is sealed, and (c) at the
   last trusted boundary before the verifier is invoked. A snapshot modified,
   truncated, deleted, or replaced between boundaries fails closed.

**Manifest mismatch fails closed.** If the snapshot hash/size differ from the
manifest, staging returns a structured NotReady (`GenericGateFailure`) that
carries `case_id`, expected hash/size, and observed hash/size. No launchable
envelope is produced, no launch attestation runs, no target process is created,
the manifest is not rewritten, and no observed revision is automatically
registered as the authoritative `gto_launcher` revision. Existing snapshot
revisions are never deleted or overwritten.

**Status.** This is offline wiring of the production staging boundary — it is not
real-sample perfect-unpack acceptance. The authoritative sample revision remains
under adjudication (manifest-bound `_dyncdb/launcher.exe` vs the dynamically
updated `D:\Tools\RE\dumps\gto\启动器.exe`). No real GTO sample process was run.
GTO remains `NOT completed / NOT perfect / NOT accepted`; `no-gate` means there is
no acceptance gate, not that the product is accepted. The next step is real
snapshot staging + run acceptance only after the authority decision.

## 11. GTO launch path + identity double binding (G3-R3-R1)

The immutable snapshot is now bound into the **launch attestation**, not just
staging/preflight. `attest_ready_before_launch` matches the GTO target case by
hash/size, then `enforce_gto_snapshot_path_binding` additionally requires the
launch input to be the **exact immutable `snapshot.bin` path** sealed at staging:

- The envelope's GTO `CaseRunnerConfigEnvelope` now carries an optional
  `protected_input_path` (the sealed snapshot path). It is part of the
  canonical case-set digest, so tampering the path breaks the seal (CLI
  `canonical_case_entry`, acceptance `main.rs` recompute, and the hermetic
  `preflight_boundary` reseal all include it).
- At launch, for the GTO lane: `canonicalize(ctx.input)` must equal the
  canonical sealed snapshot path, the report's recorded path must equal the
  sealed path, and the path must be a well-formed `<root>/gto_launcher/<sha>/
  snapshot.bin` under a controlled snapshot_root (`snapshot_root_of_snapshot`,
  which also rejects relative, `..`-containing, malformed, and non-canonical
  addresses). Canonical comparison resolves symlinks/junctions, so a live
  source or alias with identical bytes but a different path is refused.
- `rerun_verifier` feeds the GTO target case the recorded snapshot path (never
  a live-source alias), and `RunEvidenceContext` binds the snapshot path.
- Oreans fixed cases are unaffected: they carry `protected_input_path = None`
  and keep their live-input lane (no path binding).

A live dynamic source — even one byte-identical to the snapshot — is refused at
launch; it is provenance only. This closes the boundary gap where a GTO case
could pass preflight on `snapshot.bin` but launch on a same-hash live source.
## 12. GTO verifier/digest chain closure (G3-R3-R2)

Two gaps in the GTO chain were closed:

**1. Acceptance GTO runner-config validation (P1).** The acceptance verifier's
GTO branch used to `continue` after a shallow family/identity check, skipping
the shared strict runner-config validation. Now GTO runs the SAME common checks
as Oreans: strict `RunnerConfig` reparse, `parsed.packer_family == family_id`,
independent digest recompute, `tool_revision` cross-check, and insertion into the
keyed `case_config_digests`. GTO remains generic/no-gate and never enters the
Oreans locked-manifest or v8 gate.

**2. CLI/acceptance canonical-encoding drift (P1).** The CLI lowercases
`protected_input_path` in its canonical case entry; the acceptance recompute now
lowercases it identically, so a mixed-case Windows snapshot path produces a
stable case-set digest across both sides (locked by a real-acceptance-binary
test and a cross-crate reseal test).

**Lane/path schema (tightened both sides).** The GTO envelope must seal a
non-empty `protected_input_path`; Oreans fixed cases must carry `None`. Missing
GTO path, Oreans-injected path, unknown family, and a content-address hash
directory ≠ `protected_input.sha256` all fail closed on BOTH the CLI
(`validate_case_set`, `enforce_gto_snapshot_path_binding`) and the acceptance
verifier. A raw sealed path containing `.`/`..` is rejected before
canonicalization even when it would resolve to the same snapshot.

Tests: 9 real-acceptance-binary integration tests (positive mixed-case envelope
→ clean report + matching GTO per-case digest; chain write→verifier→read_gate_report;
runner-config family/digest tamper, missing GTO path, Oreans-with-path,
hash-dir mismatch, raw `..` path, and mixed-case digest stability negatives) plus
4 hermetic gate tests (`check_chain_ready` accepts the verified GTO digest and
rejects a tampered one; `validate_case_set` rejects missing-path / Oreans-with-path).

## 13. Verifier input↔sealed-path binding + self-contained tests (G3-R3-R2-R1)

**Independent verifier path binding.** The `mida-acceptance` verifier now binds
each GTO `--case` actual input to the envelope's sealed `protected_input_path`
by case_id, independently of the CLI launch helper. For the GTO case it requires
the sealed path to be non-empty and absolute, free of `.`/`..`, of the exact
shape `<root>/gto_launcher/<sha256>/snapshot.bin`, with its hash directory equal
to `protected_input.sha256` (case-normalized), and `canonicalize(actual input)`
equal to `canonicalize(sealed path)` — a same-bytes live source/alias is refused
by the verifier itself. The report's GTO `protected_input_path` is the verified
sealed snapshot path. Oreans keeps its live-input lane.

**Launch helper raw-path first.** `enforce_gto_snapshot_path_binding` now
validates the RAW sealed path lexically/shape-wise (absolute, no `.`/`..`,
content-address structure, hash binding) BEFORE any canonical comparison, so a
raw `..` is refused even if it would canonicalize to the same snapshot.

**Self-contained package tests.** The real-`mida-acceptance` binary tests moved
to the acceptance package's own integration tests (`crates/acceptance/tests/`),
which are self-contained via `CARGO_BIN_EXE_mida-acceptance`. The CLI integration
tests (`preflight_boundary.rs`, `launch_attestation.rs`) resolve/build the
acceptance binary on demand into a dedicated, per-process target dir (hermetic,
concurrency-safe via cargo's build lock and distinct temp dirs), so
`cargo test -p mida-cli --offline` passes in a fresh `CARGO_TARGET_DIR` without
first running `cargo test -p mida-acceptance` or `cargo test --workspace`.

Tests: `verifier_accepts_exact_bound_gto_snapshot`,
`verifier_rejects_same_bytes_different_gto_path`,
`verifier_rejects_gto_raw_dotdot_path`, `verifier_report_binds_sealed_gto_path`,
`gto_positive_control_has_no_gto_rejection_reasons` (+ 5 GTO/Oreans negatives in
`crates/acceptance/tests/gto_verifier.rs`), and the CLI hermetic
`launch_helper_rejects_raw_dotdot_before_canonicalization`. Oreans v2/v8
regression stays green.

## 14. Per-case GTO binding + bidirectional case correspondence (G3-R3-R2-R1-R1)

**Per-case GTO path-binding semantics.** A GTO actual-input ↔ sealed-path
binding failure is now a per-case verdict on the GTO case itself, not a
top-level-only note:
- the GTO case `identity_ok` is `false`;
- the GTO case `reasons` includes a clear `GTO path binding failed: …` reason;
- the report's GTO `protected_input_path` is empty/unverified — it never falls
  back to the raw `--case` input, a live source, or `canonicalize_loose(input)`;
- the top-level reasons may still carry the failure, but never replace the
  per-case failure.
On success the report's GTO `protected_input_path` is exactly the verified
sealed snapshot path. Oreans live-input semantics are untouched.

**Bidirectional case-set ↔ `--case` correspondence.** The acceptance verifier
builds an envelope case inventory and a `--case` manifest inventory (by case_id,
order-independent) and requires them to correspond:
- Oreans fixed lane: `origin_macro` and `lunlun_software` exactly once each in
  both the envelope and the `--case` inputs;
- GTO lane: present in the envelope IFF present in `--case`, at most once per
  side — envelope-has-GTO/`--case`-lacks-GTO, `--case`-has-GTO/envelope-lacks-GTO,
  duplicate GTO, and malformed/unreadable `--case` manifest case_id all fail
  closed before the report is usable.

Tests (crates/acceptance/tests/gto_verifier.rs): the exact-bound positive control
asserts GTO `identity_ok=true`, empty reasons, report path == sealed path,
per-case digest == envelope digest, and case-set digest == envelope digest; the
same-bytes/different-path control asserts NotReady, GTO `identity_ok=false`, a
path-binding reason, and a report path that is NOT the live source; the five
correspondence negatives (envelope-GTO-lacks-case, case-GTO-lacks-envelope,
duplicate `--case` GTO, duplicate envelope GTO, malformed manifest id) all fail
closed; the raw `..`, hash-dir mismatch, and family/digest-tamper negatives stay
green; Oreans live-input/v2/v8 regression stays green.

## 15. Sample authority adjudication dossier + promotion gate (G3-R4)

The GTO sample's authority is NOT auto-decided; this task builds the audit
inputs and an explicit promotion gate (offline only).

**`mida.sample-authority-dossier/v1`** (`crate::authority_dossier`): a machine-
readable dossier of the observed sample revisions. It records logical_sample_id,
packer_family, manifest_path, manifest_declared_identity, observed_revisions[]
(each with sha256, size, immutable_snapshot_path, availability
`verified`/`missing`/`historical-record-only`, comparison_verdict
`matches_manifest`/`differs_from_manifest`, PE base identity), source_path
(provenance only), capture_tool_revision, captured_at (provenance only),
family_observation, authority_status (always `pending_human_decision`),
blockers[], completion_marker, and a sealed_dossier_hash over the canonical
content. It never auto-fills accepted/promoted/current_authority.

**Producer** (`produce_authority_dossier`): for a live candidate source it
calls `capture_snapshot` then `verified_read_snapshot` (fail-closed if the
source changes between the two reads), extracts hash/size/PE identity, and never
trusts the live source directly. A historical revision whose file is gone is
recorded as `historical-record-only` (no fake snapshot). Output path is
caller-provided; it never writes into `lab/cases/v2` and never mutates a
manifest. Timestamps/source paths are provenance only and never part of any
revision identity.

**`mida.sample-authority-decision/v1`**: an externally-provided human decision
(logical_sample_id, selected_revision_sha256, selected_revision_size,
dossier_sha256, decision `retain_manifest`/`promote_revision`/`reject_revision`,
decision_reason, decided_by, decided_at, acknowledgement[]). This task generates
only a pending template; it never creates an approved decision.

**Promotion gate** (`apply_decision`): a pure offline verifier that recomputes
the dossier sealed hash, requires the selected revision to be in the dossier with
matching hash/size, re-reads the verified snapshot from disk, requires all three
acknowledgements, and then:
- `retain_manifest` may only select the current manifest identity;
- `promote_revision` returns a HUMAN-APPLY-ONLY promotion plan (never writes the
  manifest);
- `reject_revision` never enters staging;
- pending/missing/unknown decision, dossier-hash mismatch, outside-revision, or
  hash/size mismatch all fail closed.

Production GTO staging still treats the manifest `protected_input` as the sole
current authority; the promotion plan is never wired to a manifest write.

## 16. Dossier semantic seal + deterministic revision selection hardening (G3-R4-R1)

Three offline-audit findings on the G3-R4 dossier were hardened:

**1. `captured_at` is part of the dossier-level seal.** `AuthorityDossier::canonical_content()`
now includes `captured_at`. A capture timestamp is provenance only and never part
of any revision identity (revision ID remains `sha256` + `size_bytes`), but it IS
a property of a specific dossier, so changing it breaks `verify_sealed()`.

**2. Full semantic validation (`verify_semantics`, called by `verify_sealed`).**
Rejects: invalid `logical_sample_id`; malformed / non-canonical manifest or
revision sha256; unknown `packer_family` or `family_observation.selected_family`
(reuses `mida_core`'s known-family registry, preserving GTO/Oreans isolation);
invalid `availability` / `comparison_verdict`; `authority_status` not
`pending_human_decision`; missing completion marker; a verified revision with an
empty or structurally invalid snapshot path (`validate_snapshot_path`: absolute,
no `.`/`..`, `<root>/<logical_sample_id>/<sha256>/snapshot.bin`); a
missing/historical-record-only revision with a non-empty snapshot path; and a
duplicate revision identity (`sha256` + `size_bytes`).

**3. Deterministic revision selection.** The producer rejects duplicate
revision identities fail-closed; `apply_decision` no longer uses "first match" —
it rejects a decision whose selected revision matches more than one observed
revision. Reordering candidate sources yields the same dossier (revisions sorted
by sha in the canonical seal).

**4. Promotion-plan path cross-check.** `apply_decision`'s promote path validates
the recorded `immutable_snapshot_path`, re-reads the verified snapshot from disk,
canonical-compares the recorded path against `verified.snapshot_abs_path`, and
emits the plan with the DISK-VERIFIED canonical path — never the raw dossier
field. A forged recorded path is rejected even after resealing.

**5. Decision hardening.** `decision_reason`, `decided_by`, `decided_at` must not
be empty or the `pending` placeholder. The three acknowledgements are required
exactly (extra acks permitted and documented); a duplicate of one required ack
cannot substitute for a missing one. `pending_decision_template` still emits a
pending template; `apply_decision` stably fails closed on it.

Production GTO staging still treats the manifest `protected_input` as the sole
current authority; the promotion plan is never wired to a manifest write.

## 17. Unified revision identity key + snapshot-path contract inventory (G3-R4-R1-R1)

**Unified identity key.** The authority dossier's revision identity is now
uniformly `(canonical sha256, size_bytes)` across sealing and decisions:
- `apply_decision` selects an observed revision by the FULL key
  (`selected_revision_sha256` + `selected_revision_size`), so a revision that
  shares a sha256 with a DIFFERENT size is a distinct identity, not an
  ambiguity. 0 exact matches fails closed; >1 exact matches means a duplicate
  full identity (rejected). `selected_revision_sha256` must be canonical
  lowercase and well-formed.
- `canonical_content()` sorts `observed_revisions` by the full key (sha256 then
  size_bytes). Duplicate full identities are rejected earlier by the producer
  and `verify_semantics`, so the sort never has to mask a duplicate.
- Candidate input order never changes the equivalent dossier's canonical content
  or `sealed_dossier_hash` (verified by forward/reverse ordering tests).

**Snapshot-path contract inventory (multiple implementations).** The GTO
immutable snapshot path layout `<root>/gto_launcher/<sha256>/snapshot.bin` is
currently parsed in three places, kept in sync but NOT unified:
1. `crate::authority_dossier::validate_snapshot_path` — content-addressed path
   structural validation for the authority dossier (any logical_sample_id).
2. `crate::runner_preflight::snapshot_root_of_snapshot` — the CLI launch
   helper's path/boundary validation (hard-coded to the GTO lane).
3. the acceptance crate's GTO path parser (`gto_snapshot_hash_dir` in
   `crates/acceptance/src/main.rs`) — the independent verifier's structural
   check.

These are multiple implementations by design (independent verifier boundary;
dossier vs launch lane). **If the snapshot layout ever changes, all three must be
audited together**; this task does not refactor the production launch lane. The
GTO launch lane and the authority dossier remain separate; the dossier's
promotion plan is never wired to the manifest or to staging.
