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
