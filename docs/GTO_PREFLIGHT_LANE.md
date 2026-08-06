# GTO Preflight Lane — G3 Design (family-aware / no-gate)

**Status:** DESIGN (G2-R2-hardening stage B). Not yet wired into production
staging/attestation; the fixed Oreans two-sample v4/v8 regression gate is
unchanged. No real GTO sample is executed.

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

The GTO lane is **not** production-reachable: `validate_case_set` and
`attest_ready_before_launch` still require exactly the two Oreans cases, so a
GTO case cannot be staged/attested through the production path yet. The lane
components (family dispatch, generic producers, digest binding, fail-closed
family checks) are unit-tested; wiring the lane into staging/attestation is a
separate, later step. A reachability-guard test
(`gto_preflight_is_not_yet_reachable`) locks this boundary.

## 7. Verification posture

- Offline synthetic tests only; no real GTO/Oreans sample is executed.
- Oreans v2/v8 vectors and the two-sample gate remain green.
- Lane components are tested through the real `evidence_schema` dispatch, the
  real sidecar/PE producers, the generic assembler + consumer, and the
  family/digest binding.
