# Generic Unpack-Evidence Bundle — `mida.unpack-evidence-bundle/v1`

**Status:** G2 (2026-08-06), family-agnostic evidence contract ratified and
offline-tested. The family-agnostic sibling of
`mida.oreans-evidence-bundle/v2` (`docs/VNEXT_EVIDENCE_BUNDLE_V1.md`), it lets
non-Oreans packer families — today AHK/GTO (`ahk_gto`) — record one complete,
hash-pinned unpack run without ever masquerading as Oreans evidence.

**Scope:** one isolated unpack run for one packer family. This document is the
producer->consumer wire contract; the consumer
(`mida-acceptance::validate_unpack_bundle` / `consume_unpack_bundle`) is the
only authority on generic-bundle validity.

## 1. Why a generic contract (G2)

G1 folded GTO into the shared post-attach/post-loop mainline. Before G2, a
GTO run that produced evidence did so through the Oreans v2 bundle — i.e. GTO
products were *disguised as Oreans evidence*. That is unsafe for two reasons:

1. The Oreans two-sample gate (`mida.oreans-two-sample-gate/v8`) and the
   Oreans acceptance contract are calibrated to the two fixed Oreans cases
   (`origin_macro`, `lunlun_software`). A GTO product accepted there would
   silently claim Oreans-level verification it never earned.
2. The v2 bundle carries no family identity, so a cross-family product cannot
   be routed or audited correctly.

G2 introduces a family-agnostic contract that is *explicitly bound to a packer
family* (`family_id`), so each family's evidence is recorded under its own
schema and consumed by its own consumer. The Oreans v2/v8 contracts are
untouched: same schema ids, same shapes, same vectors, same sealed evidence.

## 2. Family dispatch (fail-closed)

The packer family is bound into the attested runner config
(`packer_family`, default `oreans_themida`) and into every emitted evidence
context. Family selects the evidence contract:

| family_id | evidence bundle schema | gate schema |
|---|---|---|
| `oreans_themida` | `mida.oreans-evidence-bundle/v2` | `mida.oreans-two-sample-gate/v8` |
| `ahk_gto` | `mida.unpack-evidence-bundle/v1` | `no-gate` (explicit absent marker, not a schema id) |
| unknown | refused (no schema resolves) | refused |

Dispatch is fail-closed on every seam:

- a missing/empty `family_id` in a generic bundle is rejected;
- an unknown generic schema version is rejected;
- a generic consumer accepts any REGISTERED generic family (extensible family
  registry; currently `ahk_gto`) — an Oreans or unknown family id is rejected;
- an Oreans v2 bundle cannot deserialize into the generic type (v2 schema id +
  `deny_unknown_fields`, no `family_id`), so Oreans evidence is never consumed
  as GTO generic evidence;
- a GTO generic bundle cannot deserialize into `OreansEvidenceBundle` (generic
  schema id + `family_id` are unknown fields there), so GTO evidence is never
  consumed as Oreans evidence;
- every member must carry a GENERIC `mida.unpack-*-evidence/v1` schema — an
  Oreans `mida.oreans-*-evidence/v1` member under a generic envelope is rejected,
  and a generic member under an Oreans envelope is rejected by the Oreans
  consumer (no cross-family member smuggling in either direction);
- an unknown packer family at the runner-config / evidence-context boundary
  fails closed (no evidence contract is chosen).

## 3. Producer

`mida-cli` produces the generic bundle through
`crate::unpacker::generic_bundle_assembler::assemble_generic_evidence_bundle`
(family `ahk_gto` only). The producer keeps its own copy of the canonical hash
forms and never imports the consumer types (the boundary is one-way). It is
selected by family in `runner_preflight::complete_run_evidence`:
`oreans_themida` → the v2 assembler, `ahk_gto` → the generic assembler, unknown
→ refused.

G2-R1: the packer family is bound at STAGING time, not at launch. The case
manifest's `capability_cell.protection_family` is mapped to a packer family and
sealed into the envelope's per-case `family_id` (part of the case-set digest).
The launch boundary resolves that family BEFORE building the actual/frozen
policy or the digest, and the attestation binds the single-use evidence context
to the envelope's family. There is NO rebind path: after the input PE is
parsed, the PE-identified family must equal the attested envelope family, and
any mismatch fails closed BEFORE the sample process is created. A garbage input
is still refused at the launch boundary *before* any PE work (the attestation
gate precedes PE parsing).

## 4. Manifest shape

The generic bundle is the Oreans v2 bundle plus `family_id`:

```json
{
  "schema_version": "mida.unpack-evidence-bundle/v1",
  "family_id": "ahk_gto",
  "case_id": "gto_launcher",
  "tool_revision": "...",
  "runner_config_digest": "64-hex",
  "emitted_at": "...",
  "completion_marker": { "state": "complete" },
  "protected_input": { "sha256": "64-hex", "size_bytes": 0 },
  "candidate": { "sha256": "64-hex", "size_bytes": 0 },
  "members_sha256": "64-hex",
  "manifest_sha256": "64-hex",
  "members": [
    { "name": "oep_evidence", "relative_path": "oep_evidence.json",
      "sha256": "64-hex", "size_bytes": 0 }
  ]
}
```

`deny_unknown_fields` is enforced on both sides. The seven required members are
the same logical sidecars as the Oreans contract (OEP, IAT, TLS, relocation,
section rebuild, PE, transform manifest), but each carries a GENERIC,
family-agnostic schema id — `mida.unpack-oep-evidence/v1`,
`mida.unpack-iat-evidence/v1`, `mida.unpack-tls-evidence/v1`,
`mida.unpack-relocation-evidence/v1`, `mida.unpack-section-rebuild-evidence/v1`,
`mida.unpack-pe-evidence/v1` — never the Oreans `mida.oreans-*-evidence/v1`
sidecars. The generic envelope manifests them under a `family_id`. The two
sealed hashes (`members_sha256`, `manifest_sha256`, the latter covering
`family_id`) and the identity-chain checks behave exactly as in v2. A partial
`completion_marker` is never a valid bundle.

## 5. Consumer

`mida-acceptance` (`crate::acceptance::generic_bundle`) is the only authority
on generic-bundle validity. `validate_unpack_bundle` performs the full
fail-closed check; `consume_unpack_bundle` is the high-level seam that returns
`Err` on any rejection and only accepts a complete GTO-family generic bundle.

## 6. Runner-config identity

`packer_family` is part of the canonical runner config, so GTO and Oreans
configs — including the frozen fixed-mode policies and their runner-config
digests — are always distinct. A family-less legacy config parses as
`oreans_themida` (backward compatible) and produces the Oreans digest.

## 7. Test posture

- generic producer -> consumer round-trip (`mida-cli` unit + cross-contamination
  integration tests) — offline, synthetic sidecars;
- Oreans v2/v8 vectors remain green (untouched);
- family/schema cross-contamination is rejected on both directions (generic
  envelope + Oreans member, Oreans envelope + generic member);
- missing family, unknown family, unknown schema, wrong member schema, partial
  marker all fail closed;
- family/digest binding: an Oreans envelope case refuses a GTO-family config
  (no rebind / no masquerading an Oreans digest as GTO); an unknown or missing
  envelope family fails case-set validation; GTO and Oreans digests are never
  equal; the PE-identified family must equal the attested envelope family
  before process creation;
- G2-R2 production-shaped: the shared sidecar producers (IAT/OEP/TLS/section)
  dispatch their member schema by family (`mida.oreans-*` vs
  `mida.unpack-*`) through a single `evidence_schema` dispatch; the generic
  PE-evidence producer (`build_unpack_pe_evidence` / `unpack-pe-evidence`
  command) is schema-distinct from the Oreans one and never crosses lines; a
  real producer output matches the generic assembler's expected member schema.

## 7b. GTO preflight reachability (G2-R2, choice B)

The generic producers are now real and family-wired, but the GTO **preflight
lane is NOT yet reachable end-to-end**. This is a deliberate, documented choice:

- the fixed two-sample regression gate (`FIXED_CASE_IDS`) remains strictly
  `origin_macro` + `lunlun_software` (both Oreans), so no GTO case can be
  staged into the envelope today;
- `attest_ready_before_launch` restricts to those two Oreans cases, so a GTO
  family attestation is not exercisable through the production staging path;
- the GTO family / digest / attest / generic-bundle path is unit-tested and the
  producers are family-correct, but wiring GTO into the preflight lane is a
  **later, separate task** (independent family-aware / no-gate GTO lane);
- a reachability-guard test (`gto_preflight_is_not_yet_reachable`) locks this
  boundary so no future change can silently claim GTO preflight is live.

## 8. Current standing

- `gto_launcher` remains the main attack line.
- `origin_macro` + `lunlun_software` remain the Oreans regression gate.
- Real GTO perfect unpack is **not yet accepted**; the generic contract exists
  so that GTO evidence is recorded honestly (as GTO, under its own schema)
  rather than disguised as Oreans evidence.
