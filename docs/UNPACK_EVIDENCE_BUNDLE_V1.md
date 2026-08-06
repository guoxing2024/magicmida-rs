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
| `ahk_gto` | `mida.unpack-evidence-bundle/v1` | `mida.unpack-gate/none` |
| unknown | refused (no schema resolves) | refused |

Dispatch is fail-closed on every seam:

- a missing/empty `family_id` in a generic bundle is rejected;
- an unknown generic schema version is rejected;
- a generic consumer only accepts `family_id = ahk_gto` (an Oreans family id is
  rejected);
- an Oreans v2 bundle cannot deserialize into the generic type (v2 schema id +
  `deny_unknown_fields`, no `family_id`), so Oreans evidence is never consumed
  as GTO generic evidence;
- a GTO generic bundle cannot deserialize into `OreansEvidenceBundle` (generic
  schema id + `family_id` are unknown fields there), so GTO evidence is never
  consumed as Oreans evidence;
- any member whose `schema_version` does not match the family's expected
  schema is rejected (no cross-family member smuggling);
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

The launch boundary attests a run before the input PE is parsed (the input is
not yet identified), so the attested evidence context starts on the
Oreans-compat family; once `dual_select_packer` identifies GTO, the context is
rebound to `ahk_gto` (`RunEvidenceContext::rebind_family`) so its evidence
routes to the generic contract. A garbage input is still refused at the launch
boundary *before* any PE work (the attestation gate precedes PE parsing).

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
the same family-agnostic sidecars the Oreans contract binds (OEP, IAT, TLS,
relocation, section rebuild, PE, transform manifest); the generic bundle
manifests them under a family-agnostic envelope with a `family_id`. The two
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
- family/schema cross-contamination is rejected on both directions;
- missing family, unknown schema, wrong member schema, partial marker all
  fail closed.

## 8. Current standing

- `gto_launcher` remains the main attack line.
- `origin_macro` + `lunlun_software` remain the Oreans regression gate.
- Real GTO perfect unpack is **not yet accepted**; the generic contract exists
  so that GTO evidence is recorded honestly (as GTO, under its own schema)
  rather than disguised as Oreans evidence.
