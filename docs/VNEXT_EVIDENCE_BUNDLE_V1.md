# Evidence Bundle v1 — `mida.oreans-evidence-bundle/v1`

**Status:** contract draft (2026-08-04), offline-tested in `mida-acceptance`.
**Scope:** one isolated unpack run for one of the two fixed Oreans cases must
produce exactly one bundle. This document is the producer->consumer wire
contract; the consumer (`mida-acceptance::validate_evidence_bundle`) is the
only authority on bundle validity.

## 1. Purpose

The CLI currently writes the candidate, a bound transform manifest, structured
PE evidence, and five candidate-bound sidecars (OEP, IAT, TLS, relocation,
section rebuild) as separate files with no unified completion record. A failed
run can leave a candidate next to a subset of sidecars, and nothing today
proves "these files belong to one run, nothing is missing, and no file was
swapped". The bundle closes that gap: it is the aggregate, hash-pinned
inventory of a single run.

A partial bundle is **never** a valid run. A bundle whose files do not match
their declared hashes, whose sidecar `schema_version` values are not the exact
schemas the gate consumes, or whose transform manifest binds a different
candidate is invalid, even if every other field parses.

## 2. Manifest shape

```json
{
  "schema_version": "mida.oreans-evidence-bundle/v1",
  "case_id": "origin_macro",
  "tool_revision": "oreans/two-sample-mainline@<frozen-commit>",
  "runner_config_digest": "<64 hex chars>",
  "emitted_at": "2026-08-04T12:00:00Z",
  "completion_marker": { "state": "complete" },
  "protected_input": { "sha256": "<64 hex>", "size_bytes": 5232656 },
  "candidate": { "sha256": "<64 hex>", "size_bytes": 4096 },
  "bundle_sha256": "<64 hex>",
  "members": [
    { "name": "oep_evidence", "relative_path": "oep_evidence.json",
      "sha256": "<64 hex>", "size_bytes": 1234 }
  ]
}
```

`completion_marker` is a tagged enum: `{"state":"complete"}` or
`{"state":"partial","reason":"..."}`. `deny_unknown_fields` is enforced on the
manifest and every nested object; an unknown field makes the bundle invalid.

## 3. Required members

Every member file's JSON top-level `schema_version` must be exactly:

| member | expected schema |
|---|---|
| `oep_evidence` | `mida.oreans-oep-evidence/v1` |
| `iat_evidence` | `mida.oreans-iat-evidence/v1` |
| `tls_evidence` | `mida.oreans-tls-evidence/v1` |
| `relocation_evidence` | `mida.oreans-relocation-evidence/v1` |
| `section_rebuild_evidence` | `mida.oreans-section-rebuild-evidence/v1` |
| `pe_evidence` | `mida.oreans-pe-evidence/v1` |
| `transform_manifest` | `mida.transform-manifest/v0` |

The transform manifest must additionally bind the same candidate identity
(`candidate_sha256` + `candidate_size_bytes` equal to the manifest's
`candidate` object).

## 4. Validation rules (fail-closed, in `mida-acceptance`)

1. `schema_version` is exactly `mida.oreans-evidence-bundle/v1`.
2. `runner_config_digest` is exactly 64 hexadecimal characters.
3. Identities are 64-hex SHA-256 with size > 0; `case_id`, `tool_revision`,
   and `emitted_at` are non-empty.
4. Member names are unique; every member file is present and its bytes match
   the declared SHA-256 and size exactly.
5. `bundle_sha256` matches the recomputed canonical hash (below).
6. Every required member is declared, and its JSON `schema_version` matches
   the expected schema id (black-box producer compatibility).
7. The transform manifest binds the declared candidate identity.
8. `completion_marker: partial` is invalid; `complete` is honored only when
   every other check passed.

## 5. Canonical bundle hash

SHA-256 over the UTF-8 concatenation of lines `name|sha256|size\n` for all
members sorted lexicographically by `name`, lowercase hex SHA-256. Any member
addition, removal, reorder, or byte change changes the hash; the manifest
therefore cannot be edited without invalidating itself.

## 6. Black-box boundary

`mida-acceptance` defines its own serde types for the bundle contract. It must
not import producer types from `mida-cli`/`mida-pe`. Schema drift is caught by
the offline tests:

- `crates/acceptance/src/evidence_bundle.rs` — unit tests (10)
- `crates/acceptance/tests/evidence_bundle.rs` — synthetic
  producer->bundle->consumer black-box tests (4)

Run:

```powershell
cargo test -p mida-acceptance --offline
```

## 7. Not yet done (next steps)

- The CLI/runner does not yet emit the bundle manifest; a `bundle-assembler`
  step (Lab agent) must aggregate the existing sidecars and write it
  atomically next to the candidate.
- The v8 gate should consume the bundle inventory as its input envelope so
  "which files belong to this run" stops being implicit.
- The `runner_config_digest` value must come from the frozen runner policy
  that the 10/10 replay records.
