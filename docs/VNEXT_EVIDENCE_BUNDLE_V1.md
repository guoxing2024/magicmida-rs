# Evidence Bundle — `mida.oreans-evidence-bundle/v2`

**Status:** contract ratified (2026-08-04), offline-tested in `mida-acceptance`
and verified with `cargo deny check` (cargo-deny 0.20.2).
**Scope:** one isolated unpack run for one of the two fixed Oreans cases must
produce exactly one bundle. This document is the producer->consumer wire
contract; the consumer (`mida-acceptance::validate_evidence_bundle`) is the
only authority on bundle validity.

## 0. v2 amendments (v1 withdrawn pre-production)

v1 (`mida.oreans-evidence-bundle/v1`) never shipped from any producer and is
withdrawn. v2 changes:

1. `bundle_sha256` (member list only) renamed **`members_sha256`**.
2. New sealed **`manifest_sha256`** covers every top-level field and every
   member field, including `relative_path`.
3. Every required sidecar's `protected_input`/`candidate` identity objects are
   re-parsed and cross-checked against the bundle identities. Swapping a
   sidecar's identity and recomputing all hashes still fails.
4. `relative_path` is validated: relative only, no `.`/`..` components, no
   drive letters or `:`, and unique across members.

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
schemas the gate consumes, whose embedded identities disagree with the bundle
identities, or whose transform manifest binds a different candidate is
invalid, even if every other field parses.

## 2. Manifest shape

```json
{
  "schema_version": "mida.oreans-evidence-bundle/v2",
  "case_id": "origin_macro",
  "tool_revision": "oreans/two-sample-mainline@<frozen-commit>",
  "runner_config_digest": "<64 hex chars>",
  "emitted_at": "2026-08-04T12:00:00Z",
  "completion_marker": { "state": "complete" },
  "protected_input": { "sha256": "<64 hex>", "size_bytes": 5232656 },
  "candidate": { "sha256": "<64 hex>", "size_bytes": 4096 },
  "members_sha256": "<64 hex>",
  "manifest_sha256": "<64 hex>",
  "members": [
    { "name": "oep_evidence", "relative_path": "evidence/oep_evidence.json",
      "sha256": "<64 hex>", "size_bytes": 1234 }
  ]
}
```

`completion_marker` is a tagged enum: `{"state":"complete"}` or
`{"state":"partial","reason":"..."}`. `deny_unknown_fields` is enforced on the
manifest and every nested object; an unknown field makes the bundle invalid.

`relative_path` must be relative (no leading `/` or `\`, no drive letter), free
of `.`/`..` components and `:`, and unique across members.

Free-text fields reject control characters (including CR/LF/NUL) and the
canonical-hash separators `|` and `=`. Identifiers (`case_id`,
`tool_revision`, member names, `relative_path`) additionally reject `:`;
timestamps (`emitted_at`) and the completion reason may contain `:` because
their canonical lines split at the first separator and stay unambiguous.

## 3. Required members

Every member file's JSON top-level `schema_version` must be exactly:

| member | expected schema | embedded identity to check |
|---|---|---|
| `oep_evidence` | `mida.oreans-oep-evidence/v1` | `protected_input` + `candidate` |
| `iat_evidence` | `mida.oreans-iat-evidence/v1` | `protected_input` + `candidate` |
| `tls_evidence` | `mida.oreans-tls-evidence/v1` | `protected_input` + `candidate` |
| `relocation_evidence` | `mida.oreans-relocation-evidence/v1` | `protected_input` + `candidate` |
| `section_rebuild_evidence` | `mida.oreans-section-rebuild-evidence/v1` | `protected_input` + `candidate` |
| `pe_evidence` | `mida.oreans-pe-evidence/v1` | `candidate` only |
| `transform_manifest` | `mida.transform-manifest/v0` | flat `candidate_sha256` + `candidate_size_bytes` |

Each identity object is `{"sha256": "<64 hex>", "size_bytes": N}` and must
equal the bundle's `protected_input` / `candidate` objects exactly. This seals
the identity chain: recomputing member hashes after a sidecar identity swap
cannot launder the bundle.

## 4. Validation rules (fail-closed, in `mida-acceptance`)

1. `schema_version` is exactly `mida.oreans-evidence-bundle/v2`.
2. `runner_config_digest` is exactly 64 hexadecimal characters.
3. Identities are 64-hex SHA-256 with size > 0; `case_id`, `tool_revision`,
   and `emitted_at` are non-empty.
4. Member names and `relative_path` values are unique; paths are relative,
   without `.`/`..`/`:`; free-text fields are free of control characters and
   the canonical separators `|`/`=` (identifiers also free of `:`).
5. Every member file is present and its bytes match the declared SHA-256 and
   size exactly.
6. `members_sha256` matches the canonical member-set hash and
   `manifest_sha256` matches the canonical full-manifest hash (below).
7. Every required member is declared, its JSON `schema_version` matches the
   expected schema id, and its embedded identities match the bundle
   (black-box producer compatibility + identity-chain sealing).
8. The transform manifest binds the declared candidate identity.
9. `completion_marker: partial` is invalid; `complete` is honored only when
   every other check passed.

## 5. Canonical hashes

`members_sha256`: SHA-256 over the UTF-8 concatenation of lines
`name|sha256|size\n` for all members sorted lexicographically by `name`,
lowercase hex SHA-256.

`manifest_sha256`: SHA-256 over the UTF-8 concatenation of lines below, in
this exact order, with member lines sorted by name:

```text
schema_version=<v>
case_id=<id>
tool_revision=<rev>
runner_config_digest=<digest>
emitted_at=<ts>
completion_marker=complete            (or "partial:<reason>")
protected_input=<sha>:<size>
candidate=<sha>:<size>
members_sha256=<members hash>
member=<name>:<relative_path>:<sha256>:<size>
```

The `manifest_sha256` field itself is excluded (self-reference); every other
field — including `members_sha256` and each member's `relative_path` — is
covered. Editing the manifest or any member file without recomputing both
hashes invalidates the bundle.

## 6. Black-box boundary

`mida-acceptance` defines its own serde types for the bundle contract. It must
not import producer types from `mida-cli`/`mida-pe`. Schema drift is caught by
the offline tests:

- `crates/acceptance/src/evidence_bundle.rs` — unit tests (18)
- `crates/acceptance/tests/evidence_bundle.rs` — synthetic
  producer->bundle->consumer black-box tests (6), including an
  attacker-style test that swaps a normal sidecar's candidate identity and
  recomputes every hash, which must still fail.

Run:

```powershell
cargo test -p mida-acceptance --offline
```

## 7. Not yet done (next steps)

- The CLI/runner does not yet emit the bundle manifest; a `bundle-assembler`
  step (Lab agent) must aggregate the existing sidecars, compute both
  canonical hashes, and write the manifest atomically next to the candidate.
- The v8 gate should consume the bundle inventory as its input envelope so
  "which files belong to this run" stops being implicit.
- The `runner_config_digest` value must come from the frozen runner policy
  that the 10/10 replay records.
