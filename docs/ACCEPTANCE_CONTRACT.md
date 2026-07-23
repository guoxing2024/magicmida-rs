# Acceptance Contract (VNEXT-R0B)

This document defines the independent acceptance kernel contract. The kernel
judges candidate PE files by **static structure only** in R0B. It does not
unpack, execute samples, attach debuggers, call Win32 APIs, or apply packer
heuristics.

The acceptance crate (`mida-acceptance`) must not depend on production crates
`mida-core`, `mida-pe`, `mida-tracer`, `mida-packers-*`, or `mida-cli`.

## Verdicts

Every completed static evaluation yields exactly one of three verdicts.

### `Rejected`

The candidate fails one or more fail-closed structural gates, or its
`ArtifactIdentity` does not match the file bytes (digest and/or size).

`Rejected` is terminal for acceptance purposes: no oracle, legacy output, or
operator claim may promote a `Rejected` result.

### `StructuralPassBehaviorPending`

The candidate passes all implemented static structural gates and identity
checks. Behavioral equivalence, loader runtime success, and production
acceptance remain **unproven**.

This is the only non-reject success path available in R0B. It is **not**
product acceptance.

### `Accepted`

Reserved for a future phase that combines structural gates with independent
behavioral evidence under the acceptance kernel (see
[VNEXT_ARCHITECTURE.md](VNEXT_ARCHITECTURE.md)).

**R0B rule:** no code path in this phase may return `Accepted` for any input.
Returning `Accepted` is a contract violation.

## Artifact identity

An evaluation is bound to an `ArtifactIdentity`:

| Field | Meaning |
|-------|---------|
| `sha256` | Lowercase hex SHA-256 of the candidate file bytes |
| `size_bytes` | Exact byte length of those bytes |
| `role` | Declared artifact role (for example `candidate`) |
| `expected_sha256` | Optional caller-supplied digest that must match `sha256` |

If `expected_sha256` is supplied and does not match the computed digest, or if a
declared size does not match the file length, the result is **fail-closed**
`Rejected`. Identity mismatches are never warnings.

## Static structural gates (R0B)

Gates run against raw bytes with an independent parser. Failures accumulate;
the final verdict is `Rejected` if any gate fails.

Minimum coverage:

1. DOS / NT / optional header bounds and signatures.
2. PE32 vs PE32+ optional-header magic consistency with COFF machine.
3. Section table: RVA/raw ranges, overlap, and integer overflow.
4. `SizeOfHeaders`, `SizeOfImage`, file and section alignment invariants.
5. Entry point RVA must land in an executable section that has raw file backing.
6. Import and IAT directories: descriptor, thunk, name, and ordinal bounds.
7. Export, TLS, base relocation, and exception directories: basic structure and
   bounds.
8. ASLR-related flags vs relocation state consistency.
9. Data directories must not extend past image or file bounds.

## Deterministic report

Each evaluation produces a JSON report with:

- `schema_version`
- `artifact` identity
- `verdict`
- ordered `gates`
- `failures`
- `warnings`
- `residual_risks`
- optional `oracle_observations`

The same input bytes and options must produce **byte-identical** JSON across
runs. Reports must not embed timestamps, hostnames, or absolute paths.

## Oracle rules

A legacy oracle (historical dump or prior tool output) may be supplied only as a
comparison source.

- Oracle presence, match, or mismatch may emit **comparison observations** only.
- Oracle state must not convert `Rejected` into a pass.
- Oracle state must not produce `Accepted`.
- Oracle absence is not a failure by itself.

Legacy oracles are never authorities for acceptance.

## CLI contract

```text
mida-acceptance check-static <candidate> [--expected-sha256 <hex>]
                                         [--expected-size <bytes>]
                                         [--role <role>]
                                         [--oracle <path>]
                                         [--report <path>]
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Verdict is `StructuralPassBehaviorPending` |
| `2` | Verdict is `Rejected` |
| `1` | I/O, configuration, or internal error (no PE verdict) |

The CLI is read-only with respect to the candidate and oracle files.
`--report` must not alias the candidate or oracle path (including hard links).
If a report path aliases an input, the CLI exits with code `1` and leaves the
input bytes unchanged.

## Residual risks

Any residual coupling (for example a shared third-party PE parser crate also
used by production code) must appear in the report `residual_risks` array.

**R0B rule:** the kernel implements an independent byte-level PE parser and
must not depend on `pelite`, `mida-pe`, or other production unpacker crates.
Under that independent-parser posture, `residual_risks` is **always empty**
(`[]`). Introducing a shared parser or production dependency is a contract
change that must repopulate this array and update this document.

## Non-goals (R0B)

- Unpacking algorithms
- Live process or sample execution
- Network access
- Vault / quarantine mutation
- Behavioral equivalence scoring
- Production release gates beyond structural MVP

## Behavioral path (post-R0B; not active in R0B)

Structural gates remain as specified above. A future phase may compose
**pre-recorded** behavioral evidence with a structural pass to allow
`Accepted`. That work is tracked in
[VNEXT_BEHAVIORAL_PATH.md](VNEXT_BEHAVIORAL_PATH.md) (B-A0 contract).

Until a scheduled behavioral gate closes and this document is revised:

1. No library or CLI path may return `Accepted`.
2. Evidence files alone do not change `check-static` results.
3. Probes run **outside** the acceptance crate; the kernel only validates
   evidence identity binding and composition rules when that CLI mode ships.

