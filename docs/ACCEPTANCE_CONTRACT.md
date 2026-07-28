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

Structural gates pass **and** pre-recorded behavioral evidence binds to the
candidate with verdict `Pass`, composed only on the explicit
`check-with-behavior` path (see
[VNEXT_BEHAVIORAL_PATH.md](VNEXT_BEHAVIORAL_PATH.md) B-A2).

**R0B rule:** `check-static` / library `check_static` must never return
`Accepted` for any input. Returning `Accepted` on that path is a contract
violation.

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

mida-acceptance check-with-behavior <candidate> --behavior-evidence <json>
                                         [--expected-sha256 <hex>]
                                         [--expected-size <bytes>]
                                         [--role <role>]
                                         [--oracle <path>]
                                         [--report <path>]
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | `StructuralPassBehaviorPending` or `Accepted` (`Accepted` only via check-with-behavior) |
| `2` | Verdict is `Rejected` |
| `1` | I/O, configuration, invalid evidence, or internal error (no PE verdict) |

The CLI is read-only with respect to the candidate, oracle, and behavior-evidence
files. `--report` must not alias any of those paths (including hard links).
If a report path aliases an input, the CLI exits with code `1` and leaves the
input bytes unchanged.

`check-static` never returns `Accepted`. `check-with-behavior` loads
pre-recorded `mida.behavior-evidence/v0` JSON only; it does not run probes.

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

## Behavioral path (B-A2 compose; managed candidate)

Structural gates remain as specified above. **B-A2** composes **pre-recorded**
behavioral evidence with a structural pass to allow `Accepted` on the explicit
path only. Details:
[VNEXT_BEHAVIORAL_PATH.md](VNEXT_BEHAVIORAL_PATH.md).

### Managed vs unmanaged

| Path | API / CLI | Max verdict |
|------|-----------|-------------|
| Unmanaged | `check_with_behavior` / `--allow-unmanaged-candidate` | `StructuralPassBehaviorPending` |
| Managed | sibling `*.transform_manifest.json` + `VerifiedManagedCandidate::verify` + `check_with_behavior_managed` | `Accepted` possible |

Product `Accepted` additionally requires:

1. Registered product probe id (not `load_no_crash_v0`).
2. Bilateral / protected reference with digest.
3. Transform ledger consistent with dump-side manifest (manifest is authoritative).
4. Transform entries either empty (clean standard reconstruction) or covered by
   registered `(id, kind, rule)` triples — see
   [TRANSFORM_TAXONOMY_V1.md](TRANSFORM_TAXONOMY_V1.md).
5. **Authenticity (CLI default):** product `Accepted` on
   `check-with-behavior` requires a verified `SignatureEnvelope` with a
   **non-caller-controlled** trust root via `check_with_behavior_signed`
   (evidence sealed inside the bundle from hashed JSON). Missing envelope →
   managed compose is **capped** at `StructuralPassBehaviorPending` unless
   `--allow-unsigned-managed` (lab only). Caller-supplied HMAC requires
   `--allow-hmac-lab` and is **not** product authenticity. Ed25519 fixed
   allowlist is reserved / not yet shipped. Dumper never self-signs.

`sample_bypass` transforms (e.g. GTO fixed-RVA patches) **block** product Accept.
Capture-class ledger rows without registered rules also **block** Accept.

Library note: `check_with_behavior_managed` may still return `Accepted` without
an envelope (unit tests / internal). **CLI product posture** is the signed path.

Until a scheduled **VNEXT-BEH** gate closes **and** Ed25519 CI keys ship:

1. `check-static` / `check_static` must never return `Accepted`.
2. Evidence files alone do not change `check-static` results.
3. Probes run **outside** the acceptance crate; the kernel only validates
   evidence identity binding and composition on `check-with-behavior*`.
4. Default product path remains structural Pending; pure default flip is
   independent of this compose path.
5. Lab scripts may use `--allow-unsigned-managed` or `--allow-hmac-lab`; those
   flags are **not** product release claims.

