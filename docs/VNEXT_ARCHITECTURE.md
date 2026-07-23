# MagicMida vNext Architecture Contract

## Mission

Produce loader-valid, behaviorally equivalent PE files from protected Windows
binaries through a reusable engine and family-specific plugins. Correctness must
come from independent evidence, not from a plugin validating its own output.

## Non-negotiable boundaries

### Acceptance kernel

The acceptance kernel owns structural PE checks, loader-critical invariants,
behavioral evidence comparison, repeatability accounting, and final verdicts. It
must not import packer plugins, debugger backends, or their private heuristics.
Legacy outputs may be comparison candidates, never authorities.

### PE model and rebuild

PE parsing, address translation, layout, imports, exports, relocations, TLS,
exception data, and serialization form a pure layer. This layer accepts byte
buffers and typed values; it must not call Win32, inspect a live process, or
contain sample- or packer-specific policy.

### Runtime event engine

One event pump owns debug-event acknowledgement, thread/process handles,
breakpoints, and target lifetime. Runtime addresses use explicit typed wrappers
for VA, RVA, file offset, preferred base, and runtime base. Backends are:

- Win32 for authorized live acquisition; and
- replay for deterministic offline tests.

Neither backend decides how a packer family reaches OEP or reconstructs state.

### Packer plugins

A plugin identifies a protection family and implements only family strategy:
transition recognition, OEP evidence, decrypted-region selection, import
observation, and cleanup hints. It consumes runtime and PE interfaces and emits
evidence; it cannot bypass the acceptance kernel.

### Case and artifact layer

Case manifests are declarative contracts. Binary payloads live in the external
SHA-256 object store. A manifest records role, size, digest, capability cell,
execution policy, and oracle status without machine-specific paths or success
claims.

## Delivery sequence

1. `VNEXT-R0B`: build the independent acceptance kernel
   ([ACCEPTANCE_CONTRACT.md](ACCEPTANCE_CONTRACT.md); crate `mida-acceptance`).
2. `VNEXT-R1`: extract a pure PE model and rebuild pipeline
   ([VNEXT_R1_ROADMAP.md](VNEXT_R1_ROADMAP.md)).
3. `VNEXT-R2`: establish the single runtime/event engine and replay backend
   ([VNEXT_R2_RUNTIME_API.md](VNEXT_R2_RUNTIME_API.md) — Slice 0 docs sketch landed).
4. `VNEXT-R3`: implement the Oreans plugin and pass Origin, Lunlun, and a blind
   holdout ten consecutive times.
5. `VNEXT-R4`: add a second independent protection-family plugin.

General 1.0 eligibility begins only after steps 1-5 pass their recorded gates.

## Current baseline

The canonical recovery commit preserves the previous implementation for
traceability. Its current coupling, heuristics, and historical tests are inputs
to refactoring; they are not the vNext architecture and do not establish product
acceptance.

### R1 progress

- **R1-A:** pure PE API sketch and module inventory
  ([VNEXT_R1_PE_API.md](VNEXT_R1_PE_API.md)); purity source scan on
  `mida-pe` pure-listed modules. Crate-level `windows` / `mida-core` remain for
  dump adapters.
- **R1-B:** pure parse/serialize and overflow-safe RVA/offset offline tests.
- **R1-C..E:** pure `RebuildPlan` rebuild pipeline + production opt-in pure emit
  ([VNEXT_R1_ROADMAP.md](VNEXT_R1_ROADMAP.md)). Phase2 live pure structural_equal
  on Origin/Lunlun; default dump remains legacy (flip=No).
- **R2-Slice0:** runtime/plugin API sketch only
  ([VNEXT_R2_RUNTIME_API.md](VNEXT_R2_RUNTIME_API.md)); no live behavior change yet.
