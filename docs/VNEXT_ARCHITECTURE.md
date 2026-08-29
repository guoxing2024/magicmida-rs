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

> **Status note (2026-08-29):** The `gto_launcher` line is now governed by the
> owner-signed **GVM-0 anti-virtualization campaign** (2026-08-28,
> [GVM-0_RULING_20260828.md](GVM-0_RULING_20260828.md)): VM semantics recovery
> → lifter → whole-image devirtualization, three gated phases, dump route stays
> TERMINAL. The `xiongxiong_duokai` rev2 (WinLicense) perfect-unpack campaign
> closed 2026-08-28 (S1-S4). The R0B-R4 sequence below remains the engine/
> architecture contract and is not replaced by those campaigns.

1. `VNEXT-R0B`: build the independent acceptance kernel
   ([ACCEPTANCE_CONTRACT.md](ACCEPTANCE_CONTRACT.md); crate `mida-acceptance`).
2. `VNEXT-R1`: extract a pure PE model and rebuild pipeline
   ([VNEXT_R1_ROADMAP.md](VNEXT_R1_ROADMAP.md)).
3. `VNEXT-R2`: establish the single runtime/event engine and replay backend
   ([VNEXT_R2_RUNTIME_API.md](VNEXT_R2_RUNTIME_API.md) — Slice 0 docs sketch landed).
4. `VNEXT-R3`: implement the Oreans plugin and pass Origin, Lunlun, and a blind
   holdout ten consecutive times — **structural gate closed** (VNEXT-R3).
5. `VNEXT-R4`: add a second independent protection-family plugin
   ([VNEXT_R4_AHK_GTO_PATH.md](VNEXT_R4_AHK_GTO_PATH.md) — **structural gate closed**, VNEXT-R4).
6. `VNEXT-BEH`: independent behavioral acceptance
   ([VNEXT_BEHAVIORAL_PATH.md](VNEXT_BEHAVIORAL_PATH.md) — B-A0 contract only;
   `Accepted` still forbidden until a scheduled B-B gate).

General 1.0 eligibility begins only after steps 1-5 **and** a recorded
behavioral gate (step 6) pass their release rules. Structural R3/R4 alone is
not product acceptance.

## Current baseline

The canonical recovery commit preserves the previous implementation for
traceability. Its current coupling, heuristics, and historical tests are inputs
to refactoring; they are not the vNext architecture and do not establish product
acceptance.

**Strategic role split (see README):** the primary long-term target is
`gto_launcher`. The Oreans pair `origin_macro` + `lunlun_software` is the active
regression gate — the fail-closed wall that GTO work must not break and the
place where the structured evidence stack closes end-to-end first. Both families
target the same engine/plugin boundaries below; they share the engine, not the
policy.

### R1 progress

- **R1-A:** pure PE API sketch and module inventory
  ([VNEXT_R1_PE_API.md](VNEXT_R1_PE_API.md)); purity source scan on
  `mida-pe` pure-listed modules. Crate-level `windows` / `mida-core` remain for
  dump adapters.
- **R1-B:** pure parse/serialize and overflow-safe RVA/offset offline tests.
- **R1-C..E:** pure `RebuildPlan` rebuild pipeline + production opt-in pure emit
  ([VNEXT_R1_ROADMAP.md](VNEXT_R1_ROADMAP.md)). Phase2 live pure structural_equal
  on Origin/Lunlun; default dump remains legacy (flip=No).
- **R2-Slice0..4 + 3b-5/6:** addr + RuntimeEngine + CLI pump + `PackerPlugin` /
  `ThemidaPlugin` policy surface (3b-1..6: milestones, loop flags, thresholds,
  IAT skip vs complete, dump-enter host helpers, `plugin_host` extract) +
  Slice4 `ReplayMemory` / guard→OEP offline skeleton (handler bodies still in
  `cli/unpacker`) ([VNEXT_R2_RUNTIME_API.md](VNEXT_R2_RUNTIME_API.md)).
- **R3-path-A/B (not gate):** Oreans path contract, offline skip_v3 replay, multi-run
  EP/R0B harness; holdout schema slot + preflight (`holdout_status=empty` until a
  third vault Oreans sample is registered)
  ([VNEXT_R3_OREANS_PATH.md](VNEXT_R3_OREANS_PATH.md)). R3 structural 10× **closed**
  (2026-07-23); R4 structural **closed** (VNEXT-R4); pure flip still No;
  Behavioral Accepted not claimed. Behavioral path B-A0:
  [VNEXT_BEHAVIORAL_PATH.md](VNEXT_BEHAVIORAL_PATH.md).
