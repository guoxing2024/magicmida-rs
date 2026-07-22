# VNEXT-R1 Roadmap — Pure PE Model and Rebuild Pipeline

Status: **open after R0B close-out**. R0B (`mida-acceptance`) owns independent
static structural judgment. R1 extracts a pure PE model so production rebuild
code no longer mixes live process / Win32 policy with byte-level PE work.

## Goal

Provide a pure PE parse/layout/rebuild layer that:

- accepts byte buffers and typed values only;
- performs address translation (VA, RVA, file offset, preferred base, runtime base
  as typed wrappers — runtime base mapping may remain API-shaped stubs until R2);
- owns imports, exports, relocations, TLS, exception data, and serialization;
- does **not** call Win32, inspect a live process, or encode packer-family policy;
- can be consumed by packer plugins and the rebuild pipeline without importing
  debugger backends.

## Why R1 after R0B

Acceptance already judges candidates with an independent parser. Production
`mida-pe` still couples to `mida-core`, `windows`, and `mida-disasm`. R1 splits
the pure model so:

1. rebuild correctness can be tested offline with fixtures;
2. plugins stop reimplementing PE layout heuristics inside packer code;
3. R2 can attach a single runtime engine without PE modules owning process handles.

## Non-goals (R1)

- Behavioral acceptance / `Accepted` verdicts (later acceptance phases).
- Runtime event pump, breakpoints, or live acquisition (R2).
- Oreans/Themida family strategy (R3).
- Replacing `mida-acceptance` gates with production PE code (acceptance stays
  independent).

## Inventory of current coupling (baseline)

| Area | Crate / module | Coupling to remove or isolate |
|------|----------------|-------------------------------|
| PE crate root | `crates/pe` | `windows`, `mida-core`, `mida-disasm` deps |
| Header / sections | `header/`, `section` | Prefer pure buffer APIs; path-based loaders are thin adapters |
| Import reconstruction | `import_table` | No live process reads; memory views are input buffers |
| Relocations / postprocess | `relocation`, `postprocess` | No debugger callbacks |
| Dump / live helpers | any process-backed dump path | Move behind R2 runtime interfaces or quarantine as adapters |

Exact module splits may change; the contract is purity of the model API surface.

## Delivery slices

### R1-A — Boundary and API surface

1. Document the pure PE public API (parse, translate, mutate layout, serialize).
2. Introduce typed address wrappers if not already shared with a neutral crate
   (prefer not depending on debugger types).
3. Add a workspace hygiene / dependency note: pure modules must not use `windows`.
4. Keep `mida-acceptance` untouched and independent.

**Exit criteria:** written API sketch in-repo; no production unpacker behavior change required.

### R1-B — Pure parse + serialize core

1. Extract or harden parse of DOS/NT/optional headers, section table, data
   directories from buffers.
2. File offset ↔ RVA translation with overflow-safe arithmetic.
3. Round-trip serialize for fixture PEs (byte-stable where layout is fully known).
4. Unit tests with source-controlled fixtures only (artifact policy).

**Exit criteria:** offline tests pass without Win32; fixtures under
`crates/**/fixtures` with manifests.

### R1-C — Directories and rebuild primitives

1. Import / IAT / export / TLS / reloc / exception directory builders and validators
   as pure operations.
2. Rebuild pipeline that takes a typed image model + rebuild plan and emits PE bytes.
3. Optional thin adapters that feed live dumps **as byte/memory maps** (no Win32
   inside pure modules).

**Exit criteria:** rebuild unit tests for synthetic images; no packer plugin required.

### R1-D — Production migration

1. Point `mida-packers-*` / CLI rebuild paths at the pure API.
2. Leave legacy helpers behind feature flags or adapter modules until deleted.
3. Confirm workspace hygiene and offline `cargo test` for pe + consumers.

**Exit criteria:** no pure PE module imports `windows`; live code lives only in
adapters owned by core/tracer/runtime.

## Acceptance relationship

| Concern | Owner |
|---------|--------|
| Structural gates on candidates | `mida-acceptance` (R0B) — independent parser |
| Producing PE bytes | pure PE rebuild (R1) |
| Judging behavioral equivalence | future acceptance phases, not R1 |

Legacy dumps remain comparison inputs only. R1 must not teach acceptance to trust
production PE code.

## Validation checklist (R1 complete)

- [ ] Pure PE path builds and tests offline with `CARGO_TARGET_DIR` outside the repo.
- [ ] No `windows` / process APIs in pure PE modules.
- [ ] Fixture-only binary inputs; hygiene script clean.
- [ ] `mida-acceptance` still has zero production crate deps
      (`dependency_boundary` style check remains green).
- [ ] README / architecture docs list R1 status honestly (not product 1.0).

## Suggested first commit after R0B

Focus on **R1-A + inventory**: dependency map of `mida-pe`, mark pure vs adapter
modules, and add failing/placeholder tests that lock the purity boundary before
large moves.