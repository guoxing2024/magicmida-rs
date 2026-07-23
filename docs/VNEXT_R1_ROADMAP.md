# VNEXT-R1 Roadmap - Pure PE Model and Rebuild Pipeline

Status: **R1-A..E closed on synthetic/structural corpus** (2026-07-23 Windows
validation: workspace offline tests green under MSVC). Pure path remains opt-in
(`--pure-rebuild`); production dump still defaults to legacy.
R0B (`mida-acceptance`) owns independent static structural judgment. R1 extracts a
pure PE model so production rebuild code no longer mixes live process / Win32
inside layout math.

## Goals

1. Pure PE parse, address translation, and header/section serialization from
   byte buffers and typed values only.
2. Rebuild pipeline: `RebuildPlan` -> full PE image with directory wiring.
3. Host-side dump adapters feed maps into pure rebuild without Win32 inside pure
   modules.
4. Opt-in production emit (`--pure-rebuild`); keep legacy default until live +
   acceptance justify a flip.
5. Never claim product 1.0 or `Accepted` from structural gates alone.

## Slice map

### R1-A - Inventory + purity lock (done)

- Pure vs adapter module inventory documented.
- `purity_boundary` test + `pe_purity_boundary.json`.
- API surface doc: `docs/VNEXT_R1_PE_API.md`.

### R1-B - Pure parse / serialize core (done)

- Overflow-safe RVA/offset translation.
- Pure `PeHeader` parse + `serialize_headers`.
- Offline synthetic tests only.

### R1-C - RebuildPlan + directory builders (done)

- `rebuild_pe_image` with import/export/exception/TLS/reloc wiring.
- Pure byte-map adapters: `plan_from_memory_image`.
- Offline map -> plan -> PE round-trips without Win32.

### R1-D - Production migration (done, opt-in)

1. CLI / dump paths can emit via pure API (`--pure-rebuild`, `emit_pure_rebuild*`,
   `plan_from_host_dump`) after host dump fills a map / host state.
2. Legacy serialize path remains default until live + acceptance corpus justify flip.
3. Workspace offline `cargo test` green for pe + consumers under MSVC (2026-07-23).

**Exit criteria:** no pure PE module imports `windows`; live code lives only in
adapters owned by core/tracer/runtime. **Met** for pure module list + purity scan.

### R1-E - Pure/legacy dump parity (done on synthetic corpus)

Goal: pure emit can carry host-prepared dump state without breaking import/IAT
directories that point into content sections.

1. `PlannedSection.virtual_address` preserves host/map RVAs (optional pack when None).
2. `RebuildPlan.fallback_data_directories` applies host DDs only where typed
   builders left zeros (typed import/export/TLS/exception/reloc still win).
3. Host adapter defaults: `preserve_section_vas` + `carry_host_data_directories`.
4. `PureRebuildParitySnapshot` defines offline structural parity gates (not acceptance).
5. Production dump still defaults to legacy; pure remains opt-in.

**Exit criteria (R1-E):** unit tests pass for fixed-VA layout, fallback import/IAT
DD, adapter parity on synthetic host dump with `.import` extra_data; docs list
pure vs legacy paths and parity criteria; purity scan still green. **Met** (synthetic).

**Still open (not R1-E blockers):** live pure-vs-legacy smoke on vault samples;
typed import rebuild from host-resolved IAT; default flip to pure.

## Acceptance relationship

- R0B judges **bytes** only; pure rebuild is a **producer** of candidates.
- Structural pass from R0B is never product success (`Accepted` reserved for R2+).
- Dual-path offline corpus: pure emit -> `mida-acceptance` structural gate
  (acceptance is a **dev-dependency** of pe only for that corpus).

## Validation checklist (R1 complete)

- [x] Pure PE path builds and tests offline with `CARGO_TARGET_DIR` outside the repo
      (Windows 2026-07-23: `D:\MidaVault\scratch\cargo-target`, MSVC 14.44).
- [x] No `windows` / process APIs in pure PE modules (`pe_purity_boundary` pass).
- [x] Fixture-only binary inputs; no PE samples in Git.
- [x] `mida-acceptance` still has zero production crate deps
      (`dependency_boundary` pass).
- [x] README / architecture docs list R1 status honestly (not product 1.0).

## Suggested next work after R1

1. Live pure-vs-legacy smoke on vault samples (Origin / Lunlun to scratch).
2. Optionally lift import/export/TLS from maps into typed builders (still pure
   parsers, or host-resolved IAT to pure `ImportTableBuilder`).
3. Keep purity scan green; do not pull live dump modules into pure paths.
4. Flip default pure only after parity corpus + acceptance structural quality.
5. R2 runtime/event engine; R3 Oreans plugin boundary.
