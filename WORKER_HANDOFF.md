# WORKER_HANDOFF - VNEXT-R1-E closed (pure/legacy structural corpus) -> R2

## Summary

R0B (`mida-acceptance`) remains the independent static structural judge.
**R1-A..C** established pure PE APIs, buffer safety, offline rebuild, and
`plan_from_memory_image` byte-map adapters.
**R1-D** wired pure rebuild into the **production dump path** as an **opt-in**
emit path (`DumpOptions.pure_rebuild` / CLI `--pure-rebuild`).
**R1-E** closed: host-built import/IAT directories and section VAs survive pure
emit, with offline dual-path structural corpus + independent R0B gates on pure
(and fair legacy) candidates. Default dump path remains legacy.

## R1-E deliverables (this slice)

| Artifact | Role |
|----------|------|
| `PlannedSection.virtual_address: Option<u32>` | Preserve host/map section RVAs during pure rebuild |
| `RebuildPlan.fallback_data_directories` | Carry host data directories when typed builders leave zeros |
| `PureRebuildEmitOptions.preserve_section_vas` | Default true: keep host section VAs |
| `PureRebuildEmitOptions.carry_host_data_directories` | Default true: copy host DD table as fallback |
| `PureRebuildParitySnapshot` | Offline pure-vs-host structural gates (not acceptance) |
| `emit_pure_rebuild_with_parity` | Emit + host/pure snapshots for parity tests |
| `byte_map::plan_from_memory_image` | Preserves section VAs + host DDs |

### Pure vs legacy dump paths (R1-E)

```text
dump_process(...)
  host: live capture, overlays, import section (extra_data), IAT fill
  |
  +-- opts.pure_rebuild == true  --> pure_rebuild_adapter::emit_pure_rebuild
  |       plan_from_host_dump:
  |         - section data from extra_data or VA dump slice
  |         - preserve_section_vas (host RVAs)
  |         - fallback_data_directories (import/IAT/TLS/...)
  |         - optional exception/reloc typed rebind
  |       rebuild_pe_image_with_meta -> PE bytes
  |
  +-- opts.pure_rebuild == false --> legacy write_output_file
          serialize_headers + section raw write + IAT patches
```

Default remains **legacy** (`pure_rebuild: false`). Flip only after parity
corpus shows pure >= legacy structural quality.

### Parity evidence criteria (pure vs legacy emit)

Structural gates (offline, unit-testable; **not** `mida-acceptance` verdicts):

1. **Arch / EP / base / subsystem** match host model after reparse.
2. **Import DD** (RVA+size) and **IAT DD** match host when host set them
   (content-carried `.import` + host directories).
3. **Critical section names** present: `.text`, `.import`, `.edata`, `.boot`,
   `.rdata`, `.data`, `.rsrc` when host had them.
4. **Host section VAs** preserved for content sections under
   `preserve_section_vas` (import DD targets remain valid).
5. **Typed rebind ownership**: when pure rebuilds exception/reloc sections,
   those DDs may point at pure-owned shells; host content shells are skipped.
6. **Out of scope for R1-E**: byte-identical files, runtime behavior, full
   import descriptor tree reparse (R2/R3 + acceptance).

`PureRebuildParitySnapshot::structural_mismatches` implements gates 1-3 (+ TLS
when both non-zero). Tests cover VA preserve + import/IAT DD carry.

### R1-E close-out evidence (landed)

Offline dual-path corpus in `pure_rebuild_adapter` unit tests (no vault samples):

| Test | What it proves |
|------|----------------|
| `r1e_dual_path_import_content_structural_corpus` | Host model with content-carried `.import` + import/IAT DDs → pure emit + legacy `write_output_file` → host↔pure `structural_mismatches` empty; both candidates `StructuralPassBehaviorPending` under independent `mida-acceptance::check_static` (never `Accepted`) |
| `r1e_dual_path_from_va_mapped_oracle_structural` | Pure-built oracle mapped to VA-linear `dump_buf` (index==RVA) → pure re-emit preserves import/IAT DDs + R0B structural pass |

Wiring notes:

- `mida-pe` **dev-dependency only** on `mida-acceptance` for dual-path corpus
  (production lib must not depend on acceptance; boundary remains one-way).
- Not byte-identical; not runtime. Typed import rebind still out of scope.

### Explicit non-goals (unchanged)

- No default flip of production dump to pure.
- No import rebind from live IAT inside pure modules (host extra_data only).
- No behavioral `Accepted` / runtime engine (R2) / Oreans plugin (R3).
- Pure modules still exclude Win32 / `DebuggerCore` / `mida_disasm`.
- Samples stay in vault only (`D:\MidaVault\objects\sha256\...`).

### Pure modules (unchanged from R1-C)

`error`, `utils`, `header/*`, `section`, `import_table`, `export_table`,
`exception_table`, `tls`, `relocation`, `rebuild`, `byte_map`, `postprocess`,
`apiset_data`.

### Still adapter / live

`dumper/*` live paths (including `pure_rebuild_adapter` host surface),
`original_imports` Win32 resolve, `remote_modules`, heap/container snapshots,
host symbol resolution for IAT.

## Boundaries (unchanged)

- `mida-acceptance` does **not** depend on `mida-pe` or other production crates.
- Pure PE modules must not gain `windows` / `DebuggerCore` / `mida_disasm`.
- Acceptance verdicts still forbid `Accepted` in R0B.
- Goal remains loader-valid + behaviorally equivalent samples judged by
  independent evidence — R1 only produces structural candidates.

## Validation (R1-E — closed)

```powershell
cargo check -p mida-pe -p mida-cli
cargo test -p mida-pe pure_rebuild
cargo test -p mida-pe r1e_dual_path
cargo test -p mida-pe --lib rebuild
cargo test -p mida-pe --lib byte_map
cargo test -p mida-pe --test purity_boundary
cargo test -p mida-acceptance
```

Optional live smoke (host sample / vault materialize to scratch, not CI):

```text
mida dump-process <sample> --pure-rebuild
# then mida-acceptance (or gate) on output; compare vs legacy dump
```

## Validation evidence (2026-07-23 Windows)

- Host: Windows 11; VS 2022 Professional MSVC 14.44 via `tools/_enter_msvc_env.ps1`.
- `CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target`
- `cargo test --workspace --offline`: **412 passed / 0 failed**
- `dependency_boundary` + `pe_purity_boundary`: pass
- `validation_summary.json` task: **VNEXT-R1-E**

## Suggested next slices

- **Live smoke**: vault Origin / Lunlun pure vs legacy dump → scratch + acceptance.
- **GTO** controlled run (if authorized); **Dali** remains OOS until policy says otherwise.
- **Import typed rebuild** (optional / R1-F?): host-resolved IAT → pure import builder.
- **R2**: runtime event / behavioral acceptance engine skeleton.
- Flip default only after live + acceptance corpus shows pure ≥ legacy structural quality.
