# VNEXT-R1 — Pure PE API Surface and Module Inventory

Status: **R1-A documented**; **R1-B pure parse/serialize core landed**;
**R1-C core rebuild pipeline landed** (synthetic full-image emit + import/export/
exception/TLS/reloc wiring) **plus pure byte-map adapters**
(`plan_from_memory_image` / exception+reloc rebind). Production `mida-pe` still
mixes pure layout work with live dump adapters for dump orchestration
(**R1-D** migration). This document freezes the pure surface and module
classification.

`mida-acceptance` remains an independent judge and must not depend on `mida-pe`.

## Pure PE contract (target)

A pure PE operation:

- accepts **byte buffers** and **typed PE values** only;
- performs layout math (VA / RVA / file offset / preferred base as typed numbers
  or future neutral wrappers);
- mutates or builds PE directories and serializes bytes;
- does **not** call Win32, touch a live process, or encode packer-family policy;
- may use `std::fs` only in **thin path loaders** that read whole files into
  buffers (adapters at the edge, not inside rebuild math).

Forbidden inside pure modules:

- `windows` crate / Win32 process or library-loader APIs;
- `mida_core::DebuggerCore` (or any debugger/process handle type);
- `mida_disasm` (family/runtime analysis belongs elsewhere);
- packer strategy (Oreans/Themida-specific policy).

## Public API sketch (pure)

Names reflect current types where they already fit; R1-B may re-export under a
clearer `mida_pe::pure` (or split crate) without changing acceptance.

### Parse

| API | Role |
|-----|------|
| `PeHeader::from_bytes(&[u8])` | Parse DOS/NT/optional headers + section table from a buffer |
| `PeHeader::from_file(path)` | Thin path loader → `from_bytes` (edge adapter) |
| Header structs | `ImageDosHeader`, `ImageFileHeader`, `ImageOptionalHeader`, `ImageNtHeaders`, `ImageDataDirectory`, `ImageSectionHeader`, `PeSection` |

### Address translation

| API | Role |
|-----|------|
| `PeHeader::rva_to_offset(rva)` | RVA → file offset via section table (checked arithmetic) |
| `PeHeader::offset_to_rva(offset)` | File offset → RVA (checked arithmetic) |
| `PeHeader::get_section_by_rva(rva)` | Section lookup (checked range end) |
| `align_up` / `file_align` / `section_align` | Alignment helpers |

Runtime-base mapping remains API-shaped for R2; pure R1 uses preferred base and
caller-supplied bases as integers/wrappers, not process handles.

### Layout mutation

| API | Role |
|-----|------|
| `PeHeader::create_section_*` / `delete_section` / `rename_*` | Section table edits |
| `PeHeader::sanitize` / `trim_huge_sections` | Layout cleanup on the model + buffer |
| `PeSectionData` | Optional attached section bytes for rebuild |

### Directories / builders (pure builders)

| API | Role |
|-----|------|
| `ImportThunk`, `ImportModule`, `ImportTableBuilder` | Build import directory / IAT bytes |
| `ExportFunction`, `ExportTableBuilder` | Build export directory / EAT / names / ordinals |
| `RuntimeFunction`, `ExceptionTableBuilder` | Build exception / `.pdata` RUNTIME_FUNCTION table (+ optional embedded UNWIND_INFO) |
| `TlsDirectoryBuilder` | Build TLS directory + template + callbacks (absolute VAs from image_base) |
| `RelocationTableBuilder` | Build `.reloc` bytes |
| `postprocess_image` / `pack_*` / `build_relocation_table` | Buffer-level fixups (no live process) |
| `RebuildPlan`, `PlannedSection`, `rebuild_pe_image` | Typed plan → full PE image bytes (R1-C core) |
| `rebuild_pe_image_with_meta` | Same emit + directory layout metadata for tests/adapters |
| `ImageByteMap`, `ByteMapPlanOptions`, `plan_from_memory_image` | Memory/VA-linear dump bytes → pure `RebuildPlan` (no host I/O) |
| `slice_rva` / `section_bytes_from_map` | Checked map slices for section payloads |
| `exception_builder_from_map` / `relocations_from_map` | Rebind exception + basereloc directories into typed plan fields |
| `rebuild_from_memory_image` | Convenience: map → plan → PE bytes (structural candidate only) |
| `directory_hints` | Which data directories are non-empty on a map (adapter diagnostics) |

### Serialize

| API | Role |
|-----|------|
| `PeHeader::serialize_headers()` | Emit PE signature + COFF + optional header + section table (+ legacy `0x200` pad). Pure buffer math; no Win32. |
| `rebuild_pe_image` / `rebuild_pe_image_with_meta` | Full-image emit: DOS stub + NT/headers + section payloads + optional `.edata` / `.idata` / `.pdata` / `.tls` / `.reloc` |

**R1-B:** `serialize_headers` lives on pure `header::PeHeader`. Dump adapters still call it;
`dumper/serialize.rs` is a compatibility stub only.

**R1-C (core):** `rebuild.rs` materializes export/import/exception/tls/reloc sections,
assigns VA/raw layout, splices `serialize_headers` into a DOS image, and round-trips
via `PeHeader::from_bytes`. Still pure: no Win32 / process handles.

**R1-C (byte-map adapters):** `byte_map.rs` accepts a VA-linear image buffer and
produces a `RebuildPlan` (section payloads + optional exception/reloc rebind).
Host dump code may fill the map; pure modules never open processes.

### Explicitly **not** pure (adapters / host)

| API / module | Why |
|--------------|-----|
| `dump_process`, `dump_dotnet`, `DumpOptions`, … | Live process dump |
| `rebuild_import_table` (dumper path) | Reads IAT via debugger |
| `resolve_imports_via_getprocaddress` | Win32 `LoadLibrary` / `GetProcAddress` |
| `remote_modules`, dumper helpers | `ReadProcessMemory`, `VirtualQueryEx`, toolhelp |
| `dll_exports` host path search | Hardcoded `System32` / host FS policy |
| `apiset` debugger-shaped entry | Signature takes `DebuggerCore` |

## Module inventory (`crates/pe/src`)

Classification is **source-level intent** for R1. Crate-level `Cargo.toml` still
lists `mida-core` and `windows` because adapters remain in-tree.

### Pure (must stay free of Win32 / debugger types)

| Path | Notes |
|------|--------|
| `error.rs` | Error types |
| `utils.rs` | Alignment / flag helpers |
| `header/mod.rs`, `header/tests.rs` | Parse + translate + `serialize_headers`; `from_file` is thin FS edge |
| `section.rs` | Section table ops on `PeHeader` |
| `import_table.rs` | Import directory builder (buffers only) |
| `export_table.rs` | Export directory builder (buffers only) |
| `exception_table.rs` | Exception / `.pdata` RUNTIME_FUNCTION builder (+ optional UNWIND_INFO) |
| `tls.rs` | TLS directory builder (buffers only; absolute VAs from image_base) |
| `relocation.rs` | Reloc table builder |
| `rebuild.rs` | Rebuild plan → full PE bytes (export/import/exception/tls/reloc dirs wired) |
| `byte_map.rs` | Memory/VA map → `RebuildPlan` + exception/reloc rebind (buffers only) |
| `postprocess.rs` | Image buffer postprocess |
| `apiset_data.rs` | Static ApiSet tables (data only) |

### Mixed / migrate later

| Path | Notes |
|------|--------|
| `apiset.rs` | Static resolve is pure-shaped; live helper takes `DebuggerCore` |
| `original_imports.rs` | PE-file import read vs Win32 resolve |
| `dll_exports.rs` | Export parse from path/bytes vs host System32 search |
| `dumper/serialize.rs` | Stub only after R1-B; real emit is on `PeHeader` |
| `header_patch.rs`, `import_section.rs`, … | Byte work still lives next to live dump orchestration |

### Adapter / live (R2 boundary or quarantine)

| Path | Coupling |
|------|----------|
| `dumper/dump_process.rs` | `DebuggerCore`, process memory |
| `dumper/helpers.rs` | `windows` Virtual\* / RPM |
| `dumper/remote_modules.rs` | Toolhelp + RPM |
| `dumper/heap_*`, `container_*`, `data_snapshot`, `global_vars`, `import_rebuild` | Debugger reads |
| `dumper/mod.rs` | Public re-exports of live dump API |

## Crate dependency map (baseline)

| Dependency | Role today | R1 target |
|------------|------------|-----------|
| `mida-core` | Debugger traits for dump path | Adapters only; pure modules must not import |
| `windows` | Live memory / module / GetProcAddress | Adapters only |
| `tracing` | Logging | Allowed in pure (observability) |
| `thiserror` | Errors | Allowed |
| `pelite` | **Declared, unused in sources** | Remove or gate when convenient (R1 hygiene) |
| `mida-disasm` | **Declared, unused in sources** | Remove or keep out of pure PE forever |

## Enforcement

- Integration test: `crates/pe/tests/purity_boundary.rs`
  - Scans **pure-listed** source files for forbidden imports/APIs.
  - Writes local `pe_purity_boundary.json` (gitignored) as evidence.
- Does **not** require deleting live dump code in R1-A.
- Does **not** change `mida-acceptance` boundaries.

## Exit criteria

### R1-A

- [x] Written API sketch + inventory (this document)
- [x] Pure module list locked by automated source scan
- [x] Acceptance crate remains independent
- [x] No required production unpacker behavior change

### R1-B

- [x] `PeHeader::from_bytes` + overflow-safe RVA/offset offline tests
- [x] `serialize_headers` on pure `PeHeader` with PE32 / PE32+ round-trips
- [x] Offline tests without Win32 (`crates/pe/tests/pure_parse_serialize.rs`)
- [x] Artifact policy: no PE-image binaries in-repo; synthetic buffers only
      (hygiene forbids `pe_image_content` under fixtures)

### R1-C (in progress)

- [x] Pure `RebuildPlan` → full PE bytes (`crates/pe/src/rebuild.rs`)
- [x] Import + basereloc directories wired on synthetic images (offline unit tests)
- [x] Export + TLS pure builders + `RebuildPlan` wiring (offline unit tests)
- [x] Exception / `.pdata` pure builder + validators + `RebuildPlan` wiring
- [x] `rebuild.rs` / `export_table.rs` / `exception_table.rs` / `tls.rs` on purity lock
- [x] Thin pure byte-map adapters (`byte_map.rs`) feeding maps into `RebuildPlan`
      (exception + basereloc rebind; imports/exports/TLS stay content or host-resolved)

Next: **R1-D** production migration (`docs/VNEXT_R1_ROADMAP.md`) — point dump/
packer/CLI rebuild at pure `rebuild_pe_image` / `plan_from_memory_image`.

## R1-E pure/legacy parity notes

### Dump emit paths

| Path | Trigger | Owner |
|------|---------|--------|
| Legacy | `DumpOptions.pure_rebuild = false` (default) | `write_output_file` in `dumper` |
| Pure | `pure_rebuild = true` / CLI `--pure-rebuild` | `pure_rebuild_adapter::emit_pure_rebuild` → pure `rebuild_pe_image` |

Host still owns live capture, overlays, import section `extra_data`, and IAT
construction. Pure path serializes a `RebuildPlan` only.

### Plan fields added for parity

| Field | Meaning |
|-------|---------|
| `PlannedSection.virtual_address` | Optional fixed section RVA (host dump layout) |
| `RebuildPlan.fallback_data_directories` | Host DD table applied when typed rebuild left zero |

### Adapter options

| Option | Default | Role |
|--------|---------|------|
| `rebind_exceptions` | true | Typed `.pdata` rebind from VA map |
| `rebind_relocations` | true | Typed basereloc rebind from VA map |
| `preserve_section_vas` | true | Keep host section RVAs |
| `carry_host_data_directories` | true | Fallback import/IAT/TLS/… DDs |

### Parity evidence (offline)

`PureRebuildParitySnapshot` compares host model vs reparsed pure emit for
arch/EP/base/subsystem, import+IAT directories, and critical section names.
Does **not** replace `mida-acceptance` (R0B).

- [x] Fixed section VA layout in pure rebuild
- [x] Fallback data directories for content-carried import/IAT
- [x] Host adapter preserve VAs + carry DDs
- [x] Synthetic parity unit tests (no vault samples)
