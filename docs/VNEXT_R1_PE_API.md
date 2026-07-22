# VNEXT-R1-A — Pure PE API Surface and Module Inventory

Status: **R1-A documented**. Production `mida-pe` still mixes pure layout work with
live dump adapters. This document freezes the intended pure surface and the
module classification before large moves (R1-B+).

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
| `PeHeader::rva_to_offset(rva)` | RVA → file offset via section table |
| `PeHeader::offset_to_rva(offset)` | File offset → RVA |
| `PeHeader::get_section_by_rva(rva)` | Section lookup |
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
| `RelocationTableBuilder` | Build `.reloc` bytes |
| `postprocess_image` / `pack_*` / `build_relocation_table` | Buffer-level fixups (no live process) |

### Serialize

Target (R1-B/C): round-trip emit of PE bytes from the typed model + section
payloads. Today, serialization lives partly under `dumper::serialize` and is
still entangled with dump types — treat that as migration debt, not pure surface
yet.

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
| `header/mod.rs`, `header/tests.rs` | Parse + translate; `from_file` is thin FS edge |
| `section.rs` | Section table ops on `PeHeader` |
| `import_table.rs` | Import directory builder (buffers only) |
| `relocation.rs` | Reloc table builder |
| `postprocess.rs` | Image buffer postprocess |
| `apiset_data.rs` | Static ApiSet tables (data only) |

### Mixed / migrate later

| Path | Notes |
|------|--------|
| `apiset.rs` | Static resolve is pure-shaped; live helper takes `DebuggerCore` |
| `original_imports.rs` | PE-file import read vs Win32 resolve |
| `dll_exports.rs` | Export parse from path/bytes vs host System32 search |
| `dumper/serialize.rs`, `header_patch.rs`, `import_section.rs`, … | Byte work still lives next to live dump orchestration |

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

## Exit criteria (R1-A)

- [x] Written API sketch + inventory (this document)
- [x] Pure module list locked by automated source scan
- [x] Acceptance crate remains independent
- [x] No required production unpacker behavior change

Next: **R1-B** pure parse/serialize core and offline fixture tests
(`docs/VNEXT_R1_ROADMAP.md`).
