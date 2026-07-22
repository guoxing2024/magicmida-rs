# WORKER_HANDOFF — VNEXT-R1-A landed → R1-B

## Summary

R0B (`mida-acceptance`) remains the independent static structural judge.
**R1-A** documents the pure PE API surface, inventories `mida-pe` modules as
pure vs adapter, and locks pure module sources with an automated scan.

## R1-A deliverables

| Artifact | Role |
|----------|------|
| [docs/VNEXT_R1_PE_API.md](docs/VNEXT_R1_PE_API.md) | API sketch + module inventory + dep map |
| `crates/pe/tests/purity_boundary.rs` | Pure module source forbidden-pattern scan |
| `pe_purity_boundary.json` | Local evidence (gitignored) |

### Pure modules (locked)

`error`, `utils`, `header/*`, `section`, `import_table`, `relocation`,
`postprocess`, `apiset_data`.

### Still adapter / live (crate-level deps remain)

`dumper/*` live paths, `original_imports` Win32 resolve, `remote_modules`,
heap/container snapshots, `resolve_imports_via_getprocaddress`.

### Declared but unused in sources (hygiene debt)

`pelite`, `mida-disasm` on `mida-pe` — remove or gate in a later slice; not
required for R1-A exit.

## Boundaries (unchanged)

- `mida-acceptance` does **not** depend on `mida-pe` or other production crates.
- Pure PE modules must not gain `windows` / `DebuggerCore` / `mida_disasm`.
- Acceptance verdicts still forbid `Accepted` in R0B.

## Validation

```powershell
$env:CARGO_TARGET_DIR = '<vault>\scratch\cargo-target'
cargo test -p mida-pe --test purity_boundary --offline
cargo test -p mida-acceptance --offline
cargo fmt --all -- --check
powershell -File tools\verify_workspace_hygiene.ps1
```

## Next: R1-B

See [docs/VNEXT_R1_ROADMAP.md](docs/VNEXT_R1_ROADMAP.md).

1. Harden `PeHeader::from_bytes` + file offset ↔ RVA offline tests.
2. Round-trip serialize for fixture PEs (artifact policy).
3. Keep purity boundary green; move byte serialize out of live-only types when ready.

Out of scope: behavioral `Accepted`, runtime event engine (R2), Oreans plugin (R3).
