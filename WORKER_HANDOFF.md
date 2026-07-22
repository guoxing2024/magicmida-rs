# WORKER_HANDOFF — VNEXT-R0B-1

## Summary

Added independent acceptance kernel crate **`mida-acceptance`** (`crates/acceptance`)
implementing static PE structural gates, fail-closed artifact identity, deterministic
JSON reports, legacy-oracle comparison observations only, and a read-only CLI.

## Contract

- `docs/ACCEPTANCE_CONTRACT.md` — `Rejected` | `StructuralPassBehaviorPending` | `Accepted`
- R0B: **`Accepted` is never returned**

## CLI

```text
mida-acceptance check-static <candidate> [--expected-sha256 HEX] [--role ROLE]
                                         [--oracle PATH] [--report PATH]
```

| Exit | Meaning |
|------|---------|
| 0 | `StructuralPassBehaviorPending` |
| 2 | `Rejected` |
| 1 | I/O / config / internal error |

## Boundaries

- Does **not** depend on `mida-core`, `mida-pe`, `mida-tracer`, `mida-packers-*`, `mida-cli`
- No Win32, process launch, debugger, or packer heuristics
- Independent PE byte parser (not `pelite`); residual risks empty
- Evidence: `dependency_boundary.json` (`pass: true`)

## Production code touch set

- Workspace member registration (`Cargo.toml`, `Cargo.lock`)
- README + architecture doc links only
- No changes to unpacker/debugger production logic

## Validation

See `validation_summary.json` and `cargo_test.txt`. Workspace tests offline pass.
Manifest verifier (unit + vault) pass. Hygiene clean after this commit.

## Next (out of scope)

Behavioral acceptance path that can emit `Accepted`; pure PE model extraction (R1);
runtime event engine (R2).
