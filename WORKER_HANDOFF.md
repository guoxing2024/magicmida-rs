# WORKER_HANDOFF — VNEXT-R0B close-out → R1

## Summary

R0B independent acceptance kernel (`mida-acceptance`) is the static structural
judge. This handoff closes residual CLI/contract hygiene and points next work at
**VNEXT-R1** (pure PE model).

## R0B contract

- `docs/ACCEPTANCE_CONTRACT.md`
- Verdicts: `Rejected` | `StructuralPassBehaviorPending` | `Accepted` (forbidden in R0B)
- Independent PE byte parser; **not** `pelite` / `mida-pe`
- `residual_risks` is **empty** under the independent-parser posture
- Oracle files are comparison observations only

## CLI

```text
mida-acceptance check-static <candidate> [--expected-sha256 HEX]
                                         [--expected-size N]
                                         [--role ROLE]
                                         [--oracle PATH]
                                         [--report PATH]
```

| Exit | Meaning |
|------|---------|
| 0 | `StructuralPassBehaviorPending` |
| 2 | `Rejected` |
| 1 | I/O / config / internal error (includes report path aliasing an input) |

Report writes must not alias candidate or oracle (path or hard link). Inputs stay
byte-identical on rejection of the report path.

## Boundaries

- No deps on `mida-core`, `mida-pe`, `mida-tracer`, `mida-packers-*`, `mida-cli`, `mida-disasm`
- No Win32 process/debug APIs in the acceptance library; CLI may use OS identity
  checks only to protect input files from report overwrite
- Evidence: run `cargo test -p mida-acceptance --test dependency_boundary` (writes
  local `dependency_boundary.json`, gitignored)

## Validation

```powershell
$env:CARGO_TARGET_DIR = '<vault>\scratch\cargo-target'
cargo test -p mida-acceptance --offline
cargo fmt --all -- --check
powershell -File tools\verify_workspace_hygiene.ps1
```

## Next: R1

See [docs/VNEXT_R1_ROADMAP.md](docs/VNEXT_R1_ROADMAP.md).

Out of R0B scope: behavioral `Accepted`, runtime event engine (R2), Oreans plugin (R3).
