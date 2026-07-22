# MagicMida vNext

MagicMida vNext is a Windows PE unpacking research platform. Its long-term goal is
reliable, family-extensible unpacking with explicit evidence for every claim.

This repository is a canonical recovery baseline, not a general-purpose 1.0
release. The legacy Themida/Oreans implementation is retained so it can be split
behind stable interfaces and tested against an independent acceptance kernel. A
historical output, including the Origin macro oracle candidate, is regression
input only and is never proof that a new output is correct.

## Repository scope

The active repository contains only:

- Rust source and deterministic unit-test fixtures;
- v2 case manifests that refer to external artifacts by SHA-256;
- manifest and workspace-policy verifiers; and
- current architecture and artifact-policy documentation.

Samples, unpacked outputs, crash dumps, third-party tools, runtime logs, and build
output belong outside Git in a content-addressed vault. See
[ARTIFACT_POLICY.md](ARTIFACT_POLICY.md).

## Layout

```text
crates/
  acceptance/        independent acceptance kernel (static structural gates)
  core/              legacy debugger/process primitives
  pe/                PE parsing and rebuild code
  disasm/            instruction decoding and scan helpers
  tracer/            trace primitives
  packers/themida/   legacy Oreans/Themida implementation
  cli/               command-line adapter
lab/cases/v2/        case contracts; artifact references are SHA-256 only
tools/               repository hygiene verification
docs/                vNext architecture and acceptance contracts
```

The target boundaries for the rebuild are defined in
[docs/VNEXT_ARCHITECTURE.md](docs/VNEXT_ARCHITECTURE.md). The R0B acceptance
verdict contract is defined in
[docs/ACCEPTANCE_CONTRACT.md](docs/ACCEPTANCE_CONTRACT.md). Existing crate names
do not imply that those boundaries have already been achieved.

### Acceptance kernel (R0B)

`mida-acceptance` is an independent crate: it must not depend on production
unpacker crates. Static structural evaluation only; R0B never emits `Accepted`.
Report paths must not overwrite the candidate or oracle.

```powershell
cargo run -p mida-acceptance --offline -- check-static <candidate> `
  --expected-sha256 <hex> --expected-size <bytes> --report <report.json>
```

### Pure PE model (R1)

R1-A landed: pure vs adapter inventory and source purity lock for `mida-pe`.
API sketch: [docs/VNEXT_R1_PE_API.md](docs/VNEXT_R1_PE_API.md). Remaining R1
slices (parse/serialize extraction, production migration):
[docs/VNEXT_R1_ROADMAP.md](docs/VNEXT_R1_ROADMAP.md).

```powershell
cargo test -p mida-pe --test purity_boundary --offline
```

## Build and test

Use a Visual Studio developer shell, or another shell initialized with
`vcvars64.bat`, and keep Cargo output outside the repository:

```powershell
$env:CARGO_TARGET_DIR = '<vault>\scratch\cargo-target'
cargo fmt --all -- --check
cargo check --workspace --tests --offline
cargo test --workspace --offline
```

No sample is required for these commands. Tests that need binary fragments use
small, source-controlled fixtures governed by the artifact policy.

## Case manifests

Validate the v2 contracts against a populated SHA-256 object store:

```powershell
python -B lab\cases\verify_manifests.py --objects-root '<vault>\objects\sha256'
python -B -m unittest lab\cases\test_verify_manifests.py -v
```

The verifier checks schema semantics, object size/hash, forbidden legacy path
references, and self-certifying language. Dynamic execution remains forbidden
unless a case explicitly authorizes a fixed digest under an isolated runner.

## Release rule

"Universal" and "perfect" are goals, not status labels. A production release
requires an independent acceptance kernel, deterministic replay evidence,
holdout cases, and at least two production-quality packer-family plugins. The
Oreans suite must pass ten consecutive isolated runs before it can satisfy its
family gate.

## License

GPL-3.0. See [LICENSE](LICENSE).
