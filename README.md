# MagicMida vNext

MagicMida vNext is a Windows PE unpacking research platform. Its long-term goal is
reliable, family-extensible unpacking with explicit evidence for every claim.

This repository is a canonical recovery baseline, not a general-purpose 1.0
release. The legacy Themida/Oreans implementation is retained so it can be split
behind stable interfaces and tested against an independent acceptance kernel. A
historical output, including the Origin macro oracle candidate, is regression
input only and is never proof that a new output is correct.

Strategically, the primary long-term target is `gto_launcher`
(`D:\Tools\RE\dumps\gto\启动器.exe`). The Oreans `origin_macro` +
`lunlun_software` pair remains the active regression gate, but GTO is now a
first-class support line, not a side quest.

### Mutable GTO acquisition path (mandatory)

`D:\Tools\RE\dumps\gto\启动器.exe` is a **mutable locator**, not a sample
identity. The file may auto-update or be replaced without notice. Never run it
because its path or filename matches. Before any build, unpack, or live route,
resolve the bytes to an immutable vault object and compare it with the pinned
`protected_input` in `lab/cases/v2/gto_launcher.json`. Execute only the matching
vault object. A mismatch is `SampleIdentityMismatch` and must stop before
execution; a new digest requires a separately reviewed manifest revision.

Resolution is automated by a fail-closed preflight resolver:
`tools/resolve_gto_source_revision.ps1` (core
`tools/_resolve_gto_source_revision.py`). It resolves the manifest-authorized
vault object first and never re-reads the mutable path when the authorized
vault object already verifies. Exit codes are machine-consumable (see
`docs/GTO_SAMPLE_REVISION_POLICY.md` §3.5).

See [docs/GTO_SAMPLE_REVISION_POLICY.md](docs/GTO_SAMPLE_REVISION_POLICY.md).

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

### Current sample lines

The repository now has two explicit sample tracks:

- **Primary strategic line:** `gto_launcher`
  (`D:\Tools\RE\dumps\gto\启动器.exe`), with manifest
  `lab/cases/v2/gto_launcher.json`.
- **Active regression gate:** `origin_macro` + `lunlun_software`, with fixed
  identities and fail-closed gates documented in
  [docs/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md](docs/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md).

A structural `Accepted`, historical oracle match, Shiguang server/icon patch,
GTO holdout result, or retry-selected replay is not proof of perfect unpacking
for any line. The gate remains open until each declared line passes the
relevant OEP, IAT, TLS, relocation, section rebuild, behavior equivalence, and
10 consecutive isolated-run requirements. The evidence-bundle inventory contract
that makes a run record auditable is defined in
[docs/VNEXT_EVIDENCE_BUNDLE_V1.md](docs/VNEXT_EVIDENCE_BUNDLE_V1.md).
**Current status: not closed; this README makes no claim of perfect or
universal unpacking.**

### GTO default entry (G0) and shared mainline skeleton (G1)

`gto_launcher` is a first-class sample in the **default build**: the
`mida-packers-ahk-gto` plugin is a workspace member and `mida-cli` default
build, so a GTO-shaped layout (`.KI3` entry section, scrambled section names,
numbered `.data0`/`.data1` payload sections) is recognized and routed to the
`ahk_gto` family by `dual_select_packer` without any feature flag.

Since G1, the GTO family no longer runs a full independent host: it shares the
same mainline skeleton as Oreans — same `unpack` create-process, same
post-attach observation loop, same post-loop dump. The only family-specific
decision point is the observation policy (GTO uses UI-window / multi-section
watch; Oreans uses the plain-`.text` freeze). GTO-specific policy, profile,
capture hint, and evidence semantics are preserved in the plugin/policy layer.

Heavyweight GTO recovery still requires explicit opt-in:

- `cargo build -p mida-cli --features gto-product-recovery` for the recovery
  stages (shared-skeleton GTO path fails closed without it); and
- `--profile=ahk-gto-experimental` at unpack time for the experimental dump
  stages.

A default-build run that identifies GTO but is not opted in fails closed with a
clear error rather than silently running the experimental recovery path. Default
profile remains `oreans-classic`; no unpack silently becomes an experimental
GTO path.

GTO perfect unpack is **not** closed — the open work is the recovery itself
(no-bypass cold-start / heap-rebasing wall), not routing. The Oreans
`origin_macro` + `lunlun_software` regression gate must remain green: GTO work
must not break that fixed evidence stack.

### GTO preflight lane (G3, offline)

A separate, family-aware / no-gate GTO preflight lane is wired into the CLI and
acceptance code paths and covered by offline tests — see
[docs/GTO_PREFLIGHT_LANE.md](docs/GTO_PREFLIGHT_LANE.md). It stages `gto_launcher`
with `family_id=ahk_gto` into the envelope, attests it against that family, and
produces generic `mida.unpack-*` evidence with an explicit `no-gate` state. The
Oreans fixed two-sample lane is unchanged. **No real GTO sample has been run**:
this is lane-implementation-complete offline, NOT a completed/perfect/accepted
GTO result.

### Immutable sample identity (G3-R2)

`D:\Tools\RE\dumps\gto\启动器.exe` is a dynamic source path that automation
overwrites. Before staging/preflight, a source is frozen into an immutable,
content-addressed snapshot whose hash/size become the case identity; the source
path is provenance only. Capture is fail-closed (`source_changed_during_capture`
if the file changes mid-capture), revisions are hash-derived, and old revisions
stay reproducible by hash. See
[docs/SAMPLE_IDENTITY_LIFECYCLE.md](docs/SAMPLE_IDENTITY_LIFECYCLE.md). The
sealed `lab/cases/v2/gto_launcher.json` is untouched and the authoritative GTO
sample revision is still under adjudication.

### Production snapshot-to-preflight wiring (G3-R3, offline)

The immutable snapshot is wired into the **production GTO staging boundary**:
`run_offline_preflight_command(_with_snapshot_root)` captures the protected
input, verified-resolves it from disk, requires the snapshot hash/size/revision
to match the sealed manifest's `protected_input` identity, and binds the GTO
envelope to the snapshot path (family `ahk_gto`, generic evidence + `no-gate`).
The snapshot is re-verified from disk before the envelope is sealed and again at
the last trusted boundary before the verifier runs; a manifest mismatch or any
post-capture tamper fails closed with a structured NotReady and never yields a
launchable envelope. The two Oreans fixed cases keep their v2/v8 live-input lane.
**This is offline wiring only — no real GTO sample has been run.** GTO remains
`NOT completed / NOT perfect / NOT accepted`; `no-gate` means there is no
acceptance gate, not that the product is accepted.

### Acceptance kernel (R0B)

`mida-acceptance` is an independent crate: it must not depend on production
unpacker crates. Static structural evaluation only; R0B never emits `Accepted`.
Report paths must not overwrite the candidate or oracle.

```powershell
cargo run -p mida-acceptance --offline -- check-static <candidate> `
  --expected-sha256 <hex> --expected-size <bytes> --report <report.json>
```

### Pure PE model (R1)

**R1-A..E closed** on synthetic/structural corpus (pure inventory + purity lock,
parse/serialize, `RebuildPlan` rebuild, byte-map adapters, opt-in production
emit via `--pure-rebuild`, pure/legacy parity snapshots). Production dump still
defaults to **legacy**; pure remains opt-in. Offline synthetic tests only (no
PE-image fixture binaries). API: [docs/VNEXT_R1_PE_API.md](docs/VNEXT_R1_PE_API.md).
Roadmap / next live smoke: [docs/VNEXT_R1_ROADMAP.md](docs/VNEXT_R1_ROADMAP.md).
Full audit: [docs/PROJECT_AUDIT_AND_ROADMAP.md](docs/PROJECT_AUDIT_AND_ROADMAP.md).

```powershell
cargo test -p mida-pe --test purity_boundary --offline
cargo test -p mida-pe --test pure_parse_serialize --offline
cargo test -p mida-pe --lib rebuild --offline
cargo test -p mida-pe --lib byte_map --offline
cargo test -p mida-pe --lib export_table --offline
cargo test -p mida-pe --lib exception_table --offline
cargo test -p mida-pe --lib tls --offline
cargo test -p mida-pe pure_rebuild --offline
cargo test -p mida-pe r1e_dual_path --offline
```

## Build and test

Use a Visual Studio developer shell, or another shell initialized with
`vcvars64.bat`, and keep Cargo output outside the repository:

```powershell
# VS Developer / vcvars, or: . .\tools\_enter_msvc_env.ps1
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

## Long-term plan

1. Make `gto_launcher` a first-class product path with a dedicated replay and
   evidence bundle, not just an experimental profile.
2. Keep `origin_macro` + `lunlun_software` as the regression wall so GTO work
   cannot quietly break the Oreans baseline.
3. Finish runtime/event and family-plugin separation so GTO and Oreans share
   the engine but not the policy.
4. Keep structured OEP, IAT, TLS, relocation, section rebuild, and behavior
   evidence mandatory for every supported line.
5. Only then widen support to additional sample families.

## Release rule

"Universal" and "perfect" are goals, not status labels. A production release
requires an independent acceptance kernel, deterministic replay evidence,
holdout cases, and at least two production-quality packer-family plugins. The
GTO launcher line must be first-class, and the Oreans suite must still pass ten
consecutive isolated runs before it can satisfy its family gate.

## License

GPL-3.0. See [LICENSE](LICENSE).
