# MagicMida vNext

MagicMida vNext is a Windows PE unpacking research platform. Its long-term goal is
reliable, family-extensible unpacking with explicit evidence for every claim.

This repository is a canonical recovery baseline, not a general-purpose 1.0
release. The legacy Themida/Oreans implementation is retained so it can be split
behind stable interfaces and tested against an independent acceptance kernel. A
historical output, including the Origin macro oracle candidate, is regression
input only and is never proof that a new output is correct.

Strategically, the primary long-term target is `gto_launcher`
(`D:\Tools\RE\dumps\gto\启动器.exe`), now pursued as the **GVM-0
anti-virtualization campaign** (ruling 2026-08-28). The Oreans
`origin_macro` + `lunlun_software` pair remains the active regression gate,
and the closed `xiongxiong_duokai` rev2 campaign (2026-08-28) is the
WinLicense-tier reference; GTO remains a first-class support line, not a side
quest.

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

The repository's active sample tracks are:

- **Completed campaign:** `xiongxiong_duokai` (熊熊 rev2, WinLicense tier)
  — perfect-unpack campaign **closed 2026-08-28** (S1 structural 12/12, S2
  plaintext .text 100%, S3 load_no_crash 10/10, S4 behavior alignment). See
  [AUTHORIZATION_XX_20260827.md](AUTHORIZATION_XX_20260827.md).
- **Perfect candidate (XC-XXI/XXI-B, 2026-08-29):** `xiongxiong_core`
  (core.dll) — the WinLicense-DLL companion of the above, **independently
  characterized per the 2026-08-28 XC owner directive** (identity from its own
  features; manifest family `unclassified_candidate`, `oreans_candidate` kept
  as hypothesis). XX-III delivered an equivalence-grade candidate; the
  **XC-XXI/XXI-B campaigns upgraded it to a perfect candidate**
  (`core_perfect_candidate.dll`, sha256 `3650ea6c…`): VM mechanism confirmed
  as **runtime-decrypt-materializes** (path A, no interpreter), S1 12/12, S2
  plaintext 100%, S3 load_no_crash 6/6, S4 GetAppVersion×10 equivalent;
  **Run business chain FULL but download call not actually fired (GUI
  message-loop bound, deny_all kept) → Run verdict PARTIAL**. See
  [AUTHORIZATION_XX_20260827.md](AUTHORIZATION_XX_20260827.md) (XC section),
  [docs/XX21B_CORE_PERFECT_REPORT_20260829.md](docs/XX21B_CORE_PERFECT_REPORT_20260829.md).
- **Active regression gate:** `origin_macro` + `lunlun_software`, with fixed
  identities and fail-closed gates documented in
  [archive/routes/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md](archive/routes/OREANS_TWO_SAMPLE_PERFECT_UNPACK_PLAN.md).
- **Primary strategic line:** `gto_launcher`, now as the **anti-virtualization
  campaign (GVM-0, ruling 2026-08-28)** — VM semantics recovery, lifter, and
  whole-image devirtualization in three gated phases. See
  [docs/GVM-0_RULING_20260828.md](docs/GVM-0_RULING_20260828.md).

**Retired sample lines:** `shiguang` and `dali` (and any other legacy tracks
from before the XX campaign) are **withdrawn** — they are no longer active
sample lines and are not acceptance gates. Their historical manifests/evidence
stay in the repository as archive only.

A structural `Accepted`, historical oracle match, GTO holdout result, or
retry-selected replay is not proof of perfect unpacking for any line. The gate
remains open until each declared line passes the relevant OEP, IAT, TLS,
relocation, section rebuild, behavior equivalence, and 10 consecutive isolated-
run requirements. The evidence-bundle inventory contract that makes a run
record auditable is defined in
[docs/VNEXT_EVIDENCE_BUNDLE_V1.md](docs/VNEXT_EVIDENCE_BUNDLE_V1.md).
**Current status: not closed for the open lines; this README makes no claim of
perfect or universal unpacking beyond the closed XX campaigns.**

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

> **MSVC link.exe shadowing:** a plain Git-Bash/`PATH` shell may resolve
> `link.exe` to Git's GNU coreutils `link` (hard-link tool) instead of MSVC's
> linker, causing `link: missing operand after '@…/linker-arguments'` at link
> time. Always initialize `vcvars64.bat` first (or run
> `build_with_msvc.bat` / `test_with_msvc.bat`, which locate Visual Studio via
> `vswhere`). `cargo check` (no linking) is unaffected.

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



## GTO launcher line status (terminal closeout 2026-08-22)

**GTO dump-route: TERMINAL (structural ceiling).** After the LIVE-2/LIVE-3
quantified experiments (docs/GTO_TERMINAL_CHARACTERIZATION_20260822.md):

- suspected-SecureEngine-class protection performs **execution-driven
  per-page decryption**: passive waiting (LIVE-2 R2, 60s) and real execution
  (LIVE-3 R1, 300s) both produced **zero new decrypted pages**;
- coverage 4.26% constant (16/376 strips are on-disk raw data, not decrypt
  products), unreadable=0, 60% economic gate missed by 14x;
- structural argument: per-page lazy decryption implies any independently
  re-run must touch ciphertext pages => dump-based perfect unpacking is
  **structurally unreachable**; "the protector owns execution" is the
  dump-route terminal state.

This is NOT a claim of perfect/universal unpacking — see Release rule below.
The GTO line remains an experimental research line with honest graded
wording (suspected-SecureEngine-class, Themida version unverified).

## XX campaign closeout — xiongxiong_duokai rev2 (2026-08-28)

The `xiongxiong_duokai` rev2 (WinLicense tier) perfect-unpack campaign is
**CLOSED** (AUTHORIZATION-XX-FULL terminal sign-off, 2026-08-28). All four
criteria verified against the anchored candidate
(`rev2_unpacked.exe`, attempt 20260828-112236):

- **S1 structural R0B:** 12/12 PASS;
- **S2 plaintext:** `.text` 100% readable (222/222 blocks ent<6.5, 2688
  prologues, OEP=0x1010 native MSVC CRT, shell sections stripped);
- **S3 survival:** load_no_crash 10/10 (isolated runs, no retry-picked);
- **S4 behavior alignment:** window title / module set / `config.ini`
  byte-identical, no disclosed behavioral differences.

Per the authorization, the campaign then transitions to the GTO launcher
campaign (next section). This closeout is a claim about this one case line
only, not a general "universal/perfect" label.

## GVM-0 anti-virtualization campaign (2026-08-28)

Ruling `docs/GVM-0_RULING_20260828.md` (owner-signed 2026-08-28) opens the
**GTO anti-virtualization campaign** on vault-anchored sample `11473d2e…`:

- **Direction:** the GTO dump route stays TERMINAL; the campaign does not
  retry it. The bet is **VM semantics recovery**: the protector is
  suspected-SecureEngine-class and owns execution, so the new line recovers
  the VM interpreter/handlers and rebuilds a native image instead of dumping.
- **Authorization extension:** protection-semantics reverse engineering
  (VM interpreter + handler semantics, bytecode format, data-plane decryption
  triggers) is unblocked for the anchored sample, isolation-only, outputs
  vaulted (`D:/MidaVault/lab/evidence/gvm/`), NO_BYPASS=1 throughout.
- **Three gated phases (ledger GVM 0/8):**
  1. Phase 1 — `0x3d610` mapping: dispatcher semantics, handler inventory,
     bytecode format, data-plane decryption schedule (2-4 wks; gate: self-
     consistent ISA spec, 3-function manual push-down vs trace);
  2. Phase 2 — Lifter: VM bytecode → IR → compilable native (3-6 wks; gate:
     end-to-end devirt of `0x3d610` with trace-equivalent semantics);
  3. Phase 3 — whole-image devirtualization + native rebuild (4-8 wks; gate:
     S1-S4 full acceptance per 熊熊 standard).
- **Honest risk disclosure:** B1 is the hardest of the three paths (gate 1
  pass ~60-70%, full-path ~40-50%); Phase 1 outputs (ISA spec) are valuable
  regardless of gate outcome.

The Oreans fixed two-sample regression wall stays green during this work.

## Long-term plan

1. Execute the **GVM-0 anti-virtualization campaign** on `gto_launcher`
   (VM semantics recovery → lifter → whole-image devirtualization) through its
   gated phases, with the GTO dump route kept TERMINAL and never retried.
2. Keep `origin_macro` + `lunlun_software` as the regression wall so GTO work
   cannot quietly break the Oreans baseline; the closed `xiongxiong_duokai`
   rev2 campaign remains the WinLicense-tier reference (S1-S4 criteria).
3. Finish runtime/event and family-plugin separation so GTO and Oreans share
   the engine but not the policy.
4. Keep structured OEP, IAT, TLS, relocation, section rebuild, and behavior
   evidence mandatory for every supported line.
5. Only then widen support to additional sample families.

## Release rule

"Universal" and "perfect" are goals, not status labels. A production release
requires an independent acceptance kernel, deterministic replay evidence,
holdout cases, and at least two production-quality packer-family plugins. The
GTO launcher line must pass its anti-virtualization campaign gates, and the
Oreans suite must still pass ten consecutive isolated runs before it can
satisfy its family gate. The `xiongxiong_duokai` rev2 closeout is a
single-case milestone, not a release.

## License

GPL-3.0. See [LICENSE](LICENSE).
