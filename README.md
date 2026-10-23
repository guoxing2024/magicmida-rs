# Magicmida-RS

Themida automatic unpacker, Rust reimplementation.

Based on the reverse engineering of [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) (Pascal),
the entire unpacking pipeline is rewritten in Rust for safer memory management,
better error handling, and a modular architecture.

> ## ⚠️ Scope of this branch
>
> **This branch is an experimental sandbox forked from the upstream project on
> 2026-07-09, not the project's mainline.** It does not track upstream and does
> not represent the project's capability. See
> [`BRANCH_DECISION.md`](../BRANCH_DECISION.md) for the rationale and for the
> list of assets worth porting back upstream.
>
> Everything below describes **what has actually been measured on this branch**.
> Anything not verified is marked as such rather than advertised.

## Verified capability

| Target | Status | Evidence |
|---|---|---|
| **Themida v3, x64, EXE** | ✅ Works | 186 imports / 9 modules / product launches to its auth window. Frozen as a gate: `crates/packers/themida/tests/e2e_gate.rs` |
| Themida v3, **x64, DLL** | ✅ Works | 289 imports / 12 modules; the product loads, `GetAppVersion()` returns `"1.1"`, and `Run()` reaches its own auth window (`PigToGoLicenseDialog`). Frozen as a gate: `crates/packers/themida/tests/dll_e2e_gate.rs`. Slots 901/965/1057 are reported as `not-an-import` (bare RVAs into read-only data, zero code references) |
| Themida v3, **x86** | ⚠️ **Builds, never run** | The x86 target now compiles (`i686-pc-windows-gnu`, real `pei-i386`, the CLI runs), and the x86 ScyllaHide hashes in `binaries.rs` are the real values instead of all-zero placeholders. **But there is no x86 sample, so the pipeline has never been executed end to end.** The link-time setup is documented in `AGENTS.md` |
| Themida **v1 / v2** | ❓ **No evidence** | No sample, no test |

Native `.dll` targets are accepted. A packed DLL is loaded through a generated
loader host (`ensure_loader_host`) that calls the real `LoadLibraryW`, because a
Themida DLL shell expects the loader's `DLL_PROCESS_ATTACH` sequencing; the older
"rewrite the DLL into a stub EXE" approach bypassed it and the shell died at
`.winlice+0x33E22E`.

Only the EXE row has an automated end-to-end gate. Treat the rest as
measured-but-ungated.

## Features

- **Runtime IAT reconstruction** — resolves imports via live memory tracing
- **OEP discovery** — MSVC CRT startup pattern matching, Go/Delphi heuristics
- **ScyllaHide integration** — bypasses anti-debugging on newer Themida builds
- **PE rebuild** — import table, section table, data directory repair
- **Verify mode** — diff unpacked output against a known-good reference

## Prerequisites

| Requirement | Notes |
|---|---|
| **Windows 10/11** | x64 host. The debugger core uses Win32 Debug API; not cross-platform. |
| **Rust toolchain** | stable GNU target (`x86_64-pc-windows-gnu`). Install via [rustup](https://rustup.rs). The x86 target (`i686-pc-windows-gnu`) also builds; see `AGENTS.md` for the extra link-time setup it needs. |
| **ScyllaHide** (optional) | Required for Themida v3 targets with hardware-breakpoint detection. Download from [ScyllaHide Releases](https://github.com/x64dbg/ScyllaHide/releases). |

## Quick Start

```bash
# 1. Build
cargo build --release

# 2. (Optional) Place ScyllaHide binaries next to the executable
#    The project ships a default config at scylla_hide.ini
cp HookLibraryx64.dll InjectorCLIx64.exe target/release/

# 3. Unpack
target/release/mida-cli.exe /unpack "protected.exe"
# → writes protectedU.exe
```

## Usage

```
mida-cli /unpack <filename> [options]
mida-cli /dump-process <pid> <unpacked-file>
mida-cli /verify <unpacked-file> <reference-file>
```

### `/unpack` — Unpack a Themida-protected executable

Launches the target under a debugger, waits for OEP, dumps memory, and rebuilds
the import table.

| Option | Description |
|---|---|
| `<filename>` | Path to the input executable (`.exe` or `.dll`). |
| `-o <path>` / `--output <path>` | Output path. Defaults to `<input>U.exe` (the "U" suffix convention from Pascal Magicmida). |
| `--data-sections` | Restore `.rdata` / `.data` sections from the target process. Needed for MSVC TLS callbacks and initialized global data. |
| `--shrink` | Remove Themida-specific sections (`.winlice` / `.boot` / `.themida`), compact VAs, clear dangling data directories, restore standard section names, build relocation table, and enable ASLR. **Enabled by default.** |
| `--no-shrink` | Disable shrinking. Keeps Themida sections and disables ASLR/relocation. Use for debugging or when shrink causes issues. |
| `-v` / `--verbose` | Enable debug-level logging. |

**Examples:**

```bash
# Basic unpack — output written to targetU.exe
mida-cli.exe /unpack target.exe

# Full rebuild with data sections and stub removal
mida-cli.exe /unpack target.exe --data-sections --shrink

# Specify output path, verbose logging
mida-cli.exe /unpack target.exe -o clean.exe -v
```

### `/dump-process` — Dump `.text` from a running process

For targets that have already been unpacked in memory (manually or by another
tool). Reads the decrypted `.text` section from the live process and writes it
to a file.

```bash
mida-cli.exe /dump-process 12345 unpacked_text.bin
```

### `/verify` — Compare against a reference

Compares PE structure (sections, imports, entry point) of an unpacked file
against a known-good reference to validate correctness.

```bash
mida-cli.exe /verify unpacked.exe reference_clean.exe
```

## Architecture

```
crates/
  core/              Debugger core: process creation, breakpoints, debug event loop
  pe/                PE parsing, section operations, import table reconstruction
  disasm/            iced-x86 wrapper, disassembly and pattern matching
  tracer/            Single-step trace engine
  packers/themida/   Themida unpacker implementation
  cli/               Command-line entry point
```

Each crate is an independent module with a clear boundary. The debugger core
(`mida-core`) owns all process/handle state; packers and CLI interact with it
exclusively through the `DebuggerCore` trait.

## Build

```bash
cargo build --release      # Optimized binary at target/release/mida-cli.exe
cargo test --workspace     # Run all tests (must use --workspace for cross-crate coverage)
cargo run -- /unpack <file>  # Build + run in one step
```

## ScyllaHide Integration

Newer Themida versions detect hardware breakpoints via `GetThreadContext` checks.
ScyllaHide hooks these APIs in the target process to hide debugger presence.

**What ScyllaHide does:** It injects a hook DLL (`HookLibraryx64.dll`) into the
target process using `InjectorCLIx64.exe`. The hook intercepts anti-debugging
APIs (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`,
`GetThreadContext`, etc.) and returns spoofed results, making the target believe
it is running without a debugger.

**Setup:**

1. Download [ScyllaHide](https://github.com/x64dbg/ScyllaHide/releases) (x64 build).
2. Extract `HookLibraryx64.dll` and `InjectorCLIx64.exe` from the archive.
3. Place both files in the same directory as `mida-cli.exe` (typically
   `target/release/`).
4. Create a `scylla_hide.ini` config file in the same directory. The project
   ships a default config — adjust profile settings if your target uses
   non-standard anti-debug checks.
5. When you run `mida-cli /unpack`, the packer crate automatically:
   - Verifies the SHA-256 hashes of `InjectorCLIx64.exe` and `HookLibraryx64.dll`
     against known-good values (see `crates/packers/themida/src/binaries.rs`).
   - Launches `InjectorCLIx64.exe` to inject the hook DLL into the target.
   - Waits for injection to complete before setting hardware breakpoints.

**Note:** If the SHA-256 verification fails, the unpacker will refuse to inject
and report an error. This prevents running tampered hook binaries. To use a
different version of ScyllaHide, update the hashes in `binaries.rs`.

ScyllaHide binaries are **not** committed to this repository. They are
user-downloaded and verified at runtime via SHA-256 checksums (see
`crates/packers/themida/src/binaries.rs`).

## Supported Targets

**Only one combination is verified.** The table below separates "the code path
exists" from "somebody ran it and checked the result".

| Themida Version | x86 | x64 | Notes |
|---|---|---|---|
| **V1** (Ancient) | ❓ unverified | — | Detection code exists; never run on a real sample. |
| **V2** | ❓ unverified | — | Detected by dual `0x1000`-sized stub sections; never run on a real sample. |
| **V3** | ❓ unverified | ✅ **verified** | x64 is always V3. Requires ScyllaHide. This is the only gated case. |

**Known limitations:**

- **x86 is untested.** The x86 build has never been compiled on the dev machine,
  and the x86 ScyllaHide SHA-256 values in `binaries.rs` are all-zero
  placeholders that `verify_sha256` rejects by design. Populate them before
  claiming x86 support.
- Themida v3 x86 with heavy VM obfuscation may require runtime heuristics that
  static analysis alone cannot resolve (`ThemidaVersion::Unknown`).
- Import resolution for fully virtualized IAT (v3 VM-strong) may produce
  incomplete results; the original PE's import table is used as a fallback.
- **DLL (.dll) targets**: accepted, but with two measured defects — the
  `GetAppVersion()` `.bss` value is captured too early (`"0.0"` vs `"1.1"`), and
  slots 901/965/1057 fail to trace. The dump itself loads and its exports
  resolve. Do not treat DLL output as verified.
- **Relocation table generation** — scans non-executable sections for absolute
  addresses, builds a complete `.reloc` table, and enables ASLR (`DYNAMIC_BASE`).
  The table is clamped to fit the available VA space between `.reloc` and the
  next section, preventing VA overlap.
- **Section shrinking** — removes `.winlice` / `.boot` / `.themida` sections,
  compacts remaining VAs to eliminate gaps, clears dangling data directories,
  and restores standard section names (`.text` / `.data` / `.rdata` etc.).
- **Absolute address fixing** — patches all runtime-hardcoded addresses in
  non-executable sections from the runtime image base to the original file
  image base, enabling correct ASLR relocation.

## Acknowledgements

This project is a Rust reimplementation based on the reverse engineering work of
[Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) (original Pascal source).
The entire unpacking pipeline logic is studied from Magicmida and rewritten in Rust
for safer memory management, better error handling, and a modular architecture.

## License

GPLv3
