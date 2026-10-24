# Magicmida-RS

Themida automatic unpacker, Rust reimplementation.

Based on the reverse engineering of [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) (Pascal),
the entire unpacking pipeline is rewritten in Rust for safer memory management,
better error handling, and a modular architecture.

> ## Scope of this branch
>
> This repository is an **experimental sandbox** forked from the upstream project
> on 2026-07-09. It does not track upstream and does not represent upstream's
> capability.
>
> Everything below describes **what has actually been measured here**. Anything
> not verified is marked as such rather than advertised.

## Verified capability

All three rows are gated. Each gate asserts byte-level reproducibility *and*
observable behaviour, and each refuses to run unless the input matches the
SHA-256 recorded in `crates/packers/themida/tests/cases/`.

| Target | Status | Evidence |
|---|---|---|
| **Themida v3, x64, EXE** | ✅ Works | 186 resolved imports / 0 failed / 8 `not-an-import`; product launches to its `授权验证` window. Gate: `e2e_gate.rs` |
| **Themida v3, x64, DLL** | ✅ Works | 289 resolved / 0 failed / 3 `not-an-import`; product loads through a real `LoadLibraryW`, `GetAppVersion()` returns `"1.1"`, `Run()` reaches `PigToGoLicenseDialog`. Gate: `dll_e2e_gate.rs` |
| **Themida v3, x86, EXE** | ✅ Works | 55 resolved / 0 failed / 55 `not-an-import`; product's `MidaX86Sample` window appears in ~24 ms. Gate: `x86_e2e_gate.rs` |
| Themida **v1 / v2** | ❓ No evidence | Detection code exists; never run on a real sample |

The 8 / 3 / 55 `not-an-import` slots are **not** failures. They hold bare RVAs
pointing into read-only data — exactly what the real Windows loader sees. They
are classified separately (`IatSlotDecision::NotAnImport`) so that a genuine
failure cannot hide inside "data".

**Byte-level reproducibility** (independent runs, whole-file SHA-256):

| Product | Size | SHA-256 |
|---|---|---|
| x64 EXE | 1,539,072 B | `af092f96…09b9fdd` |
| x64 DLL | 1,737,216 B | `97b9f20f…aa9f67` |
| x86 EXE | 110,592 B | `cf176ac9…5aa0d4` |

All three products declare `0x60000020` (read-only, executable) on their first
section — the same flags as their respective protected inputs.

Native `.dll` targets are loaded through a generated loader host
(`ensure_loader_host`) that calls the real `LoadLibraryW`, because a Themida DLL
shell expects the loader's `DLL_PROCESS_ATTACH` sequencing; the older "rewrite
the DLL into a stub EXE" approach bypassed it and the shell died at
`.winlice+0x33E22E`.

## Features

- **Runtime IAT reconstruction** — resolves imports via live memory tracing, with
  a pure-function slot classifier (zero runs are separators, resolved blocks are
  adopted, VM pointers are traced, bare in-image RVAs are rebased)
- **OEP discovery** — MSVC CRT startup pattern matching, plus a guard path that
  works even when the image does not enforce DEP
- **ScyllaHide integration** — bypasses anti-debugging on newer Themida builds
- **PE rebuild** — import table, section table, exception table (`.pdata`), data
  directory repair, relocation table, ASLR
- **Verify mode** — diff unpacked output against a known-good reference,
  section by section
- **GUI** — graphical front-end (`mida-gui.exe`)
- **MCP server** — drive the pipeline from an AI client (`mida-mcp.exe`)

## Prerequisites

| Requirement | Notes |
|---|---|
| **Windows 10/11** | x64 host. The debugger core uses the Win32 Debug API; not cross-platform. |
| **Rust toolchain** | stable GNU target (`x86_64-pc-windows-gnu`). Install via [rustup](https://rustup.rs). |
| **ScyllaHide** (optional) | Required for Themida v3 targets with hardware-breakpoint detection. Download from [ScyllaHide Releases](https://github.com/x64dbg/ScyllaHide/releases). |
| **Interactive desktop session** | `/unpack` injects ScyllaHide and the target creates its own windows. Headless CI can only use `verify` and `triage`. |

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

### Building the x86 target

The x86 pipeline needs extra link-time setup that cannot be committed (it points
at absolute paths on the build machine). In short: point the `i686-pc-windows-gnu`
linker at an i686 GCC, supply a real `libgcc_eh.a`, and wrap the system import
libraries in `--start-group`. The full recipe is in
[`docs/RUNBOOK.md`](docs/RUNBOOK.md).

```bash
rustup target add i686-pc-windows-gnu
cargo build --release --target i686-pc-windows-gnu
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

## MCP server

`mida-mcp.exe` exposes the pipeline to AI clients (Claude, Cursor, DSH, …) over
the Model Context Protocol. Five tools:

| Tool | Behaviour |
|---|---|
| `triage` | Synchronous. Reports PE facts without running anything. |
| `unpack_start` | Returns a `job_id` immediately. |
| `unpack_status` | Long-polls up to 45 s; returns phase and metrics. |
| `unpack_cancel` | `taskkill /T`, taking the debuggee with it. |
| `verify` | Synchronous, read-only file comparison. |

The job model exists because unpacking is not a 60-second operation (measured:
x86 success 5.5 s, x64 success ~27 s, x64 failure path 466 s, and the debug loop
`wait_event()` has no timeout at all). A single blocking tool would be cut off by
the client on exactly the failure path where its diagnostics matter most.

Register it by pointing your client at the binary:

```json
{
  "mcpServers": {
    "magicmida": { "command": "D:\\path\\to\\mida-mcp.exe" }
  }
}
```

The server reads the target's own PE header and picks `mida-cli.exe` or
`mida-cli-x86.exe` accordingly — the debugger's register layout follows the
*host*, so a 64-bit `mida-cli` refuses 32-bit targets. If the x86 CLI is missing
it says so precisely, instead of surfacing the CLI's own "please use the 32-bit
version" message.

## Architecture

```
crates/
  core/              Debugger core: process creation, breakpoints, debug event loop
  pe/                PE parsing, section operations, import table reconstruction
  disasm/            iced-x86 wrapper, disassembly and pattern matching
  packers/themida/   Themida unpacker implementation
  run/               Log parsing + job state, shared by the GUI and the MCP server
  cli/               Command-line entry point
  gui/               egui front-end
  mcp/               MCP server
```

Each crate is an independent module with a clear boundary. The debugger core
(`mida-core`) owns all process/handle state; packers and CLI interact with it
exclusively through the `DebuggerCore` trait.

`mida-run` exists so that the GUI and the MCP server cannot disagree about
whether a run succeeded. `RunReport` encodes "success" as one rule: **exit code
0 + a `Done.` line + no fatal error**, all three required.

## Build

```bash
cargo build --release      # Optimized binary at target/release/mida-cli.exe
cargo test --workspace     # Run all tests (must use --workspace for cross-crate coverage)
cargo run -- /unpack <file>  # Build + run in one step
```

Test counts on this machine (release, 2026-10-24):

| Target | Result |
|---|---|
| x64 | 278 passed / 0 failed / 3 ignored |
| x86 (`--target i686-pc-windows-gnu`) | 271 passed / 0 failed / 3 ignored |

The 3 ignored tests per target are the end-to-end gates, which need real
protected samples, a desktop session, and ScyllaHide.

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
   - Returns immediately after spawning the injector — it does **not** wait.

**Note:** If the SHA-256 verification fails, the unpacker will refuse to inject
and report an error. This prevents running tampered hook binaries. To use a
different version of ScyllaHide, update the hashes in `binaries.rs`.

The injector is deliberately not awaited: it hijacks the target's main thread,
and a debuggee with an unacknowledged debug event has all of its threads frozen
until the debugger calls `ContinueDebugEvent`. Waiting inside the
`CREATE_PROCESS` handler therefore deadlocks — measured, not theorised.

ScyllaHide binaries are **not** committed to this repository. They are
user-downloaded and verified at runtime via SHA-256 checksums (see
`crates/packers/themida/src/binaries.rs`).

## Supported Targets

| Themida Version | x86 | x64 | Notes |
|---|---|---|---|
| **V1** (Ancient) | ❓ unverified | — | Detection code exists; never run on a real sample. |
| **V2** | ❓ unverified | — | Detected by dual `0x1000`-sized stub sections; never run on a real sample. |
| **V3** | ✅ **verified** | ✅ **verified** | x64 EXE, x64 DLL and x86 EXE are all gated. Requires ScyllaHide. |

**Known limitations:**

- **Sample coverage is narrow.** Three protected inputs, all built with Themida
  v3. V1/V2 detection exists but has never been exercised on a real sample.
- Themida v3 with heavy VM obfuscation may require runtime heuristics that static
  analysis alone cannot resolve (`ThemidaVersion::Unknown`).
- Import resolution for a fully virtualized IAT (v3 VM-strong) may produce
  incomplete results; the original PE's import table is used as a fallback.
- **The EXE gate's GUI check is judged by a control sample.** The reference
  sample needs a remote module server; when that server is unreachable, the
  *original packed sample* cannot reach its auth window either. In that case the
  gate reports `GUI check NOT exercised` rather than blaming the dump, and still
  requires the product not to crash.
- **Byte-level reproducibility assumes the same toolchain.** The golden hashes
  above were recorded with the Rust and GCC versions on the dev machine. A
  different compiler may produce a structurally equivalent but byte-different
  product.
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

## Documentation

| File | Contents |
|---|---|
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Toolchain setup, test order, gates, building x86 samples |
| [`docs/POSTMORTEMS.md`](docs/POSTMORTEMS.md) | Every fixed defect, with the measurement that located it |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |

## Acknowledgements

This project is a Rust reimplementation based on the reverse engineering work of
[Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) (original Pascal source).
The entire unpacking pipeline logic is studied from Magicmida and rewritten in Rust
for safer memory management, better error handling, and a modular architecture.

## License

GPLv3 — see [`LICENSE`](LICENSE).
