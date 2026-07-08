# Magicmida-RS

Themida automatic unpacker, Rust reimplementation.

Based on the reverse engineering of [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) (Pascal),
the entire unpacking pipeline is rewritten in Rust for safer memory management,
better error handling, and a modular architecture.

## Features

- **Themida v1/v2/v3** detection and unpacking (x86 & x64)
- **Runtime IAT reconstruction** — resolves imports via live memory tracing
- **OEP discovery** — MSVC CRT startup pattern matching, Go/Delphi heuristics
- **ScyllaHide integration** — bypasses anti-debugging on newer Themida builds
- **PE rebuild** — import table, section table, data directory repair
- **Verify mode** — diff unpacked output against a known-good reference

## Prerequisites

| Requirement | Notes |
|---|---|
| **Windows 10/11** | x64 host. The debugger core uses Win32 Debug API; not cross-platform. |
| **Rust toolchain** | stable MSVC target (`x86_64-pc-windows-msvc`). Install via [rustup](https://rustup.rs). |
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
magicmida /unpack <filename> [options]
magicmida /dump-process <pid> <unpacked-file>
magicmida /verify <unpacked-file> <reference-file>
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

**Setup:**

1. Download [ScyllaHide](https://github.com/x64dbg/ScyllaHide/releases) (x64 build).
2. Place `HookLibraryx64.dll` and `InjectorCLIx64.exe` next to `mida-cli.exe`.
3. Create a `scylla_hide.ini` config (or use the ScyllaHide default) — adjust if needed.

ScyllaHide binaries are **not** committed to this repository. They are
user-downloaded and verified at runtime via SHA-256 checksums (see
`crates/packers/themida/src/binaries.rs`).

## Supported Targets

| Themida Version | x86 | x64 | Notes |
|---|---|---|---|
| **V1** (Ancient) | ✅ | — | Legacy Themida. |
| **V2** | ✅ | — | Detected by dual `0x1000`-sized stub sections. |
| **V3** | ✅ | ✅ | Current generation. x64 is always V3. Requires ScyllaHide. |

**Known limitations:**

- Themida v3 x86 with heavy VM obfuscation may require runtime heuristics that
  static analysis alone cannot resolve (`ThemidaVersion::Unknown`).
- Import resolution for fully virtualized IAT (v3 VM-strong) may produce
  incomplete results; the original PE's import table is used as a fallback.
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
