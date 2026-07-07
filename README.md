# Magicmida-RS

Themida automatic unpacker, Rust reimplementation.

Based on the reverse engineering of [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) (Pascal),
the entire unpacking pipeline is rewritten in Rust for safer memory management,
better error handling, and a modular architecture.

## Architecture

`
crates/
  core/          Debugger core: process creation, breakpoints, debug event loop
  pe/            PE parsing, section operations, import table reconstruction
  disasm/        iced-x86 wrapper, disassembly and pattern matching
  tracer/        Single-step trace engine
  packers/themida/  Themida unpacker implementation
  cli/           Command-line entry point
`

## Usage

`	ext
magicmida-rs.exe /unpack target.exe                # Unpack
magicmida-rs.exe /unpack target.exe --data-sections # Create data sections (MSVC TLS)
magicmida-rs.exe /unpack target.exe --shrink        # Remove unused sections
magicmida-rs.exe /dump-process <pid> unpacked.exe   # Dump .text from running process
`

## Build

`ash
cargo build --release
cargo test
`

Target platform: Windows x86/x64

## ScyllaHide Integration

Newer Themida versions detect hardware breakpoints. Download [ScyllaHide](https://github.com/x64dbg/ScyllaHide/releases)
and place HookLibraryx64.dll and InjectorCLIx64.exe next to the executable.
The project ships with a suitable config at scylla_hide.ini.

## Acknowledgements

This project is a Rust reimplementation based on the reverse engineering work of
[Hendi48/Magicmida](https://github.com/Hendi48/Magicmida) (original Pascal source).
The entire unpacking pipeline logic is studied from Magicmida and rewritten in Rust
for safer memory management, better error handling, and a modular architecture.

## License

GPLv3