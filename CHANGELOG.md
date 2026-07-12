# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Post-attach unpacking mode** — when the target's section 0 is plain
  `.text` (Themida did not strip section names), the process is created
  *without* a debug port (`DEBUG_ONLY_THIS_PROCESS` omitted).  Themida's
  startup `EPROCESS.DebugPort` check sees NULL and does not trigger
  `0xDEADC0DE`.  The unpacker then polls the IAT until resolved, freezes
  via `SuspendThread`, and dumps directly — bypassing the entire debug event
  loop and the `PAGE_NOACCESS` guard that caused `0xDEADC0DE` on detection.
- `WindowsDebugger::post_attach_init` — resume → wait → PEB patch sequence
  for post-attach mode.
- `CreateProcessOptions::post_attach` flag to select the creation path.
- `find_real_oep_by_scanning` entry point for OEP discovery without debug
  events (used by the post-attach fast path).

### Fixed
- Eliminated all 13 compiler warnings (unused imports, unused variables,
  dead constants, redundant reassignment).
- Fixed `test_sanitize` test to match the CIG/ACG-safe behavior: `sanitize()`
  no longer forces `IMAGE_SCN_MEM_WRITE` on the first section (writable +
  executable sections are rejected by the Windows loader).
- `NtProtectVirtualMemory` guard disabled (caused infinite re-fire in the
  debug event loop).  The post-attach path eliminates this issue entirely
  by not installing the guard.
- `.text` section filter heuristics: `is_themida_section` now checks
  `!is_standard_section_name()` and `!name.trim().is_empty()` to prevent
  `.text` (raw_size=0) and blank-named sections from being misclassified.

### Changed
- `DumpOptions` gains `section_filter: Option<fn(&PeSection) -> bool>` for
  flexible section selection during dump.
- `.reloc` section always deleted during `shrink_sections` (rebuilt from
  scratch); virtual size increased to `0x4000` to prevent relocation table
  overflow.
- IAT trace skipped in post-attach mode (slots already resolved).
- V3 IAT fix uses `post-attach` mode when section 0 is `.text`.

### Earlier (pre-post-attach)

#### Fixed
- Replaced x86 ScyllaHide SHA-256 placeholder hashes with all-zero placeholders
  that will fail verification until real hashes are configured (P0-3).
- Fixed UTF-8 mojibake in source comments across `crates/core/` and
  `crates/tracer/` (P1-6).
- Fixed binary name inconsistency in README and CLI usage text (`magicmida` ->
  `mida-cli`) (P2-9, N3).
- Narrowed `.gitignore` from overly broad `*.bat` to specific `build.bat`
  (P1-8).
- Removed `run_unpack.bat` and `unpack_*.log` from repository (contained
  hardcoded local paths) (N1).

#### Changed
- Added `[workspace.package]` metadata (repository, license, readme) to root
  `Cargo.toml`; all sub-crates now inherit via `*.workspace = true` (P0-4).
- Enhanced ScyllaHide Integration section in README with detailed setup steps
  and runtime verification explanation (P2-11).

#### Removed
- Removed `CLAUDE.md` (internal development guide) from the public repository
  and added it to `.gitignore` (P1-5).
- Created `CHANGELOG.md` documenting project history (P2-12).
- Added DLL target limitation to README Known limitations section (P1-7).

---

## Project History

The following documents the major changes across the project's commit history.

### Initial Release — Themida Unpacker (db1ad7e)

- Initial commit: Rust reimplementation of [Hendi48/Magicmida](https://github.com/Hendi48/Magicmida)
  (original Pascal source).
- Core debugger engine using Win32 Debug API.
- PE parsing, section operations, and import table reconstruction.
- Themida v1/v2/v3 detection and unpacking.
- OEP discovery via MSVC CRT startup pattern matching.
- ScyllaHide integration for anti-anti-debugging.
- Single-step trace engine for following unpacker control flow.

### Documentation & Style (4412de1, 046bc62, 920fac2)

- Expanded README with full usage guide, command-line options, and architecture
  overview.
- Added SAFETY comments to 75 unsafe blocks for CLAUDE.md compliance.
- Updated internal development guide with 500-line rule exceptions.

### Refactoring — Module Extraction (f493b06, f54c6bb, ecac26a, 0710db4, 89434f8, 6169f1f)

- Extracted API set data table to `apiset_data.rs` in the PE crate.
- Split `dumper`, `oep`, and `trace_imports` modules for better separation.
- Replaced `eprintln!` with `tracing` macros for structured logging.
- Removed unused imports from `trace_imports` split.
- Split `iat.rs` (2350 lines → 4 files) and `postprocess.rs` (1218 lines → 4 files)
  in the Themida packer crate.
- Split anti-anti-debug module and extracted tests from `header`, `version`,
  and `text_tracer` modules.

### Feature — Full Themida v3 Unpacking (08470c4)

- Complete Themida v3 unpacking: deletes packer sections (`.winlice` / `.boot` /
  `.themida`), fixes absolute addresses, and rebuilds the import table.
- Restores standard section names (`.text` / `.data` / `.rdata` etc.).
- Clears dangling data directories.

### Feature — ASLR & Relocation (0e89c99)

- Enabled ASLR (`DYNAMIC_BASE`) in unpacked PEs.
- Generates complete relocation tables — a capability beyond the original Pascal
  Magicmida.
- Builds `.reloc` table from absolute addresses found in non-executable sections.

### Preparation for GitHub (45ac408, 9fa1ff6, c78fdb1, 04759bc)

- Updated README and `.gitignore` for public GitHub release.
- Removed temporary log files from the repository.
- Exception directory recovery with complete (non-truncated) relocation table.
- Final cleanup of log artifacts.
