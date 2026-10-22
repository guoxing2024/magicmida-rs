# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Non-reproducible output: TLS template length** (`dumper`).  Themida updates
  `IMAGE_TLS_DIRECTORY.EndRawData` lazily during startup, so a live-memory dump
  can capture an intermediate value.  On the reference v3 x64 target, ten
  consecutive runs of the same binary produced `StartRawData+0x8` on some runs
  and `StartRawData+0x8008` on others (one allocation-granularity overshoot).
  Both products launch, but the second is semantically wrong (a 32 KB TLS
  template instead of 8 bytes) and it made the whole-file SHA-256
  non-reproducible — which invalidated using a golden hash as the regression
  criterion.  `normalize_tls_directory()` now clamps `EndRawData` to the
  template length declared by the protected input (fallback: the dumped `.tls`
  section extent), and only ever shrinks an out-of-range value.  After the fix:
  10/10 runs produce the golden hash.
- **Module snapshot order was not stable** (`dumper::remote_modules`).
  `TH32CS_SNAPMODULE` returns the loader's load order, which varies between
  runs because the OS resolves some dependencies asynchronously; that ordering
  leaked into the emitted import table.  The snapshot is now sorted by module
  base.
- **Native DLL targets hung instead of failing** (`cli::unpack`).  A packed
  `core.dll` (6 MB) previously ran for more than ten minutes before being killed
  by hand.  `unpack()` now rejects native DLL input up front with an explanation;
  the `.NET` path (COM descriptor present) is unaffected.
- **Two shrink counters read like a contradiction** (`postprocess`,
  `dumper::header_patch`).  `shrink_pe` reports sections dropped from the
  in-memory PE model, the dump stage reports sections dropped from the live
  header.  They were never meant to match, but both said "Shrink complete".
  They are now labelled by stage.
- **IAT trace aborted early on fragmented v3 IATs** (`trace_imports`): the
  trash-threshold counter treated already-resolved API addresses

  (`0x7FFx_xxxx_xxxx`, whole blocks decrypted by Themida before the trace ran)
  as garbage, aborting the scan at slot 142 of 1063 on a real-world V3 x64
  target.  ~900 slots — including the slot behind `call [rip+disp]` at
  `.text+0x3b63` — kept VM trampolines and the dumped image crashed with
  0xC0000005 on launch.  Slot classification is now a pure function
  (`classify_iat_slot` / `IatSlotDecision`): zero runs are separators (not
  trash), resolved blocks are adopted, VM pointers are traced, bare in-image
  RVAs are rebased before tracing.  On the reference sample: 50→186 resolved
  imports, 8→9 modules (shell32 restored), unpacked binary launches.
- Replaced x86 ScyllaHide SHA-256 placeholder hashes with all-zero placeholders
  that will fail verification until real hashes are configured (P0-3).
- Fixed UTF-8 mojibake (`鈥` → `—`, `鈫` → `→`) in source comments across
  `crates/core/` and `crates/tracer/` (P1-6).
- Fixed binary name inconsistency in README and CLI usage text (`magicmida` →
  `mida-cli`) (P2-9, N3).
- Narrowed `.gitignore` from overly broad `*.bat` to specific `build.bat` (P1-8).
- Removed `run_unpack.bat` and `unpack_*.log` from repository (contained
  hardcoded local paths) (N1).

### Changed
- **Removed the duplicate in-loop IAT trace engine** (`cli::unpacker::iat_trace`,
  558 lines).  Two engines resolved IAT slots in the same process: the
  production one in `packers/themida/trace_imports` (post-loop, 186 resolved)
  and an experimental one in the CLI (in-loop, 0 resolved / 46 failed).  The
  second duplicated the slot classifier with looser semantics — its
  `is_real_api` check had no upper bound, so any value above `0x10000` reset the
  trash counter and the scan never terminated — wrote its partial results back
  into the target process, then discarded them.  It contributed nothing to the
  output: removing it left the product byte-identical.  The 5-second post-OEP
  IAT decryption window was kept; it is not a trace engine (it installs a guard
  and records faulting instructions into `state.guard_addrs`, which
  `determine_iat_address` consumes).
- **Dependency graph tightened.**  Dropped three dead edges — `pe → disasm`,
  `cli → disasm`, `cli → tracer` (zero references each).  Moved `LogMsgType`
  from `mida-tracer` into `mida-core` and deleted the `mida-tracer` crate (532
  lines, `Tracer::trace` had no production call sites).  Six crates became five.
- **Capability claims now match measurement** (README).  Only "Themida v3 x64
  EXE" is claimed verified.  x86 and v1/v2 are marked unverified (the x86 path
  has never been compiled here; its ScyllaHide hashes are all-zero
  placeholders).  DLL is marked unsupported.  A scope banner points at
  `BRANCH_DECISION.md`, which records that this branch is a sandbox forked from
  upstream on 2026-07-09 rather than the project mainline.
- Added `[workspace.package]` metadata (repository, license, readme) to root
  `Cargo.toml`; all sub-crates now inherit via `*.workspace = true` (P0-4).
- Enhanced ScyllaHide Integration section in README with detailed setup steps
  and runtime verification explanation (P2-11).
- **Per-access IAT debug logging removed.**  The post-OEP monitoring window sees
  150k–274k IAT touches per run on a real v3 target; logging each one turned a
  `-v` run into a 14.9 MB log.  Only the aggregate count is logged now
  (14,902,098 B → 101,049 B).

### Removed
- Removed `CLAUDE.md` (internal development guide) from the public repository
  and added it to `.gitignore` (P1-5).
- Removed the dead free function `session::get_thread_context_control`; every
  call site goes through the `DebuggerCore` trait method of the same name.

### Added
- **End-to-end acceptance gate** (`crates/packers/themida/tests/e2e_gate.rs`).
  Until now no test ran the pipeline over a real protected binary, so the
  headline numbers of the only successful case were protected by prose alone.
  The gate is `#[ignore]`d by default (needs the sample, a Windows host, and
  ScyllaHide) and asserts eight things: exit status, resolved/failed counts,
  module/thunk counts, full 1063-slot IAT scan (catches early abort), product
  size, PE structure (PE32+, non-null entry point, sections inside
  `SizeOfImage`, populated import directory), byte-level SHA-256, and that the
  product actually loads.  Sample identity and frozen metrics come from
  `tests/cases/guoxing_shiguang.case`, not from literals in the test; the gate
  fail-closes on a SHA-256 mismatch.  Three log-parser self-tests run in the
  normal suite.  Discriminating power verified by flipping `expect_resolved`
  186 → 185 (gate fails) and back (gate passes).
- **Regression fixtures for the first fully-successful real-world case**
  (`crates/packers/themida/tests/regression_guoxing_shiguang.rs` + unit tests
  in `trace_imports::decision`): the packed sample's 16-section Themida v3 x64
  fingerprint (blank 8-space section names, `.winlice`/`.boot` memory-only
  stubs, OEP entering the VM via `call rel32`), the runtime Themida/IAT bounds,
  the observed slot-value taxonomy (zero separators, decrypted API blocks,
  VM trampolines, packed-32-bit data garbage), and the golden before/after
  metrics (50→186 resolved, 8→9 modules, crash slot `0x113C48` →
  `SetProcessDPIAware`).  11 integration tests + 8 classifier tests, all
  sample-free.
- `ARCHITECTURE_REVIEW.md` (workspace root) — dependency topology, end-to-end
  flow, the dual-engine defect, capability matrix, dead-code inventory, and a
  five-axis project review.
- `BRANCH_DECISION.md` (workspace root) — records that this branch is a
  sandbox on the 2026-07-09 fork point, and lists the assets worth porting back
  upstream.
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
