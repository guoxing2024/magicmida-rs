# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **The classic (v1-generation) unpack pipeline groundwork** — `/unpack` now
  routes V1/Ancient targets through a measured branch: at the shell's first
  `CloseHandle` the `.text` guard is installed directly (the v3 write-BP
  staging never fires for them), `IatFixStrategy::V1` handles the IAT, and the
  product's `.reloc` reservation is sized from a scan of the dumped image
  (gated on the dump having no `.reloc` of its own, so the v3 byte-goldens are
  untouched). Measured end-to-end on Themida 1.9.1.0 (version ladder): the
  full chain completes — guard → 222,985 recorded decompression-write faults →
  one `.text` execute candidate → IAT located (2,316 slots / 90 blocks) → 4
  entries repaired → imports rebuilt (74 thunks) → 2.77 MB product written,
  exit 0. The product loads and initialises but does not reach the unpackme's
  own UI (the packed control does) — dump quality is the remaining gap, and
  **"v1 unpacking works" is not claimed**. Two more measured shapes bound the
  claim: the 1.1.1 shell materialises the original via a file mapping
  elsewhere (zero in-place `.text` activity) and defeats the guard approach
  entirely; the first `.text` execute candidate cannot be verified by its
  return address (this shell's transfer leaves data, not a return, on the
  stack — the implemented verification probe logs why it did not arm).
  Companion fixes: `base_of_data` for classic targets comes from the first
  section's own span (the packed header's value is garbage — the guard used to
  cover half the code, OEP outside it, zero faults), `Ancient` maps to the V1
  IAT strategy, and `fix_iat_v1` leaves unreadable jumper slots untouched
  instead of aborting the unpack. The three e2e gates' log scrapers now strip
  the ANSI wrapping tracing puts around structured field names (a latent
  false-red: `module_count=` assertions could not match the wrapped form).
- **Themida/WinLicense version fingerprints for 1.x and 2.x** — measured on a
  76-sample version ladder (Themida 1.1.1.0–1.9.1.0, WinLicense 1.1.1.0–2.0.8.0,
  each labelled by its exact packer version, fetched from the archived Tuts 4 You
  Collection 2011; see RUNBOOK for the reproducible range-download recipe).
  `/analyze` now reports the generation: `Ancient` = `"Themida "` section name
  (1.1.1–1.8.2), `V1` = the classic import pair (exactly kernel32+comctl32,
  ≤ 4 functions — covers 1.9.1 whose section name the packer's user renamed),
  `V2` = the SecureEngine single-kernel32 import surface (function randomised
  per build) or the Pascal dual-`0x1000` stub rule. Measured corollaries, all
  pinned: section names are unreliable below 3.x; `is_themida_section` was
  blind to WinLicense 1.x's truncated `WinLicen` section name (19 samples
  missed — now routed); unlicense's 2.x section-start byte patterns score 0
  on this ladder and were deliberately not ported. WinLicense 2.0.8 shares the
  classic V1 surface — recorded as a documented ambiguity. The 2005-era stubs
  run on modern Windows; `/unpack` on 1.x/2.x is **not** claimed — a measured
  run ends `OEP not found` because the OEP pipeline is v3-shaped.
- **A version-ladder corpus gate** (`themida_ladder_gate`, runs by default,
  SKIPs when the corpus is absent like the VMProtect corpus gate): every
  ladder sample must classify by its labelled generation (76/76 measured) and
  carry a Themida-section shape; unit tests drive the import-surface rules on
  hand-built import directories, so the gate is green without the corpus.

- **UPX as the third packer (`mida-packers-upx`)** — measured against UPX 5.2.1
  output and cross-checked with UPX's own source at tag v5.2.1: the 32-byte
  `PackHeader` (version 13; PE32 = 9, PE32+/AMD64 = 36; method 8 = NRV2E_LE32
  by default, 14 = LZMA; header checksum `sum(bytes[+4..+32]) mod 251`), the
  **single-block** compressed stream (no `b_info` chain in the PE format),
  `c_adler` = standard Adler-32 seeded 1 (4/4 samples), the
  ident-inside-`UPX1` placement rule, and the structural invariant
  `UPX1_raw + align_up(ic + c_len, 16) == entry-point file offset` (4/4).
  Detection requires a valid header **and** UPX-named sections; `/analyze`
  prints the full layout and verifies the invariant per file. This round
  delivers detection + parse + report only — the static unpacker (NRV/LZMA
  decode, filter undo, PE rebuild, diffed against `upx -d`) is the next
  increment and is not claimed anywhere. `--packer upx` parses and refuses
  with that exact answer. `l_info`/`p_info` do not appear in UPX 5.2.1 PE
  output — measured, not assumed.
- **UPX static unpacker** — `/unpack <file> --packer upx` (and auto-detection)
  restores the original file with **no process and no desktop session**:
  NRV2E `le32` decode (UCL `n2e_d.c` port), LZMA with UPX's 2-byte property
  header (`compress_lzma.cpp` — *not* the `.lzma`-alone format), call-trick
  filter undo (`cto.h` 0x26 / `ctok.h` 0x49 including the `0F 8x` jcc arm),
  and the `unpack0` PE rebuild: imports from the compact blob, relocations
  from the delta stream (byte-swapped values, `size_of_block` counts the
  align-to-4 padding), resources from the packed tree. Verified
  **byte-for-byte against `upx -d`** on all four corpus samples — both
  architectures, both methods, both filters — with the recorded caveat that
  the ground truth is `upx -d`'s own output, not the pre-pack original (UPX
  rewrites the DOS stub area when packing and never restores it). Ported from
  the v5.2.1 sources fetched for the purpose; prototyped in Python first
  (`OUT\upx_unpack_proto.py`) exactly like the measurement round. `/analyze`
  no longer claims the decode is missing.
- **MCP `triage` classifies the packer** — the tool now answers with a `packer`
  object: `family` (`Themida` / `VMProtect` / `UPX` / `unknown`), the VMProtect
  `mode` (`min-protection` / `packed`), and the `evidence` / `absent` lists
  behind the verdict, so a model can pick the pipeline before paying for a
  run. The gate order matches `/analyze`: structured detection first, Themida's
  markers only when both say no. The `themida_markers` block and
  `likely_themida` are kept for compatibility. Also corrected while there: the
  x86 `hint` still described the pre-2026-10-24 state ("import wiring not yet
  correct"); x86 has been a verified end-to-end path since then.
- **Guided mode for beginners** — running `mida-cli` with **no arguments** no
  longer errors out; it starts a three-step wizard: pick a file → static
  recognition (same gate order as `/analyze`: VMProtect → UPX → Themida) →
  one suggested command with the reasoning printed, confirmed before it runs.
  Explicit spellings (`interactive` / `-i`) run the wizard even with piped
  stdin, which is how it is smoke-tested (a real UPX sample driven through
  the wizard produces the golden product hash `459f4f8e…`); a bare no-args
  invocation with a non-terminal stdin prints the friendly help instead of
  blocking on a prompt nobody can answer. Mistyped commands now get a
  "did you mean" suggestion (bounded edit distance ≤ 2 or a ≥3-char prefix),
  and `--help` is rewritten: grouped by intent, with the guided mode and the
  desktop-session requirement stated up front.
- **GUI beginner surfaces** — drag-and-drop now reacts *while* the drag is
  over the window (the empty state's drop box highlights and re-labels to
  「松开鼠标载入文件」); a 流程·三步 strip (选择文件 → 开始脱壳 → 验证产物)
  sits under the drop box; a successful run gains a one-click
  「打开产物位置」 button (Explorer `/select` on the product); and the
  开始脱壳 button explains the target-windows-will-appear surprise in its
  tooltip before it happens.
- **The GUI now exposes the CLI's unpack options** — `mida-run` grows
  `PackerChoice` / `SpawnOptions` / `unpack_args` / `Job::spawn_with` (the
  old `spawn` signature is kept and delegates with defaults, so the MCP
  server is untouched), and the GUI's 选项 section gains a 壳类型 dropdown
  (自动检测/Themida/VMProtect/UPX, each with a one-line hint), a
  恢复数据段 (`--data-sections`) checkbox and a 收缩 Themida 段
  (`--shrink`, default on like the CLI) checkbox — all disabled while a run
  is in flight. The start button's tooltip adapts: on the UPX branch it
  promises a static run instead of warning about target windows. A unit test
  pins `unpack_args` to reproduce the old hand-built command line under
  defaults, so the MCP path cannot drift.
- **The guided mode gains a verify branch** — the wizard now opens with
  要做什么 [1=脱壳/分析文件 2=验证产物]; branch 2 walks through `/verify`
  (product path → reference path → confirm → run), the one advanced command
  that is read-only and headless and therefore safe to hand a beginner.
  Smoke-tested end to end through piped stdin against a real UPX product and
  its `upx -d` reference (`Verification PASSED ✓`).
- **README screenshots** — the GUI's option rail and a finished run are now
  embedded in the Quick Start (`docs/img/`), captured with `PrintWindow` so
  no input automation and no focus stealing is involved.
- **NRV2B and NRV2D decoding** — the UPX static unpacker now covers all four
  PE methods. The three UCL NRV variants share one ported core (`nrv.rs`,
  from `n2b_d.c`/`n2d_d.c`/`n2e_d.c`; the deltas — B's branchless offset
  loop and 0xd00 threshold, D/E's LSB-theft length seed and 0x500, E's extra
  selector level — are tabulated in the module doc), with `nrv2e.rs` turned
  into a thin wrapper whose existing hand-built vector proves the refactor
  faithful. New vectors come from `OUT\nrv2bd_encode.py` (BFS over the
  decoder's own ops, self-verified against embedded Python ports and
  cross-rejected: B's stream fails D's decoder and vice versa). Real-sample
  proof: `upx --nrv2b` / `--nrv2d` on the two corpus originals unpack
  byte-for-byte to the same `upx -d` goldens as NRV2E/LZMA
  (`459f4f8e…` / `da7a1dce…`) — three new gate entries, corpus now seven
  samples. The port bug this caught: B reads *two* fresh length bits, the
  first Rust draft consumed one and desynced — exactly what the vectors are
  for. 
- **UPX behaviour gate** — the byte gate proved the products equal `upx -d`
  but never ran one; the new `upx_behavior_gate` (runs by default, no
  desktop session) unpacks all six `mida-cli`-derived corpus products and
  probes each with `/version` against its **pre-pack original as the
  control**: exit 0, stdout equal to the control's, and the control itself
  must answer the version banner first (so both-sides-fail-identically
  cannot pass). `injector_x64.upx.exe` is deliberately excluded — spawning
  ScyllaHide's injector from a test is a side-effect risk the mida-cli
  products (a full 6 MB rebuild exercising imports/relocs/TLS) don't need.
  Discriminating power measured: corrupting a product's
  `AddressOfEntryPoint` makes the probe die with `0xC0000005` and empty
  stdout — exactly what the two assertions catch.
- **DLL gate control method** — the last hard, environment-sensitive window
  assertion is now control-gated, mirroring the EXE gate: the **protected
  original** runs through the same acceptance harness first (a plain
  `LoadLibraryW` suffices for this shell — `LOADED=1 VERSION=1.1`), and the
  judgement table decides: control creates+shows its window → the product's
  window asserts stay hard (class/title/visibility); control itself cannot
  show it (measured in a real session: `WINDOW_FOUND=1 WINDOW_VISIBLE=0`) →
  the window checks print `NOT EXERCISED` naming the environment while
  `LOADED`/`VERSION` remain hard; a control that does not load/answer fails
  loudly ("this session cannot judge"). Discriminating power measured: a
  wrong manifest title reds the gate on `WINDOW_TITLE`. The same round found
  and fixed a buried gate defect: all three e2e gates resolved
  `mida-cli.exe` profile-relatively, so `cargo test` silently ran the
  **debug** pipeline — which reproducibly loses the shell's main thread
  before the IAT trace (`OpenThread` succeeds, `GetThreadContext` returns
  `ERROR_INVALID_HANDLE`; release passes 9/9, debug fails 7/7, with env /
  cwd / pipes / stdin ruled out one by one) — the gates now prefer the same
  target triple's release binary. The DLL byte golden was re-recorded a
  third time (`8ba37a79…`): the live-IAT count still read 288 yet the bytes
  moved again, and an A/B run with the `48fa9d4` worktree binary produced
  byte-identical products — the session has more than one dial, the code is
  innocent (manifest and POSTMORTEMS carry the evidence).

### Fixed
- **The decoded VMProtect payload was named and sold as an EXE** — the measured
  `Packed`-line product `e7004e89…` carries `IMAGE_FILE_DLL` (file
  characteristics `0x2022`), so `CreateProcess` refuses it with "is not a valid
  application for this OS platform" and a user handed `…rcdata131.decoded.exe`
  got exactly that. The launcher family (`zz_test.exe`, byte-identical to
  `启动器10.9.exe`) loads it with `LoadLibrary`. Both carve paths
  (`/analyze --extract`, `/dump-image`) now name the decoded output by what the
  bytes declare (`is_dll_image`, unit-tested): `…rcdata131.decoded.dll`.
- **`mida-run` parser missed the non-Themida product lines** — `RunState
  .output_path` / `output_size` were only filled from `Unpacked: <path>`
  (Themida) and `Dump written successfully path=…` (/dump-image), so a fully
  successful UPX run showed 产物 `—` and never enabled the GUI's follow-up
  button (measured on 2026-10-26 in the GUI acceptance pass). The parser now
  also reads `Wrote <path> (<n> bytes), …` (UPX static unpacker) and
  `Wrote <n> bytes to <path>` (/dump-image), pinned by two unit tests.
- **`/unpack auto` would have run the Themida loop on a UPX target** — `UPX0`
  is an executable section with `raw_size == 0` and a large virtual size,
  exactly the shape `is_themida_section` keys on (measured on the real
  sections, pinned in the upx crate's gate). The gate now runs
  VMProtect → UPX → Themida in that order, before any process is created.
- The gate's log no longer attaches the VMProtect structure report to
  non-VMProtect verdicts (measured: a UPX verdict printed a meaningless
  "large resources: none" VMProtect report above it).

## [0.3.0] — 2026-10-26

Released: tag `v0.3.0` → commit `1bb1931`; GitHub Release with four assets,
each verified by size + sha256 after download.

The branch now turns a measured VMProtect target into a product: it identifies
the packer and its mode, reports the structure, extracts payloads that are in the
file, captures a live image for targets whose code is not, and decodes the
payload to a runnable PE. The measurement tables are in
[`docs/RUNBOOK.md`](docs/RUNBOOK.md).

The honest boundary: the payload decode is a **per-family measured key**, not a
cipher break, and it was validated on one vendor family. Two `Packed` samples
and 14 `MinProtection` samples exist here; `FullVirtualize` was not exercised
and x86 VMProtect targets are unmeasured.

### Added
- **`mida-packer-api`** — the workspace's first real packer abstraction:
  `PackerKind` / `VmProtectMode` / `Family` / `Evidence` / `Detection` and the
  `Packer` trait. A verdict carries the evidence that produced it *and* the
  markers that were absent, because `likely_themida: false` with no reason is
  not diagnosable.
- **`mida-packers-vmprotect`** — detection, mode classification, and a static
  structure report: runtime section, packed sections, virtualised-function stubs,
  scrambled `.pdata`, relocated exception directory, and large `RT_RCDATA`
  payloads with size, file offset, entropy, sha256 and printable magic.
- **`/analyze <file> [--extract <dir>]`** — static analysis with no debugger and
  no desktop session. The static report used to be reachable only by running
  `/unpack` and reading the resulting error, which is not a usable entry point
  for a documented capability. It answers for Themida as well, and names the
  markers it looked for when nothing matches.
- **`/dump-image <pid> <out> [--wait]`** — flatten a running process's loaded image into a
  file, reading memory through `OpenProcess` + `ReadProcessMemory` and never
  attaching a debugger. Output is a flat image (`file offset == RVA`), and ASLR
  is undone by walking `.reloc` and subtracting the load-base delta. With
  `--wait`, it keeps sampling until the image stops changing — required for a
  `Packed` target, whose payload is rewritten in place after start-up, and it
  keeps a sample already read even if the process exits mid-loop. Payloads are
  carved out of the image afterwards.
- **Payload decode to a runnable PE** — the carved container decodes to a valid
  PE32+ x64 image. The key is recorded per `(resource type, resource id)` in
  `crates/packers/vmprotect/src/payload_xor.rs`, derived from two independent
  artefacts (a single 32-byte repeating XOR: `K[i] == K[i-32]` holds across all
  12,782,080 bytes with one distinct block and only 31 distinct byte values).
  Acceptance is structural — the result must parse as a PE — so a wrong key is
  rejected rather than producing plausible garbage.
- **A corpus gate over third-party samples** — the static gate walks every
  `*.vmp*.exe` in a sample directory and requires each to be recognised and
  classified, with the two modes staying distinguishable on real files.
  Measured: 14 recognised, all `MinProtection`, 0.03 s, no desktop session.
- **`--packer auto|themida|vmprotect`** for `/unpack` — `auto` keeps the refusal;
  the other two make a heuristic verdict overridable for diagnostics, with the
  override logged.
- **Per-packer ScyllaHide profile** — `crates/cli/assets/scylla_hide.ini` is now
  tracked and carries three profiles. The VMProtect profile's hook set is
  ScyllaHide's own `[VMProtect x86/x64]` preset; six debugger-integration keys
  are taken from this project's working profile instead, because those presets
  target an interactive debugger and this project drives its own CLI loop.
- **A static gate that runs in CI** — `tests/vmprotect_static_gate.rs` is
  deliberately **not** `#[ignore]`d: it only reads files, so it needs no desktop
  session. It skips with an explicit `SKIP:` line when a sample is absent rather
  than failing, and includes a Themida negative control.

### Fixed
- **An uninitialised section was classified as a packed one** (`vmprotect`).
  The rule asked "is any executable section empty?", and an ordinary `.bss` — or
  VMProtect's own `.textbss`, `raw_size 0`, `virtual_size 0x10000`, executable —
  satisfies it. **12 of the 14 corpus samples have that shape**, so a
  MinProtection sample reported as `Packed` while `.text` still held real code
  and the entry point sat inside it. The criterion is now which sections *lost a
  body they would normally have* (`.text`/`.rdata`/`.data`/`.pdata`/`.idata`/
  `.reloc`/`.rsrc`/`.tls`). Found the moment the branch met samples it did not
  author — the argument for a corpus gate over two hand-picked samples.
- **A VMProtect target was classified as Themida and driven as one.** `/unpack`
  on the `Packed` sample printed `Themida version: V3`, created the debuggee and
  ran the entire Themida loop against it, ending in `OEP not found` after 8 s.
  Themida's section heuristic (`raw_size == 0` plus a large virtual size) is
  satisfied by that sample's `.rdata0` **and** by 6 genuine Themida samples, so it
  could not be tightened into a VMProtect test. The packer decision now runs
  first; the same command refuses in 20 ms with evidence and a structure report,
  and creates no process.
- **`ScyllaHideConfig::ini_path` was inert.** The injector is launched as
  `InjectorCLIx64.exe pid:<pid> <HookLibraryx64.dll> nowait` — with no ini
  argument — and nothing ever read the field; both call sites set it to `None`.
  The field is removed and `select_profile()` is the real mechanism.
- **`.gitignore`'s bare `scylla_hide.ini` pattern matched at any depth** and
  swallowed the profile file this project authors, so the first commit shipped
  the README describing it but not the file.
- **`/analyze --extract` recommended the wrong follow-up command** for `Packed`
  samples: `/dump-process` writes a single section and is Themida-specific.
- `replace_current_profile` wrote `\r\r\n` for a CRLF line and did not recognise
  `currentprofile = A`. Both were caught by the tests written for it.

### Changed
- `README.md` capability tables now cover VMProtect, with the modes and the
  non-claims stated explicitly.
- `mida-cli /help` and the usage strings list the new commands.

### Not verified
- **`/dump-image`'s read path cannot be exercised in CI** — it needs a live
  process. The relocation walk it depends on has unit tests, and the read was
  measured end to end (9/9 sections flat, the payload carves and decodes
  byte-exactly), but reproducing the given reference artefact (`b6355439…`)
  needs an elevated session: that sample family registers a `RUNASADMIN`
  compatibility layer for its own path, and an elevated target cannot be opened
  with `PROCESS_VM_READ` from an unelevated one.
- **The ScyllaHide profile's hook set was not observed on a live target**, for
  the same reason.
- **devirtualisation** is not attempted and not claimed.
- **The payload decode is one measured key, not a cipher break.** It covers the
  one family it was derived from; another VMProtect build needs its own
  measurement.
- **`FullVirtualize` was not exercised** — it is a per-function option and
  producing such a sample needs VMProtect's project file, whose schema was not
  recovered. Both binaries of the installed VMProtect Demo 3.11 are themselves
  VMProtect-packed, so the schema cannot be read out of them statically.
- **x86 VMProtect targets are unmeasured.** The detector is not
  architecture-specific, but no x86 target has been run.

## [0.2.0] — 2026-10-25

First tagged release.  Everything below was measured on the dev machine; where
something is unverified it says so.


### Fixed
- **x86 pipeline now runs end to end** (`packers::themida`, `core`).  The x86
  target compiled but had never produced an unpacked binary.  Four independent
  defects were located by measurement:
  1. *The OEP guard assumed DEP.*  Branch 4 relaxed `.text` to
     `PAGE_EXECUTE_READWRITE` and relied on a fault when a TLS callback returned
     into the Themida section — but `x86_c.exe` does not set `NX_COMPAT`
     (`DllCharacteristics = 0x0000`), so DEP is off for that image and the
     return simply executed.  Measured: 40 s with zero further access
     violations and the real EP never reached.  Fix: plant `int3` on the callback
     return address, which fires regardless of DEP; consume it by rewinding
     `Eip`, because otherwise the shell's first instruction (`pushfd`) is
     skipped and the target storms.
  2. *TLS-callback detection never worked on PE32.*  Three stacked defects:
     `tls_dir.size < 40` hardcoded the **64-bit** `IMAGE_TLS_DIRECTORY` size
     (PE32's is 24, so every 32-bit target returned 0); `AddressOfCallBacks` was
     read at `+0x18` instead of `+0x0C`; and the callback count divided a VA by
     an RVA.  The callback array is also encrypted on disk in both reference
     samples, so it can only be read from live memory — a bounded guess of 4 is
     used, and the guard now validates the callback parameter signature
     (`(hInstance & 0xFFF) == 0 && fdwReason <= 3`) so a real OEP is not
     swallowed as a callback.
  3. *`find_iat_ref_from_address` had no cycle detection.*  Recursing into
     `call rel32` targets with neither a depth limit nor a visited set overflowed
     the main thread's stack on x86 `.text` (which is mutually recursive).
  4. *`.reloc` reservation left a hole in the virtual layout.*  `create_reloc_section`
     reserved `0x2000` and declared it as `virtual_size`; when
     `build_relocation_table` later shrank it to the real length the following
     sections were not moved, so their VAs were no longer contiguous.  **The
     loader rejects any image with a VA gap**: measured
     `ERROR_BAD_EXE_FORMAT (193)`, while the same product passed every `pefile`
     structural check — and injecting a gap into a known-working control sample
     failed with the same 193.  The reservation stays `0x2000` (it determines
     where `.import` lands and therefore `SizeOfImage`, so shrinking it would
     move the x64 golden); `build_relocation_table` now grows `.reloc`'s
     `virtual_size` up to the next section's VA instead.
- **`.bss` raw-size rule was an x64 regression** (`pe::section`).  Making
  `SizeOfRawData = 0` for uninitialised sections is correct on x86 (with captured
  bytes the product loads and resolves its imports but **never creates a
  window**; zeroing them makes the window appear in 16 ms) and wrong on x64
  **DLL**, where it discards the globals the shell had finished writing
  (`GetAppVersion()` returned `"0.0"` instead of `"1.1"`).  The same rule has
  opposite conclusions per architecture, so it is now gated on the *target*
  architecture (`PeHeader::is_64bit`).  This went unnoticed because the binary
  used for that round's verification predated the commit that introduced the
  rule.
- **The first section's flags were wrong on x64** (`pe::section`).  The code
  granted `MEM_WRITE` unconditionally to 64-bit targets and only conditionally to
  32-bit ones — an arch split kept solely so the two x64 goldens would not move,
  not a measured requirement.  All four protected inputs declare `0x60000020`,
  so none of them should receive the bit.  Before changing it the bit was proved
  not load-bearing: hand-patching one byte in each x64 product left behaviour
  identical (DLL still `VERSION=1.1` / `PigToGoLicenseDialog` /
  `RUN_THREAD_ALIVE=1`; EXE still reached `授权验证`).  The rule is now
  uniform — a section gets `MEM_WRITE` only if it declares code *and*
  initialised data.  Products changed by exactly one byte and both goldens were
  re-recorded.
- **`ERROR_SEM_TIMEOUT` was unreachable** (`core::windows_debugger`).  The code
  compared the whole HRESULT against `121`:
  `HRESULT_FROM_WIN32(121) = 0x80070079`, so `CoreError::Timeout` never fired and
  every idle tick became a hard error.  Now a single
  `windows_debugger::is_sem_timeout(hresult)` (`& 0xFFFF == 121`), and
  `CoreError::Windows` stores the low 16 bits.  Four unit tests guard it,
  including `assert_ne!(hresult, 121)` to pin the original bug.
- **The `Real OEP not found` false alarm is now `debug!`** (`oep`).  It is one
  attempt among several and the caller retries successfully; it nevertheless
  printed four yellow lines on every successful EXE run, and the claim itself was
  false.  Measured count after the change: 0.
- **`.pdata` was emitted as zeros** (`postprocess`).  Both products carried a
  50 KB exception table whose non-zero byte count was **0** — not a harmless
  warning, because the dispatcher treats it as a `RUNTIME_FUNCTION` array.  The
  root cause is ordering: `shrink_sections()` compacted the header before the
  live image was read, and the table lives in `.winlice`, which was already
  excluded from the buffer.  Live memory held real data (DLL 4198 entries, EXE
  4011).  The table is now read *before* shrinking and filtered against the
  product's own section table; if nothing survives, no `.pdata` is emitted at
  all, because an all-zero table is worse than none.
- **A non-UTF-8 line killed the whole MCP server** (`mcp`).  MCP's stdio
  transport is UTF-8, but on Windows the client is often a PowerShell script
  whose `StandardInputEncoding` defaults to the console code page (GB2312 here).
  A `triage` call carrying `D:\Projects\shiguang\时光一键宏.exe` arrived as GBK
  bytes, `BufRead::read_line` returned `InvalidData`, and `?` in `main` ended the
  process — the client saw a dead pipe with no diagnostic.  Reading is now
  byte-oriented (`read_until(b'\n')`) with a `decode_line()` that tries UTF-8,
  falls back to the ANSI code page, then to lossy: no byte sequence can end the
  session.  Five unit tests pin it.
- **The MCP server announced a protocol version no SDK recognises** (`mcp`).
  It replied to every `initialize` with a hardcoded `"2026-07-28"` — a string
  that was assumed, never measured.  The SDK bundled with the client lists
  `["2025-11-25","2025-06-18","2025-03-26","2024-11-05","2024-10-07"]`, so the
  real client rejected the handshake and the tools never appeared, while the
  server itself was fine.  All three harnesses asserted the invented version, so
  they agreed with each other and were all wrong.  `initialize` now negotiates.
  A unit test pins `SUPPORTED_PROTOCOL_VERSIONS` against the real SDK list.
- **`JobHandle::snapshot()` deadlocked itself** (`mcp`).  It re-locked the same
  `std::sync::Mutex` by calling `self.report()` while holding `state`; the first
  run therefore hung the server permanently (measured: `unpack_status` never
  returned, the client timed out at 150 s).  The lock is now released before the
  JSON is built.
- **The MCP server only knew about one CLI** (`mcp`).  An x86 target produced
  `File is for the wrong architecture (Machine=IMAGE_FILE_MACHINE(332))` — a
  correct diagnosis through the wrong pipe.  It now reads the target's own PE
  header and selects `mida-cli.exe` or `mida-cli-x86.exe`, reporting a precise
  error when the x86 CLI is absent.
- **ScyllaHide injection deadlocked the debug loop** (`core`,
  `packers::themida`).  `inject_scylla_hide` waited for the injector to exit.
  The injector hijacks the target's main thread, and a debuggee holding an
  unacknowledged debug event has **all** its threads frozen until the debugger
  calls `ContinueDebugEvent` — so waiting inside the `CREATE_PROCESS` handler
  deadlocks.  Measured with a probe: target running → injector exits in 47 ms;
  target `CREATE_SUSPENDED` → still running after 15 s; resume-then-spawn →
  47 ms again.  The function now spawns and returns immediately.
- **The EXE gate blamed the dump for an external dependency** (`test`).  "Still
  alive after 20 s" conflated "the product reached its GUI" with "the product
  needed the network".  Measured on one machine: the original packed sample
  showed `程序启动` ("cannot fetch program module, check your network") and was
  alive at 20 s, while the byte-identical-to-golden product showed **zero**
  top-level windows and exited after 198 ms — neither reached `授权验证`.  The
  gate now runs the original packed sample as a control: control reaches the
  window + product does → pass; control reaches + product does not → dump-side
  defect; control does not → the check is not exercised on this machine, which
  is reported loudly and still requires the product not to crash.
- **The DLL golden hash was wrong twice** (`test`).  First: the old record
  corresponded to a product whose `.bss` held **1** non-zero byte; `.bss` is
  where the shell parks initialised globals, so 1 byte means "dumped before the
  shell finished" and 81 means "it finished".  The 11 extra qwords are in-image
  pointers, deliberately kept and then rebased by `fix_hardcoded_addresses`.
  Second: the `.text` fidelity fix above.  Both new values are deterministic;
  the old ones were the error.
- **IAT head location regressed on the DLL line** (`resolved` 289 → 14,
  `packers::themida`).  Five independent defects: a bare RVA was treated as
  "unknown, keep walking" when it is in fact a boundary (both samples have one
  immediately before the table head); the walk result was discarded twice (once
  by `select_primary_block` falling back to the largest block, once by
  `combined_start` re-adding the padding); the merge conditions conflict between
  the two samples and are only separable by *how far the walk travelled*, not by
  gap width; the read window was one-sided, leaving zero forward space when
  `iat_ref` sat in the last slot; and the table head was never trimmed of its
  leading padding.
- **Stale live pointers were dumped into the file** (`dump_process`).  Pointer-
  width qwords in writable, non-executable sections that hold this process's
  live addresses and lie outside the image are now cleared (EXE 21, DLL 28).
  Filtering by the relocation table is impossible — the packed input's table is
  empty (`size = 0x10`) and the real one is only built later.
- **TLS template length made the whole-file hash non-reproducible** (`dumper`).
  Themida updates `IMAGE_TLS_DIRECTORY.EndRawData` lazily; ten runs of one
  binary produced `StartRawData+0x8` and `StartRawData+0x8008` interchangeably.
  `normalize_tls_directory()` now clamps it to the template length declared by
  the protected input, and only ever shrinks.  10/10 runs now match.
- **Module snapshot order leaked into the output** (`dumper::remote_modules`).
  `TH32CS_SNAPMODULE` returns loader order, which varies because the OS resolves
  some dependencies asynchronously.  Sorted by module base now.
- **IAT trace aborted early on fragmented v3 IATs** (`trace_imports`).  The
  trash counter treated already-resolved API addresses as garbage and stopped at
  slot 142 of 1063; ~900 slots kept VM trampolines and the dump crashed with
  `0xC0000005`.  Slot classification is now a pure function
  (`classify_iat_slot` / `IatSlotDecision`).  On the reference sample: 50 → 186
  resolved imports, 8 → 9 modules, the product launches.
- **Eight / three / fifty-five IAT slots were mis-reported as failures**
  (`trace_imports`).  They hold bare RVAs into read-only data, exactly what the
  real Windows loader sees.  A new `IatSlotDecision::NotAnImport` classifies them
  separately so that a genuine failure cannot hide inside "data"; the EXE's
  product bytes were unchanged by the reclassification.
- **Loader host polluted the user's sample directory** (`core`).  It is now
  written under `%TEMP%\magicmida-hosts\`, and "cannot delete yet" is a
  `debug!` rather than a `WARN`, because the host is a cache.  Passing a relative
  DLL path broke after the move — `CreateProcess` sets the child's CWD to the
  host directory — so the DLL argument is canonicalised first.
- **`major_linker_version == 2` was treated as "no CRT pattern"**
  (`cli::unpacker::av_handler`).  MinGW/GCC reports `MajorLinkerVersion = 2`
  (measured: i686-w64-mingw32-gcc 16.2.0 → 2.47) and its CRT has the same
  `call rel32; jmp rel32` shape, so that line made **every MinGW target** skip
  OEP pattern matching.
- **The AV storm watchdog was silently disabled** (`cli::unpacker::av_handler`).
  The counter was reset unconditionally on every guard fault, including faults
  that are not in the guarded page at all — the shell dereferencing a null
  pointer (`0x538866` reading `0x5`, 156,000 times, log grown to 1.6 GB).  Reset
  now happens only when the fault target lies inside the guarded `.text`, and the
  run fails in 4 s with `Target is stuck: 1024 consecutive identical access
  violations`.  Eight unit tests guard the semantics.
- **`DBG_CONTINUE` was the wrong status for first-chance exceptions**
  (`core::windows_debugger`).  Unmodelled exceptions were returned as errors,
  which killed runs that the program's own SEH would have handled — and Themida
  uses exactly that (`STATUS_PRIVILEGED_INSTRUCTION`, `0xC0000096`) as an
  anti-debug probe.  They are now `DebugEvent::UnhandledException`, and the
  continue status must be `DBG_EXCEPTION_NOT_HANDLED`, not `DBG_CONTINUE`
  (the latter resumes at the faulting instruction and re-raises forever).
- **A sparse IAT write could land in the PE header** (`unpacker`).
  `section_rva_to_file_offset` fell back to `rva as usize` for out-of-section
  RVAs, so a thunk the trace could not locate wrote `BF 90 01 00` at file
  offset 0 and overwrote `MZ`; the dump then failed with
  `Invalid DOS signature`.  It is now skipped and reported.
- **Two shrink counters read like a contradiction** (`postprocess`,
  `dumper::header_patch`).  One counts sections dropped from the in-memory model,
  the other from the live header; they were never meant to match but both said
  "Shrink complete".  They are labelled by stage now.
- **GUI console flashes, window sizing** (`gui`).  Four sources of a black CMD
  box were fixed (debuggee `CREATE_NEW_CONSOLE` → `CREATE_NO_WINDOW`, the gcc
  invocation, ScyllaHide's injector, and the GUI's own subsystem).  The window
  now fits the screen on the first frame using `DWMWA_EXTENDED_FRAME_BOUNDS`
  (measured 1076×699 natural size on a 1600×900 screen with an 852-high work
  area).
- **x86 ScyllaHide hashes were all-zero placeholders** (`binaries`), which
  `verify_sha256` rejects by design.  Real hashes are filled in.

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
- **Zero compiler warnings on both architectures.**  Starting from 16 (x64) the
  cleanup removed the dead stub-EXE path, arch-gated the `*_AMD64` imports that
  only exist on 64-bit hosts, dropped an empty `#[cfg(x86)] pub use` block,
  removed an unread struct field, and renamed `NtQIP_SYSCALL_NUMBER` to
  `NT_QIP_SYSCALL_NUMBER`.  `cargo build --release --workspace` is now silent for
  both `x86_64-pc-windows-gnu` and `i686-pc-windows-gnu`.
- **README rewritten to match measurement.**  The previous text contradicted
  itself: it claimed the DLL product returned `"1.1"` in one section and `"0.0"`
  in another, described x86 as "builds, never run" with "no x86 sample", and
  said "only the EXE row has an automated gate" when three gates were green.
- **Version 0.2.0.**  First tagged release.

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
- **The dead `DLL → stub EXE` code path** (`core::process`).  Replacing a packed
  DLL's headers and appending an entry-point shim was abandoned when the real
  loader host was introduced; the shim bypassed `DLL_PROCESS_ATTACH` sequencing
  and the shell died at `.winlice+0x33E22E`.  Removed: `make_dll_executable`
  (276 lines), the x86/x64 stub byte arrays and their patch offsets,
  `STUB_EXE_SUFFIX`, `PeInfo::has_force_integrity`, and the two
  `DllCharacteristics` helpers that only served it.  `cleanup_stub_exe` stays —
  it still sweeps the loader-host cache.
- Removed `CLAUDE.md` (internal development guide) from the public repository
  and added it to `.gitignore` (P1-5).
- Removed the dead free function `session::get_thread_context_control`; every
  call site goes through the `DebuggerCore` trait method of the same name.
- Removed the duplicate in-loop IAT trace engine (`cli::unpacker::iat_trace`,
  558 lines).  Two engines resolved IAT slots in the same process: the
  production one in `packers/themida/trace_imports` (post-loop, 186 resolved)
  and a second in-loop copy that resolved 0 of 46, discarded its own result, and
  polluted the target's memory.  Deleting it left the product byte-identical.
- Removed three dead dependencies and the `mida-tracer` crate (`LogMsgType`
  moved down into `core`): 6 crates → 5.

### Added
- **MCP server** (`mida-mcp.exe`, `crates/mcp`).  Five tools —
  `triage`, `unpack_start`, `unpack_status`, `unpack_cancel`, `verify` — so an
  AI client can drive the pipeline.  The job model exists because unpacking is
  not a 60-second operation: measured x86 success 5.5 s, x64 success ~27 s, x64
  failure path 466 s, and the debug loop's `wait_event()` has no timeout at all.
  A single blocking tool would be cut off by the client on exactly the failure
  path where its diagnostics matter.  `unpack_status` long-polls for at most
  45 s, deliberately below the client's 60 s.
- **`mida-run` crate** (`crates/run`).  The GUI's log parsing and job state were
  lifted out so the GUI and the MCP server share one definition of "success".
  `RunReport` requires all three of: exit code 0, a `Done.` line, and no fatal
  error.
- **GUI** (`mida-gui.exe`, `crates/gui`).  Graphical front-end over the same
  pipeline.
- **Fifth end-to-end gate: x86** (`tests/x86_e2e_gate.rs`,
  `tests/cases/x86_sample.case`).  Asserts **both** byte reproducibility
  (4/4 runs → `cf176ac9…`, 110,592 B) and behaviour (window `MidaX86Sample` /
  `验证 x86 样本` in ~24 ms).  Unlike the EXE gate it needs no control sample:
  the x86 sample is a local program with no remote dependency.
- **`.text` first-section-characteristics assertion** in both x64 gates
  (`expect_first_section_characteristics: 0x60000020`), plus a manifest
  self-test that pins "do not write `0xe0000020` here" — treating the packer's
  own signature as the target is exactly what the assertion exists to prevent.
- **Documentation**: `docs/RUNBOOK.md` (toolchain setup, test order, gates,
  building x86 samples) and `docs/POSTMORTEMS.md` (every fixed defect with the
  measurement that located it).

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
