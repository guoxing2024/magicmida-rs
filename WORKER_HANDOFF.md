# WORKER_HANDOFF - R2-Slice2b DebuggerCoreEngine

## Summary

Phase2 closed (flip=No). R2 progress:

| Slice | Deliverable |
|-------|-------------|
| 1 | `mida_core::addr` newtypes |
| 2 | `RuntimeEngine` + `ReplayRuntimeEngine` |
| 2b | `DebuggerCoreEngine<D>` live adapter (CLI not switched) |

Docs: [VNEXT_R2_RUNTIME_API.md](docs/VNEXT_R2_RUNTIME_API.md).
**Next careful step:** optional CLI pump migration, or PackerPlugin trait
stub — prefer zero live behavior change + Origin smoke if CLI is touched.

## R1-E deliverables (this slice)

| Artifact | Role |
|----------|------|
| `PlannedSection.virtual_address: Option<u32>` | Preserve host/map section RVAs during pure rebuild |
| `RebuildPlan.fallback_data_directories` | Carry host data directories when typed builders leave zeros |
| `PureRebuildEmitOptions.preserve_section_vas` | Default true: keep host section VAs |
| `PureRebuildEmitOptions.carry_host_data_directories` | Default true: copy host DD table as fallback |
| `PureRebuildParitySnapshot` | Offline pure-vs-host structural gates (not acceptance) |
| `emit_pure_rebuild_with_parity` | Emit + host/pure snapshots for parity tests |
| `byte_map::plan_from_memory_image` | Preserves section VAs + host DDs |

### Pure vs legacy dump paths (R1-E)

```text
dump_process(...)
  host: live capture, overlays, import section (extra_data), IAT fill
  |
  +-- opts.pure_rebuild == true  --> pure_rebuild_adapter::emit_pure_rebuild
  |       plan_from_host_dump:
  |         - section data from extra_data or VA dump slice
  |         - preserve_section_vas (host RVAs)
  |         - fallback_data_directories (import/IAT/TLS/...)
  |         - optional exception/reloc typed rebind
  |       rebuild_pe_image_with_meta -> PE bytes
  |
  +-- opts.pure_rebuild == false --> legacy write_output_file
          serialize_headers + section raw write + IAT patches
```

Default remains **legacy** (`pure_rebuild: false`). Origin live structural
parity is met (Phase 2); flip still requires explicit multi-case decision +
optional Lunlun pure smoke.

### Phase-2 live pure alignment (2026-07-23)

| Change | Why |
|--------|-----|
| pure emit `image_base` = preferred (host-patched), not `DumpOptions` ASLR | closed pure `0x7ff…` vs legacy `0x140000000` |
| `header_patch` also sets `pe.image_base` | top-level cache was stale after optional_header restore |
| live pure: `rebind_exceptions/relocations=false`, `prefer_aslr_when_relocs=false` | keep `.winlice` cover sections; avoid trailing typed `.pdata`/`.reloc` |

Evidence (vault only):

- `D:\MidaVault\lab\evidence\origin_macro\live_20260723-173403_p2align2_pure\`
- R0B `StructuralPassBehaviorPending`, failures `[]`
- `structural_compare_vs_p1smoke.json` → **verdict: structural_equal**
- Intermediate: `…-173130_p2align_pure` (winlice fixed; image_base still ASLR)
- Prior mismatch baseline: `…-165826_p1pure_pure` (9 mismatches)

Unit tests: `content_cover_sections_kept_when_rebind_off`,
`exception_rebind_skips_cover_section` (+ existing pure_rebuild suite **9/9**).

### Parity evidence criteria (pure vs legacy emit)

Structural gates (offline, unit-testable; **not** `mida-acceptance` verdicts):

1. **Arch / EP / base / subsystem** match host model after reparse.
2. **Import DD** (RVA+size) and **IAT DD** match host when host set them
   (content-carried `.import` + host directories).
3. **Critical section names** present: `.text`, `.import`, `.edata`, `.boot`,
   `.rdata`, `.data`, `.rsrc` when host had them.
4. **Host section VAs** preserved for content sections under
   `preserve_section_vas` (import DD targets remain valid).
5. **Typed rebind ownership**: when pure rebuilds exception/reloc sections,
   those DDs may point at pure-owned shells; host content shells are skipped.
6. **Out of scope for R1-E**: byte-identical files, runtime behavior, full
   import descriptor tree reparse (R2/R3 + acceptance).

`PureRebuildParitySnapshot::structural_mismatches` implements gates 1-3 (+ TLS
when both non-zero). Tests cover VA preserve + import/IAT DD carry.

### R1-E close-out evidence (landed)

Offline dual-path corpus in `pure_rebuild_adapter` unit tests (no vault samples):

| Test | What it proves |
|------|----------------|
| `r1e_dual_path_import_content_structural_corpus` | Host model with content-carried `.import` + import/IAT DDs → pure emit + legacy `write_output_file` → host↔pure `structural_mismatches` empty; both candidates `StructuralPassBehaviorPending` under independent `mida-acceptance::check_static` (never `Accepted`) |
| `r1e_dual_path_from_va_mapped_oracle_structural` | Pure-built oracle mapped to VA-linear `dump_buf` (index==RVA) → pure re-emit preserves import/IAT DDs + R0B structural pass |

Wiring notes:

- `mida-pe` **dev-dependency only** on `mida-acceptance` for dual-path corpus
  (production lib must not depend on acceptance; boundary remains one-way).
- Not byte-identical; not runtime. Typed import rebind still out of scope.

### Explicit non-goals (unchanged)

- No default flip of production dump to pure.
- No import rebind from live IAT inside pure modules (host extra_data only).
- No behavioral `Accepted` / runtime engine (R2) / Oreans plugin (R3).
- Pure modules still exclude Win32 / `DebuggerCore` / `mida_disasm`.
- Samples stay in vault only (`D:\MidaVault\objects\sha256\...`).

### Pure modules (unchanged from R1-C)

`error`, `utils`, `header/*`, `section`, `import_table`, `export_table`,
`exception_table`, `tls`, `relocation`, `rebuild`, `byte_map`, `postprocess`,
`apiset_data`.

### Still adapter / live

`dumper/*` live paths (including `pure_rebuild_adapter` host surface),
`original_imports` Win32 resolve, `remote_modules`, heap/container snapshots,
host symbol resolution for IAT.

## Boundaries (unchanged)

- `mida-acceptance` does **not** depend on `mida-pe` or other production crates.
- Pure PE modules must not gain `windows` / `DebuggerCore` / `mida_disasm`.
- Acceptance verdicts still forbid `Accepted` in R0B.
- Goal remains loader-valid + behaviorally equivalent samples judged by
  independent evidence — R1 only produces structural candidates.

## Validation (R1-E — closed)

```powershell
cargo check -p mida-pe -p mida-cli
cargo test -p mida-pe pure_rebuild
cargo test -p mida-pe r1e_dual_path
cargo test -p mida-pe --lib rebuild
cargo test -p mida-pe --lib byte_map
cargo test -p mida-pe --test purity_boundary
cargo test -p mida-acceptance
```

Optional live smoke (host sample / vault materialize to scratch, not CI):

```text
mida dump-process <sample> --pure-rebuild
# then mida-acceptance (or gate) on output; compare vs legacy dump
```

## Validation evidence (2026-07-23 Windows)

- Host: Windows 11; VS 2022 Professional MSVC 14.44 via `tools/_enter_msvc_env.ps1`.
- `CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target`
- `cargo test --workspace --offline`: **412 passed / 0 failed**
- `dependency_boundary` + `pe_purity_boundary`: pass
- `validation_summary.json` task: **VNEXT-R1-E**

### Phase 0 re-verify (post hardening)

- **When:** 2026-07-23 after `eaf8468`
- **Command:** MSVC env via `tools/_enter_msvc_env.ps1`; `CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target`; `cargo test --workspace --offline`
- **Result:** **412 passed / 0 failed** (exit 0)
- **Log:** `D:\MidaVault\scratch\phase0_workspace_test.log`
- **Stamp:** `D:\MidaVault\lab\evidence\PHASE0_REVERIFY_20260723.md`

### Origin live unpack (Phase 1 — first structural pass)

- **Evidence:** `D:\MidaVault\lab\evidence\origin_macro\live_20260723-132326\`
- **CLI:** `mida-cli /unpack … --data-sections --no-shrink -v` → **exit 0**, ~12.6s
- **Candidate:** size `13746176`, sha256 `0c0923e34cb8571f09d954047880c75388ed062157ea384c6613f0c93a58efbb`
- **R0B:** `StructuralPassBehaviorPending`, failures `[]` (oracle observation only)
- **Path:** OEP found → IAT multi-block **305 slots** traced → dump 17 sections → structure gate ok
- **Unblock fix (committed `876bc0e`):**
  - `crates/core/src/windows_debugger.rs` — prefer `CONTEXT_CONTROL|INTEGER` over `CONTEXT_ALL`/XSAVE for Get/SetThreadContext; SuspendThread retry; OpenThread GET|SET|SUSPEND
  - Win11 failure mode was `SetThreadContext` → `ERROR_NOACCESS` (0x800703E6) during virtualized OEP and IAT v3-trace

### Lunlun live unpack (Phase 1 — second structural pass, degraded path)

- **Evidence:** `D:\MidaVault\lab\evidence\lunlun_software\live_20260723-163436_p1fix3\`
- **CLI:** same flags → **exit 0**, ~6.45s
- **Candidate:** size `12980224`, sha256 `dd44d9ca607aa15bf650900f51ad2dc22918665bd560b25b68aa9a52ac14c380`
- **R0B:** `StructuralPassBehaviorPending`, failures `[]` (no oracle)
- **Path (degraded):** virtualized OEP → null-AV storm escape → forced OEP `0x1401656f4` → process ExitProcess during IAT wait → **skip v3-trace** → dump 14 sections; IAT rebuild **41/352** → original import table
- **Unblock fixes (committed `eaf8468`):**
  - `crates/packers/themida/src/guard.rs` — early NotGuarded if fault outside `.text`
  - `crates/cli/src/unpacker/av_handler.rs` — null-storm (≥8) accept last PossibleOEP; skip in-loop v3-trace when process exited
  - `crates/cli/src/unpacker/mod.rs` — `process_exited` / `unrelated_av_streak`; post-loop skip V3 IAT trace when exited
- **Quality residual:** not Origin-class IAT recovery; structural pass only

### Origin stability ×3 (post-Lunlun hardening — no regression)

- **Index:** `D:\MidaVault\lab\evidence\origin_macro\STABILITY_20260723_p1smoke.md`
- **Runs:** `live_20260723-164243_p1smoke`, `…-164314_p1smoke2`, `…-164339_p1smoke3`
- **Result:** **3/3** exit 0, size `13746176`, R0B `StructuralPassBehaviorPending` failures `[]`
- **Path:** still OEP found → IAT **305** slots traced → dump 17 sections (not degraded Lunlun path)
- Candidate SHA varies with ASLR (expected); structural gates stable

### GTO experimental baseline (Phase 1 — record only)

- **Evidence:** `D:\MidaVault\lab\evidence\gto_launcher\live_20260723-164707_p1exp\`
- **CLI:** `/unpack … --profile=ahk-gto-experimental --data-sections --no-shrink -v` → **exit 0**, ~67s
- **Candidate:** size `16445952`, sha256 `2bdd7cb29a4793079f9f209ec3f6ebf78520caac995d41d61d909743e652a6fe`
- **R0B:** `StructuralPassBehaviorPending`, failures `[]` (analysis_reference observation only)
- **Path:** post-attach IAT OK → OEP observe **timeout 60s** → .text scan OEP `0x1400070b0` → IAT rebuild **545/572** → container/bootstrap `.boot` EP `0xecc000` → dump 11 sections
- **Not production:** experimental profile only; SecurityCookie fail-closed; CRT wrapper not patchable

### Origin pure-rebuild live compare (Phase 1 / Phase 2 gate input)

- **Evidence:** `D:\MidaVault\lab\evidence\origin_macro\live_20260723-165826_p1pure_pure\`
- **CLI:** same + `--pure-rebuild` → exit 0; size `6188032`; sha256 `a96e3fe423cddf1d43a1eda27f416c7e76bd773cd0d6ad8733d3151532ab774c`
- **R0B pure:** `StructuralPassBehaviorPending` failures `[]`
- **vs legacy smoke** `live_20260723-164243_p1smoke`: file-level `structural_mismatch` (see `structural_compare_vs_p1smoke.json`)
  - **Match:** entry `0x13e0`, nsections 17, import/IAT/TLS DDs identical
  - **Mismatch:** image_base (runtime ASLR retained), size_of_image, exception/reloc placement, `.winlice` layout / trailing section order; raw file size 6.2MB vs 13.7MB
- **Gate decision:** **keep pure opt-in**; **do not** flip production default

### ScyllaHide x64 hash hygiene (Phase 1 — verified)

- **Evidence:** `D:\MidaVault\lab\evidence\hygiene\scyllahide_hash_20260723\`
- **Expected (source):** `crates/packers/themida/src/binaries.rs` x64
  - InjectorCLIx64: `211f7b804f1db43abddbb3dbdf41162d6cee76ae84e0bb38818cdbf4d07cf630`
  - HookLibraryx64: `d4b20eed23caebad7efa53e5f2f3c86d445864c2d3e43b343e01c8a9785e800e`
- **On-disk (live next to CLI + staging `D:\magicmida-rs-build\`):** **both MATCH**; live≡staging
- **Path:** `helpers.rs` → `current_exe().parent()` + name; integrity gate in `inject_scylla_hide` before spawn
- **Runtime corroboration:** Origin p1smoke + Lunlun p1fix3 logs show `ScyllaHide injection completed successfully` (implies hash gate passed)
- **x86 residual:** placeholders (all-zero) remain; no x86 helpers on host; not required for current x64 corpus
- **Code change:** none required for x64

## Suggested next slices (strict order)

1. ~~Phase 0 re-verify~~ → 412/0 after `eaf8468`.
2. ~~Origin pure-rebuild live compare~~ → R0B pass both; file structural_mismatch recorded.
3. ~~ScyllaHide x64 hash hygiene~~ → match (evidence above); x86 still open.
### Dali OOS one-pager (Phase 1 — complete)

- **Evidence:** `D:\MidaVault\lab\evidence\dali_plugin\OOS_20260723.md`
- **Contract:** `engine_route: out_of_scope`; managed_host_candidate / PE32 / CLR + `mscoree.dll`
- **Static re-verify:** sha256 `e4f48d5a…165d`, CLR dir present, import-only mscoree; R0B on packed PE is structure-only (`20260723-124049`)
- **Live unpack:** not planned; must not score as Oreans/R3 signal

## Suggested next slices (strict order)

1. ~~Phase 0 re-verify~~ → 412/0 after `eaf8468`.
2. ~~Origin pure-rebuild live compare~~ → R0B pass both; file structural_mismatch recorded.
3. ~~ScyllaHide x64 hash hygiene~~ → match; x86 still open.
4. ~~Dali OOS one-pager~~ → `OOS_20260723.md`.
5. **Optional still open (not blocking Phase 1 close):** Lunlun OEP/IAT quality only as a **scoped** slice with re-smoke.
6. **Phase 2 / R1-F only after** deliberate pure parity plan (image_base preferred, section content parity) — not yet.
7. **R2** only after Phase 1 board consciously closed or deferred in handoff.
8. Flip default pure **only if** live pure ≥ legacy structural quality on Origin+Lunlun; **never** default `ahk-gto-experimental`.
