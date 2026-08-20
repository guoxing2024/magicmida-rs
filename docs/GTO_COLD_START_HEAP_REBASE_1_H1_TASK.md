# GTO-COLD-START-HEAP-REBASE-1 — H1 Task Card (heap/container model recovery)

> status: ACTIVE — started 2026-08-20 (boundary: docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md)
> execution channel: **observation-only** (MIDA_GTO_OBSERVATION_ONLY=1) —
> debugger-side reads only, no runtime injection, no target writes, no product
> candidate, fail-closed. Production semantics unchanged.

## H1 objective

Recover the heap/container model for the authorized immutable gto_launcher
(sha256 11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86,
manifest rev 2) under **no-bypass cold start**, and produce the six H1
deliverables. Answer: which heap regions belong to the protector container,
which addresses are absolute VAs, which fields track process/heap base, which
pointers form the internal graph, which regions are missing/late-created/
mis-restored in cold start, and where cold start fails (init / reloc / TLS /
IAT / container).

## 1. Frozen context (from H0)

| Item | Value |
|---|---|
| Input | D:\MidaVault\vault\sha256\11\11473d2e…\artifact.exe (ResolvedAuthorizedRevision) |
| Source | 96cd929be44c226ae11b89d9e5d17f7a37078ed2 (branch oreans/two-sample-mainline) |
| CLI | D:\MidaVault\scratch\gto_cold_start_heap_rebase_1\cargo-target\debug\mida-cli.exe sha256 29c86074be4da634b3b1372b2efc0bdec704b933f5e35b1a32d25cde1ac2498c (attestation: gto_product_recovery=true) |
| Profile | ahk-gto-experimental (explicit; never auto-selected) |
| Capture policy | ahk_gto_defaults (hot_roots=8) + case-manifest capture_policy |
| Env | MIDA_GTO_NO_BYPASS=1; MIDA_GTO_OBSERVATION_ONLY=1; MIDA_GTO_BYPASS absent; MIDA_GTO_SEMANTIC_REPAIR absent |

## 2. Evidence dirs

- Run evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H1_observation\<run_id>\
- Scratch:      D:\MidaVault\scratch\gto_cold_start_heap_rebase_1\H1\
- resolved_source.json REQUIRED in each run dir before any live step

## 3. What a compliant H1 observation run looks like

```
set MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1
python tools/_case_live_unpack.py gto_launcher \
  --profile=ahk-gto-experimental --tag h1_obs_<n>
```

Expected: target cold-launches under the debugger (CREATE_PROCESS
CREATE_SUSPENDED), debugger-side reads only; run terminates target after
observation; NO candidate; evidence tagged observation-only. Fail-closed on
any unexpected state.

## 4. Six H1 deliverables (each written under the H1 evidence dir, hashed)

1. heap region inventory — base/len/protect/type/state, owner, provenance
   (container vs heap_globals vs slab vs raw); from capture epoch + VirtualQuery
2. allocation timeline — first-seen ordering per epoch, per-run deltas
3. region hash/diff — per-region sha256; cross-run and cross-layout deltas
   (ASLR/heap base changes between runs)
4. pointer graph — region → slots → targets; classification per
   PointerClassification (internal / module VA / RVA / vtable-fnptr / tagged /
   relative / non-pointer)
5. base-relative field candidates — fields tracking image base / heap base;
   two-layout diff to confirm
6. cold-start failure timeline — no-bypass cold launch; stage attribution per
   gto_exit_path_catalog (feature_gate / capture_policy_parse /
   create_process_attach / observe_gto / process_exit_before_dump /
   container_detection / heap_global_detection / …); exit codes recorded;
   every observation fail-closed; no candidate claimed

Baseline to diff against (existing vault runs):
- live_20260724-124524_u_gto_host_scan60 (host scan 60s)
- live_20260723-225951_r4c_gto
- r27_nobypass_round0_20260725 (r27 no-bypass cold AV at AutoHotkey+0x5e2570 /
  MinHookDisable+0x5e2570, rax=0x846898)
- live_20260808T185515Z_route_l_r1_raw_coherent_rebase
- live_20260809T015332Z_route_m_r1_synthetic_derived
- live_20260809T154340Z_route_o_r1_end_to_end_recovery (failure stage
  raw_slab_overlay; drift child 0x9f93e8 slab [0x9bf000,+0x2db3750) offset
  0x3a3e8 first_mismatch 0x28)
- live_20260810T180501Z_route_x_r1_ledger_closure
- live_20260811T173546Z_route_y1_a6_declared_size_reinit
- live_r11_script_heap_diag
- live_r25b_newclassname

## 5. Exit criteria (H1 complete)

- [ ] six deliverables present, hashed, sha256-indexed in H1 evidence manifest
- [ ] every observation run used the vault object (resolved_source.json
      revision_match=true) — no mutable path, no promotion
- [ ] cold-start failure attributed to a stage with exit codes, not a guess
- [ ] no candidate claimed; no target write; ADR7 untouched; Oreans untouched

## 6. Non-claims

- H1 does NOT close the heap-rebasing wall (that is H3)
- H1 does NOT produce or validate a product candidate
- Observation-only evidence is NOT acceptance evidence
