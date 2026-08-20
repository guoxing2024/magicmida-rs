# GTO-COLD-START-HEAP-REBASE-1 — Task Boundary (H0)

> status: ACTIVE — task boundary (H0) established 2026-08-20
> scope: gto_launcher cold-start heap/container model + generic rebasing
> authority: this file is the H0 boundary. ADR7 stays frozen; the Oreans
> regression gate (origin_macro + lunlun_software) is untouched.
> parent route lineage: GTO-PRODUCT-RECOVERY Routes A–H (archive/gto-20260730/),
> Route J/K/L/O/R–Y1A6 evidence (vault). This task opens a NEW ledger.

## 0. One-line objective

From an authorized immutable gto_launcher cold start, recover the heap/container
state and rebuild a loadable, verifiable PE — without bypasses, without stealing
prior process state.

## 1. Frozen inputs (pinned)

| Item | Value | Authority |
|---|---|---|
| Case id | gto_launcher | lab/cases/v2/gto_launcher.json |
| Manifest revision | 2 | same manifest |
| Protected input sha256 | 11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86 | manifest primary_artifact_sha256 |
| Protected input size | 24636416 bytes | manifest artifacts[0].size_bytes |
| Analysis reference | 4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8 (8583680) | manifest artifacts[1].role=analysis_reference |
| Vault object | D:\MidaVault\vault\sha256\11\11473d2e…\artifact.exe (present, verified) | resolver |
| Mutable locator | D:\Tools\RE\dumps\gto\启动器.exe (NEVER authoritative) | GTO_SAMPLE_REVISION_POLICY |
| PE identity | PE32+ 0x8664, image_base 0x140000000, entry_rva 0x16fb532 (.rdata2), 9 sections, 16 import descriptors, has_tls=true, has_relocations=false | static_fingerprint |
| Engine route | ahk_gto (future_plugin_ahk_gto -> mida_plugin_ahk_gto) | capability_cell |

Source revision pin: **commit 96cd929be44c226ae11b89d9e5d17f7a37078ed2**
(branch oreans/two-sample-mainline, clean tree) — the ADR7 closeout HEAD.
Every H1+ build/run records its own source revision; the H0 pin is the
starting point and the "baseline" for the Oreans regression wall.

## 2. Runtime / helper identities (recorded at first build)

To be recorded in the per-stage evidence (resolved_source.json + attestation):

- mida-cli.exe sha256 (built via tools/build_gto_live_cli.ps1, feature
  gto-product-recovery, profile ahk-gto-experimental)
- runtime dll/pdb/offset_map identities (as ADR7 closeout did for B4/B5)
- python helper sha256 (tools/_case_live_unpack.py, controller, resolver)
- capture policy identity (ahk_gto_defaults + case manifest capture_policy)

## 3. Constraints (no-bypass, binding)

Environment for every live run:

- MIDA_GTO_NO_BYPASS=1
- MIDA_GTO_BYPASS absent
- MIDA_GTO_SEMANTIC_REPAIR absent
- No DRx / VEH / injection / bwhook / R1B / E2
- No stealing prior process state (no reuse of a previous process's heap)
- Identity resolution is a preflight stop, never a runtime: use the vault
  object, never the mutable path; mismatch -> SampleIdentityMismatch stop
- Network deny_all; process-tree accounting required

## 4. Allowed dynamic observation means

- Debugger-side (mida-cli WindowsDebugger / gto_host observer) event timeline:
  module load, thread create/exit, exception, debug string, attach states
- Memory capture at defined epochs (capture_policy hot_roots, container/heap
  globals, raw slabs) — read-only wrt the target
- Process/thread state inspection (registers at suspend points, TEB/PEB reads)
- Wait-free enumeration of VirtualQuery-level region metadata
- NOT allowed: writes into the target, patch-and-rerun equivalence, packet
  forgery, or any state the target did not itself produce

## 5. Stage gates (acceptance criteria per stage)

### H0 (this doc) — DONE when:
- [x] boundary doc written (this file)
- [x] manifest/vault identity verified via resolver (resolve_20260808 evidence
      lineage; re-verify in H1 evidence dir)
- [x] CLI/helper hashes recorded in H1 evidence (H1 report §2)
- [x] ADR7 untouched; Oreans gate untouched (verified at each commit)

### H1 — heap/container model recovery. DONE when all six deliverables exist
in the evidence dir with hashes and a diff baseline against the pre-existing
vault runs (live_20260724-124524_u_gto_host_scan60, r4c, Route L/O/R/S/T/V/W/X/Y
snapshots):

1. heap region inventory (region list: base/len/protect/type/state, owner,
   provenance — container vs heap_globals vs slab vs raw)
2. allocation timeline (first_seen ordering, per-epoch deltas)
3. region hash/diff (per-region sha256, cross-run deltas)
4. pointer graph (regions -> slots -> targets; internal edges vs module VA vs
   RVA vs vtable/fnptr vs tagged vs relative)
5. base-relative field candidates (fields that track image base / heap base)
6. cold-start failure timeline (no-bypass cold launch; stage attribution per
   gto_exit_path_catalog: feature_gate / capture_policy_parse /
   create_process_attach / observe_gto / process_exit_before_dump /
   container_detection / heap_global_detection / …; every observation
   fail-closed; exit codes recorded; no candidate claimed)

### H2 — generic rebasing primitives. DONE when:
- old_heap_base->new_heap_base and old_module_base->new_module_base primitives
  exist, classification-driven (PointerClassification), no blanket +delta
- two different ASLR/heap layouts rebuild the same logical object graph
- unknown fields fail closed; classification provenance recorded per slot

### H3 — no-bypass cold start through the wall. DONE when:
- immutable authorized sample -> normal cold launch -> container initialized ->
  recovered state restored -> first behavior divergence point recorded
- every recovery action logged with source address, old/new value, region
  ownership, rollback path, first unrecoverable error
- stage milestones, not "process stays alive longer"

### H4 — OEP / IAT / TLS / exception recovery + dump:
- dynamic import/IAT capture; TLS callbacks/index/data rebuild; exception/
  unwind rebuild; no-reloc constraint handling; pure PE candidate output

### H5 — independent acceptance (no self-verdict):
- R0B static structural gate, loader smoke, bounded behavioral assertions,
  repeated isolated runs; no byte-matching vs historical dumps as success

### H6 — Oreans regression wall on every shared change:
- ADR7 closeout verifier (tools/verify_adr7_closeout.ps1, read-only, PASS)
- Oreans offline + bounded live smoke (origin_macro, lunlun_software)
- New results go to NEW regression evidence dirs; never rewrite ADR7 evidence

## 6. Output directory conventions

- Evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\<stage>\
- Scratch:  D:\MidaVault\scratch\gto_cold_start_heap_rebase_1\<stage>\
- Repo docs: docs/ (this doc + per-stage reports under docs/gto_cold_start/…)
- Round reports: archive/routes/ is historical; new rounds get fresh docs under
  docs/ with their own ledgers; do NOT append to archive/gto-20260730/*
- resolved_source.json is REQUIRED before any live step in each evidence dir

## 7. Seal rules

- Per-stage evidence dir gets a manifest with sha256 of every file
- No in-place modification of frozen packages (ADR7 B4/B5, archive routes,
  previous stage evidence); new stages create new versioned dirs
- Commits: docs-only for boundary/report; code changes must pass
  cargo fmt --all -- --check, cargo test --workspace --offline (baseline
  1885 passed / 0 failed / 2 ignored), git diff --check, hygiene script
- No samples/binaries committed to git; vault paths recorded logically

## 8. Ledger

| Stage | Status | Evidence |
|---|---|---|
| H0 boundary | ACTIVE (this doc) | docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md |
| H1 cold-start failure timeline | DONE (obs. report) | docs/GTO_COLD_START_HEAP_REBASE_1_H1_REPORT.md |
| H2 rebasing primitives | DONE (plan layer; stub execution deferred to H4) | docs/GTO_COLD_START_HEAP_REBASE_1_H2_REPORT.md |
| H3 cold-start wall | pending | (next) |
| H4-A SMR (ViaStableBinding stub exec) | TECHNICAL PASS + LIVE EVIDENCE (3 ASLR layouts, exit 0, unresolved_required=0/0/0) | docs/GTO_COLD_START_HEAP_REBASE_1_H4A_SMR_DESIGN.md, docs/GTO_COLD_START_HEAP_REBASE_1_H4A_REPORT.md; evidence H4A_smr/ + H4A_smr/layout_B/ |
| H4-B OEP entry-chain evidence | TECHNICAL PASS; evidence package PARTIAL (attempt_001 raw log unrecoverable; formal seal/sign-off NOT granted — see GTO-H4-LEDGER-CONSISTENCY-1) | docs/GTO_COLD_START_HEAP_REBASE_1_H4B_REPORT.md |
| H4-C TLS directory+evidence | TECHNICAL PASS + 3-layout evidence PASS; Seal-2 verifier PASS (48/48 size+sha, 0 missing, 0 unexpected, self-hash MATCH); formal sign-off PENDING review disposition | docs/GTO_COLD_START_HEAP_REBASE_1_H4C_TLS_DESIGN.md, docs/GTO_COLD_START_HEAP_REBASE_1_H4C_REPORT.md; evidence H4C_tls/ (seal GTO-H4-C-EVIDENCE-SEAL-2); verifier tools/gto_h4c_seal/ |
| H4-D exception+no-reloc | pending | (next) |
| H5 acceptance | pending | (next) |
| H6 Oreans regression | pending | (next) |

## 9. Non-claims (binding)

- NOT product 1.0; NOT gto perfect unpack; NOT "process survived longer"
- NOT claiming heap-rebasing wall closed until H3 exit criteria met
- NOT reusing prior process state; NOT bypass patches
- NOT extending Route A–H ledgers; this is a new ledger
- No push unless separately authorized

