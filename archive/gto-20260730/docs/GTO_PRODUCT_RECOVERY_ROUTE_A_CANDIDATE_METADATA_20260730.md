# GTO-PRODUCT-RECOVERY Route A — Candidate Metadata Pack M0 (2026-07-30)

> **Status:** metadata-only evidence packaging (post-R2).  
> **Class:** governance / deterministic descriptor.  
> **Fix rounds consumed:** **0**.  
> **NOT R3.** No live measurement. No target execution. No dump/restore/patch. No push.

---

## 0. One-sentence result

From the expert-accepted Route A R2 vault set `product_recovery_route_a_r2_n5_20260730-012013` (report commit `2c8ebeab…`), this pack deterministically extracts and source-controls the primary-anchor candidate family `sz0x120000|fp1891a1ae5a1e8f8f` — MEM_PRIVATE / MEM_COMMIT / `PAGE_EXECUTE_READ` (`protect=32`) / size `0x127000` / identical 4 KiB + multi-page fingerprints across **5/5** runs with **5** identity dimensions — as metadata only.

---

## 1. Inputs consumed (READ-ONLY vault)

| Logical ID | Role |
|------------|------|
| `product_recovery_route_a_r2_n5_20260730-012013` | R2 evidence set id |
| `aggregate.json` | machine pre-report aggregate |
| `orchestrator_summary.json` | N=5 orchestrator summary |
| `run_1`…`run_5` / `outcomes.json` | per-run sidecars |

R2 report (repo): `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R2_20260730.md`  
R2 accepted commit: `2c8ebeabbcd6da55ec2359300241d5aff3c461b8`

Machine aggregate is **not rewritten**: `item_8_report=false`, `evidence_bar_pass=false`, `fail_reasons=["item_8_report"]` remain as vault facts; expert acceptance lives on the human report layer.

---

## 2. SHA-256 table (full)

| Artifact | SHA-256 |
|----------|---------|
| aggregate.json | `d85d0cdedea4801ee5aacd671adf7c17d24929ea1dd96a25c34f02659609ed74` |
| orchestrator_summary.json | `9add48ab46560d57308f8b75602f1b78f1350198e52498949582c75eb8fc2880` |
| run_1/outcomes.json | `6cd24fbffb2df539afd8bd487547476f59a402e0454082830848e3d330562f58` |
| run_2/outcomes.json | `d10d513cb7e659d6b92ad1089a3f53900ce4a4655e82a841683b3350807a0924` |
| run_3/outcomes.json | `1f80479f08cac71508238fae2f31760240ebac6b177707b6cefb009fccc40d4b` |
| run_4/outcomes.json | `546abbe86c215bcb2cce8f7684528a3a9a347b2bf32ec2b0e3312eaeafdb45ab` |
| run_5/outcomes.json | `e06c176c50d6385d9363adef85c14ea49b743db4013b321f0d592c17b2b97a29` |
| target `gto_protected.exe` | `4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8` |
| observer binary (R2 build) | `1217a5913d5ddde6a1ae1d23c3a0ec0a1be0b5e765581f473f080f94ba014a6d` |

Emitted pack JSON (repo): `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_CANDIDATE_METADATA_20260730.json`  
Generator: `tools/_mtr_route_a_candidate_metadata.py`

---

## 3. Selected candidate family

| Field | Value |
|-------|-------|
| `family_key` | `sz0x120000\|fp1891a1ae5a1e8f8f` |
| role | `route_a_r2_primary_anchor_candidate` |
| reproduction | **5/5** runs |
| size | `1208320` / `0x127000` |
| protect | `32` / `PAGE_EXECUTE_READ` |
| state | `4096` / `MEM_COMMIT` |
| type | `131072` / `MEM_PRIVATE` |
| executable_private | true |
| image_backed | false |
| checksum_4k | `a4ac6465eca1bd16bad4cf377dfcb07b` (identical 5/5) |
| checksum_multi_page | `1891a1ae5a1e8f8ff65fe85c15d986f2ecb5b5897b655432ff3627f10b25cef8` (identical 5/5) |
| identity dims | size, checksum, lifetime, neighborhood, protection (**independent_count=5**) |

---

## 4. Per-run base / tick table

| run | base | first_seen | last_seen | tick_count_seen |
|----:|------|----------:|----------:|----------------:|
| 1 | `0x3621000` | 12 | 301 | 290 |
| 2 | `0x3471000` | 11 | 330 | 320 |
| 3 | `0x3471000` | 11 | 273 | 263 |
| 4 | `0x35e1000` | 11 | 302 | 292 |
| 5 | `0x34f1000` | 11 | 288 | 278 |

### Base addresses are ASLR drift, not identity

Per-run `base` values differ (`0x3471000` … `0x3621000`) because Windows rebases private allocations across fresh process spawns. **Identity** for this family is carried by **size + fingerprints + lifetime pattern + neighborhood class + protection class**, not by absolute base. Treat `base` as a run-local locator only.

---

## 5. Explicit non-claims

This pack does **not** claim:

- product 1.0  
- gto perfect unpack  
- R1B re-entry  
- E2  
- DRx / VEH / injection  
- bypass / sample_bypass  
- proven expansion (`vm_codegen_region_expand` name retained historically; expansion not proven)  
- necessarily RWX (`protect=32` = `PAGE_EXECUTE_READ`)  
- `.boot` module-visible binding  

---

## 6. Scope statements

- **Metadata-only.** No dump, no restore, no patch, no PE rebuild, no binary mutation.  
- **NOT R3.** Route A fix-round ledger remains used=2/cap=2/remaining=0; this pack consumes **0** fix rounds.  
- **No live measurement / no target execution** during M0.  
- **No vault rewrite.** Aggregate `item_8_report=false` remains.  
- **No push** required by this task class beyond local commit of the four allowed files.

---

## 7. Next-governance recommendation

Accept metadata pack M0 as deterministic descriptor of the R2 primary-anchor candidate.  
Next possible task, if separately approved: route-selection ruling for Route B or another non-Route-A successor.  
Do not reopen Route A R3.

---

## 8. Generator command (reproducible)

```powershell
python tools/_mtr_route_a_candidate_metadata.py `
  --out-root D:\MidaVault\scratch\product_recovery_route_a_r2_n5_20260730-012013 `
  --report-commit 2c8ebeabbcd6da55ec2359300241d5aff3c461b8 `
  --output docs/GTO_PRODUCT_RECOVERY_ROUTE_A_CANDIDATE_METADATA_20260730.json
```
