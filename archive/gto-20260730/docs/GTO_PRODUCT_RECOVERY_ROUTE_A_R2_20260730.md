# GTO-PRODUCT-RECOVERY Phase 1 — Route A R2 evidence report (2026-07-30)

> **Status:** **R2 PASS accepted by expert review (2026-07-30).** Closeout-ready.
> Machine pre-report `aggregate.json` still has **`item_8_report=false` by design** and **`evidence_bar_pass=false`**; the **human report layer** is what expert accepted — machine output is not rewritten.
> **Authorization:** expert ruling 2026-07-30 (`GTO-PRODUCT-RECOVERY Phase 1 Route A R2`) + expert acceptance closeout 2026-07-30.
> **Baseline HEAD at start of R2:** `55976c9d3f1fda65166c317f9ef4242daab5cac5` (R1 sealed).
> **Branch:** `codex/gto-product-recovery-route-a`.
> **Ledger burn:** `GTO-PRODUCT-RECOVERY Route A` — R1=1 + **R2=1 round consumed** (Rust+Python diff + rebuild + re-measure); **cap=2; remaining=0**.
> **`GTO-POINTEE-EPOCH` UNCHANGED** (used=2/cap=2/remaining=0, FROZEN). **No R3.** No R1B. No E2. No DRx. No bypass. No push.

---

## 0. One-sentence R2 result

Five independent external-observer runs (`N=5`, no DRx/VEH/injection, `MIDA_GTO_NO_BYPASS=1`) against the same canonical `gto_protected.exe` (sha256 `4d5770af…037c8`) reproduced **one stable primary-anchor candidate family in 5/5 runs** — MEM_PRIVATE + `PAGE_EXECUTE_READ` (`protect=32`) + size=`0x127000` (1.2 MiB) + identical 4 KiB and multi-page fingerprints — with **5/5 independent identity dimensions** true (size, checksum, lifetime, neighborhood, protection). Machine items 1–7 true; **`item_8_report=false` by design** in `aggregate.json`; **`evidence_bar_pass=false`** left as machine output. Final R2 pass = expert acceptance after report review only.

---

## 1. Evidence bar checklist (R2 authorization §七)

### 1.1 Machine pre-report output (`aggregate.json`)

`aggregate.json` is **pre-report machine output**. Aggregator hard-codes `item_8_report = False`.

| # | Item | Machine result |
|---|------|----------------|
| 1 | N≥5 | **true** — 5/5 present, 0 failures |
| 2 | ≥3/5 reproduce R1 primary anchor as stable family | **true** — **5/5** on family `sz0x120000\|fp1891a1ae5a1e8f8f` |
| 3 | ≥2 independent identity dimensions | **true** — **5/5** dims (size, checksum, lifetime, neighborhood, protection) |
| 4 | `bypass_used=false` all runs | **true** |
| 5 | `drx_used=false` / `veh_used=false` / `injection_used=false` + `rsp_source=external-observer` | **true** |
| 6 | JSON sidecars + aggregate | **true** |
| 7 | shared dumper untouched / Phase C N/A | **true** (no pe/dumper/unpacker edits) |
| 8 | report | **false by design** — this document is the report layer |

Machine: `evidence_bar_pass = false` (expected).

### 1.2 Expert-layer status — ACCEPTED

**Expert acceptance (2026-07-30):**

- **R2 PASS accepted by expert review.**
- Machine vault `aggregate.json` is **unchanged** and still reports `item_8_report=false` / `evidence_bar_pass=false` by design (pre-report machine output).
- The **human report layer** (this document) is accepted as item 8; final R2 pass is expert acceptance after report review, not a machine flip of `evidence_bar_pass`.
- **Closeout-ready** for local commit of R2-relevant files only.
- **No R3.** Cap exhausted (Route A used=2/cap=2/remaining=0).
- Optional later steps (e.g. candidate dump **metadata** only) require **separate new governance** — not authorized by this closeout.
- All non-claims in §9 remain binding.

---

## 2. Primary anchor — strengthened identity

### 2.1 R1 inheritance (downgrades retained)

- JSON name `vm_codegen_region_expand` **retained**.
- **Expansion not proven** (lifetime tracker records presence ticks, not growth).
- Sample `protect=32` = `PAGE_EXECUTE_READ` — **not necessarily RWX**.
- `vm_protection_transition` remains **supporting weak observation only** (not primary pass anchor). Transitions now carry size/state/type fields, but still are not the R2 primary claim.

### 2.2 Stable candidate family (5/5)

| Field | Value |
|-------|-------|
| `family_key` | `sz0x120000\|fp1891a1ae5a1e8f8f` |
| `reproduction_count` | **5** |
| size (all runs) | **1208320** (`0x127000`, >1 MiB) |
| protect (all runs) | **32** (`PAGE_EXECUTE_READ`) |
| state / type | `4096` (`MEM_COMMIT`) / `131072` (`MEM_PRIVATE`) |
| `executable_private` | true |
| `image_backed` | false |
| `checksum_4k` (identical 5/5) | `a4ac6465eca1bd16bad4cf377dfcb07b…` |
| `checksum_multi_page` (identical 5/5) | `1891a1ae5a1e8f8ff65fe85c15d986f2…` |
| lifetime ticks seen | 263–320 (first_seen ≈ tick 11–12; last_seen ≈ end of window) |
| base addresses | ASLR drift: `0x3471000` / `0x34f1000` / `0x35e1000` / `0x3621000` (content-identical family) |

### 2.3 Identity dimensions (best family)

| Dimension | Result |
|-----------|--------|
| size stability | **true** (exact size match 5/5) |
| checksum similarity | **true** (4k + multi-page identical 5/5) |
| lifetime / tick pattern | **true** (ticks 263–320, low CV, first_seen ~11–12) |
| allocation neighborhood | **true** (non-empty ±2 MiB private-neighbor summaries all runs) |
| protection evolution / class | **true** (protect=32 stable 5/5) |
| **independent_count** | **5** (≥2 required) |

### 2.4 VM-ownership inference (honest)

- Candidate is **MEM_PRIVATE**, **not image-backed**, **executable** (`PAGE_EXECUTE_READ`), **>1 MiB**, content-stable across fresh spawns.
- This is consistent with a Themida-style **VM-owned private code/bytecode container** placed outside the PE image.
- **`.boot` section name is not module-visible** in any of the 5 runs (`boot_region_candidates` empty / no boot-named module hit). **No `.boot` binding is claimed.**
- R2 does **not** claim product UI, script load, perfect unpack, or pointee-epoch capture.

### 2.5 Supporting weak observation

- `vm_protection_transition` present 5/5 (counts ~23–28). Binding text explicitly marks supporting-weak; primary pass does **not** rest on it.

---

## 3. Run records (N=5)

| run | pid | ticks | candidates | top base | size | protect | tick_count_seen | sidecar_sha256 |
|----:|----:|------:|-----------:|---------:|-----:|--------:|----------------:|----------------|
| 1 | 31840 | 301 | 1 | `0x3621000` | `0x127000` | 32 | 290 | `6cd24fbf…562f58` |
| 2 | 33092 | 330 | 2 | `0x3471000` | `0x127000` | 32 | 320 | `d10d513c…7a0924` |
| 3 | 31052 | 273 | 1 | `0x3471000` | `0x127000` | 32 | 263 | `1f80479f…c40d4b` |
| 4 | 22724 | 302 | 2 | `0x35e1000` | `0x127000` | 32 | 292 | `546abbe8…db45ab` |
| 5 | 32328 | 288 | 2 | `0x34f1000` | `0x127000` | 32 | 278 | `e06c176c…b97a29` |

Common fields all runs:

- `route = "GTO-PRODUCT-RECOVERY/RouteA"`, `round = "R2"`
- `method_class = "memory-state-epoch external observer"`
- `bypass_used = false`, `semantic_repair_used = false`
- `drx_used = false`, `veh_used = false`, `injection_used = false`
- `rsp_source = "external-observer"`
- `target_sample = "gto_launcher"`
- `target_sha256 = 4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8`
- `observer_sha256 = 1217a5913d5ddde6a1ae1d23c3a0ec0a1be0b5e765581f473f080f94ba014a6d`
- `source_commit = 55976c9d3f1fda65166c317f9ef4242daab5cac5`
- `observation_window_ms = 30000`, `poll_period_ms = 50`
- `failure_class = "none"`

---

## 4. Implementation delta (R2)

### 4.1 Changed files (uncommitted)

| Path | Change |
|------|--------|
| `crates/cli/src/bin/mida_gto_product_recovery_observer.rs` | R2 schema: `candidate_regions[]` with lifetime + multi-page fingerprint + neighborhood; honest bindings; `round`/`drx_used`/`veh_used`/`injection_used`; transition size/state/type; per-tick dedup of region lists |
| `tools/_mtr_acq_route_a_observer.py` | default N=5, `--round`, timezone-aware timestamps, R2 out-root naming |
| `tools/_mtr_acq_route_a_aggregate.py` | family clustering + 5 identity dims + R2 evidence bar; item_8 false by design |
| `docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R2_20260730.md` | this report |
| `WORKER_HANDOFF.md` | R2 filed section |

### 4.2 NOT touched

- `crates/bwhook/**`
- `tools/_r1b_transient_epoch_trap.py`
- `crates/cli/src/unpacker/gto_host.rs`
- seal / parked R1A/R1B docs
- old vault evidence under `D:\MidaVault\lab\evidence\`
- shared pe dumper / acceptance
- no push, no commit yet

### 4.3 Forbidden primitives (verified absent)

No DR0–DR7, no VEH, no Get/SetThreadContext debug path, no DLL injection, no CreateRemoteThread, no WriteProcessMemory, no R1B runner reuse, no E2, no `MIDA_GTO_BYPASS`, no `MIDA_GTO_SEMANTIC_REPAIR`, no sample_bypass, no forced UI.

Allowed APIs only: `CreateProcessW`, `OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)`, `VirtualQueryEx`, `ReadProcessMemory`, module snapshot for nearest-module labeling.

---

## 5. Commands run

```
git status --short --branch          # clean at 55976c9 before R2 edits
git rev-parse HEAD                   # 55976c9d3f1fda65166c317f9ef4242daab5cac5

# after implementation (via vcvars64):
cargo check -p mida-cli --bin mida_gto_product_recovery_observer --offline   # ok
cargo build -p mida-cli --bin mida_gto_product_recovery_observer --offline   # ok

python tools/_mtr_acq_route_a_observer.py \
  --n 5 --round R2 \
  --observation-window-ms 30000 --poll-period-ms 50 \
  --out-root D:\MidaVault\scratch\product_recovery_route_a_r2_n5_20260730-012013
# → 5/5 sidecars; aggregator conditional machine pass (items 1-7); item_8 false
```

Env:

| Var | Value |
|-----|-------|
| `MIDA_GTO_NO_BYPASS` | `1` |
| `MIDA_GTO_BYPASS` | absent |
| `MIDA_GTO_SEMANTIC_REPAIR` | absent |

---

## 6. Vault evidence (READ-ONLY references)

Root: `D:\MidaVault\scratch\product_recovery_route_a_r2_n5_20260730-012013\`

- `aggregate.json` — `reproduction_count=5`, `evidence_bar_pass=false`, `item_8_report=false`
- `orchestrator_summary.json`
- `run_1` … `run_5` / `outcomes.json` + logs

SHA-256:

- target: `4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8`
- observer binary (R2 build): `1217a5913d5ddde6a1ae1d23c3a0ec0a1be0b5e765581f473f080f94ba014a6d`
- sidecars: see §3 table

---

## 7. Budget

| Ledger | Used | Cap | Remaining |
|--------|------|-----|-----------|
| `GTO-POINTEE-EPOCH` | 2 | 2 | **0 FROZEN** |
| `GTO-PRODUCT-RECOVERY Route A` | **2** (R1+R2) | 2 | **0** |

**R2 consumed the final round.** Failure path would be residual-stop; measurement does not indicate residual-stop. **No R3** under current charter.

---

## 8. Recommendation (for expert, not auto-action)

1. **Accept R2 measurement** as strengthened Route A identity on the R1 primary anchor (5/5 family, 5 identity dims, honest non-RWX / non-expand claims).
2. **Next governance step (separate ruling required):** optional **candidate dump metadata only** (JSON region descriptor + fingerprints + lifecycle) — **not** post-VM restore, not R1B blob restore, not E2, not UI green, not bypass. Prefer metadata over binary mutation.
3. Alternative product-behavior routes remain out of this authorization.
4. **Do not** interpret R2 as product 1.0, gto perfect unpack, R1B re-entry, or E2 activation.

---

## 9. Explicit non-claims

- **not** product 1.0
- **not** gto perfect unpack
- **not** R1B re-entry
- **not** E2
- **not** DRx / VEH / injection
- **not** bypass / sample_bypass
- **not** proven expansion
- **not** necessarily RWX (`protect=32` = `PAGE_EXECUTE_READ`)
- **not** `.boot` module-visible binding
- **not** auto-commit / auto-push / auto-R3

---

## 10. Commit discipline / closeout

Per authorization §十 + expert acceptance 2026-07-30:

- Expert accepted R2 PASS; closeout commit of the five R2-relevant files is authorized.
- **No push.**
- **No R3.**
- No new measurement; no rustfmt drive-by; no R1B/E2/DRx/VEH/bypass.

### Expert acceptance block (closeout)

```
R2 PASS accepted by expert review
Date: 2026-07-30
Machine aggregate: item_8_report=false (by design, unchanged); evidence_bar_pass=false (unchanged)
Human report layer: accepted as item 8
Non-claims: retained in full (§9)
Ledger: GTO-PRODUCT-RECOVERY Route A used=2/cap=2/remaining=0; No R3
GTO-POINTEE-EPOCH: frozen unchanged
```
