# GTO-PRODUCT-RECOVERY Route H R1 Report (2026-07-30 / 2026-07-31)

**Branch:** `codex/gto-route-h-r1`  
**Base:** `7ab296a`  
**Ledger after R1:** used=1 / cap=2 / remaining=1

---

## Protected input (updated)

| Field | Value |
|-------|-------|
| Source | `D:\Tools\RE\dumps\gto\启动器.exe` (operator-updated) |
| size_bytes | `14300672` |
| sha256 | **`46539ea7b1bf1f43cf2ed09fc0642d84b10a274939efb7c08f87b1869d738aa8`** |
| Prior authority | `4d5770af…037c8` (8,583,680) — **obsolete for product claims** |

Layout note: **no `.KI3`**; sections include `.data0` / `.data1` / `.data2` / `_RDATA`; EP RVA `0xbaf8db`.

---

## Code changes

### 1. `crates/packers/ahk_gto/src/plugin.rs` (required for new sample)

- Identify **Match** on ≥2 numbered `.dataN` sections (without `.KI3`).
- Unit: `numbered_data_sections_match_without_ki3` PASS.
- Without this, dual-select routed **Oreans** (`ahk_gto=Ambiguous`) and H1 GTO-host timing never ran.

### 2. `crates/cli/src/unpacker/gto_host.rs` (H1 dump timing)

- No-bypass: prefer **UI-seen** settle (5s post-window); max_wait 90s; less SuspendThread thrashing.
- **No pure IAT+10s early dump** as primary policy.
- Last-resort **alive** dump at IAT+9s if UI never appears (process often exits ~12s; dump-after-exit RPM fails).
- Dump-before-exit after IAT if process dies (Route G reliability retained).

### 3. Docs hygiene

- Route G evidence JSON top-level `route` label corrected `Route E` → **`Route G`** (metadata only).

---

## Acquisition (new sample, no-bypass)

| Field | Value |
|-------|-------|
| Env | `MIDA_GTO_NO_BYPASS=1`; bypass/semantic-repair absent |
| Identify | `ahk_gto` Match conf=75 |
| Host | GTO independent host (Route H timing log present) |
| UI during dump | **`ui_seen=false`** |
| Dump reason | `IAT+9108 ms … last_resort_alive=true` (UI never appeared) |
| Candidate | size `26525240`, sha256 `4f2f9a4462cd5e03ef92205251897abb0454e55cd31b407790069b60bd30118d` |
| evidence_set | `scratch/product_recovery_route_h_r1_newsample_b_20260731` |

---

## Product gates (honest)

| Gate | Result |
|------|--------|
| Clean-byte 5/5 (Route E seals for **old** `4d5770af`) | **FAIL** — all five sites mismatch; seals do **not** transfer to `46539ea7` layout |
| Natural load N=3 fixed | **Fail** — `os_error` / WinError **193** (not a valid Win32 application) 0/3 |
| UI `NewClassName` | **Inconclusive/error** — same OSError (cannot launch) |
| Script engine runtime | **not obtained** (candidate not loadable) |
| Harness `product_1_0` | **false** (not claimed) |

---

## H1 experiment conclusion

| Question | Answer |
|----------|--------|
| Is IAT+10s early-dump the sole cause of cold UI AV on **old** sample? | **Not re-tested on old input** this round (operator deprecated old protected). |
| Did UI-prefer path fire on **new** sample? | **No** — protected process never showed `NewClassName` within live window; last-resort alive dump at ~9s. |
| Is new candidate product-viable? | **No** — CreateProcess **WinError 193** (invalid PE for loader). |
| Exact residual | (1) new-sample **identify** fixed; (2) dump still **no UI-seen**; (3) candidate **not loader-valid**; (4) **clean-byte taxonomy must be re-sealed** for `46539ea7…` (old RVAs invalid). |

**Status: RESIDUAL toward product 1.0** (R2 available). Do **not** claim product PASS.

---

## Ledger

used=1 / cap=2 / remaining=1 — Route H **R2** may continue (e.g. loader-valid dump for new layout + re-seal clean bytes + UI-seen dump).

## Non-claims

- Not product 1.0 / not perfect unpack
- Not clean-byte PASS on new sample
- No bypass / semantic repair / DRx / VEH / injection / R1B / E2 / push
