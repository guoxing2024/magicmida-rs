# GTO-PRODUCT-RECOVERY Route H P0 Proposal (2026-07-30)

**Base:** `f756950`  
**Branch:** `codex/gto-route-g-r1`  
**Class:** governance proposal only (docs)  
**P0 rounds consumed:** **0** (does not start implementation)

---

## Operator context

Product 1.0 / perfect unpack for `gto_launcher` remains required.

Route G is **closed** (used=2/cap=2/remaining=0, **no R3**). Acquisition is
reliable enough to produce a no-bypass candidate with clean-byte **PASS**, but
product gates still fail.

---

## Carried blockers (exact)

From Route G R2 residual-stop (`f756950` / evidence package):

| Blocker | Fact |
|---------|------|
| UI path AV | `gui_window_class_v0` expect `NewClassName` → **Fail**; 3/3 `nt_exception_exit:0xc0000005` (`ACCESS_VIOLATION`); `classes_seen=[]` |
| Script engine runtime proof | **absent** — no runtime script-engine Pass; static `pe_string` may show AutoHotkey/NewClassName but does **not** prove execution |
| Natural load only 1/3 | `load_no_crash_v0` Pass with `load_quality` samples=3 pass=1 fail=2 **pass_rate=0.3333** |
| `product_1_0` | **false** |
| Perfect unpack | **not achieved** |

### Audit metadata defect (carried)

Route G evidence JSON (`docs/GTO_PRODUCT_RECOVERY_ROUTE_G_EVIDENCE_20260730.json`)
has a **stale route label**: top-level `"route": "GTO-PRODUCT-RECOVERY Route E"`
while the package is Route G R2 evidence. Record as **audit metadata defect**
(label only; does not change probe hashes or gate outcomes). Route H R1 may
correct the label as docs hygiene if authorized; it is **not** product PASS.

---

## Prior routes (exhausted)

| Route | Ledger | Outcome |
|-------|--------|---------|
| A–E | used=2/cap=2 each | closed / residual as previously sealed; **no R3** |
| F | used=2/cap=2 | heap-slab prefix landed; live remeasure residual; **no R3** |
| G | used=2/cap=2 | acquisition reliability + product evidence residual-stop; **no R3** |

Do **not** reopen Route A–G R3.

---

## New route: Route H

**Name:** no-bypass cold-UI completeness (dump-timing / runtime-graph) route  

**Single narrow root-cause hypothesis (H1):**

> The Route G no-bypass candidate is dumped **too early for product UI**
> (IAT+~10s, `ui_seen=false`, scan EP). The frozen AHK runtime / heap graph is
> still incomplete for cold `RegisterClass`/`CreateWindow` → cold start hits
> **AV `0xc0000005`** before `NewClassName`, so script-engine execution never
> becomes observable. This is **not** a clean-byte / bypass-site problem
> (those already PASS) and **not** an acquisition hard-FATAL problem (G R1 closed).

### Fresh ledger

- Namespace: `GTO-PRODUCT-RECOVERY Route H`
- Cap: **2**
- Used: **0**
- Remaining: **2**
- Separate from A–G (no inheritance)

### Allowed future surfaces (if Phase 1 authorized)

Implementation rounds may touch only surfaces needed to test H1, e.g.:

- `crates/cli/src/unpacker/gto_host.rs` (no-bypass dump timing / UI-wait policy only)
- dumper heap/capture policy modules already used on no-bypass path
  (`heap_global_snapshot`, `capture_policy`, bootstrap as required)
- product harness evidence ingest only as needed

### Forbidden (Route H)

- bypass / semantic repair
- DRx / VEH / injection
- R1B / E2
- `crates/bwhook/**`
- Route A observer/scripts
- inventing UI/script Pass without probes
- push unless separately ordered

---

## R1 objective (if separately authorized)

One narrow experiment against H1:

1. Produce a **new** no-bypass candidate under `MIDA_GTO_NO_BYPASS=1` with dump
   policy that prefers **UI-seen settle** (or a longer post-IAT live window
   while process stays alive) over pure IAT+10s early dump when possible.
2. Keep clean-byte gate discipline (Route E sealed sites must still PASS).
3. Re-run product probes on that candidate.

### Measurable PASS gates (R1)

| Gate | PASS criterion |
|------|----------------|
| Env | `MIDA_GTO_NO_BYPASS=1`; `MIDA_GTO_BYPASS` / `MIDA_GTO_SEMANTIC_REPAIR` absent |
| Acquisition | candidate PE written; R0B not Rejected |
| Clean-byte | harness `no_bypass_patches=PASS` (5/5) |
| Natural load | `load_no_crash` Pass with **pass_rate ≥ 2/3** on fixed N≥3 (stricter than G R2 1/3) |
| UI path | `gui_window_class_v0` expect `NewClassName` → **Pass** (no 0xc0000005 on gate attempts) |
| Script engine | dedicated **runtime** evidence Pass (not pe_string-only); explicit true + source/hash/timestamp |
| Product | harness `overall_status=PASS` and `product_1_0=true` **only if all above hold** |

R1 may **residual-stop** if UI still AVs: record exact AV site / next stale ptr class; do not claim product 1.0.

### R2 objective (if R1 residual and separately authorized)

One follow-on round only: close the **single** residual named in R1 (e.g. next
heap-graph hole or dump-timing knob), re-run the same PASS table. Cap remains 2
total for Route H. **No R3.**

---

## Evidence bar

- UI still `0xc0000005` ⇒ **no product PASS**
- Script engine only static strings ⇒ **no product PASS**
- Natural load pass_rate &lt; 2/3 ⇒ **no product PASS** (H1 quality bar)
- Stale route labels in evidence JSON ⇒ audit defect; fix as hygiene, not PASS
- Product 1.0 **only if** harness PASS with `product_1_0=true`

---

## Authorization bar

P0 is **proposal only**. It:

- consumes **0** fix rounds
- does **not** start R1 implementation
- does **not** allocate work until operator names
  `GTO-PRODUCT-RECOVERY Phase 1 on Route H` literally
  and a separate expert ruling records the ledger allocation

Bare "continue" / "proceed" does **not** open Route H R1.

---

## Non-claims

- Not product 1.0 / not gto perfect unpack
- Not Route G reopen / not Route G R3
- Not a claim that H1 is proven — only the next testable hypothesis
- No code / cargo / live / vault write / push in this P0 filing
