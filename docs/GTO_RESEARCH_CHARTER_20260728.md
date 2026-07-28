# GTO Research Charter — GTO-POINTEE-EPOCH

> **Status:** Open research battlefield (expert-authorized 2026-07-28)  
> **Branch:** `research/gto-bootwatch-20260728` (default worktree for code)  
> **Binding goal:** `docs/PROJECT_GOAL_20260725.md` — `gto_launcher` perfect unpack  
> **Product 1.0:** still **NO** until this charter’s product exit is met **without** `sample_bypass`  
> **Discipline:** one battlefield · ≤2 fix rounds then residual-stop · evidence-driven · no fake UI green

---

## 0. One-sentence mission

Capture a **committed, readable pointee** at the real load epoch of  
`mov r10,[rsp+rax] @ 0x1405febb8` (or an equivalent proven VIP epoch), restore the  
minimum state needed for free-run past the next transfer, and only then reassess  
UI / AHK script reality — **without** r26b-class sample bypass patches.

---

## 1. Why this battlefield (hard wall, not polish)

Established facts (r27 r4–r5 + KI3 §12.6 + self-corr §22–27):

1. Dump **correctly decrypts** `.text` (e.g. WinMain prologue at `0x5a10` plaintext).
2. Protected process **never executes** those `.text` RVAs — Themida VM owns control  
   (EP / interpreter in `.boot` / `.,\W` / `.KI3` engine).
3. Candidate stub → `.text@0x5a10` runs the **wrong native path** (machine-ID MessageBox).
4. Heap slab + VirtualAlloc original-address remap: **necessary, not sufficient**.
5. DISPATCH-freeze pointee capture: slot often **MEM_FREE** / wrong epoch  
   (`GTO-POINTEE-CAPTURE-1` negative close — do not fake regions from dead dumps).
6. VEH/DR0 in-process capture: **anti-tamper kills** (`0xDEADC0DE` class).
7. External soft-BP: can execute 10⁵–10⁶ VIP fetches but locks **non-product** linear path.
8. Five r26b bypasses can fake `NewClassName` window oracle — **diagnostic only**;  
   taxonomy `sample_bypass` **blocks** product `Accepted`.

**Implication:** static dump + “jump to plaintext OEP” architecture has hit a ceiling.  
This charter is **post-VM state capture / epoch-correct restart**, not another hot-root peel.

---

## 2. Scope

### 2.1 In scope

| ID | Work |
|----|------|
| E0 | Baseline on research branch: reproduce DISPATCH freeze + slot MEM_FREE (or document delta) |
| E1 | **GTO-POINTEE-EPOCH** — capture at load instruction time / later VIP when region is committed+readable |
| E2 | Minimal pointee restore into restart stub / sidecar; free-run past next transfer |
| E3 | If E2 holds: reassess GTO-UI-1 (real class name / script path) **without** bypass |

### 2.2 Explicitly out of scope (this charter)

- Full Themida devirtualizer / universal VM lifter
- Product Ed25519 / CI signing (Phase F; separate)
- Expanding `sample_bypass` allowlist or default `MIDA_GTO_BYPASS=1`
- Mixing BootWatch mega-diff into baseline Set A without expert merge review
- Adding `crates/bwhook` to workspace `members`
- Lunlun / Xiongxiong / Dali as 1.0 gates
- Claiming product `Accepted` from `load_no_crash_v0` or export/window oracles alone

### 2.3 Code / doc home

| Asset | Location |
|-------|----------|
| Host residual | `crates/cli/src/unpacker/gto_host.rs` (research branch) |
| Region / inject APIs | `crates/core/src/windows_debugger.rs` (`MemoryRegionInfo`, `query_region_full`, …) |
| soft-BP analysis host | `tools/softbp_host.py` |
| RE bible | `docs/KI3_DECRYPT_BREAKPOINT_ANALYSIS.md` §12.6 |
| Self-corr stuck labels | `docs/AUDIT_SELF_CORRECTION_20260727.md` §22–27 |
| bwhook (research-only) | `crates/bwhook/**` — **exclude** from root members |
| Vault evidence | `D:\MidaVault\scratch\bootwatch\` and case evidence under vault only |

Baseline (`baseline/legacy-recovery-20260722`) remains the **P0 / origin-safe** line.  
Default implementation commits for this charter go on **`research/gto-bootwatch-20260728`**.

---

## 3. Non-negotiable gates

1. **`sample_bypass` never product-Accepts** (`docs/TRANSFORM_TAXONOMY_V1.md`).
2. **`MIDA_GTO_BYPASS` default OFF**; bypass dumps = diagnostic.
3. **Dumper never self-signs**; unsigned managed → Pending on product CLI posture.
4. **One battlefield**; max **2** rounds of code→rebuild→measure; then residual-stop.
5. **No debug-port assumptions** that contradict proven anti-tamper (prefer post-attach / external host patterns already validated).
6. **No fake pointees** from free/dead VAs (`GTO-POINTEE-CAPTURE-1`).
7. **No push/remote** unless separately authorized.
8. Origin perfect-unpack invariants (three-band scrub, EP OptionalHeader+16) must not regress if shared dump code is touched — re-run Phase C smoke after any `mida-pe` dumper change.

---

## 4. Success / exit criteria

### 4.1 Research exit (charter complete as research)

All of:

1. Documented capture method with vault evidence (JSON sidecars + logs) showing  
   committed+readable pointee at a **named** epoch (RIP/VIP + timing).
2. Free-run advances past the previously blocking transfer **≥2/3** independent runs  
   (or honest residual explaining irreducible wall).
3. Residual doc updated: what was proven / disproven / next wall.
4. Language remains research — **not** product 1.0.

### 4.2 Product-facing exit (only path to gto perfect-unpack claim)

All of (`PROJECT_GOAL_20260725`):

1. **No** r26b / `sample_bypass` patches in candidate.
2. Structure R0B `StructuralPassBehaviorPending`.
3. Load 10× isolated attempt=1.
4. Real product UI path (not forced class / skipped MessageBox / skipped LoadFile).
5. AHK script engine load/execute reality (not oracle-only).
6. Reproducible with current CLI on research→reviewed merge path.
7. Product Accept only under current contract (registered probe + managed + taxonomy + authenticity policy) — **not** this charter’s default deliverable.

If product exit is judged unachievable after residual-stop: expert may authorize  
**scope write-down** (document “independent-PE perfect unpack not achievable for this  
VM-mode build”) — **not** silent claim inflation.

### 4.3 Failure stop (mandatory)

After 2 fix rounds without E1/E2 measurable advance:

- Write/update residual (prefer `docs/UNATTENDED_RESIDUAL_20260724.md` appendix or  
  new `docs/GTO_POINTEE_EPOCH_RESIDUAL_YYYYMMDD.md`).
- Stop coding loops; do not open parallel GTO peels.
- Leave research branch tip green enough to rebuild; no half-merged baseline pollution.

---

## 5. Method constraints (recommended approach)

**Do:**

- Prefer **memory-state / epoch** capture over instruction-pattern VM ENTER myths  
  (启动器 has no portable spinlock ENTER vs hello_world).
- Treat `.KI3` as encrypted **source store**; runtime focus `.boot` / RWX residue.
- Reuse validated assets: slab capture, VirtualAlloc original-address remap,  
  BootWatch early freeze, RBP/R9 restart policy where already proven.
- Measure first (E0) before code (E1).

**Do not:**

- Re-open r1–r26 hot-root onion peels as primary strategy.
- Treat soft-BP linear VIP++ as product progress.
- Restore RBP=0 free-run that reintroduces SOI cliff without new evidence.
- Commit diagnostic bypasses as default dump behavior.

---

## 6. Round budget (template)

| Round | Intent | Max code surface | Exit measure |
|-------|--------|------------------|--------------|
| 0 | Reproduce epoch problem | logs/scripts only preferred | MEM_FREE or committed? N≥3 |
| 1 | Capture at later/load epoch | gto_host + core query APIs | readable pointee sidecar |
| 2 | Minimal restore + free-run | restart stub / policy | past next transfer ≥2/3 |

If Round 0 already shows a new wall class → residual-stop without burning Round 1–2 on dead ends.

---

## 7. Verification commands (research host)

```powershell
. .\tools\_enter_msvc_env.ps1
$env:CARGO_TARGET_DIR = 'D:\MidaVault\scratch\cargo-target'

# Work on research branch
git checkout research/gto-bootwatch-20260728

cargo build -p mida-cli --offline
# Then operator-authorized BootWatch / softbp recipes under vault scratch
# (exact env flags documented in KI3 §12.6 — do not invent product defaults)
```

After any shared `mida-pe` dumper edit, also:

```powershell
git checkout baseline/legacy-recovery-20260722   # or merge-test worktree
python tools\_origin_live_unpack.py
# R0B StructuralPassBehaviorPending on fresh candidate
```

---

## 8. Reporting language (required)

| Allowed | Forbidden |
|---------|-----------|
| “research advance / residual” | “perfect unpack complete” (gto) |
| “pointee epoch captured (evidence path)” | “product Accepted” via load survival |
| “free-run past transfer N/M” | “UI fixed” with bypass still on |
| “Blocked — wall = …” | silent re-label of historical B-B Accepted |

---

## 9. Relationship to product baseline

| Line | Role |
|------|------|
| `baseline/legacy-recovery-20260722` | P0 fail-closed, origin perfect-unpack protection, lab summary honesty |
| `research/gto-bootwatch-20260728` | This charter’s default implementation branch |
| Merge research → baseline | Only after expert review; no bypass-default; origin smoke green |

---

## 10. Authorization record

| Item | Value |
|------|-------|
| Opened | 2026-07-28 (operator request: process Set C + open GTO research charter) |
| Battlefield ID | `GTO-POINTEE-EPOCH` |
| Auto-start grind | **No** — charter opens the battlefield; Round 0 measure starts when operator says “execute charter Round 0” or equivalent |
| Closes | Research exit §4.1 or residual-stop §4.3 or expert revoke |

---

*Does not claim gto perfect unpack or product 1.0.*
