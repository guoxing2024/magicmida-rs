# GTO-PRODUCT-RECOVERY Route F R1 Report (2026-07-30)

**Branch:** `codex/gto-route-f-r1`  
**Base:** `26248f4`  
**Ledger after R1:** used=1 / cap=2 / remaining=1

---

## Goal

Attack the Route E residual blocker: no-bypass r27 candidate passes clean-byte
gates but AVs on cold start at the **heap-rebasing wall** (stale computed
heap pointers in pre-object gaps).

---

## Root cause (deterministic)

Historical r27 layout:

- heap handle ≈ `0x830000`
- computed ptr `0x846898` = handle + `0x16898`
- nearest captured object at `0x846bb0`
- **0x318-byte uncaptured gap** before the object

Prior `capture_heap_slab` set `old_base = min(object live_ptrs)`. Under the
strict-interior rebase rule `old_base < V < old_base+len`, `0x846898` was
**outside** the slab and never rebased → cold-start AV.

---

## Functional change

File: `crates/pe/src/dumper/heap_global_snapshot.rs`

1. **`HEAP_SLAB_PREFIX_PAD = 0x1000`** — pull slab base down before the first
   object (page-aligned) so pre-object holes of the `0x318` class fall interior.
2. **`compute_heap_slab_span`** — pure span computation (testable offline).
3. **`heap_slab_covers_interior`** — documents strict-interior membership.
4. **`capture_heap_slab`** — uses the padded span; RPM still best-effort with
   zero-fill for unreadable pages.
5. Unit tests:
   - `heap_slab_span_covers_r27_pre_object_gap`
   - `heap_slab_span_none_for_single_object`

No bypass / semantic repair. Slab still gated by existing
`MIDA_GTO_NO_BYPASS=1` path in dump_process (unchanged this round).

---

## Validation

```text
cargo test -p mida-pe --lib heap_slab_span   # 2 passed
python tools/_mtr_gto_product_perfect_validate.py --self-test
python tools/_mtr_gto_product_perfect_validate.py \
  --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json \
  --evidence-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_EVIDENCE_20260730.json
```

Route E harness: still `product_1_0=false` (live/UI/script evidence FAIL) —
clean-byte gate discipline preserved.

---

## Status

**INCONCLUSIVE / residual toward product 1.0**

- Production span fix landed + unit-proven for the r27 gap class
- **Not** product 1.0: no live no-bypass re-dump + harness PASS this round
  (no live execution authorized in R1 validation set)
- Remaining: re-measure no-bypass dump with slab prefix under operator live
  authorization; then Route E evidence gates

## Ledger

used=1 / cap=2 / remaining=1

## Non-claims

- Not product 1.0 / not gto perfect unpack
- No live re-run / vault write / push
- No gto_host / bwhook / DRx / VEH / injection / bypass / R1B / E2
- Prefix pad does not invent heap contents (RPM or zero-fill only)
