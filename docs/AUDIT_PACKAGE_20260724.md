# Audit Package — Unattended baseline (2026-07-24, B-B close)

**Audience:** human auditor / acceptance only.  
**Branch:** `baseline/legacy-recovery-20260722`  
**Decisions:** [UNATTENDED_DECISIONS_20260724.md](UNATTENDED_DECISIONS_20260724.md) (D1–D8 + Q1–Q7 all A)  
**Residual detail:** [UNATTENDED_RESIDUAL_20260724.md](UNATTENDED_RESIDUAL_20260724.md)  
**Validation summary task:** **VNEXT-BEH** (batch `bb_gate_pin`)

---

## 1. Executive verdict (honest)

| Claim | Status |
|-------|--------|
| Independent structural acceptance (R0B) | **Yes** — `check-static` never `Accepted` alone |
| Origin-only pure default (D3) | **Yes** (code + live pure dump); pure not global |
| Oreans 3× engineering harden (D6) | **Yes** — vault batch `u_harden_3x` all_ok |
| Independent GTO host (D4) | **Yes** (code path + structural smoke) |
| Vault B-B / VNEXT-BEH (D2/D7/Q7) | **Yes** — 4-case all_ok; VNEXT-BEH written |
| Perfect unpack 1.0 | **Not claimed** (load survival ≠ product logic) |

**Auditor bottom line:** B-B closed under Q7 with vault evidence + compose Accepted on all four cases. Product **1.0** still blocked by load-flake residual and lack of full business-logic equivalence.

---

## 2. Closed / not closed

| Gate | Status | Anchor |
|------|--------|--------|
| R0B structural | closed | acceptance crate |
| R3 / R4 structural history | closed | validation_summary.prev_* |
| B-A0..B-A3 synthetic | closed | VNEXT_BEHAVIORAL_PATH |
| Oreans 3× harden | engineering green | `lab/evidence/_repeat/batch_20260724-013625_u_harden_3x` |
| B-B vault 4-case | **closed** | `lab/evidence/_beh_gate/batch_20260724-112907_bb_gate_pin` |
| VNEXT-BEH | **written** | `validation_summary.json` task VNEXT-BEH |

### B-B winning compose

| Case | Compose | Candidate tag |
|------|---------|---------------|
| origin_macro | **Accepted** | `live_20260724-101051_u_origin_pure_r1` |
| lunlun_software | **Accepted** | `live_20260724-013746_u_harden_3x_n3` |
| xiongxiong_duokai | **Accepted** | `live_20260724-013837_u_harden_3x_n3` |
| gto_launcher | **Accepted** | `live_20260723-225951_r4c_gto` |

---

## 3. Code surfaces (this close)

| Area | Path |
|------|------|
| Origin pure resolve | `crates/cli/src/origin_pure.rs` |
| GTO independent host | `crates/cli/src/unpacker/gto_host.rs` |
| Clear RELOCS_STRIPPED on dump | `crates/pe/src/dumper/header_patch.rs` |
| Probe load_no_crash harden | `tools/_behavior_probe.py` |
| B-B gate pin + walk | `tools/_behavior_bb_gate.py` |

---

## 4. Residual (still blocks product 1.0)

| ID | Item | Blocks 1.0? |
|----|------|-------------|
| R-LOAD-FLAKE | Origin/GTO intermittent 0xC0000005 without probe retries | Stability |
| R-GTO-LATEST | Newest GTO dumps often Fail; older pin Accepted | Quality |
| R-PURE-LOGIC | load_no_crash ≠ full product equivalence | **Yes** |
| R-X86 | ScyllaHide x86 residual | x86 only |

### Origin crash note (engineering)

cdb: `o+0x39e5c` `xchg [r10]` with bad `r10`; IAT neighborhood includes **GetCurrentThreadId**. Structural IAT intact; failure is runtime/intermittent.

---

## 5. Re-run matrix

```powershell
cmd /c tools\_rebuild_cli.cmd
$env:CARGO_TARGET_DIR='D:\MidaVault\scratch\cargo-target'
cargo test -p mida-acceptance --offline
python tools\_behavior_bb_gate.py --cases origin_macro,lunlun_software,xiongxiong_duokai,gto_launcher --write-summary --tag bb_gate_pin --max-wall-ms 8000 --attempts 12 --max-candidates 3
```

---

## 6. Permissions honored

- Auto **commit** local only  
- **No push**  
- Essential tools only in commit (scratch `_origin_*` / one-off scripts stay untracked)
