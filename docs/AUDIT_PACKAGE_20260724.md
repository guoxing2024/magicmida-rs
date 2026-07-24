# Audit Package — Unattended baseline (2026-07-24, residual close)

**Audience:** human auditor / acceptance only.  
**Branch:** `baseline/legacy-recovery-20260722`  
**Decisions:** [UNATTENDED_DECISIONS_20260724.md](UNATTENDED_DECISIONS_20260724.md) (D1–D8 + Q1–Q7 all A)  
**Residual detail:** [UNATTENDED_RESIDUAL_20260724.md](UNATTENDED_RESIDUAL_20260724.md)  
**Validation summary task:** still **VNEXT-R4** (not VNEXT-BEH)

---

## 1. Executive verdict (honest)

| Claim | Status |
|-------|--------|
| Independent structural acceptance (R0B) | **Yes** — `check-static` never `Accepted` |
| Origin-only pure default (D3) | **Yes** (code + live pure dump); pure not global |
| Oreans 3× engineering harden (D6) | **Yes** — vault batch `u_harden_3x` all_ok |
| Independent GTO host (D4) | **Yes** (code path + structural smoke) |
| Vault B-B / VNEXT-BEH (D2/D7/Q7) | **No** — 4-case all_ok failed; write refused |
| Perfect unpack 1.0 | **Not claimed** |

**Auditor bottom line:** Engineering progress on pure/GTO/probe/3× is **commit-ready**; product **1.0** and **VNEXT-BEH** remain **blocked** on Origin+GTO load_no_crash stability (see residual).

---

## 2. Closed / not closed

| Gate | Status | Anchor |
|------|--------|--------|
| R0B structural | closed historically + still green on candidates | acceptance crate |
| R3 structural history | closed | validation_summary.prev_* |
| R4 structural | closed | validation_summary.json VNEXT-R4 |
| B-A0..B-A3 synthetic | closed | VNEXT_BEHAVIORAL_PATH |
| Oreans 3× harden | engineering green | `lab/evidence/_repeat/batch_20260724-013625_u_harden_3x` |
| B-B vault 4-case | **open / fail** | `lab/evidence/_beh_gate/batch_20260724-101505_bb_gate_r2b` |
| VNEXT-BEH | **not written** | gate refused `not all_ok` |

### B-B partial (honest)

| Case | Compose |
|------|---------|
| lunlun_software | **Accepted** |
| xiongxiong_duokai | **Accepted** |
| origin_macro | probe Fail (AV / flaky) |
| gto_launcher | probe Fail (AV) |

---

## 3. Code surfaces (this run)

| Area | Path |
|------|------|
| Origin pure resolve | `crates/cli/src/origin_pure.rs` |
| Pure CLI flags | `crates/cli/src/args.rs` |
| GTO independent host | `crates/cli/src/unpacker/gto_host.rs` |
| Pure postprocess panic fix | `crates/pe/src/postprocess.rs` |
| Probe load_no_crash | `tools/_behavior_probe.py` |
| B-B gate | `tools/_behavior_bb_gate.py` |

---

## 4. Residual (blocks 1.0)

| ID | Item | Blocks 1.0? |
|----|------|-------------|
| R-BEH | B-B 4-case not all_ok; no VNEXT-BEH | **Yes** |
| R-ORIGIN-LOAD | Origin pure/legacy load_no_crash AV flaky vs oracle Pass | **Yes** |
| R-GTO-LOAD | GTO unpacked load_no_crash AV | **Yes** |
| R-PURE-QUALITY | Pure dump structural OK; not proven load-stable | Quality |
| R-X86 | ScyllaHide x86 residual (search empty) | x86 only |

---

## 5. Re-run matrix

```powershell
cmd /c tools\_rebuild_cli.cmd
$env:CARGO_TARGET_DIR='D:\MidaVault\scratch\cargo-target'
cargo test -p mida-acceptance --offline
python tools\_behavior_ba3_smoke.py
python tools\_behavior_bb_gate.py --cases origin_macro,lunlun_software,xiongxiong_duokai,gto_launcher --write-summary --tag bb_gate
# VNEXT-BEH file only if summary all_ok true
```

---

## 6. Permissions honored

- Auto **commit** local only  
- **No push**  
- No CI/remote  
