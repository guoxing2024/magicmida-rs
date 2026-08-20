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

**W4 claim-bar (2026-07-24):** product **1.0 = NO**. Course-correction W0–W4 closed at metric/governance; see [UNATTENDED_RESIDUAL_20260724.md](UNATTENDED_RESIDUAL_20260724.md) W4 + [COURSE_CORRECTION_WORK_ORDER.md](COURSE_CORRECTION_WORK_ORDER.md).

| ID | Item | Blocks 1.0? | Status after W1–W4 |
|----|------|-------------|-------------------|
| R-LOAD-FLAKE | Origin/GTO quiet attempt=1 load | Stability | **Metric-closed** (W1 Origin scrub_v2; W2 GTO clear-regs); W4 reconfirm Origin+GTO N=5 = 1.0 |
| R-GTO-LATEST | Fresh GTO without r4c walk | Quality | **Metric-closed** (W2) |
| R-GTO-BOOT | Independent-host `.boot` heap snapshot variance | Quality | Open (honesty) |
| R-PURE-LOGIC | load / window / title / controls / exit / exports / pe_string ≠ business equivalence | **Yes** | Advanced (W3 + P1 + P2 controls/pe_string); **still blocks 1.0** |
| R-GTO-UI | Unpacked GTO no product window; protected has NewClassName login | Quality / GTO 1.0 | **Open + advanced** (2-round fix: title root plant + gscript 32KiB + UI-early dump; cold still ExitProcess(0); p2 + r_gto_ui_r2) |
| R-4CASE-FRESH | Full 4-case attempt=1 on best pins | Claim hygiene | **P1-A closed** (4× N=10 = 1.0) |
| R-X86 | ScyllaHide x86 residual | x86 only | Open |

### Origin crash note (engineering, historical)

Pre-W1 cdb: `o+0x39e5c` `xchg [r10]` with bad `r10` (kernel-canonical object head `0xfc388`). Fixed at metric by W1 scrub_v2; retained as root-cause archive.

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
