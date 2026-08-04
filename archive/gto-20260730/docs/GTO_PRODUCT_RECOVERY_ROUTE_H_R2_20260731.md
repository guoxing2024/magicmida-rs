# GTO-PRODUCT-RECOVERY Route H R2 Report (2026-07-31)

**Branch:** `codex/gto-route-h-r1`
**Base:** `e4b1cfc`
**Ledger after R2:** used=2 / cap=2 / remaining=0 — **No H R3**
**Status:** **RESIDUAL-STOP** (loader-valid fixed; product 1.0 not achieved)

Wall-clock evidence times use local `2026-07-31T01:2x+08:00` / UTC `2026-07-30T17:2xZ` (not future-dated).

---

## Protected input

| Field | Value |
|-------|-------|
| Source | `D:\Tools\RE\dumps\gto\启动器.exe` (operator-updated) |
| size_bytes | `14300672` |
| sha256 | **`46539ea7b1bf1f43cf2ed09fc0642d84b10a274939efb7c08f87b1869d738aa8`** |

---

## R2 primary fix — loader-valid PE raw-range completeness

### Diagnosed defect (R1 candidate)

| Field | Value |
|-------|-------|
| R1 candidate | `scratch/product_recovery_route_h_r1_newsample_b_20260731/gto_unpacked.exe` |
| Example | `.boot` raw end `0x194c000` vs file size `0x194be38` (**missing `0x1c8`**) |
| OS symptom | CreateProcess **WinError 193** (not a valid Win32 application) |

Root class: section headers claim `PointerToRawData + SizeOfRawData` past EOF. Bootstrap / extra_data paths often set **section-aligned** `SizeOfRawData` while writing only unpadded payload length.

### Code (generic; no sample hardcode)

1. **`crates/pe/src/dumper/output_writer.rs`**
   - `ensure_section_raw_ranges_covered`: zero-pad final file so every section raw range fits.
   - `write_section_data`: size from **claimed** `SizeOfRawData`, not only `extra.len()` / partial dump slice.
   - `section_raw_ranges_fit` helper for tests/self-check.
2. **`tls_bootstrap.rs`**: pad `.boot` `extra_data` to claimed raw size when that path installs TLS bootstrap (belt-and-suspenders; writer still enforces independently).
3. **`postprocess.rs` `pack_section_layout`**: if max section raw end exceeds buffer, **pad** instead of leaving truncated.

### Regression tests (no `0x1c8` sample constant)

`dumper::output_writer::tests`:

- `write_output_file_pads_short_extra_data_to_claimed_raw_size` — multiple shortfall sizes `(0x100,0x1000)`, `(0xE38,0x1000)`, `(0x50,0x200)`
- `ensure_section_raw_ranges_covered_extends_truncated_buffer`
- `section_raw_ranges_fit_rejects_past_eof`

Result: **3/3 ok**.

---

## New no-bypass candidate (R2)

| Field | Value |
|-------|-------|
| Env | `MIDA_GTO_NO_BYPASS=1`; `MIDA_GTO_BYPASS` / `MIDA_GTO_SEMANTIC_REPAIR` **absent** |
| Evidence set | `scratch/product_recovery_route_h_r2_20260731` |
| Candidate | `gto_unpacked.exe` |
| size_bytes | `26378240` (`0x1928000`) |
| sha256 | **`49258efbbb4bbf61fd500c034fa46d247e0317416bd6e7a67b133c94cf1133ce`** |
| Dump note | ahk_gto Match; Route H timing; last-resort alive path class (same host policy as R1) |

### PE raw-range invariant (on candidate)

- All 11 sections: `PointerToRawData + SizeOfRawData <= file_len`
- `.boot` End=`0x1928000` == file_len; **violations=0**, gap=0

### CreateProcess

| Candidate | Result |
|-----------|--------|
| R2 new | **OK** — process starts and stays alive (≥500 ms); **not** WinError 193 |
| R1 old (control) | Still **WinError 193** (invalid Win32 application) |

Loader structural defect that caused 193 is **closed**.

---

## Product probes (after loader-valid)

| Gate | Result |
|------|--------|
| Natural load fixed N=3 | **2/3** (`pass_rate=0.6667`) — probe verdict Pass; evidence `scratch/.../load_no_crash.json` |
| UI `NewClassName` | **Fail** — 3/3 `nt_exception_exit:0xc0000005` (AV); classes_seen=[] |
| Runtime script engine | **not obtained** (no UI class; no independent script proof) |
| Clean-byte 5/5 | **unsealed / fail-closed** — no independent authority for `46539ea7…` layout; **forbidden** to self-seal from candidate; old Route E seals for `4d5770af…` do not apply |
| Harness `product_1_0` | **false** (not claimed) |
| `overall_status=PASS` | **not met** |

### First real failure point **after** loader fix

**UI path access violation `0xc0000005` before `NewClassName` is observed.**

Natural load can survive 2/3 of short windows, but the product UI class never appears; all window probes die with STATUS_ACCESS_VIOLATION. Script-engine runtime proof is blocked behind that UI path.

This matches the historical cold-UI AV class on GTO product recovery, now reachable only because the PE is finally loader-valid.

---

## PASS table (binding)

| Requirement | Met? |
|-------------|------|
| no-bypass env | yes |
| loader-valid (no 193; raw ranges covered) | **yes** |
| clean-byte from independent authority | **no** (none available; not self-sealed) |
| load ≥2/3 | yes (2/3) |
| NewClassName Pass | **no** (AV) |
| runtime script Pass | **no** |
| harness `overall_status=PASS` + `product_1_0=true` | **no** |

**Product 1.0 is not claimed.**

---

## Residual-stop seal

- Route H ledger: **used=2 / cap=2 / remaining=0**
- **No H R3** under current authorization
- Progress retained: generic PE emit invariant + tests; new-sample no-bypass candidate is loader-valid and load-survives 2/3
- Next product work requires **new governance** (new route / round allocation), not silent continuation

### Non-claims

- Not product 1.0 / not perfect unpack
- No bypass / no semantic repair / no DRx/VEH/injection / no R1B/E2
- No inventing clean-byte seals from the candidate itself
- No push

---

## Verification run (this round)

| Check | Result |
|-------|--------|
| `cargo check --offline -p mida-pe -p mida-cli` | ok |
| `cargo test --offline -p mida-pe --lib dumper::output_writer::tests` | 3/3 ok |
| product harness `--self-test` | OK |
| PE raw-range invariant on R2 candidate | violations=0 |
| `cargo fmt --all -- --check` | fails on **pre-existing** repo style noise (untouched files); touched files rustfmt-checked |
| `git diff --check` on touched paths | clean |
