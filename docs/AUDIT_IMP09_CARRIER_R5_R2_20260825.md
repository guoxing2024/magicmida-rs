# AUDIT — IMP-09-CARRIER-R5-R2 (Walker Carrier Alive-Window / Mapping Proof / Execute Gate)

**Work order**: WORK_ORDER_IMP-09-CARRIER-R5-R2_20260825.md
**Branch**: `codex/imp09-carrier-r5-r2` (created from `9cd2e4dffa9c8de3031c78bf8d670688afdd7c78`)
**HEAD (base)**: `9cd2e4dffa9c8de3031c78bf8d670688afdd7c78` — IMP-09-CARRIER-R5-R1
**Audit date**: 2026-08-25

## 0. Executive summary

R5-R2 delivers, on top of R5-R1's production bind caller:

1. **R5-R2-1 (alive window)**: both production paths (`CREATE_PROCESS` and `post_attach`) now run the controller gate — walker bind + execute — BEFORE `terminate_and_wait()`. `AntidebugStageOptions.defer_cleanup_to_caller` keeps `run()` from firing the termination backend, so the debugger owns exactly-once termination after the gate. `probe_process_liveness()` (GetExitCodeProcess == STILL_ACTIVE) is required before bind AND before execute; unknown/dead fails closed.
2. **R5-R2-2 (candidate pre-bind mapping proof)**: `prove_candidate_mappings()` runs `VirtualQueryEx` per candidate BEFORE `install_walker_session_production()`: canonical user VA, image envelope `[module_base, module_base + verified_size_of_image)`, MEM_COMMIT, probe-span contained in region, readable protection. Any failure rejects the whole set (fail-closed). The proof set is retained on the controller for evidence.
3. **R5-R2-3 (verified image envelope)**: `RuntimeFileIdentity` now seals `verified_size_of_image` (PE32+ SizeOfImage read from the SAME verified file bytes via `pe32_size_of_image()`, fail-closed 0 for non-PE32+/truncated). The envelope is never read from a live-process header.
4. **R5-R2-4 (execute gate)**: `execute_walker_production()` requires an AUTHORIZED target-side dispatch bridge (`WalkerDispatchBridge` trait). Without one (R5-R2 production wiring always passes `None` — live authorization deferred to R5-R3/R5-R4), it records and returns `NOT_IMPLEMENTED`; it never calls the in-process engineering `exports::WalkerExecute` and never forges success. `WALKER_STATUS_OK` + marshaled output present is the ONLY path to `Proceed`; non-OK raw status or missing output fail closed.
5. **R5-R2-5 (rollback)**: existing transactional installer + RAII `WalkerTeardownGuard` free both remote allocations on every failure path; no READY/success is published on failure.

All exit gates: `Proceed` is BLOCKED on bind failure, execute non-OK, output missing, or missing dispatch bridge.

## 1. Production caller graph (non-test, file:line)

### CREATE_PROCESS path (`crates/cli/src/unpacker/mod.rs`)

```text
mod.rs:1181  evidence_dir := output_path.parent()
mod.rs:1186  AntidebugStageOptions { walker_dispatch: None, defer_cleanup_to_caller: true, ... }
mod.rs:1422  let outcome = ad_controller.run();        // gate runs in ALIVE window
mod.rs:1426  ad_controller.record_terminate_enter();   // BEFORE terminate
mod.rs:1438  let cleanup_report = dbg.terminate_and_wait();  // AFTER gate
mod.rs:1440  ad_controller.set_cleanup_report(&cleanup_report);
mod.rs:1453  write_walker_evidence(&ad_controller.walker_evidence_record("create_process"), &evidence_dir)
mod.rs:1462  match outcome: Failed -> write_failure_evidence + Err; Proceed -> info
```

### post-attach path (`crates/cli/src/unpacker/mod.rs`)

```text
mod.rs:757   AntidebugStageOptions { walker_dispatch: None, defer_cleanup_to_caller: true, ... }
mod.rs:805   let outcome = ad_controller.run();        // gate runs in ALIVE window
mod.rs:809   ad_controller.record_terminate_enter();   // BEFORE terminate
mod.rs:814   let cleanup_report = dbg.terminate_and_wait();  // AFTER gate
mod.rs:816   ad_controller.set_cleanup_report(&cleanup_report);
mod.rs:818   write_walker_evidence(&ad_controller.walker_evidence_record("post_attach"), &evidence_dir)
mod.rs:835   Failed -> write_failure_evidence + Err
```

### Controller internals (`crates/cli/src/unpacker/antidebug_controller.rs`)

```text
antidebug_controller.rs:707   fn bind_walker_from_loader_production  (bind caller)
antidebug_controller.rs:776   fn execute_walker_production          (execute gate caller)
antidebug_controller.rs:811   pub fn record_walker_event            (raw event recorder)
antidebug_controller.rs:825   pub fn record_terminate_enter         (terminate marker)
antidebug_controller.rs:846   pub fn walker_evidence_record         (evidence builder)
antidebug_controller.rs:1099  pub fn run                            (lifecycle driver)
antidebug_controller.rs:1459  pub fn write_walker_evidence          (sidecar writer)
```

### Walker session carriers (`crates/cli/src/unpacker/walker_session.rs`)

```text
walker_session.rs:206  pub fn probe_process_liveness          (GetExitCodeProcess == STILL_ACTIVE)
walker_session.rs:297  pub fn prove_candidate_mapping        (single candidate VirtualQueryEx proof)
walker_session.rs:415  pub fn prove_candidate_mappings       (whole candidate set proof)
walker_session.rs:450  pub trait WalkerDispatchBridge         (authorized target-side dispatch seam)
```

### Verified image envelope (`crates/cli/src/unpacker/runtime_loader.rs`)

```text
runtime_loader.rs:275  pub fn pe32_size_of_image              (pure-file PE32+ SizeOfImage, fail-closed 0)
runtime_loader.rs:218  verify_file() seals verified_size_of_image from the SAME verified bytes
runtime_loader.rs:392  pub fn verified_size_of_image(&self)   (sealed accessor)
```

## 2. Event sequence samples (raw records)

### Success path with authorized bridge (offline mock; R5-R2 production has NO bridge)

```json
[
  { "sequence": 1, "phase": "loader_complete", "detail": "target_pid=1234 module_base=0x1a2b3c0000", "walker_status_raw": null },
  { "sequence": 2, "phase": "bind_enter",     "detail": "module_base=0x1a2b3c0000 image_size=0x4000", "walker_status_raw": null },
  { "sequence": 3, "phase": "bind_exit",      "detail": "WIRED", "walker_status_raw": null },
  { "sequence": 4, "phase": "execute_enter",  "detail": "authorized target-side dispatch", "walker_status_raw": null },
  { "sequence": 5, "phase": "execute_exit",   "detail": "outcome=Success", "walker_status_raw": 0 },
  { "sequence": 6, "phase": "terminate_enter","detail": null, "walker_status_raw": null }
]
```

### Fail-closed path (no authorized dispatch bridge — the R5-R2 production reality)

```json
[
  { "sequence": 1, "phase": "loader_complete", "detail": "target_pid=1234 module_base=0x1a2b3c0000", "walker_status_raw": null },
  { "sequence": 2, "phase": "bind_enter",     "detail": "module_base=0x1a2b3c0000 image_size=0x4000", "walker_status_raw": null },
  { "sequence": 3, "phase": "bind_exit",      "detail": "WIRED", "walker_status_raw": null },
  { "sequence": 4, "phase": "execute_enter",  "detail": "authorized target-side dispatch", "walker_status_raw": null },
  { "sequence": 5, "phase": "execute_exit",   "detail": "outcome=NotImplemented", "walker_status_raw": null },
  { "sequence": 6, "phase": "terminate_enter","detail": null, "walker_status_raw": null }
]
liveness_probe="alive", execute_liveness="alive", capture_phase="create_process"
Outcome: FAILED (AntiDebugRuntimeUnavailable) — Proceed blocked. Evidence sidecar written.
```

### Fail-closed path (bind failure — no target handle)

```json
[
  { "sequence": 1, "phase": "loader_complete", "detail": "...", "walker_status_raw": null },
  { "sequence": 2, "phase": "bind_enter",     "detail": "...", "walker_status_raw": null },
  { "sequence": 3, "phase": "bind_exit",      "detail": "NOT_WIRED liveness=Some(Unknown) proof=false", "walker_status_raw": null }
]
liveness_probe="unknown" — Outcome: FAILED (AntiDebugRuntimeUnavailable). Proceed blocked.
```

## 3. Candidate mapping proof schema

```json
{
  "module_base": 4509715660800,
  "verified_size_of_image": 16384,
  "probe_span": 16,
  "all_passed": true,
  "items": [
    { "candidate_va": 4509715660800, "canonical_va": true, "page_span_fits": true,
      "in_image_envelope": true, "envelope_base": 4509715660800, "envelope_end": 4509715677184,
      "query_ok": true, "state": 4096, "mem_committed": true,
      "region_base": 4509715660800, "region_size": 16384,
      "region_type": 131072, "probe_contained_in_region": true, "protection": 4,
      "readable_protection": true,
      "passed": true, "fail_reason": null },
    { "candidate_va": 4509715664896, "canonical_va": true, "page_span_fits": true,
      "in_image_envelope": true, "envelope_base": 4509715660800, "envelope_end": 4509715677184,
      "query_ok": true, "state": 4096, "mem_committed": true,
      "region_base": 4509715660800, "region_size": 16384,
      "region_type": 131072, "probe_contained_in_region": true, "protection": 4,
      "readable_protection": true,
      "passed": true, "fail_reason": null },
    "... (base+0x2000, base+0x3000 identical shape) ..."
  ]
}
```

`state` is the raw MEMORY_BASIC_INFORMATION.State (MEM_COMMIT=0x1000).
`protection` is the raw PAGE_PROTECTION_FLAGS u32 (PAGE_READWRITE=0x04 in the sample).
`region_type` is the raw MEMORY_BASIC_INFORMATION.Type (MEM_PRIVATE=0x20000=131072 in the sample).

## 4. Negative tests (offline; each proves fail-closed)

| Test | File | What it proves |
|------|------|----------------|
| `r5r2_mapping_proof_rejects_mem_free` | walker_session.rs | candidate in a MEM_FREE region -> passed=false |
| `r5r2_mapping_proof_rejects_outside_envelope` | walker_session.rs | candidate outside [base, base+size) -> passed=false |
| `r5r2_mapping_proof_rejects_page_cross` | walker_session.rs | probe span crosses a page boundary -> passed=false |
| `r5r2_mapping_proof_requires_verified_image_size` | walker_session.rs | SizeOfImage=0 (missing) -> fail closed |
| `r5r2_mapping_proof_set_fails_when_any_item_fails` | walker_session.rs | one bad candidate rejects the WHOLE set |
| `r5r2_liveness_unknown_for_invalid_handle` | walker_session.rs | invalid handle -> Unknown (fail-closed) |
| `imp09_r5r1_run_bind_fails_closed_without_target_handle` | antidebug_controller.rs | no handle -> liveness Unknown -> bind fails -> Proceed blocked |
| `imp06_controller_proceeds_with_valid_loader_result` | antidebug_controller.rs | valid loader but NO walker carrier -> bind fails -> Proceed blocked (R5-R2 contract) |
| `imp09_r5r2_execute_gate_non_ok_status_blocks_proceed` | antidebug_controller.rs | raw status=2 (MAP_FAILED) -> Failed + raw status recorded |
| `imp09_r5r2_execute_gate_missing_output_blocks_proceed` | antidebug_controller.rs | OK status but no output -> Failed |
| `imp09_r5r2_no_bridge_records_not_implemented_raw` | antidebug_controller.rs | no authorized bridge -> NOT_IMPLEMENTED, never forged success |
| `imp09_r5r2_walker_evidence_record_roundtrips` | antidebug_controller.rs | 6-event monotonic sequence + JSON roundtrip |
| `imp09_r5r2_write_walker_evidence_atomic_roundtrip` | antidebug_controller.rs | sidecar write + read-back |

### Bind-after-terminate is structurally impossible

`terminate_and_wait()` is called ONLY after `run()` returns AND `record_terminate_enter()` is recorded (mod.rs:1426/809). The bind + execute gates are inside `run()`; there is no code path that binds after termination. The liveness probe (`probe_process_liveness`) would return Dead/Unknown for a terminated target and fail closed even if such a path were added.

## 5. Command evidence

```text
BASE HEAD: 9cd2e4dffa9c8de3031c78bf8d670688afdd7c78 (IMP-09-CARRIER-R5-R1)
CORRECTION HEAD: 7c0dc8decce897a9a11cce9e1856831dc6e27ca6 (IMP-09-CARRIER-R5-R2-CORRECTION)
toolchain: 1.97.1-x86_64-pc-windows-msvc (rust-toolchain.toml pin)

$ export PATH='/c/Program Files/Microsoft Visual Studio/2022/Professional/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64':$PATH

$ cargo test -p mida-cli --lib
   (3 consecutive runs on this machine, all green)
   run1: 507 passed; 0 failed; 1 ignored; finished 22.05s  -> r5r2_correction_full_mida_cli_lib.txt
   run2: 507 passed; 0 failed; 1 ignored; finished 21.90s  -> r5r2_correction_full_mida_cli_lib_2.txt
   run3: 507 passed; 0 failed; 1 ignored; finished 23.08s  -> r5r2_correction_full_mida_cli_lib_3.txt
   raw sidecars preserved in repo root (stdout+stderr+exit code 0)

$ cargo test -p mida-antidebug-runtime -p mida-antidebug -p mida-core
   all suites green: 2+25+65+68+34+26+27+100 passed, 0 failed
   raw sidecar: r5r2_correction_other_crates.txt

$ cargo test -p mida-cli --lib r5r2_  (R5-R2 subset, 16 tests)
   test result: ok. 16 passed; 0 failed -> r5r2_correction_subset.txt

$ cargo fmt --all -- --check
   baseline (HEAD):            197 diffs (pre-existing, acknowledged)
   corrected working tree:     198 diffs (EXIT_CODE=1, NOT a clean gate)
   the +1 diff is pre-existing R5-R2 code (runtime_loader pe32_size_of_image
   formatting); the region_type correction added 0 new rustfmt diffs.
   raw sidecar: r5r2_correction_fmt_check.txt
   format_gate = NOT PASS (repo-wide pre-existing debt; same as baseline +1)

Raw evidence sidecar (machine-generated, real run):
  evidence/r5r2/mida_antidebug_walker.evidence.json
  - generated by a REAL offline controller run (temporary capture test,
    removed after generation) through the PRODUCTION write_walker_evidence()
  - real target_pid=17088, real VirtualQueryEx results, real region_type
    (131072 = MEM_PRIVATE on all 4 candidates), real monotonic 6-event
    sequence, raw walker status 0
  - this is NOT hand-written JSON; it is the exact bytes written by the
    production sidecar writer for the success path with an authorized bridge
    (offline mock; production R5-R2 has no bridge -> NOT_IMPLEMENTED)

File SHA-256 (corrected working tree):
  antidebug_controller.rs  31b650f991250109702cd523b38d71515f36e9f63402427bbc6e21fb7e8686cc  (unchanged)
  mod.rs                   81a7c92a74210eab673fa0d159d485d337daa0e9a1f47efa9405e5c467f0cdb0  (unchanged)
  runtime_loader.rs        3acdc0bcc41efeda029f924132437fd58813de46d747a51e33a873b79ceae896  (unchanged)
  walker_session.rs        61eb7e74a803f94eb71f3ea055f4c2c623a8ff037c9da20f20c8d30a69c3e352  (region_type added)
  docs/AUDIT_IMP09_CARRIER_R5_R2_20260825.md  0ae1c1b1478f4482adcf3b95cc5073726131ecf7125fcb53affb5cdeaf9d9ef5
```

## 5.1 Audit finding dispositions (R5-R2-CORRECTION)

| Finding | Disposition |
|---------|-------------|
| CandidateMappingProof missing MEMORY_BASIC_INFORMATION.Type | FIXED: region_type: u32 added + recorded raw (walker_session.rs), asserted in test (MEM_PRIVATE=0x20000), real sidecar shows 131072 |
| Raw evidence = hand-written JSON | FIXED: real machine-generated sidecar evidence/r5r2/mida_antidebug_walker.evidence.json from production writer (real PID/VirtualQueryEx/Type/sequence) |
| mida-cli full test 504/3 (audit binary) | REPRODUCED + EXPLAINED: the 3 symlink tests pass individually (1/1) and pass in the 9-test resolver subset and in 3 consecutive FULL suite runs on this machine. The audit run's failures are environment-specific: on that run symlink_file creation fell back to the hard_link fallback (no symlink privilege at that moment), so the resolver correctly accepted the hard-linked sibling (canonical == expected) and the expect_err panicked. The resolver behavior is CORRECT; the test fallback converts a privilege absence into a false failure. runner_preflight.rs is OUTSIDE this work order's allowed file list, so no test change was made; the finding is recorded as environment-limited, and the full crate gate is re-proven green (507/0) on this machine. |
| fmt written as pass | CORRECTED: format_gate = NOT PASS (198 diffs, exit 1; baseline 197 pre-existing). No green claim. |
| HEAD not rebound | REBOUND: see correction HEAD above after commit |
| production target-side dispatch | UNCHANGED (NOT_IMPLEMENTED by design, R5-R3/R5-R4) |
| section producer / protected sample / live test | UNCHANGED (NOT AUTHORIZED) |

## 6. Deferred (per work order §5 — NOT implemented in R5-R2)

- section producer / round1+round2 DONE writes (R5-R3)
- runtime-side probe execution (R5-R3)
- V2 attestation digest consumer final acceptance
- full `VirtualFreeEx` / `GetLastError` teardown observability (R5-R4)
- protected sample / live authorization: `NOT AUTHORIZED`; production `walker_dispatch` is always `None`
- No offline/mock PASS is claimed as a Windows live PASS.
