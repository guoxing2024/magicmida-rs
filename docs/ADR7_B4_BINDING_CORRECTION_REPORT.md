# ADR7-B4-RUNTIME-BINDING-CORRECTION-1 - B4 dynamic observation binding correction report

> status: COMPLETE - FORMAL PASS evidence package (evidences re-sealed 2026-08-20 after ADR7-B4-EVIDENCE-CONSISTENCY-1)
> generated: 2026-08-20
> parent: ADR7-B4-RUNTIME-BINDING-CORRECTION-1 (P0 runtime-offset binding correction)
> evidence dir: D:\MidaVault\lab\evidence\adr7b_b4_binding_correction
> supersedes: adr7b_b4_requal (SUPERSEDED_RUNTIME_OFFSET_BINDING)

## 0. Background (audit finding being corrected)

The B4 requalification package (adr7b_b4_requal) recorded runtime cbf64f93 with
a fault RVA 0x2e816, but the observer still carried the OLD static c22cb722
offset tables (RUNTIME_OBS_POINTS 0x2ed90/0x2edb6/0x2e5f4/0x2e628 and
INT29_SITES without 0x2e816). All 8 target timelines showed:

    actual_int29_address = null
    breakpoint_hit_address = null

i.e. the observation points were bound to the wrong runtime revision and never
matched the actual crash site. This package corrects that: the observer is now
bound to the EXACT runtime artifact used in the live matrix via a generated
runtime-hash -> offset map, and fails closed on any other runtime.

## 1. New commit

    HEAD   b2ae59139e41f722f286aa86827f941257a43688  test(adr7): ADR7-B4-RUNTIME-BINDING-CORRECTION-1
    parent 7e65cf657029c8d3452bd9b595f8ca6f1cf79e18  (ADR7-B4-REQUAL-1)

Scope: crates/core/src/adr7_b4_observer.rs, crates/core/src/windows_debugger.rs,
crates/core/src/lib.rs, crates/core/src/b4_runtime_offset_map.json (new),
crates/core/src/b4_runtime_offsets.rs (new), crates/antidebug-runtime/tests/
b4_dynamic_observer.rs. No docs/lab/cdb/disasm/temp files, no protected sample
copies, no Cargo.toml EOL dirt.

## 2. Exact runtime binding

The observer offset tables are now generated from b4_runtime_offset_map.json,
which is bound to the exact artifact observed in this matrix:

    runtime DLL sha256  ae42901ec940dfa95566dcf9e0787d1e2c9439d90e7c593ed3a803a4f9cdbb76
    runtime DLL size    370,688 B
    runtime PDB sha256  b8165cf81b7e5469979fb61e7fe6b84e7376c14a09af5fa9131dae4dd86eed96
    PDB GUID            DDCD43FD-2CFF-4242-85BF-39DC0ADB09E0  age 1
    image base          0x180000000

Observation points (verified by cdb symbol + dumpbin disassembly of the exact
artifact):

    panic_count::increase entry                        0x2eda0
    panic_count::increase+0x26 (TLS check jne)         0x2edc6
    panic_with_hook entry                              0x2e604
    panic_with_hook -> panic_count::increase call site 0x2e638

int29 (__fastfail) sites:

    0x2bfc1 0x2c366 0x2c599 0x2c759 0x2d070 0x2e7e8 0x2e816 0x3f32c 0x3fab7

Fail-closed behavior: the observer records the bound runtime_sha256 and a
binding status in every timeline; observation points are only armed after the
runtime DLL load is observed in the target, and the timeline marks the binding
as Verified only when the loaded runtime matches the bound artifact. A stale or
unknown runtime cannot silently reuse old offsets: the fault RVA is matched
against the bound int29 table only, so an unbound runtime yields
actual_int29_address=null and binding=Unverified (detectable, never a false
claim).

## 3. Build provenance

    commit/tree        b2ae59139e41f722f286aa86827f941257a43688 (parent 7e65cf6)
    runtime DLL hash   ae42901ec940dfa95566dcf9e0787d1e2c9439d90e7c593ed3a803a4f9cdbb76
    runtime PDB hash   b8165cf81b7e5469979fb61e7fe6b84e7376c14a09af5fa9131dae4dd86eed96
    CLI hash           524f61ececc7191d4bb6a3f41e6476d27af8e0059dab8e29b7c0a54e762f8ca3 (12,150,272 B)
    offset-map hash    b0c471587ebbf15e94a3537e77e4ea17e5ea444b43655bf6b6de0c54e0bc95af
    authority digest   befd38670fe418f7fecd22e95aa852ff251cc6af313103c6895358b0cc98bb8c
    toolchain          rustc 1.97.1 MSVC (1.97.1-x86_64-pc-windows-msvc)
    build commands     see adr7b_b4_binding_correction_build_provenance.json

## 4. Live matrix (20 attempts, reference-only samples)

Formal target baseline (12/12 stable):

| attempt | sample | observer | result |
|---|---|---|---|
| origin_macro_noobs_1..3 | origin_macro | none | 0xc0000409 @ 0x2e816 (3/3) |
| lunlun_software_noobs_1..3 | lunlun_software | none | 0xc0000409 @ 0x2e816 (3/3) |
| origin_macro_passive_1..3 | origin_macro | passive | 0xc0000409 @ 0x2e816; actual_int29_address != null; binding Verified (3/3) |
| lunlun_software_passive_1..3 | lunlun_software | passive | 0xc0000409 @ 0x2e816; actual_int29_address != null; binding Verified (3/3) |

Supplementary active perturbation (2 attempts, perturbation-only):

| attempt | sample | observer | result |
|---|---|---|---|
| origin_macro_active_1 | origin_macro | active (4 HW BP) | 4/4 observation points hit (0x2e604,0x2e638,0x2eda0,0x2edc6); perturbation -> bounded 60s timeout, second-chance 0xc0000005 (fail-closed cleanup) |
| lunlun_software_active_1 | lunlun_software | active (4 HW BP) | 4/4 observation points hit (0x2e604,0x2e638,0x2eda0,0x2edc6); perturbation -> second-chance 0xc0000005 |

Controls (6/6 PASS):

| attempt | sample | observer | result |
|---|---|---|---|
| c1_benign_passive_1..3 | none (benign host) | passive attach (b4_dynamic_observer) | b1 exit 0, obs_hits=0, int29_hits=0, no 0xc0000409 |
| c2_debugger_benign_1..3 | none (benign host) | debugger attach (b2_debugger_attach) | b1 exit 0, b2 exit 0, exception_0xc0000409=0 |

All protected-sample references use the original vault paths (reference-only);
no protected sample binary is copied into this evidence directory.

## 5. Dynamic chain now PROVEN

The active-mode timelines show the complete panic-path traversal with the
runtime-hash-bound observation points:

    panic_with_hook entry (0x2e604) hit
      -> call site (0x2e638) hit
        -> panic_count::increase entry (0x2eda0) hit
          -> TLS check (0x2edc6) hit
            -> [active perturbation: AV at 0x2edcf, bounded fail]

The passive/no-observer timelines show the fail-fast site itself:

    0xc0000409 (STATUS_STACK_BUFFER_OVERRUN) second-chance @ RVA 0x2e816,
    matched against the bound int29 table -> actual_int29_address != null.

Therefore the previously-missing facts are now established:
    actual int29 site dynamically matched:   YES (6/6 passive + 6/6 noobs)
    panic_count::increase dynamically hit:   YES (2/2 active)
    panic_with_hook dynamically hit:         YES (2/2 active)
    panic -> TLS -> int29 dynamic chain:     YES (active 4/4 points, passive fault site)

## 6. Bounded root-cause wording

- The runtime panics on both protected samples (origin_macro, lunlun_software)
  at the same bound int29 site 0x2e816, and does not panic on the benign host.
- The panic path enters panic_with_hook and panic_count::increase; the TLS
  check is traversed (active hit at 0x2edc6); the fail-fast (int29 @ 0x2e816)
  fires second-chance 0xc0000409 in passive/no-observer runs.
- Active mode perturbs the outcome (AV at the TLS local-count increment,
  0x2edcf) — reported as perturbation, not as the natural outcome.
- The exact panic payload/source (which assert fired) is NOT captured: that
  would require reading the panic payload or a stack snapshot, which the
  debugger-side observer does not do. The chain panic -> TLS -> int29 IS
  observed; the specific assert text is not.

## 7. Verdict gates

    runtime-specific offsets generated      PASS (offset_map.json bound to AE42901E)
    actual_int29_address != null            PASS (6/6 passive targets)
    active breakpoint hits or bounded fail  PASS (4/4 hits x2; bounded 60s timeout)
    20-attempt matrix                       PASS (20/20 attempts)
    raw/evidence/root/final/seal            PASS (see manifests)
    CLI/runtime/source provenance           PASS (build provenance + authority)
    no protected sample copies              PASS
    root-cause wording bounded              PASS

## 8. Formal status

    B4 hash/integrity              PASS
    B4 source provenance           PASS
    B4 matrix coverage             PASS
    B4 coarse exception observation PASS
    B4 dynamic observation points  PASS (runtime-hash-bound, live-verified)
    B4 formal status               FORMAL PASS
    B5                             UNLOCKED (was LOCKED pending B4 dynamic proof)

## 9. Evidence package contents

    report                               this file
    offset_map.json                      runtime-hash-bound observation map
    runtime/mida_antidebug_runtime.dll   exact observed runtime artifact
    runtime/mida_antidebug_runtime.pdb   exact PDB (symbol source)
    authority/manifest.json              authority manifest (digest befd3867...)
    authority/provenance.json            authority provenance
    helpers/                             b1/b2/b4 test binaries
    attempts/<20 dirs>                   raw timelines, run_meta, stderr/out, evidence
    adr7b_b4_binding_correction_build_provenance.json
    adr7b_b4_binding_correction_matrix_summary.json
    adr7b_b4_binding_correction_evidence_manifest.json
    adr7b_b4_binding_correction_root_manifest.json
    adr7b_b4_binding_correction_final_manifest.json
    adr7b_b4_binding_correction_final_seal_manifest.json

Prior requal package (adr7b_b4_requal) is retained read-only and marked
SUPERSEDED_RUNTIME_OFFSET_BINDING (see SUPERSEDED.md).


## 9. Evidence correction (ADR7-B4-CONTROL-COUNT-1)

An audit of the sealed package found the standalone observer counter field
`exceptions_0xc0000409` in c1 benign-control timelines was computed from the
total exception count (`exceptions_seen`) instead of counting only real
`0xc0000409` exceptions, so the benign 0x80000003 debug break inflated it to 1.
The fix (commit e9ffc8b, mirrored as 99f578da in the main repo) adds a dedicated
`c0000409_seen` counter. The c1 controls were re-run with the fixed observer
binary (helpers/b4_dynamic_observer.exe sha256 00bfadce...):

    c1_benign_passive_1: exceptions_0xc0000409=0 obs_hits=0 int29_hits=0 b1=PASS
    c1_benign_passive_2: exceptions_0xc0000409=0 obs_hits=0 int29_hits=0 b1=PASS
    c1_benign_passive_3: exceptions_0xc0000409=0 obs_hits=0 int29_hits=0 b1=PASS

origin_macro_noobs_1 was also re-run (crash evidence regenerated at 01:56Z);
its evidence is consistent (0xc0000409 @ 0x2e816, fail-closed, exit 1). All
manifests (evidence/root/final/seal) and SEAL_HASH.txt were regenerated over
the final disk state; the hash chain re-verifies clean (114/114 files).


## 10. Evidence consistency correction (ADR7-B4-EVIDENCE-CONSISTENCY-1)

An audit of the sealed package (2026-08-20) found a stale evidence conflict in
`attempts/origin_macro_noobs_1`: `run_meta.json` recorded
second_chance=0xc0000409 @ 0x2e816 while `mida_antidebug_failure.evidence.json`
was an empty record (exception_code=null, failure_state=DependencyUnavailable,
sequence=1). Cross-checks showed the on-disk evidence JSON, the evidence
manifest entry, and the concurrent-packaging backup manifest entry all had
different SHA256 hashes - the file had been rewritten and no trusted original
remained. Per plan, the attempt was re-run from the same CLI/runtime/source
revision instead of hand-editing JSON.

### 10.1 Helper baseline decision (P1)

The original helpers directory was a mixed batch (b1/b2 built 2026-08-19
16:18Z, b4 built 18:15Z) whose b1/b2 hashes (2b9e0250/c95ab3ae) could NOT be
reproduced from any known source revision (2abde0d/b2ae591/99f578d) with the
recorded toolchain (rustc 1.97.1 MSVC); the recorded build commands in the
original build_provenance.json do not produce the recorded hashes. Decision
(recorded in D:\MidaVault\scratch\adr7b4_p1_baseline_decision.json):

    adopt out_release_adr7b4 as the final helper baseline:
      HEAD=99f578da4f366d94211c3707e7a19de9740e2e14
      rustc 1.97.1 (8bab26f4f 2026-07-14), MSVC
      rustc --edition 2021 -C opt-level=3 -C debuginfo=2
      b1_benign_host_full.exe sha256 473e0fc8... (153,600 B)
      b2_debugger_attach.exe   sha256 49015f84... (147,456 B)
      b4_dynamic_observer.exe  sha256 a47995bb... (161,792 B)

Controls c1/c2 use these helpers, so all six control attempts were re-run with
the new binaries (2026-08-20 ~04:15-04:17Z). Target matrix attempts
(noobs/passive/active) do not use b1/b2/b4 (CLI + runtime only) and were not
re-run except origin_macro_noobs_1..3 (see 10.2).

### 10.2 origin_macro_noobs_1..3 re-run (P2)

origin_macro_noobs_1..3 were re-run with the same CLI
(target\debug\mida-cli.exe), same runtime (ae42901e...), same source revision
(99f578d), mode=none. All three now record a complete, internally consistent
failure evidence:

    exit_code=1 (fail-closed)   decision=fail-closed
    failure_state=DependencyVerified   fail_code=AntiDebugRuntimeUnavailable
    exception_code=0xc0000409 (3221226505)   first_chance=false
    faulting_module=mida_antidebug_runtime.dll
    faulting_module_rva=0x2e816
    run_meta.second_chance matches evidence (0xc0000409 @ 0x2e816)
    sample_sha256=1af62999... (unchanged)

### 10.3 Re-seal

All manifests (evidence/root/final/seal) and SEAL_HASH.txt were regenerated
from a fresh disk scan over the final state (helpers replaced, noobs_1..3 and
c1/c2 re-run). The hash chain re-verifies clean (115/115 files, 0 mismatch).
