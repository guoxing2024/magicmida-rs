# ADR7-B5-TLS-ROOT-CAUSE-ISOLATION-1 - debugger-side TLS scene capture report

> status: COMPLETE - TLS scene captured and classified on 6/6 target attempts
> generated: 2026-08-20
> parent: ADR7-B4-RUNTIME-BINDING-CORRECTION-1 (exact runtime binding, b2ae591)
> evidence dir: D:\MidaVault\lab\evidence\adr7b_b5
> runtime bound: ae42901ec940dfa95566dcf9e0787d1e2c9439d90e7c593ed3a803a4f9cdbb76 (PDB b8165cf8..., GUID DDCD43FD-2CFF-4242-85BF-39DC0ADB09E0 age 1)

## 1. Objective

Isolate whether the runtime panic path (panic -> panic_count::increase ->
LOCAL_PANIC_COUNT TLS slot -> int29 fail-fast) fails because of a TLS-context
problem in the target, or because of the panic source itself. The B4 matrix
(ADR7-B4-RUNTIME-BINDING-CORRECTION-1) proved the observer can dynamically
correlate the int29 fault (0xc0000409 @ 0x2e816) with the bound runtime; B5
extends the observer with a TLS scene snapshot at the fault moment.

## 2. New commits (on top of b2ae591)

    2e0995f  test(adr7): ADR7-B5-TLS-ROOT-CAUSE-ISOLATION-1 - debugger-side TLS scene capture
    0b26247  fix(adr7): ADR7-B5 F-B5-001/002 - TLS capture fail-closed classification and observed trigger/phase
    b656a82  fix(adr7): ADR7-B5 F-B5-003 - persist TLS snapshot in observer timeline
    6b8ff08  style(adr7): ADR7-B5 rustfmt - b5_tls_capture classify condition and import order
    99f578d  fix(adr7): ADR7-B4-CONTROL-COUNT-1 - standalone observer counts real 0xc0000409 exceptions

Scope: crates/core/src/{b5_tls_capture.rs (new), windows_debugger.rs,
adr7_b4_observer.rs, lib.rs} only - no docs/lab/cdb/disasm/temp files, no
sample copies, no Cargo.toml EOL dirt. HEAD 99f578d = matrix tree.

## 3. TLS scene capture design (see tls_capture_schema.json)

Per-exception capture (first/second chance) when the runtime is observed in
the target, reading from the faulting thread:

    TEB + 0x58            -> TLS array base (ThreadLocalStoragePointer)
    _tls_index (0x575b4)  -> module TLS index
    array[index]          -> TLS slot pointer
    slot + 0x18           -> LOCAL_PANIC_COUNT counter (u64)
    slot + 0x20           -> LOCAL_PANIC_COUNT in-panic flag (u8)
    VirtualQueryEx        -> slot page state/protect

Classification (F-B5-001 fail-closed): ANY capture error => capture_failed
(never an affirmative TLS verdict). Otherwise slot_absent / slot_invalid /
local_panic_count_pointer_corrupted / tls_slot_read_only / tls_slot_writable.
F-B5-002: capture_trigger and capture_phase record the OBSERVED exception
code and debug-event phase; a second-chance snapshot is a POST-FAULT capture
and self-describes as such. F-B5-003: the snapshot is persisted in the
timeline record (regression: a pre-TLS clone previously dropped it).

## 4. Live matrix (12 attempts)

| group | attempts | runtime binding | panic | TLS capture | classification |
|---|---|---|---|---|---|
| benign host+runtime (c1-style) | 3 | n/a (standalone obs) | none | none | clean (no false positive) |
| debugger+benign+runtime (c2-style) | 3 | n/a (b2 attach) | none | n/a | clean (exception_0xc0000409=0) |
| origin_macro+runtime | 3 | Verified | 0xc0000409 @ 0x2e816 | 1 each | tls_slot_writable (3/3) |
| lunlun_software+runtime | 3 | Verified | 0xc0000409 @ 0x2e816 | 1 each | tls_slot_writable (3/3) |

All 6 target attempts show the SAME scene: TLS slot page MEM_COMMIT +
PAGE_READWRITE, LOCAL_PANIC_COUNT counter=1 readable, in-panic flag=0,
classification tls_slot_writable, capture_trigger 0xc0000409,
capture_phase second_chance.

## 5. B5-C verdict (dynamic correlation)

Correlation requirements (all satisfied):
- same PID/TID: the TLS snapshot tid equals the exception record tid (verified in all 6 attempts);
- monotonic ordering: capture happens in the exception handler of the same
  debug event (seq N exception -> seq N snapshot), timeline order preserved;
- exact binding: runtime_binding=Verified (AE42901E) in all 6 timelines.

VERDICT: the TLS context is HEALTHY at the fault moment in all 6 target
attempts (slot writable, counter readable, flag 0). The fail-fast is NOT
caused by a TLS-context problem in the target. Per B5-C rules the failure
PIVOTS to the panic-source/payload/FFI-env trigger: the panic itself (and
its source/payload propagation into panic_count::increase) is the
correlated cause, not the TLS slot.

Instrumentation-sensitivity: benign controls show zero false positives
(no TLS capture without a panic; obs_hits=0, int29_hits=0). Target behavior
matches the B4 baseline (same 0xc0000409 @ 0x2e816, same sample hashes).
No instrumentation-sensitive divergence observed.

## 6. Gates

    instrumentation committed (B5 chain on b2ae591)     PASS
    per-attempt runtime binding recorded                PASS (6/6 Verified)
    per-attempt TLS metadata recorded                   PASS (6/6 snapshots)
    panic-int29 timeline recorded                       PASS (6/6 0xc0000409@0x2e816)
    exception context recorded                          PASS (evidence json + timeline)
    cleanup recorded                                    PASS (terminate_and_wait ok in stderr)
    benign controls clean (no false TLS)                PASS (6/6)
    protected samples reference-only                    PASS (paths only, no copies)

## 7. Artifacts

    tls_capture_schema.json            capture schema + classification rules
    offset_map.json                    runtime-hash-bound observation map
    runtime/mida_antidebug_runtime.dll exact bound runtime artifact
    runtime/mida_antidebug_runtime.pdb exact PDB (symbol source)
    authority/manifest.json            authority manifest (digest befd3867...)
    authority/provenance.json          authority provenance
    helpers/                           b1/b2/b4 test binaries
    attempts/<12 dirs>                 raw timelines, run_meta, stderr/out
    adr7b_b5_build_provenance.json     committed instrumentation provenance
    adr7b_b5_matrix_summary.json       matrix summary
    adr7b_b5_evidence_manifest.json    evidence manifest
    adr7b_b5_root_manifest.json        root manifest
    adr7b_b5_final_manifest.json       final manifest
    adr7b_b5_final_seal_manifest.json  seal manifest
