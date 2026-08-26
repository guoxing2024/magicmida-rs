# GTO-COLD-START-HEAP-REBASE-1 — H4-D P5 Correction Report

> status: P5 CORRECTIONS CLOSED — ready for independent re-audit
> correction: GTO-H4-D-P5-CORRECTION-1 (commit 8a12aff)
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4D_P5_validation\
> env: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, no bураs​s/semantic-repair
> H4-D status: BLOCKED_PENDING_P5_CORRECTION (unchanged; authorization is the
>   reviewer's call after re-audit — this report only presents evidence)

## 1. Corrections applied (all three audit findings closed)

### 1.1 UNWIND_CODE field order (final decoder)
The final decoder read byte[0] as UnwindOp/OpInfo and byte[1] as
CodeOffset — contradicting the runtime observer. Both parsers now use:

    byte[0] = CodeOffset
    byte[1] low nibble  = UnwindOp
    byte[1] high nibble = OpInfo

Regression tests: p5_runtime_final_code_field_order_parity and
p5_unwind_code_field_order / p5_final_unwind_code_field_order assert the
exact (0x05, 0x02, 0x04) decoding of a 05 42 slot in both parsers.

### 1.2 CHAININFO full 12-byte RUNTIME_FUNCTION
Previously only 4 bytes were read and BeginAddress was reused as
handler_rva. Now a complete 12-byte tuple is parsed:

    BeginAddress | EndAddress | UnwindInfoAddress

with per-field validation (Begin<End; all three RVAs inside SizeOfImage;
full read required). New ChainInfoObservation/ChainInfoStatus model is
exported through lib.rs and into the cli exception evidence sidecar.
handler_rva is EH/UH-only and is never derived from the chain tuple.

### 1.3 Optional-tail bounds (fail-closed truncation)
Span now = header + align_up(codes,4) + (EH/UH ? 4 : 0) + (CHAININFO ? 12 : 0).
A truncated tail (crossing SizeOfImage OR the raw-backed section span) is
CodesOutOfBounds. The final decoder's raw_span check covers the FULL span
(was: header 4 bytes only).

## 2. Negative tests added (all pass)

| test | checks |
|---|---|
| p5_unwind_code_field_order | byte[0]=CodeOffset, byte[1]=op/info |
| p5_chaininfo_full_12_byte_tuple | valid chain, handler_rva stays None |
| p5_chaininfo_tail_truncated_fails_closed | 12B tail crossing image → InvalidChain |
| p5_chaininfo_begin_not_less_end_fails_closed | Begin>=End → InvalidChain |
| p5_chaininfo_rva_out_of_image_fails_closed | chain RVA >= SizeOfImage → InvalidChain |
| p5_eh_handler_tail_truncated_fails_closed | 4B tail crossing image → CodesOutOfBounds |
| p5_final_* (same five on the final decoder) | same |
| p5_runtime_final_chaininfo_parity | field-for-field runtime==final (incl. chain) |
| p5_runtime_final_code_field_order_parity | code-field order identical |

## 3. Offline regression (layout_A original candidate)

Independent byte reparse with the corrected rules:

    RUNTIME_FUNCTION total:   4570  (0 invalid range, 0 begin>=end)
    EH/UH total:               375  (375 handler in-exec; 0 outside)
    OLD out-of-image handlers:   0  (was 112 — parser defect, not obfuscation)
    CHAININFO total:          1510  (1510 valid; 0 begin>=end; 0 OOR; 0 short)
    tail truncated:              0
    UNWIND_CODE slots:       20445  (matches auditor's independent count)

## 4. Live observation-channel validation (two ASLR layouts)

| field | attempt_001 | attempt_002 |
|---|---|---|
| controller exit | 0 | 0 |
| runtime function_count | 4570 | 4570 |
| final function_count | 4570 | 4570 |
| runtime/final unwind_infos | 4570 / 4570 | 4570 / 4570 |
| runtime/final CHAININFO | 1510 / 1510 | 1510 / 1510 |
| all_preserved | **True** | **True** |
| preservation blockers | [] | [] |
| handlers_in_executable | True | True |
| no-reloc state | preserved (directory absent, relocs_stripped) | same |
| evidence sidecar | exception_evidence.json (10.6 MB) | same |

The previously observed "UNWIND_INFO mismatch" preservation blocker is
gone in both layouts.

## 5. Suite status

    mida-pe lib: 985 passed / 0 failed
    mida-cli:    green (20+17+39+3+4+1)
    ADR7:        17/17 PASS (frozen)
    cargo fmt:   clean
    build attestation: baseline 8a12aff (commit of this correction)

## 6. Non-claims

- This report does NOT grant GTO-H4-D-LIVE-AUTHORIZATION-2 — that is the
  reviewer's call after independent re-audit.
- layout_B/C execution remains FORBIDDEN until authorization.
- H5 remains LOCKED. ADR7 remains FROZEN.
- Observation channel only; candidate_created=false; target terminated.
- No bураs​s; no target patching; no gate removal; no samples/binaries
  committed.
