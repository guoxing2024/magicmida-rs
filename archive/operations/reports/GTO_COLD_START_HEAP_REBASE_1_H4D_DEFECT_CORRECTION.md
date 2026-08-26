# GTO-COLD-START-HEAP-REBASE-1 — H4-D PARSER/NORELOC DEFECT CORRECTION (GTO-H4-D-DES)

> status: P1-P4 DONE (commit 07e8f46); P3 overlay written; P5/P6 PENDING
> 总指挥 independent audit result: H4-D = BLOCKED_BY_CONFIRMED_PARSER_AND_NORELOC_DEFECT
> old LIVE-AUTHORIZATION-1 = SUPERSEDED; H5 = LOCKED; ADR7 = FROZEN / 17/17 PASS

## 1. Confirmed defects

### 1.1 UNWIND handler-slot alignment (P1) — fn78
x64 UNWIND_INFO layout: the optional handler/chain slot is placed on a
**4-byte-aligned boundary** after the unwind codes:

    slot_offset = UNWIND_INFO_HEADER_SIZE + align_up(count_of_codes * 2, 4)

The pre-fix code read the slot at:

    slot_offset = UNWIND_INFO_HEADER_SIZE + count_of_codes * 2     // WRONG

For odd count_of_codes (e.g. 13), the codes span 26 bytes but the slot is
at +28 (2 padding bytes inserted). The wrong read took bytes from the
padding + first 2 bytes of the real slot → misaligned garbage.

fn78 actual result (总指挥 raw reparse):
- CountOfCodes = 13
- wrong read = 0x6ee80000 (misaligned)
- correct read = 0x00106ee8 (inside an executable section)

The 112/375 "out-of-range handler" observations were this defect, NOT
Themida obfuscation. The obfuscation inference is FALSIFIED.

### 1.2 CHAININFO + handler flag combos (P1)
0x05/0x06/0x07 (CHAININFO combined with EHANDLER/UHANDLER) are invalid on
x64 (a chain entry must not carry its own handler). The pre-fix
ALLOWED_UNWIND_FLAGS allowed 0x00..0x07; now only {0,1,2,3,4} are valid,
and the combos fail closed as InvalidFlags in both parsers.

### 1.3 RELOCS_STRIPPED preservation (P2)
header_patch.rs unconditionally cleared IMAGE_FILE_RELOCS_STRIPPED. Only
the shrink path rebuilds .reloc; no-shrink must preserve the protected
input's genuine no-reloc state (directory absent + stripped preserved).
Clearing it fabricated relocation capability the candidate does not have.

## 2. Corrections applied (commit 07e8f46)

| file | change |
|---|---|
| exception_observation.rs | align_up_4 for slot offset + E13 span; flags {0..4}; tests |
| exception_final.rs | same alignment in independent decoder; flags {0..4}; tests |
| header_patch.rs | RELOCS_STRIPPED clear gated on opts.shrink |
| exception_evidence.rs | NoRelocFinalState full reparse; runtime/final mismatch fail-closed on all axes |
| post_loop.rs | candidate PE reparse for the full final no-reloc state |

## 3. Static acceptance (P4) — all green

- mida-pe lib: 971 passed / 0 failed (incl. 7 new h4d_* tests)
- mida-cli lib: 321 passed / 0 failed (1 pre-existing ignored)
- ADR7 verifier: 17/17 PASS (frozen, untouched)
- fmt: clean

New tests:
- h4d_odd_count_of_codes_handler_alignment_fn78_regression (odd 13,
  padding trap byte 0xcc, aligned slot read)
- h4d_even_count_of_codes_handler_no_padding (even 4, no padding)
- h4d_chaininfo_with_handler_is_invalid_flags (0x05 fails closed)
- h4d_final_* (same on the independent final decoder)
- h4d_final_runtime_function_12_byte_tuple (full 12-byte RUNTIME_FUNCTION)

## 4. Evidence status (P3)

- correction overlay: H4D_exception_no_reloc/correction_overlay_parser_defect.json
- layout_A/B/C layout_status.json: INVALIDATED_FOR_H4D_ACCEPTANCE/PARSER_DEFECT
- build_attestation_reference.json: SUPERSEDED_BY_PARSER_DEFECT_CORRECTION
- original evidence bytes preserved; no old records deleted

## 5. Pending (need 总指挥)

- P5: independent review of design/code/tests → issue
  GTO-H4-D-LIVE-AUTHORIZATION-2 → new build attestation
- P6: fresh correction evidence root; re-run A/B/C (3/3 exception
  sidecars prerequisite_passes=true; no-reloc directory absent +
  stripped preserved + dynamic=false + runtime=preferred)
- Until then: NO layout_B/C runs, H5 stays LOCKED
