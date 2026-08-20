# RouteY_R1_GTO_LAUNCHER_SIMPLEHEAP_TAGGED_VALUE_PRODUCER_RECOVERY_1 — Result

**Status:** `RouteY_R1_GTO_LAUNCHER_SIMPLEHEAP_TAGGED_VALUE_PRODUCER_RECOVERY_1_ReviewRequested`
**Mode:** OFFLINE / CONTROLLED REVERSE ENGINEERING / EVIDENCE FIRST (static; no dynamic observation, no sample rerun)
**Date:** 2026-08-14T11:18:25.588Z

## Producer write-site: RECOVERED (code-level, cross-variant)

Target 4d5770af's .text is packed (entropy 7.998), but two recovered AHK runtime images of the same
launcher family (A08F1A2F, dcc411af) have decoded .text (entropy 6.53) with the full tag-store idiom:

- Dispatcher rva 0xC4AE0: `mov ecx,[r13+rax*4+0xC603C]; add rcx,r13; jmp rcx` (type dispatch)
- INTEGER tag: rva 0xC4AE8 `or byte [rdi+4], 1`
- **FLOAT bit (0x02) writes: 5 OR sites** (rva 0x20076/0x38E77/0x38FE7/0xA5914/0xA59E7)
- Cross-variant: dcc411af has identical idiom (16 OR / 21 movzx / 14 cmp)

## Consumer: RECOVERED

- FLOAT bit test rva 0xD6BFE: `test byte [rcx+4], 0x02; jz +0x0E`
- 21 movzx tag reads + 48 test sites + jump-table dispatch (rva 0xC603C)

## Encoding model (code-level crosschecked)

```text
8-byte AHK Value slot:
  bytes[0..3] = payload (int32 or IEEE754 float32 bits)
  byte[4]     = TYPE BITFIELD (OR-constructed): 0x01 INT, 0x02 FLOAT, 0x04 STR, 0x08 OBJ
  byte[5]     = len/subtype; bytes[6..7] = pad
```

## 0x2ffeeffee = AHK FLOAT-typed value slot

Tag byte[4]=0x02 (FLOAT bit), payload 0xEEFFEEFF (IEEE754 float32 → NaN/huge negative), runtime-computed
(0 static hits). **NOT a pointer.** Remains unknown+required until evidence-exclusion is separately authorized.

## Caveats (honest)

1. Recovered images are different variants; tag idiom is **family-level** confirmed; target's own code not
   directly observed (.text packed).
2. Type enum from AHK v2 source knowledge + corpus + code consistency.
3. 0x2ffeeffee's individual producer instruction not located; the tag-construction idiom IS located.

## Deliverables

18 files in `D:\MidaVault\lab\analysis\route_y_r1_gto_launcher_simpleheap_tagged_value_producer_recovery_1_20260814T120000Z\
` (13 payloads + manifest/sidecar/selfcheck/freeze_before/freeze_after).
Manifest SHA `df467f7b…`, selfcheck PASS, strict order verified.

## Boundaries

No source change, no rebuild, no sample rerun, 0 dynamic attempts, no production driver, no A6, no
scheduled task, no MIDA_GTO_BYPASS, no module resolver / heap-hole / slab normalization / evidence
exclusion implemented, no value-specific rule, no commit/push/git add, no historical evidence-root overwrite.
