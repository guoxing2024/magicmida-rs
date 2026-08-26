# GTO-COLD-START-HEAP-REBASE-1 — H4-C Report: TLS directory capture & evidence COMPLETE

> status: H4-C DONE — TLS evidence verified on 3 independent ASLR layouts
> input: pinned manifest rev 2 sample (11473d2e…), has_tls=true
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4C_tls\layout_{A,B,C}\
> env: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, no bypass/semantic-repair
> commits: 19ff1f6 (design), this report; authorized-head 19ff1f6
> design: docs/GTO_COLD_START_HEAP_REBASE_1_H4C_TLS_DESIGN.md

## 1. What was delivered

TLS directory capture, candidate validation, and complete evidence for the
GTO cold-start candidate, satisfying Acceptance gate #7 (TLS basic
structure and bounds). The implementation was already present across three
paths (design §2); Phase 4 verified it live on 3 fresh ASLR layouts.

## 2. Acceptance-gate verification (work order criteria)

| # | criterion | layout_A | layout_B | layout_C |
|---|---|---|---|---|
| 1 | exit 0 (3 layouts) | 0 | 0 | 0 |
| 2 | sidecar tls_complete | true | true | true |
| 3 | callbacks match runtime | 4/4 | 4/4 | 4/4 |
| 4 | independent decoder | pass | pass | pass |
| 5 | ADR7 17/17 | PASS | PASS | PASS |
| 6 | mida-pe 951/0 | PASS | PASS | PASS |

## 3. Runtime observation (identical across layouts — static TLS)

- directory_present=true, PE32+, ptr_size 8
- directory_rva=0x15c2e10 (22818320), size=40
- start=0x15a0190 end=0x15a2f30 index=0x180490 callbacks=0x15c2e38
- callbacks: [0x1728972(.rdata2), 0x60a0(.text), 0x10538c(.text),
  0x105474(.text)] + 0 terminator — ALL in static sections (no heap-rebased
  targets; SMR-style resolution NOT needed for this sample)
- null_terminated=true, zero_fill=0, characteristics=0x500000

## 4. Candidate verification (independent decoder)

parse_final_candidate (PeHeader reparse of candidate file bytes):
- final callback_rvas IDENTICAL to runtime (order preserved)
- preservation: all_preserved=true, blockers=[] (each layout)
- prerequisite_passes=true (each layout)
- sidecar schema mida.oreans-tls-evidence/v1, fail-closed write policy

## 5. Dump statistics (cross-layout)

| field | A | B | C |
|---|---|---|---|
| regions_total/required | 319/319 | 319/319 | 319/319 |
| bytes_captured | 810744 | 678360 | 680600 |
| pointer_slots/fixups | 10779 | 11282 | 8748 |
| resolver_count | 1821 | 1817 | 1714 |
| unresolved_required | 0 | 0 | 0 |
| dump size (B) | 48755712 | 48649216 | 48522240 |
| sections | 12 | 12 | 12 |

Layout-dependent capture volume, identical structural outcome.

## 6. Non-claims

- NOT product 1.0; NOT perfect unpack; candidate NOT acceptance-verified
  (R0B/loader smoke/behavior are H5 external gates)
- TLS callbacks' runtime *semantics* not executed (observation-only)
- No TLS callback observed into heap-rebased memory; such a case would
  fail closed (preservation blocker), never silently accepted
- No bypass; ADR7 frozen; Oreans gate untouched; no samples/binaries committed
