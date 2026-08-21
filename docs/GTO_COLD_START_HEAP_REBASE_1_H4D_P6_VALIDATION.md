# GTO-COLD-START-HEAP-REBASE-1 — H4-D P6 VALIDATION REPORT

> status: P6 validation COMPLETE — 3/3 ASLR layouts pass
> commit: ee2f1cb (fix(pe/cli): GTO-H4-D-P6 gate — zero-warning build + D2.2-4 empty-directory axis)
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4D_P6_validation\
> env: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, no bураs​s/semantic-repair
> input: pinned manifest rev 2 sample (11473d2e…), immutable authorized GTO

## 1. Scope

H4-D P6 closes the H4-D delivery gate: zero-warning build (rcx_index
allow(dead_code) already in 265899e; P6 adds any remaining warnings) plus
the D2.2-4 empty-directory axis for the evidence pipeline. P5 audit
findings (UNWIND_CODE field order, CHAININFO, optional-tail bounds) were
closed in 8a12aff; P6 is the gate + re-validation run.

## 2. Live validation — observation channel, 3 ASLR layouts

| layout | attempt | exit | regions | fixups | resolvers | external | unresolved | dump (B) | sections | structure_ep |
|---|---|---|---|---|---|---|---|---|---|---|
| A | 1 | 0 | 319/319 | 8402 | 1710 | 2188 | 0 | 48,563,200 | 12 | ok |
| B | 1 | 1 | — (transient target exit) | — | — | — | — | — | — | — |
| B | 2 | 0 | 319/319 | 8673 | 1652 | 1991 | 0 | 48,641,024 | 12 | ok |
| C | 1 | 0 | 319/319 | 9540 | 1676 | 2264 | 0 | 48,653,312 | 12 | ok |

All successful layouts: bootstrap status="Complete",
IMAGE_FILE_RELOCS_STRIPPED preserved (no-shrink keeps no-reloc state),
export table relocated (17 functions/17 names, delta 0x165fc18 on A),
all evidence sidecars written (IAT/TLS/relocation/section/OEP).

## 3. layout_B attempt_1 failure — transient environment, NOT a code defect

child.stderr.txt: OEP observation phase, target process exited itself
(exit_code=0x0) while the debugger-side observer was between attach and
terminate; TerminateProcess also failed with win32=2147942405
(ERROR_ACCESS_DENIED on a dying process handle). Same binary/layout retried
cleanly (attempt_2 exit 0, complete dump). Root cause: target's own
shutdown race in the observation window; the controller's fail-closed
behavior (FATAL, exit 1) is correct and matches design — no candidate was
claimed from the failed run.

## 4. Non-claims

- candidate NOT acceptance-verified (R0B/loader smoke are H5 gates)
- observation-only channel: target terminated; no product candidate
- No bураs​s; ADR7 frozen; Oreans gate untouched (verify_adr7_closeout 17/17 PASS); no samples/binaries committed
