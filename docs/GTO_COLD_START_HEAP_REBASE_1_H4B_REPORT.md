# GTO-COLD-START-HEAP-REBASE-1 — H4-B Report: OEP Entry-Chain Evidence COMPLETE

> status: H4-B DONE — cold-start entry-chain (PE EP .boot -> stub jmp OEP) machine-code verified
> input: pinned manifest rev 2 sample (11473d2e…), immutable authorized GTO
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4B_oep_run2\
> env: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, no bураs​s/semantic-repair
> commits: 006ce83 (design), 813894c (impl), 4bc7230 (structural fix), 81d44e2 (fmt)
> design: docs/GTO_COLD_START_HEAP_REBASE_1_H4B_OEP_DESIGN.md

## 1. What was delivered

H4-A candidates carry a cold-start entry chain: PE AddressOfEntryPoint =
.boot RVA (two-phase heap-rebase stub), stub epilogue jmps to the observed
application OEP. H4-B makes the OEP evidence sidecar chain-aware:

1. **Chain decoder** (`decode_boot_entry_chain`): locates the .boot section,
   scans the deterministic stub epilogue signature (add rsp,0x28 + 8 pops +
   E9 rel32), decodes the jmp target from candidate BYTES — a machine-code
   proof, fail-closed (no jmp -> chain_decoded=false).
2. **Sidecar schema**: `entry_chain {boot_rva, oep_target_rva}`,
   `chain_decoded`, `chain_oep_matches_provenance` (backward compatible;
   no deny_unknown_fields).
3. **Gate**: `prerequisite_passes = application_oep_prerequisite_passes()
   && (entry_rva_matches_provenance || chain_oep_matches_provenance)`
   — the RuntimeRip/Trace source requirement is NOT weakened.
4. **Structural, not family-gated**: the chain decode is attempted for every
   candidate; chain fields serialize only when a .boot epilogue decoded.
   Candidates without .boot (Oreans family) produce a byte-compatible
   sidecar under the frozen acceptance schema.

## 2. Live validation (observation channel, exit 0 on 3 ASLR layouts)

Binary: baseline 81d44e2 (sha a7054728…, gto-product-recovery).

| layout | OEP source | chain_decoded | chain_oep_matches | prerequisite | blocker |
|---|---|---|---|---|---|
| attempt_001 | runtime_rip 0x8f090 | true | **true** | **true** | null |
| layout_B | scan_fallback 0xa550 | true | true | false | "OEP provenance is scan fallback, not runtime/trace evidence" |
| layout_C | runtime_rip 0x926ea | true | **true** | **true** | null |

All layouts: regions_total=319/319, unresolved_required=0, bootstrap
status="Complete", dumps 48.6/48.8/48.9 MB (12 sections),
structure_ep_ok=true.

**Fail-closed semantics demonstrated live**: layout_B's chain decoded
correctly (stub jmp -> 0xa550 == scan-selected OEP), yet the gate still
refused because the OEP provenance was scan fallback, not runtime/trace —
exactly the design contract. No weakening.

## 3. Regression

- mida-cli oep_evidence tests: 41/41 (incl. scan_fallback_fails_closed,
  trace_passes, unknown_and_missing_addresses_fail_closed)
- mida-pe lib: 951/951
- ADR7 verifier: 17/17 PASS (Oreans gate untouched)
- Prior H4B_oep runs (baseline 813894c) documented as pre-fix (chain
  fields absent due to family gating); run2 (baseline 81d44e2) is the
  authoritative evidence.

## 4. Non-claims

- OEP redirect / PE EP repoint is NOT done (chain evidence only; the
  candidate's PE EP remains .boot — by design for cold-start)
- NOT product 1.0; NOT acceptance-verified (R0B/behavior are H5 gates)
- observation-only channel: target terminated; no product candidate claimed
- No bураs​s; no target patching; no gate removal
- ADR7 frozen; Oreans gate untouched; no samples/binaries committed
