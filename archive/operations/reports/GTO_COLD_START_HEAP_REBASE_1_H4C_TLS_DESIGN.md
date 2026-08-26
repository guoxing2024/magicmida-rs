# GTO-COLD-START-HEAP-REBASE-1 — H4-C Design: TLS directory capture, rebuild & evidence

> status: DESIGN — live validation pending authorization (Phase 4)
> input: pinned manifest rev 2 sample (11473d2e…), has_tls=true (BOUNDARY.md L27)
> baseline: HEAD dd737a5 (H4-B COMPLETE); mida-pe 951/0; ADR7 17/17 PASS
> scope: GTO-COLD-START-HEAP-REBASE-1 ledger (ADR7 frozen)

## 1. Objective

Deliver TLS directory capture + complete evidence for the GTO cold-start
candidate through Acceptance gate #7 (TLS basic structure and bounds), with
the fail-closed semantics and evidence binding of the ADR7-B5 standard.

## 2. Current-state analysis (what already exists)

The H4-B run2 pipeline already produced a TLS evidence sidecar with
prerequisite_passes=true. Three independent code paths exist:

### 2.1 Path A — GTO dump_process (byte-preserve) [primary]
- `dump_process` line 399: `observe_tls_runtime` called BEFORE any header
  patch/shrink/sanitize (dump boundary) — immutable runtime evidence.
- TLS data directory bytes are preserved in-place in .rdata2 (dump keeps
  host sections; .boot/.import appended after). Verified on H4B run2:
  - dd[9] TLS RVA 0x15c2e10 size 40 (matches runtime observation)
  - start=0x15a0190 end=0x15a2f30 index=0x180490 callbacks=0x15c2e38
  - callbacks [0x1728972(.rdata2), 0x60a0(.text), 0x10538c(.text),
    0x105474(.text), 0(TERM)] — all in static (non-heap) sections
  - `compare_runtime_final` preservation all_preserved=true
- `validate_bootstrap_contract` (dump_process line 2114) binds tls_rva to
  the .boot contract.

### 2.2 Path B — pure_rebuild (R1-D/E adapter)
- `plan_from_host_dump` carries host data directories via
  `fallback_data_directories` (rebuild.rs line ~590: fallback applies where
  typed builders left zeros, TLS index 9 included).
- `preserve_section_vas=true` keeps TLS-referenced content RVA-valid.
- `PureRebuildParitySnapshot` compares tls_rva host vs pure.

### 2.3 Path C — typed TlsDirectoryBuilder rebuild
- `crate::tls::TlsDirectoryBuilder` (pe32/pe32_plus, template_data,
  callback_rvas) → `plan.tls` → `.tls` section + dd[9] (rebuild.rs
  line 582/614). Tests: rebuild_with_tls_sets_directory,
  rebuild_tls_arch_mismatch_errors.

## 3. Evidence chain (ADR7-B5 standard)

`write_tls_evidence` (cli/unpacker/tls_evidence.rs) builds the sidecar:

- runtime:  TlsObservationReport → RuntimeTlsEvidence (directory_present,
  directory_rva/size, start/end/index/callbacks, callback_slots with
  status Resolved/ZeroTerminator/NonExecutable, null_terminated, blockers)
- final:    parse_final_candidate — INDEPENDENT decoder (PeHeader reparse)
  reading the candidate file bytes, fail-closed on partial tuples,
  non-raw-backed, out-of-image, truncated, reversed ranges
- compare:  preservation per field (PE kind, pointer size, presence,
  directory RVA/size, raw range, index, callbacks RVA + list/order,
  NULL terminator, zero-fill, characteristics)
- gate:     prerequisite_passes = blockers.empty && all_preserved
- write:    FAIL-CLOSED — a sidecar with any blocker is refused
  (`refusing to write TLS evidence sidecar`); existing valid sidecar is
  never replaced by a failing one
- negative: directory_present=false on both sides → complete negative
  observation (both_absent → all preserved, no blockers)

## 4. Fail-closed semantics (kept)

| condition | behavior |
|---|---|
| TLS dir absent | directory_present=false complete negative observation, NOT failure |
| callbacks read failure | blocker recorded, is_complete()=false, sidecar refused |
| non-NULL-terminated array | blocker (null_terminator_preserved=false) |
| callback pointer to non-executable | slot status NonExecutable, mismatch → blocker |
| partial (RVA,size) tuple | blocker (parse_final_candidate) |
| raw range reversed/out-of-image | blocker |

## 5. GTO-specific risk assessment

- callbacks point to static sections (.text/.rdata2) in observed layouts —
  NO heap-rebased callback targets observed. If a future layout produces a
  callback into heap-rebased memory, preservation fails closed (callbacks
  mismatch blocker) — no silent acceptance. SMR-style resolution (H4-A)
  is NOT needed for TLS callbacks on this sample (static targets).
- TLS index slot at 0x180490 (.data) preserved; raw-backed check applies.
- Template data range [0x15a0190, 0x15a2f30) fully inside .rdata2.

## 6. Acceptance-gate mapping (work order acceptance criteria)

| # | criterion | status |
|---|---|---|
| 1 | 3 ASLR layouts exit 0 | H4B run2: 3/3 (re-verify under H4C_tls evidence dir) |
| 2 | sidecar tls_complete=true | H4B run2: runtime_evidence_complete=true |
| 3 | callbacks count/RVA match runtime | verified (4 + terminator, order) |
| 4 | candidate dir via independent decoder | parse_final_candidate (PeHeader reparse) |
| 5 | ADR7 17/17 | PASS (baseline) |
| 6 | mida-pe 951/0 | PASS (baseline) |
| 7 | evidence in H4C_tls/layout_{A,B,C} | pending Phase 4 (authorization) |
| 8 | design + report docs | design: this file; report: pending |
| 9 | ledger BOUNDARY.md §8 H4-C COMPLETE | pending |

## 7. Phase plan

- Phase 1-3 (offline, NO new code needed — analysis above proves existing
  implementation covers the work order): design doc + gap verification.
- Phase 4 (needs authorization): 3 fresh ASLR layouts under
  D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4C_tls\layout_{A,B,C}\,
  same controller contract as H4-A/H4-B (MIDA_GTO_NO_BYPASS=1,
  MIDA_GTO_OBSERVATION_ONLY=1, authorized-head pinned, attestation).
- Phase 5: report + ledger + commit chain.

## 8. Out of scope

- Exception/unwind tables (H4-D), base relocation (H4-D; sample
  has_relocations=false), pure candidate output (H5), TLS callback
  *semantic* execution (runtime behavior — H5 acceptance).
