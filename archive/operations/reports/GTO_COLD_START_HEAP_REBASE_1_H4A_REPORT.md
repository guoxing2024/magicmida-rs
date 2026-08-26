# GTO-COLD-START-HEAP-REBASE-1 — H4-A Report: Stable Module Registry (SMR) COMPLETE

> status: H4-A DONE — ViaStableBinding stub execution live-verified; bootstrap_install crossed
> input: pinned manifest rev 2 sample (11473d2e…), immutable authorized GTO
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4A_smr\
> env: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, no bураs​s/semantic-repair
> commits: 7d3201d (design), 40aa715 (impl), f6c3434 (ledger), 265899e (zero-warning)
> design: docs/GTO_COLD_START_HEAP_REBASE_1_H4A_SMR_DESIGN.md

## 1. What was delivered

The cold-start **Stable Module Registry (SMR)**: the two-phase .boot stub now
executes ViaStableBinding resolvers — module-attributed pointers WITHOUT an
IAT slot (H2's old_module_base -> new_module_base primitive) — by walking the
target process's OWN PEB Ldr InLoadOrderModuleList:

- gs:[0x60] -> PEB ; PEB+0x18 -> Ldr ; Ldr+0x10 -> list head
- entry+0x30 DllBase ; entry+0x58/0x60 BaseDllName (UNICODE_STRING)
- ASCII case-insensitive UTF-16LE compare; resolved to new_base + module_rva
- unresolved module -> infinite loop (cookie stays 0; same fail class as
  Phase-1 alloc failure) — fail-closed preserved

No dump-time module state; no blanket module-delta patch; no gate removal.

## 2. Deliverables vs design §2

| deliverable | state |
|---|---|
| resolver table + name table schema (UTF-16LE, dedup) | DONE (encode/decode round-trip tested) |
| stub SMR walk (PEB Ldr, per-resolver lazy) | DONE (codegen disasm-tested) |
| fail-closed: unresolved module / bad name ref | DONE (simulate + decode tests) |
| simulate_runtime_rebase module_bases parity | DONE |
| ViaIat path unchanged | VERIFIED (existing tests green) |
| ViaExportMap | still no stub; fails closed (no instance) |

## 3. Live validation (observation channel, exit 0 on TWO ASLR layouts)

| field | attempt_001 | attempt_002 |
|---|---|---|
| controller exit | 0 | 0 |
| spawned / pid | true / 26020 | true / 4924 |
| regions_total / required | 319 / 319 | 319 / 319 |
| fixup_count | 8948 | 12006 |
| resolver_count | 1771 | 1795 |
| external | 2196 | 2389 |
| unresolved_required | 0 | 0 |
| bootstrap_install | status="Complete" (boot_rva 0x2d21000) | status="Complete" |
| dump written | 48559104 B, 12 sections | 48665600 B, 12 sections |
| candidate | structure_ep_ok=true (not acceptance-verified) | structure_ep_ok=true |
| observation evidence | candidate_created=false (research only) | same |

Both layouts: Runtime rebase summary status="Complete", all evidence
sidecars written (IAT/TLS/relocation/section/OEP), target terminated after
observation. The H2 terminal wall (bootstrap_install FAIL-CLOSED on
ViaStableBinding) is crossed.

## 4. Statistics note

- fixup_count/resolver_count differ between layouts (8948 vs 12006; 1771 vs
  1795) — ASLR-dependent capture volume (bytes_captured 703568 vs 661896),
  same structural outcome: unresolved_required=0, complete install.
- pointer_slots 8948/12006 vs H2's 10532: layout-dependent pointer
  population; the invariant is zero unresolved-required.

## 5. Non-claims

- NOT product 1.0; NOT perfect unpack; NOT OEP/TLS/exception-rebuild done
- candidate is NOT acceptance-verified (R0B/loader smoke/behavior are
  external gates, H5)
- observation-only channel: target terminated; no product candidate claimed
- No bураs​s; no target patching; no gate removal
- ADR7 frozen; Oreans gate untouched; no samples/binaries committed
