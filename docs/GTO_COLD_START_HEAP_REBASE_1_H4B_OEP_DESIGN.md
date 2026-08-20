# GTO-COLD-START-HEAP-REBASE-1 — H4-B Design: OEP Entry-Chain Evidence

> status: DESIGN (H4-B scoped) — implementation follows in a separate commit
> ledger: GTO-COLD-START-HEAP-REBASE-1 H4-B (OEP entry-chain evidence)
> input: authorized immutable rev-2 vault object
>        sha256 11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86
> upstream: H4-A DONE (SMR executes ViaStableBinding; bootstrap_install crossed;
>           live-verified on 3 ASLR layouts — docs/GTO_COLD_START_HEAP_REBASE_1_H4A_REPORT.md)
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4A_smr\

## 1. Problem statement

H4-A candidates carry a cold-start entry chain: PE AddressOfEntryPoint =
.boot RVA (the two-phase heap-rebase stub), and the stub's epilogue jmps to
the observed application OEP after the completion cookie is written:

- layout_B candidate: final_entry_rva = 0x2d21000 (.boot), provenance RVA =
  0x8f054 (runtime_rip, application_oep=true, bootstrap_or_ambiguous=false)

The OEP evidence sidecar (crates/cli/src/unpacker/oep_evidence.rs) computes:

- entry_rva_matches_provenance = (provenance.rva == Some(final_entry_rva))
  = false (0x2d21000 != 0x8f054)
- prerequisite_passes = application_oep_prerequisite_passes() &&
  entry_rva_matches_provenance = false

The gate correctly fails closed: a cold-start candidate's PE EP is .boot by
design, so the naive "final entry must equal the provenance RVA" test cannot
pass for ANY correct cold-start candidate. This is not a code bug — it is a
semantic gap between the entry-chain model and the evidence contract.

## 2. H4-B scope

**Deliverable:** entry-chain OEP evidence — the sidecar records AND the gate
accepts the cold-start chain (PE EP .boot -> stub jmp OEP) with a decoded
machine-code proof, without changing the PE entry, without removing the
provenance prerequisite, and without weakening the RuntimeRip/Trace source
requirement.

**In scope:**

1. Sidecar schema extension: add
   - `entry_chain`: { boot_rva: u32, oep_target_rva: u32 } — the decoded
     .boot stub's final near-jmp target
   - `chain_oep_matches_provenance`: bool — decoded target == provenance RVA
   - `chain_decoded`: bool — the jmp was found and decoded from candidate bytes
   (Backward compatible: OepEvidenceSidecar has no deny_unknown_fields; the
   existing fields keep their exact meaning.)

2. Chain decoder: parse the candidate PE, locate the .boot section (by
   installed bootstrap metadata / section name), scan the stub blob for the
   final `jmp rel32` (the epilogue transfer after cookie write + reg clear +
   rsp restore + pop sequence), decode rel32 against the jmp address, and
   produce boot_rva + oep_target_rva. Fail closed: no jmp found -> chain
   evidence absent (chain_decoded=false).

3. Gate update (cli side only; Oreans acceptance gate untouched):
   `prerequisite_passes = application_oep_prerequisite_passes() &&
   (entry_rva_matches_provenance || chain_oep_matches_provenance)`
   with chain_oep_matches_provenance requiring chain_decoded == true.
   - entry_rva_matches_provenance remains the default OEP policy path
     (non-bootstrap candidates unchanged).
   - cold-start candidates pass ONLY with a decoded chain to the provenance
     RVA AND a RuntimeRip/Trace provenance.

**Out of scope (not designed here):**

- TLS callbacks/index/data rebuild (H4-C)
- exception/unwind rebuild, no-reloc handling (H4-D)
- pure PE candidate output (H4 final)
- Any change to the Oreans acceptance gate (crates/acceptance/…) — frozen

## 3. Why this is not a bypass

The gate change adds a STRICTER acceptance path, not a weaker one:

- provenance must still be RuntimeRip or Trace (application_oep=true,
  bootstrap_or_ambiguous=false) — scan_fallback stays fail-closed;
- the chain target is DECODED from the candidate bytes (machine-code proof),
  not taken from dump-time bookkeeping;
- the chain target must equal the provenance RVA exactly;
- the PE EP is not changed; no gate removal; no old-process state reuse.

A cold-start candidate that does not actually transfer to the observed OEP
(chain mismatch or no decodable jmp) keeps prerequisite_passes=false.

## 4. Chain decoder sketch

```
fn decode_boot_entry_chain(candidate_bytes: &[u8], boot_rva: u32)
    -> Option<(u32, u32)> // (boot_rva, oep_target_rva)
- parse PE headers (PeHeader::from_bytes)
- locate the section containing boot_rva (the .boot section)
- take the section's raw bytes; walk forward from the section start
- find the LAST `jmp rel32` (opcode E9) that is NOT inside the SMR helper
  region (the SMR helper also ends in a ret; its internal jmps are short
  targets). Use the known stub epilogue shape: after `add rsp, 0x28` and
  8 pops, an `E9 xx xx xx xx`. Decode rel32 relative to the address after
  the 5-byte jmp (boot_rva + offset + 5) to get oep_target_rva.
- fail closed (None) if no such jmp decodes
```

The emitted stub layout is deterministic (emit_two_phase_code), so the
epilogue jmp position is found by scanning for the unique sequence:
add rsp,0x28 ; pop r15..rbx (8 pops) ; E9 rel32. Tests decode the exact
stub bytes from emit_two_phase_code and assert the recovered target equals
original_entry_point.

## 5. Test plan

1. chain decoder unit tests: exact stub bytes -> recovered target == OEP;
   truncated/no-jmp bytes -> None (fail closed).
2. sidecar schema: new fields serialize/parse; old sidecar JSON (without new
   fields) still parses with defaults (chain_decoded=false).
3. gate: runtime_rip + entry match -> pass (unchanged); runtime_rip + chain
   match -> pass (new); runtime_rip + chain mismatch -> fail; scan_fallback
   + chain match -> fail (source gate unchanged).
4. Live: re-run observation channel (attempt_00x) on the authorized sample;
   layout_B-style run must produce prerequisite_passes=true.
5. Cross-layout repeat; evidence under H4B_oep/.

## 6. Ledger status

| item | state |
|---|---|
| H4-B design | THIS DOC |
| chain decoder | pending (separate commit) |
| sidecar extension | pending |
| gate update | pending |
| unit tests | pending |
| live validation | pending |

ADR7 frozen; Oreans gate untouched; no samples/binaries committed.
