# GTO-COLD-START-HEAP-REBASE-1 — H4-D LIVE WALL (deterministic)

> status: H4-D live matrix BLOCKED — unwind-handler obfuscation wall
> authorization: GTO-H4-D-LIVE-AUTHORIZATION-1 (approved ce4c370; implementation delivered at c2cc9e8)
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4D_exception_no_reloc\
> env: MIDA_GTO_NO_BYPASS=1, MIDA_GTO_OBSERVATION_ONLY=1, no bураs​s/semantic-repair

## 1. Wall facts (layout_A, live run, attempt_001)

- Dump pipeline SUCCEEDS: 48,948,224 B candidate, 12 sections, all prior
  sidecars (IAT/TLS/relocation/section/OEP) written, exit 0 through dump.
- NEW H4-D exception evidence sidecar REFUSED (fail-closed):
  runtime: unwind handler RVA outside executable sections
  final:   unwind handler RVA outside executable sections
  preservation: UNWIND_INFO mismatch
- Exception directory: 4570 RUNTIME_FUNCTION entries; 375 carry
  EHANDLER/UHANDLER flags; **112 handlers > SizeOfImage** (12 unique
  obfuscated values: 0x37680000, 0x4f100000, 0x508c0000, 0x51140000,
  0x537c0000, 0x5de00000, 0x6e600000, 0x6ee80000, …).
- Verified at byte level (fn78: unwind hdr[0]=0x11 → version=1, flags=2
  UHANDLER; handler slot bytes 00 00 e8 6e = 0x6ee80000): the handler
  slots are **ciphertext**, not real RVAs — Themida obfuscates unwind
  handler slots in packed images.
- 263 handler entries are in-image (classification pending; may contain
  valid and/or further obfuscated values).

## 2. Why this is a wall, not a bug

Design doc E12 (frozen): "UNW_FLAG_EHANDLER/UHANDLER: handler RVA 在可执行节内
| 在不可执行节 -> blocker". The sample's out-of-image handler values are
provable ciphertext (real handlers must resolve inside the image). E12 has no
defined semantics for obfuscated handler slots; the implementation fails
closed exactly as designed. This is the first live observation that Themida
obfuscates the unwind handler field in this sample's .pdata.

## 3. Options presented to 总指挥 (pending decision)

1. Design correction: out-of-image handler = recorded obfuscation evidence
   (not a blocker); E12 keeps blocking in-image-but-non-exec handlers.
   Requires DESIGN-CORRECTION + re-authorization, then matrix proceeds.
2. Keep E12 frozen: H4-D live BLOCKED on this wall; exception evidence
   cannot be produced on this sample.
3. Write non-passing evidence (prerequisite_passes=false with the wall
   documented inside) — matrix completes in FAIL state, no preservation
   claims.

## 4. Current disposition (fail-closed, no bypass)

- H4-D live matrix: BLOCKED pending 总指挥 decision (default: option 2 —
  E12 stays frozen; no evidence claims; no partial-pass sidecar).
- layout_A dump candidate + all pre-H4-D sidecars preserved as evidence.
- No bураs​s; no E12 relaxation without authorization; ADR7 frozen.
