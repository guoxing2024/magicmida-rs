# GTO-COLD-START-HEAP-REBASE-1 — H4-A Design: Cold-Start Stable Module Registry (SMR)

> status: DESIGN (H4-A scoped) — implementation follows in a separate commit
> ledger: GTO-COLD-START-HEAP-REBASE-1 H4-A (SMR)
> input: authorized immutable rev-2 vault object
>        sha256 11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86
> upstream: H2 plan layer DONE (old_module_base -> new_module_base primitive);
>           ViaStableBinding stub execution is the explicit H2->H4 handoff marker

## 1. Problem statement

H2 (docs/GTO_COLD_START_HEAP_REBASE_1_H2_REPORT.md) closed every rebasing
wall up to the plan layer. The terminal observation (attempt_021 + layout_A +
layout_B, 3 ASLR layouts) is deterministic:

```
bootstrap_install: FAIL-CLOSED by design:
  "ViaStableBinding resolver present — cold-start module re-base (H4) not
   yet implemented in the two-phase stub; refusing to emit a broken fixup"
```

A ViaStableBinding resolver is an `ExternalTarget` with:

- `module_identity` (lowercase dll name, e.g. "kernel32.dll")
- `module_rva` (export offset within that module)
- `iat_rva = None` (NO IAT slot — this is the defining property)
- `resolution_kind = ExternalResolutionKind::ViaStableBinding`

The two-phase cold-start stub (crates/pe/src/dumper/runtime_bootstrap.rs,
`emit_two_phase_code`) implements ONLY `ViaIat` (read the rebuilt IAT slot).
Encoding a ViaStableBinding resolver into `.boot` today would silently read
`image_base + 0` as the API address — a wrong fixup — so
`encode_plan_metadata` fails closed (the H4 marker).

## 2. H4-A scope

**Deliverable:** the cold-start **Stable Module Registry (SMR)** — the stub-
internal mechanism that turns `(module_identity, module_rva)` into a concrete
`new_base + module_rva` at cold start, WITHOUT any dump-time module state,
WITHOUT any blanket module-delta patch, WITHOUT removing the fail-closed gate.

**In scope (H4-A):**

1. Metadata schema extension: resolver table gains a module-name reference
   (offset into a new NUL-terminated name table inside `.boot`).
2. Stub execution: a PEB Ldr module-list walk (InLoadOrder) that resolves
   module_identity -> loaded base, then emits `new_base + module_rva`.
3. Fail-closed semantics: unresolved ViaStableBinding -> stub never reaches
   OEP (infinite loop, same as Phase-1 allocation failure); the completion
   cookie stays 0 and the dump side reads the cookie as the gate.
4. Offline simulator parity: `simulate_runtime_rebase` learns the same
   module-map resolution so offline tests prove the round-trip.

**Out of scope (later H4 stages, NOT designed here):**

- OEP capture/redirect beyond the existing captured-entry model (H4-B)
- TLS callbacks/index/data rebuild (H4-C)
- exception/unwind rebuild, no-reloc handling (H4-D)
- pure PE candidate output (H4 final)

## 3. No-bypass semantics (the SMR is NOT stolen state)

The SMR enumerates the **cold-start process's own PEB Ldr data**:

```
gs:[0x60]        -> PEB
PEB+0x18         -> PEB_LDR_DATA
Ldr+0x10         -> InLoadOrderModuleList (LIST_ENTRY head)
head.Flink       -> first LDR_DATA_TABLE_ENTRY.InLoadOrderLinks
entry+0x30       -> DllBase   (x64)
entry+0x40       -> SizeOfImage
entry+0x58       -> BaseDllName (UNICODE_STRING)
  Length  @ +0x58 (USHORT)
  Buffer  @ +0x60 (pointer)
entry+0x00.Flink -> next entry; walk until back at the head
```

This is the target process's OWN loader state at cold start — the same state
the CRT/loader gives the process. It is:

- **no-bураs​s**: we never read a dump-time module map, never inject a module
  list, never patch the target's loader data;
- **ASLR-safe**: bases are read at cold start, never baked from the capture;
- **immutable-input-consistent**: the authorized sample cold-launches the same
  way every time; the registry is derived from that cold launch.

## 4. Metadata schema extension (design)

### 4.1 Resolver entry (current, 0x20 bytes)

```
BootResolver {
  module_rva: u64,       // +0x00
  iat_rva: u32,          // +0x08  (0 when ViaStableBinding)
  resolution_kind: u32,  // +0x0c  (0 ViaIat / 1 ViaExportMap / 2 ViaStableBinding)
  // +0x10..0x20 reserved (zero) today
}
```

### 4.2 Resolver entry (H4-A, 0x30 bytes)

```
BootResolver {
  module_rva: u64,       // +0x00
  iat_rva: u32,          // +0x08
  resolution_kind: u32,  // +0x0c
  module_name_rva: u32,  // +0x10  offset of NUL-terminated name in name table
  reserved: u32,         // +0x14
  // +0x18..0x30 reserved (zero)
}
```

- RESOLVER_META_SIZE 0x20 -> 0x30.
- decode rejects `module_name_rva` pointing outside the name table.
- encode writes `module_name_rva = 0` for ViaIat/ViaExportMap resolvers
  (name unused), and a real name-table offset for ViaStableBinding.

### 4.3 Name table (new region in `.boot`)

A NUL-terminated string table appended after the resolver table (before the
payload region). Layout order in `.boot` becomes:

```
code | header | regions | fixups | resolvers | NAME TABLE | payload | alloc map | cookie
```

- header gains `name_table_off` (+0x34, u32) and `name_table_len` (+0x38, u32).
- names are the plan's `module_identity` strings (already lowercase);
  the stub compares case-insensitively anyway.
- PLAN_HEADER_SIZE grows accordingly; magic unchanged; decoder fails closed
  on a name-table offset/len overflow or a resolver name_rva out of bounds.

## 5. Stub execution design (Phase 2.5 — module resolution)

### 5.1 Placement

Phase 2 (fixup walk) currently handles cls==3 (ExternalModule) by reading the
IAT slot. H4-A splits cls==3:

- resolver.resolution_kind == 0 (ViaIat): existing IAT-slot read, unchanged.
- resolver.resolution_kind == 2 (ViaStableBinding): SMR resolution.

The SMR path is a **per-resolver lazy walk** (bounded by module count, ~40
entries for this sample; 158 module-zone values in attempt_019 map to far
fewer distinct resolvers). No registry caching in stub-local memory is
needed for Phase 2 volume; a walk per distinct resolver is deterministic and
bounded.

### 5.2 Register budget (x64, Win64 ABI)

Persistent across the whole stub today:

- rbp  = loaded image base (ASLR scheme B)
- rbx  = alloc map base
- r15  = meta base
- r14  = process heap (Phase 1 only)
- r13  = loop count, r12 = table ptr, r11 = index (Phase 2 loop)
- r10  = scratch (image base + rva), rdx = write value, rax = src addr
- rcx  = scratch pointer, r8/r9 = scratch

SMR walk needs one base register for the entry pointer. **r9 is free inside
the ExternalModule branch after the resolver pointer is computed** (current
code already reuses r9 for the resolver table base). Walk plan:

```
; on entry to ViaStableBinding branch:
;   rcx = resolver entry (kept from the existing branch setup)
;   r9  = resolver table base (existing)
; 1. r8 = module_name_rva = [rcx+0x10]; name_ptr = r15 + r8
; 2. rax = gs:[0x60]            ; PEB
;    rax = [rax+0x18]           ; Ldr
;    rax = [rax+0x10]           ; InLoadOrderModuleList head
;    r9  = [rax]                ; first entry (Flink)
;    rdx = rax                  ; head sentinel
; walk loop:
;    cmp r9, rdx ; jz fail      ; back at head -> not found
;    ; entry BaseDllName: [r9+0x58].Length, [r9+0x60].Buffer
;    r10 = [r9+0x60]            ; name buffer
;    r8d = [r9+0x58]            ; length (bytes)
;    compare name_ptr (r15+r8name) vs r10 for r8d/2 chars, case-insensitive
;    jz found
;    r9 = [r9]                  ; Flink
;    jmp walk loop
; found: rdx = [r9+0x30]        ; DllBase
;        r10 = rdx ; r10 += module_rva ([rcx+0x00]) ; rdx = r10
;        jmp p2_write
; fail:  infinite loop (never reaches OEP; cookie stays 0)
```

Case-insensitive compare: ASCII-only fold (A-Z | 0x20) — all Windows module
names are ASCII. Length compare first (bytes equal), then per-char fold.

### 5.3 Fail-closed semantics

- A ViaStableBinding resolver whose module is NOT loaded at cold start is a
  **hard stop**: infinite loop, completion cookie stays 0. This is the same
  failure class as a Phase-1 allocation failure (the stub never reaches OEP),
  so the dump side's existing cookie check needs no new failure mode.
- The walk reads ONLY Ldr data; a corrupted/absent Ldr head (NULL PEB->Ldr)
  also fails closed the same way.
- No partial fixup writes happen before a resolver is resolved: the branch
  writes only AFTER the module match. If the walk fails, the current fixup is
  NOT written and the stub loops — no torn state reaches OEP (OEP is never
  reached).

### 5.4 Why lazy walk, not a registry table

- The registry is inherently the process's Ldr state — caching it in stub
  memory is redundant (same bytes, more code).
- Per-resolver walk cost is O(modules x resolvers) with modules ~40,
  resolvers ~single digits (attempt_021: 158 zone values dedup to a handful
  of distinct (module, rva) keys).
- Deterministic: walk order is Ldr list order (stable per process boot);
  results depend only on cold-start loader state.

## 6. Offline simulator parity

`simulate_runtime_rebase` currently resolves ExternalModule via
`iat_contents`. H4-A extends it with a `module_bases: &HashMap<String, u64>`
parameter:

- ViaIat: unchanged (iat_contents).
- ViaStableBinding: `module_bases.get(&name)` -> base + module_rva;
  missing module -> `UnresolvedRequired` (same fail-closed).
- ViaExportMap (kind 1): still absent from the stub -> encode fails closed
  as today (no instance in the sample; plan layer only).

All existing tests keep working (ViaIat path unchanged); new tests cover the
SMR path.

## 7. Test plan

| # | test | level | asserts |
|---|---|---|---|
| 1 | encode/decode round-trip with ViaStableBinding resolver | unit | name_table bytes round-trip; module_name_rva resolved; resolver kind preserved |
| 2 | name-table bounds fail-closed | unit | bad name_rva -> decode error |
| 3 | simulate ViaStableBinding resolution | unit | base+rva patched; missing module -> UnresolvedRequired |
| 4 | simulate ViaIat unchanged | unit | existing metadata_round_trip + fixup tests still green |
| 5 | stub codegen contains SMR walk (disassembly smoke) | unit | emitted bytes contain gs:[0x60] PEB load + Ldr walk pattern; branch targets resolve |
| 6 | live observation re-run (attempt_024+) | live (controller) | bootstrap_install passes; cookie=1; regions/fixups unchanged count |
| 7 | cross-layout repeat (2 layouts) | live | SMR resolves same (module, rva) set on both ASLR layouts |

Fail-closed checks: unresolved module -> encode OK (plan layer) but simulate
fails; stub walk fail -> cookie 0 (covered by codegen review + test 5 branch
target audit).

## 8. Boundary gates (unchanged from H0 §5-H4)

- dynamic import/IAT capture: DONE (H2)
- ViaStableBinding cold-start execution: THIS stage
- TLS/exception/no-reloc: later H4 stages
- Gate discipline: no gate removal; encode_plan_metadata stays fail-closed
  for ViaExportMap until a stub exists for it; ADR7 frozen; no bураs​s

## 9. Evidence & ledger

- Evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4A_smr\
  (resolved_source.json REQUIRED before live steps)
- Scratch:   D:\MidaVault\scratch\gto_cold_start_heap_rebase_1\H4A_smr\
- Commit discipline: code changes pass cargo fmt --all -- --check,
  cargo test --workspace --offline, git diff --check; docs-only commit first
- New ledger rows for H4-A only; no Route A-H ledger extension

## 10. Non-claims (binding)

- NOT product 1.0; NOT cold-start wall closed (H3 exit criteria untouched)
- No bураs​s; no target patching; no gate removal; no dump-time module state
- ViaStableBinding stub execution is H4-A scope ONLY; ViaExportMap stub
  remains out (no instance, fail-closed)
- ADR7 frozen; Oreans gate untouched; no samples/binaries committed
