# Transform Taxonomy v1

> **Status:** Frozen contract draft for signature-envelope work.  
> **Version:** `mida.transform-taxonomy/v1`  
> **Date:** 2026-07-27  
> **Binding:** dump emit + `transform_manifest` + acceptance ledger

This document freezes which dump-time mutations must appear in the bound
transform manifest / evidence ledger, which are standard PE reconstruction
(no ledger entry), and which are **diagnostic-only** (block product `Accepted`
unless a registered equivalence rule applies).

Signing an empty ledger before this freeze would certify incomplete semantics.

---

## 1. Goals

1. Every **semantic** change to candidate bytes is either:
   - **Standard reconstruction** (implicit, no ledger row), or
   - **Declared transform** (stable `id` + `kind` in manifest/ledger).
2. **Diagnostic** transforms never product-Accept without an equivalence rule
   that is registered as `(id, kind, rule)` in code.
3. Taxonomy version is part of future signature envelope payload.

---

## 2. Kinds

| `kind` | Meaning | Default Accept impact |
|--------|---------|------------------------|
| `pe_repair` | Generic PE rebuild / import / reloc / scrub that restores loader-correct form without sample-specific logic skips | Allowed **only** with registered `(id, kind, rule)` |
| `sample_bypass` | Sample-specific control-flow / UI / load skips (GTO r26b-class) | **Blocks** product Accept (no registered rule) |
| `serialization` | Header serialize, alignment pad, zero-fill to file layout **without** changing semantic image content beyond PE rules | Not ledgered (standard) |
| `capture` | Early snapshot overlay / heap capture that materializes runtime state into the image | See table below |

Unknown `kind` → treat as blocking (fail-closed).

---

## 3. Standard reconstruction (no ledger row)

These run on production dump paths and are **not** listed in
`transform_manifest.entries` under v1. They must remain **generic** (no
sample-specific RVA patches):

| Operation | Code locus (indicative) | Rationale |
|-----------|-------------------------|-----------|
| PE sanitize / section rename defaults | `PeHeader::sanitize`, dump path | Structural cleanup |
| Header serialize at file offset 0 | `serialize_headers` / emit | Layout only |
| File/section alignment padding | dump pad / `file_align` | PE rules |
| Import table rebuild from live IAT | `rebuild_import_table*` | Standard unpack repair; **rule** `pe_iat_rebuild_v0` if ever ledgered |
| Fix absolute image-base constants | `fix_hardcoded_addresses` | Standard rebasing |
| Optional reloc table rebuild (`opts.shrink`) | `build_relocation_table` | Optional layout; if enabled, future ledger id `reloc_rebind` |
| Optional section pack (`opts.shrink`) | `pack_section_layout` | Optional layout |
| Bound empty `transform_manifest` always | `write_bound_transform_manifest` | Contract artifact, not a mutation |

If a “standard” step gains **sample-specific** RVA lists or forced UI
behavior, it **must** be reclassified as `sample_bypass` or a new kind and
ledgered.

---

## 4. Declared transforms (must ledger when applied)

### 4.1 Diagnostic — `sample_bypass` (no product Accept)

| `id` | When | Parameters (future envelope) | Equivalence |
|------|------|------------------------------|-------------|
| `gto_bypass_loadfile` | `AhkGtoExperimental` + `MIDA_GTO_BYPASS=1` | site RVA | **None** — diagnostic only |
| `gto_bypass_registerclass` | same | site RVAs | **None** |
| `gto_bypass_msgloop` | same | site RVA | **None** |
| `gto_bypass_messagebox` | same | site RVA | **None** |

Dumper must record these in `applied_transforms` → manifest `entries` with
`equivalence_rule: null`. Acceptance rejects product Accept if any such entry
lacks a **registered** rule (none exist for GTO bypass by design).

### 4.2 Optional pe_repair (ledger **if** we choose to disclose)

v1 **allows** these IDs in the registry for future mandatory disclosure; dump
does **not** yet auto-emit them (empty ledger for clean Oreans path is OK
**only** when no sample_bypass ran):

| `id` | `kind` | Registered rule | Meaning |
|------|--------|-----------------|---------|
| `iat_rebuild` | `pe_repair` | `pe_iat_rebuild_v0` | Live IAT → import section rebuild |
| `reloc_rebind` | `pe_repair` | `pe_reloc_rebind_v0` | Rebuild reloc table after layout change |
| `clear_stale_ptrs` | `pe_repair` | `clear_stale_process_ptrs_v0` | Scrub process-local absolute pointers in data |

**Policy (v1):**

- Clean OreansClassic dump with **only** standard reconstruction → empty
  `entries` is valid.
- Any `sample_bypass` → non-empty ledger, no Accept.
- Future tightening may **require** pe_repair rows whenever the corresponding
  code path runs; that is a taxonomy **v2** bump.

### 4.3 Capture / experimental (ledger when non-default)

| `id` | `kind` | When | Accept |
|------|--------|------|--------|
| `early_section_overlay` | `capture` | early snapshots applied | Pending unless rule added in v2 |
| `heap_slab_restore` | `capture` | heap slab bytes captured | Pending / diagnostic |
| `heap_bootstrap` | `capture` | `install_heap_bootstrap` actually installed | Pending / diagnostic |
| `cs_reinit` | `pe_repair` | CRITICAL_SECTION reinit RVAs from policy | Disclose in v2 if sample-specific |

**Emit (implemented):** when these paths run, dumper **must** append the
corresponding `(id, kind)` to the bound transform manifest:

- `early_section_overlay` / `capture` — early snapshot bytes applied
- `heap_slab_restore` / `capture` — heap slab captured (may be independent of bootstrap)
- `heap_bootstrap` / `capture` — heap/container bootstrap stub installed (may run without slab)
- `cs_reinit` / `pe_repair` — non-empty `cs_reinit_rvas` policy applied

No registered equivalence rules exist for these ids → product Accept blocked
when present (diagnostic / Pending only). Operational rule: **do not CI-sign**
dumps that carry capture rows until rules or product policy change (v2).

---

## 5. Acceptance registry (code must match)

`REGISTERED_TRANSFORM_RULES` in `crates/acceptance/src/behavior.rs` is the only
authority for product Accept with non-empty ledger:

```text
(id, kind, rule)
("iat_rebuild", "pe_repair", "pe_iat_rebuild_v0")
("reloc_rebind", "pe_repair", "pe_reloc_rebind_v0")
("clear_stale_ptrs", "pe_repair", "clear_stale_process_ptrs_v0")
```

- Free-form `equivalence_rule` strings → reject.
- Wrong `(id, kind)` pairing → reject.
- `sample_bypass` + any pe_repair rule → reject.

---

## 6. Manifest always

Every dump (native and .NET) writes `*.transform_manifest.json` bound to
candidate SHA-256 + size:

- **Required field** `taxonomy_version`: exact `mida.transform-taxonomy/v1`
  (missing → cannot mint `VerifiedManagedCandidate`; unknown → reject)
- Clean path: `entries: []`
- Bypass path: GTO ids with `equivalence_rule: null`
- Manifest write failure → delete candidate (fail-closed)

`check-with-behavior` requires sibling manifest unless
`--allow-unmanaged-candidate` (lab only; **cannot** product-Accept).

Legacy manifests without `taxonomy_version` are **not** managed — they do not
unlock `Accepted` (fail-closed; no silent Option default).

---

## 7. Signature envelope (verify-side implemented)

Schema: `mida.signature-envelope/v0` (`crates/acceptance/src/envelope.rs`).

Payload **must** include at least:

| Field | Purpose |
|-------|---------|
| `taxonomy_version` | `mida.transform-taxonomy/v1` |
| `candidate_sha256` / size | Byte identity |
| `manifest_sha256` | Bound transform list |
| `evidence_sha256` | Behavior evidence doc |
| `probe_id` / reference | Product probe binding |
| `producer_tool_sha256` | mida-cli / dumper binary |
| `git_commit` + dirty flag | Source identity |
| `toolchain` | rustc/MSVC ids |
| `run_uuid` / `created_utc` | Replay |
| `key_id` | CI signer |

API:

- `SignatureEnvelope::parse_json` + `verify_bundle` → `VerifiedSignedBundle`
- `check_with_behavior_signed` composes only after bundle is sealed
- Algorithms: `mida.hmac-sha256/v0` (CI lab); `mida.ed25519/v1` reserved (unimplemented → reject)
- Default `EnvelopePolicy` allowlist is **empty** (fail-closed); dirty git rejected
- `RejectAllVerifier` is the default product posture until CI injects keys

Rules:

- Dumper **must not** self-sign (`sign_hmac_sha256_for_test` is test/CI-tool only).
- Unknown keys, dirty tree (if policy forbids), taxonomy mismatch, or any hash
  mismatch → no `Accepted`.
- Canonical message = `serde_json::to_vec(payload)` (struct field order).
- **CLI default:** missing envelope → managed Accept **capped** at Pending
  (`--allow-unsigned-managed` lab escape). Library managed API still unsigned-capable.
- **Sealed evidence:** `verify_bundle` parses evidence from hashed JSON and stores
  it in `VerifiedSignedBundle`; `check_with_behavior_signed` has no external
  evidence parameter (cannot swap post-verify).
- **HMAC trust root:** caller-supplied HMAC is **lab-only** (`--allow-hmac-lab` +
  `EnvelopePolicy.allow_hmac_lab`). Product path requires a fixed non-caller
  trust root (Ed25519 reserved; not yet shipped).

---

## 8. Non-goals (v1)

- Devirtualization / VM free-run transforms
- Full heap graph equivalence proofs
- Auto-ledger of every pe_repair step (deferred to v2)
- Cross-volume atomic multi-file bundle (separate work item)

---

## 9. Change control

Any new dump mutation that changes control flow, skips product code, or injects
sample-specific constants **must**:

1. Add a row to §4 with stable `id`/`kind`.
2. Update dumper `applied_transforms` emit.
3. Update acceptance registry **or** leave `equivalence_rule` null (diagnostic).
4. Bump taxonomy version if semantics of existing ids change.

---

## 10. Checklist before first CI signature

- [x] Taxonomy v1 reviewed and linked from ACCEPTANCE_CONTRACT
- [x] GTO bypass always ledgered
- [x] Capture transforms ledgered (`early_section_overlay` / `heap_slab_restore` / `cs_reinit`)
- [x] No self-sign in dumper
- [x] Envelope fields + verify path in acceptance (`envelope.rs`)
- [x] CLI product path requires signed envelope for Accepted (cap / lab flag)
- [ ] Ed25519 CI key material + public allowlist
- [ ] Fake-debugger .NET e2e green
- [ ] Full Windows CI green on same commit
