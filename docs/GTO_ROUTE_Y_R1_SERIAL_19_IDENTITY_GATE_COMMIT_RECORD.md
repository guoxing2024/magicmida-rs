# GTO Route Y R1 — MIDA-SERIAL-19 Identity Gate Commit Record

## 1. Record date

2026-08-15

## 2. Repository state

- branch: `oreans/two-sample-mainline`
- base HEAD (prior): `217db8abc788f89f73260e44a2b703b9a4f2b9ee`
- final HEAD: `52a48648ddcdc6607f2edb3662596cef03cfaef8`
- local-only: the two commits exist only in the local repository
- remote/upstream: **not configured**; push: **not executed**

## 3. Commit chain

Two local commits, applied in this exact order (strictly linear):

| # | SHA (full) | Message | Files | Boundary |
|---|---|---|---|---|
| 1 | `67075123e9ebe8591d56352bc833ae904c43858e` | `feat(pe): add ASLR-stable module identity and identity-bound policy gate` | `crates/pe/src/dumper/module_identity.rs`, `crates/pe/src/dumper/mod.rs`, `crates/pe/src/dumper/capture_policy.rs`, `crates/cli/src/capture_policy_file.rs` | Core (standalone) |
| 2 | `52a48648ddcdc6607f2edb3662596cef03cfaef8` | `fix(pe): gate sample transforms and persist truthful activation evidence` | `crates/pe/src/dumper/snapshot_manifest.rs`, `crates/pe/src/dumper/raw_slab_coherence.rs`, `crates/pe/src/dumper/dump_process.rs`, `crates/pe/src/dumper/heap_global_snapshot.rs` | **Atomic** Evidence + Integration |

Parent chain: Commit 1 parent = `217db8a`; Commit 2 parent = Commit 1. `git rev-list --count 217db8a..HEAD` = 2 (no third commit).

## 4. Atomic boundaries

- Core (Commit 1) compiles independently (module_identity + mod.rs + capture_policy + capture_policy_file).
- Evidence + Integration (Commit 2) **must be one atomic commit**: `snapshot_manifest` activation parameter propagation requires `dump_process` to exist in the same commit (otherwise E0061: 17 vs 16 arguments).
- No docs/lab files mixed in; no `runner_preflight.rs`/`runtime_rebase.rs`; no historical governance docs.

## 5. Verification (offline facts only)

- `cargo check --workspace --offline`: **PASS**
- `cargo test --workspace --offline`: **1909 passed / 0 failed / 2 ignored**
- capture_policy: **16 passed**; module_identity: **9 passed**
- snapshot_manifest: **11 passed**; dump_process: **46 passed**
- heap_global_snapshot: **73 passed**; raw_slab_coherence: **292 passed**
- m17_: **2 passed**
- `cargo fmt --all -- --check`: **PASS**; `git diff --check`: **PASS**
- tracked working tree: **clean**; staged: **0**; push: **not executed**
- No dynamic target was executed.

## 6. Identity gate semantics

- `ModuleIdentity` (module_identity.rs) uses Machine, TimeDateStamp, SizeOfImage, CheckSum, and a canonical SHA-256 section-layout digest (name + VirtualAddress + VirtualSize + SizeOfRawData + PointerToRawData + Characteristics, sorted deterministically).
- It does **not** include `image_base` (ASLR-stable); missing sections fail closed (`ModuleIdentityError::NoSections`).
- `DumpCapturePolicy` gained `module_binding` (Option<ModuleIdentity>), `policy_revision` (u32), `policy_digest` (SHA-256 hex over revision + binding + all sample-specific + behavior-affecting fields).
- Gate: unbound / binding mismatch / revision 0 / digest mismatch / missing identity → **deny** (fail-closed, generic-only fallback via `strip_sample_specific`).
- Only a matching identity + valid revision + valid digest permits sample-specific transforms.
- The gate is reused (not re-derived) by `detect_heap_globals` and `dump_process` via the same `sample_specific_activation` predicate.

## 7. Manifest and ledger truthfulness

- `render_manifest_json`/`write_dump_snapshot_manifest` take a `sample_activation: bool` parameter driven by the dump pipeline final `sample_active` — **no hardcoded false**.
- Rejected transforms do **not** call `apply_recorded_transform`, so no applied `transform_id`, no forged before/after digest, and no applied ledger record are written.
- matching activation records the transform and the manifest reports `"sample_specific_activation": true`.
- Schema version remains `mida.dump-snapshot-manifest/v1`; v0 constant retained for read-back compatibility (no authorization semantics).

## 8. Fixed-RVA scope and exclusions

- The `0x141bf0` special case still exists but is **identity-bound** (gated by `sample_active`); it was **not** renamed into a config item and claimed generalized.
- `0x147868`/`0x147888` fixed RVAs are **not generalized**; `0x147868` does **not** enter sanitize/reinit (proven by `m17_cmd_table_147868_not_sanitized_or_reinitialized`).
- No new heuristic; no new `cold_reinit_rvas`/`sanitize_reinit_rvas`; no shape/size/density generalization.
- MIDA-SERIAL-06 generic-predicate blocker is **not** claimed resolved.

## 9. Governance state

- `dynamic_authorized = false`
- `governance = RouteY_R1_GTO_LAUNCHER_REV2_DynamicAuthorizationSuspended`
- Approved scope remains only: `RouteY_R1_GTO_LAUNCHER_REV2_RUNTIME_MODULE_IDENTITY_RECAPTURE_2` (module identity recapture; not a launcher/target start authorization).
- Local commit closure **≠** dynamic authorization; offline test PASS **≠** dynamic validation; manifest activation=true **≠** authority approval.

## 10. Deferred P1/P2

- `POLICY_UNBOUND_SAMPLE_COUPLING`: identity-gated and statically mitigated, but **governance-deferred / not authority-resolved**.
- P2: `detect_heap_globals` full debugger pipeline test gap.
- P2: `sample_transform_allowed`/`policy_for_generic_path` unused reserved interfaces.
- P2: fixed-RVA generalization still requires an independent governance work order.

## 11. Evidence provenance

- This document records the state reported by MIDA-SERIAL-19 (identity gate local commit closure), building on MIDA-SERIAL-14 through MIDA-SERIAL-18.
- Historical authority reviews (REVIEW_1/2/3/4, static baseline, forensic reconciliation, etc.) are **not rewritten**; MIDA-SERIAL-09 commit record is **not modified**; the new HEAD is **not** written into old records.
- Corroborating mutable handoff entry: `WORKER_HANDOFF.md` section `### MIDA-SERIAL-19 Identity Gate Local Commit Closure — 2026-08-15` (appended 2026-08-15).

## 12. Explicit non-authorization statement

- This document is **not** a dynamic-execution authorization and **not** a new authority approval.
- No launcher/target was started; no observer/controller/network/firewall/hook/injection/debugger was executed.
- Local commits and offline test results do **not** constitute production qualification or dynamic validation.
- `sample_specific_activation=true` in a manifest means only that the static identity-bound policy allowed a sample transform in the constructing scenario; it does **not** grant dynamic authorization.
- `POLICY_UNBOUND_SAMPLE_COUPLING` remains **deferred / not authority-resolved**.