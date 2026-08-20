# GTO-COLD-START-HEAP-REBASE-1 — H1 Cold-Start Observation Report

> status: H1 OBSERVATION COMPLETE (cold-start failure timeline recorded;
> heap/container model deliverables blocked behind the anti-debug runtime wall)
> generated: 2026-08-20
> task: GTO-COLD-START-HEAP-REBASE-1 (boundary: docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md)
> evidence root: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\

## 0. TL;DR

The no-bypass cold-start wall, re-measured at HEAD d88de29 on the authorized
immutable rev-2 sample, fails EARLIER than the Route E-H historical wall:

    preflight (identity/env/build)        PASS  (controller gates, no spawn issues)
    process create + attach               PASS  (pid spawned, PEB patched, suspended)
    post-attach anti-debug controller     FAIL  (runtime injected, InitializeAbiError
                                                 -1073740791 = 0xC0000409 fastfail in target)

The 0xC0000409 (STATUS_STACK_BUFFER_OVERRUN / int29 fail-fast) fires inside the
target during mida-antidebug-runtime initialization — the same fail-fast class
ADR7-B4 documented at bound int29 site 0x2e816 for the Oreans samples
(origin_macro/lunlun_software). For the GTO sample the runtime injection
path itself (CreateRemoteThread + PEB surface writes) triggers the protected
target's fail-fast before any heap/container capture stage can run.

## 1. Identity (resolved, vault-first)

| Field | Value |
|---|---|
| case_id | gto_launcher (manifest rev 2) |
| protected_input sha256 | 11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86 |
| size | 24636416 |
| vault object | D:\MidaVault\vault\sha256\11\11473d2e…\artifact.exe |
| resolution | ResolvedAuthorizedRevision (resolved_source.json, H0_boundary/) |
| source revision | d88de29f45c7d2a15cad671fda8ac8f1bc9319c7 (docs-only H0 commit on 96cd929) |

## 2. Tool identities (recorded)

| Tool | sha256 | size | note |
|---|---|---|---|
| mida-cli.exe (plain build) | 29c86074be4da634b3b1372b2efc0bdec704b933f5e35b1a32d25cde1ac2498c | 12211200 | gto-product-recovery, debug, attestation in cargo-target/ |
| mida-cli.exe (runtime-bound) | 84bb158311a4043b76d0868a654f19427c037445c0cab6ba4da5f092aa5adcb3 | 12214784 | MIDA_RUNTIME_AUTHORITY_DIGEST=befd3867… MIDA_RUNTIME_SOURCE_REF=7e65cf6 |
| runtime DLL (B4/B5) | ae42901ec940dfa95566dcf9e0787d1e2c9439d90e7c593ed3a803a4f9cdbb76 | 370688 | authority manifest sha256 befd3867… (B4 authority/manifest.json) |
| authority manifest | befd38670fe418f7fecd22e95aa852ff251cc6af313103c6895358b0cc98bb8c | 1133 | source_ref 7e65cf657029c8d3452bd9b595f8ca6f1cf79e18 |
| _resolve_gto_source_revision.py | 4d93b68aad5767833c61bccbd3827c4d30de3260e55c1ce5bf867ac37c527c72 | 36641 | |
| _case_live_unpack.py | 751df3a738c1761f429f94d33062e7289f783e2bedc24e24691231327ec6ea96 | 15068 | |
| gto_live_route_controller.py | 512b26dffc685fe2077a9b84c124d47f1340ade1a76402342e699da6986cda36 | 32813 | |
| build_gto_live_cli.ps1 | 594867ca1a27a78d29c02f3323fed3e372f8c5573b4b014e01475bd252c1b14e | 5244 | |
| verify_adr7_closeout.ps1 | 52a57d37477b2bba49a033a11cfe5ed23965321c8bda4a85b139150886de9cbd | 13583 | |

## 3. Cold-start attempt timeline (controller-driven, no-bypass)

### attempt_001 (plain build, no runtime env) — H1_coldstart_observation/attempt_001

| seq | gate | result |
|---|---|---|
| 1 | build capability | FAIL build_binary_path_mismatch (attestation path normalization; config issue, no spawn) |
| 2 | env contract | FAIL allowlist_missing_no_bypass + capture_policy_file_missing (config, no spawn) |
| 3 | capture policy | FAIL capture_policy_file_missing (file not in attempt dir; config, no spawn) |
| 4 | ALL preflight | **PASS — spawned** |
| — | process | created pid=22776, PEB patched, main thread suspended/resumed |
| — | runtime | NOT injected (plain build has empty MIDA_RUNTIME_AUTHORITY_DIGEST → DependencyUnavailable) |
| — | result | exit 1, state=DependencyUnavailable fail_code=AntiDebugRuntimeUnavailable |

stderr sha256 198999032ddd00675cbf897e28fde4205b587b99496fcc3ef091392d326b5dbe (3712 B)

### attempt_002 (runtime-bound build + B4 runtime env) — H1_coldstart_observation/attempt_002

| item | result |
|---|---|
| ALL preflight | **PASS — spawned** |
| process | created pid=13124, PEB patched, main thread resumed |
| runtime | injected via CreateRemoteThread (LoadLibrary + thunk call to MidaAntidebugInitialize) |
| failure | **InitializeAbiError -1073740791 (= 0xC0000409 STATUS_STACK_BUFFER_OVERRUN as i32)** |
| cleanup | TerminateProcess FAILED (win32=2147942405 ERROR_ACCESS_DENIED); wait signaled; escalated CleanupFailed |
| result | exit 1, state=CleanupFailed fail_code=CleanupFailed |

stderr sha256 5b9fa9717bf1530837eebd23eea78fb0059fea835fefd455e0efdac779d0a995 (4542 B)

## 4. Wall attribution (fail-closed, no bypass)

The 0xC0000409 fires inside the target during runtime initialize. Sources
(by elimination):

1. NOT a runtime enumeration error: MidaAntidebugError codes are 0..10;
   -1073740791 is not one of them, so the remote thread did not return a
   structured error — it fast-failed (int29) inside the target.
2. ADR7-B4 documented the same fail-fast class at int29 site 0x2e816
   (panic_with_hook → panic_count::increase → TLS check → int29) for the
   Oreans protected samples; the runtime panics on protected targets by design
   (fail-closed) and does not panic on benign hosts.
3. For GTO (Themida-shaped, .rdata2 EP, no relocs), the injection path itself
   (CreateRemoteThread + PEB BeingDebugged/pShimData writes) is the most
   likely trigger — the protected process fast-fails on the surface writes.

So the wall is: **the anti-debug runtime controller (post-attach mandatory
stage) cannot initialize inside the GTO target without triggering its
fail-fast, and the pipeline fails closed before any heap/container capture
stage runs.** This is the FIRST gate; the historical Route E-H raw_slab_overlay
wall (heap state rebuild) is BEHIND it and was not reached.

## 5. Deliverables status (per H1 gate in the boundary doc)

| # | deliverable | status |
|---|---|---|
| 1 | heap region inventory | NOT REACHED (blocked pre-capture) — baseline exists in vault (r27, Route L/O/R/S/T/V/W/X/Y manifests) |
| 2 | allocation timeline | NOT REACHED (same) |
| 3 | region hash/diff | NOT REACHED (same; _diff_boot_heap.py / _diff_dump_snapshot.py exist) |
| 4 | pointer graph | NOT REACHED (same) |
| 5 | base-relative field candidates | NOT REACHED (same) |
| 6 | cold-start failure timeline | **DONE** (this report; attempts 001/002; stage attribution per gto_exit_path_catalog: observe_gto/post-attach runtime stage) |

## 6. Next stage input (H2 / H3 preconditions)

- The post-attach anti-debug runtime stage is MANDATORY and fail-closed; to
  reach heap capture the controller must either (a) observe the target
  WITHOUT the runtime injection (a read-only observer path — the B4
  b4_dynamic_observer model), or (b) make the runtime initialize not trigger
  the protected target's fail-fast. Both are H2+ scope; neither is a bypass
  (both are observation-side).
- Baseline heap/container manifests (r27, Route L/O/R/S/T/V/W/X/Y) remain the
  H1 deliverable sources once a capture path is available; the diff tooling is
  already in-tree.

## 7. Non-claims

- NOT product 1.0; NOT "process survived"; NOT heap-rebasing wall closed.
- NOT claiming the target crashed due to our code vs its own integrity check
  (root cause of the 0xC0000409 inside the target is NOT established beyond
  the B4 int29 class; a stack snapshot inside the target was NOT taken).
- No bypass / semantic repair / DRx / VEH / injection into a second process;
  the runtime injection is the product's own ADR-4 mechanism, not a bypass.
- ADR7 evidence untouched (read-only); Oreans gate untouched.
