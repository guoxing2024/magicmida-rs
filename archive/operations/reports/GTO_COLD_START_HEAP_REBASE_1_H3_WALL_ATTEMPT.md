# GTO-COLD-START-HEAP-REBASE-1 — H3 cold-start wall live remeasure (2026-08-20)

> status: H3 ATTEMPT MEASURED — pre-resume runtime loader DOES NOT cross the wall
> inputs: pinned manifest rev 2 sample (11473d2e…), source revision b778701
> evidence: D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H3_wall_attempt\
> env: MIDA_GTO_NO_BYPASS=1, no bypass/semantic-repair/DRx/VEH/injection/R1B/E2
> runtime: mida_antidebug_runtime.dll ae42901e… (manifest sha befd3867…, source 7e65cf6)

## 1. What was measured

H3 (commit b778701) hoists the post-attach runtime loader to run BEFORE
resume_post_attach_main_thread(), so the MIDA runtime is injected and
initialized while the main thread is still CREATE_SUSPENDED. Live remeasure
via the route controller (authorized build attestation, authority digest
compiled in, no-bураs​s env contract):

| attempt | outcome |
|---|---|
| 1 | preflight stop: build_binary_path_mismatch (argv0="--" — controller REMAINDER misuse, not a code defect) |
| 2 | spawned; loader failed at authority resolution (MIDA_RUNTIME_AUTHORITY was set to a digest; code expects manifest path) |
| 3 | **spawned; runtime injected + verified pre-resume; remote init -> abi error -1073740791 (0xC0000409); cleanup escalated (ERROR_ACCESS_DENIED); exit 1** |

Attempt-3 stderr (child.stderr.txt, controller_run.json): the loader ran
while the main thread stayed suspended (7 s remote-init window), the runtime
module was verified against the compiled-in authority digest, and the remote
MidaAntidebugInitialize call returned exit code -1073740791 = 0xC0000409.

## 2. Attribution (fail-fast owner)

MIDA runtime's MidaAntidebugInitialize is a pure FFI entry: catch_unwind,
structured error codes, never fail-fast itself (crates/antidebug-runtime/
src/exports.rs). Therefore the 0xC0000409 observed at remote-init is NOT the
runtime self-terminating — it is the GTO protector detecting the injected
runtime state (module list change / PEB surface patch / TLS / debugger
signature) and fail-fast'ing the process during the remote init call.

Pre-resume injection does NOT avoid the detection: the protector's fail-fast
is armed before the first resumed instruction, i.e. it detects the runtime at
load/init time, not at execution time. This is the same fail-fast class as
ADR7-B4 (0xC0000409 int29 on Oreans) but here on GTO.

## 3. Wall state (updated)

| item | state |
|---|---|
| post-attach runtime loader | works (authority + provenance verified) |
| pre-resume injection | works (runs before first resumed instruction) |
| protector fail-fast on injected runtime | **persists** — wall NOT crossed |
| heap capture stages | still unreachable (fail-fast precedes them) |
| route E-H raw_slab_overlay wall | still behind this gate |

## 4. Options for the next stage (not executed here)

All remain no-bураs​s (no patching the target, no disabling its fail-fast):

1. **Observation-first cold start (no runtime injection):** run the cold
   target with NO injected runtime and capture the heap/container epoch
   before the protector's UI path, using only debugger-side reads (the
   pre-existing Route L/O/S raw-slab capture machinery). The runtime is a
   defensive net for OUR side; the wall is the target's own fail-fast, so
   the first heap model must be obtained without adding load-time state.
2. **Staged injection after UI settle:** let the target reach its product
   UI naturally (2/3 load-survive in Route H), THEN load the runtime — but
   keep the no-bураs​s env and terminate instead of patching on detection.
3. **Runtime as pure observer (no PEB surface writes):** initialize with
   expected_surfaces=[] and no surface install, so the injected module
   performs read-only telemetry; if the protector still fail-fasts on mere
   module presence, that itself is evidence for option 1.

Recommended order: option 1 first (it is the only one that can produce the
H1-mandated heap inventory from a real cold start without target writes),
then option 3 as a controlled probe of the protector's detection surface.

## 5. Non-claims

- NOT product 1.0; NOT perfect unpack; NOT heap-rebasing wall closed
- No bураs​s; no target patching; no gate removal; target terminated
- ADR7 frozen; Oreans gate untouched; no samples/binaries committed
