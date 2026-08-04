# P3 Runtime Ownership — status (2026-08-04)

**Status:** implementation landed, offline gates green; **live equivalence
pending authorization** (P6/P7). This document closes the P3 ownership
statement: the CLI no longer owns the AV/OEP/IAT decision bodies.

## What moved

| P3 slice | Decision body | Capability seam | Host |
|---|---|---|---|
| P3-A capability contract | — | `RuntimeEngine` (core): read/write memory, thread context, HW breakpoints, exactly-once continue, `CapabilityRecord` log | `ReplayRuntimeEngine` + `DebuggerCoreEngine` |
| P3-B AV/OEP | `themida::runtime::av_oep_handler::decide_av_oep` | `AvOepQuery` | `cli::unpacker::av_query::AvQueryCtx` |
| P3-C IAT trace | `themida::runtime::iat_trace_handler::{handle_trace_step, advance_to_next_slot}` | `IatTraceQuery` | `cli::unpacker::iat_trace` (thin executor) |
| P3-D host | loop only: wait, call handler, execute action, log/sidecar | — | `av_handler` phase 1 delegates; phase 2 (IAT monitor) untouched |

No Win32 type (HANDLE / CONTEXT) appears on any public capability surface;
the low-level `DebuggerCore` trait remains the single Win32-typed backend
seam.

## Contracts pinned

- **Explicit actions, no implicit double-continue:** every decision branch
  returns one of the action enums; the host executes exactly one continue
  per action. `continue_thread` rejects thread-id mismatches and keeps the
  event pending on failure.
- **Fail-closed:** unmapped memory reads, unseeded contexts, out-of-range /
  duplicate / unarmed HW breakpoint slots, trash storms (>64), trace-limit
  give-ups, bad resolves, and context-read failures all fail closed.
- **Single completion milestone:** the IAT walk emits exactly one
  `Finished` (writeback at most once) with the legacy accounting invariants
  (`slots_accounted`, `product_complete` — including the legacy slot-0
  behavior, reproduced verbatim).
- **OEP provenance** (`Trace` / `ScanFallback` / `Unknown`) flows unchanged
  through replay and live paths.

## Verification (offline, all green)

- `cargo test --workspace --locked --offline` — 35 suites, 0 warnings.
- New replay coverage: P3-A 7 engine tests (incl. op-for-op capability-log
  parity between replay and live adapters), P3-B 10, P3-C 9, P3-QA 5
  (full guard→TLS→OEP→IAT→dump pipeline, action-exactly-once, context
  failure propagation, break/continue mapping).
- GTO feature build, `cargo deny --offline check`, `git diff --check` green.

## Open items (do not call P3 closed without these)

1. **Live equivalence:** the two fixed samples must still unpack with
   identical OEP/IAT outcomes after the rewiring. This cannot be proven
   offline; it is the P6/P7 preflight + smoke deliverable (authorization
   gated).
2. The IAT-monitor phase (post-OEP decryption loop) remains host-side in
   `av_handler` phase 2; its decisions were already themida-side
   (`process_iat_monitoring_access`), the loop orchestration stays in the
   host by design.
3. `iat_trace`/`av_handler` host executors still contain Win32 calls
   (`VirtualProtectEx`, `GetProcAddress`) behind the query seams — that is
   the host's role; the seams keep them out of the decision code.
