# VNEXT-R2 Runtime / Event Engine

Status: **Slice 4 + 3b-6 closed; R3-path-A open** (2026-07-23) — address
newtypes, `RuntimeEngine`, `ReplayRuntimeEngine` + `ReplayMemory`,
`DebuggerCoreEngine`, CLI pump, `PackerPlugin` 3b-1..6, offline guard→OEP +
skip_v3 skeleton. Pure flip=**No**. R3 10× gate not claimed.
Prerequisites: R0B + R1 closed; Phase2 pure opt-in.

## Goals

1. One event pump owns wait / continue / thread lifetime / breakpoints.
2. Addresses use explicit typed wrappers (no raw `u64` soup for base arithmetic).
3. Two backends: **Win32 live** and **replay** (deterministic offline tests).
4. Packer plugins advise strategy only; they do not own the pump or acceptance.

## Non-goals (Slice 0)

- No default pure flip; no R3 Oreans 10×; no Behavioral `Accepted`.
- No live behavior change; no mass move of `cli/unpacker` yet.
- No new crate required until Slice 1+ lands traits in `mida-core`.

---

## Address types (sketch)

| Type | Meaning | Typical source |
|------|---------|----------------|
| `PreferredBase` | PE optional header ImageBase (preferred) | on-disk / patched PE |
| `RuntimeBase` | Actual load base (ASLR) | `CreateProcess` / PEB |
| `Rva` | Offset from image base | headers, DDs, sections |
| `Va` | Absolute process address | debugger events, IAT slots |
| `FileOffset` | Offset in PE file bytes | serialize / dump raw |

### Conversion rules (must be explicit)

```text
Va  = RuntimeBase + Rva          // live map
// preferred layout (post header_patch dump emit):
//   emit ImageBase := PreferredBase
//   fix_hardcoded:  runtime_va - RuntimeBase + PreferredBase

// FORBIDDEN: treating RuntimeBase as PreferredBase in pure emit
// (Phase2 bug class; fixed by host-patched preferred base)
```

### Implementation (Slice 1)

Module: `mida_core::addr` (re-exported at crate root).

| Type | Notes |
|------|--------|
| `PreferredBase` | PE ImageBase preferred; dump emit |
| `RuntimeBase` | Live ASLR / CreateProcess base |
| `Rva` / `Va` / `FileOffset` | as sketched |
| `Va::from_runtime` / `to_rva` | live map |
| `Va::from_preferred` / `to_rva_preferred` | preferred layout |
| `Va::rebase_to_preferred` | hardcoded-address fix formula |

Unit tests cover live/preferred round-trips, below-base / u32 overflow rejection,
and the Phase2 “must not treat runtime as preferred” distinction.

**Not yet:** unpacker/dumper call sites still pass raw `u64` (incremental adopt).

---

## Existing building blocks (map, do not rewrite)

| Current artifact | Role in R2 |
|------------------|------------|
| `mida_core::DebuggerCore` | Live backend surface (wait/continue/mem/ctx/BP) |
| `mida_core::DebugEvent` | Decoded event enum (already backend-ish) |
| `mida_core::DebugEventLifecycle` | Pure pending-event / exactly-once continue SM |
| `cli/unpacker` `LoopState` + main loop | **Plugin + session policy** mixed into CLI |
| `mida_packers_themida` | Family strategy (guard, IAT, OEP, ScyllaHide) |
| `mida_pe::dumper` | Host dump / pure emit adapters |

Slice 0 conclusion: **lifecycle SM already exists**; missing pieces are (1) a
named **engine** that owns the loop, (2) **plugin trait** boundary, (3) **replay**
backend implementing the same wait/continue contract without Win32.

---

## Runtime engine (Slice 2)

Implemented in `mida_core::runtime_engine`:

| Item | Status |
|------|--------|
| `RuntimeEngine` trait | ✅ `wait` / `continue_event` / `runtime_base` / `process_exited` |
| `EngineEvent { sequence, event }` | ✅ |
| `ReplayRuntimeEngine` | ✅ pure scripted events; unit tests |
| `ReplayMemory` + `with_memory` | ✅ Slice 4 sparse VA maps; unmapped = `MemoryRead` |
| `guard_oep_event_script` | ✅ create → LoadDll → guard AV → OEP BP → exit |
| Exhausted finite wait | ✅ `CoreError::Timeout` (short-wait sim) |
| `DebuggerCoreEngine<D>` | ✅ live adapter; pending wait/continue; `backend_mut` |
| CLI `ProcessSession` pump | ✅ wait/timeout/continue via engine; Origin smoke OK |

### Engine event vs debug event

`EngineEvent` wraps `DebugEvent` with a monotonic `sequence`. Replay sets
`runtime_base` from `CreateProcess.image_base`.

### Ownership rules

1. Only the engine calls wait/continue (or the lifecycle plans that gate them).
2. Plugins receive **immutable event views** + **capability handles** (read mem,
   set BP) via engine-mediated APIs — not raw process handles long-term.
3. Dump/OEP/IAT decisions remain packer-side; engine does not know Themida.

---

## Backend trait (sketch)

```rust
pub trait DebugBackend {
    fn wait_raw(&mut self, timeout_ms: u32) -> Result<RawDebugEvent, CoreError>;
    fn continue_raw(&mut self, plan: ContinuePlan, status: ContinueStatus) -> Result<(), CoreError>;
    // memory / context / BP — align with DebuggerCore over time
}

// Win32Backend: wraps WindowsDebugger (current path)
// ReplayBackend: feeds recorded RawDebugEvent list + scripted memory
```

**Replay minimum event set (Slice 1+ exit):**

- `CreateProcess` (image base, threads)
- `Exception` → Breakpoint / AccessViolation / SingleStep
- `LoadDll` / `UnloadDll` (optional early)
- `ExitProcess` / `ExitThread`

---

## PackerPlugin (Slice 3 stub + 3b-1 policy consult)

| Item | Location | Status |
|------|----------|--------|
| `PackerPlugin` + `IdentifyInput` / `PluginCtx` / advice types | `mida_core::plugin` | ✅ |
| `NullPackerPlugin` | `mida_core` | ✅ |
| `ThemidaPlugin` identify + `on_event` policy | `mida_packers_themida::plugin` | ✅ |
| CLI consults plugin after each wait | `cli/unpacker` + `ProcessSession::wait_engine` | ✅ 3b-1 |
| Full handler bodies in plugin | ScyllaHide / guard / AV / IAT / dump | ❌ still host |

Identify uses **host-prepared** `IdentifyInput` (section names, EP, arch) so
`mida-core` does not depend on `mida-pe`.

### PluginCtx session hints vs policy outputs (3b-1)

| Field | Direction | Role |
|-------|-----------|------|
| `is_dotnet`, `section0_is_plain_text` | host → plugin | Session config before loop |
| `preferred_base` | host → plugin | PE preferred ImageBase |
| `request_text_poll`, `request_close_handle_chain` | plugin → host | CreateProcess guard-path |
| `process_exited`, `phase`, `runtime_base`, `oep_rva` | plugin → host | Lifecycle / dump hints |

### What plugins must not do

- Import `mida-acceptance` or set verdicts
- Call pure PE rebuild with packer-specific Win32 inside pure modules
- Own process lifetime (kill/continue) outside engine advice
- Treat vault oracle SHA as success authority

### Themida today → plugin tomorrow

| Today (3b-1) | Tomorrow |
|--------------|----------|
| CreateProcess **path** (text-poll vs CloseHandle) | ✅ in `ThemidaPlugin::on_event` |
| ExitProcess → Done | ✅ plugin + host break |
| ScyllaHide, guard, OEP AV, IAT, dump | still `cli/unpacker` handlers |
| `LoopState` operational flags | gradual merge into plugin-local state |
| CLI | thin: args → engine + plugin select → dump path |

---

## Migration stages (after Slice 0)

| Stage | Work | Behavior change? |
|-------|------|------------------|
| **Slice 0** | API doc + handoff/roadmap pointers | No |
| **Slice 1** | Address newtypes in `mida-core::addr` + unit tests | No live |
| **Slice 2** | `RuntimeEngine` + `ReplayRuntimeEngine`; CLI still on `DebuggerCore` | No live |
| **Slice 2b** | Live adapter; optional CLI pump switch (behavior-preserving) | No if careful |
| **Slice 3** | `PackerPlugin` trait + Themida identify stub (no live drive) | No |
| **Slice 3b-1** | Wire `on_event` consult; CreateProcess path policy in plugin | Careful (same paths) |
| **Slice 3b-2** | OEP/IAT/dump milestones → `PluginCtx` (handlers still host) | Careful + smoke |
| **Slice 3b-3** | Loop decision flags (leave / short-wait / CloseHandle / timeouts) | Careful + smoke |
| **Slice 3b-4** | AV/text thresholds + dump-boundary `Va→Rva` / `skip_v3` | Careful + smoke |
| **Slice 3b-5** | `note_iat_trace_skipped` + extract `plugin_host` | Careful + smoke |
| **Slice 3b-6** | Unify IAT-complete + dump-enter + leave helper | Careful + smoke |
| **Slice 3b+** | Further policy if needed; keep handler bodies host | Careful + smoke |
| **Slice 4** | Expand replay skeleton (mem script / guard→OEP) | Test-only ✅ |

**Slice 0 exit criteria:**

- [x] Address type names and conversion rules written
- [x] Map current `DebuggerCore` / lifecycle / unpacker ownership
- [x] Sketch `RuntimeEngine`, backend, `PackerPlugin`
- [x] Explicit non-goals and migration stages

**Slice 1 exit criteria:**

- [x] `mida_core::{PreferredBase, RuntimeBase, Rva, Va, FileOffset}`
- [x] Conversion helpers + unit tests (including preferred≠runtime)
- [x] Docs updated; **no** required call-site migration yet

**Slice 2 exit criteria (partial):**

- [x] `RuntimeEngine` + `EngineEvent` in `mida-core`
- [x] `ReplayRuntimeEngine` + order/pending/continue unit tests
- [x] Synthetic create→guard_av→oep_bp→exit skeleton test
- [x] Live `DebuggerCoreEngine` adapter + unit tests
- [x] CLI `ProcessSession` pump migration + Origin legacy StructuralPass smoke

**Slice 3 stub exit criteria:**

- [x] `PackerPlugin` in `mida-core` (object-safe, no pe/acceptance deps)
- [x] `ThemidaPlugin` identify heuristics + unit tests
- [x] Explicit: CLI **not** controlled by plugin yet

**Slice 3b-1 exit criteria:**

- [x] `PluginCtx` session hints + policy flags (`request_text_poll`, …)
- [x] `ThemidaPlugin::on_event` owns CreateProcess path + ExitProcess Done
- [x] CLI `wait_engine` + post-wait `on_event` consult; Abort honored
- [x] CreateProcess host arm applies plugin flags (not local section-name branch)
- [x] Origin legacy smoke after 3b (`live_20260723-183940`, StructuralPass)
- [ ] Further handlers (OEP/IAT) still host-owned until later 3b slices

**Slice 3b-2 exit criteria:**

- [x] Milestone helpers on `PackerPlugin`: guard / OEP / IAT / dump
- [x] `PluginCtx.oep_rva` filled from host OEP VA via runtime/preferred base
- [x] CLI `sync_plugin_milestones` after each loop iter + post-loop
- [x] `dump_advice` logged at dump enter (pure still opt-in / prefer false)
- [x] post-attach path records OEP + dump phase
- [x] Origin smoke: identify Match, CloseHandle path, OEP RVA 0x13e0, dump_advice
- [x] R0B `StructuralPassBehaviorPending` on `live_20260723-183940`
- [ ] AV/IAT **handler bodies** remain host-owned (not moved)

**Slice 3b-3 exit criteria:**

- [x] `HostLoopFacts` + `PackerPlugin::refresh_loop_policy`
- [x] Decision flags: `prefer_short_wait`, `allow_close_handle_bp`,
      `request_leave_debug_loop`, `skip_v3_iat_trace`, timeout fields
- [x] CLI wait / leave / CloseHandle BP / text-poll idle / IAT monitor secs from plugin
- [x] `note_iat_trace_complete` + sticky leave reasons
- [x] Origin smoke `live_20260723-185129` StructuralPassBehaviorPending
      (identify 83, CloseHandle path, OEP RVA 0x13e0, pure=false)
- [ ] AV/IAT **bodies** still host-owned (deferred to 3b+ / later)

**Slice 3b-4 exit criteria:**

- [x] `PluginCtx` AV/text thresholds (retries / storm / min_nonzero)
- [x] `ThemidaPlugin::apply_session_defaults` writes historical constants
- [x] CLI `LoopState` + `av_handler` + text-poll use plugin thresholds
- [x] Dump entry via `RuntimeBase` + `Va::to_rva` (no raw `wrapping_sub`)
- [x] Post-loop skip V3 when `process_exited || skip_v3_iat_trace`
- [x] Origin smoke `live_20260723-185936` (EP 0x13e0, exit 0)
- [x] Lunlun smoke `live_20260723-190051_3b4` (EP 0x1656f4, exit 0)
- [ ] AV/IAT **bodies** still host-owned

**Slice 3b-5 exit criteria:**

- [x] `PackerPlugin::note_iat_trace_skipped` (vs complete) + unit tests
- [x] `ThemidaPlugin` override records phase on skip
- [x] `cli/unpacker/plugin_host.rs`: facts / refresh / sync / av_break
- [x] `AvAction::Break` → complete if IAT done else skip with reason
- [x] Origin smoke `live_20260723-194036` (EP 0x13e0, exit 0, full IAT path)
- [x] Lunlun smoke `live_20260723-194142_3b5` (EP 0x1656f4;
      `IAT v3 skipped reason=process_exited_skip_v3`)
- [ ] AV/IAT **bodies** still host-owned

**Slice 3b-6 exit criteria:**

- [x] `plugin_host::note_plugin_iat_complete` (SingleStep full-trace)
- [x] `plugin_host::enter_dump_phase` (post-attach + post-loop)
- [x] `plugin_host::plugin_leave_reason` (shared sticky leave)
- [x] Origin smoke `live_20260723-200918` (EP 0x13e0, exit 0)
- [x] Lunlun smoke `live_20260723-200918_3b6` (EP 0x1656f4, skip_v3)
- [ ] AV/IAT **bodies** still host-owned

**Slice 4 exit criteria:**

- [x] `ReplayMemory` sparse map + read/write on `ReplayRuntimeEngine`
- [x] `guard_oep_event_script` (create / LoadDll / guard AV / OEP BP / exit)
- [x] Finite wait on exhausted stream → `CoreError::Timeout`
- [x] Offline test: mem script + plugin milestones (guard / OEP / leave / skip_v3)
- [x] No live / CLI behavior change (test-only)

**R3-prep / R3-path-A (not R3 gate):**

- [x] `ThemidaPlugin` offline replay against `ReplayRuntimeEngine` + mem
- [x] `identify_record` + CLI uses it
- [x] `tools/_oreans_repeat_smoke.py` multi-run engineering harness
      (`r3_gate: false`; refuses `--claim-r3`)
- [x] Offline skip_v3 + dump after scanned OEP (Lunlun-shaped)
- [x] Harness EP/`--expect-ep` + R0B rollup from evidence logs
- [x] Engineering batch Origin+Lunlun ×3 `batch_20260723-201638_r3a`
- [x] R3-path-C Lunlun IAT: storm freeze + post-loop v3 → **336/352 (95%)**
      (`live_20260723-203635_lun_iat_v3defer`; Origin reg OK)
- [x] R3-path-D stability ×3 Origin+Lunlun (`batch_20260723-204853_r3d`;
      IAT 96%/95%; harness coverage rollup)
- [x] R3 close: Origin + Lunlun + **holdout** continuous **10×** +
      `validation_summary` task VNEXT-R3 (`batch_20260723-214718_r3c_gate`)
- See [VNEXT_R3_OREANS_PATH.md](VNEXT_R3_OREANS_PATH.md)

---

## Relationship to Phase 2 pure path

Pure rebuild remains a **dump emit option** inside host dump (`--pure-rebuild`).
R2 does not change emit defaults. Preferred vs runtime base rules above are the
same contract Phase2 fixed for pure emit.

---

## Validation when code lands

```text
cargo test -p mida-core          # lifecycle + future engine unit tests
cargo test -p mida-cli           # exit codes / gate vectors; live optional
cargo test --workspace --offline # MSVC + vault CARGO_TARGET_DIR
```

Live vault smokes stay evidence-only; not CI.
