# VNEXT-R2 Runtime / Event Engine

Status: **Slice 2 partial** (2026-07-23) — address newtypes + `RuntimeEngine`
trait + pure `ReplayRuntimeEngine`. Live CLI still uses `DebuggerCore` directly.
Prerequisites: R0B + R1 closed; Phase2 pure opt-in with flip=**No**.

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
| Live adapter over `WindowsDebugger` | ⏳ later (wire CLI without behavior change) |
| `backend_mut()` on trait | deferred (replay has no mem/BP surface yet) |

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

## PackerPlugin trait (sketch)

```rust
pub trait PackerPlugin {
    fn family_id(&self) -> &'static str;
    fn identify(&self, pe: &PeView) -> IdentifyResult;

    /// Called after CreateProcess / module loads; may install BPs / guards.
    fn on_event(&mut self, ctx: &mut PluginCtx, ev: &EngineEvent) -> PluginAdvice;

    /// Advise when to dump and with which host dump options.
    fn dump_advice(&self, ctx: &PluginCtx) -> Option<DumpAdvice>;
}

pub enum PluginAdvice {
    Continue(ContinueStatus),
    /// Request engine to stop pump for IAT/dump phase (OEP found, etc.)
    Transition(UnpackPhase),
    Abort(PluginError),
}

pub enum UnpackPhase {
    Observe,
    GuardActive,
    OepCandidate,
    IatTrace,
    Dump,
    Done,
}
```

### What plugins must not do

- Import `mida-acceptance` or set verdicts
- Call pure PE rebuild with packer-specific Win32 inside pure modules
- Own process lifetime (kill/continue) outside engine advice
- Treat vault oracle SHA as success authority

### Themida today → plugin tomorrow

| Today | Tomorrow |
|-------|----------|
| `cli/unpacker` installs ScyllaHide, guard, OEP, IAT | `OreansPlugin` / `ThemidaPlugin` methods |
| `LoopState` flags | plugin-local state |
| `generic_unpack` / profiles | second plugin or profile adapter |
| CLI | thin: args → engine + plugin select → dump path |

---

## Migration stages (after Slice 0)

| Stage | Work | Behavior change? |
|-------|------|------------------|
| **Slice 0** | API doc + handoff/roadmap pointers | No |
| **Slice 1** | Address newtypes in `mida-core::addr` + unit tests | No live |
| **Slice 2** | `RuntimeEngine` + `ReplayRuntimeEngine`; CLI still on `DebuggerCore` | No live |
| **Slice 2b** | Live adapter; optional CLI pump switch (behavior-preserving) | No if careful |
| **Slice 3** | Extract Themida policy behind `PackerPlugin` | No if careful |
| **Slice 4** | Expand replay skeleton (mem script / guard→OEP) | Test-only |

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
- [ ] Live `DebuggerCore` adapter / CLI pump migration

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
