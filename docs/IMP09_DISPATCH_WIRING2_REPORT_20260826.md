# IMP-09-DISPATCH-WIRING-2 - Carrier channel completion report

**Work order**: WORK_ORDER_IMP-09-DISPATCH-WIRING-2_20260826.md
**Baseline HEAD**: 645459c (branch codex/imp09-carrier-r5-r2)
**Status**: COMPLETE - CARRIER_CHANNEL=PROVEN, T1-T18 ALL PASS, workspace 2720/0/2 green

---

## 1. Diff summary (git diff --stat)

```
 crates/cli/src/unpacker/antidebug_controller.rs |  23 ++++-
 crates/cli/src/unpacker/mod.rs                  |  31 ++++---
 crates/cli/src/unpacker/runtime_loader.rs       |   9 ++
 crates/cli/src/unpacker/walker_dispatch.rs      | 109 +++++++++++++++++++++
 docs/IMP09_DISPATCH_BRIDGE_DESIGN_20260825.md   |  27 ++++--
 5 files changed, 178 insertions(+), 21 deletions(-)
```

| File | Change |
|---|---|
| antidebug_controller.rs | LoaderResult: add sealed field `walker_exports: Option<MidaExportsV2>`, ctor 7th arg, `pub fn walker_exports()` accessor, import MidaExportsV2; 2 test ctor calls get extra `None` |
| runtime_loader.rs | `run_runtime_loader` tail writes `Some(loaded.exports)` into the new field (verify/provenance order unchanged); 1 test ctor call updated |
| mod.rs | post-attach site: exports from `loader_outcome.as_ref().ok().and_then(\|l\| l.walker_exports())`; CREATE_PROCESS site: keep None (runs before loader) with updated comment |
| walker_dispatch.rs | T17 + T18 with env lock (reuses T16 ENV_LOCK); build_loader_result helper ctor updated |
| IMP09_DISPATCH_BRIDGE_DESIGN_20260825.md | Section D gap paragraph rewritten to "closed by WIRING-2" |

## 2. Exit gate ini (measured)

```ini
CARRIER_CHANNEL = PROVEN
T17_T18 = ALL_PASS
WORKSPACE_GREEN = true
R5_SEMANTICS_UNCHANGED = true
LIVE_AUTHORIZED = false
```

## 3. Verification

### 3.1 walker_dispatch tests
T1-T18: 18 passed; 0 failed; 0 ignored; RC=0.
- T17: `LoaderResult.walker_exports()` is `Some` and `walker_execute == module_base + file_rva` (dual-sealed cross-check input consistent). Bare LoaderResult without channel stays `None`.
- T18: gate open + channel carriers complete -> `try_build_live_dispatch_bridge_boxed` returns `Some(bridge)` and `cross_check_passes(0x7FF600000000 + 0x2040)`; channel missing / loader missing -> `None`.

Raw: `evidence_staging/WIRING2/walker_dispatch_test_raw.txt`

### 3.2 workspace full
2720 passed; 0 failed; 2 ignored; RC=0 (~60 test result blocks; same 3 baseline warnings as WIRING-1, no new ones).

Raw: `evidence_staging/WIRING2/workspace_test_raw.txt`

## 4. Remaining structural gap (honest record)

CREATE_PROCESS construction site (`mod.rs` ~L1252) still passes `None`: that site runs BEFORE the runtime loader (`AntidebugController` is constructed when `loader_result` is not yet produced; loader runs at ~L1343), so both carriers are structurally unavailable there. Per the "missing carrier -> keep None + report" guard, it stays fail-closed. Wiring the WIRING-2 channel into that site would need a deferred/rebuild seam on `AntidebugController` (construct with placeholder `None`, then after `set_loader_result` re-run `try_build_live_dispatch_bridge_boxed` and replace `options.walker_dispatch`) - a new work order, out of scope here.

## 5. Work order guard compliance

- R5 semantics unchanged: 3 cargo warnings identical to WIRING-1 baseline (AbortState unused import, oep_evidence.rs:622 redundant parens, post_attach.rs:400 dump_timing unused var). No new warning/error.
- `runner_preflight.rs`: 0 changes (grep).
- Authority chain not relaxed: T15 mismatch still BAD_PARAMS; T17 proves the new channel is consistent with the existing file-side RVA carrier.
- No live sample execution: only `cargo test`; zero real process activity.
- Correction cap 1: not triggered (T18 compile error fixed once and green on retry; no second correction).

## 6. Evidence index

- `evidence_staging/WIRING2/walker_dispatch_test_raw.txt` - T1-T18 raw + RC=0
- `evidence_staging/WIRING2/workspace_test_raw.txt` - workspace raw + RC=0 (2720/0/2)
- `docs/IMP09_DISPATCH_BRIDGE_DESIGN_20260825.md` Section D - "closed by WIRING-2"
- `git diff` - 5 files, 178+/21-

## 7. Test runner environment

MSVC environment built manually (bypassing vcvars setlocal trap; see WIRING-1 report for rationale):
PATH = `<MSVC>/bin/Hostx64/x64` + `<KITS>/bin/<SDK>/x64` with Git `usr/bin` and `mingw64/bin` stripped
LIB = MSVC `lib/x64` + Windows Kits `Lib/<SDK>/um/x64` + `Lib/<SDK>/ucrt/x64`
INCLUDE = MSVC `include` + Windows Kits `Include/<SDK>/{ucrt,um,shared}`
Helpers retained at `evidence_staging/WIRING2/_run_*.py` for replay; not part of the production delivery.
