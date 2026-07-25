# -*- coding: utf-8 -*-
from pathlib import Path

dirp = Path(r"D:\MidaVault\lab\evidence\origin_macro\live_20260723-132326")
notes = """# Origin live unpack success — live_20260723-132326

## Result

- **CLI exit:** 0
- **candidate size:** 13746176
- **candidate sha256:** 0c0923e34cb8571f09d954047880c75388ed062157ea384c6613f0c93a58efbb
- **R0B verdict:** StructuralPassBehaviorPending (exit 0, failures=[])
- **oracle:** present as observation only (legacy fe92f992…); not authority

## Command

```
mida-cli /unpack origin_protected.exe -o origin_unpacked.exe --data-sections --no-shrink -v
```

CLI: `D:\\MidaVault\\scratch\\cargo-target\\debug\\mida-cli.exe` (built post CONTROL|INTEGER SetThreadContext fix)

## Stage path (success)

1. ScyllaHide InjectorCLIx64 inject OK
2. Section names blank → CloseHandle HW BP fallback (expected for wiped names)
3. Virtualized OEP retries then **OEP found** at runtime VA (log: `OEP found — letting program execute…`)
4. IAT multi-block: **305 slots**, span size 0x988
5. IAT single-step trace completed (many slots traced)
6. Dump written: 17 sections; EP structure gate exec_ok=true; TLS present
7. Hardcoded-address fix: 2913 patches in writable sections
8. GOOD: Unpacked + Done

## What unblocked this run

### Pre-fix failures

| run | fail stage | error |
|-----|------------|-------|
| live_20260723-130856 | virtualized OEP retry | SetThreadContext ERROR_NOACCESS → EXIT |
| live_20260723-132013 | IAT v3-trace slot 0 | `trace_one_slot set_thread_context` 0x800703E6 |

### Fix (core)

`crates/core/src/windows_debugger.rs`:

- `get_thread_context`: prefer CONTEXT_CONTROL|INTEGER; fallback CONTEXT_ALL
- `set_thread_context`: force CONTROL|INTEGER (strip XSAVE/ALL); OpenThread with GET|SET|SUSPEND; SuspendThread retry; fall back to CREATE_THREAD table handle
- `enable_single_step`: CONTROL-only Get/Set for TF

Also earlier (cli path):

- `session::set_thread_context_control` Suspend retry
- `av_handler` soft-fail virtualized OEP SetThreadContext
- `generic.rs` blank section-name fallback

## Residual risks (not Accepted)

- R0B never emits Accepted (no behavioral engine)
- Oracle size/sha differ from candidate by design (legacy operator dump vs this pipeline)
- Drop cleanup wait TIMEOUT after success (cosmetic; process terminate ok)
- `.winlice` / `.boot` still present in dump (no shrink; data-sections on)
- Section names still blank in many original sections (expected post-Themida)
- x86 ScyllaHide hashes still placeholders (this sample is x64)
- pure-rebuild path not exercised this run
- single smoke, not 10× Oreans family gate

## Next

1. Lunlun live unpack + R0B same recipe
2. Origin ×N smoke for flakiness of SetThreadContext path
3. Optional `--pure-rebuild` structural compare on same capture
4. Keep vault evidence; do not git PE binaries
"""
(dirp / "notes.md").write_text(notes, encoding="utf-8")
# lightweight sha file
(dirp / "candidate.sha256").write_text(
    "0c0923e34cb8571f09d954047880c75388ed062157ea384c6613f0c93a58efbb  origin_unpacked.exe\n",
    encoding="utf-8",
)
print("wrote", dirp / "notes.md")
