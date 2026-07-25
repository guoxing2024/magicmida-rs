# -*- coding: utf-8 -*-
from __future__ import annotations

from datetime import datetime
from pathlib import Path

notes = """# Origin Phase-1 Live Unpack Diagnosis

- run_window: 2026-07-23 (local)
- sample: origin_macro (Oreans/Themida V3, PE32+)
- protected sha256: 1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7
- size: 5232656

## Static PE facts (protected)

- machine=0x8664, optional_magic=0x20b (PE32+)
- entry_rva=0x8c8058, preferred_image_base=0x140000000
- number_of_sections=16
- all section names blanked/spaces (no .text string)
- R0B protected_input: Rejected (exception_no_raw; directory_start_unmapped DD3 0x8bac58)
- R0B legacy_oracle: StructuralPassBehaviorPending (exit 0)

## Live unpack path (pre-fix)

- CLI: D:\\\\MidaVault\\\\scratch\\\\cargo-target\\\\debug\\\\mida-cli.exe
- evidence: live_20260723-130856
- profile: OreansClassic, oep_policy=Captured, container_restore=Off
- ScyllaHide InjectorCLIx64 + HookLibraryx64: injection completed successfully
- early decision: Section 0 is NOT .text — using CloseHandle HW BP chain (name wipe)
- failure pin: first Possible OEP / virtualized OEP path
  - is_oep_virtualized true
  - retries under cap then SetThreadContext ERROR_NOACCESS 0x800703E6
  - loop treated as fatal then EXIT_PROCESS
- duration: few seconds after many LoadDll events

## Generic-unpack path (pre-fix)

- failed immediately: required .text by name; blank section names; exit 1
- no poll/dump reached

## Root-cause ranking

1. P0 runtime: virtualized-OEP recovery depends on SetThreadContext Rip/Rsp rewrite; Win11 returns 0x800703E6.
2. P0 product assumptions: code range = pe_sections[0] + base_of_data; names not trusted (OK for Oreans live; broken for generic-unpack pre-fix).
3. P1 product: post-OEP and FTraceMSVCOEP also hard-failed on SetThreadContext.
4. P1 env: ScyllaHide x86 hashes still placeholders; x64 live inject succeeded this run.
5. Not root cause: pure-rebuild / R1 PE — Origin never reached dump.

## Code changes applied this segment

1. session::set_thread_context_control — force CONTEXT_CONTROL; SuspendThread + one retry
2. av_handler virtualized OEP / FTraceMSVCOEP / post-OEP — soft-fail on SetThreadContext
3. generic.rs — blank-name fallback: .text* -> first executable/code section -> section[0]

## Expected next smoke

- rebuild CLI (done)
- re-run Origin live
- success criteria (smoke, not Accepted): no FATAL SetThreadContext abort; reach OEP found/dump attempt or structured stage failure past virtualized-OEP

## Gate meaning for perfect unpack

- Protected Rejected is expected for packed input.
- Perfect = candidate StructuralPassBehaviorPending then later Behavioral Accepted; not oracle byte-identity.
"""


def main() -> None:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    dirp = Path(r"D:/MidaVault/lab/evidence/origin_macro") / f"phase1_diag_{run_id}"
    dirp.mkdir(parents=True, exist_ok=True)
    path = dirp / "notes.md"
    path.write_text(notes, encoding="utf-8")
    print(dirp)
    print(path.stat().st_size)


if __name__ == "__main__":
    main()
