# ADR-6 benign host harness (loader/controller verification)

Real-process verification of the ADR-6 loader machinery in THIS benign
process (no protected sample, no ScyllaHide). Source kept OUT-OF-TREE at
D:/tmp/magicmida-adr6-target/benign_host_adr6.rs (a standalone rustc
program; the cargo test harness would compile any .rs under tests/).

## What it verifies

- The x64 remote-call thunk (fixed: sub rsp, 0x38) via CreateThread
  calling GetCurrentProcessId -> correct PID returned;
- 5 rounds of LoadLibrary -> Initialize (real PEB surfaces 002+003
  installed, attestation complete, AD-PROC-001 absent) -> Shutdown ->
  FreeLibrary with no handle growth (54 -> 58, +4 first-load fixed cost,
  zero growth afterwards);
- BENIGN_HOST_ADR6_OK.

## Build & run (out-of-tree)

```powershell
$env:CARGO_TARGET_DIR = "D:\tmp\magicmida-adr6-target"
cargo build -p mida-antidebug-runtime --release --offline
Copy-Item "$env:CARGO_TARGET_DIR\release\mida_antidebug_runtime.dll" "$env:CARGO_TARGET_DIR\"
rustc --edition 2021 "$env:CARGO_TARGET_DIR\benign_host_adr6.rs" -o "$env:CARGO_TARGET_DIR\benign_host_adr6.exe"
& "$env:CARGO_TARGET_DIR\benign_host_adr6.exe"
```

## Thunk fix record (benign-verified)

The initial thunk used `sub rsp, 0x28`; the 5th stack argument (arg4) was
written at rsp+0x20 (inside shadow space) and arg5 at rsp+0x28 (outside
the 0x28 frame), corrupting the caller frame and crashing the remote
thread. Fixed to `sub rsp, 0x38` (0x20 shadow + 2 stack args + alignment);
benign host proves the full thunk works end-to-end.
