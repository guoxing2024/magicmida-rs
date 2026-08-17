# ADR-5 benign host harness

Real-process verification of AD-PROC-002 (PEB.BeingDebugged) and
AD-PROC-003 (PEB.pShimData) via the runtime DLL C ABI, loaded into THIS
benign process (no protected sample, no ScyllaHide).

Source: kept OUT-OF-TREE at D:/tmp/magicmida-adr5-target/benign_host_adr5.rs
(the cargo test harness compiles every .rs under tests/, so the standalone
rustc program cannot live here as .rs; this README is the in-repo record).

## Rounds

- Round 1: real PEB state - BeingDebugged observed (0), install,
  attestation shows AD-PROC-002 installed; pShimData is 0xFFFF...
  (unreadable) so AD-PROC-003 fails honestly -> attestation incomplete
  (fail-closed). Shutdown restores BeingDebugged.
- Round 2: harness presets a valid readable pShimData (stack address),
  loads a fresh runtime instance; attestation shows BOTH surfaces
  installed with hook_failures=[]. Runtime is ObserveOnly for pShimData
  (never modifies it); harness restores the original pointer.

## Build & run (out-of-tree only)

```powershell
# 1. Build runtime cdylib with CARGO_TARGET_DIR out-of-tree
$env:CARGO_TARGET_DIR = "D:\tmp\magicmida-adr5-target"
cargo build -p mida-antidebug-runtime --release --offline
Copy-Item "$env:CARGO_TARGET_DIR\release\mida_antidebug_runtime.dll" "$env:CARGO_TARGET_DIR\"

# 2. Compile harness (dynamic loading; rustc + MSVC env)
rustc --edition 2021 crates\antidebug-runtime\tests\benign_host_adr5.rs -o "$env:CARGO_TARGET_DIR\benign_host_adr5.exe"

# 3. Run
& "$env:CARGO_TARGET_DIR\benign_host_adr5.exe"
```

Expected: BENIGN_HOST_ADR5_OK, handle delta <= 8, both rounds pass.

## Acceptance record (ADR-5)

Executed: round1 fail-closed path + round2 full-install path both pass;
handles base 54 final 58 (delta 4); BENIGN_HOST_ADR5_OK. No protected
sample, no ScyllaHide, no DLL/EXE committed.