# Benign host harness (ADR-4-CORRECTION)

Repeated `LoadLibraryW` / `FreeLibrary` cycles of the MIDA anti-debug
`runtime DLL with a full lifecycle per round:

```text
LoadLibrary -> Initialize -> GetAttestation x2 -> Shutdown
-> (post-shutdown GetAttestation must return AlreadyShutdown) -> FreeLibrary
```

Purpose: verify real load/unload of the runtime DLL does not leak
resources (handles) and that module-level state resets between loads
(each round re-initializes successfully).

## Why this file is not a `#[test]`

The Rust test harness links the crate as an rlib. To exercise the C ABI
through a real DLL load/unload cycle, this program is compiled as a
standalone exe with `rustc` (no Cargo), using **dynamic loading**
(`LoadLibraryW`/`GetProcAddress`/`FreeLibrary`) so `FreeLibrary` truly
unloads the module between rounds - a static import would keep the DLL
resident and defeat the unload/reload semantics.

## Build & run (out-of-tree only)

Nothing in this directory is compiled by `cargo test`. The exe and the
runtime DLL are built to an out-of-tree target dir and never committed.

```powershell
# 1. Build the runtime cdylib (MSVC env)
powershell -ExecutionPolicy Bypass -File tools\_enter_msvc_env.ps1
cargo build -p mida-antidebug-runtime --release --offline

# 2. Stage DLL + import lib into the out-of-tree dir
$t = "D:\tmp\magicmida-adr4c-target"
Copy-Item target\release\deps\mida_antidebug_runtime.dll $t\

# 3. Compile the harness (dynamic loading - no import lib needed)
rustc --edition 2021 crates\antidebug-runtime\tests\benign_host.rs -o $t\benign_host.exe

# 4. Run
& "$t\benign_host.exe"
```

Expected result (5 rounds):

```text
baseline handles=N
round 0: handles N+4 (delta 4)   <- first DLL load fixed overhead
round 1..4: handles N+4 (delta 0) <- no growth
final handles=N+4
BENIGN_HOST_OK rounds=5
```

## ADR-4-CORRECTION acceptance record

Executed 2026 (ADR-4-CORRECTION): 5 rounds, handle count baseline 54,
final 58 (+4 first-load overhead, zero growth afterwards),
BENIGN_HOST_OK. No protected sample, no ScyllaHide, no DLL/EXE committed.
