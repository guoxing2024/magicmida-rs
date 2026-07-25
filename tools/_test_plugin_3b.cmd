@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 -no_logo
if errorlevel 1 exit /b 1
set CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target
set CARGO_TERM_COLOR=never
cd /d "D:\Claude project\magicmida-rs"
echo === mida-core plugin + runtime_engine tests ===
cargo test -p mida-core --lib plugin --offline -- --nocapture
if errorlevel 1 exit /b 1
cargo test -p mida-core --lib runtime_engine --offline -- --nocapture
if errorlevel 1 exit /b 1
echo === mida-packers-themida plugin tests (incl R3-prep offline replay) ===
cargo test -p mida-packers-themida --lib plugin --offline -- --nocapture
if errorlevel 1 exit /b 1
echo === mida-cli build ===
cargo build -p mida-cli --offline
if errorlevel 1 (
  echo CLI_BUILD_FAIL
  exit /b 1
)
echo ALL_OK
endlocal
