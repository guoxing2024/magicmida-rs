@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 -no_logo
if errorlevel 1 exit /b 1
set CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target
set CARGO_TERM_COLOR=never
cd /d "D:\Claude project\magicmida-rs"
echo Building mida-packers-ahk-gto, themida, mida-cli...
cargo build -p mida-packers-ahk-gto --offline > D:\MidaVault\scratch\build_ahkgto.log 2>&1
if errorlevel 1 (
  echo AHKGTO_BUILD_FAIL
  type D:\MidaVault\scratch\build_ahkgto.log
  exit /b 1
)
echo AHKGTO_BUILD_OK
cargo build -p mida-packers-themida --offline > D:\MidaVault\scratch\build_themida.log 2>&1
if errorlevel 1 (
  echo THEMIDA_BUILD_FAIL
  type D:\MidaVault\scratch\build_themida.log
  exit /b 1
)
echo THEMIDA_BUILD_OK
cargo build -p mida-cli --offline > D:\MidaVault\scratch\build_cli.log 2>&1
if errorlevel 1 (
  echo CLI_BUILD_FAIL
  type D:\MidaVault\scratch\build_cli.log
  exit /b 1
)
echo CLI_BUILD_OK
dir D:\MidaVault\scratch\cargo-target\debug\mida-cli.exe
endlocal
