@echo off
REM Engineering regression only — NOT R3 10x, NOT R4 re-gate, NOT VNEXT-BEH.
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 -no_logo
if errorlevel 1 exit /b 1
set CARGO_TARGET_DIR=D:\MidaVault\scratch\cargo-target
set CARGO_TERM_COLOR=never
cd /d "D:\Claude project\magicmida-rs"

echo === build mida-cli ===
cargo build -p mida-cli --offline
if errorlevel 1 exit /b 1

set PATH=%CARGO_TARGET_DIR%\debug;%PATH%

echo === dual_select unit ===
cargo test -p mida-cli --lib --offline dual_select
if errorlevel 1 exit /b 1

echo === Origin 1x ===
python tools\_oreans_repeat_smoke.py --cases origin_macro --count 1 --tag u_reg_origin --expect-ep origin_macro=0x13e0
set ORIG=%ERRORLEVEL%
echo ORIG_EXIT=%ORIG%

echo === GTO experimental 1x ===
python tools\_gto_live_smoke.py --cases gto_launcher --tag u_reg_gto --require-r0b
set GTO=%ERRORLEVEL%
echo GTO_EXIT=%GTO%

if not "%ORIG%"=="0" exit /b %ORIG%
if not "%GTO%"=="0" exit /b %GTO%
echo UNATTENDED_REGRESSION_OK
exit /b 0
