@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
cd /d "D:\Claude project\magicmida-rs"

echo === Origin 1x engineering smoke (not R3) ===
python tools\_oreans_repeat_smoke.py --cases origin_macro --count 1 --tag p1_origin_reg --expect-ep origin_macro=0x13e0
set ORIG=%ERRORLEVEL%
echo ORIG_EXIT=%ORIG%

echo === GTO experimental 1x engineering smoke (not R4 re-gate) ===
python tools\_gto_live_smoke.py --cases gto_launcher --tag p1_gto_reg --require-r0b
set GTO=%ERRORLEVEL%
echo GTO_EXIT=%GTO%

if not "%ORIG%"=="0" exit /b %ORIG%
if not "%GTO%"=="0" exit /b %GTO%
exit /b 0
