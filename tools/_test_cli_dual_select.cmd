@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
cd /d "D:\Claude project\magicmida-rs"
cargo test -p mida-cli --lib --offline dual_select
if errorlevel 1 exit /b 1
cargo test -p mida-cli --lib --offline selected_
if errorlevel 1 exit /b 1
cargo test -p mida-cli --lib --offline select_
exit /b %ERRORLEVEL%
