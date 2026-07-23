@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64
if errorlevel 1 exit /b 1
cd /d "D:\Claude project\magicmida-rs"
cargo test -p mida-acceptance --offline %*
exit /b %ERRORLEVEL%
