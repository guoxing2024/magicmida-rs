@echo off
REM Build script with correct MSVC environment
REM This ensures MSVC's link.exe is used instead of Git's
REM NOTE: Requires Visual Studio 2022 Professional (vcvars64 at
REM   C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat)
REM   Adjust the path below if your VS edition/install differs.

echo Initializing MSVC environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

echo.
echo Building mida-cli...
cargo build --release -p mida-cli

echo.
echo Build complete. Check target\release\mida-cli.exe
pause