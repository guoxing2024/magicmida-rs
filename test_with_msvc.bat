@echo off
REM Test script with correct MSVC environment
REM NOTE: Requires Visual Studio 2022 Professional (vcvars64 at
REM   C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat)
REM   Adjust the path below if your VS edition/install differs.

echo Initializing MSVC environment...
call "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"

echo.
echo Running tests for mida-pe...
cargo test -p mida-pe --lib

echo.
echo Tests complete.
pause