@echo off
REM Test script with correct MSVC environment
REM Locates Visual Studio via vswhere (any edition/install), with the historical
REM VS 2022 Professional path as a fallback.

setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VCVARS64="

if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%i\VC\Auxiliary\Build\vcvars64.bat" (
            set "VCVARS64=%%i\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)

if not defined VCVARS64 (
    if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat" (
        set "VCVARS64=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
    )
)

if not defined VCVARS64 (
    echo ERROR: could not locate vcvars64.bat. Install the MSVC C++ build tools.
    exit /b 1
)

echo Initializing MSVC environment: %VCVARS64%
call "%VCVARS64%"

echo.
echo Running tests for mida-pe...
cargo test -p mida-pe --lib

echo.
echo Tests complete.
endlocal
