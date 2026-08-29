@echo off
REM Initialize an MSVC link.exe environment without VsDevCmd/vcvars64
REM (both are blocked in some sandboxed shells). Resolves the MSVC toolset and
REM Windows SDK by globbing their version directories instead of hardcoding a
REM version, then exports LIB/INCLUDE and pins the linker for cargo so a
REM Git-Bash PATH cannot shadow link.exe with GNU coreutils `link`.
REM
REM Usage:  call tools\_enter_msvc_env.cmd  &&  cargo test --workspace --offline

set "MIDA_VS_ROOT="
for /d %%i in ("%ProgramFiles%\Microsoft Visual Studio\2022\*") do (
    if exist "%%i\VC\Tools\MSVC" set "MIDA_VS_ROOT=%%i"
)
if not defined MIDA_VS_ROOT (
    echo ERROR: no Visual Studio 2022 install with VC tools found. 1>&2
    exit /b 1
)

set "MIDA_MSVC="
for /d %%i in ("%MIDA_VS_ROOT%\VC\Tools\MSVC\*") do set "MIDA_MSVC=%%i"
if not defined MIDA_MSVC (
    echo ERROR: no MSVC toolset under %MIDA_VS_ROOT%\VC\Tools\MSVC. 1>&2
    exit /b 1
)

set "MIDA_KIT=%ProgramFiles(x86)%\Windows Kits\10"
set "MIDA_SDK="
for /d %%i in ("%MIDA_KIT%\Lib\10.*") do set "MIDA_SDK=%%~nxi"
REM %MIDA_KIT% contains literal parentheses ("Program Files (x86)"), which would
REM close a parenthesized IF block at parse time -- keep this check paren-free.
if defined MIDA_SDK goto :sdk_ok
echo ERROR: no Windows 10/11 SDK lib directory found under the Windows Kits root. 1>&2
exit /b 1
:sdk_ok

set "PATH=%MIDA_MSVC%\bin\Hostx64\x64;%MIDA_KIT%\bin\%MIDA_SDK%\x64;%PATH%"
set "LIB=%MIDA_MSVC%\lib\x64;%MIDA_KIT%\Lib\%MIDA_SDK%\um\x64;%MIDA_KIT%\Lib\%MIDA_SDK%\ucrt\x64"
set "INCLUDE=%MIDA_MSVC%\include;%MIDA_KIT%\Include\%MIDA_SDK%\ucrt;%MIDA_KIT%\Include\%MIDA_SDK%\um;%MIDA_KIT%\Include\%MIDA_SDK%\shared"
set "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=%MIDA_MSVC%\bin\Hostx64\x64\link.exe"

REM Incremental compilation reproducibly ICEs rustc 1.97.1 on mida-disasm in
REM this workspace once the incremental cache has been touched by an aborted
REM build ("the compiler unexpectedly panicked", crates\disasm\src\lib.rs).
REM Non-incremental builds are unaffected, so pin it off for every session.
set "CARGO_INCREMENTAL=0"

echo [msvc-env] toolset : %MIDA_MSVC%
echo [msvc-env] sdk     : %MIDA_SDK%
echo [msvc-env] linker  : %CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER%
