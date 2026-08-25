# R5-R3 evidence runner: imports the MSVC x64 dev environment (vcvars64),
# strips Git usr/bin from PATH (its link.exe shadows the MSVC linker),
# then runs the requested cargo command.
# Usage: pwsh -File run_cargo.ps1 <cargo args...>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$CargoArgs
)

$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) {
    $vcvars = "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars64.bat"
}

# Capture the env vcvars64.bat sets, then apply it to this process.
$envBlock = cmd /c "`"$vcvars`" >nul 2>&1 && set" | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        [pscustomobject]@{ Name = $matches[1]; Value = $matches[2] }
    }
}
foreach ($kv in $envBlock) {
    [Environment]::SetEnvironmentVariable($kv.Name, $kv.Value, 'Process')
}

# Strip Git usr/bin entries so link.exe resolves to the MSVC linker,
# then force the MSVC host dir to the FRONT of PATH (first match wins).
$cleanPath = ($env:Path -split ';' | Where-Object { $_ -notmatch '\\Git\\usr\\bin($|\\)' }) -join ';'
$env:Path = "$msvcHost;$sdkBin;$cleanPath"
$env:VSLANG = "1033"

Write-Host "link.exe -> $((Get-Command link.exe -ErrorAction SilentlyContinue).Source)"
Write-Host "LIB -> $env:LIB"
& cargo @CargoArgs
exit $LASTEXITCODE
