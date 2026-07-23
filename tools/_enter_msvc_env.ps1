# Import VS 2022 x64 toolchain env into current PowerShell session.
$ErrorActionPreference = 'Stop'
$vsdev = 'C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $vsdev)) {
    throw "VsDevCmd.bat not found: $vsdev"
}
$tmp = Join-Path $env:TEMP ("vsdev_env_{0}.txt" -f [guid]::NewGuid().ToString('N'))
try {
    $cmd = "`"$vsdev`" -arch=amd64 -host_arch=amd64 -no_logo >nul && set > `"$tmp`""
    cmd /c $cmd | Out-Null
    if (-not (Test-Path $tmp)) { throw 'VsDevCmd did not emit env dump' }
    Get-Content $tmp | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            $name = $Matches[1]
            $val = $Matches[2]
            # Skip these to avoid breaking PowerShell internals
            if ($name -in @('PROMPT')) { return }
            Set-Item -Path "Env:$name" -Value $val
        }
    }
} finally {
    if (Test-Path $tmp) { Remove-Item $tmp -Force }
}
$link = Get-Command link.exe -ErrorAction SilentlyContinue
if (-not $link) { throw 'link.exe still not on PATH after VsDevCmd' }
Write-Host "MSVC env ready: $($link.Source)"
