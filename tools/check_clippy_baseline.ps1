# check_clippy_baseline.ps1 — WO-23 warn-level lint gate.
#
# Runs `cargo clippy --workspace --lib --bins` (JSON), counts warnings by
# lint name, and fails if any count exceeds the `_clippy_baseline` file in
# the repository root. Baseline counts are MONOTONIC (may only go down).
#
# Usage (from repo root, inside the MSVC env):
#   powershell -File tools/check_clippy_baseline.ps1
param(
    [string]$BaselinePath = (Join-Path $PSScriptRoot '..\_clippy_baseline')
)
$ErrorActionPreference = 'Stop'

$baselinePath = [System.IO.Path]::GetFullPath($BaselinePath)
if (-not (Test-Path $baselinePath)) {
    Write-Error "baseline file not found: $baselinePath"
    exit 2
}

# Parse baseline "lint = count" lines.
$baseline = @{}
$total = 0
foreach ($line in [System.IO.File]::ReadAllLines($baselinePath)) {
    $t = $line.Trim()
    if ($t -eq '' -or $t.StartsWith('#')) { continue }
    if ($t -match '^([A-Za-z_0-9:]+)\s*=\s*(\d+)\s*$') {
        $baseline[$Matches[1]] = [int]$Matches[2]
        if ($Matches[1] -eq 'TOTAL') { $total = [int]$Matches[2] }
    }
}
if ($baseline.Count -eq 0) {
    Write-Error "no baseline entries parsed from $baselinePath"
    exit 2
}

Write-Host "Running cargo clippy --workspace --lib --bins (JSON)..."
# cargo writes progress to stderr; under $ErrorActionPreference='Stop' that
# raises NativeCommandError per line, so relax it around the native call and
# capture stderr to a temp file.
$savedEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$errFile = [System.IO.Path]::GetTempFileName()
$output = & cargo clippy --workspace --lib --bins --message-format=json 2>$errFile | Out-String
$code = $LASTEXITCODE
$ErrorActionPreference = $savedEAP
$stderr = if (Test-Path $errFile) { [System.IO.File]::ReadAllText($errFile) } else { '' }
Remove-Item $errFile -ErrorAction SilentlyContinue
if ($code -ne 0) {
    # clippy may exit non-zero on deny-level lints; still parse warnings.
    Write-Host "NOTE: cargo clippy exited $code (deny-level lint present)."
}

# Count warnings by lint code.
$counts = @{}
foreach ($line in $output -split "`r?`n") {
    $t = $line.Trim()
    if (-not $t.StartsWith('{')) { continue }
    try {
        $d = $t | ConvertFrom-Json -ErrorAction Stop
    } catch { continue }
    if ($d.reason -ne 'compiler-message') { continue }
    $msg = $d.message
    if ($msg.level -ne 'warning') { continue }
    $code = $msg.code.code
    if (-not $code) { $code = 'uncategorized' }
    if ($counts.ContainsKey($code)) { $counts[$code]++ } else { $counts[$code] = 1 }
}

# Compare.
$failures = @()
foreach ($key in $baseline.Keys) {
    $exp = $baseline[$key]
    $got = 0
    if ($counts.ContainsKey($key)) { $got = $counts[$key] }
    if ($got -gt $exp) {
        $failures += "${key}: baseline=$exp got=$got"
    }
}
# New lint names not in baseline are also failures (regressions).
$newLints = @()
foreach ($key in $counts.Keys) {
    if (-not $baseline.ContainsKey($key)) {
        $newLints += "${key}=$($counts[$key])"
    }
}

if ($failures.Count -gt 0 -or $newLints.Count -gt 0) {
    Write-Host "FAIL: clippy warn baseline exceeded."
    foreach ($f in $failures) { Write-Host "  over baseline: $f" }
    foreach ($n in $newLints) { Write-Host "  new lint (not in baseline): $n" }
    exit 1
}
Write-Host "OK: clippy warn baseline holds (TOTAL baseline=$total)."
exit 0
