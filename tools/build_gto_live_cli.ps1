<#
.SYNOPSIS
    Route W R0 (W0-A / W0-C): canonical GTO live-CLI build + attestation.

.DESCRIPTION
    The SINGLE authorized way to build the GTO live mida-cli binary. It always
    builds with `--features gto-product-recovery` (the feature the production GTO
    route requires) and emits a `gto_cli_build_attestation.json` that a live
    controller can verify before spawning an armed run.

    This removes the Route V R1 failure mode where the operator built the live
    CLI WITHOUT the GTO feature and the binary then failed at its own GTO gate
    before any dump work.

    NEVER lets an operator hand-assemble cargo arguments.

.PARAMETER TargetDir
    Cargo target dir for this build (e.g. D:\MidaVault\scratch\cargo-target-route-w1).
    Defaults to <repo>\target\route_w0.

.PARAMETER AttestationOut
    Output path for gto_cli_build_attestation.json. Defaults to
    <TargetDir>\gto_cli_build_attestation.json.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools/build_gto_live_cli.ps1 `
        -TargetDir D:\MidaVault\scratch\cargo-target-route-w1
#>
[CmdletBinding()]
param(
    [string]$TargetDir,
    [string]$AttestationOut,
    [string]$Profile = "debug"
)

$ErrorActionPreference = 'Stop'

# --- locate VS dev env ------------------------------------------------
$vsdev = 'C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $vsdev)) {
    throw "VsDevCmd.bat not found: $vsdev"
}
$envTmp = Join-Path $env:TEMP ("vsdev_env_{0}.txt" -f [guid]::NewGuid().ToString('N'))
try {
    $cmd = "`"$vsdev`" -arch=amd64 -host_arch=amd64 -no_logo >nul 2>&1 && set > `"$envTmp`""
    cmd /c $cmd | Out-Null
    if (-not (Test-Path $envTmp)) { throw 'VsDevCmd did not emit env dump' }
    Get-Content $envTmp | ForEach-Object {
        if ($_ -match '^(.*?)=(.*)$') {
            $name = $Matches[1]; $val = $Matches[2]
            if ($name -in @('PROMPT')) { return }
            Set-Item -Path "Env:$name" -Value $val
        }
    }
} finally {
    if (Test-Path $envTmp) { Remove-Item $envTmp -Force }
}
if (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
    throw 'link.exe still not on PATH after VsDevCmd'
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot

if (-not $TargetDir) { $TargetDir = Join-Path $repoRoot "target\route_w0" }
if (-not $AttestationOut) { $AttestationOut = Join-Path $TargetDir 'gto_cli_build_attestation.json' }
New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null

$HEAD = (git rev-parse HEAD).Trim()
$cargoVersion = (cargo --version).Trim()
$rustcVersion = (rustc --version).Trim()
$cargoCommand = "cargo build -p mida-cli --features gto-product-recovery --profile $Profile --offline"

Write-Host "Building GTO live CLI at HEAD $HEAD"
Write-Host "Command: $cargoCommand"

# --- the single authorized build --------------------------------------
$env:CARGO_TARGET_DIR = $TargetDir
$profileArg = if ($Profile -eq 'release') { '--release' } else { '' }
$cargoArgs = @('build', '-p', 'mida-cli', '--features', 'gto-product-recovery')
if ($profileArg) { $cargoArgs += $profileArg }
$cargoArgs += '--offline'
& cargo @cargoArgs
if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit $LASTEXITCODE" }

$binaryRel = if ($Profile -eq 'release') { 'release\mida-cli.exe' } else { 'debug\mida-cli.exe' }
$binaryPath = Join-Path $TargetDir $binaryRel
if (-not (Test-Path $binaryPath)) { throw "built binary not found: $binaryPath" }

# --- capability probe (W0-B) ------------------------------------------
$probeOutput = (& $binaryPath '--build-capabilities-json' 2>&1 | Out-String).Trim()
$capJson = $probeOutput | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw "capability probe failed: $probeOutput" }
$gtoCapability = $capJson.gto_product_recovery -eq $true

# --- attestation (W0-C) ----------------------------------------------
$bytes = [System.IO.File]::ReadAllBytes($binaryPath)
$sha = [System.Security.Cryptography.SHA256]::Create()
$hash = $sha.ComputeHash($bytes)
$shaHex = -join ($hash | ForEach-Object { $_.ToString('x2') })
$size = $bytes.Length

$attestation = [ordered]@{
    schema_version      = 'mida.build-attestation/v1'
    baseline_commit     = $HEAD
    binary_path         = $binaryPath
    binary_sha256       = $shaHex
    binary_size         = $size
    cargo_package       = 'mida-cli'
    cargo_profile       = $Profile
    requested_features  = @('gto-product-recovery')
    capability_probe_output = $probeOutput
    gto_product_recovery = $gtoCapability
    cargo_command       = $cargoCommand
    cargo_version       = $cargoVersion
    rustc_version       = $rustcVersion
    target_dir          = $TargetDir
    created_utc         = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$attestation | ConvertTo-Json -Depth 5 | Out-String | Set-Content -Path $AttestationOut -Encoding ascii

Write-Host "=== BUILD ATTESTATION ==="
Get-Content $AttestationOut
Write-Host "Binary: $binaryPath"
Write-Host "Size: $size bytes  SHA256: $shaHex"
Write-Host "gto_product_recovery: $gtoCapability"

if (-not $gtoCapability) {
    throw "gto_product_recovery is FALSE in built binary — cannot produce an armed-ready GTO live CLI"
}
