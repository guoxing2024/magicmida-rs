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
        -TargetDir D:\MidaVault\scratch\cargo-target-route-w1 `
        -RuntimeAuthorityManifestPath D:\MidaVault\lab\evidence\adr7b_b4_binding_correction\authority\manifest.json `
        -RuntimeDllPath D:\MidaVault\lab\evidence\adr7b_b4_binding_correction\runtime\mida_antidebug_runtime.dll

    IMP-09-LIVE-PREP (P2): RuntimeAuthorityManifestPath / RuntimeDllPath are
    REQUIRED. They bind the compile-time MIDA_RUNTIME_AUTHORITY_DIGEST (SHA-256
    of the authority MANIFEST bytes) and MIDA_RUNTIME_SOURCE_REF into the build
    and record the runtime-authority chain in gto_cli_build_attestation.json.
#>
[CmdletBinding()]
param(
    [string]$TargetDir,
    [string]$AttestationOut,
    [string]$Profile = "debug",

    # IMP-09-LIVE-PREP (P2): runtime authority binding. BOTH ARE REQUIRED —
    # an authority-less live build reproduces the attempt_002
    # STRUCTURAL_PRECONDITION_MISSING failure (compile-time
    # MIDA_RUNTIME_AUTHORITY_DIGEST empty), so this script refuses to build
    # without them (fail-closed).
    [string]$RuntimeAuthorityManifestPath,
    [string]$RuntimeDllPath
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

# --- IMP-09-LIVE-PREP (P2): runtime authority binding ------------------
# The loader (crates/cli/src/unpacker/runtime_loader.rs) compares the
# compile-time MIDA_RUNTIME_AUTHORITY_DIGEST against the SHA-256 OF THE
# AUTHORITY MANIFEST BYTES (the manifest itself is the protected object;
# its `sha256` field binds the runtime DLL). The compile-time
# MIDA_RUNTIME_SOURCE_REF must equal the manifest `source_ref`
# (ADR-6 CORRECTION-2). Every mismatch fails closed HERE, before cargo runs.
if (-not $RuntimeAuthorityManifestPath) {
    throw 'RuntimeAuthorityManifestPath is REQUIRED: path to the audited authority manifest.json'
}
if (-not $RuntimeDllPath) {
    throw 'RuntimeDllPath is REQUIRED: path to the mida_antidebug_runtime.dll referenced by the manifest'
}
$authorityManifestPath = (Resolve-Path $RuntimeAuthorityManifestPath).Path
$runtimeDllResolvedPath = (Resolve-Path $RuntimeDllPath).Path
$shaAuthority = [System.Security.Cryptography.SHA256]::Create()
try {
    $manifestBytes = [System.IO.File]::ReadAllBytes($authorityManifestPath)
    $manifestSha256 = -join ($shaAuthority.ComputeHash($manifestBytes) | ForEach-Object { $_.ToString('x2') })
    $dllBytes = [System.IO.File]::ReadAllBytes($runtimeDllResolvedPath)
    $dllSha256 = -join ($shaAuthority.ComputeHash($dllBytes) | ForEach-Object { $_.ToString('x2') })
} finally {
    $shaAuthority.Dispose()
}
$dllSizeBytes = $dllBytes.Length
$manifestJson = Get-Content $authorityManifestPath -Raw | ConvertFrom-Json
if ($manifestJson.sha256 -ne $dllSha256) {
    throw ("authority manifest sha256 {0} != runtime DLL sha256 {1}" -f $manifestJson.sha256, $dllSha256)
}
if ($manifestJson.size_bytes -ne $dllSizeBytes) {
    throw ("authority manifest size_bytes {0} != runtime DLL size {1}" -f $manifestJson.size_bytes, $dllSizeBytes)
}
if (-not $manifestJson.source_ref) {
    throw 'authority manifest has no source_ref; MIDA_RUNTIME_SOURCE_REF cannot be bound'
}
$runtimeSourceRef = $manifestJson.source_ref
Write-Host "Runtime authority manifest            : $authorityManifestPath"
Write-Host "  manifest sha256 (-> MIDA_RUNTIME_AUTHORITY_DIGEST): $manifestSha256"
Write-Host "Runtime DLL                           : $runtimeDllResolvedPath"
Write-Host "  dll sha256 (manifest.sha256-bound)  : $dllSha256"
Write-Host "  source_ref (-> MIDA_RUNTIME_SOURCE_REF): $runtimeSourceRef"

# --- the single authorized build --------------------------------------
# option_env! reads these at compile time (tracked by cargo dep-info).
$env:MIDA_RUNTIME_AUTHORITY_DIGEST = $manifestSha256
$env:MIDA_RUNTIME_SOURCE_REF = $runtimeSourceRef
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

# --- IMP-09-LIVE-PREP (P2): post-build injection proof -----------------
# The injected constants must appear as literal strings in the built binary
# (option_env! bakes them into .rdata). Absent -> fail-closed, no attestation.
$binaryAscii = [System.Text.Encoding]::ASCII.GetString($bytes)
$compiledDigestPresent = $binaryAscii.Contains($manifestSha256)
$compiledSourceRefPresent = $binaryAscii.Contains($runtimeSourceRef)
if (-not $compiledDigestPresent) {
    throw 'MIDA_RUNTIME_AUTHORITY_DIGEST NOT found in the built binary (injection failed); refusing to attest'
}
if (-not $compiledSourceRefPresent) {
    throw 'MIDA_RUNTIME_SOURCE_REF NOT found in the built binary (injection failed); refusing to attest'
}
Write-Host "Compiled-in DIGEST present in binary   : $compiledDigestPresent"
Write-Host "Compiled-in SOURCE_REF present in binary: $compiledSourceRefPresent"

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
    runtime_authority   = [ordered]@{
        manifest_path                         = $authorityManifestPath
        manifest_sha256_compiled_in           = $manifestSha256
        runtime_dll_path                      = $runtimeDllResolvedPath
        runtime_dll_sha256                    = $dllSha256
        runtime_dll_size_bytes                = $dllSizeBytes
        runtime_source_ref_compiled_in        = $runtimeSourceRef
        compiled_digest_present_in_binary     = $compiledDigestPresent
        compiled_source_ref_present_in_binary = $compiledSourceRefPresent
        binding_note                          = 'MIDA_RUNTIME_AUTHORITY_DIGEST = SHA-256 of the authority MANIFEST bytes; manifest.sha256 binds the runtime DLL'
    }
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
