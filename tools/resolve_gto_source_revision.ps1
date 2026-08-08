<#
.SYNOPSIS
    Windows entry point for the manifest-pinned GTO sample revision resolver.

.DESCRIPTION
    Locates the repository and the Python stdlib core
    (tools/_resolve_gto_source_revision.py), forwards all arguments verbatim,
    and returns the Python core's exit code unchanged. This wrapper does NOT
    re-implement any lenient identity logic and never starts a sample.

.PARAMETER ManifestPath
    Path to the source-controlled case manifest JSON.

.PARAMETER VaultRoot
    Content-addressed external vault root.

.PARAMETER EvidenceDir
    Output directory for resolved_source.json (required).

.PARAMETER SourcePath
    Mutable acquisition locator (optional; only read when the authorized vault
    object is absent or --ForceAcquire is set).

.PARAMETER CaseId
    Case id; defaults to gto_launcher.

.PARAMETER ForceAcquire
    Read the mutable locator even if an authorized vault object exists.

.PARAMETER RetainUnmatched
    Archive a stable-but-unmatched snapshot under observed-revisions (never promotes).

.PARAMETER ObservedRevisionsDir
    Directory for retained unmatched revisions.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools/resolve_gto_source_revision.ps1 `
        -ManifestPath lab/cases/v2/gto_launcher.json `
        -VaultRoot D:\MidaVault\vault `
        -EvidenceDir D:\MidaVault\lab\evidence\run1

.NOTES
    Exit codes are defined by the Python core and are machine-consumable.
#>
[CmdletBinding()]
param(
    [string]$ManifestPath,

    [string]$VaultRoot,

    [string]$EvidenceDir,

    [string]$SourcePath,

    [string]$CaseId = "gto_launcher",

    [switch]$ForceAcquire,
    [switch]$RetainUnmatched,
    [string]$ObservedRevisionsDir,

    [switch]$Help
)

$ErrorActionPreference = "Stop"

# --- Honor -Help / -? to show comment-based help ---
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

# --- Required-argument validation (after help path) ---
if (-not $ManifestPath -or -not $VaultRoot -or -not $EvidenceDir) {
    Write-Error "ManifestPath, VaultRoot, and EvidenceDir are required (use -Help for usage)."
    exit 17
}

# --- Locate repository root from this script's location ---
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptDir
$corePy = Join-Path $scriptDir "_resolve_gto_source_revision.py"

if (-not (Test-Path $corePy -PathType Leaf)) {
    Write-Error "resolver core not found: $corePy"
    exit 17   # InternalError
}

# --- Locate python ---
$python = $null
foreach ($candidate in @("python", "py")) {
    try {
        $cmd = Get-Command $candidate -ErrorAction Stop
        $python = $cmd.Source
        break
    } catch {
        # try next
    }
}
if ($null -eq $python) {
    Write-Error "python not found on PATH"
    exit 17
}

# --- Forward args verbatim, preserving the core's exit code ---
$coreArgs = @(
    "--ManifestPath", $ManifestPath,
    "--VaultRoot", $VaultRoot,
    "--EvidenceDir", $EvidenceDir,
    "--CaseId", $CaseId
)
if ($SourcePath) { $coreArgs += @("--SourcePath", $SourcePath) }
if ($ForceAcquire) { $coreArgs += "--ForceAcquire" }
if ($RetainUnmatched) { $coreArgs += "--RetainUnmatched" }
if ($ObservedRevisionsDir) { $coreArgs += @("--ObservedRevisionsDir", $ObservedRevisionsDir) }

& $python $corePy @coreArgs
$exit = $LASTEXITCODE
if ($null -eq $exit) { $exit = 0 }
exit $exit
