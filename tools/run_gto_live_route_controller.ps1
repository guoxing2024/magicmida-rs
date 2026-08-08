<#
.SYNOPSIS
    Windows entry point for the binary-safe GTO live-route controller.

.DESCRIPTION
    Locates the Python core (tools/gto_live_route_controller.py), forwards all
    arguments verbatim (preserving argv boundaries), and returns the child/core
    exit code unchanged. Does not re-implement any controller logic.

.PARAMETER EvidenceDir
    Output evidence directory.

.PARAMETER Command
    Child command + args. Use `--` before the child command so PowerShell does
    not mangle the argv.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File tools/run_gto_live_route_controller.ps1 `
        -EvidenceDir D:\MidaVault\evidence\run1 -- mida-cli.exe /unpack ...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$EvidenceDir,

    [string]$Cwd,

    [double]$Timeout = 120.0,

    [string[]]$EnvAllowlist,

    [string[]]$SetEnv,

    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Command,

    [switch]$Help
)

if ($Help) {
    Get-Help $MyInvocation.MyCommand.Path -Full
    exit 0
}

if (-not $Command -or $Command.Count -eq 0) {
    [Console]::Error.WriteLine("a child command is required (use -- <command> [args...])")
    exit 3
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$corePy = Join-Path $scriptDir "gto_live_route_controller.py"
if (-not (Test-Path $corePy -PathType Leaf)) {
    [Console]::Error.WriteLine("controller core not found: $corePy")
    exit 3
}

$python = $null
foreach ($candidate in @("python", "py")) {
    try {
        $python = (Get-Command $candidate -ErrorAction Stop).Source
        break
    } catch {
    }
}
if ($null -eq $python) {
    [Console]::Error.WriteLine("python not found on PATH")
    exit 3
}

$coreArgs = @("--evidence-dir", $EvidenceDir)
if ($Cwd) { $coreArgs += @("--cwd", $Cwd) }
$coreArgs += @("--timeout", ([string]$Timeout))
foreach ($k in $EnvAllowlist) { $coreArgs += @("--env-allowlist", $k) }
foreach ($kv in $SetEnv) { $coreArgs += @("--set-env", $kv) }
$coreArgs += "--"
$coreArgs += $Command

& $python $corePy @coreArgs
exit $LASTEXITCODE
