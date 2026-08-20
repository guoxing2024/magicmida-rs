#requires -Version 5.1
<#
  verify_adr7_closeout.ps1 - read-only ADR7 closeout verifier (B4/B5)

  Verifies:
    1. B4 evidence seal (final_seal_manifest entries vs disk, chain root/final/seal)
    2. B5 evidence seal (same)
    3. B4/B5 report hashes
    4. B5 formal sign-off hash
    5. root/final/seal chain (final -> root -> covers)
    6. attempt semantic summary (targets + controls)
    7. no protected sample copies inside evidence packages
    8. helper provenance (helpers on disk == provenance hashes)

  Output: PASS / FAIL with mismatch lists. Never writes to the evidence dirs.
  Exit code 0 = PASS, 1 = FAIL, 2 = usage error.

  Usage:
    pwsh -File tools/verify_adr7_closeout.ps1 [-EvidenceRoot D:\MidaVault\lab\evidence]
#>
param(
    [string] $EvidenceRoot = "D:\MidaVault\lab\evidence"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$B4Dir = Join-Path $EvidenceRoot 'adr7b_b4_binding_correction'
$B5Dir = Join-Path $EvidenceRoot 'adr7b_b5'

$failures = [System.Collections.Generic.List[string]]::new()
$warnings = [System.Collections.Generic.List[string]]::new()
$checks = [System.Collections.Generic.List[string]]::new()

function Add-Check {
    param([string] $Name)
    $script:checks.Add($Name)
    Write-Host ("[check] " + $Name)
}

function Add-Failure {
    param([string] $Msg)
    $script:failures.Add($Msg)
    Write-Host ("[FAIL]  " + $Msg)
}

function Add-Warning {
    param([string] $Msg)
    $script:warnings.Add($Msg)
    Write-Host ("[WARN]  " + $Msg)
}

function Get-Sha256 {
    param([string] $Path)
    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
    }
    finally { $stream.Dispose() }
}

function Test-SealChain {
    param(
        [string] $Dir,
        [string] $SealManifestName,
        [string] $SealHashFile,
        [string] $ExpectedSealHash,
        [string] $Label
    )
    $sealPath = Join-Path $Dir $SealManifestName
    if (-not (Test-Path $sealPath)) { Add-Failure "$Label seal manifest missing: $sealPath"; return }

    $seal = Get-Content -Raw -LiteralPath $sealPath | ConvertFrom-Json
    $sealHash = Get-Sha256 $sealPath

    $sealHashFile = Join-Path $Dir $SealHashFile
    if (Test-Path $sealHashFile) {
        $recorded = (Get-Content -Raw -LiteralPath $sealHashFile).Trim().ToLowerInvariant()
        if ($recorded -ne $sealHash) { Add-Failure "$Label SEAL_HASH.txt ($recorded) != seal manifest sha256 ($sealHash)" }
        elseif ($ExpectedSealHash -and $recorded -ne $ExpectedSealHash) { Add-Failure "$Label SEAL_HASH.txt ($recorded) != expected closeout value ($ExpectedSealHash)" }
    } else {
        Add-Warning "$Label $SealHashFile missing (seal self-reference not externally closable)"
    }

    $count = 0
    foreach ($entry in $seal.files.PSObject.Properties) {
        $count++
        $rel = $entry.Name -replace '/', [System.IO.Path]::DirectorySeparatorChar
        $full = Join-Path $Dir $rel
        if (-not (Test-Path -LiteralPath $full)) {
            Add-Failure "$Label sealed file missing: $rel"
            continue
        }
        $meta = $entry.Value
        $fi = Get-Item -LiteralPath $full
        if ($fi.Length -ne [int64] $meta.size) { Add-Failure "$Label size mismatch: $rel (disk $($fi.Length) vs seal $($meta.size))" }
        $h = Get-Sha256 $full
        if ($h -ne $meta.sha256) { Add-Failure "$Label hash mismatch: $rel" }
    }
    Add-Check "$Label seal entries vs disk ($count entries)"

    $finalPath = Join-Path $Dir 'adr7b_b4_binding_correction_final_manifest.json'
    if (-not (Test-Path $finalPath)) { $finalPath = Join-Path $Dir 'adr7b_b5_final_manifest.json' }
    if (Test-Path $finalPath) {
        $final = Get-Content -Raw -LiteralPath $finalPath | ConvertFrom-Json
        $finalHash = Get-Sha256 $finalPath
        if ($finalHash -ne $seal.final_manifest_sha256) { Add-Failure "$Label final manifest sha256 mismatch (disk $finalHash vs seal $($seal.final_manifest_sha256))" }
        else { Add-Check "$Label final manifest hash matches seal.final_manifest_sha256" }

        $rootRel = $final.root_manifest.file
        if ($rootRel) {
            $rootPath = Join-Path $Dir ($rootRel -replace '/', [System.IO.Path]::DirectorySeparatorChar)
            if (Test-Path $rootPath) {
                $rootHash = Get-Sha256 $rootPath
                if ($rootHash -ne $final.root_manifest.sha256) { Add-Failure "$Label root manifest hash mismatch (disk $rootHash vs final $($final.root_manifest.sha256))" }
                else { Add-Check "$Label final -> root manifest hash OK" }
                $root = Get-Content -Raw -LiteralPath $rootPath | ConvertFrom-Json
                foreach ($cover in $root.covers.PSObject.Properties) {
                    $cpath = Join-Path $Dir ($cover.Value.file -replace '/', [System.IO.Path]::DirectorySeparatorChar)
                    if (-not (Test-Path $cpath)) { Add-Failure "$Label root cover missing: $($cover.Value.file)" }
                    else {
                        $ch = Get-Sha256 $cpath
                        if ($ch -ne $cover.Value.sha256) { Add-Failure "$Label root cover hash mismatch: $($cover.Value.file)" }
                    }
                }
                $coverCount = @($root.covers.PSObject.Properties).Count
                Add-Check "$Label root covers ($coverCount)"
            } else { Add-Failure "$Label root manifest file missing: $rootRel" }
        }
    } else { Add-Failure "$Label final manifest file not found (probed both naming conventions)" }
}

# ===== 1 + 2. B4 / B5 seal chains =====
Test-SealChain -Dir $B4Dir -SealManifestName 'adr7b_b4_binding_correction_final_seal_manifest.json' -SealHashFile 'SEAL_HASH.txt' -ExpectedSealHash '56b3df5c6ba4fd62759469d4e63db45886b937a12cd52ac88626a7539766f89a' -Label 'B4'
Test-SealChain -Dir $B5Dir -SealManifestName 'adr7b_b5_final_seal_manifest.json' -SealHashFile 'SEAL_HASH.txt' -ExpectedSealHash 'a32c4a513b1adec6863fdd49a91907abd39ec9ed6a601c288a8df0168c81d509' -Label 'B5'

# ===== 3. report hashes =====
$b4Report = Join-Path $B4Dir 'ADR7_B4_BINDING_CORRECTION_REPORT.md'
$b5Report = Join-Path $B5Dir 'ADR7_B5_TLS_ROOT_CAUSE_ISOLATION_REPORT.md'
if (Test-Path $b4Report) {
    $h = Get-Sha256 $b4Report
    if ($h -ne 'a330362c58ab11e85fb08ba5a81a692447dc400be677bf1b981600d42c99dd05') { Add-Failure "B4 report hash mismatch: $h" } else { Add-Check 'B4 report hash OK' }
} else { Add-Failure 'B4 report missing' }

if (Test-Path $b5Report) {
    $h = Get-Sha256 $b5Report
    if ($h -ne '081339b632d94e8aa3d1e7ca9348924134eb9d877f0b8c28be5370cb934d8a35') { Add-Failure "B5 report hash mismatch: $h" } else { Add-Check 'B5 report hash OK' }
} else { Add-Failure 'B5 report missing' }

# ===== 4. B5 sign-off hash =====
$soPath = Join-Path $B5Dir 'ADR7_B5_FORMAL_SIGNOFF.json'
if (Test-Path $soPath) {
    $h = Get-Sha256 $soPath
    if ($h -ne 'ca6c43ba6319e688571d8fac91b76f153baa74c9045e7901c038dbbf2501f243') { Add-Failure "B5 sign-off hash mismatch: $h" } else { Add-Check 'B5 formal sign-off hash OK' }
} else { Add-Failure 'B5 formal sign-off missing' }

# ===== 5. semantic summary =====
function Get-Json {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $raw = Get-Content -Raw -LiteralPath $Path
    if ($raw.Length -gt 0 -and [int] $raw[0] -eq 0xFEFF) { $raw = $raw.Substring(1) }
    try { return $raw | ConvertFrom-Json } catch { return $null }
}

foreach ($a in @('origin_rt_1','origin_rt_2','origin_rt_3','lunlun_rt_1','lunlun_rt_2','lunlun_rt_3')) {
    $tlPath = Join-Path $B5Dir (('timelines' + [System.IO.Path]::DirectorySeparatorChar) + $a + '_timeline.json')
    $snPath = Join-Path $B5Dir (('tls_snapshots' + [System.IO.Path]::DirectorySeparatorChar) + $a + '_tls_snapshot.json')
    $tl = Get-Json $tlPath
    $sn = Get-Json $snPath
    if (-not $tl -or -not $sn) { Add-Failure "B5 $a timeline or snapshot missing"; continue }
    $rec = $tl.records | Where-Object { $_.kind -eq 'second_chance_exception' } | Select-Object -First 1
    if (-not $rec) { Add-Failure "B5 $a no second_chance_exception record"; continue }
    if ($rec.tid -ne $sn.tid) { Add-Failure "B5 $a snapshot tid != exception tid ($($sn.tid) vs $($rec.tid))" }
    if ($rec.exception_code -ne '0xc0000409') { Add-Failure "B5 $a exception_code != 0xc0000409 ($($rec.exception_code))" }
    if ($rec.runtime_rva -ne '0x2e816') { Add-Failure "B5 $a rva != 0x2e816 ($($rec.runtime_rva))" }
    if ($sn.classification -ne 'tls_slot_writable') { Add-Failure "B5 $a classification != tls_slot_writable ($($sn.classification))" }
    if ($sn.capture_phase -ne 'second_chance') { Add-Failure "B5 $a capture_phase != second_chance ($($sn.capture_phase))" }
    if ($tl.runtime_binding -ne 'Verified') { Add-Failure "B5 $a runtime_binding != Verified ($($tl.runtime_binding))" }
}
Add-Check 'B5 target semantic summary (6 attempts)'

foreach ($a in @('benign_rt_1','benign_rt_2','benign_rt_3')) {
    $tlPath = Join-Path $B5Dir (('timelines' + [System.IO.Path]::DirectorySeparatorChar) + $a + '_timeline.json')
    $tl = Get-Json $tlPath
    if (-not $tl) { Add-Failure "B5 control $a timeline missing"; continue }
    if ($tl.exceptions_0xc0000409 -ne 0) { Add-Failure "B5 control $a exceptions_0xc0000409 != 0 ($($tl.exceptions_0xc0000409))" }
    $hasTls = $false
    foreach ($r in $tl.records) { if ($null -ne ($r.PSObject.Properties['tls_snapshot'])) { $hasTls = $true } }
    if ($hasTls) { Add-Failure "B5 control $a has a TLS snapshot (false positive)" }
}
Add-Check 'B5 benign control semantic summary (3 attempts)'

foreach ($a in @('dbg_benign_rt_1','dbg_benign_rt_2','dbg_benign_rt_3')) {
    $b2Path = Join-Path $B5Dir (('attempts' + [System.IO.Path]::DirectorySeparatorChar) + $a + [System.IO.Path]::DirectorySeparatorChar + 'b2_debugger.out.txt')
    if (-not (Test-Path -LiteralPath $b2Path)) { Add-Failure "B5 debugger control $a b2 output missing"; continue }
    $b2 = Get-Content -Raw -LiteralPath $b2Path
    $m = [regex]::Match($b2, '"exception_0xc0000409"\s*:\s*(\d+)')
    if (-not $m.Success) { Add-Failure "B5 debugger control $a no exception_0xc0000409 field in b2 output" ; continue }
    if ([int] $m.Groups[1].Value -ne 0) { Add-Failure "B5 debugger control $a exception_0xc0000409 != 0 ($($m.Groups[1].Value))" }
}
Add-Check 'B5 debugger control semantic summary (3 attempts)'

foreach ($a in @('origin_macro_passive_1','origin_macro_passive_2','origin_macro_passive_3','lunlun_software_passive_1','lunlun_software_passive_2','lunlun_software_passive_3')) {
    $tl = Get-Json (Join-Path $B4Dir ((('attempts' + [System.IO.Path]::DirectorySeparatorChar) + $a) + [System.IO.Path]::DirectorySeparatorChar + 'b4_timeline.json'))
    if (-not $tl) { Add-Failure "B4 $a timeline missing"; continue }
    $rec = $tl.records | Where-Object { $_.kind -eq 'second_chance_exception' } | Select-Object -First 1
    if (-not $rec) { Add-Failure "B4 $a no second_chance_exception"; continue }
    if ($rec.exception_code -ne '0xc0000409') { Add-Failure "B4 $a exception_code != 0xc0000409" }
    if ($rec.runtime_rva -ne '0x2e816') { Add-Failure "B4 $a rva != 0x2e816" }
}
Add-Check 'B4 passive target semantic summary (6 attempts)'

# ===== 6. no protected sample copies =====
$strayExe = 0
foreach ($dir in @($B4Dir, $B5Dir)) {
    Get-ChildItem -Path $dir -Recurse -File -Filter '*.exe' | ForEach-Object {
        $rel = $_.FullName.Substring($dir.Length).TrimStart([char[]] @('\'))
        if (-not $rel.StartsWith('helpers' + [System.IO.Path]::DirectorySeparatorChar)) {
            Add-Failure "stray exe outside helpers: $rel"
            $strayExe++
        }
    }
}
if ($strayExe -eq 0) { Add-Check 'no protected sample copies (0 stray exe)' }

# ===== 7. helper provenance =====
$helperExpect = @{
    'B4' = @{
        'b1_benign_host_full.exe' = '473e0fc8ebca74f257bc7a76daaf0ed16a377c8d0da237e26bbc8afa41ae53e3'
        'b2_debugger_attach.exe'  = '49015f84a6f731673e775a8b18ed1efc6ca1e7ef3deb967dda449b054b1f0c75'
        'b4_dynamic_observer.exe' = 'a47995bb0ab8593ee1da42f580ae65a61901562851b5e880ce4ddf22c94a3d7d'
    }
    'B5' = @{
        'b1_benign_host_full.exe' = '58e3eb17fb1a146047af5fcb2e719f14a94997d1703775c26fee019734f7c874'
        'b2_debugger_attach.exe'  = '6a1092a63b78561979e184b2b51101597a90d353885ea1eac7f2c4527e3f1e34'
        'b4_dynamic_observer.exe' = '00bfadce92a1fa69b396e275f3df11b10c86b3f8f9747fd579cb369ce5c022ac'
    }
}
foreach ($pkg in @('B4', 'B5')) {
    $dir = if ($pkg -eq 'B4') { $B4Dir } else { $B5Dir }
    $hDir = Join-Path $dir 'helpers'
    foreach ($name in $helperExpect[$pkg].Keys) {
        $full = Join-Path $hDir $name
        if (-not (Test-Path $full)) { Add-Failure "$pkg helper missing: $name"; continue }
        $h = Get-Sha256 $full
        if ($h -ne $helperExpect[$pkg][$name]) { Add-Failure "$pkg helper hash mismatch: $name ($h)" }
    }
}
Add-Check 'helper provenance (B4 + B5, 6 binaries)'

# ===== summary =====
Write-Host ''
Write-Host ('checks run:   ' + $checks.Count)
Write-Host ('warnings:     ' + $warnings.Count)
foreach ($w in $warnings) { Write-Host ('  [warn] ' + $w) }
if ($failures.Count -eq 0) {
    Write-Host ''
    Write-Host 'RESULT: PASS'
    exit 0
} else {
    Write-Host ''
    Write-Host ('RESULT: FAIL (' + $failures.Count + ' failures)')
    foreach ($f in $failures) { Write-Host ('  [fail] ' + $f) }
    exit 1
}
