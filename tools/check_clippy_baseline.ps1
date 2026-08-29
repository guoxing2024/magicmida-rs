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
$output = & cargo clippy --workspace --lib --bins --message-format=json @($env:CARGO_CLIPPY_EXTRA_ARGS -split ' ') 2>$errFile | Out-String
$code = $LASTEXITCODE
$ErrorActionPreference = $savedEAP
$stderr = if (Test-Path $errFile) { [System.IO.File]::ReadAllText($errFile) } else { '' }
Remove-Item $errFile -ErrorAction SilentlyContinue

# ---------------------------------------------------------------------------
# TASK-003: distinguish "clippy did not run / did not complete analysis" from
# "clippy ran fine and hit deny-level lints".
#
# WHY a plain `$code -ne 0` gate would be wrong: this workspace pins
# `clippy::print_stdout` / `clippy::dbg_macro` to deny (Cargo.toml
# [workspace.lints.clippy]), so a code change that hits one of those makes
# `cargo clippy` exit 101 even though analysis completed and the warn-level
# baseline is still a valid, meaningful measurement. CI even runs the
# warn-baseline job AFTER the -D clippy job, so a deny hit in the baseline
# job would otherwise fail a healthy gate. We therefore never treat a
# non-zero exit by itself as failure.
#
# Chosen discriminator (ticket requirement 2, option 1: triage every
# `"level":"error"` diagnostic BY ITS `code`, three ways):
#
#   code absent (null)          -> RUSTC FAILURE  (compile / link error)
#   code starts with 'clippy::' -> DENY-LEVEL CLIPPY LINT HIT  (legitimate:
#                                  analysis completed, warn baseline is still
#                                  a valid measurement -> do NOT abort)
#   anything else               -> RUSTC FAILURE  (rationale below)
#
# Rationale for the third bucket. This is exactly the hole that got round 1
# rejected: an injected `let probe: u32 = "x";` (E0308) produced an error
# diagnostic whose `code` is non-empty, round 1's "has a code == deny hit"
# rule therefore filed it as a legitimate deny hit, and the gate printed
# `OK: clippy warn baseline holds` with exit 0 — a real compile error read as
# green. Two sub-cases:
#   * `E0xxx` codes (E0308/E0277/E0432/...) are rustc *compile* errors. The
#     crate never finished compiling, so it emitted no lint counts at all:
#     there is nothing to compare with the baseline.
#   * Bare rustc lint names (`unused_variables`, `unused_unsafe`, ...) only
#     reach error level when something outside this repo's own lint policy
#     promotes them (`-D` on the command line, RUSTFLAGS, a crate-level
#     attribute). This workspace's only deny source is
#     `[workspace.lints.clippy]` (print_stdout / dbg_macro — Cargo.toml), and
#     both carry the `clippy::` prefix, so they always land in bucket two.
#     We deliberately treat an ad-hoc-promoted rustc lint as a failure rather
#     than as a legitimate deny hit, because (a) promoting a lint to error
#     moves its diagnostics OUT of the warn bucket, silently lowering the
#     warn counts and turning a real regression into a green gate — the very
#     soft pass this ticket removes; and (b) the gate must never report a
#     measurement it cannot vouch for. Accepted cost: hand-running this
#     script with e.g. `-D unused_variables` now fails hard instead of
#     comparing warnings. That is survivable because the CI baseline job
#     (`windows-clippy` -> "Clippy warn-baseline (WO-23)") invokes this
#     script with no extra rustc flags; the `-D clippy::*` phases are
#     separate `cargo clippy` invocations.
#
# Secondary signals — never sufficient on their own:
#  (2) JSON `"reason":"build-finished"` with `"success":false` — cargo also
#      reports this for a deny-level lint hit, so it only counts as a failure
#      when a rustc failure is already established by the triage above.
#  (3) exit code 101/1 — likewise only recorded as an extra reason.
#  (4) "zero parsed clippy warnings after a build-finished record" and
#      "no JSON at all" — catch cargo aborting before it emitted any
#      diagnostics (missing toolchain, unregistered `-D` lint, ...). A
#      completed clippy pass that merely hit deny lints still yields its full
#      warn-level diagnostics, so these cannot misfire on that scenario.
# ---------------------------------------------------------------------------

$json = $output -split "`r?`n" | Where-Object { $_.Trim().StartsWith('{') }

$analysisFailed = $false
$failReasons = New-Object System.Collections.Generic.List[string]

# Error-level diagnostic triage (see the table in the comment block above).
# Verified shapes (captured during TASK-003 round 2, see run report):
#   - deny hit:   {"level":"error","code":{"code":"clippy::let_unit_value"}}  -> denyLintHits
#   - link fail:  {"level":"error","code":null,"message":"linking with ..."}  -> rustcFailures
#   - type error: {"level":"error","code":{"code":"E0308"}, ...}              -> rustcFailures
$denyLintHits = 0
$rustcFailures = 0
$errorExamples = New-Object System.Collections.Generic.List[string]
foreach ($line in $json) {
    try { $d = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
    if ($d.reason -ne 'compiler-message') { continue }
    $msg = $d.message
    if ($msg.level -ne 'error') { continue }
    $errCode = $msg.code.code
    if ($errCode -and $errCode.StartsWith('clippy::')) {
        # Bucket two: a clippy lint promoted to deny. Analysis ran to
        # completion; the warn-level counts below are still meaningful.
        $denyLintHits++
    } else {
        # Buckets one and three: no code at all (link/compile abort) or a
        # non-clippy code (E0xxx compile error, rustc lint promoted by an
        # ad-hoc flag). Either way clippy did not produce a trustworthy
        # warn-level measurement.
        $rustcFailures++
        if ($errorExamples.Count -lt 3) {
            $prefix = if ($errCode) { "[$errCode] " } else { '[no-code] ' }
            $firstLine = ($msg.rendered -split "`n")[0]
            if (-not $firstLine) { $firstLine = $msg.message }
            $errorExamples.Add($prefix + $firstLine)
        }
    }
}
if ($rustcFailures -gt 0) {
    $analysisFailed = $true
    $failReasons.Add("$rustcFailures rustc error-level diagnostic(s) that are not clippy deny hits (compile/link failure)")
}

# Build-finished record. IMPORTANT (verified): cargo also reports
# success=false when a deny-level lint errors - the -D clippy jobs in CI
# run before this gate and exit there, but if a deny hit lands HERE,
# success=false alone must NOT abort (that is the exact legitimate scenario
# the ticket forbids aborting). Only treat it as failure when it coincides
# with a rustc failure (code-less errors) - otherwise it just confirms a
# deny-hit abort and the warn-level counts below are still meaningful.
# (The triage above already separated the two cases, so this only adds a
# confirmation line to the reason list.)
$hasBuildFinished = $false
foreach ($line in $json) {
    try { $d = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
    if ($d.reason -eq 'build-finished') {
        $hasBuildFinished = $true
        if (-not $d.success -and $rustcFailures -gt 0) {
            $analysisFailed = $true
            $failReasons.Add('JSON build-finished success=false (build graph aborted)')
        }
    }
}

# Fast guard: rustc error exit codes. A deny-hit clippy pass also exits
# 101, so this never fires on its own - it is only a secondary signal that
# joins the fail reasons once a rustc failure is already established.
if ($code -eq 101 -or $code -eq 1) {
    if ($analysisFailed) { $failReasons.Add("cargo clippy exited $code") }
}

$clippyWarnings = 0
foreach ($line in $json) {
    try { $d = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
    if ($d.reason -ne 'compiler-message') { continue }
    $msg = $d.message
    if ($msg.level -eq 'warning') {
        if ($msg.code.code -and $msg.code.code.StartsWith('clippy::')) { $clippyWarnings++ }
    }
}

# Sanity check: when analysis completed (build-finished present), warn-level
# clippy lints MUST be present. Zero warnings with success=true is
# impossible for this workspace (baseline TOTAL=349) and indicates the
# diagnostic stream never reached us.
if (-not $analysisFailed -and $clippyWarnings -eq 0 -and $hasBuildFinished) {
    $analysisFailed = $true
    $failReasons.Add('analysis completed but zero clippy warnings parsed (diagnostic stream empty?)')
}

# Fallback for "cargo produced NO JSON at all": clippy aborted before
# emitting diagnostics (e.g. an unregistered -D lint like
# clippy::dbg_macro, a missing toolchain, or a broken cargo). Then exit
# code 0 is cargo's buggy "ran nothing" behavior and $output is empty -
# no analysis was performed, so the baseline must not be evaluated.
if (-not $analysisFailed -and -not $hasBuildFinished -and $output.Trim() -eq '') {
    $analysisFailed = $true
    $failReasons.Add('cargo clippy produced no JSON output at all (did not run; exit=' + $code + ')')
}

if ($analysisFailed) {
    Write-Host "FAIL: cargo clippy did not complete analysis — baseline not evaluated."
    Write-Host "  reason(s): $($failReasons -join '; ')"
    if ($errorExamples.Count -gt 0) {
        Write-Host '  error diagnostics (first 3):'
        foreach ($e in $errorExamples) { Write-Host "    $e" }
    }
    if ($stderr.Trim() -ne '') {
        Write-Host '  stderr tail:'
        foreach ($l in ($stderr -split "`r?`n" | Select-Object -Last 5)) { if ($l.Trim() -ne '') { Write-Host "    $l" } }
    }
    exit 3
}

if ($denyLintHits -gt 0) {
    # Factual, not presumed: these are the error-level diagnostics the triage
    # above classified as clippy deny hits.
    Write-Host "NOTE: $denyLintHits error-level clippy lint diagnostic(s) classified as deny-level lint hits (analysis completed)."
}
if ($code -ne 0) {
    # TASK-003 requirement 4: do NOT presume WHY clippy exited non-zero. The
    # triage above already established that analysis completed; the old
    # wording ("deny-level lint present") asserted a cause it had not
    # verified, and in round 1 it was printed verbatim on a run that had
    # actually died of an E0308 compile error.
    Write-Host "NOTE: cargo clippy exited $code (non-zero) but completed analysis; continuing with the warn-level baseline comparison (cause not assumed)."
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
    # NB: do not reuse `$code` here - that variable holds the clippy exit
    # code used by the NOTE above.
    $lintCode = $msg.code.code
    if (-not $lintCode) { $lintCode = 'uncategorized' }
    if ($counts.ContainsKey($lintCode)) { $counts[$lintCode]++ } else { $counts[$lintCode] = 1 }
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
