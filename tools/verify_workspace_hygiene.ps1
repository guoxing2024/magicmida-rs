[CmdletBinding()]
param(
    [Parameter()]
    [string] $RepositoryRoot,

    [Parameter()]
    [switch] $SkipGitDirtyCheck,

    [Parameter()]
    [ValidateRange(1, [long]::MaxValue)]
    [long] $MaxFixtureBytes = 1MB
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
    $RepositoryRoot = Split-Path -Parent $scriptDirectory
}

function Convert-ToRelativePath {
    param(
        [Parameter(Mandatory)]
        [string] $Root,

        [Parameter(Mandatory)]
        [string] $Path
    )

    $normalizedRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]] @('\', '/'))
    $normalizedPath = [System.IO.Path]::GetFullPath($Path)
    if ($normalizedPath.Equals($normalizedRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        return '.'
    }

    $rootPrefix = $normalizedRoot + [System.IO.Path]::DirectorySeparatorChar
    if (-not $normalizedPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path is outside RepositoryRoot: $normalizedPath"
    }

    return $normalizedPath.Substring($rootPrefix.Length).Replace('\', '/')
}

function Test-IsUnderGitMetadata {
    param(
        [Parameter(Mandatory)]
        [string] $RelativePath
    )

    return $RelativePath -eq '.git' -or $RelativePath.StartsWith('.git/', [System.StringComparison]::Ordinal)
}

function Get-FixtureRoot {
    param(
        [Parameter(Mandatory)]
        [System.IO.FileInfo] $File,

        [Parameter(Mandatory)]
        [string] $Root
    )

    $rootWithSeparator = $Root.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    $directory = $File.Directory
    while ($null -ne $directory -and $directory.FullName.StartsWith($rootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
        if ($directory.Name -ieq 'fixtures') {
            return $directory
        }
        $directory = $directory.Parent
    }

    return $null
}

function Get-ForbiddenBinaryMagic {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    )
    try {
        $header = [byte[]]::new(64)
        $headerBytes = $stream.Read($header, 0, $header.Length)
        if ($headerBytes -ge 4 -and
            $header[0] -eq 0x4d -and $header[1] -eq 0x44 -and
            $header[2] -eq 0x4d -and $header[3] -eq 0x50) {
            return 'minidump_content'
        }

        if ($headerBytes -ge 64 -and $header[0] -eq 0x4d -and $header[1] -eq 0x5a) {
            $peOffset = [System.BitConverter]::ToUInt32($header, 0x3c)
            if (([uint64] $peOffset + 4) -le [uint64] $stream.Length) {
                $stream.Position = [long] $peOffset
                $signature = [byte[]]::new(4)
                if ($stream.Read($signature, 0, 4) -eq 4 -and
                    $signature[0] -eq 0x50 -and $signature[1] -eq 0x45 -and
                    $signature[2] -eq 0 -and $signature[3] -eq 0) {
                    return 'pe_image_content'
                }
            }
        }
        return $null
    }
    finally {
        $stream.Dispose()
    }
}

function Convert-ToFixtureManifestName {
    param(
        [Parameter(Mandatory)]
        [object] $Value,

        [Parameter(Mandatory)]
        [string] $Context
    )

    $name = [string] $Value
    if ([string]::IsNullOrWhiteSpace($name)) { throw "$Context is empty" }
    if ($name.Contains('\') -or [System.IO.Path]::IsPathRooted($name) -or
        $name.StartsWith('/') -or $name -match '^[A-Za-z]:') {
        throw "$Context must be a canonical /-separated relative path"
    }
    if ($name -match '[:*?""<>|]') { throw "$Context contains a forbidden character" }
    foreach ($character in $name.ToCharArray()) {
        if ([int] $character -lt 32) { throw "$Context contains a control character" }
    }
    foreach ($segment in $name.Split('/')) {
        if ([string]::IsNullOrWhiteSpace($segment) -or $segment -eq '.' -or $segment -eq '..') {
            throw "$Context contains an empty, dot, or whitespace-only segment"
        }
    }
    if ([System.IO.Path]::GetExtension($name) -ine '.bin') { throw "$Context must name a .bin file" }
    return $name
}

function Convert-ToFixtureSize {
    param(
        [Parameter(Mandatory)]
        [object] $Value,

        [Parameter(Mandatory)]
        [string] $Context
    )

    $text = [string] $Value
    if ($text -notmatch '^(0|[1-9][0-9]*)$') { throw "$Context must be a non-negative integer" }
    $size = [long] 0
    if (-not [long]::TryParse($text, [ref] $size)) { throw "$Context exceeds Int64" }
    return $size
}

function Convert-ToFixtureSha256 {
    param(
        [Parameter(Mandatory)]
        [object] $Value,

        [Parameter(Mandatory)]
        [string] $Context
    )

    $sha = [string] $Value
    if ($sha -notmatch '^[A-Fa-f0-9]{64}$') { throw "$Context must be a SHA-256 digest" }
    return $sha.ToLowerInvariant()
}

function Get-RequiredJsonProperty {
    param(
        [Parameter(Mandatory)]
        [object] $Object,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [string] $Context
    )

    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { throw "$Context is missing property '$Name'" }
    return $property
}

function Read-FixtureManifest {
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $manifest = Get-Content -Raw -LiteralPath $Path -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $manifest) { throw 'manifest is null' }
    $schema = [string] (Get-RequiredJsonProperty $manifest 'schema' 'manifest').Value
    if ($schema -cne 'mida.fixture-provenance/v1') { throw "unsupported schema '$schema'" }
    $fixturesProperty = Get-RequiredJsonProperty $manifest 'fixtures' 'manifest'
    if (-not ($fixturesProperty.Value -is [System.Array])) { throw 'manifest.fixtures must be an array' }

    $records = [System.Collections.Generic.List[object]]::new()
    $seenNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($rawRecord in @($fixturesProperty.Value)) {
        if ($null -eq $rawRecord) { throw 'manifest.fixtures contains null' }
        $allowed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        @('name', 'size_bytes', 'sha256') | ForEach-Object { [void] $allowed.Add($_) }
        foreach ($property in $rawRecord.PSObject.Properties) {
            if (-not $allowed.Contains($property.Name)) {
                throw "fixture record contains unknown property '$($property.Name)'"
            }
        }

        $name = Convert-ToFixtureManifestName (Get-RequiredJsonProperty $rawRecord 'name' 'fixture record').Value 'fixture record.name'
        if (-not $seenNames.Add($name)) { throw "duplicate fixture record '$name'" }
        $size = Convert-ToFixtureSize (Get-RequiredJsonProperty $rawRecord 'size_bytes' "fixture '$name'").Value "fixture '$name'.size_bytes"
        $sha = Convert-ToFixtureSha256 (Get-RequiredJsonProperty $rawRecord 'sha256' "fixture '$name'").Value "fixture '$name'.sha256"
        $records.Add([ordered]@{ name = $name; size = $size; sha256 = $sha })
    }
    return ,$records.ToArray()
}

function Write-ResultAndExit {
    param(
        [Parameter(Mandatory)]
        [object] $Result,

        [Parameter(Mandatory)]
        [ValidateSet(0, 1, 2)]
        [int] $ExitCode
    )

    $Result | ConvertTo-Json -Depth 8
    exit $ExitCode
}

try {
    $resolvedRoot = (Resolve-Path -LiteralPath $RepositoryRoot -ErrorAction Stop).ProviderPath
    if (-not [System.IO.Directory]::Exists($resolvedRoot)) {
        throw "RepositoryRoot is not a directory: $resolvedRoot"
    }

    $forbiddenArtifacts = [System.Collections.Generic.List[object]]::new()
    $cacheDirectories = [System.Collections.Generic.List[object]]::new()
    $oversizedFixtures = [System.Collections.Generic.List[object]]::new()
    $unmanifestedFixtures = [System.Collections.Generic.List[object]]::new()
    $fixtureManifestViolations = [System.Collections.Generic.List[object]]::new()
    $checkerErrors = [System.Collections.Generic.List[string]]::new()
    $fixtureRoots = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $fixtureBins = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $forbiddenExtensions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @('.exe', '.dll', '.dmp', '.log', '.pyc', '.pyo') | ForEach-Object { [void] $forbiddenExtensions.Add($_) }

    $cacheDirectoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @('target', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.pytype', '.hypothesis', '.tox', '.nox') |
        ForEach-Object { [void] $cacheDirectoryNames.Add($_) }

    $logDirectoryNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    @('log', 'logs') | ForEach-Object { [void] $logDirectoryNames.Add($_) }

    $provenanceNames = @('SOURCE.txt', 'manifest.json')
    $allItems = @(Get-ChildItem -LiteralPath $resolvedRoot -Force -Recurse -ErrorAction Stop)

    foreach ($item in $allItems) {
        $relativePath = Convert-ToRelativePath -Root $resolvedRoot -Path $item.FullName
        if (Test-IsUnderGitMetadata -RelativePath $relativePath) {
            continue
        }

        if ($item -is [System.IO.DirectoryInfo]) {
            if ($item.Name -ieq 'fixtures' -and $relativePath -imatch '^crates/.+/fixtures$') {
                if (-not $fixtureRoots.ContainsKey($item.FullName)) {
                    $fixtureRoots.Add($item.FullName, $item)
                    $fixtureBins.Add($item.FullName, [System.Collections.Generic.List[System.IO.FileInfo]]::new())
                }
            }
            if ($cacheDirectoryNames.Contains($item.Name)) {
                $cacheDirectories.Add([ordered]@{
                    path = $relativePath
                    kind = 'generated_cache_directory'
                })
            }
            elseif ($logDirectoryNames.Contains($item.Name)) {
                $forbiddenArtifacts.Add([ordered]@{
                    path = $relativePath
                    kind = 'runtime_log_directory'
                })
            }
            continue
        }

        $magicKind = Get-ForbiddenBinaryMagic -Path $item.FullName
        if ($null -ne $magicKind) {
            $forbiddenArtifacts.Add([ordered]@{
                path = $relativePath
                kind = $magicKind
                size = $item.Length
            })
        }
        elseif ($item.Name -ieq 'scylla_hide.ini') {
            $forbiddenArtifacts.Add([ordered]@{
                path = $relativePath
                kind = 'forbidden_scylla_hide_config'
                size = $item.Length
            })
        }
        elseif ($forbiddenExtensions.Contains($item.Extension)) {
            $kind = if ($item.Extension -iin @('.pyc', '.pyo')) { 'python_bytecode' } else { 'forbidden_file_type' }
            $forbiddenArtifacts.Add([ordered]@{
                path = $relativePath
                kind = $kind
                size = $item.Length
            })
        }

        if ($item.Extension -ine '.bin') {
            continue
        }

        $fixtureRoot = Get-FixtureRoot -File $item -Root $resolvedRoot
        $isCrateFixture = $null -ne $fixtureRoot -and
            (Convert-ToRelativePath -Root $resolvedRoot -Path $fixtureRoot.FullName) -imatch '^crates/.+/fixtures$'

        if (-not $isCrateFixture) {
            $forbiddenArtifacts.Add([ordered]@{
                path = $relativePath
                kind = 'bin_outside_crate_fixture'
                size = $item.Length
            })
            continue
        }

        if (-not $fixtureRoots.ContainsKey($fixtureRoot.FullName)) {
            $fixtureRoots.Add($fixtureRoot.FullName, $fixtureRoot)
            $fixtureBins.Add($fixtureRoot.FullName, [System.Collections.Generic.List[System.IO.FileInfo]]::new())
        }
        $fixtureBins[$fixtureRoot.FullName].Add($item)

        if ($item.Length -gt $MaxFixtureBytes) {
            $oversizedFixtures.Add([ordered]@{
                path = $relativePath
                size = $item.Length
                maximum_size = $MaxFixtureBytes
            })
        }
    }

    foreach ($fixtureRootPath in $fixtureRoots.Keys) {
        $rootRelative = Convert-ToRelativePath -Root $resolvedRoot -Path $fixtureRootPath
        $binFiles = $fixtureBins[$fixtureRootPath]
        $provenanceFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
        foreach ($name in $provenanceNames) {
            $candidate = Join-Path -Path $fixtureRootPath -ChildPath $name
            if ([System.IO.File]::Exists($candidate)) {
                $provenanceFiles.Add((Get-Item -LiteralPath $candidate -Force -ErrorAction Stop))
            }
        }

        if ($binFiles.Count -eq 0 -and $provenanceFiles.Count -eq 0) {
            continue
        }
        if ($provenanceFiles.Count -eq 0) {
            $unmanifestedFixtures.Add([ordered]@{
                fixture_root = $rootRelative
                bin_count = $binFiles.Count
                accepted_provenance_names = $provenanceNames
            })
            continue
        }
        if ($provenanceFiles.Count -ne 1) {
            $fixtureManifestViolations.Add([ordered]@{
                fixture_root = $rootRelative
                kind = 'ambiguous_fixture_manifest'
                manifests = @($provenanceFiles | ForEach-Object { $_.Name })
            })
            continue
        }

        $manifestFile = $provenanceFiles[0]
        try {
            $manifestRecords = Read-FixtureManifest -Path $manifestFile.FullName
        }
        catch {
            $fixtureManifestViolations.Add([ordered]@{
                fixture_root = $rootRelative
                manifest = $manifestFile.Name
                kind = 'invalid_fixture_manifest'
                detail = $_.Exception.Message
            })
            continue
        }

        $declared = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($record in $manifestRecords) { $declared.Add($record.name, $record) }
        $actual = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($binFile in $binFiles) {
            $name = Convert-ToRelativePath -Root $fixtureRootPath -Path $binFile.FullName
            if ($actual.ContainsKey($name)) {
                $fixtureManifestViolations.Add([ordered]@{
                    fixture_root = $rootRelative
                    manifest = $manifestFile.Name
                    kind = 'duplicate_actual_fixture_name'
                    name = $name
                })
                continue
            }
            $actual.Add($name, $binFile)
        }

        foreach ($name in $actual.Keys) {
            if (-not $declared.ContainsKey($name)) {
                $fixtureManifestViolations.Add([ordered]@{
                    fixture_root = $rootRelative
                    manifest = $manifestFile.Name
                    kind = 'missing_manifest_entry'
                    name = $name
                })
                continue
            }

            $record = $declared[$name]
            $binFile = $actual[$name]
            if ($record.name -cne $name) {
                $fixtureManifestViolations.Add([ordered]@{
                    fixture_root = $rootRelative
                    manifest = $manifestFile.Name
                    kind = 'fixture_name_case_mismatch'
                    declared_name = $record.name
                    actual_name = $name
                })
            }
            if ([long] $record.size -ne [long] $binFile.Length) {
                $fixtureManifestViolations.Add([ordered]@{
                    fixture_root = $rootRelative
                    manifest = $manifestFile.Name
                    kind = 'fixture_size_mismatch'
                    name = $name
                    declared_size = [long] $record.size
                    actual_size = [long] $binFile.Length
                })
            }
            $actualSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $binFile.FullName).Hash.ToLowerInvariant()
            if ($record.sha256 -cne $actualSha) {
                $fixtureManifestViolations.Add([ordered]@{
                    fixture_root = $rootRelative
                    manifest = $manifestFile.Name
                    kind = 'fixture_sha256_mismatch'
                    name = $name
                    declared_sha256 = $record.sha256
                    actual_sha256 = $actualSha
                })
            }
        }

        foreach ($name in $declared.Keys) {
            if (-not $actual.ContainsKey($name)) {
                $fixtureManifestViolations.Add([ordered]@{
                    fixture_root = $rootRelative
                    manifest = $manifestFile.Name
                    kind = 'extra_manifest_entry'
                    name = $declared[$name].name
                })
            }
        }
    }

    $gitDirty = [System.Collections.Generic.List[string]]::new()
    $checkGitDirty = -not $SkipGitDirtyCheck.IsPresent
    if ($checkGitDirty) {
        $previousOptionalLocks = $env:GIT_OPTIONAL_LOCKS
        try {
            $env:GIT_OPTIONAL_LOCKS = '0'
            $gitOutput = @(& git -c core.excludesFile= -C $resolvedRoot status --porcelain=v1 --untracked-files=all 2>&1)
            if ($LASTEXITCODE -ne 0) {
                $checkerErrors.Add("git status failed with exit code ${LASTEXITCODE}: $($gitOutput -join ' ')")
            }
            else {
                foreach ($line in $gitOutput) {
                    if (-not [string]::IsNullOrWhiteSpace([string] $line)) {
                        $gitDirty.Add([string] $line)
                    }
                }
            }
        }
        finally {
            if ($null -eq $previousOptionalLocks) {
                Remove-Item Env:GIT_OPTIONAL_LOCKS -ErrorAction SilentlyContinue
            }
            else {
                $env:GIT_OPTIONAL_LOCKS = $previousOptionalLocks
            }
        }
    }

    $violationCount = $forbiddenArtifacts.Count + $cacheDirectories.Count +
        $oversizedFixtures.Count + $unmanifestedFixtures.Count +
        $fixtureManifestViolations.Count + $gitDirty.Count

    $result = [ordered]@{
        schema_version = 1
        repository_root = $resolvedRoot
        check_git_dirty = $checkGitDirty
        max_fixture_bytes = $MaxFixtureBytes
        status = if ($checkerErrors.Count -gt 0) { 'ERROR' } elseif ($violationCount -gt 0) { 'FAIL' } else { 'PASS' }
        counts = [ordered]@{
            forbidden_artifacts = $forbiddenArtifacts.Count
            cache_directories = $cacheDirectories.Count
            oversized_fixtures = $oversizedFixtures.Count
            unmanifested_fixtures = $unmanifestedFixtures.Count
            fixture_manifest_violations = $fixtureManifestViolations.Count
            git_dirty = $gitDirty.Count
            checker_errors = $checkerErrors.Count
        }
        forbidden_artifacts = $forbiddenArtifacts
        cache_directories = $cacheDirectories
        oversized_fixtures = $oversizedFixtures
        unmanifested_fixtures = $unmanifestedFixtures
        fixture_manifest_violations = $fixtureManifestViolations
        git_dirty = $gitDirty
        checker_errors = $checkerErrors
    }

    if ($checkerErrors.Count -gt 0) {
        Write-ResultAndExit -Result $result -ExitCode 2
    }
    if ($violationCount -gt 0) {
        Write-ResultAndExit -Result $result -ExitCode 1
    }
    Write-ResultAndExit -Result $result -ExitCode 0
}
catch {
    $failure = [ordered]@{
        schema_version = 1
        repository_root = $RepositoryRoot
        check_git_dirty = -not $SkipGitDirtyCheck.IsPresent
        max_fixture_bytes = $MaxFixtureBytes
        status = 'ERROR'
        counts = [ordered]@{
            forbidden_artifacts = 0
            cache_directories = 0
            oversized_fixtures = 0
            unmanifested_fixtures = 0
            fixture_manifest_violations = 0
            git_dirty = 0
            checker_errors = 1
        }
        forbidden_artifacts = @()
        cache_directories = @()
        oversized_fixtures = @()
        unmanifested_fixtures = @()
        fixture_manifest_violations = @()
        git_dirty = @()
        checker_errors = @($_.Exception.Message)
    }
    Write-ResultAndExit -Result $failure -ExitCode 2
}
