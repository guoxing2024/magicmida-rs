# Active Repository Artifact Policy

This repository contains production source code and small deterministic test fixtures only. Runtime captures, unpacked programs, crash dumps, third-party tools, and build output belong in the external SHA-256 vault. A `.gitignore` entry is not an exception to this policy: ignored files are still prohibited from the active worktree.

## Prohibited artifacts

The following must not exist anywhere in the active worktree:

- Windows executables, libraries, or dumps: `*.exe`, `*.dll`, and `*.dmp`.
- Any file whose content is a PE image (`MZ`, a valid DOS `e_lfanew`, and `PE\0\0`) or a minidump (`MDMP`), regardless of its filename or extension.
- The third-party runtime configuration file named exactly `scylla_hide.ini` (case-insensitive).
- Runtime logs: `*.log` and directories named `log` or `logs`.
- Rust build directories named `target`.
- Python bytecode and caches: `*.pyc`, `*.pyo`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.pytype`, `.hypothesis`, `.tox`, and `.nox`.

Store retained binaries outside the repository by SHA-256. Source-controlled manifests may refer to a vault object by its digest, size, role, and provenance, but must not contain a machine-specific absolute path or claim that an artifact is accepted/perfect without validation evidence.

## Mutable external source paths

An external path can be a mutable acquisition locator and must never be treated
as artifact identity. In particular, `D:\Tools\RE\dumps\gto\启动器.exe` may
auto-update or be replaced without notice. Before any sample-derived task:

1. Resolve the manifest-authorized immutable vault object first; if it exists and
   re-verifies, do not re-read the mutable path.
2. Only when the authorized vault object is absent, hash and size the source,
   copy it to a temporary external file, hash both the copy and source again,
   and require all observations to match (H1/H2/H3 stable copy).
3. Resolve the stable copy into the external content-addressed vault by SHA-256.
4. Compare the vault object with the source-controlled case manifest digest and
   size.
5. Run only the verified vault path recorded in a per-run `resolved_source.json`;
   never re-open the mutable locator after validation.
6. Fail closed on `SourceChangedDuringSnapshot`, `SampleIdentityMismatch`, or
   `AuthorizedRevisionUnavailable`.

This is automated by `tools/resolve_gto_source_revision.ps1` /
`tools/_resolve_gto_source_revision.py`; see
`docs/GTO_SAMPLE_REVISION_POLICY.md`.

A newly observed digest is a new revision. It does not supersede the manifest
until a dedicated reviewed commit increments the manifest revision and records
new authority. See
[docs/GTO_SAMPLE_REVISION_POLICY.md](docs/GTO_SAMPLE_REVISION_POLICY.md).

## Binary fixture exception

A `.bin` file is allowed only when all of the following are true:

1. It is below a `crates/**/fixtures/` directory.
2. It is no larger than 1 MiB (1,048,576 bytes).
3. The fixture root contains exactly one provenance file named `SOURCE.txt` or `manifest.json`. The file must be valid JSON with schema `mida.fixture-provenance/v1`.
4. Its provenance `fixtures` array declares every `.bin` below that fixture root, and only those files. Each record must contain the canonical `/`-separated relative `name`, exact `size_bytes`, and lowercase or uppercase SHA-256. Missing, extra, duplicate, malformed, renamed, or modified entries are violations.
5. It is deterministic, minimal, and consumed by an automated test. It must not contain PE or MDMP content, be a complete executable/DLL/process dump, or substitute for a case artifact.

The minimum provenance shape is:

```json
{
  "schema": "mida.fixture-provenance/v1",
  "fixtures": [
    {
      "name": "example.bin",
      "size_bytes": 16,
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  ]
}
```

Fixture records permit no additional fields. The manifest may contain additional set-level provenance such as source-artifact digest, extraction method, and purpose. When a fixture root contains another directory named `fixtures`, that nested directory is a separate fixture root and owns its own manifest.

Larger test inputs belong in the SHA-256 vault and must be materialized only in an isolated test workspace. Adding another binary extension or weakening these limits requires a policy change and review; it is not a local fixture exception.

## Enforcement

Run the read-only checker from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/verify_workspace_hygiene.ps1
```

The checker scans ignored as well as tracked content. It emits a JSON report and exits with:

- `0`: no violations;
- `1`: one or more policy violations;
- `2`: the checker could not complete reliably.

Git dirtiness is checked by default. A caller that is validating a staged-but-not-yet-committed sanitation change may explicitly disable only that check:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tools/verify_workspace_hygiene.ps1 -SkipGitDirtyCheck
```

Skipping the Git check does not suppress artifact, cache, log, or fixture validation. Release and CI validation must use the default.
