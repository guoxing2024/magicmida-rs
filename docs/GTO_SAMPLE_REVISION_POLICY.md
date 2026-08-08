# GTO Sample Revision and Mutable Source Path Policy

**Status:** mandatory handoff and live-run policy
**Effective:** 2026-08-08

## 1. The problem

`D:\Tools\RE\dumps\gto\启动器.exe` is a **mutable acquisition path**. The file may be replaced or automatically updated without notice, so the path does not identify a stable sample revision. Two reads of that path on different days — or during an update — may return different bytes, SHA-256 values, sizes, PE layouts, and protection revisions.

Therefore:

> A path is a locator, never an artifact identity.

No worker, script, live route, or acceptance step may infer that the bytes at this path are the authorized `gto_launcher` revision merely because the filename and path match.

## 2. Authority hierarchy

Use the following authority order:

1. `lab/cases/v2/gto_launcher.json` — source-controlled identity authority. The `primary_artifact_sha256`, matching `protected_input` record, size, and `execution_policy.dynamic.fixed_sha256` define the authorized revision.
2. An immutable external SHA-256 vault object whose bytes reproduce that digest and size.
3. A per-run `resolved_source.json` produced after resolving and verifying the vault object.
4. The mutable acquisition path — discovery/input convenience only; never authoritative.

The current manifest-authorized protected input is intentionally pinned by digest and size. Updating the file at the mutable path does **not** update or supersede the manifest.

## 3. Mandatory resolution workflow

Every live or sample-derived task must resolve the sample before build, unpack, launch, or analysis.

### 3.1 Snapshot the mutable path safely

Do not run directly from `D:\Tools\RE\dumps\gto\启动器.exe`.

This snapshot procedure applies only when the authorized vault object is absent
or acquisition is explicitly requested — see §3.5. When an authorized vault
object already exists and verifies, this step is skipped and the mutable path is
not read.

Use a stable-copy procedure in an external workspace:

1. Record source size and SHA-256 (`H1`).
2. Copy the file to a new temporary file outside the repository.
3. Hash and size the copied bytes (`H2`).
4. Hash and size the mutable source again (`H3`).
5. Require `H1 == H2 == H3` and all three sizes to match.
6. If any value differs, classify the source as `SourceChangedDuringSnapshot` and stop. Do not retry indefinitely and do not execute either copy.
7. Move the verified temporary copy into the external vault under its SHA-256 identity.

Suggested vault layout:

```text
D:\MidaVault\vault\sha256\<first-two-hex>\<full-sha256>\artifact.exe
```

The vault directory should also contain immutable metadata recording source path, observed timestamps, size, SHA-256, acquisition method, and operator/task identity. Read-only attributes or ACLs are defense in depth; the digest remains the authority.

### 3.2 Compare with the case manifest

Resolve the expected protected input from:

```text
lab/cases/v2/gto_launcher.json
```

Require exact equality of:

- SHA-256;
- size in bytes;
- role (`protected_input`);
- manifest revision/case id;
- architecture and PE capability cell where applicable.

Only an exact match may enter the authorized live route.

### 3.3 Produce a per-run resolution record

Every evidence workspace must contain `resolved_source.json` before any candidate is built. Minimum shape:
```json
{
  "schema_version": "mida.resolved-source/v1",
  "case_id": "gto_launcher",
  "manifest_revision": 1,
  "mutable_locator": "D:\\Tools\\RE\\dumps\\gto\\启动器.exe",
  "resolved_vault_path": "D:\\MidaVault\\vault\\sha256\\...\\artifact.exe",
  "observed_sha256": "...",
  "observed_size_bytes": 0,
  "expected_sha256": "...",
  "expected_size_bytes": 0,
  "source_stable_during_snapshot": true,
  "revision_match": true,
  "resolved_utc": "...",
  "resolver_tool_sha256": "..."
}
```

A live command must consume the verified vault path recorded here, not re-open the mutable locator.
### 3.4 Route-budget boundary

Identity resolution is an acquisition/preflight phase, not live execution. For
all newly authorized routes, the live-round budget begins only after
`resolved_source.json` exists with `source_stable_during_snapshot=true` and
`revision_match=true`. `SampleIdentityMismatch`, `SourceChangedDuringSnapshot`,
or `AuthorizedRevisionUnavailable` must close the preflight attempt without
claiming that bootstrap/runtime recovery was executed. Governance ledgers should
record these as preflight stops separately from consumed live rounds.

## 3.5 Executable resolver (vault-first; do not re-read the mutable path)

A resolver implements this policy as a deterministic, fail-closed preflight
tool. The decision order is fixed:

1. **Manifest is the revision authority.** The authorized `protected_input`
   digest+size come only from `lab/cases/v2/gto_launcher.json` after strict
   validation.
2. **Authorized vault object first.** If the content-addressed vault object for
   the manifest digest exists and its bytes re-hash to that digest+size, the
   resolver succeeds and **never reads the mutable locator**. This means an
   auto-update of `D:\Tools\RE\dumps\gto\启动器.exe` does not make an already
   archived authorized revision invalid.
3. **Mutable acquisition only when the authorized vault object is absent** (or
   the caller explicitly requests acquisition via `--ForceAcquire`). Only then
   is the mutable path read, using the stable H1/H2/H3 copy procedure.
4. **A new digest is a new revision.** A stable snapshot that does not match the
   manifest is `SampleIdentityMismatch`; it is not promoted and never becomes
   the authorized revision.

The three-hash snapshot is **not** run for every live route. It runs only when
the authorized vault object is missing. Do not re-read the mutable path to
"confirm" an already-verified vault object.

Resolver entry points:

- Windows wrapper: `tools/resolve_gto_source_revision.ps1`
- Python core: `tools/_resolve_gto_source_revision.py`

Example (authorized vault-first):

```powershell
powershell -ExecutionPolicy Bypass -File `
  D:\Claude project\magicmida-rs\tools\resolve_gto_source_revision.ps1 `
  -ManifestPath D:\Claude project\magicmida-rs\lab\cases\v2\gto_launcher.json `
  -VaultRoot D:\MidaVault\vault `
  -EvidenceDir <external-evidence-dir> `
  -SourcePath D:\Tools\RE\dumps\gto\启动器.exe
```

If the authorized vault object already exists and verifies, this succeeds
without reading `-SourcePath`. Show usage with:

```powershell
powershell -ExecutionPolicy Bypass -File `
  D:\Claude project\magicmida-rs\tools\resolve_gto_source_revision.ps1 -Help
```

### 3.5.0 Promotion, ForceAcquire, and TOCTOU

**No-clobber promotion.** Vault and observed-revision artifacts are published
atomically with an atomic hard-link create (`os.link`), which fails atomically
if the destination already exists. There is no `exists()+replace` and no
`os.replace` on artifact promotion. If the destination already exists it is
re-hashed: identical bytes are an idempotent success, different bytes are
`VaultObjectCorrupt`, and existing bytes are never overwritten. If post-publish
verification fails, the resolver removes only the object this invocation
created.

**`--ForceAcquire` never overwrites.** When the authorized vault object already
exists, `--ForceAcquire` verifies the mutable source and cross-checks it against
the existing object, then **discards** the snapshot. It does not replace the
existing object, and it cannot bypass an existing object's integrity check (a
corrupt existing object is `VaultObjectCorrupt` even under `--ForceAcquire`).

**`SourceChangedDuringSnapshot` evidence.** The resolution record reports
`source_stable_during_snapshot: false` (never `null`) plus a structured
`snapshot_observation` block with `h1/h2/h3/s1/s2/s3`, so downstream tooling can
consume the race deterministically rather than parsing a stderr string.

**Manifest single-read binding.** The resolver reads the manifest file exactly
once. The recorded `manifest_sha256` and the authority fields (digest/size) are
all derived from that same byte buffer; it never re-opens the manifest to fetch
a digest.

**Storage location.** `VaultRoot` and `ObservedRevisionsDir` must be outside the
repository root; the resolver rejects them (`SourceInvalid`) if they fall inside
the repository, and staging is always created on the destination volume outside
the repo. The repository root is derived **authoritatively by the resolver
itself** from its own file location (there is no public `--RepoRoot` override a
caller could use to forge a different trust root).

**Retention never re-reads the mutable locator.** Once the first H1/H2/H3
snapshot produces a verified `StableCopy`, retention of an unmatched revision
sources bytes strictly from that verified copy — never from the mutable path
again. On a different volume the verified bytes are staged onto the observed
volume and cross-verified (hash/size) before the no-clobber publish. The record
reports `observed_sha256` equal to the archived object's digest, plus
`observed_archive_path` and `observed_archive_verified`. Deleting or updating the
mutable source after the primary snapshot does not change the archived revision.

**Ownership-safe cleanup.** After a successful `os.link`, the resolver records
the staging/destination file identity (`os.stat(follow_symlinks=False)` +
`os.path.samestat`). If post-publish verification fails it removes the
destination name only when the destination identity still equals the identity it
created. If a concurrent actor replaced the destination (identity differs), or
the identity cannot be compared, the resolver fails closed and never unlinks the
(possibly concurrent) object.

**Path-replacement TOCTOU remains.** File-identity checks narrow the window, but
there is still a time-of-check/time-of-use gap between the resolver recording
`resolved_vault_path` and a downstream process consuming it. A downstream
executor must re-hash the file immediately before spawn and must not treat the
resolver alone as eliminating all TOCTOU. The digest (not the path) remains the
authority.

### 3.5.1 Resolver exit codes (machine-consumable)

| Code | Status | Meaning |
|------|--------|---------|
| 0 | `ResolvedAuthorizedRevision` | Authorized revision resolved and verified. |
| 10 | `SourceChangedDuringSnapshot` | Mutable source changed during H1/H2/H3 copy. |
| 11 | `SampleIdentityMismatch` | Stable snapshot digest/size differ from manifest. |
| 12 | `AuthorizedRevisionUnavailable` | No authorized vault object and no (usable) mutable locator. |
| 13 | `VaultObjectCorrupt` | Vault object exists but re-hash/size mismatch; overwrite refused. |
| 14 | `ManifestInvalid` | Manifest missing, not a file, unreadable, or failed strict validation. |
| 15 | `SourceInvalid` | Source not a regular file / reparse point, or `--ForceAcquire` without `--SourcePath`, or a storage root inside the repository. |
| 16 | `ResolutionRecordWriteFailed` | Could not atomically write `resolved_source.json`. |
| 17 | `InternalError` | Unexpected failure. |

All failure codes are non-zero. The PowerShell wrapper returns the Python
core's code unchanged. Exit code `2` is reserved **only** for argparse CLI usage
errors (unknown flag, missing required flag); it is never produced by a normal
resolver status path.

### 3.5.2 Success gate

A downstream command may treat a run as resolved only if the record reports all
of:

- `resolution_status == "ResolvedAuthorizedRevision"` (exit 0);
- `revision_match == true`;
- `vault_object_verified == true`;
- `resolved_vault_path` is non-empty.

A failure record must never report `revision_match=true`. When the mutable
locator was not read, `source_stable_during_snapshot` must be `null` (not
falsely `true`).

## 4. Fail-closed outcomes

### `SampleIdentityMismatch`

Use when the stable copied bytes do not match the manifest-authorized digest or size.

Required action:

- stop before build/unpack/launch;
- do not update the manifest;
- do not call the new binary the old revision;
- preserve the stable copy under its own SHA-256 if retention is authorized (the
  resolver archives stable-but-unmatched bytes under an `observed-revisions`
  area only when `--RetainUnmatched` is passed; it is never auto-promoted);
- report the mismatch as a sample-revision event, not a recovery-code failure.

### `SourceChangedDuringSnapshot`

Use when the mutable source changes during the copy/hash sequence.

Required action:

- discard the temporary copy or quarantine it as non-authoritative;
- do not execute it;
- report all observed hashes/sizes and timestamps;
- wait for a stable source window or an operator-supplied immutable copy.

### `AuthorizedRevisionUnavailable`

Use when the manifest revision is known but no immutable vault object reproduces it.

Required action:

- stop the live route;
- request the exact authorized bytes or a separately governed manifest-revision change;
- never substitute the current mutable-path contents.

## 5. Introducing a new sample revision

A newly observed SHA-256 is a new revision, not an automatic replacement.

To promote it:

1. Archive the bytes under their own SHA-256 in the external vault.
2. Produce static identity/fingerprint evidence.
3. Decide whether it is a new case revision, a new corpus artifact, or an untrusted update.
4. Review compatibility and migration impact.
5. Update the case manifest in a dedicated, reviewed commit with an incremented `manifest_revision`.
6. Update or add authority dossier/evidence references.
7. Open a new explicitly authorized live route for that revision.
8. Keep prior revisions addressable by digest; do not overwrite historical authority.

A manifest change must never be made merely to make a failing preflight turn green.

## 6. Handoff requirements

Every worker handoff involving GTO must state:

- mutable locator used;
- stable resolved vault path;
- observed SHA-256 and size;
- expected SHA-256 and size;
- manifest revision;
- `revision_match` result;
- whether the source changed during snapshot;
- whether any sample was executed;
- route/round ledger outcome.

The handoff must include this exact warning:

> `D:\Tools\RE\dumps\gto\启动器.exe` is mutable and may auto-update. Never trust it by path or filename. Snapshot it, verify stability, resolve by SHA-256, and run only the manifest-authorized immutable vault object.

## 7. Current Route I lesson

Route I R1 on 2026-08-08 correctly stopped at preflight because the mutable path contained a different revision from the manifest-authorized artifact. That event is `SampleIdentityMismatch`; it provides no result about bootstrap, OEP, UI, script execution, or product readiness.

Future routes must resolve the immutable revision before consuming a live-round budget. A preflight-only identity mismatch should be recorded separately from an executed live round whenever governance permits that distinction.
