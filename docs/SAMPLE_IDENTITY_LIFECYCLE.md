# Sample Identity Lifecycle (G3-R2)

## Problem

`D:\Tools\RE\dumps\gto\启动器.exe` is a **dynamic source path** that automation
overwrites frequently. Binding a case manifest directly to that path is
unstable: the manifest `lab/cases/v2/gto_launcher.json` declares a fixed
protected-input hash, but the live file at that path keeps changing, so
staging/preflight cannot trust the path.

Known distinct identities observed (do NOT assume they are the same revision):

| identity | SHA-256 | size | notes |
|---|---|---|---|
| manifest-bound | `4d5770af…` | 8583680 | matches `_dyncdb/launcher.exe` (`.KI3` layout) |
| earlier `启动器.exe` | `79e26e91…` | 13633536 | observed during a prior acceptance run |
| later `启动器.exe` | `bd7366d6…` | 13373952 | current live file at snapshot time (`.rdataN` layout) |

## Immutable snapshot model

A source file is **frozen into an immutable snapshot before any
staging/preflight**. The snapshot's hash/size become the case identity; the
source path is recorded only as provenance.

- **revision** is hash-derived: `<logical_id>@sha256-<fullhash>` — not a bare
  timestamp, so the same bytes always map to the same revision and changed
  bytes always yield a different revision.
- Snapshots are **content-addressed**: `<snapshot_root>/<logical_id>/<sha256>/snapshot.bin`,
  so a same-name source update never overwrites an older revision, and any old
  revision is reproducible purely by its hash.
- Capture is **fail-closed**: the source is read before and after the snapshot
  write; unless size and hash are identical on both reads AND the snapshot
  equals the source, the capture is rejected with
  `source_changed_during_capture` and no half-written snapshot is kept.
- If the file changes during capture, the caller must **not** proceed to
  staging.

## Staging seam

Staging is driven by a **snapshot path**, never the live source path. The
offline `sample_snapshot::StagingIdentity` carries the snapshot hash/size as
the identity and the source path as provenance; `staging_identity_matches`
fails closed unless the snapshot hash AND size equal an expected manifest
identity. A new revision therefore never passes an old manifest-bound identity,
and a tampered snapshot is rejected.

## Current wiring point

`mida-cli` exposes `crate::sample_snapshot` (capture, resolve, staging-identity
seam) with offline tests. It is NOT yet wired into the GTO preflight lane: the
sealed `lab/cases/v2/gto_launcher.json` is untouched, and the authoritative
sample revision is still under adjudication. The next wiring step is for a GTO
staging entry to take a snapshot path as its input identity and bind the case to
the snapshot hash/size.

## Rules

- The dynamic path is a source; the manifest binds a frozen revision, never the
  dynamic path.
- `4d5770af…`, `79e26e91…`, `bd7366d6…` must not be automatically merged.
- Real-sample acceptance must target an explicit revision.
- Without human adjudication of the authoritative sample, do not enter GTO
  staging.
