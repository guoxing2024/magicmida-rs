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
- **The idempotent-reuse path is no less strict than a fresh capture.** Reusing
  an existing content-addressed snapshot still requires BOTH source reads: the
  source must be byte-stable across the whole capture, exactly like a fresh
  capture. If the source changes or becomes unreadable while the existing
  snapshot is being verified, capture fails closed and the existing snapshot is
  neither deleted nor overwritten (G3-R2-R2).
- **Publish is atomic no-replace.** `publish_no_replace` uses
  `std::fs::hard_link(temp, target)`, not `exists()+rename()`. On Unix this is
  the atomic directory-entry creation semantics of `link(2)`; on Windows the
  standard library maps to the no-replace `CreateHardLinkW` operation. A race
  yields exactly one successful `Published` result and `AlreadyExists` for the
  losers; an existing target is never overwritten and no half-written target is
  visible because the temp file was fully written and verified first. The temp
  and target are deliberately in the same hash directory, so they must be on
  the same filesystem/volume; cross-volume publication is not supported.
- **Failed-capture cleanup is ownership-safe.** A failed fresh capture removes
  only its own uniquely named temp file. It does not remove the shared
  content-addressed hash directory, even when that directory is empty: directory
  ownership can change between an existence check and cleanup, while an empty
  directory is harmless metadata.
- If the file changes during capture, the caller must **not** proceed to
  staging.

## Staging seam

Staging is driven by a **snapshot path**, never the live source path. The
offline `sample_snapshot::StagingIdentity` carries the snapshot hash/size as
the identity and the source path as provenance.

**Verified resolve is mandatory before staging.** `verified_read_snapshot`
re-reads the on-disk snapshot and recomputes its SHA-256, size, and
revision/logical-id consistency; a modified, truncated, replaced, missing, or
forged snapshot is rejected (`VerifiedResolveFailed`). The returned
`VerifiedSnapshot`, including `snapshot_bytes`, proves only what was observed at
that read instant; it is not a durable immutability proof. `staging_identity_matches`
does NOT trust the in-memory `SampleSnapshot`/`StagingIdentity` hash/size alone:
it re-verifies the on-disk snapshot against the expected manifest identity at the
staging boundary. A forged or stale in-memory identity cannot bypass this.

**Revision integrity is part of the identity.** `staging_identity_matches` also
requires `staging.revision == revision_id(logical_sample_id, canonical_sha256)`.
A `StagingIdentity` with the correct hash/size/disk but a forged or re-ordered
revision (derived from a different hash or a different logical id) is rejected
(G3-R2-R2). Hash inputs are canonicalized to lowercase, so resolve, verified
resolve, and revision construction all agree on the same address.

A new revision therefore never passes an old manifest-bound identity, and a
tampered snapshot is rejected (verified by real on-disk tamper tests).

## Current wiring point

`mida-cli` exposes `crate::sample_snapshot` (capture, verified resolve,
staging-identity seam) with offline tests covering idempotent capture
(incl. the reuse path's two-read stability), concurrent publication, no-replace
publish races, fail-closed cleanup of a failed second read, revision-integrity
forgery rejection, verified resolve, real disk tampering, path-boundary
validation, and fresh/reused PE-identity consistency. It is NOT yet wired into
the GTO preflight lane: the sealed `lab/cases/v2/gto_launcher.json` is
untouched, and the authoritative sample revision is still under adjudication.
The next wiring step is for a GTO staging entry to take a verified snapshot path
as its input identity and bind the case to the snapshot hash/size.

## Rules

- The dynamic path is a source; the manifest binds a frozen revision, never the
  dynamic path.
- `4d5770af…`, `79e26e91…`, `bd7366d6…` must not be automatically merged.
- Real-sample acceptance must target an explicit revision.
- Without human adjudication of the authoritative sample, do not enter GTO
  staging.
