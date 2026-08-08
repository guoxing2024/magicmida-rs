#!/usr/bin/env python3
"""Manifest-pinned GTO sample revision resolver (pure stdlib core).

Implements the policy in docs/GTO_SAMPLE_REVISION_POLICY.md as a deterministic,
fail-closed preflight resolver.

Authority model
---------------
1.  ``lab/cases/v2/<case_id>.json`` is the identity authority. The authorized
    protected_input digest+size come ONLY from the manifest after strict
    validation.
2.  A content-addressed vault object (by SHA-256) that reproduces that digest
    and size is the immutable, executable source.
3.  The mutable acquisition path is a locator, never an identity. It is read
    ONLY when the authorized vault object is absent, or when the caller
    explicitly requests acquisition.

Modes
-----
- authorized_vault  : resolve an existing, re-hashed vault object; do not read
                      the mutable locator.
- mutable_snapshot  : stable-copy the mutable locator (H1/H2/H3), verify it
                      matches the manifest, then place it in the vault.

Exit codes (stable, machine-consumable):
    0   ResolvedAuthorizedRevision
    10  SourceChangedDuringSnapshot
    11  SampleIdentityMismatch
    12  AuthorizedRevisionUnavailable
    13  VaultObjectCorrupt
    14  ManifestInvalid
    15  SourceInvalid
    16  ResolutionRecordWriteFailed
    17  InternalError

This script never loads, launches, or executes a PE. All tests use synthetic
bytes and temp directories.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# Exit codes / statuses
# ---------------------------------------------------------------------------

EXIT_OK = 0
EXIT_SOURCE_CHANGED = 10
EXIT_SAMPLE_MISMATCH = 11
EXIT_UNAVAILABLE = 12
EXIT_VAULT_CORRUPT = 13
EXIT_MANIFEST_INVALID = 14
EXIT_SOURCE_INVALID = 15
EXIT_RECORD_WRITE_FAILED = 16
EXIT_INTERNAL = 17

STATUS_RESOLVED = "ResolvedAuthorizedRevision"
STATUS_SOURCE_CHANGED = "SourceChangedDuringSnapshot"
STATUS_SAMPLE_MISMATCH = "SampleIdentityMismatch"
STATUS_UNAVAILABLE = "AuthorizedRevisionUnavailable"
STATUS_VAULT_CORRUPT = "VaultObjectCorrupt"
STATUS_MANIFEST_INVALID = "ManifestInvalid"
STATUS_SOURCE_INVALID = "SourceInvalid"
STATUS_RECORD_WRITE_FAILED = "ResolutionRecordWriteFailed"
STATUS_INTERNAL = "InternalError"

STATUS_BY_EXIT = {
    EXIT_OK: STATUS_RESOLVED,
    EXIT_SOURCE_CHANGED: STATUS_SOURCE_CHANGED,
    EXIT_SAMPLE_MISMATCH: STATUS_SAMPLE_MISMATCH,
    EXIT_UNAVAILABLE: STATUS_UNAVAILABLE,
    EXIT_VAULT_CORRUPT: STATUS_VAULT_CORRUPT,
    EXIT_MANIFEST_INVALID: STATUS_MANIFEST_INVALID,
    EXIT_SOURCE_INVALID: STATUS_SOURCE_INVALID,
    EXIT_RECORD_WRITE_FAILED: STATUS_RECORD_WRITE_FAILED,
    EXIT_INTERNAL: STATUS_INTERNAL,
}

RESOLVED_SCHEMA = "mida.resolved-source/v1"


class ResolverError(Exception):
    """Carries an exit code (and optional detail)."""

    def __init__(self, exit_code: int, detail: str) -> None:
        super().__init__(detail)
        self.exit_code = exit_code
        self.detail = detail

    @property
    def status(self) -> str:
        return STATUS_BY_EXIT.get(self.exit_code, STATUS_INTERNAL)


# ---------------------------------------------------------------------------
# JSON parsing helpers (strict)
# ---------------------------------------------------------------------------

def _reject_duplicate_keys(pairs):
    result: Dict[str, Any] = {}
    for key, val in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key!r}")
        result[key] = val
    return result


def _load_json_strict(path: Path) -> Dict[str, Any]:
    """Load JSON rejecting duplicate keys and malformed input."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read manifest: {exc}") from exc
    decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys)
    try:
        text = raw.decode("utf-8-sig")
        value, _end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"malformed JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("manifest root must be a JSON object")
    # raw_decode stops at the first value; reject trailing non-whitespace.
    if _end != len(text):
        remainder = text[_end:].strip()
        if remainder:
            raise ValueError("manifest has trailing non-whitespace content")
    return value


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_lower_hex64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


# ---------------------------------------------------------------------------
# Test seams (deterministic hooks; never rely on real mutation races)
# ---------------------------------------------------------------------------

HASH_FILE_HOOK: Optional[Callable[[Path], str]] = None
SIZE_HOOK: Optional[Callable[[Path], int]] = None


def _hash_file(path: Path) -> str:
    if HASH_FILE_HOOK is not None:
        return HASH_FILE_HOOK(path)
    return sha256_file(path)


def _size(path: Path) -> int:
    if SIZE_HOOK is not None:
        return SIZE_HOOK(path)
    return os.path.getsize(path)


# ---------------------------------------------------------------------------
# Manifest validation
# ---------------------------------------------------------------------------

def validate_manifest(manifest_path: Path, case_id: str) -> Dict[str, Any]:
    """Return validated manifest fields. Raises ResolverError on any violation."""
    if not manifest_path.exists():
        raise ResolverError(
            EXIT_MANIFEST_INVALID, f"manifest path does not exist: {manifest_path}"
        )
    try:
        manifest = _load_json_strict(manifest_path)
    except ValueError as exc:
        raise ResolverError(EXIT_MANIFEST_INVALID, str(exc)) from exc

    if manifest.get("schema_version") != "mida.case-manifest/v2":
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "schema_version must equal 'mida.case-manifest/v2'",
        )
    if manifest.get("case_id") != case_id:
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            f"case_id must equal requested case id {case_id!r}",
        )
    rev = manifest.get("manifest_revision")
    if not isinstance(rev, int) or isinstance(rev, bool) or rev <= 0:
        raise ResolverError(
            EXIT_MANIFEST_INVALID, "manifest_revision must be a positive integer"
        )

    primary = manifest.get("primary_artifact_sha256")
    if not is_lower_hex64(primary):
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "primary_artifact_sha256 must be lowercase 64-hex",
        )

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ResolverError(EXIT_MANIFEST_INVALID, "artifacts must be a list")

    protected_inputs = [
        a for a in artifacts if isinstance(a, dict) and a.get("role") == "protected_input"
    ]
    if len(protected_inputs) != 1:
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "artifacts must have exactly one role=protected_input",
        )
    protected = protected_inputs[0]

    protected_sha = protected.get("sha256")
    if not is_lower_hex64(protected_sha):
        raise ResolverError(
            EXIT_MANIFEST_INVALID, "protected_input.sha256 must be lowercase 64-hex"
        )

    size = protected.get("size_bytes")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "protected_input.size_bytes must be a positive integer",
        )

    dyn = manifest.get("execution_policy", {})
    if not isinstance(dyn, dict):
        raise ResolverError(EXIT_MANIFEST_INVALID, "execution_policy must be object")
    dyn = dyn.get("dynamic")
    if not isinstance(dyn, dict):
        raise ResolverError(EXIT_MANIFEST_INVALID, "execution_policy.dynamic must be object")
    fixed_sha = dyn.get("fixed_sha256")
    if not is_lower_hex64(fixed_sha):
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "execution_policy.dynamic.fixed_sha256 must be lowercase 64-hex",
        )
    mode = dyn.get("mode")
    if mode != "explicit_authorization_required":
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "execution_policy.dynamic.mode must be explicit_authorization_required",
        )

    if primary != protected_sha:
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "primary_artifact_sha256 != protected_input.sha256",
        )
    if fixed_sha != protected_sha:
        raise ResolverError(
            EXIT_MANIFEST_INVALID,
            "execution_policy.dynamic.fixed_sha256 != protected_input.sha256",
        )

    return {
        "manifest": manifest,
        "case_id": case_id,
        "manifest_revision": rev,
        "expected_sha256": protected_sha,
        "expected_size_bytes": size,
    }


# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

def vault_object_path(vault_root: Path, sha256: str) -> Path:
    """Derive the content-addressed vault path from a validated digest."""
    if not is_lower_hex64(sha256):
        raise ValueError(f"refusing vault path from non-64-hex: {sha256!r}")
    return vault_root / "sha256" / sha256[:2] / sha256 / "artifact.exe"


def _is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        import ctypes

        FILE_ATTRIBUTE_REPARSE_POINT = 0x400
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == 0xFFFFFFFF:
            return False
        return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)
    except Exception:  # pragma: no cover - non-Windows fallback
        return False


# ---------------------------------------------------------------------------
# Stable snapshot (H1/H2/H3)
# ---------------------------------------------------------------------------

class StableCopy:
    """A verified stable temp copy of the mutable source.

    ``path`` holds bytes verified to satisfy H1==H2==H3 and all sizes equal.
    Caller owns cleanup via ``discard()`` or promotion via ``promote_to``.
    """

    __slots__ = ("path", "sha256", "size")

    def __init__(self, path: Path, sha256: str, size: int) -> None:
        self.path = path
        self.sha256 = sha256
        self.size = size

    def discard(self) -> None:
        # Consumed copies (path is None after promotion) are left in place.
        if self.path is None:
            return
        try:
            if self.path.exists():
                os.unlink(self.path)
        except OSError:
            pass
        self.path = None

    def promote_to(self, dest: Path) -> None:
        """Atomically move the verified bytes into place, then re-hash."""
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self.path, dest)
        if _hash_file(dest) != self.sha256 or _size(dest) != self.size:
            raise ResolverError(
                EXIT_VAULT_CORRUPT,
                f"vault object failed post-write hash verification: {dest}",
            )
        self.path = None  # consumed; discard becomes a no-op


def stable_snapshot(source: Path, staging_dir: Path) -> StableCopy:
    """Stable-copy ``source`` into a random temp file under ``staging_dir``.

    H1/S1 from source, copy, H2/S2 from the copy, H3/S3 from the source again.
    Require all equal. Returns a verified StableCopy (temp file) whose bytes
    satisfy the checks. Raises ResolverError on invalid source or change.
    """
    if not source.exists():
        raise ResolverError(
            EXIT_UNAVAILABLE,
            "authorized vault object absent and mutable locator does not exist: "
            f"{source}",
        )
    if not source.is_file():
        raise ResolverError(
            EXIT_SOURCE_INVALID, f"mutable source is not a regular file: {source}"
        )
    if _is_reparse_point(source):
        raise ResolverError(
            EXIT_SOURCE_INVALID, f"refusing reparse point/symlink source: {source}"
        )

    h1 = _hash_file(source)
    s1 = _size(source)

    staging_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".resolve-", suffix=".tmp", dir=str(staging_dir))
    os.close(fd)
    tmp = Path(tmp_path)
    try:
        shutil.copyfile(source, tmp)
        h2 = _hash_file(tmp)
        s2 = _size(tmp)
        h3 = _hash_file(source)
        s3 = _size(source)

        if not (h1 == h2 == h3 and s1 == s2 == s3):
            raise ResolverError(
                EXIT_SOURCE_CHANGED,
                f"source changed during snapshot (H=[{h1[:8]}..,{h2[:8]}..,{h3[:8]}..] "
                f"S=[{s1},{s2},{s3}])",
            )
        return StableCopy(tmp, h1, s1)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Atomic writes
# ---------------------------------------------------------------------------

def _atomic_write_bytes(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".write-", suffix=".tmp", dir=str(dest.parent))
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, dest)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Record writing
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def tool_sha256() -> str:
    try:
        return sha256_text(Path(__file__).read_text(encoding="utf-8"))
    except OSError:
        return ""


def _write_record(record: Dict[str, Any], evidence_dir: Path) -> None:
    out_path = evidence_dir / "resolved_source.json"
    data = json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    try:
        _atomic_write_bytes(out_path, data.encode("utf-8"))
    except OSError as exc:
        raise ResolverError(
            EXIT_RECORD_WRITE_FAILED,
            f"failed to atomically write resolution record: {exc}",
        ) from exc


def _finalize_record(record: Dict[str, Any], evidence_dir: Path) -> Dict[str, Any]:
    record["resolved_utc"] = utc_now()
    record["resolver_tool_sha256"] = tool_sha256()
    _write_record(record, evidence_dir)
    return record


# ---------------------------------------------------------------------------
# Resolution orchestration
# ---------------------------------------------------------------------------

def _new_record(parsed, manifest_path, source_path, manifest_sha) -> Dict[str, Any]:
    return {
        "schema_version": RESOLVED_SCHEMA,
        "case_id": parsed["case_id"],
        "manifest_revision": parsed["manifest_revision"],
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha,
        "mutable_locator": str(source_path) if source_path is not None else None,
        "resolution_mode": "authorized_vault",
        "resolved_vault_path": None,
        "observed_sha256": None,
        "observed_size_bytes": None,
        "expected_sha256": parsed["expected_sha256"],
        "expected_size_bytes": parsed["expected_size_bytes"],
        "source_stable_during_snapshot": None,
        "vault_object_verified": False,
        "revision_match": False,
        "resolution_status": STATUS_UNAVAILABLE,
        "resolved_utc": None,
        "resolver_tool_sha256": None,
    }


def resolve(
    *,
    manifest_path: Path,
    case_id: str,
    vault_root: Path,
    evidence_dir: Path,
    source_path: Optional[Path],
    force_acquire: bool,
    retain_unmatched: bool,
    observed_revisions_dir: Optional[Path],
) -> Dict[str, Any]:
    parsed = validate_manifest(manifest_path, case_id)
    manifest_sha = sha256_bytes(manifest_path.read_bytes())
    record = _new_record(parsed, manifest_path, source_path, manifest_sha)
    expected_sha = parsed["expected_sha256"]
    expected_size = parsed["expected_size_bytes"]
    vault_path = vault_object_path(vault_root, expected_sha)

    try:
        # --- Mode A: authorized vault-first (default) ---
        if not force_acquire:
            if vault_path.exists():
                if not vault_path.is_file():
                    raise ResolverError(
                        EXIT_VAULT_CORRUPT,
                        f"vault object not a regular file: {vault_path}",
                    )
                obj_sha = _hash_file(vault_path)
                obj_size = _size(vault_path)
                if obj_sha == expected_sha and obj_size == expected_size:
                    record.update(
                        {
                            "resolution_mode": "authorized_vault",
                            "resolved_vault_path": str(vault_path),
                            "observed_sha256": obj_sha,
                            "observed_size_bytes": obj_size,
                            "source_stable_during_snapshot": None,
                            "vault_object_verified": True,
                            "revision_match": True,
                            "resolution_status": STATUS_RESOLVED,
                        }
                    )
                    return _finalize_record(record, evidence_dir)
                raise ResolverError(
                    EXIT_VAULT_CORRUPT,
                    f"vault object exists but content mismatch "
                    f"(expected {expected_sha[:12]}.../{expected_size}, "
                    f"got {obj_sha[:12] if obj_sha else '?'}/{obj_size if obj_size is not None else '?'}); "
                    f"refusing to overwrite: {vault_path}",
                )

        # --- Mode B: mutable acquisition (only when vault absent or forced) ---
        if source_path is None:
            raise ResolverError(
                EXIT_UNAVAILABLE,
                "authorized vault object absent and no mutable source path provided",
            )

        record["resolution_mode"] = "mutable_snapshot"
        copy = stable_snapshot(source_path, vault_root)
        try:
            record["source_stable_during_snapshot"] = True
            record["observed_sha256"] = copy.sha256
            record["observed_size_bytes"] = copy.size

            if copy.sha256 != expected_sha or copy.size != expected_size:
                if retain_unmatched and observed_revisions_dir is not None:
                    _archive_observed(copy, observed_revisions_dir, vault_root)
                raise ResolverError(
                    EXIT_SAMPLE_MISMATCH,
                    f"stable snapshot does not match manifest "
                    f"(got {copy.sha256[:12]}.../{copy.size}, "
                    f"expected {expected_sha[:12]}.../{expected_size})",
                )

            copy.promote_to(vault_path)
            record["resolved_vault_path"] = str(vault_path)
            record["vault_object_verified"] = True
            record["revision_match"] = True
            record["resolution_status"] = STATUS_RESOLVED
            return _finalize_record(record, evidence_dir)
        finally:
            copy.discard()
    except ResolverError as exc:
        record["resolution_status"] = exc.status
        _finalize_record(record, evidence_dir)
        raise


def _archive_observed(copy: StableCopy, observed_dir: Path, vault_root: Path) -> None:
    """Archive a stable-but-unmatched revision (non-promoting, no overwrite)."""
    dest = observed_dir / copy.sha256[:2] / copy.sha256 / "artifact.exe"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        raise ResolverError(
            EXIT_VAULT_CORRUPT,
            f"observed revision path already present; refusing overwrite: {dest}",
        )
    copy.promote_to(dest)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="resolve_gto_source_revision",
        description=(
            "Resolve the manifest-authorized GTO sample revision to an immutable "
            "vault path (fail-closed). Never loads or executes a PE."
        ),
        add_help=True,
    )
    p.add_argument("--ManifestPath", required=True, help="path to case manifest JSON")
    p.add_argument("--CaseId", default="gto_launcher", help="case id (default gto_launcher)")
    p.add_argument("--VaultRoot", required=True, help="content-addressed vault root")
    p.add_argument("--EvidenceDir", required=True, help="output dir for resolved_source.json")
    p.add_argument("--SourcePath", default=None, help="mutable acquisition locator (optional)")
    p.add_argument(
        "--ForceAcquire",
        action="store_true",
        help="read the mutable locator even if an authorized vault object exists",
    )
    p.add_argument(
        "--RetainUnmatched",
        action="store_true",
        help="archive a stable-but-unmatched snapshot under observed-revisions (never promotes)",
    )
    p.add_argument(
        "--ObservedRevisionsDir",
        default=None,
        help="dir to archive stable unmatched revisions when --RetainUnmatched",
    )
    return p


def main(argv: Optional[list] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        manifest_path = Path(args.ManifestPath)
        vault_root = Path(args.VaultRoot)
        evidence_dir = Path(args.EvidenceDir)
        source_path = Path(args.SourcePath) if args.SourcePath else None
        observed_dir = (
            Path(args.ObservedRevisionsDir) if args.ObservedRevisionsDir else None
        )
        if args.RetainUnmatched and observed_dir is None:
            observed_dir = vault_root.parent / "observed-revisions"
        if args.ForceAcquire and source_path is None:
            parser.error("--ForceAcquire requires --SourcePath")

        resolve(
            manifest_path=manifest_path,
            case_id=args.CaseId,
            vault_root=vault_root,
            evidence_dir=evidence_dir,
            source_path=source_path,
            force_acquire=args.ForceAcquire,
            retain_unmatched=args.RetainUnmatched,
            observed_revisions_dir=observed_dir,
        )
        return EXIT_OK
    except ResolverError as exc:
        print(f"[{exc.status}] {exc.detail}", file=sys.stderr)
        return exc.exit_code
    except Exception as exc:  # pragma: no cover - defensive
        print(f"[InternalError] {exc!r}", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    sys.exit(main())
