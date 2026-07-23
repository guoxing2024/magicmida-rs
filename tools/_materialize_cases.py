# -*- coding: utf-8 -*-
"""Materialize vault case PE objects into scratch for authorized local runs."""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

VAULT = Path(r"D:\MidaVault")
CASES = VAULT / "manifests" / "cases"
OBJECTS = VAULT / "objects" / "sha256"
OUT = VAULT / "scratch" / "materialized"


def object_path(sha: str) -> Path:
    return OBJECTS / sha[:2] / sha


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    report = []
    for mf in sorted(CASES.glob("*.json")):
        data = json.loads(mf.read_text(encoding="utf-8"))
        case_id = data.get("case_id", mf.stem)
        arts = data.get("artifacts") or []
        primary = data.get("primary_artifact_sha256")
        for art in arts:
            sha = art["sha256"]
            size = art.get("size_bytes")
            role = art.get("role", "artifact")
            src = object_path(sha)
            present = src.is_file()
            actual = src.stat().st_size if present else None
            size_ok = present and (size is None or actual == size)
            dest = OUT / f"{case_id}__{role}__{sha[:12]}.bin"
            hash_ok = False
            if present and size_ok:
                # hardlink or copy
                if dest.exists():
                    dest.unlink()
                try:
                    dest.hardlink_to(src)
                except OSError:
                    shutil.copy2(src, dest)
                h = hashlib.sha256()
                with dest.open("rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                hash_ok = h.hexdigest() == sha
            entry = {
                "case_id": case_id,
                "role": role,
                "sha256": sha,
                "primary": sha == primary,
                "present": present,
                "size_ok": size_ok,
                "hash_ok": hash_ok,
                "dest": str(dest) if present and size_ok else None,
            }
            report.append(entry)
            print(
                f"{case_id:18} {role:28} present={present} size_ok={size_ok} "
                f"hash_ok={hash_ok} primary={sha == primary}"
            )
    summary = OUT / "_materialize_report.json"
    summary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("wrote", summary)
    bad = [r for r in report if not (r["present"] and r["size_ok"] and r["hash_ok"])]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
