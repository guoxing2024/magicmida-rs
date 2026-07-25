# -*- coding: utf-8 -*-
"""R0B static check for Origin live unpack candidate (vault evidence only)."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ACC = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-acceptance.exe")
CAND = Path(
    r"D:\MidaVault\lab\evidence\origin_macro\live_20260723-132326\origin_unpacked.exe"
)
ORACLE = Path(
    r"D:\MidaVault\scratch\materialized\origin_macro__legacy_oracle_candidate__fe92f992bcf0.bin"
)
EV_DIR = Path(r"D:\MidaVault\lab\evidence\origin_macro\live_20260723-132326")


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    if not CAND.is_file():
        print("missing candidate", CAND, file=sys.stderr)
        return 2
    if not ACC.is_file():
        print("missing acceptance", ACC, file=sys.stderr)
        return 2

    digest = sha256_file(CAND)
    size = CAND.stat().st_size
    report = EV_DIR / "r0b_candidate.json"
    cmd = [
        str(ACC),
        "check-static",
        str(CAND),
        "--expected-sha256",
        digest,
        "--expected-size",
        str(size),
        "--role",
        "candidate",
        "--report",
        str(report),
    ]
    if ORACLE.is_file():
        cmd.extend(["--oracle", str(ORACLE)])

    print("RUN", " ".join(cmd), flush=True)
    p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    stdout_path = EV_DIR / "r0b_candidate.stdout.txt"
    stdout_path.write_text((p.stdout or "") + "\n---STDERR---\n" + (p.stderr or ""), encoding="utf-8")

    verdict = None
    failures = []
    if report.is_file():
        data = json.loads(report.read_text(encoding="utf-8"))
        verdict = data.get("verdict")
        failures = [
            f.get("code") or f.get("gate_id") for f in (data.get("failures") or [])
        ]

    meta = {
        "run_id": "live_20260723-132326",
        "candidate": str(CAND),
        "sha256": digest,
        "size": size,
        "exit_code": p.returncode,
        "verdict": verdict,
        "failures": failures,
        "report": str(report),
        "finished": datetime.now().isoformat(timespec="seconds"),
    }
    (EV_DIR / "r0b_candidate_meta.json").write_text(
        json.dumps(meta, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(meta, indent=2))
    return 0 if p.returncode == 0 else p.returncode


if __name__ == "__main__":
    sys.exit(main())
