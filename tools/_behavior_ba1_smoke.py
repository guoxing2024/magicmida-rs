#!/usr/bin/env python3
"""B-A1 smoke: synthetic fixture positive/negative probes.

Engineering only — not VNEXT-BEH, not Accepted.
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PROBE = REPO / "tools" / "_behavior_probe.py"
OUT_ROOT = REPO / "lab" / "behavior" / "evidence"


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(PROBE), *args]
    print("+", " ".join(cmd), flush=True)
    # Windows VsDevCmd / cargo may emit CP936; never fail the smoke on decode.
    return subprocess.run(
        cmd,
        cwd=str(REPO),
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


def main() -> int:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch = OUT_ROOT / f"batch_{stamp}_ba1"
    batch.mkdir(parents=True, exist_ok=True)

    # Build fixture once
    b = run(["--build-fixture"])
    print(b.stdout, end="")
    print(b.stderr, end="", file=sys.stderr)
    if b.returncode != 0:
        print("BUILD_FAIL", file=sys.stderr)
        return 1
    fixture = b.stdout.strip().splitlines()[-1].strip()
    if not Path(fixture).is_file():
        print("fixture path missing:", fixture, file=sys.stderr)
        return 1

    cases = [
        {
            "name": "pass",
            "args": [
                "--candidate",
                fixture,
                "--mode",
                "pass",
                "--expect-verdict",
                "Pass",
                "--out",
                str(batch / "pass.json"),
            ],
            "want": "Pass",
        },
        {
            "name": "fail_exit",
            "args": [
                "--candidate",
                fixture,
                "--mode",
                "fail_exit",
                "--expect-verdict",
                "Fail",
                "--out",
                str(batch / "fail_exit.json"),
            ],
            "want": "Fail",
        },
        {
            "name": "no_marker",
            "args": [
                "--candidate",
                fixture,
                "--mode",
                "no_marker",
                "--expect-verdict",
                "Fail",
                "--out",
                str(batch / "no_marker.json"),
            ],
            "want": "Fail",
        },
        {
            "name": "hang_timeout",
            "args": [
                "--candidate",
                fixture,
                "--mode",
                "hang",
                "--max-wall-ms",
                "800",
                "--expect-verdict",
                "Inconclusive",
                "--out",
                str(batch / "hang.json"),
            ],
            "want": "Inconclusive",
        },
    ]

    results = []
    all_ok = True
    for c in cases:
        r = run(c["args"])
        print(r.stdout, end="")
        if r.stderr:
            print(r.stderr, end="", file=sys.stderr)
        ok = r.returncode == 0
        verdict = None
        out_path = None
        for a, b_ in zip(c["args"], c["args"][1:]):
            if a == "--out":
                out_path = Path(b_)
        if out_path and out_path.is_file():
            ev = json.loads(out_path.read_text(encoding="utf-8"))
            verdict = ev.get("verdict")
            if verdict != c["want"]:
                ok = False
        else:
            ok = False
        results.append(
            {
                "name": c["name"],
                "ok": ok,
                "exit": r.returncode,
                "verdict": verdict,
                "want": c["want"],
            }
        )
        if not ok:
            all_ok = False

    summary = {
        "phase": "B-A1",
        "r4_gate": False,
        "beh_gate": False,
        "accepted_enabled": False,
        "batch_dir": str(batch),
        "fixture": fixture,
        "results": results,
        "all_ok": all_ok,
        "note": "Engineering synthetic probe only. Does not write VNEXT-BEH or Accepted.",
    }
    summary_path = batch / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"summary {summary_path} all_ok {all_ok}", flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
