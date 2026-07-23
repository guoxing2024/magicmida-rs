#!/usr/bin/env python3
"""B-A3 lab smoke: structural → probe → evidence compose (synthetic first).

Pipeline per case:
  1. mida-acceptance check-static <candidate>   → structural report
  2. tools/_behavior_probe.py                    → mida.behavior-evidence/v0
  3. mida-acceptance check-with-behavior …       → composed verdict

Engineering only — not VNEXT-BEH, not pure flip, not vault malware.
Origin/protected samples are out of scope for this smoke.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
PROBE = REPO / "tools" / "_behavior_probe.py"
OUT_ROOT = REPO / "lab" / "behavior" / "evidence"
VSDEV = Path(
    r"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
)


def run(
    args: list[str], *, cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(args), flush=True)
    return subprocess.run(
        args,
        cwd=str(cwd or REPO),
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )


def find_acceptance_bin() -> Path | None:
    env = os.environ.get("MIDA_ACCEPTANCE_BIN")
    if env:
        p = Path(env)
        if p.is_file():
            return p
    candidates = [
        REPO / "target" / "debug" / "mida-acceptance.exe",
        REPO / "target" / "release" / "mida-acceptance.exe",
        REPO / "target" / "debug" / "mida-acceptance",
        REPO / "target" / "release" / "mida-acceptance",
    ]
    td = os.environ.get("CARGO_TARGET_DIR")
    if td:
        t = Path(td)
        candidates.extend(
            [
                t / "debug" / "mida-acceptance.exe",
                t / "release" / "mida-acceptance.exe",
                t / "debug" / "mida-acceptance",
                t / "release" / "mida-acceptance",
            ]
        )
    for p in candidates:
        if p.is_file():
            return p
    # Walk target once (bounded)
    root = REPO / "target"
    if root.is_dir():
        for p in root.rglob("mida-acceptance.exe"):
            return p
        for p in root.rglob("mida-acceptance"):
            if p.is_file():
                return p
    return None


def ensure_acceptance_bin() -> Path:
    existing = find_acceptance_bin()
    if existing is not None:
        return existing

    target_dir = REPO / "target"
    cargo = [
        "cargo",
        "build",
        "-p",
        "mida-acceptance",
        "--offline",
        "--bin",
        "mida-acceptance",
    ]
    if VSDEV.is_file() and os.name == "nt":
        bat = REPO / "lab" / "behavior" / "evidence" / "_build_acceptance_ba3.cmd"
        bat.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            "@echo off",
            f'call "{VSDEV}" -arch=x64 -host_arch=x64 -no_logo',
            "if errorlevel 1 exit /b 1",
            f'cd /d "{REPO}"',
            " ".join(f'"{a}"' for a in cargo),
            "exit /b %ERRORLEVEL%",
            "",
        ]
        bat.write_text("\r\n".join(lines), encoding="ascii")
        r = run(["cmd", "/c", str(bat)])
    else:
        r = run(cargo)
    print(r.stdout, end="")
    if r.stderr:
        print(r.stderr, end="", file=sys.stderr)
    if r.returncode != 0:
        raise SystemExit(f"build mida-acceptance failed exit={r.returncode}")
    found = find_acceptance_bin()
    if found is None:
        raise SystemExit(f"mida-acceptance binary missing under {target_dir}")
    return found


def parse_report_json(stdout: str) -> dict[str, Any]:
    text = stdout.strip()
    if not text:
        raise ValueError("empty stdout")
    # CLI prints a single JSON document
    return json.loads(text)


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> int:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    batch = OUT_ROOT / f"batch_{stamp}_ba3"
    batch.mkdir(parents=True, exist_ok=True)

    acc = ensure_acceptance_bin()
    print(f"acceptance_bin={acc}", flush=True)

    # 1) Build / locate synthetic candidate
    b = run([sys.executable, str(PROBE), "--build-fixture"])
    print(b.stdout, end="")
    if b.stderr:
        print(b.stderr, end="", file=sys.stderr)
    if b.returncode != 0:
        print("BUILD_FIXTURE_FAIL", file=sys.stderr)
        return 1
    fixture = Path(b.stdout.strip().splitlines()[-1].strip())
    if not fixture.is_file():
        print("fixture missing:", fixture, file=sys.stderr)
        return 1

    # 2) Structural only: must be Pending, never Accepted
    r_static = run([str(acc), "check-static", str(fixture), "--report", str(batch / "structural.json")])
    print(r_static.stdout, end="")
    if r_static.stderr:
        print(r_static.stderr, end="", file=sys.stderr)
    try:
        structural = parse_report_json(r_static.stdout)
    except Exception as e:
        print("STRUCTURAL_PARSE_FAIL", e, file=sys.stderr)
        return 1
    structural_verdict = structural.get("verdict")
    if structural_verdict != "StructuralPassBehaviorPending" or r_static.returncode != 0:
        print(
            f"STRUCTURAL_FAIL verdict={structural_verdict} exit={r_static.returncode}",
            file=sys.stderr,
        )
        return 1
    if structural_verdict == "Accepted":
        print("CONTRACT_FAIL check-static returned Accepted", file=sys.stderr)
        return 1

    cases: list[dict[str, Any]] = [
        {
            "name": "pass_compose_accepted",
            "mode": "pass",
            "expect_evidence": "Pass",
            "expect_compose": "Accepted",
            "expect_exit": 0,
            "max_wall_ms": "5000",
        },
        {
            "name": "fail_compose_rejected",
            "mode": "fail_exit",
            "expect_evidence": "Fail",
            "expect_compose": "Rejected",
            "expect_exit": 2,
            "max_wall_ms": "5000",
        },
        {
            "name": "timeout_compose_pending",
            "mode": "hang",
            "expect_evidence": "Inconclusive",
            "expect_compose": "StructuralPassBehaviorPending",
            "expect_exit": 0,
            "max_wall_ms": "800",
        },
    ]

    results: list[dict[str, Any]] = []
    all_ok = True

    for c in cases:
        name = c["name"]
        case_dir = batch / name
        case_dir.mkdir(parents=True, exist_ok=True)
        evidence_path = case_dir / "evidence.json"
        compose_report = case_dir / "compose.json"

        probe_args = [
            sys.executable,
            str(PROBE),
            "--candidate",
            str(fixture),
            "--mode",
            c["mode"],
            "--max-wall-ms",
            c["max_wall_ms"],
            "--expect-verdict",
            c["expect_evidence"],
            "--out",
            str(evidence_path),
        ]
        pr = run(probe_args)
        print(pr.stdout, end="")
        if pr.stderr:
            print(pr.stderr, end="", file=sys.stderr)

        evidence_verdict = None
        if evidence_path.is_file():
            evidence_verdict = json.loads(evidence_path.read_text(encoding="utf-8")).get(
                "verdict"
            )

        cr = run(
            [
                str(acc),
                "check-with-behavior",
                str(fixture),
                "--behavior-evidence",
                str(evidence_path),
                "--report",
                str(compose_report),
            ]
        )
        print(cr.stdout, end="")
        if cr.stderr:
            print(cr.stderr, end="", file=sys.stderr)

        compose_verdict = None
        try:
            compose_verdict = parse_report_json(cr.stdout).get("verdict")
        except Exception:
            if compose_report.is_file():
                try:
                    compose_verdict = json.loads(
                        compose_report.read_text(encoding="utf-8")
                    ).get("verdict")
                except Exception:
                    compose_verdict = None

        ok = (
            pr.returncode == 0
            and evidence_verdict == c["expect_evidence"]
            and compose_verdict == c["expect_compose"]
            and cr.returncode == c["expect_exit"]
        )
        row = {
            "name": name,
            "ok": ok,
            "probe_exit": pr.returncode,
            "evidence_verdict": evidence_verdict,
            "want_evidence": c["expect_evidence"],
            "compose_exit": cr.returncode,
            "compose_verdict": compose_verdict,
            "want_compose": c["expect_compose"],
            "want_compose_exit": c["expect_exit"],
        }
        results.append(row)
        if not ok:
            all_ok = False
            print("CASE_FAIL", json.dumps(row), file=sys.stderr)

    # 4) Identity mismatch: structural pass + Pass evidence with wrong sha → Rejected
    mismatch_dir = batch / "identity_mismatch"
    mismatch_dir.mkdir(parents=True, exist_ok=True)
    good_ev = batch / "pass_compose_accepted" / "evidence.json"
    bad_ev = mismatch_dir / "evidence.json"
    if good_ev.is_file():
        ev = json.loads(good_ev.read_text(encoding="utf-8"))
        ev["candidate"]["sha256"] = "bb" * 32
        ev["candidate"]["size_bytes"] = 1
        # Keep verdict Pass so only identity binding fails
        ev["verdict"] = "Pass"
        write_json(bad_ev, ev)
        mr = run(
            [
                str(acc),
                "check-with-behavior",
                str(fixture),
                "--behavior-evidence",
                str(bad_ev),
                "--report",
                str(mismatch_dir / "compose.json"),
            ]
        )
        print(mr.stdout, end="")
        if mr.stderr:
            print(mr.stderr, end="", file=sys.stderr)
        try:
            m_verdict = parse_report_json(mr.stdout).get("verdict")
        except Exception:
            m_verdict = None
        m_ok = mr.returncode == 2 and m_verdict == "Rejected"
        results.append(
            {
                "name": "identity_mismatch_rejected",
                "ok": m_ok,
                "compose_exit": mr.returncode,
                "compose_verdict": m_verdict,
                "want_compose": "Rejected",
                "want_compose_exit": 2,
            }
        )
        if not m_ok:
            all_ok = False
    else:
        results.append(
            {
                "name": "identity_mismatch_rejected",
                "ok": False,
                "error": "missing pass evidence for mutation",
            }
        )
        all_ok = False

    # 5) check-static must still refuse Accepted after a successful compose path
    r_static2 = run([str(acc), "check-static", str(fixture)])
    try:
        v2 = parse_report_json(r_static2.stdout).get("verdict")
    except Exception:
        v2 = None
    static_ok = v2 == "StructuralPassBehaviorPending" and r_static2.returncode == 0
    results.append(
        {
            "name": "check_static_still_never_accepted",
            "ok": static_ok,
            "verdict": v2,
            "exit": r_static2.returncode,
        }
    )
    if not static_ok:
        all_ok = False

    summary = {
        "phase": "B-A3",
        "r4_gate": False,
        "beh_gate": False,
        "accepted_enabled": False,
        "pure_default": False,
        "batch_dir": str(batch),
        "fixture": str(fixture),
        "acceptance_bin": str(acc),
        "structural_verdict": structural_verdict,
        "pipeline": "check-static → probe → check-with-behavior",
        "results": results,
        "all_ok": all_ok,
        "note": (
            "Synthetic-only wire of structural + pre-recorded evidence compose. "
            "Does not schedule VNEXT-BEH or flip pure default."
        ),
    }
    summary_path = batch / "summary.json"
    write_json(summary_path, summary)
    print(json.dumps(summary, indent=2))
    print(f"summary {summary_path} all_ok {all_ok}", flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
