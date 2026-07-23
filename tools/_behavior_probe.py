#!/usr/bin/env python3
"""B-A1 offline behavioral probe harness (engineering only).

Runs a candidate PE under a wall-clock cap, checks exit code + optional marker
file, and writes mida.behavior-evidence/v0 JSON.

Does NOT:
  - return or claim R0B Accepted
  - write validation_summary VNEXT-BEH
  - touch vault malware samples
  - enable network (policy network=deny recorded; process inherits host stack
    but probe does not open sockets — synthetic fixtures must not either)

Usage:
  python tools/_behavior_probe.py --candidate path\\to\\pe.exe --mode pass
  python tools/_behavior_probe.py --candidate pe.exe --mode hang --max-wall-ms 500
  python tools/_behavior_probe.py --build-fixture   # cargo build marker_exit
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
FIXTURE_MANIFEST = REPO / "lab" / "behavior" / "synthetic" / "marker_exit" / "Cargo.toml"
SCHEMA_VERSION = "mida.behavior-evidence/v0"
PRODUCER_NAME = "tools/_behavior_probe.py"
PRODUCER_VERSION = "0.1.0-ba1"
MARKER_NEEDLE = "MIDA_BEH_MARKER=1"
PROBE_ID = "exit_code_marker_v0"

# Job-object network isolation is deferred; residual risk is always listed.
RESIDUAL_RISKS = [
    "network_deny_is_policy_not_kernel_filter",
    "no_api_trace_scoring",
    "synthetic_only_ba1",
]


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    data = path.read_bytes()
    h.update(data)
    return h.hexdigest(), len(data)


def find_fixture_exe() -> Path | None:
    """Locate marker_exit.exe under local cargo target dirs."""
    candidates: list[Path] = []
    # Standalone package target next to fixture
    local = (
        REPO
        / "lab"
        / "behavior"
        / "synthetic"
        / "marker_exit"
        / "target"
        / "release"
        / "marker_exit.exe"
    )
    candidates.append(local)
    candidates.append(local.with_name("marker_exit").with_suffix(""))  # non-windows
    debug = local.parent.parent / "debug" / "marker_exit.exe"
    candidates.append(debug)
    env_td = os.environ.get("CARGO_TARGET_DIR")
    if env_td:
        td = Path(env_td)
        candidates.append(td / "release" / "marker_exit.exe")
        candidates.append(td / "debug" / "marker_exit.exe")
        # When building with --manifest-path, package may nest
        candidates.append(td / "release" / "deps" / "marker_exit.exe")
    for p in candidates:
        if p.is_file():
            return p
    return None


def _vsdev_bat() -> Path | None:
    p = Path(
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\VsDevCmd.bat"
    )
    return p if p.is_file() else None


def build_fixture(release: bool = True) -> Path:
    if not FIXTURE_MANIFEST.is_file():
        raise SystemExit(f"fixture Cargo.toml missing: {FIXTURE_MANIFEST}")
    target_dir = REPO / "lab" / "behavior" / "synthetic" / "marker_exit" / "target"
    cargo_args = [
        "cargo",
        "build",
        "--manifest-path",
        str(FIXTURE_MANIFEST),
        "--target-dir",
        str(target_dir),
    ]
    if release:
        cargo_args.append("--release")
    # Prefer VsDevCmd so link.exe is available on bare PowerShell sessions.
    vs = _vsdev_bat()
    log_path = target_dir / "build_fixture.log"
    target_dir.mkdir(parents=True, exist_ok=True)
    if vs is not None and os.name == "nt":
        # Write a temp .cmd to avoid nested-quote breakage under cmd /c.
        bat_path = target_dir / "build_fixture.cmd"
        bat_lines = [
            "@echo off",
            f'call "{vs}" -arch=amd64 -host_arch=amd64 -no_logo',
            "if errorlevel 1 exit /b 1",
            " ".join(f'"{a}"' for a in cargo_args),
            "exit /b %ERRORLEVEL%",
            "",
        ]
        bat_path.write_text("\r\n".join(bat_lines), encoding="ascii")
        print("building fixture (VsDevCmd bat):", bat_path, flush=True)
        with open(log_path, "w", encoding="utf-8", errors="replace") as logf:
            r = subprocess.run(
                ["cmd", "/c", str(bat_path)],
                cwd=str(REPO),
                stdout=logf,
                stderr=subprocess.STDOUT,
            )
    else:
        print("building fixture:", " ".join(cargo_args), flush=True)
        with open(log_path, "w", encoding="utf-8", errors="replace") as logf:
            r = subprocess.run(
                cargo_args, cwd=str(REPO), stdout=logf, stderr=subprocess.STDOUT
            )
    if r.returncode != 0:
        try:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        except OSError:
            tail = "(no log)"
        print(tail, file=sys.stderr)
        raise SystemExit(f"cargo build fixture failed exit={r.returncode}")
    profile = "release" if release else "debug"
    exe = target_dir / profile / "marker_exit.exe"
    if not exe.is_file():
        # non-windows
        alt = target_dir / profile / "marker_exit"
        if alt.is_file():
            return alt
        raise SystemExit(f"fixture binary not found after build: {exe}")
    print(str(exe), flush=True)
    return exe


def run_probe(
    candidate: Path,
    *,
    mode: str | None,
    max_wall_ms: int,
    max_output_bytes: int,
    expect_exit: int,
    require_marker: bool,
    work_dir: Path | None,
) -> dict[str, Any]:
    candidate = candidate.resolve()
    if not candidate.is_file():
        raise SystemExit(f"candidate not found: {candidate}")

    digest, size = sha256_file(candidate)
    scratch = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="mida_beh_"))
    scratch.mkdir(parents=True, exist_ok=True)
    marker_path = scratch / "marker.txt"

    env = os.environ.copy()
    env["MIDA_BEH_MARKER_PATH"] = str(marker_path)
    if mode:
        env["MIDA_BEH_MODE"] = mode

    cmd = [str(candidate)]
    if mode:
        cmd.append(mode)

    t0 = time.perf_counter()
    status = "error"
    exit_code: int | None = None
    error_class: str | None = None
    markers_found: list[str] = []
    stdout_tail = ""
    stderr_tail = ""

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(scratch),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            out_b, err_b = proc.communicate(timeout=max_wall_ms / 1000.0)
            exit_code = proc.returncode
            status = "pass"  # process completed; composition decides Pass/Fail
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                out_b, err_b = proc.communicate(timeout=2.0)
            except Exception:
                out_b, err_b = b"", b""
            status = "timeout"
            error_class = "wall_clock_timeout"
            exit_code = None
        if out_b:
            stdout_tail = out_b[:max_output_bytes].decode("utf-8", errors="replace")
        if err_b:
            stderr_tail = err_b[:max_output_bytes].decode("utf-8", errors="replace")
    except OSError as e:
        status = "error"
        error_class = f"os_error:{e.__class__.__name__}"
        out_b, err_b = b"", b""

    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    if marker_path.is_file():
        try:
            text = marker_path.read_text(encoding="utf-8", errors="replace")
            if MARKER_NEEDLE in text.replace("\r\n", "\n"):
                markers_found.append(MARKER_NEEDLE)
        except OSError:
            pass

    # Refine probe.result.status for fail vs pass at observation layer
    result_status = status
    if status == "pass":
        ok_exit = exit_code == expect_exit
        ok_marker = (MARKER_NEEDLE in markers_found) if require_marker else True
        if not ok_exit or not ok_marker:
            result_status = "fail"

    if result_status == "pass" and require_marker and MARKER_NEEDLE in markers_found:
        verdict = "Pass"
    elif result_status in ("timeout", "error"):
        verdict = "Inconclusive"
    else:
        verdict = "Fail"

    evidence: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "candidate": {
            "sha256": digest,
            "size_bytes": size,
            "role": "candidate",
        },
        "reference": {
            "kind": "synthetic_pair" if mode else "none",
            "sha256": None,
            "notes": f"mode={mode}" if mode else None,
        },
        "probe": {
            "id": PROBE_ID,
            "policy": {
                "network": "deny",
                "max_wall_ms": max_wall_ms,
                "max_output_bytes": max_output_bytes,
            },
            "result": {
                "status": result_status,
                "exit_code": exit_code,
                "markers_found": markers_found,
                "error_class": error_class,
            },
        },
        "verdict": verdict,
        "residual_risks": list(RESIDUAL_RISKS),
        "producer": {
            "name": PRODUCER_NAME,
            "version": PRODUCER_VERSION,
        },
    }
    # Non-compared debug (not part of schema; strip before schema validate)
    meta = {
        "elapsed_ms": elapsed_ms,
        "scratch": str(scratch),
        "stdout_tail": stdout_tail[:512],
        "stderr_tail": stderr_tail[:512],
        "candidate_path": str(candidate),
        "mode": mode,
        "expect_exit": expect_exit,
        "require_marker": require_marker,
    }
    return {"evidence": evidence, "meta": meta}


def validate_evidence_shape(evidence: dict[str, Any]) -> list[str]:
    """Lightweight shape check (no jsonschema dependency required)."""
    errs: list[str] = []
    if evidence.get("schema_version") != SCHEMA_VERSION:
        errs.append("schema_version")
    cand = evidence.get("candidate") or {}
    if not isinstance(cand.get("sha256"), str) or len(cand["sha256"]) != 64:
        errs.append("candidate.sha256")
    if not isinstance(cand.get("size_bytes"), int):
        errs.append("candidate.size_bytes")
    if evidence.get("verdict") not in ("Pass", "Fail", "Inconclusive"):
        errs.append("verdict")
    probe = evidence.get("probe") or {}
    pol = probe.get("policy") or {}
    if pol.get("network") != "deny":
        errs.append("probe.policy.network")
    res = probe.get("result") or {}
    if res.get("status") not in ("pass", "fail", "error", "timeout"):
        errs.append("probe.result.status")
    if "producer" not in evidence:
        errs.append("producer")
    if not isinstance(evidence.get("residual_risks"), list):
        errs.append("residual_risks")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description="B-A1 behavioral probe (not VNEXT-BEH gate)")
    ap.add_argument("--candidate", type=Path, help="PE to probe")
    ap.add_argument(
        "--mode",
        choices=["pass", "fail_exit", "no_marker", "hang"],
        default=None,
        help="Synthetic marker_exit mode (passed as argv + env)",
    )
    ap.add_argument("--max-wall-ms", type=int, default=5000)
    ap.add_argument("--max-output-bytes", type=int, default=65536)
    ap.add_argument(
        "--expect-exit",
        type=int,
        default=0,
        help="Expected process exit code for Pass composition",
    )
    ap.add_argument(
        "--require-marker",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Require MIDA_BEH_MARKER=1 for Pass (default true)",
    )
    ap.add_argument("--out", type=Path, help="Write evidence JSON path")
    ap.add_argument("--work-dir", type=Path, default=None)
    ap.add_argument(
        "--build-fixture",
        action="store_true",
        help="Build lab/behavior/synthetic/marker_exit and print path",
    )
    ap.add_argument(
        "--use-fixture",
        action="store_true",
        help="Use built marker_exit as --candidate (build if missing)",
    )
    ap.add_argument(
        "--expect-verdict",
        choices=["Pass", "Fail", "Inconclusive"],
        default=None,
        help="Exit 1 if evidence.verdict mismatches",
    )
    args = ap.parse_args()

    if args.build_fixture:
        exe = build_fixture(release=True)
        print(exe)
        return 0

    candidate = args.candidate
    if args.use_fixture:
        exe = find_fixture_exe()
        if exe is None:
            exe = build_fixture(release=True)
        candidate = exe

    if candidate is None:
        ap.error("need --candidate or --use-fixture")

    # Mode-specific defaults for synthetic fixture expectations
    expect_exit = args.expect_exit
    require_marker = args.require_marker
    if args.mode == "fail_exit" and args.expect_exit == 0 and args.expect_verdict == "Fail":
        # probing "is this a Pass candidate?" → Fail
        expect_exit = 0
        require_marker = True
    if args.mode == "no_marker":
        require_marker = True
        expect_exit = 0

    packed = run_probe(
        candidate,
        mode=args.mode,
        max_wall_ms=args.max_wall_ms,
        max_output_bytes=args.max_output_bytes,
        expect_exit=expect_exit,
        require_marker=require_marker,
        work_dir=args.work_dir,
    )
    evidence = packed["evidence"]
    shape_errs = validate_evidence_shape(evidence)
    if shape_errs:
        print("SHAPE_FAIL", shape_errs, file=sys.stderr)
        return 1

    out = args.out
    if out is None:
        out_dir = REPO / "lab" / "behavior" / "evidence"
        out_dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        mode_part = args.mode or "run"
        out = out_dir / f"evidence_{stamp}_{mode_part}.json"

    out.parent.mkdir(parents=True, exist_ok=True)
    # Stable key order via explicit dump
    text = json.dumps(evidence, indent=2, ensure_ascii=False) + "\n"
    out.write_text(text, encoding="utf-8")

    print(
        f"verdict={evidence['verdict']} status={evidence['probe']['result']['status']} "
        f"exit={evidence['probe']['result']['exit_code']} "
        f"markers={evidence['probe']['result']['markers_found']} out={out}",
        flush=True,
    )

    if args.expect_verdict and evidence["verdict"] != args.expect_verdict:
        print(
            f"EXPECT_FAIL want={args.expect_verdict} got={evidence['verdict']}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
