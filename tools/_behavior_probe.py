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
PRODUCER_VERSION = "0.1.1-m1"
MARKER_NEEDLE = "MIDA_BEH_MARKER=1"
PROBE_ID_MARKER = "exit_code_marker_v0"
PROBE_ID_LOAD = "load_no_crash_v0"

# Job-object network isolation is deferred; residual risk is always listed.
RESIDUAL_RISKS_MARKER = [
    "network_deny_is_policy_not_kernel_filter",
    "no_api_trace_scoring",
    "synthetic_only_ba1",
]
RESIDUAL_RISKS_LOAD = [
    "network_deny_is_policy_not_kernel_filter",
    "no_api_trace_scoring",
    "load_survive_is_not_full_product_equivalence",
    "gui_apps_may_survive_without_proving_business_logic",
    "timeout_survive_treated_as_Pass_for_load_no_crash_v0",
    "non_nt_nonzero_exit_treated_as_Pass_for_load_no_crash_v0",
    "cwd_is_candidate_parent_for_load_probe",
    "load_no_crash_retries_on_nt_exception",
    "load_no_crash_runs_isolated_copy_per_attempt",
    "load_no_crash_uses_plain_createflags_by_default",
    "origin_like_gui_may_av_intermittently_on_bad_heap_paths",
    "load_pass_rate_is_quality_metric_not_r0b_accepted",
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


def _is_nt_exception_exit(code: int | None) -> bool:
    """Win32 exception-style exits (0xC0000000..) after cast to signed int32."""
    if code is None:
        return False
    u = code & 0xFFFFFFFF
    return u >= 0xC0000000


def _terminate_proc(proc: subprocess.Popen[Any]) -> None:
    """Best-effort kill of launched process (and Windows child tree via taskkill)."""
    try:
        if proc.poll() is not None:
            return
    except Exception:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except Exception:
            pass
    try:
        proc.kill()
    except Exception:
        pass
    try:
        proc.wait(timeout=3.0)
    except Exception:
        pass


def _kill_stale_by_stem(stem: str) -> None:
    """Kill leftover probe children by image stem (Windows). Best-effort."""
    if os.name != "nt" or not stem:
        return
    # taskkill image name must include .exe on Windows.
    names = {f"{stem}.exe", stem}
    for name in names:
        try:
            subprocess.run(
                ["taskkill", "/IM", name, "/T", "/F"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except Exception:
            pass


def _load_createflags() -> int:
    """Windows creation flags for load_no_crash launches.

    Default is plain (0): Origin/GTO flaky AVs were *worse* under
    CREATE_NO_WINDOW in A/B sampling. Override with MIDA_BEH_CREATEFLAGS
    (hex or decimal int), e.g. 0x08000200 for NEW_PROCESS_GROUP|CREATE_NO_WINDOW.
    """
    raw = (os.environ.get("MIDA_BEH_CREATEFLAGS") or "").strip()
    if not raw:
        return 0
    try:
        return int(raw, 0)
    except ValueError:
        return 0


def _run_one_process(
    candidate: Path,
    *,
    mode: str | None,
    max_wall_ms: int,
    max_output_bytes: int,
    probe_kind: str,
    env: dict[str, str],
    run_cwd: str,
) -> tuple[str, int | None, str | None, bool, str, str]:
    """Single launch. Returns status, exit_code, error_class, survived_timeout, stdout, stderr."""
    cmd = [str(candidate)]
    if mode and probe_kind == "marker":
        cmd.append(mode)

    status = "error"
    exit_code: int | None = None
    error_class: str | None = None
    stdout_tail = ""
    stderr_tail = ""
    survived_timeout = False
    creationflags = 0
    if os.name == "nt" and probe_kind == "load_no_crash":
        creationflags = _load_createflags()

    proc: subprocess.Popen[Any] | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=run_cwd,
            env=env,
            stdout=subprocess.DEVNULL if probe_kind == "load_no_crash" else subprocess.PIPE,
            stderr=subprocess.DEVNULL if probe_kind == "load_no_crash" else subprocess.PIPE,
            creationflags=creationflags,
        )
        try:
            if probe_kind == "load_no_crash":
                proc.wait(timeout=max_wall_ms / 1000.0)
                out_b, err_b = b"", b""
            else:
                out_b, err_b = proc.communicate(timeout=max_wall_ms / 1000.0)
            exit_code = proc.returncode
            status = "pass"
        except subprocess.TimeoutExpired:
            survived_timeout = True
            _terminate_proc(proc)
            out_b, err_b = b"", b""
            if probe_kind != "load_no_crash":
                try:
                    out_b, err_b = proc.communicate(timeout=1.0)
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
        if proc is not None:
            _terminate_proc(proc)
    return status, exit_code, error_class, survived_timeout, stdout_tail, stderr_tail


def _attempt_is_load_pass(
    status: str, exit_code: int | None, survived_timeout: bool
) -> bool:
    """Single-launch survival for quality accounting (matches Pass composition)."""
    if status == "error":
        return False
    if _is_nt_exception_exit(exit_code):
        return False
    if survived_timeout or status == "timeout":
        return True
    # exit 0 or non-NT nonzero: loaded without AV
    return status in ("pass", "timeout") or exit_code is not None


def run_probe(
    candidate: Path,
    *,
    mode: str | None,
    max_wall_ms: int,
    max_output_bytes: int,
    expect_exit: int,
    require_marker: bool,
    work_dir: Path | None,
    probe_kind: str = "marker",
    attempts: int = 1,
    rate_samples: int = 0,
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

    # load_no_crash: each attempt runs an isolated copy under scratch so single-instance
    # mutex / leftover file locks from prior launches do not poison the gate.
    # marker synthetic fixtures stay in scratch so marker file stays isolated.
    if probe_kind == "load_no_crash":
        attempts = max(1, attempts)
        rate_samples = max(0, int(rate_samples))
    else:
        attempts = 1
        rate_samples = 0

    t0 = time.perf_counter()
    status = "error"
    exit_code: int | None = None
    error_class: str | None = None
    markers_found: list[str] = []
    stdout_tail = ""
    stderr_tail = ""
    survived_timeout = False
    attempt_notes: list[str] = []
    # Gate path: early-exit on first Pass (attempts). Quality path: fixed samples.
    measure_rate = rate_samples > 0
    loop_n = rate_samples if measure_rate else attempts
    pass_count = 0
    fail_count = 0
    error_count = 0

    for attempt in range(1, loop_n + 1):
        if probe_kind == "load_no_crash":
            attempt_dir = scratch / f"run_{attempt}"
            attempt_dir.mkdir(parents=True, exist_ok=True)
            # Keep original basename: some GUI apps key single-instance / paths on name.
            run_exe = attempt_dir / candidate.name
            try:
                shutil.copy2(candidate, run_exe)
            except OSError as e:
                status = "error"
                error_class = f"copy_error:{e.__class__.__name__}"
                attempt_notes.append(f"a{attempt}:copy_fail:{e}")
                error_count += 1
                if measure_rate:
                    time.sleep(0.4)
                    continue
                if attempt < attempts:
                    time.sleep(0.6 * attempt + 0.4)
                    continue
                break
            launch_path = run_exe
            run_cwd = str(attempt_dir)
        else:
            launch_path = candidate
            run_cwd = str(scratch)

        status, exit_code, error_class, survived_timeout, stdout_tail, stderr_tail = (
            _run_one_process(
                launch_path,
                mode=mode,
                max_wall_ms=max_wall_ms,
                max_output_bytes=max_output_bytes,
                probe_kind=probe_kind,
                env=env,
                run_cwd=run_cwd,
            )
        )
        # Early stop when this attempt is already a load survival candidate.
        if probe_kind == "load_no_crash":
            nt_fail = _is_nt_exception_exit(exit_code)
            ok = _attempt_is_load_pass(status, exit_code, survived_timeout)
            if ok:
                pass_count += 1
            elif status == "error":
                error_count += 1
            else:
                fail_count += 1
            attempt_notes.append(
                f"a{attempt}:status={status}:exit={exit_code}:survived={survived_timeout}:ok={ok}"
            )
            if measure_rate:
                # Fixed sample budget for pass-rate; always backoff between launches.
                _kill_stale_by_stem(Path(launch_path).stem)
                _kill_stale_by_stem(candidate.stem)
                if attempt < loop_n:
                    time.sleep(0.5)
                continue
            # Gate path: accept first non-error non-NT attempt.
            if status != "error" and not nt_fail:
                break
            # Clean stragglers before retry (mutex / zombie GUI).
            _kill_stale_by_stem(Path(launch_path).stem)
            _kill_stale_by_stem(candidate.stem)
            if attempt < attempts and (nt_fail or status == "error"):
                # Backoff: Origin pure shows ~40-80% survival; need space between AVs.
                time.sleep(0.6 * attempt + 0.5)
                continue
            break
        break

    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    samples_run = pass_count + fail_count + error_count if probe_kind == "load_no_crash" else 0

    if marker_path.is_file():
        try:
            text = marker_path.read_text(encoding="utf-8", errors="replace")
            if MARKER_NEEDLE in text.replace("\r\n", "\n"):
                markers_found.append(MARKER_NEEDLE)
        except OSError:
            pass

    if probe_kind == "load_no_crash":
        probe_id = PROBE_ID_LOAD
        residuals = list(RESIDUAL_RISKS_LOAD)
        if measure_rate:
            # Quality metric path: verdict from pass_count (not first-success gate).
            if samples_run == 0:
                result_status = "error"
                verdict = "Inconclusive"
            elif pass_count == 0:
                result_status = "fail"
                error_class = error_class or "load_pass_rate_zero"
                verdict = "Fail"
            else:
                # Any survival in the sample set → Pass for gate compose; rate is separate.
                result_status = "pass"
                error_class = f"pass_rate:{pass_count}/{samples_run}"
                verdict = "Pass"
        else:
            # Survive window without NT exception => Pass.
            # Non-zero non-NT exits (missing args / single-instance / GUI early return)
            # still prove the image loaded and ran user code without AV — Pass with residual.
            if status == "error":
                result_status = "error"
                verdict = "Inconclusive"
            elif _is_nt_exception_exit(exit_code):
                result_status = "fail"
                error_class = error_class or f"nt_exception_exit:{exit_code & 0xFFFFFFFF:#x}"
                verdict = "Fail"
            elif survived_timeout or status == "timeout":
                result_status = "pass"
                error_class = "survived_wall_clock_then_killed"
                verdict = "Pass"
            elif exit_code == 0:
                result_status = "pass"
                verdict = "Pass"
            else:
                result_status = "pass"
                error_class = error_class or f"nonzero_non_nt_exit:{exit_code & 0xFFFFFFFF:#x}"
                verdict = "Pass"
    else:
        probe_id = PROBE_ID_MARKER
        residuals = list(RESIDUAL_RISKS_MARKER)
        result_status = status
        if status == "pass":
            ok_exit = exit_code == expect_exit
            ok_marker = (MARKER_NEEDLE in markers_found) if require_marker else True
            if not ok_exit or not ok_marker:
                result_status = "fail"
        if result_status == "pass" and require_marker and MARKER_NEEDLE in markers_found:
            verdict = "Pass"
        elif result_status == "pass" and not require_marker and exit_code == expect_exit:
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
            "notes": f"mode={mode}" if mode else f"probe_kind={probe_kind}",
        },
        "probe": {
            "id": probe_id,
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
        "residual_risks": residuals,
        "producer": {
            "name": PRODUCER_NAME,
            "version": PRODUCER_VERSION,
        },
    }
    if probe_kind == "load_no_crash" and samples_run > 0:
        # Quality metric (does not change R0B Accepted rules).
        evidence["load_quality"] = {
            "samples": samples_run,
            "pass": pass_count,
            "fail": fail_count,
            "error": error_count,
            "pass_rate": round(pass_count / samples_run, 4) if samples_run else 0.0,
            "mode": "fixed_samples" if measure_rate else "gate_early_exit",
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
        "attempts": attempts,
        "rate_samples": rate_samples,
        "attempt_notes": attempt_notes,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "error_count": error_count,
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
    ap.add_argument(
        "--probe-kind",
        choices=["marker", "load_no_crash"],
        default="marker",
        help="marker=exit_code_marker_v0 (default); load_no_crash=vault PE load survival",
    )
    ap.add_argument(
        "--attempts",
        type=int,
        default=12,
        help="load_no_crash only: retry launches on NT exception (default 12)",
    )
    ap.add_argument(
        "--rate-samples",
        type=int,
        default=0,
        help=(
            "load_no_crash only: run N fixed serial samples for pass-rate quality "
            "(no early exit). When >0, overrides gate early-exit attempts path."
        ),
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

    if args.probe_kind == "load_no_crash":
        require_marker = False
    packed = run_probe(
        candidate,
        mode=args.mode,
        max_wall_ms=args.max_wall_ms,
        max_output_bytes=args.max_output_bytes,
        expect_exit=expect_exit,
        require_marker=require_marker,
        work_dir=args.work_dir,
        probe_kind=args.probe_kind,
        attempts=args.attempts if args.probe_kind == "load_no_crash" else 1,
        rate_samples=args.rate_samples if args.probe_kind == "load_no_crash" else 0,
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

    # Optional companion for rate runs (full meta including attempt_notes).
    if packed["meta"].get("rate_samples"):
        meta_path = out.with_suffix(".meta.json")
        meta_path.write_text(
            json.dumps(packed["meta"], indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    lq = evidence.get("load_quality") or {}
    rate_s = ""
    if lq:
        rate_s = (
            f" pass_rate={lq.get('pass')}/{lq.get('samples')}"
            f"({lq.get('pass_rate')})"
        )
    print(
        f"verdict={evidence['verdict']} status={evidence['probe']['result']['status']} "
        f"exit={evidence['probe']['result']['exit_code']} "
        f"markers={evidence['probe']['result']['markers_found']}{rate_s} out={out}",
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
