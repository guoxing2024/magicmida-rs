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
PRODUCER_VERSION = "0.3.0-p1"
MARKER_NEEDLE = "MIDA_BEH_MARKER=1"
PROBE_ID_MARKER = "exit_code_marker_v0"
PROBE_ID_LOAD = "load_no_crash_v0"
PROBE_ID_WINDOW = "gui_window_class_v0"
PROBE_ID_EXPORTS = "pe_export_names_v0"
PROBE_ID_EXIT_EXACT = "exit_code_exact_v0"

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
RESIDUAL_RISKS_WINDOW = [
    "network_deny_is_policy_not_kernel_filter",
    "window_class_is_not_full_product_logic",
    "window_class_does_not_prove_license_or_business_path",
    "gui_title_text_is_not_scored_unless_require_title",
    "ime_helper_windows_ignored_for_class_match",
    "window_probe_uses_plain_createflags_by_default",
    "window_probe_runs_isolated_copy_per_attempt",
]
RESIDUAL_RISKS_EXPORTS = [
    "export_names_are_static_surface_not_runtime_behavior",
    "export_names_do_not_prove_script_engine_runs",
    "export_parse_is_pe_only_no_dll_load",
    "missing_exports_fail_closed",
]
RESIDUAL_RISKS_EXIT_EXACT = [
    "network_deny_is_policy_not_kernel_filter",
    "exit_code_exact_is_not_full_product_logic",
    "exit_code_may_encode_missing_args_or_license_state",
    "timeout_without_exit_is_Fail_for_exit_code_exact",
    "exit_code_exact_runs_isolated_copy_per_attempt",
    "exit_code_exact_uses_plain_createflags_by_default",
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
    quiet_launch = probe_kind in ("load_no_crash", "exit_code")
    if os.name == "nt" and quiet_launch:
        creationflags = _load_createflags()

    proc: subprocess.Popen[Any] | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=run_cwd,
            env=env,
            stdout=subprocess.DEVNULL if quiet_launch else subprocess.PIPE,
            stderr=subprocess.DEVNULL if quiet_launch else subprocess.PIPE,
            creationflags=creationflags,
        )
        try:
            if quiet_launch:
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
            if not quiet_launch:
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


def pe_export_names(path: Path) -> list[str]:
    """Parse PE export name table (static; no image load). Empty if none/invalid."""
    import struct

    data = path.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        return []
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return []
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    if opt + 2 > len(data):
        return []
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        dd = opt + 112
    elif magic == 0x10B:
        dd = opt + 96
    else:
        return []
    if dd + 8 > len(data):
        return []
    exp_rva, _exp_sz = struct.unpack_from("<II", data, dd)
    if exp_rva == 0:
        return []
    sec_off = opt + opt_size
    sections: list[tuple[int, int, int, int]] = []
    for i in range(nsec):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
        sections.append((va, vsz, raw, rsz))

    def rva_to_off(rva: int) -> int | None:
        for va, vsz, raw, rsz in sections:
            span = max(vsz, rsz)
            if va <= rva < va + span and raw:
                return raw + (rva - va)
        return None

    exp_off = rva_to_off(exp_rva)
    if exp_off is None or exp_off + 40 > len(data):
        return []
    n_names = struct.unpack_from("<I", data, exp_off + 24)[0]
    names_rva = struct.unpack_from("<I", data, exp_off + 32)[0]
    names_off = rva_to_off(names_rva)
    if names_off is None or n_names == 0 or n_names > 10_000:
        return []
    out: list[str] = []
    for i in range(n_names):
        slot = names_off + i * 4
        if slot + 4 > len(data):
            break
        nrva = struct.unpack_from("<I", data, slot)[0]
        noff = rva_to_off(nrva)
        if noff is None or noff >= len(data):
            continue
        end = data.find(b"\0", noff, min(noff + 256, len(data)))
        if end < 0:
            continue
        try:
            name = data[noff:end].decode("ascii")
        except UnicodeDecodeError:
            continue
        if name:
            out.append(name)
    return out


def _enum_windows_for_pid(pid: int) -> list[tuple[str, str, bool]]:
    """Return (class_name, title, visible) for top-level windows owned by pid."""
    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    GetClassNameW = user32.GetClassNameW
    GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    GetClassNameW.restype = ctypes.c_int
    GetWindowTextW = user32.GetWindowTextW
    GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    GetWindowThreadProcessId = user32.GetWindowThreadProcessId
    GetWindowThreadProcessId.argtypes = [
        wintypes.HWND,
        ctypes.POINTER(wintypes.DWORD),
    ]
    GetWindowThreadProcessId.restype = wintypes.DWORD
    IsWindowVisible = user32.IsWindowVisible
    EnumWindows = user32.EnumWindows

    found: list[tuple[str, str, bool]] = []

    @WNDENUMPROC
    def _cb(hwnd: int, _lparam: int) -> bool:
        p = wintypes.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        if int(p.value) != int(pid):
            return True
        cn = ctypes.create_unicode_buffer(256)
        GetClassNameW(hwnd, cn, 256)
        tt = ctypes.create_unicode_buffer(512)
        GetWindowTextW(hwnd, tt, 512)
        found.append((cn.value, tt.value, bool(IsWindowVisible(hwnd))))
        return True

    EnumWindows(_cb, 0)
    return found


def _run_window_class_probe(
    launch_path: Path,
    *,
    max_wall_ms: int,
    expect_classes: list[str],
    require_title_substr: str | None,
    env: dict[str, str],
    run_cwd: str,
) -> tuple[str, int | None, str | None, list[str], list[str]]:
    """Launch PE; Pass when an expected window class appears (no NT AV).

    Returns status, exit_code, error_class, markers_found, classes_seen.
    """
    expect_set = {c for c in expect_classes if c}
    if not expect_set:
        return "error", None, "no_expect_window_class", [], []

    creationflags = _load_createflags() if os.name == "nt" else 0
    status = "error"
    exit_code: int | None = None
    error_class: str | None = None
    markers: list[str] = []
    classes_seen: list[str] = []
    proc: subprocess.Popen[Any] | None = None
    try:
        proc = subprocess.Popen(
            [str(launch_path)],
            cwd=run_cwd,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
        deadline = time.perf_counter() + max(0.2, max_wall_ms / 1000.0)
        matched_class: str | None = None
        matched_title: str | None = None
        while time.perf_counter() < deadline:
            for cn, title, _vis in _enum_windows_for_pid(proc.pid):
                if cn and cn not in classes_seen:
                    classes_seen.append(cn)
                if cn in expect_set:
                    if require_title_substr and require_title_substr not in title:
                        continue
                    matched_class = cn
                    matched_title = title
                    break
            if matched_class is not None:
                break
            if proc.poll() is not None:
                break
            time.sleep(0.12)

        exit_code = proc.poll()
        if matched_class is not None:
            markers.append(f"window_class:{matched_class}")
            if matched_title:
                markers.append(f"window_title_seen:{matched_title[:80]}")
            status = "pass"
            error_class = "window_class_matched"
        elif exit_code is not None and _is_nt_exception_exit(exit_code):
            status = "fail"
            error_class = f"nt_exception_exit:{exit_code & 0xFFFFFFFF:#x}"
        elif exit_code is not None:
            status = "fail"
            error_class = "process_exited_without_expected_window"
        else:
            status = "fail"
            error_class = "window_class_not_seen_within_wall"
    except OSError as e:
        status = "error"
        error_class = f"os_error:{e.__class__.__name__}"
    finally:
        if proc is not None:
            _terminate_proc(proc)
    return status, exit_code, error_class, markers, classes_seen


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
    expect_window_classes: list[str] | None = None,
    require_title_substr: str | None = None,
    require_exports: list[str] | None = None,
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

    # Process-launch probes: isolated copy per attempt (mutex / file locks).
    # marker synthetic fixtures stay in scratch so marker file stays isolated.
    process_probe = probe_kind in ("load_no_crash", "window_class", "exit_code")
    if process_probe:
        attempts = max(1, attempts)
        rate_samples = max(0, int(rate_samples)) if probe_kind == "load_no_crash" else 0
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
    classes_seen: list[str] = []
    exports_found: list[str] = []
    # Gate path: early-exit on first Pass (attempts). Quality path: fixed samples.
    measure_rate = rate_samples > 0
    loop_n = rate_samples if measure_rate else attempts
    pass_count = 0
    fail_count = 0
    error_count = 0

    # --- static export_names probe (no process launch) ---
    if probe_kind == "export_names":
        req = [x for x in (require_exports or []) if x]
        if not req:
            status = "error"
            error_class = "no_require_exports"
            result_status = "error"
            verdict = "Inconclusive"
            probe_id = PROBE_ID_EXPORTS
            residuals = list(RESIDUAL_RISKS_EXPORTS)
        else:
            exports_found = pe_export_names(candidate)
            # Case-sensitive PE names; also accept case-insensitive hit for AHK surface.
            lower_map = {n.lower(): n for n in exports_found}
            missing: list[str] = []
            matched: list[str] = []
            for want in req:
                if want in exports_found:
                    matched.append(want)
                elif want.lower() in lower_map:
                    matched.append(lower_map[want.lower()])
                else:
                    missing.append(want)
            markers_found = [f"export:{m}" for m in matched]
            if missing:
                status = "fail"
                result_status = "fail"
                error_class = "missing_exports:" + ",".join(missing)
                verdict = "Fail"
            else:
                status = "pass"
                result_status = "pass"
                error_class = f"exports_matched:{len(matched)}"
                verdict = "Pass"
            probe_id = PROBE_ID_EXPORTS
            residuals = list(RESIDUAL_RISKS_EXPORTS)
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        evidence = {
            "schema_version": SCHEMA_VERSION,
            "candidate": {
                "sha256": digest,
                "size_bytes": size,
                "role": "candidate",
            },
            "reference": {
                "kind": "none",
                "sha256": None,
                "notes": f"probe_kind=export_names require={req}",
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
                    "exit_code": None,
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
            "export_quality": {
                "required": req,
                "matched": [m.replace("export:", "") for m in markers_found],
                "export_count": len(exports_found),
            },
        }
        meta = {
            "elapsed_ms": elapsed_ms,
            "scratch": str(scratch),
            "candidate_path": str(candidate),
            "probe_kind": probe_kind,
            "exports_found_sample": exports_found[:40],
        }
        return {"evidence": evidence, "meta": meta}

    for attempt in range(1, loop_n + 1):
        if process_probe:
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

        if probe_kind == "window_class":
            status, exit_code, error_class, win_markers, classes_seen = (
                _run_window_class_probe(
                    launch_path,
                    max_wall_ms=max_wall_ms,
                    expect_classes=list(expect_window_classes or []),
                    require_title_substr=require_title_substr,
                    env=env,
                    run_cwd=run_cwd,
                )
            )
            markers_found = list(win_markers)
            survived_timeout = False
            stdout_tail = ""
            stderr_tail = ""
            ok = status == "pass"
            if ok:
                pass_count += 1
            elif status == "error":
                error_count += 1
            else:
                fail_count += 1
            attempt_notes.append(
                f"a{attempt}:status={status}:exit={exit_code}:classes={classes_seen}:ok={ok}"
            )
            _kill_stale_by_stem(Path(launch_path).stem)
            _kill_stale_by_stem(candidate.stem)
            if ok:
                break
            if attempt < attempts:
                time.sleep(0.5 * attempt + 0.3)
                continue
            break

        if probe_kind == "exit_code":
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
            # Exact exit required; timeout / NT exception / wrong code = fail.
            if status == "error":
                ok = False
                error_count += 1
            elif survived_timeout or status == "timeout" or exit_code is None:
                status = "fail"
                error_class = error_class or "exit_code_timeout_no_exit"
                ok = False
                fail_count += 1
            elif _is_nt_exception_exit(exit_code):
                status = "fail"
                error_class = error_class or f"nt_exception_exit:{exit_code & 0xFFFFFFFF:#x}"
                ok = False
                fail_count += 1
            elif (exit_code & 0xFFFFFFFF) == (expect_exit & 0xFFFFFFFF):
                status = "pass"
                error_class = f"exit_code_matched:{exit_code & 0xFFFFFFFF:#x}"
                markers_found = [f"exit_code:{exit_code & 0xFFFFFFFF:#x}"]
                ok = True
                pass_count += 1
            else:
                status = "fail"
                error_class = (
                    f"exit_code_mismatch:got={exit_code & 0xFFFFFFFF:#x}"
                    f":expect={expect_exit & 0xFFFFFFFF:#x}"
                )
                ok = False
                fail_count += 1
            attempt_notes.append(
                f"a{attempt}:status={status}:exit={exit_code}:expect={expect_exit}:ok={ok}"
            )
            _kill_stale_by_stem(Path(launch_path).stem)
            _kill_stale_by_stem(candidate.stem)
            if ok:
                break
            if attempt < attempts:
                time.sleep(0.4 * attempt + 0.3)
                continue
            break

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
    samples_run = (
        pass_count + fail_count + error_count
        if probe_kind in ("load_no_crash", "window_class", "exit_code")
        else 0
    )

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
    elif probe_kind == "window_class":
        probe_id = PROBE_ID_WINDOW
        residuals = list(RESIDUAL_RISKS_WINDOW)
        if status == "pass":
            result_status = "pass"
            verdict = "Pass"
        elif status == "error":
            result_status = "error"
            verdict = "Inconclusive"
        else:
            result_status = "fail"
            verdict = "Fail"
    elif probe_kind == "exit_code":
        probe_id = PROBE_ID_EXIT_EXACT
        residuals = list(RESIDUAL_RISKS_EXIT_EXACT)
        if status == "pass":
            result_status = "pass"
            verdict = "Pass"
        elif status == "error":
            result_status = "error"
            verdict = "Inconclusive"
        else:
            result_status = "fail"
            verdict = "Fail"
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

    ref_notes = f"mode={mode}" if mode else f"probe_kind={probe_kind}"
    if probe_kind == "window_class":
        ref_notes = (
            f"probe_kind=window_class expect_classes="
            f"{','.join(expect_window_classes or [])}"
        )
        if require_title_substr:
            ref_notes += f" require_title={require_title_substr!r}"
    elif probe_kind == "exit_code":
        ref_notes = f"probe_kind=exit_code expect_exit={expect_exit & 0xFFFFFFFF:#x}"

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
            "notes": ref_notes,
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
    if probe_kind == "window_class":
        evidence["window_quality"] = {
            "expect_classes": list(expect_window_classes or []),
            "require_title_substr": require_title_substr,
            "classes_seen": classes_seen,
            "attempts": attempts,
            "pass_count": pass_count,
            "fail_count": fail_count,
        }
    if probe_kind == "exit_code":
        evidence["exit_quality"] = {
            "expect_exit": expect_exit & 0xFFFFFFFF,
            "got_exit": (exit_code & 0xFFFFFFFF) if exit_code is not None else None,
            "attempts": attempts,
            "pass_count": pass_count,
            "fail_count": fail_count,
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
        "classes_seen": classes_seen,
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
        choices=["marker", "load_no_crash", "window_class", "export_names", "exit_code"],
        default="marker",
        help=(
            "marker=exit_code_marker_v0 (default); load_no_crash=load survival; "
            "window_class=gui class oracle (W3); export_names=static PE exports (W3); "
            "exit_code=exact process exit (P1 pure-logic step)"
        ),
    )
    ap.add_argument(
        "--attempts",
        type=int,
        default=12,
        help="load_no_crash/window_class/exit_code: retry launches (default 12)",
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
    ap.add_argument(
        "--expect-window-class",
        action="append",
        default=[],
        help="window_class: expected Win32 class name (repeatable)",
    )
    ap.add_argument(
        "--require-title-substr",
        default=None,
        help="window_class: optional title substring (UTF-8/unicode)",
    )
    ap.add_argument(
        "--require-export",
        action="append",
        default=[],
        help="export_names: required export symbol (repeatable; case-insensitive fallback)",
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

    if args.probe_kind in ("load_no_crash", "window_class", "export_names", "exit_code"):
        require_marker = False
    if args.probe_kind == "window_class" and not args.expect_window_class:
        ap.error("window_class requires --expect-window-class")
    if args.probe_kind == "export_names" and not args.require_export:
        ap.error("export_names requires --require-export")
    if args.probe_kind == "exit_code" and args.expect_exit is None:
        # argparse always supplies int default 0; treat as required by forcing flag
        # presence via a sentinel is awkward — require explicit --expect-exit always OK.
        pass
    packed = run_probe(
        candidate,
        mode=args.mode,
        max_wall_ms=args.max_wall_ms,
        max_output_bytes=args.max_output_bytes,
        expect_exit=expect_exit,
        require_marker=require_marker,
        work_dir=args.work_dir,
        probe_kind=args.probe_kind,
        attempts=(
            args.attempts
            if args.probe_kind in ("load_no_crash", "window_class", "exit_code")
            else 1
        ),
        rate_samples=args.rate_samples if args.probe_kind == "load_no_crash" else 0,
        expect_window_classes=list(args.expect_window_class or []),
        require_title_substr=args.require_title_substr,
        require_exports=list(args.require_export or []),
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
