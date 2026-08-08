#!/usr/bin/env python3
"""Binary-safe live-route subprocess controller for GTO.

Fixes the Route J R1 root cause: ``subprocess.run(..., text=True)`` with no
explicit encoding used Windows' default ``cp936`` (GBK) to decode the Rust CLI's
output, and a non-decodable byte killed the internal ``_readerthread`` (losing
stdout/stderr). This controller never decodes child output during execution; it
writes stdout/stderr directly to ``.bin`` files via ``wb`` file handles handed
to ``Popen``, then generates display ``.txt`` copies afterward.

Authoritative evidence: ``child.stdout.bin`` / ``child.stderr.bin`` (raw bytes).
Display copies: ``child.stdout.txt`` / ``child.stderr.txt`` (decode best-effort;
never treated as authoritative).

Every run atomically writes ``controller_run.json`` with lifecycle metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

SCHEMA = "mida.live-route-controller/v1"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def atomic_write_bytes(dest: Path, data: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".ctrl-", suffix=".tmp", dir=str(dest.parent))
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


def decode_display(raw: bytes, label: str) -> Dict[str, Any]:
    """Best-effort UTF-8 decode for the display copy. Never authoritative."""
    try:
        text = raw.decode("utf-8")
        return {"decode_status": "utf-8", "replacement_count": 0, "display_text": text}
    except UnicodeDecodeError as exc:
        text = raw.decode("utf-8", errors="replace")
        return {
            "decode_status": "utf-8_with_replacement",
            "replacement_count": 1,
            "display_text": text,
            "decode_error": f"{exc}",
        }


def build_env(allowlist: List[str]) -> Dict[str, str]:
    """Build the child environment from an explicit allowlist only.

    Sensitive variables are never exported wholesale. Unknown allowlist keys
    that are absent from the parent env are skipped.
    """
    env = {}
    for key in allowlist:
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def run_child(
    *,
    argv: List[str],
    cwd: Optional[Path],
    evidence_dir: Path,
    env_allowlist: List[str],
    timeout_sec: float,
    timeout_kill_tree: bool = True,
    extra_env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run ``argv`` as a child, capturing stdout/stderr as raw bytes.

    Returns a structured record. Never raises on child failure (exit != 0);
    sets ``controller_error`` on controller-side faults.
    """
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    started = utc_now()
    t0 = time.monotonic()

    stdout_raw_path = evidence_dir / "child.stdout.bin"
    stderr_raw_path = evidence_dir / "child.stderr.bin"
    stdout_disp_path = evidence_dir / "child.stdout.txt"
    stderr_disp_path = evidence_dir / "child.stderr.txt"
    run_json_path = evidence_dir / "controller_run.json"

    env = build_env(env_allowlist)
    if extra_env:
        for k, v in extra_env.items():
            env[k] = v

    record: Dict[str, Any] = {
        "schema_version": SCHEMA,
        "controller_tool_sha256": sha256_file(Path(__file__)),
        "command_argv": argv,
        "command_line_display": subprocess.list2cmdline(argv),
        "cwd": str(cwd.resolve()) if cwd else None,
        "environment_allowlist": env_allowlist,
        "started_utc": started,
        "finished_utc": None,
        "elapsed_ms": None,
        "pid": None,
        "exit_code": None,
        "timed_out": False,
        "termination_action": None,
        "process_tree_cleanup_status": None,
        "stdout_raw_path": str(stdout_raw_path),
        "stdout_raw_sha256": None,
        "stdout_raw_size": None,
        "stderr_raw_path": str(stderr_raw_path),
        "stderr_raw_sha256": None,
        "stderr_raw_size": None,
        "stdout_decode_status": None,
        "stderr_decode_status": None,
        "spawn_error": None,
        "controller_error": None,
    }

    # Open raw .bin handles and hand them DIRECTLY to Popen (bytes mode, no
    # reader thread, no text decode). This is the fix for the Route J R1 crash.
    timed_out = False
    term_action = None
    cleanup_status = None
    returncode = None
    try:
        with open(stdout_raw_path, "wb") as fout, open(stderr_raw_path, "wb") as ferr:
            proc = subprocess.Popen(
                argv,
                stdout=fout,
                stderr=ferr,
                cwd=str(cwd) if cwd else None,
                env=env,
            )
            record["pid"] = proc.pid
            try:
                returncode = proc.wait(timeout=timeout_sec)
                timed_out = False
                term_action = None
                cleanup_status = "exited_naturally"
            except subprocess.TimeoutExpired:
                timed_out = True
                term_action = "terminate_tree"
                cleanup_status = "terminated"
                # Terminate the whole process tree.
                try:
                    _terminate_tree(proc.pid)
                    proc.wait(timeout=5)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                returncode = proc.returncode
    except FileNotFoundError as exc:
        record["spawn_error"] = f"executable not found: {exc}"
    except OSError as exc:
        record["spawn_error"] = f"OSError: {exc}"
    except Exception as exc:  # controller-side fault
        record["controller_error"] = f"{type(exc).__name__}: {exc}"

    t1 = time.monotonic()
    record["finished_utc"] = utc_now()
    record["elapsed_ms"] = int(round((t1 - t0) * 1000))
    record["exit_code"] = returncode
    record["timed_out"] = timed_out
    record["termination_action"] = term_action
    record["process_tree_cleanup_status"] = cleanup_status

    # Raw evidence + display copies (decode best-effort, never authoritative).
    if stdout_raw_path.exists():
        raw_out = stdout_raw_path.read_bytes()
        record["stdout_raw_sha256"] = sha256_bytes(raw_out)
        record["stdout_raw_size"] = len(raw_out)
        dec_out = decode_display(raw_out, "stdout")
        record["stdout_decode_status"] = dec_out["decode_status"]
        stdout_disp_path.write_text(dec_out["display_text"], encoding="utf-8")
    else:
        record["stdout_decode_status"] = "no_output_file"

    if stderr_raw_path.exists():
        raw_err = stderr_raw_path.read_bytes()
        record["stderr_raw_sha256"] = sha256_bytes(raw_err)
        record["stderr_raw_size"] = len(raw_err)
        dec_err = decode_display(raw_err, "stderr")
        record["stderr_decode_status"] = dec_err["decode_status"]
        stderr_disp_path.write_text(dec_err["display_text"], encoding="utf-8")
    else:
        record["stderr_decode_status"] = "no_output_file"

    # Atomic controller_run.json
    atomic_write_bytes(
        run_json_path,
        json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True).encode("utf-8") + b"\n",
    )
    return record


def _terminate_tree(pid: int) -> None:
    """Terminate a child and its descendants on Windows via taskkill /T."""
    import subprocess as _sp

    try:
        _sp.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            capture_output=True,
            timeout=15,
        )
    except Exception:
        pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="gto_live_route_controller",
        description=(
            "Binary-safe controller for a GTO live-route child process. "
            "Captures stdout/stderr as raw .bin evidence; never decodes during run."
        ),
    )
    parser.add_argument("--evidence-dir", required=True, help="output evidence directory")
    parser.add_argument("--cwd", default=None, help="working directory for the child")
    parser.add_argument("--timeout", type=float, default=120.0, help="timeout seconds")
    parser.add_argument("--env-allowlist", action="append", default=[],
                        help="environment variable names to propagate (repeatable)")
    parser.add_argument("--set-env", action="append", default=[],
                        help="KEY=VALUE extra env (repeatable)")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="child argv after --")
    args = parser.parse_args(argv)

    extra_env = {}
    for kv in args.set_env:
        if "=" in kv:
            k, v = kv.split("=", 1)
            extra_env[k] = v

    cwd = Path(args.cwd) if args.cwd else None
    record = run_child(
        argv=args.command,
        cwd=cwd,
        evidence_dir=Path(args.evidence_dir),
        env_allowlist=args.env_allowlist,
        timeout_sec=args.timeout,
        extra_env=extra_env,
    )
    print(json.dumps({"exit_code": record["exit_code"],
                      "controller_error": record["controller_error"],
                      "timed_out": record["timed_out"]}))
    # Return child exit code if available (0..255), else a controller error code.
    ec = record["exit_code"]
    if ec is None:
        return 2 if record.get("controller_error") else 3
    return ec & 0xFF


if __name__ == "__main__":
    sys.exit(main())
