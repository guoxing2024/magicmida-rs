"""GTO-PRODUCT-RECOVERY Route A R1 orchestrator (2026-07-29).

Launches the external observer binary ``mida_gto_product_recovery_observer``
N times (default N=3) against a single canonical protected binary in the vault.
Each run writes a JSON sidecar under the run directory. After all N runs, the
aggregator ``_mtr_acq_route_a_aggregate.py`` is invoked.

Per docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md:
- This script is OBSERVATION-ONLY. It does NOT touch the target binary, does
  NOT install any hook, does NOT use DRx/VEH/in-process instrumentation.
- It is a READ-ONLY process launcher + log aggregator.
- It does NOT import ``tools/_r1b_transient_epoch_trap.py`` (forbidden per
  authorization).
- It does NOT set ``MIDA_GTO_BYPASS`` or ``MIDA_GTO_SEMANTIC_REPAIR``.
- It DOES set ``MIDA_GTO_NO_BYPASS=1`` (default deny-bypass) for the spawned
  protected process so the target runs without the ``sample_bypass`` patches.
- It performs N independent fresh-spawn runs (no shared observer state across
  runs).

CLI args:
    --target-path PATH    Canonical ``gto_protected.exe`` to spawn (default:
                          ``D:\\MidaVault\\lab\\evidence\\gto_launcher\\
                          r27_nobypass_round0_20260725\\gto_protected.exe``).
    --observer-bin PATH   Observer binary to run (default: ``target\\debug\\
                          mida_gto_product_recovery_observer.exe`` resolved
                          relative to repo root).
    --repo-root PATH      Magicmida-RS repo root (default: two levels up from
                          this script).
    --out-root PATH       Output root. The N run dirs and the aggregate live
                          under here (default:
                          ``D:\\MidaVault\\scratch\\
                          product_recovery_route_a_r1_n3_<ts>``).
    --n N                 Number of independent runs (default 3).
    --observation-window-ms U32  Default 30000 (30 s — short enough to keep
                                the vault footprint small, long enough to
                                catch the ``.boot`` first-commit window).
    --poll-period-ms U32  Default 15.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path


REPO_ROOT_DEFAULT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = Path(
    r"D:\MidaVault\lab\evidence\gto_launcher\r27_nobypass_round0_20260725"
    r"\gto_protected.exe"
)
DEFAULT_OBSERVER = REPO_ROOT_DEFAULT / "target" / "debug" / (
    "mida_gto_product_recovery_observer.exe"
)


def _now_iso() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_dir() -> str:
    return _dt.datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def _sha256_file(p: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_one(
    target: Path,
    observer_bin: Path,
    run_dir: Path,
    observation_window_ms: int,
    poll_period_ms: int,
) -> dict:
    """Launch the observer binary once. Returns a small record dict.

    The observer writes ``outcomes.json`` itself; we just capture stdout/stderr
    for diagnostics and the sidecar hash.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    # Default-deny: do NOT pass MIDA_GTO_BYPASS or MIDA_GTO_SEMANTIC_REPAIR.
    env.pop("MIDA_GTO_BYPASS", None)
    env.pop("MIDA_GTO_SEMANTIC_REPAIR", None)
    env["MIDA_GTO_NO_BYPASS"] = "1"

    cmd = [
        str(observer_bin),
        "--spawn", str(target),
        "--observation-window-ms", str(observation_window_ms),
        "--poll-period-ms", str(poll_period_ms),
        "--out-dir", str(run_dir),
    ]

    log_path = run_dir / "observer.stdout.log"
    started_at = _now_iso()
    started_wall = time.time()
    proc = subprocess.run(
        cmd, cwd=str(observer_bin.parent),
        env=env, capture_output=True, text=True,
    )
    ended_at = _now_iso()
    ended_wall = time.time()
    log_path.write_text(
        f"# cmd: {' '.join(cmd)}\n"
        f"# started_at: {started_at}\n"
        f"# ended_at: {ended_at}\n"
        f"# exit_code: {proc.returncode}\n"
        f"# stdout ({len(proc.stdout)} bytes):\n{proc.stdout}\n"
        f"# stderr ({len(proc.stderr)} bytes):\n{proc.stderr}\n",
        encoding="utf-8",
    )

    sidecar = run_dir / "outcomes.json"
    sidecar_sha = _sha256_file(sidecar) if sidecar.is_file() else None
    return {
        "run_dir": str(run_dir),
        "started_at": started_at,
        "ended_at": ended_at,
        "elapsed_sec": round(ended_wall - started_wall, 3),
        "exit_code": proc.returncode,
        "observer_stderr_tail": proc.stderr[-2000:] if proc.stderr else "",
        "sidecar_exists": sidecar.is_file(),
        "sidecar_path": str(sidecar),
        "sidecar_sha256": sidecar_sha,
        "env": {k: v for k, v in env.items() if k.startswith("MIDA_GTO_")},
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target-path", default=str(DEFAULT_TARGET))
    p.add_argument("--observer-bin", default=str(DEFAULT_OBSERVER))
    p.add_argument("--repo-root", default=str(REPO_ROOT_DEFAULT))
    p.add_argument("--out-root", default=None)
    p.add_argument("--n", type=int, default=3)
    p.add_argument("--observation-window-ms", type=int, default=30000)
    p.add_argument("--poll-period-ms", type=int, default=15)
    args = p.parse_args(argv)

    target = Path(args.target_path)
    observer_bin = Path(args.observer_bin)
    repo_root = Path(args.repo_root)

    if not target.is_file():
        print(f"FATAL: target not found: {target}", file=sys.stderr)
        return 2
    if not observer_bin.is_file():
        print(f"FATAL: observer binary not found: {observer_bin}", file=sys.stderr)
        return 2

    target_sha = _sha256_file(target)
    observer_sha = _sha256_file(observer_bin)

    out_root = (
        Path(args.out_root)
        if args.out_root
        else Path(rf"D:\MidaVault\scratch\product_recovery_route_a_r1_n{args.n}_{_ts_dir()}")
    )
    out_root.mkdir(parents=True, exist_ok=True)

    print(f"[orchestrator] target        = {target}")
    print(f"[orchestrator] target_sha256 = {target_sha}")
    print(f"[orchestrator] observer_bin  = {observer_bin}")
    print(f"[orchestrator] observer_sha  = {observer_sha}")
    print(f"[orchestrator] out_root      = {out_root}")
    print(f"[orchestrator] n             = {args.n}")
    print(f"[orchestrator] window_ms     = {args.observation_window_ms}")
    print(f"[orchestrator] poll_period   = {args.poll_period_ms}")
    print(f"[orchestrator] env           = MIDA_GTO_NO_BYPASS=1 (BYPASS/SEMANTIC_REPAIR unset)")

    run_records: list[dict] = []
    for i in range(1, args.n + 1):
        run_dir = out_root / f"run_{i}"
        print(f"[orchestrator] === run {i}/{args.n} ===")
        rec = _run_one(
            target=target,
            observer_bin=observer_bin,
            run_dir=run_dir,
            observation_window_ms=args.observation_window_ms,
            poll_period_ms=args.poll_period_ms,
        )
        run_records.append(rec)
        print(
            f"[orchestrator] run {i}: exit_code={rec['exit_code']} "
            f"sidecar_exists={rec['sidecar_exists']} "
            f"sidecar_sha256={rec['sidecar_sha256']} "
            f"elapsed={rec['elapsed_sec']}s"
        )

    summary = {
        "route": "GTO-PRODUCT-RECOVERY/RouteA",
        "method_class": "memory-state-epoch external observer",
        "orchestrator": Path(__file__).name,
        "started_at": _now_iso(),
        "target_path": str(target),
        "target_sha256": target_sha,
        "observer_bin": str(observer_bin),
        "observer_sha256": observer_sha,
        "out_root": str(out_root),
        "n": args.n,
        "observation_window_ms": args.observation_window_ms,
        "poll_period_ms": args.poll_period_ms,
        "env": {
            "MIDA_GTO_NO_BYPASS": "1",
            "MIDA_GTO_BYPASS": "<absent>",
            "MIDA_GTO_SEMANTIC_REPAIR": "<absent>",
        },
        "run_records": run_records,
    }
    summary_path = out_root / "orchestrator_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[orchestrator] wrote summary -> {summary_path}")

    # Invoke aggregator.
    aggregator = Path(__file__).resolve().parent / "_mtr_acq_route_a_aggregate.py"
    if aggregator.is_file():
        print(f"[orchestrator] invoking aggregator {aggregator.name}")
        agg_proc = subprocess.run(
            [sys.executable, str(aggregator), "--out-root", str(out_root), "--n", str(args.n)],
            capture_output=True, text=True,
        )
        print(agg_proc.stdout)
        if agg_proc.stderr:
            print(agg_proc.stderr, file=sys.stderr)
        return agg_proc.returncode
    else:
        print(f"[orchestrator] WARN: aggregator not found at {aggregator}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
