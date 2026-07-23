# -*- coding: utf-8 -*-
"""R3 gate preflight — inventory only; never claims R3 closed.

Exit codes:
  0  preflight ran; print status (even if holdout empty)
  2  --require-holdout and holdout not ready, or --claim-r3 refused
  3  Origin/Lunlun assets missing (when --require-core)

Writes vault summary under D:\\MidaVault\\lab\\evidence\\_repeat\\preflight_*
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Allow `python tools/_r3_gate_preflight.py` without package install.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _r3_corpus import preflight_report  # noqa: E402

EV_ROOT = Path(r"D:\MidaVault\lab\evidence\_repeat")


def main() -> int:
    ap = argparse.ArgumentParser(description="R3 gate preflight (not a gate close)")
    ap.add_argument(
        "--require-holdout",
        action="store_true",
        help="exit 2 if holdout_status != ready",
    )
    ap.add_argument(
        "--require-core",
        action="store_true",
        help="exit 3 if Origin/Lunlun not materialized",
    )
    ap.add_argument(
        "--claim-r3",
        action="store_true",
        help="rejected: preflight never claims R3",
    )
    ap.add_argument(
        "--write",
        action="store_true",
        help="write preflight JSON under vault _repeat/",
    )
    args = ap.parse_args()

    if args.claim_r3:
        print(
            "REFUSED: preflight cannot claim R3. "
            "Need holdout ready + continuous 10x + validation_summary.",
            file=sys.stderr,
        )
        return 2

    report = preflight_report()
    print(json.dumps(report, indent=2), flush=True)
    print(
        f"holdout_status={report['holdout_status']} "
        f"gate_assets_ready={report['gate_assets_ready']} "
        f"r3_gate={report['r3_gate']}",
        flush=True,
    )

    if args.write:
        EV_ROOT.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out = EV_ROOT / f"preflight_{stamp}_r3b"
        out.mkdir(parents=True, exist_ok=True)
        (out / "preflight.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        (out / "notes.md").write_text(
            f"# R3 preflight `{stamp}`\n\n"
            f"- holdout_status: **{report['holdout_status']}**\n"
            f"- gate_assets_ready: {report['gate_assets_ready']}\n"
            f"- r3_gate: false (preflight never closes R3)\n",
            encoding="utf-8",
        )
        print("wrote", out / "preflight.json", flush=True)

    if args.require_core:
        if not report["origin"].get("materialized") or not report["lunlun"].get(
            "materialized"
        ):
            print("CORE_ASSETS_MISSING", file=sys.stderr)
            return 3

    if args.require_holdout and report["holdout_status"] != "ready":
        print(
            f"HOLDOUT_NOT_READY status={report['holdout_status']}",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
