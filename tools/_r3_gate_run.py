# -*- coding: utf-8 -*-
"""Scheduled R3 Oreans 10x gate runner.

Runs Origin + Lunlun + ready holdout continuous N times (default 10) with:
  - structure gate EP match (expect-ep)
  - R0B StructuralPass* on every run
  - vault batch evidence under D:\\MidaVault\\lab\\evidence\\_repeat\\

On full pass, optionally writes repo `validation_summary.json` as VNEXT-R3
(previous R1-E summary is archived beside it).

Does **not** flip pure. Behavioral Accepted is never claimed.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from _oreans_repeat_smoke import r0b_structural_pass  # noqa: E402
from _r3_corpus import preflight_report  # noqa: E402

SMOKE = REPO / "tools" / "_oreans_repeat_smoke.py"
EV_REPEAT = Path(r"D:\MidaVault\lab\evidence\_repeat")
VALIDATION = REPO / "validation_summary.json"

# Fixed EPs from post-pdata green smokes (structure gate).
DEFAULT_EXPECT_EP = (
    "origin_macro=0x13e0,"
    "lunlun_software=0x1656f4,"
    "xiongxiong_duokai=0x35000"
)
DEFAULT_CASES = "origin_macro,lunlun_software,xiongxiong_duokai"
GATE_COUNT = 10


def main() -> int:
    ap = argparse.ArgumentParser(description="R3 Oreans continuous gate (scheduled)")
    ap.add_argument(
        "--count",
        type=int,
        default=GATE_COUNT,
        help=f"consecutive runs per case (default {GATE_COUNT})",
    )
    ap.add_argument("--cases", default=DEFAULT_CASES)
    ap.add_argument("--expect-ep", default=DEFAULT_EXPECT_EP)
    ap.add_argument(
        "--tag",
        default="",
        help="batch tag (default r3c_gate)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="preflight + print command only; do not unpack",
    )
    ap.add_argument(
        "--write-validation-summary",
        action="store_true",
        help="on pass, archive prior validation_summary and write VNEXT-R3",
    )
    ap.add_argument(
        "--allow-short-count",
        action="store_true",
        help="allow --count != 10 (engineering drill; will not set r3_gate true)",
    )
    args = ap.parse_args()

    if args.count < 1 or args.count > 20:
        print("count must be 1..20", file=sys.stderr)
        return 2

    formal_10 = args.count == GATE_COUNT and not args.allow_short_count
    if args.count != GATE_COUNT and not args.allow_short_count:
        print(
            f"REFUSED: formal R3 gate requires --count {GATE_COUNT} "
            f"(got {args.count}); use --allow-short-count for drills only",
            file=sys.stderr,
        )
        return 2

    pf = preflight_report()
    if not pf.get("gate_assets_ready"):
        print(
            "GATE_ASSETS_NOT_READY "
            f"holdout_status={pf.get('holdout_status')} "
            f"origin_mat={pf.get('origin', {}).get('materialized')} "
            f"lunlun_mat={pf.get('lunlun', {}).get('materialized')}",
            file=sys.stderr,
        )
        return 2
    if pf.get("holdout_status") != "ready":
        print(f"HOLDOUT_NOT_READY status={pf.get('holdout_status')}", file=sys.stderr)
        return 2

    tag = args.tag.strip() or ("r3c_gate" if formal_10 else f"r3c_drill_n{args.count}")
    smoke_cmd = [
        sys.executable,
        str(SMOKE),
        "--cases",
        args.cases,
        "--count",
        str(args.count),
        "--tag",
        tag,
        "--require-holdout",
        "--require-r0b",
        "--expect-ep",
        args.expect_ep,
    ]

    print(
        json.dumps(
            {
                "phase": "R3-C",
                "formal_10x": formal_10,
                "gate_assets_ready": pf.get("gate_assets_ready"),
                "holdout_status": pf.get("holdout_status"),
                "cases": [c.strip() for c in args.cases.split(",") if c.strip()],
                "count": args.count,
                "expect_ep": args.expect_ep,
                "smoke_cmd": smoke_cmd,
                "write_validation_summary": args.write_validation_summary,
            },
            indent=2,
        ),
        flush=True,
    )

    if args.dry_run:
        print("DRY_RUN ok", flush=True)
        return 0

    if not SMOKE.is_file():
        print("missing", SMOKE, file=sys.stderr)
        return 2

    print("=== R3 gate batch start ===", flush=True)
    t0 = datetime.now(timezone.utc)
    p = subprocess.run(smoke_cmd, cwd=str(REPO))
    t1 = datetime.now(timezone.utc)
    elapsed = (t1 - t0).total_seconds()

    # Locate latest batch dir for this tag.
    batch_dirs = sorted(
        [
            d
            for d in EV_REPEAT.iterdir()
            if d.is_dir() and d.name.endswith(f"_{tag}")
        ],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    ) if EV_REPEAT.is_dir() else []
    batch_dir = batch_dirs[0] if batch_dirs else None
    summary_path = batch_dir / "summary.json" if batch_dir else None
    summary = None
    if summary_path and summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))

    gate_ok = False
    reasons: list[str] = []
    if p.returncode != 0:
        reasons.append(f"smoke_exit={p.returncode}")
    if summary is None:
        reasons.append("missing_batch_summary")
    else:
        if not summary.get("all_ok"):
            reasons.append("summary_all_ok=false")
        if summary.get("count_requested") != args.count:
            reasons.append(
                f"count_mismatch want={args.count} got={summary.get('count_requested')}"
            )
        cases = summary.get("cases") or []
        need = {c.strip() for c in args.cases.split(",") if c.strip()}
        if set(cases) != need:
            reasons.append(f"cases_mismatch want={sorted(need)} got={cases}")
        if not summary.get("require_r0b"):
            reasons.append("require_r0b_not_set_in_batch")
        results = summary.get("results") or []
        if len(results) != len(need) * args.count:
            reasons.append(
                f"result_count want={len(need) * args.count} got={len(results)}"
            )
        for r in results:
            if not r.get("ok"):
                reasons.append(f"unpack_fail {r.get('case_id')} {r.get('tag')}")
            if not r0b_structural_pass(r.get("r0b_verdict")):
                reasons.append(
                    f"r0b_fail {r.get('case_id')} {r.get('tag')} "
                    f"verdict={r.get('r0b_verdict')!r}"
                )
            if not r.get("structure_ep"):
                reasons.append(f"no_structure_ep {r.get('case_id')} {r.get('tag')}")
        if summary.get("rollup", {}).get("ep_mismatches"):
            reasons.append(f"ep_mismatches={summary['rollup']['ep_mismatches']}")
        if summary.get("r0b_failures"):
            reasons.append(f"r0b_failures={summary['r0b_failures']}")

        # Formal R3 only when count==10 and criteria clean.
        gate_ok = formal_10 and not reasons and summary.get("all_ok") is True

    # Always write gate envelope next to batch (or under _repeat if missing).
    out_root = batch_dir if batch_dir else EV_REPEAT / f"gate_{datetime.now().strftime('%Y%m%d-%H%M%S')}_{tag}"
    out_root.mkdir(parents=True, exist_ok=True)
    envelope = {
        "schema_version": "mida.r3-gate-envelope/v1",
        "task": "VNEXT-R3",
        "formal_10x": formal_10,
        "r3_gate": gate_ok,
        "smoke_exit": p.returncode,
        "elapsed_sec": round(elapsed, 2),
        "started_utc": t0.isoformat(),
        "finished_utc": t1.isoformat(),
        "batch_dir": str(batch_dir) if batch_dir else None,
        "summary_path": str(summary_path) if summary_path else None,
        "preflight": {
            "holdout_status": pf.get("holdout_status"),
            "gate_assets_ready": pf.get("gate_assets_ready"),
            "holdouts": pf.get("holdouts"),
        },
        "fail_reasons": reasons,
        "pure_rebuild_default": False,
        "note": (
            "R3 structural gate only. Behavioral Accepted not claimed. "
            "Pure remains opt-in."
            if gate_ok
            else "R3 gate not closed."
        ),
    }
    env_path = out_root / "r3_gate_envelope.json"
    env_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    (out_root / "r3_gate_notes.md").write_text(
        "\n".join(
            [
                f"# R3 gate `{tag}`",
                "",
                f"- **r3_gate:** {gate_ok}",
                f"- formal_10x: {formal_10}",
                f"- smoke_exit: {p.returncode}",
                f"- elapsed_sec: {envelope['elapsed_sec']}",
                f"- batch: {batch_dir}",
                f"- fail_reasons: {reasons or '[]'}",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(
        f"r3_gate={gate_ok} formal_10x={formal_10} "
        f"reasons={reasons or '[]'} envelope={env_path}",
        flush=True,
    )

    if gate_ok and args.write_validation_summary:
        _write_validation_summary(envelope, summary, batch_dir)
        print("wrote", VALIDATION, flush=True)
    elif gate_ok and not args.write_validation_summary:
        print(
            "PASS but validation_summary not written "
            "(re-run with --write-validation-summary or write manually)",
            flush=True,
        )

    return 0 if gate_ok else 1


def _write_validation_summary(
    envelope: dict,
    summary: dict | None,
    batch_dir: Path | None,
) -> None:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    if VALIDATION.is_file():
        archive = REPO / f"validation_summary.prev_{stamp}.json"
        shutil.copy2(VALIDATION, archive)

    by_case = (summary or {}).get("rollup", {}).get("by_case", {})
    case_lines = []
    for cid, slot in by_case.items():
        case_lines.append(
            f"{cid}: ok={slot.get('ok')}/{slot.get('runs')} "
            f"ep={slot.get('unique_eps')} r0b={slot.get('r0b_unique')} "
            f"iat_avg={slot.get('iat_pct_avg')}"
        )

    doc = {
        "schema_version": "mida.validation-summary/v1",
        "task": "VNEXT-R3",
        "title": "Oreans family plugin structural gate (Origin+Lunlun+holdout 10x)",
        "package": "mida-cli / mida-packers-themida / mida-acceptance",
        "verdict_contract": "docs/ACCEPTANCE_CONTRACT.md",
        "roadmap": "docs/VNEXT_R3_OREANS_PATH.md",
        "checks": {
            "r3_continuous_10x": "pass",
            "cases": [
                "origin_macro",
                "lunlun_software",
                "xiongxiong_duokai",
            ],
            "structure_gate_ep_stable": "pass",
            "r0b_floor": "StructuralPassBehaviorPending",
            "holdout_corpus_role": "holdout",
            "pure_rebuild_default": False,
            "behavioral_accepted": False,
            "target_process_starts": int(
                (summary or {}).get("count_requested", 10)
            )
            * 3,
            "network_actions": 0,
        },
        "notes": [
            "VNEXT-R3 closed on continuous 10x live unpack + structure gate + "
            "R0B StructuralPassBehaviorPending for Origin, Lunlun, and holdout "
            f"xiongxiong_duokai ({stamp}).",
            "Evidence: vault lab/evidence/_repeat batch + r3_gate_envelope.json.",
            "Pure rebuild remains opt-in; production dump defaults to legacy.",
            "R0B never returns Behavioral Accepted at this gate.",
            "IAT quality residual (holdout rebuild ~77%) is non-blocking for R3 "
            "structural close; tracked as engineering follow-up.",
            *case_lines,
        ],
        "artifacts": [
            "docs/VNEXT_R3_OREANS_PATH.md",
            "docs/PROJECT_AUDIT_AND_ROADMAP.md",
            "WORKER_HANDOFF.md",
            "tools/_r3_gate_run.py",
            "tools/_oreans_repeat_smoke.py",
            "lab/cases/v2/xiongxiong_duokai.json",
            str(batch_dir) if batch_dir else "",
            str(envelope.get("batch_dir") or ""),
        ],
        "gate_envelope": {
            "r3_gate": True,
            "batch_dir": envelope.get("batch_dir"),
            "elapsed_sec": envelope.get("elapsed_sec"),
            "finished_utc": envelope.get("finished_utc"),
        },
    }
    # Drop empty artifact strings.
    doc["artifacts"] = [a for a in doc["artifacts"] if a]
    VALIDATION.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
