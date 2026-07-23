# -*- coding: utf-8 -*-
"""Engineering multi-run Oreans live smoke (NOT the R3 10x gate).

Runs Origin and/or Lunlun N times via `_case_live_unpack.py`, writes a vault
summary with EP / R0B rollup. Exit 0 only if every selected case succeeds all
iterations (and optional --expect-ep matches).

This does **not** open or claim R3:
- no holdout case
- no validation_summary R3 close
- default count is small (engineering); use --count 10 only as prep data

Evidence root: D:\\MidaVault\\lab\\evidence\\_repeat\\
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
from _r3_corpus import (  # noqa: E402
    FORBIDDEN_HOLDOUT_IDS,
    is_oreans_candidate,
    load_manifests,
    preflight_report,
    resolve_case_cfg,
)

CASE_SCRIPT = REPO / "tools" / "_case_live_unpack.py"
EV_ROOT = Path(r"D:\MidaVault\lab\evidence")
SUMMARY_ROOT = EV_ROOT / "_repeat"

CASES_DEFAULT = ("origin_macro",)

# Structure gate line from mida-cli verbose unpack log.
RE_STRUCTURE_EP = re.compile(r"Structure gate:\s*EP=(0x[0-9a-fA-F]+)", re.I)
RE_IAT_SKIP = re.compile(r"IAT v3 skipped.*?reason=\"([^\"]+)\"")
RE_PLUGIN_MATCH = re.compile(
    r'PackerPlugin identify:\s*Match\s+family="([^"]+)"\s+confidence=(\d+)'
)
# Post-rebuild coverage (R3-path-C / holdout quality signal).
# Matches:
#   IAT rebuild sufficient: 336/352 non-zero slots (95% coverage; total_slots=352)
#   IAT rebuild incomplete: 221/286 non-zero (77%); original has more ...
#   IAT rebuild incomplete vs non-zero slots (221/286 = 77%), but original ...
#   legacy: IAT rebuild sufficient: 336/352 runtime slots (95% coverage)
RE_IAT_REBUILD = re.compile(
    r"IAT rebuild (?:sufficient|incomplete).*?(\d+)/(\d+).*?(\d+)%",
    re.I,
)
RE_V3_RESOLVED = re.compile(
    r"fix_iat_v3:\s*(\d+)\s+resolved,\s*(\d+)\s+failed",
    re.I,
)
RE_STORM_FREEZE = re.compile(r"Storm escape freeze", re.I)

# R0B static never returns Behavioral Accepted; gate floor is StructuralPass*.
R0B_PASS_PREFIX = "StructuralPass"


def r0b_structural_pass(verdict: str | None) -> bool:
    if not verdict or not isinstance(verdict, str):
        return False
    return verdict.startswith(R0B_PASS_PREFIX)


def parse_expect_ep(s: str) -> dict[str, str]:
    """Parse `case=0x13e0,case2=0x1656f4` → normalized lowercase hex strings."""
    out: dict[str, str] = {}
    if not s or not s.strip():
        return out
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            raise SystemExit(f"bad --expect-ep fragment (need case=0x..): {part!r}")
        case, ep = part.split("=", 1)
        case = case.strip()
        ep = ep.strip().lower()
        if not ep.startswith("0x"):
            ep = "0x" + ep
        out[case] = ep
    return out


def parse_log_signals(text: str) -> dict:
    ep = None
    m = RE_STRUCTURE_EP.search(text)
    if m:
        ep = m.group(1).lower()
    skip_reason = None
    m2 = RE_IAT_SKIP.search(text)
    if m2:
        skip_reason = m2.group(1)
    family = None
    confidence = None
    m3 = RE_PLUGIN_MATCH.search(text)
    if m3:
        family = m3.group(1)
        confidence = int(m3.group(2))
    iat_rebuild = None
    m4 = RE_IAT_REBUILD.search(text)
    if m4:
        iat_rebuild = {
            "resolved": int(m4.group(1)),
            "total": int(m4.group(2)),
            "pct": int(m4.group(3)),
        }
    v3 = None
    m5 = RE_V3_RESOLVED.search(text)
    if m5:
        v3 = {"resolved": int(m5.group(1)), "failed": int(m5.group(2))}
    return {
        "structure_ep": ep,
        "iat_skip_reason": skip_reason,
        "plugin_family": family,
        "plugin_confidence": confidence,
        "iat_rebuild": iat_rebuild,
        "v3_trace": v3,
        "storm_escape_freeze": bool(RE_STORM_FREEZE.search(text)),
    }


def find_latest_live_dir(case_id: str, tag: str) -> Path | None:
    """Locate evidence dir for this run: live_*_{tag} under case evidence root."""
    case_root = EV_ROOT / case_id
    if not case_root.is_dir():
        return None
    # Prefer exact suffix match on tag (case script: live_{ts}_{tag}).
    candidates = sorted(
        [p for p in case_root.iterdir() if p.is_dir() and p.name.endswith(f"_{tag}")],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return candidates[0] if candidates else None


def load_evidence_text(live_dir: Path | None) -> str:
    if live_dir is None:
        return ""
    parts: list[str] = []
    for name in ("unpack.stdout.txt", "r0b_candidate.stdout.txt", "run_meta.json"):
        p = live_dir / name
        if p.is_file():
            try:
                parts.append(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
    return "\n".join(parts)


def run_one(case_id: str, tag: str, pure: bool, no_r0b: bool) -> dict:
    cmd = [sys.executable, str(CASE_SCRIPT), case_id, "--tag", tag]
    if pure:
        cmd.append("--pure-rebuild")
    if no_r0b:
        cmd.append("--no-r0b")
    t0 = time.time()
    p = subprocess.run(
        cmd,
        cwd=str(REPO),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    elapsed = round(time.time() - t0, 2)
    out = (p.stdout or "") + (p.stderr or "")

    live_dir = find_latest_live_dir(case_id, tag)
    # Full unpack log beats case-script console tail (skip/identify are early).
    evidence = load_evidence_text(live_dir)
    signals = parse_log_signals(evidence if evidence else out)

    verdict = None
    for line in out.splitlines():
        if line.startswith("R0B "):
            parts = line.split()
            if len(parts) >= 2:
                verdict = parts[1]
            break
    if verdict is None and live_dir is not None:
        meta_path = live_dir / "r0b_candidate_meta.json"
        if meta_path.is_file():
            try:
                verdict = json.loads(meta_path.read_text(encoding="utf-8")).get("verdict")
            except (OSError, json.JSONDecodeError):
                pass

    return {
        "case_id": case_id,
        "tag": tag,
        "exit_code": p.returncode,
        "elapsed_sec": elapsed,
        "r0b_verdict": verdict,
        "structure_ep": signals["structure_ep"],
        "iat_skip_reason": signals["iat_skip_reason"],
        "plugin_family": signals["plugin_family"],
        "plugin_confidence": signals["plugin_confidence"],
        "iat_rebuild": signals.get("iat_rebuild"),
        "v3_trace": signals.get("v3_trace"),
        "storm_escape_freeze": signals.get("storm_escape_freeze"),
        "evidence_dir": str(live_dir) if live_dir else None,
        "ok": p.returncode == 0,
        "stdout_tail": "\n".join(out.splitlines()[-15:]),
    }


def rollup(results: list[dict], expect_ep: dict[str, str]) -> dict:
    by_case: dict[str, dict] = {}
    ep_mismatches: list[dict] = []
    for r in results:
        c = r["case_id"]
        slot = by_case.setdefault(
            c,
            {
                "runs": 0,
                "ok": 0,
                "eps": [],
                "r0b": [],
                "skip_reasons": [],
                "elapsed": [],
                "iat_pcts": [],
                "storm_freeze_count": 0,
            },
        )
        slot["runs"] += 1
        if r["ok"]:
            slot["ok"] += 1
        if r.get("structure_ep"):
            slot["eps"].append(r["structure_ep"])
        if r.get("r0b_verdict"):
            slot["r0b"].append(r["r0b_verdict"])
        if r.get("iat_skip_reason"):
            slot["skip_reasons"].append(r["iat_skip_reason"])
        if r.get("iat_rebuild") and isinstance(r["iat_rebuild"], dict):
            pct = r["iat_rebuild"].get("pct")
            if pct is not None:
                slot["iat_pcts"].append(pct)
        if r.get("storm_escape_freeze"):
            slot["storm_freeze_count"] += 1
        slot["elapsed"].append(r["elapsed_sec"])

        exp = expect_ep.get(c)
        got = r.get("structure_ep")
        if exp and r["ok"] and got and got != exp:
            ep_mismatches.append({"case_id": c, "tag": r["tag"], "expected": exp, "got": got})

    for c, slot in by_case.items():
        eps = slot["eps"]
        slot["unique_eps"] = sorted(set(eps))
        slot["ep_stable"] = len(set(eps)) <= 1 if eps else None
        slot["r0b_unique"] = sorted(set(slot["r0b"]))
        slot["avg_elapsed_sec"] = (
            round(sum(slot["elapsed"]) / len(slot["elapsed"]), 2) if slot["elapsed"] else None
        )
        pcts = slot["iat_pcts"]
        slot["iat_pct_min"] = min(pcts) if pcts else None
        slot["iat_pct_max"] = max(pcts) if pcts else None
        slot["iat_pct_avg"] = round(sum(pcts) / len(pcts), 1) if pcts else None
        del slot["elapsed"]
        del slot["iat_pcts"]

    return {
        "by_case": by_case,
        "ep_mismatches": ep_mismatches,
        "expect_ep": expect_ep,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Oreans multi-run engineering smoke (not R3 gate)"
    )
    ap.add_argument(
        "--cases",
        default=",".join(CASES_DEFAULT),
        help="comma-separated case ids (manifest-resolved; holdout when registered)",
    )
    ap.add_argument(
        "--count",
        type=int,
        default=2,
        help="iterations per case (default 2; use 10 only for prep data, still not R3)",
    )
    ap.add_argument("--tag", default="r3prep", help="tag suffix for live_ dirs")
    ap.add_argument("--pure-rebuild", action="store_true")
    ap.add_argument("--no-r0b", action="store_true")
    ap.add_argument(
        "--expect-ep",
        default="",
        help="optional case=0xEP map, e.g. origin_macro=0x13e0,lunlun_software=0x1656f4",
    )
    ap.add_argument(
        "--require-holdout",
        action="store_true",
        help="fail unless a ready Oreans holdout is in the --cases list (still not R3)",
    )
    ap.add_argument(
        "--include-holdout",
        action="store_true",
        help="append ready holdout case_ids to --cases when present",
    )
    ap.add_argument(
        "--require-r0b",
        action="store_true",
        help=(
            "fail unless every successful unpack has R0B verdict starting with "
            "StructuralPass (gate-quality rollup; still not claim-r3)"
        ),
    )
    ap.add_argument(
        "--claim-r3",
        action="store_true",
        help="rejected: this tool never claims R3 (flag exists to fail loudly)",
    )
    args = ap.parse_args()

    if args.claim_r3:
        print(
            "REFUSED: --claim-r3 is not supported. "
            "Use tools/_r3_gate_run.py for scheduled R3 10x + validation_summary.",
            file=sys.stderr,
        )
        return 2
    if args.no_r0b and args.require_r0b:
        print("cannot combine --no-r0b with --require-r0b", file=sys.stderr)
        return 2
    if args.count < 1 or args.count > 20:
        print("count must be 1..20", file=sys.stderr)
        return 2

    try:
        expect_ep = parse_expect_ep(args.expect_ep)
    except SystemExit as e:
        print(e, file=sys.stderr)
        return 2

    cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    pf = preflight_report()
    holdout_ready_ids = [
        h["case_id"]
        for h in pf.get("holdouts") or []
        if h.get("materialized") and h.get("object_present")
    ]
    if args.include_holdout:
        for hid in holdout_ready_ids:
            if hid not in cases:
                cases.append(hid)

    builtin_oreans = {"origin_macro", "lunlun_software"}
    for c in cases:
        if c in builtin_oreans:
            continue
        if c in FORBIDDEN_HOLDOUT_IDS:
            print(
                f"case {c!r} cannot be used as Oreans harness target "
                f"(see HOLDOUT_SLOT.md forbidden list)",
                file=sys.stderr,
            )
            return 2
        if c in holdout_ready_ids:
            continue
        man = next((m for m in load_manifests() if m.get("case_id") == c), None)
        if man is None or not is_oreans_candidate(man):
            print(
                f"case {c!r} not Oreans-routed or unknown; "
                f"oreans={pf.get('oreans_case_ids')} holdout_status={pf.get('holdout_status')}",
                file=sys.stderr,
            )
            return 2
        if resolve_case_cfg(c) is None:
            print(f"case {c!r} not materialized", file=sys.stderr)
            return 2
        # Oreans non-holdout extras (future) allowed only if materialized.


    if args.require_holdout:
        if pf.get("holdout_status") != "ready":
            print(
                f"HOLDOUT_NOT_READY status={pf.get('holdout_status')} "
                f"(see lab/cases/v2/HOLDOUT_SLOT.md)",
                file=sys.stderr,
            )
            return 2
        if not any(c in holdout_ready_ids for c in cases):
            print(
                "require-holdout: no holdout case in --cases; "
                f"ready={holdout_ready_ids}",
                file=sys.stderr,
            )
            return 2

    if not CASE_SCRIPT.is_file():
        print("missing", CASE_SCRIPT, file=sys.stderr)
        return 2

    batch_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = SUMMARY_ROOT / f"batch_{batch_id}_{args.tag}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(
        "NOTE: engineering multi-run only — NOT R3 Oreans gate "
        f"(holdout_status={pf.get('holdout_status')}; no validation_summary close).",
        flush=True,
    )
    print(
        f"batch={batch_id} cases={cases} count={args.count} expect_ep={expect_ep or '{}'}",
        flush=True,
    )

    results: list[dict] = []
    failed = 0
    for case_id in cases:
        for i in range(1, args.count + 1):
            tag = f"{args.tag}_n{i}"
            print(f"=== {case_id} iter {i}/{args.count} tag={tag} ===", flush=True)
            r = run_one(case_id, tag, args.pure_rebuild, args.no_r0b)
            results.append(r)
            status = "OK" if r["ok"] else "FAIL"
            print(
                f"  {status} exit={r['exit_code']} elapsed={r['elapsed_sec']} "
                f"ep={r['structure_ep']} r0b={r['r0b_verdict']} "
                f"skip={r['iat_skip_reason']}",
                flush=True,
            )
            if not r["ok"]:
                failed += 1
                break
            if args.require_r0b and not r0b_structural_pass(r.get("r0b_verdict")):
                print(
                    f"  R0B_FAIL need StructuralPass* got={r.get('r0b_verdict')!r}",
                    flush=True,
                )
                failed += 1
                break
        if failed:
            break

    roll = rollup(results, expect_ep)
    if roll["ep_mismatches"]:
        failed += len(roll["ep_mismatches"])

    r0b_failures: list[dict] = []
    if args.require_r0b:
        for r in results:
            if not r0b_structural_pass(r.get("r0b_verdict")):
                r0b_failures.append(
                    {
                        "case_id": r["case_id"],
                        "tag": r["tag"],
                        "r0b_verdict": r.get("r0b_verdict"),
                    }
                )
        if r0b_failures:
            failed += len(r0b_failures)

    all_ok = (
        failed == 0
        and len(results) == len(cases) * args.count
        and not roll["ep_mismatches"]
        and not r0b_failures
    )

    summary = {
        "batch_id": batch_id,
        "tag": args.tag,
        "cases": cases,
        "count_requested": args.count,
        "pure_rebuild": args.pure_rebuild,
        "no_r0b": args.no_r0b,
        "require_r0b": args.require_r0b,
        "r3_gate": False,
        "phase": "R3-path-D",
        "holdout_status": pf.get("holdout_status"),
        "gate_assets_ready": pf.get("gate_assets_ready"),
        "require_holdout": args.require_holdout,
        "note": (
            "Engineering repeat only. Not R3 close "
            "(use tools/_r3_gate_run.py for scheduled 10x + validation_summary)."
        ),
        "results": results,
        "rollup": roll,
        "r0b_failures": r0b_failures,
        "all_ok": all_ok,
        "failed_count": failed,
    }
    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    lines = [
        f"# Oreans repeat batch `{batch_id}`",
        "",
        "- **r3_gate:** false (engineering / R3-path only)",
        f"- **phase:** R3-path-D",
        f"- cases: {cases}",
        f"- count: {args.count}",
        f"- all_ok: {all_ok}",
        f"- failed_count: {failed}",
        f"- expect_ep: {expect_ep or '{}'}",
        "",
        "## Rollup",
        "",
    ]
    for case_id, slot in roll["by_case"].items():
        lines.append(
            f"- **{case_id}:** ok={slot['ok']}/{slot['runs']} "
            f"eps={slot['unique_eps']} stable={slot['ep_stable']} "
            f"r0b={slot['r0b_unique']} avg_s={slot['avg_elapsed_sec']}"
        )
    if roll["ep_mismatches"]:
        lines.append("")
        lines.append("## EP mismatches")
        lines.append("")
        for m in roll["ep_mismatches"]:
            lines.append(
                f"- {m['case_id']} {m['tag']}: expected {m['expected']} got {m['got']}"
            )
    if r0b_failures:
        lines.append("")
        lines.append("## R0B failures")
        lines.append("")
        for m in r0b_failures:
            lines.append(
                f"- {m['case_id']} {m['tag']}: r0b={m.get('r0b_verdict')!r}"
            )
    lines.append("")
    (out_dir / "notes.md").write_text("\n".join(lines), encoding="utf-8")
    print("summary", summary_path, "all_ok", all_ok, flush=True)
    if roll["ep_mismatches"]:
        print("EP_MISMATCHES", roll["ep_mismatches"], flush=True)
    if r0b_failures:
        print("R0B_FAILURES", r0b_failures, flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
