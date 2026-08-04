# -*- coding: utf-8 -*-
"""R4-A2 engineering GTO live smoke harness (NOT R4 / R3 gate).

Always runs with explicit `--profile=ahk-gto-experimental`.
Never auto-selects GTO dump stages from case_id alone.
Oreans failure is out of scope here — use `_oreans_repeat_smoke.py`.

Exit 0 only when:
  - unpack exit 0
  - dual-select family is ahk_gto (unless --allow-family-mismatch)
  - optional --require-r0b and verdict starts with StructuralPass

Does not write validation_summary VNEXT-R4.
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

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "tools"))
from _r3_corpus import (  # noqa: E402
    FORBIDDEN_HOLDOUT_IDS,
    engine_route,
    load_manifests,
    protection_family,
    resolve_case_cfg,
)

CASE_SCRIPT = REPO / "tools" / "_case_live_unpack.py"
EV_ROOT = Path(r"D:\MidaVault\lab\evidence")
SUMMARY_ROOT = EV_ROOT / "_gto_smoke"

DEFAULT_CASE = "gto_launcher"
GTO_PROFILE = "ahk-gto-experimental"
EXPECTED_FAMILY = "ahk_gto"
R0B_PASS_PREFIX = "StructuralPass"

RE_DUAL = re.compile(
    r'PackerPlugin identify:\s*dual-family select.*?selected="([^"]+)".*?conf=(\d+)',
    re.I,
)
RE_MATCH = re.compile(
    r'PackerPlugin identify:\s*Match\s+family="([^"]+)"\s+confidence=(\d+)',
    re.I,
)
RE_STRUCTURE_EP = re.compile(r"Structure gate:\s*EP=(0x[0-9a-fA-F]+)", re.I)
RE_DUMP_FAMILY = re.compile(
    r'PackerPlugin:\s*dump enter.*?family="([^"]+)"',
    re.I,
)


def is_gto_research_case(case_id: str, manifests: list | None = None) -> bool:
    mans = manifests if manifests is not None else load_manifests()
    man = next((m for m in mans if m.get("case_id") == case_id), None)
    if man is None:
        return False
    fam = protection_family(man) or ""
    route = engine_route(man) or ""
    return "ahk_gto" in fam or "ahk_gto" in route or case_id == DEFAULT_CASE


def find_latest_live_dir(case_id: str, tag: str) -> Path | None:
    case_root = EV_ROOT / case_id
    if not case_root.is_dir():
        return None
    candidates = sorted(
        [p for p in case_root.iterdir() if p.is_dir() and p.name.endswith(f"_{tag}")],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        return candidates[0]
    # profile may append _gtoexp after tag
    looser = sorted(
        [
            p
            for p in case_root.iterdir()
            if p.is_dir() and tag in p.name and p.name.startswith("live_")
        ],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return looser[0] if looser else None


def parse_signals_from_dir(live_dir: Path | None) -> dict:
    text = ""
    meta_signals: dict = {}
    if live_dir is None:
        return {
            "selected_family": None,
            "plugin_confidence": None,
            "structure_ep": None,
            "dump_family": None,
            "profile": None,
            "r0b_verdict": None,
        }
    log_p = live_dir / "unpack.stdout.txt"
    if log_p.is_file():
        text = log_p.read_text(encoding="utf-8", errors="replace")
    meta_p = live_dir / "run_meta.json"
    if meta_p.is_file():
        try:
            meta = json.loads(meta_p.read_text(encoding="utf-8"))
            meta_signals = meta.get("signals") or {}
        except (OSError, json.JSONDecodeError):
            meta = {}
    else:
        meta = {}

    selected = meta_signals.get("selected_family")
    conf = meta_signals.get("plugin_confidence")
    ep = meta_signals.get("structure_ep")
    dump_family = meta_signals.get("dump_family")
    if not selected and text:
        m = RE_DUAL.search(text) or RE_MATCH.search(text)
        if m:
            selected = m.group(1)
            conf = int(m.group(2))
    if not ep and text:
        m = RE_STRUCTURE_EP.search(text)
        if m:
            ep = m.group(1).lower()
    if not dump_family and text:
        m = RE_DUMP_FAMILY.search(text)
        if m:
            dump_family = m.group(1)

    r0b = None
    r0b_meta = live_dir / "r0b_candidate_meta.json"
    if r0b_meta.is_file():
        try:
            r0b = json.loads(r0b_meta.read_text(encoding="utf-8")).get("verdict")
        except (OSError, json.JSONDecodeError):
            pass
    if r0b is None and isinstance(meta.get("r0b"), dict):
        r0b = meta["r0b"].get("verdict")

    return {
        "selected_family": selected,
        "plugin_confidence": conf,
        "structure_ep": ep,
        "dump_family": dump_family,
        "profile": meta.get("profile"),
        "r0b_verdict": r0b,
    }


def r0b_ok(verdict: str | None) -> bool:
    return bool(verdict) and str(verdict).startswith(R0B_PASS_PREFIX)


def run_one(case_id: str, tag: str, no_r0b: bool) -> dict:
    cmd = [
        sys.executable,
        str(CASE_SCRIPT),
        case_id,
        "--tag",
        tag,
        "--profile",
        GTO_PROFILE,
    ]
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
    signals = parse_signals_from_dir(live_dir)

    # Console may print R0B line even when meta is elsewhere.
    if signals.get("r0b_verdict") is None:
        for line in out.splitlines():
            if line.startswith("R0B "):
                parts = line.split()
                if len(parts) >= 2:
                    signals["r0b_verdict"] = parts[1]
                break

    family_ok = signals.get("selected_family") == EXPECTED_FAMILY
    # Profile is always forced on the harness CLI; meta should record it.
    profile_recorded = signals.get("profile") == GTO_PROFILE

    ok = p.returncode == 0 and family_ok
    return {
        "case_id": case_id,
        "tag": tag,
        "exit_code": p.returncode,
        "elapsed_sec": elapsed,
        "selected_family": signals.get("selected_family"),
        "plugin_confidence": signals.get("plugin_confidence"),
        "structure_ep": signals.get("structure_ep"),
        "dump_family": signals.get("dump_family"),
        "r0b_verdict": signals.get("r0b_verdict"),
        "profile": GTO_PROFILE,
        "family_ok": family_ok,
        "profile_recorded": profile_recorded,
        "evidence_dir": str(live_dir) if live_dir else None,
        "ok": ok,
        "stdout_tail": "\n".join(out.splitlines()[-20:]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="R4-A2 GTO live smoke (engineering only; not R4 gate)."
    )
    ap.add_argument(
        "--cases",
        default=DEFAULT_CASE,
        help=f"comma-separated case ids (default {DEFAULT_CASE})",
    )
    ap.add_argument("--tag", default="r4a2_gto", help="evidence tag suffix")
    ap.add_argument(
        "--require-r0b",
        action="store_true",
        help="fail if R0B verdict is not StructuralPass*",
    )
    ap.add_argument("--no-r0b", action="store_true", help="skip R0B entirely")
    ap.add_argument(
        "--allow-family-mismatch",
        action="store_true",
        help="do not fail when selected family != ahk_gto (debug only)",
    )
    ap.add_argument(
        "--allow-non-gto-case",
        action="store_true",
        help="allow running on non-ahk_gto manifests (still forces GTO profile)",
    )
    args = ap.parse_args()

    if args.require_r0b and args.no_r0b:
        print("cannot combine --require-r0b and --no-r0b", file=sys.stderr)
        return 2

    cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    if not cases:
        print("no cases", file=sys.stderr)
        return 2

    manifests = load_manifests()
    batch_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    batch_dir = SUMMARY_ROOT / f"batch_{batch_id}_{args.tag}"
    batch_dir.mkdir(parents=True, exist_ok=True)

    print(
        "NOTE: R4-A2 GTO engineering smoke only — NOT R4 gate, NOT R3, "
        f"profile={GTO_PROFILE} always explicit.",
        flush=True,
    )
    print(f"batch={batch_id} cases={cases} tag={args.tag}", flush=True)

    results: list[dict] = []
    for case_id in cases:
        if case_id in FORBIDDEN_HOLDOUT_IDS and case_id != DEFAULT_CASE:
            # still allow gto_launcher; block treating oreans as GTO by accident
            pass
        if not args.allow_non_gto_case and not is_gto_research_case(case_id, manifests):
            print(
                f"REFUSE {case_id}: not ahk_gto research case "
                f"(pass --allow-non-gto-case to override)",
                file=sys.stderr,
            )
            results.append(
                {
                    "case_id": case_id,
                    "ok": False,
                    "error": "not_gto_research_case",
                }
            )
            continue
        cfg = resolve_case_cfg(case_id, manifests=manifests)
        if cfg is None:
            print(f"missing materialization for {case_id}", file=sys.stderr)
            results.append(
                {"case_id": case_id, "ok": False, "error": "not_materialized"}
            )
            continue

        tag = f"{args.tag}_{case_id}" if len(cases) > 1 else args.tag
        print(f"=== {case_id} tag={tag} profile={GTO_PROFILE} ===", flush=True)
        r = run_one(case_id, tag, no_r0b=args.no_r0b)
        if args.allow_family_mismatch and r.get("exit_code") == 0:
            r["ok"] = True
            r["family_ok"] = r.get("family_ok")  # keep truth
        if args.require_r0b:
            if not r0b_ok(r.get("r0b_verdict")):
                r["ok"] = False
                r["r0b_fail"] = True
        results.append(r)
        print(
            f"  exit={r.get('exit_code')} family={r.get('selected_family')} "
            f"conf={r.get('plugin_confidence')} ep={r.get('structure_ep')} "
            f"r0b={r.get('r0b_verdict')} ok={r.get('ok')}",
            flush=True,
        )
        if r.get("evidence_dir"):
            print(f"  evidence {r['evidence_dir']}", flush=True)

    all_ok = all(r.get("ok") for r in results) and len(results) == len(cases)
    summary = {
        "batch_id": batch_id,
        "tag": args.tag,
        "phase": "R4-A2",
        "r4_gate": False,
        "r3_gate": False,
        "profile": GTO_PROFILE,
        "expected_family": EXPECTED_FAMILY,
        "require_r0b": args.require_r0b,
        "cases": cases,
        "results": results,
        "all_ok": all_ok,
        "note": (
            "Engineering GTO smoke only. Explicit ahk-gto-experimental profile. "
            "Does not close R4 or write validation_summary VNEXT-R4."
        ),
    }
    summary_path = batch_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"summary {summary_path} all_ok {all_ok}", flush=True)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
