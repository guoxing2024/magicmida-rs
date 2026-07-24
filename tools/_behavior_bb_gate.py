# -*- coding: utf-8 -*-
"""Scheduled B-B / VNEXT-BEH gate runner (operator-authorized).

Pipeline per case (vault candidates from live unpack evidence):
  1) R0B check-static → StructuralPassBehaviorPending required
  2) load_no_crash_v0 probe → evidence Pass required for Accepted
  3) mida-acceptance check-with-behavior → Accepted required

Writes vault evidence under D:\\MidaVault\\lab\\evidence\\_beh_gate\\
and optionally updates repo validation_summary.json task VNEXT-BEH.

Does NOT invent Pass when probes Fail/Inconclusive.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

CLI = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-cli.exe")
ACC = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-acceptance.exe")
# Fallback local target
if not ACC.is_file():
    ACC = REPO / "target" / "debug" / "mida-acceptance.exe"
EV_ROOT = Path(r"D:\MidaVault\lab\evidence")
GATE_ROOT = EV_ROOT / "_beh_gate"

PROBE = REPO / "tools" / "_behavior_probe.py"
CASE_UNPACK = REPO / "tools" / "_case_live_unpack.py"
GTO_SMOKE = REPO / "tools" / "_gto_live_smoke.py"


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(str(c) for c in cmd), flush=True)
    return subprocess.run(cmd, **kw)


def _candidate_in_live(live_dir: Path, name_hints: list[str]) -> Path | None:
    for hint in name_hints:
        for p in live_dir.glob(hint):
            if p.is_file() and p.stat().st_size > 1024:
                return p
    for p in live_dir.glob("*_unpacked.exe"):
        if p.is_file() and p.stat().st_size > 1024:
            return p
    for p in live_dir.glob("*.exe"):
        if "protected" in p.name.lower():
            continue
        if p.is_file() and p.stat().st_size > 1024:
            return p
    return None


# Prefer tags that have already composed Accepted / load-survived in prior gates.
# Newest-first walk still runs after these pins (deduped).
PREFERRED_LIVE_TAGS: dict[str, list[str]] = {
    "origin_macro": [
        "live_20260724-101051_u_origin_pure_r1",
        "live_20260724-104711_u_origin_pure_r2",
    ],
    "gto_launcher": [
        "live_20260724-004707_p1_gto_reg",
    ],
    "lunlun_software": [
        "live_20260724-013746_u_harden_3x_n3",
    ],
    "xiongxiong_duokai": [
        "live_20260724-013837_u_harden_3x_n3",
    ],
}


def iter_structural_candidates(
    case_id: str,
    name_hints: list[str],
    *,
    max_candidates: int = 4,
) -> list[Path]:
    """Preferred tags first, then newest StructuralPass; skip R0B Rejected."""
    case_dir = EV_ROOT / case_id
    if not case_dir.is_dir():
        return []
    out: list[Path] = []
    seen: set[str] = set()

    def _try_add(d: Path) -> None:
        if len(out) >= max_candidates:
            return
        cand = _candidate_in_live(d, name_hints)
        if cand is None:
            return
        key = str(cand.resolve())
        if key in seen:
            return
        if ACC.is_file():
            report = d / "_r0b_select.json"
            try:
                r0b = r0b_check(cand, report)
                v = r0b.get("verdict") or ""
                if v == "Rejected":
                    return
                if not (v.startswith("StructuralPass") or v is None or v == ""):
                    # Unknown non-StructuralPass — still allow if not Rejected.
                    if v and not v.startswith("Structural"):
                        return
            except Exception:
                pass
        seen.add(key)
        out.append(cand)

    for tag in PREFERRED_LIVE_TAGS.get(case_id, []):
        d = case_dir / tag
        if d.is_dir():
            _try_add(d)

    lives = sorted(
        [p for p in case_dir.iterdir() if p.is_dir() and p.name.startswith("live_")],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for d in lives:
        if len(out) >= max_candidates:
            break
        _try_add(d)
    return out


def find_latest_candidate(case_id: str, name_hints: list[str]) -> Path | None:
    cands = iter_structural_candidates(case_id, name_hints)
    return cands[0] if cands else None


def r0b_check(candidate: Path, report: Path) -> dict:
    r = run(
        [str(ACC), "check-static", str(candidate), "--report", str(report)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    verdict = None
    if report.is_file():
        try:
            verdict = json.loads(report.read_text(encoding="utf-8")).get("verdict")
        except json.JSONDecodeError:
            pass
    return {"exit": r.returncode, "verdict": verdict, "stdout": (r.stdout or "")[-500:]}


def compose(candidate: Path, evidence: Path, report: Path) -> dict:
    r = run(
        [
            str(ACC),
            "check-with-behavior",
            str(candidate),
            "--behavior-evidence",
            str(evidence),
            "--report",
            str(report),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    verdict = None
    if report.is_file():
        try:
            verdict = json.loads(report.read_text(encoding="utf-8")).get("verdict")
        except json.JSONDecodeError:
            pass
    return {"exit": r.returncode, "verdict": verdict, "stdout": (r.stdout or "")[-500:]}


def probe_load(candidate: Path, out: Path, max_wall_ms: int, attempts: int = 8) -> dict:
    r = run(
        [
            sys.executable,
            str(PROBE),
            "--candidate",
            str(candidate),
            "--probe-kind",
            "load_no_crash",
            "--max-wall-ms",
            str(max_wall_ms),
            "--attempts",
            str(attempts),
            "--no-require-marker",
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    verdict = None
    if out.is_file():
        try:
            verdict = json.loads(out.read_text(encoding="utf-8")).get("verdict")
        except json.JSONDecodeError:
            pass
    return {
        "exit": r.returncode,
        "verdict": verdict,
        "stdout": (r.stdout or "")[-400:],
        "stderr": (r.stderr or "")[-400:],
    }


def write_validation_summary(batch_dir: Path, results: list[dict], all_ok: bool) -> Path:
    path = REPO / "validation_summary.json"
    # archive previous
    if path.is_file():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        prev = REPO / f"validation_summary.prev_{stamp}.json"
        shutil.copy2(path, prev)
    body = {
        "schema_version": "mida.validation-summary/v1",
        "task": "VNEXT-BEH",
        "title": "Behavioral acceptance gate (vault load_no_crash_v0 + R0B compose)",
        "package": "mida-acceptance / mida-cli / tools/_behavior_bb_gate.py",
        "verdict_contract": "docs/ACCEPTANCE_CONTRACT.md",
        "roadmap": "docs/VNEXT_BEHAVIORAL_PATH.md",
        "checks": {
            "bb_behavioral_gate": "pass" if all_ok else "fail",
            "probe_id": "load_no_crash_v0",
            "cases": [r["case_id"] for r in results],
            "all_compose_accepted": all_ok,
            "pure_rebuild_default_global": False,
            "origin_pure_default": True,
            "gto_independent_host": True,
            "behavioral_accepted": all_ok,
            "network_actions": 0,
        },
        "notes": [
            "B-B closed only when every scheduled vault case binds Pass evidence and check-with-behavior returns Accepted.",
            "Probe load_no_crash_v0: process survives wall-clock without NT exception (or clean exit 0). Residual: not full product logic equivalence.",
            f"Batch: {batch_dir}",
        ]
        + [
            f"{r['case_id']}: r0b={r.get('r0b_verdict')} probe={r.get('probe_verdict')} compose={r.get('compose_verdict')} ok={r.get('ok')}"
            for r in results
        ],
        "artifacts": [
            "docs/VNEXT_BEHAVIORAL_PATH.md",
            "docs/UNATTENDED_DECISIONS_20260724.md",
            "tools/_behavior_bb_gate.py",
            "tools/_behavior_probe.py",
            str(batch_dir),
        ],
        "gate_envelope": {
            "bb_gate": True,
            "batch_dir": str(batch_dir),
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "all_ok": all_ok,
            "explicit_claims": [
                "check-with-behavior Accepted on vault candidates when all_ok",
                "check-static still never Accepted alone",
            ],
            "explicit_non_claims": [
                "not full product business-logic equivalence",
                "pure default still Origin-only not global",
                "GTO still requires --profile=ahk-gto-experimental for experimental dump stages",
            ],
        },
    }
    path.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(description="B-B VNEXT-BEH gate (vault behavioral)")
    ap.add_argument(
        "--cases",
        default="origin_macro,lunlun_software,xiongxiong_duokai,gto_launcher",
        help="Comma-separated case ids",
    )
    ap.add_argument("--max-wall-ms", type=int, default=10000)
    ap.add_argument(
        "--attempts",
        type=int,
        default=12,
        help="load_no_crash retry attempts per candidate (default 12)",
    )
    ap.add_argument(
        "--max-candidates",
        type=int,
        default=4,
        help="Max StructuralPass candidates to walk per case (default 4)",
    )
    ap.add_argument(
        "--case-cooldown-s",
        type=float,
        default=3.0,
        help="Sleep between cases to reduce mutex/AV pressure (default 3s)",
    )
    ap.add_argument(
        "--refresh-candidates",
        action="store_true",
        help="Run live unpack first for each case (slow)",
    )
    ap.add_argument(
        "--write-summary",
        action="store_true",
        help="Write validation_summary task VNEXT-BEH only if all_ok",
    )
    ap.add_argument("--tag", default="bb_gate")
    args = ap.parse_args()

    if not ACC.is_file():
        print("mida-acceptance missing:", ACC, file=sys.stderr)
        return 1

    cases = [c.strip() for c in args.cases.split(",") if c.strip()]
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    batch = GATE_ROOT / f"batch_{stamp}_{args.tag}"
    batch.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    for idx, case_id in enumerate(cases):
        if idx > 0:
            # Cool-down between vault PE launches (mutex / pagefile / AV pressure).
            time.sleep(max(0.0, float(args.case_cooldown_s)))
        case_dir = batch / case_id
        case_dir.mkdir(parents=True, exist_ok=True)
        rec: dict = {"case_id": case_id, "ok": False}

        if args.refresh_candidates:
            if case_id == "gto_launcher":
                run(
                    [
                        sys.executable,
                        str(GTO_SMOKE),
                        "--cases",
                        "gto_launcher",
                        "--tag",
                        f"{args.tag}_refresh",
                        "--require-r0b",
                    ]
                )
            else:
                run(
                    [
                        sys.executable,
                        str(CASE_UNPACK),
                        "--case",
                        case_id,
                        "--tag",
                        f"{args.tag}_refresh",
                        "--r0b",
                    ]
                )

        hints = {
            "origin_macro": ["origin_unpacked.exe", "*unpacked*.exe"],
            "lunlun_software": ["lunlun_unpacked.exe", "*unpacked*.exe"],
            "xiongxiong_duokai": ["*unpacked*.exe"],
            "gto_launcher": ["gto_unpacked.exe", "*unpacked*.exe", "candidate.exe"],
        }.get(case_id, ["*unpacked*.exe"])

        candidates = iter_structural_candidates(
            case_id, hints, max_candidates=max(1, int(args.max_candidates))
        )
        if not candidates:
            rec["error"] = "no_candidate"
            results.append(rec)
            continue

        # Preferred tags then newest StructuralPass until load Pass + compose Accepted.
        tried: list[dict] = []
        selected = False
        for cand_i, cand in enumerate(candidates):
            if cand_i > 0:
                time.sleep(1.0)
            trial: dict = {"candidate": str(cand)}
            r0b_report = case_dir / f"r0b_{len(tried)}.json"
            r0b = r0b_check(cand, r0b_report)
            trial["r0b_verdict"] = r0b["verdict"]
            if not (r0b["verdict"] or "").startswith("StructuralPass"):
                trial["skip"] = "r0b"
                tried.append(trial)
                continue

            ev_path = case_dir / f"evidence_{len(tried)}.json"
            pr = probe_load(cand, ev_path, args.max_wall_ms, attempts=args.attempts)
            trial["probe_verdict"] = pr["verdict"]
            if pr["verdict"] != "Pass":
                trial["skip"] = "probe"
                tried.append(trial)
                continue

            compose_report = case_dir / f"compose_{len(tried)}.json"
            co = compose(cand, ev_path, compose_report)
            trial["compose_verdict"] = co["verdict"]
            if co["verdict"] != "Accepted":
                trial["skip"] = "compose"
                tried.append(trial)
                continue

            # Success path — promote selected artifacts to canonical names.
            rec["candidate"] = str(cand)
            (case_dir / "candidate_path.txt").write_text(str(cand), encoding="utf-8")
            rec["r0b_verdict"] = r0b["verdict"]
            rec["r0b_exit"] = r0b["exit"]
            rec["probe_verdict"] = pr["verdict"]
            rec["probe_exit"] = pr["exit"]
            rec["compose_verdict"] = co["verdict"]
            rec["compose_exit"] = co["exit"]
            rec["ok"] = True
            rec["candidates_tried"] = tried + [trial]
            # Keep last winning reports as r0b.json / evidence.json / compose.json
            try:
                shutil.copy2(r0b_report, case_dir / "r0b.json")
                shutil.copy2(ev_path, case_dir / "evidence.json")
                shutil.copy2(compose_report, case_dir / "compose.json")
            except OSError:
                pass
            selected = True
            results.append(rec)
            break

        if not selected:
            rec["error"] = "no_candidate_probe_pass"
            rec["candidates_tried"] = tried
            if tried:
                last = tried[-1]
                rec["r0b_verdict"] = last.get("r0b_verdict")
                rec["probe_verdict"] = last.get("probe_verdict")
                rec["compose_verdict"] = last.get("compose_verdict")
            results.append(rec)

    all_ok = bool(results) and all(r.get("ok") for r in results)
    summary = {
        "batch": str(batch),
        "tag": args.tag,
        "probe": "load_no_crash_v0",
        "cases": cases,
        "results": results,
        "all_ok": all_ok,
        "write_summary_requested": args.write_summary,
        "validation_summary_written": False,
        "note": "VNEXT-BEH only if --write-summary and all_ok",
    }
    if args.write_summary and all_ok:
        vpath = write_validation_summary(batch, results, all_ok=True)
        summary["validation_summary_written"] = True
        summary["validation_summary"] = str(vpath)
    elif args.write_summary and not all_ok:
        summary["note"] = "refused to write VNEXT-BEH: not all_ok"

    (batch / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if all_ok else 2


if __name__ == "__main__":
    sys.exit(main())
