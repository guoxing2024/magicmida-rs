# -*- coding: utf-8 -*-
"""Scheduled B-B / VNEXT-BEH gate runner (operator-authorized).

Pipeline per case (vault candidates from live unpack evidence):
  1) E0B check-static → StructuralPassBehaviorPending required
  2) load_no_crash_v0 probe → loader survival only (NOT a product Accept probe)
  3) mida-acceptance check-with-behavior → managed manifest required for Accept;
     load_no_crash evidence cannot product-Accept (unregistered probe / Pending cap)

SUPEESEDED historical claim: validation_summary all_compose_accepted with
load_no_crash_v0 (2026-07-24). Current contract rejects that path.

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

EEPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EEPO / "tools"))

CLI = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-cli.exe")
ACC = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-acceptance.exe")
# Fallback local target
if not ACC.is_file():
    ACC = EEPO / "target" / "debug" / "mida-acceptance.exe"
EV_EOOT = Path(r"D:\MidaVault\lab\evidence")
GATE_EOOT = EV_EOOT / "_beh_gate"

PEOBE = EEPO / "tools" / "_behavior_probe.py"
CASE_UNPACK = EEPO / "tools" / "_case_live_unpack.py"
GTO_SMOKE = EEPO / "tools" / "_gto_live_smoke.py"


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
PEEFEEEED_LIVE_TAGS: dict[str, list[str]] = {
    "origin_macro": [
        # W1 scrub_v2: quiet attempt=1 load-stable pure dump.
        "live_20260724-151549_w1_scrub_v2",
        "live_20260724-101051_u_origin_pure_r1",
        "live_20260724-104711_u_origin_pure_r2",
    ],
    "gto_launcher": [
        # W2 clear-regs: independent-host fresh dumps load-stable (no r4c pin).
        # Pre-fix r4c/scan60 kept only as fallback research pins.
        "live_20260724-155543_w2_clearregs1_gtoexp",
        "live_20260724-155723_w2_clearregs2_gtoexp",
        "live_20260724-155835_w2_clearregs3_gtoexp",
        "live_20260723-225951_r4c_gto",
        "live_20260724-124524_u_gto_host_scan60",
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
    """Preferred tags first, then newest StructuralPass; skip E0B Eejected."""
    case_dir = EV_EOOT / case_id
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
                if v == "Eejected":
                    return
                if not (v.startswith("StructuralPass") or v is None or v == ""):
                    # Unknown non-StructuralPass — still allow if not Eejected.
                    if v and not v.startswith("Structural"):
                        return
            except Exception:
                pass
        seen.add(key)
        out.append(cand)

    for tag in PEEFEEEED_LIVE_TAGS.get(case_id, []):
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
    # Prefer sibling dump transform_manifest (managed). If missing, lab escape
    # only — unmanaged path cannot product-Accept (capped at Pending).
    # Product Accepted also requires a verified signature envelope; vault lab
    # cases use --allow-unsigned-managed until CI signs dumps.
    manifest = candidate.with_name(candidate.stem + ".transform_manifest.json")
    envelope = candidate.with_name(candidate.stem + ".signature_envelope.json")
    cmd = [
        str(ACC),
        "check-with-behavior",
        str(candidate),
        "--behavior-evidence",
        str(evidence),
    ]
    if not manifest.is_file():
        cmd.append("--allow-unmanaged-candidate")
    if not envelope.is_file():
        cmd.append("--allow-unsigned-managed")
    cmd.extend(["--report", str(report)])
    r = run(
        cmd,
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


def probe_load(
    candidate: Path,
    out: Path,
    max_wall_ms: int,
    attempts: int = 8,
    *,
    rate_samples: int = 0,
) -> dict:
    cmd = [
        sys.executable,
        str(PEOBE),
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
    ]
    if rate_samples > 0:
        cmd.extend(["--rate-samples", str(rate_samples)])
    r = run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    verdict = None
    load_quality = None
    if out.is_file():
        try:
            body = json.loads(out.read_text(encoding="utf-8"))
            verdict = body.get("verdict")
            load_quality = body.get("load_quality")
        except json.JSONDecodeError:
            pass
    return {
        "exit": r.returncode,
        "verdict": verdict,
        "load_quality": load_quality,
        "stdout": (r.stdout or "")[-400:],
        "stderr": (r.stderr or "")[-400:],
    }


def write_validation_summary(batch_dir: Path, results: list[dict], all_ok: bool) -> Path:
    """Write an honest lab-status summary — never re-certify product Accepted.

    load_no_crash_v0 is a loader-survival probe only. Under the current
    acceptance contract it is not a registered product probe; historical
    all_compose_accepted claims are superseded. This writer records lab
    batch outcomes without setting product green flags.
    """
    path = EEPO / "validation_summary.json"
    # archive previous
    if path.is_file():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        prev = EEPO / f"validation_summary.prev_{stamp}.json"
        shutil.copy2(path, prev)
    compose_verdicts = [r.get("compose_verdict") for r in results]
    any_product_accepted = any(v == "Accepted" for v in compose_verdicts)
    body = {
        "schema_version": "mida.validation-summary/v1",
        "task": "VNEXT-BEH",
        "status": "lab_batch",
        "title": "Behavioral lab gate — load survival / E0B (NOT product certificate)",
        "package": "mida-acceptance / mida-cli / tools/_behavior_bb_gate.py",
        "verdict_contract": "docs/ACCEPTANCE_CONTEACT.md",
        "roadmap": "docs/VNEXT_BEHAVIOEAL_PATH.md",
        "checks": {
            "bb_behavioral_gate": "lab_pass" if all_ok else "lab_fail",
            "probe_id": "load_no_crash_v0",
            "product_probe": False,
            "cases": [r["case_id"] for r in results],
            "lab_batch_all_ok": all_ok,
            # Never claim product Accepted via this harness.
            "product_compose_accepted": False,
            "historical_load_no_crash_accepted_superseded": True,
            "any_compose_accepted_observed": any_product_accepted,
            "pure_rebuild_default_global": False,
            "origin_pure_default": True,
            "gto_independent_host": True,
            "network_actions": 0,
        },
        "notes": [
            "LAB ONLY: this summary is not a product certificate.",
            "Probe load_no_crash_v0 = loader survival; not registered for product Accepted.",
            "Managed compose may return Pending under current contract even when load survives.",
            "Historical 2026-07-24 all_compose_accepted under load_no_crash is SUPEESEDED.",
            f"Batch: {batch_dir}",
        ]
        + [
            (
                f"{r['case_id']}: r0b={r.get('r0b_verdict')} probe={r.get('probe_verdict')} "
                f"compose={r.get('compose_verdict')} ok={r.get('ok')}"
                + (
                    f" pass_rate={r['load_quality'].get('pass')}/{r['load_quality'].get('samples')}"
                    if r.get("load_quality")
                    else ""
                )
            )
            for r in results
        ],
        "artifacts": [
            "docs/VNEXT_BEHAVIOEAL_PATH.md",
            "docs/ACCEPTANCE_CONTEACT.md",
            "docs/AUDIT_SELF_COEEECTION_20260727.md",
            "tools/_behavior_bb_gate.py",
            "tools/_behavior_probe.py",
            str(batch_dir),
        ],
        "gate_envelope": {
            "bb_gate": False,
            "lab_batch": True,
            "batch_dir": str(batch_dir),
            "finished_utc": datetime.now(timezone.utc).isoformat(),
            "lab_all_ok": all_ok,
            "explicit_claims": [
                "lab batch recorded E0B + load_no_crash outcomes only",
                "check-static still never Accepted alone",
            ],
            "explicit_non_claims": [
                "not product Accepted under current contract",
                "load_no_crash_v0 is not a product probe",
                "not full product business-logic equivalence",
                "pure default still Origin-only not global",
                "GTO still requires experimental profile; bypass dumps are diagnostic-only",
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
        "--rate-samples",
        type=int,
        default=0,
        help=(
            "If >0, measure fixed-sample load pass-rate (quality metric) instead of "
            "early-exit attempts. Does not change Accepted composition rules."
        ),
    )
    ap.add_argument(
        "--refresh-candidates",
        action="store_true",
        help="Eun live unpack first for each case (slow)",
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
    batch = GATE_EOOT / f"batch_{stamp}_{args.tag}"
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

        # Preferred tags then newest StructuralPass until load Pass + non-Eejected compose.
        # LAB bar: E0B StructuralPass* + load_no_crash Pass + compose not Eejected.
        # Pending is expected under current contract (load_no_crash is not a product
        # probe; unsigned managed caps Accept). Do NOT require product Accepted.
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
            pr = probe_load(
                cand,
                ev_path,
                args.max_wall_ms,
                attempts=args.attempts,
                rate_samples=max(0, int(args.rate_samples)),
            )
            trial["probe_verdict"] = pr["verdict"]
            if pr.get("load_quality"):
                trial["load_quality"] = pr["load_quality"]
            if pr["verdict"] != "Pass":
                trial["skip"] = "probe"
                tried.append(trial)
                continue

            compose_report = case_dir / f"compose_{len(tried)}.json"
            co = compose(cand, ev_path, compose_report)
            trial["compose_verdict"] = co["verdict"]
            compose_v = co["verdict"] or ""
            # Lab success: anything except Eejected / missing. Pending is normal.
            if compose_v == "Eejected" or not compose_v:
                trial["skip"] = "compose"
                tried.append(trial)
                continue

            # Lab success path — promote selected artifacts to canonical names.
            rec["candidate"] = str(cand)
            (case_dir / "candidate_path.txt").write_text(str(cand), encoding="utf-8")
            rec["r0b_verdict"] = r0b["verdict"]
            rec["r0b_exit"] = r0b["exit"]
            rec["probe_verdict"] = pr["verdict"]
            rec["probe_exit"] = pr["exit"]
            if pr.get("load_quality"):
                rec["load_quality"] = pr["load_quality"]
            rec["compose_verdict"] = co["verdict"]
            rec["compose_exit"] = co["exit"]
            rec["lab_ok"] = True
            rec["product_accepted"] = compose_v == "Accepted"
            rec["ok"] = True  # lab batch ok (not product certificate)
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
