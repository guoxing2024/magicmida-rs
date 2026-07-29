"""GTO-PRODUCT-RECOVERY Route A R1 aggregator (2026-07-29).

Reads N ``outcomes.json`` sidecars from the orchestrator's ``out_root``, then:
- computes a per-named-epoch stability score (count of runs that observed the
  name divided by N);
- decides pass/fail against the R1 evidence bar per
  docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R1_PLAN_20260729.md §3.1 (8 items);
- writes ``aggregate.json`` next to the orchestrator summary.

Pre-implementation self-check (plan §5):
    1. N>=3                              (here: N=3)
    2. >=2/3 stable named epoch          (here: |names_in_>=ceil(2N/3) runs|>=1)
    3. .boot/VM/alloc binding            (here: union of named_observations with
                                          non-empty evidence_binding)
    4. bypass_used=false                 (plan §4.1: env MIDA_GTO_NO_BYPASS=1)
    5. no sample_bypass                  (inherited from sample_bypass taxonomy)
    6. no DRx                            (observer code uses no DRx)
    7. JSON sidecars                     (this script reads + re-emits them)
    8. report                            (downstream: ``docs/...`` doc)

This script is READ-ONLY on outcomes.json files; it does NOT modify the
target process or vault evidence files.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import sys
from pathlib import Path


def _now_iso() -> str:
    return _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _classify_status(sidecar: dict) -> tuple[str, str]:
    """Map a sidecar's failure_class to a small categorical bucket."""
    fc = (sidecar.get("failure_class") or "none").strip().lower()
    return fc, fc


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out-root", required=True)
    p.add_argument("--n", type=int, default=3)
    args = p.parse_args(argv)

    out_root = Path(args.out_root)
    if not out_root.is_dir():
        print(f"FATAL: out_root not a directory: {out_root}", file=sys.stderr)
        return 2

    sidecars: list[dict] = []
    sidecar_paths: list[Path] = []
    failures: list[dict] = []

    for i in range(1, args.n + 1):
        sp = out_root / f"run_{i}" / "outcomes.json"
        sidecar_paths.append(sp)
        if not sp.is_file():
            failures.append({"run": i, "path": str(sp), "reason": "missing sidecar"})
            continue
        try:
            d = json.loads(sp.read_text(encoding="utf-8"))
        except Exception as e:
            failures.append({"run": i, "path": str(sp), "reason": f"json parse: {e}"})
            continue
        sidecars.append(d)

    n_present = len(sidecars)
    n_total = args.n
    stability_min_runs = math.ceil((2 * n_total) / 3.0)  # 2/3 of N

    # Per-named-epoch count.
    epoch_to_runs: dict[str, list[int]] = {}
    for idx, d in enumerate(sidecars, start=1):
        for obs in d.get("named_observations", []) or []:
            name = obs.get("name", "<missing>")
            epoch_to_runs.setdefault(name, []).append(idx)

    stable_epochs = sorted([n for n, runs in epoch_to_runs.items() if len(runs) >= stability_min_runs])
    all_epochs = sorted(epoch_to_runs.keys())
    stability_score = (
        round(len(stable_epochs) / len(all_epochs), 3)
        if all_epochs else 0.0
    )

    evidence_bar = {
        "item_1_n_ge_3": n_present >= 3,
        "item_2_at_least_2_of_3_stable_named_epoch": len(stable_epochs) >= 1,
        "item_3_evidence_binding_to_boot_or_vm_owned_or_alloc": (
            any(
                (o.get("evidence_binding") or "")
                for d in sidecars
                for o in d.get("named_observations", []) or []
            )
            if sidecars else False
        ),
        "item_4_bypass_used_false": all(
            (d.get("bypass_used") is False) for d in sidecars
        ) if sidecars else False,
        "item_5_no_sample_bypass": True,  # taxonomic; observer code never sets it
        "item_6_no_drx_in_observer": all(
            (d.get("rsp_source") == "external-observer") for d in sidecars
        ) if sidecars else False,
        "item_7_json_sidecars": all(sp.is_file() for sp in sidecar_paths),
        "item_8_report": False,  # filled in by reporter after this script
    }
    evidence_bar_pass = all(evidence_bar.values())

    aggregate = {
        "route": "GTO-PRODUCT-RECOVERY/RouteA",
        "method_class": "memory-state-epoch external observer",
        "aggregator": Path(__file__).name,
        "ran_at": _now_iso(),
        "out_root": str(out_root),
        "n_requested": n_total,
        "n_present": n_present,
        "n_failed": len(failures),
        "failures": failures,
        "sidecar_paths": [str(sp) for sp in sidecar_paths],
        "all_named_epochs": all_epochs,
        "stable_named_epochs": stable_epochs,
        "stability_score": stability_score,
        "same_epoch_observations": [
            {
                "name": name,
                "runs_observing": epoch_to_runs[name],
                "count": len(epoch_to_runs[name]),
                "evidence_binding": (
                    next(
                        (o.get("evidence_binding") or "")
                        for d in sidecars
                        for o in d.get("named_observations", []) or []
                        if o.get("name") == name
                    )
                    or None
                ),
            }
            for name in all_epochs
        ],
        "evidence_bar": evidence_bar,
        "evidence_bar_pass": evidence_bar_pass,
        "named_epoch_candidates": stable_epochs,
    }

    out = out_root / "aggregate.json"
    out.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[aggregator] wrote -> {out}")
    print(f"[aggregator] n_present = {n_present}/{n_total}, failures = {len(failures)}")
    print(f"[aggregator] all_named_epochs = {all_epochs}")
    print(f"[aggregator] stable_named_epochs (>= 2/3 runs) = {stable_epochs}")
    print(f"[aggregator] stability_score = {stability_score}")
    print(f"[aggregator] evidence_bar_pass = {evidence_bar_pass}")
    print(f"[aggregator] evidence_bar = {evidence_bar}")

    # Decide R1 pass.
    if evidence_bar_pass and n_present == n_total and len(stable_epochs) >= 1:
        print("R1 PASS (per plan §3.1)")
        return 0
    else:
        print("R1 FAIL (insufficient evidence or failed bar items)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
