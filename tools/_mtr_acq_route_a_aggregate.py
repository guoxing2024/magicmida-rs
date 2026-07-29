"""GTO-PRODUCT-RECOVERY Route A aggregator (R1/R2).

Reads N ``outcomes.json`` sidecars and:
- groups primary-anchor candidates into stable families (size + checksum + lifetime)
- decides pass/fail against the round evidence bar
- writes ``aggregate.json``

R2 evidence bar (authorization 2026-07-30):
  1. N>=5 present
  2. >=3/5 reproduce R1 primary anchor as stable candidate family
     (MEM_PRIVATE + executable RX/RWX-class + size>1MiB)
  3. family identity strengthened by >=2 independent dimensions
     (size / checksum / lifetime / neighborhood / protection)
  4. bypass_used=false all runs
  5. drx_used=false / veh_used=false / injection_used=false all runs
  6. JSON sidecars + aggregate present
  7. (Origin Phase C only if shared dumper touched — R2 does not)
  8. report (filled after report filed; machine starts false)

This script is READ-ONLY on outcomes.json; it does NOT modify the target
process or vault evidence beyond writing aggregate.json under out_root.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sha256_file(p: Path) -> str | None:
    if not p.is_file():
        return None
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _is_primary_candidate(c: dict) -> bool:
    """R1 primary anchor: MEM_PRIVATE + executable class + size > 1MiB + not image."""
    size = int(c.get("size") or 0)
    protect = int(c.get("protect") or 0)
    state = int(c.get("state") or 0)
    ty = int(c.get("type") or 0)
    image_backed = bool(c.get("image_backed"))
    exec_priv = c.get("executable_private")
    # PAGE_EXECUTE_READ=0x20, PAGE_EXECUTE_READWRITE=0x40, PAGE_EXECUTE_WRITECOPY=0x80
    is_exec = protect in (0x20, 0x40, 0x80) or bool(exec_priv)
    # MEM_PRIVATE=0x20000, MEM_COMMIT=0x1000
    is_private = ty == 0x20000
    is_commit = state == 0x1000
    return (
        size > 0x100000
        and is_exec
        and is_private
        and is_commit
        and not image_backed
    )


def _family_key(c: dict) -> str:
    """Bucket by size class + 4k checksum prefix (first 16 hex of multi or 4k)."""
    size = int(c.get("size") or 0)
    # Quantize size to 64 KiB buckets so minor drift still clusters.
    size_bucket = (size // 0x10000) * 0x10000
    c4 = (c.get("checksum_4k") or "")[:16]
    cmp_ = (c.get("checksum_multi_page") or "")[:16]
    # Prefer multi-page when present.
    fp = cmp_ or c4 or "nofp"
    return f"sz0x{size_bucket:x}|fp{fp}"


def _identity_dimensions(members: list[dict]) -> dict:
    """Count which identity dimensions are stable across family members."""
    if not members:
        return {
            "size_stability": False,
            "checksum_similarity": False,
            "lifetime_tick_pattern": False,
            "allocation_neighborhood": False,
            "protection_evolution": False,
            "independent_count": 0,
            "details": {},
        }

    sizes = [int(m.get("size") or 0) for m in members]
    size_ok = (max(sizes) - min(sizes)) <= 0x10000  # within 64 KiB

    c4s = [(m.get("checksum_4k") or "")[:16] for m in members]
    cmps = [(m.get("checksum_multi_page") or "")[:16] for m in members]
    # Similarity: majority share same non-empty fingerprint.
    def majority_same(vals: list[str]) -> bool:
        vals = [v for v in vals if v]
        if not vals:
            return False
        counts: dict[str, int] = defaultdict(int)
        for v in vals:
            counts[v] += 1
        return max(counts.values()) >= max(2, math.ceil(len(vals) * 0.6))

    checksum_ok = majority_same(cmps) or majority_same(c4s)

    ticks = [int(m.get("tick_count_seen") or 0) for m in members]
    # Lifetime pattern: all seen for a substantial fraction of window, low CV.
    if ticks and min(ticks) >= 10:
        mean = sum(ticks) / len(ticks)
        if mean > 0:
            var = sum((t - mean) ** 2 for t in ticks) / len(ticks)
            cv = (var ** 0.5) / mean
            lifetime_ok = cv <= 0.35
        else:
            lifetime_ok = False
    else:
        lifetime_ok = False

    # Neighborhood: non-empty summaries that share a common private-neighbor signal.
    neigh = [m.get("neighborhood_summary") or "" for m in members]
    neigh_ok = all("private=" in n for n in neigh) and len(neigh) >= 2

    protects = [int(m.get("protect") or 0) for m in members]
    # Protection evolution / stability: all same protect class counts as a dimension.
    protect_ok = len(set(protects)) == 1 and protects[0] in (0x20, 0x40, 0x80)

    dims = {
        "size_stability": size_ok,
        "checksum_similarity": checksum_ok,
        "lifetime_tick_pattern": lifetime_ok,
        "allocation_neighborhood": neigh_ok,
        "protection_evolution": protect_ok,
    }
    independent = sum(1 for v in dims.values() if v)
    return {
        **dims,
        "independent_count": independent,
        "details": {
            "sizes": sizes,
            "protects": protects,
            "tick_counts": ticks,
            "checksum_4k_prefixes": c4s,
            "checksum_multi_prefixes": cmps,
        },
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out-root", required=True)
    p.add_argument("--n", type=int, default=5)
    p.add_argument("--round", default="R2")
    args = p.parse_args(argv)

    out_root = Path(args.out_root)
    if not out_root.is_dir():
        print(f"FATAL: out_root not a directory: {out_root}", file=sys.stderr)
        return 2

    sidecars: list[dict] = []
    sidecar_paths: list[Path] = []
    sidecar_hashes: list[str | None] = []
    failures: list[dict] = []

    for i in range(1, args.n + 1):
        sp = out_root / f"run_{i}" / "outcomes.json"
        sidecar_paths.append(sp)
        if not sp.is_file():
            failures.append({"run": i, "path": str(sp), "reason": "missing sidecar"})
            sidecar_hashes.append(None)
            continue
        try:
            d = json.loads(sp.read_text(encoding="utf-8"))
        except Exception as e:
            failures.append({"run": i, "path": str(sp), "reason": f"json parse: {e}"})
            sidecar_hashes.append(None)
            continue
        sidecars.append(d)
        sidecar_hashes.append(_sha256_file(sp))

    n_present = len(sidecars)
    n_total = args.n
    is_r2 = args.round.upper() == "R2"
    # R2: need family in >=3/5 runs. R1 kept 2/3 named-epoch rule as fallback.
    min_family_runs = 3 if is_r2 else math.ceil((2 * n_total) / 3.0)

    # Collect primary candidates per run.
    family_to_runs: dict[str, list[int]] = defaultdict(list)
    family_to_members: dict[str, list[dict]] = defaultdict(list)
    per_run_primary: list[dict] = []

    for idx, d in enumerate(sidecars, start=1):
        cands = d.get("candidate_regions") or []
        primaries = [c for c in cands if _is_primary_candidate(c)]
        # Fallback: if observer pre-R2 (no candidate_regions), synthesize from named + vm_owned.
        if not primaries and not cands:
            for r in d.get("vm_owned_region_candidates") or []:
                synth = {
                    "base": r.get("base"),
                    "size": r.get("size"),
                    "protect": r.get("protect"),
                    "state": r.get("state"),
                    "type": r.get("type"),
                    "checksum_4k": "",
                    "checksum_multi_page": None,
                    "tick_count_seen": 1,
                    "executable_private": True,
                    "image_backed": bool(r.get("is_pe_image")),
                    "neighborhood_summary": "",
                }
                if _is_primary_candidate(synth):
                    primaries.append(synth)
        per_run_primary.append({
            "run": idx,
            "primary_count": len(primaries),
            "bases": [c.get("base") for c in primaries[:5]],
            "sizes": [c.get("size") for c in primaries[:5]],
        })
        # One family membership per run (best primary by tick_count then size).
        if primaries:
            best = sorted(
                primaries,
                key=lambda c: (int(c.get("tick_count_seen") or 0), int(c.get("size") or 0)),
                reverse=True,
            )[0]
            key = _family_key(best)
            if idx not in family_to_runs[key]:
                family_to_runs[key].append(idx)
            family_to_members[key].append({**best, "_run": idx})

    stable_families = []
    for key, runs in family_to_runs.items():
        if len(runs) >= min_family_runs:
            dims = _identity_dimensions(family_to_members[key])
            stable_families.append({
                "family_key": key,
                "runs_observing": runs,
                "reproduction_count": len(runs),
                "identity_dimensions": dims,
                "sample_member": {
                    k: family_to_members[key][0].get(k)
                    for k in (
                        "base", "size", "protect", "protect_name", "state", "type",
                        "checksum_4k", "checksum_multi_page", "tick_count_seen",
                        "first_seen_tick", "last_seen_tick", "neighborhood_summary",
                        "executable_private", "image_backed", "size_class",
                    )
                },
            })

    # Rank families by reproduction then identity strength.
    stable_families.sort(
        key=lambda f: (
            f["reproduction_count"],
            f["identity_dimensions"]["independent_count"],
        ),
        reverse=True,
    )

    best_family = stable_families[0] if stable_families else None
    best_dims = (best_family or {}).get("identity_dimensions") or {"independent_count": 0}
    reproduction_count = (best_family or {}).get("reproduction_count", 0)

    # Discipline flags across all present sidecars.
    def all_false(field: str) -> bool:
        return all((d.get(field) is False) for d in sidecars) if sidecars else False

    def all_eq(field: str, value) -> bool:
        return all((d.get(field) == value) for d in sidecars) if sidecars else False

    evidence_bar = {
        "item_1_n_ge_required": n_present >= (5 if is_r2 else 3),
        "item_2_family_reproduced": reproduction_count >= min_family_runs,
        "item_3_identity_ge_2_dims": best_dims.get("independent_count", 0) >= 2,
        "item_4_bypass_used_false": all_false("bypass_used"),
        "item_5_no_drx_veh_injection": (
            all_false("drx_used")
            and all_false("veh_used")
            and all_false("injection_used")
            and all_eq("rsp_source", "external-observer")
        ) if sidecars else False,
        "item_6_json_sidecars": all(sp.is_file() for sp in sidecar_paths),
        "item_7_shared_dumper_untouched_or_phase_c": True,  # R2 does not touch shared dumper
        "item_8_report": False,  # filled after human report
    }
    # R1 compatibility: also surface named-epoch stability.
    epoch_to_runs: dict[str, list[int]] = defaultdict(list)
    for idx, d in enumerate(sidecars, start=1):
        for obs in d.get("named_observations") or []:
            epoch_to_runs[obs.get("name", "<missing>")].append(idx)
    stable_epochs = sorted(
        n for n, runs in epoch_to_runs.items() if len(runs) >= min_family_runs
    )

    evidence_bar_pass = all(evidence_bar.values())
    fail_reasons = [k for k, v in evidence_bar.items() if not v]

    aggregate = {
        "route": "GTO-PRODUCT-RECOVERY/RouteA",
        "round": args.round,
        "method_class": "memory-state-epoch external observer",
        "aggregator": Path(__file__).name,
        "ran_at": _now_iso(),
        "out_root": str(out_root),
        "n_requested": n_total,
        "n_present": n_present,
        "n_failed": len(failures),
        "failures": failures,
        "sidecar_paths": [str(sp) for sp in sidecar_paths],
        "sidecar_hashes": sidecar_hashes,
        "per_run_primary": per_run_primary,
        "stable_candidate_families": stable_families,
        "reproduction_count": reproduction_count,
        "best_family": best_family,
        "all_named_epochs": sorted(epoch_to_runs.keys()),
        "stable_named_epochs": stable_epochs,
        "evidence_bar": evidence_bar,
        "evidence_bar_pass": evidence_bar_pass,
        "fail_reasons": fail_reasons,
        "non_claims": {
            "product_1_0": False,
            "gto_perfect_unpack": False,
            "r1b_reentry": False,
            "e2": False,
            "drx": False,
            "bypass": False,
            "expansion_proven": False,
            "necessarily_rwx": False,
        },
    }

    out = out_root / "aggregate.json"
    out.write_text(json.dumps(aggregate, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[aggregator] wrote -> {out}")
    print(f"[aggregator] n_present = {n_present}/{n_total}, failures = {len(failures)}")
    print(f"[aggregator] reproduction_count (best family) = {reproduction_count}")
    print(f"[aggregator] stable_families = {len(stable_families)}")
    if best_family:
        print(f"[aggregator] best_family_key = {best_family['family_key']}")
        print(f"[aggregator] identity_dims = {best_dims}")
    print(f"[aggregator] evidence_bar_pass = {evidence_bar_pass}")
    print(f"[aggregator] evidence_bar = {evidence_bar}")
    if fail_reasons:
        print(f"[aggregator] fail_reasons = {fail_reasons}")

    label = args.round.upper()
    if evidence_bar_pass and n_present == n_total:
        print(f"{label} PASS (machine bar; report still required for item_8)")
        return 0
    # Machine cannot pass item_8; treat items 1-7 green as conditional.
    machine_core = {k: v for k, v in evidence_bar.items() if k != "item_8_report"}
    if all(machine_core.values()) and n_present == n_total:
        print(
            f"{label} CONDITIONAL MACHINE PASS (items 1-7); "
            f"item_8_report=false by design — expert acceptance after report review",
            file=sys.stderr,
        )
        return 0
    print(f"{label} FAIL (insufficient evidence or failed bar items)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
