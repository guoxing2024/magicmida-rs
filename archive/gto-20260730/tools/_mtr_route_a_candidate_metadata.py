"""GTO-PRODUCT-RECOVERY Route A — Candidate Metadata Pack M0 (2026-07-30).

Deterministic, READ-ONLY packaging of the expert-accepted Route A R2 primary
anchor candidate family from existing vault sidecars.

- Consumes 0 fix rounds.
- No live measurement, no target execution, no dump/restore/patch.
- NOT Route A R3.
- Does not rewrite vault evidence or aggregate.json.

Invocation:
  python tools/_mtr_route_a_candidate_metadata.py \\
    --out-root D:\\MidaVault\\scratch\\product_recovery_route_a_r2_n5_20260730-012013 \\
    --report-commit 2c8ebeabbcd6da55ec2359300241d5aff3c461b8 \\
    --output docs/GTO_PRODUCT_RECOVERY_ROUTE_A_CANDIDATE_METADATA_20260730.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

EXPECTED_FAMILY_KEY = "sz0x120000|fp1891a1ae5a1e8f8f"
EXPECTED_TARGET_SHA = (
    "4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8"
)
EXPECTED_OBSERVER_SHA = (
    "1217a5913d5ddde6a1ae1d23c3a0ec0a1be0b5e765581f473f080f94ba014a6d"
)
BAR_ITEMS_1_7 = [
    "item_1_n_ge_required",
    "item_2_family_reproduced",
    "item_3_identity_ge_2_dims",
    "item_4_bypass_used_false",
    "item_5_no_drx_veh_injection",
    "item_6_json_sidecars",
    "item_7_shared_dumper_untouched_or_phase_c",
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def _is_primary_member(c: dict) -> bool:
    size = int(c.get("size") or 0)
    protect = int(c.get("protect") or 0)
    state = int(c.get("state") or 0)
    ty = int(c.get("type") or 0)
    image_backed = bool(c.get("image_backed"))
    return (
        size == 1208320
        and protect == 32
        and state == 4096
        and ty == 131072
        and not image_backed
    )


def _pick_primary(sidecar: dict) -> dict:
    cands = list(sidecar.get("candidate_regions") or [])
    primaries = [c for c in cands if _is_primary_member(c)]
    _assert(primaries, "no primary candidate member matching family size/protect/type")
    primaries.sort(
        key=lambda c: (int(c.get("tick_count_seen") or 0), int(c.get("size") or 0)),
        reverse=True,
    )
    return primaries[0]


def build_pack(out_root: Path, report_commit: str) -> dict:
    agg_path = out_root / "aggregate.json"
    orch_path = out_root / "orchestrator_summary.json"
    run_paths = {i: out_root / f"run_{i}" / "outcomes.json" for i in range(1, 6)}

    for p in [agg_path, orch_path, *run_paths.values()]:
        _assert(p.is_file(), f"missing required evidence file: {p.name}")

    aggregate_sha = _sha256_file(agg_path)
    orch_sha = _sha256_file(orch_path)
    sidecar_sha = {f"run_{i}": _sha256_file(run_paths[i]) for i in range(1, 6)}

    agg = _load_json(agg_path)
    orch = _load_json(orch_path)
    sidecars = {i: _load_json(run_paths[i]) for i in range(1, 6)}

    # --- aggregate assertions ---
    _assert(agg.get("n_present") == 5, f"n_present != 5: {agg.get('n_present')}")
    _assert(agg.get("n_failed") == 0, f"n_failed != 0: {agg.get('n_failed')}")
    bar = agg.get("evidence_bar") or {}
    for k in BAR_ITEMS_1_7:
        _assert(bar.get(k) is True, f"evidence_bar.{k} is not true")
    _assert(bar.get("item_8_report") is False, "item_8_report must remain false")
    _assert(agg.get("evidence_bar_pass") is False, "evidence_bar_pass must remain false")
    fail_reasons = list(agg.get("fail_reasons") or [])
    _assert(
        fail_reasons == ["item_8_report"],
        f"fail_reasons unexpected: {fail_reasons!r}",
    )

    best = agg.get("best_family") or {}
    family_key = best.get("family_key")
    _assert(
        family_key == EXPECTED_FAMILY_KEY,
        f"best family_key mismatch: {family_key!r}",
    )
    _assert(agg.get("reproduction_count") == 5, "reproduction_count != 5")
    dims = best.get("identity_dimensions") or {}
    _assert(
        int(dims.get("independent_count") or 0) >= 5,
        f"independent_count < 5: {dims.get('independent_count')}",
    )
    for dim in (
        "size_stability",
        "checksum_similarity",
        "lifetime_tick_pattern",
        "allocation_neighborhood",
        "protection_evolution",
    ):
        _assert(dims.get(dim) is True, f"identity dim {dim} is not true")

    # --- per-sidecar discipline + primary member ---
    per_run: list[dict] = []
    checksum_4k_vals: set[str] = set()
    checksum_mp_vals: set[str] = set()
    for i in range(1, 6):
        d = sidecars[i]
        _assert(d.get("bypass_used") is False, f"run_{i} bypass_used")
        _assert(d.get("semantic_repair_used") is False, f"run_{i} semantic_repair_used")
        _assert(d.get("drx_used") is False, f"run_{i} drx_used")
        _assert(d.get("veh_used") is False, f"run_{i} veh_used")
        _assert(d.get("injection_used") is False, f"run_{i} injection_used")
        _assert(d.get("rsp_source") == "external-observer", f"run_{i} rsp_source")
        _assert(
            d.get("target_sha256") == EXPECTED_TARGET_SHA,
            f"run_{i} target_sha256 mismatch",
        )
        _assert(
            d.get("observer_sha256") == EXPECTED_OBSERVER_SHA,
            f"run_{i} observer_sha256 mismatch",
        )
        c = _pick_primary(d)
        c4 = str(c.get("checksum_4k") or "")
        cmp_ = str(c.get("checksum_multi_page") or "")
        _assert(c4, f"run_{i} missing checksum_4k")
        _assert(cmp_, f"run_{i} missing checksum_multi_page")
        checksum_4k_vals.add(c4)
        checksum_mp_vals.add(cmp_)
        base = int(c.get("base") or 0)
        per_run.append(
            {
                "run": i,
                "base": f"0x{base:x}",
                "base_note": "ASLR-only; not identity",
                "first_seen_tick": int(c.get("first_seen_tick") or 0),
                "last_seen_tick": int(c.get("last_seen_tick") or 0),
                "tick_count_seen": int(c.get("tick_count_seen") or 0),
            }
        )

    _assert(len(checksum_4k_vals) == 1, f"checksum_4k not identical: {checksum_4k_vals}")
    _assert(
        len(checksum_mp_vals) == 1,
        f"checksum_multi_page not identical: {checksum_mp_vals}",
    )
    checksum_4k = next(iter(checksum_4k_vals))
    checksum_multi_page = next(iter(checksum_mp_vals))

    sample = best.get("sample_member") or {}
    size = int(sample.get("size") or 1208320)
    protect = int(sample.get("protect") or 32)
    state = int(sample.get("state") or 4096)
    ty = int(sample.get("type") or 131072)

    # Prefer orchestrator values when present; fall back to sidecar/common constants.
    observation_window_ms = int(
        orch.get("observation_window_ms")
        or sidecars[1].get("observation_window_ms")
        or 30000
    )
    poll_period_ms = int(
        orch.get("poll_period_ms") or sidecars[1].get("poll_period_ms") or 50
    )
    target_sha = str(orch.get("target_sha256") or EXPECTED_TARGET_SHA)
    observer_sha = str(orch.get("observer_sha256") or EXPECTED_OBSERVER_SHA)
    _assert(target_sha == EXPECTED_TARGET_SHA, "orchestrator target_sha256 mismatch")
    _assert(observer_sha == EXPECTED_OBSERVER_SHA, "orchestrator observer_sha256 mismatch")

    pack = {
        "schema": "mida.gto_product_recovery.route_a.candidate_metadata/v1",
        "task": "GTO-PRODUCT-RECOVERY Route A Candidate Metadata Pack M0",
        "status": "metadata_only",
        "report_commit": report_commit,
        "source_r2_report": "docs/GTO_PRODUCT_RECOVERY_ROUTE_A_R2_20260730.md",
        "source_evidence": {
            "evidence_set_id": "product_recovery_route_a_r2_n5_20260730-012013",
            "aggregate_sha256": aggregate_sha,
            "orchestrator_summary_sha256": orch_sha,
            "sidecar_sha256": {
                "run_1": sidecar_sha["run_1"],
                "run_2": sidecar_sha["run_2"],
                "run_3": sidecar_sha["run_3"],
                "run_4": sidecar_sha["run_4"],
                "run_5": sidecar_sha["run_5"],
            },
        },
        "target": {
            "sample": "gto_launcher",
            "sha256": target_sha,
        },
        "observer": {
            "sha256": observer_sha,
            "method_class": "memory-state-epoch external observer",
            "observation_window_ms": observation_window_ms,
            "poll_period_ms": poll_period_ms,
        },
        "selected_candidate_family": {
            "family_key": family_key,
            "role": "route_a_r2_primary_anchor_candidate",
            "reproduction": {
                "runs_observing": [1, 2, 3, 4, 5],
                "count": 5,
                "requested": 5,
            },
            "memory_properties": {
                "size": size,
                "size_hex": f"0x{size:x}",
                "protect": protect,
                "protect_name": str(sample.get("protect_name") or "PAGE_EXECUTE_READ"),
                "state": state,
                "state_name": "MEM_COMMIT",
                "type": ty,
                "type_name": "MEM_PRIVATE",
                "executable_private": True,
                "image_backed": False,
            },
            "fingerprints": {
                "checksum_4k": checksum_4k,
                "checksum_multi_page": checksum_multi_page,
            },
            "identity_dimensions": {
                "size_stability": True,
                "checksum_similarity": True,
                "lifetime_tick_pattern": True,
                "allocation_neighborhood": True,
                "protection_evolution": True,
                "independent_count": int(dims.get("independent_count") or 5),
            },
            "per_run": per_run,
        },
        "expert_acceptance": {
            "r2_accepted": True,
            "accepted_on": "2026-07-30",
            "machine_item_8_report_remains_false": True,
            "aggregate_not_rewritten": True,
        },
        "non_claims": {
            "product_1_0": False,
            "gto_perfect_unpack": False,
            "r1b_reentry": False,
            "e2": False,
            "drx": False,
            "veh": False,
            "injection": False,
            "bypass": False,
            "expansion_proven": False,
            "necessarily_rwx": False,
            "boot_module_visible": False,
        },
    }
    return pack


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--out-root", required=True, help="R2 vault evidence root")
    p.add_argument("--report-commit", required=True, help="R2 accepted commit hash")
    p.add_argument(
        "--output",
        required=True,
        help="Repo-relative path for candidate metadata JSON",
    )
    args = p.parse_args(argv)

    out_root = Path(args.out_root)
    output = Path(args.output)
    if not out_root.is_dir():
        print(f"FATAL: out-root not a directory: {out_root}", file=sys.stderr)
        return 2

    try:
        pack = build_pack(out_root, args.report_commit)
    except AssertionError as e:
        print(f"ASSERT FAIL: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"FATAL: {e}", file=sys.stderr)
        return 2

    text = json.dumps(pack, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(text, encoding="utf-8")
    print(f"[metadata] wrote -> {output}")
    print(f"[metadata] family_key = {pack['selected_candidate_family']['family_key']}")
    print(
        f"[metadata] reproduction = "
        f"{pack['selected_candidate_family']['reproduction']['count']}/"
        f"{pack['selected_candidate_family']['reproduction']['requested']}"
    )
    print(
        f"[metadata] aggregate_sha256 = "
        f"{pack['source_evidence']['aggregate_sha256']}"
    )
    print("[metadata] status = metadata_only (NOT R3; 0 fix rounds)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
