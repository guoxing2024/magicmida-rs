# -*- coding: utf-8 -*-
"""Shared Oreans/R3 corpus helpers (manifest + vault materialization).

No PE bytes. No R3 claim. Used by preflight, case live unpack, and repeat smoke.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]
MANIFEST_DIR = REPO / "lab" / "cases" / "v2"
MAT = Path(r"D:\MidaVault\scratch\materialized")
OBJECTS = Path(r"D:\MidaVault\objects\sha256")

# Engineering defaults (not holdout).
OREANS_REGRESSION_CASE = "origin_macro"
OREANS_DEV_CASE = "lunlun_software"

# Forbidden as Oreans holdout (wrong role or wrong family).
FORBIDDEN_HOLDOUT_IDS = frozenset(
    {
        "origin_macro",
        "lunlun_software",
        "gto_launcher",
        "dali_plugin",
        "plain_pe32",
    }
)


def load_manifests(manifest_dir: Path | None = None) -> list[dict[str, Any]]:
    root = manifest_dir or MANIFEST_DIR
    out: list[dict[str, Any]] = []
    if not root.is_dir():
        return out
    for path in sorted(root.glob("*.json")):
        if path.name.startswith("_") or path.name.endswith(".schema.json"):
            continue
        if path.name == "case-manifest.schema.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict) or "case_id" not in data:
            continue
        data["_manifest_path"] = str(path)
        out.append(data)
    return out


def primary_sha(manifest: dict[str, Any]) -> str | None:
    return manifest.get("primary_artifact_sha256")


def corpus_role(manifest: dict[str, Any]) -> str | None:
    cell = manifest.get("capability_cell") or {}
    return cell.get("corpus_role")


def protection_family(manifest: dict[str, Any]) -> str | None:
    cell = manifest.get("capability_cell") or {}
    return cell.get("protection_family")


def engine_route(manifest: dict[str, Any]) -> str | None:
    cell = manifest.get("capability_cell") or {}
    return cell.get("engine_route")


def is_oreans_candidate(manifest: dict[str, Any]) -> bool:
    return protection_family(manifest) == "oreans_candidate" and engine_route(
        manifest
    ) == "mida_plugin_oreans"


def find_materialized_protected(case_id: str, sha256: str, mat: Path | None = None) -> Path | None:
    """Resolve vault materialization by naming convention."""
    root = mat or MAT
    if not root.is_dir() or not sha256:
        return None
    short = sha256[:12]
    # Exact convention used by materialize tools.
    candidates = sorted(root.glob(f"{case_id}__protected_input__{short}*.bin"))
    if candidates:
        return candidates[0]
    # Looser: any protected_input for case_id (hash check later).
    loose = sorted(root.glob(f"{case_id}__protected_input__*.bin"))
    return loose[0] if loose else None


def object_path(sha256: str, objects_root: Path | None = None) -> Path | None:
    root = objects_root or OBJECTS
    if not sha256 or len(sha256) != 64:
        return None
    p = root / sha256[:2] / sha256
    return p if p.is_file() else None


def oracle_materialized(case_id: str, manifest: dict[str, Any], mat: Path | None = None) -> Path | None:
    root = mat or MAT
    oracle = manifest.get("oracle") or {}
    sha = oracle.get("artifact_sha256")
    if not sha:
        return None
    short = sha[:12]
    for role in ("legacy_oracle_candidate", "analysis_reference"):
        hits = sorted(root.glob(f"{case_id}__{role}__{short}*.bin"))
        if hits:
            return hits[0]
    return None


def resolve_case_cfg(
    case_id: str,
    *,
    manifests: list[dict[str, Any]] | None = None,
    mat: Path | None = None,
) -> dict[str, Any] | None:
    """Build live-unpack config for a case_id from manifest + materialization."""
    mans = manifests if manifests is not None else load_manifests()
    man = next((m for m in mans if m.get("case_id") == case_id), None)
    if man is None:
        return None
    sha = primary_sha(man)
    if not sha:
        return None
    src_path = find_materialized_protected(case_id, sha, mat=mat)
    if src_path is None or not src_path.is_file():
        return None
    oracle_path = oracle_materialized(case_id, man, mat=mat)
    # Short prefix for evidence filenames (origin / lunlun / case tail).
    prefix = case_id.split("_")[0] if "_" in case_id else case_id
    if case_id == "origin_macro":
        prefix = "origin"
    elif case_id == "lunlun_software":
        prefix = "lunlun"
    # Optional M4 capture_policy object from case-manifest (research knobs).
    cap = man.get("capture_policy")
    if cap is not None and not isinstance(cap, dict):
        cap = None

    return {
        "case_id": case_id,
        "src": src_path.name,
        "src_path": src_path,
        "src_note": f"{case_id} protected_input {sha[:12]}",
        "prefix": prefix,
        "oracle": oracle_path.name if oracle_path else None,
        "oracle_path": oracle_path,
        "sha256": sha,
        "corpus_role": corpus_role(man),
        "protection_family": protection_family(man),
        "engine_route": engine_route(man),
        "is_oreans": is_oreans_candidate(man),
        "manifest_path": man.get("_manifest_path"),
        "capture_policy": cap,
    }


def list_oreans_cases(manifests: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    mans = manifests if manifests is not None else load_manifests()
    return [m for m in mans if is_oreans_candidate(m)]


def list_holdout_oreans(manifests: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    mans = manifests if manifests is not None else load_manifests()
    out = []
    for m in mans:
        if not is_oreans_candidate(m):
            continue
        if corpus_role(m) != "holdout":
            continue
        cid = m.get("case_id")
        if cid in FORBIDDEN_HOLDOUT_IDS:
            continue
        out.append(m)
    return out


def preflight_report(
    *,
    mat: Path | None = None,
    objects_root: Path | None = None,
    manifest_dir: Path | None = None,
) -> dict[str, Any]:
    """Engineering preflight for R3 path. Never sets r3_gate true."""
    mans = load_manifests(manifest_dir)
    oreans = list_oreans_cases(mans)
    holdouts = list_holdout_oreans(mans)

    def case_slot(case_id: str) -> dict[str, Any]:
        man = next((m for m in mans if m.get("case_id") == case_id), None)
        if man is None:
            return {"case_id": case_id, "present": False}
        sha = primary_sha(man) or ""
        mat_path = find_materialized_protected(case_id, sha, mat=mat)
        obj = object_path(sha, objects_root=objects_root)
        return {
            "case_id": case_id,
            "present": True,
            "corpus_role": corpus_role(man),
            "protection_family": protection_family(man),
            "sha256": sha,
            "materialized": bool(mat_path and mat_path.is_file()),
            "materialized_path": str(mat_path) if mat_path else None,
            "object_present": bool(obj),
            "is_oreans": is_oreans_candidate(man),
        }

    origin = case_slot(OREANS_REGRESSION_CASE)
    lunlun = case_slot(OREANS_DEV_CASE)

    holdout_details = []
    for h in holdouts:
        cid = h["case_id"]
        holdout_details.append(case_slot(cid))

    if not holdouts:
        holdout_status = "empty"
    elif all(d.get("materialized") and d.get("object_present") for d in holdout_details):
        holdout_status = "ready"
    elif any(d.get("present") for d in holdout_details):
        holdout_status = "manifest_only_or_incomplete"
    else:
        holdout_status = "empty"

    gate_ready = (
        origin.get("materialized")
        and lunlun.get("materialized")
        and holdout_status == "ready"
        and all(d.get("is_oreans") for d in holdout_details)
    )

    return {
        "phase": "R3-path-B",
        "r3_gate": False,
        "note": (
            "Preflight only. R3 gate still requires continuous 10x on "
            "Origin+Lunlun+holdout + validation_summary close."
        ),
        "origin": origin,
        "lunlun": lunlun,
        "oreans_case_ids": [m.get("case_id") for m in oreans],
        "holdout_status": holdout_status,
        "holdouts": holdout_details,
        "gate_assets_ready": bool(gate_ready),
        "forbidden_holdout_ids": sorted(FORBIDDEN_HOLDOUT_IDS),
    }
