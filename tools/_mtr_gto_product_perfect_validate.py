# -*- coding: utf-8 -*-
"""GTO product-perfect validation harness (Route D R2 + Route E R1).

Static + external-evidence gates. No live execution, no UI probe, no
script-engine probe, no vault writes, no cargo.

Route E R1:
- Optional --clean-bytes-json loads sealed/unsealed r26b clean-byte manifest.
- Sealed site + matching candidate bytes => PASS site.
- Sealed site + mismatch => FAIL site.
- Unsealed / missing manifest => INCONCLUSIVE (never invent clean bytes).
- product_1_0 still requires live/UI/script evidence gates PASS.

Usage:
  python tools/_mtr_gto_product_perfect_validate.py --help
  python tools/_mtr_gto_product_perfect_validate.py --self-test
  python tools/_mtr_gto_product_perfect_validate.py \\
      --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json
  python tools/_mtr_gto_product_perfect_validate.py --candidate dump.exe \\
      --clean-bytes-json docs/GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json \\
      --evidence-json evidence.json --output out.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

SCHEMA = "mida.gto.product-perfect-validate/v2"
FORBIDDEN_ENV = ("MIDA_GTO_BYPASS", "MIDA_GTO_SEMANTIC_REPAIR")
DEFAULT_SITE_SPAN = 8
CLEAN_BYTES_SCHEMA = "mida.gto.r26b-clean-bytes/v0"


@dataclass(frozen=True)
class BypassSite:
    rva: int
    site_id: str
    description: str
    span: int = DEFAULT_SITE_SPAN
    # Lowercase hex of expected clean/original bytes at rva, or None if unsealed.
    expected_clean_hex: str | None = None
    sealed: bool = False
    unsealed_reason: str | None = None


R26B_BYPASS_SITES: tuple[BypassSite, ...] = (
    BypassSite(0x5C5D, "r26b_0x5c5d", "MessageBoxW skip"),
    BypassSite(0x63F4, "r26b_0x63f4", "LoadFile skip"),
    BypassSite(0x34F66, "r26b_0x34f66", "CreateWindowEx forced NewClassName"),
    BypassSite(0x34F59, "r26b_0x34f59", "WS_VISIBLE forced"),
    BypassSite(0x6757, "r26b_0x6757", "msg-loop AV skip"),
)

EVIDENCE_KEYS = (
    "natural_execution_evidence",
    "ui_script_path_evidence",
    "script_engine_execution_evidence",
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _gate(
    name: str,
    status: str,
    detail: str,
    **extra: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {"name": name, "status": status, "detail": detail}
    out.update(extra)
    return out


def _parse_rva(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"invalid rva: {value!r}")


def _norm_hex(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("expected_clean_hex must be string or null")
    h = value.lower().replace(" ", "").replace("0x", "")
    if len(h) % 2 != 0 or any(c not in "0123456789abcdef" for c in h):
        raise ValueError(f"invalid hex: {value!r}")
    if not h:
        return None
    return h


def load_clean_bytes_manifest(path: Path) -> tuple[list[BypassSite], dict[str, Any]]:
    """Load clean-byte manifest; returns sites overlay + meta."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("clean-bytes-json root must be object")
    sites_raw = raw.get("sites")
    if not isinstance(sites_raw, list) or not sites_raw:
        raise ValueError("clean-bytes-json.sites must be non-empty list")

    by_id = {s.site_id: s for s in R26B_BYPASS_SITES}
    by_rva = {s.rva: s for s in R26B_BYPASS_SITES}
    out: list[BypassSite] = []
    seen: set[str] = set()

    for entry in sites_raw:
        if not isinstance(entry, dict):
            raise ValueError("site entry must be object")
        rva = _parse_rva(entry.get("rva"))
        site_id = str(entry.get("site_id") or by_rva.get(rva, BypassSite(rva, f"rva_{rva:x}", "")).site_id)
        base = by_id.get(site_id) or by_rva.get(rva)
        if base is None:
            base = BypassSite(
                rva=rva,
                site_id=site_id,
                description=str(entry.get("description") or site_id),
            )
        span = int(entry.get("span") or base.span)
        sealed = bool(entry.get("sealed", False))
        exp = _norm_hex(entry.get("expected_clean_hex"))
        reason = entry.get("unsealed_reason")
        if sealed:
            if not exp:
                raise ValueError(f"sealed site {site_id} missing expected_clean_hex")
            if len(exp) != span * 2:
                raise ValueError(
                    f"sealed site {site_id}: hex length {len(exp)} != span*2 ({span * 2})"
                )
            out.append(
                replace(
                    base,
                    rva=rva,
                    site_id=site_id,
                    span=span,
                    expected_clean_hex=exp,
                    sealed=True,
                    unsealed_reason=None,
                    description=str(entry.get("description") or base.description),
                )
            )
        else:
            out.append(
                replace(
                    base,
                    rva=rva,
                    site_id=site_id,
                    span=span,
                    expected_clean_hex=None,
                    sealed=False,
                    unsealed_reason=str(reason or "unsealed in clean-bytes manifest"),
                    description=str(entry.get("description") or base.description),
                )
            )
        seen.add(site_id)

    # Ensure canonical five sites present (fill unsealed if missing).
    for canon in R26B_BYPASS_SITES:
        if canon.site_id not in seen:
            out.append(
                replace(
                    canon,
                    sealed=False,
                    expected_clean_hex=None,
                    unsealed_reason="missing from clean-bytes manifest",
                )
            )

    # Stable order by canonical RVA then extras
    order = {s.site_id: i for i, s in enumerate(R26B_BYPASS_SITES)}
    out.sort(key=lambda s: (order.get(s.site_id, 1000), s.rva, s.site_id))
    meta = {
        "path": path.as_posix(),
        "schema_version": raw.get("schema_version"),
        "sha256": _sha256_file(path),
        "site_count": len(out),
        "sealed_count": sum(1 for s in out if s.sealed),
        "unsealed_count": sum(1 for s in out if not s.sealed),
    }
    return out, meta


def sites_from_manifest_or_default(
    clean_bytes: dict[str, Any] | None,
) -> tuple[list[BypassSite], dict[str, Any] | None]:
    if clean_bytes is None:
        sites = [
            replace(s, sealed=False, expected_clean_hex=None, unsealed_reason="no clean-bytes manifest")
            for s in R26B_BYPASS_SITES
        ]
        return sites, None
    # clean_bytes already parsed as {"sites": [...], "meta": ...} or full raw
    if "sites_objects" in clean_bytes:
        return clean_bytes["sites_objects"], clean_bytes.get("meta")
    raise ValueError("internal: clean_bytes must be preloaded")


def _check_forbidden_env() -> dict[str, Any]:
    present = [k for k in FORBIDDEN_ENV if os.environ.get(k)]
    if present:
        return _gate(
            "no_semantic_repair",
            "FAIL",
            "forbidden env present: " + ",".join(sorted(present)),
        )
    return _gate(
        "no_semantic_repair",
        "PASS",
        "MIDA_GTO_BYPASS and MIDA_GTO_SEMANTIC_REPAIR absent",
    )


def _check_site(data: bytes, site: BypassSite) -> dict[str, Any]:
    need = site.rva + site.span
    base = {
        "site_id": site.site_id,
        "rva": f"0x{site.rva:x}",
        "description": site.description,
        "span": site.span,
        "sealed": site.sealed,
    }
    if len(data) < need:
        return {
            **base,
            "status": "FAIL",
            "detail": (
                f"candidate too small for site: size={len(data)} "
                f"need>={need} (rva+span)"
            ),
        }
    actual = data[site.rva : site.rva + site.span]
    actual_hex = actual.hex()
    if not site.sealed or site.expected_clean_hex is None:
        return {
            **base,
            "status": "INCONCLUSIVE",
            "detail": (
                "site unsealed: "
                + (site.unsealed_reason or "expected clean bytes not sealed")
                + "; cannot PASS; observed="
                + actual_hex
            ),
            "observed_hex": actual_hex,
            "expected_clean_hex": None,
            "unsealed_reason": site.unsealed_reason,
        }
    exp = site.expected_clean_hex
    if actual_hex == exp:
        return {
            **base,
            "status": "PASS",
            "detail": "matches sealed clean bytes",
            "observed_hex": actual_hex,
            "expected_clean_hex": exp,
        }
    return {
        **base,
        "status": "FAIL",
        "detail": f"bytes differ from sealed clean; observed={actual_hex} expected={exp}",
        "observed_hex": actual_hex,
        "expected_clean_hex": exp,
    }


def _check_no_bypass_patches(
    candidate: Path | None,
    sites: list[BypassSite],
) -> dict[str, Any]:
    if candidate is None:
        return _gate(
            "no_bypass_patches",
            "INCONCLUSIVE",
            "no candidate supplied; r26b site checks require candidate bytes",
            sites=[],
        )

    data = candidate.read_bytes()
    env_name_hits = [k for k in FORBIDDEN_ENV if k.encode("ascii") in data]
    site_results = [_check_site(data, s) for s in sites]
    statuses = [s["status"] for s in site_results]

    if any(st == "FAIL" for st in statuses):
        overall = "FAIL"
        detail = "one or more r26b bypass sites FAIL (see sites[])"
    elif len(site_results) >= 5 and all(st == "PASS" for st in statuses):
        overall = "PASS"
        detail = "all bypass sites match sealed clean bytes"
    else:
        overall = "INCONCLUSIVE"
        detail = (
            "r26b site checks incomplete: unsealed sites and/or mixed "
            "INCONCLUSIVE; env-string scan is not proof of patch absence"
        )
        if env_name_hits:
            detail += "; residual env-name strings in image: " + ",".join(env_name_hits)

    return _gate(
        "no_bypass_patches",
        overall,
        detail,
        sites=site_results,
        env_string_scan_hits=env_name_hits,
        env_string_scan_proves_patch_absence=False,
    )


def _validate_evidence_blob(key: str, blob: Any) -> dict[str, Any]:
    if blob is None:
        return _gate(key, "INCONCLUSIVE", f"{key} absent")
    if not isinstance(blob, dict):
        return _gate(key, "FAIL", f"{key} must be an object")
    flag = blob.get("true", blob.get("present", None))
    if flag is not True:
        return _gate(
            key,
            "FAIL" if flag is False else "INCONCLUSIVE",
            f"{key} requires explicit true/present=true; got {flag!r}",
        )
    missing = [
        f
        for f in ("source", "hash", "timestamp")
        if not isinstance(blob.get(f), str) or not str(blob.get(f)).strip()
    ]
    if missing:
        return _gate(
            key,
            "FAIL",
            f"{key} missing/empty required fields: " + ",".join(missing),
        )
    return _gate(
        key,
        "PASS",
        f"{key} present with source/hash/timestamp",
        source=str(blob["source"]),
        hash=str(blob["hash"]),
        timestamp=str(blob["timestamp"]),
    )


def _check_evidence_gates(evidence: dict[str, Any] | None) -> list[dict[str, Any]]:
    if evidence is None:
        return [
            _gate(
                "natural_execution",
                "INCONCLUSIVE",
                "natural_execution_evidence absent (--evidence-json not supplied)",
            ),
            _gate(
                "ui_script_path",
                "INCONCLUSIVE",
                "ui_script_path_evidence absent (--evidence-json not supplied)",
            ),
            _gate(
                "script_engine_execution",
                "INCONCLUSIVE",
                "script_engine_execution_evidence absent (--evidence-json not supplied)",
            ),
        ]
    if not isinstance(evidence, dict):
        return [
            _gate("natural_execution", "FAIL", "evidence root invalid"),
            _gate("ui_script_path", "FAIL", "evidence root invalid"),
            _gate("script_engine_execution", "FAIL", "evidence root invalid"),
        ]

    nat = _validate_evidence_blob(
        "natural_execution", evidence.get("natural_execution_evidence")
    )
    nat["name"] = "natural_execution"
    ui = _validate_evidence_blob(
        "ui_script_path", evidence.get("ui_script_path_evidence")
    )
    ui["name"] = "ui_script_path"
    scr = _validate_evidence_blob(
        "script_engine_execution", evidence.get("script_engine_execution_evidence")
    )
    scr["name"] = "script_engine_execution"
    return [nat, ui, scr]


def evaluate(
    candidate: Path | None,
    evidence: dict[str, Any] | None = None,
    sites: list[BypassSite] | None = None,
    clean_bytes_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if sites is None:
        sites = [
            replace(
                s,
                sealed=False,
                expected_clean_hex=None,
                unsealed_reason="no clean-bytes manifest",
            )
            for s in R26B_BYPASS_SITES
        ]

    bypass = _check_no_bypass_patches(candidate, sites)
    env = _check_forbidden_env()
    evidence_gates = _check_evidence_gates(evidence)
    gates = [bypass, env, *evidence_gates]

    artifact: dict[str, Any] = {
        "role": "candidate",
        "path": None,
        "sha256": None,
        "size_bytes": None,
    }
    if candidate is not None:
        artifact["path"] = candidate.as_posix()
        artifact["size_bytes"] = candidate.stat().st_size
        artifact["sha256"] = _sha256_file(candidate)

    required_names = {
        "no_bypass_patches",
        "no_semantic_repair",
        "natural_execution",
        "ui_script_path",
        "script_engine_execution",
    }
    by_name = {g["name"]: g for g in gates}
    product_1_0 = all(
        by_name.get(n, {}).get("status") == "PASS" for n in required_names
    )

    fail = any(g["status"] == "FAIL" for g in gates)
    if fail:
        overall = "FAIL"
    elif product_1_0:
        overall = "PASS"
    else:
        overall = "INCONCLUSIVE"

    return {
        "schema_version": SCHEMA,
        "route": "GTO-PRODUCT-RECOVERY Route E",
        "round": "R1-clean-bytes",
        "overall_status": overall,
        "product_1_0": bool(product_1_0),
        "gates": gates,
        "artifact": artifact,
        "clean_bytes_manifest": clean_bytes_meta,
        "r26b_bypass_sites": [
            {
                "rva": f"0x{s.rva:x}",
                "site_id": s.site_id,
                "description": s.description,
                "span": s.span,
                "sealed": s.sealed,
                "expected_clean_hex_sealed": bool(s.sealed and s.expected_clean_hex),
                "unsealed_reason": s.unsealed_reason,
            }
            for s in sites
        ],
        "forbidden_env_checked": list(FORBIDDEN_ENV),
        "evidence_keys_required": list(EVIDENCE_KEYS),
        "non_claims": [
            "not product 1.0 unless product_1_0 true",
            "not gto perfect unpack",
            "no live execution performed by this harness",
            "no UI/script evidence collected by this harness",
            "env-string scan does not prove r26b patch absence",
            "unsealed clean bytes cannot yield bypass-site PASS",
            "production clean-byte inventing is forbidden",
        ],
    }


def _dumps(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def _load_evidence(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("evidence-json root must be object")
    return raw


def _synthetic_all_sealed(hex_byte: str = "90") -> list[BypassSite]:
    """Self-test only: seal all canonical sites with repeated fill byte."""
    fill = (hex_byte * DEFAULT_SITE_SPAN)
    return [
        replace(
            s,
            sealed=True,
            expected_clean_hex=fill,
            unsealed_reason=None,
        )
        for s in R26B_BYPASS_SITES
    ]


def _build_synthetic_candidate(sites: list[BypassSite], mutate_rva: int | None = None) -> bytes:
    size = max(s.rva + s.span for s in sites) + 16
    buf = bytearray(b"\x00" * size)
    for s in sites:
        assert s.expected_clean_hex
        raw = bytes.fromhex(s.expected_clean_hex)
        if mutate_rva is not None and s.rva == mutate_rva:
            raw = bytes((b ^ 0xFF) for b in raw)
        buf[s.rva : s.rva + s.span] = raw
    return bytes(buf)


def run_self_test() -> int:
    for k in FORBIDDEN_ENV:
        os.environ.pop(k, None)

    # --- prior Route D tests (smoke) ---
    r0 = evaluate(None)
    assert r0["overall_status"] == "INCONCLUSIVE", r0
    assert r0["product_1_0"] is False
    assert r0["gates"][0]["status"] == "INCONCLUSIVE"
    assert _dumps(r0) == _dumps(r0)

    # no manifest => INCONCLUSIVE sites when candidate large
    big = b"\x00" * (0x34F66 + 16)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(big)
        large = Path(tf.name)
    try:
        r_nom = evaluate(large)
        assert r_nom["gates"][0]["status"] == "INCONCLUSIVE"
        assert all(s["status"] == "INCONCLUSIVE" for s in r_nom["gates"][0]["sites"])
    finally:
        large.unlink(missing_ok=True)

    # --- Route E R1: sealed synthetic + matching candidate => site PASS ---
    sealed = _synthetic_all_sealed("ab")
    cand_bytes = _build_synthetic_candidate(sealed)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(cand_bytes)
        cand_path = Path(tf.name)
    try:
        r_ok = evaluate(cand_path, sites=sealed)
        assert r_ok["gates"][0]["status"] == "PASS", r_ok["gates"][0]
        assert all(s["status"] == "PASS" for s in r_ok["gates"][0]["sites"])
        # still no live evidence => not product_1_0
        assert r_ok["product_1_0"] is False
        assert r_ok["overall_status"] == "INCONCLUSIVE"
    finally:
        cand_path.unlink(missing_ok=True)

    # mismatch => FAIL
    sealed2 = _synthetic_all_sealed("cd")
    bad_bytes = _build_synthetic_candidate(sealed2, mutate_rva=0x5C5D)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(bad_bytes)
        bad_path = Path(tf.name)
    try:
        r_bad = evaluate(bad_path, sites=sealed2)
        assert r_bad["gates"][0]["status"] == "FAIL", r_bad["gates"][0]
        assert r_bad["product_1_0"] is False
        assert any(s["status"] == "FAIL" for s in r_bad["gates"][0]["sites"])
    finally:
        bad_path.unlink(missing_ok=True)

    # unsealed manifest sites => INCONCLUSIVE
    unsealed = [
        replace(s, sealed=False, expected_clean_hex=None, unsealed_reason="test-unsealed")
        for s in R26B_BYPASS_SITES
    ]
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(b"\x00" * (0x34F66 + 16))
        u_path = Path(tf.name)
    try:
        r_u = evaluate(u_path, sites=unsealed)
        assert r_u["gates"][0]["status"] == "INCONCLUSIVE"
        assert all(s["status"] == "INCONCLUSIVE" for s in r_u["gates"][0]["sites"])
    finally:
        u_path.unlink(missing_ok=True)

    # load real production manifest (all unsealed) via loader
    repo = Path(__file__).resolve().parents[1]
    prod = repo / "docs" / "GTO_PRODUCT_RECOVERY_ROUTE_E_CLEAN_BYTES_20260730.json"
    if prod.is_file():
        sites_p, meta_p = load_clean_bytes_manifest(prod)
        assert meta_p["sealed_count"] == 0
        assert meta_p["unsealed_count"] >= 5
        assert all(not s.sealed for s in sites_p)

    # sealed + evidence still needs candidate match for product_1_0; with match
    # + full evidence => product_1_0 true (synthetic only)
    full_ev = {
        "natural_execution_evidence": {
            "true": True,
            "source": "lab/run",
            "hash": "a" * 64,
            "timestamp": "2026-07-30T00:00:00Z",
        },
        "ui_script_path_evidence": {
            "true": True,
            "source": "lab/ui",
            "hash": "b" * 64,
            "timestamp": "2026-07-30T00:00:00Z",
        },
        "script_engine_execution_evidence": {
            "true": True,
            "source": "lab/script",
            "hash": "c" * 64,
            "timestamp": "2026-07-30T00:00:00Z",
        },
    }
    sealed3 = _synthetic_all_sealed("11")
    good = _build_synthetic_candidate(sealed3)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(good)
        g_path = Path(tf.name)
    try:
        r_pass = evaluate(g_path, evidence=full_ev, sites=sealed3)
        assert r_pass["gates"][0]["status"] == "PASS"
        assert r_pass["product_1_0"] is True
        assert r_pass["overall_status"] == "PASS"
    finally:
        g_path.unlink(missing_ok=True)

    print("self-test: OK", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="tools/_mtr_gto_product_perfect_validate.py",
        description=(
            "Product-perfect validation harness (Route D gates + Route E clean-bytes). "
            "Use --clean-bytes-json for sealed/unsealed r26b clean-byte manifest. "
            "Without sealed clean bytes and live evidence, overall is INCONCLUSIVE."
        ),
    )
    p.add_argument(
        "--candidate",
        type=Path,
        default=None,
        help="Optional candidate PE/dump path (required for r26b site checks)",
    )
    p.add_argument(
        "--clean-bytes-json",
        type=Path,
        default=None,
        help="Optional Route E clean-byte manifest JSON (sealed/unsealed per site)",
    )
    p.add_argument(
        "--evidence-json",
        type=Path,
        default=None,
        help=(
            "Optional external evidence JSON with natural_execution_evidence, "
            "ui_script_path_evidence, script_engine_execution_evidence"
        ),
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path to write deterministic JSON report",
    )
    p.add_argument(
        "--self-test",
        action="store_true",
        help="Run offline deterministic self-tests and exit",
    )
    args = p.parse_args(argv)

    if args.self_test:
        return run_self_test()

    candidate = args.candidate
    if candidate is not None:
        candidate = candidate.resolve()
        if not candidate.is_file():
            print(f"error: candidate not a file: {candidate}", file=sys.stderr)
            return 1

    sites: list[BypassSite] | None = None
    clean_meta: dict[str, Any] | None = None
    if args.clean_bytes_json is not None:
        cp = args.clean_bytes_json.resolve()
        if not cp.is_file():
            print(f"error: clean-bytes-json not a file: {cp}", file=sys.stderr)
            return 1
        try:
            sites, clean_meta = load_clean_bytes_manifest(cp)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: clean-bytes-json: {exc}", file=sys.stderr)
            return 1

    evidence = None
    if args.evidence_json is not None:
        ep = args.evidence_json.resolve()
        if not ep.is_file():
            print(f"error: evidence-json not a file: {ep}", file=sys.stderr)
            return 1
        try:
            evidence = _load_evidence(ep)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: evidence-json: {exc}", file=sys.stderr)
            return 1

    report = evaluate(
        candidate,
        evidence=evidence,
        sites=sites,
        clean_bytes_meta=clean_meta,
    )
    text = _dumps(report)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    sys.stdout.write(text)
    if report["overall_status"] == "FAIL":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
