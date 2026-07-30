# -*- coding: utf-8 -*-
"""GTO-PRODUCT-RECOVERY Route D R2 — product-perfect validation harness.

Hardened static + external-evidence gates. No live execution, no UI probe, no
script-engine probe, no vault writes, no cargo.

R1 defect (audited): bypass gate only scanned forbidden env *strings* and could
not claim the five r26b bypass patch sites were absent.

R2 upgrades:
- Explicit r26b bypass site model (5 RVAs).
- Per-site byte checks; unknown clean bytes → INCONCLUSIVE (never invent PASS).
- Optional --evidence-json for natural/UI/script external evidence.
- product_1_0 only when every required gate is PASS.

Usage:
  python tools/_mtr_gto_product_perfect_validate.py --help
  python tools/_mtr_gto_product_perfect_validate.py --self-test
  python tools/_mtr_gto_product_perfect_validate.py --candidate dump.exe
  python tools/_mtr_gto_product_perfect_validate.py --candidate dump.exe \\
      --evidence-json evidence.json --output out.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "mida.gto.product-perfect-validate/v1"
FORBIDDEN_ENV = ("MIDA_GTO_BYPASS", "MIDA_GTO_SEMANTIC_REPAIR")

# r26b bypass patch sites (image RVAs treated as raw file offsets for dump
# candidates that are file-mapped 1:1 from preferred base). Clean original
# bytes are NOT sealed in-repo → expected_clean_hex is None → site cannot PASS.
# Registering clean bytes requires separate governance; do not invent them.
DEFAULT_SITE_SPAN = 8


@dataclass(frozen=True)
class BypassSite:
    rva: int
    site_id: str
    description: str
    span: int = DEFAULT_SITE_SPAN
    # Lowercase hex of expected clean/original bytes at rva, or None if unknown.
    expected_clean_hex: str | None = None


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
    if len(data) < need:
        return {
            "site_id": site.site_id,
            "rva": f"0x{site.rva:x}",
            "description": site.description,
            "status": "FAIL",
            "detail": (
                f"candidate too small for site: size={len(data)} "
                f"need>={need} (rva+span)"
            ),
        }
    actual = data[site.rva : site.rva + site.span]
    actual_hex = actual.hex()
    if site.expected_clean_hex is None:
        return {
            "site_id": site.site_id,
            "rva": f"0x{site.rva:x}",
            "description": site.description,
            "status": "INCONCLUSIVE",
            "detail": (
                "expected clean/original bytes not sealed; "
                "cannot PASS site; observed=" + actual_hex
            ),
            "observed_hex": actual_hex,
            "expected_clean_hex": None,
        }
    exp = site.expected_clean_hex.lower().replace(" ", "")
    if actual_hex == exp:
        return {
            "site_id": site.site_id,
            "rva": f"0x{site.rva:x}",
            "description": site.description,
            "status": "PASS",
            "detail": "matches sealed clean bytes",
            "observed_hex": actual_hex,
            "expected_clean_hex": exp,
        }
    return {
        "site_id": site.site_id,
        "rva": f"0x{site.rva:x}",
        "description": site.description,
        "status": "FAIL",
        "detail": f"bytes differ from sealed clean; observed={actual_hex} expected={exp}",
        "observed_hex": actual_hex,
        "expected_clean_hex": exp,
    }


def _check_no_bypass_patches(candidate: Path | None) -> dict[str, Any]:
    """Fail-closed site model. Env-string scan is NOT proof of patch absence."""
    if candidate is None:
        return _gate(
            "no_bypass_patches",
            "INCONCLUSIVE",
            "no candidate supplied; r26b site checks require candidate bytes",
            sites=[],
        )

    data = candidate.read_bytes()
    # Residual note only — must not drive PASS.
    env_name_hits = [k for k in FORBIDDEN_ENV if k.encode("ascii") in data]

    site_results = [_check_site(data, s) for s in R26B_BYPASS_SITES]
    statuses = [s["status"] for s in site_results]

    if any(st == "FAIL" for st in statuses):
        overall = "FAIL"
        detail = "one or more r26b bypass sites FAIL (see sites[])"
    elif all(st == "PASS" for st in statuses):
        overall = "PASS"
        detail = "all five r26b bypass sites match sealed clean bytes"
    else:
        overall = "INCONCLUSIVE"
        detail = (
            "r26b site checks incomplete: clean bytes unsealed and/or mixed "
            "INCONCLUSIVE results; env-string scan is not proof of patch absence"
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
    """Require explicit true + source/hash/timestamp non-empty strings."""
    if blob is None:
        return _gate(key, "INCONCLUSIVE", f"{key} absent")
    if not isinstance(blob, dict):
        return _gate(key, "FAIL", f"{key} must be an object")
    # Accept either {"true": true, ...} or {"present": true, ...}
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
        bad = _gate("evidence_json", "FAIL", "evidence root must be a JSON object")
        return [
            bad,
            _gate("natural_execution", "FAIL", "evidence root invalid"),
            _gate("ui_script_path", "FAIL", "evidence root invalid"),
            _gate("script_engine_execution", "FAIL", "evidence root invalid"),
        ]

    nat = _validate_evidence_blob(
        "natural_execution", evidence.get("natural_execution_evidence")
    )
    # Map internal names for gate list consistency
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
) -> dict[str, Any]:
    bypass = _check_no_bypass_patches(candidate)
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
        "route": "GTO-PRODUCT-RECOVERY Route D",
        "round": "R2",
        "overall_status": overall,
        "product_1_0": bool(product_1_0),
        "gates": gates,
        "artifact": artifact,
        "r26b_bypass_sites": [
            {
                "rva": f"0x{s.rva:x}",
                "site_id": s.site_id,
                "description": s.description,
                "span": s.span,
                "expected_clean_hex_sealed": s.expected_clean_hex is not None,
            }
            for s in R26B_BYPASS_SITES
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
        ],
    }


def _dumps(report: dict[str, Any]) -> str:
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def _load_evidence(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("evidence-json root must be object")
    return raw


def run_self_test() -> int:
    for k in FORBIDDEN_ENV:
        os.environ.pop(k, None)

    # 1) no candidate => INCONCLUSIVE, product_1_0 false
    r0 = evaluate(None)
    assert r0["overall_status"] == "INCONCLUSIVE", r0
    assert r0["product_1_0"] is False, r0
    assert r0["gates"][0]["status"] == "INCONCLUSIVE", r0
    s0 = _dumps(r0)
    assert s0 == _dumps(r0), "JSON not deterministic"

    # 2) forbidden env => FAIL
    os.environ["MIDA_GTO_BYPASS"] = "1"
    r_env = evaluate(None)
    assert r_env["overall_status"] == "FAIL", r_env
    assert r_env["product_1_0"] is False, r_env
    assert r_env["gates"][1]["status"] == "FAIL", r_env
    os.environ.pop("MIDA_GTO_BYPASS", None)

    # 3) candidate too small => not PASS (FAIL on sites)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(b"tiny")
        tiny = Path(tf.name)
    try:
        r_tiny = evaluate(tiny)
        assert r_tiny["product_1_0"] is False
        assert r_tiny["overall_status"] != "PASS"
        assert r_tiny["gates"][0]["status"] == "FAIL", r_tiny["gates"][0]
        assert r_tiny["artifact"]["size_bytes"] == 4
        assert r_tiny["artifact"]["sha256"] == _sha256_file(tiny)
    finally:
        tiny.unlink(missing_ok=True)

    # 4) large candidate, evidence absent => INCONCLUSIVE (clean bytes unsealed)
    big = b"\x00" * (0x34F66 + 16)
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(big)
        large = Path(tf.name)
    try:
        r_large = evaluate(large)
        assert r_large["overall_status"] == "INCONCLUSIVE", r_large
        assert r_large["product_1_0"] is False
        assert r_large["gates"][0]["status"] == "INCONCLUSIVE"
        sites = r_large["gates"][0]["sites"]
        assert len(sites) == 5
        assert all(s["status"] == "INCONCLUSIVE" for s in sites)
        # evidence gates INCONCLUSIVE
        assert r_large["gates"][2]["status"] == "INCONCLUSIVE"
        assert r_large["gates"][3]["status"] == "INCONCLUSIVE"
        assert r_large["gates"][4]["status"] == "INCONCLUSIVE"
    finally:
        large.unlink(missing_ok=True)

    # 5) fake evidence missing fields => FAIL/INCONCLUSIVE, not PASS
    fake_bad = {
        "natural_execution_evidence": {"true": True, "source": "x"},  # missing hash/ts
        "ui_script_path_evidence": {"true": True, "source": "y", "hash": "h", "timestamp": "t"},
        "script_engine_execution_evidence": {
            "true": True,
            "source": "z",
            "hash": "h2",
            "timestamp": "t2",
        },
    }
    r_bad = evaluate(None, evidence=fake_bad)
    assert r_bad["product_1_0"] is False
    assert r_bad["overall_status"] != "PASS"
    assert r_bad["gates"][2]["status"] == "FAIL", r_bad["gates"][2]

    fake_incomplete = {
        "natural_execution_evidence": None,
    }
    r_inc = evaluate(None, evidence=fake_incomplete)
    assert r_inc["product_1_0"] is False
    assert r_inc["overall_status"] == "INCONCLUSIVE"
    assert r_inc["gates"][2]["status"] == "INCONCLUSIVE"

    # 6) full evidence still cannot product_1_0 without sealed clean + candidate PASS
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
    r_full = evaluate(None, evidence=full_ev)
    assert r_full["gates"][2]["status"] == "PASS"
    assert r_full["gates"][3]["status"] == "PASS"
    assert r_full["gates"][4]["status"] == "PASS"
    assert r_full["gates"][0]["status"] == "INCONCLUSIVE"  # no candidate
    assert r_full["product_1_0"] is False
    assert r_full["overall_status"] == "INCONCLUSIVE"

    print("self-test: OK", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="tools/_mtr_gto_product_perfect_validate.py",
        description=(
            "Route D product-perfect validation harness (R2 hardened). "
            "r26b bypass sites + optional external evidence JSON. "
            "Without sealed clean bytes and full evidence, overall is INCONCLUSIVE."
        ),
    )
    p.add_argument(
        "--candidate",
        type=Path,
        default=None,
        help="Optional candidate PE/dump path (required for r26b site checks)",
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

    report = evaluate(candidate, evidence=evidence)
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
