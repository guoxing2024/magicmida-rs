# -*- coding: utf-8 -*-
"""GTO-PRODUCT-RECOVERY Route D R1 — product-perfect validation harness.

Deterministic static/env gates only. No live execution, no UI probe, no
script-engine probe, no vault writes, no cargo.

Verdict rules:
- Without live + UI/script evidence → overall status is always INCONCLUSIVE.
- product_1_0 is true only when every gate is PASS (including live evidence).
- This harness never invents live evidence; therefore product_1_0 stays false
  and overall status stays INCONCLUSIVE unless future evidence files are
  supplied by a separately authorized path (not implemented in R1).

Usage:
  python tools/_mtr_gto_product_perfect_validate.py --help
  python tools/_mtr_gto_product_perfect_validate.py --self-test
  python tools/_mtr_gto_product_perfect_validate.py --candidate path\\to\\dump.exe
  python tools/_mtr_gto_product_perfect_validate.py --candidate dump.exe --output out.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

SCHEMA = "mida.gto.product-perfect-validate/v0"
FORBIDDEN_ENV = ("MIDA_GTO_BYPASS", "MIDA_GTO_SEMANTIC_REPAIR")

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _gate(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _check_forbidden_env() -> dict[str, str]:
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


def _check_no_bypass_patches(candidate: Path | None) -> dict[str, str]:
    if candidate is None:
        return _gate(
            "no_bypass_patches",
            "INCONCLUSIVE",
            "no candidate supplied; static bypass scan skipped",
        )
    data = candidate.read_bytes()
    # R1 sealed check: fail only if forbidden bypass/repair env names are
    # embedded as ASCII in the candidate image. Broader r26b signature corpus
    # requires separate governance before it can fail-closed.
    ascii_env = [k for k in FORBIDDEN_ENV if k.encode("ascii") in data]
    if ascii_env:
        return _gate(
            "no_bypass_patches",
            "FAIL",
            "candidate embeds forbidden env name(s): " + ",".join(ascii_env),
        )
    return _gate(
        "no_bypass_patches",
        "PASS",
        "forbidden env-name strings absent in candidate image",
    )


def _check_natural_execution() -> dict[str, str]:
    return _gate(
        "natural_execution",
        "INCONCLUSIVE",
        "live execution evidence not supplied (R1 harness is static-only)",
    )


def _check_ui_script_path() -> dict[str, str]:
    return _gate(
        "ui_script_path",
        "INCONCLUSIVE",
        "UI + script-engine evidence not supplied (R1 harness is static-only)",
    )


def evaluate(candidate: Path | None) -> dict[str, Any]:
    gates = [
        _check_no_bypass_patches(candidate),
        _check_forbidden_env(),
        _check_natural_execution(),
        _check_ui_script_path(),
    ]

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

    fail = any(g["status"] == "FAIL" for g in gates)
    all_pass = all(g["status"] == "PASS" for g in gates)
    # Hard rule: without live/UI evidence, never overall PASS / product_1_0.
    product_1_0 = bool(all_pass)
    if fail:
        overall = "FAIL"
    elif product_1_0:
        overall = "PASS"
    else:
        overall = "INCONCLUSIVE"

    report = {
        "schema_version": SCHEMA,
        "route": "GTO-PRODUCT-RECOVERY Route D",
        "round": "R1",
        "overall_status": overall,
        "product_1_0": product_1_0,
        "gates": gates,
        "artifact": artifact,
        "forbidden_env_checked": list(FORBIDDEN_ENV),
        "non_claims": [
            "not product 1.0 unless product_1_0 true",
            "not gto perfect unpack",
            "no live execution performed by this harness",
            "no UI/script evidence collected by this harness",
        ],
    }
    return report


def _dumps(report: dict[str, Any]) -> str:
    # Deterministic: sorted keys, stable separators, trailing newline.
    return json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def run_self_test() -> int:
    # 1) forbidden env absent → no_semantic_repair PASS
    for k in FORBIDDEN_ENV:
        os.environ.pop(k, None)
    r1 = evaluate(None)
    assert r1["overall_status"] == "INCONCLUSIVE", r1
    assert r1["product_1_0"] is False, r1
    assert r1["gates"][1]["status"] == "PASS", r1
    assert r1["gates"][2]["status"] == "INCONCLUSIVE", r1
    assert r1["gates"][3]["status"] == "INCONCLUSIVE", r1
    s1 = _dumps(r1)
    s1b = _dumps(r1)
    assert s1 == s1b, "JSON not deterministic"

    # 2) forbidden env present → FAIL
    os.environ["MIDA_GTO_BYPASS"] = "1"
    r2 = evaluate(None)
    assert r2["overall_status"] == "FAIL", r2
    assert r2["product_1_0"] is False, r2
    assert r2["gates"][1]["status"] == "FAIL", r2
    os.environ.pop("MIDA_GTO_BYPASS", None)

    # 3) candidate sha/size
    import tempfile

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tf:
        tf.write(b"GTO-ROUTE-D-R1-SELFTEST\n")
        tmp = Path(tf.name)
    try:
        r3 = evaluate(tmp)
        assert r3["artifact"]["size_bytes"] == tmp.stat().st_size
        assert r3["artifact"]["sha256"] == _sha256_file(tmp)
        assert r3["overall_status"] == "INCONCLUSIVE"
        assert r3["product_1_0"] is False
    finally:
        tmp.unlink(missing_ok=True)

    print("self-test: OK", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="tools/_mtr_gto_product_perfect_validate.py",
        description=(
            "Route D product-perfect validation harness (static/env only). "
            "Without live/UI/script evidence overall status is INCONCLUSIVE."
        ),
    )
    p.add_argument(
        "--candidate",
        type=Path,
        default=None,
        help="Optional candidate PE/dump path (sha256/size computed when present)",
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
            return 2

    report = evaluate(candidate)
    text = _dumps(report)
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8", newline="\n")
    sys.stdout.write(text)
    # Exit: 0 INCONCLUSIVE or PASS, 2 FAIL, 1 config/IO already handled
    if report["overall_status"] == "FAIL":
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
