# -*- coding: utf-8 -*-
"""Phase-1 static R0B for all vault cases. Writes evidence under D:\\MidaVault\\lab\\evidence."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ACC = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-acceptance.exe")
MAT = Path(r"D:\MidaVault\scratch\materialized")
EV_ROOT = Path(r"D:\MidaVault\lab\evidence")

CASES = [
    {
        "case_id": "origin_macro",
        "file": "origin_macro__protected_input__1af62999cf5b.bin",
        "sha256": "1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7",
        "size": 5232656,
        "role": "protected_input",
    },
    {
        "case_id": "origin_macro",
        "file": "origin_macro__legacy_oracle_candidate__fe92f992bcf0.bin",
        "sha256": "fe92f992bcf07e630c82ff3a1cfc138a8c2463e3e03f862da171e8781119268f",
        "size": 1696768,
        "role": "legacy_oracle_candidate",
        "report_name": "r0b_oracle.json",
    },
    {
        "case_id": "lunlun_software",
        "file": "lunlun_software__protected_input__8a0118d04e03.bin",
        "sha256": "8a0118d04e03752728999c845536c29215d2a626ac65845c22e3f1149de0db07",
        "size": 4976144,
        "role": "protected_input",
    },
    {
        "case_id": "gto_launcher",
        "file": "gto_launcher__protected_input__4d5770afdd2f.bin",
        "sha256": "4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8",
        "size": 8583680,
        "role": "protected_input",
    },
    {
        "case_id": "gto_launcher",
        "file": "gto_launcher__analysis_reference__dcc411afaafe.bin",
        "sha256": "dcc411afaafed6bf3fbc52c0c72eddf79f56fc9aea1516b911d49f59c94af379",
        "size": 15497216,
        "role": "analysis_reference",
        "report_name": "r0b_analysis_ref.json",
    },
    {
        "case_id": "dali_plugin",
        "file": "dali_plugin__protected_input__e4f48d5a1358.bin",
        "sha256": "e4f48d5a13589bd7232268d4836f1b7581983536f3310cc066f04d463873165d",
        "size": 6129664,
        "role": "protected_input",
    },
    {
        "case_id": "plain_pe32",
        "file": "plain_pe32__synthetic_control__5ae16f20b113.bin",
        "sha256": "5ae16f20b1131e0e030a5f364340fe20d5425be4684bb1b2514ed4ebbb137df3",
        "size": 1024,
        "role": "synthetic_control",
    },
]


def main() -> int:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    summary = []
    for c in CASES:
        case_dir = EV_ROOT / c["case_id"] / run_id
        case_dir.mkdir(parents=True, exist_ok=True)
        src = MAT / c["file"]
        report_name = c.get("report_name", f"r0b_{c['role']}.json")
        report = case_dir / report_name
        cmd = [
            str(ACC),
            "check-static",
            str(src),
            "--expected-sha256",
            c["sha256"],
            "--expected-size",
            str(c["size"]),
            "--role",
            c["role"],
            "--report",
            str(report),
        ]
        print("RUN", c["case_id"], c["role"], flush=True)
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
        (case_dir / (report_name + ".stdout.txt")).write_text(
            (p.stdout or "") + (p.stderr or ""), encoding="utf-8"
        )
        verdict = None
        failures = []
        if report.is_file():
            data = json.loads(report.read_text(encoding="utf-8"))
            verdict = data.get("verdict")
            failures = [
                f.get("code") or f.get("gate_id") for f in (data.get("failures") or [])
            ]
        entry = {
            "case_id": c["case_id"],
            "role": c["role"],
            "exit_code": p.returncode,
            "verdict": verdict,
            "failures": failures,
            "report": str(report),
        }
        summary.append(entry)
        print(" ->", entry["verdict"], "exit", p.returncode, failures, flush=True)

    out = EV_ROOT / f"_phase1_static_summary_{run_id}.json"
    out.write_text(json.dumps({"run_id": run_id, "cases": summary}, indent=2) + "\n", encoding="utf-8")
    print("wrote", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
