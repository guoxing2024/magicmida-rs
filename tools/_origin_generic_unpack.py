# -*- coding: utf-8 -*-
"""Phase-1 Origin generic-unpack smoke (packer-agnostic dump)."""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

CLI = Path(r"D:\MidaVault\scratch\cargo-target\debug\mida-cli.exe")
SRC = Path(r"D:\MidaVault\scratch\materialized\origin_macro__protected_input__1af62999cf5b.bin")
EV_ROOT = Path(r"D:\MidaVault\lab\evidence\origin_macro")


def main() -> int:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = EV_ROOT / f"generic_{run_id}"
    out_dir.mkdir(parents=True, exist_ok=True)
    work_input = out_dir / "origin_protected.exe"
    work_input.write_bytes(SRC.read_bytes())
    out_pe = out_dir / "origin_genericU.exe"
    log_path = out_dir / "unpack.stdout.txt"
    meta_path = out_dir / "run_meta.json"

    cmd = [
        str(CLI),
        "/generic-unpack",
        str(work_input),
        "-o",
        str(out_pe),
        "-v",
        "--wait-sec",
        "90",
        "--stable",
        "2",
    ]
    meta = {
        "run_id": run_id,
        "cmd": cmd,
        "started": datetime.now().isoformat(timespec="seconds"),
        "path": "generic-unpack",
    }
    print("RUN", " ".join(cmd), flush=True)
    t0 = time.time()
    p = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=str(CLI.parent),
    )
    elapsed = time.time() - t0
    log = (p.stdout or "") + "\n---STDERR---\n" + (p.stderr or "")
    log_path.write_text(log, encoding="utf-8")
    meta.update(
        {
            "finished": datetime.now().isoformat(timespec="seconds"),
            "elapsed_sec": round(elapsed, 2),
            "exit_code": p.returncode,
            "out_pe_exists": out_pe.is_file(),
            "out_pe_size": out_pe.stat().st_size if out_pe.is_file() else None,
            "log": str(log_path),
        }
    )
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print("exit", p.returncode, "elapsed", round(elapsed, 2), "out", meta["out_pe_size"], flush=True)
    for line in log.splitlines()[-50:]:
        print(line)
    return 0 if p.returncode == 0 else p.returncode


if __name__ == "__main__":
    sys.exit(main())
