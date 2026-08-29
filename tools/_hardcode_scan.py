#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hard-coding scanner for MagicMida (general-purpose engine policy).

Scans production Rust sources (crates/*/src) for hard-coded, session/sample/
machine-bound literals that violate the "general-purpose engine" requirement:

  - win_path   : Windows drive path literals (D:\\..., C:/...)
  - long_hex   : address-like literals 0x<7+ hex> (needs triage: masks/consts OK)
  - high_aslr  : high ASLR module-band addresses (0x7ffe...., session-bound)
  - sample_hex : known sample-anchor hashes (from ANCHORS list)
  - vault_path : vault / dumps path fragments (MidaVault, RE\\dumps)

Skips test files (*_tests.rs, *_test.rs, tests/ dir) and #[cfg(test)] blocks.
Intent: emit a precise production-code candidate list; reuse as a CI gate
later (fail on win_path / vault_path / sample_hex in production code).

Usage: python tools/_hardcode_scan.py [--all] [--gate]
  --all  : also include test files (default: production only)
  --gate : CI gate mode — fail (exit 1) if ANY win_path / vault_path /
           sample_hex hit in production code (long_hex stays manual triage).
"""
import os
import re
import sys

ROOT = r"D:\Claude project\magicmida-rs"
CRATES = ["core", "pe", "disasm", "tracer", "cli", "acceptance",
          "antidebug", "antidebug-runtime", "packers"]

# Gate-failing categories (general-purpose engine policy): no Windows drive
# paths, no vault/dumps paths, no sample-anchor hashes in production code.
GATE_PATTERNS = {"win_path", "vault_path", "sample_hex"}

# Known sample anchors (sha256 prefixes / paths) — extend as project evolves.
ANCHORS = [
    "78009803", "09f3dd34", "11473d2e", "36043cb4", "3650ea6c", "41ec52e0",
    "2848fcc0", "1af62999", "8a0118d0",
]

PATTERNS = {
    "win_path": re.compile(r'"[A-Za-z]:[\\/]'),
    "long_hex": re.compile(r"0x[0-9a-fA-F]{7,}"),
    "high_aslr": re.compile(r"0x7ffe[0-9a-fA-F]{5,}", re.IGNORECASE),
    "sample_hex": re.compile(r"|".join(ANCHORS), re.IGNORECASE),
    "vault_path": re.compile(r"MidaVault|Tools[\\/]RE[\\/]dumps", re.IGNORECASE),
}


def is_test_file(path):
    base = os.path.basename(path)
    return "_tests" in base or base.endswith("_test.rs") or "/tests/" in path


def scan_file(path, include_tests):
    hits = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    in_test_block = False
    brace_depth = 0
    for lineno, raw in enumerate(lines, 1):
        line = raw.strip()
        if line.startswith("//") or line.startswith("//!"):
            continue
        if not include_tests:
            # crude #[cfg(test)] block skip: enter on cfg(test), exit on the
            # matching close brace (depth tracked from the `mod ... {` line).
            if "cfg(test)" in line:
                in_test_block = True
                brace_depth = 1
                continue
            if in_test_block:
                brace_depth += line.count("{") - line.count("}")
                if brace_depth <= 0:
                    in_test_block = False
                continue
        for name, pat in PATTERNS.items():
            for m in pat.finditer(raw):
                hits.append((lineno, name, m.group(), raw.strip()))
    return hits


def main():
    include_tests = "--all" in sys.argv
    gate_mode = "--gate" in sys.argv
    total = {}
    for crate in CRATES:
        src = os.path.join(ROOT, "crates", crate, "src")
        if not os.path.isdir(src):
            continue
        for dirpath, _, files in os.walk(src):
            for f in files:
                if not f.endswith(".rs"):
                    continue
                full = os.path.join(dirpath, f)
                if is_test_file(full) and not include_tests:
                    continue
                rel = os.path.relpath(full, ROOT).replace("\\", "/")
                for lineno, name, val, text in scan_file(full, include_tests):
                    total.setdefault(name, []).append(f"{rel}:{lineno}:{val}  # {text[:90]}")
    if gate_mode:
        gate_hits = {k: v for k, v in total.items() if k in GATE_PATTERNS}
        if gate_hits:
            print("HARD-CODING GATE FAILED (general-purpose policy):")
            for name in sorted(gate_hits):
                for hit in gate_hits[name]:
                    print(f"  [{name}] {hit}")
            print(f"exit 1 — {sum(len(v) for v in gate_hits.values())} gate hits")
            sys.exit(1)
        print("HARD-CODING GATE PASS (no win_path/vault_path/sample_hex in production code)")
        sys.exit(0)
    for name in sorted(total):
        print(f"\n===== {name}: {len(total[name])} =====")
        for hit in total[name]:
            print(hit)
    print(f"\nTOTAL: {sum(len(v) for v in total.values())}")


if __name__ == "__main__":
    main()
