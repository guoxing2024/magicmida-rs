#!/usr/bin/env python3
"""GTO-R6-A1 — Data-Directory + Entry restore tool (OFFLINE ONLY).

Work order: WORK_ORDER_GTO-R6-A1-DD-RESTORE_20260825.md

Purpose
-------
The H5 startup-order attribution determined that the dump pipeline rebuilt the
candidate PE header data directories, while the Themida TLS-phase API resolver
reads the ORIGINAL Import Directory values. This tool (offline, no process
creation, no sample execution) rewrites exactly the four target fields of the
layout_A candidate so the header matches the protected reference:

    AddressOfEntryPoint       0x2d21000 -> 0x16fb532
    DataDirectory[0] Export   RVA 0x2e51000 -> 0x17f13e8   (Size 0x1ae unchanged)
    DataDirectory[1] Import   RVA 0x2d1e000 -> 0x17dc3e8   (Size 0x154 unchanged)
    DataDirectory[12] IAT     RVA 0x12c000  -> 0x159f000   (Size 0x1190 unchanged)

Only the four 4-byte RVA/entry fields are written (15 differing bytes on this
layout: IAT.RVA 0x12c000 -> 0x159f000 shares its high byte; three
discontiguous ranges in the Optional Header).  Every other byte of the output
is asserted byte-identical to the input candidate (full-file diff assertion),
and every non-target field (all other DataDirectories, all Size fields) is
asserted equal between candidate and protected reference before writing.

The "expected_changed_byte_count" contract of the work order ("entry 8B + each
dir 8B") is recorded in the report as a literal-contract conflict: the
field-level target values in work-order §3 (confirmed against the protected
reference header and the H5 attribution report §三) require changing only the
RVA halves (4B per field); the Size halves already match and are therefore not
changed.  See docs/GTO_R6_A1_DD_RESTORE_REPORT.md for the adjudication.

Offline-only guarantees:
  * reads bytes from disk with open(path, "rb")
  * writes bytes with open(path, "wb") to the evidence output path
  * never imports/exeutes the candidate, never spawns a process
  * does not touch runner_preflight.rs or any dump-pipeline production code

Usage
-----
    python tools/dd_restore.py            # uses the hard-coded vault paths
    python tools/dd_restore.py --dry-run  # verify only, no output written
    python tools/dd_restore.py --output-dir DIR
                                          # stage evidence under DIR instead
                                          # of the mandated vault location
                                          # (same layout_A/ sub-structure)

Exit status: 0 on success (report written), 1 on any failure (no partial
output; the output file is removed if the diff assertion fails).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Work-order §2 inputs (read-only; vault-anchored, hashes verified below)
# ---------------------------------------------------------------------------
CANDIDATE = Path(
    r"D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\H4D_P6_validation"
    r"\layout_A\candidate\gto_unpacked.exe"
)
PROTECTED_REF = Path(
    r"D:\MidaVault\vault\sha256\11"
    r"\11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86\artifact.exe"
)
# Work-order §3 mandated evidence location (used when no --output-dir given).
DEFAULT_OUTPUT_DIR = Path(
    r"D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A1_dd_restore"
)
OUTPUT_NAME = "layout_A/gto_unpacked.dd_restored.exe"
REPORT_NAME = "dd_restore_report.json"

# Work-order §2 pinned hashes.
CANDIDATE_SHA256 = "9d41a1fd49609a14e3b820b68a04f7c4c811eb847d863fa7054dad6a7b3ef1c3"
PROTECTED_SHA256 = "11473d2e6b00d8a7f079e0e2d7eff9cfd0c7134af3c6bd3ca2e600b637895c86"

DIR_NAMES = [
    "Export", "Import", "Resource", "Exception", "Certificate", "BaseReloc",
    "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
    "IAT", "DelayImport", "CLR", "Reserved",
]

# Work-order §3 target values (confirmed against the protected reference
# header and docs/GTO_H5_STARTUP_ORDER_ATTRIBUTION_REPORT.md §三).
TARGET_ENTRY_RVA = 0x16FB532
TARGET_DD = {
    0: 0x17F13E8,   # Export RVA  (size unchanged, reference 0x1ae)
    1: 0x17DC3E8,   # Import RVA  (size unchanged, reference 0x154)
    12: 0x159F000,  # IAT RVA     (size unchanged, reference 0x1190)
}


class DDRestoreError(Exception):
    """Fatal, reportable error (aborts the tool with exit 1)."""


# ---------------------------------------------------------------------------
# PE header parsing (read-only)
# ---------------------------------------------------------------------------
def parse_pe_header(data: bytes, label: str) -> dict:
    """Parse enough of a PE32+ header to locate the fields we touch.

    Returns dict with absolute file offsets of the entry field and the
    DataDirectory table, plus parsed values.  Raises DDRestoreError on any
    structural mismatch (fail closed).
    """
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise DDRestoreError(f"{label}: not an MZ file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 + 0xE0 > len(data):
        raise DDRestoreError(f"{label}: truncated headers (e_lfanew={e_lfanew:#x})")
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise DDRestoreError(f"{label}: no PE signature at {e_lfanew:#x}")
    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        dd_off = opt + 112
        entry_off = opt + 16
        size_off = opt + 56  # SizeOfImage, sanity only
    elif magic == 0x10B:
        dd_off = opt + 96
        entry_off = opt + 16
        size_off = opt + 56
    else:
        raise DDRestoreError(f"{label}: unknown optional-header magic {magic:#x}")
    if size_opt < 240:
        raise DDRestoreError(f"{label}: optional header too small ({size_opt})")
    if dd_off + 16 * 8 > len(data):
        raise DDRestoreError(f"{label}: data directory table out of file bounds")
    dds = []
    for i in range(16):
        rva, size = struct.unpack_from("<II", data, dd_off + i * 8)
        dds.append({"rva": rva, "size": size})
    entry = struct.unpack_from("<I", data, entry_off)[0]
    return {
        "e_lfanew": e_lfanew,
        "num_sections": num_sections,
        "size_optional_header": size_opt,
        "magic": magic,
        "entry_off": entry_off,
        "dd_off": dd_off,
        "size_of_image": struct.unpack_from("<I", data, size_off)[0],
        "entry_rva": entry,
        "data_directories": dds,
    }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Core restore logic
# ---------------------------------------------------------------------------
def build_changes(candidate: bytes, ref: bytes, label: str = "inputs"):
    """Compute the target field values from the protected reference header.

    Returns (entry_new, dd_new_rvas, changes) where changes is a list of
    (file_offset, old_bytes, new_bytes, field_name).  Raises DDRestoreError
    when the two inputs disagree on any non-target structural field.
    """
    c = parse_pe_header(candidate, f"{label}: candidate")
    r = parse_pe_header(ref, f"{label}: protected reference")

    # Fail closed only on the structural items that determine the layout of
    # the fields we touch.  e_lfanew / num_sections / size_of_image are
    # per-image properties and legitimately differ between a Themida-packed
    # protected binary and its unpacked dump — they are NOT required to match.
    for key in ("size_optional_header", "magic"):
        if c[key] != r[key]:
            raise DDRestoreError(
                f"{label}: structural mismatch on {key}: "
                f"candidate={c[key]!r} ref={r[key]!r}")

    changes = []
    entry_new = r["entry_rva"]
    if c["entry_rva"] != entry_new:
        changes.append((c["entry_off"], c["entry_rva"], entry_new,
                        "AddressOfEntryPoint"))
    dd_new_rvas = {}
    for idx in TARGET_DD:
        cdd = c["data_directories"][idx]
        rdd = r["data_directories"][idx]
        # Sizes are outside the target field set: they must already match.
        if cdd["size"] != rdd["size"]:
            raise DDRestoreError(
                f"{label}: DataDirectory[{idx}] size differs "
                f"(candidate={cdd['size']:#x} ref={rdd['size']:#x}); "
                f"refusing to touch a non-target field")
        if cdd["rva"] != rdd["rva"]:
            off = c["dd_off"] + idx * 8
            changes.append((off, cdd["rva"], rdd["rva"],
                            f"DataDirectory[{idx}] {DIR_NAMES[idx]}.RVA"))
        dd_new_rvas[idx] = rdd["rva"]

    # Guard: every non-target DataDirectory must already be identical.
    for idx in range(16):
        if idx in TARGET_DD:
            continue
        if c["data_directories"][idx] != r["data_directories"][idx]:
            raise DDRestoreError(
                f"{label}: non-target DataDirectory[{idx}] differs "
                f"(candidate={c['data_directories'][idx]!r} "
                f"ref={r['data_directories'][idx]!r})")

    return entry_new, dd_new_rvas, changes


def apply_changes(data: bytearray, changes) -> None:
    for off, old, new, _name in changes:
        old_b = struct.pack("<I", old)
        new_b = struct.pack("<I", new)
        if data[off:off + 4] != old_b:
            raise DDRestoreError(
                f"field at {off:#x}: pre-image mismatch "
                f"(expected {old_b.hex()} found {bytes(data[off:off + 4]).hex()})")
        data[off:off + 4] = new_b


def expected_byte_count(changes) -> int:
    """Number of output bytes that actually differ from the input candidate.

    Counts byte positions where old != new across the target fields
    (overlapping 4B fields share bytes).  A field whose old/new values share
    identical bytes (e.g. IAT.RVA 0x12c000 -> 0x159f000, both high byte 0x01)
    contributes only its genuinely changed bytes, so this number always equals
    the full-file diff count — the work-order §3 invariant.
    """
    return len({(off, i) for off, old, new, _name in changes if old != new
                for i in range(4)
                if (old >> (8 * i)) & 0xFF != (new >> (8 * i)) & 0xFF})


def changed_byte_ranges(changes) -> list:
    """Contiguous [start, end) ranges of bytes that actually change."""
    diffs = sorted({off + i for off, old, new, _n in changes if old != new
                    for i in range(4)
                    if (old >> (8 * i)) & 0xFF != (new >> (8 * i)) & 0xFF})
    ranges = []
    for b in diffs:
        if ranges and b == ranges[-1][1]:
            ranges[-1][1] = b + 1
        else:
            ranges.append([b, b + 1])
    return ranges


def full_diff_count(a: bytes, b: bytes) -> int:
    """Number of byte positions where a and b differ (full-file assertion)."""
    if len(a) != len(b):
        raise DDRestoreError(
            f"length mismatch: input={len(a)} output={len(b)}")
    return sum(1 for x, y in zip(a, b) if x != y)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
def field_table(candidate: bytes, output: bytes, changes, label_old="candidate",
                label_new="dd_restored"):
    """old->new table for the report (hex, per field, 4-byte little-endian)."""
    c = parse_pe_header(candidate, label_old)
    out = parse_pe_header(output, label_new)
    rows = [{
        "field": "AddressOfEntryPoint",
        "offset": hex(c["entry_off"]),
        "old": hex(c["entry_rva"]),
        "new": hex(out["entry_rva"]),
    }]
    for idx in sorted(TARGET_DD):
        rows.append({
            "field": f"DataDirectory[{idx}] {DIR_NAMES[idx]}.RVA",
            "offset": hex(c["dd_off"] + idx * 8),
            "old": hex(c["data_directories"][idx]["rva"]),
            "new": hex(out["data_directories"][idx]["rva"]),
        })
    for idx in sorted(TARGET_DD):
        rows.append({
            "field": f"DataDirectory[{idx}] {DIR_NAMES[idx]}.Size",
            "offset": hex(c["dd_off"] + idx * 8 + 4),
            "old": hex(c["data_directories"][idx]["size"]),
            "new": hex(out["data_directories"][idx]["size"]),
            "note": "unchanged (matches protected reference)",
        })
    return rows


def build_report(candidate: Path, protected: Path, output: Path, changes,
                 input_sha: str, output_sha: str, expected: int,
                 actual: int) -> dict:
    cand = candidate.read_bytes()
    outp = output.read_bytes()
    ranges = changed_byte_ranges(changes)
    return {
        "work_order": "WORK_ORDER_GTO-R6-A1-DD-RESTORE_20260825.md",
        "status": "PASS" if actual == expected and expected > 0 else "FAIL",
        "input": {
            "path": str(candidate),
            "size_bytes": len(cand),
            "sha256": input_sha,
            "sha256_pinned_in_work_order": CANDIDATE_SHA256,
        },
        "protected_reference": {
            "path": str(protected),
            "size_bytes": protected.stat().st_size,
            "sha256": sha256_file(protected),
        },
        "output": {
            "path": str(output),
            "size_bytes": len(outp),
            "sha256": output_sha,
        },
        "changed_byte_ranges_count": actual,
        "expected_changed_byte_ranges_count_work_order_literal": expected,
        "expected_byte_count_note": (
            "work-order §3 field-level targets change only the 4 RVA/entry "
            "fields (15 bytes on this layout); the 'entry 8B + each dir 8B' "
            "literal contract "
            "is superseded by the field-level targets — see report doc, §冲突裁决"
        ),
        "changed_byte_ranges": [
            {"start": hex(s), "end": hex(e), "length": e - s}
            for s, e in ranges
        ],
        "fields": field_table(cand, outp, changes),
        "assertions": {
            "full_file_diff_byte_count": full_diff_count(cand, outp),
            "full_file_identical_outside_target_ranges": (
                full_diff_count(cand, outp) == actual
            ),
            "all_non_target_fields_match_reference": True,
        },
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="GTO-R6-A1 data-directory restore (offline, read/write "
                    "bytes only — never executes any sample).")
    ap.add_argument("--dry-run", action="store_true",
                    help="verify inputs and compute the change plan without "
                         "writing any output")
    ap.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
                    help="evidence output root (default: the work-order §3 "
                         "mandated vault evidence dir)")
    args = ap.parse_args(argv)

    output_dir = args.output_dir
    output = output_dir / OUTPUT_NAME
    report = output_dir / REPORT_NAME

    try:
        for path, pinned in ((CANDIDATE, CANDIDATE_SHA256),
                             (PROTECTED_REF, PROTECTED_SHA256)):
            if not path.is_file():
                raise DDRestoreError(f"missing input: {path}")
            h = sha256_file(path)
            if h != pinned:
                raise DDRestoreError(
                    f"hash mismatch for {path.name}: got {h}, "
                    f"pinned {pinned} (fail closed)")

        candidate = CANDIDATE.read_bytes()
        ref = PROTECTED_REF.read_bytes()
        entry_new, dd_new, changes = build_changes(candidate, ref)
        expected = expected_byte_count(changes)
        if len(changes) == 0:
            raise DDRestoreError("no target-field changes needed; "
                                 "candidate already matches reference")

        print(f"[dd_restore] plan: {len(changes)} fields, "
              f"{expected} expected changed bytes "
              f"(entry 0x{entry_new:x}, DD rvas "
              + ", ".join(f"[{k}]=0x{v:x}" for k, v in sorted(dd_new.items()))
              + ")")

        if args.dry_run:
            print("[dd_restore] dry-run: no output written (exit 0)")
            return 0

        output.parent.mkdir(parents=True, exist_ok=True)
        out_data = bytearray(candidate)
        apply_changes(out_data, changes)
        out_bytes = bytes(out_data)

        # Full-file diff assertion BEFORE writing to the evidence path.
        diff = full_diff_count(candidate, out_bytes)
        if diff != expected:
            raise DDRestoreError(
                f"diff assertion failed: full-file diff {diff} != expected "
                f"{expected}; aborting without output")

        output.write_bytes(out_bytes)
        output_sha = sha256_file(output)

        report_path = output_dir / REPORT_NAME
        report = build_report(CANDIDATE, PROTECTED_REF, output, changes,
                              CANDIDATE_SHA256, output_sha, expected, diff)
        report["expected_changed_byte_ranges_count_work_order_literal"] = (
            "literal-contract conflict: work-order text 'entry 8B + each dir "
            "8B' (32B) vs field-level targets §3 (15B) — resolved in favor of "
            "§3 field-level targets; see doc §冲突裁决")
        report["output_dir"] = str(output_dir)
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"[dd_restore] wrote {output}")
        print(f"[dd_restore] wrote {report_path}")
        print(f"[dd_restore] output sha256: {output_sha}")
        print(f"[dd_restore] changed byte ranges: {report['changed_byte_ranges']}")
        print("[dd_restore] OK (exit 0)")
        return 0
    except DDRestoreError as exc:
        print(f"[dd_restore] FAIL: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[dd_restore] FAIL (IO): {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
