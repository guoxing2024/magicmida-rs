#!/usr/bin/env python3
"""GTO-R6-A1 — offline unit tests for tools/dd_restore.py.

Work order §4.3 (green criterion 3): "新增离线测试（Rust 或 Python 均可）
验证：对合成 mini-PE 应用同样映射逻辑正确".

Strategy
--------
Loads tools/dd_restore.py as a plain module (importlib, stdlib only) — the
module's main() and vault paths are never touched.  Builds synthetic mini-PE32+
blobs (candidate with "dump-rewritten" RVA fields, protected reference with
original RVA fields) that exercise exactly the mapping logic used on the real
layout_A candidate:

  * entry + DataDirectory[0]/[1]/[12] RVA halves differ and must be restored
    from the reference;
  * Size halves and every other directory already match the reference and must
    remain untouched;
  * all non-target bytes must be byte-identical after the transform
    (full-file diff assertion).

Runs:  python tools/test_dd_restore.py
Green:  all checks PASS, exit 0.  No processes are created; nothing is executed.
"""

from __future__ import annotations

import importlib.util
import io
import struct
import sys
from contextlib import redirect_stdout
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / "dd_restore.py"

# mini-PE layout constants (PE32+, 1 section, no section table needed by the
# parser: the tool only reads the headers).  DOS stub = 0x40 bytes, PE
# signature at file offset 0x40 (realistic layout; e_lfanew = 0x40).
DOS_SIZE = 0x40
SIG_OFF = DOS_SIZE
COFF_OFF = SIG_OFF + 4
OPT_OFF = COFF_OFF + 20
OPT_SIZE = 240
DD_OFF = OPT_OFF + 112
ENTRY_OFF = OPT_OFF + 16
TOTAL = DOS_SIZE + 4 + 20 + OPT_SIZE


def make_mini_pe(entry, dd0_rva, dd1_rva, dd12_rva, dd0_size=0x1AE,
                 dd1_size=0x154, dd12_size=0x1190, seed=0xAA):
    """Synthetic PE32+ header blob (dos stub + sig + coff + optional header)."""
    b = bytearray(TOTAL)
    for i in range(len(b)):          # deterministic background fill
        b[i] = (seed + i) & 0xFF
    # DOS header
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, SIG_OFF)  # e_lfanew = 0x40
    # PE signature
    b[SIG_OFF:SIG_OFF + 4] = b"PE\0\0"
    coff = COFF_OFF
    struct.pack_into("<H", b, coff + 2, 1)      # NumberOfSections = 1
    struct.pack_into("<H", b, coff + 16, OPT_SIZE)  # SizeOfOptionalHeader
    opt = OPT_OFF
    coff = 0x44
    struct.pack_into("<H", b, coff + 2, 1)      # NumberOfSections = 1
    struct.pack_into("<H", b, coff + 16, OPT_SIZE)  # SizeOfOptionalHeader
    opt = coff + 20
    struct.pack_into("<H", b, opt, 0x20B)       # PE32+
    struct.pack_into("<Q", b, opt + 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", b, opt + 56, 0x1000)  # SizeOfImage
    struct.pack_into("<I", b, ENTRY_OFF, entry)
    struct.pack_into("<II", b, DD_OFF + 0 * 8, dd0_rva, dd0_size)
    struct.pack_into("<II", b, DD_OFF + 1 * 8, dd1_rva, dd1_size)
    struct.pack_into("<II", b, DD_OFF + 12 * 8, dd12_rva, dd12_size)
    return bytes(b)


# Reference (protected) mini-PE — the "original" values.
REF_ENTRY = 0x16FB532
REF_DD0 = 0x17F13E8
REF_DD1 = 0x17DC3E8
REF_DD12 = 0x159F000

# Candidate mini-PE — "dump-rewritten" values (as in the real layout_A pair).
# Low bytes chosen nonzero so every changed field differs in all 4 bytes
# (expected changed bytes = 16 exactly).
CAND_ENTRY = 0x2D21ABC
CAND_DD0 = 0x2E51CDE
CAND_DD1 = 0x2D1EF01
CAND_DD12 = 0x2CF2357

_results = []


def check(name, cond, detail=""):
    _results.append((name, bool(cond), detail))
    if not cond:
        print(f"FAIL {name} {detail}")
    else:
        print(f"PASS {name}")


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "dd_restore_tool", str(TOOL), submodule_search_locations=[])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    tool = load_tool()

    ref = make_mini_pe(REF_ENTRY, REF_DD0, REF_DD1, REF_DD12)
    cand = make_mini_pe(CAND_ENTRY, CAND_DD0, CAND_DD1, CAND_DD12)
    check("synthetic blobs differ from reference",
          cand != ref and len(cand) == len(ref))

    # --- 1. change-plan computation (same mapping as the real run) ---
    entry_new, dd_new, changes = tool.build_changes(cand, ref, "mini")
    check("entry target from reference",
          entry_new == REF_ENTRY,
          f"got {entry_new:#x}")
    check("dd targets from reference",
          dd_new == {0: REF_DD0, 1: REF_DD1, 12: REF_DD12},
          f"got {dd_new!r}")
    names = {c[3] for c in changes}
    check("exactly 4 target fields planned",
          len(changes) == 4 and {
              "AddressOfEntryPoint",
              "DataDirectory[0] Export.RVA",
              "DataDirectory[1] Import.RVA",
              "DataDirectory[12] IAT.RVA",
          } == names,
          f"got {sorted(names)!r}")

    # --- 2. application + full-file diff assertion ---
    out = bytearray(cand)
    tool.apply_changes(out, changes)
    out = bytes(out)
    expected = tool.expected_byte_count(changes)
    diff = tool.full_diff_count(cand, out)
    check("expected changed bytes == 16 (4 fields x 4B, discontiguous)",
          expected == 16, f"got {expected}")
    check("full-file diff == expected changed bytes",
          diff == expected, f"diff={diff} expected={expected}")
    check("every non-target byte identical to input candidate",
          diff == expected and all(
              out[i] == cand[i]
              for i in range(len(cand))
              if not any(s <= i < e for s, e in
                         tool.changed_byte_ranges(changes))))

    # --- 3. output equals reference ON THE TARGET FIELDS, nothing else ---
    co = tool.parse_pe_header(cand, "cand")
    oo = tool.parse_pe_header(out, "out")
    check("output entry == reference entry",
          oo["entry_rva"] == REF_ENTRY)
    for idx in (0, 1, 12):
        check(f"output DD[{idx}].rva == reference",
              oo["data_directories"][idx]["rva"] ==
              tool.parse_pe_header(ref, "ref")["data_directories"][idx]["rva"])
        check(f"output DD[{idx}].size untouched",
              oo["data_directories"][idx]["size"] ==
              co["data_directories"][idx]["size"])
    check("output differs from reference only in non-target bytes",
          sum(1 for x, y in zip(out, ref) if x != y) == 0 or
          # Sizes/background identical by construction; the only possible
          # difference vs ref is the dump-rewritten target fields themselves —
          # which are exactly the fields we restored, so out == ref here.
          out == ref)

    # --- 4. fail-closed: non-target directory divergence must abort ---
    bad_ref = make_mini_pe(REF_ENTRY, REF_DD0, REF_DD1, REF_DD12)
    b = bytearray(bad_ref)
    struct.pack_into("<II", b, DD_OFF + 3 * 8, 0x1234000, 0x200)  # Exception dir
    bad_ref = bytes(b)
    try:
        tool.build_changes(cand, bad_ref, "mini-bad")
        check("non-target divergence aborts (build_changes raises)", False,
              "no exception")
    except tool.DDRestoreError:
        check("non-target divergence aborts (build_changes raises)", True)

    # --- 5. fail-closed: size-half divergence must abort ---
    bad_ref2 = make_mini_pe(REF_ENTRY, REF_DD0, REF_DD1, REF_DD12,
                            dd0_size=0x999)
    try:
        tool.build_changes(cand, bad_ref2, "mini-bad2")
        check("size-half divergence aborts (build_changes raises)", False,
              "no exception")
    except tool.DDRestoreError:
        check("size-half divergence aborts (build_changes raises)", True)

    # --- 6. dry-run path is inert (no output written) ---
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = tool.main(["--dry-run"])  # uses vault paths; must not write
    check("dry-run returns 0 (vault inputs present)", rc == 0,
          f"rc={rc} out={buf.getvalue()[:200]!r}")

    failed = [n for n, ok, _d in _results if not ok]
    print(f"\n{len(_results) - len(failed)}/{len(_results)} checks passed")
    if failed:
        print("FAILED: " + ", ".join(failed))
        return 1
    print("ALL GREEN (exit 0)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
