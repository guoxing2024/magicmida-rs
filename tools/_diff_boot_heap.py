# -*- coding: utf-8 -*-
"""Diff independent-host vs r4c .boot heap/container payloads (research)."""
from __future__ import annotations

import struct
import sys
from collections import Counter
from pathlib import Path

CONTAINER_META = 40
HEAP_META = 24
FIXUP = 24
N_C = 1
N_G = 320
META0 = 560  # measured: container meta starts after code pad


def get_boot(p: Path) -> bytes:
    b = p.read_bytes()
    e = struct.unpack_from("<I", b, 0x3C)[0]
    nsec = struct.unpack_from("<H", b, e + 6)[0]
    optsize = struct.unpack_from("<H", b, e + 20)[0]
    sect = e + 24 + optsize
    for i in range(nsec):
        off = sect + i * 40
        name = b[off : off + 8].split(b"\x00")[0]
        if b"boot" in name:
            vsize, va, rsize, ro = struct.unpack_from("<IIII", b, off + 8)
            return b[ro : ro + rsize]
    raise SystemExit(f"no .boot in {p}")


def parse(label: str, p: Path):
    raw = get_boot(p)
    c_off = META0
    g_off = c_off + N_C * CONTAINER_META
    f_off = g_off + N_G * HEAP_META
    d_off = f_off + (N_C + N_G) * FIXUP
    print(f"=== {label} boot_len={len(raw)} data_base={d_off}")
    rva, csize, cookie, doff, cap = struct.unpack_from("<IIQII", raw, c_off)
    live = struct.unpack_from("<Q", raw, c_off + 0x18)[0]
    print(
        f"  container rva={rva:#x} csize={csize} cookie={cookie:#x} "
        f"doff={doff} cap={cap} live={live:#x}"
    )
    entries = []
    for i in range(N_G):
        off = g_off + i * HEAP_META
        grva, gsz, gdoff, flags, livep = struct.unpack_from("<IIIIQ", raw, off)
        entries.append(
            dict(i=i, rva=grva, size=gsz, doff=gdoff, flags=flags, live=livep)
        )
    hg_sum = sum(e["size"] for e in entries)
    print(f"  heap_globals payload={hg_sum} container={csize} total={hg_sum + csize}")
    print(f"  layout estimate={d_off + hg_sum + csize} actual_stub={len(raw)}")
    hist: Counter[str] = Counter()
    for e in entries:
        if e["flags"] & 1:
            hist["handle"] += 1
        elif e["size"] == 0:
            hist["empty"] += 1
        elif e["size"] <= 0x40:
            hist["<=0x40"] += 1
        elif e["size"] <= 0x100:
            hist["<=0x100"] += 1
        elif e["size"] <= 0x400:
            hist["<=0x400"] += 1
        elif e["size"] <= 0x1000:
            hist["<=0x1000"] += 1
        elif e["size"] <= 0x2000:
            hist["<=0x2000"] += 1
        else:
            hist[">0x2000"] += 1
    print("  size hist", dict(hist))
    top = sorted(entries, key=lambda e: -e["size"])[:15]
    print("  top15:")
    for e in top:
        print(
            f"    i={e['i']:3d} rva={e['rva']:#08x} size={e['size']:#x} "
            f"live={e['live']:#x} flags={e['flags']}"
        )
    rvas = {e["rva"] for e in entries}
    return entries, rvas, hg_sum, csize


def main() -> int:
    scan = Path(
        r"D:\MidaVault\lab\evidence\gto_launcher\live_20260724-124524_u_gto_host_scan60\gto_unpacked.exe"
    )
    r4c = Path(
        r"D:\MidaVault\lab\evidence\gto_launcher\live_20260723-225951_r4c_gto\gto_unpacked.exe"
    )
    if len(sys.argv) >= 3:
        scan, r4c = Path(sys.argv[1]), Path(sys.argv[2])

    e1, r1, p1, c1 = parse("scan60", scan)
    e2, r2, p2, c2 = parse("r4c", r4c)
    print()
    print(f"payload delta heap_globals {p2 - p1:+d} container {c2 - c1:+d}")
    print(f"rva only scan60 count={len(r1 - r2)} only r4c count={len(r2 - r1)} common={len(r1 & r2)}")
    by1 = {e["rva"]: e for e in e1}
    by2 = {e["rva"]: e for e in e2}
    # rva==0 graph children: multiple entries share rva 0 — use list not map
    diffs = []
    for rva in sorted((r1 & r2) - {0}):
        if by1[rva]["size"] != by2[rva]["size"]:
            diffs.append(
                (
                    rva,
                    by1[rva]["size"],
                    by2[rva]["size"],
                    by1[rva]["live"],
                    by2[rva]["live"],
                )
            )
    print(f"same-rva size diffs (excl rva0): {len(diffs)}")
    for d in sorted(diffs, key=lambda x: -abs(x[2] - x[1]))[:25]:
        print(
            f"  rva={d[0]:#x} scan={d[1]:#x} r4c={d[2]:#x} "
            f"delta={d[2] - d[1]:+#x} live_s={d[3]:#x} live_r={d[4]:#x}"
        )

    only1 = sum(e["size"] for e in e1 if e["rva"] not in r2 and e["rva"] != 0)
    only2 = sum(e["size"] for e in e2 if e["rva"] not in r1 and e["rva"] != 0)
    print(f"payload unique image-rva scan60={only1} r4c={only2}")

    # graph children (rva==0)
    g1 = [e for e in e1 if e["rva"] == 0]
    g2 = [e for e in e2 if e["rva"] == 0]
    print(
        f"graph children rva0: scan n={len(g1)} bytes={sum(e['size'] for e in g1)} "
        f"r4c n={len(g2)} bytes={sum(e['size'] for e in g2)}"
    )
    # size multiset compare for rva0
    s1 = sorted(e["size"] for e in g1)
    s2 = sorted(e["size"] for e in g2)
    print(f"  rva0 size multiset equal={s1==s2} sum_delta={sum(s2)-sum(s1)}")

    # image-rooted hot RVAs
    hot = [
        0x149D50,
        0x18A898,
        0x141BF0,
        0x148BF8,
        0x148CB8,
        0x148CC0,
        0x148CB0,
        0x148CA8,
        0x148C98,
        0x148C00,
    ]
    print("HOT_GSCRIPT sizes:")
    for rva in hot:
        a = next((e for e in e1 if e["rva"] == rva), None)
        b = next((e for e in e2 if e["rva"] == rva), None)
        sa = a["size"] if a else None
        sb = b["size"] if b else None
        print(f"  {rva:#x}: scan={sa} r4c={sb} delta={(sb or 0)-(sa or 0):+#x}")

    # total size by category: image-root vs graph
    def split(entries):
        roots = [e for e in entries if e["rva"] != 0]
        kids = [e for e in entries if e["rva"] == 0]
        return (
            sum(e["size"] for e in roots),
            len(roots),
            sum(e["size"] for e in kids),
            len(kids),
        )

    print("scan split roots_bytes/n kids_bytes/n", split(e1))
    print("r4c  split roots_bytes/n kids_bytes/n", split(e2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
