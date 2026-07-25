# -*- coding: utf-8 -*-
"""W2: compare GTO OEP region + key .data slots across dumps."""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path


def pe_map(path: Path):
    data = path.read_bytes()
    assert data[:2] == b"MZ"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew : e_lfanew + 4] == b"PE\0\0"
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    assert magic == 0x20B
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    sec_off = opt + opt_size
    sections = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
        sections.append((name, va, vsz, raw, rsz))
    return data, image_base, entry, sections


def rva_to_off(sections, rva: int):
    for name, va, vsz, raw, rsz in sections:
        span = max(vsz, rsz)
        if va <= rva < va + span and raw:
            return raw + (rva - va), name
    return None, None


def read_u64(data, sections, rva: int):
    off, sec = rva_to_off(sections, rva)
    if off is None or off + 8 > len(data):
        return None, sec
    return struct.unpack_from("<Q", data, off)[0], sec


def main() -> int:
    dumps = [
        ("scan60", Path(r"D:\MidaVault\lab\evidence\gto_launcher\live_20260724-124524_u_gto_host_scan60\gto_unpacked.exe")),
        ("r4c", Path(r"D:\MidaVault\lab\evidence\gto_launcher\live_20260723-225951_r4c_gto\gto_unpacked.exe")),
        ("fresh1", Path(r"D:\MidaVault\lab\evidence\gto_launcher\live_20260724-154209_w2_fresh1_gtoexp\gto_unpacked.exe")),
        ("m3", Path(r"D:\MidaVault\lab\evidence\gto_launcher\live_20260724-141353_m3_plugin_gtoexp\gto_unpacked.exe")),
    ]
    key_rvas = [
        0x141BF0,
        0x141BF8,
        0x145D50,
        0x148C98,
        0x148CA8,
        0x148CB0,
        0x148CB8,
        0x148CC0,
        0x149D50,
        0x145710,
        0x148BF8,
        0x148C00,
    ]
    for label, path in dumps:
        if not path.is_file():
            print(f"=== {label}: MISSING {path}")
            continue
        data, ib, ep, secs = pe_map(path)
        print(f"=== {label} base={ib:#x} ep_hdr={ep:#x} size={len(data)}")
        for rva in (0x70B0, 0x70C0, 0x70C9):
            off, sec = rva_to_off(secs, rva)
            if off is None:
                print(f"  code {rva:#x}: unmapped")
                continue
            print(f"  code {rva:#x} @{sec} off={off:#x}: {data[off:off+16].hex()}")
        off, sec = rva_to_off(secs, 0x70B0)
        if off is not None:
            print(f"  OEP+0..0x40: {data[off:off+0x40].hex()}")
        for rva in key_rvas:
            val, sec = read_u64(data, secs, rva)
            if val is None:
                print(f"  data {rva:#x}: unmapped")
            else:
                print(f"  data {rva:#x} @{sec}: {val:#018x}")
        # count QWORDs equal to 0x8000 in .data-like
        count_8k = 0
        samples = []
        for name, va, vsz, raw, rsz in secs:
            if not raw or rsz < 8:
                continue
            if "data" not in name.lower() and name.strip() not in ("", ".data"):
                # still scan .boot payload region lightly? skip code
                if name.startswith(".") and name not in (".data", ".rdata", ".boot"):
                    continue
            chunk = data[raw : raw + rsz]
            for i in range(0, len(chunk) - 7, 8):
                v = struct.unpack_from("<Q", chunk, i)[0]
                if v == 0x8000:
                    count_8k += 1
                    if len(samples) < 8:
                        samples.append(va + i)
        print(f"  qword==0x8000 count≈{count_8k} samples_rva={[hex(x) for x in samples]}")
        snap = path.with_suffix(".dump_snapshot.json")
        if snap.is_file():
            d = json.loads(snap.read_text(encoding="utf-8"))
            hg = d.get("heap_globals") or []
            if isinstance(hg, list):
                roots = [x for x in hg if isinstance(x, dict) and int(str(x.get("rva", "0")), 0) != 0]
                total = sum(int(x.get("content_size") or 0) for x in hg if isinstance(x, dict))
                print(f"  snapshot slots={len(hg)} image_roots={len(roots)} total_bytes={total}")
                for want in (0x141BF0, 0x148C98, 0x149D50):
                    hit = next(
                        (
                            x
                            for x in roots
                            if int(str(x.get("rva", "0")), 0) == want
                        ),
                        None,
                    )
                    if hit:
                        print(
                            f"    root {want:#x} size={hit.get('content_size')} live={hit.get('live_ptr')}"
                        )
                    else:
                        print(f"    root {want:#x}: NOT in snapshot")
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
