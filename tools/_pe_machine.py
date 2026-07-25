import struct
from pathlib import Path

files = list(Path(r"D:\MidaVault\scratch\materialized").glob("*.bin"))
for p in sorted(files):
    data = p.read_bytes()
    if len(data) < 0x40 or data[:2] != b"MZ":
        print(p.name, "not PE")
        continue
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        print(p.name, "bad PE")
        continue
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
    arch = {0x14C: "I386", 0x8664: "AMD64"}.get(machine, hex(machine))
    pe = {0x10B: "PE32", 0x20B: "PE32+"}.get(magic, hex(magic))
    print(f"{p.name}: machine={arch} optional={pe} size={len(data)}")
