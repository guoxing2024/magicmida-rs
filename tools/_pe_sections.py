# -*- coding: utf-8 -*-
import struct
import sys
from pathlib import Path

p = Path(sys.argv[1])
b = p.read_bytes()
e_lfanew = struct.unpack_from("<I", b, 0x3C)[0]
coff = e_lfanew + 4
machine, nsec, _, _, _, optsize, chars = struct.unpack_from("<HHIIIHH", b, coff)
magic = struct.unpack_from("<H", b, coff + 20)[0]
opt = coff + 20
if magic == 0x20B:
    image_base = struct.unpack_from("<Q", b, opt + 24)[0]
    entry = struct.unpack_from("<I", b, opt + 16)[0]
else:
    image_base = struct.unpack_from("<I", b, opt + 28)[0]
    entry = struct.unpack_from("<I", b, opt + 16)[0]
sect = opt + optsize
print(f"machine={machine:#x} nsec={nsec} magic={magic:#x} entry={entry:#x} image_base={image_base:#x}")
for i in range(nsec):
    off = sect + i * 40
    name = b[off : off + 8].split(b"\x00")[0].decode("latin1", "replace")
    vsize, va, rsize, ro = struct.unpack_from("<IIII", b, off + 8)
    chars_s = struct.unpack_from("<I", b, off + 36)[0]
    print(f"{i}: name={name!r} va={va:#x} vsize={vsize:#x} rsize={rsize:#x} ro={ro:#x} chars={chars_s:#x}")
