#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 1 静态分析深度: 0x1e918/0xff940/0x1e920 目标归属 + .winlice 引用关系"""
import pefile
import json
from capstone import *

CAND = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx3_attempt_3/core_candidate_nep.dll"
BASE = 0x7ffe1da10000

def main():
    pe = pefile.PE(CAND, fast_load=False)
    image = pe.get_memory_mapped_image()
    out = {"schema": "xx21_step1_static_deep/v1"}

    def sec_of(rva):
        for s in pe.sections:
            v = s.VirtualAddress
            vs = s.Misc_VirtualSize if s.Misc_VirtualSize else s.SizeOfRawData
            if v <= rva < v + vs:
                return s.Name.rstrip(b"\x00").decode("latin1") or "(anon)", rva - v
        return "?", rva

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def disasm(rva, n=40, label=""):
        data = image[rva:rva + 0x400]
        insns = []
        for i in md.disasm(data, BASE + rva):
            insns.append({
                "rva": hex(i.address - BASE),
                "mnem": i.mnemonic,
                "op": i.op_str,
                "sec": sec_of(i.address - BASE)[0],
            })
            if len(insns) >= n:
                break
        return insns

    # 三个被调目标
    for name, rva in [("init_0x1e918", 0x1e918), ("init_0xff940", 0xff940), ("init_0x1e920", 0x1e920), ("init_0x1e910", 0x1e910)]:
        out[name] = {
            "section": sec_of(rva),
            "head_bytes": image[rva:rva+16].hex(),
            "insns": disasm(rva, 30),
        }

    # .winlice 内容检查: 是否为明文 VM 代码(可反汇编) vs 乱码
    win_rva = 0x198000
    win_bytes = image[win_rva:win_rva+0x200]
    # 统计可解码指令比例
    code_bytes = 0
    total = 0
    for i in md.disasm(win_bytes, BASE + win_rva):
        code_bytes += i.size
        total += 1
    out["winlice"] = {
        "rva": hex(win_rva),
        "size": 0x708000,
        "first_bytes": win_bytes[:64].hex(),
        "decodable_in_first_512": code_bytes,
        "total_insns_512": total,
        "section": sec_of(win_rva),
    }
    # 熵 (抽样)
    import math
    ent = 0.0
    for off in range(win_rva, win_rva + 0x10000, 0x1000):
        blk = image[off:off+0x1000]
        if not blk:
            continue
        hist = [0]*256
        for b in blk:
            hist[b] += 1
        for c in hist:
            if c:
                p = c/len(blk)
                ent -= p*math.log2(p)
    out["winlice_entropy_avg_first64k"] = round(ent/16, 3)

    # .boot 检查
    boot_rva = 0x8a0000
    boot_bytes = image[boot_rva:boot_rva+0x100]
    out["boot"] = {
        "rva": hex(boot_rva),
        "first_bytes": boot_bytes[:64].hex(),
    }

    print(json.dumps(out, indent=1, ensure_ascii=False))

if __name__ == "__main__":
    main()
