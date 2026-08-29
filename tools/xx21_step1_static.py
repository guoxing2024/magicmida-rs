#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 1 离线静态分析: 候选 NEP DLL 导出初始化路径 vs .winlice VM handler"""
import pefile
import json
import sys
from capstone import *

CAND = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx3_attempt_3/core_candidate_nep.dll"

def sec_for_rva(pe, rva):
    for s in pe.sections:
        v = s.VirtualAddress
        vs = s.Misc_VirtualSize if s.Misc_VirtualSize else s.SizeOfRawData
        if v <= rva < v + vs:
            return s.Name.rstrip(b"\x00").decode("latin1"), rva - v
    return "?", rva

def main():
    pe = pefile.PE(CAND, fast_load=False)
    out = {
        "schema": "xx21_step1_static/v1",
        "candidate": CAND,
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "sections": [],
        "exports": [],
        "disasm": {},
    }
    for s in pe.sections:
        out["sections"].append({
            "name": s.Name.rstrip(b"\x00").decode("latin1"),
            "va": hex(pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress),
            "rva": hex(s.VirtualAddress),
            "vsize": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData,
            "raw_ptr": s.PointerToRawData,
            "chars": hex(s.Characteristics),
        })
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if e.address:
                out["exports"].append({
                    "name": e.name.decode("latin1") if e.name else f"ord{e.ordinal}",
                    "rva": hex(e.address),
                    "va": hex(pe.OPTIONAL_HEADER.ImageBase + e.address),
                    "section": sec_for_rva(pe, e.address),
                })

    # 反汇编 GetAppVersion@0xBB30 / Run@0x1C120 初始化路径
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    targets = {}
    for e in out["exports"]:
        rva = int(e["rva"], 16)
        targets[e["name"]] = rva

    # 关键地址: attempt4 指向 0x1e918/0xff940/0x1e920 (RVA 假设)
    probe_entries = [
        ("GetAppVersion", targets.get("GetAppVersion", 0xBB30)),
        ("Run", targets.get("Run", 0x1C120)),
    ]
    for name, rva in probe_entries:
        sec, off = sec_for_rva(pe, rva)
        data = pe.get_memory_mapped_image()[rva:rva + 0x200]
        insns = []
        for i in md.disasm(data, pe.OPTIONAL_HEADER.ImageBase + rva):
            insns.append({
                "addr": hex(i.address),
                "rva": hex(i.address - pe.OPTIONAL_HEADER.ImageBase),
                "mnem": i.mnemonic,
                "op": i.op_str,
                "sec": sec_for_rva(pe, i.address - pe.OPTIONAL_HEADER.ImageBase)[0],
            })
            if len(insns) >= 80:
                break
        out["disasm"][f"{name}@{hex(rva)}"] = {
            "section": sec,
            "instructions": insns,
        }

    # 关键地址归属 (.winlice?)
    for key, rva in [("candidate_init_0x1e918", 0x1e918), ("candidate_init_0xff940", 0xff940), ("candidate_init_0x1e920", 0x1e920)]:
        out[key] = sec_for_rva(pe, rva)

    print(json.dumps(out, indent=1, ensure_ascii=False))

if __name__ == "__main__":
    main()
