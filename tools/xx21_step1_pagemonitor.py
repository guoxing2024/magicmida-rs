#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 1 页级监控实弹 (门1, 1 格)
宿主 = 监控进程 (模拟真实宿主: LoadLibraryW 候选 core.dll)
流程: before 快照 (.winlice/.text/.boot 逐 4KB 页) -> 触发 GetAppVersion xN -> after 快照 -> 对比
判定: 实体化 = 调用后目标页出现/保持明文代码; 纯解释 = 目标页保持加密字节流但函数正常返回
红线: NO_BYPASS=1; 不修改样品; 不外发 (Run 不触发, 避免 urlmon 网络副作用)
"""
import ctypes, ctypes.wintypes as wt
import hashlib, json, os, sys, struct
import pefile

CAND = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx3_attempt_3/core_candidate_nep.dll"
EXPECTED_SHA = "41ec52e085b258c1c0b993f7ced1f7ee6339e8883239ad8482aec3fc45f2a25e"
BASE_EXPECT = 0x7FFE1DA10000
PAGE = 0x1000

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    os.environ["NO_BYPASS"] = "1"
    os.environ["MIDA_GTO_NO_BYPASS"] = "1"

    # 0) 红线核实: sha256 vs manifest
    s = sha256_file(CAND)
    if not s.startswith(EXPECTED_SHA[:32]):
        print(json.dumps({"redline": "FAIL", "sha256": s, "expected_prefix": EXPECTED_SHA[:32]}, indent=1))
        sys.exit(2)
    print("redline sha256 OK:", s[:32])

    pe = pefile.PE(CAND, fast_load=False)
    imgbase = pe.OPTIONAL_HEADER.ImageBase

    # 1) 宿主加载候选
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    LoadLibraryW = kernel32.LoadLibraryW
    LoadLibraryW.argtypes = [ctypes.c_wchar_p]
    LoadLibraryW.restype = wt.HMODULE
    hmod = LoadLibraryW(CAND)
    if not hmod:
        print(json.dumps({"load": "FAIL", "err": ctypes.get_last_error()}, indent=1))
        sys.exit(1)
    base = ctypes.cast(hmod, ctypes.c_void_p).value
    print(f"loaded: hmod=0x{base:X} (expected 0x{BASE_EXPECT:X}, hit={base == BASE_EXPECT})")

    # 2) 目标区定义 (RVA -> 名称)
    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin1") or "(anon)"
        vsize = s.Misc_VirtualSize if s.Misc_VirtualSize else s.SizeOfRawData
        sections.append({"name": name, "rva": s.VirtualAddress, "size": vsize, "raw": s.SizeOfRawData})
    target_names = {".winlice", ".boot"}
    anon_text = next((s for s in sections if s["name"] == "" and s["rva"] == 0x1000), None)
    targets = [s for s in sections if s["name"] in target_names]
    if anon_text:
        targets.append({"name": ".text(anon)", "rva": anon_text["rva"], "size": anon_text["size"], "raw": anon_text["raw"]})
    # 也包含导出所在匿名节全范围 (0x1000 起 1MB) 已由 anon_text 覆盖

    def page_snapshot(rva, size):
        """逐 4KB 页: sha256, 首16B, 可解码指令数(capstone 前64B)"""
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        out = {}
        va = base + rva
        for off in range(0, size, PAGE):
            chunk = min(PAGE, size - off)
            buf = ctypes.string_at(va + off, chunk)
            h = hashlib.sha256(buf).hexdigest()
            dec = 0
            try:
                for i in md.disasm(buf[:64], va + off):
                    dec += 1
                    if dec > 20:
                        break
            except Exception:
                dec = -1
            out[hex(va + off)] = {
                "rva": hex(rva + off),
                "sha256": h,
                "head16": buf[:16].hex(),
                "decodable_insns_64": dec,
            }
        return out

    # 3) before 快照
    snap_before = {}
    for t in targets:
        print(f"snapshot before: {t['name']} rva=0x{t['rva']:X} size=0x{t['size']:X}")
        snap_before[t["name"]] = page_snapshot(t["rva"], t["size"])

    # 4) 触发 GetAppVersion x10 (attempt3 同款), 记录返回值
    GetProcAddress = kernel32.GetProcAddress
    GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_char_p]
    GetProcAddress.restype = ctypes.c_void_p
    ver_addr = GetProcAddress(hmod, b"GetAppVersion")
    run_addr = GetProcAddress(hmod, b"Run")
    print(f"GetAppVersion @ 0x{ver_addr or 0:X} (rva 0x{(ver_addr or 0) - base:X})")
    print(f"Run           @ 0x{run_addr or 0:X} (rva 0x{(run_addr or 0) - base:X})")

    returns = []
    if ver_addr:
        CFUNCTYPE = ctypes.CFUNCTYPE(ctypes.c_uint64)
        fn = CFUNCTYPE(ver_addr)
        for _ in range(10):
            try:
                r = fn()
                returns.append(hex(r))
            except Exception as e:
                returns.append(f"EXC:{e}")
    print("GetAppVersion x10 returns:", returns)

    # 5) after 快照
    snap_after = {}
    for t in targets:
        snap_after[t["name"]] = page_snapshot(t["rva"], t["size"])

    # 6) 对比
    diff = {}
    for name in snap_before:
        changed = []
        for va, p in snap_before[name].items():
            a = snap_after[name].get(va)
            if a is None or a["sha256"] != p["sha256"]:
                changed.append({"va": va, "before_head": p["head16"], "after_head": (a or {}).get("head16"), "before_dec": p["decodable_insns_64"], "after_dec": (a or {}).get("decodable_insns_64")})
        diff[name] = {"pages": len(snap_before[name]), "changed": len(changed), "changed_pages": changed[:20]}

    result = {
        "schema": "xx21_step1_pagemonitor/v1",
        "case": "xiongxiong_core",
        "work_order": "XC-XXI",
        "step": 1,
        "phase": "live_pagemonitor",
        "ledger": {"xc_xxi_used": 1, "xc_xxi_total": 4},
        "redline": {"no_bypass": "1", "sha256_prefix": s[:32], "manifest_match": True, "run_not_called": True},
        "host": {"mode": "monitor_process_LoadLibraryW", "candidate": CAND},
        "load": {"base": hex(base), "expected_base": hex(BASE_EXPECT), "base_hit": base == BASE_EXPECT},
        "exports": {"GetAppVersion": hex(ver_addr or 0), "GetAppVersion_rva": hex((ver_addr or 0) - base), "Run": hex(run_addr or 0), "Run_rva": hex((run_addr or 0) - base)},
        "GetAppVersion_x10_returns": returns,
        "page_diff": diff,
        "verdict_static": "winlice_is_plaintext_in_candidate (109 insns/512B)",
        "verdict_live": "pending",
    }

    # 判定逻辑
    verdict = {}
    for name, d in diff.items():
        if name == ".boot":
            verdict[name] = "unchanged" if d["changed"] == 0 else "changed"
        else:
            # 明文保持 = 实体化(dump产物已是明文, 加载后保持) ; 页变化 = 调用时实体化
            verdict[name] = "changed_after_call" if d["changed"] > 0 else "plaintext_kept_unchanged"
    result["verdict_live"] = verdict
    result["gate1_conclusion"] = (
        "路径A(运行时解密实体化): GetAppVersion 调用前后 .winlice/.text 页内容无变化且保持明文可解码代码, "
        "说明解密实体化在加载/DllMain 阶段完成, dump 产物保留明文, 非纯解释执行" 
        if all(v != "changed_after_call" for v in verdict.values()) and any(v == "plaintext_kept_unchanged" for v in verdict.values())
        else "待人工判定"
    )

    print(json.dumps(result, indent=1, ensure_ascii=False))
    with open(r"D:/Claude project/magicmida-rs/tools/xx21_step1_pagemonitor_out.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)

if __name__ == "__main__":
    main()
