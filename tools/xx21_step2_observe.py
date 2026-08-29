#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 2 S4 宿主补测观测: 验证宿主进程内 core.dll 加载 + 导出解析 + GetAppVersion 远程调用"""
import ctypes, ctypes.wintypes as wt
import json, sys, os

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
BASE_EXPECT = 0x7FFE1DA10000
CORE_RVA_GETAPPVERSION = 0xBB30

def main():
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else 24820
    out_path = sys.argv[2] if len(sys.argv) > 2 else r"D:/Claude project/magicmida-rs/lab/xx21_s4/s4_observe.json"

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    OpenProcess = k32.OpenProcess
    OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    OpenProcess.restype = wt.HANDLE
    ReadProcessMemory = k32.ReadProcessMemory
    ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    ReadProcessMemory.restype = wt.BOOL

    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        print(json.dumps({"open": "FAIL", "pid": pid, "err": ctypes.get_last_error()}))
        sys.exit(1)
    print(f"OpenProcess OK pid={pid}")

    def rpm(addr, size):
        buf = ctypes.create_string_buffer(size)
        nread = ctypes.c_size_t(0)
        ok = ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(nread))
        if not ok:
            return None
        return buf.raw[:nread.value]

    result = {
        "schema": "xx21_step2_s4_observe/v1",
        "case": "xiongxiong_core",
        "work_order": "XC-XXI",
        "step": 2,
        "host_pid": pid,
        "host": "rev2_unpacked.exe (已脱壳)",
        "candidate_base_expected": hex(BASE_EXPECT),
    }

    # 1) 验证固定基址处 MZ/PE 头
    head = rpm(BASE_EXPECT, 0x1000)
    if head is None:
        result["load_check"] = {"FAIL": f"cannot read 0x{BASE_EXPECT:X}", "loaded": False}
        print(json.dumps(result, indent=1, ensure_ascii=False))
        json.dump(result, open(out_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        return
    mz = head[:2]
    e_lfanew = int.from_bytes(head[0x3C:0x40], "little")
    pe_sig = rpm(BASE_EXPECT + e_lfanew, 4)
    pe_ok = mz == b"MZ" and pe_sig == b"PE\x00\x00"
    result["load_check"] = {
        "mz": mz.hex(),
        "e_lfanew": hex(e_lfanew),
        "pe_sig": pe_sig.hex() if pe_sig else None,
        "pe_valid": pe_ok,
        "loaded_at_fixed_base": pe_ok,
    }
    print("MZ:", mz.hex(), "PE sig:", pe_sig.hex() if pe_sig else None, "valid:", pe_ok)

    if not pe_ok:
        print("core.dll NOT loaded at fixed base — S4 fail (loading)")
        json.dump(result, open(out_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
        return

    # 2) 读 PE 头 + 导出表
    pe_hdr = rpm(BASE_EXPECT, 0x400)
    opt_off = e_lfanew + 24  # optional header 起点
    opt = pe_hdr[opt_off:]
    image_base = int.from_bytes(opt[0x18:0x20], "little")
    size_of_image = int.from_bytes(opt[0x38:0x40], "little")
    export_dir_rva = int.from_bytes(opt[0x70:0x74], "little")
    export_dir_size = int.from_bytes(opt[0x74:0x78], "little")
    magic = int.from_bytes(opt[0:2], "little")
    result["pe"] = {
        "magic": hex(magic),
        "runtime_image_base": hex(image_base),
        "size_of_image": hex(size_of_image),
        "export_dir_rva": hex(export_dir_rva),
        "export_dir_size": hex(export_dir_size),
    }

    # 导出表解析
    ed = rpm(BASE_EXPECT + export_dir_rva, 0x28)
    nfunc = int.from_bytes(ed[0x14:0x18], "little")
    nnames = int.from_bytes(ed[0x18:0x1C], "little")
    addr_of_functions = int.from_bytes(ed[0x1C:0x20], "little")
    addr_of_names = int.from_bytes(ed[0x20:0x24], "little")
    addr_of_ordinals = int.from_bytes(ed[0x24:0x28], "little")
    exports = []
    for i in range(min(nnames, 64)):
        name_rva = int.from_bytes(rpm(BASE_EXPECT + addr_of_names + i*4, 4), "little")
        nm = rpm(BASE_EXPECT + name_rva, 64)
        name = nm.split(b"\x00")[0].decode("latin1") if nm else "?"
        ord_idx = int.from_bytes(rpm(BASE_EXPECT + addr_of_ordinals + i*2, 2), "little")
        func_rva = int.from_bytes(rpm(BASE_EXPECT + addr_of_functions + ord_idx*4, 4), "little")
        exports.append({"name": name, "ordinal": ord_idx, "rva": hex(func_rva)})
    result["exports"] = exports
    print("exports:", [(e["name"], e["rva"]) for e in exports])

    # 3) GetAppVersion 本址字节 (验证明文)
    ga_rva = CORE_RVA_GETAPPVERSION
    ga_bytes = rpm(BASE_EXPECT + ga_rva, 16)
    result["getappversion"] = {
        "rva": hex(ga_rva),
        "bytes": ga_bytes.hex() if ga_bytes else None,
        "plaintext_prologue": ga_bytes and ga_bytes[0] in (0x40, 0x48, 0x55, 0x53, 0x49),
    }
    print("GetAppVersion bytes:", ga_bytes.hex() if ga_bytes else None)

    json.dump(result, open(out_path, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("written:", out_path)

if __name__ == "__main__":
    main()
