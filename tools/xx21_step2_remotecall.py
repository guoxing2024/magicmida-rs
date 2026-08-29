#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 2 S4 宿主补测: 远程线程调用宿主进程内 core.dll 的 GetAppVersion
验证: 业务调用链真实返回 (非 AV)。Run 不触发 (urlmon 网络副作用, 对齐 attempt3 决策)。
"""
import ctypes, ctypes.wintypes as wt
import json, sys, time

PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
BASE = 0x7FFE1DA10000
GETAPPVERSION_VA = BASE + 0xBB30

def main():
    pid = int(sys.argv[1])
    out_path = sys.argv[2]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    OpenProcess = k32.OpenProcess
    OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    OpenProcess.restype = wt.HANDLE
    CreateRemoteThread = k32.CreateRemoteThread
    CreateRemoteThread.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.LPVOID, wt.LPVOID, wt.DWORD, wt.LPDWORD]
    CreateRemoteThread.restype = wt.HANDLE
    WaitForSingleObject = k32.WaitForSingleObject
    WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    WaitForSingleObject.restype = wt.DWORD
    GetExitCodeThread = k32.GetExitCodeThread
    GetExitCodeThread.argtypes = [wt.HANDLE, wt.LPDWORD]
    GetExitCodeThread.restype = wt.BOOL
    VirtualAllocEx = k32.VirtualAllocEx
    VirtualAllocEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD]
    VirtualAllocEx.restype = wt.LPVOID
    CloseHandle = k32.CloseHandle
    CloseHandle.argtypes = [wt.HANDLE]
    CloseHandle.restype = wt.BOOL

    h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, False, pid)
    if not h:
        print(json.dumps({"open": "FAIL", "pid": pid, "err": ctypes.get_last_error()}))
        sys.exit(1)

    result = {
        "schema": "xx21_step2_s4_remotecall/v1",
        "case": "xiongxiong_core",
        "work_order": "XC-XXI",
        "step": 2,
        "host_pid": pid,
        "calls": [],
    }

    # 远程线程调用 GetAppVersion (无参数, 返回 rax)
    for i in range(3):
        tid = wt.DWORD(0)
        hThread = CreateRemoteThread(h, None, 0, ctypes.c_void_p(GETAPPVERSION_VA), None, 0, ctypes.byref(tid))
        if not hThread:
            result["calls"].append({"iter": i, "status": f"CreateRemoteThread FAIL err={ctypes.get_last_error()}"})
            continue
        wr = WaitForSingleObject(hThread, 10000)
        if wr != 0:
            result["calls"].append({"iter": i, "status": f"WAIT_TIMEOUT/FAIL wr={wr}"})
            CloseHandle(hThread)
            continue
        code = wt.DWORD(0)
        GetExitCodeThread(hThread, ctypes.byref(code))
        CloseHandle(hThread)
        result["calls"].append({
            "iter": i,
            "function": "GetAppVersion",
            "va": hex(GETAPPVERSION_VA),
            "rva": hex(0xBB30),
            "exit_code": hex(code.value),
            "expected": "0x1DB4C4C0",
            "match_expected": (code.value & 0xFFFFFFFF) == 0x1DB4C4C0,
            "non_av": code.value != 0xC0000005,
        })
        time.sleep(0.1)

    # 汇总判定
    calls = result["calls"]
    ok = [c for c in calls if c.get("match_expected")]
    result["verdict"] = {
        "GetAppVersion_called": len(calls) > 0,
        "all_match_expected": len(ok) == len(calls) and len(calls) > 0,
        "any_av": any(c.get("exit_code") == "0xc0000005" for c in calls),
        "Run_called": False,
        "note": "Run 不主动触发 (urlmon.URLDownloadToFileA 网络副作用, 对齐 attempt3 决策)",
    }
    print(json.dumps(result, indent=1, ensure_ascii=False))
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)

if __name__ == "__main__":
    main()
