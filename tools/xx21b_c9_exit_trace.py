#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TASK-023 (D-046) C-9 根因诊断: int3 退出漏斗断点 + 候选 EP 判别位 → 退出决策者归属表

fork 自 tools/xx21b_t05_ui_drive_pcell.py (T022), 保留全部红线机制:
  sha fail-closed / NO_BYPASS=1 / 导出动态解析零硬编码 / 泵线程全量即时消费 + ndjson 边到边落盘 /
  泵健康自证 / EXCEPTION 全记录 / 防火墙只读核实 / MZ 双核 / 临时文件清理。

本版新增 (TASK-023 票面, 诊断 only 不许修任何东西):
  1) 退出漏斗断点 (全部动态解析, 零硬编码):
       kernel32!ExitProcess / kernel32!TerminateProcess / ntdll!RtlExitUserProcess / ntdll!NtTerminateProcess
       —— 导出 RVA 从 C:\\Windows\\System32\\ntdll.dll / kernel32.dll 磁盘导出表解析;
          运行时 VA = 磁盘RVA + 进程内模块基址 (LOAD_DLL 事件识别 + 导出存在性/MZ 双核验证, 不用绝对地址常量)。
  2) 候选 EP 判别位: EP RVA 从候选 disk PE 头动态读 (T022: 0x1027c0 NOP stub 31c0ffc0c3);
       VA = 候选加载基址 + EP RVA, 在 core.dll LOAD_DLL 事件后布置; 命中 = DllMain (NOP stub) 被调用。
  3) int3 引擎: WriteProcessMemory 写 0xCC (原字节留存) + FlushInstructionCache; 命中
       (EXCEPTION_BREAKPOINT, 真地址 = Rip-1) → 法证记录: 模块归属 (enum_modules + MZ 双核) / 全寄存器
       (GetThreadContext CONTEXT_CONTROL|CONTEXT_INTEGER = 0x100003) / 栈链 rsp[0..16] qword 逐个模块归属 /
       命中断点名; 恢复原字节 + Rip 回退 1 + TF 单步重布 (re-arm); re-arm 失败降级 fire-once。
  4) 两种运行模式:
       --mode=verify: host_loader 隔离加载候选 (S3 同款, 预期存活), 断点全布 —— 预期 0 退出漏斗命中
           (EP 判别位预期 1-2 次命中 = DllMain attach/detach 被调用, 正控制, 证明法证链可用; 非误触发);
       --mode=diag: rev2 宿主 a852880a + 候选 096f3bdf + config cde9be13, 泵 + 断点全布, ≥3 趟。
  5) 判定产出 (核心交付): 退出链命中序列 / 退出决策者归属 (最外层漏斗命中 [rsp] 返回地址 →
       host-image | candidate-image | ntdll-loader | other, 附 RVA) / EP 判别位结果 / 栈链 RVA 明细。

[诊断趟关键语义 — 实测校准 (standalone_diag)]: 当被调试进程调用 ExitProcess(0) 时, 调试泵收到
  EXIT_PROCESS_DEBUG_EVENT (code 5, exitCode 0), 但进程在调试器 ContinueDebugEvent 完成拆解前
  外部 OpenProcess 仍可成功 (调试器冻结的僵尸窗口)。因此泵侧 EXIT_PROCESS = "退出决策已作出
  (ExitProcess 已被调用)", 而非"进程已消失"。int3 退出漏斗断点在 ExitProcess 调用发生时即命中
  (先于 EXIT_PROCESS 事件), 法证链完整。这正是 T022 记录的 C-9 "exit 0" 的本质: 退出决策真实存在,
  本工具定位其调用者。

红线: NO_BYPASS=1; 样品 sha 不匹配即 STOP; 样品不外发; 禁止伪造证据; 防火墙只读; git 只读 (不 commit/push);
      不新增依赖 (ctypes/标准库); crates/ 一行未动; 既有脚本零改动 (本文件为新 fork);
      int3 仅内存驻留 (WriteProcessMemory 写调试目标进程内存, 命中后恢复原字节; 磁盘文件零改动;
      部署件 sha 前后双验) — 标准调试器实践 (T015 引擎同族); 若仪器化改变行为 (退出模式偏离 T022 基线,
      如出现 AV) → 如实记录 → STOP。
"""
import ctypes, ctypes.wintypes as wt
import json, os, sys, time, subprocess, hashlib, datetime, threading
import struct

# ---------------- 常量 ----------------
# TASK-025 (D-050) 变体部署目录: lab/xx21b_boot (宿主 a852880a + 变体 core_shell_bootstrap_variant.dll + config cde9be13)
# 诊断趟目标 = rev2 宿主 + 变体 core.dll (EP 0x8a0108); CORE 路径为部署的 core.dll (= 变体副本, CAND_SHA = 变体 sha)
DEPLOY = r"D:\Claude project\magicmida-rs\lab\xx21b_boot"
HOST = os.path.join(DEPLOY, "rev2_unpacked.exe")
CORE = os.path.join(DEPLOY, "core.dll")
CONFIG = os.path.join(DEPLOY, "config.ini")
CAND_SHA = "7b47011799c3233024fd8b00cfea2fafd8f9f92daac1a5aacb20d56df0e0b585"  # TASK-025 变体 (096f3bdf + EP 0x8a0108)
HOST_SHA = "a852880aabba215b16a2a96245322ca09d19ff148afaa30ff42b1a8ea438edac"
CONFIG_SHA = "cde9be13a5da62f5805cbf3b359c56c27f020d12cd1ae838f6a4218492d1d610"
HOST_LOADER = r"D:\Claude project\magicmida-rs\lab\xx21b_repro\host_loader.exe"  # S3 同款隔离加载器
NTDLL_DISK = r"C:\Windows\System32\ntdll.dll"
K32_DISK = r"C:\Windows\System32\kernel32.dll"
# 退出漏斗: (导出名, 宿主模块 basename, 磁盘路径)
FUNNEL = [
    ("ExitProcess", "kernel32.dll", K32_DISK),
    ("TerminateProcess", "kernel32.dll", K32_DISK),
    ("RtlExitUserProcess", "ntdll.dll", NTDLL_DISK),
    ("NtTerminateProcess", "ntdll.dll", NTDLL_DISK),
]
# 旧 (dump 会话) 死区间, 用于 AV 地址标注 (T021/T022 同口径, 诊断基线对照)
OLD_NTDLL_DEAD = (0x7FFEEB320000, 0x300000)
OLD_URLMON_DEAD = (0x7FFEC48F0000, 0x1DD000)

# 进程/线程权限
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002

# 调试常量
DEBUG_ONLY_THIS_PROCESS = 0x2
CREATE_UNICODE_ENVIRONMENT = 0x400
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
WAIT_TIMEOUT_ERR = 121  # ERROR_SEM_TIMEOUT
CONTEXT_CONTROL_AMD64 = 0x100001
CONTEXT_CONTROL_INTEGER_AMD64 = 0x100003
DBG_EVENT_NAMES = {
    1: "EXCEPTION_DEBUG_EVENT", 2: "CREATE_THREAD_DEBUG_EVENT", 3: "CREATE_PROCESS_DEBUG_EVENT",
    4: "EXIT_THREAD_DEBUG_EVENT", 5: "EXIT_PROCESS_DEBUG_EVENT", 6: "LOAD_DLL_DEBUG_EVENT",
    7: "RIP_EVENT", 8: "OUTPUT_DEBUG_STRING_EVENT", 9: "UNLOAD_DLL_DEBUG_EVENT",
}
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004
# [T018-实测] 0xc000008e = STATUS_FLOAT_MULTIPLE_FAULTS 引导期良性首机会异常 (DBG_CONTINUE 被动观测);
# 0x80000003 首个引导断点 (LdrpDoDebuggerBreak, 非本工具布点) 亦良性。
BENIGN_BOOT_EXCEPTIONS = (EXCEPTION_BREAKPOINT, 0xc000008e)
BP_MAX_HITS = 4  # 每断点 re-arm 命中预算 (单次退出链 2-4 调用; 超出自动 fire-once)


# ---------------- 调试事件结构体 ----------------
class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", ctypes.c_uint32), ("ExceptionFlags", ctypes.c_uint32),
                ("ExceptionRecord", ctypes.c_void_p), ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", ctypes.c_uint32),
                ("ExceptionInformation", ctypes.c_uint64 * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", ctypes.c_uint32)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", ctypes.c_void_p), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", ctypes.c_void_p), ("hProcess", ctypes.c_void_p), ("hThread", ctypes.c_void_p),
                ("lpBaseOfImage", ctypes.c_void_p), ("dwDebugInfoFileOffset", ctypes.c_uint32),
                ("nDebugInfoSize", ctypes.c_uint32), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p), ("lpImageName", ctypes.c_void_p),
                ("fUnicode", ctypes.c_uint16)]


class EXIT_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", ctypes.c_uint32)]


class EXIT_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("dwExitCode", ctypes.c_uint32)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", ctypes.c_void_p), ("lpBaseOfDll", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", ctypes.c_uint32), ("nDebugInfoSize", ctypes.c_uint32),
                ("lpImageName", ctypes.c_void_p), ("fUnicode", ctypes.c_uint16)]


class OUTPUT_DEBUG_STRING_INFO(ctypes.Structure):
    _fields_ = [("lpDebugStringData", ctypes.c_void_p), ("fUnicode", ctypes.c_uint16),
                ("nDebugStringLength", ctypes.c_uint16)]


class UNLOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p)]


class RIP_INFO(ctypes.Structure):
    _fields_ = [("dwError", ctypes.c_uint32), ("dwType", ctypes.c_uint32)]


class DEBUG_EVENT_U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO), ("ExitThread", EXIT_THREAD_DEBUG_INFO),
                ("ExitProcess", EXIT_PROCESS_DEBUG_INFO), ("LoadDll", LOAD_DLL_DEBUG_INFO),
                ("OutputDebugString", OUTPUT_DEBUG_STRING_INFO), ("RipInfo", RIP_INFO),
                ("UnloadDll", UNLOAD_DLL_DEBUG_INFO)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", ctypes.c_uint32), ("dwProcessId", ctypes.c_uint32),
                ("dwThreadId", ctypes.c_uint32), ("u", DEBUG_EVENT_U)]


class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wt.DWORD), ("lpReserved", ctypes.c_wchar_p), ("lpDesktop", ctypes.c_wchar_p),
                ("lpTitle", ctypes.c_wchar_p), ("dwX", wt.DWORD), ("dwY", wt.DWORD),
                ("dwXSize", wt.DWORD), ("dwYSize", wt.DWORD), ("dwXCountChars", wt.DWORD),
                ("dwYCountChars", wt.DWORD), ("dwFillAttribute", wt.DWORD), ("dwFlags", wt.DWORD),
                ("wShowWindow", wt.WORD), ("cbReserved2", wt.WORD), ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
                ("hStdInput", wt.HANDLE), ("hStdOutput", wt.HANDLE), ("hStdError", wt.HANDLE)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wt.HANDLE), ("hThread", wt.HANDLE), ("dwProcessId", wt.DWORD), ("dwThreadId", wt.DWORD)]


class CONTEXT(ctypes.Structure):
    _fields_ = [("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
                ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
                ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
                ("ContextFlags", ctypes.c_ulong), ("MxCsr", ctypes.c_ulong),
                ("SegCs", ctypes.c_ushort), ("SegDs", ctypes.c_ushort),
                ("SegEs", ctypes.c_ushort), ("SegFs", ctypes.c_ushort),
                ("SegGs", ctypes.c_ushort), ("SegSs", ctypes.c_ushort),
                ("EFlags", ctypes.c_ulong), ("Dr0", ctypes.c_uint64),
                ("Dr1", ctypes.c_uint64), ("Dr2", ctypes.c_uint64),
                ("Dr3", ctypes.c_uint64), ("Dr6", ctypes.c_uint64),
                ("Dr7", ctypes.c_uint64), ("Rax", ctypes.c_uint64),
                ("Rcx", ctypes.c_uint64), ("Rdx", ctypes.c_uint64),
                ("Rbx", ctypes.c_uint64), ("Rsp", ctypes.c_uint64),
                ("Rbp", ctypes.c_uint64), ("Rsi", ctypes.c_uint64),
                ("Rdi", ctypes.c_uint64), ("R8", ctypes.c_uint64),
                ("R9", ctypes.c_uint64), ("R10", ctypes.c_uint64),
                ("R11", ctypes.c_uint64), ("R12", ctypes.c_uint64),
                ("R13", ctypes.c_uint64), ("R14", ctypes.c_uint64),
                ("R15", ctypes.c_uint64), ("Rip", ctypes.c_uint64)]


class MODULEINFO(ctypes.Structure):
    _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", ctypes.c_ulong),
                ("EntryPoint", ctypes.c_void_p)]


class bp:
    """单个 int3 断点状态。"""
    __slots__ = ("name", "va", "mod_name", "orig_byte", "armed", "hits", "fire_once",
                 "armed_at", "disabled")

    def __init__(self, name, va, mod_name):
        self.name = name
        self.va = int(va)
        self.mod_name = mod_name
        self.orig_byte = None
        self.armed = False
        self.hits = 0
        self.fire_once = False
        self.armed_at = None
        self.disabled = None


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def now_utc():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class runtime:
    def __init__(self):
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.proc = None
        self.pid = None
        self.pi = None
        self.hproc = None
        self.main_hthread = None
        self.main_hprocess = None
        self.modules = []          # [(base, size, name)]
        self.events = []           # [{t, kind, detail}] 主线时间线
        self.t0 = 0
        # ---- 动态解析结果 ----
        self.funnel_rvas = {}      # {export_name: rva}
        self.ep_rva = None         # 候选 EP RVA (disk PE 头动态读)
        self.cand_preferred_base = None  # 候选 PE 头 ImageBase
        self.export_parse_err = None
        # ---- int3 引擎状态 ----
        self.bps = []              # [bp]
        self.bp_by_va = {}         # va(int) -> bp
        self.bp_pending = {}       # tid -> bp (TF 单步重布中)
        self.bp_hits = []          # 法证记录 [{...}]
        self.bp_mode = "rearm"     # rearm (TF) | fire_once
        self.rearm_failures = []
        self.funnel_armed = False
        self.ep_armed = False
        self.mod_base = {}         # basename -> base (LOAD_DLL 识别)
        self.core_load_base = None
        self.core_load_trigger = None  # name | preferred_base
        # ---- 泵共享态 ----
        self.pump_lock = threading.Lock()
        self.pump_stop = threading.Event()
        self.pump_thread = None
        self.pump_started = False
        self.pump_health = {
            "total": 0, "continues": 0, "continue_fails": 0, "wait_errors": [],
            "by_code": {}, "last_consume_t": None, "pump_exited": False,
            "first_breakpoint_seen": False, "create_failed": False, "create_err": None,
        }
        self.dbg_events = []
        self.dbg_events_lock = threading.Lock()
        self._pump_event_fd = None
        self._pump_event_path = None
        self._bp_hits_fd = None
        self._bp_hits_path = None
        self.pump_created = threading.Event()
        self.thread_handles = {}
        self.exceptions = []
        self.pump_exit_code = None
        self.pump_process_exited = False
        self.ctx_lock = threading.Lock()
        self._closed_handles = set()
        self.freeze_symptoms = []
        self.attach_changed_behavior = False
        self.windows = []
        # ctypes 签名 (int3 引擎用)
        self.k32.WriteProcessMemory.restype = wt.BOOL
        self.k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.k32.FlushInstructionCache.restype = wt.BOOL
        self.k32.FlushInstructionCache.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t]
        self.k32.SetThreadContext.restype = wt.BOOL
        self.k32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT)]
        self.k32.GetThreadContext.restype = wt.BOOL
        self.k32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT)]

    # ================= 基础内存 API (调试句柄, 泵内可用) =================
    def rpm_handle(self, handle, addr, size):
        if not handle:
            return None
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        if not self.k32.ReadProcessMemory(wt.HANDLE(handle), ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
            return None
        return buf.raw[:n.value]

    def read_qword_handle(self, handle, addr):
        b = self.rpm_handle(handle, addr, 8)
        return int.from_bytes(b, "little") if b else None

    def wpm(self, handle, addr, data):
        if not handle:
            return False
        buf = ctypes.create_string_buffer(data)
        n = ctypes.c_size_t(0)
        ok = self.k32.WriteProcessMemory(wt.HANDLE(handle), ctypes.c_void_p(addr), buf, len(data),
                                         ctypes.byref(n))
        return bool(ok) and n.value == len(data)

    def open_proc(self):
        self.hproc = self.k32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, False, self.pid)
        return bool(self.hproc)

    def rpm(self, addr, size):
        return self.rpm_handle(self.hproc, addr, size)

    def read_qword(self, addr):
        return self.read_qword_handle(self.hproc, addr)

    # ================= 模块枚举 + 归属 (MZ 双核) =================
    def enum_modules(self, handle=None):
        h = handle or self.hproc
        if not h:
            return []
        MAX = 2048
        arr = (ctypes.c_void_p * MAX)()
        cb = ctypes.c_ulong(0)
        if not self.psapi.EnumProcessModulesEx(wt.HANDLE(h), arr, ctypes.sizeof(arr), ctypes.byref(cb), 3):
            return []
        cnt = cb.value // ctypes.sizeof(ctypes.c_void_p)
        mods = []
        for i in range(min(cnt, MAX)):
            hmod = arr[i]
            name_buf = ctypes.create_unicode_buffer(520)
            self.psapi.GetModuleFileNameExW(wt.HANDLE(h), ctypes.c_void_p(hmod), name_buf, 520)
            mi = MODULEINFO()
            ok = self.psapi.GetModuleInformation(wt.HANDLE(h), ctypes.c_void_p(hmod), ctypes.byref(mi),
                                                 ctypes.sizeof(mi))
            base = mi.lpBaseOfDll if ok else hmod
            size = mi.SizeOfImage if ok else 0
            mods.append((int(base), int(size), os.path.basename(name_buf.value)))
        mods.sort(key=lambda m: m[0])
        self.modules = mods
        return mods

    def owner_of(self, addr, mods):
        if not addr:
            return None
        for base, size, name in mods:
            if base <= addr < base + size:
                return name
        return "unknown"

    def attr_detail(self, addr, mods, handle):
        """地址归属: {module, rva, mz} (MZ 双核: 归属模块基址读 MZ 复核)。"""
        if not addr:
            return None
        name = self.owner_of(addr, mods)
        base = None
        for b, s, n in mods:
            if n == name:
                base = b
                break
        mz = False
        if base is not None:
            h = self.rpm_handle(handle, base, 2)
            mz = bool(h and h[:2] == b"MZ")
        rva = (addr - base) if base is not None and addr >= base else None
        return {"addr": hex(addr), "module": name, "base": hex(base) if base else None,
                "rva": hex(rva) if rva is not None else None, "mz": mz}

    def stack_walk(self, rsp, mods, handle, n=17):
        """栈链 rsp[0..16] qword 逐个模块归属 (含 RVA)。"""
        out = []
        for i in range(n):
            a = (rsp or 0) + i * 8
            q = self.read_qword_handle(handle, a)
            if q is None:
                break
            out.append({"idx": i, "addr": hex(a), "qword": hex(q),
                        "attr": self.attr_detail(q, mods, handle)})
        return out

    # ================= PE 解析 (磁盘 + 内存) =================
    def _pe_dirs(self, image):
        """读 PE 头: 返回 (image_base, sections, data_dirs, pe32plus, dllchars)。"""
        if len(image) < 0x40 or image[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
        if e_lfanew + 0x18 > len(image) or image[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            return None
        opt_off = e_lfanew + 4 + 20
        magic = struct.unpack_from("<H", image, opt_off)[0]
        if magic not in (0x10b, 0x20b):
            return None
        pe32plus = magic == 0x20b
        if pe32plus:
            imgbase = struct.unpack_from("<Q", image, opt_off + 0x18)[0]
            dllchars_off = opt_off + 0x5E
            nsec_off = opt_off + 0x6C
            sec_off = opt_off + 0xF0
        else:
            imgbase = struct.unpack_from("<I", image, opt_off + 0x1C)[0]
            dllchars_off = opt_off + 0x46
            nsec_off = opt_off + 0x60
            sec_off = opt_off + 0xE0
        dllchars = struct.unpack_from("<H", image, dllchars_off)[0]
        ndirs = struct.unpack_from("<I", image, nsec_off)[0]
        nsec = struct.unpack_from("<H", image, e_lfanew + 6)[0]
        dirs = []
        for i in range(min(ndirs, 16)):
            rva, sz = struct.unpack_from("<II", image, opt_off + (0x70 if pe32plus else 0x60) + i * 8)
            dirs.append((rva, sz))
        secs = []
        for i in range(nsec):
            o = sec_off + i * 40
            name = image[o:o + 8].rstrip(b"\0").decode('latin1')
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", image, o + 8)
            secs.append((name, vaddr, vsize, roff, rsize))
        return (imgbase, secs, dirs, pe32plus, dllchars)

    @staticmethod
    def _rva2off(secs, rva):
        for name, vaddr, vsize, roff, rsize in secs:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return roff + (rva - vaddr)
        return None

    def resolve_exports_disk_file(self, path):
        """从磁盘 PE 文件解析导出表 {name: rva}。失败置 self.export_parse_err。"""
        try:
            image = open(path, "rb").read()
        except Exception as e:
            self.export_parse_err = "open %s failed: %r" % (path, e)
            return {}
        pe = self._pe_dirs(image)
        if not pe:
            self.export_parse_err = "PE parse failed: %s" % path
            return {}
        _, secs, dirs, _, _ = pe
        exp_rva, exp_size = dirs[0]
        if not exp_rva:
            self.export_parse_err = "export dir missing: %s" % path
            return {}
        off = self._rva2off(secs, exp_rva)
        if off is None:
            self.export_parse_err = "export dir rva %#x not in sections (%s)" % (exp_rva, path)
            return {}
        try:
            nnames = struct.unpack_from("<I", image, off + 24)[0]
            afuncs = struct.unpack_from("<I", image, off + 28)[0]
            anames = struct.unpack_from("<I", image, off + 32)[0]
            aords = struct.unpack_from("<I", image, off + 36)[0]
        except Exception as e:
            self.export_parse_err = "export dir read failed (%s): %r" % (path, e)
            return {}
        noff = self._rva2off(secs, anames)
        ordoff = self._rva2off(secs, aords)
        funcoff = self._rva2off(secs, afuncs)
        if noff is None or ordoff is None or funcoff is None:
            self.export_parse_err = "export arrays not mappable (%s)" % path
            return {}
        res = {}
        for i in range(min(nnames, 4096)):
            nrva = struct.unpack_from("<I", image, noff + i * 4)[0]
            oi = struct.unpack_from("<H", image, ordoff + i * 2)[0]
            frva = struct.unpack_from("<I", image, funcoff + oi * 4)[0]
            noff2 = self._rva2off(secs, nrva)
            if noff2 is None:
                continue
            nm = image[noff2:noff2 + 64].split(b"\0")[0].decode('latin1', 'replace')
            res[nm] = frva
        return res

    def _mem_exports(self, base, handle=None):
        """从进程内存映像读导出表 {name: rva} (rva 平铺映射: mem = base + rva)。"""
        h = handle or self.main_hprocess
        head = self.rpm_handle(h, base, 0x1000)
        if not head or head[:2] != b"MZ":
            return {}
        pe = self._pe_dirs(head)
        if not pe:
            return {}
        _, _, dirs, _, _ = pe
        exp_rva, exp_size = dirs[0]
        if not exp_rva:
            return {}

        def mem_read(rva, n):
            return self.rpm_handle(h, base + rva, n)

        ed = mem_read(exp_rva, 40)
        if not ed:
            return {}
        nnames = struct.unpack_from("<I", ed, 24)[0]
        afuncs = struct.unpack_from("<I", ed, 28)[0]
        anames = struct.unpack_from("<I", ed, 32)[0]
        aords = struct.unpack_from("<I", ed, 36)[0]
        res = {}
        for i in range(min(nnames, 4096)):
            nrva_b = mem_read(anames + i * 4, 4)
            oi_b = mem_read(aords + i * 2, 2)
            frva_b = mem_read(afuncs + struct.unpack_from("<H", oi_b, 0)[0] * 4, 4) if oi_b else None
            if not nrva_b or not frva_b:
                continue
            nrva = struct.unpack_from("<I", nrva_b, 0)[0]
            nm_bytes = mem_read(nrva, 64)
            if not nm_bytes:
                continue
            nm = nm_bytes.split(b"\0")[0].decode('latin1', 'replace')
            res[nm] = struct.unpack_from("<I", frva_b, 0)[0]
        return res

    def _id_from_exports(self, base, handle=None):
        """用内存导出存在性识别模块 basename (LOAD_DLL 名不可读时的回退)。"""
        exps = self._mem_exports(base, handle)
        if not exps:
            return None
        if "NtTerminateProcess" in exps and "RtlExitUserProcess" in exps:
            return "ntdll.dll"
        if "ExitProcess" in exps and "TerminateProcess" in exps:
            return "kernel32.dll"
        if "Run" in exps and "GetAppVersion" in exps:
            return "core.dll"
        return None

    def read_candidate_ep_disk(self):
        """从磁盘候选 PE 头动态读 EP RVA + ImageBase (零硬编码)。"""
        try:
            image = open(CORE, "rb").read()
        except Exception as e:
            return None, None, "open failed: %r" % (e,)
        pe = self._pe_dirs(image)
        if not pe:
            return None, None, "PE parse failed"
        imgbase, _, _, pe32plus, _ = pe
        e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
        opt_off = e_lfanew + 4 + 20
        ep = struct.unpack_from("<I", image, opt_off + 16)[0]
        return ep, imgbase, None

    # ================= int3 引擎 =================
    def log_bp(self, kind, name, detail):
        rec = {"kind": kind, "bp": name, "detail": detail}
        self.events.append({"t": round(time.time() - self.t0, 3), "kind": kind, "detail": "%s %s" % (name, detail)})
        try:
            if self._bp_hits_fd:
                self._bp_hits_fd.write(json.dumps(rec, ensure_ascii=False) + chr(10))
                self._bp_hits_fd.flush()
        except Exception:
            pass
        print("[%7.3f] %s %s: %s" % (time.time() - self.t0, kind, name, detail))

    def arm_bp(self, b, handle):
        """WriteProcessMemory 0xCC + FlushInstructionCache (原字节留存)。"""
        if b.armed or b.disabled:
            return b.armed
        raw = self.rpm_handle(handle, b.va, 1)
        if raw is None:
            b.disabled = "rpm_fail"
            self.log_bp("BP_ARM_FAIL", b.name, "rpm read fail at %#x" % b.va)
            return False
        b.orig_byte = raw[0]
        if raw[0] == 0xCC:
            b.disabled = "already_int3"
            self.log_bp("BP_ARM_FAIL", b.name, "already int3 at %#x (未覆盖)" % b.va)
            return False
        if not self.wpm(handle, b.va, b"\xCC"):
            b.disabled = "wpm_fail"
            self.log_bp("BP_ARM_FAIL", b.name, "WriteProcessMemory fail at %#x" % b.va)
            return False
        self.k32.FlushInstructionCache(wt.HANDLE(handle), ctypes.c_void_p(b.va), 1)
        b.armed = True
        b.armed_at = round(time.time() - self.t0, 3)
        self.log_bp("BP_ARM", b.name, "va=%#x orig=0x%02x" % (b.va, b.orig_byte))
        return True

    def disarm_bp(self, b, handle):
        """恢复原字节 + FlushInstructionCache (命中后调用)。"""
        if b.orig_byte is None:
            return
        self.wpm(handle, b.va, bytes([b.orig_byte]))
        self.k32.FlushInstructionCache(wt.HANDLE(handle), ctypes.c_void_p(b.va), 1)
        b.armed = False

    def _get_ctx(self, h):
        if not h:
            return None
        with self.ctx_lock:
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_CONTROL_INTEGER_AMD64
            if self.k32.GetThreadContext(wt.HANDLE(h), ctypes.byref(ctx)):
                return ctx
            ctx2 = CONTEXT()
            ctx2.ContextFlags = CONTEXT_CONTROL_AMD64
            if self.k32.GetThreadContext(wt.HANDLE(h), ctypes.byref(ctx2)):
                return ctx2
        return None

    @staticmethod
    def _ctx_dict(ctx):
        fields = ["Rax", "Rcx", "Rdx", "Rbx", "Rsp", "Rbp", "Rsi", "Rdi",
                  "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
                  "Rip", "EFlags", "SegCs", "SegDs", "SegEs", "SegFs", "SegGs", "SegSs",
                  "Dr0", "Dr1", "Dr2", "Dr3", "Dr6", "Dr7"]
        return {f: getattr(ctx, f) for f in fields}

    def _set_ctx(self, h, ctx):
        if not h:
            return False
        with self.ctx_lock:
            return bool(self.k32.SetThreadContext(wt.HANDLE(h), ctypes.byref(ctx)))

    def _on_int3_hit(self, ev, b, rec):
        """int3 命中: 法证记录 + 恢复原字节 + Rip 回退 1 + TF 单步重布 (re-arm) / fire-once。"""
        tid = ev.dwThreadId
        h = self.thread_handles.get(tid)
        ctx = self._get_ctx(h)
        true_addr = (ctx.Rip - 1) if ctx else None
        handle = self.main_hprocess
        if not self.modules:
            self.enum_modules(handle)
        mods = self.modules
        rsp = ctx.Rsp if ctx else None
        ret_qword = self.read_qword_handle(handle, rsp) if rsp else None
        foren = {
            "kind": "int3_hit",
            "t": round(time.time() - self.t0, 4),
            "bp_name": b.name,
            "bp_va": hex(b.va),
            "bp_module": b.mod_name,
            "true_addr_rip_minus_1": hex(true_addr) if true_addr is not None else None,
            "matches_armed_va": (true_addr == b.va),
            "tid": tid,
            "regs": {k: hex(v) for k, v in self._ctx_dict(ctx).items()} if ctx else None,
            "ret_addr_rsp0": hex(ret_qword) if ret_qword else None,
            "ret_attr": self.attr_detail(ret_qword, mods, handle) if ret_qword else None,
            "stack": self.stack_walk(rsp, mods, handle, 17) if rsp else [],
            "module_count": len(mods),
        }
        self.bp_hits.append(foren)
        b.hits += 1
        rec["bp_name"] = b.name
        rec["true_addr"] = foren["true_addr_rip_minus_1"]
        rec["ret_attr"] = foren["ret_attr"]
        rec["hit_seq"] = len(self.bp_hits)
        # 恢复原字节
        self.disarm_bp(b, handle)
        # re-arm: Rip 回退 1 + TF 单步 (标准 re-arm); 失败/超预算 → fire-once
        if ctx and h:
            if self.bp_mode == "rearm" and b.hits <= BP_MAX_HITS:
                ctx.Rip = b.va
                ctx.EFlags |= 0x100  # TF
                if self._set_ctx(h, ctx):
                    self.bp_pending[tid] = b
                    rec["rearm"] = "TF_singlestep_pending"
                else:
                    b.fire_once = True
                    rec["rearm"] = "setctx_fail_fire_once"
                    self.rearm_failures.append({"bp": b.name, "why": "setctx_fail"})
            else:
                ctx.Rip = b.va
                self._set_ctx(h, ctx)
                b.fire_once = True
                rec["rearm"] = "fire_once"
        else:
            b.fire_once = True
            rec["rearm"] = "no_ctx_fire_once"
        # 边到边落盘 (法证全量)
        try:
            if self._bp_hits_fd:
                self._bp_hits_fd.write(json.dumps(foren, ensure_ascii=False) + chr(10))
                self._bp_hits_fd.flush()
        except Exception:
            pass
        self.log_bp("BP_HIT", b.name,
                    "va=%#x ret=%s rearm=%s tid=%d" % (b.va,
                        (foren["ret_attr"]["module"] + "+" + foren["ret_attr"]["rva"]) if foren["ret_attr"] else "?",
                        rec["rearm"], tid))

    def _on_singlestep(self, ev, rec):
        """EXCEPTION_SINGLE_STEP: 清 TF + 重布 0xCC (re-arm)。"""
        tid = ev.dwThreadId
        b = self.bp_pending.pop(tid, None)
        if b is None:
            rec["singlestep"] = "no_pending"
            return
        h = self.thread_handles.get(tid)
        if h:
            ctx = self._get_ctx(h)
            if ctx:
                ctx.EFlags &= ~0x100
                self._set_ctx(h, ctx)
        ok = self.arm_bp(b, self.main_hprocess)
        rec["bp_rearmed"] = b.name
        rec["rearm_ok"] = ok
        self.log_bp("BP_REARM", b.name, "va=%#x ok=%s" % (b.va, ok))

    def _clear_pending_on_other_exception(self, tid):
        """TF 挂起中撞上其它异常 → 清 TF + 该断点降级 fire-once (re-arm 失败路径)。"""
        b = self.bp_pending.pop(tid, None)
        if b is None:
            return
        h = self.thread_handles.get(tid)
        if h:
            ctx = self._get_ctx(h)
            if ctx:
                ctx.EFlags &= ~0x100
                self._set_ctx(h, ctx)
        b.fire_once = True
        self.rearm_failures.append({"bp": b.name, "why": "other_exception_while_tf_pending"})
        self.log_bp("BP_REARM_FAIL", b.name, "TF 挂起中撞其它异常 → fire-once")

    # ================= 断点布置 =================
    def _try_arm_funnel(self):
        if self.funnel_armed:
            return
        nb = self.mod_base.get("ntdll.dll")
        kb = self.mod_base.get("kernel32.dll")
        if nb is None or kb is None:
            return
        handle = self.main_hprocess
        if not handle:
            return
        # MZ 双核 (部署前)
        for base in (nb, kb):
            h = self.rpm_handle(handle, base, 2)
            if not h or h[:2] != b"MZ":
                self.log_bp("BP_ARM_DEFER", "funnel", "MZ check fail at %#x" % base)
                return
        base_of = {"ntdll.dll": nb, "kernel32.dll": kb}
        for name, mod, _path in FUNNEL:
            rva = self.funnel_rvas.get(name)
            if rva is None:
                self.log_bp("BP_ARM_SKIP", name, "export rva missing")
                continue
            va = base_of[mod] + rva
            if va in self.bp_by_va:
                continue
            b = bp(name, va, mod)
            self.bps.append(b)
            self.bp_by_va[va] = b
            self.arm_bp(b, handle)
        self.funnel_armed = all(any(bp_.name == f[0] and bp_.armed for bp_ in self.bps) for f in FUNNEL)
        if self.funnel_armed:
            self.log_bp("BP_FUNNEL_ARMED", "all", "")

    def _try_arm_ep(self):
        if self.ep_armed or self.ep_rva is None:
            return
        handle = self.main_hprocess
        if not handle:
            return
        base = self.core_load_base
        if base is None:
            return
        h = self.rpm_handle(handle, base, 2)
        if not h or h[:2] != b"MZ":
            self.log_bp("BP_ARM_DEFER", "candidate_ep", "MZ check fail at %#x" % base)
            return
        va = base + self.ep_rva
        b = bp("candidate_ep", va, "core.dll")
        self.bps.append(b)
        self.bp_by_va[va] = b
        ok = self.arm_bp(b, handle)
        self.ep_armed = ok
        if ok:
            self.log_bp("BP_EP_ARMED", "candidate_ep", "va=%#x (base=%#x + EP rva %#x, trigger=%s)"
                        % (va, base, self.ep_rva, self.core_load_trigger))

    def _read_loaddll_name(self, ev):
        """读 LOAD_DLL_DEBUG_EVENT 的 lpImageName (两级指针)。失败返回 None。"""
        ldi = ev.u.LoadDll
        if not ldi.lpImageName or not self.main_hprocess:
            return None
        ptr_buf = self.rpm_handle(self.main_hprocess, ldi.lpImageName, 8)
        if not ptr_buf:
            return None
        str_ptr = struct.unpack("<Q", ptr_buf)[0]
        if not str_ptr:
            return None
        if ldi.fUnicode:
            raw = self.rpm_handle(self.main_hprocess, str_ptr, 520 * 2)
            if not raw:
                return None
            return raw.decode('utf-16-le', 'replace').split("\0")[0]
        raw = self.rpm_handle(self.main_hprocess, str_ptr, 520)
        if not raw:
            return None
        return raw.split(b"\0")[0].decode('latin1', 'replace')

    # ================= 调试泵 =================
    def _read_event_raw_qword(self, ev, off):
        raw = (ctypes.c_ubyte * 48).from_address(ctypes.addressof(ev))
        return int.from_bytes(bytes(raw[off:off + 8]), "little")

    def _thread_ctx(self, hthread):
        if not hthread:
            return (None, None, None, False)
        with self.ctx_lock:
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_CONTROL_INTEGER_AMD64
            ok = self.k32.GetThreadContext(wt.HANDLE(hthread), ctypes.byref(ctx))
            if not ok:
                ctx2 = CONTEXT()
                ctx2.ContextFlags = CONTEXT_CONTROL_AMD64
                ok2 = self.k32.GetThreadContext(wt.HANDLE(hthread), ctypes.byref(ctx2))
                if not ok2:
                    return (None, None, None, False)
                return (ctx2.Rip, ctx2.Rsp, None, True)
            return (ctx.Rip, ctx.Rsp, ctx.Rax, True)

    def _handle_debug_event(self, ev):
        code = ev.dwDebugEventCode
        pid = ev.dwProcessId
        tid = ev.dwThreadId
        detail = ""
        status = DBG_CONTINUE
        rec = {"code": code, "name": DBG_EVENT_NAMES.get(code, "EVENT_%d" % code), "tid": tid}

        if code == 3:  # CREATE_PROCESS_DEBUG_EVENT
            cpi = ev.u.CreateProcessInfo
            raw_hproc = self._read_event_raw_qword(ev, 24)
            raw_hthread = self._read_event_raw_qword(ev, 32)
            raw_imagebase = self._read_event_raw_qword(ev, 40)
            self.main_hprocess = cpi.hProcess
            self.main_hthread = cpi.hThread
            with self.pump_lock:
                self.thread_handles[tid] = cpi.hThread
            detail = ("struct: hProcess=%#x hThread=%#x imageBase=%#x start=%#x | raw24/32/40: %#x / %#x / %#x"
                      % (cpi.hProcess, cpi.hThread, cpi.lpBaseOfImage, cpi.lpStartAddress,
                         raw_hproc, raw_hthread, raw_imagebase))
            rec.update({"hProcess": cpi.hProcess, "hThread": cpi.hThread,
                        "imageBase": cpi.lpBaseOfImage, "start": cpi.lpStartAddress,
                        "raw_hProcess24": raw_hproc, "raw_hThread32": raw_hthread,
                        "raw_imageBase40": raw_imagebase})
            if cpi.hFile:
                self.k32.CloseHandle(ctypes.c_void_p(cpi.hFile))
        elif code == 2:  # CREATE_THREAD_DEBUG_EVENT
            cti = ev.u.CreateThread
            with self.pump_lock:
                self.thread_handles[tid] = cti.hThread
            rip, rsp, rax, ok = self._thread_ctx(cti.hThread)
            detail = ("hThread=%#x start=%#x threadCtxOk=%s Rip=%s" % (cti.hThread, cti.lpStartAddress,
                                                                      ok, hex(rip) if rip else None))
            rec.update({"hThread": cti.hThread, "start": cti.lpStartAddress,
                        "ctx_ok": ok, "rip_at_create": hex(rip) if rip else None})
        elif code == 1:  # EXCEPTION_DEBUG_EVENT
            ei = ev.u.Exception
            exc = ei.ExceptionRecord
            rec.update({"code": hex(exc.ExceptionCode), "flags": hex(exc.ExceptionFlags),
                        "address": exc.ExceptionAddress, "firstChance": ei.dwFirstChance})
            h = self.thread_handles.get(tid)
            rip, rsp, rax, ok = self._thread_ctx(h)
            rec.update({"thread_rip": hex(rip) if rip else None,
                        "thread_rsp": hex(rsp) if rsp else None,
                        "thread_rax": hex(rax) if rax is not None else None,
                        "thread_ctx_ok": ok})
            true_addr = int(exc.ExceptionAddress) if exc.ExceptionAddress else None
            b = self.bp_by_va.get(true_addr) if true_addr is not None else None
            if b is not None and b.armed:
                # 本工具 int3 命中
                status = DBG_CONTINUE
                rec["handled"] = "DBG_CONTINUE_int3_bp"
                self._on_int3_hit(ev, b, rec)
            elif exc.ExceptionCode == EXCEPTION_SINGLE_STEP:
                status = DBG_CONTINUE
                rec["handled"] = "DBG_CONTINUE_singlestep"
                self._on_singlestep(ev, rec)
            elif exc.ExceptionCode in BENIGN_BOOT_EXCEPTIONS:
                is_bp = (exc.ExceptionCode == EXCEPTION_BREAKPOINT)
                with self.pump_lock:
                    if is_bp and not self.pump_health["first_breakpoint_seen"]:
                        self.pump_health["first_breakpoint_seen"] = True
                status = DBG_CONTINUE
                rec["handled"] = "DBG_CONTINUE_benign_boot"
            else:
                status = DBG_EXCEPTION_NOT_HANDLED
                rec["handled"] = "DBG_EXCEPTION_NOT_HANDLED"
                self._clear_pending_on_other_exception(tid)
            self.exceptions.append(rec)
            detail = ("code=%s addr=%#x firstChance=%d thread=%d threadRip=%s handled=%s"
                      % (rec["code"], exc.ExceptionAddress, ei.dwFirstChance, tid,
                         rec["thread_rip"], rec["handled"]))
        elif code == 4:  # EXIT_THREAD_DEBUG_EVENT
            rec.update({"exitCode": ev.u.ExitThread.dwExitCode})
            with self.pump_lock:
                self.thread_handles.pop(tid, None)
            detail = "tid=%d exitCode=%d" % (tid, ev.u.ExitThread.dwExitCode)
        elif code == 5:  # EXIT_PROCESS_DEBUG_EVENT
            rec.update({"exitCode": ev.u.ExitProcess.dwExitCode})
            with self.pump_lock:
                self.pump_exit_code = ev.u.ExitProcess.dwExitCode
                self.pump_process_exited = True
            detail = "exitCode=%d" % ev.u.ExitProcess.dwExitCode
        elif code == 6:  # LOAD_DLL_DEBUG_EVENT
            ldi = ev.u.LoadDll
            rec.update({"base": ldi.lpBaseOfDll})
            if ldi.hFile:
                self.k32.CloseHandle(ctypes.c_void_p(ldi.hFile))
            # 模块识别: 事件名 → 导出存在性回退 → 首选基址匹配
            name = self._read_loaddll_name(ev)
            ident = None
            if name:
                ident = os.path.basename(name)
            if ident is None:
                ident = self._id_from_exports(ldi.lpBaseOfDll, self.main_hprocess)
            rec["mod_name"] = ident
            base = int(ldi.lpBaseOfDll)
            if ident:
                nl = ident.lower()
                if nl == "ntdll.dll" and "ntdll.dll" not in self.mod_base:
                    self.mod_base["ntdll.dll"] = base
                elif nl == "kernel32.dll" and "kernel32.dll" not in self.mod_base:
                    self.mod_base["kernel32.dll"] = base
                elif nl == "core.dll" and self.core_load_base is None:
                    self.core_load_base = base
                    self.core_load_trigger = "name"
            if self.core_load_base is None and self.cand_preferred_base and base == self.cand_preferred_base:
                self.core_load_base = base
                self.core_load_trigger = "preferred_base"
            if self.core_load_base is not None:
                self._try_arm_funnel()
                self._try_arm_ep()
            detail = "base=%#x name=%s" % (base, ident)
        elif code == 8:  # OUTPUT_DEBUG_STRING
            rec.update({"length": ev.u.OutputDebugString.nDebugStringLength,
                        "unicode": ev.u.OutputDebugString.fUnicode})
            detail = "len=%d" % ev.u.OutputDebugString.nDebugStringLength
        elif code == 7:  # RIP_EVENT
            rec.update({"err": ev.u.RipInfo.dwError, "type": ev.u.RipInfo.dwType})
            detail = "err=%d type=%d" % (ev.u.RipInfo.dwError, ev.u.RipInfo.dwType)
        elif code == 9:  # UNLOAD_DLL
            rec.update({"base": ev.u.UnloadDll.lpBaseOfDll})
            detail = "base=%#x" % ev.u.UnloadDll.lpBaseOfDll
        else:
            detail = "unknown code %d" % code

        rec["detail"] = detail
        with self.pump_lock:
            self.dbg_events.append(dict(rec))
            self.pump_health["last_consume_t"] = time.time()
        try:
            if self._pump_event_fd:
                self._pump_event_fd.write(json.dumps(rec, ensure_ascii=False) + chr(10))
                self._pump_event_fd.flush()
        except Exception:
            pass
        return status

    def pump_loop(self):
        """调试泵线程: CreateProcessW(DEBUG_ONLY_THIS_PROCESS) (调试会话线程绑定) → WaitForDebugEvent → Continue。"""
        if not self.create_host_debug(getattr(self, "_pump_target", None),
                                      getattr(self, "_pump_args", None)):
            with self.pump_lock:
                self.pump_health["create_failed"] = True
                self.pump_health["create_err"] = ctypes.get_last_error()
                self.pump_health["pump_exited"] = True
                self.dbg_events.append({"code": -3, "name": "CREATE_HOST_FAILED", "tid": None,
                                        "detail": "CreateProcessW DEBUG_ONLY_THIS_PROCESS err=%d" % ctypes.get_last_error()})
            return
        self.pid = self.pi.dwProcessId
        self.t0 = time.time()
        self.pump_created.set()
        with self.pump_lock:
            self.dbg_events.append({"code": 0, "name": "HOST_CREATED", "tid": None,
                                    "detail": "pid=%d DEBUG_ONLY_THIS_PROCESS(0x2) NO_BYPASS=1" % self.pid})
        while not self.pump_stop.is_set():
            ev = DEBUG_EVENT()
            ok = self.k32.WaitForDebugEvent(ctypes.byref(ev), 500)
            if not ok:
                err = ctypes.get_last_error()
                if err == WAIT_TIMEOUT_ERR:
                    continue
                with self.pump_lock:
                    self.pump_health["wait_errors"].append(err)
                    self.pump_health["pump_exited"] = True
                    self.dbg_events.append({"code": -1, "name": "PUMP_WAIT_ERROR", "tid": None,
                                            "detail": "WaitForDebugEvent err=%d" % err})
                break
            status = DBG_CONTINUE
            try:
                status = self._handle_debug_event(ev)
            except Exception as e:  # noqa: BLE001 — 泵处理异常也必须继续事件
                with self.pump_lock:
                    self.dbg_events.append({"code": -2, "name": "PUMP_HANDLER_ERROR", "tid": ev.dwThreadId,
                                            "detail": "handler exc: %r" % (e,)})
            finally:
                cont_ok = self.k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
                with self.pump_lock:
                    self.pump_health["continues"] += 1
                    if not cont_ok:
                        self.pump_health["continue_fails"] += 1
            if ev.dwDebugEventCode == 5:
                break
        with self.pump_lock:
            self.pump_health["pump_exited"] = True

    # ================= 宿主创建 (调试端口) =================
    def create_host_debug(self, target=None, args=None):
        """CreateProcessW(..., DEBUG_ONLY_THIS_PROCESS); NO_BYPASS=1 环境块。
        target: 可执行路径 (默认 HOST); args: 额外命令行参数 (verify 模式 host_loader <candidate>)。"""
        k32 = self.k32
        k32.CreateProcessW.restype = wt.BOOL
        k32.CreateProcessW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p,
                                       wt.BOOL, wt.DWORD, ctypes.c_void_p, ctypes.c_wchar_p,
                                       ctypes.POINTER(STARTUPINFO), ctypes.POINTER(PROCESS_INFORMATION)]
        env = dict(os.environ)
        env["NO_BYPASS"] = "1"
        env["MIDA_GTO_NO_BYPASS"] = "1"
        env_block = "".join("%s=%s\0" % (k, v) for k, v in env.items()) + "\0"
        env_buf = ctypes.create_unicode_buffer(env_block)
        si = STARTUPINFO()
        si.cb = ctypes.sizeof(STARTUPINFO)
        pi = PROCESS_INFORMATION()
        exe = target or HOST
        cmd_line = '"%s"' % exe
        if args:
            cmd_line += " " + " ".join('"%s"' % a for a in args)
        cmd = ctypes.create_unicode_buffer(cmd_line)
        flags = DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT
        ok = k32.CreateProcessW(None, cmd, None, None, False, flags, env_buf, DEPLOY,
                                ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            return False
        self.pi = pi
        self.proc = pi.hProcess
        self._create_cmdline = cmd_line
        return True

    def terminate_host(self):
        if self.proc:
            try:
                self.k32.TerminateProcess(wt.HANDLE(self.proc), 0)
            except Exception:
                pass

    # ================= 窗口 (基线对照: T022 无窗口) =================
    def find_windows(self):
        WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
        found = []

        @WNDENUMPROC
        def _cb(hwnd, lp):
            p = wt.DWORD(0)
            wtid = int(self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p)))
            if int(p.value) != self.pid:
                return True
            cn = ctypes.create_unicode_buffer(256)
            self.user32.GetClassNameW(hwnd, cn, 256)
            tt = ctypes.create_unicode_buffer(512)
            self.user32.GetWindowTextW(hwnd, tt, 512)
            found.append({"hwnd": int(hwnd), "class": cn.value, "title": tt.value,
                          "pid": int(p.value), "tid": wtid, "thread": wtid})
            return True

        self.user32.EnumWindows(_cb, 0)
        if found:
            return found
        known_classes = ["PigToGoLicenseDialog", "IME", "MSCTFIME UI"]
        for cls in known_classes:
            hwnd = self.user32.FindWindowW(cls, None)
            if hwnd:
                p = wt.DWORD(0)
                wtid = int(self.user32.GetWindowThreadProcessId(wt.HWND(hwnd), ctypes.byref(p)))
                if int(p.value) == self.pid:
                    cn = ctypes.create_unicode_buffer(256)
                    self.user32.GetClassNameW(wt.HWND(hwnd), cn, 256)
                    tt = ctypes.create_unicode_buffer(512)
                    self.user32.GetWindowTextW(wt.HWND(hwnd), tt, 512)
                    found.append({"hwnd": int(hwnd), "class": cn.value, "title": tt.value,
                                  "pid": int(p.value), "tid": wtid, "thread": wtid})
        return found

    # ================= 防火墙现状核实 (只读) =================
    def firewall_block_status(self):
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 'Get-NetFirewallRule -Direction Outbound -Action Block | Where-Object { $_.Enabled -eq "True" } | Select-Object -ExpandProperty DisplayName'],
                capture_output=True, text=True, timeout=30)
            names = [l.strip() for l in out.stdout.splitlines() if l.strip()]
            return {"ok": True, "count": len(names), "rules": names, "rc": out.returncode}
        except Exception as e:
            return {"ok": False, "err": str(e)}

    # ================= 事件记录 =================
    def log_event(self, kind, detail):
        self.events.append({"t": round(time.time() - self.t0, 3), "kind": kind, "detail": detail})
        print("[%7.3f] %s: %s" % (time.time() - self.t0, kind, detail))

    def pump_summary(self):
        with self.pump_lock:
            return {
                "health": dict(self.pump_health),
                "threads_seen": sorted(self.thread_handles.keys()),
                "exit_code": self.pump_exit_code,
                "process_exited": self.pump_process_exited,
                "exceptions_count": len(self.exceptions),
                "dbg_events": list(self.dbg_events),
            }

    # ================= 判定 =================
    def attr_category(self, mod_name):
        """决策者归属四分类: host-image / candidate-image / ntdll-loader / other。"""
        if not mod_name:
            return "other"
        nl = mod_name.lower()
        if nl == "rev2_unpacked.exe":
            return "host-image"
        if nl == "core.dll":
            return "candidate-image"
        if nl == "ntdll.dll":
            return "ntdll-loader"
        return "other"

    def build_attribution(self):
        """核心交付: 退出链命中序列 + 退出决策者归属 + EP 判别位 + 栈链 RVA 明细。"""
        funnel_hits = [h for h in self.bp_hits if h["bp_name"] != "candidate_ep"]
        ep_hits = [h for h in self.bp_hits if h["bp_name"] == "candidate_ep"]
        funnel_hits.sort(key=lambda h: h["t"])
        ep_hits.sort(key=lambda h: h["t"])
        chain = [{"seq": i + 1, "t": h["t"], "bp": h["bp_name"], "va": h["bp_va"],
                  "ret_addr": h["ret_addr_rsp0"], "ret_module": (h["ret_attr"] or {}).get("module"),
                  "ret_rva": (h["ret_attr"] or {}).get("rva"),
                  "ret_category": self.attr_category((h["ret_attr"] or {}).get("module")),
                  "tid": h["tid"]} for i, h in enumerate(funnel_hits)]
        decision_maker = None
        if funnel_hits:
            outer = funnel_hits[0]
            ra = outer.get("ret_attr") or {}
            decision_maker = {
                "hit_bp": outer["bp_name"],
                "hit_va": outer["bp_va"],
                "t": outer["t"],
                "ret_addr": outer.get("ret_addr_rsp0"),
                "module": ra.get("module"),
                "rva": ra.get("rva"),
                "mz": ra.get("mz"),
                "category": self.attr_category(ra.get("module")),
            }
        ep = {
            "called": len(ep_hits) > 0,
            "hit_count": len(ep_hits),
            "hits": [{"t": h["t"], "ret_module": (h["ret_attr"] or {}).get("module"),
                      "ret_rva": (h["ret_attr"] or {}).get("rva"),
                      "category": self.attr_category((h["ret_attr"] or {}).get("module"))} for h in ep_hits],
            "meaning": "EP 命中 = 候选 DllMain (NOP stub 0x1027c0) 被加载器调用; 0 命中 = DllMain 未被调用 (加载器初始化失败 / 退出先于 DllMain)",
        }
        return {"exit_chain": chain, "funnel_hit_count": len(funnel_hits),
                "decision_maker": decision_maker, "ep_discriminator": ep}

    def classify(self, mode):
        """诊断判定: 与 T022 基线 (exit 0 / 无 AV / 无窗口) 对照; 仪器化改变行为 → STOP。"""
        att = self.build_attribution()
        real_avs = [e for e in self.exceptions
                    if e.get("code") not in ("0x80000003", "0x80000004", "0xc000008e")]
        if real_avs:
            return "INSTRUMENTATION_DEVIATION_AV (EXCEPTION 非引导/单步: %s)" % (
                [{"code": e.get("code"), "addr": hex(e.get("address")) if e.get("address") else None,
                  "threadRip": e.get("thread_rip")} for e in real_avs[:8]])
        if self.attach_changed_behavior:
            return "ATTACH_CHANGED_BEHAVIOR (窗口出现, T022 基线无窗口) — 如实上报"
        if self.pump_process_exited:
            if self.pump_exit_code != 0:
                return "EXIT_CODE_DEVIATION (exit_code=%r, T022 基线 0)" % self.pump_exit_code
            if att["funnel_hit_count"] == 0:
                return "EXIT_0_ZERO_FUNNEL_HITS (exit 0 复现但 0 命中 — 退出经直接 syscall 绕过 ntdll 漏斗? )"
            return "EXIT_0_FUNNEL_HITS (exit 0 复现, 漏斗命中 %d)" % att["funnel_hit_count"]
        return "ALIVE_NO_EXIT (观测窗内进程存活未退出 — 偏离 T022 基线, 疑似仪器化影响) — 如实上报"

    # ================= 运行流程 =================
    def _common_setup(self):
        """导出动态解析 + EP 动态读 + 防火墙只读核实。"""
        nt_exp = self.resolve_exports_disk_file(NTDLL_DISK)
        k32_exp = self.resolve_exports_disk_file(K32_DISK)
        for name, mod, _path in FUNNEL:
            rva = (nt_exp if mod == "ntdll.dll" else k32_exp).get(name)
            self.funnel_rvas[name] = rva
        missing = [n for n, r in self.funnel_rvas.items() if not r]
        if missing:
            return {"redline": "FAIL_FUNNEL_EXPORT", "missing": missing,
                    "err": self.export_parse_err, "no_bypass": "1"}
        # 防御性 forwarder 检查: 导出 RVA 不得落在导出目录内 (forwarder 字符串区)
        for name, mod, path in FUNNEL:
            rva = self.funnel_rvas[name]
            image = open(path, "rb").read()
            pe = self._pe_dirs(image)
            if pe:
                _, secs, dirs, _, _ = pe
                exp_rva, exp_size = dirs[0]
                if exp_rva and exp_rva <= rva < exp_rva + exp_size:
                    return {"redline": "FAIL_FUNNEL_FORWARDER", "export": name,
                            "rva": hex(rva), "detail": "RVA 落在导出目录内 = forwarder, 拒绝布点"}
        self.ep_rva, self.cand_preferred_base, err = self.read_candidate_ep_disk()
        if self.ep_rva is None:
            return {"redline": "FAIL_CANDIDATE_EP", "err": err, "no_bypass": "1"}
        fw = self.firewall_block_status()
        self.log_event("firewall_check", json.dumps(fw))
        self.log_event("export_resolve", json.dumps({
            "funnel_rvas": {k: hex(v) for k, v in self.funnel_rvas.items()},
            "candidate_ep_rva": hex(self.ep_rva),
            "candidate_preferred_base": hex(self.cand_preferred_base),
            "resolved_from_disk": True}))
        return None

    def _start_pump(self, out_prefix, target=None, args=None):
        """启动泵线程; 保存 target/args 供 pump_loop → create_host_debug 使用
        (修复: 原实现 _start_pump 未把 target 传给 pump_loop, verify 误用了 HOST=rev2_unpacked.exe)。"""
        self._pump_event_path = os.path.join(DEPLOY, "%s_dbg_pump_events.ndjson" % out_prefix)
        self._bp_hits_path = os.path.join(DEPLOY, "%s_bp_hits.ndjson" % out_prefix)
        try:
            self._pump_event_fd = open(self._pump_event_path, "w", encoding="utf-8")
            self._bp_hits_fd = open(self._bp_hits_path, "w", encoding="utf-8")
        except Exception:
            self._pump_event_fd = None
            self._bp_hits_fd = None
        self.pump_stop.clear()
        self._pump_target = target
        self._pump_args = args
        self.pump_thread = threading.Thread(target=self.pump_loop, daemon=True, name="dbg-pump")
        self.pump_thread.start()
        self.pump_started = True
        if not self.pump_created.wait(timeout=15):
            self._cleanup_pump()
            return {"redline": "FAIL_CREATEPROCESS_DEBUG", "err": "pump create timeout", "no_bypass": "1"}
        if self.pump_health.get("create_failed"):
            self._cleanup_pump()
            return {"redline": "FAIL_CREATEPROCESS_DEBUG",
                    "err": self.pump_health.get("create_err"), "no_bypass": "1"}
        self.log_event("host_start_debug", "pid=%d DEBUG_ONLY_THIS_PROCESS(0x2) NO_BYPASS=1 target=%s" % (
            self.pid, target or HOST))
        return None

    def run_verify(self, out_prefix="c9_verify"):
        """验证趟: host_loader 隔离加载候选 (S3 同款), 断点全布。
        预期: 0 退出漏斗命中 + 进程存活; EP 判别位预期 1-2 次命中 (DllMain attach/detach — 正控制)。"""
        t_all = time.time()
        sha_core = sha256_file(CORE)
        if sha_core != CAND_SHA:
            return {"redline": "FAIL_CORE_SHA", "sha": sha_core, "expect": CAND_SHA}
        print("redline sha OK (core=096f3bdf candidate; host_loader sha=%s)" % sha256_file(HOST_LOADER))
        err = self._common_setup()
        if err:
            return err
        err = self._start_pump(out_prefix, target=HOST_LOADER, args=[CORE])
        if err:
            return err
        # 等待断点布置 (funnel + EP)
        deadline = time.time() + 15
        while time.time() < deadline and not (self.funnel_armed and self.ep_armed):
            if self.pump_process_exited:
                break
            time.sleep(0.1)
        self.log_event("verify_arm", json.dumps({
            "funnel_armed": self.funnel_armed, "ep_armed": self.ep_armed,
            "mod_base": {k: hex(v) for k, v in self.mod_base.items()},
            "core_load_base": hex(self.core_load_base) if self.core_load_base else None,
            "bps": [{"name": b.name, "va": hex(b.va), "armed": b.armed,
                     "hits": b.hits, "orig": hex(b.orig_byte) if b.orig_byte is not None else None}
                    for b in self.bps]}))
        # 观测窗 8s
        obs_end = time.time() + 8
        while time.time() < obs_end:
            with self.pump_lock:
                if self.pump_process_exited:
                    break
            time.sleep(0.2)
        alive = not self.pump_process_exited
        self.find_windows()
        att = self.build_attribution()
        out = {
            "schema": "xx21b_c9_exit_trace_verify/v1",
            "mode": "verify",
            "date_utc": now_utc(),
            "redline": {"no_bypass": "1", "candidate_sha256": CAND_SHA,
                        "host_loader_sha256": sha256_file(HOST_LOADER),
                        "samples_not_modified": True},
            "export_resolve": {"funnel_rvas": {k: hex(v) for k, v in self.funnel_rvas.items()},
                               "candidate_ep_rva": hex(self.ep_rva) if self.ep_rva else None},
            "arm": {"funnel_armed": self.funnel_armed, "ep_armed": self.ep_armed,
                    "bps": [{"name": b.name, "va": hex(b.va), "armed": b.armed,
                             "hits": b.hits, "disabled": b.disabled,
                             "orig": hex(b.orig_byte) if b.orig_byte is not None else None}
                            for b in self.bps]},
            "bp_hits": self.bp_hits,
            "attribution": att,
            "process_alive_at_end": alive,
            "process_exit_code": self.pump_exit_code,
            "exceptions": self.exceptions,
            "windows": self.windows,
            "pump": self.pump_summary(),
            "events": self.events,
            "duration_s": round(time.time() - t_all, 2),
        }
        self.log_event("verify_verdict", json.dumps({
            "funnel_hit_count": att["funnel_hit_count"],
            "ep_hit_count": att["ep_discriminator"]["hit_count"],
            "alive": alive, "exit_code": self.pump_exit_code,
            "windows": len(self.windows),
            "expected": "0 funnel hits + alive; EP hit = DllMain positive control"}))
        self.terminate_host()
        time.sleep(1.0)
        self._cleanup_pump(wait_s=10)
        self._cleanup_handles()
        return out

    def run_diag(self, out_prefix="c9_diag"):
        """诊断趟: rev2 宿主 + 候选, 泵 + 断点全布, 观测至退出决策 (上限 40s)。"""
        t_all = time.time()
        sha_core = sha256_file(CORE)
        if sha_core != CAND_SHA:
            return {"redline": "FAIL_CORE_SHA", "sha": sha_core, "expect": CAND_SHA}
        sha_host = sha256_file(HOST)
        if sha_host != HOST_SHA:
            return {"redline": "FAIL_HOST_SHA", "sha": sha_host, "expect": HOST_SHA}
        sha_cfg = sha256_file(CONFIG)
        if sha_cfg != CONFIG_SHA:
            return {"redline": "FAIL_CONFIG_SHA", "sha": sha_cfg, "expect": CONFIG_SHA}
        print("redline sha OK (core=096f3bdf candidate, host=a852880a, config=cde9be13)")
        err = self._common_setup()
        if err:
            return err
        err = self._start_pump(out_prefix, target=HOST, args=None)
        if err:
            return err
        # 等待断点布置
        deadline = time.time() + 15
        while time.time() < deadline and not (self.funnel_armed and self.ep_armed):
            if self.pump_process_exited:
                break
            time.sleep(0.1)
        self.log_event("diag_arm", json.dumps({
            "funnel_armed": self.funnel_armed, "ep_armed": self.ep_armed,
            "core_load_base": hex(self.core_load_base) if self.core_load_base else None,
            "core_load_trigger": self.core_load_trigger,
            "mod_base": {k: hex(v) for k, v in self.mod_base.items()},
            "bps": [{"name": b.name, "va": hex(b.va), "armed": b.armed,
                     "hits": b.hits} for b in self.bps]}))
        # 观测至退出决策 (40s 上限)
        obs_end = time.time() + 40
        exited = False
        while time.time() < obs_end:
            with self.pump_lock:
                if self.pump_process_exited:
                    exited = True
                    break
            time.sleep(0.2)
        # 退出决策后 1s 让泵收尾 (EXIT_PROCESS 事件已消费, 法证已记录)
        time.sleep(1.0)
        self.find_windows()
        att = self.build_attribution()
        verdict = self.classify("diag")
        self.log_event("diag_verdict", verdict)
        self.log_event("diag_attribution", json.dumps(att))
        out = {
            "schema": "xx21b_c9_exit_trace_diag/v1",
            "mode": "diag",
            "date_utc": now_utc(),
            "redline": {"no_bypass": "1",
                        "candidate_sha256": CAND_SHA, "host_sha256": HOST_SHA,
                        "config_sha256": CONFIG_SHA,
                        "samples_not_modified": True},
            "export_resolve": {"funnel_rvas": {k: hex(v) for k, v in self.funnel_rvas.items()},
                               "candidate_ep_rva": hex(self.ep_rva) if self.ep_rva else None,
                               "candidate_preferred_base": hex(self.cand_preferred_base) if self.cand_preferred_base else None},
            "arm": {"funnel_armed": self.funnel_armed, "ep_armed": self.ep_armed,
                    "core_load_base": hex(self.core_load_base) if self.core_load_base else None,
                    "core_load_trigger": self.core_load_trigger,
                    "base_equal": (self.core_load_base == self.cand_preferred_base) if (self.core_load_base and self.cand_preferred_base) else None,
                    "bps": [{"name": b.name, "va": hex(b.va), "armed": b.armed,
                             "hits": b.hits, "disabled": b.disabled,
                             "orig": hex(b.orig_byte) if b.orig_byte is not None else None}
                            for b in self.bps]},
            "bp_hits": self.bp_hits,
            "attribution": att,
            "verdict": verdict,
            "exited": exited,
            "process_exit_code": self.pump_exit_code,
            "exceptions": self.exceptions,
            "windows": self.windows,
            "attach_changed_behavior": self.attach_changed_behavior,
            "pump": self.pump_summary(),
            "events": self.events,
            "duration_s": round(time.time() - t_all, 2),
        }
        self.terminate_host()
        time.sleep(1.0)
        self._cleanup_pump(wait_s=10)
        self._cleanup_handles()
        return out

    # ================= 收尾 =================
    def _cleanup_pump(self, wait_s=8):
        self.pump_stop.set()
        if self.pump_thread and self.pump_thread.is_alive():
            self.pump_thread.join(timeout=wait_s)
        if self._pump_event_fd:
            try:
                self._pump_event_fd.close()
            except Exception:
                pass
            self._pump_event_fd = None
        if self._bp_hits_fd:
            try:
                self._bp_hits_fd.close()
            except Exception:
                pass
            self._bp_hits_fd = None

    def _cleanup_handles(self):
        to_close = []
        with self.pump_lock:
            for tid, h in list(self.thread_handles.items()):
                to_close.append(("thread_%d" % tid, h))
            self.thread_handles.clear()
            if self.main_hthread:
                to_close.append(("main_hthread", self.main_hthread))
                self.main_hthread = None
            if self.main_hprocess:
                to_close.append(("main_hprocess", self.main_hprocess))
                self.main_hprocess = None
        for tag, h in to_close:
            try:
                self.k32.CloseHandle(wt.HANDLE(h))
            except Exception:
                pass
        if self.hproc:
            try:
                self.k32.CloseHandle(wt.HANDLE(self.hproc))
            except Exception:
                pass
            self.hproc = None


def selftest():
    """单元自测: 断点解析器对 System32 导出表解析出 4 个 RVA 且非 0; EP RVA = 0x8a0108 (TASK-025 变体) 动态读得并打印。"""
    h = runtime()
    nt_exp = h.resolve_exports_disk_file(NTDLL_DISK)
    k32_exp = h.resolve_exports_disk_file(K32_DISK)
    rvas = {
        "ExitProcess": k32_exp.get("ExitProcess"),
        "TerminateProcess": k32_exp.get("TerminateProcess"),
        "RtlExitUserProcess": nt_exp.get("RtlExitUserProcess"),
        "NtTerminateProcess": nt_exp.get("NtTerminateProcess"),
    }
    print("SELFTEST export RVAs (System32 disk export table):")
    ok = True
    for name, rva in rvas.items():
        print("  %-20s RVA=%s  nonzero=%s" % (name, hex(rva) if rva else None, bool(rva)))
        if not rva:
            ok = False
    ep, imgbase, err = h.read_candidate_ep_disk()
    print("SELFTEST candidate EP RVA=%s ImageBase=%s err=%r" % (
        hex(ep) if ep is not None else None, hex(imgbase) if imgbase else None, err))
    print("SELFTEST expect EP RVA = 0x8a0108 (TASK-025 variant, original shell entry)")
    if ep != 0x8a0108:
        print("SELFTEST FAIL: EP RVA != 0x8a0108")
        ok = False
    if not ok:
        print("SELFTEST_EXIT=1")
        return 1
    print("SELFTEST PASS")
    print("SELFTEST_EXIT=0")
    return 0


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        sys.exit(selftest())
    mode = None
    for a in args:
        if a.startswith("--mode="):
            mode = a.split("=", 1)[1]
    if mode not in ("verify", "diag"):
        print("usage:")
        print("  python tools/xx21b_c9_exit_trace.py --selftest")
        print("  python tools/xx21b_c9_exit_trace.py --mode=verify [out_prefix] [out_json]")
        print("  python tools/xx21b_c9_exit_trace.py --mode=diag [out_prefix] [out_json]")
        sys.exit(2)
    positional = [a for a in args if not a.startswith("--")]
    prefix = positional[0] if len(positional) > 0 else ("c9_verify" if mode == "verify" else "c9_diag")
    out_path = positional[1] if len(positional) > 1 else os.path.join(DEPLOY, "%s_evidence.json" % prefix)
    h = runtime()
    if mode == "verify":
        out = h.run_verify(prefix)
    else:
        out = h.run_diag(prefix)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    print("=== SUMMARY ===")
    print(json.dumps({k: out.get(k) for k in (
        "redline", "mode", "arm", "attribution", "verdict", "process_alive_at_end",
        "process_exit_code", "exited", "pump")}, indent=1, ensure_ascii=False))
    print("written:", out_path)


if __name__ == "__main__":
    main()
