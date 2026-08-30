#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI-B T0.5 终跑（TASK-019，完美候选路线）：B1' 宿主 + 脱壳 core 完美候选 + 调试端口泵，三态判定
fork 自 tools/xx21b_t05_ui_drive_dbg.py (TASK-018 版); 原两套脚本 (T017 版 / T018 版) 不改, 本脚本为新增文件.

判定对象 = "B1' 宿主 (a852880a) + 脱壳 core 完美候选 (3650ea6c) + config.ini" 组合 (与 T0.4 Step1 基线同构).
保留 T018 全部机制 (泵线程全量即时消费 / CREATE_THREAD 调试句柄 RIP 采样不 OpenThread / EXCEPTION 全记录 /
泵健康自证 / attach_changed_behavior 上报 / sha fail-closed / 防火墙只读核实 / NO_BYPASS=1)。

本版改动 (T019 票面):
  1) sha 双门更新: CORE 期望 -> 3650ea6c (14,435,328 B); HOST 期望 -> a852880a (1,539,072 B);
  2) Run/GetAppVersion 动态解析: 经 core.dll 导出表解析 (T0.4 报告实证: Run@0x1C120 / GetAppVersion@0xBB30
     在候选中存在) — 不许硬编码 RVA (解析失败 -> fail-loud FAIL_RUN_EXPORT);
  3) 基址一致性自证: 候选固定基址 (首选 0x7ffe1da10000, DYNAMIC_BASE 清除) — 动态解析结果与首选基址
     分别记录、相互核对 (不一致 -> 记录事实并继续, 判定不依赖一致), 不回退到钉死;
  4) urlmon IAT 槽解析同样动态化: 导出目录 + .idata 深度解析 URLDownloadToFileA 槽 RVA (不硬编码 0x16f300),
     动态基址 + 槽 RVA 得 VA; 解析失败仅记录不阻断 (T0.4 报告静态证据已足)。
三态判定语义与 T017/T018 票面逐字一致, 仅判定对象换为完美候选组合; 结论 = 路径级 (FULL = 路径级结论, 非完全行为等价).
红线: NO_BYPASS=1; 不真联网; 不改防火墙; 样品/产物不外发; 不写 C:\\Windows; 不新增依赖 (仅 ctypes/subprocess/标准库).
"""
import ctypes, ctypes.wintypes as wt
import json, os, sys, time, subprocess, hashlib, datetime, threading
import struct

# ---------------- 常量 ----------------
DEPLOY = r"D:\Claude project\magicmida-rs\lab\xx21b_run_pcell"
HOST = os.path.join(DEPLOY, "rev2_unpacked.exe")
CORE = os.path.join(DEPLOY, "core.dll")
CONFIG = os.path.join(DEPLOY, "config.ini")
CAND_SHA = "3650ea6c0a88c731d4b613eaa533ab1d48258ce782843a5661ca6c683fd9b64e"
HOST_SHA = "a852880aabba215b16a2a96245322ca09d19ff148afaa30ff42b1a8ea438edac"
CONFIG_SHA = "cde9be13a5da62f5805cbf3b359c56c27f020d12cd1ae838f6a4218492d1d610"
# 候选固定基址首选 (T0.4 报告: keep_runtime_base 固定基址, DYNAMIC_BASE 清除, 0x7ffe1da10000 保留)
CAND_PREFERRED_BASE = 0x7FFE1DA10000

# 进程/线程权限
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# 调试常量
DEBUG_ONLY_THIS_PROCESS = 0x2
CREATE_UNICODE_ENVIRONMENT = 0x400
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
WAIT_TIMEOUT_ERR = 121  # ERROR_SEM_TIMEOUT
CONTEXT_CONTROL_AMD64 = 0x100001  # CONTEXT_AMD64 | CONTEXT_CONTROL (引擎同款 fast-path)
CONTEXT_CONTROL_INTEGER_AMD64 = 0x100003  # + CONTEXT_INTEGER (Rax 亦读)
DBG_EVENT_NAMES = {
    1: "EXCEPTION_DEBUG_EVENT", 2: "CREATE_THREAD_DEBUG_EVENT", 3: "CREATE_PROCESS_DEBUG_EVENT",
    4: "EXIT_THREAD_DEBUG_EVENT", 5: "EXIT_PROCESS_DEBUG_EVENT", 6: "LOAD_DLL_DEBUG_EVENT",
    7: "RIP_EVENT", 8: "OUTPUT_DEBUG_STRING_EVENT", 9: "UNLOAD_DLL_DEBUG_EVENT",
}
EXCEPTION_BREAKPOINT = 0x80000003
# [T018-实测偏差，证据见 T018 报告 §调试泵异常策略] 0xc000008e = STATUS_FLOAT_MULTIPLE_FAULTS,
# 是壳 VM 初始化期的一类良性首机会异常 (非调试下由宿主自身 SEH 静默处理, 宿主正常引导)。
# 调试附加下若按 NOT_HANDLED 路由 -> 壳 SEH 弹出 WinLicense 反调试对话框并干净退出
# (exit_code=0, 附加改变行为) -> 三态判定不可能完成。
# 策略: 0x80000003 首个引导断点 + 0xc000008e 引导期良性浮点异常 -> DBG_CONTINUE (被动观测);
#       其它一切 EXCEPTION (含真实 AV 0xc0000005 等) -> DBG_EXCEPTION_NOT_HANDLED, 全部记录不吞。
# AV 三态判据 = EXCEPTION 事件记录 (地址/码/Rip) 与进程退出码 — 与 Continue 状态无关, 证据链完整。
BENIGN_BOOT_EXCEPTIONS = (0x80000003, 0xc000008e)


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
        self.hthread = None
        self.tid = None
        self.run_tid = None
        self.modules = []          # [(base, size, name)]
        self.rip_log = []          # [{t, rip, owner, rsp, rax}]
        self.events = []           # [{t, kind, detail}] 主线时间线
        self.windows = []          # Run 窗口发现
        self.sampling = False
        self.sample_lock = threading.Lock()
        self.iat_pre = None
        self.iat_post = None
        self.core_base = None
        self.host_exe_base = None
        self.urlmon_slot_va = None
        self.gui_alive = False
        self.t0 = 0
        # ---- T019: 动态导出解析结果 (Run/GetAppVersion/urlmon IAT 槽) ----
        self.export_resolve = {}   # {name: rva} 解析自 core.dll 导出表
        self.urlmon_slot_rva = None
        self.export_resolve_ok = False
        self.export_resolve_err = None
        self.base_agreement = None  # {"actual":..., "preferred":..., "equal": bool}
        # ---- 调试泵共享态 (泵线程 <-> 主线) ----
        self.pump_lock = threading.Lock()
        self.pump_stop = threading.Event()
        self.pump_thread = None
        self.pump_started = False
        self.pump_health = {
            "total": 0, "continues": 0, "continue_fails": 0, "wait_errors": [],
            "by_code": {}, "last_consume_t": None, "pump_exited": False,
            "first_breakpoint_seen": False,
        }
        self.dbg_events = []       # 泵全量事件日志 [{seq, code, name, tid, detail}]
        self.dbg_events_lock = threading.Lock()
        self._pump_event_fd = None  # 泵事件边到边落盘 (提前退出也留证据)
        self._pump_event_path = None
        self.pump_created = threading.Event()  # 泵线程内 CreateProcessW 完成
        self._pump_core_candidate = None       # LOAD_DLL 泵侧记录的 core.dll 候选基址
        self.exceptions = []       # EXCEPTION_DEBUG_EVENT 记录 (含线程 Rip)
        self.thread_handles = {}   # tid -> hThread (调试事件句柄, 不用 OpenThread)
        self.main_hthread = None   # CREATE_PROCESS 事件的主线程句柄
        self.main_hprocess = None  # CREATE_PROCESS 事件的进程句柄
        self.run_hthread = None    # Run 线程调试句柄 (CREATE_THREAD_DEBUG_EVENT)
        self.run_thread_ready = threading.Event()
        self.pump_exit_code = None
        self.pump_process_exited = False
        self.ctx_lock = threading.Lock()
        self._closed_handles = set()
        # ---- 冻结/附加行为观测 ----
        self.freeze_symptoms = []  # [{t, kind, detail}]
        self.attach_changed_behavior = False

    # ================= 基础 API =================
    def open_proc(self):
        self.hproc = self.k32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, False, self.pid)
        return bool(self.hproc)

    def rpm(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        if not self.k32.ReadProcessMemory(self.hproc, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
            return None
        return buf.raw[:n.value]

    def read_qword(self, addr):
        b = self.rpm(addr, 8)
        return int.from_bytes(b, "little") if b else None

    def read_dword(self, addr):
        b = self.rpm(addr, 4)
        return int.from_bytes(b, "little") if b else None

    class MODULEINFO(ctypes.Structure):
        _fields_ = [("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", ctypes.c_ulong),
                    ("EntryPoint", ctypes.c_void_p)]

    def enum_modules(self):
        self.modules = []
        MAX = 2048
        arr = (ctypes.c_void_p * MAX)()
        cb = ctypes.c_ulong(0)
        if not self.psapi.EnumProcessModulesEx(self.hproc, arr, ctypes.sizeof(arr), ctypes.byref(cb), 3):
            return
        cnt = cb.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(min(cnt, MAX)):
            hmod = arr[i]
            name_buf = ctypes.create_unicode_buffer(260)
            self.psapi.GetModuleFileNameExW(self.hproc, ctypes.c_void_p(hmod), name_buf, 260)
            mi = self.MODULEINFO()
            if self.psapi.GetModuleInformation(self.hproc, ctypes.c_void_p(hmod), ctypes.byref(mi), ctypes.sizeof(mi)):
                base = mi.lpBaseOfDll
                size = mi.SizeOfImage
            else:
                base = hmod
                size = 0
            self.modules.append((base, size, os.path.basename(name_buf.value)))
        self.modules.sort(key=lambda m: m[0])

    def owner(self, rip):
        for base, size, name in self.modules:
            if base <= rip < base + size:
                return name
        return "unknown"

    # ================= PE 解析 (静态 + 会话动态, T019) =================
    def _pe_dirs(self, image):
        """读 PE 头: 返回 (image_base, sections, data_dirs, pe32plus)。
        sections = [(name, vaddr, vsize, roff, rsize)]; data_dirs 为 (rva,size) 列表。"""
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
            nsec_off = opt_off + 0x6C  # NumberOfRvaAndSizes
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

    @staticmethod
    def _sec_of(secs, rva):
        for name, vaddr, vsize, roff, rsize in secs:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return name
        return None

    def resolve_exports_disk(self):
        """从磁盘 CORE 文件解析导出表 (T019 任务 1: Run/GetAppVersion 动态解析, 不许硬编码 RVA)。
        返回 {name: rva}; 失败时 self.export_resolve_err 记录原因。"""
        try:
            image = open(CORE, "rb").read()
        except Exception as e:
            self.export_resolve_err = "open failed: %r" % (e,)
            return {}
        pe = self._pe_dirs(image)
        if not pe:
            self.export_resolve_err = "PE parse failed"
            return {}
        _, secs, dirs, _, _ = pe
        exp_rva, exp_size = dirs[0]
        if not exp_rva:
            self.export_resolve_err = "export dir missing"
            return {}
        off = self._rva2off(secs, exp_rva)
        if off is None:
            self.export_resolve_err = "export dir rva %#x not in sections" % exp_rva
            return {}
        try:
            nnames = struct.unpack_from("<I", image, off + 24)[0]  # NumberOfNames
            afuncs = struct.unpack_from("<I", image, off + 28)[0]   # AddressOfFunctions
            anames = struct.unpack_from("<I", image, off + 32)[0]   # AddressOfNames
            aords = struct.unpack_from("<I", image, off + 36)[0]    # AddressOfNameOrdinals
        except Exception as e:
            self.export_resolve_err = "export dir read failed: %r" % (e,)
            return {}
        res = {}
        noff = self._rva2off(secs, anames)
        ordoff = self._rva2off(secs, aords)
        funcoff = self._rva2off(secs, afuncs)
        if noff is None or ordoff is None or funcoff is None:
            self.export_resolve_err = "export arrays rva not mappable (anames=%#x aords=%#x afuncs=%#x)" % (
                anames, aords, afuncs)
            return {}
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

    def resolve_urlmon_slot_disk(self):
        """从磁盘 CORE 文件解析 urlmon IAT 槽 (URLDownloadToFileA 导入槽 RVA)。
        T0.4 报告静态: urlmon IAT 槽 [0x16f300] = URLDownloadToFileA (导出 RVA 0xfe470, GetProcAddress 验证一致)。
        本函数动态定位: 经 .idata 深度解析找 URLDownloadToFileA 的 IAT 槽 RVA; 失败仅记录不阻断。"""
        try:
            image = open(CORE, "rb").read()
        except Exception:
            return None
        pe = self._pe_dirs(image)
        if not pe:
            return None
        _, secs, dirs, _, _ = pe
        imp_rva, imp_size = dirs[1]
        if not imp_rva:
            return None
        imp_off = self._rva2off(secs, imp_rva)
        if imp_off is None:
            return None
        desc_size = 20
        i = 0
        while True:
            d = imp_off + i * desc_size
            if d + desc_size > len(image):
                break
            oft, ts, fwd, name_rva, iat_rva = struct.unpack_from("<IIIII", image, d)
            if not (oft or ts or name_rva):
                break
            i += 1
            if not name_rva:
                continue
            dlnoff = self._rva2off(secs, name_rva)
            if dlnoff is None:
                continue
            dllname = image[dlnoff:dlnoff + 64].split(b"\0")[0].decode('latin1', 'replace').lower()
            if "urlmon" not in dllname:
                continue
            thunk_rva = oft if oft else iat_rva
            thunk_off = self._rva2off(secs, thunk_rva)
            if thunk_off is None:
                continue
            slot_rva = iat_rva
            k = 0
            while thunk_off + k * 8 + 8 <= len(image):
                entry = struct.unpack_from("<Q", image, thunk_off + k * 8)[0]
                if entry == 0:
                    break
                if not (entry & 0x8000000000000000):  # import by name
                    hint_off = self._rva2off(secs, entry & 0x7FFFFFFF)
                    if hint_off is not None:
                        nm = image[hint_off + 2:hint_off + 2 + 64].split(b"\0")[0].decode('latin1', 'replace')
                        if nm == "URLDownloadToFileA":
                            return slot_rva + k * 8
                k += 1
        return None

    # ================= 调试泵 (T018 核心) =================
    def _read_event_raw_qword(self, ev, off):
        """从 DEBUG_EVENT 缓冲区原始偏移读 qword (票面: hProcess@24 / hThread@32 / imageBase@40)"""
        raw = (ctypes.c_ubyte * 48).from_address(ctypes.addressof(ev))
        return int.from_bytes(bytes(raw[off:off + 8]), "little")

    def _thread_ctx(self, hthread):
        """GetThreadContext via 调试事件句柄 (CONTEXT_CONTROL_AMD64, 引擎同款 fast-path)。
        返回 (rip, rsp, rax, ok)。"""
        if not hthread:
            return (None, None, None, False)
        with self.ctx_lock:
            ctx = CONTEXT()
            ctx.ContextFlags = CONTEXT_CONTROL_INTEGER_AMD64
            ok = self.k32.GetThreadContext(wt.HANDLE(hthread), ctypes.byref(ctx))
            if not ok:
                # 回退到 CONTROL-only (引擎已验证路径)
                ctx2 = CONTEXT()
                ctx2.ContextFlags = CONTEXT_CONTROL_AMD64
                ok2 = self.k32.GetThreadContext(wt.HANDLE(hthread), ctypes.byref(ctx2))
                if not ok2:
                    return (None, None, None, False)
                return (ctx2.Rip, ctx2.Rsp, None, True)
            return (ctx.Rip, ctx.Rsp, ctx.Rax, True)

    def pump_summary(self):
        with self.pump_lock:
            return {
                "health": dict(self.pump_health),
                "threads_seen": sorted(self.thread_handles.keys()),
                "run_thread_ready": self.run_thread_ready.is_set(),
                "run_hthread": hex(self.run_hthread) if self.run_hthread else None,
                "exit_code": self.pump_exit_code,
                "process_exited": self.pump_process_exited,
                "exceptions_count": len(self.exceptions),
            }

    def _handle_debug_event(self, ev):
        """处理单个调试事件; 返回 ContinueDebugEvent status。必须轻量、不得阻塞。"""
        code = ev.dwDebugEventCode
        pid = ev.dwProcessId
        tid = ev.dwThreadId
        detail = ""
        status = DBG_CONTINUE
        rec = {"code": code, "name": DBG_EVENT_NAMES.get(code, f"EVENT_{code}"), "tid": tid}

        if code == 3:  # CREATE_PROCESS_DEBUG_EVENT
            cpi = ev.u.CreateProcessInfo
            # 票面: hProcess@24 / hThread@32 / imageBase@40 (DEBUG_EVENT 原始偏移)
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
                if self.run_tid is not None and tid == self.run_tid and self.run_hthread is None:
                    self.run_hthread = cti.hThread
                    self.run_thread_ready.set()
            rip, rsp, rax, ok = self._thread_ctx(cti.hThread)
            detail = ("hThread=%#x start=%#x threadCtxOk=%s Rip=%s" % (cti.hThread, cti.lpStartAddress, ok, hex(rip) if rip else None))
            rec.update({"hThread": cti.hThread, "start": cti.lpStartAddress,
                        "ctx_ok": ok, "rip_at_create": hex(rip) if rip else None})
            if tid == self.run_tid:
                rec["is_run_thread"] = True
        elif code == 1:  # EXCEPTION_DEBUG_EVENT
            ei = ev.u.Exception
            exc = ei.ExceptionRecord
            rec.update({"code": hex(exc.ExceptionCode), "flags": hex(exc.ExceptionFlags),
                        "address": exc.ExceptionAddress, "firstChance": ei.dwFirstChance})
            # 首挂起线程 Rip (异常线程 = 当前事件线程; 用调试句柄读上下文)
            h = self.thread_handles.get(tid)
            rip, rsp, rax, ok = self._thread_ctx(h)
            rec.update({"thread_rip": hex(rip) if rip else None,
                        "thread_rsp": hex(rsp) if rsp else None,
                        "thread_rax": hex(rax) if rax is not None else None,
                        "thread_ctx_ok": ok})
            is_bp = (exc.ExceptionCode == EXCEPTION_BREAKPOINT)
            benign_boot = exc.ExceptionCode in BENIGN_BOOT_EXCEPTIONS
            with self.pump_lock:
                first_bp = not self.pump_health["first_breakpoint_seen"] and is_bp
                if is_bp:
                    self.pump_health["first_breakpoint_seen"] = True
            if benign_boot:
                status = DBG_CONTINUE  # 引导断点 / 引导期良性浮点异常 → 被动观测继续
                rec["handled"] = "DBG_CONTINUE_benign_boot" if not is_bp else "DBG_CONTINUE_first_breakpoint"
            else:
                status = DBG_EXCEPTION_NOT_HANDLED  # 其它 (含真实 AV) → 不吞 (交给进程自身分发)
                rec["handled"] = "DBG_EXCEPTION_NOT_HANDLED"
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
            # core.dll 加载探测 (泵事件侧, 避免引导期外部观测扰动反调试)
            if ldi.lpBaseOfDll and self.core_base is None:
                self._pump_core_candidate = ldi.lpBaseOfDll
            detail = "base=%#x" % ldi.lpBaseOfDll
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
        # 边到边落盘 (提前退出也留证据)
        try:
            if self._pump_event_fd:
                self._pump_event_fd.write(json.dumps(rec, ensure_ascii=False) + "\n")
                self._pump_event_fd.flush()
        except Exception:
            pass
        return status

    def pump_loop(self):
        """调试泵线程: 先在泵线程内 CreateProcessW(DEBUG_ONLY_THIS_PROCESS) (调试会话线程绑定),
        然后 WaitForDebugEvent(500ms 超时轮询停止标志) → 处理 → 立即 Continue。"""
        if not self.create_host_debug():
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
            # EXIT_PROCESS 之后调试会话结束 → 退出泵
            if ev.dwDebugEventCode == 5:
                break
        with self.pump_lock:
            self.pump_health["pump_exited"] = True

    # ================= 宿主创建 (调试端口) =================
    def create_host_debug(self):
        """CreateProcessW(..., DEBUG_ONLY_THIS_PROCESS) 取代普通创建; NO_BYPASS=1 环境块。
        [T018-实测] Windows 调试会话是线程绑定的: WaitForDebugEvent 必须在 CreateProcessW 的
        同一线程调用 (否则 err=6 ERROR_INVALID_HANDLE)。本方法由泵线程调用, 事件即刻可泵。"""
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
        cmd = ctypes.create_unicode_buffer('"%s"' % HOST)
        flags = DEBUG_ONLY_THIS_PROCESS | CREATE_UNICODE_ENVIRONMENT
        ok = k32.CreateProcessW(None, cmd, None, None, False, flags, env_buf, DEPLOY,
                                ctypes.byref(si), ctypes.byref(pi))
        if not ok:
            return False
        self.pi = pi
        self.proc = pi.hProcess
        return True

    def terminate_host(self):
        if self.proc:
            try:
                self.k32.TerminateProcess(wt.HANDLE(self.proc), 0)
            except Exception:
                pass

    # ================= RIP 采样 (Run 线程调试句柄, 不用 OpenThread) =================
    def sample_rip(self):
        """对 Run 线程调试句柄 SuspendThread+GetThreadContext+ResumeThread。
        [T018] 句柄来自 CREATE_THREAD_DEBUG_EVENT, 不是 OpenThread (P-11 外部观测族垫零)。"""
        with self.pump_lock:
            ht = self.run_hthread
        if not ht:
            return None
        with self.ctx_lock:
            prev = self.k32.SuspendThread(wt.HANDLE(ht))
            if prev == 0xFFFFFFFF:
                return {"rip": None, "owner": None, "rsp": None, "rax": None,
                        "error": "suspend_failed", "hthread_src": "CREATE_THREAD_DEBUG_EVENT"}
            try:
                ctx = CONTEXT()
                ctx.ContextFlags = CONTEXT_CONTROL_INTEGER_AMD64
                ok = self.k32.GetThreadContext(wt.HANDLE(ht), ctypes.byref(ctx))
                if not ok:
                    return {"rip": None, "owner": None, "rsp": None, "rax": None,
                            "error": "getctx_failed %d" % ctypes.get_last_error(),
                            "hthread_src": "CREATE_THREAD_DEBUG_EVENT"}
                rip = ctx.Rip
                return {
                    "rip": hex(rip),
                    "owner": self.owner(rip) if rip else "(zero)",
                    "rsp": hex(ctx.Rsp),
                    "rax": hex(ctx.Rax),
                    "hthread_src": "CREATE_THREAD_DEBUG_EVENT",
                }
            finally:
                self.k32.ResumeThread(wt.HANDLE(ht))

    def sampler_loop(self, interval=0.03, duration=0):
        t0 = time.time()
        seq = 0
        while self.sampling:
            s = self.sample_rip()
            if s:
                with self.sample_lock:
                    self.rip_log.append({"t": round(time.time() - t0, 3), "seq": seq, **s})
                seq += 1
            time.sleep(interval)

    # ================= 窗口 =================
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
        # 回退: EnumWindows 回调不触发 (P-11) → FindWindowW 按已知类名扫 (T017 实弹窗口类)
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

    def _win_thread(self, hwnd):
        p = wt.DWORD(0)
        tid = int(self.user32.GetWindowThreadProcessId(wt.HWND(hwnd), ctypes.byref(p)))
        return tid

    def enum_children(self, parent):
        WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
        out = []

        @WNDENUMPROC
        def _cb(hwnd, lp):
            cn = ctypes.create_unicode_buffer(256)
            self.user32.GetClassNameW(hwnd, cn, 256)
            tt = ctypes.create_unicode_buffer(512)
            self.user32.GetWindowTextW(hwnd, tt, 512)
            cid = self.user32.GetDlgCtrlID(hwnd)
            rect = wt.RECT()
            self.user32.GetWindowRect(hwnd, ctypes.byref(rect))
            out.append({"hwnd": int(hwnd), "class": cn.value, "title": tt.value,
                        "ctrl_id": int(cid),
                        "rect": [rect.left, rect.top, rect.right, rect.bottom],
                        "thread": self._win_thread(hwnd)})
            return True

        self.user32.EnumChildWindows(wt.HWND(parent), _cb, 0)
        return out

    # ================= GUI 存活观测 =================
    def gui_hung(self, hwnd):
        return int(self.user32.IsHungAppWindow(ctypes.c_void_p(hwnd)))

    def gui_snapshot(self, hwnds):
        snap = []
        for hwnd in hwnds:
            alive = bool(self.user32.IsWindow(ctypes.c_void_p(hwnd)))
            snap.append({"hwnd": hex(hwnd), "is_window": alive,
                         "hung": self.gui_hung(hwnd) if alive else None})
        return snap

    def gui_pump(self, hwnd, n=3, interval=0.05):
        ok = 0
        for _ in range(n):
            try:
                self.send(hwnd, 0x0)  # WM_NULL
                ok += 1
            except Exception:
                break
            time.sleep(interval)
        return ok

    # ================= 事件驱动 =================
    def resolve_core_base(self):
        for base, size, name in self.modules:
            if name.lower() == "core.dll":
                h = self.rpm(base, 0x1000)
                if h and h[:2] == b"MZ":
                    return base, size
        return None, None

    def resolve_host_exe_base(self):
        host_name = os.path.basename(HOST)
        for base, size, name in self.modules:
            if name.lower() == host_name.lower():
                h = self.rpm(base, 0x1000)
                if h and h[:2] == b"MZ":
                    return base, size
        return None, None

    def wait_core_loaded(self, timeout=40):
        t0 = time.time()
        while time.time() - t0 < timeout:
            self.enum_modules()
            cb, sz = self.resolve_core_base()
            if cb:
                self.core_base = cb
                core_mod = [{"base": hex(b), "size": hex(s), "name": n} for b, s, n in self.modules if n.lower() == "core.dll"]
                return {"loaded": True, "wait_s": round(time.time() - t0, 2), "core_module": core_mod}
            time.sleep(0.5)
        return {"loaded": False, "wait_s": round(time.time() - t0, 2), "core_module": None}

    def log_event(self, kind, detail):
        self.events.append({"t": round(time.time() - self.t0, 3), "kind": kind, "detail": detail})
        print("[%7.3f] %s: %s" % (time.time() - self.t0, kind, detail))

    def post_thread(self, tid, msg, w=0, l=0):
        return bool(self.user32.PostThreadMessageW(wt.DWORD(tid), msg, w, l))

    def drive_thread_queue(self, tid):
        WM_NULL, WM_PAINT = 0x0, 0xF
        WM_TIMER, WM_COMMAND = 0x113, 0x111
        WM_USER, WM_APP = 0x400, 0x8000
        W_USER1, W_312 = 0x401, 0x312
        WM_ACTIVATEAPP, WM_ACTIVATE, WM_SETFOCUS = 0x1C, 0x6, 0x7
        VK_RETURN, VK_SPACE, VK_TAB = 0x0D, 0x20, 0x09

        def MAKEWPARAM(lo, hi): return (hi << 16) | lo

        self.log_event("phase", "T: PostThreadMessage 线程队列驱动")
        for msg in (WM_NULL, WM_PAINT, WM_ACTIVATEAPP, WM_ACTIVATE, WM_SETFOCUS):
            self.post_thread(tid, msg); time.sleep(0.08)
        for tid_ in (1, 2, 3, 5, 0x65, 0x3e8, 0x3e9, 0x3ea, 0x3eb, 0x3ec, 0x3ed):
            self.post_thread(tid, WM_TIMER, tid_, 0); time.sleep(0.12)
            s = self.sample_rip()
            if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", "PostThreadMessage WM_TIMER id=%#x -> RIP %s" % (tid_, s))
                return True
        for lp in (0x203, 0x205, 0):
            self.post_thread(tid, W_USER1, 0, lp); time.sleep(0.15)
        for wp in (0, 1, 2):
            self.post_thread(tid, W_312, wp, 0); time.sleep(0.15)
        for vk in (VK_RETURN, VK_SPACE, VK_TAB):
            self.post_thread(tid, WM_COMMAND, MAKEWPARAM(vk, 0), 0); time.sleep(0.15)
        s = self.sample_rip()
        if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
            self.log_event("urlmon_hit", "thread queue -> RIP %s" % (s,))
            return True
        return False

    def send(self, hwnd, msg, w=0, l=0):
        """SendMessageTimeoutW (SMTO_ABORTIFHUNG|SMTO_BLOCK, 1000ms) — 防调试附加下窗口冻结导致主线程永久阻塞。
        返回 (ok_bool, result)。"""
        SMTO_ABORTIFHUNG = 0x0002
        SMTO_BLOCK = 0x0001
        res = wt.LPARAM(0)
        ok = self.user32.SendMessageTimeoutW(wt.HWND(hwnd), msg, w, l, SMTO_ABORTIFHUNG | SMTO_BLOCK, 1000, ctypes.byref(res))
        return (bool(ok), int(res.value))

    def post(self, hwnd, msg, w=0, l=0):
        return self.user32.PostMessageW(wt.HWND(hwnd), msg, w, l)

    def drive_battery(self, hwnd, children):
        WM_NULL, WM_PAINT, WM_CLOSE, WM_COMMAND = 0x0, 0xF, 0x10, 0x111
        WM_TIMER, WM_DRAWITEM, WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x113, 0x2B, 0x100, 0x101, 0x102
        WM_LBUTTONDOWN, WM_LBUTTONUP, WM_LBUTTONDBLCLK = 0x201, 0x202, 0x203
        WM_RBUTTONDOWN, WM_RBUTTONUP, WM_RBUTTONDBLCLK = 0x204, 0x205, 0x206
        WM_MOUSEMOVE, BM_CLICK = 0x200, 0xF5
        W_USER1 = 0x401
        W_312 = 0x312
        MK_LBUTTON = 0x0001
        VK_RETURN, VK_TAB, VK_SPACE = 0x0D, 0x09, 0x20

        def MAKEWPARAM(lo, hi): return (hi << 32) | (lo & 0xFFFF) if False else (hi << 16) | lo
        def MAKELPARAM(x, y): return (y << 16) | (x & 0xFFFF)

        self.log_event("phase", "0: 基本泵 (WM_NULL/WM_PAINT/WM_TIMER/WM_USER/键盘/激活)")
        for _ in range(3):
            self.post(hwnd, WM_NULL)
            time.sleep(0.05)
        self.post(hwnd, WM_PAINT); time.sleep(0.15)
        for msg in (0x1C, 0x6, 0x7, 0x18):
            self.post(hwnd, msg); time.sleep(0.1)
        for tid_ in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x65, 0x100, 0x3e8, 0x3e9, 0x3ea, 0x3eb, 0x3ec, 0x3ed):
            self.post(hwnd, WM_TIMER, tid_, 0); time.sleep(0.08)
            s = self.sample_rip()
            if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", "WM_TIMER id=%#x -> RIP %s" % (tid_, s))
                return True
        for lp in (0x203, 0x205, 0):
            self.send(hwnd, W_USER1, 0, lp); time.sleep(0.15)
        for wp in (0, 1, 2):
            self.send(hwnd, W_312, wp, 0); time.sleep(0.15)
        for vk in (VK_RETURN, VK_TAB, VK_SPACE):
            self.send(hwnd, WM_KEYDOWN, vk, 0); time.sleep(0.1)
            self.send(hwnd, WM_KEYUP, vk, 0); time.sleep(0.1)

        self.log_event("phase", "1: 控件交互 (%d Button / %d child)" % (
            len([c for c in children if c["class"] == "Button"]), len(children)))
        for c in children:
            self.log_event("child", "hwnd=%#x class=%s id=%d title=%r" % (
                c["hwnd"], c["class"], c["ctrl_id"], c["title"][:40]))
        for c in children:
            hid = c["ctrl_id"]
            self.post(c["hwnd"], BM_CLICK); time.sleep(0.2)
            self.send(c["hwnd"], BM_CLICK); time.sleep(0.2)
            self.send(hwnd, WM_COMMAND, MAKEWPARAM(hid, 0), c["hwnd"]); time.sleep(0.25)
            s = self.sample_rip()
            if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", "WM_COMMAND id=%#x -> RIP %s" % (hid, s))
                return True

        self.log_event("phase", "2: 鼠标事件")
        for c in children:
            x0, y0, x1, y1 = c["rect"]
            cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
            lp = MAKELPARAM(cx, cy)
            self.send(hwnd, WM_LBUTTONDOWN, MK_LBUTTON, lp); time.sleep(0.12)
            self.send(hwnd, WM_LBUTTONUP, 0, lp); time.sleep(0.15)
            self.send(hwnd, WM_LBUTTONDBLCLK, MK_LBUTTON, lp); time.sleep(0.12)
            self.send(hwnd, WM_RBUTTONDOWN, 0, lp); time.sleep(0.12)
            self.send(hwnd, WM_RBUTTONUP, 0, lp); time.sleep(0.15)
            s = self.sample_rip()
            if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", "mouse child %#x -> RIP %s" % (c["hwnd"], s))
                return True
        r = wt.RECT()
        self.user32.GetClientRect(wt.HWND(hwnd), ctypes.byref(r))
        cx, cy = r.right // 2, r.bottom // 2
        for msg in (WM_LBUTTONDOWN, WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONDOWN, WM_RBUTTONUP):
            self.send(hwnd, msg, MK_LBUTTON if msg in (WM_LBUTTONDOWN, WM_LBUTTONDBLCLK) else 0, MAKELPARAM(cx, cy))
            time.sleep(0.15)
        s = self.sample_rip()
        if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
            self.log_event("urlmon_hit", "mouse client -> RIP %s" % (s,))
            return True

        self.log_event("phase", "3: 计时器轮询 + 自定义组合")
        for tid_ in list(range(1, 25)) + [0x3e8, 0x3e9, 0x3ea, 0x3eb, 0x3ec, 0x3ed]:
            self.post(hwnd, WM_TIMER, tid_, 0)
            if tid_ % 4 == 0:
                time.sleep(0.2)
                s = self.sample_rip()
                if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", "timer storm id=%#x -> RIP %s" % (tid_, s))
                    return True
        for hid in (0x3ec, 0x3ed, 0x3e4, 0x3e5, 0x14e, 0x154, 2, 3, 7, 9, 1, 0x65, 0x30, 0x33, 0x34, 0x36, 0x3e6, 0x3e7, 0x3e8):
            for hi in (0, 1, 2):
                self.send(hwnd, WM_COMMAND, MAKEWPARAM(hid, hi), 0)
                time.sleep(0.12)
                s = self.sample_rip()
                if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", "WM_COMMAND id=%#x hi=%d -> RIP %s" % (hid, hi, s))
                    return True

        self.log_event("phase", "4: WM_CLOSE (预期 PostQuitMessage 退出路径)")
        self.post(hwnd, WM_CLOSE)
        time.sleep(1.0)
        return False

    def finish(self):
        code = wt.DWORD(0)
        self.k32.GetExitCodeThread(self.hthread, ctypes.byref(code))
        self.iat_post = self.read_qword(self.urlmon_slot_va) if self.urlmon_slot_va else None
        alive = self.k32.WaitForSingleObject(self.hthread, 0) == 0x102  # STILL_ACTIVE
        return {"exit_code": hex(code.value), "still_active": alive,
                "iat_pre": hex(self.iat_pre) if self.iat_pre else None,
                "iat_post": hex(self.iat_post) if self.iat_post else None,
                "iat_unchanged": self.iat_pre == self.iat_post if self.iat_pre is not None and self.iat_post is not None else None}

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

    # ================= 冻结/泵健康观测 =================
    def check_freeze(self, tag):
        """冻结征兆: GUI hung>0 或 泵消费停滞 (last_consume 距今 >5s) 或 泵提前退出。
        排除进程已退出后的泵空闲 (进程死了泵当然无事可消费, 不是冻结)。"""
        with self.pump_lock:
            last = self.pump_health.get("last_consume_t")
            pump_exited = self.pump_health.get("pump_exited")
            wait_errors = list(self.pump_health.get("wait_errors", []))
            proc_exited = self.pump_process_exited
        now = time.time()
        if proc_exited:
            return self.freeze_symptoms  # 进程已退: 泵空闲是正常终止, 非冻结
        if last and (now - last) > 5.0:
            self.freeze_symptoms.append({"t": round(now - self.t0, 3), "kind": "pump_stall",
                                         "detail": "%s: pump last_consume %.1fs ago (泵未消费 = 冻结判据作废)" % (tag, now - last)})
        if pump_exited and not self.pump_process_exited:
            self.freeze_symptoms.append({"t": round(now - self.t0, 3), "kind": "pump_exited_early",
                                         "detail": "%s: pump exited before EXIT_PROCESS; wait_errors=%r" % (tag, wait_errors)})
        if wait_errors:
            self.freeze_symptoms.append({"t": round(now - self.t0, 3), "kind": "pump_wait_error",
                                         "detail": "%s: wait_errors=%r" % (tag, wait_errors)})
        return self.freeze_symptoms

    # ================= 主流程 =================
    def run(self, out_prefix="t05", dry=False, terminate_at_end=True):
        t_all = time.time()
        # 0) 红线: sha256 fail-closed (候选三文件)
        sha_core = sha256_file(CORE)
        if sha_core != CAND_SHA:
            return {"redline": "FAIL_CORE_SHA", "sha": sha_core, "expect": CAND_SHA}
        sha_host = sha256_file(HOST)
        if sha_host != HOST_SHA:
            return {"redline": "FAIL_HOST_SHA", "sha": sha_host, "expect": HOST_SHA}
        sha_cfg = sha256_file(CONFIG)
        if sha_cfg != CONFIG_SHA:
            return {"redline": "FAIL_CONFIG_SHA", "sha": sha_cfg, "expect": CONFIG_SHA}
        print("redline sha OK (core=3650ea6c perfect candidate, host=a852880a, config=cde9be13)")

        # 0.25) 任务 1: 导出表动态解析 (Run/GetAppVersion — 不许硬编码 RVA)
        exports = self.resolve_exports_disk()
        self.export_resolve = exports
        run_rva = exports.get("Run")
        getapp_rva = exports.get("GetAppVersion")
        if not run_rva or not getapp_rva:
            self.export_resolve_ok = False
            self.log_event("export_resolve", json.dumps({
                "ok": False, "err": self.export_resolve_err,
                "found": sorted(exports.keys())[:20]}))
            return {"redline": "FAIL_RUN_EXPORT", "err": self.export_resolve_err,
                    "found": sorted(exports.keys())[:20], "export_resolve": exports,
                    "no_bypass": "1"}
        self.export_resolve_ok = True
        RUN_RVA = run_rva
        URLMON_SLOT_RVA = self.resolve_urlmon_slot_disk()
        self.urlmon_slot_rva = URLMON_SLOT_RVA
        self.log_event("export_resolve", json.dumps({
            "ok": True, "Run_rva": hex(RUN_RVA), "GetAppVersion_rva": hex(getapp_rva),
            "urlmon_slot_rva": hex(URLMON_SLOT_RVA) if URLMON_SLOT_RVA else None,
            "preferred_base": hex(CAND_PREFERRED_BASE),
            "resolved_from_disk_export_table": True}))

        # 0.5) 防火墙现状核实 (只读, 不改)
        fw = self.firewall_block_status()
        self.log_event("firewall_check", json.dumps(fw))

        # 1) 宿主创建 + 调试泵: 泵线程内 CreateProcessW(DEBUG_ONLY_THIS_PROCESS) + WaitForDebugEvent
        #    [T018-实测] Windows 调试会话线程绑定: 创建与泵必须同线程 (否则 err=6)。
        self._pump_event_path = os.path.join(DEPLOY, "%s_dbg_pump_events.ndjson" % out_prefix)
        try:
            self._pump_event_fd = open(self._pump_event_path, "w", encoding="utf-8")
        except Exception:
            self._pump_event_fd = None
        self.pump_stop.clear()
        self.pump_thread = threading.Thread(target=self.pump_loop, daemon=True, name="dbg-pump")
        self.pump_thread.start()
        self.pump_started = True
        if not self.pump_created.wait(timeout=15):
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_CREATEPROCESS_DEBUG", "err": "pump create timeout",
                    "no_bypass": "1", "pump": self.pump_summary()}
        if self.pump_health.get("create_failed"):
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_CREATEPROCESS_DEBUG", "err": self.pump_health.get("create_err"),
                    "no_bypass": "1", "pump": self.pump_summary()}
        self.log_event("host_start_debug", "pid=%d DEBUG_ONLY_THIS_PROCESS(0x2) NO_BYPASS=1" % self.pid)

        # 1.2) 引导期: 泵事件侧等待 core.dll LOAD_DLL (不做外部观测 — 反调试扰动最小化)
        #      [T018-实测] 引导期并发 open_proc/enum_modules/rpm 会触发壳反调试 (WinLicense 对话框)。
        boot_deadline = time.time() + 40
        while time.time() < boot_deadline:
            with self.pump_lock:
                cand = self._pump_core_candidate
                pump_ok = not self.pump_health.get("wait_errors") and not self.pump_health.get("create_failed")
                proc_exited = self.pump_process_exited
            if proc_exited:
                self._cleanup_pump()
                self._cleanup_handles()
                return {"redline": "FAIL_HOST_EXITED_AT_BOOT", "exit_code": self.pump_exit_code,
                        "pump": self.pump_summary(), "no_bypass": "1"}
            if cand is not None and pump_ok:
                self.log_event("core_load_pump", "core.dll LOAD_DLL base=%#x (pump event)" % cand)
                break
            time.sleep(0.1)
        else:
            self.terminate_host()
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_CORE_NOT_LOADED_BOOT", "pump": self.pump_summary(),
                    "no_bypass": "1"}

        # 1.3) 引导完成沉降 (让壳引导/消息循环建立, 再开始外部观测)
        time.sleep(2.0)

        # 1.4) 外部观测开始: open_proc + 一次 enum_modules (MZ 双核 fail-closed)
        if not self.open_proc():
            self.terminate_host()
            self._cleanup_pump()
            return {"redline": "FAIL_OPENPROC", "err": ctypes.get_last_error(), "pid": self.pid}

        # 1.5) 等待 core.dll 基址确认 (enum_modules + MZ, 短超时)
        wcl = self.wait_core_loaded(timeout=10)
        self.log_event("core_load_wait", json.dumps(wcl))
        if not wcl["loaded"]:
            self.terminate_host()
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_CORE_NOT_LOADED", "wait": wcl,
                    "pump": self.pump_summary()}

        # 2) 基址动态解析 (MZ 双核 fail-closed) + 首选基址核对 (T019 票面语义边界条款)
        self.enum_modules()
        core_base, core_size = self.resolve_core_base()
        if core_base is None:
            self.terminate_host()
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_CORE_NOT_FOUND", "modules": [n for _, _, n in self.modules],
                    "pump": self.pump_summary()}
        self.core_base = core_base
        host_base, host_size = self.resolve_host_exe_base()
        if host_base is None:
            self.terminate_host()
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_HOST_NOT_FOUND", "modules": [n for _, _, n in self.modules],
                    "pump": self.pump_summary()}
        self.host_exe_base = host_base
        # T019 决定性约束 ③: 实际加载基址 vs 候选首选基址 是否一致 (记录事实, 判定不依赖)
        self.base_agreement = {
            "actual_core_base": hex(core_base),
            "preferred_candidate_base": hex(CAND_PREFERRED_BASE),
            "equal": core_base == CAND_PREFERRED_BASE,
        }
        RUN_VA = core_base + RUN_RVA
        URLMON_SLOT_VA = core_base + URLMON_SLOT_RVA if URLMON_SLOT_RVA else None
        self.urlmon_slot_va = URLMON_SLOT_VA
        RUN_PARAM = host_base
        core_head = self.rpm(core_base, 0x1000)
        core_ok = core_head and core_head[:2] == b"MZ"
        host_head = self.rpm(host_base, 0x1000)
        host_ok = host_head and host_head[:2] == b"MZ"
        run_bytes = self.rpm(RUN_VA, 16)
        iat_val = self.read_qword(URLMON_SLOT_VA) if URLMON_SLOT_VA else None
        self.iat_pre = iat_val
        urlmon_mod = [{"base": hex(b), "size": hex(s), "name": n} for b, s, n in self.modules if "urlmon" in n.lower()]
        wininet_mod = [{"base": hex(b), "size": hex(s), "name": n} for b, s, n in self.modules if "wininet" in n.lower()]
        deploy_check = {
            "core_base": hex(core_base), "core_size": hex(core_size), "core_mz": core_ok,
            "host_exe_base": hex(host_base), "host_size": hex(host_size), "host_mz": host_ok,
            "base_agreement": self.base_agreement,
            "run_rva": hex(RUN_RVA), "run_va": hex(RUN_VA),
            "run_head": run_bytes.hex() if run_bytes else None,
            "run_head_plaintext": run_bytes[:6] == bytes.fromhex("415741564155") if run_bytes else False,
            "getapp_rva": hex(getapp_rva),
            "urlmon_iat_slot": hex(URLMON_SLOT_VA) if URLMON_SLOT_VA else None,
            "urlmon_iat_slot_rva": hex(URLMON_SLOT_RVA) if URLMON_SLOT_RVA else None,
            "urlmon_iat_value": hex(iat_val) if iat_val else None,
            "urlmon_module": urlmon_mod,
            "wininet_module": wininet_mod,
        }
        self.log_event("deploy_check", json.dumps(deploy_check))
        if not (core_ok and host_ok):
            self.terminate_host()
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_FIXED_BASE", "deploy_check": deploy_check,
                    "pump": self.pump_summary()}

        if dry:
            all_wnds = self.find_windows()
            print("modules:", len(self.modules), "urlmon:", urlmon_mod, "wininet:", wininet_mod)
            print("windows:", json.dumps(all_wnds, ensure_ascii=False)[:2000])
            self.terminate_host()
            time.sleep(1)
            self._cleanup_pump()
            self._cleanup_handles()
            return {"dry": True, "deploy_check": deploy_check, "modules_count": len(self.modules),
                    "urlmon_loaded": bool(urlmon_mod), "wininet_loaded": bool(wininet_mod),
                    "windows": all_wnds, "pump": self.pump_summary(),
                    "export_resolve": self.export_resolve,
                    "base_agreement": self.base_agreement}

        # 3) 触发 Run
        tid = wt.DWORD(0)
        self.hthread = self.k32.CreateRemoteThread(
            self.hproc, None, 0, ctypes.c_void_p(RUN_VA), ctypes.c_void_p(RUN_PARAM), 0, ctypes.byref(tid))
        if not self.hthread:
            self.terminate_host()
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_CREATEREMOTETHREAD", "err": ctypes.get_last_error(),
                    "pump": self.pump_summary()}
        self.tid = tid.value
        self.run_tid = self.tid
        self.log_event("run_trigger", "CreateRemoteThread Run@%#x param=%#x tid=%d" % (RUN_VA, RUN_PARAM, self.tid))

        # 3.5) 等待泵记录 Run 线程调试句柄 (CREATE_THREAD_DEBUG_EVENT)
        with self.pump_lock:
            if self.run_tid in self.thread_handles and self.run_hthread is None:
                self.run_hthread = self.thread_handles[self.run_tid]
                self.run_thread_ready.set()
        if not self.run_thread_ready.wait(timeout=15):
            self.check_freeze("run_thread_handle_wait")
            self.terminate_host()
            self._cleanup_pump()
            self._cleanup_handles()
            return {"redline": "FAIL_RUN_THREAD_HANDLE", "tid": self.tid,
                    "pump": self.pump_summary(), "freeze": self.freeze_symptoms}
        self.log_event("run_thread_handle", "hThread=%#x (CREATE_THREAD_DEBUG_EVENT) tid=%d" % (
            self.run_hthread, self.tid))

        # 4) RIP 采样线程 (0.03s 高密; 调试句柄 suspend/read/resume)
        self.sampling = True
        sampler = threading.Thread(target=self.sampler_loop, args=(0.03,), daemon=True)
        sampler.start()

        # 5) 等待 Run 到达消息循环 (win32u/user32)
        loop_reached = False
        deadline = time.time() + 20
        while time.time() < deadline:
            s = self.sample_rip()
            if s and s.get("owner") in ("win32u.dll", "user32.dll"):
                loop_reached = True
                self.log_event("msg_loop", "RIP=%s owner=%s" % (s.get("rip"), s.get("owner")))
                break
            time.sleep(0.1)
        if not loop_reached:
            time.sleep(2)
            s = self.sample_rip()
            self.log_event("msg_loop_not_confirmed", "RIP=%s" % (s,))

        # 6) 窗口发现 (Run 线程窗口 tid 匹配)
        all_host_wnds = self.find_windows()
        run_wnds = [w for w in all_host_wnds if w["tid"] == self.tid]
        self.windows = all_host_wnds
        self.log_event("windows", "host windows=%d run_thread_windows=%d tid=%d" % (
            len(all_host_wnds), len(run_wnds), self.tid))
        license_wnds = [w for w in all_host_wnds if w["class"] == "PigToGoLicenseDialog"]
        if not license_wnds:
            # 附加改变行为自证: T017 非附加下 3/3 出现"授权验证"
            self.attach_changed_behavior = True
            self.log_event("attach_changed_behavior",
                           "PigToGoLicenseDialog NOT found under DEBUG_ONLY_THIS_PROCESS (T017 非附加 3/3 出现) — 如实上报")

        # 6.5) 线程队列驱动
        result = {"hit_urlmon": False, "hit_wininet": False}
        hit = self.drive_thread_queue(self.tid)
        if hit:
            result["hit_urlmon"] = True

        # 7) UI 事件驱动
        if not result["hit_urlmon"]:
            targets = run_wnds if run_wnds else all_host_wnds[:3]
            self.log_event("window_targets", "driving %d windows" % len(targets))
            for w in targets:
                hwnd = w["hwnd"]
                children = self.enum_children(hwnd)
                self.log_event("window_target", "hwnd=%#x class=%s title=%r children=%d" % (
                    hwnd, w["class"], w["title"][:60], len(children)))
                hit = self.drive_battery(hwnd, children)
                if hit:
                    result["hit_urlmon"] = True
                    break

        # 7.5) 延后沉降采样
        if not result["hit_urlmon"]:
            self.log_event("phase", "S: 延后沉降采样 5s (异步/延迟触发)")
            settle_deadline = time.time() + 5
            while time.time() < settle_deadline:
                s = self.sample_rip()
                if s and s.get("owner") in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", "settle -> RIP %s" % (s,))
                    result["hit_urlmon"] = True
                    break
                time.sleep(0.05)

        time.sleep(1.5)
        self.sampling = False
        sampler.join(timeout=3)

        # 7.75) GUI 存活观测 + 冻结征兆
        gui_obs = []
        for w in (self.windows if self.windows else []):
            snap = self.gui_snapshot([w["hwnd"]])
            pumped = self.gui_pump(w["hwnd"], n=2, interval=0.03)
            gui_obs.append({"window": w, "snapshot": snap, "wm_null_pumped": pumped})
            for g in snap:
                if g.get("hung"):
                    self.freeze_symptoms.append({"t": round(time.time() - self.t0, 3),
                                                 "kind": "gui_hung",
                                                 "detail": "hwnd=%s hung=%d (冻结征兆候选)" % (g["hwnd"], g["hung"])})
        self.gui_alive = any(g["snapshot"][0]["hung"] == 0 and g["snapshot"][0]["is_window"]
                             for g in gui_obs) if gui_obs else False
        self.gui_obs = gui_obs
        self.check_freeze("final")
        self.log_event("gui_alive", json.dumps({"alive": self.gui_alive, "obs": gui_obs}))

        # 8) 终态
        fin = self.finish()
        self.log_event("final", json.dumps(fin))

        # 9) urlmon 命中分析 + 稳定 RIP 分析
        urlmon_hits = [r for r in self.rip_log if r.get("owner") in ("urlmon.dll", "wininet.dll")]
        result["urlmon_hits"] = urlmon_hits[:20]
        result["urlmon_hit_count"] = len(urlmon_hits)
        if urlmon_hits:
            result["urlmon_first_enter_t"] = urlmon_hits[0]["t"]
            result["hit_urlmon"] = True
        stable_rip = self._analyze_stable_rip()

        # 10) 判定证据
        real_avs = [e for e in self.exceptions
                    if e.get("code") in ("0xc0000005", "0xc0000008", "0xc000001d", "0xc0000096",
                                         "0xc000001e", "0xc0000094", "0xc0000095", "0xc0000096")
                    or (e.get("code") and e.get("code") not in ("0x80000003", "0xc000008e"))]
        # EXIT_PROCESS 缺失时的崩溃签名: EXIT_THREAD exitCode 全 = 0xC0000005
        crash_thread_exits = [e for e in self.dbg_events
                              if e.get("name") == "EXIT_THREAD_DEBUG_EVENT"
                              and e.get("exitCode") and e.get("exitCode") not in (0,)]
        exit_crash_code = None
        if crash_thread_exits:
            exit_crash_code = max(e.get("exitCode") for e in crash_thread_exits)
        if self.pump_exit_code is None and exit_crash_code:
            self.pump_exit_code = exit_crash_code
            self.pump_process_exited = True
        non_boot_exceptions = real_avs
        verdict = {
            "evidence_source": "debug_port_pump (DEBUG_ONLY_THIS_PROCESS)",
            "urlmon_hit_count": len(urlmon_hits),
            "urlmon_first_hit": urlmon_hits[0] if urlmon_hits else None,
            "exception_events_non_breakpoint": non_boot_exceptions,
            "exception_events_total": len(self.exceptions),
            "process_alive_at_final": bool(fin["still_active"]),
            "process_exit_code": self.pump_exit_code,
            "process_exited_before_end": self.pump_process_exited,
            "exit_thread_crash_codes": crash_thread_exits[:5],
            "stable_rip": stable_rip,
            "attach_changed_behavior": self.attach_changed_behavior,
            "freeze_symptoms": self.freeze_symptoms,
            "pump": self.pump_summary(),
            "state": self._classify(non_boot_exceptions, urlmon_hits, stable_rip, fin, result),
        }
        self.log_event("verdict", json.dumps(verdict))

        # 11) 退出
        if terminate_at_end:
            self.terminate_host()
            time.sleep(1.0)
        self._cleanup_pump(wait_s=10)
        if self.pump_thread and self.pump_thread.is_alive():
            self.log_event("pump_join_timeout", "pump thread still alive after join (10s)")
        self._cleanup_handles()

        out = {
            "schema": "xx21b_t05_run_ui_dbg_pcell_verdict/v1",
            "case": "xiongxiong_core",
            "work_order": "XC-XXI-B",
            "task": "T0.5 终跑 (完美候选路线): B1' 宿主 + 脱壳 core 完美候选 + 调试端口泵",
            "date_utc": now_utc(),
            "redline": {
                "no_bypass": "1",
                "candidate_sha256": CAND_SHA,
                "host_sha256": HOST_SHA,
                "config_sha256": CONFIG_SHA,
                "samples_not_modified": True,
                "network_deny_all": fw,
            },
            "export_resolve": {"ok": self.export_resolve_ok, "err": self.export_resolve_err,
                               "Run_rva": hex(run_rva) if run_rva else None,
                               "GetAppVersion_rva": hex(getapp_rva) if getapp_rva else None,
                               "urlmon_slot_rva": hex(URLMON_SLOT_RVA) if URLMON_SLOT_RVA else None,
                               "all": {k: hex(v) for k, v in self.export_resolve.items()}},
            "deploy_check": deploy_check,
            "run_trigger": {"method": "CreateRemoteThread", "va": hex(RUN_VA),
                            "param": hex(RUN_PARAM), "tid": self.tid},
            "host_creation": {"method": "CreateProcessW", "flags": "DEBUG_ONLY_THIS_PROCESS(0x2)|CREATE_UNICODE_ENVIRONMENT(0x400)",
                              "pid": self.pid},
            "dbg_port": {
                "pump_health": dict(self.pump_health),
                "dbg_events": list(self.dbg_events),
                "exceptions": list(self.exceptions),
                "exit_code": self.pump_exit_code,
                "process_exited": self.pump_process_exited,
                "threads_seen": sorted(list(self.thread_handles.keys())) if not self.pump_process_exited else [],
            },
            "windows": self.windows,
            "gui_alive": self.gui_alive,
            "gui_obs": getattr(self, "gui_obs", []),
            "freeze_symptoms": self.freeze_symptoms,
            "attach_changed_behavior": self.attach_changed_behavior,
            "events": self.events,
            "rip_log": self.rip_log,
            "final": fin,
            "result": result,
            "verdict": verdict,
            "duration_s": round(time.time() - t_all, 2),
        }
        return out

    def _analyze_stable_rip(self):
        """真实采样值分析: 最近 20 采样的稳定位置 (新阻塞证据)。排除进程退出后 (owner=None) 采样。"""
        live = [r for r in self.rip_log if r.get("rip") and r.get("owner")]
        recent = live[-20:]
        if not recent:
            return None
        locs = {}
        for r in recent:
            key = (r.get("rip"), r.get("owner"))
            locs[key] = locs.get(key, 0) + 1
        top = max(locs.items(), key=lambda kv: kv[1])
        total = len(recent)
        return {"mode_rip": top[0][0], "mode_owner": top[0][1], "count": top[1],
                "of_last_n": total,
                "stable": top[1] >= total * 0.7 and total >= 10,
                "in_message_loop": top[0][1] in ("win32u.dll", "user32.dll") if top[0][1] else False}

    def _classify(self, non_boot_exceptions, urlmon_hits, stable_rip, fin, out_result):
        """三态判定 (语义与 T017/T018 票面逐字一致; 证据源 = 调试端口)。
        T017 票面语义:
          FULL: RIP 采样落入 urlmon.dll 模块区间 + 进程存活;
          新阻塞: RIP 稳定卡在新位置 (真实采样值) → verdict 仍 PARTIAL, 证据上报 → STOP;
          AV: EXCEPTION 调试事件 (地址/码) 或进程异常退出 → 证据上报 → STOP。
        AV > 新阻塞 > FULL 顺序判定 (AV 证据优先); 0xc000008e 引导期良性浮点不计 AV。
        attach_changed_behavior 作为语境附注, 不压过 AV。
        FULL 语义边界 (T019 票面): 宿主+候选组合的路径级结论 (Run→urlmon 明文可达), 非完全行为等价。"""
        av_list = non_boot_exceptions
        if av_list:
            return "AV_EVIDENCE (EXCEPTION 调试事件非引导断点: %s%s)" % (
                [{"code": e.get("code"), "addr": hex(e.get("address")) if e.get("address") else None,
                  "threadRip": e.get("thread_rip")} for e in av_list[:8]],
                " + attach_changed_behavior" if self.attach_changed_behavior else "")
        if self.pump_process_exited:
            code = self.pump_exit_code
            if code:
                return "AV_EVIDENCE (进程异常退出 exit_code=%r)" % code
            return "PROCESS_EXITED (exit_code=0, 进程已退出非存活) — 无法判 FULL, 上报"
        if self.attach_changed_behavior:
            return "ATTACH_CHANGED_BEHAVIOR (GUI 层未出现, 无 AV/退出 — 如实上报, 三态不硬凑)"
        if urlmon_hits and fin.get("still_active"):
            return "FULL (RIP 采样落入 urlmon/wininet 模块区间 + 进程存活)"
        if stable_rip and stable_rip.get("stable") and not stable_rip.get("in_message_loop"):
            return "NEW_BLOCK (RIP 稳定卡于 %s %s, 真实采样值)" % (
                stable_rip.get("mode_owner"), stable_rip.get("mode_rip"))
        return "UNDETERMINED (GUI 存活但无 urlmon 命中/无异常/无稳定新卡点; 见证据)"

    # ================= 收尾 =================
    def _cleanup_pump(self, wait_s=8):
        """停止泵线程 + 关闭泵事件落盘 fd (所有退出路径调用)。"""
        self.pump_stop.set()
        if self.pump_thread and self.pump_thread.is_alive():
            self.pump_thread.join(timeout=wait_s)
        if self._pump_event_fd:
            try:
                self._pump_event_fd.close()
            except Exception:
                pass
            self._pump_event_fd = None

    def _cleanup_handles(self):
        to_close = []
        with self.pump_lock:
            if self.run_hthread:
                to_close.append(("run_hthread", self.run_hthread))
                self.run_hthread = None
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
        if self.hthread:
            try:
                self.k32.CloseHandle(wt.HANDLE(self.hthread))
            except Exception:
                pass
            self.hthread = None


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "t05"
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(DEPLOY, "t05_run_ui_dbg_pcell_evidence.json")
    dry = "--dry" in sys.argv
    terminate = "--no-terminate" not in sys.argv
    h = runtime()
    out = h.run(prefix, dry=dry, terminate_at_end=terminate)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    # 调试泵日志单独落盘 (泵全量事件)
    pump_log_path = out_path.replace(".json", "_pump.json")
    with open(pump_log_path, "w", encoding="utf-8") as f:
        json.dump({"schema": "xx21b_t05_dbg_pump_log_pcell/v1", "date_utc": now_utc(),
                   "pump_health": out.get("dbg_port", {}).get("pump_health"),
                   "dbg_events": out.get("dbg_port", {}).get("dbg_events"),
                   "exceptions": out.get("dbg_port", {}).get("exceptions")}, f, indent=1, ensure_ascii=False)
    if dry:
        print("=== DRY CHECK ===")
        print(json.dumps({k: out.get(k) for k in ("dry", "deploy_check", "modules_count", "urlmon_loaded", "wininet_loaded", "windows", "pump", "export_resolve", "base_agreement")}, indent=1, ensure_ascii=False))
    else:
        print("=== SUMMARY ===")
        print(json.dumps({k: out.get(k) for k in ("result", "deploy_check", "final", "verdict", "freeze_symptoms", "attach_changed_behavior")}, indent=1, ensure_ascii=False))
    print("written:", out_path)
    print("written pump log:", pump_log_path)


if __name__ == "__main__":
    main()
