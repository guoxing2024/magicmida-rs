#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI-B T0.5: Run UI 事件驱动补测 (宿主 UI 事件触发 URLDownloadToFileA 实调用)
基线: Step1 Run 阻塞于 GUI 消息循环 (NtUserMessageCall), RIP 未入 urlmon.dll → PARTIAL
本单: 部署完美候选 + 触发 Run + 驱动宿主 UI 事件 (SendMessage/PostMessage/BM_CLICK/鼠标/计时器)
      → 观察 RIP 是否落入 urlmon.dll (URLDownloadToFileA 调用点) → FULL / 新阻塞记录
红线: NO_BYPASS=1; 候选 sha256 预核实; 网络 deny_all (防火墙 BLOCK); 不真联网; 不改样品
"""
import ctypes, ctypes.wintypes as wt
import json, os, sys, time, subprocess, hashlib, datetime, threading

# ---------------- 常量 ----------------
DEPLOY = r"D:\Claude project\magicmida-rs\lab\xx21b_run_ui"
HOST = os.path.join(DEPLOY, "rev2_unpacked.exe")
CORE = os.path.join(DEPLOY, "core.dll")
CAND_SHA = "3650ea6c0a88c731d4b613eaa533ab1d48258ce782843a5661ca6c683fd9b64e"
HOST_SHA = "36043cb4e82a500dbf94472d6219b0beac35823cebcd2d28fbdbaa4ab796c79b"
BASE = 0x7FFE1DA10000        # core.dll 固定基址
RUN_RVA = 0x1C120
RUN_VA = BASE + RUN_RVA
URLMON_SLOT_RVA = 0x16F300
URLMON_SLOT_VA = BASE + URLMON_SLOT_RVA
HOST_EXE_BASE = 0x140000000  # 宿主 EXE 基址 (Step1 基线 0x2bbb0 校验通过)
RUN_PARAM = HOST_EXE_BASE

# 权限
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040
THREAD_SUSPEND_RESUME = 0x0002

def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()

def now_utc():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

class Harness:
    def __init__(self):
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self.proc = None
        self.pid = None
        self.hproc = None
        self.hthread = None
        self.tid = None
        self.modules = []          # [(base, size, name)]
        self.rip_log = []          # [{t, rip, owner, rsp}]
        self.events = []           # [{t, kind, detail}]
        self.windows = []          # Run 窗口发现
        self.sampling = False
        self.sample_lock = threading.Lock()
        self.iat_pre = None
        self.iat_post = None

    # ---------- 基础 API ----------
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

    def read_cstr(self, addr, maxlen=256):
        b = self.rpm(addr, maxlen)
        if not b: return None
        i = b.find(b"\x00")
        return b[:i].decode("latin1") if i >= 0 else b.decode("latin1")

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

    def sample_rip(self):
        """单次采样 Run 线程 RIP"""
        ht = self.k32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, self.tid)
        if not ht: return None
        try:
            ctx = self._new_ctx()
            if not self.k32.GetThreadContext(ht, ctypes.byref(ctx)):
                return None
            rip = ctx.Rip
            return {
                "rip": hex(rip),
                "owner": self.owner(rip),
                "rsp": hex(ctx.Rsp),
                "rax": hex(ctx.Rax),
            }
        finally:
            self.k32.CloseHandle(ht)

    def _new_ctx(self):
        class C(ctypes.Structure):
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
        c = C()
        c.ContextFlags = 0x100000  # CONTEXT_CONTROL | CONTEXT_INTEGER
        return c

    def sampler_loop(self, interval=0.06, duration=0):
        t0 = time.time()
        seq = 0
        while self.sampling:
            s = self.sample_rip()
            if s:
                with self.sample_lock:
                    self.rip_log.append({"t": round(time.time() - t0, 3), "seq": seq, **s})
                seq += 1
            time.sleep(interval)

    # ---------- 窗口 ----------
    def find_windows(self):
        WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
        user32 = self.user32
        found = []

        @WNDENUMPROC
        def _cb(hwnd, lp):
            p = wt.DWORD(0)
            wtid = int(user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p)))
            if int(p.value) != self.pid:
                return True
            cn = ctypes.create_unicode_buffer(256)
            user32.GetClassNameW(hwnd, cn, 256)
            tt = ctypes.create_unicode_buffer(512)
            user32.GetWindowTextW(hwnd, tt, 512)
            entry = {
                "hwnd": int(hwnd),
                "class": cn.value,
                "title": tt.value,
                "pid": int(p.value),
                "tid": wtid,
                "thread": wtid,
            }
            found.append(entry)
            return True

        user32.EnumWindows(_cb, 0)
        return found

    def _win_thread(self, hwnd):
        p = wt.DWORD(0)
        # GetWindowThreadProcessId 返回值 = 创建窗口的线程 TID (修复: 原实现误存 PID)
        tid = int(self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p)))
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

    # ---------- 事件驱动 ----------
    def wait_core_loaded(self, timeout=40):
        """轮询等待 core.dll 固定基址就绪 (MZ at BASE) — 部署核实前置"""
        t0 = time.time()
        while time.time() - t0 < timeout:
            self.enum_modules()
            h = self.rpm(BASE, 0x1000)
            if h and h[:2] == b"MZ":
                core_mod = [{"base": hex(b), "size": hex(s), "name": n} for b, s, n in self.modules if n.lower() == "core.dll"]
                return {"loaded": True, "wait_s": round(time.time() - t0, 2), "core_module": core_mod}
            time.sleep(0.5)
        return {"loaded": False, "wait_s": round(time.time() - t0, 2), "core_module": None}

    def post_thread(self, tid, msg, w=0, l=0):
        return bool(self.user32.PostThreadMessageW(wt.DWORD(tid), msg, w, l))

    def drive_thread_queue(self, tid):
        """PostThreadMessage 驱动 Run 线程消息队列 (GetMessage(NULL) 线程循环)"""
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
            if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", f"PostThreadMessage WM_TIMER id={tid_} -> RIP {s}")
                return True
        for lp in (0x203, 0x205, 0):
            self.post_thread(tid, W_USER1, 0, lp); time.sleep(0.15)
        for wp in (0, 1, 2):
            self.post_thread(tid, W_312, wp, 0); time.sleep(0.15)
        for vk in (VK_RETURN, VK_SPACE, VK_TAB):
            self.post_thread(tid, WM_COMMAND, MAKEWPARAM(vk, 0), 0); time.sleep(0.15)
        s = self.sample_rip()
        if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
            self.log_event("urlmon_hit", f"thread queue -> RIP {s}")
            return True
        return False

    def send(self, hwnd, msg, w=0, l=0):
        return self.user32.SendMessageW(wt.HWND(hwnd), msg, w, l)

    def post(self, hwnd, msg, w=0, l=0):
        return self.user32.PostMessageW(wt.HWND(hwnd), msg, w, l)

    def log_event(self, kind, detail):
        self.events.append({"t": round(time.time() - self.t0, 3), "kind": kind, "detail": detail})
        print(f"[{time.time()-self.t0:7.3f}] {kind}: {detail}")

    def drive_battery(self, hwnd, children):
        """UI 事件电池: 分阶段驱动, 每阶段后采样观察"""
        WM_NULL, WM_PAINT, WM_CLOSE, WM_COMMAND = 0x0, 0xF, 0x10, 0x111
        WM_TIMER, WM_DRAWITEM, WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x113, 0x2B, 0x100, 0x101, 0x102
        WM_LBUTTONDOWN, WM_LBUTTONUP, WM_LBUTTONDBLCLK = 0x201, 0x202, 0x203
        WM_RBUTTONDOWN, WM_RBUTTONUP, WM_RBUTTONDBLCLK = 0x204, 0x205, 0x206
        WM_MOUSEMOVE, BM_CLICK = 0x200, 0xF5
        W_USER1 = 0x401
        W_312 = 0x312
        MK_LBUTTON = 0x0001
        VK_RETURN, VK_TAB, VK_SPACE = 0x0D, 0x09, 0x20

        def MAKEWPARAM(lo, hi): return (hi << 16) | lo
        def MAKELPARAM(x, y): return (y << 16) | (x & 0xFFFF)

        # ---- 阶段 0: 基本泵 + 计时器 + 自定义消息 ----
        self.log_event("phase", "0: 基本泵 (WM_NULL/WM_PAINT/WM_TIMER/WM_USER/键盘/激活)")
        for _ in range(3):
            self.post(hwnd, WM_NULL)
            time.sleep(0.05)
        self.post(hwnd, WM_PAINT); time.sleep(0.15)
        for msg in (0x1C, 0x6, 0x7, 0x18):  # WM_ACTIVATEAPP / WM_ACTIVATE / WM_SETFOCUS / WM_SHOWWINDOW
            self.post(hwnd, msg); time.sleep(0.1)
        for tid_ in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x65, 0x100, 0x3e8, 0x3e9, 0x3ea, 0x3eb, 0x3ec, 0x3ed):
            self.post(hwnd, WM_TIMER, tid_, 0); time.sleep(0.08)
            s = self.sample_rip()
            if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", f"WM_TIMER id={tid_} -> RIP {s}")
                return True
        for lp in (0x203, 0x205, 0):
            self.send(hwnd, W_USER1, 0, lp); time.sleep(0.15)
        for wp in (0, 1, 2):
            self.send(hwnd, W_312, wp, 0); time.sleep(0.15)
        for vk in (VK_RETURN, VK_TAB, VK_SPACE):
            self.send(hwnd, WM_KEYDOWN, vk, 0); time.sleep(0.1)
            self.send(hwnd, WM_KEYUP, vk, 0); time.sleep(0.1)

        # ---- 阶段 1: 子控件 (Button BM_CLICK + WM_COMMAND) ----
        btns = [c for c in children if c["class"] == "Button"]
        self.log_event("phase", f"1: 控件交互 ({len(btns)} Button / {len(children)} child)")
        for c in children:
            self.log_event("child", f"hwnd={c['hwnd']:#x} class={c['class']} id={c['ctrl_id']} title={c['title'][:40]!r}")
        for c in children:
            hid = c["ctrl_id"]
            # BM_CLICK 直接发按钮
            self.post(c["hwnd"], BM_CLICK); time.sleep(0.2)
            self.send(c["hwnd"], BM_CLICK); time.sleep(0.2)
            # WM_COMMAND 发父窗口 (标准通知路径)
            self.send(hwnd, WM_COMMAND, MAKEWPARAM(hid, 0), c["hwnd"]); time.sleep(0.25)
            s = self.sample_rip()
            if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", f"WM_COMMAND id={hid} -> RIP {s}")
                return True

        # ---- 阶段 2: 鼠标 (子控件中心点击 → 父窗口) ----
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
            if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", f"mouse child {c['hwnd']:#x} -> RIP {s}")
                return True
        # 窗口客户区中心
        r = wt.RECT()
        self.user32.GetClientRect(wt.HWND(hwnd), ctypes.byref(r))
        cx, cy = r.right // 2, r.bottom // 2
        for msg in (WM_LBUTTONDOWN, WM_LBUTTONUP, WM_LBUTTONDBLCLK, WM_RBUTTONDOWN, WM_RBUTTONUP):
            self.send(hwnd, msg, MK_LBUTTON if msg in (WM_LBUTTONDOWN, WM_LBUTTONDBLCLK) else 0, MAKELPARAM(cx, cy))
            time.sleep(0.15)
        s = self.sample_rip()
        if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
            self.log_event("urlmon_hit", f"mouse client -> RIP {s}")
            return True

        # ---- 阶段 3: 计时器轮询风暴 + 自定义消息组合 ----
        self.log_event("phase", "3: 计时器轮询 + 自定义组合")
        for tid_ in list(range(1, 25)) + [0x3e8, 0x3e9, 0x3ea, 0x3eb, 0x3ec, 0x3ed]:
            self.post(hwnd, WM_TIMER, tid_, 0)
            if tid_ % 4 == 0:
                time.sleep(0.2)
                s = self.sample_rip()
                if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", f"timer storm id={tid_} -> RIP {s}")
                    return True
        # WM_COMMAND 高位通知码组合
        for hid in (0x3ec, 0x3ed, 0x3e4, 0x3e5, 0x14e, 0x154, 2, 3, 7, 9, 1, 0x65, 0x30, 0x33, 0x34, 0x36, 0x3e6, 0x3e7, 0x3e8):
            for hi in (0, 1, 2):
                self.send(hwnd, WM_COMMAND, MAKEWPARAM(hid, hi), 0)
                time.sleep(0.12)
                s = self.sample_rip()
                if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", f"WM_COMMAND id={hid} hi={hi} -> RIP {s}")
                    return True

        # ---- 阶段 4: 关闭 ----
        self.log_event("phase", "4: WM_CLOSE (预期 PostQuitMessage 退出路径)")
        self.post(hwnd, WM_CLOSE)
        time.sleep(1.0)
        return False

    def finish(self):
        # 终态: 线程退出码 / IAT / 页级
        code = wt.DWORD(0)
        self.k32.GetExitCodeThread(self.hthread, ctypes.byref(code))
        self.iat_post = self.read_qword(URLMON_SLOT_VA)
        alive = self.k32.WaitForSingleObject(self.hthread, 0) == 0x102  # STILL_ACTIVE
        return {"exit_code": hex(code.value), "still_active": alive,
                "iat_pre": hex(self.iat_pre) if self.iat_pre else None,
                "iat_post": hex(self.iat_post) if self.iat_post else None,
                "iat_unchanged": self.iat_pre == self.iat_post}

    def run(self, out_prefix="t05", dry=False, attach_pid=None, terminate_at_end=True):
        t_all = time.time()
        # 0) 红线核实
        if sha256_file(CORE) != CAND_SHA:
            return {"redline": "FAIL_CORE_SHA", "sha": sha256_file(CORE)}
        if sha256_file(HOST) != HOST_SHA:
            return {"redline": "FAIL_HOST_SHA", "sha": sha256_file(HOST)}
        print("redline sha OK (core=perfect candidate, host=rev2_unpacked)")

        # 1) 启动宿主 (或 attach 已有 cdb 宿主)
        if attach_pid:
            self.pid = attach_pid
            self.t0 = time.time()
            self.log_event("host_attach", f"pid={self.pid} (cdb-launched)")
        else:
            env = dict(os.environ)
            env["NO_BYPASS"] = "1"
            env["MIDA_GTO_NO_BYPASS"] = "1"
            self.proc = subprocess.Popen([HOST], cwd=DEPLOY, env=env,
                                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.pid = self.proc.pid
            self.t0 = time.time()
            self.log_event("host_start", f"pid={self.pid} NO_BYPASS=1")

        if not self.open_proc():
            return {"redline": "FAIL_OPENPROC", "err": ctypes.get_last_error(), "pid": self.pid}

        # 1.5) 轮询等待 core.dll 固定基址就绪
        wcl = self.wait_core_loaded(timeout=40)
        self.log_event("core_load_wait", json.dumps(wcl))
        if not wcl["loaded"]:
            return {"redline": "FAIL_CORE_NOT_LOADED", "wait": wcl}

        # 2) 基址核实
        core_head = self.rpm(BASE, 0x1000)
        core_ok = core_head and core_head[:2] == b"MZ"
        host_head = self.rpm(HOST_EXE_BASE, 0x1000)
        host_ok = host_head and host_head[:2] == b"MZ"
        run_bytes = self.rpm(RUN_VA, 16)
        iat_val = self.read_qword(URLMON_SLOT_VA)
        self.iat_pre = iat_val
        deploy_check = {
            "core_fixed_base": hex(BASE), "core_mz": core_ok,
            "host_exe_base": hex(HOST_EXE_BASE), "host_mz": host_ok,
            "run_rva": hex(RUN_RVA), "run_va": hex(RUN_VA),
            "run_head": run_bytes.hex() if run_bytes else None,
            "run_head_plaintext": run_bytes[:6] == bytes.fromhex("415741564155") if run_bytes else False,
            "urlmon_iat_slot": hex(URLMON_SLOT_VA),
            "urlmon_iat_value": hex(iat_val) if iat_val else None,
        }
        self.log_event("deploy_check", json.dumps(deploy_check))
        if not (core_ok and host_ok):
            return {"redline": "FAIL_FIXED_BASE", "deploy_check": deploy_check}

        if dry:
            # 预检: 只读观察 (窗口/模块), 不触发 Run
            all_wnds = self.find_windows()
            mods = [{"base": hex(b), "size": hex(s), "name": n} for b, s, n in self.modules]
            urlmon_mod = [m for m in self.modules if "urlmon" in m[2].lower()]
            wininet_mod = [m for m in self.modules if "wininet" in m[2].lower()]
            print("modules:", len(self.modules), "urlmon:", urlmon_mod, "wininet:", wininet_mod)
            print("windows:", json.dumps(all_wnds, ensure_ascii=False)[:2000])
            if self.proc:
                self.proc.terminate()
                time.sleep(1)
            return {"dry": True, "deploy_check": deploy_check, "modules_count": len(self.modules),
                    "urlmon_loaded": bool(urlmon_mod), "wininet_loaded": bool(wininet_mod),
                    "windows": all_wnds}

        # 3) 触发 Run
        tid = wt.DWORD(0)
        self.hthread = self.k32.CreateRemoteThread(
            self.hproc, None, 0, ctypes.c_void_p(RUN_VA), ctypes.c_void_p(RUN_PARAM), 0, ctypes.byref(tid))
        if not self.hthread:
            return {"redline": "FAIL_CREATEREMOTETHREAD", "err": ctypes.get_last_error()}
        self.tid = tid.value
        self.log_event("run_trigger", f"CreateRemoteThread Run@{hex(RUN_VA)} param={hex(RUN_PARAM)} tid={self.tid}")

        # 4) RIP 采样线程 (0.03s 高密)
        self.sampling = True
        sampler = threading.Thread(target=self.sampler_loop, args=(0.03,), daemon=True)
        sampler.start()

        # 5) 等待 Run 到达消息循环 (win32u/NtUserMessageCall 或 ntdll 等待)
        loop_reached = False
        deadline = time.time() + 20
        while time.time() < deadline:
            s = self.sample_rip()
            if s and (s["owner"] in ("win32u.dll", "user32.dll") or "win32u" in s["owner"]):
                loop_reached = True
                self.log_event("msg_loop", f"RIP={s['rip']} owner={s['owner']}")
                break
            time.sleep(0.1)
        if not loop_reached:
            time.sleep(2)
            s = self.sample_rip()
            self.log_event("msg_loop_not_confirmed", f"RIP={s}")

        # 6) 窗口发现 (含 Run 线程窗口 tid 修正)
        all_host_wnds = self.find_windows()
        run_wnds = [w for w in all_host_wnds if w["tid"] == self.tid]
        self.windows = all_host_wnds
        self.log_event("windows", f"host windows={len(all_host_wnds)} run_thread_windows={len(run_wnds)} tid={self.tid}")

        # 6.5) 线程队列驱动 (PostThreadMessage -> Run 线程 GetMessage 循环)
        result = {"hit_urlmon": False, "hit_wininet": False}
        hit = self.drive_thread_queue(self.tid)
        if hit:
            result["hit_urlmon"] = True

        # 7) UI 事件驱动 (窗口消息)
        if not result["hit_urlmon"]:
            targets = run_wnds if run_wnds else all_host_wnds[:3]
            self.log_event("window_targets", f"driving {len(targets)} windows")
            for w in targets:
                hwnd = w["hwnd"]
                children = self.enum_children(hwnd)
                self.log_event("window_target", f"hwnd={hwnd:#x} class={w['class']} title={w['title'][:60]!r} children={len(children)}")
                hit = self.drive_battery(hwnd, children)
                if hit:
                    result["hit_urlmon"] = True
                    break

        # 7.5) 延后沉降采样 (延迟计时器/异步触发捕获)
        if not result["hit_urlmon"]:
            self.log_event("phase", "S: 延后沉降采样 5s (异步/延迟触发)")
            settle_deadline = time.time() + 5
            while time.time() < settle_deadline:
                s = self.sample_rip()
                if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", f"settle -> RIP {s}")
                    result["hit_urlmon"] = True
                    break
                time.sleep(0.05)

        time.sleep(1.5)
        self.sampling = False
        sampler.join(timeout=3)

        # 8) 终态
        fin = self.finish()
        self.log_event("final", json.dumps(fin))

        # 9) urlmon 命中分析
        urlmon_hits = [r for r in self.rip_log if r["owner"] in ("urlmon.dll", "wininet.dll")]
        result["urlmon_hits"] = urlmon_hits[:20]
        result["urlmon_hit_count"] = len(urlmon_hits)
        if urlmon_hits:
            first = urlmon_hits[0]
            result["urlmon_first_enter_t"] = first["t"]
            result["hit_urlmon"] = True

        # 10) 退出
        if terminate_at_end:
            try:
                if self.proc:
                    self.proc.terminate()
            except Exception:
                pass
            time.sleep(1)

        out = {
            "schema": "xx21b_t05_run_ui_verdict/v1",
            "case": "xiongxiong_core",
            "work_order": "XC-XXI-B",
            "task": "T0.5 Run UI 事件驱动补测",
            "date_utc": now_utc(),
            "redline": {
                "no_bypass": "1",
                "candidate_sha256": CAND_SHA,
                "host_sha256": HOST_SHA,
                "samples_not_modified": True,
                "network_deny_all": "BLOCK_XX21B_RUNUI_HOST + BLOCK_XX21B_REV2_HOST (outbound block)",
            },
            "deploy_check": deploy_check,
            "run_trigger": {"method": "CreateRemoteThread", "va": hex(RUN_VA), "param": hex(RUN_PARAM), "tid": self.tid},
            "windows": self.windows,
            "events": self.events,
            "rip_log": self.rip_log,
            "final": fin,
            "result": result,
            "duration_s": round(time.time() - t_all, 2),
        }
        return out


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else "t05"
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(DEPLOY, "t05_run_ui_evidence.json")
    dry = "--dry" in sys.argv
    attach_pid = None
    terminate = "--no-terminate" not in sys.argv
    for a in sys.argv:
        if a.startswith("--attach="):
            attach_pid = int(a.split("=", 1)[1])
    h = Harness()
    out = h.run(prefix, dry=dry, attach_pid=attach_pid, terminate_at_end=terminate)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
    if dry:
        print("=== DRY CHECK ===")
        print(json.dumps({k: out.get(k) for k in ("dry", "deploy_check", "modules_count", "urlmon_loaded", "wininet_loaded", "windows")}, indent=1, ensure_ascii=False))
    else:
        print("=== SUMMARY ===")
        print(json.dumps({k: out.get(k) for k in ("result", "deploy_check", "final")}, indent=1, ensure_ascii=False))
    print("written:", out_path)


if __name__ == "__main__":
    main()
