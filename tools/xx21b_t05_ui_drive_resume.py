#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI-B T0.5 续跑: Run UI 事件驱动补测 (重脱壳产物, 当前会话)
基线: T0.5 首跑 BLOCKED_ENV (旧 rev2 宿主 ASLR 会话绑定, 启动即 AV)
本单: 新 rev2 宿主 (daa6c7f3) + 新固化候选 core.dll (d1b7ec67) + config.ini
  容器: host_loader.exe (LoadLibraryW 候选, 固定基址 0x7ff9d5b90000) — 新 rev2 宿主
        启动受沙箱 TSBX IPC 干扰未达 Loader 链 (已记录), Run 补测在 host_loader
        容器内触发 (Step2/Step3 同款候选加载机制)
流程: 触发 Run@base+0x1C120 (CreateRemoteThread, param=容器 EXE 基址)
      → 采样 RIP (0.03s) → UI 事件驱动 (PostThreadMessage 线程队列 + 窗口电池)
      → 观察 RIP 是否落入 urlmon.dll (URLDownloadToFileA 调用点) → FULL / 新阻塞
红线: NO_BYPASS=1; 候选/宿主 sha256 预核实; 网络 deny_all (BLOCK 规则); 不真联网; 不改样品
"""
import ctypes, ctypes.wintypes as wt
import json, os, sys, time, subprocess, hashlib, datetime, threading

# ---------------- 常量 ----------------
DEPLOY = r"D:\Claude project\magmida-rs\lab\xx21b_resume\run_ui"
HOST_LOADER = r"D:\Claude project\magicmida-rs\target\release\host_loader.exe"
CORE = os.path.join(DEPLOY, "core.dll")
HOST = os.path.join(DEPLOY, "rev2_unpacked.exe")
CAND_SHA = "d1b7ec6745ca200081a3729f29b04defa357348b7e1cb08fa58f1b45b1a09f63"
HOST_SHA = "daa6c7f329a1f0be7a52bf1edd8a471e96736a07162923ba8589fc1519be4de7"
BASE = 0x7FF9D5B90000        # solid 候选固定基址
RUN_RVA = 0x1C120
RUN_VA = BASE + RUN_RVA
URLMON_SLOT_RVA = None       # import dir 为空; 用模块归属检测 urlmon 命中
HOST_EXE_BASE = 0x140000000  # 新 rev2 宿主固定基址 (部署核实用)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
THREAD_GET_CONTEXT = 0x0008
THREAD_QUERY_INFORMATION = 0x0040

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
        self.modules = []
        self.rip_log = []
        self.events = []
        self.windows = []
        self.sampling = False
        self.sample_lock = threading.Lock()
        self.t0 = 0
        self.container_base = None

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
            name_buf = ctypes.create_unicode_buffer(520)
            self.psapi.GetModuleFileNameExW(self.hproc, ctypes.c_void_p(hmod), name_buf, 520)
            mi = self.MODULEINFO()
            ok = self.psapi.GetModuleInformation(self.hproc, ctypes.c_void_p(hmod), ctypes.byref(mi), ctypes.sizeof(mi))
            base = mi.lpBaseOfDll if ok else hmod
            size = mi.SizeOfImage if ok else 0
            self.modules.append((base, size, os.path.basename(name_buf.value)))
        self.modules.sort(key=lambda m: m[0])

    def owner(self, rip):
        for base, size, name in self.modules:
            if base <= rip < base + size:
                return name
        return "unknown"

    def sample_rip(self):
        ht = self.k32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, self.tid)
        if not ht:
            return None
        try:
            ctx = self._new_ctx()
            if not self.k32.GetThreadContext(ht, ctypes.byref(ctx)):
                return None
            return {"rip": hex(ctx.Rip), "owner": self.owner(ctx.Rip),
                    "rsp": hex(ctx.Rsp), "rax": hex(ctx.Rax)}
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
        c.ContextFlags = 0x100000
        return c

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
                          "pid": int(p.value), "tid": wtid})
            return True

        self.user32.EnumWindows(_cb, 0)
        return found

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
            out.append({"hwnd": int(hwnd), "class": cn.value, "title": tt.value, "ctrl_id": int(cid)})
            return True

        self.user32.EnumChildWindows(wt.HWND(parent), _cb, 0)
        return out

    def wait_core_loaded(self, timeout=40):
        t0 = time.time()
        while time.time() - t0 < timeout:
            self.enum_modules()
            h = self.rpm(BASE, 0x1000)
            if h and h[:2] == b"MZ":
                return {"loaded": True, "wait_s": round(time.time() - t0, 2)}
            time.sleep(0.5)
        return {"loaded": False, "wait_s": round(time.time() - t0, 2)}

    def log_event(self, kind, detail):
        self.events.append({"t": round(time.time() - self.t0, 3), "kind": kind, "detail": detail})
        print(f"[{time.time()-self.t0:7.3f}] {kind}: {detail}")

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
            if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", f"PostThreadMessage WM_TIMER id={tid_} -> RIP {s}")
                return True
        for lp in (0x203, 0x205, 0):
            self.post_thread(tid, W_USER1, 0, lp); time.sleep(0.15)
        for wp in (0, 1, 2):
            self.post_thread(tid, W_312, wp, 0); time.sleep(0.15)
        for vk in (VK_RETURN, VK_SPACE, VK_TAB):
            self.post_thread(tid, WM_COMMAND, MAKEWPARAM(vk, 0), 0); time.sleep(0.15)
        return False

    def send(self, hwnd, msg, w=0, l=0):
        return self.user32.SendMessageW(wt.HWND(hwnd), msg, w, l)

    def post(self, hwnd, msg, w=0, l=0):
        return self.user32.PostMessageW(wt.HWND(hwnd), msg, w, l)

    def drive_battery(self, hwnd, children):
        WM_NULL, WM_PAINT, WM_CLOSE, WM_COMMAND = 0x0, 0xF, 0x10, 0x111
        WM_TIMER, WM_DRAWITEM, WM_KEYDOWN, WM_KEYUP, WM_CHAR = 0x113, 0x2B, 0x100, 0x101, 0x102
        WM_LBUTTONDOWN, WM_LBUTTONUP, WM_LBUTTONDBLCLK = 0x201, 0x202, 0x203
        WM_RBUTTONDOWN, WM_RBUTTONUP = 0x204, 0x205
        WM_MOUSEMOVE, BM_CLICK = 0x200, 0xF5
        W_USER1 = 0x401
        W_312 = 0x312
        MK_LBUTTON = 0x0001
        VK_RETURN, VK_TAB, VK_SPACE = 0x0D, 0x09, 0x20

        def MAKEWPARAM(lo, hi): return (hi << 16) | lo
        def MAKELPARAM(x, y): return (y << 16) | (x & 0xFFFF)

        self.log_event("phase", "0: 基本泵 (WM_NULL/WM_PAINT/WM_TIMER/WM_USER/键盘/激活)")
        for _ in range(3):
            self.post(hwnd, WM_NULL); time.sleep(0.05)
        self.post(hwnd, WM_PAINT); time.sleep(0.15)
        for msg in (0x1C, 0x6, 0x7, 0x18):
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

        self.log_event("phase", f"1: 控件交互 ({len(children)} child)")
        for c in children:
            hid = c["ctrl_id"]
            self.post(c["hwnd"], BM_CLICK); time.sleep(0.2)
            self.send(c["hwnd"], BM_CLICK); time.sleep(0.2)
            self.send(hwnd, WM_COMMAND, MAKEWPARAM(hid, 0), c["hwnd"]); time.sleep(0.25)
            s = self.sample_rip()
            if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                self.log_event("urlmon_hit", f"WM_COMMAND id={hid} -> RIP {s}")
                return True

        self.log_event("phase", "2: 鼠标事件")
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

        self.log_event("phase", "3: 计时器风暴 + WM_COMMAND 组合")
        for tid_ in list(range(1, 25)) + [0x3e8, 0x3e9, 0x3ea, 0x3eb, 0x3ec, 0x3ed]:
            self.post(hwnd, WM_TIMER, tid_, 0)
            if tid_ % 4 == 0:
                time.sleep(0.2)
                s = self.sample_rip()
                if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", f"timer storm id={tid_} -> RIP {s}")
                    return True
        for hid in (0x3ec, 0x3ed, 0x3e4, 0x3e5, 0x14e, 0x154, 2, 3, 7, 9, 1, 0x65, 0x30, 0x33, 0x34, 0x36, 0x3e6, 0x3e7, 0x3e8):
            for hi in (0, 1, 2):
                self.send(hwnd, WM_COMMAND, MAKEWPARAM(hid, hi), 0)
                time.sleep(0.12)
                s = self.sample_rip()
                if s and s["owner"] in ("urlmon.dll", "wininet.dll"):
                    self.log_event("urlmon_hit", f"WM_COMMAND id={hid} hi={hi} -> RIP {s}")
                    return True
        return False

    def finish(self):
        code = wt.DWORD(0)
        self.k32.GetExitCodeThread(self.hthread, ctypes.byref(code))
        alive = self.k32.WaitForSingleObject(self.hthread, 0) == 0x102
        return {"exit_code": hex(code.value), "still_active": alive}

    def run(self, out_path, dry=False):
        t_all = time.time()
        # 0) 红线核实
        if sha256_file(CORE) != CAND_SHA:
            return {"redline": "FAIL_CORE_SHA", "sha": sha256_file(CORE)}
        if sha256_file(HOST) != HOST_SHA:
            return {"redline": "FAIL_HOST_SHA", "sha": sha256_file(HOST)}
        print("redline sha OK (core=solid candidate, host=new rev2_unpacked)")

        # 1) 启动容器: host_loader LoadLibraryW(候选 core.dll)
        env = dict(os.environ)
        env["NO_BYPASS"] = "1"
        env["MIDA_GTO_NO_BYPASS"] = "1"
        self.proc = subprocess.Popen([HOST_LOADER, CORE], cwd=DEPLOY, env=env,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.pid = self.proc.pid
        self.t0 = time.time()
        self.log_event("container_start", f"host_loader pid={self.pid} LoadLibraryW(core.dll) NO_BYPASS=1")

        if not self.open_proc():
            return {"redline": "FAIL_OPENPROC", "err": ctypes.get_last_error(), "pid": self.pid}

        # 1.5) 等待候选固定基址就绪
        wcl = self.wait_core_loaded(timeout=60)
        self.log_event("core_load_wait", json.dumps(wcl))
        if not wcl["loaded"]:
            return {"redline": "FAIL_CORE_NOT_LOADED", "wait": wcl}

        # 1.6) 容器 EXE 基址 (Run 参数映像校验)
        self.enum_modules()
        for base, size, name in self.modules:
            if name.lower() == "host_loader.exe":
                self.container_base = base
                break
        self.log_event("container_base", hex(self.container_base) if self.container_base else "?")

        # 2) 基址核实
        core_head = self.rpm(BASE, 0x1000)
        core_ok = core_head and core_head[:2] == b"MZ"
        run_bytes = self.rpm(RUN_VA, 16)
        deploy_check = {
            "core_fixed_base": hex(BASE), "core_mz": core_ok,
            "run_rva": hex(RUN_RVA), "run_va": hex(RUN_VA),
            "run_head": run_bytes.hex() if run_bytes else None,
            "run_head_plaintext": run_bytes[:6] == bytes.fromhex("415741564155") if run_bytes else False,
            "container_base": hex(self.container_base) if self.container_base else None,
        }
        self.log_event("deploy_check", json.dumps(deploy_check))
        if not core_ok:
            return {"redline": "FAIL_FIXED_BASE", "deploy_check": deploy_check}

        if dry:
            urlmon_mod = [{"base": hex(b), "size": hex(s), "name": n} for b, s, n in self.modules if "urlmon" in n.lower()]
            wininet_mod = [{"base": hex(b), "size": hex(s), "name": n} for b, s, n in self.modules if "wininet" in n.lower()]
            all_wnds = self.find_windows()
            self.proc.terminate()
            time.sleep(1)
            return {"dry": True, "deploy_check": deploy_check,
                    "urlmon_loaded": bool(urlmon_mod), "urlmon": urlmon_mod,
                    "wininet_loaded": bool(wininet_mod), "windows": all_wnds}

        # 3) 触发 Run
        run_param = self.container_base if self.container_base else HOST_EXE_BASE
        tid = wt.DWORD(0)
        self.hthread = self.k32.CreateRemoteThread(
            self.hproc, None, 0, ctypes.c_void_p(RUN_VA), ctypes.c_void_p(run_param), 0, ctypes.byref(tid))
        if not self.hthread:
            return {"redline": "FAIL_CREATEREMOTETHREAD", "err": ctypes.get_last_error()}
        self.tid = tid.value
        self.log_event("run_trigger", f"CreateRemoteThread Run@{hex(RUN_VA)} param={hex(run_param)} tid={self.tid}")

        # 4) RIP 采样 (0.03s)
        self.sampling = True
        sampler = threading.Thread(target=self.sampler_loop, args=(0.03,), daemon=True)
        sampler.start()

        # 5) 等待 Run 达消息循环
        loop_reached = False
        deadline = time.time() + 20
        while time.time() < deadline:
            s = self.sample_rip()
            if s and s["owner"] in ("win32u.dll", "user32.dll"):
                loop_reached = True
                self.log_event("msg_loop", f"RIP={s['rip']} owner={s['owner']}")
                break
            time.sleep(0.1)
        if not loop_reached:
            s = self.sample_rip()
            self.log_event("msg_loop_not_confirmed", f"RIP={s}")

        # 6) 窗口发现 + 线程队列驱动
        self.windows = self.find_windows()
        run_wnds = [w for w in self.windows if w["tid"] == self.tid]
        self.log_event("windows", f"host windows={len(self.windows)} run_thread_windows={len(run_wnds)} tid={self.tid}")
        result = {"hit_urlmon": False, "hit_wininet": False}
        hit = self.drive_thread_queue(self.tid)
        if hit:
            result["hit_urlmon"] = True

        # 7) 窗口事件电池
        if not result["hit_urlmon"]:
            targets = run_wnds if run_wnds else self.windows[:3]
            self.log_event("window_targets", f"driving {len(targets)} windows")
            for w in targets:
                hwnd = w["hwnd"]
                children = self.enum_children(hwnd)
                self.log_event("window_target", f"hwnd={hwnd:#x} class={w['class']} title={w['title'][:60]!r} children={len(children)}")
                if self.drive_battery(hwnd, children):
                    result["hit_urlmon"] = True
                    break

        # 7.5) 延后沉降采样
        if not result["hit_urlmon"]:
            self.log_event("phase", "S: 延后沉降采样 5s")
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
            result["urlmon_first_enter_t"] = urlmon_hits[0]["t"]
            result["hit_urlmon"] = True

        # 10) 退出
        try:
            self.proc.terminate()
        except Exception:
            pass
        time.sleep(1)

        out = {
            "schema": "xx21b_t05_run_ui_resume_verdict/v1",
            "case": "xiongxiong_core",
            "work_order": "XC-XXI-B",
            "task": "T0.5 续跑 Run UI 事件驱动补测 (重脱壳产物)",
            "date_utc": now_utc(),
            "redline": {
                "no_bypass": "1",
                "candidate_sha256": CAND_SHA,
                "candidate_name": "core_perfect_candidate_new_solid.dll (EP=NOP stub 固化)",
                "host_sha256": HOST_SHA,
                "host_name": "rev2_unpacked.exe (重脱壳, T0.7 会话清洗)",
                "samples_not_modified": True,
                "network_deny_all": "BLOCK_XX21B_RESUME_* (outbound block)",
            },
            "deploy_check": deploy_check,
            "run_trigger": {"method": "CreateRemoteThread", "va": hex(RUN_VA), "param": hex(run_param), "tid": self.tid},
            "windows": self.windows,
            "events": self.events,
            "rip_log": self.rip_log,
            "final": fin,
            "result": result,
            "duration_s": round(time.time() - t_all, 2),
        }
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=1, ensure_ascii=False)
        return out


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DEPLOY, "t05_resume_ui_evidence.json")
    dry = "--dry" in sys.argv
    h = Harness()
    out = h.run(out_path, dry=dry)
    if dry:
        print("=== DRY ===")
        print(json.dumps({k: out.get(k) for k in ("dry", "deploy_check", "urlmon_loaded", "wininet_loaded", "windows")}, indent=1, ensure_ascii=False))
    else:
        print("=== SUMMARY ===")
        print(json.dumps({k: out.get(k) for k in ("result", "deploy_check", "final")}, indent=1, ensure_ascii=False))
    print("written:", out_path)


if __name__ == "__main__":
    main()
