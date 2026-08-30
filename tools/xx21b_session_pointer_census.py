#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XX-21B 会话指针普查器（TASK-022 验收门 + 审计工具，总指挥 D-043 普查的固化版）

用途：对重建 PE（候选 core.dll 类产物）做全域会话指针普查——扫描文件内所有
疑似用户态绝对指针（0x7ff0_00000000..0x7fff_ffffffff，含未对齐命中），按
[自映像 | KUSER_SHARED_DATA | 活体模块表 | 违规] 分类，产出普查地图 JSON。

历史教训（D-040/D-041/D-043，写进本工具防重蹈）：
  1. 扫描模式必须覆盖 0x7ff0-0x7fff 全域（T020 按已知死区间设计窗口 → ≥8 个
     旧模块区结构性逃逸）；本工具用 byte5==0x7f && byte4>=0xf0 的逐字节扫描，
     不依赖任何"已知范围"清单。
  2. 扫描器自身必须先过自校准（--selftest，对已知答案文件 094f5401 逐项核对
     指标），校准不过禁止出报告（总指挥审计时 0x7ffF* 模式漏 0x7ffE* 的假阴性
     教训——扫描器覆盖域必须 fail-loud 自检）。
  3. 未对齐/加密区（.winlice/.boot）命中 = 入册 residual_unpatched 不盲改
     （T020 票面纪律）；明文节 8 对齐违规 = 硬门 FAIL。

用法：
  python tools/xx21b_session_pointer_census.py --selftest --image <094f5401 文件>
  python tools/xx21b_session_pointer_census.py --image <新候选> \
      --module-map <活体模块表.json> --out <普查报告.json>

module-map JSON 格式（worker 在 dump 会话从活体宿主进程枚举生成）：
  {"pid": 1234, "boot_time": "2026-08-30 10:05:53.549",
   "modules": [{"name": "core.dll", "base": "0x7ffd35290000", "size": 14435328}, ...]}

退出码：0 = 门通过（或自校准通过）；1 = 用法/自校准失败；2 = 明文对齐违规硬门 FAIL。
仅标准库；对样品文件只读。
"""
import argparse, collections, hashlib, json, struct, sys

# 自校准目标：T020R1 清洗件（已知答案，D-041/D-043 逐项独立核实）
SELFTEST_SHA = "094f5401b9c59db5512ec510ed1b13675013c414f98f78cde7ffa1fc31996457"
# 自校准期望值（总指挥 2026-08-30 独立普查实测值，D-043 F3）
SELFTEST_EXPECT = {
    "own_image_refs": 4865,            # 全部自引用（含未对齐；BASE-LOCK 记录 4865）
    "old_ntdll_hits": 13,              # [0x7ffeeb320000,+0x300000) 残留（T020 pointer_map residual_unpatched）
    "old_ntdll_all_unaligned": True,   # 13 个全部未对齐
    "family_b14_b32_hits": 73,         # [0x7ffeeb140000, 0x7ffeeb320000) 逃逸族总命中
    "family_b14_b32_aligned": 69,      # 其中 8 对齐（连续指针表 + .bss 簇）
    "kuser_hits": 3,                   # KUSER_SHARED_DATA (0x7ffe00000000) 合法常量引用
}

KUSER_BASE, KUSER_END = 0x7FFE00000000, 0x7FFE00001000
ENCRYPTED_SECTIONS = {".winlice", ".boot"}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class PE:
    def __init__(self, data):
        self.data = data
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        magic_pe = struct.unpack_from("<I", data, e_lfanew)[0]
        if magic_pe != 0x00004550:
            raise ValueError("not a PE file")
        nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_off = e_lfanew + 24
        opt_magic = struct.unpack_from("<H", data, opt_off)[0]
        if opt_magic != 0x20B:
            raise ValueError("not PE32+ (x64)")
        self.image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        self.size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
        self.dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
        sec_off = opt_off + struct.unpack_from("<H", data, e_lfanew + 20)[0]
        self.sections = []  # (name, vaddr, vsize, rawptr, rawsize)
        for i in range(nsec):
            base = sec_off + i * 40
            name = data[base:base + 8].rstrip(b"\x00").decode("latin1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, base + 8)
            self.sections.append((name or "(unnamed@0x%x)" % vaddr, vaddr, vsize, rawptr, rawsize))

    def off_to_rva(self, off):
        for name, vaddr, vsize, rawptr, rawsize in self.sections:
            if rawptr <= off < rawptr + rawsize:
                return vaddr + (off - rawptr)
        return None

    def off_to_section(self, off):
        for name, vaddr, vsize, rawptr, rawsize in self.sections:
            if rawptr <= off < rawptr + rawsize:
                return name
        return "(header)"


def scan_pointers(data):
    """全域扫描：byte5==0x7f && byte4>=0xf0 → 值域 [0x7ff000000000, 0x800000000000)。
    覆盖 0x7ff0-0x7fff 全部高段（含未对齐命中），不依赖已知范围清单。"""
    hits = []
    i = data.find(b"\x7f")
    while i != -1:
        if i >= 5 and data[i - 1] >= 0xF0:
            v = int.from_bytes(data[i - 5:i + 1], "little")
            if 0x7FF000000000 <= v < 0x800000000000:
                hits.append((i - 5, v))
        i = data.find(b"\x7f", i + 1)
    return hits


def classify(image, hits, module_map):
    ib, isize = image.image_base, image.size_of_image
    mods = []
    for m in (module_map or {}).get("modules", []):
        mods.append((m.get("name", "?"), int(m["base"], 0) if isinstance(m["base"], str) else int(m["base"]),
                     int(m.get("size", 0))))
    buckets = collections.Counter()
    own = kuser = 0
    violations = []  # (off, rva, value, aligned, section)
    module_hits = collections.Counter()
    for off, v in hits:
        buckets[v >> 16] += 1
        if ib <= v < ib + isize:
            own += 1
            continue
        if KUSER_BASE <= v < KUSER_END:
            kuser += 1
            continue
        hit_mod = None
        for name, base, size in mods:
            if base <= v < base + size:
                hit_mod = name
                break
        if hit_mod is not None:
            module_hits[hit_mod] += 1
            continue
        rva = image.off_to_rva(off)
        aligned = (rva % 8 == 0) if rva is not None else (off % 8 == 0)
        violations.append({"file_offset": hex(off), "rva": hex(rva) if rva is not None else None,
                           "value": hex(v), "aligned": aligned,
                           "section": image.off_to_section(off)})
    return {"buckets": buckets, "own": own, "kuser": kuser, "violations": violations,
            "module_hits": module_hits}


def gate_decision(image, res):
    """硬门：明文节 8 对齐违规 = FAIL；未对齐/加密区命中 = 入册 residual（不盲改）。"""
    hard, residual = [], []
    for v in res["violations"]:
        if v["aligned"] and v["section"] not in ENCRYPTED_SECTIONS:
            hard.append(v)
        else:
            residual.append(v)
    return hard, residual


def selftest(path):
    sha = sha256_file(path)
    if sha != SELFTEST_SHA:
        print("SELFTEST FAIL: image sha %s != expected %s" % (sha, SELFTEST_SHA))
        return 1
    data = open(path, "rb").read()
    image = PE(data)
    hits = scan_pointers(data)
    own = sum(1 for _, v in hits if image.image_base <= v < image.image_base + image.size_of_image)
    kuser = sum(1 for _, v in hits if KUSER_BASE <= v < KUSER_END)
    oldn = [(o, v) for o, v in hits if 0x7FFEEB320000 <= v < 0x7FFEEB620000]
    fam = [(o, v) for o, v in hits if 0x7FFEEB140000 <= v < 0x7FFEEB320000]
    fam_aligned = sum(1 for o, v in fam
                      if ((image.off_to_rva(o) if image.off_to_rva(o) is not None else o) % 8 == 0))
    got = {"own_image_refs": own, "old_ntdll_hits": len(oldn),
           "old_ntdll_all_unaligned": all(o % 8 != 0 and image.off_to_rva(o) % 8 != 0 for o, _ in oldn),
           "family_b14_b32_hits": len(fam), "family_b14_b32_aligned": fam_aligned,
           "kuser_hits": kuser}
    ok = True
    for k, exp in SELFTEST_EXPECT.items():
        good = (got[k] == exp)
        ok &= good
        print("  %-26s got=%-6s expect=%-6s %s" % (k, got[k], exp, "OK" if good else "MISMATCH"))
    print("SELFTEST %s (%s)" % ("PASS" if ok else "FAIL", path))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--module-map")
    ap.add_argument("--out")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest(args.image))

    data = open(args.image, "rb").read()
    image = PE(data)
    hits = scan_pointers(data)
    module_map = json.load(open(args.module_map, encoding="utf-8")) if args.module_map else None
    res = classify(image, hits, module_map)
    hard, residual = gate_decision(image, res)
    top_buckets = [{"bucket": hex(b << 16), "count": c} for b, c in res["buckets"].most_common(24)]
    report = {
        "schema": "xx21b_session_pointer_census/v1",
        "image": args.image,
        "image_sha256": sha256_file(args.image),
        "image_base": hex(image.image_base),
        "size_of_image": image.size_of_image,
        "dll_characteristics": hex(image.dll_characteristics),
        "module_map_source": args.module_map,
        "module_map_boot_time": (module_map or {}).get("boot_time"),
        "total_hits": len(hits),
        "own_image_refs": res["own"],
        "kuser_shared_data_refs": res["kuser"],
        "module_map_refs": dict(res["module_hits"]),
        "top_buckets": top_buckets,
        "hard_violations_aligned_plaintext": hard,
        "residual_unpatched": residual,
        "gate": "FAIL" if hard else "PASS",
        "note": "对齐明文违规=硬门FAIL；未对齐/加密区命中=入册 residual 不盲改（T020 票面纪律）",
    }
    text = json.dumps(report, ensure_ascii=False, indent=1)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(text)
    print(text)
    sys.exit(2 if hard else 0)


if __name__ == "__main__":
    main()
