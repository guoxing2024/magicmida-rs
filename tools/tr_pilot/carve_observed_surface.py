#!/usr/bin/env python3
"""GTO-TR-T2 Phase A: 观测表面雕刻原型

从 trace-era 全像转储按区域处置矩阵切分组件, 并产出页级 provenance。
头已被壳擦除 -> 节表采用 live 枚举值(E15_align rpc.start 回执)。
"""
import json, os, hashlib, collections

DUMP = r"D:\MidaVault\lab\evidence\gto_tr_t1\E15_align\trace_era_dump.bin"
OUT_DIR = r"D:\MidaVault\lab\evidence\gto_tr_t2\components"
PROV = r"D:\MidaVault\lab\evidence\gto_tr_t2\provenance.json"

# 节表来源: E15_align 会话 rpc.start 的 sections 消息(live loader 视图)
SECTIONS = [
    # name, rva, vsize            (end-rva 由日志换算)
    ("text",    0x1000,   0x12becc - 0x1000),
    ("rdata",   0x12c000, 0x176250 - 0x12c000),
    ("data",    0x177000, 0x1845cc - 0x177000),
    ("pdata",   0x185000, 0x18fa04 - 0x185000),
    ("fptable", 0x190000, 0x190100 - 0x190000),
    ("rdata0",  0x191000, 0x159e61d - 0x191000),
    ("rdata1",  0x159f000, 0x15a2f60 - 0x159f000),
    ("rdata2",  0x15a3000, 0x2d1ab78 - 0x15a3000),
    ("rsrc",    0x2d1b000, 0x2d1dbec - 0x2d1b000),
]
IMAGE_BASE = 0x140000000
SIZE_OF_IMAGE = 0x2d1e000

JSONLS = [
    r"D:\MidaVault\lab\evidence\gto_tr_t1\E1_a1\out.jsonl",
    r"D:\MidaVault\lab\evidence\gto_tr_t1\E1_a2\out.jsonl",
    r"D:\MidaVault\lab\evidence\gto_tr_t1\E15_align\out.jsonl",
] + [os.path.join(r"D:\MidaVault\lab\evidence\gto_tr_t1\E2_c1", f"s{i:02d}", "out.jsonl")
     for i in range(1, 11)]

def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    img = open(DUMP, "rb").read()
    assert len(img) == SIZE_OF_IMAGE, f"dump size {len(img):#x} != sizeOfImage {SIZE_OF_IMAGE:#x}"

    # 执行图: 绝对页号 -> 出现过的会话集合
    seen = collections.defaultdict(set)
    for idx, p in enumerate(JSONLS):
        tag = {0: "a1", 1: "a2", 2: "t15"}.get(idx, f"s{idx-2:02d}")
        if not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                try: e = json.loads(line)
                except Exception: continue
                if e.get("evt") != "exec": continue
                try: pg = int(e["rva"], 16) >> 12
                except Exception: continue
                seen[pg].add(tag)

    a1_r2 = {pg for pg, tags in seen.items() if "a1" in tags}

    prov = {"image": {"base": hex(IMAGE_BASE), "size_of_image": hex(SIZE_OF_IMAGE),
                      "dump_source": DUMP},
            "sections": [], "pages": {}}
    total_live = total_unknown = total_cond = total_decoy = 0

    img_bytes_written = 0
    for name, rva, vsize in SECTIONS:
        data = img[rva:rva + vsize]
        comp = os.path.join(OUT_DIR, f"{name}.bin")
        with open(comp, "wb") as f:
            f.write(data)
        base_pg = rva >> 12
        npages = vsize >> 12
        page_cls = {}
        cls_counts = collections.Counter()
        for rel in range(npages):
            pabs = base_pg + rel
            prva = hex(rva + rel * 0x1000)
            if name == "text":
                c = "live" if pabs in seen else "text-unexecuted"
            elif name == "rdata0":
                c = "live" if pabs in seen else "unknown"
            elif name == "rdata2":
                if pabs in a1_r2:
                    c = "cond-rare"; total_cond += 1
                elif pabs in seen:
                    c = "live"; total_live += 1
                else:
                    c = "suspected-decoy"; total_decoy += 1
            else:
                c = "data"
            page_cls[prva] = c
            cls_counts[c] += 1
        prov["sections"].append({
            "name": name, "rva": hex(rva), "vsize": hex(vsize),
            "component": f"{name}.bin", "sha256": hashlib.sha256(data).hexdigest(),
            "page_classes": dict(cls_counts),
        })
        prov["pages"][name] = page_cls
        img_bytes_written += len(data)
        print(f"{name:10s} rva=0x{rva:07x} vsize=0x{vsize:07x} -> {len(data):,} bytes "
              f"classes={dict(cls_counts)}")

    with open(PROV, "w", encoding="utf-8") as f:
        json.dump(prov, f, ensure_ascii=False)
    print(f"\ncomponents dir: {OUT_DIR}")
    print(f"provenance:     {PROV}")
    print(f"coverage: {img_bytes_written:,} / {SIZE_OF_IMAGE:,} bytes "
          f"({img_bytes_written/SIZE_OF_IMAGE*100:.1f}% of image)")
    print(f"rdata2 classes: cond-rare={total_cond} suspected-decoy={total_decoy} "
          f"(+live={total_live})")

if __name__ == "__main__":
    main()
