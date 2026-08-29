#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TASK-005 — 0x8c000-0x8cfff 区归属复核（0x8c4c0 是否主译码器）

纯离线，Python 标准库。只读 trace，输出统计。

三种统计口径（自证）：
  A. 页起始地址精确匹配：exec rva 恰好等于页首 0x8c000
  B. 页区间包含：exec rva 落在 [0x8c000, 0x8d000)
  C. 基本块覆盖（块区间包含）：用"上一记录 → 本记录"的地址对，
     若上一记录地址落在 0x8c000-0x8cfff 区间内，则按"块起始 ∈ 区间"计，
     并且尝试用前后记录的地址跨度判断该块是否可能覆盖 0x8c4c0。

关键地址逐址 exec：0x8c4c0 / 0x8f0bb / 0x8f099 / 0x12d8c8。
间接 call 目标分布：0x8f099 之后（同源相邻 exec）实际落到哪些地址（top-N）。
"""
import re, sys, time
from collections import Counter

RVA_RE = re.compile(r'"rva": "(0x[0-9a-fA-F]+)"')
TICK_RE = re.compile(r'"tick_ms": (\d+)')

PAGE = 0x8C000
PAGE_HI = 0x8D000
TARGET = 0x8C4C0
DECODE = 0x8F099
DECODE_NEXT_BYTES = 32  # 0x8f099 块内后续地址跨度上限（用于"块可能覆盖目标"的推断）

def scan(path):
    stats = {
        'lines': 0, 'exec': 0,
        'page_start_exact': 0,        # A: rva == 0x8c000
        'page_interval': 0,           # B: 0x8c000 <= rva < 0x8d000
        'block_in_page': 0,           # C: 上一个 exec rva 落在页区间（块起始在页内）
        'block_may_cover': 0,         # C2: 上一个 rva 在页内，且 上rva < 0x8c4c0 < 下rva
        'addr': Counter(),
        'decode_next': Counter(),     # 0x8f099 之后的下一 exec 地址
        'decode_prev': Counter(),     # 0x8f099 之前的上一 exec 地址
        'unique_in_page': set(),
    }
    prev = None
    with open(path, 'r', encoding='utf-8', errors='replace') as fh:
        for line in fh:
            stats['lines'] += 1
            if '"evt": "exec"' not in line:
                continue
            m = RVA_RE.search(line)
            if not m:
                continue
            a = int(m.group(1), 16)
            stats['exec'] += 1
            stats['addr'][a] += 1
            if a == PAGE:
                stats['page_start_exact'] += 1
            if PAGE <= a < PAGE_HI:
                stats['page_interval'] += 1
                stats['unique_in_page'].add(a)
            if prev is not None:
                if PAGE <= prev < PAGE_HI:
                    stats['block_in_page'] += 1
                    if prev < TARGET < a:
                        stats['block_may_cover'] += 1
                if prev == DECODE:
                    stats['decode_next'][a] += 1
                if a == DECODE:
                    stats['decode_prev'][prev] += 1
            prev = a
    return stats

def main():
    out = sys.argv[3]
    t0 = time.time()
    print("[*] scanning E15_align ...")
    e15 = scan(sys.argv[1])
    print(f"    lines={e15['lines']:,} exec={e15['exec']:,} ({time.time()-t0:.1f}s)")
    t1 = time.time()
    print("[*] scanning D_b1 ...")
    db1 = scan(sys.argv[2])
    print(f"    lines={db1['lines']:,} exec={db1['exec']:,} ({time.time()-t1:.1f}s)")

    L = []
    L.append("# TASK-005 — 0x8c4c0 区归属复核（复算输出）\n")
    L.append(f"- 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    L.append(f"- 脚本: tools/task005_recheck_8c4c0.py（本工单独立复算）")
    L.append(f"- 粒度: 基本块入口级（trace 事件 = 块首地址）\n")

    L.append("## 一、三种口径下的 0x8c000-0x8cfff 区计数\n")
    L.append("| 口径 | E15_align | D_b1 | 合计 |")
    L.append("|---:|---:|---:|---:|")
    rows = [
        ("A. 页起始地址精确匹配 (rva==0x8c000)", 'page_start_exact'),
        ("B. 页区间包含 (0x8c000<=rva<0x8d000)", 'page_interval'),
        ("C. 块起始∈页区间 (上一条exec rva∈页内)", 'block_in_page'),
        ("C2. 块可能跨越覆盖 0x8c4c0 (上rva<0x8c4c0<下rva)", 'block_may_cover'),
    ]
    for label, key in rows:
        a, b = e15[key], db1[key]
        L.append(f"| {label} | {a:,} | {b:,} | {a+b:,} |")
    L.append(f"| 页区间内 unique 地址数 | {len(e15['unique_in_page'])} | {len(db1['unique_in_page'])} | {len(e15['unique_in_page']|db1['unique_in_page'])} |")

    L.append("\n## 二、关键地址逐址 exec 计数\n")
    L.append("| 地址 | E15 | D_b1 | 合计 |")
    L.append("|---:|---:|---:|---:|")
    for a in [0x8c4c0, 0x8f0bb, 0x8f099, 0x12d8c8]:
        ea, da = e15['addr'].get(a, 0), db1['addr'].get(a, 0)
        L.append(f"| 0x{a:06x} | {ea:,} | {da:,} | {ea+da:,} |")

    L.append("\n## 三、0x8f099（译码分支）之后同源相邻 exec 目标分布 top-8\n")
    L.append("| 目标 | E15 | D_b1 | 合计 | 区间 |")
    L.append("|---:|---:|---:|---:|---|")
    merged = Counter()
    for k, v in e15['decode_next'].items():
        merged[k] += v
    for k, v in db1['decode_next'].items():
        merged[k] += v
    for a, v in merged.most_common(8):
        ea, da = e15['decode_next'].get(a, 0), db1['decode_next'].get(a, 0)
        zone = "0x8c000-0x8cfff" if PAGE <= a < PAGE_HI else ("0x8f000区" if 0x8f000 <= a < 0x90000 else "其他")
        L.append(f"| 0x{a:06x} | {ea:,} | {da:,} | {v:,} | {zone} |")

    L.append("\n## 四、0x8f099 之前同源相邻 exec 来源分布 top-5\n")
    L.append("| 来源 | E15 | D_b1 | 合计 |")
    L.append("|---:|---:|---:|---:|")
    mp = Counter()
    for k, v in e15['decode_prev'].items():
        mp[k] += v
    for k, v in db1['decode_prev'].items():
        mp[k] += v
    for a, v in mp.most_common(5):
        ea, da = e15['decode_prev'].get(a, 0), db1['decode_prev'].get(a, 0)
        L.append(f"| 0x{a:06x} | {ea:,} | {da:,} | {v:,} |")

    with open(out, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(L) + '\n')
    print(f"[+] written: {out}")
    print(f"[+] total {time.time()-t0:.1f}s")

if __name__ == '__main__':
    main()
