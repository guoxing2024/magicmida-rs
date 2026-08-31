#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TASK-027: VPC probe - validate Pushan Sec5.1 Themida VPC hypothesis on our .winlice.
Offline static, zero live fire. Input: PE with .winlice section.
Scans plaintext-code pages for VPC candidates:
  - rip-relative LEA (48/4C 8D modrm rm=101) targeting inside .winlice
  - mov r64,imm64 (48/49/4C B8+) targeting inside .winlice
  - indirect use: bytecode reads [reg+disp] where reg in candidate set
Outputs: entropy page map + candidate table JSON.
Usage: python tools/xx21b_vpc_probe.py <pe_path> <out_json>
"""
import sys, json, struct, math
from collections import Counter, defaultdict

def entropy(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def parse_sections(path):
    import pefile
    pe = pefile.PE(path)
    secs = []
    for s in pe.sections:
        name = s.Name.decode(errors='replace').rstrip('\x00') or '(unnamed)'
        secs.append({'name': name, 'va': s.VirtualAddress, 'vsz': s.Misc_VirtualSize,
                     'raw': s.PointerToRawData, 'rawsz': s.SizeOfRawData,
                     'chars': s.Characteristics})
    return pe, secs

def find_sec(secs, name):
    for s in secs:
        if s['name'] == name:
            return s
    return None

def scan_rip_lea(data, lo, hi, wl_va, wl_size, ib):
    """Find LEA reg,[rip+disp32] in [lo,hi) whose target lands in [wl_va, wl_va+wl_size).
    reg decoded with REX.R (b0 bit2)."""
    hits = []
    i = lo
    n = hi - 7
    while i < n:
        b0 = data[i]
        if b0 in (0x48, 0x4C, 0x49, 0x4D) and data[i+1] == 0x8D:
            rex = b0
            modrm = data[i+2]
            mod = (modrm >> 6) & 3
            rm  = modrm & 7
            if mod == 0 and rm == 5:  # [rip+disp32]
                disp = struct.unpack_from('<i', data, i+3)[0]
                insn_len = 7
                insn_va = wl_va + (i - lo)
                target = insn_va + insn_len + disp
                if wl_va <= target < wl_va + wl_size:
                    reg = ((modrm >> 3) & 7) | (0x8 if (rex & 4) else 0)  # REX.R
                    hits.append({'off': i, 'bytes': data[i:i+7].hex(),
                                 'insn': f'lea r{reg},[rip+0x{disp & 0xffffffff:x}]',
                                 'insn_va': insn_va, 'target': target, 'reg': reg})
            i += 1
        else:
            i += 1
    return hits

def scan_mov_imm64(data, lo, hi, wl_va, wl_size):
    """mov r64, imm64: 48/49/4C/4D B8-BF + 8-byte imm. reg decoded with REX.B."""
    hits = []
    i = lo
    n = hi - 9
    while i < n:
        b0 = data[i]
        if b0 in (0x48, 0x49, 0x4C, 0x4D) and 0xB8 <= data[i+1] <= 0xBF:
            reg = (data[i+1] & 7) | (0x8 if (b0 & 1) else 0)  # REX.B
            imm = struct.unpack_from('<Q', data, i+2)[0]
            if wl_va <= imm < wl_va + wl_size:
                insn_va = wl_va + (i - lo)
                hits.append({'off': i, 'bytes': data[i:i+10].hex(),
                             'insn': f'mov r{reg},0x{imm:x}', 'insn_va': insn_va,
                             'target': imm, 'reg': reg})
            i += 1
        else:
            i += 1
    return hits

def scan_indirect_uses(data, lo, hi, wl_va, cand_regs):
    """[reg+disp] reads (movzx/mov) where base reg (modrm rm + REX.B) in cand_regs."""
    uses = []
    i = lo
    n = hi - 4
    while i < n:
        b0 = data[i]
        rex = 0
        if b0 in (0x48, 0x4C, 0x49, 0x4D):
            # look ahead: movzx/mov with REX prefix
            j = i + 1
            if j >= hi: break
            if data[j] == 0x0F and j+1 < hi and data[j+1] in (0xB6, 0xB7):
                rex = b0
                modrm = data[j+2]; base = j+3; sz = 2
                if ((modrm >> 6) & 3) == 2: sz = 3
                rm = (modrm & 7) | (0x8 if (rex & 1) else 0)
                if rm in cand_regs and ((modrm >> 6) & 3) in (1, 2):
                    disp = struct.unpack_from('<b' if ((modrm>>6)&3)==1 else '<i', data, base)[0]
                    insn_va = wl_va + (i - lo)
                    uses.append({'off': i, 'bytes': data[i:base+sz].hex(),
                                 'insn': f'movzx r?,[r{rm}+0x{disp & 0xffffffff:x}]',
                                 'insn_va': insn_va, 'base_reg': rm})
                    i = base + sz - 1
                else:
                    i += 1
                continue
            elif data[j] == 0x8B:
                rex = b0
                modrm = data[j+1]; base = j+2; sz = 2
                if ((modrm >> 6) & 3) == 2: sz = 3
                rm = (modrm & 7) | (0x8 if (rex & 1) else 0)
                if rm in cand_regs and ((modrm >> 6) & 3) in (1, 2):
                    disp = struct.unpack_from('<b' if ((modrm>>6)&3)==1 else '<i', data, base)[0]
                    insn_va = wl_va + (i - lo)
                    uses.append({'off': i, 'bytes': data[i:base+sz].hex(),
                                 'insn': f'mov r?,[r{rm}+0x{disp & 0xffffffff:x}]',
                                 'insn_va': insn_va, 'base_reg': rm})
                    i = base + sz - 1
                else:
                    i += 1
                continue
            else:
                i += 1
                continue
        # no REX prefix: movzx 0F B6/B7, mov 8B
        if b0 == 0x0F and i+1 < hi and data[i+1] in (0xB6, 0xB7):
            modrm = data[i+2]
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            if mod in (1, 2) and rm in cand_regs:
                sz = 2 if mod == 1 else 3
                disp = struct.unpack_from('<b' if mod == 1 else '<i', data, i+3)[0]
                insn_va = wl_va + (i - lo)
                uses.append({'off': i, 'bytes': data[i:i+3+sz].hex(),
                             'insn': f'movzx r?,[r{rm}+0x{disp & 0xffffffff:x}]',
                             'insn_va': insn_va, 'base_reg': rm})
            i += 1
        elif b0 == 0x8B:
            modrm = data[i+1]
            mod = (modrm >> 6) & 3
            rm = modrm & 7
            if mod in (1, 2) and rm in cand_regs:
                sz = 2 if mod == 1 else 3
                disp = struct.unpack_from('<b' if mod == 1 else '<i', data, i+2)[0]
                insn_va = wl_va + (i - lo)
                uses.append({'off': i, 'bytes': data[i:i+2+sz].hex(),
                             'insn': f'mov r?,[r{rm}+0x{disp & 0xffffffff:x}]',
                             'insn_va': insn_va, 'base_reg': rm})
            i += 1
        else:
            i += 1
    return uses

def main():
    path = sys.argv[1]
    out = sys.argv[2]
    pe, secs = parse_sections(path)
    ib = pe.OPTIONAL_HEADER.ImageBase
    wl = find_sec(secs, '.winlice')
    if not wl:
        print("NO .winlice section"); sys.exit(2)
    data = open(path, 'rb').read()
    raw_lo = wl['raw']; raw_sz = wl['rawsz']
    raw_hi = min(raw_lo + raw_sz, len(data))
    wl_va = wl['va']

    # entropy page map
    pages = []
    for off in range(raw_lo, raw_hi, 4096):
        chunk = data[off:min(off+4096, raw_hi)]
        e = entropy(chunk)
        pages.append({'off': off, 'va': wl_va + (off - raw_lo),
                      'entropy': round(e, 3),
                      'class': 'plain' if e < 6.5 else ('bytecode' if e >= 7.0 else 'mixed')})

    plain_pages = [p for p in pages if p['class'] == 'plain']
    print(f"winlice raw={raw_lo:#x}..{raw_hi:#x} size={raw_sz:#x} pages={len(pages)} "
          f"plain={len(plain_pages)} mixed={sum(1 for p in pages if p['class']=='mixed')} "
          f"bytecode={sum(1 for p in pages if p['class']=='bytecode')}")

    # scan plain pages only (code region)
    scan_lo = raw_lo if plain_pages else raw_lo
    scan_hi = raw_hi
    leas = scan_rip_lea(data, scan_lo, scan_hi, wl_va, wl['vsz'], ib)
    movs = scan_mov_imm64(data, scan_lo, scan_hi, wl_va, wl['vsz'])
    print(f"rip-lea hits in .winlice: {len(leas)} | mov imm64 hits: {len(movs)}")

    # candidate regs from lea targets pointing to bytecode pages (entropy>=7)
    bytecode_vas = {p['va'] for p in pages if p['class'] == 'bytecode'}
    def in_bytecode(t):
        return any(v <= t < v + 4096 for v in bytecode_vas)
    cand = []
    for h in leas + movs:
        if in_bytecode(h['target']):
            cand.append(h)
    print(f"candidates targeting bytecode pages: {len(cand)}")

    # indirect uses of candidate regs
    cand_regs = sorted({h['reg'] for h in cand})
    uses = scan_indirect_uses(data, scan_lo, scan_hi, wl_va, set(cand_regs))
    print(f"indirect [reg+disp] uses (cand regs {cand_regs}): {len(uses)}")

    # VPC plausibility: candidates whose reg is used in >=3 indirect reads
    reg_use = defaultdict(int)
    for u in uses:
        reg_use[u['base_reg']] += 1
    vpc_plausible = [h for h in cand if reg_use.get(h['reg'], 0) >= 3]

    result = {
        'input': path,
        'image_base': hex(ib),
        'winlice': {'va': hex(wl_va), 'raw': hex(raw_lo), 'size': hex(raw_sz)},
        'pages': pages,
        'candidates': cand,
        'indirect_uses': uses,
        'reg_use_counts': dict(reg_use),
        'vpc_plausible': vpc_plausible,
        'verdict': 'HYPOTHESIS_SUPPORTED' if vpc_plausible else ('HYPOTHESIS_UNCLEAR' if cand else 'HYPOTHESIS_REJECTED'),
    }
    with open(out, 'w') as f:
        json.dump(result, f, indent=1)
    print("verdict:", result['verdict'])
    for h in vpc_plausible[:10]:
        print(f"  VPC cand: {h['insn']} @va=0x{h['insn_va']:x} target=0x{h['target']:x} reg={h['reg']} uses={reg_use.get(h['reg'],0)}")

if __name__ == '__main__':
    main()
