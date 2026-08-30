#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TASK-020R1 — candidate core session-pointer cleanse, base-correction micro-patch
(option A, pure offline, zero live fire).

Corrects TASK-020's wrong ntdll patch base 0x7ffd37ae0000 -> 0x7ffd379e0000
(commander-owned D-038 mis-decomposition; quadruple-verified per ticket).
Adds the TASK-020-missing NON-ALIGNED census pass:
  - aligned scan (as TASK-020) for A-class dead-range hits  -> patched
  - NON-aligned scan over old ntdll dead range [0x7ffeeb320000, +0x300000)
    and old urlmon dead range -> residuals recorded in pointer_map
    "residual_unpatched" (NOT patched: .winlice is the reserved shell region,
    blind edits risk breaking encoding).

Work object is a FRESH COPY of the vault original
(D:/MidaVault/lab/worktree_evidence_20260830/lab/xx21b_run/core_perfect_candidate.dll,
sha256 3650ea6c..., read-only).  No process is started; no module loaded.
git is read-only; crates/ untouched.
"""

import argparse
import hashlib
import io
import json
import os
import shutil
import struct
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

CAND_SHA256 = "3650ea6c0a88c731d4b613eaa533ab1d48258ce782843a5661ca6c683fd9b64e"

# Dump session dead module ranges (same evidence as TASK-020).
DEAD_RANGES = [
    {"module": "ntdll.dll", "base": 0x7FFEEB320000, "size": 0x300000,
     "evidence": "T0.4 report: ntdll 0x7ffeeb320000 (+0x106390 stale=0x7ffeeb426390); "
                 "D-038/30c163 verdict; T019 2/2 AV @0x7ffeeb426390. "
                 "R1: census window widened to +0x300000 per ticket item 2."},
    {"module": "urlmon.dll", "base": 0x7FFEC48F0000, "size": 0x1DD000,
     "evidence": "recovered from T0.4 step1 IAT slot value 0x7ffec49ee470 - urlmon "
                 "export rva 0xfe470 (URLDownloadToFileA) = base 0x7ffec48f0000"},
    {"module": "wininet.dll", "base": 0x7FFD20460000, "size": 0x295000,
     "evidence": "recovered from T0.5 att1 (t05_att1_dbg.json) deploy_check "
                 "wininet_module base=0x7ffd20460000"},
]

# CURRENT session bases. R1: ntdll corrected 0x7ffd37ae0000 -> 0x7ffd379e0000
# (quadruple-verified per ticket: python EnumProcessModules, .bss minus doc offset,
# T019 first LOAD_DLL, T018 RIP sample). urlmon/wininet unchanged.
CURRENT_MODULES = {
    "ntdll.dll": 0x7FFD379E0000,
    "urlmon.dll": 0x7FFD10050000,
    "wininet.dll": 0x7FFD20460000,
}

CURRENT_MODULES_EVIDENCE = (
    "TASK-020R1: ntdll base CORRECTED to 0x7ffd379e0000 (quadruple-verified: "
    "1) commander python EnumProcessModules ntdll=0x7ffd379e0000 kernel32=0x7ffd36600000; "
    "2) host a852880a .bss 0x112c10 value 0x7ffd37ae6390 - documented offset 0x106390 "
    "= 0x7ffd379e0000; 3) T019 pump first LOAD_DLL (ntdll)=0x7ffd379e0000; "
    "4) T018 RIP sample 0x7ffd37b44680 (owner ntdll.dll) - 0x7ffd379e0000 = 0x164680 "
    "in ntdll image range). urlmon 0x7ffd10050000, wininet 0x7ffd20460000 unchanged "
    "from TASK-020 (urlmon slot verified correct)."
)


class PeSection:
    __slots__ = ("name", "vaddr", "vsize", "raw_off", "raw_size", "idx")

    def __init__(self, name, vaddr, vsize, raw_off, raw_size, idx):
        self.name = name
        self.vaddr = vaddr
        self.vsize = vsize
        self.raw_off = raw_off
        self.raw_size = raw_size
        self.idx = idx

    def __repr__(self):  # pragma: no cover
        return "PeSection(%r,vaddr=%#x,vsize=%#x,raw_off=%#x,raw_size=%#x)" % (
            self.name, self.vaddr, self.vsize, self.raw_off, self.raw_size)


class PeInfo:
    """Minimal PE32+ reader: headers, section table, data directory, RVA<->offset."""

    def __init__(self, data):
        self.data = data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise ValueError("not an MZ PE")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("no PE signature")
        self.e_lfanew = e_lfanew
        self.machine, self.nsects, _, _, _, self.sizopt, _ = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4)
        self.opt = e_lfanew + 24
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        if self.magic != 0x20B:
            raise ValueError("not PE32+ (magic=%#x)" % self.magic)
        self.image_base = struct.unpack_from("<Q", data, self.opt + 24)[0]
        self.size_of_image = struct.unpack_from("<I", data, self.opt + 56)[0]
        self.dll_chars = struct.unpack_from("<H", data, self.opt + 70)[0]
        self.file_chars = struct.unpack_from("<H", data, e_lfanew + 4 + 18)[0]
        self.dirs = []
        dd = self.opt + 112
        for i in range(16):
            rva, size = struct.unpack_from("<II", data, dd + i * 8)
            self.dirs.append((rva, size))
        so = self.opt + self.sizopt
        self.sections = []
        for i in range(self.nsects):
            off = so + i * 40
            name = data[off:off + 8].rstrip(b"\0").decode("latin1")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append(PeSection(name, vaddr, vsize, roff, rsize, i))

    def section_at_rva(self, rva):
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size) and s.raw_size > 0:
                return s
        return None

    def rva_to_offset(self, rva):
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + max(s.vsize, s.raw_size) and s.raw_size > 0:
                return s.raw_off + (rva - s.vaddr)
        return None

    def offset_to_rva(self, off):
        for s in self.sections:
            if s.raw_off <= off < s.raw_off + s.raw_size:
                return s.vaddr + (off - s.raw_off)
        return None

    def read_qword_at_rva(self, rva):
        o = self.rva_to_offset(rva)
        if o is None or o + 8 > len(self.data):
            return None
        return struct.unpack_from("<Q", self.data, o)[0]


def parse_reloc_table(pe, data):
    rva, size = pe.dirs[5]
    if rva == 0 or size == 0:
        return [], (0, 0)
    o = pe.rva_to_offset(rva)
    if o is None:
        return [], (0, 0)
    entries = []
    p = o
    end = o + size
    while p + 8 <= end:
        page, bsize = struct.unpack_from("<II", data, p)
        if bsize < 8 or p + bsize > end:
            break
        n = (bsize - 8) // 2
        for j in range(n):
            w = struct.unpack_from("<H", data, p + 8 + j * 2)[0]
            typ = w >> 12
            offin = w & 0xFFF
            if typ == 0:
                continue
            entries.append((page, page + offin, typ))
        p += bsize
    return entries, (o, end)


def parse_exports(pe, data):
    rva, size = pe.dirs[0]
    if rva == 0:
        return {}
    o = pe.rva_to_offset(rva)
    if o is None:
        return {}
    nfuncs = struct.unpack_from("<I", data, o + 20)[0]
    nnames = struct.unpack_from("<I", data, o + 24)[0]
    addr_rva = struct.unpack_from("<I", data, o + 28)[0]
    name_rva = struct.unpack_from("<I", data, o + 32)[0]
    ord_rva = struct.unpack_from("<I", data, o + 36)[0]
    out = {}
    for i in range(nnames):
        nr = struct.unpack_from("<I", data, pe.rva_to_offset(name_rva) + i * 4)[0]
        no = pe.rva_to_offset(nr)
        if no is None:
            continue
        end = data.find(b"\0", no)
        nm = data[no:end].decode("latin1")
        ordi = struct.unpack_from("<H", data, pe.rva_to_offset(ord_rva) + i * 2)[0]
        if ordi < nfuncs:
            frva = struct.unpack_from(
                "<I", data, pe.rva_to_offset(addr_rva) + ordi * 4)[0]
            out[nm] = frva
    return out


def is_user_pointer(v):
    if v == 0:
        return False
    if (v >> 48) & 0xFFFF != 0:
        return False
    hi = (v >> 32) & 0xFFFF
    if hi in (0x7FFD, 0x7FFE, 0x7FFC, 0x7FFB, 0x7FFA, 0x7FF9, 0x7FF8):
        return True
    return False


def scan_pointers(pe, data, aligned_only=True):
    """aligned_only=True -> 8-byte aligned offsets (TASK-020 semantics).
    aligned_only=False -> every byte offset (non-aligned census)."""
    hits = []
    n = len(data)
    step = 8 if aligned_only else 1
    for off in range(0, n - 7, step):
        v = struct.unpack_from("<Q", data, off)[0]
        if not is_user_pointer(v):
            continue
        rva = pe.offset_to_rva(off)
        sec = pe.section_at_rva(rva) if rva is not None else None
        hits.append({
            "file_offset": off,
            "rva": rva,
            "section": sec.name if sec else None,
            "value": v,
            "value_hex": "0x%016x" % v,
        })
    return hits


def classify(hits, dead_ranges):
    out = []
    for h in hits:
        v = h["value"]
        a = None
        for dr in dead_ranges:
            if dr["base"] <= v < dr["base"] + dr["size"]:
                a = {
                    "module": dr["module"],
                    "base": dr["base"],
                    "size": dr["size"],
                    "offset": v - dr["base"],
                    "evidence": dr["evidence"],
                }
                break
        h["class"] = "A" if a else "B"
        h["dead_range"] = a
        out.append(h)
    return out


def plan_patches(pe, data, a_hits, current_modules, reloc_entries, log):
    reloc_rvas = set()
    for page, erva, typ in reloc_entries:
        reloc_rvas.add(erva)
    patches = []
    uncleaned = []
    for h in a_hits:
        dr = h["dead_range"]
        cur = current_modules.get(dr["module"])
        new_val = (cur + dr["offset"]) if cur is not None else None
        rva = h["rva"]
        covered = rva in reloc_rvas if rva is not None else False
        if new_val is None:
            h["action"] = "uncleaned(no-current-base)"
            uncleaned.append(h)
            continue
        if covered:
            h["action"] = "uncleaned(reloc-covered)"
            uncleaned.append(h)
            continue
        h["action"] = "patch"
        h["new_value"] = new_val
        h["new_value_hex"] = "0x%016x" % new_val
        h["reloc_covered"] = False
        patches.append(h)
    return patches, uncleaned


def apply_patches(data, patches):
    out = bytearray(data)
    for p in patches:
        off = p["file_offset"]
        struct.pack_into("<Q", out, off, p["new_value"])
        p["old_bytes"] = bytes(data[off:off + 8]).hex()
        p["new_bytes"] = bytes(out[off:off + 8]).hex()
    return bytes(out)


def sha256_of(b):
    return hashlib.sha256(b).hexdigest()


def diff_bytes(orig, new):
    diffs = []
    n = min(len(orig), len(new))
    i = 0
    while i < n:
        if orig[i] != new[i]:
            j = i
            while j < n and orig[j] != new[j]:
                j += 1
            diffs.append((i, j - i))
            i = j
        else:
            i += 1
    return diffs


def main():
    ap = argparse.ArgumentParser(description="TASK-020R1 candidate core cleanse (base-corrected)")
    ap.add_argument("--copy-dir", default="lab/xx21b_pcell_clean",
                    help="work directory for the copy (default lab/xx21b_pcell_clean)")
    ap.add_argument("--vault-original", required=True,
                    help="path to vault original core_perfect_candidate.dll (read-only)")
    ap.add_argument("--rescan-only", action="store_true",
                    help="only rescan the cleaned copy and report A-class hits")
    args = ap.parse_args()

    orig_path = args.vault_original
    copy_dir = args.copy_dir
    copy_path = os.path.join(copy_dir, "core_perfect_candidate_cleaned.dll")

    orig_sha = sha256_of(open(orig_path, "rb").read())
    print("[gate] vault original sha256 = %s (expect %s)" % (orig_sha, CAND_SHA256))
    if orig_sha != CAND_SHA256:
        print("[gate] FAIL: vault original identity mismatch -> STOP")
        return 2
    print("[gate] vault original identity OK")

    if args.rescan_only:
        if not os.path.exists(copy_path):
            print("[rescan] no cleaned copy at %s" % copy_path)
            return 1
        data = open(copy_path, "rb").read()
        pe = PeInfo(data)
        hits = classify(scan_pointers(pe, data), DEAD_RANGES)
        a_hits = [h for h in hits if h["class"] == "A"]
        print("[rescan] aligned A-class hits = %d" % len(a_hits))
        for h in a_hits:
            print("  A-hit off=%#x rva=%s sec=%s val=%s dead=%s" % (
                h["file_offset"], h["rva"], h["section"],
                h["value_hex"], h["dead_range"]["module"]))
        # residual_unpatched = non-aligned A-class hits EXCLUDING the aligned
        # patch slots (those are already patched; ticket expects 13 residuals,
        # all .winlice).  On the cleaned copy the aligned slots no longer hit,
        # so this filter only matters for symmetry on the original.
        na_all = classify(scan_pointers(pe, data, aligned_only=False), DEAD_RANGES)
        na_aligned_offsets = {h["file_offset"] for h in a_hits}
        na = [h for h in na_all if h["class"] == "A"
              and h["file_offset"] not in na_aligned_offsets]
        print("[rescan] non-aligned dead-range residuals (excl. aligned slots) = %d" % len(na))
        for h in na:
            print("  NA-hit off=%#x rva=%s sec=%s val=%s dead=%s+%#x" % (
                h["file_offset"], h["rva"], h["section"], h["value_hex"],
                h["dead_range"]["module"], h["dead_range"]["offset"]))
        return 0 if (len(a_hits) == 0 and len(na) == 0) else 3

    # ---- Phase 1: scan original (read-only) ----
    data = open(orig_path, "rb").read()
    pe = PeInfo(data)
    reloc_entries, reloc_extent = parse_reloc_table(pe, data)
    exports = parse_exports(pe, data)
    print("[phase1] sections=%d image_base=%#x size_of_image=%#x" % (
        pe.nsects, pe.image_base, pe.size_of_image))
    print("[phase1] exports: %s" % sorted(exports.items()))
    print("[phase1] reloc entries=%d extent=%s" % (len(reloc_entries), reloc_extent))
    for e in reloc_entries:
        print("   reloc page=%#x entry_rva=%#x type=%d" % (e[0], e[1], e[2]))

    hits = classify(scan_pointers(pe, data), DEAD_RANGES)
    a_hits = [h for h in hits if h["class"] == "A"]
    print("[phase1] pointer-looking hits (aligned) = %d, A-class = %d" % (
        len(hits), len(a_hits)))
    for h in a_hits:
        print("  A-hit off=%#x rva=%s sec=%s val=%s dead=%s+%#x" % (
            h["file_offset"], h["rva"], h["section"], h["value_hex"],
            h["dead_range"]["module"], h["dead_range"]["offset"]))

    # ---- Phase 2: plan + apply on FRESH copy ----
    patches, uncleaned = plan_patches(pe, data, a_hits, CURRENT_MODULES, reloc_entries, print)
    print("[phase2] patches=%d uncleaned=%d" % (len(patches), len(uncleaned)))
    for u in uncleaned:
        print("  uncleaned: off=%#x val=%s reason=%s" % (
            u["file_offset"], u["value_hex"], u["action"]))

    os.makedirs(copy_dir, exist_ok=True)
    shutil.copy2(orig_path, copy_path)          # FRESH copy from vault original
    new_data = apply_patches(data, patches)
    with open(copy_path, "wb") as f:
        f.write(new_data)

    # ---- Phase 3: verify on copy ----
    pe2 = PeInfo(new_data)
    hits2 = classify(scan_pointers(pe2, new_data), DEAD_RANGES)
    a2 = [h for h in hits2 if h["class"] == "A"]
    print("[phase3] rescan aligned A-class hits = %d" % len(a2))
    for h in a2:
        print("  A-hit off=%#x rva=%s sec=%s val=%s" % (
            h["file_offset"], h["rva"], h["section"], h["value_hex"]))

    diffs = diff_bytes(data, new_data)
    diff_total = sum(sz for _, sz in diffs)
    patch_ranges = [(p["file_offset"], p["file_offset"] + 8) for p in patches]
    coverage_ok = True
    for o, sz in diffs:
        covered = any(o >= s and o + sz <= e for s, e in patch_ranges)
        if not covered:
            coverage_ok = False
            print("  [minimality] diff region off=%#x size=%d NOT covered by any patch" % (o, sz))
    slot_changed = []
    for p in patches:
        o = p["file_offset"]
        nd = sum(1 for k in range(8) if data[o + k] != new_data[o + k])
        slot_changed.append((o, nd))
    slot_bytes = sum(nd for _, nd in slot_changed)
    print("[phase3] diff regions=%d diff_bytes=%d patch_slots=%d per-slot changed=%s "
          "sum=%d coverage_ok=%s (sum == diff_total: %s)" % (
              len(diffs), diff_total, len(patches),
              ["%#x:%d" % (o, n) for o, n in slot_changed],
              slot_bytes, coverage_ok, slot_bytes == diff_total))

    exports2 = parse_exports(pe2, new_data)
    print("[phase3] exports2: %s" % sorted(exports2.items()))

    sec0 = pe.sections[0]
    t_orig = data[sec0.raw_off:sec0.raw_off + sec0.raw_size]
    t_new = new_data[sec0.raw_off:sec0.raw_off + sec0.raw_size]
    print("[phase3] .text[0] (%s vaddr=%#x raw=%#x+%#x) unchanged=%s" % (
        sec0.name, sec0.vaddr, sec0.raw_off, sec0.raw_size, t_orig == t_new))

    r_orig = data[reloc_extent[0]:reloc_extent[1]]
    r_new = new_data[reloc_extent[0]:reloc_extent[1]]
    print("[phase3] .reloc extent %s unchanged=%s" % (
        (hex(reloc_extent[0]), hex(reloc_extent[1])), r_orig == r_new))

    # ---- Non-aligned residual census (TASK-020 missing item) ----
    # residual_unpatched = non-aligned A-class hits EXCLUDING the aligned patch
    # slots (ticket: 13 residuals, all .winlice reserved shell region).
    patch_offsets = {p["file_offset"] for p in patches}
    na_orig = classify(scan_pointers(pe, data, aligned_only=False), DEAD_RANGES)
    na_orig_hits = [h for h in na_orig if h["class"] == "A"
                    and h["file_offset"] not in patch_offsets]
    na_new = classify(scan_pointers(pe2, new_data, aligned_only=False), DEAD_RANGES)
    na_new_hits = [h for h in na_new if h["class"] == "A"
                   and h["file_offset"] not in patch_offsets]
    print("[phase3] non-aligned dead-range residuals (orig) = %d" % len(na_orig_hits))
    for h in na_orig_hits:
        print("  NA-orig off=%#x rva=%s sec=%s val=%s dead=%s+%#x" % (
            h["file_offset"], h["rva"], h["section"], h["value_hex"],
            h["dead_range"]["module"], h["dead_range"]["offset"]))
    print("[phase3] non-aligned dead-range residuals (copy) = %d" % len(na_new_hits))
    for h in na_new_hits:
        print("  NA-copy off=%#x rva=%s sec=%s val=%s dead=%s+%#x" % (
            h["file_offset"], h["rva"], h["section"], h["value_hex"],
            h["dead_range"]["module"], h["dead_range"]["offset"]))
    na_orig_keys = {(h["file_offset"], h["value"]) for h in na_orig_hits}
    na_new_keys = {(h["file_offset"], h["value"]) for h in na_new_hits}
    print("[phase3] non-aligned residual orig==copy: %s" % (na_orig_keys == na_new_keys))
    all_winlice = all(h["section"] == ".winlice" for h in na_orig_hits)
    print("[phase3] all residuals in .winlice: %s (count=%d, ticket expects 13)" % (
        all_winlice, len(na_orig_hits)))

    new_sha = sha256_of(new_data)
    print("[phase3] cleaned copy sha256 = %s" % new_sha)

    # ---- pointer_map.json ----
    pm = {
        "schema": "xx21b_pointer_map/v1",
        "task": "TASK-020R1",
        "ticket": "tickets/TASK-020R1.md",
        "supersedes": "TASK-020",
        "candidate_sha256": CAND_SHA256,
        "cleaned_copy_sha256": new_sha,
        "cleaned_copy_path": copy_path,
        "image_base": pe.image_base,
        "size_of_image": pe.size_of_image,
        "dead_ranges": DEAD_RANGES,
        "current_modules": CURRENT_MODULES,
        "current_modules_evidence": CURRENT_MODULES_EVIDENCE,
        "dead_ranges_excluded": [
            {"module": "wininet.dll", "base": 0x7FFD20460000,
             "why": "base belongs to current-session family (T0.5 att1), not dump session"}
        ],
        "hits": hits,
        "patches": patches,
        "uncleaned": uncleaned,
        "residual_unpatched": na_orig_hits,
        "rescan_a_class_hits_after": len(a2),
        "rescan_non_aligned_residuals_after": len(na_new_hits),
        "non_aligned_residual_orig_copy_identical": (na_orig_keys == na_new_keys),
        "diff_regions": [{"offset": o, "size": s} for o, s in diffs],
        "diff_total_bytes": diff_total,
        "patch_slots": len(patches),
        "per_slot_changed_bytes": [{"offset": o, "changed": n} for o, n in slot_changed],
        "minimality_coverage_ok": coverage_ok,
        "minimality_sum_equals_diff_total": slot_bytes == diff_total,
        "exports": sorted(exports.items()),
        "note": ("TASK-020R1: ntdll patch base CORRECTED 0x7ffd37ae0000 -> 0x7ffd379e0000 "
                 "(D-038 mis-decomposition, commander-owned). 13 non-aligned residuals "
                 "(all .winlice reserved shell region) recorded in residual_unpatched, "
                 "NOT patched per ticket (blind edits risk breaking VM encoding). "
                 "Cleanup still binds to CURRENT session; cross-reboot dies (C-5 not cured). "
                 "pointer_map.json is the future T0.5 runtime deploy-time fixup input."),
    }
    pm_path = os.path.join(copy_dir, "pointer_map.json")
    with open(pm_path, "w", encoding="utf-8") as f:
        json.dump(pm, f, ensure_ascii=False, indent=1)
    print("[done] pointer_map.json written to %s" % pm_path)

    print("[audit] per-patch byte reconciliation:")
    for p in patches:
        off = p["file_offset"]
        old = bytes(data[off:off + 8]).hex()
        new = bytes(new_data[off:off + 8]).hex()
        ok = (old == p.get("old_bytes") and new == p.get("new_bytes"))
        print("  off=%#x old=%s new=%s ok=%s" % (off, old, new, ok))
    return 0


if __name__ == "__main__":
    sys.exit(main())
