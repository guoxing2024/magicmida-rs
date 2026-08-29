#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 1 证据打包: 离线静态分析 (门1 前置) → vault 内容寻址 JSON"""
import json, hashlib, datetime, os

EVID = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx21_perfect_path"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def write_evid(name, obj):
    raw = json.dumps(obj, indent=1, ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    fn = f"{digest[:16]}_{name}"
    with open(os.path.join(EVID, fn), "wb") as f:
        f.write(raw)
    return fn, digest

def main():
    base = json.load(open(r"D:/Claude project/magicmida-rs/tools/xx21_step1_static_out.json", encoding="utf-8"))
    deep = json.load(open(r"D:/Claude project/magicmida-rs/tools/xx21_step1_static_deep_out.json", encoding="utf-8"))
    cand_sha = "41ec52e085b258c1c0b993f7ced1f7ee6339e8883239ad8482aec3fc45f2a25e"

    # 提取关键结论
    summary = {
        "schema": "xx21_step1_static_evidence/v1",
        "case": "xiongxiong_core",
        "work_order": "XC-XXI",
        "date_utc": "2026-08-29",
        "step": 1,
        "phase": "offline_static",
        "candidate": {
            "path": r"D:/MidaVault/lab/evidence/xiongxiong_core/xx3_attempt_3/core_candidate_nep.dll",
            "sha256": cand_sha,
            "size_bytes": 14424064,
            "image_base": base["image_base"],
        },
        "exports": [
            {"name": e["name"], "rva": e["rva"], "va": e["va"]} for e in base["exports"]
        ],
        "callchain_findings": {
            "GetAppVersion_init_calls": {
                "0xbb9f_call": "0x1e918 (thunk, IAT 风格)",
                "0xbbb8_call": "0xff940 (明文函数)",
                "0xbbe4_call": "0x1e920 (thunk, IAT 风格)",
                "0xbc12_call": "0x1e910 (thunk, IAT 风格)",
            },
            "thunk_resolution": {
                "0x1e910": {"ptr_loc_rva": "0x142370", "target_rva": "0x350e62", "target_sec": ".winlice", "target_bytes": "e9ab554d00e9c5544e0008..."},
                "0x1e918": {"ptr_loc_rva": "0x142368", "target_rva": "0x2d1da4", "target_sec": ".winlice", "target_bytes": "e9255e5500e9901c2a004883c410..."},
                "0x1e920": {"ptr_loc_rva": "0x142360", "target_rva": "0x2b9a6d", "target_sec": ".winlice", "target_bytes": "e9c3785600e954ca5600c5a7..."},
            },
            "conclusion": "GetAppVersion 初始化路径的间接调用 thunk 全部解析到 .winlice 节内部明文代码区 (VM handler 域), 调用链确认经 .winlice",
        },
        "winlice_state": {
            "rva": "0x198000",
            "size": 7372800,
            "section_chars": "0xe0000060",
            "file_first_bytes": "4989ec4981c4690100004889ea4881c2cc000000488b12...",
            "decodable_first_512_bytes": "109 insns / 512 bytes (标准 x64 序言)",
            "entropy_avg_first_64k": deep["winlice_entropy_avg_first64k"],
            "conclusion": ".winlice 在候选 dump 产物中已是实体化明文代码 (非加密字节流) — 离线证据指向「运行时解密实体化」",
        },
        "boot_state": {
            "rva": "0x8a0000",
            "first_bytes": "eb4417843af5c7d94dd2507bedf75d30",
            "conclusion": ".boot 仍为高熵加密态 (dump 未解密), 壳解密实体化范围不含 .boot",
        },
        "app_code_state": {
            "GetAppVersion_rva": "0xbb30",
            "head": "push r14; push rdi; push rsi; push rbx; sub rsp,0x158 (标准 x64 prologue, 明文)",
            "conclusion": "导出函数本址在候选 dump 产物中为明文 x64 代码",
        },
        "gate1_static_verdict": "callchain_through_winlice: CONFIRMED; 离线证据强指向路径A(运行时解密实体化); 待页级监控实弹确认",
    }

    fn, digest = write_evid("step1_offline_static.json", summary)
    print("written:", fn)
    print("sha256:", digest)

    # 附 raw 深数据副本 (引用完整)
    fn2, d2 = write_evid("step1_offline_raw_full.json", {"static": base, "deep": deep})
    print("raw written:", fn2, d2[:16])

    # 记录索引文件
    idx_fn = os.path.join(EVID, "INDEX_XX21.json")
    idx = []
    if os.path.exists(idx_fn):
        idx = json.load(open(idx_fn, encoding="utf-8"))
    idx.append({"artifact": fn, "sha256": digest, "schema": "xx21_step1_static_evidence/v1", "ts_utc": datetime.datetime.utcnow().isoformat() + "Z"})
    idx.append({"artifact": fn2, "sha256": d2, "schema": "xx21_step1_offline_raw_full/v1", "ts_utc": datetime.datetime.utcnow().isoformat() + "Z"})
    json.dump(idx, open(idx_fn, "w", encoding="utf-8"), indent=1, ensure_ascii=False)

if __name__ == "__main__":
    main()
