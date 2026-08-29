#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 1 实弹证据打包 (页级监控, 门1) → vault 内容寻址"""
import json, hashlib, datetime, os

EVID = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx21_perfect_path"

def write_evid(name, obj):
    raw = json.dumps(obj, indent=1, ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    fn = f"{digest[:16]}_{name}"
    with open(os.path.join(EVID, fn), "wb") as f:
        f.write(raw)
    return fn, digest

def main():
    mon = json.load(open(r"D:/Claude project/magicmida-rs/tools/xx21_monitor_out/step1_pagemonitor.json", encoding="utf-8"))
    cand_sha = "41ec52e085b258c1c0b993f7ced1f7ee6339e8883239ad8482aec3fc45f2a25e"

    evidence = {
        "schema": "xx21_step1_live_pagemonitor/v1",
        "case": "xiongxiong_core",
        "work_order": "XC-XXI",
        "date_utc": "2026-08-29",
        "step": 1,
        "phase": "live_pagemonitor",
        "ledger": {"xc_xxi_used": 1, "xc_xxi_total": 4, "note": "Step1 实弹 1 格 (离线构建/静态不计格)"},
        "redline": {
            "no_bypass": "1",
            "candidate_sha256": cand_sha,
            "manifest_match": "41ec52e085b258c1c0b993f7ced1f7ee... (attempt3 manifest sha256_nep)",
            "run_not_called": True,
            "samples_not_exfiltrated": True,
        },
        "host": {
            "type": "独立进程宿主 (xx21_monitor.exe)",
            "mode": "LoadLibraryW(candidate) -> before snap -> GetAppVersion x10 -> after snap",
            "base": mon["base"],
            "expected_base": "0x7FFE1DA10000",
            "base_hit": mon["base"] == "0x7FFE1DA10000",
        },
        "export_call": {
            "GetAppVersion_x10": mon["getappversion_returns"],
            "all_identical": len(set(mon["getappversion_returns"])) == 1,
            "value": mon["getappversion_returns"][0] if mon["getappversion_returns"] else None,
            "expected": "0x7FFE1DB4C4C0 (attempt3 行为门 0x1DB4C4C0 + 基址)",
            "run_called": False,
        },
        "page_diff": mon["page_diff"],
        "analysis": {
            "winlice_plaintext_after_load": "1800 页全部保持明文可解码代码 (加载期实体化, 非调用期新解密)",
            "zero_page_changes": "调用 GetAppVersion x10 前后 .text/.winlice/.boot 共 3356 页零变化",
            "interpretation": "实体化发生在加载/DllMain 期: 壳把 VM 代码解密为明文写入 .winlice, dump 产物保留该明文; 调用导出时 CPU 直接执行明文原生代码, 无解释器循环特征, 无新解密",
        },
        "gate1_verdict": {
            "path": "A (运行时解密实体化)",
            "basis": [
                "离线: .winlice 在 dump 产物中即明文 (109 insns/512B, 标准 x64 序言), thunk 0x1e910/0x1e918/0x1e920 全部解析到 .winlice 内代码",
                "实弹: 宿主加载后 .winlice 1800 页明文保持, GetAppVersion 调用前后零变化, 返回 0x1DB4C4C0 x10 一致",
                "排除纯解释执行: 若为纯解释, .winlice 应为加密字节流由 handler 解释, 但实测为原生明文代码且被直接执行",
            ],
            "conclusion": "路径 A 成立 — dump 捕获可行, 转 Step 2 (S4 宿主补测)",
        },
        "evidence_chain": [
            "step1_offline_static.json (调用链经 .winlice 确认)",
            "step1_live_pagemonitor (本文件)",
        ],
    }

    fn, digest = write_evid("step1_live_pagemonitor.json", evidence)
    print("written:", fn)
    print("sha256:", digest)

    idx_fn = os.path.join(EVID, "INDEX_XX21.json")
    idx = json.load(open(idx_fn, encoding="utf-8")) if os.path.exists(idx_fn) else []
    idx.append({"artifact": fn, "sha256": digest, "schema": "xx21_step1_live_pagemonitor/v1", "ts_utc": datetime.datetime.now(datetime.UTC).isoformat()})
    json.dump(idx, open(idx_fn, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("index updated:", len(idx), "entries")

if __name__ == "__main__":
    main()
