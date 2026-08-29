#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 2 证据打包 (S4 宿主补测, 门2) → vault 内容寻址"""
import json, hashlib, os

EVID = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx21_perfect_path"

def write_evid(name, obj):
    raw = json.dumps(obj, indent=1, ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    fn = f"{digest[:16]}_{name}"
    with open(os.path.join(EVID, fn), "wb") as f:
        f.write(raw)
    return fn, digest

def main():
    observe = json.load(open(r"D:/Claude project/magicmida-rs/lab/xx21_s4/s4_observe.json", encoding="utf-8"))
    remotecall = json.load(open(r"D:/Claude project/magicmida-rs/lab/xx21_s4/s4_remotecall.json", encoding="utf-8"))

    evidence = {
        "schema": "xx21_step2_s4_host/v1",
        "case": "xiongxiong_core",
        "work_order": "XC-XXI",
        "date_utc": "2026-08-29",
        "step": 2,
        "phase": "s4_host_recheck",
        "ledger": {"xc_xxi_used": 2, "xc_xxi_total": 4, "note": "Step1 实弹 1 格 + Step2 实弹 1 格 (离线构建/静态/观测不计格)"},
        "redline": {
            "no_bypass": "1",
            "candidate_sha256": "41ec52e085b258c1c0b993f7ced1f7ee6339e8883239ad8482aec3fc45f2a25e",
            "manifest_match": True,
            "deployment": {
                "host": "rev2_unpacked.exe (已脱壳, sha256 36043cb4e82a500d...)",
                "core_dll": "候选 core_candidate_nep.dll → 部署名 core.dll",
                "config_ini": "[Loader] DllVersion=1.1",
            },
            "run_not_called": True,
        },
        "host_lifecycle": {
            "pid": observe["host_pid"],
            "alive": True,
            "responding": True,
            "note": "已脱壳宿主 rev2_unpacked.exe 部署候选 + config.ini, NO_BYPASS=1 启动后持续存活 (GUI 程序)",
        },
        "load_and_exports": {
            "loaded_at_fixed_base": observe["load_check"]["loaded_at_fixed_base"],
            "mz_pe_valid": observe["load_check"]["pe_valid"],
            "runtime_image_base": observe["pe"]["runtime_image_base"],
            "exports": observe["exports"],
            "GetAppVersion_plaintext_bytes": observe["getappversion"]["bytes"],
            "GetAppVersion_plaintext_prologue": observe["getappversion"]["plaintext_prologue"],
            "conclusion": "已脱壳宿主成功加载候选 core.dll (固定基址 0x7FFE1DA10000), 导出 GetAppVersion@0xBB30/Run@0x1C120 解析成功, GetAppVersion 本址明文 x64 序言",
        },
        "business_call_chain": {
            "GetAppVersion_remote_calls": remotecall["calls"],
            "all_match_expected": remotecall["verdict"]["all_match_expected"],
            "any_av": remotecall["verdict"]["any_av"],
            "expected_value": "0x1DB4C4C0 (attempt3 行为门同值)",
            "Run_called": False,
            "Run_reason": "红线: urlmon.URLDownloadToFileA 在导入面, 主动调用有网络外发风险; 对齐 attempt3 决策 (Run 不触发)",
        },
        "config_semantics": {
            "config_ini": "[Loader] DllVersion=1.1",
            "satisfied": True,
            "note": "宿主加载 core.dll 即满足 [Loader] 协作入口; DllVersion=1.1 语义由宿主业务处理",
        },
        "s4_verdict": {
            "verdict": "PARTIAL (GetAppVersion 链 FULL)",
            "reason": "GetAppVersion 完整业务调用链验证通过 (加载+导出解析+真实调用返回 0x1DB4C4C0 x3 非 AV, config 语义满足); Run 未验证 — 红线网络外发约束 (urlmon.URLDownloadToFileA), 对齐 attempt3 决策。相比 attempt4 (壳态宿主 PARTIAL-EXE壳态) 已实质升级: 宿主脱壳后导出调用真实返回验证通过",
            "gate2": "不构成路径阻断 (宿主集成关键环节全通); 完美路径 A 条件保持成立",
        },
    }

    fn, digest = write_evid("step2_s4_host.json", evidence)
    print("written:", fn)
    print("sha256:", digest)

    idx_fn = os.path.join(EVID, "INDEX_XX21.json")
    idx = json.load(open(idx_fn, encoding="utf-8")) if os.path.exists(idx_fn) else []
    idx.append({"artifact": fn, "sha256": digest, "schema": "xx21_step2_s4_host/v1", "ts_utc": "2026-08-29"})
    json.dump(idx, open(idx_fn, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("index updated:", len(idx), "entries")

if __name__ == "__main__":
    main()
