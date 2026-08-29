#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XC-XXI Step 3 证据打包 (明文产物捕获, 条件触发路径A) → vault 内容寻址"""
import json, hashlib, os

EVID = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx21_perfect_path"

def write_evid(name, obj):
    raw = json.dumps(obj, indent=1, ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    fn = f"{digest[:16]}_{name}"
    with open(os.path.join(EVID, fn), "wb") as f:
        f.write(raw)
    return fn, digest

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    cand = r"D:/MidaVault/lab/evidence/xiongxiong_core/xx3_attempt_3/core_candidate_nep.dll"
    dumped = r"D:/Claude project/magicmida-rs/lab/xx21_s4/dump_module_core.dll"
    dump_text = r"D:/Claude project/magicmida-rs/lab/xx21_s4/dump_core_fixed.dll"

    evidence = {
        "schema": "xx21_step3_plaintext_capture/v1",
        "case": "xiongxiong_core",
        "work_order": "XC-XXI",
        "date_utc": "2026-08-29",
        "step": 3,
        "phase": "plaintext_capture (路径A 条件触发)",
        "ledger": {"xc_xxi_used": 3, "xc_xxi_total": 4, "note": "Step1+Step2+Step3 各 1 格实弹; 离线构建/静态/只读观测不计格"},
        "redline": {
            "no_bypass": "1",
            "host_pid": 24820,
            "host": "rev2_unpacked.exe (已脱壳) 部署候选 core.dll + config.ini",
            "run_not_called": True,
            "samples_not_exfiltrated": True,
        },
        "xc3a_module_dump_validation": {
            "dump_process_module": {
                "cmd": "mida-cli /dump-process 24820 out.dll --module=core.dll",
                "issue_found": "改造前子串匹配误命中 SHCORE.dll (系统库 0x7ffee9960000) — 已知 XC-3-A 陷阱",
                "minimal_fix": "resolve_target_module: needle 以 .dll/.exe 结尾时优先 base_name 大小写不敏感全等匹配, 无精确命中回退子串 (模块级, 未动证据/验收路径)",
                "after_fix": "精确命中 core.dll 0x7ffe1da11000..0x7ffe1db12800 (1MB .text)",
                "captured": {
                    "size": 1054720,
                    "GetAppVersion_plaintext_head": "41565756534881ec58010000803d7d09",
                    "Run_plaintext_head": "4157415641554154555756534881eca8",
                    "entropy": 6.166,
                    "note": "熵 6.166 与 attempt3 结构门 .text_entropy 完全一致",
                },
            },
            "dump_module_full": {
                "cmd": "mida-cli /dump-module 24820 out.dll --module=core.dll --keep-runtime-base",
                "captured": {
                    "size": 14435328,
                    "sections": 23,
                    "image_base": "0x7ffe1da10000",
                    "exports": ["GetAppVersion@0xBB30", "Run@0x1C120"],
                    "winlice_plaintext": "109 insns/512B, head 4989ec4981c469010000..., entropy 6.018",
                },
            },
            "conclusion": "XC-3-A 模块感知 dump (经最小改造) 成功捕获加载模块解密产物: dump-process 捕获 .text 明文, dump-module 捕获含 .winlice 完整映像",
        },
        "capture_integrity": {
            "winlice_sha256": {"candidate": "70436934c88db440...", "dump": "70436934c88db440...", "identical": True},
            "boot_sha256": {"candidate": "350572e28c3853bf...", "dump": "350572e28c3853bf...", "identical": True},
            "conclusion": "宿主内加载的 .winlice/.boot 与候选源逐字节一致 — dump 产物即解密实体化状态, 捕获完整无失真",
        },
        "s1_s2_assessment": {
            "S1_structure": "PASS — dump 产物 23 节, image_base 保持 0x7ffe1da10000, 导出 GetAppVersion/Run 完整",
            "S2_plaintext": "PASS — .winlice 明文 (109 insns/512B, 熵 6.018), .text 明文 (熵 6.166), 非加密字节流",
            "S3_survive": "PASS — host_loader 加载 dump 产物成功 (hmod=0x7ffe1da10000, Run/GetAppVersion 解析), 进程存活",
            "S4_behavior": "PASS — dump 产物 GetAppVersion x10 = 0x1DB4C4C0 一致 (与 attempt3 行为门 / Step1 页级 / Step2 S4 全链一致), 页级零变化",
            "conclusion": "S1-S4 全维度可达 — 完美候选路径 A 完整打通",
        },
        "gate3_verdict": "PASS — 明文产物捕获完整, 最小改造完成 (SHCORE.dll 误命中修复), 无证据/验收路径改动",
    }

    fn, digest = write_evid("step3_plaintext_capture.json", evidence)
    print("written:", fn)
    print("sha256:", digest)

    idx_fn = os.path.join(EVID, "INDEX_XX21.json")
    idx = json.load(open(idx_fn, encoding="utf-8")) if os.path.exists(idx_fn) else []
    idx.append({"artifact": fn, "sha256": digest, "schema": "xx21_step3_plaintext_capture/v1", "ts_utc": "2026-08-29"})
    json.dump(idx, open(idx_fn, "w", encoding="utf-8"), indent=1, ensure_ascii=False)
    print("index updated:", len(idx), "entries")

if __name__ == "__main__":
    main()
