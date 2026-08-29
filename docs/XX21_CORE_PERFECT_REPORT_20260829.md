# XX21 CORE PERFECT — 判定实验报告

**工作单**: XC-XXI · core.dll 完美路径判定实验（连续单）
**执行**: worker-I · 2026-08-29 · NO_BYPASS=1 全程
**账本**: XC-XXI **3/4**（Step1 实弹 1 格 + Step2 实弹 1 格 + Step3 实弹 1 格；离线构建/静态/只读观测不计格）
**证据库**: `D:/MidaVault/lab/evidence/xiongxiong_core/xx21_perfect_path/`（内容寻址，INDEX_XX21.json 索引）

---

## 0. 输入资产核实（红线前置）

| 资产 | 核实 |
|---|---|
| 候选 `core_candidate_nep.dll` | ✅ sha256 `41ec52e0...` 与 attempt3 manifest `sha256_nep` 前缀一致 |
| 已脱壳宿主 `rev2_unpacked.exe` | ✅ sha256 `36043cb4...` |
| 原版宿主 | ✅ 工作单路径 `xiongxiong.exe` 实为 `熊熊.exe`（sha256 `7800980301...` = 特征化 rev2 EXE） |
| config.ini | ✅ `[Loader] DllVersion=1.1` |
| 原版 core.dll | ✅ sha256 `09f3dd3442...` 与特征化文档样品一致 |

---

## Step 1 — VM 机制判定（门 1）→ **路径 A：运行时解密实体化**

### 1.1 离线静态
- 候选 image_base `0x7ffe1da10000`，GetAppVersion@0xBB30 / Run@0x1C120
- GetAppVersion 初始化路径（attempt4 指向 0x1e918/0xff940/0x1e920）确认：
  - `0xbb9f call 0x1e918`、`0xbbe4 call 0x1e920`、`0xbc12 call 0x1e910` 均为 **IAT 风格 thunk**（`jmp qword ptr [rip+disp]`）
  - thunk 指针解析（IAT 修复后值）**全部指向 .winlice 节内部**：
    - 0x1e910 → rva 0x350e62 (.winlice, off 1805922) `e9 ab 55 4d 00...`
    - 0x1e918 → rva 0x2d1da4 (.winlice, off 1285540) `e9 25 5e 55 00...`
    - 0x1e920 → rva 0x2b9a6d (.winlice, off 1186413) `e9 c3 78 56 00...`
  - **结论：GetAppVersion 初始化调用链确实经 .winlice VM handler 区域**
- .winlice 在候选 dump 产物中**已是明文可解码代码**（前 512B 109 条指令、标准 x64 序言 `49 89 ec 49 81 c4 69 01...`，熵抽样 6.018）；.boot 仍高熵加密（`eb 44 17 84...`）

### 1.2 页级监控实弹（1 格）
宿主 = 独立进程 `xx21_monitor.exe`（LoadLibraryW 候选 → before 快照 → GetAppVersion×10 → after 快照，逐 4KB 页 sha256）：

| 目标区 | 页数 | 调用前后变化 | 明文启发 |
|---|---|---|---|
| .text(anon) | 258 | **0** | 54 页 |
| .winlice | 1800 | **0** | 118 页 |
| .boot | 1298 | **0** | 43 页 |

- 基址精确命中 `0x7FFE1DA10000`；GetAppVersion×10 = `0x1DB4C4C0` 全一致（与 attempt3 行为门吻合）
- python.exe 内加载被 rebase（`0x171A8120000`）→ 硬编码地址失效 AV（退出码 3）——**证实固定基址约束**，独立宿主进程方案必要

### 1.3 门 1 判定
**路径 A（运行时解密实体化）**。依据：
1. 实体化发生在加载/DllMain 期：壳把 VM 代码解密为明文写入 .winlice，dump 产物保留明文
2. 调用导出时 CPU 直接执行明文原生代码，**无解释器循环特征**（若有纯解释执行，.winlice 应为加密字节流由 handler 消费，实测为原生明文且被直接执行）
3. 调用前后 3356 页零变化 = 无调用期新解密（实体化已完）

> 排除 B1（纯解释执行）→ 不判死，转 Step 2。

---

## Step 2 — S4 宿主补测（门 2）→ **PARTIAL（GetAppVersion 链 FULL）**

### 2.1 构建核实
- 手动 MSVC 环境：`CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER` 指向 `VS2022/VC/Tools/MSVC/14.44.35207/.../link.exe` + `LIB/INCLUDE` Windows 分号格式 + `CARGO_INCREMENTAL=0`（VsDevCmd 被沙箱拦，走记忆方案）
- mida-cli 重建成功（02:15）；xx21_monitor 构建成功

### 2.2 实弹（1 格）
- 部署：`rev2_unpacked.exe` + 候选 `core.dll` + `config.ini [Loader] DllVersion=1.1`，NO_BYPASS=1 启动 → 进程存活（PID 24820, responding=True, GUI）
- 观测（ReadProcessMemory，固定基址直读）：
  - **加载成功**：MZ/PE 头在 `0x7FFE1DA10000` 有效，runtime_image_base 精确命中
  - **导出解析**：GetAppVersion@0xBB30 / Run@0x1C120
  - **GetAppVersion 本址明文**：`41 56 57 56 53 48 81 ec 58 01 00 00...`（标准 x64 prologue，解密保持）
- **业务调用链远程触发**：CreateRemoteThread 调 GetAppVersion ×3 → 全部返回 `0x1DB4C4C0`，**非 AV**，与 expected 一致

### 2.3 config 语义
`[Loader] DllVersion=1.1` 协作入口满足——宿主加载 core.dll 即满足；rev2_unpacked.exe 无静态 core.dll 导入（动态 LoadLibrary，与壳态宿主同构）。

### 2.4 S4 verdict
```
verdict: PARTIAL (GetAppVersion 链 FULL)
reason : GetAppVersion 完整业务调用链验证通过 (加载+导出解析+真实调用返回 0x1DB4C4C0 ×3 非 AV,
         config 语义满足); Run 未验证 — 红线: urlmon.URLDownloadToFileA 网络外发约束, 对齐
         attempt3 决策 (Run 不触发)。
gate2  : 相比 attempt4 (壳态宿主 PARTIAL-EXE壳态) 实质升级: 宿主脱壳后导出调用真实返回验证通过。
         不构成路径阻断 — 完美路径 A 条件保持成立, 转 Step 3。
```

---

## Step 3 — 明文产物捕获（条件触发，路径 A）→ **PASS，S1-S4 全可达**

### 3.1 XC-3-A 模块感知 dump 验证 + 最小改造
- **缺陷复现**：改造前 `--module=core.dll` 子串匹配误命中 **SHCORE.dll**（系统库 0x7ffee9960000，dump 634880B）
- **最小改造（模块级，未动证据/验收路径）**：`crates/cli/src/unpacker/dump.rs::resolve_target_module` 当 needle 以 `.dll/.exe` 结尾时优先 `base_name.eq_ignore_ascii_case(needle)` 精确匹配，无精确命中回退子串。两个命令（/dump-process、/dump-module）共用此函数，一并修复
- **改造后**：`/dump-process 24820 out.dll --module=core.dll` 精确命中 core.dll（`0x7ffe1da11000..0x7ffe1db12800`，1MB .text）

### 3.2 捕获结果
| 工具 | 产物 | 关键证据 |
|---|---|---|
| /dump-process --module=core.dll | 1,054,720 B .text | GetAppVersion 序言 `41 56 57 56...` 与宿主内存一致；熵 **6.166** = attempt3 结构门同值 |
| /dump-module --module=core.dll --keep-runtime-base | 14,435,328 B / 23 节 | 导出完整；.winlice 明文 109 insns/512B，head `49 89 ec...` 与 Step1 静态逐字节一致 |

### 3.3 捕获完整性（内容寻址对照）
| 节 | 候选源 sha256 | dump 捕获 sha256 | 一致 |
|---|---|---|---|
| .winlice (7,372,800 B) | 70436934c88db440... | 70436934c88db440... | ✅ True |
| .boot (5,315,072 B) | 350572e28c3853bf... | 350572e28c3853bf... | ✅ True |

### 3.4 S1-S4 评估（完美候选对照）
- **S1 结构 PASS**：23 节，image_base 保持 `0x7ffe1da10000`，导出完整
- **S2 明文 PASS**：.winlice 明文（熵 6.018）、.text 明文（熵 6.166），非加密字节流
- **S3 存活 PASS**：host_loader 加载 dump 产物成功（hmod=0x7ffe1da10000，Run/GetAppVersion 解析），进程存活
- **S4 行为 PASS**：dump 产物 GetAppVersion×10 = `0x1DB4C4C0` 全一致，页级零变化（与 attempt3 行为门 / Step1 / Step2 全链闭环）

---

## 账本消耗

| 项 | 消耗 |
|---|---|
| XC-XXI 总格 | 4 |
| Step 1 实弹（页级监控） | 1 |
| Step 2 实弹（S4 宿主补测） | 1 |
| Step 3 实弹（dump 产物行为） | 1 |
| **used / total** | **3 / 4**（1 格未用） |

离线构建（mida-cli/xx21_monitor）、离线静态、只读观测（ReadProcessMemory/dump）不计格。

---

## 总判定

**路径 A 完美打通**：
- 门1：运行时解密实体化（非纯解释执行）✅
- 门2：S4 PARTIAL（GetAppVersion 全链 FULL；Run 受红线约束未触发）✅ 不阻断
- 门3：明文产物捕获完整（最小改造修复 SHCORE.dll 误命中），S1-S4 全维度可达 ✅

**阻塞点 / 遗留**：
1. **Run 业务链未验证**——红线（urlmon.URLDownloadToFileA 网络外发）约束，对齐 attempt3 决策；如需补测需 owner 明确豁免网络外发红线后单独授权
2. 固定基址约束（0x7FFE1DA10000）——换机器/重启需重跑 dump（XC-6-A 方案 B 已知 tradeoff）
3. 完美候选交付（S1-S4 达标产物）未在本工作单产出——本单判定"可达"，产物化属后续工作单

**证据索引**：`INDEX_XX21.json`（5 条内容寻址证据）
- `318ddf73..._step1_offline_static.json` + `192958ea..._step1_offline_raw_full.json`
- `2de341b5..._step1_live_pagemonitor.json`
- `c595805c..._step2_s4_host.json`
- `4bf026a5..._step3_plaintext_capture.json`

*worker-I · XC-XXI 连续执行完成 · 2026-08-29*
