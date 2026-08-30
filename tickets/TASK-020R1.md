# TASK-020R1 — 清洗基址纠正（微型补正，纯离线零实弹，不烧格）

✅ **已授权（在 D-039 授权范围内，无新令牌不烧格）**：总指挥审计 TASK-020（D-040）判定执行纪律全 PASS，但**补丁目标基址错误**——责任在总指挥：D-038 把宿主 `.bss` 值 `0x7ffd37ae6390` 错误分解为"基址 `0x7ffd37ae0000` + 0x106390"，worker 采信该记录导致 7 个 ntdll 槽全部 +0x100000。worker 报告 §9 的"实测差 0x100000"备注即此错误的报警（其对差异的解释——"Windows 对 ntdll 做进程级随机化"——不成立：T015/T017/T018 的宿主进程在本 boot 全部以 ntdll=0x7ffd379e0000 存活，见 D-040 四重验证）。

## 正确基址（总指挥四重验证，worker 不得另测）

**当前会话 ntdll = `0x7ffd379e0000`**。验证源：① 总指挥本机 python 实测（EnumProcessModulesEx）= `0x7ffd379e0000`，kernel32 = `0x7ffd36600000`；② 宿主 a852880a `.bss 0x112c10` 值 `0x7ffd37ae6390` − 文档化偏移 0x106390 = `0x7ffd379e0000`；③ T019 泵事件流首个 LOAD_DLL（ntdll）= `0x7ffd379e0000`；④ T018 RIP 样本 `0x7ffd37b44680`（owner=ntdll.dll）− `0x7ffd379e0000` = 0x164680 ∈ ntdll 映像范围。

## 任务（全部在副本上做，vault 原件 3650ea6c 依旧只读一字节不动）

1. **重补 7 个 ntdll 槽**：从 vault 原件取**全新副本**重做（或对现有副本回滚后重做），基址参数 = `0x7ffd379e0000`。**期望逐槽值（总指挥已算好，worker 逐一核对）**：

   | 文件偏移 | 原值（旧会话） | 正确新值 | 偏移 |
   |---|---|---|---|
   | 0x13f808 | 0x7ffeeb4279a0 | **0x7ffd37ae79a0** | 0x1079a0 |
   | 0x13f810 | 0x7ffeeb426390 | **0x7ffd37ae6390** | 0x106390 |
   | 0x141bf8 | 0x7ffeeb347610 | **0x7ffd37a07610** | 0x27610 |
   | 0x141c10 | 0x7ffeeb3612f0 | **0x7ffd37a12f0** | 0x412f0 |
   | 0x141d30 | 0x7ffeeb34de50 | **0x7ffd37a0de50** | 0x2de50 |
   | 0x141d48 | 0x7ffeeb3613f0 | **0x7ffd37a13f0** | 0x413f0 |
   | 0x141e48 | 0x7ffeeb3c09e0 | **0x7ffd37a809e0** | 0xa09e0 |

   urlmon 槽 0x1b41e8（`0x7ffec48f0000` → `0x7ffd10050000`）**已验证正确，保持不动**。
2. **非对齐普查（补 TASK-020 漏项）**：全文件**非对齐**扫描旧 ntdll 死区间 [0x7ffeeb320000, +0x300000) 与旧 urlmon 死区间——总指挥已探得 **13 个非对齐残留（全部在 `.winlice` 保留壳区）**。R1 处置 = **全部列入 pointer_map 的 `residual_unpatched`（不补丁）**：.winlice 是保留壳区（休眠），盲改 VM 区内值有破坏编码风险；若 T0.5 三态重跑再爆且地址落在这些残留内，凭证据逐个处理。
3. **重验证**（与 TASK-020 同标准）：补丁最小性对账（预期仍 8 槽、每槽 ≤3 字节差异——基址低字节变化不同，以实际 diff 为准）、对齐 A 类复扫归零、结构/导出/`.text` 完好、vault 原件 sha 不变、pointer_map 更新（新值 + residual_unpatched 段）。
4. **零实弹**（不启动任何进程）、git 只读、临时文件逐个删除、`crates/` 零改动。

## 交付物

- 更新后的 `lab/xx21b_pcell_clean/core_perfect_candidate_cleaned.dll` + `pointer_map.json`（含 residual_unpatched 段）
- `runs/20260830-TASK-020.md` 末尾增补"TASK-020R1 补正"段（令牌回抄引用本票号 + 逐槽对照 + 验证原始输出）
- 工作区留改动，**不提交**。
