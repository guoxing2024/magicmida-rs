# XX-11-B 管线修复报告（裁决书 #17）

> **批次**: XX（2026-08-28）
> **执行**: worker-J（管线修复单，不计格）
> **基线**: `68109ba` + XX-11-A 取证（无代码改动）
> **修复**: OEP scan prologue 回溯（`find_real_oep_by_scanning`）

## 一、缺陷根因（XX-10 AV 真相）

裁决书 #16 质疑命中：XX-10 候选 0/10 AV 非 wininet 内部错位，而是**管线 OEP 缺陷**。

**证据链**（XX-11-A 取证，`XX11A_EP_ALIGNMENT_EVIDENCE.json`）：

| 测量点 | rsp mod 16 | 正确值 |
|---|---|---|
| PE EP=0x1020（`mov eax,0x30` CRT 内部）| 8 | 8（loader 正确）|
| `0x2144` call 0x1690 前 | **8** | 0 ❌ |
| `0x16c5` call InternetOpenA 前 | **8** | 0 ❌ |
| `_tailMerge_iertutil_dll` 入口 | **0** | 8 ❌ |

**根因**：候选 RVA `0x1010` 才是真实函数入口（8 push + `sub rsp,0x58` 完整 prologue），
而 `find_real_oep_by_scanning` 的通用 prologue 检测选中了 `0x1020`（prologue **之后**的第一条指令）。

**PE EP 写为 0x1020 → 跳过 0x1010-0x101c 的 8 push + sub → 整个进程从启动起栈错位 8 字节**
→ wininet 冷启动路径 `movdqa [rsp+20h]` SSE AV（第一个 SSE 踩雷点）。

**修复验证**（决定性对照）：
- EP=0x1020（缺陷）：2× AV（wininet movdqa），瞬间崩溃
- EP=0x1010（补丁）：**0 AV，进程存活 90s+**（timeout 终止，正常运行）

## 二、修复内容

### `crates/packers/themida/src/oep/mod.rs`

1. **`backtrack_to_function_start(text_buf, scan_hit)`**（新增纯函数）：
   - 从扫描命中点回溯，识别 push 序列（`0x53/55/56/57` 或 `41 54..57`）+ 结尾 `48 83 EC imm8` / `48 81 EC imm32`
   - 起点验证：push 序列前一字节为 `ret(0xC3)/int3(0xCC)/nop(0x90)/nop-prefix(0x0F)` 或节首
   - **保守原则**：边界不可证明 → 维持原命中点 + `Uncertain`（绝不猜）

2. **`BacktrackDecision`** 枚举：
   - `AlreadyStart`：命中点已是函数起点
   - `Backtracked { scan_hit, reason }`：回溯到 prologue 起点
   - `Uncertain { scan_hit }`：边界不可证明，维持命中点

3. **`find_real_oep_by_scanning_with_backtrack`**（新增导出）：
   - 返回 `OepScanOutcome { final_oep, scan_hit, backtrack }`，供 sidecar 记录
   - 原 `find_real_oep_by_scanning` 委托保留（4 处调用点兼容）

4. **`push_run_start`**（重写）：正向识别 push 序列，修复反向回走对 `41 54..57` reg 字节的误判

### `crates/cli/src/unpacker/mod.rs`（主调用点）

- 改用 `find_real_oep_by_scanning_with_backtrack`
- sidecar evidence 记录 `oep_backtrack=backtracked|already_start|uncertain` + `scan_hit_rva` + `final_oep_rva`

### `crates/packers/themida/src/lib.rs`

- 导出 `find_real_oep_by_scanning_with_backtrack`

## 三、回归保护

- **XX-10 现场向量**：`0x1010` prologue 字节序列（`41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC 58`）入库为固定测试向量
- **5 个新测试**：
  - `xx11b_backtrack_from_hit_inside_prologue`（命中 0x1020 → 回溯 0x1010）
  - `xx11b_backtrack_when_hit_is_sub_itself`（命中 0x101c → 回溯 0x1010）
  - `xx11b_already_at_function_start`（命中 0x1010 → 不调整）
  - `xx11b_conservative_when_boundary_unprovable`（边界不可证明 → 维持 + Uncertain）
  - `xx11b_rev1_golden_path_unchanged`（rev1 金标准 `sub rsp,0x28` 路径不被破坏）
- **rev1 ×10 绿路径**：rev1 OEP 命中逻辑（MSVC `E8..E9` / `mov ebp,esp` 模式）未改动

## 四、红线验收

| 红线 | 基线 | 当前 | 状态 |
|---|---|---|---|
| 测试 ≥2761 绿 | 2761 | **2769 绿 0 失败** | ✅ |
| clippy ≤349 | 349 | **348** | ✅ |
| 不触碰 IAT/trace/dump 语义 | — | 仅改 OEP scan 路径 | ✅ |

## 五、XX-11 attempt（7/8）预授权

1. 重 dump（EP 修复后，`oep_backtrack=backtracked` sidecar 记录）
2. 结构门 12/12 + **正常环境 load_no_crash ×10**（EP 对齐正确，wininet 冷启动应存活——XX-10 90s 存活对照已预演）
3. ×10 ≥9/10 → S4 业务标记对齐（候选 vs 原版 5/5 标记集，联网分支差异如实记录）
4. S4 对齐 → 战役收官终审材料报总指挥
