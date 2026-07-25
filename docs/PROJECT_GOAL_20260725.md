# Project Goal — Redefined 2026-07-25

## 最终目标（唯一焦点）

**完美脱壳以下两个样品**（结构 + 加载 + 行为等价 + 可复现，无绕过补丁）：

| 样品 | case_id | 保护族 | 路径 | manifest SHA-256 |
|------|---------|--------|------|------------------|
| 时光一键宏.exe | `origin_macro` | oreans_candidate (Themida) | `D:\Tools\RE\dumps\new\时光一键宏.exe` | `1af62999cf5be0b2f21abc39034c122a42aa46cfbfdb546faa184de37ac09ac7` |
| 启动器.exe | `gto_launcher` | ahk_gto_candidate (AHK 启动器) | `D:\Tools\RE\dumps\gto\启动器.exe` | `4d5770afdd2f6d9553fef66826c5a55211b80d8d174360a115f247efafb037c8` |

此目标取代此前 D1–D8/Q1–Q7 的"4 案 + multi-family"通用化叙事。
Lunlun / Xiongxiong 不再是 1.0 门禁样品（降为回归对照）。

## "完美脱壳"的可操作定义（对这两个样品）

对每个样品，以下全部成立且**无样本特化绕过补丁**：

1. **结构**：独立 `mida-acceptance` R0B = `StructuralPassBehaviorPending`（已达标，两案）。
2. **加载**：OS loader 加载、不崩；attempt=1 隔离运行 10× = 10/10（已达标，两案）。
3. **行为等价**：解包候选与受保护输入在受控探针下行为一致：
   - UI 出现、控件可驱动、产品逻辑响应相同（license 校验 / 脚本加载 / 窗口创建路径）。
   - **判定标准 = 同一 oracle 在受保护输入与解包候选上双侧 Pass 且响应一致。**
4. **可复现**：固定输入 → 当前 CLI 重新解包 → 上述全复现（不依赖历史 pin）。
5. **无绕过补丁**：解包候选中不得存在"跳过产品代码 / 硬塞结果 / 强制可见"的样本特化字节补丁。允许：通用还原修复（CS re-init、stale-pointer scrub、clear-regs、IAT/relloc/TLS 一致性）——这些是还原，不是绕过。

## 当前距离（2026-07-25）

### 时光一键宏.exe（origin_macro）— **接近**

- 结构 / 加载 / 10× / 业务行为（license 拒绝路径 N=3 双侧等价）/ 零绕过补丁：**全部已达标**。
- **唯一缺口**：valid-code 接受路径（输对授权码 → 授权通过 → 产品完整可用）。需有效授权码或可接受的产品功能探针才能证明。拒绝路径已等价。

### 启动器.exe（gto_launcher）— **远**

- 结构 / 加载 / 10×：达标（clearregs 是还原，非绕过）。
- **窗类 NewClassName 靠 5 个 r26b 绕过补丁伪造**：跳 LoadFile、跳 MessageBox、硬塞 NewClassName、强加 WS_VISIBLE、跳 msg-loop AV。脚本没真跑。
- **缺口**：撤掉全部绕过补丁后，产品代码自然运行到出 UI 且 AHK 脚本引擎能加载/执行。这是 r1–r26 未解的 heap/script resume 根因，研究级。

## 纪律（沿用）

- 一次只开一个样品的主战场；exit 未过不开下一场。
- 每战场最多 2 轮「改代码→rebuild→复测」；仍失败写 residual 停手，不无限磨。
- 先量后改；先只读根因再动代码。
- 不假 1.0；两案全部达标前语言仍是"工程进展/证据"。
- 受保护输入的参考行为优先；解包候选必须复现参考行为，不是复现探针期望值。
