# GTO 线终局定性报告（WO-801，选项 B 收官）

**签发依据**: 批次 8 工单 WO-801 + 战略裁决（WO-703 ACCEPTED, Round 2 不授予, 选项 B 生效）
**性质**: docs-only 综合定性 — 全弧线证据链收口
**执行**: 唯一 worker · 2026-08-22
**状态**: TERMINAL — dump 式脱壳结构性不可达（分级措辞）

---

## 一、全弧线时间线（r27 → 终局）

| 阶段 | 关键事件 | 证据 |
|---|---|---|
| r27（历史） | 26 轮 UI 剥离；GTO 主线的启动器样本研究起点 | WORKER_HANDOFF（历史条目） |
| Route A–H | GTO 恢复尝试的多条路线；冷启动堆重定基为主线 | archive/routes/（治理存档） |
| H0–H6 门控 | H0 边界 → H1 故障时间线 → H2 重定基原语 → H3 吸收 → H4-A/B/C/D 签核 → H5 墙 | docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md |
| ADR7/B4/B5 | Oreans 回归门 17/17 PASS（frozen）；B4/B5 正式签核 | docs/ADR7_CLOSEOUT_REPORT.md |
| WO-001→004 | 账本纠偏：真实阶段状态、测试基线精确化、根因调查 | 批次 2 文档 |
| WO-102/103 | H5 根因链（.rdata 内容=加密区快照）+ 修复路径设计 | docs/GTO_H5_LOADER_WALL_ROOT_CAUSE.md |
| H4-A/B/C | SMR/OEP/TLS 三阶段正式签核（owner 裁决） | docs/GTO_H4_ABC_FORMAL_SIGNOFF_20260821.md |
| LIVE-2 R1 | 再基线+测量：.rdata2 熵 7.878（密文确证），smoke 3/3 AV 复现 | docs/GTO_H5_LIVE2_R1_REPORT.md |
| LIVE-2 R2 | PostSelfDecrypt 60s 观察：熵全程恒定 → 惰性解密假设成立 | docs/GTO_H5_LIVE2_R2_REPORT.md |
| WO-601 | 壳归因：YARA 零厂商字符串、TLS 目录磁盘态密文、节名溯源 | docs/GTO_PACKER_ATTRIBUTION_REPORT.md |
| LIVE-3 R1 | 双相量化：覆盖率 4.26% 恒定、300s 零新增解密页 | docs/GTO_H5_LIVE3_R1_REPORT.md |
| **终局** | 选项 B 收官：dump 式天花板三重证据闭合 | 本报告 |

## 二、定量锚点表（全部实测，证据指针）

| 锚点 | 值 | 测量 | 证据 |
|---|---|---|---|
| .rdata0 密文熵 | **7.426** bits/byte（恒定） | LIVE-2 R1/R2 + LIVE-3 A 相 | LIVE2_R1 §三 / LIVE3_R1 §四 |
| .rdata2 密文熵 | **7.878** bits/byte（恒定） | 同上 | 同上 |
| .pdata 熵 | **7.896** bits/byte（恒定） | 同上 | 同上 |
| 被动等待（LIVE-2 R2） | 60s 观察窗**零解密**（熵无下降） | PostSelfDecrypt C3 | LIVE2_R2 §四/§五 |
| 真实运行（LIVE-3 R1） | 300s **零新增解密页**（t0=end 覆盖恒定） | 双相测量 | LIVE3_R1 §五 |
| unreadable | **0%**（708 条带全可读） | B 相扫描 | LIVE3_R1 §六 |
| .rdata2 覆盖率 | **4.26%**（16/376 恒定；16 条带为磁盘态 raw 数据，非解密产物） | B 相 | LIVE3_R1 §五/§六 |
| 60% 经济门差距 | **14 倍**（4.26% vs 60%） | 决策算式 | LIVE3_R1 §七 |
| loader smoke | 3/3 0xC0000005（r27 时代 9/9 同码） | LIVE-2 R1 | LIVE2_R1 §四 |

## 三、终局命题（分级措辞，每条挂证据）

**命题**: suspected-SecureEngine-class 保护 + 执行驱动按页解密 ⇒ **dump 式完美脱壳结构性不可达；“保护器拥有执行”为 dump 路线终态。**

| 断言 | 分级 | 证据 |
|---|---|---|
| 样本受商业保护壳保护 | confirmed | 全节虚拟化 + PE 头加密 + EP 密文（WO-601 §二/§六） |
| 壳属 SecureEngine 系 | suspected-secureengine-class | 行为矩阵：TLS 时刻解析器 + unwind 混淆（WO-601 §五/§六） |
| 具体为 Themida V3 | unverified（原断言为启发式推断） | 无厂商字符串；SecureEngine 变体未排除（WO-601 §一） |
| 保护器做执行驱动按页解密 | confirmed（本观察条件） | 300s 真实运行零新增页 + unreadable=0（LIVE-3 R1） |
| 被动等待不触发解密 | confirmed | 60s 零解密（LIVE-2 R2） |
| dump 式完美脱壳结构性不可达 | **结构论证（§四）** | 本报告 §四 |

## 四、结构天花板论证（独立成节）

**结论先行**: 即使交互式脱壳把覆盖率推高（窗口驱动解密页），产出的候选在**独立运行时依然 AV**——因为:

1. **按页惰性解密 ⇒ 独立重跑必走新路径**: 保护器只解密当前执行路径触碰的页。dump 时已解密页 = 本次运行路径的页；独立运行（新进程、新 ASLR 布局）执行流必然触碰**未在 dump 时解密的新页**——这些页在候选里仍是密文；
2. **候选执行 = 踩密文页**: 新路径 → 新页 → 密文 → 乱码游走 → 0xC0000005（r27 时代 9/9 与 LIVE-2 R1 3/3 同码复现）；
3. **覆盖率推高不改变结构**: 即使交互把本次覆盖率从 4% 推到 90%，dump 时未覆盖的 10% 中，独立运行必踩其一（不同执行路径）——除非覆盖率=100% 且覆盖了所有可达路径，而这需要保护器解密算法的完整复现；
4. **复现解密算法 = 破译保护器** — 超出项目范围，且与 bypass/红线冲突（授权 §四：禁止语义修复/逆向保护器语义）。

**推论**: dump 式路线（无论 Immediate/PostSelfDecrypt/覆盖测量）结构性不可达完美脱壳。"保护器拥有执行"是终态——候选可以忠实呈现 dump 时刻的内存映像，但无法成为独立可运行的完美脱壳产物。

## 五、已关闭项清单 vs 永久开放项清单

### 已关闭（证据闭合）
- [x] H5 loader 墙根因：.rdata 内容=加密区快照（WO-002）
- [x] 被动等待路径（PostSelfDecrypt）：惰性解密假设成立（LIVE-2 R2）
- [x] 覆盖测量路径：4.26% 恒定、300s 零增长（LIVE-3 R1）
- [x] 壳归因分级：suspected-secureengine-class（WO-601）
- [x] dump 式路线天花板：结构性不可达（本报告 §四）
- [x] LIVE-2/LIVE-3 账本：used 记录完整（2/2、1/2 deliberate-unspent）

### 永久开放（不关闭，诚实标注）
- [ ] GTO 样本的**完美脱壳**（dump 式）：结构性不可达，永久开放
- [ ] 保护器厂商确证（Themida vs 其他 SecureEngine 变体）：unverified，永久开放
- [ ] 反调试停滞/窗口未现的机制诊断：不影响战略结论，保持开放
- [ ] 未来新工具/新思路的脱壳路径：走新治理，不以此账本为据

## 六、非声明段

- ❌ 不声称 perfect unpack / product 1.0 / 墙已破
- ❌ 不声称"保护器不可破解"（仅声称 dump 式路线结构性不可达）
- ❌ 不声称壳厂商确证（suspected 级）
- ❌ 不声称已穷尽所有脱壳方法（仅 dump 式路线）
- ✅ 所有定量锚点均可复现（证据指针齐全）
- ✅ 未花的 LIVE-3 轮次是干净的终局记录（deliberately unspent）

---

**终局落款**: GTO 主线 dump 式路线以完整证据链 + 量化数字收官——非含糊放弃，而是结构性结论。

---

## 七、product 1.0 定义修订提案（WO-803，仅提案不自行生效）

**现状**: 原 product 1.0 定义隐含 "perfect unpack" 目标（GTO 线）。终局证明 dump 式完美脱壳对
suspected-SecureEngine-class 保护结构性不可达 → 原定义对 GTO 线不可满足。

**提案（供 owner 审阅，不自行生效）**:

**product 1.0（修订版）: 对受保护目标产出"忠实 dump + 已知限制文档化"**

1. **忠实 dump**: 候选 = dump 时刻内存映像的忠实呈现（已达成：结构门、IAT/TLS/reloc/exception 证据齐全）；
2. **已知限制文档化**: 每样本产出附分级措辞的能力声明（confirmed/suspected/unverified），
   明确"dump 式路线 vs 保护器拥有执行"的边界（本报告 §三/§四）；
3. **回归墙不变**: Oreans 两样本门（ADR7 17/17 PASS）继续为唯一 formal acceptance 基准；
4. **GTO 线定位**: 从"完美脱壳目标"改为"研究线（忠实 dump + 证据链）"；
5. **不声称**: perfect/universal unpack、墙已破、保护器已破解。

**生效条件**: owner 书面批准本提案（批准即修订 product 1.0 定义；未批准则现状不变）。
