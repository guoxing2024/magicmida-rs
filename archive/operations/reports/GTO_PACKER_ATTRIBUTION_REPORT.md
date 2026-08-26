# GTO 样本壳归因验证报告（WO-601，离线只读）

**依据**: 批次 6 工单 WO-601 + 此前静态取证数据（工单输入）
**性质**: 离线只读（仅扫描 vault 字节，零样本执行）
**执行**: 唯一 worker · 2026-08-22
**状态**: COMPLETE — 结论分级标注，未改写任何历史文档断言

---

## 一、结论摘要（分级标注）

| 结论 | 分级 | 依据 |
|---|---|---|
| 样本受商业保护壳保护（非裸 PE） | **confirmed** | 全节 raw=0 虚拟化 + PE 头字段加密 + EP 密文 |
| 壳属 SecureEngine 系（Themida/WinLicense 家族） | **suspected-secureengine-class** | 行为特征间接证据（见 §五），无厂商字符串直接证据 |
| 具体为 Themida V3 | **unverified**（原 themida_version=V3 为运行时启发式推断） | 无 TheMida 字符串/签名；运行时特征可被其他 SecureEngine 变体复现 |
| 样本含 VMProtect/其他商业壳 | **unverified**（无证据支持） | 无 VMP 字符串/节名/特征 |

**核心声明**: 全库现存 Themida 断言**从未被确证** — 现有依据仅为行为特征（SecureEngine 系间接证据）。

## 二、YARA/签名规则比对（离线扫描 vault 对象）

方法: 公开 Themida/WinLicense/VMProtect/Oreans/SecureEngine/其他 30+ 壳的已知字符串特征，对 vault 对象（11473d2e…, 24,636,416 字节）做大小写敏感 + 不敏感扫描。

结果:
- **Themida/WinLicense/Oreans/SecureEngine/VMProtect 全部 MISS**（0 命中）— 确认库无任何厂商字符串
- 误报排除: UPX x2 / FSG x2 / MEW x1（不区分大小写）均为 .rdata2 加密区随机字节巧合（上下文检查确认非真实壳标记，无 UPX0/UPX1 节名、无 FSG 头部）

结论: **签名比对零确证** — 无任何厂商字符串可直接归因。

## 三、TLS 回调链静态解析（目录 0x15C2E10, .rdata2 内）

结果: **磁盘态 TLS 目录字段全为随机值**（StartAddressOfRawData=0x8d47def1c1487ef2 等）— PE 头 TLS 目录在磁盘态为**密文/混淆状态**。

推论:
- 磁盘态无法静态解析 TLS 回调链（目录本身加密）— SecureEngine 系 PE 头字段加密特征
- 运行时 TLS 观测（H4-C 已完成, 3 layouts PASS）是唯一有效路径 — 磁盘静态解析不可行是保护设计使然
- 与 dump 侧 TLS=0x15c2e10/0x28 (hint only; not R0B) 一致 — 磁盘 TLS 目录不可信

## 四、节名溯源（rev1/rev2/rev3 布局演变）

| 修订 | 样本 | 节布局 | 说明 |
|---|---|---|---|
| rev 1 | 4d5770af…（analysis_reference, 8,583,680 B） | **.KI3** 布局 | 历史；非 rev2 执行目标 |
| rev 2 | 11473d2e…（protected_input, 24,636,416 B） | **.fptable/.rdata0/.rdata1/.rdata2** | 当前执行目标 |
| rev 3 | （未见独立布局记录） | 同 rev2（推测） | 待确认 |

观察: 节名从 .KI3 → .rdata0/1/2 的**版本间随机化** — SecureEngine 系（Themida/WinLicense）随机节名混淆的典型行为；跨版本节名不稳定是**间接证据**（suspected 级）。

## 五、行为特征矩阵（SecureEngine vs VMP vs 其他商业壳）

| 特征 | 本样本观测 | SecureEngine (Themida/WL) | VMProtect | 判定 |
|---|---|---|---|---|
| 随机节名 | .fptable/.rdata0/1/2（rev2）、.KI3（rev1） | ✅ 典型 | ✅ 也有 | 弱信号 |
| 全节 raw=0 虚拟化 | 6/9 raw=0 | ✅ 典型 | ✅ 典型 | 弱信号 |
| PE 头字段加密 | TLS 目录磁盘态随机值 | ✅ 典型 | ✅ 也有 | 弱信号 |
| EP 密文 | 磁盘 EP 非 E8（乱码） | ✅ 典型 | ✅ 也有 | 弱信号 |
| 运行时 TLS 时刻解析器 | H4-C 观测（3 layouts 一致） | ✅ 典型 | 少用 | **中等信号 → SecureEngine** |
| unwind 混淆 | 异常目录异常（H4-D 观测） | ✅ 典型 | 少用 | **中等信号 → SecureEngine** |
| 惰性解密（Round 2 实测） | 60s 熵恒定（7.4-7.9 无下降） | ✅ 典型 | ✅ 也有 | 弱信号 |
| 导入表加密 | IAT 运行时 562/562 一致（H5 观测） | ✅ 典型 | ✅ 也有 | 弱信号 |
| 无厂商字符串 | 全 miss | ✅ 典型 | ✅ 典型 | 无区分度 |

## 六、结论（强制分级）

1. **confirmed**: 样本受商业保护壳保护（全节虚拟化 + PE 头加密 + EP 密文，客观可复现）
2. **suspected-secureengine-class**: 行为特征矩阵中 TLS 时刻解析器 + unwind 混淆两项为 SecureEngine 系强特征，其余特征与 SecureEngine 兼容；无任何厂商字符串直接证据
3. **unverified**: 具体归因到 Themida V3（现库内断言）— 运行时启发式推断，非确证；VMP 或其他 SecureEngine 变体未被排除

## 七、措辞修正清单（只列不改）

以下位置含 Themida 断言，建议改为分级措辞（本单**只列清单**，改写须另批）：

| 位置 | 当前措辞 | 建议分级 |
|---|---|---|
| crates/cli/src/unpacker/mod.rs | PackerPlugin identify family=oreans_themida | suspected-secureengine-class |
| crates/cli/src/unpacker/mod.rs | Host layout family=oreans_themida themida_version=V3 | suspected-secureengine-class |
| crates/packers/themida/* | 模块名 themida（包名） | 保留（包名非断言），文档措辞需分级 |
| docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md | 多处 Themida 引用 | 需分级标注 |
| docs/GTO_H5_LOADER_WALL_ROOT_CAUSE.md | Themida 加密/虚拟化代码 | 需分级标注 |
| docs/GTO_H5_RDATA_DEFECT_ROOT_CAUSE_INVESTIGATION.md | Themida 未解密区域 | 需分级标注 |
| docs/GTO_H5_LIVE2_R1_REPORT.md / R2_REPORT | Themida 自解密 等 | 需分级标注 |
| WORK_ORDERS_BATCH_*.md | 工单中 Themida 引用 | 治理记录 — 建议保留原样（历史），仅新文档分级 |
| docs/VNEXT_R4_AHK_GTO_PATH.md | family=oreans_themida 断言 | 需分级标注 |
| docs/GTO_PREFLIGHT_LANE.md | dual_select_packer 分数 | 需分级标注 |

**改写原则建议**（供另批时参考）: 代码内 family_id 字符串（oreans_themida）为路由标识可保留；文档断言改为 confirmed/suspected/unverified 三分级措辞；历史治理记录不改写（避免污染）。

## 八、非声明段

- 未执行任何样本（纯离线扫描 vault 字节）
- 未修改任何既有文档断言（仅列清单）
- YARA 规则库为公开特征子集，非完整商业规则库（unverified 级归因不受影响）
- confirmed 仅指受保护事实，不指具体壳厂商
