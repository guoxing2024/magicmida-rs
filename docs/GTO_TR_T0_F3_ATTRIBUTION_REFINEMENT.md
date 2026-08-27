# GTO-TR T0 · F3 报告：归因精化——从 suspected 级向变体/版本级推进

**执行**: GTO-TR 线 T0 sprint F3 子代理 · 2026-08-26
**范围**: 纯文档推理，无新二进制分析（未触碰 vault 字节，F1/F2 的字节级结论直接引用）
**输入**: WO-601 全量 + archive/operations/reports/ 下 GTO_H4/H5/H6 全系行为报告
**方法**: 对 WO-601 每条证据项标注区分度（SecureEngine 共性 / 变体特异 / 版本特异），
再核对既有行为数据补采新特征，输出补采清单与精化归因建议。

---

## 一、WO-601 证据项区分度标注表

> 列说明：区分度 = 该证据能在哪个层级把壳从"SecureEngine 家族"区分到
> "具体变体/版本"。SecureEngine 共性 = 无法区分 Themida vs WinLicense vs 其他变体；
> 变体特异 = 能在家族内区分；版本特异 = 能区分 2.x/3.x/等具体版本。

| # | WO-601 证据项 | 证据出处 | 区分度 | 理由链 |
|---|---|---|---|---|
| 1 | 随机节名（.fptable/.rdata0/1/2, rev1 .KI3） | §四 | **SecureEngine 共性**（弱） | VMP 也随机节名；跨版本节名不稳定是家族共性，无法分离变体 |
| 2 | 全节 raw=0 虚拟化（6/9） | §五 | **SecureEngine 共性**（弱） | VMP/Enigma 同样全节化；无变体信号 |
| 3 | PE 头字段加密（TLS 目录磁盘随机） | §三 | **SecureEngine 共性**（弱） | 家族级特征，VMP 也有 |
| 4 | EP 密文（磁盘 EP 非 E8） | §五 | **SecureEngine 共性**（弱） | 家族级 |
| 5 | 运行时 TLS 时刻解析器（H4-C 3 layouts） | §五 / H4C | **变体特异（中等）** | 已知行为矩阵中唯一指向 SecureEngine>VMP 的强项；但 Themida 与 WinLicense 都走 TLS 解析，仍无法分离二者 |
| 6 | unwind/异常混淆（H4-D，handlers_preserved=12） | §五 / H4D | **变体特异（中等）** | 保留 12 个原生 handler = 非全虚拟化；此点可区分"深度虚拟化变体"与"选择性虚拟化变体"（见 §三） |
| 7 | 惰性解密（300s 熵恒定 7.4-7.9） | §五 / LIVE3 | **SecureEngine 共性**（弱） | VMP 也惰性解密；但 **.text 恒定 6.002 且 H6 证实 text_is_plain** 是关键补充（见 §三） |
| 8 | 导入表加密（IAT 562/562 一致） | §五 / LIVE2 | **变体特异（中强）** | **全量原生 IAT 一致（562/562）** 说明导入**未被深度虚拟化**——这是 Themida 默认 IAT 保护（中档）vs WinLicense 常做的更重 IAT 混淆的关键分岔（见 §三） |
| 9 | 无厂商字符串（全 miss） | §二 | **无区分度** | 所有现代壳都去字符串 |

---

## 二、从既有归档行为数据补采的区分性特征（F1 后续迭代用）

以下特征**均已存在**于归档数据中，但 WO-601 未将其纳入归因矩阵。F1 后续可
直接取用，无需新增二进制分析：

| 特征 | 归档来源 | 观测值 | 归因意义 |
|---|---|---|---|
| **C1 `.text` 明文原生 MSVC 形态（1.2MB）** | F1 结构指纹 + H6 LIVE1 `text_is_plain_for_attestation=true` + LIVE3 §四 .text 熵 6.002 | 0x1000-0x12BECB ≈ 1.2MB 明文原生代码，运行时即刻可读且恒定 | **强力排除 VMP/深虚拟化**：真正的 VMP 或深 SecureEngine 虚拟化会把 .text 主体虚拟化，不会保留 1.2MB 明文 MSVC。指向**选择性虚拟化**模型 |
| **C2 `.rdata0` 含 13-15% 密度原生代码岛** | F1 结构指纹 | .rdata0 内散布原生代码岛（非纯数据） | 与 Themida 的"代码岛置于数据段"惯用法一致；区分于纯密文段（.rdata2） |
| **C3 TLS 回调：3/4 原生 .text，仅 TLS0 在 .rdata2 且为 VM/resolver 入口** | H4C §3（callbacks 0x60a0/0x10538c/0x105474 在 .text；0x1728972 在 .rdata2）| 混合原生+虚拟化引导 | Themida 典型：主引导虚拟化，部分原生回调保留。TLS0 是加密 resolver 入口（R9 §二 证实 resolver=0x1728972=TLS0） |
| **C4 无 reloc 目录** | F1 结构指纹 + H4D no-reloc | 无 .reloc | Themida 对自身映像常剥离 reloc；此点 WinLicense 行为类似，单独无区分度，但与 C1 组合有意义 |
| **C5 导入全量原生（562/562），无 delay-load 依赖** | LIVE2 + H5 | 运行时 IAT 562/562 一致，vcomp140 是 cdb 假符号（实际仅 gto_unpacked.exe 单模块） | 关键：**主模块导入未深度虚拟化**。区分 Themida（IAT 保护默认中档）vs 更重混淆的变体 |
| **C6 原生异常处理保留（handlers_preserved=12）** | H4D 设计 §handlers_preserved | 12 个原生 handler 保留 | 与 C1/C5 同向：**非全虚拟化**，选择性子集虚拟化 |

**补采特征归因合力**（对 F1 后续迭代的指令）：C1+C3+C5+C6 四者合力
指向**"选择性虚拟化 + 大量明文原生保留"**模型——这精确对应 **Themida（非 WinLicense）**
的默认保护轮廓（WinLicense 在相同保护级别下会对 .text 与导入做更重的混淆/虚拟化）。
据此建议 F1 后续把指纹重点转向版本级：TLS 回调计数与顺序、OEP 引导链形状、
节随机化种子、IAT 保护档位、是否带 license-check 逻辑入口（WinLicense 特有）。

---

## 三、精化归因建议

### 建议表述

> **confirmed-packer**: 样本受商业保护壳保护，且保护模型为
> "选择性虚拟化 + 大体积明文原生保留"（.text 1.2MB 明文、导入 562/562 原生、
> 12 个原生 unwind handler 保留、TLS0 为加密 resolver 入口）。
> **suspected-Themida（非 WinLicense，非 VMP）**: 上述选择性虚拟化轮廓与
> Themida 默认保护高度一致；与 WinLicense（同保护档下更重混淆/含授权逻辑）
> 和 VMP（深度全虚拟化）均不吻合。
> **unverified-version**: 具体 2.x/3.x 版本无法由现有归档数据判定，
> 需 F1 版本级指纹（TLS 引导形状、节随机化种子、IAT 档位）补足。

### 为何从 suspected-SecureEngine-class 收紧到 suspected-Themida

WO-601 的 suspected-class 保留了两层不确定：(a) 是否为 SecureEngine 家族本身；
(b) 家族内是 Themida 还是 WinLicense。本轮用**既有行为数据**在两层上各推进一步：

1. **排除 VMP/深虚拟化**（强化家族判定）：C1（1.2MB 明文 .text）+ C5（562/562
   原生 IAT）+ C6（12 原生 handler）三者在 VMP 深度虚拟化下不可能共存。
   即使是最"轻"的 VMP 配置，也不会把 1.2MB MSVC 主体留作纯明文且 IAT 全原生。
   → **家族判定从"疑似 SecureEngine 或 VMP"收窄为"SecureEngine 家族"**（confirmed 级）。

2. **Themida > WinLicense**（家族内分岔）：在 SecureEngine 家族内，WinLicense
   的默认保护（尤其启用许可证后）会对 .text 与导入做比重保护档更重的混淆/虚拟化，
   并注入授权逻辑；而本样本呈现的是**轻-中档、选择性子集虚拟化 + 明文主体保留**。
   这与 **Themida** 的典型默认轮廓吻合。此为 **suspected-Themida**（非 confirmed：
   无厂商字符串，且 WinLicense 关闭授权功能时可退化为近 Themida 行为，故保留分级）。

3. **版本不可判**（诚实保留）：现有归档数据无版本特异锚点（无字符串、无
   Themida 2.x 的经典区段名、无 3.x 的特定 VM 结构签名）。版本级判定交 F1。

### 置信度

| 层级 | 判定 | 置信度 | 证据 |
|---|---|---|---|
| 家族（SecureEngine） | confirmed | 高 | C1+C5+C6 合力排除 VMP/深虚拟化 + WO-601 TLS/unwind 强特征 |
| 变体（Themida vs WinLicense） | suspected-Themida | 中高 | 选择性虚拟化轮廓；WinLicense 关闭授权时不可排除 |
| 版本 | unverified | — | 无版本特异锚点，交 F1 |

---

## 四、补采清单（交付 F1 后续迭代）

以下特征**可由 F1 在 vault 字节上采集**，用于把 suspected-Themida 推至
confirmed-Themida 与版本级判定。按区分度排序：

1. **TLS 引导链形状指纹**：TLS0(resolver=0x1728972) 入口处的指令模式——
   Themida 3.x 的 dispatch 循环/加密 resolver 前缀与 2.x 明显不同。
   *版本特异*，最高优先。
2. **IAT 保护档位判定**：562 个 IAT 槽中，原生直连 vs 经 stub 中转的比例。
   Themida 默认中档多为直连，高档才 stub。*版本特异*。
3. **节随机化种子分析**：.fptable/.rdataN 命名序列的伪随机生成器——不同版本
   节名生成器不同。*版本特异*。
4. **OEP/引导链形状**：.text 入口（0x16fb532 附近，H5 记录）与 TLS0 的跳转
   关系——Themida 各版本引导 stub 模板不同。*版本特异*。
5. **.rdata0 代码岛特征**：13-15% 密度代码岛的具体分布与编码——Themida
   "代码岛"算法版本可溯。*变体→版本特异*。
6. **异常目录保留范围**：12 个原生 handler 中虚拟化/原生的分界——深虚拟化
   变体保留范围小。*变体特异*。
7. **WinLicense 授权逻辑探测**：检索疑似 license-check 导入（无厂商字符串下
   用导入名启发式）——命中则反向强化 WinLicense 假设。*变体特异*。
8. **无 reloc 的载荷补偿**：无 .reloc 时映像是否依赖绝对地址（ASLR 失效的
   暗示）——Themida 对自身映像的处理 vs 一般。*变体特异*。

---

## 五、非声明段

- 未执行任何二进制字节级新分析（那是 F1 的活）；本报告全部基于
  WO-601 + archive/operations/reports/ 既有文档与行为数据。
- C1/C3/C5/C6 等补采特征为**既有归档数据的再组织**，非新测量；若归档
  dump 数据与报告数值有出入，以 F1 的重新测量为准。
- suspected-Themida 是**概率性收窄**，不是 confirmed：WinLicense 在
  关闭授权功能时其保护轮廓可退化至近 Themida 行为，本报告在无厂商
  字符串前提下无法绝对排除。
- 版本（unverified）是诚实保留项——不因"可能"而越权判定。
