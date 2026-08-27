# GTO-TR R0 引擎指纹报告（T0 收口）

> **工单**: WORK_ORDER_GTO-TR-0_20260826 · T0 阶段
> **执行**: Lead 裁决综合；F1/F2/F3 由子代理完成（主力分组 deepseek-v4-pro-0813 @ max）
> **状态**: T0 CLOSED — 归因升级达成，且出现一项改变 T1 先验的战略性发现
> **子报告**: [GTO_TR_T0_F2_FINGERPRINT_MATRIX.md](GTO_TR_T0_F2_FINGERPRINT_MATRIX.md)（公开语料矩阵）、
> [GTO_TR_T0_F3_ATTRIBUTION_REFINEMENT.md](GTO_TR_T0_F3_ATTRIBUTION_REFINEMENT.md)（归因精化）

---

## 一、归因裁决（WO-601 suspected → 精化）

| 维度 | 原 | 现 | 关键证据 |
|---|---|---|---|
| 家族 | suspected-SecureEngine-class | **confirmed-SecureEngine-family** | C1 明文原生 .text + C5 IAT 562/562 全原生 + C6 原生 unwind 保留——三者合力排除 VMP 深虚拟化模型 |
| 变体 | unverified | **suspected-Themida**（非 WinLicense） | WinLicense 同保护档下对 .text/导入混淆更重；本样本为轻-中档选择性虚拟化 |
| 版本 | unverified | unverified（诚实维持） | 公开语料版本收口上限为「Themida/WinLicense 3.x 系」；build 级判定依赖 F1 补采清单前 4 项（TLS0 引导链形状优先） |

## 二、战略性发现：虚拟化是选择性的，不是全量的

F1 对 H5_LIVE2_R1 运行时 dump（48.8MB）的字节级分析修正了 WO-601 的"全节虚拟化"定性：

- `.text` = **1.2MB 明文原生 x64**（1557 处标准 MSVC prologue，指令密度 24.4%，TEB 访问形态正常）
- `.rdata0` 含 13–15% 密度的原生代码岛（VM 化与原生存根混合）
- `.rdata2` 纯密文零节拍（无明文 handler 表——强加密数据或深度 VM 字节码主体）
- 结构指纹：`.import` 截断尾巴 IAT 名（最具识别性）、`.boot` RWX 段映射表、无 reloc 目录、`.fptable` 内核指针

**对 TR 主命题的影响**：「原生形态物化」不再是需要验证的假设——它已有直接证据。
T1 的 E1/E2 问题从"是否存在原生时刻"变为"**原生并集能否逼近可达区域全集**"。
假设 A 世界（traced-rebuild 可行）的先验概率显著上调。

## 三、公开工具现状（必答题闭合）

unlicense / Magicmida(Hendi48) / UnpackThemida 等覆盖 Themida 2.x/3.x，
但全部是「运行→dump→修导入」范式——正是本样本被 TERMINAL 报告证伪的路线；
按页惰性解密是它们的已知失效场景。声称 devirtualization 的项目
（bobalkkagi/Themida-3x）标注 future、无成熟度证据。

**结论：跨越惰性解密范式的工具在公开世界不存在 → 自建 traced-rebuild 的必要性成立。**

## 四、移交 T1 的输入

1. F3 补采清单 8 项（区分度排序：TLS0 引导链形状 > IAT 保护档位 > 节随机化种子 > OEP 引导模板…）——并入 E1 trace 观测目标
2. E1 工具选型待验：HyperDbg（需内核驱动/测试签名环境）vs Bochs（确定性回退案）——本机可用性 smoke 是 T1 第一动作
3. 判据不变：E1 原生驻留占比、E2 并集覆盖曲线渐近 vs 可达集、E3 残余三分类

## 五、账本

- T0：CLOSED（F1/F2/F3 各 1 attempt，零失败重试——前台 fork 通道）
- T1：used=0/6，未开
