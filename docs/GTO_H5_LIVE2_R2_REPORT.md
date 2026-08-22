# GTO-H5-LIVE-2 Round 2 — PostSelfDecrypt 实弹报告（WO-402）


> **编者注（WO-802, 2026-08-22）**: 本文中 "Themida" 均为未经厂商确证的启发式称谓。" 按壳归因结论（docs/GTO_PACKER_ATTRIBUTION_REPORT.md），正确分级为 **suspected-SecureEngine-class**（具体版本 **unverified**）。历史叙事事实不改写，仅断言强度分级。


**签发依据**: GTO-H5-LIVE-AUTHORIZATION-2 §三 + WO-402 书面放行（批次 6）
**账本**: GTO-H5-LIVE-2 · Round 2 · used=2/2 · remaining=0
**执行**: 唯一 worker · 2026-08-21T19:10Z
**状态**: COMPLETE — C3 超时 + 惰性解密假设成立（A2 预设结局，有效科学结果）

---

## 一、身份预检（硬门）— PASS

- 工具: tools/resolve_gto_source_revision.ps1
- 结果: revision_match=true, ResolvedAuthorizedRevision, vault_object_verified=true
- 样本: 11473d2e…（manifest rev 2）— 与 Round 1 一致
- 证据: H5_LIVE2_R2/resolved_source.json · 未消耗轮次（mismatch 才停）

## 二、授权门使用（WO-402 规则）

- 变量: MIDA_GTO_LIVE2_AUTHORIZED=1 仅在单命令窗口内设置（命令前缀式），运行后立即清除（AUTH_CLEARED=true 实测）
- 未入 profile/全局/系统环境
- manifest 凭证: attempt_001 候选的 transform_manifest 含 live2_authorized/authorization_gate 条目 — 消费凭证核验通过
- 环境: MIDA_GTO_NO_BYPASS=1 + MIDA_GTO_OBSERVATION_ONLY=1

## 三、执行序列（工单顺序不可调换）

| 步骤 | 结果 |
|---|---|
| ① 身份预检 | PASS（§一） |
| ② no-bypass + PostSelfDecrypt 采集 | attempt_001（Immediate 路径）exit 0 产候选；attempt_002（PostSelfDecrypt 生效）观察窗 60.058s |
| ③ 观察窗结局 | C3 超时（60s 硬上限，无 C1/C2） |
| ④ 时间线侧车核验 | 360 点全量落盘（A2 首要交付物 ✅） |
| ⑤ smoke | C3 拒绝候选 → 无候选可 smoke（N/A，见 §五） |

## 四、熵时间线全量（A2 首要交付物）

证据: H5_LIVE2_R2/attempt_002_candidate/gto_unpacked.post_self_decrypt_timeline.json（32438 字节, 360 点）

| 节 | 采样数 | min | max | mean | 恒定值 | <6.5 计数 |
|---|---|---|---|---|---|---|
| .rdata0 | 120 | 7.426 | 7.426 | 7.426 | 恒定 | 0/120 |
| .rdata2 | 120 | 7.878 | 7.878 | 7.878 | 恒定 | 0/120 |
| .pdata | 120 | 7.896 | 7.896 | 7.896 | 恒定 | 0/120 |

- 采样周期 500ms x 60s = 120 点/节（A1: .pdata 并入 ✅）
- 三节熵值全程恒定（7.426/7.878/7.896 无任何波动）— 60s 内未观察到任何解密活动

## 五、判据触发记录

| 判据 | 结果 | 说明 |
|---|---|---|
| C1（熵稳定下降 <6.5 连续 3 点） | 未触发 | 全程 >7.4，0/360 点低于 6.5 |
| C2（RIP 稳定入 .text >2s） | 未接线 | 无调试端口（direct dump mode），WaitForDebugEvent error_code=6；WO-401A P1-3 已诚实标注 |
| C3（60s 硬上限） | 触发 | window_ms=60058, timeline_points=360 |
| A2 惰性假设 | 成立 | C3 + 全程平坦高熵 → lazy_decrypt_hypothesis=true |

smoke: 候选被 C3 fail-closed 拒绝（无候选产出）→ smoke N≥3 不适用（N/A）。attempt_001 的 Immediate 候选非本次 PostSelfDecrypt 产物，不用于 smoke（其性质与 Round 1 相同，Round 1 已有 3/3 AV 记录）。

## 六、eager-vs-lazy 显式结论（A2 强制）

结论: 惰性/按页解密假设成立；整体批量解密（eager）假设不成立。

依据:
1. .rdata0/.rdata2/.pdata 熵在 60s 观察窗内完全恒定（7.426/7.878/7.896），无任何下降趋势 — 若 Themida 做整体批量解密，必然观察到全局熵下降（C1 应触发）；
2. 未观察到 ≠ 未解密：更精确的表述是 在观察窗内未观察到已解密状态 — 解密可能：(a) 惰性/按页（只解密实际执行的页）；(b) 依赖运行时驱动（UI/交互/特定代码路径触发）；(c) 需要反调试/VM 环境；
3. 因此 整体等待策略无效（A2 原文）— 等待目标自解密后 dump 的路径 (d) 在 60s 窗口内不可行。

对下一杠杆的意义: 若需继续，下一杠杆 = 运行驱动解密覆盖后再 dump（Route H UI-prefer 经验回归），需新授权（GTO-H5-LIVE-2 已耗尽）。

## 七、非声明段（授权文件 §五）

- ❌ 不声称 gto perfect unpack、product 1.0、墙已破
- ❌ 不声称 H5 解锁/签核（仍 BLOCKED_AT_LOADER_SMOKE）
- ❌ 不声称解密不存在 — 仅声称 60s 观察窗内未观察到解密活动
- ❌ 不声称 C2 曾触发（未接线，诚实标注）
- ❌ 不将 attempt_001 的 Immediate 候选作为 PostSelfDecrypt 产物声称
- ❌ WaitForDebugEvent error_code=6（无调试端口）不用于归因

## 八、轮次记账

- GTO-H5-LIVE-2: used=2/2, remaining=0 — 本轮为最后一轮，任何后续需新治理
- 证据目录: H5_LIVE2_R2/（append-only, 14 文件）
- 授权变量已清除（不留 profile/全局）

## 九、给总指挥的后续建议

1. F6 判据迭代或新路径（如运行驱动解密覆盖后再 dump）需新治理授权 — GTO-H5-LIVE-2 已耗尽
2. 壳归因（WO-601 并行进行中）将提供为何惰性解密的补充证据（Themida/SecureEngine 特征）
3. .pdata 熵 7.896 恒定 → 大概率非运行时解密数据，倾向 dump 布局伪影（WO-601 节名溯源将交叉验证）
