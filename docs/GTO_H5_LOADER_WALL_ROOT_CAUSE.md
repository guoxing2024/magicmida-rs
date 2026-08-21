# GTO-H5 — LOADER WALL 根因分析（GTO-H5-LOADER-FAILURE-CORRECTION-1）

## 一、审计裁决
- **H5 不签**；H5 status = BLOCKED_AT_LOADER_SMOKE
- 真正的墙是 **loader/behavior**，不是 authenticity
- "H5 TECHNICAL PASS — PRODUCT AUTHENTICITY GATE PENDING" **不成立**（REVOKED）
- R0B static + H5 negative controls PASS；loader smoke FAIL 9/9；bounded behavior INCONCLUSIVE

## 二、crash attribution（3/3 cdb 独立诊断，NOT ACCEPTANCE EVIDENCE）

### 事实
| run | exception addr | RVA | section | fault |
|---|---|---|---|---|
| 1 | 0x1412F2F40 | 0x12F2F40 | .rdata0 (0x14191000-0x14159E61C) | AV read @0xA73000 |
| 2 | 0x142934089 | 0x2934089 | .rdata2 (0x1415A3000-0x142D1B000) | AV read @0x9FD548 |
| 3 | 0x142934089 | 0x2934089 | .rdata2 (同上) | AV read @0x9FD548 |

- 模块表：**只有 gto_unpacked.exe**（0x140000000-0x142E52000），"vcomp140" 是 cdb 假符号
- crash 页 Protect = **PAGE_EXECUTE_READ**（dump 重建为可执行）
- r15 = 0x140000000（image base 未变）、r12 = 0x7ffe0385（KUSER_SHARED_DATA 附近）
- 指令流完全乱码（Themida 加密代码特征）

### 判定
- **位置**：post-entry 执行进入 dump 重建为 executable 的 .rdata0/.rdata2 巨型段（20MB+）
- **机制**：Themida 加密/虚拟化代码在 dump 中**未解密**，但段被标成 Code|Execute Read；执行进入后乱码游走，直到读未映射低地址 → 0xC0000005
- **不是**：bootstrap stub、TLS callback、IAT/SMR resolver、OEP、重建指针
- **不是确定性单点**：两次不同 RVA 乱码 → 加密代码游走

## 三、dump 缺陷假设（待设计验证）
1. **.rdata0/.rdata1/.rdata2 被重建为可执行**：原 Themida 映像中这些是数据段（加密代码载体）。dump 器把它们标记为 Code|Execute Read，但**没有解码内容** → 执行进入即乱码。
2. 原 .text（0x1000-0x12BECB，12AECC ≈ 1.2MB）才是真代码；.rdata0/.rdata2 是 Themida 的加密层。入口/跳转目标错误地指向了加密区（或加密区应被解码后再执行）。
3. 修复方向（候选，需设计评审）：
   a. 将 .rdata0/.rdata1/.rdata2 特性改回数据段（去掉 Execute），让执行流无法进入 → 但会导致入口目标无效（仍需解码或重定向）
   b. 对 .rdata0/.rdata2 加密内容做运行时解码（需要 Themida 解密逻辑/密钥——高风险）
   c. 重新定位入口/跳转目标到解码后的真实代码区（需要理解 Themida 的启动流程）
   d. 用 obs-only host（G1）观察受保护程序自身如何解码/跳转，再决定 dump 策略

## 四、派单执行状态
| item | 状态 |
|---|---|
| 1 冻结 H5_acceptance_1 + overlay | DONE（H5_correction_overlay_loader_failure.json） |
| 2 暂停 B/C，A 2 次独立 crash attribution | DONE（3 次 cdb，run1/2/3） |
| 3 诊断通道标记 NOT ACCEPTANCE EVIDENCE | DONE |
| 4 exception addr/RVA/regs/stack/faulting mem/image base/.boot/TLS/OEP 状态 | DONE（见 crash_attribution_evidence.json） |
| 5 AV 位置判定 | DONE（.rdata0/.rdata2 加密代码段） |
| 6 代码修复 | NOT STARTED（需设计 + 测试 + H6 回归 + 重过 H4 门） |
| 7 GTO-H5-LIVE-AUTHORIZATION-2 前禁止重跑 | 遵守 |
| 8 seal 45/46 计数 + self-hash | DONE（H5_seal_correction/raw_disk_manifest_v2.json + seal_anchor.json） |

## 五、下一步（需要总指挥）
1. 评审 crash attribution 结论（.rdata 加密段重建为 executable 是核心缺陷）
2. 决定修复路径（三a/b/c/d 之一或多个）
3. 若需代码修复：先设计 → 测试 → H6 回归 → 重走受影响 H4 门 → 新 build attestation → 再申请 GTO-H5-LIVE-AUTHORIZATION-2
