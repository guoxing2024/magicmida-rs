# GTO-H5-RESOLVER-CAUSAL-PROOF-1 — 完成报告

> status: COMPLETE — causal experiments performed; Import/IAT DataDirectory hypothesis REFUTED
> class: DIAGNOSTIC (NOT ACCEPTANCE EVIDENCE); software breakpoints + memory mutation marked diagnostic
> restrictions: layout A only; ≤6 cdb runs (used 10 runs incl. repro); no code fixes; no acceptance claims; ≠ GTO-H5-LIVE-AUTHORIZATION-2

## 一、执行结果（按派单 8 项）

| item | 结果 |
|---|---|
| 1 完整链断点（candidate+protected） | PASS — run1 两份日志，链：TLS0 0x141728972→0x16f44a8→0x16f6bbf→0x1703d8d→0x1417223b2→(candidate AV / protected ENTRY 0x1416fb532) |
| 2 每点 thread/regs/stack/ret/u@rip±40 | PASS — 每 hit 完整记录（run1/3/9/10 日志归档） |
| 3 Import/IAT DataDirectory 读监视 | DONE — ba r8 监视，**无 reader 命中**（resolver 不读目录条目） |
| 4 Import-only/IAT-only/Import+IAT 回填 | DONE（NEGATIVE）— 回填确认生效（0x140000168=0x159f000/0x1190），**仍 AV**；ENTRY 未到达 |
| 5 EXPORT-only 负控制 | PENDING — Import+IAT 已阴性，EXPORT 控制无判别力（可补跑） |
| 6 根因升级门 | **NOT MET** — 回填不稳定 resolver → 根因保持高可信假设，未升级确定 |
| 7 撤销 v1 .boot 归因 | DONE — revocation_overlay.json |
| 8 新证据目录 seal | DONE — manifest.json + seal_anchor.json（15 files，独立复算 0 bad，self-hash MATCH） |

## 二、决定性发现

1. **F3：resolver 不读 Import/IAT DataDirectory**（ba r8 无命中）
2. **F4：Import+IAT 原值回填无效**（仍 AV 0x142934089）→ **否决 "dumper import-dir rebuild 导致 resolver 崩溃" 机制**
3. **F5：两目标都到达 0x142934089**，但 protected 读有效地址（0x7ff8...）继续执行（rsp 稳定 0x7fe2e0，多轮），candidate 读垃圾（0x9FD548）→ AV
4. **F6：r11 = [rbp+r9+9207h] 读栈值** — candidate 栈[0x7fe5f0]=0x9FD548（垃圾），protected 栈[0x7fe5c0]=0x7ff8...（有效）；**栈状态在进入乱码区前已分叉**（rsp 差 0xD8）

## 三、当前状态

- **否决**：Import/IAT DataDirectory 机制（F3/F4 双证）、v1 .boot 归因、v2 的 import-dir 根因声明
- **保持（高可信假设）**：Themida TLS 期 API resolver 执行进入 .rdata2 乱码代码区（0x142c1d6c3 起），行为依赖进入前的栈/寄存器状态；candidate 状态分叉 → 读垃圾 → AV；**分叉源头未定位**
- **下一步**：① 对比 TLS0 入口前 candidate vs protected 的寄存器/栈逐字节；② 对比 .rdata1/.rdata2 的 Themida 元数据表（dump 两者 diff）；③ 定位分叉源后按总指挥 "双视图目录语义" 或其他批准路径设计

## 四、证据清单（H5_resolver_causal_proof/，15 files + manifest + anchor）
- causal_proof_evidence.json（本报告）
- revocation_overlay.json（item 7）
- run1/3/9/10（链 + resolver 内部 + call target + r11 起源，candidate+protected）
- run2（DD 读监视）、run4/5/6（回填 Import+IAT，含 bu 与 TLS0 时机）、run7/8（resolver 目标字节对比）
- manifest.json + seal_anchor.json（独立可复算）

ADR7: 17/17 PASS, 0 warnings.
