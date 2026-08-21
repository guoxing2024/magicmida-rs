# GTO-H5-R9-ORIGIN-CAUSAL-PROOF-1 — 完成报告

> status: COMPLETE per dispatch scope — r9 last-writer NOT provable (encrypted region); boundary documented; root cause PENDING

## 验收对照
| 项 | 结果 |
|---|---|
| 两侧 r9/r11/rbp/rsp + [rbp+r9+0x9207] + 前驱控制流 | **PASS**（cand_ctx.txt / prot_ctx.txt 全量记录） |
| r9 最后写入点 + 数据来源 | **BOUNDARY**：写入发生在 0x142c1d6c3..0x142934069 加密区；静态 3 个 lea r9,[rsp] 候选（0x2960dea/0x2a42f50/0x2a6f2d3）运行**均未命中**；2242 pop-r9 无法静态解析；0x1429d6ecc 也未命中——实际执行路径与静态字节不一致 |
| 来源表项 RVA/section/运行时 diff | **N/A**：r9 是栈地址（0x7fe5f0/0x7fe5c0），非 .rdata* 表项 |
| 仅观察 | **PASS**（无 patch/backfill/代码改） |
| 根因双侧因果链 | **未形成 → PENDING** |

## 关键事实（两侧同执行点）
1. r9 链：resolver 入口 = 0x142bd5d93 = 0x142c1d6c3 = **0x141728972**（TLS0 地址，两侧一致）→ 0x142934069 = **0x7fe5f0**(cand) / **0x7fe5c0**(prot)
2. 0x142934069 处 rbp=0xffffffffffff6df9（两侧，= -0x9207）→ **[rbp+r9+0x9207] = [r9]**
3. candidate [r9]=[0x7fe5f0]=0x9FD548（垃圾）→ AV；protected [r9]=[0x7fe5c0]=0x7ff848718f70（有效）→ 继续
4. 栈槽内容差异发生在加密执行**期间**（TLS0→resolver 两侧 regs/rsp 一致）
5. candidate 崩溃点跨运行漂移（0x142934089 / 0x1412f2f40）——加密乱码游走特征

## 边界声明（诚实）
- 无法证明 r9 唯一最后写入指令：加密区（3MB）动态路径 ≠ 静态字节；断点候选全未命中
- r9 来源是栈（非 .rdata*）；栈槽差异的源头写入在加密区内，静态不可解析
- 指令级崩溃机制确认（[r9] 读垃圾），但到 dump 缺陷的因果链未建立

## 封存
- H5_r9_origin_proof/：13 files，manifest + seal_anchor，self-hash MATCH
- ADR7 17/17；工作树 clean；GTO-H5-LIVE-AUTHORIZATION-2 不申请
