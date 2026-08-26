# GTO-R6-A2 LOADER SMOKE — 完成报告

> status: COMPLETE — **判定 A2-FAIL**
> class: DIAGNOSTIC (NOT ACCEPTANCE EVIDENCE)
> work order: `WORK_ORDER_GTO-R6-A2-LOADER-SMOKE_20260825.md`
> date: 2026-08-25
> executor: worker (Hermes 总审计派单，owner 已书面批准)

---

## 一、前置校验（工单 §2）

| 项 | 值 | 结果 |
|---|---|---|
| 被测文件 | `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A1_dd_restore\layout_A\gto_unpacked.dd_restored.exe` | 存在 |
| 运行前 SHA-256 | `c4a1a94e367c0f555243d3408446df0320c04d2262cc039a2fd436a064e01637` | **MATCH** |
| 运行后 SHA-256（复核） | `c4a1a94e367c0f555243d3408446df0320c04d2262cc039a2fd436a064e01637` | **MATCH**（未改任何字节） |
| 大小 / 架构 | 48,563,200 B / x64 PE (0x8664) | — |
| ImageBase | `0x140000000` | 与断点 RVA 换算一致 |
| 断点地址落段 | TLS0 `0x141728972`→RVA 0x1728972、resolver `0x1417223b2`→RVA 0x17223B2、entry `0x1416fb532`→RVA 0x16FB532，均在 `.rdata2`（Themida 可执行加密区） | 全部有效 |

## 二、执行协议（工单 §3 落实）

- 调试器：cdb 10.0.26100.8249 (x64)，单实例，每 attempt 硬超时 **120s**，超时即 kill（实际全部在 1s 内结束，无超时）。
- 断点：cdb 原生 `bp` 机制（软件断点，仅诊断用途，**未写入/未 patch 目标内存数据、未改样本字节**）。
  - TLS0 `0x141728972`：命中记录 rip/全部关键寄存器后 `g`
  - resolver `0x1417223b2`：同上
  - entry `0x1416fb532`：同上
- 异常：`sxe av` first-chance 记录现场后 `gn` 继续；**首个 second-chance 记录完整现场（exception addr/RVA/section/regs/faulting address）后终止**，不做乱码游走。
- 环境：未设置 MIDA_GTO_LIVE 授权变量（本单为 owner 直接批准的诊断 smoke）。
- 无注入、无内存写（除 cdb 断点本身）。

**协议修正说明（attempt_001 缺陷 → attempt_002/003 修正）**：
attempt_001 使用 `cdb -g`（忽略初始断点），`-cf` 脚本在首个 first-chance 停点才执行，而 Themida TLS 链（TLS0→resolver）**在初始断点之前已执行完毕**，三个断点未命中（second-chance 栈中可见 `0x14172898a`=TLS0+0x18 返回地址，证实执行确实经过 TLS0，但断点错过）。
attempt_002/003 改为 **不带 `-g`**：cdb 停在 `ntdll!LdrpDoDebuggerBreak`（initial breakpoint，TLS 链尚未执行），脚本设断点后 `g` —— 与 H5 `run_candidate_chain_cdb.txt` 验证过的协议一致，断点完整命中。

## 三、命中时间线（attempt_002，与 attempt_003 完全一致）

| seq | 事件 | rip | 关键寄存器 |
|---|---|---|---|
| 1 | initial breakpoint (`ntdll!LdrpDoDebuggerBreak+0x35`) | `0x7ff968a5d78d` | — |
| 2 | 三断点设置成功（`bl` 确认） | — | — |
| 3 | **HIT TLS0** `0x141728972` | `0x141728972` | rdx=**1** (DLL_PROCESS_ATTACH), rsp=0x7ff178, rbp=0, rcx=0x140000000; 反汇编 `cmp edx,1` |
| 4 | **HIT RESOLVER** `0x1417223b2` | `0x1417223b2` | rdx=1, rsp=0x7ff130, rbp=0; 反汇编 `push rdx`（与 H5 记录的 resolver 前导字节一致） |
| 5 | **FIRST-CHANCE AV** c0000005 | `0x1412f2f40` | 读 `0xa83000`（attempt_003: `0xa06000`）未映射；栈已损坏，`~*k` 为垃圾 |
| 6 | **SECOND-CHANCE AV**（首个，终止） | `0x1412f2f40` | 见下节 |

**ENTRY `0x1416fb532` 从未命中；resolver 未正常返回。**

## 四、首个 second-chance 异常完整现场（attempt_002 / attempt_003 一致）

- **异常**：`c0000005` Access violation（read）
- **ExceptionAddress**：`0x1412f2f40` → **RVA 0x12F2F40 → `.rdata0` 段**（Themida 加密数据/代码区，RVA 0x191000..0x159E800）
- **Faulting address**：`0xa83000`（attempt_003: `0xa06000`）—— 未映射用户地址
- **指令**：`mov eax,dword ptr [rbx+rsi-1E962246h]`（`8b 84 33 ba dd 69 e1`）
- **寄存器**：rax=0xb9, rbx=0x1e962246, rcx=0xb9, rdx=0xb9, rsi=0xa83000, rdi=0x7fe148, rsp=0x7fe080, **rbp=0x1bffc92da（垃圾）**, r10=0x1412f2f21, **r11=0x407dd3a75（垃圾）**, r12=0x7ffe0385, r14=1, r15=0x140000000
- **栈**：已损坏（`~*k` 无法回溯），异常上下文 HRESULT 0x8000FFFF

**attempt_001 独立观察**（断点错过但捕获 second-chance）：AV @ `0x142934089`（RVA 0x2934089，`.rdata2`）读 `0x9fd548`，寄存器 rbp=0xffffffffffff6df9/rbx=0x1b6fb377300045（垃圾）—— **与 H5 报告 candidate 崩点 `0x142934089` 读 `0x9fd548` 完全一致**。

## 五、判据对照（工单 §4 二值判据）

| 判据 | 要求 | 实测 | 对照 |
|---|---|---|---|
| resolver `0x1417223b2` 命中后**正常返回** | 是 | **未返回**（返回前在 `.rdata0` 崩溃） | **FAIL** |
| ENTRY `0x1416fb532` 命中 | 是 | **从未命中**（3 次 attempt） | **FAIL** |
| 无 second-chance 异常 | 是 | second-chance AV c0000005 @ `0x1412f2f40`（.rdata0）/ `0x142934089`（.rdata2） | **FAIL** |
| 无超时 | 是 | 全部 attempt < 1s，无超时 | PASS（不影响判定） |

## 六、判定

# **A2-FAIL**

- 依据：**resolver 命中后未正常返回、ENTRY 从未命中、出现 second-chance 访问违例**（c0000005），三条件满足工单 §4 A2-FAIL 定义（"任何位置 second-chance 异常"）。
- 一致性：attempt_002/003 完全复现（TLS0→resolver→`.rdata0` AV 读 0xa0xxxx）；attempt_001 独立观察到 `.rdata2` 崩点 `0x142934089` 读 `0x9fd548`，与 H5 已知 candidate 崩溃**逐字节一致**。
- 假设符合度：**支持** H5 startup-order attribution —— candidate 在 TLS 期 resolver 路径上崩溃，源于 dump 重建数据目录后 resolver 解析到错误目标（两次运行的崩点/读址不同 = 垃圾寄存器驱动的非确定性跳转，正是"解析到乱码"的表现）。**注意崩点位置与 H5 不同（.rdata0 vs .rdata2），属同一机制下的非确定性分支，需总审计根因确认。**

## 七、交付物

### Vault（工单 §6 目标路径）
> ⚠️ **沙箱限制声明**：`D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A2_loader_smoke\` **无法写入**（本会话文件沙箱拒绝工作区外写入，且无审批通道可用；已尝试 pwsh/文件工具 + 升级均失败）。**全部 evidence 已完整落盘到 staging**，需审计侧转移至 vault：

**`D:\Claude project\magicmida-rs\evidence_staging\R6_A2_loader_smoke\`**
```
evidence_index.json                 # 实验总索引 + 判定
attempt_001\cdb_run.log             # cdb 全量日志（-g 缺陷运行，含 .rdata2 崩点）
attempt_001\crash_scene.json        # second-chance 异常现场 JSON
attempt_001\cdb_script_001.txt      # 协议脚本
attempt_002\cdb_run.log             # cdb 全量日志（协议修正，断点完整命中）
attempt_002\cdb_run_002.log         # 同（备份副本）
attempt_002\hit_timeline.json       # 命中时间线 + 异常现场 JSON
attempt_002\cdb_script_002.txt      # 协议脚本
attempt_003\cdb_run.log             # cdb 全量日志（复现运行）
attempt_003\cdb_console_003.txt     # stdout 完整捕获
attempt_003\hit_timeline.json       # 命中时间线 + 异常现场 JSON
```

### Repo
`docs/GTO_R6_A2_LOADER_SMOKE_REPORT.md`（本文件）— 判定 A2-FAIL + 判据对照表 + raw 日志指针。

## 八、禁止项复核（工单 §5）

- ✅ 未修改 `dd_restored.exe` 任何字节（前后哈希一致）
- ✅ 未写入/patch 目标进程内存（仅 cdb 原生 bp 断点，断点字节由调试器管理）
- ✅ 本报告为 diagnostic，非 acceptance/loader-pass 声明
- ✅ 未触碰 Oreans 门、未触碰 R5 冻结语义

## 九、后续（供总审计）

1. A2-FAIL 证据（时间线 + 双崩点）交总审计做根因分析/假设修正
2. 建议：确认 `.rdata0` 崩点与 `.rdata2` 崩点是否同源（resolver 垃圾跳转）；若修复路径涉及 dump 保留原始 Import/IAT 目录，需 H6 行为验证设计
3. vault 转移：staging → `D:\MidaVault\lab\evidence\gto_cold_start_heap_rebase_1\R6_A2_loader_smoke\attempt_NNN\`
