# MIDA-ADR-5B Protected Sample Live Validation（如实封版）

> **工作令：** MIDA-ADR-5B —— protected sample live validation（origin_macro + lunlun_software 各 3 次 attempt）。
> **状态：** 执行完成，**如实封版（负结果交付）**。
> **基线：** `0d2d4ef`（ADR-6-CORRECTION-2 封版）。代码修复提交：`6c10980`。
> **性质：** 真实 protected sample 运行（明确授权）；未执行 ScyllaHide；未做差分。

## 1. 结论摘要

```text
控制组（无 MIDA runtime）  6/6  fail-closed exit=1（~10.3s，AntiDebugRuntimeUnavailable evidence）
实验组（有 MIDA runtime）  6/6  Proceed 达成（loader 全链路成功）但 180s 内 unpack 未完成
overall gate verdict:       FAIL（候选未产出；unpack 未在 180s 内完成）
```

**核心发现（负结果，为 ADR-7 提供直接依据）：** MIDA runtime 只覆盖 AD-PROC-002/003
（PEB.BeingDebugged / pShimData）两个 hard-required surface。真实 Themida/WinLicense
样本的完整反调试（EPROCESS.DebugPort、NtQueryInformationProcess、时序、异常行为分析等）
远超当前覆盖：Proceed 后样本渐进死亡（调试事件间隔从毫秒级恶化到 30s→56s→111s→∞），
unpack 流程无法在 180s 内完成，最终 exit=1（无候选）。

## 2. 起始基线与最终提交

```text
起始基线  0d2d4ef  fix(antidebug): ADR-6 correction-2 ...
代码提交  6c10980  fix(antidebug): ADR-5B live-validation fixes - debug-window drain,
                  remote module/export resolution, 64-bit module base
修改文件  crates/cli/src/unpacker/mod.rs           (+70/-1)
          crates/cli/src/unpacker/runtime_loader.rs (+530/-43)
工作树    提交后 untracked=110（docs 98 + lab 12），staged=0，tracked 修改=0
```

## 3. 交付的代码修复（ADR-5B live validation 暴露的 6 个集成缺陷）

ADR-6 loader 此前只在 benign host（同进程 CreateThread）验证过。真实 protected sample
暴露并修复了 6 个致命集成缺陷：

| # | 缺陷 | 修复 |
|---|---|---|
| 1 | CREATE_PROCESS 调试事件窗口内目标所有线程冻结，同步 CreateRemoteThread+wait 永不完成（10s 超时） | CREATE_PROCESS handler 内先 continue 事件解冻，loader 携带 Win32 级 drain 回调（WaitForDebugEvent+ContinueDebugEvent）保持目标存活 |
| 2 | GetExitCodeThread 仅 32 位，LoadLibraryW 的 64 位 HMODULE 被截断 | 裸远程 LoadLibraryW（wrapper stub 会被样本检测）+ PEB.Ldr InMemoryOrderModuleList 遍历恢复完整 64 位基址 |
| 3 | 调试器进程 GetProcAddress 看不到仅加载在目标进程的 DLL 导出 | resolve_mida_exports_remote 从目标内存解析 PE 导出目录 |
| 4 | 导出表 DataDirectory 偏移错误（0x70 应为 0x18+0x70=0x88） | 修正 OptionalHeader 基址偏移 |
| 5 | MSVC link.exe 导出 ordinal 数组是 0-based（Base=1 时 GetAttestation ord=0），func_idx=ord-base 映射错 | ordinal 直接作 AddressOfFunctions 索引 |
| 6 | thunk_call blob 布局 64 字节放不下 91 字节 THUNK_CODE → panic | 分配 0x100，thunk 在 [0..96)，args 在 [96..160) |

修复后：`anti-debug lifecycle: Proceed (MIDA runtime ready)` 在真实 protected sample 上
稳定达成（6/6 attempt）。

## 4. Live 时间线与样本死亡 taxonomy

### 4.1 origin_macro（rt_1，代表性）

```text
13:54:18.975  进程创建 (pid 由 runner 记录)
13:54:22.735  Proceed (MIDA runtime ready)   <- loader 全链路 ~3.8s
13:54:22.770-793  事件密集（LOAD_DLL/CREATE_THREAD，正常）
13:54:53.071  下一事件（+30.3s）              <- 首次明显停滞
13:55:49.001  下一事件（+55.9s）              <- 渐进死亡
之后          事件间隔继续恶化 → 180s 超时，无候选产出
```

### 4.2 样本死亡 taxonomy

```text
死亡模式: 渐进式（非立即退出）。Themida 反调试检测逐层触发：
  1) PEB.BeingDebugged / pShimData  -> 已被 MIDA 覆盖（不触发）
  2) EPROCESS.DebugPort / NtQueryInformationProcess -> 未覆盖（主要嫌疑）
  3) 时序检测（RDTSC/GetTickCount 异常） -> 未覆盖
  4) 异常行为分析（调试器吞异常） -> 未覆盖
  5) 线程行为分析（远程线程/DLL 注入痕迹） -> 未覆盖
最终: 主线程被样本冻结/终止，调试事件流枯竭，unpack 卡死 -> exit=1
```

## 5. 控制组（fail-closed 基线）

无 MIDA_RUNTIME_AUTHORITY/DLL 环境变量，controller 在依赖解析阶段确定性失败：

```text
origin_macro   ctl_1/2/3  exit=1  ~10.3s  candidate=N
lunlun_software ctl_1/2/3  exit=1  ~10.3s  candidate=N
evidence: mida.antidebug-evidence/v1 record_kind=cli-failure decision=fail-closed
          failure_state=CleanupFailed fail_code=CleanupFailed
          cleanup_result=failed (terminate wait TIMEOUT - 样本进程对 TerminateProcess 无响应)
```

## 6. TLS pass 情况

ADR-5B 未产生新的 TLS evidence 侧车：

```text
控制组: 无候选产出 -> 无 TLS evidence（fail-closed 正确阻止了 unpack 流程）
实验组: Proceed 后 unpack 未完成（样本死亡）-> 无候选 -> 无 TLS evidence
TLS pass 判定: 不适用（N/A）—— 与 behavior 独立性的验证被覆盖不足阻断，
             需 ADR-7 扩展 surface 后重测
```

## 7. Overall gate verdict

```text
gate: FAIL（open gate 保持：exit=1，candidate=N）
原因: 反反调试覆盖不足（计划内），非 loader/controller 故障
loader 机制: 已验证（6/6 Proceed）
controller 状态机: 已验证（6/6 Proceed，控制组 6/6 fail-closed）
覆盖缺口: AD-PROC-004/005（DebugPort/NtQIP）、AD-TIM-*、AD-EXC-* 等为 ADR-7 工作项
```

## 8. 验收命令结果

```text
cargo fmt --all -- --check                                     OK
cargo check --workspace --tests --offline                     OK
cargo test --workspace --offline                             OK (全绿)
RUSTFLAGS=-D warnings cargo check --workspace --all-features --tests --offline  OK
git diff --check                                              OK
untracked = 110（基线一致），staged=0，tracked 修改=0            OK
```

## 9. 约束遵守声明

- 执行 protected sample 仅限派单授权的 live validation（6 次 attempt × 2 组）；
- 未执行 ScyllaHide、未复制其源码/配置/二进制、未做差分；
- 未修改 crates/antidebug/**、crates/pe/**、crates/acceptance/**、crates/packers/**、crates/core/**；
  修改仅限 crates/cli/src/unpacker/{mod.rs, runtime_loader.rs}（ADR-6 loader 与 CREATE_PROCESS 接线）；
- 无 DLL/EXE 入库（构建产物在 D:/tmp/magicmida-adr5b-target、D:/MidaVault/lab/evidence/adr5b）；
- 临时 C 测试产物（.obj/.exe）全部清理，工作区无残留；
- 历史 110 个未跟踪文件（docs 98 + lab 12）未触碰。

## 10. 对 ADR-7 的直接输入

```text
1. 优先实现 AD-PROC-004（NtQueryInformationProcess DebugPort 响应清空）——
   样本死亡 taxonomy 的最大嫌疑；
2. 评估 AD-PROC-005（CheckRemoteDebuggerPresent）与 NtQuerySystemInformation；
3. 时序 surface（AD-TIM-001..004）在 PEB surface 稳定后评估；
4. 每次扩展后重跑 ADR-5B 同款 live 验证（180s 窗口，Proceed + unpack 完成双指标）。
```

---

*ADR-5B 如实封版。loader 机制在真实目标上证明可用；反反调试覆盖不足为计划内负结果，
作为 ADR-7 的验收基线与优先级依据。*