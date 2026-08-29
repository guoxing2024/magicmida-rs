# XX21B T0.5 — Run UI 事件驱动补测：环境阻断报告（Run verdict 维持 PARTIAL）

**任务**: T0.5 · core.dll 的 Run UI 事件驱动补测（宿主 UI 事件触发 URLDownloadToFileA 实调用 → Run verdict PARTIAL→FULL）
**执行**: worker · 2026-08-29 · NO_BYPASS=1 全程 · 网络 deny_all 保持
**授权**: XC-XXI §七 Run 豁免（UI 事件驱动属 Run 补测延续）
**基线**: XX21B Step1 Run 业务链 FULL，URLDownloadToFileA 调用点就绪（IAT 槽 0x16f300 = urlmon!URLDownloadToFileA 真实地址），实际调用未触发（阻塞于 GUI 消息循环 NtUserMessageCall）→ PARTIAL
**输入核实**: 候选 `core_perfect_candidate.dll` sha256 `3650ea6c0a88c731...` ✅（部署名 core.dll）；宿主 `rev2_unpacked.exe` sha256 `36043cb4e82a500d...` ✅（lab=vault 一致）；config.ini `[Loader] DllVersion=1.1` ✅
**结果**: **BLOCKED_ENV（环境级阻断）** — 宿主在当前启动会话无法启动（启动即 AV），Run UI 事件驱动未能执行，Run verdict 维持 PARTIAL

---

## 1. 环境检查与清理（红线前置）

| 项 | 结果 |
|---|---|
| 残留进程（rev2_unpacked/loader/cdb） | 无 ✅ |
| 防火墙规则 | 4 条 BLOCK 就位：`BLOCK_XX21B_RUNUI_HOST`（指向本部署目录）、`BLOCK_XX21B_REV2_HOST`、`BLOCK_GTO_TMP`、`BLOCK_GTO_LAUNCHER` ✅ |
| 部署目录 | `lab/xx21b_run_ui/`：宿主+候选 core.dll+config.ini，sha256 全匹配 ✅ |
| 工具链 | Python 3.13 + cdb 10.0.26100 就绪；UI 驱动脚本 `tools/xx21b_t05_ui_drive.py`（上次尝试遗留，已修复 `_win_thread` 误存 PID bug + 补 PostThreadMessage 线程队列驱动 + 模块加载轮询 + attach 模式 + 0.03s 高密采样）|

---

## 2. 宿主启动失败（决定性发现）

### 2.1 现象
- **dry 预检**：宿主启动 40s 内 core.dll 未在固定基址 `0x7FFE1DA10000` 加载（FAIL_CORE_NOT_LOADED）→ 宿主自身已崩溃
- **直接启动**（NO_BYPASS=1）：6s 内进程退出码 `0xC0000005`（ACCESS_VIOLATION）
- **cdb 诊断×5**：启动早期（IMM32.DLL 加载后、core.dll 加载前）即 AV `c0000005`，与 TSBX/调试器在场无关

### 2.2 根因（字节级证据链）
1. **机器重启**：`2026-08-29 07:58:23`（Win32_OperatingSystem.LastBootUpTime）→ 系统 DLL ASLR 重随机化
   - 上一工作会话（03:44 前，Step1/上次 cdb 会话）ntdll 基址：`0x7ffeeb320000`
   - 当前会话 ntdll 基址：`0x7ffa952a0000`
2. **样品文件硬编码陈旧指针**：宿主 `rev2_unpacked.exe` RVA `0x112c10`（.bss）文件字节 `90 63 42 eb fe 7f 00 00` = `0x7ffeeb426390`（= 旧 ntdll `0x7ffeeb320000` + `0x106390`）——**陈旧 ntdll 绝对地址直接写死在样品文件中**（脱壳时解析/固化，未在新启动会话重定位）
3. **启动期调用**：宿主 RVA `0x21cc0-0x21cd8`（cdb 反汇编）：
   ```
   mov  rax, qword ptr [rev2_unpacked+0x112c10]   ; rax = 0x7ffeeb426390 (陈旧)
   test rax,rax / je +0x21d0e
   lea  rdx,[rev2_unpacked+0x20f80]
   mov  ecx,1
   call rax                                        ; 指令取指 AV
   ```
4. **AV 现场**（cdb）：RIP=RAX=`0x7ffeeb426390`（无加载模块覆盖）；kb 栈：`0x7ffeeb426390` ← `rev2_unpacked+0x21cda` ← ntdll LdrInitializeThunk 加载链（CRT/TLS 初始化路径）

### 2.3 结论
宿主 `rev2_unpacked.exe` **ASLR 绑定旧启动会话**：其数据区固化了一个上一会话 ntdll 的绝对地址，07:58 重启后该地址无映射 → 启动初始化期指令取指 AV → 进程崩溃于 **core.dll 加载之前**。

> 这解释了为何 08-28 12:30 脱壳后至 08-29 03:44 全部会话可运行（同一启动会话、ASLR 未变），而 07:58 重启后必然崩溃（直接启动与调试器下均复现）。

---

## 3. Run UI 事件驱动未执行（阻断原因）

- Run 需宿主进入 GUI 消息循环后方可由 UI 事件驱动（基线阻塞点）；但宿主**无法完成启动**（core.dll 未达加载、无窗口、无消息循环）→ UI 事件驱动无从施加
- 既定驱动面已就绪（`tools/xx21b_t05_ui_drive.py`）：PostThreadMessage 线程队列 + SendMessage/PostMessage 窗口事件电池（WM_NULL/WM_PAINT/WM_TIMER/WM_USER/WM_312/键盘/激活）+ BM_CLICK/WM_COMMAND/鼠标/计时器风暴 + 延后沉降采样
- **所需 UI 事件类型**：N/A（阻塞点不在 UI 事件类型，而在宿主启动本身）

---

## 4. deny_all 落实（红线保持）

| 观测 | 结果 |
|---|---|
| 防火墙 | `BLOCK_XX21B_RUNUI_HOST` + `BLOCK_XX21B_REV2_HOST` 出站阻断生效；pfirewall.log 29120 行中 **rev2_unpacked 记录 = 0** |
| ETW（Microsoft-Windows-WinINet） | `t05wininet_live.etl` 2516 事件均非宿主进程（宿主崩溃前未达任何 WinINet 调用）|
| 结论 | deny_all 落实且生效；宿主无真实外联（未触达下载逻辑即崩溃，下载拒绝为预期终态的性质不变）|

---

## 5. T0.5 verdict

```
verdict : BLOCKED_ENV
run     : Run verdict 维持 PARTIAL（基线不变，未达重测）
detail  : 宿主 rev2_unpacked.exe 在当前启动会话（07:58 重启后）启动即 AV（RVA 0x112c10 硬编码陈旧
          ntdll 地址 0x7ffeeb426390，ASLR 已变 → 指令取指 AV c0000005），崩溃于 core.dll 加载之前；
          Run UI 事件驱动无法执行。失败留证据，不静默（证据 JSON 已入 vault）。
blocking: 环境级（宿主 ASLR 绑定旧启动会话），非 UI 事件类型问题
```

## 6. 证据与交付

- **证据 JSON（vault）**: `D:/MidaVault/lab/evidence/xiongxiong_core/xx21b_perfect_output/30c163c98dc10910_t05_run_ui_blocked.json`（sha256 `30c163c98dc1091044cf80ea852baa20435e215f3a21ec7a1a5019ddd1650bab`）——含 verdict+事件序列+RIP 轨迹+AV 根因（文件级字节/代码级反汇编/运行时上下文/deny_all 观测）
- **诊断原始产物（lab/xx21b_run_ui/）**: `cdb_t05_live{1-5}.log`（AV 上下文/反汇编/栈）、`t05_cdb{1-5}.txt`（cdb 脚本）、`t05wininet_live.etl` + `t05wininet_parse.xml`（ETW）、`t05_dry2.json`（预检）
- **账本**: XC-XXI-B **2/4**（T0.5 实弹 attempt 计 1 格；若 owner 裁定环境阻断不计格可回退至 1/4）
- **INDEX**: `INDEX_XX21B.json` 更新至 13 条

## 7. 建议（待 owner 决策）

1. **重脱壳**：在新启动会话对原版宿主重新脱壳产出新的 rev2_unpacked（解决 ASLR 绑定），随后重跑 T0.5 UI 事件驱动（脚本已就绪）
2. **ASLR 匹配环境**：提供与脱壳时一致的运行环境（重启前快照/特定启动参数），宿主可启动后重跑
3. **不推荐**运行时修补陈旧指针（违背 NO_BYPASS/禁止改样品红线），不伪造证据

*worker · XC-XXI-B T0.5 · 2026-08-29*
