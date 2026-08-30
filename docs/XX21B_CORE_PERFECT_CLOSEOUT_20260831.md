# XX-21B core.dll 还原线战役收官总结（T017→T026）

- 收官裁定：老板 2026-08-31 "先收官A"（D-055）· 账本冻结 **XC-XXI-B 17/4** · 全程红线未破
- 战役问题（T0.5 终判）：宿主 a852880a + 会话干净重产候选组合，Run 触发后 Run 线程 RIP 是否落入 urlmon.dll（T0.5 FULL 三态判据）
- **终态裁定：Run verdict = PARTIAL 定档（GUI 层证据 + RIP 级结构性不可达证明 P-11×C-8，T018）；FULL 未达成；剩余阻塞 = Themida VM 内部状态机（黑盒观测边界），快照重建路线经我方十票证据链 + 外部专家佐证（D-054）判死。**

## 一、十连因果链（每票一个决定性结论，8 格实弹 + 3 张零格离线票）

| 票 | 终态 | 格 | 决定性结论 |
|---|---|---|---|
| T017 | tool-blockage | 9→10 | B1' 产物 Run 到达 GUI 业务层 3/3（PigToGoLicenseDialog、无 AV）；RIP 证据系统性不可得 = **P-11**（环境清零非附加进程 GetThreadContext） |
| T018 | AV 5/5 STOP | 10→11 | 调试泵 harness 建成（1361 行）；**C-8** = 附加调试 → 壳扣发 .text 解密（密文 586db5df vs 明文 41574156）；**Run verdict PARTIAL 定档**（多 attempts = 1 格先例） |
| T019 | AV STOP | 11→12 | 根因修正（总指挥取证）：陈旧指针在**候选**不在宿主 = **C-5 会话绑定击中自家重建产物**；P-10 教训（开票前必读 vault 历史） |
| T020+R1 | 零格 | ±0 | 指针清洗 8+ 槽成功；暴露 **BASE-LOCK**（3549 自引用 vs 4 条 reloc → 候选基址锁死，重定位结构性无效） |
| T021 | AV STOP | 12→13 | 总指挥全域普查升格：~230 对齐陈旧指针、≥8 旧会话模块区 → 按已知死区间清洗属结构性盲区，逐族打地鼠不可收敛 |
| T022 | STOP（3 任务） | 13→14 | 当前 boot 活体重产（`fix_hardcoded_addresses` dump 时重锚 3500 指针）→ **C-5 对管线产出路径结构性关闭**；普查器 v2 五类分类学 + 判别力锚点（094f5401 hard=144 FAIL / 096f3bdf hard=0 PASS）；新阻塞 = **C-9**（宿主+重产候选引导期 exit(0)，3/3+3/3） |
| T023 | 诊断达成 | 14→15 | exit 归因：宿主侧 CRT `_exit`→ExitProcess(0)，决策者 msvcrt+0x3e2c9 字节级，DllMain 返回后 2.4ms；EP 判别位排除加载器初始化失败 |
| T024 | 零格 | ±0 | C-9 = 宿主 Themida VM 区查询沉睡 core 失败 → exit(0)（静态不可达）；两代宿主 .text 逐字节一致（"新宿主更严"子分支否决）；候选侧退出三查排除 |
| T025 | **结局(a) C-9 破解** | 15→16 | 根因实弹证实 = T0.4 固化 NOP stub（`31 c0 ff c0 c3`）阉割壳自举 → 宿主查询失败；变体 7b470117（EP 0x1027c0→0x8a0108，恰 3 字节差异）宿主存活不再退出；**新观测 C-10**（存活无窗口）；C-8 未触发 = 泵兼容自举变体 |
| T026 | 新阻塞定性 2/2 | 16→17 | 深观测 3×180s 零窗口（迟到排除）；1 线程 .winlice VM 区单核满速轮询 + Run 线程 100% 阻塞 NtWaitForSingleObject（D-053 修正 worker 丢位 0x60404 与"条件变量"误定性）；urlmon 0 命中、IAT 槽/页零变化、无 AV → **FULL 未达成** |

外部专家佐证（D-054，2026-08-31）：C-10 表征 = SecureEngine "silent tamper response" 典型指纹；快照重建对 WinLicense DLL = 社区长期结论的死路（环境指纹密钥源料 + 滚动解密/就地擦除 + 句柄绑定）；总指挥修正专家三处（mock 方案改泵 API 层截获 / 无码时 Q5 只能大概率 / 等待句柄应为新进程内合法对象、缺 signal 侧）。

## 二、四大缺陷终态

| 缺陷 | 终态 | 证据锚点 |
|---|---|---|
| C-5 会话指针 | **管线路径结构性关闭**（dump 时重锚 + 普查器 v2 零残留） | T022；判别锚点 094f5401/096f3bdf |
| C-8 反调试扣解密 | 定性完整；泵与自举变体兼容 | T018 字节级；T025 attach_changed=False |
| C-9 引导期 exit(0) | **破解**（EP 字段 4 字节修复，根因实弹证实） | T023/T024/T025 三票链 |
| C-10 VM 状态机卡死 | 定性到黑盒边界；工作假设 = silent tamper response（外证级）；修复需 VM 还原（GVM-0 量级），超本战役授权 | T026 2/2；D-053/D-054 |

## 三、平台资产清单（全部可复算、已入库）

1. **会话干净候选管线**：T0.4 配方（`/dump-module --keep-runtime-base` 固化 + dump 时指针重锚 + EP 处置）——产出绑 boot 的研究级快照重建件
2. **普查器 v2**（`tools/xx21b_session_pointer_census.py`）：全域 0x7ff0-0x7fff 扫描、五类分类学（sentinel/nan_double/inherited_baseline/code_immediate_context/cross_field_rva）、判别力锚点、selftest 6/6
3. **退出漏斗诊断**（`tools/xx21b_c9_exit_trace.py`）：int3 四断点（退出漏斗动态导出解析，序数间接寻址）+ 候选 EP 判别位 + re-arm TF 引擎
4. **三态 UI 驱动 harness**（`tools/xx21b_t05_ui_drive_pcell.py` + boot pcell）：三态判定语义、深观测（180s 窗口轮询 + 全线程 RIP 采样）、页快照
5. **证据库六座**：`D:/MidaVault/lab/evidence/{xx21b_t05, xx21b_repro, xx21b_c9, xx21b_c9_static, xx21b_boot, xx21b_threestate}/`（泵事件 ndjson、断点命中流、diff 证明、普查结果、INDEX sha 登记）
6. **知识资产**：C-5/C-8/C-9/C-10 终态定性、BASE-LOCK、P-2b/P-4/P-8/P-9/P-10/P-11 方法论教训、普查五类分类学

## 四、诚实边界声明

- 本战役**不是"完美脱壳"**：产物 = 研究级快照重建件（可加载、宿主可存活），T0.5 FULL（urlmon 路径级等价）未达成。
- Run verdict 终态 = **PARTIAL**（GUI 层证据 + RIP 级结构性不可能证明），不是 FULL，也不是"基本完成"。
- C-10 机制为工作假设（外证级）：VM 内部等待/信号逻辑未本地实证，黑盒观测已到边界。
- 快照重建路线对 WinLicense 保护的 DLL 判死：我方证据（C-5 修完指针仍不够、EP 修回仍卡 VM 边界）+ 外部佐证（D-054）双重支撑；此结论不因未来意愿改变。
- 红线全程未破：`NO_BYPASS=1`；样品/产物零外发；零伪造证据；零越界改动；workers 零 git 写操作。

## 五、账目与移交

- **账本**：XC-XXI-B 终态 **17/4**（T017→T026 段耗 8 格；T020/T020R1/T024 三张零格离线票）。
- **git**：分支 `oreans/two-sample-mainline` 对自身上游 **ahead 45**——推送决策按 D-010 待老板逐次确认；推送前建议 `cargo deny check advisories`（本机离线跑不了）。
- **B 项目（CORE-REWRITE 干净重写）**：老板 2026-08-31 裁定 = **独立项目，不属本项目**（本项目 = 还原研究；B = 正向工程）。本战役证据库对 B 只读可引用（2 导出契约 GetAppVersion/Run、后端端点清单、黑盒行为记录）；B 入场券 = 权利依据 + 新服务器端点清单，另立授权。
- **遗留小项（暂缓，非遗留债务）**：TASK-007（GVM-0 定向 dump，D-012 已批未开跑）、clippy 基线门修复（D-031 F3）、§九 GTO-UI anchor 清理、mod.rs LifecycleError 归类测试、load 探针 cdb 变体。
- 逐票执行报告：`runs/20260830-TASK-021.md` … `runs/20260831-TASK-026.md`；决策链：D-034 → D-055。
