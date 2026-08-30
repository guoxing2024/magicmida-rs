# TASK-021 — T0.5 三态重跑（清洗后候选路线）：收官之战

✅ **已授权 —— 授权令牌（必须在报告第一节原文回抄）**：
> `老板 · 2026-08-30 · 原话"批准"（按全案解释：批准 TASK-021 = T0.5 三态重跑（清洗后候选路线），实弹 1 格，账本 XC-XXI-B 12/4 → 13/4；判定语义与 T017/T018/T019 逐字一致，基址硬门与 .winlice 残留风险注记以票面为准）· 前置由总指挥亲验（2026-08-30）：清洗件 core_perfect_candidate_cleaned_R1.dll（094f5401…）在 vault 且经总指挥逐槽独立验证 8/8（D-041）；宿主 a852880a / config.ini 在位；HEAD = 1bf8b86；BootTime = 10:05:53.549（连续无重启）`

- **岗位**：developer（实弹：调试端口附加运行 B1' 宿主 + 清洗后候选 core + UI 事件驱动；单 worker 连续执行）
- **账本**：XC-XXI-B 12/4 → **13/4**（1 格。本单内多次驱动尝试仍记 1 格——T015/T017/T018/T019 先例；**若中途判断需要重新 `/unpack` 或重做清洗 → 停，另立单另批格**）

## 背景（收官之战的前置全部就绪）

- **T017**：非附加下宿主+原版 core 跑到 GUI 业务层，但外部 RIP 采样被环境垫零（P-11）。
- **T018**：调试端口泵可采真实 RIP，但原版 core 附加即死（C-8 扣解密——因 T017/T018 派单部署了原版 core，P-10 失误，D-037 记档）。
- **T019**：换完美候选后 C-8 消失（Run 字节明文），但候选自带 dump 会话陈旧 ntdll 指针（C-5）→ 宿主初始化消费即 AV（worker 归因"宿主"被总指挥法证纠正，D-038）。
- **T020+R1**：候选会话指针清洗完成——8 槽全部指向当前会话（总指挥逐槽独立验证 8/8，D-041），对齐死区间复扫归零；13 个 `.winlice` 非对齐残留如实入册（不盲改）。
- **判定语义**：与 T017/T018/T019 逐字一致（FULL / 新阻塞 / AV / 附加改变行为）。**FULL = 路径级结论**（Run→urlmon 在"宿主 a852880a + 清洗候选 core"组合上可达），≠ "完全行为等价"（T019 票面语义边界沿用）。

## 任务

### 1. 修改 `tools/xx21b_t05_ui_drive_pcell.py`（授权；最小 diff，其余机制零改动）

1. **sha 门更新**：`CAND_SHA` → `094f5401…`（清洗件全文 sha 见 vault `task020_cleanse/core_perfect_candidate_cleaned_R1.dll`）；HOST/CONFIG 不变（a852880a / cde9be13）。
2. **基址硬门（新增，本单核心保险丝）**：候选首选基址从其 PE 头 ImageBase **动态读取**（不硬编码），core.dll 实际加载基址从 LOAD_DLL 事件/enum_modules **动态读取**；两者不等 → `FAIL_CORE_BASE_RELOCATED` fail-loud，**在触发 Run 之前终止**（候选 3549 个自引用指针基址锁死、`.reloc` 仅 4 条——重定位即必败，T019 实测被重定位过；这道门防止把实验烧在注定失败的运行上）。一致 → 记录 `base_agreement=true` 继续。
3. **run_head 明文预检**：触发 Run 前读取映射后 run_head 字节，预期明文 prologue（非 C-8 加密态）——异常即 fail-loud。
4. **保留 T019 全部机制**：`DEBUG_ONLY_THIS_PROCESS` + 同线程泵全量即时消费 + CREATE_THREAD 调试句柄 RIP 采样（不 OpenThread）+ EXCEPTION 全记录（`0x80000003`/`0xc000008e` 引导期 CONTINUE、其余 NOT_HANDLED）+ 泵健康自证 + `attach_changed_behavior` 上报 + 导出动态解析 + sha fail-closed + 防火墙只读核实 + `NO_BYPASS=1`。

### 2. 实弹执行（1 格）

- 部署：vault 复制宿主 a852880a → `lab/xx21b_run_pcell/rev2_unpacked.exe`、清洗件 094f5401 → `lab/xx21b_run_pcell/core.dll`、config.ini（cde9be13）；sha 三核 fail-closed。
- 执行 ≥2 次驱动（三态判定需 ≥2 次可复现）；每趟证据 JSON + 泵日志落 `lab/xx21b_run_pcell/`，**收尾前先拷入 vault** `D:/MidaVault/lab/evidence/xx21b_t05/`（并入 INDEX.md）。

## 验收标准（每条要真原始输出含退出码）

1. **三态判定（证据源 = 调试端口，语义逐字沿用）**：
   - **FULL**：Run 触发后 RIP 采样落入 urlmon.dll 模块区间、进程存活、≥2 次驱动可复现 → 熊熊 Run verdict PARTIAL → **FULL**，战役收官；
   - **新阻塞**：RIP 稳定卡在新位置（真实采样值）→ verdict 仍 PARTIAL，证据上报 → **STOP**；
   - **AV**：EXCEPTION 事件（地址/码）或异常退出 → 证据上报 → **STOP**；**若 AV 地址落在旧 ntdll 死区间 [0x7ffeeb320000,+0x300000) 或旧 urlmon 区间 → 明确标注"`.winlice` 残留命中"**（13 个已入册残留之一）→ STOP；
   - **附加改变行为**（GUI 层不再出现等）→ 如实上报 → **STOP**；
   - **基址硬门触发**（`FAIL_CORE_BASE_RELOCATED`）→ 如实记录 → **STOP**（这是环境事实不是失败，重跑策略由总指挥裁定）。
2. **调试泵健康自证**：事件全消费、无冻结征兆（延续 T018/T019 判据）。
3. **基址一致性记录**：`base_agreement` 字段进每趟证据（实际 vs 首选，动态读取）。
4. 脚本 diff + 判定 + 全部原始输出进报告；结论按 `[已验证]`/`[推断]`/`[存疑]` 标注。
5. **零越界**：只改 `tools/xx21b_t05_ui_drive_pcell.py`（+ 复用 lab 部署目录与 vault 证据目录）；生产代码 `crates/` 一行不动；T017/T018 两套脚本与 T020 清洗脚本不改；git 只读。
6. **开跑前自查**：BootTime 仍 = `2026-08-30 10:05:53.549` 连续无重启（变了 → STOP 上报勿硬跑——宿主与清洗候选都绑定本 boot，C-4/B/C-5 未根治）；部署三件 sha 复核；防火墙 BLOCK 现状核实（未拦截 → STOP 请示，不许真联网）。
7. 临时文件逐个删除；vault 证据先行；报告第一节回抄授权令牌。

## 红线（违反即整单作废）

`NO_BYPASS=1`；不真联网、不改防火墙；样品/产物不外发、产物只在本机运行；不写 `C:\Windows`；不新增依赖；样品身份哈希不匹配即 STOP；同一验收标准连续 2 次不通过 → 停下写报告。

## 交付物

- `runs/20260830-TASK-021.md`（令牌回抄 + 脚本 diff + 三态判定 + 泵健康自证 + 基址一致性记录 + 全部原始输出 + 「我没做的事 / 我不确定的事」）
- vault `D:/MidaVault/lab/evidence/xx21b_t05/`（新证据并入 + INDEX.md 更新）
- 工作区留改动给总指挥，**不提交**。
