# TASK-016R1 — T016 审计补正（微型：1 行行为还原 + 硬编码审计文档增补）

> 总指挥审计 TASK-016 后出具条件通过（见 `docs/DECISIONS.md` D-031）。本单是补正轮，**在 D-030 授权范围内**（同一文件清单、同一"行为中性硬编码清除"处置类别），**不新开账本格、无新授权令牌**——报告第一节回抄 D-030 令牌原文并引用本票号即可。
> 岗位：developer（纯离线，零实弹）。账本：XC-XXI-B 9/4（不变）。

## 背景结论（总指挥审计 2026-08-30，D-031）

TASK-016 的 8 条验收标准中 7 条亲验 PASS（含总指挥自选缝的 preflight 判别力探针：非零值分支禁用 → `scylla_hide_key_set_to_one_fails_loud` 红、exit 101 → 字节级恢复）。两处需补正：

- **F1（行为还原）**：`iat_gap_retarget.rs` 把 `for delta in 1..64u32` 改成了 `for delta in 1..=GAP_NAME_NEIGHBOR_MAX_DELTA`（const=64）。原代码最多搜 63 槽，改后搜 64 槽——**这不是同值改名，是未申报的窗口加宽**，与报告"无一处改变数值、分支"冲突。[已验证：diff 对照]。B1' 端点可证不受影响（`retarget_iat_gap_call_sites` 在 T015 两次实弹日志零输出行、interior-zero 检测要求前后邻居都非零而 B1' 201 槽无 interior zero、sites_seen=0 → 不打补丁 → 产物字节不变），但行为中性铁律按字面执行：还原原窗口。
- **F2（审计完整性）**：`docs/HARDCODING_AUDIT_T016.md` 的"授权文件生产代码无样品级硬编码进入控制流"以全称命题成立为假。`dump_process.rs` 内有整片**既有** GTO-UI 样品锚区未盘点：裸字面量 `0x147868`/`0x147888`（:2298-2299、:2362，AHK cmd 表计数保持路径）；具名补丁常量 `SITE_RVA=0x5c5d`、`TARGET_RVA=0x35520`、`TARGET_RVA=0x364e0`、`CHECK_RVA=0x34dbb`、`CLASS_RVA_SITE=0x34ed4`、`CW_CLASS_RVA=0x34f66`、`STYLE_RVA=0x34f59` 及注释内 0x63f4/0x6757/0x1b10 等。这些全部被 `stage_plan`/`capture_policy`（AhkGto 专属）门控，对 B1'/xx21b 是死代码，但按工单判据（magic RVA 进控制流）必须**进审计报告**，处置需实弹再验证 → 列为 STOP 级待处置，本单不改它们。

## 任务

### 1. F1 行为还原（1 处）

`crates/pe/src/dumper/iat_gap_retarget.rs`：

- `GAP_NAME_NEIGHBOR_MAX_DELTA` 值 `64` → `63`，保持 `for delta in 1..=GAP_NAME_NEIGHBOR_MAX_DELTA` 不变（63 = 原代码 `1..64` 的实际最大搜索槽距，逐位还原原行为）。
- 该 const 的 doc 注释改为如实描述："Max slots searched left/right of an interior-zero slot when guessing the API name from the original continuous import order (the actual probed deltas are 1..=63; matches the pre-TASK-016 `1..64` range). Bounded heuristic: …"（后半句保留原文）。

### 2. F2 审计文档增补（不改任何生产代码）

`docs/HARDCODING_AUDIT_T016.md`：

1. §一.1 与 §八的全称命题改为限定命题：明确"该结论仅覆盖 T014/T015 引入的字面量；既有 GTO-UI 锚区见新增小节"。
2. 新增小节"§九 既有 GTO-UI 样品锚区清单（总指挥审计补录）"：上表全部常量/裸字面量逐项列（位置、值、门控方式、对 B1' 是否可达=不可达），处置栏统一写"既有代码、AhkGto 门控、清除需行为性改动+实弹再验证 → STOP 级，留待下一战役工单"。
3. 补一行勘误：授权清单里的 `iat_completeness.rs` 实际路径是 `crates/pe/src/iat_completeness.rs`（工单误写为 `dumper/` 前缀）；已核对 `201/192` 仅存在于该文件 :281-282 的 doc 注释（诊断说明），原审计结论对该文件仍成立。

### 3. 验收标准（全离线，真退出码）

1. `git diff` 相对补正前工作区**只含**上述 2 个文件；`iat_gap_retarget.rs` 的 delta 循环还原后与 HEAD（2d0f5d2）版语义逐位一致（`1..=63`）。
2. `cargo test -p mida-pe --lib --offline` → exit 0，**1054 passed 不变**；`cargo test -p mida-acceptance --lib --offline` → exit 0，**263 passed 不变**。
3. `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` → 0；`cargo fmt --all -- --check` → 0。`powershell -ExecutionPolicy Bypass -File tools/check_clippy_baseline.ps1`：总指挥已证其为**既有失败**（`too_many_arguments` 基线 61 → 实测 62，62 条命中 0 条由 T016 引入、HEAD 上同为 62，见 D-031 F3）——R1 跑一遍并把失败原样记录进报告增补段即可；**不许改 `_clippy_baseline` / `check_clippy_baseline.ps1` / 任何门文件，也不许为过门重构清单外函数**（修门需老板另授权）。
4. 报告以增补段（≤1 页）贴在 `runs/20260830-TASK-016.md` 末尾（新章节"TASK-016R1 补正"），含上述全部原始输出；第一节回抄 D-030 令牌 + 引用本票号。
5. 零实弹自证（tasklist 无相关进程）；git 只读；临时文件逐个删除。

## 红线

同 TASK-016（零实弹 / git 只读 / 行为中性 / 测试计数只增不减 / 不新增依赖）。**不许顺手改任何其它代码**——F2 只动 `docs/HARDCODING_AUDIT_T016.md`，GTO-UI 区生产代码一行都不许碰。
