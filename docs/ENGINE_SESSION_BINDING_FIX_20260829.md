# 引擎根治：消除脱壳产物的会话绑定（T0.7）

> 执行：2026-08-29　执行人：worker（T0.7 派单）
> 任务单：`docs/TASK_BOARD_20260829.md` T0.7（P0，通用型核心）
> 关联审计：`docs/HARDCODING_AUDIT_20260829.md` P0（data_reinit 会话绑定）
> 触发证据：T0.5 实锤——`keep_runtime_base` 产物（熊熊 rev2、core 完美候选）在跨 ASLR 重启后启动即 AV

---

## 一、根因确认（证据链）

### 1.1 T0.5 实弹证据（`docs/XX21B_RUN_UI_UPDATE_20260829.md`）

机器 07:58 重启后系统 DLL ASLR 重随机化：

| 会话 | ntdll 基址 |
|---|---|
| 脱壳时（旧会话） | `0x7ffeeb320000`（产物固化指针 `0x7ffeeb426390` 位于该模块） |
| 重启后（新会话） | `0x7ffa952a0000` |

脱壳宿主 `rev2_unpacked.exe`（`keep_runtime_base` 产物）启动初始化期 RVA `0x112c10` 持有陈旧 ntdll 绝对指针 `0x7ffeeb426390`，`call rax` 取指 AV（c0000005），进程崩溃于 core.dll 加载之前。

### 1.2 代码根因（`crates/pe/src/dumper/data_reinit.rs`）

`is_stale_absolute_pointer`（原始 166-229 行）的判定链：

```
value >= HIGH_ASLR_MODULE_MIN (0x7ff0_0000_0000)  → return false（保留）
```

设计意图是"高 ASLR 模块 VA 需保留直到 `fix_hardcoded_addresses` rebase"（Origin W1 回归：清零会破坏 `call [fn_table]`）。但该保留**不加区分地覆盖了系统 DLL 基址**：

- 目标映像自身的运行时 VA（`0x7ff7…`）→ 在 `fix_hardcoded_addresses` 的 `runtime_start..runtime_end` 范围内 → rebase 修正 → **保留正确**；
- 系统 DLL（ntdll/kernel32/urlmon…）基址（`0x7ffe…`）→ **不在** runtime 范围内（非被 dump 映像的 section）→ rebase 不修正 → 固化到产物 → 跨 ASLR 重启即失效 → **保留错误**。

`keep_runtime_base`（XC-6-A 方案 B）只固定**模块自身**基址；系统 DLL 基址由每次启动的 ASLR 决定，产物无法预知。T0.5 已将问题定性为**通用型引擎缺陷**（非样品问题）：任何 `keep_runtime_base` 产物均为会话绑定、不可移植。

### 1.3 结论

**需要区分两类"高 ASLR 指针"**：
1. 指向被 dump 映像自身（rebase 候选）→ 保留；
2. 指向被 dump 会话中的**其他模块**（系统 DLL / 依赖库，ASLR 随机会话）→ 陈旧会话指针 → 清洗（清零，由加载时重新解析）。

区分依据 = dump 时枚举的"会话模块表"（非映像自身模块的真实基址范围）。

---

## 二、方案设计（T0.7 方案三要素落地）

### 2.1 会话模块表捕获（方案①）

dump 主流程 `dump_process_with_report` 中**已有**可复用基建：

- `remote_modules::take_module_snapshot`（`crates/pe/src/dumper/remote_modules.rs`）：ToolHelp（`CreateToolhelp32Snapshot` → `Module32FirstW/NextW`）枚举目标进程已加载模块，返回 `RemoteModule { base, end_off, size_of_image, name, … }`；
- 主流程 1891 行已有 `module_map: Vec<(String, u64, u64)>`（name, base, end），跳过目标映像自身（`take_module_snapshot` 用 `opts.image_base` 作主模块判别，dump 成功时 `opts.image_base` 恒等于目标映像实际加载基址，主模块被正确排除）。

**决定**：直接复用 `module_map`，不重复造轮子。它恰好满足"系统 DLL 真实基址 + 映像名 + 非模块自身范围"的全部要求。

### 2.2 陈旧指针清洗（方案②）

扩展 `data_reinit` 清洗逻辑（`is_stale_absolute_pointer`）：

- 高 ASLR 带（`value >= HIGH_ASLR_MODULE_MIN`）分支：先查会话模块表
  - **命中**（`base <= value < end`，某模块范围）→ 识别为陈旧会话指针 → `true`（清零，由加载时重新解析）；
  - **未命中**（映像自身 VA / 表中无此模块）→ `false`（保留，维持现状，不误伤）；
- **对照表缺失**（`session_modules` 为空，如模块快照失败）→ 保持历史行为（`false`，永不清理该带）——红线"对照表缺失时保持现状"。

该清洗对**所有 dump 路径**生效（不只 `keep_runtime_base`）：传统 rebase 路径下指向系统 DLL 的裸指针同样会固化失效，命中表即清，属一致修复。64 位限制保持（`reinitialize_zero_filled_data` 原有 `!pe.is_64bit → return 0`，32 位系统 DLL 位于低地址带，走原有对齐启发式，行为不变）。

### 2.3 归档（方案①的"随产物"部分）

新增 best-effort sidecar `<output>.session_modules.json`（与 `coverage_timeline.json` / `post_self_decrypt_timeline.json` 同契约：写失败仅 warn，永不失败 dump）：

```json
{
  "schema_version": "mida.session-modules/v1",
  "candidate_sha256": "<候选 sha256>",
  "modules": [
    { "name": "ntdll.dll",  "base": "0x7ffeeb320000", "end": "0x7ffeeb620000" },
    { "name": "kernel32.dll", "base": "0x7ffa952a0000", "end": "0x7ffa95370000" },
    …
  ]
}
```

使 dump 产物可移植且可审计：消费方（或对旧 dump 重清洗）可凭此表识别并清理固化到旧会话 ASLR 布局的指针。

### 2.4 验收维度（方案③，文档层）

S3"存活"维度增补"**跨 ASLR 重启存活**"（详见 §6.1 与任务板备注）：`keep_runtime_base` 产物必须在跨 ASLR 重启的独立会话中可加载、无启动期 AV。实现状态：**代码就绪，实弹验证待环境允许**。

---

## 三、实现点（代码改动，最小化且可 review）

### 3.1 `crates/pe/src/dumper/data_reinit.rs`（171+/17-）

1. 新增 `pub(crate) type SessionModuleRange = (String, u64, u64);`（name, base, end-exclusive）。
2. `reinitialize_zero_filled_data` 增加参数 `session_modules: &[SessionModuleRange]`，透传至 `clear_process_local_absolute_pointers`。
3. `clear_process_local_absolute_pointers` 增加同名参数，逐槽判定透传 `is_stale_absolute_pointer`。
4. `is_stale_absolute_pointer` 增加参数，高 ASLR 带分支由 `return false` 改为 `return matches_session_module(session_modules, value)`；文档更新为三类判定（补第 3 类）。
5. 新增 `matches_session_module`：`session_modules.iter().any(|(_, base, end)| *base <= value && value < *end)`。
6. 顺手等价修正：`value < MIN || value > MAX` → `!(MIN..=MAX).contains(&value)`（消除 clippy `manual_range_contains`，本就在被改函数内）。
7. 测试：既有 `clears_origin_kernel_garbage_object_head` 全部断言改用空表（回归基线）；新增 2 用例：
   - `clears_stale_session_system_dll_pointers`：T0.5 真实指针 `0x7ffeeb426390` 命中 ntdll 范围 → 清；kernel32 导出地址 → 清；范围边界（end 排他 / base 含）→ 正确；
   - `session_table_missing_or_non_matching_preserves_high_aslr`：空表 / 未命中表 / 映像自身 VA → 全部保留（不误伤）。

### 3.2 `crates/pe/src/dumper/dump_process.rs`（85+/10-）

1. 2240 行 `reinitialize_zero_filled_data` 调用追加 `&module_map`（复用 1891 行已捕获的会话模块表；模块快照失败 → 空表 → 清洗保持现状）。
2. 新增 `persist_session_modules_sidecar(opts, candidate_bytes, session_modules)`：序列化 `mida.session-modules/v1` sidecar，写 `<output>.session_modules.json`（best-effort）。
3. `Dump written successfully` 之后调用 sidecar 写入（transform manifest 之后、report 组装之前）。
4. rustfmt 全文件规范化 4 处等价重排（`apply_static_corroboration` 2 处、`dump_process_with_report` 2 处）——行格式变化，无语义变化，保证改动文件 fmt 干净。

### 3.3 未改动

- 样品、验收路径语义、证据/账本：零改动；
- `remote_modules.rs` / `types.rs` / IAT 重建 / `fix_hardcoded_addresses`：零改动（复用现有基建）；
- 无新增硬编码（会话模块表来自运行时枚举，非字面量）。

---

## 四、测试结果

### 4.1 `cargo test -p mida-pe --lib --offline`

```
test result: ok. 1029 passed; 0 failed; 0 ignored
```

data_reinit 模块 6/6（含 2 个新增用例）：

```
test dumper::data_reinit::tests::clears_origin_kernel_garbage_object_head ... ok
test dumper::data_reinit::tests::clears_stale_session_system_dll_pointers ... ok
test dumper::data_reinit::tests::session_table_missing_or_non_matching_preserves_high_aslr ... ok
test dumper::data_reinit::tests::finds_cookie_followed_by_complement ... ok
test dumper::data_reinit::tests::preserves_encoded_image_and_unordered_values ... ok
test dumper::data_reinit::tests::resets_only_ordered_heap_pointer_triples ... ok
```

### 4.2 关键断言（新增用例覆盖的证据语义）

| 场景 | 输入 | 预期 |
|---|---|---|
| 旧会话 ntdll 指针（T0.5 实锤值 `0x7ffeeb426390`）命中表 | `ntdll [0x7ffeeb320000, 0x7ffeeb620000)` | 清（stale） |
| kernel32 导出地址命中表 | `kernel32 [0x7ffa952a0000, …)` | 清 |
| 表缺失（空表） | 同一 `0x7ffeeb426390` | 保留（历史行为） |
| 表存在但值未命中（映像自身 VA `0x7ff7…`） | 其他会话表 | 保留（rebase 候选） |
| 表存在但旧 ntdll 不在该表 | 其他会话表 | 保留（不误伤） |
| 边界：`end` 排他 / `base` 含 | `0x7ffeeb620000` / `0x7ffeeb320000` | 保留 / 清 |

---

## 五、门禁结果

| 门禁 | 命令 | 结果 |
|---|---|---|
| check | `cargo check --workspace --lib --bins --offline` | ✅ 通过（exit 0） |
| test | `cargo test -p mida-pe --lib --offline` | ✅ 1029 passed / 0 failed |
| clippy | `cargo clippy --workspace --lib --bins --offline -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else` | ✅ exit 0 / 0 error（三 lint 零命中） |
| fmt | 改动文件 `rustfmt --check` | ✅ dump_process.rs 干净；data_reinit.rs 为 legacy CRLF 文件（HEAD 基线即不过 fmt，与基线一致，行尾未变） |

环境说明：Windows/MSVC 手动设置 `PATH`（VS2022 Professional `VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64`）+ `LIB`（MSVC lib + Windows Kits 10.0.26100.0 um/ucrt）+ `CARGO_INCREMENTAL=0`（VsDevCmd 被拦，与任务执行注意一致）。

新增代码无 clippy warning（`persist_session_modules_sidecar` / `matches_session_module` / 两调用点均零告警）；未引入新的 fmt 违规。

---

## 六、验收维度增补（S3）

### 6.1 S3"存活"维度扩展（文档层）

原定义（README / XX21B 报告）：**S3 survival = load_no_crash N/N 独立进程加载**。

增补为：**S3-survival = load_no_crash + 跨 ASLR 重启存活**——`keep_runtime_base` 产物必须在**跨 ASLR 重启的独立会话**中可加载、无启动期 AV（不再绑定脱壳时旧会话的系统 DLL 绝对地址）。

实现状态：**代码已就绪**（会话模块表清洗 + sidecar 归档）；**实弹验证待环境允许**（见 §七 待验证项）。

落点：本报告 §6、`docs/TASK_BOARD_20260829.md` T0.7 备注。（验收契约 `docs/ACCEPTANCE_CONTRACT.md` 为 R0B 静态内核契约，不含 S1-S4 行为维度定义，故 S3 维度按任务指令落于 TASK_BOARD 备注 + 本报告。）

### 6.2 判定口径（供未来实弹验证）

- 前置：`keep_runtime_base=1` 重脱壳新会话产物（或既有产物重清洗后重脱壳）；
- 步骤：关机/重启（触发系统 DLL ASLR 重随机化）→ 独立进程加载产物 → 检查启动期无 c0000005（重点 RVA：原 T0.5 `0x112c10` 类站点）；
- 通过标准：加载存活 + `load_no_crash` N/N + 无"指向旧会话系统 DLL 的启动期 AV"；
- 对照：清洗前产物同环境必现 AV（T0.5 已实锤）→ 清洗后产物存活，即证明会话绑定消除。

---

## 七、待验证项（环境受限，不强行实弹）

1. **跨 ASLR 重启实弹验证**：需真实系统重启（宿主重启会改变全部系统 DLL 基址）方可验证"清洗后产物在新会话存活"。当前会话无法在单进程内完成"旧会话 dump → 重启 → 新会话加载"闭环（需重启宿主或提供一致 ASLR 环境），按任务执行注意**记录为待验证项，不强行实弹**。判定口径见 §6.2；验证脚本/流程可复用 T0.5 的 `tools/xx21b_t05_ui_drive.py` 与 vault 证据基建。
2. **sidecar 消费端闭环**：`<output>.session_modules.json` 已归档，但"消费方/重清洗工具读取 sidecar 清洗旧 dump"的独立工具链未实现（本单范围仅为 dump 侧清洗 + 归档；消费端为后续工作单候选）。
3. **32 位目标覆盖**：本修复聚焦 64 位（`reinitialize_zero_filled_data` 原有限制）；32 位进程系统 DLL 低地址带走原有启发式，跨会话行为未变（未引入回归，但未增补 32 位专项用例）。

## 八、阻塞点

- **无代码级阻塞点**。环境级限制：跨重启实弹验证依赖真实重启/宿主（见 §七.1），不属于代码缺陷；VsDevCmd 被拦已用手动 PATH/LIB 绕过。
- 相关遗留（非本单范围，保持透明）：T0.5 Run UI 事件驱动补测仍受会话绑定宿主导航限制，需 owner 决策（新会话重脱壳或提供一致 ASLR 环境）——本单根治后，新会话重脱壳产物将不再绑定旧会话，可作为其前置条件之一。

---

## 九、证据索引

| 证据 | 位置 |
|---|---|
| 根因审计（P0 定性） | `docs/HARDCODING_AUDIT_20260829.md` |
| T0.5 实弹 AV 证据 | `docs/XX21B_RUN_UI_UPDATE_20260829.md` + vault `xx21b_perfect_output/30c163c98dc10910_t05_run_ui_blocked.json` |
| 本修复报告 | `docs/ENGINE_SESSION_BINDING_FIX_20260829.md`（本文件） |
| 任务板 T0.7 验收 | `docs/TASK_BOARD_20260829.md` |
| 代码改动 | `crates/pe/src/dumper/data_reinit.rs`、`crates/pe/src/dumper/dump_process.rs` |
| 门禁输出 | §五 命令（本报告内联记录） |

---

*本报告由 worker 执行 T0.7 产出；代码改动最小化、可 review；未改样品/验收路径语义；未新增硬编码；门禁全绿。*
