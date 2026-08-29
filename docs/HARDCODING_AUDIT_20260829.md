# 硬编码审计报告（通用型引擎政策）

> 审计：2026-08-29　审计人：小助手（总指挥）
> 触发：T0.5 暴露"脱壳产物绑定旧 ASLR 会话"缺陷（ntdll 陈旧指针）；owner 指令"项目所有代码检查，不要有硬编码，我们是通用型项目"
> 工具：`tools/_hardcode_scan.py`（可复用；跳过测试文件与 #[cfg(test)] 块；未来可作 CI 门禁）

## 一、结论（先讲重点）

**生产代码整体干净**：粗扫 1200+ 候选，逐项甄别后**真硬编码仅 6 处字面量 + 1 个引擎级会话绑定问题 + 2 处文档示例**。绝大多数"长 hex"是合法常量（PE 规范特征、FNV-1a 算法常量、PE 签名），大量命中在测试代码（测试向量/夹具，合理豁免）。

| 级别 | 项 | 说明 |
|---|---|---|
| **P0 引擎级** | `data_reinit.rs` 保留高 ASLR 系统 DLL 指针 | 会话绑定根因（T0.5 实锤）：产物跨 ASLR 重启失效。**通用型核心缺陷**（T0.7 已修，见 `docs/ENGINE_SESSION_BINDING_FIX_20260829.md`） |
| **P1 字面量** | 3 处样品哈希（`origin_pure.rs:17`、`oreans_gate.rs:57,63`） | ✅ 已修复（T0.8）：改从 `lab/cases/v2/*.json` manifest 读取，生产代码无样品哈希字面量 |
| **P1 字面量** | 3 处系统目录路径（`dll_exports.rs:232-234`） | ✅ 已修复（T0.9）：改 `GetSystemDirectoryW`/`GetWindowsDirectoryW` 派生，系统目录不假设在 C: |
| **P3 示例** | `args.rs:505`、`lib.rs:161` 的 `0x14013F1E8` | ✅ 已修复（T0.10）：改通用 PE32+ image-base 示例 `0x140000000` 并标注 |
| 豁免 | long_hex 22 处 | PE 特征标志/算法常量/签名（合法）；测试向量（合理） |

## 二、扫描方法

- 范围：`crates/*/src` 生产代码（排除 `*_tests.rs`/`*_test.rs`/`tests/` 目录/`#[cfg(test)]` 块）；
- 模式：Windows 路径字面量 / ≥7 位 hex 地址 / 高 ASLR 带（0x7ffe）/ 已知样品锚定哈希 / vault 路径；
- 未覆盖（后续批次）：`tools/`（Python/PS 工具脚本，多为内部运维）、`lab/`（实验）、文档示例——内部工具硬编码容忍度更高，列入 P2 观察。

## 三、问题清单（证据）

### P0 — data_reinit.rs 会话绑定（引擎级，通用型核心）
- 位置：`crates/pe/src/dumper/data_reinit.rs` `is_stale_absolute_pointer`（166-229 行）
- 机制：`value >= HIGH_ASLR_MODULE_MIN → return false`（保留高 ASLR 模块带指针，注释 "must survive until rebase"）；`keep_runtime_base`（XC-6-A 方案 B）只固定模块自身基址，**系统 DLL 基址随启动 ASLR 变** → 产物固化旧会话 ntdll 绝对地址 → 跨重启启动即 AV（T0.5：RVA 0x112c10 = 旧 ntdll 0x7ffeeb426390，当前 ntdll 0x7ffa952a0000）
- 影响：所有 `keep_runtime_base` 产物（熊熊 rev2、core 完美候选）均为**会话绑定**，非可移植
- 修复方向：dump 时记录会话系统 DLL 基址表 → 重建时识别并清洗指向旧会话系统 DLL 的指针 → 验收契约 S3 增补"跨 ASLR 重启存活"

### P1 — 样品哈希硬编码（3 处）
- `crates/cli/src/origin_pure.rs:17`：`"1af62999…"`（origin_macro protected_input）
- `crates/acceptance/src/oreans_gate.rs:57,63`：origin_macro + lunlun_software sha256
- 修复：从 `lab/cases/v2/*.json` manifest 读取（验收门契约数据源应是 manifest 而非代码字面量）

### P1 — 系统目录路径硬编码（3 处）
- `crates/pe/src/dll_exports.rs:232-234`：`C:\Windows\System32` / `SysWOW64` / `System`
- 修复：`GetSystemDirectoryW`/`GetWindowsDirectoryW`（通用引擎不得假设系统盘为 C:）

### P3 — CLI 帮助示例地址（2 处）
- `crates/cli/src/args.rs:505`、`crates/cli/src/lib.rs:161`：示例 `0x14013F1E8,0x200` → 改通用示例（如 `0x140000000,0x200`）并标注为示例

## 四、门禁建议（后续）

- `tools/_hardcode_scan.py` 升级为 CI 检查：**生产代码出现 win_path / vault_path / sample_hex 即失败**（long_hex 走白名单/人工）；已落盘脚本可直接复用。

## 五、任务单映射

| 任务 | 级别 | 内容 | 状态 |
|---|---|---|---|
| T0.7 | P0 | data_reinit 会话系统 DLL 基址表清洗 + 验收跨重启维度 | ✅ 已完成（`docs/ENGINE_SESSION_BINDING_FIX_20260829.md`；跨重启实弹待验证） |
| T0.8 | P1 | 3 处样品哈希改 manifest 读取 | ✅ 已完成（2026-08-29，见 §六） |
| T0.9 | P1 | 3 处系统目录改 API 查询 | ✅ 已完成（2026-08-29，见 §六） |
| T0.10 | P3 | 2 处示例地址改通用 | ✅ 已完成（2026-08-29，见 §六） |

## 六、执行回执（T0.8/T0.9/T0.10，2026-08-29 worker 批量执行）

### T0.8 样品哈希改 manifest 读取（3 处 → 0 处）
- `crates/cli/src/origin_pure.rs`：删除 `ORIGIN_MACRO_PROTECTED_SHA256` 字面量常量；新增 `origin_macro_protected_sha256()` —— 通过 `include_str!` 在构建期嵌入 `lab/cases/v2/origin_macro.json` 并从 `protected_input` artifact 解析 SHA-256（manifest 为契约数据源，换样品不改代码、重建即可）。`is_origin_macro_protected_input` / `resolve_pure_rebuild` 改为基于 manifest 身份；manifest 不可解析时 **fail-closed**（绝不误判为 Origin，reason 显式标注 "manifest unavailable (fail-closed legacy default)"）。
- `crates/acceptance/src/oreans_gate.rs`：`OreansSampleManifestLock` 仅保留 `case_id` + `manifest_path`（锁 = 哪些 case 是门禁 case + manifest 位置），不再携带哈希字面量；新增 `load_locked_manifest_identity(lock) -> Result<OreansArtifactIdentity, OreansManifestError>`（严格 `CaseManifestV2` 解析 + case_id 核对 + `protected_input` artifact 提取），错误类型 Read/Parse/CaseIdMismatch/NoProtectedInput 全部显式。`evaluate_sample` 改从 manifest 加载预期身份，加载失败 → 门禁失败条目（fail-closed）。
- `crates/acceptance/src/bundle_gate.rs`：生产入口 `evaluate_bundle_gate` 通过 loader 从真实 manifest 取身份；`evaluate_bundle_gate_with_manifest` 注入器类型改为 `Fn(&str) -> Result<Option<OreansArtifactIdentity>, BundleGateError>`；新增 `BundleGateError::Manifest` 变体（manifest 不可读 → 整门 fail-closed）。
- `crates/acceptance/src/preflight.rs`：`check_case_identity` 移除"声明值 vs 代码内嵌锁值"交叉校验（锁值即同一 manifest，交叉校验退化为自比）；保留 case_id 成员校验 + 磁盘重算（真实输入文件 sha/size vs manifest 声明，即运行时真正校验）。
- `crates/acceptance/src/main.rs`：信封校验改经 loader 取身份，manifest 不可读 → 显式 reason（fail-closed）。
- 测试适配：`oreans_gate.rs` 锁清单测试改经 loader；新增 2 个 fail-closed 用例（缺文件 → Read、case_id 不匹配 → CaseIdMismatch、无 protected_input → NoProtectedInput、畸形 → Parse）；`tests/bundle_gate.rs`、`tests/oreans_two_sample_gate.rs`、`cli/src/unpacker/production_e2e.rs` 注入器同步改为身份型。
- 语义不变：哈希值完全相同（来源唯一从 manifest），解析行为等价；manifest 缺失路径由"代码常量"改为"显式错误/fail-closed"。

### T0.9 系统目录改 API 查询（3 处 → 0 处）
- `crates/pe/src/dll_exports.rs`：`find_system_dll(dll_name)` → `find_system_dll(dll_name, system_dirs: &[PathBuf])`（纯函数，目录参数化，离线/解析场景可无 Win32 使用）；新增 `#[cfg(windows)] system_dll_search_dirs()`：`GetSystemDirectoryW`（System32）+ `GetWindowsDirectoryW` 派生 `SysWOW64`/`System`（系统盘不再假设为 C:），API 失败 → 空表（调用点 `warn!` 显式兜底，非静默）；`#[cfg(not(windows))]` 返回空表。
- `crates/pe/src/dumper/dump_process.rs:1231`：调用点先 `system_dll_search_dirs()` 取一次目录表，再逐个 `find_system_dll(name, &dirs)`。
- 新增 2 个纯函数单元测试（命中/未命中/空表）。

### T0.10 CLI 示例地址改通用（2 处 + 1 注释）
- `crates/cli/src/args.rs:505`（错误提示）与 `crates/cli/src/lib.rs:161`（帮助文本）的 `0x14013F1E8,0x200` → `0x140000000,0x200`（通用 PE32+ image base 示例）并标注 "generic PE32+ image-base example"；`args.rs:455` 注释同步。

### 门禁与扫描证据（2026-08-29，Windows/MSVC 手动 PATH）
- `cargo check --workspace --lib --bins --offline`：exit 0
- `cargo test -p mida-pe --lib --offline`：1031 passed（含新增 dll_exports 2 用例）；0 failed
- `cargo test -p mida-acceptance --lib --offline`：253 passed（含新增 fail-closed 2 用例）；0 failed
- `cargo test -p mida-cli --lib --offline`：572 passed / 1 ignored；0 failed
- `cargo test -p mida-acceptance --test bundle_gate --test oreans_two_sample_gate --offline`：exit 0（16 + 43）
- clippy 门禁 `-- -D clippy::unwrap_used -D clippy::expect_used -D clippy::manual_let_else`：exit 0 / 0 error
- `python tools/_hardcode_scan.py`：**sample_hex 0（原 3）、win_path 0（原 3）**；long_hex 22 均为合法常量（PE 特征/算法常量/签名，含 T0.10 通用示例地址，属豁免）
- 改动文件已按 `.gitattributes`（`* text=auto eol=lf`）归一化为 LF；新增代码 rustfmt 对齐（遗留差异均为既有基线）。
- 阻塞点：无。VsDevCmd 被沙箱拦截（既有环境限制），全程采用手动 MSVC PATH（`tools/xx21_msvc_env.cmd` 同款）完成链接。
