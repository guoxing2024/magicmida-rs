# GTO-H5 修复路径设计（WO-102）

**依据**: WO-002（.rdata 段特性根因调查，COMPLETE）+ H5 诊断链（r9 不可证明 / IAT 562/562 一致 / Import-IAT 回填阴性）
**状态**: DESIGN ONLY — 零代码改动，未触碰 H5 未授权代码
**前置**: WO-002 COMPLETE（本设计基于其结论）

---

## 一、WO-002 结论回顾（设计前提）

1. **节 EXECUTE 特性不是缺陷**：`.rdata0/.rdata1/.rdata2` 的 characteristics 是直接复制自 dump 捕获的宿主内存节表（`byte_map.rs:391-395`），与受保护输入磁盘字节一致（.rdata0=0x60000020, .rdata2=0x68000060）。
2. **真正问题是内容**：`.rdata*` 内容是运行时内存快照，包含 Themida 未解密区域 → 候选执行到该区域时读到乱码 → AV（0x142934069 mov r11,[rbp+r9+0x9207] 读垃圾值）。
3. **OEP/entry 分歧**：候选 entry=0x2d21000（.boot）≠ 受保护 entry=0x16fb532（.rdata2）；候选从不到达其真实入口。
4. **r9 最后写入者不可证明**（3MB 加密区 0x142c1d6c3..0x142934069），Import/IAT DataDirectory 回填全部阴性。

---

## 二、候选路径重评（4 条）

### (a) 去除 .rdata0/.rdata1/.rdata2 的 EXECUTE 特性 — **REJECTED**

| 项 | 评估 |
|---|---|
| 原理 | 把 executable 段改为数据段，防止 CPU 把乱码当代码执行 |
| 为什么拒绝 | **WO-002 已证伪前提**：特性本身是宿主原样、非 dumper 合成。改特性 = 伪造输入语义，且 Themida 运行时靠这些段执行解密代码，去掉 EXECUTE 会让候选在更早阶段失败 |
| 验证 | 无离线验证方案（特性正确保留已被字节级对比证实） |
| 结论 | **拒绝** — 修复错误的目标 |

### (b) 运行时解密 .rdata 内容 — **REJECTED（高风险）**

| 项 | 评估 |
|---|---|
| 原理 | 让 dumper 在 dump 前等待 Themida 完成解密，或复现 Themida 解密逻辑 |
| 为什么拒绝 | ① 需 Themida 专有解密知识（未掌握）；② 解密时序依赖运行环境（版本、VM、反调试）不可离线验证；③ 与红线冲突（修码冻结对生产路径有效，H5 未授权）；④ WO-002 诚实未知项 2（live dump 路径 vs rebuild 路径特性处理）未消解 |
| 结论 | **拒绝** — 高风险且不可离线验证 |

### (c) OEP patch（.boot stub → 原始入口 0x16fb532）— **NOT AUTHORIZED**

| 项 | 评估 |
|---|---|
| 原理 | 把 entry 改回受保护程序原始入口，让候选走 Themida 自身入口链 |
| 为什么拒绝 | ① 需要 `GTO-H5-LIVE-AUTHORIZATION-2` 授权（未签发）；② 入口语义修正涉及 H5 核心未授权代码；③ 即使改 entry，候选进入加密区后仍可能 AV（入口链后续同样依赖 Themida 解密状态） |
| 结论 | **拒绝（当前）** — 授权未达，且不解决内容问题 |

### (d) 启动顺序观察（dump 时机后移 / 观察 Themida 自解密完成点）— **SELECTED（设计）**

| 项 | 评估 |
|---|---|
| 原理 | WO-002 结论 6 提出的候选方向：**dump 时机后移**，在 Themida 完成自解密后再捕获，使 .rdata 内容为解密后状态 |
| 为什么可选 | ① 不伪造特性、不改 entry、不注入；② 纯观察性（dump 时机是捕获策略，非目标改写）；③ 有离线验证方案（见 §五） |
| 风险 | Themida 自解密可能依赖反调试/VM，延迟后仍不解密；需授权实测 |
| 结论 | **设计推荐** — 但需 GTO-H5-LIVE-AUTHORIZATION-2 实测授权 |

---

## 三、fail-closed 规则（dumper 无法区分代码 vs 加密数据时）

设计原则：**dumper 对节特性/内容不做语义猜测；无法判断时拒绝产出，而不是猜测**。

### 规则 R1：节内容一致性检查（新增，设计）
- 当 `plan_from_memory_image` 或 `write_output_file` 准备 emit 节内容时，若节具有 EXECUTE 特性**且**内容与受保护输入磁盘节（若可用）字节不一致，dumper **不得**静默产出候选。
- 行为：返回 `PeError::DumpContentMismatch`（或等价），附差异摘要（首个差异偏移、长度）。

### 规则 R2：加密区探测（观察性，不解析）
- 若节内容高熵率（香农熵 > 7.5 bits/byte，抽样 4KB）且节具有 EXECUTE 特性，记录 `encrypted_region_suspect=true` 到 dump manifest，**不修改任何字节**。
- 这是观察而非修复：manifests 记录嫌疑，候选仍产出（fail-open 记录 + fail-closed 于一致性）。

### 规则 R3：特征保留（不变）
- 节 characteristics 永远复制宿主（现状 `byte_map.rs:391-395`），dumper 不合成、不推断。
- 对"代码 vs 加密数据"不可区分时：**保留 + 记录**，绝不猜测。

### 规则 R4：entry 语义
- `.boot` stub 的 entry 指向维持现状（设计阶段不修改）；若实测证明需改，必须走授权流程（GTO-H5-LIVE-AUTHORIZATION-2 或新授权）。

---

## 四、需触碰文件清单（实施时，设计阶段不触碰）

| 文件 | 改动类型 | 用途 |
|---|---|---|
| `crates/pe/src/dumper/types.rs` | 新增 DumpOptions 字段 | `dump_timing: DumpTiming`（Immediate / PostSelfDecrypt） |
| `crates/pe/src/dumper/dump_process.rs` | 新增时机分支 | dump 前等待 Themida 自解密（观察性延迟） |
| `crates/pe/src/byte_map.rs` | 新增一致性检查（R1） | emit 前节内容 vs 输入磁盘对比 |
| `crates/pe/src/dumper/output_writer.rs` | 新增 manifest 字段（R2） | 加密区嫌疑记录 |
| `crates/pe/src/error.rs` | 新增错误变体 | `DumpContentMismatch` |
| `crates/cli/src/commands.rs` | 新增 CLI 开关 | `--dump-timing`（设计阶段不实现） |

> 实施时每文件须过 WO-002 的红线检查（不改函数行为、不碰 ADR7/Oreans 门）。

---

## 五、离线单元测试方案（验收路径）

1. **R1 一致性检查单测**（纯离线，无真实样本）：
   - 构造内存映像 map：节 A 内容 = 输入磁盘节 A 内容（一致）→ 应通过
   - 构造内存映像 map：节 B 内容 ≠ 输入磁盘节 B 内容（翻转若干字节）→ 应返回 `DumpContentMismatch`
   - 无输入磁盘节可对比时 → 走 R2 记录路径（不 fail）
2. **R2 熵探测单测**：
   - 高熵节（随机字节填充 4KB）→ `encrypted_region_suspect=true` 记录
   - 低熵节（全 0 或 ASCII 文本）→ 不记录
3. **特性保留回归**（现有 `pure_parse_serialize` 等测试扩展）：
   - 断言 emit 后节 characteristics == 输入（防未来回归）
4. **不破坏现有基线**：`cargo test --workspace --offline` 2257+/0 fail（doctest 修复后含 0 doctest fail）

---

## 六、仍需真实授权项清单（GTO-H5-LIVE-AUTHORIZATION-2 或后续）

| # | 项 | 说明 |
|---|---|---|
| 1 | dump 时机后移实测 | 观察 Themida 自解密完成点（需真实样本运行） |
| 2 | entry 语义修正验证 | 若 R4 触发，需授权改 entry 并验证 |
| 3 | 解密后 IAT/r9 链重测 | 解密状态下的 resolver 链（0x142934069 读值）验证 |
| 4 | loader smoke 复测 | 9 项 loader smoke 在解密后内容下的行为 |

---

## 七、Oreans 门影响评估

| 门 | 影响 |
|---|---|
| ADR7（17/17 PASS，frozen） | **无影响** — 本设计零代码改动；实施时新增字段/检查不触碰 ADR7 路径 |
| Oreans 两样本门（验证器） | **无影响** — 设计仅涉及 dump 时机与一致性检查，不改变样本门输入 |
| GTO 门控（H0-H6） | H5 保持 `BLOCKED_AT_LOADER_SMOKE`，本设计不声称任何 CLOSED/DELIVERED |

---

## 八、结论

- **推荐路径 (d)**：dump 时机后移（观察 Themida 自解密完成点），配套 fail-closed 一致性检查（R1-R4）。
- **零代码改动**（本设计阶段）；实施需新授权。
- 所有拒绝路径（a/b/c）均有明确理由；无 overclaim。
