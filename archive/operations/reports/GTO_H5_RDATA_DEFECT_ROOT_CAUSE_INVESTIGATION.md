# GTO-H5 .rdata 段特性根因调查（WO-002）


> **编者注（WO-802, 2026-08-22）**: 本文中 "Themida" 均为未经厂商确证的启发式称谓。" 按壳归因结论（docs/GTO_PACKER_ATTRIBUTION_REPORT.md），正确分级为 **suspected-SecureEngine-class**（具体版本 **unverified**）。历史叙事事实不改写，仅断言强度分级。


**依据**: WORK_ORDERS_CORRECTION.md WO-002（手动代码审查，规避安全护栏）  
**状态**: COMPLETE — 根因链条定位到代码级

## 一、结论（先给答案）

**.rdata0/.rdata1/.rdata2 的 EXECUTE 特性不是 dumper 合成的——是直接复制自 dump 捕获的宿主内存节表。**  
宿主节表 = Themida 运行时进程的 PE 节表，其中 .rdata0/.rdata2 在受保护输入磁盘上本就带 EXECUTE
（.rdata0=0x60000020, .rdata2=0x68000060，已验证与候选一致）。**dumper 忠实保留了宿主节特性。**

## 二、代码定位（文件:行号）

### 1. 特性复制链条（rebuild 路径）

`crates/pe/src/byte_map.rs`:
- **L329**: `plan_from_memory_image(map, opts)` — 从内存映像 map 构建 rebuild plan
- **L335-339**: `let pe = PeHeader::from_bytes(map)?` — 解析 map 的 PE 节表（dump 捕获的宿主节表）
- **L389**: `let data = section_bytes_from_map(...)` — 节内容来自 map（运行时内存）
- **L391-395**: 
  ```rust
  let chars = if sec.characteristics == 0 {
      DEFAULT_SCN_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
  } else {
      sec.characteristics   // ← 直接复制宿主节特性
  };
  ```
- **L397**: `plan.sections.push(PlannedSection { characteristics: chars, ... })`

`crates/pe/src/rebuild.rs`:
- **L566-567**: `pe.entry_point = plan.entry_point_rva` — 最终 PE entry 来自 plan

### 2. 节内容来源（运行时内存 vs 磁盘）

`crates/pe/src/byte_map.rs` L389 `section_bytes_from_map` — 节原始字节**来自 dump 时的运行时内存**（map）。
这意味着：.rdata0/.rdata1/.rdata2 的**内容** = 进程内存快照（Themida 运行时状态），
**特性** = 宿主节表（与受保护输入磁盘一致）。

### 3. OEP 重定向（.boot stub）

`crates/pe/src/dumper/dump_process.rs`:
- **L1991**: `let output_entry_point = if stage_plan.install_heap_bootstrap { ... }` — GTO R0-B
  安装 plan-driven bootstrap 时，entry 指向 bootstrap（.boot 区域）
- **L2135**: `installed.boot_rva` — boot 段 RVA 用于 entry

## 三、机制回答（WO-002 验收）

| 问题 | 答案 |
|---|---|
| 特性从源 PE 复制？ | **否** — 从 dump 捕获的宿主内存节表复制（map 内 PE 头） |
| 从运行时页保护推断？ | 否 — 直接用节表 characteristics，不推断 |
| 由 dumper 合成？ | 否 — 非零特性原样保留（L391-395） |
| 是否区分"真实代码" vs "运行时恰好可执行的加密数据"？ | **不区分** — dumper 对节特性零语义判断，忠实复制 |

## 四、诚实未知项

1. **map 的来源**：plan_from_memory_image 的 map 由谁构建（dump 时捕获的内存映像）——调用点在
   `pure_rebuild_adapter.rs`（L20 引入 section_bytes_from_map）——但 **live dump 路径**（dump_process）
   是否也走此 rebuild，还是走 output_writer 直写路径，需进一步确认（两路径特性处理可能不同）
2. **dump_process 直写路径**（非 rebuild）：output_writer.rs 直写节头时 characteristics 来源未完全追踪
   （L535/583/604 出现 0x60000020 等常量，其中部分在测试；生产路径需确认）
3. **OEP/boot 重定向的正确性**：.boot stub 的 entry 指向是否应改为原始 Themida entry（0x16fb532）——
   这是 H5 崩溃链的一部分（candidate TLS0 后进入 .boot 而非原始入口）

## 五、结论

- **"dumper 把数据段改成 executable" 假设 = 证伪**（特性是宿主原样，已由字节级对比确认）
- **真正差异在运行时行为**：候选执行 TLS0 后无法按 Themida 语义继续（.boot stub 或 IAT 解析路径问题），
  最终进入 .rdata2 乱码 → AV。**特性本身不是缺陷；内容是运行时快照（含未解密区域）才是关键**
- 与 H5 诊断一致：Import/IAT 回填阴性、runtime IAT 562/562 一致、r9 写入点在加密区不可证明

## 六、后续（WO-003 输入）

修复路径评估需基于：内容（加密区快照）而非特性（正确保留）——候选路径：
- (b) 运行时解密 .rdata 内容（需 Themida 知识，高风险）
- 或 dump 时机后移（Themida 完成解密后）
- 或 entry 语义修正（.boot stub → 原始入口链）
