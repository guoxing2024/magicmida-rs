# GTO-H5-STARTUP-ORDER-AND-OEP-ATTRIBUTION-2 — 完成报告

> status: COMPLETE — startup order observed, OEP provenance assessed, root cause identified
> class: DIAGNOSTIC (NOT ACCEPTANCE EVIDENCE)
> restrictions honored: layout A only; no code fixes; GTO-H5-LIVE-AUTHORIZATION-2 not granted

## 一、启动顺序观察（cdb 固定断点，layout A）

### Candidate（gto_unpacked.exe, layout_A）
TLS0 0x141728972 → 0x16f44a8 → 0x16f6bbf → 0x1703d8d → 0x1417223b2 (API resolver) → **AV 0x142934089 (.rdata2)**

### Protected reference（artifact.exe）
TLS0 0x141728972 → 0x16f44a8 → 0x16f6bbf → 0x1703d8d → 0x1417223b2 (API resolver) → **正常返回** → ENTRY 0x1416fb532 → 继续

### 每点记录
- TLS0: 标准 ntdll TLS 链（ImageTlsCallbackCaller→LdrpCallTlsInitializers→LdrpInitializeProcess），rdx=1 (DLL_PROCESS_ATTACH)，代码字节两文件一致
- resolver 0x1417223b2: 两文件字节一致（push rdx; mov [rsp+18h], 0x89a7201; lea rsp,[rsp+18h]; call ...）
- candidate AV: 读 0x9FD548（未映射），rbp 垃圾，栈垃圾

## 二、OEP provenance
- **OEP-A 0x140091E61 在两个目标中都从未命中** —— H4-B runtime_rip OEP 不是实际执行入口
- 实际执行入口：protected = 0x1416fb532（PE entry），candidate = 0x142d21000（.boot，dump 改写）
- candidate 在到达 entry 之前就崩溃（TLS 链内），所以 **entry/OEP 差异是症状，不是直接原因**

## 三、根因（确定的机制，非假设）
**dump 器重建了 candidate PE 头的数据目录：**
- IMPORT: 0x17dc3e8 → 0x2d1e000
- IAT: 0x159f000 → 0x12c000
- EXPORT: 0x17f13e8 → 0x2e51000
- entry: 0x16fb532 → 0x2d21000

**Themida 的 TLS 期 API resolver（0x1417223b2）读取 Import Directory 解析加密 API hash（0x89a7201）**：
- protected: 读到原始 Import Directory（0x17dc3e8）→ 解析正确 → 返回 → entry
- candidate: 读到 dump 重建的 Import Directory（0x2d1e000）→ 解析到错误目标 → 跳入 .rdata2 乱码 → 0xC0000005

**排除项**（均有证据）：
- TLS callback 机制本身（两目标标准 ntdll 链，正常执行）
- .rdata0/.rdata2 可执行特性（两文件一致，原 Themida 布局）
- .rdata1 运行时内容（两目标运行时都是外部地址表，一致）
- 加密代码未解密（代码字节两文件完全一致，protected 能跑）
- boot stub（candidate 从未到达 entry）

## 四、seal v3（item 7）
- raw_disk_manifest_v3.json: 46 files（含 legacy manifest 61f62611… 作为第 46 个磁盘文件）
- self.path 修正为 raw_disk_manifest_v3.json
- seal_anchor_v3.json: whole-file + zeroed-self hash 双锚
- 独立复算 MATCH

## 五、派单 item 状态
| item | 状态 |
|---|---|
| 1 冻结 + overlay 撤回错误归因 | DONE（H5_correction_overlay_loader_failure.json + startup_order_attribution_v2） |
| 2 仅 layout A diagnostic | DONE |
| 3 固定基址断点 + 严格命中顺序 + 每点 thread/reg/stack/ret/±32B | DONE（见 evidence） |
| 4 软件断点标记 diagnostic mutation | DONE（NOT ACCEPTANCE EVIDENCE） |
| 5 protected 同类观察对比 | DONE（hit order 对照） |
| 6 分流 | DONE → H4-B OEP/import-provenance reopen（设计，未授权修复） |
| 7 seal v3 | DONE |
| 8 只归因 + 设计，不修代码，不授权 | DONE |

## 六、下一步（需总指挥）
1. 审阅根因（import 目录重建破坏 Themida TLS 期 API 解析）
2. 决定修复路径（候选：dump 保留原始 Import/IAT 目录；或解析器改用原始表；或 TLS 期后重定位——需设计评审）
3. 设计 → 测试 → H6 回归 → 重走受影响 H4 门 → 新 attestation → GTO-H5-LIVE-AUTHORIZATION-2
