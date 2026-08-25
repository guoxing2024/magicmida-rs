# WORK ORDER — IMP-09-CARRIER-R5-R3-SECTION-PRODUCER (EXECUTION DISPATCH)

**派发**: Hermes 总审计，owner 授权转入 IMP-09 支援
**日期**: 2026-08-25
**性质**: 执行既有工单 `WORK_ORDER_IMP-09-CARRIER-R5-R3-SECTION-PRODUCER_20260825.md`（已签发、未执行）
**基线**: HEAD `affb992f2b30b2c9f8243c72296456b5515f6e86`（branch codex/imp09-carrier-r5-r2）

## 0. 总审计补充约束（在原工单之上追加，冲突时以更严者为准）

1. **Correction 硬上限 = 1**：交付若被审计判 FAIL，不允许自行发起第二轮 correction；
   停下并在报告中列出失败项，等待总审计重设计。禁止重演 R5-R2 的 4 轮循环。
2. **证据从简**：raw evidence 只需工单 §4.5 要求的测试输出/退出码/source hashes/
   manifest 一套；**不要求** byte-level self-hash sidecar、untracked 清单、
   capture-time baseline 等 C3/C4 式仪式（那是 R5-R2 封存的特例，不是常态）。
3. **fmt/test 分开记录**按原工单 §4.6 执行。
4. 代码事实锚点（总审计已勘察，供快速定位）：
   - 协议常量与 section 编解码: `crates/antidebug-runtime/src/walker_protocol.rs`
     （`ResultSectionHeaderV2` L949、`encode_section` L1212、`parse_section` L1337、
     `validate_section` L1421、`COMPLETED_FLAG_DONE` L90、status 集合 L96-103）
   - 会话/事务安装: `crates/cli/src/unpacker/walker_session.rs`（1861 行）
   - 控制面: `crates/antidebug-runtime/src/walker_control.rs`
   - 若发现现有 header 无 round-1/round-2 双 DONE 字段，需扩展协议时：
     允许新增字段/常量，**不得改动已有字段的字节布局或语义**
     （R5-R2 冻结契约），新字段走版本化（PROTOCOL_VERSION 不动，用 header 内
     flag/option 位或尾部扩展区）。

## 1. 任务

完整执行原工单 §1-§5：生产 round-1/round-2 section producer、DONE 发布协议、
production consumer + V2 attestation digest 校验闭环、全部负向门、rollback。
出口门 §5 全部 PROVEN 后交付。

## 2. 交付物

1. 生产代码 + 测试（正向 1 组 + 负向 ≥9 组，覆盖原工单 §4.4 清单）；
2. 设计/协议说明文档（状态转移表 + caller graph）;
3. raw evidence 一套（§0.2 从简口径）;
4. 报告明确声明: `offline_mock=true` / `live_authorized=false` /
   `protected_sample=NOT_AUTHORIZED`。

## 3. 禁止

沿用原工单 §2 禁止清单全项（不改 runner_preflight、不接 live dispatch、
不动 R5-R2 冻结语义、不用 mock 冒充生产路径、不 silent retry）。
