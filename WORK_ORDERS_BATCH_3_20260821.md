# 工作单批次 3 — 总指挥派单(owner 行国胜 授权派单)

**签发人**: 项目总指挥
**执行人**: 唯一 worker
**授权边界**: 本批次 = **派单授权**,非 `GTO-H5-LIVE-AUTHORIZATION-2`。
❌ 禁止运行真实样本/禁止实弹验证 —— 路径 (d) 的实测部分仍 BLOCKED。
批次 2 约束全部继承(无 push、不动分支、不动 ADR7/Oreans 门/vault 封存证据、MSVC 环境、门禁三件套)。

---

## WO-201(P1)WO-102 离线可验部分实施(R2/R3 + 受控 R1)

**前置更正(总指挥对设计的实施约束,优先级高于设计原文)**:
R1 一致性检查**若按设计原文默认启用会击穿主线**——任何合法脱壳的 .text 必然 ≠ 输入磁盘字节,
default-on 等于让 origin_macro 门全红。故 R1 必须 **opt-in**:仅在显式开关/家族策略下激活。

### 任务

1. `crates/pe/src/dumper/types.rs`:新增 `DumpTiming`(`Immediate` 默认 | `PostSelfDecrypt` 预留),
   并入 `DumpOptions`;默认行为零变化。
2. `crates/pe/src/error.rs`:新增 `DumpContentMismatch`(含首个差异偏移+长度摘要)。
3. **R2(默认开启,纯观察)**:`output_writer.rs` manifest 增记
   `encrypted_region_suspect=true`(EXECUTE 节且 4KB 抽样熵 > 7.5 bits/byte);不改任何字节。
4. **R1(opt-in only)**:`byte_map.rs` emit 前节内容 vs 输入磁盘对比;
   仅当调用方显式传入比较基准(新 DumpOptions 字段)时启用;无基准→跳过(走 R2 记录)。
   **禁止**在任何现有生产路径(gto_host/generic/themida 主线)隐式传基准。
5. **R3 回归测试**:断言 emit 后 characteristics == 输入(扩展现有测试)。
6. 单测:按 WO-102 §五(R1 一致/差异/无基准三分支;R2 高熵/低熵)。
7. CLI `--dump-timing` 参数骨架:仅解析与校验,`PostSelfDecrypt` 选中时输出
   "requires GTO-H5-LIVE-AUTHORIZATION-2" 结构化错误并 fail-closed(fail 在预检,不进运行时)。

### 验收

- [ ] 全量测试 ≥2257 passed / 0 failed(新增测试另计)
- [ ] 默认路径行为零变化(origin_macro 门输入不受影响——以现有回归测试证明)
- [ ] `--dump-timing=post-self-decrypt` 未授权即 fail-closed 于预检
- [ ] fmt + hygiene + 双 lane check 干净;本地提交,无 push

---

## WO-202(P2)治理状态落账

把批次 2/3 的裁决写入文档并提交:

1. `docs/GTO_WORKSPACE_VERIFICATION_2026-08-21.md` 追加:clippy 676 冻结裁决(理由:CI 用 rustc -D warnings 不含 clippy;行为敏感重构离线不可证等价;未来清理需专单+H5 授权);
2. 同文档记录:仓库**无 remote**(git remote -v 为空),push 待 owner 配置后由 worker 执行 `git push -u origin oreans/two-sample-mainline`;
3. `WORKER_HANDOFF.md` 追加批次 2/3 验收记录(4 提交哈希、基线 2257、clippy 决议、push 状态)。

**验收**: 文档一致、无过度声称、本地提交。

---

## WO-203(P2)H4-A/B/C 签核材料包(供 owner 审阅)

为解除三项 PENDING 签核,汇总一份**只读审阅包**:

1. 新建 `docs/GTO_H4_ABC_SIGNOFF_PACKET_20260821.md`:每阶段(A/B/C)一节——
   设计文档指针、证据 vault 逻辑标识(evidence_set_id/sha256,不含绝对路径)、
   已知保留项(H4-B attempt_001 raw 不可恢复等)、审阅清单(逐条可勾选)、
   与账本 §8 行的交叉引用;
2. **只读**:不修改任何证据、不改账本既有行、不下结论(签核权在 owner);
3. 明确列出每项签核需要 owner 确认的具体问题清单(让 owner 可以逐项回答 PASS/REJECT)。

**验收**: owner 可仅凭此包完成三阶段签核决策;无 vault 写入。

---

## 执行顺序与并行

**WO-201 →(WO-202 ‖ WO-203)**;预计总量 6–8h。

## 红线重申(违反即作废)

- ❌ 实弹(H5-LIVE-AUTHORIZATION-2 未签发,`PostSelfDecrypt` 只能停在预检拒绝)
- ❌ push / 改历史 / 删分支
- ❌ 触碰 ADR7 验证器、Oreans 门行为、vault 封存证据
- ❌ 提交信息出现 CLOSED / DELIVERED / FORMAL PASS(除非引用账本已有 formal acceptance 行)
- ✅ MSVC 环境 + fmt/hygiene/双 lane 三件套;样本相关字面量不得新增进 git

**签发**: 项目总指挥 · 批次 3
