# GTO 项目工作单修正清单

**签发时间**: 2026-08-21 20:15  
**签发人**: 项目总指挥  
**前提**: 离线工作，禁止运行真实样本，禁止提交/推送

---

## WO-001: 更正账本和交付报告（优先级 P0）

**负责人**: [待分配]  
**预计工时**: 2小时  
**状态**: READY

### 任务

1. **更新边界账本** (`docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md` §8)
   - 替换为 WO-B 审计生成的修正表格
   - 明确 H3 状态（建议：标记为"absorbed into H4"或"waived - documented"）
   - 更新 H4-D 为"live runs completed"

2. **修正交付报告** (`GTO_DELIVERY_FINAL_2026-08-21.md`)
   - 标题改为"GTO H1/H2/H4C 交付报告 + H4A/B/D 技术通过报告 + H5 阻塞分析"
   - §1 执行摘要改为：
     ```
     H1/H2: DONE
     H4-A/B: TECHNICAL PASS（正式签核 PENDING/NOT GRANTED）
     H4-C: TECHNICAL PASS + 正式签核 COMPLETED
     H4-D: DESIGN + LIVE RUNS COMPLETED（观察通道，非验收证据）
     H5: BLOCKED_AT_LOADER_SMOKE（9/9 失败，未签核）
     ```
   - 移除所有"H4 CLOSED"、"H5 BOUNDED"声称
   - §5 将 H5 从"已达成"移到"阻塞"
   - §11 修改总评分，诚实报告阻塞状态

3. **修正最新提交信息**
   - 添加更正记录 `docs/GTO_AUDIT_CORRECTION_2026-08-21.md`
   - 记录过度声称及修正理由
   - 未来提交不得声称"CLOSED"直到正式签核完成

### 验收标准
- [ ] 修正后的账本表与 WO-B 输出一致
- [ ] 交付报告不再有 CRITICAL/HIGH 级别的过度声称
- [ ] 新增更正记录文档，解释误判原因

---

## WO-002: .rdata 可执行段缺陷根因调查（优先级 P1）

**负责人**: [待分配]  
**预计工时**: 4-6小时  
**状态**: BLOCKED（需规避安全护栏）

### 背景
`docs/GTO_H5_LOADER_WALL_ROOT_CAUSE.md` 记录了解包候选在加载器冒烟测试中 9/9 失败。三次独立 cdb 诊断定位崩溃点在 .rdata0/.rdata2 段（RVA 0x12F2F40, 0x2934089），这些段的 Characteristics 包含 EXECUTE，但内容是 Themida 加密代码的乱码。

### 任务
**手动代码审查**（不使用可能触发护栏的自动化工具）：

1. 在 `crates/pe/src/dumper/` 中查找节区特性（IMAGE_SCN_MEM_EXECUTE、IMAGE_SCN_CNT_CODE）的设置位置
2. 确认特性来源：
   - 从源 PE 复制？
   - 从运行时页保护推断？
   - 由 dumper 合成？
3. 检查 OEP 重定向逻辑（是否将入口指向 .boot bootstrap stub）
4. 确认 .rdata0/.rdata1/.rdata2 内容来源（运行时内存转储 vs 磁盘复制）

### 输出
创建 `docs/GTO_H5_RDATA_DEFECT_ROOT_CAUSE_INVESTIGATION.md`，包含：
- 代码位置（文件:行号）
- 特性决策机制
- 是否区分"真实代码"vs"运行时恰好可执行的加密数据"
- 未知项清单

### 验收标准
- [ ] 代码位置精确到文件:行号
- [ ] 机制描述基于实际代码，非推测
- [ ] 诚实列出无法从代码确认的项

---

## WO-003: .rdata 修复路径设计（优先级 P1）

**负责人**: [待分配]  
**前置**: WO-002 完成  
**预计工时**: 3-4小时  
**状态**: BLOCKED

### 任务
基于 WO-002 根因调查，评估四条候选修复路径（见 `docs/GTO_H5_LOADER_WALL_ROOT_CAUSE.md` §3）：

**(a)** 去除 .rdata0/.rdata1/.rdata2 的 EXECUTE 特性  
**(b)** 运行时解密 .rdata 内容（高风险）  
**(c)** 重定向入口/跳转目标到解密后的代码区  
**(d)** 使用观察宿主（G1）先采集受保护程序自身的解密/跳转行为作为证据

权衡标准：
1. 是否需要我们不掌握的知识（Themida 内部机制）？
2. 能否离线验证？
3. 是否符合 H0 约束（无 bypass、无写入目标、无窃取先前状态）？
4. 对 ADR7 和 Oreans 两样本门的影响半径？

### 输出
创建 `docs/GTO_H5_LOADER_FIX_PATH_DESIGN.md`，包含：
- 推荐路径 + 理由
- 拒绝路径 + 拒绝理由
- fail-closed 规则（dumper 无法区分代码 vs 加密数据时如何处理）
- 需要触碰的文件列表
- 离线单元测试方案
- 仍需真实授权的内容清单
- 对 Oreans 门的影响评估

### 验收标准
- [ ] 推荐路径有明确的离线验证方案
- [ ] fail-closed 规则不依赖猜测
- [ ] 明确区分"可离线证明"vs"需真实授权"

---

## WO-004: 工作区正式验证记录（优先级 P2）

**负责人**: [待分配]  
**预计工时**: 1小时  
**状态**: READY

### 任务
将 WO-C 的验证结果正式记录到边界账本。

当前 WO-C 报告：
- 1271 tests passed / 0 failed / 2 ignored
- cargo fmt --all -- --check 通过
- 15 个 clippy 警告
- git diff --check 通过

边界账本 §7 声称基线是"1885 passed / 0 failed / 2 ignored"。

调查测试计数差异：
1. 检查 git log 确认测试是否被移除/禁用
2. 检查是否有测试被标记为 `#[ignore]`
3. 确认 1271 vs 1885 的差异原因

### 输出
更新 `docs/GTO_COLD_START_HEAP_REBASE_1_BOUNDARY.md` §7：
- 如果 1271 是新基线：更新为"1271 passed / 0 failed / 2 ignored（基线更新于 2026-08-21）"
- 如果 1885 仍是目标：记录缺失的 614 个测试的原因

创建 `docs/GTO_WORKSPACE_VERIFICATION_2026-08-21.md`，记录：
- 完整测试输出
- clippy 警告清单
- git status 结果

### 验收标准
- [ ] 边界账本 §7 反映真实测试计数
- [ ] 测试计数变化有明确解释
- [ ] 验证记录可复现

---

## WO-005: 清理代码警告（优先级 P3）

**负责人**: [待分配]  
**预计工时**: 1-2小时  
**状态**: READY（可选）

### 任务
修复 WO-C 报告的 15 个 clippy 警告：
- `crates/pe/src/dumper/global_vars.rs:17` - 未使用字段
- `crates/pe/src/dumper/tls_bootstrap.rs:54-55` - 未使用常量

### 验收标准
- [ ] `cargo clippy --workspace --all-targets` 零警告
- [ ] 不引入新的测试失败

---

## 派单优先级

**立即执行**:
1. WO-001（P0）- 修正账本和报告

**并行执行**（WO-001 完成后）:
2. WO-002（P1）- 根因调查
3. WO-004（P2）- 工作区验证记录

**顺序执行**:
4. WO-003（P1）- 修复路径设计（需 WO-002）

**可选**:
5. WO-005（P3）- 代码警告清理

---

## 约束重申

**所有工作单必须遵守**：
- ❌ 禁止运行真实样本（GTO-H5-LIVE-AUTHORIZATION-2 未批准）
- ❌ 禁止提交、推送、修改 git 历史
- ❌ 禁止修改 D:\MidaVault\lab\evidence\ 下的封存证据
- ❌ 禁止修改 ADR7 或 Oreans 两样本门
- ✅ 只读代码审查、文档修正、离线测试、设计文档

**环境提示**：
- Bash 环境的 PATH 被 Git link.exe 污染
- 需要通过 PowerShell + vcvars64.bat 或使用 `test_with_msvc.bat` / `build_with_msvc.bat`

---

**签发**: 项目总指挥  
**日期**: 2026-08-21 20:15
