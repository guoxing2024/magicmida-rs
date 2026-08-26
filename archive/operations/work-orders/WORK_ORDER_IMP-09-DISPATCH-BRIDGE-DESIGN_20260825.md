# WORK ORDER — IMP-09-DISPATCH-BRIDGE-DESIGN (target-side WalkerExecute 桥接设计)

**签发**: Hermes 总审计，owner 授权
**日期**: 2026-08-25
**性质**: 设计 + 静态审计单（design-only；无 tracked 生产代码改动、无 live）
**基线**: HEAD `c33401a`（R5-R4 已入库）
**前置状态**: R5-R3 PASS / R5-R4 PASS 均经独立审计

## 1. 背景

IMP-09 链剩余最后一块生产件：AUTHORIZED target-side dispatch bridge。
当前 `execute_walker_production()` 对无桥接情形返回 NotImplemented
（fail-closed 正确）。本单产出可实施的设计与静态验证，供下一张
实现卡照建，并作为 H6 LIVE-4 授权申请的前置条件。

## 2. 设计必须回答的问题（逐项成文）

1. **调用面**: 目标侧入口是 V2 导出集的哪个函数？现有 wanted 5 项 +
   `MidaAntidebugInitializeV2`（Phase04A 报告指出尚不存在）如何扩展？
   给出目标函数签名、参数 blob 布局与 R5-R3 params blob 的关系；
2. **权威链**: target-side 执行的每个输入（params_va/section1_va/digests/
   export RVA）如何从既有 sealed carrier 获得？禁止任何 open caller
   string 或魔法值——沿用 install_walker_session_verified 的矩阵；
3. **写原语边界**: 允许的注入原语清单（如 CreateRemoteThread /
   NtCreateThreadEx / APC），每个标注 Windows 版本可用性与检测面；
   默认推荐项及理由；
4. **失败语义**: 注入失败的 fail-closed 行为、与 TeardownOutcome 的交互
   （注入失败时 session 从未建立 → teardown 必须报 Released/空账本，
   不得伪造 PartiallyReleased）;
5. **观测性**: dispatch 每步进 walker evidence sidecar 的哪些字段；
6. **LIVE 边界**: 哪些行为只在 live_authorized=true 时解锁（编译期或
   运行期门），offline 下如何证明未解锁。

## 3. 静态交付（不写生产代码）

1. 设计文档: `docs/IMP09_DISPATCH_BRIDGE_DESIGN_20260825.md`，
   含 caller graph（现 NotImplemented 点 → 新桥 → target 入口）；
2. 接口草案: trait/fn 签名级 Rust 代码块（贴在文档内，不落 src/）;
3. 现状锚点核对表: 引用真实源码行号（antidebug_controller.rs 的
   execute_walker_production / runtime_loader.rs 的 exports 解析段）,
   与 Phase04A readiness 报告的事实基线对账，列出"当时不存在、现在仍不存在"
   与"已存在可直接复用"两栏；
4. 测试计划: 实现卡的离线测试矩阵（含注入失败、digest mismatch、
   未授权时拒绝）。

## 4. 附带轻量任务（同卡完成）

1. ADR7 回归门复验: 跑 Oreans 门 verify（17/17 记录 raw 输出）;
2. GTO preflight resolver dry-run: `tools/resolve_gto_source_revision.ps1`
   记录 revision_match 结果（只读，不执行样本）。

## 5. 出口门

```ini
DISPATCH_BRIDGE_DESIGN = DELIVERED
AUTHORITY_MATRIX_COMPLETE = true
OFFLINE_LIVE_BOUNDARY_DEFINED = true
ADR7_REGRESSION = 17/17
GTO_PREFLIGHT_DRYRUN = MATCH (or documented mismatch -> STOP)
NO_PRODUCTION_CODE_CHANGED = true
LIVE_AUTHORIZED = false
```

Correction 上限 = 1；证据从简；禁止接 live、禁改 runner_preflight.rs、
禁改 R5-R2/R5-R3/R5-R4 冻结语义。
